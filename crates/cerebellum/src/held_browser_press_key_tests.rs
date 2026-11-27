use super::*;

async fn read_input(planes: &Planes, kind: &str, override_action: Option<&str>) -> Value {
    let identity = &planes.routes.get(8, 3).unwrap().identity;
    let field = BackendNodeIdentity::new("target", "frame", 42).unwrap();
    let mut button = json!(["type", "submit"]);
    if let Some(url) = override_action {
        button = json!(["type", "submit", "formaction", url, "formmethod", "get"]);
    }
    let dom = json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","nodeValue":""},
        {"nodeId":2,"backendNodeId":2,"parentId":1,"nodeType":1,"nodeName":"FORM","localName":"form","attributes":["action","/submit","method","post"]},
        {"nodeId":42,"backendNodeId":42,"parentId":2,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":["type",kind]},
        {"nodeId":43,"backendNodeId":43,"parentId":2,"nodeType":1,"nodeName":"BUTTON","localName":"button","attributes":button}
    ]});
    let classification = crate::browser::navigation::classify_flattened_document(
        dom.as_object().unwrap(),
        &field,
        0,
        "https://example.com",
    )
    .unwrap();
    let submit = BackendNodeIdentity::new("target", "frame", 43).unwrap();
    let submit_classification = crate::browser::navigation::classify_flattened_document(
        dom.as_object().unwrap(),
        &submit,
        0,
        "https://example.com",
    )
    .unwrap();
    let refs = [
        (field, classification, "e1", "textbox"),
        (submit, submit_classification, "e2", "button"),
    ];
    let ax = refs
        .iter()
        .map(|(_, _, reference, role)| AxRecord {
            depth: 0,
            role: (*role).into(),
            name: (*role).into(),
            value: None,
            reference: Some((*reference).into()),
        })
        .collect::<Vec<_>>();
    let refs = refs
        .into_iter()
        .map(|(node, classification, reference, role)| RefRecord {
            frame_document: None,
            captured: SnapshotRef::new(reference, role, role, 0).unwrap(),
            frame_path: vec!["frame".into()],
            backend_identity: Some(node),
            raw_role: None,
            raw_name: None,
            classification: Ok(Box::new(classification)),
        })
        .collect();
    planes
        .browser
        .retain_text_snapshot(
            identity,
            SnapshotKind::Ax,
            &ax,
            None,
            refs,
            4096,
            Some(CommittedDocument::new("https://example.com", 1, "loader")),
        )
        .await
        .unwrap()
}

fn key(read: &Value, reference: &str, key: &str, call: &str) -> Value {
    json!({"name":"browser_use","call_key":call,"arguments":{"action":"press_key","ref":reference,"snapshot_id":read["snapshot_id"],"key":key}})
}

fn model_body(reply: &Value) -> &Value {
    reply.get("structuredContent").unwrap_or(reply)
}

#[tokio::test]
async fn own_press_key_enter_submits_after_approval() {
    let (planes, consent, page, _) = fixture().await;
    let read = read_input(&planes, "search", None).await;
    let call = key(&read, "e1", "enter", "enter-search");
    assert_held(&decode(exchange(&planes, 9, 3, call).await), "consent");
    assert_eq!(page.submits.load(Ordering::SeqCst), 0);
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late_key(&planes, 9, "enter-search").await;
    let result = &reply["entries"][0]["result"]["structuredContent"];
    assert_eq!(result["outcome"], "ok", "{reply}");
    assert_eq!(result["navigation"], "main_frame", "{reply}");
    assert_eq!(page.submits.load(Ordering::SeqCst), 1);
    let journal = planes.browser.journal_export_for_test().await;
    assert!(journal.contains("\"key\":\"enter\""));
    assert!(journal.contains("\"intent_redacted\":\"press enter\""));
    let line = journal
        .lines()
        .find(|line| line.contains("\"key\":\"enter\""))
        .unwrap();
    let old_entry = journal::assert_legacy_key_entry(line);
    assert_eq!(old_entry.capability, Some(journal::Capability::Click));
    assert_eq!(old_entry.intent_redacted.as_deref(), Some("press enter"));
}

#[tokio::test]
async fn own_press_key_enter_and_click_disclose_the_same_credential_hazard() {
    let mut cards = Vec::new();
    for enter in [false, true] {
        let (planes, consent, page, _) = fixture().await;
        let read = read_input(&planes, "password", None).await;
        let call = if enter {
            key(&read, "e1", "enter", "sign-in")
        } else {
            json!({"name":"browser_use","call_key":"sign-in","arguments":{"action":"click","ref":"e2","snapshot_id":read["snapshot_id"],"intent":"submit","severity":{"tier":4,"credential":true,"financial":false}}})
        };
        assert_held(&decode(exchange(&planes, 9, 3, call).await), "consent");
        assert_eq!(page.inputs.load(Ordering::SeqCst), 0);
        cards.push(consent.cards().pop().unwrap());
    }
    assert!(cards[1].to_string().contains("sign-in"), "{:?}", cards[1]);
    assert_eq!(cards[0]["facts"], cards[1]["facts"]);
}

#[tokio::test]
async fn own_press_key_refuses_password_edits_invalid_keys_and_unread_pages() {
    let (planes, _, page, _) = fixture().await;
    let read = read_input(&planes, "password", None).await;
    for deletion in ["backspace", "delete"] {
        let refused = decode(exchange(&planes, 9, 3, key(&read, "e1", deletion, deletion)).await);
        assert_eq!(
            model_body(&refused)["detail"]["reason_code"],
            "credential_field",
            "{refused}"
        );
    }
    let invalid = decode(exchange(&planes, 9, 3, key(&read, "e1", "f12", "bad-key")).await);
    assert_eq!(model_body(&invalid)["detail"]["field"], "key", "{invalid}");
    let stale = decode(exchange(&planes, 9, 3, key(&read, "e999", "tab", "old-ref")).await);
    assert_eq!(model_body(&stale)["outcome"], "ref_not_found", "{stale}");
    let tab = decode(exchange(&planes, 9, 3, key(&read, "e1", "tab", "tab")).await);
    assert_eq!(model_body(&tab)["outcome"], "ok", "{tab}");
    assert_eq!(page.inputs.load(Ordering::SeqCst), 1);
    *page.url.lock().unwrap() = "https://example.com/person-moved".into();
    page.document_replaced.store(1, Ordering::SeqCst);
    let moved = decode(exchange(&planes, 9, 3, key(&read, "e1", "tab", "page-moved")).await);
    assert_eq!(model_body(&moved)["outcome"], "stale_snapshot", "{moved}");
    assert_eq!(page.inputs.load(Ordering::SeqCst), 1);
}
