use super::*;

fn key(tab: &str, read: &Value, reference: &str, key: &str) -> Value {
    json!({"action":"press_key","browser":"user","tab":tab,"snapshot_id":read["snapshot_id"],"ref":reference,"key":key})
}

fn form(field: u64, override_action: Option<&str>) -> Value {
    let mut page = dom(false, false, false, false);
    let nodes = page["nodes"].as_array_mut().unwrap();
    nodes.push(json!({"nodeId":7,"parentId":2,"backendNodeId":7,"nodeType":1,"nodeName":"FORM","localName":"form","attributes":["method","post","action","/submit"]}));
    for node in nodes {
        if node["backendNodeId"] == field || node["backendNodeId"] == 3 {
            node["parentId"] = json!(7);
        }
        if node["backendNodeId"] == 3 {
            node["attributes"] = if let Some(action) = override_action {
                json!(["type", "submit", "formaction", action, "formmethod", "get"])
            } else {
                json!(["type", "submit"])
            };
        }
    }
    page
}

#[tokio::test]
async fn press_key_enter_submits_the_search_form_after_click_equivalent_approval() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.dom_override = Some(form(4, None));
        state.press_key_submits = true;
    }
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (refused_click, click_cards) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "deny",
        )
        .await;
    assert_eq!(
        refused_click["reason"], "consent_declined",
        "{refused_click}"
    );
    let (reply, key_cards) = fixture
        .call(
            1,
            key(&tab, &snapshot, &reference(&snapshot, "Message"), "enter"),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["page_changed"], true);
    assert_eq!(key_cards.len(), 1);
    assert!(key_cards[0]["facts"].is_array(), "{key_cards:?}");
    assert_eq!(key_cards[0]["facts"], click_cards[0]["facts"]);
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.tabs[&tab].url, "https://example.com/submitted");
    let commands = state
        .commands
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten());
    let key_events = commands
        .filter(|command| command["method"] == "Input.dispatchKeyEvent")
        .map(|command| command["params"].clone())
        .collect::<Vec<_>>();
    assert_eq!(
        key_events,
        [
            json!({"type":"keyDown","key":"Enter","code":"Enter","windowsVirtualKeyCode":13,"text":"\r"}),
            json!({"type":"keyUp","key":"Enter","code":"Enter","windowsVirtualKeyCode":13}),
        ]
    );
}

#[tokio::test]
async fn press_key_enter_discloses_sign_in_and_honors_the_submitters_destination() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    fixture.state.lock().unwrap().dom_override =
        Some(form(5, Some("https://identity.example/session")));
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let (reply, cards) = fixture
        .call(
            1,
            key(&tab, &snapshot, &reference(&snapshot, "Password"), "enter"),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 2, "{cards:?}");
    let expected = site_hazard_words("credential_form_submit");
    for card in &cards {
        assert!(card.to_string().contains(expected), "{card}");
    }
    assert!(
        cards[1].to_string().contains("https://identity.example"),
        "{cards:?}"
    );
}

#[tokio::test]
async fn press_key_preserves_field_and_fresh_read_guards() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let password = reference(&snapshot, "Password");
    for name in ["backspace", "delete"] {
        let (reply, _) = fixture
            .call(1, key(&tab, &snapshot, &password, name), "deny")
            .await;
        assert_eq!(
            reply["detail"]["reason_code"], "credential_field",
            "{reply}"
        );
    }
    let (unknown, _) = fixture
        .call(1, key(&tab, &snapshot, &password, "control_w"), "deny")
        .await;
    assert_eq!(unknown["outcome"], "invalid_request", "{unknown}");
    assert_eq!(unknown["detail"]["field"], "key");
    let (stale, _) = fixture
        .call(1, key(&tab, &snapshot, "e999", "tab"), "deny")
        .await;
    assert_eq!(stale["reason"], "ref_scope_mismatch", "{stale}");
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    let (allowed, _) = fixture
        .call(1, key(&tab, &snapshot, &password, "tab"), "allow_30m")
        .await;
    assert_eq!(allowed["outcome"], "ok", "{allowed}");
    assert_eq!(allowed["page_changed"], false);
    {
        let mut state = fixture.state.lock().unwrap();
        state.inputs.clear();
        state.human_before_input = true;
    }
    let (refused, _) = fixture
        .call(1, key(&tab, &snapshot, &password, "tab"), "deny")
        .await;
    assert_eq!(refused["reason"], "state_changed_by_person", "{refused}");
    assert_eq!(refused["input_dispatched"], false);
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
    let journal = fixture.planes.browser.journal_export_for_test().await;
    assert!(journal.contains("\"action\":\"press_key\""));
    assert!(journal.contains("\"key\":\"tab\""));
    assert!(!journal.contains("secret-value"));
    let outcome = journal
        .lines()
        .map(crate::journal::assert_legacy_key_entry)
        .filter_map(|entry| entry.detail)
        .find(|detail| {
            detail["action"] == "press_key" && detail["key"] == "tab" && detail["outcome"] == "ok"
        });
    assert!(
        outcome.is_some(),
        "the running journal reader preserves the user's key event"
    );
}
