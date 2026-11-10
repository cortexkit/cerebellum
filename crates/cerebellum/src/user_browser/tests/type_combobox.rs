use super::*;

fn combobox_fixture() -> Fixture {
    let fixture = Fixture::new();
    let mut tree = ax();
    tree["nodes"][2]["role"]["value"] = json!("combobox");
    tree["nodes"][2]["name"]["value"] = json!("Search query");
    tree["nodes"][2]["properties"] = json!([
        {"name":"focused","value":{"type":"boolean","value":false}},
        {"name":"expanded","value":{"type":"booleanOrUndefined","value":false}}
    ]);
    let mut initial_dom = dom(false, false, false, false);
    initial_dom["nodes"][3]["parentId"] = json!(7);
    initial_dom["nodes"][3]["attributes"] = json!([
        "type",
        "text",
        "role",
        "combobox",
        "name",
        "search",
        "id",
        "search-query",
        "placeholder",
        "Search",
        "autocomplete",
        "off",
        "aria-autocomplete",
        "list",
        "aria-expanded",
        "false"
    ]);
    initial_dom["nodes"].as_array_mut().unwrap().extend([
        json!({"nodeId":7,"parentId":2,"backendNodeId":7,"nodeType":1,"nodeName":"FORM","localName":"form","attributes":["id","search-form"]}),
        json!({"nodeId":8,"parentId":2,"backendNodeId":8,"nodeType":1,"nodeName":"FORM","localName":"form","attributes":["id","other-form"]}),
    ]);
    let mut focused_dom = initial_dom.clone();
    let attrs = focused_dom["nodes"][3]["attributes"]
        .as_array_mut()
        .unwrap();
    *attrs.last_mut().unwrap() = json!("true");
    attrs.extend([
        json!("aria-activedescendant"),
        json!("search-option"),
        json!("aria-controls"),
        json!("search-popup"),
        json!("aria-owns"),
        json!("search-popup"),
    ]);
    focused_dom["nodes"].as_array_mut().unwrap().extend([
        json!({"nodeId":9,"parentId":7,"backendNodeId":9,"nodeType":1,"nodeName":"UL","localName":"ul","attributes":["id","search-popup","role","listbox"]}),
        json!({"nodeId":10,"parentId":9,"backendNodeId":10,"nodeType":1,"nodeName":"LI","localName":"li","attributes":["id","search-option","role","option"]}),
    ]);
    let mut focused_tree = tree.clone();
    focused_tree["nodes"][2]["properties"] = json!([
        {"name":"focused","value":{"type":"boolean","value":true}},
        {"name":"expanded","value":{"type":"booleanOrUndefined","value":true}},
        {"name":"activedescendant","value":{"type":"idref","relatedNodes":[{"backendDOMNodeId":10,"idref":"search-option"}]}},
        {"name":"controls","value":{"type":"idrefList","relatedNodes":[{"backendDOMNodeId":9,"idref":"search-popup"}]}}
    ]);
    focused_tree["nodes"][0]["childIds"]
        .as_array_mut()
        .unwrap()
        .push(json!("popup"));
    focused_tree["nodes"].as_array_mut().unwrap().extend([
        json!({"nodeId":"popup","ignored":false,"role":{"value":"listbox"},"name":{"value":"Search suggestions"},"backendDOMNodeId":9,"childIds":["option"]}),
        json!({"nodeId":"option","ignored":false,"role":{"value":"option"},"name":{"value":"rust language"},"backendDOMNodeId":10}),
    ]);
    {
        let mut state = fixture.state.lock().unwrap();
        state.dom_override = Some(initial_dom);
        state.ax_override = Some(tree);
        // These captures are applied after DOM.focus, just as a focus handler
        // opens a popup without replacing the input node.
        state.type_capture_after_focus = Some((focused_dom, focused_tree));
        state.type_focused_backend = Some(4);
    }
    fixture
}

async fn type_search(fixture: &Fixture) -> Value {
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Search query"),"text":"rust language"}), "allow_30m").await.0
}

#[tokio::test]
async fn combobox_popup_focus_changes_receive_text_in_the_same_node() {
    let fixture = combobox_fixture();
    let reply = type_search(&fixture).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.typed_value, "rust language");
    assert_eq!(state.type_resolved_backend, 4);
    assert_eq!(state.inputs, ["DOM.focus", "Input.insertText"]);
    assert!(state.type_capture_after_focus.is_none());
    assert_eq!(
        state.dom_override.as_ref().unwrap()["nodes"][3]["backendNodeId"],
        4
    );
    let attrs = state.dom_override.as_ref().unwrap()["nodes"][3]["attributes"]
        .as_array()
        .unwrap();
    let (pairs, _) = attrs.as_chunks::<2>();
    assert!(pairs.iter().any(|pair| pair == &["aria-expanded", "true"]));
}

#[tokio::test]
async fn combobox_popup_and_same_url_push_state_after_focus_receive_text() {
    let fixture = combobox_fixture();
    fixture.state.lock().unwrap().page_reaction = Some(PageReaction::PushSameUrl);
    let reply = type_search(&fixture).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.typed_value, "rust language");
    assert_eq!(state.type_resolved_backend, 4);
    assert_eq!(state.inputs, ["DOM.focus", "Input.insertText"]);
    let history = state.history.as_ref().unwrap();
    assert_eq!(history["currentIndex"], 1);
    assert_ne!(history["entries"][0]["id"], history["entries"][1]["id"]);
    assert_eq!(history["entries"][0]["url"], history["entries"][1]["url"]);
}

fn set_target_attribute(dom: &mut Value, name: &str, value: &str) {
    let attrs = dom["nodes"][3]["attributes"].as_array_mut().unwrap();
    let (pairs, _) = attrs.as_chunks_mut::<2>();
    if let Some(pair) = pairs.iter_mut().find(|pair| pair[0] == name) {
        pair[1] = json!(value);
    } else {
        attrs.extend([json!(name), json!(value)]);
    }
}

#[tokio::test]
async fn combobox_security_changes_during_focus_never_receive_text() {
    for (name, value) in [
        ("type", "password"),
        ("autocomplete", "cc-number"),
        ("name", "password"),
        ("id", "credit_card_number"),
        ("readonly", ""),
    ] {
        let fixture = combobox_fixture();
        {
            let mut state = fixture.state.lock().unwrap();
            let dom = &mut state.type_capture_after_focus.as_mut().unwrap().0;
            set_target_attribute(dom, name, value);
        }
        let reply = type_search(&fixture).await;
        assert_eq!(reply["outcome"], "outcome_unknown", "{name}: {reply}");
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.inputs, ["DOM.focus"], "{name}: {reply}");
        assert!(state.typed_value.is_empty(), "{name}: {reply}");
    }
}

#[tokio::test]
async fn combobox_moving_to_another_form_during_focus_is_refused() {
    let fixture = combobox_fixture();
    {
        let mut state = fixture.state.lock().unwrap();
        state.type_capture_after_focus.as_mut().unwrap().0["nodes"][3]["parentId"] = json!(8);
    }
    let reply = type_search(&fixture).await;
    assert_eq!(reply["outcome"], "outcome_unknown", "{reply}");
    assert_eq!(reply["reason"], "classification_changed", "{reply}");
    assert_eq!(
        reply["detail"],
        json!({"check":"post-focus","changed_fields":["form_owner"]})
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.inputs, ["DOM.focus"]);
    assert!(state.typed_value.is_empty());
}

#[tokio::test]
async fn combobox_focus_popup_does_not_hide_person_input() {
    for reaction in [
        PageReaction::PersonKey,
        PageReaction::PersonClick,
        PageReaction::PersonScroll,
    ] {
        let fixture = combobox_fixture();
        fixture.state.lock().unwrap().page_reaction = Some(reaction);
        let reply = type_search(&fixture).await;
        assert_eq!(reply["outcome"], "outcome_unknown", "{reaction:?}: {reply}");
        assert_eq!(
            reply["reason"], "state_changed_by_person",
            "{reaction:?}: {reply}"
        );
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.inputs, ["DOM.focus"]);
        assert!(state.typed_value.is_empty());
    }
}

#[tokio::test]
async fn combobox_security_change_before_focus_is_refused_without_dispatch() {
    let fixture = combobox_fixture();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    {
        let mut state = fixture.state.lock().unwrap();
        set_target_attribute(
            state.dom_override.as_mut().unwrap(),
            "autocomplete",
            "cc-number",
        );
    }
    let (reply, _) = fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Search query"),"text":"rust language"}), "allow_30m").await;
    assert_eq!(reply["reason"], "classification_changed", "{reply}");
    assert_eq!(reply["input_dispatched"], false, "{reply}");
    assert_eq!(reply["detail"]["check"], "pre-dispatch");
    assert!(reply["detail"]["changed_fields"]
        .as_array()
        .unwrap()
        .contains(&json!("target_autocomplete_tokens")));
    let state = fixture.state.lock().unwrap();
    assert!(state.inputs.is_empty());
    assert!(state.typed_value.is_empty());
}

#[tokio::test]
async fn combobox_form_change_before_insertion_names_only_the_changed_field() {
    let fixture = combobox_fixture();
    {
        let mut state = fixture.state.lock().unwrap();
        let mut changed = state.type_capture_after_focus.as_ref().unwrap().0.clone();
        changed["nodes"][3]["parentId"] = json!(8);
        state.type_dom_after_focus_check = Some(changed);
    }
    let reply = type_search(&fixture).await;
    assert_eq!(reply["reason"], "classification_changed", "{reply}");
    assert_eq!(
        reply["detail"],
        json!({"check":"pre-insertion","changed_fields":["form_owner"]})
    );
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.inputs, ["DOM.focus"]);
    assert!(state.typed_value.is_empty());
}

#[tokio::test]
async fn combobox_click_form_change_names_only_the_changed_field() {
    let fixture = combobox_fixture();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    fixture.state.lock().unwrap().dom_override.as_mut().unwrap()["nodes"][3]["parentId"] = json!(8);
    let (reply, _) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Search query")),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["reason"], "classification_changed", "{reply}");
    assert_eq!(
        reply["detail"],
        json!({"check":"pre-dispatch","changed_fields":["form_owner"]})
    );
    assert!(fixture.state.lock().unwrap().inputs.is_empty());
}

#[tokio::test]
async fn classification_changed_reports_every_closed_field_without_values() {
    let fixture = combobox_fixture();
    let state = fixture.state.lock().unwrap();
    let identity = BackendNodeIdentity::new("handed", "main", 4).unwrap();
    let expected = classify_flattened_document(
        state.dom_override.as_ref().unwrap().as_object().unwrap(),
        &identity,
        1,
        "https://example.com",
    )
    .unwrap();
    macro_rules! check_field {
        ($field:ident, $value:expr) => {{
            let mut observed = expected.clone();
            observed.$field = $value;
            assert_ne!(observed, expected);
            let reply = classification_changed(&expected, &observed, InputCheck::PreDispatch);
            assert_eq!(reply["detail"], json!({"check":"pre-dispatch","changed_fields":[stringify!($field)]}));
        }};
    }
    check_field!(schema, "private-schema".into());
    check_field!(node_identity, "private-node".into());
    check_field!(activation_target_identity, "private-activation-node".into());
    check_field!(document_epoch, 2);
    check_field!(target_kind, crate::classification::TargetKind::Button);
    check_field!(effective_input_type, Some("password".into()));
    check_field!(
        activation_invokes_form_submit,
        !expected.activation_invokes_form_submit
    );
    check_field!(form_owner, None);
    check_field!(current_top_level_origin, "https://private.example".into());
    check_field!(
        activation_destination_origin,
        Some("https://private.example".into())
    );
    check_field!(target_autocomplete_tokens, vec!["cc-number".into()]);
    check_field!(target_password, !expected.target_password);
    check_field!(associated_form_controls, vec![]);
    check_field!(required_tier, expected.required_tier + 1);
    check_field!(credential, !expected.credential);
    check_field!(financial, !expected.financial);
    let mut login_changed = expected.clone();
    login_changed.login_field.as_mut().unwrap().name = "private-password-name".into();
    assert_eq!(login_changed, expected);
    assert_eq!(
        classification_changed(&expected, &login_changed, InputCheck::PreDispatch)["detail"]
            ["changed_fields"],
        json!([])
    );
}
