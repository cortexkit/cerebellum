use super::*;

fn replacement_fixture(name: &str, role: &str, attrs: Value, frame: &str) -> Fixture {
    let fixture = Fixture::new();
    let mut tree = ax();
    tree["nodes"][2]["role"]["value"] = json!("combobox");
    tree["nodes"][2]["name"]["value"] = json!("Search query");
    let mut replacement_tree = tree.clone();
    replacement_tree["nodes"][2]["backendDOMNodeId"] = json!(40);
    replacement_tree["nodes"][2]["role"]["value"] = json!(role);
    replacement_tree["nodes"][2]["name"]["value"] = json!(name);
    replacement_tree["nodes"][2]["frameId"] = json!(frame);
    replacement_tree["nodes"][2]["properties"] =
        json!([{"name":"focused","value":{"type":"boolean","value":true}}]);
    let mut replacement_dom = dom(false, false, false, false);
    replacement_dom["nodes"][3]["nodeId"] = json!(40);
    replacement_dom["nodes"][3]["backendNodeId"] = json!(40);
    replacement_dom["nodes"][3]["attributes"] = attrs;
    {
        let mut state = fixture.state.lock().unwrap();
        state.ax_override = Some(tree);
        state.type_capture_after_focus = Some((replacement_dom, replacement_tree));
        state.type_focused_backend = Some(40);
    }
    fixture
}

fn safe_replacement() -> Fixture {
    replacement_fixture("Search query", "combobox", json!(["type", "text"]), "main")
}

async fn type_search(fixture: &Fixture) -> Value {
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    fixture.call(1, json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot,"Search query"),"text":"rust language"}), "allow_30m").await.0
}

#[tokio::test]
async fn focus_replacement_receives_text_in_the_new_node() {
    let fixture = safe_replacement();
    let reply = type_search(&fixture).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.typed_value, "rust language");
    assert_eq!(state.type_resolved_backend, 40);
    assert_eq!(state.inputs, ["DOM.focus", "Input.insertText"]);
}

#[tokio::test]
async fn unsafe_focus_replacements_never_receive_text() {
    for (name, role, attrs, frame) in [
        ("Other search", "combobox", json!(["type", "text"]), "main"),
        ("Search query", "textbox", json!(["type", "text"]), "main"),
        (
            "Search query",
            "combobox",
            json!(["type", "password"]),
            "main",
        ),
        (
            "Search query",
            "combobox",
            json!(["type", "text", "autocomplete", "cc-number"]),
            "main",
        ),
        (
            "Search query",
            "combobox",
            json!(["type", "text", "readonly", ""]),
            "main",
        ),
        (
            "Search query",
            "combobox",
            json!(["type", "text"]),
            "foreign",
        ),
    ] {
        let fixture = replacement_fixture(name, role, attrs.clone(), frame);
        let reply = type_search(&fixture).await;
        assert_eq!(
            reply["outcome"], "outcome_unknown",
            "{name}/{role}/{attrs}/{frame}: {reply}"
        );
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.inputs, ["DOM.focus"], "{reply}");
        assert!(state.typed_value.is_empty(), "{reply}");
        assert!(
            reply["remedy"]
                .as_str()
                .unwrap()
                .contains("requested text was not sent"),
            "{reply}"
        );
        assert!(
            !reply["remedy"].as_str().unwrap().contains("Do not repeat"),
            "{reply}"
        );
    }
}

#[tokio::test]
async fn person_or_navigation_after_focus_prevents_adoption() {
    for reaction in [
        PageReaction::PersonKey,
        PageReaction::PersonClick,
        PageReaction::Reload,
        PageReaction::ChildNavigation,
    ] {
        let fixture = safe_replacement();
        fixture.state.lock().unwrap().page_reaction = Some(reaction);
        let reply = type_search(&fixture).await;
        assert_eq!(reply["outcome"], "outcome_unknown", "{reaction:?}: {reply}");
        assert!(
            matches!(
                reply["reason"].as_str(),
                Some("state_changed_by_person" | "observer_unavailable")
            ),
            "{reply}"
        );
        assert_eq!(fixture.state.lock().unwrap().inputs, ["DOM.focus"]);
    }
}

#[tokio::test]
async fn an_attached_original_cannot_handoff_to_a_focused_lookalike() {
    let fixture = safe_replacement();
    {
        let mut state = fixture.state.lock().unwrap();
        state.type_capture_after_focus.as_mut().unwrap().0["nodes"]
            .as_array_mut()
            .unwrap()
            .push(dom(false, false, false, false)["nodes"][3].clone());
    }
    let reply = type_search(&fixture).await;
    assert_eq!(reply["reason"], "type_focus_not_ready", "{reply}");
    assert_eq!(fixture.state.lock().unwrap().inputs, ["DOM.focus"]);
}

#[tokio::test]
async fn adopted_node_is_reverified_before_inserting_text() {
    let fixture = safe_replacement();
    {
        let mut state = fixture.state.lock().unwrap();
        let mut changed = state.type_capture_after_focus.as_ref().unwrap().0.clone();
        changed["nodes"][3]["attributes"] = json!(["type", "password"]);
        state.type_dom_after_focus_check = Some(changed);
        state.type_focus_checks_before_mutation = 1;
    }
    let reply = type_search(&fixture).await;
    assert_eq!(reply["outcome"], "outcome_unknown", "{reply}");
    assert_eq!(reply["reason"], "classification_changed", "{reply}");
    assert_eq!(fixture.state.lock().unwrap().inputs, ["DOM.focus"]);
}

#[tokio::test]
async fn an_ax_focus_hint_must_be_confirmed_by_the_active_element() {
    let fixture = safe_replacement();
    fixture.state.lock().unwrap().type_focused_backend = Some(4);
    let reply = type_search(&fixture).await;
    assert_eq!(reply["reason"], "type_focus_not_ready", "{reply}");
    assert_eq!(fixture.state.lock().unwrap().inputs, ["DOM.focus"]);
}
