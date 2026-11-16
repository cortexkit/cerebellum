use super::*;

fn fixture() -> Fixture {
    let fixture = Fixture::new();
    let mut state = fixture.state.lock().unwrap();
    state.top_level_only = true;
    state.dom_override = Some(json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":""},
        {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"FORM","localName":"form","attributes":[]},
        {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":"SELECT","localName":"select","attributes":[]},
        {"nodeId":4,"parentId":3,"backendNodeId":4,"nodeType":1,"nodeName":"OPTION","localName":"option","attributes":["value","mac"]}
    ]}));
    state.ax_override = Some(json!({"nodes":[
        {"nodeId":"root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Page"},"backendDOMNodeId":1,"frameId":"main","childIds":["select"]},
        {"nodeId":"select","ignored":false,"role":{"value":"combobox"},"name":{"value":"Platform"},"backendDOMNodeId":3,"childIds":["option"]},
        {"nodeId":"option","ignored":false,"role":{"value":"option"},"name":{"value":"macOS"},"backendDOMNodeId":4}
    ]}));
    drop(state);
    fixture
}

async fn prepare(fixture: &Fixture) -> (String, Value, Value) {
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let click = click(&tab, &snapshot, &reference(&snapshot, "option macOS"));
    (tab, snapshot, click)
}

#[tokio::test]
async fn native_option_uses_pinned_runtime_and_reports_value_without_geometry() {
    let fixture = fixture();
    let (_, _, args) = prepare(&fixture).await;
    let (reply, _) = fixture.call(1, args, "allow_30m").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["value"], "mac");
    assert_eq!(reply["selectedIndex"], 1);
    let state = fixture.state.lock().unwrap();
    assert_eq!(state.inputs, ["Runtime.callFunctionOn"]);
    assert!(!state
        .commands
        .iter()
        .flat_map(|plan| plan["commands"].as_array().into_iter().flatten())
        .any(|command| command["method"] == "DOM.scrollIntoViewIfNeeded"
            || command["method"] == "DOM.getContentQuads"));
}

#[tokio::test]
async fn native_option_refuses_disabled_controls_and_sensitive_forms_before_input() {
    for kind in ["option", "select", "optgroup", "payment", "credential"] {
        let fixture = fixture();
        {
            let mut state = fixture.state.lock().unwrap();
            let nodes = state.dom_override.as_mut().unwrap()["nodes"]
                .as_array_mut()
                .unwrap();
            match kind {
                "option" => nodes[3]["attributes"] = json!(["disabled", ""]),
                "select" => nodes[2]["attributes"] = json!(["disabled", ""]),
                "optgroup" => {
                    nodes[3]["parentId"] = json!(5);
                    nodes.push(json!({"nodeId":5,"parentId":3,"backendNodeId":5,"nodeType":1,"nodeName":"OPTGROUP","localName":"optgroup","attributes":["disabled",""]}));
                }
                _ => nodes.push(json!({"nodeId":5,"parentId":2,"backendNodeId":5,"nodeType":1,"nodeName":"INPUT","localName":"input","attributes":if kind == "payment" {json!(["autocomplete","cc-number"])} else {json!(["type","password"])}})),
            }
        }
        let (_, _, args) = prepare(&fixture).await;
        let (reply, _) = fixture.call(1, args, "allow_30m").await;
        assert_eq!(reply["reason"], "target_not_interactive", "{kind}: {reply}");
        assert!(fixture.state.lock().unwrap().inputs.is_empty(), "{kind}");
    }
}

#[tokio::test]
async fn native_option_still_checks_snapshot_person_and_click_tier() {
    for kind in ["snapshot", "person", "tier"] {
        let fixture = fixture();
        let (tab, _, mut args) = prepare(&fixture).await;
        match kind {
            "snapshot" => args["snapshot_id"] = json!("not-a-snapshot"),
            "person" => {
                fixture
                    .state
                    .lock()
                    .unwrap()
                    .tabs
                    .get_mut(&tab)
                    .unwrap()
                    .interaction += 1
            }
            _ => args["severity"]["tier"] = json!(0),
        }
        let (reply, _) = fixture.call(1, args, "allow_30m").await;
        assert_ne!(reply["outcome"], "ok", "{kind}: {reply}");
        assert!(fixture.state.lock().unwrap().inputs.is_empty(), "{kind}");
    }
}

#[tokio::test]
async fn revision_four_keeps_existing_actions_but_refuses_native_option_selection() {
    let fixture = fixture();
    fixture.state.lock().unwrap().extension_revision = Some(Some(4));
    let (_, _, args) = prepare(&fixture).await;
    let (reply, _) = fixture.call(1, args, "allow_30m").await;
    assert_eq!(reply["reason"], "extension_outdated", "{reply}");
    assert_eq!(reply["detail"]["required_revision"], 5);
}
