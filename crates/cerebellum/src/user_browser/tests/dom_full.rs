use super::*;

fn dashboard(fixture: &Fixture) -> (String, String, String) {
    let navigation = format!("<nav>{}</nav>", "<a href='/'>Navigation</a>".repeat(500));
    let main = "<main><h1>Quarterly results</h1><p>Revenue rose 12% — net.</p></main>".to_owned();
    let markup = format!("<html><body>{navigation}{main}</body></html>");
    let mut state = fixture.state.lock().unwrap();
    state.top_level_only = true;
    state.ax_override = Some(json!({"nodes":[
        {"nodeId":"root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Dashboard"},"backendDOMNodeId":1,"frameId":"main","childIds":["nav","main"]},
        {"nodeId":"nav","ignored":false,"role":{"value":"navigation"},"name":{"value":"Navigation"},"backendDOMNodeId":3},
        {"nodeId":"main","ignored":false,"role":{"value":"main"},"name":{"value":"Quarterly results"},"backendDOMNodeId":4}
    ]}));
    state.dom_override = Some(json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"nodeName":"#document","localName":"","nodeValue":""},
        {"nodeId":2,"parentId":1,"backendNodeId":2,"nodeType":1,"nodeName":"BODY","localName":"body","attributes":[]},
        {"nodeId":3,"parentId":2,"backendNodeId":3,"nodeType":1,"nodeName":"NAV","localName":"nav","attributes":[]},
        {"nodeId":4,"parentId":2,"backendNodeId":4,"nodeType":1,"nodeName":"MAIN","localName":"main","attributes":[]}
    ]}));
    for (backend, html) in [(1, &markup), (3, &navigation), (4, &main)] {
        state
            .outer_html
            .insert(("main".into(), backend), html.clone());
    }
    (markup, navigation, main)
}

fn dom_args(tab: &str, max_bytes: usize) -> Value {
    json!({"browser":"user","action":"snapshot","tab":tab,"mode":"dom_full","max_bytes":max_bytes})
}

fn comment_ref(text: &str, role: &str) -> String {
    let prefix = format!("<!-- {role} ");
    text.lines()
        .find_map(|line| line.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing {role} comment: {text}"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

#[tokio::test]
async fn over_limit_main_comes_first_and_cut_chrome_refs_are_retained() {
    let fixture = Fixture::new();
    let (_, _, main) = dashboard(&fixture);
    let tab = fixture.claim(1).await;
    let (reply, _) = fixture.call(1, dom_args(&tab, 800), "allow_30m").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    let text = reply["state_text"].as_str().unwrap();
    assert!(text.starts_with("<!-- main e"), "{text}");
    assert!(text.contains(&main), "{text}");
    assert!(text.len() <= 800, "{text}");
    assert_eq!(reply["truncated"], true);
    let navigation = comment_ref(text, "navigation");
    assert!(text.contains(&format!("; zoom {navigation} -->")), "{text}");
    let state = fixture.planes.user_browser.target().state();
    let snapshot = &state.snapshots[reply["snapshot_id"].as_str().unwrap()];
    assert!(snapshot.refs.contains_key(&navigation));
    assert!(snapshot.refs.contains_key(&comment_ref(text, "main")));
    assert_eq!(snapshot.refs.len(), 2);
}

#[tokio::test]
async fn dom_full_zoom_reads_the_named_outer_html_and_ax_still_refuses_zoom() {
    let fixture = Fixture::new();
    let (_, navigation, _) = dashboard(&fixture);
    let tab = fixture.claim(1).await;
    let (first, _) = fixture.call(1, dom_args(&tab, 800), "allow_30m").await;
    assert_eq!(first["outcome"], "ok", "{first}");
    let reference = comment_ref(first["state_text"].as_str().unwrap(), "navigation");
    let mut args = dom_args(&tab, navigation.len());
    args["zoom"] = json!(reference);
    let (zoomed, _) = fixture.call(1, args.clone(), "").await;
    assert_eq!(zoomed["outcome"], "ok", "{zoomed}");
    assert_eq!(zoomed["state_text"], navigation);
    assert_eq!(zoomed["truncated"], false);
    {
        let state = fixture.state.lock().unwrap();
        let last_html = state
            .commands
            .iter()
            .rev()
            .flat_map(|plan| plan["commands"].as_array().unwrap().iter().rev())
            .find(|command| command["method"] == "DOM.getOuterHTML")
            .unwrap();
        assert_eq!(last_html["params"]["backendNodeId"], 3);
    }

    args["max_bytes"] = json!(250);
    let (bounded, _) = fixture.call(1, args.clone(), "").await;
    assert_eq!(bounded["outcome"], "ok", "{bounded}");
    let text = bounded["state_text"].as_str().unwrap();
    assert!(text.starts_with("<nav>"), "{text}");
    assert!(text.contains("<!-- markup cut:"), "{text}");
    assert!(text.len() <= 250, "{text}");
    assert_eq!(bounded["truncated"], true);

    args["mode"] = json!("ax");
    let (refused, _) = fixture.call(1, args, "").await;
    assert_eq!(refused["outcome"], "invalid_request", "{refused}");
    assert_eq!(
        refused["detail"]["reason_code"], "unsupported_value",
        "{refused}"
    );
    assert_eq!(refused["detail"]["field"], "zoom", "{refused}");
}

#[tokio::test]
async fn dom_full_zoom_uses_the_child_session_and_rejects_a_changed_document() {
    let fixture = Fixture::new();
    let markup = "<button>Child go — only this node</button>";
    fixture
        .state
        .lock()
        .unwrap()
        .outer_html
        .insert(("foreign".into(), 3), markup.into());
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let mut args = dom_args(&tab, 5000);
    args["zoom"] = json!(reference(&snapshot, "Child go"));
    let (zoomed, _) = fixture.call(1, args.clone(), "").await;
    assert_eq!(zoomed["outcome"], "ok", "{zoomed}");
    assert_eq!(zoomed["state_text"], markup);
    {
        let state = fixture.state.lock().unwrap();
        let command = state
            .commands
            .iter()
            .rev()
            .flat_map(|plan| plan["commands"].as_array().unwrap().iter().rev())
            .find(|command| command["method"] == "DOM.getOuterHTML")
            .unwrap();
        assert_eq!(command["frame_id"], "foreign");
        assert_eq!(command["session_id"], "child-target");
        assert_eq!(command["loader_id"], "foreign-loader");
        assert_eq!(command["params"]["backendNodeId"], 3);
    }
    fixture
        .state
        .lock()
        .unwrap()
        .tabs
        .get_mut(&tab)
        .unwrap()
        .loader += 1;
    let (stale, _) = fixture.call(1, args, "").await;
    assert_eq!(stale["outcome"], "refused", "{stale}");
    assert_eq!(stale["reason"], "state_changed_by_person", "{stale}");
}

#[tokio::test]
async fn within_limit_dom_full_bytes_are_unchanged_including_frame_separators() {
    let fixture = Fixture::new();
    let (markup, _, _) = dashboard(&fixture);
    let tab = fixture.claim(1).await;
    let (reply, _) = fixture
        .call(1, dom_args(&tab, markup.len()), "allow_30m")
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(
        reply["state_text"].as_str().unwrap().as_bytes(),
        markup.as_bytes()
    );
    assert_eq!(reply["truncated"], false);

    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (reply, _) = fixture.call(1, dom_args(&tab, 5000), "allow_30m").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["state_text"], "HTML-main\nHTML-foreign");
    assert_eq!(reply["truncated"], false);
}
