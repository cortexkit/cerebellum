use super::*;

// A page can react to the agent focusing a field before the agent's next
// typing plan. History-only reactions may continue; document changes and
// interaction-epoch signals must stop the type and name the signal.

async fn type_into_reacting_field(reaction: PageReaction) -> (Value, Vec<String>, String) {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    fixture.state.lock().unwrap().page_reaction = Some(reaction);
    let (reply, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot, "Message"),"text":"rust language"}),
            "allow_30m",
        )
        .await;
    let state = fixture.state.lock().unwrap();
    (reply, state.inputs.clone(), state.typed_value.clone())
}

#[tokio::test]
async fn same_url_history_reactions_to_focus_allow_all_text() {
    for reaction in [PageReaction::PushSameUrl, PageReaction::ReplaceState] {
        let (reply, inputs, value) = type_into_reacting_field(reaction).await;
        assert_eq!(reply["outcome"], "ok", "{reaction:?}: {reply}");
        assert!(reply.get("reason").is_none(), "{reaction:?}: {reply}");
        assert_eq!(inputs, ["DOM.focus", "Input.insertText"], "{reaction:?}");
        assert_eq!(value, "rust language", "{reaction:?}");
    }
}

#[tokio::test]
async fn a_history_change_before_dispatch_still_refuses_all_input() {
    for during_classification in [false, true] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
        {
            let mut state = fixture.state.lock().unwrap();
            if during_classification {
                state.history_during_classification = true;
            } else {
                state.history = Some(same_url_push_state(state.tabs.get(&tab).unwrap()));
            }
        }
        let (reply, _) = fixture
            .call(
                1,
                json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot, "Message"),"text":"rust language"}),
                "allow_30m",
            )
            .await;
        assert_eq!(reply["reason"], "state_changed_by_person", "{reply}");
        assert_eq!(reply["input_dispatched"], false, "{reply}");
        assert!(fixture.state.lock().unwrap().inputs.is_empty());
    }
}

#[tokio::test]
async fn unsafe_reactions_to_focus_still_stop_before_text_and_name_the_cause() {
    let epoch = |cause: &str| json!({"check":"interaction_epoch","cause":cause});
    let document = |entry: bool, index: bool, length: bool, url: bool| json!({"check":"committed_document","history_entry_changed":entry,"history_index_changed":index,"history_length_changed":length,"url_changed":url,"loader_changed":false});
    for (reaction, reason, detail) in [
        (
            PageReaction::ExecCommand,
            "state_changed_by_person",
            Some(epoch("input.input.main")),
        ),
        (PageReaction::ChildNavigation, "observer_unavailable", None),
        (
            PageReaction::Reload,
            "state_changed_by_person",
            Some(
                json!({"check":"committed_document","history_entry_changed":true,"history_index_changed":false,"history_length_changed":false,"url_changed":false,"loader_changed":true}),
            ),
        ),
        (
            PageReaction::PushState,
            "state_changed_by_person",
            Some(document(true, true, true, true)),
        ),
        (
            PageReaction::PersonKey,
            "state_changed_by_person",
            Some(epoch("input.keydown.main")),
        ),
        (
            PageReaction::PersonClick,
            "state_changed_by_person",
            Some(epoch("input.pointerdown.main")),
        ),
        (
            PageReaction::PersonScroll,
            "state_changed_by_person",
            Some(epoch("input.wheel.main")),
        ),
        (
            PageReaction::ForeignCause,
            "state_changed_by_person",
            Some(epoch("unrecognized")),
        ),
    ] {
        let (reply, inputs, value) = type_into_reacting_field(reaction).await;
        assert_eq!(reply["outcome"], "outcome_unknown", "{reaction:?}: {reply}");
        assert_eq!(reply["reason"], reason, "{reaction:?}: {reply}");
        assert_eq!(reply["input_dispatched"], true, "{reaction:?}: {reply}");
        assert_eq!(
            reply.get("detail"),
            detail.as_ref(),
            "{reaction:?}: {reply}"
        );
        // The focus step ran; the text was never inserted.
        assert_eq!(inputs, ["DOM.focus"], "{reaction:?}");
        assert!(value.is_empty(), "{reaction:?}: {value}");
    }
}

/// The text a model reads for a type stopped by a page reaction names the
/// signal that stopped it, as the structured `detail` does: without that line
/// a model cannot tell a person's input from the page reacting to its own.
#[tokio::test]
async fn a_stopped_type_prints_the_signal_that_stopped_it() {
    for (reaction, signal) in [
        (
            PageReaction::ExecCommand,
            "Signal: input.input.main (a trusted input event in the main frame, outside the agent's own input).",
        ),
        (
            PageReaction::Reload,
            "Signal: committed_document (the tab's committed document changed: history entry, document loader).",
        ),
        (
            PageReaction::PushState,
            "Signal: committed_document (the tab's committed document changed: history entry, history position, history length, URL).",
        ),
        (
            PageReaction::PersonKey,
            "Signal: input.keydown.main (a trusted keydown event in the main frame, outside the agent's own input).",
        ),
        (
            PageReaction::ForeignCause,
            "Signal: unrecognized (the extension sent a code outside the known vocabulary).",
        ),
    ] {
        let (reply, _, _) = type_into_reacting_field(reaction).await;
        let encoded: Value =
            serde_json::from_slice(&crate::tool_result::encode(reply.clone()).unwrap()).unwrap();
        let text = encoded["content"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|part| part["text"].as_str())
            .collect::<Vec<_>>()
            .join("\n");
        let expected = [
            "Outcome unknown.",
            "Input was dispatched and may have taken effect. Do not repeat this action; take a fresh read before deciding what to do next.",
            "Input was dispatched to the person's browser.",
            "Reason: state changed by person.",
            signal,
        ]
        .join("\n");
        assert_eq!(text, expected, "{reaction:?}: {reply}");
    }
}

#[tokio::test]
async fn a_type_without_page_reaction_inserts_its_text() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    let (reply, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot, "Message"),"text":"typed"}),
            "allow_30m",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(
        fixture.state.lock().unwrap().inputs,
        ["DOM.focus", "Input.insertText"]
    );
}

#[test]
fn only_the_extensions_closed_cause_vocabulary_reaches_a_reply() {
    for code in [
        "input.keydown.main",
        "input.beforeinput.subframe",
        "navigation.main",
        "navigation.subframe",
    ] {
        assert_eq!(recognized_cause(Some(code.into())).as_deref(), Some(code));
    }
    for code in [
        "input.focus.main",
        "input.keydown.main.extra",
        "input.keydown.sidebar",
        "navigation.https://private.example/secret",
        "typed hunter2",
    ] {
        assert_eq!(
            recognized_cause(Some(code.into())).as_deref(),
            Some("unrecognized"),
            "{code}"
        );
    }
    assert_eq!(recognized_cause(None), None);
}

#[test]
fn cause_events_are_exactly_the_ones_the_extension_observes() {
    let source = include_str!("../../../../../extension/sentinel.js");
    let declared = source
        .lines()
        .find_map(|line| line.trim().strip_prefix("const types = "))
        .and_then(|list| list.strip_suffix(';'))
        .expect("sentinel.js declares its observed event types");
    let declared: Vec<String> = serde_json::from_str(declared).unwrap();
    assert_eq!(declared, OBSERVED_INPUT_EVENTS);
}
