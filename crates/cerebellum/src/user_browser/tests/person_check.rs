use super::*;

// A page can react to the agent focusing a field before the agent's next
// typing plan. Each reaction below is a candidate for a type stopped half-way,
// and each must produce its own refusal cause, so a stopped type on a real page
// says which signal stopped it.

async fn type_into_reacting_field(reaction: PageReaction) -> (Value, Vec<String>) {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_origin_always").await;
    fixture.state.lock().unwrap().page_reaction = Some(reaction);
    let (reply, _) = fixture
        .call(
            1,
            json!({"browser":"user","action":"type","tab":tab,"ref":reference(&snapshot, "Message"),"text":"not typed"}),
            "allow_30m",
        )
        .await;
    let inputs = fixture.state.lock().unwrap().inputs.clone();
    (reply, inputs)
}

#[tokio::test]
async fn each_page_reaction_to_focus_names_its_own_cause() {
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
            PageReaction::ReplaceState,
            "state_changed_by_person",
            Some(document(true, false, false, false)),
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
            PageReaction::ForeignCause,
            "state_changed_by_person",
            Some(epoch("unrecognized")),
        ),
    ] {
        let (reply, inputs) = type_into_reacting_field(reaction).await;
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
