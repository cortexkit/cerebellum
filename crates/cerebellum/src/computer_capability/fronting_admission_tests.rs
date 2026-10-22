//! Fronting through the plane when it may not happen, or may not happen yet:
//!
//! - a build without the app-use review fronts nothing outside the keystroke
//!   bracket, on any path. Each call site that checks the admission has a
//!   test on the first effect only that check prevents (a pre-read row, a
//!   wait on the fronting lock, a front request), since the check every
//!   temporary front makes once it holds the lock would hide the rest;
//! - a front followed by input needs something the conversation was shown of
//!   the application to check the person against;
//! - system shortcuts take the takeover route, and chords inside the
//!   application keep the app grant's;
//! - a send posted to the session as a whole and still in flight stops every
//!   front.

use super::*;

/// The `fronting` of a foreground action in a build that may not front.
fn foreground_unfronted() -> Value {
    json!({"mode":"foreground","fronted":false,"purpose":"foreground_mode",
        "restore":"not_needed","not_fronted_reason":"fronting_unavailable"})
}

/// The front requests the screen received, in order.
fn front_requests(rig: &Rig) -> Vec<String> {
    rig.screen
        .log()
        .into_iter()
        .filter(|entry| entry.starts_with("front:"))
        .collect()
}

/// A plane built without the app-use review. `bracket` says whether the
/// takeover review, which admits today's keystroke bracket, is carried.
async fn unadmitted(mode: AppUse, desk: support::Desk, bracket: bool) -> Rig {
    rig_admitting(
        mode,
        desk,
        support::granted_management().await,
        false,
        bracket,
    )
}

/// Hold the takeover grant for the fixture conversation.
async fn grant_takeover(rig: &Rig) {
    let carrier = support::ScriptedCarrier::answering(&["computer_30m"]);
    rig.management
        .computer_grants()
        .require(
            &crate::computer_grants::GrantNeed::Takeover,
            &support::relayed(&carrier),
            &crate::CancelHandle::pending(),
        )
        .await
        .unwrap();
}

fn bring_to_front_read() -> Value {
    json!({"target": support::TARGET_BUNDLE_ID, "include_image": true, "bring_to_front": true})
}

/// The id of the first element of the desk's first window, given to the
/// fixture conversation by numbering a read directly, outside the plane's
/// read path, so no seen marks are recorded with it. A read the plane
/// serves always records them; this is the only way to hold an element id
/// with no seen baseline behind it.
fn first_id_never_seen(rig: &Rig) -> String {
    let raw = rig
        .desk
        .source()
        .read_app_state(&support::grant(), Default::default())
        .unwrap();
    let read = rig.management.app_state_sessions().observe(
        &support::identity().conversation_key,
        &support::grant(),
        &raw,
    );
    assert!(!rig.seen_marks_recorded());
    read.roots[0].children[0]
        .element_id
        .clone()
        .expect("the element is numbered")
}

/// A reply that refused because the conversation never read the target:
/// nothing fronted, the unreadable person check's reason, and a remedy
/// asking for a read.
fn assert_never_read(reply: &Value) {
    assert_eq!(reply["outcome"], "not_fronted", "{reply}");
    assert_eq!(reply["remedy"], NEVER_READ_REMEDY, "{reply}");
    assert_eq!(reply["fronting"]["fronted"], false, "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"],
        not_fronted_reason(FrontingStop::PersonCheckUnreadable).as_str(),
        "{reply}"
    );
}

// ---------------------------------------------------------------------------
// A build without the app-use review fronts nothing outside the bracket
// ---------------------------------------------------------------------------

/// Foreground mode in a build without the app-use review: a read goes ahead
/// unfronted, saying fronting is unavailable, and no front is requested.
#[tokio::test]
async fn without_the_review_a_foreground_read_requests_no_front() {
    let rig = unadmitted(AppUse::Foreground, mail_desk(), true).await;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.read_state",
            json!({"target": support::TARGET_BUNDLE_ID}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"], foreground_unfronted(), "{reply}");
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(!rig.lock.held());
}

/// Foreground mode in a build without the app-use review: a press, a
/// Command chord and `open_app` front nothing. The press goes ahead
/// unfronted, the chord to a background application is refused because
/// fronting under the app grant is not admitted and the caller holds no
/// takeover, and the opened application is left where it is.
#[tokio::test]
async fn without_the_review_a_foreground_press_chord_or_open_app_requests_no_front() {
    let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
    let send = rig.send_id().await;
    let rig = rig.with_mode(AppUse::Foreground);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"], foreground_unfronted(), "{reply}");
    assert_eq!(rig.desk.state().presses, [10]);

    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(
        reply["outcome"], "modifier_chord_needs_foreground",
        "{reply}"
    );
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());

    let management = apps_management();
    Who::fixture()
        .grant(&management, support::TARGET_BUNDLE_ID)
        .await;
    let rig = rig_admitting(
        AppUse::Foreground,
        installed_desk(true),
        management,
        false,
        true,
    );
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.open_app",
            json!({"target": "Safari"}),
        )
        .await;
    assert_eq!(reply["outcome"], "already_running", "{reply}");
    assert_eq!(reply["fronting"], foreground_unfronted(), "{reply}");
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(!rig.lock.held());
}

/// Foreground mode in a build without the app-use review: typing and a
/// write go to the application where it is, unfronted.
#[tokio::test]
async fn without_the_review_foreground_typing_and_writes_request_no_front() {
    let rig = unadmitted(AppUse::Background, support::focused_text_desk(), true).await;
    rig.desk
        .state()
        .elements
        .get_mut(&2)
        .unwrap()
        .facts
        .value_settable = true;
    let reply = rig.read().await;
    // The state text is a header line, the window, then the text field.
    let field = reply["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .nth(2)
        .and_then(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .unwrap_or_else(|| panic!("no text field in {reply}"));
    let rig = rig.with_mode(AppUse::Foreground);

    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.type",
            json!({"target": support::TARGET_BUNDLE_ID, "text": "hi"}),
        )
        .await;
    assert_ne!(reply["outcome"], "not_fronted", "{reply}");
    assert_eq!(reply["fronting"], foreground_unfronted(), "{reply}");
    assert_eq!(
        rig.screen.log(),
        ["post"],
        "typed per process, never fronted"
    );

    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.write_text",
            json!({"element_id": field, "text": "hello", "write_mode": "replace_value"}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"], foreground_unfronted(), "{reply}");
    assert!(front_requests(&rig).is_empty(), "{:?}", rig.screen.log());
    assert!(!rig.lock.held());
}

/// Background mode in a build without the app-use review: a press on a
/// button disabled in the background is refused `element_disabled` without
/// the pre-read that decides whether to front the application: the press's
/// own row is the only one it writes.
#[tokio::test]
async fn without_the_review_a_disabled_background_press_skips_the_needs_front_pre_read() {
    let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    let before = journal_results(&rig).len();
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "element_disabled", "{reply}");
    assert!(reply.get("fronting").is_none(), "{reply}");
    assert!(rig.desk.state().presses.is_empty());
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    let rows = journal_results(&rig);
    let added = &rows[before..];
    assert_eq!(added.len(), 1, "only the press's own row: {added:?}");
    assert!(!rig.lock.held());
}

/// Background mode in a build without the app-use review: a Command chord
/// to a background application, from a caller without takeover, is refused
/// `modifier_chord_needs_foreground` at once. It never waits on the
/// fronting lock, which another call holds here.
#[tokio::test(start_paused = true)]
async fn without_the_review_a_background_chord_is_refused_without_waiting_on_the_lock() {
    let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
    rig.read().await;
    let held = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(
        reply["outcome"], "modifier_chord_needs_foreground",
        "{reply}"
    );
    assert!(
        started.elapsed() < Duration::from_millis(crate::budgets::FRONTING_LOCK_WAIT_MS),
        "the chord waited on the fronting lock: {:?}",
        started.elapsed()
    );
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    drop(held);
}

/// A build carrying neither review: a `bring_to_front` image read under
/// held takeover fronts nothing at all.
#[tokio::test]
async fn without_either_review_a_bring_to_front_read_requests_no_front() {
    let rig = unadmitted(AppUse::Background, mail_desk(), false).await;
    grant_takeover(&rig).await;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.read_state",
            bring_to_front_read(),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(reply.get("image").is_none(), "{reply}");
    assert!(reply.get("fronting").is_none(), "{reply}");
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(!rig.lock.held());
}

/// A build carrying the takeover review but not the app-use review: a
/// `bring_to_front` image read under held takeover runs today's keystroke
/// bracket, which never takes the fronting lock, so another call holding
/// the lock does not hold it up.
#[tokio::test(start_paused = true)]
async fn without_the_review_a_bring_to_front_read_runs_the_bracket_without_the_lock() {
    let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
    grant_takeover(&rig).await;
    let held = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.read_state",
            bring_to_front_read(),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(
        started.elapsed() < Duration::from_millis(crate::budgets::FRONTING_LOCK_WAIT_MS),
        "the read waited on the fronting lock: {:?}",
        started.elapsed()
    );
    // Today's bracket puts the previous application back with a plain
    // front request.
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "read", "front:100"],
        "{reply}"
    );
    drop(held);
}

/// The check every temporary front makes for itself once it holds the
/// lock: in a build that may not front, preparing one fails, whichever
/// caller asked, and the lock is released again.
#[tokio::test]
async fn a_temporary_front_is_never_prepared_where_fronting_is_not_admitted() {
    let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
    let who = Who::fixture();
    let consent = who.consent();
    let cancel = crate::CancelHandle::pending();
    let grant = support::grant();
    let prepared = crate::CALL_TERMINAL
        .scope(under_terminal(), async {
            rig.plane
                .prepare_temporary_front(
                    FrontCall {
                        grant: &grant,
                        consent: &consent,
                        cancel: &cancel,
                        management: &rig.management,
                        conversation_key: &who.identity.conversation_key,
                        input_follows: false,
                    },
                    crate::terminal_arbiter::FrontingPurpose::BringToFront,
                    true,
                )
                .await
                .map(|_| ())
        })
        .await;
    assert_eq!(
        prepared.err().map(|stopped| stopped.stop),
        Some(FrontingStop::FrontingNotAdmitted)
    );
    assert!(!rig.lock.held());
    assert!(rig.screen.log().is_empty());
}

// ---------------------------------------------------------------------------
// System shortcuts need takeover; chords inside the application do not
// ---------------------------------------------------------------------------

fn keys(chord: &[&str]) -> Value {
    json!({"keys": chord, "target": support::TARGET_BUNDLE_ID})
}

/// Command-Space opens Spotlight whichever application receives it, so the
/// app grant does not admit it even with the application already in front:
/// without takeover it is refused, naming the takeover permission, and
/// nothing is posted. Foreground mode does not front the application for a
/// chord it then refuses. With takeover held it runs in the takeover bracket.
#[tokio::test]
async fn a_system_shortcut_takes_the_takeover_route_even_to_a_frontmost_app() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    rig.desk.state().frontmost = Some(TARGET);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.keys",
            keys(&["command", "space"]),
        )
        .await;
    assert_eq!(
        reply["outcome"], "modifier_chord_needs_foreground",
        "{reply}"
    );
    assert_eq!(reply["reason"], "modifier_chord_needs_foreground");
    let remedy = reply["remedy"].as_str().unwrap();
    assert!(
        remedy.contains("takeover permission") && remedy.contains("mouse and keyboard"),
        "{remedy}"
    );
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());

    let rig = rig.with_mode(AppUse::Foreground);
    rig.desk.state().frontmost = Some(PREVIOUS);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.keys",
            keys(&["command", "tab"]),
        )
        .await;
    assert_eq!(
        reply["outcome"], "modifier_chord_needs_foreground",
        "{reply}"
    );
    assert!(
        rig.screen.log().is_empty(),
        "nothing fronted for a refused chord: {:?}",
        rig.screen.log()
    );

    let rig = rig.with_mode(AppUse::Background);
    rig.desk.state().frontmost = Some(TARGET);
    grant_takeover(&rig).await;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.keys",
            keys(&["command", "space"]),
        )
        .await;
    assert_ne!(
        reply["outcome"], "modifier_chord_needs_foreground",
        "{reply}"
    );
    assert!(reply["remedy"].is_null(), "{reply}");
    assert!(
        rig.screen.log().contains(&"post".to_owned()),
        "posted in the takeover bracket: {:?}",
        rig.screen.log()
    );
}

/// Command-Q quits only the application that receives it, so it stays under
/// the app grant like any chord inside the application: to an application
/// in the background it is fronted, posted and restored with no takeover.
#[tokio::test]
async fn a_command_q_to_a_background_app_keeps_the_app_grant_route() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", keys(&["command", "q"]))
        .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "post", "restore:100"]);
    assert_eq!(reply["fronting"]["purpose"], "needs_front", "{reply}");
}

// ---------------------------------------------------------------------------
// A front followed by input needs a seen baseline
// ---------------------------------------------------------------------------

/// A Command chord to a background application the conversation never read
/// is not fronted: there is nothing to check the person against. Once read,
/// the same chord fronts, posts and restores.
#[tokio::test]
async fn a_background_chord_to_an_app_never_read_fronts_nothing_until_it_is_read() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_never_read(&reply);
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(!rig.lock.held());

    rig.read().await;
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "post", "restore:100"]);
}

/// Foreground mode: keys, typing and a write to an application the
/// conversation never read do not front it, and send nothing.
#[tokio::test]
async fn foreground_input_to_an_app_never_read_fronts_nothing() {
    let rig = rig(AppUse::Foreground, support::focused_text_desk()).await;
    let field = first_id_never_seen(&rig);
    for (name, arguments) in [
        ("computer.keys", command_chord()),
        (
            "computer.type",
            json!({"target": support::TARGET_BUNDLE_ID, "text": "hi"}),
        ),
        (
            "computer.write_text",
            json!({"element_id": field, "text": "hello", "write_mode": "replace_value"}),
        ),
    ] {
        let reply = rig.call_under(&under_terminal(), name, arguments).await;
        assert_never_read(&reply);
        assert!(
            rig.screen.log().is_empty(),
            "{name}: {:?}",
            rig.screen.log()
        );
    }
    assert_eq!(
        rig.desk.state().elements[&2].value.as_deref(),
        Some(""),
        "nothing was written"
    );
}

/// A foreground press, and a background press on a button disabled in the
/// background, on an element of an application the conversation was never
/// shown: neither fronts it nor presses.
#[tokio::test]
async fn a_press_on_an_app_never_read_fronts_nothing() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    let send = first_id_never_seen(&rig);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_never_read(&reply);

    let rig = rig.with_mode(AppUse::Background);
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_never_read(&reply);
    assert!(rig.desk.state().presses.is_empty());
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(!rig.lock.held());
}

// ---------------------------------------------------------------------------
// Guard (0) and a session-wide send still in flight
// ---------------------------------------------------------------------------

/// Another call's takeover drag, posted to the session as a whole and still
/// in flight with the mouse button down, stops this conversation's fronts:
/// a foreground read goes ahead unfronted and a background chord is not
/// fronted, both saying held input is unconfirmed. Once that send returns
/// with nothing held, the chord fronts.
#[tokio::test]
async fn a_live_session_wide_send_from_another_call_stops_every_front() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    let drag = SyntheticAction::drag_pointer(
        cerebellum_computer::platform::SyntheticPoint { x: 1.0, y: 1.0 },
        cerebellum_computer::platform::SyntheticPoint { x: 2.0, y: 2.0 },
    );
    // The other call's own terminal is live: its send is in flight, not
    // stuck, and nothing is quarantined.
    let other_call = under_terminal();
    let ticket = rig.plane.held_input.begin_send(
        super::super::held_input::HeldPress::global(&other_app(), &drag).unwrap(),
        Some(other_call),
    );
    assert!(matches!(rig.plane.held_input.pending_release(), Ok(None)));

    let reply = rig.read().await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "held_input_unconfirmed",
        "{reply}"
    );
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());

    let rig = rig.with_mode(AppUse::Background);
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(reply["outcome"], "not_fronted", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "held_input_unconfirmed",
        "{reply}"
    );
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());

    ticket.settle(HeldStateDisposition::NoneHeld, |_| false);
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242", "post", "restore:100"]);
}
