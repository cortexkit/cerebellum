//! An element action that shows the agent's badge waits for the badge to
//! reach what it acts on, and only then presses or writes, so the real action
//! and the badge's tap happen together. With nothing to see it does not wait.
//!
//! Every timing claim here runs on tokio's paused clock, which moves only
//! while every task waits on a timer (never while blocking work runs), so it
//! is exact rather than a real-time guess. The desk records, on that clock,
//! when each press and write reached it.

use super::support;

use std::sync::Arc;
use std::time::Duration;

use cerebellum::computer_capability::cursor::Coordinator;
use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::management::ManagementPlane;
use cerebellum::CancelHandle;
use cerebellum_computer::app_state::source::{ElementFacts, RawElement};
use cerebellum_computer::capture::{EnumeratedWindow, InMemoryCaptureBackend, WindowFrame};
use cerebellum_computer::cursor::{duration_ms, entry_ms, CursorEvent, CursorLine, MotionStyle};
use cerebellum_computer::platform::ProcessGrant;
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use serde_json::{json, Value};
use support::computer::{
    audit, facts, grant, granted_management, identity, live_permissions, no_relay, Desk,
    DeskElement, DeskFocus, DeskHook, TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};
use tokio::sync::mpsc;
use tokio::time::Instant;

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
>;

/// Three buttons far enough apart that each press sends the badge on a
/// glide of its own length: 400 points across, then 600 down.
const BUTTONS: [(u64, &str, [f64; 4]); 3] = [
    (20, "One", [100.0, 100.0, 80.0, 20.0]),
    (21, "Two", [500.0, 100.0, 80.0, 20.0]),
    (22, "Three", [500.0, 700.0, 80.0, 20.0]),
];
const FIELD: (u64, &str, [f64; 4]) = (30, "Composer", [100.0, 400.0, 300.0, 24.0]);

/// The longest any action may wait for its badge, as the call's work budget
/// counts it.
const CAP: Duration = Duration::from_millis(cerebellum::budgets::CURSOR_ARRIVAL_MS);

/// The agent whose badge a call by the fixture identity draws.
fn agent() -> String {
    identity().agent_project_id
}

fn centre(frame: [f64; 4]) -> [f64; 2] {
    [frame[0] + frame[2] / 2.0, frame[1] + frame[3] / 2.0]
}

fn ms(value: f64) -> Duration {
    Duration::from_secs_f64(value / 1000.0)
}

/// How long the badge takes to glide between two element centres, with or
/// without Reduce Motion (each picture line says which the module used).
fn glide(from: [f64; 4], to: [f64; 4], reduce_motion: bool) -> Duration {
    let (from, to) = (centre(from), centre(to));
    ms(duration_ms(
        (to[0] - from[0]).hypot(to[1] - from[1]),
        reduce_motion,
    ))
}

fn desk() -> Desk {
    let mut children: Vec<RawElement> = BUTTONS
        .iter()
        .map(|(token, title, _)| RawElement::fixture(*token, "AXButton").titled(title))
        .collect();
    children.push(RawElement::fixture(FIELD.0, "AXTextField").titled(FIELD.1));
    let mut desk = Desk::new(vec![RawElement::fixture(1, "AXWindow")
        .titled("Chat")
        .with_children(children)]);
    for (token, _, _) in BUTTONS {
        desk = desk.with_element(
            token,
            DeskElement {
                facts: facts("AXButton", &["AXPress"]),
                ..DeskElement::default()
            },
        );
    }
    desk = desk.with_element(
        FIELD.0,
        DeskElement {
            facts: ElementFacts {
                value_settable: true,
                ..facts("AXTextField", &[])
            },
            value: Some(String::new()),
            applies_writes: true,
            ..DeskElement::default()
        },
    );
    {
        let mut state = desk.state();
        state.cursor_visible = true;
        state.cursor_frames.insert(1, [0.0, 0.0, 800.0, 600.0]);
        for (token, _, frame) in BUTTONS.iter().chain([&FIELD]) {
            state.cursor_frames.insert(*token, *frame);
            state.cursor_windows.insert(*token, 1);
        }
    }
    desk
}

// Point-action fixtures capture fake windows, whose visibility cannot be read
// from the real desktop. Certify only the fixture's fully visible window.
struct VisibleFixture;
impl cerebellum::computer_capability::image_freshness::ImageFreshnessSource for VisibleFixture {
    fn inspect(
        &self,
        _: &ProcessGrant,
        _: Option<&str>,
    ) -> (
        bool,
        cerebellum::computer_capability::image_freshness::WindowVisibility,
    ) {
        (
            false,
            cerebellum::computer_capability::image_freshness::WindowVisibility::FullyVisible,
        )
    }
}

/// A plane in foreground mode: these tests are about the on-screen badge,
/// which background mode (the default) never draws.
fn plane(desk: &Desk) -> Plane {
    ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold)
        .with_foreground_app_use_for_test()
        .with_permission_liveness(live_permissions())
        .with_app_state_source(desk.source())
        .with_image_freshness_source(Arc::new(VisibleFixture))
}

async fn serve_with(
    plane: &Plane,
    management: &Arc<ManagementPlane>,
    cancel: CancelHandle,
    name: &str,
    arguments: Value,
    backend: InMemoryCaptureBackend,
) -> Value {
    let clock = FakeClock::new();
    plane
        .serve(
            servable(name).expect("the capability is served"),
            &arguments,
            ServeContext {
                cancel,
                grantee: GRANTEE,
                identity: identity(),
                management,
                consent: no_relay(),
                clock: &clock,
                now_ms: 10,
            },
            move |_| backend,
        )
        .await
        .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
}

async fn serve(
    plane: &Plane,
    management: &Arc<ManagementPlane>,
    name: &str,
    arguments: Value,
) -> Value {
    serve_with(
        plane,
        management,
        CancelHandle::pending(),
        name,
        arguments,
        InMemoryCaptureBackend::default(),
    )
    .await
}

/// The state's text, read so the actions after it have ids to name and a
/// read to compare the person's activity against.
async fn read(plane: &Plane, management: &Arc<ManagementPlane>) -> String {
    let reply = serve(
        plane,
        management,
        "computer.read_state",
        json!({"target": TARGET_BUNDLE_ID}),
    )
    .await;
    reply["state_text"]
        .as_str()
        .unwrap_or_else(|| panic!("no state in {reply}"))
        .to_owned()
}

fn id_of(tree: &str, needle: &str) -> String {
    tree.lines()
        .find(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle} in\n{tree}"))
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned()
}

/// The next line the helper would draw, which must be a picture.
async fn picture(pictures: &mut mpsc::Receiver<CursorLine>) -> CursorEvent {
    pictures
        .recv()
        .await
        .expect("the pipe stays open")
        .picture()
        .expect("a picture, not a hide or a follow")
}

/// A desk, its plane with a live badge, and a read made with the badge on,
/// so the badge already shows and the next action glides to its target.
struct Rig {
    desk: Desk,
    plane: Plane,
    management: Arc<ManagementPlane>,
    cursor: Coordinator,
    pictures: mpsc::Receiver<CursorLine>,
    tree: String,
}

async fn rig_with_badge_shown() -> Rig {
    let desk = desk();
    let (cursor, mut pictures) = Coordinator::channel();
    let plane = plane(&desk).with_cursor(cursor.clone());
    let management = granted_management().await;
    let tree = read(&plane, &management).await;
    // The read's own picture: the badge appears.
    picture(&mut pictures).await;
    Rig {
        desk,
        plane,
        management,
        cursor,
        pictures,
        tree,
    }
}

// ---------------------------------------------------------------------------
// When the action is sent
// ---------------------------------------------------------------------------

/// The badge's first appearance plays its entry on the target, so a press,
/// a point press and a write each wait for the entry to end and are sent
/// then: not before, and no later than the cap.
#[tokio::test(start_paused = true)]
async fn an_action_with_a_drawn_badge_is_sent_when_the_badge_arrives_and_not_before() {
    for action in [
        "computer.press_element",
        "computer.write_text",
        "computer.press_point",
    ] {
        let desk = desk();
        {
            let mut state = desk.state();
            state.application_hit = Some((BUTTONS[0].0, Some(grant().pid)));
            state.element_windows.insert(BUTTONS[0].0, 77);
        }
        let base = plane(&desk);
        let management = granted_management().await;
        // Read without a badge, so the action's own picture is the first.
        let tree = read(&base, &management).await;
        let image = serve_with(
            &base,
            &management,
            CancelHandle::pending(),
            "computer.read_state",
            json!({"target": TARGET_BUNDLE_ID, "include_image": true}),
            capturing(),
        )
        .await["image"]["image_id"]
            .as_str()
            .expect("an image")
            .to_owned();
        let (cursor, mut pictures) = Coordinator::channel();
        let plane = base.with_cursor(cursor);
        let arguments = match action {
            "computer.press_element" => json!({"element_id": id_of(&tree, "One")}),
            "computer.write_text" => json!({
                "element_id": id_of(&tree, "Composer"),
                "text": "hello",
                "write_mode": "replace_value",
            }),
            _ => json!({"image_id": image, "x": 625, "y": 125}),
        };
        let start = Instant::now();
        let reply = serve(&plane, &management, action, arguments).await;
        assert_eq!(reply["outcome"], "completed", "{action}: {reply}");
        assert!(plane.result_schema_findings().is_empty(), "{action}");
        let drawn = picture(&mut pictures).await;
        assert!(drawn.label.is_some(), "{action}");
        assert_eq!(drawn.motion.style, MotionStyle::Entry, "{action}");
        let entry = ms(entry_ms(drawn.motion.reduce_motion));
        assert_eq!(ms(drawn.motion.duration_ms), entry, "{action}");
        let sent = desk.state().dispatched_at.clone();
        assert_eq!(sent.len(), 1, "{action}: one action reached the desk");
        assert!(
            sent[0] >= start + entry,
            "{action}: sent {:?} after it was asked for, before the badge's {entry:?} entry ended",
            sent[0] - start
        );
        assert!(
            sent[0] <= start + CAP,
            "{action}: waited {:?}, past the {CAP:?} cap",
            sent[0] - start
        );
    }
}

/// With no badge to draw, an action is sent at once: the badge is switched
/// off, or the element's place cannot be read so no picture goes out.
#[tokio::test(start_paused = true)]
async fn with_no_badge_to_draw_the_action_is_sent_at_once() {
    for case in ["badge switched off", "no geometry"] {
        let desk = desk();
        let base = plane(&desk);
        let management = granted_management().await;
        let tree = read(&base, &management).await;
        let (cursor, mut pictures) = Coordinator::channel();
        let plane = if case == "badge switched off" {
            base
        } else {
            desk.state().cursor_visible = false;
            base.with_cursor(cursor)
        };
        let start = Instant::now();
        let reply = serve(
            &plane,
            &management,
            "computer.press_element",
            json!({"element_id": id_of(&tree, "One")}),
        )
        .await;
        assert_eq!(reply["outcome"], "completed", "{case}: {reply}");
        assert_eq!(
            desk.state().dispatched_at,
            [start],
            "{case}: the press waited for a badge nobody sees"
        );
        if case == "no geometry" {
            assert!(matches!(
                pictures.try_recv().expect("hide any old badge"),
                CursorLine::Hide(_)
            ));
        }
        assert!(pictures.try_recv().is_err(), "{case}: no picture was drawn");
    }
}

#[tokio::test(start_paused = true)]
async fn a_refused_press_draws_nothing_and_does_not_wait_for_arrival() {
    for case in ["no press offered", "no screen position"] {
        let desk = desk();
        let base = plane(&desk);
        let management = granted_management().await;
        let tree = read(&base, &management).await;
        {
            let mut state = desk.state();
            if case == "no press offered" {
                state
                    .elements
                    .get_mut(&BUTTONS[0].0)
                    .unwrap()
                    .facts
                    .actions
                    .clear();
            } else {
                state.press_frame = None;
            }
        }
        let (cursor, mut pictures) = Coordinator::channel();
        let plane = base.with_cursor(cursor);
        let start = Instant::now();
        let reply = serve(
            &plane,
            &management,
            "computer.press_element",
            json!({"element_id": id_of(&tree, "One")}),
        )
        .await;
        assert_eq!(reply["outcome"], "no_press_action", "{case}: {reply}");
        assert!(
            pictures.try_recv().is_err(),
            "{case}: a refused press drew a badge"
        );
        assert_eq!(
            Instant::now(),
            start,
            "{case}: a refused press waited for arrival"
        );
        assert!(desk.state().dispatched_at.is_empty());
    }
}

/// A batch presses its elements one by one, each when its own badge has
/// arrived: the first after the entry, each later one a glide after the one
/// before, from that element to the next.
#[tokio::test(start_paused = true)]
async fn a_batch_of_three_waits_for_each_badge_in_turn() {
    let desk = desk();
    let base = plane(&desk);
    let management = granted_management().await;
    let tree = read(&base, &management).await;
    let (cursor, mut pictures) = Coordinator::channel();
    let plane = base.with_cursor(cursor);
    let ids: Vec<String> = BUTTONS
        .iter()
        .map(|(_, title, _)| id_of(&tree, title))
        .collect();
    let start = Instant::now();
    let reply = serve(
        &plane,
        &management,
        "computer.press_element",
        json!({"element_ids": ids}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(desk.state().presses, [20, 21, 22], "pressed in order");
    let mut drawn = Vec::new();
    for (_, _, frame) in BUTTONS {
        let next = picture(&mut pictures).await;
        assert_eq!(next.to, centre(frame));
        drawn.push(next);
    }
    let sent = desk.state().dispatched_at.clone();
    assert!(sent[0] >= start);
    for step in 1..3 {
        let expected = glide(
            BUTTONS[step - 1].2,
            BUTTONS[step].2,
            drawn[step].motion.reduce_motion,
        );
        assert_eq!(
            ms(drawn[step].motion.duration_ms),
            expected,
            "press {}: the glide from the previous element",
            step + 1
        );
        let waited = sent[step] - sent[step - 1];
        assert!(
            waited >= expected && waited <= expected + Duration::from_millis(1),
            "press {} waited {waited:?} after the one before, not its {expected:?} glide",
            step + 1
        );
    }
}

// ---------------------------------------------------------------------------
// What stops an action while its badge travels
// ---------------------------------------------------------------------------

/// A cancel that lands while the badge is on its way sends nothing, and the
/// reply says the call was cancelled before anything was dispatched.
#[tokio::test(start_paused = true)]
async fn cancelling_while_the_badge_travels_sends_nothing_and_replies_cancelled() {
    let mut rig = rig_with_badge_shown().await;
    let cancel = CancelHandle::pending();
    let (reply, ()) = tokio::join!(
        serve_with(
            &rig.plane,
            &rig.management,
            cancel.clone(),
            "computer.press_element",
            json!({"element_id": id_of(&rig.tree, "One")}),
            InMemoryCaptureBackend::default(),
        ),
        async {
            picture(&mut rig.pictures).await;
            cancel.cancel();
        }
    );
    assert_eq!(reply["outcome"], "cancelled", "{reply}");
    assert_eq!(reply["detail"]["dispatched"], false, "{reply}");
    assert!(rig.desk.state().presses.is_empty(), "nothing was pressed");
    assert!(rig.plane.result_schema_findings().is_empty());
}

/// The person using the application while the badge travels is seen right
/// before the press would be sent: a key press, click or scroll in the
/// frontmost target, or its focus moving, refuses the action and nothing is
/// pressed.
#[tokio::test(start_paused = true)]
async fn the_person_acting_while_the_badge_travels_refuses_the_press() {
    for (change, reason) in [("input", "input_seen"), ("focus", "focus_changed")] {
        let mut rig = rig_with_badge_shown().await;
        let desk = rig.desk.clone();
        let (reply, ()) = tokio::join!(
            serve(
                &rig.plane,
                &rig.management,
                "computer.press_element",
                json!({"element_id": id_of(&rig.tree, "One")}),
            ),
            async {
                picture(&mut rig.pictures).await;
                let mut state = desk.state();
                if change == "input" {
                    // The person's hardware (pid 0), after the read.
                    state.input.push((0, std::time::Instant::now()));
                } else {
                    // The person clicks the field: focus moves, with input.
                    state.focus = DeskFocus::Element(FIELD.0);
                    state.input.push((0, std::time::Instant::now()));
                }
            }
        );
        assert_eq!(
            reply["outcome"], "state_changed_by_person",
            "{change}: {reply}"
        );
        assert_eq!(reply["reason"], reason, "{change}: {reply}");
        assert!(
            rig.desk.state().presses.is_empty(),
            "{change}: nothing was pressed"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn a_window_leaving_the_screen_while_the_badge_travels_refuses_the_press() {
    for hidden in [false, true] {
        let mut rig = rig_with_badge_shown().await;
        let desk = rig.desk.clone();
        let (reply, ()) = tokio::join!(
            serve(
                &rig.plane,
                &rig.management,
                "computer.press_element",
                json!({"element_id": id_of(&rig.tree, "One")}),
            ),
            async {
                picture(&mut rig.pictures).await;
                let mut state = desk.state();
                if hidden {
                    state.application_hidden = Some(true);
                } else {
                    state.minimized_windows.insert(1);
                }
            }
        );
        assert_eq!(reply["outcome"], "state_changed_by_person", "{reply}");
        assert_eq!(reply["reason"], "window_changed", "{reply}");
        assert!(
            reply["remedy"]
                .as_str()
                .unwrap()
                .contains("left the screen"),
            "{reply}"
        );
        assert!(rig.desk.state().presses.is_empty(), "nothing was pressed");
    }
}

#[tokio::test(start_paused = true)]
async fn an_already_minimized_target_still_presses_without_a_badge() {
    let mut rig = rig_with_badge_shown().await;
    rig.desk.state().minimized_windows.insert(1);
    let reply = serve(
        &rig.plane,
        &rig.management,
        "computer.press_element",
        json!({"element_id": id_of(&rig.tree, "One")}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.desk.state().presses, [BUTTONS[0].0]);
    let line = rig.pictures.try_recv().expect("old badge hidden");
    assert!(matches!(line, CursorLine::Hide(_)), "{line:?}");
    assert!(rig.pictures.try_recv().is_err(), "no new picture");
}

/// The agent's turn ending while its badge travels takes the badge off the
/// screen and stops the press: nothing is sent, the reply is cancelled, and
/// it comes at once rather than after the glide nobody sees any more.
#[tokio::test(start_paused = true)]
async fn ending_the_badge_while_it_travels_sends_nothing_and_answers_at_once() {
    let mut rig = rig_with_badge_shown().await;
    let cursor = rig.cursor.clone();
    let ((reply, replied), (ended, glide)) = tokio::join!(
        async {
            let reply = serve(
                &rig.plane,
                &rig.management,
                "computer.press_element",
                json!({"element_id": id_of(&rig.tree, "One")}),
            )
            .await;
            (reply, Instant::now())
        },
        async {
            let drawn = picture(&mut rig.pictures).await;
            cursor.end(&agent());
            (Instant::now(), ms(drawn.motion.duration_ms))
        }
    );
    assert_eq!(reply["outcome"], "cancelled", "{reply}");
    assert_eq!(reply["detail"]["dispatched"], false, "{reply}");
    assert!(rig.desk.state().presses.is_empty(), "nothing was pressed");
    assert!(
        replied - ended < glide / 2,
        "the reply came {:?} after the end, as if the {glide:?} glide were still awaited",
        replied - ended
    );
}

/// The turn ending while the badge's geometry is still being read drops the
/// picture, so there is nothing to wait for, and the press is not sent
/// either: the end came after the action asked for its badge.
#[tokio::test(start_paused = true)]
async fn ending_the_badge_during_its_geometry_read_sends_nothing() {
    let mut rig = rig_with_badge_shown().await;
    let cursor = rig.cursor.clone();
    {
        let mut state = rig.desk.state();
        state.cursor_frame_hook_target = Some(BUTTONS[0].0);
        state.on_cursor_frame = Some(DeskHook(Arc::new(move || cursor.end(&agent()))));
    }
    let reply = serve(
        &rig.plane,
        &rig.management,
        "computer.press_element",
        json!({"element_id": id_of(&rig.tree, "One")}),
    )
    .await;
    assert_eq!(reply["outcome"], "cancelled", "{reply}");
    assert_eq!(reply["detail"]["dispatched"], false, "{reply}");
    assert!(rig.desk.state().presses.is_empty(), "nothing was pressed");
    // The end's hide, and no picture after it.
    assert!(matches!(rig.pictures.try_recv(), Ok(CursorLine::Hide(_))));
    assert!(rig.pictures.try_recv().is_err(), "the picture was dropped");
}

/// A previous picture's window follower must not steal an action's frame hook.
#[test]
fn a_window_follow_frame_does_not_consume_the_actions_geometry_hook() {
    let desk = desk();
    let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = fired.clone();
    {
        let mut state = desk.state();
        state.cursor_frame_hook_target = Some(BUTTONS[0].0);
        state.on_cursor_frame = Some(DeskHook(Arc::new(move || {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
        })));
    }
    let source = desk.source();
    source.cursor_frame(&RawElement::fixture(1, "AXWindow").handle);
    assert!(
        !fired.load(std::sync::atomic::Ordering::SeqCst),
        "the previous badge's follower consumed the action's hook"
    );
    source.cursor_frame(&RawElement::fixture(BUTTONS[0].0, "AXButton").handle);
    assert!(
        fired.load(std::sync::atomic::Ordering::SeqCst),
        "the action's geometry must run the hook"
    );
}

/// An end inside either visibility read still cancels the scheduled press.
#[tokio::test(start_paused = true)]
async fn ending_the_badge_during_its_visibility_read_sends_nothing() {
    for minimized_read in [false, true] {
        let desk = desk();
        let base = plane(&desk);
        let management = granted_management().await;
        // Attach the cursor only after this read, so no earlier window-follow
        // task competes for the press's visibility hook.
        let tree = read(&base, &management).await;
        let (cursor, mut pictures) = Coordinator::channel();
        let plane = base.with_cursor(cursor.clone());
        let fired = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = fired.clone();
        let end = DeskHook(Arc::new(move || {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
            cursor.end(&agent());
        }));
        {
            let mut state = desk.state();
            if minimized_read {
                state.on_window_minimized = Some(end);
            } else {
                state.on_application_hidden = Some(end);
            }
        }
        let reply = serve(
            &plane,
            &management,
            "computer.press_element",
            json!({"element_id": id_of(&tree, "One")}),
        )
        .await;
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the visibility read must run the end hook"
        );
        assert_eq!(reply["outcome"], "cancelled", "{reply}");
        assert_eq!(reply["detail"]["dispatched"], false, "{reply}");
        assert!(desk.state().presses.is_empty(), "nothing was pressed");
        assert!(matches!(pictures.try_recv(), Ok(CursorLine::Hide(_))));
        assert!(pictures.try_recv().is_err(), "the picture was dropped");
    }
}

/// An end before the action asked for its badge (the previous turn's) does
/// not stop it: the action draws a new badge and is pressed.
#[tokio::test(start_paused = true)]
async fn an_end_before_the_action_does_not_stop_it() {
    let mut rig = rig_with_badge_shown().await;
    rig.cursor.end(&agent());
    assert!(matches!(
        rig.pictures.recv().await,
        Some(CursorLine::Hide(_))
    ));
    let reply = serve(
        &rig.plane,
        &rig.management,
        "computer.press_element",
        json!({"element_id": id_of(&rig.tree, "One")}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.desk.state().presses, [BUTTONS[0].0]);
    assert_eq!(picture(&mut rig.pictures).await.to, centre(BUTTONS[0].2));
}

/// An end after the press was sent changes nothing about it: the press
/// stands and the reply is the completed one.
#[tokio::test(start_paused = true)]
async fn an_end_after_the_press_was_sent_leaves_it_completed() {
    let rig = rig_with_badge_shown().await;
    let cursor = rig.cursor.clone();
    rig.desk.state().on_press = Some(DeskHook(Arc::new(move || cursor.end(&agent()))));
    let reply = serve(
        &rig.plane,
        &rig.management,
        "computer.press_element",
        json!({"element_id": id_of(&rig.tree, "One")}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.desk.state().presses, [BUTTONS[0].0]);
}

fn jpeg(width: u16, height: u16) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x0B, 0x08];
    bytes.extend_from_slice(&height.to_be_bytes());
    bytes.extend_from_slice(&width.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x01, 0x11, 0x00, 0xFF, 0xD9]);
    bytes
}

/// One window of the fixture application at (100, 50), 1000 by 600 points,
/// captured at 2000 by 1200 and scaled to 1250 by 750.
fn capturing() -> InMemoryCaptureBackend {
    let mut backend = InMemoryCaptureBackend::default();
    backend.set_windows(vec![EnumeratedWindow {
        window_id: "77".into(),
        owner_identity: grant(),
        owner_identity_verified: true,
        frame: WindowFrame {
            x: 100,
            y: 50,
            width: 1000,
            height: 600,
        },
        accessibility_root: None,
    }]);
    backend.set_frontmost_window(Some("77".into()));
    backend.set_vision_frame("77", 2000, 1200, jpeg(1250, 750));
    backend
}
