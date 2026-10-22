//! The background-mode preview as `computer_use` actions drive it: served
//! through the plane against a fixture application, with the helper's pipe
//! read directly and frames captured by a fake that counts its calls.
//!
//! Timing claims run on tokio's paused clock, which moves only while every
//! task waits on a timer (never while blocking work runs), so a claim about
//! when an action reached the application is exact.

use super::cursor::{Coordinator, SessionScope, TurnOutcome, ACTING_AGENT, ACTING_SESSION};
use super::preview::{CaptureJob, PreviewCapturer, PreviewJpeg, PreviewPlane, PreviewRefused};
use super::*;
use cerebellum_computer::app_state::source::{ElementFacts, RawElement};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::cursor::{
    CursorLine, CursorPreview, CursorPreviewMotion, PreviewFallback,
};
use cerebellum_computer::platform::ProcessGrant;
use cerebellum_core::config::AppUse;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

#[allow(dead_code)]
mod support {
    use crate as cerebellum;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/it/support/computer.rs"
    ));
}

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    support::TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
>;

/// The application's two windows, by their accessibility tokens and their
/// window-server numbers. `FRONT` is the one the person last used; `BEHIND`
/// is covered by it.
const FRONT: (u64, u32, [f64; 4]) = (100, 10, [0.0, 0.0, 1600.0, 900.0]);
const BEHIND: (u64, u32, [f64; 4]) = (110, 11, [200.0, 100.0, 800.0, 600.0]);
/// A button in the front window, which holds the application's focus.
const SEND: (u64, [f64; 4]) = (1, [10.0, 10.0, 50.0, 20.0]);
/// A text field and a button in the covered window.
const BODY: (u64, [f64; 4]) = (2, [400.0, 250.0, 100.0, 50.0]);
const SAVE: (u64, [f64; 4]) = (3, [600.0, 500.0, 80.0, 20.0]);
/// The application the person has in front: not the target.
const PERSONS_APP: u32 = 100;
/// The bundle the fixture application runs from, whose icon a preview shows
/// in place of a frame.
const BUNDLE: &str = "/Applications/Safari.app";

/// A covered application with two windows, focused in the front one.
fn two_window_desk() -> support::Desk {
    let desk = support::Desk::new(vec![
        RawElement::fixture(FRONT.0, "AXWindow")
            .titled("Inbox")
            .with_children(vec![RawElement::fixture(SEND.0, "AXButton").titled("Send")]),
        RawElement::fixture(BEHIND.0, "AXWindow")
            .titled("Draft")
            .with_children(vec![
                RawElement::fixture(BODY.0, "AXTextField").titled("Body"),
                RawElement::fixture(SAVE.0, "AXButton").titled("Save"),
            ]),
    ])
    .with_element(
        SEND.0,
        support::DeskElement {
            facts: ElementFacts {
                title: Some("Send".into()),
                ..support::facts("AXButton", &["AXPress"])
            },
            ..support::DeskElement::default()
        },
    )
    .with_element(
        BODY.0,
        support::DeskElement {
            facts: ElementFacts {
                title: Some("Body".into()),
                value_settable: true,
                ..support::facts("AXTextField", &[])
            },
            value: Some(String::new()),
            applies_writes: true,
            ..support::DeskElement::default()
        },
    )
    .with_element(
        SAVE.0,
        support::DeskElement {
            facts: ElementFacts {
                title: Some("Save".into()),
                ..support::facts("AXButton", &["AXPress"])
            },
            ..support::DeskElement::default()
        },
    );
    {
        let mut state = desk.state();
        state.frontmost = Some(PERSONS_APP);
        state.focus = support::DeskFocus::Element(SEND.0);
        state.focused_cursor_window = Some(FRONT.0);
        for (window, number, frame) in [FRONT, BEHIND] {
            state.cursor_frames.insert(window, frame);
            state.element_windows.insert(window, number);
        }
        for (element, frame, window) in [
            (SEND.0, SEND.1, FRONT.0),
            (BODY.0, BODY.1, BEHIND.0),
            (SAVE.0, SAVE.1, BEHIND.0),
        ] {
            state.cursor_frames.insert(element, frame);
            state.cursor_windows.insert(element, window);
        }
    }
    desk
}

/// Captures every frame at once, counting its calls.
#[derive(Default)]
struct CountingCapture(AtomicUsize);

impl PreviewCapturer for CountingCapture {
    fn capture(&self, _job: &CaptureJob) -> Result<PreviewJpeg, PreviewRefused> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(PreviewJpeg {
            size: [4, 3],
            jpeg: vec![0xFF, 0xD8, 0xFF, 0xD9],
        })
    }
}

/// A config file holding one `app_use`, never changing.
struct FixedConfig(&'static str);

impl super::app_use::ConfigFiles for FixedConfig {
    fn modified(&self, _path: &std::path::Path) -> std::io::Result<std::time::SystemTime> {
        Ok(std::time::SystemTime::UNIX_EPOCH)
    }
    fn read_to_string(&self, _path: &std::path::Path) -> std::io::Result<String> {
        Ok(self.0.to_owned())
    }
}

fn app_use_file(mode: AppUse) -> super::app_use::LiveAppUse {
    super::app_use::LiveAppUse::new(
        Some(PathBuf::from(
            "/fixture/home/.config/cortexkit/cerebellum.jsonc",
        )),
        Arc::new(FixedConfig(match mode {
            AppUse::Foreground => r#"{"computer_use":{"app_use":"foreground"}}"#,
            AppUse::Background => r#"{"computer_use":{"app_use":"background"}}"#,
        })),
    )
}

struct Rig {
    plane: Plane,
    desk: support::Desk,
    management: Arc<crate::management::ManagementPlane>,
    captures: Arc<CountingCapture>,
    lines: Lines,
}

/// Everything the helper's pipe has been sent, read as it arrives.
struct Lines {
    receiver: Option<tokio::sync::mpsc::Receiver<CursorLine>>,
    seen: Vec<CursorLine>,
}

impl Lines {
    fn take(&mut self) {
        if let Some(receiver) = self.receiver.as_mut() {
            while let Ok(line) = receiver.try_recv() {
                self.seen.push(line);
            }
        }
    }

    /// Read until `done` holds of what was seen. Bounded by a count of
    /// steps, never by a real-clock time.
    async fn until(&mut self, what: &str, done: impl Fn(&[CursorLine]) -> bool) {
        for _ in 0..10_000 {
            self.take();
            if done(&self.seen) {
                return;
            }
            tokio::task::yield_now().await;
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("never saw {what}: {:?}", self.seen);
    }

    fn previews(&self, agent: &str) -> Vec<CursorPreview> {
        self.seen
            .iter()
            .filter_map(|line| match line {
                CursorLine::Preview(preview) if preview.preview_agent == agent => {
                    Some(preview.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn motions(&self, agent: &str) -> Vec<CursorPreviewMotion> {
        self.seen
            .iter()
            .filter_map(|line| match line {
                CursorLine::PreviewMotion(motion) if motion.pmotion_agent == agent => {
                    Some(motion.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn frames(&self, agent: &str) -> usize {
        self.seen
            .iter()
            .filter(|line| matches!(line, CursorLine::Frame(frame) if frame.frame_agent == agent))
            .count()
    }

    fn pictures(&self, agent: &str) -> usize {
        self.seen
            .iter()
            .filter(|line| matches!(line, CursorLine::Picture(event) if event.agent == agent))
            .count()
    }

    fn hides(&self, agent: &str) -> usize {
        self.seen
            .iter()
            .filter(|line| matches!(line, CursorLine::Hide(hide) if hide.agent == agent))
            .count()
    }
}

/// The agent a call by the fixture identity acts as.
fn agent() -> String {
    support::identity().agent_project_id
}

async fn rig(mode: AppUse, admitted: bool, cursor_on: bool) -> Rig {
    let desk = two_window_desk();
    let captures = Arc::new(CountingCapture::default());
    let frontmost: super::cursor::FrontmostWindow = Arc::new(|_: &ProcessGrant| Some(FRONT.1));
    let bundle: super::cursor::BundlePath = Arc::new(|grant: &ProcessGrant| {
        (grant.pid == support::grant().pid).then(|| BUNDLE.to_owned())
    });
    let mut plane = ComputerPlane::with_result_schema_enforcement(
        support::audit(),
        ResultSchemaEnforcement::Withhold,
    )
    .with_permission_liveness(support::live_permissions())
    .with_app_state_source(desk.source())
    .with_app_use(app_use_file(mode))
    .with_preview(PreviewPlane::new(
        captures.clone(),
        admitted,
        frontmost,
        bundle,
    ));
    let mut receiver = None;
    if cursor_on {
        let (cursor, lines) = Coordinator::channel();
        plane = plane.with_cursor(cursor);
        receiver = Some(lines);
    }
    Rig {
        plane,
        desk,
        management: support::granted_management().await,
        captures,
        lines: Lines {
            receiver,
            seen: Vec::new(),
        },
    }
}

impl Rig {
    fn with_mode(self, mode: AppUse) -> Self {
        Self {
            plane: self.plane.with_app_use(app_use_file(mode)),
            ..self
        }
    }

    async fn call(&self, name: &str, arguments: Value) -> Value {
        let clock = cerebellum_core::clock::FakeClock::new();
        let reply = self
            .plane
            .serve(
                servable(name).expect("served"),
                &arguments,
                ServeContext {
                    cancel: crate::CancelHandle::pending(),
                    grantee: support::GRANTEE,
                    identity: support::identity(),
                    management: &self.management,
                    consent: support::no_relay(),
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"));
        assert!(
            self.plane.result_schema_findings().is_empty(),
            "{name}: {reply}"
        );
        reply
    }

    /// `call`, as `agent` acting.
    async fn call_as(&self, agent: &str, name: &str, arguments: Value) -> Value {
        ACTING_AGENT
            .scope(Some(agent.to_owned()), self.call(name, arguments))
            .await
    }

    async fn read(&self) -> String {
        let reply = self
            .call(
                "computer.read_state",
                json!({"target": support::TARGET_BUNDLE_ID}),
            )
            .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        reply["state_text"].as_str().unwrap().to_owned()
    }

    fn captures(&self) -> usize {
        self.captures.0.load(Ordering::SeqCst)
    }

    /// Wait until the preview worker has made `count` captures. Yields to
    /// the runtime between polls: the refresh that leads to a capture can be
    /// reported from a task of this test's own single-thread runtime, which a
    /// blocking wait would never let run.
    async fn until_captured(&self, count: usize) {
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while self.captures() < count {
            assert!(
                std::time::Instant::now() < give_up,
                "only {} captures",
                self.captures()
            );
            std::thread::sleep(Duration::from_millis(1));
            tokio::task::yield_now().await;
        }
    }

    fn shown(&self, agent: &str) -> bool {
        self.plane
            .preview
            .running()
            .is_some_and(|worker| worker.is_shown(agent))
    }

    fn dispatched(&self) -> Vec<tokio::time::Instant> {
        self.desk.state().dispatched_at.clone()
    }
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

fn read_arguments() -> Value {
    json!({"target": support::TARGET_BUNDLE_ID})
}

/// The first background action shows the agent's preview, a second and a
/// third agent's stack below it, and a fourth agent gets no preview, no
/// badge and no wait: its press reaches the application at once and its
/// reply says `preview: "not_shown_capacity"`.
#[tokio::test(start_paused = true)]
async fn previews_stack_for_three_agents_and_a_fourth_gets_not_shown_capacity() {
    let mut rig = rig(AppUse::Background, true, true).await;
    let tree = rig.read().await;
    // The fixture identity's read took the first slot; its end frees it,
    // so the three named agents fill all three.
    rig.plane.cursor().end(&agent());
    for (slot, agent) in ["agent-a", "agent-b", "agent-c"].into_iter().enumerate() {
        let reply = rig
            .call_as(agent, "computer.read_state", read_arguments())
            .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(reply.get("preview"), None, "{agent}: {reply}");
        rig.lines
            .until("the preview", |seen| {
                seen.iter().any(|line| {
                    matches!(line,
                    CursorLine::Preview(p) if p.preview_agent == agent)
                })
            })
            .await;
        let preview = rig.lines.previews(agent).remove(0);
        assert_eq!(usize::from(preview.preview_slot), slot, "{agent}");
        assert_eq!(preview.preview_window, FRONT.1, "{agent}");
        assert_eq!(preview.preview_fallback, None, "{agent}");
    }
    rig.lines.take();
    let before = rig.lines.seen.len();
    let start = tokio::time::Instant::now();
    let reply = rig
        .call_as(
            "agent-d",
            "computer.press_element",
            json!({"element_id": id_of(&tree, "Save")}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["preview"], "not_shown_capacity", "{reply}");
    assert_eq!(rig.dispatched(), [start], "the press waited for nothing");
    rig.lines.take();
    assert!(
        rig.lines.seen[before..].iter().all(|line| match line {
            CursorLine::Preview(p) => p.preview_agent != "agent-d",
            CursorLine::PreviewMotion(m) => m.pmotion_agent != "agent-d",
            CursorLine::Picture(e) => e.agent != "agent-d",
            _ => true,
        }),
        "a fourth agent drew something: {:?}",
        &rig.lines.seen[before..]
    );
    assert!(!rig.shown("agent-d"));
}

/// A covered application with two windows: a write to the field in the
/// window behind, which is not the focused one, retargets the preview to
/// that window before the badge moves, without changing the application's
/// focus or the front application. The badge lands at the field's place in
/// the thumbnail, and the write reaches the field when the badge arrives.
/// A press in the same window keeps the preview there and glides.
#[tokio::test(start_paused = true)]
async fn an_action_in_a_covered_apps_second_window_retargets_the_preview_there() {
    let mut rig = rig(AppUse::Background, true, true).await;
    let tree = rig.read().await;
    let me = agent();
    rig.lines
        .until("the read's preview", |seen| {
            seen.iter()
                .any(|line| matches!(line, CursorLine::Preview(_)))
        })
        .await;
    let first = rig.lines.previews(&me).remove(0);
    assert_eq!(first.preview_window, FRONT.1);

    let start = tokio::time::Instant::now();
    let reply = rig
        .call(
            "computer.write_text",
            json!({
                "element_id": id_of(&tree, "Body"),
                "text": "hello",
                "write_mode": "replace_value",
            }),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply.get("preview"), None, "{reply}");
    rig.lines.take();
    let previews = rig.lines.previews(&me);
    let retarget = previews.last().unwrap();
    assert_eq!(retarget.preview_window, BEHIND.1, "{previews:?}");
    assert_eq!(retarget.preview_aspect, [BEHIND.2[2], BEHIND.2[3]]);
    assert!(retarget.preview_generation > first.preview_generation);
    let motions = rig.lines.motions(&me);
    assert_eq!(motions.len(), 1, "{motions:?}");
    let motion = &motions[0];
    assert_eq!(motion.pmotion_window, BEHIND.1);
    assert_eq!(motion.pmotion_generation, retarget.preview_generation);
    // The field's centre, as a place in the window behind.
    let centre = [
        (BODY.1[0] + BODY.1[2] / 2.0 - BEHIND.2[0]) / BEHIND.2[2],
        (BODY.1[1] + BODY.1[3] / 2.0 - BEHIND.2[1]) / BEHIND.2[3],
    ];
    assert_eq!(motion.pmotion_to, centre);
    assert_eq!(motion.pmotion_target, centre);
    // Where the helper draws it: the same place in the thumbnail.
    let layout = cerebellum_computer::preview_layout::preview_layout(
        retarget.preview_aspect,
        cerebellum_computer::preview_layout::PREVIEW_MAX_HEIGHT,
    )
    .unwrap();
    let mapped =
        cerebellum_computer::preview_layout::thumbnail_point(layout.thumbnail, motion.pmotion_to)
            .unwrap();
    assert_eq!(
        mapped,
        [
            layout.thumbnail.x + centre[0] * layout.thumbnail.width,
            layout.thumbnail.y + centre[1] * layout.thumbnail.height,
        ]
    );
    // A new window is a new space: the badge appears there with its entry,
    // and the write is sent as it lands.
    let entry = Duration::from_secs_f64(motion.pmotion_motion.duration_ms / 1000.0);
    assert_eq!(
        motion.pmotion_motion.duration_ms,
        cerebellum_computer::cursor::entry_ms(motion.pmotion_motion.reduce_motion)
    );
    assert_eq!(rig.dispatched(), [start + entry]);
    {
        let state = rig.desk.state();
        assert_eq!(state.focus, support::DeskFocus::Element(SEND.0));
        assert_eq!(state.frontmost, Some(PERSONS_APP));
        assert_eq!(state.writes.len(), 1);
    }
    assert_eq!(rig.lines.pictures(&me), 0, "an on-screen badge was drawn");

    let reply = rig
        .call(
            "computer.press_element",
            json!({"element_id": id_of(&tree, "Save")}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    rig.lines.take();
    let previews = rig.lines.previews(&me);
    assert_eq!(previews.last().unwrap().preview_window, BEHIND.1);
    assert_eq!(
        previews.last().unwrap().preview_generation,
        retarget.preview_generation,
        "the same window is not a retarget"
    );
    let glide = rig.lines.motions(&me).pop().unwrap();
    assert_eq!(
        glide.pmotion_motion.style,
        cerebellum_computer::cursor::MotionStyle::Glide
    );
    assert_eq!(rig.desk.state().focus, support::DeskFocus::Element(SEND.0));
}

/// A write whose badge line stays unwritten (the helper stopped reading)
/// goes ahead at the cap, and its reply says `preview: "not_synchronized"`
/// rather than claiming the badge arrived.
#[tokio::test(start_paused = true)]
async fn a_stalled_badge_write_replies_not_synchronized_at_the_cap() {
    let (release, held) = std::sync::mpsc::channel::<()>();
    let held = std::sync::Mutex::new(held);
    let cursor = Coordinator::piped_for_test(move |line| {
        if matches!(line, CursorLine::PreviewMotion(_)) {
            let _ = held.lock().unwrap().recv();
        }
        true
    });
    let rig = rig(AppUse::Background, true, false).await;
    let rig = Rig {
        plane: rig.plane.with_cursor(cursor),
        ..rig
    };
    let tree = rig.read().await;
    let start = tokio::time::Instant::now();
    let reply = rig
        .call(
            "computer.write_text",
            json!({
                "element_id": id_of(&tree, "Body"),
                "text": "hello",
                "write_mode": "replace_value",
            }),
        )
        .await;
    release.send(()).unwrap();
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["preview"], "not_synchronized", "{reply}");
    assert_eq!(rig.dispatched(), [start + super::cursor::ARRIVAL_CAP]);
}

/// A build without `preview_capture_admitted` captures nothing: the
/// preview shows the application's icon with `capture_refused`, the badge
/// makes no motion there, and the action waits for nothing.
#[tokio::test(start_paused = true)]
async fn an_unadmitted_build_captures_nothing_and_shows_the_icon() {
    let mut rig = rig(AppUse::Background, false, true).await;
    let tree = rig.read().await;
    let start = tokio::time::Instant::now();
    let reply = rig
        .call(
            "computer.press_element",
            json!({"element_id": id_of(&tree, "Save")}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.dispatched(), [start], "the press waited");
    rig.lines.take();
    let previews = rig.lines.previews(&agent());
    assert!(!previews.is_empty());
    for preview in &previews {
        assert_eq!(
            preview.preview_fallback,
            Some(PreviewFallback::CaptureRefused)
        );
        assert_eq!(preview.preview_icon_path.as_deref(), Some(BUNDLE));
    }
    assert!(rig.lines.motions(&agent()).is_empty());
    assert_eq!(rig.lines.pictures(&agent()), 0);
    // Give the worker every chance to capture: it never does.
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.captures(), 0);
    rig.lines.take();
    assert_eq!(rig.lines.frames(&agent()), 0);
}

/// A minimized target window shows the application's icon with
/// `minimized`: nothing is captured of it and the badge makes no motion.
#[tokio::test(start_paused = true)]
async fn a_minimized_window_shows_the_minimized_fallback() {
    let mut rig = rig(AppUse::Background, true, true).await;
    rig.desk.state().minimized_windows.insert(BEHIND.0);
    let tree = rig.read().await;
    rig.until_captured(1).await;
    let start = tokio::time::Instant::now();
    let reply = rig
        .call(
            "computer.write_text",
            json!({
                "element_id": id_of(&tree, "Body"),
                "text": "hello",
                "write_mode": "replace_value",
            }),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.dispatched(), [start], "the write waited");
    rig.lines.take();
    let preview = rig.lines.previews(&agent()).pop().unwrap();
    assert_eq!(preview.preview_window, BEHIND.1);
    assert_eq!(preview.preview_fallback, Some(PreviewFallback::Minimized));
    assert_eq!(preview.preview_icon_path.as_deref(), Some(BUNDLE));
    assert!(rig.lines.motions(&agent()).is_empty());
    let captured = rig.captures();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.captures(), captured, "a minimized window was captured");
}

/// With `agent_cursor: false` there is no preview, no badge and no wait:
/// the preview worker is never even started.
#[tokio::test(start_paused = true)]
async fn with_the_agent_cursor_off_there_is_no_preview_badge_or_wait() {
    let rig = rig(AppUse::Background, true, false).await;
    let tree = rig.read().await;
    let start = tokio::time::Instant::now();
    let reply = rig
        .call(
            "computer.press_element",
            json!({"element_id": id_of(&tree, "Save")}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply.get("preview"), None, "{reply}");
    assert_eq!(rig.dispatched(), [start]);
    assert!(rig.plane.preview.running().is_none());
    assert_eq!(rig.captures(), 0);
}

/// Every end hides the agent's preview with its badge, and nothing more is
/// captured for it: the session's turn ending, `Coordinator::end` itself
/// (where a Cancel and a closed route arrive; the frame tests below send
/// those through the wire handler), and a switch to foreground mode, whose
/// next action hides the preview and draws the badge on the screen again.
#[tokio::test(start_paused = true)]
async fn the_preview_hides_on_turn_end_on_an_end_signal_and_on_a_switch_to_foreground() {
    let mut rig = rig(AppUse::Background, true, true).await;
    let me = agent();
    let session = SessionScope {
        scope_ref: "scope-1".into(),
        epoch: 1,
    };

    // The turn ends.
    ACTING_SESSION
        .scope(Some(session.clone()), rig.read())
        .await;
    rig.until_captured(1).await;
    assert!(rig.shown(&me));
    assert!(rig
        .plane
        .cursor()
        .turn_ended("session-1", Some("scope-1"), TurnOutcome::Completed));
    assert!(!rig.shown(&me), "the turn's end left the preview showing");
    rig.lines
        .until("the hide", |seen| {
            seen.iter().any(|line| matches!(line, CursorLine::Hide(_)))
        })
        .await;
    let captured = rig.captures();
    let frames = rig.lines.frames(&me);
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.captures(), captured, "captured after the turn ended");
    rig.lines.take();
    assert_eq!(
        rig.lines.frames(&me),
        frames,
        "a frame after the turn ended"
    );

    // An end signal, as a Cancel or a closed route delivers it.
    rig.read().await;
    rig.lines
        .until("a second preview", |seen| {
            seen.iter()
                .filter(|line| matches!(line, CursorLine::Preview(_)))
                .count()
                >= 2
        })
        .await;
    assert!(rig.shown(&me));
    rig.plane.cursor().end(&me);
    assert!(!rig.shown(&me), "an end left the preview showing");

    // A switch to foreground mode, at the agent's next action.
    rig.read().await;
    rig.lines
        .until("a third preview", |seen| {
            seen.iter()
                .filter(|line| matches!(line, CursorLine::Preview(_)))
                .count()
                >= 3
        })
        .await;
    assert!(rig.shown(&me));
    let hides = rig.lines.hides(&me);
    let mut rig = rig.with_mode(AppUse::Foreground);
    rig.desk.state().cursor_visible = true;
    rig.read().await;
    assert!(!rig.shown(&me), "foreground mode left the preview showing");
    rig.lines
        .until("the badge back on the screen", |seen| {
            seen.iter()
                .any(|line| matches!(line, CursorLine::Picture(_)))
        })
        .await;
    assert_eq!(
        rig.lines.hides(&me),
        hides + 1,
        "no hide line for the switch"
    );
    let hide_at = rig
        .lines
        .seen
        .iter()
        .rposition(|line| matches!(line, CursorLine::Hide(_)))
        .unwrap();
    let picture_at = rig
        .lines
        .seen
        .iter()
        .position(|line| matches!(line, CursorLine::Picture(_)))
        .unwrap();
    assert!(hide_at < picture_at, "the badge was drawn before the hide");
    let captured = rig.captures();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.captures(), captured, "captured after the switch");
}

/// The health gauges a desk probe reads to see that an idle preview costs
/// nothing: one shown preview's one refresh is one capture request and one
/// frame line written to the helper, and once the preview is hidden neither
/// moves again, though an action starts and the clock runs on.
#[tokio::test(start_paused = true)]
async fn one_refresh_moves_each_preview_gauge_by_one_and_a_hidden_preview_neither() {
    // Gauges of this test's own: other tests capture in parallel into the
    // process's.
    let gauges: &'static super::preview::PreviewGauges =
        Box::leak(Box::new(super::preview::PreviewGauges::new()));
    // Frame lines as the helper's pipe takes them, counted apart from the
    // gauge so a gauge that never moves fails at once rather than hanging.
    let delivered = Arc::new(AtomicUsize::new(0));
    let piped = delivered.clone();
    let cursor = Coordinator::piped_for_test(move |line| {
        if matches!(line, CursorLine::Frame(_)) {
            piped.fetch_add(1, Ordering::SeqCst);
        }
        true
    })
    .counting_frames_in(gauges);
    let captures = Arc::new(CountingCapture::default());
    let worker = super::preview::PreviewWorker::spawn_counting(
        Arc::new(cursor.clone()),
        captures.clone(),
        true,
        gauges,
    );
    let shown = worker.show(super::preview::PreviewRequest {
        agent: "agent-a".into(),
        target: support::grant(),
        window: super::preview::PreviewWindow::new(BEHIND.1, BEHIND.2).unwrap(),
        app: "Safari".into(),
        icon_path: None,
        label: None,
        backing_scale: 2.0,
    });
    assert!(matches!(
        shown,
        super::preview::ShowOutcome::Shown { icon: false, .. }
    ));
    let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
    while delivered.load(Ordering::SeqCst) < 1 {
        assert!(std::time::Instant::now() < give_up, "no frame was written");
        std::thread::sleep(Duration::from_millis(1));
    }
    // Nothing more follows the one refresh a shown preview asks for.
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(delivered.load(Ordering::SeqCst), 1);
    assert_eq!(gauges.capture_requests(), 1);
    assert_eq!(gauges.frames_written(), 1);
    assert_eq!(captures.0.load(Ordering::SeqCst), 1);

    cursor.end("agent-a");
    worker.hide("agent-a");
    worker.action_started("agent-a");
    for _ in 0..20 {
        tokio::time::advance(Duration::from_secs(30)).await;
        std::thread::sleep(Duration::from_millis(2));
    }
    worker.action_settled("agent-a");
    for _ in 0..20 {
        tokio::time::advance(Duration::from_secs(30)).await;
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        gauges.capture_requests(),
        1,
        "a hidden preview was captured"
    );
    assert_eq!(gauges.frames_written(), 1, "a hidden preview wrote a frame");
}

/// In background mode a window that cannot be read means no badge at all for
/// that action: no preview, no badge inside one, no on-screen picture (which
/// would point at whatever covers the application), and no wait.
#[tokio::test(start_paused = true)]
async fn a_background_action_with_no_readable_window_draws_nothing_and_does_not_wait() {
    let mut rig = rig(AppUse::Background, true, true).await;
    {
        let mut state = rig.desk.state();
        // The badge would be visible on the screen, were it drawn there.
        state.cursor_visible = true;
        state.cursor_windows.clear();
        state.focused_cursor_window = None;
    }
    let tree = rig.read().await;
    let start = tokio::time::Instant::now();
    let reply = rig
        .call(
            "computer.press_element",
            json!({"element_id": id_of(&tree, "Save")}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply.get("preview"), None, "{reply}");
    assert_eq!(rig.dispatched(), [start], "the press waited");
    for _ in 0..50 {
        tokio::task::yield_now().await;
    }
    rig.lines.take();
    assert!(
        rig.lines.seen.iter().all(|line| !matches!(
            line,
            CursorLine::Picture(_) | CursorLine::Preview(_) | CursorLine::PreviewMotion(_)
        )),
        "something was drawn: {:?}",
        rig.lines.seen
    );
    assert!(!rig.shown(&agent()));
}

/// `keys` and `type` show the focused element's window: the field focused in
/// the covered window brings the preview there. With no element focused,
/// the application's focused window.
#[tokio::test(start_paused = true)]
async fn keys_and_type_preview_the_focused_elements_window_or_the_focused_window() {
    for (action, arguments) in [
        (
            "computer.type",
            json!({"target": support::TARGET_BUNDLE_ID, "text": "hi"}),
        ),
        (
            "computer.keys",
            json!({"keys": ["s"], "target": support::TARGET_BUNDLE_ID}),
        ),
    ] {
        let mut rig = rig(AppUse::Background, true, true).await;
        rig.desk.state().focus = support::DeskFocus::Element(BODY.0);
        rig.call(action, arguments.clone()).await;
        rig.lines
            .until("the preview", |seen| {
                seen.iter()
                    .any(|line| matches!(line, CursorLine::Preview(_)))
            })
            .await;
        let preview = rig.lines.previews(&agent()).pop().unwrap();
        assert_eq!(
            preview.preview_window, BEHIND.1,
            "{action}: focused element"
        );
        let motion = rig.lines.motions(&agent()).pop().expect("a motion");
        assert_eq!(motion.pmotion_window, BEHIND.1, "{action}");

        // Nothing focused: the focused window, in front.
        let mut rig = self::rig(AppUse::Background, true, true).await;
        rig.desk.state().focus = support::DeskFocus::Nothing;
        rig.call(action, arguments).await;
        rig.lines
            .until("the preview", |seen| {
                seen.iter()
                    .any(|line| matches!(line, CursorLine::Preview(_)))
            })
            .await;
        let preview = rig.lines.previews(&agent()).pop().unwrap();
        assert_eq!(preview.preview_window, FRONT.1, "{action}: focused window");
        assert!(
            rig.lines.motions(&agent()).is_empty(),
            "{action}: no element, no motion"
        );
    }
}

/// The wire handler's planes with this rig's cursor, and a route request
/// handler that serves one background read on the rig's plane and then stays
/// open until `release` fires, so a Cancel finds it running. The receiver
/// yields once the read has shown its preview.
fn planes_serving_a_read(
    rig: Rig,
    release: Arc<tokio::sync::Notify>,
) -> (crate::Planes, tokio::sync::mpsc::Receiver<()>, Arc<Rig>) {
    let mut planes = crate::Planes::with_browser_config_journaling(
        Arc::new(cerebellum_core::health::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    planes.cursor_for_test = Some(rig.plane.cursor());
    let rig = Arc::new(rig);
    let (read, read_rx) = tokio::sync::mpsc::channel(4);
    let serving = rig.clone();
    planes.route_test_handler = Some(Arc::new(move || {
        let (rig, release, read) = (serving.clone(), release.clone(), read.clone());
        Box::pin(async move {
            let reply = rig.call("computer.read_state", read_arguments()).await;
            assert_eq!(reply["outcome"], "completed", "{reply}");
            let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while !rig.shown(&agent()) {
                assert!(std::time::Instant::now() < give_up, "no preview shown");
                tokio::task::yield_now().await;
            }
            let _ = read.send(()).await;
            release.notified().await;
        })
    }));
    (planes, read_rx, rig)
}

fn wire_frame(
    ty: subc_protocol::FrameType,
    channel: u16,
    epoch: u32,
    corr: u64,
) -> subc_protocol::Frame {
    subc_protocol::Frame::build(
        ty,
        crate::wire::control_flags(),
        channel,
        epoch,
        corr,
        b"{}".to_vec(),
    )
    .unwrap()
}

/// A consumer's Cancel of the computer call, sent through the wire handler,
/// hides the preview that call showed: nothing more is captured for it.
#[tokio::test]
async fn a_cancel_frame_hides_the_preview_its_call_showed() {
    let release = Arc::new(tokio::sync::Notify::new());
    let (planes, mut read, rig) =
        planes_serving_a_read(rig(AppUse::Background, true, true).await, release.clone());
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(
        wire_frame(subc_protocol::FrameType::Request, 7, 1, 42),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    read.recv().await.unwrap();
    rig.until_captured(1).await;
    // A correlation nobody is running cancels nothing.
    crate::handle_frame(
        wire_frame(subc_protocol::FrameType::Cancel, 7, 1, 99),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    assert!(rig.shown(&agent()));
    crate::handle_frame(
        wire_frame(subc_protocol::FrameType::Cancel, 7, 1, 42),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    assert!(!rig.shown(&agent()), "the Cancel left the preview showing");
    let captured = rig.captures();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.captures(), captured, "captured after the Cancel");
    release.notify_waiters();
}

/// A route's GOODBYE, sent through the wire handler, hides the previews its
/// calls showed; another epoch of the channel is another route and hides
/// nothing.
#[tokio::test]
async fn a_goodbye_frame_hides_the_previews_its_route_showed() {
    let release = Arc::new(tokio::sync::Notify::new());
    let (planes, mut read, rig) =
        planes_serving_a_read(rig(AppUse::Background, true, true).await, release.clone());
    let (tx, _rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(
        wire_frame(subc_protocol::FrameType::Request, 7, 1, 42),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    read.recv().await.unwrap();
    rig.until_captured(1).await;
    crate::handle_frame(
        wire_frame(subc_protocol::FrameType::Goodbye, 7, 2, 0),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    assert!(
        rig.shown(&agent()),
        "another route's GOODBYE hid the preview"
    );
    crate::handle_frame(
        wire_frame(subc_protocol::FrameType::Goodbye, 7, 1, 0),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    assert!(!rig.shown(&agent()), "the GOODBYE left the preview showing");
    let captured = rig.captures();
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(1));
        tokio::task::yield_now().await;
    }
    assert_eq!(rig.captures(), captured, "captured after the GOODBYE");
    release.notify_waiters();
}
