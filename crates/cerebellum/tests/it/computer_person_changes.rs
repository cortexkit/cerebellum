//! Acting on an application the person used since the agent last saw it.
//!
//! Each test drives `ComputerPlane::serve` over a scripted desk: the agent
//! reads, something happens to the application, and the agent acts. What was
//! done is read from the desk's record of presses and the driver's record of
//! posts, never from the reply alone.

use super::support;

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::management::ManagementPlane;
use cerebellum_computer::app_state::source::RawElement;
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{
    AccessibilityTreeRequest, AccessibilityTreeResult, AttendancePreconditionRequest,
    AttendancePreconditionResult, CapabilityAdvertisementContext, CapabilityDeclaration,
    DispatchResult, DriverError, EffectObservationRequest, EffectObservationResult, EffectStatus,
    ElementResolutionRequest, ElementResolutionResult, FocusQueryRequest, FocusQueryResult,
    FrontingSnapshot, InputObservationRequest, InputObservationResult, InputObserverLiveness,
    PlatformDriver, ProcessGrant, SemanticDispatchRequest, SyntheticDispatchRequest,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use serde_json::{json, Value};
use support::computer::{
    audit, facts, grant, granted_management, identity, no_relay, Desk, DeskElement, DeskFocus,
    TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};

/// The pid the desk's input count gives this module's own posts.
fn our_pid() -> i64 {
    i64::from(std::process::id())
}

/// What a driver built for one test does when asked to post.
#[derive(Debug, Default)]
struct Posts {
    calls: Vec<SyntheticDispatchRequest>,
    /// When set, each post is counted in the desk's input this long after
    /// it returns, the way the HID system's table takes this module's own
    /// events some time after they are posted.
    counted_after: Option<Duration>,
}

/// A driver that records each per-process post and makes the application
/// show it: the desk's next tree replaces the current one, and the post is
/// counted in the desk's input as this module's.
struct PostingDriver {
    desk: Desk,
    posts: Arc<Mutex<Posts>>,
}

impl PlatformDriver for PostingDriver {
    fn capability_declarations(
        &self,
        _context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        Vec::new()
    }

    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        Err(DriverError::Unsupported("test reads no tree"))
    }

    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        Err(DriverError::Unsupported("test resolves no element"))
    }

    fn dispatch_semantic(
        &mut self,
        _request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported(
            "test dispatches nothing semantically",
        ))
    }

    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        let counted_after = {
            let mut posts = self.posts.lock().unwrap();
            posts.calls.push(request);
            posts.counted_after
        };
        let mut desk = self.desk.state();
        if let Some(after) = desk.after_action.take() {
            desk.roots = after;
        }
        if let Some(delay) = counted_after {
            desk.input.push((our_pid(), Instant::now() + delay));
        }
        Ok(DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: 0,
            delivery_posts_returned: 1,
            delivery_generation_verifications: 2,
        })
    }

    fn dispatch_global(
        &mut self,
        _request: cerebellum_computer::platform::GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("test posts nothing globally"))
    }

    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        Ok(FocusQueryResult {
            matches_target: true,
        })
    }

    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported("test captures no fronting state"))
    }

    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: true,
            raw_hid_live: true,
            self_echo_filter_live: true,
        }
    }

    fn session_locked(&self) -> Option<bool> {
        Some(false)
    }

    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Ok(InputObservationResult {
            human_or_ambiguous_input: false,
            detection_latency_ms: 1,
        })
    }

    fn observe_effect(
        &mut self,
        _request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        Ok(EffectObservationResult {
            status: EffectStatus::EffectIndeterminate,
            failure_reason: Some("post_condition_undeclarable".to_string()),
        })
    }

    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        Ok(AttendancePreconditionResult {
            valid: true,
            lease_generation: Some("lease-1".to_string()),
            age_ms: Some(1),
        })
    }
}

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    PostingDriver,
>;

/// The Send button's token, and the composer's.
const SEND: u64 = 10;
const COMPOSER: u64 = 12;

fn chat(title: &str) -> Vec<RawElement> {
    vec![RawElement::fixture(1, "AXWindow")
        .titled(title)
        .with_children(vec![
            RawElement::fixture(SEND, "AXButton").titled("Send"),
            RawElement::fixture(11, "AXStaticText").titled("Hello"),
            RawElement::fixture(COMPOSER, "AXTextField").titled("Composer"),
        ])]
}

/// A frontmost chat application with a Send button and a focused composer,
/// whose focused window is the chat window titled "Draft".
struct Rig {
    desk: Desk,
    posts: Arc<Mutex<Posts>>,
    plane: Plane,
    management: Arc<ManagementPlane>,
}

async fn rig() -> Rig {
    let desk = Desk::new(chat("Draft"))
        .with_element(
            SEND,
            DeskElement {
                facts: facts("AXButton", &["AXPress"]),
                ..DeskElement::default()
            },
        )
        .with_element(
            COMPOSER,
            DeskElement {
                facts: facts("AXTextField", &[]),
                value: Some(String::new()),
                applies_writes: true,
                ..DeskElement::default()
            },
        );
    {
        let mut state = desk.state();
        state.focus = DeskFocus::Element(COMPOSER);
        state.window = Some((1, Some("Draft".into())));
    }
    let posts = Arc::new(Mutex::new(Posts::default()));
    let factory = {
        let desk = desk.clone();
        let posts = Arc::clone(&posts);
        move || PostingDriver {
            desk: desk.clone(),
            posts: Arc::clone(&posts),
        }
    };
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit(),
        ResultSchemaEnforcement::Withhold,
        factory,
    )
    .with_app_state_source(desk.source());
    Rig {
        desk,
        posts,
        plane,
        management: granted_management().await,
    }
}

impl Rig {
    async fn serve(&self, name: &str, arguments: Value) -> Value {
        let clock = FakeClock::new();
        self.plane
            .serve(
                servable(name).expect("the capability is served"),
                &arguments,
                ServeContext {
                    cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                    grantee: GRANTEE,
                    identity: identity(),
                    management: &self.management,
                    consent: no_relay(),
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
    }

    /// Read the application, returning the Send button's id.
    async fn read(&self) -> String {
        let read = self
            .serve("computer.read_state", json!({"target": TARGET_BUNDLE_ID}))
            .await;
        assert_eq!(read["outcome"], "completed", "{read}");
        let text = read["state_text"]
            .as_str()
            .expect("a read carries state_text");
        text.lines()
            .find(|line| line.contains("Send"))
            .and_then(|line| line.split_whitespace().next())
            .unwrap_or_else(|| panic!("the read shows no Send button: {text}"))
            .to_string()
    }

    async fn press(&self, element_id: &str) -> Value {
        self.serve("computer.press_element", json!({"element_id": element_id}))
            .await
    }

    async fn type_text(&self) -> Value {
        self.serve(
            "computer.type",
            json!({"target": TARGET_BUNDLE_ID, "text": "hi"}),
        )
        .await
    }

    fn presses(&self) -> Vec<u64> {
        self.desk.state().presses.clone()
    }

    fn posts(&self) -> usize {
        self.posts.lock().unwrap().calls.len()
    }
}

/// The refusal names the reason, says nothing was done and how to go on.
fn assert_person_refusal(reply: &Value, reason: &str) {
    assert_eq!(reply["outcome"], "state_changed_by_person", "{reply}");
    assert_eq!(reply["reason"], reason, "{reply}");
    let remedy = reply["remedy"].as_str().expect("the refusal has a remedy");
    assert!(
        remedy.starts_with("The person used ")
            && remedy
                .ends_with(" since your last read. Call read_state, then act on what it shows."),
        "{remedy}"
    );
}

#[tokio::test]
async fn a_press_after_the_person_moved_focus_is_refused_and_nothing_is_pressed() {
    let rig = rig().await;
    let send = rig.read().await;

    rig.desk.state().focus = DeskFocus::Element(11);
    let reply = rig.press(&send).await;

    assert_person_refusal(&reply, "focus_changed");
    assert!(rig.presses().is_empty(), "pressed {:?}", rig.presses());
}

#[tokio::test]
async fn a_write_after_the_person_switched_tabs_is_refused_and_nothing_is_written() {
    let rig = rig().await;
    let read = rig
        .serve(
            "computer.read_state",
            json!({"target": TARGET_BUNDLE_ID, "text_filter": "Composer"}),
        )
        .await;
    let composer = read["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.contains("Composer"))
        .and_then(|line| line.split_whitespace().next())
        .expect("the filtered read shows the composer")
        .to_string();

    // A browser's window takes its active tab's title.
    rig.desk.state().window = Some((1, Some("Inbox".into())));
    let reply = rig
        .serve(
            "computer.write_text",
            json!({"element_id": composer, "text": "hi", "write_mode": "replace_value"}),
        )
        .await;

    assert_person_refusal(&reply, "window_changed");
    assert!(rig.desk.state().writes.is_empty(), "a write was made");
}

#[tokio::test]
async fn a_press_after_this_module_s_own_press_moved_focus_is_allowed() {
    let rig = rig().await;
    let send = rig.read().await;
    {
        let mut state = rig.desk.state();
        state.after_action = Some(chat("Sent"));
        state.focus_after_action = Some(DeskFocus::Element(11));
        state.window = Some((1, Some("Draft".into())));
    }

    let first = rig.press(&send).await;
    assert_eq!(first["outcome"], "completed", "{first}");
    let second = rig.press(&send).await;

    assert_eq!(second["outcome"], "completed", "{second}");
    assert_eq!(rig.presses(), vec![SEND, SEND]);
}

#[tokio::test]
async fn typing_after_the_person_typed_into_the_frontmost_app_is_refused_and_nothing_is_posted() {
    let rig = rig().await;
    let _ = rig.read().await;

    // A key press from hardware (source pid 0, the person) counted while
    // the application is frontmost.
    rig.desk.state().input.push((0, Instant::now()));
    let reply = rig.type_text().await;

    assert_person_refusal(&reply, "input_seen");
    assert_eq!(reply["effect_status"], "not_dispatched", "{reply}");
    assert_eq!(reply["posts_returned"], 0, "{reply}");
    assert_eq!(rig.posts(), 0, "a refused type posted");
}

#[tokio::test]
async fn the_person_typing_in_another_application_does_not_refuse() {
    let rig = rig().await;
    let send = rig.read().await;

    {
        let mut state = rig.desk.state();
        state.frontmost = Some(grant().pid + 1);
        state.input.push((0, Instant::now()));
    }
    let reply = rig.press(&send).await;

    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.presses(), vec![SEND]);
}

#[tokio::test]
async fn a_press_with_nothing_changed_since_the_read_is_allowed() {
    let rig = rig().await;
    let send = rig.read().await;

    let reply = rig.press(&send).await;

    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.presses(), vec![SEND]);
}

#[tokio::test]
async fn after_the_refusal_a_read_lets_the_press_through() {
    let rig = rig().await;
    let send = rig.read().await;
    rig.desk.state().focus = DeskFocus::Element(11);

    assert_person_refusal(&rig.press(&send).await, "focus_changed");
    // A refusal shows the agent no new state, so it does not reset what the
    // agent was last shown and a retry is refused again.
    assert_person_refusal(&rig.press(&send).await, "focus_changed");

    let send = rig.read().await;
    let reply = rig.press(&send).await;

    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.presses(), vec![SEND]);
}

/// The input count takes this module's own keystrokes some time after they
/// are posted, which can be after the read the reply's diff came from. They
/// are still this module's, not the person's.
#[tokio::test]
async fn this_module_s_own_keystrokes_counted_late_are_not_taken_for_the_person_s() {
    let rig = rig().await;
    let send = rig.read().await;
    {
        let mut state = rig.desk.state();
        state.after_action = Some(chat("Draft hi"));
    }
    rig.posts.lock().unwrap().counted_after = Some(Duration::from_millis(80));

    let keys = rig
        .serve(
            "computer.keys",
            json!({"keys": ["shift", "a"], "target": TARGET_BUNDLE_ID}),
        )
        .await;
    assert_eq!(keys["outcome"], "delivery_unconfirmed", "{keys}");
    assert_eq!(rig.posts(), 1);
    let reply = rig.press(&send).await;

    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.presses(), vec![SEND]);
}

#[tokio::test]
async fn an_action_never_shown_the_application_is_not_refused() {
    let rig = rig().await;
    rig.desk.state().input.push((0, Instant::now()));

    let reply = rig.type_text().await;

    assert_ne!(reply["outcome"], "state_changed_by_person", "{reply}");
    assert_eq!(rig.posts(), 1);
}

#[tokio::test]
async fn another_process_s_synthetic_input_is_not_attributed_to_the_person() {
    let rig = rig().await;
    let send = rig.read().await;
    rig.desk.state().input.push((4242, Instant::now()));
    let reply = rig.press(&send).await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.presses(), vec![SEND]);
}

#[tokio::test]
async fn every_filtered_read_even_without_matches_refreshes_person_marks() {
    for filter in [
        json!({"text_filter": "missing"}),
        json!({"text_filter": "Composer"}),
        json!({"role_filter": ["AXLink"]}),
        json!({"role_filter": ["AXButton"]}),
    ] {
        let rig = rig().await;
        let send = rig.read().await;
        {
            let mut state = rig.desk.state();
            state.focus = DeskFocus::Element(11);
            state.window = Some((1, Some("Inbox".into())));
            state.input.push((0, Instant::now()));
        }
        let mut arguments = filter;
        arguments["target"] = json!(TARGET_BUNDLE_ID);
        let read = rig.serve("computer.read_state", arguments).await;
        assert_eq!(read["outcome"], "completed", "{read}");
        let reply = rig.press(&send).await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(rig.presses(), vec![SEND]);
        rig.desk.state().input.push((0, Instant::now()));
        assert_person_refusal(&rig.press(&send).await, "input_seen");
        assert_eq!(rig.presses(), vec![SEND]);
    }
}

#[tokio::test]
async fn first_read_of_a_frontmost_process_does_not_count_input_predating_the_read() {
    let rig = rig().await;
    rig.desk
        .state()
        .input
        .push((0, Instant::now() - Duration::from_secs(60)));
    let send = rig.read().await;
    let reply = rig.press(&send).await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.presses(), vec![SEND]);
}

#[tokio::test]
async fn uncovered_frontmost_input_refuses_honestly_but_background_and_focus_checks_work() {
    let rig = rig().await;
    let send = rig.read().await;
    rig.desk.state().hardware_coverage = None;
    let reply = rig.press(&send).await;
    assert_eq!(reply["outcome"], "observer_unavailable", "{reply}");
    assert!(reply["remedy"]
        .as_str()
        .unwrap()
        .contains("could not tell whether"));
    assert!(rig.presses().is_empty());
    let typed = rig.type_text().await;
    assert_eq!(typed["outcome"], "observer_unavailable", "{typed}");
    assert_eq!(rig.posts(), 0);
    rig.desk.state().focus = DeskFocus::Element(11);
    assert_person_refusal(&rig.press(&send).await, "focus_changed");
    rig.desk.state().focus = DeskFocus::Element(COMPOSER);
    rig.desk.state().window = Some((1, Some("Inbox".into())));
    assert_person_refusal(&rig.press(&send).await, "window_changed");
    rig.desk.state().window = Some((1, Some("Draft".into())));
    rig.desk.state().frontmost = Some(grant().pid + 1);
    assert_eq!(rig.press(&send).await["outcome"], "completed");
    assert_eq!(rig.presses(), vec![SEND]);
}

#[tokio::test]
async fn observer_started_after_read_requires_a_new_read() {
    let rig = rig().await;
    let send = rig.read().await;
    rig.desk.state().hardware_coverage = Some(Instant::now());
    assert_eq!(rig.press(&send).await["outcome"], "observer_unavailable");
    let send = rig.read().await;
    assert_eq!(rig.press(&send).await["outcome"], "completed");
}

#[tokio::test]
async fn config_filter_matches_emoji_label_and_discloses_unpopulated_window_content() {
    let rig = rig().await;
    rig.desk.state().roots = vec![RawElement::fixture(1, "AXWindow")
        .titled("Dashboard")
        .with_children(vec![RawElement::fixture(2, "AXWebArea")])];
    let empty = rig
        .serve(
            "computer.read_state",
            json!({"target": TARGET_BUNDLE_ID, "text_filter": "Config"}),
        )
        .await;
    assert_eq!(empty["outcome"], "completed", "{empty}");
    assert_eq!(empty["unreadable_subtrees"], 1, "{empty}");
    assert!(empty["state_text"]
        .as_str()
        .unwrap()
        .contains("Accessibility content incomplete"));
    rig.desk.state().roots = vec![RawElement::fixture(1, "AXWindow")
        .titled("Dashboard")
        .with_children(vec![RawElement::fixture(2, "AXWebArea").with_children(
            vec![RawElement::fixture(SEND, "AXButton").titled("⚙️ Config")],
        )])];
    for filter in [
        json!({"text_filter": "Config"}),
        json!({"text_filter": "config"}),
        json!({"role_filter": ["AXButton", "AXLink"]}),
    ] {
        let mut arguments = filter;
        arguments["target"] = json!(TARGET_BUNDLE_ID);
        let reply = rig.serve("computer.read_state", arguments).await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(reply["unreadable_subtrees"], 0, "{reply}");
        assert!(
            reply["state_text"].as_str().unwrap().contains("⚙️ Config"),
            "{reply}"
        );
    }
    rig.desk.state().roots = vec![RawElement::fixture(1, "AXWindow").titled("Dashboard")];
    let shell = rig
        .serve(
            "computer.read_state",
            json!({"target": TARGET_BUNDLE_ID, "text_filter": "Config"}),
        )
        .await;
    assert_eq!(shell["unreadable_subtrees"], 1, "{shell}");
}

#[tokio::test]
async fn session_hardware_input_requires_a_fresh_read_when_the_target_becomes_frontmost() {
    let rig = rig().await;
    let send = rig.read().await;
    {
        let mut state = rig.desk.state();
        state.frontmost = Some(grant().pid + 1);
        state.input.push((0, Instant::now()));
        state.frontmost = Some(grant().pid);
    }
    assert_person_refusal(&rig.press(&send).await, "input_seen");
    assert!(rig.presses().is_empty());
    let send = rig.read().await;
    assert_eq!(rig.press(&send).await["outcome"], "completed");
    assert_eq!(rig.presses(), vec![SEND]);
}
