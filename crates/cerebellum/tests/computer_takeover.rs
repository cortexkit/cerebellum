//! Serving the takeover actions over the wire: moving, dragging and scrolling
//! with the real pointer.
//!
//! Every test drives `ComputerPlane::serve` in withholding mode, so a reply
//! its row does not declare fails the test, and asserts on what the platform
//! driver was asked to post rather than on the outcome alone.
//!
//! The driver here runs the observed-mode gates the macOS driver runs, through
//! the same shared helpers: the idle gate before anything is posted, the seize
//! watcher and the frontmost check before every post, and the paired release
//! of a held button when a sequence stops. Only the event posting itself is
//! recorded instead of sent to the window server.

mod support;

use std::cell::Cell;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::computer_grants::{AppCode, ConsentContext, GrantNeed};
use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::app_state::image::ImageMapping;
use cerebellum_computer::app_state::session::RegisteredImage;
use cerebellum_computer::app_state::source::RawElement;
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::dispatch::{
    begin_observed_sequence, dispatch_observed_post_in_order, HeartbeatMarker,
    HeartbeatObservation, HeartbeatProbe, ObservedSequenceHooks, SeizeWatcher, SourcedInputEvent,
    UserIdleEstimator, HARDWARE_INPUT_SOURCE_PID,
};
use cerebellum_computer::platform::process_event::{post_guarded_event_sequence, SyntheticStep};
use cerebellum_computer::platform::{
    AccessibilityTreeRequest, AccessibilityTreeResult, AttendancePreconditionRequest,
    AttendancePreconditionResult, CapabilityAdvertisementContext, CapabilityDeclaration,
    DispatchResult, DriverError, EffectObservationRequest, EffectObservationResult, EffectStatus,
    ElementResolutionRequest, ElementResolutionResult, FocusQueryRequest, FocusQueryResult,
    FrontingSnapshot, GlobalDispatchRequest, IdleReading, InputObservationRequest,
    InputObservationResult, InputObserverLiveness, PlatformDriver, ProcessEventRefusal,
    ProcessGrant, SemanticDispatchRequest, SequencePostFailure, SyntheticAction,
    SyntheticDispatchRequest, SyntheticPoint, SyntheticScrollAxis, TargetResolution,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};
use serde_json::{json, Value};
use support::computer::{
    audit, grant, grant_app, identity, no_relay, relayed, Desk, InjectedCode, ScriptedCarrier,
    TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};

/// A second application, with no grant unless a test gives it one.
const OTHER_BUNDLE_ID: &str = "com.example.Other";
const OTHER_PID: u32 = 5151;
/// The pid the fake desk attributes the module's own posts to.
const OUR_PID: i64 = 7;

fn other() -> ProcessGrant {
    ProcessGrant {
        pid: OTHER_PID,
        bundle_identity: OTHER_BUNDLE_ID.to_string(),
        process_generation_evidence: "1700000000000001".to_string(),
    }
}

/// Two running applications, each resolvable by name and by pid.
struct TwoApplications;

impl TargetResolver for TwoApplications {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        match bundle_identity {
            TARGET_BUNDLE_ID => TargetResolution::Resolved(grant()),
            OTHER_BUNDLE_ID => TargetResolution::Resolved(other()),
            _ => TargetResolution::NotRunning,
        }
    }

    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        [grant(), other()]
            .into_iter()
            .find(|process| process.pid == pid)
    }

    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(InjectedCode::default())
    }
}

/// What the fake pointer was asked to do, and how it is scripted to behave.
#[derive(Default)]
struct Pointer {
    dispatched: Vec<SyntheticDispatchRequest>,
    /// Each event posted, by its index in the action's sequence, and whether
    /// it was a release posted to recover a held button.
    posts: Vec<(usize, bool)>,
    idle_ms: u64,
    /// Hardware input arrives just before the post with this index.
    seize_before_post: Option<usize>,
    /// Signalled after the first post; the sequence then waits for the
    /// caller's cancel before going on.
    pause_after_first_post: Option<Arc<tokio::sync::Notify>>,
    /// The heartbeat that proves the input watch live is never seen.
    heartbeat_missed: bool,
    /// The platform refuses the dispatch outright with this error.
    fail_with: Option<DriverError>,
}

struct PointerDriver {
    pointer: Arc<Mutex<Pointer>>,
    desk: Desk,
}

fn stopped(watcher: &SeizeWatcher) -> DriverError {
    match watcher.abort_decision() {
        Some(abort) => DriverError::ObservedDispatchAborted(abort),
        None => DriverError::Unsupported("refused without a recorded abort"),
    }
}

impl PlatformDriver for PointerDriver {
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
            "a takeover action is never semantic",
        ))
    }

    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported(
            "a takeover action is never per process",
        ))
    }

    /// The observed global sequence, in the macOS driver's order: the idle
    /// gate and heartbeat before anything, then for every post the seize
    /// watcher and the frontmost check, with a held button released when the
    /// sequence stops.
    fn dispatch_global(
        &mut self,
        request: GlobalDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        let (idle_ms, seize_before_post, pause, heartbeat_missed) = {
            let mut pointer = self.pointer.lock().unwrap();
            pointer.dispatched.push(request.synthetic.clone());
            if let Some(error) = pointer.fail_with.clone() {
                return Err(error);
            }
            (
                pointer.idle_ms,
                pointer.seize_before_post,
                pointer.pause_after_first_post.clone(),
                pointer.heartbeat_missed,
            )
        };
        let target_pid = request.synthetic.target.pid;
        let estimator = UserIdleEstimator::new();
        let mut watcher = SeizeWatcher::new(request.maximum_seize_detection_latency_ms);
        let roles = request.synthetic.action.step_roles();
        for _ in &roles {
            watcher.queue_post();
        }
        let probe = HeartbeatProbe {
            marker: HeartbeatMarker::new(1),
            posted_at_ms: 0,
            our_pid: OUR_PID,
        };
        if begin_observed_sequence(
            &estimator,
            &mut watcher,
            OUR_PID,
            Instant::now(),
            ObservedSequenceHooks {
                create_tap: || (),
                read_idle: || IdleReading::Milliseconds(idle_ms),
                drain: |_: &()| Vec::new(),
                post_heartbeat: || probe,
            },
        )
        .is_err()
        {
            return Err(stopped(&watcher));
        }

        let steps = roles
            .into_iter()
            .enumerate()
            .map(|(index, role)| SyntheticStep { event: index, role })
            .collect();
        let posted = Cell::new(0_usize);
        let pointer = Arc::clone(&self.pointer);
        let desk = self.desk.clone();
        let sequence = post_guarded_event_sequence(steps, cancelled, |index, event, recovery| {
            let Some(event) = event else {
                return Ok(0);
            };
            if recovery {
                pointer.lock().unwrap().posts.push((event, true));
                return Ok(1);
            }
            if seize_before_post == Some(index) {
                watcher.observe_sourced_input(
                    SourcedInputEvent {
                        source_unix_process_id: HARDWARE_INPUT_SOURCE_PID,
                        detection_latency_ms: 1,
                        platform_delivery_latency_ms: Some(0),
                    },
                    OUR_PID,
                    index,
                );
            }
            dispatch_observed_post_in_order(
                &mut watcher,
                index,
                probe,
                |posted: &HeartbeatProbe| {
                    if heartbeat_missed {
                        return HeartbeatObservation::Missed;
                    }
                    HeartbeatObservation::Seen {
                        marker: posted.marker,
                        source_unix_process_id: posted.our_pid,
                        observed_at_ms: posted.posted_at_ms,
                    }
                },
                || desk.state().frontmost == Some(target_pid),
                || pointer.lock().unwrap().posts.push((event, false)),
            )
            .map_err(|_| stopped(&watcher))?;
            watcher.take_post_slot();
            posted.set(posted.get() + 1);
            if posted.get() == 1 {
                if let Some(pause) = &pause {
                    pause.notify_one();
                    let deadline = Instant::now() + std::time::Duration::from_secs(2);
                    while !cancelled() && Instant::now() < deadline {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
            }
            Ok(1)
        });
        match sequence {
            Ok(report) => Ok(DispatchResult {
                accepted_by_platform: report.posts_returned > 0,
                effect_status: EffectStatus::EffectIndeterminate,
                unreadable_subtrees: 0,
                delivery_posts_returned: report.posts_returned,
                delivery_generation_verifications: 0,
            }),
            Err(failure) => Err(failure
                .refusal
                .unwrap_or(DriverError::SyntheticDispatchFailed(SequencePostFailure {
                    posts_returned: failure.posts_returned,
                    refusal: ProcessEventRefusal::Cancelled,
                    held_state: failure.held_state,
                }))),
        }
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

    /// A machine whose screen was read and found unlocked, so the whole
    /// replies asserted here carry no unknown-lock disclosure.
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
    PointerDriver,
>;

struct Rig {
    desk: Desk,
    pointer: Arc<Mutex<Pointer>>,
    plane: Plane,
    management: Arc<ManagementPlane>,
    image_id: String,
}

impl Rig {
    fn dispatched(&self) -> Vec<SyntheticDispatchRequest> {
        self.pointer.lock().unwrap().dispatched.clone()
    }

    fn posts(&self) -> Vec<(usize, bool)> {
        self.pointer.lock().unwrap().posts.clone()
    }
}

/// The fixture application frontmost, with an image of its window whose
/// pixels map one to one onto the desktop at (100, 50); whatever is under a
/// point belongs to it unless a test says otherwise. No grant is held.
fn rig() -> Rig {
    let desk = Desk::new(vec![RawElement::fixture(1, "AXWindow").titled("Fixture")]);
    {
        let mut state = desk.state();
        state.application_hit = Some((60, Some(grant().pid)));
        state.system_wide_hit = Some((60, Some(grant().pid)));
    }
    let pointer = Arc::new(Mutex::new(Pointer {
        idle_ms: 60_000,
        ..Pointer::default()
    }));
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit(),
        ResultSchemaEnforcement::Withhold,
        {
            let pointer = Arc::clone(&pointer);
            let desk = desk.clone();
            move || PointerDriver {
                pointer: Arc::clone(&pointer),
                desk: desk.clone(),
            }
        },
    )
    .with_app_state_source(desk.source());
    let management = Arc::new(ManagementPlane::new(Arc::new(TwoApplications)));
    let image_id = management.app_state_sessions().register_image(
        &identity().conversation_key,
        RegisteredImage {
            bundle_identity: TARGET_BUNDLE_ID.to_string(),
            pid: grant().pid,
            process_generation: grant().process_generation_evidence,
            width_px: 1000,
            height_px: 600,
            mapping: ImageMapping::for_window(
                (100.0, 50.0),
                (1000.0, 600.0),
                (1000, 600),
                (1000, 600),
            )
            .expect("a whole-window mapping"),
        },
    );
    Rig {
        desk,
        pointer,
        plane,
        management,
        image_id,
    }
}

async fn hold_takeover(management: &ManagementPlane) {
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    management
        .computer_grants()
        .require(
            &GrantNeed::Takeover,
            &relayed(&carrier),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .expect("the takeover question is answered allow_conversation");
}

async fn hold_other_app(management: &ManagementPlane) {
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    management
        .admit_app(
            OTHER_BUNDLE_ID,
            &relayed(&carrier),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .expect("the other application's question is answered allow_conversation");
}

/// Both grants a move or drag in the fixture application needs.
async fn granted_rig() -> Rig {
    let rig = rig();
    grant_app(&rig.management).await;
    hold_takeover(&rig.management).await;
    rig
}

async fn serve_with(
    rig: &Rig,
    name: &str,
    arguments: Value,
    consent: ConsentContext,
    cancel: cerebellum::CancelHandle,
) -> Value {
    let clock = FakeClock::new();
    let reply = rig
        .plane
        .serve(
            servable(name).expect("the takeover rows are served"),
            &arguments,
            ServeContext {
                cancel,
                grantee: GRANTEE,
                identity: identity(),
                management: &rig.management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"));
    assert!(rig.plane.result_schema_findings().is_empty());
    reply
}

async fn serve(rig: &Rig, name: &str, arguments: Value) -> Value {
    serve_with(
        rig,
        name,
        arguments,
        no_relay(),
        cerebellum::CancelHandle::pending(),
    )
    .await
}

fn at(x: f64, y: f64) -> SyntheticPoint {
    SyntheticPoint { x, y }
}

// ---------------------------------------------------------------------------
// Containment targets
// ---------------------------------------------------------------------------

/// A move to a point in a granted application posts one pointer move at the
/// desktop point the image pixel shows, contained to that application.
#[tokio::test]
async fn a_move_into_a_granted_application_posts_one_move_at_the_mapped_point() {
    let rig = granted_rig().await;
    let reply = serve(
        &rig,
        "computer.takeover_move",
        json!({"image_id": rig.image_id, "to": {"x": 10, "y": 20}}),
    )
    .await;
    assert_eq!(reply, json!({"outcome": "completed"}));
    let dispatched = rig.dispatched();
    assert_eq!(dispatched.len(), 1);
    assert_eq!(dispatched[0].target, grant());
    assert_eq!(
        dispatched[0].action,
        SyntheticAction::move_pointer(at(110.0, 70.0))
    );
    assert_eq!(rig.posts(), vec![(0, false)]);
}

/// A move whose point lands in an application this conversation holds no
/// app grant for is refused naming that application. Nobody is asked, not
/// even for the takeover, and nothing is posted.
#[tokio::test]
async fn a_move_into_an_application_without_a_grant_asks_nobody_and_posts_nothing() {
    let rig = rig();
    grant_app(&rig.management).await;
    {
        let mut state = rig.desk.state();
        state.application_hit = None;
        state.system_wide_hit = Some((99, Some(OTHER_PID)));
    }
    let carrier = ScriptedCarrier::default();
    let reply = serve_with(
        &rig,
        "computer.takeover_move",
        json!({"image_id": rig.image_id, "to": {"x": 10, "y": 20}}),
        relayed(&carrier),
        cerebellum::CancelHandle::pending(),
    )
    .await;
    assert_eq!(reply["outcome"], "app_grant_required", "{reply}");
    assert_eq!(reply["bundle_identity"], OTHER_BUNDLE_ID);
    assert!(
        reply["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains("read_state")),
        "{reply}"
    );
    assert!(carrier.questions().is_empty(), "{:?}", carrier.questions());
    assert!(rig.dispatched().is_empty());
    assert!(rig.posts().is_empty());
}

/// The application under the point is the containment target even when it
/// is not the image's: with its own grant, the move is contained to it.
#[tokio::test]
async fn a_move_is_contained_to_the_application_under_its_point() {
    let rig = granted_rig().await;
    hold_other_app(&rig.management).await;
    {
        let mut state = rig.desk.state();
        state.application_hit = None;
        state.system_wide_hit = Some((99, Some(OTHER_PID)));
        state.frontmost = Some(OTHER_PID);
    }
    let reply = serve(
        &rig,
        "computer.takeover_move",
        json!({"image_id": rig.image_id, "to": {"x": 10, "y": 20}}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(rig.dispatched()[0].target, other());
}

/// A drag that starts and ends in one application presses, moves and
/// releases there.
#[tokio::test]
async fn a_drag_within_one_application_presses_moves_and_releases() {
    let rig = granted_rig().await;
    let reply = serve(
        &rig,
        "computer.takeover_drag",
        json!({"image_id": rig.image_id, "from": {"x": 10, "y": 20}, "to": {"x": 300, "y": 400}}),
    )
    .await;
    assert_eq!(reply, json!({"outcome": "completed"}));
    let dispatched = rig.dispatched();
    assert_eq!(dispatched[0].target, grant());
    assert_eq!(
        dispatched[0].action,
        SyntheticAction::drag_pointer(at(110.0, 70.0), at(400.0, 450.0))
    );
    assert_eq!(rig.posts(), vec![(0, false), (1, false), (2, false)]);
}

/// A drag whose end lies in a different application is refused before
/// anything is posted, even with every grant held for both.
#[tokio::test]
async fn a_drag_across_two_applications_is_refused_before_anything_is_posted() {
    let rig = granted_rig().await;
    hold_other_app(&rig.management).await;
    {
        let mut state = rig.desk.state();
        state.application_hit = None;
        state.system_wide_hits_at = vec![((400.0, 450.0), (99, Some(OTHER_PID)))];
    }
    let reply = serve(
        &rig,
        "computer.takeover_drag",
        json!({"image_id": rig.image_id, "from": {"x": 10, "y": 20}, "to": {"x": 300, "y": 400}}),
    )
    .await;
    assert_eq!(reply["outcome"], "target_not_frontmost", "{reply}");
    assert_eq!(reply["reason"], "drag_crosses_applications");
    assert!(rig.dispatched().is_empty());
    assert!(rig.posts().is_empty());
}

/// A scroll names its application and carries no point, so the takeover
/// grant alone admits it: no app grant is held here, and none is asked for.
#[tokio::test]
async fn a_scroll_needs_only_the_takeover_grant() {
    let rig = rig();
    hold_takeover(&rig.management).await;
    let carrier = ScriptedCarrier::default();
    let reply = serve_with(
        &rig,
        "computer.takeover_scroll",
        json!({"target": TARGET_BUNDLE_ID, "axis": "horizontal", "amount_lines": -3}),
        relayed(&carrier),
        cerebellum::CancelHandle::pending(),
    )
    .await;
    assert_eq!(reply, json!({"outcome": "completed"}));
    assert!(carrier.questions().is_empty());
    let dispatched = rig.dispatched();
    assert_eq!(dispatched[0].target, grant());
    assert_eq!(
        dispatched[0].action,
        SyntheticAction::scroll_along(
            SyntheticScrollAxis::Horizontal,
            cerebellum_computer::platform::SyntheticScrollUnit::Line,
            -3
        )
    );
    assert_eq!(rig.posts(), vec![(0, false)]);
}

/// Without the takeover grant a scroll raises the takeover question, and an
/// app grant for the same application does not stand in for it: the question
/// is still asked, and a refusal posts nothing.
#[tokio::test]
async fn a_scroll_without_the_takeover_grant_asks_for_it_even_under_an_app_grant() {
    let rig = rig();
    grant_app(&rig.management).await;
    let carrier = ScriptedCarrier::answering(&["deny"]);
    let reply = serve_with(
        &rig,
        "computer.takeover_scroll",
        json!({"target": TARGET_BUNDLE_ID, "axis": "vertical", "amount_lines": 2}),
        relayed(&carrier),
        cerebellum::CancelHandle::pending(),
    )
    .await;
    assert_eq!(reply["outcome"], "consent_denied", "{reply}");
    let questions = carrier.questions();
    assert_eq!(questions.len(), 1);
    assert_eq!(questions[0]["params"]["grant_kind"], "takeover");
    assert!(rig.dispatched().is_empty());
    assert!(rig.posts().is_empty());
}

// ---------------------------------------------------------------------------
// Refusals on the way to the pointer
// ---------------------------------------------------------------------------

/// A target that is not frontmost is refused by the check made before every
/// post, and nothing is posted: a takeover action never fronts anything.
#[tokio::test]
async fn a_target_that_is_not_frontmost_is_refused_at_the_post() {
    let rig = granted_rig().await;
    rig.desk.state().frontmost = Some(OTHER_PID);
    let reply = serve(
        &rig,
        "computer.takeover_move",
        json!({"image_id": rig.image_id, "to": {"x": 10, "y": 20}}),
    )
    .await;
    assert_eq!(reply["outcome"], "target_not_frontmost", "{reply}");
    assert_eq!(reply["reason"], "target_focus_mismatch");
    assert_eq!(rig.dispatched().len(), 1, "the check is the dispatch's own");
    assert!(rig.posts().is_empty());
}

/// An image id the conversation does not hold, and a point outside the
/// image, are refused before anything is looked up under the pointer.
#[tokio::test]
async fn a_stale_image_and_a_point_outside_it_are_refused_by_name() {
    let rig = granted_rig().await;
    let reply = serve(
        &rig,
        "computer.takeover_move",
        json!({"image_id": "image-that-was-never-returned", "to": {"x": 10, "y": 20}}),
    )
    .await;
    assert_eq!(reply["outcome"], "image_reference_unknown", "{reply}");

    let reply = serve(
        &rig,
        "computer.takeover_drag",
        json!({"image_id": rig.image_id, "from": {"x": 10, "y": 20}, "to": {"x": 1000, "y": 20}}),
    )
    .await;
    assert_eq!(reply["outcome"], "point_out_of_bounds", "{reply}");
    assert!(rig.desk.state().hit_scopes.is_empty());
    assert!(rig.dispatched().is_empty());
}

/// A dispatch the module could not carry out answers `dispatch_failed` with
/// the dispatch error's code, never `invalid_request`: the request was
/// correct, and a caller told otherwise would change it. Both replies pass
/// the rows' result schemas in withholding mode.
#[tokio::test]
async fn a_failed_dispatch_is_the_module_s_failure_not_the_request_s() {
    let rig = granted_rig().await;
    rig.pointer.lock().unwrap().fail_with =
        Some(DriverError::Unsupported("global target generation changed"));
    let reply = serve(
        &rig,
        "computer.takeover_move",
        json!({"image_id": rig.image_id, "to": {"x": 10, "y": 20}}),
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
    assert_eq!(reply["reason"], "synthetic_unavailable");
    assert!(reply["remedy"].is_string());
    assert!(rig.posts().is_empty());

    // An input watch whose heartbeat is never seen is a module failure too,
    // not an unreadable idle time.
    let rig = granted_rig().await;
    rig.pointer.lock().unwrap().heartbeat_missed = true;
    let reply = serve(
        &rig,
        "computer.takeover_scroll",
        json!({"target": TARGET_BUNDLE_ID, "axis": "vertical", "amount_lines": 1}),
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
    assert_eq!(reply["reason"], "observer_unavailable");
    assert!(rig.posts().is_empty());
}

/// A person who used the machine a moment ago keeps the pointer: the idle
/// gate refuses before anything is posted.
#[tokio::test]
async fn recent_input_refuses_the_move_before_anything_is_posted() {
    let rig = granted_rig().await;
    rig.pointer.lock().unwrap().idle_ms = 10;
    let reply = serve(
        &rig,
        "computer.takeover_move",
        json!({"image_id": rig.image_id, "to": {"x": 10, "y": 20}}),
    )
    .await;
    assert_eq!(reply["outcome"], "not_idle", "{reply}");
    assert!(rig.posts().is_empty());
}

/// Input from the person in the middle of a drag stops it at once, and the
/// button it pressed is released rather than left held.
#[tokio::test]
async fn a_seize_mid_drag_stops_it_and_releases_the_button() {
    let rig = granted_rig().await;
    rig.pointer.lock().unwrap().seize_before_post = Some(1);
    let reply = serve(
        &rig,
        "computer.takeover_drag",
        json!({"image_id": rig.image_id, "from": {"x": 10, "y": 20}, "to": {"x": 300, "y": 400}}),
    )
    .await;
    assert_eq!(reply["outcome"], "user_seized_control", "{reply}");
    assert_eq!(rig.posts(), vec![(0, false), (2, true)]);
}

/// A caller's cancel in the middle of a drag stops it at the next post and
/// releases the button the drag pressed, and the reply says so.
#[tokio::test]
async fn a_cancel_mid_drag_releases_the_button() {
    let rig = granted_rig().await;
    let posted = Arc::new(tokio::sync::Notify::new());
    rig.pointer.lock().unwrap().pause_after_first_post = Some(Arc::clone(&posted));
    let cancel = cerebellum::CancelHandle::pending();
    let serving = serve_with(
        &rig,
        "computer.takeover_drag",
        json!({"image_id": rig.image_id, "from": {"x": 10, "y": 20}, "to": {"x": 300, "y": 400}}),
        no_relay(),
        cancel.clone(),
    );
    let interrupt = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), posted.notified())
            .await
            .expect("the drag never reached its first post");
        cancel.cancel();
    };
    let (reply, ()) = tokio::join!(serving, interrupt);
    assert_eq!(reply["outcome"], "cancelled", "{reply}");
    assert_eq!(reply["posts_returned"], 1);
    assert_eq!(reply["reason"], "caller_interrupted_held_input_released");
    assert_eq!(rig.posts(), vec![(0, false), (2, true)]);
}
