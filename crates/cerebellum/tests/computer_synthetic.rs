//! Serving the keystroke capabilities over the wire.
//!
//! Every test here drives `ComputerPlane::serve` -- the boundary the wire
//! route calls -- and asserts on the events the platform driver was asked to
//! post, not on the returned outcome. A handler that answers "completed"
//! while posting nothing has shipped from this repository twice, and an
//! outcome assertion cannot see it.

mod support;

use std::sync::{Arc, Mutex};

use cerebellum::computer_capability::{
    servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
};
use cerebellum::management::ManagementPlane;
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{
    AccessibilityTreeRequest, AccessibilityTreeResult, AttendancePreconditionRequest,
    AttendancePreconditionResult, CapabilityAdvertisementContext, CapabilityDeclaration,
    DispatchResult, DriverError, EffectObservationRequest, EffectObservationResult, EffectStatus,
    ElementResolutionRequest, ElementResolutionResult, FocusQueryRequest, FocusQueryResult,
    FrontingSnapshot, HeldStateDisposition, InputObservationRequest, InputObservationResult,
    InputObserverLiveness, PlatformDriver, PostCallFailure, ProcessEventRefusal, ProcessGrant,
    SemanticDispatchRequest, SequencePostFailure, SyntheticAction, SyntheticDispatchRequest,
    SyntheticKey, SyntheticKeyModifiers, BLOCKED_CHORDS,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::journal::{
    InMemoryJournalStorage, JournalStorage, LifecycleState, ValidatedSeverityTaxonomy,
};
use serde_json::{json, Value};
use support::computer::{
    audit, focused_text_desk, grant, granted_management, identity, management, no_relay,
    TestRedactor, GRANTEE, TARGET_BUNDLE_ID,
};

/// One synthetic dispatch the platform driver was asked to perform.
#[derive(Debug, Clone, PartialEq)]
enum DispatchedCall {
    PerPid(SyntheticDispatchRequest),
    Global(SyntheticDispatchRequest),
    Fronted(SyntheticDispatchRequest),
}

/// What every driver instance built for one test shares: the calls made, and
/// the answers to give. A test flips the answers between serves to exercise
/// failure paths through the same plane.
#[derive(Debug)]
struct Shared {
    calls: Vec<DispatchedCall>,
    interrupt_after_two: Option<Arc<tokio::sync::Notify>>,
    per_pid: Result<DispatchResult, DriverError>,
    global: Result<DispatchResult, DriverError>,
    fronted: FrontedScript,
    route_evidence: cerebellum_computer::platform::input_route::InputRouteEvidence,
}

impl Shared {
    fn handle() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            calls: Vec::new(),
            interrupt_after_two: None,
            per_pid: Ok(DispatchResult {
                accepted_by_platform: true,
                effect_status: EffectStatus::EffectIndeterminate,
                unreadable_subtrees: 0,
                delivery_posts_returned: 1,
                delivery_generation_verifications: 2,
            }),
            global: Ok(DispatchResult {
                accepted_by_platform: true,
                effect_status: EffectStatus::EffectIndeterminate,
                unreadable_subtrees: 0,
                delivery_posts_returned: 0,
                delivery_generation_verifications: 0,
            }),
            fronted: FrontedScript::default(),
            route_evidence: Default::default(),
        }))
    }
}

/// A platform driver that records the synthetic dispatches it is asked for
/// and answers every observation the dispatch seam makes.
struct SyntheticDriver(Arc<Mutex<Shared>>);

impl SyntheticDriver {
    fn factory(shared: Arc<Mutex<Shared>>) -> impl Fn() -> SyntheticDriver {
        move || SyntheticDriver(Arc::clone(&shared))
    }
}

impl PlatformDriver for SyntheticDriver {
    fn take_input_route_evidence(
        &mut self,
    ) -> cerebellum_computer::platform::input_route::InputRouteEvidence {
        std::mem::take(&mut self.0.lock().unwrap().route_evidence)
    }
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
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        let mut shared = self.0.lock().unwrap();
        shared.calls.push(DispatchedCall::PerPid(request));
        if let Some(posted) = shared.interrupt_after_two.clone() {
            drop(shared);
            use cerebellum_computer::platform::process_event::*;
            let steps = (0..5)
                .map(|event| SyntheticStep {
                    event,
                    role: SyntheticStepRole::SelfContained,
                })
                .collect();
            let failure = post_guarded_event_sequence(steps, cancelled, |_, event, _| {
                if event == Some(1) {
                    posted.notify_one();
                    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                    while !cancelled() && std::time::Instant::now() < deadline {
                        std::thread::sleep(std::time::Duration::from_millis(1));
                    }
                }
                Ok::<_, ProcessEventRefusal>(2)
            })
            .expect_err("caller cancellation reached the synchronous sequence");
            return Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
                posts_returned: failure.posts_returned,
                refusal: failure.refusal.unwrap_or(ProcessEventRefusal::Cancelled),
                held_state: failure.held_state,
            }));
        }
        shared.per_pid.clone()
    }

    fn dispatch_global(
        &mut self,
        request: cerebellum_computer::platform::GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        let mut shared = self.0.lock().unwrap();
        shared.calls.push(DispatchedCall::Global(request.synthetic));
        shared.global.clone()
    }

    /// Runs the real fronting bracket over a fake desk, so the plane's
    /// handling of every way a bracket ends is exercised end to end.
    fn dispatch_fronted(
        &mut self,
        request: cerebellum_computer::platform::FrontedDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<cerebellum_computer::dispatch::BracketReport, DriverError> {
        let script = {
            let mut shared = self.0.lock().unwrap();
            shared
                .calls
                .push(DispatchedCall::Fronted(request.synthetic.clone()));
            shared.fronted.clone()
        };
        let units = match &request.synthetic.action {
            SyntheticAction::TypeText { text } => text.chars().count(),
            _ => 1,
        };
        let mut desk = FrontingDesk {
            now: 0,
            frontmost: Some(OTHER_APPLICATION_PID),
            pending: None,
            refuse_front_of: script.refuse_restore.then_some(OTHER_APPLICATION_PID),
            front_latency_ms: script.front_latency_ms.unwrap_or(2),
            unit_failure: script.unit_failure.clone(),
        };
        let chunks_started = std::cell::Cell::new(0);
        let scripted_cancel = || {
            chunks_started.set(chunks_started.get() + 1);
            cancelled() || (script.cancel_after_first_chunk && chunks_started.get() > 1)
        };
        Ok(cerebellum_computer::dispatch::run_fronting_bracket(
            &mut desk,
            &mut cerebellum_computer::dispatch::UserIdleEstimator::new(),
            cerebellum_computer::dispatch::BracketPlan {
                target_pid: request.synthetic.target.pid,
                units,
                maximum_interval_ms: request.maximum_interval_ms,
                maximum_seize_detection_latency_ms: request.maximum_seize_detection_latency_ms,
            },
            &scripted_cancel,
        ))
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
            // A post call returning is not an effect, and the five request
            // schemas declare no post-condition to check: indeterminate is
            // the only honest answer this driver can give.
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

/// How the fake desk behind a fronting bracket misbehaves.
#[derive(Debug, Clone, Default)]
struct FrontingScript {
    refuse_restore: bool,
    cancel_after_first_chunk: bool,
    /// How long a fronting request takes to take effect; 2 ms when unset.
    front_latency_ms: Option<u64>,
    /// When set, every unit post fails this way instead of succeeding.
    unit_failure: Option<SequencePostFailure>,
}

type FrontedScript = FrontingScript;

/// The application in front when a bracket starts.
const OTHER_APPLICATION_PID: u32 = 100;

/// A desk on a fake clock: a fronting request takes effect `front_latency_ms`
/// later, and each unit takes 3 ms to post.
struct FrontingDesk {
    now: u64,
    frontmost: Option<u32>,
    pending: Option<(u32, u64)>,
    refuse_front_of: Option<u32>,
    front_latency_ms: u64,
    unit_failure: Option<SequencePostFailure>,
}

impl FrontingDesk {
    fn advance(&mut self, milliseconds: u64) {
        self.now += milliseconds;
        if let Some((pid, at)) = self.pending {
            if self.now >= at {
                self.frontmost = Some(pid);
                self.pending = None;
            }
        }
    }
}

impl cerebellum_computer::dispatch::FrontingBracketHost for FrontingDesk {
    type Tap = ();
    fn now_ms(&mut self) -> u64 {
        self.now
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.advance(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        if self.refuse_front_of != Some(pid) {
            self.pending = Some((pid, self.now + self.front_latency_ms));
        }
        true
    }
    fn our_pid(&self) -> i64 {
        7
    }
    fn create_tap(&mut self) -> Option<()> {
        Some(())
    }
    fn read_idle(&mut self) -> cerebellum_computer::platform::IdleReading {
        cerebellum_computer::platform::IdleReading::Milliseconds(60_000)
    }
    fn drain(&mut self, _tap: &()) -> Vec<cerebellum_computer::dispatch::SourcedInputEvent> {
        Vec::new()
    }
    fn post_heartbeat(&mut self) -> cerebellum_computer::dispatch::HeartbeatProbe {
        cerebellum_computer::dispatch::HeartbeatProbe {
            marker: cerebellum_computer::dispatch::HeartbeatMarker::new(1),
            posted_at_ms: self.now,
            our_pid: 7,
        }
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        probe: cerebellum_computer::dispatch::HeartbeatProbe,
        _watcher: &mut cerebellum_computer::dispatch::SeizeWatcher,
    ) -> cerebellum_computer::dispatch::HeartbeatObservation {
        cerebellum_computer::dispatch::HeartbeatObservation::Seen {
            marker: probe.marker,
            source_unix_process_id: 7,
            observed_at_ms: probe.posted_at_ms,
        }
    }
    fn post_unit(
        &mut self,
        _index: usize,
    ) -> Result<cerebellum_computer::dispatch::UnitPosted, SequencePostFailure> {
        self.advance(3);
        if let Some(failure) = self.unit_failure.clone() {
            return Err(failure);
        }
        Ok(cerebellum_computer::dispatch::UnitPosted {
            posts_returned: 2,
            generation_verifications: 4,
        })
    }
}

type TestPlane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    SyntheticDriver,
>;

/// A plane whose target application is frontmost with a plain text field
/// focused, so the keystroke rows' secure-field check and frontmost check
/// both pass and a dispatch reaches the driver.
fn plane_with(shared: &Arc<Mutex<Shared>>) -> TestPlane {
    ComputerPlane::with_synthetic_driver(audit(), SyntheticDriver::factory(Arc::clone(shared)))
        .with_app_state_source(focused_text_desk().source())
}

/// Snapshot the dispatch calls made so far, without holding the lock into an
/// await point.
fn dispatched_calls(shared: &Arc<Mutex<Shared>>) -> Vec<DispatchedCall> {
    shared.lock().unwrap().calls.clone()
}

async fn serve(
    plane: &TestPlane,
    name: &str,
    arguments: Value,
    management: &Arc<ManagementPlane>,
    clock: &FakeClock,
) -> Value {
    plane
        .serve(
            servable(name).expect("the capability is servable"),
            &arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management,
                consent: no_relay(),
                clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the reply")
}

fn type_request() -> Value {
    json!({"target": TARGET_BUNDLE_ID, "text": "hi"})
}

fn keys_request(keys: &[&str]) -> Value {
    json!({"keys": keys, "target": TARGET_BUNDLE_ID})
}

/// Typing reaches the named application's process generation and reports
/// structural containment, and a post that nothing confirmed arrived is
/// reported as unconfirmed delivery, with the diff that followed it.
#[tokio::test]
async fn computer_type_reports_pid_structural_and_unconfirmed_delivery() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = granted_management().await;
    let before = plane.journal_entry_count().await;

    let reply = serve(&plane, "computer.type", type_request(), &management, &clock).await;

    assert_eq!(
        reply,
        json!({
            "outcome": "delivery_unconfirmed",
            "containment_rung": "pid_structural",
            "target_fronted": false,
            "effect_status": "effect_indeterminate",
            "changed": [],
            "added": [],
            "removed": [],
            "unreadable_subtrees": 0,
        })
    );
    let calls = dispatched_calls(&shared);
    let [DispatchedCall::PerPid(request)] = &calls[..] else {
        panic!("type must deliver per-process exactly once: {calls:?}");
    };
    assert_eq!(request.target, grant());
    assert_eq!(request.action, SyntheticAction::type_text("hi"));
    assert!(
        plane.journal_entry_count().await > before,
        "a completed type left no audit record"
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );
}

/// A chord without Command is an editing keystroke and runs under compose.
#[tokio::test]
async fn computer_keys_dispatches_a_plain_chord_as_compose() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = granted_management().await;

    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["shift", "a"]),
        &management,
        &clock,
    )
    .await;

    assert_eq!(reply["outcome"], "delivery_unconfirmed");
    let calls = dispatched_calls(&shared);
    let [DispatchedCall::PerPid(request)] = &calls[..] else {
        panic!("keys must deliver per-process exactly once: {calls:?}");
    };
    assert_eq!(request.target, grant());
    assert_eq!(
        request.action,
        SyntheticAction::key_combination(
            SyntheticKey::A,
            SyntheticKeyModifiers {
                shift: true,
                ..SyntheticKeyModifiers::NONE
            },
        )
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );
}

/// Every session-ending chord remains refused even with the application's app
/// grant held; the floor runs before authority and records the attempt.
///
/// Gated to the platforms that HAVE a chord set. The fixture is neutral, but
/// the floor is consulted through `current_blocked_chord_platform()`, which is
/// None on Linux because there is no synthetic dispatch there to block -- so
/// on Linux this test has nothing to iterate and panicked at the expect
/// instead (red on CI for one run, #18). Membership on every platform is held
/// by `the_session_floor_holds_every_chord_this_test_names`, which passes the
/// platform explicitly; this test adds the wire-level proof on hosts where the
/// wire can reach the floor.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn every_listed_session_ending_chord_is_refused_above_an_app_grant() {
    let platform = cerebellum_computer::platform::current_blocked_chord_platform()
        .expect("this test is compiled only where a chord set exists");
    let clock = FakeClock::new();
    let management = granted_management().await;
    let shared = Shared::handle();
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit(),
        ResultSchemaEnforcement::Withhold,
        SyntheticDriver::factory(Arc::clone(&shared)),
    );
    let mut tested = 0;

    for blocked in BLOCKED_CHORDS
        .iter()
        .filter(|blocked| blocked.platform == platform)
    {
        let reply = serve(
            &plane,
            "computer.keys",
            keys_request(blocked.chord),
            &management,
            &clock,
        )
        .await;
        let chord = blocked.chord.join("+");
        assert_eq!(reply["outcome"], "chord_blocked", "{chord} was admitted");
        assert_eq!(
            reply["chord"], chord,
            "{chord} was rewritten in its refusal"
        );
        assert_eq!(reply["reason"], blocked.reason, "{chord} lost its reason");
        assert!(
            reply["remedy"]
                .as_str()
                .is_some_and(|remedy| remedy.contains("do this yourself")),
            "{chord} offered a grant path"
        );
        tested += 1;
    }
    assert!(
        tested > 0,
        "the current platform has no session-ending chord coverage"
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "the declared chord refusal failed schema validation: {:?}",
        plane.result_schema_findings()
    );

    let history = plane
        .refusal_history_for_test(GRANTEE)
        .await
        .expect("a blocked chord enters the refusal ring");
    assert_eq!(history.total_count, tested);
    for (record, blocked) in history.records.iter().zip(
        BLOCKED_CHORDS
            .iter()
            .filter(|blocked| blocked.platform == platform),
    ) {
        let chord = blocked.chord.join("+");
        assert_eq!(record.claimed_addressing, chord);
        assert_eq!(record.reason.chord, chord);
        assert_eq!(record.reason.reason, blocked.reason);
    }
}

/// Exact modifiers matter: quitting an app and saving-as remain grantable.
/// The floor's membership, as literals this file owns.
///
/// The test above iterates BLOCKED_CHORDS, so removing an entry from the
/// constant removes that entry's check with it and the test stays green --
/// that mutation was run and was not caught. This one names what the floor
/// must hold on each platform in its own words, so a chord dropped from the
/// constant fails here by name. Add to BOTH when the floor grows.
#[test]
fn the_session_floor_holds_every_chord_this_test_names() {
    use cerebellum_computer::platform::{blocked_chord, BlockedChordPlatform};

    let mods = |command: bool, control: bool, option: bool, shift: bool, windows: bool| {
        SyntheticKeyModifiers {
            command,
            control,
            option,
            shift,
            windows,
        }
    };
    let expected: [(
        BlockedChordPlatform,
        SyntheticKeyModifiers,
        SyntheticKey,
        &str,
    ); 6] = [
        (
            BlockedChordPlatform::MacOs,
            mods(true, true, false, false, false),
            SyntheticKey::Q,
            "lock",
        ),
        (
            BlockedChordPlatform::MacOs,
            mods(true, false, false, true, false),
            SyntheticKey::Q,
            "logout",
        ),
        (
            BlockedChordPlatform::MacOs,
            mods(true, false, true, false, false),
            SyntheticKey::Escape,
            "force_quit",
        ),
        (
            BlockedChordPlatform::MacOs,
            mods(true, false, false, true, false),
            SyntheticKey::Backspace,
            "empty_trash",
        ),
        (
            BlockedChordPlatform::MacOs,
            mods(true, false, true, true, false),
            SyntheticKey::Escape,
            "force_quit",
        ),
        (
            BlockedChordPlatform::Windows,
            mods(false, false, false, false, true),
            SyntheticKey::L,
            "lock",
        ),
    ];
    for (platform, modifiers, key, reason) in expected {
        let found = blocked_chord(modifiers, key, platform);
        assert!(
            found.is_some_and(|b| b.reason == reason),
            "the floor no longer holds {platform:?} {modifiers:?}+{key:?} ({reason}); found {found:?}"
        );
    }
    assert_eq!(
        BLOCKED_CHORDS.len(),
        expected.len(),
        "the constant and this list disagree on how many chords the floor holds"
    );
}

#[tokio::test]
async fn session_floor_leaves_command_near_misses_grantable() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = granted_management().await;

    for keys in [&["command", "q"][..], &["command", "shift", "s"][..]] {
        let reply = serve(
            &plane,
            "computer.keys",
            keys_request(keys),
            &management,
            &clock,
        )
        .await;
        assert_eq!(
            reply["outcome"],
            "delivery_unconfirmed",
            "{} was blocked",
            keys.join("+")
        );
    }
}

/// Invalid synthetic requests preserve both the failed field and its one-word
/// reason when the production serving boundary enforces the frozen schema.
#[tokio::test]
async fn withholding_mode_preserves_keys_invalid_request_diagnostics() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> =
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold);
    let clock = FakeClock::new();
    let management = management();

    let reply = plane
        .serve(
            servable("computer.keys").expect("keys is servable"),
            &keys_request(&["a", "b"]),
            ServeContext {
                cancel: cerebellum::CancelHandle::for_uninterruptible_probe(),
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                consent: no_relay(),
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("a declared refusal reaches the caller in withholding mode");

    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["field"], "keys");
    assert_eq!(reply["reason"], "multiple_keys");
    assert!(
        plane.result_schema_findings().is_empty(),
        "withholding a declared refusal recorded a schema finding: {:?}",
        plane.result_schema_findings()
    );
}

/// Without the application's app grant, no keystroke reaches it. Asserted for
/// each keystroke row, and by the ABSENCE of a dispatched event and of a
/// journal entry: a handler that skipped the grant check would post.
#[tokio::test]
async fn a_keystroke_row_without_its_app_grant_posts_nothing() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management();

    let cases = [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["s"])),
    ];
    for (name, request) in cases {
        let before = plane.journal_entry_count().await;
        let reply = serve(&plane, name, request, &management, &clock).await;
        assert_eq!(
            reply["outcome"], "consent_unavailable",
            "{name} ran without its app grant: {reply}"
        );
        assert_eq!(
            plane.journal_entry_count().await,
            before,
            "{name} journaled an action it was not authorised for"
        );
    }
    assert!(
        dispatched_calls(&shared).is_empty(),
        "a refused action still posted events"
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );
}

/// A Command chord is admitted by the application's app grant like any other
/// key press: the grant covers everything done inside the application, and
/// the chord is still recorded as a durable action in the dispatch evidence.
#[tokio::test]
async fn a_command_chord_is_admitted_by_the_app_grant() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();

    let durable = granted_management().await;
    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["command", "s"]),
        &durable,
        &clock,
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed");
    let calls = dispatched_calls(&shared);
    let [DispatchedCall::PerPid(request)] = &calls[..] else {
        panic!("the durable chord did not dispatch: {calls:?}");
    };
    assert_eq!(
        request.action,
        SyntheticAction::key_combination(
            SyntheticKey::S,
            SyntheticKeyModifiers {
                command: true,
                ..SyntheticKeyModifiers::NONE
            },
        )
    );
}

/// A mid-sequence failure whose held state is unknown must reach the caller
/// as itself. A caller answered a generic failure would send its next action
/// into a target that may still have a key or button down.
#[tokio::test]
async fn an_unknown_held_state_reaches_the_caller_unflattened() {
    let shared = Shared::handle();
    shared.lock().unwrap().per_pid =
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: 2,
            refusal: ProcessEventRefusal::PostCallFailed(PostCallFailure::new(
                "framework call failed",
            )),
            held_state: HeldStateDisposition::Unknown,
        }));
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = granted_management().await;

    let reply = serve(&plane, "computer.type", type_request(), &management, &clock).await;

    assert_eq!(
        reply,
        json!({
            "outcome": "held_state_unknown",
            "posts_returned": 2,
            "containment_rung": "global_none",
            // Present even on a refusal: false here means nothing established
            // that the target was fronted, which is not the same claim as the
            // target being elsewhere. Declaring it required is what spares a
            // caller from telling an absent claim from a false one.
            "target_fronted": false,
            "effect_status": "effect_indeterminate",
        })
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );

    // The distinction is the held state, not the failure: a failure that
    // provably released everything is a dispatch failure and nothing more.
    shared.lock().unwrap().per_pid =
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: 1,
            refusal: ProcessEventRefusal::PostCallFailed(PostCallFailure::new(
                "framework call failed",
            )),
            held_state: HeldStateDisposition::Released { posts_returned: 1 },
        }));
    let reply = serve(&plane, "computer.type", type_request(), &management, &clock).await;
    assert_eq!(reply["outcome"], "dispatch_failed");
}

/// Intent is journaled before dispatch and finalised before the caller is
/// answered, so a failing dispatch still leaves a COMPLETED audit record --
/// never an open one that a crash would leave indeterminate. Asserted on the
/// obligation's lifecycle, because a count of entries cannot tell a finalised
/// record from one left open mid-flight.
#[tokio::test]
async fn a_failing_dispatch_still_finalises_its_audit_entry() {
    let shared = Shared::handle();
    shared.lock().unwrap().per_pid =
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: 1,
            refusal: ProcessEventRefusal::PostCallFailed(PostCallFailure::new(
                "framework call failed",
            )),
            held_state: HeldStateDisposition::Unknown,
        }));
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = granted_management().await;

    let before = plane.journal_entry_count().await;
    let reply = serve(&plane, "computer.type", type_request(), &management, &clock).await;
    assert_eq!(reply["outcome"], "held_state_unknown");
    let after = plane.journal_entry_count().await;
    assert!(
        after > before,
        "a dispatch that failed left no audit record at all"
    );

    for sequence in before..after {
        assert_eq!(
            plane.obligation_lifecycle(sequence).await,
            Some(LifecycleState::Finalized),
            "obligation {sequence} was left open when the caller was answered"
        );
    }
}

/// Typed text must not reach the durable journal.
///
/// `computer.type` carries whatever a caller sends, which on a login form is a
/// password. The journal is durable AND enrolled for fleet backup in
/// engram-catalog.json, so text landing there is text that gets backed up.
///
/// Today the actuation descriptor carries capability, containment and
/// observation and nothing else, so this holds by construction rather than by a
/// filter. That is exactly why it needs a fence: the property is invisible in
/// the code that provides it, and adding the action to the record "for
/// diagnostics" would read as an improvement.
///
/// The scan decodes base64 as well as reading the raw JSON, because journal byte
/// fields ARE base64 since the v2 encoding change. A plain substring search over
/// the serialized state would silently stop catching leaks the moment a secret
/// travelled inside a byte field -- passing for the wrong reason, which is worse
/// than failing.
#[tokio::test]
async fn typed_text_never_reaches_the_journal() {
    const SECRET: &str = "hunter2-Sw0rdf1sh-correct-horse";

    let shared = Shared::handle();
    let storage = InMemoryJournalStorage::new();
    let plane = ComputerPlane::with_synthetic_driver(
        support::computer::audit_with_storage(storage.clone()),
        SyntheticDriver::factory(Arc::clone(&shared)),
    )
    .with_app_state_source(focused_text_desk().source());
    let clock = FakeClock::new();
    let management = granted_management().await;

    let reply = serve(
        &plane,
        "computer.type",
        json!({"target": TARGET_BUNDLE_ID, "text": SECRET}),
        &management,
        &clock,
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert!(
        plane.journal_entry_count().await > 0,
        "the action must be journaled, or this test proves nothing"
    );

    // Prove the scanner can find a secret before trusting it to report none.
    // A base64 decoder that silently returns nothing would make every assertion
    // below pass for the wrong reason -- and it is the failure mode with no
    // symptom, since a leak and a broken detector look identical from here.
    let planted = format!("{{\"bytes\":\"{}\"}}", base64_of(SECRET.as_bytes()));
    assert!(
        base64_decoded_strings(&planted)
            .iter()
            .any(|text| text.contains(SECRET)),
        "the scanner cannot find a secret it was handed, so it cannot report their absence"
    );

    let state = storage.load().expect("journal state loads");
    let serialized = serde_json::to_string(&state).expect("journal state serializes");
    assert!(
        !serialized.contains(SECRET),
        "the typed text is in the journal verbatim"
    );

    // Every string in the record, decoded as base64 where it decodes. A byte
    // field holding the secret would not match the raw scan above.
    let decoded_hits = base64_decoded_strings(&serialized)
        .into_iter()
        .filter(|text| text.contains(SECRET))
        .count();
    assert_eq!(
        decoded_hits, 0,
        "the typed text is in the journal inside an encoded field"
    );
}

/// Decode every base64-looking token in the text, keeping what decodes to UTF-8.
fn base64_decoded_strings(text: &str) -> Vec<String> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = Vec::new();
    for token in
        text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='))
    {
        if token.len() < 8 {
            continue;
        }
        let mut buffer = Vec::new();
        let mut accumulator = 0u32;
        let mut bits = 0u32;
        let mut usable = true;
        for byte in token.bytes().take_while(|b| *b != b'=') {
            let Some(index) = ALPHABET.iter().position(|c| *c == byte) else {
                usable = false;
                break;
            };
            accumulator = (accumulator << 6) | index as u32;
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                buffer.push((accumulator >> bits) as u8);
            }
        }
        if usable {
            if let Ok(text) = String::from_utf8(buffer) {
                out.push(text);
            }
        }
    }
    out
}

/// Encode bytes as base64, for planting a known positive in the scan self-check.
fn base64_of(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let triple = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[((triple >> (18 - i * 6)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

#[tokio::test]
async fn a_single_thread_runtime_can_interrupt_a_posting_computer_action() {
    let shared = Shared::handle();
    let posted = Arc::new(tokio::sync::Notify::new());
    shared.lock().unwrap().interrupt_after_two = Some(posted.clone());
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = granted_management().await;
    let cancel = cerebellum::CancelHandle::pending();
    let arguments = json!({"target": TARGET_BUNDLE_ID, "text":"abcde"});
    let serving = plane.serve(
        servable("computer.type").unwrap(),
        &arguments,
        ServeContext {
            cancel: cancel.clone(),
            grantee: GRANTEE,
            identity: identity(),
            management: &management,
            consent: no_relay(),
            clock: &clock,
            now_ms: 10,
        },
        |_| InMemoryCaptureBackend::default(),
    );
    let interrupt = async {
        tokio::time::timeout(std::time::Duration::from_secs(5), posted.notified())
            .await
            .expect("the cancel never reached the loop: the action did not signal its second post; check fixture admission and synchronous dispatch scheduling");
        cancel.cancel();
    };
    let (reply, ()) = tokio::join!(serving, interrupt);
    let reply = reply.unwrap();
    assert_eq!(reply["outcome"], "cancelled");
    assert_eq!(reply["posts_returned"], 2);
    assert_eq!(
        plane.obligation_lifecycle(1).await,
        Some(LifecycleState::Finalized)
    );
}

// ---------------------------------------------------------------------------
// The secure-field check, background targets and honest delivery
// ---------------------------------------------------------------------------

use support::computer::{relayed, Desk, DeskFocus, ScriptedCarrier};

/// A plane over `desk` that withholds any reply its row does not declare, in
/// a build that does or does not carry the fronting bracket's review.
fn plane_on(shared: &Arc<Mutex<Shared>>, desk: &Desk, bracket_admitted: bool) -> TestPlane {
    ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit(),
        ResultSchemaEnforcement::Withhold,
        SyntheticDriver::factory(Arc::clone(shared)),
    )
    .with_app_state_source(desk.source())
    .with_fronting_bracket_admitted(bracket_admitted)
}

async fn serve_asking(
    plane: &TestPlane,
    name: &str,
    arguments: Value,
    management: &Arc<ManagementPlane>,
    consent: cerebellum::computer_grants::ConsentContext,
) -> Value {
    let clock = FakeClock::new();
    plane
        .serve(
            servable(name).expect("the capability is servable"),
            &arguments,
            ServeContext {
                cancel: cerebellum::CancelHandle::pending(),
                grantee: GRANTEE,
                identity: identity(),
                management,
                consent,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
}

fn background(desk: Desk) -> Desk {
    desk.state().frontmost = Some(OTHER_APPLICATION_PID);
    desk
}

/// A secure field focused in the target refuses both keystroke rows before
/// anything is posted or fronted.
#[tokio::test]
async fn a_secure_focused_field_refuses_keystrokes_before_anything_is_posted() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    desk.state().elements.get_mut(&2).unwrap().facts.subrole = Some("AXSecureTextField".into());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    for (name, request) in [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["a"])),
    ] {
        let reply = serve(&plane, name, request, &management, &FakeClock::new()).await;
        assert_eq!(reply["outcome"], "secure_field_refused", "{name}: {reply}");
        assert_eq!(reply["reason"], "secure_field_focused");
    }
    assert!(dispatched_calls(&shared).is_empty());
    assert!(plane.result_schema_findings().is_empty());
}

/// A focus that cannot be read cannot be shown not to be secure, so the
/// check fails closed.
#[tokio::test]
async fn an_unreadable_focus_refuses_keystrokes() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    desk.state().focus = DeskFocus::Unreadable;
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    for (name, request) in [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["a"])),
    ] {
        let reply = serve(&plane, name, request, &management, &FakeClock::new()).await;
        assert_eq!(reply["outcome"], "secure_field_refused", "{name}: {reply}");
        assert_eq!(reply["reason"], "focus_unreadable");
    }
    assert!(dispatched_calls(&shared).is_empty());
}

/// An application that reports no focused element, but whose field carries
/// its own focused flag (a backgrounded Electron app), still has that field
/// checked for a secure one before anything is posted.
#[tokio::test]
async fn a_secure_field_flagged_focused_refuses_when_the_app_reports_no_focus() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    {
        let mut state = desk.state();
        state.focus = DeskFocus::Nothing;
        state.roots[0].children[0].focused = true;
        state.elements.get_mut(&2).unwrap().facts.subrole = Some("AXSecureTextField".into());
    }
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    for (name, request) in [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["a"])),
    ] {
        let reply = serve(&plane, name, request, &management, &FakeClock::new()).await;
        assert_eq!(reply["outcome"], "secure_field_refused", "{name}: {reply}");
        assert_eq!(reply["reason"], "secure_field_focused");
    }
    assert!(dispatched_calls(&shared).is_empty());
}

/// Typing into a field the application marks focused only on the field
/// itself is confirmed by reading that field back.
#[tokio::test]
async fn typing_into_a_field_flagged_focused_is_confirmed_when_the_app_reports_no_focus() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    {
        let mut state = desk.state();
        state.focus = DeskFocus::Nothing;
        state.roots[0].children[0].focused = true;
        state.elements.get_mut(&2).unwrap().readbacks =
            [Some("ab".to_string()), Some("ahib".to_string())].into();
    }
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_observed");
}

/// Plain typing needs no takeover, even in a build without a fronting bracket.
#[tokio::test]
async fn background_plain_and_shift_typing_use_per_process_without_takeover() {
    let shared = Shared::handle();
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let carrier = ScriptedCarrier::default();
    for (name, request) in [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["a"])),
        ("computer.keys", keys_request(&["shift", "a"])),
    ] {
        let reply = serve_asking(&plane, name, request, &management, relayed(&carrier)).await;
        assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    }
    assert!(carrier.questions().is_empty());
    let calls = dispatched_calls(&shared);
    assert_eq!(calls.len(), 3);
    assert!(calls
        .iter()
        .all(|call| matches!(call, DispatchedCall::PerPid(_))));
}

#[tokio::test]
async fn background_modifier_chords_refuse_without_takeover_and_post_nothing() {
    let shared = Shared::handle();
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    let carrier = ScriptedCarrier::default();
    for modifier in ["command", "control", "option"] {
        let reply = serve_asking(
            &plane,
            "computer.keys",
            keys_request(&[modifier, "a"]),
            &management,
            relayed(&carrier),
        )
        .await;
        assert!(
            dispatched_calls(&shared).is_empty(),
            "a background shortcut was posted"
        );
        assert_eq!(
            reply["outcome"], "modifier_chord_needs_foreground",
            "{reply}"
        );
    }
    assert!(
        carrier.questions().is_empty(),
        "refusal must not silently request takeover"
    );
}

async fn grant_takeover(management: &Arc<ManagementPlane>) {
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    management
        .computer_grants()
        .require(
            &cerebellum::computer_grants::GrantNeed::Takeover,
            &relayed(&carrier),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .unwrap();
}

/// A held takeover permits a background shortcut to front and restore.
#[tokio::test]
async fn a_background_target_with_the_takeover_grant_is_posted_through_the_bracket() {
    let shared = Shared::handle();
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    grant_takeover(&management).await;
    let carrier = ScriptedCarrier::default();
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["command", "a"]),
        &management,
        relayed(&carrier),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["target_fronted"], true, "{reply}");
    assert!(matches!(
        &dispatched_calls(&shared)[..],
        [DispatchedCall::Fronted(_)]
    ));
    assert!(carrier.questions().is_empty());
}

/// A frontmost target is posted to per process, and no takeover question is
/// raised even in a build that could ask one.
#[tokio::test]
async fn a_frontmost_target_is_posted_per_process_without_a_takeover_question() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    let carrier = ScriptedCarrier::default();
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["a"]),
        &management,
        relayed(&carrier),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert!(carrier.questions().is_empty());
    assert!(matches!(
        &dispatched_calls(&shared)[..],
        [DispatchedCall::PerPid(_)]
    ));
}

/// A chord that was posted, where only putting the previous application
/// back ran past the bound, is reported as delivered with the overrun named.
/// Reporting it as a refusal would tell the caller keystrokes that landed
/// did not, and a retry would send them twice.
#[tokio::test]
async fn a_chord_whose_restore_overran_the_bound_is_reported_delivered_not_refused() {
    let shared = Shared::handle();
    // Front and restore each take 49 ms: the chord fits the prediction, and
    // the whole interval (49 + 3 + 49) runs past the 100 ms bound.
    shared.lock().unwrap().fronted.front_latency_ms = Some(49);
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    grant_takeover(&management).await;
    let carrier = ScriptedCarrier::default();
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["command", "a"]),
        &management,
        relayed(&carrier),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["target_fronted"], false, "{reply}");
    assert_eq!(
        reply["containment_forfeited_because"], "fronting_bound_exceeded",
        "{reply}"
    );
}

/// A previous application that cannot be put back is reported by name,
/// whatever else happened: the person's next keystrokes go to what was left
/// in front.
#[tokio::test]
async fn a_failed_restore_is_reported_naming_the_application_left_in_front() {
    let shared = Shared::handle();
    shared.lock().unwrap().fronted.refuse_restore = true;
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    grant_takeover(&management).await;
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["command", "a"]),
        &management,
        relayed(&carrier),
    )
    .await;
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(reply["bundle_identity"], TARGET_BUNDLE_ID);
    assert_eq!(reply["target_fronted"], false);
    assert!(reply["remedy"].as_str().unwrap().contains(TARGET_BUNDLE_ID));
}

/// Plain text never enters the bracket, even with its cancel fixture armed.
#[tokio::test]
async fn plain_background_text_never_enters_the_fronting_bracket() {
    let shared = Shared::handle();
    shared.lock().unwrap().fronted.cancel_after_first_chunk = true;
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    let reply = serve_asking(
        &plane,
        "computer.type",
        json!({"target": TARGET_BUNDLE_ID, "text": "a".repeat(60)}),
        &management,
        relayed(&carrier),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert!(matches!(
        &dispatched_calls(&shared)[..],
        [DispatchedCall::PerPid(_)]
    ));
}

/// Typed text that shows up in the part of the focused value that changed
/// is confirmed.
#[tokio::test]
async fn typed_text_found_in_what_changed_is_completed() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    desk.state().elements.get_mut(&2).unwrap().readbacks =
        [Some("ab".to_string()), Some("ahib".to_string())].into();
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_observed");
}

/// Text the application shows only a few reads after the posts return is
/// still confirmed: the check is polled up to the row's effect deadline, not
/// taken once. A backgrounded Discord showed typed text over a second late.
#[tokio::test]
async fn typed_text_that_lands_a_few_reads_late_is_completed() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    desk.state().elements.get_mut(&2).unwrap().readbacks = [
        Some("ab".to_string()),
        Some("ab".to_string()),
        Some("ab".to_string()),
        Some("ahib".to_string()),
    ]
    .into();
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_observed");
}

/// A field that already held the text, and did not change, proves nothing
/// about this call.
#[tokio::test]
async fn a_field_that_already_held_the_text_is_not_confirmed() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    desk.state().elements.get_mut(&2).unwrap().value = Some("hi".into());
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_indeterminate");
}

/// A chord is never reported delivered, even when the focused value changed.
#[tokio::test]
async fn keys_are_never_reported_delivered() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    desk.state().elements.get_mut(&2).unwrap().readbacks =
        [Some(String::new()), Some("a".to_string())].into();
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["a"]),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
}

#[tokio::test]
async fn route_summaries_reach_the_journal_not_the_wire_on_success_and_auth_failure() {
    use cerebellum_computer::platform::input_route::*;
    use cerebellum_computer::platform::process_event::*;
    for fail in [false, true] {
        let shared = Shared::handle();
        let evidence = InputRouteEvidence {
            routes: RouteCounts {
                skylight: 1,
                public: 1,
            },
            release_routes: RouteCounts {
                skylight: u64::from(fail),
                public: 0,
            },
            auth: AuthEvidence::Attached,
            fallback_reason: Some("skylight_symbol_missing".into()),
        };
        {
            let mut state = shared.lock().unwrap();
            state.route_evidence = evidence.clone();
            if fail {
                state.per_pid = Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
                    posts_returned: 2,
                    refusal: ProcessEventRefusal::PostCallFailed(PostCallFailure::new(
                        PRIVATE_INPUT_AUTH_FAILED,
                    )),
                    held_state: HeldStateDisposition::Released { posts_returned: 1 },
                }));
            }
        }
        let storage = InMemoryJournalStorage::new();
        let plane = ComputerPlane::with_synthetic_driver(
            support::computer::audit_with_storage(storage.clone()),
            SyntheticDriver::factory(Arc::clone(&shared)),
        )
        .with_app_state_source(focused_text_desk().source());
        let management = granted_management().await;
        let reply = serve(
            &plane,
            "computer.type",
            type_request(),
            &management,
            &FakeClock::new(),
        )
        .await;
        if fail {
            assert_eq!(reply["reason"], "private_input_auth_failed", "{reply}");
            assert_eq!(reply["outcome"], "private_input_auth_failed", "{reply}");
        }
        for name in ["routes", "release_routes", "auth", "fallback_reason"] {
            assert!(
                reply.get(name).is_none(),
                "audit material leaked onto the wire: {reply}"
            );
        }
        let saved = serde_json::to_string(&storage.load().unwrap()).unwrap();
        let entry = base64_decoded_strings(&saved)
            .into_iter()
            .filter_map(|text| serde_json::from_str::<Value>(&text).ok())
            .find(|entry| entry.get("completed_result").is_some())
            .expect("finalized journal entry");
        let bytes: Vec<u8> = serde_json::from_value(entry["completed_result"].clone()).unwrap();
        let outcome: cerebellum_computer::audit::RecordedActuationOutcome =
            serde_json::from_slice(&bytes).unwrap();
        assert_eq!(outcome.routes, evidence);
    }
}

// ---------------------------------------------------------------------------
// not_dispatched: a keystroke refusal that made no post call says so
// ---------------------------------------------------------------------------

/// The sentence a refusal that posted nothing adds to its remedy.
const RETRY_IS_SAFE: &str = "No keystroke was posted, so this call can be retried safely.";

/// Assert that `reply` says it made no post call, in the words a caller
/// reads: the effect status, a zero count, and a remedy saying retry is safe.
fn assert_not_dispatched(reply: &Value) {
    assert_eq!(reply["effect_status"], "not_dispatched", "{reply}");
    assert_eq!(reply["posts_returned"], 0, "{reply}");
    assert!(
        reply["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains(RETRY_IS_SAFE)),
        "{reply}"
    );
}

/// A target that comes forward too slowly for even one keystroke to fit the
/// fronting bound posts nothing, and says so: retrying it is safe, and a
/// caller told "indeterminate" would stop instead.
#[tokio::test]
async fn a_bracket_whose_front_is_slower_than_the_bound_reports_not_dispatched() {
    let shared = Shared::handle();
    // Coming forward takes 60 ms, and the restore is predicted to take as
    // long, so no unit fits inside the 100 ms bound.
    shared.lock().unwrap().fronted.front_latency_ms = Some(60);
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let management = granted_management().await;
    grant_takeover(&management).await;
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["command", "a"]),
        &management,
        relayed(&ScriptedCarrier::default()),
    )
    .await;
    assert_eq!(reply["outcome"], "fronting_bound_exceeded", "{reply}");
    assert_not_dispatched(&reply);
    assert!(matches!(
        &dispatched_calls(&shared)[..],
        [DispatchedCall::Fronted(_)]
    ));
    assert!(plane.result_schema_findings().is_empty());
}

/// Refusals decided before anything is dispatched report not_dispatched and
/// keep their own reason.
#[tokio::test]
async fn refusals_made_before_dispatch_report_not_dispatched() {
    let shared = Shared::handle();
    let secure = focused_text_desk();
    secure.state().elements.get_mut(&2).unwrap().facts.subrole = Some("AXSecureTextField".into());
    let plane = plane_on(&shared, &secure, true);
    let management = granted_management().await;
    for (name, request) in [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["a"])),
    ] {
        let reply = serve(&plane, name, request, &management, &FakeClock::new()).await;
        assert_eq!(reply["outcome"], "secure_field_refused", "{name}: {reply}");
        assert_eq!(reply["reason"], "secure_field_focused");
        assert_not_dispatched(&reply);
    }

    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["command", "a"]),
        &management,
        relayed(&ScriptedCarrier::default()),
    )
    .await;
    assert_eq!(
        reply["outcome"], "modifier_chord_needs_foreground",
        "{reply}"
    );
    assert_eq!(reply["reason"], "modifier_chord_needs_foreground");
    assert_not_dispatched(&reply);

    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["a", "b"]),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "invalid_request", "{reply}");
    assert_not_dispatched(&reply);

    assert!(dispatched_calls(&shared).is_empty());
    assert!(plane.result_schema_findings().is_empty());
}

/// A sequence stopped by a routing check before its first post call made no
/// call, and reports not_dispatched.
#[tokio::test]
async fn a_sequence_stopped_before_its_first_post_call_reports_not_dispatched() {
    let shared = Shared::handle();
    shared.lock().unwrap().per_pid =
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: 0,
            refusal: ProcessEventRefusal::ProcessGone,
            held_state: HeldStateDisposition::NoneHeld,
        }));
    let desk = focused_text_desk();
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
    assert_not_dispatched(&reply);
    assert!(plane.result_schema_findings().is_empty());
}

/// A first post call that FAILED still made a call, and a failed call is
/// uncertain: the event may have gone out. Its posts_returned is 0 because
/// it counts calls that returned, so reading 0 as "never posted" would tell
/// a caller to retry keys that may have landed.
#[tokio::test]
async fn a_first_post_call_that_failed_stays_indeterminate_at_zero_posts() {
    let shared = Shared::handle();
    shared.lock().unwrap().per_pid =
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: 0,
            refusal: ProcessEventRefusal::PostCallFailed(PostCallFailure::new(
                "framework call failed",
            )),
            held_state: HeldStateDisposition::NoneHeld,
        }));
    let desk = focused_text_desk();
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_indeterminate", "{reply}");
    assert_eq!(reply["posts_returned"], 0, "{reply}");
    assert!(plane.result_schema_findings().is_empty());
}

/// A stop after posting stays effect_indeterminate and carries its count,
/// through a per-process sequence and through the fronting bracket. This is
/// what fails if every refusal were called not_dispatched.
#[tokio::test]
async fn a_stop_after_posting_stays_indeterminate_with_its_count() {
    let management = granted_management().await;

    let shared = Shared::handle();
    shared.lock().unwrap().per_pid =
        Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
            posts_returned: 2,
            refusal: ProcessEventRefusal::ProcessGone,
            held_state: HeldStateDisposition::NoneHeld,
        }));
    let desk = focused_text_desk();
    let plane = plane_on(&shared, &desk, false);
    let reply = serve(
        &plane,
        "computer.type",
        type_request(),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_indeterminate", "{reply}");
    assert_eq!(reply["posts_returned"], 2, "{reply}");
    assert!(!reply["remedy"]
        .as_str()
        .is_some_and(|remedy| remedy.contains(RETRY_IS_SAFE)));
    assert!(plane.result_schema_findings().is_empty());

    // Through the bracket: the unit's key press was posted, then the process
    // went away before the rest of the unit.
    let shared = Shared::handle();
    shared.lock().unwrap().fronted.unit_failure = Some(SequencePostFailure {
        posts_returned: 1,
        refusal: ProcessEventRefusal::ProcessGone,
        held_state: HeldStateDisposition::NoneHeld,
    });
    grant_takeover(&management).await;
    let desk = background(focused_text_desk());
    let plane = plane_on(&shared, &desk, true);
    let reply = serve_asking(
        &plane,
        "computer.keys",
        keys_request(&["command", "a"]),
        &management,
        relayed(&ScriptedCarrier::default()),
    )
    .await;
    assert_eq!(reply["outcome"], "dispatch_failed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_indeterminate", "{reply}");
    assert_eq!(reply["posts_returned"], 1, "{reply}");
    assert!(plane.result_schema_findings().is_empty());
}

/// A dispatch that posted everything is reported as before: unconfirmed
/// delivery with an indeterminate effect, and no count or retry claim.
#[tokio::test]
async fn a_successful_keystroke_reply_is_unchanged() {
    let shared = Shared::handle();
    let desk = focused_text_desk();
    let plane = plane_on(&shared, &desk, false);
    let management = granted_management().await;
    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["a"]),
        &management,
        &FakeClock::new(),
    )
    .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["effect_status"], "effect_indeterminate", "{reply}");
    assert!(reply.get("posts_returned").is_none(), "{reply}");
    assert!(reply.get("remedy").is_none(), "{reply}");
    assert!(plane.result_schema_findings().is_empty());
}
