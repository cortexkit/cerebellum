//! Serving the five synthetic input capabilities over the wire.
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
    current_blocked_chord_platform, AccessibilityTreeRequest, AccessibilityTreeResult,
    AttendancePreconditionRequest, AttendancePreconditionResult, CapabilityAdvertisementContext,
    CapabilityDeclaration, DispatchResult, DriverError, EffectObservationRequest,
    EffectObservationResult, EffectStatus, ElementResolutionRequest, ElementResolutionResult,
    FocusQueryRequest, FocusQueryResult, FrontingSnapshot, HeldStateDisposition,
    InputObservationRequest, InputObservationResult, InputObserverLiveness, PlatformDriver,
    PostCallFailure, ProcessEventRefusal, ProcessGrant, SemanticDispatchRequest,
    SequencePostFailure, SyntheticAction, SyntheticDispatchRequest, SyntheticKey,
    SyntheticKeyModifiers, SyntheticPoint, SyntheticScrollUnit, BLOCKED_CHORDS,
};
use cerebellum_core::clock::FakeClock;
use cerebellum_core::consent::ActionKind;
use cerebellum_core::journal::{
    InMemoryJournalStorage, JournalStorage, LifecycleState, ValidatedSeverityTaxonomy,
};
use serde_json::{json, Value};
use support::computer::{audit, grant, grant_lease, identity, management, TestRedactor, GRANTEE};

/// One synthetic dispatch the platform driver was asked to perform.
#[derive(Debug, Clone, PartialEq)]
enum DispatchedCall {
    PerPid(SyntheticDispatchRequest),
    Global(SyntheticDispatchRequest),
}

/// What every driver instance built for one test shares: the calls made, and
/// the answers to give. A test flips the answers between serves to exercise
/// failure paths through the same plane.
#[derive(Debug)]
struct Shared {
    calls: Vec<DispatchedCall>,
    per_pid: Result<DispatchResult, DriverError>,
    global: Result<DispatchResult, DriverError>,
}

impl Shared {
    fn handle() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            calls: Vec::new(),
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
    ) -> Result<DispatchResult, DriverError> {
        let mut shared = self.0.lock().unwrap();
        shared.calls.push(DispatchedCall::PerPid(request));
        shared.per_pid.clone()
    }

    fn dispatch_global(
        &mut self,
        request: cerebellum_computer::platform::GlobalDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        let mut shared = self.0.lock().unwrap();
        shared.calls.push(DispatchedCall::Global(request.synthetic));
        shared.global.clone()
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

type TestPlane = ComputerPlane<
    InMemoryCaptureBackend,
    TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    SyntheticDriver,
>;

fn plane_with(shared: &Arc<Mutex<Shared>>) -> TestPlane {
    ComputerPlane::with_synthetic_driver(audit(), SyntheticDriver::factory(Arc::clone(shared)))
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
                grantee: GRANTEE,
                identity: identity(),
                management,
                clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("detect-only validation preserves the reply")
}

async fn management_leased(kind: ActionKind, clock: &FakeClock) -> Arc<ManagementPlane> {
    let management = management();
    grant_lease(&management, kind, clock).await;
    management
}

async fn management_once(clock: &FakeClock) -> Arc<ManagementPlane> {
    let management = management();
    let (reply, _) = management
        .open_target(
            GRANTEE,
            support::computer::TARGET_BUNDLE_ID,
            ActionKind::MutateDurable,
            true,
            clock,
        )
        .await;
    let ask_id = reply["ask_id"].as_str().expect("an ask is minted");
    assert!(
        management
            .settle(ask_id, Some(&json!({"decision": "allow_once"})), clock,)
            .await,
        "the fixture Once lease settles"
    );
    management
}

fn type_request() -> Value {
    json!({"target": "editor", "text": "hi", "replace_selection": false})
}

fn keys_request(keys: &[&str]) -> Value {
    json!({"keys": keys, "target": "editor"})
}

fn scroll_request() -> Value {
    json!({"target": "editor", "axis": "vertical", "amount_lines": -3})
}

fn move_request() -> Value {
    json!({"to": "812,460"})
}

fn drag_request() -> Value {
    json!({"from": "1,2", "to": "3.5,4", "button": "left", "modifiers": []})
}

/// Typing reaches the target's leased process generation and reports structural
/// containment even when the target process is not frontmost.
#[tokio::test]
async fn computer_type_reports_pid_structural_for_an_unfocused_target() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management_leased(ActionKind::Compose, &clock).await;
    let before = plane.journal_entry_count().await;

    let reply = serve(&plane, "computer.type", type_request(), &management, &clock).await;

    assert_eq!(
        reply,
        json!({
            "outcome": "completed",
            "containment_rung": "pid_structural",
            "target_fronted": false,
            "effect_status": "effect_indeterminate",
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
    let management = management_leased(ActionKind::Compose, &clock).await;

    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["shift", "a"]),
        &management,
        &clock,
    )
    .await;

    assert_eq!(reply["outcome"], "completed");
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

/// Scrolling reaches the leased process as the wheel delta requested.
#[tokio::test]
async fn computer_scroll_dispatches_its_wheel_event_through_observed_global_input() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management_once(&clock).await;

    let reply = serve(
        &plane,
        "computer.scroll",
        scroll_request(),
        &management,
        &clock,
    )
    .await;

    assert_eq!(reply["outcome"], "completed");
    let calls = dispatched_calls(&shared);
    let [DispatchedCall::Global(request)] = &calls[..] else {
        panic!("scroll must deliver through observed global dispatch exactly once: {calls:?}");
    };
    assert_eq!(request.target, grant());
    assert_eq!(
        request.action,
        SyntheticAction::scroll(SyntheticScrollUnit::Line, -3)
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );
}

/// computer.move is frozen observed-only: it goes through the global path,
/// never the per-process one, and its reply carries no containment rung.
#[tokio::test]
async fn computer_move_dispatches_through_the_global_path_while_observed() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management_once(&clock).await;

    let reply = serve(&plane, "computer.move", move_request(), &management, &clock).await;

    assert_eq!(
        reply,
        json!({
            "outcome": "completed",
            "containment_forfeited_because": "coordinate_addressed",
            "target_fronted": false,
            "effect_status": "effect_indeterminate",
        }),
        "the move row declares no containment rung, so the reply still says WHY \
         -- a caller reading an absent rung cannot otherwise tell a \
         coordinate-addressed row from a failed one"
    );
    let calls = dispatched_calls(&shared);
    let [DispatchedCall::Global(request)] = &calls[..] else {
        panic!("move must deliver through the global path exactly once: {calls:?}");
    };
    assert_eq!(request.target, grant());
    assert_eq!(
        request.action,
        SyntheticAction::move_pointer(SyntheticPoint { x: 812.0, y: 460.0 })
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );
}

/// An Until lease cannot authorize global dispatch. A Once lease admits one
/// move and is gone before a second move asks, proving the wire consumes it.
#[tokio::test]
async fn computer_move_requires_and_consumes_a_once_mutate_durable_lease() {
    let clock = FakeClock::new();

    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let until = management_leased(ActionKind::MutateDurable, &clock).await;
    let refused = serve(&plane, "computer.move", move_request(), &until, &clock).await;
    assert_eq!(refused["outcome"], "once_grant_required");
    assert!(
        dispatched_calls(&shared).is_empty(),
        "an Until lease reached global dispatch"
    );

    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let once = management_once(&clock).await;
    let first = serve(&plane, "computer.move", move_request(), &once, &clock).await;
    assert_eq!(first["outcome"], "completed");
    assert_eq!(dispatched_calls(&shared).len(), 1);

    let second = serve(&plane, "computer.move", move_request(), &once, &clock).await;
    assert_eq!(second["outcome"], "once_grant_required");
    assert_eq!(
        dispatched_calls(&shared).len(),
        1,
        "the consumed Once lease admitted a second global post"
    );
}

/// A once-grant refusal keeps its repair instruction when the production serving
/// boundary enforces the frozen result schema instead of merely detecting it.
#[tokio::test]
async fn withholding_mode_preserves_move_once_grant_remedy() {
    let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> =
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::Withhold);
    let clock = FakeClock::new();
    let management = management_leased(ActionKind::MutateDurable, &clock).await;

    let reply = plane
        .serve(
            servable("computer.move").expect("move is servable"),
            &move_request(),
            ServeContext {
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
                clock: &clock,
                now_ms: 10,
            },
            |_| InMemoryCaptureBackend::default(),
        )
        .await
        .expect("a declared refusal reaches the caller in withholding mode");

    assert_eq!(reply["outcome"], "once_grant_required");
    assert_eq!(
        reply["remedy"],
        "call computer.open_target for action_kind 'mutate_durable', choose the 'once' grant kind, then retry"
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "withholding a declared refusal recorded a schema finding: {:?}",
        plane.result_schema_findings()
    );
}

/// Every session-ending chord remains refused even with the widest lease this
/// fixture can mint; the floor runs before authority and records the attempt.
#[tokio::test]
async fn every_listed_session_ending_chord_is_refused_above_a_full_lease() {
    let platform = current_blocked_chord_platform().expect("this test runs on a synthetic host");
    let clock = FakeClock::new();
    let management = management_leased(ActionKind::MutateDurable, &clock).await;
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
#[tokio::test]
async fn session_floor_leaves_command_near_misses_grantable() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management_leased(ActionKind::MutateDurable, &clock).await;

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
            "completed",
            "{} was blocked",
            keys.join("+")
        );
    }
}

/// Semantic click titles lack the key-chord information this floor uses; a
/// locale- and role-aware session-action policy would be needed to cover them.
#[cfg(target_os = "macos")]
#[tokio::test]
async fn semantic_click_log_out_title_is_not_refused_by_the_chord_floor() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management();
    let reply = serve(
        &plane,
        "computer.click",
        json!({
            "target": {"by": "role_and_title", "role": "AXMenuItem", "title": "Log Out…"},
            "button": "left",
            "click_count": 1,
            "modifiers": [],
        }),
        &management,
        &clock,
    )
    .await;

    assert_ne!(reply["outcome"], "chord_blocked");
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
                grantee: GRANTEE,
                identity: identity(),
                management: &management,
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

/// Dragging is mutate_durable outright and globally delivers its three events
/// while observed: press, move, release at the requested points.
#[tokio::test]
async fn computer_drag_dispatches_its_drag_events_through_observed_global_input() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management_once(&clock).await;

    let reply = serve(&plane, "computer.drag", drag_request(), &management, &clock).await;

    assert_eq!(
        reply,
        json!({
            "outcome": "completed",
            "containment_forfeited_because": "coordinate_addressed",
            "target_fronted": false,
            "effect_status": "effect_indeterminate",
        }),
        "the drag row declares no containment rung, so the reply still says WHY \
         -- a caller reading an absent rung cannot otherwise tell a \
         coordinate-addressed row from a failed one"
    );
    let calls = dispatched_calls(&shared);
    let [DispatchedCall::Global(request)] = &calls[..] else {
        panic!("drag must deliver through observed global dispatch exactly once: {calls:?}");
    };
    assert_eq!(request.target, grant());
    assert_eq!(
        request.action,
        SyntheticAction::drag_pointer(
            SyntheticPoint { x: 1.0, y: 2.0 },
            SyntheticPoint { x: 3.5, y: 4.0 },
        )
    );
    assert!(
        plane.result_schema_findings().is_empty(),
        "{:?}",
        plane.result_schema_findings()
    );
}

/// A lease that authorised observing an application authorises no input into
/// it. Asserted for each of the five, and by the ABSENCE of a dispatched
/// event and of a journal entry: a handler that asked the wrong action kind
/// would pass the lease check and post.
#[tokio::test]
async fn an_observe_only_lease_is_refused_for_each_of_the_five() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();
    let management = management_leased(ActionKind::Observe, &clock).await;

    let cases = [
        ("computer.type", type_request()),
        ("computer.keys", keys_request(&["s"])),
        ("computer.scroll", scroll_request()),
        ("computer.move", move_request()),
        ("computer.drag", drag_request()),
    ];
    for (name, request) in cases {
        let before = plane.journal_entry_count().await;
        let reply = serve(&plane, name, request, &management, &clock).await;
        let expected = if matches!(name, "computer.scroll" | "computer.move" | "computer.drag") {
            "once_grant_required"
        } else {
            "no_lease"
        };
        assert_eq!(
            reply["outcome"], expected,
            "{name} ran under an observe-only lease"
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

/// The vocabulary's durable_chord override: a Command chord escalates to
/// mutate_durable, so a compose lease does not cover it and a durable one
/// does. If every chord were treated as compose, the first half of this test
/// would dispatch under the compose lease and fail by name.
#[tokio::test]
async fn a_command_chord_demands_a_mutate_durable_lease() {
    let shared = Shared::handle();
    let plane = plane_with(&shared);
    let clock = FakeClock::new();

    let compose_only = management_leased(ActionKind::Compose, &clock).await;
    let before = plane.journal_entry_count().await;
    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["command", "s"]),
        &compose_only,
        &clock,
    )
    .await;
    assert_eq!(
        reply["outcome"], "no_lease",
        "a durable chord ran under a compose-only lease"
    );
    assert_eq!(plane.journal_entry_count().await, before);
    assert!(dispatched_calls(&shared).is_empty());

    let durable = management_leased(ActionKind::MutateDurable, &clock).await;
    let reply = serve(
        &plane,
        "computer.keys",
        keys_request(&["command", "s"]),
        &durable,
        &clock,
    )
    .await;
    assert_eq!(reply["outcome"], "completed");
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
    let management = management_leased(ActionKind::Compose, &clock).await;

    let reply = serve(&plane, "computer.type", type_request(), &management, &clock).await;

    assert_eq!(
        reply,
        json!({
            "outcome": "held_state_unknown",
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
    let management = management_leased(ActionKind::Compose, &clock).await;

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
    );
    let clock = FakeClock::new();
    let management = management_leased(ActionKind::Compose, &clock).await;

    let reply = serve(
        &plane,
        "computer.type",
        json!({"target": "field", "text": SECRET, "replace_selection": false}),
        &management,
        &clock,
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
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
