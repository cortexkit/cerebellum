use cerebellum_computer::audit::ComputerAudit;
use cerebellum_computer::capture_custody::{
    CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
};
use cerebellum_computer::dispatch::post_condition::PostCondition;
use cerebellum_computer::dispatch::{
    authorize_escalation, retry_decision, AbortDecision, AbortReason, AttemptDisposition,
    AttendanceContext, AttendanceLease, BracketReport, ConsentDecision, DispatchError,
    DispatchPhase, DispatchRequest, Dispatcher, ExpectedPostCondition, FocusCheckPlan,
    FrozenDispatchRow, ReconciliationResult, RestoreStatus, RetryDecision, SeizeWatcher,
    SourcedInputKind,
};
use cerebellum_computer::platform::containment::IdentityAtomicBinding;
use cerebellum_computer::platform::*;
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::storage::JournalStorage;
use cerebellum_core::journal::{
    DurableState, EffectClass, InMemoryJournalStorage, IsolationClass, JournalConfig,
    JournalIdentity, LifecycleState, ObservabilityClass, RecoveryClassification, Redactor,
    SeverityInputs, SeverityRecord, StorageError, ValidatedSeverityTaxonomy,
};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

struct TestRedactor;

impl Redactor for TestRedactor {
    fn available(&self) -> bool {
        true
    }

    fn redact(
        &self,
        input: &str,
        _max_bytes: usize,
    ) -> Result<String, cerebellum_core::journal::RedactionUnavailable> {
        Ok(input.to_string())
    }
}

fn taxonomy() -> ValidatedSeverityTaxonomy {
    ValidatedSeverityTaxonomy::new(
        "dispatch-test-v1",
        [
            EffectClass::Read,
            EffectClass::Mutate,
            EffectClass::Authorize,
        ]
        .into_iter()
        .flat_map(|effect| {
            [
                IsolationClass::ResourceScoped,
                IsolationClass::OwnerScoped,
                IsolationClass::Uncontained,
            ]
            .into_iter()
            .flat_map(move |isolation| {
                [
                    ObservabilityClass::HumanObserved,
                    ObservabilityClass::HumanUnobserved,
                ]
                .into_iter()
                .map(move |observation| {
                    (
                        SeverityInputs {
                            effect_class: effect,
                            isolation_class: isolation,
                            observability_class: observation,
                        },
                        SeverityRecord {
                            tier: 2,
                            credential: false,
                            financial: false,
                        },
                    )
                })
            })
        }),
    )
    .unwrap()
}

fn audit_identity() -> JournalIdentity {
    JournalIdentity {
        witness: cerebellum_core::dispatch_witness::DispatchWitness::armed(),
        principal: "prefrontal".into(),
        conversation_key: "conversation-1".into(),
        agent_project_id: "project-1".into(),
        session_kind: SessionKind::Primary,
        origin: Default::default(),
        computer_order: None,
    }
}

fn audit_with_storage<S: JournalStorage>(
    storage: S,
) -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, S> {
    let custody = CaptureCustody::new(
        CustodyBounds {
            maximum_verification_duration_ms: 100,
            maximum_pin_lifetime_ms: 50,
            maximum_concurrently_pinned_artifacts: 4,
            maximum_total_pinned_artifact_bytes: 10_000,
            maximum_custody_attachment_bytes: 2_000,
        },
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    )
    .unwrap();
    ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        storage,
        custody,
    )
    .unwrap()
}

fn audit() -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    audit_with_storage(InMemoryJournalStorage::new())
}

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 42,
        bundle_identity: "com.example.target".into(),
        process_generation_evidence: "generation-1".into(),
    }
}

fn fronting(at: u64) -> FrontingSnapshot {
    FrontingSnapshot {
        captured_at_ms: at,
        frontmost_application_identity: Some("com.example.other".into()),
        target_windows: vec![FrontingWindow {
            observation_window_id: "window-1".into(),
            owning_process_generation: "generation-1".into(),
            activation_state: "inactive".into(),
            z_order: 1,
        }],
        completeness: true,
    }
}

#[derive(Debug, Default)]
struct DispatchProbe {
    latest_state: Option<Value>,
    intent_was_durable_at_dispatch: bool,
}

#[derive(Clone, Debug)]
struct RecordingJournalStorage {
    inner: InMemoryJournalStorage,
    probe: Arc<Mutex<DispatchProbe>>,
}

impl RecordingJournalStorage {
    fn new(probe: Arc<Mutex<DispatchProbe>>) -> Self {
        Self {
            inner: InMemoryJournalStorage::new(),
            probe,
        }
    }
}

impl JournalStorage for RecordingJournalStorage {
    fn load(&self) -> Result<DurableState, StorageError> {
        self.inner.load()
    }

    fn save(&self, state: &DurableState) -> Result<(), StorageError> {
        self.inner.save(state)?;
        self.probe.lock().unwrap().latest_state = Some(serde_json::to_value(state).unwrap());
        Ok(())
    }

    fn raise_format(
        &self,
        format: cerebellum_core::format_floor::DurableFormat,
    ) -> Result<(), StorageError> {
        self.inner.raise_format(format)
    }
}

fn has_durable_intent(state: &Value) -> bool {
    state["reservations"]
        .as_object()
        .is_some_and(|reservations| {
            reservations
                .values()
                .any(|reservation| reservation["state"] == json!("dispatched"))
        })
}

fn decode_embedded_json(value: &Value) -> Value {
    let bytes = value
        .as_array()
        .expect("journal material is a byte array")
        .iter()
        .map(|byte| byte.as_u64().expect("journal byte is numeric") as u8)
        .collect::<Vec<_>>();
    serde_json::from_slice(&bytes).expect("journal material is JSON")
}

#[derive(Debug)]
struct RecordingDriver {
    semantic_result: Result<cerebellum_computer::platform::DispatchResult, DriverError>,
    per_pid_result: cerebellum_computer::platform::DispatchResult,
    fronted_result: Option<BracketReport>,
    fronted_bounds: Vec<u64>,
    effect: Result<EffectObservationResult, DriverError>,
    liveness: InputObserverLiveness,
    input: Result<InputObservationResult, DriverError>,
    focus: Result<FocusQueryResult, DriverError>,
    attendance: Result<AttendancePreconditionResult, DriverError>,
    fronting: VecDeque<FrontingSnapshot>,
    semantic_calls: usize,
    semantic_actions: Vec<String>,
    per_pid_calls: usize,
    global_calls: usize,
    effect_calls: usize,
    /// Which application each observation was asked to read.
    ///
    /// Recorded rather than counted, because an observation that ran against
    /// the wrong application returns an answer of exactly the same shape as one
    /// that ran against the right one.
    effect_targets: Vec<ProcessGrant>,
    dispatch_probe: Option<Arc<Mutex<DispatchProbe>>>,
    panic_during_semantic_dispatch: bool,
    /// An exact stop decision for the global path to return, when a test needs
    /// to name the numbers rather than accept the ones this driver derives.
    global_abort: Option<AbortDecision>,
    cancellation_posts: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

impl Default for RecordingDriver {
    fn default() -> Self {
        Self {
            semantic_result: Ok(cerebellum_computer::platform::DispatchResult {
                accepted_by_platform: true,
                effect_status: EffectStatus::EffectObserved,
                unreadable_subtrees: 0,
                delivery_posts_returned: 0,
                delivery_generation_verifications: 0,
            }),
            per_pid_result: cerebellum_computer::platform::DispatchResult {
                accepted_by_platform: true,
                effect_status: EffectStatus::EffectIndeterminate,
                unreadable_subtrees: 0,
                delivery_posts_returned: 2,
                delivery_generation_verifications: 4,
            },
            fronted_result: None,
            fronted_bounds: Vec::new(),
            effect: Ok(EffectObservationResult {
                status: EffectStatus::EffectObserved,
                failure_reason: None,
            }),
            effect_targets: Vec::new(),
            liveness: InputObserverLiveness {
                session_tap_live: true,
                raw_hid_live: true,
                self_echo_filter_live: true,
            },
            input: Ok(InputObservationResult {
                human_or_ambiguous_input: false,
                detection_latency_ms: 1,
            }),
            focus: Ok(FocusQueryResult {
                matches_target: true,
            }),
            attendance: Ok(AttendancePreconditionResult {
                valid: true,
                lease_generation: Some("lease-1".into()),
                age_ms: Some(1),
            }),
            fronting: VecDeque::from([fronting(0), fronting(100)]),
            semantic_calls: 0,
            semantic_actions: Vec::new(),
            per_pid_calls: 0,
            global_calls: 0,
            effect_calls: 0,
            dispatch_probe: None,
            panic_during_semantic_dispatch: false,
            global_abort: None,
            cancellation_posts: None,
        }
    }
}

impl PlatformDriver for RecordingDriver {
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
        Err(DriverError::Unsupported("tree"))
    }
    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        Err(DriverError::Unsupported("element"))
    }
    fn dispatch_semantic(
        &mut self,
        request: SemanticDispatchRequest,
    ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
        self.semantic_calls += 1;
        self.semantic_actions.push(request.action);
        if let Some(probe) = &self.dispatch_probe {
            let mut probe = probe.lock().unwrap();
            probe.intent_was_durable_at_dispatch =
                probe.latest_state.as_ref().is_some_and(has_durable_intent);
        }
        if self.panic_during_semantic_dispatch {
            panic!("simulated process crash after durable intent");
        }
        self.semantic_result.clone()
    }
    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
        if let Some(posts) = &self.cancellation_posts {
            use cerebellum_computer::platform::process_event::*;
            let steps = (0..5)
                .map(|event| SyntheticStep {
                    event,
                    role: SyntheticStepRole::SelfContained,
                })
                .collect();
            let failure = post_guarded_event_sequence(steps, cancelled, |_, event, _| {
                if event.is_some() {
                    posts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                Ok::<_, ProcessEventRefusal>(2)
            })
            .expect_err("script must be cancelled");
            return Err(DriverError::SyntheticDispatchFailed(SequencePostFailure {
                posts_returned: failure.posts_returned,
                refusal: failure.refusal.unwrap_or(ProcessEventRefusal::Cancelled),
                held_state: failure.held_state,
            }));
        }
        self.per_pid_calls += 1;
        Ok(self.per_pid_result.clone())
    }
    fn dispatch_fronted(
        &mut self,
        request: FrontedDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<BracketReport, DriverError> {
        self.fronted_bounds.push(request.maximum_interval_ms);
        self.fronted_result
            .clone()
            .ok_or(DriverError::Unsupported("fronted dispatch"))
    }

    fn dispatch_global(
        &mut self,
        request: GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
        if let Some(abort) = self.global_abort {
            return Err(DriverError::ObservedDispatchAborted(abort));
        }
        let reason = if self
            .input
            .as_ref()
            .is_ok_and(|input| input.human_or_ambiguous_input)
        {
            Some(AbortReason::UserSeizedControl)
        } else if self.focus.as_ref().is_ok_and(|focus| !focus.matches_target) {
            Some(AbortReason::FocusMismatch)
        } else {
            None
        };
        if let Some(reason) = reason {
            return Err(DriverError::ObservedDispatchAborted(AbortDecision {
                reason,
                stopped_action_index: 0,
                detection_latency_ms: Some(1),
                platform_delivery_latency_ms: None,
                sourced_input_kind: (reason == AbortReason::UserSeizedControl).then_some(
                    cerebellum_computer::dispatch::SourcedInputKind::OtherProcess { pid: 36_680 },
                ),
                maximum_detection_latency_ms: request.maximum_seize_detection_latency_ms,
                queued_posts_cancelled: 1,
            }));
        }
        self.global_calls += 1;
        Ok(cerebellum_computer::platform::DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: 0,
            delivery_posts_returned: 0,
            delivery_generation_verifications: 0,
        })
    }
    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        self.focus.clone()
    }
    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        self.fronting
            .pop_front()
            .ok_or(DriverError::Unsupported("fronting"))
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        self.liveness.clone()
    }
    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        self.input.clone()
    }
    fn observe_effect(
        &mut self,
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        self.effect_calls += 1;
        self.effect_targets.push(request.target);
        self.effect.clone()
    }
    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        self.attendance.clone()
    }
}

#[derive(Debug)]
struct RecordingConsent {
    calls: Vec<String>,
    decision: ConsentDecision,
}

impl cerebellum_computer::dispatch::EscalationConsent for RecordingConsent {
    fn request_consent(&mut self, escalation_id: &str) -> ConsentDecision {
        self.calls.push(escalation_id.to_string());
        self.decision
    }
}

fn once_dispatch_token() -> cerebellum_core::consent::OnceDispatchToken {
    cerebellum_core::consent::OnceDispatchToken::admitted_by_takeover_grant()
}

fn background_attendance() -> AttendanceContext {
    AttendanceContext::background(
        "conversation-1",
        target(),
        "process-1",
        AttendanceLease::new(
            "conversation-1",
            target(),
            "process-1",
            0,
            300_000,
            "lease-1",
            "monotonic-v1",
        )
        .unwrap(),
        0,
        0,
        300_000,
        50,
        true,
    )
}

fn semantic_request(row: FrozenDispatchRow) -> DispatchRequest {
    semantic_request_for_action(row, SEMANTIC_PRESS_ACTION)
}

fn semantic_request_for_action(row: FrozenDispatchRow, action: &str) -> DispatchRequest {
    let element = ElementResolutionResult {
        element_name: AccessibilityElementName::Identifier("element-1".into()),
        alternate_name: None,
        owning_process: target(),
        semantic_actions: vec![action.into()],
        unreadable_subtrees: 0,
    };
    DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "computer-effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::background(
            "conversation-1",
            target(),
            "process-1",
            AttendanceLease::new(
                "conversation-1",
                target(),
                "process-1",
                0,
                300_000,
                "lease-1",
                "monotonic-v1",
            )
            .unwrap(),
            0,
            0,
            300_000,
            50,
            true,
        ),
        0,
    )
    .with_semantic(element, action)
}

#[test]
fn semantic_dispatch_is_first_and_effect_is_observed_even_when_no_effect_occurs() {
    let driver = RecordingDriver {
        effect: Ok(EffectObservationResult {
            status: EffectStatus::NoEffectObserved,
            failure_reason: Some("post_condition_undeclarable".into()),
        }),
        ..RecordingDriver::default()
    };
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let report = dispatcher
        .dispatch(
            &mut audit(),
            audit_identity(),
            semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap()),
        )
        .unwrap();
    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::SemanticAccessibility
    );
    assert_eq!(report.effect.status, EffectStatus::NoEffectObserved);
    assert_eq!(report.effect.observation_attempts, 1);
    assert_eq!(dispatcher.driver().semantic_calls, 1);
    assert_eq!(dispatcher.driver().per_pid_calls, 0);
    assert_eq!(dispatcher.trace()[0], DispatchPhase::PredicateSerialized);
    assert!(
        dispatcher
            .trace()
            .iter()
            .position(|p| *p == DispatchPhase::SemanticDispatch)
            .unwrap()
            < dispatcher
                .trace()
                .iter()
                .position(|p| *p == DispatchPhase::EffectObserved)
                .unwrap()
    );
    assert_eq!(
        report.containment.containment_rung,
        Some(cerebellum_computer::platform::containment::ContainmentRung::SemanticElement)
    );
}

#[test]
fn press_and_cancel_reach_the_same_audited_semantic_platform_path() {
    for action in [SEMANTIC_PRESS_ACTION, SEMANTIC_CANCEL_ACTION] {
        let request = semantic_request_for_action(
            FrozenDispatchRow::for_capability("computer.type").unwrap(),
            action,
        );
        let mut dispatcher = Dispatcher::new(
            RecordingDriver::default(),
            &cerebellum_computer::platform::process_event::never_cancelled,
        );
        let mut audit = audit();

        let report = dispatcher
            .dispatch(&mut audit, audit_identity(), request)
            .expect("both click actions use semantic dispatch");

        assert_eq!(dispatcher.driver().semantic_actions, [action]);
        assert_eq!(
            report.delivery_primitive,
            cerebellum_computer::platform::containment::DeliveryPrimitive::SemanticAccessibility
        );
        assert_eq!(
            report.containment.rung(),
            Some(cerebellum_computer::platform::containment::ContainmentRung::SemanticElement)
        );
        let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
            &audit.journal().export_bytes(),
        )
        .unwrap();
        assert_eq!(entry["phase"], json!("finalized"));
        assert_eq!(
            decode_embedded_json(&entry["dispatch_material"])["action"],
            json!(action)
        );
        assert_eq!(
            decode_embedded_json(&entry["completed_result"])["outcome"],
            json!("handler_returned")
        );
    }
}

#[test]
fn semantic_delivery_cannot_report_a_non_semantic_rung() {
    let mut request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap());
    request.identity = None;
    let report = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    )
    .dispatch(&mut audit(), audit_identity(), request)
    .expect("semantic delivery has element-scoped containment without structural evidence");

    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::SemanticAccessibility
    );
    assert_eq!(
        report.containment.rung(),
        Some(cerebellum_computer::platform::containment::ContainmentRung::SemanticElement),
        "semantic accessibility delivery reported a weaker containment rung"
    );
}

#[test]
fn semantic_reply_and_journal_use_the_same_containment_rung() {
    let mut request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap());
    request.identity = None;
    let mut audit = audit();
    let report = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    )
    .dispatch(&mut audit, audit_identity(), request)
    .expect("semantic delivery is recorded before returning its report");

    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::SemanticAccessibility
    );
    let reply_rung = serde_json::to_value(
        report
            .containment
            .rung()
            .expect("an input delivery reports one containment rung"),
    )
    .unwrap();
    let journal_rung = serde_json::to_value(
        audit
            .read_computer_audit_record(1)
            .unwrap()
            .descriptor
            .containment_rung,
    )
    .unwrap();
    assert_eq!(
        reply_rung,
        json!("semantic_element"),
        "semantic accessibility delivery reported a non-semantic rung"
    );
    assert_eq!(
        reply_rung, journal_rung,
        "the reply and durable journal recorded different containment rungs"
    );
}

#[test]
fn mode_and_delivery_primitive_are_not_substituted() {
    let mut driver = RecordingDriver::default();
    let row = FrozenDispatchRow::for_capability("computer.type")
        .unwrap()
        .with_private_envelope(false);
    let request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"));
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    assert_eq!(
        dispatcher.dispatch(&mut audit(), audit_identity(), request),
        Err(DispatchError::EnvelopeUnrecognized)
    );
    assert_eq!(dispatcher.driver().per_pid_calls, 0);
    assert_eq!(dispatcher.driver().global_calls, 0);

    driver = RecordingDriver::default();
    let row = FrozenDispatchRow::for_capability("computer.type")
        .unwrap()
        .with_global_cursor_movement(PermissionLiveness::Unavailable);
    let request = DispatchRequest::new(
        row,
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"))
    .with_focus_plan(FocusCheckPlan::immediate(0));
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    assert_eq!(
        dispatcher.dispatch(&mut audit(), audit_identity(), request),
        Err(DispatchError::AttendanceUnavailable)
    );
    assert_eq!(dispatcher.driver().per_pid_calls, 0);
    assert_eq!(dispatcher.driver().global_calls, 0);
}

#[test]
fn seized_input_aborts_sequence_and_cancels_every_queued_post() {
    let driver = RecordingDriver {
        input: Ok(InputObservationResult {
            human_or_ambiguous_input: true,
            detection_latency_ms: 2,
        }),
        ..RecordingDriver::default()
    };
    let row = FrozenDispatchRow::for_capability("computer.type").unwrap();
    let request = DispatchRequest::new(
        row,
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"))
    .with_focus_plan(FocusCheckPlan::immediate(0))
    .with_once_dispatch_token(once_dispatch_token());
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit();
    let sequence = dispatcher
        .dispatch_sequence(&mut audit, &audit_identity(), [request])
        .unwrap();
    assert_eq!(sequence.completed.len(), 0);
    assert_eq!(
        sequence.abort.unwrap().reason,
        AbortReason::UserSeizedControl
    );
    assert_eq!(dispatcher.driver().global_calls, 0);
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], json!("finalized"));
    assert_eq!(
        decode_embedded_json(&entry["completed_result"]),
        json!({
            "outcome": "refused",
            "routes": {"skylight": 0, "public": 0},
            "release_routes": {"skylight": 0, "public": 0},
            "auth": "not_applicable",
            "refusal": {
                "reason": "user_seized_control",
                "sourced_input_kind": {"source": "other_process", "pid": 36_680},
            },
            "abort": {
                "reason": "user_seized_control",
                "stopped_action_index": 0,
                "detection_latency_ms": 1,
                "sourced_input_kind": {"source": "other_process", "pid": 36_680},
                "maximum_detection_latency_ms": 50,
                "queued_posts_cancelled": 1,
            },
        }),
        "the journal must retain which process seized global input"
    );

    let mut watcher = SeizeWatcher::new(50);
    assert!(watcher.queue_post());
    assert!(watcher.queue_post());
    watcher.abort(AbortReason::UserSeizedControl, 1, Some(2));
    assert_eq!(watcher.abort_decision().unwrap().queued_posts_cancelled, 2);
    assert!(!watcher.take_post_slot());
}

/// An observed abort leaves its numbers in the journal, and only there.
///
/// The refusal the caller receives is fixed: a reason and which source seized.
/// How long detection took, which action in the sequence stopped, and how many
/// queued posts were thrown away have no declared place in that reply, so the
/// audit record is the only place anyone can read them afterwards. Both halves
/// are asserted, because a change that widened the reply instead would satisfy
/// the journal half alone.
///
/// The three numbers are asserted as literals rather than as presence: a record
/// that carried the right shape with the wrong values -- a default, a zero, the
/// latency bound in place of the measurement -- would read as a pass.
#[test]
fn an_observed_abort_journals_its_numbers_while_the_wire_reply_carries_none() {
    let driver = RecordingDriver {
        global_abort: Some(AbortDecision {
            reason: AbortReason::UserSeizedControl,
            stopped_action_index: 2,
            detection_latency_ms: Some(23),
            platform_delivery_latency_ms: None,
            sourced_input_kind: Some(SourcedInputKind::Hardware),
            maximum_detection_latency_ms: 50,
            queued_posts_cancelled: 3,
        }),
        ..RecordingDriver::default()
    };
    let request = DispatchRequest::new(
        FrozenDispatchRow::for_capability("computer.takeover_move").unwrap(),
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(SyntheticAction::move_pointer(SyntheticPoint {
        x: 10.0,
        y: 20.0,
    }))
    .with_focus_plan(FocusCheckPlan::immediate(0))
    .with_once_dispatch_token(once_dispatch_token());

    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit();
    let refusal = dispatcher
        .dispatch(&mut audit, audit_identity(), request)
        .expect_err("the driver aborted this dispatch");
    assert_eq!(
        refusal,
        DispatchError::UserSeizedControl {
            sourced_input_kind: Some(SourcedInputKind::Hardware),
        }
    );

    // Exactly what the module serializes into the tool reply.
    let wire = serde_json::to_value(&refusal).expect("the refusal taxonomy serializes");
    assert_eq!(wire["reason"], json!("user_seized_control"));
    assert!(
        wire.get("abort").is_none(),
        "the stop decision reached the caller's reply: {wire}"
    );

    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], json!("finalized"));
    let outcome = decode_embedded_json(&entry["completed_result"]);
    assert_eq!(
        outcome["abort"],
        json!({
            "reason": "user_seized_control",
            "stopped_action_index": 2,
            "detection_latency_ms": 23,
            "sourced_input_kind": {"source": "hardware"},
            "maximum_detection_latency_ms": 50,
            "queued_posts_cancelled": 3,
        }),
        "the journal must carry the whole stop decision: {outcome}"
    );
}

#[test]
fn coordinate_per_pid_delivery_succeeds_only_with_the_global_none_rung() {
    // No current row may name a per-process target by coordinate, so the row
    // is widened to one that may ground by pixels: the rung rule under test
    // belongs to the dispatcher, whichever row first needs it.
    let mut row = FrozenDispatchRow::for_capability("computer.type").unwrap();
    row.pixel_fallback_eligible = true;
    let request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(SyntheticAction::move_pointer(SyntheticPoint {
        x: 10.0,
        y: 20.0,
    }));
    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let report = dispatcher
        .dispatch(&mut audit(), audit_identity(), request)
        .unwrap();
    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::PerPidSynthetic
    );
    assert_eq!(
        report.containment.containment_rung,
        Some(cerebellum_computer::platform::containment::ContainmentRung::GlobalNone)
    );
    assert_eq!(
        report.containment.forfeiture_reason,
        Some(cerebellum_computer::platform::containment::ContainmentForfeitureReason::CoordinateAddressed)
    );
}

/// A per-pid synthetic dispatch earns the structural containment rung, not
/// the semantic one.
///
/// Semantic actuation asks an application to invoke its own control; a
/// synthetic post types into whatever has focus inside the process. Awarding
/// the semantic containment rung to it would under-report severity in the
/// audit journal, so the rung is awarded from the delivery primitive, and the
/// reply and the durable journal must agree on it.
#[test]
fn a_delivery_that_posted_nothing_cannot_earn_an_atomic_binding() {
    // The ratio test is arithmetic: zero checks for zero posts satisfies it,
    // so an empty delivery would earn the STRONGEST binding for having done
    // nothing. `computer.type` accepts an empty string, so this is a request a
    // caller can send rather than a hypothetical.
    //
    // The wrong implementation and the right one agree on every non-empty
    // delivery, which is exactly why this case needs its own test: a fixture
    // that always posts cannot tell them apart.
    let result = DispatchResult {
        accepted_by_platform: true,
        effect_status: EffectStatus::EffectIndeterminate,
        unreadable_subtrees: 0,
        delivery_posts_returned: 0,
        delivery_generation_verifications: 0,
    };
    assert_eq!(
        result.identity_to_delivery_binding(),
        IdentityAtomicBinding::NonAtomic,
        "a delivery with no posts has nothing to bind identity to"
    );

    // Contrast, so the test above cannot pass by the binding being NonAtomic
    // for everything: a real delivery with a check before every post earns it.
    let delivered = DispatchResult {
        accepted_by_platform: true,
        effect_status: EffectStatus::EffectIndeterminate,
        unreadable_subtrees: 0,
        delivery_posts_returned: 2,
        delivery_generation_verifications: 4,
    };
    assert_eq!(
        delivered.identity_to_delivery_binding(),
        IdentityAtomicBinding::Atomic,
        "two checks per post is the atomic shape"
    );
}

#[test]
fn per_pid_synthetic_delivery_reports_the_structural_rung_not_the_semantic_one() {
    let row = FrozenDispatchRow::for_capability("computer.type").unwrap();
    let request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"));
    let mut audit = audit();
    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let report = dispatcher
        .dispatch(&mut audit, audit_identity(), request)
        .expect("per-pid delivery succeeds against the recording driver");

    assert_eq!(dispatcher.driver().per_pid_calls, 1);
    assert_eq!(dispatcher.driver().semantic_calls, 0);
    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::PerPidSynthetic
    );
    let delivery_identity = report
        .containment
        .identity
        .as_ref()
        .expect("per-pid delivery reports its generation checks");
    assert_eq!(
        delivery_identity.identity_to_delivery_binding,
        IdentityAtomicBinding::Atomic
    );
    assert_eq!(
        delivery_identity.status,
        cerebellum_computer::platform::containment::IdentityVerificationStatus::Matched
    );
    let reply_rung = serde_json::to_value(
        report
            .containment
            .rung()
            .expect("an input delivery reports one containment rung"),
    )
    .unwrap();
    let journal_rung = serde_json::to_value(
        audit
            .read_computer_audit_record(1)
            .unwrap()
            .descriptor
            .containment_rung,
    )
    .unwrap();
    assert_eq!(
        reply_rung,
        json!("pid_structural"),
        "per-pid synthetic delivery reported a rung it did not earn"
    );
    assert_eq!(
        reply_rung, journal_rung,
        "the reply and durable journal recorded different containment rungs"
    );
}

#[test]
fn a_fronted_dispatch_compares_against_its_plan_and_other_dispatches_keep_the_row_bound() {
    let row_bound = FrozenDispatchRow::for_capability("computer.type")
        .unwrap()
        .maximum_fronting_bracket_interval_ms;
    for (plan_bound, interval_ms, stable) in [
        (Some(200), 150, true),
        (Some(200), 210, false),
        (Some(row_bound), 150, false),
        (None, 150, false),
    ] {
        let mut request = typing_request("x");
        let observation_window_ms = request.row.fronting_observation_window_ms;
        // The pre snapshot precedes dispatch, and the post snapshot lands at
        // dispatch plus the unchanged observation window in every case.
        request.now_ms = interval_ms - observation_window_ms;
        if let Some(bound) = plan_bound {
            request = request.with_fronting_bracket(bound);
        }
        let driver = RecordingDriver {
            fronting: VecDeque::from([fronting(0), fronting(interval_ms)]),
            fronted_result: Some(BracketReport {
                previous_frontmost: Some(99),
                chunks: 1,
                units_posted: 1,
                posts_returned: 2,
                generation_verifications: 4,
                longest_fronted_interval_ms: interval_ms,
                slowest_unit_ms: interval_ms,
                slowest_restore_ms: 0,
                restore: RestoreStatus::Restored,
                stop: None,
                waiting_out_slow_post: false,
                waiting_out_slow_restore: false,
            }),
            ..RecordingDriver::default()
        };
        let mut audit = audit();
        let mut dispatcher = Dispatcher::new(
            driver,
            &cerebellum_computer::platform::process_event::never_cancelled,
        );
        let report = dispatcher
            .dispatch(&mut audit, audit_identity(), request)
            .expect("the scripted delivery succeeds");
        assert_eq!(report.containment.fronting_stable, stable, "{report:?}");
        let comparison = report.fronting.expect("input compares fronting");
        assert_eq!(comparison.unchanged(), stable);
        assert_eq!(comparison.measured_bracket_interval_ms, Some(interval_ms));
        assert_eq!(
            comparison.maximum_fronting_bracket_interval_ms,
            plan_bound.unwrap_or(row_bound)
        );
        assert_eq!(
            comparison.declared_observation_window_ms,
            observation_window_ms
        );
        assert_eq!(
            dispatcher.driver().fronted_bounds,
            plan_bound.into_iter().collect::<Vec<_>>()
        );
        assert_eq!(
            serde_json::to_value(report.containment.rung().unwrap()).unwrap(),
            json!("pid_structural")
        );
    }
}

#[test]
fn a_hoisted_generation_check_cannot_earn_atomic_per_pid_binding() {
    let row = FrozenDispatchRow::for_capability("computer.type").unwrap();
    let request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"));
    let mut driver = RecordingDriver::default();
    driver.per_pid_result.delivery_generation_verifications = 3;

    let report = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    )
    .dispatch(&mut audit(), audit_identity(), request)
    .expect("global-none authorization records a non-atomic delivery honestly");
    let delivery_identity = report
        .containment
        .identity
        .expect("the delivery counts produce identity evidence");

    assert_eq!(
        delivery_identity.identity_to_delivery_binding,
        IdentityAtomicBinding::NonAtomic,
        "three checks for two posts must not claim an atomic binding"
    );
    assert_eq!(
        report.containment.containment_rung,
        Some(cerebellum_computer::platform::containment::ContainmentRung::GlobalNone)
    );
    assert_eq!(
        report.containment.forfeiture_reason,
        Some(
            cerebellum_computer::platform::containment::ContainmentForfeitureReason::IdentityUnavailable
        )
    );
}

#[test]
fn background_lease_is_renewable_but_expiry_before_post_stops_delivery() {
    let lease = AttendanceLease::new(
        "conversation-1",
        target(),
        "process-1",
        0,
        10,
        "lease-1",
        "monotonic-v1",
    )
    .unwrap();
    let row = FrozenDispatchRow::for_capability("computer.type").unwrap();
    let valid_request = DispatchRequest::new(
        row.clone(),
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::background(
            "conversation-1",
            target(),
            "process-1",
            lease.clone(),
            0,
            5,
            300_000,
            50,
            true,
        ),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"));
    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    assert!(dispatcher
        .dispatch(&mut audit(), audit_identity(), valid_request)
        .is_ok());
    assert_eq!(dispatcher.driver().per_pid_calls, 1);

    let expired_request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::background(
            "conversation-1",
            target(),
            "process-1",
            lease,
            0,
            11,
            300_000,
            50,
            true,
        ),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"));
    assert_eq!(
        dispatcher.dispatch(&mut audit(), audit_identity(), expired_request),
        Err(DispatchError::AttendanceUnavailable)
    );
    assert_eq!(dispatcher.driver().per_pid_calls, 1);
}

#[test]
fn retry_and_escalation_never_repeat_a_committed_attempt_blindly() {
    let mut ledger = cerebellum_computer::dispatch::AttemptLedger::new();
    ledger.record("attempt-1", AttemptDisposition::Committed);
    assert_eq!(
        retry_decision(
            RetryClass::Idempotent,
            AttemptDisposition::Committed,
            ReconciliationResult::NoEffectObserved,
            None,
            &ledger,
            "attempt-1",
        ),
        RetryDecision::DoNotRetry
    );
    assert_eq!(
        retry_decision(
            RetryClass::ReconcileBeforeRetry,
            AttemptDisposition::MayHaveCommitted,
            ReconciliationResult::NoEffectObserved,
            None,
            &ledger,
            "attempt-2",
        ),
        RetryDecision::RetryAfterNoEffect
    );

    struct Consent;
    impl cerebellum_computer::dispatch::EscalationConsent for Consent {
        fn request_consent(&mut self, _escalation_id: &str) -> ConsentDecision {
            ConsentDecision::Granted
        }
    }
    let mut consent = Consent;
    let escalation = authorize_escalation(
        &mut consent,
        "escalation-1",
        "attempt-2",
        AttemptDisposition::MayHaveCommitted,
        ReconciliationResult::NoEffectObserved,
        RetryClass::ReconcileBeforeRetry,
        &ledger,
    )
    .unwrap();
    assert_eq!(escalation.consent, ConsentDecision::Granted);
    assert_eq!(
        escalation.observed_attempt_id.as_deref(),
        Some("escalation-1:observed")
    );
}

// Escalation retries an action in observed mode after a background attempt whose
// effect may already have landed, so refusing an unsafe retry is what stops a
// committed action from being performed twice.  The consent call is asserted to
// be absent rather than merely late: asking someone to approve an escalation
// already known to be unsafe is itself the defect, and the ordering is only a
// property of the current control flow until a test requires it.
fn assert_escalation_refused_before_consent(
    prior_disposition: AttemptDisposition,
    reconciliation: ReconciliationResult,
    retry_class: RetryClass,
    ledger: &cerebellum_computer::dispatch::AttemptLedger,
    attempt_id: &str,
) {
    let mut consent = RecordingConsent {
        calls: Vec::new(),
        decision: ConsentDecision::Granted,
    };
    let result = authorize_escalation(
        &mut consent,
        "unsafe-escalation",
        attempt_id,
        prior_disposition,
        reconciliation,
        retry_class,
        ledger,
    );
    assert_eq!(
        result,
        Err(cerebellum_computer::dispatch::EscalationError::RetryUnsafe)
    );
    assert_eq!(consent.calls, Vec::<String>::new());
}

#[test]
fn escalation_refuses_possible_commit_without_no_effect_reconciliation() {
    let ledger = cerebellum_computer::dispatch::AttemptLedger::new();
    assert_escalation_refused_before_consent(
        AttemptDisposition::MayHaveCommitted,
        ReconciliationResult::EffectIndeterminate,
        RetryClass::Idempotent,
        &ledger,
        "possibly-committed",
    );
}

#[test]
fn every_non_retryable_class_refuses_before_consent() {
    let ledger = cerebellum_computer::dispatch::AttemptLedger::new();
    assert_escalation_refused_before_consent(
        AttemptDisposition::NoEffectObserved,
        ReconciliationResult::NoEffectObserved,
        RetryClass::NeverAutomaticRetry,
        &ledger,
        "never-automatic",
    );
    assert_escalation_refused_before_consent(
        AttemptDisposition::NoEffectObserved,
        ReconciliationResult::NoEffectObserved,
        RetryClass::Deduplicated,
        &ledger,
        "missing-deduplication-key",
    );
    assert_escalation_refused_before_consent(
        AttemptDisposition::NoEffectObserved,
        ReconciliationResult::EffectIndeterminate,
        RetryClass::ReconcileBeforeRetry,
        &ledger,
        "unreconciled",
    );
}

#[test]
fn permitted_escalation_requests_consent_and_records_a_distinct_attempt() {
    let ledger = cerebellum_computer::dispatch::AttemptLedger::new();
    let mut consent = RecordingConsent {
        calls: Vec::new(),
        decision: ConsentDecision::Granted,
    };
    let result = authorize_escalation(
        &mut consent,
        "escalation-positive",
        "background-attempt",
        AttemptDisposition::MayHaveCommitted,
        ReconciliationResult::NoEffectObserved,
        RetryClass::ReconcileBeforeRetry,
        &ledger,
    );
    assert_eq!(
        result,
        Ok(cerebellum_computer::dispatch::EscalationAttempt {
            escalation_id: "escalation-positive".into(),
            background_attempt_id: "background-attempt".into(),
            observed_attempt_id: Some("escalation-positive:observed".into()),
            consent: ConsentDecision::Granted,
            prior_disposition: AttemptDisposition::MayHaveCommitted,
            reconciliation: ReconciliationResult::NoEffectObserved,
        })
    );
    assert_eq!(consent.calls, vec!["escalation-positive".to_string()]);
}

#[test]
fn seize_latency_must_fit_between_observed_posts() {
    let row = FrozenDispatchRow::for_capability("computer.type").unwrap();
    let first = DispatchRequest::new(
        row.clone(),
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"))
    .with_focus_plan(FocusCheckPlan::immediate(0))
    .with_once_dispatch_token(once_dispatch_token());
    let second = DispatchRequest::new(
        row,
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 1, 1, true),
        1,
    )
    .with_synthetic(SyntheticAction::type_text("x"))
    .with_focus_plan(FocusCheckPlan::immediate(1))
    .with_once_dispatch_token(once_dispatch_token());
    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let result = dispatcher
        .dispatch_sequence(&mut audit(), &audit_identity(), [first, second])
        .unwrap();
    assert_eq!(result.completed.len(), 1);
    assert_eq!(
        result.abort.unwrap().reason,
        AbortReason::SeizeLatencyBoundExceeded
    );
    assert_eq!(dispatcher.driver().global_calls, 1);
}

#[test]
fn unsupported_semantic_path_reaches_the_caller_without_a_synthetic_retry() {
    let driver = RecordingDriver {
        semantic_result: Err(DriverError::Unsupported("semantic")),
        ..RecordingDriver::default()
    };
    let request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap())
        .with_synthetic(SyntheticAction::type_text("x"));
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit();

    let refusal = dispatcher
        .dispatch(&mut audit, audit_identity(), request)
        .expect_err("an unsupported semantic attempt is not retried through another primitive");

    assert_eq!(refusal, DispatchError::SemanticPathUnavailable);
    assert_eq!(
        serde_json::to_value(&refusal).unwrap(),
        json!({"reason": "semantic_path_unavailable"})
    );
    assert_eq!(dispatcher.driver().semantic_calls, 1);
    assert_eq!(dispatcher.driver().per_pid_calls, 0);
    assert_eq!(dispatcher.driver().global_calls, 0);
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], json!("finalized"));
    assert_eq!(
        decode_embedded_json(&entry["completed_result"]),
        json!({
            "outcome": "refused",
            "routes": {"skylight": 0, "public": 0},
            "release_routes": {"skylight": 0, "public": 0},
            "auth": "not_applicable",
            "refusal": {"reason": "semantic_path_unavailable"},
        })
    );
}

#[test]
fn observed_focus_mismatch_prevents_the_global_post() {
    let driver = RecordingDriver {
        focus: Ok(FocusQueryResult {
            matches_target: false,
        }),
        ..RecordingDriver::default()
    };
    let request = DispatchRequest::new(
        FrozenDispatchRow::for_capability("computer.type").unwrap(),
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("x"))
    .with_focus_plan(FocusCheckPlan::immediate(0))
    .with_once_dispatch_token(once_dispatch_token());
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    assert_eq!(
        dispatcher.dispatch(&mut audit(), audit_identity(), request),
        Err(DispatchError::TargetFocusMismatch)
    );
    assert_eq!(dispatcher.driver().global_calls, 0);
}

#[test]
fn unavailable_effect_observer_is_one_indeterminate_status() {
    let driver = RecordingDriver {
        effect: Err(DriverError::Unsupported("effect")),
        ..RecordingDriver::default()
    };
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let report = dispatcher
        .dispatch(
            &mut audit(),
            audit_identity(),
            semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap()),
        )
        .unwrap();
    assert_eq!(report.effect.status, EffectStatus::EffectIndeterminate);
    assert_eq!(report.effect.observation_attempts, 1);
    assert_eq!(dispatcher.driver().effect_calls, 1);
}

#[test]
fn fronting_downgrade_does_not_forfeit_semantic_delivery_containment() {
    let mut post = fronting(100);
    post.target_windows[0].z_order = 2;
    let driver = RecordingDriver {
        fronting: VecDeque::from([fronting(0), post]),
        ..RecordingDriver::default()
    };
    let request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap());
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let report = dispatcher
        .dispatch(&mut audit(), audit_identity(), request)
        .unwrap();
    assert_eq!(
        report.containment.containment_rung,
        Some(cerebellum_computer::platform::containment::ContainmentRung::SemanticElement)
    );
    assert_eq!(report.containment.forfeiture_reason, None);
    assert_eq!(
        report.fronting.unwrap().comparison,
        FrontingComparison::DowngradeDetected
    );
}

/// An element belonging to another process is not acted on through this grant.
///
/// The containment boundary itself. A grant names one process, and an element
/// resolved from a different one is outside what the user permitted -- so
/// dispatching it semantically would deliver an action to an application nobody
/// authorised, while the journal recorded the authorised target.
///
/// Falling through to synthetic is correct rather than a workaround: synthetic
/// delivery is addressed to the grant's own process, so the action stays inside
/// the boundary and merely loses the containment dividend it could not earn.
#[test]
fn an_element_owned_by_another_process_does_not_take_the_semantic_path() {
    let mut request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap());
    let foreign = ProcessGrant {
        pid: 99,
        bundle_identity: "com.example.other".into(),
        process_generation_evidence: "generation-9".into(),
    };
    request = request
        .with_semantic(
            ElementResolutionResult {
                element_name: AccessibilityElementName::Identifier("element-1".into()),
                alternate_name: None,
                owning_process: foreign,
                semantic_actions: vec![SEMANTIC_PRESS_ACTION.into()],
                unreadable_subtrees: 0,
            },
            SEMANTIC_PRESS_ACTION,
        )
        .with_synthetic(SyntheticAction::type_text("x"));

    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let report = dispatcher
        .dispatch(&mut audit(), audit_identity(), request)
        .unwrap();

    assert_eq!(
        dispatcher.driver().semantic_calls,
        0,
        "an element owned by another process reached the semantic path"
    );
    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::PerPidSynthetic
    );
    assert_ne!(
        report.containment.containment_rung,
        Some(cerebellum_computer::platform::containment::ContainmentRung::SemanticElement),
        "the semantic containment dividend was claimed without a semantic dispatch"
    );
}

/// A gate refusal is a finalized audit event even though no handler ran.
#[test]
fn an_unadvertised_cancel_is_refused_by_name_and_lists_advertised_actions() {
    let request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap())
        .with_semantic(
            ElementResolutionResult {
                element_name: AccessibilityElementName::Identifier("element-1".into()),
                alternate_name: None,
                owning_process: target(),
                semantic_actions: vec![SEMANTIC_PRESS_ACTION.into()],
                unreadable_subtrees: 0,
            },
            SEMANTIC_CANCEL_ACTION,
        )
        .with_synthetic(SyntheticAction::type_text("x"));
    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit();

    let refusal = dispatcher
        .dispatch(&mut audit, audit_identity(), request)
        .expect_err("an unadvertised action is refused before dispatch");

    assert_eq!(
        serde_json::to_value(&refusal).unwrap(),
        json!({
            "reason": "action_not_advertised",
            "action": "cancel",
            "advertised": ["press"],
        })
    );
    assert_eq!(dispatcher.driver().semantic_calls, 0);
    assert_eq!(dispatcher.driver().per_pid_calls, 0);
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], json!("rejected"));
    assert_eq!(
        decode_embedded_json(&entry["rejection_material"]),
        json!({
            "outcome": "no_action",
            "routes": {"skylight": 0, "public": 0},
            "release_routes": {"skylight": 0, "public": 0},
            "auth": "not_applicable",
            "refusal": {
                "reason": "action_not_advertised",
                "action": "cancel",
                "advertised": ["press"],
            },
        })
    );
}

/// The effect is checked in the application the action was authorised against.
///
/// An observation carries the grant rather than letting the observer decide
/// which application to read. An observer that read whichever application was
/// frontmost would check the condition against a window the action never
/// touched — and since the answer has the same shape either way, a wrong
/// reading is indistinguishable from a right one at every layer above.
///
/// The failure this prevents is worse than a missed effect: an action that did
/// nothing would be reported as having worked, because something else on the
/// screen happened to satisfy the condition.
#[test]
fn the_effect_is_observed_in_the_authorised_application() {
    let mut dispatcher = Dispatcher::new(
        RecordingDriver::default(),
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    dispatcher
        .dispatch(
            &mut audit(),
            audit_identity(),
            semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap()),
        )
        .unwrap();

    assert_eq!(
        dispatcher.driver().effect_targets,
        vec![target()],
        "the effect was checked somewhere other than the authorised application"
    );
}

/// A recorded condition can be decided by whoever reads it back.
///
/// The condition is written down before an action and read again afterwards by
/// an observer that must answer whether it held. Free text could be recorded
/// and could not be answered, so the observer's only honest reply would be
/// indeterminate — indistinguishable from an action that could not be observed
/// at all, and the two call for opposite responses.
///
/// This asserts the round trip yields a condition the evaluator accepts, which
/// is what makes recording it worth anything.
#[test]
fn a_recorded_condition_can_be_decided_when_it_is_read_back() {
    use cerebellum_computer::dispatch::post_condition::{
        evaluate, ConditionOutcome, ObservedElement,
    };

    let expected = ExpectedPostCondition::new(
        "computer-effect-v1",
        PostCondition::ElementValueEquals {
            element: AccessibilityElementName::identifier("field-1"),
            expected: "typed".into(),
        },
    );
    let bytes = expected.serialize_before_dispatch().expect("serializes");

    let restored: ExpectedPostCondition = serde_json::from_slice(&bytes).expect("reads back");
    assert_eq!(restored, expected);

    // The restored condition gets a definite outcome rather than the
    // indeterminate one an undecidable condition would produce.
    let outcome = evaluate(
        &restored.condition,
        &ObservedElement {
            present: true,
            focused: None,
            enabled: None,
            value: Some("typed".into()),
            unreadable_subtrees: 0,
        },
    );
    assert_eq!(outcome, ConditionOutcome::Satisfied);
}

#[test]
fn every_semantic_refusal_reaches_the_caller_with_its_remedy_payload() {
    let cases = vec![
        (
            DriverError::Semantic(SemanticDriverError::ActionUnsupported {
                intent: SemanticActionIntent::Cancel,
                platform: SemanticActionPlatform::Windows,
            }),
            json!({
                "reason": "semantic_action_unsupported",
                "intent": "cancel",
                "platform": "windows",
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::ElementNameAmbiguous {
                key_form: AccessibilityKeyForm::RoleAndTitle,
                match_count: 30,
            }),
            json!({
                "reason": "element_name_ambiguous",
                "key_form": "role_and_title",
                "match_count": 30,
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::ElementNotFound {
                key_form: AccessibilityKeyForm::Identifier,
            }),
            json!({
                "reason": "element_not_found",
                "key_form": "identifier",
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::ActionNotAdvertised {
                action: SEMANTIC_PRESS_ACTION.to_string(),
                advertised: vec!["AXConfirm".to_string(), "AXCancel".to_string()],
            }),
            json!({
                "reason": "action_not_advertised",
                "action": "press",
                "advertised": ["AXConfirm", "AXCancel"],
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::ApplicationRefused { ax_error: -25205 }),
            json!({
                "reason": "application_refused",
                "ax_error": -25205,
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::AccessibilityPermissionUnavailable),
            json!({"reason": "accessibility_permission_unavailable"}),
        ),
        (
            DriverError::Semantic(SemanticDriverError::TargetNoLongerCurrent {
                disposition: TargetDisposition::Gone,
            }),
            json!({
                "reason": "target_no_longer_current",
                "disposition": "gone",
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::TargetNoLongerCurrent {
                disposition: TargetDisposition::Replaced,
            }),
            json!({
                "reason": "target_no_longer_current",
                "disposition": "replaced",
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::Transient { deadline_ms: 3_000 }),
            json!({
                "reason": "semantic_dispatch_transient",
                "deadline_ms": 3_000,
            }),
        ),
        (
            DriverError::Semantic(SemanticDriverError::PathUnavailable),
            json!({"reason": "semantic_path_unavailable"}),
        ),
    ];

    for (driver_error, expected_caller_payload) in cases {
        let driver = RecordingDriver {
            semantic_result: Err(driver_error),
            ..RecordingDriver::default()
        };
        let mut dispatcher = Dispatcher::new(
            driver,
            &cerebellum_computer::platform::process_event::never_cancelled,
        );
        let mut audit = audit();
        let refusal = dispatcher
            .dispatch(
                &mut audit,
                audit_identity(),
                semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap()),
            )
            .expect_err("the semantic driver refusal reaches its caller");

        assert_eq!(
            serde_json::to_value(&refusal).unwrap(),
            expected_caller_payload,
            "caller received the wrong semantic remedy for {refusal:?}"
        );
        assert_eq!(dispatcher.driver().semantic_calls, 1);
        assert_eq!(dispatcher.driver().per_pid_calls, 0);
    }
}

#[test]
fn intent_is_durable_before_dispatch_and_outcome_is_visible_before_return() {
    let probe = Arc::new(Mutex::new(DispatchProbe::default()));
    let storage = RecordingJournalStorage::new(probe.clone());
    let driver = RecordingDriver {
        dispatch_probe: Some(probe.clone()),
        ..RecordingDriver::default()
    };
    let request = semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap())
        .with_semantic(
            ElementResolutionResult {
                element_name: AccessibilityElementName::Identifier("element-1".into()),
                alternate_name: Some(AccessibilityElementName::RoleAndTitle {
                    role: "AXButton".into(),
                    title: "Save".into(),
                }),
                owning_process: target(),
                semantic_actions: vec![SEMANTIC_PRESS_ACTION.into()],
                unreadable_subtrees: 0,
            },
            SEMANTIC_PRESS_ACTION,
        );
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit_with_storage(storage);

    dispatcher
        .dispatch(&mut audit, audit_identity(), request)
        .expect("the handler-returned outcome is durable before success returns");

    assert!(
        probe.lock().unwrap().intent_was_durable_at_dispatch,
        "the platform driver ran before the intent reached durable storage"
    );
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], json!("finalized"));
    assert_eq!(
        decode_embedded_json(&entry["dispatch_material"]),
        json!({
            "element": {
                "matched_by": {"Identifier": "element-1"},
                "alternate_name": {
                    "RoleAndTitle": {"role": "AXButton", "title": "Save"},
                },
            },
            "action": "press",
            "grant_identity": {
                "pid": 42,
                "bundle_identity": "com.example.target",
                "process_generation_evidence": "generation-1",
            },
        })
    );
    assert_eq!(
        decode_embedded_json(&entry["completed_result"]),
        json!({"outcome": "handler_returned", "unreadable_subtrees": 0, "routes": {"skylight": 0, "public": 0}, "release_routes": {"skylight": 0, "public": 0}, "auth": "not_applicable"})
    );
    let record = audit.read_computer_audit_record(1).unwrap();
    assert_eq!(
        record.descriptor.capability,
        cerebellum_computer::audit::ComputerCapability::Type
    );
    assert_eq!(
        record.terminal_kind,
        Some(cerebellum_computer::audit::ComputerTerminalKind::FinalizedCommitted)
    );
}

#[test]
fn partial_action_tree_disclosure_reaches_caller_and_decoded_audit_entry() {
    let driver = RecordingDriver {
        semantic_result: Ok(cerebellum_computer::platform::DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: 2,
            delivery_posts_returned: 0,
            delivery_generation_verifications: 0,
        }),
        ..RecordingDriver::default()
    };
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit();

    let report = dispatcher
        .dispatch(
            &mut audit,
            audit_identity(),
            semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap()),
        )
        .expect("a unique match in the readable tree reaches its handler");

    assert_eq!(report.platform_result.unreadable_subtrees, 2);
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(
        decode_embedded_json(&entry["completed_result"]),
        json!({"outcome": "handler_returned", "unreadable_subtrees": 2, "routes": {"skylight": 0, "public": 0}, "release_routes": {"skylight": 0, "public": 0}, "auth": "not_applicable"})
    );
}

#[test]
fn a_crash_between_intent_and_outcome_remains_indeterminate_and_is_not_retried() {
    let probe = Arc::new(Mutex::new(DispatchProbe::default()));
    let storage = RecordingJournalStorage::new(probe.clone());
    let driver = RecordingDriver {
        dispatch_probe: Some(probe),
        panic_during_semantic_dispatch: true,
        ..RecordingDriver::default()
    };
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let mut audit = audit_with_storage(storage);

    let crash = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = dispatcher.dispatch(
            &mut audit,
            audit_identity(),
            semantic_request(FrozenDispatchRow::for_capability("computer.type").unwrap()),
        );
    }));
    assert!(crash.is_err(), "the fixture did not interrupt dispatch");
    assert_eq!(
        audit.read_obligation_audit(1).unwrap().lifecycle,
        LifecycleState::Dispatched
    );
    assert_eq!(dispatcher.driver().semantic_calls, 1);

    let recovery = audit.recover_active();
    assert_eq!(recovery.len(), 1);
    assert_eq!(
        recovery[0].classification,
        RecoveryClassification::ProvisionalDispatched
    );
    assert_eq!(dispatcher.driver().semantic_calls, 1);
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], json!("recovery_terminal"));
    assert_eq!(entry["classification"], json!("indeterminate"));
    assert!(entry.get("completed_result").is_none());
}

#[test]
fn a_cancelled_dispatch_is_finalized_as_cancelled() {
    let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let driver = RecordingDriver {
        cancellation_posts: Some(posts.clone()),
        ..RecordingDriver::default()
    };
    let request = DispatchRequest::new(
        FrozenDispatchRow::for_capability("computer.type").unwrap(),
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(SyntheticAction::type_text("abcde"));
    let mut audit = audit();
    let cancelled = || posts.load(std::sync::atomic::Ordering::SeqCst) >= 2;
    let refusal = Dispatcher::new(driver, &cancelled)
        .dispatch(&mut audit, audit_identity(), request)
        .unwrap_err();
    assert_eq!(
        refusal,
        DispatchError::Cancelled {
            posts_returned: 2,
            held_state: HeldStateDisposition::NoneHeld
        }
    );
    assert_eq!(audit.journal().unfinalized_dispatch_count(), 0);
    let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
        &audit.journal().export_bytes(),
    )
    .unwrap();
    assert_eq!(entry["phase"], "finalized");
    let outcome: cerebellum_computer::audit::ActuationOutcome =
        serde_json::from_value(decode_embedded_json(&entry["completed_result"])).unwrap();
    assert_eq!(
        outcome,
        cerebellum_computer::audit::ActuationOutcome::Cancelled {
            posts_returned: 2,
            held_state: HeldStateDisposition::NoneHeld
        }
    );
}

/// A gate the test closes: shut from the start, or once `after` posts have
/// returned, standing in for a call's terminal decision.
struct TestGate {
    posts: Arc<std::sync::atomic::AtomicUsize>,
    after: usize,
}

impl cerebellum_computer::dispatch::MutationGate for TestGate {
    fn begin_mutation(&self) -> bool {
        !self.stopped()
    }

    fn stopped(&self) -> bool {
        self.posts.load(std::sync::atomic::Ordering::SeqCst) >= self.after
    }
}

fn typing_request(text: &str) -> DispatchRequest {
    DispatchRequest::new(
        FrozenDispatchRow::for_capability("computer.type").unwrap(),
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element: AccessibilityElementName::identifier("element-1"),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(SyntheticAction::type_text(text))
}

#[test]
fn a_stopped_gate_commits_no_intent_and_reaches_no_platform_post() {
    let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let driver = RecordingDriver {
        cancellation_posts: Some(posts.clone()),
        ..RecordingDriver::default()
    };
    let shared = Arc::new(Mutex::new(audit()));
    let gate = Arc::new(TestGate {
        posts: posts.clone(),
        after: 0,
    });
    let mut token = cerebellum_computer::audit::AuditToken::new(shared.clone(), gate);
    let request = typing_request("abcde");
    cerebellum_computer::dispatch::reserve_actuation_ahead(&mut token, audit_identity(), &request)
        .unwrap();
    let mut dispatcher = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    );
    let refusal = dispatcher
        .dispatch(&mut token, audit_identity(), request)
        .unwrap_err();
    assert_eq!(refusal, DispatchError::DispatchStopped);
    assert_eq!(
        dispatcher.driver().per_pid_calls,
        0,
        "no platform call after stop"
    );
    assert_eq!(posts.load(std::sync::atomic::Ordering::SeqCst), 0);
    let audit = shared.lock().unwrap();
    assert_eq!(
        audit.journal().next_sequence(),
        2,
        "the reservation made ahead was the dispatch's own, not a second entry"
    );
    assert_eq!(
        audit.read_obligation_audit(1).unwrap().lifecycle,
        LifecycleState::Rejected,
        "the entry reserved ahead is closed as an action that never ran"
    );
    assert_eq!(audit.journal().unfinalized_dispatch_count(), 0);
}

#[test]
fn a_stop_between_posts_lets_no_later_post_run() {
    let posts = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let driver = RecordingDriver {
        cancellation_posts: Some(posts.clone()),
        ..RecordingDriver::default()
    };
    let shared = Arc::new(Mutex::new(audit()));
    let gate = Arc::new(TestGate {
        posts: posts.clone(),
        after: 1,
    });
    let mut token = cerebellum_computer::audit::AuditToken::new(shared.clone(), gate);
    let refusal = Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    )
    .dispatch(&mut token, audit_identity(), typing_request("abcde"))
    .unwrap_err();
    assert!(
        matches!(
            refusal,
            DispatchError::Cancelled {
                posts_returned: 1,
                ..
            }
        ),
        "{refusal:?}"
    );
    assert_eq!(
        posts.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the post in flight at the stop returned; no ordinary post followed it"
    );
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .journal()
            .unfinalized_dispatch_count(),
        0
    );
}

#[test]
fn the_token_holds_the_audit_lock_only_for_journal_steps() {
    let shared = Arc::new(Mutex::new(audit()));
    let probe = shared.clone();
    let lock_free_during_post = Arc::new(std::sync::atomic::AtomicBool::new(false));
    struct LockProbe {
        inner: RecordingDriver,
        audit: Arc<
            Mutex<ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage>>,
        >,
        seen_free: Arc<std::sync::atomic::AtomicBool>,
    }
    impl PlatformDriver for LockProbe {
        fn capability_declarations(
            &self,
            context: &CapabilityAdvertisementContext,
        ) -> Vec<CapabilityDeclaration> {
            self.inner.capability_declarations(context)
        }
        fn read_accessibility_tree(
            &mut self,
            request: AccessibilityTreeRequest,
        ) -> Result<AccessibilityTreeResult, DriverError> {
            self.inner.read_accessibility_tree(request)
        }
        fn resolve_element(
            &mut self,
            request: ElementResolutionRequest,
        ) -> Result<ElementResolutionResult, DriverError> {
            self.inner.resolve_element(request)
        }
        fn dispatch_semantic(
            &mut self,
            request: SemanticDispatchRequest,
        ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
            self.inner.dispatch_semantic(request)
        }
        fn dispatch_per_pid(
            &mut self,
            request: SyntheticDispatchRequest,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
            // Another application's journaling must be able to proceed while
            // this post is in flight.
            self.seen_free.store(
                self.audit.try_lock().is_ok(),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.inner.dispatch_per_pid(request, cancelled)
        }
        fn dispatch_global(
            &mut self,
            request: GlobalDispatchRequest,
            cancelled: &dyn Fn() -> bool,
        ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
            self.inner.dispatch_global(request, cancelled)
        }
        fn query_focus(
            &mut self,
            request: FocusQueryRequest,
        ) -> Result<FocusQueryResult, DriverError> {
            self.inner.query_focus(request)
        }
        fn fronting_snapshot(
            &mut self,
            target: &ProcessGrant,
        ) -> Result<FrontingSnapshot, DriverError> {
            self.inner.fronting_snapshot(target)
        }
        fn input_observer_liveness(&self) -> InputObserverLiveness {
            self.inner.input_observer_liveness()
        }
        fn observe_input(
            &mut self,
            request: InputObservationRequest,
        ) -> Result<InputObservationResult, DriverError> {
            self.inner.observe_input(request)
        }
        fn observe_effect(
            &mut self,
            request: EffectObservationRequest,
        ) -> Result<EffectObservationResult, DriverError> {
            self.inner.observe_effect(request)
        }
        fn verify_attendance(
            &mut self,
            request: AttendancePreconditionRequest,
        ) -> Result<AttendancePreconditionResult, DriverError> {
            self.inner.verify_attendance(request)
        }
    }
    let driver = LockProbe {
        inner: RecordingDriver {
            cancellation_posts: None,
            ..RecordingDriver::default()
        },
        audit: probe,
        seen_free: lock_free_during_post.clone(),
    };
    let mut token = cerebellum_computer::audit::AuditToken::new(
        shared.clone(),
        Arc::new(cerebellum_computer::dispatch::OpenGate),
    );
    Dispatcher::new(
        driver,
        &cerebellum_computer::platform::process_event::never_cancelled,
    )
    .dispatch(&mut token, audit_identity(), typing_request("ab"))
    .expect("the open gate admits the post");
    assert!(
        lock_free_during_post.load(std::sync::atomic::Ordering::SeqCst),
        "the audit lock was held across the platform post"
    );
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .journal()
            .unfinalized_dispatch_count(),
        0
    );
}
