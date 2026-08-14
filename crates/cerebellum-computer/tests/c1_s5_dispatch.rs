use cerebellum_computer::dispatch::post_condition::PostCondition;
use cerebellum_computer::dispatch::{
    authorize_escalation, retry_decision, AbortReason, AttemptDisposition, AttendanceContext,
    AttendanceLease, ConsentDecision, DispatchError, DispatchPhase, DispatchRequest, Dispatcher,
    ExpectedPostCondition, FocusCheckPlan, FrozenDispatchRow, ReconciliationResult, RetryDecision,
    SeizeWatcher,
};
use cerebellum_computer::platform::containment::{
    IdentityAtomicBinding, IdentityDiscriminationRequirement, ProcessIdentityEvidence,
    ProcessIdentityObservation, ProcessIdentityPrimitive,
};
use cerebellum_computer::platform::*;
use std::collections::VecDeque;

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 42,
        bundle_identity: "com.example.target".into(),
        process_generation_evidence: "generation-1".into(),
    }
}

fn identity() -> cerebellum_computer::platform::containment::IdentityCheckEvidence {
    let primitive = ProcessIdentityPrimitive::pinned_v1()
        .with_identity_to_delivery_binding(IdentityAtomicBinding::Atomic);
    let grant = primitive
        .capture_grant(
            target(),
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
            0,
        )
        .unwrap();
    primitive.verify_for_dispatch(
        &grant,
        &ProcessIdentityObservation::new(
            42,
            "com.example.target",
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
        ),
        10,
        Some(12),
        Some(5),
        IdentityDiscriminationRequirement::GenerationDiscriminating,
    )
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

#[derive(Debug)]
struct RecordingDriver {
    semantic_result: Result<cerebellum_computer::platform::DispatchResult, DriverError>,
    effect: Result<EffectObservationResult, DriverError>,
    liveness: InputObserverLiveness,
    input: Result<InputObservationResult, DriverError>,
    focus: Result<FocusQueryResult, DriverError>,
    attendance: Result<AttendancePreconditionResult, DriverError>,
    fronting: VecDeque<FrontingSnapshot>,
    semantic_calls: usize,
    per_pid_calls: usize,
    global_calls: usize,
    effect_calls: usize,
    /// Which application each observation was asked to read.
    ///
    /// Recorded rather than counted, because an observation that ran against
    /// the wrong application returns an answer of exactly the same shape as one
    /// that ran against the right one.
    effect_targets: Vec<ProcessGrant>,
}

impl Default for RecordingDriver {
    fn default() -> Self {
        Self {
            semantic_result: Ok(cerebellum_computer::platform::DispatchResult {
                accepted_by_platform: true,
                effect_status: EffectStatus::EffectObserved,
            }),
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
            per_pid_calls: 0,
            global_calls: 0,
            effect_calls: 0,
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
        _request: SemanticDispatchRequest,
    ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
        self.semantic_calls += 1;
        self.semantic_result.clone()
    }
    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
    ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
        self.per_pid_calls += 1;
        Ok(cerebellum_computer::platform::DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
        })
    }
    fn dispatch_global(
        &mut self,
        _request: SyntheticDispatchRequest,
    ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
        self.global_calls += 1;
        Ok(cerebellum_computer::platform::DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
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
    let element = ElementResolutionResult {
        element_name: AccessibilityElementName::Identifier("element-1".into()),
        owning_process: target(),
        semantic_actions: vec!["press".into()],
    };
    DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "computer-effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
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
    .with_semantic(element, "press")
    .with_identity(identity())
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
    let mut dispatcher = Dispatcher::new(driver);
    let report = dispatcher
        .dispatch(semantic_request(
            FrozenDispatchRow::for_capability("computer.click").unwrap(),
        ))
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
fn mode_and_delivery_primitive_are_not_substituted() {
    let mut driver = RecordingDriver::default();
    let row = FrozenDispatchRow::for_capability("computer.click")
        .unwrap()
        .with_private_envelope(false);
    let request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(1, false);
    let mut dispatcher = Dispatcher::new(driver);
    assert_eq!(
        dispatcher.dispatch(request),
        Err(DispatchError::EnvelopeUnrecognized)
    );
    assert_eq!(dispatcher.driver().per_pid_calls, 0);
    assert_eq!(dispatcher.driver().global_calls, 0);

    driver = RecordingDriver::default();
    let row = FrozenDispatchRow::for_capability("computer.click")
        .unwrap()
        .with_global_cursor_movement(PermissionLiveness::Unavailable);
    let request = DispatchRequest::new(
        row,
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(1, false)
    .with_focus_plan(FocusCheckPlan::immediate(0));
    let mut dispatcher = Dispatcher::new(driver);
    assert_eq!(
        dispatcher.dispatch(request),
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
    let row = FrozenDispatchRow::for_capability("computer.click").unwrap();
    let request = DispatchRequest::new(
        row,
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(1, false)
    .with_focus_plan(FocusCheckPlan::immediate(0));
    let mut dispatcher = Dispatcher::new(driver);
    let sequence = dispatcher.dispatch_sequence([request]).unwrap();
    assert_eq!(sequence.completed.len(), 0);
    assert_eq!(
        sequence.abort.unwrap().reason,
        AbortReason::UserSeizedControl
    );
    assert_eq!(dispatcher.driver().global_calls, 0);

    let mut watcher = SeizeWatcher::new(50);
    assert!(watcher.queue_post());
    assert!(watcher.queue_post());
    watcher.abort(AbortReason::UserSeizedControl, 1, Some(2));
    assert_eq!(watcher.abort_decision().unwrap().queued_posts_cancelled, 2);
    assert!(!watcher.take_post_slot());
}

#[test]
fn coordinate_per_pid_delivery_succeeds_only_with_the_global_none_rung() {
    let row = FrozenDispatchRow::for_capability("computer.click").unwrap();
    let request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_synthetic(1, true);
    let mut dispatcher = Dispatcher::new(RecordingDriver::default());
    let report = dispatcher.dispatch(request).unwrap();
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
    let row = FrozenDispatchRow::for_capability("computer.click").unwrap();
    let valid_request = DispatchRequest::new(
        row.clone(),
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
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
    .with_synthetic(1, false);
    let mut dispatcher = Dispatcher::new(RecordingDriver::default());
    assert!(dispatcher.dispatch(valid_request).is_ok());
    assert_eq!(dispatcher.driver().per_pid_calls, 1);

    let expired_request = DispatchRequest::new(
        row,
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
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
    .with_synthetic(1, false);
    assert_eq!(
        dispatcher.dispatch(expired_request),
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
    let row = FrozenDispatchRow::for_capability("computer.click").unwrap();
    let first = DispatchRequest::new(
        row.clone(),
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(1, false)
    .with_focus_plan(FocusCheckPlan::immediate(0));
    let second = DispatchRequest::new(
        row,
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 1, 1, true),
        1,
    )
    .with_synthetic(1, false)
    .with_focus_plan(FocusCheckPlan::immediate(1));
    let mut dispatcher = Dispatcher::new(RecordingDriver::default());
    let result = dispatcher.dispatch_sequence([first, second]).unwrap();
    assert_eq!(result.completed.len(), 1);
    assert_eq!(
        result.abort.unwrap().reason,
        AbortReason::SeizeLatencyBoundExceeded
    );
    assert_eq!(dispatcher.driver().global_calls, 1);
}

#[test]
fn semantic_unavailability_uses_only_the_selected_background_primitive() {
    let driver = RecordingDriver {
        semantic_result: Err(DriverError::Unsupported("semantic")),
        ..RecordingDriver::default()
    };
    let element = ElementResolutionResult {
        element_name: AccessibilityElementName::Identifier("element-1".into()),
        owning_process: target(),
        semantic_actions: vec!["press".into()],
    };
    let request = DispatchRequest::new(
        FrozenDispatchRow::for_capability("computer.click").unwrap(),
        DispatchMode::Background,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        background_attendance(),
        0,
    )
    .with_semantic(element, "press")
    .with_synthetic(1, false);
    let mut dispatcher = Dispatcher::new(driver);
    let report = dispatcher.dispatch(request).unwrap();
    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::PerPidSynthetic
    );
    assert_eq!(dispatcher.driver().semantic_calls, 1);
    assert_eq!(dispatcher.driver().per_pid_calls, 1);
    assert_eq!(dispatcher.driver().global_calls, 0);
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
        FrozenDispatchRow::for_capability("computer.click").unwrap(),
        DispatchMode::Observed,
        target(),
        ExpectedPostCondition::new(
            "effect-v1",
            PostCondition::ElementEnabledIs {
                element_identifier: "element-1".into(),
                expected: true,
            },
        ),
        AttendanceContext::observed("conversation-1", target(), "process-1", 0, 0, true),
        0,
    )
    .with_synthetic(1, false)
    .with_focus_plan(FocusCheckPlan::immediate(0));
    let mut dispatcher = Dispatcher::new(driver);
    assert_eq!(
        dispatcher.dispatch(request),
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
    let mut dispatcher = Dispatcher::new(driver);
    let report = dispatcher
        .dispatch(semantic_request(
            FrozenDispatchRow::for_capability("computer.click").unwrap(),
        ))
        .unwrap();
    assert_eq!(report.effect.status, EffectStatus::EffectIndeterminate);
    assert_eq!(report.effect.observation_attempts, 1);
    assert_eq!(dispatcher.driver().effect_calls, 1);
}

#[test]
fn fronting_downgrade_is_a_success_with_exact_global_none_evidence() {
    let mut post = fronting(100);
    post.target_windows[0].z_order = 2;
    let driver = RecordingDriver {
        fronting: VecDeque::from([fronting(0), post]),
        ..RecordingDriver::default()
    };
    let request = semantic_request(FrozenDispatchRow::for_capability("computer.click").unwrap());
    let mut dispatcher = Dispatcher::new(driver);
    let report = dispatcher.dispatch(request).unwrap();
    assert_eq!(
        report.containment.containment_rung,
        Some(cerebellum_computer::platform::containment::ContainmentRung::GlobalNone)
    );
    assert_eq!(
        report.containment.forfeiture_reason,
        Some(cerebellum_computer::platform::containment::ContainmentForfeitureReason::FrontingDowngradeDetected)
    );
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
    let mut request =
        semantic_request(FrozenDispatchRow::for_capability("computer.click").unwrap());
    let foreign = ProcessGrant {
        pid: 99,
        bundle_identity: "com.example.other".into(),
        process_generation_evidence: "generation-9".into(),
    };
    request = request
        .with_semantic(
            ElementResolutionResult {
                element_name: AccessibilityElementName::Identifier("element-1".into()),
                owning_process: foreign,
                semantic_actions: vec!["press".into()],
            },
            "press",
        )
        .with_synthetic(1, false);

    let mut dispatcher = Dispatcher::new(RecordingDriver::default());
    let report = dispatcher.dispatch(request).unwrap();

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

/// An action the element does not advertise does not take the semantic path.
///
/// Asking an application to perform an action it never offered is asking it to
/// do something the caller invented. The lower layer refuses this too, and the
/// refusals are not redundant: this one decides which PATH is taken, and a
/// decision that reached the driver and was refused there would report a
/// semantic attempt that could never have worked.
#[test]
fn an_unadvertised_action_does_not_take_the_semantic_path() {
    let mut request =
        semantic_request(FrozenDispatchRow::for_capability("computer.click").unwrap());
    request = request
        .with_semantic(
            ElementResolutionResult {
                element_name: AccessibilityElementName::Identifier("element-1".into()),
                owning_process: target(),
                // The element offers only "press".
                semantic_actions: vec!["press".into()],
            },
            "confirm",
        )
        .with_synthetic(1, false);

    let mut dispatcher = Dispatcher::new(RecordingDriver::default());
    let report = dispatcher.dispatch(request).unwrap();

    assert_eq!(
        dispatcher.driver().semantic_calls,
        0,
        "an action the element does not advertise reached the semantic path"
    );
    assert_eq!(
        report.delivery_primitive,
        cerebellum_computer::platform::containment::DeliveryPrimitive::PerPidSynthetic
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
    let mut dispatcher = Dispatcher::new(RecordingDriver::default());
    dispatcher
        .dispatch(semantic_request(
            FrozenDispatchRow::for_capability("computer.click").unwrap(),
        ))
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
            element_identifier: "field-1".into(),
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
        },
    );
    assert_eq!(outcome, ConditionOutcome::Satisfied);
}
