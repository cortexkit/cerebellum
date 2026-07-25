use cerebellum_computer::platform::containment::{
    compare_fronting, finalize_containment, ContainmentEvidence, ContainmentForfeitureReason,
    ContainmentRefusalCode, ContainmentRung, DeliveryPrimitive, FrontingReason,
    IdentityAtomicBinding, IdentityClockSemantics, IdentityDiscriminationRequirement,
    IdentityVerificationStatus, ProcessIdentityEvidence, ProcessIdentityObservation,
    ProcessIdentityPrimitive,
};
use cerebellum_computer::platform::{ActionKind, FrontingSnapshot, FrontingWindow, ProcessGrant};

fn grant() -> ProcessGrant {
    ProcessGrant {
        pid: 7,
        bundle_identity: "com.example.target".into(),
        process_generation_evidence: "generation-1".into(),
    }
}

fn snapshot(at: u64, z_order: i32) -> FrontingSnapshot {
    FrontingSnapshot {
        captured_at_ms: at,
        frontmost_application_identity: Some("com.example.other".into()),
        target_windows: vec![FrontingWindow {
            observation_window_id: "window-1".into(),
            owning_process_generation: "generation-1".into(),
            activation_state: "inactive".into(),
            z_order,
        }],
        completeness: true,
    }
}

fn identity_check(
    observed_evidence: ProcessIdentityEvidence,
    dispatch_at_ms: u64,
) -> cerebellum_computer::platform::containment::IdentityCheckEvidence {
    identity_check_with_maximum(observed_evidence, dispatch_at_ms, Some(5))
}

fn identity_check_with_maximum(
    observed_evidence: ProcessIdentityEvidence,
    dispatch_at_ms: u64,
    maximum_interval_ms: Option<u64>,
) -> cerebellum_computer::platform::containment::IdentityCheckEvidence {
    let primitive = ProcessIdentityPrimitive::pinned_v1();
    let binding = primitive
        .capture_grant(
            grant(),
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
            0,
        )
        .unwrap();
    primitive.verify_for_dispatch(
        &binding,
        &ProcessIdentityObservation::new(7, "com.example.target", observed_evidence),
        10,
        Some(dispatch_at_ms),
        maximum_interval_ms,
        IdentityDiscriminationRequirement::GenerationDiscriminating,
    )
}

#[test]
fn replacement_is_rejected_before_any_containment_rung_is_finalized() {
    let identity = identity_check(ProcessIdentityEvidence::kernel_vouched("generation-2"), 11);
    assert_eq!(identity.status, IdentityVerificationStatus::Mismatch);
    let refusal = finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        DeliveryPrimitive::PerPidSynthetic,
        false,
        Some(identity),
        None,
        true,
    ))
    .unwrap_err();
    assert_eq!(refusal.code, ContainmentRefusalCode::GrantIdentityMismatch);
}

#[test]
fn stale_identity_forfeits_structural_containment_but_can_fall_to_global_none() {
    let identity = identity_check(ProcessIdentityEvidence::kernel_vouched("generation-1"), 20);
    assert_eq!(identity.status, IdentityVerificationStatus::Stale);
    let fronting = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(100, 1)),
        0,
        100,
        100,
    );
    let result = finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        DeliveryPrimitive::PerPidSynthetic,
        false,
        Some(identity),
        Some(fronting),
        true,
    ))
    .unwrap();
    assert_eq!(result.containment_rung, Some(ContainmentRung::GlobalNone));
    assert_eq!(
        result.forfeiture_reason,
        Some(ContainmentForfeitureReason::IdentityStale)
    );
}

// When a bound is exceeded the action is not refused: dispatch continues, and
// the containment level recorded for it drops to the weaker one.  These cases
// are therefore successes rather than failures, which is why each needs its own
// test -- finalization that wrongly kept the stronger level would still return
// Ok, and the audit record would then claim the input was confined to the target
// process when it was not.  The exact reason is asserted because the audit
// record carries it, and a wrong reason is as misleading as a wrong level.
#[test]
fn identity_bound_exceeded_finalizes_global_none_with_exact_reason() {
    let mut identity = identity_check_with_maximum(
        ProcessIdentityEvidence::kernel_vouched("generation-1"),
        20,
        None,
    );
    identity.maximum_identity_check_to_dispatch_interval_ms = Some(5);
    let fronting = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(100, 1)),
        0,
        100,
        100,
    );
    let result = finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        DeliveryPrimitive::PerPidSynthetic,
        false,
        Some(identity),
        Some(fronting),
        true,
    ))
    .unwrap();
    assert_eq!(result.containment_rung, Some(ContainmentRung::GlobalNone));
    assert_eq!(
        result.forfeiture_reason,
        Some(ContainmentForfeitureReason::IdentityBoundExceeded)
    );
}

#[test]
fn identity_within_bound_finalizes_pid_structural_without_forfeiture() {
    let mut identity = identity_check_with_maximum(
        ProcessIdentityEvidence::kernel_vouched("generation-1"),
        12,
        None,
    );
    identity.maximum_identity_check_to_dispatch_interval_ms = Some(5);
    let fronting = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(100, 1)),
        0,
        100,
        100,
    );
    let result = finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        DeliveryPrimitive::PerPidSynthetic,
        false,
        Some(identity),
        Some(fronting),
        true,
    ))
    .unwrap();
    assert_eq!(
        result.containment_rung,
        Some(ContainmentRung::PidStructural)
    );
    assert_eq!(result.forfeiture_reason, None);
}

#[test]
fn fronting_bound_exceeded_finalizes_global_none_with_exact_reason() {
    let mut identity = identity_check_with_maximum(
        ProcessIdentityEvidence::kernel_vouched("generation-1"),
        12,
        None,
    );
    identity.maximum_identity_check_to_dispatch_interval_ms = Some(5);
    let mut fronting = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(100, 1)),
        0,
        100,
        100,
    );
    fronting.maximum_fronting_bracket_interval_ms = 50;
    let result = finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        DeliveryPrimitive::PerPidSynthetic,
        false,
        Some(identity),
        Some(fronting),
        true,
    ))
    .unwrap();
    assert_eq!(result.containment_rung, Some(ContainmentRung::GlobalNone));
    assert_eq!(
        result.forfeiture_reason,
        Some(ContainmentForfeitureReason::FrontingBoundExceeded)
    );
}

#[test]
fn fronting_within_bound_finalizes_pid_structural_without_forfeiture() {
    let mut identity = identity_check_with_maximum(
        ProcessIdentityEvidence::kernel_vouched("generation-1"),
        12,
        None,
    );
    identity.maximum_identity_check_to_dispatch_interval_ms = Some(5);
    let fronting = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(100, 1)),
        0,
        100,
        100,
    );
    let result = finalize_containment(ContainmentEvidence::input(
        ActionKind::Compose,
        DeliveryPrimitive::PerPidSynthetic,
        false,
        Some(identity),
        Some(fronting),
        true,
    ))
    .unwrap();
    assert_eq!(
        result.containment_rung,
        Some(ContainmentRung::PidStructural)
    );
    assert_eq!(result.forfeiture_reason, None);
}

#[test]
fn fronting_comparison_has_one_closed_state_and_bound_failures_are_indeterminate() {
    let changed = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(100, 2)),
        0,
        100,
        100,
    );
    assert_eq!(
        changed.comparison,
        cerebellum_computer::platform::FrontingComparison::DowngradeDetected
    );
    assert_eq!(changed.reasons, vec![FrontingReason::TargetWindowRaised]);

    let late = compare_fronting(
        &grant(),
        Some(snapshot(0, 1)),
        Some(snapshot(101, 1)),
        0,
        100,
        100,
    );
    assert_eq!(
        late.comparison,
        cerebellum_computer::platform::FrontingComparison::Indeterminate
    );
    assert_eq!(late.reasons, vec![FrontingReason::ComparisonUnavailable]);
}

#[test]
fn timestamp_discrimination_requires_kernel_microsecond_evidence() {
    let primitive = ProcessIdentityPrimitive::timestamp_v1(1_000, IdentityAtomicBinding::NonAtomic);
    let evidence = ProcessIdentityEvidence::timestamp_with_clock(
        1,
        10_000,
        IdentityClockSemantics::KernelSourced,
    );
    let compatibility = primitive.compatibility(
        IdentityDiscriminationRequirement::GenerationDiscriminating,
        &evidence,
    );
    assert!(!compatibility.compatible);
}

#[test]
fn non_input_action_has_no_containment_rung() {
    let result = finalize_containment(ContainmentEvidence::non_input(ActionKind::Observe)).unwrap();
    assert_eq!(result.containment_rung, None);
}

#[test]
fn delivery_binding_records_atomicity_without_claiming_non_atomic_exclusion() {
    use cerebellum_computer::platform::containment::IdentityDeliveryOutcome;

    let replacement = ProcessIdentityObservation::new(
        7,
        "com.example.target",
        ProcessIdentityEvidence::kernel_vouched("generation-2"),
    );
    let non_atomic = ProcessIdentityPrimitive::pinned_v1();
    let binding = non_atomic
        .capture_grant(
            grant(),
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
            0,
        )
        .unwrap();
    let check = non_atomic.verify(
        &binding,
        &ProcessIdentityObservation::new(
            7,
            "com.example.target",
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
        ),
        10,
        IdentityDiscriminationRequirement::GenerationDiscriminating,
    );
    let evidence = non_atomic.bind_identity_to_delivery(&binding, check, Some(&replacement), 12, 5);
    assert_eq!(
        evidence.outcome,
        IdentityDeliveryOutcome::NonAtomicReplacementObserved
    );
    assert_eq!(evidence.measured_check_to_dispatch_interval_ms, Some(2));
    assert_eq!(evidence.atomic_binding, IdentityAtomicBinding::NonAtomic);

    let atomic = ProcessIdentityPrimitive::pinned_v1()
        .with_identity_to_delivery_binding(IdentityAtomicBinding::Atomic);
    let atomic_binding = atomic
        .capture_grant(
            grant(),
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
            0,
        )
        .unwrap();
    let atomic_check = atomic.verify(
        &atomic_binding,
        &ProcessIdentityObservation::new(
            7,
            "com.example.target",
            ProcessIdentityEvidence::kernel_vouched("generation-1"),
        ),
        10,
        IdentityDiscriminationRequirement::GenerationDiscriminating,
    );
    let atomic_evidence =
        atomic.bind_identity_to_delivery(&atomic_binding, atomic_check, Some(&replacement), 12, 5);
    assert_eq!(
        atomic_evidence.outcome,
        IdentityDeliveryOutcome::ReplacementBlocked
    );
}
