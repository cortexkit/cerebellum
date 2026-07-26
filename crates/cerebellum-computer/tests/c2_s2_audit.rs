use std::collections::BTreeMap;

use cerebellum_computer::audit::{
    AttemptRole, BackgroundEscalationDescriptor, BackgroundFailureCause, ComputerAudit,
    ComputerCapability, ComputerPlaneDescriptor, ComputerTerminalKind, ConsentProvenance,
    EscalationPair, ObservationState, ReauthorizedEscalationDescriptor, TypedCaptureDispatch,
};
use cerebellum_computer::capture_custody::{
    redact_accessibility_snapshot, AccessibilityRedactionOutcome, AccessibilityRedactionPath,
    AccessibilitySchema, AccessibilitySnapshot, CaptureCustody, CaptureGrant, CaptureScope,
    CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority, PixelArtifact,
};
use cerebellum_computer::grounding::ContainmentRung;
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::{
    EffectClass, InMemoryJournalStorage, IsolationClass, JournalConfig, JournalIdentity,
    LifecycleState, ObservabilityClass, Redactor, SeverityInputs, SeverityRecord,
    ValidatedSeverityTaxonomy,
};

#[derive(Clone)]
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
        Ok(input.replace("secret", "[REDACTED]"))
    }
}

fn taxonomy() -> ValidatedSeverityTaxonomy {
    let effects = [
        EffectClass::Read,
        EffectClass::Mutate,
        EffectClass::Authorize,
    ];
    let isolations = [
        IsolationClass::ResourceScoped,
        IsolationClass::OwnerScoped,
        IsolationClass::Uncontained,
    ];
    let observations = [
        ObservabilityClass::HumanObserved,
        ObservabilityClass::HumanUnobserved,
    ];
    ValidatedSeverityTaxonomy::new(
        "computer-test-v1",
        effects.into_iter().flat_map(move |effect| {
            let isolations = isolations;
            let observations = observations;
            isolations.into_iter().flat_map(move |isolation| {
                let observations = observations;
                observations.into_iter().map(move |observation| {
                    (
                        SeverityInputs {
                            effect_class: effect,
                            isolation_class: isolation,
                            observability_class: observation,
                        },
                        SeverityRecord {
                            tier: if effect == EffectClass::Read { 1 } else { 2 },
                            credential: false,
                            financial: effect == EffectClass::Authorize,
                        },
                    )
                })
            })
        }),
    )
    .unwrap()
}

fn identity() -> JournalIdentity {
    JournalIdentity {
        principal: "prefrontal".into(),
        conversation_key: "conversation-1".into(),
        agent_project_id: "project-1".into(),
        session_kind: SessionKind::Primary,
    }
}

fn bounds() -> CustodyBounds {
    CustodyBounds {
        maximum_verification_duration_ms: 100,
        maximum_pin_lifetime_ms: 50,
        maximum_concurrently_pinned_artifacts: 4,
        maximum_total_pinned_artifact_bytes: 10_000,
        maximum_custody_attachment_bytes: 2_000,
    }
}

fn audit() -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    let mut authority = InMemoryGrantAuthority::default();
    authority.insert(CaptureGrant::new(
        "grant-1",
        CaptureScope::PerWindow,
        0,
        1_000,
    ));
    let custody = CaptureCustody::new(bounds(), authority, InMemoryCustodyStorage::new()).unwrap();
    ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        InMemoryJournalStorage::new(),
        custody,
    )
    .unwrap()
}

#[test]
fn capability_and_containment_maps_are_closed() {
    assert_eq!(ComputerCapability::ALL.len(), 8);
    assert_eq!(
        ComputerCapability::Screenshot.action_kind(),
        cerebellum_computer::platform::ActionKind::Observe
    );
    assert_eq!(
        cerebellum_computer::audit::containment_isolation_class(ContainmentRung::SemanticElement),
        IsolationClass::ResourceScoped
    );
    assert_eq!(
        cerebellum_computer::audit::containment_isolation_class(ContainmentRung::PidStructural),
        IsolationClass::OwnerScoped
    );
    assert_eq!(
        cerebellum_computer::audit::containment_isolation_class(ContainmentRung::GlobalNone),
        IsolationClass::Uncontained
    );
}

#[test]
fn preparation_refusal_reports_admitted_artifact_before_live_token() {
    let mut audit = audit();
    let handle = audit
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::SemanticElement,
                ObservationState::HumanUnobserved,
            ),
        )
        .unwrap();
    let token = audit
        .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
        .unwrap();
    assert_eq!(
        audit
            .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
            .unwrap_err()
            .cause,
        cerebellum_computer::capture_custody::CapturePrepareRefusalCause::PreparationAlreadyActive
    );
    let artifact = PixelArtifact::per_window(vec![1, 2, 3], 10, "window-1", 42, 10, 10);
    let artifact_id = audit.admit_capture(token, artifact, 10).unwrap();
    assert_eq!(
        audit
            .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
            .unwrap_err()
            .cause,
        cerebellum_computer::capture_custody::CapturePrepareRefusalCause::ArtifactAlreadyAdmitted
    );
    assert_eq!(
        audit.custody().read_artifact(&artifact_id),
        Some(vec![1, 2, 3])
    );
}

#[test]
fn terminal_closure_deletes_unpinned_artifact_but_preserves_audit_descriptor() {
    let mut audit = audit();
    let handle = audit
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::PidStructural,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();
    let token = audit
        .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
        .unwrap();
    let artifact_id = audit
        .admit_capture(
            token,
            PixelArtifact::per_window(vec![9, 8], 10, "window-1", 42, 2, 1),
            10,
        )
        .unwrap();
    audit
        .finalize_rejected(handle, b"refused".to_vec())
        .unwrap();
    assert_eq!(audit.custody().read_artifact(&artifact_id), None);
    assert!(audit.custody().capture_descriptor(&artifact_id).is_some());
    let record = audit.read_obligation_audit(handle.sequence()).unwrap();
    assert_eq!(
        record.terminal_kind.map(ComputerTerminalKind::from),
        Some(ComputerTerminalKind::RejectedCommitted)
    );
    assert!(!record.attachment_slots.is_empty());
}

#[test]
fn pin_survives_terminal_closure_until_release_and_journal_purge() {
    let mut audit = audit();
    let handle = audit
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::SemanticElement,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();
    let token = audit
        .prepare_capture(handle, CaptureScope::PerWindow, Some("grant-1".into()), 10)
        .unwrap();
    let artifact_id = audit
        .admit_capture(
            token,
            PixelArtifact {
                bytes: vec![7, 7],
                captured_at: 10,
                target_window_id: Some("window-1".into()),
                owning_process_id: Some(42),
                width_px: 2,
                height_px: 1,
                capture_scope: CaptureScope::PerWindow,
                grant_id: Some("grant-1".into()),
            },
            10,
        )
        .unwrap();
    let pin = audit
        .pin_capture(&artifact_id, Some("grant-1".into()), 40, 10)
        .unwrap();
    audit.finalize_rejected(handle, b"done".to_vec()).unwrap();
    assert_eq!(
        audit.custody().read_artifact(&artifact_id),
        Some(vec![7, 7])
    );
    audit.journal_purge();
    assert_eq!(
        audit.custody().read_artifact(&artifact_id),
        Some(vec![7, 7])
    );
    assert_eq!(
        audit.release_capture(&pin),
        cerebellum_computer::capture_custody::CaptureReleaseResult::Released
    );
    assert_eq!(audit.custody().read_artifact(&artifact_id), None);
}

#[test]
fn accessibility_path_is_atomic_when_not_selected_and_bounded_when_durable() {
    let schema =
        AccessibilitySchema::new("computer-ax-v1", ["title".to_string(), "body".to_string()]);
    let snapshot = AccessibilitySnapshot::new(
        "computer-ax-v1",
        BTreeMap::from([
            ("body".to_string(), "secret body".to_string()),
            ("title".to_string(), "safe title".to_string()),
        ]),
    );
    let not_selected = redact_accessibility_snapshot(
        snapshot.clone(),
        &schema,
        &TestRedactor,
        "redactor-v1",
        100,
        500,
        AccessibilityRedactionPath::SuccessNotSelected,
    )
    .unwrap();
    assert_eq!(
        not_selected,
        AccessibilityRedactionOutcome::SuccessNotSelected
    );
    let pending = redact_accessibility_snapshot(
        snapshot,
        &schema,
        &TestRedactor,
        "redactor-v1",
        100,
        500,
        AccessibilityRedactionPath::Durable,
    )
    .unwrap();
    let AccessibilityRedactionOutcome::PendingSuccess { envelope, .. } = pending else {
        panic!("durable path must return pending success")
    };
    assert!(String::from_utf8(envelope.redacted_snapshot_bytes)
        .unwrap()
        .contains("[REDACTED]"));
}

#[test]
fn consent_pair_verifies_digest_and_refused_escalation_has_no_successor() {
    let background = cerebellum_computer::audit::BackgroundEscalationDescriptor {
        escalation_id: "escalation-1".into(),
        attempt_role: cerebellum_computer::audit::AttemptRole::Background,
        achieved_containment_rung: ContainmentRung::PidStructural,
        background_failure_cause:
            cerebellum_computer::audit::BackgroundFailureCause::FrontingConsentRequired,
    };
    let pair = EscalationPair::refused(background).unwrap();
    assert!(pair.reauthorized.is_none());
    let provenance = cerebellum_computer::audit::ConsentProvenance::new(
        "grant-1",
        "authority-1",
        "decision-1",
        "window-1",
        10,
        20,
    )
    .unwrap();
    assert!(provenance.verify().is_ok());
}

#[test]
fn consented_escalation_retains_its_reauthorization_descriptor() {
    let background = BackgroundEscalationDescriptor {
        escalation_id: "escalation-2".into(),
        attempt_role: AttemptRole::Background,
        achieved_containment_rung: ContainmentRung::PidStructural,
        background_failure_cause: BackgroundFailureCause::PidScopeUnavailable,
    };
    let provenance =
        ConsentProvenance::new("grant-2", "authority-2", "decision-2", "window-2", 30, 40).unwrap();
    let reauthorized = ReauthorizedEscalationDescriptor {
        escalation_id: "escalation-2".into(),
        attempt_role: AttemptRole::Reauthorized,
        consent_provenance: provenance,
    };
    let pair = EscalationPair::consented(background.clone(), reauthorized.clone()).unwrap();

    assert_eq!(pair.background, background);
    assert_eq!(pair.reauthorized, Some(reauthorized));
}

#[test]
fn reduced_terminal_keeps_the_redaction_unavailable_reason() {
    let mut audit = audit();
    let handle = audit
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::SemanticElement,
                ObservationState::HumanUnobserved,
            ),
        )
        .unwrap();

    audit.finalize_redacted_failure(handle).unwrap();
    let record = audit.read_obligation_audit(handle.sequence()).unwrap();
    assert_eq!(record.lifecycle, LifecycleState::Rejected);
    assert_eq!(
        record.reason,
        Some(cerebellum_core::journal::JournalReason::RedactionUnavailable)
    );
}

#[test]
fn typed_dispatch_carries_adapter_resolved_inputs() {
    let dispatch = TypedCaptureDispatch::new(
        ComputerCapability::Click,
        ContainmentRung::GlobalNone,
        ObservationState::HumanObserved,
    );
    assert_eq!(
        dispatch.severity_inputs().isolation_class,
        IsolationClass::Uncontained
    );
}

/// A broad-grant (full-display) capture must be refused outright when its grant
/// is absent.  The gate has its own test because a broad capture is the only
/// path that can return another application's pixels, and silently degrading it
/// to a per-window capture would make the recorded scope describe something the
/// caller never asked for.
#[test]
fn broad_grant_capture_without_its_grant_is_refused() {
    let mut audit = audit();
    let handle = audit
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::GlobalNone,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();

    assert_eq!(
        audit
            .prepare_capture(handle, CaptureScope::BroadGrant, None, 10)
            .unwrap_err()
            .cause,
        cerebellum_computer::capture_custody::CapturePrepareRefusalCause::GrantAbsent
    );

    // The paired positive: the same scope with a valid broad grant is admitted,
    // so a blanket refusal cannot satisfy the case above.
    let mut authority = cerebellum_computer::capture_custody::InMemoryGrantAuthority::default();
    authority.insert(cerebellum_computer::capture_custody::CaptureGrant::new(
        "broad-1",
        CaptureScope::BroadGrant,
        0,
        1_000,
    ));
    let custody = cerebellum_computer::capture_custody::CaptureCustody::new(
        bounds(),
        authority,
        cerebellum_computer::capture_custody::InMemoryCustodyStorage::new(),
    )
    .unwrap();
    let mut granted = ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        InMemoryJournalStorage::new(),
        custody,
    )
    .unwrap();
    let handle = granted
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::GlobalNone,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();
    assert!(granted
        .prepare_capture(
            handle,
            CaptureScope::BroadGrant,
            Some("broad-1".to_string()),
            10
        )
        .is_ok());
}
