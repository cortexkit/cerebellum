use std::collections::BTreeMap;

use cerebellum_computer::audit::{
    redaction::ExcludeApplicationText, ActuationElementIdentity, ActuationIntent, AttemptRole,
    BackgroundEscalationDescriptor, BackgroundFailureCause, ComputerAudit, ComputerAuditError,
    ComputerCapability, ComputerJournalCodec, ComputerPlaneDescriptor, ComputerTerminalKind,
    ConsentProvenance, EscalationPair, ObservationState, ReauthorizedEscalationDescriptor,
    TypedCaptureDispatch,
};
use cerebellum_computer::capture_custody::{
    redact_accessibility_snapshot, AccessibilityRedactionOutcome, AccessibilityRedactionPath,
    AccessibilitySchema, AccessibilitySnapshot, CaptureCustody, CaptureGrant,
    CapturePinRefusalCause, CapturePrepareRefusalCause, CaptureScope, CustodyBounds,
    InMemoryCustodyStorage, InMemoryGrantAuthority, PixelArtifact,
};
use cerebellum_computer::grounding::ContainmentRung;
use cerebellum_computer::platform::{AccessibilityElementName, ProcessGrant};
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::{
    EffectClass, InMemoryJournalStorage, IsolationClass, JournalConfig, JournalError,
    JournalIdentity, LifecycleState, ObservabilityClass, Redactor, SeverityInputs, SeverityRecord,
    ValidatedSeverityTaxonomy,
};
use serde_json::json;

#[derive(Clone)]
/// A redactor that cannot redact, to prove what happens when the policy fails.
///
/// Its counterpart always succeeds, and a suite holding only that one never
/// reaches the code that handles a refusal. That path is where an unredacted
/// value would otherwise be copied into a durable record, so the failing case
/// is the one worth constructing.
struct UnavailableRedactor;

impl Redactor for UnavailableRedactor {
    fn available(&self) -> bool {
        // Available, and unable to produce a value. The two are separate: a
        // policy can be bound and still fail on a particular input, which is
        // the case a bound check alone does not cover.
        true
    }

    fn redact(
        &self,
        _input: &str,
        _max_bytes: usize,
    ) -> Result<String, cerebellum_core::journal::RedactionUnavailable> {
        Err(cerebellum_core::journal::RedactionUnavailable)
    }
}

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

fn audit_with_redactor<R: Redactor>(
    redactor: R,
) -> ComputerAudit<R, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    let mut authority = InMemoryGrantAuthority::default();
    authority.insert(CaptureGrant::new(
        "grant-1",
        CaptureScope::PerWindow,
        0,
        1_000,
    ));
    let custody = CaptureCustody::new(bounds(), authority, InMemoryCustodyStorage::new()).unwrap();
    ComputerAudit::new(
        redactor,
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

fn audit() -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    audit_with_redactor(TestRedactor)
}

#[test]
fn capability_and_containment_maps_are_closed() {
    assert_eq!(ComputerCapability::ALL.len(), 10);
    assert_eq!(ComputerCapability::RETIRED.len(), 5);
    assert_eq!(
        ComputerCapability::ReadState.action_kind(),
        cerebellum_computer::platform::ActionKind::Observe
    );
    // A retired capability is readable from the journal and nothing else: no
    // capability id names it any more.
    for retired in ComputerCapability::RETIRED {
        assert!(retired.is_retired());
        assert_eq!(ComputerCapability::parse(retired.capability_id()), None);
    }
    for current in ComputerCapability::ALL {
        assert!(!current.is_retired());
        assert_eq!(
            ComputerCapability::parse(current.capability_id()),
            Some(current)
        );
    }
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
        Ok(Some(vec![1, 2, 3]))
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
    assert_eq!(audit.custody().read_artifact(&artifact_id), Ok(None));
    assert!(audit
        .custody()
        .capture_descriptor(&artifact_id)
        .is_ok_and(|d| d.is_some()));
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
        Ok(Some(vec![7, 7]))
    );
    audit.journal_purge();
    assert_eq!(
        audit.custody().read_artifact(&artifact_id),
        Ok(Some(vec![7, 7]))
    );
    assert_eq!(
        audit.release_capture(&pin),
        cerebellum_computer::capture_custody::CaptureReleaseResult::Released
    );
    assert_eq!(audit.custody().read_artifact(&artifact_id), Ok(None));
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
fn successful_dispatch_lifecycle_records_material_and_rejects_recommitment() {
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
    let admission = audit
        .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
        .unwrap();
    let artifact_id = audit
        .admit_capture(
            admission,
            PixelArtifact::per_window(vec![4, 5, 6], 10, "window-1", 42, 3, 1),
            10,
        )
        .unwrap();
    let dispatch = TypedCaptureDispatch::new(
        ComputerCapability::Screenshot,
        ContainmentRung::SemanticElement,
        ObservationState::HumanObserved,
    )
    .dispatch_material(b"dispatch-material".to_vec());
    let expected_severity_inputs = SeverityInputs {
        effect_class: EffectClass::Read,
        isolation_class: IsolationClass::ResourceScoped,
        observability_class: ObservabilityClass::HumanObserved,
    };

    let token = audit
        .commit_dispatched(
            handle,
            &dispatch,
            b"grant-decision".to_vec(),
            Some(b"observation-42".to_vec()),
        )
        .unwrap();
    let dispatched_record = audit.read_obligation_audit(handle.sequence()).unwrap();
    assert_eq!(dispatched_record.lifecycle, LifecycleState::Dispatched);
    assert_eq!(
        dispatched_record.severity_inputs,
        Some(expected_severity_inputs)
    );
    let dispatched_entry =
        ComputerJournalCodec::decode_entry(&audit.journal().export_bytes()).unwrap();
    assert_eq!(dispatched_entry["phase"], json!("dispatched"));
    assert_eq!(
        dispatched_entry["dispatch_material"],
        json!([100, 105, 115, 112, 97, 116, 99, 104, 45, 109, 97, 116, 101, 114, 105, 97, 108])
    );
    assert_eq!(
        dispatched_entry["severity_inputs"],
        json!({
            "effect_class": "read",
            "isolation_class": "resource_scoped",
            "observability_class": "human_observed",
        })
    );
    assert_eq!(
        dispatched_entry["grant_decision"],
        json!([103, 114, 97, 110, 116, 45, 100, 101, 99, 105, 115, 105, 111, 110])
    );
    assert_eq!(
        dispatched_entry["governing_observation"],
        json!([111, 98, 115, 101, 114, 118, 97, 116, 105, 111, 110, 45, 52, 50])
    );

    audit
        .finalize_dispatched(token, b"completed".to_vec(), b"context-42".to_vec())
        .unwrap();
    let record = audit.read_obligation_audit(handle.sequence()).unwrap();
    assert_eq!(record.lifecycle, LifecycleState::Finalized);
    assert_eq!(
        record.terminal_kind.map(ComputerTerminalKind::from),
        Some(ComputerTerminalKind::FinalizedCommitted)
    );
    assert_eq!(record.severity_inputs, Some(expected_severity_inputs));
    assert_eq!(audit.custody().read_artifact(&artifact_id), Ok(None));
    let finalized_entry =
        ComputerJournalCodec::decode_entry(&audit.journal().export_bytes()).unwrap();
    assert_eq!(finalized_entry["phase"], json!("finalized"));
    assert_eq!(
        finalized_entry["dispatch_material"],
        json!([100, 105, 115, 112, 97, 116, 99, 104, 45, 109, 97, 116, 101, 114, 105, 97, 108])
    );
    assert_eq!(
        finalized_entry["severity_inputs"],
        json!({
            "effect_class": "read",
            "isolation_class": "resource_scoped",
            "observability_class": "human_observed",
        })
    );

    assert_eq!(
        audit
            .commit_dispatched(
                handle,
                &dispatch,
                b"retry-grant".to_vec(),
                Some(b"retry-observation".to_vec()),
            )
            .unwrap_err(),
        ComputerAuditError::Journal(JournalError::ObligationUnknown)
    );
}

/// A finalized action admits no further pixels.
///
/// Capture admission is gated on the obligation still being active, and
/// finalizing is what ends that. Without it, an artifact could be attached to an
/// action whose audit record is already closed and describes a different set of
/// pixels than the ones retained.
///
/// The journal is consulted after finalization removes the local reservation
/// metadata. The resulting refusal must name the durable terminal state rather
/// than reporting the obligation as missing from the journal.
#[test]
fn a_finalized_action_admits_no_further_capture() {
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

    // The positive case uses a SEPARATE obligation. Preparing twice on one
    // obligation is refused as already-prepared, and admitting twice as
    // already-admitted, so proving the positive on the same handle would mask
    // the rule under test behind an unrelated one.
    let live = audit
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::SemanticElement,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();
    audit
        .prepare_capture(live, CaptureScope::PerWindow, None, 10)
        .expect("a live obligation admits capture");

    let dispatch = TypedCaptureDispatch::new(
        ComputerCapability::Screenshot,
        ContainmentRung::SemanticElement,
        ObservationState::HumanObserved,
    )
    .dispatch_material(b"dispatch-material".to_vec());
    let token = audit
        .commit_dispatched(handle, &dispatch, b"grant".to_vec(), None)
        .unwrap();
    audit
        .finalize_dispatched(token, b"completed".to_vec(), b"context".to_vec())
        .unwrap();

    let refusal = audit
        .prepare_capture(handle, CaptureScope::PerWindow, None, 20)
        .expect_err("a finalized action must not admit capture");
    assert_eq!(
        refusal.cause,
        CapturePrepareRefusalCause::ObligationAlreadyTerminal
    );
}

/// A handle from a different audit has no corresponding durable journal entry.
#[test]
fn an_unknown_obligation_is_distinguished_from_a_terminal_obligation() {
    let mut source = audit();
    let unknown_handle = source
        .reserve(
            identity(),
            ComputerPlaneDescriptor::new(
                ComputerCapability::Screenshot,
                ContainmentRung::SemanticElement,
                ObservationState::HumanObserved,
            ),
        )
        .unwrap();
    let mut audit = audit();

    let refusal = audit
        .prepare_capture(unknown_handle, CaptureScope::PerWindow, None, 10)
        .expect_err("an unknown obligation must not admit capture");

    assert_eq!(refusal.cause, CapturePrepareRefusalCause::ObligationUnknown);
}

/// A terminal journal record also explains why an existing artifact cannot be pinned.
#[test]
fn a_terminal_obligation_cannot_acquire_a_later_capture_pin() {
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
        .prepare_capture(handle, CaptureScope::PerWindow, None, 10)
        .unwrap();
    let artifact_id = audit
        .admit_capture(
            token,
            PixelArtifact::per_window(vec![1, 2, 3], 10, "window-1", 42, 3, 1),
            10,
        )
        .unwrap();
    audit
        .finalize_rejected(handle, b"complete".to_vec())
        .unwrap();

    let refusal = audit
        .pin_capture(&artifact_id, None, 20, 10)
        .expect_err("a terminal obligation cannot acquire a new pin");

    assert_eq!(
        refusal.cause,
        CapturePinRefusalCause::ObligationAlreadyTerminal
    );
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

/// A field that cannot be redacted refuses, and carries no input onward.
///
/// The refusal is the whole mechanism: when a policy cannot redact, the only
/// safe output is none. Copying the value through -- which is what an
/// `unwrap_or_else` here would do -- writes application text verbatim into a
/// durable record, and does it precisely when the protection was unavailable.
///
/// Asserted as an exact outcome AND as the absence of the input in the error
/// path, because a refusal that still returned the value would satisfy a check
/// that only looked at the outcome.
#[test]
fn a_field_that_cannot_be_redacted_refuses_rather_than_passing_the_value_through() {
    let schema =
        AccessibilitySchema::new("computer-ax-v1", ["title".to_string(), "body".to_string()]);
    let snapshot = AccessibilitySnapshot::new(
        "computer-ax-v1",
        BTreeMap::from([
            ("body".to_string(), "secret body".to_string()),
            ("title".to_string(), "safe title".to_string()),
        ]),
    );

    let outcome = redact_accessibility_snapshot(
        snapshot,
        &schema,
        &UnavailableRedactor,
        "redactor-v1",
        100,
        500,
        AccessibilityRedactionPath::Durable,
    );

    assert_eq!(
        outcome,
        Err(
            cerebellum_computer::capture_custody::AccessibilityRedactionError::RedactionUnavailable
        ),
        "a snapshot survived a redaction policy that could not redact"
    );
}

/// The descriptor shared by the actuation-commit tests.
fn actuation_descriptor() -> ComputerPlaneDescriptor {
    ComputerPlaneDescriptor::new(
        ComputerCapability::Click,
        ContainmentRung::SemanticElement,
        ObservationState::HumanObserved,
    )
}

fn target_grant() -> ProcessGrant {
    ProcessGrant {
        pid: 42,
        bundle_identity: "com.example.target".into(),
        process_generation_evidence: "generation-1".into(),
    }
}

/// The dispatch-material bytes of the single entry a fresh audit exports right
/// after a commit: the exact bytes the commit made durable.
///
/// The entry stores that material as a byte array, so lifting it out is the
/// only honest way to scan what reached the journal. A text search over the
/// raw export would find nothing whether or not the material was redacted,
/// because the codec never embeds it as text, and would pass vacuously.
fn committed_intent_bytes<R: Redactor>(
    audit: &ComputerAudit<R, ValidatedSeverityTaxonomy, InMemoryJournalStorage>,
) -> Vec<u8> {
    let entry = ComputerJournalCodec::decode_entry(&audit.journal().export_bytes())
        .expect("a fresh audit exports exactly one decodable entry after a commit");
    entry["dispatch_material"]
        .as_array()
        .expect("dispatch material is stored as a byte array")
        .iter()
        .map(|byte| u8::try_from(byte.as_u64().expect("a byte value")).expect("a byte value"))
        .collect()
}

/// An identifier-addressed actuation journals no application text at all.
///
/// The caller named the element by identifier, so the caller's own identifier
/// survives, but the alternate name was scraped off the screen by the plane
/// and may only survive in the form the bound redaction policy emits. Asserted
/// on the serialized entry bytes rather than the intent struct: the claim is
/// about what reaches the journal, and the two can differ.
#[test]
fn identifier_addressed_actuation_journals_no_screen_text() {
    let mut audit = audit_with_redactor(ExcludeApplicationText);
    let descriptor = actuation_descriptor();
    let handle = audit.reserve(identity(), descriptor.clone()).unwrap();
    let intent = ActuationIntent {
        element: Some(ActuationElementIdentity {
            matched_by: AccessibilityElementName::Identifier("toolbar-submit".into()),
            alternate_name: Some(AccessibilityElementName::RoleAndTitle {
                role: "Button".into(),
                title: "Save Document".into(),
            }),
        }),
        action: "press".into(),
        grant_identity: target_grant(),
    };

    audit
        .commit_actuation_intent(handle, &descriptor, &intent)
        .expect("a bound redactor admits the commit");

    let entry_text =
        String::from_utf8(committed_intent_bytes(&audit)).expect("the serialized intent is UTF-8");
    assert!(
        entry_text.contains("toolbar-submit"),
        "the caller's own identifier must survive raw: {entry_text}"
    );
    assert!(
        !entry_text.contains("Save Document"),
        "the scraped alternate title reached the journal: {entry_text}"
    );
    assert!(
        !entry_text.contains("Button"),
        "the scraped alternate role reached the journal: {entry_text}"
    );
    assert!(
        entry_text.contains("[withheld]"),
        "the alternate name was dropped instead of redacted: {entry_text}"
    );
}

/// A role+title-addressed actuation journals exactly the key the caller
/// supplied.
///
/// The caller's own phrase is the reason the record exists, so it survives raw
/// even though it is also text that appears on the screen: the words the
/// caller asked with are not the words the plane scraped. The scraped
/// alternate identifier may only survive in redacted form.
#[test]
fn role_and_title_actuation_journals_exactly_the_callers_key() {
    let mut audit = audit_with_redactor(ExcludeApplicationText);
    let descriptor = actuation_descriptor();
    let handle = audit.reserve(identity(), descriptor.clone()).unwrap();
    let intent = ActuationIntent {
        element: Some(ActuationElementIdentity {
            matched_by: AccessibilityElementName::RoleAndTitle {
                role: "Button".into(),
                title: "Print Document".into(),
            },
            alternate_name: Some(AccessibilityElementName::Identifier(
                "internal-element-42".into(),
            )),
        }),
        action: "press".into(),
        grant_identity: target_grant(),
    };

    audit
        .commit_actuation_intent(handle, &descriptor, &intent)
        .expect("a bound redactor admits the commit");

    let entry_text =
        String::from_utf8(committed_intent_bytes(&audit)).expect("the serialized intent is UTF-8");
    assert!(
        entry_text.contains("\"role\":\"Button\""),
        "the caller's role must survive exactly as supplied: {entry_text}"
    );
    assert!(
        entry_text.contains("\"title\":\"Print Document\""),
        "the caller's title must survive exactly as supplied: {entry_text}"
    );
    assert!(
        !entry_text.contains("internal-element-42"),
        "the scraped alternate identifier reached the journal: {entry_text}"
    );
    assert!(
        entry_text.contains("[withheld]"),
        "the alternate identifier was dropped instead of redacted: {entry_text}"
    );
}

/// A commit carrying scraped text refuses when the redactor cannot redact.
///
/// Fail closed, with no copy-through fallback: the intent must be durable
/// before dispatch, so refusing the commit refuses the actuation itself. An
/// action that cannot be audited safely does not happen.
#[test]
fn actuation_commit_with_scraped_text_refuses_when_redaction_is_unavailable() {
    let mut audit = audit_with_redactor(UnavailableRedactor);
    let descriptor = actuation_descriptor();
    let handle = audit.reserve(identity(), descriptor.clone()).unwrap();
    let intent = ActuationIntent {
        element: Some(ActuationElementIdentity {
            matched_by: AccessibilityElementName::Identifier("toolbar-submit".into()),
            alternate_name: Some(AccessibilityElementName::RoleAndTitle {
                role: "Button".into(),
                title: "Save Document".into(),
            }),
        }),
        action: "press".into(),
        grant_identity: target_grant(),
    };

    let error = audit
        .commit_actuation_intent(handle, &descriptor, &intent)
        .expect_err("a commit carrying scraped text must fail closed");

    assert_eq!(
        error,
        ComputerAuditError::Journal(JournalError::RedactionUnavailable)
    );
    let exported = audit.journal().export_bytes();
    assert!(
        exported.is_empty(),
        "the refused commit still left an entry behind: {exported:?}"
    );
}

/// An intent carrying no scraped text commits even when no redactor can act.
///
/// The caller's own key is never redacted, and without an alternate name there
/// is no screen text to protect, so a missing redactor must not refuse it:
/// refusing here would withhold the caller's words, which the record exists to
/// keep.
#[test]
fn actuation_commit_without_scraped_text_needs_no_redactor() {
    let descriptor = actuation_descriptor();

    let mut caller_key_audit = audit_with_redactor(UnavailableRedactor);
    let handle = caller_key_audit
        .reserve(identity(), descriptor.clone())
        .unwrap();
    let caller_key_only = ActuationIntent {
        element: Some(ActuationElementIdentity {
            matched_by: AccessibilityElementName::RoleAndTitle {
                role: "MenuItem".into(),
                title: "Print".into(),
            },
            alternate_name: None,
        }),
        action: "press".into(),
        grant_identity: target_grant(),
    };
    caller_key_audit
        .commit_actuation_intent(handle, &descriptor, &caller_key_only)
        .expect("the caller's own key needs no redactor");
    let entry_text = String::from_utf8(committed_intent_bytes(&caller_key_audit))
        .expect("the serialized intent is UTF-8");
    assert!(
        entry_text.contains("\"title\":\"Print\""),
        "the caller's title must survive raw: {entry_text}"
    );

    let mut elementless_audit = audit_with_redactor(UnavailableRedactor);
    let handle = elementless_audit
        .reserve(identity(), descriptor.clone())
        .unwrap();
    let elementless = ActuationIntent {
        element: None,
        action: "press".into(),
        grant_identity: target_grant(),
    };
    elementless_audit
        .commit_actuation_intent(handle, &descriptor, &elementless)
        .expect("an element-less intent carries nothing to redact");
    let entry_text = String::from_utf8(committed_intent_bytes(&elementless_audit))
        .expect("the serialized intent is UTF-8");
    assert!(
        entry_text.contains("\"element\":null"),
        "an element-less intent must commit as element-less: {entry_text}"
    );
}

/// A recovered actuation records uncertainty instead of claiming the press settled.
#[test]
fn crash_orphaned_actuation_is_unsettled_and_names_startup_reconciliation() {
    let mut audit = audit();
    let descriptor = actuation_descriptor();
    let handle = audit.reserve(identity(), descriptor.clone()).unwrap();
    let intent = ActuationIntent {
        element: Some(ActuationElementIdentity {
            matched_by: AccessibilityElementName::Identifier("toolbar-submit".into()),
            alternate_name: None,
        }),
        action: "press".into(),
        grant_identity: target_grant(),
    };
    audit
        .commit_actuation_intent(handle, &descriptor, &intent)
        .unwrap();

    audit.startup_reconcile(10).unwrap();

    let entry = ComputerJournalCodec::decode_entry(&audit.journal().export_bytes()).unwrap();
    assert_eq!(entry["phase"], json!("recovery_terminal"));
    assert_eq!(entry["terminal_kind"], json!("dispatch_outcome_unknown"));
    assert_eq!(entry["settled"], json!(false));
    assert_eq!(entry["settler"], json!("startup_reconciliation"));
    assert_eq!(
        audit
            .read_computer_audit_record(handle.sequence())
            .unwrap()
            .terminal_kind,
        Some(ComputerTerminalKind::DispatchOutcomeUnknown)
    );
}

/// A recovered capture remains settled because dispatch itself performed the read.
#[test]
fn crash_orphaned_capture_is_finalized_by_startup_reconciliation() {
    let mut audit = audit();
    let descriptor = ComputerPlaneDescriptor::new(
        ComputerCapability::Screenshot,
        ContainmentRung::PidStructural,
        ObservationState::HumanUnobserved,
    );
    let handle = audit.reserve(identity(), descriptor).unwrap();
    let dispatch = TypedCaptureDispatch::new(
        ComputerCapability::Screenshot,
        ContainmentRung::PidStructural,
        ObservationState::HumanUnobserved,
    )
    .dispatch_material(b"computer.screenshot".to_vec());
    audit
        .commit_dispatched(handle, &dispatch, b"lease".to_vec(), None)
        .unwrap();

    audit.startup_reconcile(10).unwrap();

    let entry = ComputerJournalCodec::decode_entry(&audit.journal().export_bytes()).unwrap();
    assert_eq!(entry["phase"], json!("recovery_terminal"));
    assert_eq!(entry["terminal_kind"], json!("recovery_dispatch_finalized"));
    assert_eq!(entry["settled"], json!(true));
    assert_eq!(entry["settler"], json!("startup_reconciliation"));
    assert_eq!(
        audit
            .read_computer_audit_record(handle.sequence())
            .unwrap()
            .terminal_kind,
        Some(ComputerTerminalKind::RecoveryDispatchFinalized)
    );
}

/// A journal written before `click` and `screenshot` were retired still loads.
///
/// The fixture is a real `computer.json`, written by the journal code as it
/// stood when both capabilities were served: a completed click, a completed
/// screenshot, and one of each that was mid-flight when the process died. The
/// descriptor inside each entry names its capability by its serialized name, so
/// deleting a retired variant would make these entries undecodable, and the
/// module would refuse to start on any machine that had ever clicked. The
/// orphaned entries matter most: startup reconciliation must decode their
/// descriptors to settle them, which is the path that fails first.
#[test]
fn a_journal_holding_retired_click_and_screenshot_entries_reconciles_at_startup() {
    const FIXTURE: &[u8] = include_bytes!("fixtures/v12_computer_journal.json");
    // A private copy per run, because reconciliation rewrites the file it
    // loaded and the checked-in fixture must stay as it was written.
    let path = std::env::temp_dir().join(format!(
        "cerebellum-retired-journal-{}-{}.json",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::write(&path, FIXTURE).unwrap();
    let custody = CaptureCustody::new(
        bounds(),
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    )
    .unwrap();
    let mut audit = ComputerAudit::new(
        ExcludeApplicationText,
        cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
        JournalConfig {
            journal_retention_bytes: 8 * 1024 * 1024,
            journal_max_entry_bytes: 64 * 1024,
        },
        cerebellum_core::journal::FilesystemJournalStorage::new(path.clone()),
        custody,
    )
    .expect("a journal holding retired capabilities binds");

    let reconciled = audit.startup_reconcile(10);
    let records: Vec<_> = (1..=4)
        .map(|sequence| audit.read_computer_audit_record(sequence))
        .collect();
    let _ = std::fs::remove_file(&path);

    reconciled.expect("startup reconciliation settles the retired entries");
    let records: Vec<_> = records
        .into_iter()
        .map(|record| record.expect("every retired entry decodes"))
        .collect();
    assert_eq!(
        records
            .iter()
            .map(|record| record.descriptor.capability)
            .collect::<Vec<_>>(),
        vec![
            ComputerCapability::Click,
            ComputerCapability::Screenshot,
            ComputerCapability::Click,
            ComputerCapability::Screenshot,
        ]
    );
    assert_eq!(
        records
            .iter()
            .map(|record| record.terminal_kind)
            .collect::<Vec<_>>(),
        vec![
            Some(ComputerTerminalKind::FinalizedCommitted),
            Some(ComputerTerminalKind::FinalizedCommitted),
            Some(ComputerTerminalKind::DispatchOutcomeUnknown),
            Some(ComputerTerminalKind::RecoveryDispatchFinalized),
        ],
        "the two orphaned entries were settled by reconciliation"
    );
}
