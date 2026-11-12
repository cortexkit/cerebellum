//! S10 acceptance tests: the invocation-bound journal pin and B2B association
//! seam.
//!
//! Each safety test is non-vacuous: it asserts a concrete journal-state or
//! seam-state consequence that would not hold if the mechanism under test were
//! removed (not merely that an error was returned).

use cerebellum::journal::recovery::RecoveryAction;
use cerebellum::journal::reservation::{
    CompletedResult, DispatchMaterial, FinalContextAssociation, RejectionMaterial,
};
use cerebellum::journal::store::JournalStore;
use cerebellum::journal::{
    Action, Capability, GoverningObservation, GrantDecision, GrantOutcome, JournalConfig,
    JournalReasonCode, NavigateWait, Outcome, SessionKind,
};
use cerebellum::journal_pin::{
    AbortOutcome, CurrentOpenFacts, CurrentOpenPublication, FactProvenance, JournalPin,
    PreparedOpenRef, SeamViolation, StampedBindFacts,
};
use cerebellum_core::dispatch_witness::with_fixture_dispatch_witness;

fn store() -> JournalStore {
    JournalStore::new_in_memory(JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    })
    .unwrap()
}

fn pin() -> JournalPin {
    JournalPin::new(store())
}

fn bind_facts() -> StampedBindFacts {
    StampedBindFacts {
        principal: "direct:agent".to_string(),
        conversation_key: "conv-1".to_string(),
        agent_project_id: "proj-1".to_string(),
        session_kind: SessionKind::Primary,
        provenance: FactProvenance::DaemonAttested,
    }
}

fn publication() -> CurrentOpenPublication {
    CurrentOpenPublication {
        facts: CurrentOpenFacts {
            profile_uuid: None,
            profile_name: None,
            association_epoch: 1,
            valid: true,
        },
        current_association_epoch: 1,
    }
}

fn rejection() -> RejectionMaterial {
    RejectionMaterial {
        intent_redacted: None,
        requested_severity: None,
        effective_severity: None,
        grant_decision: GrantDecision::not_reached(),
        governing_observation: GoverningObservation::observation_not_required(),
        action: None,
        locator: None,
        snapshot_ids: vec![],
        outcome: Outcome::Denied,
        detail: serde_json::json!({"message":"denied"}),
    }
}

fn dispatch() -> DispatchMaterial {
    DispatchMaterial {
        intent_redacted: None,
        requested_severity: None,
        effective_severity: None,
        grant_decision: GrantDecision {
            outcome: GrantOutcome::Allowed,
            reason: None,
        },
        action: Some(Action::Navigate {
            url_redacted: "https://example.com".to_string(),
            wait: NavigateWait::Settle,
        }),
        locator: None,
        snapshot_ids: vec![],
        governing_observation: GoverningObservation::no_prior_observation(),
    }
}

// ---------------------------------------------------------------------------
// Required: a cross-invocation transition call leaves zero journal mutation.
// ---------------------------------------------------------------------------

#[test]
fn cross_invocation_transition_leaves_journal_byte_identical() {
    let mut pin = pin();
    let inv_a = pin.mint_invocation();
    let inv_b = pin.mint_invocation();
    let handle_a = with_fixture_dispatch_witness(|| {
        pin.reserve(inv_a, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();
    let token_a = pin.commit_dispatched(inv_a, handle_a, &dispatch()).unwrap();

    // The journal is non-empty (a provisional dispatched entry is exportable).
    let before = pin.export();
    assert!(!before.is_empty());

    // Invocation B attempts every transition on A's handle with byte-identical
    // material. Each must fail closed and leave the journal byte-identical: no
    // marker, no mutation. Without the invocation-ownership preflight, S7's
    // per-sequence idempotence would let B's commit_dispatched and
    // finalize_dispatched succeed and mutate the journal.
    let err = pin
        .finalize_rejected(inv_b, handle_a, &rejection())
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    assert_eq!(
        pin.export(),
        before,
        "cross-invocation finalize_rejected mutated the journal"
    );

    let err = pin
        .commit_dispatched(inv_b, handle_a, &dispatch())
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    assert_eq!(
        pin.export(),
        before,
        "cross-invocation commit_dispatched mutated the journal"
    );

    let err = pin
        .finalize_dispatched(
            inv_b,
            token_a,
            &FinalContextAssociation {
                profile_uuid: None,
                profile_name: None,
            },
            &CompletedResult {
                outcome: Outcome::Success,
                detail: serde_json::json!({"message":"ok"}),
            },
        )
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    assert_eq!(
        pin.export(),
        before,
        "cross-invocation finalize_dispatched mutated the journal"
    );

    // The rightful invocation is unaffected by B's rejected attempts and can
    // still finalize the dispatched result.
    pin.finalize_dispatched(
        inv_a,
        token_a,
        &FinalContextAssociation {
            profile_uuid: None,
            profile_name: None,
        },
        &CompletedResult {
            outcome: Outcome::Success,
            detail: serde_json::json!({"message":"ok"}),
        },
    )
    .unwrap();
    assert!(pin.export().contains("\"outcome\":\"success\""));
}

// ---------------------------------------------------------------------------
// Required: a post-preflight reservation failure blocks every later
// invocation-side transition.
// ---------------------------------------------------------------------------

#[test]
fn post_preflight_reservation_failure_blocks_every_later_transition() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();

    // A post-preflight marker-establishment failure returns
    // journal_reservation_failed and leaves an UNMARKED orphan. The S7 substrate
    // alone would still admit a caller retry here (the reservation carries no
    // marker), so the pin's post-preflight lock is what prohibits every later
    // invocation-side transition.
    pin.store_mut().faults.arm("establish_marker", 1);
    let err = pin
        .finalize_rejected(inv, handle, &rejection())
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);

    // Every later invocation-side transition is prohibited, including a
    // byte-identical retry of the attempted transition.
    let err = pin
        .finalize_rejected(inv, handle, &rejection())
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    let err = pin.commit_dispatched(inv, handle, &dispatch()).unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);

    // S7 writer recovery exclusively owns the reservation: it cancels the
    // unmarked orphan after proving no commitment exists, exporting no entry.
    let outcome = pin.store_mut().recover_one(handle.sequence()).unwrap();
    assert_eq!(outcome.action, RecoveryAction::Cancelled);
    assert!(pin.export().is_empty());
}

#[test]
fn post_preflight_marked_commit_failure_also_locks_invocation_side() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();

    // The dispatch-commitment marker is established but the commit fails.
    pin.store_mut().faults.arm("commit_dispatch", 1);
    let err = pin.commit_dispatched(inv, handle, &dispatch()).unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);

    // The invocation side may perform no further transition.
    let err = pin.commit_dispatched(inv, handle, &dispatch()).unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    let err = pin
        .finalize_rejected(inv, handle, &rejection())
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);

    // Recovery cancels the failed commitment (never retried as a commitment).
    let outcome = pin.store_mut().recover_one(handle.sequence()).unwrap();
    assert_eq!(outcome.action, RecoveryAction::Cancelled);
}

// ---------------------------------------------------------------------------
// Strict bind-fact and current-open validation precede reserve.
// ---------------------------------------------------------------------------

#[test]
fn strict_bind_fact_failure_allocates_no_sequence() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let next_before = pin.store().next_sequence();

    // Compatibility-derived provenance is ineligible for a B2A-enabled route.
    let mut facts = bind_facts();
    facts.provenance = FactProvenance::CompatibilityDerived;
    let err = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &facts, &publication())
    })
    .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    // No sequence was allocated and no journal mutation occurred.
    assert_eq!(pin.store().next_sequence(), next_before);
    assert!(pin.export().is_empty());

    // An absent required fact (no project_root fallback) fails the same way.
    let mut facts = bind_facts();
    facts.agent_project_id = String::new();
    let err = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &facts, &publication())
    })
    .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    assert_eq!(pin.store().next_sequence(), next_before);
}

#[test]
fn stale_current_open_association_fails_before_allocation() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let next_before = pin.store().next_sequence();

    // The tuple's association_epoch does not match the session's current
    // association epoch published on the same channel: stale.
    let mut stale = publication();
    stale.facts.association_epoch = 5;
    stale.current_association_epoch = 6;
    let err = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &stale)
    })
    .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    assert_eq!(pin.store().next_sequence(), next_before);

    // An invalid association fails the same way.
    let mut invalid = publication();
    invalid.facts.valid = false;
    let err = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &invalid)
    })
    .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    assert_eq!(pin.store().next_sequence(), next_before);
}

#[test]
fn corrected_valid_call_allowed_for_rightful_active_invocation() {
    let mut pin = pin();
    let inv_a = pin.mint_invocation();
    let inv_b = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv_a, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();

    // B's cross-invocation attempt fails closed with no mutation, leaving the
    // reservation still active for its rightful invocation.
    pin.finalize_rejected(inv_b, handle, &rejection())
        .unwrap_err();
    // A (the rightful still-active invocation) finalizes before any no-commit
    // completion decision.
    pin.finalize_rejected(inv_a, handle, &rejection()).unwrap();
    // After the no-commit completion, A may no longer dispatch the reservation.
    let err = pin
        .commit_dispatched(inv_a, handle, &dispatch())
        .unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
}

// ---------------------------------------------------------------------------
// Association seam: launch ordering, final-context equality, abort attempts.
// ---------------------------------------------------------------------------

#[test]
fn launch_is_rejected_before_matching_commitment() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();

    // A launch before any durable commitment is a violation and is not observed.
    let err = pin.observe_launch(inv, handle).unwrap_err();
    assert_eq!(
        err,
        SeamViolation::LaunchWithoutCommitment {
            sequence: handle.sequence()
        }
    );
    assert!(!pin.seam().is_launched(handle.sequence()));

    // After the matching commitment, the same launch is observed.
    pin.commit_dispatched(inv, handle, &dispatch()).unwrap();
    pin.observe_launch(inv, handle).unwrap();
    assert!(pin.seam().is_launched(handle.sequence()));
}

#[test]
fn final_context_equals_journal_profile_facts() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();
    let token = pin.commit_dispatched(inv, handle, &dispatch()).unwrap();
    let final_context = FinalContextAssociation {
        profile_uuid: Some("final-uuid".to_string()),
        profile_name: Some("final-profile".to_string()),
    };
    pin.finalize_dispatched(
        inv,
        token,
        &final_context,
        &CompletedResult {
            outcome: Outcome::Success,
            detail: serde_json::json!({"message":"navigated"}),
        },
    )
    .unwrap();

    // The seam recorded the immutable token-bound final-context association.
    assert_eq!(
        pin.seam().final_context(handle.sequence()),
        Some(&final_context)
    );
    // The journal profile facts equal the final-context facts (the same object
    // B1 forms the completed result context from).
    let export = pin.export();
    assert!(export.contains("final-uuid"));
    assert!(export.contains("final-profile"));
}

#[test]
fn exactly_one_abort_attempt_per_associated_no_commit_invocation() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();

    // Associate an opaque prepared-open reference (idempotent when repeated).
    pin.associate_prepared_open(inv, handle, PreparedOpenRef("prep-1".to_string()))
        .unwrap();
    pin.associate_prepared_open(inv, handle, PreparedOpenRef("prep-1".to_string()))
        .unwrap();
    // A different reference fails closed.
    let err = pin
        .associate_prepared_open(inv, handle, PreparedOpenRef("prep-2".to_string()))
        .unwrap_err();
    assert_eq!(
        err,
        SeamViolation::ConflictingPreparedOpen {
            sequence: handle.sequence()
        }
    );

    // A no-commit completion: finalize a rejection.
    pin.finalize_rejected(inv, handle, &rejection()).unwrap();

    // Record the abort outcome once; byte-identical recording is idempotent.
    pin.record_abort_outcome(inv, handle, AbortOutcome::Completed)
        .unwrap();
    assert_eq!(pin.seam().abort_attempt_count(handle.sequence()), 1);
    pin.record_abort_outcome(inv, handle, AbortOutcome::Completed)
        .unwrap();
    assert_eq!(pin.seam().abort_attempt_count(handle.sequence()), 1);

    // A conflicting outcome is rejected; still exactly one logical attempt.
    let err = pin
        .record_abort_outcome(inv, handle, AbortOutcome::Failed)
        .unwrap_err();
    assert_eq!(
        err,
        SeamViolation::ConflictingAbortOutcome {
            sequence: handle.sequence()
        }
    );
    assert_eq!(pin.seam().abort_attempt_count(handle.sequence()), 1);
}

#[test]
fn abort_outcome_requires_a_no_commit_completion() {
    let mut pin = pin();
    let inv = pin.mint_invocation();
    let handle = with_fixture_dispatch_witness(|| {
        pin.reserve(inv, Capability::Navigate, &bind_facts(), &publication())
    })
    .unwrap();
    pin.associate_prepared_open(inv, handle, PreparedOpenRef("prep-1".to_string()))
        .unwrap();

    // The reservation is still active (no no-commit completion yet): recording
    // an abort outcome is premature and fails closed.
    let err = pin
        .record_abort_outcome(inv, handle, AbortOutcome::Completed)
        .unwrap_err();
    assert_eq!(
        err,
        SeamViolation::ConflictingAbortOutcome {
            sequence: handle.sequence()
        }
    );
    assert_eq!(pin.seam().abort_attempt_count(handle.sequence()), 0);
}
