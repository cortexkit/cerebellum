//! S7 acceptance tests: audit journal, redaction, snapshots, and late events.
//!
//! The journal module is implemented in `src/journal` and exposed from the crate
//! root as the public `cerebellum::journal` API. These tests use that public API
//! rather than a `#[path]` include, so the module is compiled once as live
//! library code and needs no standalone dead-code suppression.

use cerebellum::journal::late_events::{
    CommitOutcome, DeliveryRoute, LateEventError, LateEventQueue, PolicyEventPayload,
};
use cerebellum::journal::recovery::RecoveryClassification;
use cerebellum::journal::reservation::{
    CompletedResult, DispatchMaterial, FinalContextAssociation, RejectionMaterial,
};
use cerebellum::journal::snapshots::{Observation, SnapshotError, SnapshotStore};
use cerebellum::journal::store::JournalStore;
use cerebellum::journal::{
    Action, Capability, GoverningObservation, GrantDecision, GrantOutcome, HandoffJournalOutcome,
    JournalConfig, JournalEntry, JournalIdentity, JournalReasonCode, NavigateWait, Outcome,
    PolicyEventDetail, SessionKind,
};

fn identity() -> JournalIdentity {
    JournalIdentity {
        principal: "direct:agent".to_string(),
        conversation_key: "conv-1".to_string(),
        agent_project_id: "proj-1".to_string(),
        session_kind: SessionKind::Primary,
        profile_uuid: None,
        profile_name: None,
    }
}

fn store() -> JournalStore {
    JournalStore::new_in_memory(JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    })
    .unwrap()
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

#[test]
fn smoke_reserve_reject_export() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    store.finalize_rejected(handle, &rejection()).unwrap();
    assert_eq!(store.export().lines().count(), 1);
    let _ = JournalReasonCode::InternalFailure;
    let _ = CompletedResult {
        outcome: Outcome::Success,
        detail: serde_json::Value::Null,
    };
    let _ = FinalContextAssociation {
        profile_uuid: None,
        profile_name: None,
    };
}

// ---------------------------------------------------------------------------
// AC1 / AC9: full dispatched lifecycle, invocation-bound handles and tokens.
// ---------------------------------------------------------------------------

#[test]
fn dispatched_lifecycle_updates_profile_from_final_context_only() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    let token = store.commit_dispatched(handle, &dispatch()).unwrap();
    // The provisional entry is exportable and active before completion.
    let status = store.status();
    assert_eq!(status.entry_count, 1);
    assert!(store.export().contains("interrupted_after_dispatch"));

    // Completion sets profile facts from the immutable final-context
    // association, never the reservation-time association (which was null).
    store
        .finalize_dispatched(
            token,
            &FinalContextAssociation {
                profile_uuid: Some("final-uuid".to_string()),
                profile_name: Some("final-profile".to_string()),
            },
            &CompletedResult {
                outcome: Outcome::Success,
                detail: serde_json::json!({"message":"navigated"}),
            },
        )
        .unwrap();
    let export = store.export();
    assert!(export.contains("final-uuid"));
    assert!(export.contains("final-profile"));
    assert!(export.contains("\"outcome\":\"success\""));
    // Active charge released after finalization.
    assert_eq!(store.active_reserved_bytes(), 0);
}

#[test]
fn sequence_is_never_reused_across_recovery_purge_and_eviction() {
    let mut store = store();
    // seq 1: orphaned, recovered to a gap.
    let orphan = store.reserve(identity(), Capability::Navigate).unwrap();
    store.recover_one(orphan.sequence()).unwrap();
    // seq 2: finalized then purged.
    let purged = store.reserve(identity(), Capability::Navigate).unwrap();
    store.finalize_rejected(purged, &rejection()).unwrap();
    store.purge();
    // seq 3: next allocation continues strictly increasing, never reusing 1 or 2.
    assert_eq!(store.next_sequence(), 3);
    let next = store.reserve(identity(), Capability::Navigate).unwrap();
    assert_eq!(next.sequence(), 3);
}

// ---------------------------------------------------------------------------
// AC1: three-way recovery classification from durable state.
// ---------------------------------------------------------------------------

#[test]
fn recovery_classifies_orphan_failed_rejection_and_failed_commitment() {
    let mut store = store();

    // Unmarked orphan: reserved, no transition attempted.
    let orphan = store.reserve(identity(), Capability::Navigate).unwrap();
    assert_eq!(
        store.classify(orphan.sequence()),
        Some(RecoveryClassification::UnmarkedOrphan)
    );

    // Failed-rejection: marker recorded, rejection commit failed.
    let failed_rej = store.reserve(identity(), Capability::Click).unwrap();
    store.faults.arm("commit_rejection", 1);
    store
        .finalize_rejected(failed_rej, &rejection())
        .unwrap_err();
    assert_eq!(
        store.classify(failed_rej.sequence()),
        Some(RecoveryClassification::FailedRejection)
    );

    // Failed-commitment: dispatch-commitment marker, commitment failed.
    let failed_commit = store.reserve(identity(), Capability::Type).unwrap();
    store.faults.arm("commit_dispatch", 1);
    store
        .commit_dispatched(failed_commit, &dispatch())
        .unwrap_err();
    assert_eq!(
        store.classify(failed_commit.sequence()),
        Some(RecoveryClassification::FailedCommitment)
    );

    // Recovery resolves all three: orphan and failed-commitment cancel (gaps);
    // failed-rejection retries the bounded rejection.
    let outcomes = store.recover_all();
    assert_eq!(outcomes.len(), 3);
    let export = store.export();
    // Exactly one entry exported: the retried rejection.
    assert_eq!(export.lines().count(), 1);
    assert!(export.contains("rejected_pre_dispatch"));
    // No active writes remain: every reservation was resolved by recovery.
    assert_eq!(store.active_reserved_bytes(), 0);
}

// ---------------------------------------------------------------------------
// AC2: dispatch completion failure preserves the provisional entry.
// ---------------------------------------------------------------------------

#[test]
fn failed_finalization_recovery_finalizes_interrupted_after_dispatch() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    let seq = handle.sequence();
    let token = store.commit_dispatched(handle, &dispatch()).unwrap();
    // Crash before finalize_dispatched completes.
    store.faults.arm("commit_finalization", 1);
    store
        .finalize_dispatched(
            token,
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
    // Recovery preserves the unchanged provisional record.
    let outcome = store.recover_one(seq).unwrap();
    assert_eq!(
        outcome.classification,
        RecoveryClassification::ProvisionalDispatched
    );
    let export = store.export();
    assert!(export.contains("interrupted_after_dispatch"));
    assert!(!export.contains("\"outcome\":\"success\""));
    assert_eq!(store.active_reserved_bytes(), 0);
}

// ---------------------------------------------------------------------------
// AC4: exact reduced oversize paths and branch-conditioned export visibility.
// ---------------------------------------------------------------------------

#[test]
fn oversize_marker_failure_leaves_orphan_that_recovery_cancels_as_gap() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    let seq = handle.sequence();
    store.faults.arm("establish_marker", 1);
    let err = store.select_oversize_reduced(handle).unwrap_err();
    // Caller surfaces reservation_failed; oversize is never surfaced.
    assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
    assert!(store.oversize_flag());
    // The reservation is an unmarked orphan.
    assert_eq!(
        store.classify(seq),
        Some(RecoveryClassification::UnmarkedOrphan)
    );
    // Recovery cancels it after proving no commitment exists: permanent gap,
    // no entry exported.
    store.recover_one(seq).unwrap();
    assert!(store.export().is_empty());
    assert!(!store.export().contains("journal_entry_oversize"));
}

#[test]
fn oversize_post_marker_failure_is_retried_by_recovery() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    let seq = handle.sequence();
    store.faults.arm("commit_rejection", 1);
    let err = store.select_oversize_reduced(handle).unwrap_err();
    assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
    // No entry exported before recovery.
    assert!(store.export().is_empty());
    // Recovery retries the marked exact reduced rejection.
    store.recover_one(seq).unwrap();
    assert!(store.export().contains("journal_entry_oversize"));
}

// ---------------------------------------------------------------------------
// AC5: redaction-unavailable branch-conditioned export visibility.
// ---------------------------------------------------------------------------

#[test]
fn redaction_unavailable_branches_condition_export_visibility() {
    // Branch 1: marker establishment + finalization succeed => entry exported.
    {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let code = store.select_redaction_unavailable_reduced(handle).unwrap();
        assert_eq!(code, JournalReasonCode::InternalFailure);
        assert!(store.export().contains("redaction_unavailable"));
    }

    // Branch 2: marker-establishment failure => no entry, orphan for recovery.
    {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        store.faults.arm("establish_marker", 1);
        store
            .select_redaction_unavailable_reduced(handle)
            .unwrap_err();
        assert!(store.export().is_empty());
        assert_eq!(
            store.classify(seq),
            Some(RecoveryClassification::UnmarkedOrphan)
        );
    }

    // Branch 3: post-marker finalization failure => no entry until recovery.
    {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        store.faults.arm("commit_rejection", 1);
        store
            .select_redaction_unavailable_reduced(handle)
            .unwrap_err();
        assert!(store.export().is_empty());
        store.recover_one(seq).unwrap();
        assert!(store.export().contains("redaction_unavailable"));
    }
}

// ---------------------------------------------------------------------------
// AC3: snapshot retention, pins, epoch invalidation, teardown.
// ---------------------------------------------------------------------------

#[test]
fn snapshot_pin_held_until_terminal_point_then_released_exactly_once() {
    let mut snapshots = SnapshotStore::new(2).unwrap();
    snapshots
        .retain(
            "snap-1",
            Observation::Text {
                content: "redacted".to_string(),
            },
        )
        .unwrap();
    let obs = snapshots.validate_and_pin("snap-1").unwrap();
    // The governing observation carries the exact retained bytes.
    match obs.to_governing() {
        GoverningObservation::Text { bytes_utf8, .. } => assert_eq!(bytes_utf8, "redacted"),
        _ => panic!("expected text observation"),
    }
    // An epoch transition invalidates but cannot delete the pinned bytes.
    snapshots.transition_epoch(1);
    assert_eq!(snapshots.retained_count(), 1);
    // Releasing the pin at the durable terminal point deletes the invalidated
    // observation and frees the slot exactly once.
    snapshots.release_pin("snap-1");
    assert_eq!(snapshots.retained_count(), 0);
    snapshots.release_pin("snap-1"); // idempotent no-op
    assert_eq!(snapshots.retained_count(), 0);
}

#[test]
fn evicted_or_invalidated_snapshot_is_stale_and_never_dispatched() {
    let mut snapshots = SnapshotStore::new(2).unwrap();
    snapshots
        .retain(
            "snap-1",
            Observation::Text {
                content: "x".to_string(),
            },
        )
        .unwrap();
    snapshots.transition_epoch(1);
    // Prior-epoch unpinned observation deleted; validation is stale.
    assert_eq!(
        snapshots.validate_and_pin("snap-1").unwrap_err(),
        SnapshotError::StaleSnapshot
    );
}

#[test]
fn teardown_blocks_until_pins_release_then_deletes_once() {
    let mut snapshots = SnapshotStore::new(3).unwrap();
    snapshots
        .retain(
            "a",
            Observation::Text {
                content: "1".to_string(),
            },
        )
        .unwrap();
    snapshots.validate_and_pin("a").unwrap();
    snapshots.begin_teardown();
    // No new capture or pin during teardown.
    assert!(snapshots
        .retain(
            "b",
            Observation::Text {
                content: "2".to_string()
            }
        )
        .is_err());
    // Teardown cannot complete while the pin is held.
    assert!(snapshots.complete_teardown().is_err());
    snapshots.release_pin("a");
    snapshots.complete_teardown().unwrap();
    assert_eq!(snapshots.retained_count(), 0);
}

// ---------------------------------------------------------------------------
// AC7: policy events, combined-count accounting, wait_for, abandonment.
// ---------------------------------------------------------------------------

fn download_payload(route: DeliveryRoute) -> PolicyEventPayload {
    PolicyEventPayload {
        detail: PolicyEventDetail::DownloadBlocked {
            initiating_capability: None,
            initiating_snapshot_id: None,
        },
        identity: identity(),
        route,
        outcome: Outcome::InternalError,
        outcome_detail: Some(serde_json::json!({"reason_code":"internal_failure"})),
    }
}

#[test]
fn policy_event_combined_count_and_wait_for_sequence_order() {
    let mut store = store();
    let mut queue = LateEventQueue::new(8).unwrap();

    // Two committed route-wait events hold one charge each.
    for _ in 0..2 {
        let payload = queue.admit(download_payload(DeliveryRoute::Wait)).unwrap();
        assert_eq!(
            queue.commit(&mut store, payload).unwrap(),
            CommitOutcome::Wait
        );
    }
    assert_eq!(queue.combined_count(), 2);

    // wait_for delivers the lowest sequence; confirmation releases its charge.
    let first = queue.wait_for(&mut store).unwrap();
    assert!(queue.confirm_wait_delivery(first.sequence));
    assert_eq!(queue.combined_count(), 1);
    let second = queue.wait_for(&mut store).unwrap();
    assert!(second.sequence > first.sequence);
    assert!(queue.confirm_wait_delivery(second.sequence));
    assert_eq!(queue.combined_count(), 0);
    // No more items: backpressure.
    assert!(queue.wait_for(&mut store).is_err());
}

#[test]
fn policy_event_obligation_recovery_and_abandonment_gap() {
    let mut store = store();
    let mut queue = LateEventQueue::new(8).unwrap();

    // A failed commitment creates an uncommitted obligation (audit-failed).
    let payload = queue.admit(download_payload(DeliveryRoute::Wait)).unwrap();
    store.faults.arm("commit_policy_event", 1);
    queue.commit(&mut store, payload).unwrap_err();
    assert!(queue.is_audit_failed());
    assert!(queue.audit_suspension_active());

    // Live-session recovery commits it exactly once at the original sequence.
    let seq_before = store.next_sequence();
    queue.recover_obligations(&mut store);
    assert!(!queue.is_audit_failed());
    assert_eq!(store.next_sequence(), seq_before);
    assert_eq!(queue.wait_item_count(), 1);

    // A second obligation abandoned on teardown leaves a permanent gap.
    let payload = queue
        .admit(download_payload(DeliveryRoute::Direct))
        .unwrap();
    store.faults.arm("commit_policy_event", 1);
    queue.commit(&mut store, payload).unwrap_err();
    assert_eq!(queue.obligation_count(), 1);
    queue.abandon_on_teardown();
    assert_eq!(queue.obligation_count(), 0);
    assert_eq!(queue.combined_count(), 1); // the surviving wait item
}

#[test]
fn policy_event_queue_saturation_creates_no_sequence_or_gap() {
    let mut store = store();
    let mut queue = LateEventQueue::new(1).unwrap();
    // A committed route-wait event holds its charge as a delivery item, so the
    // combined count stays at the bound.
    let payload = queue.admit(download_payload(DeliveryRoute::Wait)).unwrap();
    queue.commit(&mut store, payload).unwrap();
    assert_eq!(queue.combined_count(), 1);
    // At the bound: refused without sequence or gap.
    assert_eq!(
        queue
            .admit(download_payload(DeliveryRoute::Direct))
            .unwrap_err(),
        LateEventError::QueueFull
    );
    assert_eq!(store.next_sequence(), 2); // only the one committed event
}

// ---------------------------------------------------------------------------
// AC4 / AC8: retention eviction, purge, and status consistency.
// ---------------------------------------------------------------------------

#[test]
fn status_retained_bytes_includes_active_reserved_bytes() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    store.finalize_rejected(handle, &rejection()).unwrap();
    let active = store.reserve(identity(), Capability::Click).unwrap();
    let status = store.status();
    // retained_bytes already includes active_reserved_bytes; clients must not
    // sum the two.
    assert!(status.retained_bytes >= status.active_reserved_bytes);
    assert_eq!(status.active_reservation_count, 1);
    assert!(status.retained_bytes > 0);
    let _ = active;
}

#[test]
fn purge_clears_oversize_flag_and_reports_only_finalized_entries() {
    let mut store = store();
    let handle = store.reserve(identity(), Capability::Navigate).unwrap();
    store.select_oversize_reduced(handle).unwrap();
    assert!(store.oversize_flag());
    let report = store.purge();
    assert_eq!(report.purged_entry_count, 1);
    assert!(!store.oversize_flag());
    assert!(store.export().is_empty());
    // The allocator is not reset by purge.
    assert_eq!(store.next_sequence(), 2);
}

/// Every browser capability records under its own name, and no two collapse.
///
/// Three observations used to fold onto Navigate, so a snapshot of a page in a
/// durable profile persisted as `browser.navigate` — a read recorded as a page
/// load. That is worse than not recording it at all: an absent entry is honest
/// about being absent, while a wrong one is read as authoritative, and this
/// journal directory is enrolled for fleet backup, so a wrong record is
/// permanent.
///
/// The expected names are literals rather than derived from the enum, because
/// deriving them would let a mapping change satisfy the test by moving both
/// sides at once.
#[test]
fn no_two_browser_capabilities_share_a_journal_name() {
    use cerebellum::journal::Capability;

    let expected = [
        (Capability::Navigate, "browser.navigate"),
        (Capability::Click, "browser.click"),
        (Capability::Type, "browser.type"),
        (Capability::ClickPoint, "browser.click_point"),
        (Capability::Snapshot, "browser.snapshot"),
        (Capability::Screenshot, "browser.screenshot"),
        (Capability::WaitFor, "browser.wait_for"),
        (Capability::Present, "browser.present"),
    ];

    let mut seen = std::collections::BTreeSet::new();
    for (capability, name) in expected {
        assert_eq!(capability.as_str(), name);
        assert!(
            seen.insert(name),
            "{name} is claimed by more than one capability"
        );
    }
    assert_eq!(seen.len(), 8, "a capability was added without a name here");
}

#[test]
fn v3_fixture_reads_through_the_v4_reader() {
    let fixture = include_str!("fixtures/browser-journal-v3.jsonl");
    let entry: JournalEntry = serde_json::from_str(fixture.trim()).unwrap();
    assert_eq!(entry.format_version, "ck-browser-journal/v3");
    assert_eq!(entry.capability, Some(Capability::Snapshot));
    assert!(entry.payload.is_none());
}

#[test]
fn handoff_records_carry_a_count_and_no_names() {
    let mut journal = store();
    journal
        .commit_handoff(
            identity(),
            "https://login.example".to_string(),
            HandoffJournalOutcome::Opened,
            None,
        )
        .unwrap();
    journal
        .commit_handoff(
            identity(),
            "https://login.example".to_string(),
            HandoffJournalOutcome::LoginObserved,
            Some(2),
        )
        .unwrap();

    let entries = journal
        .export()
        .lines()
        .map(|line| serde_json::from_str::<JournalEntry>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(entries.len(), 2);
    assert!(entries.iter().all(|entry| {
        entry.format_version == "ck-browser-journal/v4"
            && entry.capability == Some(Capability::Present)
            && entry.action.is_none()
    }));
    let opened = entries[0].payload.as_ref().unwrap();
    assert_eq!(opened.outcome, HandoffJournalOutcome::Opened);
    assert_eq!(opened.cookie_names_added, None);
    let closed = entries[1].payload.as_ref().unwrap();
    assert_eq!(closed.outcome, HandoffJournalOutcome::LoginObserved);
    assert_eq!(closed.cookie_names_added, Some(2));
    let serialized = journal.export();
    assert!(!serialized.contains("session_cookie"));
    assert!(!serialized.contains("csrf_cookie"));
}
