//! Live-process and startup writer recovery.
//!
//! After a failed marked journal transition, the invocation-side caller performs
//! no further transition; B2A writer recovery exclusively owns retry or
//! cancellation. Recovery distinguishes an orphaned reservation abandoned before
//! any finalization attempt from a reservation whose rejection finalization or
//! dispatch commitment failed, using the durable transition-attempt marker.
//!
//! Classification of an unresolved pre-dispatch reservation:
//! - **unmarked orphan** — no marker; cancelled only after durable proof that no
//!   dispatch commitment or durable rejection exists.
//! - **failed-rejection** — a normal or exact-reduced rejection marker; recovery
//!   retries the bounded rejection when its material remains durably available
//!   and otherwise cancels.
//! - **failed-commitment** — a dispatch-commitment marker; recovery proves no
//!   commitment exists and cancels. It never retries or replaces a commitment.
//!
//! A provisional dispatched entry is preserved unchanged and finalized as the
//! `interrupted_after_dispatch` recovery record before its unused capacity is
//! released. Cancellation exports no entry and leaves a permanent sequence gap.

use crate::journal::store::{JournalStore, ReservationState, TransitionMarker};

/// How recovery classifies an unresolved pre-dispatch reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryClassification {
    /// No transition-attempt marker: abandoned before any finalization attempt.
    UnmarkedOrphan,
    /// A normal or exact-reduced rejection marker whose transition failed.
    FailedRejection,
    /// A dispatch-commitment marker whose transition failed.
    FailedCommitment,
    /// A provisional dispatched entry left unfinished.
    ProvisionalDispatched,
}

/// The durable outcome of recovering one reservation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Cancelled: capacity released, no entry exported, permanent sequence gap.
    Cancelled,
    /// A bounded rejection was retried and durably committed at the sequence.
    RejectionCommitted,
    /// A provisional dispatched entry was finalized unchanged as the
    /// `interrupted_after_dispatch` recovery record.
    DispatchFinalized,
}

/// A per-sequence recovery result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RecoveryOutcome {
    pub sequence: u64,
    pub classification: RecoveryClassification,
    pub action: RecoveryAction,
}

impl JournalStore {
    /// Classify an unresolved active reservation from durable state.
    pub fn classify(&self, sequence: u64) -> Option<RecoveryClassification> {
        let record = self.reservation(sequence)?;
        if record.state == ReservationState::Dispatched {
            return Some(RecoveryClassification::ProvisionalDispatched);
        }
        match &record.marker {
            None => Some(RecoveryClassification::UnmarkedOrphan),
            Some(TransitionMarker::NormalRejection { .. }) => {
                Some(RecoveryClassification::FailedRejection)
            }
            Some(TransitionMarker::ExactReduced { .. }) => {
                Some(RecoveryClassification::FailedRejection)
            }
            Some(TransitionMarker::DispatchCommitment) => {
                Some(RecoveryClassification::FailedCommitment)
            }
        }
    }

    /// Recover one active reservation.
    ///
    /// Recovery is deterministic from durable state and never consults caller
    /// material or later bind/profile state.
    pub fn recover_one(&mut self, sequence: u64) -> Option<RecoveryOutcome> {
        let classification = self.classify(sequence)?;
        let action = match classification {
            RecoveryClassification::ProvisionalDispatched => {
                self.finalize_provisional_unchanged(sequence)
            }
            RecoveryClassification::UnmarkedOrphan => self.cancel_orphan(sequence),
            RecoveryClassification::FailedCommitment => self.cancel_failed_commitment(sequence),
            RecoveryClassification::FailedRejection => self.retry_or_cancel_rejection(sequence),
        };
        Some(RecoveryOutcome {
            sequence,
            classification,
            action,
        })
    }

    /// Recover every active reservation in ascending sequence order.
    ///
    /// Used both by live-process writer recovery (scheduled immediately after a
    /// marked failure) and by startup recovery (which never resurrects an
    /// abandoned policy-event obligation).
    pub fn recover_all(&mut self) -> Vec<RecoveryOutcome> {
        let sequences = self.active_sequences();
        let mut outcomes = Vec::new();
        for seq in sequences {
            if let Some(outcome) = self.recover_one(seq) {
                outcomes.push(outcome);
            }
        }
        outcomes
    }

    /// Finalize a provisional dispatched entry unchanged as the
    /// `interrupted_after_dispatch` recovery record, then release unused
    /// capacity. The entry content is not modified.
    fn finalize_provisional_unchanged(&mut self, sequence: u64) -> RecoveryAction {
        let provisional = self
            .reservation(sequence)
            .and_then(|r| r.provisional.clone());
        if let Some(entry) = provisional {
            // Insert unchanged; accounting switches to the actual size and the
            // establishment-time charge is released.
            if self.insert_finalized(entry).is_ok() {
                return RecoveryAction::DispatchFinalized;
            }
        }
        // Integrity failure: the provisional representation could not be
        // finalized. Cancel without exporting a fabricated entry.
        self.cancel_reservation(sequence);
        RecoveryAction::Cancelled
    }

    /// Cancel an unmarked orphan after durable proof that no dispatch commitment
    /// or durable rejection exists.
    fn cancel_orphan(&mut self, sequence: u64) -> RecoveryAction {
        if self.proven_no_commitment_or_rejection(sequence) {
            self.cancel_reservation(sequence);
        }
        RecoveryAction::Cancelled
    }

    /// Cancel a failed dispatch commitment after proving no commitment exists.
    /// Recovery never retries or replaces a commitment.
    fn cancel_failed_commitment(&mut self, sequence: u64) -> RecoveryAction {
        if self.proven_no_commitment_or_rejection(sequence) {
            self.cancel_reservation(sequence);
        }
        RecoveryAction::Cancelled
    }

    /// Retry a marked normal or exact-reduced rejection when its bounded
    /// material remains durably available; otherwise cancel.
    fn retry_or_cancel_rejection(&mut self, sequence: u64) -> RecoveryAction {
        let marker = self.reservation(sequence).and_then(|r| r.marker.clone());
        let bounded = match marker {
            Some(TransitionMarker::NormalRejection { rejection }) => rejection.map(|b| *b),
            Some(TransitionMarker::ExactReduced { entry, .. }) => Some(*entry),
            _ => None,
        };
        match bounded {
            Some(entry) if self.proven_no_commitment_or_rejection(sequence) => {
                if self.insert_finalized(entry).is_ok() {
                    RecoveryAction::RejectionCommitted
                } else {
                    // Bounded material is not durably committable (integrity
                    // failure): cancel without exporting a fabricated entry.
                    self.cancel_reservation(sequence);
                    RecoveryAction::Cancelled
                }
            }
            _ => {
                // No durable bounded material (normal rejection without
                // material) or a commitment/rejection already exists: cancel.
                if self.proven_no_commitment_or_rejection(sequence) {
                    self.cancel_reservation(sequence);
                }
                RecoveryAction::Cancelled
            }
        }
    }

    /// Durable proof that neither a dispatch commitment nor a durable rejection
    /// already exists for `sequence`.
    ///
    /// A successful dispatch commitment moves the reservation to the
    /// `Dispatched` state with a provisional entry, and a successful rejection
    /// places a finalized entry at the sequence; an active pre-dispatch
    /// reservation with neither is therefore uncommitted.
    fn proven_no_commitment_or_rejection(&self, sequence: u64) -> bool {
        if self.entry(sequence).is_some() {
            return false;
        }
        match self.reservation(sequence) {
            Some(record) => {
                record.state == ReservationState::ActivePreDispatch && record.provisional.is_none()
            }
            // No reservation at all: nothing committed.
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::reservation::{
        DispatchMaterial, FinalContextAssociation, RejectionMaterial,
    };
    use crate::journal::{
        Action, Capability, GoverningObservation, GrantDecision, JournalConfig, JournalIdentity,
        JournalReasonCode, Outcome, SessionKind,
    };

    fn identity() -> JournalIdentity {
        JournalIdentity {
            principal: "direct:agent".to_string(),
            conversation_key: "conv".to_string(),
            agent_project_id: "proj".to_string(),
            session_kind: SessionKind::Primary,
            profile_uuid: None,
            profile_name: None,
        }
    }

    fn store() -> JournalStore {
        JournalStore::new(JournalConfig {
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
            grant_decision: GrantDecision::not_reached(),
            action: Action::Navigate {
                url_redacted: "https://example.com".to_string(),
                wait: crate::journal::NavigateWait::Settle,
            },
            locator: None,
            snapshot_ids: vec![],
            governing_observation: GoverningObservation::no_prior_observation(),
        }
    }

    #[test]
    fn unmarked_orphan_is_cancelled_leaving_a_gap() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        // No transition attempted: the reservation is an unmarked orphan.
        assert_eq!(
            store.classify(seq),
            Some(RecoveryClassification::UnmarkedOrphan)
        );
        let outcome = store.recover_one(seq).unwrap();
        assert_eq!(outcome.action, RecoveryAction::Cancelled);
        // No entry exported; sequence is a permanent gap.
        assert!(store.export().is_empty());
        assert!(store.reservation(seq).is_none());
        assert_eq!(store.next_sequence(), 2);
    }

    #[test]
    fn failed_normal_rejection_is_retried_and_committed() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        store.faults.arm("commit_rejection", 1);
        store.finalize_rejected(handle, &rejection()).unwrap_err();
        assert_eq!(
            store.classify(seq),
            Some(RecoveryClassification::FailedRejection)
        );
        let outcome = store.recover_one(seq).unwrap();
        assert_eq!(outcome.action, RecoveryAction::RejectionCommitted);
        assert!(store.export().contains("rejected_pre_dispatch"));
    }

    #[test]
    fn failed_exact_reduced_rejection_is_retried() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        store.faults.arm("commit_rejection", 1);
        store.select_oversize_reduced(handle).unwrap_err();
        let outcome = store.recover_one(seq).unwrap();
        assert_eq!(
            outcome.classification,
            RecoveryClassification::FailedRejection
        );
        assert_eq!(outcome.action, RecoveryAction::RejectionCommitted);
        assert!(store.export().contains("journal_entry_oversize"));
    }

    #[test]
    fn failed_dispatch_commitment_is_cancelled_never_retried() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        store.faults.arm("commit_dispatch", 1);
        store.commit_dispatched(handle, &dispatch()).unwrap_err();
        assert_eq!(
            store.classify(seq),
            Some(RecoveryClassification::FailedCommitment)
        );
        let outcome = store.recover_one(seq).unwrap();
        assert_eq!(outcome.action, RecoveryAction::Cancelled);
        // No dispatched entry was ever exported; permanent gap.
        assert!(!store.export().contains("dispatched"));
        assert!(store.reservation(seq).is_none());
    }

    #[test]
    fn provisional_dispatched_is_finalized_unchanged_as_interrupted() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        let token = store.commit_dispatched(handle, &dispatch()).unwrap();
        // Simulate a crash before finalize_dispatched: fail the finalization.
        store.faults.arm("commit_finalization", 1);
        store
            .finalize_dispatched(
                token,
                &FinalContextAssociation {
                    profile_uuid: None,
                    profile_name: None,
                },
                &crate::journal::reservation::CompletedResult {
                    outcome: Outcome::Success,
                    detail: serde_json::json!({"message":"ok"}),
                },
            )
            .unwrap_err();
        assert_eq!(
            store.classify(seq),
            Some(RecoveryClassification::ProvisionalDispatched)
        );
        let outcome = store.recover_one(seq).unwrap();
        assert_eq!(outcome.action, RecoveryAction::DispatchFinalized);
        // The unchanged provisional record is the recovery record.
        let export = store.export();
        assert!(export.contains("interrupted_after_dispatch"));
        assert!(!export.contains("success"));
        // Active charge released; accounting uses the actual size.
        assert_eq!(store.active_reserved_bytes(), 0);
    }

    #[test]
    fn recover_all_resolves_every_active_reservation() {
        let mut store = store();
        let orphan = store.reserve(identity(), Capability::Navigate).unwrap();
        let failed_rej = store.reserve(identity(), Capability::Click).unwrap();
        store.faults.arm("commit_rejection", 1);
        store
            .finalize_rejected(failed_rej, &rejection())
            .unwrap_err();
        let outcomes = store.recover_all();
        assert_eq!(outcomes.len(), 2);
        assert!(store.active_sequences().is_empty());
        let _ = orphan;
    }

    #[test]
    fn recovery_never_resurrects_after_cancel() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let seq = handle.sequence();
        store.recover_one(seq).unwrap();
        // Once cancelled, there is nothing left to recover.
        assert!(store.recover_one(seq).is_none());
        let _ = JournalReasonCode::InternalFailure;
    }
}
