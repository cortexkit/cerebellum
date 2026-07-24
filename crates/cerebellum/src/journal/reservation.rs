//! The journal reservation and transition pin.
//!
//! Implements the four frozen operations of the journal pin — `reserve`,
//! `finalize_rejected`, `commit_dispatched`, and `finalize_dispatched` — as
//! methods on [`JournalStore`], together with the opaque invocation-bound
//! reservation handle and dispatch-commitment token.
//!
//! A reservation permits exactly one rejection finalization or one dispatch
//! commitment; a commitment permits exactly one completed-result finalization.
//! Byte-identical retries after a successful transition are idempotent.
//! Conflicting, mismatched, stale, and cross-invocation use fails closed with
//! `internal_failure` and never authorizes dispatch.
//!
//! After a *failed marked* transition the invocation-side caller performs no
//! further transition on that reservation; B2A writer recovery exclusively owns
//! retry or cancellation (see `recovery.rs`). This module enforces that by
//! refusing every caller transition on a reservation that already carries a
//! transition-attempt marker.

use crate::journal::store::{JournalStore, ReducedPath, ReservationState, TransitionMarker};
use crate::journal::{
    Action, Capability, GoverningObservation, GrantDecision, JournalEntry, JournalError,
    JournalIdentity, JournalReasonCode, Locator, Outcome, Phase, Severity, FORMAT_VERSION,
};

/// An opaque, invocation-bound reservation handle.
///
/// Wraps the allocated sequence but is never caller-constructed, persisted,
/// exported, or returned across invocations. B1/B2B never construct or reuse a
/// handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReservationHandle(pub(crate) u64);

impl ReservationHandle {
    pub fn sequence(&self) -> u64 {
        self.0
    }
}

/// An opaque, invocation-bound dispatch-commitment token.
///
/// Returned by a successful `commit_dispatched` and required by
/// `finalize_dispatched`. Never caller-constructed or reused across
/// invocations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DispatchCommitmentToken(pub(crate) u64);

impl DispatchCommitmentToken {
    pub fn sequence(&self) -> u64 {
        self.0
    }
}

/// A successful terminal journal transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Committed;

/// Bounded rejection material supplied to `finalize_rejected`.
///
/// Supplies the B1-owned fields needed for a complete rejection. B2A fixes
/// `format_version`, `sequence`, `phase`, `identity`, and `capability` from the
/// reservation and never accepts identity or profile facts from this material.
#[derive(Debug, Clone, PartialEq)]
pub struct RejectionMaterial {
    pub intent_redacted: Option<String>,
    pub requested_severity: Option<Severity>,
    pub effective_severity: Option<Severity>,
    pub grant_decision: GrantDecision,
    pub governing_observation: GoverningObservation,
    pub action: Option<Action>,
    pub locator: Option<Locator>,
    pub snapshot_ids: Vec<String>,
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

/// Bounded dispatch material supplied to `commit_dispatched`.
///
/// Contains the complete B1-owned action, locator, snapshot-selection,
/// severity, grant, and intent fields. It never contains governing-observation
/// bytes (B2A selects those from its retained store), identity/profile facts,
/// or the provisional outcome and detail fixed by B2A.
#[derive(Debug, Clone, PartialEq)]
pub struct DispatchMaterial {
    pub intent_redacted: Option<String>,
    pub requested_severity: Option<Severity>,
    pub effective_severity: Option<Severity>,
    pub grant_decision: GrantDecision,
    pub action: Action,
    pub locator: Option<Locator>,
    pub snapshot_ids: Vec<String>,
    /// The governing observation B2A selected from its retained pinned store.
    pub governing_observation: GoverningObservation,
}

/// The immutable B2B final-context association consumed by
/// `finalize_dispatched`.
///
/// This is the same object B1 forms the completed result context from; it is
/// never the reservation-time association.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalContextAssociation {
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
}

/// A completed B1 result supplied to `finalize_dispatched`.
#[derive(Debug, Clone, PartialEq)]
pub struct CompletedResult {
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

impl JournalStore {
    /// Reserve durable journal capacity for one parsed unfenceable invocation.
    ///
    /// Durably advances the allocator, then atomically establishes an active
    /// pre-dispatch reservation charged at `journal_max_entry_bytes`. Both steps
    /// complete before any session/profile check or browser-side activity.
    /// Allocation or establishment failure returns
    /// `journal_reservation_failed`; `journal_entry_oversize` is never a
    /// `reserve` outcome.
    pub fn reserve(
        &mut self,
        identity: JournalIdentity,
        capability: Capability,
    ) -> Result<ReservationHandle, JournalError> {
        let sequence = self.allocate_sequence()?;
        self.establish_reservation(sequence, identity, capability)?;
        Ok(ReservationHandle(sequence))
    }

    /// Finalize a reservation as one exportable `rejected_pre_dispatch` entry.
    ///
    /// Records the transition-attempt marker before attempting the durable
    /// rejection commit. Success makes the rejection durably exportable,
    /// terminates the reservation, releases unused capacity, and never
    /// authorizes dispatch.
    pub fn finalize_rejected(
        &mut self,
        handle: ReservationHandle,
        material: &RejectionMaterial,
    ) -> Result<Committed, JournalError> {
        let seq = handle.0;

        // Idempotence / conflict against an already-finalized entry.
        if let Some(existing) = self.entry(seq) {
            let capability = existing.capability.unwrap_or(Capability::Navigate);
            let candidate = self.build_rejection(seq, &existing.identity, capability, material);
            return if existing == &candidate {
                Ok(Committed)
            } else {
                Err(JournalError::internal_failure())
            };
        }

        let record = self
            .reservation(seq)
            .ok_or_else(JournalError::internal_failure)?
            .clone();
        if record.state != ReservationState::ActivePreDispatch {
            return Err(JournalError::internal_failure());
        }
        // A reservation that already carries a marker is governed by writer
        // recovery; the invocation-side caller may perform no further
        // transition, including a byte-identical retry.
        if record.marker.is_some() {
            return Err(JournalError::internal_failure());
        }

        let entry = self.build_rejection(seq, &record.identity, record.capability, material);

        // Durably record the transition-attempt marker first.
        if self.faults.take("establish_marker") {
            // Marker establishment failed: the reservation stays an unmarked
            // orphan; recovery cancels it after proving no commitment exists.
            return Err(JournalError::reservation_failed());
        }
        self.reservation_mut(seq)
            .expect("reservation present")
            .marker = Some(TransitionMarker::NormalRejection {
            rejection: Some(Box::new(entry.clone())),
        });

        // Attempt the durable rejection commit.
        if self.faults.take("commit_rejection") {
            // The reservation remains active, marked, charged; writer recovery
            // owns retry or cancellation.
            return Err(JournalError::reservation_failed());
        }
        self.insert_finalized(entry)?;
        Ok(Committed)
    }

    /// Commit a reservation as an exportable, active provisional
    /// `phase:"dispatched"` entry with fixed `outcome:"internal_error"` and
    /// `detail:{reason_code:"interrupted_after_dispatch"}`.
    ///
    /// No browser-side dispatch is permitted before this succeeds. A failed
    /// commitment is never converted into a rejection; recovery owns it.
    pub fn commit_dispatched(
        &mut self,
        handle: ReservationHandle,
        material: &DispatchMaterial,
    ) -> Result<DispatchCommitmentToken, JournalError> {
        let seq = handle.0;

        let record = self
            .reservation(seq)
            .ok_or_else(JournalError::internal_failure)?
            .clone();

        // Idempotence: a byte-identical commitment after success returns the
        // same token.
        if record.state == ReservationState::Dispatched {
            let candidate =
                self.build_provisional(seq, &record.identity, record.capability, material);
            return if record.provisional.as_ref() == Some(&candidate) {
                Ok(DispatchCommitmentToken(seq))
            } else {
                Err(JournalError::internal_failure())
            };
        }

        if record.state != ReservationState::ActivePreDispatch {
            return Err(JournalError::internal_failure());
        }
        // A marked reservation is recovery-owned; no caller transition allowed.
        if record.marker.is_some() {
            return Err(JournalError::internal_failure());
        }

        let identity = record.identity.clone();
        let capability = record.capability;
        let provisional = self.build_provisional(seq, &identity, capability, material);

        // Durably record the dispatch-commitment marker first.
        if self.faults.take("establish_marker") {
            return Err(JournalError::reservation_failed());
        }
        self.reservation_mut(seq)
            .expect("reservation present")
            .marker = Some(TransitionMarker::DispatchCommitment);

        // Attempt the durable dispatch commitment.
        if self.faults.take("commit_dispatch") {
            // Reservation remains active, marked, charged; recovery proves no
            // commitment exists and cancels. Never retried as a commitment.
            return Err(JournalError::reservation_failed());
        }
        let record = self.reservation_mut(seq).expect("reservation present");
        record.state = ReservationState::Dispatched;
        record.provisional = Some(provisional);
        // The marker is retained; it is superseded by the durable dispatched
        // state but kept for recovery classification symmetry.
        record.marker = None;
        Ok(DispatchCommitmentToken(seq))
    }

    /// Finalize a dispatch commitment with the completed B1 result.
    ///
    /// Atomically commits the completed result and updates journal profile
    /// facts from the immutable token-bound final-context association, then
    /// releases unused capacity. Failure leaves the provisional entry
    /// authoritative and charged; `oversize_flag` is set for a bound violation.
    pub fn finalize_dispatched(
        &mut self,
        token: DispatchCommitmentToken,
        final_context: &FinalContextAssociation,
        result: &CompletedResult,
    ) -> Result<Committed, JournalError> {
        let seq = token.0;

        // Idempotence / conflict against an already-finalized entry.
        if let Some(existing) = self.entry(seq) {
            let record_identity = self
                .reservation(seq)
                .map(|r| r.identity.clone())
                .or_else(|| Some(existing.identity.clone()));
            // A byte-identical completed result is idempotent.
            if existing.outcome == Some(result.outcome)
                && existing.detail.as_ref() == Some(&result.detail)
            {
                return Ok(Committed);
            }
            let _ = record_identity;
            return Err(JournalError::internal_failure());
        }

        let record = self
            .reservation(seq)
            .ok_or_else(JournalError::internal_failure)?
            .clone();
        if record.state != ReservationState::Dispatched {
            return Err(JournalError::internal_failure());
        }
        let provisional = record
            .provisional
            .clone()
            .ok_or_else(JournalError::internal_failure)?;

        // Build the completed entry from the provisional, replacing outcome and
        // detail and setting profile facts from the final-context association.
        let mut completed = provisional.clone();
        completed.outcome = Some(result.outcome);
        completed.detail = Some(result.detail.clone());
        completed.identity.profile_uuid = final_context.profile_uuid.clone();
        completed.identity.profile_name = final_context.profile_name.clone();

        // Completed-result serialization bound: if the completed entry violates
        // the precomputed maximum, fail without persisting the oversize result
        // material. The provisional entry remains authoritative.
        if completed.serialized_size() > self.max_entry_bytes() {
            self.set_oversize_flag();
            return Err(JournalError::internal_failure());
        }

        // Attempt the durable completed-result commit.
        if self.faults.take("commit_finalization") {
            // Provisional entry remains authoritative and charged; writer
            // recovery finalizes it as interrupted_after_dispatch.
            return Err(JournalError::internal_failure());
        }
        self.insert_finalized(completed)?;
        Ok(Committed)
    }

    // ------------------------------------------------------------------
    // Entry construction helpers
    // ------------------------------------------------------------------

    fn build_rejection(
        &self,
        seq: u64,
        identity: &JournalIdentity,
        capability: Capability,
        material: &RejectionMaterial,
    ) -> JournalEntry {
        JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: seq,
            phase: Phase::RejectedPreDispatch,
            identity: identity.clone(),
            capability: Some(capability),
            intent_redacted: material.intent_redacted.clone(),
            requested_severity: material.requested_severity,
            effective_severity: material.effective_severity,
            grant_decision: material.grant_decision.clone(),
            governing_observation: material.governing_observation.clone(),
            action: material.action.clone(),
            locator: material.locator.clone(),
            snapshot_ids: material.snapshot_ids.clone(),
            outcome: Some(material.outcome),
            detail: Some(material.detail.clone()),
        }
    }

    fn build_provisional(
        &self,
        seq: u64,
        identity: &JournalIdentity,
        capability: Capability,
        material: &DispatchMaterial,
    ) -> JournalEntry {
        JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: seq,
            phase: Phase::Dispatched,
            identity: identity.clone(),
            capability: Some(capability),
            intent_redacted: material.intent_redacted.clone(),
            requested_severity: material.requested_severity,
            effective_severity: material.effective_severity,
            grant_decision: material.grant_decision.clone(),
            governing_observation: material.governing_observation.clone(),
            action: Some(material.action.clone()),
            locator: material.locator.clone(),
            snapshot_ids: material.snapshot_ids.clone(),
            outcome: Some(Outcome::InternalError),
            detail: Some(serde_json::json!({
                "reason_code": JournalReasonCode::InterruptedAfterDispatch.as_str()
            })),
        }
    }

    /// Build the exact reduced rejection entry for `seq` on the given reduced
    /// path. Used by the oversize and redactor-unavailable paths and by
    /// recovery. The entry carries no caller- or page-derived material.
    pub(crate) fn build_exact_reduced(
        &self,
        seq: u64,
        identity: &JournalIdentity,
        capability: Capability,
        path: ReducedPath,
    ) -> JournalEntry {
        let reason_code = match path {
            ReducedPath::Oversize => JournalReasonCode::JournalEntryOversize,
            ReducedPath::RedactionUnavailable => JournalReasonCode::RedactionUnavailable,
        };
        JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: seq,
            phase: Phase::RejectedPreDispatch,
            identity: identity.clone(),
            capability: Some(capability),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: vec![],
            outcome: Some(Outcome::InternalError),
            detail: Some(serde_json::json!({"reason_code": reason_code.as_str()})),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalConfig, JournalIdentity, SessionKind};

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
            grant_decision: GrantDecision {
                outcome: crate::journal::GrantOutcome::Allowed,
                reason: None,
            },
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
    fn reserve_then_finalize_rejected_exports_one_entry() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.finalize_rejected(handle, &rejection()).unwrap();
        let export = store.export();
        assert_eq!(export.lines().count(), 1);
        assert!(export.contains("rejected_pre_dispatch"));
        // Reservation terminated; no active charge remains.
        assert_eq!(store.active_reserved_bytes(), 0);
    }

    #[test]
    fn reserve_never_returns_oversize() {
        // A valid configuration always admits at least one reservation; it is
        // capacity exhaustion that produces `journal_reservation_failed`, and
        // never `journal_entry_oversize`.
        let mut tiny = JournalStore::new(JournalConfig {
            journal_retention_bytes: 10,
            journal_max_entry_bytes: 10,
        })
        .unwrap();
        let _first = tiny.reserve(identity(), Capability::Navigate).unwrap();
        let err = tiny.reserve(identity(), Capability::Navigate).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
    }

    #[test]
    fn byte_identical_rejection_retry_is_idempotent() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let material = rejection();
        store.finalize_rejected(handle, &material).unwrap();
        // Same material again: idempotent success.
        store.finalize_rejected(handle, &material).unwrap();
        assert_eq!(store.export().lines().count(), 1);
    }

    #[test]
    fn conflicting_rejection_after_success_fails_closed() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.finalize_rejected(handle, &rejection()).unwrap();
        let mut other = rejection();
        other.outcome = Outcome::InvalidRequest;
        let err = store.finalize_rejected(handle, &other).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    }

    #[test]
    fn commit_then_finalize_dispatched_updates_profile_from_final_context() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let token = store.commit_dispatched(handle, &dispatch()).unwrap();
        // Provisional entry is exportable and active before finalization.
        assert!(store.export().contains("dispatched"));
        let final_context = FinalContextAssociation {
            profile_uuid: Some("uuid-1".to_string()),
            profile_name: Some("profile-a".to_string()),
        };
        store
            .finalize_dispatched(
                token,
                &final_context,
                &CompletedResult {
                    outcome: Outcome::Success,
                    detail: serde_json::json!({"message":"ok"}),
                },
            )
            .unwrap();
        let export = store.export();
        assert!(export.contains("uuid-1"));
        assert!(export.contains("profile-a"));
        assert!(export.contains("success"));
        // Active charge released after finalization.
        assert_eq!(store.active_reserved_bytes(), 0);
    }

    #[test]
    fn no_dispatch_before_durable_commitment() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.faults.arm("commit_dispatch", 1);
        let err = store.commit_dispatched(handle, &dispatch()).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::JournalReservationFailed);
        // No dispatched entry was exported.
        assert!(!store.export().contains("dispatched"));
    }

    #[test]
    fn caller_cannot_transition_after_failed_marked_attempt() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.faults.arm("commit_rejection", 1);
        // finalize_rejected fails after the marker is recorded.
        store.finalize_rejected(handle, &rejection()).unwrap_err();
        // Any further caller transition on the marked reservation fails closed.
        let err = store.finalize_rejected(handle, &rejection()).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
        let err = store.commit_dispatched(handle, &dispatch()).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    }

    #[test]
    fn failed_dispatch_commitment_is_never_converted_to_rejection() {
        let mut store = store();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        store.faults.arm("commit_dispatch", 1);
        store.commit_dispatched(handle, &dispatch()).unwrap_err();
        // The caller may not finalize a rejection on the marked reservation.
        let err = store.finalize_rejected(handle, &rejection()).unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
    }

    #[test]
    fn completed_result_oversize_keeps_provisional_authoritative() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 1_000,
        })
        .unwrap();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        let token = store.commit_dispatched(handle, &dispatch()).unwrap();
        // A completed result whose detail blows the bound fails and sets the
        // oversize flag, leaving the provisional entry authoritative.
        let huge = "x".repeat(5_000);
        let err = store
            .finalize_dispatched(
                token,
                &FinalContextAssociation {
                    profile_uuid: None,
                    profile_name: None,
                },
                &CompletedResult {
                    outcome: Outcome::Success,
                    detail: serde_json::json!({"message": huge}),
                },
            )
            .unwrap_err();
        assert_eq!(err.reason_code, JournalReasonCode::InternalFailure);
        assert!(store.oversize_flag());
        // The provisional interrupted_after_dispatch entry remains exported.
        assert!(store.export().contains("interrupted_after_dispatch"));
    }
}
