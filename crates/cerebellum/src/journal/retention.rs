//! Journal retention accounting and `retention.set` validation.
//!
//! Capacity is measured as the sum of the RFC 8785 JCS-plus-LF bytes of every
//! finalized retained exportable entry together with the establishment-time
//! charges held by active unevictable writes (active pre-dispatch reservations
//! and active provisional dispatched entries). An establishment-time charge is
//! the `journal_max_entry_bytes` in force when the write was durably
//! established; it is fixed for the lifetime of the active write and a later
//! `retention.set` never reprices it. `active_reserved_bytes` is a subset of
//! `retained_bytes`; the two gauges must not be summed.
//!
//! `retention.set` is atomic: it validates every bound and active-capacity
//! invariant, performs any required finalized-entry eviction in ascending
//! sequence order in the same transaction, and only then commits the new
//! configuration and clears the oversize flag. Failure exposes neither eviction
//! nor configuration mutation.

use crate::journal::store::JournalStore;
use crate::journal::{JournalConfig, JournalError};

impl JournalStore {
    /// The active retention configuration (`retention.get`).
    pub fn retention_get(&self) -> JournalConfig {
        self.config()
    }

    /// Record the maximum reachable representation size for an active write.
    ///
    /// Used by the invocation seam to publish, for each active reservation, the
    /// largest serialized representation still reachable from its parsed
    /// capability (every bounded rejection, exact reduced rejection, provisional
    /// dispatched representation, and bounded completed result). `retention.set`
    /// refuses to lower the maximum entry size below this for any active write.
    pub fn set_reachable_max(&mut self, sequence: u64, size: u64) {
        if let Some(record) = self.reservation_mut(sequence) {
            record.reachable_max = size;
        }
    }

    /// Atomically validate and commit a new retention configuration
    /// (`retention.set`).
    ///
    /// Commits only if:
    /// - both values are positive and `journal_max_entry_bytes <=
    ///   journal_retention_bytes`;
    /// - every active write's reachable representation fits the proposed maximum
    ///   entry size;
    /// - all active unevictable establishment-time charges fit within the
    ///   proposed retention capacity (after evicting finalized entries oldest
    ///   first in the same transaction).
    ///
    /// On success the oversize flag is cleared only after all checks and
    /// evictions commit. Establishment-time charges of existing active writes
    /// are not repriced; the new maximum applies only to reservations created
    /// after commit.
    pub fn retention_set(
        &mut self,
        proposed: JournalConfig,
    ) -> Result<JournalConfig, JournalError> {
        // Ordering and positivity.
        proposed.validate()?;

        // Every active write must remain safely finalizable under the proposed
        // maximum: no reachable representation may exceed it.
        for record in self.active_records() {
            if record.reachable_max > proposed.journal_max_entry_bytes {
                return Err(JournalError::internal_failure());
            }
        }

        // All active unevictable establishment-time charges must fit within the
        // proposed retention capacity. Active writes cannot be evicted, so their
        // total fixed charge is a hard floor.
        let active_charges: u64 = self.active_reserved_bytes();
        if active_charges > proposed.journal_retention_bytes {
            return Err(JournalError::internal_failure());
        }

        // Compute the finalized-entry eviction required to fit within the
        // proposed retention capacity, oldest first, without mutating yet.
        let finalized: Vec<(u64, u64)> = self.finalized_entries().collect();
        let mut finalized_total: u64 = finalized.iter().map(|(_, s)| *s).sum();
        let mut to_evict: Vec<u64> = Vec::new();
        for (seq, size) in finalized.iter() {
            if active_charges + finalized_total <= proposed.journal_retention_bytes {
                break;
            }
            to_evict.push(*seq);
            finalized_total -= size;
        }
        // After eviction the active charges plus remaining finalized entries
        // must fit; if not, the active charges alone exceed capacity (already
        // checked above) so this is defensive.
        if active_charges + finalized_total > proposed.journal_retention_bytes {
            return Err(JournalError::internal_failure());
        }

        // All checks passed: commit eviction and configuration atomically.
        for seq in to_evict {
            self.evict_finalized(seq);
        }
        self.apply_config(proposed);
        // Clear the oversize flag only after all checks and evictions commit.
        self.clear_oversize_flag();
        Ok(proposed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{
        Capability, GoverningObservation, GrantDecision, JournalIdentity, Outcome, Phase,
        SessionKind, FORMAT_VERSION,
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

    fn entry(seq: u64) -> crate::journal::JournalEntry {
        crate::journal::JournalEntry {
            format_version: FORMAT_VERSION.to_string(),
            sequence: seq,
            phase: Phase::RejectedPreDispatch,
            identity: identity(),
            capability: Some(Capability::Navigate),
            intent_redacted: None,
            requested_severity: None,
            effective_severity: None,
            grant_decision: GrantDecision::not_reached(),
            governing_observation: GoverningObservation::observation_not_required(),
            action: None,
            locator: None,
            snapshot_ids: vec![],
            outcome: Some(Outcome::InternalError),
            detail: Some(serde_json::json!({"reason_code":"journal_entry_oversize"})),
        }
    }

    #[test]
    fn retention_get_reports_active_values() {
        let store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1000,
            journal_max_entry_bytes: 500,
        })
        .unwrap();
        let config = store.retention_get();
        assert_eq!(config.journal_retention_bytes, 1000);
        assert_eq!(config.journal_max_entry_bytes, 500);
    }

    #[test]
    fn retention_set_rejects_bad_ordering() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1000,
            journal_max_entry_bytes: 500,
        })
        .unwrap();
        assert!(store
            .retention_set(JournalConfig {
                journal_retention_bytes: 100,
                journal_max_entry_bytes: 500,
            })
            .is_err());
        // Configuration unchanged on failure.
        assert_eq!(store.retention_get().journal_retention_bytes, 1000);
    }

    #[test]
    fn retention_set_rejects_lowering_below_active_reachable_max() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        // The active reservation's reachable max defaults to its establishment
        // charge (50_000). Lowering the maximum below it is rejected.
        let err = store
            .retention_set(JournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 10_000,
            })
            .unwrap_err();
        assert_eq!(
            err.reason_code,
            crate::journal::JournalReasonCode::InternalFailure
        );
        let _ = handle;
    }

    #[test]
    fn retention_set_evicts_oldest_finalized_to_fit_active_charges() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 1_000,
        })
        .unwrap();
        store.insert_finalized(entry(1)).unwrap();
        store.insert_finalized(entry(2)).unwrap();
        // Two finalized entries exceed the proposed retention; the oldest is
        // evicted in the same atomic transaction.
        let result = store
            .retention_set(JournalConfig {
                journal_retention_bytes: 1_000,
                journal_max_entry_bytes: 1_000,
            })
            .unwrap();
        assert_eq!(result.journal_retention_bytes, 1_000);
        assert!(store.retained_bytes() <= 1_000);
    }

    #[test]
    fn retention_set_clears_oversize_flag_only_on_success() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 500,
        })
        .unwrap();
        store.set_oversize_flag();
        assert!(store.oversize_flag());
        // A failed set leaves the flag set.
        let _ = store
            .retention_set(JournalConfig {
                journal_retention_bytes: 100,
                journal_max_entry_bytes: 500,
            })
            .unwrap_err();
        assert!(store.oversize_flag());
        // A successful set clears it.
        store
            .retention_set(JournalConfig {
                journal_retention_bytes: 1_000_000,
                journal_max_entry_bytes: 500,
            })
            .unwrap();
        assert!(!store.oversize_flag());
    }

    #[test]
    fn retention_set_does_not_reprice_existing_active_charges() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        let handle = store.reserve(identity(), Capability::Navigate).unwrap();
        assert_eq!(store.active_reserved_bytes(), 50_000);
        // Raise the maximum; the existing active charge is unchanged.
        store
            .retention_set(JournalConfig {
                journal_retention_bytes: 2_000_000,
                journal_max_entry_bytes: 80_000,
            })
            .unwrap();
        assert_eq!(store.active_reserved_bytes(), 50_000);
        // A new reservation uses the new maximum.
        let handle2 = store.reserve(identity(), Capability::Click).unwrap();
        assert_eq!(store.active_reserved_bytes(), 50_000 + 80_000);
        let _ = (handle, handle2);
    }
}
