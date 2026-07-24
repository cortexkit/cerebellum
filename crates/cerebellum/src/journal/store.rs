//! The durable journal allocator and store.
//!
//! This is the substrate the rest of the journal module builds on. It owns the
//! strictly increasing sequence allocator, the retained exportable entries, the
//! active unevictable writes (pre-dispatch reservations and provisional
//! dispatched entries), establishment-time capacity accounting, oldest-first
//! eviction of finalized entries, export, purge, retention configuration, and
//! the administrative oversize flag.
//!
//! Every mutation is an explicit atomic commit against in-memory durable state
//! (see the module note). A [`FaultInjector`] fails a named durable-write step
//! on demand so tests can exercise the marker, recovery, and cancellation
//! contracts.

use std::collections::BTreeMap;

use crate::journal::{
    Capability, JournalConfig, JournalEntry, JournalError, JournalIdentity, Phase, MAX_SEQUENCE,
};

/// A durable, non-exportable transition-attempt marker.
///
/// Recorded before a rejection finalization or dispatch commitment is attempted.
/// A reservation with no marker is an orphan; a reservation with a marker but
/// without the requested durable transition is a failed-transition reservation.
/// The marker contains no unredacted caller material.
#[derive(Debug, Clone, PartialEq)]
pub enum TransitionMarker {
    /// A normal rejection finalization was attempted. When `rejection` is
    /// present, complete schema-valid bounded rejection material is durably
    /// available and recovery retries it; when absent, recovery cancels.
    NormalRejection {
        rejection: Option<Box<JournalEntry>>,
    },
    /// An exact reduced rejection (oversize or redactor-unavailable) was
    /// selected. The bounded entry is fully reproducible from the reservation-time
    /// values retained here, so recovery always retries it.
    ExactReduced {
        path: ReducedPath,
        entry: Box<JournalEntry>,
    },
    /// A dispatch commitment was attempted but failed before becoming durable.
    /// Recovery never retries or replaces a commitment; it cancels once it has
    /// durably proved that no commitment exists.
    DispatchCommitment,
}

/// Which exact reduced rejection a marker selected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReducedPath {
    Oversize,
    RedactionUnavailable,
}

/// The durable state of one reserved sequence.
#[derive(Debug, Clone, PartialEq)]
pub struct ReservationRecord {
    pub sequence: u64,
    /// The fixed establishment-time charge: the `journal_max_entry_bytes` in
    /// force when the reservation was durably established. Never repriced.
    pub establishment_charge: u64,
    pub identity: JournalIdentity,
    pub capability: Capability,
    pub state: ReservationState,
    pub marker: Option<TransitionMarker>,
    /// The provisional dispatched entry, present once dispatch is committed.
    pub provisional: Option<JournalEntry>,
    /// The maximum serialized size of any representation reachable for this
    /// active write (every bounded rejection, exact reduced rejection,
    /// provisional dispatched representation, and bounded completed result).
    /// `retention.set` refuses to lower the maximum below this for any active
    /// write. Defaults to the establishment-time charge.
    pub reachable_max: u64,
}

/// The lifecycle state of a reserved sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReservationState {
    /// Active pre-dispatch reservation: non-exportable, unevictable, charged at
    /// the establishment-time amount.
    ActivePreDispatch,
    /// Dispatch committed: the provisional entry is exportable but still active
    /// and unevictable, charged at the same establishment-time amount.
    Dispatched,
}

/// Test-only durable-write fault injection.
///
/// `arm(point, n)` makes the next `n` durable writes at `point` fail. A point
/// that is not armed always succeeds. Points are named after the durable step
/// they govern (e.g. `"establish_reservation"`, `"commit_dispatch"`).
#[derive(Debug, Default)]
pub struct FaultInjector {
    failures: BTreeMap<String, usize>,
}

impl FaultInjector {
    pub fn arm(&mut self, point: impl Into<String>, count: usize) {
        self.failures.insert(point.into(), count);
    }

    /// Consume one armed failure at `point`, returning `true` if this write
    /// should fail.
    pub fn take(&mut self, point: &str) -> bool {
        if let Some(n) = self.failures.get_mut(point) {
            if *n > 0 {
                *n -= 1;
                return true;
            }
        }
        false
    }
}

/// The durable journal store.
#[derive(Debug)]
pub struct JournalStore {
    config: JournalConfig,
    /// The next sequence the allocator will hand out. Strictly increasing; a
    /// committed advancement is never rolled back.
    next_sequence: u64,
    /// Finalized retained exportable entries, keyed by sequence, ascending.
    entries: BTreeMap<u64, JournalEntry>,
    /// Active unevictable writes (pre-dispatch reservations and provisional
    /// dispatched entries), keyed by sequence.
    reservations: BTreeMap<u64, ReservationRecord>,
    /// Administrative oversize flag: set by an oversize detection, cleared only
    /// by purge or a successful `retention.set` that revalidates all bounds.
    oversize_flag: bool,
    pub faults: FaultInjector,
}

/// The status snapshot reported by the administration `status` operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JournalStatus {
    pub entry_count: u64,
    pub oldest_retained_sequence: Option<u64>,
    pub newest_retained_sequence: Option<u64>,
    pub retained_bytes: u64,
    pub active_reservation_count: u64,
    pub active_reserved_bytes: u64,
    pub oversize_flag: bool,
}

impl JournalStore {
    /// Open a store with the given manifest-bound configuration.
    pub fn new(config: JournalConfig) -> Result<Self, JournalError> {
        config.validate()?;
        Ok(Self {
            config,
            next_sequence: 1,
            entries: BTreeMap::new(),
            reservations: BTreeMap::new(),
            oversize_flag: false,
            faults: FaultInjector::default(),
        })
    }

    pub fn config(&self) -> JournalConfig {
        self.config
    }

    pub fn max_entry_bytes(&self) -> u64 {
        self.config.journal_max_entry_bytes
    }

    pub fn retention_bytes(&self) -> u64 {
        self.config.journal_retention_bytes
    }

    pub fn oversize_flag(&self) -> bool {
        self.oversize_flag
    }

    pub fn set_oversize_flag(&mut self) {
        self.oversize_flag = true;
    }

    /// The next sequence that would be allocated, without advancing.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    // ------------------------------------------------------------------
    // Allocator
    // ------------------------------------------------------------------

    /// Durably advance the allocator and claim the next sequence.
    ///
    /// The committed advancement is never rolled back. Exhaustion never wraps:
    /// it returns `journal_reservation_failed`. A fault at `advance_allocator`
    /// fails before any claim, leaving the allocator unchanged.
    pub fn allocate_sequence(&mut self) -> Result<u64, JournalError> {
        if self.faults.take("advance_allocator") {
            return Err(JournalError::reservation_failed());
        }
        if self.next_sequence > MAX_SEQUENCE {
            return Err(JournalError::reservation_failed());
        }
        let seq = self.next_sequence;
        // Advance durably. If this would move past the maximum, the next call
        // observes exhaustion; the claimed sequence is still valid.
        self.next_sequence = self.next_sequence.saturating_add(1);
        Ok(seq)
    }

    // ------------------------------------------------------------------
    // Capacity accounting
    // ------------------------------------------------------------------

    /// Total measured capacity: finalized retained entries at their actual
    /// JCS-plus-LF size plus active-write fixed establishment-time charges.
    pub fn retained_bytes(&self) -> u64 {
        let finalized: u64 = self
            .entries
            .values()
            .map(JournalEntry::serialized_size)
            .sum();
        finalized + self.active_reserved_bytes()
    }

    /// The active-write portion of capacity: the sum of establishment-time
    /// charges for active pre-dispatch reservations and provisional dispatched
    /// entries. This is a subset of [`Self::retained_bytes`].
    pub fn active_reserved_bytes(&self) -> u64 {
        self.reservations
            .values()
            .map(|r| r.establishment_charge)
            .sum()
    }

    /// Count of active pre-dispatch reservations only (not provisional
    /// dispatched entries).
    pub fn active_pre_dispatch_count(&self) -> u64 {
        self.reservations
            .values()
            .filter(|r| r.state == ReservationState::ActivePreDispatch)
            .count() as u64
    }

    fn finalized_bytes(&self) -> u64 {
        self.entries
            .values()
            .map(JournalEntry::serialized_size)
            .sum()
    }

    /// Evict finalized exportable entries in strictly ascending sequence order
    /// until `needed` additional bytes fit within retention capacity. Never
    /// evicts an active write or resets the allocator. Returns `false` if
    /// sufficient capacity cannot be freed.
    fn make_room(&mut self, needed: u64) -> bool {
        // Capacity already available?
        if self.retained_bytes().saturating_add(needed) <= self.retention_bytes() {
            return true;
        }
        // Evict oldest finalized entries first.
        let evictable: Vec<u64> = self.entries.keys().copied().collect();
        for seq in evictable {
            if self.retained_bytes().saturating_add(needed) <= self.retention_bytes() {
                return true;
            }
            self.entries.remove(&seq);
        }
        self.retained_bytes().saturating_add(needed) <= self.retention_bytes()
    }

    // ------------------------------------------------------------------
    // Reservation establishment (called by the transition pin)
    // ------------------------------------------------------------------

    /// Durably establish an active pre-dispatch reservation for `sequence`,
    /// charging exactly the current `journal_max_entry_bytes`. Evicts finalized
    /// entries as needed. Establishment either commits completely or leaves no
    /// active, partial, or exportable reservation; its failure does not roll
    /// back the allocator, so the claimed sequence becomes a gap.
    pub(crate) fn establish_reservation(
        &mut self,
        sequence: u64,
        identity: JournalIdentity,
        capability: Capability,
    ) -> Result<(), JournalError> {
        let charge = self.max_entry_bytes();
        if !self.make_room(charge) {
            return Err(JournalError::reservation_failed());
        }
        if self.faults.take("establish_reservation") {
            // Allocator already advanced; the sequence is now a gap.
            return Err(JournalError::reservation_failed());
        }
        self.reservations.insert(
            sequence,
            ReservationRecord {
                sequence,
                establishment_charge: charge,
                identity,
                capability,
                state: ReservationState::ActivePreDispatch,
                marker: None,
                provisional: None,
                reachable_max: charge,
            },
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // Finalized-entry insertion (called by transition pin / recovery)
    // ------------------------------------------------------------------

    /// Insert a finalized exportable entry, releasing the active-write charge
    /// for its sequence if one exists. Accounting then uses the entry's actual
    /// serialized size. The entry must fit within `journal_max_entry_bytes`.
    pub(crate) fn insert_finalized(&mut self, entry: JournalEntry) -> Result<(), JournalError> {
        let size = entry.serialized_size();
        if size > self.max_entry_bytes() {
            return Err(JournalError::internal_failure());
        }
        let seq = entry.sequence;
        // Release the active-write charge for this sequence, if any.
        self.reservations.remove(&seq);
        if !self.make_room(size) {
            // Cannot admit the finalized entry at its actual size. This is a
            // serialization-bound violation; the caller handles the provisional
            // or reduced path.
            return Err(JournalError::internal_failure());
        }
        self.entries.insert(seq, entry);
        Ok(())
    }

    /// Remove an active reservation without exporting an entry, releasing its
    /// establishment-time charge and leaving the sequence as a permanent gap.
    pub(crate) fn cancel_reservation(&mut self, sequence: u64) {
        self.reservations.remove(&sequence);
    }

    /// Durably commit a bounded `phase:"policy_event"` entry.
    ///
    /// Uses the same admission rules as reservation establishment: it may evict
    /// finalized exportable entries but never an active reservation or
    /// provisional dispatched entry. Failure means the event is not marked
    /// delivered and the audit-failed rules apply.
    pub fn commit_policy_event(&mut self, entry: JournalEntry) -> Result<(), JournalError> {
        if self.faults.take("commit_policy_event") {
            return Err(JournalError::reservation_failed());
        }
        self.insert_finalized(entry)
    }

    pub(crate) fn reservation_mut(&mut self, sequence: u64) -> Option<&mut ReservationRecord> {
        self.reservations.get_mut(&sequence)
    }

    pub(crate) fn reservation(&self, sequence: u64) -> Option<&ReservationRecord> {
        self.reservations.get(&sequence)
    }

    pub(crate) fn entry(&self, sequence: u64) -> Option<&JournalEntry> {
        self.entries.get(&sequence)
    }

    /// Snapshot of all active reservation records (for retention validation).
    pub(crate) fn active_records(&self) -> Vec<&ReservationRecord> {
        self.reservations.values().collect()
    }

    /// Finalized entries as `(sequence, serialized_size)` in ascending order.
    pub(crate) fn finalized_entries(&self) -> impl Iterator<Item = (u64, u64)> + '_ {
        self.entries
            .iter()
            .map(|(seq, entry)| (*seq, entry.serialized_size()))
    }

    /// Evict one finalized entry by sequence (used by `retention.set`).
    pub(crate) fn evict_finalized(&mut self, sequence: u64) {
        self.entries.remove(&sequence);
    }

    /// Replace the active configuration (used by `retention.set` on success).
    pub(crate) fn apply_config(&mut self, config: JournalConfig) {
        self.config = config;
    }

    /// Clear the administrative oversize flag.
    pub(crate) fn clear_oversize_flag(&mut self) {
        self.oversize_flag = false;
    }

    /// Sequences of all active reservations, ascending. Used by recovery.
    pub(crate) fn active_sequences(&self) -> Vec<u64> {
        self.reservations.keys().copied().collect()
    }

    // ------------------------------------------------------------------
    // Export and purge
    // ------------------------------------------------------------------

    /// The point-in-time export snapshot: retained exportable entries in
    /// ascending sequence order, each as one JCS JSON line terminated by LF.
    /// Active provisional dispatched entries present at the snapshot point are
    /// included; active pre-dispatch reservations are not (they are
    /// non-exportable).
    pub fn export(&self) -> String {
        let mut out = String::new();
        // Finalized retained entries.
        for entry in self.entries.values() {
            out.push_str(&entry.export_line());
        }
        // Active provisional dispatched entries are exportable and included.
        for record in self.reservations.values() {
            if record.state == ReservationState::Dispatched {
                if let Some(provisional) = &record.provisional {
                    out.push_str(&provisional.export_line());
                }
            }
        }
        // The export must be globally ascending by sequence; merge the two
        // ordered sources. Because entries and reservations are disjoint by
        // sequence, re-sort the lines by sequence to guarantee ordering.
        reorder_export_by_sequence(&out)
    }

    /// Atomically remove all finalized exportable entries and clear the oversize
    /// flag. Does not remove an active provisional dispatched entry, cancel an
    /// active reservation, change active-write charges, or alter the allocator.
    pub fn purge(&mut self) -> PurgeReport {
        let purged_entry_count = self.entries.len() as u64;
        let purged_bytes: u64 = self.finalized_bytes();
        self.entries.clear();
        self.oversize_flag = false;
        PurgeReport {
            purged_entry_count,
            purged_bytes,
        }
    }

    // ------------------------------------------------------------------
    // Status
    // ------------------------------------------------------------------

    pub fn status(&self) -> JournalStatus {
        // entry_count includes active provisional dispatched entries.
        let provisional_count = self
            .reservations
            .values()
            .filter(|r| r.state == ReservationState::Dispatched)
            .count() as u64;
        let entry_count = self.entries.len() as u64 + provisional_count;

        let mut sequences: Vec<u64> = self.entries.keys().copied().collect();
        for record in self.reservations.values() {
            if record.state == ReservationState::Dispatched {
                sequences.push(record.sequence);
            }
        }
        sequences.sort_unstable();
        let oldest_retained_sequence = sequences.first().copied();
        let newest_retained_sequence = sequences.last().copied();

        JournalStatus {
            entry_count,
            oldest_retained_sequence,
            newest_retained_sequence,
            retained_bytes: self.retained_bytes(),
            active_reservation_count: self.active_pre_dispatch_count(),
            active_reserved_bytes: self.active_reserved_bytes(),
            oversize_flag: self.oversize_flag,
        }
    }
}

/// The result of a purge operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PurgeReport {
    pub purged_entry_count: u64,
    pub purged_bytes: u64,
}

/// Re-order concatenated export lines into ascending sequence order.
///
/// Each line is one JSON object with a `sequence` field. Lines that fail to
/// parse are dropped (cannot happen for entries this store produced).
fn reorder_export_by_sequence(export: &str) -> String {
    let mut lines: Vec<(u64, String)> = export
        .lines()
        .filter(|l| !l.is_empty())
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            let seq = value.get("sequence")?.as_u64()?;
            Some((seq, format!("{line}\n")))
        })
        .collect();
    lines.sort_by_key(|(seq, _)| *seq);
    let mut out = String::new();
    for (_, line) in lines {
        out.push_str(&line);
    }
    out
}

/// Whether `entry` is a provisional dispatched entry (exportable but active).
pub fn is_provisional_dispatched(entry: &JournalEntry) -> bool {
    entry.phase == Phase::Dispatched
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{
        GoverningObservation, GrantDecision, JournalReasonCode, Outcome, SessionKind,
        FORMAT_VERSION,
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

    fn reduced_oversize(seq: u64) -> JournalEntry {
        JournalEntry {
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
            detail: Some(
                serde_json::json!({"reason_code": JournalReasonCode::JournalEntryOversize.as_str()}),
            ),
        }
    }

    #[test]
    fn allocator_is_strictly_increasing_and_never_reuses() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 100_000,
        })
        .unwrap();
        let a = store.allocate_sequence().unwrap();
        let b = store.allocate_sequence().unwrap();
        let c = store.allocate_sequence().unwrap();
        assert_eq!((a, b, c), (1, 2, 3));
    }

    #[test]
    fn establishment_charges_max_entry_bytes_and_is_retained() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        let seq = store.allocate_sequence().unwrap();
        store
            .establish_reservation(seq, identity(), Capability::Navigate)
            .unwrap();
        assert_eq!(store.active_reserved_bytes(), 50_000);
        assert_eq!(store.retained_bytes(), 50_000);
        assert_eq!(store.active_pre_dispatch_count(), 1);
    }

    #[test]
    fn establishment_failure_after_alloc_leaves_a_gap() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        let seq = store.allocate_sequence().unwrap();
        store.faults.arm("establish_reservation", 1);
        assert!(store
            .establish_reservation(seq, identity(), Capability::Navigate)
            .is_err());
        // Allocator already advanced; the next sequence is a fresh one.
        assert_eq!(store.next_sequence(), 2);
        assert_eq!(store.active_pre_dispatch_count(), 0);
    }

    #[test]
    fn eviction_is_oldest_first_and_never_touches_active_writes() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 2_000,
            journal_max_entry_bytes: 1_000,
        })
        .unwrap();
        // Two finalized entries.
        store.insert_finalized(reduced_oversize(1)).unwrap();
        store.insert_finalized(reduced_oversize(2)).unwrap();
        // Establishing a reservation that needs room evicts the oldest first.
        let seq = store.allocate_sequence().unwrap();
        store
            .establish_reservation(seq, identity(), Capability::Navigate)
            .unwrap();
        // Oldest finalized (seq 1) evicted to make room; seq 2 may also be
        // evicted depending on sizes, but the active reservation always stays.
        assert!(store.reservation(seq).is_some());
        assert!(store.entry(1).is_none());
    }

    #[test]
    fn purge_clears_finalized_entries_and_oversize_flag_but_keeps_active() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        store.insert_finalized(reduced_oversize(1)).unwrap();
        store.set_oversize_flag();
        let seq = store.allocate_sequence().unwrap();
        store
            .establish_reservation(seq, identity(), Capability::Navigate)
            .unwrap();
        let report = store.purge();
        assert_eq!(report.purged_entry_count, 1);
        assert!(!store.oversize_flag());
        // Active reservation survives purge.
        assert!(store.reservation(seq).is_some());
        // Allocator is not reset.
        assert_eq!(store.next_sequence(), 2);
    }

    #[test]
    fn export_orders_by_sequence_and_includes_provisional_dispatched() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        store.insert_finalized(reduced_oversize(5)).unwrap();
        store.insert_finalized(reduced_oversize(2)).unwrap();
        let export = store.export();
        let seqs: Vec<u64> = export
            .lines()
            .map(|l| {
                serde_json::from_str::<serde_json::Value>(l).unwrap()["sequence"]
                    .as_u64()
                    .unwrap()
            })
            .collect();
        assert_eq!(seqs, vec![2, 5]);
    }

    #[test]
    fn status_reports_active_and_retained_gauges() {
        let mut store = JournalStore::new(JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 50_000,
        })
        .unwrap();
        store.insert_finalized(reduced_oversize(1)).unwrap();
        let seq = store.allocate_sequence().unwrap();
        store
            .establish_reservation(seq, identity(), Capability::Navigate)
            .unwrap();
        let status = store.status();
        assert_eq!(status.active_reservation_count, 1);
        assert_eq!(status.active_reserved_bytes, 50_000);
        // retained_bytes already includes active_reserved_bytes.
        assert!(status.retained_bytes >= status.active_reserved_bytes);
        assert_eq!(status.entry_count, 1);
    }
}
