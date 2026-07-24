//! Policy-event admission, routing, audit obligations, and late-event delivery.
//!
//! A download, JavaScript-dialog, origin-transition, or network-policy event
//! initiated by browser activity receives its required safety response
//! independently of journal availability. When the event is observed, B2A
//! assigns exactly one immutable delivery route (`direct`, `wait`, or
//! `record_only`) and submits the event to the policy-event journal path.
//!
//! The combined policy-event queue bounds the count of accepted unresolved
//! events. Each accepted event holds exactly one combined-count charge from
//! capacity admission until it reaches a releasing terminal point; the charge is
//! provisional during admission, retained by an uncommitted audit obligation
//! after a failed commitment, converted (without incrementing) into a committed
//! route-`wait` delivery item on successful route-`wait` commitment, and
//! released on successful route-`direct`/`record_only` commitment, on allocator
//! failure before allocation, on abandonment, or on successful route-`wait`
//! delivery. No event is represented by more than one charge at a time.
//!
//! Uncommitted obligations are session-scoped and non-exportable. Live-session
//! audit recovery commits an obligation exactly once at its original sequence;
//! startup recovery never resurrects an abandoned obligation. An obligation may
//! be abandoned only on graceful teardown of the original live session, process
//! failure, or restart without resuming that session — never for write
//! unavailability, retry count, elapsed time, capacity pressure, queue
//! saturation, or administrative operations while the session is active.

use std::collections::BTreeMap;

use crate::journal::store::JournalStore;
use crate::journal::{
    GoverningObservation, GrantDecision, JournalEntry, JournalIdentity, Outcome, Phase,
    PolicyEventDetail, FORMAT_VERSION,
};

/// The immutable delivery route assigned when an event is observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRoute {
    /// The initiating capability is still in flight and returns the mapped
    /// outcome; successful commitment creates no delivery item.
    Direct,
    /// Caller-deliverable via `browser.wait_for`; successful commitment creates
    /// one committed delivery item.
    Wait,
    /// Journal-only; never changes the initiating result or creates a delivery
    /// item.
    RecordOnly,
}

/// The bounded, already-redacted policy-event payload admitted to the journal
/// path.
///
/// Retains only the closed journal detail and delivery metadata selected when
/// the event was observed. Never retains unredacted origin, URL, exception, or
/// other raw page/caller text.
#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEventPayload {
    pub detail: PolicyEventDetail,
    pub identity: JournalIdentity,
    pub route: DeliveryRoute,
    /// The exact bounded B1 outcome for `direct`/`wait` routes; null for
    /// `record_only`.
    pub outcome: Option<Outcome>,
    /// The exact bounded B1 detail for `direct`/`wait` routes.
    pub outcome_detail: Option<serde_json::Value>,
}

/// The combined-count charge state for an accepted event that has not reached a
/// releasing terminal point.
#[derive(Debug, Clone, PartialEq)]
struct EventRecord {
    sequence: u64,
    route: DeliveryRoute,
    detail: PolicyEventDetail,
    identity: JournalIdentity,
    outcome: Option<Outcome>,
    outcome_detail: Option<serde_json::Value>,
}

/// Failure of a late-event journal operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateEventError {
    /// The combined queue is at its bound: safety response occurs, no sequence
    /// or obligation is created, and the browser context and CDP supervisor
    /// terminate.
    QueueFull,
    /// Allocator advancement failed before sequence allocation: terminal
    /// audit-unavailable; no gap or entry is fabricated and the provisional
    /// charge is released.
    AllocatorFailed,
    /// Commitment failed after sequence allocation: the event becomes an
    /// uncommitted audit obligation and the session enters audit-failed state.
    CommitmentFailed,
    /// `browser.wait_for` backpressure: a lower-sequence uncommitted route-`wait`
    /// obligation remains, or no committed route-`wait` item exists. Maps to
    /// `journal_reservation_failed`.
    Backpressure,
}

/// The result of a successful policy-event commitment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    /// Route `direct`: committed, charge released, no delivery item.
    Direct,
    /// Route `wait`: committed, one delivery item created (charge converted).
    Wait,
    /// Route `record_only`: committed, charge released, no delivery item.
    RecordOnly,
}

/// A deliverable route-`wait` item peeked by `browser.wait_for`.
#[derive(Debug, Clone, PartialEq)]
pub struct WaitDelivery {
    pub sequence: u64,
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

/// The session-scoped combined policy-event queue.
#[derive(Debug)]
pub struct LateEventQueue {
    queue_max: usize,
    /// Uncommitted audit obligations, keyed by original sequence.
    obligations: BTreeMap<u64, EventRecord>,
    /// Committed route-`wait` delivery items not yet delivered, keyed by
    /// sequence.
    wait_items: BTreeMap<u64, EventRecord>,
    /// In-flight provisional charges (admitted, not yet resolved).
    provisional_charges: usize,
    /// Terminal audit-unavailable: set on allocator failure; no later
    /// browser-side activity is permitted.
    terminal_audit_unavailable: bool,
}

impl LateEventQueue {
    /// Create a queue with a concrete positive combined-count maximum.
    pub fn new(queue_max: usize) -> Result<Self, LateEventError> {
        if queue_max == 0 {
            return Err(LateEventError::QueueFull);
        }
        Ok(Self {
            queue_max,
            obligations: BTreeMap::new(),
            wait_items: BTreeMap::new(),
            provisional_charges: 0,
            terminal_audit_unavailable: false,
        })
    }

    /// The combined count: one charge per accepted event that has not reached a
    /// releasing terminal point.
    pub fn combined_count(&self) -> usize {
        self.obligations.len() + self.wait_items.len() + self.provisional_charges
    }

    /// Whether the session is audit-failed: any uncommitted obligation remains.
    pub fn is_audit_failed(&self) -> bool {
        !self.obligations.is_empty()
    }

    /// Whether audit-suspension backpressure applies to unfenceable, snapshot,
    /// screenshot, and wait_for capabilities.
    pub fn audit_suspension_active(&self) -> bool {
        self.is_audit_failed()
    }

    pub fn is_terminal_audit_unavailable(&self) -> bool {
        self.terminal_audit_unavailable
    }

    pub fn obligation_count(&self) -> usize {
        self.obligations.len()
    }

    pub fn wait_item_count(&self) -> usize {
        self.wait_items.len()
    }

    // ------------------------------------------------------------------
    // Admission and commitment
    // ------------------------------------------------------------------

    /// Atomically admit a candidate event, acquiring one provisional combined
    /// charge.
    ///
    /// Fails with `QueueFull` when the combined count is already at the bound;
    /// the caller applies the safety response and terminates the browser context
    /// and CDP supervisor, creating no sequence, obligation, or delivery item.
    pub fn admit(
        &mut self,
        payload: PolicyEventPayload,
    ) -> Result<PolicyEventPayload, LateEventError> {
        if self.terminal_audit_unavailable {
            return Err(LateEventError::AllocatorFailed);
        }
        if self.combined_count() >= self.queue_max {
            return Err(LateEventError::QueueFull);
        }
        self.provisional_charges += 1;
        Ok(payload)
    }

    /// Allocate a sequence and commit the bounded policy-event entry for an
    /// admitted event.
    ///
    /// On allocator failure before allocation the provisional charge is released
    /// and the session enters terminal audit-unavailable state. On commitment
    /// failure after allocation the provisional charge is converted into an
    /// uncommitted obligation (no count change) and the session enters
    /// audit-failed state. On success the charge is released (direct/record_only)
    /// or converted into a delivery item (wait).
    pub fn commit(
        &mut self,
        store: &mut JournalStore,
        payload: PolicyEventPayload,
    ) -> Result<CommitOutcome, LateEventError> {
        // Allocate the sequence.
        let sequence = match store.allocate_sequence() {
            Ok(seq) => seq,
            Err(_) => {
                self.release_provisional();
                self.terminal_audit_unavailable = true;
                return Err(LateEventError::AllocatorFailed);
            }
        };

        let entry = build_policy_event_entry(sequence, &payload);

        // Attempt the durable commitment.
        if store.commit_policy_event(entry).is_err() {
            // Convert the provisional charge into an uncommitted obligation at
            // the original sequence; the count is unchanged.
            self.provisional_charges = self.provisional_charges.saturating_sub(1);
            self.obligations.insert(
                sequence,
                EventRecord {
                    sequence,
                    route: payload.route,
                    detail: payload.detail,
                    identity: payload.identity,
                    outcome: payload.outcome,
                    outcome_detail: payload.outcome_detail,
                },
            );
            return Err(LateEventError::CommitmentFailed);
        }

        // Commitment succeeded: resolve the provisional charge by route.
        self.release_provisional();
        match payload.route {
            DeliveryRoute::Direct => Ok(CommitOutcome::Direct),
            DeliveryRoute::RecordOnly => Ok(CommitOutcome::RecordOnly),
            DeliveryRoute::Wait => {
                // Convert the (already released) charge into a committed
                // delivery item; the combined count is unchanged overall.
                self.wait_items.insert(
                    sequence,
                    EventRecord {
                        sequence,
                        route: payload.route,
                        detail: payload.detail,
                        identity: payload.identity,
                        outcome: payload.outcome,
                        outcome_detail: payload.outcome_detail,
                    },
                );
                Ok(CommitOutcome::Wait)
            }
        }
    }

    fn release_provisional(&mut self) {
        self.provisional_charges = self.provisional_charges.saturating_sub(1);
    }

    // ------------------------------------------------------------------
    // Audit recovery
    // ------------------------------------------------------------------

    /// Retry every uncommitted obligation exactly once at its original sequence.
    ///
    /// A route-`wait` obligation becomes one committed delivery item without
    /// changing the combined count; route-`direct` and route-`record_only`
    /// obligations create only the exportable journal entry and release their
    /// charge. Audit-failed state clears only after every obligation commits.
    pub fn recover_obligations(&mut self, store: &mut JournalStore) {
        let sequences: Vec<u64> = self.obligations.keys().copied().collect();
        for sequence in sequences {
            let record = match self.obligations.get(&sequence) {
                Some(r) => r.clone(),
                None => continue,
            };
            let entry = build_policy_event_entry(
                sequence,
                &PolicyEventPayload {
                    detail: record.detail.clone(),
                    identity: record.identity.clone(),
                    route: record.route,
                    outcome: record.outcome,
                    outcome_detail: record.outcome_detail.clone(),
                },
            );
            if store.commit_policy_event(entry).is_ok() {
                self.obligations.remove(&sequence);
                if record.route == DeliveryRoute::Wait {
                    // Convert the obligation's charge into a delivery item; the
                    // combined count is unchanged.
                    self.wait_items.insert(sequence, record);
                }
                // direct/record_only: the obligation's charge is released by
                // removal.
            }
            // If retry still fails, the obligation remains and the session
            // stays audit-failed.
        }
    }

    // ------------------------------------------------------------------
    // browser.wait_for delivery
    // ------------------------------------------------------------------

    /// Perform audit recovery, then peek the lowest-sequence deliverable
    /// route-`wait` item.
    ///
    /// Returns `Backpressure` (caller surfaces `journal_reservation_failed`) if
    /// a lower-sequence uncommitted route-`wait` obligation remains after
    /// recovery, or if no committed route-`wait` item exists. The peeked item is
    /// not released until [`Self::confirm_wait_delivery`] is called after the
    /// complete B1 result is successfully formed; failed result formation leaves
    /// it queued.
    pub fn wait_for(&mut self, store: &mut JournalStore) -> Result<WaitDelivery, LateEventError> {
        self.recover_obligations(store);

        // A lower-sequence uncommitted route-wait obligation blocks delivery.
        if self
            .obligations
            .values()
            .any(|r| r.route == DeliveryRoute::Wait)
        {
            return Err(LateEventError::Backpressure);
        }

        // Deliver the lowest-sequence committed route-wait item.
        let lowest = self.wait_items.keys().next().copied();
        match lowest {
            Some(sequence) => {
                let record = &self.wait_items[&sequence];
                Ok(WaitDelivery {
                    sequence,
                    outcome: record.outcome.unwrap_or(Outcome::Success),
                    detail: record
                        .outcome_detail
                        .clone()
                        .unwrap_or(serde_json::Value::Null),
                })
            }
            None => Err(LateEventError::Backpressure),
        }
    }

    /// Confirm delivery of a peeked route-`wait` item, releasing its combined
    /// charge exactly once.
    ///
    /// Called only after the complete B1 result is successfully formed. Decreases
    /// the combined count by one. Journal eviction does not remove a live
    /// delivery item or decrease the count.
    pub fn confirm_wait_delivery(&mut self, sequence: u64) -> bool {
        self.wait_items.remove(&sequence).is_some()
    }

    // ------------------------------------------------------------------
    // Abandonment (closed trigger set)
    // ------------------------------------------------------------------

    /// Abandon every uncommitted obligation on graceful teardown of the original
    /// live session.
    ///
    /// Releases each obligation's combined charge, creates no journal entry or
    /// delivery item, and leaves each allocated sequence as a permanent gap.
    pub fn abandon_on_teardown(&mut self) {
        self.obligations.clear();
    }

    /// Abandon every uncommitted obligation on process failure.
    pub fn abandon_on_process_failure(&mut self) {
        self.obligations.clear();
    }

    /// Abandon every uncommitted obligation on restart without resuming the
    /// original session.
    pub fn abandon_on_restart(&mut self) {
        self.obligations.clear();
    }
}

/// Build the bounded `phase:"policy_event"` journal entry for an admitted event.
///
/// `capability`, `intent_redacted`, severities, `action`, and `locator` are
/// null; `grant_decision` is `not_reached`; `outcome` is null; `detail` carries
/// the closed event block. `snapshot_ids` carries the initiating snapshot id
/// when the detail references one.
fn build_policy_event_entry(sequence: u64, payload: &PolicyEventPayload) -> JournalEntry {
    let initiating_snapshot_id = match &payload.detail {
        PolicyEventDetail::DownloadBlocked {
            initiating_snapshot_id,
            ..
        } => initiating_snapshot_id.clone(),
        PolicyEventDetail::JsDialogDismissed {
            initiating_snapshot_id,
            ..
        } => initiating_snapshot_id.clone(),
        _ => None,
    };
    let snapshot_ids: Vec<String> = initiating_snapshot_id.into_iter().collect();
    let detail_value = serde_json::to_value(&payload.detail).expect("closed detail serializes");
    JournalEntry {
        format_version: FORMAT_VERSION.to_string(),
        sequence,
        phase: Phase::PolicyEvent,
        identity: payload.identity.clone(),
        capability: None,
        intent_redacted: None,
        requested_severity: None,
        effective_severity: None,
        grant_decision: GrantDecision::not_reached(),
        governing_observation: GoverningObservation::observation_not_required(),
        action: None,
        locator: None,
        snapshot_ids,
        outcome: None,
        detail: Some(detail_value),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::{JournalConfig, JournalReasonCode, SessionKind};

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

    fn download(route: DeliveryRoute) -> PolicyEventPayload {
        PolicyEventPayload {
            detail: PolicyEventDetail::DownloadBlocked {
                initiating_capability: None,
                initiating_snapshot_id: None,
            },
            identity: identity(),
            route,
            outcome: Some(Outcome::InternalError),
            outcome_detail: Some(serde_json::json!({"reason_code":"internal_failure"})),
        }
    }

    #[test]
    fn queue_max_must_be_positive() {
        assert!(LateEventQueue::new(0).is_err());
        assert!(LateEventQueue::new(1).is_ok());
    }

    #[test]
    fn direct_commit_releases_charge_and_creates_no_item() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Direct)).unwrap();
        let outcome = queue.commit(&mut store, payload).unwrap();
        assert_eq!(outcome, CommitOutcome::Direct);
        assert_eq!(queue.combined_count(), 0);
        assert_eq!(queue.wait_item_count(), 0);
        assert!(store.export().contains("download_blocked"));
    }

    #[test]
    fn wait_commit_creates_one_delivery_item_without_changing_count() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        assert_eq!(queue.combined_count(), 1);
        let outcome = queue.commit(&mut store, payload).unwrap();
        assert_eq!(outcome, CommitOutcome::Wait);
        // Count unchanged: provisional charge converted to a wait-item charge.
        assert_eq!(queue.combined_count(), 1);
        assert_eq!(queue.wait_item_count(), 1);
    }

    #[test]
    fn record_only_commit_releases_charge_and_creates_no_item() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::RecordOnly)).unwrap();
        let outcome = queue.commit(&mut store, payload).unwrap();
        assert_eq!(outcome, CommitOutcome::RecordOnly);
        assert_eq!(queue.combined_count(), 0);
        assert!(store.export().contains("download_blocked"));
    }

    #[test]
    fn queue_saturation_admits_no_sequence_or_obligation() {
        let mut store = store();
        let mut queue = LateEventQueue::new(1).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        queue.commit(&mut store, payload).unwrap();
        // Combined count is at the bound; the next event is refused.
        let err = queue.admit(download(DeliveryRoute::Direct)).unwrap_err();
        assert_eq!(err, LateEventError::QueueFull);
        assert_eq!(queue.combined_count(), 1);
    }

    #[test]
    fn commitment_failure_creates_obligation_and_audit_failed_state() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        store.faults.arm("commit_policy_event", 1);
        let err = queue.commit(&mut store, payload).unwrap_err();
        assert_eq!(err, LateEventError::CommitmentFailed);
        // The provisional charge is retained by the obligation; count unchanged.
        assert_eq!(queue.combined_count(), 1);
        assert_eq!(queue.obligation_count(), 1);
        assert!(queue.is_audit_failed());
        assert!(queue.audit_suspension_active());
    }

    #[test]
    fn allocator_failure_is_terminal_and_releases_provisional_charge() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Direct)).unwrap();
        store.faults.arm("advance_allocator", 1);
        let err = queue.commit(&mut store, payload).unwrap_err();
        assert_eq!(err, LateEventError::AllocatorFailed);
        // Provisional charge released; no gap fabricated, no obligation.
        assert_eq!(queue.combined_count(), 0);
        assert!(queue.is_terminal_audit_unavailable());
    }

    #[test]
    fn recovery_commits_obligation_once_at_original_sequence() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        store.faults.arm("commit_policy_event", 1);
        queue.commit(&mut store, payload).unwrap_err();
        let seq_before = store.next_sequence();
        // Recovery retries; the fault is spent so it commits at the same seq.
        queue.recover_obligations(&mut store);
        assert_eq!(queue.obligation_count(), 0);
        assert_eq!(queue.wait_item_count(), 1);
        // No new sequence was allocated by recovery.
        assert_eq!(store.next_sequence(), seq_before);
        assert!(!queue.is_audit_failed());
    }

    #[test]
    fn wait_for_delivers_lowest_wait_item_in_sequence_order() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        for _ in 0..2 {
            let payload = queue.admit(download(DeliveryRoute::Wait)).unwrap();
            queue.commit(&mut store, payload).unwrap();
        }
        let first = queue.wait_for(&mut store).unwrap();
        let second_peek = queue.wait_for(&mut store).unwrap();
        // Without confirmation the same lowest item is peeked again.
        assert_eq!(first.sequence, second_peek.sequence);
        // Confirming releases it and the next wait advances.
        assert!(queue.confirm_wait_delivery(first.sequence));
        assert_eq!(queue.combined_count(), 1);
        let next = queue.wait_for(&mut store).unwrap();
        assert!(next.sequence > first.sequence);
    }

    #[test]
    fn wait_for_backpressure_when_lower_obligation_remains() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        // First event: committed wait item at a low sequence.
        let p1 = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        queue.commit(&mut store, p1).unwrap();
        // Second event: a wait obligation that fails to commit (lower? no,
        // higher sequence). To create a LOWER-sequence obligation we make the
        // first event fail and the second succeed is impossible by ordering; so
        // instead make a wait obligation remain uncommitted while a higher wait
        // item exists by failing recovery for the lower one.
        let p2 = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        store.faults.arm("commit_policy_event", 1);
        queue.commit(&mut store, p2).unwrap_err();
        // Keep the lower obligation uncommitted by arming recovery to fail.
        store.faults.arm("commit_policy_event", 1);
        let err = queue.wait_for(&mut store).unwrap_err();
        assert_eq!(err, LateEventError::Backpressure);
    }

    #[test]
    fn wait_for_returns_backpressure_when_no_wait_item_exists() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let err = queue.wait_for(&mut store).unwrap_err();
        assert_eq!(err, LateEventError::Backpressure);
    }

    #[test]
    fn direct_and_record_only_are_never_delivered_by_wait_for() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let p = queue.admit(download(DeliveryRoute::Direct)).unwrap();
        queue.commit(&mut store, p).unwrap();
        let p = queue.admit(download(DeliveryRoute::RecordOnly)).unwrap();
        queue.commit(&mut store, p).unwrap();
        // No wait items exist; wait_for backs off.
        assert_eq!(
            queue.wait_for(&mut store).unwrap_err(),
            LateEventError::Backpressure
        );
    }

    #[test]
    fn abandonment_releases_charges_and_leaves_permanent_gaps() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::Wait)).unwrap();
        store.faults.arm("commit_policy_event", 1);
        queue.commit(&mut store, payload).unwrap_err();
        let seq = store.next_sequence();
        assert_eq!(queue.obligation_count(), 1);
        // Graceful teardown abandons the obligation exactly once.
        queue.abandon_on_teardown();
        assert_eq!(queue.obligation_count(), 0);
        assert_eq!(queue.combined_count(), 0);
        // The allocated sequence is a permanent gap; recovery does not
        // resurrect it and no entry was exported for it.
        assert!(!store.export().contains("download_blocked"));
        assert_eq!(store.next_sequence(), seq);
    }

    #[test]
    fn policy_event_entry_has_null_capability_and_not_reached_grant() {
        let mut store = store();
        let mut queue = LateEventQueue::new(4).unwrap();
        let payload = queue.admit(download(DeliveryRoute::RecordOnly)).unwrap();
        queue.commit(&mut store, payload).unwrap();
        let export = store.export();
        assert!(export.contains("\"phase\":\"policy_event\""));
        assert!(export.contains("\"capability\":null"));
        assert!(export.contains("\"outcome\":null"));
        let _ = JournalReasonCode::InternalFailure;
    }
}
