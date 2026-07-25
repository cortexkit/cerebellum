//! Converts late events from the core journal event queue into the browser-facing
//! journal API.

use std::collections::{BTreeMap, VecDeque};

use cerebellum_core::journal as core_journal;

use super::store::JournalStore;
use super::{
    GoverningObservation, GrantDecision, JournalEntry, JournalIdentity, Outcome, Phase,
    PolicyEventDetail, FORMAT_VERSION,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryRoute {
    Direct,
    Wait,
    RecordOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyEventPayload {
    pub detail: PolicyEventDetail,
    pub identity: JournalIdentity,
    pub route: DeliveryRoute,
    /// The outcome reported to a waiting caller.  Required rather than optional:
    /// an absent outcome would have to be given a meaning at delivery, and every
    /// available meaning is a claim -- reporting success asserts a result nobody
    /// established, and reporting a failure invents one.  The admitting caller
    /// always knows the outcome, so the ambiguous state is removed rather than
    /// resolved by a default.
    pub outcome: Outcome,
    pub outcome_detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateEventError {
    QueueFull,
    AllocatorFailed,
    CommitmentFailed,
    Backpressure,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitOutcome {
    Direct,
    Wait,
    RecordOnly,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WaitDelivery {
    pub sequence: u64,
    pub outcome: Outcome,
    pub detail: serde_json::Value,
}

pub struct LateEventQueue {
    core: core_journal::LateEventQueue,
    admission_order: VecDeque<core_journal::LateEventSequence>,
    payloads: BTreeMap<u64, PolicyEventPayload>,
    tokens: BTreeMap<u64, core_journal::LateEventSequence>,
    actual_sequences: BTreeMap<u64, u64>,
    terminal_audit_unavailable: bool,
}

impl LateEventQueue {
    pub fn new(queue_max: usize) -> Result<Self, LateEventError> {
        Ok(Self {
            core: core_journal::LateEventQueue::new(queue_max).map_err(map_error)?,
            admission_order: VecDeque::new(),
            payloads: BTreeMap::new(),
            tokens: BTreeMap::new(),
            actual_sequences: BTreeMap::new(),
            terminal_audit_unavailable: false,
        })
    }

    pub fn combined_count(&self) -> usize {
        self.core.combined_count()
    }

    pub fn is_audit_failed(&self) -> bool {
        self.core.has_uncommitted()
    }

    pub fn audit_suspension_active(&self) -> bool {
        self.is_audit_failed()
    }

    pub fn is_terminal_audit_unavailable(&self) -> bool {
        self.terminal_audit_unavailable
    }

    pub fn obligation_count(&self) -> usize {
        self.core.uncommitted_count()
    }

    pub fn wait_item_count(&self) -> usize {
        self.core.committed_count(core_journal::DeliveryRoute::Wait)
    }

    pub fn admit(
        &mut self,
        payload: PolicyEventPayload,
    ) -> Result<PolicyEventPayload, LateEventError> {
        let descriptor = core_journal::LateEventDescriptor {
            identity: JournalStore::browser_identity(&payload.identity),
            opaque_bytes: serde_json::to_vec(&payload.detail)
                .map_err(|_| LateEventError::CommitmentFailed)?,
        };
        let token = self
            .core
            .admit_late_event(descriptor, route(payload.route))
            .map_err(map_error)?;
        self.admission_order.push_back(token);
        self.tokens.insert(token.get(), token);
        self.payloads.insert(token.get(), payload.clone());
        Ok(payload)
    }

    pub fn commit(
        &mut self,
        store: &mut JournalStore,
        payload: PolicyEventPayload,
    ) -> Result<CommitOutcome, LateEventError> {
        let token = self
            .admission_order
            .front()
            .copied()
            .ok_or(LateEventError::CommitmentFailed)?;
        let actual = match store.reserve_policy_event(&payload.identity) {
            Ok(handle) => handle,
            Err(_) => {
                self.admission_order.pop_front();
                self.payloads.remove(&token.get());
                self.tokens.remove(&token.get());
                self.tokens.remove(&token.get());
                self.core.release_late_event(token);
                self.terminal_audit_unavailable = true;
                return Err(LateEventError::AllocatorFailed);
            }
        };
        let entry = build_policy_event_entry(actual.sequence(), &payload);
        if store
            .commit_reserved_policy(actual, entry.export_line().into_bytes())
            .is_err()
        {
            self.admission_order.pop_front();
            self.actual_sequences.insert(token.get(), actual.sequence());
            return Err(LateEventError::CommitmentFailed);
        }
        self.admission_order.pop_front();
        self.actual_sequences.insert(token.get(), actual.sequence());
        self.core.commit_late_event(token).map_err(map_error)?;
        match payload.route {
            DeliveryRoute::Direct => {
                self.core.release_late_event(token);
                self.payloads.remove(&token.get());
                self.tokens.remove(&token.get());
                Ok(CommitOutcome::Direct)
            }
            DeliveryRoute::RecordOnly => {
                self.core.release_late_event(token);
                self.payloads.remove(&token.get());
                self.tokens.remove(&token.get());
                Ok(CommitOutcome::RecordOnly)
            }
            DeliveryRoute::Wait => Ok(CommitOutcome::Wait),
        }
    }

    pub fn recover_obligations(&mut self, store: &mut JournalStore) {
        for outcome in store.recover_all() {
            let Some((&local, _)) = self
                .actual_sequences
                .iter()
                .find(|(_, actual)| **actual == outcome.sequence)
            else {
                continue;
            };
            let Some(&token) = self.tokens.get(&local) else {
                continue;
            };
            if !self.core.recover_late_event(token) {
                continue;
            }
            if self
                .payloads
                .get(&local)
                .is_some_and(|payload| payload.route != DeliveryRoute::Wait)
            {
                self.core.release_late_event(token);
                self.payloads.remove(&local);
                self.tokens.remove(&local);
            }
        }
    }

    pub fn wait_for(&mut self, store: &mut JournalStore) -> Result<WaitDelivery, LateEventError> {
        self.recover_obligations(store);
        let delivery = self
            .core
            .take_late_delivery(core_journal::DeliveryRoute::Wait)
            .map_err(map_error)?;
        let local = delivery.sequence.get();
        let payload = self
            .payloads
            .get(&local)
            .ok_or(LateEventError::Backpressure)?;
        let sequence = self.actual_sequences.get(&local).copied().unwrap_or(local);
        Ok(WaitDelivery {
            sequence,
            outcome: payload.outcome,
            detail: payload
                .outcome_detail
                .clone()
                .unwrap_or(serde_json::Value::Null),
        })
    }

    pub fn confirm_wait_delivery(&mut self, sequence: u64) -> bool {
        let Some((&local, _)) = self
            .actual_sequences
            .iter()
            .find(|(_, actual)| **actual == sequence)
        else {
            return false;
        };
        let confirmed = self
            .core
            .confirm_late_delivery(*self.tokens.get(&local).unwrap());
        if confirmed {
            self.payloads.remove(&local);
            self.tokens.remove(&local);
            self.actual_sequences.remove(&local);
        }
        confirmed
    }

    pub fn abandon_on_teardown(&mut self) {
        self.abandon_all();
    }

    pub fn abandon_on_process_failure(&mut self) {
        self.abandon_all();
    }

    pub fn abandon_on_restart(&mut self) {
        self.abandon_all();
    }

    fn abandon_all(&mut self) {
        let tokens: Vec<u64> = self.payloads.keys().copied().collect();
        for local in tokens {
            let Some(&token) = self.tokens.get(&local) else {
                continue;
            };
            if !self.core.is_committed(token) {
                self.core.release_late_event(token);
                self.payloads.remove(&local);
                self.tokens.remove(&local);
                self.actual_sequences.remove(&local);
            }
        }
        self.admission_order.clear();
    }
}

fn route(route: DeliveryRoute) -> core_journal::DeliveryRoute {
    match route {
        DeliveryRoute::Direct => core_journal::DeliveryRoute::Direct,
        DeliveryRoute::Wait => core_journal::DeliveryRoute::Wait,
        DeliveryRoute::RecordOnly => core_journal::DeliveryRoute::RecordOnly,
    }
}

fn map_error(error: core_journal::LateEventError) -> LateEventError {
    match error.cause {
        core_journal::LateEventCause::QueueFull => LateEventError::QueueFull,
        core_journal::LateEventCause::AllocatorFailed => LateEventError::AllocatorFailed,
        core_journal::LateEventCause::CommitmentFailed => LateEventError::CommitmentFailed,
        core_journal::LateEventCause::Backpressure
        | core_journal::LateEventCause::BoundUnavailable
        | core_journal::LateEventCause::DescriptorRefused => LateEventError::Backpressure,
    }
}

fn build_policy_event_entry(sequence: u64, payload: &PolicyEventPayload) -> JournalEntry {
    let initiating_snapshot_id = match &payload.detail {
        PolicyEventDetail::DownloadBlocked {
            initiating_snapshot_id,
            ..
        }
        | PolicyEventDetail::JsDialogDismissed {
            initiating_snapshot_id,
            ..
        } => initiating_snapshot_id.clone(),
        _ => None,
    };
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
        snapshot_ids: initiating_snapshot_id.into_iter().collect(),
        outcome: None,
        detail: Some(serde_json::to_value(&payload.detail).expect("closed detail serializes")),
    }
}
