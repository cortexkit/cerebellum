//! Content-free policy events and recovery of failed commits per source unit.

use std::sync::{Arc, Mutex};

use cerebellum_ability::{BoundScope, Platform, Token};
use serde_json::{json, Map, Value};

use super::{binding::Install, Refusal, CALL, SETUP};
use crate::{
    journal::{
        reservation::ReservationHandle, store::JournalStore, GoverningObservation, GrantDecision,
        JournalEntry, JournalError, JournalIdentity, Phase, FORMAT_VERSION,
    },
    AcceptedBindFacts,
};

#[derive(Clone)]
pub(super) struct Summary {
    outcome: String,
    item_count: Option<usize>,
}

impl Summary {
    pub(super) fn from_result(result: &Result<Option<Value>, Refusal>) -> Self {
        let (outcome, item_count) = match result {
            Err(refusal) => (refusal.wire().0.to_owned(), None),
            Ok(None) => ("stopped".into(), None),
            Ok(Some(reply)) => {
                if let Some(state) = reply.get("state").and_then(Value::as_str) {
                    (state.to_owned(), None)
                } else {
                    let count = reply
                        .get("items")
                        .or_else(|| reply.get("choices"))
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .or_else(|| reply.get("item").map(|_| 1));
                    ("ok".into(), count)
                }
            }
        };
        Self {
            outcome,
            item_count,
        }
    }
}

/// Only a successful reservation creates this proof. A plane explicitly built
/// without a journal also succeeds, but allocates no durable reservation.
/// The completion slot retains counts, never data, after a route has closed.
pub(super) struct ReservedRead {
    completion: Arc<Mutex<Option<Summary>>>,
}

impl ReservedRead {
    pub(super) fn completion(&self) -> Arc<Mutex<Option<Summary>>> {
        self.completion.clone()
    }
}

pub(super) struct Reservation {
    handle: Option<ReservationHandle>,
    entry: Option<JournalEntry>,
    completion: Arc<Mutex<Option<Summary>>>,
}

pub(super) fn detail(
    facts: &AcceptedBindFacts,
    platform: Platform,
    method: &str,
    token: Token,
    params: &Map<String, Value>,
    call: Option<(&BoundScope, &Install)>,
) -> Value {
    let ids = call.and_then(|(scope, _)| {
        if platform != Platform::MacOs
            || !matches!(token, Token::Calendar | Token::Reminders | Token::Contacts)
        {
            return None;
        }
        let ids = json!(scope.ids());
        (serde_json::to_vec(&ids).expect("ids serialize").len() <= 16 * 1024).then_some(ids)
    });
    json!({
        "event": method,
        "token": token.as_str(),
        "op": if method == CALL { params.get("op") } else { None },
        "key": if method != SETUP { params.get("key") } else { None },
        "flow_id": call.and(facts.flow_id.as_deref()),
        "run_id": call.and_then(|_| facts.scope.as_ref().and_then(|s| s.attributes.run_id.as_deref())),
        "install_id": call.map(|(_, install)| &install.0),
        "install_version": call.map(|(_, install)| &install.1),
        "bound_count": call.map(|(scope, _)| scope.ids().len()),
        "bound_ids": ids,
        "outcome": null,
        "item_count": null,
    })
}

pub(super) fn reserve(
    store: Option<&mut JournalStore>,
    pending: &mut Option<u64>,
    facts: &AcceptedBindFacts,
    detail: Value,
) -> Result<Reservation, JournalError> {
    let completion = Arc::default();
    let Some(store) = store else {
        return Ok(Reservation {
            handle: None,
            entry: None,
            completion,
        });
    };
    if let Some(sequence) = *pending {
        if !store.recover_policy_event(sequence) {
            return Err(JournalError::internal_failure());
        }
        *pending = None;
    }
    let identity = JournalIdentity {
        principal: crate::principal_label(&facts.principal),
        ..crate::browser::journal_identity(&facts.identity)
    };
    let handle = store.reserve_policy_event(&identity)?;
    *pending = Some(handle.sequence());
    let entry = JournalEntry {
        format_version: FORMAT_VERSION.into(),
        sequence: handle.sequence(),
        phase: Phase::Dispatched,
        identity,
        capability: None,
        intent_redacted: None,
        requested_severity: None,
        effective_severity: None,
        grant_decision: GrantDecision::not_reached(),
        governing_observation: GoverningObservation::observation_not_required(),
        action: None,
        locator: None,
        snapshot_ids: Vec::new(),
        outcome: None,
        payload: None,
        detail: Some(detail),
    };
    Ok(Reservation {
        handle: Some(handle),
        entry: Some(entry),
        completion,
    })
}

impl Reservation {
    pub(super) fn proof(&self) -> ReservedRead {
        ReservedRead {
            completion: self.completion.clone(),
        }
    }

    pub(super) fn commit(
        mut self,
        store: Option<&mut JournalStore>,
        pending: &mut Option<u64>,
        result: &Result<Option<Value>, Refusal>,
    ) -> Result<(), JournalError> {
        let Some(handle) = self.handle else {
            return Ok(());
        };
        let summary = if matches!(result, Ok(None)) {
            self.completion
                .lock()
                .unwrap()
                .take()
                .unwrap_or_else(|| Summary::from_result(result))
        } else {
            Summary::from_result(result)
        };
        let entry = self.entry.as_mut().expect("reserved entry");
        let detail = entry.detail.as_mut().expect("policy detail");
        detail["outcome"] = json!(summary.outcome);
        detail["item_count"] = json!(summary.item_count);
        store
            .ok_or_else(JournalError::internal_failure)?
            .commit_reserved_policy(handle, entry.export_line().into_bytes())?;
        *pending = None;
        Ok(())
    }
}
