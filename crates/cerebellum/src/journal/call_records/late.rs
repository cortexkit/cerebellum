//! Text-free handoff settlements share the keyed-call journal so a crash
//! cannot orphan a held reply. Sequence numbers belong to one process only;
//! settlement identity and acknowledgements survive a restart.

use super::*;
use cortexkit_role_tool_provider::late_results::{
    self, AckRequest, Cursor, LateEntry, LateResultsReply, LateResultsRequest,
};
use sha2::{Digest, Sha256};

const RESULT_RETENTION_MS: u64 = 24 * 60 * 60 * 1000;
const MAX_RESULTS: usize = 1000;
const MAX_EXPIRED: usize = 1000;

#[derive(Hash, PartialEq, Eq)]
enum RetentionGroup {
    Session {
        owner: String,
        reference: String,
        epoch: u64,
    },
    ExpiredOwner(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffEnding {
    LoginObserved,
    HandoffExpired,
    ClosedByCaller,
    HandoffInterrupted,
}

impl HandoffEnding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LoginObserved => "login_observed",
            Self::HandoffExpired => "handoff_expired",
            Self::ClosedByCaller => "closed_by_caller",
            Self::HandoffInterrupted => "handoff_interrupted",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
enum Phase {
    Pending,
    Result {
        outcome: HandoffEnding,
        settled_at: u64,
    },
    Expired {
        event_id: String,
        settled_at: u64,
    },
    Acked,
}

/// Only a canonical origin and closed outcome codes are persisted. In
/// particular, the CDP observations used to detect login never enter this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldHandoff {
    origin: String,
    scope: ScopeIdentity,
    phase: Phase,
}

pub(super) fn incarnation() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("a provider incarnation requires OS randomness");
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

pub(super) fn unacked(record: &CallRecord) -> bool {
    record
        .handoff
        .as_ref()
        .is_some_and(|handoff| !matches!(handoff.phase, Phase::Acked))
}

fn event_id(
    record: &CallRecord,
    handoff: &HeldHandoff,
    outcome: HandoffEnding,
    settled_at: u64,
) -> String {
    // Hash a tuple, not concatenated strings: opaque identifiers can contain
    // separators, and two distinct settlements must not share a dedupe key.
    let bytes = serde_json::to_vec(&(
        "browser-handoff/v1",
        &record.principal,
        &record.call_key,
        &handoff.scope,
        &handoff.origin,
        outcome,
        settled_at,
    ))
    .expect("text-free settlement identity serializes");
    format!("{:x}", Sha256::digest(bytes))
}

fn next_seq(inner: &mut Inner, key: &Key) {
    let head = inner.late_heads.entry(key.0.clone()).or_default();
    *head += 1;
    inner
        .entries
        .get_mut(key)
        .expect("sequenced record exists")
        .late_seq = Some(*head);
}

pub(super) fn reconcile(inner: &mut Inner, now_ms: u64) -> bool {
    let mut changed = false;
    let mut keys = Vec::new();
    for (key, entry) in &mut inner.entries {
        let Some(handoff) = entry.record.handoff.as_mut() else {
            continue;
        };
        if matches!(handoff.phase, Phase::Pending) {
            handoff.phase = Phase::Result {
                outcome: HandoffEnding::HandoffInterrupted,
                settled_at: now_ms,
            };
            entry.record.outcome = Some(HandoffEnding::HandoffInterrupted.as_str().into());
            entry.record.state = CallState::Replied;
            entry.record.settled_at_ms = Some(now_ms);
            changed = true;
        }
        if let Phase::Result { settled_at, .. } | Phase::Expired { settled_at, .. } = handoff.phase
        {
            keys.push((settled_at, key.clone()));
        }
    }
    keys.sort();
    for (_, key) in keys {
        next_seq(inner, &key);
    }
    changed
}

fn wire_entry(record: &CallRecord) -> Option<LateEntry> {
    let handoff = record.handoff.as_ref()?;
    let (kind, id, settled_at, result) = match &handoff.phase {
        Phase::Result {
            outcome,
            settled_at,
        } => (
            late_results::kinds::RESULT,
            event_id(record, handoff, *outcome, *settled_at),
            *settled_at,
            Some(json!({"outcome": outcome.as_str(), "origin": handoff.origin})),
        ),
        Phase::Expired {
            event_id,
            settled_at,
        } => (
            late_results::kinds::EXPIRED,
            event_id.clone(),
            *settled_at,
            None,
        ),
        Phase::Pending | Phase::Acked => return None,
    };
    let mut entry = LateEntry::new(
        kind,
        &handoff.scope.owner,
        &handoff.scope.reference,
        handoff.scope.scope_epoch,
        &record.principal,
        &record.call_key,
        id,
        settled_at,
    );
    if let Some(result) = result {
        entry = entry.with_result(result);
    }
    Some(entry)
}

pub(super) fn settled_result(record: &CallRecord) -> Option<Value> {
    let handoff = record.handoff.as_ref()?;
    if matches!(handoff.phase, Phase::Pending) {
        return None;
    }
    let outcome = record.outcome.as_deref()?;
    Some(json!({"outcome":outcome,"origin":handoff.origin}))
}

impl CallRecords {
    /// Sync the recovery obligation before returning `login_pending`. Without
    /// this write, a crash could leave the custodian waiting for a result forever.
    pub fn hold_handoff(
        &self,
        principal: &str,
        call_key: &str,
        conversation: &str,
        scope: ScopeIdentity,
        origin: &str,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        if crate::classification::canonical_grant_origin(origin).as_deref() != Some(origin) {
            return Err(CallRecordError::Corrupt(
                "handoff origin is not canonical".into(),
            ));
        }
        let mut inner = self.lock();
        if let Some(error) = &inner.broken {
            return Err(error.clone());
        }
        let key = (principal.to_owned(), call_key.to_owned());
        let mut record = inner
            .entries
            .get(&key)
            .ok_or_else(|| CallRecordError::Corrupt("held call has no record".into()))?
            .record
            .clone();
        record.handoff = Some(HeldHandoff {
            origin: origin.to_owned(),
            scope,
            phase: Phase::Pending,
        });
        self.write(&mut inner, &record, now_ms)?;
        inner
            .entries
            .get_mut(&key)
            .expect("held record exists")
            .record = record;
        inner.handoffs.insert(conversation.to_owned(), key);
        Ok(())
    }

    /// Idempotent even if a poll races resume or browser teardown. The first
    /// terminal observation wins, and a later one cannot recreate an acked entry.
    pub fn finish_handoff(
        &self,
        principal: &str,
        call_key: &str,
        outcome: HandoffEnding,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        let key = (principal.to_owned(), call_key.to_owned());
        self.finish_handoff_locked(&mut inner, &key, outcome, now_ms)
    }

    fn finish_handoff_locked(
        &self,
        inner: &mut Inner,
        key: &Key,
        outcome: HandoffEnding,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let Some(entry) = inner.entries.get(key) else {
            return Ok(());
        };
        let mut record = entry.record.clone();
        let Some(handoff) = record.handoff.as_mut() else {
            return Ok(());
        };
        if !matches!(handoff.phase, Phase::Pending) {
            return Ok(());
        }
        handoff.phase = Phase::Result {
            outcome,
            settled_at: now_ms,
        };
        record.outcome = Some(outcome.as_str().into());
        record.state = CallState::Replied;
        record.settled_at_ms = Some(now_ms);
        self.write(inner, &record, now_ms)?;
        let result = settled_result(&record).expect("settled handoff has a result");
        let entry = inner.entries.get_mut(key).expect("settled record exists");
        entry.record = record;
        // A resend must not receive login_pending after its entry was acked:
        // that would create another hold with no remaining settlement to pull.
        if let Some(reply) = entry.reply.as_mut() {
            reply.frame.body = serde_json::to_vec(&result).expect("handoff result serializes");
            inner.cached_bytes -= entry.reply_bytes;
            entry.reply_bytes = reply.frame.body.len();
            inner.cached_bytes += entry.reply_bytes;
        }
        inner.handoffs.retain(|_, held_key| held_key != key);
        next_seq(inner, key);
        self.bound_late(inner, now_ms)?;
        Ok(())
    }

    /// Hold the record lock while resume consumes the session's ending, so a
    /// concurrent poll cannot mistake that consumption for an interrupted login.
    pub(crate) fn resume_handoff(
        &self,
        conversation: &str,
        now_ms: u64,
        resume: impl FnOnce() -> Result<
            crate::browser_session::HandoffClose,
            crate::browser_session::ResumeRefusal,
        >,
    ) -> Result<crate::browser_session::HandoffClose, crate::browser_session::ResumeRefusal> {
        let mut inner = self.lock();
        let close = resume()?;
        if let Some(key) = inner.handoffs.get(conversation).cloned() {
            let _ = self.finish_handoff_locked(
                &mut inner,
                &key,
                crate::handoff_ending(close.outcome),
                now_ms,
            );
        }
        Ok(close)
    }

    pub(super) fn bound_late(&self, inner: &mut Inner, now_ms: u64) -> Result<(), CallRecordError> {
        let mut expiring = Vec::new();
        for (key, entry) in &inner.entries {
            let Some(handoff) = &entry.record.handoff else {
                continue;
            };
            if let Phase::Result {
                outcome,
                settled_at,
            } = handoff.phase
            {
                if now_ms.saturating_sub(settled_at) >= RESULT_RETENTION_MS {
                    let mut record = entry.record.clone();
                    record.handoff.as_mut().expect("handoff exists").phase = Phase::Expired {
                        event_id: event_id(&entry.record, handoff, outcome, settled_at),
                        settled_at,
                    };
                    expiring.push((key.clone(), record));
                }
            }
        }
        for (key, record) in expiring {
            self.write(inner, &record, now_ms)?;
            inner
                .entries
                .get_mut(&key)
                .expect("expired record exists")
                .record = record;
            next_seq(inner, &key);
        }
        let mut groups: HashMap<RetentionGroup, Vec<(u64, Key)>> = HashMap::new();
        for (key, entry) in &inner.entries {
            let Some(handoff) = &entry.record.handoff else {
                continue;
            };
            let (expired, settled_at) = match handoff.phase {
                Phase::Result { settled_at, .. } => (false, settled_at),
                Phase::Expired { settled_at, .. } => (true, settled_at),
                _ => continue,
            };
            let group = if expired {
                RetentionGroup::ExpiredOwner(handoff.scope.owner.clone())
            } else {
                RetentionGroup::Session {
                    owner: handoff.scope.owner.clone(),
                    reference: handoff.scope.reference.clone(),
                    epoch: handoff.scope.scope_epoch,
                }
            };
            groups
                .entry(group)
                .or_default()
                .push((settled_at, key.clone()));
        }
        for (group, mut entries) in groups {
            let max = if matches!(group, RetentionGroup::ExpiredOwner(_)) {
                MAX_EXPIRED
            } else {
                MAX_RESULTS
            };
            entries.sort();
            let excess = entries.len().saturating_sub(max);
            for (_, key) in entries.into_iter().take(excess) {
                self.ack_key(inner, &key, now_ms)?;
            }
        }
        Ok(())
    }

    fn ack_key(&self, inner: &mut Inner, key: &Key, now_ms: u64) -> Result<(), CallRecordError> {
        let mut record = inner
            .entries
            .get(key)
            .expect("acked record exists")
            .record
            .clone();
        record.handoff.as_mut().expect("acked handoff exists").phase = Phase::Acked;
        self.write(inner, &record, now_ms)?;
        let entry = inner.entries.get_mut(key).expect("acked record exists");
        entry.record = record;
        entry.late_seq = None;
        Ok(())
    }

    pub fn late_results(
        &self,
        principal: &str,
        request: &LateResultsRequest,
        now_ms: u64,
    ) -> Result<LateResultsReply, subc_protocol::ErrorBody> {
        let mut inner = self.lock();
        self.bound_late(&mut inner, now_ms).map_err(store_error)?;
        if let Some(error) = inner.broken.clone() {
            return Err(store_error(error));
        }
        let head = inner.late_heads.get(principal).copied().unwrap_or(0);
        late_results::check_since(&inner.incarnation, head, request.since.as_ref())?;
        let since = request.since.as_ref().map_or(0, |cursor| cursor.seq);
        let mut entries: Vec<_> = inner
            .entries
            .values()
            .filter(|entry| entry.record.principal == principal)
            .filter_map(|entry| Some((entry.late_seq?, wire_entry(&entry.record)?)))
            .filter(|(seq, _)| *seq > since)
            .collect();
        entries.sort_by_key(|(seq, _)| *seq);
        let limit = request.limit.unwrap_or(100) as usize;
        let more = entries.len() > limit;
        entries.truncate(limit);
        let seq = entries
            .last()
            .map_or(if more { since } else { head }, |(seq, _)| *seq);
        Ok(LateResultsReply {
            entries: entries.into_iter().map(|(_, entry)| entry).collect(),
            cursor: Cursor {
                provider_incarnation: inner.incarnation.clone(),
                seq,
            },
            more,
        })
    }

    pub fn ack_late_results(
        &self,
        principal: &str,
        request: &AckRequest,
        now_ms: u64,
    ) -> Result<(), subc_protocol::ErrorBody> {
        let mut inner = self.lock();
        if let Some(error) = inner.broken.clone() {
            return Err(store_error(error));
        }
        late_results::check_since(
            &inner.incarnation,
            inner.late_heads.get(principal).copied().unwrap_or(0),
            Some(&request.through),
        )?;
        let keys: Vec<_> = inner
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.record.principal == principal
                    && entry.late_seq.is_some_and(|seq| seq <= request.through.seq)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            self.ack_key(&mut inner, &key, now_ms)
                .map_err(store_error)?;
        }
        Ok(())
    }
}

fn store_error(error: CallRecordError) -> subc_protocol::ErrorBody {
    subc_protocol::ErrorBody::new(
        "call_record_unavailable",
        format!("late results cannot be retained: {error}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const OWNER: &str = "reserved:prefrontal-core";
    const ORIGIN: &str = "https://login.example";
    fn scope(reference: &str) -> ScopeIdentity {
        ScopeIdentity {
            owner: OWNER.into(),
            reference: reference.into(),
            scope_epoch: 3,
        }
    }
    fn hold(calls: &CallRecords, key: &str, reference: &str, now: u64) {
        assert!(matches!(
            calls.begin(OWNER, key, reference, now),
            Begin::Execute(_)
        ));
        calls
            .hold_handoff(OWNER, key, reference, scope(reference), ORIGIN, now)
            .unwrap();
    }
    fn settled(calls: &CallRecords, key: &str, reference: &str, now: u64) {
        hold(calls, key, reference, now);
        calls
            .finish_handoff(OWNER, key, HandoffEnding::LoginObserved, now)
            .unwrap();
    }

    #[test]
    fn expired_entry_survives_record_retention_and_restart_until_ack() {
        let storage = InMemoryCallRecordStorage::new();
        let calls = CallRecords::open(Box::new(storage.clone()), 100);
        settled(&calls, "pf:expired", "s1", 100);
        calls.end_conversation("s1");
        let initial = calls
            .late_results(OWNER, &LateResultsRequest::new(), 100)
            .unwrap();
        assert_eq!(
            initial.entries.len(),
            1,
            "scope ending deleted its late result"
        );
        let at_deadline = calls
            .late_results(
                OWNER,
                &LateResultsRequest::new().with_since(initial.cursor),
                100 + RESULT_RETENTION_MS,
            )
            .unwrap();
        assert_eq!(at_deadline.entries.len(), 1);
        assert_eq!(at_deadline.entries[0].kind, "expired");
        assert!(at_deadline.entries[0].result.is_none());
        assert!(at_deadline.entries[0].outcome.is_none());
        assert_eq!(initial.entries[0].event_id, at_deadline.entries[0].event_id);
        let later = 100 + 100 * RESULT_RETENTION_MS;
        let reopened = CallRecords::open(Box::new(storage.clone()), later);
        let remaining = reopened
            .late_results(OWNER, &LateResultsRequest::new(), later)
            .unwrap();
        assert_eq!(remaining.entries, at_deadline.entries);
        reopened
            .ack_late_results(
                OWNER,
                &AckRequest {
                    through: remaining.cursor,
                },
                later,
            )
            .unwrap();
        let again = CallRecords::open(Box::new(storage), later + 1);
        assert!(again
            .late_results(OWNER, &LateResultsRequest::new(), later + 1)
            .unwrap()
            .entries
            .is_empty());
    }

    #[test]
    fn caps_drop_oldest_results_per_session_and_expired_per_owner() {
        let calls = CallRecords::in_memory();
        for index in 0..1001 {
            settled(&calls, &format!("pf:s1:{index}"), "s1", index + 1);
        }
        settled(&calls, "pf:s2:0", "s2", 1002);
        let kept = calls
            .late_results(OWNER, &LateResultsRequest::new().with_limit(2000), 1002)
            .unwrap();
        assert_eq!(
            kept.entries.len(),
            1001,
            "one session's cap removed another session's result"
        );
        assert!(!kept.entries.iter().any(|entry| entry.call_key == "pf:s1:0"));
        assert!(kept.entries.iter().any(|entry| entry.call_key == "pf:s2:0"));
        let expired = calls
            .late_results(
                OWNER,
                &LateResultsRequest::new().with_limit(2000),
                1002 + RESULT_RETENTION_MS,
            )
            .unwrap();
        assert_eq!(expired.entries.len(), 1000);
        assert!(expired.entries.iter().all(|entry| entry.kind == "expired"));
        assert!(
            !expired
                .entries
                .iter()
                .any(|entry| entry.call_key == "pf:s1:1"),
            "expired cap did not remove the oldest"
        );
    }

    #[test]
    fn handoff_expiry_is_a_result_not_retention_expiry() {
        let calls = CallRecords::in_memory();
        hold(&calls, "pf:timeout", "s1", 10);
        calls
            .finish_handoff(OWNER, "pf:timeout", HandoffEnding::HandoffExpired, 20)
            .unwrap();
        calls
            .finish_handoff(OWNER, "pf:timeout", HandoffEnding::LoginObserved, 30)
            .unwrap();
        let reply = calls
            .late_results(OWNER, &LateResultsRequest::new(), 30)
            .unwrap();
        assert_eq!(reply.entries.len(), 1);
        assert_eq!(reply.entries[0].kind, "result");
        assert_eq!(
            reply.entries[0].result,
            Some(json!({"outcome":"handoff_expired","origin":ORIGIN}))
        );
        crate::browser::validate_browser_result(
            "browser.present",
            reply.entries[0].result.as_ref().unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn invalid_origin_cannot_enter_held_store() {
        let storage = InMemoryCallRecordStorage::new();
        let calls = CallRecords::open(Box::new(storage.clone()), 0);
        assert!(matches!(
            calls.begin(OWNER, "pf:bad", "s1", 0),
            Begin::Execute(_)
        ));
        let before = storage.contents().unwrap();
        assert!(calls
            .hold_handoff(
                OWNER,
                "pf:bad",
                "s1",
                scope("s1"),
                "https://login.example/private?cookie=secret",
                1
            )
            .is_err());
        assert_eq!(storage.contents().unwrap(), before);
    }
}
