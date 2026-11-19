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

fn retention_group(scope: &ScopeIdentity, expired: bool) -> RetentionGroup {
    let owner = scope.owner_key();
    if expired {
        RetentionGroup::ExpiredOwner(owner)
    } else {
        RetentionGroup::Session {
            owner,
            reference: scope.reference.clone(),
            epoch: scope.scope_epoch,
        }
    }
}

#[cfg(test)]
mod rename_tests {
    use super::*;
    use std::hash::{Hash, Hasher};

    #[test]
    fn rename_followup_late_retention_groups_share_owner_identity() {
        for (before, after) in [
            ("prefrontal-core", "prefrontal"),
            ("prefrontal", "prefrontal-core"),
        ] {
            let old = ScopeIdentity {
                owner: format!("reserved:{before}"),
                reference: "head".into(),
                scope_epoch: 7,
            };
            let mut new = old.clone();
            new.owner = format!("reserved:{after}");
            for expired in [false, true] {
                let old_group = retention_group(&old, expired);
                let new_group = retention_group(&new, expired);
                assert!(old_group == new_group);
                let hash = |key: &RetentionGroup| {
                    let mut state = std::collections::hash_map::DefaultHasher::new();
                    key.hash(&mut state);
                    state.finish()
                };
                assert_eq!(hash(&old_group), hash(&new_group));
                assert_eq!(
                    std::collections::HashMap::from([(old_group, 1)]).get(&new_group),
                    Some(&1)
                );
            }
            new.reference = "different".into();
            assert!(retention_group(&old, false) != retention_group(&new, false));
            new.reference = old.reference.clone();
            new.scope_epoch += 1;
            assert!(retention_group(&old, false) != retention_group(&new, false));
            new = old.clone();
            new.owner = "reserved:aft".into();
            assert!(retention_group(&old, false) != retention_group(&new, false));
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffEnding {
    Captured,
    SessionInvalid,
    Expired,
    LoginObserved,
    HandoffExpired,
    ClosedByCaller,
    HandoffInterrupted,
    Unknown,
}

impl HandoffEnding {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Captured => "captured",
            Self::SessionInvalid => "session_invalid",
            Self::Expired => "expired",
            Self::LoginObserved => "login_observed",
            Self::HandoffExpired => "handoff_expired",
            Self::ClosedByCaller => "closed_by_caller",
            Self::HandoffInterrupted => "handoff_interrupted",
            Self::Unknown => "unknown",
        }
    }
}

/// The answer to a consent question. A live, re-verifiable browser request may
/// consume approval; otherwise only the grant survives for a fresh call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsentEnding {
    Approved,
    Denied,
    Withdrawn,
    Expired,
}

impl ConsentEnding {
    fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Withdrawn => "withdrawn",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub(super) enum LateOutcome {
    Handoff(HandoffEnding),
    Consent(ConsentEnding),
    Scope(ScopeEnding),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ScopeEnding {
    ScopeEnded,
}

impl LateOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Handoff(ending) => ending.as_str(),
            Self::Consent(ending) => ending.as_str(),
            Self::Scope(ScopeEnding::ScopeEnded) => late_results::reasons::SCOPE_ENDED,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Phase {
    Pending,
    Result {
        outcome: LateOutcome,
        settled_at: u64,
    },
    Expired {
        event_id: String,
        settled_at: u64,
    },
    Acked,
}

/// Login and consent share retention, acknowledgements and recovery. Only
/// identifiers and closed outcomes are persisted, never captured page content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldHandoff {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    origin: String,
    pub(super) scope: ScopeIdentity,
    pub(super) phase: Phase,
    // Omitted for present so its existing version-3 representation is unchanged.
    #[serde(default, skip_serializing_if = "is_false")]
    capture: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) consent: Option<String>,
}

fn is_false(value: &bool) -> bool {
    !value
}

impl HeldHandoff {
    pub(super) fn requires_reader_6(&self) -> bool {
        self.scope_ended()
            || matches!(
                self.phase,
                Phase::Result {
                    outcome: LateOutcome::Handoff(HandoffEnding::Unknown),
                    ..
                }
            )
    }

    pub(super) fn scope_ended(&self) -> bool {
        matches!(
            self.phase,
            Phase::Result {
                outcome: LateOutcome::Scope(_),
                ..
            }
        )
    }

    pub(super) fn is_consent(&self) -> bool {
        self.consent.is_some()
    }
    pub(super) fn is_capture(&self) -> bool {
        self.capture
    }
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
    outcome: LateOutcome,
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
    let mut hash = Sha256::new();
    hash.update(bytes);
    if let Some(ask_id) = &handoff.consent {
        hash.update(serde_json::to_vec(&("consent/v1", ask_id)).unwrap());
    }
    format!("{:x}", hash.finalize())
}

pub(super) fn next_seq(inner: &mut Inner, key: &Key) {
    let head = inner.late_heads.entry(key.0.clone()).or_default();
    *head += 1;
    inner
        .entries
        .get_mut(key)
        .expect("sequenced record exists")
        .late_seq = Some(*head);
}

pub(super) fn reconcile(inner: &mut Inner, now_ms: u64) -> Vec<Key> {
    let mut ready = Vec::new();
    let mut keys = Vec::new();
    for (key, entry) in &mut inner.entries {
        let Some(handoff) = entry.record.handoff.as_mut() else {
            continue;
        };
        if matches!(handoff.phase, Phase::Pending) {
            let outcome = if handoff.is_consent() {
                LateOutcome::Consent(ConsentEnding::Withdrawn)
            } else {
                LateOutcome::Handoff(HandoffEnding::HandoffInterrupted)
            };
            handoff.phase = Phase::Result {
                outcome,
                settled_at: now_ms,
            };
            entry.record.outcome = Some(outcome.as_str().into());
            entry.record.state = if handoff.is_consent() {
                CallState::Asked
            } else {
                CallState::Replied
            };
            entry.record.settled_at_ms = Some(now_ms);
            ready.push(key.clone());
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
    ready
}

fn wire_entry(record: &CallRecord) -> Option<LateEntry> {
    let handoff = record.handoff.as_ref()?;
    let (kind, id, settled_at, result) = match &handoff.phase {
        Phase::Result {
            outcome,
            settled_at,
        } => (
            if (handoff.is_consent() && matches!(outcome, LateOutcome::Consent(_)))
                || handoff.scope_ended()
            {
                late_results::kinds::NOT_STARTED
            } else {
                late_results::kinds::RESULT
            },
            event_id(record, handoff, *outcome, *settled_at),
            *settled_at,
            Some(result_body(handoff, outcome.as_str())),
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
    if handoff.scope_ended() {
        entry.reason = Some(late_results::reasons::SCOPE_ENDED.into());
    } else if let (
        Some(ask_id),
        Phase::Result {
            outcome: LateOutcome::Consent(outcome),
            ..
        },
    ) = (&handoff.consent, &handoff.phase)
    {
        entry.reason = Some("consent".into());
        entry.outcome = Some(outcome.as_str().into());
        entry.extra.insert(
            "detail".into(),
            json!({"consent":outcome.as_str(), "ask_id":ask_id}),
        );
    }
    Some(entry)
}

pub(super) fn settled_result(record: &CallRecord) -> Option<Value> {
    let handoff = record.handoff.as_ref()?;
    if matches!(handoff.phase, Phase::Pending) {
        return None;
    }
    let outcome = record.outcome.as_deref()?;
    Some(result_body(handoff, outcome))
}

fn result_body(held: &HeldHandoff, outcome: &str) -> Value {
    if outcome == late_results::reasons::SCOPE_ENDED {
        json!({"outcome":"not_started","reason":late_results::reasons::SCOPE_ENDED})
    } else if held.is_consent() && outcome == "unknown" {
        json!({"outcome":"outcome_unknown"})
    } else if let Some(ask_id) = &held.consent {
        json!({"outcome": if outcome == "approved" { "not_started" } else { outcome },
            "detail":{"consent":outcome,"ask_id":ask_id},
            "remedy":if outcome == "approved" { "Approved; call again to run it." } else { "The original action was not run." }})
    } else {
        json!({"outcome":outcome,"origin":held.origin})
    }
}

impl CallRecords {
    pub(super) fn publish_late_notice(&self, inner: &Inner, key: &Key, outcome: &str) {
        // Use the same settlement identity the reader pulls through late_results.
        // An acknowledgement or retention drop leaves nothing to announce.
        if let Some(entry) = inner
            .entries
            .get(key)
            .and_then(|entry| wire_entry(&entry.record))
        {
            self.events
                .late_result(&entry.custodian, &entry.call_key, &entry.event_id, outcome);
        }
    }

    /// Persist the call record before forwarding the held first reply. The
    /// original browser request, if resumable, stays only in bounded memory.
    pub fn hold_consent(
        &self,
        principal: &str,
        call_key: &str,
        ask_id: &str,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        if let Some(error) = &inner.broken {
            return Err(error.clone());
        }
        let key = (principal.to_owned(), call_key.to_owned());
        let entry = inner
            .entries
            .get(&key)
            .ok_or_else(|| CallRecordError::Corrupt("held consent has no call record".into()))?;
        if entry.consent_ended {
            return Err(CallRecordError::Corrupt(
                "the consent context has ended".into(),
            ));
        }
        let mut record = entry.record.clone();
        let scope = record
            .scope
            .clone()
            .ok_or_else(|| CallRecordError::Corrupt("held consent has no scope".into()))?;
        record.handoff = Some(HeldHandoff {
            origin: String::new(),
            scope: scope.clone(),
            phase: Phase::Pending,
            capture: false,
            consent: Some(ask_id.into()),
        });
        self.write(&mut inner, &record, now_ms)?;
        let scope_ended = inner.ended_scopes.contains(&scope);
        let head_ended = inner.entries[&key]
            .browser_hold
            .as_ref()
            .and_then(|hold| hold.head_scope.as_ref())
            .is_some_and(|scope| inner.ended_scopes.contains(scope));
        let entry = inner.entries.get_mut(&key).unwrap();
        entry.record = record;
        if head_ended {
            entry.clear_browser_request();
        }
        if scope_ended {
            self.finish_held_locked(
                &mut inner,
                &key,
                LateOutcome::Scope(ScopeEnding::ScopeEnded),
                now_ms,
            )?;
        } else if let Some(hold) = entry.browser_hold.as_mut() {
            hold.idle.start(CACHE_MAX_AGE);
        }
        Ok(())
    }

    /// Only the daemon's exact scope-end signal settles holds. A route close,
    /// rebind or restart must not manufacture this outcome.
    pub(crate) fn end_held_scope(
        &self,
        scope: &ScopeIdentity,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        inner.ended_scopes.insert(scope.clone());
        for entry in inner.entries.values_mut().filter(|entry| {
            entry
                .browser_hold
                .as_ref()
                .and_then(|hold| hold.head_scope.as_ref())
                == Some(scope)
        }) {
            entry.clear_browser_request();
        }
        let keys: Vec<_> = inner
            .entries
            .iter()
            .filter(|(_, entry)| {
                !entry.held_dispatched
                    && entry.record.handoff.as_ref().is_some_and(|held| {
                        &held.scope == scope && matches!(held.phase, Phase::Pending)
                    })
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in keys {
            self.finish_held_locked(
                &mut inner,
                &key,
                LateOutcome::Scope(ScopeEnding::ScopeEnded),
                now_ms,
            )?;
        }
        Ok(())
    }

    pub(crate) fn held_scope_ended(&self, scope: &ScopeIdentity) -> bool {
        self.lock().ended_scopes.contains(scope)
    }

    /// Serialize the deposit boundary with scope end. After this returns true,
    /// sending may begin and only the observed deposit result can settle it.
    pub(crate) fn begin_capture_deposit(&self, principal: &str, call_key: &str) -> bool {
        let mut inner = self.lock();
        let key = (principal.to_owned(), call_key.to_owned());
        let Some(entry) = inner.entries.get(&key) else {
            return false;
        };
        let Some(held) = entry.record.handoff.as_ref() else {
            return false;
        };
        if !held.capture
            || !matches!(held.phase, Phase::Pending)
            || inner.ended_scopes.contains(&held.scope)
        {
            return false;
        }
        inner.entries.get_mut(&key).unwrap().held_dispatched = true;
        true
    }

    pub(crate) fn has_pending_scope(&self, scope: &ScopeIdentity) -> bool {
        self.lock().entries.values().any(|entry| {
            entry
                .record
                .handoff
                .as_ref()
                .is_some_and(|held| &held.scope == scope && matches!(held.phase, Phase::Pending))
        })
    }

    pub fn has_pending_consents(&self) -> bool {
        self.lock().entries.values().any(|entry| {
            entry
                .record
                .handoff
                .as_ref()
                .is_some_and(|held| held.is_consent() && matches!(held.phase, Phase::Pending))
        })
    }

    /// A definitive session end removes the cards locally, so no future live
    /// drain can answer these holds. Settle them without contacting Cingulate,
    /// and reject an older request whose custody write arrives after teardown.
    pub(crate) fn end_consent_conversation(
        &self,
        conversation: &str,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        let mut keys = Vec::new();
        for (key, entry) in &mut inner.entries {
            if entry.conversation_key == conversation {
                entry.consent_ended = true;
                if entry
                    .record
                    .handoff
                    .as_ref()
                    .is_some_and(|held| held.is_consent() && matches!(held.phase, Phase::Pending))
                {
                    keys.push(key.clone());
                }
            }
        }
        for key in keys {
            self.finish_held_locked(
                &mut inner,
                &key,
                LateOutcome::Consent(ConsentEnding::Withdrawn),
                now_ms,
            )?;
        }
        Ok(())
    }

    pub fn finish_consent(
        &self,
        ask_id: &str,
        ending: ConsentEnding,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        let keys: Vec<_> = inner
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.record.handoff.as_ref().is_some_and(|held| {
                    held.consent.as_deref() == Some(ask_id) && matches!(held.phase, Phase::Pending)
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        let mut consumed = false;
        for key in keys {
            if ending == ConsentEnding::Approved && inner.entries[&key].browser_resume.is_some() {
                let record = inner.entries[&key].record.clone();
                self.write(&mut inner, &record, now_ms)?;
                let resume = inner
                    .entries
                    .get_mut(&key)
                    .unwrap()
                    .browser_resume
                    .as_mut()
                    .unwrap();
                resume.approved = true;
                consumed = true;
                continue;
            }
            self.finish_held_locked(&mut inner, &key, LateOutcome::Consent(ending), now_ms)?;
        }
        if !consumed {
            if let Some(display) = self.display.get().and_then(std::sync::Weak::upgrade) {
                display.consent_completed(ask_id, ending.as_str());
            }
        }
        Ok(())
    }

    /// Sync the recovery obligation before returning a pending handoff. Without
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
        self.hold_login(
            principal,
            call_key,
            Some(conversation),
            scope,
            origin,
            now_ms,
        )
    }

    /// Capture sign-in uses a separate throwaway browser. `browser.resume`
    /// ends the persistent browser's handoff, not the capture, so the capture's
    /// later result must remain owed until its own sign-in has ended.
    pub fn hold_capture(
        &self,
        principal: &str,
        call_key: &str,
        scope: ScopeIdentity,
        origin: &str,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        self.hold_login(principal, call_key, None, scope, origin, now_ms)
    }

    fn hold_login(
        &self,
        principal: &str,
        call_key: &str,
        conversation: Option<&str>,
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
            scope: scope.clone(),
            phase: Phase::Pending,
            capture: conversation.is_none(),
            consent: None,
        });
        self.write(&mut inner, &record, now_ms)?;
        let entry = inner.entries.get_mut(&key).expect("held record exists");
        entry.record = record;
        // A new login/capture hold must still stop on scope end until its own
        // deposit starts. Claiming the earlier consent is not evidence that
        // the deposit has been sent.
        entry.held_dispatched = false;
        if let Some(conversation) = conversation {
            inner.handoffs.insert(conversation.to_owned(), key);
        }
        if inner.ended_scopes.contains(&scope) {
            self.finish_held_locked(
                &mut inner,
                &(principal.into(), call_key.into()),
                LateOutcome::Scope(ScopeEnding::ScopeEnded),
                now_ms,
            )?;
        }
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
        self.finish_held_locked(inner, key, LateOutcome::Handoff(outcome), now_ms)
    }

    pub(super) fn finish_held_locked(
        &self,
        inner: &mut Inner,
        key: &Key,
        outcome: LateOutcome,
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
        // Remember the observed end even when its first custody write failed.
        // A later consent answer or poll retries the same terminal, not its own.
        let outcome = if !entry.held_dispatched && inner.ended_scopes.contains(&handoff.scope) {
            LateOutcome::Scope(ScopeEnding::ScopeEnded)
        } else {
            outcome
        };
        handoff.phase = Phase::Result {
            outcome,
            settled_at: now_ms,
        };
        record.outcome = Some(outcome.as_str().into());
        record.state = if handoff.scope_ended() {
            record.refusal_reason = Some(late_results::reasons::SCOPE_ENDED.into());
            CallState::Refused
        } else if handoff.is_consent() {
            CallState::Asked
        } else {
            CallState::Replied
        };
        record.settled_at_ms = Some(now_ms);
        // An observed terminal event releases the browser even if persisting
        // that event must be retried later.
        inner.entries.get_mut(key).unwrap().browser_hold = None;
        self.write(inner, &record, now_ms)?;
        let result = settled_result(&record).expect("settled handoff has a result");
        let entry = inner.entries.get_mut(key).expect("settled record exists");
        entry.clear_browser_request();
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
        self.publish_late_notice(
            inner,
            key,
            crate::event_publish::late_result_outcome(&result, false),
        );
        if let Some(display) = self.display.get().and_then(std::sync::Weak::upgrade) {
            display.completed(&key.0, &key.1, &result);
        }
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
            let group = retention_group(&handoff.scope, expired);
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
        for (_, entry) in &mut entries {
            let key = (entry.custodian.clone(), entry.call_key.clone());
            Self::overlay_browser_result(&inner, &key, entry);
        }
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

    const OWNER: &str = "reserved:prefrontal";
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

    #[tokio::test(start_paused = true)]
    async fn bus_notice_startup_recovery_queues_only_new_commits_with_live_identity() {
        use crate::event_publish::tests::{settle, Fake};

        let storage = InMemoryCallRecordStorage::new();
        let calls = CallRecords::open(Box::new(storage.clone()), 100);
        hold(&calls, "opaque:recovered", "scope", 100);
        drop(calls);
        let recovered = CallRecords::open(Box::new(storage.clone()), 101);
        let committed = recovered
            .late_results(OWNER, &LateResultsRequest::new(), 101)
            .unwrap();
        assert_eq!(committed.entries.len(), 1);
        assert_eq!(
            committed.entries[0].result.as_ref().unwrap()["outcome"],
            "handoff_interrupted"
        );
        tokio::time::advance(std::time::Duration::from_secs(60)).await;
        let fake = Arc::new(Fake::default());
        recovered.events.connect(Arc::new(fake.clone()));
        settle().await;
        let recovery = fake.writes.lock().unwrap().clone();
        assert_eq!(
            recovery.len(),
            1,
            "recovery queued one notice before transport installation"
        );

        let live = CallRecords::in_memory();
        let live_fake = Arc::new(Fake::default());
        live.events.connect(Arc::new(live_fake.clone()));
        hold(&live, "opaque:recovered", "scope", 100);
        live.finish_handoff(
            OWNER,
            "opaque:recovered",
            HandoffEnding::HandoffInterrupted,
            101,
        )
        .unwrap();
        settle().await;
        let live_writes = live_fake.writes.lock().unwrap().clone();
        assert_eq!(live_writes.len(), 1);
        assert_eq!(live_writes[0].id, recovery[0].id);
        assert_eq!(live_writes[0].bytes, recovery[0].bytes);
        assert_eq!(live_writes[0].kind, recovery[0].kind);

        let reopened = CallRecords::open(Box::new(storage), 102);
        let second_fake = Arc::new(Fake::default());
        reopened.events.connect(Arc::new(second_fake.clone()));
        settle().await;
        assert!(
            second_fake.writes.lock().unwrap().is_empty(),
            "opening an already committed result is not another commit"
        );
    }

    #[tokio::test]
    async fn bus_notice_requires_committed_late_result_and_excludes_screen_text() {
        use crate::event_publish::{
            tests::{publisher, settle},
            Kind,
        };
        use std::sync::atomic::{AtomicBool, Ordering::Relaxed};

        struct FallibleStorage {
            memory: InMemoryCallRecordStorage,
            refuse: Arc<AtomicBool>,
        }
        impl CallRecordStorage for FallibleStorage {
            fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
                self.memory.load()
            }
            fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
                if self.refuse.load(Relaxed) {
                    return Err(CallRecordError::WriteFailed("fixture".into()));
                }
                self.memory.append(bytes, version)
            }
            fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
                self.memory.replace(bytes, version)
            }
        }

        for fail_commit in [true, false] {
            let memory = InMemoryCallRecordStorage::new();
            let refuse = Arc::new(AtomicBool::new(false));
            let mut calls = CallRecords::open(
                Box::new(FallibleStorage {
                    memory: memory.clone(),
                    refuse: refuse.clone(),
                }),
                100,
            );
            let (events, fake) = publisher();
            calls.events = events;
            assert!(matches!(
                calls.begin(OWNER, "opaque:key", "conversation", 100),
                Begin::Execute(_)
            ));
            calls
                .hold_handoff(
                    OWNER,
                    "opaque:key",
                    "handoff",
                    scope("scope"),
                    "https://planted-screen-text.example",
                    100,
                )
                .unwrap();
            settle().await;
            assert!(
                fake.writes.lock().unwrap().is_empty(),
                "pending holds have no ready result"
            );
            refuse.store(fail_commit, Relaxed);
            let result =
                calls.finish_handoff(OWNER, "opaque:key", HandoffEnding::LoginObserved, 101);
            settle().await;
            let writes = fake.writes.lock().unwrap();
            if fail_commit {
                assert!(result.is_err());
                assert!(
                    writes.is_empty(),
                    "failed custody write must not enqueue a notice"
                );
                continue;
            }
            result.unwrap();
            assert_eq!(writes.len(), 1);
            assert_eq!(
                writes[0].kind,
                Kind::LateResultReady {
                    custodian_module: Some("prefrontal".into())
                }
            );
            assert_eq!(
                serde_json::from_slice::<Value>(&writes[0].bytes).unwrap(),
                json!({"call_key":"opaque:key", "outcome":"ok"})
            );
            assert!(!String::from_utf8_lossy(&writes[0].bytes).contains("planted-screen-text"));
            // Reopening from committed bytes, not the live in-memory entries,
            // must already expose the result the notice describes.
            let reopened = CallRecords::open(Box::new(memory), 101);
            let late = reopened
                .late_results(OWNER, &LateResultsRequest::new(), 101)
                .unwrap();
            assert_eq!(late.entries.len(), 1);
            assert_eq!(
                writes[0].id,
                format!("{}:prefrontal", late.entries[0].event_id)
            );
            let body = serde_json::to_value(&late.entries[0]).unwrap();
            assert_eq!(body["call_key"], "opaque:key");
            assert_eq!(body["result"]["outcome"], "login_observed");
            assert!(
                body.to_string().contains("planted-screen-text"),
                "the fixture must plant content in the stored result"
            );
        }
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

    /// An acknowledgement whose append reaches the compaction threshold must
    /// be part of the rewritten file, or a restart would deliver the acked
    /// result again.
    #[test]
    fn an_ack_that_triggers_compaction_stays_acked_after_restart() {
        let storage = InMemoryCallRecordStorage::new();
        let calls = CallRecords::open(Box::new(storage.clone()), 100);
        settled(&calls, "pf:acked", "s1", 100);
        let pulled = calls
            .late_results(OWNER, &LateResultsRequest::new(), 100)
            .unwrap();
        assert_eq!(pulled.entries.len(), 1);
        calls.lock().appended_since_compaction = MAX_RECORDS - 1;
        calls
            .ack_late_results(
                OWNER,
                &AckRequest {
                    through: pulled.cursor,
                },
                101,
            )
            .unwrap();
        assert_eq!(
            calls.lock().appended_since_compaction,
            0,
            "the acknowledgement must have triggered compaction"
        );
        drop(calls);
        let reopened = CallRecords::open(Box::new(storage), 102);
        assert!(reopened
            .late_results(OWNER, &LateResultsRequest::new(), 102)
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
