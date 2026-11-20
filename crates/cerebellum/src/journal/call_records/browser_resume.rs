//! Process-local continuations for held browser consent. Never serialize arguments.

use super::late::{ConsentEnding, HandoffEnding, LateOutcome, Phase};
use super::*;
use crate::browser_session::IdleHold;
use cortexkit_role_tool_provider::late_results::LateEntry;

pub(crate) struct BrowserResume {
    pub frame: Frame,
    pub facts: crate::AcceptedBindFacts,
    pub bind_sequence: u64,
    pub head: Option<((u16, u32), u64)>,
    pub approved: bool,
    pub ask_id: String,
    pub created: Instant,
    pub idle_hold: Option<IdleHold>,
}

/// Even an action that must never resume (such as a coordinate click) can
/// hold a session for consent. Retain only the pin and its cancellation keys.
#[derive(Debug)]
pub(crate) struct BrowserHold {
    pub idle: IdleHold,
    pub request: (u16, u32, u64),
    pub head_route: (u16, u32),
    pub head_scope: Option<ScopeIdentity>,
}

impl Entry {
    pub(super) fn clear_browser_request(&mut self) {
        self.browser_hold = None;
        self.browser_resume = None;
    }
}

impl std::fmt::Debug for BrowserResume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Arguments can contain typed text and must not enter diagnostics.
        f.debug_struct("BrowserResume")
            .field("approved", &self.approved)
            .finish_non_exhaustive()
    }
}

impl CallRecords {
    pub(crate) fn browser_request_bytes(&self, principal: &str, key: &str) -> Option<usize> {
        self.lock()
            .entries
            .get(&(principal.into(), key.into()))?
            .browser_resume
            .as_ref()
            .map(|resume| resume.frame.body.len())
    }
    pub(crate) fn retain_browser_request(
        &self,
        principal: &str,
        key: &str,
        resume: Option<BrowserResume>,
        hold: Option<BrowserHold>,
        tasks: &crate::browser_held::Tasks,
    ) {
        let mut inner = self.lock();
        let (running, running_bytes) = tasks.usage();
        let (count, bytes) = inner
            .entries
            .values()
            .filter_map(|entry| entry.browser_resume.as_ref())
            .fold((0, 0), |(count, bytes), resume| {
                (count + 1, bytes + resume.frame.body.len())
            });
        if let Some(entry) = inner.entries.get_mut(&(principal.into(), key.into())) {
            if let Some(hold) = hold {
                entry.browser_hold = Some(hold);
            }
            if let Some(resume) = resume.filter(|resume| {
                count + running < CACHE_MAX_REPLIES
                    && bytes
                        .saturating_add(running_bytes)
                        .saturating_add(resume.frame.body.len())
                        <= CACHE_MAX_BYTES
                    && resume.frame.body.len() <= CACHE_MAX_REPLY_BYTES
            }) {
                entry.browser_resume = Some(resume);
            }
        }
    }

    pub(crate) fn approved_browser_requests(&self) -> Vec<(String, String)> {
        self.lock()
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .browser_resume
                    .as_ref()
                    .is_some_and(|resume| resume.approved)
            })
            .map(|(key, _)| key.clone())
            .collect()
    }

    /// Claim custody before dispatch. Scope end, withdrawal and a second drain
    /// all compete under the same lock; only the winner may run the request.
    pub(crate) fn claim_browser_request(
        &self,
        principal: &str,
        call_key: &str,
        now: u64,
        admitted: impl FnOnce(&BrowserResume) -> bool,
    ) -> Result<Option<BrowserResume>, CallRecordError> {
        let mut inner = self.lock();
        let key = (principal.into(), call_key.into());
        let Some(entry) = inner.entries.get(&key) else {
            return Ok(None);
        };
        let Some(held) = entry.record.handoff.as_ref() else {
            return Ok(None);
        };
        if !matches!(held.phase, Phase::Pending)
            || entry.held_dispatched
            || entry.consent_ended
            || inner.ended_scopes.contains(&held.scope)
            || !entry
                .browser_resume
                .as_ref()
                .is_some_and(|resume| resume.approved)
        {
            return Ok(None);
        }
        let resume = entry.browser_resume.as_ref().unwrap();
        if resume.created.elapsed() > CACHE_MAX_AGE || !admitted(resume) {
            self.finish_held_locked(
                &mut inner,
                &key,
                LateOutcome::Consent(ConsentEnding::Approved),
                now,
            )?;
            return Ok(None);
        }
        let mut record = entry.record.clone();
        // Page text must never reach durable records. Call-record format 6
        // already understands Unknown; after a restart it conservatively
        // becomes outcome_unknown, without requiring a newer call-record reader.
        // The actual reply is delivered only from the bounded memory cache.
        record.handoff.as_mut().unwrap().phase = Phase::Result {
            outcome: LateOutcome::Handoff(HandoffEnding::Unknown),
            settled_at: now,
        };
        record.outcome = Some("unknown".into());
        record.state = CallState::Unknown;
        record.settled_at_ms = Some(now);
        self.write(&mut inner, &record, now)?;
        let entry = inner.entries.get_mut(&key).unwrap();
        entry.record = record;
        entry.held_dispatched = true;
        if let Some(resume) = entry.browser_resume.as_mut() {
            resume.idle_hold = entry.browser_hold.take().map(|hold| hold.idle);
            resume.ask_id = entry
                .record
                .handoff
                .as_ref()
                .unwrap()
                .consent
                .clone()
                .unwrap();
        }
        Ok(entry.browser_resume.take())
    }

    pub(crate) fn abandon_browser_request(
        &self,
        principal: &str,
        call_key: &str,
        now: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        let key = (principal.into(), call_key.into());
        let Some(entry) = inner
            .entries
            .get_mut(&key)
            .filter(|entry| entry.browser_resume.is_some() || entry.browser_hold.is_some())
        else {
            return Ok(());
        };
        entry.clear_browser_request();
        self.finish_held_locked(
            &mut inner,
            &key,
            LateOutcome::Consent(ConsentEnding::Withdrawn),
            now,
        )
    }

    pub(crate) fn abandon_browser_route(&self, channel: u16, epoch: u32, now: u64) {
        let keys: Vec<_> = self
            .lock()
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.browser_hold.as_ref().is_some_and(|hold| {
                    (hold.request.0, hold.request.1) == (channel, epoch)
                        || hold.head_route == (channel, epoch)
                }) || entry.browser_resume.as_ref().is_some_and(|resume| {
                    (resume.frame.header.channel, resume.frame.header.epoch) == (channel, epoch)
                        || resume
                            .head
                            .is_some_and(|(route, _)| route == (channel, epoch))
                })
            })
            .map(|(key, _)| key.clone())
            .collect();
        for (principal, key) in keys {
            let mut inner = self.lock();
            let key = (principal, key);
            let approved = inner
                .entries
                .get_mut(&key)
                .and_then(|entry| {
                    entry.browser_hold = None;
                    entry.browser_resume.take()
                })
                .is_some_and(|resume| resume.approved);
            // Closing a route is not proof that its scope ended. Leave an
            // unanswered card answerable, but discard its executable request.
            if approved {
                let _ = self.finish_held_locked(
                    &mut inner,
                    &key,
                    LateOutcome::Consent(ConsentEnding::Approved),
                    now,
                );
            }
        }
    }

    pub(crate) fn abandon_browser_correlation(
        &self,
        channel: u16,
        epoch: u32,
        corr: u64,
        now: u64,
    ) {
        let keys: Vec<_> = self
            .lock()
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry
                    .browser_hold
                    .as_ref()
                    .is_some_and(|hold| hold.request == (channel, epoch, corr))
                    || entry.browser_resume.as_ref().is_some_and(|resume| {
                        let header = &resume.frame.header;
                        (header.channel, header.epoch, header.corr) == (channel, epoch, corr)
                    })
            })
            .map(|(key, _)| key.clone())
            .collect();
        for (principal, key) in keys {
            let _ = self.abandon_browser_request(&principal, &key, now);
        }
    }

    pub(crate) fn finish_browser_request(
        &self,
        principal: &str,
        call_key: &str,
        mut reply: Frame,
        dispatched: bool,
        now: u64,
    ) -> Result<(), CallRecordError> {
        let mut inner = self.lock();
        let key = (principal.into(), call_key.into());
        let Some(entry) = inner.entries.get(&key) else {
            return Ok(());
        };
        // A continuation may itself start a login handoff. If that handoff is
        // still pending, do not turn this reply into a final result.
        if entry
            .record
            .handoff
            .as_ref()
            .is_some_and(|held| matches!(held.phase, Phase::Pending))
        {
            return Ok(());
        }
        let value: Value = serde_json::from_slice(&reply.body)
            .unwrap_or_else(|_| json!({"outcome":"outcome_unknown"}));
        let notice_outcome =
            crate::event_publish::late_result_outcome(&value, reply.header.ty == FrameType::Error)
                .to_owned();
        let mut body = value.get("structuredContent").cloned().unwrap_or(value);
        if reply.header.ty == FrameType::Error && !dispatched {
            body = json!({"outcome":"not_started","reason":body["code"],"detail":{"refusal":body}});
        } else if matches!(
            body["outcome"].as_str(),
            Some(
                "stale_snapshot"
                    | "ref_not_found"
                    | "ref_ambiguous"
                    | "classification_unavailable"
                    | "credential_form_submit"
                    | "financial_form_submit"
                    | "authorization_denied"
                    | "consent_unavailable"
                    | "invalid_request"
                    | "refused"
            )
        ) && body["input_dispatched"] != true
            && !dispatched
        {
            let reason = body
                .get("reason")
                .filter(|reason| reason.is_string())
                .cloned()
                .unwrap_or_else(|| body["outcome"].clone());
            body = json!({"outcome":"not_started","reason":reason,"detail":{"refusal":body}});
        }
        reply.body = serde_json::to_vec(&body).expect("browser result serializes");
        let size = reply.body.len();
        let freed = inner.entries[&key].reply_bytes;
        inner.cached_bytes -= freed;
        let entry = inner.entries.get_mut(&key).unwrap();
        entry.reply = None;
        entry.reply_bytes = 0;
        entry.cached_at = None;
        entry.resumed_result = true;
        if size <= CACHE_MAX_REPLY_BYTES {
            entry.reply = Some(CachedReply { frame: reply });
            entry.reply_bytes = size;
            entry.cached_at = Some(Instant::now());
            inner.cached_bytes += size;
            inner.cached.retain(|cached| cached != &key);
            inner.cached.push_back(key.clone());
        }
        while inner.cached.len() > CACHE_MAX_REPLIES || inner.cached_bytes > CACHE_MAX_BYTES {
            let Some(oldest) = inner.cached.pop_front() else {
                break;
            };
            if let Some(entry) = inner.entries.get_mut(&oldest) {
                entry.reply = None;
                entry.cached_at = None;
                inner.cached_bytes -= std::mem::take(&mut entry.reply_bytes);
            }
        }
        super::late::next_seq(&mut inner, &key);
        self.bound_late(&mut inner, now)?;
        self.publish_late_notice(&inner, &key, &notice_outcome);
        if let Some(display) = self.display.get().and_then(std::sync::Weak::upgrade) {
            display.completed(principal, call_key, &body);
        }
        Ok(())
    }

    pub(super) fn overlay_browser_result(inner: &Inner, key: &Key, late: &mut LateEntry) {
        if late.kind == cortexkit_role_tool_provider::late_results::kinds::EXPIRED {
            return;
        }
        if let Some(entry) = inner.entries.get(key).filter(|entry| entry.resumed_result) {
            if entry
                .cached_at
                .is_some_and(|at| at.elapsed() <= CACHE_MAX_AGE)
            {
                if let Some(result) = entry.reply.as_ref().and_then(CachedReply::result) {
                    if result["outcome"] == "not_started" {
                        late.kind = "not_started".into();
                        late.reason = result["reason"].as_str().map(str::to_owned);
                    }
                    late.result = Some(result);
                }
            }
        }
    }

    /// Drop a resumed browser reply once its late result is acknowledged.
    /// Until then a consumer that lost a late_results response can pull the
    /// same observed result again, within the cache's memory bounds.
    pub(super) fn release_resumed_reply(inner: &mut Inner, key: &Key) {
        if let Some(entry) = inner
            .entries
            .get_mut(key)
            .filter(|entry| entry.resumed_result)
        {
            entry.reply = None;
            entry.cached_at = None;
            inner.cached_bytes -= std::mem::take(&mut entry.reply_bytes);
        }
    }

    #[cfg(test)]
    pub(crate) fn browser_request_count(&self) -> usize {
        self.lock()
            .entries
            .values()
            .filter(|entry| entry.browser_resume.is_some())
            .count()
    }
}
