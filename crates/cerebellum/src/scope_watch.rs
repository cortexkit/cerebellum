//! Ending what a session scope allowed once the scope itself has ended.
//!
//! # Why
//!
//! A route opened under a session scope carries the daemon's stamp of that
//! scope, `(owner, ref, scope_epoch)`. A browser opened on such a route, and
//! the grants and questions its conversation holds, belong to that session.
//! When the session ends (its owner removes the scope, or starts a new session
//! under the same ref at a higher epoch) they must end with it.
//!
//! # The rule that matters most: act only on a definitive end
//!
//! Routes close for ordinary reasons too: a client reconnecting, a module or
//! daemon restart. The route GOODBYE a module receives carries no reason, and
//! right after a daemon restart every scope reads as "not live" until its owner
//! syncs again. Closing a browser on that guess would destroy an agent's work.
//! So a scoped route closing only starts a question to the daemon,
//! `scope.describe`, and the scope is treated as ended only when the answer is
//! definitive (see [`classify`]). Anything else (an owner that has not synced
//! since a daemon restart, an error, no answer, a daemon too old to have
//! `scope.describe`) leaves everything in place. The browser idle reaper is the
//! backstop for an owner that never comes back.
//!
//! # How the question is sent
//!
//! `scope.describe` is a module control request: a `REQUEST` frame on channel
//! 0 of this module's own daemon connection, written through the same frame
//! writer every reply uses. The daemon answers on channel 0 with a `RESPONSE`
//! (or an `ERROR`) carrying the same correlation id. Inbound responses on
//! channel 0 can only answer requests this module sent (the daemon's own
//! requests arrive as `REQUEST` frames), so [`ControlRequests`] matches an
//! answer to its question by correlation id alone. Each question is bounded by
//! [`SCOPE_DESCRIBE_TIMEOUT`], at most [`MAX_CONTROL_REQUESTS_IN_FLIGHT`] are
//! outstanding at once, and at most one per scope is asked at a time. None of
//! it runs on the frame loop: the loop only hands answers over.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use serde_json::Value;
use subc_protocol::scope::{ScopeStamp, ScopeStatus};
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};
use subc_protocol::{Frame, FrameType, Principal};
use tokio::sync::{mpsc, oneshot};

/// How long one `scope.describe` may wait for its answer. The daemon answers
/// it from memory under one read lock, so an answer later than this means the
/// connection or the daemon is in trouble; the question then counts as
/// unanswered, which is never read as an end.
pub const SCOPE_DESCRIBE_TIMEOUT: Duration = Duration::from_secs(5);

/// How often a scope that is still unresolved is asked about again, while a
/// browser it opened is still open and no route under it is bound.
///
/// With no route open nothing else would notice the scope ending, so without
/// this a revoked session's browser would run until the idle reaper, up to ten
/// minutes. Thirty seconds bounds that to about half a minute, and costs one
/// small in-memory lookup in the daemon per open browser per interval, which is
/// nothing next to the browser itself. It is also well past the few seconds an
/// owner takes to sync again after a daemon restart, so a browser waiting out a
/// restart is asked about a handful of times at most.
pub const SCOPE_RECHECK_INTERVAL: Duration = Duration::from_secs(30);

/// The most module control requests outstanding at once. A module that cannot
/// get an answer should not pile up questions without bound; one past this is
/// treated as unanswered.
pub const MAX_CONTROL_REQUESTS_IN_FLIGHT: usize = 64;

/// Correlation ids this module uses for its own channel-0 requests start here,
/// far from the small ids used for the HELLO, so a trace reads unambiguously.
const FIRST_CONTROL_CORR: u64 = 1 << 40;

/// What the daemon sent back for one control request.
#[derive(Debug, Clone, PartialEq)]
pub enum ControlAnswer {
    Response(Value),
    Error(Value),
}

/// This module's outstanding channel-0 requests to the daemon.
pub struct ControlRequests {
    next_corr: AtomicU64,
    pending: Mutex<HashMap<u64, oneshot::Sender<ControlAnswer>>>,
}

impl Default for ControlRequests {
    fn default() -> Self {
        Self {
            next_corr: AtomicU64::new(FIRST_CONTROL_CORR),
            pending: Mutex::new(HashMap::new()),
        }
    }
}

impl ControlRequests {
    /// Send `request` on channel 0 and wait up to `deadline` for its answer.
    /// `None` when it could not be sent, too many are outstanding, or no answer
    /// came in time.
    pub async fn request(
        &self,
        writer: &mpsc::Sender<Frame>,
        request: &ModuleControlRequestFromModule,
        deadline: Duration,
    ) -> Option<ControlAnswer> {
        let body = serde_json::to_vec(request).ok()?;
        let corr = self.next_corr.fetch_add(1, Ordering::Relaxed);
        let (answered, answer) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if pending.len() >= MAX_CONTROL_REQUESTS_IN_FLIGHT {
                return None;
            }
            pending.insert(corr, answered);
        }
        let frame = Frame::build(FrameType::Request, crate::control_flags(), 0, 0, corr, body).ok();
        let answer = match frame {
            Some(frame) => tokio::time::timeout(deadline, async {
                writer.send(frame).await.ok()?;
                answer.await.ok()
            })
            .await
            .ok()
            .flatten(),
            None => None,
        };
        // Forget the question whether or not it was answered, so an answer
        // arriving after the deadline finds nobody and is dropped.
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&corr);
        answer
    }

    /// Hand an answer that arrived on channel 0 to whoever asked. Returns
    /// whether anyone was waiting for it.
    pub fn deliver(&self, corr: u64, answer: ControlAnswer) -> bool {
        let waiting = self
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&corr);
        waiting.is_some_and(|waiting| waiting.send(answer).is_ok())
    }

    /// How many requests are waiting for an answer.
    pub fn outstanding(&self) -> usize {
        self.pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .len()
    }
}

/// The part of a `scope.describe` answer the decision reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DescribeAnswer {
    pub status: ScopeStatus,
    pub scope_epoch: Option<u64>,
    pub owner_synced: bool,
    pub owner_configured: bool,
}

impl DescribeAnswer {
    /// Read a daemon answer. An error frame, or a body that is not a
    /// `scope.describe` answer, reads as no answer at all.
    pub fn from_control(answer: Option<ControlAnswer>) -> Option<Self> {
        let Some(ControlAnswer::Response(body)) = answer else {
            return None;
        };
        match serde_json::from_value::<ModuleControlResponseToModule>(body).ok()? {
            ModuleControlResponseToModule::ScopeDescribe {
                status,
                scope_epoch,
                owner_synced,
                owner_configured,
                ..
            } => Some(Self {
                status,
                scope_epoch,
                owner_synced,
                owner_configured,
            }),
            _ => None,
        }
    }
}

/// What a describe answer says about a session held at `recorded_epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeVerdict {
    /// The session has definitely ended.
    Ended,
    /// It may still be live, or the daemon cannot say yet. Nothing is ended.
    Unresolved,
}

/// Decide whether the session held at `recorded_epoch` has definitely ended.
///
/// Definitive, following the daemon's reader rules:
/// - `ended` at or after the recorded epoch;
/// - `live` at a higher epoch: a new session reused the ref, so the old one
///   ended;
/// - `not_live` with `owner_synced`: an owner's first sync after a daemon
///   restart is its full set, so a ref missing from it is gone;
/// - `not_live` with the owner not configured: it will never sync again.
///
/// Everything else is unresolved: `live` at the recorded epoch, `not_live`
/// from a configured owner that has not synced since a daemon restart, an
/// answer with no epoch where one is needed, an error, or no answer.
pub fn classify(answer: Option<&DescribeAnswer>, recorded_epoch: u64) -> ScopeVerdict {
    let Some(answer) = answer else {
        return ScopeVerdict::Unresolved;
    };
    let ended = match answer.status {
        ScopeStatus::Ended => answer
            .scope_epoch
            .is_some_and(|epoch| epoch >= recorded_epoch),
        ScopeStatus::Live => answer
            .scope_epoch
            .is_some_and(|epoch| epoch > recorded_epoch),
        ScopeStatus::NotLive => answer.owner_synced || !answer.owner_configured,
    };
    if ended {
        ScopeVerdict::Ended
    } else {
        ScopeVerdict::Unresolved
    }
}

/// One session scope, as a stamp names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeKey {
    pub owner: Principal,
    pub scope_ref: String,
    pub scope_epoch: u64,
}

impl std::hash::Hash for ScopeKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        // `Principal` has no hash of its own; its label is equal exactly when
        // the principals are.
        crate::journal::call_records::principal_label(Some(&self.owner)).hash(state);
        self.scope_ref.hash(state);
        self.scope_epoch.hash(state);
    }
}

impl ScopeKey {
    pub fn from_stamp(stamp: &ScopeStamp) -> Self {
        Self {
            owner: stamp.owner.clone(),
            scope_ref: stamp.scope_ref.clone(),
            scope_epoch: stamp.scope_epoch,
        }
    }

    /// Whether `stamp` names this scope.
    pub fn names(&self, stamp: &ScopeStamp) -> bool {
        self.owner == stamp.owner
            && self.scope_ref == stamp.scope_ref
            && self.scope_epoch == stamp.scope_epoch
    }
}

#[derive(Debug, Default)]
struct Watched {
    /// The conversations routes under this scope carried when they closed.
    conversations: BTreeSet<String>,
    /// Woken when another route under the scope closes while its watcher
    /// waits out an interval, so that close is asked about at once rather
    /// than at the next interval.
    closed_again: std::sync::Arc<tokio::sync::Notify>,
}

/// The scopes whose routes closed and whose end has not been settled, and how
/// to ask the daemon about them.
pub struct ScopeRevocation {
    pub control: ControlRequests,
    watched: Mutex<HashMap<ScopeKey, Watched>>,
    /// How long an unresolved scope waits before it is asked about again.
    /// [`SCOPE_RECHECK_INTERVAL`] in production; tests shorten it.
    pub recheck_interval: Duration,
    /// How long one describe may wait. [`SCOPE_DESCRIBE_TIMEOUT`] in
    /// production; tests shorten it.
    pub describe_timeout: Duration,
}

impl Default for ScopeRevocation {
    fn default() -> Self {
        Self {
            control: ControlRequests::default(),
            watched: Mutex::new(HashMap::new()),
            recheck_interval: SCOPE_RECHECK_INTERVAL,
            describe_timeout: SCOPE_DESCRIBE_TIMEOUT,
        }
    }
}

impl ScopeRevocation {
    /// Intervals shortened for tests that exercise the re-ask without waiting
    /// out the production ones.
    pub fn with_intervals(recheck_interval: Duration, describe_timeout: Duration) -> Self {
        Self {
            recheck_interval,
            describe_timeout,
            ..Self::default()
        }
    }

    fn watched(&self) -> std::sync::MutexGuard<'_, HashMap<ScopeKey, Watched>> {
        self.watched.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Note that a route under `key`, carrying `conversation_key`, closed.
    /// Returns true when nobody is watching the scope yet, so the caller
    /// starts the one watcher it gets.
    pub fn note_closed(&self, key: &ScopeKey, conversation_key: &str) -> bool {
        let mut watched = self.watched();
        let starting = !watched.contains_key(key);
        let entry = watched.entry(key.clone()).or_default();
        entry.conversations.insert(conversation_key.to_string());
        if !starting {
            entry.closed_again.notify_one();
        }
        starting
    }

    /// What wakes `key`'s watcher when another route under it closes.
    pub fn closed_again(&self, key: &ScopeKey) -> std::sync::Arc<tokio::sync::Notify> {
        self.watched()
            .entry(key.clone())
            .or_default()
            .closed_again
            .clone()
    }

    /// The conversations noted for `key` so far.
    pub fn conversations(&self, key: &ScopeKey) -> BTreeSet<String> {
        self.watched()
            .get(key)
            .map(|watched| watched.conversations.clone())
            .unwrap_or_default()
    }

    /// Stop watching `key`, returning the conversations it had noted.
    pub fn finish(&self, key: &ScopeKey) -> BTreeSet<String> {
        self.watched()
            .remove(key)
            .map(|watched| watched.conversations)
            .unwrap_or_default()
    }

    /// Whether anything watches `key`.
    pub fn is_watching(&self, key: &ScopeKey) -> bool {
        self.watched().contains_key(key)
    }

    /// Ask the daemon about `key`'s scope.
    pub async fn describe(
        &self,
        writer: &mpsc::Sender<Frame>,
        key: &ScopeKey,
    ) -> Option<DescribeAnswer> {
        let request = ModuleControlRequestFromModule::ScopeDescribe {
            owner: key.owner.clone(),
            scope_ref: key.scope_ref.clone(),
        };
        DescribeAnswer::from_control(
            self.control
                .request(writer, &request, self.describe_timeout)
                .await,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn answer(
        status: ScopeStatus,
        scope_epoch: Option<u64>,
        owner_synced: bool,
        owner_configured: bool,
    ) -> DescribeAnswer {
        DescribeAnswer {
            status,
            scope_epoch,
            owner_synced,
            owner_configured,
        }
    }

    #[test]
    fn only_the_daemons_definitive_answers_end_a_scope() {
        use ScopeStatus::{Ended, Live, NotLive};
        const END: ScopeVerdict = ScopeVerdict::Ended;
        const HOLD: ScopeVerdict = ScopeVerdict::Unresolved;
        let cases = [
            (Some(answer(Ended, Some(3), true, true)), END),
            (Some(answer(Ended, Some(4), true, true)), END),
            (Some(answer(Ended, Some(2), true, true)), HOLD),
            (Some(answer(Ended, None, true, true)), HOLD),
            (Some(answer(Live, Some(4), true, true)), END),
            (Some(answer(Live, Some(3), true, true)), HOLD),
            (Some(answer(Live, Some(2), true, true)), HOLD),
            (Some(answer(NotLive, None, true, true)), END),
            (Some(answer(NotLive, None, false, false)), END),
            // A configured owner that has not synced since a daemon restart.
            (Some(answer(NotLive, None, false, true)), HOLD),
            (None, HOLD),
        ];
        for (answer, expected) in cases {
            assert_eq!(classify(answer.as_ref(), 3), expected, "{answer:?}");
        }
    }

    #[test]
    fn an_error_or_a_foreign_body_reads_as_no_answer() {
        assert_eq!(
            DescribeAnswer::from_control(Some(ControlAnswer::Error(
                serde_json::json!({"code": "unknown_control_op", "message": "no"})
            ))),
            None
        );
        assert_eq!(
            DescribeAnswer::from_control(Some(ControlAnswer::Response(
                serde_json::json!({"op": "catalog.update"})
            ))),
            None
        );
        assert_eq!(DescribeAnswer::from_control(None), None);
    }

    #[tokio::test]
    async fn an_answer_is_matched_to_its_question_by_correlation_and_a_late_one_is_dropped() {
        let requests = std::sync::Arc::new(ControlRequests::default());
        let (writer, mut sent) = mpsc::channel(4);
        let asking = {
            let requests = std::sync::Arc::clone(&requests);
            tokio::spawn(async move {
                requests
                    .request(
                        &writer,
                        &ModuleControlRequestFromModule::ScopeDescribe {
                            owner: Principal::Reserved {
                                module_id: "prefrontal-core".into(),
                            },
                            scope_ref: "s-1".into(),
                        },
                        Duration::from_secs(5),
                    )
                    .await
            })
        };
        let question = sent.recv().await.unwrap();
        assert_eq!(question.header.ty, FrameType::Request);
        assert_eq!(question.header.channel, 0);
        let body: Value = serde_json::from_slice(&question.body).unwrap();
        assert_eq!(body["op"], "scope.describe");
        assert_eq!(body["ref"], "s-1");
        assert!(!requests.deliver(
            question.header.corr + 1,
            ControlAnswer::Response(Value::Null)
        ));
        assert!(requests.deliver(
            question.header.corr,
            ControlAnswer::Response(serde_json::json!({"answered": true}))
        ));
        assert_eq!(
            asking.await.unwrap(),
            Some(ControlAnswer::Response(
                serde_json::json!({"answered": true})
            ))
        );
        assert!(!requests.deliver(question.header.corr, ControlAnswer::Response(Value::Null)));
        assert_eq!(requests.outstanding(), 0);
    }

    #[tokio::test]
    async fn an_unanswered_question_ends_at_its_deadline_and_is_forgotten() {
        let requests = ControlRequests::default();
        let (writer, _sent) = mpsc::channel(4);
        let answer = requests
            .request(
                &writer,
                &ModuleControlRequestFromModule::LiveRoots {},
                Duration::from_millis(20),
            )
            .await;
        assert_eq!(answer, None);
        assert_eq!(requests.outstanding(), 0);
    }
}
