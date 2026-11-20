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
    pending: Mutex<HashMap<u64, PendingControl>>,
    connection: std::sync::OnceLock<mpsc::WeakSender<Frame>>,
}

struct PendingControl {
    operation: String,
    answer: oneshot::Sender<ControlAnswer>,
}

struct ForgetControl<'a>(&'a ControlRequests, u64);
impl Drop for ForgetControl<'_> {
    fn drop(&mut self) {
        self.0
            .pending
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.1);
    }
}

impl Default for ControlRequests {
    fn default() -> Self {
        Self::starting_at(FIRST_CONTROL_CORR)
    }
}

impl ControlRequests {
    pub(crate) fn starting_at(first: u64) -> Self {
        Self {
            next_corr: AtomicU64::new(first),
            pending: Mutex::new(HashMap::new()),
            connection: std::sync::OnceLock::new(),
        }
    }

    /// Attach the module connection only after its daemon handshake succeeds.
    /// Isolated planes have no connection and cannot invent scope authority.
    pub fn connect(&self, writer: &mpsc::Sender<Frame>) -> bool {
        // Plane clones may outlive the connection. Retaining its writer here
        // would prevent the egress channel from ever closing during shutdown.
        self.connection.set(writer.downgrade()).is_ok()
    }

    pub(crate) async fn request_connected(
        &self,
        request: &impl serde::Serialize,
        deadline: Duration,
    ) -> Option<ControlAnswer> {
        let writer = self.connection.get()?.upgrade()?;
        self.request(&writer, request, deadline).await
    }

    /// Send `request` on channel 0 and wait up to `deadline` for its answer.
    /// `None` when it could not be sent, too many are outstanding, or no answer
    /// came in time.
    pub async fn request(
        &self,
        writer: &mpsc::Sender<Frame>,
        request: &impl serde::Serialize,
        deadline: Duration,
    ) -> Option<ControlAnswer> {
        self.request_with_version(
            writer,
            request,
            Some(deadline),
            subc_protocol::PROTOCOL_VERSION,
        )
        .await
    }

    pub(crate) async fn request_with_version(
        &self,
        writer: &mpsc::Sender<Frame>,
        request: &impl serde::Serialize,
        deadline: Option<Duration>,
        ver: u8,
    ) -> Option<ControlAnswer> {
        let body = serde_json::to_vec(request).ok()?;
        let value: Value = serde_json::from_slice(&body).ok()?;
        let operation = value.get("op")?.as_str()?.to_owned();
        let corr = self.next_corr.fetch_add(1, Ordering::Relaxed);
        let (answered, answer) = oneshot::channel();
        {
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
            if pending.len() >= MAX_CONTROL_REQUESTS_IN_FLIGHT {
                return None;
            }
            pending.insert(
                corr,
                PendingControl {
                    operation,
                    answer: answered,
                },
            );
        }
        let _forget = ForgetControl(self, corr);
        let frame = Frame::build_with_version(
            ver,
            FrameType::Request,
            crate::control_flags(),
            0,
            0,
            corr,
            body,
        )
        .ok()?;
        let wait = async {
            writer.send(frame).await.ok()?;
            answer.await.ok()
        };
        match deadline {
            Some(deadline) => tokio::time::timeout(deadline, wait).await.ok().flatten(),
            None => wait.await,
        }
    }

    /// Hand an answer that arrived on channel 0 to whoever asked. Returns
    /// whether anyone was waiting for it.
    pub fn deliver(&self, corr: u64, answer: ControlAnswer) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
        if let ControlAnswer::Response(body) = &answer {
            if pending
                .get(&corr)
                .is_none_or(|waiting| body["op"] != waiting.operation)
            {
                return false;
            }
        }
        pending
            .remove(&corr)
            .is_some_and(|waiting| waiting.answer.send(answer).is_ok())
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
#[derive(Debug, Clone, Eq)]
pub struct ScopeKey {
    pub owner: Principal,
    pub scope_ref: String,
    pub scope_epoch: u64,
}

impl PartialEq for ScopeKey {
    fn eq(&self, other: &Self) -> bool {
        self.projection() == other.projection()
    }
}

impl std::hash::Hash for ScopeKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.projection().hash(state);
    }
}

impl ScopeKey {
    fn projection(&self) -> (String, &str, u64) {
        let owner = cerebellum_core::principal::read_legacy_scope_owner(&self.owner);
        (
            crate::journal::call_records::principal_label(Some(&owner)),
            &self.scope_ref,
            self.scope_epoch,
        )
    }

    pub fn from_stamp(stamp: &ScopeStamp) -> Self {
        Self {
            owner: stamp.owner.clone(),
            scope_ref: stamp.scope_ref.clone(),
            scope_epoch: stamp.scope_epoch,
        }
    }

    /// Whether `stamp` names this scope.
    pub fn names(&self, stamp: &ScopeStamp) -> bool {
        self == &Self::from_stamp(stamp)
    }
}

#[derive(Debug, Default)]
struct Watched {
    /// The conversation key of each route under this scope that has closed.
    conversations: BTreeSet<String>,
    /// Woken when another route under the scope closes while its watcher
    /// waits out an interval, so that close is asked about at once rather
    /// than at the next interval.
    closed_again: std::sync::Arc<tokio::sync::Notify>,
}

/// The highest epoch cerebellum has seen stamped for one `(owner, ref)`, and
/// the conversations routes stamped with it carried.
#[derive(Debug, Default)]
struct EpochSeen {
    epoch: u64,
    conversations: BTreeSet<String>,
}

/// What a stamped bind says about its session's epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindEpoch {
    /// The highest epoch seen for its `(owner, ref)`, or the first.
    Current,
    /// Higher than any seen before: every lower epoch of this `(owner, ref)`
    /// has ended, the same as a `live` answer at a higher epoch says. The
    /// conversations those epochs' routes carried are returned so what they
    /// were allowed can be ended before the new route is served.
    Advanced {
        ended_conversations: BTreeSet<String>,
    },
    /// Lower than an epoch already seen: an ended session. Refused.
    Stale { current: u64 },
}

/// The scopes whose routes closed and whose end has not been settled, and how
/// to ask the daemon about them.
pub struct ScopeRevocation {
    pub control: ControlRequests,
    watched: Mutex<HashMap<ScopeKey, Watched>>,
    /// Keyed by `(owner label, ref)`. Grants and questions are keyed by
    /// conversation, and an owner may reuse a ref for a new session whose
    /// route binds before anything noticed the old one ending. This is what
    /// lets the bind itself notice, so a new session never serves under what a
    /// person allowed the old one.
    epochs: Mutex<HashMap<(String, String), EpochSeen>>,
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
            epochs: Mutex::new(HashMap::new()),
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

    /// Note a bind stamped with `stamp` carrying `conversation_key`, and say
    /// whether its epoch is current, newer than any seen, or already ended.
    ///
    /// On an advance, any watcher of a lower epoch of the same `(owner, ref)`
    /// stops holding its conversations: they are returned here to be ended
    /// now, rather than after that watcher's next answer.
    pub fn note_bind(&self, stamp: &ScopeStamp, conversation_key: &str) -> BindEpoch {
        let owner = ScopeKey::from_stamp(stamp).projection().0;
        let mut epochs = self.epochs.lock().unwrap_or_else(PoisonError::into_inner);
        let seen = epochs
            .entry((owner, stamp.scope_ref.clone()))
            .or_insert_with(|| EpochSeen {
                epoch: stamp.scope_epoch,
                conversations: BTreeSet::new(),
            });
        if stamp.scope_epoch < seen.epoch {
            return BindEpoch::Stale {
                current: seen.epoch,
            };
        }
        let verdict = if stamp.scope_epoch > seen.epoch {
            let mut ended_conversations = std::mem::take(&mut seen.conversations);
            seen.epoch = stamp.scope_epoch;
            let mut watched = self.watched();
            let superseded: Vec<ScopeKey> = watched
                .keys()
                .filter(|key| {
                    cerebellum_core::principal::read_legacy_scope_owner(&key.owner)
                        == cerebellum_core::principal::read_legacy_scope_owner(&stamp.owner)
                        && key.scope_ref == stamp.scope_ref
                        && key.scope_epoch < stamp.scope_epoch
                })
                .cloned()
                .collect();
            for key in superseded {
                if let Some(old) = watched.remove(&key) {
                    ended_conversations.extend(old.conversations);
                }
            }
            BindEpoch::Advanced {
                ended_conversations,
            }
        } else {
            BindEpoch::Current
        };
        seen.conversations.insert(conversation_key.to_string());
        verdict
    }

    /// Whether a newer epoch of `stamp`'s `(owner, ref)` has been seen, which
    /// means `stamp`'s session has ended. A route still bound under it (its
    /// close not yet delivered) must serve nothing more.
    pub fn is_superseded(&self, stamp: &ScopeStamp) -> bool {
        let owner = ScopeKey::from_stamp(stamp).projection().0;
        self.epochs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(owner, stamp.scope_ref.clone()))
            .is_some_and(|seen| seen.epoch > stamp.scope_epoch)
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

    /// Retained consent cards need a scope watcher without claiming that a
    /// browser conversation was open in this process. Share any existing watch.
    pub(crate) fn note_retained(&self, key: &ScopeKey) -> bool {
        let mut watched = self.watched();
        if let std::collections::hash_map::Entry::Vacant(entry) = watched.entry(key.clone()) {
            entry.insert(Watched::default());
            true
        } else {
            false
        }
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

    /// After `key`'s session ended definitively and its conversations were
    /// revoked, forget the conversations its epoch noted: they protect nothing
    /// more. The epoch itself stays, so a late bind of that or a lower epoch
    /// is still refused as stale and cannot revive the ended session.
    pub fn forget_ended(&self, key: &ScopeKey) {
        let (owner, scope_ref, _) = key.projection();
        let mut epochs = self.epochs.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(seen) = epochs
            .get_mut(&(owner, scope_ref.to_owned()))
            .filter(|seen| seen.epoch == key.scope_epoch)
        {
            seen.conversations.clear();
        }
    }

    /// The conversations the highest epoch of `stamp`'s `(owner, ref)` noted.
    #[cfg(test)]
    pub(crate) fn epoch_conversations(&self, stamp: &ScopeStamp) -> BTreeSet<String> {
        let owner = ScopeKey::from_stamp(stamp).projection().0;
        self.epochs
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&(owner, stamp.scope_ref.clone()))
            .map(|seen| seen.conversations.clone())
            .unwrap_or_default()
    }

    /// Whether anything watches `key`.
    pub fn is_watching(&self, key: &ScopeKey) -> bool {
        self.watched().contains_key(key)
    }

    /// Resolve a retained scope against the owner's current daemon registration.
    pub async fn describe(
        &self,
        writer: &mpsc::Sender<Frame>,
        key: &ScopeKey,
    ) -> Option<DescribeAnswer> {
        let request = ModuleControlRequestFromModule::ScopeDescribe {
            owner: cerebellum_core::principal::read_legacy_scope_owner(&key.owner),
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

    #[test]
    fn prefrontal_rename_scope_keys_share_state() {
        use std::hash::{Hash, Hasher};
        for (before, after) in [
            ("prefrontal-core", "prefrontal"),
            ("prefrontal", "prefrontal-core"),
        ] {
            let mut stamp = crate::computer_grants::tests::stamp("rename-scope");
            stamp.owner = Principal::Reserved {
                module_id: before.into(),
            };
            let old = ScopeKey::from_stamp(&stamp);
            let scopes = ScopeRevocation::default();
            assert_eq!(scopes.note_bind(&stamp, "conversation"), BindEpoch::Current);
            assert!(scopes.note_closed(&old, "conversation"));
            stamp.owner = Principal::Reserved {
                module_id: after.into(),
            };
            let new = ScopeKey::from_stamp(&stamp);
            assert_eq!(
                old.owner,
                Principal::Reserved {
                    module_id: before.into()
                }
            );
            assert_eq!(
                new.owner,
                Principal::Reserved {
                    module_id: after.into()
                }
            );
            assert_eq!(old, new);
            assert!(old.names(&stamp));
            let hash = |key: &ScopeKey| {
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                key.hash(&mut hasher);
                hasher.finish()
            };
            assert_eq!(hash(&old), hash(&new));
            assert!(!scopes.note_closed(&new, "second"));
            assert_eq!(scopes.conversations(&new).len(), 2);
            stamp.scope_ref.push_str("-different");
            assert_ne!(old, ScopeKey::from_stamp(&stamp));
            stamp.scope_ref = old.scope_ref.clone();
            stamp.scope_epoch += 1;
            assert_ne!(old, ScopeKey::from_stamp(&stamp));
            assert!(matches!(
                scopes.note_bind(&stamp, "new"),
                BindEpoch::Advanced { .. }
            ));
            assert!(scopes.is_superseded(&subc_protocol::scope::ScopeStamp::new(
                old.owner.clone(),
                old.scope_ref.clone(),
                old.scope_epoch,
                subc_protocol::scope::ScopeKind::Head,
            )));
            stamp.scope_epoch = old.scope_epoch;
            stamp.owner = Principal::Reserved {
                module_id: "prefrontal-corex".into(),
            };
            assert_ne!(old, ScopeKey::from_stamp(&stamp));
        }
    }

    /// A definitive end drops the conversations its epoch noted, so many
    /// sequential sessions on distinct refs hold no conversation strings once
    /// they end. The epoch stays: a late bind of a lower epoch still refuses.
    #[test]
    fn an_ended_scope_forgets_its_conversations_but_still_refuses_stale_binds() {
        let scopes = ScopeRevocation::default();
        let mut stamp = crate::computer_grants::tests::stamp("ended-scope");
        stamp.scope_epoch = 2;
        assert_eq!(scopes.note_bind(&stamp, "first"), BindEpoch::Current);
        assert_eq!(scopes.note_bind(&stamp, "second"), BindEpoch::Current);
        let older = ScopeKey {
            scope_epoch: 1,
            ..ScopeKey::from_stamp(&stamp)
        };
        scopes.forget_ended(&older);
        assert_eq!(
            scopes.epoch_conversations(&stamp).len(),
            2,
            "an older epoch's end leaves the current epoch's conversations"
        );
        scopes.forget_ended(&ScopeKey::from_stamp(&stamp));
        assert!(scopes.epoch_conversations(&stamp).is_empty());
        let mut late = stamp.clone();
        late.scope_epoch = 1;
        assert_eq!(
            scopes.note_bind(&late, "late"),
            BindEpoch::Stale { current: 2 }
        );
        stamp.scope_epoch = 3;
        assert_eq!(
            scopes.note_bind(&stamp, "next"),
            BindEpoch::Advanced {
                ended_conversations: BTreeSet::new()
            }
        );
    }

    #[test]
    fn retained_consent_and_closed_routes_share_one_watch_without_inventing_a_conversation() {
        let scopes = ScopeRevocation::default();
        let key = ScopeKey::from_stamp(&crate::computer_grants::tests::stamp("scope"));
        assert!(scopes.note_retained(&key));
        assert!(!scopes.note_retained(&key));
        assert!(scopes.conversations(&key).is_empty());
        assert!(!scopes.note_closed(&key, "real-conversation"));
        assert_eq!(
            scopes.finish(&key),
            BTreeSet::from(["real-conversation".into()])
        );
        assert!(scopes.note_closed(&key, "another-conversation"));
        assert!(!scopes.note_retained(&key));
        assert_eq!(
            scopes.finish(&key),
            BTreeSet::from(["another-conversation".into()])
        );
    }

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

    #[tokio::test]
    async fn a_retained_scope_is_described_once_under_the_current_owner() {
        for stored in ["prefrontal-core", "prefrontal"] {
            let scopes = ScopeRevocation::default();
            let key = ScopeKey {
                owner: Principal::Reserved {
                    module_id: stored.into(),
                },
                scope_ref: "head".into(),
                scope_epoch: 7,
            };
            let (writer, mut sent) = mpsc::channel::<Frame>(4);
            let respond = async {
                let frame = sent.recv().await.unwrap();
                let body: Value = serde_json::from_slice(&frame.body).unwrap();
                assert_eq!(body["ref"], "head");
                assert_eq!(body["owner"]["module_id"], "prefrontal");
                assert!(scopes.control.deliver(
                    frame.header.corr,
                    ControlAnswer::Response(serde_json::json!({
                        "op":"scope.describe", "status":"ended", "scope_epoch":7,
                        "daemon_incarnation":"test", "owner_synced":true, "owner_configured":true,
                    }))
                ));
            };
            let (result, ()) = tokio::join!(scopes.describe(&writer, &key), respond);
            assert_eq!(classify(result.as_ref(), 7), ScopeVerdict::Ended);
            assert!(sent.try_recv().is_err());
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
                                module_id: "prefrontal".into(),
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
            ControlAnswer::Response(serde_json::json!({"op":"scope.describe", "answered": true}))
        ));
        assert_eq!(
            asking.await.unwrap(),
            Some(ControlAnswer::Response(
                serde_json::json!({"op":"scope.describe", "answered": true})
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
