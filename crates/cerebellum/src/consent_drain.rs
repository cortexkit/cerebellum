//! Apply late consent answers only while serving an admitted session call.
//!
//! Each flow owns its pending records and elects the caller that stores the
//! effect. The drain shares that election through a per-kind adapter, rather
//! than keeping a second pending map that could let two callers act.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};

use crate::cingulate_client::card::CardKind;
use crate::cingulate_client::desk::{
    Apply, ApplyFailed, ConsentDesk, DrainReport, Ending, RaisedCard, RegistryStore,
};
use crate::cingulate_client::live_call::{LiveCall, NotLive, SessionKey};
use crate::cingulate_client::route::{BoxFuture, CallError, CingulateOpener, CingulateRoute};
use crate::cingulate_client::wire::Record;
use crate::{AcceptedBindFacts, BoundRoute, Frame, Planes};

/// An elected settlement, whose completion cannot be announced until the desk
/// has finished recording any single-use approval and its applied mark.
pub struct AppliedSettlement {
    pub effect: Apply,
    pub completion: Option<Arc<tokio::sync::watch::Sender<bool>>>,
}

/// A flow's pending-record lookup and settlement election.
///
/// `apply` removes the pending record under the flow's lock, releases that lock,
/// and stores the effect before returning. Only the elected caller returns the
/// record's completion sender; losers leave it to the winner to fire. Holders
/// subscribe to that same watch before awaiting Cingulate. `has_pending` must
/// include a settlement still being stored by a holder; `apply` returns
/// `ApplyFailed` in that case, so the drain cannot ack before the holder's write.
pub trait ConsentEffects: Send + Sync {
    fn has_pending(&self, card: &RaisedCard) -> bool;
    fn apply(
        &self,
        card: &RaisedCard,
        record: &Record,
        ending: &Ending,
    ) -> Result<AppliedSettlement, ApplyFailed>;
}

/// Late login answers need no memory-only pending record: the desk records the
/// approval under the durable subject so a retry can take it exactly once.
struct SingleUseEffects;

impl ConsentEffects for SingleUseEffects {
    fn has_pending(&self, _card: &RaisedCard) -> bool {
        true
    }

    fn apply(
        &self,
        _card: &RaisedCard,
        _record: &Record,
        _ending: &Ending,
    ) -> Result<AppliedSettlement, ApplyFailed> {
        Ok(AppliedSettlement {
            effect: Apply::Applied,
            completion: None,
        })
    }
}

/// Shared by every route and clone of a plane. A weak lock entry can disappear
/// after the last pass, without retaining every session the module ever served.
pub struct ConsentDrain {
    sessions: Mutex<HashMap<SessionKey, Weak<tokio::sync::Mutex<()>>>>,
    effects: Mutex<HashMap<CardKind, Arc<dyn ConsentEffects>>>,
}

impl Default for ConsentDrain {
    fn default() -> Self {
        let login: Arc<dyn ConsentEffects> = Arc::new(SingleUseEffects);
        Self {
            sessions: Mutex::new(HashMap::new()),
            effects: Mutex::new(HashMap::from([
                (CardKind::LoginImport, Arc::clone(&login)),
                (CardKind::LoginCapture, login),
            ])),
        }
    }
}

impl ConsentDrain {
    /// Register the flow's adapter before it can raise cards of this kind.
    /// Unregistered kinds are left unapplied and unacknowledged, so a flow wired
    /// later can still receive their answers.
    pub fn register(&self, kind: CardKind, effects: Arc<dyn ConsentEffects>) {
        self.effects.lock().unwrap().insert(kind, effects);
    }

    fn session_lock(&self, session: &SessionKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = sessions.get(session).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(tokio::sync::Mutex::new(()));
        sessions.insert(session.clone(), Arc::downgrade(&lock));
        lock
    }

    /// Sweep lost memory-only records before reading the feed, then apply and
    /// acknowledge answers. The session lock covers the entire pass, including
    /// the registry check, so a waiting call opens no second route after a winner.
    pub async fn run(&self, desk: &ConsentDesk, live: &LiveCall) -> Result<DrainReport, Ending> {
        let lock = self.session_lock(live.session());
        let _pass = lock.lock().await;
        let cards = desk.unapplied(live.session());
        if cards.is_empty() {
            return Ok(DrainReport::default());
        }
        let effects = self.effects.lock().unwrap().clone();
        let mut session = desk
            .session(live)
            .await
            .map_err(|error| Ending::of_refusal(&error))?;
        for card in &cards {
            let Some(adapter) = effects.get(&card.kind) else {
                // Absence of an adapter is not proof of a lost pending record.
                continue;
            };
            if card.kind.single_use() || adapter.has_pending(card) {
                continue;
            }
            let record = session.get(&card.elicitation_id).await?;
            if !record.is_settled() {
                // If withdrawal races an answer, keep the settled card for the
                // answer feed to acknowledge without minting a permission.
                // withdraw forgets cards refused as NotOwner or NotFound.
                if let Err(ending) = session.withdraw(&card.elicitation_id).await {
                    if desk.raised(&card.elicitation_id).is_some() {
                        return Err(ending);
                    }
                }
            }
        }
        let mut completions = Vec::new();
        let result = session
            .drain_answers(&mut |card, record, ending| {
                let adapter = effects.get(&card.kind).ok_or_else(|| {
                    ApplyFailed("the card's flow has not registered a consent adapter".into())
                })?;
                if !card.kind.single_use() && !adapter.has_pending(card) {
                    return Ok(Apply::NoRecord);
                }
                let applied = adapter.apply(card, record, ending)?;
                if let Some(completion) = applied.completion {
                    completions.push(completion);
                }
                Ok(applied.effect)
            })
            .await;
        // A caller that lost the settlement election may now use the stored
        // permission or single-use approval. Release its completion watch even
        // if acknowledging the answer feed failed; the effect is already stored.
        for completion in completions {
            completion.send_replace(true);
        }
        result
    }
}

/// Require the same prefrontal-core caller, attested agent project, and non-flow
/// session as consent-raising calls. An operator's direct route cannot borrow
/// the agent's permission to reach Cingulate merely by copying its scope stamp.
pub fn live_call(
    frame: &Frame,
    facts: &AcceptedBindFacts,
    planes: &Planes,
) -> Result<LiveCall, NotLive> {
    let stamp = (facts.admits_session_calls()
        && facts.agent_project_id_attested
        && facts.flow_id.is_none())
    .then_some(facts.scope.as_ref())
    .flatten();
    let guard = crate::elicit::ROUTE_GUARD
        .try_with(Arc::clone)
        .map_err(|_| NotLive::CallEnded)?;
    LiveCall::from_inbound(
        stamp,
        &guard,
        Arc::new(BoundRoute {
            routes: Arc::clone(&planes.routes),
            channel: frame.header.channel,
            epoch: frame.header.epoch,
            conversation_key: facts.identity.conversation_key.clone(),
        }),
    )
}

/// Plane constructors without daemon configuration cannot open a route to
/// Cingulate. Before serving calls, `run` installs the opener that authenticates
/// with the supervised module identity and the daemon's connection file.
pub(crate) struct UnconfiguredCingulate;

impl CingulateOpener for UnconfiguredCingulate {
    fn open<'a>(
        &'a self,
        _live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        Box::pin(async { Err(CallError::Transport { code: None }) })
    }
}

/// Failure to resolve the production registry path is an unreadable registry,
/// not permission to replace durable consent state with an empty memory store.
pub(crate) struct UnavailableRegistry(pub String);

impl RegistryStore for UnavailableRegistry {
    fn load(&self) -> Result<Vec<RaisedCard>, String> {
        Err(self.0.clone())
    }

    fn save(&self, _cards: &[RaisedCard]) -> Result<(), String> {
        Err(self.0.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cingulate_client::desk::FileRegistryStore;
    use crate::cingulate_client::wire;
    use crate::cingulate_client::{Reply, ScriptedCingulate};
    use crate::terminal_arbiter::{TerminalArbiter, TerminalCause, CALL_TERMINAL};
    use cerebellum_core::health::HealthState;
    use serde_json::{json, Value};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    use subc_protocol::{BindIdentity, FrameType, Principal, RouteTarget};
    use tokio::sync::mpsc;

    fn stamp() -> ScopeStamp {
        ScopeStamp {
            owner: Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            scope_ref: "head".into(),
            scope_epoch: 3,
            kind: ScopeKind::Head,
            parent: None,
            parent_state: None,
            attributes: ScopeAttributes::new().with_agent_id(Some("test-project".into())),
            owner_authorized: true,
        }
    }

    fn facts() -> AcceptedBindFacts {
        AcceptedBindFacts::from_bind(
            &BindIdentity::new("/test/project", "test", "test-session"),
            Some(Principal::Reserved {
                module_id: "prefrontal-core".into(),
            }),
            Some(
                &json!({"agentProjectId":"test-project", "sessionKind":"primary",
                "effectiveCapabilityScope":["*"]}),
            ),
            None,
            &RouteTarget::ManagementSurface {
                module_id: "cerebellum".into(),
            },
        )
        .with_scope(Some(stamp()))
    }

    fn card(kind: CardKind) -> RaisedCard {
        let stamp = stamp();
        RaisedCard {
            elicitation_id: "el_1".into(),
            session: SessionKey {
                owner: serde_json::to_string(&stamp.owner).unwrap(),
                scope_ref: stamp.scope_ref,
                scope_epoch: stamp.scope_epoch,
            },
            kind,
            subject: "test-subject".into(),
            grant_ids: vec!["allow".into()],
            decline_id: "deny".into(),
            next_steps: Default::default(),
            applied: false,
        }
    }

    static SCRATCH_SEQUENCE: AtomicUsize = AtomicUsize::new(0);

    struct Scratch(std::path::PathBuf);

    impl Scratch {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "cerebellum-consent-drain-{}-{}",
                std::process::id(),
                SCRATCH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn planes(
        cards: &[RaisedCard],
        opener: Arc<dyn CingulateOpener>,
    ) -> (Planes, Scratch, Arc<FileRegistryStore>) {
        let dir = Scratch::new();
        let store = Arc::new(FileRegistryStore::new(dir.0.join("raised.json")));
        store.save(cards).unwrap();
        let planes = Planes::with_cingulate_for_test(
            Arc::new(HealthState::new()),
            None,
            opener,
            store.clone(),
        );
        planes.routes.insert(1, 1, facts());
        planes.routes.insert(2, 1, facts());
        (planes, dir, store)
    }

    fn request(channel: u16) -> Frame {
        Frame::build(
            FrameType::Request,
            crate::control_flags(),
            channel,
            1,
            1,
            serde_json::to_vec(&json!({"method":"test.unknown", "params":{}})).unwrap(),
        )
        .unwrap()
    }

    async fn invoke(planes: &Planes, channel: u16) -> Frame {
        let (writer, mut rx) = mpsc::channel(16);
        crate::handle_frame_for_test(request(channel), &writer, planes)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap()
    }

    fn ordinary_reply(frame: &Frame) {
        assert_eq!(frame.header.ty, FrameType::Error);
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(body["code"], "unknown_method");
    }

    fn record(state: &str) -> Value {
        json!({"elicitation_id":"el_1", "state":state, "answered_choice_id":"allow"})
    }

    fn feed(cingulate: &Arc<ScriptedCingulate>) {
        cingulate
            .then(
                wire::CONSENT_ANSWERS,
                Reply::Result(json!({"records":[record("answered")], "cursor":1})),
            )
            .then(wire::CONSENT_ACK, Reply::Result(json!({})));
    }

    struct Effects {
        present: bool,
        applied: AtomicUsize,
        completion: Arc<tokio::sync::watch::Sender<bool>>,
    }

    impl Effects {
        fn new(present: bool) -> Arc<Self> {
            Arc::new(Self {
                present,
                applied: AtomicUsize::new(0),
                completion: Arc::new(tokio::sync::watch::channel(false).0),
            })
        }
    }

    impl ConsentEffects for Effects {
        fn has_pending(&self, _card: &RaisedCard) -> bool {
            self.present
        }
        fn apply(
            &self,
            _card: &RaisedCard,
            _record: &Record,
            _ending: &Ending,
        ) -> Result<AppliedSettlement, ApplyFailed> {
            assert!(self.present, "a missing record must never mint an effect");
            self.applied.fetch_add(1, Ordering::SeqCst);
            Ok(AppliedSettlement {
                effect: Apply::Applied,
                completion: Some(Arc::clone(&self.completion)),
            })
        }
    }

    #[tokio::test]
    async fn no_unapplied_card_opens_no_route() {
        for cards in [
            vec![],
            vec![RaisedCard {
                applied: true,
                ..card(CardKind::AppControl)
            }],
        ] {
            let cingulate = ScriptedCingulate::new();
            let (planes, _dir, _store) = planes(&cards, Arc::new(cingulate.clone()));
            ordinary_reply(&invoke(&planes, 1).await);
            assert_eq!(cingulate.opens(), 0);
        }
    }

    #[tokio::test]
    async fn copied_stamp_on_a_direct_route_opens_no_route() {
        let cingulate = ScriptedCingulate::new();
        let (planes, _dir, _store) =
            planes(&[card(CardKind::LoginImport)], Arc::new(cingulate.clone()));
        let mut direct = facts();
        direct.principal = Some(Principal::Direct);
        // Keep the daemon-attested agent project and the agent's scope stamp.
        // Changing only the caller to Direct must still forbid opening Cingulate
        // under that session, regardless of the copied identity metadata.
        planes.routes.insert(1, 1, direct);
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.opens(), 0);
    }

    #[tokio::test]
    async fn unscoped_unattested_and_flow_routes_open_no_route() {
        let cingulate = ScriptedCingulate::new();
        let (planes, _dir, _store) =
            planes(&[card(CardKind::LoginImport)], Arc::new(cingulate.clone()));
        let mut unscoped = facts();
        unscoped.scope = None;
        let mut unattested = facts();
        unattested.agent_project_id_attested = false;
        let mut flow = facts();
        flow.flow_id = Some("background-flow".into());
        for facts in [unscoped, unattested, flow] {
            planes.routes.insert(1, 1, facts);
            ordinary_reply(&invoke(&planes, 1).await);
        }
        assert_eq!(cingulate.opens(), 0);
    }

    #[tokio::test]
    async fn drain_open_failure_preserves_reply_and_registry() {
        let cingulate = ScriptedCingulate::new();
        *cingulate.refuse_open.lock().unwrap() = Some("scope_not_carrier");
        let (planes, _dir, store) =
            planes(&[card(CardKind::LoginImport)], Arc::new(cingulate.clone()));
        let before = std::fs::read(store.path()).unwrap();
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.opens(), 1);
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert!(!planes.consent.raised("el_1").unwrap().applied);
    }

    #[tokio::test]
    async fn unreadable_registry_preserves_reply_and_file() {
        let cingulate = ScriptedCingulate::new();
        let (planes, _dir, store) = planes(&[], Arc::new(cingulate.clone()));
        let before = b"{\"version\":999,\"cards\":[]}";
        std::fs::write(store.path(), before).unwrap();
        let planes = planes.with_cingulate(Arc::new(cingulate.clone()), store.clone());
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.opens(), 0);
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }

    #[tokio::test]
    async fn handler_without_a_live_guard_opens_no_route() {
        let cingulate = ScriptedCingulate::new();
        let (planes, _dir, _store) =
            planes(&[card(CardKind::LoginImport)], Arc::new(cingulate.clone()));
        let (writer, mut rx) = mpsc::channel(16);
        crate::handle_route_request(request(1), &writer, &planes)
            .await
            .unwrap();
        ordinary_reply(&rx.recv().await.unwrap());
        assert_eq!(cingulate.opens(), 0);
    }

    #[tokio::test]
    async fn feed_transport_failure_preserves_reply_and_registry() {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_ANSWERS, Reply::Transport);
        let (planes, _dir, store) =
            planes(&[card(CardKind::LoginImport)], Arc::new(cingulate.clone()));
        let before = std::fs::read(store.path()).unwrap();
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.methods(), [wire::CONSENT_ANSWERS]);
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert!(!planes.consent.raised("el_1").unwrap().applied);
    }

    struct FailingEffects;

    impl ConsentEffects for FailingEffects {
        fn has_pending(&self, _card: &RaisedCard) -> bool {
            true
        }
        fn apply(
            &self,
            _card: &RaisedCard,
            _record: &Record,
            _ending: &Ending,
        ) -> Result<AppliedSettlement, ApplyFailed> {
            Err(ApplyFailed("effect store refused the write".into()))
        }
    }

    #[tokio::test]
    async fn apply_failure_preserves_reply_and_registry() {
        let cingulate = ScriptedCingulate::new();
        feed(&cingulate);
        let (planes, _dir, store) =
            planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
        planes
            .consent_drain
            .register(CardKind::AppControl, Arc::new(FailingEffects));
        let before = std::fs::read(store.path()).unwrap();
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.methods(), [wire::CONSENT_ANSWERS]);
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert!(!planes.consent.raised("el_1").unwrap().applied);
    }

    #[tokio::test]
    async fn unadapted_answer_is_not_applied_or_acked() {
        let cingulate = ScriptedCingulate::new();
        feed(&cingulate);
        let (planes, _dir, store) =
            planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
        let before = std::fs::read(store.path()).unwrap();
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.methods(), [wire::CONSENT_ANSWERS]);
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
        assert!(!planes.consent.raised("el_1").unwrap().applied);
    }

    #[tokio::test]
    async fn memory_only_pending_card_is_withdrawn_before_feed() {
        for refusal in [
            None,
            Some("elicitation_not_owner"),
            Some("elicitation_not_found"),
        ] {
            let cingulate = ScriptedCingulate::new();
            cingulate
                .then(wire::CONSENT_GET, Reply::Result(record("pending")))
                .then(
                    wire::CONSENT_WITHDRAW,
                    refusal.map_or_else(|| Reply::Result(record("withdrawn")), Reply::Refused),
                );
            feed(&cingulate);
            let (planes, _dir, store) =
                planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
            let effects = Effects::new(false);
            planes
                .consent_drain
                .register(CardKind::AppControl, effects.clone());
            ordinary_reply(&invoke(&planes, 1).await);
            assert_eq!(
                cingulate.methods(),
                [
                    wire::CONSENT_GET,
                    wire::CONSENT_WITHDRAW,
                    wire::CONSENT_ANSWERS,
                    wire::CONSENT_ACK
                ]
            );
            assert!(store.load().unwrap().is_empty());
            assert_eq!(effects.applied.load(Ordering::SeqCst), 0);
        }
    }

    #[tokio::test]
    async fn missing_settled_record_is_acked_without_effect() {
        for settled_at_get in [true, false] {
            let cingulate = ScriptedCingulate::new();
            cingulate.then(
                wire::CONSENT_GET,
                Reply::Result(record(if settled_at_get {
                    "answered"
                } else {
                    "pending"
                })),
            );
            if !settled_at_get {
                cingulate.then(wire::CONSENT_WITHDRAW, Reply::Result(record("answered")));
            }
            feed(&cingulate);
            let (planes, _dir, store) =
                planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
            let effects = Effects::new(false);
            planes
                .consent_drain
                .register(CardKind::AppControl, effects.clone());
            ordinary_reply(&invoke(&planes, 1).await);
            assert_eq!(cingulate.methods().last().unwrap(), wire::CONSENT_ACK);
            assert!(store.load().unwrap().is_empty());
            assert_eq!(effects.applied.load(Ordering::SeqCst), 0);
            assert!(!*effects.completion.borrow());
        }
    }

    #[tokio::test]
    async fn sweep_transport_failure_preserves_reply_and_registry() {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_GET, Reply::Transport);
        let (planes, _dir, store) =
            planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
        planes
            .consent_drain
            .register(CardKind::AppControl, Effects::new(false));
        let before = std::fs::read(store.path()).unwrap();
        ordinary_reply(&invoke(&planes, 1).await);
        assert_eq!(cingulate.methods(), [wire::CONSENT_GET]);
        assert_eq!(std::fs::read(store.path()).unwrap(), before);
    }

    struct ProbeOpener {
        cingulate: Arc<ScriptedCingulate>,
        opens: AtomicUsize,
        delay_first: bool,
        completion: Option<Arc<tokio::sync::watch::Sender<bool>>>,
    }

    impl CingulateOpener for ProbeOpener {
        fn open<'a>(
            &'a self,
            live: &'a LiveCall,
        ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
            Box::pin(async move {
                let first = self.opens.fetch_add(1, Ordering::SeqCst) == 0;
                if self.delay_first && first {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let route = self.cingulate.open(live).await?;
                Ok(Box::new(ProbeRoute {
                    route,
                    completion: self.completion.clone(),
                }) as Box<dyn CingulateRoute>)
            })
        }
    }

    struct ProbeRoute {
        route: Box<dyn CingulateRoute>,
        completion: Option<Arc<tokio::sync::watch::Sender<bool>>>,
    }

    impl CingulateRoute for ProbeRoute {
        fn call<'a>(
            &'a mut self,
            method: &'a str,
            params: Value,
        ) -> BoxFuture<'a, Result<Value, CallError>> {
            Box::pin(async move {
                if method == wire::CONSENT_ACK {
                    if let Some(completion) = &self.completion {
                        assert!(
                            !*completion.borrow(),
                            "completion fired before drain_answers returned"
                        );
                    }
                }
                self.route.call(method, params).await
            })
        }
    }

    #[tokio::test]
    async fn concurrent_session_calls_share_one_drain() {
        let cingulate = ScriptedCingulate::new();
        feed(&cingulate);
        feed(&cingulate);
        let opener = Arc::new(ProbeOpener {
            cingulate: cingulate.clone(),
            opens: AtomicUsize::new(0),
            delay_first: true,
            completion: None,
        });
        let (planes, _dir, store) = planes(&[card(CardKind::AppControl)], opener);
        let effects = Effects::new(true);
        planes
            .consent_drain
            .register(CardKind::AppControl, effects.clone());
        let cloned = planes.clone();
        let (first, second) = tokio::join!(invoke(&planes, 1), invoke(&cloned, 2));
        ordinary_reply(&first);
        ordinary_reply(&second);
        assert_eq!(
            cingulate.opens(),
            1,
            "the second call must recheck under the session lock"
        );
        assert_eq!(effects.applied.load(Ordering::SeqCst), 1);
        assert!(store.load().unwrap().is_empty());
    }

    #[tokio::test]
    async fn drain_winner_fires_completion_after_approval_and_ack() {
        let cingulate = ScriptedCingulate::new();
        feed(&cingulate);
        let effects = Effects::new(true);
        let opener = Arc::new(ProbeOpener {
            cingulate: cingulate.clone(),
            opens: AtomicUsize::new(0),
            delay_first: false,
            completion: Some(effects.completion.clone()),
        });
        let (planes, _dir, store) = planes(&[card(CardKind::LoginImport)], opener);
        planes
            .consent_drain
            .register(CardKind::LoginImport, effects.clone());
        ordinary_reply(&invoke(&planes, 1).await);
        assert!(*effects.completion.borrow());
        assert_eq!(effects.applied.load(Ordering::SeqCst), 1);
        assert_eq!(
            planes
                .consent
                .take_single_use_approval(&card(CardKind::LoginImport).session, "test-subject"),
            Some("el_1".into())
        );
        assert!(store.load().unwrap().is_empty());
    }

    #[tokio::test]
    async fn rebuilt_login_desk_records_a_single_use_approval() {
        for kind in [CardKind::LoginImport, CardKind::LoginCapture] {
            let cingulate = ScriptedCingulate::new();
            feed(&cingulate);
            let (planes, _dir, store) = planes(&[card(kind)], Arc::new(cingulate.clone()));
            ordinary_reply(&invoke(&planes, 1).await);
            assert_eq!(
                planes
                    .consent
                    .take_single_use_approval(&card(kind).session, "test-subject"),
                Some("el_1".into())
            );
            assert_eq!(
                planes
                    .consent
                    .take_single_use_approval(&card(kind).session, "test-subject"),
                None
            );
            let rebuilt = Planes::with_cingulate_for_test(
                Arc::new(HealthState::new()),
                None,
                Arc::new(cingulate.clone()),
                store.clone(),
            );
            rebuilt.routes.insert(1, 1, facts());
            ordinary_reply(&invoke(&rebuilt, 1).await);
            assert_eq!(cingulate.opens(), 1);
            assert_eq!(
                rebuilt
                    .consent
                    .take_single_use_approval(&card(kind).session, "test-subject"),
                None
            );
        }
    }

    #[tokio::test]
    async fn superseded_scope_is_refused_before_drain() {
        let cingulate = ScriptedCingulate::new();
        let (planes, _dir, _store) =
            planes(&[card(CardKind::LoginImport)], Arc::new(cingulate.clone()));
        let mut newer = stamp();
        newer.scope_epoch += 1;
        planes.scopes.note_bind(&newer, "test-conversation");
        let reply = invoke(&planes, 1).await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["code"], "scope_ended");
        assert_eq!(cingulate.opens(), 0);
    }

    #[tokio::test]
    async fn missing_record_report_lists_without_effect() {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_GET, Reply::Result(record("answered")));
        feed(&cingulate);
        let (planes, _dir, _store) =
            planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
        planes
            .consent_drain
            .register(CardKind::AppControl, Effects::new(false));
        let guard = Arc::new(planes.health.enter_request());
        crate::elicit::ROUTE_GUARD
            .scope(guard, async {
                let live = live_call(&request(1), &facts(), &planes).unwrap();
                let report = planes
                    .consent_drain
                    .run(&planes.consent, &live)
                    .await
                    .unwrap();
                assert_eq!(report.without_effect, ["el_1"]);
                assert!(report.applied.is_empty());
                assert_eq!(report.acked, Some(1));
            })
            .await;
    }

    async fn deadline_in_wait(hold: bool) {
        let cingulate = ScriptedCingulate::new();
        cingulate.then(wire::CONSENT_AWAIT, Reply::Hang);
        let (planes, _dir, _store) =
            planes(&[card(CardKind::AppControl)], Arc::new(cingulate.clone()));
        let terminal = Arc::new(TerminalArbiter::new(request(1)));
        let guard = Arc::new(planes.health.enter_request());
        crate::elicit::ROUTE_GUARD
            .scope(
                guard,
                CALL_TERMINAL.scope(terminal.clone(), async {
                    let live = live_call(&request(1), &facts(), &planes).unwrap();
                    let mut session = planes.consent.session(&live).await.unwrap();
                    let wait = async {
                        if hold {
                            session
                                .hold("el_1", Duration::from_secs(120), std::future::pending())
                                .await
                        } else {
                            session
                                .park("el_1", Duration::from_secs(120), std::future::pending())
                                .await
                        }
                    };
                    tokio::select! {
                        _ = wait => panic!("scripted await must remain pending"),
                        _ = tokio::time::sleep(Duration::from_millis(5)) => {},
                    }
                    terminal.stop(TerminalCause::Deadline);
                    let chosen = terminal.state.lock().unwrap().chosen.clone().unwrap();
                    let body: Value = serde_json::from_slice(&chosen.body).unwrap();
                    assert_eq!(body["detail"]["step"], "consent");
                }),
            )
            .await;
        assert_eq!(cingulate.methods(), [wire::CONSENT_AWAIT]);
    }

    #[tokio::test]
    async fn park_deadline_reports_consent_step() {
        deadline_in_wait(false).await;
    }

    #[tokio::test]
    async fn hold_deadline_reports_consent_step() {
        deadline_in_wait(true).await;
    }
}
