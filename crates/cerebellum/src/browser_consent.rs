//! Browser permission questions are sent to Cingulate, the consent service,
//! only while an agent call is live. Answers arriving after the reply are
//! applied by a later call, not by a task waiting after the caller has left.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use serde_json::{json, Value};
use tokio::sync::watch;

use crate::cingulate_client::card::{consent_request, CardKind};
use crate::cingulate_client::desk::{
    Apply, ApplyFailed, DeskSession, Ending, InCall, LetGo, NoCard, RaisedCard,
};
use crate::cingulate_client::live_call::LiveCall;
use crate::cingulate_client::wire::Record;
use crate::consent_drain::{AppliedSettlement, ConsentEffects};
use crate::management::{BrowserGrantSettlement, ManagementPlane, Question};
use crate::{AcceptedBindFacts, BoundRoute, Planes};

#[derive(Default)]
pub(crate) struct BrowserCards {
    pub creation: tokio::sync::Mutex<()>,
    state: Mutex<CardState>,
}

#[derive(Default)]
struct CardState {
    /// A later call may read the new card before its request returns locally.
    /// This marker prevents that call from withdrawing it as an abandoned card
    /// while its returned id is being attached to the pending record.
    creating: BTreeSet<String>,
    open: BTreeMap<String, Arc<Completion>>,
}

pub(crate) struct Completion {
    done: Arc<watch::Sender<bool>>,
    result: Mutex<Option<(Ending, BrowserGrantSettlement)>>,
    applying: Mutex<bool>,
}

impl Completion {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            done: Arc::new(watch::channel(false).0),
            result: Mutex::new(None),
            applying: Mutex::new(false),
        })
    }
}

pub(crate) fn live(
    facts: &AcceptedBindFacts,
    planes: &Planes,
    channel: u16,
    epoch: u32,
) -> Result<LiveCall, Ending> {
    let stamp = crate::permission_scope::card_stamp(facts);
    if stamp.is_none() {
        return Err(Ending::NoCard(NoCard::NoAgentSession));
    }
    let guard = crate::call_context::ROUTE_GUARD
        .try_with(Arc::clone)
        .map_err(|_| Ending::NoCard(NoCard::CallEnded))?;
    LiveCall::from_inbound(
        stamp,
        &guard,
        Arc::new(BoundRoute {
            routes: Arc::clone(&planes.routes),
            channel,
            epoch,
            conversation_key: facts.identity.conversation_key.clone(),
        }),
    )
    .map(|live| {
        live.with_authorizing_agent(
            crate::permission_scope::authorizing_holder(facts)
                .map(|holder| holder.agent_id().to_string()),
        )
    })
    .map_err(|error| Ending::NoCard(NoCard::of_not_live(error)))
}

pub(crate) fn word(ending: &Ending, decline: &str) -> &'static str {
    match ending {
        Ending::Granted { .. } => "allow",
        Ending::Declined { choice_id } if choice_id == decline => "declined",
        Ending::Declined { .. } => "unrecognized_answer",
        Ending::NoAnswer => "no_answer",
        Ending::NotPutToAnyone => "not_put_to_anyone",
        Ending::DeliveryFailed => "undeliverable",
        Ending::Withdrawn => "question_withdrawn",
        Ending::NoCard(reason) => reason.reason().unwrap_or("cancelled"),
    }
}

pub(crate) fn unavailable(reply: &mut Value, ending: &Ending, decline: &str) {
    reply["outcome"] = json!("consent_unavailable");
    reply.as_object_mut().unwrap().remove("ask_id");
    reply["detail"]["reason"] = json!(word(ending, decline));
    if let Ending::NoCard(reason) = ending {
        reply["remedy"] = json!(reason.remedy());
    } else if let Some(remedy) = crate::in_call_grant_remedy(word(ending, decline)) {
        reply["remedy"] = json!(remedy);
    }
}

pub(crate) fn in_call_refusal(reply: &mut Value, ending: &Ending) {
    if matches!(ending, Ending::NoCard(_)) {
        unavailable(reply, ending, crate::management::BROWSER_GRANT_DECLINE);
    } else {
        let decision = word(ending, crate::management::BROWSER_GRANT_DECLINE);
        reply["detail"]["decision"] = json!(decision);
        if let Some(remedy) = crate::in_call_grant_remedy(decision) {
            reply["remedy"] = json!(remedy);
        }
    }
}

struct Creating<'a> {
    cards: &'a BrowserCards,
    subject: String,
}
impl Drop for Creating<'_> {
    fn drop(&mut self) {
        self.cards
            .state
            .lock()
            .unwrap()
            .creating
            .remove(&self.subject);
    }
}

/// File the permission snapshot under the consent service's returned id before
/// waiting for its answer. Serializing creation prevents two calls asking about
/// the same conversation and origins from raising separate questions.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn raise(
    management: &ManagementPlane,
    desk: &crate::cingulate_client::desk::ConsentDesk,
    live: &LiveCall,
    session: &mut DeskSession<'_>,
    kind: CardKind,
    question: &Question,
    detached: bool,
) -> Result<(String, Arc<Completion>), Ending> {
    let serialization = desk.settlement_lock(live.session());
    let _settlement = if crate::codemode::accepts_held() {
        Some(serialization.lock().await)
    } else {
        None
    };
    let _creation = management.browser_consent.creation.lock().await;
    management
        .browser_consent
        .state
        .lock()
        .unwrap()
        .open
        .retain(|id, completion| !*completion.done.borrow() && desk.raised(id).is_some());
    let subject = question.subject();
    if let Some(card) = desk.open_card_for(live.session(), &subject) {
        let completion = management
            .browser_consent
            .state
            .lock()
            .unwrap()
            .open
            .get(&card.elicitation_id)
            .cloned();
        if let Some(completion) = completion {
            management.rekey_consent(kind, &question.ask_id, None);
            crate::codemode::prepare_consent(&card.elicitation_id, kind).await?;
            return Ok((card.elicitation_id, completion));
        }
        return Err(Ending::DeliveryFailed);
    }
    management
        .browser_consent
        .state
        .lock()
        .unwrap()
        .creating
        .insert(subject.clone());
    let _creating = Creating {
        cards: &management.browser_consent,
        subject: subject.clone(),
    };
    let card = consent_request(
        kind,
        &question.body,
        question.deadline,
        crate::call_context::current_call_key().as_deref(),
        None,
        None,
    )
    .map_err(|_| Ending::DeliveryFailed)?;
    let ask_id = if detached {
        session.raise_detached(card, &subject).await?
    } else {
        session.raise(card, &subject).await?
    };
    crate::codemode::prepare_consent(&ask_id, kind).await?;
    management.record_prepared_consent(question, &ask_id);
    let completion = Completion::new();
    management
        .browser_consent
        .state
        .lock()
        .unwrap()
        .open
        .insert(ask_id.clone(), Arc::clone(&completion));
    Ok((ask_id, completion))
}

fn settle(
    management: &ManagementPlane,
    kind: CardKind,
    id: &str,
    ending: &Ending,
) -> Result<BrowserGrantSettlement, ApplyFailed> {
    match kind {
        CardKind::WebsiteAccessInCall | CardKind::WebsiteAccessInAdvance => {
            management.settle_browser_grant_sync(id, Some(ending))
        }
        CardKind::ProfileReidentification => Ok(
            if management.settle_profile_root_rebind_sync(id, Some(ending)) {
                BrowserGrantSettlement::NotGranted
            } else {
                BrowserGrantSettlement::UnknownAsk
            },
        ),
        CardKind::StuckProfileClearance => {
            management.settle_launch_recovery_clear_sync(id, ending, Instant::now());
            Ok(BrowserGrantSettlement::NotGranted)
        }
        _ => Err(ApplyFailed("not a browser consent kind".into())),
    }
}

pub(crate) fn settle_failed(
    management: &ManagementPlane,
    kind: CardKind,
    question: &Question,
    ending: &Ending,
) {
    management.record_prepared_consent(question, &question.ask_id);
    let _ = settle(management, kind, &question.ask_id, ending);
}

fn elect(
    management: &ManagementPlane,
    kind: CardKind,
    id: &str,
    ending: &Ending,
    completion: &Completion,
) -> Result<bool, ApplyFailed> {
    {
        let mut applying = completion.applying.lock().unwrap();
        if *applying {
            return Err(ApplyFailed(
                "the elected browser caller is still storing the effect".into(),
            ));
        }
        if completion.result.lock().unwrap().is_some() {
            return Ok(false);
        }
        *applying = true;
    }
    let result = settle(management, kind, id, ending);
    if let Ok(result) = &result {
        *completion.result.lock().unwrap() = Some((ending.clone(), result.clone()));
    }
    *completion.applying.lock().unwrap() = false;
    result.map(|_| true)
}

pub(crate) async fn park(
    planes: &Planes,
    session: &mut DeskSession<'_>,
    id: &str,
    completion: Arc<Completion>,
    limit: Duration,
    cancelled: impl std::future::Future<Output = LetGo>,
) -> (InCall, BrowserGrantSettlement) {
    let end = tokio::time::Instant::now() + limit;
    let mut done = completion.done.subscribe();
    let result = tokio::select! {
        result = session.park(id, limit, cancelled) => Some(result),
        _ = done.wait_for(|done| *done) => None,
    };
    match result {
        Some(InCall::Settled(ref ending)) => loop {
            match elect(
                &planes.management,
                CardKind::WebsiteAccessInCall,
                id,
                ending,
                &completion,
            ) {
                Ok(true) => {
                    let _ = planes.consent.mark_applied(id);
                    if matches!(
                        completion.result.lock().unwrap().as_ref(),
                        Some((
                            Ending::Granted { .. },
                            BrowserGrantSettlement::NotRecorded { .. }
                        ))
                    ) {
                        let _ = planes.consent.finish_execution(id, crate::cingulate_client::wire::Execution::ApprovedNotExecuted, Some(crate::cingulate_client::wire::ExecutionReason::GrantStoreUnavailable));
                    }
                    completion.done.send_replace(true);
                    break;
                }
                Ok(false) => break,
                Err(_) if tokio::time::Instant::now() < end => tokio::task::yield_now().await,
                Err(_) => {
                    let _ = session.detach(id).await;
                    return (
                        InCall::Pending { ask_id: id.into() },
                        BrowserGrantSettlement::NotGranted,
                    );
                }
            }
        },
        Some(result) => {
            if planes.consent.raised(id).is_none() {
                planes
                    .management
                    .rekey_consent(CardKind::WebsiteAccessInCall, id, None);
                completion.done.send_replace(true);
            }
            return (result, BrowserGrantSettlement::NotGranted);
        }
        None => {}
    }
    if !*done.borrow()
        && tokio::time::timeout_at(end, done.wait_for(|done| *done))
            .await
            .is_err()
    {
        let _ = session.detach(id).await;
        return (
            InCall::Pending { ask_id: id.into() },
            BrowserGrantSettlement::NotGranted,
        );
    }
    let result = completion.result.lock().unwrap().clone();
    result.map_or(
        (
            InCall::Settled(Ending::Withdrawn),
            BrowserGrantSettlement::NotGranted,
        ),
        |(ending, settled)| (InCall::Settled(ending), settled),
    )
}

struct BrowserEffects(Weak<ManagementPlane>);
impl ConsentEffects for BrowserEffects {
    fn has_pending(&self, card: &RaisedCard) -> bool {
        self.0.upgrade().is_some_and(|management| {
            let state = management.browser_consent.state.lock().unwrap();
            state.creating.contains(&card.subject) || state.open.contains_key(&card.elicitation_id)
        })
    }
    fn apply(
        &self,
        card: &RaisedCard,
        _: &Record,
        ending: &Ending,
    ) -> Result<AppliedSettlement, ApplyFailed> {
        let Some(management) = self.0.upgrade() else {
            return Ok(AppliedSettlement {
                effect: Apply::NoRecord,
                completion: None,
            });
        };
        let completion = management
            .browser_consent
            .state
            .lock()
            .unwrap()
            .open
            .get(&card.elicitation_id)
            .cloned();
        let Some(completion) = completion else {
            return Err(ApplyFailed(
                "the browser card is still being recorded".into(),
            ));
        };
        let elected = elect(
            &management,
            card.kind,
            &card.elicitation_id,
            ending,
            &completion,
        )?;
        if !elected && !*completion.done.borrow() {
            return Err(ApplyFailed(
                "the elected browser caller has not marked its effect applied".into(),
            ));
        }
        Ok(AppliedSettlement {
            effect: Apply::Applied,
            completion: elected.then(|| Arc::clone(&completion.done)),
        })
    }
}

pub(crate) fn register(planes: &Planes) {
    let adapter = Arc::new(BrowserEffects(Arc::downgrade(&planes.management)));
    for kind in [
        CardKind::WebsiteAccessInCall,
        CardKind::WebsiteAccessInAdvance,
        CardKind::ProfileReidentification,
        CardKind::StuckProfileClearance,
    ] {
        planes.consent_drain.register(kind, adapter.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_grants::{
        AgentGrant, AgentGrantStorage, AgentGrantStoreError, AgentGrantStoreState, AgentGrants,
        BrowserTarget, GrantHolder, GrantSubject, InMemoryAgentGrantStorage, LegacyGrantSource,
    };
    use crate::browser_standing_grants::ManualWallClock;
    use crate::cingulate_client::desk::FileRegistryStore;
    use crate::cingulate_client::double::{Reply, ScriptedCingulate};
    use crate::{Frame, FrameType, JournalPersistence};
    use cerebellum_core::health::HealthState;
    use subc_protocol::{BindIdentity, Flags, Priority, RouteTarget, PROTOCOL_VERSION};

    #[derive(Default)]
    struct GrantStorage {
        inner: InMemoryAgentGrantStorage,
        writes: std::sync::atomic::AtomicUsize,
    }
    impl AgentGrantStorage for GrantStorage {
        fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
            self.inner.load()
        }
        fn save(&self, state: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
            self.writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.save(state)
        }
    }
    impl LegacyGrantSource for GrantStorage {
        fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
            Ok(AgentGrantStoreState::default())
        }
    }

    struct Fixture {
        planes: Planes,
        service: Arc<ScriptedCingulate>,
        root: std::path::PathBuf,
        grant_storage: Arc<GrantStorage>,
        clock: Arc<ManualWallClock>,
    }
    impl Fixture {
        fn new(unreadable: bool) -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let root = std::env::temp_dir().join(format!(
                "browser-cards-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&root).unwrap();
            if unreadable {
                std::fs::write(root.join("registry.json"), br#"{"version":99,"cards":[]}"#)
                    .unwrap();
            }
            let service = ScriptedCingulate::new().accept_execution_reports();
            let grant_storage = Arc::new(GrantStorage::default());
            let clock = Arc::new(ManualWallClock::at(100));
            let mut planes = Planes::with_browser_config_journaling(
                Arc::new(HealthState::default()),
                None,
                JournalPersistence::Isolated,
            );
            planes.management = Arc::new(
                crate::management::ManagementPlane::new(Arc::new(
                    crate::management::PlatformResolver::new(),
                ))
                .with_agent_grants(Arc::new(
                    AgentGrants::open(
                        grant_storage.clone(),
                        grant_storage.as_ref(),
                        Some("machine-test".into()),
                    )
                    .with_clock(clock.clone()),
                )),
            );
            planes.browser = Arc::new(
                Arc::try_unwrap(planes.browser)
                    .ok()
                    .unwrap()
                    .with_shared_grants(planes.management.browser_grants()),
            );
            let planes = planes.with_cingulate(
                Arc::new(service.clone()),
                Arc::new(FileRegistryStore::new(root.join("registry.json"))),
            );
            let facts = AcceptedBindFacts::from_bind(
                &BindIdentity::new("/test", "test", "browser-cards"),
                crate::session_caller_principal_for_test(),
                Some(
                    &json!({"agentProjectId":"browser-tests","sessionKind":"primary","effectiveCapabilityScope":["*"]}),
                ),
                None,
                &RouteTarget::ManagementSurface {
                    module_id: "cerebellum".into(),
                },
            );
            planes.routes.insert(
                4,
                1,
                facts.with_scope(Some(crate::computer_grants::tests::stamp("browser-tests"))),
            );
            Self {
                planes,
                service,
                root,
                grant_storage,
                clock,
            }
        }
        async fn call(&self, method: &str, params: Value) -> Value {
            let frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                4,
                1,
                100,
                serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
            )
            .unwrap();
            let (tx, mut rx) = tokio::sync::mpsc::channel(8);
            crate::handle_frame_for_test(frame, &tx, &self.planes)
                .await
                .unwrap();
            let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_ne!(frame.header.ty, FrameType::Request, "no reverse-lane frame");
            let reply = serde_json::from_slice(&frame.body).unwrap();
            assert!(rx.try_recv().is_err());
            reply
        }
        async fn open(&self) -> Value {
            self.call(
                crate::management::OPEN_GRANT,
                json!({"origins":["https://requested.example.com"],"hazards":[]}),
            )
            .await
        }
        fn grant(&self, subject: GrantSubject, expires_at_ms: Option<u64>) -> AgentGrant {
            let store = self.planes.management.agent_grants();
            let mut row = AgentGrant {
                id: String::new(),
                holder: GrantHolder::Head {
                    agent_id: "browser-tests".into(),
                },
                subject,
                browser_target: Some(BrowserTarget::AgentProfile),
                machine_uuid: "machine-test".into(),
                granted_at_ms: store.now_ms(),
                expires_at_ms,
                card_ref: Some("el_existing".into()),
                max_level: 2,
                hazards: Vec::new(),
                team_id: None,
                designated_requirement: None,
            };
            row.id = store.upsert(row.clone(), store.now_ms()).unwrap();
            row
        }
        fn writes(&self) -> usize {
            self.grant_storage
                .writes
                .load(std::sync::atomic::Ordering::SeqCst)
        }
        fn raised(&self, id: &str) {
            self.service.then(
                "consent.request",
                Reply::Result(json!({"elicitation_id":id})),
            );
            self.service.then(
                "consent.detach",
                Reply::Result(json!({"elicitation_id":id,"state":"pending","detached":true})),
            );
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    struct RequestGate {
        inner: Arc<ScriptedCingulate>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    struct GatedRoute {
        inner: Box<dyn crate::cingulate_client::route::CingulateRoute>,
        entered: Arc<tokio::sync::Notify>,
        release: Arc<tokio::sync::Notify>,
    }
    impl crate::cingulate_client::route::CingulateOpener for RequestGate {
        fn open<'a>(
            &'a self,
            live: &'a LiveCall,
        ) -> crate::cingulate_client::route::BoxFuture<
            'a,
            Result<
                Box<dyn crate::cingulate_client::route::CingulateRoute>,
                crate::cingulate_client::route::CallError,
            >,
        > {
            Box::pin(async move {
                Ok(Box::new(GatedRoute {
                    inner: self.inner.open(live).await?,
                    entered: self.entered.clone(),
                    release: self.release.clone(),
                })
                    as Box<dyn crate::cingulate_client::route::CingulateRoute>)
            })
        }
    }
    impl crate::cingulate_client::route::CingulateRoute for GatedRoute {
        fn call<'a>(
            &'a mut self,
            method: &'a str,
            params: Value,
        ) -> crate::cingulate_client::route::BoxFuture<
            'a,
            Result<Value, crate::cingulate_client::route::CallError>,
        > {
            Box::pin(async move {
                if method == "consent.request" {
                    self.entered.notify_one();
                    self.release.notified().await;
                }
                self.inner.call(method, params).await
            })
        }
    }

    #[tokio::test]
    async fn no_pending_record_exists_before_cingulate_returns_the_card_id() {
        let mut fixture = Fixture::new(false);
        let entered = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(tokio::sync::Notify::new());
        fixture.planes = fixture.planes.clone().with_cingulate(
            Arc::new(RequestGate {
                inner: fixture.service.clone(),
                entered: entered.clone(),
                release: release.clone(),
            }),
            Arc::new(FileRegistryStore::new(fixture.root.join("registry.json"))),
        );
        fixture.raised("el_returned");
        let caller = fixture.open();
        tokio::pin!(caller);
        tokio::select! {
            reply = &mut caller => panic!("request returned before the gate was released: {reply}"),
            _ = entered.notified() => {}
        }
        assert_eq!(
            fixture
                .planes
                .management
                .browser_grant_pending_count()
                .await,
            0
        );
        release.notify_one();
        let reply = caller.await;
        assert_eq!(reply["ask_id"], "el_returned");
        assert_eq!(
            fixture
                .planes
                .management
                .browser_grant_pending_count()
                .await,
            1
        );
        assert!(fixture
            .planes
            .management
            .consent_subject(CardKind::WebsiteAccessInAdvance, "el_returned")
            .is_some());
    }

    #[tokio::test]
    async fn an_in_flight_detach_is_not_swept_as_a_missing_memory_record() {
        let fixture = Fixture::new(false);
        fixture.service.then(
            "consent.request",
            Reply::Result(json!({"elicitation_id":"el_creating"})),
        );
        fixture.service.then("consent.detach", Reply::Hang);
        fixture.service.then(
            "consent.answers",
            Reply::Result(json!({"records":[],"cursor":1})),
        );
        fixture
            .service
            .then("consent.ack", Reply::Result(json!({"cursor":1})));
        let frame = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false), 4, 1, 99, serde_json::to_vec(&json!({"method":"browser.open_grant","params":{"origins":["https://requested.example.com"],"hazards":[]}})).unwrap()).unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(4);
        crate::handle_frame_for_test(frame.clone(), &tx, &fixture.planes)
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !fixture
                .service
                .methods()
                .iter()
                .any(|method| method == "consent.detach")
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            fixture
                .planes
                .management
                .browser_grant_pending_count()
                .await,
            0
        );
        fixture.call("test.drain", json!({})).await;
        assert_eq!(
            fixture.service.methods(),
            [
                "consent.request",
                "consent.detach",
                "consent.answers",
                "consent.ack"
            ]
        );
        assert!(fixture.planes.consent.raised("el_creating").is_some());
        assert_eq!(fixture.planes.management.browser_grant_count().await, 0);
        let mut cancel = frame;
        cancel.header.ty = FrameType::Cancel;
        cancel.body.clear();
        crate::handle_frame_for_test(cancel, &tx, &fixture.planes)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn open_grant_live_domain_covers_subdomains_without_cingulate_or_writes() {
        for expiry in [None, Some(1_800_100)] {
            let fixture = Fixture::new(false);
            let row = fixture.grant(GrantSubject::Domain("example.com".into()), expiry);
            let writes = fixture.writes();
            fixture.raised("el_unexpected");
            let reply = fixture
                .call(
                    crate::management::OPEN_GRANT,
                    json!({"origins":["https://child.example.com"],"severity_tier":2,"hazards":[]}),
                )
                .await;
            assert_eq!(reply["outcome"], "granted", "{reply}");
            assert_eq!(reply["origins"], json!(["https://child.example.com"]));
            assert!(reply.get("ask_id").is_none());
            assert!(fixture.service.methods().is_empty());
            assert_eq!(fixture.writes(), writes);
            let store = fixture.planes.management.agent_grants();
            assert_eq!(store.live_rows(None, store.now_ms()).unwrap(), vec![row]);
        }
    }

    #[tokio::test]
    async fn open_grant_all_sites_excludes_non_public_origins_and_hazards() {
        for (origin, hazards, expected) in [
            ("https://example.com", json!([]), "granted"),
            ("http://localhost", json!([]), "consent_pending"),
            ("http://192.168.1.10", json!([]), "consent_pending"),
            ("https://intranet.local", json!([]), "consent_pending"),
            ("https://service.internal", json!([]), "consent_pending"),
            ("https://example.com:8443", json!([]), "consent_pending"),
            (
                "https://example.com",
                json!(["credential_form_submit"]),
                "consent_pending",
            ),
            (
                "https://example.com",
                json!(["financial_form_submit"]),
                "consent_pending",
            ),
            (
                "https://example.com",
                json!(["unverified_form_contents"]),
                "consent_pending",
            ),
        ] {
            let fixture = Fixture::new(false);
            fixture.grant(GrantSubject::AllSites, None);
            let writes = fixture.writes();
            fixture.raised("el_missing");
            let reply = fixture
                .call(
                    crate::management::OPEN_GRANT,
                    json!({"origins":[origin],"severity_tier":2,"hazards":hazards}),
                )
                .await;
            assert_eq!(reply["outcome"], expected, "{origin}: {reply}");
            assert_eq!(fixture.writes(), writes);
            if expected == "granted" {
                assert!(fixture.service.methods().is_empty());
            } else {
                assert_eq!(reply["origins"], json!([origin]));
                assert_eq!(
                    fixture.service.methods(),
                    ["consent.request", "consent.detach"]
                );
            }
        }
    }

    #[tokio::test]
    async fn open_grant_expired_thirty_minute_grant_asks_again() {
        let fixture = Fixture::new(false);
        fixture.grant(GrantSubject::Domain("example.com".into()), Some(1_800_100));
        fixture.clock.advance_ms(1_800_001);
        fixture.raised("el_expired_retry");
        let reply = fixture.open().await;
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        assert_eq!(reply["ask_id"], "el_expired_retry");
        assert_eq!(
            fixture.service.methods(),
            ["consent.request", "consent.detach"]
        );
    }

    #[tokio::test]
    async fn open_grant_partial_coverage_asks_only_for_missing_origins() {
        let fixture = Fixture::new(false);
        fixture.grant(GrantSubject::Domain("example.com".into()), None);
        fixture.raised("el_partial");
        let reply = fixture
            .call(
                crate::management::OPEN_GRANT,
                json!({
                    "origins":["https://child.example.com","https://missing.example.org"],
                    "severity_tier":2,
                    "hazards":[],
                }),
            )
            .await;
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        assert_eq!(reply["origins"], json!(["https://missing.example.org"]));
        assert_eq!(
            reply["already_covered_origins"],
            json!(["https://child.example.com"])
        );
        assert_eq!(
            fixture.service.methods(),
            ["consent.request", "consent.detach"]
        );
        let request = fixture.service.calls()[0].1.to_string();
        assert!(request.contains("missing.example.org"), "{request}");
        assert!(!request.contains("example.com"), "{request}");
        assert_eq!(
            fixture
                .planes
                .management
                .consent_subject(CardKind::WebsiteAccessInAdvance, "el_partial")
                .unwrap(),
            crate::cingulate_client::subject::website_access_in_call(
                &fixture
                    .planes
                    .routes
                    .get(4, 1)
                    .unwrap()
                    .identity
                    .conversation_key,
                &["https://missing.example.org".into()],
            )
        );
    }

    #[tokio::test]
    async fn open_grant_late_always_answer_never_raises_a_second_card() {
        for acknowledged in [true, false] {
            let fixture = Fixture::new(false);
            fixture.raised("el_late_always");
            assert_eq!(fixture.open().await["outcome"], "consent_pending");
            fixture.service.then(
                "consent.answers",
                Reply::Result(json!({"records":[{
                    "elicitation_id":"el_late_always",
                    "state":"answered",
                    "answered_choice_id":crate::management::BrowserGrantChoice::OriginAlways.option_id(),
                }],"cursor":1})),
            );
            fixture.service.then(
                "consent.ack",
                if acknowledged {
                    Reply::Result(json!({"cursor":1}))
                } else {
                    Reply::Refused("elicitation_store_error")
                },
            );
            assert_eq!(fixture.open().await["outcome"], "granted");
            let methods = fixture.service.methods();
            assert_eq!(
                methods,
                [
                    "consent.request",
                    "consent.detach",
                    "consent.answers",
                    "consent.ack"
                ]
            );
            let card = fixture.planes.consent.raised("el_late_always");
            if acknowledged {
                assert!(card.unwrap().lifecycle.acked);
            } else {
                assert!(card.unwrap().applied);
            }
            let writes = fixture.writes();
            assert_eq!(fixture.open().await["outcome"], "granted");
            assert_eq!(fixture.service.methods(), methods);
            assert_eq!(fixture.writes(), writes);
            let store = fixture.planes.management.agent_grants();
            let rows = store.live_rows(None, store.now_ms()).unwrap();
            assert_eq!(rows.len(), 1);
            assert_eq!(rows[0].subject, GrantSubject::Domain("example.com".into()));
            assert_eq!(rows[0].expires_at_ms, None);
            assert_eq!(rows[0].card_ref.as_deref(), Some("el_late_always"));
        }
    }

    #[tokio::test]
    async fn asked_ahead_detaches_without_await_or_reverse_frame() {
        let fixture = Fixture::new(false);
        fixture.raised("el_browser_1");
        let reply = fixture.open().await;
        assert_eq!(reply["outcome"], "consent_pending");
        assert_eq!(reply["ask_id"], "el_browser_1");
        assert_eq!(
            fixture.service.methods(),
            ["consent.request", "consent.detach"]
        );
        let request = &fixture.service.calls()[0].1;
        assert_eq!(request["urgency"], "normal");
        assert_eq!(request["expires_in_ms"], 1_800_000);
        assert!(request.get("dedup_key").is_none());
        assert!(fixture
            .planes
            .management
            .consent_subject(CardKind::WebsiteAccessInAdvance, "el_browser_1")
            .is_some());
    }

    #[tokio::test]
    async fn late_browser_endings_are_applied_only_by_the_next_call_drain() {
        for (state, choice, granted) in [
            ("answered", "allow_30m", true),
            ("answered", "deny", false),
            ("expired", "", false),
        ] {
            let fixture = Fixture::new(false);
            fixture.raised("el_browser_late");
            assert_eq!(fixture.open().await["outcome"], "consent_pending");
            let record = json!({"elicitation_id":"el_browser_late","state":state,"answered_choice_id":choice});
            fixture.service.then(
                "consent.answers",
                Reply::Result(json!({"records":[record],"cursor":1})),
            );
            fixture
                .service
                .then("consent.ack", Reply::Result(json!({"cursor":1})));
            assert_eq!(
                fixture
                    .planes
                    .management
                    .browser_grant_pending_count()
                    .await,
                1
            );
            assert_eq!(fixture.planes.management.browser_grant_count().await, 0);
            fixture.call("test.drain", json!({})).await;
            assert_eq!(
                fixture
                    .planes
                    .management
                    .browser_grant_pending_count()
                    .await,
                0
            );
            assert_eq!(
                fixture
                    .planes
                    .management
                    .agent_grants()
                    .live_rows(None, fixture.planes.management.agent_grants().now_ms())
                    .unwrap()
                    .len(),
                usize::from(granted)
            );
            assert_eq!(
                fixture.service.methods(),
                [
                    "consent.request",
                    "consent.detach",
                    "consent.answers",
                    "consent.ack"
                ]
            );
            assert!(
                fixture
                    .planes
                    .consent
                    .raised("el_browser_late")
                    .unwrap()
                    .lifecycle
                    .acked
            );
        }
    }

    #[tokio::test]
    async fn refused_asked_ahead_requests_report_each_ending_word() {
        for (code, expected) in [
            ("elicitation_request_too_large", "undeliverable"),
            ("invalid_request", "undeliverable"),
            ("unknown_method", "undeliverable"),
            ("consent_unavailable", "undeliverable"),
            ("elicitation_store_error", "undeliverable"),
            ("cancelled", "undeliverable"),
            ("elicitation_requester_refused", "not_put_to_anyone"),
            ("elicitation_invalid_request", "undeliverable"),
            ("elicitation_unknown_kind", "undeliverable"),
            ("elicitation_fail_closed_required", "not_put_to_anyone"),
            ("consent_retired", "not_put_to_anyone"),
            ("elicitation_not_owner", "no_answer"),
            ("elicitation_not_found", "no_answer"),
            ("elicitation_invalid_execution", "undeliverable"),
            ("future_code", "undeliverable"),
        ] {
            let fixture = Fixture::new(false);
            fixture
                .service
                .then("consent.request", Reply::Refused(code));
            let reply = fixture.open().await;
            assert_eq!(reply["outcome"], "consent_unavailable", "{code}: {reply}");
            assert_eq!(reply["detail"]["reason"], expected, "{code}: {reply}");
            assert_eq!(fixture.service.methods(), ["consent.request"]);
            assert_eq!(
                fixture
                    .planes
                    .management
                    .browser_grant_pending_count()
                    .await,
                0
            );
            fixture.raised("el_retry");
            let retry = fixture.open().await;
            assert_eq!(
                retry["previous_request"]["disposition"].as_str(),
                (expected == "not_put_to_anyone").then_some("not_put_to_anyone")
            );
        }
    }

    #[tokio::test]
    async fn failed_asked_ahead_detach_withdraws_and_reports_undeliverable() {
        let fixture = Fixture::new(false);
        fixture.service.then(
            "consent.request",
            Reply::Result(json!({"elicitation_id":"el_browser_bad_detach"})),
        );
        fixture
            .service
            .then("consent.detach", Reply::Refused("unknown_method"));
        fixture.service.then(
            "consent.withdraw",
            Reply::Result(json!({"elicitation_id":"el_browser_bad_detach","state":"withdrawn"})),
        );
        let reply = fixture.open().await;
        assert_eq!(reply["outcome"], "consent_unavailable");
        assert_eq!(reply["detail"]["reason"], "undeliverable");
        assert_eq!(
            fixture.service.methods(),
            ["consent.request", "consent.detach", "consent.withdraw"]
        );
        assert!(fixture
            .planes
            .consent
            .raised("el_browser_bad_detach")
            .is_none());
        assert_eq!(
            fixture
                .planes
                .management
                .browser_grant_pending_count()
                .await,
            0
        );
    }

    #[tokio::test]
    async fn no_agent_or_unreadable_registry_opens_no_consent_route() {
        for unreadable in [false, true] {
            let fixture = Fixture::new(unreadable);
            if !unreadable {
                let facts = fixture.planes.routes.get(4, 1).unwrap();
                fixture.planes.routes.insert(4, 1, facts.with_scope(None));
            }
            let reply = fixture.open().await;
            assert_eq!(reply["outcome"], "consent_unavailable");
            assert_eq!(
                reply["detail"]["reason"],
                if unreadable {
                    "consent_registry_unreadable"
                } else {
                    "no_agent_session"
                }
            );
            assert_eq!(fixture.service.opens(), 0);
            assert_eq!(
                fixture
                    .planes
                    .management
                    .browser_grant_pending_count()
                    .await,
                0
            );
        }
    }

    struct Clearer(Mutex<Vec<String>>);
    impl crate::launch_recovery::LaunchRecoveryClearer for Clearer {
        fn preview(
            &self,
            project: &str,
            sequence: Option<u64>,
        ) -> Result<crate::launch_recovery::ClearPreview, crate::launch_recovery::ClearRefusal>
        {
            use crate::launch_recovery::*;
            Ok(ClearPreview {
                agent_project_id: project.into(),
                profile_uuid: "profile-test".into(),
                sequence: sequence.unwrap_or(7),
                reason: crate::browser_launch::RecoveryPendingReason::AttestationUntrusted,
                launched_at: None,
                evidence: ProfileEvidence {
                    processes: ProcessReading::NoneNamesDirectory { examined: 0 },
                    singleton_lock: SingletonLockReading::Absent,
                },
            })
        }
        fn clear(
            &self,
            _: &crate::launch_recovery::ClearPreview,
            id: &str,
        ) -> Result<(), crate::launch_recovery::ClearFailure> {
            self.0.lock().unwrap().push(id.into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn late_clear_endings_settle_and_report_on_a_later_request() {
        for (state, choice, expected) in [
            ("answered", "clear", "cleared"),
            ("answered", "keep", "kept"),
            ("expired", "", "no_answer"),
        ] {
            let fixture = Fixture::new(false);
            let clearer = Arc::new(Clearer(Mutex::new(Vec::new())));
            fixture
                .planes
                .management
                .launch_recovery_registry()
                .publish(clearer.clone());
            fixture.raised("el_clear");
            let pending = fixture
                .call(
                    crate::management::CLEAR_LAUNCH_RECOVERY,
                    json!({"agent_project_id":"browser-tests","sequence":7}),
                )
                .await;
            assert_eq!(pending["outcome"], "consent_pending");
            assert_eq!(pending["ask_id"], "el_clear");
            assert!(clearer.0.lock().unwrap().is_empty());
            fixture.service.then("consent.answers", Reply::Result(json!({"records":[{"elicitation_id":"el_clear","state":state,"answered_choice_id":choice}],"cursor":1})));
            fixture
                .service
                .then("consent.ack", Reply::Result(json!({"cursor":1})));
            fixture.call("test.drain", json!({})).await;
            assert_eq!(
                clearer.0.lock().unwrap().len(),
                usize::from(choice == "clear")
            );
            fixture.raised("el_clear_retry");
            let retry = fixture
                .call(
                    crate::management::CLEAR_LAUNCH_RECOVERY,
                    json!({"agent_project_id":"browser-tests","sequence":7}),
                )
                .await;
            assert_eq!(retry["previous_answer"]["outcome"], expected);
            assert_eq!(
                fixture
                    .service
                    .methods()
                    .iter()
                    .filter(|method| method.as_str() == "consent.await")
                    .count(),
                0
            );
        }
    }

    #[tokio::test]
    async fn opaque_clear_id_uses_the_pending_incarnation_not_an_id_prefix() {
        let old = Fixture::new(false);
        old.planes
            .management
            .launch_recovery_registry()
            .publish(Arc::new(Clearer(Mutex::new(Vec::new()))));
        old.raised("el_opaque_old");
        assert_eq!(
            old.call(
                crate::management::CLEAR_LAUNCH_RECOVERY,
                json!({"agent_project_id":"browser-tests"})
            )
            .await["ask_id"],
            "el_opaque_old"
        );
        let new = Fixture::new(false);
        new.planes.management.copy_pending_clear_for_test(
            &old.planes.management,
            "el_opaque_old",
            "el_no_incarnation_prefix",
        );
        assert_eq!(
            new.planes
                .management
                .settle_launch_recovery_clear(
                    "el_no_incarnation_prefix",
                    Some(&json!({"decision":"clear"}))
                )
                .await,
            crate::management::ClearSettlement::AskedByEarlierStart
        );
    }

    #[tokio::test]
    async fn direct_clear_with_a_copied_stamp_opens_no_consent_route() {
        let fixture = Fixture::new(false);
        fixture
            .planes
            .management
            .launch_recovery_registry()
            .publish(Arc::new(Clearer(Mutex::new(Vec::new()))));
        let facts = AcceptedBindFacts::from_bind(
            &BindIdentity::new("/test", "test", "operator"),
            Some(subc_protocol::Principal::Direct),
            Some(
                &json!({"agentProjectId":"browser-tests","sessionKind":"primary","effectiveCapabilityScope":["*"]}),
            ),
            None,
            &RouteTarget::ManagementSurface {
                module_id: "cerebellum".into(),
            },
        );
        fixture.planes.routes.insert(
            4,
            1,
            facts.with_scope(Some(crate::computer_grants::tests::stamp("browser-tests"))),
        );
        let reply = fixture
            .call(
                crate::management::CLEAR_LAUNCH_RECOVERY,
                json!({"agent_project_id":"browser-tests"}),
            )
            .await;
        assert_eq!(reply["outcome"], "consent_unavailable");
        assert_eq!(reply["detail"]["reason"], "no_agent_session");
        assert_eq!(fixture.service.opens(), 0);
        assert_eq!(
            fixture
                .planes
                .management
                .launch_recovery_clear_pending_count()
                .await,
            0
        );
    }

    #[tokio::test]
    async fn refused_consent_route_uses_the_refusal_row_remedy() {
        for (code, expected, remedy) in [
            (
                "scope_not_carrier",
                "not_a_carrier",
                "the agent session does not list cerebellum as a carrier; restart the session",
            ),
            (
                "scope_ended",
                "scope_ended",
                "this session has ended; call from the current session",
            ),
        ] {
            let fixture = Fixture::new(false);
            *fixture.service.refuse_open.lock().unwrap() = Some(code);
            let reply = fixture.open().await;
            assert_eq!(reply["outcome"], "consent_unavailable");
            assert_eq!(reply["detail"]["reason"], expected);
            assert_eq!(reply["remedy"], remedy);
            assert!(fixture.service.calls().is_empty());
        }
    }
}
