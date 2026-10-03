//! Standing browser site grants, driven through the module's real dispatch.
//!
//! Every request here is a frame handed to `handle_frame_for_test` on a route
//! bound with a real `route.bind`, so admission, the attested agent identity,
//! the in-call consent card and the browser plane's authorization all run as
//! they do in production. The browser is a double that records what reached
//! it and commits whatever page a navigation lands on, including a redirect.
//! Each test builds its own planes over an isolated journal and its own
//! standing grant store.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::authorization::HazardClass;
use cerebellum::browser::navigation::BrowserScreenshotObservation;
use cerebellum::browser::Tracker;
use cerebellum::browser_launch::ExecutableIdentityCheckpoints;
use cerebellum::browser_session::{
    BrowserClickOutcome, BrowserClickPosition, BrowserInputEvent, BrowserSessionLauncher,
    CleanupStage, ClickDriveError, ClickNavigation, LaunchedBrowser, NavigationDriveError,
    NavigationWait, OwnedBrowserProcess, ProcessControlFailure, SessionCleanup,
};
use cerebellum::browser_standing_grants::{
    FilesystemStandingGrantStorage, InMemoryStandingGrantStorage, ManualWallClock,
    StandingBrowserGrants, StandingGrantStorage, StandingSubject, ALL_SITES_SHORT_GRANT_MS,
};
use cerebellum::classification::{
    canonical_origin_from_url, classify_click, AssociatedFormControlInput,
    ClassificationUnavailable, ElementClassificationInput, NodeIdentityInput,
    NonTypeClassificationInput, NonTypeClassificationRecord, TargetKind,
};
use cerebellum::coordinate::{TransformInputs, ViewportObservation};
use cerebellum::snapshot_store::CommittedDocument;
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

// The suite's own copy of the probes' relay; only the observing variant is used.
#[allow(dead_code)]
#[path = "../../examples/support/consent_relay.rs"]
mod consent_relay;

/// The machine every store in these tests is bound to.
const MACHINE: &str = "machine-under-test";
const AGENT: &str = "pj-standing-agent";
const OTHER_AGENT: &str = "pj-another-agent";
const PUBLIC: &str = "https://news.example";
/// A valid one-pixel PNG, the smallest image a screenshot reply admits.
const ONE_BY_ONE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";

fn config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    }
}

// ---------------------------------------------------------------------------
// The browser double
// ---------------------------------------------------------------------------

/// The page the double shows, and where a navigation to a URL lands.
#[derive(Clone, Default)]
struct Browser {
    /// `(entry id, url)` of every committed entry; the last is current.
    entries: Arc<Mutex<Vec<(i64, String)>>>,
    /// A navigation to the key lands on the value, as a server redirect would.
    redirects: Arc<Mutex<BTreeMap<String, String>>>,
    /// Every navigation and click that reached the browser.
    effects: Arc<Mutex<Vec<String>>>,
}

impl Browser {
    fn redirect(&self, from: &str, to: &str) {
        self.redirects
            .lock()
            .unwrap()
            .insert(from.to_string(), to.to_string());
    }

    fn document(&self) -> CommittedDocument {
        let entries = self.entries.lock().unwrap();
        let (entry_id, url) = entries
            .last()
            .cloned()
            .unwrap_or((1, "about:blank".to_string()));
        CommittedDocument {
            url,
            entry_id,
            history: entries.iter().map(|entry| entry.0).collect(),
            current_index: entries.len().saturating_sub(1),
            loader_id: format!("loader-{entry_id}"),
        }
    }

    fn effects(&self) -> Vec<String> {
        self.effects.lock().unwrap().clone()
    }
}

impl BrowserSessionLauncher for Browser {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        Ok(LaunchedBrowser {
            process: Box::new(Process(self.clone())),
            cleanup: Box::new(Cleanup),
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::AfterExecOnly,
        })
    }
}

struct Process(Browser);

impl OwnedBrowserProcess for Process {
    fn committed_document(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        Ok(self.0.document())
    }

    fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
        Ok(self.0.document().url)
    }

    fn navigate(
        &mut self,
        _: &str,
        url: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.0
            .effects
            .lock()
            .unwrap()
            .push(format!("navigate {url}"));
        let landed = self
            .0
            .redirects
            .lock()
            .unwrap()
            .get(url)
            .cloned()
            .unwrap_or_else(|| url.to_string());
        {
            let mut entries = self.0.entries.lock().unwrap();
            let id = entries.len() as i64 + 2;
            entries.push((id, landed.clone()));
        }
        let now = std::time::Instant::now();
        tracker.url_final = Some(landed);
        tracker.load(now);
        tracker.poll_settlement(now + Duration::from_millis(cerebellum::browser::QUIET_MS));
        Ok(())
    }

    fn screenshot(
        &mut self,
        _: &str,
        document_epoch: u64,
        _: u64,
        _: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        let viewport = ViewportObservation::new(
            document_epoch,
            TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
        );
        Ok(BrowserScreenshotObservation {
            image_png_b64: ONE_BY_ONE_PNG_B64.into(),
            before: viewport,
            after: viewport,
            invalidation_observed: false,
        })
    }

    /// Every point is on the submit button of a sign-in form, so a click
    /// there carries the credential form-submit hazard.
    fn classify_point(
        &mut self,
        _: &str,
        _: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        _: u64,
    ) -> Result<Result<NonTypeClassificationRecord, ClassificationUnavailable>, NavigationDriveError>
    {
        let origin = canonical_origin_from_url(document_url).expect("the page has an origin");
        let target = ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame-main", 42),
            TargetKind::Button,
        )
        .form_owner(NodeIdentityInput::new("target", "frame-main", 7))
        .associated_control(
            AssociatedFormControlInput::new(NodeIdentityInput::new("target", "frame-main", 8))
                .with_tokens(["current-password"]),
        );
        Ok(Ok(classify_click(&NonTypeClassificationInput::new(
            document_epoch,
            target,
            origin,
        ))
        .expect("the sign-in button classifies")))
    }

    fn click_point_classified(
        &mut self,
        _: &str,
        position: BrowserClickPosition,
        _: u64,
        _: &str,
        _: &NonTypeClassificationRecord,
        _: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.0.effects.lock().unwrap().push("click_point".into());
        input_dispatched(BrowserInputEvent::Press(position));
        input_dispatched(BrowserInputEvent::Release(position));
        Ok(BrowserClickOutcome::Clicked {
            position,
            navigation: ClickNavigation::NoneObserved { window_ms: 100 },
        })
    }

    fn generation_matches(&self) -> bool {
        true
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }

    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(true)
    }

    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }

    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
}

struct Cleanup;

impl SessionCleanup for Cleanup {
    fn after_reap(
        &mut self,
    ) -> Result<cerebellum::browser_session::SessionCleanupOutcome, CleanupStage> {
        Ok(cerebellum::browser_session::SessionCleanupOutcome::Complete)
    }
}

// ---------------------------------------------------------------------------
// Planes, routes and requests
// ---------------------------------------------------------------------------

/// A standing grant store on [`MACHINE`] over `storage`, stamped by `clock`.
fn store_over(
    storage: impl StandingGrantStorage + 'static,
    clock: &ManualWallClock,
) -> Arc<StandingBrowserGrants> {
    Arc::new(
        StandingBrowserGrants::open(Arc::new(storage), Some(MACHINE.to_string()))
            .with_clock(Arc::new(clock.clone())),
    )
}

struct Fixture {
    planes: Planes,
    browser: Browser,
    store: Arc<StandingBrowserGrants>,
    clock: ManualWallClock,
    next_channel: u16,
}

impl Fixture {
    fn new() -> Self {
        let clock = ManualWallClock::at(1_700_000_000_000);
        let store = store_over(InMemoryStandingGrantStorage::new(), &clock);
        Self::with_store(store, clock)
    }

    fn with_store(store: Arc<StandingBrowserGrants>, clock: ManualWallClock) -> Self {
        let browser = Browser::default();
        let mut planes = Planes::with_browser_config_journaling_and_standing_grants(
            Arc::new(HealthState::new()),
            Some(config()),
            JournalPersistence::Isolated,
            Some(Arc::clone(&store)),
        );
        planes.launch_service = Some(Arc::new(browser.clone()));
        Self {
            planes,
            browser,
            store,
            clock,
            next_channel: 20,
        }
    }

    /// Record a standing row directly, as an answered card would.
    fn seed(&self, agent: &str, subject: StandingSubject, level: u8, hazards: &[HazardClass]) {
        self.store
            .record(agent, subject, level, hazards.to_vec(), None, "el_seeded")
            .expect("the seeded row is recorded");
    }

    /// Bind a fresh tool route with real `route.bind` admission facts.
    async fn route(&mut self, session: Session<'_>) -> Route {
        self.bind(session, false).await
    }

    /// Bind a fresh management route for the operator's operations.
    async fn management_route(&mut self) -> Route {
        self.bind(
            Session {
                conversation: "operator-desk",
                agent: Some("pj-operator"),
                kind: "primary",
                asks: false,
            },
            true,
        )
        .await
    }

    async fn bind(&mut self, session: Session<'_>, management: bool) -> Route {
        let channel = self.next_channel;
        self.next_channel += 1;
        let mut facts = json!({
            "sessionKind": session.kind,
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.launch", "browser.status", "browser.close"],
        });
        if let Some(agent) = session.agent {
            facts["agentProjectId"] = json!(agent);
        }
        let request = ModuleControlRequest::RouteBind {
            role_versions: None,
            route_channel: channel,
            epoch: 1,
            target: if management {
                RouteTarget::ManagementSurface {
                    module_id: "cerebellum".to_string(),
                }
            } else {
                RouteTarget::ToolProvider {
                    module_id: "cerebellum".to_string(),
                }
            },
            identity: BindIdentity::new("/test/project", "test", session.conversation.to_string()),
            principal: cerebellum::session_caller_principal_for_test(),
            consumer_capabilities: session.asks.then(|| vec!["elicitation".to_string()]),
            admission_facts: Some(facts),
            scope: None,
        };
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            u64::from(channel),
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(4);
        cerebellum::handle_frame_for_test(frame, &tx, &self.planes)
            .await
            .expect("the bind is handled");
        let reply = rx.recv().await.expect("route.bind replies");
        assert_eq!(
            reply.header.ty,
            FrameType::Response,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let route = Route {
            channel,
            next_corr: Arc::new(Mutex::new(100)),
        };
        // A browser session is launched only for an attested agent; an
        // unattested route is refused at launch, so it is left without one.
        if !management && session.agent.is_some() {
            let launched = self.call(&route, "browser.launch", json!({})).await;
            assert_eq!(launched["outcome"], "launched", "{launched}");
        }
        route
    }

    /// Send one request on `route` and return its reply, failing if it asks a
    /// person anything.
    async fn call(&self, route: &Route, name: &str, arguments: Value) -> Value {
        let mut asked = Vec::new();
        let reply = self
            .call_answering(route, name, arguments, json!({"decision": "deny"}), |q| {
                asked.push(q.clone())
            })
            .await;
        assert!(asked.is_empty(), "{name} asked a person: {asked:?}");
        reply
    }

    /// Send one request, answering any question it raises with `answer`.
    async fn call_answering(
        &self,
        route: &Route,
        name: &str,
        arguments: Value,
        answer: Value,
        observe: impl FnMut(&Value),
    ) -> Value {
        self.send(
            route,
            json!({"name": name, "arguments": arguments}),
            answer,
            observe,
        )
        .await
    }

    /// Send a management operation on a management route.
    async fn operate(&self, route: &Route, method: &str, params: Value) -> Value {
        self.send(
            route,
            json!({"method": method, "params": params}),
            json!({"decision": "deny"}),
            |question| panic!("{method} asked a person: {question}"),
        )
        .await
    }

    async fn send(
        &self,
        route: &Route,
        body: Value,
        answer: Value,
        observe: impl FnMut(&Value),
    ) -> Value {
        let corr = {
            let mut next = route.next_corr.lock().unwrap();
            *next += 1;
            *next
        };
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            route.channel,
            1,
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        consent_relay::elicit_and_answer_observing(&self.planes, frame, answer, "request", observe)
            .await
            .expect("the request completes")
    }

    async fn navigate(&self, route: &Route, url: &str) -> Value {
        self.call(route, "browser.navigate", navigation(url, 2))
            .await
    }
}

#[derive(Clone, Copy)]
struct Session<'a> {
    conversation: &'a str,
    agent: Option<&'a str>,
    kind: &'a str,
    /// Whether the route can relay a question to a person.
    asks: bool,
}

impl<'a> Session<'a> {
    /// A primary session of `agent` that cannot ask anyone, so an action no
    /// grant covers is refused at once.
    fn primary(conversation: &'a str, agent: &'a str) -> Self {
        Self {
            conversation,
            agent: Some(agent),
            kind: "primary",
            asks: false,
        }
    }

    fn asking(self) -> Self {
        Self { asks: true, ..self }
    }
}

struct Route {
    channel: u16,
    next_corr: Arc<Mutex<u64>>,
}

fn navigation(url: &str, tier: u8) -> Value {
    json!({
        "url": url,
        "intent": "read the page",
        "wait": "settle",
        "severity": {"tier": tier, "credential": false, "financial": false},
    })
}

fn assert_authorized(reply: &Value, what: &str) {
    assert_ne!(
        reply["outcome"], "authorization_denied",
        "{what} was refused: {reply}"
    );
    assert_eq!(reply["outcome"], "ok", "{what}: {reply}");
}

fn assert_refused(reply: &Value, what: &str) {
    assert_eq!(
        reply["outcome"], "authorization_denied",
        "{what} was not refused: {reply}"
    );
}

/// The option ids of the one card a request raised.
fn option_ids(question: &Value) -> Vec<String> {
    question["params"]["options"]
        .as_array()
        .unwrap()
        .iter()
        .map(|option| option["id"].as_str().unwrap().to_string())
        .collect()
}

const ALL_OPTIONS: [&str; 5] = [
    "allow_conversation",
    "allow_origin_always",
    "allow_all_sites_10m",
    "allow_all_sites_always",
    "deny",
];

// ---------------------------------------------------------------------------
// The card and its answers
// ---------------------------------------------------------------------------

/// Each option of the full card, answered on a fresh module, mints exactly
/// what it names and nothing else; an id the card did not offer mints nothing.
#[tokio::test]
async fn each_answered_option_mints_exactly_its_row() {
    for (index, id) in ALL_OPTIONS
        .into_iter()
        .filter(|id| *id != "deny")
        .chain(["allow"])
        .enumerate()
    {
        let mut fixture = Fixture::new();
        let route = fixture
            .route(Session::primary("conversation-mapping", AGENT).asking())
            .await;
        let consent_ref = format!("el_mapping_{index}");
        let mut offered = Vec::new();
        let reply = fixture
            .call_answering(
                &route,
                "browser.navigate",
                navigation(&format!("{PUBLIC}/"), 2),
                json!({"decision": id, "elicitation_id": consent_ref}),
                |question| offered.push(option_ids(question)),
            )
            .await;
        assert_eq!(
            offered,
            vec![ALL_OPTIONS.map(str::to_string).to_vec()],
            "{id}"
        );

        let conversation_grants = fixture.planes.management.browser_grant_count().await;
        let rows = fixture.store.live_rows(AGENT);
        let now = fixture.clock_now();
        match id {
            "allow_conversation" => {
                assert_authorized(&reply, id);
                assert_eq!(conversation_grants, 1, "{id}");
                assert!(rows.is_empty(), "{id}: {rows:?}");
            }
            "allow" => {
                assert_refused(&reply, id);
                assert_eq!(
                    reply["detail"]["decision"], "unrecognized_answer",
                    "{reply}"
                );
                assert_eq!(conversation_grants, 0, "{id}");
                assert!(rows.is_empty(), "{id}: {rows:?}");
            }
            _ => {
                assert_authorized(&reply, id);
                assert_eq!(
                    conversation_grants, 0,
                    "{id} also minted a conversation grant"
                );
                assert_eq!(rows.len(), 1, "{id}: {rows:?}");
                let row = &rows[0];
                assert_eq!(row.agent_id, AGENT);
                assert_eq!(row.max_level, 2, "{id}");
                assert!(row.hazards.is_empty(), "{id}");
                assert_eq!(row.consent_ref, consent_ref);
                assert_eq!(row.granted_at_ms, now);
                assert_eq!(row.revoked_at_ms, None);
                let (subject, expires) = match id {
                    "allow_origin_always" => (StandingSubject::Origin(PUBLIC.into()), None),
                    "allow_all_sites_10m" => (
                        StandingSubject::AllSites,
                        Some(now + ALL_SITES_SHORT_GRANT_MS),
                    ),
                    _ => (StandingSubject::AllSites, None),
                };
                assert_eq!(row.subject, subject, "{id}");
                assert_eq!(row.expires_at_ms, expires, "{id}");
            }
        }
    }
}

impl Fixture {
    fn clock_now(&self) -> u64 {
        use cerebellum::browser_standing_grants::WallClock;
        self.clock.now_ms()
    }
}

/// Which options a card offers follows the session and the request: a worker
/// or an unattested session is offered this conversation only, and the
/// all-sites options are withheld from a lasting-change request, a request
/// disclosing a hazard, and a site that is not public.
#[tokio::test]
async fn the_card_offers_only_what_the_session_and_request_allow() {
    let conversation_only = vec!["allow_conversation", "deny"];
    let no_all_sites = vec!["allow_conversation", "allow_origin_always", "deny"];
    let cases: [(&str, Session<'_>, &str, u8, Vec<&str>); 5] = [
        (
            "primary, public, ordinary",
            Session::primary("c-full", AGENT).asking(),
            "https://news.example/",
            2,
            ALL_OPTIONS.to_vec(),
        ),
        (
            "lasting changes",
            Session::primary("c-level4", AGENT).asking(),
            "https://news.example/",
            4,
            no_all_sites.clone(),
        ),
        (
            "private address",
            Session::primary("c-private", AGENT).asking(),
            "http://10.0.0.5/",
            2,
            no_all_sites.clone(),
        ),
        (
            "loopback",
            Session::primary("c-loopback", AGENT).asking(),
            "http://127.0.0.1:8080/",
            2,
            no_all_sites,
        ),
        (
            "worker session",
            Session {
                kind: "subagent",
                ..Session::primary("c-worker", AGENT).asking()
            },
            "https://news.example/",
            2,
            conversation_only.clone(),
        ),
    ];
    for (case, session, url, tier, expected) in cases {
        let mut fixture = Fixture::new();
        let route = fixture.route(session).await;
        let mut offered = Vec::new();
        let reply = fixture
            .call_answering(
                &route,
                "browser.navigate",
                navigation(url, tier),
                json!({"decision": "deny"}),
                |question| offered.push(option_ids(question)),
            )
            .await;
        assert_refused(&reply, case);
        assert_eq!(offered, vec![expected], "{case}");
    }

    // The advance card follows the same rules: a disclosed hazard withholds
    // the all-sites options, and an unattested session (which cannot launch
    // a browser, so asks only ahead) is offered this conversation only.
    for (case, session, hazards, expected) in [
        (
            "hazard asked ahead",
            Session::primary("c-hazard", AGENT).asking(),
            json!(["credential_form_submit"]),
            vec!["allow_conversation", "allow_origin_always", "deny"],
        ),
        (
            "ordinary request asked ahead",
            Session::primary("c-ahead", AGENT).asking(),
            json!([]),
            ALL_OPTIONS.to_vec(),
        ),
        (
            "unattested agent",
            Session {
                agent: None,
                ..Session::primary("c-unattested", AGENT).asking()
            },
            json!([]),
            vec!["allow_conversation", "deny"],
        ),
    ] {
        let mut fixture = Fixture::new();
        let route = fixture.route(session).await;
        let mut offered = Vec::new();
        let reply = fixture
            .call_answering(
                &route,
                "browser_use",
                json!({"action": "open_grant", "origins": [PUBLIC], "hazards": hazards}),
                json!({"decision": "deny"}),
                |question| offered.push(option_ids(question)),
            )
            .await;
        assert_eq!(reply["outcome"], "consent_pending", "{case}: {reply}");
        assert_eq!(offered, vec![expected], "{case}");
    }
}

// ---------------------------------------------------------------------------
// Authorization under standing rows
// ---------------------------------------------------------------------------

/// An origin answered "always" in one conversation authorizes the same agent
/// in a new conversation, and never another agent or an unattested session.
#[tokio::test]
async fn an_origin_row_authorizes_a_new_conversation_of_its_agent_and_no_other() {
    let mut fixture = Fixture::new();
    let first = fixture
        .route(Session::primary("conversation-one", AGENT).asking())
        .await;
    let reply = fixture
        .call_answering(
            &first,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 2),
            json!({"decision": "allow_origin_always", "elicitation_id": "el_origin"}),
            |_| {},
        )
        .await;
    assert_authorized(&reply, "the answered navigation");

    let later = fixture
        .route(Session::primary("conversation-two", AGENT))
        .await;
    assert_authorized(
        &fixture.navigate(&later, &format!("{PUBLIC}/later")).await,
        "the same agent in a new conversation",
    );
    assert_refused(
        &fixture.navigate(&later, "https://elsewhere.example/").await,
        "another origin",
    );

    let other = fixture
        .route(Session::primary("conversation-three", OTHER_AGENT))
        .await;
    assert_refused(
        &fixture.navigate(&other, &format!("{PUBLIC}/")).await,
        "another agent",
    );
}

/// An all-sites row covers any public website, reads included, and never a
/// loopback, private-use or localhost address.
#[tokio::test]
async fn an_all_sites_row_covers_public_origins_and_no_local_or_private_one() {
    let mut fixture = Fixture::new();
    fixture.seed(AGENT, StandingSubject::AllSites, 2, &[]);
    let route = fixture.route(Session::primary("c-all", AGENT)).await;
    for public in ["https://news.example/", "https://shop.example:8443/item"] {
        assert_authorized(&fixture.navigate(&route, public).await, public);
    }
    // A read commits its decision, which re-checks the standing row.
    let captured = fixture.call(&route, "browser.screenshot", json!({})).await;
    assert_eq!(captured["outcome"], "ok", "{captured}");
    for local in [
        "http://127.0.0.1:8080/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://localhost:3000/",
    ] {
        assert_refused(&fixture.navigate(&route, local).await, local);
    }
}

fn assert_hazard_refused(reply: &Value, what: &str) {
    assert_eq!(
        reply["outcome"], "hazard_not_disclosed",
        "{what} was not refused for its hazard: {reply}"
    );
    assert_eq!(
        reply["detail"]["missing_hazard"], "credential_form_submit",
        "{what}: {reply}"
    );
}

/// No all-sites row covers an action carrying a form hazard, and an origin
/// row covers one only when it lists that very hazard.
#[tokio::test]
async fn a_standing_row_never_covers_a_hazard_it_does_not_list() {
    async fn point_click(fixture: &Fixture, route: &Route) -> Value {
        let shot = fixture.call(route, "browser.screenshot", json!({})).await;
        assert_eq!(shot["outcome"], "ok", "{shot}");
        fixture
            .call(
                route,
                "browser.click_point",
                json!({
                    "snapshot_id": shot["snapshot_id"],
                    "x_px": 0,
                    "y_px": 0,
                    "image_width_px": shot["image_width_px"],
                    "image_height_px": shot["image_height_px"],
                    "intent": "press the button",
                    "severity": {"tier": 2, "credential": false, "financial": false},
                }),
            )
            .await
    }

    // All sites, at the highest level an all-sites row can carry.
    let mut fixture = Fixture::new();
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    let route = fixture.route(Session::primary("c-hazard-all", AGENT)).await;
    assert_authorized(
        &fixture.navigate(&route, &format!("{PUBLIC}/")).await,
        "navigate",
    );
    assert_hazard_refused(
        &point_click(&fixture, &route).await,
        "a sign-in submit under all sites",
    );
    assert!(!fixture
        .browser
        .effects()
        .contains(&"click_point".to_string()));

    // An origin row whose ceiling and flags cover the click, listing every
    // hazard but the one this click carries.
    let mut fixture = Fixture::new();
    fixture.seed(
        AGENT,
        StandingSubject::Origin(PUBLIC.into()),
        4,
        &[
            HazardClass::FinancialFormSubmit,
            HazardClass::UnverifiedFormContents,
        ],
    );
    let route = fixture
        .route(Session::primary("c-hazard-origin", AGENT))
        .await;
    assert_authorized(
        &fixture.navigate(&route, &format!("{PUBLIC}/")).await,
        "navigate",
    );
    assert_hazard_refused(
        &point_click(&fixture, &route).await,
        "a click whose hazard the row does not list",
    );
    assert!(!fixture
        .browser
        .effects()
        .contains(&"click_point".to_string()));

    // A row listing that hazard admits the same click, so the refusals above
    // are the hazard's and not something else about the click.
    let mut fixture = Fixture::new();
    fixture.seed(
        AGENT,
        StandingSubject::Origin(PUBLIC.into()),
        4,
        &[HazardClass::CredentialFormSubmit],
    );
    let route = fixture
        .route(Session::primary("c-hazard-listed", AGENT))
        .await;
    assert_authorized(
        &fixture.navigate(&route, &format!("{PUBLIC}/")).await,
        "navigate",
    );
    let admitted = point_click(&fixture, &route).await;
    assert_ne!(admitted["outcome"], "authorization_denied", "{admitted}");
    assert!(fixture
        .browser
        .effects()
        .contains(&"click_point".to_string()));
}

/// The ten-minute answer covers for ten minutes of the store's clock and
/// nothing after.
#[tokio::test]
async fn the_ten_minute_all_sites_row_expires() {
    let mut fixture = Fixture::new();
    let asking = fixture
        .route(Session::primary("c-short", AGENT).asking())
        .await;
    let reply = fixture
        .call_answering(
            &asking,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 2),
            json!({"decision": "allow_all_sites_10m", "elicitation_id": "el_short"}),
            |_| {},
        )
        .await;
    assert_authorized(&reply, "the answered navigation");

    let route = fixture
        .route(Session::primary("c-short-later", AGENT))
        .await;
    fixture.clock.advance_ms(ALL_SITES_SHORT_GRANT_MS - 1);
    assert_authorized(
        &fixture.navigate(&route, "https://other.example/").await,
        "one millisecond before expiry",
    );
    fixture.clock.advance_ms(1);
    assert_refused(
        &fixture.navigate(&route, "https://other.example/").await,
        "at expiry",
    );
    assert!(fixture.store.live_rows(AGENT).is_empty());
}

/// A public page that redirects into a private address is re-authorized
/// against where it landed, and an all-sites row does not cover that.
#[tokio::test]
async fn a_redirect_into_a_private_address_is_refused_under_an_all_sites_row() {
    let mut fixture = Fixture::new();
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    fixture
        .browser
        .redirect("https://news.example/go", "http://10.0.0.5/admin");
    let route = fixture.route(Session::primary("c-redirect", AGENT)).await;
    // The request names a public origin, so the navigation itself is covered.
    assert_authorized(
        &fixture.navigate(&route, "https://news.example/go").await,
        "the navigation",
    );
    // Reading where it landed is not.
    for read in ["browser.snapshot", "browser.screenshot"] {
        let refused = fixture.call(&route, read, json!({})).await;
        assert_refused(&refused, read);
        assert_eq!(
            refused["detail"]["attempted_origin"], "http://10.0.0.5",
            "{refused}"
        );
    }
}

/// No standing row, however broad, reaches typing: `browser.type` is not
/// served on the wire and the flat tool has no typing action. The refusal of
/// typing into credential and payment fields itself is held by
/// `credential_and_financial_targets_are_refused_before_authorization` in
/// `browser_type`, which refuses before any authorizer is consulted.
#[tokio::test]
async fn typing_a_password_is_refused_under_any_standing_row() {
    let mut fixture = Fixture::new();
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    fixture.seed(
        AGENT,
        StandingSubject::Origin(PUBLIC.into()),
        4,
        &HazardClass::ALL,
    );
    let route = fixture.route(Session::primary("c-type", AGENT)).await;
    assert_authorized(
        &fixture.navigate(&route, &format!("{PUBLIC}/login")).await,
        "navigate",
    );
    let typed = fixture
        .call(
            &route,
            "browser.type",
            json!({"ref": "e1", "snapshot_id": "s1", "text": "hunter2"}),
        )
        .await;
    assert_eq!(typed["code"], "capability_not_admitted", "{typed}");
    let flat = fixture
        .call(
            &route,
            "browser_use",
            json!({"action": "type", "ref": "e1", "snapshot_id": "s1", "text": "hunter2"}),
        )
        .await;
    assert_eq!(flat["outcome"], "invalid_request", "{flat}");
    assert!(
        !fixture
            .browser
            .effects()
            .iter()
            .any(|effect| effect.contains("type")),
        "{:?}",
        fixture.browser.effects()
    );
}

// ---------------------------------------------------------------------------
// Revoking and listing
// ---------------------------------------------------------------------------

/// An agent removes its own standing access, one origin or all of it, and
/// never another agent's.
#[tokio::test]
async fn revoke_access_removes_the_calling_agents_rows_only() {
    let mut fixture = Fixture::new();
    fixture.seed(AGENT, StandingSubject::Origin(PUBLIC.into()), 2, &[]);
    fixture.seed(
        AGENT,
        StandingSubject::Origin("https://docs.example".into()),
        2,
        &[],
    );
    fixture.seed(AGENT, StandingSubject::AllSites, 2, &[]);
    fixture.seed(OTHER_AGENT, StandingSubject::Origin(PUBLIC.into()), 2, &[]);
    let route = fixture.route(Session::primary("c-revoke", AGENT)).await;

    let one = fixture
        .call(
            &route,
            "browser_use",
            json!({"action": "revoke_access", "origin": PUBLIC}),
        )
        .await;
    assert_eq!(one, json!({"outcome": "revoked", "revoked": 1}));
    assert_eq!(fixture.store.live_rows(AGENT).len(), 2);

    let rest = fixture
        .call(&route, "browser_use", json!({"action": "revoke_access"}))
        .await;
    assert_eq!(rest, json!({"outcome": "revoked", "revoked": 2}));
    assert!(fixture.store.live_rows(AGENT).is_empty());
    assert_refused(
        &fixture.navigate(&route, &format!("{PUBLIC}/")).await,
        "after revoking",
    );
    assert_eq!(fixture.store.live_rows(OTHER_AGENT).len(), 1);

    let again = fixture
        .call(&route, "browser_use", json!({"action": "revoke_access"}))
        .await;
    assert_eq!(again, json!({"outcome": "nothing_to_revoke", "revoked": 0}));

    let invalid = fixture
        .call(
            &route,
            "browser_use",
            json!({"action": "revoke_access", "origin": "https://news.example/path"}),
        )
        .await;
    assert_eq!(invalid["outcome"], "invalid_request", "{invalid}");

    let unattested = fixture
        .route(Session {
            agent: None,
            ..Session::primary("c-revoke-unattested", AGENT)
        })
        .await;
    let refused = fixture
        .call(
            &unattested,
            "browser_use",
            json!({"action": "revoke_access"}),
        )
        .await;
    assert_eq!(refused["outcome"], "agent_not_attested", "{refused}");
    assert_eq!(fixture.store.live_rows(OTHER_AGENT).len(), 1);
}

/// The operator lists an agent's standing access with its always-allow app
/// grants, and revokes one origin, the all-sites rows, or everything.
#[tokio::test]
async fn the_operator_lists_and_revokes_an_agents_standing_access() {
    let mut fixture = Fixture::new();
    fixture.seed(AGENT, StandingSubject::Origin(PUBLIC.into()), 2, &[]);
    fixture.seed(
        AGENT,
        StandingSubject::Origin("https://docs.example".into()),
        4,
        &[HazardClass::CredentialFormSubmit],
    );
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    fixture.seed(OTHER_AGENT, StandingSubject::AllSites, 2, &[]);
    let desk = fixture.management_route().await;

    let listed = fixture
        .operate(&desk, "grants.list", json!({"agent_id": AGENT}))
        .await;
    assert_eq!(listed["agent_id"], AGENT, "{listed}");
    let rows = listed["browser"]["grants"].as_array().unwrap();
    assert_eq!(rows.len(), 3, "{listed}");
    assert_eq!(
        rows[1],
        json!({
            "agent_id": AGENT,
            "subject": {"origin": "https://docs.example"},
            "max_level": 4,
            "hazards": ["credential_form_submit"],
            "expires_at_ms": null,
            "granted_at_ms": fixture.clock_now(),
            "consent_ref": "el_seeded",
            "revoked_at_ms": null,
        })
    );
    assert_eq!(listed["browser"]["store"], json!({"state": "loaded"}));
    assert_eq!(listed["apps"]["grants"], json!([]), "{listed}");

    let all_sites = fixture
        .operate(
            &desk,
            "browser.revoke_grant",
            json!({"agent_id": AGENT, "all_sites": true}),
        )
        .await;
    assert_eq!(all_sites, json!({"outcome": "revoked", "revoked": 1}));
    let origin = fixture
        .operate(
            &desk,
            "browser.revoke_grant",
            json!({"agent_id": AGENT, "origin": PUBLIC}),
        )
        .await;
    assert_eq!(origin, json!({"outcome": "revoked", "revoked": 1}));
    let listed = fixture
        .operate(&desk, "grants.list", json!({"agent_id": AGENT}))
        .await;
    assert_eq!(listed["browser"]["grants"].as_array().unwrap().len(), 1);

    let everything = fixture
        .operate(&desk, "browser.revoke_grant", json!({"agent_id": AGENT}))
        .await;
    assert_eq!(everything, json!({"outcome": "revoked", "revoked": 1}));
    assert!(fixture.store.live_rows(AGENT).is_empty());
    assert_eq!(fixture.store.live_rows(OTHER_AGENT).len(), 1);

    for (params, field) in [
        (
            json!({"agent_id": AGENT, "origin": PUBLIC, "all_sites": true}),
            "all_sites",
        ),
        (json!({"origin": PUBLIC}), "agent_id"),
        (json!({"agent_id": AGENT, "everything": true}), "everything"),
    ] {
        let refused = fixture
            .operate(&desk, "browser.revoke_grant", params.clone())
            .await;
        assert_eq!(refused["outcome"], "invalid_request", "{params}: {refused}");
        assert_eq!(refused["detail"]["field"], field, "{params}: {refused}");
    }
}

// ---------------------------------------------------------------------------
// The store
// ---------------------------------------------------------------------------

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cerebellum-standing-grants-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn storage(&self) -> FilesystemStandingGrantStorage {
        FilesystemStandingGrantStorage::new(self.0.join("browser_standing_grants.json"))
            .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(
                self.0
                    .join(cerebellum_core::format_floor::FORMAT_FLOOR_FILE),
            ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A row answered before a restart still authorizes after it, read back
/// from the file the first module wrote.
#[tokio::test]
async fn a_standing_row_survives_a_module_restart() {
    let scratch = Scratch::new("restart");
    let clock = ManualWallClock::at(1_700_000_000_000);
    {
        let mut fixture = Fixture::with_store(store_over(scratch.storage(), &clock), clock.clone());
        let route = fixture
            .route(Session::primary("before-restart", AGENT).asking())
            .await;
        let reply = fixture
            .call_answering(
                &route,
                "browser.navigate",
                navigation(&format!("{PUBLIC}/"), 2),
                json!({"decision": "allow_origin_always", "elicitation_id": "el_restart"}),
                |_| {},
            )
            .await;
        assert_authorized(&reply, "before the restart");
    }
    let mut fixture = Fixture::with_store(store_over(scratch.storage(), &clock), clock);
    let route = fixture
        .route(Session::primary("after-restart", AGENT))
        .await;
    assert_authorized(
        &fixture.navigate(&route, &format!("{PUBLIC}/")).await,
        "after the restart",
    );
}

/// A store restored onto another machine grants nothing there, offers no
/// standing answer to be written over it, and lists nothing.
#[tokio::test]
async fn a_row_bound_to_another_machine_grants_nothing() {
    let storage = InMemoryStandingGrantStorage::new();
    let clock = ManualWallClock::at(1_700_000_000_000);
    store_over(storage.clone(), &clock)
        .record(
            AGENT,
            StandingSubject::AllSites,
            2,
            Vec::new(),
            None,
            "el_elsewhere",
        )
        .unwrap();
    let restored = Arc::new(
        StandingBrowserGrants::open(Arc::new(storage), Some("another-machine".to_string()))
            .with_clock(Arc::new(clock.clone())),
    );
    let mut fixture = Fixture::with_store(restored, clock);
    let route = fixture.route(Session::primary("c-restored", AGENT)).await;
    assert_refused(
        &fixture.navigate(&route, &format!("{PUBLIC}/")).await,
        "a row from another machine",
    );
    assert!(fixture.store.live_rows(AGENT).is_empty());
}

/// A file this build cannot read withholds every standing grant, offers no
/// standing answer, and is left exactly as it was.
#[tokio::test]
async fn an_unreadable_store_withholds_standing_grants_and_is_not_overwritten() {
    let scratch = Scratch::new("unreadable");
    let path = scratch.0.join("browser_standing_grants.json");
    std::fs::write(&path, br#"{"version": 2, "grants": []}"#).unwrap();
    let clock = ManualWallClock::at(1_700_000_000_000);
    let mut fixture = Fixture::with_store(store_over(scratch.storage(), &clock), clock);
    assert!(fixture.store.store_error().is_some());
    let route = fixture
        .route(Session::primary("c-unreadable", AGENT).asking())
        .await;
    let mut offered = Vec::new();
    fixture
        .call_answering(
            &route,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 2),
            json!({"decision": "deny"}),
            |question| offered.push(option_ids(question)),
        )
        .await;
    assert_eq!(offered, vec![vec!["allow_conversation", "deny"]]);
    let revoke = fixture
        .call(&route, "browser_use", json!({"action": "revoke_access"}))
        .await;
    assert_eq!(revoke["outcome"], "store_unavailable", "{revoke}");
    assert_eq!(
        std::fs::read(&path).unwrap(),
        br#"{"version": 2, "grants": []}"#
    );
}
