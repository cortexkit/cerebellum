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
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::authorization::HazardClass;
use cerebellum::browser::navigation::{BrowserScreenshotObservation, BrowserSnapshotObservation};
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
use cerebellum::snapshot_store::{
    AxRecord, BackendNodeIdentity, CommittedDocument, FrameDocument, RefRecord, SnapshotKind,
    SnapshotRef,
};
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

// The probes' consent relay, as the suite's consent_relay module includes it.
use crate::consent_relay::consent_relay;

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
    login_step: Arc<AtomicUsize>,
    frames: Arc<Mutex<Vec<FrameDocument>>>,
    readable_frames: Arc<Mutex<Vec<FrameDocument>>>,
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
    fn frame_documents(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<Vec<FrameDocument>, NavigationDriveError> {
        Ok(self.0.frames.lock().unwrap().clone())
    }

    fn set_read_frames(&mut self, frames: Vec<FrameDocument>) -> Result<(), NavigationDriveError> {
        *self.0.readable_frames.lock().unwrap() = frames;
        Ok(())
    }
    fn snapshot_classified(
        &mut self,
        _: &str,
        _: SnapshotKind,
        epoch: u64,
        origin: &str,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let origin = canonical_origin_from_url(origin).unwrap();
        let targets = [
            (
                "Button",
                ElementClassificationInput::new(
                    NodeIdentityInput::new("target", "frame-main", 42),
                    TargetKind::Button,
                )
                .input_type("button"),
            ),
            (
                "Link",
                ElementClassificationInput::new(
                    NodeIdentityInput::new("target", "frame-main", 43),
                    TargetKind::Anchor,
                )
                .destination("https://other.example/page"),
            ),
            (
                "Text",
                ElementClassificationInput::new(
                    NodeIdentityInput::new("target", "frame-main", 44),
                    TargetKind::Input,
                )
                .input_type("text"),
            ),
            (
                "Submit",
                ElementClassificationInput::new(
                    NodeIdentityInput::new("target", "frame-main", 45),
                    TargetKind::Button,
                )
                .form_owner(NodeIdentityInput::new("target", "frame-main", 7)),
            ),
            (
                "Password",
                ElementClassificationInput::new(
                    NodeIdentityInput::new("target", "frame-main", 46),
                    TargetKind::Input,
                )
                .input_type("password")
                .password(true),
            ),
            (
                "Payment",
                ElementClassificationInput::new(
                    NodeIdentityInput::new("target", "frame-main", 47),
                    TargetKind::Input,
                )
                .input_type("text")
                .autocomplete(["cc-number"]),
            ),
        ];
        let mut observation = BrowserSnapshotObservation {
            records: vec![],
            dom_text: Some("<main>Public page</main>".into()),
            refs: vec![],
            ax_truncated: false,
            refs_truncated: false,
            facts: Default::default(),
        };
        for (index, (name, target)) in targets.into_iter().enumerate() {
            let reference = format!("e{}", index + 1);
            let classification =
                classify_click(&NonTypeClassificationInput::new(epoch, target, &origin)).unwrap();
            observation.records.push(AxRecord {
                depth: 0,
                role: "button".into(),
                name: name.into(),
                value: None,
                reference: Some(reference.clone()),
            });
            observation.refs.push(RefRecord {
                frame_document: None,
                captured: SnapshotRef::new(&reference, "button", name, 0).unwrap(),
                frame_path: vec!["frame-main".into()],
                backend_identity: Some(
                    BackendNodeIdentity::new("target", "frame-main", 42 + index as u64).unwrap(),
                ),
                raw_role: Some("button".into()),
                raw_name: Some(name.into()),
                classification: Ok(Box::new(classification)),
            });
        }
        for frame in self
            .0
            .readable_frames
            .lock()
            .unwrap()
            .iter()
            .filter(|frame| frame.parent_id.is_some())
        {
            let name = match frame.frame_id.as_str() {
                "frame-private" => "Local admin secret",
                "frame-nested" => "Nested public child",
                _ => "Public embedded text",
            };
            let reference = format!("e{}", observation.refs.len() + 1);
            let backend = match frame.frame_id.as_str() {
                "frame-private" => 142,
                "frame-nested" => 143,
                _ => 144,
            };
            let target = ElementClassificationInput::new(
                NodeIdentityInput::new("target", &frame.frame_id, backend),
                TargetKind::Button,
            )
            .input_type("button");
            let record = classify_click(&NonTypeClassificationInput::new(
                epoch,
                target,
                &frame.origin,
            ))
            .unwrap();
            observation.records.push(AxRecord {
                depth: 0,
                role: "button".into(),
                name: name.into(),
                value: None,
                reference: Some(reference.clone()),
            });
            observation.refs.push(RefRecord {
                frame_document: Some(frame.clone()),
                captured: SnapshotRef::new(&reference, "button", name, 0).unwrap(),
                frame_path: vec!["frame-main".into(), frame.frame_id.clone()],
                backend_identity: Some(
                    BackendNodeIdentity::new("target", &frame.frame_id, backend).unwrap(),
                ),
                raw_role: Some("button".into()),
                raw_name: Some(name.into()),
                classification: Ok(Box::new(record)),
            });
            observation
                .dom_text
                .as_mut()
                .unwrap()
                .push_str(&format!("<div>{name}</div>"));
        }
        Ok(observation)
    }

    fn click_classified(
        &mut self,
        _: &str,
        _: &BackendNodeIdentity,
        _: u64,
        _: &str,
        _: Option<&NonTypeClassificationRecord>,
        _: u64,
        input: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.0.effects.lock().unwrap().push("click".into());
        let position = BrowserClickPosition {
            x_css: 1.0,
            y_css: 1.0,
        };
        input(BrowserInputEvent::Press(position));
        input(BrowserInputEvent::Release(position));
        Ok(BrowserClickOutcome::Clicked {
            position,
            navigation: ClickNavigation::NoneObserved { window_ms: 100 },
        })
    }

    fn type_classified(
        &mut self,
        _: &str,
        _: &cerebellum::browser_type::TypeDispatch,
        _: &str,
        _: bool,
        _: u64,
    ) -> Result<cerebellum::browser_type::BrowserTypeResult, NavigationDriveError> {
        self.0.effects.lock().unwrap().push("type".into());
        Ok(cerebellum::browser_type::BrowserTypeResult::Ok)
    }

    fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
        self.0.login_step.store(1, Ordering::SeqCst);
        Ok(())
    }
    fn cookie_names_for_origin(
        &mut self,
        _: &str,
        _: &str,
        _: u64,
    ) -> Result<std::collections::BTreeSet<String>, NavigationDriveError> {
        Ok(if self.0.login_step.load(Ordering::SeqCst) >= 2 {
            ["session".to_string()].into()
        } else {
            Default::default()
        })
    }
    fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
        Ok(self.0.login_step.swap(2, Ordering::SeqCst) == 1)
    }
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
    signed_in: Arc<cerebellum::browser_signed_in::SignedInDomains>,
}

impl Fixture {
    fn new() -> Self {
        let clock = ManualWallClock::at(1_700_000_000_000);
        let store = store_over(InMemoryStandingGrantStorage::new(), &clock);
        Self::with_store(store, clock)
    }

    fn with_store(store: Arc<StandingBrowserGrants>, clock: ManualWallClock) -> Self {
        Self::with_login_store(store, clock, None)
    }

    fn with_login_store(
        store: Arc<StandingBrowserGrants>,
        clock: ManualWallClock,
        signed_in: Option<Arc<cerebellum::browser_signed_in::SignedInDomains>>,
    ) -> Self {
        let signed_in = signed_in
            .unwrap_or_else(|| Arc::new(cerebellum::browser_signed_in::SignedInDomains::default()));
        let browser = Browser::default();
        let mut planes = Planes::with_browser_state(
            Arc::new(HealthState::new()),
            Some(config()),
            JournalPersistence::Isolated,
            Some(Arc::clone(&store)),
            Some(Arc::clone(&signed_in)),
        );
        planes.launch_service = Some(Arc::new(browser.clone()));
        Self {
            planes,
            browser,
            store,
            clock,
            next_channel: 20,
            signed_in,
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
        let identity = cerebellum_core::identity::RouteIdentity::from_accepted_bind(
            &BindIdentity::new("/test/project", "test", session.conversation.to_string()),
            &cerebellum::session_caller_principal_for_test(),
            Some(&facts),
        );
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
            identity,
        };
        if let Some(agent) = session.agent.filter(|_| !management) {
            let profile = if session.kind == "primary" {
                "default".to_string()
            } else {
                format!("disposable:{}", session.conversation)
            };
            if !self.signed_in.contains_profile(agent, &profile) {
                self.signed_in
                    .initialize_profile(
                        agent,
                        &profile,
                        &format!("fixture-{agent}-{profile}"),
                        true,
                    )
                    .unwrap();
            }
        }
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

    // Declare reversible-change severity (tier 3), above the public-browsing
    // ceiling, so these probes must use an explicit site grant.
    async fn navigate(&self, route: &Route, url: &str) -> Value {
        self.call(route, "browser.navigate", navigation(url, 3))
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
    identity: cerebellum_core::identity::RouteIdentity,
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
                navigation(&format!("{PUBLIC}/"), 3),
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
                assert_eq!(row.max_level, 3, "{id}");
                assert!(row.hazards.is_empty(), "{id}");
                assert_eq!(row.consent_ref, consent_ref);
                assert_eq!(row.granted_at_ms, now);
                assert_eq!(row.revoked_at_ms, None);
                let (subject, expires) = match id {
                    "allow_origin_always" => (StandingSubject::Domain("news.example".into()), None),
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
            3,
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
            3,
            no_all_sites.clone(),
        ),
        (
            "loopback",
            Session::primary("c-loopback", AGENT).asking(),
            "http://127.0.0.1:8080/",
            3,
            no_all_sites,
        ),
        (
            "worker session",
            Session {
                kind: "subagent",
                ..Session::primary("c-worker", AGENT).asking()
            },
            "https://news.example/",
            3,
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
            navigation(&format!("{PUBLIC}/"), 3),
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
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    let route = fixture.route(Session::primary("c-all", AGENT)).await;
    for public in ["https://news.example/", "https://shop.example/item"] {
        assert_authorized(&fixture.navigate(&route, public).await, public);
    }
    // A read commits its decision, which re-checks the standing row.
    let captured = fixture.call(&route, "browser.screenshot", json!({})).await;
    assert_eq!(captured["outcome"], "ok", "{captured}");
    for local in [
        "https://shop.example:8443/item",
        "https://1.1.1.1/",
        "http://1.1.1.1/",
        "https://office.local/",
        "https://office.internal/",
        "http://127.0.0.1:8080/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "http://localhost:3000/",
    ] {
        assert_refused(&fixture.navigate(&route, local).await, local);
    }
    fixture.seed(
        AGENT,
        StandingSubject::Origin("https://shop.example:8443".into()),
        3,
        &[],
    );
    assert_authorized(
        &fixture
            .navigate(&route, "https://shop.example:8443/item")
            .await,
        "an exact service-port grant",
    );
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
            navigation(&format!("{PUBLIC}/"), 3),
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

/// A broad standing row cannot bypass the requirement to read a target first.
#[tokio::test]
async fn typing_without_a_snapshot_is_refused_under_any_standing_row() {
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
            json!({"ref": "e1", "text": "hunter2"}),
        )
        .await;
    assert_eq!(typed["outcome"], "stale_snapshot", "{typed}");
    let flat = fixture
        .call(
            &route,
            "browser_use",
            json!({"action": "type", "ref": "e1", "text": "hunter2"}),
        )
        .await;
    assert_eq!(flat["outcome"], "stale_snapshot", "{flat}");
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
    fixture.seed(AGENT, StandingSubject::Origin(PUBLIC.into()), 3, &[]);
    fixture.seed(
        AGENT,
        StandingSubject::Origin("https://docs.example".into()),
        3,
        &[],
    );
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    fixture.seed(OTHER_AGENT, StandingSubject::Origin(PUBLIC.into()), 3, &[]);
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
    fixture.seed(AGENT, StandingSubject::Origin(PUBLIC.into()), 3, &[]);
    fixture.seed(
        AGENT,
        StandingSubject::Origin("https://docs.example".into()),
        4,
        &[HazardClass::CredentialFormSubmit],
    );
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    fixture.seed(OTHER_AGENT, StandingSubject::AllSites, 3, &[]);
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

struct Scratch(cortexkit_test_support::ScratchDir);

impl Scratch {
    fn new(label: &str) -> Self {
        Self(cortexkit_test_support::ScratchDir::new(&format!(
            "cerebellum-standing-grants-{label}"
        )))
    }

    fn storage(&self) -> FilesystemStandingGrantStorage {
        FilesystemStandingGrantStorage::new(self.0.join("browser_standing_grants.json"))
            .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(
                self.0
                    .join(cerebellum_core::format_floor::FORMAT_FLOOR_FILE),
            ))
    }
}

/// Replacing an origin answer keeps the earlier consent row as revoked history.
#[tokio::test]
async fn replacing_an_origin_row_keeps_the_old_consent_as_revoked_history() {
    let scratch = Scratch::new("superseded");
    let clock = ManualWallClock::at(1_700_000_000_000);
    let storage = scratch.storage();
    let store = store_over(storage, &clock);
    let subject = StandingSubject::Origin(PUBLIC.into());
    store
        .record(AGENT, subject.clone(), 3, vec![], None, "el_first")
        .unwrap();
    clock.advance_ms(18_000);
    store
        .record(AGENT, subject, 3, vec![], None, "el_second")
        .unwrap();

    let file: Value = serde_json::from_slice(
        &std::fs::read(scratch.0.join("browser_standing_grants.json")).unwrap(),
    )
    .unwrap();
    let rows = file["grants"].as_array().unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["consent_ref"], "el_first");
    assert_eq!(rows[0]["revoked_at_ms"], 1_700_000_018_000_u64);
    assert_eq!(rows[1]["consent_ref"], "el_second");
    assert_eq!(rows[1]["revoked_at_ms"], Value::Null);
    assert_eq!(store.live_rows(AGENT).len(), 1);
    assert_eq!(store.live_rows(AGENT)[0].consent_ref, "el_second");

    let mut fixture = Fixture::with_store(store, clock);
    let desk = fixture.management_route().await;
    let listed = fixture
        .operate(&desk, "grants.list", json!({"agent_id": AGENT}))
        .await;
    let listed_rows = listed["browser"]["grants"].as_array().unwrap();
    assert_eq!(listed_rows.len(), 1);
    assert_eq!(listed_rows[0]["consent_ref"], "el_second");
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
                navigation(&format!("{PUBLIC}/"), 3),
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
            3,
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
    std::fs::write(&path, br#"{"version": 3, "grants": []}"#).unwrap();
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
            navigation(&format!("{PUBLIC}/"), 3),
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
        br#"{"version": 3, "grants": []}"#
    );
}

#[tokio::test]
async fn domain_always_mints_and_authorizes_a_sibling_without_a_card() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-domain", AGENT).asking())
        .await;
    let reply = fixture
        .call_answering(
            &route,
            "browser.navigate",
            navigation("https://manager.eu.ovhcloud.com/", 3),
            json!({"decision": "allow_origin_always", "elicitation_id":"el_domain"}),
            |question| {
                assert!(question
                    .to_string()
                    .contains("Always allow on ovhcloud.com and its subdomains"));
            },
        )
        .await;
    assert_authorized(&reply, "domain answer");
    assert_eq!(
        fixture.store.live_rows(AGENT)[0].subject.to_value(),
        json!({"domain":"ovhcloud.com"})
    );
    let reply = fixture
        .call(
            &route,
            "browser.navigate",
            navigation("https://auth.eu.ovhcloud.com/", 3),
        )
        .await;
    assert_authorized(&reply, "sibling");
}

#[tokio::test]
async fn suffix_localhost_and_ip_cards_remain_host_only() {
    for (origin, host) in [
        ("https://github.io", "github.io"),
        ("http://localhost:8080", "localhost"),
        ("https://93.184.216.34", "93.184.216.34"),
    ] {
        let mut fixture = Fixture::new();
        let route = fixture
            .route(Session::primary("c-host", AGENT).asking())
            .await;
        fixture
            .call_answering(
                &route,
                "browser.navigate",
                navigation(&format!("{origin}/"), 3),
                json!({"decision":"deny"}),
                |question| {
                    let text = question.to_string();
                    assert!(text.contains(&format!("Always allow on {host}")), "{text}");
                    assert!(!text.contains("and its subdomains"), "{text}");
                },
            )
            .await;
    }
}

#[tokio::test]
async fn domain_rows_never_cover_http() {
    let mut fixture = Fixture::new();
    fixture.seed(
        AGENT,
        StandingSubject::Domain("ovhcloud.com".into()),
        3,
        &[],
    );
    let route = fixture.route(Session::primary("c-http", AGENT)).await;
    let reply = fixture
        .call(
            &route,
            "browser.navigate",
            navigation("http://auth.ovhcloud.com/", 3),
        )
        .await;
    assert_refused(&reply, "http");
}

#[tokio::test]
async fn domain_rows_never_cover_sibling_domains() {
    let mut fixture = Fixture::new();
    fixture.seed(
        AGENT,
        StandingSubject::Domain("ovhcloud.com".into()),
        3,
        &[],
    );
    let route = fixture.route(Session::primary("c-sibling", AGENT)).await;
    let reply = fixture
        .call(
            &route,
            "browser.navigate",
            navigation("https://notovhcloud.com/", 3),
        )
        .await;
    assert_refused(&reply, "sibling domain");
}

#[tokio::test]
async fn domain_rows_are_listed_and_revoked_by_operator_and_agent() {
    let mut fixture = Fixture::new();
    fixture.seed(
        AGENT,
        StandingSubject::Domain("ovhcloud.com".into()),
        4,
        &[HazardClass::CredentialFormSubmit],
    );
    let desk = fixture.management_route().await;
    let listed = fixture
        .operate(&desk, "grants.list", json!({"agent_id":AGENT}))
        .await;
    assert_eq!(
        listed["browser"]["grants"][0]["subject"],
        json!({"domain":"ovhcloud.com"})
    );
    let revoked = fixture
        .operate(
            &desk,
            "browser.revoke_grant",
            json!({"agent_id":AGENT,"domain":"ovhcloud.com"}),
        )
        .await;
    assert_eq!(revoked["revoked"], 1);
    fixture.seed(
        AGENT,
        StandingSubject::Domain("ovhcloud.com".into()),
        3,
        &[],
    );
    let route = fixture.route(Session::primary("c-withdraw", AGENT)).await;
    let revoked = fixture
        .call(
            &route,
            "browser_use",
            json!({"action":"revoke_access","domain":"ovhcloud.com"}),
        )
        .await;
    assert_eq!(revoked["revoked"], 1, "{revoked}");
}

// ---------------------------------------------------------------------------
// Public browsing without stored grants
// ---------------------------------------------------------------------------

fn named_ref(snapshot: &Value, name: &str) -> String {
    snapshot["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|row| row["name"] == name)
        .unwrap()["ref"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn public_snapshot(fixture: &Fixture, route: &Route, origin: &str) -> Value {
    let navigated = fixture
        .call(
            route,
            "browser.navigate",
            navigation(&format!("{origin}/"), 1),
        )
        .await;
    assert_authorized(&navigated, "baseline navigation");
    let snapshot = fixture
        .call(route, "browser.snapshot", json!({"mode":"ax"}))
        .await;
    assert_authorized(&snapshot, "baseline snapshot");
    snapshot
}

async fn observed_fixture_login(
    fixture: &Fixture,
    route: &Route,
    conversation: &str,
    origin: &str,
) {
    let presented = fixture
        .call(
            route,
            "browser_use",
            json!({"action":"present","origin":origin}),
        )
        .await;
    assert_eq!(presented["outcome"], "presented", "{presented}");
    use cerebellum::browser_session::{HandoffOutcome, HandoffPollResult};
    let sessions = &fixture.planes.sessions;
    assert!(matches!(
        sessions.poll_handoff(conversation, 1, 100, fixture.planes.lease_clock.as_ref()),
        HandoffPollResult::Open
    ));
    let closed = sessions.poll_handoff(conversation, 1, 100, fixture.planes.lease_clock.as_ref());
    assert!(
        matches!(closed, HandoffPollResult::Closed(ref close) if close.outcome == HandoffOutcome::LoginObserved),
        "{closed:?}"
    );
    if let HandoffPollResult::Closed(close) = &closed {
        fixture
            .planes
            .browser
            .journal_handoff_closed(&route.identity, close)
            .await
            .unwrap();
    }
    let resumed = fixture
        .call(route, "browser_use", json!({"action":"resume"}))
        .await;
    assert_eq!(resumed["handoff"], "login_observed", "{resumed}");
}

#[tokio::test]
async fn baseline_public_reads_and_ordinary_clicks_need_no_card() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-reads", AGENT).asking())
        .await;
    let snapshot = public_snapshot(&fixture, &route, PUBLIC).await;
    assert_authorized(
        &fixture.call(&route, "browser.screenshot", json!({})).await,
        "baseline screenshot",
    );
    for name in ["Button", "Link"] {
        let clicked = fixture.call(&route, "browser.click", json!({"ref":named_ref(&snapshot, name),"snapshot_id":snapshot["snapshot_id"],"intent":"follow an ordinary control","severity":{"tier":2,"credential":false,"financial":false}})).await;
        assert_authorized(&clicked, name);
    }
    assert_eq!(fixture.planes.management.browser_grant_count().await, 0);
    assert!(fixture.store.live_rows(AGENT).is_empty());
    assert_eq!(
        fixture
            .browser
            .effects()
            .iter()
            .filter(|effect| effect.as_str() == "click")
            .count(),
        2
    );
    let export = fixture.planes.browser.journal_export_for_test().await;
    let rows: Vec<Value> = export
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|row| row.get("grant_decision").is_some())
        .collect();
    assert_eq!(rows.len(), 5, "{export}");
    for row in rows {
        assert_eq!(
            row["grant_decision"],
            json!({"outcome":"allowed","reason":"public_web_baseline"}),
            "{row}"
        );
        assert_eq!(row["format_version"], "ck-browser-journal/v8");
    }
}

#[tokio::test]
async fn baseline_form_submit_still_asks() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-submit", AGENT).asking())
        .await;
    let snapshot = public_snapshot(&fixture, &route, PUBLIC).await;
    let mut cards = Vec::new();
    let submitted = fixture.call_answering(&route, "browser.click", json!({"ref":named_ref(&snapshot,"Submit"),"snapshot_id":snapshot["snapshot_id"],"intent":"submit the form","severity":{"tier":2,"credential":false,"financial":false}}), json!({"decision":"deny"}), |question| cards.push(question.clone())).await;
    assert_refused(&submitted, "form submission");
    assert_eq!(cards.len(), 1, "{cards:?}");
    assert!(!fixture
        .browser
        .effects()
        .iter()
        .any(|effect| effect == "click"));
}

#[tokio::test]
async fn baseline_signed_in_typing_still_asks() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-type", AGENT).asking())
        .await;
    let snapshot = public_snapshot(&fixture, &route, PUBLIC).await;
    let arguments = json!({"ref":named_ref(&snapshot,"Text"),"snapshot_id":snapshot["snapshot_id"],"text":"hello"});
    assert_authorized(
        &fixture
            .call(&route, "browser.type", arguments.clone())
            .await,
        "never-signed-in typing",
    );
    observed_fixture_login(&fixture, &route, "c-baseline-type", PUBLIC).await;
    let sibling = public_snapshot(&fixture, &route, "https://account.news.example").await;
    let mut cards = Vec::new();
    let typed = fixture.call_answering(&route, "browser.type", json!({"ref":named_ref(&sibling,"Text"),"snapshot_id":sibling["snapshot_id"],"text":"hello again"}), json!({"decision":"deny"}), |question| cards.push(question.clone())).await;
    assert_refused(&typed, "signed-in typing on a sibling");
    assert_eq!(cards.len(), 1, "{cards:?}");
    assert_eq!(
        fixture
            .browser
            .effects()
            .iter()
            .filter(|effect| effect.as_str() == "type")
            .count(),
        1
    );
    // An observed login belongs to one agent's browser profile, not every
    // agent sharing this machine.
    let worker = fixture
        .route(Session {
            kind: "subagent",
            ..Session::primary("c-baseline-worker", AGENT).asking()
        })
        .await;
    let worker_snapshot = public_snapshot(&fixture, &worker, PUBLIC).await;
    assert_eq!(
        worker_snapshot["context"]["profile_disposition"],
        "disposable"
    );
    assert_authorized(&fixture.call(&worker, "browser.type", json!({"ref":named_ref(&worker_snapshot,"Text"),"snapshot_id":worker_snapshot["snapshot_id"],"text":"a separate disposable profile"})).await,"unsigned disposable profile");
    let other = fixture
        .route(Session::primary("c-baseline-other", OTHER_AGENT).asking())
        .await;
    let snapshot = public_snapshot(&fixture, &other, PUBLIC).await;
    assert_authorized(&fixture.call(&other,"browser.type",json!({"ref":named_ref(&snapshot,"Text"),"snapshot_id":snapshot["snapshot_id"],"text":"another profile"})).await,"another profile's typing");
}

#[tokio::test]
async fn baseline_local_services_still_ask() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-local", AGENT).asking())
        .await;
    for url in [
        "http://localhost/",
        "http://10.0.0.5/",
        "http://192.168.1.1/",
        "https://news.example:8443/",
        "http://1.1.1.1/",
        "https://1.1.1.1/",
        "http://printer.local/",
        "https://service.internal/",
    ] {
        let mut cards = Vec::new();
        let reply = fixture
            .call_answering(
                &route,
                "browser.navigate",
                navigation(url, 1),
                json!({"decision":"deny"}),
                |question| cards.push(question.clone()),
            )
            .await;
        assert_refused(&reply, url);
        assert_eq!(cards.len(), 1, "{url}: {cards:?}");
    }
    assert!(fixture.browser.effects().is_empty());
}

#[tokio::test]
async fn baseline_credential_and_payment_typing_remain_hard_refused() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-sensitive", AGENT).asking())
        .await;
    let snapshot = public_snapshot(&fixture, &route, PUBLIC).await;
    for name in ["Password", "Payment"] {
        let reply = fixture.call(&route,"browser.type",json!({"ref":named_ref(&snapshot,name),"snapshot_id":snapshot["snapshot_id"],"text":"sensitive"})).await;
        assert_eq!(reply["outcome"], "invalid_request", "{reply}");
        assert_eq!(
            reply["detail"]["reason_code"], "credential_input_unsupported",
            "{reply}"
        );
    }
    assert!(!fixture
        .browser
        .effects()
        .iter()
        .any(|effect| effect == "type"));
}

#[tokio::test]
async fn baseline_login_record_survives_plane_restart() {
    let scratch = cortexkit_test_support::ScratchDir::new("baseline-login-restart");
    let path = scratch.join("browser/signed-in-domains.json");
    let floor_path = scratch.join("browser/format-floor.json");
    let clock = ManualWallClock::at(1_700_000_000_000);
    let store = store_over(InMemoryStandingGrantStorage::new(), &clock);
    let signed_in = Arc::new(
        cerebellum::browser_signed_in::SignedInDomains::open(path.clone())
            .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(&floor_path)),
    );
    assert!(!path.exists());
    assert!(!floor_path.exists());
    {
        let mut fixture =
            Fixture::with_login_store(Arc::clone(&store), clock.clone(), Some(signed_in));
        let route = fixture
            .route(Session::primary("c-login-before", AGENT).asking())
            .await;
        let creation = std::fs::read(&path).unwrap();
        public_snapshot(&fixture, &route, PUBLIC).await;
        assert_eq!(
            std::fs::read(&path).unwrap(),
            creation,
            "reading must not write login state"
        );
        observed_fixture_login(&fixture, &route, "c-login-before", PUBLIC).await;
        assert!(path.exists());
    }
    let bytes = std::fs::read_to_string(&path).unwrap();
    let state: Value = serde_json::from_str(&bytes).unwrap();
    assert_eq!(
        state,
        json!({"version":1,"profiles":{AGENT:{"default":{"domains":["news.example"],"signed_in_coverage":"complete","profile_uuid":"fixture-pj-standing-agent-default"}}}})
    );
    assert!(!bytes.contains("https://"));
    assert!(!bytes.contains("session"));
    assert_eq!(
        cerebellum_core::format_floor::read_floors(&floor_path).unwrap()
            ["browser-signed-in-domains"],
        1
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    let mut restarted = Fixture::with_login_store(
        store,
        clock,
        Some(Arc::new(
            cerebellum::browser_signed_in::SignedInDomains::open(path),
        )),
    );
    let route = restarted
        .route(Session::primary("c-login-after", AGENT).asking())
        .await;
    let snapshot = public_snapshot(&restarted, &route, PUBLIC).await;
    let mut cards = Vec::new();
    let reply = restarted.call_answering(&route,"browser.type",json!({"ref":named_ref(&snapshot,"Text"),"snapshot_id":snapshot["snapshot_id"],"text":"after restart"}),json!({"decision":"deny"}),|question| cards.push(question.clone())).await;
    assert_refused(&reply, "restarted signed-in profile");
    assert_eq!(cards.len(), 1);
}

#[tokio::test]
async fn baseline_would_ask_answers_yes_for_public_browsing() {
    let mut fixture = Fixture::new();
    fixture
        .signed_in
        .initialize_profile(AGENT, "default", "new-install-profile", true)
        .unwrap();
    let operator = fixture.management_route().await;
    let reply = fixture.operate(&operator,"grants.would_ask",json!({"agent_id":AGENT,"flow_id":"public-reader","items":[{"tool":"browser_use","target":PUBLIC,"level":1},{"tool":"browser_use","target":PUBLIC,"level":2},{"tool":"browser_use","target":PUBLIC,"level":4},{"tool":"browser_use","target":"http://localhost","level":1}]})).await;
    assert_eq!(reply["items"][0]["verdict"], "yes", "{reply}");
    assert_eq!(reply["items"][0]["reason"], "public_web_baseline");
    assert_eq!(reply["items"][1]["verdict"], "yes");
    assert_eq!(reply["items"][2]["verdict"], "would_ask");
    assert_eq!(reply["items"][3]["verdict"], "would_ask");
}

#[tokio::test]
async fn baseline_sensitive_clicks_ask_but_observation_stays_free() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-sensitive-click", AGENT).asking())
        .await;
    let snapshot = public_snapshot(&fixture, &route, PUBLIC).await;
    assert_authorized(
        &fixture.call(&route, "browser.screenshot", json!({})).await,
        "observing sensitive fields",
    );
    for name in ["Password", "Payment"] {
        let mut cards = Vec::new();
        let reply = fixture.call_answering(&route,"browser.click",json!({"ref":named_ref(&snapshot,name),"snapshot_id":snapshot["snapshot_id"],"intent":"focus a sensitive field","severity":{"tier":2,"credential":false,"financial":false}}),json!({"decision":"deny"}),|question| cards.push(question.clone())).await;
        assert_refused(&reply, name);
        assert_eq!(cards.len(), 1, "{name}: {cards:?}");
    }
    assert!(!fixture
        .browser
        .effects()
        .iter()
        .any(|effect| effect == "click"));
}

#[tokio::test]
async fn baseline_private_frames_are_omitted_until_the_top_page_has_person_permission() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-baseline-frames", AGENT).asking())
        .await;
    let frame = |id: &str, parent: Option<&str>, origin: &str| FrameDocument {
        navigation_revision: 0,
        frame_id: id.into(),
        parent_id: parent.map(str::to_string),
        session_id: format!("session-{id}"),
        loader_id: format!("loader-{id}"),
        url: if parent.is_none() {
            format!("{origin}/")
        } else {
            format!("{origin}/frame")
        },
        origin: origin.into(),
    };
    *fixture.browser.frames.lock().unwrap() = vec![
        frame("frame-main", None, PUBLIC),
        frame("frame-private", Some("frame-main"), "http://127.0.0.1"),
        frame(
            "frame-nested",
            Some("frame-private"),
            "https://nested.example",
        ),
        frame("frame-public", Some("frame-main"), "https://widget.example"),
    ];
    assert_authorized(
        &fixture
            .call(
                &route,
                "browser.navigate",
                navigation(&format!("{PUBLIC}/"), 1),
            )
            .await,
        "public parent",
    );
    for mode in ["actionable", "ax", "dom_full"] {
        let snapshot = fixture
            .call(&route, "browser.snapshot", json!({"mode":mode}))
            .await;
        assert_authorized(&snapshot, "baseline framed snapshot");
        let text = snapshot["state_text"].as_str().unwrap();
        assert!(!text.contains("Local admin secret"), "{snapshot}");
        assert!(!text.contains("Nested public child"), "{snapshot}");
        assert!(text.contains("Public embedded text"), "{snapshot}");
        assert!(
            text.contains("embedded frame") && text.contains("needs site permission"),
            "{snapshot}"
        );
        assert_eq!(snapshot["truncated"], true, "{snapshot}");
        let readable = fixture.browser.readable_frames.lock().unwrap();
        assert_eq!(readable.len(), 2);
        assert!(!readable
            .iter()
            .any(|frame| frame.frame_id == "frame-private" || frame.frame_id == "frame-nested"));
        if mode == "ax" {
            assert_eq!(
                text.lines()
                    .filter_map(|line| serde_json::from_str::<Value>(line).ok())
                    .filter(|row| row["ref"].is_string())
                    .count(),
                7
            );
        }
    }
    let mut cards = Vec::new();
    fixture
        .call_answering(
            &route,
            "browser_use",
            json!({"action":"open_grant","origins":[PUBLIC],"hazards":[]}),
            json!({"decision":"allow_conversation"}),
            |question| cards.push(question.clone()),
        )
        .await;
    assert_eq!(cards.len(), 1);
    tokio::time::timeout(Duration::from_secs(2), async {
        while fixture.planes.management.browser_grant_count().await == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(fixture.planes.management.browser_grant_count().await, 1);
    for mode in ["actionable", "ax", "dom_full"] {
        let snapshot = fixture
            .call(&route, "browser.snapshot", json!({"mode":mode}))
            .await;
        assert_authorized(&snapshot, "person-granted framed snapshot");
        let text = snapshot["state_text"].as_str().unwrap();
        assert!(
            text.contains("Local admin secret") && text.contains("Nested public child"),
            "{snapshot}"
        );
        assert!(!text.contains("needs site permission"), "{snapshot}");
        assert_eq!(snapshot["truncated"], false, "{snapshot}");
        if mode == "ax" {
            assert!(!named_ref(&snapshot, "Local admin secret").is_empty());
        }
    }
}

#[tokio::test]
async fn baseline_seeded_legacy_profiles_require_typing_permission_everywhere() {
    let mut fixture = Fixture::new();
    let route = fixture
        .route(Session::primary("c-legacy-history", AGENT).asking())
        .await;
    public_snapshot(&fixture, &route, "https://seen.example").await;
    observed_fixture_login(&fixture, &route, "c-legacy-history", "https://seen.example").await;
    fixture
        .planes
        .browser
        .journal_login_import(
            &route.identity,
            "https://imported.example",
            "transferred",
            Some("chrome"),
            1,
        )
        .await
        .unwrap();
    let export = fixture.planes.browser.journal_export_for_test().await;
    let evidence = cerebellum::browser_signed_in::LoginJournalEvidence::from_export(
        &export,
        AGENT,
        "default",
        "legacy-profile",
    );
    assert_eq!(
        evidence.domains,
        ["seen.example".to_string(), "imported.example".to_string()].into()
    );
    // A first registry lookup after an upgrade identifies an existing profile,
    // but the untimed journal cannot prove that all of its sign-ins are retained.
    fixture
        .signed_in
        .initialize_profile(AGENT, "default", "legacy-profile", false)
        .unwrap();
    for origin in ["https://seen.example", "https://never-signed.example"] {
        let snapshot = public_snapshot(&fixture, &route, origin).await;
        let mut cards = Vec::new();
        let reply = fixture.call_answering(&route,"browser.type",json!({"ref":named_ref(&snapshot,"Text"),"snapshot_id":snapshot["snapshot_id"],"text":"legacy profile"}),json!({"decision":"deny"}),|question|cards.push(question.clone())).await;
        assert_refused(&reply, "incomplete legacy typing");
        assert_eq!(cards.len(), 1);
        assert_authorized(&fixture.call(&route,"browser.click",json!({"ref":named_ref(&snapshot,"Button"),"snapshot_id":snapshot["snapshot_id"],"intent":"ordinary click","severity":{"tier":2,"credential":false,"financial":false}})).await,"legacy ordinary click");
    }
    assert!(fixture
        .signed_in
        .is_signed_in(AGENT, "default", "https://any-other.example"));
}
