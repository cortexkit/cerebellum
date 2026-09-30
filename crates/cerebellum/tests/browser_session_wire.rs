use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::authorization::{ActionGrant, GrantStore, HazardClass, Severity, OBSERVE};
use cerebellum::browser::navigation::{
    classify_flattened_document, BrowserScreenshotObservation, BrowserSnapshotObservation,
    CdpNavigationDriver,
};
use cerebellum::browser::{BrowserPlane, Tracker};
use cerebellum::browser_launch::ExecutableIdentityCheckpoints;
use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
use cerebellum::browser_session::{
    BrowserClickOutcome, BrowserClickPosition, BrowserInputEvent, BrowserSessionLauncher,
    CleanupStage, ClickDriveError, ClickNavigation, ClickPointDriveError, LaunchedBrowser,
    NavigationDriveError, NavigationWait, OwnedBrowserProcess, ProcessControlFailure,
    SessionCleanup,
};
use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
use cerebellum::classification::{
    classify_click, AssociatedFormControlInput, ElementClassificationInput, NodeIdentityInput,
    NonTypeClassificationInput, TargetKind,
};
use cerebellum::coordinate::{TransformInputs, ViewportObservation};
use cerebellum::snapshot_store::{
    AxRecord, BackendNodeIdentity, CommittedDocument, RefRecord, SnapshotKind, SnapshotRef,
};
use cerebellum::{BrowserConfig, BrowserSurface, Planes};
use cerebellum_computer::platform::vocabulary::{
    CapabilityResultValidationError, CapabilityResultViolation,
};
use cerebellum_core::health::HealthState;
use cerebellum_core::identity::RouteIdentity;
use serde_json::{json, Value};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

#[path = "../examples/support/consent_relay.rs"]
mod consent_relay;

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

fn request(corr: u64, name: &str, arguments: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        corr,
        serde_json::to_vec(&json!({"name": name, "arguments": arguments})).unwrap(),
    )
    .unwrap()
}

async fn invoke_existing(planes: &Planes, corr: u64, name: &str, arguments: Value) -> Frame {
    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_tool_request_for_test_with_existing_planes(
        request(corr, name, arguments),
        &tx,
        planes,
    )
    .await
    .unwrap();
    rx.recv().await.unwrap()
}

async fn invoke(planes: &Planes, corr: u64, name: &str, arguments: Value) -> Frame {
    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_tool_request_for_test_with_planes(
        request(corr, name, arguments),
        &tx,
        planes,
    )
    .await
    .unwrap();
    rx.recv().await.unwrap()
}

fn route_identity() -> RouteIdentity {
    RouteIdentity::from_bind(
        &BindIdentity::new("/test/project", "test", "test-session".to_string()),
        &Some(Principal::Direct),
    )
}

async fn grant_browser(planes: &Planes, origin: &str, hazards: Vec<HazardClass>) {
    let question = planes
        .management
        .browser_grant_question_for_test("test-session", vec![origin.to_string()], hazards)
        .await;
    assert!(
        planes
            .management
            .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow"})))
            .await
    );
}

const MANAGEMENT_CHANNEL: u16 = 4;
const MANAGEMENT_EPOCH: u32 = 1;

/// Bind a management route for the same session the tool route uses, able to
/// relay a question to a person, so `browser.open_grant` runs through the
/// production management dispatcher and mints into the grants the browser
/// reads.
async fn bind_management_route(planes: &Planes) {
    let request = ModuleControlRequest::RouteBind {
        route_channel: MANAGEMENT_CHANNEL,
        epoch: MANAGEMENT_EPOCH,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        identity: BindIdentity::new("/test/project", "test", "test-session".to_string()),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": "pj-browser-session-wire",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.open_grant"]
        })),
        scope: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        u64::from(MANAGEMENT_CHANNEL),
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    cerebellum::handle_control_request_for_test_with_bindings(
        frame,
        &writer,
        &planes.health,
        &planes.routes,
    )
    .await
    .expect("the management route binds");
    let reply = replies.recv().await.expect("route.bind receives a reply");
    assert_eq!(reply.header.ty, FrameType::Response);
}

/// Send `browser.open_grant` with exactly `params`, allow the question, and
/// wait until the grant is minted. Returns the `open_grant` reply, whose
/// `severity_ceiling` is the ceiling the minted grant carries.
async fn open_grant_and_allow(planes: &Planes, corr: u64, params: Value) -> Value {
    let before = planes.management.browser_grant_count().await;
    let opening = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        corr,
        serde_json::to_vec(&json!({
            "method": cerebellum::management::OPEN_GRANT,
            "params": params,
        }))
        .unwrap(),
    )
    .unwrap();
    let reply = consent_relay::elicit_and_answer(
        planes,
        opening,
        json!({"decision": "allow"}),
        "browser.open_grant",
    )
    .await
    .expect("the grant request and its question complete");
    assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    tokio::time::timeout(Duration::from_secs(2), async {
        while planes.management.browser_grant_count().await <= before {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the affirmative answer mints a grant");
    reply
}

fn snapshot_observation(
    clicked: bool,
    hazardous: bool,
    cross_site_link: bool,
    document_epoch: u64,
    current_url: &str,
) -> BrowserSnapshotObservation {
    let (scheme, rest) = current_url
        .split_once("://")
        .expect("the wire test page URL has a scheme");
    let authority = rest.split(['/', '?', '#']).next().unwrap();
    let origin = format!("{scheme}://{authority}");
    let mut target = if cross_site_link {
        // A link whose destination is another site: classification requires
        // a higher tier for it than for an ordinary same-site click.
        ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame-main", 42),
            TargetKind::Anchor,
        )
        .destination("https://www.iana.org/domains/example")
    } else {
        ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame-main", 42),
            TargetKind::Button,
        )
    };
    if hazardous {
        target = target
            .form_owner(NodeIdentityInput::new("target", "frame-main", 7))
            .associated_control(
                AssociatedFormControlInput::new(NodeIdentityInput::new("target", "frame-main", 8))
                    .with_tokens(["current-password"]),
            );
    }
    let classification = classify_click(&NonTypeClassificationInput::new(
        document_epoch,
        target,
        origin,
    ))
    .unwrap();
    let heading = if clicked {
        "Click probe after"
    } else {
        "Click probe before"
    };
    BrowserSnapshotObservation {
        records: vec![
            AxRecord {
                depth: 0,
                role: "heading".into(),
                name: heading.into(),
                value: None,
                reference: None,
            },
            AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Sign in".into(),
                value: None,
                reference: Some("e1".into()),
            },
        ],
        dom_text: None,
        refs: vec![RefRecord {
            captured: SnapshotRef::new("e1", "button", "Sign in", 0).unwrap(),
            frame_path: vec!["frame-main".into()],
            backend_identity: Some(BackendNodeIdentity::new("target", "frame-main", 42).unwrap()),
            raw_role: Some("button".into()),
            raw_name: Some("Sign in".into()),
            classification: Ok(Box::new(classification)),
        }],
        ax_truncated: false,
        refs_truncated: false,
    }
}

/// The main frame's committed history, shared between a test and the process
/// it launches, modelled on what Chrome reports through
/// `Page.getNavigationHistory` and `Page.getFrameTree`.
///
/// Page reads and actions check what the browser reports here, not the
/// navigation the module tracked. A double that echoed the tracker would make
/// every check pass for the reason under test, so the test moves the page
/// itself, the way a page's own script or a late redirect would.
///
/// As in Chrome: a cross-document navigation prunes forward history, adds an
/// entry with a new unique id, and loads a new document (a new loader id); a
/// same-document navigation such as a fragment change also adds an entry with
/// a new id but keeps the document and its loader; a traversal back moves the
/// current index to an existing entry and restores that entry's document.
#[derive(Clone)]
struct CommittedPage(Arc<Mutex<PageHistory>>);

struct PageHistory {
    /// `(entry id, url, loader id)` per entry.
    entries: Vec<(i64, String, String)>,
    current: usize,
    next_id: i64,
}

impl Default for CommittedPage {
    fn default() -> Self {
        Self(Arc::new(Mutex::new(PageHistory {
            entries: vec![(1, "about:blank".into(), "loader-1".into())],
            current: 0,
            next_id: 2,
        })))
    }
}

impl CommittedPage {
    fn push(&self, url: &str, new_document: bool) {
        let mut history = self.0.lock().unwrap();
        let id = history.next_id;
        history.next_id += 1;
        let loader = if new_document {
            format!("loader-{id}")
        } else {
            history.entries[history.current].2.clone()
        };
        let keep = history.current + 1;
        history.entries.truncate(keep);
        history.entries.push((id, url.to_string(), loader));
        history.current = keep;
    }

    /// A cross-document navigation commits.
    fn commit(&self, url: &str) {
        self.push(url, true);
    }

    /// A same-document navigation (fragment change) commits.
    fn fragment(&self, url: &str) {
        self.push(url, false);
    }

    /// `history.back()` commits, restoring the previous entry's document as
    /// the back/forward cache does.
    fn back(&self) {
        let mut history = self.0.lock().unwrap();
        history.current -= 1;
    }

    fn url(&self) -> String {
        let history = self.0.lock().unwrap();
        history.entries[history.current].1.clone()
    }

    fn document(&self) -> CommittedDocument {
        let history = self.0.lock().unwrap();
        let (entry_id, url, loader_id) = history.entries[history.current].clone();
        CommittedDocument {
            url,
            entry_id,
            history: history.entries.iter().map(|entry| entry.0).collect(),
            current_index: history.current,
            loader_id,
        }
    }

    fn navigation_history(&self) -> Value {
        let history = self.0.lock().unwrap();
        json!({
            "currentIndex": history.current,
            "entries": history.entries.iter().map(|(id, url, _)| json!({
                "id": id, "url": url, "userTypedURL": url, "title": "", "transitionType": "link"
            })).collect::<Vec<_>>(),
        })
    }

    fn frame_tree(&self) -> Value {
        let document = self.document();
        json!({"frameTree":{"frame":{
            "id": MAIN_FRAME,
            "loaderId": document.loader_id,
            "url": document.url,
            "securityOrigin": "",
            "mimeType": "text/html"
        }}})
    }
}

/// One way a page moves while a read is being captured.
#[derive(Clone)]
enum PageMove {
    Commit(&'static str),
    Back,
}

#[derive(Default)]
struct RecordingLauncher {
    launches: Arc<Mutex<usize>>,
    page: CommittedPage,
    /// Navigations the page commits while a snapshot or screenshot is being
    /// captured, standing for ones that land between the read's
    /// authorization and its return. Consumed by the next capture.
    moves_during_capture: Arc<Mutex<Vec<PageMove>>>,
    effects: Arc<Mutex<Vec<&'static str>>>,
    hazardous_target: bool,
    cross_site_link_target: bool,
    present_error: Option<&'static str>,
    cookie_value: Option<&'static str>,
    cookie_grows_on_poll: bool,
    credential_field_then_clears: bool,
    /// Shared with every process this launcher starts; setting it makes them
    /// all report that the browser has exited, as a crashed browser would.
    exited: Arc<Mutex<bool>>,
}

impl BrowserSessionLauncher for RecordingLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        *self.launches.lock().unwrap() += 1;
        Ok(LaunchedBrowser {
            process: Box::new(RecordingProcess {
                effects: Arc::clone(&self.effects),
                page: self.page.clone(),
                moves_during_capture: Arc::clone(&self.moves_during_capture),
                clicked: false,
                hazardous_target: self.hazardous_target,
                cross_site_link_target: self.cross_site_link_target,
                present_error: self.present_error,
                cookie_value: self.cookie_value,
                cookie_grows_on_poll: self.cookie_grows_on_poll,
                credential_field_then_clears: self.credential_field_then_clears,
                cookie_reads: 0,
                exited: Arc::clone(&self.exited),
            }),
            cleanup: Box::new(RecordingCleanup {
                effects: Arc::clone(&self.effects),
            }),
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::AfterExecOnly,
        })
    }
}

struct RecoveryFailedLauncher;

impl BrowserSessionLauncher for RecoveryFailedLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        Err(json!({
            "outcome": "internal_failure",
            "reason_code": "browser_launch_recovery_failed",
        }))
    }
}

struct UndeclaredReplyLauncher;

impl BrowserSessionLauncher for UndeclaredReplyLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        Err(json!({
            "outcome": "internal_failure",
            "undeclared_at_the_dispatch_site": true,
        }))
    }
}

struct RecordingProcess {
    effects: Arc<Mutex<Vec<&'static str>>>,
    page: CommittedPage,
    moves_during_capture: Arc<Mutex<Vec<PageMove>>>,
    clicked: bool,
    hazardous_target: bool,
    cross_site_link_target: bool,
    present_error: Option<&'static str>,
    cookie_value: Option<&'static str>,
    cookie_grows_on_poll: bool,
    credential_field_then_clears: bool,
    cookie_reads: usize,
    exited: Arc<Mutex<bool>>,
}

impl RecordingProcess {
    fn apply_moves_during_capture(&mut self) {
        for page_move in std::mem::take(&mut *self.moves_during_capture.lock().unwrap()) {
            match page_move {
                PageMove::Commit(url) => self.page.commit(url),
                PageMove::Back => self.page.back(),
            }
        }
    }
}

impl OwnedBrowserProcess for RecordingProcess {
    fn committed_document(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        Ok(self.page.document())
    }

    fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
        self.effects.lock().unwrap().push("Page.bringToFront");
        if let Some(error_text) = self.present_error {
            return Err(NavigationDriveError::CommandFailed {
                error_text: error_text.to_string(),
            });
        }
        self.effects.lock().unwrap().push("Target.activateTarget");
        Ok(())
    }

    fn cookie_names_for_origin(
        &mut self,
        _: &str,
        _: &str,
        _: u64,
    ) -> Result<BTreeSet<String>, NavigationDriveError> {
        self.cookie_reads += 1;
        let fixture_cookie = ("session", self.cookie_value.unwrap_or_default());
        let mut names = BTreeSet::from([fixture_cookie.0.to_string()]);
        if self.cookie_grows_on_poll && self.cookie_reads > 1 {
            names.insert("authenticated".to_string());
        }
        Ok(names)
    }

    fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
        Ok(self.page.url())
    }

    fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
        Ok(self.credential_field_then_clears && self.cookie_reads == 2)
    }

    fn navigate(
        &mut self,
        _: &str,
        _: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.effects.lock().unwrap().push("navigate");
        let now = std::time::Instant::now();
        self.page.commit("https://landed.example/final");
        tracker.url_final = Some("https://landed.example/final".into());
        tracker.load(now);
        tracker.poll_settlement(now + Duration::from_millis(cerebellum::browser::QUIET_MS));
        Ok(())
    }

    fn snapshot_classified(
        &mut self,
        _: &str,
        _: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.effects.lock().unwrap().push("snapshot");
        let observation = snapshot_observation(
            self.clicked,
            self.hazardous_target,
            self.cross_site_link_target,
            document_epoch,
            current_origin,
        );
        self.apply_moves_during_capture();
        Ok(observation)
    }

    fn screenshot(
        &mut self,
        _: &str,
        _: u64,
        _: u64,
        _: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        self.effects.lock().unwrap().push("screenshot");
        let viewport = ViewportObservation::new(
            0,
            TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
        );
        let observation = BrowserScreenshotObservation {
            image_png_b64: ONE_BY_ONE_PNG_B64.into(),
            before: viewport,
            after: viewport,
            invalidation_observed: false,
        };
        self.apply_moves_during_capture();
        Ok(observation)
    }

    fn click_classified(
        &mut self,
        _: &str,
        _: &BackendNodeIdentity,
        _: u64,
        _: &str,
        _: Option<&cerebellum::classification::NonTypeClassificationRecord>,
        _: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let position = BrowserClickPosition {
            x_css: 12.0,
            y_css: 24.0,
        };
        self.effects.lock().unwrap().push("input_press");
        input_dispatched(BrowserInputEvent::Press(position));
        self.effects.lock().unwrap().push("input_release");
        input_dispatched(BrowserInputEvent::Release(position));
        self.clicked = true;
        Ok(BrowserClickOutcome::Clicked {
            position,
            navigation: ClickNavigation::NoneObserved { window_ms: 100 },
        })
    }

    fn generation_matches(&self) -> bool {
        !*self.exited.lock().unwrap()
    }

    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        self.effects.lock().unwrap().push("graceful");
        Ok(())
    }

    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        self.effects.lock().unwrap().push("grace_wait");
        Ok(false)
    }

    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        self.effects.lock().unwrap().push("force");
        Ok(())
    }

    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        self.effects.lock().unwrap().push("reap");
        Ok(())
    }
}

struct RecordingCleanup {
    effects: Arc<Mutex<Vec<&'static str>>>,
}

impl SessionCleanup for RecordingCleanup {
    fn after_reap(
        &mut self,
    ) -> Result<cerebellum::browser_session::SessionCleanupOutcome, CleanupStage> {
        self.effects.lock().unwrap().push("cleanup");
        Ok(cerebellum::browser_session::SessionCleanupOutcome::Complete)
    }
}

/// Launch and put the page at `{origin}/page`: committed in the browser double
/// and recorded in the module's tracker, so the two agree as they do after a
/// navigation the module watched.
async fn launch_at(planes: &Planes, page: &CommittedPage, origin: &str) {
    let launched = invoke(planes, 1, "browser.launch", json!({})).await;
    let launched: Value = serde_json::from_slice(&launched.body).unwrap();
    assert_eq!(launched["outcome"], "launched", "{launched}");
    page.commit(&format!("{origin}/page"));
    planes
        .browser
        .same_document_url(
            &route_identity(),
            &format!("{origin}/page"),
            cerebellum::snapshot_store::SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();
}

#[test]
fn real_manifest_path_advertises_exactly_the_configured_wire_surface() {
    fn names(configured: bool) -> Vec<String> {
        let surface = if configured {
            BrowserSurface::Available(config())
        } else {
            BrowserSurface::NotConfigured
        };
        let manifest =
            cerebellum::serialize_manifest_with_browser_configuration("cerebellum", &surface);
        manifest["provides"]
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["role"] == "tool_provider")
            .unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str().map(str::to_string))
            .filter(|name| name.starts_with("browser."))
            .collect()
    }

    assert_eq!(
        names(true),
        [
            "browser.launch",
            "browser.status",
            "browser.close",
            "browser.navigate",
            "browser.snapshot",
            "browser.click",
            // Both admitted after being driven through this wire path against
            // Chrome 151, THROUGH their authorization gates.
            "browser.screenshot",
            // click_point addresses a retained screenshot, so its risk is the
            // pixel-to-css mapping rather than the dispatch: a click that lands
            // somewhere plausible is worse than one that fails, because nothing
            // reports it. A page listener recorded (600,476) css where the
            // mapping predicts 476.75 -- truncation against rounding. A scale
            // error, the failure this guards, would have shown as a factor.
            "browser.click_point",
        ]
        .map(str::to_string)
    );
    assert!(names(false).is_empty());
}

#[tokio::test]
async fn wire_launch_reaches_ready_refuses_a_duplicate_and_closes_after_reap() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());

    let launched = invoke(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(launched.header.ty, FrameType::Response);
    let launched: Value = serde_json::from_slice(&launched.body).unwrap();
    assert_eq!(launched["outcome"], "launched");
    assert_eq!(launched["profile_disposition"], "durable");
    assert_eq!(
        launched["executable_identity_checkpoints"],
        "after_exec_only"
    );
    assert!(launched["browser_session_id"]
        .as_str()
        .is_some_and(|id| !id.is_empty()));
    assert_eq!(launched["lease"]["idle_timeout_ms"], 30_000);
    assert!(launched["lease"]["idle_expires_at"]
        .as_str()
        .is_some_and(|value| value.ends_with('Z') && value.contains('.')));

    let navigated = invoke(
        &planes,
        11,
        "browser.navigate",
        json!({
            "url": "https://requested.example/",
            "intent": "follow the redirect",
            "wait": "settle",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    let navigated: Value = serde_json::from_slice(&navigated.body).unwrap();
    // Refused for want of a grant, which is what a caller gets today: nothing in
    // production mints an ActionGrant, so the store this plane is built with is
    // empty and covers nothing. The capability is wired and unreachable until
    // consent has a path, and that is the intended order rather than a gap.
    //
    // This assertion previously read "ok". It passed because the authorization
    // gate was governed by a bool that `derive(Default)` set to false, so wire
    // navigation was SERVED with no grant check at all -- the test was
    // recording the bypass rather than the policy.
    //
    // The successful-navigation behaviour it used to cover is asserted in
    // b1_s3_browser.rs, where a grant can be installed directly:
    // navigation_reports_the_browser_landing_url_instead_of_the_request makes
    // the same url_final assertion against a plane that holds authority.
    assert_eq!(navigated["outcome"], "authorization_denied", "{navigated}");
    assert_eq!(navigated["detail"]["reason"], "no_grant", "{navigated}");

    // Implemented and deliberately not admitted. These are NOT unknown: naming
    // them that way tells a caller to stop asking for something we built and
    // withheld on purpose, and invites a bug report for a decision.
    for (corr, unavailable) in [(16, "browser.wait_for"), (17, "browser.type")] {
        let refused = invoke(&planes, corr, unavailable, json!({})).await;
        let refused: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(refused["code"], "capability_not_admitted", "{refused}");
    }

    // A name this build genuinely does not have stays unknown_method, which is
    // the contrast that makes the distinction worth drawing at all.
    let invented = invoke(&planes, 18, "browser.teleport", json!({})).await;
    let invented: Value = serde_json::from_slice(&invented.body).unwrap();
    assert_eq!(invented["code"], "unknown_method", "{invented}");

    // browser.screenshot is admitted, so it must REACH the handler rather than
    // be refused by name. With no grant installed it is refused by its
    // AUTHORIZATION gate, which is a different fact from "this module does not
    // serve that" -- and asserting the reason rather than merely that it
    // errored, because an unknown method also errors.
    let attempted = invoke(&planes, 15, "browser.screenshot", json!({})).await;
    let attempted: Value = serde_json::from_slice(&attempted.body).unwrap();
    assert_ne!(attempted["code"], "unknown_method", "{attempted}");
    // EMPTY, and this is the load-bearing half of the refusal above: the
    // authorization gate runs before anything reaches the browser, so a
    // navigation refused for want of a grant leaves no effect behind. An
    // assertion that the caller got an error would still pass if the page had
    // been navigated and the error raised afterwards.
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "a navigation refused for want of a grant still reached the browser: {:?}",
        launcher.effects.lock().unwrap()
    );

    let duplicate = invoke(&planes, 2, "browser.launch", json!({})).await;
    let duplicate: Value = serde_json::from_slice(&duplicate.body).unwrap();
    assert_eq!(duplicate["outcome"], "browser_session_exists");
    assert_eq!(
        duplicate["browser_session_id"],
        launched["browser_session_id"]
    );
    assert_eq!(*launcher.launches.lock().unwrap(), 1);

    let status = invoke(&planes, 3, "browser.status", json!({})).await;
    let status: Value = serde_json::from_slice(&status.body).unwrap();
    assert_eq!(status["outcome"], "ready");
    assert!(status.get("context").is_none());
    assert!(status.get("session").is_none());
    assert!(status.get("profile_uuid").is_none());

    let deadline = planes
        .sessions
        .lease_deadline_for_test("test-session")
        .unwrap();
    let rejected = invoke(&planes, 31, "browser.status", json!({"unexpected": true})).await;
    let rejected: Value = serde_json::from_slice(&rejected.body).unwrap();
    assert_eq!(rejected["outcome"], "invalid_request");
    assert_eq!(
        planes.sessions.lease_deadline_for_test("test-session"),
        Some(deadline),
        "request validation failure renewed the lease"
    );

    let closed = invoke(
        &planes,
        4,
        "browser.close",
        json!({"browser_session_id": launched["browser_session_id"]}),
    )
    .await;
    let closed: Value = serde_json::from_slice(&closed.body).unwrap();
    assert_eq!(closed["outcome"], "closed");
    for body in [&launched, &status, &closed] {
        assert!(body.get("profile_uuid").is_none());
        assert!(body.get("profile_name").is_none());
        assert!(body.get("session_kind_effective").is_none());
    }
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        // No "navigate": the navigation above was refused for want of a grant
        // before it reached the browser. This assertion is about the teardown
        // ladder, which is unaffected.
        ["graceful", "grace_wait", "force", "reap", "cleanup"]
    );
    let repeated = invoke(
        &planes,
        5,
        "browser.close",
        json!({"browser_session_id": launched["browser_session_id"]}),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&repeated.body).unwrap()["outcome"],
        "closed"
    );
    let unknown = invoke(
        &planes,
        6,
        "browser.close",
        json!({"browser_session_id": "browser-session-unknown"}),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&unknown.body).unwrap()["outcome"],
        "browser_session_not_found"
    );
    // Five, not six: the refused navigation contributed no effect.
    assert_eq!(launcher.effects.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn wire_snapshot_requires_a_grant_for_the_current_page_origin_before_cdp() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://page.example").await;

    let no_grant = invoke(&planes, 20, "browser.snapshot", json!({"mode": "ax"})).await;
    let no_grant: Value = serde_json::from_slice(&no_grant.body).unwrap();
    assert_eq!(no_grant["outcome"], "authorization_denied", "{no_grant}");
    assert_eq!(no_grant["detail"]["reason"], "no_grant", "{no_grant}");
    assert!(launcher.effects.lock().unwrap().is_empty());

    grant_browser(&planes, "https://other.example", Vec::new()).await;
    grant_browser(&planes, "https://second-other.example", Vec::new()).await;
    let wrong_origin = invoke(&planes, 21, "browser.snapshot", json!({"mode": "ax"})).await;
    let wrong_origin: Value = serde_json::from_slice(&wrong_origin.body).unwrap();
    assert_eq!(
        wrong_origin["outcome"], "authorization_denied",
        "{wrong_origin}"
    );
    assert_eq!(
        wrong_origin["detail"]["reason"], "origin_scope",
        "{wrong_origin}"
    );
    // Compared as a set: the list follows grant-id order, and minted grant ids
    // come from a process-wide counter shared with every other test in this
    // binary, so `...-9` and `...-10` can sort either way round.
    let mut granted_origins: Vec<String> =
        serde_json::from_value(wrong_origin["detail"]["granted_origins"].clone()).unwrap();
    granted_origins.sort();
    assert_eq!(
        granted_origins,
        ["https://other.example", "https://second-other.example"],
        "the origin-scope refusal must name every severity-covering grant: {wrong_origin}"
    );
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "a refused snapshot reached CDP: {:?}",
        launcher.effects.lock().unwrap()
    );
}

#[tokio::test]
async fn wire_snapshot_mints_the_ref_that_wire_click_dispatches() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(
        &planes,
        "https://page.example",
        vec![HazardClass::CredentialFormSubmit],
    )
    .await;
    launch_at(&planes, &launcher.page, "https://page.example").await;

    let before = invoke(&planes, 30, "browser.snapshot", json!({"mode": "ax"})).await;
    let before: Value = serde_json::from_slice(&before.body).unwrap();
    assert_eq!(before["outcome"], "ok", "{before}");
    assert!(
        before["content"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe before")),
        "{before}"
    );
    let snapshot_id = before["snapshot_id"].as_str().unwrap();
    let reference = before["refs"][0]["ref"].as_str().unwrap();

    let clicked = invoke(
        &planes,
        31,
        "browser.click",
        json!({
            "ref": reference,
            "snapshot_id": snapshot_id,
            "intent": "exercise the snapshot ref",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot", "input_press", "input_release"]
    );

    let after = invoke(&planes, 32, "browser.snapshot", json!({"mode": "ax"})).await;
    let after: Value = serde_json::from_slice(&after.body).unwrap();
    assert!(
        after["content"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe after")),
        "{after}"
    );
}

#[tokio::test]
async fn wire_click_without_a_covering_grant_dispatches_no_input() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            Arc::clone(&planes.lease_clock),
            config().navigation_settle_deadline_ms,
        )
        .with_grants_installed(GrantStore::new([ActionGrant::new(
            "snapshot-only",
            1,
            "test-session",
            Severity::new(OBSERVE, false, false),
            ["https://page.example"],
        )])),
    );
    launch_at(&planes, &launcher.page, "https://page.example").await;

    let snapshot = invoke(&planes, 40, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke(
        &planes,
        41,
        "browser.click",
        json!({
            "ref": snapshot["refs"][0]["ref"],
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "must remain refused",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "authorization_denied", "{clicked}");
    // The conversation holds a grant, just one whose ceiling is below a click,
    // so the refusal says the severity is short rather than that no grant
    // exists.
    assert_eq!(
        clicked["detail"]["reason"], "grant_severity_insufficient",
        "{clicked}"
    );
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot"],
        "a refused click dispatched input"
    );
}

/// A grant for the page at the default ceiling cannot admit a click that
/// classifies higher. The refusal must name the severity it needs, and
/// opening a grant with exactly the arguments the refusal names must make the
/// same click succeed; a remedy that leaves the outcome unchanged sends the
/// caller round the same loop forever.
#[tokio::test]
async fn wire_click_above_the_grant_ceiling_names_the_severity_and_the_named_grant_admits_it() {
    let launcher = Arc::new(RecordingLauncher {
        cross_site_link_target: true,
        ..RecordingLauncher::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    bind_management_route(&planes).await;
    // No hazards and no tier: the ordinary browsing grant, ceiling tier 2.
    open_grant_and_allow(
        &planes,
        60,
        json!({"origins": ["https://page.example"], "hazards": []}),
    )
    .await;
    launch_at(&planes, &launcher.page, "https://page.example").await;

    let snapshot = invoke(&planes, 61, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let click = json!({
        "ref": snapshot["refs"][0]["ref"],
        "snapshot_id": snapshot["snapshot_id"],
        "intent": "follow the cross-site link",
        "severity": {"tier": 2, "credential": false, "financial": false}
    });

    // Asserted on the wire reply: an undeclared field or reason would have
    // been withheld by result-schema enforcement instead of reaching here.
    let refused = invoke_existing(&planes, 62, "browser.click", click.clone()).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(
        refused["detail"]["reason"], "grant_severity_insufficient",
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["required"],
        json!({"tier": 4, "credential": false, "financial": false}),
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["granted_ceilings"],
        json!([{"tier": 2, "credential": false, "financial": false}]),
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://page.example",
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["grant_request"],
        json!({"origins": ["https://page.example"], "severity_tier": 4, "hazards": []}),
        "{refused}"
    );
    assert_eq!(
        refused["remedy"],
        "call browser.open_grant with the arguments in detail.grant_request, then retry",
        "{refused}"
    );
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot"],
        "a refused click dispatched input"
    );

    // Both the source and the declared landing origin must be authorized.
    open_grant_and_allow(&planes, 63, refused["detail"]["grant_request"].clone()).await;
    let landing = invoke_existing(&planes, 64, "browser.click", click.clone()).await;
    let landing: Value = serde_json::from_slice(&landing.body).unwrap();
    assert_eq!(landing["outcome"], "authorization_denied", "{landing}");
    assert_eq!(
        landing["detail"]["attempted_origin"],
        "https://www.iana.org"
    );
    open_grant_and_allow(&planes, 65, landing["detail"]["grant_request"].clone()).await;
    let clicked = invoke_existing(&planes, 66, "browser.click", click).await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot", "input_press", "input_release"]
    );
}

/// With no grant at all, `no_grant` names the origin and severity a grant
/// must cover, and opening exactly that grant admits the retry. A read needs
/// only tier 1, but a grant without hazards is never minted below compose, so
/// the request names tier 2: the ceiling the grant it opens really carries.
#[tokio::test]
async fn wire_no_grant_names_the_origin_and_severity_and_the_named_grant_admits_it() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    bind_management_route(&planes).await;
    launch_at(&planes, &launcher.page, "https://page.example").await;

    let refused = invoke_existing(&planes, 70, "browser.snapshot", json!({})).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(refused["detail"]["reason"], "no_grant", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://page.example",
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["required"],
        json!({"tier": 1, "credential": false, "financial": false}),
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["grant_request"],
        json!({"origins": ["https://page.example"], "severity_tier": 2, "hazards": []}),
        "{refused}"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());

    let opened =
        open_grant_and_allow(&planes, 71, refused["detail"]["grant_request"].clone()).await;
    assert_eq!(
        opened["severity_ceiling"]["tier"], refused["detail"]["grant_request"]["severity_tier"],
        "the refusal named a tier the grant is not minted at: {opened}"
    );
    let snapshot = invoke_existing(&planes, 72, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
}

/// The opaque origin `null` names no site, so `browser.open_grant` refuses it
/// as an invalid request before any question reaches a person: approving it
/// would be consent to nothing identifiable, and the grant would match every
/// about:blank, data: and sandboxed page at once.
#[tokio::test]
async fn wire_open_grant_refuses_the_opaque_null_origin_without_asking_a_person() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    bind_management_route(&planes).await;
    let opening = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        80,
        serde_json::to_vec(&json!({
            "method": cerebellum::management::OPEN_GRANT,
            "params": {"origins": ["null"], "hazards": []},
        }))
        .unwrap(),
    )
    .unwrap();
    let (writer, mut frames) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(opening, &writer, &planes)
        .await
        .expect("the grant request is served");
    drop(writer);

    let mut replies = Vec::new();
    while let Ok(Some(frame)) =
        tokio::time::timeout(Duration::from_millis(300), frames.recv()).await
    {
        // A question to a person travels as a reverse request on the route.
        assert_ne!(
            frame.header.ty,
            FrameType::Request,
            "a question was put to a person for a null-origin grant"
        );
        replies.push(serde_json::from_slice::<Value>(&frame.body).unwrap());
    }
    assert_eq!(replies.len(), 1, "{replies:?}");
    let reply = &replies[0];
    assert_eq!(reply["outcome"], "invalid_request", "{reply}");
    assert_eq!(
        reply["detail"],
        json!({"field": "origins", "reason_code": "unsupported_value", "value": "null"}),
        "{reply}"
    );
    assert_eq!(planes.management.browser_grant_count().await, 0);
}

/// A page with an opaque origin (the fresh about:blank a launch starts on)
/// cannot be granted, so the refusal offers no grant arguments and tells the
/// caller to go to an http(s) page instead. Offering `origins: ["null"]` would
/// send the caller to a grant `browser.open_grant` refuses.
#[tokio::test]
async fn wire_snapshot_on_an_opaque_origin_page_says_to_navigate_and_offers_no_grant() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    let launched = invoke(&planes, 1, "browser.launch", json!({})).await;
    let launched: Value = serde_json::from_slice(&launched.body).unwrap();
    assert_eq!(launched["outcome"], "launched", "{launched}");
    assert_eq!(launcher.page.url(), "about:blank");

    let refused = invoke_existing(&planes, 81, "browser.snapshot", json!({})).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(refused["detail"]["attempted_origin"], "null", "{refused}");
    assert!(
        refused["detail"].get("grant_request").is_none(),
        "{refused}"
    );
    assert_eq!(
        refused["remedy"],
        "no grant can name detail.attempted_origin; navigate to an http or https page, then retry",
        "{refused}"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());
}

fn planes_with_installed_grants(
    launcher: &Arc<RecordingLauncher>,
    grants: Vec<ActionGrant>,
) -> Planes {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            Arc::clone(&planes.lease_clock),
            config().navigation_settle_deadline_ms,
        )
        .with_grants_installed(GrantStore::new(grants)),
    );
    planes
}

async fn click_cross_site_link(planes: &Planes, corr: u64) -> Value {
    let snapshot = invoke(planes, corr, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke(
        planes,
        corr + 1,
        "browser.click",
        json!({
            "ref": snapshot["refs"][0]["ref"],
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "follow the cross-site link",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    serde_json::from_slice(&clicked.body).unwrap()
}

/// Severity is checked before origin. A grant that reaches the severity but
/// names another origin is still an origin-scope refusal; when no grant
/// reaches the severity, the severity refusal names the attempted origin in
/// its grant request, so the one grant it describes fixes both.
#[tokio::test]
async fn wire_click_origin_mismatch_at_sufficient_severity_stays_origin_scope() {
    let launcher = Arc::new(RecordingLauncher {
        cross_site_link_target: true,
        ..RecordingLauncher::default()
    });
    let snapshot_grant = ActionGrant::new(
        "snapshot-only",
        1,
        "test-session",
        Severity::new(OBSERVE, false, false),
        ["https://page.example"],
    );

    let planes = planes_with_installed_grants(
        &launcher,
        vec![
            snapshot_grant.clone(),
            ActionGrant::new(
                "durable-elsewhere",
                1,
                "test-session",
                Severity::new(4, false, false),
                ["https://other.example"],
            ),
        ],
    );
    launch_at(&planes, &launcher.page, "https://page.example").await;
    let clicked = click_cross_site_link(&planes, 80).await;
    assert_eq!(clicked["outcome"], "authorization_denied", "{clicked}");
    assert_eq!(clicked["detail"]["reason"], "origin_scope", "{clicked}");
    assert_eq!(
        clicked["detail"]["granted_origins"],
        json!(["https://other.example"]),
        "{clicked}"
    );

    let planes = planes_with_installed_grants(
        &launcher,
        vec![
            snapshot_grant,
            ActionGrant::new(
                "compose-elsewhere",
                1,
                "test-session",
                Severity::new(2, false, false),
                ["https://other.example"],
            ),
        ],
    );
    launch_at(&planes, &launcher.page, "https://page.example").await;
    let clicked = click_cross_site_link(&planes, 90).await;
    assert_eq!(
        clicked["detail"]["reason"], "grant_severity_insufficient",
        "{clicked}"
    );
    assert_eq!(
        clicked["detail"]["grant_request"],
        json!({"origins": ["https://page.example"], "severity_tier": 4, "hazards": []}),
        "{clicked}"
    );
}

#[tokio::test]
async fn wire_click_names_an_undisclosed_target_hazard_before_input() {
    let launcher = Arc::new(RecordingLauncher {
        hazardous_target: true,
        ..RecordingLauncher::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            Arc::clone(&planes.lease_clock),
            config().navigation_settle_deadline_ms,
        )
        .with_grants_installed(GrantStore::new([ActionGrant::new(
            "hazard-incomplete",
            1,
            "test-session",
            Severity::new(4, true, true),
            ["https://page.example"],
        )
        .with_disclosed_hazards([HazardClass::FinancialFormSubmit])])),
    );
    launch_at(&planes, &launcher.page, "https://page.example").await;

    let snapshot = invoke(&planes, 50, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke(
        &planes,
        51,
        "browser.click",
        json!({
            "ref": snapshot["refs"][0]["ref"],
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "must remain refused",
            "severity": {"tier": 4, "credential": true, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "hazard_not_disclosed", "{clicked}");
    assert_eq!(
        clicked["detail"]["missing_hazard"], "credential_form_submit",
        "{clicked}"
    );
    // The existing grant discloses only the financial hazard, so the grant
    // that admits this click names the credential hazard it lacks.
    assert_eq!(
        clicked["detail"]["grant_request"],
        json!({"origins": ["https://page.example"], "severity_tier": 4, "hazards": ["credential_form_submit"]}),
        "{clicked}"
    );
    assert_eq!(
        clicked["remedy"],
        "call browser.open_grant with the arguments in detail.grant_request, then retry",
        "{clicked}"
    );
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot"],
        "hazard refusal dispatched input"
    );
}

#[tokio::test]
async fn wire_launch_withholds_undeclared_launcher_reply_at_the_dispatch_site() {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(UndeclaredReplyLauncher));

    let response = invoke(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(response.header.ty, FrameType::Error);
    let error: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(error.code, "computer_result_schema_violation");
    assert!(error.message.contains("undeclared_at_the_dispatch_site"));
}

#[test]
fn browser_control_outcome_vocabularies_reject_undeclared_words() {
    for capability_id in ["browser.launch", "browser.status", "browser.close"] {
        let error = cerebellum::browser::validate_browser_result(
            capability_id,
            &json!({"outcome": "new_undeclared_outcome"}),
        )
        .expect_err("an undeclared browser-control outcome must be refused");
        assert!(matches!(
            error,
            CapabilityResultValidationError::ReplyViolations {
                ref violations,
                ..
            } if violations == &[CapabilityResultViolation::EnumMismatch {
                path: "$.outcome".into(),
            }]
        ));
    }
}

#[tokio::test]
async fn failed_startup_recovery_refuses_launch_while_health_stays_answerable() {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(RecoveryFailedLauncher));

    let response = invoke(&planes, 1, "browser.launch", json!({})).await;
    let body: Value = serde_json::from_slice(&response.body).unwrap();

    assert_eq!(
        body,
        json!({
            "outcome": "internal_failure",
            "reason_code": "browser_launch_recovery_failed",
        })
    );
    assert!(matches!(
        planes.health.report(),
        subc_protocol::session::ModuleControlResponse::HealthCheck { .. }
    ));
}

#[tokio::test]
async fn route_unbind_runs_the_same_reap_then_cleanup_ladder() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    let launched = invoke(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&launched.body).unwrap()["outcome"],
        "launched"
    );

    let goodbye = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Goodbye,
        Flags::new(false, Priority::Passive, false),
        9,
        3,
        2,
        Vec::new(),
    )
    .unwrap();
    let (tx, _rx) = mpsc::channel(1);
    assert!(cerebellum::handle_frame_for_test(goodbye, &tx, &planes)
        .await
        .unwrap());
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["graceful", "grace_wait", "force", "reap", "cleanup"]
    );
}

#[tokio::test]
async fn all_browser_controls_share_the_existing_invalid_request_shape() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    for (corr, operation) in [
        (1, "browser.launch"),
        (2, "browser.status"),
        (3, "browser.close"),
    ] {
        let response = invoke(&planes, corr, operation, Value::Null).await;
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body,
            cerebellum::capability::invalid_request("$", "wrong_type")
        );
    }
    for (corr, operation, arguments) in [
        (4, "browser.launch", json!({"z": 1, "a": 2})),
        (5, "browser.status", json!({"z": 1, "a": 2})),
        (
            6,
            "browser.close",
            json!({"browser_session_id": "opaque", "z": 1, "a": 2}),
        ),
    ] {
        let response = invoke(&planes, corr, operation, arguments).await;
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(
            body,
            cerebellum::capability::invalid_request("a", "unknown_field")
        );
    }
}

#[tokio::test]
async fn operation_authority_refusal_precedes_parameter_validation_and_effects() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    cerebellum::install_browser_test_bind(&planes.routes, 9, 3, &[]);

    let response = invoke_existing(&planes, 1, "browser.launch", Value::Null).await;
    assert_eq!(response.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "authorization_denied", "{body}");
    assert_eq!(body["reason"], "operation_not_granted", "{body}");
    let valid_response = invoke_existing(&planes, 2, "browser.launch", json!({})).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&valid_response.body).unwrap()["reason"],
        "operation_not_granted"
    );
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
    assert_eq!(
        planes.sessions.status(
            "test-session",
            planes.lease_clock.as_ref(),
            std::time::SystemTime::UNIX_EPOCH,
        )["outcome"],
        "no_session"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn missing_operation_authority_has_no_launch_effects() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    cerebellum::install_browser_test_bind(&planes.routes, 9, 3, &[]);

    let response = invoke_existing(&planes, 1, "browser.launch", json!({})).await;
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "authorization_denied", "{body}");
    assert_eq!(body["reason"], "operation_not_granted", "{body}");
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn project_root_compatibility_fallback_cannot_reach_profile_launch() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    cerebellum::install_browser_compatibility_test_bind(&planes.routes, 9, 3);

    let response = invoke_existing(&planes, 1, "browser.launch", json!({})).await;
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "authorization_denied", "{body}");
    assert_eq!(body["reason"], "agent_project_id_unattested", "{body}");
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

/// Open the data-plane route `invoke_existing` uses through a real
/// `route.bind` control frame carrying exactly `admission_facts`, and expect
/// the bind to be accepted.
async fn bind_tool_route_with_facts(planes: &Planes, admission_facts: Value) {
    let reply = send_tool_route_bind(planes, admission_facts).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
}

/// Send a real `route.bind` for the data-plane route `invoke_existing` uses,
/// carrying exactly `admission_facts`, and return the control reply.
async fn send_tool_route_bind(planes: &Planes, admission_facts: Value) -> Frame {
    let request = ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        },
        identity: BindIdentity::new("/caller/chosen/project", "test", "test-session".to_string()),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: None,
        admission_facts: Some(admission_facts),
        scope: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        9,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    cerebellum::handle_control_request_for_test_with_bindings(
        frame,
        &writer,
        &planes.health,
        &planes.routes,
    )
    .await
    .expect("the control request is handled");
    replies.recv().await.expect("route.bind receives a reply")
}

/// Bind a route with `admission_facts` and call `browser.launch` on it,
/// returning the reply body and how many browsers were launched.
async fn launch_on_route_with_facts(admission_facts: Value) -> (Value, usize) {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    bind_tool_route_with_facts(&planes, admission_facts).await;
    let response = invoke_existing(&planes, 1, "browser.launch", json!({})).await;
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    let launches = *launcher.launches.lock().unwrap();
    (body, launches)
}

/// Admission facts are read only at the root of the stamped object, under one
/// exact camelCase name each.
///
/// These facts pick the durable profile a launch opens and the controls a
/// route may call, so a fact stamped anywhere else, whether nested under
/// another object or spelled another way, must refuse the launch exactly as the
/// same bind with that fact absent does. Driven through a real `route.bind`
/// and `browser.launch`, because the bind path is where the facts are read.
#[tokio::test]
async fn a_fact_outside_its_root_camel_case_key_refuses_a_launch_as_if_absent() {
    let operations = json!(["browser.launch"]);

    let (absent_project, launches) = launch_on_route_with_facts(json!({
        "sessionKind": "primary",
        "browserControlOperations": operations,
    }))
    .await;
    assert_eq!(absent_project["reason"], "agent_project_id_unattested");
    assert_eq!(launches, 0);
    for (shape, facts) in [
        (
            "nested under accepted",
            json!({"sessionKind": "primary", "browserControlOperations": operations,
                   "accepted": {"agentProjectId": "pj-misplaced"}}),
        ),
        (
            "nested under bind",
            json!({"sessionKind": "primary", "browserControlOperations": operations,
                   "bind": {"agentProjectId": "pj-misplaced"}}),
        ),
        (
            "nested under identity",
            json!({"sessionKind": "primary", "browserControlOperations": operations,
                   "identity": {"agentProjectId": "pj-misplaced"}}),
        ),
        (
            "spelled agent_project_id",
            json!({"sessionKind": "primary", "browserControlOperations": operations,
                   "agent_project_id": "pj-misplaced"}),
        ),
        (
            "spelled projectId",
            json!({"sessionKind": "primary", "browserControlOperations": operations,
                   "projectId": "pj-misplaced"}),
        ),
    ] {
        let (body, launches) = launch_on_route_with_facts(facts).await;
        assert_eq!(body, absent_project, "{shape}");
        assert_eq!(launches, 0, "{shape}");
    }

    let (absent_kind, launches) = launch_on_route_with_facts(json!({
        "agentProjectId": "pj-accepted",
        "browserControlOperations": operations,
    }))
    .await;
    assert_eq!(absent_kind["reason"], "session_kind_unattested");
    assert_eq!(launches, 0);
    let (body, launches) = launch_on_route_with_facts(json!({
        "agentProjectId": "pj-accepted",
        "session_kind": "primary",
        "browserControlOperations": operations,
    }))
    .await;
    assert_eq!(body, absent_kind, "spelled session_kind");
    assert_eq!(launches, 0);

    let (absent_operations, launches) = launch_on_route_with_facts(json!({
        "agentProjectId": "pj-accepted",
        "sessionKind": "primary",
    }))
    .await;
    assert_eq!(absent_operations["reason"], "operation_not_granted");
    assert_eq!(launches, 0);
    let (body, launches) = launch_on_route_with_facts(json!({
        "agentProjectId": "pj-accepted",
        "sessionKind": "primary",
        "accepted": {"browserControlOperations": operations},
    }))
    .await;
    assert_eq!(body, absent_operations, "nested browserControlOperations");
    assert_eq!(launches, 0);
}

/// The three root facts beside a key this module does not know launch
/// normally: an unknown fact is ignored, never refused, so a carrier can stamp
/// facts for other consumers on the same route.
#[tokio::test]
async fn an_unknown_top_level_fact_beside_the_root_facts_still_launches() {
    let (body, launches) = launch_on_route_with_facts(json!({
        "agentProjectId": "pj-accepted",
        "sessionKind": "primary",
        "browserControlOperations": ["browser.launch"],
        "ck.project-trust/v1": {"projectId": "pj-other-schema", "trusted": true},
    }))
    .await;
    assert_eq!(body["outcome"], "launched", "{body}");
    assert_eq!(body["profile_disposition"], "durable", "{body}");
    assert_eq!(launches, 1);
}

/// A capability scope stamped where it is no longer read refuses the bind.
///
/// The scope is the one fact that restricts: absent, a route gets the
/// permissive default. So a scope under a retired spelling, or nested under an
/// object it used to be read from, must not be ignored the way an unknown fact
/// is, because ignoring it would admit the route unrestricted. The bind is
/// refused by name with the offending key, and the route it named serves
/// nothing afterwards.
#[tokio::test]
async fn a_capability_scope_in_a_retired_place_refuses_the_bind() {
    let base = json!({
        "agentProjectId": "pj-accepted",
        "sessionKind": "primary",
        "browserControlOperations": ["browser.launch"],
    });
    let mut cases = Vec::new();
    for name in [
        "effective_capability_scope",
        "capabilityScope",
        "capability_scope",
    ] {
        let mut facts = base.clone();
        facts[name] = json!(["browser.status"]);
        cases.push((name.to_string(), facts));
    }
    for container in ["accepted", "bind", "bind_identity", "identity"] {
        for name in [
            "effectiveCapabilityScope",
            "effective_capability_scope",
            "capabilityScope",
            "capability_scope",
        ] {
            let mut facts = base.clone();
            facts[container] = json!({ name: ["browser.status"] });
            cases.push((format!("{container}.{name}"), facts));
        }
    }

    for (key, facts) in cases {
        let launcher = Arc::new(RecordingLauncher::default());
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config()),
            cerebellum::JournalPersistence::Isolated,
        );
        planes.launch_service = Some(launcher.clone());

        let reply = send_tool_route_bind(&planes, facts).await;
        assert_eq!(reply.header.ty, FrameType::Error, "{key}");
        let error: subc_protocol::ErrorBody = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(error.code, "admission_fact_misspelled", "{key}");
        assert_eq!(
            error.detail.as_ref().map(|detail| &detail["key"]),
            Some(&json!(key)),
            "{key}"
        );

        let response = invoke_existing(&planes, 1, "browser.launch", json!({})).await;
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"], "route_not_bound", "{key}: {body}");
        assert_eq!(*launcher.launches.lock().unwrap(), 0, "{key}");
    }

    // The same facts with the scope under its one read name bind normally, so
    // the refusal above is about where the scope was written.
    let mut facts = base.clone();
    facts["effectiveCapabilityScope"] = json!(["browser.launch"]);
    let (body, launches) = launch_on_route_with_facts(facts).await;
    assert_eq!(body["outcome"], "launched", "{body}");
    assert_eq!(launches, 1);
}

/// A route opened without the admission carrier is refused with the reason
/// and remedy that say so, through the declared reply contract.
///
/// A daemon opens a route with no admission facts whenever it is not
/// configured to stamp them for the caller that opened it, which makes this
/// the refusal the session caller meets first on a misconfigured daemon. (Any
/// other caller is refused earlier, as not admitted to act in a conversation.)
/// Driven through the real dispatch for all
/// three control operations, because the refusal sits in front of all of them
/// and each has its own schema.
///
/// The reply is a `Response` rather than an `Error` frame, and that half is the
/// contract check: had the reply bypassed its schema or fallen outside it,
/// enforcement would have answered `computer_result_schema_violation` instead.
#[tokio::test]
async fn a_route_opened_without_the_carrier_is_refused_with_a_reason_through_the_contract() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    cerebellum::install_browser_direct_test_bind(&planes.routes, 9, 3);

    for (corr, name, arguments) in [
        (1, "browser.status", json!({})),
        (2, "browser.launch", json!({})),
        (3, "browser.close", json!({"browser_session_id": "absent"})),
    ] {
        let response = invoke_existing(&planes, corr, name, arguments).await;
        assert_eq!(
            response.header.ty,
            FrameType::Response,
            "{name}: {}",
            String::from_utf8_lossy(&response.body)
        );
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "authorization_denied", "{name}: {body}");
        assert_eq!(body["reason"], "admission_facts_absent", "{name}: {body}");
        assert!(
            body["remedy"]
                .as_str()
                .is_some_and(|remedy| remedy.contains("admission carrier")),
            "{name}: the remedy must say how to get a route that carries facts: {body}"
        );
    }
}

#[tokio::test]
async fn absent_browser_config_uses_the_route_level_unknown_method_envelope() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        cerebellum::JournalPersistence::Isolated,
    );
    let response = invoke(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(response.header.ty, FrameType::Error);
    let error: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
    // A route-level error frame rather than a tool response carrying a refusal:
    // that is what this test guards, and it is unchanged. The code now names the
    // REASON, because an operator whose browser is simply unconfigured can act on
    // that and cannot act on "unknown method".
    assert_eq!(error.code, "browser_not_configured");
    assert!(
        error.message.contains("browser.executable_path"),
        "the refusal must name what to configure: {}",
        error.message
    );
    assert_eq!(
        planes.sessions.status(
            "test-session",
            planes.lease_clock.as_ref(),
            std::time::SystemTime::UNIX_EPOCH,
        )["outcome"],
        "no_session"
    );
}

/// The advertised browser tools and the browser dispatch path admit the same set.
///
/// Each set is read from its production path: `browser_wire_tools` constructs the
/// advertised tools and `dispatchable_tool_for_test` calls the predicate the wire
/// loop uses. Comparing those sets rather than a literal makes either one-sided
/// admission change fail by capability name.
#[test]
fn browser_wire_advertisement_and_dispatch_are_equal() {
    let advertised: BTreeSet<String> = cerebellum::manifest::browser_wire_tools()
        .into_iter()
        .map(|tool| tool.name)
        .collect();
    let dispatchable: BTreeSet<String> = cerebellum::browser::tool_definitions()
        .into_iter()
        .filter_map(|(name, _, _)| {
            cerebellum::dispatchable_tool_for_test(name, true)
                .is_some()
                .then(|| name.to_string())
        })
        .collect();

    assert_eq!(
        advertised,
        dispatchable,
        "browser wire admission differs: advertised-only={:?}; dispatchable-only={:?}",
        advertised.difference(&dispatchable).collect::<Vec<_>>(),
        dispatchable.difference(&advertised).collect::<Vec<_>>(),
    );
}

/// The surface reporter agrees with the predicate it claims to read.
///
/// `browser_wire_surface` exists so a person can ask what a caller can reach
/// without deriving it from three files. That only helps if it reports rather
/// than asserts: a reporter that can disagree with dispatch is worse than none,
/// because it carries the authority of having read the production path while
/// answering from somewhere else.
///
/// Nothing else watches it. It is a probe, so no acceptance test fails when it
/// drifts, and its output looks equally plausible either way -- which is the
/// exact shape that needs a fence rather than a reader's attention.
#[test]
fn the_browser_surface_reporter_agrees_with_dispatch() {
    for configured in [true, false] {
        let reported = cerebellum::browser_wire_surface(configured);
        assert!(
            !reported.is_empty(),
            "the reporter returned nothing, so it cannot disagree with anything"
        );

        let mut any_reachable = false;
        let mut any_refused = false;
        for (name, reachable) in &reported {
            // The predicate `send_hello` filters on, asked directly.
            let dispatchable = cerebellum::dispatchable_tool_for_test(name, configured).is_some();
            assert_eq!(
                *reachable, dispatchable,
                "the reporter says {name} reachable={reachable} with                  browser_configured={configured}, but dispatch says {dispatchable}"
            );
            if *reachable {
                any_reachable = true;
            } else {
                any_refused = true;
            }
        }

        // Without this the test passes over a reporter that answers a constant:
        // every row agreeing that nothing is reachable is agreement about
        // nothing. A configured host must reach something; a bare one must not.
        if configured {
            assert!(any_reachable, "a configured host reached no browser tool");
        } else {
            assert!(
                any_refused,
                "an unconfigured host reached every browser tool"
            );
        }
    }
}

/// The production constructor wires a launcher wherever one exists.
///
/// Every other test in this file ASSIGNS `launch_service` directly, which is
/// why a real defect hid here for as long as it did: a fixture that injects a
/// launcher never asks whether production builds one. iceteaSA found it by
/// running on Linux, where the wiring was gated to macOS and the refusal blamed
/// profile storage on a healthy disk.
///
/// This runs on every platform and asserts the platform's own answer, so it
/// fails on the platform that regressed rather than only where it was written.
#[tokio::test]
async fn the_production_constructor_wires_a_launcher_on_every_platform_that_has_one() {
    // A path that is a file, since the wiring filters on exactly that.
    let executable = std::env::current_exe().expect("the test binary is a file");
    let planes = cerebellum::Planes::with_browser_config_journaling(
        std::sync::Arc::new(cerebellum_core::health::HealthState::new()),
        Some(cerebellum::browser_config::BrowserConfig {
            executable_path: Some(executable),
            expected_identity: Some("test.identity".into()),
            launch_handshake_deadline_ms: 10_000,
            termination_grace_period_ms: 1_000,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 5_000,
            navigation_settle_deadline_ms: 10_000,
        }),
        cerebellum::JournalPersistence::Isolated,
    );

    // Platforms with a process launcher must wire one. The list is the same one
    // the wiring itself uses, written out rather than derived from it, so
    // narrowing the wiring cannot silently narrow its own test.
    let has_launcher = cfg!(target_os = "macos") || cfg!(target_os = "linux");
    assert_eq!(
        planes.launch_service.is_some(),
        has_launcher,
        "on {} a launcher should be {}, and the production constructor said otherwise",
        std::env::consts::OS,
        if has_launcher { "wired" } else { "absent" }
    );
}

/// Set in the child process that builds the isolated plane; the parent only
/// spawns it and inspects the directory afterwards.
const ISOLATED_DATA_HOME_CHILD: &str = "CEREBELLUM_TEST_ISOLATED_DATA_HOME_CHILD";

/// An isolated plane with a launchable browser writes nothing under the data
/// home.
///
/// `Isolated` is what a test passes to stay off the operator's audit data, so a
/// journal it still opens on disk is a journal every test run touches: the
/// launch journal also runs startup recovery, which may kill a browser and move
/// profile custody recorded there. A launch also opens the profile registry and
/// takes custody locks, which under the data home are the operator's real,
/// backed-up profiles. The check has to look at the disk, because
/// nothing inside the plane can tell that a file was opened where it should not
/// have been.
///
/// The data home is found through `XDG_DATA_HOME` and `HOME`, which are
/// process-wide. Pointing them at a scratch directory inside this test binary
/// would redirect every test running beside it, so the plane is built in a
/// child process -- this same binary, filtered to this one test -- that
/// receives the scratch directory through its own environment.
#[test]
fn an_isolated_plane_leaves_nothing_under_the_data_home() {
    if std::env::var_os(ISOLATED_DATA_HOME_CHILD).is_some() {
        build_an_isolated_plane_with_a_launcher();
        return;
    }

    let scratch = std::env::temp_dir().join(format!(
        "cerebellum-isolated-data-home-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("the clock is after the epoch")
            .as_nanos()
    ));
    let data_home = scratch.join("data");
    let home = scratch.join("home");
    std::fs::create_dir_all(&data_home).expect("create the scratch data home");
    std::fs::create_dir_all(&home).expect("create the scratch home");

    let output = std::process::Command::new(std::env::current_exe().expect("test binary path"))
        .args([
            "--exact",
            "an_isolated_plane_leaves_nothing_under_the_data_home",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ISOLATED_DATA_HOME_CHILD, "1")
        .env("XDG_DATA_HOME", &data_home)
        .env("HOME", &home)
        .output()
        .expect("spawn the child test process");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the child that builds the isolated plane failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A filter that matched nothing also exits successfully, having built no
    // plane and so written nothing -- which would pass the checks below.
    assert!(
        stdout.contains("1 passed"),
        "the child ran no test, so it built no plane:\n{stdout}"
    );

    let written: Vec<_> = [
        data_home.join("cortexkit").join("cerebellum"),
        home.join(".local")
            .join("share")
            .join("cortexkit")
            .join("cerebellum"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .map(|path| {
        let entries = walk(&path);
        format!("{}: {entries:?}", path.display())
    })
    .collect();
    let _ = std::fs::remove_dir_all(&scratch);
    assert!(
        written.is_empty(),
        "an isolated plane wrote under the data home: {written:?}"
    );
}

fn build_an_isolated_plane_with_a_launcher() {
    // The scratch directory reaches the plane only if the journal path is
    // resolved from it. Were it resolved elsewhere, nothing would be written
    // under the scratch directory whatever the plane did.
    let data_home = std::path::PathBuf::from(
        std::env::var_os("XDG_DATA_HOME").expect("the parent set XDG_DATA_HOME"),
    );
    let launch_journal = cerebellum_core::journal::journal_data_path("browser-launch.json")
        .expect("the journal path resolves");
    assert!(
        launch_journal.starts_with(&data_home),
        "{} is not under the scratch data home {}",
        launch_journal.display(),
        data_home.display()
    );

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build a runtime");
    runtime.block_on(async {
        let planes = cerebellum::Planes::with_browser_config_journaling(
            std::sync::Arc::new(cerebellum_core::health::HealthState::new()),
            Some(cerebellum::browser_config::BrowserConfig {
                // A path that is a file, since the launcher wiring filters on
                // exactly that. It is never executed: nothing here launches.
                executable_path: Some(std::env::current_exe().expect("the test binary is a file")),
                expected_identity: Some("test.identity".into()),
                launch_handshake_deadline_ms: 10_000,
                termination_grace_period_ms: 1_000,
                browser_idle_timeout_ms: 60_000,
                browser_exit_observation_deadline_ms: 5_000,
                navigation_settle_deadline_ms: 10_000,
            }),
            cerebellum::JournalPersistence::Isolated,
        );
        // Without a launcher the launch journal is never opened, and an empty
        // data home would say nothing about it.
        assert_eq!(
            planes.launch_service.is_some(),
            cfg!(target_os = "macos") || cfg!(target_os = "linux"),
            "the launcher wiring changed, so this no longer reaches the launch journal"
        );
        // The computer plane journals too; an isolated plane still serves it,
        // from memory.
        #[cfg(any(target_os = "macos", target_os = "windows"))]
        assert!(
            planes.computer.is_ok(),
            "the isolated computer plane is unavailable: {:?}",
            planes.computer.as_ref().err()
        );
    });

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    take_profile_custody_through_an_isolated_launch_service(&data_home);
}

/// Open the profile registry and take custody through an isolated launch
/// service, the way a launch does before it spawns a browser.
///
/// The plane's own launcher is never asked to launch here -- that needs a
/// verified browser -- so without this the registry and custody locks would
/// never be opened and an empty data home would prove nothing about them.
/// The service is built directly because the plane holds it behind the
/// launcher trait; `Planes` passes its persistence to this same constructor.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn take_profile_custody_through_an_isolated_launch_service(data_home: &std::path::Path) {
    use cerebellum_core::identity::{
        AcceptedBindFacts, ProfileDisposition, RouteIdentity, RouteSurface, SessionKind,
    };

    let service = cerebellum::browser_launch_service::ProductionLaunchService::open(
        cerebellum::browser_config::BrowserConfig {
            executable_path: Some(std::env::current_exe().expect("the test binary is a file")),
            expected_identity: Some("test.identity".into()),
            launch_handshake_deadline_ms: 10_000,
            termination_grace_period_ms: 1_000,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 5_000,
            navigation_settle_deadline_ms: 10_000,
        },
        cerebellum::JournalPersistence::Isolated,
    );
    let accepted = AcceptedBindFacts {
        identity: RouteIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            conversation_key: "isolated-conversation".to_string(),
            agent_project_id: "isolated-project".to_string(),
            session_kind: SessionKind::Primary,
            // Durable, because a durable profile is the one the operator's
            // real registry keeps, so it is the one that must not land there.
            profile_disposition: ProfileDisposition::Durable,
            project_root: std::path::PathBuf::from("/tmp"),
        },
        // The bind validator refuses an empty principal before the registry
        // is opened.
        principal: Some(subc_protocol::Principal::Direct),
        agent_project_id_attested: true,
        session_kind_attested: true,
        control_operations: Vec::new(),
        effective_capability_scope: None,
        consumer_capabilities: Vec::new(),
        surface: RouteSurface::Tools,
        scope: None,
    };
    // It must succeed: a refusal before the registry opened would also leave
    // the data home empty, and would pass the parent's check for nothing.
    let profile_directory = service
        .take_and_return_profile_custody(&accepted, "isolated-session")
        .expect("an isolated service takes and returns profile custody");
    assert!(
        !profile_directory.starts_with(data_home),
        "the isolated profile {} is under the data home {}",
        profile_directory.display(),
        data_home.display()
    );
    // The private root goes with the service, so a test run leaves no
    // profiles behind in the temporary directory either.
    drop(service);
    assert!(
        !profile_directory.exists(),
        "the isolated profile {} outlived its service",
        profile_directory.display()
    );
}

fn walk(root: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            found.push(path);
        }
    }
    found
}

#[tokio::test]
async fn present_with_opaque_origin_does_not_front_browser() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://landed.example").await;

    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_tool_request_for_test_with_existing_planes(
        request(
            50,
            "browser_use",
            json!({"action": "present", "origin": "null"}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let reply = rx.recv().await.expect("an invalid-request response");
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "invalid_request", "{body}");
    assert_eq!(body["detail"]["field"], "origin", "{body}");
    assert_eq!(body["detail"]["reason_code"], "invalid_origin", "{body}");
    assert!(rx.try_recv().is_err(), "an elicitation frame was sent");
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "browser was fronted"
    );
}

#[tokio::test]
async fn present_fronts_then_marks_human_in_control() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://landed.example").await;

    let presented = cerebellum::present_browser_handoff_for_test(
        &planes,
        &route_identity(),
        "https://landed.example",
    )
    .await;
    assert_eq!(
        presented,
        json!({"outcome":"presented","expires_in_ms":600_000})
    );
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["Page.bringToFront", "Target.activateTarget"]
    );

    let operations_before = planes.browser.operation_log().await;
    let journal_before = planes.browser.journal_export_for_test().await;
    let blocked = invoke_existing(&planes, 20, "browser.snapshot", json!({})).await;
    let blocked: Value = serde_json::from_slice(&blocked.body).unwrap();
    assert_eq!(blocked["outcome"], "human_in_control", "{blocked}");
    assert_eq!(blocked["remedy"], "browser.resume", "{blocked}");
    assert_eq!(blocked["origin"], "https://landed.example", "{blocked}");
    assert!(blocked["expires_in_ms"].as_u64().unwrap() <= 600_000);
    assert_eq!(planes.browser.operation_log().await, operations_before);
    assert_eq!(
        planes.browser.journal_export_for_test().await,
        journal_before
    );
}

#[tokio::test]
async fn present_that_cannot_front_is_refused_not_presented() {
    let launcher = Arc::new(RecordingLauncher {
        present_error: Some("fronting was refused by Chrome"),
        ..RecordingLauncher::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://landed.example").await;

    let reply = cerebellum::present_browser_handoff_for_test(
        &planes,
        &route_identity(),
        "https://landed.example",
    )
    .await;
    assert_eq!(reply["outcome"], "present_failed", "{reply}");
    assert_eq!(reply["error_text"], "fronting was refused by Chrome");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["Page.bringToFront"]
    );
    assert!(
        planes
            .sessions
            .human_in_control(
                &route_identity().conversation_key,
                planes.lease_clock.as_ref()
            )
            .is_none(),
        "a failed front must not hand control away"
    );
}

#[tokio::test]
async fn resume_closes_by_caller_and_reports_it() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://landed.example").await;
    let route = route_identity();

    let presented =
        cerebellum::present_browser_handoff_for_test(&planes, &route, "https://landed.example")
            .await;
    assert_eq!(presented["outcome"], "presented", "{presented}");
    let resumed = cerebellum::resume_browser_handoff_for_test(&planes, &route).await;
    assert_eq!(
        resumed,
        json!({
            "outcome":"resumed",
            "handoff":"closed_by_caller",
            "origin":"https://landed.example",
        })
    );
    let no_handoff = cerebellum::resume_browser_handoff_for_test(&planes, &route).await;
    assert_eq!(no_handoff["outcome"], "no_handoff");
}

#[tokio::test]
async fn cookie_values_never_leave_the_driver() {
    const SECRET: &str = "SECRET-9f1c";
    let launcher = Arc::new(RecordingLauncher {
        cookie_value: Some(SECRET),
        cookie_grows_on_poll: true,
        credential_field_then_clears: true,
        ..RecordingLauncher::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://landed.example").await;
    let route = route_identity();

    let presented =
        cerebellum::present_browser_handoff_for_test(&planes, &route, "https://landed.example")
            .await;
    assert_eq!(presented["outcome"], "presented", "{presented}");
    tokio::time::timeout(Duration::from_secs(6), async {
        loop {
            if planes
                .browser
                .journal_export_for_test()
                .await
                .contains("login_observed")
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("one bounded poll observes login");
    let resumed = cerebellum::resume_browser_handoff_for_test(&planes, &route).await;
    assert_eq!(resumed["handoff"], "login_observed", "{resumed}");

    let journal = planes.browser.journal_export_for_test().await;
    let wire = format!("{presented}{resumed}");
    let planted = format!(
        "{{\"bytes\":\"{}\"}}",
        cerebellum_core::serde_base64::encode(SECRET.as_bytes())
    );
    assert!(
        base64_decoded_strings(&planted)
            .iter()
            .any(|text| text.contains(SECRET)),
        "the scanner cannot find a planted secret, so absence would prove nothing"
    );
    for serialized in [&journal, &wire] {
        assert!(!serialized.contains(SECRET), "cookie value leaked verbatim");
        assert!(
            !base64_decoded_strings(serialized)
                .iter()
                .any(|text| text.contains(SECRET)),
            "cookie value leaked through an encoded field"
        );
    }
}

fn base64_decoded_strings(text: &str) -> Vec<String> {
    text.split(|character: char| {
        !(character.is_ascii_alphanumeric()
            || character == '+'
            || character == '/'
            || character == '=')
    })
    .filter(|token| token.len() >= 8)
    .filter_map(|token| cerebellum_core::serde_base64::decode(token).ok())
    .filter_map(|bytes| String::from_utf8(bytes).ok())
    .collect()
}

fn session_lock_refusal() -> Value {
    json!({"outcome": "internal_failure", "stage": "browser_session_lock"})
}

async fn response_body(planes: &Planes, corr: u64, name: &str, arguments: Value) -> Value {
    let response = invoke(planes, corr, name, arguments).await;
    // An Error frame here would mean the refusal was withheld as a schema
    // violation instead of reaching the caller.
    assert_eq!(
        response.header.ty,
        FrameType::Response,
        "{name}: {}",
        String::from_utf8_lossy(&response.body)
    );
    serde_json::from_slice(&response.body).unwrap()
}

#[tokio::test]
async fn poisoned_session_lock_refuses_status_close_and_launch_through_the_wire() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    let launched = response_body(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
    let browser_session_id = launched["browser_session_id"].as_str().unwrap().to_string();
    planes.sessions.poison_for_test();

    assert_eq!(
        response_body(&planes, 2, "browser.status", json!({})).await,
        session_lock_refusal()
    );
    assert_eq!(
        response_body(
            &planes,
            3,
            "browser.close",
            json!({"browser_session_id": browser_session_id}),
        )
        .await,
        session_lock_refusal()
    );
    assert_eq!(
        response_body(&planes, 4, "browser.launch", json!({})).await,
        session_lock_refusal()
    );
    assert_eq!(
        *launcher.launches.lock().unwrap(),
        1,
        "a launch was attempted over a poisoned session lock"
    );
}

#[tokio::test]
async fn poisoned_session_lock_refuses_a_browser_action_through_the_wire() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://page.example").await;
    grant_browser(&planes, "https://page.example", Vec::new()).await;
    planes.sessions.poison_for_test();

    let refused = response_body(&planes, 20, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(refused["outcome"], "internal_failure", "{refused}");
    assert_eq!(refused["stage"], "browser_session_lock", "{refused}");
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "a snapshot reached CDP over a poisoned session lock"
    );
}

/// A launcher whose own lock was poisoned, refusing the way the production
/// launcher does for its profile registry lock.
struct PoisonedRegistryLauncher;

impl BrowserSessionLauncher for PoisonedRegistryLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        let lock = Arc::new(Mutex::new(()));
        let poisoned = Arc::clone(&lock);
        let _ = std::thread::spawn(move || {
            let _guard = poisoned.lock();
            panic!("poison the registry fixture lock");
        })
        .join();
        let Err(refusal) =
            cerebellum::browser_session::refuse_poisoned(lock.lock(), "profile_registry_lock")
        else {
            panic!("the fixture lock was not poisoned");
        };
        Err(refusal)
    }
}

#[tokio::test]
async fn poisoned_profile_registry_lock_launch_refusal_reaches_the_caller_not_a_schema_violation() {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(PoisonedRegistryLauncher));

    assert_eq!(
        response_body(&planes, 1, "browser.launch", json!({})).await,
        json!({"outcome": "internal_failure", "stage": "profile_registry_lock"})
    );
}

/// A launcher refusing the way production does when the profile registry no
/// longer trusts its managed root. The live refusal that motivated this test
/// was a root pinned by a device number a reboot had moved; under the
/// fact-based identity that registry now refuses as predating the stored
/// facts, which is the refusal the next real launch on it receives.
struct UntrustedRootLauncher;

impl BrowserSessionLauncher for UntrustedRootLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        Err(
            cerebellum::browser_launch::BrowserLaunchOutcome::ProfileRegistryUntrustedRoot {
                reason:
                    cerebellum::profile::UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
            }
            .as_json(),
        )
    }
}

/// The reply boundary withholds undeclared replies. This refusal was once
/// undeclared, so the caller received `computer_result_schema_violation` and
/// lost the remedy that would have told it to rebind the profile root.
#[tokio::test]
async fn untrusted_profile_root_launch_refusal_reaches_the_caller_not_a_schema_violation() {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(UntrustedRootLauncher));

    let refusal = response_body(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(
        refusal["outcome"], "profile_registry_untrusted_root",
        "{refusal}"
    );
    assert_eq!(
        refusal["reason_code"], "profile_registry_managed_root_identity_predates_facts",
        "{refusal}"
    );
    assert!(
        refusal["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains("browser.rebind_profile_root")),
        "{refusal}"
    );
    // The launch slot is released, so the next attempt meets the same refusal
    // rather than a session left half-open by the first.
    assert_eq!(
        response_body(&planes, 2, "browser.launch", json!({})).await,
        refusal
    );
}

/// Launch through the wire, place the page at `origin`, and return the new
/// browser session id so the caller can close it.
async fn launch_session_at(
    planes: &Planes,
    page: &CommittedPage,
    corr: u64,
    origin: &str,
) -> String {
    let launched = response_body(planes, corr, "browser.launch", json!({})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
    page.commit(&format!("{origin}/page"));
    planes
        .browser
        .same_document_url(
            &route_identity(),
            &format!("{origin}/page"),
            cerebellum::snapshot_store::SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();
    launched["browser_session_id"].as_str().unwrap().to_string()
}

async fn close_session(planes: &Planes, corr: u64, browser_session_id: &str) {
    let closed = response_body(
        planes,
        corr,
        "browser.close",
        json!({"browser_session_id": browser_session_id}),
    )
    .await;
    assert_eq!(closed["outcome"], "closed", "{closed}");
}

fn recording_planes(launcher: &Arc<RecordingLauncher>) -> Planes {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    planes
}

// Closing a browser marks the conversation's page context ended. A later
// launch on the same conversation is a new browser, and its pages must be
// readable: before, the ended context survived the relaunch and every read on
// the new browser was refused as no_session.
#[tokio::test]
async fn a_browser_relaunched_after_close_serves_snapshots() {
    let launcher = Arc::new(RecordingLauncher::default());
    let planes = recording_planes(&launcher);
    grant_browser(&planes, "https://page.example", Vec::new()).await;

    let first = launch_session_at(&planes, &launcher.page, 1, "https://page.example").await;
    let before_close = response_body(&planes, 2, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(before_close["outcome"], "ok", "{before_close}");
    close_session(&planes, 3, &first).await;

    let second = launch_session_at(&planes, &launcher.page, 4, "https://page.example").await;
    assert_ne!(first, second);
    let relaunched = response_body(&planes, 5, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(relaunched["outcome"], "ok", "{relaunched}");
    assert!(
        relaunched["content"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe before")),
        "{relaunched}"
    );
    // The new browser must not re-mint an id the caller holds from the old one.
    assert_ne!(relaunched["snapshot_id"], before_close["snapshot_id"]);
}

// The same relaunch, read through navigate's read_page rather than a separate
// snapshot call: the read runs in the same page context and was refused the
// same way.
#[tokio::test]
async fn a_browser_relaunched_after_close_serves_navigate_read_page() {
    let launcher = Arc::new(RecordingLauncher::default());
    let planes = recording_planes(&launcher);
    grant_browser(&planes, "https://requested.example", Vec::new()).await;
    grant_browser(&planes, "https://landed.example", Vec::new()).await;

    let first = launch_session_at(&planes, &launcher.page, 1, "https://requested.example").await;
    close_session(&planes, 2, &first).await;
    launch_session_at(&planes, &launcher.page, 3, "https://requested.example").await;

    let navigated = response_body(
        &planes,
        4,
        "browser.navigate",
        json!({
            "url": "https://requested.example/",
            "intent": "read the page after a relaunch",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false},
            "read_page": true
        }),
    )
    .await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(navigated["read_page"]["outcome"], "ok", "{navigated}");
    assert!(
        navigated["read_page"]["content"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe before")),
        "{navigated}"
    );
}

// A browser that exits on its own is torn down by the exit sweep, which never
// tells the page context. The relaunched browser must read its own pages, and
// a snapshot id from the crashed browser must not address anything on the new
// one: its refs name elements of a page that is gone.
#[tokio::test]
async fn a_browser_relaunched_after_a_crash_reads_fresh_and_drops_old_snapshots() {
    let launcher = Arc::new(RecordingLauncher::default());
    let planes = recording_planes(&launcher);
    grant_browser(
        &planes,
        "https://page.example",
        vec![HazardClass::CredentialFormSubmit],
    )
    .await;

    launch_session_at(&planes, &launcher.page, 1, "https://page.example").await;
    let old = response_body(&planes, 2, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(old["outcome"], "ok", "{old}");

    *launcher.exited.lock().unwrap() = true;
    planes.sessions.observe_exits_all(&config());
    let status = response_body(&planes, 3, "browser.status", json!({})).await;
    assert_ne!(status["outcome"], "ready", "{status}");
    *launcher.exited.lock().unwrap() = false;

    launch_session_at(&planes, &launcher.page, 4, "https://page.example").await;
    let fresh = response_body(&planes, 5, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(fresh["outcome"], "ok", "{fresh}");
    assert_ne!(fresh["snapshot_id"], old["snapshot_id"]);

    launcher.effects.lock().unwrap().clear();
    let stale_click = response_body(
        &planes,
        6,
        "browser.click",
        json!({
            "ref": old["refs"][0]["ref"],
            "snapshot_id": old["snapshot_id"],
            "intent": "click through a snapshot of the crashed browser",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    assert_ne!(stale_click["outcome"], "ok", "{stale_click}");
    assert!(
        !launcher
            .effects
            .lock()
            .unwrap()
            .iter()
            .any(|effect| effect.starts_with("input_")),
        "a stale snapshot dispatched input on the relaunched browser: {:?}",
        launcher.effects.lock().unwrap()
    );
}

// A closed browser that nobody relaunched stays closed: reads keep refusing.
#[tokio::test]
async fn a_closed_browser_without_relaunch_still_refuses_snapshots() {
    let launcher = Arc::new(RecordingLauncher::default());
    let planes = recording_planes(&launcher);
    grant_browser(&planes, "https://page.example", Vec::new()).await;

    let first = launch_session_at(&planes, &launcher.page, 1, "https://page.example").await;
    close_session(&planes, 2, &first).await;
    let refused = response_body(&planes, 3, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(refused["outcome"], "no_session", "{refused}");
}

// ---------------------------------------------------------------------------
// A click's reply reports the navigation it caused.
//
// These drive `browser.click` through the wire into the production CDP
// driver, over a pipe that answers commands and emits page events in the
// order Chrome 153 was measured to emit them for the same kind of click.
// ---------------------------------------------------------------------------

/// The page every scenario starts on, as a canonical origin plus the path
/// `launch_at` records.
const CLICK_PAGE_ORIGIN: &str = "https://example.com";
/// A page target's main frame id is its target id in Chrome.
const MAIN_FRAME: &str = "target-own";
const LINK_BACKEND_NODE: u64 = 42;
const LINK_DESTINATION: &str = "https://iana.org/domains/example";

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ClickScenario {
    /// The main frame follows the link through a redirect chain to another
    /// origin, commits, loads and goes quiet.
    CrossOriginRedirect,
    /// The click changes nothing.
    NoNavigation,
    /// Only an iframe navigates; the main frame stays where it is.
    SubframeOnly,
    /// The click opens a confirm dialog, which is dismissed; nothing navigates.
    DialogDismissed,
}

/// The `DOM.getFlattenedDocument` result for the page: one link. The snapshot
/// classifies the same document, so the driver's pre-input reclassification
/// agrees with it.
fn click_page_document() -> serde_json::Map<String, Value> {
    json!({"nodes":[{
        "nodeId":1,
        "backendNodeId":LINK_BACKEND_NODE,
        "nodeType":1,
        "localName":"a",
        "nodeName":"A",
        "attributes":["href", LINK_DESTINATION],
    }]})
    .as_object()
    .unwrap()
    .clone()
}

fn session_event(method: &str, params: Value) -> Value {
    json!({"method":method,"sessionId":"session-own","params":params})
}

fn document_response(request_id: &str, frame_id: &str, url: &str, status: u16) -> Value {
    session_event(
        "Network.responseReceived",
        json!({
            "requestId":request_id,
            "frameId":frame_id,
            "type":"Document",
            "response":{"url":url,"status":status,"statusText":"OK","headers":{}}
        }),
    )
}

fn document_request(
    request_id: &str,
    frame_id: &str,
    url: &str,
    redirect_from: Option<u16>,
) -> Value {
    let mut params = json!({
        "requestId":request_id,
        "frameId":frame_id,
        "type":"Document",
        "request":{"url":url}
    });
    if let Some(status) = redirect_from {
        params["redirectResponse"] = json!({"status":status,"statusText":"Moved","headers":{}});
    }
    session_event("Network.requestWillBeSent", params)
}

/// Events Chrome sends after acknowledging the release, per scenario.
fn events_after_release(scenario: ClickScenario) -> Vec<Value> {
    match scenario {
        ClickScenario::CrossOriginRedirect => vec![
            session_event("Page.frameStartedLoading", json!({"frameId":MAIN_FRAME})),
            document_request("doc-1", MAIN_FRAME, LINK_DESTINATION, None),
            document_request(
                "doc-1",
                MAIN_FRAME,
                "https://www.iana.org/domains/example",
                Some(301),
            ),
            document_request(
                "doc-1",
                MAIN_FRAME,
                "http://www.iana.org/help/example-domains",
                Some(301),
            ),
            document_request(
                "doc-1",
                MAIN_FRAME,
                "https://www.iana.org/help/example-domains",
                Some(307),
            ),
            document_response(
                "doc-1",
                MAIN_FRAME,
                "https://www.iana.org/help/example-domains",
                200,
            ),
            session_event(
                "Page.frameNavigated",
                json!({"frame":{
                    "id":MAIN_FRAME,
                    "loaderId":"loader-2",
                    "url":"https://www.iana.org/help/example-domains",
                    "securityOrigin":"https://www.iana.org",
                    "mimeType":"text/html"
                },"type":"Navigation"}),
            ),
            session_event("Network.loadingFinished", json!({"requestId":"doc-1"})),
            session_event("Page.domContentEventFired", json!({"timestamp":1.0})),
            session_event("Page.loadEventFired", json!({"timestamp":1.1})),
            session_event("Page.frameStoppedLoading", json!({"frameId":MAIN_FRAME})),
        ],
        ClickScenario::SubframeOnly => vec![
            session_event("Page.frameStartedLoading", json!({"frameId":"frame-child"})),
            document_request("doc-2", "frame-child", "https://example.com/frame2", None),
            document_response("doc-2", "frame-child", "https://example.com/frame2", 200),
            session_event(
                "Page.frameNavigated",
                json!({"frame":{
                    "id":"frame-child",
                    "parentId":MAIN_FRAME,
                    "loaderId":"loader-3",
                    "url":"https://example.com/frame2",
                    "securityOrigin":"https://example.com",
                    "mimeType":"text/html"
                },"type":"Navigation"}),
            ),
            session_event("Network.loadingFinished", json!({"requestId":"doc-2"})),
            session_event("Page.frameStoppedLoading", json!({"frameId":"frame-child"})),
        ],
        ClickScenario::NoNavigation | ClickScenario::DialogDismissed => Vec::new(),
    }
}

/// A CDP pipe that answers the driver's commands the way Chrome does and,
/// on the mouse release, emits the scenario's page events.
struct ChromeLikePipe {
    scenario: ClickScenario,
    /// The main frame's committed URL, which `Page.getNavigationHistory`
    /// reports and a main-frame `Page.frameNavigated` moves.
    page: CommittedPage,
    /// Every CDP method the driver sent, in order.
    commands: Arc<Mutex<Vec<String>>>,
    reads: VecDeque<Vec<u8>>,
    blocked_release_id: Option<u64>,
}

impl ChromeLikePipe {
    fn queue(&mut self, frame: Value) {
        let mut bytes = serde_json::to_vec(&frame).unwrap();
        bytes.push(0);
        self.reads.push_back(bytes);
    }

    fn reply(&mut self, id: u64, result: Value) {
        self.queue(json!({"id":id,"sessionId":"session-own","result":result}));
    }
}

impl CdpPipeIo for ChromeLikePipe {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let id = command["id"].as_u64().unwrap();
        self.commands
            .lock()
            .unwrap()
            .push(command["method"].as_str().unwrap().to_string());
        match command["method"].as_str().unwrap() {
            "Target.createTarget" => {
                self.queue(json!({"id":id,"result":{"targetId":"target-own"}}));
            }
            "Target.attachToTarget" => {
                self.queue(json!({"id":id,"result":{"sessionId":"session-own"}}));
            }
            "DOM.getContentQuads" => self.reply(
                id,
                json!({"quads":[[10.0, 20.0, 34.0, 20.0, 34.0, 52.0, 10.0, 52.0]]}),
            ),
            "Page.getLayoutMetrics" => self.reply(
                id,
                json!({"cssVisualViewport":{
                    "offsetX":0.0,"offsetY":0.0,"pageX":0.0,"pageY":0.0,
                    "clientWidth":1280.0,"clientHeight":713.0,"scale":1.0
                }}),
            ),
            "DOM.getNodeForLocation" => self.reply(
                id,
                json!({"backendNodeId":LINK_BACKEND_NODE,"frameId":MAIN_FRAME}),
            ),
            "DOM.getFlattenedDocument" => self.reply(id, Value::Object(click_page_document())),
            "Page.getNavigationHistory" => {
                let history = self.page.navigation_history();
                self.reply(id, history)
            }
            "Page.getFrameTree" => {
                let tree = self.page.frame_tree();
                self.reply(id, tree)
            }
            "DOM.scrollIntoViewIfNeeded" | "DOM.enable" | "Page.enable" | "Network.enable" => {
                self.reply(id, json!({}))
            }
            "Input.dispatchMouseEvent" if command["params"]["type"] == "mousePressed" => {
                self.reply(id, json!({}))
            }
            "Input.dispatchMouseEvent" => match self.scenario {
                ClickScenario::DialogDismissed => {
                    // The release blocks until the dialog is answered.
                    self.blocked_release_id = Some(id);
                    self.queue(session_event(
                        "Page.javascriptDialogOpening",
                        json!({
                            "type":"confirm",
                            "message":"leave?",
                            "url":"https://example.com/page",
                            "hasBrowserHandler":false
                        }),
                    ));
                }
                scenario => {
                    // Measured: the navigation request for a link click
                    // arrives before the release acknowledgement.
                    match scenario {
                        ClickScenario::CrossOriginRedirect => self.queue(session_event(
                            "Page.frameRequestedNavigation",
                            json!({
                                "frameId":MAIN_FRAME,
                                "reason":"anchorClick",
                                "url":LINK_DESTINATION,
                                "disposition":"currentTab"
                            }),
                        )),
                        ClickScenario::SubframeOnly => self.queue(session_event(
                            "Page.frameRequestedNavigation",
                            json!({
                                "frameId":"frame-child",
                                "reason":"anchorClick",
                                "url":"https://example.com/frame2",
                                "disposition":"currentTab"
                            }),
                        )),
                        _ => {}
                    }
                    self.reply(id, json!({}));
                    for event in events_after_release(scenario) {
                        // Chrome's history entry moves when the main frame
                        // commits, which is the event that says so.
                        if event["method"] == "Page.frameNavigated"
                            && event["params"]["frame"].get("parentId").is_none()
                        {
                            let url = event["params"]["frame"]["url"].as_str().unwrap();
                            self.page.commit(url);
                        }
                        self.queue(event);
                    }
                }
            },
            "Page.handleJavaScriptDialog" => {
                assert_eq!(command["params"]["accept"], false);
                let release_id = self
                    .blocked_release_id
                    .take()
                    .expect("the dialog handler follows a blocked release");
                self.reply(release_id, json!({}));
                self.reply(id, json!({}));
            }
            other => panic!("unexpected CDP command {other}: {command}"),
        }
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> std::io::Result<PipeRead> {
        let Some(bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(PipeRead::Bytes(bytes.len()))
    }
}

/// A browser whose snapshot is canned (the snapshot path is not what these
/// tests exercise) and whose click runs through the production CDP driver.
struct CdpClickProcess {
    driver: CdpNavigationDriver<ChromeLikePipe>,
    snapshots: Arc<Mutex<usize>>,
}

impl OwnedBrowserProcess for CdpClickProcess {
    fn main_frame_url(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
        self.driver.main_frame_url(context_key, deadline_ms)
    }

    fn committed_document(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        self.driver.committed_document(context_key, deadline_ms)
    }

    /// Canned like the snapshot: what matters here is the document the
    /// capture records and the click_point that follows, which runs through
    /// the production driver. The viewport matches the pipe's layout metrics.
    fn screenshot(
        &mut self,
        _: &str,
        _: u64,
        _: u64,
        _: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        let viewport = ViewportObservation::new(
            0,
            TransformInputs::from_values(0.0, 0.0, 1280.0, 713.0, 1.0, 1.0),
        );
        Ok(BrowserScreenshotObservation {
            image_png_b64: ONE_BY_ONE_PNG_B64.into(),
            before: viewport,
            after: viewport,
            invalidation_observed: false,
        })
    }

    fn classify_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        deadline_ms: u64,
    ) -> Result<
        Result<
            cerebellum::classification::NonTypeClassificationRecord,
            cerebellum::classification::ClassificationUnavailable,
        >,
        NavigationDriveError,
    > {
        self.driver.classify_point(
            context_key,
            position,
            document_epoch,
            document_url,
            deadline_ms,
        )
    }

    fn click_point_classified(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        expected: &cerebellum::classification::NonTypeClassificationRecord,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.driver.click_point_classified(
            context_key,
            position,
            document_epoch,
            document_url,
            expected,
            deadline_ms,
            input_dispatched,
        )
    }

    fn click_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        self.driver
            .click_point(context_key, position, deadline_ms, input_dispatched)
    }

    fn snapshot_classified(
        &mut self,
        _: &str,
        _: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        *self.snapshots.lock().unwrap() += 1;
        let identity =
            BackendNodeIdentity::new("target-own", MAIN_FRAME, LINK_BACKEND_NODE).unwrap();
        let classification = classify_flattened_document(
            &click_page_document(),
            &identity,
            document_epoch,
            current_origin,
        )
        .expect("the link on the page classifies");
        Ok(BrowserSnapshotObservation {
            records: vec![AxRecord {
                depth: 0,
                role: "link".into(),
                name: "Learn more".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            dom_text: None,
            refs: vec![RefRecord {
                captured: SnapshotRef::new("e1", "link", "Learn more", 0).unwrap(),
                frame_path: vec![MAIN_FRAME.into()],
                backend_identity: Some(identity),
                raw_role: Some("link".into()),
                raw_name: Some("Learn more".into()),
                classification: Ok(Box::new(classification)),
            }],
            ax_truncated: false,
            refs_truncated: false,
        })
    }

    fn click_classified(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        document_epoch: u64,
        current_origin: &str,
        expected: Option<&cerebellum::classification::NonTypeClassificationRecord>,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.driver.click_classified(
            context_key,
            identity,
            document_epoch,
            current_origin,
            expected,
            deadline_ms,
            input_dispatched,
        )
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

struct CdpClickLauncher {
    scenario: ClickScenario,
    snapshots: Arc<Mutex<usize>>,
    page: CommittedPage,
    commands: Arc<Mutex<Vec<String>>>,
}

impl BrowserSessionLauncher for CdpClickLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        Ok(LaunchedBrowser {
            process: Box::new(CdpClickProcess {
                driver: CdpNavigationDriver::new(
                    ChromeLikePipe {
                        scenario: self.scenario,
                        page: self.page.clone(),
                        commands: Arc::clone(&self.commands),
                        reads: VecDeque::new(),
                        blocked_release_id: None,
                    },
                    CdpTransport::new(),
                    CdpFrameDecoder::default(),
                ),
                snapshots: Arc::clone(&self.snapshots),
            }),
            cleanup: Box::new(RecordingCleanup {
                effects: Arc::new(Mutex::new(Vec::new())),
            }),
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::AfterExecOnly,
        })
    }
}

/// Long enough for a navigation to reach network quiet, which needs
/// `QUIET_MS` of real time after the last request finishes.
const CLICK_SETTLE_DEADLINE_MS: u64 = 3_000;

/// Launch on the example page with a tier-4 grant for `granted_origins`,
/// snapshot it, and click its link.
async fn click_link(scenario: ClickScenario, granted_origins: &[&str]) -> (Planes, Value, usize) {
    let snapshots = Arc::new(Mutex::new(0));
    let page = CommittedPage::default();
    let config = BrowserConfig {
        navigation_settle_deadline_ms: CLICK_SETTLE_DEADLINE_MS,
        ..config()
    };
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config.clone()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(CdpClickLauncher {
        scenario,
        snapshots: Arc::clone(&snapshots),
        page: page.clone(),
        commands: Arc::default(),
    }));
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            Arc::clone(&planes.lease_clock),
            config.navigation_settle_deadline_ms,
        )
        .with_grants_installed(GrantStore::new([ActionGrant::new(
            "browse",
            1,
            "test-session",
            Severity::new(4, false, false),
            granted_origins.iter().copied().chain(["https://iana.org"]),
        )])),
    );
    launch_at(&planes, &page, CLICK_PAGE_ORIGIN).await;

    let snapshot = invoke(&planes, 100, "browser.snapshot", json!({"mode": "ax"})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke(
        &planes,
        101,
        "browser.click",
        json!({
            "ref": snapshot["refs"][0]["ref"],
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "follow the Learn more link",
            "severity": {"tier": 4, "credential": false, "financial": false}
        }),
    )
    .await;
    // Parsed from the wire frame, after result-schema enforcement: a field
    // the click schema did not declare would have withheld this reply.
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    let snapshot_count = *snapshots.lock().unwrap();
    (planes, clicked, snapshot_count)
}

#[tokio::test]
async fn a_click_that_navigates_cross_origin_reports_where_it_landed_and_that_reading_there_is_ungranted(
) {
    let (planes, clicked, _) =
        click_link(ClickScenario::CrossOriginRedirect, &[CLICK_PAGE_ORIGIN]).await;

    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(clicked["navigation"], "main_frame", "{clicked}");
    assert_eq!(
        clicked["url_final"], "https://www.iana.org/help/example-domains",
        "{clicked}"
    );
    assert_eq!(
        clicked["lifecycle"],
        json!({"events":["navigation_started", "load", "network_quiet"],"loaded":true,"settled":true}),
        "{clicked}"
    );
    assert_eq!(clicked["http_status"], 200, "{clicked}");
    assert_eq!(
        clicked["landing_origin"], "https://www.iana.org",
        "{clicked}"
    );
    assert_eq!(clicked["landing_origin_granted"], false, "{clicked}");
    assert!(clicked.get("navigation_window_ms").is_none(), "{clicked}");

    // The reply's claim holds: the conversation's page is now the landing
    // page, and reading it is refused under the grant for the old origin.
    let refused = invoke(&planes, 102, "browser.snapshot", json!({"mode": "ax"})).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://www.iana.org",
        "{refused}"
    );
}

/// The way an ungranted page is reached live: a click follows a link to
/// another origin, and the next read there is refused `origin_scope`. That
/// refusal must name the grant for the page's origin as it is now, and
/// following it literally -- open exactly those arguments, answer allow,
/// read again -- must succeed. A refusal whose remedy leaves the caller to
/// guess the tier or hazards sends it round the same loop.
#[tokio::test]
async fn an_origin_scope_refusal_names_the_grant_that_admits_the_read_and_following_it_succeeds() {
    let page = CommittedPage::default();
    let config = BrowserConfig {
        navigation_settle_deadline_ms: CLICK_SETTLE_DEADLINE_MS,
        ..config()
    };
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(CdpClickLauncher {
        scenario: ClickScenario::CrossOriginRedirect,
        snapshots: Arc::default(),
        page: page.clone(),
        commands: Arc::default(),
    }));
    bind_management_route(&planes).await;
    // Authorize the declared destination, but not the final redirect origin.
    open_grant_and_allow(
        &planes,
        110,
        json!({"origins": [CLICK_PAGE_ORIGIN, "https://iana.org"], "hazards": [], "severity_tier": 4}),
    )
    .await;
    launch_at(&planes, &page, CLICK_PAGE_ORIGIN).await;

    let snapshot = invoke_existing(&planes, 111, "browser.snapshot", json!({"mode": "ax"})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke_existing(
        &planes,
        112,
        "browser.click",
        json!({
            "ref": snapshot["refs"][0]["ref"],
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "follow the Learn more link",
            "severity": {"tier": 4, "credential": false, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(
        clicked["landing_origin"], "https://www.iana.org",
        "{clicked}"
    );
    assert_eq!(clicked["landing_origin_granted"], false, "{clicked}");

    // Parsed from the wire frame, after result-schema enforcement: an
    // undeclared detail field would have withheld this reply.
    let read = json!({"mode": "ax"});
    let refused = invoke_existing(&planes, 113, "browser.snapshot", read.clone()).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(refused["detail"]["reason"], "origin_scope", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://www.iana.org",
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["granted_origins"],
        json!(["https://example.com", "https://iana.org"]),
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["required"],
        json!({"tier": 1, "credential": false, "financial": false}),
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["grant_request"],
        json!({"origins": ["https://www.iana.org"], "severity_tier": 2, "hazards": []}),
        "{refused}"
    );
    assert_eq!(
        refused["remedy"],
        "call browser.open_grant with the arguments in detail.grant_request, then retry",
        "{refused}"
    );

    // Follow the remedy literally, then retry the identical read.
    let opened =
        open_grant_and_allow(&planes, 114, refused["detail"]["grant_request"].clone()).await;
    assert_eq!(
        opened["severity_ceiling"]["tier"], refused["detail"]["grant_request"]["severity_tier"],
        "{opened}"
    );
    let read_again = invoke_existing(&planes, 115, "browser.snapshot", read).await;
    let read_again: Value = serde_json::from_slice(&read_again.body).unwrap();
    assert_eq!(read_again["outcome"], "ok", "{read_again}");
    assert_eq!(
        read_again["source_origin"], "https://www.iana.org/help/example-domains",
        "{read_again}"
    );
}

#[tokio::test]
async fn a_click_landing_on_a_granted_origin_says_it_can_be_read() {
    let (_, clicked, _) = click_link(
        ClickScenario::CrossOriginRedirect,
        &[CLICK_PAGE_ORIGIN, "https://www.iana.org"],
    )
    .await;

    assert_eq!(clicked["navigation"], "main_frame", "{clicked}");
    assert_eq!(
        clicked["landing_origin"], "https://www.iana.org",
        "{clicked}"
    );
    assert_eq!(clicked["landing_origin_granted"], true, "{clicked}");
}

#[tokio::test]
async fn a_click_that_navigates_nowhere_says_none_was_observed() {
    let (_, clicked, _) = click_link(ClickScenario::NoNavigation, &[CLICK_PAGE_ORIGIN]).await;

    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(clicked["navigation"], "none_observed", "{clicked}");
    assert_eq!(clicked["navigation_window_ms"], 100, "{clicked}");
    // Nothing was measured, so nothing that reads like a measurement is
    // claimed: no empty lifecycle, no null landing URL.
    for absent in [
        "lifecycle",
        "url_final",
        "landing_origin",
        "landing_origin_granted",
    ] {
        assert!(clicked.get(absent).is_none(), "{absent} in {clicked}");
    }
}

#[tokio::test]
async fn a_subframe_navigation_is_not_reported_as_the_page_navigating() {
    let (planes, clicked, _) = click_link(ClickScenario::SubframeOnly, &[CLICK_PAGE_ORIGIN]).await;

    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(clicked["navigation"], "none_observed", "{clicked}");
    for absent in ["lifecycle", "url_final", "http_status", "landing_origin"] {
        assert!(clicked.get(absent).is_none(), "{absent} in {clicked}");
    }

    // The page is still the one the click started on, so it is still readable.
    let snapshot = invoke(&planes, 102, "browser.snapshot", json!({"mode": "ax"})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(
        snapshot["source_origin"], "https://example.com/page",
        "{snapshot}"
    );
}

#[tokio::test]
async fn a_click_whose_dialog_is_dismissed_reports_the_dialog_and_no_navigation() {
    let (planes, clicked, _) =
        click_link(ClickScenario::DialogDismissed, &[CLICK_PAGE_ORIGIN]).await;

    assert_eq!(
        clicked["outcome"], "javascript_dialog_dismissed",
        "{clicked}"
    );
    assert_eq!(
        clicked["dialogs"],
        json!([{"dialog_type":"confirm","response":"dismissed"}]),
        "{clicked}"
    );
    assert_eq!(
        clicked["lifecycle"],
        json!({"events":[],"loaded":false,"settled":false}),
        "{clicked}"
    );
    assert_eq!(clicked["navigation"], "none_observed", "{clicked}");
    assert!(clicked.get("url_final").is_none(), "{clicked}");

    let snapshot = invoke(&planes, 102, "browser.snapshot", json!({"mode": "ax"})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
}

// ---------------------------------------------------------------------------
// Page reads authorize against where the page IS, not where the module last
// saw it navigate.
//
// A page can leave the document the module navigated to without the module
// starting or watching the move: a timer, a meta refresh, a script assigning
// `location`, a redirect that lands after a click's observation window. The
// double stands in for that by committing a new main-frame URL directly, which
// is all Chrome's navigation history shows afterwards. The module's tracker
// still names the old page in every one of these tests.
// ---------------------------------------------------------------------------

/// Text that appears only in the double's page content: a reply carrying any
/// of it returned bytes from a document.
const PAGE_CONTENT_MARKERS: [&str; 3] = ["Click probe", "Sign in", ONE_BY_ONE_PNG_B64];

fn assert_no_page_content(reply: &Value) {
    let serialized = reply.to_string();
    for marker in PAGE_CONTENT_MARKERS {
        assert!(
            !serialized.contains(marker),
            "a refused read returned page content ({marker}): {reply}"
        );
    }
}

/// Launch, grant navigation to `https://requested.example` plus a read grant
/// for each of `readable`, and navigate there. The double lands on
/// `https://landed.example/final`, which is also what the tracker records.
async fn navigated_to_landed(readable: &[&str]) -> (Arc<RecordingLauncher>, Planes) {
    let launcher = Arc::new(RecordingLauncher::default());
    let planes = recording_planes(&launcher);
    grant_browser(&planes, "https://requested.example", Vec::new()).await;
    for origin in readable {
        grant_browser(&planes, origin, Vec::new()).await;
    }
    launch_session_at(&planes, &launcher.page, 1, "https://requested.example").await;
    let navigated = response_body(
        &planes,
        2,
        "browser.navigate",
        json!({
            "url": "https://requested.example/",
            "intent": "open the page the reads are about",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(
        navigated["url_final"], "https://landed.example/final",
        "{navigated}"
    );
    (launcher, planes)
}

/// Every refusal the plane's refusal ring holds, as `(page URL the refused read
/// addressed, reason)`, across all callers: the wire route's project id is
/// assigned by the harness, and which caller a record lands under is not what
/// these tests are about.
async fn refusal_records(planes: &Planes) -> Vec<(String, String)> {
    let export = planes.browser.refusal_ring_export_for_test().await;
    if export.is_empty() {
        return Vec::new();
    }
    let ring: Value = serde_json::from_str(&export).unwrap();
    ring["callers"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|caller| caller["records"].as_array().unwrap().clone())
        .map(|record| {
            (
                record["claimed_addressing"].as_str().unwrap().to_string(),
                record["reason"].as_str().unwrap().to_string(),
            )
        })
        .collect()
}

#[tokio::test]
async fn a_page_that_moves_itself_off_the_granted_origin_refuses_the_next_snapshot_in_both_modes() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example"]).await;
    // The same read succeeds while the page stays where it was navigated, so
    // the refusals below come from the move and not from a plane refusing
    // everything.
    let before = response_body(&planes, 3, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(before["outcome"], "ok", "{before}");

    launcher.page.commit("https://attacker.example/moved");

    for (corr, mode) in [(4, "ax"), (5, "dom_full")] {
        let refused = response_body(&planes, corr, "browser.snapshot", json!({"mode": mode})).await;
        assert_eq!(
            refused["outcome"], "authorization_denied",
            "{mode}: {refused}"
        );
        assert_eq!(
            refused["detail"]["attempted_origin"], "https://attacker.example",
            "{mode}: {refused}"
        );
        assert_no_page_content(&refused);
    }
    assert_eq!(
        launcher
            .effects
            .lock()
            .unwrap()
            .iter()
            .filter(|effect| **effect == "snapshot")
            .count(),
        1,
        "a refused snapshot still reached the capture: {:?}",
        launcher.effects.lock().unwrap()
    );
    let moved = (
        "https://attacker.example/moved".to_string(),
        "origin_scope".to_string(),
    );
    assert_eq!(refusal_records(&planes).await, [moved.clone(), moved]);
}

#[tokio::test]
async fn a_page_that_moves_itself_off_the_granted_origin_refuses_the_next_screenshot() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example"]).await;
    let before = response_body(&planes, 3, "browser.screenshot", json!({})).await;
    assert_eq!(before["outcome"], "ok", "{before}");

    launcher.page.commit("https://attacker.example/moved");

    let refused = response_body(&planes, 4, "browser.screenshot", json!({})).await;
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://attacker.example",
        "{refused}"
    );
    assert_no_page_content(&refused);
    assert_eq!(
        launcher
            .effects
            .lock()
            .unwrap()
            .iter()
            .filter(|effect| **effect == "screenshot")
            .count(),
        1,
        "a refused screenshot still reached the capture: {:?}",
        launcher.effects.lock().unwrap()
    );
}

#[tokio::test]
async fn a_navigation_that_commits_during_a_read_discards_the_capture() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example"]).await;

    for (corr, tool, arguments) in [
        (3, "browser.snapshot", json!({"mode": "ax"})),
        (5, "browser.snapshot", json!({"mode": "dom_full"})),
        (7, "browser.screenshot", json!({})),
    ] {
        launcher.page.commit("https://landed.example/final");
        *launcher.moves_during_capture.lock().unwrap() =
            vec![PageMove::Commit("https://attacker.example/mid-read")];

        let refused = response_body(&planes, corr, tool, arguments.clone()).await;
        assert_eq!(
            refused["outcome"], "page_navigated_during_read",
            "{tool} {arguments}: {refused}"
        );
        assert_eq!(
            refused["detail"]["authorized_origin"], "https://landed.example",
            "{refused}"
        );
        assert_eq!(
            refused["detail"]["live_origin"], "https://attacker.example",
            "{refused}"
        );
        assert_no_page_content(&refused);

        // The page is now on the ungranted origin, so reading again is
        // refused before any capture rather than repeating the race.
        let again = response_body(&planes, corr + 1, tool, arguments).await;
        assert_eq!(again["outcome"], "authorization_denied", "{again}");
        assert_no_page_content(&again);
    }

    // The same race inside navigate's read_page: the navigation itself is
    // reported, and the embedded read is withheld.
    launcher.page.commit("https://landed.example/final");
    *launcher.moves_during_capture.lock().unwrap() =
        vec![PageMove::Commit("https://attacker.example/mid-read")];
    let navigated = response_body(
        &planes,
        9,
        "browser.navigate",
        json!({
            "url": "https://requested.example/",
            "intent": "read the page as it lands",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false},
            "read_page": true
        }),
    )
    .await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(
        navigated["read_page"]["outcome"], "page_navigated_during_read",
        "{navigated}"
    );
    assert_no_page_content(&navigated);

    let records = refusal_records(&planes).await;
    assert_eq!(
        records
            .iter()
            .filter(
                |(addressing, reason)| addressing == "https://attacker.example/mid-read"
                    && reason == "page_navigated_during_read"
            )
            .count(),
        4,
        "{records:?}"
    );
}

#[tokio::test]
async fn a_page_that_stays_put_reads_as_before() {
    let (_launcher, planes) = navigated_to_landed(&["https://landed.example"]).await;

    for (corr, mode) in [(3, "ax"), (4, "dom_full")] {
        let read = response_body(&planes, corr, "browser.snapshot", json!({"mode": mode})).await;
        assert_eq!(read["outcome"], "ok", "{mode}: {read}");
        assert_eq!(
            read["source_origin"], "https://landed.example/final",
            "{read}"
        );
    }
    let ax = response_body(&planes, 5, "browser.snapshot", json!({"mode": "ax"})).await;
    assert!(
        ax["content"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe before")),
        "{ax}"
    );
    let screenshot = response_body(&planes, 6, "browser.screenshot", json!({})).await;
    assert_eq!(screenshot["outcome"], "ok", "{screenshot}");
    assert_eq!(
        screenshot["image"]["data_b64"], ONE_BY_ONE_PNG_B64,
        "{screenshot}"
    );
    assert_eq!(
        screenshot["source_origin"], "https://landed.example/final",
        "{screenshot}"
    );
    assert!(refusal_records(&planes).await.is_empty());
}

#[tokio::test]
async fn a_read_authorizes_against_the_live_origin_when_the_tracker_is_stale() {
    // Only the page's CURRENT origin is readable; the one the module tracked
    // is not. Authorizing against the tracker would refuse both reads.
    let (launcher, planes) = navigated_to_landed(&["https://moved.example"]).await;
    launcher.page.commit("https://moved.example/next");

    let snapshot = response_body(&planes, 3, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(
        snapshot["source_origin"], "https://moved.example/next",
        "{snapshot}"
    );
    let screenshot = response_body(&planes, 4, "browser.screenshot", json!({})).await;
    assert_eq!(screenshot["outcome"], "ok", "{screenshot}");
    assert_eq!(
        screenshot["source_origin"], "https://moved.example/next",
        "{screenshot}"
    );
}

#[tokio::test]
async fn a_round_trip_through_another_origin_during_a_read_discards_the_capture() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example"]).await;

    // Out and straight back by a new navigation, and out and back by history
    // traversal. Either way the page is on the authorized origin at both ends
    // of the capture, and either way the capture may hold the other page's
    // content. Checking only the origin would return it.
    let mut corr = 3;
    for moves in [
        vec![
            PageMove::Commit("https://attacker.example/mid-read"),
            PageMove::Commit("https://landed.example/final"),
        ],
        vec![
            PageMove::Commit("https://attacker.example/mid-read"),
            PageMove::Back,
        ],
    ] {
        for (tool, arguments) in [
            ("browser.snapshot", json!({"mode": "ax"})),
            ("browser.snapshot", json!({"mode": "dom_full"})),
            ("browser.screenshot", json!({})),
        ] {
            *launcher.moves_during_capture.lock().unwrap() = moves.clone();
            let refused = response_body(&planes, corr, tool, arguments.clone()).await;
            corr += 1;
            assert_eq!(
                refused["outcome"], "page_navigated_during_read",
                "{tool} {arguments}: {refused}"
            );
            assert_eq!(
                refused["detail"]["authorized_origin"], "https://landed.example",
                "{refused}"
            );
            assert_eq!(
                refused["detail"]["live_origin"], "https://landed.example",
                "{refused}"
            );
            assert_no_page_content(&refused);
        }
    }

    // Back where it started and holding still: reads work.
    let read = response_body(&planes, corr, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(read["outcome"], "ok", "{read}");
}

/// Launch the Chrome-like double on the example page with a grant that
/// covers clicking there, including a screenshot point whose target is not
/// classified. Returns the planes, the page, and the double's CDP command log.
async fn actuation_planes() -> (Planes, CommittedPage, Arc<Mutex<Vec<String>>>) {
    let page = CommittedPage::default();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let config = BrowserConfig {
        navigation_settle_deadline_ms: CLICK_SETTLE_DEADLINE_MS,
        ..config()
    };
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config.clone()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(CdpClickLauncher {
        scenario: ClickScenario::NoNavigation,
        snapshots: Arc::new(Mutex::new(0)),
        page: page.clone(),
        commands: Arc::clone(&commands),
    }));
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            Arc::clone(&planes.lease_clock),
            config.navigation_settle_deadline_ms,
        )
        .with_result_schema_enforcement(
            cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
        )
        .with_grants_installed(GrantStore::new([ActionGrant::new(
            "act",
            1,
            "test-session",
            Severity::new(4, true, true),
            [CLICK_PAGE_ORIGIN, "https://iana.org"],
        )
        .with_disclosed_hazards([HazardClass::UnverifiedFormContents])])),
    );
    launch_at(&planes, &page, CLICK_PAGE_ORIGIN).await;
    (planes, page, commands)
}

fn mouse_events(commands: &Arc<Mutex<Vec<String>>>) -> usize {
    commands
        .lock()
        .unwrap()
        .iter()
        .filter(|method| *method == "Input.dispatchMouseEvent")
        .count()
}

async fn click_ref(planes: &Planes, corr: u64, snapshot: &Value) -> Value {
    response_body(
        planes,
        corr,
        "browser.click",
        json!({
            "ref": snapshot["refs"][0]["ref"],
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "follow the Learn more link",
            "severity": {"tier": 4, "credential": true, "financial": true}
        }),
    )
    .await
}

async fn click_screenshot_point(planes: &Planes, corr: u64, screenshot: &Value) -> Value {
    response_body(
        planes,
        corr,
        "browser.click_point",
        json!({
            "snapshot_id": screenshot["snapshot_id"],
            "x_px": 0,
            "y_px": 0,
            "image_width_px": screenshot["image_width_px"],
            "image_height_px": screenshot["image_height_px"],
            "intent": "click the top-left point",
            "severity": {"tier": 4, "credential": true, "financial": true}
        }),
    )
    .await
}

#[tokio::test]
async fn screenshot_wire_preserves_liftable_image_and_click_dimensions() {
    let (planes, _page, commands) = actuation_planes().await;
    let screenshot = response_body(&planes, 100, "browser.screenshot", json!({})).await;
    assert_eq!(screenshot["outcome"], "ok", "{screenshot}");
    assert!(screenshot.get("image_png_b64").is_none(), "{screenshot}");
    let image = &screenshot["image"];
    assert_eq!(image["mime"], "image/png", "{screenshot}");
    assert_eq!(image["data_b64"], ONE_BY_ONE_PNG_B64, "{screenshot}");
    let png = cerebellum_core::serde_base64::decode(image["data_b64"].as_str().unwrap()).unwrap();
    assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
    // Read dimensions directly from the PNG header, independently of the
    // capture adapter, to check the reported size against the image bytes.
    let width = u32::from_be_bytes(png[16..20].try_into().unwrap());
    let height = u32::from_be_bytes(png[20..24].try_into().unwrap());
    assert!(width > 0 && height > 0);
    assert_eq!(image["width_px"], width);
    assert_eq!(image["height_px"], height);
    assert_eq!(screenshot["image_width_px"], width);
    assert_eq!(screenshot["image_height_px"], height);
    assert!(screenshot["snapshot_id"].as_str().is_some());

    let mut wrong_size = screenshot.clone();
    wrong_size["image_width_px"] = json!(width + 1);
    let before = mouse_events(&commands);
    let refused = click_screenshot_point(&planes, 101, &wrong_size).await;
    assert_eq!(
        refused["detail"]["reason_code"], "image_size_mismatch",
        "{refused}"
    );
    assert_eq!(mouse_events(&commands), before);
    let clicked = click_screenshot_point(&planes, 102, &screenshot).await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert!(mouse_events(&commands) > before);
}

#[tokio::test]
async fn an_action_on_a_snapshot_of_a_page_that_has_since_moved_dispatches_no_input() {
    let (planes, page, commands) = actuation_planes().await;
    let snapshot = response_body(&planes, 100, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let screenshot = response_body(&planes, 101, "browser.screenshot", json!({})).await;
    assert_eq!(screenshot["outcome"], "ok", "{screenshot}");

    // The page replaces itself with another site's document. The tracker
    // never hears of it, so both retained captures still look current.
    page.commit("https://attacker.example/moved");

    let clicked = click_ref(&planes, 102, &snapshot).await;
    let pointed = click_screenshot_point(&planes, 103, &screenshot).await;
    for refused in [&clicked, &pointed] {
        assert_eq!(refused["outcome"], "stale_snapshot", "{refused}");
        assert_eq!(
            refused["detail"]["reason_code"], "page_changed_since_snapshot",
            "{refused}"
        );
        assert_eq!(
            refused["detail"]["snapshot_origin"], CLICK_PAGE_ORIGIN,
            "{refused}"
        );
        assert_eq!(
            refused["detail"]["live_origin"], "https://attacker.example",
            "{refused}"
        );
    }
    assert_eq!(
        mouse_events(&commands),
        0,
        "input reached a page nobody snapshotted: {:?}",
        commands.lock().unwrap()
    );
}

#[tokio::test]
async fn an_action_after_a_same_document_fragment_change_still_dispatches() {
    let (planes, page, commands) = actuation_planes().await;
    let snapshot = response_body(&planes, 100, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let screenshot = response_body(&planes, 101, "browser.screenshot", json!({})).await;
    assert_eq!(screenshot["outcome"], "ok", "{screenshot}");

    // Chrome adds a history entry, with a new id, for a fragment change, but
    // the document and every element in it stay. The refs and pixels still
    // name what they named.
    page.fragment(&format!("{CLICK_PAGE_ORIGIN}/page#details"));

    let clicked = click_ref(&planes, 102, &snapshot).await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    let after_click = mouse_events(&commands);
    assert!(after_click > 0, "{:?}", commands.lock().unwrap());
    let pointed = click_screenshot_point(&planes, 103, &screenshot).await;
    assert_eq!(pointed["outcome"], "ok", "{pointed}");
    assert!(
        mouse_events(&commands) > after_click,
        "{:?}",
        commands.lock().unwrap()
    );
}

async fn blocking_grant_fixture() -> (Planes, Arc<RecordingLauncher>) {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://page.example").await;
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "test-session"),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"pj-browser-session-wire", "sessionKind":"primary", "effectiveCapabilityScope":["*"], "browserControlOperations":["browser.status"]}),
        ),
        scope: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        800,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(frame, &tx, &planes)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    (planes, launcher)
}

fn blocking_navigation(tier: u8) -> Frame {
    request(
        801,
        "browser.navigate",
        json!({"url":"https://requested.example/path", "intent":"read the page", "wait":"none", "severity":{"tier":tier,"credential":false,"financial":false}}),
    )
}

async fn consent_frame(rx: &mut mpsc::Receiver<Frame>) -> Frame {
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("prompt reply")
        .unwrap()
}

async fn answer_browser(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    question: &Frame,
    decision: &str,
) {
    let answer = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        question.header.corr,
        serde_json::to_vec(&json!({"decision":decision})).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(answer, tx, planes)
        .await
        .unwrap();
}

#[tokio::test]
async fn blocking_browser_grant_allow_continues_same_navigation() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = consent_frame(&mut rx).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let body: Value = serde_json::from_slice(&question.body).unwrap();
    assert_eq!(
        body["params"]["scope"]["origins"],
        json!(["https://requested.example"])
    );
    let p = &body["params"];
    assert_eq!(p["kind"], "consent");
    assert_eq!(
        p["target"],
        json!({"kind": "site", "label": "requested.example"})
    );
    assert_eq!(p["default"], "deny");
    assert_eq!(p["on_expiry"], "deny");
    assert_eq!(p["expires_in_ms"], 1_800_000);
    assert_eq!(
        p["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["allow", "deny"]
    );
    assert_eq!(
        p["requestedSchema"]["properties"]["decision"]["enum"],
        json!(["allow", "deny"])
    );
    assert_eq!(p["options"][0]["effect"], "grant");
    assert_eq!(p["options"][1]["effect"], "decline");
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow").await;
    let reply = consent_frame(&mut rx).await;
    assert_eq!(reply.header.corr, 801);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "ok", "{body}");
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);
    assert!(rx.try_recv().is_err(), "only one question and one reply");
    assert_eq!(planes.elicitor.outstanding(), 0);
    assert!(planes.browser.result_schema_findings().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_deny_never_navigates() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = consent_frame(&mut rx).await;
    assert_eq!(question.header.ty, FrameType::Request);
    answer_browser(&planes, &tx, &question, "deny").await;
    let reply = consent_frame(&mut rx).await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "authorization_denied", "{body}");
    assert_eq!(body["detail"]["decision"], "declined", "{body}");
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "no CDP navigation after deny"
    );
    assert!(rx.try_recv().is_err(), "no second question");
    assert!(planes.browser.result_schema_findings().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_timeout_keeps_late_answer() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_browser_consent_deadline_for_test(
        blocking_navigation(1),
        &tx,
        &planes,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    let question = consent_frame(&mut rx).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let reply = consent_frame(&mut rx).await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "consent_pending", "{body}");
    assert!(body["ask_id"].as_str().is_some());
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow").await;
    tokio::time::timeout(Duration::from_secs(1), async {
        while planes.management.browser_grant_count().await == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(reply.header.ty, FrameType::Response, "no second question");
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["outcome"],
        "ok"
    );
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);
    assert!(rx.try_recv().is_err());
    assert!(planes.browser.result_schema_findings().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_cancel_releases_registry() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let baseline = planes.elicitor.outstanding();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = consent_frame(&mut rx).await;
    assert_eq!(question.header.ty, FrameType::Request);
    assert_eq!(planes.elicitor.outstanding(), baseline + 1);
    let mut cancel = blocking_navigation(1);
    cancel.header.ty = FrameType::Cancel;
    cancel.body.clear();
    cerebellum::handle_frame_for_test(cancel, &tx, &planes)
        .await
        .unwrap();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["detail"]["decision"],
        "cancelled"
    );
    assert_eq!(planes.elicitor.outstanding(), baseline);
    answer_browser(&planes, &tx, &question, "allow").await;
    assert_eq!(planes.management.browser_grant_count().await, 0);
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_wait_releases_session_locks() {
    let (planes, _) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = consent_frame(&mut rx).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let subc_protocol::session::ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = planes.health.report()
    else {
        panic!("health metrics");
    };
    assert_eq!(metrics["inFlightActions"], 0);
    assert_eq!(metrics["awaitingConsent"], 1);
    let status = tokio::time::timeout(
        Duration::from_secs(1),
        invoke_existing(&planes, 802, "browser.status", json!({})),
    )
    .await
    .expect("status must not wait on consent");
    assert_eq!(status.header.ty, FrameType::Response);
    // Status reads the session table; also probe the CDP serialization lane so
    // future calls on this conversation cannot be stalled behind the question.
    let lane = tokio::time::timeout(
        Duration::from_secs(1),
        planes.browser.lane_for_test("test-session"),
    )
    .await
    .expect("conversation lane must not wait on consent");
    drop(lane);
    answer_browser(&planes, &tx, &question, "deny").await;
    consent_frame(&mut rx).await;
}

#[tokio::test]
async fn blocking_browser_grant_unfixable_refusals_never_ask() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(5), &tx, &planes)
        .await
        .unwrap();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(reply.header.ty, FrameType::Response, "tier 5 must not ask");
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["outcome"],
        "authorization_denied"
    );
    launcher.page.commit("about:blank");
    cerebellum::handle_frame_for_test(request(803, "browser.snapshot", json!({})), &tx, &planes)
        .await
        .unwrap();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "null origin must not ask"
    );
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["detail"]["attempted_origin"], "null", "{body}");
    assert!(rx.try_recv().is_err());
    assert_eq!(planes.elicitor.outstanding(), 0);
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_goodbye_and_drain_withdraw_even_after_timeout() {
    for timed_out in [false, true] {
        for draining in [false, true] {
            let (planes, _) = blocking_grant_fixture().await;
            let (tx, mut rx) = mpsc::channel(8);
            if timed_out {
                cerebellum::handle_browser_consent_deadline_for_test(
                    blocking_navigation(1),
                    &tx,
                    &planes,
                    Duration::from_millis(20),
                )
                .await
                .unwrap();
            } else {
                cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
                    .await
                    .unwrap();
            }
            let question = consent_frame(&mut rx).await;
            assert_eq!(question.header.ty, FrameType::Request);
            if timed_out {
                assert_eq!(
                    serde_json::from_slice::<Value>(&consent_frame(&mut rx).await.body).unwrap()
                        ["outcome"],
                    "consent_pending"
                );
            }
            let ending = Frame::build_with_version(
                PROTOCOL_VERSION,
                if draining {
                    FrameType::Push
                } else {
                    FrameType::Goodbye
                },
                Flags::new(false, Priority::Interactive, false),
                if draining { 0 } else { 9 },
                if draining { 0 } else { 3 },
                0,
                serde_json::to_vec(
                    &json!({"op":"module.draining", "reason":"restart", "deadline_ms":123}),
                )
                .unwrap(),
            )
            .unwrap();
            cerebellum::handle_frame_for_test(ending, &tx, &planes)
                .await
                .unwrap();
            tokio::time::timeout(Duration::from_secs(1), async {
                while planes.elicitor.outstanding() != 0 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("ending must withdraw the question");
            answer_browser(&planes, &tx, &question, "allow").await;
            assert_eq!(planes.management.browser_grant_count().await, 0);
        }
    }
}

// ---------------------------------------------------------------------------
// call_key: resends answered from the record, and tool.withdraw
// ---------------------------------------------------------------------------

/// A tool request on `channel`, epoch 3, carrying `call_key`.
fn keyed_on(channel: u16, corr: u64, name: &str, arguments: Value, call_key: &str) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        3,
        corr,
        serde_json::to_vec(&json!({"name": name, "arguments": arguments, "call_key": call_key}))
            .unwrap(),
    )
    .unwrap()
}

/// The navigation the blocking-grant fixture asks consent for, with a key.
fn keyed_navigation(channel: u16, corr: u64, call_key: &str) -> Frame {
    keyed_on(
        channel,
        corr,
        "browser.navigate",
        json!({"url":"https://requested.example/path", "intent":"read the page", "wait":"none", "severity":{"tier":1,"credential":false,"financial":false}}),
        call_key,
    )
}

fn withdraw_on(channel: u16, corr: u64, arguments: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        3,
        corr,
        serde_json::to_vec(&json!({"name": "tool.withdraw", "arguments": arguments})).unwrap(),
    )
    .unwrap()
}

/// Send `frame` and return the next frame the module writes.
async fn exchange(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    frame: Frame,
) -> Frame {
    cerebellum::handle_frame_for_test(frame, tx, planes)
        .await
        .unwrap();
    consent_frame(rx).await
}

async fn withdraw(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    channel: u16,
    corr: u64,
    call_key: &str,
) -> Frame {
    exchange(
        planes,
        tx,
        rx,
        withdraw_on(channel, corr, json!({"call_key": call_key})),
    )
    .await
}

fn error_code(frame: &Frame) -> String {
    assert_eq!(frame.header.ty, FrameType::Error, "expected an error frame");
    serde_json::from_slice::<Value>(&frame.body).unwrap()["code"]
        .as_str()
        .unwrap()
        .to_string()
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}

/// Bind a second route, 10/3, for the same conversation under a different
/// principal (`direct`), so calls on the two routes carry the same keys from
/// two principals. Only the session caller is admitted to act in a
/// conversation, so this principal's calls are refused before dispatch.
async fn bind_second_principal(planes: &Planes) {
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 10,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "test-session"),
        principal: Some(Principal::Direct),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"pj-browser-session-wire", "sessionKind":"primary", "effectiveCapabilityScope":["*"], "browserControlOperations":["browser.status"]}),
        ),
        scope: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        900,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
}

/// Run a keyed navigation through its consent question, answered allow, and
/// return its reply.
async fn allowed_keyed_navigation(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    call_key: &str,
) -> Frame {
    let question = exchange(planes, tx, rx, keyed_navigation(9, 801, call_key)).await;
    assert_eq!(question.header.ty, FrameType::Request, "a consent question");
    answer_browser(planes, tx, &question, "allow").await;
    let reply = consent_frame(rx).await;
    assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));
    reply
}

#[tokio::test]
async fn a_resend_after_completion_returns_the_recorded_reply_without_executing() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let first = allowed_keyed_navigation(&planes, &tx, &mut rx, "pf:resend-1").await;
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);

    let resent = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 802, "pf:resend-1"),
    )
    .await;
    assert_eq!(resent.header.ty, FrameType::Response);
    assert_eq!(resent.header.corr, 802, "the replay answers the resend");
    assert_eq!(resent.body, first.body, "the recorded reply, byte for byte");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["navigate"],
        "the resend navigated again"
    );
    assert!(rx.try_recv().is_err(), "the resend asked a second question");
}

#[tokio::test]
async fn a_resend_while_the_first_is_running_does_not_run_twice() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 801, "pf:inflight"),
    )
    .await;
    assert_eq!(question.header.ty, FrameType::Request);

    let resent = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 802, "pf:inflight"),
    )
    .await;
    assert_eq!(error_code(&resent), "call_in_flight");
    assert_eq!(resent.header.corr, 802);

    answer_browser(&planes, &tx, &question, "allow").await;
    let reply = consent_frame(&mut rx).await;
    assert_eq!(reply.header.corr, 801);
    assert_eq!(body(&reply)["outcome"], "ok");
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);
    assert!(rx.try_recv().is_err(), "a second question or reply");
}

#[tokio::test]
async fn the_same_call_key_from_two_principals_is_two_records() {
    let (planes, launcher) = blocking_grant_fixture().await;
    bind_second_principal(&planes).await;
    let (tx, mut rx) = mpsc::channel(8);
    let first = allowed_keyed_navigation(&planes, &tx, &mut rx, "shared-key").await;

    // The other principal's call with the same key is its own call: it is
    // not answered with the first one's reply. It is refused before dispatch,
    // since that principal may not act in a conversation, and its record
    // says so.
    let second = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(10, 803, "shared-key"),
    )
    .await;
    assert_eq!(
        error_code(&second),
        cerebellum_core::principal::SESSION_CALLER_NOT_ADMITTED,
        "one principal's key answered for another's call"
    );
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);

    // Each principal's withdraw reads its own record.
    let mine = withdraw(&planes, &tx, &mut rx, 9, 804, "shared-key").await;
    assert_eq!(
        body(&mine),
        json!({"answer": "completed", "result": body(&first)})
    );
    let theirs = withdraw(&planes, &tx, &mut rx, 10, 805, "shared-key").await;
    assert_eq!(
        body(&theirs),
        json!({"answer": "refused", "reason": "session_caller_not_admitted"})
    );
}

#[tokio::test]
async fn a_call_without_a_call_key_runs_as_before_and_leaves_no_record() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(&planes, &tx, &mut rx, blocking_navigation(1)).await;
    answer_browser(&planes, &tx, &question, "allow").await;
    assert_eq!(body(&consent_frame(&mut rx).await)["outcome"], "ok");
    let again = exchange(&planes, &tx, &mut rx, blocking_navigation(1)).await;
    assert_eq!(body(&again)["outcome"], "ok");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["navigate", "navigate"],
        "a keyless call is not deduplicated, so both ran"
    );
    assert_eq!(planes.calls.record_count(), 0);
}

#[tokio::test]
async fn withdrawing_a_completed_call_answers_its_result_identically_on_every_repeat() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let reply = allowed_keyed_navigation(&planes, &tx, &mut rx, "pf:done").await;
    let first = withdraw(&planes, &tx, &mut rx, 9, 810, "pf:done").await;
    assert_eq!(first.header.ty, FrameType::Response);
    assert_eq!(
        body(&first),
        json!({"answer": "completed", "result": body(&reply)})
    );
    let repeat = withdraw(&planes, &tx, &mut rx, 9, 811, "pf:done").await;
    assert_eq!(repeat.body, first.body, "a repeat answered differently");
}

#[tokio::test]
async fn withdrawing_a_running_call_is_already_started_with_outcome_unknown() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 801, "pf:running"),
    )
    .await;
    assert_eq!(question.header.ty, FrameType::Request);
    let first = withdraw(&planes, &tx, &mut rx, 9, 812, "pf:running").await;
    assert_eq!(
        body(&first),
        json!({"answer": "already_started", "outcome": "unknown"})
    );
    let repeat = withdraw(&planes, &tx, &mut rx, 9, 813, "pf:running").await;
    assert_eq!(repeat.body, first.body);
    answer_browser(&planes, &tx, &question, "deny").await;
    assert_eq!(consent_frame(&mut rx).await.header.corr, 801);
}

#[tokio::test]
async fn withdrawing_a_denied_call_is_refused_denied() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(&planes, &tx, &mut rx, keyed_navigation(9, 801, "pf:denied")).await;
    answer_browser(&planes, &tx, &question, "deny").await;
    assert_eq!(
        body(&consent_frame(&mut rx).await)["outcome"],
        "authorization_denied"
    );
    let answer = withdraw(&planes, &tx, &mut rx, 9, 814, "pf:denied").await;
    assert_eq!(
        body(&answer),
        json!({"answer": "refused", "reason": "denied"})
    );
}

#[tokio::test]
async fn withdrawing_a_consent_pending_call_closes_its_question_and_repeats_identically() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_browser_consent_deadline_for_test(
        keyed_navigation(9, 801, "pf:pending"),
        &tx,
        &planes,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    let question = consent_frame(&mut rx).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let pending = consent_frame(&mut rx).await;
    assert_eq!(
        body(&pending)["outcome"],
        "consent_pending",
        "{}",
        body(&pending)
    );

    let first = withdraw(&planes, &tx, &mut rx, 9, 815, "pf:pending").await;
    assert_eq!(body(&first), json!({"answer": "withdrawn"}));
    let repeat = withdraw(&planes, &tx, &mut rx, 9, 816, "pf:pending").await;
    assert_eq!(repeat.body, first.body, "a repeat answered differently");

    // The question closed: a late allow writes no grant, and nothing ran.
    answer_browser(&planes, &tx, &question, "allow").await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(planes.management.browser_grant_count().await, 0);
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn withdrawing_an_unknown_key_is_unknown_call() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let answer = withdraw(&planes, &tx, &mut rx, 9, 817, "pf:never-sent").await;
    assert_eq!(answer.header.ty, FrameType::Response);
    assert_eq!(body(&answer), json!({"answer": "unknown_call"}));
}

#[tokio::test]
async fn a_third_principal_is_refused_withdrawal() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_second_principal(&planes).await;
    let (tx, mut rx) = mpsc::channel(8);
    allowed_keyed_navigation(&planes, &tx, &mut rx, "pf:not-yours").await;
    let refused = withdraw(&planes, &tx, &mut rx, 10, 818, "pf:not-yours").await;
    assert_eq!(error_code(&refused), "withdraw_not_permitted");
}

#[tokio::test]
async fn malformed_keys_and_a_second_key_on_a_withdrawal_are_invalid_requests() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    for bad in [
        json!(""),
        json!("tab\tkey"),
        json!(7),
        json!("k".repeat(257)),
    ] {
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            9,
            3,
            820,
            serde_json::to_vec(
                &json!({"name": "browser.navigate", "arguments": {}, "call_key": bad}),
            )
            .unwrap(),
        )
        .unwrap();
        let reply = exchange(&planes, &tx, &mut rx, frame).await;
        assert_eq!(body(&reply)["outcome"], "invalid_request");
        assert_eq!(body(&reply)["detail"]["field"], "call_key");
    }
    let doubled = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        821,
        serde_json::to_vec(
            &json!({"name": "tool.withdraw", "arguments": {"call_key": "a"}, "call_key": "b"}),
        )
        .unwrap(),
    )
    .unwrap();
    let reply = exchange(&planes, &tx, &mut rx, doubled).await;
    assert_eq!(body(&reply)["detail"]["field"], "call_key");
    let scoped = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(9, 822, json!({"call_key": "a", "scope": {"owner": "x"}})),
    )
    .await;
    assert_eq!(body(&scoped)["detail"]["field"], "arguments.scope");
    let well_scoped = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            9,
            823,
            json!({"call_key": "a", "scope": {"owner": "reserved:prefrontal-core", "ref": "s-1", "scope_epoch": 4}}),
        ),
    )
    .await;
    // A well-shaped scope passes the shape check; what the answer is for an
    // unrecorded key is the unknown-key test's business.
    assert_ne!(
        body(&well_scoped)["outcome"],
        "invalid_request",
        "{}",
        body(&well_scoped)
    );
    assert!(launcher.effects.lock().unwrap().is_empty());
}

/// Planted text in a keyed call's arguments reaches neither the durable call
/// records nor a withdrawal's record, whether the call completed or was
/// refused.
#[tokio::test]
async fn typed_text_never_reaches_the_call_records() {
    const SECRET: &str = "PLANTED-SECRET-7f3c1e";
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = cerebellum::journal::call_records::InMemoryCallRecordStorage::new();
    planes.calls = Arc::new(cerebellum::journal::call_records::CallRecords::open(
        Box::new(storage.clone()),
        0,
    ));
    let (tx, mut rx) = mpsc::channel(8);

    // A completed call whose arguments carry the text.
    let question = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_on(
            9,
            801,
            "browser.navigate",
            json!({"url":"https://requested.example/path", "intent": SECRET, "wait":"none", "severity":{"tier":1,"credential":false,"financial":false}}),
            "pf:secret-1",
        ),
    )
    .await;
    answer_browser(&planes, &tx, &question, "allow").await;
    assert_eq!(body(&consent_frame(&mut rx).await)["outcome"], "ok");
    // A computer typing call whose text is the planted string. Whether this
    // host serves or refuses it, its record must not hold the text.
    exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_on(
            9,
            802,
            "computer_use",
            json!({"action": "type", "app": "com.apple.TextEdit", "text": SECRET}),
            "pf:secret-2",
        ),
    )
    .await;
    for (corr, key) in [(803, "pf:secret-1"), (804, "pf:secret-2")] {
        withdraw(&planes, &tx, &mut rx, 9, corr, key).await;
    }

    let stored = String::from_utf8(storage.contents().expect("records were written")).unwrap();
    assert!(
        stored.contains("pf:secret-1") && stored.contains("pf:secret-2"),
        "{stored}"
    );
    assert!(
        !stored.contains(SECRET),
        "planted text reached the call records: {stored}"
    );
}

// ---------------------------------------------------------------------------
// Session scopes: the daemon's stamp on the bind, recorded on calls, the
// owner's withdraw, and what a scope's end takes with it
// ---------------------------------------------------------------------------

const SCOPE_OWNER: &str = "reserved:prefrontal-core";
const SCOPE_CARRIER: &str = "reserved:broca";

fn scope_stamp(scope_epoch: u64, owner_authorized: bool) -> subc_protocol::scope::ScopeStamp {
    subc_protocol::scope::ScopeStamp {
        owner: Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        scope_ref: "s-1".into(),
        scope_epoch,
        kind: subc_protocol::scope::ScopeKind::Head,
        parent: None,
        parent_state: None,
        attributes: subc_protocol::scope::ScopeAttributes::default(),
        owner_authorized,
    }
}

/// Bind route `channel`/3 for the fixture's conversation under `principal`,
/// carrying `scope` exactly as the daemon would stamp it.
async fn bind_route(
    planes: &Planes,
    channel: u16,
    principal: Principal,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) {
    let bind = ModuleControlRequest::RouteBind {
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "test-session"),
        principal: Some(principal),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"pj-browser-session-wire", "sessionKind":"primary", "effectiveCapabilityScope":["*"], "browserControlOperations":["browser.status", "browser.close"]}),
        ),
        scope,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        900 + u64::from(channel),
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
}

fn reserved(module_id: &str) -> Principal {
    Principal::Reserved {
        module_id: module_id.into(),
    }
}

fn goodbye(channel: u16) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Goodbye,
        Flags::new(false, Priority::Interactive, false),
        channel,
        3,
        0,
        Vec::new(),
    )
    .unwrap()
}

/// Planes whose call records can be read back as the durable file holds them.
fn with_readable_call_records(
    planes: &mut Planes,
) -> cerebellum::journal::call_records::InMemoryCallRecordStorage {
    let storage = cerebellum::journal::call_records::InMemoryCallRecordStorage::new();
    planes.calls = Arc::new(cerebellum::journal::call_records::CallRecords::open(
        Box::new(storage.clone()),
        0,
    ));
    storage
}

/// A route opened without a scope is served exactly as before scopes: its
/// call record names no scope, its close tears the browser down at once as
/// `route_unbound` and ends the conversation's computer state as it always
/// did, and the module asks the daemon nothing.
#[tokio::test]
async fn an_unscoped_route_behaves_exactly_as_before_scopes() {
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);
    grant_browser(&planes, "https://requested.example", Vec::new()).await;
    let (tx, mut rx) = mpsc::channel(8);
    let refused = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_on(
            9,
            801,
            "browser.navigate",
            json!({"url":"https://requested.example/path", "intent":"read", "wait":"none", "severity":{"tier":1,"credential":false,"financial":false}}),
            "pf:unscoped",
        ),
    )
    .await;
    assert_eq!(refused.header.corr, 801);
    let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
    assert!(stored.contains("\"scope\":null"), "{stored}");

    assert!(planes.sessions.has_open_session("test-session"));
    cerebellum::handle_frame_for_test(goodbye(9), &tx, &planes)
        .await
        .unwrap();
    // The browser is torn down on the frame loop itself, before the GOODBYE
    // returns.
    assert!(!planes.sessions.has_open_session("test-session"));
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        rx.try_recv().is_err(),
        "an unscoped route's close sent the daemon a question"
    );
    assert_eq!(planes.scopes.control.outstanding(), 0);
    // Browser grants were never ended by a route close, and still are not.
    assert_eq!(planes.management.browser_grant_count().await, 1);
}

/// A keyed call on a scoped route records the stamp's owner, ref and epoch,
/// and no text from its arguments.
#[tokio::test]
async fn a_scoped_call_records_the_stamps_identity_and_no_text() {
    const SECRET: &str = "PLANTED-SECRET-5d2a90";
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);
    bind_route(
        &planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_on(
            12,
            801,
            "browser.navigate",
            json!({"url":"https://requested.example/path", "intent": SECRET, "wait":"none", "severity":{"tier":1,"credential":false,"financial":false}}),
            "pf:scoped-1",
        ),
    )
    .await;
    if question.header.ty == FrameType::Request {
        let answer = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            12,
            3,
            question.header.corr,
            serde_json::to_vec(&json!({"decision":"deny"})).unwrap(),
        )
        .unwrap();
        cerebellum::handle_frame_for_test(answer, &tx, &planes)
            .await
            .unwrap();
        consent_frame(&mut rx).await;
    }
    let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
    assert!(
        stored.contains(
            r#""scope":{"owner":"reserved:prefrontal-core","ref":"s-1","scope_epoch":4}"#
        ),
        "{stored}"
    );
    assert!(
        !stored.contains(SECRET),
        "planted text reached the call records: {stored}"
    );
}

/// The fixture for the owner's withdraw: a carrier's keyed call recorded under
/// scope s-1 at epoch 4, and the carrier's own answer for it.
async fn carrier_call_under_scope() -> (Planes, mpsc::Sender<Frame>, mpsc::Receiver<Frame>, Value) {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_route(&planes, 10, reserved("broca"), Some(scope_stamp(4, true))).await;
    let (tx, mut rx) = mpsc::channel(8);
    // Broca may not act in a conversation, so the call is refused before
    // dispatch; it is still a call recorded under the scope.
    let refused = exchange(&planes, &tx, &mut rx, keyed_navigation(10, 801, "br:1")).await;
    assert_eq!(
        error_code(&refused),
        cerebellum_core::principal::SESSION_CALLER_NOT_ADMITTED
    );
    let own = withdraw(&planes, &tx, &mut rx, 10, 802, "br:1").await;
    let own = body(&own);
    assert_eq!(
        own,
        json!({"answer": "refused", "reason": "session_caller_not_admitted"})
    );
    (planes, tx, rx, own)
}

#[tokio::test]
async fn the_authorized_owner_naming_the_carrier_gets_the_carriers_answer() {
    let (planes, tx, mut rx, own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    let answer = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            11,
            803,
            json!({"call_key": "br:1", "carrier": SCOPE_CARRIER}),
        ),
    )
    .await;
    assert_eq!(answer.header.ty, FrameType::Response);
    assert_eq!(body(&answer), own, "the owner was answered differently");
    // Naming the route's own scope is allowed and changes nothing.
    let scoped = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            11,
            804,
            json!({"call_key": "br:1", "carrier": SCOPE_CARRIER, "scope": {"owner": SCOPE_OWNER, "ref": "s-1", "scope_epoch": 4}}),
        ),
    )
    .await;
    assert_eq!(body(&scoped), own);
}

#[tokio::test]
async fn an_owner_withdraw_without_a_carrier_is_an_invalid_request() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    let refused = withdraw(&planes, &tx, &mut rx, 11, 803, "br:1").await;
    assert_eq!(body(&refused)["outcome"], "invalid_request");
    assert_eq!(body(&refused)["detail"]["field"], "arguments.carrier");
    assert_eq!(body(&refused)["detail"]["reason_code"], "missing_field");
}

#[tokio::test]
async fn a_carrier_naming_another_carrier_is_an_invalid_request() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(&planes, 13, reserved("aft"), Some(scope_stamp(4, true))).await;
    let refused = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            13,
            803,
            json!({"call_key": "br:1", "carrier": SCOPE_CARRIER}),
        ),
    )
    .await;
    assert_eq!(body(&refused)["outcome"], "invalid_request");
    assert_eq!(body(&refused)["detail"]["field"], "arguments.carrier");
    // The carrier itself naming its own label is its ordinary withdraw.
    let own = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            10,
            804,
            json!({"call_key": "br:1", "carrier": SCOPE_CARRIER}),
        ),
    )
    .await;
    assert_eq!(
        body(&own),
        json!({"answer": "refused", "reason": "session_caller_not_admitted"})
    );
}

#[tokio::test]
async fn an_owner_naming_a_carrier_that_raised_no_such_call_learns_nothing() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    let answer = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            11,
            803,
            json!({"call_key": "br:1", "carrier": "reserved:aft"}),
        ),
    )
    .await;
    assert_eq!(body(&answer), json!({"answer": "unknown_call"}));
}

#[tokio::test]
async fn an_owner_the_daemon_does_not_authorize_may_not_withdraw() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, false)),
    )
    .await;
    let refused = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            11,
            803,
            json!({"call_key": "br:1", "carrier": SCOPE_CARRIER}),
        ),
    )
    .await;
    assert_eq!(error_code(&refused), "withdraw_not_permitted");
}

#[tokio::test]
async fn an_owner_at_another_epoch_may_not_withdraw() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(5, true)),
    )
    .await;
    let refused = exchange(
        &planes,
        &tx,
        &mut rx,
        withdraw_on(
            11,
            803,
            json!({"call_key": "br:1", "carrier": SCOPE_CARRIER}),
        ),
    )
    .await;
    assert_eq!(error_code(&refused), "withdraw_not_permitted");
}

#[tokio::test]
async fn a_named_scope_that_differs_from_the_stamp_is_refused() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    for (corr, scope) in [
        (
            803,
            json!({"owner": SCOPE_OWNER, "ref": "s-other", "scope_epoch": 4}),
        ),
        (
            804,
            json!({"owner": SCOPE_OWNER, "ref": "s-1", "scope_epoch": 3}),
        ),
        (
            805,
            json!({"owner": "reserved:aft", "ref": "s-1", "scope_epoch": 4}),
        ),
    ] {
        let refused = exchange(
            &planes,
            &tx,
            &mut rx,
            withdraw_on(
                11,
                corr,
                json!({"call_key": "br:1", "carrier": SCOPE_CARRIER, "scope": scope}),
            ),
        )
        .await;
        assert_eq!(body(&refused)["outcome"], "invalid_request", "{scope}");
        assert_eq!(body(&refused)["detail"]["field"], "arguments.scope");
    }
}

/// The scoped-route revocation fixture: the fixture's browser open for the
/// conversation, route 12 bound under scope s-1 at epoch 4, one browser grant
/// held and one browser grant question open for the conversation. Returns the
/// open question's id.
async fn scoped_browser(planes: &Planes) -> String {
    bind_route(
        planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    grant_browser(planes, "https://requested.example", Vec::new()).await;
    let question = planes
        .management
        .browser_grant_question_for_test(
            "test-session",
            vec!["https://other.example".to_string()],
            Vec::new(),
        )
        .await;
    assert!(planes.sessions.has_open_session("test-session"));
    assert_eq!(planes.management.browser_grant_count().await, 1);
    assert!(
        planes
            .management
            .browser_grant_question_open(&question.ask_id)
            .await
    );
    question.ask_id
}

/// Close route 12 and return the `scope.describe` it makes the module send.
async fn close_scoped_route(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
) -> Frame {
    cerebellum::handle_frame_for_test(goodbye(12), tx, planes)
        .await
        .unwrap();
    // Closing the route alone leaves the browser open while the daemon is
    // asked about the scope.
    assert!(planes.sessions.has_open_session("test-session"));
    next_describe(rx).await
}

async fn next_describe(rx: &mut mpsc::Receiver<Frame>) -> Frame {
    let question = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the module asks the daemon about the scope")
        .unwrap();
    assert_eq!(question.header.ty, FrameType::Request);
    assert_eq!(question.header.channel, 0);
    assert_eq!(
        body(&question),
        json!({"op": "scope.describe", "owner": {"kind": "reserved", "module_id": "prefrontal-core"}, "ref": "s-1"})
    );
    question
}

/// Answer a `scope.describe` as the daemon would.
async fn answer_describe(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    question: &Frame,
    ty: FrameType,
    answer: Value,
) {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        ty,
        cerebellum::control_flags(),
        0,
        0,
        question.header.corr,
        serde_json::to_vec(&answer).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(frame, tx, planes)
        .await
        .unwrap();
}

fn describe_answer(
    status: &str,
    scope_epoch: Option<u64>,
    synced: bool,
    configured: bool,
) -> Value {
    let mut answer = json!({
        "op": "scope.describe",
        "status": status,
        "daemon_incarnation": "test-incarnation",
        "owner_synced": synced,
        "owner_configured": configured,
    });
    if let Some(epoch) = scope_epoch {
        answer["scope_epoch"] = json!(epoch);
    }
    answer
}

async fn wait_until_closed(planes: &Planes) {
    tokio::time::timeout(Duration::from_secs(5), async {
        while planes.sessions.has_open_session("test-session") {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the scope's browser closes");
}

/// A definitive end of the scope closes its browser as `scope_revoked`, drops
/// the conversation's browser grants, and closes its open question so a late
/// answer grants nothing. `browser.status` then reports the outcome through
/// the production reply boundary, which withholds a reply its result schema
/// does not declare.
#[tokio::test]
async fn a_definitive_scope_end_closes_the_browser_drops_grants_and_closes_the_question() {
    for answer in [
        describe_answer("ended", Some(4), true, true),
        describe_answer("live", Some(5), true, true),
        describe_answer("not_live", None, true, true),
        describe_answer("not_live", None, false, false),
    ] {
        let (planes, _launcher) = blocking_grant_fixture().await;
        let ask_id = scoped_browser(&planes).await;
        let (tx, mut rx) = mpsc::channel(8);
        let question = close_scoped_route(&planes, &tx, &mut rx).await;
        answer_describe(&planes, &tx, &question, FrameType::Response, answer.clone()).await;
        wait_until_closed(&planes).await;
        assert_eq!(planes.management.browser_grant_count().await, 0, "{answer}");
        assert!(
            !planes.management.browser_grant_question_open(&ask_id).await,
            "the scope's open question survived its end: {answer}"
        );
        assert!(
            !planes
                .management
                .settle_browser_grant(&ask_id, Some(&json!({"decision": "allow"})))
                .await
        );
        assert_eq!(planes.management.browser_grant_count().await, 0);

        let status = exchange(
            &planes,
            &tx,
            &mut rx,
            request(830, "browser.status", json!({})),
        )
        .await;
        assert_eq!(status.header.ty, FrameType::Response, "{}", body(&status));
        assert_eq!(
            body(&status)["terminal_outcome"],
            "scope_revoked",
            "{}",
            body(&status)
        );
        // `browser.close` of the revoked session answers the outcome through
        // the same Withhold boundary. Asked on an unscoped route of the same
        // conversation that may close.
        bind_route(&planes, 17, reserved("prefrontal-core"), None).await;
        let session_id = body(&status)["browser_session_id"].clone();
        assert!(session_id.is_string(), "{}", body(&status));
        let closed = exchange(
            &planes,
            &tx,
            &mut rx,
            request_on(
                17,
                831,
                "browser.close",
                json!({"browser_session_id": session_id}),
            ),
        )
        .await;
        assert_eq!(closed.header.ty, FrameType::Response, "{}", body(&closed));
        assert_eq!(
            body(&closed)["outcome"],
            "scope_revoked",
            "{}",
            body(&closed)
        );
    }
}

/// A tool request on `channel`, epoch 3.
fn request_on(channel: u16, corr: u64, name: &str, arguments: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        3,
        corr,
        serde_json::to_vec(&json!({"name": name, "arguments": arguments})).unwrap(),
    )
    .unwrap()
}

/// Bind a route stamped `stamp` and return the daemon-bound reply frame,
/// which a refused bind answers with an error.
async fn bind_reply(
    planes: &Planes,
    channel: u16,
    stamp: subc_protocol::scope::ScopeStamp,
) -> Frame {
    let bind = ModuleControlRequest::RouteBind {
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "test-session"),
        principal: Some(reserved("prefrontal-core")),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"pj-browser-session-wire", "sessionKind":"primary", "effectiveCapabilityScope":["*"], "browserControlOperations":["browser.status", "browser.close"]}),
        ),
        scope: Some(stamp),
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        950 + u64::from(channel),
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    rx.recv().await.unwrap()
}

/// A grant a person gave the epoch-1 session is gone the moment an epoch-2
/// route of the same scope binds, with no watcher running (route 12 never
/// closed), so nothing on the new route is served under it.
#[tokio::test]
async fn a_grant_made_under_epoch_1_is_not_usable_from_an_epoch_2_route() {
    let (planes, launcher) = blocking_grant_fixture().await;
    bind_route(
        &planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(1, true)),
    )
    .await;
    grant_browser(&planes, "https://requested.example", Vec::new()).await;
    assert_eq!(planes.management.browser_grant_count().await, 1);

    let bound = bind_reply(&planes, 15, scope_stamp(2, true)).await;
    assert_eq!(bound.header.ty, FrameType::Response, "{}", body(&bound));
    // Gone before the bind was answered, so before any call on route 15.
    assert_eq!(planes.management.browser_grant_count().await, 0);
    assert!(!planes
        .scopes
        .is_watching(&cerebellum::scope_watch::ScopeKey::from_stamp(
            &scope_stamp(1, true)
        )));

    let (tx, mut rx) = mpsc::channel(8);
    let navigated = exchange(
        &planes,
        &tx,
        &mut rx,
        request_on(
            15,
            840,
            "browser.navigate",
            json!({"url":"https://requested.example/path", "intent":"read", "wait":"none", "severity":{"tier":1,"credential":false,"financial":false}}),
        ),
    )
    .await;
    assert!(
        navigated.header.ty == FrameType::Request || body(&navigated)["outcome"] != "ok",
        "the epoch-2 route navigated under the epoch-1 grant: {}",
        body(&navigated)
    );
    assert!(
        !launcher.effects.lock().unwrap().contains(&"navigate"),
        "navigated under the old session's grant"
    );
}

/// A question the epoch-1 session left open grants nothing when answered
/// after the epoch-2 bind.
#[tokio::test]
async fn an_open_epoch_1_question_answered_after_the_epoch_2_bind_grants_nothing() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_route(
        &planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(1, true)),
    )
    .await;
    let question = planes
        .management
        .browser_grant_question_for_test(
            "test-session",
            vec!["https://asked.example".to_string()],
            Vec::new(),
        )
        .await;
    let bound = bind_reply(&planes, 15, scope_stamp(2, true)).await;
    assert_eq!(bound.header.ty, FrameType::Response);
    assert!(
        !planes
            .management
            .browser_grant_question_open(&question.ask_id)
            .await
    );
    assert!(
        !planes
            .management
            .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow"})))
            .await
    );
    assert_eq!(planes.management.browser_grant_count().await, 0);
}

/// An epoch-2 bind while the epoch-1 session's browser is open closes it as
/// `scope_revoked`.
#[tokio::test]
async fn an_epoch_2_bind_closes_the_epoch_1_browser_as_scope_revoked() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_route(
        &planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(1, true)),
    )
    .await;
    assert!(planes.sessions.has_open_session("test-session"));
    let bound = bind_reply(&planes, 15, scope_stamp(2, true)).await;
    assert_eq!(bound.header.ty, FrameType::Response);
    wait_until_closed(&planes).await;
    let (tx, mut rx) = mpsc::channel(8);
    let status = exchange(
        &planes,
        &tx,
        &mut rx,
        request_on(15, 841, "browser.status", json!({})),
    )
    .await;
    assert_eq!(
        body(&status)["terminal_outcome"],
        "scope_revoked",
        "{}",
        body(&status)
    );
}

/// A bind at a lower epoch than one already bound is an ended session: refused
/// `scope_ended` and never bound. A route of the replaced epoch that is still
/// bound serves nothing more either.
#[tokio::test]
async fn a_stale_lower_epoch_bind_is_refused() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_route(
        &planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(1, true)),
    )
    .await;
    let bound = bind_reply(&planes, 15, scope_stamp(2, true)).await;
    assert_eq!(bound.header.ty, FrameType::Response);
    let stale = bind_reply(&planes, 16, scope_stamp(1, true)).await;
    assert_eq!(error_code(&stale), "scope_ended");
    let (tx, mut rx) = mpsc::channel(8);
    let unbound = exchange(
        &planes,
        &tx,
        &mut rx,
        request_on(16, 842, "browser.status", json!({})),
    )
    .await;
    assert_eq!(error_code(&unbound), "route_not_bound");
    let replaced = exchange(
        &planes,
        &tx,
        &mut rx,
        request_on(12, 843, "browser.status", json!({})),
    )
    .await;
    assert_eq!(error_code(&replaced), "scope_ended");
    // The live epoch is served.
    let current = exchange(
        &planes,
        &tx,
        &mut rx,
        request_on(15, 844, "browser.status", json!({})),
    )
    .await;
    assert_eq!(current.header.ty, FrameType::Response, "{}", body(&current));
}
/// Every answer that does not definitively end the scope leaves the browser,
/// the grants and the open question in place, and the scope is asked about
/// again while its browser stays open. An owner that has not synced since a
/// daemon restart is the case that matters most: a restart must not destroy
/// an agent's work.
#[tokio::test]
async fn a_non_definitive_answer_leaves_the_browser_the_grants_and_the_question() {
    let restart_like = (
        FrameType::Response,
        describe_answer("not_live", None, false, true),
    );
    for (ty, answer) in [
        restart_like,
        (
            FrameType::Response,
            describe_answer("live", Some(4), true, true),
        ),
        (
            FrameType::Response,
            describe_answer("ended", Some(3), true, true),
        ),
        (
            FrameType::Error,
            json!({"code": "unknown_control_op", "message": "this daemon has no scope.describe"}),
        ),
    ] {
        let (mut planes, _launcher) = blocking_grant_fixture().await;
        planes.scopes = Arc::new(cerebellum::scope_watch::ScopeRevocation::with_intervals(
            Duration::from_millis(40),
            Duration::from_secs(5),
        ));
        let ask_id = scoped_browser(&planes).await;
        let (tx, mut rx) = mpsc::channel(8);
        let question = close_scoped_route(&planes, &tx, &mut rx).await;
        answer_describe(&planes, &tx, &question, ty, answer.clone()).await;
        // Asked again once the interval passes, because the browser is still
        // open and no route under the scope is bound.
        let again = next_describe(&mut rx).await;
        assert!(planes.sessions.has_open_session("test-session"), "{answer}");
        assert_eq!(planes.management.browser_grant_count().await, 1, "{answer}");
        assert!(
            planes.management.browser_grant_question_open(&ask_id).await,
            "{answer}"
        );
        // A definitive answer on the re-ask then ends it.
        answer_describe(
            &planes,
            &tx,
            &again,
            FrameType::Response,
            describe_answer("ended", Some(4), true, true),
        )
        .await;
        wait_until_closed(&planes).await;
        assert_eq!(planes.management.browser_grant_count().await, 0);
    }
}

/// No answer at all within the describe bound is not an end either.
#[tokio::test]
async fn an_unanswered_describe_leaves_everything_in_place() {
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    planes.scopes = Arc::new(cerebellum::scope_watch::ScopeRevocation::with_intervals(
        Duration::from_secs(60),
        Duration::from_millis(30),
    ));
    let ask_id = scoped_browser(&planes).await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = close_scoped_route(&planes, &tx, &mut rx).await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    // An answer after the bound finds nobody waiting and is dropped.
    answer_describe(
        &planes,
        &tx,
        &question,
        FrameType::Response,
        describe_answer("ended", Some(4), true, true),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(planes.sessions.has_open_session("test-session"));
    assert_eq!(planes.management.browser_grant_count().await, 1);
    assert!(planes.management.browser_grant_question_open(&ask_id).await);
    assert_eq!(planes.scopes.control.outstanding(), 0);
}

/// While another route under the same scope is still bound, a non-definitive
/// answer is not asked about again: that route's own close will ask.
#[tokio::test]
async fn a_scope_with_a_route_still_bound_is_not_polled() {
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    planes.scopes = Arc::new(cerebellum::scope_watch::ScopeRevocation::with_intervals(
        Duration::from_millis(20),
        Duration::from_secs(5),
    ));
    scoped_browser(&planes).await;
    bind_route(
        &planes,
        14,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = close_scoped_route(&planes, &tx, &mut rx).await;
    answer_describe(
        &planes,
        &tx,
        &question,
        FrameType::Response,
        describe_answer("live", Some(4), true, true),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(120)).await;
    assert!(
        rx.try_recv().is_err(),
        "a scope with a bound route was polled"
    );
    assert!(planes.sessions.has_open_session("test-session"));
}
