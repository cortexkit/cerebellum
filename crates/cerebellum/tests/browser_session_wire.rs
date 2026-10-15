// Separate binary: re-executes current_exe() with exact child-test names.
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

#[path = "../examples/support/cingulate_answer.rs"]
mod cingulate_answer;
use cingulate_answer::cingulate::ScriptedCarrier;

#[path = "support/browser_stable_refs.rs"]
mod stable_refs;

#[path = "support/browser_queue.rs"]
mod browser_queue;

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
            .settle_browser_grant(
                &question.ask_id,
                Some(&json!({"decision": "allow_conversation"}))
            )
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
        role_versions: None,
        call_mode: None,
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
        scope: Some(cingulate_answer::cingulate::stamp(
            "pj-browser-session-wire",
        )),
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
    let reply = cingulate_answer::answer_cards(
        planes,
        opening,
        json!({"decision": "allow_conversation"}),
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

/// The first ref a snapshot reply's page text names: a ref is the first word
/// of a line in the default view, and a row's `ref` in the ax view.
fn first_ref(snapshot: &Value) -> String {
    let text = snapshot["state_text"]
        .as_str()
        .unwrap_or_else(|| panic!("no state_text: {snapshot}"));
    text.lines()
        .find_map(|line| match serde_json::from_str::<Value>(line) {
            Ok(row) => row["ref"].as_str().map(str::to_string),
            Err(_) => line
                .split_whitespace()
                .next()
                .filter(|word| {
                    word.len() > 1
                        && word.starts_with('e')
                        && word[1..].chars().all(|c| c.is_ascii_digit())
                })
                .map(str::to_string),
        })
        .unwrap_or_else(|| panic!("no ref in state_text: {snapshot}"))
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
        // A link into a local service keeps the elevated tier and explicit
        // destination consent even though ordinary public links are reading.
        ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame-main", 42),
            TargetKind::Anchor,
        )
        .destination("http://127.0.0.1:8080/domains/example")
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
            frame_document: None,
            captured: SnapshotRef::new("e1", "button", "Sign in", 0).unwrap(),
            frame_path: vec!["frame-main".into()],
            backend_identity: Some(BackendNodeIdentity::new("target", "frame-main", 42).unwrap()),
            raw_role: Some("button".into()),
            raw_name: Some("Sign in".into()),
            classification: Ok(Box::new(classification)),
        }],
        ax_truncated: false,
        refs_truncated: false,
        facts: Default::default(),
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
    /// The capture returns an error once the moves queued ahead of this one
    /// in the same list have been applied, as Chrome's accessibility read
    /// does once the document it was reading is gone.
    CaptureFails,
}

#[derive(Default)]
struct RecordingLauncher {
    launches: Arc<Mutex<usize>>,
    accepted_launches: Mutex<Vec<cerebellum_core::identity::AcceptedBindFacts>>,
    profile_service: Option<cerebellum::browser_launch_service::ProductionLaunchService>,
    profile_directories: Mutex<Vec<std::path::PathBuf>>,
    page: CommittedPage,
    /// Navigations the page commits while a snapshot or screenshot is being
    /// captured, standing for ones that land between the read's
    /// authorization and its return. Consumed by the next capture.
    moves_during_capture: Arc<Mutex<Vec<PageMove>>>,
    effects: Arc<Mutex<Vec<&'static str>>>,
    dropdowns: Option<Arc<Mutex<stable_refs::Dropdowns>>>,
    frame_fixture: Option<Arc<Mutex<FrameFixture>>>,
    hazardous_target: bool,
    cross_site_link_target: bool,
    present_error: Option<&'static str>,
    cookie_value: Option<&'static str>,
    cookie_grows_on_poll: bool,
    credential_field_then_clears: bool,
    /// Shared with every process this launcher starts; setting it makes them
    /// all report that the browser has exited, as a crashed browser would.
    exited: Arc<Mutex<bool>>,
    /// While set, every navigation parks after recording its effect, standing
    /// for a CDP command that does not return.
    navigate_hold: Arc<NavigateHold>,
}

#[derive(Default)]
struct NavigateHold {
    held: Mutex<bool>,
    wake: std::sync::Condvar,
}

/// Releases a held navigation when dropped, so a failing test still lets the
/// parked worker end instead of hanging its runtime's shutdown.
struct HeldNavigation(Arc<NavigateHold>);

impl Drop for HeldNavigation {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl NavigateHold {
    fn hold(self: &Arc<Self>) -> HeldNavigation {
        *self.held.lock().unwrap() = true;
        HeldNavigation(Arc::clone(self))
    }

    fn release(&self) {
        *self.held.lock().unwrap() = false;
        self.wake.notify_all();
    }

    fn wait(&self) {
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.wake.wait(held).unwrap();
        }
    }
}

impl BrowserSessionLauncher for RecordingLauncher {
    fn launch(
        &self,
        accepted: &cerebellum_core::identity::AcceptedBindFacts,
        session_id: &str,
    ) -> Result<LaunchedBrowser, Value> {
        if let Some(service) = &self.profile_service {
            let directory = service.take_and_return_profile_custody(accepted, session_id)?;
            self.profile_directories.lock().unwrap().push(directory);
        }
        self.accepted_launches
            .lock()
            .unwrap()
            .push(accepted.clone());
        *self.launches.lock().unwrap() += 1;
        Ok(LaunchedBrowser {
            process: Box::new(RecordingProcess {
                effects: Arc::clone(&self.effects),
                page: self.page.clone(),
                moves_during_capture: Arc::clone(&self.moves_during_capture),
                clicked: false,
                dropdowns: self.dropdowns.clone(),
                frame_fixture: self.frame_fixture.clone(),
                hazardous_target: self.hazardous_target,
                cross_site_link_target: self.cross_site_link_target,
                present_error: self.present_error,
                cookie_value: self.cookie_value,
                cookie_grows_on_poll: self.cookie_grows_on_poll,
                credential_field_then_clears: self.credential_field_then_clears,
                cookie_reads: 0,
                exited: Arc::clone(&self.exited),
                navigate_hold: Arc::clone(&self.navigate_hold),
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

#[derive(Default)]
struct FrameFixture {
    financial: bool,
    action_origin_override: Option<String>,
    churn_on_screenshot: bool,
    documents: Vec<cerebellum::snapshot_store::FrameDocument>,
    readable: Vec<cerebellum::snapshot_store::FrameDocument>,
}

struct RecordingProcess {
    effects: Arc<Mutex<Vec<&'static str>>>,
    page: CommittedPage,
    moves_during_capture: Arc<Mutex<Vec<PageMove>>>,
    clicked: bool,
    dropdowns: Option<Arc<Mutex<stable_refs::Dropdowns>>>,
    frame_fixture: Option<Arc<Mutex<FrameFixture>>>,
    hazardous_target: bool,
    cross_site_link_target: bool,
    present_error: Option<&'static str>,
    cookie_value: Option<&'static str>,
    cookie_grows_on_poll: bool,
    credential_field_then_clears: bool,
    cookie_reads: usize,
    exited: Arc<Mutex<bool>>,
    navigate_hold: Arc<NavigateHold>,
}

impl RecordingProcess {
    /// Apply the moves queued for this capture; whether the capture fails.
    fn apply_moves_during_capture(&mut self) -> bool {
        let mut capture_fails = false;
        for page_move in std::mem::take(&mut *self.moves_during_capture.lock().unwrap()) {
            match page_move {
                PageMove::Commit(url) => self.page.commit(url),
                PageMove::Back => self.page.back(),
                PageMove::CaptureFails => capture_fails = true,
            }
        }
        capture_fails
    }
}

impl OwnedBrowserProcess for RecordingProcess {
    fn scroll(
        &mut self,
        _: &str,
        target: &cerebellum::browser_session::BrowserScrollTarget,
        _: u64,
    ) -> Result<(), NavigationDriveError> {
        use cerebellum::browser_session::BrowserScrollTarget;
        let effect = match target {
            BrowserScrollTarget::Element(identity) if identity.backend_node_id == 42 => {
                "scroll_ref"
            }
            BrowserScrollTarget::Page { x: 0, y: 600 } => "scroll_page",
            _ => "unexpected_scroll",
        };
        self.effects.lock().unwrap().push(effect);
        Ok(())
    }

    fn frame_documents(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<Vec<cerebellum::snapshot_store::FrameDocument>, NavigationDriveError> {
        Ok(self
            .frame_fixture
            .as_ref()
            .map(|f| f.lock().unwrap().documents.clone())
            .unwrap_or_default())
    }
    fn set_read_frames(
        &mut self,
        frames: Vec<cerebellum::snapshot_store::FrameDocument>,
    ) -> Result<(), NavigationDriveError> {
        if let Some(fixture) = &self.frame_fixture {
            fixture.lock().unwrap().readable = frames;
        }
        Ok(())
    }
    fn prepare_frame(
        &mut self,
        _: &str,
        expected: &cerebellum::snapshot_store::FrameDocument,
        _: u64,
    ) -> Result<bool, NavigationDriveError> {
        Ok(self.frame_fixture.as_ref().is_some_and(|f| {
            f.lock()
                .unwrap()
                .documents
                .iter()
                .any(|live| live.same_document(expected))
        }))
    }

    fn classify_point(
        &mut self,
        _: &str,
        _: BrowserClickPosition,
        epoch: u64,
        _: &str,
        _: u64,
    ) -> Result<
        Result<
            cerebellum::classification::NonTypeClassificationRecord,
            cerebellum::classification::ClassificationUnavailable,
        >,
        NavigationDriveError,
    > {
        let fixture = self
            .frame_fixture
            .as_ref()
            .ok_or(NavigationDriveError::Unavailable)?
            .lock()
            .unwrap();
        let frame = fixture
            .documents
            .iter()
            .find(|frame| frame.parent_id.is_some())
            .ok_or(NavigationDriveError::Unavailable)?;
        Ok(Ok(frame_submit_record(
            frame,
            epoch,
            if fixture.financial {
                "cc-number"
            } else if self.hazardous_target {
                "current-password"
            } else {
                ""
            },
        )))
    }
    fn point_frame_document(&mut self) -> Option<cerebellum::snapshot_store::FrameDocument> {
        self.frame_fixture.as_ref().and_then(|fixture| {
            let fixture = fixture.lock().unwrap();
            let mut frame = fixture
                .documents
                .iter()
                .find(|frame| frame.parent_id.is_some())
                .cloned()?;
            if let Some(origin) = &fixture.action_origin_override {
                frame.origin = origin.clone();
                frame.url = format!("{origin}/frame");
            }
            Some(frame)
        })
    }

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
        self.navigate_hold.wait();
        let now = std::time::Instant::now();
        self.page.commit("https://landed.example:8443/final");
        tracker.url_final = Some("https://landed.example:8443/final".into());
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
        if let Some(dropdowns) = &self.dropdowns {
            return Ok(dropdowns
                .lock()
                .unwrap()
                .observation(document_epoch, current_origin));
        }
        let mut observation = snapshot_observation(
            self.clicked,
            self.hazardous_target,
            self.cross_site_link_target,
            document_epoch,
            current_origin,
        );
        if let Some(fixture) = &self.frame_fixture {
            let fixture = fixture.lock().unwrap();
            if let Some(frame) = fixture.documents.iter().find(|f| f.parent_id.is_some()) {
                if fixture.readable.contains(frame) {
                    observation.dom_text = Some("<button>Sign in</button>".into());
                    let mut captured_frame = frame.clone();
                    if let Some(origin) = &fixture.action_origin_override {
                        captured_frame.origin = origin.clone();
                        captured_frame.url = format!("{origin}/frame");
                    }
                    observation.refs[0].frame_document = Some(captured_frame);
                    let backend = observation.refs[0].backend_identity.as_mut().unwrap();
                    backend.frame_id = frame.frame_id.clone();
                    let identity = backend.digest();
                    let record = observation.refs[0].classification.as_mut().unwrap();
                    record.node_identity = identity.clone();
                    record.activation_target_identity = identity;
                    record.current_top_level_origin = frame.origin.clone();
                    if fixture.financial || self.hazardous_target {
                        **record = frame_submit_record(
                            frame,
                            document_epoch,
                            if fixture.financial {
                                "cc-number"
                            } else {
                                "current-password"
                            },
                        );
                    } else {
                        **record = classify_click(&NonTypeClassificationInput::new(
                            document_epoch,
                            ElementClassificationInput::new(
                                NodeIdentityInput::new("target", &frame.frame_id, 42),
                                TargetKind::Button,
                            )
                            .input_type("button"),
                            &frame.origin,
                        ))
                        .unwrap();
                    }
                } else {
                    observation.refs.clear();
                    observation.records = vec![AxRecord {
                        depth: 0,
                        role: "document".into(),
                        name: format!("{} needs browser.open_grant read grant", frame.origin),
                        value: None,
                        reference: None,
                    }];
                }
            }
        }
        if self.apply_moves_during_capture() {
            return Err(NavigationDriveError::CdpFailure);
        }
        Ok(observation)
    }

    fn snapshot_subtree_classified(
        &mut self,
        context: &str,
        mode: SnapshotKind,
        reference: &RefRecord,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.effects.lock().unwrap().push("snapshot_subtree");
        let mut observation = if let Some(dropdowns) = &self.dropdowns {
            dropdowns
                .lock()
                .unwrap()
                .observation(document_epoch, current_origin)
        } else {
            self.snapshot_classified(context, mode, document_epoch, current_origin, deadline_ms)?
        };
        let target = observation
            .refs
            .iter()
            .find(|fresh| fresh.backend_identity == reference.backend_identity)
            .map(|fresh| fresh.captured.reference.clone());
        if let Some(start) = target.as_ref().and_then(|target| {
            observation
                .records
                .iter()
                .position(|record| record.reference.as_ref() == Some(target))
        }) {
            let depth = observation.records[start].depth;
            let end = observation.records[start + 1..]
                .iter()
                .position(|record| record.depth <= depth)
                .map(|offset| start + 1 + offset)
                .unwrap_or(observation.records.len());
            observation.records = observation.records[start..end].to_vec();
            for record in &mut observation.records {
                record.depth -= depth;
            }
            observation.refs.retain(|reference| {
                observation
                    .records
                    .iter()
                    .any(|record| record.reference.as_ref() == Some(&reference.captured.reference))
            });
        }
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
        if let Some(fixture) = &self.frame_fixture {
            let mut fixture = fixture.lock().unwrap();
            if fixture.churn_on_screenshot {
                fixture.documents[1].loader_id = "replacement-embed-loader".into();
            }
        }
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
        if self.apply_moves_during_capture() {
            return Err(NavigationDriveError::CdpFailure);
        }
        Ok(observation)
    }

    fn click_classified(
        &mut self,
        _: &str,
        identity: &BackendNodeIdentity,
        epoch: u64,
        origin: &str,
        expected: Option<&cerebellum::classification::NonTypeClassificationRecord>,
        _: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        if let Some(dropdowns) = &self.dropdowns {
            dropdowns
                .lock()
                .unwrap()
                .click(identity, epoch, origin, expected)?;
        }
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

    fn type_classified(
        &mut self,
        _: &str,
        target: &cerebellum::browser_type::TypeDispatch,
        text: &str,
        _: bool,
        _: u64,
    ) -> Result<cerebellum::browser_type::BrowserTypeResult, NavigationDriveError> {
        let dropdowns = self
            .dropdowns
            .as_ref()
            .ok_or(NavigationDriveError::Unavailable)?;
        Ok(dropdowns.lock().unwrap().type_text(target, text))
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
            "browser.type",
            "browser.click",
            // Both admitted after being driven through this wire path against
            // Chrome 151, THROUGH their authorization gates.
            "browser.screenshot",
            "browser.scroll",
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
            "url": "https://requested.example:8443/",
            "intent": "follow the redirect",
            "wait": "settle",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    let navigated: Value = serde_json::from_slice(&navigated.body).unwrap();
    // A non-default port requires an explicit site grant. Public DNS sites on
    // the standard HTTP(S) ports can be navigated without asking a person.
    assert_eq!(navigated["outcome"], "consent_unavailable", "{navigated}");
    assert_eq!(
        navigated["detail"]["reason"], "no_agent_session",
        "{navigated}"
    );

    // Implemented and deliberately not admitted. These are NOT unknown: naming
    // them that way tells a caller to stop asking for something we built and
    // withheld on purpose, and invites a bug report for a decision.
    for (corr, unavailable) in [(16, "browser.wait_for")] {
        let refused = invoke(&planes, corr, unavailable, json!({})).await;
        let refused: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(refused["code"], "capability_not_admitted", "{refused}");
    }

    // An invented name returns unknown_tool, unlike a known capability that
    // this build withholds as capability_not_admitted.
    let invented = invoke(&planes, 18, "browser.teleport", json!({})).await;
    let invented: Value = serde_json::from_slice(&invented.body).unwrap();
    assert_eq!(invented["code"], "unknown_tool", "{invented}");

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
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let no_grant = invoke(&planes, 20, "browser.snapshot", json!({"mode": "ax"})).await;
    let no_grant: Value = serde_json::from_slice(&no_grant.body).unwrap();
    assert_eq!(no_grant["outcome"], "consent_unavailable", "{no_grant}");
    assert_eq!(
        no_grant["detail"]["reason"], "no_agent_session",
        "{no_grant}"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());

    grant_browser(&planes, "https://other.example", Vec::new()).await;
    grant_browser(&planes, "https://second-other.example", Vec::new()).await;
    let wrong_origin = invoke(&planes, 21, "browser.snapshot", json!({"mode": "ax"})).await;
    let wrong_origin: Value = serde_json::from_slice(&wrong_origin.body).unwrap();
    assert_eq!(
        wrong_origin["outcome"], "consent_unavailable",
        "{wrong_origin}"
    );
    assert_eq!(
        wrong_origin["detail"]["reason"], "no_agent_session",
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
        "https://page.example:8443",
        vec![HazardClass::CredentialFormSubmit],
    )
    .await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let before = invoke(&planes, 30, "browser.snapshot", json!({"mode": "ax"})).await;
    let before: Value = serde_json::from_slice(&before.body).unwrap();
    assert_eq!(before["outcome"], "ok", "{before}");
    assert!(
        before["state_text"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe before")),
        "{before}"
    );
    let snapshot_id = before["snapshot_id"].as_str().unwrap();
    let reference = first_ref(&before);

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
        after["state_text"]
            .as_str()
            .is_some_and(|content| content.contains("Click probe after")),
        "{after}"
    );
}

/// The default snapshot's page text is plain lines whose first word is the
/// ref, with no separate ref table, and a ref read off a line is one the click
/// handler accepts and dispatches.
#[tokio::test]
async fn wire_click_dispatches_a_ref_read_from_the_page_text() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(
        &planes,
        "https://page.example:8443",
        vec![HazardClass::CredentialFormSubmit],
    )
    .await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let snapshot = invoke(&planes, 30, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert!(
        snapshot.get("content").is_none() && snapshot.get("refs").is_none(),
        "{snapshot}"
    );
    let text = snapshot["state_text"].as_str().unwrap();
    let line = text
        .lines()
        .find(|line| line.ends_with("button Sign in"))
        .unwrap_or_else(|| panic!("no button line in {text}"));
    let reference = line.split_whitespace().next().unwrap();

    let clicked = invoke(
        &planes,
        31,
        "browser.click",
        json!({
            "ref": reference,
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "click the ref the page text printed",
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
            ["https://page.example:8443"],
        )])),
    );
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let snapshot = invoke(&planes, 40, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke(
        &planes,
        41,
        "browser.click",
        json!({
            "ref": first_ref(&snapshot),
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "must remain refused",
            "severity": {"tier": 2, "credential": false, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "consent_unavailable", "{clicked}");
    // The conversation holds a grant, just one whose ceiling is below a click,
    // so the refusal says the severity is short rather than that no grant
    // exists.
    assert_eq!(clicked["detail"]["reason"], "no_agent_session", "{clicked}");
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
        json!({"origins": ["https://page.example:8443"], "hazards": []}),
    )
    .await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let snapshot = invoke(&planes, 61, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let click = json!({
        "ref": first_ref(&snapshot),
        "snapshot_id": snapshot["snapshot_id"],
        "intent": "follow the cross-site link",
        "severity": {"tier": 2, "credential": false, "financial": false}
    });

    // Asserted on the wire reply: an undeclared field or reason would have
    // been withheld by result-schema enforcement instead of reaching here.
    let refused = invoke_existing(&planes, 62, "browser.click", click.clone()).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "consent_unavailable", "{refused}");
    assert_eq!(refused["detail"]["reason"], "no_agent_session", "{refused}");
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
        refused["detail"]["attempted_origin"], "https://page.example:8443",
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["grant_request"],
        json!({"origins": ["https://page.example:8443"], "severity_tier": 4, "hazards": []}),
        "{refused}"
    );
    assert_eq!(
        refused["remedy"],
        "call from the agent session that needs the permission; it can raise the card",
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
    assert_eq!(landing["outcome"], "consent_unavailable", "{landing}");
    assert_eq!(
        landing["detail"]["attempted_origin"],
        "http://127.0.0.1:8080"
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
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let refused = invoke_existing(&planes, 70, "browser.snapshot", json!({})).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "consent_unavailable", "{refused}");
    assert_eq!(refused["detail"]["reason"], "no_agent_session", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://page.example:8443",
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["required"],
        json!({"tier": 1, "credential": false, "financial": false}),
        "{refused}"
    );
    assert_eq!(
        refused["detail"]["grant_request"],
        json!({"origins": ["https://page.example:8443"], "severity_tier": 2, "hazards": []}),
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

#[tokio::test]
async fn scroll_wire_uses_observe_grant_and_retained_ref_without_fronting() {
    let launcher = Arc::new(RecordingLauncher {
        hazardous_target: true,
        ..RecordingLauncher::default()
    });
    launcher.page.commit("https://page.example:8443/settings");
    let planes = planes_with_installed_grants(
        &launcher,
        vec![ActionGrant::new(
            "observe",
            1,
            "test-session",
            Severity::new(OBSERVE, false, false),
            ["https://page.example:8443"],
        )],
    );
    let launched = response_body(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
    let snapshot = response_body(&planes, 2, "browser.snapshot", json!({})).await;
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let reference = first_ref(&snapshot);
    launcher.effects.lock().unwrap().clear();
    for (corr, args) in [
        (3, json!({"action":"scroll","ref":reference})),
        (4, json!({"action":"scroll","direction":"down"})),
    ] {
        let reply = response_body(&planes, corr, "browser_use", args).await;
        assert_eq!(reply["outcome"], "ok", "{reply}");
        assert_eq!(reply["scroll_dispatched"], true, "{reply}");
        assert!(cerebellum::browser::validate_browser_result("browser.scroll", &reply).is_ok());
    }
    assert_eq!(
        *launcher.effects.lock().unwrap(),
        ["scroll_ref", "scroll_page"]
    );
    launcher
        .page
        .commit("https://page.example:8443/replacement");
    let stale = response_body(
        &planes,
        5,
        "browser_use",
        json!({"action":"scroll","ref":reference}),
    )
    .await;
    assert_eq!(stale["outcome"], "stale_snapshot", "{stale}");
    assert_eq!(
        *launcher.effects.lock().unwrap(),
        ["scroll_ref", "scroll_page"]
    );
}

#[tokio::test]
async fn scroll_wire_validates_target_alternatives_before_dispatch() {
    let planes = planes_with_installed_grants(&Arc::new(RecordingLauncher::default()), vec![]);
    for (corr, args) in [
        (1, json!({"action":"scroll"})),
        (2, json!({"action":"scroll","ref":"e1","direction":"down"})),
        (3, json!({"action":"scroll","direction":"down","amount":0})),
        (
            4,
            json!({"action":"scroll","direction":"down","amount":10001}),
        ),
        (5, json!({"action":"scroll","direction":"sideways"})),
    ] {
        let reply = response_body(&planes, corr, "browser_use", args).await;
        assert_eq!(reply["outcome"], "invalid_request", "{reply}");
    }
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
            "ref": first_ref(&snapshot),
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
        ["https://page.example:8443"],
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
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    let clicked = click_cross_site_link(&planes, 80).await;
    assert_eq!(clicked["outcome"], "consent_unavailable", "{clicked}");
    assert_eq!(clicked["detail"]["reason"], "no_agent_session", "{clicked}");
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
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    let clicked = click_cross_site_link(&planes, 90).await;
    assert_eq!(clicked["detail"]["reason"], "no_agent_session", "{clicked}");
    assert_eq!(
        clicked["detail"]["grant_request"],
        json!({"origins": ["https://page.example:8443"], "severity_tier": 4, "hazards": []}),
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
            ["https://page.example:8443"],
        )
        .with_disclosed_hazards([HazardClass::FinancialFormSubmit])])),
    );
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;

    let snapshot = invoke(&planes, 50, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let clicked = invoke(
        &planes,
        51,
        "browser.click",
        json!({
            "ref": first_ref(&snapshot),
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "must remain refused",
            "severity": {"tier": 4, "credential": true, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "consent_unavailable", "{clicked}");
    assert_eq!(
        clicked["detail"]["missing_hazard"], "credential_form_submit",
        "{clicked}"
    );
    // The existing grant discloses only the financial hazard, so the grant
    // that admits this click names the credential hazard it lacks.
    assert_eq!(
        clicked["detail"]["grant_request"],
        json!({"origins": ["https://page.example:8443"], "severity_tier": 4, "hazards": ["credential_form_submit"]}),
        "{clicked}"
    );
    assert_eq!(
        clicked["remedy"],
        "call from the agent session that needs the permission; it can raise the card",
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
        role_versions: None,
        call_mode: None,
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
            origin: Default::default(),
        },
        // The bind validator refuses an empty principal before the registry
        // is opened.
        principal: Some(subc_protocol::Principal::Direct),
        agent_project_id_attested: true,
        acts_as_agent: true,
        session_kind_attested: true,
        control_operations: Vec::new(),
        effective_capability_scope: None,
        flow_id: None,
        consumer_capabilities: Vec::new(),
        surface: RouteSurface::Tools,
        call_mode: subc_protocol::call_mode::CallMode::Classic,
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
    launch_at(&planes, &launcher.page, "https://landed.example:8443").await;

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
    launch_at(&planes, &launcher.page, "https://landed.example:8443").await;

    let presented = cerebellum::present_browser_handoff_for_test(
        &planes,
        &route_identity(),
        "https://landed.example:8443",
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
    assert_eq!(
        blocked["origin"], "https://landed.example:8443",
        "{blocked}"
    );
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
    launch_at(&planes, &launcher.page, "https://landed.example:8443").await;

    let reply = cerebellum::present_browser_handoff_for_test(
        &planes,
        &route_identity(),
        "https://landed.example:8443",
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
    launch_at(&planes, &launcher.page, "https://landed.example:8443").await;
    let route = route_identity();

    let presented = cerebellum::present_browser_handoff_for_test(
        &planes,
        &route,
        "https://landed.example:8443",
    )
    .await;
    assert_eq!(presented["outcome"], "presented", "{presented}");
    let resumed = cerebellum::resume_browser_handoff_for_test(&planes, &route).await;
    assert_eq!(
        resumed,
        json!({
            "outcome":"resumed",
            "handoff":"closed_by_caller",
            "origin":"https://landed.example:8443",
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
    launch_at(&planes, &launcher.page, "https://landed.example:8443").await;
    let route = route_identity();

    let presented = cerebellum::present_browser_handoff_for_test(
        &planes,
        &route,
        "https://landed.example:8443",
    )
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
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    grant_browser(&planes, "https://page.example:8443", Vec::new()).await;
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
    grant_browser(&planes, "https://page.example:8443", Vec::new()).await;

    let first = launch_session_at(&planes, &launcher.page, 1, "https://page.example:8443").await;
    let before_close = response_body(&planes, 2, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(before_close["outcome"], "ok", "{before_close}");
    close_session(&planes, 3, &first).await;

    let second = launch_session_at(&planes, &launcher.page, 4, "https://page.example:8443").await;
    assert_ne!(first, second);
    let relaunched = response_body(&planes, 5, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(relaunched["outcome"], "ok", "{relaunched}");
    assert!(
        relaunched["state_text"]
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
    grant_browser(&planes, "https://landed.example:8443", Vec::new()).await;

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
        navigated["state_text"]
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
        "https://page.example:8443",
        vec![HazardClass::CredentialFormSubmit],
    )
    .await;

    launch_session_at(&planes, &launcher.page, 1, "https://page.example:8443").await;
    let old = response_body(&planes, 2, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(old["outcome"], "ok", "{old}");

    *launcher.exited.lock().unwrap() = true;
    planes.sessions.observe_exits_all(&config());
    let status = response_body(&planes, 3, "browser.status", json!({})).await;
    assert_ne!(status["outcome"], "ready", "{status}");
    *launcher.exited.lock().unwrap() = false;

    launch_session_at(&planes, &launcher.page, 4, "https://page.example:8443").await;
    let fresh = response_body(&planes, 5, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(fresh["outcome"], "ok", "{fresh}");
    assert_ne!(fresh["snapshot_id"], old["snapshot_id"]);

    launcher.effects.lock().unwrap().clear();
    let stale_click = response_body(
        &planes,
        6,
        "browser.click",
        json!({
            "ref": first_ref(&old),
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
    grant_browser(&planes, "https://page.example:8443", Vec::new()).await;

    let first = launch_session_at(&planes, &launcher.page, 1, "https://page.example:8443").await;
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
                "https://www.iana.org:8443/domains/example",
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
                "https://www.iana.org:8443/help/example-domains",
                Some(307),
            ),
            document_response(
                "doc-1",
                MAIN_FRAME,
                "https://www.iana.org:8443/help/example-domains",
                200,
            ),
            session_event(
                "Page.frameNavigated",
                json!({"frame":{
                    "id":MAIN_FRAME,
                    "loaderId":"loader-2",
                    "url":"https://www.iana.org:8443/help/example-domains",
                    "securityOrigin":"https://www.iana.org:8443",
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
    unanswered: Option<&'static str>,
    scenario: ClickScenario,
    /// The main frame's committed URL, which `Page.getNavigationHistory`
    /// reports and a main-frame `Page.frameNavigated` moves.
    page: CommittedPage,
    /// Every CDP method the driver sent, in order.
    commands: Arc<Mutex<Vec<String>>>,
    reads: VecDeque<Vec<u8>>,
    blocked_release_id: Option<u64>,
    typing: Option<TypePage>,
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
        if self.unanswered == command["method"].as_str() {
            return Ok(());
        }
        match command["method"].as_str().unwrap() {
            "Browser.setDownloadBehavior" => self.queue(json!({"id":id,"result":{}})),
            "Page.navigate" => {
                self.page.commit(command["params"]["url"].as_str().unwrap());
                self.reply(id, json!({"frameId":MAIN_FRAME}));
            }
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
            "DOM.getFlattenedDocument" => self.reply(
                id,
                Value::Object(
                    self.typing
                        .as_ref()
                        .map(TypePage::document)
                        .unwrap_or_else(click_page_document),
                ),
            ),
            "Emulation.setFocusEmulationEnabled" => {
                *self.typing.as_ref().unwrap().has_focus.lock().unwrap() =
                    command["params"]["enabled"].as_bool().unwrap();
                self.reply(id, json!({}));
            }
            "DOM.focus" => {
                if self.typing.as_ref().is_some_and(|page| page.fail_focus) {
                    self.queue(json!({"id":id,"sessionId":"session-own","error":{"code":-32000,"message":"DOM node is not ready"}}));
                } else {
                    self.reply(id, json!({}));
                }
            }
            "Runtime.enable" => {
                *self
                    .typing
                    .as_ref()
                    .unwrap()
                    .runtime_enabled
                    .lock()
                    .unwrap() = true;
                self.reply(id, json!({}));
            }
            "DOM.resolveNode" => {
                let page = self.typing.as_ref().unwrap();
                if page.cold_runtime && !*page.runtime_enabled.lock().unwrap() {
                    self.queue(json!({"id":id,"sessionId":"session-own","error":{"code":-32000,"message":"Execution context not ready"}}));
                } else {
                    self.reply(id, json!({"object":{"objectId":"field"}}));
                }
            }
            "Runtime.callFunctionOn" => {
                let page = self.typing.as_ref().unwrap();
                let function = command["params"]["functionDeclaration"].as_str().unwrap();
                let value = if function.contains("this.select()") {
                    *page.selected.lock().unwrap() = true;
                    None
                } else if function.contains("collapse(false)") {
                    *page.caret.lock().unwrap() = page.value.lock().unwrap().len();
                    *page.selected.lock().unwrap() = false;
                    Some(true)
                } else if function.contains("length === 0") {
                    Some(page.value.lock().unwrap().is_empty())
                } else if function.contains("hasFocus()") {
                    Some(*page.has_focus.lock().unwrap())
                } else {
                    Some(true)
                };
                self.reply(
                    id,
                    value
                        .map(|value| json!({"result":{"type":"boolean","value":value}}))
                        .unwrap_or_else(|| json!({"result":{"type":"undefined"}})),
                );
            }
            "Input.dispatchKeyEvent" => {
                let page = self.typing.as_ref().unwrap();
                if command["params"]["type"] == "keyDown"
                    && *page.selected.lock().unwrap()
                    && !page.ignore_delete
                {
                    page.value.lock().unwrap().clear();
                    *page.caret.lock().unwrap() = 0;
                    *page.selected.lock().unwrap() = false;
                }
                self.reply(id, json!({}));
            }
            "Input.insertText" => {
                let page = self.typing.as_ref().unwrap();
                let text = command["params"]["text"].as_str().unwrap();
                let mut value = page.value.lock().unwrap();
                let mut caret = page.caret.lock().unwrap();
                if !*page.has_focus.lock().unwrap() {
                    *caret = 0;
                }
                if *page.selected.lock().unwrap() {
                    value.clear();
                    *caret = 0;
                }
                value.insert_str(*caret, text);
                *caret += text.len();
                *page.selected.lock().unwrap() = false;
                drop(caret);
                drop(value);
                self.reply(id, json!({}));
            }
            "Page.getNavigationHistory" => {
                let history = self.page.navigation_history();
                self.reply(id, history)
            }
            "Page.getFrameTree" => {
                let tree = self.page.frame_tree();
                self.reply(id, tree)
            }
            "DOM.scrollIntoViewIfNeeded"
            | "DOM.enable"
            | "Page.enable"
            | "Network.enable"
            | "Target.setAutoAttach" => self.reply(id, json!({})),
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
    typing: Option<TypePage>,
}

impl OwnedBrowserProcess for CdpClickProcess {
    fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.driver
            .navigate(context_key, url, wait, deadline_ms, tracker)
    }
    fn type_classified(
        &mut self,
        context_key: &str,
        target: &cerebellum::browser_type::TypeDispatch,
        text: &str,
        clear_first: bool,
        deadline_ms: u64,
    ) -> Result<cerebellum::browser_type::BrowserTypeResult, NavigationDriveError> {
        self.driver
            .type_classified(context_key, target, text, clear_first, deadline_ms)
    }

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
        let field_frame = if self
            .typing
            .as_ref()
            .is_some_and(|page| page.frame_origin.is_some())
        {
            "cross-frame"
        } else {
            MAIN_FRAME
        };
        let identity =
            BackendNodeIdentity::new("target-own", field_frame, LINK_BACKEND_NODE).unwrap();
        let classification = classify_flattened_document(
            &self
                .typing
                .as_ref()
                .map(TypePage::document)
                .unwrap_or_else(click_page_document),
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
                frame_document: self
                    .typing
                    .as_ref()
                    .and_then(|page| page.frame_origin.as_ref())
                    .map(|origin| cerebellum::snapshot_store::FrameDocument {
                        navigation_revision: 0,
                        frame_id: "cross-frame".into(),
                        parent_id: Some(MAIN_FRAME.into()),
                        session_id: "cross-session".into(),
                        loader_id: "cross-loader".into(),
                        url: format!("{origin}/field"),
                        origin: origin.clone(),
                    }),
                captured: SnapshotRef::new("e1", "link", "Learn more", 0).unwrap(),
                frame_path: vec![field_frame.into()],
                backend_identity: Some(identity),
                raw_role: Some("link".into()),
                raw_name: Some("Learn more".into()),
                classification: Ok(Box::new(classification)),
            }],
            ax_truncated: false,
            refs_truncated: false,
            facts: Default::default(),
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
    unanswered: Option<&'static str>,
    scenario: ClickScenario,
    snapshots: Arc<Mutex<usize>>,
    page: CommittedPage,
    commands: Arc<Mutex<Vec<String>>>,
    typing: Option<TypePage>,
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
                        unanswered: self.unanswered,
                        scenario: self.scenario,
                        page: self.page.clone(),
                        commands: Arc::clone(&self.commands),
                        reads: VecDeque::new(),
                        blocked_release_id: None,
                        typing: self.typing.clone(),
                    },
                    CdpTransport::new(),
                    CdpFrameDecoder::default(),
                ),
                snapshots: Arc::clone(&self.snapshots),
                typing: self.typing.clone(),
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
        unanswered: None,
        scenario,
        snapshots: Arc::clone(&snapshots),
        page: page.clone(),
        commands: Arc::default(),
        typing: None,
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
            "ref": first_ref(&snapshot),
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
        clicked["url_final"], "https://www.iana.org:8443/help/example-domains",
        "{clicked}"
    );
    assert_eq!(
        clicked["lifecycle"],
        json!({"events":["navigation_started", "load", "network_quiet"],"loaded":true,"settled":true}),
        "{clicked}"
    );
    assert_eq!(clicked["http_status"], 200, "{clicked}");
    assert_eq!(
        clicked["landing_origin"], "https://www.iana.org:8443",
        "{clicked}"
    );
    assert_eq!(clicked["landing_origin_granted"], false, "{clicked}");
    assert!(clicked.get("navigation_window_ms").is_none(), "{clicked}");

    // The reply's claim holds: the conversation's page is now the landing
    // page, and reading it is refused under the grant for the old origin.
    let refused = invoke(&planes, 102, "browser.snapshot", json!({"mode": "ax"})).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "consent_unavailable", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://www.iana.org:8443",
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
        unanswered: None,
        scenario: ClickScenario::CrossOriginRedirect,
        snapshots: Arc::default(),
        page: page.clone(),
        commands: Arc::default(),
        typing: None,
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
            "ref": first_ref(&snapshot),
            "snapshot_id": snapshot["snapshot_id"],
            "intent": "follow the Learn more link",
            "severity": {"tier": 4, "credential": false, "financial": false}
        }),
    )
    .await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(
        clicked["landing_origin"], "https://www.iana.org:8443",
        "{clicked}"
    );
    assert_eq!(clicked["landing_origin_granted"], false, "{clicked}");

    // Parsed from the wire frame, after result-schema enforcement: an
    // undeclared detail field would have withheld this reply.
    let read = json!({"mode": "ax"});
    let refused = invoke_existing(&planes, 113, "browser.snapshot", read.clone()).await;
    let refused: Value = serde_json::from_slice(&refused.body).unwrap();
    assert_eq!(refused["outcome"], "consent_unavailable", "{refused}");
    assert_eq!(refused["detail"]["reason"], "no_agent_session", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://www.iana.org:8443",
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
        json!({"origins": ["https://www.iana.org:8443"], "severity_tier": 2, "hazards": []}),
        "{refused}"
    );
    assert_eq!(
        refused["remedy"],
        "call from the agent session that needs the permission; it can raise the card",
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
        read_again["source_origin"], "https://www.iana.org:8443/help/example-domains",
        "{read_again}"
    );
}

#[tokio::test]
async fn a_click_landing_on_a_granted_origin_says_it_can_be_read() {
    let (_, clicked, _) = click_link(
        ClickScenario::CrossOriginRedirect,
        &[CLICK_PAGE_ORIGIN, "https://www.iana.org:8443"],
    )
    .await;

    assert_eq!(clicked["navigation"], "main_frame", "{clicked}");
    assert_eq!(
        clicked["landing_origin"], "https://www.iana.org:8443",
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

/// Use service-port origins so these read-scope probes exercise site grants,
/// not implicit public browsing. The navigation double redirects to the
/// landing page, and each origin in `readable` gets its own read grant.
async fn navigated_to_landed(readable: &[&str]) -> (Arc<RecordingLauncher>, Planes) {
    let launcher = Arc::new(RecordingLauncher::default());
    let planes = recording_planes(&launcher);
    grant_browser(&planes, "https://requested.example:8443", Vec::new()).await;
    for origin in readable {
        grant_browser(&planes, origin, Vec::new()).await;
    }
    launch_session_at(&planes, &launcher.page, 1, "https://requested.example:8443").await;
    let navigated = response_body(
        &planes,
        2,
        "browser.navigate",
        json!({
            "url": "https://requested.example:8443/",
            "intent": "open the page the reads are about",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(
        navigated["url_final"], "https://landed.example:8443/final",
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
    let (launcher, planes) = navigated_to_landed(&["https://landed.example:8443"]).await;
    // The same read succeeds while the page stays where it was navigated, so
    // the refusals below come from the move and not from a plane refusing
    // everything.
    let before = response_body(&planes, 3, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(before["outcome"], "ok", "{before}");

    launcher.page.commit("https://attacker.example:8443/moved");

    for (corr, mode) in [(4, "ax"), (5, "dom_full")] {
        let refused = response_body(&planes, corr, "browser.snapshot", json!({"mode": mode})).await;
        assert_eq!(
            refused["outcome"], "consent_unavailable",
            "{mode}: {refused}"
        );
        assert_eq!(
            refused["detail"]["attempted_origin"], "https://attacker.example:8443",
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
        "https://attacker.example:8443/moved".to_string(),
        "origin_scope".to_string(),
    );
    assert_eq!(refusal_records(&planes).await, [moved.clone(), moved]);
}

#[tokio::test]
async fn a_page_that_moves_itself_off_the_granted_origin_refuses_the_next_screenshot() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example:8443"]).await;
    let before = response_body(&planes, 3, "browser.screenshot", json!({})).await;
    assert_eq!(before["outcome"], "ok", "{before}");

    launcher.page.commit("https://attacker.example:8443/moved");

    let refused = response_body(&planes, 4, "browser.screenshot", json!({})).await;
    assert_eq!(refused["outcome"], "consent_unavailable", "{refused}");
    assert_eq!(
        refused["detail"]["attempted_origin"], "https://attacker.example:8443",
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
async fn a_snapshot_that_fails_because_the_page_moved_reports_the_move() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example:8443"]).await;

    *launcher.moves_during_capture.lock().unwrap() = vec![
        PageMove::Commit("https://attacker.example:8443/mid-read"),
        PageMove::CaptureFails,
    ];
    let moved = response_body(&planes, 3, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(moved["outcome"], "page_navigated_during_read", "{moved}");
    assert_eq!(
        moved["detail"]["authorized_origin"], "https://landed.example:8443",
        "{moved}"
    );
    assert_eq!(
        moved["detail"]["live_origin"], "https://attacker.example:8443",
        "{moved}"
    );
    assert_no_page_content(&moved);

    // A capture that fails while the page stays where it was authorized has
    // no move to report, so it is still the module's own failure.
    launcher.page.commit("https://landed.example:8443/final");
    *launcher.moves_during_capture.lock().unwrap() = vec![PageMove::CaptureFails];
    let failed = response_body(&planes, 4, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(failed["outcome"], "internal_error", "{failed}");
    assert_eq!(failed["detail"]["reason_code"], "cdp_failure", "{failed}");
    assert_no_page_content(&failed);
}

#[tokio::test]
async fn a_navigation_that_commits_during_a_read_discards_the_capture() {
    let (launcher, planes) = navigated_to_landed(&["https://landed.example:8443"]).await;

    for (corr, tool, arguments) in [
        (3, "browser.snapshot", json!({"mode": "ax"})),
        (5, "browser.snapshot", json!({"mode": "dom_full"})),
        (7, "browser.screenshot", json!({})),
    ] {
        launcher.page.commit("https://landed.example:8443/final");
        *launcher.moves_during_capture.lock().unwrap() =
            vec![PageMove::Commit("https://attacker.example:8443/mid-read")];

        let refused = response_body(&planes, corr, tool, arguments.clone()).await;
        assert_eq!(
            refused["outcome"], "page_navigated_during_read",
            "{tool} {arguments}: {refused}"
        );
        assert_eq!(
            refused["detail"]["authorized_origin"], "https://landed.example:8443",
            "{refused}"
        );
        assert_eq!(
            refused["detail"]["live_origin"], "https://attacker.example:8443",
            "{refused}"
        );
        assert_no_page_content(&refused);

        // The page is now on the ungranted origin, so reading again is
        // refused before any capture rather than repeating the race.
        let again = response_body(&planes, corr + 1, tool, arguments).await;
        assert_eq!(again["outcome"], "consent_unavailable", "{again}");
        assert_no_page_content(&again);
    }

    // The same race inside navigate's read_page: the navigation itself is
    // reported, and the embedded read is withheld.
    launcher.page.commit("https://landed.example:8443/final");
    *launcher.moves_during_capture.lock().unwrap() =
        vec![PageMove::Commit("https://attacker.example:8443/mid-read")];
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
                |(addressing, reason)| addressing == "https://attacker.example:8443/mid-read"
                    && reason == "page_navigated_during_read"
            )
            .count(),
        4,
        "{records:?}"
    );
}

#[tokio::test]
async fn a_page_that_stays_put_reads_as_before() {
    let (_launcher, planes) = navigated_to_landed(&["https://landed.example:8443"]).await;

    for (corr, mode) in [(3, "ax"), (4, "dom_full")] {
        let read = response_body(&planes, corr, "browser.snapshot", json!({"mode": mode})).await;
        assert_eq!(read["outcome"], "ok", "{mode}: {read}");
        assert_eq!(
            read["source_origin"], "https://landed.example:8443/final",
            "{read}"
        );
    }
    let ax = response_body(&planes, 5, "browser.snapshot", json!({"mode": "ax"})).await;
    assert!(
        ax["state_text"]
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
        screenshot["source_origin"], "https://landed.example:8443/final",
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
    let (launcher, planes) = navigated_to_landed(&["https://landed.example:8443"]).await;

    // Out and straight back by a new navigation, and out and back by history
    // traversal. Either way the page is on the authorized origin at both ends
    // of the capture, and either way the capture may hold the other page's
    // content. Checking only the origin would return it.
    let mut corr = 3;
    for moves in [
        vec![
            PageMove::Commit("https://attacker.example:8443/mid-read"),
            PageMove::Commit("https://landed.example:8443/final"),
        ],
        vec![
            PageMove::Commit("https://attacker.example:8443/mid-read"),
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
                refused["detail"]["authorized_origin"], "https://landed.example:8443",
                "{refused}"
            );
            assert_eq!(
                refused["detail"]["live_origin"], "https://landed.example:8443",
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
        unanswered: None,
        scenario: ClickScenario::NoNavigation,
        snapshots: Arc::new(Mutex::new(0)),
        page: page.clone(),
        commands: Arc::clone(&commands),
        typing: None,
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
            "ref": first_ref(snapshot),
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
    page.commit("https://attacker.example:8443/moved");

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
            refused["detail"]["live_origin"], "https://attacker.example:8443",
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
    blocking_grant_fixture_with_standing(false).await
}

async fn blocking_grant_fixture_with_standing(standing: bool) -> (Planes, Arc<RecordingLauncher>) {
    let store = standing.then(|| {
        Arc::new(
            cerebellum::browser_standing_grants::StandingBrowserGrants::open(
                Arc::new(cerebellum::browser_standing_grants::InMemoryStandingGrantStorage::new()),
                Some("test-machine".into()),
            ),
        )
    });
    blocking_grant_fixture_with_store(store).await
}

async fn blocking_grant_fixture_with_store(
    store: Option<Arc<cerebellum::browser_standing_grants::StandingBrowserGrants>>,
) -> (Planes, Arc<RecordingLauncher>) {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling_and_standing_grants(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
        store,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
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
        scope: Some(cingulate_answer::cingulate::stamp(
            "pj-browser-session-wire",
        )),
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
    let service = ScriptedCarrier::default();
    (service.install(planes), launcher)
}

fn blocking_navigation(tier: u8) -> Frame {
    // Public reading no longer exercises consent, so these requests declare
    // reversible-change severity while preserving invalid and actuation cases.
    let tier = if tier == 1 { 3 } else { tier };
    request(
        801,
        "browser.navigate",
        json!({"url":"https://requested.example/path", "intent":"read the page", "wait":"none", "severity":{"tier":tier,"credential":false,"financial":false}}),
    )
}

async fn drain_browser(planes: &Planes) {
    let facts = planes.routes.accepted_bind_for_test(9, 3).unwrap();
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 190,
        epoch: 3,
        target: RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "drain-conversation"),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: None,
        admission_facts: Some(
            json!({"agentProjectId":facts.identity.agent_project_id,"sessionKind":"primary","effectiveCapabilityScope":["*"]}),
        ),
        scope: facts.scope,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        9900,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    assert_eq!(consent_frame(&mut rx).await.header.ty, FrameType::Response);
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        190,
        3,
        9901,
        serde_json::to_vec(&json!({"method":"test.drain","params":{}})).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    assert_eq!(consent_frame(&mut rx).await.header.ty, FrameType::Error);
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
    let outcome = match decision {
        "no_answer" => cerebellum::cingulate_client::ScriptedAnswer::NoAnswer,
        "not_put_to_anyone" | "refused" => {
            cerebellum::cingulate_client::ScriptedAnswer::NotPutToAnyone
        }
        "undeliverable" => cerebellum::cingulate_client::ScriptedAnswer::Undeliverable,
        _ => cerebellum::cingulate_client::ScriptedAnswer::Answered(json!({"decision":decision})),
    };
    assert!(ScriptedCarrier::for_planes(planes)
        .answer_id(body(question)["id"].as_str().unwrap(), outcome));
    let _ = tx;
}

#[tokio::test]
async fn blocking_browser_grant_allow_continues_same_navigation() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let body: Value = serde_json::from_slice(&question.body).unwrap();
    assert_eq!(
        body["params"]["scope"]["origins"],
        json!(["https://requested.example"])
    );
    let p = &body["params"];
    assert_eq!(p["kind"], "consent");
    // The navigation is held open on the answer, so the phone alerts loudly.
    assert_eq!(p["urgency"], "high");
    // The card must cover the declared reversible-change severity, above
    // the public-browsing baseline, without inventing a form hazard.
    assert_eq!(
        p["scope"],
        json!({"origins": ["https://requested.example"], "tier": 3})
    );
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
        ["allow_conversation", "deny"]
    );
    assert_eq!(p.get("requestedSchema"), None);
    assert_eq!(p["options"][0]["effect"], "grant");
    assert_eq!(p["options"][1]["effect"], "decline");
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
    let reply = consent_frame(&mut rx).await;
    assert_eq!(reply.header.corr, 801);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "ok", "{body}");
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);
    assert!(rx.try_recv().is_err(), "only one question and one reply");
    assert!(planes.browser.result_schema_findings().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_deny_never_navigates() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
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

/// A browser action held open on a grant question reports how the question
/// ended, each ending under its own `detail.decision` and remedy, and acts on
/// none of them.
///
/// Before, silence, a question nobody was shown and an unreadable answer all
/// came back as `unavailable` with the refusal's own remedy, which tells the
/// caller to open the grant and retry: a loop for a question that reaches
/// nobody. `refused` is an error frame in place of an answer, which is how a
/// consumer with no handler for questions refuses one.
#[tokio::test]
async fn blocking_browser_grant_reports_each_unanswered_ending_by_name() {
    let cases = [
        (
            "deny",
            "declined",
            "ask again only if they change their mind",
        ),
        ("no_answer", "no_answer", "when they are available"),
        ("not_put_to_anyone", "not_put_to_anyone", "shown to no one"),
        ("refused", "not_put_to_anyone", "shown to no one"),
        (
            "some_future_word",
            "unrecognized_answer",
            "not one this question offered",
        ),
    ];
    for (ending, decision, remedy) in cases {
        let (planes, launcher) = blocking_grant_fixture().await;
        let (tx, mut rx) = mpsc::channel(8);
        cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
            .await
            .unwrap();
        let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
        assert_eq!(question.header.ty, FrameType::Request);
        answer_browser(&planes, &tx, &question, ending).await;
        let reply = consent_frame(&mut rx).await;
        assert_eq!(reply.header.corr, 801);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "authorization_denied", "{ending}: {body}");
        assert_eq!(body["detail"]["decision"], decision, "{ending}: {body}");
        let said = body["remedy"].as_str().unwrap().to_lowercase();
        assert!(said.contains(remedy), "{ending}: {said}");
        if decision == "not_put_to_anyone" {
            for loop_word in ["ask again", "retry", "wait"] {
                assert!(
                    !said.contains(loop_word),
                    "a question nobody was shown sends the caller round a loop: {said}"
                );
            }
        }
        assert!(
            launcher.effects.lock().unwrap().is_empty(),
            "{ending} navigated"
        );
        assert_eq!(
            planes.management.browser_grant_count().await,
            0,
            "{ending} granted something"
        );
        assert!(rx.try_recv().is_err(), "no second question");
        assert!(planes.browser.result_schema_findings().is_empty());
    }
}

async fn late_in_call_answer(decision: &str, _linkable: bool) {
    let (planes, launcher) = blocking_grant_fixture_with_standing(true).await;
    let facts = planes.routes.accepted_bind_for_test(9, 3).unwrap();
    assert!(facts.agent_project_id_attested && facts.acts_as_agent && facts.session_kind_attested);
    assert_eq!(
        facts.identity.session_kind,
        cerebellum_core::identity::SessionKind::Primary
    );
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_browser_consent_deadline_for_test(
        keyed_navigation(9, 801, "pf:late"),
        &tx,
        &planes,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let pending = consent_frame(&mut rx).await;
    assert_eq!(body(&pending)["outcome"], "consent_pending");
    answer_browser(&planes, &tx, &question, decision).await;
    assert_eq!(planes.management.browser_grant_count().await, 0);
    drain_browser(&planes).await;
    let rows = planes
        .management
        .standing_browser_grants()
        .live_rows(&facts.identity.agent_project_id);
    if decision == "allow_origin_always" {
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].consent_ref, body(&question)["id"].as_str().unwrap());
        // An "always" answer covers the registrable domain of an https origin
        // on the default port.
        assert_eq!(
            rows[0].subject,
            cerebellum::browser_standing_grants::StandingSubject::Domain(
                "requested.example".into()
            )
        );
    } else {
        assert!(rows.is_empty());
        assert_eq!(
            planes.management.browser_grant_count().await,
            usize::from(decision == "allow_conversation")
        );
    }
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "a late answer must not navigate"
    );
}

#[tokio::test]
async fn late_in_call_always_answer_records_standing_origin() {
    late_in_call_answer("allow_origin_always", true).await;
}

#[tokio::test]
async fn late_in_call_conversation_answer_records_conversation_grant() {
    late_in_call_answer("allow_conversation", true).await;
}

#[tokio::test]
async fn late_in_call_always_uses_the_raised_id_without_a_payload_id() {
    late_in_call_answer("allow_origin_always", false).await;
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
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let reply = consent_frame(&mut rx).await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "consent_pending", "{body}");
    assert!(body["ask_id"].as_str().is_some());
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
    assert_eq!(planes.management.browser_grant_count().await, 0);
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
async fn blocking_browser_grant_cancel_detaches_while_the_conversation_is_bound() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    let mut cancel = blocking_navigation(1);
    cancel.header.ty = FrameType::Cancel;
    cancel.body.clear();
    cerebellum::handle_frame_for_test(cancel, &tx, &planes)
        .await
        .unwrap();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(body(&reply)["detail"]["decision"], "cancelled");
    assert!(rx.try_recv().is_err(), "no reverse cancellation frame");
    let service = ScriptedCarrier::for_planes(&planes);
    assert!(service
        .calls()
        .iter()
        .any(|(method, _)| method == "consent.detach"));
    assert!(!service
        .calls()
        .iter()
        .any(|(method, _)| method == "consent.withdraw"));
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
    assert_eq!(planes.management.browser_grant_count().await, 0);
    drain_browser(&planes).await;
    assert_eq!(planes.management.browser_grant_count().await, 1);
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_wait_releases_session_locks() {
    let (planes, _) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(blocking_navigation(1), &tx, &planes)
        .await
        .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
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
    // Status reads the session table. The inner CDP lane is also released:
    // consent holds only the outer call queue, not access needed by idle sweeps.
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
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn blocking_browser_grant_goodbye_and_drain_withdraw_only_held_cards() {
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
            let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
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
            if !timed_out && draining {
                consent_frame(&mut rx).await;
            }
            if !timed_out {
                tokio::time::timeout(Duration::from_secs(2), async {
                    while !ScriptedCarrier::for_planes(&planes)
                        .calls()
                        .iter()
                        .any(|(method, _)| method == "consent.withdraw")
                    {
                        tokio::task::yield_now().await;
                    }
                })
                .await
                .expect("a held card is withdrawn");
            } else {
                assert!(
                    !ScriptedCarrier::for_planes(&planes)
                        .calls()
                        .iter()
                        .any(|(method, _)| method == "consent.withdraw"),
                    "a detached card stays answerable"
                );
            }
            answer_browser(&planes, &tx, &question, "allow_conversation").await;
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
        json!({"url":"https://requested.example/path", "intent":"read the page", "wait":"none", "severity":{"tier":3,"credential":false,"financial":false}}),
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
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    cerebellum::handle_frame_for_test(frame, tx, planes)
        .await
        .unwrap();
    if let Some(service) = ScriptedCarrier::find(planes) {
        tokio::select! {
            biased;
            frame = consent_frame(rx) => frame,
            card = service.card(channel, epoch) => card,
        }
    } else {
        consent_frame(rx).await
    }
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
        role_versions: None,
        call_mode: None,
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
    answer_browser(planes, tx, &question, "allow_conversation").await;
    let reply = consent_frame(rx).await;
    assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));
    reply
}

/// The stack a browser call's route path may use, from the frame reader
/// through a granted navigation to its journal commit. That path measured
/// about 430 KiB at its deepest in an unoptimized macOS build once its route
/// handlers were boxed; before, it took over 2 MiB and overflowed the default
/// test-thread stack. Half the default leaves room to grow while failing well
/// before a 2 MiB thread would.
const ROUTE_STACK_BUDGET_BYTES: usize = 1024 * 1024;

#[test]
fn a_browser_call_fits_half_a_default_thread_stack() {
    let call = std::thread::Builder::new()
        .name("route-stack-budget".into())
        .stack_size(ROUTE_STACK_BUDGET_BYTES)
        .spawn(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let (planes, launcher) = blocking_grant_fixture().await;
                    let (tx, mut rx) = mpsc::channel(8);
                    allowed_keyed_navigation(&planes, &tx, &mut rx, "pf:stack-budget").await;
                    assert!(launcher.effects.lock().unwrap().contains(&"navigate"));
                })
        })
        .unwrap();
    // A thread that overflows aborts the whole test binary, which fails it.
    call.join().expect("the browser call ran to its reply");
}

#[tokio::test]
async fn keyed_call_consent_card_carries_the_dispatcher_key() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 801, "pf:card-link"),
    )
    .await;
    assert_eq!(question.header.ty, FrameType::Request);
    assert_eq!(body(&question)["params"]["requester_ref"], "pf:card-link");
    answer_browser(&planes, &tx, &question, "deny").await;
    assert_eq!(consent_frame(&mut rx).await.header.corr, 801);
}

#[tokio::test]
async fn unkeyed_call_consent_card_omits_call_key() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(&planes, &tx, &mut rx, blocking_navigation(1)).await;
    assert_eq!(question.header.ty, FrameType::Request);
    assert!(body(&question)["params"].get("call_key").is_none());
    answer_browser(&planes, &tx, &question, "deny").await;
    assert_eq!(consent_frame(&mut rx).await.header.ty, FrameType::Response);
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

    answer_browser(&planes, &tx, &question, "allow_conversation").await;
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
        json!({"answer": "completed", "result": body(&first), "result_retained": true})
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
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
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
        json!({"answer": "completed", "result": body(&reply), "result_retained": true})
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
async fn withdrawing_a_consent_pending_call_keeps_late_always_answer_without_navigation() {
    let (planes, launcher) = blocking_grant_fixture_with_standing(true).await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_browser_consent_deadline_for_test(
        keyed_navigation(9, 801, "pf:pending"),
        &tx,
        &planes,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
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

    // Withdrawing the navigation leaves its site-access question open, so the
    // later permission response can still record a grant without navigating.
    answer_browser(&planes, &tx, &question, "allow_origin_always").await;
    assert!(planes
        .management
        .standing_browser_grants()
        .live_rows("pj-browser-session-wire")
        .is_empty());
    drain_browser(&planes).await;
    let rows = planes
        .management
        .standing_browser_grants()
        .live_rows("pj-browser-session-wire");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].consent_ref, body(&question)["id"].as_str().unwrap());
    assert!(
        rx.try_recv().is_err(),
        "withdraw must not end the card or resume the call"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[tokio::test]
async fn withdrawing_an_unknown_key_is_unknown_call() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_route(&planes, 9, reserved("prefrontal-core"), None).await;
    let (tx, mut rx) = mpsc::channel(8);
    let answer = withdraw(&planes, &tx, &mut rx, 9, 817, "pf:never-sent").await;
    assert_eq!(answer.header.ty, FrameType::Response);
    assert_eq!(body(&answer), json!({"answer": "unknown_call"}));
}

#[tokio::test]
async fn a_third_principal_learns_nothing_about_another_carriers_key() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_second_principal(&planes).await;
    let (tx, mut rx) = mpsc::channel(8);
    allowed_keyed_navigation(&planes, &tx, &mut rx, "pf:not-yours").await;
    let refused = withdraw(&planes, &tx, &mut rx, 10, 818, "pf:not-yours").await;
    assert_eq!(refused.header.ty, FrameType::Response);
    assert_eq!(body(&refused), json!({"answer":"unknown_call"}));
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
        assert_eq!(reply.header.ty, FrameType::Error);
        assert_eq!(body(&reply)["code"], "invalid_request");
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
            json!({"url":"https://requested.example/path", "intent": SECRET, "wait":"none", "severity":{"tier":3,"credential":false,"financial":false}}),
            "pf:secret-1",
        ),
    )
    .await;
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
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
    subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "s-1",
        scope_epoch,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(subc_protocol::scope::ScopeAttributes::default())
    .with_owner_authorized(owner_authorized)
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
        role_versions: None,
        call_mode: None,
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

#[tokio::test]
async fn flow_id_scope_stamp_binds_but_session_calls_are_refused() {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    // Reuse a call key so a recorded attended reply cannot bypass flow refusal.
    for (channel, flow_id) in [(10, None), (11, Some("flow-1".to_owned()))] {
        let mut scope = scope_stamp(1, true);
        scope.attributes.flow_id = flow_id;
        bind_route(&planes, channel, reserved("prefrontal-core"), Some(scope)).await;
        let (tx, mut rx) = mpsc::channel(8);
        let reply = exchange(
            &planes,
            &tx,
            &mut rx,
            keyed_on(channel, 801, "browser.status", json!({}), "pf:flow-status"),
        )
        .await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(
            body["outcome"],
            if channel == 11 {
                "consent_unavailable"
            } else {
                "no_session"
            },
            "{body}"
        );
    }
}

/// Wait until the launcher's browser has recorded `effect`.
async fn effect_seen(launcher: &RecordingLauncher, effect: &'static str) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while !launcher.effects.lock().unwrap().contains(&effect) {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the browser never recorded {effect}"));
}

/// The next frame the module writes for `corr`, skipping frames for others.
async fn frame_for(rx: &mut mpsc::Receiver<Frame>, corr: u64) -> Frame {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let frame = rx.recv().await.unwrap();
            if frame.header.corr == corr {
                return frame;
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no frame for request {corr}"))
}

/// Bind route channel 11 (epoch 3) for the fixture's conversation, granted
/// `browser.close` as well as status. It shares the conversation with the
/// fixture's route on channel 9, so the two share its execution lane.
async fn close_route(planes: &Planes) {
    bind_route(
        planes,
        11,
        cerebellum::session_caller_principal_for_test().unwrap(),
        None,
    )
    .await;
}

fn close_request(corr: u64, browser_session_id: &str) -> Frame {
    keyed_on(
        11,
        corr,
        "browser.close",
        json!({"browser_session_id": browser_session_id}),
        &format!("pf:close-{corr}"),
    )
}

fn cancel_of(request: &Frame) -> Frame {
    let mut cancel = request.clone();
    cancel.header.ty = FrameType::Cancel;
    cancel.body.clear();
    cancel
}

/// Start a granted navigation whose browser command never returns, then
/// cancel it: its call ends while its worker stays inside the browser,
/// which puts the conversation's session in execution quarantine.
async fn quarantined_session() -> (
    Planes,
    Arc<RecordingLauncher>,
    cerebellum::journal::call_records::InMemoryCallRecordStorage,
    mpsc::Sender<Frame>,
    mpsc::Receiver<Frame>,
    HeldNavigation,
) {
    let (mut planes, launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);
    let hold = launcher.navigate_hold.hold();
    let (tx, mut rx) = mpsc::channel(8);
    let stuck = keyed_navigation(9, 801, "pf:stuck");
    let question = exchange(&planes, &tx, &mut rx, stuck.clone()).await;
    assert_eq!(question.header.ty, FrameType::Request, "a consent question");
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
    effect_seen(&launcher, "navigate").await;
    cerebellum::handle_frame_for_test(cancel_of(&stuck), &tx, &planes)
        .await
        .unwrap();
    (planes, launcher, storage, tx, rx, hold)
}

#[tokio::test]
async fn a_call_on_a_quarantined_session_is_a_target_busy_result_recorded_refused() {
    let (planes, launcher, storage, tx, mut rx, hold) = quarantined_session().await;

    cerebellum::handle_frame_for_test(keyed_navigation(9, 802, "pf:busy"), &tx, &planes)
        .await
        .unwrap();
    let refused = frame_for(&mut rx, 802).await;
    assert_eq!(
        refused.header.ty,
        FrameType::Response,
        "a quarantine refusal is a result, not a route error: {}",
        body(&refused)
    );
    let refusal = body(&refused);
    assert_eq!(refusal["outcome"], "target_busy", "{refusal}");
    assert_eq!(
        refusal["detail"],
        json!({"dispatched": false, "step": "queue", "call": "browser session operation"}),
        "{refusal}"
    );
    assert!(
        refusal["remedy"]
            .as_str()
            .unwrap()
            .contains("nothing was dispatched"),
        "{refusal}"
    );
    let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
    let record: Value = serde_json::from_str(stored.lines().last().unwrap()).unwrap();
    assert_eq!(record["state"], "refused", "{stored}");
    assert_eq!(
        launcher
            .effects
            .lock()
            .unwrap()
            .iter()
            .filter(|effect| **effect == "navigate")
            .count(),
        1,
        "the refused call reached the browser"
    );
    assert!(planes.browser.result_schema_findings().is_empty());

    // Status bypasses the lane the stuck worker holds and reports it.
    cerebellum::handle_frame_for_test(request(803, "browser.status", json!({})), &tx, &planes)
        .await
        .unwrap();
    let status = body(&frame_for(&mut rx, 803).await);
    assert_eq!(status["outcome"], "ready", "{status}");
    assert!(
        status["remedy"].as_str().unwrap().contains("target_busy"),
        "{status}"
    );

    // The quarantine clears when the worker ends.
    drop(hold);
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let status = invoke_existing(&planes, 804, "browser.status", json!({})).await;
            if body(&status).get("remedy").is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("the quarantine outlived its worker");
}

#[tokio::test]
async fn a_close_of_a_quarantined_session_bypasses_the_lane_the_stuck_worker_holds() {
    let (planes, _launcher, _storage, tx, mut rx, hold) = quarantined_session().await;
    let status = body(&invoke_existing(&planes, 802, "browser.status", json!({})).await);
    let session = status["browser_session_id"].as_str().unwrap().to_string();
    close_route(&planes).await;

    cerebellum::handle_frame_for_test(close_request(803, &session), &tx, &planes)
        .await
        .unwrap();
    // The worker is still parked in the browser, so this reply could not
    // come through the conversation lane. The test launcher's browser has no
    // generation-checked killer, so it cannot be confirmed dead and custody
    // stays held.
    let closed = body(&frame_for(&mut rx, 803).await);
    assert_eq!(
        closed,
        json!({"outcome": "cleanup_failure", "browser_session_id": session, "stage": "custody_held"})
    );
    assert!(planes.browser.result_schema_findings().is_empty());
    drop(hold);
}

#[tokio::test]
async fn a_call_with_no_blocking_worker_free_is_refused_before_dispatch() {
    let (mut planes, launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);
    planes.sessions = planes.sessions.clone().with_blocking_workers_for_test(0);
    let (tx, mut rx) = mpsc::channel(8);
    let refused = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 801, "pf:capacity"),
    )
    .await;
    assert_eq!(refused.header.ty, FrameType::Response, "{}", body(&refused));
    let refusal = body(&refused);
    assert_eq!(
        refusal["outcome"], "blocking_capacity_exhausted",
        "{refusal}"
    );
    assert_eq!(
        refusal["detail"],
        json!({"dispatched": false, "step": "queue", "call": "browser.navigate"})
    );
    let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
    let record: Value = serde_json::from_str(stored.lines().last().unwrap()).unwrap();
    assert_eq!(record["state"], "refused", "{stored}");
    assert!(!launcher.effects.lock().unwrap().contains(&"navigate"));
    assert!(planes.browser.result_schema_findings().is_empty());
    // Status takes no permit, so it still answers with the pool exhausted.
    let status = body(&invoke_existing(&planes, 802, "browser.status", json!({})).await);
    assert_eq!(status["outcome"], "ready", "{status}");
}

/// Bind route `channel`/3 for a second conversation, `other-session`, so its
/// calls share no lane with the fixture's conversation. The binding grants
/// `browser.close`: closing a session that conversation does not have takes
/// a permit pair like any session call, yet answers at once, which makes it a
/// cheap probe of the pool.
async fn bind_other_conversation(planes: &Planes, channel: u16) {
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "other-session"),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"pj-browser-session-wire", "sessionKind":"primary", "effectiveCapabilityScope":["*"], "browserControlOperations":["browser.status", "browser.close"]}),
        ),
        scope: None,
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

#[tokio::test]
async fn a_stuck_worker_keeps_its_permits_until_it_ends() {
    let (mut planes, launcher) = blocking_grant_fixture().await;
    // One pair: the stuck call's work and release permits.
    planes.sessions = planes.sessions.clone().with_blocking_workers_for_test(2);
    bind_other_conversation(&planes, 12).await;
    let hold = launcher.navigate_hold.hold();
    let (tx, mut rx) = mpsc::channel(8);
    let stuck = keyed_navigation(9, 801, "pf:stuck");
    let question = exchange(&planes, &tx, &mut rx, stuck.clone()).await;
    assert_eq!(question.header.ty, FrameType::Request, "a consent question");
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
    effect_seen(&launcher, "navigate").await;
    cerebellum::handle_frame_for_test(cancel_of(&stuck), &tx, &planes)
        .await
        .unwrap();

    // Another conversation has its own lane, but no permit is left while the
    // cancelled call's worker is still inside the browser.
    let other_close = |corr: u64| {
        keyed_on(
            12,
            corr,
            "browser.close",
            json!({"browser_session_id": "no-such-session"}),
            &format!("pf:other-{corr}"),
        )
    };
    cerebellum::handle_frame_for_test(other_close(802), &tx, &planes)
        .await
        .unwrap();
    let refused = body(&frame_for(&mut rx, 802).await);
    assert_eq!(
        refused["outcome"], "blocking_capacity_exhausted",
        "{refused}"
    );

    drop(hold);
    tokio::time::timeout(Duration::from_secs(10), async {
        for corr in 803.. {
            cerebellum::handle_frame_for_test(other_close(corr), &tx, &planes)
                .await
                .unwrap();
            let reply = body(&frame_for(&mut rx, corr).await);
            if reply["outcome"] != "blocking_capacity_exhausted" {
                assert_eq!(reply["outcome"], "browser_session_not_found", "{reply}");
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the permits outlived the worker that held them");
}

#[tokio::test]
async fn a_close_behind_a_running_navigation_waits_for_it_and_closes_gracefully() {
    let (planes, launcher) = blocking_grant_fixture().await;
    close_route(&planes).await;
    let status = body(&invoke_existing(&planes, 800, "browser.status", json!({})).await);
    let session = status["browser_session_id"].as_str().unwrap().to_string();
    let hold = launcher.navigate_hold.hold();
    let (tx, mut rx) = mpsc::channel(8);
    let question = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_navigation(9, 801, "pf:running"),
    )
    .await;
    assert_eq!(question.header.ty, FrameType::Request, "a consent question");
    answer_browser(&planes, &tx, &question, "allow_conversation").await;
    effect_seen(&launcher, "navigate").await;
    cerebellum::handle_frame_for_test(close_request(802, &session), &tx, &planes)
        .await
        .unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(200), rx.recv())
            .await
            .is_err(),
        "the close did not wait for the navigation ahead of it"
    );
    drop(hold);
    // The two replies may reach the writer in either order, since each is
    // forwarded after its own call-record settlement.
    let (first, second) = (consent_frame(&mut rx).await, consent_frame(&mut rx).await);
    let (navigated, closed) = if first.header.corr == 801 {
        (first, second)
    } else {
        (second, first)
    };
    assert_eq!((navigated.header.corr, closed.header.corr), (801, 802));
    assert_eq!(body(&navigated)["outcome"], "ok", "{}", body(&navigated));
    let closed = body(&closed);
    assert_eq!(
        closed,
        json!({"outcome": "closed", "browser_session_id": session})
    );
    let effects = launcher.effects.lock().unwrap().clone();
    assert!(
        effects.contains(&"graceful") && effects.contains(&"cleanup"),
        "{effects:?}"
    );
}

#[tokio::test]
async fn named_preset_refusal_records_refused_before_dispatch() {
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);
    let (tx, mut rx) = mpsc::channel(8);
    let mut frame = keyed_on(
        9,
        801,
        "browser_use",
        json!({"action":"status"}),
        "pf:preset",
    );
    let mut request: Value = serde_json::from_slice(&frame.body).unwrap();
    request["preset"] = json!("head");
    frame.body = serde_json::to_vec(&request).unwrap();
    let reply = exchange(&planes, &tx, &mut rx, frame).await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "invalid_request", "{body}");
    assert_eq!(body["detail"]["field"], "preset");
    assert_eq!(body["detail"]["value"], "head");
    let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
    let record: Value = serde_json::from_str(stored.lines().last().unwrap()).unwrap();
    assert_eq!(record["state"], "refused", "{stored}");
    assert_eq!(record["refusal_reason"], "invalid_request", "{stored}");
    let withdrawn = withdraw(&planes, &tx, &mut rx, 9, 802, "pf:preset").await;
    let withdraw_body: Value = serde_json::from_slice(&withdrawn.body).unwrap();
    assert_eq!(
        withdraw_body,
        json!({"answer":"refused", "reason":"invalid_request"})
    );
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
    bind_route(&planes, 9, reserved("prefrontal-core"), None).await;
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
            json!({"url":"https://requested.example/path", "intent": SECRET, "wait":"none", "severity":{"tier":3,"credential":false,"financial":false}}),
            "pf:scoped-1",
        ),
    )
    .await;
    if question.header.ty == FrameType::Request {
        answer_browser(&planes, &tx, &question, "deny").await;
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
async fn an_owner_withdraw_without_a_carrier_is_carrier_required() {
    let (planes, tx, mut rx, _own) = carrier_call_under_scope().await;
    bind_route(
        &planes,
        11,
        reserved("prefrontal-core"),
        Some(scope_stamp(4, true)),
    )
    .await;
    let refused = withdraw(&planes, &tx, &mut rx, 11, 803, "br:1").await;
    assert_eq!(error_code(&refused), "withdraw_carrier_required");
}

#[tokio::test]
async fn a_carrier_naming_another_carrier_is_carrier_mismatch() {
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
    assert_eq!(error_code(&refused), "withdraw_carrier_mismatch");
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
        assert_eq!(error_code(&refused), "withdraw_scope_mismatch", "{scope}");
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
                .settle_browser_grant(&ask_id, Some(&json!({"decision": "allow_conversation"})))
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
        role_versions: None,
        call_mode: None,
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

#[tokio::test]
async fn scope_epoch_replacement_cancels_late_in_call_card() {
    let (planes, launcher) = blocking_grant_fixture_with_standing(true).await;
    bind_route(
        &planes,
        12,
        reserved("prefrontal-core"),
        Some(scope_stamp(1, true)),
    )
    .await;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_browser_consent_deadline_for_test(
        keyed_navigation(9, 801, "pf:replaced"),
        &tx,
        &planes,
        Duration::from_millis(20),
    )
    .await
    .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    assert_eq!(question.header.ty, FrameType::Request);
    assert_eq!(
        body(&consent_frame(&mut rx).await)["outcome"],
        "consent_pending"
    );
    assert_eq!(
        bind_reply(&planes, 15, scope_stamp(2, true))
            .await
            .header
            .ty,
        FrameType::Response
    );
    assert!(
        rx.try_recv().is_err(),
        "scope replacement has no reverse frame"
    );
    answer_browser(&planes, &tx, &question, "allow_origin_always").await;
    assert!(planes
        .management
        .standing_browser_grants()
        .live_rows("pj-browser-session-wire")
        .is_empty());
    assert!(!launcher.effects.lock().unwrap().contains(&"navigate"));
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
            .settle_browser_grant(
                &question.ask_id,
                Some(&json!({"decision": "allow_conversation"}))
            )
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

// ---------------------------------------------------------------------------
// origin: the caller behind a relayed call, recorded on every audit row the
// call writes and consulted by nothing that admits, keys or cancels it
// ---------------------------------------------------------------------------

/// A navigation on `channel`/3 that the fixture's grant lets run, with the
/// request's `origin` member set to `origin` exactly as given (any JSON, so a
/// malformed one can be sent), and a `call_key` when one is named.
fn relayed_navigation(
    channel: u16,
    corr: u64,
    call_key: Option<&str>,
    origin: Option<Value>,
) -> Frame {
    let mut request = json!({
        "name": "browser.navigate",
        "arguments": {"url":"https://requested.example/path", "intent":"read the page", "wait":"none", "severity":{"tier":3,"credential":false,"financial":false}},
    });
    if let Some(call_key) = call_key {
        request["call_key"] = call_key.into();
    }
    if let Some(origin) = origin {
        request["origin"] = origin;
    }
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        3,
        corr,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap()
}

/// A well-formed origin naming a reserved module as the caller behind a call.
fn origin_naming(module_id: &str, call_key: &str) -> Value {
    json!({"carrier": {"kind": "reserved", "module_id": module_id}, "call_key": call_key})
}

fn relayed_record(module_id: &str, call_key: &str) -> cerebellum::journal::CallOriginRecord {
    cerebellum::journal::CallOriginRecord::Relayed {
        carrier: cerebellum_core::journal::OriginCarrier::Reserved {
            module_id: module_id.to_string(),
        },
        call_key: call_key.to_string(),
    }
}

/// Send `frame` on the session caller's route and return its reply, answering
/// "allow_conversation" if the call stops to ask a person first.
async fn served(planes: &Planes, frame: Frame) -> Frame {
    let (tx, mut rx) = mpsc::channel(8);
    let first = exchange(planes, &tx, &mut rx, frame).await;
    if first.header.ty != FrameType::Request {
        return first;
    }
    answer_browser(planes, &tx, &first, "allow_conversation").await;
    consent_frame(&mut rx).await
}

/// The browser journal's rows, as exported.
async fn journal_rows(planes: &Planes) -> Vec<cerebellum::journal::JournalEntry> {
    planes
        .browser
        .journal_export_for_test()
        .await
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

/// The latest record the call-record file holds for `call_key`, as written.
fn stored_record(
    storage: &cerebellum::journal::call_records::InMemoryCallRecordStorage,
    call_key: &str,
) -> Value {
    let stored = String::from_utf8(storage.contents().expect("records were written")).unwrap();
    stored
        .lines()
        .skip(1)
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|record| record["call_key"] == call_key)
        .last()
        .unwrap_or_else(|| panic!("no record for {call_key}: {stored}"))
}

#[tokio::test]
async fn a_relayed_call_names_its_origin_on_its_journal_rows_and_its_call_record() {
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);

    let reply = served(
        &planes,
        relayed_navigation(
            9,
            801,
            Some("pf:relayed-1"),
            Some(origin_naming("agent-host", "agent:call-1")),
        ),
    )
    .await;
    assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));

    let expected = relayed_record("agent-host", "agent:call-1");
    let rows = journal_rows(&planes).await;
    assert!(!rows.is_empty(), "the call wrote no journal row");
    for row in &rows {
        assert_eq!(row.identity.origin, expected, "{row:?}");
        assert_eq!(row.format_version, "ck-browser-journal/v7");
    }
    let record = stored_record(&storage, "pf:relayed-1");
    assert_eq!(
        record["origin"],
        serde_json::to_value(&expected).unwrap(),
        "{record}"
    );
    // The record is still the route principal's: the origin names who it acted
    // for, never who acted.
    assert_eq!(record["principal"], "reserved:prefrontal-core", "{record}");
}

#[tokio::test]
async fn a_call_naming_no_origin_records_none() {
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);

    let reply = served(
        &planes,
        relayed_navigation(9, 801, Some("pf:direct-1"), None),
    )
    .await;
    assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));

    let export = planes.browser.journal_export_for_test().await;
    assert!(!export.is_empty(), "the call wrote no journal row");
    for line in export.lines() {
        let row: Value = serde_json::from_str(line).unwrap();
        assert!(row["identity"].get("origin").is_none(), "{row}");
    }
    let record = stored_record(&storage, "pf:direct-1");
    assert!(record.get("origin").is_none(), "{record}");
}

#[tokio::test]
async fn an_invalid_origin_is_recorded_absent_with_its_marker_and_never_refuses_the_call() {
    let (mut planes, launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);
    let invalid_before = cerebellum_core::journal::origin_invalid_count();

    // A keyed call whose origin key carries a space, which the wire crate's
    // rule refuses.
    let keyed = served(
        &planes,
        relayed_navigation(
            9,
            801,
            Some("pf:invalid-1"),
            Some(origin_naming("agent-host", "agent call")),
        ),
    )
    .await;
    assert_eq!(body(&keyed)["outcome"], "ok", "{}", body(&keyed));
    // And a call with no key whose origin is not even an object.
    let unkeyed = served(
        &planes,
        relayed_navigation(9, 802, None, Some(json!("prefrontal-core"))),
    )
    .await;
    assert_eq!(body(&unkeyed)["outcome"], "ok", "{}", body(&unkeyed));
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["navigate", "navigate"],
        "both calls must have run"
    );

    let rows = journal_rows(&planes).await;
    assert!(rows.len() >= 2, "{rows:?}");
    for row in &rows {
        assert_eq!(
            row.identity.origin,
            cerebellum::journal::CallOriginRecord::OriginInvalid,
            "{row:?}"
        );
    }
    let export = planes.browser.journal_export_for_test().await;
    assert!(
        export.contains(r#""origin":{"status":"origin_invalid"}"#),
        "{export}"
    );
    assert!(!export.contains("agent call"), "{export}");
    let record = stored_record(&storage, "pf:invalid-1");
    assert_eq!(
        record["origin"],
        json!({"status": cerebellum_core::journal::ORIGIN_INVALID_MARKER}),
        "{record}"
    );
    // Other tests in this binary may count too, so only growth is checked.
    assert!(cerebellum_core::journal::origin_invalid_count() >= invalid_before + 2);
}

/// Text planted in an origin member past its bound, or in a member the
/// protocol does not define, reaches neither the journal nor the call
/// records. The control call plants text within the bounds and must be
/// found, or the scan proves nothing.
#[tokio::test]
async fn text_planted_in_an_origin_past_its_bounds_reaches_no_record() {
    const CONTROL: &str = "PLANTED-ORIGIN-CONTROL-3b9e";
    const OVERLONG_KEY: &str = "PLANTED-ORIGIN-KEY-77c1";
    const OVERLONG_MODULE: &str = "PLANTED-ORIGIN-MODULE-5f02";
    const UNDEFINED_MEMBER: &str = "PLANTED-ORIGIN-NOTE-a41d";
    let (mut planes, _launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);

    let mut extra_member = origin_naming("agent-host", "agent:note");
    extra_member["note"] = UNDEFINED_MEMBER.into();
    let calls = [
        ("pf:leak-control", origin_naming("agent-host", CONTROL)),
        (
            "pf:leak-key",
            origin_naming("agent-host", &format!("{OVERLONG_KEY}{}", "k".repeat(256))),
        ),
        (
            "pf:leak-module",
            origin_naming(&format!("{OVERLONG_MODULE}{}", "m".repeat(255)), "agent:m"),
        ),
        ("pf:leak-note", extra_member),
    ];
    for (corr, (call_key, origin)) in (801..).zip(calls) {
        let reply = served(
            &planes,
            relayed_navigation(9, corr, Some(call_key), Some(origin)),
        )
        .await;
        assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));
    }

    let journal = planes.browser.journal_export_for_test().await;
    let records = String::from_utf8(storage.contents().unwrap()).unwrap();
    for (name, text) in [("journal", &journal), ("call records", &records)] {
        assert!(
            text.contains(CONTROL),
            "the control origin is missing from the {name}, so the scan proves nothing: {text}"
        );
        for planted in [OVERLONG_KEY, OVERLONG_MODULE, UNDEFINED_MEMBER] {
            assert!(
                !text.contains(planted),
                "{planted} reached the {name}: {text}"
            );
        }
    }
    // The over-long members cost the attribution, and the undefined member
    // only itself.
    assert!(records.contains(r#""origin":{"status":"origin_invalid"}"#));
    assert_eq!(
        stored_record(&storage, "pf:leak-note")["origin"],
        serde_json::to_value(relayed_record("agent-host", "agent:note")).unwrap()
    );
}

/// With the same principal and bind facts, calls naming different origins,
/// a malformed one or none are answered alike, and the origin takes no part
/// in finding a call key's record: a resend naming another origin is the same
/// call, answered from the first one's record.
#[tokio::test]
async fn the_origin_changes_no_answer_and_no_call_key_lookup() {
    let (mut planes, launcher) = blocking_grant_fixture().await;
    let storage = with_readable_call_records(&mut planes);

    let mut outcomes = Vec::new();
    for (corr, origin) in (801..).zip([
        None,
        Some(origin_naming("agent-host", "agent:1")),
        Some(origin_naming("broca", "broca:1")),
        Some(json!({"carrier": {"kind": "direct"}, "call_key": "direct:1"})),
        Some(json!(17)),
    ]) {
        let reply = served(&planes, relayed_navigation(9, corr, None, origin)).await;
        outcomes.push((reply.header.ty, body(&reply)["outcome"].clone()));
    }
    assert!(
        outcomes
            .iter()
            .all(|outcome| *outcome == (FrameType::Response, json!("ok"))),
        "{outcomes:?}"
    );

    let first = served(
        &planes,
        relayed_navigation(
            9,
            810,
            Some("pf:same-call"),
            Some(origin_naming("agent-host", "agent:first")),
        ),
    )
    .await;
    assert_eq!(body(&first)["outcome"], "ok", "{}", body(&first));
    let navigations = launcher.effects.lock().unwrap().len();
    for (corr, origin) in [
        (811, Some(origin_naming("broca", "broca:resend"))),
        (812, None),
        (813, Some(json!("not an origin"))),
    ] {
        let resent = served(
            &planes,
            relayed_navigation(9, corr, Some("pf:same-call"), origin),
        )
        .await;
        assert_eq!(resent.header.corr, corr);
        assert_eq!(body(&resent), body(&first), "a resend was not replayed");
    }
    assert_eq!(
        launcher.effects.lock().unwrap().len(),
        navigations,
        "a resend naming another origin ran again"
    );
    // One record for the key, still naming the first call's origin.
    assert_eq!(
        stored_record(&storage, "pf:same-call")["origin"],
        serde_json::to_value(relayed_record("agent-host", "agent:first")).unwrap()
    );
    let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
    let keyed: std::collections::BTreeSet<String> = stored
        .lines()
        .skip(1)
        .map(|line| serde_json::from_str::<Value>(line).unwrap()["call_key"].to_string())
        .collect();
    assert_eq!(keyed.len(), 1, "{stored}");
    assert_eq!(planes.calls.record_count(), 1);
}

/// A route is admitted as its own principal. A principal that may not act in
/// a conversation is refused alike whether or not its call names the admitted
/// module as its origin, and the admitted principal's call is served even
/// when its origin names a module that may not act.
#[tokio::test]
async fn a_relayed_call_is_admitted_only_as_its_route_principal() {
    let (planes, _launcher) = blocking_grant_fixture().await;
    bind_second_principal(&planes).await;

    let session_caller = cerebellum_core::principal::SESSION_CALLER_MODULE_ID;
    // Sent without answering anything: a refused call writes its refusal at
    // once, and an admitted one would stop to ask a person instead.
    let (tx, mut rx) = mpsc::channel(8);
    let plain = exchange(
        &planes,
        &tx,
        &mut rx,
        relayed_navigation(10, 801, None, None),
    )
    .await;
    let claiming = exchange(
        &planes,
        &tx,
        &mut rx,
        relayed_navigation(10, 802, None, Some(origin_naming(session_caller, "pf:1"))),
    )
    .await;
    assert_eq!(
        error_code(&plain),
        cerebellum_core::principal::SESSION_CALLER_NOT_ADMITTED
    );
    assert_eq!(
        (claiming.header.ty, body(&claiming)),
        (plain.header.ty, body(&plain)),
        "an origin naming the admitted module changed a refused principal's answer"
    );
    assert!(
        rx.try_recv().is_err(),
        "a refused call wrote a second frame"
    );

    let admitted = served(
        &planes,
        relayed_navigation(9, 802, None, Some(origin_naming("broca", "broca:1"))),
    )
    .await;
    assert_eq!(body(&admitted)["outcome"], "ok", "{}", body(&admitted));
}

/// A relayed call waiting on a person is cancelled by its correlation id
/// exactly as any other call is.
#[tokio::test]
async fn a_relayed_call_is_cancelled_like_any_other() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let call = relayed_navigation(9, 801, None, Some(origin_naming("agent-host", "agent:1")));
    cerebellum::handle_frame_for_test(call.clone(), &tx, &planes)
        .await
        .unwrap();
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    assert_eq!(question.header.ty, FrameType::Request);
    let mut cancel = call;
    cancel.header.ty = FrameType::Cancel;
    cancel.body.clear();
    cerebellum::handle_frame_for_test(cancel, &tx, &planes)
        .await
        .unwrap();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(
        body(&reply)["detail"]["decision"],
        "cancelled",
        "{}",
        body(&reply)
    );
    assert!(rx.try_recv().is_err());
    assert!(ScriptedCarrier::for_planes(&planes)
        .calls()
        .iter()
        .any(|(method, params)| method == "consent.detach"
            && params["elicitation_id"] == body(&question)["id"]));
    assert!(launcher.effects.lock().unwrap().is_empty());
}

#[cfg(unix)]
mod resource_busy_wire {
    use super::*;
    use cerebellum::browser_launch::{HeldOpenedProfile, ProfileBoundLaunch};
    use cerebellum::profile::{
        stamped_bind_context, BindFacts, DispatchCommitmentToken, InvocationToken,
        JournalReservationHandle, ProfileLifecycle, RegistryConfig,
    };
    use cerebellum::profile_custody::{
        FilesystemProfileCustodyJournal, KernelSupervisorLiveness, ProfileCustodyKey,
        ProfileCustodyLocks,
    };
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    type Locks = ProfileCustodyLocks<FilesystemProfileCustodyJournal, KernelSupervisorLiveness>;
    struct CustodyLauncher {
        lifecycle: Arc<Mutex<ProfileLifecycle>>,
        locks: Arc<Mutex<Locks>>,
        process: RecordingLauncher,
    }
    struct CustodyCleanup {
        holder_id: String,
        opened: Option<HeldOpenedProfile>,
        lifecycle: Arc<Mutex<ProfileLifecycle>>,
        locks: Arc<Mutex<Locks>>,
    }
    impl SessionCleanup for CustodyCleanup {
        fn custody_holder_id(&self) -> Option<&str> {
            Some(&self.holder_id)
        }
        fn after_reap(
            &mut self,
        ) -> Result<cerebellum::browser_session::SessionCleanupOutcome, CleanupStage> {
            let mut lifecycle = self.lifecycle.lock().unwrap();
            let mut locks = self.locks.lock().unwrap();
            ProfileBoundLaunch::new(&mut lifecycle, &mut locks)
                .rollback_opened(self.opened.take().unwrap())
                .unwrap();
            Ok(cerebellum::browser_session::SessionCleanupOutcome::Complete)
        }
    }
    impl BrowserSessionLauncher for CustodyLauncher {
        fn launch(
            &self,
            accepted: &cerebellum_core::identity::AcceptedBindFacts,
            id: &str,
        ) -> Result<LaunchedBrowser, Value> {
            let context = stamped_bind_context(BindFacts {
                principal: "direct:agent".into(),
                conversation_key: accepted.identity.conversation_key.clone(),
                agent_project_id: accepted.identity.agent_project_id.clone(),
                session_kind: Some("primary".into()),
                session_kind_attested: true,
                profile_disposition: Some("durable".into()),
                effective_capability_scope: Some(vec!["browser.launch".into()]),
                provenance: "daemon_attested_spec_a".into(),
            })
            .unwrap();
            let invocation = InvocationToken::for_test(id);
            let reservation =
                JournalReservationHandle::for_test(&invocation, format!("reservation-{id}"));
            let commitment = DispatchCommitmentToken::for_test(
                &invocation,
                &reservation,
                format!("commitment-{id}"),
            );
            let mut lifecycle = self.lifecycle.lock().unwrap();
            let mut locks = self.locks.lock().unwrap();
            let mut bound =
                ProfileBoundLaunch::new(&mut lifecycle, &mut locks).with_launch_timeout(100);
            let prepared = bound
                .acquire_and_prepare(
                    ProfileCustodyKey::durable(&accepted.identity.agent_project_id),
                    &invocation,
                    &reservation,
                    &context,
                )
                .map_err(|e| e.as_json())?;
            let opened = bound
                .launch_prepared(prepared, &commitment)
                .map_err(|e| e.as_json())?;
            let holder_id = opened.holder_id().as_str().to_string();
            let mut browser = self.process.launch(accepted, id)?;
            browser.cleanup = Box::new(CustodyCleanup {
                holder_id,
                opened: Some(opened),
                lifecycle: self.lifecycle.clone(),
                locks: self.locks.clone(),
            });
            Ok(browser)
        }
    }
    async fn bind(planes: &Planes, channel: u16, conversation: &str) {
        let control = ModuleControlRequest::RouteBind {
            role_versions: None,
            call_mode: None,
            route_channel: channel,
            epoch: 3,
            target: RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            identity: BindIdentity::new("/same/project", "test", conversation),
            principal: cerebellum::session_caller_principal_for_test(),
            consumer_capabilities: None,
            admission_facts: Some(
                json!({"agentProjectId":"same-agent","sessionKind":"primary","profileDisposition":"durable","effectiveCapabilityScope":["*"],"browserControlOperations":["browser.launch","browser.status","browser.close"]}),
            ),
            scope: None,
        };
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            1,
            serde_json::to_vec(&control).unwrap(),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        cerebellum::handle_control_request_for_test_with_bindings(
            frame,
            &tx,
            &planes.health,
            &planes.routes,
        )
        .await
        .unwrap();
        assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    }
    async fn launch(planes: &Planes, channel: u16) -> Value {
        let frame = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false), channel, 3, 1, serde_json::to_vec(&json!({"name":"browser.launch","arguments":{},"call_key":format!("launch-{channel}")})).unwrap()).unwrap();
        let (tx, mut rx) = mpsc::channel(2);
        cerebellum::handle_tool_request_for_test_with_existing_planes(frame, &tx, planes)
            .await
            .unwrap();
        serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap()
    }
    #[tokio::test]
    async fn resource_busy_same_agent_launch_reaches_withhold_boundary_with_real_lease_timing() {
        resource_busy_pair(None).await;
    }

    #[tokio::test]
    async fn flow_resource_busy_wire_names_real_holder_in_both_directions() {
        resource_busy_pair(Some(true)).await;
        resource_busy_pair(Some(false)).await;
    }

    async fn resource_busy_pair(flow_holds: Option<bool>) {
        let since = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        // A per-call directory: tests in this binary run in parallel, and two
        // fixtures sharing a root share profile custody, so one test would see
        // the other's browser holding the profile. The counter keeps names
        // distinct within a millisecond, and `create_dir` refuses a reused one.
        static ROOT_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let sequence = ROOT_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let root: PathBuf = std::env::temp_dir().join(format!(
            "ck-resource-busy-{}-{since}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&root).unwrap();
        let launcher = Arc::new(CustodyLauncher {
            lifecycle: Arc::new(Mutex::new(
                ProfileLifecycle::open_with_config(
                    &root,
                    RegistryConfig {
                        uuid_protocol_compatible: true,
                        grant_verifier_available: true,
                        sealing_available: true,
                        ..RegistryConfig::default()
                    },
                )
                .unwrap(),
            )),
            locks: Arc::new(Mutex::new(
                ProfileCustodyLocks::open_filesystem(&root).unwrap(),
            )),
            process: RecordingLauncher::default(),
        });
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config()),
            cerebellum::JournalPersistence::Isolated,
        );
        planes.browser = Arc::new(
            BrowserPlane::with_session_gate(
                planes.sessions.clone(),
                Arc::clone(&planes.lease_clock),
                100,
            )
            .with_result_schema_enforcement(
                cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
            ),
        );
        planes.launch_service = Some(launcher.clone());
        bind(&planes, 9, "holder-conversation").await;
        bind(&planes, 10, "contender-conversation").await;
        if let Some(flow_holds) = flow_holds {
            let mut stamp = flow_stamp();
            stamp.attributes.agent_id = Some("same-agent".into());
            let (channel, conversation) = if flow_holds {
                (9, "holder-conversation")
            } else {
                (10, "contender-conversation")
            };
            let bind = ModuleControlRequest::RouteBind {
                role_versions: None,
                call_mode: None,
                route_channel: channel,
                epoch: 3,
                target: RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
                identity: BindIdentity::new("/same/project", "test", conversation),
                principal: Some(reserved("basal")),
                consumer_capabilities: Some(vec!["elicitation".into()]),
                admission_facts: None,
                scope: Some(stamp),
            };
            let (tx, mut rx) = mpsc::channel(2);
            cerebellum::handle_frame_for_test(
                Frame::build(
                    FrameType::Request,
                    Flags::new(false, Priority::Passive, false),
                    0,
                    0,
                    2,
                    serde_json::to_vec(&bind).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
        }
        let launched = launch(&planes, 9).await;
        assert_eq!(launched["outcome"], "launched", "{launched}");
        tokio::time::sleep(Duration::from_millis(80)).await;
        let reply = launch(&planes, 10).await;
        assert_eq!(reply["outcome"], "resource_busy", "{reply}");
        let detail: cortexkit_resource_busy::ResourceBusy =
            serde_json::from_value(reply["detail"].clone()).unwrap();
        detail.validate().unwrap();
        assert_eq!(detail.resource, "browser_profile");
        let vector: cortexkit_resource_busy::ResourceBusy =
            serde_json::from_str(include_str!("vectors/flow-browser-profile.json")).unwrap();
        vector.validate().unwrap();
        assert_eq!(
            detail.holder,
            if flow_holds == Some(true) {
                vector.holder
            } else {
                cortexkit_resource_busy::Holder::head()
            }
        );
        if flow_holds != Some(true) {
            assert!(reply["detail"]["holder"].get("flow_id").is_none());
        }
        assert!(detail.since_ms >= since && detail.since_ms <= since + 3000);
        assert!(
            detail.retry_after_ms <= config().browser_idle_timeout_ms - 50,
            "retry hint ignores activity: {reply}"
        );
        assert_eq!(
            *launcher.process.launches.lock().unwrap(),
            1,
            "refusal must not launch a second process"
        );
        let (tx, mut rx) = mpsc::channel(2);
        let record = withdraw(&planes, &tx, &mut rx, 10, 2, "launch-10").await;
        assert_eq!(
            body(&record),
            json!({"answer":"refused","reason":"resource_busy"})
        );
        planes.sessions.close(
            "holder-conversation",
            launched["browser_session_id"].as_str().unwrap(),
            &config(),
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn fleet_head_browser_profile_vector_decodes_with_provider_types() {
        let bytes = include_str!("vectors/head-browser-profile.json");
        let detail: cortexkit_resource_busy::ResourceBusy = serde_json::from_str(bytes).unwrap();
        detail.validate().unwrap();
        assert_eq!(detail.holder, cortexkit_resource_busy::Holder::head());
        assert_eq!(
            serde_json::to_value(detail).unwrap(),
            serde_json::from_str::<Value>(bytes).unwrap()
        );
    }
}

fn admission_stamp() -> subc_protocol::scope::ScopeStamp {
    let mut stamp = scope_stamp(1, true);
    stamp.attributes.agent_id = Some("pj-scope-agent".into());
    stamp.attributes.delegates = true;
    stamp
}

fn scope_admission_planes() -> (Planes, Arc<RecordingLauncher>) {
    let launcher = Arc::new(RecordingLauncher::default());
    let standing = Arc::new(
        cerebellum::browser_standing_grants::StandingBrowserGrants::open(
            Arc::new(cerebellum::browser_standing_grants::InMemoryStandingGrantStorage::new()),
            Some("test-machine".into()),
        ),
    );
    let mut planes = Planes::with_browser_config_journaling_and_standing_grants(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
        Some(standing),
    );
    planes.launch_service = Some(launcher.clone());
    (planes, launcher)
}

async fn bind_admission_stamp(
    planes: &Planes,
    stamp: subc_protocol::scope::ScopeStamp,
    principal: Principal,
    facts: Option<Value>,
) -> Frame {
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/caller/chosen/project", "test", "test-session"),
        principal: Some(principal),
        consumer_capabilities: None,
        admission_facts: facts,
        scope: Some(stamp),
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        9,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(2);
    cerebellum::handle_control_request_for_test_with_bindings(
        frame,
        &tx,
        &planes.health,
        &planes.routes,
    )
    .await
    .unwrap();
    rx.recv().await.unwrap()
}

async fn scoped_launch(planes: &Planes) -> Value {
    let reply = invoke_existing(planes, 1, "browser.launch", json!({})).await;
    serde_json::from_slice(&reply.body).unwrap()
}

async fn assert_scope_unattested(stamp: subc_protocol::scope::ScopeStamp, principal: Principal) {
    let (planes, launcher) = scope_admission_planes();
    assert_eq!(
        bind_admission_stamp(&planes, stamp, principal, None)
            .await
            .header
            .ty,
        FrameType::Response
    );
    let body = scoped_launch(&planes).await;
    // Flow routes bind but are refused even before control-operation admission.
    assert!(
        body["reason"] == "admission_facts_absent"
            || body["code"] == "session_caller_not_admitted"
            || (body["outcome"] == "consent_unavailable"
                && body["detail"]["reason"] == "flow_carrier_not_admitted"),
        "{body}"
    );
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

#[tokio::test]
async fn scope_admission_requires_owner_authorized() {
    let mut stamp = admission_stamp();
    stamp.owner_authorized = false;
    assert_scope_unattested(stamp, reserved("prefrontal-core")).await;
}
#[tokio::test]
async fn scope_admission_requires_core_owner() {
    let mut stamp = admission_stamp();
    stamp.owner = reserved("broca");
    assert_scope_unattested(stamp, reserved("prefrontal-core")).await;
}
#[tokio::test]
async fn scope_admission_requires_core_route_principal() {
    assert_scope_unattested(admission_stamp(), reserved("broca")).await;
}
#[tokio::test]
async fn scope_admission_excludes_flow_scopes() {
    let mut stamp = admission_stamp();
    stamp.attributes.flow_id = Some("flow-1".into());
    assert_scope_unattested(stamp, reserved("prefrontal-core")).await;
}
#[tokio::test]
async fn scope_admission_requires_agent_id() {
    let mut stamp = admission_stamp();
    stamp.attributes.agent_id = None;
    assert_scope_unattested(stamp, reserved("prefrontal-core")).await;
}
#[tokio::test]
async fn scope_admission_current_worker_shape_attests_nothing() {
    let mut stamp = admission_stamp();
    stamp.kind = subc_protocol::scope::ScopeKind::Worker;
    stamp.attributes.agent_id = None;
    stamp.attributes.delegates = false;
    assert_scope_unattested(stamp.clone(), reserved("prefrontal-core")).await;
    let (planes, _) = scope_admission_planes();
    bind_admission_stamp(&planes, stamp, reserved("prefrontal-core"), None).await;
    let body = scoped_launch(&planes).await;
    assert_eq!(body["reason"], "admission_facts_absent");
    assert!(
        body["remedy"].as_str().unwrap().contains("agent_id"),
        "{body}"
    );
}
#[tokio::test]
async fn scope_admission_worker_with_agent_gets_controls_and_disposable_profile() {
    let (planes, launcher) = scope_admission_planes();
    let mut stamp = admission_stamp();
    stamp.kind = subc_protocol::scope::ScopeKind::Worker;
    assert_eq!(
        bind_admission_stamp(&planes, stamp, reserved("prefrontal-core"), None)
            .await
            .header
            .ty,
        FrameType::Response
    );
    let body = scoped_launch(&planes).await;
    assert_eq!(body["outcome"], "launched", "{body}");
    assert_eq!(body["profile_disposition"], "disposable");
    assert_eq!(*launcher.launches.lock().unwrap(), 1);
    let facts = launcher.accepted_launches.lock().unwrap()[0].clone();
    assert_eq!(
        facts.identity.session_kind,
        cerebellum_core::identity::SessionKind::Subagent
    );
    for op in ["browser.launch", "browser.status", "browser.close"] {
        assert!(facts.allows_control_operation(op));
    }
}
#[tokio::test]
async fn scope_admission_ephemeral_gets_no_controls() {
    let (planes, launcher) = scope_admission_planes();
    let mut stamp = admission_stamp();
    stamp.kind = subc_protocol::scope::ScopeKind::Ephemeral;
    bind_admission_stamp(&planes, stamp, reserved("prefrontal-core"), None).await;
    let body = scoped_launch(&planes).await;
    assert_eq!(body["reason"], "operation_not_granted", "{body}");
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
    for op in ["browser.status", "browser.close"] {
        let reply = invoke_existing(
            &planes,
            3,
            op,
            if op == "browser.close" {
                json!({"browser_session_id":"absent"})
            } else {
                json!({})
            },
        )
        .await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["reason"], "operation_not_granted", "{body}");
    }
}

async fn seed_scope_standing_grant(planes: &Planes) {
    planes
        .management
        .standing_browser_grants()
        .record(
            "pj-scope-agent",
            cerebellum::browser_standing_grants::StandingSubject::Origin(
                "https://page.example:8443".into(),
            ),
            cerebellum::authorization::COMPOSE,
            vec![],
            None,
            "scope-consent",
        )
        .unwrap();
}

#[tokio::test]
async fn scope_admission_head_launches_for_agent_and_reads_standing_grants() {
    let (mut planes, _) = scope_admission_planes();
    // Exercise production profile selection and custody without starting Chrome.
    let launcher = Arc::new(RecordingLauncher {
        profile_service: Some(
            cerebellum::browser_launch_service::ProductionLaunchService::open(
                config(),
                cerebellum::JournalPersistence::Isolated,
            ),
        ),
        ..RecordingLauncher::default()
    });
    planes.launch_service = Some(launcher.clone());
    seed_scope_standing_grant(&planes).await;
    bind_admission_stamp(
        &planes,
        admission_stamp(),
        reserved("prefrontal-core"),
        None,
    )
    .await;
    let body = scoped_launch(&planes).await;
    assert_eq!(body["outcome"], "launched", "{body}");
    assert_eq!(body["profile_disposition"], "durable");
    let launched = launcher.accepted_launches.lock().unwrap()[0].clone();
    assert_eq!(launched.identity.agent_project_id, "pj-scope-agent");
    assert!(launched.acts_as_agent);
    assert_eq!(launcher.profile_directories.lock().unwrap().len(), 1);
    let service = launcher.profile_service.as_ref().unwrap();
    let reused = service
        .take_and_return_profile_custody(&launched, "second-session")
        .unwrap();
    assert_eq!(
        reused,
        launcher.profile_directories.lock().unwrap()[0],
        "durable agent profile is reused across sessions"
    );
    let mut another_agent = launched.clone();
    another_agent.identity.agent_project_id = "pj-other-agent".into();
    let other = service
        .take_and_return_profile_custody(&another_agent, "other-session")
        .unwrap();
    assert_ne!(
        other, reused,
        "profile ownership is keyed on the stamp's agent"
    );
    assert_eq!(
        launched.identity.logical_profile_key(),
        Some(("pj-scope-agent".into(), "default".into()))
    );
    let navigated = invoke_existing(
        &planes,
        2,
        "browser.navigate",
        json!({"url":"https://page.example:8443/page", "intent":"read the page", "severity":{"tier":2,"credential":false,"financial":false}}),
    )
    .await;
    let body: Value = serde_json::from_slice(&navigated.body).unwrap();
    assert_eq!(
        body["outcome"], "ok",
        "standing row must authorize navigation: {body}"
    );
}

#[tokio::test]
async fn scope_admission_nondelegating_head_has_no_durable_profile_or_standing_access() {
    let (planes, launcher) = scope_admission_planes();
    seed_scope_standing_grant(&planes).await;
    let mut stamp = admission_stamp();
    stamp.attributes.delegates = false;
    bind_admission_stamp(&planes, stamp.clone(), reserved("prefrontal-core"), None).await;
    let body = scoped_launch(&planes).await;
    assert_eq!(body["outcome"], "no_profile", "{body}");
    assert_eq!(body["profile_disposition"], "none", "{body}");
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
    let accepted = cerebellum_core::identity::AcceptedBindFacts::from_bind(
        &BindIdentity::new("/caller/project", "test", "test-session"),
        Some(reserved("prefrontal-core")),
        None,
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    )
    .with_scope(Some(stamp));
    assert_eq!(
        accepted.identity.resolve_profile().logical_profile_key,
        None
    );
    let service = cerebellum::browser_launch_service::ProductionLaunchService::open(
        config(),
        cerebellum::JournalPersistence::Isolated,
    );
    let refusal = service
        .take_and_return_profile_custody(&accepted, "no-profile-session")
        .unwrap_err();
    assert_eq!(refusal["outcome"], "no_profile");
    let navigated = invoke_existing(
        &planes,
        2,
        "browser.navigate",
        json!({"url":"https://page.example:8443/page", "intent":"read the page", "severity":{"tier":2,"credential":false,"financial":false}}),
    )
    .await;
    let body: Value = serde_json::from_slice(&navigated.body).unwrap();
    assert_eq!(
        body["outcome"], "authorization_denied",
        "standing rows must not authorize: {body}"
    );
    assert_eq!(body["context"]["profile_disposition"], "none", "{body}");
    assert!(body["context"]["profile_name"].is_null(), "{body}");
}

#[tokio::test]
async fn scope_admission_conflicting_facts_refuse_bind_and_agreeing_facts_bind() {
    for (field, value) in [
        ("agentProjectId", json!("pj-other")),
        ("sessionKind", json!("subagent")),
    ] {
        let (planes, _) = scope_admission_planes();
        let mut facts = json!({"agentProjectId":"pj-scope-agent", "sessionKind":"primary"});
        facts[field] = value;
        let reply = bind_admission_stamp(
            &planes,
            admission_stamp(),
            reserved("prefrontal-core"),
            Some(facts),
        )
        .await;
        assert_eq!(reply.header.ty, FrameType::Error);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["code"], "scope_admission_conflict");
        assert_eq!(body["detail"]["field"], field);
        assert_eq!(scoped_launch(&planes).await["code"], "route_not_bound");
    }
    let (planes, _) = scope_admission_planes();
    let reply = bind_admission_stamp(&planes, admission_stamp(), reserved("prefrontal-core"),
        Some(json!({"agentProjectId":"pj-scope-agent", "sessionKind":"primary", "effectiveCapabilityScope":["browser.status"]}))).await;
    assert_eq!(reply.header.ty, FrameType::Response);

    let body = scoped_launch(&planes).await;
    assert_eq!(
        body["code"], "capability_denied",
        "facts remain the only capability scope source: {body}"
    );
}

#[tokio::test]
async fn flow_scope_admission_refuses_flat_calls_before_dispatch_and_records_refusal() {
    let (mut planes, launcher) = scope_admission_planes();
    let storage = with_readable_call_records(&mut planes);
    let mut stamp = admission_stamp();
    stamp.attributes.flow_id = Some("flow-1".into());
    let facts = json!({"agentProjectId":"pj-scope-agent", "sessionKind":"primary", "browserControlOperations":["browser.launch","browser.status","browser.close"]});
    assert_eq!(
        bind_admission_stamp(
            &planes,
            stamp.clone(),
            reserved("prefrontal-core"),
            Some(facts.clone())
        )
        .await
        .header
        .ty,
        FrameType::Response
    );
    let expected = json!({"outcome":"consent_unavailable", "detail":{"reason":"flow_carrier_not_admitted"}, "remedy":"open the flow route through authorized reserved:basal"});
    let (tx, mut rx) = mpsc::channel(8);
    for (corr, name, args) in [
        (801, "browser_use", json!({"action":"launch"})),
        (
            802,
            "computer_use",
            json!({"action":"read_state", "target":"com.example.NotInstalled"}),
        ),
    ] {
        let reply = exchange(
            &planes,
            &tx,
            &mut rx,
            keyed_on(9, corr, name, args, &format!("flow:{corr}")),
        )
        .await;
        assert_eq!(reply.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(
            body, expected,
            "{name} must use the pinned route-admission envelope"
        );
        let stored = String::from_utf8(storage.contents().unwrap()).unwrap();
        let record: Value = serde_json::from_str(stored.lines().last().unwrap()).unwrap();
        assert_eq!(record["state"], "refused", "{stored}");
        assert_eq!(record["refusal_reason"], "consent_unavailable", "{stored}");
        assert!(
            rx.try_recv().is_err(),
            "no elicitation or reverse request was sent"
        );
        assert_eq!(*launcher.launches.lock().unwrap(), 0);
    }
    stamp.attributes.flow_id = None;
    assert_eq!(
        bind_admission_stamp(&planes, stamp, reserved("prefrontal-core"), Some(facts))
            .await
            .header
            .ty,
        FrameType::Response
    );
    let reply = invoke_existing(&planes, 803, "browser_use", json!({"action":"launch"})).await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "launched", "{body}");
    assert_eq!(*launcher.launches.lock().unwrap(), 1);
    let reply = invoke_existing(
        &planes,
        804,
        "computer_use",
        json!({"action":"read_state", "target":"com.example.NotInstalled"}),
    )
    .await;
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    // Which refusal follows depends on the platform (Linux serves no computer
    // plane), so the control asserts only that the flow refusal is gone.
    assert_ne!(
        body, expected,
        "without a flow the call must reach ordinary computer admission: {body}"
    );
}

fn flow_stamp() -> subc_protocol::scope::ScopeStamp {
    let mut stamp = admission_stamp();
    stamp.attributes.flow_id = Some("flow-7".into());
    stamp
}

async fn bind_flow_wire(
    planes: &Planes,
    stamp: Option<subc_protocol::scope::ScopeStamp>,
    principal: Principal,
) {
    bind_flow_wire_target(
        planes,
        stamp,
        principal,
        RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    )
    .await;
}

async fn bind_flow_wire_target(
    planes: &Planes,
    stamp: Option<subc_protocol::scope::ScopeStamp>,
    principal: Principal,
    target: RouteTarget,
) {
    let reply = bind_flow_wire_reply(planes, stamp, principal, target).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
}

async fn bind_flow_wire_reply(
    planes: &Planes,
    stamp: Option<subc_protocol::scope::ScopeStamp>,
    principal: Principal,
    target: RouteTarget,
) -> Frame {
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 9,
        epoch: 3,
        target,
        identity: BindIdentity::new("/caller/project", "test", "test-session"),
        principal: Some(principal),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: None,
        scope: stamp,
    };
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(
        Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            1,
            serde_json::to_vec(&bind).unwrap(),
        )
        .unwrap(),
        &tx,
        planes,
    )
    .await
    .unwrap();
    rx.recv().await.unwrap()
}

async fn flow_wire_call(planes: &Planes, corr: u64, action: Value) -> Value {
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(request(corr, "browser_use", action), &tx, planes)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "no flow may elicit: {reply:?}"
    );
    assert!(rx.try_recv().is_err(), "unexpected elicitation frame");
    serde_json::from_slice(&reply.body).unwrap()
}

fn flow_planes() -> (Planes, Arc<RecordingLauncher>) {
    let (mut planes, launcher) = scope_admission_planes();
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .unwrap_or_else(|_| panic!("fresh browser plane is uniquely owned"))
            .with_result_schema_enforcement(
                cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
            ),
    );
    (planes, launcher)
}

#[tokio::test]
async fn flow_owner_standing_grant_navigates_without_elicitation() {
    let (planes, launcher) = flow_planes();
    seed_scope_standing_grant(&planes).await;
    bind_flow_wire(&planes, Some(flow_stamp()), reserved("basal")).await;
    let launch = flow_wire_call(&planes, 2, json!({"action":"launch"})).await;
    assert_eq!(launch["outcome"], "launched", "{launch}");
    let accepted = launcher.accepted_launches.lock().unwrap()[0].clone();
    assert_eq!(
        accepted.identity.logical_profile_key(),
        Some(("pj-scope-agent".into(), "default".into()))
    );
    assert_eq!(accepted.flow_id.as_deref(), Some("flow-7"));
    let reply = flow_wire_call(&planes, 3, json!({"action":"navigate","url":"https://page.example:8443/page","intent":"read the page","severity":{"tier":2,"credential":false,"financial":false}})).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(*launcher.launches.lock().unwrap(), 1);
}

#[tokio::test]
async fn flow_missing_browser_grant_refuses_before_launch_or_navigation() {
    let (planes, launcher) = flow_planes();
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    bind_flow_wire(&planes, Some(flow_stamp()), reserved("basal")).await;
    let reply = flow_wire_call(&planes, 2, json!({"action":"navigate","url":"https://page.example:8443/page","intent":"read the page","severity":{"tier":2,"credential":false,"financial":false}})).await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(reply["detail"]["reason"], "unattended_flow");
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
    assert!(launcher.accepted_launches.lock().unwrap().is_empty());
}

#[tokio::test]
async fn flow_global_and_nondelegating_have_no_profile_or_standing_authority() {
    for no_agent in [true, false] {
        let (planes, launcher) = flow_planes();
        seed_scope_standing_grant(&planes).await;
        let mut stamp = flow_stamp();
        if no_agent {
            stamp.attributes.agent_id = None;
        } else {
            stamp.attributes.delegates = false;
        }
        bind_flow_wire(&planes, Some(stamp.clone()), reserved("basal")).await;
        let facts = planes.routes.accepted_bind_for_test(9, 3).unwrap();
        assert!(!facts.acts_as_agent);
        assert!(!facts.agent_project_id_attested);
        assert!(!facts.session_kind_attested);
        assert_eq!(facts.identity.logical_profile_key(), None);
        for (corr, action) in [
            (2, json!({"action":"launch"})),
            (
                3,
                json!({"action":"navigate","url":"https://page.example:8443/page","intent":"read the page","severity":{"tier":2,"credential":false,"financial":false}}),
            ),
        ] {
            assert_eq!(
                flow_wire_call(&planes, corr, action).await["outcome"],
                "consent_unavailable"
            );
        }
        assert_eq!(*launcher.launches.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn flow_carrier_requires_exact_basal_authorized_core_stamp() {
    for (principal, owner, authorized) in [
        ("prefrontal-core", "prefrontal-core", true),
        ("broca", "prefrontal-core", true),
    ] {
        let (planes, launcher) = flow_planes();
        let mut stamp = flow_stamp();
        stamp.owner = reserved(owner);
        stamp.owner_authorized = authorized;
        bind_flow_wire(&planes, Some(stamp), reserved(principal)).await;
        for (corr, action) in [
            (2, json!({"action":"launch"})),
            (
                3,
                json!({"action":"navigate","url":"https://page.example:8443/page","intent":"read the page","severity":{"tier":2,"credential":false,"financial":false}}),
            ),
        ] {
            let reply = flow_wire_call(&planes, corr, action).await;
            assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
            assert_eq!(
                reply["detail"]["reason"], "flow_carrier_not_admitted",
                "{reply}"
            );
        }
        assert_eq!(*launcher.launches.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn flow_login_and_standing_offer_sites_refuse_without_cards() {
    let (planes, launcher) = flow_planes();
    bind_flow_wire(&planes, Some(flow_stamp()), reserved("basal")).await;
    for (corr, action) in [
        (
            2,
            json!({"action":"import_login","origin":"https://page.example:8443"}),
        ),
        (
            3,
            json!({"action":"capture_login","credential_domain":"page.example","account":"me","fetch_url":"https://page.example:8443/api","login_url":"https://page.example:8443/login"}),
        ),
        (
            4,
            json!({"action":"open_grant","origins":["https://page.example:8443"],"hazards":[]}),
        ),
        (
            5,
            json!({"action":"present","origin":"https://page.example:8443"}),
        ),
    ] {
        let reply = flow_wire_call(&planes, corr, action).await;
        assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
        assert_eq!(reply["detail"]["reason"], "unattended_flow", "{reply}");
    }
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

#[tokio::test]
async fn flow_recovery_and_profile_rebind_consent_sites_never_open_cards() {
    let (planes, launcher) = flow_planes();
    bind_flow_wire_target(
        &planes,
        Some(flow_stamp()),
        reserved("basal"),
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    )
    .await;
    for (corr, method, params) in [
        (
            2,
            cerebellum::management::CLEAR_LAUNCH_RECOVERY,
            json!({"agent_project_id":"pj-scope-agent"}),
        ),
        (3, cerebellum::management::REBIND_PROFILE_ROOT, json!({})),
    ] {
        let mut frame = request(corr, "unused", json!({}));
        frame.body = serde_json::to_vec(&json!({"method":method,"params":params})).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        cerebellum::handle_frame_for_test(frame, &tx, &planes)
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "consent_unavailable", "{body}");
        assert_eq!(body["detail"]["reason"], "unattended_flow");
        assert!(rx.try_recv().is_err());
    }
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

#[tokio::test]
async fn flow_basal_bind_requires_admitted_carrier() {
    let mut no_flow_id = flow_stamp();
    no_flow_id.attributes.flow_id = None;
    let mut unauthorized = flow_stamp();
    unauthorized.owner_authorized = false;
    let mut wrong_owner = flow_stamp();
    wrong_owner.owner = reserved("broca");
    for stamp in [
        None,
        Some(no_flow_id),
        Some(unauthorized),
        Some(wrong_owner),
    ] {
        let (planes, launcher) = flow_planes();
        let reply = bind_flow_wire_reply(
            &planes,
            stamp,
            reserved("basal"),
            RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
        )
        .await;
        assert_eq!(
            reply.header.ty,
            FrameType::Error,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["code"], "principal_denied", "{body}");
        assert!(planes.routes.accepted_bind_for_test(9, 3).is_none());
        assert_eq!(*launcher.launches.lock().unwrap(), 0);
    }
}

#[tokio::test]
async fn flow_operator_operations_cannot_list_or_revoke_app_grants() {
    use cerebellum::computer_grants::{
        AlwaysGrantRecord, ComputerGrants, GrantStorage, GrantStoreState, InMemoryGrantStorage,
        GRANT_STORE_VERSION,
    };
    let (mut planes, launcher) = flow_planes();
    let storage = Arc::new(InMemoryGrantStorage::new());
    let state = GrantStoreState {
        version: GRANT_STORE_VERSION,
        records: vec![AlwaysGrantRecord {
            agent_project_id: "pj-scope-agent".into(),
            bundle_identity: "com.example.Editor".into(),
            team_id: Some("TEAM".into()),
            designated_requirement: Some("test requirement".into()),
            machine_uuid: "machine".into(),
            created_at_ms: 1,
        }],
    };
    storage.save(&state).unwrap();
    planes.management = Arc::new(
        cerebellum::management::ManagementPlane::with_computer_grants(
            Arc::new(cerebellum::management::PlatformResolver::new()),
            Arc::new(ComputerGrants::open(
                storage.clone(),
                Some("machine".into()),
            )),
        ),
    );
    assert_eq!(
        planes.management.computer_grants().list()["grants"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    bind_flow_wire_target(
        &planes,
        Some(flow_stamp()),
        reserved("basal"),
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    )
    .await;
    for (corr, method, params) in [
        (2, cerebellum::management::LIST_APP_GRANTS, json!({})),
        (
            3,
            cerebellum::management::REVOKE_APP_GRANT,
            json!({"grantee":"pj-scope-agent","bundle_identity":"com.example.Editor"}),
        ),
        (
            4,
            cerebellum::management::CLEAR_LAUNCH_RECOVERY,
            json!({"agent_project_id":"pj-scope-agent"}),
        ),
        (5, cerebellum::management::REBIND_PROFILE_ROOT, json!({})),
        (6, cerebellum::management::REVOKE_GRANT, json!({})),
        (
            7,
            cerebellum::management::LIST_GRANTS,
            json!({"agent_id":"pj-scope-agent"}),
        ),
    ] {
        let mut frame = request(corr, "unused", json!({}));
        frame.body = serde_json::to_vec(&json!({"method":method,"params":params})).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        cerebellum::handle_frame_for_test(frame, &tx, &planes)
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "consent_unavailable", "{method}: {body}");
        assert_eq!(body["detail"]["reason"], "unattended_flow");
        assert!(
            body.get("grants").is_none(),
            "operator records must not be disclosed"
        );
        assert!(rx.try_recv().is_err());
        assert_eq!(
            planes.management.computer_grants().list()["grants"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(storage.load().unwrap(), state);
    }
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

fn frame_fixture() -> Arc<Mutex<FrameFixture>> {
    use cerebellum::snapshot_store::FrameDocument;
    Arc::new(Mutex::new(FrameFixture {
        financial: false,
        action_origin_override: None,
        churn_on_screenshot: false,
        readable: vec![],
        documents: vec![
            FrameDocument {
                navigation_revision: 0,
                frame_id: "frame-main".into(),
                parent_id: None,
                session_id: "main-session".into(),
                loader_id: "main-loader".into(),
                url: "https://page.example:8443/page".into(),
                origin: "https://page.example:8443".into(),
            },
            FrameDocument {
                navigation_revision: 0,
                frame_id: "payment-frame".into(),
                parent_id: Some("frame-main".into()),
                session_id: "payment-session".into(),
                loader_id: "payment-loader".into(),
                url: "https://payment.example:8443/frame".into(),
                origin: "https://payment.example:8443".into(),
            },
        ],
    }))
}

#[tokio::test]
async fn top_page_read_covers_ungranted_frame_but_actions_require_frame_origin() {
    let fixture = frame_fixture();
    let launcher = Arc::new(RecordingLauncher {
        frame_fixture: Some(fixture.clone()),
        ..Default::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    for mode in ["actionable", "ax"] {
        let snapshot = invoke(&planes, 900, "browser.snapshot", json!({"mode":mode})).await;
        let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        assert!(snapshot.to_string().contains("Sign in"), "{snapshot}");
        assert_eq!(fixture.lock().unwrap().readable.len(), 2);
        let click = invoke(&planes, 901, "browser.click", json!({"ref":first_ref(&snapshot),"snapshot_id":snapshot["snapshot_id"],"intent":"check embedded action origin","severity":{"tier":2,"credential":false,"financial":false}})).await;
        let click: Value = serde_json::from_slice(&click.body).unwrap();
        assert_eq!(click["outcome"], "consent_unavailable", "{click}");
        assert_eq!(
            click["detail"]["attempted_origin"],
            "https://payment.example:8443"
        );
        assert_eq!(
            click["detail"]["grant_request"],
            json!({"origins":["https://payment.example:8443"],"severity_tier":2,"hazards":[]})
        );
        assert!(click["remedy"]
            .as_str()
            .unwrap()
            .contains("call from the agent session"));
        let zoom = invoke(
            &planes,
            902,
            "browser.snapshot",
            json!({"zoom":first_ref(&snapshot)}),
        )
        .await;
        let zoom: Value = serde_json::from_slice(&zoom.body).unwrap();
        assert_eq!(zoom["outcome"], "ok", "{zoom}");
        assert!(zoom.to_string().contains("Sign in"));
    }
    let full = invoke(&planes, 905, "browser.snapshot", json!({"mode":"dom_full"})).await;
    let full: Value = serde_json::from_slice(&full.body).unwrap();
    assert_eq!(full["outcome"], "ok", "{full}");
    assert!(full.to_string().contains("Sign in"));
    let image = invoke(&planes, 903, "browser.screenshot", json!({})).await;
    let image: Value = serde_json::from_slice(&image.body).unwrap();
    assert_eq!(image["outcome"], "ok", "{image}");
    assert!(launcher.effects.lock().unwrap().contains(&"screenshot"));
    let point = invoke(&planes, 904, "browser.click_point", json!({"x_px":0,"y_px":0,"image_width_px":1,"image_height_px":1,"snapshot_id":image["snapshot_id"],"intent":"check point action origin","severity":{"tier":4,"credential":false,"financial":true}})).await;
    let point: Value = serde_json::from_slice(&point.body).unwrap();
    assert_eq!(point["outcome"], "consent_unavailable", "{point}");
    assert_eq!(
        point["detail"]["attempted_origin"],
        "https://payment.example:8443"
    );
    assert_eq!(
        point["detail"]["grant_request"]["origins"],
        json!(["https://payment.example:8443"])
    );
    assert!(point["remedy"]
        .as_str()
        .unwrap()
        .contains("call from the agent session"));
    assert!(!launcher.effects.lock().unwrap().contains(&"input_press"));
}

#[tokio::test]
async fn frame_ref_and_point_actions_use_frame_origin_not_shell_origin() {
    let fixture = frame_fixture();
    let launcher = Arc::new(RecordingLauncher {
        frame_fixture: Some(fixture.clone()),
        ..Default::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    grant_browser(&planes, "https://payment.example:8443", vec![]).await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    // Inject a ref naming another origin to exercise action authorization
    // independently of the top page's coverage of embedded reads.
    fixture.lock().unwrap().action_origin_override =
        Some("https://other-frame.example:8443".into());
    let snapshot = invoke(&planes, 910, "browser.snapshot", json!({"mode":"ax"})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    let reply = invoke(&planes, 911, "browser.click", json!({"ref":first_ref(&snapshot),"snapshot_id":snapshot["snapshot_id"],"intent":"exercise the frame authorization boundary","severity":{"tier":2,"credential":false,"financial":false}})).await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert_eq!(
        reply["detail"]["attempted_origin"],
        "https://other-frame.example:8443"
    );
    let screenshot = invoke(&planes, 912, "browser.screenshot", json!({})).await;
    let screenshot: Value = serde_json::from_slice(&screenshot.body).unwrap();
    let point = invoke(&planes, 913, "browser.click_point", json!({"x_px":0,"y_px":0,"image_width_px":1,"image_height_px":1,"snapshot_id":screenshot["snapshot_id"],"intent":"exercise point frame authorization","severity":{"tier":4,"credential":false,"financial":true}})).await;
    let point: Value = serde_json::from_slice(&point.body).unwrap();
    assert_eq!(point["outcome"], "consent_unavailable", "{point}");
    assert_eq!(
        point["detail"]["attempted_origin"],
        "https://other-frame.example:8443"
    );
    assert!(!launcher.effects.lock().unwrap().contains(&"input_press"));
}

#[tokio::test]
async fn navigated_frame_ref_is_stale_before_mouse_input() {
    let fixture = frame_fixture();
    let launcher = Arc::new(RecordingLauncher {
        frame_fixture: Some(fixture.clone()),
        ..Default::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    grant_browser(&planes, "https://payment.example:8443", vec![]).await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    let snapshot = invoke(&planes, 920, "browser.snapshot", json!({"mode":"ax"})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    fixture.lock().unwrap().documents[1].loader_id = "navigated-loader".into();
    let zoom = invoke(
        &planes,
        922,
        "browser.snapshot",
        json!({"zoom":first_ref(&snapshot)}),
    )
    .await;
    let zoom: Value = serde_json::from_slice(&zoom.body).unwrap();
    assert_eq!(zoom["outcome"], "stale_snapshot", "{zoom}");
    let reply = invoke(&planes, 921, "browser.click", json!({"ref":first_ref(&snapshot),"snapshot_id":snapshot["snapshot_id"],"intent":"exercise stale frame refusal","severity":{"tier":2,"credential":false,"financial":false}})).await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["outcome"], "stale_snapshot", "{reply}");
    assert!(reply["remedy"].as_str().unwrap().contains("snapshot"));
    assert!(!launcher.effects.lock().unwrap().contains(&"input_press"));
    let fresh = invoke(&planes, 923, "browser.snapshot", json!({"mode":"ax"})).await;
    let fresh: Value = serde_json::from_slice(&fresh.body).unwrap();
    let clicked = invoke(&planes, 924, "browser.click", json!({"ref":first_ref(&fresh),"snapshot_id":fresh["snapshot_id"],"intent":"fresh frame snapshot can click","severity":{"tier":2,"credential":false,"financial":false}})).await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert!(launcher.effects.lock().unwrap().contains(&"input_press"));
}

fn frame_submit_record(
    frame: &cerebellum::snapshot_store::FrameDocument,
    epoch: u64,
    token: &str,
) -> cerebellum::classification::NonTypeClassificationRecord {
    let dom = json!({"nodes":[
        {"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"","nodeName":"#document"},
        {"nodeId":7,"backendNodeId":7,"parentId":1,"nodeType":1,"localName":"form","attributes":[]},
        {"nodeId":8,"backendNodeId":8,"parentId":7,"nodeType":1,"localName":"input","attributes":["autocomplete",token]},
        {"nodeId":42,"backendNodeId":42,"parentId":7,"nodeType":1,"localName":"button","attributes":["type",if token.is_empty() { "button" } else { "submit" }]}
    ]});
    cerebellum::browser::navigation::classify_flattened_document(
        dom.as_object().unwrap(),
        &BackendNodeIdentity::new("target", &frame.frame_id, 42).unwrap(),
        epoch,
        &frame.origin,
    )
    .unwrap()
}

#[tokio::test]
async fn frame_credential_and_payment_submit_is_refused_by_ref_and_point_wire_paths() {
    for (financial, missing_hazard) in [
        (true, "financial_form_submit"),
        (false, "credential_form_submit"),
    ] {
        let fixture = frame_fixture();
        fixture.lock().unwrap().financial = financial;
        let launcher = Arc::new(RecordingLauncher {
            frame_fixture: Some(fixture),
            hazardous_target: !financial,
            ..Default::default()
        });
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config()),
            cerebellum::JournalPersistence::Isolated,
        );
        planes.launch_service = Some(launcher.clone());
        grant_browser(&planes, "https://page.example:8443", vec![]).await;
        grant_browser(&planes, "https://payment.example:8443", vec![]).await;
        launch_at(&planes, &launcher.page, "https://page.example:8443").await;
        let snapshot = invoke(&planes, 930, "browser.snapshot", json!({"mode":"ax"})).await;
        let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
        let screenshot = invoke(&planes, 931, "browser.screenshot", json!({})).await;
        let screenshot: Value = serde_json::from_slice(&screenshot.body).unwrap();
        assert_eq!(screenshot["outcome"], "ok", "{screenshot}");
        let severity = json!({"tier":4,"credential":!financial,"financial":financial});
        let ref_reply = invoke(&planes, 932, "browser.click", json!({"ref":first_ref(&snapshot),"snapshot_id":snapshot["snapshot_id"],"intent":"exercise frame submit policy","severity":severity})).await;
        let point_reply = invoke(&planes, 933, "browser.click_point", json!({"x_px":0,"y_px":0,"image_width_px":1,"image_height_px":1,"snapshot_id":screenshot["snapshot_id"],"intent":"exercise frame point submit policy","severity":severity})).await;
        for reply in [ref_reply, point_reply] {
            let reply: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
            assert_eq!(reply["detail"]["missing_hazard"], missing_hazard);
            assert_eq!(
                reply["detail"]["attempted_origin"],
                "https://payment.example:8443"
            );
            assert_eq!(
                reply["detail"]["required"]["financial"], financial,
                "{reply}"
            );
            assert_eq!(
                reply["detail"]["required"]["credential"], !financial,
                "{reply}"
            );
        }
        assert!(!launcher.effects.lock().unwrap().contains(&"input_press"));
    }
}

#[tokio::test]
async fn screenshot_accepts_embedded_frame_churn_under_top_page_read_grant() {
    let fixture = frame_fixture();
    fixture.lock().unwrap().churn_on_screenshot = true;
    let launcher = Arc::new(RecordingLauncher {
        frame_fixture: Some(fixture.clone()),
        ..Default::default()
    });
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    launch_at(&planes, &launcher.page, "https://page.example:8443").await;
    let image = invoke(&planes, 990, "browser.screenshot", json!({})).await;
    let image: Value = serde_json::from_slice(&image.body).unwrap();
    assert_eq!(image["outcome"], "ok", "{image}");
    assert_eq!(
        fixture.lock().unwrap().documents[1].loader_id,
        "replacement-embed-loader"
    );
    assert!(launcher.effects.lock().unwrap().contains(&"screenshot"));
}

#[derive(Clone, Default)]
struct TypePage {
    input_type: String,
    caret: Arc<Mutex<usize>>,
    selected: Arc<Mutex<bool>>,
    ignore_delete: bool,
    fail_focus: bool,
    cold_runtime: bool,
    has_focus: Arc<Mutex<bool>>,
    runtime_enabled: Arc<Mutex<bool>>,
    autocomplete: String,
    frame_origin: Option<String>,
    value: Arc<Mutex<String>>,
}

impl TypePage {
    fn document(&self) -> serde_json::Map<String, Value> {
        json!({"nodes":[{"nodeId":1,"backendNodeId":LINK_BACKEND_NODE,"nodeType":1,"localName":"input","nodeName":"INPUT","attributes":["type",if self.input_type.is_empty() { "text" } else { &self.input_type },"autocomplete",self.autocomplete]}]}).as_object().unwrap().clone()
    }
}

async fn type_fixture(page: TypePage) -> (Planes, CommittedPage, Arc<Mutex<Vec<String>>>, String) {
    let committed = CommittedPage::default();
    let commands = Arc::new(Mutex::new(Vec::new()));
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(CdpClickLauncher {
        unanswered: None,
        scenario: ClickScenario::NoNavigation,
        snapshots: Arc::default(),
        page: committed.clone(),
        commands: commands.clone(),
        typing: Some(page),
    }));
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(planes.sessions.clone(), planes.lease_clock.clone(), 3_000)
            .with_result_schema_enforcement(
                cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
            )
            .with_in_memory_journal(cerebellum::journal::JournalConfig {
                journal_retention_bytes: 1_048_576,
                journal_max_entry_bytes: 65_536,
            })
            .with_grants_installed(GrantStore::new([ActionGrant::new(
                "type",
                1,
                "test-session",
                Severity::new(4, false, false),
                [CLICK_PAGE_ORIGIN],
            )])),
    );
    launch_at(&planes, &committed, CLICK_PAGE_ORIGIN).await;
    let snapshot = body(&invoke(&planes, 900, "browser.snapshot", json!({"mode":"ax"})).await);
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    let reference = first_ref(&snapshot);
    (planes, committed, commands, reference)
}

async fn type_wire(planes: &Planes, reference: &str, text: &str, clear_first: bool) -> Value {
    body(
        &invoke(
            planes,
            901,
            "browser_use",
            json!({"action":"type","ref":reference,"text":text,"clear_first":clear_first}),
        )
        .await,
    )
}

#[tokio::test]
async fn wire_type_plain_field_dispatches_characters() {
    let page = TypePage::default();
    let value = page.value.clone();
    let (planes, _, commands, reference) = type_fixture(page).await;
    let reply = body(
        &invoke(
            &planes,
            901,
            "browser.type",
            json!({"ref":reference,"text":"hello 🦀"}),
        )
        .await,
    );
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["characters_dispatched"], 7);
    assert_eq!(*value.lock().unwrap(), "hello 🦀");
    let methods = commands.lock().unwrap();
    assert!(methods.iter().any(|method| method == "DOM.focus"));
    assert!(methods.iter().any(|method| method == "Input.insertText"));
}

#[tokio::test]
async fn wire_type_clear_first_replaces_value() {
    let page = TypePage::default();
    let value = page.value.clone();
    *value.lock().unwrap() = "previous".into();
    let (planes, _, _, reference) = type_fixture(page).await;
    assert_eq!(
        type_wire(&planes, &reference, "replacement", true).await["outcome"],
        "ok"
    );
    assert_eq!(*value.lock().unwrap(), "replacement");
}

#[tokio::test]
async fn wire_type_sensitive_cross_origin_fields_refuse_before_authorization() {
    for (input_type, autocomplete) in [
        ("password", ""),
        ("text", "cc-number"),
        ("text", "current-password"),
        ("text", "new-password"),
        ("text", "one-time-code"),
    ] {
        let page = TypePage {
            input_type: input_type.into(),
            autocomplete: autocomplete.into(),
            frame_origin: Some("https://payments.example".into()),
            ..Default::default()
        };
        let (planes, _, commands, reference) = type_fixture(page).await;
        let before = planes.browser.journal_export_for_test().await;
        let reply = type_wire(&planes, &reference, "secret", false).await;
        assert_eq!(
            reply["detail"]["reason_code"], "credential_input_unsupported",
            "{reply}"
        );
        assert!(reply["remedy"].as_str().unwrap().contains("present"));
        assert_eq!(planes.browser.journal_export_for_test().await, before);
        assert!(!commands
            .lock()
            .unwrap()
            .iter()
            .any(|method| method.starts_with("Input.") || method == "DOM.focus"));
    }
}

#[tokio::test]
async fn wire_type_ungranted_frame_names_its_origin() {
    let (planes, _, commands, reference) = type_fixture(TypePage {
        frame_origin: Some("https://ungranted.example".into()),
        ..Default::default()
    })
    .await;
    let reply = type_wire(&planes, &reference, "hello", false).await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    assert!(
        reply.to_string().contains("https://ungranted.example"),
        "{reply}"
    );
    assert!(!commands
        .lock()
        .unwrap()
        .iter()
        .any(|method| method.starts_with("Input.")));
}

#[tokio::test]
async fn wire_type_stale_document_refuses_before_input() {
    let (planes, page, commands, reference) = type_fixture(TypePage::default()).await;
    page.commit("https://example.com/different-document");
    let reply = type_wire(&planes, &reference, "hello", false).await;
    assert_eq!(reply["outcome"], "stale_snapshot", "{reply}");
    assert!(!commands
        .lock()
        .unwrap()
        .iter()
        .any(|method| method.starts_with("Input.") || method == "DOM.focus"));
}

#[tokio::test]
async fn wire_type_missing_text_is_refused_by_name() {
    let (planes, _, _, reference) = type_fixture(TypePage::default()).await;
    let reply = body(
        &invoke(
            &planes,
            902,
            "browser_use",
            json!({"action":"type","ref":reference}),
        )
        .await,
    );
    assert_eq!(reply["outcome"], "invalid_request", "{reply}");
    assert_eq!(reply["detail"]["field"], "text", "{reply}");
    let granular = body(&invoke(&planes, 904, "browser.type", json!({"ref":reference})).await);
    assert_eq!(granular["detail"]["field"], "text", "{granular}");
}

fn contains_type_secret(records: &[String], secret: &str) -> bool {
    records.iter().any(|record| record.contains(secret))
}

#[tokio::test]
async fn wire_type_planted_secret_absent_from_all_records() {
    const SECRET: &str = "PLANTED-BROWSER-TYPE-SECRET-7f3c1e";
    let page = TypePage::default();
    let value = page.value.clone();
    let (mut planes, _, _, reference) = type_fixture(page).await;
    let storage = with_readable_call_records(&mut planes);
    let (tx, mut rx) = mpsc::channel(8);
    let reply = exchange(
        &planes,
        &tx,
        &mut rx,
        keyed_on(
            9,
            903,
            "browser_use",
            json!({"action":"type","ref":reference,"text":SECRET}),
            "pf:type-secret",
        ),
    )
    .await;
    assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));
    assert_eq!(*value.lock().unwrap(), SECRET);
    let journal = planes.browser.journal_export_for_test().await;
    assert!(
        journal.contains("browser.type") || journal.contains("\"type\""),
        "{journal}"
    );
    let records = vec![
        journal,
        planes.browser.refusal_ring_export_for_test().await,
        String::from_utf8(storage.contents().expect("keyed call record")).unwrap(),
        body(&reply).to_string(),
    ];
    assert!(
        !contains_type_secret(&records, SECRET),
        "typed text reached records"
    );
    // Plant the marker into a copy of a real journal row to prove the same scanner detects it.
    let mut planted = records.clone();
    planted[0].push_str(SECRET);
    assert!(contains_type_secret(&planted, SECRET));
}

#[tokio::test]
async fn wire_type_append_moves_caret_to_end() {
    let page = TypePage::default();
    let value = page.value.clone();
    *value.lock().unwrap() = "existing".into();
    let (planes, _, _, reference) = type_fixture(page).await;
    let reply = type_wire(&planes, &reference, " suffix", false).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(*value.lock().unwrap(), "existing suffix");
}

#[tokio::test]
async fn wire_type_clear_verifies_empty_before_insert() {
    let page = TypePage {
        ignore_delete: true,
        ..Default::default()
    };
    let value = page.value.clone();
    *value.lock().unwrap() = "existing".into();
    let (planes, _, commands, reference) = type_fixture(page).await;
    let reply = type_wire(&planes, &reference, "replacement", true).await;
    assert_eq!(reply["outcome"], "type_not_ready", "{reply}");
    assert_eq!(*value.lock().unwrap(), "existing");
    assert!(!commands
        .lock()
        .unwrap()
        .iter()
        .any(|method| method == "Input.insertText"));
}

#[tokio::test]
async fn wire_type_focus_failure_is_retryable_not_internal() {
    let (planes, _, commands, reference) = type_fixture(TypePage {
        fail_focus: true,
        ..Default::default()
    })
    .await;
    let reply = type_wire(&planes, &reference, "hello", false).await;
    assert_eq!(reply["outcome"], "type_not_ready", "{reply}");
    assert_eq!(
        reply["detail"]["reason_code"], "type_focus_not_ready",
        "{reply}"
    );
    assert!(!commands
        .lock()
        .unwrap()
        .iter()
        .any(|method| method.starts_with("Input.")));
}

#[tokio::test]
async fn wire_type_initializes_runtime_before_resolving_cold_target() {
    let page = TypePage {
        cold_runtime: true,
        ..Default::default()
    };
    let value = page.value.clone();
    let (planes, _, commands, reference) = type_fixture(page).await;
    let reply = type_wire(&planes, &reference, "cold text", false).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(*value.lock().unwrap(), "cold text");
    let commands = commands.lock().unwrap();
    assert!(
        commands
            .iter()
            .position(|method| method == "Runtime.enable")
            .unwrap()
            < commands
                .iter()
                .position(|method| method == "DOM.resolveNode")
                .unwrap()
    );
}

#[tokio::test]
async fn wire_type_emulates_focus_before_setting_append_caret() {
    let page = TypePage::default();
    assert!(!*page.has_focus.lock().unwrap());
    let value = page.value.clone();
    *value.lock().unwrap() = "existing".into();
    let (planes, _, _, reference) = type_fixture(page).await;
    let reply = type_wire(&planes, &reference, " suffix", false).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(*value.lock().unwrap(), "existing suffix");
}

#[tokio::test]
async fn wire_type_emulates_focus_once_per_attached_session() {
    let page = TypePage::default();
    let has_focus = page.has_focus.clone();
    let (planes, _, commands, reference) = type_fixture(page).await;
    assert_eq!(
        type_wire(&planes, &reference, "first", false).await["outcome"],
        "ok"
    );
    assert_eq!(
        type_wire(&planes, &reference, "second", false).await["outcome"],
        "ok"
    );
    assert!(*has_focus.lock().unwrap());
    assert_eq!(
        commands
            .lock()
            .unwrap()
            .iter()
            .filter(|method| method.as_str() == "Emulation.setFocusEmulationEnabled")
            .count(),
        1
    );
}

async fn navigate_unanswered(method: &'static str, code: &str, sent: bool) {
    let commands = Arc::new(Mutex::new(Vec::new()));
    let cfg = BrowserConfig {
        navigation_settle_deadline_ms: if code == "navigate_deadline_expired" {
            0
        } else {
            100
        },
        ..config()
    };
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(cfg.clone()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(CdpClickLauncher {
        unanswered: Some(method),
        scenario: ClickScenario::NoNavigation,
        snapshots: Arc::default(),
        page: CommittedPage::default(),
        commands: commands.clone(),
        typing: None,
    }));
    planes.browser = Arc::new(
        BrowserPlane::with_session_gate(
            planes.sessions.clone(),
            planes.lease_clock.clone(),
            cfg.navigation_settle_deadline_ms,
        )
        .with_result_schema_enforcement(
            cerebellum::computer_capability::ResultSchemaEnforcement::Withhold,
        )
        .with_grants_installed(GrantStore::new([ActionGrant::new(
            "browse",
            1,
            "test-session",
            Severity::new(4, false, false),
            ["https://example.com"],
        )])),
    );
    let launched = invoke(&planes, 1, "browser.launch", json!({})).await;
    let launched: Value = serde_json::from_slice(&launched.body).unwrap();
    assert_eq!(launched["outcome"], "launched", "{launched}");
    let reply = invoke(&planes, 2, "browser.navigate", json!({"url":"https://example.com", "intent":"open page", "wait":"none", "severity":{"tier":1,"credential":false,"financial":false}})).await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["outcome"], "navigate_not_ready", "{reply}");
    assert_eq!(reply["detail"]["reason_code"], code, "{reply}");
    assert_eq!(reply["detail"]["navigation_sent"], sent, "{reply}");
    let commands = commands.lock().unwrap();
    if code == "navigate_deadline_expired" {
        assert!(commands.is_empty(), "{commands:?}");
    } else {
        assert!(
            commands.iter().any(|command| command == method),
            "{commands:?}"
        );
    }
    assert_eq!(
        commands.iter().any(|method| method == "Page.navigate"),
        sent,
        "{commands:?}"
    );
    let remedy = reply["remedy"].as_str().unwrap();
    assert!(
        if sent {
            remedy.contains("snapshot first")
        } else {
            remedy.contains("Page.navigate was not sent")
        },
        "{reply}"
    );
}

#[tokio::test]
async fn navigate_target_timeout_is_retryable() {
    navigate_unanswered("Target.createTarget", "navigate_target_not_ready", false).await;
}
#[tokio::test]
async fn navigate_attachment_timeout_is_retryable() {
    navigate_unanswered(
        "Target.attachToTarget",
        "navigate_attachment_not_ready",
        false,
    )
    .await;
}
#[tokio::test]
async fn navigate_page_timeout_is_retryable() {
    navigate_unanswered("Page.enable", "navigate_page_not_ready", false).await;
}
#[tokio::test]
async fn navigate_network_timeout_is_retryable() {
    navigate_unanswered("Network.enable", "navigate_network_not_ready", false).await;
}
#[tokio::test]
async fn navigate_response_timeout_requires_snapshot() {
    navigate_unanswered("Page.navigate", "navigate_response_not_ready", true).await;
}

#[tokio::test]
async fn navigate_zero_budget_never_dispatches() {
    navigate_unanswered("Target.createTarget", "navigate_deadline_expired", false).await;
}

fn decode_missing_grant(token: &str) -> Value {
    let encoded = token
        .strip_prefix("g1.")
        .unwrap()
        .rsplit_once('.')
        .unwrap()
        .0;
    serde_json::from_slice(&cerebellum_core::serde_base64::decode(encoded).unwrap()).unwrap()
}

async fn flow_permission_query(planes: &Planes, corr: u64, params: Value) -> Value {
    let mut frame = request(corr, "unused", json!({}));
    frame.body = serde_json::to_vec(&json!({"method":"grants.would_ask","params":params})).unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_ne!(reply.header.ty, FrameType::Request);
    assert!(rx.try_recv().is_err());
    serde_json::from_slice(&reply.body).unwrap()
}

#[tokio::test]
async fn flow_browser_missing_permission_roundtrip_and_private_journal() {
    let (planes, launcher) = flow_planes();
    bind_flow_wire(&planes, Some(flow_stamp()), reserved("basal")).await;
    let reply = flow_wire_call(&planes, 2, json!({"action":"navigate","url":"https://page.example/page","intent":"read the page","severity":{"tier":3,"credential":false,"financial":false}})).await;
    assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
    let token = reply["detail"]["grant"].as_str().unwrap();
    let label = reply["detail"]["grant_label"].as_str().unwrap();
    assert_eq!(
        decode_missing_grant(token),
        json!({"tool":"browser_use","subject":{"domain":"page.example"},"level":3})
    );
    assert_eq!(
        label,
        "browser access to page.example up to filling in forms and other changes that can be undone"
    );
    bind_flow_wire_target(
        &planes,
        Some(flow_stamp()),
        reserved("basal"),
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    )
    .await;
    let params = json!({"agent_id":"pj-scope-agent","flow_id":"flow-7","items":[{"grant":token}]});
    let before = flow_permission_query(&planes, 3, params.clone()).await;
    assert_eq!(before["items"][0]["verdict"], "would_ask", "{before}");
    seed_scope_standing_grant(&planes).await;
    let apex_only = flow_permission_query(&planes, 30, params.clone()).await;
    assert_eq!(apex_only["items"][0]["verdict"], "would_ask", "{apex_only}");
    planes
        .management
        .standing_browser_grants()
        .record(
            "pj-scope-agent",
            cerebellum::browser_standing_grants::StandingSubject::Domain("page.example".into()),
            1,
            vec![],
            None,
            "lower-permission",
        )
        .unwrap();
    let lower = flow_permission_query(&planes, 31, params.clone()).await;
    assert_eq!(lower["items"][0]["verdict"], "would_ask", "{lower}");
    assert_eq!(lower["items"][0]["reason"], "level_above_grant", "{lower}");
    planes
        .management
        .standing_browser_grants()
        .record(
            "pj-scope-agent",
            cerebellum::browser_standing_grants::StandingSubject::Domain("page.example".into()),
            3,
            vec![],
            None,
            "permission-restored",
        )
        .unwrap();
    let after = flow_permission_query(&planes, 4, params.clone()).await;
    assert_eq!(after["items"][0]["verdict"], "yes", "{after}");
    let mut other = params.clone();
    other["agent_id"] = json!("another-agent");
    let denied = flow_permission_query(&planes, 5, other).await;
    assert!(denied.to_string().contains("agent_id"), "{denied}");
    assert!(denied.get("items").is_none(), "{denied}");
    let mut other = params.clone();
    other["flow_id"] = json!("another-flow");
    let denied = flow_permission_query(&planes, 6, other).await;
    assert!(denied.to_string().contains("flow_id"), "{denied}");
    assert!(denied.get("items").is_none(), "{denied}");
    for (corr, broken, reason) in [
        (7, token.replacen("g1.", "g99.", 1), "version"),
        (8, format!("{token}0"), "checksum"),
    ] {
        let mut invalid = params.clone();
        invalid["items"][0]["grant"] = json!(broken);
        let answer = flow_permission_query(&planes, corr, invalid).await;
        assert_eq!(answer["items"][0]["verdict"], "invalid_grant", "{answer}");
        assert_eq!(answer["items"][0]["reason"], "invalid_grant");
        assert_eq!(answer["items"][0]["field"], reason);
    }
    for (field, value) in [
        ("tool", json!("other_use")),
        ("level", json!(9)),
        ("subject", json!({"domain":"com"})),
        ("unexpected", json!(true)),
    ] {
        use sha2::{Digest, Sha256};
        let mut grant = decode_missing_grant(token);
        grant[field] = value;
        let bytes = serde_json::to_vec(&grant).unwrap();
        let broken = format!(
            "g1.{}.{:x}",
            cerebellum_core::serde_base64::encode(&bytes),
            Sha256::digest(&bytes)
        );
        let answer = flow_permission_query(
            &planes,
            9,
            json!({"agent_id":"pj-scope-agent","flow_id":"flow-7","items":[{"grant":broken}]}),
        )
        .await;
        assert_eq!(answer["items"][0]["verdict"], "invalid_grant", "{answer}");
        assert_eq!(answer["items"][0]["field"], field, "{answer}");
    }
    let journal = planes.browser.journal_export_for_test().await;
    assert!(!journal.is_empty());
    assert!(!journal.contains(token), "token leaked into journal");
    assert!(!journal.contains(label), "label leaked into journal");
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn only_profile_creation_marks_signed_in_coverage_complete() {
    use cerebellum_core::identity::{
        AcceptedBindFacts, ProfileDisposition, RouteSurface, SessionKind,
    };
    let scratch = cortexkit_test_support::ScratchDir::new("profile-sign-in-coverage");
    let signed_in = Arc::new(cerebellum::browser_signed_in::SignedInDomains::open(
        scratch.join("signed-in-domains.json"),
    ));
    let mut browser_config = config();
    browser_config.executable_path = Some(std::env::current_exe().unwrap());
    browser_config.expected_identity = Some("test.identity".into());
    let service = cerebellum::browser_launch_service::ProductionLaunchService::open(
        browser_config,
        cerebellum::JournalPersistence::Isolated,
    );
    let mut accepted = AcceptedBindFacts {
        identity: RouteIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            conversation_key: "coverage-legacy".into(),
            agent_project_id: "legacy-agent".into(),
            session_kind: SessionKind::Primary,
            profile_disposition: ProfileDisposition::Durable,
            project_root: "/tmp".into(),
            origin: Default::default(),
        },
        principal: Some(subc_protocol::Principal::Direct),
        agent_project_id_attested: true,
        acts_as_agent: true,
        session_kind_attested: true,
        control_operations: vec![],
        effective_capability_scope: None,
        flow_id: None,
        consumer_capabilities: vec![],
        surface: RouteSurface::Tools,
        call_mode: subc_protocol::call_mode::CallMode::Classic,
        scope: None,
    };
    let legacy = service
        .take_and_return_profile_custody(&accepted, "before-coverage-tracking")
        .unwrap();
    let service = service.with_signed_in_domains(Arc::clone(&signed_in));
    assert_eq!(
        service
            .take_and_return_profile_custody(&accepted, "existing-profile")
            .unwrap(),
        legacy
    );
    assert!(signed_in.is_signed_in("legacy-agent", "default", "https://never-signed.example"));
    accepted.identity.conversation_key = "coverage-fresh".into();
    accepted.identity.agent_project_id = "fresh-agent".into();
    let fresh = service
        .take_and_return_profile_custody(&accepted, "new-profile")
        .unwrap();
    assert_ne!(fresh, legacy);
    assert!(!signed_in.is_signed_in("fresh-agent", "default", "https://never-signed.example"));
    signed_in
        .record("fresh-agent", "default", "https://seen.example")
        .unwrap();
    assert_eq!(
        service
            .take_and_return_profile_custody(&accepted, "reopen-fresh-profile")
            .unwrap(),
        fresh
    );
    assert!(signed_in.is_signed_in("fresh-agent", "default", "https://seen.example"));
    assert!(!signed_in.is_signed_in("fresh-agent", "default", "https://never-signed.example"));
    let persisted = cerebellum::browser_signed_in::SignedInDomains::open(
        scratch.join("signed-in-domains.json"),
    );
    assert!(persisted.is_signed_in("legacy-agent", "default", "https://never-signed.example"));
    assert!(!persisted.is_signed_in("fresh-agent", "default", "https://never-signed.example"));
}

struct HeldStandingSave {
    inner: cerebellum::browser_standing_grants::InMemoryStandingGrantStorage,
    started: tokio::sync::Notify,
    release: (Mutex<bool>, std::sync::Condvar),
    saves: std::sync::atomic::AtomicUsize,
}
impl HeldStandingSave {
    fn new() -> Self {
        Self {
            inner: Default::default(),
            started: tokio::sync::Notify::new(),
            release: (Mutex::new(false), std::sync::Condvar::new()),
            saves: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    fn release(&self) {
        *self.release.0.lock().unwrap() = true;
        self.release.1.notify_all();
    }
}
impl cerebellum::browser_standing_grants::StandingGrantStorage for HeldStandingSave {
    fn load(
        &self,
    ) -> Result<
        cerebellum::browser_standing_grants::StandingGrantStoreState,
        cerebellum::browser_standing_grants::StandingGrantStoreError,
    > {
        self.inner.load()
    }
    fn save(
        &self,
        state: &cerebellum::browser_standing_grants::StandingGrantStoreState,
    ) -> Result<(), cerebellum::browser_standing_grants::StandingGrantStoreError> {
        self.saves.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.started.notify_one();
        let released = self.release.0.lock().unwrap();
        let (_released, wait) = self
            .release
            .1
            .wait_timeout_while(released, Duration::from_secs(5), |released| !*released)
            .unwrap();
        assert!(
            !wait.timed_out(),
            "test must release the standing-grant write"
        );
        self.inner.save(state)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn navigate_joins_open_grant_and_waits_for_the_drain_winners_stored_effect() {
    let storage = Arc::new(HeldStandingSave::new());
    let standing = Arc::new(
        cerebellum::browser_standing_grants::StandingBrowserGrants::open(
            storage.clone(),
            Some("test-machine".into()),
        ),
    );
    let (planes, launcher) = blocking_grant_fixture_with_store(Some(standing.clone())).await;
    bind_management_route(&planes).await;
    let service = ScriptedCarrier::for_planes(&planes);
    let (tx, mut rx) = mpsc::channel(8);
    let opening = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false), MANAGEMENT_CHANNEL, MANAGEMENT_EPOCH, 9800, serde_json::to_vec(&json!({"method":"browser.open_grant","params":{"origins":["https://requested.example"],"hazards":[],"severity_tier":3}})).unwrap()).unwrap();
    cerebellum::handle_frame_for_test(opening, &tx, &planes)
        .await
        .unwrap();
    let pending = consent_frame(&mut rx).await;
    assert_eq!(body(&pending)["outcome"], "consent_pending");
    let card = service.card(MANAGEMENT_CHANNEL, MANAGEMENT_EPOCH).await;
    assert_eq!(body(&pending)["ask_id"], body(&card)["id"]);
    service.defer_awaits();
    cerebellum::handle_frame_for_test(blocking_navigation(3), &tx, &planes)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        while !service
            .calls()
            .iter()
            .any(|(method, _)| method == "consent.await")
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == "consent.request")
            .count(),
        1,
        "navigate joins the same subject"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &card, "allow_origin_always").await;
    let drainer = {
        let planes = planes.clone();
        tokio::spawn(async move {
            drain_browser(&planes).await;
        })
    };
    tokio::time::timeout(Duration::from_secs(10), storage.started.notified())
        .await
        .unwrap();
    assert_eq!(
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == "consent.answers")
            .count(),
        2,
        "the competing drain reaches the answer feed before the held write"
    );
    let before_store = tokio::time::timeout(Duration::from_millis(75), rx.recv()).await;
    // Always release the blocked writer before asserting, so a failing guard
    // does not leave a runtime worker trapped inside the test store.
    storage.release();
    assert!(
        before_store.is_err(),
        "a losing holder replied before the winner stored the permission"
    );
    drainer.await.unwrap();
    service.resume_awaits();
    let reply = consent_frame(&mut rx).await;
    assert_eq!(body(&reply)["outcome"], "ok", "{}", body(&reply));
    assert_eq!(
        storage.saves.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "only the election winner stores the answer"
    );
    assert_eq!(standing.live_rows("pj-browser-session-wire").len(), 1);
    assert_eq!(launcher.effects.lock().unwrap().as_slice(), ["navigate"]);
    assert!(
        rx.try_recv().is_err(),
        "no reverse frame or duplicate reply"
    );
}
