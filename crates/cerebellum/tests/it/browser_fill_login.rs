//! `browser.fill_login` end to end: a real `route.bind` with a stamped scope,
//! the production plane and CDP driver, a scripted page behind the CDP pipe,
//! a scripted consent service, and a vault double that answers `secret.use`
//! in the vault's own shapes.
//!
//! The page double speaks CDP the way Chrome does for the commands the fill
//! sends, and records every command. The snapshot is canned (the snapshot
//! path is not what these tests exercise), built from the same DOM the driver
//! reads, so the fill's live re-check sees what the snapshot saw.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::support::computer::cingulate::{stamp, ScriptedCarrier};
use crate::support::permissions as permission_support;
use crate::support::HANG_GUARD;
use cerebellum::authorization::{ActionGrant, GrantStore, Severity};
use cerebellum::browser::fill::{
    LoginMaterialSource, SecretUseRequest, SourceFuture, REDACTED_PASSWORD,
};
use cerebellum::browser::navigation::{
    classify_flattened_document, BrowserScreenshotObservation, BrowserSnapshotObservation,
    CdpNavigationDriver,
};
use cerebellum::browser_launch::ExecutableIdentityCheckpoints;
use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
use cerebellum::browser_session::{
    BrowserSessionLauncher, CleanupStage, LaunchedBrowser, NavigationDriveError,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup,
};
use cerebellum::cdp::{CdpFrameDecoder, CdpTransport};
use cerebellum::cingulate_client::ScriptedAnswer;
use cerebellum::coordinate::{TransformInputs, ViewportObservation};
use cerebellum::snapshot_store::{
    AxRecord, BackendNodeIdentity, CommittedDocument, RefRecord, SnapshotKind, SnapshotRef,
};
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Map, Value};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

/// The planted secret every leak check scans for.
const PASSWORD: &str = "hunter2-PLANTED-fill-pw";
const USERNAME: &str = "agent-user@login.example";
const TOTP: &str = "424242";
const SECRET: &str = "work-login";
const SITE: &str = "https://login.example";
const FRAME_SITE: &str = "https://auth.other.example";

const CHANNEL: u16 = 9;
const EPOCH: u32 = 3;
const AGENT: &str = "test-project";
const CONVERSATION: &str = "test-session";
const TARGET: &str = "target-own";
const SESSION: &str = "session-own";
const MAIN: &str = "main";
const LOGIN_FRAME: &str = "frame-login";

const FORM: u64 = 10;
const USERNAME_NODE: u64 = 11;
const PASSWORD_NODE: u64 = 12;
const OTP_NODE: u64 = 13;

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
        navigation_settle_deadline_ms: 1_000,
    }
}

// ---------------------------------------------------------------------------
// The page behind the CDP pipe
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Place {
    Main,
    Frame,
}

/// The embedded frame, when the page has one.
#[derive(Clone)]
struct FrameSpec {
    url: String,
    /// `None` leaves `securityOrigin` out of the frame tree, as Chrome does
    /// for a srcdoc frame.
    security_origin: Option<String>,
}

struct Page {
    main_url: String,
    /// Bumped by every cross-document navigation.
    document: u64,
    frame: Option<FrameSpec>,
    /// Where the username and password form is.
    form_in: Place,
    /// Where the one-time-code input is.
    otp_in: Place,
    password_type: String,
    values: HashMap<u64, String>,
    focused: Option<u64>,
    /// Text a page script copied into the document.
    copied_text: Option<String>,
    /// Every CDP method sent, in order.
    commands: Vec<String>,
    /// The node each `Input.insertText` landed in.
    inserted: Vec<u64>,
    /// Commit another document right after the first insertion, keeping the
    /// form's nodes so a clear of them can be observed.
    navigate_after_first_insert: bool,
    /// The form is gone from the document.
    form_removed: bool,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            main_url: format!("{SITE}/signin"),
            document: 1,
            frame: None,
            form_in: Place::Main,
            otp_in: Place::Main,
            password_type: "password".into(),
            values: HashMap::new(),
            focused: None,
            copied_text: None,
            commands: Vec::new(),
            inserted: Vec::new(),
            navigate_after_first_insert: false,
            form_removed: false,
        }
    }
}

#[derive(Clone)]
struct Shared(Arc<Mutex<Page>>);

impl Shared {
    fn new(page: Page) -> Self {
        Self(Arc::new(Mutex::new(page)))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Page> {
        self.0.lock().unwrap()
    }

    /// The page leaves for another document, taking the form with it.
    fn navigate_away(&self) {
        let mut page = self.lock();
        page.document += 1;
        page.main_url = format!("{SITE}/home");
        page.form_removed = true;
    }

    fn value(&self, node: u64) -> String {
        self.lock().values.get(&node).cloned().unwrap_or_default()
    }

    fn insertions(&self) -> usize {
        self.lock()
            .commands
            .iter()
            .filter(|method| *method == "Input.insertText")
            .count()
    }
}

impl Page {
    fn dom(&self) -> Map<String, Value> {
        let mut nodes = vec![json!({"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"","nodeName":"#document"})];
        if !self.form_removed {
            nodes.push(json!({"nodeId":FORM,"backendNodeId":FORM,"parentId":1,"nodeType":1,"localName":"form","nodeName":"FORM","attributes":[]}));
            nodes.push(json!({"nodeId":USERNAME_NODE,"backendNodeId":USERNAME_NODE,"parentId":FORM,"nodeType":1,"localName":"input","nodeName":"INPUT","attributes":["type","email","autocomplete","username"]}));
            nodes.push(json!({"nodeId":PASSWORD_NODE,"backendNodeId":PASSWORD_NODE,"parentId":FORM,"nodeType":1,"localName":"input","nodeName":"INPUT","attributes":["type",self.password_type]}));
            nodes.push(json!({"nodeId":OTP_NODE,"backendNodeId":OTP_NODE,"parentId":1,"nodeType":1,"localName":"input","nodeName":"INPUT","attributes":["type","text","autocomplete","one-time-code"]}));
        }
        json!({ "nodes": nodes }).as_object().unwrap().clone()
    }

    fn frame_tree(&self) -> Value {
        let origin = cerebellum::classification::canonical_origin_from_url(&self.main_url)
            .unwrap_or_else(|| "null".into());
        let mut root = json!({"frame":{
            "id": MAIN,
            "loaderId": format!("loader-{}", self.document),
            "url": self.main_url,
            "securityOrigin": origin,
            "mimeType": "text/html",
        }});
        if let Some(frame) = &self.frame {
            let mut child = json!({
                "id": LOGIN_FRAME,
                "parentId": MAIN,
                "loaderId": "frame-loader-1",
                "url": frame.url,
                "mimeType": "text/html",
            });
            if let Some(origin) = &frame.security_origin {
                child["securityOrigin"] = json!(origin);
            }
            root["childFrames"] = json!([{"frame": child}]);
        }
        json!({ "frameTree": root })
    }

    fn history(&self) -> Value {
        json!({"currentIndex":0,"entries":[{"id":self.document as i64,"url":self.main_url,"userTypedURL":self.main_url,"title":"","transitionType":"link"}]})
    }

    fn object_node(params: &Value) -> Option<u64> {
        params["objectId"]
            .as_str()?
            .strip_prefix("node-")?
            .parse()
            .ok()
    }

    /// Answer one CDP command: `Ok` result or `Err` error message.
    fn answer(&mut self, method: &str, params: &Value) -> Result<Value, &'static str> {
        self.commands.push(method.to_string());
        let field = |node: u64| matches!(node, USERNAME_NODE | PASSWORD_NODE | OTP_NODE);
        Ok(match method {
            "Target.createTarget" => json!({"targetId": TARGET}),
            "Target.attachToTarget" => json!({"sessionId": SESSION}),
            "Page.getNavigationHistory" => self.history(),
            "Page.getFrameTree" => self.frame_tree(),
            "DOM.getFlattenedDocument" => Value::Object(self.dom()),
            "DOM.focus" => {
                self.focused = params["backendNodeId"].as_u64();
                json!({})
            }
            "DOM.resolveNode" => {
                let node = params["backendNodeId"].as_u64().unwrap_or_default();
                if self.form_removed && field(node) {
                    return Err("No node with given id found");
                }
                json!({"object": {"objectId": format!("node-{node}")}})
            }
            "Runtime.callFunctionOn" => {
                let node = Self::object_node(params).ok_or("Cannot find context")?;
                let function = params["functionDeclaration"].as_str().unwrap_or_default();
                let value = if function.contains("this.select()") {
                    self.focused = Some(node);
                    json!(true)
                } else if function.contains("this.value.length : -1") {
                    json!(self.values.get(&node).map_or(0, |value| value.encode_utf16().count()))
                } else if function.contains("this.value = ''") {
                    self.values.insert(node, String::new());
                    json!(true)
                } else if function.contains("isConnected") {
                    json!(!self.form_removed && self.values.get(&node).is_some_and(|value| !value.is_empty()))
                } else {
                    json!(true)
                };
                json!({"result": {"type": "boolean", "value": value}})
            }
            "Input.insertText" => {
                let node = self.focused.ok_or("no focused element")?;
                let text = params["text"].as_str().unwrap_or_default().to_string();
                self.values.insert(node, text);
                self.inserted.push(node);
                if self.navigate_after_first_insert && self.inserted.len() == 1 {
                    self.document += 1;
                }
                json!({})
            }
            _ => json!({}),
        })
    }
}

struct Pipe {
    page: Shared,
    reads: VecDeque<Vec<u8>>,
}

impl CdpPipeIo for Pipe {
    fn write_frame(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        let method = command["method"].as_str().unwrap().to_string();
        let answered = self.page.lock().answer(&method, &command["params"]);
        let mut reply = json!({"id": command["id"]});
        if let Some(session) = command.get("sessionId") {
            reply["sessionId"] = session.clone();
        }
        match answered {
            Ok(result) => reply["result"] = result,
            Err(message) => reply["error"] = json!({"code": -32000, "message": message}),
        }
        let mut bytes = serde_json::to_vec(&reply).unwrap();
        bytes.push(0);
        self.reads.push_back(bytes);
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

// ---------------------------------------------------------------------------
// The browser process: the production CDP driver over the page double
// ---------------------------------------------------------------------------

struct Process {
    driver: CdpNavigationDriver<Pipe>,
    page: Shared,
}

impl Process {
    fn field(&self, place: Place) -> (&'static str, bool) {
        match place {
            Place::Main => (MAIN, false),
            Place::Frame => (LOGIN_FRAME, true),
        }
    }
}

impl OwnedBrowserProcess for Process {
    fn committed_document(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        self.driver.committed_document(context_key, deadline_ms)
    }

    fn main_frame_url(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
        self.driver.main_frame_url(context_key, deadline_ms)
    }

    fn frame_documents(
        &mut self,
        context: &str,
        deadline_ms: u64,
    ) -> Result<Vec<cerebellum::snapshot_store::FrameDocument>, NavigationDriveError> {
        self.driver.frame_documents(context, deadline_ms)
    }

    fn set_read_frames(
        &mut self,
        frames: Vec<cerebellum::snapshot_store::FrameDocument>,
    ) -> Result<(), NavigationDriveError> {
        self.driver.set_read_frames(frames);
        Ok(())
    }

    fn prepare_frame(
        &mut self,
        context: &str,
        expected: &cerebellum::snapshot_store::FrameDocument,
        deadline_ms: u64,
    ) -> Result<bool, NavigationDriveError> {
        self.driver.prepare_frame(context, expected, deadline_ms)
    }

    /// Canned from the page's own DOM: one ref per login field, with the
    /// classification the driver will compute again before filling, and the
    /// value each field holds now.
    fn snapshot_classified(
        &mut self,
        context_key: &str,
        _: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let frames = self.driver.frame_documents(context_key, deadline_ms)?;
        let page = self.page.lock();
        let dom = page.dom();
        let mut observation = BrowserSnapshotObservation {
            records: vec![],
            dom_text: Some(String::new()),
            refs: vec![],
            ax_truncated: false,
            refs_truncated: false,
            facts: Default::default(),
        };
        if !page.form_removed {
            for (node, name, place) in [
                (USERNAME_NODE, "Email", page.form_in),
                (PASSWORD_NODE, "Password", page.form_in),
                (OTP_NODE, "One-time code", page.otp_in),
            ] {
                let (frame_id, in_frame) = self.field(place);
                let identity = BackendNodeIdentity::new(TARGET, frame_id, node).unwrap();
                let classification =
                    classify_flattened_document(&dom, &identity, document_epoch, current_origin)
                        .expect("the login field classifies");
                let reference = format!("e{node}");
                let value = page.values.get(&node).cloned().filter(|value| !value.is_empty());
                observation.records.push(AxRecord {
                    depth: 0,
                    role: "textbox".into(),
                    name: name.into(),
                    value: value.clone(),
                    reference: Some(reference.clone()),
                });
                // What the DOM says about the field now: a password input is
                // a credential field, the same input toggled to text is not.
                observation.facts.entry(reference.clone()).or_default().credential =
                    Some(node == PASSWORD_NODE && page.password_type == "password");
                observation.dom_text.as_mut().unwrap().push_str(&format!(
                    "<label>{name}<input value=\"{}\"></label>",
                    value.unwrap_or_default()
                ));
                observation.refs.push(RefRecord {
                    frame_document: in_frame
                        .then(|| frames.iter().find(|f| f.frame_id == LOGIN_FRAME).cloned())
                        .flatten(),
                    captured: SnapshotRef::new(&reference, "textbox", name, 0).unwrap(),
                    frame_path: vec![frame_id.into()],
                    backend_identity: Some(identity),
                    raw_role: Some("textbox".into()),
                    raw_name: Some(name.into()),
                    classification: Ok(Box::new(classification)),
                });
            }
        }
        if let Some(copied) = &page.copied_text {
            observation.records.push(AxRecord {
                depth: 0,
                role: "StaticText".into(),
                name: copied.clone(),
                value: None,
                reference: None,
            });
            observation
                .dom_text
                .as_mut()
                .unwrap()
                .push_str(&format!("<p>{copied}</p>"));
        }
        Ok(observation)
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

    fn fill_login(
        &mut self,
        context_key: &str,
        dispatch: &cerebellum::browser::fill::FillDispatch,
        deadline_ms: u64,
    ) -> Result<cerebellum::browser::fill::FillOutcome, NavigationDriveError> {
        self.driver.fill_login(context_key, dispatch, deadline_ms)
    }

    fn clear_filled(
        &mut self,
        context_key: &str,
        fields: &[cerebellum::browser::fill::FilledField],
        deadline_ms: u64,
    ) -> Result<(), NavigationDriveError> {
        self.driver.clear_filled(context_key, fields, deadline_ms)
    }

    fn filled_fields_state(
        &mut self,
        context_key: &str,
        fields: &[cerebellum::browser::fill::FilledField],
        deadline_ms: u64,
    ) -> Result<cerebellum::browser::fill::FilledFieldsState, NavigationDriveError> {
        self.driver
            .filled_fields_state(context_key, fields, deadline_ms)
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

struct Launcher(Shared);

impl BrowserSessionLauncher for Launcher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<LaunchedBrowser, Value> {
        Ok(LaunchedBrowser {
            process: Box::new(Process {
                driver: CdpNavigationDriver::new(
                    Pipe {
                        page: self.0.clone(),
                        reads: VecDeque::new(),
                    },
                    CdpTransport::new(),
                    CdpFrameDecoder::default(),
                ),
                page: self.0.clone(),
            }),
            cleanup: Box::new(Cleanup),
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::AfterExecOnly,
        })
    }
}

// ---------------------------------------------------------------------------
// The vault double
// ---------------------------------------------------------------------------

/// Answers `secret.use` as the vault does: a closed request
/// `{name, coverage?, stamp, target: {origin}}`; `released`,
/// `approval_required`, or one `{error}` for unknown, ungranted and
/// wrong-origin requests alike.
struct VaultState {
    saved_origin: String,
    totp: bool,
    needs_approval: bool,
    approved: bool,
    /// Treat the person as approving every card: once the vault has asked,
    /// it releases on the next request, as it does after reading the
    /// person's signed answer.
    approves_when_asked: bool,
    /// Every request's params, as received.
    requests: Vec<Value>,
    /// Run during each request, to move the page while the vault is asked.
    during_request: Option<Box<dyn FnMut() + Send>>,
}

impl Default for VaultState {
    fn default() -> Self {
        Self {
            saved_origin: SITE.into(),
            totp: false,
            needs_approval: false,
            approved: false,
            approves_when_asked: false,
            requests: Vec::new(),
            during_request: None,
        }
    }
}

#[derive(Clone)]
struct Vault(Arc<Mutex<VaultState>>);

impl Vault {
    fn requests(&self) -> Vec<Value> {
        self.0.lock().unwrap().requests.clone()
    }
}

impl LoginMaterialSource for Vault {
    fn secret_use(&self, request: &SecretUseRequest) -> SourceFuture<'_> {
        let params = request.params();
        let mut state = self.0.lock().unwrap();
        state.requests.push(params.clone());
        if let Some(during) = state.during_request.as_mut() {
            during();
        }
        let closed = params.as_object().is_some_and(|object| {
            object.keys().all(|key| matches!(key.as_str(), "name" | "coverage" | "stamp" | "target"))
        }) && params["target"].as_object().is_some_and(|target| target.len() == 1);
        let reply = if !closed
            || params["name"] != SECRET
            || params["target"]["origin"] != json!(state.saved_origin)
        {
            json!({"error": {"code": "secret_unavailable", "class": "refused"}})
        } else if state.needs_approval && !state.approved {
            state.approved = state.approves_when_asked;
            json!({
                "status": "approval_required",
                "request_id": "req_vault_1",
                "statement_b64url": "eyJsb2dpbiI6IndvcmstbG9naW4ifQ",
                "expires_at_ms": 4_102_444_800_000u64,
            })
        } else {
            let mut released = json!({
                "status": "released",
                "kind": "site_login",
                "username": USERNAME,
                "password": PASSWORD,
            });
            if state.totp {
                released["totp"] = json!(TOTP);
            }
            released
        };
        Box::pin(async move { Ok(reply) })
    }
}

// ---------------------------------------------------------------------------
// The fixture
// ---------------------------------------------------------------------------

struct Fixture {
    planes: Planes,
    page: Shared,
    vault: Vault,
    next_corr: Mutex<u64>,
}

fn fixture(page: Page, vault: VaultState) -> impl std::future::Future<Output = Fixture> {
    fixture_with_window(page, vault, Duration::from_secs(600))
}

async fn fixture_with_window(page: Page, vault: VaultState, window: Duration) -> Fixture {
    let page = Shared::new(page);
    let vault = Vault(Arc::new(Mutex::new(vault)));
    let mut planes = permission_support::planes(
        Arc::new(HealthState::new()),
        Some(config()),
        JournalPersistence::Isolated,
    );
    planes.launch_service = Some(Arc::new(Launcher(page.clone())));
    let grants = GrantStore::new([ActionGrant::new(
        "read",
        1,
        CONVERSATION,
        Severity::new(4, false, false),
        [SITE, "http://login.example", FRAME_SITE],
    )]);
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .expect("the fixture owns its browser plane")
            .with_grants_installed(grants)
            .with_login_material_source(Some(Arc::new(vault.clone())))
            .with_fill_window_for_test(window),
    );
    let launched = test_bind_call(&planes, "browser.launch", json!({})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
    bind(&planes).await;
    let planes = ScriptedCarrier::default().install(planes);
    Fixture {
        planes,
        page,
        vault,
        next_corr: Mutex::new(100),
    }
}

/// A call on the helper's own route binding, before the stamped bind.
async fn test_bind_call(planes: &Planes, name: &str, arguments: Value) -> Value {
    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_tool_request_for_test_with_planes(
        tool_frame(1, json!({"name": name, "arguments": arguments})),
        &tx,
        planes,
    )
    .await
    .unwrap();
    reply_body(&rx.recv().await.unwrap())
}

/// Bind the tool route with the stamped scope of a head session that can
/// ask a person.
async fn bind(planes: &Planes) {
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: CHANNEL,
        epoch: EPOCH,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", CONVERSATION),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(json!({
            "agentProjectId": AGENT,
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.status"],
        })),
        scope: Some(stamp(AGENT)),
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
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
}

fn tool_frame(corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        CHANNEL,
        EPOCH,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn reply_body(frame: &Frame) -> Value {
    let reply: Value = serde_json::from_slice(&frame.body).unwrap();
    reply.get("structuredContent").cloned().unwrap_or(reply)
}

impl Fixture {
    fn corr(&self) -> u64 {
        let mut next = self.next_corr.lock().unwrap();
        *next += 1;
        *next
    }

    /// Send one request on the stamped route and return its reply frame.
    async fn send(&self, body: Value, consent_wait: Option<Duration>) -> Frame {
        let (tx, mut rx) = mpsc::channel(8);
        let frame = tool_frame(self.corr(), body);
        match consent_wait {
            None => cerebellum::handle_frame_for_test(frame, &tx, &self.planes)
                .await
                .map(|_| ())
                .unwrap(),
            Some(wait) => {
                cerebellum::handle_browser_consent_deadline_for_test(frame, &tx, &self.planes, wait)
                    .await
                    .unwrap()
            }
        }
        tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .expect("the request replies")
            .unwrap()
    }

    async fn call(&self, name: &str, arguments: Value) -> Value {
        reply_body(
            &self
                .send(json!({"name": name, "arguments": arguments}), None)
                .await,
        )
    }

    async fn snapshot(&self, mode: &str) -> Value {
        let snapshot = self.call("browser.snapshot", json!({"mode": mode})).await;
        assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
        snapshot
    }

    async fn screenshot(&self) -> Value {
        self.call("browser.screenshot", json!({})).await
    }

    /// The fill arguments naming the snapshot's login fields.
    async fn fill_arguments(&self, otp: bool) -> Value {
        let snapshot = self.snapshot("ax").await;
        let mut arguments = json!({
            "secret": SECRET,
            "username_ref": named_ref(&snapshot, "Email"),
            "password_ref": named_ref(&snapshot, "Password"),
        });
        if otp {
            arguments["otp_ref"] = json!(named_ref(&snapshot, "One-time code"));
        }
        arguments
    }

    async fn fill(&self, otp: bool) -> Value {
        let arguments = self.fill_arguments(otp).await;
        self.call("browser.fill_login", arguments).await
    }

    fn carrier(&self) -> ScriptedCarrier {
        ScriptedCarrier::for_planes(&self.planes)
    }
}

/// The ref of the ax line whose name is `name`: such a line reads
/// `<ref> <role> <name>[, Value: <value>]`.
fn named_ref(snapshot: &Value, name: &str) -> String {
    snapshot["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .find_map(|line| {
            let (reference, rest) = line.trim_start().split_once(' ')?;
            let (_, line_name) = rest.split_once(' ')?;
            let line_name = line_name
                .split_once(", Value: ")
                .map_or(line_name, |(line_name, _)| line_name);
            (line_name == name).then(|| reference.to_string())
        })
        .unwrap_or_else(|| panic!("no line named {name}: {snapshot}"))
}

fn contains_password(value: &Value) -> bool {
    value.to_string().contains(PASSWORD)
}

fn reason_code(reply: &Value) -> &str {
    reply["detail"]["reason_code"].as_str().unwrap_or_default()
}

fn line_for<'a>(snapshot: &'a Value, name: &str) -> &'a str {
    snapshot["state_text"]
        .as_str()
        .unwrap()
        .lines()
        .find(|line| line.contains(&format!("textbox {name}")))
        .unwrap_or_else(|| panic!("no {name} line: {snapshot}"))
}

// ---------------------------------------------------------------------------
// Filling
// ---------------------------------------------------------------------------

/// The vault is asked once, in its own closed shape, for the origin read from
/// the page and the scope stamped on the route; the reply names the fields
/// and the origin and nothing that went into them.
#[tokio::test]
async fn a_fill_inserts_the_login_and_replies_with_fields_and_origin_only() {
    let fixture = fixture(
        Page::default(),
        VaultState {
            totp: true,
            ..Default::default()
        },
    )
    .await;
    let reply = fixture.fill(true).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["origin"], SITE);
    assert_eq!(reply["filled"], json!(["username", "password", "otp"]));
    for secret in [PASSWORD, USERNAME, TOTP] {
        assert!(!reply.to_string().contains(secret), "{reply}");
    }
    assert_eq!(fixture.page.value(USERNAME_NODE), USERNAME);
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    assert_eq!(fixture.page.value(OTP_NODE), TOTP);
    assert_eq!(
        fixture.vault.requests(),
        vec![json!({
            "name": SECRET,
            "coverage": "scope",
            "stamp": serde_json::to_value(stamp(AGENT)).unwrap(),
            "target": {"origin": SITE},
        })]
    );
    assert!(fixture.planes.browser.result_schema_findings().is_empty());
}

/// Every origin refusal is decided from the fields' own frames before the
/// vault is asked, so a refused fill never brings a secret into memory.
#[tokio::test]
async fn origin_refusals_are_decided_before_the_vault_is_asked() {
    let frame = |url: &str, security_origin: Option<&str>| {
        Some(FrameSpec {
            url: url.into(),
            security_origin: security_origin.map(str::to_owned),
        })
    };
    let cases: Vec<(&str, Page, bool, &str)> = vec![
        (
            "http page",
            Page {
                main_url: "http://login.example/signin".into(),
                ..Default::default()
            },
            false,
            "origin_not_https",
        ),
        (
            "login form in a cross-site iframe, code field on the page",
            Page {
                frame: frame(&format!("{FRAME_SITE}/login"), Some(FRAME_SITE)),
                form_in: Place::Frame,
                otp_in: Place::Main,
                ..Default::default()
            },
            true,
            "origins_differ",
        ),
        (
            "sandboxed frame",
            Page {
                frame: frame(&format!("{FRAME_SITE}/login"), Some("null")),
                form_in: Place::Frame,
                ..Default::default()
            },
            false,
            "origin_opaque",
        ),
        (
            "srcdoc frame",
            Page {
                frame: frame("about:srcdoc", None),
                form_in: Place::Frame,
                ..Default::default()
            },
            false,
            "origin_opaque",
        ),
        (
            "data: frame",
            Page {
                frame: frame("data:text/html,<form></form>", Some("null")),
                form_in: Place::Frame,
                ..Default::default()
            },
            false,
            "origin_opaque",
        ),
    ];
    for (name, page, otp, expected) in cases {
        let fixture = fixture(page, VaultState::default()).await;
        let reply = fixture.fill(otp).await;
        assert_eq!(reply["outcome"], "authorization_denied", "{name}: {reply}");
        assert_eq!(reason_code(&reply), expected, "{name}: {reply}");
        assert!(fixture.vault.requests().is_empty(), "{name}: the vault was asked");
        assert_eq!(fixture.page.insertions(), 0, "{name}");
        assert!(fixture.planes.browser.result_schema_findings().is_empty(), "{name}");
    }
}

/// The origin the vault checks is never the caller's to name.
#[tokio::test]
async fn an_origin_in_the_arguments_is_refused_before_the_vault_is_asked() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let mut arguments = fixture.fill_arguments(false).await;
    arguments["origin"] = json!(SITE);
    let reply = fixture.call("browser.fill_login", arguments).await;
    assert_eq!(reply["outcome"], "invalid_request", "{reply}");
    assert_eq!(reply["detail"]["field"], "origin");
    assert_eq!(reason_code(&reply), "unknown_field");
    assert!(fixture.vault.requests().is_empty());
}

/// A login saved for another site is refused exactly like an unknown name:
/// the vault is asked for the origin of the fields' frame (an iframe's, not
/// the tab's) and its refusal says nothing about why.
#[tokio::test]
async fn a_login_saved_for_another_origin_is_refused_like_an_unknown_one() {
    let fixture = fixture(
        Page {
            frame: Some(FrameSpec {
                url: format!("{FRAME_SITE}/login"),
                security_origin: Some(FRAME_SITE.into()),
            }),
            form_in: Place::Frame,
            ..Default::default()
        },
        VaultState::default(),
    )
    .await;
    let wrong_origin = fixture.fill(false).await;
    assert_eq!(wrong_origin["outcome"], "authorization_denied", "{wrong_origin}");
    assert_eq!(reason_code(&wrong_origin), "login_unavailable");
    let requests = fixture.vault.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["target"]["origin"], FRAME_SITE);

    let mut arguments = fixture.fill_arguments(false).await;
    arguments["secret"] = json!("no-such-login");
    let unknown = fixture.call("browser.fill_login", arguments).await;
    for key in ["outcome", "detail", "remedy"] {
        assert_eq!(wrong_origin[key], unknown[key], "{key}");
    }
    assert_eq!(fixture.page.insertions(), 0);
    assert!(!fixture.planes.browser.fill_window_open_for_test(&identity()).await);
}

fn identity() -> cerebellum_core::identity::RouteIdentity {
    cerebellum_core::identity::RouteIdentity::from_bind(
        &BindIdentity::new("/test/project", "test", CONVERSATION.to_string()),
        &Some(subc_protocol::Principal::Direct),
    )
}

// ---------------------------------------------------------------------------
// The re-check right before the insertion
// ---------------------------------------------------------------------------

/// The page navigates while the vault is asked: the live check finds another
/// document and nothing is inserted.
#[tokio::test]
async fn a_navigation_between_the_check_and_the_insertion_inserts_nothing() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let moved = fixture.page.clone();
    fixture.vault.0.lock().unwrap().during_request = Some(Box::new(move || moved.navigate_away()));
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "stale_snapshot", "{reply}");
    assert_eq!(reason_code(&reply), "document_changed");
    assert_eq!(fixture.page.insertions(), 0);
    assert_eq!(fixture.page.value(USERNAME_NODE), "");
    assert_eq!(fixture.page.value(PASSWORD_NODE), "");
    assert!(!fixture.planes.browser.fill_window_open_for_test(&identity()).await);
    assert!(!contains_password(&reply));
}

/// The document changes after the first field is filled: the second field
/// is never filled and the first is emptied again.
#[tokio::test]
async fn a_change_after_the_first_field_clears_it_and_fills_no_more() {
    let fixture = fixture(
        Page {
            navigate_after_first_insert: true,
            ..Default::default()
        },
        VaultState::default(),
    )
    .await;
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "stale_snapshot", "{reply}");
    assert_eq!(reason_code(&reply), "document_changed");
    assert_eq!(fixture.page.lock().inserted, vec![USERNAME_NODE]);
    assert_eq!(fixture.page.value(USERNAME_NODE), "", "the username was not cleared");
    assert_eq!(fixture.page.value(PASSWORD_NODE), "");
    assert!(!fixture.planes.browser.fill_window_open_for_test(&identity()).await);
}

// ---------------------------------------------------------------------------
// What leaves the module
// ---------------------------------------------------------------------------

/// The planted password is in no reply, journal entry or call record; the
/// scan is shown to find a planted copy, and each scanned store is shown to
/// hold this test's records.
#[tokio::test]
async fn the_password_never_reaches_the_reply_journal_or_call_record() {
    let mut fixture = fixture(Page::default(), VaultState::default()).await;
    let storage = cerebellum::journal::call_records::InMemoryCallRecordStorage::new();
    fixture.planes.calls = Arc::new(cerebellum::journal::call_records::CallRecords::open(
        Box::new(storage.clone()),
        0,
    ));
    assert!(contains_password(&json!({"planted": format!("<{PASSWORD}>")})));

    let arguments = fixture.fill_arguments(false).await;
    let reply = reply_body(
        &fixture
            .send(
                json!({"name": "browser.fill_login", "arguments": arguments, "call_key": "pf:fill-1"}),
                None,
            )
            .await,
    );
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD, "the fill ran");
    assert!(!contains_password(&reply), "{reply}");

    let journal = fixture.planes.browser.journal_export_for_test().await;
    assert!(journal.contains("browser.snapshot"), "the journal holds this test's reads");
    assert!(!journal.contains(PASSWORD));

    assert_eq!(fixture.planes.calls.record_count(), 1, "the keyed fill was recorded");
    let records = String::from_utf8_lossy(&storage.contents().unwrap_or_default()).into_owned();
    assert!(records.contains("pf:fill-1"), "{records}");
    assert!(!records.contains(PASSWORD));
    let refusals = fixture.planes.browser.refusal_ring_export_for_test().await;
    assert!(!refusals.contains(PASSWORD));
}

// ---------------------------------------------------------------------------
// The window after a fill
// ---------------------------------------------------------------------------

#[tokio::test]
async fn screenshots_are_refused_while_the_password_is_on_the_page() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.screenshot().await["outcome"], "ok");
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    let refused = fixture.screenshot().await;
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(reason_code(&refused), "filled_password_on_page");
    assert_eq!(refused["detail"]["reason"], "a filled password is on this page");
    assert!(fixture.planes.browser.result_schema_findings().is_empty());

    fixture.page.navigate_away();
    let allowed = fixture.screenshot().await;
    assert_eq!(allowed["outcome"], "ok", "{allowed}");
    assert!(!fixture.planes.browser.fill_window_open_for_test(&identity()).await);
}

/// The window also ends once the page has emptied every filled field.
#[tokio::test]
async fn emptied_fields_end_the_window() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    assert_eq!(fixture.screenshot().await["outcome"], "authorization_denied");
    fixture.page.lock().values.clear();
    let allowed = fixture.screenshot().await;
    assert_eq!(allowed["outcome"], "ok", "{allowed}");
}

/// Reads keep working in every mode. Text a page script copied into the
/// document loses the password; the filled fields show no value, the
/// password field included after the page turns it into a text input.
#[tokio::test]
async fn text_reads_drop_the_password_and_mask_the_filled_fields() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    let copied = format!("Signed in with {PASSWORD}");
    assert!(copied.contains(PASSWORD), "the page text carries a planted copy");
    fixture.page.lock().copied_text = Some(copied);
    for mode in ["actionable", "ax", "dom_full"] {
        let snapshot = fixture.snapshot(mode).await;
        assert!(!contains_password(&snapshot), "{mode}: {snapshot}");
        assert!(
            snapshot["state_text"].as_str().unwrap().contains(REDACTED_PASSWORD),
            "{mode}: the copied text was dropped instead of redacted: {snapshot}"
        );
    }
    // The username is not a secret the redaction knows, so only masking by
    // node identity keeps its value off the page text.
    let ax = fixture.snapshot("ax").await;
    assert!(!line_for(&ax, "Email").contains("Value:"), "{ax}");

    fixture.page.lock().password_type = "text".into();
    let toggled = fixture.snapshot("ax").await;
    let password_line = line_for(&toggled, "Password");
    assert!(!password_line.contains("Value:"), "{toggled}");
    assert!(!contains_password(&toggled));
    assert!(fixture.planes.browser.result_schema_findings().is_empty());
}

#[tokio::test]
async fn reads_are_refused_after_the_window_runs_out_until_the_page_navigates() {
    let fixture = fixture_with_window(
        Page::default(),
        VaultState::default(),
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let refused = fixture.call("browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(reason_code(&refused), "filled_login_expired");
    assert_eq!(reason_code(&fixture.screenshot().await), "filled_login_expired");

    fixture.page.navigate_away();
    let read = fixture.call("browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(read["outcome"], "ok", "{read}");
    assert_eq!(fixture.screenshot().await["outcome"], "ok");
}

// ---------------------------------------------------------------------------
// The person's approval
// ---------------------------------------------------------------------------

/// `approval_required` files one card carrying the vault's request id and
/// statement unchanged; approved while the call waits, the vault is asked
/// again and the login filled in the same call.
#[tokio::test]
async fn an_approval_files_a_card_and_fills_once_approved_in_the_call() {
    let fixture = fixture(
        Page::default(),
        VaultState {
            needs_approval: true,
            approves_when_asked: true,
            ..Default::default()
        },
    )
    .await;
    fixture
        .carrier()
        .queue(ScriptedAnswer::Answered(json!({"decision": "allow"})));
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    let questions = fixture.carrier().questions();
    assert_eq!(questions.len(), 1, "{questions:?}");
    let card = &questions[0]["params"];
    assert_eq!(
        card["scope"],
        json!({"vault_request_id": "req_vault_1", "statement_b64url": "eyJsb2dpbiI6IndvcmstbG9naW4ifQ"}),
        "{card}"
    );
    assert_eq!(card["late_execution"], "execute");
    assert!(!card.to_string().contains(PASSWORD));
    assert_eq!(fixture.vault.requests().len(), 2);
}

#[tokio::test]
async fn a_declined_approval_fills_nothing() {
    let fixture = fixture(
        Page::default(),
        VaultState {
            needs_approval: true,
            ..Default::default()
        },
    )
    .await;
    fixture
        .carrier()
        .queue(ScriptedAnswer::Answered(json!({"decision": "deny"})));
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(reply["detail"]["decision"], "declined", "{reply}");
    assert_eq!(fixture.page.insertions(), 0);
    assert_eq!(fixture.vault.requests().len(), 1);
}

/// An approval given after the call stopped waiting fills nothing; the
/// agent's next call is what uses it.
#[tokio::test]
async fn a_late_approval_fills_nothing_until_the_agent_calls_again() {
    let fixture = fixture(
        Page::default(),
        VaultState {
            needs_approval: true,
            ..Default::default()
        },
    )
    .await;
    let arguments = fixture.fill_arguments(false).await;
    let pending = reply_body(
        &fixture
            .send(
                json!({"name": "browser.fill_login", "arguments": arguments.clone()}),
                Some(Duration::from_millis(200)),
            )
            .await,
    );
    assert_eq!(pending["outcome"], "consent_pending", "{pending}");
    let ask_id = pending["ask_id"].as_str().unwrap().to_string();
    assert!(fixture
        .carrier()
        .answer_id(&ask_id, ScriptedAnswer::Answered(json!({"decision": "allow"}))));
    // The vault records the approval from the person's signed answer.
    fixture.vault.0.lock().unwrap().approved = true;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let read = fixture.snapshot("ax").await;
    assert_eq!(fixture.page.insertions(), 0, "a late approval filled the page");
    assert_eq!(fixture.page.value(PASSWORD_NODE), "");
    assert!(!fixture.planes.browser.fill_window_open_for_test(&identity()).await);
    assert!(!contains_password(&read));

    let filled = fixture.fill(false).await;
    assert_eq!(filled["outcome"], "ok", "{filled}");
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    assert_eq!(fixture.carrier().questions().len(), 1, "no second card");
}

// ---------------------------------------------------------------------------
// What does not change
// ---------------------------------------------------------------------------

#[tokio::test]
async fn typing_still_refuses_credential_fields() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    for filled in [false, true] {
        let snapshot = fixture.snapshot("ax").await;
        let reply = fixture
            .call(
                "browser.type",
                json!({"ref": named_ref(&snapshot, "Password"), "text": "typed"}),
            )
            .await;
        assert_eq!(reply["outcome"], "invalid_request", "{reply}");
        assert_eq!(reason_code(&reply), "credential_input_unsupported");
        if !filled {
            assert_eq!(fixture.page.insertions(), 0);
            assert_eq!(fixture.fill(false).await["outcome"], "ok");
        }
    }
    assert_eq!(fixture.page.lock().inserted, vec![USERNAME_NODE, PASSWORD_NODE]);
}

/// No plane built for a running module serves the capability: it has no
/// source of login material until the vault is wired in.
#[tokio::test]
async fn production_planes_do_not_serve_fill_login() {
    assert!(cerebellum::browser::fill::PRODUCTION_LOGIN_MATERIAL_SOURCE.is_none());
    assert!(cerebellum::browser::fill::production_login_material_source().is_none());
    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_tool_request_for_test(
        tool_frame(
            1,
            json!({"name": "browser.fill_login", "arguments": {"secret": SECRET}}),
        ),
        &tx,
        &Arc::new(HealthState::new()),
    )
    .await
    .unwrap();
    let refused: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(refused["code"], "capability_not_admitted", "{refused}");
}
