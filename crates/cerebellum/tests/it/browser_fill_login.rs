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
    main_opaque: bool,
    adopted_owner: bool,
    mutate_before_set: bool,
    fail_after_password: bool,
    resolve_fails: bool,
    snapshot_delay: Duration,
    real_dom_capture: bool,
    frame_generation: u64,
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
            main_opaque: false,
            adopted_owner: false,
            mutate_before_set: false,
            fail_after_password: false,
            resolve_fails: false,
            snapshot_delay: Duration::ZERO,
            real_dom_capture: false,
            frame_generation: 1,
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
        page.values.clear();
        page.copied_text = None;
    }

    fn value(&self, node: u64) -> String {
        self.lock().values.get(&node).cloned().unwrap_or_default()
    }

    fn insertions(&self) -> usize {
        self.lock().inserted.len()
    }
}

impl Page {
    fn dom(&self) -> Map<String, Value> {
        let mut nodes = vec![
            json!({"nodeId":1,"backendNodeId":1,"nodeType":9,"localName":"","nodeName":"#document"}),
        ];
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
            "securityOrigin": if self.main_opaque { "null" } else { origin.as_str() },
            "mimeType": "text/html",
        }});
        if let Some(frame) = &self.frame {
            let mut child = json!({
                "id": LOGIN_FRAME,
                "parentId": MAIN,
                "loaderId": format!("frame-loader-{}", self.frame_generation),
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
            "Page.createIsolatedWorld" => json!({"executionContextId": 1}),
            "DOM.describeNode" => {
                let in_frame = self.form_in == Place::Frame;
                json!({"node":{"nodeType":9,"frameId":if self.adopted_owner {"adopted-frame"} else if in_frame { LOGIN_FRAME } else { MAIN },
                    "documentURL":if self.adopted_owner {"about:blank"} else if in_frame {&self.frame.as_ref().unwrap().url} else {&self.main_url}}})
            }
            "Accessibility.getRootAXNode" => {
                json!({"node":{"nodeId":"root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Login"},"backendDOMNodeId":1,"frameId":MAIN}})
            }
            "Accessibility.getChildAXNodes" => json!({"nodes":[]}),
            "DOM.getDocument" => json!({"root":{"nodeId":1}}),
            "DOM.pushNodesByBackendIdsToFrontend" => json!({"nodeIds":[1]}),
            "DOM.querySelector" => json!({"nodeId":1}),
            "DOM.getOuterHTML" => {
                json!({"outerHTML":"<body><input type=button value=IDENTITY-MASK-CANARY></body>"})
            }
            "DOM.resolveNode" => {
                if self.resolve_fails {
                    return Err("transport unavailable");
                }
                let node = params["backendNodeId"]
                    .as_u64()
                    .or_else(|| params["nodeId"].as_u64())
                    .unwrap_or_default();
                if self.form_removed && field(node) {
                    return Err("No node with given id found");
                }
                json!({"object": {"objectId": format!("node-{node}")}})
            }
            "Runtime.callFunctionOn" => {
                let node = Self::object_node(params).ok_or("Cannot find context")?;
                let function = params["functionDeclaration"].as_str().unwrap_or_default();
                if function == "function() { return this.ownerDocument; }" {
                    return Ok(json!({"result":{"objectId":"document-owner"}}));
                }
                let value = if function.contains("protectedNodes") {
                    assert!(params["arguments"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .any(|arg| arg["objectId"] == format!("node-{USERNAME_NODE}")));
                    json!("<body><input type=button></body>")
                } else if function.contains("Object.getOwnPropertyDescriptor") {
                    assert!(function.contains("this.ownerDocument !== doc"));
                    assert!(function.contains("this.isConnected"));
                    assert!(function.contains("this.type !== expectedType"));
                    assert!(function.contains("JSON.stringify(tokens)"));
                    assert!(function.contains("dispatchEvent(new win.Event('input'"));
                    assert!(function.contains("dispatchEvent(new win.Event('change'"));
                    if self.mutate_before_set {
                        return Ok(json!({"result":{"value":false}}));
                    }
                    let text = params["arguments"][4]["value"].as_str().unwrap().to_owned();
                    self.values.insert(node, text);
                    self.inserted.push(node);
                    if self.navigate_after_first_insert && self.inserted.len() == 1 {
                        self.document += 1;
                    }
                    if self.fail_after_password && node == PASSWORD_NODE {
                        return Err("timeout after setting password");
                    }
                    json!(true)
                } else if function.contains("this.select()") {
                    self.focused = Some(node);
                    json!(true)
                } else if function.contains("this.value.length : -1") {
                    json!(self
                        .values
                        .get(&node)
                        .map_or(0, |value| value.encode_utf16().count()))
                } else if function.contains("this.value = ''") {
                    if self.fail_after_password {
                        return Err("cleanup unavailable");
                    }
                    self.values.insert(node, String::new());
                    json!(true)
                } else if function.contains("isConnected") {
                    json!(
                        !self.form_removed
                            && self
                                .values
                                .get(&node)
                                .is_some_and(|value| !value.is_empty())
                    )
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
    fn navigate(
        &mut self,
        _: &str,
        url: &str,
        _: cerebellum::browser_session::NavigationWait,
        _: u64,
        tracker: &mut cerebellum::browser::Tracker,
    ) -> Result<(), NavigationDriveError> {
        if url.contains('#') {
            self.page.lock().main_url = url.into();
            tracker.main_frame_navigated_within_document(url.into());
        } else {
            self.page.navigate_away();
            self.page.lock().main_url = url.into();
            tracker.main_frame_navigated(Some(MAIN.into()), url.into());
        }
        tracker.load(std::time::Instant::now());
        Ok(())
    }

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
                let value = page
                    .values
                    .get(&node)
                    .cloned()
                    .filter(|value| !value.is_empty());
                observation.records.push(AxRecord {
                    depth: 0,
                    role: "textbox".into(),
                    name: name.into(),
                    value: value.clone(),
                    reference: Some(reference.clone()),
                });
                // What the DOM says about the field now: a password input is
                // a credential field, the same input toggled to text is not.
                observation
                    .facts
                    .entry(reference.clone())
                    .or_default()
                    .credential = Some(node == PASSWORD_NODE && page.password_type == "password");
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

    fn snapshot_protected(
        &mut self,
        context: &str,
        mode: SnapshotKind,
        reference: Option<&RefRecord>,
        epoch: u64,
        origin: &str,
        filled: &[BackendNodeIdentity],
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let (delay, real_dom) = {
            let page = self.page.lock();
            (page.snapshot_delay, page.real_dom_capture)
        };
        std::thread::sleep(delay);
        if real_dom && mode == SnapshotKind::DomFull {
            return self.driver.snapshot_protected(
                context,
                mode,
                reference,
                epoch,
                origin,
                filled,
                deadline_ms,
            );
        }
        self.snapshot_classified(context, mode, epoch, origin, deadline_ms)
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
    password: String,
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
            password: PASSWORD.into(),
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
            object
                .keys()
                .all(|key| matches!(key.as_str(), "name" | "coverage" | "stamp" | "target"))
        }) && params["target"]
            .as_object()
            .is_some_and(|target| target.len() == 1);
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
                "password": state.password,
            });
            if state.totp {
                released["totp"] = json!(TOTP);
            }
            released
        };
        Box::pin(async move {
            Ok(cerebellum::browser::fill::SecretUseAnswer::from_wire(
                zeroize::Zeroizing::new(serde_json::to_vec(&json!({"result": reply})).unwrap()),
            ))
        })
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
    fixture_with_source(page, vault, window, None).await
}

async fn fixture_with_source(
    page: Page,
    vault: VaultState,
    window: Duration,
    source: Option<Arc<dyn LoginMaterialSource>>,
) -> Fixture {
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
            .with_login_material_source(Some(source.unwrap_or_else(|| Arc::new(vault.clone()))))
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

/// Bind the tool route for a primary session whose route carries a stamped
/// agent scope (which the vault needs) and can relay a question to a person.
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
        .or_else(|| {
            // Identity masking clears names after a fill; this fixture's
            // username and password remain the first two textbox identities.
            let index = match name {
                "Email" => 0,
                "Password" => 1,
                _ => return None,
            };
            snapshot["state_text"]
                .as_str()?
                .lines()
                .filter(|line| line.contains(" textbox"))
                .nth(index)?
                .split_whitespace()
                .next()
                .map(str::to_owned)
        })
        .unwrap_or_else(|| panic!("no line named {name}: {snapshot}"))
}

fn contains_password(value: &Value) -> bool {
    value.to_string().contains(PASSWORD)
}

fn vault_approval_answer(request_id: &str, decision: &str) -> ScriptedAnswer {
    let mut answer =
        json!({"decision": decision, "items": [{"request_id": request_id, "decision": decision}]});
    if decision == "allow" {
        answer["duration"] = json!("hour");
        answer["envelope_sha256"] =
            json!("7bcd68a3ec5698ad9c9d11e0efa1d67ef7e7aa6ee18c56d963d5f6b18014f180");
    }
    ScriptedAnswer::Answered(json!({"secret_use_answer": answer}))
}

fn reason_code(reply: &Value) -> &str {
    reply["detail"]["reason_code"].as_str().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Filling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn real_source_fills_and_handles_golden_approval_and_refusal() {
    use cerebellum::login_capture::secret_use::VaultLoginSource;
    use cerebellum::login_capture::vault::{BoxFuture, CookieVault, VaultReachError, VaultRoute};
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Script {
        replies: Mutex<VecDeque<&'static [u8]>>,
        requests: Mutex<Vec<Value>>,
        opened: AtomicUsize,
        closed: AtomicUsize,
    }
    struct ScriptVault(Arc<Script>);
    struct Route(Arc<Script>);
    impl Drop for Route {
        fn drop(&mut self) {
            self.0.closed.fetch_add(1, Ordering::SeqCst);
        }
    }
    impl CookieVault for ScriptVault {
        fn open(&self) -> BoxFuture<'_, Result<Box<dyn VaultRoute>, VaultReachError>> {
            self.0.opened.fetch_add(1, Ordering::SeqCst);
            let route: Box<dyn VaultRoute> = Box::new(Route(self.0.clone()));
            Box::pin(async { Ok(route) })
        }
    }
    impl VaultRoute for Route {
        fn call<'a>(
            &'a mut self,
            body: &'a [u8],
        ) -> BoxFuture<'a, Result<Vec<u8>, VaultReachError>> {
            let request: Value = serde_json::from_slice(body).unwrap();
            self.0.requests.lock().unwrap().push(request);
            let golden = self
                .0
                .replies
                .lock()
                .unwrap()
                .pop_front()
                .expect("one reply per call");
            let mut reply = b"{\"result\":".to_vec();
            reply.extend_from_slice(golden);
            reply.push(b'}');
            Box::pin(async { Ok(reply) })
        }
    }
    let script = Arc::new(Script {
        replies: Mutex::new(VecDeque::from([
            include_bytes!("../vectors/secret-use-v1/use.result.released.site_login.json")
                .as_slice(),
            include_bytes!("../vectors/secret-use-v1/use.result.approval_required.json").as_slice(),
            include_bytes!("../vectors/secret-use-v1/error.result.json").as_slice(),
        ])),
        requests: Mutex::new(Vec::new()),
        opened: AtomicUsize::new(0),
        closed: AtomicUsize::new(0),
    });
    let source = Arc::new(VaultLoginSource::new(
        Arc::new(ScriptVault(script.clone())),
        HANG_GUARD,
    ));
    for case in 0..3 {
        let fixture = fixture_with_source(
            Page::default(),
            VaultState::default(),
            Duration::from_secs(600),
            Some(source.clone()),
        )
        .await;
        fixture.carrier().queue(vault_approval_answer(
            "01HF7YAT000000000000000001",
            "decline",
        ));
        let reply = fixture.fill(true).await;
        match case {
            0 => {
                assert_eq!(reply["outcome"], "ok", "{reply}");
                assert_eq!(fixture.page.value(USERNAME_NODE), "alice");
                assert_eq!(fixture.page.value(PASSWORD_NODE), "correct horse");
                assert_eq!(fixture.page.value(OTP_NODE), "123456");
            }
            1 => {
                assert_eq!(reply["outcome"], "authorization_denied", "{reply}");
                let questions = fixture.carrier().questions();
                assert_eq!(questions.len(), 1);
                let golden: Value = serde_json::from_slice(include_bytes!(
                    "../vectors/secret-use-v1/use.result.approval_required.json"
                ))
                .unwrap();
                assert_eq!(
                    questions[0]["params"],
                    json!({"kind": "secret_use", "secret_use": {"items": [{
                        "request_id": golden["request_id"], "statement_b64url": golden["statement_b64url"],
                    }]}})
                );
                assert_eq!(fixture.page.insertions(), 0);
            }
            _ => {
                assert_eq!(reason_code(&reply), "login_unavailable", "{reply}");
                assert_eq!(fixture.page.insertions(), 0);
                assert!(fixture.carrier().questions().is_empty());
            }
        }
        for secret in ["alice", "correct horse", "123456"] {
            assert!(!reply.to_string().contains(secret));
        }
        let journal = fixture.planes.browser.journal_export_for_test().await;
        let entries: Vec<Value> = journal
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .filter(|entry| entry["capability"] == "browser.fill_login")
            .collect();
        assert_eq!(entries.len(), 1, "{journal}");
        assert_eq!(entries[0]["payload"]["outcome"], reply["outcome"]);
        assert_eq!(entries[0]["payload"]["origin"], SITE);
        for secret in ["alice", "correct horse", "123456"] {
            assert!(!journal.contains(secret));
        }
        assert_eq!(script.opened.load(Ordering::SeqCst), case + 1);
        assert_eq!(script.closed.load(Ordering::SeqCst), case + 1);
    }
    assert!(script.replies.lock().unwrap().is_empty());
    for request in script.requests.lock().unwrap().iter() {
        assert_eq!(
            request,
            &json!({"method": "secret.use", "params": {
                "name": SECRET, "coverage": "scope", "stamp": serde_json::to_value(stamp(AGENT)).unwrap(),
                "target": {"origin": SITE},
            }})
        );
    }
}

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
        assert!(
            fixture.vault.requests().is_empty(),
            "{name}: the vault was asked"
        );
        assert_eq!(fixture.page.insertions(), 0, "{name}");
        assert!(
            fixture.planes.browser.result_schema_findings().is_empty(),
            "{name}"
        );
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
    assert_eq!(
        wrong_origin["outcome"], "authorization_denied",
        "{wrong_origin}"
    );
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
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
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
    // The window is installed before dispatch and stays until a read
    // confirms main-frame document replacement.
    assert_eq!(fixture.snapshot("ax").await["outcome"], "ok");
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
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
    assert_eq!(
        fixture.page.value(USERNAME_NODE),
        "",
        "the username was not cleared"
    );
    assert_eq!(fixture.page.value(PASSWORD_NODE), "");
    assert_eq!(fixture.snapshot("ax").await["outcome"], "ok");
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
}

// ---------------------------------------------------------------------------
// What leaves the module
// ---------------------------------------------------------------------------

/// The planted password is in no reply, journal entry or call record; the
/// scan is shown to find a planted copy, and each scanned store is shown to
/// hold this test's records.
#[tokio::test]
async fn the_password_never_reaches_the_reply_journal_or_call_record() {
    let mut fixture = fixture(
        Page::default(),
        VaultState {
            totp: true,
            ..Default::default()
        },
    )
    .await;
    let storage = cerebellum::journal::call_records::InMemoryCallRecordStorage::new();
    fixture.planes.calls = Arc::new(cerebellum::journal::call_records::CallRecords::open(
        Box::new(storage.clone()),
        0,
    ));
    assert!(contains_password(
        &json!({"planted": format!("<{PASSWORD}>")})
    ));

    let arguments = fixture.fill_arguments(true).await;
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
    assert!(
        journal.contains("browser.snapshot"),
        "the journal holds this test's reads"
    );
    assert!(!journal.contains(PASSWORD));
    let fills: Vec<Value> = journal
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|entry| entry["capability"] == "browser.fill_login")
        .collect();
    assert_eq!(fills.len(), 1, "one fill entry per call: {journal}");
    assert_eq!(fills[0]["format_version"], "ck-browser-journal/v9");
    assert_eq!(
        fills[0]["payload"],
        json!({"outcome": "ok", "origin": SITE, "filled": ["username", "password", "otp"]})
    );
    for secret in [USERNAME, PASSWORD, TOTP] {
        assert!(
            format!("{journal}{secret}").contains(secret),
            "the scan detects a planted copy"
        );
        assert!(!journal.contains(secret), "material leaked into journal");
    }

    assert_eq!(
        fixture.planes.calls.record_count(),
        1,
        "the keyed fill was recorded"
    );
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
    assert_eq!(
        refused["detail"]["reason"],
        "a filled password is on this page"
    );
    assert!(fixture.planes.browser.result_schema_findings().is_empty());

    fixture.page.navigate_away();
    let allowed = fixture.screenshot().await;
    assert_eq!(allowed["outcome"], "ok", "{allowed}");
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
}

/// Empty fields do not prove that script copies have disappeared.
#[tokio::test]
async fn emptied_fields_keep_the_window() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    assert_eq!(
        fixture.screenshot().await["outcome"],
        "authorization_denied"
    );
    fixture.page.lock().values.clear();
    let refused = fixture.screenshot().await;
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
}

/// Reads keep working in every mode. Text a page script copied into the
/// document loses the password; the filled fields show no value, the
/// password field included after the page turns it into a text input.
#[tokio::test]
async fn text_reads_drop_the_password_and_mask_the_filled_fields() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    let copied = format!("Signed in with {PASSWORD}");
    assert!(
        copied.contains(PASSWORD),
        "the page text carries a planted copy"
    );
    fixture.page.lock().copied_text = Some(copied);
    for mode in ["actionable", "ax", "dom_full"] {
        let snapshot = fixture.snapshot(mode).await;
        assert!(!contains_password(&snapshot), "{mode}: {snapshot}");
        assert!(
            snapshot["state_text"]
                .as_str()
                .unwrap()
                .contains(REDACTED_PASSWORD),
            "{mode}: the copied text was dropped instead of redacted: {snapshot}"
        );
    }
    // Filled nodes stay masked even after their input type changes.
    let ax = fixture.snapshot("ax").await;
    assert!(
        !ax["state_text"].as_str().unwrap().contains("Value:"),
        "{ax}"
    );

    fixture.page.lock().password_type = "text".into();
    let toggled = fixture.snapshot("ax").await;
    assert!(
        !toggled["state_text"].as_str().unwrap().contains("Value:"),
        "{toggled}"
    );
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
    let refused = fixture
        .call("browser.snapshot", json!({"mode": "ax"}))
        .await;
    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(reason_code(&refused), "filled_login_expired");
    assert_eq!(
        reason_code(&fixture.screenshot().await),
        "filled_login_expired"
    );

    fixture.page.navigate_away();
    let read = fixture
        .call("browser.snapshot", json!({"mode": "ax"}))
        .await;
    assert_eq!(read["outcome"], "ok", "{read}");
    assert_eq!(fixture.screenshot().await["outcome"], "ok");
}

#[tokio::test]
async fn navigation_reply_releases_quarantine_only_after_main_loader_replacement() {
    let fixture = fixture_with_window(
        Page::default(),
        VaultState::default(),
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    tokio::time::sleep(Duration::from_millis(400)).await;
    let arguments = |url: String| json!({"url":url,"intent":"navigate the test page","wait":"none","read_page":false,"severity":{"tier":1,"credential":false,"financial":false}});
    let same_document = fixture
        .call(
            "browser.navigate",
            arguments(format!("{SITE}/signin#fragment")),
        )
        .await;
    assert_eq!(
        reason_code(&same_document),
        "filled_login_expired",
        "{same_document}"
    );
    let replaced = fixture
        .call("browser.navigate", arguments(format!("{SITE}/home")))
        .await;
    assert_eq!(replaced["outcome"], "ok", "{replaced}");
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
}

// ---------------------------------------------------------------------------
// The person's approval
// ---------------------------------------------------------------------------

#[tokio::test]
async fn adopted_owner_frame_is_refused_before_insertion() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let page = fixture.page.clone();
    fixture.vault.0.lock().unwrap().during_request =
        Some(Box::new(move || page.lock().adopted_owner = true));
    let reply = fixture.fill(false).await;
    assert_eq!(reason_code(&reply), "owner_frame_changed", "{reply}");
    assert_eq!(fixture.page.insertions(), 0);
}

#[tokio::test]
async fn insertion_revalidates_on_the_node_without_focus_commands() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let page = fixture.page.clone();
    fixture.vault.0.lock().unwrap().during_request =
        Some(Box::new(move || page.lock().mutate_before_set = true));
    let reply = fixture.fill(false).await;
    assert_eq!(reason_code(&reply), "fill_insert_not_ready", "{reply}");
    assert_eq!(fixture.page.insertions(), 0);
    assert!(!fixture
        .page
        .lock()
        .commands
        .iter()
        .any(|method| matches!(method.as_str(), "DOM.focus" | "Input.insertText")));
}

#[tokio::test]
async fn partial_fill_with_failed_cleanup_keeps_protection() {
    let fixture = fixture(
        Page {
            fail_after_password: true,
            ..Default::default()
        },
        VaultState::default(),
    )
    .await;
    let reply = fixture.fill(false).await;
    assert_ne!(reply["outcome"], "ok", "{reply}");
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    assert!(
        fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
    assert_eq!(
        fixture.screenshot().await["outcome"],
        "authorization_denied"
    );
    fixture.page.lock().copied_text = Some(PASSWORD.into());
    assert!(!contains_password(&fixture.snapshot("ax").await));
}

#[tokio::test]
async fn successive_fills_keep_every_released_secret() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    fixture.vault.0.lock().unwrap().password = "second-password-canary".into();
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    fixture.page.lock().copied_text = Some(format!("{PASSWORD} second-password-canary"));
    let reply = fixture.snapshot("ax").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert!(!contains_password(&reply), "{reply}");
    assert!(
        !reply.to_string().contains("second-password-canary"),
        "{reply}"
    );
}

#[tokio::test]
async fn a_capture_crossing_the_cap_refuses_at_retention_and_output() {
    let fixture = fixture_with_window(
        Page::default(),
        VaultState::default(),
        Duration::from_millis(300),
    )
    .await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    {
        let mut page = fixture.page.lock();
        page.snapshot_delay = Duration::from_millis(400);
        page.copied_text = Some(PASSWORD.into());
    }
    let reply = fixture.call("browser.snapshot", json!({"mode":"ax"})).await;
    assert_eq!(reason_code(&reply), "filled_login_expired", "{reply}");
    assert!(!contains_password(&reply));
}

#[tokio::test]
async fn unreadable_or_removed_fields_never_end_protection() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    fixture.page.lock().resolve_fails = true;
    assert_eq!(
        fixture.screenshot().await["outcome"],
        "authorization_denied"
    );
    {
        let mut page = fixture.page.lock();
        page.resolve_fails = false;
        page.form_removed = true;
        page.copied_text = Some(PASSWORD.into());
    }
    assert_eq!(
        fixture.screenshot().await["outcome"],
        "authorization_denied"
    );
    let reply = fixture.snapshot("ax").await;
    assert!(!contains_password(&reply));
    assert!(reply["state_text"]
        .as_str()
        .unwrap()
        .contains(REDACTED_PASSWORD));
}

#[tokio::test]
async fn subframe_navigation_keeps_parent_copies_redacted_and_the_tab_quarantined() {
    let fixture = fixture(
        Page {
            form_in: Place::Frame,
            frame: Some(FrameSpec {
                url: format!("{FRAME_SITE}/signin"),
                security_origin: Some(FRAME_SITE.into()),
            }),
            ..Default::default()
        },
        VaultState {
            saved_origin: FRAME_SITE.into(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    assert_eq!(
        fixture.screenshot().await["outcome"],
        "authorization_denied"
    );
    {
        let mut page = fixture.page.lock();
        page.frame_generation += 1;
        page.values.clear();
        page.copied_text = Some(format!("Parent copied {PASSWORD}"));
    }
    let parent = fixture.snapshot("ax").await;
    assert!(!contains_password(&parent), "{parent}");
    assert!(parent["state_text"]
        .as_str()
        .unwrap()
        .contains(REDACTED_PASSWORD));
    assert_eq!(
        fixture.screenshot().await["outcome"],
        "authorization_denied"
    );
    fixture.page.navigate_away();
    assert_eq!(fixture.screenshot().await["outcome"], "ok");
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
}

#[test]
fn resolve_node_transport_failure_is_indeterminate_not_empty() {
    let page = Shared::new(Page {
        resolve_fails: true,
        ..Default::default()
    });
    let mut driver = CdpNavigationDriver::new(
        Pipe {
            page,
            reads: VecDeque::new(),
        },
        CdpTransport::new(),
        CdpFrameDecoder::default(),
    );
    let state = driver.filled_fields_state(
        CONVERSATION,
        &[cerebellum::browser::fill::FilledField {
            identity: BackendNodeIdentity::new(TARGET, MAIN, PASSWORD_NODE).unwrap(),
            frame: None,
        }],
        1_000,
    );
    assert!(
        state.is_err(),
        "unreadable node was classified as {state:?}"
    );
}

#[tokio::test]
async fn echoes_of_username_totp_and_entity_encoded_password_are_redacted() {
    let password = "entity&<>\"'password";
    let fixture = fixture(
        Page::default(),
        VaultState {
            totp: true,
            password: password.into(),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(fixture.fill(true).await["outcome"], "ok");
    fixture.page.lock().copied_text = Some(format!(
        "{USERNAME} {TOTP} entity&amp;&lt;&gt;&quot;&#39;password"
    ));
    for mode in ["ax", "actionable", "dom_full"] {
        let reply = fixture.snapshot(mode).await;
        let text = reply.to_string();
        assert_eq!(reply["outcome"], "ok", "{reply}");
        for secret in [
            USERNAME,
            TOTP,
            password,
            "entity&amp;&lt;&gt;&quot;&#39;password",
        ] {
            assert!(!text.contains(secret), "{mode}: {reply}");
        }
    }
}

#[tokio::test]
async fn opaque_main_document_refuses_before_vault_access() {
    let fixture = fixture(
        Page {
            main_opaque: true,
            ..Default::default()
        },
        VaultState::default(),
    )
    .await;
    let reply = fixture.fill(false).await;
    assert_eq!(reason_code(&reply), "origin_opaque", "{reply}");
    assert!(fixture.vault.requests().is_empty());
    assert_eq!(fixture.page.insertions(), 0);
}

#[tokio::test]
async fn dom_full_capture_masks_type_mutated_nodes_by_identity() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    assert_eq!(fixture.fill(false).await["outcome"], "ok");
    fixture.page.lock().real_dom_capture = true;
    let reply = fixture.snapshot("dom_full").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert!(
        !reply.to_string().contains("IDENTITY-MASK-CANARY"),
        "{reply}"
    );
    assert!(
        reply["state_text"]
            .as_str()
            .unwrap()
            .contains("type=button"),
        "{reply}"
    );
}

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
        .queue(vault_approval_answer("req_vault_1", "allow"));
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    let questions = fixture.carrier().questions();
    assert_eq!(questions.len(), 1, "{questions:?}");
    let card = &questions[0]["params"];
    assert_eq!(
        card,
        &json!({"kind": "secret_use", "secret_use": {"items": [{"request_id": "req_vault_1", "statement_b64url": "eyJsb2dpbiI6IndvcmstbG9naW4ifQ"}]}}),
        "{card}"
    );
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
        .queue(vault_approval_answer("req_vault_1", "decline"));
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(reply["detail"]["decision"], "declined", "{reply}");
    assert_eq!(fixture.page.insertions(), 0);
    assert_eq!(fixture.vault.requests().len(), 1);
}

#[tokio::test]
async fn dedicated_approval_requires_the_capability_and_maps_filing_refusals() {
    for (code, reason, outcome) in [
        (
            None,
            "secret_use_approval_unsupported",
            "consent_unavailable",
        ),
        (
            Some("elicitation_request_conflict"),
            "elicitation_request_conflict",
            "consent_unavailable",
        ),
        (
            Some("elicitation_invalid_request"),
            "elicitation_invalid_request",
            "consent_unavailable",
        ),
        (
            Some("elicitation_requester_refused"),
            "elicitation_requester_refused",
            "consent_unavailable",
        ),
        (
            Some("elicitation_expired"),
            "login_approval_not_given",
            "authorization_denied",
        ),
    ] {
        let fixture = fixture(
            Page::default(),
            VaultState {
                needs_approval: true,
                ..Default::default()
            },
        )
        .await;
        let carrier = fixture.carrier();
        if let Some(code) = code {
            carrier.refuse_next_request(code);
        } else {
            carrier.without_secret_use_approval();
        }
        let reply = fixture.fill(false).await;
        assert_eq!(reply["outcome"], outcome, "{reply}");
        assert_eq!(reason_code(&reply), reason, "{reply}");
        if code.is_none() {
            assert!(reply["detail"]["reason"]
                .as_str()
                .unwrap()
                .contains("secret-use-approval/v1"));
            assert!(carrier
                .calls()
                .iter()
                .all(|(method, _)| method != "consent.request"));
        }
        if code == Some("elicitation_expired") {
            assert_eq!(reply["detail"]["decision"], "no_answer");
        }
        assert_eq!(fixture.vault.requests().len(), 1);
        assert_eq!(fixture.page.insertions(), 0);
    }
}

#[tokio::test]
async fn a_generic_allow_never_retries_the_vault_or_fills_a_login() {
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
    assert_eq!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(reply["detail"]["decision"], "no_answer", "{reply}");
    assert_eq!(fixture.vault.requests().len(), 1);
    assert_eq!(fixture.page.insertions(), 0);
}

#[tokio::test]
async fn a_dedicated_allow_cannot_fill_unless_the_vault_releases_material() {
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
        .queue(vault_approval_answer("req_vault_1", "allow"));
    let reply = fixture.fill(false).await;
    assert_eq!(reply["outcome"], "authorization_denied", "{reply}");
    assert_eq!(reason_code(&reply), "login_unavailable", "{reply}");
    assert_eq!(
        fixture.vault.requests().len(),
        2,
        "allow only cues a vault retry"
    );
    assert_eq!(fixture.page.insertions(), 0);
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
        .answer_id(&ask_id, vault_approval_answer("req_vault_1", "allow")));
    // The vault records the approval from the person's signed answer.
    fixture.vault.0.lock().unwrap().approved = true;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let read = fixture.snapshot("ax").await;
    assert_eq!(
        fixture.page.insertions(),
        0,
        "a late approval filled the page"
    );
    assert_eq!(fixture.page.value(PASSWORD_NODE), "");
    assert!(
        !fixture
            .planes
            .browser
            .fill_window_open_for_test(&identity())
            .await
    );
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
    assert_eq!(
        fixture.page.lock().inserted,
        vec![USERNAME_NODE, PASSWORD_NODE]
    );
}

/// The rollout switch is on, but only a plane given a source serves the fill:
/// production startup installs the real one, and test construction installs
/// none, so a test plane still refuses `browser.fill_login` as not admitted.
#[tokio::test]
async fn test_planes_do_not_serve_fill_login() {
    const { assert!(cerebellum::browser::fill::FILL_LOGIN_ENABLED) };
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

/// `browser_use` with `action: "fill_login"` is served by `browser.fill_login`:
/// the vault is asked once, the fields are filled, and the reply names the
/// fields and the site, never the values.
#[tokio::test]
async fn browser_use_fill_login_reaches_the_fill() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let mut arguments = fixture.fill_arguments(false).await;
    arguments["action"] = json!("fill_login");
    let frame = fixture
        .send(json!({"name": "browser_use", "arguments": arguments}), None)
        .await;
    let reply = reply_body(&frame);
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(reply["origin"], SITE);
    assert_eq!(reply["filled"], json!(["username", "password"]));
    assert_eq!(fixture.page.value(USERNAME_NODE), USERNAME);
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    assert_eq!(fixture.vault.requests().len(), 1);
    assert!(!contains_password(&reply));
    assert!(fixture.planes.browser.result_schema_findings().is_empty());
}

/// The person's browser has no fill path: `browser:"user"` is refused by
/// name before the vault or the page is reached.
#[tokio::test]
async fn browser_use_fill_login_refuses_the_persons_browser() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let mut arguments = fixture.fill_arguments(false).await;
    arguments["action"] = json!("fill_login");
    arguments["browser"] = json!("user");
    let frame = fixture
        .send(json!({"name": "browser_use", "arguments": arguments}), None)
        .await;
    let reply = reply_body(&frame);
    assert_eq!(reply["outcome"], "invalid_request", "{reply}");
    assert_eq!(reply["detail"]["field"], "browser", "{reply}");
    assert_eq!(reason_code(&reply), "own_browser_only", "{reply}");
    assert!(fixture.vault.requests().is_empty());
    assert_eq!(fixture.page.insertions(), 0);
}

/// A named snapshot chooses which elements the refs name, as it does for
/// `browser.type`: an unknown or evicted one refuses exactly as type refuses
/// it, a snapshot of another kind is refused, and the snapshot that showed
/// the fields fills them. Every refusal comes before the vault is asked.
#[tokio::test]
async fn a_named_snapshot_chooses_the_refs_and_an_unknown_one_refuses_as_type_does() {
    let fixture = fixture(Page::default(), VaultState::default()).await;
    let screenshot = fixture.screenshot().await;
    assert_eq!(screenshot["outcome"], "ok", "{screenshot}");
    let snapshot = fixture.snapshot("ax").await;
    let username_ref = named_ref(&snapshot, "Email");
    let arguments = |snapshot_id: &Value| {
        json!({
            "secret": SECRET,
            "username_ref": username_ref,
            "password_ref": named_ref(&snapshot, "Password"),
            "snapshot_id": snapshot_id,
        })
    };

    let unknown = json!("0123456789abcdef0123456789abcdef");
    let refused = fixture
        .call("browser.fill_login", arguments(&unknown))
        .await;
    assert_eq!(refused["outcome"], "stale_snapshot", "{refused}");
    assert_eq!(reason_code(&refused), "snapshot_evicted", "{refused}");
    let typed = fixture
        .call(
            "browser.type",
            json!({"ref": username_ref, "snapshot_id": unknown, "text": "x"}),
        )
        .await;
    for key in ["outcome", "detail"] {
        assert_eq!(refused[key], typed[key], "{key}: {refused} versus {typed}");
    }

    let other_kind = fixture
        .call("browser.fill_login", arguments(&screenshot["snapshot_id"]))
        .await;
    assert_eq!(other_kind["outcome"], "stale_snapshot", "{other_kind}");
    assert_eq!(
        reason_code(&other_kind),
        "snapshot_kind_mismatch",
        "{other_kind}"
    );
    assert!(fixture.vault.requests().is_empty());
    assert_eq!(fixture.page.insertions(), 0);

    let filled = fixture
        .call("browser.fill_login", arguments(&snapshot["snapshot_id"]))
        .await;
    assert_eq!(filled["outcome"], "ok", "{filled}");
    assert_eq!(filled["filled"], json!(["username", "password"]));
    assert_eq!(fixture.page.value(PASSWORD_NODE), PASSWORD);
    assert_eq!(fixture.vault.requests().len(), 1);
}
