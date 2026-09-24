use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::authorization::{ActionGrant, GrantStore, HazardClass, Severity, OBSERVE};
use cerebellum::browser::navigation::BrowserSnapshotObservation;
use cerebellum::browser::{BrowserPlane, Tracker};
use cerebellum::browser_launch::ExecutableIdentityCheckpoints;
use cerebellum::browser_session::{
    BrowserClickOutcome, BrowserClickPosition, BrowserInputEvent, BrowserSessionLauncher,
    CleanupStage, ClickDriveError, LaunchedBrowser, NavigationDriveError, NavigationWait,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup,
};
use cerebellum::classification::{
    classify_click, AssociatedFormControlInput, ElementClassificationInput, NodeIdentityInput,
    NonTypeClassificationInput, TargetKind,
};
use cerebellum::snapshot_store::{
    AxRecord, BackendNodeIdentity, RefRecord, SnapshotKind, SnapshotRef,
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
        principal: Some(Principal::Direct),
        consumer_capabilities: Some(vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": "pj-browser-session-wire",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.open_grant"]
        })),
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
/// wait until the grant is minted.
async fn open_grant_and_allow(planes: &Planes, corr: u64, params: Value) {
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

#[derive(Default)]
struct RecordingLauncher {
    launches: Arc<Mutex<usize>>,
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

impl OwnedBrowserProcess for RecordingProcess {
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
        Ok("https://landed.example/final".to_string())
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
        Ok(snapshot_observation(
            self.clicked,
            self.hazardous_target,
            self.cross_site_link_target,
            document_epoch,
            current_origin,
        ))
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
        Ok(BrowserClickOutcome::Clicked(position))
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

async fn launch_at(planes: &Planes, origin: &str) {
    let launched = invoke(planes, 1, "browser.launch", json!({})).await;
    let launched: Value = serde_json::from_slice(&launched.body).unwrap();
    assert_eq!(launched["outcome"], "launched", "{launched}");
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
    launch_at(&planes, "https://page.example").await;

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
    launch_at(&planes, "https://page.example").await;

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
    launch_at(&planes, "https://page.example").await;

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
    launch_at(&planes, "https://page.example").await;

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

    // Follow the remedy literally, then retry the identical click.
    open_grant_and_allow(&planes, 63, refused["detail"]["grant_request"].clone()).await;
    let clicked = invoke_existing(&planes, 64, "browser.click", click).await;
    let clicked: Value = serde_json::from_slice(&clicked.body).unwrap();
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot", "input_press", "input_release"]
    );
}

/// With no grant at all, `no_grant` names the origin and severity a grant
/// must cover, and opening exactly that grant admits the retry.
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
    launch_at(&planes, "https://page.example").await;

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
        json!({"origins": ["https://page.example"], "severity_tier": 1, "hazards": []}),
        "{refused}"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());

    open_grant_and_allow(&planes, 71, refused["detail"]["grant_request"].clone()).await;
    let snapshot = invoke_existing(&planes, 72, "browser.snapshot", json!({})).await;
    let snapshot: Value = serde_json::from_slice(&snapshot.body).unwrap();
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
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
    launch_at(&planes, "https://page.example").await;
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
    launch_at(&planes, "https://page.example").await;
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
    launch_at(&planes, "https://page.example").await;

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
    assert_eq!(
        clicked["remedy"],
        "call browser.open_grant to mint a grant that discloses detail.missing_hazard, then retry",
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

/// A route opened without the admission carrier is refused with the reason
/// and remedy that say so, through the declared reply contract.
///
/// A daemon opens a route with no admission facts whenever anything other
/// than its configured carrier opens it, which makes this the refusal a
/// misconfigured caller meets first. Driven through the real dispatch for all
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
/// profile custody recorded there. The check has to look at the disk, because
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
async fn present_fronts_then_marks_human_in_control() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        cerebellum::JournalPersistence::Isolated,
    );
    planes.launch_service = Some(launcher.clone());
    launch_at(&planes, "https://landed.example").await;

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
    launch_at(&planes, "https://landed.example").await;

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
    planes.launch_service = Some(launcher);
    launch_at(&planes, "https://landed.example").await;
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
    planes.launch_service = Some(launcher);
    launch_at(&planes, "https://landed.example").await;
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
    launch_at(&planes, "https://page.example").await;
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
async fn launch_session_at(planes: &Planes, corr: u64, origin: &str) -> String {
    let launched = response_body(planes, corr, "browser.launch", json!({})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
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

    let first = launch_session_at(&planes, 1, "https://page.example").await;
    let before_close = response_body(&planes, 2, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(before_close["outcome"], "ok", "{before_close}");
    close_session(&planes, 3, &first).await;

    let second = launch_session_at(&planes, 4, "https://page.example").await;
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

    let first = launch_session_at(&planes, 1, "https://requested.example").await;
    close_session(&planes, 2, &first).await;
    launch_session_at(&planes, 3, "https://requested.example").await;

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

    launch_session_at(&planes, 1, "https://page.example").await;
    let old = response_body(&planes, 2, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(old["outcome"], "ok", "{old}");

    *launcher.exited.lock().unwrap() = true;
    planes.sessions.observe_exits_all(&config());
    let status = response_body(&planes, 3, "browser.status", json!({})).await;
    assert_ne!(status["outcome"], "ready", "{status}");
    *launcher.exited.lock().unwrap() = false;

    launch_session_at(&planes, 4, "https://page.example").await;
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

    let first = launch_session_at(&planes, 1, "https://page.example").await;
    close_session(&planes, 2, &first).await;
    let refused = response_body(&planes, 3, "browser.snapshot", json!({"mode": "ax"})).await;
    assert_eq!(refused["outcome"], "no_session", "{refused}");
}
