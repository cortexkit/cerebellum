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
use cerebellum_core::health::HealthState;
use cerebellum_core::identity::RouteIdentity;
use serde_json::{json, Value};
use subc_protocol::{BindIdentity, Flags, Frame, FrameType, Principal, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

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
        &BindIdentity {
            project_root: "/test/project".into(),
            harness: "test".to_string(),
            session: "test-session".to_string(),
        },
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

fn snapshot_observation(
    clicked: bool,
    hazardous: bool,
    document_epoch: u64,
    current_url: &str,
) -> BrowserSnapshotObservation {
    let (scheme, rest) = current_url
        .split_once("://")
        .expect("the wire test page URL has a scheme");
    let authority = rest.split(['/', '?', '#']).next().unwrap();
    let origin = format!("{scheme}://{authority}");
    let mut target = ElementClassificationInput::new(
        NodeIdentityInput::new("target", "frame-main", 42),
        TargetKind::Button,
    );
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
            classification: Some(Box::new(classification)),
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
    present_error: Option<&'static str>,
    cookie_value: Option<&'static str>,
    cookie_grows_on_poll: bool,
    credential_field_then_clears: bool,
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
                present_error: self.present_error,
                cookie_value: self.cookie_value,
                cookie_grows_on_poll: self.cookie_grows_on_poll,
                credential_field_then_clears: self.credential_field_then_clears,
                cookie_reads: 0,
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

struct RecordingProcess {
    effects: Arc<Mutex<Vec<&'static str>>>,
    clicked: bool,
    hazardous_target: bool,
    present_error: Option<&'static str>,
    cookie_value: Option<&'static str>,
    cookie_grows_on_poll: bool,
    credential_field_then_clears: bool,
    cookie_reads: usize,
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
        true
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
    assert_eq!(
        wrong_origin["detail"]["granted_origins"],
        json!(["https://other.example", "https://second-other.example"]),
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
    assert_eq!(clicked["detail"]["reason"], "no_grant", "{clicked}");
    assert_eq!(
        launcher.effects.lock().unwrap().as_slice(),
        ["snapshot"],
        "a refused click dispatched input"
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
    assert_eq!(body, json!({"outcome": "authorization_denied"}));
    let valid_response = invoke_existing(&planes, 2, "browser.launch", json!({})).await;
    assert_eq!(
        serde_json::from_slice::<Value>(&valid_response.body).unwrap(),
        json!({"outcome": "authorization_denied"})
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
    assert_eq!(
        serde_json::from_slice::<Value>(&response.body).unwrap(),
        json!({"outcome": "authorization_denied"})
    );
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
    assert_eq!(body, json!({"outcome": "authorization_denied"}));
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
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
