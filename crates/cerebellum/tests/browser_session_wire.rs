use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum::browser::Tracker;
use cerebellum::browser_session::{
    BrowserSessionLauncher, CleanupStage, NavigationDriveError, NavigationWait,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup,
};
use cerebellum::{BrowserConfig, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
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

#[derive(Default)]
struct RecordingLauncher {
    launches: Arc<Mutex<usize>>,
    effects: Arc<Mutex<Vec<&'static str>>>,
}

impl BrowserSessionLauncher for RecordingLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<(Box<dyn OwnedBrowserProcess>, Box<dyn SessionCleanup>), Value> {
        *self.launches.lock().unwrap() += 1;
        Ok((
            Box::new(RecordingProcess {
                effects: Arc::clone(&self.effects),
            }),
            Box::new(RecordingCleanup {
                effects: Arc::clone(&self.effects),
            }),
        ))
    }
}

struct RecoveryFailedLauncher;

impl BrowserSessionLauncher for RecoveryFailedLauncher {
    fn launch(
        &self,
        _: &cerebellum_core::identity::AcceptedBindFacts,
        _: &str,
    ) -> Result<(Box<dyn OwnedBrowserProcess>, Box<dyn SessionCleanup>), Value> {
        Err(json!({
            "outcome": "internal_failure",
            "reason_code": "browser_launch_recovery_failed",
        }))
    }
}

struct RecordingProcess {
    effects: Arc<Mutex<Vec<&'static str>>>,
}

impl OwnedBrowserProcess for RecordingProcess {
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
    fn after_reap(&mut self) -> Result<(), CleanupStage> {
        self.effects.lock().unwrap().push("cleanup");
        Ok(())
    }
}

#[test]
fn real_manifest_path_advertises_session_controls_and_navigation_only_when_configured() {
    fn names(configured: bool) -> Vec<String> {
        let manifest =
            cerebellum::serialize_manifest_with_browser_configuration("cerebellum", configured);
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
            .collect()
    }

    let configured = names(true);
    for dispatchable in [
        "browser.launch",
        "browser.status",
        "browser.close",
        "browser.navigate",
    ] {
        assert!(configured.iter().any(|name| name == dispatchable));
    }
    for unavailable in [
        "browser.click",
        "browser.click_point",
        "browser.snapshot",
        "browser.screenshot",
        "browser.wait_for",
        "browser.type",
    ] {
        assert!(!configured.iter().any(|name| name == unavailable));
    }
    let absent = names(false);
    for configured_only in ["browser.launch", "browser.close", "browser.navigate"] {
        assert!(!absent.iter().any(|name| name == configured_only));
    }
}

#[tokio::test]
async fn wire_launch_reaches_ready_refuses_a_duplicate_and_closes_after_reap() {
    let launcher = Arc::new(RecordingLauncher::default());
    let mut planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
    planes.launch_service = Some(launcher.clone());

    let launched = invoke(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(launched.header.ty, FrameType::Response);
    let launched: Value = serde_json::from_slice(&launched.body).unwrap();
    assert_eq!(launched["outcome"], "launched");
    assert_eq!(launched["profile_disposition"], "durable");
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

    for (corr, unavailable) in [
        (12, "browser.click"),
        (13, "browser.click_point"),
        (14, "browser.snapshot"),
        (15, "browser.screenshot"),
        (16, "browser.wait_for"),
        (17, "browser.type"),
    ] {
        let refused = invoke(&planes, corr, unavailable, json!({})).await;
        let refused: Value = serde_json::from_slice(&refused.body).unwrap();
        assert_eq!(refused["code"], "unknown_method", "{refused}");
    }
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
async fn failed_startup_recovery_refuses_launch_while_health_stays_answerable() {
    let mut planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
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
    let mut planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
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
    let planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
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
    let mut planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
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
    let mut planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
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
    let mut planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config()));
    planes.launch_service = Some(launcher.clone());
    cerebellum::install_browser_compatibility_test_bind(&planes.routes, 9, 3);

    let response = invoke_existing(&planes, 1, "browser.launch", json!({})).await;
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body, json!({"outcome": "authorization_denied"}));
    assert_eq!(*launcher.launches.lock().unwrap(), 0);
}

#[tokio::test]
async fn absent_browser_config_uses_the_route_level_unknown_method_envelope() {
    let planes = Planes::with_browser_config(Arc::new(HealthState::new()), None);
    let response = invoke(&planes, 1, "browser.launch", json!({})).await;
    assert_eq!(response.header.ty, FrameType::Error);
    let error: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(error.code, "unknown_method");
    assert_eq!(
        planes.sessions.status(
            "test-session",
            planes.lease_clock.as_ref(),
            std::time::SystemTime::UNIX_EPOCH,
        )["outcome"],
        "no_session"
    );
}
