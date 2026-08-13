use std::sync::Arc;
use std::time::{Duration, Instant};

use cerebellum::browser::navigation::BrowserSnapshotObservation;
use cerebellum::browser::{self, BrowserCapability, BrowserPlane, Tracker};
use cerebellum::browser_session::{
    BrowserClickPosition, BrowserInputEvent, BrowserSessions, CleanupStage, ClickDriveError,
    LaunchSlot, NavigationDriveError, NavigationWait, OwnedBrowserProcess, ProcessControlFailure,
    SessionCleanup,
};
use cerebellum::cdp::{Attachment, CdpTransport, IdentityMap};
use cerebellum::coordinate::{ScreenshotPayload, TransformInputs, ViewportObservation};
use cerebellum::snapshot_store::{
    AxRecord, BackendNodeIdentity, RefRecord, SnapshotKind, SnapshotRef,
};
use cerebellum::{BrowserConfig, RouteIdentity};
use cerebellum_core::clock::SystemClock;
use serde_json::{json, Value};

fn identity() -> RouteIdentity {
    RouteIdentity::from_bind(
        &subc_protocol::BindIdentity {
            project_root: "/tmp/b1-s3".into(),
            harness: "test".into(),
            session: "b1-s3-session".into(),
        },
        &Some(subc_protocol::Principal::Direct),
    )
}

/// A click whose coordinates came from a differently-sized copy is refused.
///
/// The endpoint that shows a screenshot to a model downscales it first, so the
/// coordinates it reports index that smaller copy. They still land inside the
/// image retained here, which is why nothing downstream objects: the transform
/// validates and the click actuates somewhere the caller never chose.
///
/// Driven through the dispatch surface rather than the mapping helper, because
/// what matters is that no click is dispatched. A check that computed the
/// mismatch correctly and then proceeded would satisfy an assertion about the
/// returned value alone.
#[tokio::test]
async fn a_click_addressing_a_differently_sized_image_is_refused_before_dispatch() {
    const ONE_BY_ONE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";

    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();

    // The context's own epoch, so the snapshot is not refused as stale before
    // the check under test is reached.
    let view = ViewportObservation::new(
        0,
        TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
    );
    let retained = plane
        .retain_screenshot(
            &route,
            ScreenshotPayload::new(ONE_BY_ONE_PNG_B64, 1, 1),
            view,
            view,
            false,
        )
        .await
        .expect("a coherent screenshot is retained");
    let snapshot_id = retained["snapshot_id"]
        .as_str()
        .expect("the retained screenshot carries its id")
        .to_string();

    // Reserving and rejecting a request are themselves logged, so the fence is
    // the absence of INPUT rather than the absence of activity.
    fn input_operations(log: &[(String, browser::Operation)]) -> usize {
        log.iter()
            .filter(|(_, operation)| {
                matches!(
                    operation,
                    browser::Operation::CdpInputPress
                        | browser::Operation::CdpInputRelease
                        | browser::Operation::CommitDispatched
                )
            })
            .count()
    }
    let input_before = input_operations(&plane.operation_log().await);

    // The only pixel that exists, addressed as though the image were larger:
    // the shape a model-reported coordinate takes after a server-side resize.
    let refusal = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &json!({
                "snapshot_id": snapshot_id,
                "x_px": 0,
                "y_px": 0,
                "image_width_px": 2,
                "image_height_px": 2,
                "intent": "press what the model saw",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    // dispatch answers with a body rather than a Result, so the refusal is read
    // from the outcome it reports.
    assert_eq!(
        refusal["detail"]["reason_code"], "image_size_mismatch",
        "refused for an unrelated reason: {refusal}"
    );
    assert_eq!(
        input_operations(&plane.operation_log().await),
        input_before,
        "the refusal committed or actuated a click anyway"
    );
}

#[tokio::test]
async fn composed_routes_omit_browser_type_and_click_uses_one_lane() {
    assert_eq!(browser::ALL_TOOLS.len(), 6);
    assert!(!browser::ALL_TOOLS.contains(&"browser.type"));
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();
    let reference = SnapshotRef::new("e1", "button", "Save", 0).unwrap();
    plane
        .retain_text_snapshot(
            &route,
            SnapshotKind::Ax,
            &[AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Save".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            None,
            vec![RefRecord {
                captured: reference,
                frame_path: vec![],
                backend_identity: None,
                raw_role: None,
                raw_name: None,
            }],
            4096,
        )
        .await
        .unwrap();
    let snapshot_id = plane
        .retain_text_snapshot(
            &route,
            SnapshotKind::DomFull,
            &[],
            Some("body"),
            vec![],
            4096,
        )
        .await
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_string();
    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &json!({
                "ref": "e1",
                "snapshot_id": snapshot_id,
                "intent": "click",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(result["outcome"], "ref_not_found");
    let operations = plane.operation_log().await;
    assert!(operations
        .iter()
        .all(|(_, operation)| *operation != browser::Operation::CdpInputPress));
}

struct NoopCleanup;

impl SessionCleanup for NoopCleanup {
    fn after_reap(&mut self) -> Result<(), CleanupStage> {
        Ok(())
    }
}

fn plane_with_process(
    route: &RouteIdentity,
    process: Box<dyn OwnedBrowserProcess>,
    navigation_settle_deadline_ms: u64,
) -> BrowserPlane {
    let sessions = BrowserSessions::default();
    let acquired_id = match sessions.acquire_launch_slot(&route.conversation_key) {
        LaunchSlot::Acquired { browser_session_id } => browser_session_id,
        LaunchSlot::Occupied { browser_session_id } => {
            panic!("unexpected occupied launch slot {browser_session_id}")
        }
    };
    let clock = Arc::new(SystemClock::new());
    let config = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms,
    };
    let Some((browser_session_id, _, cancelled)) = sessions.establish_ready(
        &route.conversation_key,
        route.profile_disposition,
        &config,
        clock.as_ref(),
        process,
        Box::new(NoopCleanup),
    ) else {
        panic!("the acquired launch slot did not accept a ready process");
    };
    assert_eq!(browser_session_id, acquired_id);
    assert!(!cancelled);
    BrowserPlane::with_session_gate(sessions, clock, navigation_settle_deadline_ms)
}

#[derive(Clone)]
struct SnapshotProcess {
    observation: BrowserSnapshotObservation,
}

impl OwnedBrowserProcess for SnapshotProcess {
    fn snapshot(
        &mut self,
        _: &str,
        _: SnapshotKind,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        Ok(self.observation.clone())
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

#[derive(Clone)]
struct ClickProcess {
    result: Result<BrowserClickPosition, ClickDriveError>,
    input_events: Arc<std::sync::Mutex<Vec<BrowserInputEvent>>>,
}

impl OwnedBrowserProcess for ClickProcess {
    fn click(
        &mut self,
        _: &str,
        _: &BackendNodeIdentity,
        _: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickPosition, ClickDriveError> {
        let position = self.result?;
        for event in [
            BrowserInputEvent::Press(position),
            BrowserInputEvent::Release(position),
        ] {
            self.input_events.lock().unwrap().push(event);
            input_dispatched(event);
        }
        Ok(position)
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

fn snapshot_observation(records: Vec<AxRecord>) -> BrowserSnapshotObservation {
    let refs = records
        .iter()
        .filter_map(|record| {
            let reference = record.reference.as_ref()?;
            Some(RefRecord {
                captured: SnapshotRef::new(reference, record.role.clone(), record.name.clone(), 0)
                    .unwrap(),
                frame_path: vec!["frame-main".into()],
                backend_identity: Some(
                    BackendNodeIdentity::new(
                        "target-own",
                        "frame-main",
                        reference.trim_start_matches('e').parse::<u64>().unwrap() + 10,
                    )
                    .unwrap(),
                ),
                raw_role: Some(record.role.clone()),
                raw_name: Some(record.name.clone()),
            })
        })
        .collect();
    BrowserSnapshotObservation {
        records,
        dom_text: None,
        refs,
        ax_truncated: false,
        refs_truncated: false,
    }
}

#[tokio::test]
async fn snapshot_without_a_ready_session_refuses_before_transport_observation() {
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Snapshot,
            &json!({"mode": "ax", "max_bytes": 4096}),
        )
        .await;

    assert_eq!(result["outcome"], "no_session");
    assert_eq!(result["detail"]["reason_code"], "no_session");
    assert_eq!(result["detail"]["reason"], "no browser session is open");
    assert!(plane.operation_log().await.is_empty());
}

#[tokio::test]
async fn snapshot_returns_the_named_page_structure_and_backend_refs() {
    let route = identity();
    let observation = snapshot_observation(vec![
        AxRecord {
            depth: 0,
            role: "RootWebArea".into(),
            name: "Structured fixture".into(),
            value: None,
            reference: Some("e1".into()),
        },
        AxRecord {
            depth: 1,
            role: "heading".into(),
            name: "Account details".into(),
            value: None,
            reference: Some("e2".into()),
        },
        AxRecord {
            depth: 1,
            role: "button".into(),
            name: "Save profile".into(),
            value: None,
            reference: Some("e3".into()),
        },
    ]);
    let plane = plane_with_process(&route, Box::new(SnapshotProcess { observation }), 1_000);
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Snapshot,
            &json!({"mode": "ax", "max_bytes": 4096}),
        )
        .await;

    assert_eq!(result["outcome"], "ok");
    let records = result["content"]
        .as_str()
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(records[1]["role"], "heading");
    assert_eq!(records[1]["name"], "Account details");
    assert_eq!(records[2]["role"], "button");
    assert_eq!(records[2]["name"], "Save profile");
    assert_eq!(result["refs"][2]["ref"], "e3");
    assert_eq!(result["refs"][2]["name"], "Save profile");
    assert_eq!(result["truncated"], false);
    assert_eq!(result["refs_truncated"], false);

    let operations = plane.operation_log().await;
    let committed = operations
        .iter()
        .position(|(_, operation)| *operation == browser::Operation::CommitDispatched)
        .unwrap();
    let observed = operations
        .iter()
        .position(|(_, operation)| *operation == browser::Operation::CdpObserve)
        .unwrap();
    assert!(committed < observed, "{operations:?}");
}

#[tokio::test]
async fn max_bytes_and_lossy_traversal_each_report_honest_incompleteness() {
    let route = identity();
    let records = vec![
        AxRecord {
            depth: 0,
            role: "RootWebArea".into(),
            name: "Large fixture".into(),
            value: None,
            reference: Some("e1".into()),
        },
        AxRecord {
            depth: 1,
            role: "heading".into(),
            name: "This record exceeds the remaining output budget".into(),
            value: None,
            reference: Some("e2".into()),
        },
    ];
    let first_line = records[0].canonical_line().unwrap();
    let plane = plane_with_process(
        &route,
        Box::new(SnapshotProcess {
            observation: snapshot_observation(records),
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Snapshot,
            &json!({"mode": "ax", "max_bytes": first_line.len()}),
        )
        .await;

    assert_eq!(result["truncated"], true);
    assert_eq!(result["content"], first_line);
    for line in result["content"].as_str().unwrap().lines() {
        let parsed: Value = serde_json::from_str(line).unwrap();
        assert!(parsed.get("role").is_some());
        assert!(parsed.get("name").is_some());
    }

    let route = identity();
    let mut observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "RootWebArea".into(),
        name: "Traversal stopped".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    observation.ax_truncated = true;
    observation.refs_truncated = true;
    let plane = plane_with_process(&route, Box::new(SnapshotProcess { observation }), 1_000);
    plane.open_context(route.clone()).await.unwrap();
    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Snapshot,
            &json!({"mode": "ax", "max_bytes": 4096}),
        )
        .await;
    assert_eq!(result["truncated"], true);
    assert_eq!(result["refs_truncated"], true);
}

struct RedirectingNavigationProcess;

impl OwnedBrowserProcess for RedirectingNavigationProcess {
    fn navigate(
        &mut self,
        _: &str,
        _: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let now = Instant::now();
        tracker.url_final = Some("https://landed.example/final".into());
        tracker.load(now);
        tracker.poll_settlement(now + Duration::from_millis(browser::QUIET_MS));
        Ok(())
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

struct UnsettledNavigationProcess;

impl OwnedBrowserProcess for UnsettledNavigationProcess {
    fn navigate(
        &mut self,
        _: &str,
        _: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        tracker.load(Instant::now());
        Ok(())
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

#[tokio::test]
async fn navigation_without_a_ready_session_refuses_before_commit_or_transport() {
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open a page",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "no_session");
    assert_eq!(result["detail"]["reason_code"], "no_session");
    assert_eq!(result["detail"]["reason"], "no browser session is open");
    assert!(plane.operation_log().await.is_empty());
}

#[tokio::test]
async fn navigation_while_launch_is_pending_still_names_no_open_session() {
    let route = identity();
    let sessions = BrowserSessions::default();
    match sessions.acquire_launch_slot(&route.conversation_key) {
        LaunchSlot::Acquired { .. } => {}
        LaunchSlot::Occupied { browser_session_id } => {
            panic!("unexpected occupied launch slot {browser_session_id}")
        }
    }
    let plane = BrowserPlane::with_session_gate(sessions, Arc::new(SystemClock::new()), 100);
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open a page",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "no_session");
    assert_eq!(result["detail"]["reason"], "no browser session is open");
    assert!(plane.operation_log().await.is_empty());
}

#[tokio::test]
async fn navigation_reports_the_browser_landing_url_instead_of_the_request() {
    let route = identity();
    let plane = plane_with_process(&route, Box::new(RedirectingNavigationProcess), 100);
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "follow the redirect",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "ok");
    assert_eq!(result["url_final"], "https://landed.example/final");
    assert_eq!(
        result["lifecycle"],
        json!(["navigation_started", "load", "network_quiet"])
    );
    let operations = plane.operation_log().await;
    let committed = operations
        .iter()
        .position(|(_, operation)| *operation == browser::Operation::CommitDispatched)
        .expect("navigation records a dispatch commitment");
    let navigated = operations
        .iter()
        .position(|(_, operation)| *operation == browser::Operation::CdpNavigate)
        .expect("navigation reaches the driver");
    assert!(committed < navigated, "{operations:?}");
}

#[tokio::test]
async fn unsettled_navigation_returns_the_observed_tokens() {
    let route = identity();
    let plane = plane_with_process(&route, Box::new(UnsettledNavigationProcess), 10);
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open a page that stays busy",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "not_settled");
    assert_eq!(result["url_final"], Value::Null);
    assert_eq!(result["lifecycle"], json!(["navigation_started", "load"]));
}

#[test]
fn cdp_correlation_and_attachment_are_fail_closed() {
    let now = Instant::now();
    let mut transport = CdpTransport::new();
    let command = transport
        .issue_command("Page.enable", None, Some("s1".into()), now)
        .unwrap();
    let response =
        serde_json::to_vec(&json!({"id": command.id, "sessionId": "s1", "result": {}})).unwrap();
    assert!(transport.take_response(&response).unwrap().result.is_some());

    let mut identities = IdentityMap::new();
    identities
        .attach(Attachment {
            target_id: "t1".into(),
            session_id: "s1".into(),
            frame_ids: vec!["f1".into()],
            context_key: "ctx".into(),
        })
        .unwrap();
    assert_eq!(
        identities.context_for("t1", "s1", Some("f1")).unwrap(),
        "ctx"
    );
    assert!(identities.detach("t1", "s1").is_ok());
}

/// The per-context dispatch lane is what keeps one invocation's CDP operations
/// from interleaving with another's verification bracket.  This asserts the
/// mutual exclusion directly: two concurrent dispatches on the SAME context must
/// not overlap, while two on DIFFERENT contexts may.
///
/// Without it, replacing the shared per-context lane with a fresh lock per call
/// leaves the suite green — the ordering property has no other witness.
#[tokio::test]
async fn same_context_dispatches_serialize_and_different_contexts_do_not() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    let plane = StdArc::new(BrowserPlane::new());
    let route_a = identity();
    let mut route_b = identity();
    route_b.conversation_key = "conv-b".to_string();
    plane.open_context(route_a.clone()).await.unwrap();
    plane.open_context(route_b.clone()).await.unwrap();

    // Concurrency observed while holding the same context's lane must never
    // exceed one.
    let peak = StdArc::new(AtomicUsize::new(0));
    let live = StdArc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..8 {
        let plane = StdArc::clone(&plane);
        let route = route_a.clone();
        let peak = StdArc::clone(&peak);
        let live = StdArc::clone(&live);
        handles.push(tokio::spawn(async move {
            let _guard = plane.lane_for_test(&route.conversation_key).await;
            let now = live.fetch_add(1, Ordering::SeqCst) + 1;
            peak.fetch_max(now, Ordering::SeqCst);
            tokio::task::yield_now().await;
            live.fetch_sub(1, Ordering::SeqCst);
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }
    assert_eq!(
        peak.load(Ordering::SeqCst),
        1,
        "two dispatches held the same context lane at once"
    );

    // Two different contexts are independent: holding A's lane must not block B.
    let guard_a = plane.lane_for_test(&route_a.conversation_key).await;
    let guard_b = tokio::time::timeout(
        std::time::Duration::from_millis(250),
        plane.lane_for_test(&route_b.conversation_key),
    )
    .await
    .expect("a different context must not block on another context's lane");
    drop(guard_b);
    drop(guard_a);
}

async fn retain_click_snapshot(plane: &BrowserPlane, route: &RouteIdentity) -> String {
    let reference = SnapshotRef::new("e1", "button", "Save", 0).unwrap();
    plane
        .retain_text_snapshot(
            route,
            SnapshotKind::Ax,
            &[AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Save".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            None,
            vec![RefRecord {
                captured: reference,
                frame_path: vec!["frame-main".into()],
                backend_identity: Some(
                    BackendNodeIdentity::new("target-own", "frame-main", 42).unwrap(),
                ),
                raw_role: Some("button".into()),
                raw_name: Some("Save".into()),
            }],
            4096,
        )
        .await
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn click_arguments(snapshot_id: &str) -> Value {
    json!({
        "ref": "e1",
        "snapshot_id": snapshot_id,
        "intent": "click",
        "severity": {"tier": 2, "credential": false, "financial": false}
    })
}

#[tokio::test]
async fn a_click_presses_before_it_releases_and_only_after_commitment() {
    let route = identity();
    let input_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let position = BrowserClickPosition {
        x_css: 22.0,
        y_css: 36.0,
    };
    let plane = plane_with_process(
        &route,
        Box::new(ClickProcess {
            result: Ok(position),
            input_events: Arc::clone(&input_events),
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    let snapshot_id = retain_click_snapshot(&plane, &route).await;

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &click_arguments(&snapshot_id),
        )
        .await;

    assert_eq!(result["outcome"], "ok");
    assert_eq!(
        *input_events.lock().unwrap(),
        vec![
            BrowserInputEvent::Press(position),
            BrowserInputEvent::Release(position),
        ]
    );
    let operations: Vec<browser::Operation> = plane
        .operation_log()
        .await
        .into_iter()
        .map(|(_, operation)| operation)
        .collect();
    let position = |wanted: browser::Operation| {
        operations
            .iter()
            .position(|operation| *operation == wanted)
            .unwrap_or_else(|| panic!("{wanted:?} was never recorded: {operations:?}"))
    };

    assert!(
        position(browser::Operation::CdpInputPress) < position(browser::Operation::CdpInputRelease),
        "a button is pressed before it is released: {operations:?}"
    );
    assert!(
        position(browser::Operation::CommitDispatched)
            < position(browser::Operation::CdpInputPress),
        "no input is dispatched before the journal commits to it: {operations:?}"
    );
    assert_eq!(
        plane
            .text_snapshot_pin_count_for_test(&route, &snapshot_id)
            .await,
        0
    );
}

#[tokio::test]
async fn a_click_without_a_resolvable_position_is_named_and_unpinned_without_input() {
    let route = identity();
    let input_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(
        &route,
        Box::new(ClickProcess {
            result: Err(ClickDriveError::NoPosition),
            input_events: Arc::clone(&input_events),
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    let snapshot_id = retain_click_snapshot(&plane, &route).await;

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &click_arguments(&snapshot_id),
        )
        .await;

    assert_eq!(result["outcome"], "element_intercepted");
    assert!(input_events.lock().unwrap().is_empty());
    let operations = plane.operation_log().await;
    assert!(operations.iter().all(|(_, operation)| !matches!(
        operation,
        browser::Operation::CdpInputPress | browser::Operation::CdpInputRelease
    )));
    assert_eq!(
        plane
            .text_snapshot_pin_count_for_test(&route, &snapshot_id)
            .await,
        0
    );
}

#[tokio::test]
async fn a_stale_text_snapshot_refuses_before_any_input_is_dispatched() {
    let route = identity();
    let input_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(
        &route,
        Box::new(ClickProcess {
            result: Ok(BrowserClickPosition {
                x_css: 22.0,
                y_css: 36.0,
            }),
            input_events: Arc::clone(&input_events),
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    let snapshot_id = retain_click_snapshot(&plane, &route).await;
    plane
        .replace_document(
            &route,
            cerebellum::snapshot_store::DocumentTransition::TopLevelDocumentReplaced,
        )
        .await
        .unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &click_arguments(&snapshot_id),
        )
        .await;

    assert_eq!(result["outcome"], "stale_snapshot");
    assert_eq!(result["detail"]["reason_code"], "snapshot_evicted");
    assert!(input_events.lock().unwrap().is_empty());
    assert!(plane.operation_log().await.iter().all(|(_, operation)| {
        !matches!(
            operation,
            browser::Operation::CdpInputPress | browser::Operation::CdpInputRelease
        )
    }));
    assert_eq!(
        plane
            .text_snapshot_pin_count_for_test(&route, &snapshot_id)
            .await,
        0
    );
}
