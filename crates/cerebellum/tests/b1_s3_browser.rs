use std::collections::VecDeque;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use cerebellum::authorization::{ActionGrant, GrantStore, HazardClass, Severity};
use cerebellum::browser::navigation::VISION_LONG_EDGE_PX;
use cerebellum::browser::navigation::{
    BrowserScreenshotObservation, BrowserSnapshotObservation, CdpNavigationDriver,
};
use cerebellum::browser::{self, BrowserCapability, BrowserPlane, SnapshotRefusalReason, Tracker};
use cerebellum::browser_launch_readiness::{CdpPipeIo, PipeRead};
use cerebellum::browser_session::{
    BrowserClickOutcome, BrowserClickPosition, BrowserInputEvent, BrowserSessions, CleanupStage,
    ClickDriveError, ClickPointDriveError, LaunchSlot, NavigationDriveError, NavigationWait,
    OwnedBrowserProcess, ProcessControlFailure, SessionCleanup, ViewportRefusal,
};
use cerebellum::cdp::{Attachment, CdpFrameDecoder, CdpTransport, IdentityMap};
use cerebellum::classification::ClassificationUnavailable;
use cerebellum::coordinate::{
    encode_base64, InputRect, ScreenshotPayload, TransformInputs, ViewportObservation,
};
use cerebellum::journal::Outcome;
use cerebellum::snapshot_store::{
    AxRecord, BackendNodeIdentity, RefRecord, SameDocumentChange, SnapshotKind, SnapshotRef,
};
use cerebellum::{BrowserConfig, RouteIdentity};
use cerebellum_core::clock::SystemClock;
use serde_json::{json, Value};

const ONE_BY_ONE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR4nGP4z8DwHwAFAAH/iZk9HQAAAABJRU5ErkJggg==";

fn identity() -> RouteIdentity {
    RouteIdentity::from_bind(
        &subc_protocol::BindIdentity::new("/tmp/b1-s3", "test", "b1-s3-session"),
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
                "snapshot_id": snapshot_id.clone(),
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
    assert_eq!(
        plane
            .snapshot_pin_count_for_test(&route, &snapshot_id)
            .await,
        0,
        "the refused coordinate click leaked its screenshot pin"
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
                classification: Err(ClassificationUnavailable::NotCaptured),
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
    fn after_reap(
        &mut self,
    ) -> Result<cerebellum::browser_session::SessionCleanupOutcome, CleanupStage> {
        Ok(cerebellum::browser_session::SessionCleanupOutcome::Complete)
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
        LaunchSlot::Refused(refusal) => panic!("unexpected launch slot refusal {refusal}"),
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
        .with_grants_installed(navigation_grants())
}

/// A grant covering this file's navigation conversation and origin.
///
/// The authorization gate always runs and an empty store covers nothing, so a
/// test about navigation behaviour must arrive holding the authority a real
/// caller would hold. Turning the gate off instead would make every one of
/// these tests pass over a plane that no longer resembles the shipped one.
fn navigation_grants() -> GrantStore {
    GrantStore::new([ActionGrant::new(
        "b1-s3-navigation-grant",
        1,
        identity().conversation_key.clone(),
        Severity {
            tier: 4,
            credential: true,
            financial: true,
        },
        ["https://requested.example"],
    )
    .with_disclosed_hazards([HazardClass::UnverifiedFormContents])])
}

fn screenshot_grants(origins: &[&str]) -> GrantStore {
    GrantStore::new([ActionGrant::new(
        "b1-s3-screenshot-grant",
        1,
        identity().conversation_key.clone(),
        Severity {
            tier: 1,
            credential: false,
            financial: false,
        },
        origins.iter().copied(),
    )])
}

#[derive(Clone)]
struct SnapshotProcess {
    observation: BrowserSnapshotObservation,
}

impl OwnedBrowserProcess for SnapshotProcess {
    fn navigate(
        &mut self,
        _: &str,
        _: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let now = Instant::now();
        tracker.url_final = Some("https://requested.example/landed".into());
        tracker.load(now);
        tracker.poll_settlement(now + Duration::from_millis(browser::QUIET_MS));
        Ok(())
    }

    fn snapshot(
        &mut self,
        _: &str,
        _: SnapshotKind,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        Ok(self.observation.clone())
    }

    fn click(
        &mut self,
        _: &str,
        _: &BackendNodeIdentity,
        _: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let position = BrowserClickPosition {
            x_css: 1.0,
            y_css: 1.0,
        };
        input_dispatched(BrowserInputEvent::Press(position));
        input_dispatched(BrowserInputEvent::Release(position));
        Ok(BrowserClickOutcome::Clicked(position))
    }

    fn click_classified(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        _: u64,
        _: &str,
        expected: Option<&cerebellum::classification::NonTypeClassificationRecord>,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        assert!(
            expected.is_none(),
            "this fixture represents an unverified target"
        );
        self.click(context_key, identity, deadline_ms, input_dispatched)
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

struct ScreenshotPipe {
    reads: VecDeque<Vec<u8>>,
}

impl ScreenshotPipe {
    fn with_frames(frames: impl IntoIterator<Item = Value>) -> Self {
        Self {
            reads: frames
                .into_iter()
                .map(|frame| {
                    let mut bytes = serde_json::to_vec(&frame).unwrap();
                    bytes.push(0);
                    bytes
                })
                .collect(),
        }
    }
}

impl CdpPipeIo for ScreenshotPipe {
    fn write_frame(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        let Some(bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(PipeRead::Bytes(bytes.len()))
    }
}

struct ScreenshotProcess {
    driver: CdpNavigationDriver<ScreenshotPipe>,
    captures: Arc<AtomicUsize>,
}

impl OwnedBrowserProcess for ScreenshotProcess {
    fn screenshot(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        self.captures.fetch_add(1, Ordering::SeqCst);
        self.driver
            .screenshot(context_key, document_epoch, deadline_ms, full)
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
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let position = self.result.clone()?;
        for event in [
            BrowserInputEvent::Press(position),
            BrowserInputEvent::Release(position),
        ] {
            self.input_events.lock().unwrap().push(event);
            input_dispatched(event);
        }
        Ok(BrowserClickOutcome::Clicked(position))
    }

    fn click_classified(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        _: u64,
        _: &str,
        expected: Option<&cerebellum::classification::NonTypeClassificationRecord>,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        assert!(
            expected.is_none(),
            "this fixture represents an unverified target"
        );
        self.click(context_key, identity, deadline_ms, input_dispatched)
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

struct RecordingClickPointPipe {
    commands: Arc<std::sync::Mutex<Vec<Value>>>,
    reads: VecDeque<Vec<u8>>,
}

impl RecordingClickPointPipe {
    fn new(commands: Arc<std::sync::Mutex<Vec<Value>>>) -> Self {
        let reads = [
            json!({"id":1,"result":{"targetId":"target-own"}}),
            json!({"id":2,"result":{"sessionId":"session-own"}}),
            json!({"id":3,"sessionId":"session-own","result":{
                "cssVisualViewport": {
                    "offsetX": 10.0,
                    "offsetY": 20.0,
                    "clientWidth": 100.0,
                    "clientHeight": 50.0,
                    "scale": 1.0
                },
                "visualViewport": {
                    "offsetX": 0.0,
                    "offsetY": 0.0,
                    "clientWidth": 40.0,
                    "clientHeight": 20.0,
                    "scale": 1.0
                }
            }}),
            json!({"id":4,"sessionId":"session-own","result":{}}),
            json!({"id":5,"sessionId":"session-own","result":{}}),
            json!({"id":6,"sessionId":"session-own","result":{}}),
        ]
        .into_iter()
        .map(|frame| {
            let mut bytes = serde_json::to_vec(&frame).unwrap();
            bytes.push(0);
            bytes
        })
        .collect();
        Self { commands, reads }
    }
}

impl CdpPipeIo for RecordingClickPointPipe {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        let command = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        self.commands.lock().unwrap().push(command);
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        let Some(bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(PipeRead::Bytes(bytes.len()))
    }
}

struct ClickPointProcess {
    driver: CdpNavigationDriver<RecordingClickPointPipe>,
}

impl OwnedBrowserProcess for ClickPointProcess {
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

struct NavigationPipe {
    reads: VecDeque<Vec<u8>>,
}

impl NavigationPipe {
    fn with_frames(frames: impl IntoIterator<Item = Value>) -> Self {
        Self {
            reads: frames
                .into_iter()
                .map(|frame| {
                    let mut bytes = serde_json::to_vec(&frame).unwrap();
                    bytes.push(0);
                    bytes
                })
                .collect(),
        }
    }
}

impl CdpPipeIo for NavigationPipe {
    fn write_frame(&mut self, _: &[u8]) -> io::Result<()> {
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        let Some(bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(PipeRead::Bytes(bytes.len()))
    }
}

struct CdpNavigationProcess {
    driver: CdpNavigationDriver<NavigationPipe>,
}

impl CdpNavigationProcess {
    fn with_frames(frames: impl IntoIterator<Item = Value>) -> Self {
        Self {
            driver: CdpNavigationDriver::new(
                NavigationPipe::with_frames(frames),
                CdpTransport::new(),
                CdpFrameDecoder::default(),
            ),
        }
    }
}

impl OwnedBrowserProcess for CdpNavigationProcess {
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

fn page_navigate_frames(
    events: impl IntoIterator<Item = Value>,
    navigate_result: Value,
) -> Vec<Value> {
    [
        json!({"id":1,"result":{"targetId":"target-own"}}),
        json!({"id":2,"result":{"sessionId":"session-own"}}),
        json!({"id":3,"sessionId":"session-own","result":{}}),
        json!({"id":4,"sessionId":"session-own","result":{}}),
    ]
    .into_iter()
    .chain(events)
    .chain(std::iter::once(
        json!({"id":5,"sessionId":"session-own","result":navigate_result}),
    ))
    .collect()
}

struct DialogClickPointPipe {
    commands: Arc<std::sync::Mutex<Vec<Value>>>,
    reads: VecDeque<Vec<u8>>,
    blocked_release_id: Option<u64>,
}

impl DialogClickPointPipe {
    fn new(commands: Arc<std::sync::Mutex<Vec<Value>>>) -> Self {
        Self {
            commands,
            reads: VecDeque::new(),
            blocked_release_id: None,
        }
    }

    fn queue(&mut self, frame: Value) {
        let mut bytes = serde_json::to_vec(&frame).unwrap();
        bytes.push(0);
        self.reads.push_back(bytes);
    }
}

impl CdpPipeIo for DialogClickPointPipe {
    fn write_frame(&mut self, bytes: &[u8]) -> io::Result<()> {
        let command: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        self.commands.lock().unwrap().push(command.clone());
        let id = command["id"].as_u64().unwrap();
        let method = command["method"].as_str().unwrap();
        match method {
            "Target.createTarget" => {
                self.queue(json!({"id":id,"result":{"targetId":"target-own"}}));
            }
            "Target.attachToTarget" => {
                self.queue(json!({"id":id,"result":{"sessionId":"session-own"}}));
            }
            "Page.getLayoutMetrics" => self.queue(json!({
                "id":id,
                "sessionId":"session-own",
                "result":{"cssVisualViewport":{
                    "offsetX":10.0,
                    "offsetY":20.0,
                    "clientWidth":100.0,
                    "clientHeight":50.0,
                    "scale":1.0
                }}
            })),
            "Input.dispatchMouseEvent"
                if command["params"]["type"] == Value::String("mousePressed".into()) =>
            {
                self.queue(json!({"id":id,"sessionId":"session-own","result":{}}));
            }
            "Input.dispatchMouseEvent" => {
                self.blocked_release_id = Some(id);
                self.queue(json!({
                    "method":"Page.javascriptDialogOpening",
                    "sessionId":"session-own",
                    "params":{
                        "type":"confirm",
                        "message":"continue?",
                        "url":"https://requested.example/page",
                        "hasBrowserHandler":false
                    }
                }));
            }
            "Page.handleJavaScriptDialog" => {
                assert_eq!(command["params"]["accept"], false);
                assert!(command["params"].get("promptText").is_none());
                let release_id = self
                    .blocked_release_id
                    .take()
                    .expect("the dialog handler follows a blocked release");
                // Chromium may acknowledge the release before the nested dialog
                // command. Preserve that response for the outer correlator.
                self.queue(json!({"id":release_id,"sessionId":"session-own","result":{}}));
                self.queue(json!({"id":id,"sessionId":"session-own","result":{}}));
            }
            "Page.enable" | "Network.enable" | "Page.navigate" => {
                self.queue(json!({"id":id,"sessionId":"session-own","result":{}}));
            }
            other => panic!("unexpected CDP command {other}: {command}"),
        }
        Ok(())
    }

    fn read(&mut self, destination: &mut [u8]) -> io::Result<PipeRead> {
        let Some(bytes) = self.reads.pop_front() else {
            return Ok(PipeRead::WouldBlock);
        };
        destination[..bytes.len()].copy_from_slice(&bytes);
        Ok(PipeRead::Bytes(bytes.len()))
    }
}

struct DialogClickPointProcess {
    driver: CdpNavigationDriver<DialogClickPointPipe>,
}

impl OwnedBrowserProcess for DialogClickPointProcess {
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

struct RefusingClickPointProcess {
    refusal: ViewportRefusal,
}

impl OwnedBrowserProcess for RefusingClickPointProcess {
    fn click_point(
        &mut self,
        _: &str,
        _: BrowserClickPosition,
        _: u64,
        _: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        Err(ClickPointDriveError::OutsideViewport(self.refusal))
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

fn click_point_process(commands: Arc<std::sync::Mutex<Vec<Value>>>) -> ClickPointProcess {
    ClickPointProcess {
        driver: CdpNavigationDriver::new(
            RecordingClickPointPipe::new(commands),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        ),
    }
}

fn dialog_click_point_process(
    commands: Arc<std::sync::Mutex<Vec<Value>>>,
) -> DialogClickPointProcess {
    DialogClickPointProcess {
        driver: CdpNavigationDriver::new(
            DialogClickPointPipe::new(commands),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        ),
    }
}

fn screenshot_process(captures: Arc<AtomicUsize>) -> ScreenshotProcess {
    let viewport = json!({
        "offsetX": 3.5,
        "offsetY": 4.25,
        "clientWidth": 40.0,
        "clientHeight": 20.0,
        "scale": 1.75
    });
    // Both viewport fields, carrying DIFFERENT numbers, as a real browser does
    // on a scaled display: the undecorated `visualViewport` is deprecated and
    // reports device pixels. A fixture supplying only one cannot tell which is
    // read, and reading the deprecated one produces a plausible-looking
    // viewport whose pixel-to-css mapping is the identity.
    let device_viewport = json!({
        "offsetX": 7.0,
        "offsetY": 8.5,
        "clientWidth": 80.0,
        "clientHeight": 40.0,
        "scale": 1.75
    });
    let metrics = json!({
        "cssVisualViewport": viewport,
        "visualViewport": device_viewport,
    });
    let frames = [
        json!({"id":1,"result":{"targetId":"target-own"}}),
        json!({"id":2,"result":{"sessionId":"session-own"}}),
        json!({"id":3,"sessionId":"session-own","result":metrics.clone()}),
        json!({"id":4,"sessionId":"session-own","result":{"result":{"type":"number","value":2.25}}}),
        json!({"id":5,"sessionId":"session-own","result":{"data":ONE_BY_ONE_PNG_B64}}),
        json!({"id":6,"sessionId":"session-own","result":metrics.clone()}),
        json!({"id":7,"sessionId":"session-own","result":{"result":{"type":"number","value":2.25}}}),
        json!({"id":8,"sessionId":"session-own","result":metrics}),
        json!({"id":9,"sessionId":"session-own","result":{}}),
        json!({"id":10,"sessionId":"session-own","result":{}}),
        json!({"id":11,"sessionId":"session-own","result":{}}),
    ];
    ScreenshotProcess {
        driver: CdpNavigationDriver::new(
            ScreenshotPipe::with_frames(frames),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        ),
        captures,
    }
}

fn png_crc32(bytes: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn png_b64_claiming_dimensions(width: u32, height: u32) -> String {
    // The 1x1 fixture is a valid PNG; only IHDR width/height (and that chunk's
    // CRC) change. Pixel payload is not inflated during admission, so this is
    // enough for a reply that must name these dimensions rather than the
    // viewport's.
    const ONE_BY_ONE_PNG_BYTES: &[u8] = &[
        137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13, 73, 72, 68, 82, 0, 0, 0, 1, 0, 0, 0, 1, 8, 6,
        0, 0, 0, 31, 21, 196, 137, 0, 0, 0, 13, 73, 68, 65, 84, 120, 156, 99, 248, 207, 192, 240,
        31, 0, 5, 0, 1, 255, 137, 153, 61, 29, 0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130,
    ];
    let mut bytes = ONE_BY_ONE_PNG_BYTES.to_vec();
    bytes[16..20].copy_from_slice(&width.to_be_bytes());
    bytes[20..24].copy_from_slice(&height.to_be_bytes());
    let crc = png_crc32(&bytes[12..29]);
    bytes[29..33].copy_from_slice(&crc.to_be_bytes());
    encode_base64(&bytes)
}

fn screenshot_process_with_capture(
    captures: Arc<AtomicUsize>,
    css_width: f64,
    css_height: f64,
    dpr: f64,
    png_b64: &str,
) -> ScreenshotProcess {
    let viewport = json!({
        "offsetX": 3.5,
        "offsetY": 4.25,
        "pageX": 40.0,
        "pageY": 80.0,
        "clientWidth": css_width,
        "clientHeight": css_height,
        "scale": 1.0
    });
    let device_viewport = json!({
        "offsetX": 7.0,
        "offsetY": 8.5,
        "pageX": 80.0,
        "pageY": 160.0,
        "clientWidth": css_width * 2.0,
        "clientHeight": css_height * 2.0,
        "scale": 1.0
    });
    let metrics = json!({
        "cssVisualViewport": viewport,
        "visualViewport": device_viewport,
    });
    let frames = [
        json!({"id":1,"result":{"targetId":"target-own"}}),
        json!({"id":2,"result":{"sessionId":"session-own"}}),
        json!({"id":3,"sessionId":"session-own","result":metrics.clone()}),
        json!({"id":4,"sessionId":"session-own","result":{"result":{"type":"number","value":dpr}}}),
        json!({"id":5,"sessionId":"session-own","result":{"data":png_b64}}),
        json!({"id":6,"sessionId":"session-own","result":metrics.clone()}),
        json!({"id":7,"sessionId":"session-own","result":{"result":{"type":"number","value":dpr}}}),
        json!({"id":8,"sessionId":"session-own","result":metrics}),
        json!({"id":9,"sessionId":"session-own","result":{}}),
        json!({"id":10,"sessionId":"session-own","result":{}}),
        json!({"id":11,"sessionId":"session-own","result":{}}),
    ];
    ScreenshotProcess {
        driver: CdpNavigationDriver::new(
            ScreenshotPipe::with_frames(frames),
            CdpTransport::new(),
            CdpFrameDecoder::default(),
        ),
        captures,
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
                classification: Err(ClassificationUnavailable::NotCaptured),
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

async fn position_on_authorized_page(plane: &BrowserPlane, route: &RouteIdentity) {
    plane
        .same_document_url(
            route,
            "https://requested.example/page",
            SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();
}

async fn retain_click_point_snapshot(plane: &BrowserPlane, route: &RouteIdentity) -> String {
    let viewport = ViewportObservation::new(
        0,
        TransformInputs::from_values(10.0, 20.0, 100.0, 50.0, 1.0, 1.0),
    );
    plane
        .retain_screenshot(
            route,
            ScreenshotPayload::new(ONE_BY_ONE_PNG_B64, 1, 1),
            viewport,
            viewport,
            false,
        )
        .await
        .unwrap()["snapshot_id"]
        .as_str()
        .unwrap()
        .to_string()
}

fn click_point_arguments(snapshot_id: &str) -> Value {
    json!({
        "snapshot_id": snapshot_id,
        "x_px": 0,
        "y_px": 0,
        "image_width_px": 1,
        "image_height_px": 1,
        "intent": "click the retained image point",
        "severity": {"tier": 2, "credential": false, "financial": false}
    })
}

#[tokio::test]
async fn click_point_handler_dispatches_press_then_release_to_the_cdp_driver() {
    let route = identity();
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(
        &route,
        Box::new(click_point_process(Arc::clone(&commands))),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let snapshot_id = retain_click_point_snapshot(&plane, &route).await;

    let _response = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &click_point_arguments(&snapshot_id),
        )
        .await;

    let commands = commands.lock().unwrap().clone();
    let methods: Vec<&str> = commands
        .iter()
        .map(|command| command["method"].as_str().unwrap())
        .collect();
    assert_eq!(
        methods,
        [
            "Target.createTarget",
            "Target.attachToTarget",
            "Page.getLayoutMetrics",
            "Page.enable",
            "Input.dispatchMouseEvent",
            "Input.dispatchMouseEvent",
        ]
    );
    assert_eq!(commands[4]["params"]["type"], "mousePressed");
    assert_eq!(commands[4]["params"]["x"], 60.0);
    assert_eq!(commands[4]["params"]["y"], 45.0);
    assert_eq!(commands[5]["params"]["type"], "mouseReleased");
    assert_eq!(commands[5]["params"]["x"], 60.0);
    assert_eq!(commands[5]["params"]["y"], 45.0);
    assert_eq!(
        plane
            .snapshot_pin_count_for_test(&route, &snapshot_id)
            .await,
        0,
        "the successful coordinate click leaked its screenshot pin"
    );
}

#[tokio::test]
async fn a_confirming_click_is_dismissed_reported_journaled_and_leaves_the_session_usable() {
    let route = identity();
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(
        &route,
        Box::new(dialog_click_point_process(Arc::clone(&commands))),
        1_000,
    )
    .with_in_memory_journal(cerebellum::journal::JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    });
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let snapshot_id = retain_click_point_snapshot(&plane, &route).await;

    let click = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &click_point_arguments(&snapshot_id),
        )
        .await;

    assert_eq!(click["outcome"], "javascript_dialog_dismissed", "{click}");
    assert_eq!(click["dialogs"][0]["dialog_type"], "confirm", "{click}");
    assert_eq!(click["dialogs"][0]["response"], "dismissed", "{click}");

    let navigation = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/after-dialog",
                "intent": "prove the same browser session remains usable",
                "wait": "none",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(navigation["outcome"], "ok", "{navigation}");

    let commands = commands.lock().unwrap().clone();
    let methods = commands
        .iter()
        .map(|command| command["method"].as_str().unwrap())
        .collect::<Vec<_>>();
    let page_enable = methods
        .iter()
        .position(|method| *method == "Page.enable")
        .unwrap();
    let first_input = methods
        .iter()
        .position(|method| *method == "Input.dispatchMouseEvent")
        .unwrap();
    assert!(
        page_enable < first_input,
        "dialog events were armed too late: {methods:?}"
    );
    assert_eq!(
        methods
            .iter()
            .filter(|method| **method == "Page.handleJavaScriptDialog")
            .count(),
        1,
        "the confirm was not answered exactly once: {methods:?}"
    );

    let export = plane.journal_export_for_test().await;
    let click_record = export
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|entry| entry["capability"] == "browser.click_point")
        .unwrap_or_else(|| panic!("the click record is missing from the journal: {export}"));
    assert_eq!(click_record["outcome"], "success", "{click_record}");
    assert_eq!(
        click_record["detail"]["outcome"], "javascript_dialog_dismissed",
        "{click_record}"
    );
    assert_eq!(
        click_record["detail"]["dialogs"][0],
        json!({"dialog_type":"confirm","response":"dismissed"}),
        "{click_record}"
    );
}

#[tokio::test]
async fn click_point_outside_the_current_viewport_is_typed_and_dispatches_nothing() {
    let route = identity();
    let position = BrowserClickPosition {
        x_css: 60.0,
        y_css: 45.0,
    };
    let viewport = InputRect::new(0.0, 0.0, 40.0, 20.0);
    let plane = plane_with_process(
        &route,
        Box::new(RefusingClickPointProcess {
            refusal: ViewportRefusal { position, viewport },
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let snapshot_id = retain_click_point_snapshot(&plane, &route).await;

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &click_point_arguments(&snapshot_id),
        )
        .await;

    assert_eq!(result["outcome"], "point_outside_viewport");
    assert_eq!(result["detail"]["reason_code"], "point_outside_viewport");
    assert_eq!(result["detail"]["point"]["x_css"], 60.0);
    assert_eq!(result["detail"]["viewport"]["width_css"], 40.0);
    assert!(result["remedy"]
        .as_str()
        .is_some_and(|remedy| remedy.contains("browser.screenshot")));
    assert!(plane.operation_log().await.iter().all(|(_, operation)| {
        !matches!(
            operation,
            browser::Operation::CdpInputPress | browser::Operation::CdpInputRelease
        )
    }));
}

#[tokio::test]
async fn click_point_operation_log_commits_before_press_and_presses_before_release() {
    let route = identity();
    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(&route, Box::new(click_point_process(commands)), 1_000);
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let snapshot_id = retain_click_point_snapshot(&plane, &route).await;

    plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &click_point_arguments(&snapshot_id),
        )
        .await;

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
        position(browser::Operation::CommitDispatched)
            < position(browser::Operation::CdpInputPress),
        "click_point input was dispatched before commitment: {operations:?}"
    );
    assert!(
        position(browser::Operation::CdpInputPress) < position(browser::Operation::CdpInputRelease),
        "click_point released before it pressed: {operations:?}"
    );
}

#[tokio::test]
async fn screenshot_authorization_refuses_no_grant_before_capture() {
    let route = identity();
    let captures = Arc::new(AtomicUsize::new(0));
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::clone(&captures))),
        100,
    )
    .with_grants_installed(GrantStore::default());
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let refused = plane
        .dispatch(&route, BrowserCapability::Screenshot, &json!({}))
        .await;

    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(refused["detail"]["reason"], "no_grant", "{refused}");
    assert_eq!(
        captures.load(Ordering::SeqCst),
        0,
        "an unauthorized screenshot reached the capture backend"
    );
}

#[tokio::test]
async fn screenshot_with_covering_observe_grant_captures() {
    let route = identity();
    let captures = Arc::new(AtomicUsize::new(0));
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::clone(&captures))),
        100,
    )
    .with_grants_installed(screenshot_grants(&["https://requested.example"]));
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let captured = plane
        .dispatch(&route, BrowserCapability::Screenshot, &json!({}))
        .await;

    assert_eq!(captured["outcome"], "ok", "{captured}");
    assert_eq!(
        captures.load(Ordering::SeqCst),
        1,
        "the covering observe grant did not admit one capture"
    );
}

#[tokio::test]
async fn screenshot_origin_scope_refuses_redirect_before_capture() {
    let route = identity();
    let captures = Arc::new(AtomicUsize::new(0));
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::clone(&captures))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    plane
        .same_document_url(
            &route,
            "https://attacker.example/after-redirect",
            SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();

    let refused = plane
        .dispatch(&route, BrowserCapability::Screenshot, &json!({}))
        .await;

    assert_eq!(refused["outcome"], "authorization_denied", "{refused}");
    assert_eq!(refused["detail"]["reason"], "origin_scope", "{refused}");
    assert_eq!(
        captures.load(Ordering::SeqCst),
        0,
        "an off-origin screenshot reached the capture backend"
    );
}

#[tokio::test]
async fn screenshot_retains_browser_reported_dimensions_and_enables_click_point() {
    let route = identity();
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::new(AtomicUsize::new(0)))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let captured = plane
        .dispatch(
            &route,
            BrowserCapability::Screenshot,
            &json!({"max_bytes": ONE_BY_ONE_PNG_B64.len()}),
        )
        .await;

    assert_eq!(captured["outcome"], "ok", "{captured}");
    assert_eq!(captured["image_width_px"], 1);
    assert_eq!(captured["image_height_px"], 1);
    assert_eq!(captured["device_scale_factor"], 2.25);
    assert_eq!(captured["visual_viewport_scale"], 1.75);
    assert_eq!(captured["input_rect"]["x_input_css"], 3.5);
    assert_eq!(captured["input_rect"]["y_input_css"], 4.25);
    assert_eq!(captured["input_rect"]["width_input_css"], 40.0);
    assert_eq!(captured["input_rect"]["height_input_css"], 20.0);

    let clicked = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &json!({
                "snapshot_id": captured["snapshot_id"],
                "x_px": 0,
                "y_px": 0,
                "image_width_px": captured["image_width_px"],
                "image_height_px": captured["image_height_px"],
                "intent": "click the captured viewport",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(
        clicked["outcome"], "ok",
        "the real capture was not retained as an addressable screenshot: {clicked}"
    );
}

#[tokio::test]
async fn screenshot_refuses_when_browser_png_exceeds_max_bytes_and_names_both_sizes() {
    let route = identity();
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::new(AtomicUsize::new(0)))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let bound_bytes = ONE_BY_ONE_PNG_B64.len() - 1;

    let refused = plane
        .dispatch(
            &route,
            BrowserCapability::Screenshot,
            &json!({"max_bytes": bound_bytes}),
        )
        .await;

    assert_eq!(refused["outcome"], "image_too_large", "{refused}");
    assert_eq!(refused["detail"]["bytes"], ONE_BY_ONE_PNG_B64.len());
    assert_eq!(refused["detail"]["bound_bytes"], bound_bytes);
}

#[tokio::test]
async fn screenshot_reply_reports_resized_image_dimensions_not_the_capture() {
    let route = identity();
    // Native capture would be 3136x1568 CSS pixels at 1x. Chrome is asked to
    // scale so the long edge is 1568, producing 1568x784. A reply that echoed
    // the pre-resize size would make every later click_point echo check pass
    // against the wrong number.
    let capture_width = 3136;
    let capture_height = 1568;
    let resized_width = VISION_LONG_EDGE_PX;
    let resized_height = 784;
    assert_ne!(
        (capture_width, capture_height),
        (resized_width, resized_height),
        "the fixture is worthless if pre- and post-resize sizes match"
    );
    let png = png_b64_claiming_dimensions(resized_width, resized_height);
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process_with_capture(
            Arc::new(AtomicUsize::new(0)),
            f64::from(capture_width),
            f64::from(capture_height),
            1.0,
            &png,
        )),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let captured = plane
        .dispatch(&route, BrowserCapability::Screenshot, &json!({}))
        .await;

    assert_eq!(captured["outcome"], "ok", "{captured}");
    assert_eq!(captured["image_width_px"], resized_width);
    assert_eq!(captured["image_height_px"], resized_height);
    assert_ne!(captured["image_width_px"], capture_width);
    assert_ne!(captured["image_height_px"], capture_height);
}

#[tokio::test]
async fn screenshot_full_keeps_the_uncropped_capture_dimensions() {
    let route = identity();
    let capture_width = 3136;
    let capture_height = 1568;
    let png = png_b64_claiming_dimensions(capture_width, capture_height);
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process_with_capture(
            Arc::new(AtomicUsize::new(0)),
            f64::from(capture_width),
            f64::from(capture_height),
            1.0,
            &png,
        )),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let captured = plane
        .dispatch(
            &route,
            BrowserCapability::Screenshot,
            &json!({ "full": true }),
        )
        .await;

    assert_eq!(captured["outcome"], "ok", "{captured}");
    assert_eq!(captured["image_width_px"], capture_width);
    assert_eq!(captured["image_height_px"], capture_height);
}

#[tokio::test]
async fn screenshot_full_over_max_bytes_refuses_rather_than_downscaling() {
    let route = identity();
    let captures = Arc::new(AtomicUsize::new(0));
    let capture_width = 3136;
    let capture_height = 1568;
    let png = png_b64_claiming_dimensions(capture_width, capture_height);
    let bound_bytes = png.len() - 1;
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process_with_capture(
            Arc::clone(&captures),
            f64::from(capture_width),
            f64::from(capture_height),
            1.0,
            &png,
        )),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let refused = plane
        .dispatch(
            &route,
            BrowserCapability::Screenshot,
            &json!({ "full": true, "max_bytes": bound_bytes }),
        )
        .await;

    assert_eq!(refused["outcome"], "image_too_large", "{refused}");
    assert_eq!(refused["detail"]["bytes"], png.len());
    assert_eq!(refused["detail"]["bound_bytes"], bound_bytes);
    assert_eq!(
        captures.load(Ordering::SeqCst),
        1,
        "full over the byte bound retried a downscaled capture"
    );
}

#[tokio::test]
async fn screenshot_path_is_refused_by_name_because_it_abandons_custody() {
    let route = identity();
    let captures = Arc::new(AtomicUsize::new(0));
    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::clone(&captures))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

    let refused = plane
        .dispatch(
            &route,
            BrowserCapability::Screenshot,
            &json!({ "path": "/tmp/authenticated-session.png" }),
        )
        .await;

    assert_eq!(refused["outcome"], "invalid_request", "{refused}");
    assert_eq!(refused["detail"]["field"], "path", "{refused}");
    assert_eq!(
        refused["detail"]["reason_code"], "path_abandons_custody",
        "{refused}"
    );
    let reason = refused["detail"]["reason"]
        .as_str()
        .expect("the path refusal names its reason");
    assert!(
        reason.contains("abandons custody"),
        "path refusal did not name custody: {reason}"
    );
    assert_eq!(
        captures.load(Ordering::SeqCst),
        0,
        "a path refusal reached the capture backend"
    );
}

#[tokio::test]
async fn snapshot_without_a_ready_session_refuses_before_transport_observation() {
    let plane = BrowserPlane::with_grants(navigation_grants());
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;

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
    position_on_authorized_page(&plane, &route).await;

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
    position_on_authorized_page(&plane, &route).await;
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
    position_on_authorized_page(&plane, &route).await;
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

#[tokio::test]
async fn read_page_false_preserves_the_navigation_reply() {
    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: "Unused page text".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let without_read = plane_with_process(
        &route,
        Box::new(SnapshotProcess {
            observation: observation.clone(),
        }),
        1_000,
    );
    without_read.open_context(route.clone()).await.unwrap();
    let without_read = without_read
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "navigate without reading",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    let explicit_false =
        plane_with_process(&route, Box::new(SnapshotProcess { observation }), 1_000);
    explicit_false.open_context(route.clone()).await.unwrap();
    let explicit_false = explicit_false
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "navigate without reading",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": false
            }),
        )
        .await;

    assert_eq!(without_read, explicit_false);
    assert!(without_read.get("read_page").is_none(), "{without_read}");
}

#[tokio::test]
async fn read_page_returns_a_bounded_clickable_snapshot_in_the_navigation_reply() {
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
            role: "button".into(),
            name: "Save profile".into(),
            value: None,
            reference: Some("e2".into()),
        },
    ]);
    let plane = plane_with_process(&route, Box::new(SnapshotProcess { observation }), 1_000);
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open and read the page",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": true,
                "max_bytes": 4096
            }),
        )
        .await;

    assert_eq!(result["outcome"], "ok", "{result}");
    let page = &result["read_page"];
    assert_eq!(page["outcome"], "ok", "{result}");
    assert!(page["content"].as_str().unwrap().contains("Save profile"));
    assert_eq!(page["truncated"], false);
    assert_eq!(page["refs_truncated"], false);
    let snapshot_id = page["snapshot_id"].as_str().unwrap();
    assert_eq!(snapshot_id.len(), 32, "{result}");

    assert_eq!(
        plane.invocation_outcomes_for_test(&route).await,
        vec![
            (BrowserCapability::Navigate, Some(Outcome::Success)),
            (BrowserCapability::Snapshot, Some(Outcome::Success)),
        ],
        "the navigation and read must retain distinct browser invocations"
    );

    let click = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &json!({
                "ref": "e2",
                "snapshot_id": snapshot_id,
                "intent": "use the reference returned by read_page",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(click["outcome"], "ok", "{click}");
}

#[tokio::test]
async fn read_page_marks_content_truncated_at_its_requested_bound() {
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
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open and read a bounded page",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": true,
                "max_bytes": first_line.len()
            }),
        )
        .await;

    assert_eq!(result["outcome"], "ok", "{result}");
    assert_eq!(result["read_page"]["truncated"], true, "{result}");
    assert_eq!(result["read_page"]["content"], first_line, "{result}");
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
    let plane = BrowserPlane::new().with_grants_installed(navigation_grants());
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
        LaunchSlot::Refused(refusal) => panic!("unexpected launch slot refusal {refusal}"),
    }
    let plane = BrowserPlane::with_session_gate(sessions, Arc::new(SystemClock::new()), 100)
        .with_grants_installed(navigation_grants());
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

#[tokio::test]
async fn page_navigate_error_text_is_a_named_refusal_not_an_ok_reply() {
    let route = identity();
    let plane = plane_with_process(
        &route,
        Box::new(CdpNavigationProcess::with_frames(page_navigate_frames(
            [],
            json!({
                "frameId": "main",
                "errorText": "net::ERR_NAME_NOT_RESOLVED"
            }),
        ))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open a resolvable host",
                "wait": "none",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(
        result,
        json!({
            "outcome": "navigation_failed",
            "remedy": "inspect detail.error_text and choose a reachable destination or retry when that browser error is transient",
            "detail": {"error_text": "net::ERR_NAME_NOT_RESOLVED"},
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    );
    assert_ne!(result["outcome"], "ok", "{result}");
}

#[tokio::test]
async fn main_frame_cloudflare_challenge_header_is_reported_as_evidence() {
    let route = identity();
    let plane = plane_with_process(
        &route,
        Box::new(CdpNavigationProcess::with_frames(page_navigate_frames(
            [
                json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"main","response":{"status":403,"statusText":"Forbidden","headers":{"cf-mitigated":"challenge"}}}}),
                json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example/"}}}),
            ],
            json!({"frameId":"main"}),
        ))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "observe a documented challenge response",
                "wait": "none",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(
        result,
        json!({
            "outcome": "ok",
            "url_final": "https://requested.example/",
            "lifecycle": ["navigation_started"],
            "http_status": 403,
            "challenge": {"vendor": "cloudflare", "evidence": "cf-mitigated: challenge"},
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    );
}

#[tokio::test]
async fn subframe_document_response_cannot_replace_main_frame_status_or_claim_a_challenge() {
    let route = identity();
    let plane = plane_with_process(
        &route,
        Box::new(CdpNavigationProcess::with_frames(page_navigate_frames(
            [
                json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example/"}}}),
                json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"main","response":{"status":403,"statusText":"Forbidden","headers":{"server":"cloudflare"}}}}),
                json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"subframe","parentId":"main","url":"https://embed.example/"}}}),
                json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"subframe","response":{"status":200,"statusText":"OK","headers":{"cf-mitigated":"challenge"}}}}),
            ],
            json!({"frameId":"main"}),
        ))),
        100,
    );
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "observe the main document response only",
                "wait": "none",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(
        result,
        json!({
            "outcome": "ok",
            "url_final": "https://requested.example/",
            "lifecycle": ["navigation_started"],
            "http_status": 403,
            "context": {
                "profile_uuid": null,
                "profile_name": "default",
                "session_kind_effective": "primary",
                "profile_disposition": "durable"
            }
        })
    );
    assert!(result.get("challenge").is_none(), "{result}");
}

#[tokio::test]
async fn unsettled_navigation_keeps_its_observed_main_frame_status() {
    let route = identity();
    let plane = plane_with_process(
        &route,
        Box::new(CdpNavigationProcess::with_frames(page_navigate_frames(
            [
                json!({"method":"Page.frameNavigated","sessionId":"session-own","params":{"frame":{"id":"main","url":"https://requested.example/"}}}),
                json!({"method":"Network.responseReceived","sessionId":"session-own","params":{"type":"Document","frameId":"main","response":{"status":503,"statusText":"Service Unavailable","headers":{}}}}),
            ],
            json!({"frameId":"main"}),
        ))),
        // One deadline covers attach, the enables, Page.navigate and the settle
        // wait, and `not_settled` is only reached by running it out, so the
        // test costs this long. 20 ms let the setup commands miss the window
        // under a loaded gate and answer cdp_failure instead; 300 ms is the
        // smallest budget that survived the full gate with the whole
        // workspace testing beside it.
        300,
    );
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "observe an unsettled service response",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    assert_eq!(result["outcome"], "not_settled", "{result}");
    assert_eq!(result["http_status"], 503, "{result}");
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
    plane
        .same_document_url(
            route,
            "https://requested.example/page",
            cerebellum::snapshot_store::SameDocumentChange::ReplaceState,
        )
        .await
        .unwrap();
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
                classification: Err(ClassificationUnavailable::NotCaptured),
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
async fn an_unscrollable_click_names_the_viewport_and_refuses_without_input() {
    let route = identity();
    let input_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let position = BrowserClickPosition {
        x_css: 150.0,
        y_css: 5020.0,
    };
    let viewport = InputRect::new(0.0, 0.0, 1280.0, 713.0);
    let plane = plane_with_process(
        &route,
        Box::new(ClickProcess {
            result: Err(ClickDriveError::OutsideViewportAfterScroll(
                ViewportRefusal { position, viewport },
            )),
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

    assert_eq!(result["outcome"], "outside_viewport_after_scroll");
    assert_eq!(
        result["detail"]["reason_code"],
        "outside_viewport_after_scroll"
    );
    assert_eq!(result["detail"]["point"]["y_css"], 5020.0);
    assert_eq!(result["detail"]["viewport"]["height_css"], 713.0);
    assert!(result["remedy"]
        .as_str()
        .is_some_and(|remedy| remedy.contains("fresh browser.snapshot")));
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

/// The plane production builds runs its authorization gate.
///
/// `BrowserPlane` derives `Default`, so a `bool` field the derive is left to
/// fill is `false`. Both production constructors reach that default -- `new()`
/// directly, and `with_session_gate` through `..Self::default()` -- while only
/// `with_grants` sets the flag, and nothing outside tests calls it.
///
/// That is not a dormant fixture setting. `browser.navigate` becomes
/// wire-dispatchable as soon as a browser is configured, so a flag reading
/// `false` means navigation is served with its grant check skipped rather than
/// refused for want of a grant -- the opposite of the fail-closed posture the
/// empty grant store is there to provide.
///
/// Asserted behaviourally rather than by reading the field, because the field
/// is private and what matters is what a request receives. An empty grant store
/// can cover nothing, so a plane whose gate runs must refuse this request; a
/// plane whose gate is skipped proceeds past it.
#[tokio::test]
async fn the_plane_production_builds_runs_its_authorization_gate() {
    let plane = BrowserPlane::new();
    let route = identity();
    plane.open_context(route.clone()).await.unwrap();

    let outcome = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://example.test/",
                "intent": "probe whether the grant gate runs",
                "wait": "none",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;

    let body = outcome.to_string();
    // A request that never reached the gate proves nothing about it.
    assert!(
        !body.contains("missing_field") && !body.contains("unsupported_value"),
        "the request was refused at validation before reaching the \
         authorization gate, so this run did not test the gate: {body}"
    );
    assert!(
        body.contains("authorization") || body.contains("grant"),
        "A navigate through the PRODUCTION constructor was not refused by the \
         authorization gate, so the gate did not run.\n\n\
         BrowserPlane derives Default and `authorization_enabled` is a bool the \
         derive sets to FALSE. `new()` and `with_session_gate` both reach that \
         default; only `with_grants`, which nothing outside tests calls, sets it \
         true. browser.navigate IS wire-dispatchable once a browser is \
         configured, so this serves navigation with no grant check at all.\n\n\
         Outcome was: {body}"
    );
}

/// A navigation double that lands somewhere other than the authorized origin.
#[derive(Clone)]
struct OffOriginRedirectProcess {
    observation: BrowserSnapshotObservation,
}

impl OwnedBrowserProcess for OffOriginRedirectProcess {
    fn navigate(
        &mut self,
        _: &str,
        _: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let now = Instant::now();
        tracker.url_final = Some("https://attacker.example/landed".into());
        tracker.load(now);
        tracker.poll_settlement(now + Duration::from_millis(browser::QUIET_MS));
        Ok(())
    }

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

/// A redirect off the authorized origin must not become permission to read.
///
/// Navigation authorizes the origin the caller REQUESTED, which is the only one
/// it can check before the browser moves. The page it lands on is chosen by the
/// site, so a grant for one origin plus one redirect would otherwise become a
/// read of a page nobody authorized -- and in this profile that page can be
/// somewhere the user is signed in.
///
/// The assertion that carries the property is the SECOND one: the navigation
/// itself succeeds, so the refusal cannot be coming from a plane that refuses
/// everything. A test asserting only the refusal would pass against exactly the
/// gate this exists to prove is absent.
#[tokio::test]
async fn a_redirect_off_the_authorized_origin_refuses_the_next_snapshot() {
    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: "Private page".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(
        &route,
        Box::new(OffOriginRedirectProcess { observation }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();

    let navigated = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open the authorized origin",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(navigated["outcome"], "ok", "{navigated}");
    assert_eq!(
        navigated["url_final"], "https://attacker.example/landed",
        "the caller is told where it actually landed: {navigated}"
    );

    let snapshot = plane
        .dispatch(
            &route,
            BrowserCapability::Snapshot,
            &json!({"mode": "ax", "max_bytes": 4096}),
        )
        .await;
    assert_eq!(snapshot["outcome"], "authorization_denied", "{snapshot}");
    assert_eq!(snapshot["detail"]["reason"], "origin_scope", "{snapshot}");
    assert!(
        snapshot.get("records").is_none() && snapshot.get("refs").is_none(),
        "a refused snapshot returns no page content: {snapshot}"
    );
}

/// A read bundled into navigation must authorize the page where the browser lands.
#[tokio::test]
async fn a_redirect_off_the_authorized_origin_withholds_read_page_content() {
    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: "Private page".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(
        &route,
        Box::new(OffOriginRedirectProcess { observation }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "open the authorized origin and read it",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": true
            }),
        )
        .await;

    assert_eq!(result["outcome"], "ok", "{result}");
    assert_eq!(
        result["url_final"], "https://attacker.example/landed",
        "the navigation must have succeeded and reported its landing page: {result}"
    );
    assert_eq!(
        result["read_page"]["outcome"], "authorization_denied",
        "{result}"
    );
    assert_eq!(result["read_page"]["detail"]["reason"], "origin_scope");
    let reply = result.to_string();
    assert!(
        result.get("content").is_none()
            && result.get("refs").is_none()
            && result.pointer("/read_page/content").is_none()
            && result.pointer("/read_page/refs").is_none()
            && !reply.contains("Private page"),
        "a refused read must not return page content: {result}"
    );
}

/// A navigation and its embedded read produce separate journal records.
///
/// Both records must survive in the plane's shared journal and retain their own
/// capability names. The serialized sizes are printed because frequent reads
/// should not crowd actuation records out of the journal.
#[tokio::test]
async fn the_journal_lifecycle_runs_and_separates_a_read_from_a_navigation() {
    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: "Journalled page".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(&route, Box::new(SnapshotProcess { observation }), 1_000)
        .with_in_memory_journal(cerebellum::journal::JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 100_000,
        });
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "drive the journal lifecycle",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": true
            }),
        )
        .await;
    assert_eq!(result["outcome"], "ok", "{result}");
    assert_eq!(result["read_page"]["outcome"], "ok", "{result}");

    // Read back through the export, which is the shape a reader actually sees.
    let export = plane.journal_export_for_test().await;
    for line in export.lines() {
        println!("journal line ({} bytes): {line}", line.len());
    }
    assert!(
        export.contains("\"capability\":\"browser.navigate\""),
        "the navigation is missing from the journal: {export}"
    );
    assert!(
        export.contains("\"capability\":\"browser.snapshot\""),
        "the read recorded as something other than a read: {export}"
    );

    // Two records per call -- the navigation and the read -- at ~730 bytes each.
    //
    // Getting that number cost three wrong ones, and the reason is worth keeping:
    // JournalStore::new opens the OPERATOR'S journal on disk, so this test was
    // writing into real audit data and reading back everything every earlier run
    // had left. It reported 11, then 17, then 21 for the same single call,
    // because it was measuring a running total. A count that GROWS across
    // identical runs is the tell, and it is only visible if you run the thing
    // twice -- which is not something a passing test asks you to do.
    //
    // The isolated binding fixed both problems at once: the measurement became
    // meaningful and the test stopped polluting durable data.
    //
    // Bounded rather than asserted equal so a third record cannot appear
    // unnoticed, since the per-call cost is what decides whether reads can be
    // journaled in production without evicting the actions beside them.
    let records = export.lines().filter(|line| !line.is_empty()).count();
    assert!(
        records <= 2,
        "a navigate with one read now writes {records} journal records, up from the \
         two measured when this was written; the per-call cost has grown"
    );
}

/// A snapshot authorization denial is recorded without reading its target.
#[tokio::test]
async fn a_refusal_records_only_claimed_addressing_and_typed_reason() {
    const SECRET: &str = "private-page-secret-7be680b9";

    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: SECRET.into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(
        &route,
        Box::new(OffOriginRedirectProcess { observation }),
        1_000,
    )
    .with_in_memory_journal(cerebellum::journal::JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    });
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "drive a refused read into its separate audit ring",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": true
            }),
        )
        .await;
    assert_eq!(result["outcome"], "ok", "{result}");
    assert_eq!(
        result["read_page"]["outcome"], "authorization_denied",
        "{result}"
    );

    let history = plane
        .refusal_history_for_test(&route.agent_project_id)
        .await
        .expect("the refusing module records its decision");
    assert_eq!(history.total_count, 1);
    assert_eq!(history.evicted_count, 0);
    assert!(!history.trimmed);
    assert_eq!(history.records.len(), 1);
    assert_eq!(
        history.records[0].claimed_addressing,
        "https://attacker.example/landed"
    );
    assert_eq!(
        history.records[0].reason,
        SnapshotRefusalReason::OriginScope
    );

    let journal = plane.journal_export_for_test().await;
    assert!(journal.contains("\"capability\":\"browser.navigate\""));
    assert!(
        !journal.contains("\"capability\":\"browser.snapshot\""),
        "a refusal entered the untrimmable actuation journal: {journal}"
    );

    let serialized = plane.refusal_ring_export_for_test().await;
    let planted = format!(
        "{{\"bytes\":\"{}\"}}",
        cerebellum_core::serde_base64::encode(SECRET.as_bytes())
    );
    assert!(
        base64_decoded_strings(&planted)
            .iter()
            .any(|text| text.contains(SECRET)),
        "the scanner cannot find a planted secret, so an absence would prove nothing"
    );
    assert!(
        !serialized.contains(SECRET),
        "target content appears verbatim in the refusal ring: {serialized}"
    );
    assert!(
        !base64_decoded_strings(&serialized)
            .iter()
            .any(|text| text.contains(SECRET)),
        "target content appears in an encoded refusal-ring field: {serialized}"
    );
}

/// Decode every base64-looking serialized token that contains UTF-8 text.
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

/// A refused read never reaches the journal, because authorization precedes
/// reservation.
///
/// I wrote this expecting the opposite -- that a refusal reserved and then
/// failed to finalize, leaving an open reservation indistinguishable from a
/// process that died mid-dispatch. It does not: `capture_snapshot` authorizes,
/// and only then reserves, so a refused read touches no journal state at all.
/// That ordering is the fail-closed one and it is what this pins.
///
/// It also means an unauthorized caller cannot write journal entries, which is
/// why the ordering is worth a test rather than a comment: reversing it would
/// hand a refused caller a way to fill an operator's audit storage.
///
/// SEPARATELY AND NOT ASSERTED HERE: whether a refusal SHOULD be recorded is an
/// open question. "Which origins did this agent try to read and get refused" is
/// close to the first thing a compromise investigation asks, and today the
/// journal cannot answer it. Recording it without re-introducing the write
/// primitive above is the design problem.
#[tokio::test]
async fn a_refused_read_never_reaches_the_journal() {
    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: "Private page".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(
        &route,
        Box::new(OffOriginRedirectProcess { observation }),
        1_000,
    )
    .with_in_memory_journal(cerebellum::journal::JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    });
    plane.open_context(route.clone()).await.unwrap();

    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "drive a refused read through the journal",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false},
                "read_page": true
            }),
        )
        .await;
    assert_eq!(result["outcome"], "ok", "{result}");
    assert_eq!(
        result["read_page"]["outcome"], "authorization_denied",
        "{result}"
    );

    let export = plane.journal_export_for_test().await;

    // The navigation happened and is recorded.
    assert!(
        export.contains("\"capability\":\"browser.navigate\""),
        "the navigation is missing from the journal: {export}"
    );

    // The refused read reserved nothing. Asserted as the ABSENCE of any
    // snapshot record rather than as the absence of a reservation, because a
    // reservation that was taken and then finalized would also leave no open
    // reservation while having written -- and that is the state this rules out.
    assert!(
        !export.contains("\"capability\":\"browser.snapshot\""),
        "a refused read wrote a journal record, so it reserved before \
         authorizing: {export}"
    );
}

/// Every dispatch uses the plane's single loaded journal store.
///
/// The record delta samples one dispatch at a time. Comparing two identical
/// deltas prevents an accumulated export count from masquerading as a
/// per-dispatch measurement.
#[tokio::test]
async fn journal_dispatches_share_one_store() {
    let route = identity();
    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "heading".into(),
        name: "Retention probe".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(&route, Box::new(SnapshotProcess { observation }), 1_000)
        .with_in_memory_journal(cerebellum::journal::JournalConfig {
            journal_retention_bytes: 1_000_000,
            journal_max_entry_bytes: 100_000,
        });
    plane.open_context(route.clone()).await.unwrap();

    let mut retained_store_counts = Vec::new();
    let mut records_per_dispatch = Vec::new();
    for _ in 0..3 {
        let records_before = plane
            .journal_export_for_test()
            .await
            .lines()
            .filter(|line| !line.is_empty())
            .count();
        let result = plane
            .dispatch(
                &route,
                BrowserCapability::Navigate,
                &json!({
                    "url": "https://requested.example/",
                    "intent": "measure journal retention",
                    "wait": "settle",
                    "severity": {"tier": 2, "credential": false, "financial": false}
                }),
            )
            .await;
        assert_eq!(result["outcome"], "ok", "{result}");

        let records_after = plane
            .journal_export_for_test()
            .await
            .lines()
            .filter(|line| !line.is_empty())
            .count();
        records_per_dispatch.push(records_after - records_before);
        retained_store_counts.push(plane.retained_journal_store_count_for_test().await);
    }

    assert_eq!(
        retained_store_counts,
        vec![1, 1, 1],
        "dispatches must reuse the plane's loaded journal store"
    );
    assert_eq!(
        records_per_dispatch,
        vec![1, 1, 1],
        "identical dispatches must each contribute one record; a growing count \
         means the measurement is integrating journal history"
    );

    plane.end_context(&route, false).await;
    assert_eq!(
        plane.retained_journal_store_count_for_test().await,
        1,
        "the journal belongs to the plane rather than the ended context"
    );
}

/// A browser that dies mid-dispatch leaves a finalized record, not an open one.
///
/// This is the last uncovered path before the journal can be wired to write
/// durably, and it is the one where getting it wrong corrupts rather than
/// loses. An open reservation is indistinguishable from a process that died
/// between reserving and finalizing — which is exactly what the recovery
/// machinery looks for on startup. So a dispatch that fails without finalizing
/// does not merely omit a record: it manufactures a recovery case, and the
/// recovery would act on it.
///
/// Drives a real CDP failure through the dispatch path rather than injecting a
/// journal state, so the finalization is exercised where it actually runs.
#[tokio::test]
async fn a_browser_that_dies_mid_dispatch_finalizes_its_journal_entry() {
    let route = identity();
    let input_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(
        &route,
        Box::new(ClickProcess {
            result: Err(ClickDriveError::Navigation(
                NavigationDriveError::Unavailable,
            )),
            input_events: Arc::clone(&input_events),
        }),
        1_000,
    )
    .with_in_memory_journal(cerebellum::journal::JournalConfig {
        journal_retention_bytes: 1_000_000,
        journal_max_entry_bytes: 100_000,
    });
    plane.open_context(route.clone()).await.unwrap();

    let snapshot_id = retain_click_snapshot(&plane, &route).await;
    let result = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &json!({
                "snapshot_id": snapshot_id,
                "ref": "e1",
                "intent": "drive a dispatch whose browser dies under it",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_ne!(result["outcome"], "ok", "{result}");

    let export = plane.journal_export_for_test().await;

    // The click must appear AND be terminal. Asserting only that a record
    // exists would pass on an open reservation, which is the state this test
    // exists to rule out.
    let click_records: Vec<&str> = export
        .lines()
        .filter(|line| line.contains("\"capability\":\"browser.click\""))
        .collect();
    assert!(
        !click_records.is_empty(),
        "a failed click left no journal record: {export}"
    );
    // Nothing may be left holding bytes, and nothing may be left committed but
    // unclosed. The second is the one that matters and the one the export
    // cannot answer: it merges finalized entries with dispatched reservations,
    // so a record appearing above proves commitment rather than closure. Byte
    // accounting cannot separate them either -- both read zero.
    //
    // An unclosed dispatch is what startup recovery reads as a process that
    // died mid-dispatch, so a finalization regression would manufacture
    // recovery cases rather than merely losing records.
    //
    // This replaced an assertion on byte accounting alone, which stayed green
    // with the invocation lookup broken at all three finalization call sites.
    assert_eq!(
        plane.active_reserved_bytes_for_test().await,
        0,
        "a failed click left bytes held in reservation: {export}"
    );
    assert_eq!(
        plane.unfinalized_dispatch_count_for_test().await,
        0,
        "a failed click was committed and never closed out, which startup \
         recovery reads as a process that died mid-dispatch: {export}"
    );
}

/// Inventory replies generated by the browser handlers themselves, not JSON
/// examples. Each tool reaches its normal success path and the shared typed
/// invalid-request refusal. Driver-specific refusal variants remain in their
/// focused fixtures above because their injected transport faults cannot be
/// combined into one deterministic process without changing the handler under
/// test.
#[tokio::test]
async fn served_browser_reply_divergence_inventory_is_empty() {
    let route = identity();
    let mut replies = Vec::new();

    let observation = snapshot_observation(vec![AxRecord {
        depth: 0,
        role: "button".into(),
        name: "Save".into(),
        value: None,
        reference: Some("e1".into()),
    }]);
    let plane = plane_with_process(
        &route,
        Box::new(SnapshotProcess {
            observation: observation.clone(),
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    let reply = plane
        .dispatch(
            &route,
            BrowserCapability::Navigate,
            &json!({
                "url": "https://requested.example/",
                "intent": "inventory navigation",
                "wait": "settle",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    replies.push((browser::NAVIGATE, reply));

    let plane = plane_with_process(
        &route,
        Box::new(SnapshotProcess {
            observation: observation.clone(),
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let reply = plane
        .dispatch(&route, BrowserCapability::Snapshot, &json!({"mode": "ax"}))
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    replies.push((browser::SNAPSHOT, reply));

    let input_events = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(
        &route,
        Box::new(ClickProcess {
            result: Ok(BrowserClickPosition {
                x_css: 1.0,
                y_css: 1.0,
            }),
            input_events,
        }),
        1_000,
    );
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let retained = plane
        .retain_text_snapshot(
            &route,
            SnapshotKind::Ax,
            &observation.records,
            observation.dom_text.as_deref(),
            observation.refs.clone(),
            4_096,
        )
        .await
        .unwrap();
    let reply = plane
        .dispatch(
            &route,
            BrowserCapability::Click,
            &click_arguments(retained["snapshot_id"].as_str().unwrap()),
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    replies.push((browser::CLICK, reply));

    let plane = plane_with_process(
        &route,
        Box::new(screenshot_process(Arc::new(AtomicUsize::new(0)))),
        1_000,
    )
    .with_grants_installed(screenshot_grants(&["https://requested.example"]));
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let reply = plane
        .dispatch(&route, BrowserCapability::Screenshot, &json!({}))
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    replies.push((browser::SCREENSHOT, reply));

    let commands = Arc::new(std::sync::Mutex::new(Vec::new()));
    let plane = plane_with_process(&route, Box::new(click_point_process(commands)), 1_000);
    plane.open_context(route.clone()).await.unwrap();
    position_on_authorized_page(&plane, &route).await;
    let snapshot_id = retain_click_point_snapshot(&plane, &route).await;
    let reply = plane
        .dispatch(
            &route,
            BrowserCapability::ClickPoint,
            &click_point_arguments(&snapshot_id),
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    replies.push((browser::CLICK_POINT, reply));

    let plane = BrowserPlane::new();
    plane.open_context(route.clone()).await.unwrap();
    let now = Instant::now();
    plane.observe_load(&route, now).await.unwrap();
    assert!(
        plane
            .poll_settlement(&route, now + Duration::from_millis(browser::QUIET_MS))
            .await
            .unwrap(),
        "the wait success fixture did not settle"
    );
    let reply = plane
        .dispatch(
            &route,
            BrowserCapability::WaitFor,
            &json!({"deadline_ms": 0}),
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    replies.push((browser::WAIT_FOR, reply));

    for capability in [
        BrowserCapability::Navigate,
        BrowserCapability::Snapshot,
        BrowserCapability::Click,
        BrowserCapability::Screenshot,
        BrowserCapability::ClickPoint,
        BrowserCapability::WaitFor,
    ] {
        let reply = BrowserPlane::new()
            .dispatch(&route, capability, &Value::Null)
            .await;
        assert_eq!(reply["outcome"], "invalid_request", "{reply}");
        replies.push((capability.name(), reply));
    }

    for (capability_id, reply) in replies {
        assert!(
            browser::validate_browser_result(capability_id, &reply).is_ok(),
            "the production {capability_id} reply diverged from its declared result schema: {reply}"
        );
    }
}
