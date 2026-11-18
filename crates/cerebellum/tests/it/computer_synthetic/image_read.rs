//! Image fronting on the synthetic desk; no application or system input is used.

use super::*;
use crate::computer_read_state::{assert_no_screen_text, capturing, jpeg, recorded_read};
use cerebellum::computer_capability::image_freshness::{ImageFreshnessSource, WindowVisibility};
use cerebellum_computer::app_state::source::RawElement;
use cerebellum_computer::capture::*;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

const WINDOW_SECRET: &str = "PrivateWindowTitle_90c39";
const ELEMENT_SECRET: &str = "PrivateElementValue_52f01";

struct Freshness {
    frontmost: Arc<AtomicU32>,
    still_covered: bool,
    cover_during_capture: bool,
}

impl ImageFreshnessSource for Freshness {
    fn inspect(&self, target: &ProcessGrant, id: Option<&str>) -> (bool, WindowVisibility) {
        (
            false,
            if self.still_covered
                || (id.is_some() && self.cover_during_capture)
                || self.frontmost.load(Ordering::SeqCst) != target.pid
            {
                WindowVisibility::Covered
            } else {
                WindowVisibility::FullyVisible
            },
        )
    }
    fn inspect_decision(
        &self,
        target: &ProcessGrant,
        id: Option<&str>,
    ) -> (
        bool,
        WindowVisibility,
        cerebellum_computer::app_state::image::ImageDecision,
    ) {
        use cerebellum_computer::app_state::image::ImageDecision;
        let (repaints, visibility) = self.inspect(target, id);
        // The synthetic desk's only cover is another normal app window.
        (
            repaints,
            visibility,
            if visibility == WindowVisibility::Covered {
                ImageDecision::CoveredByWindow
            } else {
                ImageDecision::FullyVisible
            },
        )
    }
}

/// Counts the actual capture call, so withholding after capture cannot pass for
/// refusing to capture a still-covered window.
struct TrackedCapture {
    inner: InMemoryCaptureBackend,
    captures: Arc<AtomicUsize>,
    encodes: Arc<AtomicUsize>,
    frontmost: Arc<AtomicU32>,
}
impl CaptureBackend for TrackedCapture {
    fn screen_recording_liveness(&self) -> cerebellum_computer::platform::PermissionLiveness {
        self.inner.screen_recording_liveness()
    }
    fn enumerate_windows(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        self.inner.enumerate_windows(target)
    }
    fn poll_window_change(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError> {
        self.inner.poll_window_change(target)
    }
    fn capture_window(
        &mut self,
        request: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError> {
        self.inner.capture_window(request)
    }
    fn capture_display(
        &mut self,
        request: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        self.inner.capture_display(request)
    }
    fn frontmost_window_id(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Option<String>, BackendError> {
        self.inner.frontmost_window_id(target)
    }
    fn capture_window_for_vision(
        &mut self,
        request: &WindowCaptureRequest,
    ) -> Result<VisionWindowFrame, BackendError> {
        assert_eq!(
            self.frontmost.load(Ordering::SeqCst),
            grant().pid,
            "capture must happen before restore"
        );
        self.captures.fetch_add(1, Ordering::SeqCst);
        self.inner.capture_window_for_vision(request)
    }
    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError> {
        self.inner.begin_teardown()
    }
    fn capture_window_unencoded_for_vision(
        &mut self,
        request: &WindowCaptureRequest,
    ) -> Result<PendingVisionWindowFrame, BackendError> {
        assert_eq!(
            self.frontmost.load(Ordering::SeqCst),
            grant().pid,
            "raw capture must happen before restore"
        );
        self.captures.fetch_add(1, Ordering::SeqCst);
        self.inner.capture_window_unencoded_for_vision(request)
    }
    fn encode_window_for_vision(
        &mut self,
        pending: PendingVisionWindowFrame,
    ) -> Result<VisionWindowFrame, BackendError> {
        assert_eq!(
            self.frontmost.load(Ordering::SeqCst),
            OTHER_APPLICATION_PID,
            "scaling and encoding must happen after restore"
        );
        self.encodes.fetch_add(1, Ordering::SeqCst);
        self.inner.encode_window_for_vision(pending)
    }
    fn poll_teardown(&mut self, elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError> {
        self.inner.poll_teardown(elapsed_ms)
    }
}

async fn read(
    script: FrontingScript,
    still_covered: bool,
    cover_during_capture: bool,
) -> (Value, Value, Arc<Mutex<Shared>>, usize) {
    read_with_app_grant(script, still_covered, cover_during_capture, false).await
}

async fn read_with_app_grant(
    script: FrontingScript,
    still_covered: bool,
    cover_during_capture: bool,
    allow_once: bool,
) -> (Value, Value, Arc<Mutex<Shared>>, usize) {
    let shared = Shared::handle();
    shared.lock().unwrap().fronted = script;
    let frontmost = shared.lock().unwrap().image_frontmost.clone();
    let captures = Arc::new(AtomicUsize::new(0));
    let encodes = Arc::new(AtomicUsize::new(0));
    let storage = InMemoryJournalStorage::new();
    let desk = background(Desk::new(vec![RawElement::fixture(1, "AXWindow")
        .titled(WINDOW_SECRET)
        .with_children(vec![
            RawElement::fixture(2, "AXButton").titled(ELEMENT_SECRET)
        ])]));
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        support::computer::audit_with_storage(storage.clone()),
        ResultSchemaEnforcement::Withhold,
        SyntheticDriver::factory(shared.clone()),
    )
    .with_permission_liveness(support::computer::live_permissions())
    .with_app_state_source(desk.source())
    // Production admits a covered-window picture only where both the
    // takeover review and the app-use fronting review bind; admit both.
    .with_fronting_bracket_admitted(true)
    .with_app_use_fronting_admitted(true)
    .with_image_freshness_source(Arc::new(Freshness {
        frontmost: frontmost.clone(),
        still_covered,
        cover_during_capture,
    }));
    let (management, carrier) = if allow_once {
        (
            support::computer::management(),
            ScriptedCarrier::answering(&["allow_once", "deny"]),
        )
    } else {
        (
            granted_management().await,
            ScriptedCarrier::answering(&["computer_30m"]),
        )
    };
    let clock = FakeClock::new();
    let invoke = || async {
        let mut consent = relayed(&carrier);
        if allow_once {
            // Without a grant holder, the app card can approve only this call.
            consent.caller.holder = None;
        }
        with_terminal(
            "computer.read_state",
            plane.serve(
                servable("computer.read_state").unwrap(),
                &json!({"target":TARGET_BUNDLE_ID,"include_image":true,"bring_to_front":true}),
                ServeContext {
                    cancel: cerebellum::CancelHandle::pending(),
                    grantee: GRANTEE,
                    identity: identity(),
                    management: &management,
                    consent,
                    clock: &clock,
                    now_ms: 10,
                },
                |_| TrackedCapture {
                    inner: capturing(jpeg(1250, 750, 0)),
                    captures: captures.clone(),
                    encodes: encodes.clone(),
                    frontmost: frontmost.clone(),
                },
            ),
        )
        .await
        .expect("the fronted read passes the closed reply schema")
    };
    let reply = invoke().await;
    if allow_once {
        assert!(
            reply.get("image").is_some(),
            "the waiting call uses its own approval: {reply}"
        );
        let second = invoke().await;
        assert_eq!(second["outcome"], "consent_denied", "{second}");
        let cards = carrier.questions();
        assert_eq!(cards.len(), 2, "the later call has no grant");
        for card in cards {
            assert_eq!(card["params"]["scope"]["app"], TARGET_BUNDLE_ID);
        }
    } else {
        assert!(
            carrier.questions().is_empty(),
            "an app grant suffices: {reply}"
        );
    }
    assert!(plane.result_schema_findings().is_empty());
    assert_eq!(
        encodes.load(Ordering::SeqCst),
        usize::from(reply.get("image").is_some()),
        "withheld images are not encoded"
    );
    assert_eq!(reply["outcome"], "completed", "the tree succeeded: {reply}");
    assert!(reply["state_text"]
        .as_str()
        .unwrap()
        .contains(ELEMENT_SECRET));
    let row = recorded_read(&storage);
    assert_no_screen_text(&row, WINDOW_SECRET);
    assert_no_screen_text(&row, ELEMENT_SECRET);
    assert_eq!(
        row["codec_version"], "ck-computer-journal/v3",
        "optional facts do not bump the open image row format"
    );
    let opaque: Vec<u8> = serde_json::from_value(row["completed_result"].clone()).unwrap();
    let result: Value = serde_json::from_slice(&opaque).unwrap();
    assert_eq!(row["image_decision"], result["image_decision"]);
    assert_eq!(row["image_fronting"], result["image_fronting"]);
    assert_eq!(
        row["longest_fronted_interval_ms"],
        result["longest_fronted_interval_ms"]
    );
    if row.get("image_fronting").is_some() {
        assert!(row["longest_fronted_interval_ms"].is_u64());
        assert_eq!(
            row["longest_fronted_interval_ms"],
            row["image_fronting"]["longest_fronted_interval_ms"]
        );
    }
    (reply, row, shared, captures.load(Ordering::SeqCst))
}

#[tokio::test]
async fn covered_read_fronts_captures_and_restores_with_only_an_app_grant() {
    let (reply, row, shared, captures) = read(FrontingScript::default(), false, false).await;
    assert!(reply.get("image").is_some(), "{reply}");
    assert_eq!(captures, 1);
    let shared = shared.lock().unwrap();
    assert_eq!(
        shared.image_front_requests,
        vec![grant().pid, OTHER_APPLICATION_PID]
    );
    assert_eq!(
        shared.image_frontmost.load(Ordering::SeqCst),
        OTHER_APPLICATION_PID
    );
    assert_eq!(row["image_decision"], "fronted_then_visible");
    assert_eq!(row["image_returned"], true);
    assert_eq!(row["image_fronting"], reply["image_fronting"]);
    assert_eq!(row["image_fronting"]["attempted"], true);
    assert_eq!(row["image_fronting"]["restored"], true);
}

#[tokio::test]
async fn covered_read_spends_allow_once_on_the_waiting_call_not_a_retry() {
    let (_, _, shared, captures) =
        read_with_app_grant(FrontingScript::default(), false, false, true).await;
    assert_eq!(captures, 1);
    assert_eq!(
        shared.lock().unwrap().image_front_requests,
        [grant().pid, OTHER_APPLICATION_PID]
    );
}

#[tokio::test]
async fn fronting_overrun_discloses_bound_and_withholds_image() {
    let (reply, row, shared, captures) = read(
        FrontingScript {
            front_latency_ms: Some(101),
            ..Default::default()
        },
        false,
        false,
    )
    .await;
    assert_eq!(
        reply["image_unavailable"]["reason"],
        "fronting_bound_exceeded"
    );
    assert!(reply.get("image").is_none());
    assert_eq!(captures, 0);
    assert!(
        row["image_fronting"]["longest_fronted_interval_ms"]
            .as_u64()
            .unwrap()
            > 200
    );
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .image_frontmost
            .load(Ordering::SeqCst),
        OTHER_APPLICATION_PID
    );
    assert_eq!(row["image_decision"], "covered_by_window");
    assert_eq!(row["image_returned"], false);
}

#[tokio::test]
async fn still_covered_after_fronting_never_captures() {
    let (reply, row, shared, captures) = read(FrontingScript::default(), true, false).await;
    assert_eq!(
        reply["image_unavailable"]["reason"],
        "window_covered_may_be_stale"
    );
    assert_eq!(
        captures, 0,
        "withholding captured pixels is not refusing capture"
    );
    assert!(reply.get("image").is_none());
    assert_eq!(row["image_decision"], "covered_by_window");
    assert_eq!(row["image_fronting"]["restored"], true);
    assert_eq!(
        shared.lock().unwrap().image_front_requests,
        vec![grant().pid, OTHER_APPLICATION_PID]
    );
}

#[tokio::test]
async fn cover_racing_capture_withholds_pixels_and_restores() {
    let (reply, row, _, captures) = read(FrontingScript::default(), false, true).await;
    assert_eq!(captures, 1);
    assert!(reply.get("image").is_none());
    assert_eq!(
        reply["image_unavailable"]["reason"],
        "window_covered_may_be_stale"
    );
    assert_eq!(row["image_decision"], "covered_by_window");
    assert_eq!(row["image_fronting"]["restored"], true);
}

#[tokio::test]
async fn failed_restore_is_disclosed_without_releasing_image() {
    let (reply, row, shared, captures) = read(
        FrontingScript {
            refuse_restore: true,
            ..Default::default()
        },
        false,
        false,
    )
    .await;
    assert_eq!(captures, 1);
    assert_eq!(reply["image_unavailable"]["reason"], "restore_failed");
    assert!(reply.get("image").is_none());
    assert_eq!(row["image_decision"], "fully_visible");
    assert_eq!(row["image_fronting"]["restored"], false);
    assert_eq!(row["image_fronting"]["left_in_front"], grant().pid);
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .image_frontmost
            .load(Ordering::SeqCst),
        grant().pid
    );
}

#[tokio::test]
async fn person_change_refuses_fronting_but_does_not_block_an_unfronted_read() {
    for front_image in [false, true] {
        let shared = Shared::handle();
        let desk = background(focused_text_desk());
        desk.state().window = Some((1, Some("Before".into())));
        // Production fronts a picture only where the app-use fronting
        // review binds too.
        let plane = plane_on(&shared, &desk, true)
            .with_app_use_fronting_admitted(true)
            .with_image_freshness_source(Arc::new(Freshness {
                frontmost: shared.lock().unwrap().image_frontmost.clone(),
                still_covered: false,
                cover_during_capture: false,
            }));
        let management = granted_management().await;
        let first = serve_asking(
            &plane,
            "computer.read_state",
            json!({"target": TARGET_BUNDLE_ID}),
            &management,
            no_relay(),
        )
        .await;
        assert_eq!(first["outcome"], "completed");
        desk.state().window = Some((1, Some("After".into())));
        let reply = serve_asking(
            &plane,
            "computer.read_state",
            json!({"target": TARGET_BUNDLE_ID, "include_image": true, "bring_to_front": front_image}),
            &management,
            no_relay(),
        )
        .await;
        if front_image {
            assert_eq!(reply["outcome"], "state_changed_by_person");
            assert_eq!(reply["reason"], "window_changed");
        } else {
            assert_eq!(reply["outcome"], "completed");
            assert_eq!(
                reply["image_unavailable"]["reason"],
                "window_covered_may_be_stale"
            );
        }
        assert!(shared.lock().unwrap().image_front_requests.is_empty());
    }
}

#[tokio::test]
async fn image_reads_fit_the_needs_front_bound_and_encode_after_restore() {
    let (reply, row, shared, captures) = read(
        FrontingScript {
            front_latency_ms: Some(100),
            ..Default::default()
        },
        false,
        false,
    )
    .await;
    assert!(
        reply.get("image").is_some(),
        "a 200 ms image bracket fits the needs-front bound: {reply}"
    );
    assert_eq!(captures, 1);
    assert_eq!(row["longest_fronted_interval_ms"], 200);
    assert_eq!(
        shared
            .lock()
            .unwrap()
            .image_frontmost
            .load(Ordering::SeqCst),
        OTHER_APPLICATION_PID
    );
    assert_eq!(row["image_decision"], "fronted_then_visible");
}
