//! Browser actions exercise held consent through the real frame dispatcher.

use super::*;
use crate::browser::navigation::BrowserSnapshotObservation;
use crate::browser_session::*;
use crate::classification::{
    classify_click, ElementClassificationInput, NodeIdentityInput, NonTypeClassificationInput,
    TargetKind,
};
use crate::snapshot_store::{
    AxRecord, BackendNodeIdentity, CommittedDocument, DocumentTransition, RefRecord, SnapshotKind,
    SnapshotRef,
};
use std::sync::{atomic::AtomicUsize, Mutex};

const PAGE_TEXT: &str = "held-page-text-must-never-reach-call-records-8d741";
const PNG: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII=";

#[derive(Default)]
struct Page {
    navigation_attempts: AtomicUsize,
    navigations: AtomicUsize,
    inputs: AtomicUsize,
    private_redirect: std::sync::atomic::AtomicBool,
    gate: Mutex<Option<Arc<tokio::sync::Semaphore>>>,
    navigation_started: tokio::sync::Notify,
    url: Mutex<String>,
}

struct Browser(Arc<Page>);

fn classification(epoch: u64) -> crate::classification::NonTypeClassificationRecord {
    classify_click(&NonTypeClassificationInput::new(
        epoch,
        ElementClassificationInput::new(
            NodeIdentityInput::new("target", "frame", 42),
            TargetKind::Button,
        ),
        "https://example.com",
    ))
    .unwrap()
}

impl OwnedBrowserProcess for Browser {
    fn navigate(
        &mut self,
        _: &str,
        url: &str,
        _: NavigationWait,
        _: u64,
        tracker: &mut browser::Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.0.navigation_attempts.fetch_add(1, Ordering::SeqCst);
        let gate = self.0.gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            self.0.navigation_started.notify_one();
            tokio::runtime::Handle::current()
                .block_on(gate.acquire())
                .unwrap()
                .forget();
        }
        self.0.navigations.fetch_add(1, Ordering::SeqCst);
        *self.0.url.lock().unwrap() = url.into();
        tracker.url_final = Some(url.into());
        if self.0.private_redirect.load(Ordering::SeqCst) {
            tracker.url_final = Some("https://127.0.0.1/private".into());
            tracker.main_frame_network.private_origin_seen = true;
        }
        tracker.load_observed = true;
        Ok(())
    }
    fn committed_document(
        &mut self,
        _: &str,
        _: u64,
    ) -> Result<CommittedDocument, NavigationDriveError> {
        Ok(CommittedDocument::new(
            self.0.url.lock().unwrap().clone(),
            1,
            "loader",
        ))
    }
    fn snapshot(
        &mut self,
        _: &str,
        _: SnapshotKind,
        _: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        Ok(BrowserSnapshotObservation {
            records: vec![AxRecord {
                depth: 0,
                role: "document".into(),
                name: PAGE_TEXT.into(),
                value: None,
                reference: None,
            }],
            dom_text: Some(PAGE_TEXT.into()),
            refs: vec![],
            ax_truncated: false,
            refs_truncated: false,
            facts: Default::default(),
        })
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
            crate::classification::NonTypeClassificationRecord,
            crate::classification::ClassificationUnavailable,
        >,
        NavigationDriveError,
    > {
        Ok(Ok(classification(epoch)))
    }
    fn click_point_classified(
        &mut self,
        _: &str,
        _: BrowserClickPosition,
        _: u64,
        _: &str,
        _: &crate::classification::NonTypeClassificationRecord,
        _: u64,
        _: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.0.inputs.fetch_add(1, Ordering::SeqCst);
        panic!("a held coordinate click must not dispatch")
    }
    fn click_classified(
        &mut self,
        _: &str,
        _: &BackendNodeIdentity,
        _: u64,
        _: &str,
        _: Option<&crate::classification::NonTypeClassificationRecord>,
        _: u64,
        _: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.0.inputs.fetch_add(1, Ordering::SeqCst);
        panic!("a stale held ref must not dispatch")
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

async fn fixture() -> (
    Planes,
    tests::ScriptedConsent,
    Arc<Page>,
    journal::call_records::InMemoryCallRecordStorage,
) {
    fixture_with_consent(true, Planes::short_test_browser_config()).await
}

async fn fixture_with_consent(
    detached: bool,
    config: BrowserConfig,
) -> (
    Planes,
    tests::ScriptedConsent,
    Arc<Page>,
    journal::call_records::InMemoryCallRecordStorage,
) {
    let consent = tests::ScriptedConsent::new();
    if detached {
        detach(&consent, "browser-card");
    } else {
        consent.raises("browser-card");
    }
    let mut planes = attach_consent(
        Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config),
            JournalPersistence::Isolated,
        ),
        &consent,
    );
    let storage = journal::call_records::InMemoryCallRecordStorage::new();
    planes.calls = Arc::new(journal::call_records::CallRecords::open(
        Box::new(storage.clone()),
        wall_clock_ms(),
    ));
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .unwrap()
            .with_shared_grants(planes.management.browser_grants()),
    );
    bind_held(&planes).await;
    let page = Arc::new(Page::default());
    *page.url.lock().unwrap() = "https://example.com".into();
    assert!(matches!(
        planes.sessions.acquire_launch_slot("head-conversation"),
        LaunchSlot::Acquired { .. }
    ));
    planes
        .sessions
        .establish_ready(
            "head-conversation",
            ProfileDisposition::Disposable,
            planes.browser_config.as_ref().unwrap(),
            planes.lease_clock.as_ref(),
            Box::new(Browser(page.clone())),
            Box::new(Cleanup),
        )
        .unwrap();
    let identity = &planes.routes.get(8, 3).unwrap().identity;
    planes.browser.open_context(identity.clone()).await.unwrap();
    (planes, consent, page, storage)
}

fn navigate_request() -> Value {
    json!({"name":"browser_use","call_key":"held-navigation","arguments":{
        "action":"navigate","url":"https://example.com/destination","wait":"none","read_page":true,
        "severity":{"tier":3,"credential":false,"financial":false},"intent":"read the approved destination"}})
}

async fn start_navigation(planes: &Planes) {
    assert_held(
        &decode(exchange(planes, 9, 3, navigate_request()).await),
        "consent",
    );
    assert_eq!(planes.calls.browser_request_count(), 1);
}

fn session_status(planes: &Planes) -> Value {
    planes.sessions.status(
        "head-conversation",
        planes.lease_clock.as_ref(),
        std::time::SystemTime::now(),
    )
}

fn advance_and_sweep(planes: &Planes, elapsed: Duration) {
    planes.lease_clock.advance_for_test(elapsed);
    planes.sessions.expire_all(
        planes.lease_clock.as_ref(),
        planes.browser_config.as_ref().unwrap(),
    );
}

fn idle_timeout(planes: &Planes) -> Duration {
    Duration::from_millis(
        planes
            .browser_config
            .as_ref()
            .unwrap()
            .browser_idle_timeout_ms,
    )
}

fn assert_idles_after_full_timeout(planes: &Planes) {
    let tick = Duration::from_millis(1);
    advance_and_sweep(planes, idle_timeout(planes) - tick);
    assert_eq!(session_status(planes)["outcome"], "ready");
    advance_and_sweep(planes, tick);
    assert_eq!(session_status(planes)["terminal_outcome"], "idle_expired");
}

#[tokio::test]
async fn late_held_approval_keeps_the_same_session_past_its_idle_deadline() {
    let (planes, consent, page, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    let session = session_status(&planes)["browser_session_id"].clone();
    start_navigation(&planes).await;
    advance_and_sweep(&planes, idle_timeout(&planes) + Duration::from_secs(1));

    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late_key(&planes, 9, "held-navigation").await;
    assert_eq!(reply["entries"][0]["kind"], "result", "{reply}");
    assert_eq!(
        reply["entries"][0]["result"]["structuredContent"]["outcome"], "ok",
        "{reply}"
    );
    assert_eq!(page.navigations.load(Ordering::SeqCst), 1);
    let status = session_status(&planes);
    assert_eq!(status["outcome"], "ready", "{status}");
    assert_eq!(status["browser_session_id"], session);
}

#[tokio::test]
async fn explicit_close_is_not_blocked_by_held_consent() {
    let (planes, consent, page, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    let session = session_status(&planes)["browser_session_id"].clone();
    start_navigation(&planes).await;
    advance_and_sweep(&planes, idle_timeout(&planes));
    consent.feed(json!([]));
    let close = decode(
        exchange(
            &planes,
            8,
            10,
            json!({"name":"browser_use","arguments":{
                "action":"close","browser_session_id":session,
            }}),
        )
        .await,
    );
    assert_eq!(close["outcome"], "closed", "{close}");
    assert_eq!(session_status(&planes)["terminal_outcome"], "closed");

    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late_key(&planes, 9, "held-navigation").await;
    assert_eq!(reply["entries"][0]["kind"], "result", "{reply}");
    assert_eq!(
        reply["entries"][0]["result"]["structuredContent"]["outcome"], "no_session",
        "{reply}"
    );
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

/// The approved continuation re-enters the dispatcher with the original
/// request's address, but its reply goes to the late-result store, not to
/// the live connection. It must not leave a delivery deadline on that
/// connection, or the connection is torn down long after the call succeeded.
/// Every request here, late pulls included, travels the real egress drain.
#[tokio::test]
async fn a_resumed_continuation_leaves_no_delivery_deadline_on_the_live_connection() {
    let (planes, consent, page, _) = fixture().await;
    let deadlines = Arc::clone(&planes.egress_deadlines);
    let (mut peer, socket) = tokio::io::duplex(1 << 20);
    let (inbound, mut received) = mpsc::channel(64);
    let reader = tokio::spawn(async move {
        while let Ok(Some(frame)) = subc_transport::read_frame(&mut peer).await {
            if inbound.send(frame).await.is_err() {
                break;
            }
        }
    });
    async fn call(
        planes: &Planes,
        tx: &mpsc::Sender<Frame>,
        received: &mut mpsc::Receiver<Frame>,
        corr: &mut u64,
        body: Value,
    ) -> Value {
        *corr += 1;
        handle_frame_for_test(request(9, *corr, body), tx, planes)
            .await
            .unwrap();
        let reply = tokio::time::timeout(HANG_GUARD, received.recv())
            .await
            .expect("the connection answers")
            .unwrap();
        // The writer clears a request's deadline just after its flush.
        tokio::time::timeout(HANG_GUARD, async {
            let delivering = || {
                let pending = planes.egress_deadlines.pending.lock().unwrap();
                pending.keys().any(|request| request.2 == *corr)
            };
            while delivering() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the writer acknowledges the reply");
        decode(reply)
    }
    let connection = crate::drive_connection(socket, deadlines, move |tx| async move {
        let mut corr = 3;
        let pull = || json!({"name":"late_results","arguments":{"since":null}});
        let reply = call(&planes, &tx, &mut received, &mut corr, navigate_request()).await;
        assert_held(&reply, "consent");
        consent.feed(json!([answered("browser-card", "allow_30m")]));
        let settled = tokio::time::timeout(HANG_GUARD, async {
            loop {
                let reply = call(&planes, &tx, &mut received, &mut corr, pull()).await;
                if reply["entries"][0]["kind"] == "result" {
                    return reply;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("the held call settles");
        assert_eq!(
            settled["entries"][0]["call_key"], "held-navigation",
            "{settled}"
        );
        assert_eq!(page.navigations.load(Ordering::SeqCst), 1);
        // Past any reply budget, the same connection must still serve. The
        // sleep lets the connection driver poll its deadline watch.
        tokio::time::pause();
        tokio::time::advance(Duration::from_secs(60 * 60)).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
        tokio::time::resume();
        let again = call(&planes, &tx, &mut received, &mut corr, pull()).await;
        assert!(again["entries"].is_array(), "{again}");
        Ok(())
    })
    .await;
    connection.expect("the connection outlives the resumed call");
    reader.abort();
}

/// A consumer may lose a late_results response or restart before it commits
/// its cursor. Until it acknowledges, pulling again must return the same
/// observed result, not the conservative outcome_unknown left on disk.
#[tokio::test]
async fn a_resumed_result_is_pulled_again_until_acknowledged() {
    let (planes, consent, _page, _) = fixture().await;
    start_navigation(&planes).await;
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let first = late_key(&planes, 9, "held-navigation").await;
    let observed = &first["entries"][0]["result"];
    assert_eq!(observed["structuredContent"]["outcome"], "ok", "{first}");
    let again = late(&planes, 9).await;
    assert_eq!(again["entries"][0]["result"], *observed, "{again}");
    let acked = decode(
        exchange(
            &planes,
            9,
            51,
            json!({"name":"late_results.ack","arguments":{"through":again["cursor"]}}),
        )
        .await,
    );
    assert_eq!(acked, json!({}), "{acked}");
    let after = late(&planes, 9).await;
    assert!(
        !after["entries"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["call_key"] == "held-navigation"),
        "{after}"
    );
}

#[tokio::test]
async fn approval_while_held_runs_navigate_and_returns_its_page_without_persisting_text() {
    let (planes, consent, page, storage) = fixture().await;
    start_navigation(&planes).await;
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late_key(&planes, 9, "held-navigation").await;
    let entry = &reply["entries"][0];
    assert_eq!(entry["kind"], "result", "{reply}");
    let body = &entry["result"]["structuredContent"];
    assert_eq!(body["outcome"], "ok", "{reply}");
    assert_eq!(body["url_final"], "https://example.com/destination");
    assert!(
        body["state_text"].as_str().unwrap().contains(PAGE_TEXT),
        "{reply}"
    );
    assert_eq!(page.navigations.load(Ordering::SeqCst), 1);
    assert_eq!(planes.calls.browser_request_count(), 0);
    let disk = String::from_utf8(storage.contents().unwrap()).unwrap();
    assert!(!disk.contains(PAGE_TEXT));
    let restarted = journal::call_records::CallRecords::open(Box::new(storage), wall_clock_ms());
    let after_restart = restarted
        .late_results(
            "reserved:basal",
            &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
            wall_clock_ms(),
        )
        .unwrap();
    assert_eq!(
        after_restart.entries[0].result.as_ref().unwrap()["outcome"],
        "outcome_unknown"
    );
}

#[tokio::test]
async fn stale_ref_after_held_approval_names_stale_snapshot_without_input() {
    let (planes, consent, page, _) = fixture().await;
    let identity = &planes.routes.get(8, 3).unwrap().identity;
    let snapshot = planes
        .browser
        .retain_text_snapshot(
            identity,
            SnapshotKind::Ax,
            &[AxRecord {
                depth: 0,
                role: "button".into(),
                name: "Access".into(),
                value: None,
                reference: Some("e1".into()),
            }],
            None,
            vec![RefRecord {
                frame_document: None,
                captured: SnapshotRef::new("e1", "button", "Access", 0).unwrap(),
                frame_path: vec!["frame".into()],
                backend_identity: Some(BackendNodeIdentity::new("target", "frame", 42).unwrap()),
                raw_role: None,
                raw_name: None,
                classification: Ok(Box::new(classification(0))),
            }],
            4096,
            Some(CommittedDocument::new("https://example.com", 1, "loader")),
        )
        .await
        .unwrap();
    let request = json!({"name":"browser_use","call_key":"held-ref","arguments":{"action":"click","ref":"e1","snapshot_id":snapshot["snapshot_id"],"severity":{"tier":3,"credential":false,"financial":false},"intent":"press the shown button"}});
    assert_held(&decode(exchange(&planes, 9, 3, request).await), "consent");
    planes
        .browser
        .replace_document(identity, DocumentTransition::TopLevelDocumentReplaced)
        .await
        .unwrap();
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late_key(&planes, 9, "held-ref").await;
    let entry = &reply["entries"][0];
    assert_eq!(entry["kind"], "not_started", "{reply}");
    assert_eq!(entry["reason"], "stale_snapshot", "{reply}");
    assert_eq!(
        entry["result"]["structuredContent"]["reason"],
        "stale_snapshot"
    );
    assert_eq!(page.inputs.load(Ordering::SeqCst), 0);
    assert_eq!(planes.calls.browser_request_count(), 0);
}

#[tokio::test]
async fn refused_private_landing_after_navigation_is_not_misreported_as_not_started() {
    let (planes, consent, page, _) = fixture().await;
    page.private_redirect.store(true, Ordering::SeqCst);
    start_navigation(&planes).await;
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late_key(&planes, 9, "held-navigation").await;
    assert_eq!(reply["entries"][0]["kind"], "result", "{reply}");
    assert_eq!(
        reply["entries"][0]["result"]["structuredContent"]["outcome"], "authorization_denied",
        "{reply}"
    );
    assert_eq!(page.navigations.load(Ordering::SeqCst), 1);
    assert_eq!(
        consent.cards().len(),
        1,
        "resumption must not raise a replacement consent question"
    );
}

#[tokio::test]
async fn held_click_point_never_runs_after_approval() {
    let (planes, consent, page, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    let identity = &planes.routes.get(8, 3).unwrap().identity;
    let view = coordinate::ViewportObservation::new(
        0,
        coordinate::TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
    );
    let snapshot = planes
        .browser
        .retain_screenshot(
            identity,
            coordinate::ScreenshotPayload::new(PNG, 1, 1),
            view,
            view,
            false,
            Some(CommittedDocument::new("https://example.com", 1, "loader")),
        )
        .await
        .unwrap();
    let request = json!({"name":"browser_use","call_key":"held-point","arguments":{"action":"click_point","snapshot_id":snapshot["snapshot_id"],"point":{"x":0,"y":0},"image_width_px":1,"image_height_px":1,"severity":{"tier":3,"credential":false,"financial":false},"intent":"press at the old image position"}});
    assert_held(&decode(exchange(&planes, 9, 3, request).await), "consent");
    assert_eq!(planes.calls.browser_request_count(), 0);
    advance_and_sweep(&planes, idle_timeout(&planes));
    assert_eq!(session_status(&planes)["outcome"], "ready");
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late(&planes, 9).await;
    assert_eq!(reply["entries"][0]["kind"], "not_started", "{reply}");
    assert_eq!(reply["entries"][0]["detail"]["consent"], "approved");
    assert_eq!(page.inputs.load(Ordering::SeqCst), 0);
    assert_idles_after_full_timeout(&planes);
}

#[tokio::test]
async fn late_approval_after_explicit_withdrawal_cannot_run_the_navigation() {
    let (planes, consent, page, _) = fixture().await;
    start_navigation(&planes).await;
    consent.feed(json!([]));
    let withdraw = decode(
        exchange(
            &planes,
            9,
            4,
            json!({"name":"tool.withdraw","arguments":{"call_key":"held-navigation"}}),
        )
        .await,
    );
    assert_eq!(withdraw["answer"], "withdrawn", "{withdraw}");
    assert_eq!(planes.calls.browser_request_count(), 0);
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late(&planes, 9).await;
    assert_eq!(reply["entries"][0]["kind"], "not_started", "{reply}");
    assert_eq!(reply["entries"][0]["detail"]["consent"], "withdrawn");
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn cancel_after_first_held_reply_removes_the_original_request() {
    let (planes, consent, page, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    start_navigation(&planes).await;
    advance_and_sweep(&planes, idle_timeout(&planes));
    assert_eq!(session_status(&planes)["outcome"], "ready");
    let mut cancel = request(9, 3, json!({}));
    cancel.header.ty = FrameType::Cancel;
    let (writer, _) = mpsc::channel(16);
    handle_frame_for_test(cancel, &writer, &planes)
        .await
        .unwrap();
    assert_eq!(planes.calls.browser_request_count(), 0);
    assert_idles_after_full_timeout(&planes);
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    assert_eq!(late(&planes, 9).await["entries"][0]["kind"], "not_started");
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

/// A CANCEL's journal settlement runs after the wire loop moves on, so an
/// approval can land before it. The latch the wire loop sets first must keep
/// that approval from running the cancelled call.
#[tokio::test]
async fn an_approval_before_a_cancel_settles_cannot_run_the_cancelled_call() {
    let (planes, consent, page, _) = fixture().await;
    start_navigation(&planes).await;
    planes.calls.latch_correlation((9, 3, 3));
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    // One pull drains the approval; give a wrongly claimed call time to run.
    late(&planes, 9).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
    planes
        .calls
        .abandon_browser_correlation(9, 3, 3, wall_clock_ms());
    let reply = late(&planes, 9).await;
    assert_eq!(reply["entries"][0]["kind"], "not_started", "{reply}");
    assert_eq!(reply["entries"][0]["detail"]["consent"], "withdrawn");
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn deny_and_card_expiry_remove_the_original_request() {
    for record in [
        answered("browser-card", "deny"),
        json!({"elicitation_id":"browser-card","state":"expired"}),
    ] {
        let (planes, consent, page, _) = fixture().await;
        planes.lease_clock.pause_for_test();
        start_navigation(&planes).await;
        advance_and_sweep(&planes, idle_timeout(&planes));
        assert_eq!(session_status(&planes)["outcome"], "ready");
        consent.feed(json!([record]));
        assert_eq!(late(&planes, 9).await["entries"][0]["kind"], "not_started");
        assert_eq!(planes.calls.browser_request_count(), 0);
        assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
        assert_idles_after_full_timeout(&planes);
    }
}

#[tokio::test]
async fn route_end_removes_the_original_request() {
    let (planes, _, page, _) = fixture().await;
    start_navigation(&planes).await;
    let mut goodbye = request(9, 4, json!({}));
    goodbye.header.ty = FrameType::Goodbye;
    let (writer, _) = mpsc::channel(16);
    handle_frame_for_test(goodbye, &writer, &planes)
        .await
        .unwrap();
    assert_eq!(planes.calls.browser_request_count(), 0);
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn scope_end_removes_the_original_request() {
    let (planes, _, page, _) = fixture().await;
    start_navigation(&planes).await;
    let scope = journal::call_records::ScopeIdentity::from_stamp(
        planes.routes.get(9, 3).unwrap().scope.as_ref().unwrap(),
    );
    planes
        .calls
        .end_held_scope(&scope, wall_clock_ms())
        .unwrap();
    assert_eq!(planes.calls.browser_request_count(), 0);
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn head_scope_end_releases_the_session_for_idle_expiry() {
    let (planes, _, _, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    start_navigation(&planes).await;
    advance_and_sweep(&planes, idle_timeout(&planes));
    assert_eq!(session_status(&planes)["outcome"], "ready");
    let facts = planes.routes.get(9, 3).unwrap();
    let head_scope = facts
        .codemode_head
        .as_ref()
        .unwrap()
        .scope
        .as_ref()
        .unwrap();
    assert_ne!(Some(head_scope), facts.scope.as_ref());
    settle_scope_holds(&planes, &scope_watch::ScopeKey::from_stamp(head_scope));
    crate::call_record_supervisor::settled_in_order(&planes).await;
    assert_idles_after_full_timeout(&planes);
}

#[tokio::test]
async fn a_lost_consent_ending_cannot_pin_the_session_forever() {
    let (planes, _, _, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    start_navigation(&planes).await;
    advance_and_sweep(&planes, journal::call_records::CACHE_MAX_AGE);
    assert_idles_after_full_timeout(&planes);
}

#[tokio::test]
async fn scope_end_push_settles_held_calls_for_the_current_owner() {
    let (planes, _, _, _) = fixture().await;
    start_navigation(&planes).await;
    let scope =
        scope_watch::ScopeKey::from_stamp(planes.routes.get(9, 3).unwrap().scope.as_ref().unwrap());
    let identity = held_scope_identity(&scope);
    assert!(planes.calls.has_pending_scope(&identity));
    let push = json!({"op":"route.closed", "module_id":"cerebellum", "reason":"scope_ended", "channels":[9], "drained":true, "abandoned":0});
    serde_json::from_value::<subc_control::ClientControlPush>(push.clone()).unwrap();
    let frame = Frame::build(
        FrameType::Push,
        crate::control_flags(),
        0,
        0,
        0,
        serde_json::to_vec(&push).unwrap(),
    )
    .unwrap();
    let (writer, mut requests) = mpsc::channel(16);
    handle_frame_for_test(frame, &writer, &planes)
        .await
        .unwrap();
    assert!(!planes.calls.has_pending_scope(&identity));
    assert!(requests.try_recv().is_err());
}

#[tokio::test]
async fn session_end_removes_the_original_request() {
    let (planes, _, page, _) = fixture().await;
    start_navigation(&planes).await;
    planes
        .calls
        .end_consent_conversation("head-conversation", wall_clock_ms())
        .unwrap();
    assert_eq!(planes.calls.browser_request_count(), 0);
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn resume_and_withdrawal_race_produce_exactly_one_result() {
    let (planes, _, _, _) = fixture().await;
    start_navigation(&planes).await;
    let calls = &planes.calls;
    calls
        .finish_consent(
            "browser-card",
            journal::call_records::ConsentEnding::Approved,
            wall_clock_ms(),
        )
        .unwrap();
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let claiming = scope.spawn(|| {
            barrier.wait();
            calls
                .claim_browser_request("reserved:basal", "held-navigation", wall_clock_ms(), |_| {
                    true
                })
                .unwrap()
        });
        barrier.wait();
        calls
            .abandon_browser_request("reserved:basal", "held-navigation", wall_clock_ms())
            .unwrap();
        if let Some(resume) = claiming.join().unwrap() {
            let mut result = resume.frame;
            result.header.ty = FrameType::Response;
            result.body = serde_json::to_vec(&json!({"outcome":"ok"})).unwrap();
            calls
                .finish_browser_request(
                    "reserved:basal",
                    "held-navigation",
                    result,
                    false,
                    wall_clock_ms(),
                )
                .unwrap();
        }
    });
    let reply = calls
        .late_results(
            "reserved:basal",
            &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
            wall_clock_ms(),
        )
        .unwrap();
    assert_eq!(reply.entries.len(), 1, "{reply:?}");
    assert_eq!(calls.browser_request_count(), 0);
}

#[tokio::test]
async fn replaced_head_bind_cannot_resume_even_when_its_facts_are_identical() {
    let (planes, consent, page, _) = fixture().await;
    start_navigation(&planes).await;
    let original = planes.routes.remove(8, 3).unwrap();
    planes.routes.insert(8, 3, original);
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late(&planes, 9).await;
    assert_eq!(reply["entries"][0]["kind"], "not_started", "{reply}");
    assert_eq!(reply["entries"][0]["detail"]["consent"], "approved");
    assert_eq!(planes.calls.browser_request_count(), 0);
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn expired_memory_hold_keeps_approval_for_a_fresh_call_without_running() {
    let (planes, consent, page, _) = fixture().await;
    start_navigation(&planes).await;
    let mut body = navigate_request();
    body.as_object_mut().unwrap().remove("call_key");
    planes.calls.retain_browser_request(
        "reserved:basal",
        "held-navigation",
        Some(journal::call_records::BrowserResume {
            frame: request(9, 3, body),
            facts: planes.routes.get(9, 3).unwrap(),
            bind_sequence: planes.routes.bind_sequence(9, 3).unwrap(),
            head: Some(((8, 3), planes.routes.bind_sequence(8, 3).unwrap())),
            approved: false,
            ask_id: String::new(),
            created: std::time::Instant::now()
                - journal::call_records::CACHE_MAX_AGE
                - Duration::from_secs(1),
            idle_hold: None,
        }),
        None,
        &planes.browser_resumes,
    );
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let reply = late(&planes, 9).await;
    assert_eq!(reply["entries"][0]["kind"], "not_started", "{reply}");
    assert_eq!(reply["entries"][0]["detail"]["consent"], "approved");
    assert_eq!(planes.calls.browser_request_count(), 0);
    assert_eq!(page.navigations.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn held_request_registry_is_bounded_by_count_and_argument_bytes() {
    let (planes, _, _, _) = fixture().await;
    let facts = planes.routes.get(9, 3).unwrap();
    for index in 0..=journal::call_records::CACHE_MAX_REPLIES {
        let key = format!("bounded-{index}");
        assert!(matches!(
            planes
                .calls
                .begin("reserved:basal", &key, "head-conversation", wall_clock_ms()),
            journal::call_records::Begin::Execute(_)
        ));
        browser_held::retain(
            &planes,
            &facts,
            &key,
            &request(9, 100 + index as u64, navigate_request()),
        );
    }
    assert_eq!(
        planes.calls.browser_request_count(),
        journal::call_records::CACHE_MAX_REPLIES
    );
    planes.calls.end_conversation("head-conversation");
    assert_eq!(planes.calls.browser_request_count(), 0);
    let mut oversized = navigate_request();
    oversized["arguments"]["text"] =
        json!("x".repeat(journal::call_records::CACHE_MAX_REPLY_BYTES));
    browser_held::retain(&planes, &facts, "bounded-0", &request(9, 100, oversized));
    assert_eq!(planes.calls.browser_request_count(), 0);
    for index in 0..9 {
        let mut body = navigate_request();
        body["arguments"]["text"] =
            json!("x".repeat(journal::call_records::CACHE_MAX_REPLY_BYTES - 1024));
        browser_held::retain(
            &planes,
            &facts,
            &format!("bounded-{index}"),
            &request(9, 100, body),
        );
    }
    assert_eq!(planes.calls.browser_request_count(), 8);
}

#[test]
fn browser_late_approval_classification_keeps_refs_but_never_image_coordinates() {
    for action in [
        "navigate",
        "snapshot",
        "screenshot",
        "scroll",
        "status",
        "launch",
        "open_tab",
        "claim_tab",
        "close",
        "open_grant",
        "present",
        "resume",
        "import_login",
        "capture_login",
        "fill_login",
        "revoke_access",
        "click",
        "type",
    ] {
        assert!(
            browser_held::can_resume(&json!({"action":action})),
            "{action}"
        );
    }
    assert!(!browser_held::can_resume(&json!({"action":"click_point"})));
    assert!(!browser_held::can_resume(
        &json!({"action":"click","point":{"x":1,"y":2}})
    ));
}

#[tokio::test]
async fn direct_navigation_already_runs_when_approval_arrives_in_call() {
    let (planes, consent, page, _) =
        fixture_with_consent(false, Planes::short_test_browser_config()).await;
    consent.script.then(
        cingulate_client::wire::CONSENT_AWAIT,
        cingulate_client::Reply::Result(answered("browser-card", "allow_30m")),
    );
    let mut request = navigate_request();
    request.as_object_mut().unwrap().remove("call_key");
    let reply = decode(exchange(&planes, 8, 3, request).await);
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(page.navigations.load(Ordering::SeqCst), 1);
    assert_eq!(planes.calls.browser_request_count(), 0);
}

#[tokio::test]
async fn direct_coordinate_click_does_not_run_after_waiting_for_approval() {
    let (planes, consent, page, _) =
        fixture_with_consent(false, Planes::short_test_browser_config()).await;
    consent.script.then(
        cingulate_client::wire::CONSENT_AWAIT,
        cingulate_client::Reply::Result(answered("browser-card", "allow_30m")),
    );
    let identity = &planes.routes.get(8, 3).unwrap().identity;
    let view = coordinate::ViewportObservation::new(
        0,
        coordinate::TransformInputs::from_values(0.0, 0.0, 1.0, 1.0, 1.0, 1.0),
    );
    let snapshot = planes
        .browser
        .retain_screenshot(
            identity,
            coordinate::ScreenshotPayload::new(PNG, 1, 1),
            view,
            view,
            false,
            Some(CommittedDocument::new("https://example.com", 1, "loader")),
        )
        .await
        .unwrap();
    let request = json!({"name":"browser_use","arguments":{"action":"click_point","snapshot_id":snapshot["snapshot_id"],"point":{"x":0,"y":0},"image_width_px":1,"image_height_px":1,"severity":{"tier":3,"credential":false,"financial":false},"intent":"press at the old image position"}});
    let reply = decode(exchange(&planes, 8, 3, request).await);
    assert_eq!(reply["outcome"], "not_started", "{reply}");
    assert_eq!(reply["detail"]["consent"], "approved");
    assert_eq!(page.inputs.load(Ordering::SeqCst), 0);
    assert_eq!(planes.calls.browser_request_count(), 0);
}

async fn queued_fixture(
    per_head: usize,
    global: usize,
) -> (
    Planes,
    tests::ScriptedConsent,
    Arc<Page>,
    Arc<tokio::sync::Semaphore>,
) {
    let (mut planes, consent, page, _) = fixture().await;
    planes.lease_clock.pause_for_test();
    planes.browser_resumes = Arc::new(browser_held::Tasks::new(per_head, global));
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    *page.gate.lock().unwrap() = Some(gate.clone());
    for index in 0..3 {
        if index > 0 {
            consent.feed(json!([]));
        }
        let mut request = navigate_request();
        request["call_key"] = json!(format!("queued-{index}"));
        assert_held(
            &decode(exchange(&planes, 9, 3 + index, request).await),
            "consent",
        );
    }
    consent.feed(json!([answered("browser-card", "allow_30m")]));
    let ready = tokio::time::timeout(HANG_GUARD, async {
        let _ = late(&planes, 9).await;
        page.navigation_started.notified().await;
    })
    .await;
    let counts = planes.browser_resumes.counts();
    if ready.is_err() || counts != (3, 1) {
        // Unblock the mock before unwinding so runtime shutdown can join it.
        gate.add_permits(3);
        panic!("expected one continuation at the browser and two waiting in the bounded task queue; readiness: {ready:?}, counts (total, active): {counts:?}");
    }
    (planes, consent, page, gate)
}

#[tokio::test]
async fn idle_window_starts_when_the_last_queued_resumption_finishes() {
    let (planes, _, page, gate) = queued_fixture(1, 1).await;
    advance_and_sweep(&planes, idle_timeout(&planes));
    gate.add_permits(2);
    let third_started = tokio::time::timeout(HANG_GUARD, async {
        while page.navigation_attempts.load(Ordering::SeqCst) != 3 {
            tokio::task::yield_now().await;
        }
    })
    .await;
    advance_and_sweep(&planes, idle_timeout(&planes));
    gate.add_permits(3);
    third_started.expect("the last queued call was admitted past the original deadline");
    tokio::time::timeout(HANG_GUARD, async {
        while planes.browser_resumes.counts() != (0, 0) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the last continuation finishes");
    assert_eq!(page.navigations.load(Ordering::SeqCst), 3);
    assert_idles_after_full_timeout(&planes);
}

#[tokio::test]
async fn queued_resumptions_obey_both_global_and_per_head_caps_without_blocking_the_poll() {
    for (per_head, global) in [(1, 2), (2, 1)] {
        let (planes, _consent, page, gate) = queued_fixture(per_head, global).await;
        let ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = planes.health.report()
        else {
            panic!("health metrics")
        };
        assert!(metrics["inFlightActions"].as_u64().unwrap() > 0);
        gate.add_permits(3);
        tokio::time::timeout(HANG_GUARD, async {
            while planes.browser_resumes.counts().0 != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("all queued resumptions eventually finish");
        assert_eq!(page.navigations.load(Ordering::SeqCst), 3);
    }
}

#[tokio::test]
async fn original_key_withdraw_and_cancel_stop_queued_resumptions_before_dispatch() {
    let (planes, _consent, page, gate) = queued_fixture(1, 1).await;
    // The key whose request reached the driver is deliberately not selected:
    // hash-map iteration does not promise which approved call runs first.
    let active = planes.browser_resumes.active_keys();
    let queued: Vec<_> = (0..3)
        .filter(|index| !active.contains(&format!("queued-{index}")))
        .collect();
    let key = format!("queued-{}", queued[0]);
    let _ = decode(
        exchange(
            &planes,
            9,
            20,
            json!({"name":"tool.withdraw","arguments":{"call_key":key}}),
        )
        .await,
    );
    let mut cancel = request(9, 3 + queued[1], json!({}));
    cancel.header.ty = FrameType::Cancel;
    let (writer, _) = mpsc::channel(16);
    handle_frame_for_test(cancel, &writer, &planes)
        .await
        .unwrap();
    gate.add_permits(3);
    tokio::time::timeout(HANG_GUARD, async {
        while planes.browser_resumes.counts().0 != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cancelled queued calls leave the registry");
    assert_eq!(page.navigations.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn module_teardown_aborts_and_joins_owned_resumptions_within_its_existing_budget() {
    let (planes, _consent, _page, gate) = queued_fixture(1, 1).await;
    let teardown = ShutdownTeardown::new(
        planes.sessions.clone(),
        None,
        None,
        None,
        planes.user_browser.clone(),
        Arc::clone(&planes.private_content),
        Arc::clone(&planes.browser_resumes),
    );
    tokio::time::timeout(
        browser_session::SHUTDOWN_TEARDOWN_BUDGET,
        teardown.run_or_join(),
    )
    .await
    .expect("owned resumptions do not extend teardown");
    assert_eq!(planes.browser_resumes.counts(), (0, 0));
    gate.add_permits(3);
}

#[tokio::test]
async fn route_scope_and_session_end_cancel_queued_owned_resumptions() {
    for ending in ["route", "scope", "session", "rebind"] {
        let (planes, _consent, page, gate) = queued_fixture(1, 1).await;
        match ending {
            "route" => {
                let mut goodbye = request(9, 30, json!({}));
                goodbye.header.ty = FrameType::Goodbye;
                let (writer, _) = mpsc::channel(16);
                handle_frame_for_test(goodbye, &writer, &planes)
                    .await
                    .unwrap();
            }
            "scope" => {
                let scope = scope_watch::ScopeKey::from_stamp(
                    planes.routes.get(9, 3).unwrap().scope.as_ref().unwrap(),
                );
                settle_scope_holds(&planes, &scope);
                crate::call_record_supervisor::settled_in_order(&planes).await;
            }
            "session" => forget_conversation_cards(&planes, "head-conversation"),
            _ => {
                let head = planes.routes.remove(8, 3).unwrap();
                planes.routes.insert(8, 3, head);
            }
        }
        gate.add_permits(3);
        tokio::time::timeout(HANG_GUARD, async {
            while planes.browser_resumes.counts().0 != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ended calls leave the owned task registry");
        assert!(
            page.navigations.load(Ordering::SeqCst) <= 1,
            "queued calls must not start after {ending} end"
        );
    }
}

#[tokio::test]
async fn module_draining_cancels_the_owned_resume_task_queue() {
    let (mut planes, _consent, _page, gate) = queued_fixture(1, 1).await;
    planes.browser_config = None;
    let frame = Frame::build(
        FrameType::Push,
        control_flags(),
        0,
        0,
        0,
        serde_json::to_vec(&json!({"op":"module.draining","reason":"restart","deadline_ms":123}))
            .unwrap(),
    )
    .unwrap();
    let (writer, _) = mpsc::channel(16);
    handle_frame_for_test(frame, &writer, &planes)
        .await
        .unwrap();
    planes
        .browser_resumes
        .stop_and_join(tokio::time::Instant::now() + browser_session::SHUTDOWN_TEARDOWN_BUDGET)
        .await;
    assert_eq!(planes.browser_resumes.counts(), (0, 0));
    gate.add_permits(3);
}
