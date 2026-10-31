//! Login-specific equivalents of tool-provider/v1's cursor and ack conformance cases.
//! Frames go through the production dispatcher; only the browser's CDP facts
//! are simulated, so these tests need no installed browser or real login.

use std::collections::BTreeSet;
use std::future::Future;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::support::HANG_GUARD;

use cerebellum::browser_session::{
    CleanupStage, NavigationDriveError, OwnedBrowserProcess, ProcessControlFailure, SessionCleanup,
    SessionCleanupOutcome, HANDOFF_DURATION_MS, HANDOFF_POLL_INTERVAL_MS,
};
use cerebellum::journal::call_records::{CallRecords, FilesystemCallRecordStorage, HandoffEnding};
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::format_floor::{read_floors, DurableFormat, FormatFloor};
use cerebellum_core::health::HealthState;
use cerebellum_core::identity::ProfileDisposition;
use cortexkit_role_tool_provider::late_results::{
    AckRequest, Cursor, LateEntry, LateResultsReply, LateResultsRequest,
};
use serde_json::{json, Value};
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

// `management_bounds::tests::a_handoff_poll_whose_record_write_hangs_ends_at_the_settle_bound`
// owns the poll-cadence claim on a paused clock. These file-backed integration
// waits only guard against a handoff or dispatcher that never settles.
const ORIGIN: &str = "https://login.example";
const OWNER: &str = "reserved:prefrontal-core";
const LEAKS: [&str; 3] = [
    "PLANTED_PAGE_TITLE_709",
    "PLANTED_URL_PATH_709",
    "PLANTED_COOKIE_709",
];
static SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn reserved(id: &str) -> Principal {
    Principal::Reserved {
        module_id: id.into(),
    }
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "cerebellum-late-results-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self(path)
    }
    fn store(&self) -> CallRecords {
        CallRecords::open(
            Box::new(
                FilesystemCallRecordStorage::new(self.0.join("call_records.jsonl"))
                    .with_format_floor(FormatFloor::at(self.0.join("format-floor.json"))),
            ),
            now_ms(),
        )
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct LoginFacts {
    logged_in: AtomicBool,
    credential_polled: AtomicBool,
    reads: AtomicU64,
    credential_unreadable: AtomicBool,
}
struct Browser(Arc<LoginFacts>);
impl OwnedBrowserProcess for Browser {
    fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
        Ok(())
    }
    fn cookie_names_for_origin(
        &mut self,
        _: &str,
        _: &str,
        _: u64,
    ) -> Result<BTreeSet<String>, NavigationDriveError> {
        self.0.reads.fetch_add(1, Ordering::SeqCst);
        Ok(if self.0.logged_in.load(Ordering::SeqCst) {
            BTreeSet::from([LEAKS[2].to_owned()])
        } else {
            BTreeSet::new()
        })
    }
    fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
        Ok(format!("{ORIGIN}/{}?title={}", LEAKS[1], LEAKS[0]))
    }
    fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
        if self.0.credential_unreadable.load(Ordering::SeqCst) {
            return Err(NavigationDriveError::Unavailable);
        }
        let present = !self.0.logged_in.load(Ordering::SeqCst);
        if present {
            self.0.credential_polled.store(true, Ordering::SeqCst);
        }
        Ok(present)
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
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        Ok(SessionCleanupOutcome::Complete)
    }
}

fn planes(scratch: &Scratch, ready: bool) -> (Planes, Arc<LoginFacts>) {
    let config = BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 60_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    };
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config.clone()),
        JournalPersistence::Isolated,
    );
    planes.calls = Arc::new(scratch.store());
    let logged_in = Arc::new(LoginFacts {
        logged_in: AtomicBool::new(false),
        credential_polled: AtomicBool::new(false),
        reads: AtomicU64::new(0),
        credential_unreadable: AtomicBool::new(false),
    });
    if ready {
        assert!(matches!(
            planes.sessions.acquire_launch_slot("test-session"),
            cerebellum::browser_session::LaunchSlot::Acquired { .. }
        ));
        assert!(planes
            .sessions
            .establish_ready(
                "test-session",
                ProfileDisposition::Disposable,
                &config,
                planes.lease_clock.as_ref(),
                Box::new(Browser(logged_in.clone())),
                Box::new(Cleanup)
            )
            .is_some());
    }
    (planes, logged_in)
}

fn frame(channel: u16, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        if channel == 0 { 0 } else { 3 },
        SEQUENCE.fetch_add(1, Ordering::Relaxed),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}
async fn exchange(planes: &Planes, request: Frame) -> Frame {
    let corr = request.header.corr;
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(request, &tx, planes)
        .await
        .unwrap();
    let response = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .expect("dispatcher replies within its deadline")
        .unwrap();
    assert_eq!(response.header.corr, corr);
    response
}
async fn call(planes: &Planes, channel: u16, name: &str, arguments: Value) -> Value {
    let reply = exchange(
        planes,
        frame(channel, json!({"name":name,"arguments":arguments})),
    )
    .await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    reply.get("structuredContent").cloned().unwrap_or(reply)
}
async fn bind(planes: &Planes, channel: u16, principal: Principal, management: bool) {
    bind_with_readers(planes, channel, principal, management, None).await;
}
async fn bind_with_readers(
    planes: &Planes,
    channel: u16,
    principal: Principal,
    management: bool,
    readers: Option<Vec<String>>,
) {
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: channel,
        epoch: 3,
        target: if management {
            RouteTarget::ManagementSurface {
                module_id: "cerebellum".into(),
            }
        } else {
            RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            }
        },
        identity: BindIdentity::new("test", "test-session"),
        principal: Some(principal),
        consumer_capabilities: readers,
        admission_facts: Some(
            json!({"agentProjectId":"pj-late-results","sessionKind":"primary","effectiveCapabilityScope":["*"],"browserControlOperations":["browser.present","browser.resume","browser.close"]}),
        ),
        scope: Some(
            ScopeStamp::new(reserved("prefrontal-core"), "scope-7", 3, ScopeKind::Head)
                .with_attributes(ScopeAttributes::default())
                .with_owner_authorized(true),
        ),
    };
    let reply = exchange(planes, frame(0, serde_json::to_value(bind).unwrap())).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
}
async fn present(planes: &Planes, key: Option<&str>) -> Value {
    let mut body = json!({"name":"browser_use","arguments":{"action":"present","origin":ORIGIN}});
    if let Some(key) = key {
        body["call_key"] = Value::String(key.into());
    }
    let reply = exchange(planes, frame(9, body)).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    reply.get("structuredContent").cloned().unwrap_or(reply)
}
async fn read(
    planes: &Planes,
    channel: u16,
    since: Option<Cursor>,
    limit: Option<u32>,
) -> LateResultsReply {
    let mut request = LateResultsRequest::new();
    if let Some(since) = since {
        request = request.with_since(since);
    }
    if let Some(limit) = limit {
        request = request.with_limit(limit);
    }
    serde_json::from_value(
        call(
            planes,
            channel,
            "late_results",
            serde_json::to_value(request).unwrap(),
        )
        .await,
    )
    .unwrap()
}
async fn observe_login(planes: &Planes, facts: &LoginFacts) -> LateResultsReply {
    tokio::time::timeout(HANG_GUARD, async {
        while !facts.credential_polled.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the handoff poller first observes the credential step");
    facts.logged_in.store(true, Ordering::SeqCst);
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let reply = read(planes, 9, None, None).await;
            if !reply.entries.is_empty() {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the real handoff poller observes simulated login")
}
fn vector() -> Value {
    serde_json::from_str(include_str!(
        "../fixtures/tool-provider-v1/late-results.json"
    ))
    .unwrap()
}

fn seed_version_2(scratch: &Scratch) {
    std::fs::write(
        scratch.0.join("call_records.jsonl"),
        b"{\"format\":\"call-records\",\"version\":2}\n",
    )
    .unwrap();
    FormatFloor::at(scratch.0.join("format-floor.json"))
        .raise(DurableFormat::new("call-records", 2))
        .unwrap();
}

async fn next_ending(planes: &Planes) -> LateResultsReply {
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let reply = read(planes, 9, None, None).await;
            if !reply.entries.is_empty() {
                break reply;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("the handoff watcher did not settle before the test hang guard")
}

async fn present_for_watch(planes: &Planes, key: &str) -> Value {
    struct ResumeClock;
    impl Drop for ResumeClock {
        fn drop(&mut self) {
            tokio::time::resume();
        }
    }

    // These tests check the watcher, not the six-second call-record admission
    // budget. Stop its clock during file-backed setup so a busy blocking worker
    // cannot refuse the present before the watcher runs. Keep the task runnable
    // to prevent Tokio's automatic time advance, with a real-clock hang guard.
    tokio::time::pause();
    let _resume = ResumeClock;
    let started = std::time::Instant::now();
    let mut setup = std::pin::pin!(present(planes, Some(key)));
    loop {
        assert!(started.elapsed() < HANG_GUARD, "keyed present setup hung");
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        if let std::task::Poll::Ready(reply) = setup.as_mut().poll(&mut context) {
            return reply;
        }
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn handoff_watch_observes_login_before_first_tick_without_resume_or_journal() {
    let scratch = Scratch::new();
    let (planes, facts) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    assert_eq!(
        present_for_watch(&planes, "pf:autonomous").await["expires_in_ms"],
        HANDOFF_DURATION_MS
    );
    assert!(facts.credential_polled.load(Ordering::SeqCst));
    assert_eq!(facts.reads.load(Ordering::SeqCst), 1);
    let journal = planes.browser.hold_journal_for_test().await;
    facts.logged_in.store(true, Ordering::SeqCst);
    let reply = next_ending(&planes).await;
    assert_eq!(reply.entries.len(), 1);
    assert_eq!(
        reply.entries[0].result,
        Some(json!({"outcome":"login_observed","origin":ORIGIN}))
    );
    assert_eq!(facts.reads.load(Ordering::SeqCst), 2);
    drop(journal);
    assert_eq!(
        call(&planes, 9, "browser_use", json!({"action":"resume"})).await,
        json!({"outcome":"resumed","handoff":"login_observed","origin":ORIGIN})
    );
    assert!(read(&planes, 9, Some(reply.cursor.clone()), None)
        .await
        .entries
        .is_empty());
    call(
        &planes,
        9,
        "late_results.ack",
        json!({"through":reply.cursor}),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(HANDOFF_POLL_INTERVAL_MS + 100)).await;
    assert_eq!(
        facts.reads.load(Ordering::SeqCst),
        2,
        "settled watcher kept reading CDP"
    );
    assert!(read(&planes, 9, None, None).await.entries.is_empty());
}

#[tokio::test]
async fn handoff_watch_unreadable_opening_field_is_not_login_evidence() {
    let scratch = Scratch::new();
    let (planes, facts) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    facts.credential_unreadable.store(true, Ordering::SeqCst);
    assert_eq!(
        present_for_watch(&planes, "pf:unreadable").await["outcome"],
        "login_pending"
    );
    facts.logged_in.store(true, Ordering::SeqCst);
    facts.credential_unreadable.store(false, Ordering::SeqCst);
    // A second poll can start only after the first returned without settling;
    // this observes the classifier's decision, not just the start of a read.
    tokio::time::timeout(HANG_GUARD, async {
        while facts.reads.load(Ordering::SeqCst) < 3 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("a background observation ran");
    assert_eq!(
        call(&planes, 9, "browser_use", json!({"action":"resume"})).await["handoff"],
        "closed_by_caller"
    );
    let reply = read(&planes, 9, None, None).await;
    assert_eq!(reply.entries.len(), 1);
    assert_eq!(
        reply.entries[0].result,
        Some(json!({"outcome":"closed_by_caller","origin":ORIGIN}))
    );
}

#[tokio::test]
async fn handoff_watch_expiry_still_settles_without_resume() {
    let scratch = Scratch::new();
    let (planes, facts) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    present_for_watch(&planes, "pf:expires").await;
    planes
        .sessions
        .expire_handoff_for_test("test-session", planes.lease_clock.as_ref());
    let reply = next_ending(&planes).await;
    assert_eq!(reply.entries.len(), 1);
    assert_eq!(
        reply.entries[0].result,
        Some(json!({"outcome":"handoff_expired","origin":ORIGIN}))
    );
    assert_eq!(
        facts.reads.load(Ordering::SeqCst),
        1,
        "expiry read CDP unnecessarily"
    );
    assert_eq!(
        call(&planes, 9, "browser_use", json!({"action":"resume"})).await["handoff"],
        "expired"
    );
}

#[tokio::test]
async fn handoff_watch_stops_after_close() {
    let scratch = Scratch::new();
    let (planes, facts) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    let session = planes.sessions.status(
        "test-session",
        planes.lease_clock.as_ref(),
        SystemTime::now(),
    );
    present_for_watch(&planes, "pf:close").await;
    let closed = call(
        &planes,
        9,
        "browser_use",
        json!({"action":"close", "browser_session_id":session["browser_session_id"]}),
    )
    .await;
    assert_eq!(closed["outcome"], "closed", "{closed}");
    facts.logged_in.store(true, Ordering::SeqCst);
    let reply = next_ending(&planes).await;
    assert_eq!(reply.entries.len(), 1);
    assert_eq!(
        reply.entries[0].result,
        Some(json!({"outcome":"handoff_interrupted","origin":ORIGIN}))
    );
    tokio::time::sleep(Duration::from_millis(HANDOFF_POLL_INTERVAL_MS + 100)).await;
    assert_eq!(
        facts.reads.load(Ordering::SeqCst),
        1,
        "closed watcher kept reading CDP"
    );
    assert!(read(&planes, 9, Some(reply.cursor), None)
        .await
        .entries
        .is_empty());
}

async fn seed_endings(planes: &Planes) {
    for (index, outcome) in [
        HandoffEnding::LoginObserved,
        HandoffEnding::HandoffExpired,
        HandoffEnding::HandoffInterrupted,
        HandoffEnding::Captured,
        HandoffEnding::SessionInvalid,
        HandoffEnding::Expired,
    ]
    .into_iter()
    .enumerate()
    {
        let key = format!("pf:ending-{index}");
        assert_eq!(
            present(planes, Some(&key)).await["outcome"],
            "login_pending"
        );
        planes
            .calls
            .finish_handoff(OWNER, &key, outcome, now_ms())
            .unwrap();
        call(planes, 9, "browser_use", json!({"action":"resume"})).await;
    }
}

#[tokio::test]
async fn late_results_undeclared_pull_preserves_legacy_bytes() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    seed_endings(&planes).await;
    let expected = planes
        .calls
        .late_results(OWNER, &LateResultsRequest::new(), now_ms())
        .unwrap();
    assert_eq!(
        expected.entries[0].result,
        Some(json!({"outcome":"login_observed","origin":ORIGIN}))
    );
    for readers in [None, Some(vec!["unrelated/v1".to_owned()])] {
        bind_with_readers(&planes, 10, reserved("prefrontal-core"), false, readers).await;
        let reply = exchange(
            &planes,
            frame(
                10,
                json!({"name":"late_results","arguments":{"since":null}}),
            ),
        )
        .await;
        assert_eq!(reply.header.ty, FrameType::Response);
        assert_eq!(
            reply.body,
            serde_json::to_vec(&serde_json::to_value(&expected).unwrap()).unwrap()
        );
    }
}

#[tokio::test]
async fn late_results_declared_pull_renders_each_ending_without_changing_storage() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    seed_endings(&planes).await;
    let legacy = read(&planes, 9, None, None).await;
    let stored = std::fs::read(scratch.0.join("call_records.jsonl")).unwrap();
    bind_with_readers(
        &planes,
        10,
        reserved("prefrontal-core"),
        false,
        Some(vec![
            cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
        ]),
    )
    .await;
    let rendered = read(&planes, 10, None, None).await;
    assert_eq!(rendered.entries.len(), 6);
    let sentences = [
        format!("Sign-in on {ORIGIN} was observed. Continue with snapshot."),
        format!("The sign-in window on {ORIGIN} expired before a login was seen. Call present again if still needed."),
        format!("The sign-in handoff on {ORIGIN} was interrupted by a restart. Call present again."),
        format!("Sign-in on {ORIGIN} was captured in the vault. Continue with the authenticated request."),
        format!("The captured sign-in on {ORIGIN} could not be verified. Call capture_login again."),
        format!("The sign-in window on {ORIGIN} expired before a login was seen. Call present again if still needed."),
    ];
    for ((entry, original), sentence) in rendered.entries.iter().zip(&legacy.entries).zip(sentences)
    {
        let result = entry.result.as_ref().unwrap();
        let typed = serde_json::from_value(result.clone()).unwrap();
        cortexkit_role_tool_provider::result::validate(&typed).unwrap();
        assert_eq!(result["content"], json!([{"type":"text","text":sentence}]));
        assert_eq!(
            result["structuredContent"],
            *original.result.as_ref().unwrap()
        );
        let mut unchanged = entry.clone();
        unchanged.result = original.result.clone();
        assert_eq!(unchanged, *original);
    }
    assert_eq!(read(&planes, 9, None, None).await, legacy);
    assert_eq!(
        std::fs::read(scratch.0.join("call_records.jsonl")).unwrap(),
        stored
    );
    assert!(scan_leaks(&serde_json::to_vec(&rendered).unwrap()).is_empty());
}

#[tokio::test]
async fn first_keyed_present_upgrades_version_2_to_version_3() {
    let scratch = Scratch::new();
    seed_version_2(&scratch);
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    assert_eq!(
        present(&planes, Some("pf:first-handoff")).await["outcome"],
        "login_pending"
    );
    let written = std::fs::read_to_string(scratch.0.join("call_records.jsonl")).unwrap();
    assert_eq!(
        written.lines().next(),
        Some("{\"format\":\"call-records\",\"version\":3}")
    );
    assert!(written
        .lines()
        .skip(1)
        .any(|line| serde_json::from_str::<Value>(line).unwrap()["handoff"].is_object()));
    assert_eq!(
        read_floors(&scratch.0.join("format-floor.json"))
            .unwrap()
            .get("call-records"),
        Some(&3)
    );
    call(&planes, 9, "browser_use", json!({"action":"resume"})).await;
    let ending = read(&planes, 9, None, None).await;
    call(
        &planes,
        9,
        "late_results.ack",
        json!({"through":ending.cursor}),
    )
    .await;
    let after_ack = std::fs::read_to_string(scratch.0.join("call_records.jsonl")).unwrap();
    assert_eq!(
        after_ack.lines().next(),
        Some("{\"format\":\"call-records\",\"version\":3}")
    );
}

#[tokio::test]
async fn handoff_upgrade_raises_version_3_floor_before_writing() {
    let scratch = Scratch::new();
    seed_version_2(&scratch);
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    let mut ordinary = json!({"name":"browser_use","arguments":{"action":"status"}});
    ordinary["call_key"] = json!("pf:ordinary-before-handoff");
    let response = exchange(&planes, frame(9, ordinary)).await;
    assert_eq!(response.header.ty, FrameType::Response);
    let before = std::fs::read_to_string(scratch.0.join("call_records.jsonl")).unwrap();
    assert_eq!(
        before.lines().next(),
        Some("{\"format\":\"call-records\",\"version\":2}")
    );
    assert_eq!(
        read_floors(&scratch.0.join("format-floor.json"))
            .unwrap()
            .get("call-records"),
        Some(&2)
    );
    // Storage already remembers that the minimum reader version was saved as
    // 2. A handoff needs to save minimum reader 3 first. Making that metadata
    // invalid must block the upgrade before any version 3 data is written.
    std::fs::write(scratch.0.join("format-floor.json"), b"invalid-floor").unwrap();
    assert_eq!(
        present(&planes, Some("pf:floor-blocked-handoff")).await["outcome"],
        "internal_failure"
    );
    let written = std::fs::read_to_string(scratch.0.join("call_records.jsonl")).unwrap();
    assert_eq!(
        written.lines().next(),
        Some("{\"format\":\"call-records\",\"version\":2}")
    );
    assert!(
        !written.contains("\"handoff\""),
        "handoff data was written before the format floor could be raised"
    );
    assert!(read(&planes, 9, None, None).await.entries.is_empty());
}

#[tokio::test]
async fn hello_manifest_declares_late_results_capability() {
    let (tx, mut rx) = mpsc::channel(1);
    cerebellum::send_hello_for_test(
        &tx,
        &cerebellum::ModuleConfigForTest {
            module_id: "cerebellum".into(),
        },
    )
    .await
    .unwrap();
    let hello = rx.recv().await.unwrap();
    assert_eq!(hello.header.ty, FrameType::Hello);
    let body: Value = serde_json::from_slice(&hello.body).unwrap();
    let capabilities = body["manifest"]["capabilities"]["provides"]
        .as_array()
        .unwrap();
    assert!(
        capabilities.contains(&json!("late-results/v1")),
        "HELLO does not declare late-result support: {capabilities:?}"
    );
    assert!(
        capabilities.contains(&json!("tool-provider/v1")),
        "HELLO must declare the catalog provider role"
    );
    // Declared beside late results: both tell Prefrontal core which of its
    // calls this module serves.
    assert!(
        capabilities.contains(&json!("session-turn-ended/v1")),
        "HELLO does not declare session.turn_ended support: {capabilities:?}"
    );
}

#[tokio::test]
async fn catalog_and_role_ops_are_served() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, false);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    for name in ["role.describe", "tool.catalog"] {
        let reply = exchange(&planes, frame(9, json!({"name":name,"arguments":{}}))).await;
        assert_eq!(reply.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert!(body.is_object());
    }
}

/// The detail of a role op's refusal, which must arrive as an `ERROR` frame:
/// a caller decodes a `RESPONSE` body as the op's answer.
fn refusal_detail(reply: &Frame) -> Value {
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply.header.ty, FrameType::Error, "{body}");
    assert_eq!(body["code"], "invalid_request", "{body}");
    body["detail"].clone()
}

/// A preset is refused by name, since this provider serves none, and a null
/// preset is no preset. Every refusal is an `ERROR` frame naming its field.
#[tokio::test]
async fn role_op_refusals_are_error_frames_naming_the_field() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, false);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    for name in ["role.describe", "tool.catalog"] {
        let preset = json!({"name":name,"arguments":{},"preset":"head"});
        assert_eq!(
            refusal_detail(&exchange(&planes, frame(9, preset)).await),
            json!({"field":"preset","reason_code":"unsupported_value","value":"head"})
        );
        let unknown = json!({"name":name,"arguments":{},"bogus":1});
        assert_eq!(
            refusal_detail(&exchange(&planes, frame(9, unknown)).await),
            json!({"field":"bogus","reason_code":"unknown_field"})
        );
        let null = json!({"name":name,"arguments":{},"preset":null});
        let reply = exchange(&planes, frame(9, null)).await;
        assert_eq!(reply.header.ty, FrameType::Response, "{name}");
    }
    let extra = json!({"name":"late_results","arguments":{"since":null,"extra":1}});
    assert_eq!(
        refusal_detail(&exchange(&planes, frame(9, extra)).await),
        json!({"field":"arguments.extra","reason_code":"unknown_field"})
    );
}

#[tokio::test]
async fn keyed_present_login_ack_and_custodian_isolation() {
    let scratch = Scratch::new();
    let (planes, logged_in) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    bind(&planes, 10, reserved("prefrontal-routing"), false).await;
    assert_eq!(
        present(&planes, Some("pf:login-1")).await,
        json!({"outcome":"login_pending","origin":ORIGIN,"expires_in_ms":600_000})
    );
    let reply = observe_login(&planes, &logged_in).await;
    assert_eq!(reply.entries.len(), 1);
    let entry = &reply.entries[0];
    assert_eq!(
        (
            entry.kind.as_str(),
            entry.custodian.as_str(),
            entry.call_key.as_str()
        ),
        ("result", OWNER, "pf:login-1")
    );
    assert_eq!(
        (
            entry.owner.as_str(),
            entry.scope_ref.as_str(),
            entry.scope_epoch
        ),
        (OWNER, "scope-7", 3)
    );
    assert_eq!(
        entry.result,
        Some(json!({"outcome":"login_observed","origin":ORIGIN}))
    );
    assert!(!entry.reduced);
    assert!(entry.settled_at > 0);
    cerebellum::browser::validate_browser_result("browser.present", entry.result.as_ref().unwrap())
        .unwrap();
    assert!(
        read(&planes, 10, None, None).await.entries.is_empty(),
        "a different verified custodian received the login result"
    );
    assert_eq!(
        call(
            &planes,
            9,
            "late_results.ack",
            serde_json::to_value(AckRequest {
                through: reply.cursor.clone()
            })
            .unwrap()
        )
        .await,
        json!({})
    );
    assert!(read(&planes, 9, None, None).await.entries.is_empty());
    let resumed = call(&planes, 9, "browser_use", json!({"action":"resume"})).await;
    assert_eq!(
        resumed,
        json!({"outcome":"resumed","handoff":"login_observed","origin":ORIGIN})
    );
    assert!(
        read(&planes, 9, None, None).await.entries.is_empty(),
        "resume recreated an acked settlement"
    );
    assert_eq!(
        present(&planes, Some("pf:login-1")).await,
        json!({"outcome":"login_observed","origin":ORIGIN}),
        "a resend replayed a held reply after acknowledgement"
    );
}

#[tokio::test]
async fn late_results_cursor_round_trip() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    for key in ["pf:first", "pf:second"] {
        assert_eq!(
            present(&planes, Some(key)).await["outcome"],
            "login_pending"
        );
        assert_eq!(
            call(&planes, 9, "browser_use", json!({"action":"resume"})).await["handoff"],
            "closed_by_caller"
        );
    }
    let first_request: LateResultsRequest =
        serde_json::from_value(vector()["first_request"].clone()).unwrap();
    let zero = read(&planes, 9, None, Some(0)).await;
    assert!(zero.entries.is_empty());
    assert!(zero.more);
    assert_eq!(zero.cursor.seq, 0);
    let first = read(&planes, 9, None, Some(1)).await;
    assert_eq!(first.entries.len(), 1);
    assert!(first.more);
    let second = read(&planes, 9, Some(first.cursor), Some(1)).await;
    assert_eq!(second.entries.len(), 1);
    assert!(!second.more);
    assert_eq!(second.entries[0].call_key, "pf:second");
    let done = read(&planes, 9, Some(second.cursor.clone()), first_request.limit).await;
    assert!(done.entries.is_empty());
    assert!(!done.more);
    assert_eq!(done.cursor, second.cursor);
    let shape: LateResultsReply = serde_json::from_value(vector()["reply"].clone()).unwrap();
    assert_eq!(serde_json::to_value(shape).unwrap(), vector()["reply"]);
    for case in vector()["malformed_entries"].as_array().unwrap() {
        assert!(
            serde_json::from_value::<LateEntry>(case["entry"].clone()).is_err(),
            "{}",
            case["name"]
        );
    }
    let unknown: LateEntry =
        serde_json::from_value(vector()["unknown_kinds"][0]["entry"].clone()).unwrap();
    assert_eq!(
        serde_json::to_value(unknown).unwrap(),
        vector()["unknown_kinds"][0]["entry"]
    );
}

#[tokio::test]
async fn late_results_ack() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    bind(&planes, 10, reserved("prefrontal-routing"), false).await;
    for key in ["pf:one", "pf:two"] {
        present(&planes, Some(key)).await;
        call(&planes, 9, "browser_use", json!({"action":"resume"})).await;
    }
    let first = read(&planes, 9, None, Some(1)).await;
    let own_empty = read(&planes, 10, None, None).await;
    call(
        &planes,
        10,
        "late_results.ack",
        json!({"through":own_empty.cursor}),
    )
    .await;
    assert_eq!(read(&planes, 9, None, None).await.entries.len(), 2);
    let mut ack: AckRequest = serde_json::from_value(vector()["ack"].clone()).unwrap();
    ack.through = first.cursor;
    call(
        &planes,
        9,
        "late_results.ack",
        serde_json::to_value(&ack).unwrap(),
    )
    .await;
    call(
        &planes,
        9,
        "late_results.ack",
        serde_json::to_value(&ack).unwrap(),
    )
    .await;
    let remaining = read(&planes, 9, None, None).await;
    assert_eq!(remaining.entries.len(), 1);
    assert_eq!(remaining.entries[0].call_key, "pf:two");
    call(
        &planes,
        9,
        "late_results.ack",
        json!({"through":remaining.cursor}),
    )
    .await;
    let (next, _) = planes_after_restart(&scratch);
    bind(&next, 9, reserved("prefrontal-core"), false).await;
    assert!(
        read(&next, 9, None, None).await.entries.is_empty(),
        "acknowledgement was lost at restart"
    );
}

fn planes_after_restart(scratch: &Scratch) -> (Planes, Arc<LoginFacts>) {
    planes(scratch, false)
}

#[tokio::test]
async fn late_results_incarnation_change_refused() {
    let scratch = Scratch::new();
    let (first, _) = planes(&scratch, false);
    bind(&first, 9, reserved("prefrontal-core"), false).await;
    let old = read(&first, 9, None, None).await.cursor;
    let (next, _) = planes_after_restart(&scratch);
    bind(&next, 9, reserved("prefrontal-core"), false).await;
    let current = read(&next, 9, None, None).await.cursor;
    assert_ne!(old.provider_incarnation, current.provider_incarnation);
    for cursor in [old, Cursor { seq: 1, ..current }] {
        for (op, args) in [
            ("late_results", json!({"since":cursor})),
            ("late_results.ack", json!({"through":cursor})),
        ] {
            let reply = exchange(&next, frame(9, json!({"name":op,"arguments":args}))).await;
            assert_eq!(reply.header.ty, FrameType::Error);
            let error: subc_protocol::ErrorBody = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(error.code, "cursor_incarnation_changed");
            assert!(error.detail.unwrap()["provider_incarnation"].is_string());
        }
    }
}

#[tokio::test]
async fn event_id_is_deterministic_across_pulls_and_restart() {
    let scratch = Scratch::new();
    let (first, _) = planes(&scratch, true);
    bind(&first, 9, reserved("prefrontal-core"), false).await;
    present(&first, Some("pf:stable")).await;
    call(&first, 9, "browser_use", json!({"action":"resume"})).await;
    let one = read(&first, 9, None, None).await;
    let two = read(&first, 9, None, None).await;
    assert_eq!(
        one.entries[0].event_id, two.entries[0].event_id,
        "a re-read changed the settlement identity"
    );
    let (next, _) = planes_after_restart(&scratch);
    bind(&next, 9, reserved("prefrontal-core"), false).await;
    let three = read(&next, 9, None, None).await;
    assert_eq!(
        one.entries, three.entries,
        "a restart changed a retained settlement"
    );
}

#[tokio::test]
async fn held_handoff_settles_as_interrupted_on_restart() {
    let scratch = Scratch::new();
    let (first, _) = planes(&scratch, true);
    bind(&first, 9, reserved("prefrontal-core"), false).await;
    assert_eq!(
        present(&first, Some("pf:interrupted")).await["outcome"],
        "login_pending"
    );
    assert!(read(&first, 9, None, None).await.entries.is_empty());
    // Construct fresh module state over the file left by the held call, without
    // a graceful resume or browser close. Startup alone must report
    // handoff_interrupted so the caller stops waiting after a process crash.
    let (next, _) = planes_after_restart(&scratch);
    bind(&next, 9, reserved("prefrontal-core"), false).await;
    let reply = read(&next, 9, None, None).await;
    assert_eq!(
        reply.entries.len(),
        1,
        "startup did not settle the held handoff"
    );
    assert_eq!(reply.entries[0].call_key, "pf:interrupted");
    assert_eq!(
        reply.entries[0].result,
        Some(json!({"outcome":"handoff_interrupted","origin":ORIGIN}))
    );
    let (again, _) = planes_after_restart(&scratch);
    bind(&again, 9, reserved("prefrontal-core"), false).await;
    assert_eq!(
        read(&again, 9, None, None).await.entries,
        reply.entries,
        "a second start settled the call again"
    );
}

#[tokio::test]
async fn unkeyed_present_is_not_held() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    assert_eq!(
        present(&planes, None).await,
        json!({"outcome":"presented","expires_in_ms":600_000})
    );
    call(&planes, 9, "browser_use", json!({"action":"resume"})).await;
    assert!(read(&planes, 9, None, None).await.entries.is_empty());
    assert!(!scratch.0.join("call_records.jsonl").exists());
    assert!(!scratch.0.join("format-floor.json").exists());
}

fn scan_leaks(bytes: &[u8]) -> Vec<&'static str> {
    LEAKS
        .into_iter()
        .filter(|leak| {
            bytes
                .windows(leak.len())
                .any(|window| window == leak.as_bytes())
        })
        .collect()
}

#[tokio::test]
async fn entries_and_store_are_text_free_scanner_finds_planted_control() {
    let scratch = Scratch::new();
    let (planes, logged_in) = planes(&scratch, true);
    bind(&planes, 9, reserved("prefrontal-core"), false).await;
    let control = scratch.0.join("planted-control.json");
    std::fs::write(
        &control,
        serde_json::to_vec(
            &json!({"title":LEAKS[0],"url":format!("{ORIGIN}/{}",LEAKS[1]),"cookie":LEAKS[2]}),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        scan_leaks(&std::fs::read(&control).unwrap()),
        LEAKS,
        "the scanner did not find every planted control"
    );
    std::fs::remove_file(control).unwrap();
    present(&planes, Some("pf:private")).await;
    let reply = observe_login(&planes, &logged_in).await;
    let entry_leaks = scan_leaks(&serde_json::to_vec(&reply.entries).unwrap());
    let stored = std::fs::read(scratch.0.join("call_records.jsonl")).unwrap();
    let store_leaks = scan_leaks(&stored);
    assert_eq!(
        (entry_leaks, store_leaks),
        (Vec::new(), Vec::new()),
        "page content leaked into late entries or durable call records"
    );
    assert!(
        String::from_utf8(stored).unwrap().contains(ORIGIN),
        "the scanner did not reach a handoff record"
    );
}

#[tokio::test]
async fn provider_ops_require_tool_route_and_verified_principal() {
    let scratch = Scratch::new();
    let (planes, _) = planes(&scratch, false);
    bind(&planes, 9, reserved("prefrontal-core"), true).await;
    for op in ["late_results", "late_results.ack"] {
        let reply = exchange(
            &planes,
            frame(9, json!({"name":op,"arguments":{"since":null}})),
        )
        .await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(
            body["outcome"], "invalid_request",
            "tool envelope reached a management route: {body}"
        );
    }
    let unverified_bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 10,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("test", "test-session"),
        principal: Some(Principal::Unverified),
        consumer_capabilities: None,
        admission_facts: None,
        scope: None,
    };
    let reply = exchange(
        &planes,
        frame(0, serde_json::to_value(unverified_bind).unwrap()),
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Error);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["code"],
        "principal_denied"
    );
}
