//! The frame loop's three ways of saying an agent is done with the computer:
//! a route GOODBYE, a Cancel that stops a computer call, and Prefrontal core's
//! `session.turn_ended`. Each must hide exactly the badges it owns, and leave
//! every other agent's badge alone.
//!
//! The `session-turn-ended-v1` vectors are captured here from the real
//! management handler.

use super::*;
use crate::computer_capability::cursor::{Coordinator, Identity, SessionScope};
use cerebellum_computer::cursor::CursorLine;
use sha2::{Digest, Sha256};

// These tests inspect process-lifetime atomics; serialize every call here so
// another handler test cannot make a counter assertion pass or fail by luck.
static TURN_ENDED_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn lock_turn_ended_metrics() -> tokio::sync::MutexGuard<'static, ()> {
    TURN_ENDED_TEST_LOCK.lock().await
}

fn planes_with_cursor() -> (Planes, mpsc::Receiver<CursorLine>) {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    let (cursor, receiver) = Coordinator::channel();
    planes.cursor_for_test = Some(cursor);
    (planes, receiver)
}

fn cursor(planes: &Planes) -> Coordinator {
    planes.cursor_for_test.clone().unwrap()
}

/// Every badge hidden so far, in order. Fails on a picture: nothing in these
/// tests draws one.
fn hidden(receiver: &mut mpsc::Receiver<CursorLine>) -> Vec<String> {
    let mut agents = Vec::new();
    while let Ok(line) = receiver.try_recv() {
        match line {
            CursorLine::Hide(hide) => agents.push(hide.agent),
            CursorLine::Picture(event) => panic!("unexpected picture for {}", event.agent),
        }
    }
    agents
}

fn control(ty: FrameType, channel: u16, epoch: u32, corr: u64) -> Frame {
    Frame::build(ty, control_flags(), channel, epoch, corr, b"{}".to_vec()).unwrap()
}

/// Each request on channel 7 or 8 draws a badge for `agent-<channel>` while
/// it runs, as a computer call would; a request on channel 9 draws none. The
/// requests then stay open until `release` fires, so a Cancel finds them.
/// The returned receiver yields once per request after its badge is recorded.
fn park_requests_drawing_badges(
    planes: &mut Planes,
    release: Arc<tokio::sync::Notify>,
) -> mpsc::Receiver<()> {
    let cursor = cursor(planes);
    let (drawn, drawn_rx) = mpsc::channel(8);
    planes.route_test_handler = Some(Arc::new(move || {
        let (cursor, release, drawn) = (cursor.clone(), release.clone(), drawn.clone());
        Box::pin(async move {
            let call = TerminalArbiter::current().expect("a route request has a terminal");
            let (channel, _) = call.route();
            if channel != 9 {
                cursor.draw_for_test(&Identity::for_test(
                    &format!("agent-{channel}"),
                    Some(call),
                    None,
                ));
            }
            let _ = drawn.send(()).await;
            release.notified().await;
        })
    }));
    drawn_rx
}

#[tokio::test]
async fn cancel_of_a_computer_call_ends_only_that_calls_badge() {
    let (mut planes, mut lines) = planes_with_cursor();
    let release = Arc::new(tokio::sync::Notify::new());
    let mut drawn = park_requests_drawing_badges(&mut planes, release.clone());
    let (tx, _rx) = mpsc::channel(8);
    for (channel, corr) in [(7, 42), (8, 45), (9, 46)] {
        handle_frame(control(FrameType::Request, channel, 1, corr), &tx, &planes)
            .await
            .unwrap();
    }
    for _ in 0..3 {
        drawn.recv().await.unwrap();
    }
    // A call that drew no badge, and a correlation nobody is running, end
    // nothing.
    for (channel, corr) in [(9, 46), (7, 99)] {
        handle_frame(control(FrameType::Cancel, channel, 1, corr), &tx, &planes)
            .await
            .unwrap();
    }
    assert_eq!(hidden(&mut lines), Vec::<String>::new());
    handle_frame(control(FrameType::Cancel, 7, 1, 42), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(hidden(&mut lines), ["agent-7"]);
    release.notify_waiters();
}

#[tokio::test]
async fn goodbye_ends_only_the_badges_its_route_drew() {
    let (mut planes, mut lines) = planes_with_cursor();
    let release = Arc::new(tokio::sync::Notify::new());
    let mut drawn = park_requests_drawing_badges(&mut planes, release.clone());
    let (tx, _rx) = mpsc::channel(8);
    for (channel, corr) in [(7, 42), (8, 45)] {
        handle_frame(control(FrameType::Request, channel, 1, corr), &tx, &planes)
            .await
            .unwrap();
    }
    for _ in 0..2 {
        drawn.recv().await.unwrap();
    }
    // Another epoch of the same channel is a different route.
    handle_frame(control(FrameType::Goodbye, 7, 2, 0), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(hidden(&mut lines), Vec::<String>::new());
    handle_frame(control(FrameType::Goodbye, 7, 1, 0), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(hidden(&mut lines), ["agent-7"]);
    // The route's record went with it: a second close ends nothing more.
    handle_frame(control(FrameType::Goodbye, 7, 1, 0), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(hidden(&mut lines), Vec::<String>::new());
    release.notify_waiters();
}

const MANAGEMENT: (u16, u32) = (4, 1);

fn bind_management(planes: &Planes, principal: Option<subc_protocol::Principal>) {
    planes.routes.insert(
        MANAGEMENT.0,
        MANAGEMENT.1,
        AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string()),
            principal,
            None,
            None,
            &subc_protocol::RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
}

fn prefrontal() -> Option<subc_protocol::Principal> {
    Some(subc_protocol::Principal::Reserved {
        module_id: "prefrontal-core".to_string(),
    })
}

/// The harness `turn_ended` event's fields, with synthetic values.
fn params(scope_ref: &str, outcome: &str) -> Value {
    json!({
        "session_ref": "0123456789abcdef0123456789abcdef",
        "scope": {"owner": {"kind": "reserved", "module_id": "prefrontal-core"}, "ref": scope_ref, "epoch": 3},
        "harness": "claude-code",
        "turn_id": "turn-1",
        "outcome": outcome,
        "quality": "strong",
        "source": "stop-hook",
        "seq": 7,
        "at_ms": 1_700_000_000_000u64,
    })
}

fn with_error_class(mut params: Value, class: &str) -> Value {
    params["error_class"] = json!(class);
    params
}

fn turn_ended_request(corr: u64, params: Value) -> Frame {
    Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        MANAGEMENT.0,
        MANAGEMENT.1,
        corr,
        serde_json::to_vec(&json!({"method": management::SESSION_TURN_ENDED, "params": params}))
            .unwrap(),
    )
    .unwrap()
}

async fn served(planes: &Planes, request: &Frame) -> Frame {
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame(request.clone(), &tx, planes).await.unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("the call answers promptly")
        .expect("the writer stays open");
    assert!(
        tokio::time::timeout(Duration::from_millis(50), rx.recv())
            .await
            .map_or(true, |frame| frame.is_none()),
        "one reply and nothing else"
    );
    reply
}

async fn health_metrics(planes: &Planes) -> Value {
    let (tx, mut rx) = mpsc::channel(8);
    let request = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        900,
        serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
    )
    .unwrap();
    handle_frame(request, &tx, planes).await.unwrap();
    let reply = rx.recv().await.expect("health response");
    let ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = serde_json::from_slice(&reply.body).unwrap()
    else {
        panic!("health reply")
    };
    metrics
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}

/// Two head sessions, each of which drew its own agent's badge.
fn two_sessions(planes: &Planes) {
    for (agent, scope_ref) in [("agent-a", "head-a"), ("agent-b", "head-b")] {
        cursor(planes).draw_for_test(&Identity::for_test(
            agent,
            None,
            Some(SessionScope {
                scope_ref: scope_ref.into(),
                epoch: 1,
            }),
        ));
    }
}

#[tokio::test]
async fn turn_ended_for_one_session_hides_its_badge_and_not_another() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    let (planes, mut lines) = planes_with_cursor();
    bind_management(&planes, prefrontal());
    two_sessions(&planes);
    let request = turn_ended_request(500, params("head-a", "completed"));
    let reply = served(&planes, &request).await;
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(body(&reply), json!({"acknowledged": true}));
    assert_eq!(hidden(&mut lines), ["agent-a"]);
    assert!(planes.browser.journal_export_for_test().await.is_empty());
    vectors::check(
        "acknowledged",
        "head-a drew agent-a's badge",
        &request,
        &reply,
    );
}

#[tokio::test]
async fn turn_ended_for_an_unknown_session_still_acknowledges() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    let (planes, mut lines) = planes_with_cursor();
    bind_management(&planes, prefrontal());
    two_sessions(&planes);
    let request = turn_ended_request(501, params("head-unknown", "stopped"));
    let reply = served(&planes, &request).await;
    assert_eq!(body(&reply), json!({"acknowledged": true}));
    assert_eq!(hidden(&mut lines), Vec::<String>::new());
    vectors::check(
        "unknown-session",
        "no badge was drawn for head-unknown",
        &request,
        &reply,
    );
}

#[tokio::test]
async fn turn_ended_with_an_unknown_outcome_is_refused_naming_the_field() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    let (planes, mut lines) = planes_with_cursor();
    bind_management(&planes, prefrontal());
    two_sessions(&planes);
    let request = turn_ended_request(502, params("head-a", "paused"));
    let reply = served(&planes, &request).await;
    assert_eq!(body(&reply)["outcome"], "invalid_request");
    assert_eq!(
        body(&reply)["detail"],
        json!({"field": "outcome", "reason_code": "invalid_value"})
    );
    assert_eq!(hidden(&mut lines), Vec::<String>::new());
    vectors::check(
        "invalid-outcome",
        "head-a drew agent-a's badge",
        &request,
        &reply,
    );
}

#[tokio::test]
async fn a_failed_turn_with_its_error_class_hides_the_badge() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    let (planes, mut lines) = planes_with_cursor();
    bind_management(&planes, prefrontal());
    two_sessions(&planes);
    let request = turn_ended_request(
        504,
        with_error_class(params("head-b", "failed"), "provider_quota"),
    );
    let reply = served(&planes, &request).await;
    assert_eq!(body(&reply), json!({"acknowledged": true}));
    assert_eq!(hidden(&mut lines), ["agent-b"]);
    vectors::check(
        "failed-with-error-class",
        "head-b drew agent-b's badge",
        &request,
        &reply,
    );
}

#[tokio::test]
async fn an_error_class_on_a_turn_that_did_not_fail_is_refused() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    let (planes, mut lines) = planes_with_cursor();
    bind_management(&planes, prefrontal());
    two_sessions(&planes);
    let request = turn_ended_request(505, with_error_class(params("head-a", "completed"), "auth"));
    let reply = served(&planes, &request).await;
    assert_eq!(
        body(&reply)["detail"],
        json!({"field": "error_class", "reason_code": "invalid_value"})
    );
    assert_eq!(hidden(&mut lines), Vec::<String>::new());
    vectors::check(
        "error-class-without-failed",
        "head-a drew agent-a's badge",
        &request,
        &reply,
    );
}

#[tokio::test]
async fn turn_ended_from_any_other_principal_is_refused() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    for principal in [
        None,
        Some(subc_protocol::Principal::Direct),
        Some(subc_protocol::Principal::Unverified),
        Some(subc_protocol::Principal::Reserved {
            module_id: "basal".to_string(),
        }),
        Some(subc_protocol::Principal::Reserved {
            module_id: "alfonso-core".to_string(),
        }),
        Some(subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core-shadow".to_string(),
        }),
    ] {
        let (planes, mut lines) = planes_with_cursor();
        bind_management(&planes, principal.clone());
        two_sessions(&planes);
        let reply = served(
            &planes,
            &turn_ended_request(503, params("head-a", "completed")),
        )
        .await;
        assert_eq!(body(&reply)["code"], "principal_denied", "{principal:?}");
        assert_eq!(hidden(&mut lines), Vec::<String>::new(), "{principal:?}");
    }
}

#[tokio::test]
async fn health_reports_turn_ended_counts_and_last_admitted_timestamp() {
    let _metrics_guard = lock_turn_ended_metrics().await;
    let (planes, mut lines) = planes_with_cursor();
    bind_management(&planes, prefrontal());
    two_sessions(&planes);

    let before = health_metrics(&planes).await;
    for key in [
        "turnEndedReceived",
        "turnEndedRefused",
        "turnEndedMatchedBadge",
        "turnEndedLastAtMs",
    ] {
        assert!(before.get(key).is_some(), "health includes {key}");
    }
    let received_before = before["turnEndedReceived"].as_u64().unwrap();
    let refused_before = before["turnEndedRefused"].as_u64().unwrap();
    let matched_before = before["turnEndedMatchedBadge"].as_u64().unwrap();

    let mut matched = params("head-a", "completed");
    matched["at_ms"] = json!(1_700_000_000_101u64);
    assert_eq!(
        body(&served(&planes, &turn_ended_request(901, matched)).await),
        json!({"acknowledged": true})
    );
    let after_match = health_metrics(&planes).await;
    assert_eq!(
        after_match["turnEndedReceived"].as_u64(),
        Some(received_before + 1)
    );
    assert_eq!(
        after_match["turnEndedMatchedBadge"].as_u64(),
        Some(matched_before + 1)
    );
    assert_eq!(
        after_match["turnEndedRefused"].as_u64(),
        Some(refused_before)
    );
    assert_eq!(
        after_match["turnEndedLastAtMs"],
        json!(1_700_000_000_101u64)
    );
    assert_eq!(hidden(&mut lines), ["agent-a"]);

    let mut unmatched = params("head-unknown", "completed");
    unmatched["at_ms"] = json!(1_700_000_000_202u64);
    assert_eq!(
        body(&served(&planes, &turn_ended_request(902, unmatched)).await),
        json!({"acknowledged": true})
    );
    let after_unmatched = health_metrics(&planes).await;
    assert_eq!(
        after_unmatched["turnEndedReceived"].as_u64(),
        Some(received_before + 2)
    );
    assert_eq!(
        after_unmatched["turnEndedMatchedBadge"].as_u64(),
        Some(matched_before + 1)
    );
    assert_eq!(
        after_unmatched["turnEndedRefused"].as_u64(),
        Some(refused_before)
    );
    assert_eq!(
        after_unmatched["turnEndedLastAtMs"],
        json!(1_700_000_000_202u64)
    );
    assert_eq!(hidden(&mut lines), Vec::<String>::new());

    let mut invalid = params("head-a", "paused");
    invalid["at_ms"] = json!(1_700_000_000_303u64);
    let invalid_reply = served(&planes, &turn_ended_request(903, invalid)).await;
    assert_eq!(body(&invalid_reply)["outcome"], "invalid_request");
    let after_invalid = health_metrics(&planes).await;
    assert_eq!(
        after_invalid["turnEndedReceived"],
        after_unmatched["turnEndedReceived"]
    );
    assert_eq!(
        after_invalid["turnEndedMatchedBadge"],
        after_unmatched["turnEndedMatchedBadge"]
    );
    assert_eq!(
        after_invalid["turnEndedRefused"].as_u64(),
        Some(refused_before + 1)
    );
    assert_eq!(
        after_invalid["turnEndedLastAtMs"],
        after_unmatched["turnEndedLastAtMs"]
    );

    bind_management(
        &planes,
        Some(subc_protocol::Principal::Reserved {
            module_id: "basal".to_string(),
        }),
    );
    let mut denied = params("head-a", "completed");
    denied["at_ms"] = json!(1_700_000_000_404u64);
    let denied_reply = served(&planes, &turn_ended_request(904, denied)).await;
    assert_eq!(body(&denied_reply)["code"], "principal_denied");
    let after_denied = health_metrics(&planes).await;
    assert_eq!(
        after_denied["turnEndedReceived"],
        after_invalid["turnEndedReceived"]
    );
    assert_eq!(
        after_denied["turnEndedMatchedBadge"],
        after_invalid["turnEndedMatchedBadge"]
    );
    assert_eq!(
        after_denied["turnEndedRefused"].as_u64(),
        Some(refused_before + 2)
    );
    assert_eq!(
        after_denied["turnEndedLastAtMs"],
        after_unmatched["turnEndedLastAtMs"]
    );
}

/// Byte-for-byte `session-turn-ended-v1` examples for core, captured from the
/// handler above rather than written by hand.
mod vectors {
    use super::*;

    pub(super) fn directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/session-turn-ended-v1")
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    fn frame(frame: &Frame) -> Value {
        let mut bytes = frame.header.encode().to_vec();
        bytes.extend_from_slice(&frame.body);
        json!({
            "type": format!("{:?}", frame.header.ty),
            "channel": frame.header.channel, "epoch": frame.header.epoch,
            "corr": frame.header.corr, "body_length": frame.body.len(),
            "body_utf8": std::str::from_utf8(&frame.body).unwrap(),
            "wire_hex": hex(&bytes),
        })
    }

    pub(super) fn sums() -> String {
        let mut files: Vec<_> = std::fs::read_dir(directory())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .filter(|path| path.file_name().unwrap() != "SHA256SUMS")
            .collect();
        files.sort();
        files
            .iter()
            .map(|path| {
                format!(
                    "{}  {}\n",
                    hex(&Sha256::digest(std::fs::read(path).unwrap())),
                    path.file_name().unwrap().to_str().unwrap()
                )
            })
            .collect()
    }

    /// Compare a captured exchange with its pinned file. With
    /// `CEREBELLUM_WRITE_TURN_ENDED_VECTORS` set, rewrite the file and the
    /// checksums first, for a deliberate contract change.
    pub(super) fn check(case: &str, state: &str, request: &Frame, reply: &Frame) {
        let value = json!({
            "contract": "session-turn-ended-v1", "case": case, "state": state,
            "principal": "reserved:prefrontal-core",
            "request": frame(request), "reply": frame(reply),
        });
        let bytes = format!("{}\n", serde_json::to_string_pretty(&value).unwrap());
        let dir = directory();
        let path = dir.join(format!("{case}.json"));
        // Parallel cases must not publish checksums describing a half-written
        // sibling.
        static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _write = WRITE.lock().unwrap();
        if std::env::var_os("CEREBELLUM_WRITE_TURN_ENDED_VECTORS").is_some() {
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(&path, &bytes).unwrap();
            std::fs::write(dir.join("SHA256SUMS"), sums()).unwrap();
        }
        assert_eq!(
            std::fs::read_to_string(path).unwrap(),
            bytes,
            "{case} wire bytes changed"
        );
    }

    #[test]
    fn session_turn_ended_vectors_match_their_checksums() {
        let pinned = std::fs::read_to_string(directory().join("SHA256SUMS")).unwrap();
        assert_eq!(pinned, sums());
        let names: Vec<&str> = pinned
            .lines()
            .map(|line| line.split_once("  ").unwrap().1)
            .collect();
        assert_eq!(
            names,
            [
                "README.md",
                "acknowledged.json",
                "error-class-without-failed.json",
                "failed-with-error-class.json",
                "invalid-outcome.json",
                "unknown-session.json"
            ]
        );
    }
}
