use super::*;
use crate::support::HANG_GUARD;

fn call(corr: u64, action: &str, arguments: Value) -> Frame {
    let mut arguments = arguments.as_object().unwrap().clone();
    arguments.insert("action".into(), json!(action));
    request(corr, "browser_use", Value::Object(arguments))
}

fn navigation() -> Frame {
    call(
        801,
        "navigate",
        json!({"url":"https://requested.example/path", "intent":"read the page", "wait":"none", "severity":{"tier":3,"credential":false,"financial":false}}),
    )
}

async fn send(planes: &Planes, tx: &mpsc::Sender<Frame>, frame: Frame) {
    tokio::time::timeout(
        HANG_GUARD,
        cerebellum::handle_frame_for_test(frame, tx, planes),
    )
    .await
    .expect("frame reader must not wait for browser queue")
    .unwrap();
}

fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}

async fn held(rx: &mut mpsc::Receiver<Frame>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(75), rx.recv())
            .await
            .is_err(),
        "queued browser action replied before consent ended"
    );
}

async fn begin(planes: &Planes, tx: &mpsc::Sender<Frame>, rx: &mut mpsc::Receiver<Frame>) -> Frame {
    send(planes, tx, navigation()).await;
    let question = ScriptedCarrier::for_planes(planes).card(9, 3).await;
    assert!(
        rx.try_recv().is_err(),
        "the action remains parked on its unanswered card"
    );
    assert_eq!(question.header.ty, FrameType::Request);
    question
}

async fn replies(rx: &mut mpsc::Receiver<Frame>, count: usize) -> Vec<Frame> {
    let mut replies = Vec::new();
    while replies.len() < count {
        let frame = consent_frame(rx).await;
        assert_eq!(frame.header.ty, FrameType::Response, "{}", body(&frame));
        replies.push(frame);
    }
    replies
}

async fn cancelled(rx: &mut mpsc::Receiver<Frame>) -> Frame {
    let frame = consent_frame(rx).await;
    assert_eq!(frame.header.ty, FrameType::Error);
    let error: subc_protocol::ErrorBody = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(error.code, "cancelled");
    frame
}

#[tokio::test]
async fn browser_queue_consent_holds_snapshot_and_click_on_navigated_page() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    grant_browser(&planes, "https://landed.example:8443", vec![]).await;
    // A click sent before the new snapshot returns can only name the old
    // snapshot. After navigation it must refuse that ref, never click the old page.
    let old = invoke_existing(&planes, 800, "browser.snapshot", json!({})).await;
    let old = body(&old);
    assert_eq!(old["outcome"], "ok");
    launcher.effects.lock().unwrap().clear();
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "snapshot", json!({}))).await;
    send(&planes, &tx, call(803, "click", json!({"ref":first_ref(&old),"snapshot_id":old["snapshot_id"],"intent":"click the previous ref","severity":{"tier":2,"credential":false,"financial":false}}))).await;
    held(&mut rx).await;
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "no CDP work before consent"
    );
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    let results = replies(&mut rx, 3).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802, 803]
    );
    assert_eq!(body(&results[0])["outcome"], "ok");
    let snapshot = body(&results[1]);
    assert_eq!(snapshot["outcome"], "ok", "{snapshot}");
    assert_eq!(
        snapshot["source_origin"], "https://landed.example:8443/final",
        "{snapshot}"
    );
    let click = body(&results[2]);
    assert_eq!(click["outcome"], "stale_snapshot", "{click}");
    assert_eq!(*launcher.effects.lock().unwrap(), ["navigate", "snapshot"]);
}

#[tokio::test]
async fn browser_queue_scroll_waits_for_navigation_consent() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://landed.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(
        &planes,
        &tx,
        call(802, "scroll", json!({"direction":"down"})),
    )
    .await;
    held(&mut rx).await;
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802]
    );
    assert_eq!(body(&results[1])["outcome"], "ok", "{}", body(&results[1]));
    assert_eq!(
        *launcher.effects.lock().unwrap(),
        ["navigate", "scroll_page"]
    );
}

#[tokio::test]
async fn browser_queue_cancelled_queued_call_never_runs() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://landed.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "screenshot", json!({}))).await;
    send(&planes, &tx, call(803, "snapshot", json!({}))).await;
    let mut cancel = call(802, "screenshot", json!({}));
    cancel.header.ty = FrameType::Cancel;
    cancel.body.clear();
    send(&planes, &tx, cancel).await;
    let cancelled = cancelled(&mut rx).await;
    assert_eq!(cancelled.header.corr, 802);
    held(&mut rx).await;
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 803]
    );
    assert_eq!(body(&results[1])["outcome"], "ok");
    assert_eq!(*launcher.effects.lock().unwrap(), ["navigate", "snapshot"]);
}

#[tokio::test]
async fn browser_queue_cancelled_head_releases_successor() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "snapshot", json!({}))).await;
    held(&mut rx).await;
    let mut cancel = navigation();
    cancel.header.ty = FrameType::Cancel;
    cancel.body.clear();
    send(&planes, &tx, cancel).await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802]
    );
    assert_eq!(body(&results[0])["outcome"], "cancelled");
    assert!(body(&results[0]).get("remedy").is_none());
    assert_eq!(body(&results[1])["outcome"], "ok");
    assert_eq!(*launcher.effects.lock().unwrap(), ["snapshot"]);
    let calls = ScriptedCarrier::for_planes(&planes).calls();
    assert!(calls
        .iter()
        .any(|(method, params)| method == "consent.detach"
            && params["elicitation_id"] == body(&question)["id"]));
    assert!(calls.iter().all(|(method, _)| method != "consent.withdraw"));
}

#[tokio::test]
async fn browser_queue_refused_head_releases_successor() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "snapshot", json!({}))).await;
    held(&mut rx).await;
    answer_browser(&planes, &tx, &question, "deny").await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802]
    );
    assert_eq!(body(&results[0])["detail"]["decision"], "declined");
    assert_eq!(body(&results[1])["outcome"], "ok");
    assert_eq!(*launcher.effects.lock().unwrap(), ["snapshot"]);
}

async fn bind(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    channel: u16,
    conversation: &str,
) {
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("test", conversation),
        principal: cerebellum::session_caller_principal_for_test(),
        consumer_capabilities: Some(vec!["elicitation".into()]),
        admission_facts: Some(
            json!({"agentProjectId":"test-project", "sessionKind":"primary", "effectiveCapabilityScope":["*"], "browserControlOperations":["browser.launch", "browser.status"]}),
        ),
        scope: Some(cingulate_answer::cingulate::stamp("test-project")),
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
    send(planes, tx, frame).await;
    assert_eq!(consent_frame(rx).await.header.ty, FrameType::Response);
}

#[tokio::test]
async fn browser_queue_status_bypasses_consent_wait() {
    let (planes, _) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "status", json!({}))).await;
    let status = consent_frame(&mut rx).await;
    assert_eq!(status.header.corr, 802);
    assert_eq!(body(&status)["outcome"], "ready", "{}", body(&status));
    answer_browser(&planes, &tx, &question, "deny").await;
    replies(&mut rx, 1).await;
}

#[tokio::test]
async fn browser_queue_another_conversation_launches_while_held() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(16);
    bind(&planes, &tx, &mut rx, 10, "other-conversation").await;
    let question = begin(&planes, &tx, &mut rx).await;
    let mut launch = call(802, "launch", json!({}));
    launch.header.channel = 10;
    send(&planes, &tx, launch).await;
    let launched = consent_frame(&mut rx).await;
    assert_eq!(launched.header.corr, 802);
    assert_eq!(
        body(&launched)["outcome"],
        "launched",
        "{}",
        body(&launched)
    );
    assert_eq!(*launcher.launches.lock().unwrap(), 2);
    answer_browser(&planes, &tx, &question, "deny").await;
    replies(&mut rx, 1).await;
}

#[tokio::test]
async fn browser_queue_frame_reader_serves_other_route() {
    let (planes, _) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    bind(&planes, &tx, &mut rx, 10, "other-conversation").await;
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "snapshot", json!({}))).await;
    let mut other = call(803, "launch", json!({}));
    other.header.channel = 10;
    send(&planes, &tx, other).await;
    let reply = consent_frame(&mut rx).await;
    assert_eq!(reply.header.corr, 803);
    assert_eq!(body(&reply)["outcome"], "launched");
    answer_browser(&planes, &tx, &question, "deny").await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802]
    );
}

fn positioned(mut frame: Frame, index: u32) -> Frame {
    let mut body = body(&frame);
    body["origin"] = json!({"carrier":{"kind":"module","module_id":"prefrontal"}, "call_key": format!("call-{index}"), "message_position":{"message_id":"message-one","index":index}});
    frame.body = serde_json::to_vec(&body).unwrap();
    frame
}

#[tokio::test(start_paused = true)]
async fn browser_queue_waits_through_normal_consent_on_wire() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://landed.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "snapshot", json!({}))).await;
    tokio::time::advance(Duration::from_secs(119)).await;
    tokio::task::yield_now().await;
    assert!(
        rx.try_recv().is_err(),
        "successor must wait through consent"
    );
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802]
    );
    assert_eq!(body(&results[0])["outcome"], "ok");
    assert_eq!(body(&results[1])["outcome"], "ok");
    assert_eq!(*launcher.effects.lock().unwrap(), ["navigate", "snapshot"]);
}

#[tokio::test]
async fn browser_queue_model_order_beats_reversed_arrival() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://landed.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    send(
        &planes,
        &tx,
        positioned(call(802, "snapshot", json!({})), 1),
    )
    .await;
    held(&mut rx).await;
    send(&planes, &tx, positioned(navigation(), 0)).await;
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    assert_eq!(question.header.ty, FrameType::Request);
    held(&mut rx).await;
    assert!(launcher.effects.lock().unwrap().is_empty());
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    let results = replies(&mut rx, 2).await;
    assert_eq!(
        results.iter().map(|f| f.header.corr).collect::<Vec<_>>(),
        [801, 802]
    );
    assert_eq!(body(&results[1])["outcome"], "ok");
    assert_eq!(*launcher.effects.lock().unwrap(), ["navigate", "snapshot"]);
}

#[tokio::test]
async fn browser_queue_goodbye_removes_queued_call() {
    let (planes, launcher) = blocking_grant_fixture().await;
    grant_browser(&planes, "https://page.example:8443", vec![]).await;
    let (tx, mut rx) = mpsc::channel(16);
    bind(&planes, &tx, &mut rx, 10, "test-session").await;
    let question = begin(&planes, &tx, &mut rx).await;
    send(&planes, &tx, call(802, "screenshot", json!({}))).await;
    held(&mut rx).await;
    let mut goodbye = call(802, "screenshot", json!({}));
    goodbye.header.ty = FrameType::Goodbye;
    goodbye.body.clear();
    send(&planes, &tx, goodbye).await;
    let cancelled = loop {
        let frame = consent_frame(&mut rx).await;
        if frame.header.ty == FrameType::Request {
            assert_eq!(frame.header.channel, 0);
            assert_eq!(body(&frame)["op"], "scope.describe");
            answer_describe(
                &planes,
                &tx,
                &mut rx,
                &frame,
                FrameType::Response,
                describe_answer("active", Some(1), true, true),
            )
            .await;
            continue;
        }
        assert_eq!(frame.header.ty, FrameType::Error);
        assert_eq!(body(&frame)["code"], "cancelled");
        break frame;
    };
    assert_eq!(cancelled.header.corr, 802);
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            if ScriptedCarrier::for_planes(&planes)
                .calls()
                .iter()
                .any(|(method, params)| {
                    method == "consent.withdraw"
                        && params["elicitation_id"] == body(&question)["id"]
                })
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("Goodbye withdraws the held card");
    assert!(!launcher.effects.lock().unwrap().contains(&"screenshot"));
    // Route 10 keeps the session's browser after Goodbye closes route 9.
    // Its snapshot must now pass through the per-conversation queue, proving
    // that the closed navigation no longer blocks surviving requests.
    let mut snapshot = call(803, "snapshot", json!({}));
    snapshot.header.channel = 10;
    send(&planes, &tx, snapshot).await;
    let result = loop {
        let frame = consent_frame(&mut rx).await;
        if frame.header.ty == FrameType::Request {
            assert_eq!(frame.header.channel, 0);
            assert_eq!(body(&frame)["op"], "scope.describe");
            answer_describe(
                &planes,
                &tx,
                &mut rx,
                &frame,
                FrameType::Response,
                describe_answer("active", Some(1), true, true),
            )
            .await;
            continue;
        }
        break frame;
    };
    assert_eq!(result.header.corr, 803);
    assert_eq!(body(&result)["outcome"], "ok", "{}", body(&result));
}
