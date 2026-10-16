use super::turn_stop_vectors::{cancel, check};
use super::*;

fn navigation(corr: u64) -> Frame {
    request(
        corr,
        "browser_use",
        json!({
            "action":"navigate", "url":"https://requested.example/path",
            "intent":"read the page", "wait":"none",
            "severity":{"tier":3,"credential":false,"financial":false}
        }),
    )
}

async fn send(planes: &Planes, tx: &mpsc::Sender<Frame>, frame: Frame) {
    cerebellum::handle_frame_for_test(frame, tx, planes)
        .await
        .unwrap();
}

#[tokio::test]
async fn turn_stop_cancel_browser_queued_never_dispatches() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(16);
    send(&planes, &tx, navigation(800)).await;
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    let request = navigation(801);
    send(&planes, &tx, request.clone()).await;
    assert!(tokio::time::timeout(Duration::from_millis(25), rx.recv())
        .await
        .is_err());
    let stop = cancel(&request);
    send(&planes, &tx, stop.clone()).await;
    let reply = frame_for(&mut rx, 801).await;
    assert_eq!(reply.header.ty, FrameType::Error);
    assert_eq!(body(&reply)["code"], "cancelled");
    check(
        "browser-queued",
        "queued behind another call's site card",
        &request,
        &stop,
        Some(&reply),
    );
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    frame_for(&mut rx, 800).await;
    assert_eq!(
        *launcher.effects.lock().unwrap(),
        ["navigate"],
        "cancelled queued call must not run later"
    );
}

#[tokio::test]
async fn turn_stop_cancel_browser_site_card_answers_and_detaches() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let request = navigation(802);
    send(&planes, &tx, request.clone()).await;
    let service = ScriptedCarrier::for_planes(&planes);
    let question = service.card(9, 3).await;
    let stop = cancel(&request);
    send(&planes, &tx, stop.clone()).await;
    let reply = frame_for(&mut rx, 802).await;
    let cancelled = body(&reply);
    assert_eq!(cancelled["outcome"], "cancelled");
    assert!(cancelled.get("remedy").is_none());
    assert!(
        cancelled.get("detail").is_none(),
        "a stop is not a grant refusal"
    );
    assert!(cancelled.get("grant_request").is_none());
    assert!(service
        .calls()
        .iter()
        .any(|(method, _)| method == "consent.detach"));
    assert!(!service
        .calls()
        .iter()
        .any(|(method, _)| method == "consent.withdraw"));
    check(
        "browser-site-card",
        "parked awaiting a site card on a live route",
        &request,
        &stop,
        Some(&reply),
    );
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    drain_browser(&planes).await;
    assert_eq!(permission_support::count(&planes), 1);
    assert!(
        launcher.effects.lock().unwrap().is_empty(),
        "late approval grants access but never resumes the cancelled action"
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn turn_stop_cancel_browser_running_reports_uncertainty() {
    let (planes, launcher) = blocking_grant_fixture().await;
    let hold = launcher.navigate_hold.hold();
    let (tx, mut rx) = mpsc::channel(8);
    let request = navigation(803);
    send(&planes, &tx, request.clone()).await;
    let question = ScriptedCarrier::for_planes(&planes).card(9, 3).await;
    answer_browser(&planes, &tx, &question, "allow_30m").await;
    effect_seen(&launcher, "navigate").await;
    let stop = cancel(&request);
    send(&planes, &tx, stop.clone()).await;
    let reply = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("running browser cancellation answers within its release/cleanup budget")
        .unwrap();
    assert_eq!(reply.header.corr, 803);
    assert_eq!(body(&reply)["outcome"], "dispatch_outcome_unknown");
    assert_eq!(body(&reply)["detail"]["step"], "dispatch");
    check(
        "browser-running",
        "navigation dispatched; scripted browser command has not returned",
        &request,
        &stop,
        Some(&reply),
    );
    drop(hold);
}

async fn no_reply(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    rx: &mut mpsc::Receiver<Frame>,
    stop: Frame,
) {
    send(planes, tx, stop).await;
    let ping = Frame::build(
        FrameType::Ping,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        999,
        Vec::new(),
    )
    .unwrap();
    send(planes, tx, ping).await;
    let pong = rx.recv().await.unwrap();
    assert_eq!(
        pong.header.ty,
        FrameType::Pong,
        "Cancel must not answer before the following Ping"
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn turn_stop_cancel_after_reply_and_unknown_corr_are_silent() {
    let (planes, _) = blocking_grant_fixture().await;
    let (tx, mut rx) = mpsc::channel(8);
    let request = request(804, "browser.status", json!({}));
    send(&planes, &tx, request.clone()).await;
    frame_for(&mut rx, 804).await;
    let stop = cancel(&request);
    no_reply(&planes, &tx, &mut rx, stop.clone()).await;
    check(
        "after-reply",
        "original request already replied",
        &request,
        &stop,
        None,
    );
    let request = super::request(805, "browser.status", json!({}));
    let stop = cancel(&request);
    no_reply(&planes, &tx, &mut rx, stop.clone()).await;
    check(
        "unknown-corr",
        "request was never sent; correlation is unknown",
        &request,
        &stop,
        None,
    );
}
