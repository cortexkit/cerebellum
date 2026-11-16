use super::*;
use crate::test_support::HANG_GUARD;

fn planes() -> Planes {
    Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        None,
        JournalPersistence::Isolated,
    )
}

fn frame(ty: FrameType, channel: u16, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        ty,
        control_flags(),
        channel,
        1,
        7,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn draining() -> Frame {
    frame(
        FrameType::Push,
        0,
        json!({"op":"module.draining", "reason":"restart", "deadline_ms":123}),
    )
}

fn count(planes: &Planes) -> u64 {
    let ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = planes.health.report()
    else {
        panic!("health reply")
    };
    metrics["inFlightActions"].as_u64().unwrap()
}

async fn await_count(planes: &Planes, expected: u64) {
    tokio::time::timeout(HANG_GUARD, async {
        while count(planes) != expected {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("request accounting settles");
}

fn hold(planes: &mut Planes) -> tokio::sync::oneshot::Sender<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    let rx = std::sync::Mutex::new(Some(rx));
    planes.route_test_handler = Some(Arc::new(move || {
        let rx = rx.lock().unwrap().take().unwrap();
        Box::pin(async move {
            rx.await.unwrap();
        })
    }));
    tx
}

#[tokio::test]
async fn in_flight_gauge_counts_live_route_requests() {
    let mut planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    let one = hold(&mut planes);
    handle_frame(frame(FrameType::Request, 1, json!({})), &tx, &planes)
        .await
        .unwrap();
    let oldest = planes.health.oldest_in_flight_instant().unwrap();
    let two = hold(&mut planes);
    handle_frame(frame(FrameType::Request, 2, json!({})), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(count(&planes), 2);
    assert_eq!(planes.health.oldest_in_flight_instant(), Some(oldest));
    one.send(()).unwrap();
    rx.recv().await.unwrap();
    await_count(&planes, 1).await;
    assert!(planes.health.oldest_in_flight_instant().unwrap() >= oldest);
    two.send(()).unwrap();
    rx.recv().await.unwrap();
    await_count(&planes, 0).await;
    assert_eq!(planes.health.oldest_in_flight_instant(), None);
}

#[tokio::test]
async fn a_panicking_handler_still_releases_its_in_flight_slot() {
    let mut planes = planes();
    planes.route_test_handler = Some(Arc::new(|| Box::pin(async { panic!("handler panic") })));
    let (tx, _rx) = mpsc::channel(8);
    handle_frame(frame(FrameType::Request, 1, json!({})), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(count(&planes), 1);
    await_count(&planes, 0).await;
}

#[tokio::test]
async fn draining_refuses_new_requests_and_stops_in_flight() {
    let mut planes = super::tests::management_bound_planes(1, 1);
    let (tx, mut rx) = mpsc::channel(8);
    let release = hold(&mut planes);
    handle_frame(frame(FrameType::Request, 1, json!({"method": management::OPEN_TARGET, "params": {"bundle_identity":"com.example.Nothing"}})), &tx, &planes)
        .await
        .unwrap();
    handle_frame(draining(), &tx, &planes).await.unwrap();
    planes.route_test_handler = None;
    let mut invalid = frame(FrameType::Request, 2, json!({}));
    invalid.body = b"invalid JSON".to_vec();
    handle_frame(invalid, &tx, &planes).await.unwrap();
    let refusal: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(refusal["code"], "module_draining");
    assert_eq!(refusal["detail"]["reason"], "restart");
    assert_eq!(refusal["detail"]["deadline_ms"], 123);
    assert_eq!(
        refusal["detail"]["remedy"],
        "retry after the module restarts"
    );
    assert_eq!(count(&planes), 1);
    release.send(()).unwrap();
    let reply = rx.recv().await.unwrap();
    assert_eq!(reply.header.channel, 1);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(body["outcome"], "module_draining");
    await_count(&planes, 0).await;
}

#[tokio::test]
async fn drain_does_not_wait_on_a_person() {
    let mut planes = computer_grants::tests::CardService::install(
        super::tests::management_bound_planes_with_admission_facts(
            1,
            1,
            Some(&json!({"agentProjectId": "test-project", "sessionKind": "primary"})),
        ),
        1,
        1,
    );
    let root = std::env::temp_dir().join(format!("consent-drain-{}", login_import::new_ask_id()));
    assert!(!root.exists());
    let executable = root.join("browser");
    let login_import::PreparedImport::Ready(plan) = login_import::prepare_import(
        "https://example.com",
        "project",
        &executable,
        login_import::DurableProfileLocation {
            managed_root: root.clone(),
            profile_directory: root.join("profile"),
        },
        login_import::ImportSettings::for_test(
            root.join("sqlite"),
            root.join("data"),
            root.join("cookies"),
            vec![login_import::BrowserSource {
                id: "chrome",
                display_name: "Chrome",
                data_directory: "chrome".into(),
                executable: executable.clone(),
            }],
        ),
    ) else {
        panic!("prepared import")
    };
    let (tx, mut rx) = mpsc::channel(8);
    let (result_tx, result_rx) = tokio::sync::oneshot::channel();
    let inputs = std::sync::Mutex::new(Some((plan, result_tx)));
    let admitted_planes = planes.clone();
    let writer = tx.clone();
    // Start at import_login's prepared-plan boundary to avoid reading the
    // operator's cookie stores. Admission and consent use the real route task.
    planes.route_test_handler = Some(Arc::new(move || {
        let (plan, result_tx) = inputs.lock().unwrap().take().unwrap();
        let planes = admitted_planes.clone();
        let writer = writer.clone();
        Box::pin(async move {
            let facts = planes.routes.get(1, 1).unwrap();
            let result = complete_login_import(&planes, &facts, &writer, 1, 1, plan, None).await;
            result_tx.send(result).unwrap();
        })
    }));
    handle_frame(
        frame(
            FrameType::Request,
            1,
            json!({"method":"browser.import_login", "params":{"origin":"https://example.com"}}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let question = planes.consent_test.as_ref().unwrap().card(1, 1).await;
    assert_eq!(count(&planes), 0);
    handle_frame(draining(), &tx, &planes).await.unwrap();
    assert_eq!(count(&planes), 0);
    let result = tokio::time::timeout(HANG_GUARD, result_rx)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result["outcome"], "module_draining");
    let calls = planes.consent_test.as_ref().unwrap().calls();
    assert!(
        calls
            .iter()
            .any(|(method, params)| method == "consent.withdraw"
                && params["elicitation_id"] == format!("el_test_{}", question.header.corr)),
        "the drain withdraws the card at Cingulate"
    );
    let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.header.ty, FrameType::Response);
    await_count(&planes, 0).await;
}

#[tokio::test]
async fn an_unknown_control_push_is_ignored() {
    let planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    assert!(handle_frame(
        frame(FrameType::Push, 0, json!({"op":"future.op"})),
        &tx,
        &planes
    )
    .await
    .unwrap());
    assert!(rx.try_recv().is_err());
    assert!(!planes.draining.load(std::sync::atomic::Ordering::Acquire));
}
