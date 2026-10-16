//! A computer call waiting on a person, driven through the frame loop: the
//! drain, the route's unbind and a Cancel frame each release it at once, and
//! the request is counted exactly once as in flight or as awaiting consent.

pub(crate) mod stack_tests;
use super::*;
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};

const CHANNEL: u16 = 7;
const EPOCH: u32 = 1;
const CORR: u64 = 42;
const APP: &str = "com.example.Editor";

struct Running;

impl management::TargetResolver for Running {
    fn resolve(&self, bundle_identity: &str) -> TargetResolution {
        TargetResolution::Resolved(ProcessGrant {
            pid: 4242,
            bundle_identity: bundle_identity.to_string(),
            process_generation_evidence: "1700000000000000".to_string(),
        })
    }

    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn computer_grants::AppCode> {
        Arc::new(computer_grants::SignedByFixtureTeam)
    }
}

/// Planes with one tool route that declares it can relay a question, and
/// with `computer.wait` admitted.
fn planes() -> Planes {
    computer_grants::tests::CardService::install(planes_without_cards(), CHANNEL, EPOCH)
}

fn planes_without_cards() -> Planes {
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::default()),
        None,
        JournalPersistence::Isolated,
    );
    planes.management = Arc::new(ManagementPlane::new(Arc::new(Running)));
    // The production plane reads the real screen lock, and a locked
    // developer machine would refuse the wait before it asks anyone.
    // These tests are about the parked question, so the screen is unlocked.
    planes.computer =
        computer_capability::computer_audit(JournalPersistence::Isolated).map(|audit| {
            Arc::new(
                computer_capability::ComputerPlane::with_synthetic_driver(audit, || {
                    computer_capability::NativeComputerPlatformDriver::default()
                        .without_expected_post_condition()
                })
                .with_permission_liveness(computer_capability::live_for_test())
                .with_session_lock_for_test(Some(false)),
            )
        });
    planes.computer_admitted = test_admitted_computer_capabilities();
    planes.routes.insert(
        CHANNEL,
        EPOCH,
        AcceptedBindFacts::from_bind(
            &subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string()),
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
            })),
            Some(&["elicitation".to_string()]),
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    planes
}

fn frame(ty: FrameType, channel: u16, corr: u64, body: Value) -> Frame {
    Frame::build(
        ty,
        control_flags(),
        channel,
        if channel == 0 { 0 } else { EPOCH },
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn wait_request() -> Frame {
    frame(
        FrameType::Request,
        CHANNEL,
        CORR,
        json!({
            "name": "computer.wait",
            "arguments": {
                "app": APP,
                "predicate": {"kind": "element_present", "element": {"Identifier": "ready"}},
                "timeout_ms": 0,
            },
        }),
    )
}

/// `(inFlightActions, awaitingConsent)` from the health reply.
fn counters(planes: &Planes) -> (u64, u64) {
    let ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = planes.health.report()
    else {
        panic!("health reply")
    };
    (
        metrics["inFlightActions"].as_u64().unwrap(),
        metrics["awaitingConsent"].as_u64().unwrap(),
    )
}

async fn settle_to(planes: &Planes, expected: (u64, u64)) {
    tokio::time::timeout(Duration::from_secs(2), async {
        while counters(planes) != expected {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "request accounting settled at {:?}, expected {expected:?}",
            counters(planes)
        )
    });
}

/// Send the wait and read the question it puts, with the call parked.
async fn parked_call(
    planes: &Planes,
    tx: &mpsc::Sender<Frame>,
    _rx: &mut mpsc::Receiver<Frame>,
) -> String {
    handle_frame(wait_request(), tx, planes).await.unwrap();
    let question = planes
        .consent_test
        .as_ref()
        .unwrap()
        .card(CHANNEL, EPOCH)
        .await;
    assert_eq!(question.header.ty, FrameType::Request);
    let body: Value = serde_json::from_slice(&question.body).unwrap();
    assert_eq!(body["params"]["target"]["kind"], "app");
    settle_to(planes, (0, 1)).await;
    body["id"].as_str().unwrap().to_string()
}

async fn reply(rx: &mut mpsc::Receiver<Frame>) -> Value {
    let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the parked call answered at once")
        .unwrap();
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(reply.header.corr, CORR);
    serde_json::from_slice(&reply.body).unwrap()
}

#[tokio::test]
async fn withdrawing_an_asked_computer_call_keeps_its_late_app_grant() {
    stack_tests::withdraw_asked_call_and_apply_late_grant(planes()).await;
}

#[tokio::test]
async fn a_drain_releases_a_parked_call_at_once_with_the_gauge_restored() {
    let planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame(wait_request(), &tx, &planes).await.unwrap();
    let question = planes
        .consent_test
        .as_ref()
        .unwrap()
        .card(CHANNEL, EPOCH)
        .await;
    assert_eq!(question.header.ty, FrameType::Request);
    settle_to(&planes, (0, 1)).await;

    handle_frame(
        frame(
            FrameType::Push,
            0,
            0,
            json!({"op": "module.draining", "reason": "restart", "deadline_ms": 123}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let body = reply(&mut rx).await;
    let calls = planes.consent_test.as_ref().unwrap().calls();
    assert!(
        calls
            .iter()
            .any(|(method, params)| method == "consent.withdraw"
                && params["elicitation_id"] == format!("el_test_{}", question.header.corr)),
        "drain ends the app card at Cingulate"
    );
    assert!(rx.try_recv().is_err(), "no reverse Cancel frame");
    assert_eq!(body["outcome"], "module_draining", "{body}");
    settle_to(&planes, (0, 0)).await;
}

#[tokio::test]
async fn an_unbind_releases_a_parked_call_and_a_late_allow_grants_nothing() {
    let planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    let ask_id = parked_call(&planes, &tx, &mut rx).await;
    let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();

    handle_frame(
        frame(FrameType::Goodbye, CHANNEL, 0, json!({})),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    settle_to(&planes, (0, 0)).await;
    // The caller is gone, so nothing is sent back.
    tokio::time::sleep(Duration::from_millis(50)).await;
    while let Ok(query) = rx.try_recv() {
        let response = computer_grants::tests::scope_reply(&query)
            .expect("a reply was sent to an unbound route");
        handle_frame(response, &tx, &planes).await.unwrap();
    }
    assert!(
        rx.try_recv().is_err(),
        "a reply was sent to an unbound route"
    );
    let grants = planes.management.computer_grants();
    assert!(
        !grants.question_open(&ask_id),
        "the question outlived its conversation"
    );

    let _ = planes.consent_test.as_ref().unwrap().answer_id(
        &ask_id,
        cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"})),
    );
    let caller = computer_grants::GrantCaller {
        holder: permission_scope::authorizing_holder(&facts),
        conversation_key: facts.identity.conversation_key.clone(),
        agent_project_id: facts.identity.agent_project_id.clone(),
        durable_identity_attested: false,
    };
    let need = computer_grants::GrantNeed::App {
        bundle_identity: APP.to_string(),
        display_name: APP.to_string(),
        code: Arc::new(computer_grants::SignedByFixtureTeam),
    };
    assert!(
        !grants.holds(&caller, &need),
        "a late allow on a withdrawn question granted"
    );
}

#[tokio::test]
async fn a_cancel_releases_a_parked_call_and_keeps_the_question_for_the_conversation() {
    let planes = planes();
    let (tx, mut rx) = mpsc::channel(8);
    let ask_id = parked_call(&planes, &tx, &mut rx).await;

    handle_frame(
        frame(FrameType::Cancel, CHANNEL, CORR, json!({})),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let body = reply(&mut rx).await;
    assert_eq!(body["outcome"], "cancelled", "{body}");
    assert_eq!(body["attempts"], 0, "{body}");
    settle_to(&planes, (0, 0)).await;
    assert!(
        planes.management.computer_grants().question_open(&ask_id),
        "the conversation is still bound, so its question stays open"
    );
}

#[tokio::test]
async fn turn_stop_cancel_computer_app_card_accepts_empty_and_legacy_bodies() {
    let mut replies = Vec::new();
    for legacy_body in [false, true] {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        let mut request = wait_request();
        let mut body: Value = serde_json::from_slice(&request.body).unwrap();
        body["name"] = json!("computer_use");
        body["arguments"]["action"] = json!("wait");
        request = Frame::build(
            FrameType::Request,
            control_flags(),
            CHANNEL,
            EPOCH,
            CORR,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        handle_frame_for_test(request.clone(), &tx, &planes)
            .await
            .unwrap();
        let question = planes
            .consent_test
            .as_ref()
            .unwrap()
            .card(CHANNEL, EPOCH)
            .await;
        let ask_id = serde_json::from_slice::<Value>(&question.body).unwrap()["id"]
            .as_str()
            .unwrap()
            .to_string();
        settle_to(&planes, (0, 1)).await;
        let mut stop = crate::turn_stop_vectors::cancel(&request);
        if legacy_body {
            stop = frame(FrameType::Cancel, CHANNEL, CORR, json!({}));
        }
        handle_frame_for_test(stop.clone(), &tx, &planes)
            .await
            .unwrap();
        let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("cancelled app-card call must not hang")
            .unwrap();
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "cancelled");
        assert_eq!(body["attempts"], 0);
        settle_to(&planes, (0, 0)).await;
        assert!(planes.management.computer_grants().question_open(&ask_id));
        assert!(planes
            .consent_test
            .as_ref()
            .unwrap()
            .calls()
            .iter()
            .any(|(method, _)| method == "consent.detach"));
        assert!(rx.try_recv().is_err());
        if !legacy_body {
            crate::turn_stop_vectors::check(
                "computer-app-card",
                "parked awaiting an app card on a live route",
                &request,
                &stop,
                Some(&reply),
            );
        }
        replies.push(reply.body);
    }
    assert_eq!(
        replies[0], replies[1],
        "empty wire body and legacy JSON body behave identically"
    );
}

#[tokio::test]
async fn turn_stop_cancel_computer_queued_answers_before_the_head_card() {
    let mut planes = planes();
    Arc::make_mut(&mut planes.computer_admitted).insert("computer.read_state".into());
    let (tx, mut rx) = mpsc::channel(8);
    parked_call(&planes, &tx, &mut rx).await;
    let request = frame(
        FrameType::Request,
        CHANNEL,
        CORR + 1,
        json!({"name":"computer_use", "arguments":{"action":"read_state", "target":APP}}),
    );
    handle_frame_for_test(request.clone(), &tx, &planes)
        .await
        .unwrap();
    if let Ok(early) = tokio::time::timeout(Duration::from_millis(25), rx.recv()).await {
        panic!("read_state must wait behind the head's app card: {early:?}");
    }
    let stop = crate::turn_stop_vectors::cancel(&request);
    handle_frame_for_test(stop.clone(), &tx, &planes)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("queued cancellation must not wait on the head's card")
        .unwrap();
    assert_eq!(reply.header.corr, CORR + 1);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap(),
        json!({
            "outcome":"cancelled", "remedy":"the call was cancelled before it ran; nothing was done"
        })
    );
    crate::turn_stop_vectors::check(
        "computer-queued",
        "read_state queued behind another call's app card",
        &request,
        &stop,
        Some(&reply),
    );
    handle_frame_for_test(
        crate::turn_stop_vectors::cancel(&wait_request()),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    self::reply(&mut rx).await;
    settle_to(&planes, (0, 0)).await;
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn turn_stop_cancel_running_keys_releases_both_presses() {
    use cerebellum_computer::app_state::source::{
        AppStateReadError, AppStateSource, ElementActionError, ElementHandle, RawAppState,
        ReadBounds,
    };
    struct NoFocusedField;
    impl AppStateSource for NoFocusedField {
        fn read_app_state(
            &self,
            _: &ProcessGrant,
            _: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            Err(AppStateReadError::Unreadable)
        }
        fn focused_element(
            &self,
            _: &ProcessGrant,
        ) -> Result<Option<ElementHandle>, ElementActionError> {
            Ok(None)
        }
    }
    let mut planes = planes();
    Arc::make_mut(&mut planes.computer_admitted).insert("computer.keys".into());
    let sequence = Arc::new(computer_capability::turn_stop_driver::Sequence::default());
    let script = sequence.clone();
    planes.computer = Ok(Arc::new(
        computer_capability::ComputerPlane::with_synthetic_driver(
            computer_capability::computer_audit(JournalPersistence::Isolated).unwrap(),
            move || computer_capability::NativeComputerPlatformDriver::scripted(script.clone()),
        )
        .with_permission_liveness(computer_capability::live_for_test())
        .with_session_lock_for_test(Some(false))
        .with_app_state_source(Arc::new(NoFocusedField)),
    ));
    let (tx, mut rx) = mpsc::channel(8);
    let request = frame(
        FrameType::Request,
        CHANNEL,
        806,
        json!({"name":"computer_use", "arguments":{"action":"keys", "target":APP, "keys":["shift","a"]}}),
    );
    handle_frame_for_test(request.clone(), &tx, &planes)
        .await
        .unwrap();
    let service = planes.consent_test.as_ref().unwrap();
    let question = service.card(CHANNEL, EPOCH).await;
    assert!(service.answer(
        question.header.corr,
        cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
    ));
    tokio::select! {
        _ = sequence.posted.notified() => {},
        early = rx.recv() => panic!("keys must reach the scripted platform: {}", String::from_utf8_lossy(&early.unwrap().body)),
        _ = tokio::time::sleep(Duration::from_secs(5)) => panic!("scripted sequence did not reach its second press"),
    }
    let stop = crate::turn_stop_vectors::cancel(&request);
    handle_frame_for_test(stop.clone(), &tx, &planes)
        .await
        .unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("running sequence cancellation must answer")
        .unwrap();
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["outcome"], "dispatch_outcome_unknown");
    assert_eq!(body["detail"]["step"], "dispatch");
    assert_eq!(body["detail"]["held_state"], "released");
    // Observe paired recovery posts as well as the reply: a label alone could
    // claim successful release while the actual keys remained down.
    assert_eq!(
        *sequence.events.lock().unwrap(),
        [(0, false), (1, false), (3, true), (2, true)]
    );
    crate::turn_stop_vectors::check(
        "computer-running-keys",
        "scripted platform has posted two presses; paired releases remain",
        &request,
        &stop,
        Some(&reply),
    );
    settle_to(&planes, (0, 0)).await;
    assert!(rx.try_recv().is_err());
}

/// The grant operations answer on a management route.
#[tokio::test]
async fn the_grant_operations_answer_on_the_management_surface() {
    let planes = super::tests::management_bound_planes(4, 1);
    let (tx, mut rx) = mpsc::channel(8);
    for (corr, body) in [
        (
            1,
            json!({"method": management::LIST_APP_GRANTS, "params": {}}),
        ),
        (
            2,
            json!({
                "method": management::REVOKE_APP_GRANT,
                "params": {"grantee": "pj-a", "bundle_identity": APP},
            }),
        ),
        (
            3,
            json!({"method": management::REVOKE_APP_GRANT, "params": {"grantee": "pj-a"}}),
        ),
    ] {
        let request = Frame::build(
            FrameType::Request,
            control_flags(),
            4,
            1,
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap();
        handle_route_request(request, &tx, &planes).await.unwrap();
    }
    let listed: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(listed["grants"], json!([]), "{listed}");
    assert_eq!(listed["store"]["state"], "loaded", "{listed}");
    let revoked: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(revoked["outcome"], "grant_not_found", "{revoked}");
    let refused: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(refused["outcome"], "invalid_request", "{refused}");
    assert_eq!(refused["detail"]["field"], "bundle_identity", "{refused}");
    assert_eq!(
        refused["detail"]["reason_code"], "missing_field",
        "{refused}"
    );
}
