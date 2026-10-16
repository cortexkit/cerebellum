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
