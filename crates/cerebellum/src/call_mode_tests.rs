//! A run's route lifetime must not outlive its in-flight browser calls.

use crate::*;
use subc_protocol::call_mode::CallMode;
use subc_protocol::scope::{ParentState, ScopeAttributes, ScopeKind, ScopeParent, ScopeStamp};

fn request(channel: u16, corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        if channel == 0 { 0 } else { 3 },
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
async fn ending_a_run_cancels_its_queued_call_without_ending_the_head() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    let bind = run_bind(run_stamp());
    let (tx, mut rx) = mpsc::channel(8);
    handle_frame_for_test(
        request(0, 1, serde_json::to_value(bind).unwrap()),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    let facts = planes.routes.get(9, 3).unwrap();
    assert_eq!(facts.identity.conversation_key, "head-conversation");
    assert_eq!(
        facts.identity.session_kind,
        cerebellum_core::identity::SessionKind::Primary
    );
    let (guard, _) = planes
        .browser_queue
        .arrive("head-conversation".into(), None)
        .acquire()
        .await;
    handle_frame_for_test(
        request(
            9,
            2,
            json!({"name":"browser_use", "arguments":{"action":"snapshot"}}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    assert!(planes.browser_queue.has_users(2));
    assert!(planes.cancellations.get((9, 3, 2)).is_some());
    tokio::task::yield_now().await;
    let goodbye = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Goodbye,
        control_flags(),
        9,
        3,
        0,
        vec![],
    )
    .unwrap();
    handle_frame_for_test(goodbye, &tx, &planes).await.unwrap();
    drop(tx);
    assert!(
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .is_none(),
        "a closed run route must emit neither a result nor an elicitation frame"
    );
    assert!(planes.cancellations.get((9, 3, 2)).is_none());
    assert!(planes.browser_queue.has_users(1));
    drop(guard);
    assert!(planes.browser_queue.is_empty());
}

fn run_stamp() -> ScopeStamp {
    ScopeStamp::new(
        session_caller_principal_for_test().unwrap(),
        "run",
        1,
        ScopeKind::Ephemeral,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some("test-project".into()))
            .with_run_id(Some("run-test".into())),
    )
    .with_owner_authorized(true)
    .with_parent(Some(ScopeParent::new(
        session_caller_principal_for_test().unwrap(),
        "head",
        7,
    )))
    .with_parent_state(Some(ParentState::Linked))
}

fn run_bind(scope: ScopeStamp) -> ModuleControlRequest {
    ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 3,
        principal: Some(subc_protocol::Principal::Reserved {
            module_id: "basal".into(),
        }),
        identity: subc_protocol::BindIdentity::new("/untrusted/run", "run", "misleading-session"),
        admission_facts: None,
        consumer_capabilities: Some(vec![
            cortexkit_role_tool_provider::CONTENT_V1_CAPABILITY.into()
        ]),
        target: subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        scope: Some(scope),
        role_versions: None,
        call_mode: Some(CallMode::Codemode),
    }
}

async fn exchange(planes: &Planes, channel: u16, corr: u64, body: Value) -> Frame {
    let (tx, mut rx) = mpsc::channel(16);
    handle_frame_for_test(request(channel, corr, body), &tx, planes)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .unwrap()
        .unwrap()
}

async fn bind_head(planes: &Planes) {
    let scope = ScopeStamp::new(
        session_caller_principal_for_test().unwrap(),
        "head",
        7,
        ScopeKind::Head,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some("test-project".into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true);
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 8,
        epoch: 3,
        principal: session_caller_principal_for_test(),
        identity: subc_protocol::BindIdentity::new("/test/project", "test", "head-conversation"),
        admission_facts: None,
        consumer_capabilities: Some(vec!["elicitation".into()]),
        target: subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        scope: Some(scope),
        role_versions: None,
        call_mode: None,
    };
    assert_eq!(
        exchange(planes, 0, 1, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
}

async fn refused_run(planes: &Planes, bind: ModuleControlRequest, code: &str) {
    let reply = exchange(planes, 0, 1, serde_json::to_value(bind).unwrap()).await;
    assert_eq!(reply.header.ty, FrameType::Error);
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["code"],
        code
    );
    assert!(
        planes.routes.get(9, 3).is_none(),
        "a refused run must resolve no context"
    );
}

#[tokio::test]
async fn run_parent_must_be_linked() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    for state in [None, Some(ParentState::Pending), Some(ParentState::Ended)] {
        refused_run(
            &planes,
            run_bind(run_stamp().with_parent_state(state)),
            "run_parent_not_linked",
        )
        .await;
    }
}

#[tokio::test]
async fn run_agent_must_match_attested_head() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    let mut stamp = run_stamp();
    stamp.attributes.agent_id = Some("other-agent".into());
    refused_run(&planes, run_bind(stamp), "run_agent_mismatch").await;
}

#[tokio::test]
async fn run_requires_live_head_at_parent_epoch() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    refused_run(&planes, run_bind(run_stamp()), "run_parent_unavailable").await;
    bind_head(&planes).await;
    let mut stamp = run_stamp();
    stamp.parent.as_mut().unwrap().scope_epoch += 1;
    refused_run(&planes, run_bind(stamp), "run_parent_unavailable").await;
    planes.routes.remove(8, 3);
    refused_run(&planes, run_bind(run_stamp()), "run_parent_unavailable").await;
}

#[tokio::test]
async fn run_head_identity_requires_provider_attestation() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    let mut head = planes.routes.get(8, 3).unwrap();
    head.agent_project_id_attested = false;
    planes.routes.insert(8, 3, head);
    refused_run(&planes, run_bind(run_stamp()), "run_parent_unavailable").await;
}

#[tokio::test]
async fn basal_requires_run_id_and_codemode() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    let mut stamp = run_stamp();
    stamp.attributes.run_id = None;
    refused_run(&planes, run_bind(stamp), "principal_denied").await;
    for mode in [None, Some(CallMode::Classic), Some(CallMode::Flow)] {
        let mut bind = run_bind(run_stamp());
        if let ModuleControlRequest::RouteBind { call_mode, .. } = &mut bind {
            *call_mode = mode;
        }
        refused_run(&planes, bind, "principal_denied").await;
    }
}

#[tokio::test]
async fn run_ignores_bind_session_and_borrows_head_authority() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    let ack = exchange(
        &planes,
        0,
        1,
        serde_json::to_value(run_bind(run_stamp())).unwrap(),
    )
    .await;
    assert_eq!(ack.header.ty, FrameType::Response);
    let run = planes.routes.get(9, 3).unwrap();
    let head = planes.routes.get(8, 3).unwrap();
    assert_eq!(run.identity, head.identity);
    assert!(run.admits_session_calls());
    assert!(run.flow_id.is_none());
    assert_eq!(permission_scope::card_stamp(&run), head.scope.as_ref());
    assert_eq!(
        permission_scope::authorizing_holder(&run),
        permission_scope::authorizing_holder(&head)
    );
    planes.routes.remove(8, 3);
    let reply = exchange(
        &planes,
        9,
        9,
        json!({"name":"browser_use", "arguments":{"action":"status"}}),
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<Value>(&reply.body).unwrap()["code"],
        "run_parent_unavailable"
    );
}
