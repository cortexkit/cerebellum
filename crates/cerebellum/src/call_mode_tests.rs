//! A run's route lifetime must not outlive its in-flight browser calls.

use crate::*;
use subc_protocol::call_mode::CallMode;
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};

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
    let scope = ScopeStamp::new(
        session_caller_principal_for_test().unwrap(),
        "run",
        1,
        ScopeKind::Ephemeral,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some("test-project".into()))
            .with_delegates(true)
            .with_run_id(Some("run-test".into())),
    )
    .with_owner_authorized(true);
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 3,
        principal: session_caller_principal_for_test(),
        identity: subc_protocol::BindIdentity::new("/test/project", "test", "head-conversation"),
        admission_facts: None,
        consumer_capabilities: None,
        target: subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        scope: Some(scope),
        role_versions: None,
        call_mode: Some(CallMode::Codemode),
    };
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
