//! Legacy response bytes remain stable until the bound consumer declares its reader.

use crate::*;
use subc_protocol::{BindIdentity, RouteTarget};

const CASES: &[(&str, &[u8])] = &[
    (
        flat_tools::BROWSER_USE,
        include_bytes!("../tests/fixtures/content_v1_legacy/browser_snapshot.json"),
    ),
    (
        flat_tools::BROWSER_USE,
        include_bytes!("../tests/fixtures/content_v1_legacy/browser_screenshot.json"),
    ),
    (
        flat_tools::COMPUTER_USE,
        include_bytes!("../tests/fixtures/content_v1_legacy/computer_read_state.json"),
    ),
];

async fn bound_planes(declarations: Option<Vec<String>>) -> Planes {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "head-conversation"),
        principal: session_caller_principal_for_test(),
        consumer_capabilities: declarations,
        scope: None,
        admission_facts: Some(
            json!({"agentProjectId":"test-project", "sessionKind":"primary", "effectiveCapabilityScope":["*"]}),
        ),
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        control_flags(),
        0,
        0,
        1,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    handle_frame_for_test(frame, &tx, &planes).await.unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    planes
}

async fn response(planes: &Planes, tool: &str, payload: Value) -> Frame {
    let facts = planes.routes.get(9, 3).unwrap();
    let (tx, mut rx) = mpsc::channel(1);
    tool_result::RESULT_BIND
        .scope(
            Some((tool.to_owned(), facts)),
            send_tool_response(&tx, PROTOCOL_VERSION, 9, 3, 7, payload),
        )
        .await
        .unwrap();
    rx.recv().await.unwrap()
}

#[tokio::test]
async fn legacy_routes_match_main_reply_bytes_including_image() {
    let planes = bound_planes(None).await;
    let mut mismatches = Vec::new();
    for (index, (tool, main_bytes)) in CASES.iter().enumerate() {
        let payload: Value = serde_json::from_slice(main_bytes).unwrap();
        let reply = response(&planes, tool, payload).await;
        assert_eq!(reply.header.ty, FrameType::Response);
        if reply.body.as_slice() != *main_bytes {
            mismatches.push((*tool, index));
        }
        assert_eq!(
            (reply.header.channel, reply.header.epoch, reply.header.corr),
            (9, 3, 7)
        );
    }
    assert!(
        mismatches.is_empty(),
        "legacy main bytes changed for {mismatches:?}"
    );
}

#[tokio::test]
async fn unrelated_consumer_capabilities_do_not_enable_content() {
    let planes = bound_planes(Some(vec!["elicitation".into(), "sampling".into()])).await;
    for (tool, main_bytes) in CASES {
        let reply = response(&planes, tool, serde_json::from_slice(main_bytes).unwrap()).await;
        assert_eq!(reply.body.as_slice(), *main_bytes);
    }
}

#[tokio::test]
async fn declared_reader_gets_content_with_the_same_structured_reply() {
    let planes = bound_planes(Some(vec![
        cortexkit_role_tool_provider::CONTENT_V1_CAPABILITY.into(),
    ]))
    .await;
    for (tool, main_bytes) in CASES {
        let payload: Value = serde_json::from_slice(main_bytes).unwrap();
        let reply = response(&planes, tool, payload.clone()).await;
        let result: cortexkit_role_tool_provider::result::ToolResult =
            serde_json::from_slice(&reply.body).unwrap();
        cortexkit_role_tool_provider::result::validate(&result).unwrap();
        assert_eq!(Value::Object(result.structured_content.unwrap()), payload);
        if payload.get("image").is_some() {
            assert!(result.content.iter().any(|part| matches!(
                part,
                cortexkit_role_tool_provider::result::ContentPart::Image(_)
            )));
        }
    }
}
