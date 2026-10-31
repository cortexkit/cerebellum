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

fn assert_image_bytes_are_delivered_once(
    result: &cortexkit_role_tool_provider::result::ToolResult,
    payload: &Value,
) {
    if let Some(image) = payload.get("image") {
        assert!(result.structured_content.as_ref().unwrap()["image"]
            .get("data_b64")
            .is_none());
        let images: Vec<_> = result
            .content
            .iter()
            .filter_map(|part| match part {
                cortexkit_role_tool_provider::result::ContentPart::Image(image) => Some(image),
                _ => None,
            })
            .collect();
        assert_eq!(images.len(), 1);
        assert_eq!(images[0].data, image["data_b64"].as_str().unwrap());
    }
}

#[tokio::test]
async fn declared_reader_gets_content_with_the_same_structured_reply() {
    let planes = bound_planes(Some(vec![
        cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
    ]))
    .await;
    for (tool, main_bytes) in CASES {
        let payload: Value = serde_json::from_slice(main_bytes).unwrap();
        let reply = response(&planes, tool, payload.clone()).await;
        let result: cortexkit_role_tool_provider::result::ToolResult =
            serde_json::from_slice(&reply.body).unwrap();
        cortexkit_role_tool_provider::result::validate(&result).unwrap();
        assert_image_bytes_are_delivered_once(&result, &payload);
        let mut expected = payload;
        if let Some(image) = expected.get_mut("image").and_then(Value::as_object_mut) {
            image.remove("data_b64");
        }
        assert_eq!(Value::Object(result.structured_content.unwrap()), expected);
    }
}

/// Bodies a route received at cerebellum 60488c67, when the format was still
/// named `content/v1` and the route declared that name. Captured from the same
/// `CASES` payloads through `send_tool_response`, with duplicate structured
/// image bytes removed for single delivery; see the fixture README.
const RETIRED_NAME_BODIES: &[&[u8]] = &[
    include_bytes!("../tests/fixtures/tool_result_v1_bodies/browser_snapshot.json"),
    include_bytes!("../tests/fixtures/tool_result_v1_bodies/browser_screenshot.json"),
    include_bytes!("../tests/fixtures/tool_result_v1_bodies/computer_read_state.json"),
];

/// The format rename preserved the captured bodies. Apart from removing
/// duplicate structured image bytes, a `tool-result/v1` reader still gets those
/// exact bytes, including the original image content part.
#[tokio::test]
async fn tool_result_v1_reader_gets_the_bytes_the_retired_name_got() {
    let planes = bound_planes(Some(vec![
        cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
    ]))
    .await;
    assert_eq!(CASES.len(), RETIRED_NAME_BODIES.len());
    for ((tool, main_bytes), captured) in CASES.iter().zip(RETIRED_NAME_BODIES) {
        let payload: Value = serde_json::from_slice(main_bytes).unwrap();
        let reply = response(&planes, tool, payload.clone()).await;
        assert_eq!(reply.header.ty, FrameType::Response);
        assert!(
            reply.body.as_slice() == *captured,
            "{tool}: tool-result/v1 body differs from the single-delivery fixture:\n{}",
            String::from_utf8_lossy(&reply.body)
        );
        let result = serde_json::from_slice(&reply.body).unwrap();
        assert_image_bytes_are_delivered_once(&result, &payload);
    }
}

/// The contract renamed the format with no alias, so a route that still
/// declares the retired `content/v1` name is an undeclared route and keeps the
/// legacy body.
#[tokio::test]
async fn the_retired_content_v1_name_gets_the_legacy_body() {
    let planes = bound_planes(Some(vec!["content/v1".into()])).await;
    for (tool, main_bytes) in CASES {
        let reply = response(&planes, tool, serde_json::from_slice(main_bytes).unwrap()).await;
        assert_eq!(reply.body.as_slice(), *main_bytes, "{tool}");
    }
}
