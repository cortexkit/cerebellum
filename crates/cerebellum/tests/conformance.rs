//! Conformance tests: verify the wire-v2 registration exchange and
//! route.bind handling against the pinned conformance fixture.
//!
//! These tests drive the real module loop handlers with in-memory duplex
//! streams, asserting the exact frame shapes the pinned fixture requires:
//! - HELLO carries the manifest with protocol_ver=2 and exactly one
//!   `browser.status` capability with `execution_mode: pure`.
//! - route.bind from a first-party principal is acked.
//! - route.bind from an ineligible principal receives the pinned transport
//!   rejection (Error frame with `principal_denied`).
//! - health.check returns a mechanical report from the insulated lane.
//! - browser.status returns a flat result body with `no_session` and a
//!   resolved context.

#![cfg(test)]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};
use subc_control::{ClientControlRequest, ClientControlResponse};
use subc_protocol::manifest::{ExecutionMode, ProviderRole};
use subc_protocol::session::{
    ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
};
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, ModuleHelloBody, Principal, Priority, RouteTarget,
    PROTOCOL_VERSION,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

use cerebellum::manifest;
use cerebellum_core::principal;

const MODULE_ID: &str = "cerebellum";

fn assert_field_set(body: &Value, expected: &[&str]) {
    let object = body.as_object().expect("response body must be an object");
    let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
    let mut expected = expected.to_vec();
    actual.sort_unstable();
    expected.sort_unstable();
    assert_eq!(actual, expected);
}

/// Read the pinned conformance fixture for route.bind and assert the module's
/// HELLO body shape matches the wire-v2 contract it implies.
#[tokio::test]
async fn hello_body_matches_wire_v2_contract() {
    let manifest = manifest::build(MODULE_ID);
    let hello = subc_protocol::ModuleHelloBody {
        manifest: manifest.clone(),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            "route.status".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: None,
    };

    // The HELLO body must serialize to valid JSON with the required fields.
    let body: Value = serde_json::to_value(&hello).unwrap();
    assert_eq!(body["protocol_ver"], 2);
    assert_eq!(body["manifest"]["protocol_ver"], 2);
    assert_eq!(body["manifest"]["module_id"], MODULE_ID);
    assert_eq!(body["manifest"]["trust_tier"], "first_party");

    // Exactly one application capability: browser.status, execution_mode pure.
    let provides = body["manifest"]["provides"].as_array().unwrap();
    assert_eq!(provides.len(), 1);
    assert_eq!(provides[0]["role"], "tool_provider");
    let tools = provides[0]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 1, "exactly one application capability");
    assert_eq!(tools[0]["name"], "browser.status");
    assert_eq!(tools[0]["execution_mode"], "pure");

    // Control ops are advertised but are NOT application capabilities.
    let control_ops = body["control_ops"].as_array().unwrap();
    assert!(control_ops.contains(&json!("route.bind")));
    assert!(control_ops.contains(&json!("route.status")));
    assert!(control_ops.contains(&json!("health.check")));
}

/// The manifest advertises exactly one application capability. Standard
/// wire-v2 health, discovery, and control surfaces are not counted.
#[tokio::test]
async fn manifest_advertises_exactly_one_application_capability() {
    let manifest = manifest::build(MODULE_ID);
    let ProviderRole::ToolProvider { tools, .. } = &manifest.provides[0] else {
        panic!("expected ToolProvider");
    };
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "browser.status");
    assert_eq!(tools[0].execution_mode, ExecutionMode::Pure);
}

/// A first-party route.bind (Direct principal) is acked with a RouteBindAck
/// response, matching the conformance fixture's route.bind exchange.
#[tokio::test]
async fn first_party_route_bind_is_acked() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());

    let bind = ModuleControlRequest::RouteBind {
        route_channel: 42,
        epoch: 7,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.to_string(),
        },
        identity: BindIdentity {
            project_root: PathBuf::from("/tmp/project"),
            harness: "opencode".to_string(),
            session: "session-0001".to_string(),
        },
        principal: Some(Principal::Direct),
        consumer_capabilities: Some(vec!["elicitation".to_string(), "roots".to_string()]),
        admission_facts: Some(json!({"schema": 1, "verified_class": "member"})),
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        7,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();

    cerebellum::handle_control_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    assert_eq!(response.header.ty, FrameType::Response);
    assert_eq!(response.header.channel, 0);
    assert_eq!(response.header.corr, 7);
    let body: ModuleControlResponse = serde_json::from_slice(&response.body).unwrap();
    assert!(matches!(body, ModuleControlResponse::RouteBindAck {}));
}

/// An ineligible daemon-stamped principal (subc-mcp) receives the exact pinned
/// transport rejection before capability execution: an Error frame with
/// `principal_denied`.
#[tokio::test]
async fn ineligible_principal_receives_transport_rejection() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());

    let bind = ModuleControlRequest::RouteBind {
        route_channel: 42,
        epoch: 7,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.to_string(),
        },
        identity: BindIdentity {
            project_root: PathBuf::from("/tmp/project"),
            harness: "opencode".to_string(),
            session: "session-0001".to_string(),
        },
        principal: Some(Principal::Reserved {
            module_id: "subc-mcp".to_string(),
        }),
        consumer_capabilities: None,
        admission_facts: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        7,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();

    cerebellum::handle_control_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    assert_eq!(
        response.header.ty,
        FrameType::Error,
        "ineligible principal must receive an Error frame, not a Response"
    );
    assert_eq!(response.header.channel, 0);
    assert_eq!(response.header.corr, 7);
    let body: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.code, "principal_denied");
    assert!(
        body.message.contains("subc-mcp"),
        "rejection message should name the principal: {}",
        body.message
    );
}

/// An absent principal is also rejected (fail-closed backstop).
#[tokio::test]
async fn absent_principal_is_rejected() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());

    let bind = ModuleControlRequest::RouteBind {
        route_channel: 42,
        epoch: 7,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.to_string(),
        },
        identity: BindIdentity {
            project_root: PathBuf::from("/tmp/project"),
            harness: "opencode".to_string(),
            session: "session-0001".to_string(),
        },
        principal: None,
        consumer_capabilities: None,
        admission_facts: None,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        7,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();

    cerebellum::handle_control_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    assert_eq!(response.header.ty, FrameType::Error);
    let body: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body.code, "principal_denied");
}

/// health.check returns a mechanical report from the insulated lane.
#[tokio::test]
async fn health_check_returns_insulated_report() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
    health_state.stamp_heartbeat();

    let request = ModuleControlRequest::HealthCheck {};
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        42,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    cerebellum::handle_control_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    assert_eq!(response.header.ty, FrameType::Response);
    assert_eq!(response.header.corr, 42);
    let body: ModuleControlResponse = serde_json::from_slice(&response.body).unwrap();
    match body {
        ModuleControlResponse::HealthCheck {
            status, metrics, ..
        } => {
            assert_eq!(status, subc_protocol::session::HealthStatus::Ok);
            let metrics = metrics.expect("metrics present");
            let obj = metrics.as_object().expect("metrics is an object");
            for key in [
                "heartbeatAgeSecs",
                "oldestQueuedAgeSecs",
                "oldestInFlightAgeSecs",
                "heartbeatThresholdSecs",
                "oldestActionThresholdSecs",
            ] {
                assert!(obj.contains_key(key), "metrics include {key}");
            }
        }
        _ => panic!("expected HealthCheck response"),
    }
}

/// browser.status returns a flat result body with `no_session` and a resolved
/// context (no `{result}` wrapper, no echo of caller-supplied identity).
#[tokio::test]
async fn browser_status_returns_flat_no_session_result() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());

    let request = json!({
        "name": "browser.status",
        "arguments": {},
    });
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        5,
        1,
        99,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    cerebellum::handle_tool_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    assert_eq!(response.header.ty, FrameType::Response);
    assert_eq!(response.header.channel, 5);
    assert_eq!(response.header.epoch, 1);
    assert_eq!(response.header.corr, 99);

    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert!(body.get("result").is_none(), "no {{result}} wrapper");
    assert_eq!(body["outcome"], "no_session");
    assert!(body["context"].is_object(), "context must be resolved");
    assert_eq!(body["context"]["session_kind_effective"], "primary");
    assert_eq!(body["context"]["profile_disposition"], "durable");
    assert_eq!(body["context"]["profile_uuid"], Value::Null);
    assert_eq!(body["session"], Value::Null);
    assert_field_set(&body, &["outcome", "context", "session"]);
    assert_ne!(body["outcome"], "ok");
}

/// browser.status with an unknown field returns `invalid_request` with the
/// pinned detail shape (application-level rejection, not a transport Error).
#[tokio::test]
async fn browser_status_unknown_field_returns_invalid_request_in_body() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());

    let request = json!({
        "name": "browser.status",
        "arguments": {
            "zebra": true,
            "alpha": false,
        },
    });
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        5,
        1,
        99,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    cerebellum::handle_tool_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    // The rejection is application-level: a Response frame (not an Error frame).
    assert_eq!(
        response.header.ty,
        FrameType::Response,
        "schema violations are application-level, not transport Error frames"
    );
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "invalid_request");
    assert_eq!(body["context"], Value::Null);
    assert_eq!(body["session"], Value::Null);
    assert_eq!(body["detail"]["field"], "alpha");
    assert_eq!(body["detail"]["reason_code"], "unknown_field");
    assert_field_set(&body, &["outcome", "context", "session", "detail"]);
}

/// The management-surface method/params envelope is not accepted on a tool
/// route; its members are ordinary unknown envelope fields here.
#[tokio::test]
async fn browser_status_rejects_management_envelope() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
    let request = json!({
        "method": "browser.status",
        "params": {},
    });
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        5,
        1,
        100,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();

    cerebellum::handle_tool_request_for_test(frame, &tx, &health_state)
        .await
        .unwrap();

    let response = rx.recv().await.expect("a response frame");
    assert_eq!(response.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "invalid_request");
    assert_eq!(body["detail"]["field"], "method");
    assert_eq!(body["detail"]["reason_code"], "unknown_field");
    assert_field_set(&body, &["outcome", "context", "session", "detail"]);
}

/// Missing and wrongly typed tool-route envelope members are application
/// validation failures carried by normal Response frames.
#[tokio::test]
async fn browser_status_rejects_malformed_tool_envelopes() {
    let cases = [
        (Value::Null, "$", "wrong_type"),
        (json!({"arguments": {}}), "name", "missing_field"),
        (json!({"name": 7, "arguments": {}}), "name", "wrong_type"),
        (
            json!({"name": "browser.status"}),
            "arguments",
            "missing_field",
        ),
    ];

    for (offset, (request, field, reason_code)) in cases.into_iter().enumerate() {
        let (tx, mut rx) = mpsc::channel::<Frame>(16);
        let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            5,
            1,
            200 + offset as u64,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        cerebellum::handle_tool_request_for_test(frame, &tx, &health_state)
            .await
            .unwrap();

        let response = rx.recv().await.expect("a response frame");
        assert_eq!(response.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "invalid_request");
        assert_eq!(body["detail"]["field"], field);
        assert_eq!(body["detail"]["reason_code"], reason_code);
        assert_field_set(&body, &["outcome", "context", "session", "detail"]);
    }
}

/// Every non-object capability arguments value is rejected as a wrong type
/// in a normal Response frame, rather than being treated as a route error.
#[tokio::test]
async fn browser_status_top_level_wrong_types_return_response_frames() {
    let values = [
        Value::Null,
        json!([]),
        json!("not an object"),
        json!(42),
        json!(true),
    ];

    for (offset, value) in values.into_iter().enumerate() {
        let (tx, mut rx) = mpsc::channel::<Frame>(16);
        let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
        let request = json!({
            "name": "browser.status",
            "arguments": value,
        });
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            5,
            1,
            100 + offset as u64,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        cerebellum::handle_tool_request_for_test(frame, &tx, &health_state)
            .await
            .unwrap();

        let response = rx.recv().await.expect("a response frame");
        assert_eq!(response.header.ty, FrameType::Response);
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "invalid_request");
        assert_eq!(body["detail"]["field"], "$");
        assert_eq!(body["detail"]["reason_code"], "wrong_type");
        assert_eq!(body["context"], Value::Null);
        assert_eq!(body["session"], Value::Null);
        assert_field_set(&body, &["outcome", "context", "session", "detail"]);
    }
}

/// The full sessionKind matrix resolves correctly at the status layer without
/// opening a browser: primary → durable, subagent → disposable, ephemeral → none.
#[tokio::test]
async fn session_kind_matrix_resolves_profile_disposition() {
    use cerebellum_core::identity::{ProfileDisposition, SessionKind};

    assert_eq!(
        ProfileDisposition::for_session_kind(SessionKind::Primary),
        ProfileDisposition::Durable
    );
    assert_eq!(
        ProfileDisposition::for_session_kind(SessionKind::Subagent),
        ProfileDisposition::Disposable
    );
    assert_eq!(
        ProfileDisposition::for_session_kind(SessionKind::Ephemeral),
        ProfileDisposition::None
    );
}

/// Binds for two different agentProjectId values resolve to distinct profile
/// identities.
#[tokio::test]
async fn distinct_agent_project_ids_resolve_to_distinct_profiles() {
    use cerebellum_core::identity::RouteIdentity;

    let identity_a = BindIdentity {
        project_root: PathBuf::from("/tmp/project-a"),
        harness: "opencode".to_string(),
        session: "session-1".to_string(),
    };
    let identity_b = BindIdentity {
        project_root: PathBuf::from("/tmp/project-b"),
        harness: "opencode".to_string(),
        session: "session-1".to_string(),
    };
    let route_a = RouteIdentity::from_bind(&identity_a, &None);
    let route_b = RouteIdentity::from_bind(&identity_b, &None);
    assert_ne!(
        route_a.agent_project_id, route_b.agent_project_id,
        "distinct project roots resolve to distinct agent project ids"
    );
}

/// Every `mcp:*` discovery surface omits cerebellum capabilities under the
/// pinned gateway-policy fixture. This is enforced by the subc-mcp gateway
/// (primary exclusion); the in-module backstop is tested above. This test
/// asserts the module-side policy mapping: subc-mcp is untrusted.
#[tokio::test]
async fn mcp_facade_principal_is_untrusted() {
    let trust = principal::trust_for_principal(&Some(Principal::Reserved {
        module_id: "subc-mcp".to_string(),
    }));
    assert!(!trust.is_first_party());
}

/// Eligible first-party principals discover browser.status (the module accepts
/// their bind). The capability is dispatched only when present in their
/// effective capability scope — which for Spec A is "first-party bind accepted"
/// (the single capability is available to all first-party binds).
#[tokio::test]
async fn eligible_first_party_principal_discovers_browser_status() {
    let trust = principal::trust_for_principal(&Some(Principal::Reserved {
        module_id: "prefrontal".to_string(),
    }));
    assert!(trust.is_first_party());
}

/// The HELLO frame is built on channel 0 with epoch 0 and the correct frame type.
#[tokio::test]
async fn hello_frame_is_channel_zero_epoch_zero() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let config = cerebellum::ModuleConfigForTest {
        module_id: MODULE_ID.to_string(),
    };
    cerebellum::send_hello_for_test(&tx, &config).await.unwrap();

    let frame = rx.recv().await.expect("a HELLO frame");
    assert_eq!(frame.header.ty, FrameType::Hello);
    assert_eq!(frame.header.channel, 0);
    assert_eq!(frame.header.epoch, 0);
    assert_eq!(frame.header.ver, PROTOCOL_VERSION);

    let body: ModuleHelloBody = serde_json::from_slice(&frame.body).unwrap();
    assert_eq!(body.protocol_ver, PROTOCOL_VERSION);
    assert_eq!(body.manifest.module_id, MODULE_ID);
}

/// Data-plane identity comes from the accepted bind facts. Fields added to the
/// tool request cannot change the resolved session kind or profile boundary.
#[tokio::test]
async fn accepted_bind_facts_drive_profile_resolution() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
    let route_bindings = std::sync::Arc::new(cerebellum::RouteBindings::new());

    let bind = ModuleControlRequest::RouteBind {
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.to_string(),
        },
        identity: BindIdentity {
            project_root: PathBuf::from("/tmp/request-body-project"),
            harness: "opencode".to_string(),
            session: "conversation-subagent".to_string(),
        },
        principal: Some(Principal::Direct),
        consumer_capabilities: None,
        admission_facts: Some(json!({
            "agentProjectId": "pj-accepted",
            "sessionKind": "subagent",
            "effectiveCapabilityScope": ["browser.status"],
        })),
    };
    let bind_frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        301,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    cerebellum::handle_control_request_for_test_with_bindings(
        bind_frame,
        &tx,
        &health_state,
        &route_bindings,
    )
    .await
    .unwrap();
    let bind_response = rx.recv().await.expect("bind response");
    assert_eq!(bind_response.header.ty, FrameType::Response);

    let request = json!({
        "name": "browser.status",
        "arguments": {},
    });
    let tool_frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        9,
        3,
        302,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    cerebellum::handle_tool_request_for_test_with_bindings(
        tool_frame,
        &tx,
        &health_state,
        &route_bindings,
    )
    .await
    .unwrap();

    let response = rx.recv().await.expect("status response");
    assert_eq!(response.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "no_session");
    assert_eq!(body["context"]["session_kind_effective"], "subagent");
    assert_eq!(body["context"]["profile_disposition"], "disposable");
    assert_eq!(body["context"]["profile_name"], "default");
    assert!(!body.to_string().contains("pj-accepted"));
    assert!(!body.to_string().contains("conversation-subagent"));
}

/// A bind with an explicit empty effective scope denies browser.status even
/// for a valid canonical tool-route request.
#[tokio::test]
async fn accepted_effective_scope_is_not_widened_by_request_body() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
    let route_bindings = std::sync::Arc::new(cerebellum::RouteBindings::new());
    let bind = ModuleControlRequest::RouteBind {
        route_channel: 10,
        epoch: 4,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.to_string(),
        },
        identity: BindIdentity {
            project_root: PathBuf::from("/tmp/project"),
            harness: "opencode".to_string(),
            session: "conversation-scoped".to_string(),
        },
        principal: Some(Principal::Direct),
        consumer_capabilities: None,
        admission_facts: Some(json!({
            "agentProjectId": "pj-scoped",
            "sessionKind": "primary",
            "effectiveCapabilityScope": [],
        })),
    };
    let bind_frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        401,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    cerebellum::handle_control_request_for_test_with_bindings(
        bind_frame,
        &tx,
        &health_state,
        &route_bindings,
    )
    .await
    .unwrap();
    let _ = rx.recv().await;

    let request = json!({
        "name": "browser.status",
        "arguments": {},
    });
    let tool_frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        10,
        4,
        402,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    cerebellum::handle_tool_request_for_test_with_bindings(
        tool_frame,
        &tx,
        &health_state,
        &route_bindings,
    )
    .await
    .unwrap();
    let response = rx.recv().await.expect("scope rejection");
    assert_eq!(response.header.ty, FrameType::Error);
    let error: subc_protocol::ErrorBody = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(error.code, "capability_denied");
}

/// Run the module through the real authenticated subc TCP daemon. The in-memory
/// handler tests above prove individual frame decisions; this test proves that
/// registration, route binding, and the flat capability response survive the
/// actual daemon splice without opening a browser.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_daemon_registers_and_serves_browser_status() {
    let (mut daemon, connection) = start_live_daemon().await;
    let mut client = connect_client(&connection).await;

    let catalog = wait_for_cerebellum_catalog(&mut client).await;
    let ClientControlResponse::CatalogList { modules, .. } = catalog else {
        panic!("expected catalog.list response");
    };
    let entry = modules
        .iter()
        .find(|module| module.module_id == MODULE_ID)
        .expect("real subc catalog must contain cerebellum");
    assert_eq!(entry.roles.len(), 1);
    let role = entry
        .roles
        .first()
        .expect("cerebellum must advertise a provider role");
    let ProviderRole::ToolProvider { tools, .. } = role else {
        panic!("cerebellum must register as a tool provider");
    };
    assert_eq!(tools.len(), 1);
    assert_eq!(tools[0].name, "browser.status");
    assert_eq!(tools[0].execution_mode, ExecutionMode::Pure);

    let route = open_live_route(&mut client, 2).await;
    let invalid_response =
        send_live_tool_request(&mut client, route, 3, json!({"unexpected": true})).await;
    assert_eq!(invalid_response.header.ty, FrameType::Response);
    let invalid_body: Value = serde_json::from_slice(&invalid_response.body).unwrap();
    assert_eq!(invalid_body["outcome"], "invalid_request");
    assert_eq!(invalid_body["detail"]["field"], "unexpected");
    assert_eq!(invalid_body["detail"]["reason_code"], "unknown_field");

    let response = send_live_tool_request(&mut client, route, 4, json!({})).await;
    assert_eq!(response.header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(body["outcome"], "no_session");
    assert!(body["context"].is_object());
    assert_eq!(body["context"]["session_kind_effective"], "primary");
    assert_eq!(body["context"]["profile_disposition"], "durable");
    assert_eq!(body["session"], Value::Null);
    assert!(body.get("result").is_none(), "response body is flat");

    // Close the client before the daemon and module guards are dropped so the
    // daemon can release the route deterministically.
    drop(client);
    daemon.stop();
}

struct LiveDaemonGuard {
    task: Option<JoinHandle<Result<(), subc_core::bootstrap::BootstrapError>>>,
    directory: PathBuf,
}

impl LiveDaemonGuard {
    fn stop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        let _ = fs::remove_dir_all(&self.directory);
    }
}

impl Drop for LiveDaemonGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

async fn start_live_daemon() -> (LiveDaemonGuard, subc_transport::ConnectionInfo) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_nanos();
    let directory = std::env::temp_dir().join(format!("cerebellum-conformance-{nonce}"));
    let home = directory.join("home");
    fs::create_dir_all(&home).expect("create isolated module home");
    let connection_file_path = directory.join("subc-connection.json");
    let binary = std::env::var_os("CARGO_BIN_EXE_ck-cerebellum")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/debug/ck-cerebellum")
        });
    // Pay the first-exec cost of a freshly built binary before the registration
    // deadline starts.  macOS validates a newly written executable's signature on
    // its first exec and caches the result: measured 5-22s for the first run of a
    // fresh copy of this binary, and 0.00s for every run afterwards.  cargo
    // rebuilds ck-cerebellum, the daemon spawns it, and that validation lands
    // inside the window this test measures -- so a rebuild made the test time the
    // kernel rather than registration, which is why it failed only on the first
    // run after a build.  The module exits immediately without --subc, so this
    // costs nothing once the binary is already validated.
    let _ = tokio::process::Command::new(&binary)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;

    let daemon_config_path = directory.join("subc.jsonc");
    fs::write(
        &daemon_config_path,
        serde_json::to_vec(&json!({
            "version": 1,
            "modules": {
                MODULE_ID: {
                    "program": binary,
                    "env": { "HOME": home },
                    "reserved": true,
                }
            }
        }))
        .unwrap(),
    )
    .expect("write isolated subc daemon configuration");
    let daemon_config = subc_core::bootstrap::BootstrapConfig::new(&connection_file_path, 0)
        .with_daemon_config_path(&daemon_config_path)
        .expect("load isolated subc daemon configuration");
    let task = tokio::spawn(subc_core::bootstrap::run_with_config(daemon_config));

    // Same reasoning as `wait_for_cerebellum_catalog`: this is a startup race
    // against a real daemon process, not a network operation, so the bound is
    // generous and only decides how long a genuinely broken boot takes to fail.
    let connection = timeout(Duration::from_secs(60), async {
        loop {
            if let Ok(connection) = connection_file::read(&connection_file_path) {
                break connection;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("real subc daemon must publish a connection file");

    (
        LiveDaemonGuard {
            task: Some(task),
            directory,
        },
        connection,
    )
}

async fn connect_client(connection: &subc_transport::ConnectionInfo) -> TcpStream {
    let endpoint = connection
        .endpoints
        .first()
        .expect("real daemon must publish an endpoint");
    let mut stream = TcpStream::connect(format!("{}:{}", endpoint.host, endpoint.port))
        .await
        .expect("connect to real subc daemon");
    authenticate_client(&mut stream, connection, Duration::from_secs(5))
        .await
        .expect("authenticate client against real subc daemon");
    stream
}

async fn send_control_request(
    stream: &mut TcpStream,
    corr: u64,
    request: ClientControlRequest,
) -> Frame {
    let frame = Frame::build(
        FrameType::Request,
        cerebellum::control_flags(),
        0,
        0,
        corr,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame)
        .await
        .expect("write control request to real subc");
    timeout(Duration::from_secs(5), read_frame(stream))
        .await
        .expect("real subc response deadline")
        .expect("read real subc response")
        .expect("real subc connection remains open")
}

/// Poll the daemon catalog until cerebellum registers.
///
/// The bound is wall-clock rather than an iteration count.  An iteration count
/// silently encodes an assumption about how long one poll takes, and this test
/// spawns a real daemon and a real module process while the rest of the
/// workspace suite competes for the same cores -- exactly when a poll is
/// slowest.  A generous wall-clock deadline costs nothing on an idle machine
/// (the loop returns as soon as the module appears) and still fails a genuinely
/// unregistrable module, just later.
async fn wait_for_cerebellum_catalog(stream: &mut TcpStream) -> ClientControlResponse {
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    for corr in 10.. {
        if std::time::Instant::now() >= deadline {
            break;
        }
        let frame = send_control_request(
            stream,
            corr,
            ClientControlRequest::CatalogList {
                module_id: Some(MODULE_ID.to_string()),
            },
        )
        .await;
        assert_eq!(frame.header.ty, FrameType::Response);
        let response: ClientControlResponse = serde_json::from_slice(&frame.body).unwrap();
        if let ClientControlResponse::CatalogList { modules, .. } = &response {
            if modules.iter().any(|module| module.module_id == MODULE_ID) {
                return response;
            }
        }
        sleep(Duration::from_millis(10)).await;
    }
    panic!("real subc did not register cerebellum before the deadline");
}

async fn open_live_route(stream: &mut TcpStream, corr: u64) -> (u16, u32) {
    let response = send_control_request(
        stream,
        corr,
        ClientControlRequest::RouteOpen {
            target: RouteTarget::ToolProvider {
                module_id: MODULE_ID.to_string(),
            },
            identity: BindIdentity {
                project_root: PathBuf::from("/tmp"),
                harness: "conformance".to_string(),
                session: "conversation-live".to_string(),
            },
            consumer_identity: None,
            consumer_capabilities: None,
            admission_facts: None,
        },
    )
    .await;
    assert_eq!(
        response.header.ty,
        FrameType::Response,
        "route.open failed: {}",
        String::from_utf8_lossy(&response.body)
    );
    match serde_json::from_slice::<ClientControlResponse>(&response.body).unwrap() {
        ClientControlResponse::RouteOpen {
            route_channel,
            route_epoch,
        } => (route_channel, route_epoch),
        other => panic!("expected route.open response, got {other:?}"),
    }
}

async fn send_live_tool_request(
    stream: &mut TcpStream,
    (channel, epoch): (u16, u32),
    corr: u64,
    arguments: Value,
) -> Frame {
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&json!({
            "name": "browser.status",
            "arguments": arguments,
        }))
        .unwrap(),
    )
    .unwrap();
    write_frame(stream, &frame)
        .await
        .expect("write live capability request");
    timeout(Duration::from_secs(5), read_frame(stream))
        .await
        .expect("live capability response deadline")
        .expect("read live capability response")
        .expect("real subc connection remains open")
}

#[cfg(feature = "test-observer")]
#[tokio::test]
async fn feature_gated_identity_observer_records_resolved_facts() {
    use cerebellum::take_test_observations;
    use cerebellum_core::identity::{RouteIdentity, SessionKind};

    let _ = take_test_observations();
    let identity = RouteIdentity::from_accepted_bind(
        &BindIdentity {
            project_root: PathBuf::from("/tmp/observer-project"),
            harness: "conformance".to_string(),
            session: "observer-conversation".to_string(),
        },
        &Some(Principal::Direct),
        Some(&json!({
            "agentProjectId": "pj-observer",
            "sessionKind": "subagent",
        })),
    );
    let resolution = identity.resolve_profile();
    assert_eq!(resolution.profile_disposition.as_str(), "disposable");
    let observations = take_test_observations();
    assert!(observations.iter().any(|observation| {
        observation.conversation_key == "observer-conversation"
            && observation.agent_project_id == "pj-observer"
            && observation.session_kind == SessionKind::Subagent
            && observation.logical_profile_key
                == Some((
                    "pj-observer".to_string(),
                    "observer-conversation".to_string(),
                ))
    }));
}
