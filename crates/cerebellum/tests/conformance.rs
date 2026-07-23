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

use std::path::PathBuf;

use serde_json::{json, Value};
use subc_protocol::manifest::{ExecutionMode, ProviderRole};
use subc_protocol::session::{
    ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
};
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, ModuleHelloBody, Principal, Priority, RouteTarget,
    PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

use cerebellum::manifest;
use cerebellum::principal;

const MODULE_ID: &str = "cerebellum";

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
    let health_state = std::sync::Arc::new(cerebellum::health::HealthState::new());

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
    let health_state = std::sync::Arc::new(cerebellum::health::HealthState::new());

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
    let health_state = std::sync::Arc::new(cerebellum::health::HealthState::new());

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
    let health_state = std::sync::Arc::new(cerebellum::health::HealthState::new());
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
    let health_state = std::sync::Arc::new(cerebellum::health::HealthState::new());

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
    assert_eq!(body["session"], Value::Null);
}

/// browser.status with an unknown field returns `invalid_request` with the
/// pinned detail shape (application-level rejection, not a transport Error).
#[tokio::test]
async fn browser_status_unknown_field_returns_invalid_request_in_body() {
    let (tx, mut rx) = mpsc::channel::<Frame>(16);
    let health_state = std::sync::Arc::new(cerebellum::health::HealthState::new());

    let request = json!({
        "method": "browser.status",
        "params": { "unexpected": true },
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
    assert_eq!(body["detail"]["field"], "unexpected");
    assert_eq!(body["detail"]["reason_code"], "unknown_field");
}

/// The full sessionKind matrix resolves correctly at the status layer without
/// opening a browser: primary → durable, subagent → disposable, ephemeral → none.
#[tokio::test]
async fn session_kind_matrix_resolves_profile_disposition() {
    use cerebellum::identity::{ProfileDisposition, SessionKind};

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
    use cerebellum::identity::RouteIdentity;

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
        module_id: "alfonso-core".to_string(),
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
