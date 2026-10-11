//! Catalog and schema-pin checks enter the production frame dispatcher after
//! route.bind installs a verified caller identity on the tool-provider route.

use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use cortexkit_role_tool_provider::call::SchemaPin;
use cortexkit_role_tool_provider::catalog::{schema_digest, CatalogAnswer};
use serde_json::{json, Value};
use std::sync::Arc;
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

fn planes(configured: bool) -> Planes {
    Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        configured.then_some(BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }),
        JournalPersistence::Isolated,
    )
}
async fn exchange(planes: &Planes, channel: u16, body: Value) -> Frame {
    let (tx, mut rx) = mpsc::channel(16);
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        if channel == 0 { 0 } else { 3 },
        1,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .unwrap();
    drop(tx);
    let reply = rx.recv().await.unwrap();
    assert!(
        rx.recv().await.is_none(),
        "request produced more than one frame"
    );
    reply
}
fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}
async fn bind(planes: &Planes, channel: u16, module: &str) {
    bind_with_scope(planes, channel, module, None).await;
}
async fn bind_with_scope(
    planes: &Planes,
    channel: u16,
    module: &str,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) {
    let request = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("/test/project", "test", "test-session"),
        principal: Some(Principal::Reserved {
            module_id: module.into(),
        }),
        consumer_capabilities: None,
        scope,
        admission_facts: Some(
            json!({"agentProjectId":"catalog-test","sessionKind":"primary","effectiveCapabilityScope":["*"],"browserControlOperations":["browser.status"]}),
        ),
    };
    let reply = exchange(planes, 0, serde_json::to_value(request).unwrap()).await;
    assert_eq!(reply.header.ty, FrameType::Response, "{}", body(&reply));
}
async fn catalog(planes: &Planes, arguments: Value) -> Frame {
    exchange(
        planes,
        9,
        json!({"name":"tool.catalog","arguments":arguments}),
    )
    .await
}

#[tokio::test]
async fn catalog_matches_hello_and_digest_is_stable() {
    let planes = planes(true);
    bind(&planes, 9, "prefrontal-core").await;
    let first = catalog(&planes, json!({"params":{}})).await;
    let repeated = catalog(&planes, json!({"params":{}})).await;
    assert_eq!(first.body, repeated.body);
    let full: CatalogAnswer = serde_json::from_slice(&first.body).unwrap();
    let digest = catalog(&planes, json!({"params":{},"digest_only":true})).await;
    assert_eq!(
        body(&digest),
        json!({"generation":full.generation,"catalog_digest":full.catalog_digest})
    );
    let hello = cerebellum::serialize_manifest_with_browser_configuration(
        "cerebellum",
        &cerebellum::BrowserSurface::Available(planes.browser_config.clone().unwrap()),
    );
    let tools = hello["provides"][0]["tools"].as_array().unwrap();
    let flat: Vec<_> = tools
        .iter()
        .filter(|tool| matches!(tool["name"].as_str(), Some("browser_use" | "computer_use")))
        .collect();
    assert_eq!(flat.len(), full.tools.len());
    for tool in &full.tools {
        let old = flat.iter().find(|old| old["name"] == tool.name).unwrap();
        assert_eq!(
            serde_json::to_vec(&old["schema"]).unwrap(),
            serde_json::to_vec(&tool.input_schema).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&old["description"]).unwrap(),
            serde_json::to_vec(&tool.description).unwrap()
        );
        assert_eq!(
            tool.schema_digest,
            schema_digest(&tool.input_schema).unwrap()
        );
        assert_eq!(tool.semantics, 1);
        let max_ms = match tool.name.as_str() {
            "computer_use" => cerebellum::budgets::COMPUTER_REPLY_MAX_MS,
            "browser_use" => cerebellum::budgets::BROWSER_REPLY_MAX_MS,
            _ => panic!("unexpected catalog tool: {}", tool.name),
        };
        assert_eq!(tool.reply.as_ref().unwrap().max_ms, max_ms);
    }
    let composition = json!({"params":{},"composition":{"opaque":{"v":3}}});
    let composed = catalog(&planes, composition.clone()).await;
    assert_eq!(composed.body, catalog(&planes, composition).await.body);
    assert_eq!(
        body(&composed)["composition_digest"],
        cortexkit_role_tool_provider::catalog::composition_digest(&json!({"opaque":{"v":3}}))
            .unwrap()
    );
    assert_ne!(body(&composed)["catalog_digest"], full.catalog_digest);
}

#[tokio::test]
async fn catalog_carries_exact_browser_capability_tags() {
    let planes = planes(true);
    bind(&planes, 9, "prefrontal-core").await;
    let full: CatalogAnswer =
        serde_json::from_slice(&catalog(&planes, json!({})).await.body).unwrap();
    let browser = full
        .tools
        .iter()
        .find(|tool| tool.name == "browser_use")
        .unwrap();
    assert_eq!(
        browser.capabilities,
        ["browser.use/v1", "cerebellum:browser.use/v1"]
    );
    for tag in &browser.capabilities {
        cortexkit_role_tool_provider::check_capability_tag(tag).unwrap();
    }
}

#[tokio::test]
async fn catalog_refuses_unknown_inputs_and_omits_disabled_browser() {
    let configured = planes(true);
    bind(&configured, 9, "prefrontal-core").await;
    for (arguments, field) in [
        (json!({"preset":"unknown"}), "preset"),
        (json!({"preset":null}), "preset"),
        (json!({"params":{"unknown":true}}), "params"),
        (json!({"params":null}), "params"),
        (json!({"digest_only":"yes"}), "digest_only"),
        (json!({"composition":null}), "composition"),
        (json!({"system_text":{"preset":"unknown"}}), "system_text"),
        (json!({"unknown":3}), "unknown"),
    ] {
        let reply = catalog(&configured, arguments).await;
        assert_eq!(reply.header.ty, FrameType::Error);
        assert_eq!(body(&reply)["code"], "invalid_request");
        assert_eq!(body(&reply)["detail"]["field"], field);
    }
    let disabled = planes(false);
    bind(&disabled, 9, "prefrontal-core").await;
    let answer = catalog(&disabled, json!({})).await;
    assert!(!body(&answer)["tools"]
        .as_array()
        .unwrap()
        .iter()
        .any(|tool| tool["name"] == "browser_use"));
    let refused = exchange(
        &disabled,
        9,
        json!({"name":"browser_use","arguments":{"action":"status"}}),
    )
    .await;
    assert_eq!(refused.header.ty, FrameType::Error);
    assert_eq!(body(&refused)["code"], "tool_disabled");
    assert_eq!(body(&refused)["detail"]["tool"], "browser_use");
}

#[tokio::test]
async fn mismatched_schema_pins_are_refused_before_dispatch() {
    let planes = planes(true);
    bind(&planes, 9, "prefrontal-core").await;
    let full: CatalogAnswer =
        serde_json::from_slice(&catalog(&planes, json!({})).await.body).unwrap();
    let tool = full
        .tools
        .iter()
        .find(|tool| tool.name == "browser_use")
        .unwrap();
    let call =
        json!({"name":"browser_use","arguments":{"action":"status"},"tool_call_id":"display-only"});
    let unpinned = exchange(&planes, 9, call.clone()).await;
    assert_eq!(unpinned.header.ty, FrameType::Response);
    assert_eq!(body(&unpinned)["outcome"], "no_session");
    let mut pinned = call.clone();
    pinned["schema_pin"] = json!(
        SchemaPin::new(&tool.name, &tool.schema_digest, tool.semantics)
            .encode()
            .unwrap()
    );
    assert_eq!(unpinned.body, exchange(&planes, 9, pinned).await.body);
    for (schema, semantics, code) in [
        ("0".repeat(64), tool.semantics, "tool_schema_changed"),
        (
            tool.schema_digest.clone(),
            tool.semantics + 1,
            "tool_semantics_changed",
        ),
    ] {
        let mut request = call.clone();
        request["schema_pin"] = json!(SchemaPin::new(&tool.name, &schema, semantics)
            .encode()
            .unwrap());
        request["call_key"] = json!(format!("pin:{code}"));
        let reply = exchange(&planes, 9, request).await;
        assert_eq!(reply.header.ty, FrameType::Error, "{}", body(&reply));
        assert_eq!(body(&reply)["code"], code);
        assert_eq!(body(&reply)["detail"]["tool"], tool.name);
        if code == "tool_schema_changed" {
            assert_eq!(body(&reply)["detail"]["expected"], schema);
            assert_eq!(body(&reply)["detail"]["current"], tool.schema_digest);
        } else {
            assert_eq!(body(&reply)["detail"]["expected"], semantics);
            assert_eq!(body(&reply)["detail"]["current"], tool.semantics);
        }
    }
    for pin in [
        json!(null),
        json!(3),
        json!("broken"),
        json!(SchemaPin::new("other", &tool.schema_digest, 1)
            .encode()
            .unwrap()),
    ] {
        let mut request = call.clone();
        request["schema_pin"] = pin;
        let reply = exchange(&planes, 9, request).await;
        assert_eq!(body(&reply)["code"], "invalid_request");
        assert_eq!(body(&reply)["detail"]["field"], "schema_pin");
    }
    let unknown = exchange(&planes, 9, json!({"name":"missing","arguments":{},"schema_pin":SchemaPin::new("missing", &tool.schema_digest, 1).encode().unwrap()})).await;
    assert_eq!(body(&unknown)["code"], "unknown_tool");
}

#[tokio::test]
async fn another_principals_key_is_an_unknown_call() {
    let planes = planes(true);
    bind(&planes, 9, "broca").await;
    bind(&planes, 10, "aft").await;
    exchange(
        &planes,
        9,
        json!({"name":"browser_use","arguments":{"action":"status"},"call_key":"private:key"}),
    )
    .await;
    let own = exchange(
        &planes,
        9,
        json!({"name":"tool.withdraw","arguments":{"call_key":"private:key"}}),
    )
    .await;
    assert_ne!(
        body(&own)["answer"],
        "unknown_call",
        "control: principal A must have a recorded key"
    );
    let other = exchange(
        &planes,
        10,
        json!({"name":"tool.withdraw","arguments":{"call_key":"private:key"}}),
    )
    .await;
    assert_eq!(other.header.ty, FrameType::Response);
    assert_eq!(body(&other), json!({"answer":"unknown_call"}));
}

#[tokio::test]
async fn withdrawal_checks_the_carriers_own_record_scope() {
    let planes = planes(true);
    let scope = subc_protocol::scope::ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "scope-one",
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_attributes(subc_protocol::scope::ScopeAttributes::default())
    .with_owner_authorized(true);
    bind_with_scope(&planes, 9, "broca", Some(scope.clone())).await;
    let result = exchange(
        &planes,
        9,
        json!({"name":"browser_use","arguments":{"action":"status"},"call_key":"scoped:key"}),
    )
    .await;
    let own = exchange(
        &planes,
        9,
        json!({"name":"tool.withdraw","arguments":{"call_key":"scoped:key"}}),
    )
    .await;
    assert_eq!(body(&result)["code"], "session_caller_not_admitted");
    assert_eq!(
        body(&own),
        json!({"answer":"refused","reason":"session_caller_not_admitted"})
    );
    let mut other_scope = scope;
    other_scope.scope_ref = "scope-two".into();
    bind_with_scope(&planes, 10, "broca", Some(other_scope)).await;
    let other = exchange(&planes, 10, json!({"name":"tool.withdraw","arguments":{"call_key":"scoped:key","carrier":"reserved:broca"}})).await;
    assert_eq!(other.header.ty, FrameType::Error);
    assert_eq!(body(&other)["code"], "withdraw_not_permitted");
}

#[tokio::test]
async fn withdrawal_validation_is_a_contract_route_error() {
    let planes = planes(true);
    bind(&planes, 9, "prefrontal-core").await;
    for (request, field) in [
        (
            json!({"name":"tool.withdraw","arguments":{"call_key":""}}),
            "arguments.call_key",
        ),
        (
            json!({"name":"tool.withdraw","arguments":{"call_key":3}}),
            "arguments.call_key",
        ),
        (
            json!({"name":"tool.withdraw","arguments":{"call_key":"key"},"call_key":"other"}),
            "call_key",
        ),
    ] {
        let reply = exchange(&planes, 9, request).await;
        assert_eq!(reply.header.ty, FrameType::Error);
        assert_eq!(body(&reply)["code"], "invalid_request");
        assert_eq!(body(&reply)["detail"]["field"], field);
    }
    let named_scope = exchange(&planes, 9, json!({"name":"tool.withdraw","arguments":{"call_key":"key","scope":{"owner":"reserved:prefrontal-core","ref":"claim","scope_epoch":1}}})).await;
    assert_eq!(named_scope.header.ty, FrameType::Error);
    assert_eq!(body(&named_scope)["code"], "withdraw_scope_mismatch");
}
