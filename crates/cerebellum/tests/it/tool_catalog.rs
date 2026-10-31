//! Catalog and schema-pin checks enter the production frame dispatcher after
//! route.bind installs a verified caller identity on the tool-provider route.

use crate::support::HANG_GUARD;
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
    let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(
        tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("no background elicitation may hold the writer")
            .is_none(),
        "request produced more than one frame (including an elicitation frame)"
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
    bind_with_scope_mode(planes, channel, module, scope, None).await;
}
async fn bind_with_scope_mode(
    planes: &Planes,
    channel: u16,
    module: &str,
    scope: Option<subc_protocol::scope::ScopeStamp>,
    call_mode: Option<subc_protocol::call_mode::CallMode>,
) {
    bind_with_readers(
        planes,
        channel,
        module,
        scope,
        call_mode,
        Some(vec![
            cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
        ]),
    )
    .await;
}
async fn bind_with_readers(
    planes: &Planes,
    channel: u16,
    module: &str,
    scope: Option<subc_protocol::scope::ScopeStamp>,
    call_mode: Option<subc_protocol::call_mode::CallMode>,
    consumer_capabilities: Option<Vec<String>>,
) {
    let request = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode,
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("test", "test-session"),
        principal: Some(Principal::Reserved {
            module_id: module.into(),
        }),
        consumer_capabilities,
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
        assert_eq!(
            serde_json::to_value(&tool.modes).unwrap(),
            json!(["classic", "codemode", "flow"])
        );
        // The wire name is pinned literally: a tool-result/v1 reader renders
        // content parts only for a tool whose catalog entry carries exactly
        // this string.
        assert_eq!(
            tool.result_format.as_ref().unwrap().as_str(),
            "tool-result/v1"
        );
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

#[test]
fn user_browser_budgets_are_target_specific_and_exhaustive() {
    use cerebellum::budgets;
    let expected = [
        ("open_tab", 82_000, 1, 0),
        ("claim_tab", 82_000, 1, 0),
        ("status", 76_000, 1, 0),
        ("close", 76_000, 1, 0),
        ("snapshot", 128_000, 5, 1),
        ("screenshot", 112_000, 4, 1),
        ("navigate", 158_000, 5, 1),
        ("scroll", 108_000, 3, 1),
        ("click", 192_000, 9, 3),
        ("click_point", 208_000, 10, 3),
        ("type", 270_000, 15, 1),
        ("open_grant", 12_000, 0, 1),
        ("revoke_access", 12_000, 0, 0),
    ];
    assert_eq!(expected.len(), budgets::USER_BROWSER_ACTIONS.len());
    for (action, work_ms, plans, consent_cards) in expected {
        let budget = budgets::user_browser(action).unwrap();
        assert_eq!(budget.action, action);
        assert_eq!(budget.work_ms, work_ms, "{action}");
        assert_eq!(
            budget
                .phases
                .iter()
                .find(|phase| phase.name == "plan_acknowledgements")
                .map_or(0, |phase| phase.count),
            plans,
            "{action}"
        );
        assert_eq!(
            budgets::user_consent_count(action),
            consent_cards,
            "{action}"
        );
    }
    for action in [
        "launch",
        "present",
        "resume",
        "import_login",
        "capture_login",
    ] {
        assert_eq!(
            budgets::user_browser(action),
            Some(&budgets::USER_UNSUPPORTED)
        );
    }
    assert!(budgets::user_browser("not_an_action").is_none());
    let own = budgets::BROWSER_ACTIONS
        .iter()
        .map(|action| action.work_ms + budgets::CONSENT_PARK_LIMIT_MS);
    let user = budgets::USER_BROWSER_ACTIONS.iter().map(|action| {
        action.work_ms + budgets::user_consent_count(action.action) * budgets::USER_CONSENT_MS
    });
    let max_action = own.chain(user).max().unwrap();
    assert_eq!(
        budgets::BROWSER_REPLY_MAX_MS,
        budgets::CALL_RECORD_BEGIN_MS
            + budgets::BROWSER_QUEUE_WAIT_LIMIT_MS
            + max_action
            + budgets::TERMINAL_SUFFIX_MS
    );
    const { assert!(budgets::BROWSER_REPLY_MAX_MS < 31 * 60 * 1000) };
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
    assert_eq!(
        body(&unpinned)["structuredContent"]["outcome"],
        "no_session"
    );
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
    bind(&planes, 9, "prefrontal-routing").await;
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
    use cerebellum::journal::call_records::{CallState, Lookup};

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
    bind_with_scope(&planes, 9, "prefrontal-routing", Some(scope.clone())).await;
    let result = exchange(
        &planes,
        9,
        json!({"name":"browser_use","arguments":{"action":"status"},"call_key":"scoped:key"}),
    )
    .await;
    // A reply can outrun its record worker; scope assertions need the settled refusal.
    tokio::time::timeout(HANG_GUARD, async {
        loop {
            let Lookup::Own(snapshot) = planes
                .calls
                .lookup("reserved:prefrontal-routing", "scoped:key")
            else {
                panic!("the keyed call must already have its begin record");
            };
            if snapshot.state != CallState::Started {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the keyed call's record settles");
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
    bind_with_scope(&planes, 10, "prefrontal-routing", Some(other_scope)).await;
    let other = exchange(&planes, 10, json!({"name":"tool.withdraw","arguments":{"call_key":"scoped:key","carrier":"reserved:prefrontal-routing"}})).await;
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

fn mode_scope(
    mode: &subc_protocol::call_mode::CallMode,
) -> Option<subc_protocol::scope::ScopeStamp> {
    use subc_protocol::call_mode::CallMode;
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    let attributes = ScopeAttributes::new()
        .with_agent_id(Some("catalog-test".into()))
        .with_delegates(true);
    let attributes = match mode {
        CallMode::Codemode => attributes.with_run_id(Some("run-test".into())),
        CallMode::Flow => attributes.with_flow_id(Some("flow-test".into())),
        _ => return None,
    };
    Some(
        ScopeStamp::new(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            "head",
            1,
            ScopeKind::Head,
        )
        .with_attributes(attributes)
        .with_owner_authorized(true),
    )
}

#[tokio::test]
async fn served_modes_reach_status_on_the_production_handler() {
    use subc_protocol::call_mode::CallMode;
    for mode in [CallMode::Classic, CallMode::Codemode, CallMode::Flow] {
        let planes = planes(true);
        let module = if mode == CallMode::Flow {
            "basal"
        } else {
            "prefrontal-core"
        };
        bind_with_scope_mode(&planes, 9, module, mode_scope(&mode), Some(mode.clone())).await;
        let response = exchange(
            &planes,
            9,
            json!({"name":"browser_use", "arguments":{"action":"status"}}),
        )
        .await;
        assert_eq!(
            response.header.ty,
            FrameType::Response,
            "{mode:?}: {}",
            body(&response)
        );
        assert_eq!(
            body(&response)["structuredContent"]["outcome"],
            "no_session",
            "{mode:?}"
        );
        let result: cortexkit_role_tool_provider::result::ToolResult =
            serde_json::from_slice(&response.body).unwrap();
        cortexkit_role_tool_provider::result::validate(&result).unwrap();
    }
}

#[tokio::test]
async fn unknown_mode_refused_before_grants_and_argument_dispatch() {
    use subc_protocol::call_mode::CallMode;
    let planes = planes(true);
    bind_with_scope_mode(
        &planes,
        9,
        "prefrontal-core",
        None,
        Some(CallMode::Unknown("future-mode".into())),
    )
    .await;
    let response = exchange(&planes, 9, json!({"name":"browser_use", "arguments":{"action":"open_grant", "origins":["https://example.com"], "hazards":[]}, "call_key":"unknown-mode-key"})).await;
    assert_eq!(response.header.ty, FrameType::Error);
    assert_eq!(body(&response)["code"], "call_mode_unsupported");
    assert_eq!(
        body(&response)["detail"],
        json!({"tool":"browser_use", "mode":"future-mode"})
    );
}

#[tokio::test]
async fn codemode_never_elicits_a_consent_card() {
    use subc_protocol::call_mode::CallMode;
    let service = super::support::computer::cingulate::ScriptedCarrier::default();
    let planes = service.install(planes(true));
    let typed = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: Some(CallMode::Codemode),
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("test", "test-session"),
        principal: Some(Principal::Reserved {
            module_id: "prefrontal-core".into(),
        }),
        consumer_capabilities: Some(vec![
            "elicitation".into(),
            cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
        ]),
        scope: mode_scope(&CallMode::Codemode),
        admission_facts: Some(
            json!({"agentProjectId":"catalog-test", "sessionKind":"primary", "effectiveCapabilityScope":["*"]}),
        ),
    };
    let ack = exchange(&planes, 0, serde_json::to_value(typed).unwrap()).await;
    assert_eq!(ack.header.ty, FrameType::Response);
    let reply = exchange(&planes, 9, json!({"name":"browser_use", "arguments":{"action":"open_grant", "origins":["https://example.com"], "hazards":[]}})).await;
    assert_eq!(reply.header.ty, FrameType::Response);
    let reply = body(&reply);
    assert_eq!(reply["structuredContent"]["outcome"], "consent_unavailable");
    assert_eq!(reply["structuredContent"]["detail"]["reason"], "agent_run");
    assert_eq!(reply["isError"], true);
    assert_eq!(reply["errorCode"], "consent_unavailable");
    assert!(
        service.questions().is_empty(),
        "codemode raises no permission card"
    );
    assert!(
        service.calls().is_empty(),
        "codemode opens no consent request"
    );
}

#[tokio::test]
async fn flow_still_refuses_consent_on_the_production_handler() {
    use subc_protocol::call_mode::CallMode;
    let planes = planes(true);
    bind_with_scope_mode(
        &planes,
        9,
        "basal",
        mode_scope(&CallMode::Flow),
        Some(CallMode::Flow),
    )
    .await;
    let response = exchange(&planes, 9, json!({"name":"browser_use", "arguments":{"action":"open_grant", "origins":["https://example.com"], "hazards":[]}})).await;
    assert_eq!(response.header.ty, FrameType::Response);
    assert_eq!(
        body(&response)["structuredContent"]["outcome"],
        "consent_unavailable"
    );
    assert_eq!(
        body(&response)["structuredContent"]["detail"]["reason"],
        "unattended_flow"
    );
}

#[tokio::test]
async fn classic_still_elicits_a_consent_card() {
    let service = super::support::computer::cingulate::ScriptedCarrier::default();
    let mut planes = service.install(planes(true));
    planes.management = std::sync::Arc::new(
        cerebellum::management::ManagementPlane::new(std::sync::Arc::new(
            cerebellum::management::PlatformResolver::new(),
        ))
        .with_agent_grants(std::sync::Arc::new(
            cerebellum::agent_grants::AgentGrants::in_memory(Some("catalog-test-machine".into())),
        )),
    );
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: Some(subc_protocol::call_mode::CallMode::Classic),
        route_channel: 9,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        identity: BindIdentity::new("test", "test-session"),
        principal: Some(Principal::Reserved {
            module_id: "prefrontal-core".into(),
        }),
        consumer_capabilities: Some(vec![
            "elicitation".into(),
            cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
        ]),
        scope: Some(super::support::computer::cingulate::stamp("catalog-test")),
        admission_facts: Some(
            json!({"agentProjectId":"catalog-test", "sessionKind":"primary", "effectiveCapabilityScope":["*"]}),
        ),
    };
    assert_eq!(
        exchange(&planes, 0, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
    let (tx, mut rx) = mpsc::channel(8);
    let request = Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request,
        Flags::new(false, Priority::Interactive, false), 9, 3, 2,
        serde_json::to_vec(&json!({"name":"browser_use", "arguments":{"action":"open_grant", "origins":["https://example.com"], "hazards":[]}})).unwrap()).unwrap();
    cerebellum::handle_frame_for_test(request, &tx, &planes)
        .await
        .unwrap();
    let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "the agent receives no permission Request frame"
    );
    let reply = body(&frame);
    assert_eq!(reply["structuredContent"]["outcome"], "consent_pending");
    let card = service.card(9, 3).await;
    assert_eq!(reply["structuredContent"]["ask_id"], body(&card)["id"]);
    assert_eq!(
        service
            .calls()
            .iter()
            .map(|(method, _)| method.as_str())
            .collect::<Vec<_>>(),
        ["consent.request", "consent.detach"]
    );
    assert!(
        rx.try_recv().is_err(),
        "no reverse request or duplicate reply"
    );
}

#[tokio::test]
async fn call_members_cannot_enable_a_result_reader() {
    let planes = planes(true);
    bind_with_readers(&planes, 9, "prefrontal-core", None, None, None).await;
    let response = exchange(
        &planes,
        9,
        json!({"name":"browser_use",
        "arguments":{"action":"status"}, "consumer_capabilities":[cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY]}),
    )
    .await;
    assert_eq!(response.header.ty, FrameType::Response);
    let reply = body(&response);
    assert_eq!(reply["outcome"], "invalid_request");
    assert_eq!(reply["detail"]["field"], "consumer_capabilities");
    assert!(reply.get("content").is_none());
    let status = exchange(
        &planes,
        9,
        json!({"name":"browser_use", "arguments":{"action":"status"}}),
    )
    .await;
    assert_eq!(status.body.as_slice(), br#"{"outcome":"no_session"}"#);
}

#[tokio::test]
async fn keyed_replays_use_the_current_routes_result_reader() {
    for first_reads in [false, true] {
        let planes = planes(true);
        let declaration = |reads| {
            if reads {
                Some(vec![
                    cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into(),
                ])
            } else {
                None
            }
        };
        bind_with_readers(
            &planes,
            9,
            "prefrontal-core",
            None,
            None,
            declaration(first_reads),
        )
        .await;
        bind_with_readers(
            &planes,
            10,
            "prefrontal-core",
            None,
            None,
            declaration(!first_reads),
        )
        .await;
        let call = json!({"name":"browser_use", "arguments":{"action":"status", "unexpected":true}, "call_key":"format-replay"});
        let first = exchange(&planes, 9, call.clone()).await;
        assert_eq!(first.header.ty, FrameType::Response);
        let first_body = body(&first);
        let legacy = first_body.get("structuredContent").unwrap_or(&first_body);
        assert_eq!(legacy["outcome"], "invalid_request");
        let second = exchange(&planes, 10, call.clone()).await;
        assert_eq!(second.header.ty, FrameType::Response, "{}", body(&second));
        let second_body = body(&second);
        if first_reads {
            assert_eq!(second.body, serde_json::to_vec(legacy).unwrap());
        } else {
            let result: cortexkit_role_tool_provider::result::ToolResult =
                serde_json::from_slice(&second.body).unwrap();
            cortexkit_role_tool_provider::result::validate(&result).unwrap();
            assert_eq!(second_body["structuredContent"], *legacy);
        }
        assert_eq!(second.body, exchange(&planes, 10, call).await.body);
    }
}
