//! The published role suite enters the production frame dispatcher with real
//! route binds. A separate test checks catalog bytes through the real daemon.

use super::*;
use crate::hang_guard::HANG_GUARD;
use async_trait::async_trait;
use cerebellum::journal::call_records::{CallRecords, FilesystemCallRecordStorage};
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use cortexkit_role_tool_provider::scope::ScopeIdentity;
use cortexkit_role_tool_provider_conformance::{
    harness::{
        Harness, HarnessError, KillPoint, KillReport, PointDeclaration, RouteStamp, Trigger,
    },
    run_suite, CallSpec, Capability, Exchange, ObservedFrame, RouteFailure, ScopedPrincipals,
    SuiteVerdict, ToolProviderSubject, ToolRoute,
};
use std::collections::BTreeSet;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use subc_protocol::call_mode::CallMode;
use subc_protocol::scope::{ParentState, ScopeAttributes, ScopeKind, ScopeParent, ScopeStamp};

struct Subject;
struct Route {
    planes: Arc<Planes>,
    channel: u16,
}
static NEXT: AtomicU64 = AtomicU64::new(1);
const OWNER: &str = "reserved:prefrontal";
const HEAD_REF: &str = "conformance-head";

fn frame(channel: u16, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        if channel == 0 { 0 } else { 3 },
        NEXT.fetch_add(1, Ordering::Relaxed),
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}
fn principal(label: &str) -> Principal {
    Principal::Reserved {
        module_id: label.strip_prefix("reserved:").unwrap().into(),
    }
}
fn config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 60_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    }
}

async fn bind_reader_route(
    planes: &Arc<Planes>,
    stamp: &RouteStamp,
    consumer_capabilities: Option<Vec<String>>,
) -> Result<Route, HarnessError> {
    let scope = stamp.scope.as_ref().map(|scope| {
        ScopeStamp::new(
            principal(&scope.owner),
            scope.scope_ref.clone(),
            scope.scope_epoch,
            ScopeKind::Ephemeral,
        )
        .with_attributes(
            ScopeAttributes::new()
                .with_agent_id(Some("conformance".into()))
                .with_run_id(Some(scope.scope_ref.clone())),
        )
        .with_owner_authorized(true)
        .with_parent(Some(ScopeParent::new(principal(OWNER), HEAD_REF, 1)))
        .with_parent_state(Some(ParentState::Linked))
    });
    bind_route(
        planes,
        principal(&stamp.principal),
        scope,
        (stamp.principal == "reserved:basal").then_some(CallMode::Codemode),
        consumer_capabilities,
    )
    .await
}

async fn bind_route(
    planes: &Arc<Planes>,
    principal: Principal,
    scope: Option<ScopeStamp>,
    call_mode: Option<CallMode>,
    consumer_capabilities: Option<Vec<String>>,
) -> Result<Route, HarnessError> {
    let channel = u16::try_from(NEXT.fetch_add(1, Ordering::Relaxed)).unwrap();
    let browser_operations: Vec<_> = cerebellum::browser_wire_surface(true)
        .into_iter()
        .filter_map(|(name, reachable)| reachable.then_some(name))
        .collect();
    let bind = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode,
        route_channel: channel,
        epoch: 3,
        target: RouteTarget::ToolProvider {
            module_id: MODULE_ID.into(),
        },
        identity: BindIdentity::new("conformance", "test-session"),
        principal: Some(principal),
        consumer_capabilities,
        admission_facts: Some(
            json!({"agentProjectId":"conformance","sessionKind":"primary","effectiveCapabilityScope":["*"],"browserControlOperations":browser_operations}),
        ),
        scope,
    };
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(frame(0, serde_json::to_value(bind).unwrap()), &tx, planes)
        .await
        .map_err(|error| HarnessError::new(error.to_string()))?;
    let reply = rx.recv().await.unwrap();
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "bind refused: {}",
        String::from_utf8_lossy(&reply.body)
    );
    Ok(Route {
        planes: planes.clone(),
        channel,
    })
}

#[async_trait]
impl Harness for Subject {
    type Handle = Arc<Planes>;
    type Route = Route;

    fn declared_points(&self) -> Vec<PointDeclaration> {
        Vec::new()
    }
    async fn spawn(&self, root: &Path) -> Result<Arc<Planes>, HarnessError> {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config()),
            JournalPersistence::Isolated,
        );
        planes.calls = Arc::new(CallRecords::open(
            Box::new(FilesystemCallRecordStorage::new(
                root.join("call_records.jsonl"),
            )),
            0,
        ));
        let planes = Arc::new(planes);
        // The suite opens codemode routes as reserved:basal in a run owned by
        // the supervising module. Production requires a live, delegating head route.
        // Because the route's principal (basal) differs from the scope owner
        // (the supervising module), the late-result cases can tell whether results
        // are held and served per carrying principal, as the contract
        // requires, or wrongly per scope owner.
        let head = ScopeStamp::new(principal(OWNER), HEAD_REF, 1, ScopeKind::Head)
            .with_attributes(
                ScopeAttributes::new()
                    .with_agent_id(Some("conformance".into()))
                    .with_delegates(true),
            )
            .with_owner_authorized(true);
        bind_route(&planes, principal(OWNER), Some(head), None, None).await?;
        Ok(planes)
    }
    async fn route(&self, planes: &Arc<Planes>, stamp: &RouteStamp) -> Result<Route, HarnessError> {
        bind_reader_route(planes, stamp, None).await
    }
    async fn kill_at(
        &self,
        _: Arc<Planes>,
        _: &KillPoint,
        _: Trigger<'_>,
    ) -> Result<KillReport, HarnessError> {
        Err(HarnessError::new(
            "no approval crash points declared by this harness",
        ))
    }
    async fn restart(&self, _: &Path) -> Result<Arc<Planes>, HarnessError> {
        Err(HarnessError::new(
            "no crash fixture declared by this harness",
        ))
    }
}

#[async_trait]
impl ToolRoute for Route {
    async fn request(&self, body: Value) -> Result<Exchange, RouteFailure> {
        let (tx, mut rx) = mpsc::channel(64);
        cerebellum::handle_frame_for_test(frame(self.channel, body), &tx, &self.planes)
            .await
            .map_err(|error| RouteFailure::new(error.to_string()))?;
        drop(tx);
        let mut frames = Vec::new();
        while let Some(frame) = rx.recv().await {
            frames.push(match frame.header.ty {
                FrameType::Response => {
                    ObservedFrame::Response(serde_json::from_slice(&frame.body).unwrap())
                }
                FrameType::Error => {
                    ObservedFrame::Error(serde_json::from_slice(&frame.body).unwrap())
                }
                FrameType::StreamEnd => ObservedFrame::StreamEnd,
                _ => {
                    ObservedFrame::Data(serde_json::from_slice(&frame.body).unwrap_or(Value::Null))
                }
            });
        }
        Ok(Exchange { frames })
    }
    async fn request_then_cancel(&self, _: Value) -> Result<Exchange, RouteFailure> {
        Err(RouteFailure::new(
            "no deterministic slow action in the browser-free harness",
        ))
    }
}

#[async_trait]
impl ToolProviderSubject for Subject {
    async fn route_with_consumer_capabilities(
        &self,
        handle: &Self::Handle,
        stamp: &RouteStamp,
        consumer_capabilities: &[String],
    ) -> Result<Self::Route, HarnessError> {
        bind_reader_route(handle, stamp, Some(consumer_capabilities.to_vec())).await
    }

    fn capabilities(&self) -> BTreeSet<Capability> {
        [
            Capability::CallKey,
            Capability::SchemaPin,
            Capability::DisableTool,
            Capability::ScopeStamp,
            Capability::LateResults,
        ]
        .into()
    }
    fn plain_stamp(&self) -> RouteStamp {
        RouteStamp {
            principal: OWNER.into(),
            scope: None,
        }
    }
    fn scoped_principals(&self) -> Option<ScopedPrincipals> {
        Some(ScopedPrincipals {
            scope: ScopeIdentity {
                owner: OWNER.into(),
                scope_ref: "scope".into(),
                scope_epoch: 1,
            },
            other_scope: ScopeIdentity {
                owner: OWNER.into(),
                scope_ref: "other-scope".into(),
                scope_epoch: 1,
            },
            carrier: "reserved:basal".into(),
            other_carrier: OWNER.into(),
        })
    }
    fn catalog_arguments(&self) -> Value {
        json!({"params":{}})
    }
    fn quick_call(&self) -> CallSpec {
        ("browser_use".into(), json!({"action":"status"}))
    }
    fn slow_call(&self) -> Option<CallSpec> {
        None
    }
    fn disabled_tool(&self) -> Option<String> {
        Some("computer_use".into())
    }
    fn held_call(&self, _: &Path) -> Option<CallSpec> {
        None
    }
    async fn await_held(&self, _: &str) -> Result<(), HarnessError> {
        Err(HarnessError::new("no held action fixture"))
    }
    async fn approve(&self, _: &str) -> Result<(), HarnessError> {
        Err(HarnessError::new("no approval fixture"))
    }
    async fn settle(&self) {}
}

#[tokio::test]
async fn tool_provider_role_conforms_on_production_handler() {
    let root = live_daemon_directory(0);
    let planes = Subject.spawn(&root).await.unwrap();
    let route = Subject
        .route(&planes, &Subject.plain_stamp())
        .await
        .unwrap();
    let catalog = served_catalog(&route).await;
    let browser = catalog
        .tools
        .iter()
        .find(|tool| tool.name == "browser_use")
        .expect("the portability case must check the shipped browser tool");
    assert!(browser.input_schema["properties"]["action"]["enum"]
        .as_array()
        .unwrap()
        .contains(&json!("fill_login")));
    drop((route, planes));
    let report = run_suite(&Subject, &root).await.unwrap();
    let report_text = report.render();
    println!("{report_text}");
    // Both tools serve every known mode, so no production tool can be a
    // restricted-mode probe. Unknown bind modes have separate handler tests.
    assert!(report_text.contains("SKIP call_mode_matches_catalog"));
    assert!(report_text.contains("PASS tool_result_v1_valid"));
    assert!(report_text.contains("PASS catalog_schemas_portable"));
    assert!(report_text.contains("PASS late_results_incarnation_change_refused"));
    // The catalog serves no system-prompt text. This fixture has no installed
    // browser for an approval-gated or slow cancellable action and
    // no durable Prepared/Authorized approval states with real process kills.
    // Report those cases as skips, not simulated passes. Scoped withdrawal and
    // login-specific cursor/ack lifecycles have separate handler tests.
    assert!(matches!(
        report.verdict,
        SuiteVerdict::ConformingForDeclaredCapabilities { .. }
    ));
    let _ = fs::remove_dir_all(root);
}

async fn served_catalog(route: &Route) -> cortexkit_role_tool_provider::catalog::CatalogAnswer {
    let exchange = route
        .request(json!({"name":"tool.catalog","arguments":Subject.catalog_arguments()}))
        .await
        .unwrap();
    let [ObservedFrame::Response(answer)] = exchange.frames.as_slice() else {
        panic!("catalog did not return one response: {:?}", exchange.frames);
    };
    serde_json::from_value(answer.clone()).unwrap()
}

#[cfg(target_os = "macos")]
#[tokio::test]
#[ignore = "explicit served-catalog export; requires the release build attestations"]
async fn export_served_flat_tools() {
    let root = live_daemon_directory(0);
    let planes = Subject.spawn(&root).await.unwrap();
    let route = Subject
        .route(&planes, &Subject.plain_stamp())
        .await
        .unwrap();
    let catalog = served_catalog(&route).await;
    let scratch = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/scratch");
    fs::create_dir_all(&scratch).unwrap();
    for name in ["browser_use", "computer_use"] {
        let tool = catalog.tools.iter().find(|tool| tool.name == name).unwrap();
        let bytes = serde_json::to_vec(tool).unwrap();
        fs::write(scratch.join(format!("served-{name}.json")), &bytes).unwrap();
        let definition = serde_json::to_vec(&json!({
            "name":tool.name,"description":tool.description,"input_schema":tool.input_schema
        }))
        .unwrap();
        println!(
            "{name}: served entry {} bytes sha256={}; definition {} bytes sha256={}; schema={}",
            bytes.len(),
            cerebellum::manifest::sha256_hex(&bytes),
            definition.len(),
            cerebellum::manifest::sha256_hex(&definition),
            tool.schema_digest
        );
    }
    let _ = fs::remove_dir_all(root);
}

#[tokio::test]
async fn live_daemon_catalog_preserves_registered_flat_definition() {
    let Some(home) = managed_settings::fenced_home(
        "tool_provider::live_daemon_catalog_preserves_registered_flat_definition",
        HANG_GUARD,
    )
    .await
    else {
        return;
    };
    let (mut daemon, connection) = start_live_daemon_with_browser(true, Some(home)).await;
    let mut client = connect_client(&connection).await;
    let registered = wait_for_cerebellum_catalog(&mut client).await;
    let ClientControlResponse::CatalogList { modules, .. } = registered else {
        panic!("expected catalog");
    };
    let tools = modules
        .iter()
        .find(|module| module.module_id == MODULE_ID)
        .unwrap()
        .roles
        .iter()
        .find_map(|role| {
            if let ProviderRole::ToolProvider { tools, .. } = role {
                Some(tools)
            } else {
                None
            }
        })
        .unwrap();
    let address = open_live_route(&mut client).await;
    let mut request = frame(
        address.0,
        json!({"name":"tool.catalog","arguments":{"params":{}}}),
    );
    request.header.epoch = address.1;
    let corr = request.header.corr;
    write_frame(&mut client, &request).await.unwrap();
    let response = timeout(HANG_GUARD, async {
        loop {
            let response = read_frame(&mut client).await.unwrap().unwrap();
            if response.header.corr == corr {
                break response;
            }
        }
    })
    .await
    .unwrap();
    assert_eq!(response.header.ty, FrameType::Response);
    let answer: cortexkit_role_tool_provider::catalog::CatalogAnswer =
        serde_json::from_slice(&response.body).unwrap();
    let flat = tools
        .iter()
        .find(|tool| tool.name == "browser_use")
        .unwrap();
    assert_eq!(answer.tools.len(), 1);
    assert_eq!(answer.tools[0].description, flat.description);
    assert_eq!(
        serde_json::to_vec(&answer.tools[0].input_schema).unwrap(),
        serde_json::to_vec(&flat.schema).unwrap()
    );
    drop(client);
    daemon.stop();
}

#[tokio::test]
async fn tool_result_v1_requires_route_reader_declaration() {
    let root = live_daemon_directory(0);
    let planes = Subject.spawn(&root).await.unwrap();
    let stamp = Subject.plain_stamp();
    let legacy = bind_reader_route(&planes, &stamp, None).await.unwrap();
    let reader = Subject
        .route_with_consumer_capabilities(
            &planes,
            &stamp,
            &[cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.into()],
        )
        .await
        .unwrap();
    let call = json!({"name":"browser_use", "arguments":{"action":"status"}});
    let legacy_reply = legacy.request(call.clone()).await.unwrap();
    let [ObservedFrame::Response(legacy_body)] = legacy_reply.frames.as_slice() else {
        panic!("legacy route did not produce exactly one response: {legacy_reply:?}");
    };
    assert_eq!(legacy_body, &json!({"outcome":"no_session"}));
    let reader_reply = reader.request(call).await.unwrap();
    let [ObservedFrame::Response(content)] = reader_reply.frames.as_slice() else {
        panic!("reader route did not produce exactly one response: {reader_reply:?}");
    };
    let result: cortexkit_role_tool_provider::result::ToolResult =
        serde_json::from_value(content.clone()).unwrap();
    cortexkit_role_tool_provider::result::validate(&result).unwrap();
    assert_eq!(
        result.structured_content.unwrap(),
        legacy_body.as_object().unwrap().clone()
    );
    let catalog_call = json!({"name":"tool.catalog", "arguments":{"params":{}}});
    assert_eq!(
        legacy.request(catalog_call.clone()).await.unwrap().frames,
        reader.request(catalog_call).await.unwrap().frames,
        "reader declarations must not change catalog metadata"
    );
    let _ = fs::remove_dir_all(root);
}
