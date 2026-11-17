use super::*;
use crate::{budgets, HealthState};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Condvar, Mutex,
};
use subc_protocol::{
    manifest::{ManagementOperationKind, ProviderRole},
    scope::{ScopeAttributes, ScopeStamp},
    BindIdentity, FrameType, RouteTarget,
};

mod binding_tests;
mod serving_tests;
mod validation_tests;
mod vector_tests;

fn principal(name: &str) -> Option<Principal> {
    Some(Principal::Reserved {
        module_id: name.into(),
    })
}

fn facts(name: &str) -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &BindIdentity::new("ability-test", "session"),
        principal(name),
        None,
        None,
        &RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    )
}

fn stamp(kind: ScopeKind, attrs: ScopeAttributes) -> ScopeStamp {
    ScopeStamp::new(
        principal("prefrontal-core").unwrap(),
        "ability-test",
        1,
        kind,
    )
    .with_owner_authorized(true)
    .with_attributes(attrs)
}

#[test]
fn prefrontal_aliases_admit_only_core_ability_operations() {
    for (principal, expected) in [
        (principal("prefrontal-core"), true),
        (principal("prefrontal"), true),
        (principal("prefrontal-corex"), false),
        (Some(Principal::Unverified), false),
        (Some(Principal::Direct), false),
        (None, false),
    ] {
        let mut route = facts("unused");
        route.principal = principal;
        for method in [DESCRIBE, SCOPE_CHOICES, SETUP] {
            assert_eq!(
                admitted(&route, method, false),
                expected,
                "{method}: {:?}",
                route.principal
            );
        }
        assert!(!admitted(&route, CALL, false));
        for method in [SCOPE_CHOICES, SETUP] {
            assert!(!admitted(&route, method, true));
        }
    }
}

fn flow() -> AcceptedBindFacts {
    facts("basal").with_scope(Some(stamp(
        ScopeKind::Ephemeral,
        ScopeAttributes::new().with_flow_id(Some("flow-test".into())),
    )))
}

#[derive(Default)]
struct FakeStatus {
    calls: AtomicUsize,
    seen: Mutex<Vec<Vec<Token>>>,
    fail_pim: bool,
    block_pim: Option<Arc<Block>>,
}

#[derive(Default)]
struct Block {
    started: tokio::sync::Notify,
    done: Mutex<bool>,
    wake: Condvar,
}
impl Block {
    fn release(&self) {
        *self.done.lock().unwrap() = true;
        self.wake.notify_all();
    }
}
struct Release(Arc<Block>);
impl Drop for Release {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl StatusSource for FakeStatus {
    fn status(&self, tokens: &'static [Token]) -> Result<Vec<(Token, Availability)>, ()> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen.lock().unwrap().push(tokens.to_vec());
        if tokens.contains(&Token::Calendar) {
            if let Some(block) = &self.block_pim {
                block.started.notify_one();
                let mut done = block.done.lock().unwrap();
                while !*done {
                    done = block.wake.wait(done).unwrap();
                }
            }
            if self.fail_pim {
                return Err(());
            }
        }
        Ok(tokens
            .iter()
            .map(|&token| {
                (
                    token,
                    Availability {
                        unavailable_reason: None,
                    },
                )
            })
            .collect())
    }
}

fn fixture(source: Arc<dyn StatusSource>, platform: Platform) -> Planes {
    let mut planes = crate::isolated_test_planes(&Arc::new(HealthState::new()));
    planes.browser = Arc::new(
        crate::browser::BrowserPlane::default().with_journal_persistence(
            false,
            crate::journal::JournalConfig {
                journal_retention_bytes: 4 * 1024 * 1024,
                journal_max_entry_bytes: 64 * 1024,
            },
        ),
    );
    let mut management = crate::management::ManagementPlane::new(Arc::new(
        crate::management::PlatformResolver::new(),
    ));
    management.abilities = AbilityPlane::new(platform, source, true);
    planes.management = Arc::new(management);
    planes
}

async fn wait_for_status_to_release(unit: &SourceUnit) {
    let gate = Arc::new(TerminalArbiter::new(request(json!({"method": DESCRIBE}))));
    let waiting = unit.arrive(gate).unwrap().wait();
    tokio::pin!(waiting);
    loop {
        tokio::select! {
            biased;
            lease = &mut waiting => { drop(lease.unwrap()); break; }
            _ = tokio::task::yield_now() => {}
        }
    }
}

fn request(body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        crate::control_flags(),
        19,
        1,
        7,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

async fn observed_exchange(planes: &Planes, body: Value) -> Frame {
    planes.routes.insert(19, 1, facts("prefrontal-core"));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame_for_test(request(body), &tx, planes)
        .await
        .unwrap();
    rx.recv().await.unwrap()
}

async fn exchange(planes: &Planes, facts: &AcceptedBindFacts, body: Value) -> Frame {
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_management_request(request(body), &tx, facts, planes)
        .await
        .unwrap();
    let response = rx.recv().await.unwrap();
    assert_eq!(
        (
            response.header.channel,
            response.header.epoch,
            response.header.corr
        ),
        (19, 1, 7)
    );
    assert!(rx.try_recv().is_err(), "more than one reply");
    response
}
fn body(frame: &Frame) -> Value {
    serde_json::from_slice(&frame.body).unwrap()
}
fn assert_refusal(frame: &Frame, code: &str) {
    assert_eq!(frame.header.ty, FrameType::Error, "{}", body(frame));
    let body = body(frame);
    assert_eq!(body["code"], code);
    assert_eq!(body.as_object().unwrap().len(), 2);
    assert!(body["message"].is_string());
}
fn valid_params(method: &str) -> Value {
    match method {
        DESCRIBE => json!({}),
        SCOPE_CHOICES => json!({"token":Token::Calendar.as_str(), "key":"calendar"}),
        SETUP => json!({"token":Token::Calendar.as_str()}),
        CALL => {
            json!({"key":"family_calendar", "token":Token::Calendar.as_str(), "op":"calendars.list", "args":{}, "scope":{"calendar":["bound"]}})
        }
        _ => unreachable!(),
    }
}

#[test]
fn ability_surfaces_dispatch_limits_and_phases_are_one_management_only_set() {
    let manifest = crate::manifest::build("cerebellum");
    for method in OPERATIONS {
        assert_eq!(
            crate::management::OPERATIONS
                .iter()
                .filter(|&&name| name == method)
                .count(),
            1
        );
        let operations: Vec<_> = manifest
            .provides
            .iter()
            .flat_map(|role| match role {
                ProviderRole::ManagementSurface { operations, .. } => operations.iter().collect(),
                ProviderRole::ToolProvider { tools, .. } => {
                    assert!(tools.iter().all(|tool| tool.name != method));
                    vec![]
                }
                _ => vec![],
            })
            .filter(|operation| operation.name == method)
            .collect();
        assert_eq!(operations.len(), 1);
        assert_eq!(operations[0].kind, ManagementOperationKind::Query);
        assert!(operations[0]
            .description
            .as_ref()
            .is_some_and(|value| !value.is_empty()));
        assert!(crate::dispatchable_management_operation(method));
        assert!(crate::dispatchable_tool(method).is_none());
        let limits = crate::management::call_limits(method).unwrap();
        assert_eq!(limits.queue_wait_ms, 10_000);
        assert_eq!(
            limits.park_ms,
            if method == SETUP {
                budgets::CONSENT_PARK_LIMIT_MS
            } else {
                0
            }
        );
        let phases: Vec<_> = budgets::management(method)
            .unwrap()
            .phases
            .iter()
            .map(|phase| (phase.name, phase.cap_ms, phase.count))
            .collect();
        let mut expected = vec![
            ("source", 10_000, 1),
            ("teardown", budgets::EXIT_OBSERVATION_MS, 1),
            ("slack", budgets::BOUNDARY_SLACK_MS, 1),
        ];
        if method != DESCRIBE {
            expected.push(("journal", budgets::STORE_MS, 3));
        }
        if method == CALL {
            expected.push(("binding", 10_000, 1));
        }
        assert_eq!(phases, expected);
        assert_eq!(
            limits.envelope_ms,
            budgets::CALL_RECORD_BEGIN_MS + 10_000 + limits.park_ms + limits.work_ms
        );
    }
}

#[test]
fn declared_manifest_capabilities_pass_pinned_hello_and_placement_grammar() {
    use subc_protocol::manifest::{
        validate_hello_capability_grammar, validate_manifest_capability_grammar,
    };
    let manifest = crate::manifest::build("cerebellum");
    let value = serde_json::to_value(&manifest).unwrap();
    validate_manifest_capability_grammar(&value).unwrap();
    validate_hello_capability_grammar(&json!({"manifest":value})).unwrap();
    serde_json::from_value::<subc_protocol::manifest::ModuleManifest>(value).unwrap();
    let provides = &manifest.capabilities.as_ref().unwrap().provides;
    let declared: Vec<_> = provides
        .iter()
        .filter(|value| value.starts_with("cap-"))
        .map(String::as_str)
        .collect();
    let expected: &[&str] = if cfg!(target_os = "macos") {
        &[
            "cap-calendar-read/v1",
            "cap-reminders-read/v1",
            "cap-contacts-read/v1",
            "cap-messages-read/v1",
            "cap-mail-read/v1",
        ]
    } else if cfg!(target_os = "windows") {
        &[
            "cap-calendar-read/v1",
            "cap-reminders-read/v1",
            "cap-contacts-read/v1",
            "cap-mail-read/v1",
        ]
    } else {
        &[
            "cap-calendar-read/v1",
            "cap-reminders-read/v1",
            "cap-contacts-read/v1",
        ]
    };
    assert_eq!(declared, expected);
    for capability in declared {
        assert!(subc_protocol::manifest::is_valid_capability_identifier(
            capability
        ));
        let single = json!({"capabilities":{"provides":[capability]}});
        validate_manifest_capability_grammar(&single).unwrap();
        validate_hello_capability_grammar(&json!({"manifest": single})).unwrap();
    }
}

#[tokio::test]
async fn refused_callers_have_identical_errors_no_source_access_and_no_journal() {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(source.clone(), Platform::MacOs);
    let before = planes.browser.journal_export_for_test().await;
    let mut cases = vec![
        (facts("prefrontal-core"), CALL),
        (flow(), SCOPE_CHOICES),
        (flow(), SETUP),
        (facts("basal"), DESCRIBE),
    ];
    for name in ["other", "cingulate", "cerebellum", "basal", "insula"] {
        for method in OPERATIONS {
            cases.push((facts(name), method));
        }
        let unadmitted = facts(name).with_scope(flow().scope);
        assert!(unadmitted.flow_id.is_none() || name == "basal");
        if name != "basal" {
            for method in OPERATIONS {
                cases.push((unadmitted.clone(), method));
            }
        }
    }
    let mut direct = facts("other");
    direct.principal = Some(Principal::Direct);
    for method in OPERATIONS {
        cases.push((direct.clone(), method));
    }
    direct.principal = None;
    for method in OPERATIONS {
        cases.push((direct.clone(), method));
    }
    let expected = exchange(&planes, &facts("basal"), json!({"method":DESCRIBE}))
        .await
        .body;
    for (facts, method) in cases {
        let reply = exchange(
            &planes,
            &facts,
            json!({"method":method,"params":valid_params(method)}),
        )
        .await;
        assert_refusal(&reply, "principal_denied");
        assert_eq!(reply.body, expected);
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
}

#[tokio::test]
async fn each_broken_core_route_condition_refuses_before_source_access() {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(source.clone(), Platform::MacOs);
    let core = facts("prefrontal-core");
    let mut codemode = core.clone();
    codemode.call_mode = CallMode::Codemode;
    let mut head = core.clone();
    head.codemode_head = Some(Box::new(core.clone()));
    let run = core.clone().with_scope(Some(stamp(
        ScopeKind::Ephemeral,
        ScopeAttributes::new().with_run_id(Some("run".into())),
    )));
    let agent = core.clone().with_scope(Some(stamp(
        ScopeKind::Head,
        ScopeAttributes::new()
            .with_agent_id(Some("agent".into()))
            .with_delegates(true),
    )));
    let unstamped = AcceptedBindFacts::from_bind(
        &BindIdentity::new("test", "s"),
        principal("prefrontal-core"),
        Some(&json!({"agentProjectId":"agent"})),
        None,
        &RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    );
    assert!(unstamped.acts_as_agent);
    let stamped_flow = core.with_scope(flow().scope);
    let before = planes.browser.journal_export_for_test().await;
    for route in [codemode, head, run, agent, unstamped, stamped_flow] {
        for method in [DESCRIBE, SCOPE_CHOICES, SETUP] {
            let reply = exchange(
                &planes,
                &route,
                json!({"method":method,"params":valid_params(method)}),
            )
            .await;
            assert_refusal(&reply, "principal_denied");
        }
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
}

#[tokio::test]
async fn core_card_operations_require_own_route_and_reject_any_origin_value() {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(source.clone(), Platform::MacOs);
    let core = facts("prefrontal-core");
    let agent = core.clone().with_scope(Some(stamp(
        ScopeKind::Head,
        ScopeAttributes::new()
            .with_agent_id(Some("agent".into()))
            .with_delegates(false),
    )));
    assert!(!agent.acts_as_agent);
    let worker = core
        .clone()
        .with_scope(Some(stamp(ScopeKind::Worker, ScopeAttributes::new())));
    let before = planes.browser.journal_export_for_test().await;
    for method in [SCOPE_CHOICES, SETUP] {
        for route in [&agent, &worker] {
            assert_refusal(
                &exchange(
                    &planes,
                    route,
                    json!({"method":method,"params":valid_params(method)}),
                )
                .await,
                "principal_denied",
            );
        }
        for origin in [
            Value::Null,
            json!(false),
            json!(1),
            json!(""),
            json!([]),
            json!({"module_id":"core"}),
        ] {
            assert_refusal(
                &exchange(
                    &planes,
                    &core,
                    json!({"method":method,"params":valid_params(method),"origin":origin}),
                )
                .await,
                "principal_denied",
            );
        }
    }
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    let reply = exchange(&planes, &agent, json!({"method":DESCRIBE})).await;
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(source.calls.load(Ordering::SeqCst), 2);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
    for method in [
        DESCRIBE,
        CALL,
        crate::management::WOULD_ASK,
        "unknown.method",
    ] {
        let reply = exchange(&planes, &core, json!({"method":method,"origin":null})).await;
        assert_eq!(reply.header.ty, FrameType::Response);
        assert_eq!(body(&reply)["detail"]["reason_code"], "unknown_field");
        assert_eq!(body(&reply)["detail"]["field"], "origin");
    }
}

#[test]
fn catalog_mapping_matches_entorhinal_resolver_token_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../tests/vectors/ability-v1/catalog-token-mapping.json"
    ))
    .unwrap();
    for value in vectors["capability_tokens"]["valid"].as_array().unwrap() {
        assert!(map_capability(value.as_str().unwrap()).is_some(), "{value}");
    }
    for value in vectors["capability_tokens"]["invalid"].as_array().unwrap() {
        assert!(map_capability(value.as_str().unwrap()).is_none(), "{value}");
    }
    let mapping = &vectors["capability_manifest_mapping"];
    for pair in mapping["pairs"].as_array().unwrap() {
        let token = pair["token"].as_str().unwrap();
        let capability = pair["capability"].as_str().unwrap();
        assert_eq!(map_capability(token).as_deref(), Some(capability));
        assert_eq!(map_capability(capability).as_deref(), Some(token));
    }
    assert!(map_capability(mapping["token_too_long"].as_str().unwrap()).is_none());
    for value in mapping["capability_not_a_token"].as_array().unwrap() {
        assert!(map_capability(value.as_str().unwrap()).is_none(), "{value}");
    }
}

#[tokio::test]
async fn describe_is_schema_complete_ordered_and_only_availability_changes() {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(source.clone(), Platform::MacOs);
    for route in [facts("prefrontal-core"), flow()] {
        let reply = exchange(&planes, &route, json!({"method":DESCRIBE})).await;
        assert_eq!(reply.header.ty, FrameType::Response);
        let mut reply = body(&reply);
        assert!(reply.get("outcome").is_none());
        assert!(reply.get("image").is_none());
        for token in reply["tokens"].as_array_mut().unwrap() {
            assert_eq!(
                token.as_object_mut().unwrap().remove("available"),
                Some(json!(true))
            );
            assert!(token.get("unavailable_reason").is_none());
        }
        assert_eq!(reply, json!({"tokens":token_schemas(Platform::MacOs)}));
    }
    let failing = fixture(
        Arc::new(FakeStatus {
            fail_pim: true,
            ..Default::default()
        }),
        Platform::MacOs,
    );
    let reply = exchange(
        &failing,
        &facts("prefrontal-core"),
        json!({"method":DESCRIBE,"params":{}}),
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Response);
    let mut reply = body(&reply);
    for (index, token) in reply["tokens"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .enumerate()
    {
        assert_eq!(
            token.as_object_mut().unwrap().remove("available"),
            Some(json!(index >= 3))
        );
        assert_eq!(
            token.as_object_mut().unwrap().remove("unavailable_reason"),
            if index < 3 {
                Some(json!("source_unresponsive"))
            } else {
                None
            }
        );
    }
    assert_eq!(reply, json!({"tokens": token_schemas(Platform::MacOs)}));
    assert_eq!(source.calls.load(Ordering::SeqCst), 4);
    let seen = source.seen.lock().unwrap();
    assert_eq!(
        seen.iter()
            .filter(|tokens| **tokens == [Token::Calendar, Token::Reminders, Token::Contacts])
            .count(),
        2
    );
    assert_eq!(
        seen.iter()
            .filter(|tokens| **tokens == [Token::Messages, Token::Mail])
            .count(),
        2
    );
}

#[tokio::test]
async fn default_adapters_never_advertise_available_and_manifest_is_unchanged() {
    let before = serde_json::to_value(crate::manifest::build("cerebellum")).unwrap();
    for platform in [Platform::MacOs, Platform::Windows, Platform::Linux] {
        let plane = AbilityPlane::new(platform, Arc::new(UnavailableSource(platform)), true);
        let reply = plane
            .describe(Arc::new(TerminalArbiter::new(request(
                json!({"method":DESCRIBE}),
            ))))
            .await;
        assert_eq!(
            reply["tokens"].as_array().unwrap().len(),
            platform.tokens().len()
        );
        for token in reply["tokens"].as_array().unwrap() {
            assert_eq!(token["available"], false);
            assert!(token["unavailable_reason"].is_string());
        }
    }
    assert_eq!(
        serde_json::to_value(crate::manifest::build("cerebellum")).unwrap(),
        before
    );
}

#[tokio::test]
async fn describe_invalid_params_use_fixed_error_and_principal_precedes_shape() {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(source.clone(), Platform::MacOs);
    let mut expected = None;
    for params in [
        Value::Null,
        json!([]),
        json!(1),
        json!({"secret":"do not echo"}),
    ] {
        let reply = exchange(
            &planes,
            &facts("prefrontal-core"),
            json!({"method":DESCRIBE,"params":params}),
        )
        .await;
        assert_refusal(&reply, "ability_args_invalid");
        if let Some(expected) = &expected {
            assert_eq!(&reply.body, expected);
        } else {
            expected = Some(reply.body);
        }
    }
    assert_refusal(
        &exchange(
            &planes,
            &facts("basal"),
            json!({"method":DESCRIBE,"params":null}),
        )
        .await,
        "principal_denied",
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
}

async fn assert_pending(method: &str, route: AcceptedBindFacts, code: &str) {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(
        source.clone(),
        if method == SETUP {
            Platform::MacOs
        } else {
            platform()
        },
    );
    let before = planes.browser.journal_export_for_test().await;
    let gate = Arc::new(TerminalArbiter::new(request(json!({"method": method}))));
    let holder = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap()
        .arrive(gate)
        .unwrap()
        .wait()
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    let reply = exchange(
        &planes,
        &route,
        json!({"method":method,"params":valid_params(method)}),
    )
    .await;
    assert_refusal(&reply, code);
    assert_eq!(
        start.elapsed(),
        if method == CALL {
            std::time::Duration::ZERO
        } else {
            std::time::Duration::from_secs(10)
        },
        "only bound and validated requests may wait for a source unit"
    );
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
    drop(holder);
}
#[tokio::test(start_paused = true)]
async fn scope_choices_queue_expiry_refuses_without_source_or_journal() {
    assert_pending(
        SCOPE_CHOICES,
        facts("prefrontal-core"),
        "ability_source_timeout",
    )
    .await;
}
#[tokio::test(start_paused = true)]
async fn mac_setup_queue_expiry_refuses_without_source_or_journal() {
    assert_pending(SETUP, facts("prefrontal-core"), "ability_source_timeout").await;
}
#[tokio::test(start_paused = true)]
async fn call_pending_binding_refuses_without_touching_source_unit() {
    assert_pending(CALL, flow(), "ability_binding_unavailable").await;
}

#[tokio::test(start_paused = true)]
async fn request_rows_precede_binding_and_the_busy_source_unit() {
    let source = Arc::new(FakeStatus::default());
    let planes = fixture(source.clone(), platform());
    let before = planes.browser.journal_export_for_test().await;
    let gate = Arc::new(TerminalArbiter::new(request(json!({"method": CALL}))));
    let holder = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap()
        .arrive(gate)
        .unwrap()
        .wait()
        .await
        .unwrap();
    let call = valid_params(CALL);
    let choices = valid_params(SCOPE_CHOICES);
    let mut cases = Vec::new();
    // A non-object scope is a params type error, before token or op lookup.
    let mut p = call.clone();
    p["token"] = json!("unknown");
    p["scope"] = json!([]);
    cases.push((CALL, p, "ability_args_invalid"));
    let mut p = call.clone();
    p["token"] = json!("unknown");
    p["scope"] = json!({"calendar":[""]});
    cases.push((CALL, p, "ability_token_unknown"));
    let mut p = call.clone();
    p["op"] = json!("unknown");
    p["scope"] = json!({"calendar":[""]});
    cases.push((CALL, p, "ability_op_unknown"));
    let mut p = call.clone();
    p["scope"] = json!({"calendar":[""]});
    p["args"] = json!({"unknown":true});
    cases.push((CALL, p, "ability_scope_invalid"));
    let mut p = call.clone();
    p["op"] = json!("events.get");
    p["args"] = json!({"id":"é".repeat(1025)});
    cases.push((CALL, p, "ability_args_invalid"));
    let mut p = choices.clone();
    p["token"] = json!("unknown");
    p["limit"] = json!("wrong type");
    cases.push((SCOPE_CHOICES, p, "ability_args_invalid"));
    let mut p = choices;
    p["token"] = json!("unknown");
    p["limit"] = json!(201);
    cases.push((SCOPE_CHOICES, p, "ability_token_unknown"));
    let start = tokio::time::Instant::now();
    for (method, params, code) in cases {
        let route = if method == CALL {
            flow()
        } else {
            facts("prefrontal-core")
        };
        assert_refusal(
            &exchange(&planes, &route, json!({"method":method,"params":params})).await,
            code,
        );
    }
    assert_eq!(tokio::time::Instant::now(), start);
    assert_eq!(source.calls.load(Ordering::SeqCst), 0);
    assert_eq!(planes.browser.journal_export_for_test().await, before);
    drop(holder);
}

#[tokio::test(start_paused = true)]
async fn hung_or_quarantined_unit_describes_unresponsive_without_hiding_other_units() {
    let block = Arc::new(Block::default());
    let release = Release(block.clone());
    let source = Arc::new(FakeStatus {
        block_pim: Some(block.clone()),
        ..Default::default()
    });
    let planes = Arc::new(fixture(source.clone(), Platform::MacOs));
    let request_planes = planes.clone();
    let work = tokio::spawn(async move {
        observed_exchange(&request_planes, json!({"method": DESCRIBE})).await
    });
    block.started.notified().await;
    // The messages/mail status must run while the calendar/reminders/contacts
    // helper is blocked, not after that helper's deadline.
    while source.calls.load(Ordering::SeqCst) < 2 {
        tokio::task::yield_now().await;
    }
    wait_for_status_to_release(
        planes
            .management
            .abilities
            .units
            .for_token(Token::Mail)
            .unwrap(),
    )
    .await;
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    let reply = work.await.unwrap();
    assert_eq!(reply.header.ty, FrameType::Response);
    let reply = body(&reply);
    for (index, token) in reply["tokens"].as_array().unwrap().iter().enumerate() {
        assert_eq!(token["available"], index >= 3);
        if index < 3 {
            assert_eq!(token["unavailable_reason"], "source_unresponsive");
        }
    }
    assert!(planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap()
        .quarantined());
    let reply = exchange(
        &planes,
        &facts("prefrontal-core"),
        json!({"method":DESCRIBE}),
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(
        body(&reply)["tokens"][0]["unavailable_reason"],
        "source_unresponsive"
    );
    assert_eq!(
        source.calls.load(Ordering::SeqCst),
        3,
        "quarantine started a second PIM worker"
    );
    drop(release);
}

#[tokio::test(start_paused = true)]
async fn busy_unit_describe_uses_queue_limit_and_still_returns_tokens() {
    let source = Arc::new(FakeStatus::default());
    let planes = Arc::new(fixture(source.clone(), Platform::MacOs));
    let gate = Arc::new(TerminalArbiter::new(request(json!({"method":DESCRIBE}))));
    let holder = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap()
        .arrive(gate)
        .unwrap()
        .wait()
        .await
        .unwrap();
    let request_planes = planes.clone();
    let work = tokio::spawn(async move {
        observed_exchange(&request_planes, json!({"method": DESCRIBE})).await
    });
    while source.calls.load(Ordering::SeqCst) < 1 {
        tokio::task::yield_now().await;
    }
    wait_for_status_to_release(
        planes
            .management
            .abilities
            .units
            .for_token(Token::Mail)
            .unwrap(),
    )
    .await;
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    let reply = work.await.unwrap();
    assert_eq!(reply.header.ty, FrameType::Response);
    assert_eq!(
        body(&reply)["tokens"][0]["unavailable_reason"],
        "source_unresponsive"
    );
    assert_eq!(body(&reply)["tokens"][3]["available"], true);
    drop(holder);
}

#[tokio::test(start_paused = true)]
async fn queued_then_hung_describe_returns_status_before_the_arbiter_envelope() {
    let block = Arc::new(Block::default());
    let release = Release(block.clone());
    let source = Arc::new(FakeStatus {
        block_pim: Some(block.clone()),
        ..Default::default()
    });
    let planes = Arc::new(fixture(source.clone(), Platform::MacOs));
    let gate = Arc::new(TerminalArbiter::new(request(json!({"method": DESCRIBE}))));
    let holder = planes
        .management
        .abilities
        .units
        .for_token(Token::Calendar)
        .unwrap()
        .arrive(gate)
        .unwrap()
        .wait()
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    let request_planes = planes.clone();
    let work = tokio::spawn(async move {
        observed_exchange(&request_planes, json!({"method": DESCRIBE})).await
    });
    while source.calls.load(Ordering::SeqCst) < 1 {
        tokio::task::yield_now().await;
    }
    wait_for_status_to_release(
        planes
            .management
            .abilities
            .units
            .for_token(Token::Mail)
            .unwrap(),
    )
    .await;
    tokio::time::advance(std::time::Duration::from_millis(9_999)).await;
    drop(holder);
    block.started.notified().await;
    tokio::time::advance(std::time::Duration::from_secs(10)).await;
    let reply = work.await.unwrap();
    assert_eq!(reply.header.ty, FrameType::Response, "{}", body(&reply));
    assert_eq!(
        body(&reply)["tokens"][0]["unavailable_reason"],
        "source_unresponsive"
    );
    assert_eq!(body(&reply)["tokens"][3]["available"], true);
    assert_eq!(start.elapsed(), std::time::Duration::from_millis(19_999));
    drop(release);
}
