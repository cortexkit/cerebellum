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

fn attach_consent(mut planes: Planes, consent: &tests::ScriptedConsent) -> Planes {
    planes.management = Arc::new(
        ManagementPlane::new(Arc::new(management::PlatformResolver::new())).with_agent_grants(
            Arc::new(agent_grants::AgentGrants::in_memory(Some(
                "test-machine".into(),
            ))),
        ),
    );
    planes.with_cingulate(
        Arc::new(Arc::clone(&consent.script)),
        Arc::new(consent.store()),
    )
}

fn detach(consent: &tests::ScriptedConsent, id: &str) {
    consent.raises(id);
    consent.script.then(
        cingulate_client::wire::CONSENT_DETACH,
        cingulate_client::Reply::Result(
            json!({"elicitation_id":id,"state":"pending","detached":true}),
        ),
    );
}

#[tokio::test]
async fn codemode_consent_asks_the_head_without_parking() {
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "run-site");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_head(&planes).await;
    assert_eq!(
        exchange(
            &planes,
            0,
            2,
            serde_json::to_value(run_bind(run_stamp())).unwrap()
        )
        .await
        .header
        .ty,
        FrameType::Response
    );
    let reply = exchange(
        &planes,
        9,
        3,
        json!({"name":"browser_use","arguments":{
        "action":"open_grant","origins":["https://example.com"],"hazards":[]}}),
    )
    .await;
    assert_eq!(reply.header.ty, FrameType::Response);
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["errorCode"], "held_unsupported", "{reply}");
    assert_eq!(reply["isError"], true);
    assert_eq!(reply["structuredContent"]["detail"]["step"], "consent");
    assert_eq!(
        reply["structuredContent"]["detail"]["origin"],
        "https://example.com"
    );
    assert_eq!(consent.cards().len(), 1);
    assert!(!consent.script.scopes().is_empty());
    for scope in consent.script.scopes() {
        assert_eq!(scope.scope_ref, "head");
        assert_eq!(scope.scope_epoch, Some(7));
        assert_eq!(scope.owner, session_caller_principal_for_test().unwrap());
    }
    assert!(!consent
        .methods()
        .iter()
        .any(|method| method == cingulate_client::wire::CONSENT_AWAIT));
}

#[tokio::test]
async fn legacy_run_without_call_mode_keeps_no_ask_policy() {
    let consent = tests::ScriptedConsent::new();
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    let mut bind = run_bind(run_stamp());
    if let ModuleControlRequest::RouteBind {
        principal,
        call_mode,
        ..
    } = &mut bind
    {
        *principal = session_caller_principal_for_test();
        *call_mode = None;
    }
    assert_eq!(
        exchange(&planes, 0, 2, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
    let reply = exchange(
        &planes,
        9,
        3,
        json!({"name":"browser_use","arguments":{
        "action":"open_grant","origins":["https://example.com"],"hazards":[]}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["errorCode"], "consent_unavailable", "{reply}");
    assert_eq!(reply["structuredContent"]["detail"]["reason"], "agent_run");
    assert!(consent.cards().is_empty());
}

#[tokio::test]
async fn codemode_user_browser_is_unsupported_but_coordinate_actions_are_not() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    exchange(
        &planes,
        0,
        2,
        serde_json::to_value(run_bind(run_stamp())).unwrap(),
    )
    .await;
    let reply = exchange(
        &planes,
        9,
        3,
        json!({"name":"browser_use","arguments":{
        "browser":"user","action":"snapshot","tab":"tab-1"}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["code"], "call_mode_unsupported");
    assert_eq!(
        reply["detail"],
        json!({"tool":"browser_use","mode":"codemode","action":"snapshot"})
    );
    for (tool, action) in [
        ("browser_use", "click_point"),
        ("computer_use", "press_point"),
    ] {
        let reply = exchange(
            &planes,
            9,
            4,
            json!({"name":tool,"arguments":{"action":action}}),
        )
        .await;
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_ne!(reply["code"], "call_mode_unsupported", "{reply}");
        assert_ne!(reply["errorCode"], "call_mode_unsupported", "{reply}");
    }
}

#[tokio::test]
async fn codemode_app_consent_detaches_and_standing_grants_short_circuit() {
    use computer_grants::{ConsentRefusal, GrantNeed, SignedByFixtureTeam};
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "run-app");
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_head(&planes).await;
    exchange(
        &planes,
        0,
        2,
        serde_json::to_value(run_bind(run_stamp())).unwrap(),
    )
    .await;
    let facts = planes.routes.get(9, 3).unwrap();
    let (tx, mut rx) = mpsc::channel(2);
    let frame = request(
        9,
        3,
        json!({"name":"computer_use","arguments":{"action":"read_state","target":"com.example.Test"}}),
    );
    let detail = codemode::call_detail(&frame, &facts);
    let guard = Arc::new(planes.health.enter_request());
    call_context::ROUTE_GUARD
        .scope(
            guard,
            codemode::CALL_DETAIL.scope(std::cell::RefCell::new(detail), async {
                let context = consent_context(&planes, &facts, &tx, 9, 3);
                assert!(!context.agent_run);
                let need = GrantNeed::App {
                    bundle_identity: "com.example.Test".into(),
                    display_name: "Test".into(),
                    code: Arc::new(SignedByFixtureTeam),
                };
                let grants = planes.management.computer_grants();
                let refusal = grants
                    .require(&need, &context, &CancelHandle::pending())
                    .await
                    .unwrap_err();
                assert!(matches!(refusal, ConsentRefusal::Pending { .. }));
                send_tool_response(
                    &tx,
                    PROTOCOL_VERSION,
                    9,
                    3,
                    3,
                    refusal.reply(Some("com.example.Test")),
                )
                .await
                .unwrap();
                let reply: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
                assert_eq!(reply["errorCode"], "held_unsupported", "{reply}");
                assert_eq!(
                    reply["structuredContent"]["detail"]["app"],
                    "com.example.Test"
                );
                seed_app(&planes, "com.example.Test");
                assert!(grants
                    .require(&need, &context, &CancelHandle::pending())
                    .await
                    .is_ok());
            }),
        )
        .await;
    assert_eq!(consent.cards().len(), 1);
    assert!(!consent
        .methods()
        .iter()
        .any(|method| method == cingulate_client::wire::CONSENT_AWAIT));
}

pub(crate) fn seed_app(planes: &Planes, bundle: &str) {
    use agent_grants::{AgentGrant, GrantHolder, GrantSubject};
    let store = planes.management.agent_grants();
    let now = store.now_ms();
    store
        .upsert(
            AgentGrant {
                id: String::new(),
                holder: GrantHolder::Head {
                    agent_id: "test-project".into(),
                },
                subject: GrantSubject::App(bundle.into()),
                browser_target: None,
                machine_uuid: "test-machine".into(),
                granted_at_ms: now,
                expires_at_ms: None,
                card_ref: None,
                max_level: 4,
                hazards: vec![],
                team_id: Some("TESTTEAM".into()),
                designated_requirement: Some(
                    "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                ),
            },
            now,
        )
        .unwrap();
}

pub(crate) async fn bound_run() -> Planes {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    assert_eq!(
        exchange(
            &planes,
            0,
            2,
            serde_json::to_value(run_bind(run_stamp())).unwrap()
        )
        .await
        .header
        .ty,
        FrameType::Response
    );
    planes
}

#[tokio::test]
async fn run_resolves_head_computer_images_and_elements_not_run_bind_handles() {
    use cerebellum_computer::app_state::{
        image::ImageMapping,
        session::{ElementResolution, RegisteredImage},
        source::{RawAppState, RawElement},
    };
    let planes = bound_run().await;
    let sessions = planes.management.app_state_sessions();
    let grant = cerebellum_computer::platform::ProcessGrant {
        bundle_identity: "com.example.Test".into(),
        pid: 42,
        process_generation_evidence: "generation".into(),
    };
    let image = RegisteredImage {
        bundle_identity: grant.bundle_identity.clone(),
        pid: 42,
        process_generation: grant.process_generation_evidence.clone(),
        width_px: 100,
        height_px: 100,
        mapping: ImageMapping::for_window((0.0, 0.0), (100.0, 100.0), (100, 100), (100, 100))
            .unwrap(),
    };
    let image_id = sessions.register_image("head-conversation", image.clone());
    let foreign_image = sessions.register_image("misleading-session", image.clone());
    let read = sessions.observe(
        "head-conversation",
        &grant,
        &RawAppState {
            roots: vec![RawElement::fixture(1, "AXButton").titled("Save")],
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        },
    );
    let element = read.roots[0].element_id.as_ref().unwrap();
    let run = planes.routes.get(9, 3).unwrap();
    assert_eq!(
        sessions.resolve_image(&run.identity.conversation_key, &image_id),
        Some(image)
    );
    assert!(sessions
        .resolve_image(&run.identity.conversation_key, &foreign_image)
        .is_none());
    assert!(matches!(
        sessions.resolve(&run.identity.conversation_key, element),
        ElementResolution::Live { pid: 42, .. }
    ));
    assert!(matches!(
        sessions.resolve("misleading-session", element),
        ElementResolution::Stale
    ));
}

#[tokio::test]
async fn codemode_capture_consent_detaches_without_starting_a_handoff() {
    let fixture = login_capture::test_support::fixture();
    let consent = tests::ScriptedConsent::new();
    detach(&consent, "run-capture");
    let planes = attach_consent(tests::capture_planes(&fixture), &consent);
    bind_head(&planes).await;
    exchange(
        &planes,
        0,
        2,
        serde_json::to_value(run_bind(run_stamp())).unwrap(),
    )
    .await;
    let reply = exchange(
        &planes,
        9,
        3,
        json!({"name":"browser_use","call_key":"run-capture-key", "arguments":{
        "action":"capture_login","credential_domain":"ollama.com","account":"work",
        "fetch_url":"https://ollama.com/settings","login_url":"https://ollama.com/signin"}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["errorCode"], "held_unsupported", "{reply}");
    assert_eq!(reply["structuredContent"]["detail"]["step"], "consent");
    assert_eq!(
        reply["structuredContent"]["detail"]["origin"],
        "https://ollama.com"
    );
    assert_eq!(consent.cards().len(), 1);
    assert!(!consent
        .methods()
        .iter()
        .any(|method| method == cingulate_client::wire::CONSENT_AWAIT));
}

#[tokio::test]
async fn codemode_pre_handoff_failures_are_terminal_not_held() {
    let planes = bound_run().await;
    let reply = exchange(
        &planes,
        9,
        3,
        json!({"name":"browser_use","call_key":"present-failure","arguments":{
        "action":"present","origin":"https://example.com"}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["errorCode"], "no_session", "{reply}");
    let reply = exchange(
        &planes,
        9,
        4,
        json!({"name":"browser_use","call_key":"capture-failure","arguments":{
        "action":"capture_login","credential_domain":"example.com","account":"work",
        "fetch_url":"https://example.com/settings","login_url":"http://example.com/signin"}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["errorCode"], "capture_url_outside_domain", "{reply}");
}

#[tokio::test]
async fn codemode_covering_site_grant_never_asks_or_holds() {
    let consent = tests::ScriptedConsent::new();
    let planes = attach_consent(
        isolated_test_planes(&Arc::new(HealthState::new())),
        &consent,
    );
    bind_head(&planes).await;
    exchange(
        &planes,
        0,
        2,
        serde_json::to_value(run_bind(run_stamp())).unwrap(),
    )
    .await;
    let store = planes.management.agent_grants();
    let now = store.now_ms();
    store
        .upsert(
            agent_grants::AgentGrant {
                id: String::new(),
                holder: agent_grants::GrantHolder::Head {
                    agent_id: "test-project".into(),
                },
                subject: agent_grants::GrantSubject::AllSites,
                browser_target: Some(agent_grants::BrowserTarget::AgentProfile),
                machine_uuid: "test-machine".into(),
                granted_at_ms: now,
                expires_at_ms: None,
                card_ref: None,
                max_level: 2,
                hazards: vec![],
                team_id: None,
                designated_requirement: None,
            },
            now,
        )
        .unwrap();
    let reply = exchange(
        &planes,
        9,
        3,
        json!({"name":"browser_use","arguments":{
        "action":"open_grant","origins":["https://example.com"],"hazards":[]}}),
    )
    .await;
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["structuredContent"]["outcome"], "granted", "{reply}");
    assert_ne!(reply["isError"], true);
    assert!(consent.cards().is_empty());
}

async fn start_queued_run(planes: &Planes, key: &str) -> (mpsc::Receiver<Frame>, CancelHandle) {
    let (tx, rx) = mpsc::channel(8);
    handle_frame_for_test(
        request(
            9,
            30,
            json!({"name":"browser_use","call_key":key,"arguments":{"action":"snapshot"}}),
        ),
        &tx,
        planes,
    )
    .await
    .unwrap();
    let cancel = planes.cancellations.get((9, 3, 30)).unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if matches!(
                planes.calls.lookup_exact("reserved:basal", key),
                journal::call_records::Lookup::Own(_)
            ) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("keyed call admitted before withdrawal");
    (rx, cancel)
}

async fn withdraw(planes: &Planes, channel: u16, key: &str, carrier: Option<&str>) -> Value {
    let mut args = json!({"call_key":key});
    if let Some(carrier) = carrier {
        args["carrier"] = json!(carrier);
    }
    let reply = exchange(
        planes,
        channel,
        40,
        json!({"name":"tool.withdraw","arguments":args}),
    )
    .await;
    serde_json::from_slice(&reply.body).unwrap()
}

async fn bind_carrier(planes: &Planes, module: &str, scope: ScopeStamp) {
    let mut bind = run_bind(scope);
    if let ModuleControlRequest::RouteBind {
        route_channel,
        principal,
        call_mode,
        ..
    } = &mut bind
    {
        *route_channel = 10;
        *principal = Some(subc_protocol::Principal::Reserved {
            module_id: module.into(),
        });
        *call_mode = None;
    }
    assert_eq!(
        exchange(planes, 0, 4, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
}

#[tokio::test]
async fn withdraw_fires_run_cancellation_and_reports_started_honestly() {
    let planes = bound_run().await;
    let (lane, _) = planes
        .browser_queue
        .arrive("head-conversation".into(), None)
        .acquire()
        .await;
    let (mut replies, cancel) = start_queued_run(&planes, "cancel-run").await;
    let answer = withdraw(&planes, 9, "cancel-run", None).await;
    assert_eq!(answer["answer"], "already_started", "{answer}");
    assert!(cancel.is_cancelled());
    let reply = tokio::time::timeout(Duration::from_secs(2), replies.recv())
        .await
        .unwrap()
        .unwrap();
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(reply["code"], "cancelled", "{reply}");
    drop(lane);
}

#[tokio::test]
async fn withdraw_cannot_cancel_another_carriers_matching_key() {
    let planes = bound_run().await;
    bind_carrier(&planes, "aft", run_stamp()).await;
    let (lane, _) = planes
        .browser_queue
        .arrive("head-conversation".into(), None)
        .acquire()
        .await;
    let (_replies, cancel) = start_queued_run(&planes, "shared-key").await;
    let scope = journal::call_records::ScopeIdentity::from_stamp(&run_stamp());
    assert!(matches!(
        planes.calls.begin_attributed(
            "reserved:aft",
            "shared-key",
            "other-conversation",
            Some(scope),
            Default::default(),
            wall_clock_ms()
        ),
        journal::call_records::Begin::Execute(_)
    ));
    let answer = withdraw(&planes, 10, "shared-key", None).await;
    assert_eq!(answer["answer"], "already_started", "{answer}");
    assert!(
        !cancel.is_cancelled(),
        "another carrier's same call_key cannot cancel Basal"
    );
    let answer = withdraw(&planes, 10, "shared-key", Some("reserved:basal")).await;
    assert_eq!(answer["code"], "withdraw_carrier_mismatch", "{answer}");
    assert!(!cancel.is_cancelled());
    withdraw(&planes, 9, "shared-key", None).await;
    drop(lane);
}

#[tokio::test]
async fn authorized_owner_can_withdraw_basal_but_other_scopes_cannot() {
    let planes = bound_run().await;
    let (lane, _) = planes
        .browser_queue
        .arrive("head-conversation".into(), None)
        .acquire()
        .await;
    let (_replies, cancel) = start_queued_run(&planes, "owner-key").await;
    let mut wrong = run_stamp();
    wrong.scope_ref = "different-run".into();
    bind_carrier(&planes, "prefrontal-core", wrong).await;
    let answer = withdraw(&planes, 10, "owner-key", Some("reserved:basal")).await;
    assert_eq!(answer["code"], "withdraw_not_permitted", "{answer}");
    assert!(!cancel.is_cancelled());
    bind_carrier(
        &planes,
        "prefrontal-core",
        run_stamp().with_owner_authorized(false),
    )
    .await;
    let answer = withdraw(&planes, 10, "owner-key", Some("reserved:basal")).await;
    assert_eq!(answer["code"], "withdraw_not_permitted", "{answer}");
    assert!(!cancel.is_cancelled());
    bind_carrier(&planes, "prefrontal-core", run_stamp()).await;
    let answer = withdraw(&planes, 10, "owner-key", Some("reserved:basal")).await;
    assert_eq!(answer["answer"], "already_started", "{answer}");
    assert!(cancel.is_cancelled());
    drop(lane);
}

#[tokio::test]
async fn flow_and_worker_admission_stay_separate_from_run_context() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let mut stamp = run_stamp();
    stamp.attributes.run_id = None;
    stamp.attributes.flow_id = Some("flow-test".into());
    stamp.attributes.delegates = true;
    stamp.kind = ScopeKind::Head;
    let mut bind = run_bind(stamp);
    if let ModuleControlRequest::RouteBind { call_mode, .. } = &mut bind {
        *call_mode = Some(CallMode::Flow);
    }
    assert_eq!(
        exchange(&planes, 0, 1, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
    let flow = planes.routes.get(9, 3).unwrap();
    assert_eq!(flow.flow_id.as_deref(), Some("flow-test"));
    assert!(flow.admits_session_calls());
    assert!(flow.codemode_head.is_none());
    assert_eq!(flow.identity.agent_project_id, "test-project");
    assert!(flow.agent_project_id_attested && flow.acts_as_agent);
    let mut stamp = run_stamp();
    stamp.kind = ScopeKind::Worker;
    stamp.attributes.run_id = None;
    stamp.attributes.agent_id = None;
    let mut bind = run_bind(stamp);
    if let ModuleControlRequest::RouteBind {
        principal,
        call_mode,
        ..
    } = &mut bind
    {
        *principal = session_caller_principal_for_test();
        *call_mode = None;
    }
    assert_eq!(
        exchange(&planes, 0, 2, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
    let worker = planes.routes.get(9, 3).unwrap();
    assert!(worker.admits_session_calls());
    assert!(worker.flow_id.is_none() && worker.codemode_head.is_none());
    assert_eq!(worker.identity.conversation_key, "misleading-session");
    assert_eq!(worker.scope.as_ref().unwrap().kind, ScopeKind::Worker);
}

#[tokio::test]
async fn codemode_image_results_keep_handles_and_dimensions_without_bytes() {
    let reply = json!({"outcome":"ok","image":{"image_id":"head-image","mime":"image/png","width_px":1,"height_px":1,"data_b64":"AA=="}});
    let direct: Value =
        serde_json::from_slice(&tool_result::encode(reply.clone()).unwrap()).unwrap();
    assert!(direct["content"]
        .as_array()
        .unwrap()
        .iter()
        .any(|part| part["type"] == "image"));
    codemode::CALL_DETAIL
        .scope(
            std::cell::RefCell::new(Some(json!({"action":"screenshot"}))),
            async {
                let encoded: Value =
                    serde_json::from_slice(&tool_result::encode(reply.clone()).unwrap()).unwrap();
                assert_eq!(
                    encoded["structuredContent"]["image"]["image_id"],
                    "head-image"
                );
                assert_eq!(encoded["structuredContent"]["image"]["width_px"], 1);
                assert_eq!(encoded["structuredContent"]["image"]["height_px"], 1);
                assert!(encoded["structuredContent"]["image"]
                    .get("data_b64")
                    .is_none());
                assert!(!encoded["content"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|part| part["type"] == "image"));
                let (tx, mut rx) = mpsc::channel(1);
                send_tool_response(&tx, PROTOCOL_VERSION, 9, 3, 1, reply)
                    .await
                    .unwrap();
                let raw: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
                assert_eq!(raw["image"]["image_id"], "head-image");
                assert!(raw["image"].get("data_b64").is_none());
            },
        )
        .await;
}

#[tokio::test]
async fn run_rejects_superseded_head_routes_before_bind() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    bind_head(&planes).await;
    let old = planes.routes.get(8, 3).unwrap();
    let mut newer = old.scope.unwrap();
    newer.scope_epoch += 1;
    let mut bind = run_bind(newer);
    if let ModuleControlRequest::RouteBind {
        route_channel,
        principal,
        call_mode,
        ..
    } = &mut bind
    {
        *route_channel = 11;
        *principal = session_caller_principal_for_test();
        *call_mode = None;
    }
    assert_eq!(
        exchange(&planes, 0, 2, serde_json::to_value(bind).unwrap())
            .await
            .header
            .ty,
        FrameType::Response
    );
    assert!(
        planes.routes.get(8, 3).is_some(),
        "a superseded route can await its GOODBYE"
    );
    refused_run(&planes, run_bind(run_stamp()), "run_parent_unavailable").await;
}

#[tokio::test]
async fn live_run_cancellation_is_bound_to_its_record_scope() {
    let planes = bound_run().await;
    let facts = planes.routes.get(9, 3).unwrap();
    let handle = CancelHandle::pending();
    let _registered = planes
        .run_calls
        .register(&facts, "scope-key", Some(handle.clone()))
        .unwrap();
    let scope = journal::call_records::ScopeIdentity::from_stamp(facts.scope.as_ref().unwrap());
    assert!(planes
        .run_calls
        .cancellation("reserved:basal", "scope-key", Some(&scope))
        .is_some());
    let mut wrong = scope;
    wrong.scope_epoch += 1;
    assert!(planes
        .run_calls
        .cancellation("reserved:basal", "scope-key", Some(&wrong))
        .is_none());
    assert!(planes
        .run_calls
        .cancellation("reserved:basal", "scope-key", None)
        .is_none());
}
