//! Only Prefrontal's core module may call cerebellum in a conversation's name.
//!
//! Cerebellum's standing permissions (site grants, app grants, the takeover
//! grant) are keyed on the conversation a person gave them in, and a route
//! names its conversation when it binds. Any first-party module can bind a
//! route under any conversation, so without this rule AFT, Broca, the routing
//! module or a `direct` host plugin could act on a permission the person gave
//! a different caller, without anyone being asked.
//!
//! Every test here drives the frame entry point the module loop uses
//! (`handle_frame_for_test`): a real `route.bind` control frame, then a real
//! request on the bound route. The grant a refused caller must not reach is
//! planted for the very conversation its route names, so a refusal that came
//! after the grant was read would show up as that grant being used.

use std::sync::Arc;
use std::time::Duration;

use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
use subc_protocol::{
    BindIdentity, ErrorBody, Flags, Frame, FrameType, Principal, Priority, RouteTarget,
    PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

/// The conversation every route in these tests names, and the one the planted
/// grant belongs to.
const CONVERSATION: &str = "conversation-with-a-grant";
const GRANTED_ORIGIN: &str = "https://granted.example";
const UNGRANTED_ORIGIN: &str = "http://localhost:8080";
const CHANNEL: u16 = 9;
const EPOCH: u32 = 3;

fn config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    }
}

/// Planes serving the browser, with a site grant for [`GRANTED_ORIGIN`] held
/// by [`CONVERSATION`].
async fn planes_with_a_grant() -> Planes {
    let planes = Planes::with_browser_config_journaling(
        Arc::new(HealthState::new()),
        Some(config()),
        JournalPersistence::Isolated,
    );
    let question = planes
        .management
        .browser_grant_question_for_test(CONVERSATION, vec![GRANTED_ORIGIN.to_string()], Vec::new())
        .await;
    assert!(
        planes
            .management
            .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow_30m"})))
            .await,
        "the planted grant settles"
    );
    planes
}

fn reserved(module_id: &str) -> Option<Principal> {
    Some(Principal::Reserved {
        module_id: module_id.to_string(),
    })
}

fn tool_route() -> RouteTarget {
    RouteTarget::ToolProvider {
        module_id: "cerebellum".to_string(),
    }
}

fn management_route() -> RouteTarget {
    RouteTarget::ManagementSurface {
        module_id: "cerebellum".to_string(),
    }
}

/// Send a real `route.bind` naming [`CONVERSATION`], with fully attested
/// admission facts, so that
/// nothing but the principal stands between the route and the grant. Returns
/// the control reply.
async fn bind(planes: &Planes, principal: Option<Principal>, target: RouteTarget) -> Frame {
    bind_with_scope(planes, principal, target, None).await
}

async fn bind_with_scope(
    planes: &Planes,
    principal: Option<Principal>,
    target: RouteTarget,
    scope: Option<subc_protocol::scope::ScopeStamp>,
) -> Frame {
    let request = ModuleControlRequest::RouteBind {
        role_versions: None,
        call_mode: None,
        route_channel: CHANNEL,
        epoch: EPOCH,
        target,
        identity: BindIdentity::new("/test/project", "test", CONVERSATION.to_string()),
        principal,
        consumer_capabilities: Some(vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": "pj-session-admission",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.launch", "browser.status", "browser.close", "browser.capture_login"],
        })),
        scope,
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        77,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(4);
    cerebellum::handle_frame_for_test(frame, &tx, planes)
        .await
        .expect("the bind is handled");
    rx.recv().await.expect("route.bind receives a reply")
}

async fn bind_acked(planes: &Planes, principal: Option<Principal>, target: RouteTarget) {
    let reply = bind(planes, principal, target).await;
    assert_eq!(
        reply.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&reply.body)
    );
    let body: ModuleControlResponse = serde_json::from_slice(&reply.body).unwrap();
    assert!(matches!(body, ModuleControlResponse::RouteBindAck {}));
}

fn route_request(corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        CHANNEL,
        EPOCH,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn navigate(corr: u64, origin: &str) -> Frame {
    route_request(
        corr,
        json!({
            "name": "browser.navigate",
            "arguments": {
                "url": format!("{origin}/"),
                "intent": "read the page",
                "wait": "none",
                "severity": {"tier": 1, "credential": false, "financial": false},
            },
        }),
    )
}

/// Send one request on the bound route and collect every frame it produces
/// within a short window. Permission questions must not appear on this writer.
async fn frames_for(planes: &Planes, request: Frame) -> Vec<Frame> {
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(request, &tx, planes)
        .await
        .expect("the request is handled");
    let mut frames = vec![tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("the request is answered promptly")
        .expect("the writer stays open")];
    // Keep extra frames so tests can reject a request sent back to the caller
    // (including a permission question), or a duplicate reply.
    while let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
        frames.push(frame);
    }
    frames
}

/// Assert the frames are exactly one refusal naming `label`, with no question
/// put to anyone.
fn assert_refused_as_not_admitted(frames: &[Frame], label: &str) {
    let shapes: Vec<(FrameType, String)> = frames
        .iter()
        .map(|frame| {
            (
                frame.header.ty,
                String::from_utf8_lossy(&frame.body).into_owned(),
            )
        })
        .collect();
    assert_eq!(
        frames.len(),
        1,
        "{label}: exactly one frame, the refusal, and no question: {shapes:?}"
    );
    assert_eq!(frames[0].header.ty, FrameType::Error, "{label}: {shapes:?}");
    let error: ErrorBody = serde_json::from_slice(&frames[0].body).unwrap();
    assert_eq!(
        error.code, "session_caller_not_admitted",
        "{label}: {error:?}"
    );
    let detail = error.detail.expect("the refusal carries its facts");
    assert_eq!(detail["principal"], label, "{label}");
    assert!(
        detail["remedy"]
            .as_str()
            .is_some_and(|remedy| remedy.contains("reserved:prefrontal-core")),
        "{label}: the remedy names the caller that is admitted: {detail}"
    );
}

/// First-party principals other than Prefrontal's core module.
fn other_first_party_principals() -> Vec<(Option<Principal>, &'static str)> {
    vec![
        (Some(Principal::Direct), "direct"),
        (reserved("aft"), "reserved:aft"),
        (reserved("broca"), "reserved:broca"),
        (
            reserved("prefrontal-routing"),
            "reserved:prefrontal-routing",
        ),
    ]
}

/// The admitted caller reaches its conversation's grant: navigating to the
/// granted site passes authorization and stops only because no browser is
/// running, while the ungranted site is put to the person instead.
#[tokio::test]
async fn the_session_caller_acts_on_its_conversations_grant() {
    let service = super::support::computer::cingulate::ScriptedCarrier::default();
    let planes = service.install(planes_with_a_grant().await);
    let bound = bind_with_scope(
        &planes,
        reserved("prefrontal-core"),
        tool_route(),
        Some(super::support::computer::cingulate::stamp(
            "pj-session-admission",
        )),
    )
    .await;
    assert_eq!(bound.header.ty, FrameType::Response);

    let granted = frames_for(&planes, navigate(1, GRANTED_ORIGIN)).await;
    assert_eq!(granted.len(), 1, "no question for a granted site");
    assert_eq!(granted[0].header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&granted[0].body).unwrap();
    assert_eq!(body["outcome"], "no_session", "{body}");

    // The local-service contrast proves the grant gate ran: public sites can
    // pass on the baseline, but an ungranted local service must ask.
    assert!(service.questions().is_empty());
    service.queue(cerebellum::cingulate_client::ScriptedAnswer::Answered(
        json!({"decision":"deny"}),
    ));
    let ungranted = frames_for(&planes, navigate(2, UNGRANTED_ORIGIN)).await;
    assert_eq!(ungranted.len(), 1);
    assert_eq!(
        ungranted[0].header.ty,
        FrameType::Response,
        "no reverse request"
    );
    let reply: Value = serde_json::from_slice(&ungranted[0].body).unwrap();
    assert_eq!(reply["detail"]["decision"], "declined");
    assert_eq!(
        service.questions().len(),
        1,
        "an ungranted site is put to the person through Cingulate"
    );
    assert_eq!(
        service.questions()[0]["params"]["scope"]["origins"],
        json!([UNGRANTED_ORIGIN])
    );
    assert_eq!(
        planes.management.browser_grant_count().await,
        1,
        "declining grants nothing more"
    );
}

/// Every other first-party caller is refused with the typed code, and its
/// route's conversation's grant is not used: had the grant been read, the
/// navigation would have got as far as the admitted caller's did.
#[tokio::test]
async fn other_first_party_callers_are_refused_before_their_conversations_grant() {
    for (principal, label) in other_first_party_principals() {
        let planes = planes_with_a_grant().await;
        bind_acked(&planes, principal, tool_route()).await;
        let frames = frames_for(&planes, navigate(1, GRANTED_ORIGIN)).await;
        assert_refused_as_not_admitted(&frames, label);
    }
}

/// A refused caller is refused before anything asks the person: a site its
/// conversation holds no grant for produces the refusal and no question. Had
/// the refusal come after the site grant was looked up, the missing grant
/// would have put a question to the person first.
#[tokio::test]
async fn a_refused_caller_is_never_asked_about_a_site() {
    for (principal, label) in other_first_party_principals() {
        let planes = planes_with_a_grant().await;
        bind_acked(&planes, principal, tool_route()).await;
        let frames = frames_for(&planes, navigate(1, UNGRANTED_ORIGIN)).await;
        assert_refused_as_not_admitted(&frames, label);
    }
}

/// The management surface refuses the same callers: asking the person for a
/// new site grant is a call in the conversation's name, so it is refused to
/// every caller but Prefrontal's core module, without a question being put.
#[tokio::test]
async fn a_refused_caller_cannot_open_a_grant_on_the_management_surface() {
    for (principal, label) in other_first_party_principals() {
        let planes = planes_with_a_grant().await;
        bind_acked(&planes, principal, management_route()).await;
        let frames = frames_for(
            &planes,
            route_request(
                1,
                json!({
                    "method": "browser.open_grant",
                    "params": {"origins": [UNGRANTED_ORIGIN], "hazards": []},
                }),
            ),
        )
        .await;
        assert_refused_as_not_admitted(&frames, label);
    }
}

/// Principals that resemble the admitted one are not it. None of these is
/// first-party either, so each is refused at bind, and the route it named
/// serves nothing afterwards: a later request finds no route, never the grant.
#[tokio::test]
async fn principals_resembling_the_session_caller_are_refused() {
    for module_id in [
        "prefrontal-cor",
        "prefrontal-core-x",
        "Prefrontal-Core",
        "prefrontal-core ",
        "xprefrontal-core",
    ] {
        let planes = planes_with_a_grant().await;
        let reply = bind(&planes, reserved(module_id), tool_route()).await;
        assert_eq!(reply.header.ty, FrameType::Error, "{module_id:?}");
        let error: ErrorBody = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(error.code, "principal_denied", "{module_id:?}: {error:?}");

        let frames = frames_for(&planes, navigate(1, GRANTED_ORIGIN)).await;
        assert_eq!(frames.len(), 1, "{module_id:?}");
        let error: ErrorBody = serde_json::from_slice(&frames[0].body).unwrap();
        assert_eq!(error.code, "route_not_bound", "{module_id:?}: {error:?}");
    }
}

/// The operator's own operations (listing and revoking app grants, clearing a
/// kept launch record, rebinding the profile root) are served to a `direct`
/// desk route, even though that route names a conversation. That they run
/// outside the conversation is shown in `profile_root_rebind.rs`, where the
/// rebind records which conversation it was made in.
#[tokio::test]
async fn operator_operations_are_served_to_a_direct_route() {
    let planes = planes_with_a_grant().await;
    bind_acked(&planes, Some(Principal::Direct), management_route()).await;

    let listed = frames_for(
        &planes,
        route_request(
            1,
            json!({"method": "computer.list_app_grants", "params": {}}),
        ),
    )
    .await;
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&listed[0].body).unwrap();
    assert_eq!(body["store"]["state"], "loaded", "{body}");

    let revoked = frames_for(
        &planes,
        route_request(
            2,
            json!({
                "method": "computer.revoke_app_grant",
                "params": {"grantee": "pj-other", "bundle_identity": "com.example.Editor", "dry_run": true},
            }),
        ),
    )
    .await;
    assert_eq!(revoked.len(), 1);
    assert_eq!(revoked[0].header.ty, FrameType::Response);
    let body: Value = serde_json::from_slice(&revoked[0].body).unwrap();
    assert_eq!(body["outcome"], "grant_not_found", "{body}");

    // Nothing is kept by startup recovery on these planes, so the clear
    // answers that there is nothing to clear rather than being refused.
    let cleared = frames_for(
        &planes,
        route_request(
            3,
            json!({
                "method": "browser.clear_launch_recovery",
                "params": {"agent_project_id": "pj-other"},
            }),
        ),
    )
    .await;
    assert_eq!(cleared.len(), 1);
    assert_eq!(
        cleared[0].header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&cleared[0].body)
    );

    let rebind = frames_for(
        &planes,
        route_request(
            4,
            json!({"method": "browser.rebind_profile_root", "params": {}}),
        ),
    )
    .await;
    assert_eq!(rebind.len(), 1);
    assert_eq!(
        rebind[0].header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&rebind[0].body)
    );
}

#[tokio::test]
async fn an_unscoped_session_route_cannot_raise_login_cards() {
    let script = cerebellum::cingulate_client::ScriptedCingulate::new();
    let root = std::env::temp_dir().join(format!(
        "unscoped-login-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&root).unwrap();
    for (method, params) in [
        (
            "browser.import_login",
            json!({"origin":"https://example.com"}),
        ),
        (
            "browser.capture_login",
            json!({"credential_domain":"example.com","account":"work","fetch_url":"https://example.com/settings","login_url":"https://example.com/login"}),
        ),
    ] {
        let capture = method == "browser.capture_login";
        let planes = planes_with_a_grant().await.with_cingulate(
            Arc::new(script.clone()),
            Arc::new(cerebellum::cingulate_client::desk::FileRegistryStore::new(
                root.join("registry.json"),
            )),
        );
        bind_acked(
            &planes,
            reserved("prefrontal-core"),
            if capture {
                tool_route()
            } else {
                management_route()
            },
        )
        .await;
        let body = if capture {
            let mut arguments = params;
            arguments["action"] = json!("capture_login");
            json!({"name":"browser_use", "call_key":"pf:unscoped-capture", "arguments":arguments})
        } else {
            json!({"method":method,"params":params})
        };
        let frames = frames_for(&planes, route_request(80, body)).await;
        assert_eq!(frames.len(), 1, "no reverse question frame");
        assert_eq!(frames[0].header.ty, FrameType::Response);
        let reply: Value = serde_json::from_slice(&frames[0].body).unwrap();
        assert_eq!(reply["outcome"], "consent_unavailable", "{method}: {reply}");
        assert_eq!(reply["detail"]["reason"], "no_agent_session", "{reply}");
        cerebellum::browser::validate_browser_result(method, &reply).unwrap();
    }
    assert_eq!(script.opens(), 0);
    assert!(script.calls().is_empty());
    std::fs::remove_dir_all(root).unwrap();
}
