//! Wire admission and the content-bearing reply boundary, without live apps.

use crate::*;
use private_content::{PrivateContent, ReplyPlane, Source};
use subc_protocol::scope::{ParentState, ScopeAttributes, ScopeKind, ScopeParent, ScopeStamp};
use subc_protocol::{Principal, RouteTarget};

fn principal(module: &str) -> Option<Principal> {
    Some(Principal::Reserved {
        module_id: module.into(),
    })
}

fn facts(module: &str) -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("/fixture", "fixture", "conversation"),
        principal(module),
        None,
        None,
        &RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    )
}

fn scoped(scope: &str, kind: ScopeKind) -> AcceptedBindFacts {
    facts("prefrontal-core").with_scope(Some(
        ScopeStamp::new(principal("prefrontal-core").unwrap(), scope, 1, kind)
            .with_owner_authorized(true)
            .with_attributes(
                ScopeAttributes::new()
                    .with_agent_id(Some("fixture-agent".into()))
                    .with_delegates(true),
            ),
    ))
}

fn run(planes: &Planes, scope: &str, channel: u16) -> AcceptedBindFacts {
    let head = scoped("head", ScopeKind::Head);
    planes.routes.insert(1, 1, head.clone());
    let stamp = ScopeStamp::new(
        principal("prefrontal-core").unwrap(),
        scope,
        1,
        ScopeKind::Ephemeral,
    )
    .with_owner_authorized(true)
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some("fixture-agent".into()))
            .with_run_id(Some(scope.into())),
    )
    .with_parent(Some(ScopeParent::new(
        principal("prefrontal-core").unwrap(),
        "head",
        1,
    )))
    .with_parent_state(Some(ParentState::Linked));
    let mut run = facts("basal")
        .with_scope(Some(stamp))
        .with_codemode_head(&head);
    run.call_mode = subc_protocol::call_mode::CallMode::Codemode;
    planes.routes.insert(channel, 1, run.clone());
    run
}

fn request(channel: u16, body: Value) -> Frame {
    Frame::build(
        FrameType::Request,
        control_flags(),
        channel,
        if channel == 0 { 0 } else { 1 },
        1,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

async fn wire(planes: &Planes, caller: AcceptedBindFacts, body: Value) -> (FrameType, Value) {
    planes.routes.insert(8, 1, caller);
    let (tx, mut rx) = mpsc::channel(8);
    handle_route_request(request(8, body), &tx, planes)
        .await
        .unwrap();
    let frame = rx.recv().await.unwrap();
    (
        frame.header.ty,
        serde_json::from_slice(&frame.body).unwrap(),
    )
}

pub(crate) async fn query(planes: &Planes, scope: &str) -> Value {
    let (ty, reply) = wire(
        planes,
        facts("broca"),
        json!({"method":private_content::QUERY,"params":{"scope_ref":scope}}),
    )
    .await;
    assert_eq!(ty, FrameType::Response, "{reply}");
    reply
}

async fn reply(planes: &Planes, facts: &AcceptedBindFacts, plane: ReplyPlane, payload: Value) {
    let (tx, mut rx) = mpsc::channel(1);
    private_content::send_reply(
        planes,
        facts,
        plane,
        &tx,
        (PROTOCOL_VERSION, 2, 1, 1),
        payload.clone(),
    )
    .await
    .unwrap();
    let frame = rx.recv().await.unwrap();
    assert_eq!(frame.header.ty, FrameType::Response);
    assert_eq!(
        serde_json::from_slice::<Value>(&frame.body).unwrap(),
        payload
    );
}

#[tokio::test]
async fn person_browser_content_marks_before_reply() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let facts = scoped("person", ScopeKind::Head);
    let (tx, mut rx) = mpsc::channel(1);
    tx.send(request(2, json!({}))).await.unwrap();
    let send = private_content::send_reply(
        &planes,
        &facts,
        ReplyPlane::PersonBrowser,
        &tx,
        (PROTOCOL_VERSION, 2, 1, 1),
        json!({"state_text":"private page", "outcome":"ok"}),
    );
    tokio::pin!(send);
    tokio::select! {
        biased;
        _ = &mut send => panic!("the reply queue is full"),
        answer = query(&planes, "person") => assert_eq!(answer, json!({"private_content":true,"sources":["person_browser"]})),
    }
    rx.recv().await.unwrap();
    send.await.unwrap();
    assert!(rx.recv().await.is_some());
}

#[tokio::test]
async fn desktop_content_marks_even_on_refused_input() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    reply(
        &planes,
        &scoped("desktop", ScopeKind::Head),
        ReplyPlane::DesktopApp,
        json!({"outcome":"state_changed_by_person", "state_text":"changed app"}),
    )
    .await;
    assert_eq!(
        query(&planes, "desktop").await,
        json!({"private_content":true,"sources":["desktop_app"]})
    );
}

#[tokio::test]
async fn profile_login_marks_even_unrelated_public_pages() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let facts = scoped("site", ScopeKind::Head);
    planes
        .signed_in
        .initialize_profile("fixture-agent", "default", "uuid", true)
        .unwrap();
    planes
        .signed_in
        .record("fixture-agent", "default", "https://accounts.example.com")
        .unwrap();
    reply(
        &planes,
        &facts,
        ReplyPlane::OwnBrowser,
        json!({"state_text":"private site", "source_origin":"http://www.example.com:8080"}),
    )
    .await;
    assert_eq!(
        query(&planes, "site").await,
        json!({"private_content":true,"sources":["signed_in_site"]})
    );
    reply(
        &planes,
        &scoped("public", ScopeKind::Head),
        ReplyPlane::OwnBrowser,
        json!({"state_text":"public page", "source_origin":"https://public.example.org/article?q=1"}),
    )
    .await;
    assert_eq!(
        query(&planes, "public").await["sources"],
        json!(["signed_in_site"])
    );
    let mut empty = scoped("empty-profile", ScopeKind::Head);
    empty.identity.agent_project_id = "empty-agent".into();
    planes
        .signed_in
        .initialize_profile("empty-agent", "default", "empty", true)
        .unwrap();
    reply(
        &planes,
        &empty,
        ReplyPlane::OwnBrowser,
        json!({"state_text":"public page"}),
    )
    .await;
    assert_eq!(
        query(&planes, "empty-profile").await["private_content"],
        false
    );
}

#[tokio::test]
async fn unreadable_login_history_marks_own_content() {
    let scratch = Scratch::new();
    let path = scratch.0.join("signed-in.json");
    std::fs::write(&path, "corrupt login history").unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.signed_in = Arc::new(browser_signed_in::SignedInDomains::open(path));
    reply(
        &planes,
        &scoped("unreadable-logins", ScopeKind::Head),
        ReplyPlane::OwnBrowser,
        json!({"state_text":"public page", "source_origin":"https://example.org"}),
    )
    .await;
    assert_eq!(
        query(&planes, "unreadable-logins").await["sources"],
        json!(["signed_in_site"])
    );
}

#[tokio::test]
async fn content_free_refusals_and_unknown_scopes_are_unmarked() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    for plane in [
        ReplyPlane::PersonBrowser,
        ReplyPlane::DesktopApp,
        ReplyPlane::OwnBrowser,
    ] {
        reply(
            &planes,
            &scoped("refused", ScopeKind::Head),
            plane,
            json!({"outcome":"refused","reason":"no_grant"}),
        )
        .await;
    }
    assert_eq!(
        query(&planes, "refused").await,
        json!({"private_content":false,"sources":[]})
    );
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
}

#[tokio::test]
async fn heads_mark_runs_but_runs_do_not_mark_siblings() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let first = run(&planes, "run-one", 2);
    run(&planes, "run-two", 3);
    reply(
        &planes,
        &first,
        ReplyPlane::DesktopApp,
        json!({"state_text":"run app"}),
    )
    .await;
    assert_eq!(
        query(&planes, "run-one").await["sources"],
        json!(["desktop_app"])
    );
    assert_eq!(query(&planes, "run-two").await["private_content"], false);
    assert_eq!(query(&planes, "head").await["private_content"], false);
    reply(
        &planes,
        &scoped("head", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"head page"}),
    )
    .await;
    assert_eq!(
        query(&planes, "run-two").await["sources"],
        json!(["person_browser"])
    );
    assert_eq!(
        query(&planes, "run-one").await["sources"],
        json!(["person_browser", "desktop_app"])
    );
    reply(
        &planes,
        &first,
        ReplyPlane::PersonBrowser,
        json!({"state_text":"same source"}),
    )
    .await;
    assert_eq!(
        query(&planes, "run-one").await["sources"],
        json!(["person_browser", "desktop_app"])
    );
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "private-content-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(path.join("private-content")).unwrap();
        Self(path)
    }
    fn path(&self) -> PathBuf {
        self.0.join("private-content/private-content-marks.json")
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn marks_survive_reload_and_raise_the_format_floor() {
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    reply(
        &planes,
        &scoped("durable", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"not stored"}),
    )
    .await;
    let bytes = std::fs::read(scratch.path()).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("not stored"));
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    assert_eq!(
        query(&planes, "durable").await["sources"],
        json!(["person_browser"])
    );
    let floor = cerebellum_core::format_floor::read_floors(
        &scratch.0.join("private-content/format-floor.json"),
    )
    .unwrap();
    assert_eq!(
        floor.get(private_content::PRIVATE_CONTENT_FORMAT.name),
        Some(&1)
    );
    assert!(durable_formats::readable_formats().contains(&private_content::PRIVATE_CONTENT_FORMAT));
    assert!(cerebellum_core::format_floor::FLOOR_TREES.contains(&"private-content"));
    assert!(!scratch.0.join("journal/format-floor.json").exists());
    assert!(!scratch.0.join("browser/format-floor.json").exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(scratch.path())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[tokio::test]
async fn corrupt_store_fails_closed_until_a_successful_write_repairs_it() {
    let scratch = Scratch::new();
    std::fs::write(scratch.path(), b"not json").unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    assert_eq!(
        query(&planes, "unknown").await,
        json!({"private_content":true,"sources":["person_browser","desktop_app","signed_in_site"]})
    );
    assert_eq!(planes.private_content.health(), "unreadable");
    let (tx, mut rx) = mpsc::channel(1);
    handle_control_request(
        request(0, json!({"op":"health.check"})),
        &tx,
        &planes.health,
        &planes.routes,
        None,
        Some(&planes.private_content),
    )
    .await
    .unwrap();
    let health: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert_eq!(health["metrics"]["privateContentStore"], "unreadable");
    reply(
        &planes,
        &scoped("repaired", ScopeKind::Head),
        ReplyPlane::DesktopApp,
        json!({"state_text":"app"}),
    )
    .await;
    assert_eq!(planes.private_content.health(), "loaded");
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
    assert_eq!(
        query(&planes, "repaired").await["sources"],
        json!(["desktop_app"])
    );
}

#[tokio::test]
async fn entries_at_least_twenty_four_hours_old_are_pruned() {
    let scratch = Scratch::new();
    let now = wall_clock_ms();
    std::fs::write(
        scratch.path(),
        serde_json::to_vec(&json!({"version":1,"scopes":{
            "expired":{"person_browser":now - 24*60*60*1000},
            "recent":{"desktop_app":now}
        }}))
        .unwrap(),
    )
    .unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    assert_eq!(query(&planes, "expired").await["private_content"], false);
    assert_eq!(
        query(&planes, "recent").await["sources"],
        json!(["desktop_app"])
    );
    planes
        .private_content
        .mark("new", Source::SignedInSite)
        .await;
    let document: Value = serde_json::from_slice(&std::fs::read(scratch.path()).unwrap()).unwrap();
    assert!(document["scopes"].get("expired").is_none());
}

#[tokio::test]
async fn only_broca_can_query_and_broca_has_no_other_authority() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    for module in ["prefrontal-core", "cingulate", "basal", "other"] {
        let (ty, _) = wire(
            &planes,
            facts(module),
            json!({"method":private_content::QUERY,"params":{"scope_ref":"unknown"}}),
        )
        .await;
        assert_eq!(ty, FrameType::Error, "{module}");
    }
    let (ty, body) = wire(
        &planes,
        facts("broca"),
        json!({"method":"permissions.list","params":{}}),
    )
    .await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(body["code"], "principal_denied");
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
}

#[tokio::test]
async fn broca_bind_is_management_only_and_queries_do_not_wait_for_browser_work() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    for (target, admitted) in [
        (
            RouteTarget::ManagementSurface {
                module_id: "cerebellum".into(),
            },
            true,
        ),
        (
            RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            false,
        ),
    ] {
        let bind = ModuleControlRequest::RouteBind {
            route_channel: 8,
            epoch: 1,
            principal: principal("broca"),
            identity: subc_protocol::BindIdentity::new("/fixture", "test", "session"),
            admission_facts: None,
            consumer_capabilities: None,
            target,
            scope: None,
            role_versions: None,
            call_mode: None,
        };
        let (tx, mut rx) = mpsc::channel(8);
        handle_control_request(
            request(0, serde_json::to_value(bind).unwrap()),
            &tx,
            &planes.health,
            &planes.routes,
            None,
            Some(&planes.private_content),
        )
        .await
        .unwrap();
        let response = rx.recv().await.unwrap();
        assert_eq!(response.header.ty == FrameType::Response, admitted);
    }
    let (_guard, _) = planes
        .browser_queue
        .arrive("conversation".into(), None)
        .acquire()
        .await;
    let answer = tokio::time::timeout(std::time::Duration::from_secs(2), query(&planes, "unknown"))
        .await
        .unwrap();
    assert_eq!(answer["private_content"], false);
}

#[tokio::test]
async fn images_nested_reads_and_intercepted_page_names_are_content() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes
        .signed_in
        .record("fixture-agent", "default", "https://example.com")
        .unwrap();
    for (scope, plane, payload, source) in [
        (
            "image",
            ReplyPlane::DesktopApp,
            json!({"image":{"data_b64":"pixels"}}),
            "desktop_app",
        ),
        (
            "nested",
            ReplyPlane::PersonBrowser,
            json!({"read_page":{"state_text":"page"}}),
            "person_browser",
        ),
        (
            "hit",
            ReplyPlane::OwnBrowser,
            json!({"outcome":"click_intercepted","detail":{"hit_name":"private name"}}),
            "signed_in_site",
        ),
    ] {
        reply(&planes, &scoped(scope, ScopeKind::Head), plane, payload).await;
        assert_eq!(query(&planes, scope).await["sources"], json!([source]));
    }
    reply(
        &planes,
        &scoped("unreadable", ScopeKind::Head),
        ReplyPlane::DesktopApp,
        json!({"state_text":computer_capability::DIFF_UNREADABLE}),
    )
    .await;
    assert_eq!(query(&planes, "unreadable").await["private_content"], false);
}

#[tokio::test]
async fn flow_content_stays_in_the_flow_scope() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let flow = facts("basal").with_scope(Some(
        ScopeStamp::new(
            principal("prefrontal-core").unwrap(),
            "flow",
            1,
            ScopeKind::Ephemeral,
        )
        .with_owner_authorized(true)
        .with_attributes(
            ScopeAttributes::new()
                .with_agent_id(Some("fixture-agent".into()))
                .with_flow_id(Some("flow-id".into()))
                .with_delegates(true),
        ),
    ));
    reply(
        &planes,
        &flow,
        ReplyPlane::PersonBrowser,
        json!({"state_text":"flow page"}),
    )
    .await;
    assert_eq!(
        query(&planes, "flow").await["sources"],
        json!(["person_browser"])
    );
    assert_eq!(query(&planes, "other-flow").await["private_content"], false);
}

#[tokio::test]
async fn a_failed_floor_write_fails_closed_without_writing_marks() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.0.join("private-content/format-floor.json")).unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    reply(
        &planes,
        &scoped("write-failure", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"page"}),
    )
    .await;
    assert!(!scratch.path().exists());
    assert_eq!(planes.private_content.health(), "unreadable");
    assert_eq!(
        query(&planes, "unknown").await["sources"],
        json!(["person_browser", "desktop_app", "signed_in_site"])
    );
}

#[tokio::test]
async fn delivered_codemode_image_withholding_does_not_mark() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let facts = scoped("withheld", ScopeKind::Head);
    let (tx, mut rx) = mpsc::channel(1);
    codemode::CALL_DETAIL
        .scope(
            std::cell::RefCell::new(Some(json!({"action":"screenshot"}))),
            async {
                private_content::send_reply(
                    &planes,
                    &facts,
                    ReplyPlane::DesktopApp,
                    &tx,
                    (PROTOCOL_VERSION, 2, 1, 1),
                    json!({"image":{"data_b64":"pixels"}}),
                )
                .await
                .unwrap();
            },
        )
        .await;
    let delivered: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert!(delivered["image"].get("data_b64").is_none());
    assert_eq!(query(&planes, "withheld").await["private_content"], false);
}

#[tokio::test]
async fn replay_and_withdraw_renew_marks_for_the_receiving_scope() {
    use journal::call_records::{Begin, DispatchEvidence, ScopeIdentity, Settlement};
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let original = run(&planes, "original-run", 2);
    run(&planes, "receiving-run", 3);
    let now = wall_clock_ms();
    let Begin::Execute(ticket) = planes.calls.begin_scoped(
        "reserved:basal",
        "private-replay",
        "conversation",
        original.scope.as_ref().map(ScopeIdentity::from_stamp),
        now,
    ) else {
        panic!("new call")
    };
    let stored = Frame::build(
        FrameType::Response,
        control_flags(),
        2,
        1,
        1,
        serde_json::to_vec(&json!({"outcome":"ok","browser":"user","state_text":"retained page"}))
            .unwrap(),
    )
    .unwrap();
    planes.calls.settle(
        ticket,
        Settlement::from_reply(
            &stored,
            DispatchEvidence {
                committed: true,
                ..Default::default()
            },
        ),
        now,
    );
    let (tx, mut rx) = mpsc::channel(8);
    handle_keyed_tool_request(request(3, json!({"name":"browser_use","call_key":"private-replay","arguments":{"browser":"user","action":"snapshot"}})), &tx, &planes).await.unwrap();
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    assert_eq!(
        query(&planes, "receiving-run").await["sources"],
        json!(["person_browser"])
    );
    assert_eq!(
        query(&planes, "original-run").await["private_content"],
        false
    );
    for _ in 0..2 {
        handle_keyed_tool_request(
            request(
                2,
                json!({"name":"tool.withdraw","arguments":{"call_key":"private-replay"}}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let answer: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(answer["answer"], "completed");
    }
    assert_eq!(
        query(&planes, "original-run").await["sources"],
        json!(["person_browser"])
    );
}
