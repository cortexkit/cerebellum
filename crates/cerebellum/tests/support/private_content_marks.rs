//! Wire admission and the content-bearing reply boundary, without live apps.

use crate::*;
use private_content::{PrivateContent, ReplyPlane, Retention, Source};
use subc_protocol::scope::{ParentState, ScopeAttributes, ScopeKind, ScopeParent, ScopeStamp};
use subc_protocol::{Principal, RouteTarget};

fn principal(module: &str) -> Option<Principal> {
    Some(Principal::Reserved {
        module_id: module.into(),
    })
}

fn facts(module: &str) -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("fixture", "conversation"),
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

macro_rules! person_metadata_test {
    ($name:ident, $action:literal, $payload:expr) => {
        #[tokio::test]
        async fn $name() {
            let planes = isolated_test_planes(&Arc::new(HealthState::new()));
            let payload = $payload;
            browser::validate_user_browser_result($action, &payload).unwrap();
            reply(
                &planes,
                &scoped($action, ScopeKind::Head),
                ReplyPlane::PersonBrowser,
                payload,
            )
            .await;
            assert_eq!(query(&planes, $action).await["private_content"], false);
        }
    };
}

person_metadata_test!(
    person_status_metadata_does_not_mark,
    "status",
    json!({"browser":"user","outcome":"ok","connected":true,"connection_epoch":1,
        "tabs":[{"tab":"opaque-tab","claim":"unclaimed_handed","interaction_epoch":1}]})
);
person_metadata_test!(
    person_open_tab_metadata_does_not_mark,
    "open_tab",
    json!({"browser":"user","outcome":"ok","tab":"opaque-tab","interaction_epoch":1,"input_dispatched":true})
);
person_metadata_test!(
    person_claim_tab_metadata_does_not_mark,
    "claim_tab",
    json!({"browser":"user","outcome":"ok","tab":"opaque-tab","interaction_epoch":1})
);
person_metadata_test!(
    person_open_grant_metadata_does_not_mark,
    "open_grant",
    json!({"browser":"user","outcome":"ok","origin":"https://requested.example"})
);

macro_rules! person_content_test {
    ($name:ident, $action:literal, $payload:expr) => {
        #[tokio::test]
        async fn $name() {
            let planes = isolated_test_planes(&Arc::new(HealthState::new()));
            let payload = $payload;
            browser::validate_user_browser_result($action, &payload).unwrap();
            reply(
                &planes,
                &scoped($action, ScopeKind::Head),
                ReplyPlane::PersonBrowser,
                payload,
            )
            .await;
            assert_eq!(
                query(&planes, $action).await["sources"],
                json!(["person_browser"])
            );
        }
    };
}

person_content_test!(
    person_navigate_read_page_marks,
    "navigate",
    json!({"browser":"user","outcome":"ok","tab":"opaque-tab","interaction_epoch":1,
        "read_page":{"browser":"user","outcome":"ok","state_text":"private landing page"}})
);
person_content_test!(
    person_snapshot_marks,
    "snapshot",
    json!({"browser":"user","outcome":"ok","state_text":"private page"})
);
person_content_test!(
    person_screenshot_marks,
    "screenshot",
    json!({"browser":"user","outcome":"ok","image":{"mime":"image/png","data_b64":"cGl4ZWxz","width_px":1,"height_px":1}})
);

// These paths contain fixed diagnostics, opaque handles, counts, or the
// caller's requested origin, not text read from a page. Any new leaf must be
// marked at the real reply boundary or explicitly reviewed as metadata here.
const PERSON_METADATA: &[&str] = &[
    "browser",
    "outcome",
    "ask_id",
    "reason",
    "remedy",
    "settled",
    "settlement_reason",
    "input_dispatched",
    "tab",
    "connected",
    "origin",
    "connection_epoch",
    "interaction_epoch",
    "tabs.[].tab",
    "tabs.[].claim",
    "tabs.[].interaction_epoch",
    "snapshot_id",
    // An opaque handle for the screenshot this reply already carries, not page
    // text: the bytes it names came in the same reply, which marks on its own.
    "image_handle",
    "read_page.image_handle",
    "truncated",
    "refs_truncated",
    "omitted_frames",
    "frame_note",
    "image.mime",
    "image.width_px",
    "image.height_px",
    "image_width_px",
    "image_height_px",
    "popup_activated_briefly",
    "observer_available",
    "revoked",
    "detail.field",
    "detail.reason_code",
    "detail.decision",
    "detail.reason",
    "detail.method",
    "detail.code",
    "detail.message",
    "detail.extension_revision",
    "detail.required_revision",
    "detail.step",
    "detail.problem",
    "detail.check",
    "detail.cause",
    "detail.history_entry_changed",
    "detail.history_index_changed",
    "detail.history_length_changed",
    "detail.url_changed",
    "detail.loader_changed",
];

fn schema_content_probes(
    schema: &Value,
    path: Vec<String>,
    probes: &mut Vec<(Vec<String>, Value)>,
) {
    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        assert_eq!(
            schema["additionalProperties"], false,
            "open result object at {path:?}"
        );
        for (name, child) in properties {
            let mut child_path = path.clone();
            child_path.push(name.clone());
            schema_content_probes(child, child_path, probes);
        }
    } else if let Some(items) = schema.get("items") {
        let mut child_path = path.clone();
        child_path.push("[]".into());
        schema_content_probes(items, child_path, probes);
    } else if let Some(ty) = schema.get("type") {
        let normalized = path
            .iter()
            .filter(|part| part.as_str() != "read_page")
            .cloned()
            .collect::<Vec<_>>()
            .join(".");
        if !PERSON_METADATA.contains(&normalized.as_str()) {
            let sample = if ty == "boolean" {
                json!(true)
            } else if ty == "integer" || ty == "number" {
                json!(1)
            } else {
                json!("schema privacy probe")
            };
            probes.push((path.clone(), sample));
        }
    }
    for union in ["anyOf", "oneOf", "allOf"] {
        if let Some(branches) = schema.get(union).and_then(Value::as_array) {
            for branch in branches {
                schema_content_probes(branch, path.clone(), probes);
            }
        }
    }
}

fn probe_payload(path: &[String], sample: Value) -> Value {
    let Some((first, rest)) = path.split_first() else {
        return sample;
    };
    if first == "[]" {
        return json!([probe_payload(rest, sample)]);
    }
    let mut object = serde_json::Map::new();
    object.insert(first.clone(), probe_payload(rest, sample));
    Value::Object(object)
}

/// Sends one probe reply per schema leaf that is not reviewed metadata and
/// returns the probed paths together with those whose probe did not mark.
async fn unmarked_schema_fields(schema: &Value) -> (Vec<Vec<String>>, Vec<Vec<String>>) {
    let mut probes = Vec::new();
    schema_content_probes(schema, Vec::new(), &mut probes);
    let probed = probes.iter().map(|(path, _)| path.clone()).collect();
    let mut missing = Vec::new();
    for (path, sample) in probes {
        let planes = isolated_test_planes(&Arc::new(HealthState::new()));
        reply(
            &planes,
            &scoped("schema-probe", ScopeKind::Head),
            ReplyPlane::PersonBrowser,
            probe_payload(&path, sample),
        )
        .await;
        if query(&planes, "schema-probe").await["private_content"] != true {
            missing.push(path);
        }
    }
    (probed, missing)
}

#[tokio::test]
async fn person_result_schema_has_no_unmarked_content_fields() {
    let mut probed = std::collections::BTreeSet::new();
    for action in budgets::USER_BROWSER_ACTIONS {
        let schema = browser::user_browser_result_schema(action.action);
        let (paths, missing) = unmarked_schema_fields(&schema).await;
        assert!(
            missing.is_empty(),
            "unmarked fields in {action:?}: {missing:?}"
        );
        probed.extend(paths.into_iter().map(|path| path.join(".")));
    }
    // The walk must reach the known content fields, or it proves nothing.
    for known in [
        "state_text",
        "image.data_b64",
        "read_page.state_text",
        "read_page.image.data_b64",
    ] {
        assert!(probed.contains(known), "{known} was not probed: {probed:?}");
    }
}

#[tokio::test]
async fn person_schema_guard_rejects_a_planted_title_field() {
    let mut schema = browser::user_browser_result_schema("status");
    schema["properties"]["tabs"]["items"]["properties"]["title"] = json!({"type":"string"});
    assert_eq!(
        unmarked_schema_fields(&schema).await.1,
        vec![vec!["tabs".to_owned(), "[]".to_owned(), "title".to_owned()]]
    );
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
    for plane in [ReplyPlane::PersonBrowser, ReplyPlane::OwnBrowser] {
        reply(
            &planes,
            &scoped("refused", ScopeKind::Head),
            plane,
            json!({"outcome":"refused","reason":"no_grant"}),
        )
        .await;
    }
    // Desktop replies mark unless they are refusals known to carry no app text.
    for payload in [
        json!({"outcome":"screen_locked","reason":"screen_locked","remedy":"unlock"}),
        json!({"outcome":"invalid_request","field":"app","reason":"empty_value"}),
        json!({"outcome":"blocking_capacity_exhausted",
            "detail":{"dispatched":false,"step":"read","call":"read_state"},"remedy":"retry"}),
        json!({"outcome":"cancelled"}),
    ] {
        reply(
            &planes,
            &scoped("refused", ScopeKind::Head),
            ReplyPlane::DesktopApp,
            payload,
        )
        .await;
    }
    assert_eq!(
        query(&planes, "refused").await,
        json!({"private_content":false,"sources":[]})
    );
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
}

/// A run's output returns to its head, so a run's read marks the head too,
/// and the head's other runs inherit the mark through it. A head's own read
/// marks all its runs.
#[tokio::test]
async fn run_marks_reach_their_head_and_its_other_runs() {
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
    assert_eq!(
        query(&planes, "head").await["sources"],
        json!(["desktop_app"])
    );
    assert_eq!(
        query(&planes, "run-two").await["sources"],
        json!(["desktop_app"])
    );
    assert_eq!(query(&planes, "unrelated").await["private_content"], false);
    reply(
        &planes,
        &scoped("head", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"head page"}),
    )
    .await;
    assert_eq!(
        query(&planes, "run-two").await["sources"],
        json!(["person_browser", "desktop_app"])
    );
    // The run keeps its own marks 24 hours; its head keeps them for life.
    let document = {
        let state = planes.private_content.state_for_test();
        (state.0, state.1)
    };
    assert!(document.0.contains(&"head".to_owned()), "{document:?}");
    assert!(document.1.contains(&"run-one".to_owned()), "{document:?}");
}

/// Broca names a run's parent even when the run has no Cerebellum route. The
/// run's marks then reach that parent, and the parent's other runs inherit.
#[tokio::test]
async fn a_routeless_run_marks_the_parent_broca_names() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes
        .private_content
        .mark("routeless-run", Retention::Run, Source::DesktopApp)
        .await;
    assert_eq!(query(&planes, "named-head").await["private_content"], false);
    let ask = |scope: &str| {
        json!({"method":private_content::QUERY,"params":{
            "scope_ref":scope, "parent_scope_ref":"named-head"
        }})
    };
    let (_, answer) = wire(&planes, facts("broca"), ask("routeless-run")).await;
    assert_eq!(answer["sources"], json!(["desktop_app"]));
    assert_eq!(
        query(&planes, "named-head").await["sources"],
        json!(["desktop_app"])
    );
    let (_, sibling) = wire(&planes, facts("broca"), ask("sibling-run")).await;
    assert_eq!(sibling["sources"], json!(["desktop_app"]));
}

#[tokio::test]
async fn linked_parent_marks_a_run_without_a_cerebellum_route() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    reply(
        &planes,
        &scoped("pasting-head", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"private text pasted into program source"}),
    )
    .await;
    assert_eq!(
        query(&planes, "broca-only-run").await["private_content"],
        false
    );
    let (ty, answer) = wire(
        &planes,
        facts("broca"),
        json!({"method":private_content::QUERY,"params":{
            "scope_ref":"broca-only-run", "parent_scope_ref":"pasting-head"
        }}),
    )
    .await;
    assert_eq!(ty, FrameType::Response);
    assert_eq!(
        answer,
        json!({"private_content":true,"sources":["person_browser"]})
    );
    planes
        .private_content
        .mark("broca-only-run", Retention::Run, Source::DesktopApp)
        .await;
    let (_, answer) = wire(
        &planes,
        facts("broca"),
        json!({"method":private_content::QUERY,"params":{
            "scope_ref":"broca-only-run", "parent_scope_ref":"pasting-head"
        }}),
    )
    .await;
    assert_eq!(answer["sources"], json!(["person_browser", "desktop_app"]));
    assert_eq!(
        query(&planes, "sibling-without-parent").await["private_content"],
        false
    );
}

#[tokio::test]
async fn query_parent_is_optional_but_strictly_validated() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    for (params, field, reason) in [
        (
            json!({"scope_ref":"run","parent_scope_ref":""}),
            "parent_scope_ref",
            "empty_value",
        ),
        (
            json!({"scope_ref":"run","parent_scope_ref":null}),
            "parent_scope_ref",
            "wrong_type",
        ),
        (
            json!({"scope_ref":"run","parent_scope_ref":42}),
            "parent_scope_ref",
            "wrong_type",
        ),
        (
            json!({"scope_ref":"run","parent_scope_ref":"head","extra":true}),
            "extra",
            "unknown_field",
        ),
    ] {
        let (_, answer) = wire(
            &planes,
            facts("broca"),
            json!({"method":private_content::QUERY,"params":params}),
        )
        .await;
        assert_eq!(answer["outcome"], "invalid_request", "{answer}");
        assert_eq!(answer["detail"]["field"], field, "{answer}");
        assert_eq!(answer["detail"]["reason_code"], reason, "{answer}");
    }
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
/// A file-backed store whose writes may take as long as a busy build server's
/// disk needs; only the deadline test keeps the production write deadline.
fn durable_store(path: PathBuf) -> PrivateContent {
    let store = PrivateContent::open(path);
    store.set_write_deadline(std::time::Duration::from_secs(30));
    store
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
    planes.private_content = Arc::new(durable_store(scratch.path()));
    reply(
        &planes,
        &scoped("durable", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"not stored"}),
    )
    .await;
    let bytes = std::fs::read(scratch.path()).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("not stored"));
    planes.private_content.shut_down_cleanly();
    planes.private_content = Arc::new(durable_store(scratch.path()));
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
        Some(&2)
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
async fn repeat_marks_write_only_when_new_or_an_hour_old() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let store = Arc::new(durable_store(scratch.path()));
    planes.private_content = Arc::clone(&store);
    let writes = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&writes);
    *store.write_hook.lock().unwrap() = Some(Arc::new(move || {
        counter.fetch_add(1, Ordering::SeqCst);
    }));
    let now = wall_clock_ms();
    store
        .mark_at("repeat", Retention::Run, Source::PersonBrowser, now)
        .await;
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    let first = std::fs::read(scratch.path()).unwrap();
    store
        .mark_at(
            "repeat",
            Retention::Run,
            Source::PersonBrowser,
            now + 3_599_999,
        )
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        1,
        "an in-hour repeat must not write"
    );
    assert_eq!(std::fs::read(scratch.path()).unwrap(), first);
    assert_eq!(
        query(&planes, "repeat").await["sources"],
        json!(["person_browser"])
    );
    store
        .mark_at(
            "repeat",
            Retention::Run,
            Source::PersonBrowser,
            now + 3_600_000,
        )
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        2,
        "the persisted timestamp, not the last read, sets the hour"
    );
    store
        .mark_at(
            "repeat",
            Retention::Run,
            Source::DesktopApp,
            now + 3_600_001,
        )
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        3,
        "a new source writes immediately"
    );
    store
        .mark_at(
            "other",
            Retention::Run,
            Source::PersonBrowser,
            now + 3_600_002,
        )
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        4,
        "a new scope writes immediately"
    );
    store.shut_down_cleanly_at(now + 3_600_002);
    let reloaded = Arc::new(durable_store(scratch.path()));
    *reloaded.write_hook.lock().unwrap() = Some(Arc::new(|| {
        panic!("reload must retain persisted timestamps")
    }));
    reloaded
        .mark_at(
            "repeat",
            Retention::Run,
            Source::PersonBrowser,
            now + 3_600_003,
        )
        .await;
    assert_eq!(reloaded.health(), "loaded");
}

#[derive(Default)]
struct WriteGate {
    entered: tokio::sync::Notify,
    open: std::sync::Mutex<bool>,
    released: std::sync::Condvar,
}

impl WriteGate {
    fn hold(&self) {
        self.entered.notify_one();
        let guard = self.open.lock().unwrap();
        drop(self.released.wait_while(guard, |open| !*open).unwrap());
    }
}

struct ReleaseWrite(Arc<WriteGate>);
impl Drop for ReleaseWrite {
    fn drop(&mut self) {
        *self.0.open.lock().unwrap() = true;
        self.0.released.notify_all();
    }
}

/// Advances paused time to just past the private-content write deadline.
/// Tokio's timer rounds a deadline up to the next millisecond and the clock
/// down, so advancing by exactly the deadline can leave the timer unfired.
async fn past_write_deadline() {
    tokio::time::advance(std::time::Duration::from_millis(
        budgets::PRIVATE_CONTENT_WRITE.cap_ms + 1,
    ))
    .await;
}

#[tokio::test]
async fn a_stuck_write_releases_the_reply_at_its_deadline_and_fails_closed() {
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(PrivateContent::open(scratch.path()));
    let gate = Arc::new(WriteGate::default());
    let release = ReleaseWrite(Arc::clone(&gate));
    let held = Arc::clone(&gate);
    *planes.private_content.write_hook.lock().unwrap() = Some(Arc::new(move || held.hold()));
    let (tx, mut rx) = mpsc::channel(1);
    let facts = scoped("stuck", ScopeKind::Head);
    let send = private_content::send_reply(
        &planes,
        &facts,
        ReplyPlane::PersonBrowser,
        &tx,
        (PROTOCOL_VERSION, 2, 1, 1),
        json!({"state_text":"private content"}),
    );
    tokio::pin!(send);
    tokio::select! {
        result = &mut send => panic!("reply escaped before write gate entered: {result:?}"),
        _ = gate.entered.notified() => {}
    }
    tokio::time::pause();
    assert!(
        rx.try_recv().is_err(),
        "a needed write is awaited before delivery"
    );
    assert_eq!(
        query(&planes, "stuck").await["sources"],
        json!(["person_browser"])
    );
    past_write_deadline().await;
    tokio::select! {
        biased;
        result = &mut send => result.unwrap(),
        _ = tokio::task::yield_now() => panic!("reply still held after the private-content write deadline"),
    }
    assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
    assert_eq!(planes.private_content.health(), "unreadable");
    assert_eq!(
        query(&planes, "unknown").await["sources"],
        json!(["person_browser", "desktop_app", "signed_in_site"])
    );
    // The first worker still holds the sole writer permit. A second reply
    // waits only its own deadline for it, is then sent, and starts no second
    // blocking write while the disk is stuck. Paused time does not advance on
    // its own while a blocking task runs, so the test advances it explicitly.
    let started = tokio::time::Instant::now();
    let second_facts = scoped("second", ScopeKind::Head);
    let second = reply(
        &planes,
        &second_facts,
        ReplyPlane::DesktopApp,
        json!({"state_text":"second app"}),
    );
    tokio::pin!(second);
    tokio::select! {
        biased;
        _ = &mut second => panic!("the second reply skipped waiting for the writer permit"),
        _ = tokio::task::yield_now() => {}
    }
    past_write_deadline().await;
    second.await;
    assert!(
        started.elapsed()
            >= std::time::Duration::from_millis(budgets::PRIVATE_CONTENT_WRITE.cap_ms),
        "the second reply waits for the writer permit up to its deadline"
    );
    assert_eq!(query(&planes, "unknown").await["private_content"], true);
    drop(release);
    tokio::time::resume();
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while !planes.private_content.write_idle() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        planes.private_content.health(),
        "unreadable",
        "a late write cannot restore trust"
    );
    *planes.private_content.write_hook.lock().unwrap() = None;
    // The repair below must succeed even on a slow build-server disk.
    planes
        .private_content
        .set_write_deadline(std::time::Duration::from_secs(30));
    planes
        .private_content
        .mark("stuck", Retention::Head, Source::PersonBrowser)
        .await;
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
    let document: Value = serde_json::from_slice(&std::fs::read(scratch.path()).unwrap()).unwrap();
    assert!(
        document["heads"]["second"].get("desktop_app").is_some(),
        "the repair wrote the mark whose own write timed out: {document}"
    );
    // A write failed in this process, so even a clean shutdown leaves the
    // in-use marker and the next start answers everything marked.
    planes.private_content.shut_down_cleanly();
    let mut reloaded = isolated_test_planes(&Arc::new(HealthState::new()));
    reloaded.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(query(&reloaded, "unknown").await["private_content"], true);
}

const ALL_SOURCES: [&str; 3] = ["person_browser", "desktop_app", "signed_in_site"];

/// A store that could not be read at startup hides marks it cannot see, and
/// head marks never expire. It is never written over and answers everything
/// marked until it loads, across restarts and however long that takes.
#[tokio::test]
async fn a_corrupt_store_is_never_written_over_and_stays_marked() {
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    reply(
        &planes,
        &scoped("earlier", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"private page"}),
    )
    .await;
    planes.private_content.shut_down_cleanly();
    std::fs::write(scratch.path(), b"not json").unwrap();
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(
        query(&planes, "unknown").await,
        json!({"private_content":true,"sources":ALL_SOURCES})
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
        &scoped("later", ScopeKind::Head),
        ReplyPlane::DesktopApp,
        json!({"state_text":"app"}),
    )
    .await;
    assert_eq!(
        std::fs::read(scratch.path()).unwrap(),
        b"not json",
        "a write must not replace a file whose marks were never read"
    );
    assert_eq!(
        query(&planes, "earlier").await["sources"],
        json!(ALL_SOURCES)
    );
    assert_eq!(planes.private_content.health(), "unreadable");
    planes.private_content.shut_down_cleanly();
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(
        query(&planes, "earlier").await["sources"],
        json!(ALL_SOURCES)
    );
    // Head marks never expire, so no amount of time makes replacing the
    // file safe: a month later it is still untouched and still marked.
    let month_later = wall_clock_ms() + 30 * 24 * 60 * 60 * 1000;
    planes
        .private_content
        .mark_at("fresh", Retention::Head, Source::DesktopApp, month_later)
        .await;
    assert_eq!(std::fs::read(scratch.path()).unwrap(), b"not json");
    assert_eq!(
        planes.private_content.answer(&["unknown"], month_later)["sources"],
        json!(ALL_SOURCES)
    );
    assert_eq!(planes.private_content.health(), "unreadable");
}

/// A store unreadable at startup that reads on a later attempt keeps every
/// mark it held: the retry merges before writing.
#[tokio::test]
async fn a_store_readable_on_retry_keeps_its_marks() {
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    reply(
        &planes,
        &scoped("earlier", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"private page"}),
    )
    .await;
    planes.private_content.shut_down_cleanly();
    let good = std::fs::read(scratch.path()).unwrap();
    std::fs::write(scratch.path(), b"not json").unwrap();
    planes.private_content = Arc::new(durable_store(scratch.path()));
    std::fs::write(scratch.path(), &good).unwrap();
    reply(
        &planes,
        &scoped("later", ScopeKind::Head),
        ReplyPlane::DesktopApp,
        json!({"state_text":"app"}),
    )
    .await;
    assert_eq!(planes.private_content.health(), "loaded");
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
    assert_eq!(
        query(&planes, "earlier").await["sources"],
        json!(["person_browser"])
    );
    assert_eq!(
        query(&planes, "later").await["sources"],
        json!(["desktop_app"])
    );
}

/// Head marks never expire: a head keeps what it read in its context for its
/// whole life. Run marks lapse 24 hours after their latest read.
#[tokio::test]
async fn run_marks_expire_after_a_day_but_head_marks_never_do() {
    let scratch = Scratch::new();
    let now = wall_clock_ms();
    let day = 24 * 60 * 60 * 1000;
    std::fs::write(
        scratch.path(),
        serde_json::to_vec(&json!({"version":2,
            "heads":{"old-head":{"person_browser":now - 30 * day}},
            "runs":{
                "expired":{"person_browser":now - day},
                "recent":{"desktop_app":now}
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(query(&planes, "expired").await["private_content"], false);
    assert_eq!(
        query(&planes, "recent").await["sources"],
        json!(["desktop_app"])
    );
    assert_eq!(
        query(&planes, "old-head").await["sources"],
        json!(["person_browser"])
    );
    planes
        .private_content
        .mark("new", Retention::Run, Source::SignedInSite)
        .await;
    let document: Value = serde_json::from_slice(&std::fs::read(scratch.path()).unwrap()).unwrap();
    assert!(document["runs"].get("expired").is_none(), "{document}");
    assert!(document["heads"].get("old-head").is_some(), "{document}");
}

/// The first stored shape is read as it is and rewritten as version 2, with
/// the floor raised, only by the first write: until then a build that reads
/// only version 1 can still be swapped back in.
#[tokio::test]
async fn a_version_one_store_is_read_and_rewritten_only_by_a_write() {
    let scratch = Scratch::new();
    let now = wall_clock_ms();
    let original =
        serde_json::to_vec(&json!({"version":1,"scopes":{"v1-scope":{"desktop_app":now - 1000}}}))
            .unwrap();
    std::fs::write(scratch.path(), &original).unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(
        query(&planes, "v1-scope").await["sources"],
        json!(["desktop_app"])
    );
    assert_eq!(std::fs::read(scratch.path()).unwrap(), original);
    let floor_file = scratch.0.join("private-content/format-floor.json");
    assert!(!floor_file.exists(), "opening must not raise the floor");
    planes
        .private_content
        .mark("v2-scope", Retention::Run, Source::PersonBrowser)
        .await;
    let document: Value = serde_json::from_slice(&std::fs::read(scratch.path()).unwrap()).unwrap();
    assert_eq!(document["version"], 2);
    assert!(
        document["heads"]["v1-scope"].get("desktop_app").is_some(),
        "{document}"
    );
    assert!(
        document["runs"]["v2-scope"].get("person_browser").is_some(),
        "{document}"
    );
    let floor = cerebellum_core::format_floor::read_floors(&floor_file).unwrap();
    assert_eq!(
        floor.get(private_content::PRIVATE_CONTENT_FORMAT.name),
        Some(&2)
    );
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
            identity: subc_protocol::BindIdentity::new("test", "session"),
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
    planes.private_content = Arc::new(durable_store(scratch.path()));
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
async fn delivered_codemode_image_handle_marks_before_resolve() {
    for (plane, source) in [
        (ReplyPlane::PersonBrowser, "person_browser"),
        (ReplyPlane::DesktopApp, "desktop_app"),
        (ReplyPlane::OwnBrowser, "signed_in_site"),
    ] {
        let planes = isolated_test_planes(&Arc::new(HealthState::new()));
        let capture_facts = run(&planes, "withheld", 2);
        planes
            .signed_in
            .record("fixture", "default", "https://example.com")
            .unwrap();
        let mut image = json!({"image":{"data_b64":"cGl4ZWxz", "mime":"image/png"}});
        mint_image_handle(&planes, &capture_facts, &mut image);
        let handle = image["image_handle"]
            .as_str()
            .expect("minted handle")
            .to_owned();
        let (tx, mut rx) = mpsc::channel(1);
        codemode::CALL_DETAIL
            .scope(
                std::cell::RefCell::new(Some(json!({"action":"screenshot"}))),
                async {
                    private_content::send_reply(
                        &planes,
                        &capture_facts,
                        plane,
                        &tx,
                        (PROTOCOL_VERSION, 2, 1, 1),
                        image,
                    )
                    .await
                    .unwrap();
                },
            )
            .await;
        let delivered: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert!(delivered["image"].get("data_b64").is_none());
        assert_eq!(delivered["image_handle"], handle);
        assert_eq!(query(&planes, "withheld").await["sources"], json!([source]));
        assert_eq!(query(&planes, "head").await["sources"], json!([source]));

        planes.routes.insert(8, 1, facts("broca"));
        handle_route_request(
            request(
                8,
                json!({"method":"image.resolve", "params":{
                    "scope_ref":"withheld", "handle":handle
                }}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let resolved = rx.recv().await.unwrap();
        assert!(resolved.header.flags.is_binary());
        assert!(resolved.body.ends_with(b"pixels"));
        assert_eq!(query(&planes, "withheld").await["sources"], json!([source]));
    }
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
    // The receiving run's read also marks the head both runs belong to, so
    // the original run now inherits it through that head.
    assert_eq!(
        query(&planes, "head").await["sources"],
        json!(["person_browser"])
    );
    let own_runs = || planes.private_content.state_for_test().1;
    assert!(!own_runs().contains(&"original-run".to_owned()));
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
    assert!(
        own_runs().contains(&"original-run".to_owned()),
        "the withdraw answer marks the run that received it"
    );
}

fn marker(scratch: &Scratch) -> PathBuf {
    scratch
        .0
        .join("private-content/private-content-running.json")
}

/// A reply delivered after a failed write must not answer unmarked after a
/// restart that reads a file missing its mark, even after a clean shutdown.
#[tokio::test]
async fn a_failed_write_still_answers_marked_after_a_restart() {
    let scratch = Scratch::new();
    // A directory where the floor file goes makes every write fail.
    std::fs::create_dir_all(scratch.0.join("private-content/format-floor.json")).unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    reply(
        &planes,
        &scoped("delivered", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"private page"}),
    )
    .await;
    assert!(!scratch.path().exists());
    planes.private_content.shut_down_cleanly();
    assert!(marker(&scratch).exists(), "a failed write keeps the marker");
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(
        query(&planes, "delivered").await["sources"],
        json!(ALL_SOURCES)
    );
    assert_eq!(planes.private_content.health(), "unclean_shutdown");
}

/// A process that ends without its shutdown teardown may have delivered marks
/// it never wrote, so the next start answers everything marked for a day.
#[tokio::test]
async fn a_crash_after_successful_writes_still_answers_marked() {
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    reply(
        &planes,
        &scoped("written", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"private page"}),
    )
    .await;
    assert!(scratch.path().exists());
    assert!(marker(&scratch).exists());
    // No shutdown: the process died.
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(
        query(&planes, "unknown").await["sources"],
        json!(ALL_SOURCES)
    );
    let day_later = wall_clock_ms() + 24 * 60 * 60 * 1000 + 1;
    assert_eq!(
        planes.private_content.answer(&["unknown"], day_later)["private_content"],
        false,
        "the window ends a day after the dead process started"
    );
}

/// The module's shutdown teardown removes the marker when every mark reached
/// disk, and the next start answers normally.
#[tokio::test]
async fn a_clean_shutdown_removes_the_marker_and_answers_normally() {
    let scratch = Scratch::new();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    reply(
        &planes,
        &scoped("written", ScopeKind::Head),
        ReplyPlane::PersonBrowser,
        json!({"state_text":"private page"}),
    )
    .await;
    let teardown = ShutdownTeardown::new(
        planes.sessions.clone(),
        None,
        None,
        None,
        planes.user_browser.clone(),
        Arc::clone(&planes.private_content),
    );
    teardown.run_or_join().await;
    assert!(!marker(&scratch).exists());
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert!(marker(&scratch).exists(), "the new process wrote its own");
    assert_eq!(planes.private_content.health(), "loaded");
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
    assert_eq!(
        query(&planes, "written").await["sources"],
        json!(["person_browser"])
    );
}

/// Without its in-use marker a crash could not be noticed, so a process that
/// cannot write one answers everything marked until it can.
#[tokio::test]
async fn a_marker_that_cannot_be_written_fails_closed() {
    let scratch = Scratch::new();
    std::fs::create_dir_all(marker(&scratch).join("blocked")).unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(planes.private_content.health(), "unreadable");
    assert_eq!(
        query(&planes, "unknown").await["sources"],
        json!(ALL_SOURCES)
    );
}

/// Retained replies are found by principal and call key alone, so a reply
/// read through a signed-in profile can be replayed on a route whose own
/// profile is clean. It still marks as a signed-in site.
#[tokio::test]
async fn a_replayed_own_browser_reply_marks_whatever_the_receiving_profile() {
    use journal::call_records::{Begin, DispatchEvidence, ScopeIdentity, Settlement};
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let mut signed_in = scoped("route-a", ScopeKind::Head);
    signed_in.principal = principal("basal");
    signed_in.identity.agent_project_id = "agent-a".into();
    let mut clean = scoped("route-b", ScopeKind::Head);
    clean.principal = principal("basal");
    clean.identity.agent_project_id = "agent-b".into();
    planes.routes.insert(2, 1, signed_in.clone());
    planes.routes.insert(3, 1, clean.clone());
    planes
        .signed_in
        .initialize_profile("agent-a", "default", "uuid-a", true)
        .unwrap();
    planes
        .signed_in
        .record("agent-a", "default", "https://accounts.example.com")
        .unwrap();
    // An explicit record of a fresh profile: known to hold no login.
    planes
        .signed_in
        .initialize_profile("agent-b", "default", "uuid-b", true)
        .unwrap();
    let now = wall_clock_ms();
    let Begin::Execute(ticket) = planes.calls.begin_scoped(
        "reserved:basal",
        "own-replay",
        "conversation",
        signed_in.scope.as_ref().map(ScopeIdentity::from_stamp),
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
        serde_json::to_vec(
            &json!({"outcome":"ok","context":{"profile":"default"},"state_text":"signed-in page"}),
        )
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
    handle_keyed_tool_request(
        request(
            3,
            json!({"name":"browser_use","call_key":"own-replay","arguments":{"action":"snapshot"}}),
        ),
        &tx,
        &planes,
    )
    .await
    .unwrap();
    let delivered: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
    assert!(
        delivered.to_string().contains("signed-in page"),
        "{delivered}"
    );
    assert_eq!(
        query(&planes, "route-b").await["sources"],
        json!(["signed_in_site"])
    );
}

/// The production desktop plane delivers replies that violate their schema
/// unchanged, so app text can sit in any field. Only known content-free
/// refusals stay unmarked.
#[tokio::test]
async fn desktop_replies_mark_unless_a_known_content_free_refusal() {
    for (scope, payload) in [
        (
            "app-list",
            json!({"outcome":"ok","apps":[{"name":"Secret Mail","bundle_id":"com.example.mail"}]}),
        ),
        (
            "undeclared-field",
            json!({"outcome":"ok","window_title":"Inbox - private"}),
        ),
        (
            "refusal-with-app",
            json!({"outcome":"refused","reason":"no_grant","matched_app":"Secret Mail"}),
        ),
        ("no-outcome", json!({"note":"anything"})),
        (
            "allowed-outcome-extra-field",
            json!({"outcome":"screen_locked","reason":"screen_locked","matched_app":"Secret Mail"}),
        ),
        (
            "allowed-outcome-extra-detail",
            json!({"outcome":"permission_missing",
                "detail":{"permission":"accessibility","state":"denied","app":"Secret Mail"}}),
        ),
    ] {
        let planes = isolated_test_planes(&Arc::new(HealthState::new()));
        reply(
            &planes,
            &scoped(scope, ScopeKind::Head),
            ReplyPlane::DesktopApp,
            payload,
        )
        .await;
        assert_eq!(
            query(&planes, scope).await["sources"],
            json!(["desktop_app"]),
            "{scope}"
        );
    }
}

/// A readable login store with no record for the profile does not show the
/// profile is clean: a login the agent made by itself is never recorded.
#[tokio::test]
async fn own_content_from_a_profile_without_a_login_record_marks() {
    let planes = isolated_test_planes(&Arc::new(HealthState::new()));
    let mut facts = scoped("unrecorded", ScopeKind::Head);
    facts.identity.agent_project_id = "unrecorded-agent".into();
    reply(
        &planes,
        &facts,
        ReplyPlane::OwnBrowser,
        json!({"state_text":"page"}),
    )
    .await;
    assert_eq!(
        query(&planes, "unrecorded").await["sources"],
        json!(["signed_in_site"])
    );
}
