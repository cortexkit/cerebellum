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
        .mark("broca-only-run", Source::DesktopApp)
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
    store.mark_at("repeat", Source::PersonBrowser, now).await;
    assert_eq!(writes.load(Ordering::SeqCst), 1);
    let first = std::fs::read(scratch.path()).unwrap();
    store
        .mark_at("repeat", Source::PersonBrowser, now + 3_599_999)
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
        .mark_at("repeat", Source::PersonBrowser, now + 3_600_000)
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        2,
        "the persisted timestamp, not the last read, sets the hour"
    );
    store
        .mark_at("repeat", Source::DesktopApp, now + 3_600_001)
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        3,
        "a new source writes immediately"
    );
    store
        .mark_at("other", Source::PersonBrowser, now + 3_600_002)
        .await;
    assert_eq!(
        writes.load(Ordering::SeqCst),
        4,
        "a new scope writes immediately"
    );
    let reloaded = Arc::new(durable_store(scratch.path()));
    *reloaded.write_hook.lock().unwrap() = Some(Arc::new(|| {
        panic!("reload must retain persisted timestamps")
    }));
    reloaded
        .mark_at("repeat", Source::PersonBrowser, now + 3_600_003)
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
        .mark("stuck", Source::PersonBrowser)
        .await;
    assert_eq!(query(&planes, "unknown").await["private_content"], false);
    let mut reloaded = isolated_test_planes(&Arc::new(HealthState::new()));
    reloaded.private_content = Arc::new(durable_store(scratch.path()));
    assert_eq!(
        query(&reloaded, "second").await["sources"],
        json!(["desktop_app"])
    );
}

#[tokio::test]
async fn corrupt_store_fails_closed_until_a_successful_write_repairs_it() {
    let scratch = Scratch::new();
    std::fs::write(scratch.path(), b"not json").unwrap();
    let mut planes = isolated_test_planes(&Arc::new(HealthState::new()));
    planes.private_content = Arc::new(durable_store(scratch.path()));
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
    planes.private_content = Arc::new(durable_store(scratch.path()));
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
    planes.private_content = Arc::new(durable_store(scratch.path()));
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
