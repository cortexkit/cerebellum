use super::*;
use crate::{private_content_marks_tests::query as wire_query, HealthState};
use subc_protocol::{
    scope::{ScopeAttributes, ScopeKind, ScopeStamp},
    Principal, RouteTarget,
};

fn planes() -> Planes {
    Planes::new(Arc::new(HealthState::new()))
}

fn head(scope: &str, agent: &str) -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", scope),
        Some(Principal::Reserved {
            module_id: "prefrontal-core".into(),
        }),
        None,
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
    )
    .with_scope(Some(
        ScopeStamp::new(
            Principal::Reserved {
                module_id: "prefrontal-core".into(),
            },
            scope,
            1,
            ScopeKind::Head,
        )
        .with_attributes(ScopeAttributes::new().with_agent_id(Some(agent.into()))),
    ))
}

#[tokio::test]
async fn moved_agents_new_scope_is_marked_only_after_import() {
    let planes = planes();
    planes.routes.insert(2, 1, head("new-scope", "agent-x"));
    assert_eq!(
        wire_query(&planes, "new-scope").await,
        json!({"private_content":false,"sources":[]})
    );
    assert!(
        planes
            .private_content
            .import_agent("agent-x", &BTreeSet::from([Source::SignedInSite]))
            .await
    );
    assert_eq!(
        wire_query(&planes, "new-scope").await,
        json!({"private_content":true,"sources":["signed_in_site"]})
    );
    planes.routes.insert(3, 1, head("other-scope", "agent-y"));
    assert_eq!(
        wire_query(&planes, "other-scope").await["private_content"],
        false
    );
}

#[tokio::test]
async fn unknown_agent_fails_closed_only_when_agent_marks_exist() {
    let mut planes = planes();
    planes.scopes = Arc::new(crate::scope_watch::ScopeRevocation::with_intervals(
        Duration::from_secs(1),
        Duration::from_millis(5),
    ));
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    assert!(planes.scopes.control.connect(&tx));
    assert_eq!(
        wire_query(&planes, "unknown").await["private_content"],
        false
    );
    assert!(
        rx.try_recv().is_err(),
        "empty agent store must not ask the daemon"
    );
    assert!(
        planes
            .private_content
            .import_agent("empty", &BTreeSet::new())
            .await
    );
    assert_eq!(
        wire_query(&planes, "unknown").await["private_content"],
        false
    );
    assert!(
        rx.try_recv().is_err(),
        "empty imported records carry no private marks"
    );
    planes
        .private_content
        .import_agent("agent-x", &BTreeSet::from([Source::DesktopApp]))
        .await;
    let result = wire_query(&planes, "unknown").await;
    assert_eq!(
        result,
        json!({"private_content":true,"sources":["person_browser","desktop_app","signed_in_site"]})
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&rx.recv().await.unwrap().body).unwrap()["op"],
        "scope.describe"
    );
    assert_eq!(planes.scopes.control.outstanding(), 0);
}

#[tokio::test]
async fn daemon_described_agent_and_named_parent_use_imported_marks() {
    let planes = planes();
    planes
        .private_content
        .import_agent("agent-x", &BTreeSet::from([Source::DesktopApp]))
        .await;
    let (tx, mut rx) = tokio::sync::mpsc::channel(10);
    planes.scopes.control.connect(&tx);
    let lookup = query(&planes, &["new-scope"]);
    let answer = async {
        let frame = rx.recv().await.unwrap();
        let stamp = head("new-scope", "agent-x").scope.unwrap();
        planes.scopes.control.deliver(frame.header.corr, crate::scope_watch::ControlAnswer::Response(json!({"op":"scope.describe","status":"live","owner_synced":true,"owner_configured":true,"daemon_incarnation":"test-daemon","scope_epoch":1,"scope":stamp})));
    };
    let (reply, ()) = tokio::join!(lookup, answer);
    assert_eq!(
        reply,
        json!({"private_content":true,"sources":["desktop_app"]})
    );
    planes.routes.insert(2, 1, head("run", "agent-y"));
    planes.routes.insert(3, 1, head("parent", "agent-x"));
    let response = query(&planes, &["run", "parent"]).await;
    assert_eq!(response["sources"], json!(["desktop_app"]));
}

#[tokio::test]
async fn unattributed_import_projects_to_the_closed_query_source_set() {
    let planes = planes();
    planes.routes.insert(2, 1, head("new", "agent-x"));
    planes
        .private_content
        .import_agent("agent-x", &BTreeSet::from([Source::Unattributed]))
        .await;
    let reply = wire_query(&planes, "new").await;
    assert_eq!(
        serde_json::to_string(&reply).unwrap(),
        r#"{"private_content":true,"sources":["person_browser","desktop_app","signed_in_site"]}"#
    );
    assert_eq!(
        planes.private_content.export_agent("agent-x"),
        BTreeSet::from([Source::Unattributed])
    );
}

#[tokio::test]
async fn legacy_marks_overmark_exports_but_other_agents_attributed_marks_do_not() {
    let store = Arc::new(PrivateContent::in_memory());
    store.record_agent(
        &[("other".into(), Retention::Head)],
        &[Source::SignedInSite],
        1,
        Some("other-agent"),
    );
    assert!(store.export_agent("agent-x").is_empty());
    store
        .mark("legacy", Retention::Head, Source::PersonBrowser)
        .await;
    store.record_agent(
        &[("legacy".into(), Retention::Head)],
        &[Source::PersonBrowser],
        2,
        Some("other-agent"),
    );
    assert_eq!(
        store.export_agent("agent-x"),
        BTreeSet::from([Source::Unattributed])
    );
    assert_eq!(
        store.export_agent("other-agent"),
        BTreeSet::from([Source::SignedInSite, Source::Unattributed])
    );
}

#[test]
fn conflicting_scope_attribution_never_erases_an_agents_provenance() {
    let store = PrivateContent::in_memory();
    let target = [("reused-scope".into(), Retention::Head)];
    store.record_agent(&target, &[Source::PersonBrowser], 1, Some("agent-x"));
    store.record_agent(&target, &[Source::PersonBrowser], 2, Some("agent-y"));
    assert_eq!(
        store.export_agent("agent-x"),
        BTreeSet::from([Source::Unattributed])
    );
    assert_eq!(
        store.export_agent("agent-y"),
        BTreeSet::from([Source::Unattributed])
    );
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../../target/scratch/marks-move-{}-{}",
            std::process::id(),
            TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        cerebellum_core::private_fs::create_dir_all(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn format_floor_stays_two_until_the_first_agent_attributed_write() {
    let scratch = Scratch::new();
    let path = scratch.0.join(FILE_NAME);
    let v2 = br#"{"version":2,"heads":{"legacy":{"person_browser":1}},"runs":{}}"#;
    fs::write(&path, v2).unwrap();
    FormatFloor::at(scratch.0.join("format-floor.json"))
        .raise(DurableFormat::new("private-content-marks", 2))
        .unwrap();
    let store = Arc::new(PrivateContent::open_at(path.clone(), 1));
    store.set_write_deadline(crate::test_support::HANG_GUARD);
    assert_eq!(fs::read(&path).unwrap(), v2);
    let floor = || {
        cerebellum_core::format_floor::read_floors(&scratch.0.join("format-floor.json")).unwrap()
            ["private-content-marks"]
    };
    assert_eq!(floor(), 2);
    store
        .mark("still-legacy", Retention::Head, Source::DesktopApp)
        .await;
    assert_eq!(floor(), 2);
    let failures = store
        .record_agent(
            &[("new".into(), Retention::Head)],
            &[Source::SignedInSite],
            2,
            Some("agent-x"),
        )
        .unwrap();
    assert!(store.write(failures, 2).await);
    assert_eq!(floor(), 3);
    assert_eq!(
        load(&path).unwrap().unwrap().heads["legacy"][&Source::PersonBrowser].agent(),
        None
    );
    store.shut_down_cleanly_at(2);
    let reloaded = Arc::new(PrivateContent::open_at(path, 2));
    assert_eq!(
        reloaded.export_agent("agent-x"),
        BTreeSet::from([Source::SignedInSite, Source::Unattributed])
    );
}

#[tokio::test]
async fn imported_marks_persist_add_only_without_expiry_and_refuse_failed_storage() {
    let scratch = Scratch::new();
    let path = scratch.0.join(FILE_NAME);
    let store = Arc::new(PrivateContent::open_at(path.clone(), 1));
    store.set_write_deadline(crate::test_support::HANG_GUARD);
    assert!(
        store
            .import_agent("agent-x", &BTreeSet::from([Source::PersonBrowser]))
            .await
    );
    assert!(
        store
            .import_agent("agent-x", &BTreeSet::from([Source::DesktopApp]))
            .await
    );
    store.shut_down_cleanly_at(1);
    let reloaded = Arc::new(PrivateContent::open_at(path.clone(), 1 + RETENTION_MS * 5));
    assert_eq!(
        reloaded.export_agent("agent-x"),
        BTreeSet::from([Source::PersonBrowser, Source::DesktopApp])
    );
    fs::remove_file(&path).unwrap();
    fs::create_dir(&path).unwrap();
    assert!(
        !reloaded
            .import_agent("agent-x", &BTreeSet::from([Source::SignedInSite]))
            .await
    );
}
