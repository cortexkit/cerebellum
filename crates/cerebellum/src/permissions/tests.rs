use super::*;
use crate::agent_grants::{
    AgentGrantStorage, AgentGrantStoreError, AgentGrantStoreState, AgentGrants, GrantDemand,
    InMemoryAgentGrantStorage, LegacyGrantSource,
};
use crate::browser_standing_grants::WallClock;
use crate::test_support::HANG_GUARD;
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use subc_protocol::{FrameType, Principal, RouteTarget};
use tokio::sync::mpsc;

mod durable;
mod labels;
mod retained;
mod routes;

const MACHINE: &str = "fixture-machine";
const NOW: u64 = 1_060_000;
const END: u64 = 2_800_000;

struct Clock(AtomicU64);
impl WallClock for Clock {
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}
struct Empty;
impl LegacyGrantSource for Empty {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
        Ok(AgentGrantStoreState::default())
    }
}
struct Apps;
impl management::TargetResolver for Apps {
    fn resolve(&self, bundle: &str) -> TargetResolution {
        TargetResolution::Resolved(ProcessGrant {
            pid: 42,
            bundle_identity: bundle.into(),
            process_generation_evidence: "fixture".into(),
        })
    }
    fn display_name(&self, process: &ProcessGrant) -> Option<String> {
        Some(
            match process.bundle_identity.as_str() {
                "com.apple.TextEdit" => "TextEdit",
                "com.apple.Preview" => "Preview",
                _ => "Editor",
            }
            .into(),
        )
    }
}
fn head(agent: &str) -> GrantHolder {
    GrantHolder::Head {
        agent_id: agent.into(),
    }
}
fn worker(scope: &str) -> GrantHolder {
    GrantHolder::Worker {
        agent_id: "agent-alf".into(),
        scope_ref: scope.into(),
    }
}
fn row(
    id: &str,
    holder: GrantHolder,
    subject: GrantSubject,
    expires: Option<u64>,
    card: &str,
) -> AgentGrant {
    let browser = matches!(
        subject,
        GrantSubject::Domain(_) | GrantSubject::Origin(_) | GrantSubject::AllSites
    );
    AgentGrant {
        id: id.into(),
        holder,
        subject,
        browser_target: browser.then_some(BrowserTarget::AgentProfile),
        machine_uuid: MACHINE.into(),
        granted_at_ms: 1_000_000,
        expires_at_ms: expires,
        card_ref: Some(card.into()),
        max_level: 3,
        hazards: vec![],
        team_id: None,
        designated_requirement: Some("fixture signer".into()),
    }
}
fn corpus_rows() -> Vec<AgentGrant> {
    vec![
        row(
            "grt_01",
            head("agent-alf"),
            GrantSubject::App("com.apple.TextEdit".into()),
            Some(END),
            "el_1",
        ),
        row(
            "grt_02",
            head("agent-alf"),
            GrantSubject::WholeComputer,
            None,
            "el_2",
        ),
        row(
            "grt_03",
            head("agent-alf"),
            GrantSubject::Domain("github.com".into()),
            None,
            "el_3",
        ),
        row(
            "grt_04",
            head("agent-alf"),
            GrantSubject::AllSites,
            Some(END),
            "el_4",
        ),
        row(
            "grt_05",
            worker("scope:wkr-7f3a"),
            GrantSubject::App("com.apple.Preview".into()),
            Some(END),
            "el_5",
        ),
    ]
}
fn fixture(
    rows: Vec<AgentGrant>,
) -> (
    Planes,
    Arc<AgentGrants>,
    Arc<Clock>,
    Arc<InMemoryAgentGrantStorage>,
) {
    let backend = Arc::new(InMemoryAgentGrantStorage::default());
    backend
        .save(&AgentGrantStoreState {
            grants: rows,
            ..AgentGrantStoreState::default()
        })
        .unwrap();
    let clock = Arc::new(Clock(AtomicU64::new(NOW)));
    let store = Arc::new(
        AgentGrants::open(backend.clone(), &Empty, Some(MACHINE.into())).with_clock(clock.clone()),
    );
    let mut planes = Planes::with_browser_config_journaling(
        Arc::new(crate::HealthState::default()),
        None,
        crate::JournalPersistence::Isolated,
    );
    planes.management =
        Arc::new(management::ManagementPlane::new(Arc::new(Apps)).with_agent_grants(store.clone()));
    (planes, store, clock, backend)
}
fn facts(principal: Principal) -> AcceptedBindFacts {
    AcceptedBindFacts::from_bind(
        &subc_protocol::BindIdentity::new("test", "session"),
        Some(principal),
        None,
        None,
        &RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        },
    )
}
fn aggregator() -> AcceptedBindFacts {
    facts(Principal::Reserved {
        module_id: "cingulate".into(),
    })
}
async fn call(
    planes: &Planes,
    facts: AcceptedBindFacts,
    method: &str,
    params: Value,
) -> (FrameType, Value) {
    planes.routes.insert(8, 1, facts);
    let request = Frame::build(
        FrameType::Request,
        crate::control_flags(),
        8,
        1,
        1,
        serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
    )
    .unwrap();
    let (tx, mut rx) = mpsc::channel(8);
    crate::handle_route_request(request, &tx, planes)
        .await
        .unwrap();
    let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    (
        reply.header.ty,
        serde_json::from_slice(&reply.body).unwrap(),
    )
}
fn vector(name: &str) -> Value {
    serde_json::from_slice(
        &std::fs::read(format!(
            "{}/tests/vectors/permissions-v1/{name}.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
}

fn served_list_reply() -> Value {
    serde_json::from_str(include_str!(
        "../../tests/goldens/permissions-provider-list.json"
    ))
    .unwrap()
}

fn assert_vector(name: &str, mut expected: Value, ty: FrameType, actual: Value) {
    let field = if expected.get("error").is_some() {
        "error"
    } else {
        "reply"
    };
    assert_eq!(
        ty,
        if field == "error" {
            FrameType::Error
        } else {
            FrameType::Response
        }
    );
    expected[field] = actual;
    let mut canonical = std::fs::read(format!(
        "{}/tests/vectors/permissions-v1/{name}.jcs",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    if name.starts_with("provider-list") {
        // The frozen contract examples omit allowed actions in site labels.
        // Keep their shape, lifetimes and provenance pinned, but compare the
        // display text against a literal served-reply golden instead.
        let mut original: Value = serde_json::from_slice(&canonical).unwrap();
        let served = served_list_reply();
        for row in original["reply"]["grants"].as_array_mut().unwrap() {
            let rendered = served["grants"]
                .as_array()
                .unwrap()
                .iter()
                .find(|rendered| rendered["id"] == row["id"])
                .unwrap();
            row["subject_label"] = rendered["subject_label"].clone();
        }
        canonical = serde_json::to_vec(&original).unwrap();
    }
    if name == "provider-revoke-refused-agent" {
        // Only reserved:cingulate may call the provider. This frozen vector's
        // message still says "or the local operator's direct route", so compare
        // all other bytes and assert the truthful refusal wording separately.
        assert_eq!(
            expected["error"]["message"],
            "permissions operations need reserved:cingulate"
        );
        let mut original: Value = serde_json::from_slice(&canonical).unwrap();
        original["error"].as_object_mut().unwrap().remove("message");
        expected["error"].as_object_mut().unwrap().remove("message");
        canonical = serde_json::to_vec(&original).unwrap();
    }
    assert_eq!(serde_json::to_vec(&expected).unwrap(), canonical, "{name}");
}
async fn run_vector(name: &str) {
    let expected = vector(name);
    let (planes, store, clock, _) = fixture(corpus_rows());
    clock
        .0
        .store(expected["now_ms"].as_u64().unwrap(), Ordering::SeqCst);
    if name.ends_with("after-upgrade") {
        let mut upgraded = corpus_rows().remove(0);
        upgraded.granted_at_ms = clock.now_ms();
        upgraded.expires_at_ms = None;
        upgraded.card_ref = Some("el_6".into());
        assert_eq!(store.upsert(upgraded, clock.now_ms()).unwrap(), "grt_01");
    }
    let caller = if name.ends_with("refused-agent") {
        facts(Principal::Reserved {
            module_id: "plexus".into(),
        })
    } else {
        aggregator()
    };
    let (ty, reply) = call(
        &planes,
        caller,
        expected["method"].as_str().unwrap(),
        expected["request"].clone(),
    )
    .await;
    assert_vector(name, expected, ty, reply);
}
macro_rules! corpus_test {
    ($test:ident, $name:literal) => {
        #[tokio::test]
        async fn $test() {
            run_vector($name).await;
        }
    };
}
corpus_test!(provider_list, "provider-list");
corpus_test!(provider_list_after_expiry, "provider-list-after-expiry");
corpus_test!(provider_list_after_upgrade, "provider-list-after-upgrade");
corpus_test!(provider_revoke_revoked, "provider-revoke-revoked");
corpus_test!(provider_revoke_not_found, "provider-revoke-not-found");
corpus_test!(provider_revoke_expired, "provider-revoke-expired");
corpus_test!(
    provider_revoke_refused_agent,
    "provider-revoke-refused-agent"
);

#[tokio::test]
async fn provider_revoke_stopping() {
    let (planes, store, _, _) = fixture(corpus_rows());
    let cancel = crate::CancelHandle::pending();
    let used = store
        .authorize(&head("agent-alf"), GrantDemand::Takeover)
        .unwrap();
    let ready = tokio::sync::Notify::new();
    let work = crate::grant_enforcement::scope(cancel.clone(), async {
        let takeover = planes
            .management
            .computer_grants()
            .require_takeover_dispatch(
                &crate::computer_grants::ConsentContext::without_carrier(
                    crate::computer_grants::GrantCaller::new(
                        "conversation".into(),
                        "agent-alf".into(),
                        true,
                    ),
                ),
                &cancel,
            )
            .await
            .unwrap();
        ready.notify_one();
        cancel.cancelled().await;
        assert!(!takeover.admission().commit());
        assert!(!used.is_live());
        assert!(!crate::grant_enforcement::commit_current());
    });
    let revoke = async {
        ready.notified().await;
        let expected = vector("provider-revoke-stopping");
        let (ty, reply) = call(&planes, aggregator(), REVOKE, expected["request"].clone()).await;
        assert_vector("provider-revoke-stopping", expected, ty, reply);
    };
    tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(work, revoke);
    })
    .await
    .unwrap();
    assert!(!store.is_in_use("grt_02"));
    assert_eq!(
        call(&planes, aggregator(), REVOKE, json!({"id":"grt_02"}))
            .await
            .1,
        json!({"outcome":"not_found"})
    );
}

#[tokio::test]
async fn provider_refuses_direct_and_every_non_aggregator_before_reading_or_mutating() {
    let (planes, _, _, backend) = fixture(corpus_rows());
    for caller in [
        facts(Principal::Direct),
        facts(Principal::Reserved {
            module_id: "callosum".into(),
        }),
        facts(Principal::Reserved {
            module_id: "prefrontal-core".into(),
        }),
    ] {
        for method in [LIST, REVOKE] {
            let before = backend.load().unwrap();
            let (ty, reply) = call(&planes, caller.clone(), method, json!({"id":"grt_01"})).await;
            assert_eq!(ty, FrameType::Error);
            assert_eq!(reply["code"], "permissions_operator_required");
            assert_eq!(backend.load().unwrap(), before);
        }
    }
}

#[tokio::test]
async fn provider_filters_agent_machine_and_target_labels_without_leaking_worker_keys() {
    let mut rows = corpus_rows();
    rows.push(row(
        "other",
        head("other"),
        GrantSubject::WholeComputer,
        None,
        "card",
    ));
    let mut foreign = row(
        "foreign",
        head("agent-alf"),
        GrantSubject::WholeComputer,
        None,
        "card",
    );
    foreign.machine_uuid = "foreign-machine".into();
    rows.push(foreign);
    let mut user = row(
        "user",
        worker("scope:two"),
        GrantSubject::Domain("github.com".into()),
        Some(END),
        "user-card",
    );
    user.browser_target = Some(BrowserTarget::UserBrowser);
    rows.push(user);
    let (planes, store, _, _) = fixture(rows);
    let (_, reply) = call(&planes, aggregator(), LIST, json!({"agent_id":"agent-alf"})).await;
    assert_eq!(
        reply["grants"]
            .as_array()
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["grt_01", "grt_02", "grt_03", "grt_04", "grt_05", "user"]
    );
    let user = reply["grants"].as_array().unwrap().last().unwrap();
    assert_eq!(
        user["subject_label"],
        "github.com: read, click, type and make reversible changes in the person's Chrome"
    );
    assert_eq!(
        user["scope_label"],
        "the site github.com in the person's Chrome"
    );
    assert_eq!(
        call(&planes, aggregator(), REVOKE, json!({"id":"foreign"}))
            .await
            .1,
        json!({"outcome":"not_found"})
    );
    assert_eq!(store.live_rows(Some("other"), NOW).unwrap().len(), 1);
    assert_eq!(
        call(&planes, aggregator(), LIST, json!({"agent_id":"missing"}))
            .await
            .1,
        json!({"grants":[]})
    );
}

#[tokio::test]
async fn provider_rejects_invalid_parameters_without_writing() {
    let (planes, _, _, backend) = fixture(corpus_rows());
    for (method, params, field, reason) in [
        (LIST, json!(false), "params", "wrong_type"),
        (LIST, json!({"other":1}), "other", "unknown_field"),
        (LIST, json!({"agent_id":""}), "agent_id", "empty_value"),
        (LIST, json!({"agent_id":7}), "agent_id", "wrong_type"),
        (REVOKE, json!({}), "id", "missing_field"),
        (REVOKE, json!({"id":""}), "id", "empty_value"),
        (REVOKE, json!({"id":null}), "id", "wrong_type"),
        (
            REVOKE,
            json!({"id":"grt_01","authority":"operator"}),
            "authority",
            "unknown_field",
        ),
    ] {
        let before = backend.load().unwrap();
        let (_, reply) = call(&planes, aggregator(), method, params).await;
        assert_eq!(reply["outcome"], "invalid_request");
        assert_eq!(reply["detail"]["field"], field);
        assert_eq!(reply["detail"]["reason_code"], reason);
        assert_eq!(backend.load().unwrap(), before);
    }
}

#[test]
fn provider_capability_and_management_kinds_are_declared() {
    let manifest = crate::manifest::build("cerebellum");
    assert!(manifest
        .capabilities
        .unwrap()
        .provides
        .contains(&CAPABILITY.to_string()));
    let subc_protocol::manifest::ProviderRole::ManagementSurface { operations, .. } = manifest
        .provides
        .iter()
        .find(|role| {
            matches!(
                role,
                subc_protocol::manifest::ProviderRole::ManagementSurface { .. }
            )
        })
        .unwrap()
    else {
        unreachable!()
    };
    for (name, kind) in [
        (
            LIST,
            subc_protocol::manifest::ManagementOperationKind::Query,
        ),
        (
            REVOKE,
            subc_protocol::manifest::ManagementOperationKind::Mutate,
        ),
    ] {
        assert_eq!(
            operations.iter().find(|op| op.name == name).unwrap().kind,
            kind
        );
        assert!(crate::dispatchable_management_operation(name));
        assert!(crate::management::call_limits(name).is_some());
        assert!(crate::dispatchable_tool(name).is_none());
    }
}

#[tokio::test]
async fn provider_revoke_stops_only_the_authorizing_app_row() {
    let mut rows = corpus_rows();
    rows[0].designated_requirement = Some("certificate leaf[subject.OU] = \"FIXTURE001\"".into());
    let (planes, store, _, _) = fixture(rows);
    let cancel = crate::CancelHandle::pending();
    let ready = tokio::sync::Notify::new();
    let work = crate::grant_enforcement::scope(cancel.clone(), async {
        let admission = planes
            .management
            .computer_grants()
            .require(
                &crate::computer_grants::GrantNeed::App {
                    bundle_identity: "com.apple.TextEdit".into(),
                    display_name: "TextEdit".into(),
                    code: Arc::new(crate::computer_grants::SignedByFixtureTeam),
                },
                &crate::computer_grants::ConsentContext::without_carrier(
                    crate::computer_grants::GrantCaller::new(
                        "conversation".into(),
                        "agent-alf".into(),
                        true,
                    ),
                ),
                &cancel,
            )
            .await
            .unwrap();
        ready.notify_one();
        cancel.cancelled().await;
        assert!(!admission.commit());
        assert!(!crate::grant_enforcement::commit_current());
    });
    let revoke = async {
        ready.notified().await;
        assert!(store.is_in_use("grt_01"));
        assert_eq!(
            call(&planes, aggregator(), REVOKE, json!({"id":"grt_02"}))
                .await
                .1,
            json!({"outcome":"revoked"})
        );
        assert!(
            !cancel.is_cancelled(),
            "the app row still authorizes this action"
        );
        assert_eq!(
            call(&planes, aggregator(), REVOKE, json!({"id":"grt_01"}))
                .await
                .1,
            json!({"outcome":"revoked","stopping":true})
        );
    };
    tokio::time::timeout(HANG_GUARD, async {
        tokio::join!(work, revoke);
    })
    .await
    .unwrap();
    assert!(!store.is_in_use("grt_01"));
}

struct RejectWrites(AgentGrantStoreState);
impl AgentGrantStorage for RejectWrites {
    fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
        Ok(Some(self.0.clone()))
    }
    fn save(&self, _: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
        Err(AgentGrantStoreError::WriteFailed {
            detail: "fixture read-only directory".into(),
        })
    }
}

#[tokio::test]
async fn provider_reports_unreadable_and_write_failed_stores_as_errors() {
    let (mut planes, _, _, _) = fixture(corpus_rows());
    let unavailable = Arc::new(AgentGrants::unavailable(
        AgentGrantStoreError::UnknownVersion { found: 99 },
    ));
    planes.management =
        Arc::new(management::ManagementPlane::new(Arc::new(Apps)).with_agent_grants(unavailable));
    for method in [LIST, REVOKE] {
        let (ty, reply) = call(
            &planes,
            aggregator(),
            method,
            if method == LIST {
                json!({})
            } else {
                json!({"id":"grt_01"})
            },
        )
        .await;
        assert_eq!(ty, FrameType::Error);
        assert_eq!(reply["code"], "permissions_unavailable");
    }
    let store = Arc::new(
        AgentGrants::open(
            Arc::new(RejectWrites(AgentGrantStoreState {
                grants: corpus_rows(),
                ..AgentGrantStoreState::default()
            })),
            &Empty,
            Some(MACHINE.into()),
        )
        .with_clock(Arc::new(Clock(AtomicU64::new(NOW)))),
    );
    planes.management =
        Arc::new(management::ManagementPlane::new(Arc::new(Apps)).with_agent_grants(store.clone()));
    let (ty, reply) = call(&planes, aggregator(), REVOKE, json!({"id":"grt_01"})).await;
    assert_eq!(ty, FrameType::Error);
    assert_eq!(reply["code"], "permissions_unavailable");
    assert_eq!(store.live_rows(None, NOW).unwrap(), corpus_rows());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn provider_does_not_report_finished_work_as_stopping_after_a_slow_revoke() {
    struct SlowWrite {
        writing: Arc<tokio::sync::Notify>,
        resume: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl AgentGrantStorage for SlowWrite {
        fn load(&self) -> Result<Option<AgentGrantStoreState>, AgentGrantStoreError> {
            Ok(Some(AgentGrantStoreState {
                grants: corpus_rows(),
                ..AgentGrantStoreState::default()
            }))
        }
        fn save(&self, _: &AgentGrantStoreState) -> Result<(), AgentGrantStoreError> {
            self.writing.notify_one();
            self.resume.lock().unwrap().recv().unwrap();
            Ok(())
        }
    }
    let writing = Arc::new(tokio::sync::Notify::new());
    let (resume, receiver) = std::sync::mpsc::channel();
    let store = Arc::new(
        AgentGrants::open(
            Arc::new(SlowWrite {
                writing: writing.clone(),
                resume: std::sync::Mutex::new(receiver),
            }),
            &Empty,
            Some(MACHINE.into()),
        )
        .with_clock(Arc::new(Clock(AtomicU64::new(NOW)))),
    );
    let used = store
        .authorize(&head("agent-alf"), GrantDemand::Takeover)
        .unwrap();
    let (ready, started) = tokio::sync::oneshot::channel();
    let (finish, finished) = tokio::sync::oneshot::channel();
    let action = tokio::spawn(crate::grant_enforcement::scope(
        crate::CancelHandle::pending(),
        async move {
            crate::grant_enforcement::track(&used);
            ready.send(()).unwrap();
            finished.await.unwrap();
        },
    ));
    started.await.unwrap();
    let revoke = std::thread::spawn(move || store.revoke_with_stopping("grt_02", NOW));
    tokio::time::timeout(HANG_GUARD, writing.notified())
        .await
        .unwrap();
    finish.send(()).unwrap();
    action.await.unwrap();
    resume.send(()).unwrap();
    assert_eq!(revoke.join().unwrap().unwrap(), (true, false));
}
