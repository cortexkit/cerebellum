//! An answerable Cingulate route for handler tests, shared by consent flows.

use super::*;
use crate::cingulate_client::desk::RegistryStore;
use crate::cingulate_client::route::{BoxFuture, CallError, CingulateOpener, CingulateRoute};
use crate::cingulate_client::wire;
use crate::cingulate_client::ScriptedAnswer;
use crate::test_support::HANG_GUARD;
use crate::{Frame, FrameType, Planes};
use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
use subc_protocol::{Flags, Principal, Priority, PROTOCOL_VERSION};

#[derive(Default)]
struct ServiceState {
    defer_awaits: bool,
    requests: Vec<Value>,
    consumed: usize,
    records: HashMap<String, Value>,
    errors: HashMap<String, CallError>,
    calls: Vec<(String, Value)>,
}

/// Holds await calls until the test answers or their requested park elapses.
/// No question is sent through the inbound route's writer.
pub(crate) struct CardService {
    state: Mutex<ServiceState>,
    changed: tokio::sync::Notify,
    root: PathBuf,
}

impl CardService {
    pub(crate) fn new() -> Arc<Self> {
        Self::new_in(std::env::temp_dir())
    }

    fn new_in(parent: PathBuf) -> Arc<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(1);
        let root = parent.join(format!(
            "computer-cards-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&root).unwrap();
        Arc::new(Self {
            state: Mutex::new(ServiceState::default()),
            changed: tokio::sync::Notify::new(),
            root,
        })
    }

    pub(crate) fn install(planes: Planes, channel: u16, epoch: u32) -> Planes {
        Self::install_in(planes, channel, epoch, std::env::temp_dir())
    }

    pub(crate) fn install_in(planes: Planes, channel: u16, epoch: u32, parent: PathBuf) -> Planes {
        let service = Self::new_in(parent);
        let mut planes = planes.with_cingulate(
            Arc::new(service.clone()),
            Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
                service.root.join("registry.json"),
            )),
        );
        if let Some(facts) = planes.routes.get(channel, epoch) {
            if facts.flow_id.is_none() {
                let stamp = stamp(&facts.identity.agent_project_id);
                planes
                    .routes
                    .insert(channel, epoch, facts.with_scope(Some(stamp)));
            }
        }
        planes.consent_test = Some(service);
        planes
    }

    /// Read a raised card's params. The synthetic frame is only an inspection
    /// wrapper for older tests; it is never sent to a route writer.
    pub(crate) async fn card(&self, channel: u16, epoch: u32) -> Frame {
        self.card_with_timeout(channel, epoch, HANG_GUARD).await
    }

    pub(crate) async fn card_with_timeout(
        &self,
        channel: u16,
        epoch: u32,
        bound: Duration,
    ) -> Frame {
        let end = tokio::time::Instant::now() + bound;
        loop {
            let changed = self.changed.notified();
            let params = {
                let mut state = lock(&self.state);
                let index = state.consumed;
                state.requests.get(index).cloned().map(|params| {
                    state.consumed += 1;
                    (index + 1, params)
                })
            };
            if let Some((corr, params)) = params {
                return Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Request,
                    Flags::new(false, Priority::Interactive, false),
                    channel,
                    epoch,
                    corr as u64,
                    serde_json::to_vec(&json!({"id":format!("el_test_{corr}"), "params":params}))
                        .unwrap(),
                )
                .unwrap();
            }
            tokio::time::timeout_at(end, changed)
                .await
                .expect("Cingulate received no card");
        }
    }

    pub(crate) fn answer(&self, corr: u64, outcome: ScriptedAnswer) -> bool {
        self.answer_id(&format!("el_test_{corr}"), outcome)
    }

    pub(crate) fn answer_id(&self, id: &str, outcome: ScriptedAnswer) -> bool {
        let mut state = lock(&self.state);
        if !state.records.contains_key(id) {
            return false;
        }
        match outcome {
            ScriptedAnswer::Answered(body) => {
                state.records.insert(id.into(), json!({"elicitation_id":id,"state":"answered","answered_choice_id":body["decision"]}));
            }
            ScriptedAnswer::NoAnswer => {
                state
                    .records
                    .insert(id.into(), json!({"elicitation_id":id,"state":"expired"}));
            }
            ScriptedAnswer::NotPutToAnyone => {
                state.errors.insert(
                    id.into(),
                    crate::cingulate_client::double::refusal("elicitation_requester_refused"),
                );
            }
            ScriptedAnswer::Undeliverable => {
                state
                    .errors
                    .insert(id.into(), CallError::Transport { code: None });
            }
        }
        drop(state);
        self.changed.notify_waiters();
        true
    }

    pub(crate) fn defer_awaits(&self) {
        lock(&self.state).defer_awaits = true;
    }

    pub(crate) fn calls(&self) -> Vec<(String, Value)> {
        lock(&self.state).calls.clone()
    }
}

impl Drop for CardService {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

pub(crate) fn stamp(agent: &str) -> ScopeStamp {
    ScopeStamp::new(
        Principal::Reserved {
            module_id: "prefrontal-core".into(),
        },
        "card-tests",
        1,
        ScopeKind::Head,
    )
    .with_attributes(
        ScopeAttributes::new()
            .with_agent_id(Some(agent.into()))
            .with_delegates(true),
    )
    .with_owner_authorized(true)
}

impl CingulateOpener for Arc<CardService> {
    fn open<'a>(
        &'a self,
        _: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        Box::pin(async { Ok(Box::new(ServiceRoute(self.clone())) as Box<dyn CingulateRoute>) })
    }
}

struct ServiceRoute(Arc<CardService>);
impl CingulateRoute for ServiceRoute {
    fn features(&self) -> Option<crate::cingulate_client::features::CingulateFeatures> {
        Some(crate::cingulate_client::features::CingulateFeatures {
            option_group: true,
            single_use: false,
            no_expiry: false,
        })
    }
    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: Value,
    ) -> BoxFuture<'a, Result<Value, CallError>> {
        Box::pin(async move {
            lock(&self.0.state)
                .calls
                .push((method.into(), params.clone()));
            let id = params["elicitation_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            match method {
                wire::CONSENT_REQUEST => {
                    let mut state = lock(&self.0.state);
                    let id = format!("el_test_{}", state.requests.len() + 1);
                    state.requests.push(params);
                    state
                        .records
                        .insert(id.clone(), json!({"elicitation_id":id,"state":"pending"}));
                    drop(state);
                    self.0.changed.notify_waiters();
                    Ok(json!({"elicitation_id":id}))
                }
                wire::CONSENT_AWAIT => {
                    let end = tokio::time::Instant::now()
                        + Duration::from_millis(params["timeout_ms"].as_u64().unwrap());
                    loop {
                        let changed = self.0.changed.notified();
                        {
                            let state = lock(&self.0.state);
                            if let Some(error) = state.errors.get(&id) {
                                return Err(error.clone());
                            }
                            let record = state.records[&id].clone();
                            if (!state.defer_awaits && record["state"] != "pending")
                                || tokio::time::Instant::now() >= end
                            {
                                return Ok(record);
                            }
                        }
                        let _ = tokio::time::timeout_at(end, changed).await;
                    }
                }
                wire::CONSENT_GET
                | wire::CONSENT_DETACH
                | wire::CONSENT_WITHDRAW
                | wire::CONSENT_REPORT_EXECUTION => {
                    let mut state = lock(&self.0.state);
                    let record = state.records.get_mut(&id).ok_or_else(|| {
                        crate::cingulate_client::double::refusal("elicitation_not_found")
                    })?;
                    if method == wire::CONSENT_WITHDRAW && record["state"] == "pending" {
                        record["state"] = json!("withdrawn");
                    }
                    let mut reply = record.clone();
                    if method == wire::CONSENT_DETACH && record["state"] == "pending" {
                        reply["detached"] = json!(true);
                    }
                    drop(state);
                    self.0.changed.notify_waiters();
                    Ok(reply)
                }
                wire::CONSENT_ANSWERS => Ok(
                    json!({"records":lock(&self.0.state).records.values().filter(|record| record["state"] == "answered" || record["state"] == "expired").cloned().collect::<Vec<_>>(),"cursor":1}),
                ),
                wire::CONSENT_ACK => Ok(json!({"cursor":1})),
                _ => panic!("unscripted Cingulate method {method}"),
            }
        })
    }
}

pub(crate) fn session_key(agent: &str) -> crate::cingulate_client::live_call::SessionKey {
    let stamp = stamp(agent);
    crate::cingulate_client::live_call::SessionKey {
        owner: serde_json::to_string(&stamp.owner).unwrap(),
        scope_ref: stamp.scope_ref,
        scope_epoch: stamp.scope_epoch,
    }
}

pub(crate) async fn with_live<T>(future: impl std::future::Future<Output = T>) -> T {
    let clock = cerebellum_core::clock::FakeClock::new();
    let timing = Arc::new(cerebellum_core::dispatch::DispatchTimingState::new(&clock));
    crate::call_context::ROUTE_GUARD
        .scope(Arc::new(timing.enter(&clock)), future)
        .await
}

/// Trigger the production next-call drain without taking a login approval.
pub(crate) async fn drain_call(planes: &Planes, channel: u16, epoch: u32) {
    let mut facts = planes.routes.get(channel, epoch).unwrap();
    facts.surface = cerebellum_core::identity::RouteSurface::Management;
    let drain_channel = channel + 100;
    planes.routes.insert(drain_channel, epoch, facts);
    let request = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        drain_channel,
        epoch,
        9876,
        serde_json::to_vec(&json!({"method":"test.unknown","params":{}})).unwrap(),
    )
    .unwrap();
    let (writer, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(request, &writer, planes).await.unwrap();
    let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply.header.ty, FrameType::Error);
    let body: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_eq!(body["code"], "unknown_method");
    assert_eq!(reply.header.corr, 9876);
    assert!(rx.try_recv().is_err(), "a drain sent a reverse-lane frame");
    planes.routes.remove(drain_channel, epoch);
}

struct Running;
impl crate::management::TargetResolver for Running {
    fn resolve(&self, bundle: &str) -> cerebellum_computer::platform::TargetResolution {
        cerebellum_computer::platform::TargetResolution::Resolved(
            cerebellum_computer::platform::ProcessGrant {
                pid: 4242,
                bundle_identity: bundle.into(),
                process_generation_evidence: "fixture-generation".into(),
            },
        )
    }
    fn app_code(&self, _: &cerebellum_computer::platform::ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(SignedByFixtureTeam)
    }
}

fn app_planes() -> Planes {
    let mut planes = crate::tests::management_bound_planes(1, 1);
    planes.management = Arc::new(crate::management::ManagementPlane::new(Arc::new(Running)));
    CardService::install(planes, 1, 1)
}

fn app_request(corr: u64) -> Frame {
    Frame::build_with_version(PROTOCOL_VERSION, FrameType::Request, Flags::new(false, Priority::Interactive, false), 1, 1, corr, serde_json::to_vec(&json!({"method":"computer.open_target","params":{"bundle_identity":"com.example.Editor"}})).unwrap()).unwrap()
}

async fn wire_reply(rx: &mut tokio::sync::mpsc::Receiver<Frame>) -> Value {
    let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .expect("the holder replies")
        .unwrap();
    assert_eq!(
        frame.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&frame.body)
    );
    serde_json::from_slice(&frame.body).unwrap()
}

async fn until(check: impl FnMut() -> bool) {
    until_with_timeout(check, HANG_GUARD).await;
}

async fn until_with_timeout(mut check: impl FnMut() -> bool, bound: Duration) {
    tokio::time::timeout(bound, async {
        while !check() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the consent operation ran");
}

#[tokio::test]
async fn app_cards_use_cingulate_ids_and_never_the_route_writer() {
    let planes = app_planes();
    let script = crate::cingulate_client::ScriptedCingulate::new();
    script.then(wire::CONSENT_REQUEST, crate::cingulate_client::Reply::Result(json!({"elicitation_id":"el_remote"})))
        .then(wire::CONSENT_AWAIT, crate::cingulate_client::Reply::Result(json!({"elicitation_id":"el_remote","state":"answered","answered_choice_id":"allow_30m"})));
    let store = Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
        planes
            .consent_test
            .as_ref()
            .unwrap()
            .root
            .join("scripted.json"),
    ));
    let planes = planes.with_cingulate(Arc::new(script.clone()), store.clone());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(wire_reply(&mut rx).await["outcome"], "granted");
    assert!(
        rx.try_recv().is_err(),
        "the route writer must contain no question"
    );
    assert_eq!(
        script.methods(),
        [wire::CONSENT_REQUEST, wire::CONSENT_AWAIT]
    );
    assert!(
        script.calls()[0].1.get("requester_ref").is_none(),
        "a management call without a call key has no requester ref"
    );
    assert_eq!(script.calls()[1].1["elicitation_id"], "el_remote");
    assert!(store.load().unwrap()[0].applied);
}

#[tokio::test]
async fn computer_cards_require_an_attested_agent_session_not_elicitation() {
    for mode in ["unscoped", "direct", "unattested", "admitted"] {
        let planes = app_planes();
        let mut facts = planes.routes.get(1, 1).unwrap();
        facts.consumer_capabilities.clear();
        match mode {
            "unscoped" => facts.scope = None,
            "direct" => facts.principal = Some(Principal::Direct),
            "unattested" => facts.agent_project_id_attested = false,
            _ => {}
        }
        planes.routes.insert(1, 1, facts);
        let script = crate::cingulate_client::ScriptedCingulate::new();
        script.then(wire::CONSENT_REQUEST, crate::cingulate_client::Reply::Result(json!({"elicitation_id":"el_admission"})))
            .then(wire::CONSENT_AWAIT, crate::cingulate_client::Reply::Result(json!({"elicitation_id":"el_admission","state":"answered","answered_choice_id":"allow_30m"})));
        let store = Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
            planes
                .consent_test
                .as_ref()
                .unwrap()
                .root
                .join("admission.json"),
        ));
        let planes = planes.with_cingulate(Arc::new(script.clone()), store);
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        crate::handle_frame(app_request(1), &tx, &planes)
            .await
            .unwrap();
        if mode == "direct" {
            let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            let reply: Value = serde_json::from_slice(&frame.body).unwrap();
            assert_eq!(frame.header.ty, FrameType::Error);
            assert_eq!(reply["code"], "session_caller_not_admitted");
            assert_eq!(script.opens(), 0);
            continue;
        }
        let reply = wire_reply(&mut rx).await;
        if mode == "admitted" {
            assert_eq!(reply["outcome"], "granted");
        } else {
            assert_eq!(reply["reason"], "no_agent_session", "{mode}: {reply}");
            assert_eq!(script.opens(), 0, "{mode}");
        }
        assert!(rx.try_recv().is_err());
    }
}

#[tokio::test]
async fn app_open_refusals_and_unreadable_registry_keep_their_reasons() {
    for (cause, reason) in [
        ("scope_not_carrier", "not_a_carrier"),
        ("scope_ended", "scope_ended"),
        ("damaged", "consent_registry_unreadable"),
    ] {
        let planes = app_planes();
        let script = crate::cingulate_client::ScriptedCingulate::new();
        if cause != "damaged" {
            *script.refuse_open.lock().unwrap() = Some(cause);
        }
        let path = planes
            .consent_test
            .as_ref()
            .unwrap()
            .root
            .join("refused.json");
        if cause == "damaged" {
            fs::write(&path, "{\"version\":999}").unwrap();
        }
        let planes = planes.with_cingulate(
            Arc::new(script.clone()),
            Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
                path.clone(),
            )),
        );
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        crate::handle_frame(app_request(1), &tx, &planes)
            .await
            .unwrap();
        assert_eq!(wire_reply(&mut rx).await["reason"], reason);
        assert!(script.calls().is_empty());
        if cause == "damaged" {
            assert_eq!(script.opens(), 0);
            assert_eq!(fs::read_to_string(path).unwrap(), "{\"version\":999}");
        }
    }
}

#[tokio::test]
async fn app_holder_loses_to_the_session_drain_only_after_the_grant_exists() {
    let planes = app_planes();
    let service = planes.consent_test.as_ref().unwrap();
    service.defer_awaits();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    let question = service.card(1, 1).await;
    until(|| {
        service
            .calls()
            .iter()
            .any(|(method, _)| method == wire::CONSENT_AWAIT)
    })
    .await;
    assert!(service.answer(
        question.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
    ));
    drain_call(&planes, 1, 1).await;
    assert_eq!(
        wire_reply(&mut rx).await["outcome"],
        "consent_granted_not_executed"
    );
    let facts = planes.routes.get(1, 1).unwrap();
    let caller = GrantCaller::new(
        facts.identity.conversation_key,
        facts.identity.agent_project_id,
        true,
    );
    let need = GrantNeed::App {
        bundle_identity: "com.example.Editor".into(),
        display_name: "Editor".into(),
        code: Arc::new(SignedByFixtureTeam),
    };
    assert!(planes.management.computer_grants().holds(&caller, &need));
    assert_eq!(
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_REQUEST)
            .count(),
        1
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn two_app_holders_elect_exactly_one_execution() {
    let planes = app_planes();
    let service = planes.consent_test.as_ref().unwrap();
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    let question = service.card(1, 1).await;
    crate::handle_frame(app_request(2), &tx, &planes)
        .await
        .unwrap();
    until(|| {
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_AWAIT)
            .count()
            == 2
    })
    .await;
    assert!(service.answer(
        question.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
    ));
    let mut outcomes = vec![
        wire_reply(&mut rx).await["outcome"]
            .as_str()
            .unwrap()
            .to_string(),
        wire_reply(&mut rx).await["outcome"]
            .as_str()
            .unwrap()
            .to_string(),
    ];
    outcomes.sort();
    assert_eq!(outcomes, ["consent_granted_not_executed", "granted"]);
    assert_eq!(
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_REQUEST)
            .count(),
        1
    );
}

fn sqlite(path: &Path, sql: &str) -> String {
    let output = std::process::Command::new("/usr/bin/sqlite3")
        .arg(path)
        .arg(sql)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn two_browser_plan(root: &Path) -> crate::login_import::LoginImportPlan {
    fs::create_dir_all(root.join("managed/profile")).unwrap();
    let executable = root.join("browser");
    fs::write(&executable, "fixture executable").unwrap();
    let sources: Vec<_> = [("first", "First", "6669727374"), ("second", "Second", "7365636F6E64")].into_iter().map(|(id, name, encrypted)| {
        let path = root.join("data").join(id).join("Default/Cookies");
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        if !path.exists() { sqlite(&path, &format!("CREATE TABLE cookies(host_key TEXT NOT NULL,name TEXT NOT NULL,path TEXT NOT NULL,has_expires INTEGER NOT NULL,encrypted_value BLOB NOT NULL,value TEXT NOT NULL DEFAULT ''); INSERT INTO cookies VALUES('.example.com','session','/',1,X'{encrypted}','');")); }
        crate::login_import::BrowserSource { id, display_name: name, data_directory: id.into(), executable: executable.clone() }
    }).collect();
    let crate::login_import::PreparedImport::Ready(plan) = crate::login_import::prepare_import(
        "https://example.com",
        "test-project",
        &executable,
        crate::login_import::DurableProfileLocation {
            managed_root: root.join("managed"),
            profile_directory: root.join("managed/profile"),
        },
        crate::login_import::ImportSettings::for_test(
            PathBuf::from("/usr/bin/sqlite3"),
            root.join("data"),
            root.join("safari"),
            sources,
        ),
    ) else {
        panic!("the isolated import plan is ready");
    };
    assert_eq!(
        plan.presence()
            .iter()
            .filter(|source| source.transfer == "available")
            .count(),
        2
    );
    plan
}

/// Start at the prepared-plan boundary without inspecting the operator's browsers.
async fn invoke_plan(
    planes: &Planes,
    plan: crate::login_import::LoginImportPlan,
    _corr: u64,
) -> Value {
    let (writer, _rx) = tokio::sync::mpsc::channel(8);
    let facts = planes.routes.get(1, 1).unwrap();
    with_live(crate::complete_login_import(
        planes, &facts, &writer, 1, 1, plan, None,
    ))
    .await
}

#[tokio::test]
async fn late_import_approval_copies_the_selected_browser_and_reports_execution() {
    let planes = app_planes();
    planes
        .management
        .computer_grants()
        .set_login_park_limit(Duration::from_millis(10));
    let service = planes.consent_test.as_ref().unwrap();
    let plan = two_browser_plan(&service.root);
    let pending = invoke_plan(&planes, plan, 10).await;
    assert_eq!(pending["outcome"], "consent_pending");
    let card = service.card(1, 1).await;
    assert!(service.answer(
        card.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"transfer:second"}))
    ));
    drain_call(&planes, 1, 1).await;
    let reply = invoke_plan(&planes, two_browser_plan(&service.root), 11).await;
    assert_eq!(reply["outcome"], "transferred", "{reply}");
    assert_eq!(reply["browser"], "second");
    let copied = sqlite(
        &service.root.join("managed/profile/Default/Cookies"),
        "SELECT hex(encrypted_value) FROM cookies WHERE name='session';",
    );
    assert_eq!(
        copied.trim(),
        "7365636F6E64",
        "the first browser must not be substituted for the person's choice"
    );
    let calls = service.calls();
    assert_eq!(
        calls
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_REQUEST)
            .count(),
        1
    );
    let reports: Vec<_> = calls
        .iter()
        .filter(|(method, _)| method == wire::CONSENT_REPORT_EXECUTION)
        .collect();
    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].1,
        json!({"elicitation_id":"el_test_1","execution":"executed"})
    );
    crate::browser::validate_browser_result(crate::management::IMPORT_LOGIN, &reply).unwrap();
}

#[tokio::test]
async fn new_import_endings_pass_result_schema_enforcement() {
    for ending in [
        "consent_unavailable",
        "unrecognized_answer",
        "question_withdrawn",
    ] {
        let planes = app_planes();
        let service = planes.consent_test.as_ref().unwrap();
        if ending == "consent_unavailable" {
            let mut facts = planes.routes.get(1, 1).unwrap();
            facts.scope = None;
            planes.routes.insert(1, 1, facts);
        }
        let plan = two_browser_plan(&service.root);
        let call = invoke_plan(&planes, plan, 12);
        let answer = async {
            if ending == "consent_unavailable" {
                return;
            }
            let card = service.card(1, 1).await;
            if ending == "unrecognized_answer" {
                assert!(service.answer(
                    card.header.corr,
                    ScriptedAnswer::Answered(json!({"decision":"future-choice"}))
                ));
            } else {
                let conversation = planes.routes.get(1, 1).unwrap().identity.conversation_key;
                crate::revoke_scope(&planes, &std::collections::BTreeSet::from([conversation]))
                    .await;
            }
        };
        let (reply, ()) = tokio::join!(call, answer);
        assert_eq!(reply["outcome"], ending, "{reply}");
        crate::browser::validate_browser_result(crate::management::IMPORT_LOGIN, &reply)
            .expect("the ending must not be withheld");
    }
}

#[tokio::test]
async fn revoked_login_cards_cannot_reappear_after_registry_restart() {
    let fixture = crate::login_capture::test_support::fixture();
    let planes = crate::tests::capture_planes(&fixture);
    planes
        .management
        .computer_grants()
        .set_login_park_limit(Duration::from_millis(10));
    let service = planes.consent_test.as_ref().unwrap();
    let request = crate::tests::capture_request_frame(
        15,
        json!({"credential_domain":"ollama.com","account":"work","fetch_url":"https://ollama.com/settings","login_url":"https://ollama.com/signin"}),
    );
    let (writer, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(request, &writer, &planes)
        .await
        .unwrap();
    assert_eq!(wire_reply(&mut rx).await["outcome"], "consent_pending");
    let card = service.card(4, 1).await;
    assert!(service.answer(
        card.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow"}))
    ));
    let facts = planes.routes.get(4, 1).unwrap();
    crate::revoke_scope(
        &planes,
        &std::collections::BTreeSet::from([facts.identity.conversation_key.clone()]),
    )
    .await;
    let store = Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
        service.root.join("registry.json"),
    ));
    let persisted_after_revocation = store.load().unwrap();
    let rebuilt = Planes::with_cingulate_for_test(
        Arc::new(crate::HealthState::default()),
        None,
        Arc::new(service.clone()),
        store,
    );
    rebuilt.routes.insert(4, 1, facts);
    let before = service.calls().len();
    drain_call(&rebuilt, 4, 1).await;
    assert!(!rebuilt.consent.has_single_use_approvals());
    assert!(
        persisted_after_revocation.is_empty(),
        "revocation must save the empty registry"
    );
    assert_eq!(
        service.calls().len(),
        before,
        "an ended session must open no consent route after restart"
    );
    assert!(fixture.vault.request_params().is_empty());
}

struct TestCarrier {
    desk: Arc<ConsentDesk>,
    guard: Arc<cerebellum_core::dispatch::InFlightGuard>,
}
impl TestCarrier {
    fn new(service: &Arc<CardService>) -> Arc<Self> {
        let clock = cerebellum_core::clock::FakeClock::new();
        let timing = Arc::new(cerebellum_core::dispatch::DispatchTimingState::new(&clock));
        Arc::new(Self {
            desk: Arc::new(ConsentDesk::with_store(
                Arc::new(service.clone()),
                Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
                    service.root.join("direct.json"),
                )),
            )),
            guard: Arc::new(timing.enter(&clock)),
        })
    }
}
impl QuestionCarrier for TestCarrier {
    fn desk(&self) -> Arc<ConsentDesk> {
        self.desk.clone()
    }
    fn live(&self) -> Result<LiveCall, NotLive> {
        LiveCall::from_inbound(
            Some(&stamp("test-project")),
            &self.guard,
            Arc::new(AlwaysOpenRoute),
        )
    }
}

fn context(carrier: Arc<dyn QuestionCarrier>) -> ConsentContext {
    let (tx, drain) = watch::channel(false);
    std::mem::forget(tx);
    ConsentContext::new(
        GrantCaller::new("conversation".into(), "test-project".into(), true),
        Some(carrier),
        Arc::new(AlwaysOpenRoute),
        drain,
        None,
    )
}

#[tokio::test]
async fn takeover_holders_elect_one_and_the_drain_winner_makes_holds_true() {
    for drain_wins in [false, true] {
        let service = CardService::new();
        if drain_wins {
            service.defer_awaits();
        }
        let carrier = TestCarrier::new(&service);
        let grants = Arc::new(ComputerGrants::in_memory());
        let call = || {
            let grants = grants.clone();
            let consent = context(carrier.clone());
            tokio::spawn(async move {
                grants
                    .require(&GrantNeed::Takeover, &consent, &CancelHandle::pending())
                    .await
            })
        };
        let first = call();
        let card = service.card(1, 1).await;
        let second = call();
        until(|| {
            service
                .calls()
                .iter()
                .filter(|(method, _)| method == wire::CONSENT_AWAIT)
                .count()
                == 2
        })
        .await;
        assert!(service.answer(
            card.header.corr,
            ScriptedAnswer::Answered(json!({"decision":"computer_30m"}))
        ));
        if drain_wins {
            let drain = crate::consent_drain::ConsentDrain::default();
            grants.register_drain(&drain);
            drain
                .run(&carrier.desk, &carrier.live().unwrap())
                .await
                .unwrap();
        }
        let results = [first.await.unwrap(), second.await.unwrap()];
        assert_eq!(
            results.iter().filter(|result| result.is_ok()).count(),
            usize::from(!drain_wins)
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(ConsentRefusal::GrantedNotExecuted)))
                .count(),
            if drain_wins { 2 } else { 1 }
        );
        assert!(grants.holds(&context(carrier.clone()).caller, &GrantNeed::Takeover));
        assert_eq!(
            service
                .calls()
                .iter()
                .filter(|(method, _)| method == wire::CONSENT_REQUEST)
                .count(),
            1
        );
    }
}

#[tokio::test]
async fn late_takeover_allow_once_records_no_grant_and_reports_approved_not_executed() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let grants = Arc::new(ComputerGrants::in_memory());
    let consent = context(carrier.clone()).with_park_limit(Duration::from_millis(1));
    let result = tokio::time::timeout(
        HANG_GUARD,
        grants.require(&GrantNeed::Takeover, &consent, &CancelHandle::pending()),
    )
    .await
    .expect("the takeover call must stop waiting before its late answer");
    assert!(matches!(result, Err(ConsentRefusal::Pending { .. })));
    let card = service.card(1, 1).await;
    assert!(service.answer(
        card.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow_once"}))
    ));

    let drain = crate::consent_drain::ConsentDrain::default();
    grants.register_drain(&drain);
    let live = carrier.live().unwrap();
    let applied = drain.run(&carrier.desk, &live).await.unwrap();
    assert_eq!(applied.applied, ["el_test_1"]);
    assert!(!grants.holds(&consent.caller, &GrantNeed::Takeover));
    assert!(!carrier.desk.has_single_use_approvals());
    // Opening the next drain flushes the execution report queued by settlement.
    drain.run(&carrier.desk, &live).await.unwrap();
    let reports: Vec<_> = service
        .calls()
        .into_iter()
        .filter(|(method, _)| method == wire::CONSENT_REPORT_EXECUTION)
        .collect();
    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].1,
        json!({"elicitation_id":"el_test_1","execution":"approved_not_executed"})
    );
}

fn login_request(carrier: Arc<dyn QuestionCarrier>) -> LoginConsentRequest {
    let consent = context(carrier.clone());
    LoginConsentRequest {
        conversation_key: consent.caller.conversation_key,
        capability: LoginCapability::CaptureLogin,
        parameters: "login-parameters".into(),
        carrier,
        cancel: None,
        drain: consent.drain,
        route: consent.route,
        park_guard: None,
    }
}

fn login_body() -> Value {
    crate::login_capture::consent_question(&crate::login_capture::CaptureRequest {
        credential_domain: "ollama.com".into(),
        account: "work".into(),
        fetch_url: "https://ollama.com/settings".into(),
        login_url: "https://ollama.com/signin".into(),
    })
}

#[tokio::test]
async fn login_holder_takes_the_drain_approval_without_a_second_request() {
    let service = CardService::new();
    service.defer_awaits();
    let carrier = TestCarrier::new(&service);
    let grants = Arc::new(ComputerGrants::in_memory());
    let request = login_request(carrier.clone());
    let holder_grants = grants.clone();
    let holder =
        tokio::spawn(async move { holder_grants.require_login(request, login_body).await });
    let card = service.card(1, 1).await;
    until(|| {
        service
            .calls()
            .iter()
            .any(|(method, _)| method == wire::CONSENT_AWAIT)
    })
    .await;
    assert!(service.answer(
        card.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow"}))
    ));
    let drain = crate::consent_drain::ConsentDrain::default();
    grants.register_drain(&drain);
    drain
        .run(&carrier.desk, &carrier.live().unwrap())
        .await
        .unwrap();
    let consent = tokio::time::timeout(HANG_GUARD, holder)
        .await
        .unwrap()
        .unwrap();
    let LoginConsent::Ended(answer) = consent else {
        panic!("the stored approval answers the holder");
    };
    assert!(answer.taken_approval);
    assert_eq!(answer.elicitation_id.as_deref(), Some("el_test_1"));
    assert_eq!(
        answer.ending,
        CardEnding::Granted {
            choice_id: "allow".into()
        }
    );
    assert_eq!(
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_REQUEST)
            .count(),
        1
    );
    assert!(!carrier.desk.has_single_use_approvals());
}

#[tokio::test(start_paused = true)]
async fn a_login_call_that_loses_its_approval_parks_no_longer_than_one_allowance() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let grants = Arc::new(ComputerGrants::in_memory());
    let call = || {
        let grants = grants.clone();
        let request = login_request(carrier.clone());
        tokio::spawn(async move {
            let start = tokio::time::Instant::now();
            (
                grants.require_login(request, login_body).await,
                start.elapsed(),
            )
        })
    };
    let first = call();
    let card = service
        .card_with_timeout(1, 1, Duration::from_secs(10))
        .await;
    let second = call();
    until_with_timeout(
        || {
            service
                .calls()
                .iter()
                .filter(|(method, _)| method == wire::CONSENT_AWAIT)
                .count()
                == 2
        },
        Duration::from_secs(10),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(100)).await;
    assert!(service.answer(
        card.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow"}))
    ));
    let results = [first.await.unwrap(), second.await.unwrap()];
    let pending = results
        .iter()
        .find(|(consent, _)| matches!(consent, LoginConsent::Pending { .. }))
        .expect("one approval admits only one holder");
    assert_eq!(
        pending.1, CONSENT_PARK_LIMIT,
        "losing the election must not renew the park deadline"
    );
    assert!(results.iter().any(|(consent, _)| matches!(
        consent,
        LoginConsent::Ended(LoginAnswer {
            ending: CardEnding::Granted { .. },
            taken_approval: true,
            ..
        })
    )));
}

#[tokio::test]
async fn execution_reports_cover_definite_nonexecution_and_indeterminate_results() {
    let service = CardService::new();
    let carrier: Arc<dyn QuestionCarrier> = TestCarrier::new(&service);
    lock(&service.state).records.insert(
        "el_taken".into(),
        json!({"elicitation_id":"el_taken","state":"answered","answered_choice_id":"allow"}),
    );
    let answer = LoginAnswer {
        ending: CardEnding::Granted {
            choice_id: "allow".into(),
        },
        elicitation_id: Some("el_taken".into()),
        taken_approval: true,
    };
    for (reply, expected) in [
        (json!({"outcome":"cancelled"}), "approved_not_executed"),
        (json!({"outcome":"expired"}), "approved_not_executed"),
        (
            json!({"outcome":"capture_not_stored","reason":"vault_unreachable"}),
            "approved_not_executed",
        ),
        (
            json!({"outcome":"capture_not_stored","reason":"vault_call_failed"}),
            "outcome_unknown",
        ),
        (
            json!({"outcome":"capture_not_stored","reason":"vault_deadline_exceeded","remedy":"may or may not be stored"}),
            "outcome_unknown",
        ),
        (json!({"outcome":"captured"}), "executed"),
    ] {
        assert_eq!(
            login_execution_outcome(&reply, "captured").0.as_str(),
            expected
        );
    }
    let before = service.calls().len();
    let not_taken = LoginAnswer {
        taken_approval: false,
        ..answer
    };
    report_login_execution(
        &carrier,
        &not_taken,
        &json!({"outcome":"captured"}),
        "captured",
    )
    .await;
    assert_eq!(
        service.calls().len(),
        before,
        "an approval never taken has no execution to report"
    );
}

#[tokio::test]
async fn capture_endings_keep_their_reply_words_and_no_agent_is_not_withheld() {
    for (ending, expected, reason) in [
        ("allow", "capture_pending", None),
        ("deny", "capture_consent_not_given", Some("deny")),
        (
            "future-choice",
            "capture_consent_not_given",
            Some("unrecognized_answer"),
        ),
        ("no_answer", "capture_consent_not_given", Some("no_answer")),
        (
            "not_put_to_anyone",
            "capture_consent_not_given",
            Some("not_put_to_anyone"),
        ),
        (
            "undeliverable",
            "capture_consent_not_given",
            Some("undeliverable"),
        ),
        (
            "withdrawn",
            "capture_consent_not_given",
            Some("question_withdrawn"),
        ),
        ("unscoped", "consent_unavailable", Some("no_agent_session")),
    ] {
        let fixture = crate::login_capture::test_support::fixture();
        let planes = crate::tests::capture_planes(&fixture);
        let service = planes.consent_test.as_ref().unwrap();
        if ending == "unscoped" {
            let mut facts = planes.routes.get(4, 1).unwrap();
            facts.scope = None;
            planes.routes.insert(4, 1, facts);
        }
        let request = crate::tests::capture_request_frame(
            17,
            json!({"credential_domain":"ollama.com","account":"work","fetch_url":"https://ollama.com/settings","login_url":"https://ollama.com/signin"}),
        );
        let (writer, mut rx) = tokio::sync::mpsc::channel(8);
        crate::handle_frame(request, &writer, &planes)
            .await
            .unwrap();
        if ending != "unscoped" {
            let card = service.card(4, 1).await;
            if ending == "withdrawn" {
                lock(&service.state).records.get_mut("el_test_1").unwrap()["state"] =
                    json!("withdrawn");
                service.changed.notify_waiters();
            } else {
                let outcome = match ending {
                    "no_answer" => ScriptedAnswer::NoAnswer,
                    "not_put_to_anyone" => ScriptedAnswer::NotPutToAnyone,
                    "undeliverable" => ScriptedAnswer::Undeliverable,
                    _ => ScriptedAnswer::Answered(json!({"decision":ending})),
                };
                assert!(service.answer(card.header.corr, outcome));
            }
        }
        let reply = wire_reply(&mut rx).await;
        assert_eq!(reply["outcome"], expected, "{ending}: {reply}");
        if let Some(reason) = reason {
            assert_eq!(
                if ending == "unscoped" {
                    &reply["detail"]["reason"]
                } else {
                    &reply["reason"]
                },
                reason,
                "{ending}: {reply}"
            );
        }
        crate::browser::validate_browser_result(crate::management::CAPTURE_LOGIN, &reply)
            .expect("the ending must pass the closed result schema");
        assert!(
            rx.try_recv().is_err(),
            "no card belongs on the inbound route"
        );
        if ending != "allow" {
            assert!(fixture.vault.request_params().is_empty());
        } else {
            assert_eq!(
                crate::tests::capture_late(&planes, 17).await["result"]["outcome"],
                "captured"
            );
        }
    }
}

struct BlockingStore {
    started: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    released: Mutex<bool>,
    changed: std::sync::Condvar,
}
impl GrantStorage for BlockingStore {
    fn load(&self) -> Result<GrantStoreState, GrantStoreError> {
        Ok(GrantStoreState::default())
    }
    fn save(&self, _: &GrantStoreState) -> Result<(), GrantStoreError> {
        if let Some(started) = lock(&self.started).take() {
            let _ = started.send(());
        }
        let mut released = lock(&self.released);
        while !*released {
            released = self.changed.wait(released).unwrap();
        }
        Ok(())
    }
}

impl crate::agent_grants::AgentGrantStorage for BlockingStore {
    fn load(
        &self,
    ) -> Result<
        Option<crate::agent_grants::AgentGrantStoreState>,
        crate::agent_grants::AgentGrantStoreError,
    > {
        Ok(Some(crate::agent_grants::AgentGrantStoreState::default()))
    }
    fn save(
        &self,
        _: &crate::agent_grants::AgentGrantStoreState,
    ) -> Result<(), crate::agent_grants::AgentGrantStoreError> {
        <Self as GrantStorage>::save(self, &GrantStoreState::default()).map_err(|error| {
            crate::agent_grants::AgentGrantStoreError::WriteFailed {
                detail: error.to_string(),
            }
        })
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_losing_holder_cannot_reply_before_the_winner_stores_the_effect() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let (started, saved) = tokio::sync::oneshot::channel();
    let storage = Arc::new(BlockingStore {
        started: Mutex::new(Some(started)),
        released: Mutex::new(false),
        changed: std::sync::Condvar::new(),
    });
    let grants = Arc::new(
        ComputerGrants::open(storage.clone(), Some("fixture-machine".into())).with_agent_grants(
            Arc::new(crate::agent_grants::AgentGrants::open(
                storage.clone(),
                &crate::agent_grants::LegacyGrantStores {
                    apps: Arc::new(InMemoryGrantStorage::new()),
                    browser: Arc::new(
                        crate::browser_standing_grants::InMemoryStandingGrantStorage::new(),
                    ),
                    user_browser: Arc::new(
                        crate::browser_standing_grants::InMemoryStandingGrantStorage::new(),
                    ),
                },
                Some("fixture-machine".into()),
            )),
        ),
    );
    let call = || {
        let grants = grants.clone();
        let consent = context(carrier.clone());
        tokio::spawn(async move {
            grants
                .require(
                    &GrantNeed::App {
                        bundle_identity: "com.example.Editor".into(),
                        display_name: "Editor".into(),
                        code: Arc::new(SignedByFixtureTeam),
                    },
                    &consent,
                    &CancelHandle::pending(),
                )
                .await
        })
    };
    let first = call();
    let card = service.card(1, 1).await;
    until(|| {
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_AWAIT)
            .count()
            == 1
    })
    .await;
    let second = call();
    until(|| {
        service
            .calls()
            .iter()
            .filter(|(method, _)| method == wire::CONSENT_AWAIT)
            .count()
            == 2
    })
    .await;
    assert!(service.answer(
        card.header.corr,
        ScriptedAnswer::Answered(json!({"decision":"allow_always"}))
    ));
    tokio::time::timeout(HANG_GUARD, saved)
        .await
        .expect("the agent grant store write began")
        .unwrap();
    let drain = crate::consent_drain::ConsentDrain::default();
    grants.register_drain(&drain);
    let report = drain
        .run(&carrier.desk, &carrier.live().unwrap())
        .await
        .unwrap();
    let acknowledged_before_save = report.acked.is_some();
    let applied_before_save = carrier
        .desk
        .raised("el_test_1")
        .is_some_and(|card| card.applied);
    // Release the blocking writer even when the control finds a premature reply,
    // so a deliberately broken ordering produces a failure rather than a hang.
    let premature = tokio::time::timeout(Duration::from_millis(20), async {
        while !first.is_finished() && !second.is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .is_ok();
    *lock(&storage.released) = true;
    storage.changed.notify_all();
    let results = [first.await.unwrap(), second.await.unwrap()];
    assert!(
        !premature,
        "the loser replied before the grant store completed"
    );
    assert!(
        !acknowledged_before_save,
        "the drain acknowledged a write still in progress"
    );
    assert!(
        !applied_before_save,
        "the grant was marked applied before its write finished"
    );
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(ConsentRefusal::GrantedNotExecuted)))
            .count(),
        1
    );
    assert!(carrier.desk.raised("el_test_1").unwrap().applied);
}

#[tokio::test]
async fn a_raising_card_is_not_swept_before_its_memory_record_is_registered() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let grants = Arc::new(ComputerGrants::in_memory());
    let need = GrantNeed::Takeover;
    let caller = context(carrier.clone()).caller;
    let key = Subject::of(&caller, &need).desk_subject();
    lock(&grants.state).creating.insert(key.clone());
    let live = carrier.live().unwrap();
    let mut session = carrier.desk.session(&live).await.unwrap();
    let card = consent_request(
        CardKind::Takeover,
        &question_body(&need, &[ALLOW_30M, DENY], false, None),
        TAKEOVER_QUESTION_DEADLINE,
        None,
        None,
        None,
    )
    .unwrap();
    let id = session.raise(card, &key).await.unwrap();
    // The service and registry know the card, but the raising caller has not
    // yet installed its completion watch in the memory-only pending map.
    assert!(!grants.question_open(&id));
    let drain = crate::consent_drain::ConsentDrain::default();
    grants.register_drain(&drain);
    drain.run(&carrier.desk, &live).await.unwrap();
    assert!(
        carrier.desk.raised(&id).is_some(),
        "an in-progress raise is not a record lost on restart"
    );
    assert!(!service
        .calls()
        .iter()
        .any(|(method, _)| method == wire::CONSENT_WITHDRAW));
}

#[tokio::test]
async fn retained_accounting_guard_cannot_authorize_a_card_after_terminal_finalization() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let script = crate::cingulate_client::ScriptedCingulate::new();
    script.then(
        wire::CONSENT_REQUEST,
        crate::cingulate_client::Reply::Result(json!({"elicitation_id":"el_after_reply"})),
    );
    let desk = ConsentDesk::with_store(
        Arc::new(script.clone()),
        Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
            service.root.join("terminal.json"),
        )),
    );
    let terminal = Arc::new(crate::TerminalArbiter::new(app_request(19)));
    crate::CALL_TERMINAL
        .scope(terminal.clone(), async {
            let live = carrier.live().unwrap();
            let mut opened = desk.session(&live).await.unwrap();
            let retained_guard = carrier.guard.clone();
            terminal.finalize_reply_for_test();
            assert!(Arc::strong_count(&retained_guard) > 1);
            assert!(
                !live.is_held(),
                "an accounting guard is not post-reply consent authority"
            );
            assert!(matches!(desk.session(&live).await, Err(CallError::NotLive)));
            let card = consent_request(
                CardKind::Takeover,
                &question_body(&GrantNeed::Takeover, &[ALLOW_30M, DENY], false, None),
                TAKEOVER_QUESTION_DEADLINE,
                None,
                None,
                None,
            )
            .unwrap();
            assert_eq!(
                opened.raise(card, "after-reply").await,
                Err(CardEnding::NoCard(NoCard::CallEnded))
            );
            assert_eq!(
                script.opens(),
                1,
                "only the route opened before finalization is allowed"
            );
            assert!(
                script.calls().is_empty(),
                "the existing route must raise no late card"
            );
        })
        .await;
}

struct FinalizingOpener(Arc<crate::cingulate_client::ScriptedCingulate>);
impl CingulateOpener for FinalizingOpener {
    fn open<'a>(
        &'a self,
        live: &'a LiveCall,
    ) -> BoxFuture<'a, Result<Box<dyn CingulateRoute>, CallError>> {
        Box::pin(async move {
            crate::TerminalArbiter::current()
                .unwrap()
                .finalize_reply_for_test();
            self.0.open(live).await
        })
    }
}

#[tokio::test]
async fn a_route_open_that_outlasts_the_call_returns_not_live() {
    let service = CardService::new();
    let carrier = TestCarrier::new(&service);
    let script = crate::cingulate_client::ScriptedCingulate::new();
    let desk = ConsentDesk::with_store(
        Arc::new(FinalizingOpener(script.clone())),
        Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
            service.root.join("open-finalized.json"),
        )),
    );
    let terminal = Arc::new(crate::TerminalArbiter::new(app_request(20)));
    crate::CALL_TERMINAL
        .scope(terminal, async {
            let live = carrier.live().unwrap();
            assert!(matches!(desk.session(&live).await, Err(CallError::NotLive)));
            assert_eq!(script.opens(), 1);
            assert!(script.calls().is_empty());
        })
        .await;
}

/// A scoped test route may ask whether its session remains live after unbinding.
/// Answer that control request separately from the computer call's reply.
// Its callers are macOS-only computer tests, so other hosts never use it.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn scope_reply(question: &Frame) -> Option<Frame> {
    let body: Value = serde_json::from_slice(&question.body).ok()?;
    if question.header.ty != FrameType::Request
        || question.header.channel != 0
        || body["op"] != "scope.describe"
    {
        return None;
    }
    Some(Frame::build_with_version(PROTOCOL_VERSION, FrameType::Response, Flags::new(false, Priority::Interactive, false), 0, 0, question.header.corr, serde_json::to_vec(&json!({"op":"scope.describe","status":"live","scope_epoch":1,"daemon_incarnation":"card-tests","owner_synced":true,"owner_configured":true})).unwrap()).unwrap())
}

mod worker;

mod holders;

mod agent_app_ops;
mod cards;
