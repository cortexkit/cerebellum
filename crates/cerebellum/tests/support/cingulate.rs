// Shared consent-service routes for integration tests and probes.
// Unit tests alias the current crate as `cerebellum` in the parent module;
// inherit that alias here. Other targets resolve `cerebellum` as a dependency.
#[allow(unused_imports)]
use super::*;
use cerebellum::computer_grants::QuestionCarrier;
use cerebellum::cingulate_client::ScriptedAnswer;
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
const GRANTEE: &str = "pj-example";

/// A carrier whose answers the test scripts.
///
/// Each question put through it is recorded. It is answered by the next queued
/// answer, if one was queued, or else waits until the test answers it with
/// [`ScriptedCarrier::answer_next`].
#[derive(Clone)]
pub struct ScriptedCarrier {
    state: Arc<Mutex<ScriptState>>,
    desk: Arc<cerebellum::cingulate_client::desk::ConsentDesk>,
    guard: Arc<cerebellum_core::dispatch::InFlightGuard>,
}

impl Default for ScriptedCarrier {
    fn default() -> Self {
        let state = Arc::new(Mutex::new(ScriptState::default()));
        let desk = Arc::new(cerebellum::cingulate_client::desk::ConsentDesk::new(
            Arc::new(FixtureOpener(state.clone())),
        ));
        let clock = cerebellum_core::clock::FakeClock::new();
        let timing = Arc::new(cerebellum_core::dispatch::DispatchTimingState::new(&clock));
        Self {
            state,
            desk,
            guard: Arc::new(timing.enter(&clock)),
        }
    }
}

#[derive(Default)]
struct ScriptState {
    queued: std::collections::VecDeque<ScriptedAnswer>,
    waiting: std::collections::VecDeque<(String, tokio::sync::oneshot::Sender<Value>)>,
    records: std::collections::BTreeMap<String, Value>,
    questions: Vec<Value>,
    namespace: String,
    consumed: usize,
    calls: Vec<(String, Value)>,
    request_error: Option<cerebellum::cingulate_client::route::CallError>,
    defer_awaits: bool,
    deferred: Vec<tokio::sync::oneshot::Sender<()>>,
}
#[allow(dead_code)]
impl ScriptedCarrier {
    /// Queue these option ids as the answers to successive permission questions.
    pub fn answering(decisions: &[&str]) -> Self {
        let carrier = Self::default();
        for decision in decisions {
            carrier.queue(ScriptedAnswer::Answered(json!({"decision": decision})));
        }
        carrier
    }

    pub async fn apply_late(&self, grants: &Arc<cerebellum::computer_grants::ComputerGrants>) {
        let drain = cerebellum::consent_drain::ConsentDrain::default();
        for kind in [
            cerebellum::cingulate_client::card::CardKind::AppControl,
            cerebellum::cingulate_client::card::CardKind::Takeover,
        ] {
            drain.register(kind, grants.clone());
        }
        drain.run(&self.desk, &self.live().unwrap()).await.unwrap();
    }

    pub fn defer_awaits(&self) {
        self.state.lock().unwrap().defer_awaits = true;
    }

    pub fn resume_awaits(&self) {
        let deferred = {
            let mut state = self.state.lock().unwrap();
            state.defer_awaits = false;
            std::mem::take(&mut state.deferred)
        };
        for sender in deferred { let _ = sender.send(()); }
    }

    pub fn refuse_next_request(&self, code: &str) {
        self.state.lock().unwrap().request_error =
            Some(cerebellum::cingulate_client::double::refusal(code));
    }

    pub fn queue(&self, outcome: ScriptedAnswer) {
        self.state.lock().unwrap().queued.push_back(outcome);
    }

    /// Answer the oldest waiting question; return false if no question is waiting.
    pub fn answer_next(&self, outcome: ScriptedAnswer) -> bool {
        let mut state = self.state.lock().unwrap();
        let Some((id, sender)) = state.waiting.pop_front() else {
            return false;
        };
        let record = fixture_record(&id, outcome);
        state.records.insert(id, record.clone());
        let _ = sender.send(record);
        true
    }

    pub fn answer_unraised(&self, id: &str, decision: &str) {
        self.state.lock().unwrap().records.insert(id.into(), fixture_record(id, ScriptedAnswer::Answered(json!({"decision":decision}))));
    }

    pub fn answer_id(&self, id: &str, outcome: ScriptedAnswer) -> bool {
        let mut state = self.state.lock().unwrap();
        if !state.records.contains_key(id) {
            return false;
        }
        let record = fixture_record(id, outcome);
        state.records.insert(id.into(), record.clone());
        if let Some(index) = state.waiting.iter().position(|(waiting, _)| waiting == id) {
            let (_, sender) = state.waiting.remove(index).unwrap();
            let _ = sender.send(record);
        }
        true
    }

    pub fn install(&self, planes: cerebellum::Planes) -> cerebellum::Planes {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        // Each inclusion of this support module has its own NEXT counter, so
        // counters alone can collide within one binary. Reserving a directory
        // atomically keeps their raised-card registry files separate.
        let root = loop {
            let root = std::env::temp_dir().join(format!("integration-cingulate-{}-{}", std::process::id(), NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)));
            match std::fs::create_dir(&root) {
                Ok(()) => break root,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => panic!("cannot create the consent fixture directory: {error}"),
            }
        };
        let path = root.join("registry.json");
        self.state.lock().unwrap().namespace = root.file_name().unwrap().to_string_lossy().into_owned();
        fixtures().lock().unwrap().insert(
            Arc::as_ptr(&planes.management) as usize,
            Arc::downgrade(&self.state),
        );
        planes.with_cingulate(
            Arc::new(FixtureOpener(self.state.clone())),
            Arc::new(TemporaryRegistry(path)),
        )
    }

    pub fn find(planes: &cerebellum::Planes) -> Option<Self> {
        let state = fixtures()
            .lock()
            .unwrap()
            .get(&(Arc::as_ptr(&planes.management) as usize))
            .and_then(std::sync::Weak::upgrade)?;
        let clock = cerebellum_core::clock::FakeClock::new();
        let timing = Arc::new(cerebellum_core::dispatch::DispatchTimingState::new(&clock));
        Some(Self {
            state,
            desk: planes.consent.clone(),
            guard: Arc::new(timing.enter(&clock)),
        })
    }

    pub fn for_planes(planes: &cerebellum::Planes) -> Self {
        Self::find(planes).expect("the planes have an installed Cingulate fixture")
    }

    /// Wrap the next recorded service question in a synthetic frame for
    /// inspection. Nothing is sent back to the calling agent; that caller's
    /// ordinary replies are read from its own writer separately.
    pub async fn card(&self, channel: u16, epoch: u32) -> subc_protocol::Frame {
        let end = tokio::time::Instant::now() + std::time::Duration::from_secs(3);
        loop {
            let next = {
                let mut state = self.state.lock().unwrap();
                let index = state.consumed;
                state.questions.get(index).cloned().map(|question| {
                    state.consumed += 1;
                    (index + 1, question)
                })
            };
            if let Some((corr, question)) = next {
                return subc_protocol::Frame::build_with_version(
                    subc_protocol::PROTOCOL_VERSION,
                    subc_protocol::FrameType::Request,
                    subc_protocol::Flags::new(false, subc_protocol::Priority::Interactive, false),
                    channel,
                    epoch,
                    corr as u64,
                    serde_json::to_vec(&question).unwrap(),
                )
                .unwrap();
            }
            assert!(
                tokio::time::Instant::now() < end,
                "Cingulate received no card"
            );
            tokio::task::yield_now().await;
        }
    }

    pub fn calls(&self) -> Vec<(String, Value)> {
        self.state.lock().unwrap().calls.clone()
    }

    /// Every question put so far, in order.
    pub fn questions(&self) -> Vec<Value> {
        self.state.lock().unwrap().questions.clone()
    }
}

impl QuestionCarrier for ScriptedCarrier {
    fn desk(&self) -> Arc<cerebellum::cingulate_client::desk::ConsentDesk> {
        self.desk.clone()
    }
    fn live(
        &self,
    ) -> Result<
        cerebellum::cingulate_client::live_call::LiveCall,
        cerebellum::cingulate_client::live_call::NotLive,
    > {
        use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
        let stamp = ScopeStamp::new(
            subc_protocol::Principal::Reserved { module_id: "prefrontal-core".into() },
            "computer-test",
            1,
            ScopeKind::Head,
        )
        .with_attributes(ScopeAttributes::new().with_agent_id(Some(GRANTEE.into())))
        .with_owner_authorized(true);
        cerebellum::cingulate_client::live_call::LiveCall::from_inbound(
            Some(&stamp),
            &self.guard,
            Arc::new(cerebellum::computer_grants::AlwaysOpenRoute),
        )
    }
}

type Fixtures = Mutex<std::collections::BTreeMap<usize, std::sync::Weak<Mutex<ScriptState>>>>;
fn fixtures() -> &'static Fixtures {
    static FIXTURES: std::sync::OnceLock<Fixtures> = std::sync::OnceLock::new();
    FIXTURES.get_or_init(Default::default)
}

struct TemporaryRegistry(std::path::PathBuf);
impl cerebellum::cingulate_client::desk::RegistryStore for TemporaryRegistry {
    fn load(&self) -> Result<Vec<cerebellum::cingulate_client::desk::RaisedCard>, String> {
        cerebellum::cingulate_client::desk::FileRegistryStore::new(self.0.clone()).load()
    }
    fn save(&self, cards: &[cerebellum::cingulate_client::desk::RaisedCard]) -> Result<(), String> {
        cerebellum::cingulate_client::desk::FileRegistryStore::new(self.0.clone()).save(cards)
    }
}
impl Drop for TemporaryRegistry {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
        if let Some(root) = self.0.parent() { let _ = std::fs::remove_dir(root); }
    }
}

pub fn stamp(agent: &str) -> subc_protocol::scope::ScopeStamp {
    use subc_protocol::scope::{ScopeAttributes, ScopeKind, ScopeStamp};
    ScopeStamp::new(
        subc_protocol::Principal::Reserved { module_id: "prefrontal-core".into() },
        "browser-tests",
        1,
        ScopeKind::Head,
    )
    .with_attributes(ScopeAttributes::new().with_agent_id(Some(agent.into())).with_delegates(true))
    .with_owner_authorized(true)
}

struct FixtureOpener(Arc<Mutex<ScriptState>>);
struct FixtureRoute(Arc<Mutex<ScriptState>>);
impl cerebellum::cingulate_client::route::CingulateOpener for FixtureOpener {
    fn open<'a>(
        &'a self,
        _: &'a cerebellum::cingulate_client::live_call::LiveCall,
    ) -> cerebellum::cingulate_client::route::BoxFuture<
        'a,
        Result<
            Box<dyn cerebellum::cingulate_client::route::CingulateRoute>,
            cerebellum::cingulate_client::route::CallError,
        >,
    > {
        Box::pin(async {
            Ok(Box::new(FixtureRoute(self.0.clone()))
                as Box<
                    dyn cerebellum::cingulate_client::route::CingulateRoute,
                >)
        })
    }
}

fn fixture_record(id: &str, outcome: ScriptedAnswer) -> Value {
    match outcome {
        ScriptedAnswer::Answered(body) => {
            json!({"elicitation_id":id,"state":"answered","answered_choice_id":body["decision"]})
        }
        ScriptedAnswer::NoAnswer => json!({"elicitation_id":id,"state":"expired"}),
        ScriptedAnswer::NotPutToAnyone => json!({"elicitation_id":id,"state":"not_put_to_anyone"}),
        ScriptedAnswer::Undeliverable => json!({"elicitation_id":id,"state":"delivery_failed"}),
    }
}

impl cerebellum::cingulate_client::route::CingulateRoute for FixtureRoute {
    fn features(&self) -> Option<cerebellum::cingulate_client::features::CingulateFeatures> {
        Some(cerebellum::cingulate_client::features::CingulateFeatures {
            option_group: true,
            single_use: false,
            no_expiry: false,
        })
    }
    fn call<'a>(
        &'a mut self,
        method: &'a str,
        params: Value,
    ) -> cerebellum::cingulate_client::route::BoxFuture<
        'a,
        Result<Value, cerebellum::cingulate_client::route::CallError>,
    > {
        Box::pin(async move {
            self.0
                .lock()
                .unwrap()
                .calls
                .push((method.into(), params.clone()));
            let id = params["elicitation_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            match method {
                "consent.request" => {
                    let mut state = self.0.lock().unwrap();
                    if let Some(error) = state.request_error.take() {
                        return Err(error);
                    }
                    let namespace = if state.namespace.is_empty() { "computer" } else { state.namespace.as_str() };
                    let id = format!("el_{namespace}_{}", state.questions.len() + 1);
                    state.questions.push(json!({"id":id,"params":params}));
                    let record = state.queued.pop_front().map_or_else(
                        || json!({"elicitation_id":id,"state":"pending"}),
                        |answer| fixture_record(&id, answer),
                    );
                    state.records.insert(id.clone(), record);
                    Ok(json!({"elicitation_id":id}))
                }
                "consent.await" => {
                    let deferred = {
                        let mut state = self.0.lock().unwrap();
                        state.defer_awaits.then(|| {
                            let (sender, receiver) = tokio::sync::oneshot::channel();
                            state.deferred.push(sender);
                            receiver
                        })
                    };
                    if let Some(deferred) = deferred {
                        let _ = tokio::time::timeout(std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap()), deferred).await;
                        return Ok(self.0.lock().unwrap().records[&id].clone());
                    }
                    let waiting = {
                        let mut state = self.0.lock().unwrap();
                        let record = state.records[&id].clone();
                        if record["state"] == "not_put_to_anyone" {
                            return Err(cerebellum::cingulate_client::double::refusal(
                                "elicitation_requester_refused",
                            ));
                        }
                        if record["state"] == "delivery_failed" {
                            return Err(
                                cerebellum::cingulate_client::route::CallError::Transport {
                                    code: None,
                                },
                            );
                        }
                        if record["state"] != "pending" {
                            return Ok(record);
                        }
                        let (sender, receiver) = tokio::sync::oneshot::channel();
                        state.waiting.push_back((id.clone(), sender));
                        receiver
                    };
                    let wait =
                        std::time::Duration::from_millis(params["timeout_ms"].as_u64().unwrap());
                    let record = tokio::time::timeout(wait, waiting)
                        .await
                        .ok()
                        .and_then(Result::ok)
                        .unwrap_or_else(|| self.0.lock().unwrap().records[&id].clone());
                    match record["state"].as_str() {
                        Some("not_put_to_anyone") => {
                            Err(cerebellum::cingulate_client::double::refusal(
                                "elicitation_requester_refused",
                            ))
                        }
                        Some("delivery_failed") => {
                            Err(cerebellum::cingulate_client::route::CallError::Transport {
                                code: None,
                            })
                        }
                        _ => Ok(record),
                    }
                }
                "consent.get" | "consent.detach" | "consent.report_execution" => {
                    let mut record = self.0.lock().unwrap().records[&id].clone();
                    if method == "consent.detach" && record["state"] == "pending" {
                        record["detached"] = json!(true);
                    }
                    Ok(record)
                }
                "consent.withdraw" => {
                    let mut state = self.0.lock().unwrap();
                    let record = state.records.get_mut(&id).unwrap();
                    if record["state"] == "pending" {
                        record["state"] = json!("withdrawn");
                    }
                    Ok(record.clone())
                }
                "consent.answers" => Ok(
                    json!({"records":self.0.lock().unwrap().records.values().filter(|record| record["state"] != "pending").cloned().collect::<Vec<_>>(),"cursor":1}),
                ),
                "consent.ack" => Ok(json!({"cursor":1})),
                _ => panic!("unexpected consent method {method}"),
            }
        })
    }
}
