//! Call-time transcript metadata. No argument or reply object is retained here.

use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, Weak};
use std::time::Duration;

use cortexkit_role_tool_display::{DisplayKind, DisplayWrite, FieldKind, RecordSchema};
use serde_json::{json, Map, Value};
use subc_protocol::{Frame, FrameType, Principal};

use crate::egress::{request_id, RequestId};

#[cfg(test)]
mod tests;
mod transport;

pub(crate) use transport::DaemonDisplay;

pub(crate) fn schema() -> RecordSchema {
    RecordSchema::new(
        "cerebellum_call",
        1,
        BTreeMap::from([
            ("plane".into(), FieldKind::Code),
            ("action".into(), FieldKind::Code),
            ("site".into(), FieldKind::WebOrigin),
            ("app".into(), FieldKind::AppId),
            ("postsReturned".into(), FieldKind::Integer),
        ]),
    )
}

pub(crate) fn valid_for_delivery(write: &DisplayWrite) -> bool {
    // The published validators reject an entire record containing an empty
    // array, even though the fields we produce are scalars.
    match write.kind {
        DisplayKind::Record => {
            cortexkit_role_tool_display::schema::validate_record(&write.body, &schema())
        }
        DisplayKind::Completion => {
            cortexkit_role_tool_display::schema::validate_completion(&write.body, &schema())
        }
        _ => return false,
    }
    .is_ok()
}

type Future<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
/// The daemon catalog, read to recognise the display module that may call
/// `display.read`. Cerebellum never sends display records to that module: it
/// keeps each one in the display store and announces it on the bus.
pub(crate) trait Backend: Send + Sync {
    fn declarers(&self) -> Future<'_, Option<Vec<String>>>;
}

/// How long one catalog read may take, connection and authentication included.
const CATALOG_WINDOW: Duration = Duration::from_secs(3);
const DECLARER_TTL: Duration = Duration::from_secs(30);
/// How often one module left out of the cached catalog answer may make
/// cerebellum read the catalog again. A display module that restarts binds
/// within a second of its HELLO, and the cached answer may have been read by
/// another module's bind while it was away. So the first bind of an absent
/// module re-reads at once, whatever the answer's age, and its later binds
/// re-read at most this often.
const ABSENT_RECHECK_INTERVAL: Duration = Duration::from_secs(2);
const MAX_WAITING: usize = 16_384;
const MAX_RECENT_CONSENTS: usize = 16_384;
const MAX_RECENT_CALLS: usize = 65_536;
type Key = (String, String);

#[derive(Default)]
pub(crate) struct Records {
    pub(crate) events: Arc<crate::event_publish::Publisher>,
    backend: OnceLock<Arc<dyn Backend>>,
    declarers: Mutex<DeclarerCache>,
    metrics: ArmMetrics,
    state: Mutex<State>,
    /// Every write handed to the display store, in order, so tests can check
    /// record contents without reaching into the store.
    #[cfg(test)]
    recorded: Mutex<Vec<DisplayWrite>>,
}

#[derive(Default)]
struct ArmMetrics {
    armed: AtomicU64,
    unparsed: AtomicU64,
    no_principal: AtomicU64,
    no_schema_pin: AtomicU64,
    no_call_key: AtomicU64,
    invalid_origin: AtomicU64,
    invalid_key_or_pin: AtomicU64,
    duplicate: AtomicU64,
}

#[derive(Default)]
struct DeclarerCache {
    cached: Option<(tokio::time::Instant, Vec<String>)>,
    in_flight: Option<tokio::sync::watch::Receiver<Option<Vec<String>>>>,
    /// When each absent module last made the catalog be read again. Only
    /// non-first-party reserved principals binding to cerebellum reach it, so
    /// it holds a handful of module ids.
    absent_rechecked: HashMap<String, tokio::time::Instant>,
}

#[derive(Default)]
struct State {
    requests: HashMap<RequestId, Key>,
    calls: HashMap<Key, Tracked>,
    identities: std::collections::HashSet<Key>,
    seen_local_keys: std::collections::HashSet<Key>,
    recent_calls: VecDeque<(Key, Key)>,
    waiting_order: BTreeMap<u64, Key>,
    next_order: u64,
    consent_results: HashMap<String, &'static str>,
    consent_order: VecDeque<String>,
    display_principals: std::collections::HashSet<String>,
}

struct Tracked {
    order: u64,
    /// The wire request this call was armed for, so its index entry goes
    /// with the call directly instead of by scanning every tracked request.
    request: RequestId,
    runner: Principal,
    key: String,
    pin: String,
    fields: Map<String, Value>,
    timing: Arc<Timing>,
    replied: bool,
    held: bool,
    completion: Option<Map<String, Value>>,
    completed: bool,
    ask: Option<String>,
}

pub(crate) struct Timing {
    arrived: tokio::time::Instant,
    started: Mutex<Option<tokio::time::Instant>>,
    waits: Mutex<(Duration, Option<tokio::time::Instant>)>,
    queued: Mutex<(Duration, Option<tokio::time::Instant>)>,
    targets: Mutex<Map<String, Value>>,
    records: Weak<Records>,
    local: Key,
}

impl State {
    fn remove_call(&mut self, key: &Key) {
        if let Some(call) = self.calls.remove(key) {
            self.waiting_order.remove(&call.order);
            self.forget_request(call.request, key);
        }
    }

    /// Drop `request`'s index entry if it still names `key`; a reused
    /// correlation may already name a newer call.
    fn forget_request(&mut self, request: RequestId, key: &Key) {
        if self.requests.get(&request) == Some(key) {
            self.requests.remove(&request);
        }
    }
}

impl Timing {
    fn durations(&self) -> (Duration, Duration, Duration) {
        let start = self.started.lock().unwrap().unwrap_or(self.arrived);
        let waits = self.waits.lock().unwrap();
        let held = waits.0 + waits.1.map_or(Duration::ZERO, |start| start.elapsed());
        let queued = self.queued.lock().unwrap();
        let queued = queued.0 + queued.1.map_or(Duration::ZERO, |start| start.elapsed());
        (
            start.elapsed().saturating_sub(held).saturating_sub(queued),
            start.duration_since(self.arrived) + queued,
            held,
        )
    }
}

tokio::task_local! { pub(crate) static ACTIVE: Option<Arc<Timing>>; }

pub(crate) struct PersonWait(Option<Arc<Timing>>);
impl PersonWait {
    pub(crate) fn start() -> Self {
        let timing = ACTIVE.try_with(Clone::clone).ok().flatten();
        if let Some(timing) = &timing {
            timing.waits.lock().unwrap().1 = Some(tokio::time::Instant::now());
        }
        Self(timing)
    }
}
impl Drop for PersonWait {
    fn drop(&mut self) {
        if let Some(timing) = &self.0 {
            let mut waits = timing.waits.lock().unwrap();
            if let Some(start) = waits.1.take() {
                waits.0 += start.elapsed();
            }
        }
    }
}

fn ms(duration: Duration) -> i64 {
    duration.as_millis().min(i64::MAX as u128) as i64
}

pub(crate) struct QueueWait(Option<Arc<Timing>>);
impl QueueWait {
    pub(crate) fn start() -> Self {
        let timing = ACTIVE.try_with(Clone::clone).ok().flatten();
        if let Some(timing) = &timing {
            timing.queued.lock().unwrap().1 = Some(tokio::time::Instant::now());
        }
        Self(timing)
    }
}
impl Drop for QueueWait {
    fn drop(&mut self) {
        if let Some(timing) = &self.0 {
            let mut queued = timing.queued.lock().unwrap();
            if let Some(start) = queued.1.take() {
                queued.0 += start.elapsed();
            }
        }
    }
}

pub(crate) fn handoff_settle() -> Option<crate::management_bounds::HandoffSettle> {
    let timing = ACTIVE.try_with(Clone::clone).ok().flatten()?;
    Some(Arc::new(move |ending| {
        if let Some(records) = timing.records.upgrade() {
            records.completed(
                &timing.local.0,
                &timing.local.1,
                &json!({"outcome":ending.as_str()}),
            );
        }
        true
    }))
}

pub(crate) fn started() {
    let _ = ACTIVE.try_with(|timing| {
        if let Some(timing) = timing {
            *timing.started.lock().unwrap() = Some(tokio::time::Instant::now());
        }
    });
}

pub(crate) fn app(app: &str) {
    if cortexkit_role_tool_display::schema::validate_app_id(app) {
        let _ = ACTIVE.try_with(|timing| {
            if let Some(timing) = timing {
                timing
                    .targets
                    .lock()
                    .unwrap()
                    .insert("app".into(), json!(app));
            }
        });
    }
}

pub(crate) fn site(origin: &str) {
    if cortexkit_role_tool_display::schema::validate_web_origin(origin) {
        let _ = ACTIVE.try_with(|timing| {
            if let Some(timing) = timing {
                timing
                    .targets
                    .lock()
                    .unwrap()
                    .insert("site".into(), json!(origin));
            }
        });
    }
}

impl Records {
    pub(crate) fn metrics(&self) -> Value {
        json!({
            "armed": self.metrics.armed.load(Ordering::Relaxed),
            "unparsed": self.metrics.unparsed.load(Ordering::Relaxed),
            "noPrincipal": self.metrics.no_principal.load(Ordering::Relaxed),
            "noSchemaPin": self.metrics.no_schema_pin.load(Ordering::Relaxed),
            "noCallKey": self.metrics.no_call_key.load(Ordering::Relaxed),
            "invalidOrigin": self.metrics.invalid_origin.load(Ordering::Relaxed),
            "invalidKeyOrPin": self.metrics.invalid_key_or_pin.load(Ordering::Relaxed),
            "duplicate": self.metrics.duplicate.load(Ordering::Relaxed),
        })
    }

    pub(crate) fn with_events(events: Arc<crate::event_publish::Publisher>) -> Self {
        Self {
            events,
            ..Default::default()
        }
    }
    pub(crate) fn connect(&self, backend: Arc<dyn Backend>) {
        let _ = self.backend.set(backend);
    }

    /// Catalog presence counts even modules not yet ready to accept routes.
    pub(crate) async fn declarers(&self) -> Vec<String> {
        let Some(backend) = self.backend.get() else {
            return vec![];
        };
        loop {
            let (sender, mut receiver) = {
                let mut cache = self.declarers.lock().unwrap();
                if let Some((refreshed, modules)) = &cache.cached {
                    if refreshed.elapsed() < DECLARER_TTL {
                        return modules.clone();
                    }
                }
                if let Some(receiver) = cache
                    .in_flight
                    .as_ref()
                    .filter(|receiver| receiver.has_changed().is_ok())
                {
                    (None, receiver.clone())
                } else {
                    let (sender, receiver) = tokio::sync::watch::channel(None);
                    cache.in_flight = Some(receiver.clone());
                    (Some(sender), receiver)
                }
            };
            if let Some(sender) = sender {
                let answer = tokio::time::timeout(CATALOG_WINDOW, backend.declarers())
                    .await
                    .ok()
                    .flatten();
                let mut cache = self.declarers.lock().unwrap();
                cache.cached = answer
                    .as_ref()
                    .map(|modules| (tokio::time::Instant::now(), modules.clone()));
                let modules = answer.unwrap_or_default();
                self.state
                    .lock()
                    .unwrap()
                    .display_principals
                    .extend(modules.iter().cloned());
                // Current waiters share even failures; later calls retry them.
                cache.in_flight = None;
                let _ = sender.send(Some(modules.clone()));
                return modules;
            }
            if let Ok(answer) = receiver.wait_for(Option::is_some).await {
                return answer.as_ref().unwrap().clone();
            };
            // A cancelled reader drops its sender. A waiter takes over on retry.
        }
    }

    // Retain declarations across teardown and failed catalog refreshes. A display
    // module acting under another principal's scope may call only declared reads.
    pub(crate) fn known_display_principal(&self, principal: Option<&Principal>) -> bool {
        matches!(principal, Some(Principal::Reserved { module_id })
            if self.state.lock().unwrap().display_principals.contains(module_id))
    }

    pub(crate) async fn admits_view_reader(
        &self,
        principal: Option<&Principal>,
        target: &subc_protocol::RouteTarget,
    ) -> bool {
        let Some(Principal::Reserved { module_id }) = principal else {
            return false;
        };
        if !matches!(target, subc_protocol::RouteTarget::ToolProvider { module_id }
            | subc_protocol::RouteTarget::ManagementSurface { module_id } if module_id == "cerebellum")
        {
            return false;
        }
        let asked = tokio::time::Instant::now();
        if self.declarers().await.as_slice() == [module_id.as_str()] {
            return true;
        }
        self.expire_if_absent(module_id, asked)
            && self.declarers().await.as_slice() == [module_id.as_str()]
    }

    /// Drops a cached answer that leaves `module_id` out, so the caller reads
    /// the catalog again. It keeps the answer when it was read at or after
    /// `asked` (the caller's own read already saw the module absent), or when
    /// this module caused a re-read within [`ABSENT_RECHECK_INTERVAL`]. Returns
    /// whether it dropped it. Failed reads are never cached, so only a
    /// successful answer can be dropped here.
    fn expire_if_absent(&self, module_id: &str, asked: tokio::time::Instant) -> bool {
        let mut cache = self.declarers.lock().unwrap();
        let absent = cache.cached.as_ref().is_some_and(|(refreshed, modules)| {
            *refreshed < asked && !modules.iter().any(|module| module == module_id)
        });
        let recently = cache
            .absent_rechecked
            .get(module_id)
            .is_some_and(|at| at.elapsed() < ABSENT_RECHECK_INTERVAL);
        if !absent || recently {
            return false;
        }
        let now = tokio::time::Instant::now();
        cache
            .absent_rechecked
            .retain(|_, at| now.duration_since(*at) < ABSENT_RECHECK_INTERVAL);
        cache.absent_rechecked.insert(module_id.to_owned(), now);
        cache.cached = None;
        true
    }

    pub(crate) async fn read(
        &self,
        principal: Option<&Principal>,
        params: Value,
    ) -> Result<Vec<u8>, subc_protocol::ErrorBody> {
        use cortexkit_role_tool_display::{
            DisplayRead, DISPLAY_READ_DENIED, DISPLAY_RECORD_UNKNOWN, NOT_READY,
        };
        let target = subc_protocol::RouteTarget::ManagementSurface {
            module_id: "cerebellum".into(),
        };
        if !self.admits_view_reader(principal, &target).await {
            return Err(subc_protocol::ErrorBody::new(
                DISPLAY_READ_DENIED,
                "display reads are restricted to the discovered display server",
            ));
        }
        let read: DisplayRead = serde_json::from_value(params)
            .map_err(|_| cortexkit_role_tool_display::InvalidParams::new("record_id").refusal())?;
        read.validate().map_err(|error| error.refusal())?;
        self.events
            .display_read(&read.record_id)
            .await
            .map_err(|_| subc_protocol::ErrorBody::new(NOT_READY, "provider is not ready"))?
            .ok_or_else(|| {
                subc_protocol::ErrorBody::new(DISPLAY_RECORD_UNKNOWN, "display record is unknown")
            })
    }

    pub(crate) fn arm(
        self: &Arc<Self>,
        frame: &Frame,
        facts: &crate::AcceptedBindFacts,
    ) -> Option<Arc<Timing>> {
        let request: subc_protocol::tool_call::ToolCallRequest =
            match serde_json::from_slice(&frame.body) {
                Ok(request) => request,
                Err(_) => {
                    // Management routes carry a different envelope, so failing
                    // to decode one as a tool call is not a malformed caller.
                    if facts.surface == crate::RouteSurface::Tools {
                        self.metrics.unparsed.fetch_add(1, Ordering::Relaxed);
                    }
                    return None;
                }
            };
        let plane = match request.name.as_str() {
            crate::flat_tools::BROWSER_USE => "browser",
            crate::flat_tools::COMPUTER_USE => "computer",
            _ => return None,
        };
        let (runner, key, pin) = if let Some(origin) = request.origin {
            if subc_protocol::tool_call::validate_call_origin(&origin).is_err() {
                self.metrics.invalid_origin.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let Some(pin) = origin.schema_pin else {
                self.metrics.no_schema_pin.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            (origin.carrier, origin.call_key, pin)
        } else {
            let Some(principal) = facts.principal.clone() else {
                self.metrics.no_principal.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            let Some(key) = request.call_key.clone() else {
                self.metrics.no_call_key.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            let Some(pin) = request.schema_pin else {
                self.metrics.no_schema_pin.fetch_add(1, Ordering::Relaxed);
                return None;
            };
            (principal, key, pin)
        };
        if subc_protocol::tool_call::validate_call_key(&key).is_err()
            || subc_protocol::tool_call::validate_schema_pin(&pin).is_err()
        {
            self.metrics
                .invalid_key_or_pin
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let local = (
            crate::journal::call_records::principal_label(facts.principal.as_ref()),
            request.call_key.unwrap_or_else(|| key.clone()),
        );
        let identity = (serde_json::to_string(&runner).ok()?, key.clone());
        let mut state = self.state.lock().unwrap();
        if state.calls.contains_key(&local)
            || state.seen_local_keys.contains(&local)
            || state.identities.contains(&identity)
        {
            self.metrics.duplicate.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        // Bound ID-only duplicate suppression with a recent FIFO window. For a
        // replay older than this window, the display store is the backstop: a
        // record's id is derived from its runner, call key and kind, so the
        // replay lands on the same id instead of announcing a second record.
        if state.recent_calls.len() >= MAX_RECENT_CALLS {
            if let Some((identity, local)) = state.recent_calls.pop_front() {
                state.identities.remove(&identity);
                state.seen_local_keys.remove(&local);
            }
        }
        state
            .recent_calls
            .push_back((identity.clone(), local.clone()));
        state.identities.insert(identity);
        state.seen_local_keys.insert(local.clone());
        while state.calls.len() >= MAX_WAITING {
            let Some((_, oldest)) = state.waiting_order.pop_first() else {
                break;
            };
            state.remove_call(&oldest);
        }
        let order = state.next_order;
        state.next_order += 1;
        state.waiting_order.insert(order, local.clone());
        let timing = Arc::new(Timing {
            arrived: tokio::time::Instant::now(),
            started: Mutex::new(None),
            waits: Mutex::new((Duration::ZERO, None)),
            queued: Mutex::new((Duration::ZERO, None)),
            targets: Mutex::new(Map::new()),
            records: Arc::downgrade(self),
            local: local.clone(),
        });
        state.requests.insert(request_id(frame), local.clone());
        state.calls.insert(
            local,
            Tracked {
                order,
                request: request_id(frame),
                runner,
                key,
                pin,
                fields: fields(plane, &request.arguments),
                timing: Arc::clone(&timing),
                replied: false,
                held: false,
                completion: None,
                completed: false,
                ask: None,
            },
        );
        self.metrics.armed.fetch_add(1, Ordering::Relaxed);
        Some(timing)
    }

    /// Freeze only the permitted facts before the writer releases the frame bytes.
    pub(crate) fn prepare(&self, frame: &Frame) -> Option<Prepared> {
        let key = self
            .state
            .lock()
            .unwrap()
            .requests
            .get(&request_id(frame))
            .cloned()?;
        let body = serde_json::from_slice::<Value>(&frame.body).ok()?;
        let body = body.get("structuredContent").unwrap_or(&body);
        let (outcome, reason) = outcome(body, frame.header.ty == FrameType::Error);
        Some(Prepared {
            key,
            request: request_id(frame),
            outcome,
            reason: reason.map(str::to_owned),
            posts: body
                .get("posts_returned")
                .and_then(Value::as_i64)
                .filter(|n| *n >= 0),
            ask: body
                .get("ask_id")
                .and_then(Value::as_str)
                .filter(|id| cortexkit_role_tool_display::schema::validate_id(id))
                .map(str::to_owned),
            site: ["url", "origin"]
                .into_iter()
                .filter_map(|key| body[key].as_str())
                .find_map(crate::classification::canonical_origin_from_url)
                .filter(|site| cortexkit_role_tool_display::schema::validate_web_origin(site)),
        })
    }

    /// Called only after the connection writer has flushed the terminal frame.
    pub(crate) fn delivered(self: &Arc<Self>, prepared: Prepared) {
        let writes = {
            let mut state = self.state.lock().unwrap();
            let key = prepared.key;
            state.forget_request(prepared.request, &key);
            let consent_result = prepared
                .ask
                .as_ref()
                .and_then(|ask| state.consent_results.get(ask).copied());
            let Some(call) = state.calls.get_mut(&key) else {
                return;
            };
            if call.replied {
                return;
            }
            call.replied = true;
            call.ask = prepared.ask;
            call.fields
                .extend(call.timing.targets.lock().unwrap().clone());
            if call
                .fields
                .get("plane")
                .is_some_and(|plane| plane == "browser")
            {
                if let Some(site) = prepared.site {
                    call.fields.entry("site").or_insert(json!(site));
                }
            }
            if let Some(ending) = consent_result.filter(|_| !call.completed) {
                call.completed = true;
                call.completion = completion_body(call, &consent_result_body(ending));
            }
            let mut record = call.fields.clone();
            let (outcome, reason) = (prepared.outcome, prepared.reason);
            call.held = outcome == "held";
            record.insert("outcome".into(), json!(outcome));
            if let Some(reason) = reason {
                record.insert("reason".into(), json!(reason));
            }
            let (duration, queued, held) = call.timing.durations();
            record.insert("durationMs".into(), json!(ms(duration)));
            record.insert("queuedMs".into(), json!(ms(queued)));
            if !held.is_zero() {
                record.insert("heldMs".into(), json!(ms(held)));
            }
            if let Some(posts) = prepared.posts {
                record.insert("postsReturned".into(), json!(posts));
            }
            let mut writes = vec![call.write(DisplayKind::Record, record)];
            if call.held {
                if let Some(completion) = call.completion.take() {
                    writes.push(call.write(DisplayKind::Completion, completion));
                }
            }
            if !call.held || call.completed {
                state.remove_call(&key);
            }
            writes
        };
        for write in writes {
            self.record(write);
        }
    }

    pub(crate) fn completed(self: &Arc<Self>, principal: &str, key: &str, result: &Value) {
        let write = {
            let mut state = self.state.lock().unwrap();
            let key = (principal.into(), key.into());
            let Some(call) = state.calls.get_mut(&key) else {
                return;
            };
            if call.completed {
                return;
            }
            call.completed = true;
            let body = completion_body(call, result);
            if call.replied {
                let write = body
                    .filter(|_| call.held)
                    .map(|body| call.write(DisplayKind::Completion, body));
                state.remove_call(&key);
                write
            } else {
                call.completion = body;
                None
            }
        };
        if let Some(write) = write {
            self.record(write);
        }
    }

    pub(crate) fn consent_completed(self: &Arc<Self>, ask: &str, ending: &'static str) {
        let keys = {
            let mut state = self.state.lock().unwrap();
            if !state.consent_results.contains_key(ask) {
                if state.consent_results.len() >= MAX_RECENT_CONSENTS {
                    if let Some(oldest) = state.consent_order.pop_front() {
                        state.consent_results.remove(&oldest);
                    }
                }
                state.consent_results.insert(ask.into(), ending);
                state.consent_order.push_back(ask.into());
            }
            state
                .calls
                .iter()
                .filter(|(_, call)| call.ask.as_deref() == Some(ask))
                .map(|(key, _)| key.clone())
                .collect::<Vec<_>>()
        };
        for (principal, key) in keys {
            self.completed(&principal, &key, &consent_result_body(ending));
        }
    }

    /// Hands a finished record to the display store, which announces it on the
    /// bus for the display module to fetch with `display.read`. Storing never
    /// waits: a record the store cannot take is dropped and counted there, so
    /// no display failure can delay or fail the tool call.
    fn record(&self, write: DisplayWrite) {
        if !valid_for_delivery(&write) {
            return;
        }
        #[cfg(test)]
        self.recorded.lock().unwrap().push(write.clone());
        self.events.tool_display(&write);
    }

    #[cfg(test)]
    pub(crate) fn recorded(&self) -> std::sync::MutexGuard<'_, Vec<DisplayWrite>> {
        self.recorded.lock().unwrap()
    }
}

pub(crate) struct Prepared {
    key: Key,
    request: RequestId,
    outcome: &'static str,
    reason: Option<String>,
    posts: Option<i64>,
    ask: Option<String>,
    site: Option<String>,
}

fn consent_result_body(ending: &str) -> Value {
    json!({"outcome":"not_started","detail":{"consent":ending}})
}

fn completion_body(call: &Tracked, result: &Value) -> Option<Map<String, Value>> {
    let mut body = call.fields.clone();
    body.extend(call.timing.targets.lock().unwrap().clone());
    if result["reason"] == "scope_ended" {
        body.insert("outcome".into(), json!("error"));
        body.insert("reason".into(), json!("scope_ended"));
        return Some(body);
    }
    // ConsentDrain::run_recording maps Granted, Declined, NoAnswer and Withdrawn
    // to CallRecords::finish_consent, the sole caller of consent_completed.
    // Its durable finish_held_locked path supplies the same detail.consent,
    // including consent before login/capture. Approval grants permission but
    // never runs the original action; its held record remains true without a
    // completion, and a retry gets its own call record.
    if let Some(ending) = result["detail"]["consent"].as_str() {
        let reason = match ending {
            "approved" => return None,
            "denied" => "consent_declined",
            "expired" => "consent_expired",
            "withdrawn" => "consent_withdrawn",
            _ => return None,
        };
        body.insert("outcome".into(), json!("error"));
        body.insert("reason".into(), json!(reason));
        return Some(body);
    }
    // finish_handoff/resume_handoff and handoff_settle report completed login
    // work, not permission decisions. Closing that work without observing login
    // is an error even though closed_by_caller is a normal success reply elsewhere.
    if result["outcome"] == "closed_by_caller" {
        body.insert("outcome".into(), json!("error"));
        body.insert("reason".into(), json!("closed_by_caller"));
        return Some(body);
    }
    let (outcome, reason) = outcome(result, false);
    body.insert("outcome".into(), json!(outcome));
    if let Some(reason) = reason {
        body.insert("reason".into(), json!(reason));
    }
    Some(body)
}

impl Tracked {
    fn write(&self, kind: DisplayKind, body: Map<String, Value>) -> DisplayWrite {
        DisplayWrite::new(self.runner.clone(), &self.key, kind, &self.pin, body)
    }
}

fn fields(plane: &str, args: &Value) -> Map<String, Value> {
    let mut fields = Map::from_iter([("plane".into(), json!(plane))]);
    // Match known actions, never copy a caller's arbitrary string as a code.
    if let Some(action) = args["action"].as_str().filter(|action| {
        matches!(
            *action,
            "launch"
                | "open_tab"
                | "claim_tab"
                | "status"
                | "close"
                | "navigate"
                | "snapshot"
                | "screenshot"
                | "scroll"
                | "click"
                | "press_key"
                | "type"
                | "click_point"
                | "fill_login"
                | "open_grant"
                | "present"
                | "resume"
                | "import_login"
                | "capture_login"
                | "revoke_access"
                | "read_state"
                | "press_element"
                | "press_point"
                | "write_text"
                | "keys"
                | "takeover_move"
                | "takeover_drag"
                | "takeover_scroll"
                | "wait"
                | "list_apps"
                | "open_app"
        )
    }) {
        fields.insert("action".into(), json!(action));
    }
    if plane == "browser" {
        if let Some(site) = ["url", "origin", "login_url", "fetch_url"]
            .into_iter()
            .filter_map(|key| args[key].as_str())
            .find_map(crate::classification::canonical_origin_from_url)
            .filter(|site| cortexkit_role_tool_display::schema::validate_web_origin(site))
        {
            fields.insert("site".into(), json!(site));
        }
    } else if let Some(app) = args["app"]
        .as_str()
        .filter(|app| cortexkit_role_tool_display::schema::validate_app_id(app))
    {
        // `app` names an id; a human `target` name is omitted until resolved.
        fields.insert("app".into(), json!(app));
    }
    fields
}

fn outcome(body: &Value, error_frame: bool) -> (&'static str, Option<&str>) {
    let code = body["outcome"].as_str();
    // Emitted by terminal_arbiter, user_browser, and computer_capability:
    // these codes report uncertainty, never a confirmed partial success.
    if matches!(
        code,
        Some(
            "dispatch_outcome_unknown"
                | "outcome_unknown"
                | "delivery_unconfirmed"
                | "effect_indeterminate"
                | "indeterminate"
        )
    ) {
        return ("partial", Some("outcome_unknown"));
    }
    if error_frame || body["isError"] == true {
        return (
            "error",
            code.or_else(|| body["code"].as_str())
                .filter(|code| cortexkit_role_tool_display::schema::validate_code(code)),
        );
    }
    match code {
        Some("consent_pending") => ("held", Some("consent")),
        Some("login_pending" | "presented" | "capture_pending") => ("held", Some("login_handoff")),
        Some("installed_list_partial") => ("partial", None),
        Some(code) if crate::tool_result::is_success(code) => ("success", None),
        _ => (
            "error",
            code.filter(|code| cortexkit_role_tool_display::schema::validate_code(code)),
        ),
    }
}

pub(crate) type WeakRecords = Weak<Records>;
