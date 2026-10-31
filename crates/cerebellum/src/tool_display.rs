//! Call-time transcript metadata. No argument or reply object is retained here.

use std::collections::{BTreeMap, HashMap};
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

type Future<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;
pub(crate) trait Backend: Send + Sync {
    fn declarers(&self) -> Future<'_, Option<Vec<String>>>;
    fn write<'a>(&'a self, module: &'a str, write: DisplayWrite) -> Future<'a, bool>;
}

const WRITE_WINDOW: Duration = Duration::from_secs(3);
// Keep first-write tombstones for the process lifetime. If this bounded table
// fills, drop new display metadata rather than evicting a key and writing it twice.
const MAX_TRACKED: usize = 16_384;
type Key = (String, String);

#[derive(Default)]
pub(crate) struct Records {
    backend: OnceLock<Arc<dyn Backend>>,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    requests: HashMap<RequestId, Key>,
    calls: HashMap<Key, Tracked>,
    identities: std::collections::HashSet<Key>,
    consent_results: HashMap<String, &'static str>,
    display_principals: std::collections::HashSet<String>,
}

struct Tracked {
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
    pub(crate) fn connect(&self, backend: Arc<dyn Backend>) {
        let _ = self.backend.set(backend);
    }

    /// Catalog presence counts even modules not yet ready to accept routes.
    pub(crate) async fn declarers(&self) -> Vec<String> {
        let Some(backend) = self.backend.get() else {
            return vec![];
        };
        let modules = tokio::time::timeout(WRITE_WINDOW, backend.declarers())
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
        self.state
            .lock()
            .unwrap()
            .display_principals
            .extend(modules.iter().cloned());
        modules
    }

    // Retain declarations across teardown and failed catalog refreshes. A display
    // module acting under another principal's scope may call only declared reads.
    pub(crate) fn known_display_principal(&self, principal: Option<&Principal>) -> bool {
        matches!(principal, Some(Principal::Reserved { module_id })
            if self.state.lock().unwrap().display_principals.contains(module_id))
    }

    pub(crate) fn arm(
        self: &Arc<Self>,
        frame: &Frame,
        facts: &crate::AcceptedBindFacts,
    ) -> Option<Arc<Timing>> {
        let request: subc_protocol::tool_call::ToolCallRequest =
            serde_json::from_slice(&frame.body).ok()?;
        let plane = match request.name.as_str() {
            crate::flat_tools::BROWSER_USE => "browser",
            crate::flat_tools::COMPUTER_USE => "computer",
            _ => return None,
        };
        let (runner, key, pin) = if let Some(origin) = request.origin {
            subc_protocol::tool_call::validate_call_origin(&origin).ok()?;
            (origin.carrier, origin.call_key, origin.schema_pin?)
        } else {
            (
                facts.principal.clone()?,
                request.call_key.clone()?,
                request.schema_pin?,
            )
        };
        subc_protocol::tool_call::validate_call_key(&key).ok()?;
        subc_protocol::tool_call::validate_schema_pin(&pin).ok()?;
        let local = (
            crate::journal::call_records::principal_label(facts.principal.as_ref()),
            request.call_key.unwrap_or_else(|| key.clone()),
        );
        let identity = (serde_json::to_string(&runner).ok()?, key.clone());
        let mut state = self.state.lock().unwrap();
        if state.calls.contains_key(&local)
            || state.identities.len() >= MAX_TRACKED
            || !state.identities.insert(identity)
        {
            return None;
        }
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
            outcome,
            reason,
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
            state.requests.retain(|_, local| local != &key);
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
                call.completion = Some(completion_body(call, &consent_result_body(ending)));
            }
            let mut record = call.fields.clone();
            let (outcome, reason) = (prepared.outcome, prepared.reason);
            call.held = outcome == "held";
            record.insert("outcome".into(), json!(outcome));
            if let Some(reason) = reason {
                record.insert("reason".into(), json!(reason));
            }
            let start = call
                .timing
                .started
                .lock()
                .unwrap()
                .unwrap_or(call.timing.arrived);
            let waits = call.timing.waits.lock().unwrap();
            let held = waits.0 + waits.1.map_or(Duration::ZERO, |start| start.elapsed());
            let queued = call.timing.queued.lock().unwrap();
            let queued = queued.0 + queued.1.map_or(Duration::ZERO, |start| start.elapsed());
            record.insert(
                "durationMs".into(),
                json!(ms(start
                    .elapsed()
                    .saturating_sub(held)
                    .saturating_sub(queued))),
            );
            record.insert(
                "queuedMs".into(),
                json!(ms(start.duration_since(call.timing.arrived) + queued)),
            );
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
            writes
        };
        for write in writes {
            self.spawn(write);
        }
    }

    pub(crate) fn completed(self: &Arc<Self>, principal: &str, key: &str, result: &Value) {
        let write = {
            let mut state = self.state.lock().unwrap();
            let Some(call) = state.calls.get_mut(&(principal.into(), key.into())) else {
                return;
            };
            if call.completed {
                return;
            }
            call.completed = true;
            let body = completion_body(call, result);
            if call.replied && call.held {
                Some(call.write(DisplayKind::Completion, body))
            } else {
                call.completion = Some(body);
                None
            }
        };
        if let Some(write) = write {
            self.spawn(write);
        }
    }

    pub(crate) fn consent_completed(self: &Arc<Self>, ask: &str, ending: &'static str) {
        let keys = {
            let mut state = self.state.lock().unwrap();
            if state.consent_results.len() < MAX_TRACKED {
                state.consent_results.entry(ask.into()).or_insert(ending);
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

    fn spawn(self: &Arc<Self>, write: DisplayWrite) {
        // The published validators reject an entire record containing an empty
        // array. Validate before scheduling, even though our fields are scalars.
        let valid = match write.kind {
            DisplayKind::Record => {
                cortexkit_role_tool_display::schema::validate_record(&write.body, &schema())
            }
            DisplayKind::Completion => {
                cortexkit_role_tool_display::schema::validate_completion(&write.body, &schema())
            }
            _ => return,
        };
        if valid.is_err() {
            return;
        }
        let Some(backend) = self.backend.get().cloned() else {
            return;
        };
        // Bounded exception to live-call-only outbound routes: after reply flush,
        // open a fresh display route for this one write, then close it. No standing
        // connection, retry, or display failure can delay or fail the tool call.
        tokio::spawn(async move {
            let _ = tokio::time::timeout(WRITE_WINDOW, async {
                let modules = backend.declarers().await?;
                if let [module] = modules.as_slice() {
                    let _ = backend.write(module, write).await;
                }
                Some(())
            })
            .await;
        });
    }
}

pub(crate) struct Prepared {
    key: Key,
    outcome: &'static str,
    reason: Option<&'static str>,
    posts: Option<i64>,
    ask: Option<String>,
    site: Option<String>,
}

fn consent_result_body(ending: &str) -> Value {
    // Approval changes permission, not the old action's context. The original
    // action remains not_started, and the caller must make a fresh call to run it.
    json!({"outcome":if ending == "approved" { "not_started" } else { ending }})
}

fn completion_body(call: &Tracked, result: &Value) -> Map<String, Value> {
    let mut body = call.fields.clone();
    body.extend(call.timing.targets.lock().unwrap().clone());
    let (outcome, reason) = outcome(result, false);
    body.insert("outcome".into(), json!(outcome));
    if let Some(reason) = reason {
        body.insert("reason".into(), json!(reason));
    }
    body
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

fn outcome(body: &Value, error_frame: bool) -> (&'static str, Option<&'static str>) {
    match body["outcome"].as_str() {
        Some("consent_pending") => ("held", Some("consent")),
        Some("login_pending" | "presented" | "capture_pending") => ("held", Some("login_handoff")),
        Some(
            "partial"
            | "partially_dispatched"
            | "dispatch_outcome_unknown"
            | "outcome_unknown"
            | "delivery_unconfirmed"
            | "effect_indeterminate"
            | "indeterminate",
        ) => ("partial", None),
        Some("timed_out" | "timeout" | "deadline_expired") => ("error", Some("timed_out")),
        Some("cancelled" | "turn_stopped") => ("error", Some("cancelled")),
        Some("denied" | "permission_denied") => ("error", Some("permission_denied")),
        Some("not_started") => ("error", Some("consent")),
        Some("installed_list_partial") => ("partial", None),
        Some(code) if !error_frame && crate::tool_result::is_success(code) => ("success", None),
        Some(
            "ok" | "success" | "launched" | "closed" | "navigated" | "clicked" | "typed" | "read"
            | "captured" | "dispatched" | "changed" | "unchanged" | "login_observed" | "stored"
            | "imported" | "approved" | "consent_approved" | "resumed" | "done",
        ) if !error_frame => ("success", None),
        _ if body["isError"] == true || error_frame || body.get("outcome").is_some() => {
            ("error", None)
        }
        _ => ("success", None),
    }
}

pub(crate) type WeakRecords = Weak<Records>;
