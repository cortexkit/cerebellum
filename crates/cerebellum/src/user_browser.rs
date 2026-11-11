//! Policy for the person's Chrome, separate from owned browser processes.
//!
//! The bridge carries version-one CDP plans. Metadata reads establish the
//! committed document without returning page content. Authorized captures use
//! the pipe driver's AX traversal, DOM classifier and state-text renderer.
//! Every input step is a separate plan carrying the last authorized read's
//! interaction epoch; the extension rechecks it and group membership atomically
//! before dispatch. No path in this adapter closes a tab or terminates Chrome.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Deserialize;
use serde_json::{json, Value};
use subc_protocol::Frame;
use tokio::sync::mpsc;

use crate::authorization::{self, Action, HazardClass, Severity};
use crate::browser::dom_layout::{self, DomLandmark};
use crate::browser::navigation::{classify_flattened_document, snapshot_from_capture};
use crate::browser::state_text::{self, Filters, RenderInput, Zoom};
use crate::browser_standing_grants::{always_subject, RevokeTarget, StandingBrowserGrants};
use crate::cingulate_client::card::{consent_request, CardKind};
use crate::cingulate_client::desk::{Apply, ApplyFailed, Ending, InCall, RaisedCard};
use crate::cingulate_client::subject;
use crate::cingulate_client::wire::Record;
use crate::classification::{
    canonical_grant_origin, canonical_origin_from_url, NonTypeClassificationRecord,
};
use crate::consent_drain::{AppliedSettlement, ConsentEffects};
use crate::snapshot_store::{BackendNodeIdentity, CommittedDocument, FrameDocument};
use crate::user_browser_bridge::{Route, Terminal, UserBrowserBridge};
use crate::{AcceptedBindFacts, CancelHandle, Planes};

/// Bound the in-call site-card wait. If the person has not answered, detach the
/// card so a later admitted session call can apply the answer without holding work.
pub(crate) const CONSENT_DEADLINE: Duration = Duration::from_secs(120);
const MAX_SNAPSHOTS: usize = 64;
pub(crate) const NAVIGATION_READ_DEADLINE: Duration = Duration::from_secs(30);
/// How long a snapshot or screenshot waits for the page's interaction
/// observer before refusing `observer_unavailable`. After a document commits,
/// the extension injects its observer into the new document and into each
/// child frame as that frame commits; a read sees the observer only once every
/// live frame answers. That normally takes well under a second after a commit,
/// so two seconds is ample, and a program, which cannot sleep, needs the read
/// itself to wait rather than refuse at once. The wait spends the action's own
/// work allowance: the action deadline still ends the call on time.
const OBSERVER_WAIT: Duration = Duration::from_secs(2);
/// The pause between document reads while waiting for the observer. Each read
/// is a whole extension plan (a debugger attach and detach), so poll at a
/// modest rate rather than back to back.
const OBSERVER_POLL: Duration = Duration::from_millis(50);

// A method the extension permits is not necessarily safe to call a read when
// choosing a timeout reply. Use the separate fixed set so admitting a new
// method cannot silently hide a possible mutation from the caller.
// The shared JSON explicitly includes debugger-domain enables and frame/DOM
// queries: they observe pages without changing them, even in a child session.
// Unknown methods still count as mutations rather than inheriting that policy.
static TERMINAL_READ_ONLY_METHODS: std::sync::LazyLock<Vec<String>> =
    std::sync::LazyLock::new(|| {
        serde_json::from_str(include_str!(
            "../../../extension/terminal-read-only-methods.json"
        ))
        .expect("checked-in read-only method set is valid JSON")
    });

pub(super) fn mutating_plan(command: &Value) -> bool {
    match command["action"].as_str() {
        Some("status") => false,
        Some("cdp") => command["commands"]
            .as_array()
            .is_none_or(|commands| mutating_commands(commands)),
        _ => true,
    }
}

fn mutating_commands(commands: &[Value]) -> bool {
    commands.iter().any(|command| {
        let method = command["method"].as_str().unwrap_or_default();
        !TERMINAL_READ_ONLY_METHODS.iter().any(|read| read == method)
            && !(method == "Runtime.callFunctionOn"
                && command["params"]["functionDeclaration"] == functions::HAS_FOCUS)
    })
}

tokio::task_local! {
    static POPUP_SEEN: Cell<bool>;
    pub(super) static EXECUTION: Arc<UserExecution>;
    pub(super) static EXECUTION_PERMITS: Arc<crate::blocking_permits::CallPermits>;
}

// Bind plans to the document being read or acted on. Reference input keeps its
// saved snapshot's generation: internal classification reads must not lend a
// repaired observer's baseline to that older snapshot.
fn bind_observer_continuity(continuity: u64) {
    let _ = EXECUTION.try_with(|execution| {
        execution
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .observer_continuity = Some(continuity);
    });
}

#[derive(Default)]
struct ExecutionState {
    stopped: bool,
    in_flight: bool,
    quarantined: bool,
    held: bool,
    observer_continuity: Option<u64>,
}

// Permission waits pause work only for time actually spent waiting. An unused
// permission allowance must not become extra time for slow extension plans.
struct WorkClock {
    work_end: tokio::time::Instant,
    call_end: tokio::time::Instant,
    parked: Duration,
    park_left: Duration,
    parking: Option<tokio::time::Instant>,
}

// A detached bridge task keeps both its quarantine cell and capacity alive.
// The terminal hook only locks this small cell, never the target registry.
pub(super) struct UserExecution {
    route: Route,
    tab: Option<String>,
    action: String,
    state: Mutex<ExecutionState>,
    done: tokio::sync::Notify,
    clock: Mutex<WorkClock>,
    clock_changed: tokio::sync::Notify,
}

impl UserExecution {
    pub(super) fn deadline(&self) -> tokio::time::Instant {
        let clock = self.clock.lock().unwrap();
        let pending = if clock.parking.is_some() {
            CONSENT_DEADLINE.min(clock.park_left)
        } else {
            Duration::ZERO
        };
        (clock.work_end + clock.parked + pending).min(clock.call_end)
    }

    async fn expired(&self) {
        loop {
            let changed = self.clock_changed.notified();
            tokio::select! {
                _ = changed => {},
                _ = tokio::time::sleep_until(self.deadline()) => {
                    if tokio::time::Instant::now() >= self.deadline() { return; }
                }
            }
        }
    }

    fn park(self: &Arc<Self>) -> ConsentPark {
        self.clock.lock().unwrap().parking = Some(tokio::time::Instant::now());
        self.clock_changed.notify_one();
        ConsentPark(Arc::clone(self))
    }

    pub(super) fn begin(&self, held: bool) {
        let mut state = self.state.lock().unwrap();
        state.in_flight = true;
        state.held = held;
    }

    pub(super) fn finish(&self, safe: bool) {
        let mut state = self.state.lock().unwrap();
        state.in_flight = false;
        state.quarantined = !safe;
        state.held &= !safe;
        self.done.notify_waiters();
    }

    fn stop(&self) {
        let mut state = self.state.lock().unwrap();
        state.stopped = true;
        state.quarantined |= state.in_flight;
    }

    pub(super) fn stopped(&self) -> bool {
        self.state.lock().unwrap().stopped
    }

    pub(super) fn release_receipt(
        self: &Arc<Self>,
        terminal: &crate::TerminalArbiter,
        permits: &crate::blocking_permits::CallPermits,
    ) {
        let Some(permit) = permits.take_release() else {
            return;
        };
        let watch = Arc::clone(self);
        terminal.set_release(async move {
            let _permit = permit;
            loop {
                let done = watch.done.notified();
                {
                    let state = watch.state.lock().unwrap();
                    if !state.in_flight {
                        return if state.held {
                            crate::HeldState::Unknown
                        } else {
                            crate::HeldState::Released
                        };
                    }
                }
                done.await;
            }
        });
    }
}

struct ConsentPark(Arc<UserExecution>);

impl Drop for ConsentPark {
    fn drop(&mut self) {
        let mut clock = self.0.clock.lock().unwrap();
        if let Some(start) = clock.parking.take() {
            let spent = start.elapsed().min(CONSENT_DEADLINE).min(clock.park_left);
            clock.parked += spent;
            clock.park_left -= spent;
        }
        self.0.clock_changed.notify_one();
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TabIdentity {
    tab: String,
    claimed: bool,
    handed: bool,
    interaction_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inventory {
    tabs: Vec<TabIdentity>,
    connection_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Claimed {
    tab: String,
    interaction_epoch: u64,
    connection_epoch: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CdpError {
    code: i64,
    message: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CommandResult {
    Result(Success),
    Error(Failure),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Success {
    result: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    error: CdpError,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanReply {
    tab: String,
    results: Vec<CommandResult>,
    interaction_epoch: u64,
    observer_available: bool,
    observer_continuity: u64,
    connection_epoch: u64,
    #[serde(default)]
    popup_activated_briefly: bool,
    #[serde(default)]
    frame_mappings: Vec<FrameMapping>,
    #[serde(default)]
    interaction_cause: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FrameMapping {
    frame_id: String,
    parent_id: Option<String>,
    loader_id: String,
    session_id: String,
    url: String,
    web_navigation_frame_id: Option<u64>,
    document_id: Option<String>,
    unreadable_reason: Option<FrameReadFailure>,
}

#[derive(Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum FrameReadFailure {
    Ambiguous,
    Stale,
}

impl FrameReadFailure {
    fn label(self) -> &'static str {
        match self {
            Self::Ambiguous => "ambiguous",
            Self::Stale => "stale",
        }
    }

    fn refusal(self) -> Value {
        refusal(&format!("frame_{}", self.label()))
    }

    fn from_reply(reply: &Value) -> Option<Self> {
        match reply["reason"].as_str()? {
            "frame_ambiguous" => Some(Self::Ambiguous),
            "frame_stale" | "frame_changed" | "cdp_error" => Some(Self::Stale),
            _ => None,
        }
    }
}

#[derive(Clone)]
struct ShownRef {
    identity: BackendNodeIdentity,
    frame: FrameDocument,
    classification: Option<NonTypeClassificationRecord>,
    role_name: Option<(String, String)>,
}

#[derive(Clone)]
struct Image {
    width: u64,
    height: u64,
    viewport: Value,
}

#[derive(Clone)]
struct Snapshot {
    route: Route,
    tab: String,
    connection: u64,
    interaction: u64,
    observer_continuity: u64,
    document: CommittedDocument,
    refs: BTreeMap<String, ShownRef>,
    image: Option<Image>,
}

#[derive(Default)]
struct State {
    connection: Option<u64>,
    ended_routes: BTreeSet<Route>,
    claims: BTreeMap<String, Route>,
    unobserved_blank: BTreeSet<String>,
    /// Tabs that have had a reply reporting `settled: false` since they were
    /// claimed. Settlement is never observed on the person's browser, so the
    /// text of later replies about the same tab leaves the settlement note
    /// out (their `settled` field still says it). A route whose reader takes
    /// the raw JSON reply gets no separate text projection, but its replies
    /// count too.
    settlement_noted: BTreeSet<String>,
    snapshots: BTreeMap<String, Snapshot>,
    snapshot_order: Vec<String>,
    executions: BTreeMap<String, Arc<UserExecution>>,
}

pub(crate) struct UserBrowser {
    state: Mutex<State>,
    next_ref: std::sync::atomic::AtomicU64,
    grants: Arc<StandingBrowserGrants>,
    workers: crate::blocking_permits::PermitPool,
}

impl UserBrowser {
    pub(crate) fn new(grants: Arc<StandingBrowserGrants>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            next_ref: std::sync::atomic::AtomicU64::new(1),
            grants,
            workers: crate::blocking_permits::PermitPool::new(
                crate::budgets::MAX_BLOCKING_WORKERS_BROWSER,
            ),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub(crate) fn release(&self, route: Route) {
        let mut state = self.state();
        state.claims.retain(|_, owner| *owner != route);
        let claimed: BTreeSet<_> = state.claims.keys().cloned().collect();
        state.unobserved_blank.retain(|tab| claimed.contains(tab));
        state.settlement_noted.retain(|tab| claimed.contains(tab));
        state
            .snapshots
            .retain(|_, snapshot| snapshot.route != route);
        let retained: BTreeSet<_> = state.snapshots.keys().cloned().collect();
        state.snapshot_order.retain(|id| retained.contains(id));
    }

    pub(crate) fn end_route(&self, route: Route) {
        self.state().ended_routes.insert(route);
        self.release(route);
    }

    pub(crate) fn disconnect(&self) {
        let mut state = self.state();
        let ended_routes = std::mem::take(&mut state.ended_routes);
        let executions = std::mem::take(&mut state.executions);
        *state = State {
            ended_routes,
            executions,
            ..State::default()
        };
    }

    pub(crate) fn quarantine(
        &self,
        route: Route,
        tab: Option<&str>,
    ) -> Option<crate::browser_queue::QueueRefusal> {
        let state = self.state();
        state.executions.values().find_map(|execution| {
            if execution.route != route
                || tab.is_some_and(|tab| execution.tab.as_deref() != Some(tab))
            {
                return None;
            }
            let watch = execution.state.lock().unwrap();
            watch
                .quarantined
                .then(|| crate::browser_queue::QueueRefusal::TargetBusy {
                    capability: crate::flat_tools::BROWSER_USE,
                    step: "queue",
                    reason: watch
                        .held
                        .then_some(crate::browser_session::HELD_INPUT_UNCONFIRMED),
                    call: execution.action.clone(),
                })
        })
    }

    fn execution(
        &self,
        route: Route,
        action: &str,
        args: &Value,
        budget: &crate::budgets::ActionBudget,
    ) -> Arc<UserExecution> {
        let work_ms = budget.work_ms;
        // The consent allowance follows the budget, not the action name: an
        // `open_tab` that also navigates asks about its site like navigate.
        let consents = crate::budgets::user_consent_count(budget.action);
        let tab = args["tab"].as_str().map(str::to_owned);
        let key = tab
            .clone()
            .unwrap_or_else(|| format!("route:{}:{}", route.channel, route.epoch));
        let execution = Arc::new(UserExecution {
            route,
            tab,
            action: action.into(),
            state: Mutex::new(ExecutionState::default()),
            done: tokio::sync::Notify::new(),
            clock: Mutex::new(WorkClock {
                work_end: tokio::time::Instant::now() + Duration::from_millis(work_ms),
                call_end: crate::call_context::CALL_DEADLINE
                    .try_with(|end| *end)
                    .unwrap_or_else(|_| {
                        tokio::time::Instant::now()
                            + Duration::from_millis(
                                work_ms + consents * crate::budgets::USER_CONSENT_MS,
                            )
                    }),
                parked: Duration::ZERO,
                park_left: Duration::from_millis(consents * crate::budgets::USER_CONSENT_MS),
                parking: None,
            }),
            clock_changed: tokio::sync::Notify::new(),
        });
        self.state().executions.insert(key, Arc::clone(&execution));
        if let Some(terminal) = crate::TerminalArbiter::current() {
            let watch = Arc::clone(&execution);
            if !terminal.publish_or_close(Box::new(move || watch.stop())) {
                execution.stop();
            }
        }
        execution
    }

    pub(crate) fn synchronize(&self, connection: u64) {
        let mut state = self.state();
        if state.connection != Some(connection) {
            let ended_routes = std::mem::take(&mut state.ended_routes);
            *state = State {
                connection: Some(connection),
                ended_routes,
                ..State::default()
            };
        }
    }

    fn owned(&self, route: Route, tab: &str, connection: u64) -> Result<(), Value> {
        let state = self.state();
        if state.connection != Some(connection) {
            return Err(read_again(false));
        }
        if state.claims.get(tab) != Some(&route) {
            return Err(refusal("tab_not_claimed_by_route"));
        }
        Ok(())
    }

    fn snapshot(
        &self,
        route: Route,
        tab: &str,
        connection: u64,
        args: &Value,
    ) -> Result<Snapshot, Value> {
        let state = self.state();
        let snapshot = if let Some(id) = args.get("snapshot_id").and_then(Value::as_str) {
            state.snapshots.get(id)
        } else {
            let reference = args.get("ref").and_then(Value::as_str);
            state
                .snapshot_order
                .iter()
                .rev()
                .filter_map(|id| state.snapshots.get(id))
                .find(|snapshot| {
                    reference.is_some_and(|reference| snapshot.refs.contains_key(reference))
                })
        }
        .ok_or_else(|| refusal("snapshot_scope_mismatch"))?;
        if snapshot.route != route || snapshot.tab != tab || snapshot.connection != connection {
            return Err(refusal("snapshot_scope_mismatch"));
        }
        if let Some(reference) = args.get("ref").and_then(Value::as_str) {
            if !snapshot.refs.contains_key(reference) {
                return Err(refusal("ref_scope_mismatch"));
            }
        }
        Ok(snapshot.clone())
    }

    /// The newest read (snapshot or screenshot) this route took of `tab` on
    /// this connection. A page scroll names no ref, so it acts under this
    /// read: it refuses if the person has used the page since.
    fn latest_read(&self, route: Route, tab: &str, connection: u64) -> Result<Snapshot, Value> {
        let state = self.state();
        state
            .snapshot_order
            .iter()
            .rev()
            .filter_map(|id| state.snapshots.get(id))
            .find(|snapshot| {
                snapshot.route == route && snapshot.tab == tab && snapshot.connection == connection
            })
            .cloned()
            .ok_or_else(|| {
                let mut reply = refusal("fresh_read_required");
                reply["remedy"] = json!("Take a snapshot of this tab first; a scroll acts only on a page read since the person last used it.");
                reply
            })
    }

    fn retain(&self, id: String, snapshot: Snapshot) {
        let mut state = self.state();
        if state.ended_routes.contains(&snapshot.route)
            || state.connection != Some(snapshot.connection)
        {
            return;
        }
        state.snapshot_order.push(id.clone());
        state.snapshots.insert(id, snapshot);
        while state.snapshot_order.len() > MAX_SNAPSHOTS {
            let old = state.snapshot_order.remove(0);
            state.snapshots.remove(&old);
        }
    }

    fn prior_refs(&self, snapshot: &Snapshot) -> HashMap<(String, u64), (String, FrameDocument)> {
        let state = self.state();
        let mut refs = HashMap::new();
        for previous in state
            .snapshot_order
            .iter()
            .rev()
            .filter_map(|id| state.snapshots.get(id))
        {
            if previous.route != snapshot.route
                || previous.tab != snapshot.tab
                || previous.connection != snapshot.connection
                || previous.document != snapshot.document
            {
                continue;
            }
            for (name, shown) in &previous.refs {
                refs.entry((
                    shown.identity.frame_id.clone(),
                    shown.identity.backend_node_id,
                ))
                .or_insert_with(|| (name.clone(), shown.frame.clone()));
            }
        }
        refs
    }

    fn covers(
        &self,
        agent: &str,
        origin: &str,
        severity: Severity,
        hazards: &BTreeSet<HazardClass>,
    ) -> bool {
        self.grants
            .covering_row(agent, origin, severity, hazards, self.grants.now_ms())
            .is_some_and(|row| {
                !matches!(
                    row.subject,
                    crate::browser_standing_grants::StandingSubject::AllSites
                )
            })
    }
}

fn opaque(prefix: &str) -> String {
    let mut bytes = [0; 16];
    getrandom::getrandom(&mut bytes).expect("user-browser handle entropy unavailable");
    format!(
        "{prefix}{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn refusal(reason: &str) -> Value {
    json!({"browser":"user", "outcome":"refused", "reason":reason, "input_dispatched":false})
}

fn type_field_refusal(record: &NonTypeClassificationRecord) -> Option<Value> {
    let reason_code = crate::classification::type_field_reason(record)?;
    let input_type = record.effective_input_type.as_deref().unwrap_or("none");
    Some(json!({
        "browser":"user", "outcome":"refused", "input_dispatched":false,
        "detail":{"field":"ref","reason_code":reason_code},
        "remedy":crate::classification::type_field_remedy(reason_code, input_type, true)
    }))
}

fn classification_failure(
    step: &str,
    frame_url: &str,
    node_resolved: Option<bool>,
    cause: &str,
) -> Value {
    // Derive URL details only through the fixed scheme allowlist, so private
    // paths and query values cannot enter the diagnostic. The step label and
    // classifier facts describe structure rather than page content.
    let scheme = match frame_url.split_once(':').map(|(scheme, _)| scheme) {
        Some("http") => "http",
        Some("https") => "https",
        Some("about") => "about",
        Some("blob") => "blob",
        Some("data") => "data",
        Some("file") => "file",
        _ => "other",
    };
    let resolved = node_resolved.map_or("unknown", |found| if found { "yes" } else { "no" });
    let problem =
        format!("frame_url_scheme={scheme}; node_resolved_in_capture={resolved}; cause={cause}");
    let mut reply = refusal("classification_unavailable");
    reply["detail"] = json!({"step":step,"problem":problem});
    reply["remedy"] = json!(format!("Classification failed at {step}: {problem}. No further input was sent. Take a fresh frame-aware snapshot after the frame finishes loading and retry; if it persists, report this step and cause."));
    reply
}

fn classify_frame_capture<'a>(
    capture: Option<&'a Value>,
    identity: &BackendNodeIdentity,
    frame: &FrameDocument,
    epoch: u64,
    step: &str,
) -> Result<
    (
        &'a serde_json::Map<String, Value>,
        NonTypeClassificationRecord,
    ),
    Value,
> {
    let resolved = capture
        .and_then(|capture| capture["nodes"].as_array())
        .map(|nodes| {
            nodes
                .iter()
                .any(|node| node["backendNodeId"].as_u64() == Some(identity.backend_node_id))
        });
    let fail = |cause: &str| classification_failure(step, &frame.url, resolved, cause);
    let dom = capture
        .and_then(Value::as_object)
        .ok_or_else(|| fail("flattened_document_result_missing"))?;
    let record = classify_flattened_document(dom, identity, epoch, &frame.origin)
        .map_err(|cause| fail(&cause.to_string()))?;
    Ok((dom, record))
}

#[derive(Clone, Copy)]
enum InputCheck {
    PreDispatch,
    PostFocus,
    PreInsertion,
}

impl InputCheck {
    fn name(self) -> &'static str {
        match self {
            Self::PreDispatch => "pre-dispatch",
            Self::PostFocus => "post-focus",
            Self::PreInsertion => "pre-insertion",
        }
    }
}

/// Every name `classification_changed` can report in `detail.changed_fields`.
/// The result schema closes the field over this set, so a renamed or added
/// record field that isn't listed here is withheld rather than sent.
pub(crate) const CLASSIFICATION_FIELD_NAMES: &[&str] = &[
    "schema",
    "node_identity",
    "activation_target_identity",
    "document_epoch",
    "target_kind",
    "effective_input_type",
    "activation_invokes_form_submit",
    "form_owner",
    "current_top_level_origin",
    "activation_destination_origin",
    "target_autocomplete_tokens",
    "target_password",
    "associated_form_controls",
    "required_tier",
    "credential",
    "financial",
];

fn classification_changed(
    expected: &NonTypeClassificationRecord,
    observed: &NonTypeClassificationRecord,
    check: InputCheck,
) -> Value {
    let mut changed_fields = Vec::new();
    // Match PartialEq's closed authorization fields, excluding login hints.
    // Return only field names: origins, identities and DOM metadata stay private.
    macro_rules! compare {
        ($($field:ident),+ $(,)?) => {
            $(if expected.$field != observed.$field {
                changed_fields.push(stringify!($field));
            })+
        };
    }
    compare!(
        schema,
        node_identity,
        activation_target_identity,
        document_epoch,
        target_kind,
        effective_input_type,
        activation_invokes_form_submit,
        form_owner,
        current_top_level_origin,
        activation_destination_origin,
        target_autocomplete_tokens,
        target_password,
        associated_form_controls,
        required_tier,
        credential,
        financial,
    );
    let mut reply = refusal("classification_changed");
    reply["detail"] = json!({"check":check.name(),"changed_fields":changed_fields});
    reply
}

/// The revision of the cerebellum-to-extension contract this build speaks.
/// The extension stamps its own revision (`EXTENSION_REVISION` in
/// `extension/revision.mjs`) on every completed reply and every refusal, and
/// both numbers must change together whenever a plan, reply or refusal shape
/// changes. The manifest `version` is not used for this: the person's Chrome
/// can keep running an old unpacked copy that reports the same `version`, and
/// replies from such a copy must refuse with a reload remedy instead of
/// failing to decode.
pub(crate) const EXTENSION_REVISION: u64 = 4;

const EXTENSION_OUTDATED_REMEDY: &str = "The CortexKit Chrome extension is out of date. Ask the person to reload it in chrome://extensions, then retry.";
const EXTENSION_NEWER_REMEDY: &str = "The CortexKit Chrome extension is newer than this cerebellum. Ask the person to load the extension copy installed with this cerebellum and reload it in chrome://extensions, or update cerebellum, then retry.";

/// The refusal for a reply whose extension revision differs from
/// [`EXTENSION_REVISION`]. A missing revision means an extension older than
/// the handshake itself, so it counts as outdated. Every reply from such an
/// extension is untrusted for decoding, so nothing of it is relayed except
/// whether input was dispatched.
fn extension_revision_mismatch(found: Option<u64>, input_dispatched: Option<bool>) -> Value {
    let newer = found.is_some_and(|revision| revision > EXTENSION_REVISION);
    let mut reply = refusal(if newer {
        "extension_newer"
    } else {
        "extension_outdated"
    });
    reply["remedy"] = json!(if newer {
        EXTENSION_NEWER_REMEDY
    } else {
        EXTENSION_OUTDATED_REMEDY
    });
    reply["detail"] = json!({"extension_revision":found, "required_revision":EXTENSION_REVISION});
    reply["input_dispatched"] = json!(input_dispatched);
    reply
}

/// A reply from a current extension that still could not be decoded. It stays
/// fail-closed, but names the decoding `step` and, when serde reports one, the
/// field, so the next contract drift is diagnosable from the refusal alone.
/// serde's full message is never relayed: an "invalid type" message quotes the
/// offending value, which can be page content. Field names come from the
/// extension's own reply keys, and anything that does not look like one is
/// dropped.
fn protocol_error(step: &str, error: Option<&serde_json::Error>) -> Value {
    let mut reply = refusal("protocol_error");
    let mut detail = json!({"step":step});
    if let Some(error) = error {
        let message = error.to_string();
        let (problem, field) = if let Some(rest) = message.strip_prefix("missing field `") {
            ("missing_field", rest.split('`').next())
        } else if let Some(rest) = message.strip_prefix("unknown field `") {
            ("unknown_field", rest.split('`').next())
        } else {
            ("wrong_type", None)
        };
        detail["problem"] = json!(problem);
        if let Some(field) = field.filter(|field| {
            !field.is_empty()
                && field.len() <= 64
                && field.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }) {
            detail["field"] = json!(field);
        }
    }
    reply["detail"] = detail;
    reply
}

/// [`protocol_error`] for a reply value that is present but not the expected
/// type, at a named field of a named step.
fn protocol_field_error(step: &str, field: &str) -> Value {
    let mut reply = protocol_error(step, None);
    reply["detail"]["field"] = json!(field);
    reply["detail"]["problem"] = json!("wrong_type");
    reply
}

/// Decode an extension reply as `T`, refusing with [`protocol_error`] for
/// `step` when it does not match.
fn decode<T: serde::de::DeserializeOwned>(step: &str, raw: Value) -> Result<T, Value> {
    serde_json::from_value(raw).map_err(|error| protocol_error(step, Some(&error)))
}

fn observer_unavailable() -> Value {
    let mut reply = refusal("observer_unavailable");
    reply["remedy"] = json!("The interaction observer is unavailable; take a fresh read after the page commits. If it stays unavailable, restore extension access or reload the page.");
    reply
}

fn read_again(input_dispatched: bool) -> Value {
    json!({"browser":"user", "outcome":"refused", "reason":"state_changed_by_person", "remedy":"read again", "input_dispatched":input_dispatched})
}

/// The trusted page events the extension's observer (`extension/sentinel.js`)
/// counts as a person's input. A cause code names one of these.
const OBSERVED_INPUT_EVENTS: [&str; 13] = [
    "pointerdown",
    "pointerup",
    "mousedown",
    "mouseup",
    "click",
    "dblclick",
    "keydown",
    "keyup",
    "beforeinput",
    "input",
    "wheel",
    "touchstart",
    "touchend",
];

/// The extension's code for why a tab's interaction epoch last moved, kept
/// only when it is in the extension's closed vocabulary:
/// `input.<event>.<main|subframe>` for a person's input event in the main
/// frame or a child frame, or `navigation.main` for a main-frame navigation
/// the agent did not start. `navigation.subframe` is also accepted, though
/// the extension no longer counts child-frame navigations. Any other string
/// becomes `unrecognized`, so no page-supplied text can reach a reply.
fn recognized_cause(code: Option<String>) -> Option<String> {
    let code = code?;
    let known = match code.split('.').collect::<Vec<_>>().as_slice() {
        ["input", event, "main" | "subframe"] => OBSERVED_INPUT_EVENTS.contains(event),
        ["navigation", "main" | "subframe"] => true,
        _ => false,
    };
    Some(if known { code } else { "unrecognized".into() })
}

/// [`read_again`] when the tab's interaction epoch moved since the read,
/// naming in `detail` the extension's code for the last thing that moved it
/// (`unknown` when the extension gave none).
fn epoch_moved(input_dispatched: bool, cause: Option<&str>) -> Value {
    let mut reply = read_again(input_dispatched);
    reply["detail"] = json!({"check":"interaction_epoch","cause":cause.unwrap_or("unknown")});
    reply
}

/// [`read_again`] when the tab's committed document differs from the one the
/// read saw, naming in `detail` which parts of its identity changed. Only
/// booleans are reported, never the URLs or ids themselves.
fn document_moved(
    input_dispatched: bool,
    before: &CommittedDocument,
    after: &CommittedDocument,
) -> Value {
    let mut reply = read_again(input_dispatched);
    reply["detail"] = json!({
        "check":"committed_document",
        "history_entry_changed":before.entry_id != after.entry_id,
        "history_index_changed":before.current_index != after.current_index,
        "history_length_changed":before.history.len() != after.history.len(),
        "url_changed":before.url != after.url,
        "loader_changed":before.loader_id != after.loader_id,
    });
    reply
}

fn invalid(field: &str, reason: &str) -> Value {
    json!({"browser":"user", "outcome":"invalid_request", "detail":{"field":field,"reason_code":reason}, "input_dispatched":false})
}

/// An unanswered user-browser site card chooses `deny`.
const SITE_DENY: &str = "deny";

/// The consent card asking the person whether the agent may use their own
/// signed-in Chrome on `origin`, at severity `tier` with `hazards`. "Always
/// on this site" is offered only when `standing`: this route's agent may hold
/// standing grants and the grant store can record one.
///
/// The card's params are sent to Cingulate (see
/// `cingulate_client::card::consent_request`), and the id the agent and the
/// standing grant are given is the elicitation id Cingulate returns.
#[cfg(test)]
pub(crate) fn site_question(
    origin: &str,
    tier: u8,
    hazards: &BTreeSet<HazardClass>,
    standing: bool,
) -> Value {
    let mut choices = crate::management::offered_browser_grant_choices(
        &[origin.into()],
        hazards,
        Severity::new(tier, false, false),
        standing,
    );
    choices.retain(|choice| {
        matches!(
            choice,
            crate::management::BrowserGrantChoice::SiteThirtyMinutes
                | crate::management::BrowserGrantChoice::OriginAlways
        )
    });
    site_question_with_choices(origin, tier, hazards, &choices)
}

pub(crate) fn site_question_with_choices(
    origin: &str,
    tier: u8,
    hazards: &BTreeSet<HazardClass>,
    choices: &[crate::management::BrowserGrantChoice],
) -> Value {
    use crate::consent_card::*;
    let tier = site_grant_tier(tier);
    let hazard_names: Vec<&str> = hazards.iter().map(|hazard| hazard.as_str()).collect();
    let host = crate::login_import::origin_host(origin).unwrap_or_else(|| origin.into());
    let scope = crate::browser_standing_grants::domain_scope(origin).map_or_else(
        || host.clone(),
        |domain| format!("{domain} and its subdomains"),
    );
    let options = choices
        .iter()
        .filter(|choice| {
            matches!(
                choice,
                crate::management::BrowserGrantChoice::SiteThirtyMinutes
                    | crate::management::BrowserGrantChoice::OriginAlways
            )
        })
        .map(|choice| {
            let option = crate::management::browser_grant_option(
                *choice,
                &[
                    if *choice == crate::management::BrowserGrantChoice::SiteThirtyMinutes {
                        host.clone()
                    } else {
                        scope.clone()
                    },
                ],
                Severity::new(tier, false, false),
            );
            if tier == authorization::COMPOSE && hazards.is_empty() {
                option.with_detail("Covers reading, clicking and typing on this site; submitting forms and credential or financial actions still need approval.")
            } else {
                option
            }
        })
        .collect();
    ConsentCard {
        title: format!("Allow access to {origin}?"),
        prompt: "Let the agent use your own Chrome, signed in as you, on this site?".into(),
        target: Target {
            kind: TargetKind::Site,
            label: origin.into(),
        },
        facts: vec![
            Fact::new("Browser", "Your own Chrome, signed in as you"),
            Fact::new("Site", origin),
            Fact::new("Level", tier.to_string()),
            Fact::new("Hazards", hazard_names.join(", ")),
        ],
        grants: options,
        decline: ConsentOption::decline(SITE_DENY, "Don't allow"),
        expires_in: CONSENT_DEADLINE,
        material_damage: true,
        late_execution: LateExecution::Execute,
        urgency: Urgency::High,
        scope: Scope::new()
            .with("browser", "user")
            .with("origins", json!([origin]))
            .with("severity_tier", tier)
            .with("hazards", json!(hazard_names)),
    }
    .render()
}

/// A durable site answer covers reading, clicking and typing even when a read
/// raised the card. More consequential actions still need a higher ceiling.
fn site_grant_tier(tier: u8) -> u8 {
    tier.max(authorization::COMPOSE)
}

/// The refusal when the site card ended without an answer, or could not be
/// raised. The reason stays `consent_unavailable` whatever the ending; when no
/// card could be raised at all, `detail.reason` names why, as the other
/// flows' `consent_unavailable` replies do, and the remedy says what the
/// caller can change.
fn consent_unavailable(ending: &Ending) -> Value {
    let mut reply = refusal("consent_unavailable");
    if let Ending::NoCard(why) = ending {
        if let Some(reason) = why.reason() {
            reply["detail"] = json!({ "reason": reason });
        }
        if let Some(remedy) = why.remedy() {
            reply["remedy"] = json!(remedy);
        }
    }
    reply
}

/// The subjects of the site cards that calls in this process are raising or
/// holding, each with how many calls are doing so.
///
/// A holder applies its own answer. After detachment, the session drain stores
/// durable answers using the authority retained with the card.
#[derive(Default)]
pub(crate) struct SiteCardHolders(Mutex<BTreeMap<String, usize>>);

impl SiteCardHolders {
    fn holds(&self, subject: &str) -> bool {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(subject)
    }
}

/// One call raising or holding a site card, counted in [`SiteCardHolders`]
/// until it is dropped, however the call ends.
struct SiteCardHold<'a> {
    holders: &'a SiteCardHolders,
    subject: String,
}

impl<'a> SiteCardHold<'a> {
    fn enter(holders: &'a SiteCardHolders, subject: &str) -> Self {
        *holders
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .entry(subject.to_string())
            .or_default() += 1;
        Self {
            holders,
            subject: subject.to_string(),
        }
    }
}

impl Drop for SiteCardHold<'_> {
    fn drop(&mut self) {
        let mut held = self
            .holders
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(count) = held.get_mut(&self.subject) {
            *count -= 1;
            if *count == 0 {
                held.remove(&self.subject);
            }
        }
    }
}

/// Calls still waiting on a site card store their own answers. For answers that
/// arrive after the wait ends, ConsentDrain uses the card's retained holder,
/// site and severity, not the action requested by the call reading the answer feed.
struct SiteCardEffects {
    holders: Arc<SiteCardHolders>,
    management: std::sync::Weak<crate::management::ManagementPlane>,
}

impl ConsentEffects for SiteCardEffects {
    fn has_pending(&self, card: &RaisedCard) -> bool {
        card.lifecycle.deferred_use || self.holders.holds(&card.subject)
    }

    fn apply(
        &self,
        card: &RaisedCard,
        _record: &Record,
        ending: &Ending,
    ) -> Result<AppliedSettlement, ApplyFailed> {
        if self.holders.holds(&card.subject) {
            return Err(ApplyFailed(
                "the held site call has not stored its answer yet".into(),
            ));
        }
        if let (Some(intent), Ending::Granted { choice_id }) =
            (&card.lifecycle.user_browser_grant, ending)
        {
            let choice = match choice_id.as_str() {
                "allow_30m" => Some(crate::management::BrowserGrantChoice::SiteThirtyMinutes),
                "allow_origin_always" => Some(crate::management::BrowserGrantChoice::OriginAlways),
                _ => None,
            };
            if let Some(choice) = choice {
                let management = self
                    .management
                    .upgrade()
                    .ok_or_else(|| ApplyFailed("grant store is unavailable".into()))?;
                agent_enforcement::store_answer(
                    management.agent_grants(),
                    intent,
                    &card.elicitation_id,
                    choice,
                )
                .map_err(|_| ApplyFailed("site grant could not be recorded".into()))?;
            }
        }
        Ok(AppliedSettlement {
            effect: Apply::Applied,
            completion: None,
        })
    }
}

/// Register the site card's drain adapter with the session drain.
pub(crate) fn register(planes: &Planes) {
    planes.consent_drain.register(
        CardKind::UserBrowserSite,
        Arc::new(SiteCardEffects {
            holders: Arc::clone(&planes.user_browser_cards),
            management: Arc::downgrade(&planes.management),
        }),
    );
}

fn origin(url: &str) -> Result<String, Value> {
    canonical_origin_from_url(url).ok_or_else(|| refusal("ungrantable_origin"))
}

async fn invoke(
    bridge: &UserBrowserBridge,
    route: Route,
    cancel: &CancelHandle,
    action: &str,
    mut command: Value,
) -> Result<Value, Value> {
    command["version"] = json!(2);
    command["action"] = json!(action);
    let outcome = bridge.invoke(route, command, cancel.clone()).await;
    if outcome.terminal == Terminal::Completed {
        let mut result = outcome
            .result
            .ok_or_else(|| protocol_error("reply", None))?;
        // Check the revision before any decoding, so an extension speaking
        // another contract is named as such rather than surfacing as
        // whichever field it happens to lack. Remove it here so the per-action
        // reply types, which deny unknown fields, never see it.
        let revision = result
            .as_object_mut()
            .and_then(|fields| fields.remove("extension_revision"))
            .and_then(|revision| revision.as_u64());
        if revision != Some(EXTENSION_REVISION) {
            return Err(extension_revision_mismatch(
                revision,
                outcome.input_dispatched,
            ));
        }
        return Ok(result);
    }
    // A current extension encodes every refusal as JSON carrying its
    // revision, so a refusal without one (or with another) comes from an
    // extension speaking another contract, whose reason cannot be trusted.
    if let Some(reason) = &outcome.extension_reason {
        let revision = serde_json::from_str::<Value>(reason)
            .ok()
            .and_then(|detail| detail.get("extension_revision").and_then(Value::as_u64));
        if revision != Some(EXTENSION_REVISION) {
            let mut reply = extension_revision_mismatch(revision, outcome.input_dispatched);
            reply["outcome"] = serde_json::to_value(outcome.terminal).expect("terminal serializes");
            return Err(reply);
        }
    }
    let mut reply = refusal(
        outcome
            .extension_reason
            .as_deref()
            .unwrap_or("bridge_refused"),
    );
    reply["outcome"] = serde_json::to_value(outcome.terminal).expect("terminal serializes");
    reply["input_dispatched"] = json!(outcome.input_dispatched);
    if let Some(reason) = outcome.reason {
        reply["reason"] = serde_json::to_value(reason).expect("reason serializes");
    }
    if let Some(reason) = outcome.extension_reason {
        // The extension encodes its machine reason and human remedy as JSON
        // inside the bridge's refusal string. Do not expose that envelope as a
        // machine code or copy arbitrary diagnostic/page fields into the reply.
        match serde_json::from_str::<Value>(&reason) {
            Ok(detail) if detail["reason"].as_str().is_some() => {
                reply["reason"] = detail["reason"].clone();
                if let Some(remedy) = detail["remedy"].as_str() {
                    reply["remedy"] = json!(remedy);
                }
            }
            _ => reply["reason"] = json!(reason),
        }
    }
    if let Some(remedy) = outcome.remedy {
        reply["remedy"] = json!(remedy);
    }
    if reply["reason"] == "state_changed_by_person" {
        reply["remedy"] = json!("read again");
    }
    Err(reply)
}

struct Plan {
    results: Vec<Value>,
    interaction: u64,
    interaction_cause: Option<String>,
    observer_available: bool,
    observer_continuity: u64,
    popup: bool,
    frame_mappings: Vec<FrameMapping>,
}

#[allow(clippy::too_many_arguments)]
async fn plan(
    bridge: &UserBrowserBridge,
    route: Route,
    tab: &str,
    connection: u64,
    interaction: Option<u64>,
    cancel: &CancelHandle,
    commands: Vec<Value>,
    scroll_is_input: bool,
) -> Result<Plan, Value> {
    if !crate::grant_enforcement::commit_current() {
        return Err(refusal("grant_revoked"));
    }
    let count = commands.len();
    let methods: Vec<String> = commands
        .iter()
        .map(|command| command["method"].as_str().unwrap_or_default().to_owned())
        .collect();
    let input_commands: Vec<bool> = commands
        .iter()
        .map(|command| {
            command["method"].as_str().is_some_and(|method| {
                method.starts_with("Input.")
                    || method == "DOM.focus"
                    || method == "Runtime.callFunctionOn"
                    || method == "Emulation.setFocusEmulationEnabled"
                    // A click scrolls its target into view only to measure
                    // it, before any input. For a scroll action, scrolling
                    // is the action itself, so once Chrome has done it the
                    // call has had its effect.
                    || (scroll_is_input && method == "DOM.scrollIntoViewIfNeeded")
            })
        })
        .collect();
    let mut command = json!({"tab":tab,"commands":commands});
    let observer_continuity = EXECUTION
        .try_with(|execution| {
            execution
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .observer_continuity
        })
        .ok()
        .flatten();
    if let Some(continuity) = observer_continuity {
        command["observer_continuity"] = json!(continuity);
    }
    if let Some(epoch) = interaction {
        command["interaction_epoch"] = json!(epoch);
    }
    let raw = invoke(bridge, route, cancel, "cdp", command).await?;
    let reply: PlanReply = decode("cdp_reply", raw)?;
    if reply.popup_activated_briefly {
        let _ = POPUP_SEEN.try_with(|seen| seen.set(true));
    }
    let mut results = Vec::new();
    let mut dispatched = false;
    if reply.results.len() > count {
        return Err(protocol_field_error("cdp_reply", "results"));
    }
    for (index, result) in reply.results.into_iter().enumerate() {
        match result {
            CommandResult::Result(success) => {
                dispatched |= input_commands[index];
                results.push(success.result);
            }
            CommandResult::Error(failure) => {
                let mut refusal = refusal("cdp_error");
                refusal["detail"] = cdp_error_detail(&methods[index], failure.error);
                refusal["input_dispatched"] = json!(dispatched);
                return Err(refusal);
            }
        }
    }
    if reply.tab != tab
        || reply.connection_epoch != connection
        || bridge.connected_epoch() != Some(connection)
    {
        return Err(read_again(dispatched));
    }
    let navigates = methods.iter().any(|method| method == "Page.navigate");
    if interaction.is_some() && !reply.observer_available && !navigates {
        return Err(prior_input(observer_unavailable(), dispatched));
    }
    if !navigates
        && interaction.is_some()
        && observer_continuity.is_some_and(|expected| expected != reply.observer_continuity)
    {
        return Err(prior_input(observer_unavailable(), dispatched));
    }
    let interaction_cause = recognized_cause(reply.interaction_cause);
    if !navigates && interaction.is_some_and(|expected| expected != reply.interaction_epoch) {
        return Err(epoch_moved(dispatched, interaction_cause.as_deref()));
    }
    if results.len() != count {
        return Err(prior_input(
            protocol_field_error("cdp_reply", "results"),
            dispatched,
        ));
    }
    Ok(Plan {
        results,
        interaction: reply.interaction_epoch,
        interaction_cause,
        observer_available: reply.observer_available,
        observer_continuity: reply.observer_continuity,
        popup: reply.popup_activated_briefly,
        frame_mappings: reply.frame_mappings,
    })
}

fn command(method: &str, params: Value) -> Value {
    json!({"method":method,"params":params})
}

/// Longest Chrome error message relayed in a `cdp_error` refusal.
const MAX_CDP_ERROR_MESSAGE_CHARS: usize = 200;

/// Which plan command Chrome rejected, with Chrome's own error code and
/// message, so a refused plan says what failed. CDP error messages are fixed
/// protocol strings such as "DOM agent hasn't been enabled" and carry no page
/// content; Chrome's optional `data` field is never relayed. A message that
/// does not look like such a string (too long, or containing control
/// characters) is replaced rather than passed through. The detail is part of
/// the reply only: the journal records the outcome, not this detail.
fn cdp_error_detail(method: &str, error: CdpError) -> Value {
    let message = if error.message.chars().count() <= MAX_CDP_ERROR_MESSAGE_CHARS
        && !error.message.chars().any(char::is_control)
    {
        error.message
    } else {
        "Chrome debugger command failed".into()
    };
    json!({"method":method, "code":error.code, "message":message})
}

/// The flattened DOM read used to classify and re-verify input targets.
/// Chrome refuses `DOM.getFlattenedDocument` with "DOM agent hasn't been
/// enabled" unless `DOM.enable` ran earlier on the same debugger attachment,
/// and the extension attaches afresh for every plan and detaches after it. So
/// every plan that reads the flattened DOM enables the DOM agent first; the
/// document is the plan's last result.
fn flattened_document() -> Vec<Value> {
    vec![
        command("DOM.enable", json!({})),
        command(
            "DOM.getFlattenedDocument",
            json!({"depth":-1,"pierce":true}),
        ),
    ]
}

struct Document {
    committed: CommittedDocument,
    frames: Vec<FrameDocument>,
    interaction: u64,
    interaction_cause: Option<String>,
    observer_available: bool,
    observer_continuity: u64,
    unreadable_frames: BTreeMap<String, FrameReadFailure>,
}

async fn document(
    bridge: &UserBrowserBridge,
    route: Route,
    tab: &str,
    connection: u64,
    cancel: &CancelHandle,
) -> Result<Document, Value> {
    let plan = plan(
        bridge,
        route,
        tab,
        connection,
        None,
        cancel,
        vec![
            command("Page.getNavigationHistory", json!({})),
            command("Page.getFrameTree", json!({})),
        ],
        false,
    )
    .await?;
    let history = plan.results[0]
        .as_object()
        .ok_or_else(|| protocol_error("navigation_history", None))?;
    let tree = plan.results[1]
        .as_object()
        .ok_or_else(|| protocol_error("frame_tree", None))?;
    let committed = crate::browser::navigation::committed_document_from(history, tree)
        .ok_or_else(|| refusal("document_not_ready"))?;
    let mut frames = Vec::new();
    let mut frame_count = 0;
    let mut unreadable_frames = BTreeMap::new();
    collect_frames(
        &plan.results[1]["frameTree"],
        &plan.frame_mappings,
        &mut frames,
        0,
        &mut frame_count,
        &mut unreadable_frames,
    )?;
    Ok(Document {
        committed,
        frames,
        interaction: plan.interaction,
        interaction_cause: plan.interaction_cause,
        observer_available: plan.observer_available,
        observer_continuity: plan.observer_continuity,
        unreadable_frames,
    })
}

fn collect_frames(
    tree: &Value,
    mappings: &[FrameMapping],
    frames: &mut Vec<FrameDocument>,
    depth: usize,
    count: &mut usize,
    unreadable: &mut BTreeMap<String, FrameReadFailure>,
) -> Result<(), Value> {
    if depth > 64 || *count >= 256 {
        return Err(refusal("frame_limit"));
    }
    *count += 1;
    let frame = &tree["frame"];
    let text = |field: &str| {
        frame[field]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| protocol_field_error("frame_tree", field))
    };
    let url = text("url")?;
    let id = text("id")?;
    let loader = text("loaderId")?;
    let matching: Vec<_> = mappings
        .iter()
        .filter(|mapping| mapping.frame_id == id)
        .collect();
    let mapping = (matching.len() == 1).then(|| matching[0]);
    let parent_id =
        (depth != 0).then(|| frame["parentId"].as_str().unwrap_or("embedded").to_owned());
    let reason = mapping
        .and_then(|mapping| mapping.unreadable_reason)
        .or_else(|| {
            if matching.len() > 1 {
                Some(FrameReadFailure::Ambiguous)
            } else if mapping.is_none_or(|mapping| {
                mapping.url != url
                    || mapping.loader_id != loader
                    || mapping.parent_id != parent_id
                    || mapping.session_id.is_empty()
                    || (depth == 0 && mapping.web_navigation_frame_id != Some(0))
                    || mapping.document_id.as_ref().is_some_and(String::is_empty)
            }) {
                Some(FrameReadFailure::Stale)
            } else {
                None
            }
        });
    if let Some(reason) = reason {
        unreadable.insert(id.clone(), reason);
    }
    // Sandboxed documents can have an opaque origin even at an HTTPS URL.
    // Reads belong to the top-page grant; input must use Chrome's actual origin.
    let frame_origin = if let Some(security_origin) = frame["securityOrigin"].as_str() {
        origin(security_origin).unwrap_or_else(|_| "null".into())
    } else if matches!(url.as_str(), "about:blank" | "about:srcdoc") {
        parent_id
            .as_ref()
            .and_then(|id| frames.iter().find(|frame| &frame.frame_id == id))
            .map(|frame| frame.origin.clone())
            .unwrap_or_else(|| "null".into())
    } else {
        origin(&url).unwrap_or_else(|_| "null".into())
    };
    frames.push(FrameDocument {
        network: Default::default(),
        navigation_revision: 0,
        frame_id: id,
        parent_id,
        session_id: mapping.map_or_else(|| "root".into(), |mapping| mapping.session_id.clone()),
        loader_id: loader,
        origin: frame_origin,
        url,
    });
    if let Some(children) = tree["childFrames"].as_array() {
        for child in children {
            collect_frames(child, mappings, frames, depth + 1, count, unreadable)?;
        }
    }
    Ok(())
}

/// `request` is the inbound call (channel, epoch, corr): its cancellation and
/// its consent liveness. `route` keys this call's claims, snapshots, refs,
/// quarantine and extension bookkeeping; for a codemode run it is the head's
/// route (see `codemode::user_browser_route`).
pub(crate) async fn serve(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    route: Route,
    action: &str,
    args: &Value,
) -> Value {
    let Some(budget) = crate::budgets::user_browser_call(action, args) else {
        return invalid("action", "unsupported_value");
    };
    let Some(permits) = planes.user_browser.target().workers.try_call() else {
        return json!({"browser":"user","outcome":"blocking_capacity_exhausted",
            "detail":{"dispatched":false,"step":"queue"}});
    };
    if let Some(connection) = planes.user_browser.connected_epoch() {
        planes.user_browser.target().synchronize(connection);
    }
    let execution = planes
        .user_browser
        .target()
        .execution(route, action, args, budget);
    let result = EXECUTION_PERMITS.scope(Arc::new(permits),
        EXECUTION.scope(Arc::clone(&execution), POPUP_SEEN.scope(Cell::new(false), async {
            tokio::select! {
                biased;
                _ = execution.expired() => None,
                reply = serve_scoped(planes, facts, writer, request, route, action, args) => Some(reply),
            }
        })),
    ).await;
    result.unwrap_or_else(|| {
        if let Some(terminal) = crate::TerminalArbiter::current() {
            terminal.stop(crate::TerminalCause::Deadline);
        }
        json!({"outcome":"action_deadline_exceeded","detail":{"dispatched":false,"step":"dispatch"}})
    })
}

async fn serve_scoped(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    route: Route,
    action: &str,
    args: &Value,
) -> Value {
    let mut reply = match validate(action, args) {
        Err(reply) => reply,
        Ok(()) => serve_inner(planes, facts, writer, request, route, action, args)
            .await
            .unwrap_or_else(|reply| reply),
    };
    // One browser_use call can contain several detached plans. Preserve popup
    // reports from metadata and refused plans, not only from the last input.
    if POPUP_SEEN.with(Cell::get) {
        reply["popup_activated_briefly"] = json!(true);
    }
    reply = dispatched_outcome(reply);
    if crate::browser::validate_user_browser_result(action, &reply).is_err() {
        let input = reply
            .get("input_dispatched")
            .cloned()
            .unwrap_or(Value::Null);
        reply = refusal("result_schema_violation");
        reply["input_dispatched"] = input;
    }
    reply = dispatched_outcome(reply);
    note_settlement_once(planes.user_browser.target(), &reply);
    let record_origin = args
        .get("url")
        .and_then(Value::as_str)
        .and_then(|url| origin(url).ok());
    if planes
        .browser
        .journal_user_browser(
            &facts.identity,
            action,
            record_origin.as_deref(),
            reply["outcome"].as_str().unwrap_or("refused"),
            reply.get("input_dispatched").and_then(Value::as_bool),
        )
        .await
        .is_err()
    {
        let mut failure = refusal("journal_unavailable");
        failure["input_dispatched"] = reply
            .get("input_dispatched")
            .cloned()
            .unwrap_or(Value::Null);
        if POPUP_SEEN.with(Cell::get) {
            failure["popup_activated_briefly"] = json!(true);
        }
        return dispatched_outcome(failure);
    }
    reply
}

/// Print the settlement note once per claimed tab. Settlement is never
/// observed on the person's browser, so every read of a tab reports
/// `settled: false`. Where a text projection is made, the first such reply
/// after the tab is claimed carries the note and later ones leave it out;
/// raw-JSON replies count toward this too. The reply itself is not changed.
fn note_settlement_once(target: &UserBrowser, reply: &Value) {
    if reply["settled"] != false {
        return;
    }
    let Some(tab) = reply["tab"].as_str() else {
        return;
    };
    if !target.state().settlement_noted.insert(tab.to_owned()) {
        crate::tool_result::omit_settlement_note();
    }
}

fn validate(action: &str, args: &Value) -> Result<(), Value> {
    let object = args
        .as_object()
        .ok_or_else(|| invalid("arguments", "wrong_type"))?;
    let mut fields = crate::flat_tools::browser_action_schema(action).unwrap_or_default();
    if action == "close" {
        fields.clear();
    }
    if matches!(
        action,
        "navigate"
            | "snapshot"
            | "screenshot"
            | "scroll"
            | "click"
            | "type"
            | "click_point"
            | "claim_tab"
    ) {
        fields.insert("tab".into(), json!({"type":"string","minLength":1}));
    }
    if action == "type" {
        fields.insert("snapshot_id".into(), json!({"type":"string"}));
    }
    if action == "click_point" {
        fields.remove("x_px");
        fields.remove("y_px");
        fields.insert("point".into(), json!({"type":"object","properties":{"x":{"type":"integer"},"y":{"type":"integer"}},"required":["x","y"],"additionalProperties":false}));
    }
    if action == "revoke_access" {
        fields.insert("origin".into(), json!({"type":"string"}));
    }
    // The extension can open a tab directly at a URL, but cerebellum opens it
    // blank and then runs the same per-site grant, navigation and landing
    // checks as `navigate` (see `serve_inner`), so one call can open and load
    // a page without bypassing site consent.
    if action == "open_tab" {
        fields.insert("url".into(), json!({"type":"string","minLength":1}));
    }
    // The shared `wait` field asks for page settlement before reading, but the
    // person's browser reports command results only, never the network quiet
    // that settlement is judged by. `none` is exactly what a read here does,
    // so it is accepted; `settle` is refused by name rather than treated as an
    // unknown field or silently ignored.
    if matches!(action, "snapshot" | "screenshot") {
        if object.get("wait").is_some_and(|wait| wait == "settle") {
            let mut reply = refusal("unsupported_on_user_browser");
            reply["detail"] = json!({"field":"wait","reason_code":"unsupported_value"});
            reply["remedy"] = json!(format!("wait: settle doesn't apply to {action} on the user browser: page settlement isn't observed there, so a read returns the page as it is now. Omit wait or pass none, and read again if the page is still loading."));
            return Err(reply);
        }
        fields.insert("wait".into(), json!({"type":"string","enum":["none"]}));
    }
    if action == "open_grant" {
        fields.insert(
            "origins".into(),
            json!({"type":"array","minItems":1,"maxItems":1,"items":{"type":"string"}}),
        );
        fields.insert(
            "hazards".into(),
            json!({"type":"array","items":{"type":"string"}}),
        );
        fields.insert(
            "severity_tier".into(),
            json!({"type":"integer","minimum":1,"maximum":4}),
        );
    }
    // Own-only management actions are refused as unsupported, not decoded into
    // own-browser login or handoff requests.
    if matches!(
        action,
        "present" | "resume" | "import_login" | "capture_login"
    ) {
        return Ok(());
    }
    for (field, value) in object {
        let schema = fields
            .get(field)
            .ok_or_else(|| invalid(field, "unknown_field"))?;
        if !matches_schema(value, schema) {
            return Err(invalid(field, "wrong_type_or_range"));
        }
    }
    let mut required: Vec<&str> = crate::flat_tools::browser_required_fields(action).to_vec();
    if action == "close" {
        required.clear();
    }
    if matches!(
        action,
        "navigate" | "snapshot" | "screenshot" | "scroll" | "click" | "type" | "click_point"
    ) {
        required.push("tab");
    }
    // As on browser:own, a scroll either brings one printed ref into view or
    // moves the page by a direction (and optional amount), never both.
    if action == "scroll" {
        if object.contains_key("ref") {
            if object.contains_key("direction") || object.contains_key("amount") {
                return Err(invalid("direction", "unsupported_value"));
            }
        } else if !object.contains_key("direction") {
            return Err(invalid("direction", "missing_field"));
        }
    }
    for field in required {
        if !object.contains_key(field) {
            return Err(invalid(field, "missing_field"));
        }
    }
    if action == "snapshot" && object.get("mode").is_some_and(|mode| mode != "actionable") {
        for field in ["zoom", "text_filter", "role_filter"] {
            if field == "zoom" && object.get("mode").is_some_and(|mode| mode == "dom_full") {
                continue;
            }
            if object.contains_key(field) {
                return Err(invalid(field, "unsupported_value"));
            }
        }
    }
    Ok(())
}

fn matches_schema(value: &Value, schema: &Value) -> bool {
    if let Some(options) = schema
        .get("anyOf")
        .or_else(|| schema.get("oneOf"))
        .and_then(Value::as_array)
    {
        return options.iter().any(|option| matches_schema(value, option));
    }
    if schema
        .get("enum")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.contains(value))
    {
        return false;
    }
    match schema["type"].as_str() {
        Some("string") => value.as_str().is_some_and(|text| {
            schema["minLength"]
                .as_u64()
                .is_none_or(|min| text.chars().count() as u64 >= min)
                && schema["maxLength"]
                    .as_u64()
                    .is_none_or(|max| text.chars().count() as u64 <= max)
        }),
        Some("boolean") => value.is_boolean(),
        Some("integer" | "number") => value.as_f64().is_some_and(|n| {
            (schema["type"] != "integer" || value.is_i64() || value.is_u64())
                && schema["minimum"].as_f64().is_none_or(|min| n >= min)
                && schema["maximum"].as_f64().is_none_or(|max| n <= max)
        }),
        Some("array") => value.as_array().is_some_and(|array| {
            schema["minItems"]
                .as_u64()
                .is_none_or(|min| array.len() as u64 >= min)
                && schema["maxItems"]
                    .as_u64()
                    .is_none_or(|max| array.len() as u64 <= max)
                && array
                    .iter()
                    .all(|value| matches_schema(value, &schema["items"]))
        }),
        Some("object") => value.as_object().is_some_and(|object| {
            schema["required"].as_array().is_none_or(|fields| {
                fields.iter().all(|field| {
                    field
                        .as_str()
                        .is_some_and(|field| object.contains_key(field))
                })
            }) && object.iter().all(|(key, value)| {
                schema["properties"]
                    .get(key)
                    .map_or(schema["additionalProperties"] != false, |schema| {
                        matches_schema(value, schema)
                    })
            })
        }),
        Some("null") => value.is_null(),
        _ => false,
    }
}

struct InvocationGrant {
    authorizing_row: Option<crate::agent_grants::GrantUse>,
    origin: String,
    severity: Severity,
    hazards: BTreeSet<HazardClass>,
    once: bool,
}

impl InvocationGrant {
    fn covers(&self, origin: &str, severity: Severity, hazards: &BTreeSet<HazardClass>) -> bool {
        if self
            .authorizing_row
            .as_ref()
            .is_some_and(|row| !row.is_live())
        {
            return false;
        }
        (self.once || self.authorizing_row.is_some())
            && self.origin == origin
            && self.severity.covers(severity)
            && hazards.is_subset(&self.hazards)
    }
}

struct Context<'a> {
    planes: &'a Planes,
    facts: &'a AcceptedBindFacts,
    /// The key of every claim, snapshot and extension message of this call.
    route: Route,
    /// The route the call arrived on. A codemode run's `route` is its head's,
    /// but raising a card needs the inbound call's own route to be live.
    inbound: Route,
    cancel: CancelHandle,
    connection: u64,
    action: &'a str,
}

impl Context<'_> {
    fn target(&self) -> &UserBrowser {
        self.planes.user_browser.target()
    }
    fn bridge(&self) -> &UserBrowserBridge {
        &self.planes.user_browser
    }
    fn agent(&self) -> &str {
        &self.facts.identity.agent_project_id
    }
    fn granted(
        &self,
        origin: &str,
        severity: Severity,
        hazards: &BTreeSet<HazardClass>,
        once: Option<&InvocationGrant>,
    ) -> bool {
        if let Some(grant) = once {
            if grant.authorizing_row.is_some() {
                return grant.covers(origin, severity, hazards);
            }
        }
        if let Some(store) = self.planes.management.unified_agent_grants() {
            return crate::permission_scope::authorizing_holder(self.facts)
                .and_then(|holder| {
                    store.authorize(
                        &holder,
                        crate::agent_grants::GrantDemand::Browser {
                            target: crate::agent_grants::BrowserTarget::UserBrowser,
                            origin: origin.into(),
                            severity,
                            hazards: hazards.clone(),
                        },
                    )
                })
                .is_some_and(|used| {
                    crate::grant_enforcement::track(&used);
                    true
                });
        }
        once.is_some_and(|grant| grant.covers(origin, severity, hazards))
            || (!crate::permission_scope::is_worker(self.facts)
                && self
                    .target()
                    .covers(self.agent(), origin, severity, hazards))
    }

    async fn authorize(
        &self,
        origin: &str,
        severity: Severity,
        hazards: BTreeSet<HazardClass>,
    ) -> Result<InvocationGrant, Value> {
        let mut grant = InvocationGrant {
            authorizing_row: None,
            origin: origin.into(),
            severity,
            hazards,
            once: false,
        };
        if severity.tier > 4 {
            return Err(refusal("severity_ungrantable"));
        }
        if let Some(store) = self.planes.management.unified_agent_grants() {
            let holder = crate::permission_scope::authorizing_holder(self.facts);
            if let Some(used) = holder.as_ref().and_then(|holder| {
                store.authorize(
                    holder,
                    crate::agent_grants::GrantDemand::Browser {
                        target: crate::agent_grants::BrowserTarget::UserBrowser,
                        origin: origin.into(),
                        severity,
                        hazards: grant.hazards.clone(),
                    },
                )
            }) {
                crate::grant_enforcement::track(&used);
                grant.authorizing_row = Some(used);
                return Ok(grant);
            }
        }
        if self.planes.management.unified_agent_grants().is_none()
            && !crate::permission_scope::is_worker(self.facts)
            && self
                .target()
                .covers(self.agent(), origin, severity, &grant.hazards)
        {
            return Ok(grant);
        }
        if self.facts.flow_id.is_some() {
            return Err(refusal("consent_unavailable"));
        }
        let can_record = self.planes.management.unified_agent_grants().map_or_else(
            || self.target().grants.can_record(),
            |store| store.can_record(),
        );
        let holder = crate::permission_scope::minting_holder(self.facts);
        let choices = crate::permission_cards::user_browser_choices(
            &[origin.into()],
            &grant.hazards,
            severity,
            holder.as_ref(),
            can_record,
        );
        let body = site_question_with_choices(origin, severity.tier, &grant.hazards, &choices);
        crate::permission_cards::require_grant_choice(&body, holder.as_ref())
            .map_err(|error| refusal(error.reason()))?;
        register(self.planes);
        let card = consent_request(
            CardKind::UserBrowserSite,
            &body,
            CONSENT_DEADLINE,
            crate::call_context::current_call_key().as_deref(),
            None,
            None,
        )
        .map_err(|_| consent_unavailable(&Ending::DeliveryFailed))?;
        let live = crate::browser_consent::live(
            self.facts,
            self.planes,
            self.inbound.channel,
            self.inbound.epoch,
        )
        .map_err(|ending| consent_unavailable(&ending))?;
        let mut session = self
            .planes
            .consent
            .session(&live)
            .await
            .map_err(|error| consent_unavailable(&Ending::of_refusal(&error)))?;
        let subject = format!(
            "{}:demand={}",
            subject::user_browser_site(origin),
            json!([severity.tier, grant.hazards])
        );
        if self
            .planes
            .consent
            .take_lost_answer(live.session(), &subject)
        {
            return Err(
                json!({"browser":"user", "outcome":"refused", "reason":"answer_lost", "remedy":"The answer was lost; ask again.", "input_dispatched":false}),
            );
        }
        if let Some((ask_id, choice_id)) = self
            .planes
            .consent
            .take_single_use_approval(live.session(), &subject)
        {
            let Some(choice) = choices
                .iter()
                .find(|choice| choice.option_id() == choice_id)
            else {
                let _ = self.planes.consent.finish_execution(
                    &ask_id,
                    crate::cingulate_client::wire::Execution::ApprovedNotExecuted,
                    Some(crate::cingulate_client::wire::ExecutionReason::RefusedAtDispatch),
                );
                return Err(refusal("unrecognized_answer"));
            };
            if let Some(terminal) = crate::TerminalArbiter::current() {
                terminal.track_consent(Arc::clone(&self.planes.consent), &ask_id);
            }
            return self.record_agent_answer(grant, &ask_id, *choice);
        }
        // Count this call as holding the card before raising it, so a drain
        // run by another call of this session never mistakes the card for an
        // abandoned one and withdraws it while this call raises or waits on
        // it.
        let _holding = SiteCardHold::enter(&self.planes.user_browser_cards, &subject);
        // A codemode run never waits on the card: it joins a matching card that
        // is already open, or raises a new one detached, and replies pending at
        // once. When the route reads held replies, the call's durable
        // obligation must exist before any other call's drain can read and
        // acknowledge the answer, so card creation and that preparation are
        // serialized with the session's drains.
        let codemode = crate::codemode::active();
        let serialization = self.planes.consent.settlement_lock(live.session());
        let settlement = if crate::codemode::accepts_held() {
            Some(serialization.lock().await)
        } else {
            None
        };
        let ask_id = match self.planes.consent.open_card_for(live.session(), &subject) {
            Some(card) => card.elicitation_id,
            None if codemode => session
                .raise_detached(card, &subject)
                .await
                .map_err(|ending| consent_unavailable(&ending))?,
            None => session
                .raise(card, &subject)
                .await
                .map_err(|ending| consent_unavailable(&ending))?,
        };
        self.planes
            .consent
            .retain_user_browser_grant(
                &ask_id,
                crate::cingulate_client::desk::UserBrowserGrant {
                    holder: holder.ok_or_else(|| refusal("agent_not_attested"))?,
                    origin: grant.origin.clone(),
                    severity: Severity::new(
                        site_grant_tier(grant.severity.tier),
                        grant.severity.credential,
                        grant.severity.financial,
                    ),
                    hazards: grant.hazards.clone(),
                },
            )
            .map_err(|_| refusal("grant_storage_unavailable"))?;
        if codemode {
            // The retained grant above is what the session drain mints when
            // the person approves, so the run's retry finds it and asks again
            // for nothing.
            crate::codemode::prepare_consent(&ask_id, CardKind::UserBrowserSite)
                .await
                .map_err(|ending| consent_unavailable(&ending))?;
            crate::codemode::origin(origin);
            let mut pending = crate::cingulate_client::desk::pending_reply(&ask_id);
            pending["browser"] = json!("user");
            pending["input_dispatched"] = json!(false);
            return Err(pending);
        }
        drop(settlement);
        let mut drain = self.planes.drain_signal.subscribe();
        let cancel = &self.cancel;
        let cancelled = async move {
            tokio::select! {
                _ = cancel.cancelled() => {}
                _ = drain.wait_for(|draining| *draining) => {}
            }
        };
        let guard = crate::call_context::ROUTE_GUARD.try_with(Arc::clone).ok();
        let parked = guard.as_ref().map(|guard| guard.park_on_consent());
        // A bounded call cannot hold an unanswered card forever. Detachment
        // transfers responsibility for waking the agent to the consent service.
        let work_park = EXECUTION.try_with(|execution| execution.park()).ok();
        let ended = session.hold(&ask_id, CONSENT_DEADLINE, cancelled).await;
        drop(work_park);
        drop(parked);
        let ending = match ended {
            InCall::Settled(ending) => ending,
            InCall::Cancelled if *self.planes.drain_signal.borrow() => {
                return Err(refusal("module_draining"))
            }
            InCall::Cancelled => {
                return Err(json!({
                    "browser":"user", "outcome":"cancelled", "input_dispatched":false,
                }))
            }
            InCall::RouteClosed => return Err(refusal("route_closed")),
            InCall::Pending { ask_id } => {
                let mut pending = crate::cingulate_client::desk::pending_reply(&ask_id);
                pending["browser"] = json!("user");
                pending["input_dispatched"] = json!(false);
                return Err(pending);
            }
        };
        let decided = match &ending {
            Ending::Granted { choice_id }
                if choices.iter().any(|choice| choice.option_id() == choice_id) =>
            {
                if let Some(terminal) = crate::TerminalArbiter::current() {
                    terminal.track_consent(Arc::clone(&self.planes.consent), &ask_id);
                }
                let choice = choices
                    .iter()
                    .find(|choice| choice.option_id() == choice_id)
                    .unwrap();
                return self.record_agent_answer(grant, &ask_id, *choice);
            }
            Ending::Declined { choice_id } if choice_id == SITE_DENY => {
                let mut reply = refusal("consent_declined");
                reply["detail"] = json!({"decision":"deny"});
                Err(reply)
            }
            // A choice the card did not offer is never read as a refusal or
            // as consent: nothing can be concluded from it.
            Ending::Granted { .. } | Ending::Declined { .. } => {
                let mut reply = refusal("unrecognized_answer");
                reply["remedy"] =
                    json!("The answer could not be read; retry this call to ask again.");
                Err(reply)
            }
            // No readable answer grants access. A still-pending card returned
            // above remains detached rather than being withdrawn here.
            ending => return Err(consent_unavailable(ending)),
        };
        // The answer has been acted on (a standing grant is stored first), so
        // it is marked applied: later calls of this session then need not
        // read it from Cingulate's answers feed. The result is ignored on
        // purpose: if the registry cannot be saved, a later drain reads the
        // card again, finds nothing to apply, and only acknowledges it.
        let _ = self.planes.consent.mark_applied(&ask_id);
        decided
    }

    async fn cdp(
        &self,
        tab: &str,
        interaction: Option<u64>,
        commands: Vec<Value>,
    ) -> Result<Plan, Value> {
        // The journal's dispatch event commits the same terminal witness as
        // input. Read plans must remain observable without claiming mutation.
        let event = if mutating_commands(&commands) {
            "dispatch_committed"
        } else {
            "read_committed"
        };
        self.planes
            .browser
            .journal_user_browser(&self.facts.identity, self.action, None, event, None)
            .await
            .map_err(|_| refusal("journal_unavailable"))?;
        plan(
            self.bridge(),
            self.route,
            tab,
            self.connection,
            interaction,
            &self.cancel,
            commands,
            self.action == "scroll",
        )
        .await
    }

    async fn cdp_frame(
        &self,
        tab: &str,
        interaction: Option<u64>,
        frame: &FrameDocument,
        mut commands: Vec<Value>,
    ) -> Result<Plan, Value> {
        // Frame scope chooses a debugger target, not a new action. Delegate to
        // the same bridge path so dispatch policy and remaining time are shared.
        for command in &mut commands {
            command["frame_id"] = json!(frame.frame_id);
            command["loader_id"] = json!(frame.loader_id);
            command["session_id"] = json!(frame.session_id);
        }
        self.cdp(tab, interaction, commands).await
    }

    async fn document(&self, tab: &str) -> Result<Document, Value> {
        for attempt in 0..3 {
            self.target().owned(self.route, tab, self.connection)?;
            let observed = document(
                self.bridge(),
                self.route,
                tab,
                self.connection,
                &self.cancel,
            )
            .await;
            if observed
                .as_ref()
                .is_err_and(|reply| reply["reason"] == "document_not_ready")
                && attempt < 2
            {
                // History and frame metadata can straddle the first document
                // commit. Retry only that incomplete read, never stale input.
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
            return observed;
        }
        unreachable!("the bounded document loop returns on its last attempt")
    }

    /// Read `tab`'s document, waiting up to [`OBSERVER_WAIT`] for its
    /// interaction observer when the first read finds none. The last read is
    /// taken at the bound, so a caller refusing an unobserved result never
    /// refuses before the bound has passed.
    async fn observed_document(&self, tab: &str) -> Result<Document, Value> {
        let bound = tokio::time::Instant::now() + OBSERVER_WAIT;
        loop {
            let observed = self.document(tab).await?;
            let now = tokio::time::Instant::now();
            if observed.observer_available || now >= bound {
                return Ok(observed);
            }
            tokio::time::sleep(OBSERVER_POLL.min(bound - now)).await;
        }
    }
}

async fn serve_inner(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    _writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    route: Route,
    action: &str,
    args: &Value,
) -> Result<Value, Value> {
    let bridge = &planes.user_browser;
    let target = bridge.target();
    if matches!(
        action,
        "launch" | "present" | "resume" | "import_login" | "capture_login"
    ) {
        let mut reply = refusal("unsupported_action");
        reply["remedy"] = json!("Load the extension, then use open_tab or claim_tab; login and launch tools apply only to browser:own.");
        return Err(reply);
    }
    if action == "revoke_access" {
        let revoke = match args.get("origin").and_then(Value::as_str) {
            Some(value) => match always_subject(
                canonical_grant_origin(value)
                    .ok_or_else(|| invalid("origin", "noncanonical_origin"))?,
            ) {
                crate::browser_standing_grants::StandingSubject::Origin(origin) => {
                    RevokeTarget::Origin(origin)
                }
                crate::browser_standing_grants::StandingSubject::Domain(domain) => {
                    RevokeTarget::Domain(domain)
                }
                crate::browser_standing_grants::StandingSubject::AllSites => {
                    unreachable!("one-site subject")
                }
            },
            None => RevokeTarget::Everything,
        };
        let mut reply = if let Some(store) = planes.management.unified_agent_grants() {
            agent_enforcement::revoke_access(
                store,
                crate::permission_scope::authorizing_holder(facts),
                &revoke,
            )
        } else {
            target
                .grants
                .revoke(&facts.identity.agent_project_id, &revoke)
        };
        reply["browser"] = json!("user");
        return Ok(reply);
    }
    let Some(cancel) = planes.cancellations.get(request) else {
        return Err(refusal("request_not_interruptible"));
    };
    let Some(connection) = bridge.connected_epoch() else {
        if action == "status" {
            target.disconnect();
            return Ok(json!({"browser":"user","outcome":"ok","connected":false,"tabs":[]}));
        }
        if action == "close" {
            target.release(route);
            return Ok(json!({"browser":"user","outcome":"closed","input_dispatched":false}));
        }
        let mut reply = refusal("not_connected");
        reply["remedy"] = json!("Load the Chrome extension and connect its native host, then use open_tab or claim_tab.");
        return Err(reply);
    };
    target.synchronize(connection);
    let context = Context {
        planes,
        facts,
        route,
        inbound: Route {
            channel: request.0,
            epoch: request.1,
        },
        cancel,
        connection,
        action,
    };
    if action == "status" {
        let raw = invoke(bridge, route, &context.cancel, "status", json!({})).await?;
        let inventory: Inventory = decode("status_reply", raw)?;
        if inventory.connection_epoch != connection {
            return Err(read_again(false));
        }
        let mut visible = Vec::new();
        let mut state = target.state();
        if state.ended_routes.contains(&route) || state.connection != Some(connection) {
            return Err(refusal("route_closed"));
        }
        for tab in inventory.tabs {
            if tab.tab.is_empty() {
                return Err(protocol_field_error("status_reply", "tab"));
            }
            if state
                .claims
                .get(&tab.tab)
                .is_some_and(|owner| *owner != route)
            {
                continue;
            }
            if tab.claimed {
                state.claims.insert(tab.tab.clone(), route);
                visible.push(json!({"tab":tab.tab,"claim":"claimed_by_this_route","interaction_epoch":tab.interaction_epoch}));
            } else if tab.handed {
                visible.push(json!({"tab":tab.tab,"claim":"unclaimed_handed","interaction_epoch":tab.interaction_epoch}));
            }
        }
        return Ok(
            json!({"browser":"user","outcome":"ok","connected":true,"connection_epoch":connection,"tabs":visible}),
        );
    }
    if action == "close" {
        let result = invoke(bridge, route, &context.cancel, "close", json!({})).await;
        target.release(route);
        result?;
        return Ok(json!({"browser":"user","outcome":"closed","input_dispatched":false}));
    }
    if matches!(action, "open_tab" | "claim_tab") {
        if action == "claim_tab" {
            let tab = args["tab"].as_str().expect("validated tab");
            if target
                .state()
                .claims
                .get(tab)
                .is_some_and(|owner| *owner != route)
            {
                return Err(refusal("tab_already_claimed"));
            }
        }
        // `open_tab` with a page URL opens the tab blank and then navigates it
        // exactly as `navigate` would. The site is asked about first, so a
        // refused site opens no tab at all.
        let open_url = (action == "open_tab")
            .then(|| args.get("url").and_then(Value::as_str))
            .flatten()
            .filter(|url| *url != "about:blank");
        let once = match open_url {
            Some(url) => {
                let site = origin(url)?;
                let severity = authorization::effective_severity(
                    Action::Navigate,
                    Action::Navigate.floor(),
                    None,
                )
                .map_err(|_| refusal("severity_below_floor"))?;
                Some(context.authorize(&site, severity, BTreeSet::new()).await?)
            }
            None => None,
        };
        let mut command = args.clone();
        if open_url.is_some() {
            if let Some(fields) = command.as_object_mut() {
                fields.remove("url");
            }
        }
        planes
            .browser
            .journal_user_browser(&facts.identity, action, None, "dispatch_committed", None)
            .await
            .map_err(|_| refusal("journal_unavailable"))?;
        let raw = invoke(bridge, route, &context.cancel, action, command.clone()).await?;
        let claimed: Claimed = decode("tab_reply", raw)?;
        if claimed.connection_epoch != connection || bridge.connected_epoch() != Some(connection) {
            return Err(read_again(false));
        }
        if action == "claim_tab" && args["tab"] != claimed.tab {
            return Err(protocol_field_error("tab_reply", "tab"));
        }
        {
            let mut state = target.state();
            if state.ended_routes.contains(&route) || state.connection != Some(connection) {
                return Err(refusal("route_closed"));
            }
            if state
                .claims
                .get(&claimed.tab)
                .is_some_and(|owner| *owner != route)
            {
                return Err(refusal("tab_already_claimed"));
            }
            state.claims.insert(claimed.tab.clone(), route);
            // A newly claimed tab's first reply prints the settlement note again.
            state.settlement_noted.remove(&claimed.tab);
            if action == "open_tab"
                && command.get("opener_tab").is_none()
                && command
                    .get("url")
                    .and_then(Value::as_str)
                    .is_none_or(|url| url == "about:blank")
            {
                state.unobserved_blank.insert(claimed.tab.clone());
            }
        }
        let (Some(url), Some(once)) = (open_url, once) else {
            return Ok(
                json!({"browser":"user","outcome":"ok","tab":claimed.tab,"interaction_epoch":claimed.interaction_epoch,"connection_epoch":connection,"input_dispatched":false}),
            );
        };
        let tab = claimed.tab;
        let navigation = json!({"tab":tab,"url":url});
        let navigated = async {
            let current = context.document(&tab).await?;
            navigate(&context, &tab, &navigation, &current, &once).await
        }
        .await;
        // The tab now exists and is claimed even when loading the page was
        // refused, so the refusal names it for a retry with `navigate`.
        return navigated.map_err(|mut reply| {
            reply["tab"] = json!(tab);
            reply
        });
    }
    if action == "open_grant" {
        let value = args["origins"][0].as_str().expect("validated origin");
        let site = canonical_grant_origin(value)
            .ok_or_else(|| invalid("origins", "noncanonical_origin"))?;
        let hazards = args["hazards"]
            .as_array()
            .expect("validated hazards")
            .iter()
            .map(|hazard| {
                HazardClass::from_wire(hazard.as_str().unwrap())
                    .ok_or_else(|| invalid("hazards", "unsupported_value"))
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let tier = args["severity_tier"].as_u64().unwrap_or(1) as u8;
        context
            .authorize(
                &site,
                Severity::new(
                    tier,
                    hazards.contains(&HazardClass::CredentialFormSubmit),
                    hazards.contains(&HazardClass::FinancialFormSubmit),
                ),
                hazards,
            )
            .await?;
        // The next user-browser call is scoped to this site, so name what was authorized.
        return Ok(json!({"browser":"user","outcome":"ok","origin":site,"input_dispatched":false}));
    }
    let tab = args["tab"].as_str().expect("validated tab");
    // A read issued just after a navigation can arrive before the new
    // document's observer is installed. Wait for it, bounded, rather than
    // refusing a read the caller cannot postpone. Input does not wait: it
    // acts only under the observer its snapshot saw, and a reinstalled one
    // can never match that. Navigation does not wait either, so an
    // agent-created blank tab, which has no observer yet, navigates at once.
    let current = if matches!(action, "snapshot" | "screenshot") {
        context.observed_document(tab).await?
    } else {
        context.document(tab).await?
    };
    let created_blank = action == "navigate"
        && current.committed.url == "about:blank"
        && target.state().unobserved_blank.contains(tab);
    if !current.observer_available && !created_blank {
        return Err(observer_unavailable());
    }
    if matches!(action, "snapshot" | "screenshot" | "navigate") {
        let site = if action == "navigate" {
            origin(args["url"].as_str().unwrap())?
        } else {
            origin(&current.committed.url)?
        };
        let severity = if action == "navigate" {
            authorization::effective_severity(Action::Navigate, declared_severity(args)?, None)
                .map_err(|_| refusal("severity_below_floor"))?
        } else {
            Severity::new(1, false, false)
        };
        let once = context.authorize(&site, severity, BTreeSet::new()).await?;
        if action == "navigate" {
            return navigate(&context, tab, args, &current, &once).await;
        }
        let observed = context.document(tab).await?;
        if !observed.observer_available
            || observed.observer_continuity != current.observer_continuity
        {
            return Err(observer_unavailable());
        }
        if observed.committed != current.committed || observed.interaction != current.interaction {
            return Err(read_again(false));
        }
        bind_observer_continuity(observed.observer_continuity);
        if action == "screenshot" {
            return screenshot(&context, tab, args, &observed, &once).await;
        }
        let known_zoom = args["zoom"].as_str().is_some_and(|reference| {
            target
                .state()
                .snapshots
                .values()
                .any(|snapshot| snapshot.refs.contains_key(reference))
        });
        let zoom = if known_zoom {
            Some(target.snapshot(route, tab, connection, &json!({"ref":args["zoom"]}))?)
        } else {
            None
        };
        return capture(&context, tab, args, &observed, &once, zoom.as_ref()).await;
    }
    if action == "scroll" {
        return scroll(&context, tab, args, &current).await;
    }
    input(&context, tab, action, args, &current).await
}

/// Navigate a claimed tab to `args["url"]` after `once` authorized that site,
/// then confirm the landing document is observed and its site authorized.
/// `current` is the document read before authorization. `navigate` and
/// `open_tab` with a URL share this, so both apply the same checks.
async fn navigate(
    context: &Context<'_>,
    tab: &str,
    args: &Value,
    current: &Document,
    once: &InvocationGrant,
) -> Result<Value, Value> {
    let observed = context.document(tab).await?;
    let created_blank = current.committed.url == "about:blank"
        && observed.committed.url == "about:blank"
        && context.target().state().unobserved_blank.contains(tab)
        && (!current.observer_available || !observed.observer_available);
    // An openerless agent-created blank document may not have an observer
    // before an HTTP document commits. Only explicit initial navigation may lack
    // observation; reference input and handed tabs never receive this exception.
    if !created_blank
        && (!current.observer_available
            || !observed.observer_available
            || current.observer_continuity != observed.observer_continuity)
    {
        return Err(observer_unavailable());
    }
    if !created_blank
        && (current.committed != observed.committed || current.interaction != observed.interaction)
    {
        return Err(read_again(false));
    }
    if !created_blank {
        bind_observer_continuity(observed.observer_continuity);
    }
    let navigation = context
        .cdp(
            tab,
            (!created_blank).then_some(observed.interaction),
            vec![command("Page.navigate", json!({"url":args["url"]}))],
        )
        .await?;
    if navigation.results[0].get("errorText").is_some() {
        return Err(refusal("navigation_failed"));
    }
    context.target().state().unobserved_blank.remove(tab);
    let loader = navigation.results[0]["loaderId"].as_str();
    let deadline = tokio::time::Instant::now() + NAVIGATION_READ_DEADLINE;
    let mut ticks = tokio::time::interval(Duration::from_millis(25));
    let mut observer_deadline = None;
    let landed = loop {
        if tokio::time::Instant::now() >= deadline {
            return Err(refusal("navigation_read_deadline"));
        }
        ticks.tick().await;
        let landed = context.document(tab).await?;
        if loader.is_some_and(|loader| landed.committed.loader_id == loader)
            || (loader.is_none()
                && (landed.committed.url == args["url"].as_str().unwrap()
                    || landed.committed.url != current.committed.url))
        {
            if landed.observer_available {
                break landed;
            }
            let limit = observer_deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + Duration::from_secs(5));
            // The landing document has committed, so the navigation took
            // effect. A missing observer withholds only the page read and the
            // input baseline, never the navigation's own outcome.
            if tokio::time::Instant::now() >= *limit {
                break landed;
            }
        }
    };
    let landing = origin(&landed.committed.url)?;
    if !context.granted(
        &landing,
        Severity::new(1, false, false),
        &BTreeSet::new(),
        Some(once),
    ) {
        return Err(refusal("landing_site_not_authorized"));
    }
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"connection_epoch":context.connection,"interaction_epoch":landed.interaction,"input_dispatched":false});
    // Plans carry command results, not the Page/Network event stream
    // the own-browser Tracker uses to establish network quiet.
    reply["settled"] = json!(false);
    reply["settlement_reason"] = json!("settlement isn't observed on the person's browser");
    reply["remedy"] =
        json!("Read the page before acting; only its committed document was confirmed.");
    if navigation.popup {
        reply["popup_activated_briefly"] = json!(true);
    }
    if !landed.observer_available {
        // Without an observer the landed page cannot be read, and its
        // interaction epoch cannot authorize input until a snapshot finds one.
        reply["observer_available"] = json!(false);
        reply["remedy"] = json!("The page changed; take a snapshot before acting.");
        if args["read_page"] == true {
            reply["read_page"] = observer_unavailable();
        }
        return Ok(reply);
    }
    if args["read_page"] == true {
        // The navigation has committed whatever happens to its read, so a
        // read that cannot be taken is reported beside the committed outcome,
        // never as a refusal of the navigation itself.
        reply["read_page"] = match read_landed_page(context, tab, args, landed, once).await {
            Ok(read) => read,
            Err(mut refused) => {
                if refused.get("remedy").is_none() {
                    refused["remedy"] =
                        json!("The page read is not available; take a snapshot of the tab.");
                }
                refused
            }
        };
    }
    Ok(reply)
}

/// Read the page a navigation landed on. The landing document's observer was
/// confirmed before this read, but a page that is still committing child
/// frames can replace it during the capture. Then wait for the observer once,
/// bounded by [`OBSERVER_WAIT`], and read again if the tab still shows the
/// same committed document, whose site the navigation already authorized.
async fn read_landed_page(
    context: &Context<'_>,
    tab: &str,
    args: &Value,
    landed: Document,
    once: &InvocationGrant,
) -> Result<Value, Value> {
    bind_observer_continuity(landed.observer_continuity);
    let refused = match capture(context, tab, args, &landed, once, None).await {
        Err(refused) if refused["reason"] == "observer_unavailable" => refused,
        read => return read,
    };
    let again = context.observed_document(tab).await?;
    if !again.observer_available || again.committed != landed.committed {
        return Err(refused);
    }
    bind_observer_continuity(again.observer_continuity);
    capture(context, tab, args, &again, once, None).await
}

fn baseline(context: &Context<'_>, tab: &str, document: &Document) -> Snapshot {
    Snapshot {
        route: context.route,
        tab: tab.into(),
        connection: context.connection,
        interaction: document.interaction,
        observer_continuity: document.observer_continuity,
        document: document.committed.clone(),
        refs: BTreeMap::new(),
        image: None,
    }
}

async fn confirm(context: &Context<'_>, tab: &str, expected: &Document) -> Result<(), Value> {
    let observed = context.document(tab).await?;
    if !observed.observer_available || observed.observer_continuity != expected.observer_continuity
    {
        return Err(observer_unavailable());
    }
    if observed.committed != expected.committed
        || observed.interaction != expected.interaction
        || observed.frames.len() != expected.frames.len()
        || !observed
            .frames
            .iter()
            .zip(&expected.frames)
            .all(|(a, b)| a.same_document(b))
    {
        return Err(read_again(false));
    }
    Ok(())
}

async fn capture(
    context: &Context<'_>,
    tab: &str,
    args: &Value,
    document: &Document,
    once: &InvocationGrant,
    zoom: Option<&Snapshot>,
) -> Result<Value, Value> {
    let mut retry_document = None;
    for attempt in 0..2 {
        let current = retry_document.as_ref().unwrap_or(document);
        let result = capture_attempt(context, tab, args, current, once, zoom, attempt != 0)
            .await
            .map_err(|mut reply| {
                if args.get("zoom").is_some() && reply["reason"] == "cdp_error" {
                    reply["detail"]["step"] = reply["detail"]["method"].clone();
                }
                reply
            });
        if attempt == 0
            && result
                .as_ref()
                .err()
                .is_some_and(|reply| reply["reason"] == "frame_tree_changed")
        {
            let current = context.document(tab).await?;
            if current.committed != document.committed
                || current.interaction != document.interaction
            {
                return Err(read_again(false));
            }
            retry_document = Some(current);
        } else {
            return result;
        }
    }
    unreachable!("the second capture returns its partial result")
}

fn mark_unreadable_frame(
    records: &mut Vec<crate::snapshot_store::AxRecord>,
    record_frames: &mut Vec<String>,
    snapshot: &mut Snapshot,
    facts: &mut HashMap<String, state_text::NodeFacts>,
    frame_id: &str,
    owner_index: Option<usize>,
    reason: FrameReadFailure,
) {
    let marker = crate::snapshot_store::AxRecord {
        depth: owner_index.map_or(1, |index| records[index].depth),
        role: "StaticText".into(),
        name: format!("[embedded frame not readable: {}]", reason.label()),
        value: None,
        reference: None,
    };
    if let Some(index) = owner_index {
        // Chrome can include child text without a frame tag in the parent's
        // accessibility capture. Replacing only the owner would leave that
        // unreadable document's text or refs beneath its omission marker.
        let end = records[index + 1..]
            .iter()
            .position(|record| record.depth <= records[index].depth)
            .map_or(records.len(), |offset| index + 1 + offset);
        for record in &records[index..end] {
            if let Some(reference) = &record.reference {
                snapshot.refs.remove(reference);
                facts.remove(reference);
            }
        }
        records.splice(index..end, [marker]);
        record_frames.splice(index..end, [frame_id.to_owned()]);
    } else {
        records.push(marker);
        record_frames.push(frame_id.to_owned());
    }
}

async fn capture_attempt(
    context: &Context<'_>,
    tab: &str,
    args: &Value,
    document: &Document,
    once: &InvocationGrant,
    zoom: Option<&Snapshot>,
    allow_partial_change: bool,
) -> Result<Value, Value> {
    let id = opaque("us");
    let mut snapshot = baseline(context, tab, document);
    let prior_refs = context.target().prior_refs(&snapshot);
    let mut records = Vec::new();
    let mut record_frames = Vec::new();
    let mut frame_owners = BTreeMap::new();
    let mut included_owners = BTreeSet::new();
    let mut failed_frames = BTreeSet::new();
    let mut facts = HashMap::new();
    let mut html = Vec::new();
    let mut landmark_html = BTreeMap::new();
    let mut popup = false;
    let mut ax_truncated = false;
    let mut refs_truncated = false;
    let mut zoom_target = None;
    let mut zoom_notice = String::new();
    let mut omitted_frames = 0;
    let zoom_ref = args["zoom"].as_str();
    let expected_zoom =
        zoom.and_then(|snapshot| zoom_ref.and_then(|reference| snapshot.refs.get(reference)));
    if zoom.is_some_and(|snapshot| {
        snapshot.document != document.committed || snapshot.interaction != document.interaction
    }) {
        return Err(read_again(false));
    }
    if expected_zoom.is_some_and(|reference| {
        !document
            .unreadable_frames
            .contains_key(&reference.frame.frame_id)
            && !document
                .frames
                .iter()
                .any(|frame| frame.same_document(&reference.frame))
    }) {
        return Err(refusal("frame_changed"));
    }
    for frame in &document.frames {
        if frame.parent_id.as_ref().is_some_and(|id| {
            document.unreadable_frames.contains_key(id)
                && document
                    .frames
                    .iter()
                    .any(|parent| &parent.frame_id == id && parent.parent_id.is_some())
        }) {
            continue;
        }
        if records.len() >= crate::snapshot_store::MAX_REFS {
            refs_truncated = true;
        }
        if !context.granted(
            &origin(&document.committed.url)?,
            Severity::new(1, false, false),
            &BTreeSet::new(),
            Some(once),
        ) {
            continue;
        }
        let owner_index = {
            if let Some(parent_id) = &frame.parent_id {
                let parent = document
                    .frames
                    .iter()
                    .find(|parent| &parent.frame_id == parent_id)
                    .ok_or_else(|| refusal("frame_changed"))?;
                let owner = context
                    .cdp_frame(
                        tab,
                        Some(document.interaction),
                        parent,
                        vec![command(
                            "DOM.getFrameOwner",
                            json!({"frameId":frame.frame_id}),
                        )],
                    )
                    .await;
                let owner = match owner {
                    Ok(owner) => owner,
                    Err(reply) if FrameReadFailure::from_reply(&reply).is_some() => {
                        mark_unreadable_frame(
                            &mut records,
                            &mut record_frames,
                            &mut snapshot,
                            &mut facts,
                            &frame.frame_id,
                            None,
                            FrameReadFailure::from_reply(&reply).unwrap(),
                        );
                        omitted_frames += 1;
                        continue;
                    }
                    Err(reply) => return Err(reply),
                };
                let backend = owner.results[0]["backendNodeId"]
                    .as_u64()
                    .ok_or_else(|| protocol_field_error("DOM.getFrameOwner", "backendNodeId"))?;
                let owner_ref = snapshot
                    .refs
                    .iter()
                    .find(|(_, reference)| {
                        reference.frame.same_document(parent)
                            && reference.identity.backend_node_id == backend
                    })
                    .map(|(name, _)| name);
                let index = owner_ref.and_then(|name| {
                    records
                        .iter()
                        .position(|record: &crate::snapshot_store::AxRecord| {
                            record.reference.as_ref() == Some(name)
                        })
                });
                index
            } else {
                None
            }
        };
        if let Some(index) = owner_index {
            if let Some(reference) = &records[index].reference {
                frame_owners.insert(frame.frame_id.clone(), reference.clone());
            }
        }
        if frame.parent_id.is_some() {
            if let Some(reason) = document
                .unreadable_frames
                .get(&frame.frame_id)
                .copied()
                .or_else(|| {
                    (owner_index.is_none() || records.len() >= crate::snapshot_store::MAX_REFS)
                        .then_some(FrameReadFailure::Stale)
                })
            {
                mark_unreadable_frame(
                    &mut records,
                    &mut record_frames,
                    &mut snapshot,
                    &mut facts,
                    &frame.frame_id,
                    owner_index,
                    reason,
                );
                omitted_frames += 1;
                continue;
            }
        }
        let plan = context
            .cdp_frame(
                tab,
                Some(document.interaction),
                frame,
                vec![
                    command("Accessibility.enable", json!({})),
                    command(
                        "Accessibility.getFullAXTree",
                        json!({"frameId":frame.frame_id}),
                    ),
                    command("DOM.enable", json!({})),
                    command(
                        "DOM.getFlattenedDocument",
                        json!({"depth":-1,"pierce":true}),
                    ),
                ],
            )
            .await;
        let plan = match plan {
            Ok(plan) => plan,
            Err(reply)
                if frame.parent_id.is_some() && FrameReadFailure::from_reply(&reply).is_some() =>
            {
                mark_unreadable_frame(
                    &mut records,
                    &mut record_frames,
                    &mut snapshot,
                    &mut facts,
                    &frame.frame_id,
                    owner_index,
                    FrameReadFailure::from_reply(&reply).unwrap(),
                );
                omitted_frames += 1;
                continue;
            }
            Err(reply) => return Err(reply),
        };
        popup |= plan.popup;
        let nodes = plan.results[1]["nodes"]
            .as_array()
            .ok_or_else(|| protocol_field_error("Accessibility.getFullAXTree", "nodes"))?;
        let dom = plan.results[3]
            .as_object()
            .ok_or_else(|| protocol_error("DOM.getFlattenedDocument", None))?;
        let observation = snapshot_from_capture(
            nodes,
            dom,
            tab,
            &frame.frame_id,
            document.interaction,
            &frame.url,
            &frame.origin,
        )
        .map_err(|_| {
            let mut reply = refusal("snapshot_not_ready");
            reply["remedy"] = json!("read again");
            reply
        });
        let mut observation = match observation {
            Ok(observation) => observation,
            Err(_) if frame.parent_id.is_some() => {
                mark_unreadable_frame(
                    &mut records,
                    &mut record_frames,
                    &mut snapshot,
                    &mut facts,
                    &frame.frame_id,
                    owner_index,
                    FrameReadFailure::Stale,
                );
                omitted_frames += 1;
                continue;
            }
            Err(reply) => return Err(reply),
        };
        ax_truncated |= observation.ax_truncated;
        refs_truncated |= observation.refs_truncated;
        let remaining = crate::snapshot_store::MAX_REFS.saturating_sub(records.len());
        if let Some(index) = owner_index {
            if observation.records.is_empty()
                || observation.ax_truncated
                || observation.refs_truncated
                || observation.records.len() > remaining
                || snapshot.refs.len() + observation.refs.len() > crate::snapshot_store::MAX_REFS
            {
                // No child records, or records/refs cut by a capture limit,
                // cannot establish a complete embedded document. Replace the
                // iframe element with an unreadable marker, not just a flag.
                refs_truncated |= observation.records.len() > remaining;
                mark_unreadable_frame(
                    &mut records,
                    &mut record_frames,
                    &mut snapshot,
                    &mut facts,
                    &frame.frame_id,
                    Some(index),
                    FrameReadFailure::Stale,
                );
                omitted_frames += 1;
                continue;
            }
            if let Some(reference) = &records[index].reference {
                included_owners.insert(reference.clone());
            }
        }
        if observation.records.len() > remaining {
            observation.records.truncate(remaining);
            ax_truncated = true;
            refs_truncated = true;
        }
        let mut renamed = BTreeMap::new();
        for reference in observation.refs {
            if snapshot.refs.len() >= crate::snapshot_store::MAX_REFS {
                refs_truncated = true;
                continue;
            }
            let Some(mut identity) = reference.backend_identity else {
                continue;
            };
            // The AX projection's frame id comes from Chrome. Never bind a
            // ref from another document into this frame's authorized scope.
            if identity.frame_id != frame.frame_id {
                continue;
            }
            identity.target_id = tab.into();
            let fresh = prior_refs
                .get(&(identity.frame_id.clone(), identity.backend_node_id))
                .filter(|(_, previous)| previous.same_document(frame))
                .map(|(name, _)| name.clone())
                .unwrap_or_else(|| {
                    // Never recycle numbers after releasing a route or reconnecting:
                    // a ref from another tab must not accidentally name a local node.
                    format!(
                        "e{}",
                        context
                            .target()
                            .next_ref
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
                    )
                });
            if expected_zoom.is_some_and(|expected| expected.identity == identity) {
                zoom_target = Some(fresh.clone());
            }
            renamed.insert(reference.captured.reference.clone(), fresh.clone());
            snapshot.refs.insert(
                fresh,
                ShownRef {
                    role_name: typing::role_name(nodes, identity.backend_node_id),
                    identity,
                    frame: frame.clone(),
                    classification: reference.classification.ok().map(|record| *record),
                },
            );
        }
        for record in &mut observation.records {
            if let Some(old) = record.reference.take() {
                record.reference = renamed.get(&old).cloned();
            }
            // Refs cannot retain field values after their DOM classification was
            // withheld. The shared renderer also withholds unknown field values.
        }
        for (old, value) in observation.facts {
            if let Some(fresh) = renamed.get(&old) {
                facts.insert(fresh.clone(), value);
            }
        }
        let owners = vec![frame.frame_id.clone(); observation.records.len()];
        if let Some(owner_index) = owner_index {
            let index = owner_index + 1;
            let depth = records[owner_index].depth + 1;
            for record in &mut observation.records {
                record.depth += depth;
            }
            records.splice(index..index, observation.records);
            record_frames.splice(index..index, owners);
        } else {
            records.extend(observation.records);
            record_frames.extend(owners);
        }
        if args["mode"] == "dom_full" {
            if zoom_ref.is_some() && zoom_target.is_none() {
                continue;
            }
            if expected_zoom.is_some_and(|reference| !reference.frame.same_document(frame)) {
                continue;
            }
            let root = expected_zoom
                .map(|reference| reference.identity.backend_node_id)
                .or_else(|| {
                    nodes
                        .first()
                        .and_then(|node| node["backendDOMNodeId"].as_u64())
                });
            let Some(root) = root else {
                if frame.parent_id.is_some() {
                    failed_frames.insert(frame.frame_id.clone());
                    continue;
                }
                return Err(refusal("snapshot_not_ready"));
            };
            let root = if expected_zoom.is_some() {
                let (root, kind) = crate::browser::zoom::enclosing_element(dom, root)
                    .map_err(|_| protocol_field_error("DOM.getFlattenedDocument", "nodes"))?;
                if let (Some(reference), Some(kind)) = (zoom_ref, kind) {
                    zoom_notice = crate::browser::zoom::enclosing_notice(reference, kind);
                }
                root
            } else {
                root
            };
            // Read only outermost landmarks in the requested subtree. Nested
            // landmarks are already held by their parent's markup, and a cap
            // bounds the extra CDP reads on pages with many landmarks.
            let frame_records: Vec<_> = records
                .iter()
                .zip(&record_frames)
                .filter(|(_, owner)| *owner == &frame.frame_id)
                .map(|(record, _)| record)
                .collect();
            let start = zoom_target
                .as_ref()
                .and_then(|target| {
                    frame_records
                        .iter()
                        .position(|record| record.reference.as_ref() == Some(target))
                })
                .unwrap_or(0);
            let mut inside = None;
            let mut landmarks = Vec::new();
            for record in frame_records.iter().skip(start + 1) {
                if record.depth <= frame_records[start].depth {
                    break;
                }
                if inside.is_some_and(|depth| record.depth > depth) {
                    continue;
                }
                inside = None;
                if !dom_layout::is_landmark(&record.role) {
                    continue;
                }
                if let Some(reference) = record
                    .reference
                    .as_ref()
                    .filter(|reference| snapshot.refs.contains_key(*reference))
                {
                    landmarks.push(reference.clone());
                    inside = Some(record.depth);
                    if landmarks.len() == 16 {
                        break;
                    }
                }
            }
            let mut commands = vec![command("DOM.getOuterHTML", json!({"backendNodeId":root}))];
            commands.extend(landmarks.iter().map(|reference| {
                command(
                    "DOM.getOuterHTML",
                    json!({"backendNodeId":snapshot.refs[reference].identity.backend_node_id}),
                )
            }));
            let outer = context
                .cdp_frame(tab, Some(document.interaction), frame, commands)
                .await;
            let outer = match outer {
                Ok(outer) => outer,
                Err(reply)
                    if frame.parent_id.is_some()
                        && FrameReadFailure::from_reply(&reply).is_some() =>
                {
                    failed_frames.insert(frame.frame_id.clone());
                    continue;
                }
                Err(reply) => return Err(reply),
            };
            html.push((
                frame.frame_id.clone(),
                outer.results[0]["outerHTML"]
                    .as_str()
                    .ok_or_else(|| protocol_field_error("DOM.getOuterHTML", "outerHTML"))?
                    .to_owned(),
            ));
            for (reference, result) in landmarks.into_iter().zip(outer.results.iter().skip(1)) {
                landmark_html.insert(
                    reference,
                    result["outerHTML"]
                        .as_str()
                        .ok_or_else(|| protocol_field_error("DOM.getOuterHTML", "outerHTML"))?
                        .to_owned(),
                );
            }
        }
    }
    // A parent AX tree can expose an iframe that neither frame discovery nor
    // auto-attach accounted for. Completeness must be checked against visible
    // owners too; checking only the discovered child list silently loses them.
    let mut index = 0;
    while index < records.len() {
        let record = &records[index];
        if (record.role.eq_ignore_ascii_case("iframe")
            || record.role.eq_ignore_ascii_case("iframepresentational"))
            && !record
                .reference
                .as_ref()
                .is_some_and(|reference| included_owners.contains(reference))
        {
            let frame_id = frame_owners
                .iter()
                .find(|(_, owner)| record.reference.as_ref() == Some(owner))
                .map(|(frame, _)| frame.clone())
                .unwrap_or_else(|| format!("unmapped-owner-{index}"));
            mark_unreadable_frame(
                &mut records,
                &mut record_frames,
                &mut snapshot,
                &mut facts,
                &frame_id,
                Some(index),
                FrameReadFailure::Stale,
            );
            omitted_frames += 1;
        }
        index += 1;
    }
    let omitted_zoom = expected_zoom.is_some_and(|reference| {
        document
            .unreadable_frames
            .contains_key(&reference.frame.frame_id)
            || records.iter().zip(&record_frames).any(|(record, frame)| {
                frame == &reference.frame.frame_id
                    && record.name.starts_with("[embedded frame not readable:")
            })
    });
    let observed = context.document(tab).await?;
    if !observed.observer_available || observed.observer_continuity != document.observer_continuity
    {
        return Err(observer_unavailable());
    }
    if observed.committed != document.committed || observed.interaction != document.interaction {
        return Err(read_again(false));
    }
    if let Some(requested) = zoom_ref.filter(|_| zoom_target.is_none() && !omitted_zoom) {
        let text = state_text::missing_zoom(
            requested,
            records.iter().filter(|record| {
                record
                    .reference
                    .as_ref()
                    .is_some_and(|name| prior_refs.values().any(|(prior, _)| prior == name))
            }),
        );
        return Ok(
            json!({"browser":"user", "outcome":"ref_not_found", "tab":tab,
            "state_text":text,"input_dispatched":false}),
        );
    }
    let mut changed = failed_frames;
    for frame in document
        .frames
        .iter()
        .chain(&observed.frames)
        .filter(|frame| frame.parent_id.is_some())
    {
        let before = document
            .frames
            .iter()
            .find(|candidate| candidate.frame_id == frame.frame_id);
        let after = observed
            .frames
            .iter()
            .find(|candidate| candidate.frame_id == frame.frame_id);
        if before
            .zip(after)
            .is_none_or(|(before, after)| !before.same_document(after))
            || document.unreadable_frames.get(&frame.frame_id)
                != observed.unreadable_frames.get(&frame.frame_id)
        {
            changed.insert(frame.frame_id.clone());
        }
    }
    if !changed.is_empty() && !allow_partial_change {
        return Err(refusal("frame_tree_changed"));
    }
    if !changed.is_empty() {
        // A child whose document or verified mapping changes during both read
        // attempts cannot supply current text or refs. Omit its subtree while
        // preserving the unchanged top document and sibling captures.
        for _ in 0..64 {
            let mut added = false;
            for frame in document.frames.iter().chain(&observed.frames) {
                if frame
                    .parent_id
                    .as_ref()
                    .is_some_and(|id| changed.contains(id))
                {
                    added |= changed.insert(frame.frame_id.clone());
                }
            }
            if !added {
                break;
            }
        }
        let affected: Vec<_> = document
            .frames
            .iter()
            .chain(&observed.frames)
            .filter(|frame| {
                changed.contains(&frame.frame_id)
                    && !frame
                        .parent_id
                        .as_ref()
                        .is_some_and(|id| changed.contains(id))
            })
            .cloned()
            .collect();
        let mut marked = BTreeSet::new();
        for frame in affected {
            if !marked.insert(frame.frame_id.clone()) {
                continue;
            }
            let reason = observed
                .unreadable_frames
                .get(&frame.frame_id)
                .copied()
                .unwrap_or(FrameReadFailure::Stale);
            let owner_index = frame_owners
                .get(&frame.frame_id)
                .and_then(|owner| {
                    records
                        .iter()
                        .position(|record| record.reference.as_ref() == Some(owner))
                })
                .or_else(|| record_frames.iter().position(|id| id == &frame.frame_id));
            mark_unreadable_frame(
                &mut records,
                &mut record_frames,
                &mut snapshot,
                &mut facts,
                &frame.frame_id,
                owner_index,
                reason,
            );
        }
        let mut markers = BTreeSet::new();
        let pairs = std::mem::take(&mut records)
            .into_iter()
            .zip(std::mem::take(&mut record_frames));
        for (record, owner) in pairs {
            if !changed.contains(&owner)
                || (record.name.starts_with("[embedded frame not readable:")
                    && markers.insert(owner.clone()))
            {
                records.push(record);
                record_frames.push(owner);
            }
        }
        snapshot
            .refs
            .retain(|_, reference| !changed.contains(&reference.frame.frame_id));
        facts.retain(|reference, _| snapshot.refs.contains_key(reference));
        html.retain(|(frame, _)| !changed.contains(frame));
        omitted_frames = omitted_frames.max(markers.len());
    }
    let max_bytes = args["max_bytes"].as_u64().unwrap_or(5000).min(262144) as usize;
    let mut filters = Filters {
        text: args["text_filter"].as_str().map(str::to_owned),
        roles: args["role_filter"]
            .as_array()
            .map(|roles| {
                roles
                    .iter()
                    .filter_map(|role| role.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default(),
    };
    if args["mode"] == "ax" {
        // Matching every captured role expands the full accessibility tree
        // through the same renderer that masks protected or unknown values.
        filters.roles = records
            .iter()
            .map(|record| record.role.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
    }
    let rendered = state_text::render_with_capture_status(
        &RenderInput {
            records: &records,
            facts: &facts,
            page_url: &document.committed.url,
            snapshot_id: &id,
            zoom: zoom_ref.filter(|_| !omitted_zoom).map(|requested| Zoom {
                requested,
                target: zoom_target.as_deref(),
            }),
            filters: &filters,
            max_bytes,
        },
        ax_truncated || refs_truncated,
    );
    let (text, text_truncated) = if args["mode"] == "dom_full" {
        let mut seen = BTreeSet::new();
        let mut documents = Vec::new();
        for frame in document.frames.iter().chain(&observed.frames) {
            if expected_zoom.is_some_and(|reference| !reference.frame.same_document(frame)) {
                continue;
            }
            if !seen.insert(&frame.frame_id) {
                continue;
            }
            if let Some((marker, _)) = records.iter().zip(&record_frames).find(|(record, owner)| {
                *owner == &frame.frame_id
                    && record.name.starts_with("[embedded frame not readable:")
            }) {
                documents.push(marker.name.as_str());
            } else if let Some((_, html)) = html.iter().find(|(owner, _)| owner == &frame.frame_id)
            {
                documents.push(html.as_str());
            }
        }
        for (record, frame) in records.iter().zip(&record_frames) {
            if !seen.contains(frame)
                && record.name.starts_with("[embedded frame not readable:")
                && expected_zoom.is_none_or(|reference| &reference.frame.frame_id == frame)
            {
                documents.push(record.name.as_str());
            }
        }
        let landmarks: Vec<_> = records
            .iter()
            .filter_map(|record| {
                let reference = record.reference.as_ref()?;
                snapshot.refs.get(reference)?;
                Some(DomLandmark {
                    role: &record.role,
                    reference,
                    markup: landmark_html.get(reference)?,
                })
            })
            .collect();
        while zoom_notice.len() > max_bytes {
            zoom_notice.pop();
        }
        let max_bytes = max_bytes.saturating_sub(zoom_notice.len());
        let layout = dom_layout::lay_out(&documents.join("\n"), &landmarks, max_bytes);
        snapshot
            .refs
            .retain(|reference, _| layout.named_refs.contains(reference));
        (
            format!("{zoom_notice}{}", layout.text),
            layout.omitted_bytes > 0 || layout.omitted_lines > 0,
        )
    } else {
        snapshot
            .refs
            .retain(|reference, _| rendered.printed_refs.contains(reference));
        // AX and actionable reads share the renderer that withholds protected
        // field values. Its output budget can cut an otherwise complete tree.
        (
            rendered.text,
            rendered.cut_bytes > 0 || rendered.cut_lines > 0,
        )
    };
    let truncated = ax_truncated || refs_truncated || text_truncated;
    context.target().retain(id.clone(), snapshot);
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"snapshot_id":id,"connection_epoch":context.connection,"interaction_epoch":document.interaction,"state_text":text,"input_dispatched":false,"truncated":truncated,"refs_truncated":refs_truncated});
    // A committed document and an unchanged interaction epoch do not establish
    // that Chrome has finished loading its page or accessibility tree.
    reply["settled"] = json!(false);
    if omitted_frames != 0 {
        reply["omitted_frames"] = json!(omitted_frames);
    }
    reply["settlement_reason"] = json!("Page settlement is not observed on the person's browser.");
    if ax_truncated || refs_truncated {
        reply["remedy"] = json!(state_text::capture_cut_notice(&filters));
    } else if truncated {
        reply["remedy"] = json!(state_text::BYTE_CUT_NOTICE);
    } else if args["mode"] != "dom_full"
        && records.iter().all(|record| record.role == "RootWebArea")
    {
        reply["remedy"] = json!("Chrome exposed no page content beyond the document root. This may be an empty or still-loading page; read again before assuming controls are absent.");
    }
    if popup {
        reply["popup_activated_briefly"] = json!(true);
    }
    Ok(reply)
}

async fn screenshot(
    context: &Context<'_>,
    tab: &str,
    args: &Value,
    document: &Document,
    once: &InvocationGrant,
) -> Result<Value, Value> {
    if !context.granted(
        &origin(&document.committed.url)?,
        Severity::new(1, false, false),
        &BTreeSet::new(),
        Some(once),
    ) {
        return Err(refusal("landing_site_not_authorized"));
    }
    let metrics = context
        .cdp(
            tab,
            Some(document.interaction),
            vec![command("Page.getLayoutMetrics", json!({}))],
        )
        .await?;
    let viewport = &metrics.results[0]["cssVisualViewport"];
    let transform = viewport_transform(viewport)?;
    let max_bytes = args["max_bytes"].as_u64().unwrap_or(262144) as usize;
    let mut image = String::new();
    let mut captured_scale = 1.0;
    for scale in crate::browser::navigation::SCREENSHOT_SCALE_STEPS {
        let mut params = json!({"format":"png","fromSurface":true,"captureBeyondViewport":false});
        if scale < 1.0 {
            params["clip"] = json!({
                "x":viewport["pageX"].as_f64().ok_or_else(|| protocol_field_error("Page.getLayoutMetrics", "cssVisualViewport.pageX"))?,
                "y":viewport["pageY"].as_f64().ok_or_else(|| protocol_field_error("Page.getLayoutMetrics", "cssVisualViewport.pageY"))?,
                "width":transform.width_input_css,"height":transform.height_input_css,"scale":scale
            });
        }
        let capture = context
            .cdp(
                tab,
                Some(document.interaction),
                vec![
                    command("Page.getLayoutMetrics", json!({})),
                    command("Page.captureScreenshot", params),
                    command("Page.getLayoutMetrics", json!({})),
                ],
            )
            .await?;
        if viewport != &capture.results[0]["cssVisualViewport"]
            || viewport != &capture.results[2]["cssVisualViewport"]
        {
            return Err(refusal("viewport_changed"));
        }
        image = capture.results[1]["data"]
            .as_str()
            .ok_or_else(|| protocol_field_error("Page.captureScreenshot", "data"))?
            .into();
        captured_scale = scale;
        if image.len() <= max_bytes {
            break;
        }
    }
    if image.len() > max_bytes {
        let mut reply = refusal("image_too_large");
        reply["remedy"] = json!("The screenshot still exceeds max_bytes at the smallest scale (1/16 of the initial linear size); increase max_bytes or request a text snapshot.");
        return Err(reply);
    }
    let decoded = crate::coordinate::validate_png_base64_dimensions(&image)
        .map_err(|_| refusal("screenshot_not_ready"))?;
    let width = u64::from(decoded.width_px());
    let height = u64::from(decoded.height_px());
    confirm(context, tab, document).await?;
    let id = opaque("ui");
    let mut snapshot = baseline(context, tab, document);
    snapshot.image = Some(Image {
        width,
        height,
        viewport: viewport.clone(),
    });
    context.target().retain(id.clone(), snapshot);
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"snapshot_id":id,"connection_epoch":context.connection,"interaction_epoch":document.interaction,"image":{"mime":"image/png","data_b64":image,"width_px":width,"height_px":height},"image_width_px":width,"image_height_px":height,"input_dispatched":false});
    if captured_scale < 1.0 {
        reply["remedy"] = json!(format!("Image scaled to {:.2}% of the initial linear size ({width}×{height} pixels) to fit max_bytes.", captured_scale * 100.0));
    }
    Ok(reply)
}

async fn input(
    context: &Context<'_>,
    tab: &str,
    action: &str,
    args: &Value,
    current: &Document,
) -> Result<Value, Value> {
    let mut text_attempted = false;
    let result = input_inner(context, tab, action, args, current, &mut text_attempted).await;
    result.map_err(|mut reply| {
        if action == "type" && !text_attempted && reply["input_dispatched"] == true {
            // Focus and caret events can affect the page, but they do not send
            // the requested text. Do not discourage a retry as if insertion ran.
            reply["outcome"] = json!("outcome_unknown");
            reply["remedy"] = json!("The requested text was not sent. Focus or caret input may have taken effect. Take a fresh read before deciding whether to retry typing.");
        }
        reply
    })
}

async fn input_inner(
    context: &Context<'_>,
    tab: &str,
    action: &str,
    args: &Value,
    current: &Document,
    text_attempted: &mut bool,
) -> Result<Value, Value> {
    let snapshot = context
        .target()
        .snapshot(context.route, tab, context.connection, args)?;
    if !current.observer_available || snapshot.observer_continuity != current.observer_continuity {
        return Err(observer_unavailable());
    }
    bind_observer_continuity(snapshot.observer_continuity);
    if snapshot.document != current.committed || snapshot.interaction != current.interaction {
        return Err(read_again(false));
    }
    let (mut identity, frame, position) = if action == "click_point" {
        let image = snapshot
            .image
            .as_ref()
            .ok_or_else(|| refusal("snapshot_kind_mismatch"))?;
        let (width, height) = (image.width, image.height);
        if args["image_width_px"] != width || args["image_height_px"] != height {
            return Err(invalid("image_width_px", "dimension_mismatch"));
        }
        let x = args["point"]["x"].as_i64().unwrap();
        let y = args["point"]["y"].as_i64().unwrap();
        if x < 0 || y < 0 || x as u64 >= width || y as u64 >= height {
            return Err(refusal("point_outside_viewport"));
        }
        let metrics = context
            .cdp(
                tab,
                Some(snapshot.interaction),
                vec![command("Page.getLayoutMetrics", json!({}))],
            )
            .await?;
        if metrics.results[0]["cssVisualViewport"] != image.viewport {
            return Err(refusal("viewport_changed"));
        }
        let mapped = crate::coordinate::map_pixel_center(
            viewport_transform(&image.viewport)?,
            width as u32,
            height as u32,
            x,
            y,
        )
        .map_err(|_| refusal("invalid_coordinates"))?;
        let (x, y) = mapped.tuple();
        let hit = context.cdp(tab, Some(snapshot.interaction), vec![command("DOM.getNodeForLocation", json!({"x":x.round() as i64,"y":y.round() as i64,"includeUserAgentShadowDOM":false}))]).await?;
        let frame_id = hit.results[0]["frameId"].as_str().ok_or_else(|| {
            classification_failure(
                "click_point.hit_frame",
                "",
                None,
                "hit_test_frame_id_missing",
            )
        })?;
        let frame = current
            .frames
            .iter()
            .find(|frame| frame.frame_id == frame_id)
            .ok_or_else(|| refusal("frame_not_authorized"))?
            .clone();
        let backend = hit.results[0]["backendNodeId"].as_u64().ok_or_else(|| {
            classification_failure(
                "click_point.hit_node",
                &frame.url,
                Some(false),
                "hit_test_backend_node_id_missing",
            )
        })?;
        let local = &hit.results[0]["frame_point"];
        let position = if local.is_null() {
            (x, y)
        } else {
            (
                local["x"]
                    .as_f64()
                    .ok_or_else(|| protocol_field_error("DOM.getNodeForLocation", "frame_point"))?,
                local["y"]
                    .as_f64()
                    .ok_or_else(|| protocol_field_error("DOM.getNodeForLocation", "frame_point"))?,
            )
        };
        (
            BackendNodeIdentity::new(tab, frame_id, backend).map_err(|_| {
                classification_failure(
                    "click_point.node_identity",
                    &frame.url,
                    Some(true),
                    "invalid_backend_node_identity",
                )
            })?,
            frame,
            Some(position),
        )
    } else {
        let reference = snapshot
            .refs
            .get(args["ref"].as_str().unwrap())
            .ok_or_else(|| refusal("ref_scope_mismatch"))?;
        (reference.identity.clone(), reference.frame.clone(), None)
    };
    if let Some(reason) = current.unreadable_frames.get(&frame.frame_id) {
        return Err(reason.refusal());
    }
    if !current.frames.iter().any(|live| live.same_document(&frame)) {
        return Err(refusal("frame_changed"));
    }
    // An ungranted frame cannot even be classified for input. A top-level
    // screenshot grant does not authorize acting inside a cross-site frame.
    let input_origin = origin(&frame.origin)?;
    let requested = if action == "type" {
        Severity::new(2, false, false)
    } else {
        declared_severity(args)?
    };
    let read_grant = context
        // Classification reads the frame; it does not perform the declared
        // action. Ask for that action only after its hazards are known, so a
        // form submit gets one correctly disclosed higher-risk approval.
        .authorize(
            &input_origin,
            Severity::new(authorization::OBSERVE, false, false),
            BTreeSet::new(),
        )
        .await?;
    let observed = context
        .cdp_frame(
            tab,
            Some(snapshot.interaction),
            &frame,
            flattened_document(),
        )
        .await?;
    let (dom_object, mut classification) = classify_frame_capture(
        observed.results.last(),
        &identity,
        &frame,
        snapshot.interaction,
        "input.classify_flattened_document",
    )?;
    if let Some(expected) = args["ref"]
        .as_str()
        .and_then(|reference| snapshot.refs.get(reference))
        .and_then(|reference| reference.classification.as_ref())
    {
        if *expected != classification {
            return Err(classification_changed(
                expected,
                &classification,
                InputCheck::PreDispatch,
            ));
        }
    }
    if action == "type" {
        if let Some(reply) = type_field_refusal(&classification) {
            return Err(reply);
        }
        let target = crate::browser::navigation::type_target_from_capture(
            dom_object,
            &identity,
            &classification,
        )
        .map_err(|cause| {
            classification_failure(
                "input.type_target_from_capture",
                &frame.url,
                Some(true),
                &cause.to_string(),
            )
        })?;
        if !crate::browser_type::browser_type_dispatch_eligible(&target)
            || target.classification().credential
            || target.classification().financial
        {
            return Err(refusal("target_not_interactive"));
        }
    }
    let authorized_action = if action == "click_point" {
        Action::ClickPoint
    } else {
        Action::Click
    };
    let severity = if action == "type" {
        requested
    } else {
        authorization::effective_severity(authorized_action, requested, Some(&classification))
            .map_err(|_| refusal("severity_below_floor"))?
    };
    let hazards = if action == "type" {
        BTreeSet::new()
    } else {
        authorization::target_hazards(authorized_action, Some(&classification)).map_err(|_| {
            classification_failure(
                "input.target_hazards",
                &frame.url,
                Some(true),
                "hazard_projection_failed",
            )
        })?
    };
    let once = if read_grant.covers(&input_origin, severity, &hazards) {
        read_grant
    } else {
        context
            .authorize(&input_origin, severity, hazards.clone())
            .await?
    };
    let destination_once = match &classification.activation_destination_origin {
        Some(destination) if destination != &frame.origin => Some(
            context
                .authorize(destination, severity, hazards.clone())
                .await?,
        ),
        _ => None,
    };
    // Resolve explicit new-tab links as a background open instead of letting
    // Chrome activate the page's new target, even briefly.
    if action != "type" {
        if let Some(url) =
            crate::browser::navigation::new_tab_link_from_capture(dom_object, &identity, &frame.url)
        {
            let destination = origin(&url)?;
            if !context.granted(&destination, severity, &hazards, destination_once.as_ref())
                && !context.granted(&destination, severity, &hazards, Some(&once))
            {
                return Err(refusal("grant_revoked"));
            }
            verify_input(
                context,
                tab,
                &snapshot,
                &frame,
                &identity,
                &mut classification,
                InputCheck::PreDispatch,
            )
            .await?;
            let raw = invoke(
                context.bridge(),
                context.route,
                &context.cancel,
                "open_tab",
                json!({"url":url,"opener_tab":tab}),
            )
            .await?;
            let opened: Claimed = decode("tab_reply", raw)?;
            if opened.connection_epoch != context.connection {
                return Err(read_again(false));
            }
            context
                .target()
                .state()
                .claims
                .insert(opened.tab.clone(), context.route);
            return Ok(
                json!({"browser":"user","outcome":"ok","tab":opened.tab,"connection_epoch":context.connection,"interaction_epoch":opened.interaction_epoch,"input_dispatched":false}),
            );
        }
    }
    let position = if action == "type" {
        None
    } else if position.is_some() {
        position
    } else {
        input_document(context, tab, &snapshot, false).await?;
        let quad = context
            .cdp_frame(
                tab,
                Some(snapshot.interaction),
                &frame,
                vec![
                    // CDP scrolls the node without page-supplied JavaScript or
                    // activating its tab. Measure in the same attachment after
                    // scrolling, not against the snapshot's old page position.
                    command(
                        "DOM.scrollIntoViewIfNeeded",
                        json!({"backendNodeId":identity.backend_node_id}),
                    ),
                    command("Page.getLayoutMetrics", json!({})),
                    command(
                        "DOM.getContentQuads",
                        json!({"backendNodeId":identity.backend_node_id}),
                    ),
                ],
            )
            .await?;
        Some(quad_center(
            &quad.results[2],
            &quad.results[1]["cssVisualViewport"],
        )?)
    };
    let mut steps = Vec::new();
    if action == "type" {
        steps.push(command(
            "DOM.focus",
            json!({"backendNodeId":identity.backend_node_id}),
        ));
        let declaration = if args["clear_first"] == true {
            functions::SELECT
        } else {
            functions::APPEND_CARET
        };
        steps.push(command(
            "Runtime.callFunctionOn",
            json!({"functionDeclaration":declaration,"returnByValue":true}),
        ));
        steps.push(command("Input.insertText", json!({"text":args["text"]})));
    } else {
        let (x, y) = position.unwrap();
        for event in ["mousePressed", "mouseReleased"] {
            steps.push(command(
                "Input.dispatchMouseEvent",
                json!({"type":event,"x":x,"y":y,"button":"left","clickCount":1}),
            ));
        }
    }
    let mut dispatched = false;
    let mut popup = false;
    let mut after_focus = false;
    let mut steps = steps.into_iter();
    while let Some(step) = steps.next() {
        let just_focused = std::mem::take(&mut after_focus);
        if !context.granted(&input_origin, severity, &hazards, Some(&once))
            || classification
                .activation_destination_origin
                .as_ref()
                .is_some_and(|destination| {
                    !context.granted(destination, severity, &hazards, destination_once.as_ref())
                        && !context.granted(destination, severity, &hazards, Some(&once))
                })
        {
            let mut reply = refusal("grant_revoked");
            reply["input_dispatched"] = json!(dispatched);
            return Err(reply);
        }
        let verification = verify_input(
            context,
            tab,
            &snapshot,
            &frame,
            &identity,
            &mut classification,
            if just_focused {
                InputCheck::PostFocus
            } else if dispatched {
                InputCheck::PreInsertion
            } else {
                InputCheck::PreDispatch
            },
        )
        .await;
        if let Err(reply) = verification {
            if !just_focused {
                return Err(prior_input(reply, dispatched));
            }
            let original = snapshot.refs.get(args["ref"].as_str().unwrap()).unwrap();
            let Some(replacement) = typing::after_focus(context, tab, &snapshot, original)
                .await
                .map_err(|reply| prior_input(reply, dispatched))?
            else {
                return Err(prior_input(reply, dispatched));
            };
            identity = replacement.identity;
            classification = replacement.classification.expect("classified replacement");
            verify_input(
                context,
                tab,
                &snapshot,
                &frame,
                &identity,
                &mut classification,
                InputCheck::PostFocus,
            )
            .await
            .map_err(|reply| prior_input(reply, dispatched))?;
        }
        if let Some((x, y)) = position {
            verify_click_position(
                context,
                tab,
                &snapshot,
                &frame,
                &classification,
                (x, y),
                dispatched,
            )
            .await
            .map_err(|reply| prior_input(reply, dispatched))?;
        }
        let commands = if action == "type" && step["method"] == "Runtime.callFunctionOn" {
            if args["clear_first"] != true
                && matches!(
                    classification.effective_input_type.as_deref(),
                    Some("number" | "email")
                )
            {
                // Choose the caret operation after any handoff: number and
                // email inputs reject setSelectionRange, unlike text inputs.
                vec![
                    command(
                        "Emulation.setFocusEmulationEnabled",
                        json!({"enabled":true}),
                    ),
                    command(
                        "Input.dispatchKeyEvent",
                        json!({"type":"keyDown","key":"End","code":"End","windowsVirtualKeyCode":35}),
                    ),
                    command(
                        "Input.dispatchKeyEvent",
                        json!({"type":"keyUp","key":"End","code":"End","windowsVirtualKeyCode":35}),
                    ),
                ]
            } else {
                runtime_plan(
                    &identity,
                    step["params"]["functionDeclaration"]
                        .as_str()
                        .expect("pinned declaration"),
                )
            }
        } else {
            if action == "type" && step["method"] == "Input.insertText" {
                let focused = context
                    .cdp_frame(
                        tab,
                        Some(snapshot.interaction),
                        &frame,
                        runtime_plan(&identity, functions::HAS_FOCUS),
                    )
                    .await
                    .map_err(|reply| prior_input(reply, dispatched))?;
                if focused
                    .results
                    .last()
                    .and_then(|result| result.pointer("/result/value"))
                    != Some(&json!(true))
                {
                    return Err(prior_input(refusal("type_focus_not_ready"), dispatched));
                }
                verify_input(
                    context,
                    tab,
                    &snapshot,
                    &frame,
                    &identity,
                    &mut classification,
                    InputCheck::PreInsertion,
                )
                .await
                .map_err(|reply| prior_input(reply, dispatched))?;
            }
            // Background pages can acknowledge mouse input without delivering
            // it. Emulate page focus without activating the person's tab or
            // window. Keep the mouse pair in one attachment so the extension
            // can release our press even if its between-event guard refuses.
            let mut commands = vec![command(
                "Emulation.setFocusEmulationEnabled",
                json!({"enabled":true}),
            )];
            commands.push(step);
            if action != "type" {
                commands.extend(steps.by_ref());
            }
            commands
        };
        let is_focus = action == "type"
            && commands
                .iter()
                .any(|command| command["method"] == "DOM.focus");
        *text_attempted |= commands
            .iter()
            .any(|command| command["method"] == "Input.insertText");
        let outcome = context
            .cdp_frame(tab, Some(snapshot.interaction), &frame, commands)
            .await;
        match outcome {
            Ok(result) => {
                if result
                    .results
                    .iter()
                    .any(|result| result.get("exceptionDetails").is_some())
                {
                    return Err(prior_input(refusal("runtime_exception"), true));
                }
                dispatched = true;
                after_focus = is_focus;
                popup |= result.popup;
            }
            Err(mut reply) => {
                if dispatched {
                    reply["input_dispatched"] = json!(true);
                }
                return Err(reply);
            }
        }
    }
    let landed = context.document(tab).await.map_err(|mut reply| {
        if dispatched {
            reply["input_dispatched"] = json!(true);
        }
        reply
    })?;
    if !landed.observer_available {
        return Err(prior_input(observer_unavailable(), dispatched));
    }
    let landing_origin = landed
        .frames
        .iter()
        .find(|live| live.frame_id == frame.frame_id)
        .map(|live| live.origin.clone())
        .unwrap_or_else(|| "null".into());
    let landing_allowed = |origin: &str| {
        context.granted(
            origin,
            Severity::new(1, false, false),
            &BTreeSet::new(),
            Some(&once),
        ) || context.granted(
            origin,
            Severity::new(1, false, false),
            &BTreeSet::new(),
            destination_once.as_ref(),
        )
    };
    // Acting inside a child does not revisit the unchanged top page. A real
    // top-page navigation, or a child redirect, still needs its landing grant.
    if !landing_allowed(&landing_origin)
        || (landed.committed != current.committed
            && !landing_allowed(&origin(&landed.committed.url)?))
    {
        let mut reply = refusal("landing_site_not_authorized");
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"input_dispatched":dispatched,"connection_epoch":context.connection,"interaction_epoch":landed.interaction});
    if popup {
        reply["popup_activated_briefly"] = json!(true);
    }
    Ok(reply)
}

/// Where the top document is scrolled, from a `Page.getLayoutMetrics`
/// result, in CSS pixels.
struct PagePosition {
    x: f64,
    y: f64,
    width: f64,
    height: f64,
    content_height: f64,
}

/// Device pixels per CSS pixel, from one `Page.getLayoutMetrics` result: the
/// layout viewport's width in device pixels over its width in CSS pixels.
/// This covers both the display's scale and the tab's zoom.
fn device_pixels_per_css_pixel(metrics: &Value) -> Result<f64, Value> {
    let device = metrics["layoutViewport"]["clientWidth"].as_f64();
    let css = metrics["cssLayoutViewport"]["clientWidth"].as_f64();
    match (device, css) {
        (Some(device), Some(css))
            if device.is_finite() && css.is_finite() && css > 0.0 && device > 0.0 =>
        {
            Ok(device / css)
        }
        _ => Err(refusal("viewport_not_ready")),
    }
}

fn page_position(metrics: &Value) -> Result<PagePosition, Value> {
    let number = |value: &Value| {
        value
            .as_f64()
            .filter(|number| number.is_finite())
            .ok_or_else(|| refusal("viewport_not_ready"))
    };
    let viewport = &metrics["cssLayoutViewport"];
    Ok(PagePosition {
        x: number(&viewport["pageX"])?,
        y: number(&viewport["pageY"])?,
        width: number(&viewport["clientWidth"])?,
        height: number(&viewport["clientHeight"])?,
        content_height: number(&metrics["cssContentSize"]["height"])?,
    })
}

/// The backend node id of the document's root element (`<html>`), from a
/// depth-1 `DOM.getFlattenedDocument` result.
fn document_element(flattened: &Value) -> Result<u64, Value> {
    let nodes = flattened["nodes"]
        .as_array()
        .ok_or_else(|| refusal("no_geometry"))?;
    let document = nodes
        .iter()
        .find(|node| node["nodeType"] == 9 && node.get("parentId").is_none())
        .and_then(|node| node["nodeId"].as_u64())
        .ok_or_else(|| refusal("no_geometry"))?;
    nodes
        .iter()
        .find(|node| node["nodeType"] == 1 && node["parentId"] == document)
        .and_then(|node| node["backendNodeId"].as_u64())
        .ok_or_else(|| refusal("no_geometry"))
}

/// The plain-text report of a scroll: what was asked, where the page moved,
/// and whether the page grew taller, as an infinite feed does when it loads
/// more posts.
fn scroll_report(
    asked: &str,
    page_scroll: bool,
    before: &PagePosition,
    after: &PagePosition,
) -> String {
    let mut lines = vec![asked.to_owned()];
    if (after.x, after.y) == (before.x, before.y) {
        lines.push(format!(
            "The page did not move from x {:.0}, y {:.0}.",
            before.x, before.y
        ));
        lines.push(if page_scroll {
            "It may already be at its end in that direction, or its content scrolls inside an element; scroll a ref in that element into view instead.".into()
        } else {
            "The element was already in view, or it scrolls inside an embedded frame or element.".to_owned()
        });
    } else {
        lines.push(format!(
            "The page moved from x {:.0}, y {:.0} to x {:.0}, y {:.0}; the viewport is {:.0} x {:.0} px.",
            before.x, before.y, after.x, after.y, after.width, after.height
        ));
    }
    if after.content_height > before.content_height {
        lines.push(format!(
            "The page grew from {:.0} to {:.0} px tall during the scroll: more content loaded.",
            before.content_height, after.content_height
        ));
    } else if after.content_height < before.content_height {
        lines.push(format!(
            "The page shrank from {:.0} to {:.0} px tall during the scroll.",
            before.content_height, after.content_height
        ));
    } else {
        lines.push(format!(
            "The page is {:.0} px tall, unchanged so far; content it loads after the scroll shows on the next read.",
            after.content_height
        ));
    }
    lines.join("\n")
}

/// Scroll a claimed tab: bring a printed ref into view, or move the page by
/// `direction` and `amount` CSS pixels (600 when omitted), as browser:own
/// does.
///
/// Chrome acknowledges synthetic wheel and gesture input to a background
/// page without moving it (the own browser found this, and scrolls with a
/// native call instead), and the person's Agent-group tabs are usually in
/// the background. Both forms therefore use `DOM.scrollIntoViewIfNeeded`,
/// which Chrome performs in the page itself, with no page-supplied
/// JavaScript and no trusted input events for the interaction observer to
/// count as the person's. A page scroll asks the document's root element to
/// show a viewport-sized rectangle offset by the amount from what is shown
/// now. Chrome aligns that rectangle with the viewport, which moves the page
/// by the amount, stopping at its ends. The rectangle is placed relative to
/// the root element's box, which starts at the document's origin unless the
/// page gives `<html>` a margin; the reply reports where the page actually
/// ended up.
/// Focus emulation lets a background tab draw without activating it. Keep the
/// debugger attached for two seconds after scrolling so feeds can load, then
/// read the resulting height before detach restores normal visibility.
///
/// A scroll only changes what is shown, so like browser:own it needs the
/// page's tier-1 site grant, the one a snapshot uses. Like other input it
/// acts only under the agent's last read of the tab, so a page the person
/// has used since refuses.
async fn scroll(
    context: &Context<'_>,
    tab: &str,
    args: &Value,
    current: &Document,
) -> Result<Value, Value> {
    let reference = args["ref"].as_str();
    let snapshot = match reference {
        Some(_) => context
            .target()
            .snapshot(context.route, tab, context.connection, args)?,
        None => context
            .target()
            .latest_read(context.route, tab, context.connection)?,
    };
    if !current.observer_available || snapshot.observer_continuity != current.observer_continuity {
        return Err(observer_unavailable());
    }
    bind_observer_continuity(snapshot.observer_continuity);
    if snapshot.document != current.committed {
        return Err(document_moved(
            false,
            &snapshot.document,
            &current.committed,
        ));
    }
    if snapshot.interaction != current.interaction {
        return Err(epoch_moved(false, current.interaction_cause.as_deref()));
    }
    let site = origin(&current.committed.url)?;
    context
        .authorize(
            &site,
            Severity::new(authorization::OBSERVE, false, false),
            BTreeSet::new(),
        )
        .await?;
    let interaction = Some(snapshot.interaction);
    let metrics = || command("Page.getLayoutMetrics", json!({}));
    let focus = || {
        command(
            "Emulation.setFocusEmulationEnabled",
            json!({"enabled":true}),
        )
    };
    let draw = || command("Extension.wait", json!({"ms":2000}));
    // Once the scroll step has run, any later failure still reports that
    // the page may have moved.
    let scrolled = |reply: Value| prior_input(reply, true);
    let (asked, before, after, plan) = if let Some(reference) = reference {
        let shown = snapshot
            .refs
            .get(reference)
            .ok_or_else(|| refusal("ref_scope_mismatch"))?;
        let frame = &shown.frame;
        if let Some(reason) = current.unreadable_frames.get(&frame.frame_id) {
            return Err(reason.refusal());
        }
        if !current.frames.iter().any(|live| live.same_document(frame)) {
            return Err(refusal("frame_changed"));
        }
        // The ref can be in an embedded frame, so only the scroll step is
        // sent to the ref's frame; the page position either side of it is
        // the top document's.
        let mut step = command(
            "DOM.scrollIntoViewIfNeeded",
            json!({"backendNodeId":shown.identity.backend_node_id}),
        );
        step["frame_id"] = json!(frame.frame_id);
        step["loader_id"] = json!(frame.loader_id);
        step["session_id"] = json!(frame.session_id);
        let plan = context
            .cdp(
                tab,
                interaction,
                vec![metrics(), focus(), step, draw(), metrics()],
            )
            .await?;
        let before = page_position(&plan.results[0]).map_err(scrolled)?;
        let after = page_position(&plan.results[4]).map_err(scrolled)?;
        (
            format!("Scrolled {reference} into view."),
            before,
            after,
            plan,
        )
    } else {
        let read = context
            .cdp(
                tab,
                interaction,
                vec![
                    command("DOM.enable", json!({})),
                    command(
                        "DOM.getFlattenedDocument",
                        json!({"depth":1,"pierce":false}),
                    ),
                    metrics(),
                ],
            )
            .await?;
        let root = document_element(&read.results[1])?;
        let before = page_position(&read.results[2])?;
        let scale = device_pixels_per_css_pixel(&read.results[2])?;
        let direction = args["direction"].as_str().unwrap_or_default();
        let amount = args["amount"].as_u64().unwrap_or(600);
        let distance = amount as f64;
        let (dx, dy) = match direction {
            "up" => (0.0, -distance),
            "down" => (0.0, distance),
            "left" => (-distance, 0.0),
            "right" => (distance, 0.0),
            _ => return Err(invalid("direction", "unsupported_value")),
        };
        // Chrome reads this rectangle in device pixels, not CSS pixels: on a
        // 2x display a CSS-pixel rectangle moved the page about half the
        // amount, and less on long pages. The scale comes from the same
        // layout read as the position.
        let rect = json!({
            "x": (before.x + dx) * scale,
            "y": (before.y + dy) * scale,
            "width": before.width * scale,
            "height": before.height * scale,
        });
        let plan = context
            .cdp(
                tab,
                interaction,
                vec![
                    focus(),
                    command(
                        "DOM.scrollIntoViewIfNeeded",
                        json!({"backendNodeId":root,"rect":rect}),
                    ),
                    draw(),
                    metrics(),
                ],
            )
            .await?;
        let after = page_position(&plan.results[3]).map_err(scrolled)?;
        (
            format!("Scrolled {direction} {amount} px."),
            before,
            after,
            plan,
        )
    };
    let mut reply = json!({
        "browser":"user","outcome":"ok","tab":tab,"input_dispatched":true,
        "connection_epoch":context.connection,"interaction_epoch":plan.interaction,
        "state_text":scroll_report(&asked, reference.is_none(), &before, &after),
    });
    if plan.popup {
        reply["popup_activated_briefly"] = json!(true);
    }
    Ok(reply)
}

async fn input_document(
    context: &Context<'_>,
    tab: &str,
    snapshot: &Snapshot,
    dispatched: bool,
) -> Result<Document, Value> {
    let observed = context
        .document(tab)
        .await
        .map_err(|reply| prior_input(reply, dispatched))?;
    if !observed.observer_available || observed.observer_continuity != snapshot.observer_continuity
    {
        return Err(prior_input(observer_unavailable(), dispatched));
    }
    if observed.interaction != snapshot.interaction {
        return Err(epoch_moved(
            dispatched,
            observed.interaction_cause.as_deref(),
        ));
    }
    // A page may push or replace history in response to our focus/input. After
    // this call dispatches input, history alone cannot prove a person intervened.
    // Keep every other document fact and the interaction epoch strict; before
    // the first dispatch, history must still match the read.
    let mut expected = snapshot.document.clone();
    if dispatched {
        expected.entry_id = observed.committed.entry_id;
        expected.current_index = observed.committed.current_index;
        expected.history.clone_from(&observed.committed.history);
    }
    if observed.committed != expected {
        return Err(document_moved(
            dispatched,
            &snapshot.document,
            &observed.committed,
        ));
    }
    Ok(observed)
}

async fn verify_input(
    context: &Context<'_>,
    tab: &str,
    snapshot: &Snapshot,
    frame: &FrameDocument,
    identity: &BackendNodeIdentity,
    expected: &mut NonTypeClassificationRecord,
    check: InputCheck,
) -> Result<(), Value> {
    let dispatched = !matches!(check, InputCheck::PreDispatch);
    let observed = input_document(context, tab, snapshot, dispatched).await?;
    if let Some(reason) = observed.unreadable_frames.get(&frame.frame_id) {
        return Err(prior_input(reason.refusal(), dispatched));
    }
    if !observed
        .frames
        .iter()
        .any(|current| current.same_document(frame))
    {
        let mut reply = refusal("frame_changed");
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    let plan = context
        .cdp_frame(tab, Some(snapshot.interaction), frame, flattened_document())
        .await
        .map_err(|mut reply| {
            if dispatched {
                reply["input_dispatched"] = json!(true);
            }
            reply
        })?;
    let (dom, record) = classify_frame_capture(
        plan.results.last(),
        identity,
        frame,
        snapshot.interaction,
        "verify_input.classify_flattened_document",
    )?;
    if record != *expected
        && !(context.action == "type"
            && matches!(check, InputCheck::PostFocus)
            && typing::allows_focus_form_controls(dom, identity, expected, &record))
    {
        let mut reply = classification_changed(expected, &record, check);
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    if context.action == "type" {
        if let Some(reply) = type_field_refusal(&record) {
            return Err(prior_input(reply, dispatched));
        }
        let target = crate::browser::navigation::type_target_from_capture(dom, identity, &record)
            .map_err(|cause| {
            classification_failure(
                "verify_input.type_target_from_capture",
                &frame.url,
                Some(true),
                &cause.to_string(),
            )
        })?;
        if !crate::browser_type::browser_type_dispatch_eligible(&target)
            || target.classification().credential
            || target.classification().financial
        {
            return Err(refusal("target_not_interactive"));
        }
    }
    input_document(context, tab, snapshot, dispatched).await?;
    // Only a successful check may advance the baseline. Later pre-insertion
    // checks still require exact equality with this post-focus record.
    if record != *expected {
        *expected = record;
    }
    Ok(())
}

fn quad_center(result: &Value, viewport: &Value) -> Result<(f64, f64), Value> {
    let rect = viewport_transform(viewport)?.input_rect();
    for quad in result["quads"]
        .as_array()
        .ok_or_else(|| refusal("no_geometry"))?
    {
        let Some(values) = quad.as_array().filter(|values| values.len() == 8) else {
            continue;
        };
        let numbers = values
            .iter()
            .map(Value::as_f64)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| refusal("no_geometry"))?;
        let quad = crate::browser::geometry::Quad::new([
            (numbers[0], numbers[1]),
            (numbers[2], numbers[3]),
            (numbers[4], numbers[5]),
            (numbers[6], numbers[7]),
        ]);
        if quad.midpoint().is_err() {
            continue;
        }
        // Content quads and mouse input are viewport CSS pixels. A long link
        // can intersect the viewport while its full quad's center is offscreen.
        // Clip the polygon before selecting a point; never use deprecated
        // device-pixel layout metrics or add the document's scroll offset here.
        let mut polygon = vec![
            (numbers[0], numbers[1]),
            (numbers[2], numbers[3]),
            (numbers[4], numbers[5]),
            (numbers[6], numbers[7]),
        ];
        for (axis, edge, minimum) in [
            (0, rect.x_input_css, true),
            (0, rect.x_input_css + rect.width_input_css, false),
            (1, rect.y_input_css, true),
            (1, rect.y_input_css + rect.height_input_css, false),
        ] {
            let coordinate = |point: (f64, f64)| if axis == 0 { point.0 } else { point.1 };
            let inside = |point| {
                if minimum {
                    coordinate(point) >= edge
                } else {
                    coordinate(point) <= edge
                }
            };
            let mut clipped = Vec::new();
            if let Some(mut previous) = polygon.last().copied() {
                for point in polygon {
                    if inside(previous) != inside(point) {
                        let fraction = (edge - coordinate(previous))
                            / (coordinate(point) - coordinate(previous));
                        clipped.push((
                            previous.0 + fraction * (point.0 - previous.0),
                            previous.1 + fraction * (point.1 - previous.1),
                        ));
                    }
                    if inside(point) {
                        clipped.push(point);
                    }
                    previous = point;
                }
            }
            polygon = clipped;
        }
        if polygon.len() >= 3 {
            let count = polygon.len() as f64;
            let center = polygon.iter().fold((0.0, 0.0), |sum, point| {
                (sum.0 + point.0 / count, sum.1 + point.1 / count)
            });
            if crate::browser::geometry::require_point_in_viewport(center.0, center.1, rect).is_ok()
            {
                return Ok(center);
            }
        }
    }
    Err(refusal("no_geometry"))
}

fn declared_severity(args: &Value) -> Result<Severity, Value> {
    let value = &args["severity"];
    let severity = Severity::new(
        value["tier"]
            .as_u64()
            .ok_or_else(|| invalid("severity", "wrong_type"))? as u8,
        value["credential"]
            .as_bool()
            .ok_or_else(|| invalid("severity", "wrong_type"))?,
        value["financial"]
            .as_bool()
            .ok_or_else(|| invalid("severity", "wrong_type"))?,
    );
    severity
        .validate()
        .map_err(|_| invalid("severity", "out_of_range"))?;
    Ok(severity)
}

mod agent_enforcement;
mod functions;
mod typing;

#[cfg(test)]
mod tests;

fn viewport_transform(viewport: &Value) -> Result<crate::coordinate::TransformInputs, Value> {
    let number = |field: &str| {
        viewport[field]
            .as_f64()
            .ok_or_else(|| refusal("viewport_not_ready"))
    };
    let transform = crate::coordinate::TransformInputs::from_values(
        number("offsetX")?,
        number("offsetY")?,
        number("clientWidth")?,
        number("clientHeight")?,
        1.0,
        number("scale")?,
    );
    transform
        .validate()
        .map_err(|_| refusal("viewport_not_ready"))?;
    Ok(transform)
}

async fn verify_click_position(
    context: &Context<'_>,
    tab: &str,
    snapshot: &Snapshot,
    frame: &FrameDocument,
    expected: &NonTypeClassificationRecord,
    position: (f64, f64),
    dispatched: bool,
) -> Result<(), Value> {
    let (x, y) = position;
    // User-agent shadow roots are excluded for the reason given at the own
    // browser's `document_hit_params`: an input button's centre would resolve
    // to its internal shadow root, which the flattened document never lists.
    let result = context.cdp_frame(tab, Some(snapshot.interaction), frame, vec![command("Page.getLayoutMetrics", json!({})), command("DOM.getNodeForLocation", json!({"x":x.round() as i64,"y":y.round() as i64,"includeUserAgentShadowDOM":false}))]).await.map_err(|mut reply| { if dispatched { reply["input_dispatched"] = json!(true); } reply })?;
    let viewport = &result.results[0]["cssVisualViewport"];
    if snapshot
        .image
        .as_ref()
        .is_some_and(|image| &image.viewport != viewport)
    {
        let mut reply = refusal("viewport_changed");
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    let transform = viewport_transform(viewport)?;
    let rect = transform.input_rect();
    if x < rect.x_input_css
        || y < rect.y_input_css
        || x >= rect.x_input_css + rect.width_input_css
        || y >= rect.y_input_css + rect.height_input_css
    {
        return Err(refusal("point_outside_viewport"));
    }
    let hit = &result.results[1];
    if hit["frameId"] != frame.frame_id {
        return Err(refusal("element_intercepted"));
    }
    let backend = hit["backendNodeId"]
        .as_u64()
        .ok_or_else(|| refusal("element_intercepted"))?;
    let identity = BackendNodeIdentity::new(tab, &frame.frame_id, backend)
        .map_err(|_| refusal("element_intercepted"))?;
    let dom = context
        .cdp_frame(tab, Some(snapshot.interaction), frame, flattened_document())
        .await?;
    let (_, record) = classify_frame_capture(
        dom.results.last(),
        &identity,
        frame,
        snapshot.interaction,
        "verify_click_position.classify_flattened_document",
    )?;
    if record.activation_target_identity != expected.activation_target_identity {
        let mut reply = refusal("element_intercepted");
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    Ok(())
}

fn prior_input(mut reply: Value, dispatched: bool) -> Value {
    if dispatched {
        reply["input_dispatched"] = json!(true);
    }
    reply
}

fn dispatched_outcome(mut reply: Value) -> Value {
    if reply["outcome"] == "refused" && reply["input_dispatched"] == true {
        // A refusal promises that nothing ran. Once input was sent, failed
        // observation cannot make that promise or safely invite a retry.
        reply["outcome"] = json!("outcome_unknown");
        reply["remedy"] = json!("Input was dispatched and may have taken effect. Do not repeat this action; take a fresh read before deciding what to do next.");
    }
    reply
}

fn runtime_plan(identity: &BackendNodeIdentity, declaration: &str) -> Vec<Value> {
    // A remote object is valid only while this debugger attachment lives.
    // Resolve and consume it in one plan instead of carrying its id past detach.
    vec![
        command(
            "Emulation.setFocusEmulationEnabled",
            json!({"enabled":true}),
        ),
        command("Runtime.enable", json!({})),
        command(
            "DOM.resolveNode",
            json!({"backendNodeId":identity.backend_node_id}),
        ),
        command(
            "Runtime.callFunctionOn",
            json!({"objectId":{"$result":2,"path":["object","objectId"]},"functionDeclaration":declaration,"returnByValue":true}),
        ),
    ]
}
