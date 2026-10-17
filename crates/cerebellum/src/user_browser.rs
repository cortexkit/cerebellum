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

/// How long a user-browser site card waits for the person. The card expires
/// at the same moment, so it is never left open after the call stops waiting.
pub(crate) const CONSENT_DEADLINE: Duration = Duration::from_secs(120);
const MAX_SNAPSHOTS: usize = 64;
pub(crate) const NAVIGATION_READ_DEADLINE: Duration = Duration::from_secs(30);

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

#[derive(Default)]
struct ExecutionState {
    stopped: bool,
    in_flight: bool,
    quarantined: bool,
    held: bool,
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
    connection_epoch: u64,
    #[serde(default)]
    popup_activated_briefly: bool,
    #[serde(default)]
    frame_mappings: Vec<FrameMapping>,
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
    document: CommittedDocument,
    refs: BTreeMap<String, ShownRef>,
    image: Option<Image>,
}

#[derive(Default)]
struct State {
    connection: Option<u64>,
    ended_routes: BTreeSet<Route>,
    claims: BTreeMap<String, Route>,
    snapshots: BTreeMap<String, Snapshot>,
    snapshot_order: Vec<String>,
    executions: BTreeMap<String, Arc<UserExecution>>,
}

pub(crate) struct UserBrowser {
    state: Mutex<State>,
    grants: Arc<StandingBrowserGrants>,
    workers: crate::blocking_permits::PermitPool,
}

impl UserBrowser {
    pub(crate) fn new(grants: Arc<StandingBrowserGrants>) -> Self {
        Self {
            state: Mutex::new(State::default()),
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
        work_ms: u64,
    ) -> Arc<UserExecution> {
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
                                work_ms
                                    + crate::budgets::user_consent_count(action)
                                        * crate::budgets::USER_CONSENT_MS,
                            )
                    }),
                parked: Duration::ZERO,
                park_left: Duration::from_millis(
                    crate::budgets::user_consent_count(action) * crate::budgets::USER_CONSENT_MS,
                ),
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

fn read_again(input_dispatched: bool) -> Value {
    json!({"browser":"user", "outcome":"refused", "reason":"state_changed_by_person", "remedy":"read again", "input_dispatched":input_dispatched})
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
            crate::management::browser_grant_option(
                *choice,
                &[
                    if *choice == crate::management::BrowserGrantChoice::SiteThirtyMinutes {
                        host.clone()
                    } else {
                        scope.clone()
                    },
                ],
                Severity::new(tier, false, false),
            )
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
        urgency: Urgency::High,
        scope: Scope::new()
            .with("browser", "user")
            .with("origins", json!([origin]))
            .with("severity_tier", tier)
            .with("hazards", json!(hazard_names)),
        duration: None,
    }
    .render()
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
/// A holder applies its own answer. After detachment, the registry preserves
/// the approval for a retry with the same origin, severity and hazards.
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

/// Held calls apply their own answers. Detached approvals are saved by the
/// desk for a matching retry; the drain must not steal a holder's settlement.
struct SiteCardEffects(Arc<SiteCardHolders>);

impl ConsentEffects for SiteCardEffects {
    fn has_pending(&self, card: &RaisedCard) -> bool {
        card.lifecycle.deferred_use || self.0.holds(&card.subject)
    }

    fn apply(
        &self,
        card: &RaisedCard,
        _record: &Record,
        _ending: &Ending,
    ) -> Result<AppliedSettlement, ApplyFailed> {
        if self.0.holds(&card.subject) {
            return Err(ApplyFailed(
                "the held site call has not stored its answer yet".into(),
            ));
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
        Arc::new(SiteCardEffects(Arc::clone(&planes.user_browser_cards))),
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
        return outcome.result.ok_or_else(|| refusal("protocol_error"));
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
    popup: bool,
    frame_mappings: Vec<FrameMapping>,
}

async fn plan(
    bridge: &UserBrowserBridge,
    route: Route,
    tab: &str,
    connection: u64,
    interaction: Option<u64>,
    cancel: &CancelHandle,
    commands: Vec<Value>,
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
            })
        })
        .collect();
    let mut command = json!({"tab":tab,"commands":commands});
    if let Some(epoch) = interaction {
        command["interaction_epoch"] = json!(epoch);
    }
    let raw = invoke(bridge, route, cancel, "cdp", command).await?;
    let reply: PlanReply = serde_json::from_value(raw).map_err(|_| refusal("protocol_error"))?;
    if reply.popup_activated_briefly {
        let _ = POPUP_SEEN.try_with(|seen| seen.set(true));
    }
    let mut results = Vec::new();
    let mut dispatched = false;
    if reply.results.len() > count {
        return Err(refusal("protocol_error"));
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
    if interaction.is_some_and(|expected| expected != reply.interaction_epoch) {
        return Err(read_again(dispatched));
    }
    if results.len() != count {
        return Err(refusal("protocol_error"));
    }
    Ok(Plan {
        results,
        interaction: reply.interaction_epoch,
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
    )
    .await?;
    let history = plan.results[0]
        .as_object()
        .ok_or_else(|| refusal("protocol_error"))?;
    let tree = plan.results[1]
        .as_object()
        .ok_or_else(|| refusal("protocol_error"))?;
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
            .ok_or_else(|| refusal("protocol_error"))
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

pub(crate) async fn serve(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    action: &str,
    args: &Value,
) -> Value {
    let Some(budget) = crate::budgets::user_browser(action) else {
        return invalid("action", "unsupported_value");
    };
    let Some(permits) = planes.user_browser.target().workers.try_call() else {
        return json!({"browser":"user","outcome":"blocking_capacity_exhausted",
            "detail":{"dispatched":false,"step":"queue"}});
    };
    if let Some(connection) = planes.user_browser.connected_epoch() {
        planes.user_browser.target().synchronize(connection);
    }
    let execution = planes.user_browser.target().execution(
        Route {
            channel: request.0,
            epoch: request.1,
        },
        action,
        args,
        budget.work_ms,
    );
    let result = EXECUTION_PERMITS.scope(Arc::new(permits),
        EXECUTION.scope(Arc::clone(&execution), POPUP_SEEN.scope(Cell::new(false), async {
            tokio::select! {
                biased;
                _ = execution.expired() => None,
                reply = serve_scoped(planes, facts, writer, request, action, args) => Some(reply),
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
    action: &str,
    args: &Value,
) -> Value {
    let mut reply = match validate(action, args) {
        Err(reply) => reply,
        Ok(()) => serve_inner(planes, facts, writer, request, action, args)
            .await
            .unwrap_or_else(|reply| reply),
    };
    // One browser_use call can contain several detached plans. Preserve popup
    // reports from metadata and refused plans, not only from the last input.
    if POPUP_SEEN.with(Cell::get) {
        reply["popup_activated_briefly"] = json!(true);
    }
    if crate::browser::validate_user_browser_result(action, &reply).is_err() {
        let input = reply
            .get("input_dispatched")
            .cloned()
            .unwrap_or(Value::Null);
        reply = refusal("result_schema_violation");
        reply["input_dispatched"] = input;
    }
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
        return failure;
    }
    reply
}

fn validate(action: &str, args: &Value) -> Result<(), Value> {
    if action == "scroll" {
        return Err(refusal("unsupported_on_user_browser"));
    }
    let object = args
        .as_object()
        .ok_or_else(|| invalid("arguments", "wrong_type"))?;
    let mut fields = crate::flat_tools::browser_action_schema(action).unwrap_or_default();
    if action == "close" {
        fields.clear();
    }
    if matches!(
        action,
        "navigate" | "snapshot" | "screenshot" | "click" | "type" | "click_point" | "claim_tab"
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
        "navigate" | "snapshot" | "screenshot" | "click" | "type" | "click_point"
    ) {
        required.push("tab");
    }
    for field in required {
        if !object.contains_key(field) {
            return Err(invalid(field, "missing_field"));
        }
    }
    if action == "snapshot" && object.get("mode").is_some_and(|mode| mode != "actionable") {
        for field in ["zoom", "text_filter", "role_filter"] {
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
    route: Route,
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
            self.route.channel,
            self.route.epoch,
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
        let ask_id = match self.planes.consent.open_card_for(live.session(), &subject) {
            Some(card) => card.elicitation_id,
            None => session
                .raise(card, &subject)
                .await
                .map_err(|ending| consent_unavailable(&ending))?,
        };
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
        self.target().owned(self.route, tab, self.connection)?;
        document(
            self.bridge(),
            self.route,
            tab,
            self.connection,
            &self.cancel,
        )
        .await
    }
}

async fn serve_inner(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    _writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    action: &str,
    args: &Value,
) -> Result<Value, Value> {
    let route = Route {
        channel: request.0,
        epoch: request.1,
    };
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
        cancel,
        connection,
        action,
    };
    if action == "status" {
        let raw = invoke(bridge, route, &context.cancel, "status", json!({})).await?;
        let inventory: Inventory =
            serde_json::from_value(raw).map_err(|_| refusal("protocol_error"))?;
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
                return Err(refusal("protocol_error"));
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
        planes
            .browser
            .journal_user_browser(&facts.identity, action, None, "dispatch_committed", None)
            .await
            .map_err(|_| refusal("journal_unavailable"))?;
        let raw = invoke(bridge, route, &context.cancel, action, args.clone()).await?;
        let claimed: Claimed =
            serde_json::from_value(raw).map_err(|_| refusal("protocol_error"))?;
        if claimed.connection_epoch != connection || bridge.connected_epoch() != Some(connection) {
            return Err(read_again(false));
        }
        if action == "claim_tab" && args["tab"] != claimed.tab {
            return Err(refusal("protocol_error"));
        }
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
        return Ok(
            json!({"browser":"user","outcome":"ok","tab":claimed.tab,"interaction_epoch":claimed.interaction_epoch,"connection_epoch":connection,"input_dispatched":false}),
        );
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
        return Ok(json!({"browser":"user","outcome":"ok","input_dispatched":false}));
    }
    let tab = args["tab"].as_str().expect("validated tab");
    let current = context.document(tab).await?;
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
            // The grant is checked again before dispatch; answering a card must
            // not select a newer page or a different tab implicitly.
            context.document(tab).await?;
            let navigation = context
                .cdp(
                    tab,
                    Some(current.interaction),
                    vec![command("Page.navigate", json!({"url":args["url"]}))],
                )
                .await?;
            if navigation.results[0].get("errorText").is_some() {
                return Err(refusal("navigation_failed"));
            }
            let loader = navigation.results[0]["loaderId"].as_str();
            let deadline = tokio::time::Instant::now() + NAVIGATION_READ_DEADLINE;
            let mut ticks = tokio::time::interval(Duration::from_millis(25));
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
                    break landed;
                }
            };
            let landing = origin(&landed.committed.url)?;
            if !context.granted(
                &landing,
                Severity::new(1, false, false),
                &BTreeSet::new(),
                Some(&once),
            ) {
                return Err(refusal("landing_site_not_authorized"));
            }
            let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"connection_epoch":connection,"interaction_epoch":landed.interaction,"input_dispatched":false});
            // Plans carry command results, not the Page/Network event stream
            // the own-browser Tracker uses to establish network quiet.
            reply["settled"] = json!(false);
            reply["settlement_reason"] = json!("settlement isn't observed on the person's browser");
            reply["remedy"] =
                json!("Read the page before acting; only its committed document was confirmed.");
            if navigation.popup {
                reply["popup_activated_briefly"] = json!(true);
            }
            if args["read_page"] == true {
                let read = capture(&context, tab, args, &landed, &once, None).await?;
                reply["read_page"] = read;
            }
            return Ok(reply);
        }
        let observed = context.document(tab).await?;
        if observed.committed != current.committed || observed.interaction != current.interaction {
            return Err(read_again(false));
        }
        if action == "screenshot" {
            return screenshot(&context, tab, args, &observed, &once).await;
        }
        let zoom = if args.get("zoom").is_some() {
            Some(target.snapshot(route, tab, connection, &json!({"ref":args["zoom"]}))?)
        } else {
            None
        };
        return capture(&context, tab, args, &observed, &once, zoom.as_ref()).await;
    }
    input(&context, tab, action, args, &current).await
}

fn baseline(context: &Context<'_>, tab: &str, document: &Document) -> Snapshot {
    Snapshot {
        route: context.route,
        tab: tab.into(),
        connection: context.connection,
        interaction: document.interaction,
        document: document.committed.clone(),
        refs: BTreeMap::new(),
        image: None,
    }
}

async fn confirm(context: &Context<'_>, tab: &str, expected: &Document) -> Result<(), Value> {
    let observed = context.document(tab).await?;
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
        let result = capture_attempt(context, tab, args, current, once, zoom, attempt != 0).await;
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
    let mut records = Vec::new();
    let mut record_frames = Vec::new();
    let mut frame_owners = BTreeMap::new();
    let mut included_owners = BTreeSet::new();
    let mut failed_frames = BTreeSet::new();
    let mut facts = HashMap::new();
    let mut html = Vec::new();
    let mut popup = false;
    let mut ax_truncated = false;
    let mut refs_truncated = false;
    let mut zoom_target = None;
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
                    .ok_or_else(|| refusal("protocol_error"))?;
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
            .ok_or_else(|| refusal("protocol_error"))?;
        let dom = plan.results[3]
            .as_object()
            .ok_or_else(|| refusal("protocol_error"))?;
        let observation = snapshot_from_capture(
            nodes,
            dom,
            tab,
            &frame.frame_id,
            document.interaction,
            &frame.url,
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
            let fresh = opaque("ur");
            if expected_zoom.is_some_and(|expected| expected.identity == identity) {
                zoom_target = Some(fresh.clone());
            }
            renamed.insert(reference.captured.reference.clone(), fresh.clone());
            snapshot.refs.insert(
                fresh,
                ShownRef {
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
            let root = nodes
                .first()
                .and_then(|node| node["backendDOMNodeId"].as_u64());
            let Some(root) = root else {
                if frame.parent_id.is_some() {
                    failed_frames.insert(frame.frame_id.clone());
                    continue;
                }
                return Err(refusal("snapshot_not_ready"));
            };
            let outer = context
                .cdp_frame(
                    tab,
                    Some(document.interaction),
                    frame,
                    vec![command("DOM.getOuterHTML", json!({"backendNodeId":root}))],
                )
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
                    .ok_or_else(|| refusal("protocol_error"))?
                    .to_owned(),
            ));
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
    if expected_zoom.is_some() && zoom_target.is_none() && !omitted_zoom {
        return Err(refusal("ref_scope_mismatch"));
    }
    let observed = context.document(tab).await?;
    if observed.committed != document.committed || observed.interaction != document.interaction {
        return Err(read_again(false));
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
    let rendered = state_text::render(&RenderInput {
        records: &records,
        facts: &facts,
        page_url: &document.committed.url,
        snapshot_id: &id,
        zoom: zoom_ref.map(|requested| Zoom {
            requested,
            target: zoom_target.as_deref(),
        }),
        filters: &filters,
        max_bytes,
    });
    snapshot
        .refs
        .retain(|reference, _| rendered.printed_refs.contains(reference));
    let (text, text_truncated) = if args["mode"] == "dom_full" {
        snapshot.refs.clear();
        let mut seen = BTreeSet::new();
        let mut documents = Vec::new();
        for frame in document.frames.iter().chain(&observed.frames) {
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
            if !seen.contains(frame) && record.name.starts_with("[embedded frame not readable:") {
                documents.push(record.name.as_str());
            }
        }
        crate::snapshot_store::encode_dom_text(&documents.join("\n"), max_bytes)
    } else {
        // AX and actionable reads share the renderer that withholds protected
        // field values. Its output budget can cut an otherwise complete tree.
        (
            rendered.text,
            rendered.cut_bytes > 0 || rendered.cut_lines > 0,
        )
    };
    let truncated = ax_truncated || refs_truncated || text_truncated || omitted_frames != 0;
    context.target().retain(id.clone(), snapshot);
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"snapshot_id":id,"connection_epoch":context.connection,"interaction_epoch":document.interaction,"state_text":text,"input_dispatched":false,"truncated":truncated,"refs_truncated":refs_truncated});
    // A committed document and an unchanged interaction epoch do not establish
    // that Chrome has finished loading its page or accessibility tree.
    reply["settled"] = json!(false);
    if omitted_frames != 0 {
        reply["omitted_frames"] = json!(omitted_frames);
    }
    reply["settlement_reason"] = json!("Page settlement is not observed on the person's browser.");
    if truncated {
        reply["remedy"] = json!(
            "This snapshot is partial; read again before assuming absent controls are unavailable."
        );
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
    let capture = context
        .cdp(
            tab,
            Some(document.interaction),
            vec![
                command("Page.getLayoutMetrics", json!({})),
                command(
                    "Page.captureScreenshot",
                    json!({"format":"png","captureBeyondViewport":false}),
                ),
                command("Page.getLayoutMetrics", json!({})),
            ],
        )
        .await?;
    let viewport = &capture.results[0]["cssVisualViewport"];
    if viewport != &capture.results[2]["cssVisualViewport"] {
        return Err(refusal("viewport_changed"));
    }
    let image = capture.results[1]["data"]
        .as_str()
        .ok_or_else(|| refusal("protocol_error"))?;
    let decoded = crate::coordinate::validate_png_base64_dimensions(image)
        .map_err(|_| refusal("screenshot_not_ready"))?;
    if decoded.as_bytes().len() > args["max_bytes"].as_u64().unwrap_or(262144) as usize {
        return Err(refusal("image_too_large"));
    }
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
    Ok(
        json!({"browser":"user","outcome":"ok","tab":tab,"snapshot_id":id,"connection_epoch":context.connection,"interaction_epoch":document.interaction,"image":{"mime":"image/png","data_b64":image,"width_px":width,"height_px":height},"image_width_px":width,"image_height_px":height,"input_dispatched":false}),
    )
}

async fn input(
    context: &Context<'_>,
    tab: &str,
    action: &str,
    args: &Value,
    current: &Document,
) -> Result<Value, Value> {
    let snapshot = context
        .target()
        .snapshot(context.route, tab, context.connection, args)?;
    if snapshot.document != current.committed || snapshot.interaction != current.interaction {
        return Err(read_again(false));
    }
    let (identity, frame, position) = if action == "click_point" {
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
        let hit = context.cdp(tab, Some(snapshot.interaction), vec![command("DOM.getNodeForLocation", json!({"x":x.round() as i64,"y":y.round() as i64,"includeUserAgentShadowDOM":true}))]).await?;
        let frame_id = hit.results[0]["frameId"]
            .as_str()
            .ok_or_else(|| refusal("classification_unavailable"))?;
        let frame = current
            .frames
            .iter()
            .find(|frame| frame.frame_id == frame_id)
            .ok_or_else(|| refusal("frame_not_authorized"))?
            .clone();
        let backend = hit.results[0]["backendNodeId"]
            .as_u64()
            .ok_or_else(|| refusal("classification_unavailable"))?;
        let local = &hit.results[0]["frame_point"];
        let position = if local.is_null() {
            (x, y)
        } else {
            (
                local["x"]
                    .as_f64()
                    .ok_or_else(|| refusal("protocol_error"))?,
                local["y"]
                    .as_f64()
                    .ok_or_else(|| refusal("protocol_error"))?,
            )
        };
        (
            BackendNodeIdentity::new(tab, frame_id, backend)
                .map_err(|_| refusal("classification_unavailable"))?,
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
        .authorize(&input_origin, requested, BTreeSet::new())
        .await?;
    let mut observed = context
        .cdp_frame(
            tab,
            Some(snapshot.interaction),
            &frame,
            flattened_document(),
        )
        .await?;
    let dom = observed
        .results
        .pop()
        .ok_or_else(|| refusal("classification_unavailable"))?;
    let dom_object = dom
        .as_object()
        .ok_or_else(|| refusal("classification_unavailable"))?;
    let classification =
        classify_flattened_document(dom_object, &identity, snapshot.interaction, &frame.url)
            .map_err(|_| refusal("classification_unavailable"))?;
    if let Some(expected) = args["ref"]
        .as_str()
        .and_then(|reference| snapshot.refs.get(reference))
        .and_then(|reference| reference.classification.as_ref())
    {
        if *expected != classification {
            return Err(refusal("classification_changed"));
        }
    }
    if action == "type" {
        let target = crate::browser::navigation::type_target_from_capture(
            dom_object,
            &identity,
            &classification,
        )
        .map_err(|_| refusal("classification_unavailable"))?;
        if !crate::browser_type::browser_type_dispatch_eligible(&target)
            || target.classification().credential
            || target.classification().financial
        {
            return Err(refusal("credential_payment_or_ineligible_field"));
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
        authorization::target_hazards(authorized_action, Some(&classification))
            .map_err(|_| refusal("classification_unavailable"))?
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
                &classification,
                false,
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
            let opened: Claimed =
                serde_json::from_value(raw).map_err(|_| refusal("protocol_error"))?;
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
        let quad = context
            .cdp_frame(
                tab,
                Some(snapshot.interaction),
                &frame,
                vec![command(
                    "DOM.getContentQuads",
                    json!({"backendNodeId":identity.backend_node_id}),
                )],
            )
            .await?;
        Some(quad_center(&quad.results[0])?)
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
    let mut steps = steps.into_iter();
    while let Some(step) = steps.next() {
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
        verify_input(
            context,
            tab,
            &snapshot,
            &frame,
            &identity,
            &classification,
            dispatched,
        )
        .await
        .map_err(|mut reply| {
            if dispatched {
                reply["input_dispatched"] = json!(true);
            }
            reply
        })?;
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
            runtime_plan(
                &identity,
                step["params"]["functionDeclaration"]
                    .as_str()
                    .expect("pinned declaration"),
            )
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
                    &classification,
                    dispatched,
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

async fn verify_input(
    context: &Context<'_>,
    tab: &str,
    snapshot: &Snapshot,
    frame: &FrameDocument,
    identity: &BackendNodeIdentity,
    expected: &NonTypeClassificationRecord,
    dispatched: bool,
) -> Result<(), Value> {
    let observed = context.document(tab).await.map_err(|mut reply| {
        if dispatched {
            reply["input_dispatched"] = json!(true);
        }
        reply
    })?;
    if observed.interaction != snapshot.interaction || observed.committed != snapshot.document {
        return Err(read_again(dispatched));
    }
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
    let mut plan = context
        .cdp_frame(tab, Some(snapshot.interaction), frame, flattened_document())
        .await
        .map_err(|mut reply| {
            if dispatched {
                reply["input_dispatched"] = json!(true);
            }
            reply
        })?;
    let dom = plan
        .results
        .pop()
        .ok_or_else(|| refusal("classification_unavailable"))?;
    let record = classify_flattened_document(
        dom.as_object()
            .ok_or_else(|| refusal("classification_unavailable"))?,
        identity,
        snapshot.interaction,
        &frame.url,
    )
    .map_err(|_| refusal("classification_unavailable"))?;
    if record != *expected {
        let mut reply = refusal("classification_changed");
        reply["input_dispatched"] = json!(dispatched);
        return Err(reply);
    }
    if context.action == "type" {
        let target = crate::browser::navigation::type_target_from_capture(
            dom.as_object().unwrap(),
            identity,
            &record,
        )
        .map_err(|_| refusal("classification_unavailable"))?;
        if !crate::browser_type::browser_type_dispatch_eligible(&target)
            || target.classification().credential
            || target.classification().financial
        {
            return Err(refusal("credential_payment_or_ineligible_field"));
        }
    }
    Ok(())
}

fn quad_center(result: &Value) -> Result<(f64, f64), Value> {
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
        if let Ok(center) = quad.midpoint() {
            return Ok(center);
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
    let result = context.cdp_frame(tab, Some(snapshot.interaction), frame, vec![command("Page.getLayoutMetrics", json!({})), command("DOM.getNodeForLocation", json!({"x":x.round() as i64,"y":y.round() as i64,"includeUserAgentShadowDOM":true}))]).await.map_err(|mut reply| { if dispatched { reply["input_dispatched"] = json!(true); } reply })?;
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
    let mut dom = context
        .cdp_frame(tab, Some(snapshot.interaction), frame, flattened_document())
        .await?;
    let dom = dom
        .results
        .pop()
        .ok_or_else(|| refusal("classification_unavailable"))?;
    let record = classify_flattened_document(
        dom.as_object()
            .ok_or_else(|| refusal("classification_unavailable"))?,
        &identity,
        snapshot.interaction,
        &frame.url,
    )
    .map_err(|_| refusal("classification_unavailable"))?;
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
