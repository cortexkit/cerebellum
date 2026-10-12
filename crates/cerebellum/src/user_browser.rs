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
use crate::classification::{
    canonical_grant_origin, canonical_origin_from_url, NonTypeClassificationRecord,
};
use crate::snapshot_store::{BackendNodeIdentity, CommittedDocument, FrameDocument};
use crate::user_browser_bridge::{Route, Terminal, UserBrowserBridge};
use crate::{AcceptedBindFacts, CancelHandle, Planes};

const CONSENT_DEADLINE: Duration = Duration::from_secs(120);
const MAX_SNAPSHOTS: usize = 64;
const NAVIGATION_READ_DEADLINE: Duration = Duration::from_secs(30);

tokio::task_local! {
    static POPUP_SEEN: Cell<bool>;
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
}

pub(crate) struct UserBrowser {
    state: Mutex<State>,
    grants: Arc<StandingBrowserGrants>,
}

impl UserBrowser {
    pub(crate) fn new(grants: Arc<StandingBrowserGrants>) -> Self {
        Self {
            state: Mutex::new(State::default()),
            grants,
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
        *state = State {
            ended_routes,
            ..State::default()
        };
    }

    fn synchronize(&self, connection: u64) {
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
    command["version"] = json!(1);
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
    })
}

fn command(method: &str, params: Value) -> Value {
    // WebNavigation frame 0 is the only admitted input-sentinel scope. CDP
    // frame ids belong in method parameters, never in sentinel routing.
    json!({"method":method,"params":params,"frame_id":0})
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
    embedded_frames: usize,
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
    collect_frames(
        &plan.results[1]["frameTree"],
        tab,
        &mut frames,
        0,
        &mut frame_count,
    )?;
    Ok(Document {
        committed,
        frames,
        interaction: plan.interaction,
        embedded_frames: frame_count.saturating_sub(1),
    })
}

fn collect_frames(
    tree: &Value,
    tab: &str,
    frames: &mut Vec<FrameDocument>,
    depth: usize,
    count: &mut usize,
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
    if let Ok(origin) = origin(&url) {
        frames.push(FrameDocument {
            navigation_revision: 0,
            frame_id: text("id")?,
            parent_id: (depth != 0)
                .then(|| frame["parentId"].as_str().unwrap_or("embedded").to_owned()),
            session_id: tab.into(),
            loader_id: text("loaderId")?,
            origin,
            url,
        });
    }
    if let Some(children) = tree["childFrames"].as_array() {
        for child in children {
            collect_frames(child, tab, frames, depth + 1, count)?;
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
    POPUP_SEEN
        .scope(
            Cell::new(false),
            serve_scoped(planes, facts, writer, request, action, args),
        )
        .await
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
    origin: String,
    severity: Severity,
    hazards: BTreeSet<HazardClass>,
    once: bool,
}

impl InvocationGrant {
    fn covers(&self, origin: &str, severity: Severity, hazards: &BTreeSet<HazardClass>) -> bool {
        self.once
            && self.origin == origin
            && self.severity.covers(severity)
            && hazards.is_subset(&self.hazards)
    }
}

struct Context<'a> {
    planes: &'a Planes,
    facts: &'a AcceptedBindFacts,
    writer: &'a mpsc::Sender<Frame>,
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
        once.is_some_and(|grant| grant.covers(origin, severity, hazards))
            || self
                .target()
                .covers(self.agent(), origin, severity, hazards)
    }

    async fn authorize(
        &self,
        origin: &str,
        severity: Severity,
        hazards: BTreeSet<HazardClass>,
    ) -> Result<InvocationGrant, Value> {
        let mut grant = InvocationGrant {
            origin: origin.into(),
            severity,
            hazards,
            once: false,
        };
        if severity.tier > 4 {
            return Err(refusal("severity_ungrantable"));
        }
        if self
            .target()
            .covers(self.agent(), origin, severity, &grant.hazards)
        {
            return Ok(grant);
        }
        if self.facts.flow_id.is_some() || !self.facts.declares_elicitation() {
            return Err(refusal("consent_unavailable"));
        }
        use crate::consent_card::*;
        let ask_id = opaque("user-browser:");
        let standing =
            self.target().grants.can_record() && crate::standing_offer_agent(self.facts).is_some();
        let mut options = vec![ConsentOption::grant("allow_once", "Allow once")
            .with_detail("Only this invocation, including its landing-page read.")];
        if standing {
            options.push(ConsentOption::grant(
                "allow_origin_always",
                "Always on this site",
            ));
        }
        let body = ConsentCard {
            title: format!("Allow access to {origin}?"),
            prompt: "Let the agent use your own Chrome, signed in as you, on this site?".into(),
            target: Target {
                kind: TargetKind::Site,
                label: origin.into(),
            },
            facts: vec![
                Fact::new("Browser", "Your own Chrome, signed in as you"),
                Fact::new("Site", origin),
                Fact::new("Level", severity.tier.to_string()),
                Fact::new(
                    "Hazards",
                    grant
                        .hazards
                        .iter()
                        .map(|hazard| hazard.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                ),
            ],
            grants: options,
            decline: ConsentOption::decline("deny", "Don't allow"),
            expires_in: CONSENT_DEADLINE,
            material_damage: true,
            urgency: Urgency::High,
            scope: Scope::new()
                .with("browser", "user")
                .with("origins", json!([origin]))
                .with("severity_tier", severity.tier)
                .with(
                    "hazards",
                    json!(grant
                        .hazards
                        .iter()
                        .map(|hazard| hazard.as_str())
                        .collect::<Vec<_>>()),
                ),
            duration: None,
        }
        .render(&ask_id);
        let mut drain = self.planes.drain_signal.subscribe();
        let answer = tokio::select! {
            biased;
            _ = self.cancel.cancelled() => return Err(refusal("cancelled")),
            _ = self.planes.routes.closed(self.route.channel, self.route.epoch) => return Err(refusal("route_closed")),
            _ = drain.wait_for(|draining| *draining) => return Err(refusal("module_draining")),
            answer = self.planes.elicitor.ask_for_call(self.writer, self.route.channel, self.route.epoch, body, CONSENT_DEADLINE, crate::elicit::current_call_key()) => answer,
        };
        let crate::elicit::AskOutcome::Answered(answer) = answer else {
            return Err(refusal("consent_unavailable"));
        };
        match answer.get("decision").and_then(Value::as_str) {
            Some("allow_once") => {
                grant.once = true;
                Ok(grant)
            }
            Some("allow_origin_always") if standing => {
                self.target()
                    .grants
                    .record(
                        self.agent(),
                        always_subject(origin.into()),
                        severity.tier,
                        grant.hazards.iter().copied().collect(),
                        None,
                        &ask_id,
                    )
                    .map_err(|_| refusal("grant_storage_unavailable"))?;
                Ok(grant)
            }
            _ => {
                let mut reply = refusal("consent_declined");
                reply["detail"] = json!({"decision":"deny"});
                Err(reply)
            }
        }
    }

    async fn cdp(
        &self,
        tab: &str,
        interaction: Option<u64>,
        commands: Vec<Value>,
    ) -> Result<Plan, Value> {
        self.planes
            .browser
            .journal_user_browser(
                &self.facts.identity,
                self.action,
                None,
                "dispatch_committed",
                None,
            )
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
    writer: &mpsc::Sender<Frame>,
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
        let mut reply = target
            .grants
            .revoke(&facts.identity.agent_project_id, &revoke);
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
        writer,
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
    if observed.committed != expected.committed || observed.interaction != expected.interaction {
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
    let id = opaque("us");
    let mut snapshot = baseline(context, tab, document);
    let mut records = Vec::new();
    let mut facts = HashMap::new();
    let mut html = Vec::new();
    let mut popup = false;
    let mut ax_truncated = false;
    let mut refs_truncated = false;
    let mut zoom_target = None;
    let zoom_ref = args["zoom"].as_str();
    let expected_zoom =
        zoom.and_then(|snapshot| zoom_ref.and_then(|reference| snapshot.refs.get(reference)));
    if zoom.is_some_and(|snapshot| {
        snapshot.document != document.committed || snapshot.interaction != document.interaction
    }) {
        return Err(read_again(false));
    }
    for frame in &document.frames {
        if frame.parent_id.is_some() {
            continue;
        }
        if !context.granted(
            &frame.origin,
            Severity::new(1, false, false),
            &BTreeSet::new(),
            Some(once),
        ) {
            continue;
        }
        if expected_zoom.is_some_and(|reference| !reference.frame.same_document(frame)) {
            continue;
        }
        let plan = context
            .cdp(
                tab,
                Some(document.interaction),
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
            .await?;
        popup |= plan.popup;
        let nodes = plan.results[1]["nodes"]
            .as_array()
            .ok_or_else(|| refusal("protocol_error"))?;
        let dom = plan.results[3]
            .as_object()
            .ok_or_else(|| refusal("protocol_error"))?;
        let mut observation = snapshot_from_capture(
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
        })?;
        ax_truncated |= observation.ax_truncated;
        refs_truncated |= observation.refs_truncated;
        let mut renamed = BTreeMap::new();
        for reference in observation.refs {
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
        records.extend(observation.records);
        if args["mode"] == "dom_full" {
            let root = nodes
                .first()
                .and_then(|node| node["backendDOMNodeId"].as_u64())
                .ok_or_else(|| refusal("snapshot_not_ready"))?;
            let outer = context
                .cdp(
                    tab,
                    Some(document.interaction),
                    vec![command("DOM.getOuterHTML", json!({"backendNodeId":root}))],
                )
                .await?;
            html.push(
                outer.results[0]["outerHTML"]
                    .as_str()
                    .ok_or_else(|| refusal("protocol_error"))?
                    .to_owned(),
            );
        }
    }
    if expected_zoom.is_some() && zoom_target.is_none() {
        return Err(refusal("ref_scope_mismatch"));
    }
    confirm(context, tab, document).await?;
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
        crate::snapshot_store::encode_dom_text(&html.join("\n"), max_bytes)
    } else {
        // AX and actionable reads share the renderer that withholds protected
        // field values. Its output budget can cut an otherwise complete tree.
        (
            rendered.text,
            rendered.cut_bytes > 0 || rendered.cut_lines > 0,
        )
    };
    let truncated =
        ax_truncated || refs_truncated || text_truncated || document.embedded_frames != 0;
    context.target().retain(id.clone(), snapshot);
    let mut reply = json!({"browser":"user","outcome":"ok","tab":tab,"snapshot_id":id,"connection_epoch":context.connection,"interaction_epoch":document.interaction,"state_text":text,"input_dispatched":false,"truncated":truncated,"refs_truncated":refs_truncated});
    // A committed document and an unchanged interaction epoch do not establish
    // that Chrome has finished loading its page or accessibility tree.
    reply["settled"] = json!(false);
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
    if document.embedded_frames != 0 {
        reply["omitted_frames"] = json!(document.embedded_frames);
        reply["frame_note"] =
            json!("Embedded frames are omitted; they cannot be used in the person's browser yet.");
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
        (
            BackendNodeIdentity::new(tab, frame_id, backend)
                .map_err(|_| refusal("classification_unavailable"))?,
            frame,
            Some((x, y)),
        )
    } else {
        let reference = snapshot
            .refs
            .get(args["ref"].as_str().unwrap())
            .ok_or_else(|| refusal("ref_scope_mismatch"))?;
        (reference.identity.clone(), reference.frame.clone(), None)
    };
    if frame.parent_id.is_some() {
        let mut reply = refusal("embedded_frame_unsupported");
        reply["remedy"] = json!("The embedded frame cannot be used in the person's browser yet; use the top-level page instead.");
        return Err(reply);
    }
    if !current.frames.iter().any(|live| live.same_document(&frame)) {
        return Err(refusal("frame_changed"));
    }
    // An ungranted frame cannot even be classified for input. A top-level
    // screenshot grant does not authorize acting inside a cross-site frame.
    let requested = if action == "type" {
        Severity::new(2, false, false)
    } else {
        declared_severity(args)?
    };
    let read_grant = context
        .authorize(&frame.origin, requested, BTreeSet::new())
        .await?;
    let mut observed = context
        .cdp(tab, Some(snapshot.interaction), flattened_document())
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
    let once = if read_grant.covers(&frame.origin, severity, &hazards) {
        read_grant
    } else {
        context
            .authorize(&frame.origin, severity, hazards.clone())
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
            .cdp(
                tab,
                Some(snapshot.interaction),
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
        if !context.granted(&frame.origin, severity, &hazards, Some(&once))
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
                    .cdp(
                        tab,
                        Some(snapshot.interaction),
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
        let outcome = context.cdp(tab, Some(snapshot.interaction), commands).await;
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
    let landing_origin = origin(&landed.committed.url)?;
    if !context.granted(
        &landing_origin,
        Severity::new(1, false, false),
        &BTreeSet::new(),
        Some(&once),
    ) && !context.granted(
        &landing_origin,
        Severity::new(1, false, false),
        &BTreeSet::new(),
        destination_once.as_ref(),
    ) {
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
        .cdp(tab, Some(snapshot.interaction), flattened_document())
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
    let result = context.cdp(tab, Some(snapshot.interaction), vec![command("Page.getLayoutMetrics", json!({})), command("DOM.getNodeForLocation", json!({"x":x.round() as i64,"y":y.round() as i64,"includeUserAgentShadowDOM":true}))]).await.map_err(|mut reply| { if dispatched { reply["input_dispatched"] = json!(true); } reply })?;
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
        .cdp(tab, Some(snapshot.interaction), flattened_document())
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
