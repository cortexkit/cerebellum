//! A run borrows a live, provider-admitted head route, not its bind's session id.

use crate::{AcceptedBindFacts, RouteBindings};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use subc_protocol::scope::{ParentState, ScopeKind, ScopeParent, ScopeStamp};
use subc_protocol::Principal;

type CallKey = (String, String);
type InFlight = (
    crate::journal::call_records::ScopeIdentity,
    crate::CancelHandle,
);

/// Live interruption is separate from durable call history. Exact carrier keys
/// prevent a withdrawal from discovering or cancelling another module's call.
#[derive(Clone, Default)]
pub(crate) struct RunCalls(Arc<Mutex<HashMap<CallKey, InFlight>>>);

pub(crate) struct RunCall {
    registry: RunCalls,
    key: CallKey,
    handle: crate::CancelHandle,
}

impl RunCalls {
    pub(crate) fn register(
        &self,
        facts: &AcceptedBindFacts,
        key: &str,
        handle: Option<crate::CancelHandle>,
    ) -> Option<RunCall> {
        facts.codemode_head.as_ref()?;
        let handle = handle?;
        let scope = crate::journal::call_records::ScopeIdentity::from_stamp(facts.scope.as_ref()?);
        let key = (
            crate::journal::call_records::principal_label(facts.principal.as_ref()),
            key.to_owned(),
        );
        let mut calls = self.0.lock().unwrap();
        if calls.contains_key(&key) {
            return None;
        }
        calls.insert(key.clone(), (scope, handle.clone()));
        Some(RunCall {
            registry: self.clone(),
            key,
            handle,
        })
    }

    pub(crate) fn cancellation(
        &self,
        carrier: &str,
        key: &str,
        scope: Option<&crate::journal::call_records::ScopeIdentity>,
    ) -> Option<crate::CancelHandle> {
        self.0
            .lock()
            .unwrap()
            .get(&(carrier.to_owned(), key.to_owned()))
            .filter(|(recorded, _)| Some(recorded) == scope)
            .map(|(_, handle)| handle.clone())
    }
}

impl Drop for RunCall {
    fn drop(&mut self) {
        let mut calls = self.registry.0.lock().unwrap();
        if calls
            .get(&self.key)
            .is_some_and(|(_, handle)| Arc::ptr_eq(&handle.0, &self.handle.0))
        {
            calls.remove(&self.key);
        }
    }
}

tokio::task_local! {
    pub(crate) static CALL_MODE: subc_protocol::call_mode::CallMode;
    pub(crate) static CALL_DETAIL: RefCell<Option<Value>>;
    pub(crate) static CALL_RECORDS: Arc<crate::journal::call_records::CallRecords>;
}

pub(crate) fn program() -> bool {
    CALL_MODE
        .try_with(|mode| *mode == subc_protocol::call_mode::CallMode::Codemode)
        .unwrap_or(false)
}

pub(crate) fn active() -> bool {
    CALL_DETAIL
        .try_with(|detail| detail.borrow().is_some())
        .unwrap_or(false)
}

pub(crate) fn app(bundle: &str) {
    let _ = CALL_DETAIL.try_with(|detail| {
        if let Some(detail) = detail.borrow_mut().as_mut() {
            detail["app"] = json!(bundle);
        }
    });
}

/// Name the site a held or refused codemode step is about, when the call's
/// arguments did not (a user-browser read names a tab, not a site).
pub(crate) fn origin(origin: &str) {
    crate::tool_display::site(origin);
    let _ = CALL_DETAIL.try_with(|detail| {
        if let Some(detail) = detail.borrow_mut().as_mut() {
            detail["origin"] = json!(origin);
        }
    });
}

pub(crate) fn legacy_run(facts: &AcceptedBindFacts) -> bool {
    facts.codemode_head.is_none()
        && (facts.call_mode == subc_protocol::call_mode::CallMode::Codemode
            || facts
                .scope
                .as_ref()
                .is_some_and(|stamp| stamp.attributes.run_id.is_some()))
}

pub(crate) fn call_detail(
    frame: &subc_protocol::Frame,
    facts: &AcceptedBindFacts,
) -> Option<Value> {
    facts.codemode_head.as_ref()?;
    let request: Value = serde_json::from_slice(&frame.body).ok()?;
    let args = request.get("arguments").or_else(|| request.get("params"))?;
    let action = args["action"]
        .as_str()
        .or_else(|| request["method"].as_str())
        .or_else(|| {
            request["name"]
                .as_str()
                .and_then(|name| name.split_once('.').map(|(_, action)| action))
        })?;
    let mut detail = json!({"action":action});
    if let Some(origin) = args
        .get("origin")
        .or_else(|| args["origins"].get(0))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .or_else(|| {
            args.get("url")
                .or_else(|| args.get("login_url"))?
                .as_str()
                .and_then(crate::classification::canonical_origin_from_url)
        })
    {
        detail["origin"] = json!(origin);
    }
    if let Some(app) = args
        .get("target")
        .or_else(|| args.get("app"))
        .or_else(|| args.get("bundle_identity"))
    {
        detail["app"] = app.clone();
    }
    Some(detail)
}

/// The route bind's consumer capabilities choose the held reader, not call_mode.
/// The validated envelope call_key addresses the promised durable late answer.
pub(crate) fn held(reply: &Value) -> Option<cortexkit_role_tool_provider::result::HeldReply> {
    use cortexkit_role_tool_provider::result::HeldReply;
    if !accepts_held() {
        return None;
    }
    let reason = match reply["outcome"].as_str()? {
        "consent_pending" => "consent",
        "login_pending" | "presented" => "login_handoff",
        "capture_pending" => "login_capture",
        _ => return None,
    };
    let mut detail = CALL_DETAIL.with(|detail| detail.borrow().clone().unwrap());
    for key in ["ask_id", "kind", "origin", "app", "expires_in_ms"] {
        if let Some(value) = reply.get(key) {
            detail[key] = value.clone();
        }
    }
    Some(HeldReply::new(reason).with_detail(detail.as_object().unwrap().clone()))
}

pub(crate) fn accepts_held() -> bool {
    active()
        && crate::call_context::current_call_key().is_some()
        && crate::tool_result::RESULT_BIND
            .try_with(|binding| {
                binding.as_ref().is_some_and(|(tool, bind)| {
                    matches!(
                        tool.as_str(),
                        crate::flat_tools::BROWSER_USE | crate::flat_tools::COMPUTER_USE
                    ) && cortexkit_role_tool_provider::consumer_reads_held_reply_v1(
                        bind.consumer_capabilities(),
                    )
                })
            })
            .unwrap_or(false)
}

/// Called while the consent desk's session lock is held, including when joining
/// an existing card. A competing inbound drain cannot acknowledge the answer
/// before this call's durable obligation exists.
pub(crate) async fn prepare_consent(
    ask_id: &str,
    kind: crate::cingulate_client::card::CardKind,
) -> Result<(), crate::cingulate_client::desk::Ending> {
    use crate::cingulate_client::desk::Ending;
    if !accepts_held() {
        return Ok(());
    }
    CALL_DETAIL.with(|detail| detail.borrow_mut().as_mut().unwrap()["kind"] = json!(kind));
    let calls = CALL_RECORDS
        .try_with(Arc::clone)
        .map_err(|_| Ending::DeliveryFailed)?;
    let principal = crate::tool_result::RESULT_BIND.with(|binding| {
        crate::journal::call_records::principal_label(
            binding.as_ref().unwrap().1.principal.as_ref(),
        )
    });
    let key = crate::call_context::current_call_key().unwrap();
    let ask_id = ask_id.to_owned();
    tokio::task::spawn_blocking(move || {
        calls.hold_consent(&principal, &key, &ask_id, crate::wall_clock_ms())
    })
    .await
    .map_err(|_| Ending::DeliveryFailed)?
    .map_err(|_| Ending::DeliveryFailed)
}

/// Older carriers cannot suspend on a domain pending reply. Preserve their
/// terminal refusal until the route declares the held-reply reader.
pub(crate) fn unsupported(reply: Value) -> Value {
    let pending = reply["outcome"]
        .as_str()
        .is_some_and(|outcome| outcome.ends_with("_pending") || outcome == "presented");
    if !active() || !pending {
        return reply;
    }
    let mut detail =
        CALL_DETAIL.with(|detail| detail.borrow().clone().expect("active codemode call"));
    detail["step"] = json!(match reply["outcome"].as_str() {
        Some("login_pending" | "presented") => "login_handoff",
        Some("capture_pending") => "login_capture",
        _ => "consent",
    });
    if let Some(origin) = reply.get("origin").or_else(|| reply["origins"].get(0)) {
        detail["origin"] = origin.clone();
    }
    if let Some(ask) = reply.get("ask_id") {
        detail["ask_id"] = ask.clone();
    }
    json!({"outcome":"held_unsupported", "detail":detail,
        "remedy":"this codemode step needs a person; the carrier cannot suspend until held-reply is supported"})
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ParentRefusal {
    NotLinked,
    NoLiveHead,
    AgentMismatch,
    /// The head is live, but none of its routes serves tools, so there is no
    /// route its user-browser claims and snapshots could be kept under.
    NoHeadToolsRoute,
}

impl ParentRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::NotLinked => "run_parent_not_linked",
            Self::NoLiveHead | Self::NoHeadToolsRoute => "run_parent_unavailable",
            Self::AgentMismatch => "run_agent_mismatch",
        }
    }

    pub(crate) fn message(&self) -> &'static str {
        match self {
            Self::NotLinked => "the run requires a linked parent head scope",
            Self::NoLiveHead => {
                "the parent has no live admitted cerebellum head route at that epoch"
            }
            Self::AgentMismatch => "the run agent differs from the admitted head route's agent",
            Self::NoHeadToolsRoute => {
                "the agent has no open tool route to keep its work in the person's Chrome under"
            }
        }
    }
}

/// The admitted head a run borrows, re-resolved for this request. `Ok(None)`
/// for a route that is not a run. Every request on a run route goes through
/// this check.
pub(crate) fn live_head(
    planes: &crate::Planes,
    facts: &AcceptedBindFacts,
) -> Result<Option<AcceptedBindFacts>, ParentRefusal> {
    if facts.codemode_head.is_none() {
        return Ok(None);
    }
    let head = planes
        .routes
        .run_head(facts.scope.as_ref().expect("admitted run stamp"))?;
    if head.identity.conversation_key != facts.identity.conversation_key
        || head
            .scope
            .as_ref()
            .is_some_and(|stamp| planes.scopes.is_superseded(stamp))
    {
        return Err(ParentRefusal::NoLiveHead);
    }
    Ok(Some(head))
}

/// The route whose claims, snapshots, element refs and quarantine a request on
/// (`channel`, `epoch`) uses in the person's own Chrome. Direct admitted head
/// calls and that head's runs share a retained session alias. Other scopes keep
/// their inbound route key; neither conversation identity nor relay origin
/// confers access to a head's tabs.
pub(crate) fn user_browser_route(
    planes: &crate::Planes,
    channel: u16,
    epoch: u32,
) -> Result<crate::user_browser_bridge::Route, ParentRefusal> {
    let own = crate::user_browser_bridge::Route { channel, epoch };
    let Some(facts) = planes.routes.get(channel, epoch) else {
        return Ok(own);
    };
    let head = live_head(planes, &facts)?;
    let run = head.is_some();
    let heads = if run {
        planes
            .routes
            .head_routes(facts.scope.as_ref().expect("admitted run stamp"))?
    } else {
        let Some(scope) = admitted_head_scope(&facts) else {
            return Ok(own);
        };
        if planes.scopes.is_superseded(scope) {
            return Ok(own);
        }
        planes.routes.routes_under_head(&ScopeParent::new(
            scope.owner.clone(),
            scope.scope_ref.clone(),
            scope.scope_epoch,
        ))
    };
    match head_tools_route(&heads) {
        Some(route) => {
            let scope =
                admitted_head_scope(head.as_ref().unwrap_or(&facts)).expect("admitted head scope");
            Ok(planes.user_browser.target().session_route(scope, route))
        }
        None if run => Err(ParentRefusal::NoHeadToolsRoute),
        None => Ok(own),
    }
}

/// Keep direct head calls and linked runs behind the same admission checks.
fn admitted_head_scope(facts: &AcceptedBindFacts) -> Option<&ScopeStamp> {
    let core = Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    facts.scope.as_ref().filter(|stamp| {
        stamp.kind == ScopeKind::Head
            && stamp.owner_authorized
            && stamp.owner == core
            && stamp.attributes.run_id.is_none()
            && stamp.attributes.flow_id.is_none()
            && facts.principal.as_ref() == Some(&core)
            && facts.agent_project_id_attested
            && facts.session_kind_attested
            && stamp.attributes.agent_id.as_deref()
                == Some(facts.identity.agent_project_id.as_str())
    })
}

/// One bound route of a run's head.
struct HeadRoute {
    route: crate::user_browser_bridge::Route,
    /// When the route's bind was accepted; lower is older.
    bound: u64,
    facts: AcceptedBindFacts,
}

/// Choose the initial bridge alias for a head that has not used this browser yet.
///
/// Only a tools-surface route can be that route, since management routes never
/// serve `browser_use`. Among tools routes the oldest-bound one is chosen.
/// Once retained by the session, that alias survives route closure and a newer
/// scope epoch for the same session. Its channel and epoch identify bridge
/// custody, not a live transport.
/// Channel numbers say nothing about which route was bound first.
fn head_tools_route(heads: &[HeadRoute]) -> Option<crate::user_browser_bridge::Route> {
    heads
        .iter()
        .filter(|head| head.facts.surface == crate::RouteSurface::Tools)
        .min_by_key(|head| head.bound)
        .map(|head| head.route)
}

impl RouteBindings {
    pub(crate) fn has_user_browser_session(&self, owner: &str, scope_ref: &str) -> bool {
        self.inner
            .read()
            .expect("route bindings lock poisoned")
            .values()
            .any(|facts| {
                admitted_head_scope(facts.head_context()).is_some_and(|scope| {
                    serde_json::to_string(&scope.owner).ok().as_deref() == Some(owner)
                        && scope.scope_ref == scope_ref
                })
            })
    }
    pub(crate) fn run_head(&self, run: &ScopeStamp) -> Result<AcceptedBindFacts, ParentRefusal> {
        let heads = self.head_routes(run)?;
        let head = &heads.first().ok_or(ParentRefusal::NoLiveHead)?.facts;
        if run.attributes.agent_id.as_deref() != Some(head.identity.agent_project_id.as_str()) {
            return Err(ParentRefusal::AgentMismatch);
        }
        Ok(head.clone())
    }

    /// Every bound route of the run's linked, admitted head, of any surface,
    /// sorted by (channel, epoch).
    fn head_routes(&self, run: &ScopeStamp) -> Result<Vec<HeadRoute>, ParentRefusal> {
        if run.parent_state != Some(ParentState::Linked) {
            return Err(ParentRefusal::NotLinked);
        }
        let parent = run.parent.as_ref().ok_or(ParentRefusal::NoLiveHead)?;
        Ok(self.routes_under_head(parent))
    }

    fn routes_under_head(&self, parent: &ScopeParent) -> Vec<HeadRoute> {
        let routes = self.inner.read().expect("route bindings lock poisoned");
        let mut heads = routes
            .iter()
            .filter(|(_, facts)| {
                admitted_head_scope(facts).is_some_and(|stamp| {
                    stamp.owner == parent.owner
                        && stamp.scope_ref == parent.scope_ref
                        && stamp.scope_epoch == parent.scope_epoch
                })
            })
            .map(|(&(channel, epoch), facts)| HeadRoute {
                route: crate::user_browser_bridge::Route { channel, epoch },
                bound: self.bind_sequence(channel, epoch).unwrap_or(u64::MAX),
                facts: facts.clone(),
            })
            .collect::<Vec<_>>();
        // A head may have both management and tool routes. Choose consistently;
        // they name the same head context, not whichever hash entry happens first.
        heads.sort_by_key(|head| head.route);
        heads
    }
}
