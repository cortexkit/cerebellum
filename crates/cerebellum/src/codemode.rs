//! A run borrows a live, provider-admitted head route, not its bind's session id.

use crate::{AcceptedBindFacts, RouteBindings};
use serde_json::{json, Value};
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use subc_protocol::scope::{ParentState, ScopeKind, ScopeStamp};
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
    pub(crate) static CALL_DETAIL: RefCell<Option<Value>>;
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

/// Domain handlers still validate their existing pending vocabulary. Translate
/// only at the provider boundary: Basal cannot suspend on a domain pending reply
/// until the held-reply protocol is published.
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
}

impl ParentRefusal {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::NotLinked => "run_parent_not_linked",
            Self::NoLiveHead => "run_parent_unavailable",
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
        }
    }
}

impl RouteBindings {
    pub(crate) fn run_head(&self, run: &ScopeStamp) -> Result<AcceptedBindFacts, ParentRefusal> {
        if run.parent_state != Some(ParentState::Linked) {
            return Err(ParentRefusal::NotLinked);
        }
        let parent = run.parent.as_ref().ok_or(ParentRefusal::NoLiveHead)?;
        let core = Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let routes = self.inner.read().expect("route bindings lock poisoned");
        let mut heads = routes
            .iter()
            .filter(|(_, facts)| {
                facts.scope.as_ref().is_some_and(|stamp| {
                    stamp.owner == parent.owner
                        && stamp.scope_ref == parent.scope_ref
                        && stamp.scope_epoch == parent.scope_epoch
                        && stamp.kind == ScopeKind::Head
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
            })
            .collect::<Vec<_>>();
        // A head may have both management and tool routes. Choose consistently;
        // they name the same head context, not whichever hash entry happens first.
        heads.sort_by_key(|(key, _)| **key);
        let (_, head) = heads.first().ok_or(ParentRefusal::NoLiveHead)?;
        if run.attributes.agent_id.as_deref() != Some(head.identity.agent_project_id.as_str()) {
            return Err(ParentRefusal::AgentMismatch);
        }
        Ok((*head).clone())
    }
}
