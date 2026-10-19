//! Permission authority follows the calling scope, not the head a worker names.

use cerebellum_core::identity::{AcceptedBindFacts, SessionKind};
use subc_protocol::scope::{ScopeKind, ScopeStamp, ScopeStatus};
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};

use crate::agent_grants::GrantHolder;
use crate::scope_watch::{ControlAnswer, ScopeKey};

pub(crate) struct ResolvedWorker {
    parent: ScopeKey,
    worker: ScopeKey,
    holder: GrantHolder,
}

tokio::task_local! {
    // A head may end between calls, so a successful lookup must never become
    // route-wide authority. All grant readers in this call share this answer.
    pub(crate) static WORKER_HOLDER: Option<ResolvedWorker>;
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HeadRefusal {
    NoHolder,
    Unavailable,
}

/// Session stamps are the daemon-accepted identity records. A worker's record
/// names its parent head session rather than an agent, so use the head resolved
/// for this call. A head already carries its agent id; a project path proves none.
pub(crate) fn cursor_agent(
    facts: &AcceptedBindFacts,
    worker: Option<&ResolvedWorker>,
) -> Option<String> {
    let facts = facts.head_context();
    if is_worker(facts) {
        return worker.map(|worker| match &worker.holder {
            GrantHolder::Head { agent_id } | GrantHolder::Worker { agent_id, .. } => {
                agent_id.clone()
            }
        });
    }
    facts
        .scope
        .as_ref()
        .filter(|stamp| stamp.kind == ScopeKind::Head && stamp.owner_authorized)
        .and_then(|stamp| stamp.attributes.agent_id.clone())
        .filter(|id| !id.is_empty())
}

/// The head session a call's cursor badge belongs to, as the scope the daemon
/// stamped on the head's route. A worker's calls belong to the head it works
/// for, through the parent link the daemon also stamped, so the head's turn
/// ending covers its workers' badges too. Nothing here is read from a request
/// body.
pub(crate) fn cursor_session(
    facts: &AcceptedBindFacts,
) -> Option<crate::computer_capability::cursor::SessionScope> {
    let facts = facts.head_context();
    use crate::computer_capability::cursor::SessionScope;
    let stamp = facts.scope.as_ref()?;
    match stamp.kind {
        ScopeKind::Head if stamp.owner_authorized => Some(SessionScope {
            scope_ref: stamp.scope_ref.clone(),
            epoch: stamp.scope_epoch,
        }),
        ScopeKind::Worker => worker_parent(facts).map(|parent| SessionScope {
            scope_ref: parent.scope_ref,
            epoch: parent.scope_epoch,
        }),
        _ => None,
    }
}

fn worker_parent(facts: &AcceptedBindFacts) -> Option<ScopeKey> {
    let stamp = facts.scope.as_ref()?;
    let parent = stamp.parent.as_ref()?;
    let core = subc_protocol::Principal::Reserved {
        module_id: "prefrontal-core".into(),
    };
    (stamp.kind == ScopeKind::Worker
        && stamp.owner_authorized
        && stamp.owner == core
        && parent.owner == stamp.owner
        && facts.principal.as_ref() == Some(&core)
        && stamp.attributes.flow_id.is_none()
        && facts.flow_id.is_none())
    .then(|| ScopeKey {
        owner: parent.owner.clone(),
        scope_ref: parent.scope_ref.clone(),
        scope_epoch: parent.scope_epoch,
    })
}

/// Ask on the module's own daemon connection, before any grant is read or
/// minted. The route's existing deadline bounds this future as well as dispatch.
pub(crate) async fn resolve_worker(
    facts: &AcceptedBindFacts,
    scopes: &crate::scope_watch::ScopeRevocation,
) -> Result<Option<ResolvedWorker>, HeadRefusal> {
    let Some(stamp) = facts.scope.as_ref().filter(|s| s.kind == ScopeKind::Worker) else {
        return Ok(None);
    };
    let parent = worker_parent(facts).ok_or(HeadRefusal::NoHolder)?;
    let timeout = crate::call_context::CALL_DEADLINE
        .try_with(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()))
        .map_or(scopes.describe_timeout, |remaining| {
            remaining.min(scopes.describe_timeout)
        });
    let answer = scopes
        .control
        .request_connected(
            &ModuleControlRequestFromModule::ScopeDescribe {
                owner: parent.owner.clone(),
                scope_ref: parent.scope_ref.clone(),
            },
            timeout,
        )
        .await;
    let Some(ControlAnswer::Response(body)) = answer else {
        return Err(HeadRefusal::Unavailable);
    };
    let Ok(ModuleControlResponseToModule::ScopeDescribe {
        status,
        scope_epoch,
        owner_synced,
        scope,
        ..
    }) = serde_json::from_value(body)
    else {
        return Err(HeadRefusal::Unavailable);
    };
    // After a daemon restart an owner has not yet published its full set.
    // Absence at that point is unknown, not proof that the head ended.
    if !owner_synced {
        return Err(HeadRefusal::Unavailable);
    }
    if status != ScopeStatus::Live || scope_epoch != Some(parent.scope_epoch) {
        return Err(HeadRefusal::NoHolder);
    }
    let head = scope.ok_or(HeadRefusal::NoHolder)?;
    if head.kind != ScopeKind::Head
        || head.owner != parent.owner
        || head.scope_ref != parent.scope_ref
        || head.scope_epoch != parent.scope_epoch
    {
        return Err(HeadRefusal::NoHolder);
    }
    let agent_id = head
        .attributes
        .agent_id
        .filter(|id| !id.is_empty())
        .ok_or(HeadRefusal::NoHolder)?;
    Ok(Some(ResolvedWorker {
        parent,
        worker: ScopeKey::from_stamp(stamp),
        holder: GrantHolder::Worker {
            agent_id,
            // Revival keeps this ref; a fresh task gets a different one.
            scope_ref: stamp.scope_ref.clone(),
        },
    }))
}

/// Resolve authority from accepted admission facts and this call's daemon lookup.
/// A flow attribute alone is not delegation, and a caller-controlled project
/// directory cannot establish the agent identity used to hold permissions.
pub(crate) fn authorizing_holder(facts: &AcceptedBindFacts) -> Option<GrantHolder> {
    let facts = facts.head_context();
    if facts.flow_id.is_none()
        && facts
            .scope
            .as_ref()
            .is_some_and(|stamp| stamp.attributes.flow_id.is_some())
    {
        return None;
    }
    if let Some(stamp) = facts.scope.as_ref().filter(|s| s.kind == ScopeKind::Worker) {
        let parent = worker_parent(facts)?;
        return WORKER_HOLDER
            .try_with(|resolved| {
                resolved
                    .as_ref()
                    .filter(|resolved| resolved.parent == parent && resolved.worker.names(stamp))
                    .map(|resolved| resolved.holder.clone())
            })
            .ok()
            .flatten();
    }
    if !facts.agent_project_id_attested
        || !facts.session_kind_attested
        || facts.identity.agent_project_id.is_empty()
    {
        return None;
    }
    let agent_id = facts.identity.agent_project_id.clone();
    if facts.flow_id.is_some() {
        let stamp = facts.scope.as_ref()?;
        return (cerebellum_core::identity::flow_carrier_admitted(stamp, &facts.principal)
            && stamp.attributes.delegates
            && facts.acts_as_agent
            && stamp.attributes.agent_id.as_deref() == Some(agent_id.as_str()))
        .then_some(GrantHolder::Head { agent_id });
    }
    (facts.acts_as_agent
        && !is_worker(facts)
        && facts.identity.session_kind == SessionKind::Primary)
        .then_some(GrantHolder::Head { agent_id })
}

pub(crate) fn minting_holder(facts: &AcceptedBindFacts) -> Option<GrantHolder> {
    facts
        .flow_id
        .is_none()
        .then(|| authorizing_holder(facts))
        .flatten()
}

pub(crate) fn is_worker(facts: &AcceptedBindFacts) -> bool {
    facts
        .scope
        .as_ref()
        .is_some_and(|stamp| stamp.kind == ScopeKind::Worker)
        || facts.identity.session_kind == SessionKind::Subagent
}

/// Return a scope for an admitted, non-flow head or worker call. Workers carry
/// a parent rather than an agent identity: `LiveCall::new` requires that parent,
/// and Cingulate resolves it to a live head. A worker must still pass the same
/// admitted-caller check as a head session.
pub(crate) fn card_stamp(facts: &AcceptedBindFacts) -> Option<&ScopeStamp> {
    let facts = facts.head_context();
    (facts.admits_session_calls()
        && facts.flow_id.is_none()
        && (facts.agent_project_id_attested
            || facts
                .scope
                .as_ref()
                .is_some_and(|stamp| stamp.kind == ScopeKind::Worker)))
    .then_some(facts.scope.as_ref())
    .flatten()
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Arc, Mutex};

    use serde_json::{json, Value};

    pub(crate) fn live_head() -> Value {
        json!({
            "op":"scope.describe", "status":"live", "scope_epoch":7,
            "daemon_incarnation":"daemon-test", "owner_synced":true, "owner_configured":true,
            "scope":{"owner":{"kind":"reserved","module_id":"prefrontal-core"},
                "owner_authorized":true, "ref":"sc_head_alf", "scope_epoch":7, "kind":"head",
                "attributes":{"agent_id":"test-project"}}
        })
    }

    /// Exercise the production channel-0 request tracker with a scripted daemon.
    pub(crate) fn describe(
        planes: &crate::Planes,
        answer: Value,
    ) -> (Arc<Mutex<Value>>, Arc<Mutex<Vec<Value>>>) {
        let answer = Arc::new(Mutex::new(answer));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let (tx, mut rx) = tokio::sync::mpsc::channel::<subc_protocol::Frame>(8);
        if planes.scopes.control.connect(&tx) {
            let scopes = planes.scopes.clone();
            let answer = answer.clone();
            let requests = requests.clone();
            tokio::spawn(async move {
                let _connection = tx;
                while let Some(frame) = rx.recv().await {
                    assert_eq!(frame.header.channel, 0);
                    requests
                        .lock()
                        .unwrap()
                        .push(serde_json::from_slice(&frame.body).unwrap());
                    scopes.control.deliver(
                        frame.header.corr,
                        super::ControlAnswer::Response(answer.lock().unwrap().clone()),
                    );
                }
            });
        }
        (answer, requests)
    }
}
