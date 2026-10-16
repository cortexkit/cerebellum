//! Permission authority follows the calling scope, not the head a worker names.

use cerebellum_core::identity::{AcceptedBindFacts, SessionKind};
use subc_protocol::scope::{ScopeKind, ScopeStamp};

use crate::agent_grants::GrantHolder;

/// Resolve only identities recorded in the daemon's accepted admission facts.
/// A flow attribute alone is not delegation, and a caller-controlled project
/// directory cannot establish the agent identity used to hold permissions.
pub(crate) fn authorizing_holder(facts: &AcceptedBindFacts) -> Option<GrantHolder> {
    if facts.flow_id.is_none()
        && facts
            .scope
            .as_ref()
            .is_some_and(|stamp| stamp.attributes.flow_id.is_some())
    {
        return None;
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
    if let Some(stamp) = facts.scope.as_ref().filter(|s| s.kind == ScopeKind::Worker) {
        let core = subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        return (stamp.owner_authorized
            && stamp.owner == core
            && facts.principal.as_ref() == Some(&core)
            && stamp.attributes.flow_id.is_none()
            && stamp.attributes.agent_id.as_deref() == Some(agent_id.as_str()))
        .then(|| GrantHolder::Worker {
            agent_id,
            owner: crate::journal::call_records::principal_label(Some(&stamp.owner)),
            scope_ref: stamp.scope_ref.clone(),
            scope_epoch: stamp.scope_epoch,
        });
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
