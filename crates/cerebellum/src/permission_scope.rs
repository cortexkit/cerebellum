//! Permission authority follows the calling scope, not the head a worker names.

use cerebellum_core::identity::{AcceptedBindFacts, SessionKind};
use subc_protocol::scope::{ScopeKind, ScopeStamp};

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
