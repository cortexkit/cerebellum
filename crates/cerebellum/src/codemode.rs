//! A run borrows a live, provider-admitted head route, not its bind's session id.

use crate::{AcceptedBindFacts, RouteBindings};
use subc_protocol::scope::{ParentState, ScopeKind, ScopeStamp};
use subc_protocol::Principal;

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
