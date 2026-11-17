//! Agent provenance survives scope replacement when an agent moves computers.

use super::*;
use subc_protocol::session::{ModuleControlRequestFromModule, ModuleControlResponseToModule};

pub(crate) fn bound_agent(planes: &Planes, scope: &str) -> Option<String> {
    planes
        .routes
        .inner
        .read()
        .unwrap()
        .values()
        .filter_map(|facts| facts.scope.as_ref())
        .filter(|stamp| stamp.scope_ref == scope)
        .find_map(|stamp| {
            stamp
                .attributes
                .agent_id
                .clone()
                .filter(|id| !id.is_empty())
        })
}

async fn resolve_agent(planes: &Planes, scope: &str) -> Option<String> {
    if let Some(agent) = bound_agent(planes, scope) {
        return Some(agent);
    }
    let timeout = crate::call_context::CALL_DEADLINE
        .try_with(|deadline| deadline.saturating_duration_since(tokio::time::Instant::now()))
        .map_or(planes.scopes.describe_timeout, |remaining| {
            remaining.min(planes.scopes.describe_timeout)
        });
    let lookup = async {
        for owner in cerebellum_core::principal::PREFRONTAL_MODULE_IDS {
            let response = planes
                .scopes
                .control
                .request_connected(
                    &ModuleControlRequestFromModule::ScopeDescribe {
                        owner: subc_protocol::Principal::Reserved {
                            module_id: owner.to_string(),
                        },
                        scope_ref: scope.to_owned(),
                    },
                    timeout,
                )
                .await;
            if let Some(crate::scope_watch::ControlAnswer::Response(body)) = response {
                if let Ok(ModuleControlResponseToModule::ScopeDescribe {
                    owner_synced: true,
                    status: subc_protocol::scope::ScopeStatus::Live,
                    scope_epoch: Some(epoch),
                    scope: Some(stamp),
                    ..
                }) = serde_json::from_value(body)
                {
                    if stamp.scope_ref == scope
                        && stamp.scope_epoch == epoch
                        && matches!(&stamp.owner, subc_protocol::Principal::Reserved {module_id} if module_id == owner)
                    {
                        if let Some(agent) = stamp.attributes.agent_id.filter(|id| !id.is_empty()) {
                            return Some(agent);
                        }
                    }
                }
            }
        }
        None
    };
    tokio::time::timeout(timeout, lookup).await.ok().flatten()
}

pub(super) async fn query(planes: &Planes, scopes: &[&str]) -> Value {
    let has_agents = planes
        .private_content
        .state
        .lock()
        .unwrap()
        .document
        .agents
        .values()
        .any(|sources| !sources.is_empty());
    let mut agents = Vec::new();
    if has_agents {
        for scope in scopes {
            agents.push(resolve_agent(planes, scope).await);
        }
    }
    planes
        .private_content
        .answer_agents(scopes, &agents, crate::wall_clock_ms())
}

impl PrivateContent {
    pub(crate) fn export_agent(&self, agent: &str) -> BTreeSet<Source> {
        let mut state = self.state.lock().unwrap();
        let now = crate::wall_clock_ms();
        prune(&mut state.document, now);
        let mut sources = state
            .document
            .agents
            .get(agent)
            .cloned()
            .unwrap_or_default();
        for marks in state
            .document
            .heads
            .values()
            .chain(state.document.runs.values())
        {
            for (source, mark) in marks {
                match mark.agent() {
                    Some(owner) if owner == agent => {
                        sources.insert(*source);
                    }
                    None => {
                        sources.insert(Source::Unattributed);
                    }
                    _ => {}
                }
            }
        }
        if state.fails_closed(now) {
            sources.insert(Source::Unattributed);
        }
        sources
    }

    pub(crate) async fn import_agent(
        self: &Arc<Self>,
        agent: &str,
        sources: &BTreeSet<Source>,
    ) -> bool {
        let failures = {
            let mut state = self.state.lock().unwrap();
            state.document.version = 3;
            state
                .document
                .agents
                .entry(agent.to_owned())
                .or_default()
                .extend(sources);
            state.failures
        };
        self.path.is_none() || self.write(failures, crate::wall_clock_ms()).await
    }
}

#[cfg(test)]
mod tests;
