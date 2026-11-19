//! Card effects publish to the same machine-bound store used by dispatch.

use super::{AnsweredQuestion, ComputerGrants};
use crate::agent_grants::{AgentGrant, AgentGrantStoreError, GrantHolder, GrantSubject};

impl ComputerGrants {
    pub(crate) fn note_durable_store_health(store: &crate::agent_grants::AgentGrants) {
        super::DURABLE_STORE_STATE.store(
            if store.store_error().is_none() {
                super::STORE_STATE_LOADED
            } else {
                super::STORE_STATE_UNREADABLE
            },
            std::sync::atomic::Ordering::Release,
        );
    }
    pub(super) fn write_agent_answer(
        &self,
        open: &AnsweredQuestion,
        always: bool,
    ) -> Result<(), AgentGrantStoreError> {
        self.write_agent_answer_for(open, always, false)
    }

    pub(super) fn write_agent_answer_for(
        &self,
        open: &AnsweredQuestion,
        always: bool,
        whole: bool,
    ) -> Result<(), AgentGrantStoreError> {
        let holder = open
            .holder
            .clone()
            .ok_or(AgentGrantStoreError::NoMachineIdentity)?;
        if always && !matches!(holder, GrantHolder::Head { .. }) {
            return Err(AgentGrantStoreError::NoMachineIdentity);
        }
        let subject = super::cards::subject(open, whole)?;
        let now = self.agent_grants.now_ms();
        let window = if always {
            None
        } else {
            match crate::cingulate_client::answer_time::thirty_minute_window(now) {
                Some(window) => Some(window),
                // The answer's 30 minutes ran out before it was applied: it
                // settles, and grants nothing.
                None => return Ok(()),
            }
        };
        self.agent_grants.upsert(
            AgentGrant {
                id: String::new(),
                holder,
                subject,
                browser_target: None,
                machine_uuid: self
                    .agent_grants
                    .machine_uuid()
                    .ok_or(AgentGrantStoreError::NoMachineIdentity)?
                    .into(),
                granted_at_ms: window.map_or(now, |(start, _)| start),
                expires_at_ms: window.map(|(_, end)| end),
                card_ref: Some(open.card_ref.clone()),
                max_level: 4,
                hazards: vec![],
                team_id: open
                    .identity
                    .as_ref()
                    .and_then(|identity| identity.team_id.clone()),
                designated_requirement: open
                    .identity
                    .as_ref()
                    .map(|identity| identity.designated_requirement.clone()),
            },
            now,
        )?;
        Ok(())
    }
}

impl ComputerGrants {
    pub(super) fn list_agent_app_grants(&self) -> serde_json::Value {
        let store = &self.agent_grants;
        let rows = match store.live_rows(None, store.now_ms()) {
            Ok(rows) => rows,
            Err(error) => {
                return serde_json::json!({"grants":[],"other_machine_grants":[],"unbound_grants":[],"store":{"state":"unreadable","reason":"grant_store_unreadable","detail":error.to_string()}})
            }
        };
        let mut bound = Vec::new();
        let mut unbound = Vec::new();
        for row in rows {
            if row.expires_at_ms.is_some() || !matches!(row.holder, GrantHolder::Head { .. }) {
                continue;
            }
            let GrantSubject::App(bundle) = &row.subject else {
                continue;
            };
            let mut described = serde_json::json!({"grantee":row.holder.agent_id(),"bundle_identity":bundle,"created_at_ms":row.granted_at_ms});
            if let Some(team) = &row.team_id {
                described["team_id"] = serde_json::json!(team);
            }
            if row
                .designated_requirement
                .as_ref()
                .is_some_and(|requirement| !requirement.is_empty())
            {
                bound.push(described);
            } else {
                unbound.push(described);
            }
        }
        serde_json::json!({"grants":bound,"other_machine_grants":[],"unbound_grants":unbound,"store":{"state":"loaded"}})
    }

    pub(super) fn revoke_agent_app_grants(
        &self,
        grantee: &str,
        bundle: &str,
        dry_run: bool,
    ) -> serde_json::Value {
        let store = &self.agent_grants;
        let now = store.now_ms();
        let matches = |row: &AgentGrant| {
            row.expires_at_ms.is_none()
                && matches!(&row.holder, GrantHolder::Head { agent_id } if agent_id == grantee)
                && row.subject == GrantSubject::App(bundle.into())
        };
        let rows = match store.live_rows(None, now) {
            Ok(rows) => rows,
            Err(_) => {
                return serde_json::json!({"outcome":"store_unavailable","reason":"grant_store_unreadable","remedy":"repair or remove the grant store file, then restart the module"})
            }
        };
        let count = rows.iter().filter(|row| matches(row)).count();
        if count == 0 {
            return serde_json::json!({"outcome":"grant_not_found"});
        }
        if dry_run {
            return serde_json::json!({"outcome":"would_revoke","records":count});
        }
        match store.revoke_matching(now, matches) {
            Ok(ids) => serde_json::json!({"outcome":"revoked","records":ids.len()}),
            Err(_) => {
                serde_json::json!({"outcome":"revoke_failed","reason":"grant_store_write_failed","remedy":"the grant is still in force; check the data directory is writable and retry"})
            }
        }
    }
}

#[cfg(test)]
impl ComputerGrants {
    /// Retain an already-held permission only when an action will use it.
    /// Unlike `require`, this never asks a question when authority is absent.
    pub(crate) fn retain_held(&self, caller: &super::GrantCaller, need: &super::GrantNeed) -> bool {
        self.authorizing_row(caller, need).is_some_and(|used| {
            crate::grant_enforcement::track(&used);
            true
        })
    }
}
