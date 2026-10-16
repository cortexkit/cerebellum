//! Existing management responses list and revoke the AgentGrants rows used to
//! authorize actions, without changing their JSON reply fields.

use crate::agent_grants::{
    AgentGrant, AgentGrantStoreError, AgentGrants, BrowserTarget, GrantHolder, GrantSubject,
};
use crate::browser_standing_grants::RevokeTarget;
use serde_json::{json, Value};

fn reason(error: &AgentGrantStoreError) -> &'static str {
    match error {
        AgentGrantStoreError::Unreadable { .. } | AgentGrantStoreError::Legacy { .. } => {
            "standing_grant_store_unreadable"
        }
        AgentGrantStoreError::Corrupt { .. } => "standing_grant_store_corrupt",
        AgentGrantStoreError::UnknownVersion { .. } => "standing_grant_store_version_unknown",
        AgentGrantStoreError::WriteFailed { .. } => "standing_grant_store_write_failed",
        AgentGrantStoreError::NoMachineIdentity => "machine_identity_unavailable",
    }
}

fn describe(row: &AgentGrant) -> Value {
    let subject = match &row.subject {
        GrantSubject::Origin(origin) => json!({"origin":origin}),
        GrantSubject::Domain(domain) => json!({"domain":domain}),
        GrantSubject::AllSites => json!({"all_sites":true}),
        _ => unreachable!("only browser rows are listed"),
    };
    json!({"agent_id":row.holder.agent_id(),"subject":subject,"max_level":row.max_level,"hazards":row.hazards,"expires_at_ms":row.expires_at_ms,"granted_at_ms":row.granted_at_ms,"consent_ref":row.card_ref,"revoked_at_ms":null})
}

pub(crate) fn listing(store: &AgentGrants, agent: &str) -> Value {
    match store.live_rows(Some(agent), store.now_ms()) {
        Ok(rows) => {
            json!({"grants":rows.iter().filter(|row| row.browser_target == Some(BrowserTarget::AgentProfile)).map(describe).collect::<Vec<_>>(),"store":{"state":"loaded"}})
        }
        Err(error) => {
            json!({"grants":[],"store":{"state":"unreadable","reason":reason(&error),"detail":error.to_string()}})
        }
    }
}

pub(crate) fn revoke_rows(
    store: &AgentGrants,
    browser_target: BrowserTarget,
    target: &RevokeTarget,
    holder: impl Fn(&GrantHolder) -> bool,
) -> Value {
    if let Some(error) = store.store_error() {
        return json!({"outcome":"store_unavailable","revoked":0,"reason":reason(&error),"remedy":"repair or remove the standing browser grant store file, then restart the module"});
    }
    let result = store.revoke_matching(store.now_ms(), |row| {
        holder(&row.holder)
            && row.browser_target == Some(browser_target)
            && match target {
                RevokeTarget::Everything => true,
                RevokeTarget::Origin(origin) => row.subject == GrantSubject::Origin(origin.clone()),
                RevokeTarget::Domain(domain) => row.subject == GrantSubject::Domain(domain.clone()),
                RevokeTarget::AllSites => row.subject == GrantSubject::AllSites,
            }
    });
    match result {
        Ok(ids) => {
            json!({"outcome":if ids.is_empty() {"nothing_to_revoke"} else {"revoked"},"revoked":ids.len()})
        }
        Err(error) => {
            json!({"outcome":"revoke_failed","revoked":0,"reason":reason(&error),"remedy":"the access is still in force; check the data directory is writable and retry"})
        }
    }
}
