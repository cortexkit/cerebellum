//! The person's browser has its own target in the shared store. A granting
//! answer to a UserBrowserSite permission card must never upgrade the row for
//! the same site in the agent's browser profile.

use super::{refusal, Context, InvocationGrant};
use crate::agent_grants::{AgentGrant, BrowserTarget, GrantDemand, GrantHolder, GrantSubject};
use serde_json::Value;

pub(super) fn store_answer(
    store: &crate::agent_grants::AgentGrants,
    intent: &crate::cingulate_client::desk::UserBrowserGrant,
    card_ref: &str,
    choice: crate::management::BrowserGrantChoice,
) -> Result<(), Value> {
    use crate::management::BrowserGrantChoice;
    let always = match choice {
        BrowserGrantChoice::SiteThirtyMinutes => false,
        BrowserGrantChoice::OriginAlways if matches!(intent.holder, GrantHolder::Head { .. }) => {
            true
        }
        _ => return Err(refusal("unrecognized_answer")),
    };
    let subject = if always {
        crate::browser_standing_grants::domain_scope(&intent.origin).map_or_else(
            || GrantSubject::Origin(intent.origin.clone()),
            GrantSubject::Domain,
        )
    } else {
        GrantSubject::Origin(intent.origin.clone())
    };
    let now = store.now_ms();
    store
        .upsert(
            AgentGrant {
                id: String::new(),
                holder: intent.holder.clone(),
                subject,
                browser_target: Some(BrowserTarget::UserBrowser),
                machine_uuid: store
                    .machine_uuid()
                    .ok_or_else(|| refusal("grant_storage_unavailable"))?
                    .into(),
                granted_at_ms: now,
                expires_at_ms: (!always).then_some(now.saturating_add(30 * 60 * 1000)),
                card_ref: Some(card_ref.into()),
                max_level: super::site_grant_tier(intent.severity.tier),
                hazards: intent.hazards.iter().copied().collect(),
                team_id: None,
                designated_requirement: None,
            },
            now,
        )
        .map_err(|_| refusal("grant_storage_unavailable"))?;
    Ok(())
}

pub(super) fn revoke_access(
    store: &crate::agent_grants::AgentGrants,
    holder: Option<GrantHolder>,
    target: &crate::browser_standing_grants::RevokeTarget,
) -> Value {
    let Some(holder) = holder else {
        return serde_json::json!({"outcome":"nothing_to_revoke","revoked":0});
    };
    crate::management::retained_browser_ops::revoke_rows(
        store,
        BrowserTarget::UserBrowser,
        target,
        |row_holder| row_holder == &holder,
    )
}

impl Context<'_> {
    pub(super) fn record_agent_answer(
        &self,
        mut grant: InvocationGrant,
        card_ref: &str,
        choice: crate::management::BrowserGrantChoice,
    ) -> Result<InvocationGrant, Value> {
        let holder = crate::permission_scope::minting_holder(self.facts)
            .ok_or_else(|| refusal("agent_not_attested"))?;
        let store = self.planes.management.agent_grants();
        store_answer(
            store,
            &crate::cingulate_client::desk::UserBrowserGrant {
                holder: holder.clone(),
                origin: grant.origin.clone(),
                severity: grant.severity,
                hazards: grant.hazards.clone(),
            },
            card_ref,
            choice,
        )?;
        let used = store
            .authorize(
                &holder,
                GrantDemand::Browser {
                    target: BrowserTarget::UserBrowser,
                    origin: grant.origin.clone(),
                    severity: grant.severity,
                    hazards: grant.hazards.clone(),
                },
            )
            .ok_or_else(|| refusal("grant_not_recorded"))?;
        crate::grant_enforcement::track(&used);
        grant.authorizing_row = Some(used);
        let _ = self.planes.consent.mark_applied(card_ref);
        Ok(grant)
    }
}
