//! A worker may receive temporary rows, but a permanent choice is never offered.

use crate::agent_grants::GrantHolder;
use crate::authorization::{HazardClass, Severity};
use crate::management::{offered_browser_grant_choices, BrowserGrantChoice};
use std::collections::BTreeSet;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GrantCardRefusal {
    NoGrantHolder,
    GrantStoreUnavailable,
}

impl GrantCardRefusal {
    pub(crate) fn reason(&self) -> &'static str {
        match self {
            Self::NoGrantHolder => "no_grant_holder",
            Self::GrantStoreUnavailable => "grant_store_unavailable",
        }
    }

    pub(crate) fn remedy(&self) -> &'static str {
        match self {
            Self::NoGrantHolder => {
                "call from an admitted agent head or worker that can hold the permission"
            }
            Self::GrantStoreUnavailable => {
                "restore the grant store and machine identity before asking for permission"
            }
        }
    }

    pub(crate) fn apply_to_reply(&self, reply: &mut serde_json::Value) {
        reply["outcome"] = serde_json::json!("consent_unavailable");
        reply.as_object_mut().unwrap().remove("ask_id");
        reply["detail"]["reason"] = serde_json::json!(self.reason());
        reply["remedy"] = serde_json::json!(self.remedy());
    }
}

/// A decline-only card gives the person no way to approve the call. Check the
/// rendered options so filtering cannot silently remove the last grant choice.
/// One-call choices remain useful even without a holder or a recording store.
pub(crate) fn require_grant_choice(
    body: &serde_json::Value,
    holder: Option<&GrantHolder>,
) -> Result<(), GrantCardRefusal> {
    if body["params"]["options"]
        .as_array()
        .is_some_and(|options| options.iter().any(|option| option["effect"] == "grant"))
    {
        return Ok(());
    }
    if holder.is_none() {
        return Err(GrantCardRefusal::NoGrantHolder);
    }
    Err(GrantCardRefusal::GrantStoreUnavailable)
}

pub(crate) fn browser_choices(
    origins: &[String],
    hazards: &BTreeSet<HazardClass>,
    severity: Severity,
    holder: Option<&GrantHolder>,
    can_record: bool,
) -> Vec<BrowserGrantChoice> {
    let mut choices =
        offered_browser_grant_choices(origins, hazards, severity, holder.is_some() && can_record);
    if !matches!(holder, Some(GrantHolder::Head { .. })) {
        choices.retain(|choice| {
            !matches!(
                choice,
                BrowserGrantChoice::OriginAlways | BrowserGrantChoice::AllSitesAlways
            )
        });
    }
    choices
}

/// The person's Chrome contains real logins; it is never offered an all-sites grant.
pub(crate) fn user_browser_choices(
    origins: &[String],
    hazards: &BTreeSet<HazardClass>,
    severity: Severity,
    holder: Option<&GrantHolder>,
    can_record: bool,
) -> Vec<BrowserGrantChoice> {
    browser_choices(origins, hazards, severity, holder, can_record)
        .into_iter()
        .filter(|choice| {
            matches!(
                choice,
                BrowserGrantChoice::SiteThirtyMinutes | BrowserGrantChoice::OriginAlways
            )
        })
        .collect()
}
