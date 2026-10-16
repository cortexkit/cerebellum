//! Choices are frozen on the raised card so an answer cannot broaden its scope.

use super::*;
use crate::agent_grants::{GrantHolder, GrantSubject};
use crate::consent_card::ConsentOption;

impl ComputerGrants {
    pub(crate) fn offered_choices(
        &self,
        caller: &GrantCaller,
        need: &GrantNeed,
        identity: Option<&AppIdentity>,
    ) -> Vec<&'static str> {
        let can_mint = caller.holder.is_some() && self.agent_grants.can_record();
        let head = matches!(caller.holder, Some(GrantHolder::Head { .. }));
        let mut choices = match need {
            GrantNeed::App { .. } if can_mint => vec![ALLOW_30M],
            _ => vec![ALLOW_ONCE],
        };
        if matches!(need, GrantNeed::App { .. }) && self.offers_always(caller, identity) {
            choices.push(ALLOW_ALWAYS);
        }
        if can_mint {
            choices.push(COMPUTER_30M);
            if head {
                choices.push(COMPUTER_ALWAYS);
            }
        }
        choices.push(DENY);
        choices
    }

    pub(super) fn write_card_answer(
        &self,
        open: &AnsweredQuestion,
        choice: &str,
    ) -> Result<(), crate::agent_grants::AgentGrantStoreError> {
        let whole = matches!(choice, COMPUTER_30M | COMPUTER_ALWAYS);
        let always = matches!(choice, ALLOW_ALWAYS | COMPUTER_ALWAYS);
        if whole {
            self.write_agent_answer_for(open, always, true)
        } else {
            self.write_agent_answer(open, always)
        }
    }
}

pub(super) fn render_options(need: &GrantNeed, offered: &[&str]) -> Vec<ConsentOption> {
    let app = match need {
        GrantNeed::App { display_name, .. } => display_name.as_str(),
        GrantNeed::Takeover => "the computer",
    };
    offered
        .iter()
        .filter_map(|id| {
            Some(match *id {
                ALLOW_30M => ConsentOption::grant(*id, format!("Use {app} for 30 minutes")),
                ALLOW_ALWAYS => ConsentOption::grant(*id, format!("Always allow {app}")),
                ALLOW_ONCE => ConsentOption::grant(
                    *id,
                    if matches!(need, GrantNeed::Takeover) {
                        "Allow this takeover once"
                    } else {
                        "Allow this call once"
                    },
                ),
                COMPUTER_30M => ConsentOption::grant(*id, "Use the whole computer for 30 minutes")
                    .with_detail("Covers every app, including taking over your mouse and keyboard.")
                    .danger(),
                COMPUTER_ALWAYS => ConsentOption::grant(*id, "Always allow the whole computer")
                    .with_detail("Covers every app, including taking over your mouse and keyboard.")
                    .danger(),
                _ => return None,
            })
        })
        .collect()
}

pub(super) fn subject(
    open: &AnsweredQuestion,
    whole: bool,
) -> Result<GrantSubject, crate::agent_grants::AgentGrantStoreError> {
    if whole {
        return Ok(GrantSubject::WholeComputer);
    }
    match &open.subject {
        Subject::App {
            bundle_identity, ..
        } => Ok(GrantSubject::App(bundle_identity.clone())),
        Subject::Takeover { .. } => Ok(GrantSubject::WholeComputer),
        Subject::Login { .. } => Err(crate::agent_grants::AgentGrantStoreError::NoMachineIdentity),
    }
}
