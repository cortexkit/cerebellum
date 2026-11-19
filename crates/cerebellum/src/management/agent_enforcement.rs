//! A site-permission question records the admitted caller that may receive its
//! grant. The original caller or a later session call reading Cingulate's
//! answers must apply the answer to that same holder, not to the later caller.

use super::{
    BrowserGrantChoice, BrowserGrantSettlement, ManagementPlane, PendingBrowserGrant,
    PreparedConsent, Question,
};
use crate::agent_grants::{AgentGrant, BrowserTarget, GrantHolder, GrantSubject};

impl Question {
    pub(crate) fn bind_holder(
        &mut self,
        holder: Option<GrantHolder>,
    ) -> Result<(), crate::permission_cards::GrantCardRefusal> {
        if let PreparedConsent::Browser(pending) = &mut self.prepared {
            pending.holder = holder;
            pending.choices = crate::permission_cards::browser_choices(
                &pending.authorized_origins,
                &pending.disclosed_hazards,
                pending.severity,
                pending.holder.as_ref(),
                pending.can_record,
            );
            self.body = super::browser_grant_question(
                &pending.authorized_origins,
                &pending
                    .disclosed_hazards
                    .iter()
                    .map(|hazard| hazard.as_str().to_string())
                    .collect::<Vec<_>>(),
                pending.severity,
                if self.body["params"]["urgency"] == "normal" {
                    crate::consent_card::Urgency::Normal
                } else {
                    crate::consent_card::Urgency::High
                },
                &pending.choices,
            );
            crate::permission_cards::require_grant_choice(&self.body, pending.holder.as_ref())?;
        }
        Ok(())
    }
}

impl ManagementPlane {
    pub(super) fn record_agent_browser_answer(
        &self,
        pending: &PendingBrowserGrant,
        card_ref: &str,
        choice: BrowserGrantChoice,
    ) -> BrowserGrantSettlement {
        let Some(holder) = pending.holder.clone() else {
            return BrowserGrantSettlement::NotRecorded {
                reason: "agent_not_attested",
            };
        };
        let always = matches!(
            choice,
            BrowserGrantChoice::OriginAlways | BrowserGrantChoice::AllSitesAlways
        );
        if always && matches!(holder, GrantHolder::Worker { .. }) {
            return BrowserGrantSettlement::UnrecognizedAnswer;
        }
        let subjects = match choice {
            BrowserGrantChoice::SiteThirtyMinutes => pending
                .authorized_origins
                .iter()
                .cloned()
                .map(GrantSubject::Origin)
                .collect(),
            BrowserGrantChoice::OriginAlways => pending
                .authorized_origins
                .iter()
                .cloned()
                .map(
                    |origin| match crate::browser_standing_grants::always_subject(origin) {
                        crate::browser_standing_grants::StandingSubject::Origin(origin) => {
                            GrantSubject::Origin(origin)
                        }
                        crate::browser_standing_grants::StandingSubject::Domain(domain) => {
                            GrantSubject::Domain(domain)
                        }
                        crate::browser_standing_grants::StandingSubject::AllSites => {
                            GrantSubject::AllSites
                        }
                    },
                )
                .collect(),
            BrowserGrantChoice::AllSitesThirtyMinutes | BrowserGrantChoice::AllSitesAlways => {
                vec![GrantSubject::AllSites]
            }
        };
        let store = self.agent_grants();
        let Some(machine) = store.machine_uuid() else {
            return BrowserGrantSettlement::NotRecorded {
                reason: "machine_identity_unavailable",
            };
        };
        let now = store.now_ms();
        let window = if always {
            None
        } else {
            match crate::cingulate_client::answer_time::thirty_minute_window(now) {
                Some(window) => Some(window),
                // The answer's 30 minutes ran out before it was applied.
                None => return BrowserGrantSettlement::NotGranted,
            }
        };
        for subject in subjects {
            let hazards = if subject == GrantSubject::AllSites {
                vec![]
            } else {
                pending.disclosed_hazards.iter().copied().collect()
            };
            if store
                .upsert(
                    AgentGrant {
                        id: String::new(),
                        holder: holder.clone(),
                        subject,
                        browser_target: Some(BrowserTarget::AgentProfile),
                        machine_uuid: machine.into(),
                        granted_at_ms: window.map_or(now, |(start, _)| start),
                        expires_at_ms: window.map(|(_, end)| end),
                        card_ref: Some(card_ref.into()),
                        max_level: pending.severity.tier,
                        hazards,
                        team_id: None,
                        designated_requirement: None,
                    },
                    now,
                )
                .is_err()
            {
                return BrowserGrantSettlement::NotRecorded {
                    reason: "grant_storage_unavailable",
                };
            }
        }
        BrowserGrantSettlement::Granted(choice)
    }
}

impl ManagementPlane {
    pub(super) fn agent_browser_answer(
        &self,
        agent: &str,
        origin: &str,
        level: Option<u64>,
        domain: Option<&str>,
    ) -> (&'static str, &'static str) {
        let level = level
            .and_then(|level| u8::try_from(level).ok())
            .unwrap_or(crate::authorization::OBSERVE);
        if crate::authorization::public_web_baseline_covers(
            origin,
            crate::authorization::Severity::new(level, false, false),
            &Default::default(),
        ) && (level == crate::authorization::OBSERVE
            || !self
                .signed_in_domains
                .is_signed_in(agent, "default", origin))
        {
            return ("yes", crate::authorization::PUBLIC_WEB_BASELINE);
        }
        let store = self.agent_grants();
        let Ok(rows) = store.live_rows(Some(agent), store.now_ms()) else {
            return ("would_ask", "browser_standing_grants_unavailable");
        };
        let covers = |required| {
            rows.iter().any(|row| {
                matches!(row.holder, GrantHolder::Head { .. })
                    && row.browser_target == Some(BrowserTarget::AgentProfile)
                    && domain.is_none_or(|domain| {
                        matches!(&row.subject, GrantSubject::Domain(granted) if granted == domain)
                            || row.subject == GrantSubject::AllSites
                    })
                    && crate::agent_grants::GrantDemand::Browser {
                        target: BrowserTarget::AgentProfile,
                        origin: origin.into(),
                        severity: crate::authorization::Severity::new(required, false, false),
                        hazards: Default::default(),
                    }
                    .covers(row)
            })
        };
        if covers(level) {
            ("yes", "standing_grant")
        } else if covers(crate::authorization::OBSERVE) {
            ("would_ask", "level_above_grant")
        } else {
            ("would_ask", "no_standing_grant")
        }
    }
}
