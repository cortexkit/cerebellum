use std::path::Path;
use std::sync::Arc;

use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::browser_standing_grants::{
    FilesystemStandingGrantStorage, StandingGrantStorage, StandingSubject,
    STANDING_GRANT_STORE_FILE,
};
use crate::computer_grants::{
    FilesystemGrantStorage, GrantStorage, GRANT_STORE_FILE, GRANT_STORE_VERSION,
};

use super::{
    hex, AgentGrant, AgentGrantStoreError, AgentGrantStoreState, BrowserTarget, GrantHolder,
    GrantSubject,
};

/// Used only when the agent store is absent. Implementations must not save any
/// legacy file: the projection and the first mutation share one durable write.
pub trait LegacyGrantSource: Send + Sync {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError>;
}

pub struct LegacyGrantStores {
    pub browser: Arc<dyn StandingGrantStorage>,
    pub user_browser: Arc<dyn StandingGrantStorage>,
    pub apps: Arc<dyn GrantStorage>,
}

impl LegacyGrantStores {
    pub fn beside(agent_store: &Path) -> Self {
        let directory = agent_store.parent().unwrap_or_else(|| Path::new("."));
        Self {
            browser: Arc::new(FilesystemStandingGrantStorage::new(
                directory.join(STANDING_GRANT_STORE_FILE),
            )),
            user_browser: Arc::new(FilesystemStandingGrantStorage::new(
                directory.join("user-browser-standing-grants.json"),
            )),
            apps: Arc::new(FilesystemGrantStorage::new(
                directory.join(GRANT_STORE_FILE),
            )),
        }
    }
}

impl LegacyGrantSource for LegacyGrantStores {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
        let mut state = AgentGrantStoreState::default();
        for (name, storage, target) in [
            ("browser", &self.browser, BrowserTarget::AgentProfile),
            (
                "user_browser",
                &self.user_browser,
                BrowserTarget::UserBrowser,
            ),
        ] {
            let failed = |error: crate::browser_standing_grants::StandingGrantStoreError| {
                AgentGrantStoreError::Legacy {
                    store: name,
                    detail: error.to_string(),
                }
            };
            let legacy = storage.load().map_err(failed)?;
            legacy.check().map_err(failed)?;
            for row in legacy.grants {
                if row.revoked_at_ms.is_some() {
                    continue;
                }
                let subject_key = match &row.subject {
                    StandingSubject::Origin(origin) => origin.as_str(),
                    StandingSubject::Domain(domain) => domain.as_str(),
                    StandingSubject::AllSites => "*",
                };
                let id = deterministic_id(&(
                    "browser",
                    target,
                    &row.consent_ref,
                    subject_key,
                    row.granted_at_ms,
                ));
                let subject = match row.subject {
                    StandingSubject::Origin(origin) => GrantSubject::Origin(origin),
                    StandingSubject::Domain(domain) => GrantSubject::Domain(domain),
                    StandingSubject::AllSites => GrantSubject::AllSites,
                };
                insert(
                    &mut state,
                    AgentGrant {
                        id,
                        holder: GrantHolder::Head {
                            agent_id: row.agent_id,
                        },
                        subject,
                        browser_target: Some(target),
                        machine_uuid: row.machine_uuid,
                        granted_at_ms: row.granted_at_ms,
                        expires_at_ms: row.expires_at_ms,
                        card_ref: Some(row.consent_ref),
                        max_level: row.max_level,
                        hazards: row.hazards,
                        team_id: None,
                        designated_requirement: None,
                    },
                );
            }
        }
        let legacy = self
            .apps
            .load()
            .map_err(|error| AgentGrantStoreError::Legacy {
                store: "apps",
                detail: error.to_string(),
            })?;
        if legacy.version != GRANT_STORE_VERSION {
            return Err(AgentGrantStoreError::Legacy {
                store: "apps",
                detail: format!("unknown version {}", legacy.version),
            });
        }
        for row in legacy.records {
            let id = deterministic_id(&(
                "app",
                &row.agent_project_id,
                &row.bundle_identity,
                &row.machine_uuid,
                row.created_at_ms,
            ));
            insert(
                &mut state,
                AgentGrant {
                    id,
                    holder: GrantHolder::Head {
                        agent_id: row.agent_project_id,
                    },
                    subject: GrantSubject::App(row.bundle_identity),
                    browser_target: None,
                    machine_uuid: row.machine_uuid,
                    granted_at_ms: row.created_at_ms,
                    expires_at_ms: None,
                    // The original app store never recorded a card id. Omitting it
                    // avoids presenting an invented elicitation as provenance.
                    card_ref: None,
                    max_level: 4,
                    hazards: Vec::new(),
                    team_id: row.team_id,
                    designated_requirement: row.designated_requirement,
                },
            );
        }
        state.check()?;
        Ok(state)
    }
}

fn deterministic_id(fields: &impl Serialize) -> String {
    // A structured encoding prevents delimiters inside stored fields from
    // confusing the hash. This same projection is used before and during migration.
    let bytes = serde_json::to_vec(fields).expect("legacy id fields are serializable");
    format!("grt_legacy_{}", hex(&Sha256::digest(bytes)))
}

fn insert(state: &mut AgentGrantStoreState, row: AgentGrant) {
    // The old stores can retain repeated answers. Choose the newest answer for
    // one identity, including its machine, independently of file order.
    if let Some(existing) = state
        .grants
        .iter_mut()
        .find(|existing| existing.same_identity(&row))
    {
        if (row.granted_at_ms, &row.id) > (existing.granted_at_ms, &existing.id) {
            *existing = row;
        }
    } else {
        state.grants.push(row);
    }
}
