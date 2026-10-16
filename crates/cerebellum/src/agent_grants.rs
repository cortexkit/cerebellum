//! Agent-owned grants and their read-only legacy projection.
//!
//! Opening or listing never writes. The first mutation saves the entire legacy
//! projection and its change atomically; the presence of that file is the migration
//! marker, even when it contains no rows. Legacy files are then ignored.

mod enforcement;
mod legacy;
mod storage;
pub use enforcement::{GrantDemand, GrantUse};
#[cfg(test)]
mod enforcement_tests;
#[cfg(test)]
mod tests;

pub use legacy::{LegacyGrantSource, LegacyGrantStores};
pub use storage::{AgentGrantStorage, FilesystemAgentGrantStorage, InMemoryAgentGrantStorage};

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use cerebellum_core::format_floor::DurableFormat;
use serde::{Deserialize, Serialize};

use crate::authorization::HazardClass;
use crate::browser_standing_grants::{StandingBrowserGrant, StandingSubject};

pub const AGENT_GRANT_STORE_FILE: &str = "agent-grants.json";
pub const AGENT_GRANT_STORE_FORMAT: DurableFormat = DurableFormat::new("agent-grants", 1);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum GrantHolder {
    Head { agent_id: String },
    Worker { agent_id: String, scope_ref: String },
}

impl GrantHolder {
    pub fn agent_id(&self) -> &str {
        match self {
            Self::Head { agent_id } | Self::Worker { agent_id, .. } => agent_id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserTarget {
    AgentProfile,
    UserBrowser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum GrantSubject {
    App(String),
    WholeComputer,
    Origin(String),
    Domain(String),
    AllSites,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGrant {
    pub id: String,
    pub holder: GrantHolder,
    pub subject: GrantSubject,
    pub browser_target: Option<BrowserTarget>,
    pub machine_uuid: String,
    pub granted_at_ms: u64,
    pub expires_at_ms: Option<u64>,
    // Legacy app records have no elicitation reference; permissions/v1 makes it optional.
    pub card_ref: Option<String>,
    pub max_level: u8,
    pub hazards: Vec<HazardClass>,
    pub team_id: Option<String>,
    pub designated_requirement: Option<String>,
}

impl AgentGrant {
    pub fn is_live(&self, now_ms: u64, machine_uuid: Option<&str>) -> bool {
        machine_uuid == Some(self.machine_uuid.as_str()) && self.unexpired(now_ms)
    }

    /// App authority must still be checked against this requirement by the
    /// dispatcher. Old records without it can be inventoried but grant nothing.
    pub fn is_usable(&self, now_ms: u64, machine_uuid: Option<&str>) -> bool {
        self.is_live(now_ms, machine_uuid)
            && (!matches!(self.subject, GrantSubject::App(_))
                || self
                    .designated_requirement
                    .as_ref()
                    .is_some_and(|requirement| !requirement.trim().is_empty()))
    }

    fn unexpired(&self, now_ms: u64) -> bool {
        self.expires_at_ms.is_none_or(|expires| now_ms < expires)
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.holder == other.holder
            && self.subject == other.subject
            && self.browser_target == other.browser_target
            && self.machine_uuid == other.machine_uuid
    }

    fn check(&self) -> Result<(), AgentGrantStoreError> {
        let corrupt = |detail: &str| AgentGrantStoreError::Corrupt {
            detail: detail.into(),
        };
        if self.id.is_empty() || self.holder.agent_id().is_empty() || self.machine_uuid.is_empty() {
            return Err(corrupt("a row needs an id, holder and machine identity"));
        }
        if let GrantHolder::Worker { scope_ref, .. } = &self.holder {
            if scope_ref.is_empty()
                || self.expires_at_ms.is_none_or(|expires| {
                    expires <= self.granted_at_ms || expires - self.granted_at_ms > 30 * 60 * 1000
                })
            {
                return Err(corrupt(
                    "worker grants require a scope and at most thirty minutes",
                ));
            }
        }
        let browser_subject = match &self.subject {
            GrantSubject::Origin(origin) => Some(StandingSubject::Origin(origin.clone())),
            GrantSubject::Domain(domain) => Some(StandingSubject::Domain(domain.clone())),
            GrantSubject::AllSites => Some(StandingSubject::AllSites),
            _ => None,
        };
        if browser_subject.is_some() != self.browser_target.is_some() {
            return Err(corrupt("only browser grants carry a browser target"));
        }
        if let Some(subject) = browser_subject {
            StandingBrowserGrant {
                agent_id: self.holder.agent_id().into(),
                subject,
                max_level: self.max_level,
                hazards: self.hazards.clone(),
                expires_at_ms: self.expires_at_ms,
                granted_at_ms: self.granted_at_ms,
                consent_ref: self.card_ref.clone().unwrap_or_else(|| self.id.clone()),
                revoked_at_ms: None,
                machine_uuid: self.machine_uuid.clone(),
            }
            .check()
            .map_err(|detail| AgentGrantStoreError::Corrupt { detail })?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentGrantStoreState {
    pub version: u64,
    pub grants: Vec<AgentGrant>,
}

impl Default for AgentGrantStoreState {
    fn default() -> Self {
        Self {
            version: AGENT_GRANT_STORE_FORMAT.version,
            grants: Vec::new(),
        }
    }
}

impl AgentGrantStoreState {
    fn check(&self) -> Result<(), AgentGrantStoreError> {
        if self.version != AGENT_GRANT_STORE_FORMAT.version {
            return Err(AgentGrantStoreError::UnknownVersion {
                found: self.version,
            });
        }
        let mut ids = BTreeSet::new();
        for (index, row) in self.grants.iter().enumerate() {
            row.check()?;
            // Copies from different machines can share a legacy card key. Their
            // rows are inert here, so only duplicate ids on one machine collide.
            if !ids.insert((&row.id, &row.machine_uuid))
                || self.grants[..index]
                    .iter()
                    .any(|other| row.same_identity(other))
            {
                return Err(AgentGrantStoreError::Corrupt {
                    detail: "duplicate grant id or identity".into(),
                });
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentGrantStoreError {
    Unreadable { detail: String },
    Corrupt { detail: String },
    UnknownVersion { found: u64 },
    Legacy { store: &'static str, detail: String },
    WriteFailed { detail: String },
    NoMachineIdentity,
}

impl std::fmt::Display for AgentGrantStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}
impl std::error::Error for AgentGrantStoreError {}

pub struct AgentGrants {
    storage: Arc<dyn AgentGrantStorage>,
    machine_uuid: Option<String>,
    state: Mutex<Result<AgentGrantStoreState, AgentGrantStoreError>>,
    clock: Arc<dyn crate::browser_standing_grants::WallClock>,
    changed: tokio::sync::watch::Sender<u64>,
    active: Mutex<Vec<std::sync::Weak<crate::grant_enforcement::CallGrants>>>,
}

impl AgentGrants {
    pub fn open(
        storage: Arc<dyn AgentGrantStorage>,
        legacy: &dyn LegacyGrantSource,
        machine_uuid: Option<String>,
    ) -> Self {
        let state = storage
            .load()
            .and_then(|state| match state {
                Some(state) => Ok(state),
                None => legacy.load(),
            })
            .and_then(|state| {
                state.check()?;
                Ok(state)
            });
        Self {
            storage,
            machine_uuid,
            state: Mutex::new(state),
            clock: Arc::new(crate::browser_standing_grants::SystemWallClock),
            changed: tokio::sync::watch::channel(0).0,
            active: Mutex::new(Vec::new()),
        }
    }

    pub fn open_durable(machine_uuid: Option<String>) -> Result<Self, AgentGrantStoreError> {
        let storage = FilesystemAgentGrantStorage::production()?;
        let legacy = LegacyGrantStores::beside(storage.path());
        Ok(Self::open(Arc::new(storage), &legacy, machine_uuid))
    }

    pub fn store_error(&self) -> Option<AgentGrantStoreError> {
        lock(&self.state).as_ref().err().cloned()
    }

    pub fn live_rows(
        &self,
        agent_id: Option<&str>,
        now_ms: u64,
    ) -> Result<Vec<AgentGrant>, AgentGrantStoreError> {
        let state = lock(&self.state);
        let state = state.as_ref().map_err(Clone::clone)?;
        Ok(state
            .grants
            .iter()
            .filter(|row| {
                row.is_live(now_ms, self.machine_uuid.as_deref())
                    && agent_id.is_none_or(|agent| agent == row.holder.agent_id())
            })
            .cloned()
            .collect())
    }

    /// Called only after a granting answer has been validated by the dispatcher.
    /// Replacement keeps the id even if the previous lifetime already expired.
    pub fn upsert(&self, mut row: AgentGrant, now_ms: u64) -> Result<String, AgentGrantStoreError> {
        if self.machine_uuid.as_deref() != Some(row.machine_uuid.as_str()) {
            return Err(AgentGrantStoreError::NoMachineIdentity);
        }
        self.mutate(now_ms, |state| {
            if let Some(existing) = state
                .grants
                .iter_mut()
                .find(|existing| existing.same_identity(&row))
            {
                row.id = existing.id.clone();
                row.check()?;
                *existing = row.clone();
            } else {
                let mut bytes = [0u8; 16];
                getrandom::getrandom(&mut bytes).map_err(|error| {
                    AgentGrantStoreError::WriteFailed {
                        detail: error.to_string(),
                    }
                })?;
                row.id = format!("grt_{}", hex(&bytes));
                row.check()?;
                state.grants.push(row.clone());
            }
            Ok(row.id)
        })
    }

    pub fn revoke(&self, id: &str, now_ms: u64) -> Result<bool, AgentGrantStoreError> {
        self.revoke_matching(now_ms, |row| row.id == id)
            .map(|ids| !ids.is_empty())
    }

    pub fn revoke_matching(
        &self,
        now_ms: u64,
        matches: impl Fn(&AgentGrant) -> bool,
    ) -> Result<Vec<String>, AgentGrantStoreError> {
        self.mutate(now_ms, |state| {
            let mut removed = Vec::new();
            state.grants.retain(|row| {
                if row.is_live(now_ms, self.machine_uuid.as_deref()) && matches(row) {
                    removed.push(row.id.clone());
                    false
                } else {
                    true
                }
            });
            Ok(removed)
        })
    }

    fn mutate<T>(
        &self,
        now_ms: u64,
        apply: impl FnOnce(&mut AgentGrantStoreState) -> Result<T, AgentGrantStoreError>,
    ) -> Result<T, AgentGrantStoreError> {
        let mut state = lock(&self.state);
        let mut next = state.as_ref().map_err(Clone::clone)?.clone();
        let result = apply(&mut next)?;
        next.grants.retain(|row| row.unexpired(now_ms));
        next.check()?;
        // Publish only after the durable write succeeds, so a failed mutation
        // neither changes enforcement nor marks a legacy projection migrated.
        self.storage.save(&next)?;
        *state = Ok(next);
        self.changed
            .send_modify(|version| *version = version.wrapping_add(1));
        Ok(result)
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
