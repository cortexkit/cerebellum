//! A dispatch retains the row it selected, not merely permission to look up
//! another covering row. Revocation must stop that work even when a broader
//! grant could have admitted a new dispatch.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::authorization::{HazardClass, Severity};
use crate::browser_standing_grants::{
    domain_covers, origin_is_public, WallClock, MAX_ALL_SITES_LEVEL,
};
use crate::computer_grants::{AppCode, GrantNeed};

use super::{
    lock, AgentGrant, AgentGrantStoreError, AgentGrantStoreState, AgentGrants, BrowserTarget,
    GrantHolder, GrantSubject, InMemoryAgentGrantStorage, LegacyGrantSource,
};

#[derive(Clone)]
pub enum GrantDemand {
    Browser {
        target: BrowserTarget,
        origin: String,
        severity: Severity,
        hazards: BTreeSet<HazardClass>,
    },
    App {
        bundle: String,
        code: Arc<dyn AppCode>,
    },
    Takeover,
}

impl GrantDemand {
    pub fn computer(need: &GrantNeed) -> Self {
        match need {
            GrantNeed::App {
                bundle_identity,
                code,
                ..
            } => Self::App {
                bundle: bundle_identity.clone(),
                code: Arc::clone(code),
            },
            GrantNeed::Takeover => Self::Takeover,
        }
    }

    pub(crate) fn covers(&self, row: &AgentGrant) -> bool {
        match self {
            Self::Browser {
                target,
                origin,
                severity,
                hazards,
            } => {
                if row.browser_target != Some(*target)
                    || !Severity::new(
                        row.max_level,
                        row.hazards.contains(&HazardClass::CredentialFormSubmit),
                        row.hazards.contains(&HazardClass::FinancialFormSubmit),
                    )
                    .covers(*severity)
                    || !hazards.iter().all(|hazard| row.hazards.contains(hazard))
                {
                    return false;
                }
                match &row.subject {
                    GrantSubject::Origin(granted) => granted == origin,
                    GrantSubject::Domain(domain) => domain_covers(domain, origin),
                    GrantSubject::AllSites => {
                        hazards.is_empty()
                            && !severity.credential
                            && !severity.financial
                            && row.max_level <= MAX_ALL_SITES_LEVEL
                            && origin_is_public(origin)
                    }
                    _ => false,
                }
            }
            Self::App { bundle, code } => {
                row.browser_target.is_none()
                    && match &row.subject {
                        GrantSubject::WholeComputer => true,
                        GrantSubject::App(granted) => {
                            granted == bundle
                                && row.designated_requirement.as_deref().is_some_and(
                                    |requirement| code.satisfies(requirement).unwrap_or(false),
                                )
                        }
                        _ => false,
                    }
            }
            Self::Takeover => {
                row.browser_target.is_none() && row.subject == GrantSubject::WholeComputer
            }
        }
    }
}

/// Owned by the admitted action and rechecked at its commit boundary. An
/// in-place replacement is checked against the original demand, not its old
/// tier/hazard fields and not a freshly selected substitute row.
#[derive(Clone)]
pub struct GrantUse {
    inner: Arc<GrantUseState>,
}

struct GrantUseState {
    store: Arc<AgentGrants>,
    row: AgentGrant,
    demand: GrantDemand,
}

impl PartialEq for GrantUse {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner.store, &other.inner.store)
            && self.inner.row == other.inner.row
            && match (&self.inner.demand, &other.inner.demand) {
                (
                    GrantDemand::Browser {
                        target: a,
                        origin: b,
                        severity: c,
                        hazards: d,
                    },
                    GrantDemand::Browser {
                        target: e,
                        origin: f,
                        severity: g,
                        hazards: h,
                    },
                ) => (a, b, c, d) == (e, f, g, h),
                (
                    GrantDemand::App { bundle: a, code: b },
                    GrantDemand::App { bundle: c, code: d },
                ) => a == c && Arc::ptr_eq(b, d),
                (GrantDemand::Takeover, GrantDemand::Takeover) => true,
                _ => false,
            }
    }
}
impl Eq for GrantUse {}

impl std::fmt::Debug for GrantUse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrantUse")
            .field("id", &self.inner.row.id)
            .finish_non_exhaustive()
    }
}

impl GrantUse {
    pub fn row(&self) -> &AgentGrant {
        &self.inner.row
    }

    pub fn is_live(&self) -> bool {
        loop {
            let current = lock(&self.inner.store.state)
                .as_ref()
                .ok()
                .and_then(|state| {
                    state
                        .grants
                        .iter()
                        .find(|row| {
                            row.id == self.inner.row.id
                                && row.holder == self.inner.row.holder
                                && row.is_usable(
                                    self.inner.store.now_ms(),
                                    self.inner.store.machine_uuid.as_deref(),
                                )
                        })
                        .cloned()
                });
            let Some(current) = current else {
                return false;
            };
            // Signature verification may read the process. Do not hold the
            // store lock across that work; then confirm the row did not change.
            if !self.inner.demand.covers(&current) {
                return false;
            }
            let state = lock(&self.inner.store.state);
            let Ok(state) = state.as_ref() else {
                return false;
            };
            if state.grants.iter().any(|row| row == &current) {
                return current.is_usable(
                    self.inner.store.now_ms(),
                    self.inner.store.machine_uuid.as_deref(),
                );
            }
        }
    }

    pub(crate) async fn invalidated(&self) {
        let mut changed = self.inner.store.changed.subscribe();
        let mut clock_changed = self.inner.store.clock.subscribe();
        loop {
            if !self.is_live() {
                return;
            }
            // The deadline is recomputed from wall time after each wake, so
            // clock adjustments cannot extend the row. The short recheck also
            // observes injected clocks that have no asynchronous notifier.
            let expires = lock(&self.inner.store.state)
                .as_ref()
                .ok()
                .and_then(|state| {
                    state
                        .grants
                        .iter()
                        .find(|row| {
                            row.id == self.inner.row.id && row.holder == self.inner.row.holder
                        })
                        .and_then(|row| row.expires_at_ms)
                });
            let remaining =
                expires.map_or(1000, |end| end.saturating_sub(self.inner.store.now_ms()));
            tokio::select! {
                _ = changed.changed() => {},
                _ = async { match clock_changed.as_mut() { Some(clock) => { let _ = clock.changed().await; }, None => std::future::pending().await } } => {},
                _ = tokio::time::sleep(std::time::Duration::from_millis(remaining.clamp(1, 1000))) => {},
            }
        }
    }

    pub(crate) fn register(&self, call: &Arc<crate::grant_enforcement::CallGrants>) {
        let mut active = lock(&self.inner.store.active);
        active.retain(|call| call.strong_count() > 0);
        if !active
            .iter()
            .any(|existing| existing.ptr_eq(&Arc::downgrade(call)))
        {
            active.push(Arc::downgrade(call));
        }
    }
}

struct EmptyLegacy;
impl LegacyGrantSource for EmptyLegacy {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
        Ok(AgentGrantStoreState::default())
    }
}

impl AgentGrants {
    pub fn unavailable(error: AgentGrantStoreError) -> Self {
        let store = Self::in_memory(None);
        *lock(&store.state) = Err(error);
        store
    }
    pub fn in_memory(machine_uuid: Option<String>) -> Self {
        Self::open(
            Arc::new(InMemoryAgentGrantStorage::default()),
            &EmptyLegacy,
            machine_uuid,
        )
    }

    pub fn with_clock(mut self, clock: Arc<dyn WallClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    pub fn machine_uuid(&self) -> Option<&str> {
        self.machine_uuid.as_deref()
    }

    pub fn can_record(&self) -> bool {
        self.machine_uuid.is_some() && self.store_error().is_none()
    }

    pub fn is_in_use(&self, id: &str) -> bool {
        lock(&self.active)
            .iter()
            .filter_map(std::sync::Weak::upgrade)
            .any(|call| call.uses_row(id))
    }

    pub fn authorize(
        self: &Arc<Self>,
        holder: &GrantHolder,
        demand: GrantDemand,
    ) -> Option<GrantUse> {
        let rows = self
            .live_rows(Some(holder.agent_id()), self.now_ms())
            .ok()?;
        let row = rows
            .into_iter()
            .filter(|row| {
                row.holder == *holder
                    && row.is_usable(self.now_ms(), self.machine_uuid.as_deref())
                    && demand.covers(row)
            })
            .max_by(|left, right| {
                specificity(&left.subject)
                    .cmp(&specificity(&right.subject))
                    .then_with(|| right.id.cmp(&left.id))
            })?;
        Some(GrantUse {
            inner: Arc::new(GrantUseState {
                store: Arc::clone(self),
                row,
                demand,
            }),
        })
    }
}

impl std::fmt::Debug for AgentGrants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentGrants")
            .field("machine_uuid", &self.machine_uuid)
            .finish_non_exhaustive()
    }
}

fn specificity(subject: &GrantSubject) -> (u8, usize) {
    match subject {
        GrantSubject::App(_) | GrantSubject::Origin(_) => (2, 0),
        GrantSubject::Domain(domain) => (1, domain.len()),
        GrantSubject::WholeComputer | GrantSubject::AllSites => (0, 0),
    }
}
