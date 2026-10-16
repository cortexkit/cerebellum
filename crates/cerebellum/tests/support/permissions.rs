//! Fixtures keep AgentGrants in memory and bind rows to a known test machine UUID.
//! Actions still use the production holder and browser-target checks.

use cerebellum::agent_grants::{
    AgentGrant, AgentGrantStorage, AgentGrantStoreError, AgentGrantStoreState, AgentGrants,
    BrowserTarget, GrantHolder, GrantSubject, LegacyGrantSource,
};
use cerebellum::authorization::{GrantStore, HazardClass};
use cerebellum::browser_signed_in::SignedInDomains;
use cerebellum::browser_standing_grants::WallClock;
use cerebellum::{BrowserConfig, JournalPersistence, Planes};
use cerebellum_core::health::HealthState;
use std::sync::Arc;

struct EmptyLegacy;
impl LegacyGrantSource for EmptyLegacy {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
        Ok(AgentGrantStoreState::default())
    }
}

pub fn store(
    storage: Arc<dyn AgentGrantStorage>,
    machine: &str,
    clock: Arc<dyn WallClock>,
) -> Arc<AgentGrants> {
    Arc::new(AgentGrants::open(storage, &EmptyLegacy, Some(machine.into())).with_clock(clock))
}

pub fn planes(
    health: Arc<HealthState>,
    config: Option<BrowserConfig>,
    journal: JournalPersistence,
) -> Planes {
    assert_eq!(journal, JournalPersistence::Isolated);
    let signed_in = Arc::new(SignedInDomains::default());
    attach(
        Planes::with_browser_state(
            health,
            config,
            JournalPersistence::Isolated,
            None,
            Some(signed_in.clone()),
        ),
        Arc::new(AgentGrants::in_memory(Some("test-machine".into()))),
        Some(signed_in),
    )
}

pub fn attach(
    mut planes: Planes,
    grants: Arc<AgentGrants>,
    signed_in: Option<Arc<SignedInDomains>>,
) -> Planes {
    let management = Arc::try_unwrap(planes.management)
        .ok()
        .expect("attach permissions before sharing the fixture planes");
    planes.management = Arc::new(management.with_agent_grants(grants.clone()));
    let mut browser_grants = GrantStore::default().with_agent_grants(grants);
    if let Some(signed_in) = signed_in {
        browser_grants = browser_grants.with_public_web_baseline(signed_in);
    }
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .expect("attach permissions before sharing the browser")
            .with_grants_installed(browser_grants),
    );
    planes
}

pub fn rows(grants: &AgentGrants, agent: &str) -> Vec<AgentGrant> {
    grants.live_rows(Some(agent), grants.now_ms()).unwrap()
}

pub fn count(planes: &Planes) -> usize {
    let store = planes.management.agent_grants();
    store.live_rows(None, store.now_ms()).unwrap().len()
}

pub fn seed(
    grants: &AgentGrants,
    agent: &str,
    subject: GrantSubject,
    level: u8,
    hazards: Vec<HazardClass>,
    lifetime_ms: Option<u64>,
    card_ref: &str,
) -> String {
    let now = grants.now_ms();
    grants
        .upsert(
            AgentGrant {
                id: String::new(),
                holder: GrantHolder::Head {
                    agent_id: agent.into(),
                },
                subject,
                browser_target: Some(BrowserTarget::AgentProfile),
                machine_uuid: grants.machine_uuid().unwrap().into(),
                granted_at_ms: now,
                expires_at_ms: lifetime_ms.map(|lifetime| now + lifetime),
                card_ref: Some(card_ref.into()),
                max_level: level,
                hazards,
                team_id: None,
                designated_requirement: None,
            },
            now,
        )
        .unwrap()
}
