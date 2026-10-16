use super::*;
use crate::agent_grants::{
    AgentGrant, AgentGrantStorage, AgentGrantStoreState, AgentGrants, GrantHolder, GrantSubject,
    InMemoryAgentGrantStorage, LegacyGrantSource,
};

struct Empty;
impl LegacyGrantSource for Empty {
    fn load(&self) -> Result<AgentGrantStoreState, crate::agent_grants::AgentGrantStoreError> {
        Ok(AgentGrantStoreState::default())
    }
}

#[test]
fn retained_app_operations_use_only_local_permanent_head_app_rows() {
    let backend = Arc::new(InMemoryAgentGrantStorage::default());
    let now = crate::wall_clock_ms();
    let head = |agent: &str| GrantHolder::Head {
        agent_id: agent.into(),
    };
    let row = |id: &str, holder, subject, expires, machine: &str| AgentGrant {
        id: id.into(),
        holder,
        subject,
        browser_target: None,
        machine_uuid: machine.into(),
        granted_at_ms: now,
        expires_at_ms: expires,
        card_ref: Some("card".into()),
        max_level: 4,
        hazards: vec![],
        team_id: None,
        designated_requirement: Some("fixture signer".into()),
    };
    backend
        .save(&AgentGrantStoreState {
            version: crate::agent_grants::AGENT_GRANT_STORE_FORMAT.version,
            grants: vec![
                row(
                    "permanent",
                    head("head-a"),
                    GrantSubject::App("editor".into()),
                    None,
                    "machine",
                ),
                row(
                    "worker",
                    GrantHolder::Worker {
                        agent_id: "head-a".into(),
                        scope_ref: "ref".into(),
                    },
                    GrantSubject::App("editor".into()),
                    Some(now + 1_800_000),
                    "machine",
                ),
                row(
                    "temporary",
                    head("head-a"),
                    GrantSubject::App("temporary-app".into()),
                    Some(now + 1_800_000),
                    "machine",
                ),
                row(
                    "sibling",
                    head("head-b"),
                    GrantSubject::App("editor".into()),
                    None,
                    "machine",
                ),
                row(
                    "whole",
                    head("head-a"),
                    GrantSubject::WholeComputer,
                    None,
                    "machine",
                ),
                row(
                    "foreign",
                    head("head-a"),
                    GrantSubject::App("editor".into()),
                    None,
                    "foreign-machine",
                ),
            ],
        })
        .unwrap();
    let store = Arc::new(AgentGrants::open(
        backend.clone(),
        &Empty,
        Some("machine".into()),
    ));
    let grants = ComputerGrants::in_memory().with_agent_grants(store.clone());
    let describe = |agent| json!({"grantee":agent,"bundle_identity":"editor","created_at_ms":now});
    assert_eq!(
        grants.list()["grants"],
        json!([describe("head-a"), describe("head-b")])
    );
    assert_eq!(grants.list()["other_machine_grants"], json!([]));
    let before = backend.load().unwrap();
    assert_eq!(
        grants.revoke("head-a", "editor", true),
        json!({"outcome":"would_revoke","records":1})
    );
    assert_eq!(
        backend.load().unwrap(),
        before,
        "dry-run wrote the grant store"
    );
    assert_eq!(
        grants.revoke("head-a", "editor", false),
        json!({"outcome":"revoked","records":1})
    );
    let mut remaining: Vec<_> = store
        .live_rows(None, now)
        .unwrap()
        .into_iter()
        .map(|row| row.id)
        .collect();
    remaining.sort();
    assert_eq!(remaining, ["sibling", "temporary", "whole", "worker"]);
    assert_eq!(
        grants.revoke("head-a", "temporary-app", true)["outcome"],
        "grant_not_found"
    );
    assert_eq!(
        grants.revoke("head-a", "temporary-app", false)["outcome"],
        "grant_not_found"
    );
    assert_eq!(grants.list()["grants"], json!([describe("head-b")]));
}

#[tokio::test]
async fn takeover_permission_is_retained_only_when_fronting_will_use_it() {
    for uses_takeover in [false, true] {
        let store = Arc::new(AgentGrants::in_memory(Some("machine".into())));
        let now = store.now_ms();
        let mut whole_id = String::new();
        for subject in [
            GrantSubject::App("editor".into()),
            GrantSubject::WholeComputer,
        ] {
            let is_whole = subject == GrantSubject::WholeComputer;
            let id = store
                .upsert(
                    AgentGrant {
                        id: String::new(),
                        holder: GrantHolder::Head {
                            agent_id: "head".into(),
                        },
                        subject,
                        browser_target: None,
                        machine_uuid: "machine".into(),
                        granted_at_ms: now,
                        expires_at_ms: Some(now + 1_800_000),
                        card_ref: Some("card".into()),
                        max_level: 4,
                        hazards: vec![],
                        team_id: None,
                        designated_requirement: Some(
                            "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                        ),
                    },
                    now,
                )
                .unwrap();
            if is_whole {
                whole_id = id;
            }
        }
        let grants = Arc::new(ComputerGrants::in_memory().with_agent_grants(store.clone()));
        let caller = GrantCaller::new("conversation".into(), "head".into(), true);
        let context = ConsentContext::without_carrier(caller.clone());
        let need = GrantNeed::App {
            bundle_identity: "editor".into(),
            display_name: "Editor".into(),
            code: Arc::new(SignedByFixtureTeam),
        };
        crate::grant_enforcement::scope(CancelHandle::pending(), async {
            let app = grants
                .require(&need, &context, &CancelHandle::pending())
                .await
                .unwrap();
            assert!(grants.holds(&caller, &GrantNeed::Takeover));
            if uses_takeover {
                assert!(grants.retain_held(&caller, &GrantNeed::Takeover));
            }
            store.revoke(&whole_id, now).unwrap();
            assert!(app.commit(), "the authorizing app row remains live");
            assert_eq!(crate::grant_enforcement::commit_current(), !uses_takeover);
            assert!(!grants.retain_held(&caller, &GrantNeed::Takeover));
        })
        .await;
    }
}
