use super::*;
use crate::agent_grants::{FilesystemAgentGrantStorage, AGENT_GRANT_STORE_FILE};
use crate::authorization::Severity;
use std::path::PathBuf;

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Self {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "permissions-tests-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct LegacyRow(AgentGrant);
impl LegacyGrantSource for LegacyRow {
    fn load(&self) -> Result<AgentGrantStoreState, AgentGrantStoreError> {
        Ok(AgentGrantStoreState {
            grants: vec![self.0.clone()],
            ..AgentGrantStoreState::default()
        })
    }
}

#[tokio::test]
async fn provider_revoke_survives_restart_and_denies_the_next_browser_or_app_authorization() {
    for (subject, target, demand) in [
        (
            GrantSubject::Origin("https://github.com".into()),
            Some(BrowserTarget::AgentProfile),
            GrantDemand::Browser {
                target: BrowserTarget::AgentProfile,
                origin: "https://github.com".into(),
                severity: Severity::new(2, false, false),
                hazards: Default::default(),
            },
        ),
        (
            GrantSubject::Domain("github.com".into()),
            Some(BrowserTarget::UserBrowser),
            GrantDemand::Browser {
                target: BrowserTarget::UserBrowser,
                origin: "https://github.com".into(),
                severity: Severity::new(2, false, false),
                hazards: Default::default(),
            },
        ),
        (
            GrantSubject::App("example-editor".into()),
            None,
            GrantDemand::App {
                bundle: "example-editor".into(),
                code: Arc::new(crate::computer_grants::SignedByFixtureTeam),
            },
        ),
    ] {
        let scratch = Scratch::new();
        let storage = Arc::new(
            FilesystemAgentGrantStorage::new(scratch.0.join(AGENT_GRANT_STORE_FILE))
                .with_format_floor(cerebellum_core::format_floor::FormatFloor::isolated()),
        );
        let mut grant = row("legacy", head("agent-alf"), subject, None, "card");
        grant.browser_target = target;
        grant.designated_requirement = Some("certificate leaf[subject.OU] = \"FIXTURE001\"".into());
        let legacy = LegacyRow(grant);
        let open = || {
            Arc::new(
                AgentGrants::open(storage.clone(), &legacy, Some(MACHINE.into()))
                    .with_clock(Arc::new(Clock(AtomicU64::new(NOW)))),
            )
        };
        let store = open();
        let (mut planes, _, _, _) = fixture(vec![]);
        planes.management = Arc::new(
            management::ManagementPlane::new(Arc::new(Apps)).with_agent_grants(store.clone()),
        );
        let (_, listed) = call(&planes, aggregator(), LIST, json!({})).await;
        assert_eq!(listed["grants"].as_array().unwrap().len(), 1);
        assert_eq!(listed["grants"][0]["id"], "legacy");
        assert!(
            storage.load().unwrap().is_none(),
            "listing must not migrate"
        );
        assert!(store
            .authorize(&head("agent-alf"), demand.clone())
            .is_some());
        let (ty, revoked) = call(&planes, aggregator(), REVOKE, json!({"id":"legacy"})).await;
        assert_eq!(ty, FrameType::Response);
        assert_eq!(revoked, vector("provider-revoke-revoked")["reply"]);
        assert!(store
            .authorize(&head("agent-alf"), demand.clone())
            .is_none());
        drop(planes);
        drop(store);

        // The legacy source still contains the row. A restart must prefer the
        // durable empty inventory written by revoke instead of resurrecting it.
        let restarted = open();
        assert!(restarted.authorize(&head("agent-alf"), demand).is_none());
        let (mut planes, _, _, _) = fixture(vec![]);
        planes.management =
            Arc::new(management::ManagementPlane::new(Arc::new(Apps)).with_agent_grants(restarted));
        assert_eq!(
            call(&planes, aggregator(), LIST, json!({})).await.1,
            json!({"grants":[]})
        );
        assert_eq!(
            call(&planes, aggregator(), REVOKE, json!({"id":"legacy"}))
                .await
                .1,
            vector("provider-revoke-not-found")["reply"]
        );
    }
}
