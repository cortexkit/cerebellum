use super::*;
use crate::agent_grants::{
    AgentGrant, AgentGrants, BrowserTarget, GrantDemand, GrantHolder, GrantSubject,
};

#[tokio::test]
async fn browser_dispatch_commit_refuses_a_row_revoked_after_authorization() {
    let store = Arc::new(AgentGrants::in_memory(Some("machine".into())));
    let holder = GrantHolder::Head {
        agent_id: "head".into(),
    };
    let now = store.now_ms();
    let id = store
        .upsert(
            AgentGrant {
                id: String::new(),
                holder: holder.clone(),
                subject: GrantSubject::Origin("https://example.com".into()),
                browser_target: Some(BrowserTarget::AgentProfile),
                machine_uuid: "machine".into(),
                granted_at_ms: now,
                expires_at_ms: Some(now + 1_800_000),
                card_ref: Some("card".into()),
                max_level: 3,
                hazards: vec![],
                team_id: None,
                designated_requirement: None,
            },
            now,
        )
        .unwrap();
    let used = store
        .authorize(
            &holder,
            GrantDemand::Browser {
                target: BrowserTarget::AgentProfile,
                origin: "https://example.com".into(),
                severity: Severity::new(3, false, false),
                hazards: Default::default(),
            },
        )
        .unwrap();
    let plane = BrowserPlane::new();
    let identity = RouteIdentity::from_accepted_bind(
        &subc_protocol::BindIdentity::new("test", "conversation"),
        &Some(subc_protocol::Principal::Direct),
        Some(&serde_json::json!({"agentProjectId": "test-project", "sessionKind": "primary"})),
    );
    crate::grant_enforcement::scope(crate::CancelHandle::pending(), async {
        crate::grant_enforcement::track(&used);
        store.revoke(&id, now).unwrap();
        assert!(matches!(
            plane.commit(&identity, BrowserCapability::Navigate).await,
            Err(BrowserError::AuthorizationDenied {
                reason: "grant_revoked"
            })
        ));
    })
    .await;
}
