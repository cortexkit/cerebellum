use super::*;
use crate::agent_grants::{AgentGrant, AgentGrants, BrowserTarget, GrantHolder, GrantSubject};

fn store() -> Arc<AgentGrants> {
    Arc::new(AgentGrants::in_memory(Some("test-machine".into())))
}
fn seed(store: &Arc<AgentGrants>, target: BrowserTarget, subject: GrantSubject) -> String {
    let now = store.now_ms();
    store
        .upsert(
            AgentGrant {
                id: String::new(),
                holder: GrantHolder::Head {
                    agent_id: "test-project".into(),
                },
                subject,
                browser_target: Some(target),
                machine_uuid: "test-machine".into(),
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
        .unwrap()
}

#[tokio::test]
async fn user_browser_dispatch_uses_only_its_target_and_never_the_profile_row() {
    for target in [BrowserTarget::AgentProfile, BrowserTarget::UserBrowser] {
        let store = store();
        seed(
            &store,
            target,
            GrantSubject::Origin("https://example.com".into()),
        );
        let fixture = Fixture::with_agent_grants(None, Some(store));
        let tab = fixture.claim(1).await;
        let (reply, cards) = fixture.call(1, json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/new","intent":"load page","severity":{"tier":3,"credential":false,"financial":false}}), "deny").await;
        if target == BrowserTarget::UserBrowser {
            assert_eq!(reply["outcome"], "ok", "{reply}");
            assert!(cards.is_empty());
        } else {
            assert_ne!(reply["outcome"], "ok", "{reply}");
            assert_eq!(cards.len(), 1);
        }
    }
}

#[tokio::test]
async fn user_browser_retains_the_authorizing_row_and_rechecks_it_before_plan_dispatch() {
    let store = store();
    let selected = seed(
        &store,
        BrowserTarget::UserBrowser,
        GrantSubject::Origin("https://example.com".into()),
    );
    seed(&store, BrowserTarget::UserBrowser, GrantSubject::AllSites);
    let fixture = Fixture::with_agent_grants(None, Some(store.clone()));
    let facts = fixture.planes.routes.get(1, 1).unwrap();
    let context = Context {
        planes: &fixture.planes,
        facts: &facts,
        route: Route {
            channel: 1,
            epoch: 1,
        },
        inbound: Route {
            channel: 1,
            epoch: 1,
        },
        cancel: CancelHandle::pending(),
        connection: fixture.epoch,
        action: "navigate",
    };
    let severity = Severity::new(3, false, false);
    crate::grant_enforcement::scope(CancelHandle::pending(), async {
        let grant = context
            .authorize("https://example.com", severity, Default::default())
            .await
            .unwrap();
        assert_eq!(grant.authorizing_row.as_ref().unwrap().row().id, selected);
        assert!(grant.covers("https://example.com", severity, &Default::default()));
        store.revoke(&selected, store.now_ms()).unwrap();
        assert!(!grant.covers("https://example.com", severity, &Default::default()));
        assert!(
            !context.granted(
                "https://example.com",
                severity,
                &Default::default(),
                Some(&grant)
            ),
            "the all-sites row cannot substitute within a dispatch"
        );
        let result = plan(
            &fixture.planes.user_browser,
            Route {
                channel: 1,
                epoch: 1,
            },
            "handed",
            fixture.epoch,
            None,
            &CancelHandle::pending(),
            vec![],
            false,
        )
        .await;
        assert_eq!(result.err().unwrap()["reason"], "grant_revoked");
    })
    .await;
}
