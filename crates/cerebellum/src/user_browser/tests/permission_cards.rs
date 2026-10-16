use super::*;
use crate::agent_grants::{AgentGrants, BrowserTarget};
use crate::browser_standing_grants::ManualWallClock;

fn rows(fixture: &Fixture) -> Vec<crate::agent_grants::AgentGrant> {
    let store = fixture.planes.management.agent_grants();
    store.live_rows(None, store.now_ms()).unwrap()
}

fn ask(tier: u8, hazards: Value, origin: &str) -> Value {
    json!({"browser":"user","action":"open_grant","origins":[origin],"hazards":hazards,"severity_tier":tier})
}

#[tokio::test]
async fn user_site_upgrade_keeps_id_and_temporary_answer_expires_on_the_wall_clock() {
    let clock = Arc::new(ManualWallClock::at(1000));
    let store =
        Arc::new(AgentGrants::in_memory(Some("test-machine".into())).with_clock(clock.clone()));
    let fixture = Fixture::with_agent_grants(None, Some(store));
    let (reply, cards) = fixture
        .call(1, ask(1, json!([]), "https://example.com"), "allow_30m")
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 1);
    let first = rows(&fixture).remove(0);
    assert_eq!(first.expires_at_ms, Some(1_801_000));
    let (reply, cards) = fixture
        .call(
            1,
            ask(3, json!([]), "https://example.com"),
            "allow_origin_always",
        )
        .await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(cards.len(), 1);
    let upgraded = rows(&fixture);
    assert_eq!(upgraded.len(), 1);
    assert_eq!(upgraded[0].id, first.id);
    assert_eq!(upgraded[0].browser_target, Some(BrowserTarget::UserBrowser));
    assert_eq!(upgraded[0].expires_at_ms, None);
    assert_eq!(upgraded[0].max_level, 3);
    // Shorten the upgraded site's lifetime in place; permanent authority must
    // not remain usable after the replacement's expiry.
    let mut replacement = upgraded[0].clone();
    replacement.expires_at_ms = Some(1_801_000);
    fixture
        .planes
        .management
        .agent_grants()
        .upsert(replacement, 1000)
        .unwrap();
    clock.advance_ms(1_800_000);
    let (reply, cards) = fixture
        .call(1, ask(1, json!([]), "https://example.com"), "deny")
        .await;
    assert_eq!(reply["reason"], "consent_declined", "{reply}");
    assert_eq!(cards.len(), 1);
    assert!(rows(&fixture).is_empty());
}

#[tokio::test]
async fn forged_user_browser_all_sites_answers_never_write_a_row() {
    for choice in ["allow_all_sites_30m", "allow_all_sites_always"] {
        let fixture = Fixture::new();
        let (reply, cards) = fixture
            .call(1, ask(3, json!([]), "https://example.com"), choice)
            .await;
        assert_eq!(reply["reason"], "unrecognized_answer", "{reply}");
        assert_eq!(cards.len(), 1);
        assert!(rows(&fixture).is_empty());
        for (origin, hazards) in [
            ("https://example.com", json!(["credential_form_submit"])),
            ("https://example.com", json!(["financial_form_submit"])),
            ("http://localhost", json!([])),
            ("http://10.0.0.5", json!([])),
            ("http://[::1]", json!([])),
        ] {
            let (reply, cards) = fixture.call(1, ask(3, hazards, origin), "deny").await;
            assert_eq!(reply["reason"], "consent_declined", "{origin}: {reply}");
            assert_eq!(cards.len(), 1, "{origin}");
            assert!(!cards[0]["options"]
                .as_array()
                .unwrap()
                .iter()
                .any(|option| option["group"] == "danger"));
        }
    }
}

#[test]
fn user_revoke_matches_only_the_callers_holder_target_and_subject() {
    use crate::agent_grants::{AgentGrant, GrantHolder, GrantSubject};
    let store = AgentGrants::in_memory(Some("test-machine".into()));
    let worker = |scope: &str| GrantHolder::Worker {
        agent_id: "head".into(),
        owner: "reserved:prefrontal-core".into(),
        scope_ref: scope.into(),
        scope_epoch: 1,
    };
    let caller = worker("one");
    for (holder, target, domain) in [
        (caller.clone(), BrowserTarget::UserBrowser, "example.com"),
        (caller.clone(), BrowserTarget::AgentProfile, "example.com"),
        (caller.clone(), BrowserTarget::UserBrowser, "other.example"),
        (worker("two"), BrowserTarget::UserBrowser, "example.com"),
        (
            GrantHolder::Head {
                agent_id: "head".into(),
            },
            BrowserTarget::UserBrowser,
            "example.com",
        ),
    ] {
        store
            .upsert(
                AgentGrant {
                    id: String::new(),
                    holder,
                    subject: GrantSubject::Domain(domain.into()),
                    browser_target: Some(target),
                    machine_uuid: "test-machine".into(),
                    granted_at_ms: store.now_ms(),
                    expires_at_ms: Some(store.now_ms() + 1_800_000),
                    card_ref: Some("card".into()),
                    max_level: 3,
                    hazards: vec![],
                    team_id: None,
                    designated_requirement: None,
                },
                store.now_ms(),
            )
            .unwrap();
    }
    let reply = crate::user_browser::agent_enforcement::revoke_access(
        &store,
        Some(caller.clone()),
        &crate::browser_standing_grants::RevokeTarget::Domain("example.com".into()),
    );
    assert_eq!(reply["revoked"], 1);
    let remaining = store.live_rows(None, store.now_ms()).unwrap();
    assert_eq!(remaining.len(), 4);
    assert!(!remaining.iter().any(|row| row.holder == caller
        && row.browser_target == Some(BrowserTarget::UserBrowser)
        && row.subject == GrantSubject::Domain("example.com".into())));
}

#[tokio::test]
async fn user_browser_writer_rejects_broad_or_worker_permanent_answers() {
    use crate::management::BrowserGrantChoice;
    let fixture = Fixture::new();
    for worker in [false, true] {
        let mut facts = fixture.planes.routes.get(1, 1).unwrap();
        if worker {
            let mut stamp = crate::cingulate_client::worker_vectors::worker_stamp();
            stamp.attributes.agent_id = Some("test-project".into());
            facts = facts.with_scope(Some(stamp));
        }
        let context = Context {
            planes: &fixture.planes,
            facts: &facts,
            route: Route {
                channel: 1,
                epoch: 1,
            },
            cancel: CancelHandle::pending(),
            connection: fixture.epoch,
            action: "open_grant",
        };
        for choice in [
            BrowserGrantChoice::AllSitesThirtyMinutes,
            BrowserGrantChoice::AllSitesAlways,
            BrowserGrantChoice::OriginAlways,
        ] {
            if !worker && choice == BrowserGrantChoice::OriginAlways {
                continue;
            }
            let grant = InvocationGrant {
                authorizing_row: None,
                origin: "https://example.com".into(),
                severity: Severity::new(3, false, false),
                hazards: Default::default(),
                once: false,
            };
            assert_eq!(
                context
                    .record_agent_answer(grant, "card", choice)
                    .err()
                    .unwrap()["reason"],
                "unrecognized_answer"
            );
        }
    }
    assert!(rows(&fixture).is_empty());
}
