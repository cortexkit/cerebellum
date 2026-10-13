//! Managed website cards under a stamped worker scope, through real dispatch.

use super::*;

fn worker(conversation: &str) -> Session<'_> {
    Session {
        kind: "subagent",
        ..Session::primary(conversation, AGENT).asking()
    }
}

#[tokio::test]
async fn worker_website_card_grants_only_the_worker_conversation() {
    let mut fixture = Fixture::new();
    let route = fixture.route(worker("worker-granted")).await;
    let mut offered = Vec::new();
    let reply = fixture
        .call_answering(
            &route,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 3),
            json!({"decision":"allow_conversation"}),
            |card| offered.push(option_ids(card)),
        )
        .await;
    assert_authorized(&reply, "worker conversation answer");
    assert_eq!(offered, [vec!["allow_conversation", "deny"]]);
    assert_eq!(fixture.planes.management.browser_grant_count().await, 1);
    assert!(fixture.store.live_rows(AGENT).is_empty());

    let head = fixture
        .route(Session::primary("head-without-grant", AGENT).asking())
        .await;
    let mut head_cards = 0;
    let reply = fixture
        .call_answering(
            &head,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 3),
            json!({"decision":"deny"}),
            |_| head_cards += 1,
        )
        .await;
    assert_refused(&reply, "the head cannot borrow the worker grant");
    assert_eq!(head_cards, 1);

    // A head's standing row must not authorize a new worker either.
    fixture.seed(AGENT, StandingSubject::AllSites, 3, &[]);
    let standing_head = fixture
        .route(Session::primary("head-standing", AGENT).asking())
        .await;
    let mut standing_head_cards = 0;
    let reply = fixture
        .call_answering(
            &standing_head,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 3),
            json!({"decision":"deny"}),
            |_| standing_head_cards += 1,
        )
        .await;
    assert_authorized(&reply, "the head can use its standing row");
    assert_eq!(standing_head_cards, 0);
    let other = fixture.route(worker("worker-without-grant")).await;
    let mut worker_cards = 0;
    let reply = fixture
        .call_answering(
            &other,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 3),
            json!({"decision":"deny"}),
            |_| worker_cards += 1,
        )
        .await;
    assert_refused(&reply, "the worker cannot borrow the head grant");
    assert_eq!(worker_cards, 1);
}

#[tokio::test]
async fn worker_website_cards_never_offer_or_apply_standing_or_all_sites() {
    for in_advance in [false, true] {
        for id in [
            "allow_origin_always",
            "allow_all_sites_10m",
            "allow_all_sites_always",
        ] {
            let mut fixture = Fixture::new();
            let route = fixture.route(worker("worker-unknown-choice")).await;
            let (name, arguments) = if in_advance {
                (
                    "browser_use",
                    json!({"action":"open_grant","origins":[PUBLIC],"hazards":[]}),
                )
            } else {
                ("browser.navigate", navigation(&format!("{PUBLIC}/"), 3))
            };
            let mut offered = Vec::new();
            let reply = fixture
                .call_answering(&route, name, arguments, json!({"decision":id}), |card| {
                    offered.push(option_ids(card))
                })
                .await;
            assert_eq!(
                offered,
                [vec!["allow_conversation", "deny"]],
                "{id}, advance={in_advance}"
            );
            if !in_advance {
                assert_refused(&reply, id);
                assert_eq!(
                    reply["detail"]["decision"], "unrecognized_answer",
                    "{reply}"
                );
            }
            assert_eq!(
                fixture.planes.management.browser_grant_count().await,
                0,
                "{id}"
            );
            assert!(fixture.store.live_rows(AGENT).is_empty(), "{id}");
        }
    }
}
