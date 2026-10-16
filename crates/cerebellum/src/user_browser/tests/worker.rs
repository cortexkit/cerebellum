//! A worker's site approvals store thirty-minute permissions usable only by that worker.

use super::*;

fn worker_fixture() -> Fixture {
    let fixture = Fixture::new();
    crate::permission_scope::test_support::describe(
        &fixture.planes,
        crate::permission_scope::test_support::live_head(),
    );
    let mut facts = fixture.planes.routes.get(1, 1).unwrap();
    let mut stamp = crate::cingulate_client::worker_vectors::worker_stamp();
    stamp.attributes.agent_id = Some("test-project".into());
    facts = facts.with_scope(Some(stamp));
    fixture.planes.routes.insert(1, 1, facts);
    fixture
}

#[tokio::test]
async fn worker_user_site_card_grants_thirty_minutes_but_never_offers_or_applies_always() {
    for (choice, expected) in [
        ("allow_30m", "ok"),
        ("allow_origin_always", "unrecognized_answer"),
    ] {
        let fixture = worker_fixture();
        let tab = fixture.claim(1).await;
        let (reply, cards) = fixture.snapshot(1, &tab, choice).await;
        assert_eq!(cards.len(), 1);
        assert_eq!(
            cards[0]["options"]
                .as_array()
                .unwrap()
                .iter()
                .map(|option| option["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["allow_30m", "deny"]
        );
        let key = if choice == "allow_30m" {
            "outcome"
        } else {
            "reason"
        };
        assert_eq!(reply[key], expected, "{reply}");
        assert!(fixture
            .planes
            .user_browser
            .target()
            .grants
            .live_rows("test-project")
            .is_empty());
        let (reply, cards) = fixture.snapshot(1, &tab, "deny").await;
        if choice == "allow_30m" {
            assert!(
                cards.is_empty(),
                "the worker's temporary row should be reused"
            );
            assert_eq!(reply["outcome"], "ok");
        } else {
            assert_eq!(cards.len(), 1);
            assert_eq!(reply["reason"], "consent_declined");
        }
    }
}

#[tokio::test]
async fn worker_user_site_never_borrows_the_heads_standing_grant() {
    let fixture = worker_fixture();
    let head_tab = fixture.claim(2).await;
    let (reply, _) = fixture.snapshot(2, &head_tab, "allow_origin_always").await;
    assert_eq!(reply["outcome"], "ok", "{reply}");
    assert_eq!(
        fixture
            .planes
            .management
            .agent_grants()
            .live_rows(
                Some("test-project"),
                fixture.planes.management.agent_grants().now_ms()
            )
            .unwrap()
            .len(),
        1
    );
    let (closed, _) = fixture
        .call(2, json!({"browser":"user","action":"close"}), "deny")
        .await;
    assert_eq!(closed["outcome"], "closed");
    // The person hands the released tab back to the Agent group for the worker.
    {
        let mut state = fixture.state.lock().unwrap();
        let tab = state.tabs.get_mut("handed").unwrap();
        tab.group = true;
        tab.handed = true;
    }
    let worker_tab = fixture.claim(1).await;
    let (reply, cards) = fixture.snapshot(1, &worker_tab, "deny").await;
    assert_eq!(cards.len(), 1, "the worker must ask despite the head's row");
    assert_eq!(reply["reason"], "consent_declined", "{reply}");
}
