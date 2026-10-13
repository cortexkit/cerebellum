//! A worker may ask for one user-browser invocation, never standing site access.

use super::*;

fn worker_fixture() -> Fixture {
    let fixture = Fixture::new();
    let mut facts = fixture.planes.routes.get(1, 1).unwrap();
    facts.scope = Some(crate::cingulate_client::worker_vectors::worker_stamp());
    fixture.planes.routes.insert(1, 1, facts);
    fixture
}

#[tokio::test]
async fn worker_user_site_card_allows_once_but_never_offers_or_applies_always() {
    for (choice, expected) in [
        ("allow_once", "ok"),
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
            ["allow_once", "deny"]
        );
        let key = if choice == "allow_once" {
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
        assert_eq!(
            cards.len(),
            1,
            "a worker approval is not standing authority"
        );
        assert_eq!(reply["reason"], "consent_declined");
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
            .user_browser
            .target()
            .grants
            .live_rows("test-project")
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
