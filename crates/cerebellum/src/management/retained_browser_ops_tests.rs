use super::retained_browser_ops::{listing, revoke_rows};
use crate::agent_grants::{
    AgentGrant, AgentGrantStoreError, AgentGrants, BrowserTarget, GrantHolder, GrantSubject,
};
use crate::browser_standing_grants::RevokeTarget;
use serde_json::json;

#[test]
fn retained_browser_inventory_and_revokes_preserve_holder_target_and_wire_shape() {
    let store = AgentGrants::in_memory(Some("machine-test".into()));
    let head = GrantHolder::Head {
        agent_id: "head".into(),
    };
    let worker = |scope: &str| GrantHolder::Worker {
        agent_id: "head".into(),
        scope_ref: scope.into(),
    };
    let caller = worker("one");
    for (holder, target) in [
        (head.clone(), BrowserTarget::AgentProfile),
        (caller.clone(), BrowserTarget::AgentProfile),
        (worker("two"), BrowserTarget::AgentProfile),
        (head.clone(), BrowserTarget::UserBrowser),
        (
            GrantHolder::Head {
                agent_id: "other".into(),
            },
            BrowserTarget::AgentProfile,
        ),
    ] {
        store
            .upsert(
                AgentGrant {
                    id: String::new(),
                    holder,
                    subject: GrantSubject::Domain("example.com".into()),
                    browser_target: Some(target),
                    machine_uuid: "machine-test".into(),
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
    let listed = listing(&store, "head");
    assert_eq!(listed["store"], json!({"state":"loaded"}));
    assert_eq!(listed["grants"].as_array().unwrap().len(), 3);
    for row in listed["grants"].as_array().unwrap() {
        assert_eq!(
            row.as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            [
                "agent_id",
                "consent_ref",
                "expires_at_ms",
                "granted_at_ms",
                "hazards",
                "max_level",
                "revoked_at_ms",
                "subject"
            ]
        );
        assert_eq!(row["agent_id"], "head");
        assert_eq!(row["subject"], json!({"domain":"example.com"}));
        assert_eq!(row["consent_ref"], "card");
    }
    let own = revoke_rows(
        &store,
        BrowserTarget::AgentProfile,
        &RevokeTarget::Domain("example.com".into()),
        |holder| holder == &caller,
    );
    assert_eq!(own, json!({"outcome":"revoked","revoked":1}));
    assert_eq!(
        listing(&store, "head")["grants"].as_array().unwrap().len(),
        2
    );
    let operator = revoke_rows(
        &store,
        BrowserTarget::AgentProfile,
        &RevokeTarget::Everything,
        |holder| holder.agent_id() == "head",
    );
    assert_eq!(operator, json!({"outcome":"revoked","revoked":2}));
    assert!(listing(&store, "head")["grants"]
        .as_array()
        .unwrap()
        .is_empty());
    let remaining = store.live_rows(None, store.now_ms()).unwrap();
    assert_eq!(remaining.len(), 2);
    assert!(remaining
        .iter()
        .any(|row| row.browser_target == Some(BrowserTarget::UserBrowser)));
    assert_eq!(
        listing(&store, "other")["grants"].as_array().unwrap().len(),
        1
    );
}

#[test]
fn unreadable_agent_store_is_reported_by_retained_ops_and_never_mutated() {
    let store = AgentGrants::unavailable(AgentGrantStoreError::UnknownVersion { found: 99 });
    let listed = listing(&store, "head");
    assert_eq!(listed["store"]["state"], "unreadable");
    assert_eq!(
        listed["store"]["reason"],
        "standing_grant_store_version_unknown"
    );
    assert_eq!(listed["grants"], json!([]));
    let reply = revoke_rows(
        &store,
        BrowserTarget::AgentProfile,
        &RevokeTarget::Everything,
        |_| true,
    );
    assert_eq!(reply["outcome"], "store_unavailable");
    assert_eq!(reply["revoked"], 0);
    assert_eq!(
        store.store_error(),
        Some(AgentGrantStoreError::UnknownVersion { found: 99 })
    );
}
