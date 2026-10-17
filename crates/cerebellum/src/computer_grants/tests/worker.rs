//! Worker app permission cards use the production frame handler and grant store.

use super::*;
use crate::cingulate_client::double::{Reply, ScriptedCingulate};

fn worker_planes(parent: bool) -> (Planes, Arc<InMemoryGrantStorage>) {
    let mut planes = app_planes();
    let storage = Arc::new(InMemoryGrantStorage::new());
    let grants = Arc::new(ComputerGrants::open(
        storage.clone(),
        Some("machine-test".into()),
    ));
    planes.management = Arc::new(crate::management::ManagementPlane::with_computer_grants(
        Arc::new(Running),
        grants,
    ));
    let mut facts = planes.routes.get(1, 1).unwrap();
    let mut stamp = crate::cingulate_client::worker_vectors::worker_stamp();
    if !parent {
        stamp.parent = None;
    }
    facts = facts.with_scope(Some(stamp));
    planes.routes.insert(1, 1, facts);
    (planes, storage)
}

pub(super) fn scripted(planes: Planes, choice: &str) -> (Planes, Arc<ScriptedCingulate>) {
    crate::permission_scope::test_support::describe(
        &planes,
        crate::permission_scope::test_support::live_head(),
    );
    scripted_consent(planes, choice)
}

pub(super) fn scripted_consent(planes: Planes, choice: &str) -> (Planes, Arc<ScriptedCingulate>) {
    let script = ScriptedCingulate::new().accept_execution_reports();
    script
        .then(wire::CONSENT_REQUEST, Reply::Result(json!({"elicitation_id":"el_worker"})))
        .then(wire::CONSENT_AWAIT, Reply::Result(json!({"elicitation_id":"el_worker","state":"answered","answered_choice_id":choice})));
    let store = Arc::new(crate::cingulate_client::desk::FileRegistryStore::new(
        planes
            .consent_test
            .as_ref()
            .unwrap()
            .root
            .join("worker.json"),
    ));
    (
        planes.with_cingulate(Arc::new(script.clone()), store),
        script,
    )
}

fn caller(planes: &Planes) -> GrantCaller {
    let facts = planes.routes.get(1, 1).unwrap();
    GrantCaller {
        holder: Some(crate::agent_grants::GrantHolder::Worker {
            agent_id: "test-project".into(),
            scope_ref: facts.scope.as_ref().unwrap().scope_ref.clone(),
        }),
        conversation_key: facts.identity.conversation_key,
        agent_project_id: facts.identity.agent_project_id,
        durable_identity_attested: false,
    }
}

fn need() -> GrantNeed {
    GrantNeed::App {
        bundle_identity: "com.example.Editor".into(),
        display_name: "Editor".into(),
        code: Arc::new(SignedByFixtureTeam),
    }
}

#[tokio::test]
async fn worker_app_card_grants_only_the_calling_holder_across_conversations() {
    let (planes, _) = worker_planes(true);
    let (planes, script) = scripted(planes, "allow_30m");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    assert_eq!(wire_reply(&mut rx).await["outcome"], "granted");
    assert_eq!(
        script.calls()[0].1["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["allow_30m", "computer_30m", "deny"]
    );
    let worker = caller(&planes);
    let head = GrantCaller {
        holder: Some(crate::agent_grants::GrantHolder::Head {
            agent_id: worker.agent_project_id.clone(),
        }),
        conversation_key: "head-conversation".into(),
        ..worker.clone()
    };
    let grants = planes.management.computer_grants();
    assert!(grants.holds(&worker, &need()));
    assert!(!grants.holds(&head, &need()));
    grants.end_conversation(&worker.conversation_key);
    assert!(
        grants.holds(&worker, &need()),
        "conversation closure cannot revoke an agent grant"
    );
    let store = grants.agent_grants();
    let mut row = store.live_rows(None, store.now_ms()).unwrap().remove(0);
    store.revoke(&row.id, store.now_ms()).unwrap();
    row.holder = head.holder.clone().unwrap();
    store.upsert(row, store.now_ms()).unwrap();
    assert!(grants.holds(&head, &need()), "the head has a usable grant");
    assert!(
        !grants.holds(&worker, &need()),
        "the worker cannot use the head's grant"
    );
    assert!(rx.try_recv().is_err());
}

#[tokio::test]
async fn worker_app_card_never_offers_or_applies_always() {
    // Inherited bind facts can still name the head agent. The stamped worker
    // scope, not those facts, must withhold durable authority.
    let (planes, storage) = worker_planes(true);
    let (planes, script) = scripted(planes, "allow_always");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    let reply = wire_reply(&mut rx).await;
    assert_eq!(reply["reason"], "unrecognized_answer", "{reply}");
    assert_eq!(
        script.calls()[0].1["options"]
            .as_array()
            .unwrap()
            .iter()
            .map(|option| option["id"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["allow_30m", "computer_30m", "deny"]
    );
    assert!(storage.load().unwrap().records.is_empty());
    assert!(!planes
        .management
        .computer_grants()
        .holds(&caller(&planes), &need()));
}

#[tokio::test]
async fn worker_without_parent_is_refused_before_any_route_opens() {
    let (planes, _) = worker_planes(false);
    let (planes, script) = scripted(planes, "allow_30m");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    let reply = wire_reply(&mut rx).await;
    assert_eq!(reply["reason"], "no_agent_session", "{reply}");
    assert_eq!(script.opens(), 0);
    assert!(script.calls().is_empty());
}
