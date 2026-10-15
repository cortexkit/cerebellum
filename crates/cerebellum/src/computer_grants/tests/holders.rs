//! Holder admission is exercised by the same management dispatch that native
//! app actions use, with a code-signature fixture and an isolated grant store.

use super::*;
use crate::agent_grants::{AgentGrant, GrantHolder, GrantSubject};

fn seed(planes: &Planes, holder: GrantHolder) -> String {
    let store = planes.management.agent_grants();
    let now = store.now_ms();
    store
        .upsert(
            AgentGrant {
                id: String::new(),
                holder,
                subject: GrantSubject::App("com.example.Editor".into()),
                browser_target: None,
                machine_uuid: store.machine_uuid().unwrap().into(),
                granted_at_ms: now,
                expires_at_ms: Some(now + 1_800_000),
                card_ref: Some("card".into()),
                max_level: 4,
                hazards: vec![],
                team_id: Some("TESTTEAM".into()),
                designated_requirement: Some(
                    "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                ),
            },
            now,
        )
        .unwrap()
}

async fn dispatch(
    planes: Planes,
    facts: crate::AcceptedBindFacts,
    choice: &str,
) -> (Value, Planes) {
    planes.routes.insert(1, 1, facts);
    let (planes, _) = super::worker::scripted(planes, choice);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    let frame = tokio::time::timeout(Duration::from_secs(10), rx.recv())
        .await
        .unwrap()
        .unwrap();
    (serde_json::from_slice(&frame.body).unwrap(), planes)
}

#[tokio::test]
async fn forged_project_root_and_unattested_heads_neither_match_nor_mint() {
    for missing in ["all", "agent", "session", "acts", "subagent"] {
        let planes = app_planes();
        let mut facts = planes.routes.get(1, 1).unwrap();
        let agent = facts.identity.agent_project_id.clone();
        seed(&planes, GrantHolder::Head { agent_id: agent });
        let before = planes
            .management
            .agent_grants()
            .live_rows(None, planes.management.agent_grants().now_ms())
            .unwrap();
        match missing {
            "all" => {
                facts.scope = None;
                facts.agent_project_id_attested = false;
                facts.session_kind_attested = false;
                facts.acts_as_agent = false;
            }
            "agent" => facts.agent_project_id_attested = false,
            "session" => facts.session_kind_attested = false,
            "acts" => facts.acts_as_agent = false,
            "subagent" => {
                facts.scope = None;
                facts.identity.session_kind = crate::SessionKind::Subagent;
            }
            _ => unreachable!(),
        }
        assert!(
            crate::permission_scope::authorizing_holder(&facts).is_none(),
            "missing {missing}"
        );
        assert!(crate::permission_scope::minting_holder(&facts).is_none());
        let (reply, planes) = dispatch(planes, facts, "allow_conversation").await;
        assert_ne!(reply["outcome"], "granted", "missing {missing}: {reply}");
        let store = planes.management.agent_grants();
        assert_eq!(store.live_rows(None, store.now_ms()).unwrap(), before);
    }
}

#[tokio::test]
async fn parent_only_worker_neither_matches_head_nor_mints_a_row() {
    let planes = app_planes();
    let facts = planes.routes.get(1, 1).unwrap();
    seed(
        &planes,
        GrantHolder::Head {
            agent_id: facts.identity.agent_project_id.clone(),
        },
    );
    let before = planes
        .management
        .agent_grants()
        .live_rows(None, planes.management.agent_grants().now_ms())
        .unwrap();
    let facts = facts.with_scope(Some(crate::cingulate_client::worker_vectors::worker_stamp()));
    assert!(crate::permission_scope::authorizing_holder(&facts).is_none());
    assert!(crate::permission_scope::minting_holder(&facts).is_none());
    let (reply, planes) = dispatch(planes, facts, "allow_conversation").await;
    assert_ne!(reply["outcome"], "granted", "{reply}");
    let store = planes.management.agent_grants();
    assert_eq!(store.live_rows(None, store.now_ms()).unwrap(), before);
}

#[tokio::test]
async fn stamped_worker_dispatch_uses_its_owner_ref_and_epoch_not_the_head() {
    for alteration in [
        "none",
        "head",
        "ref",
        "epoch",
        "owner",
        "unauthorized",
        "carrier",
    ] {
        let planes = app_planes();
        let facts = planes.routes.get(1, 1).unwrap();
        let mut stamp = crate::cingulate_client::worker_vectors::worker_stamp();
        stamp.attributes.agent_id = Some(facts.identity.agent_project_id.clone());
        let mut facts = facts.with_scope(Some(stamp.clone()));
        let holder = crate::permission_scope::authorizing_holder(&facts).unwrap();
        seed(&planes, holder.clone());
        match alteration {
            "none" => {}
            "head" => {
                let agent = facts.identity.agent_project_id.clone();
                facts = facts.with_scope(Some(super::stamp(&agent)));
            }
            "ref" => {
                stamp.scope_ref = "another-ref".into();
                facts = facts.with_scope(Some(stamp));
            }
            "owner" => {
                facts.scope.as_mut().unwrap().owner = Principal::Reserved {
                    module_id: "other".into(),
                };
            }
            "epoch" => {
                stamp.scope_epoch += 1;
                facts = facts.with_scope(Some(stamp));
            }
            "unauthorized" => {
                facts.scope.as_mut().unwrap().owner_authorized = false;
            }
            "carrier" => {
                facts.principal = Some(Principal::Direct);
            }
            _ => unreachable!(),
        }
        if alteration == "head" || alteration == "epoch" {
            assert_ne!(
                crate::permission_scope::authorizing_holder(&facts),
                Some(holder)
            );
        }
        if matches!(alteration, "owner" | "unauthorized" | "carrier") {
            assert!(crate::permission_scope::authorizing_holder(&facts).is_none());
        }
        let (reply, _) = dispatch(planes, facts, "deny").await;
        assert_eq!(
            reply["outcome"] == "granted",
            alteration == "none",
            "alteration {alteration}: {reply}"
        );
    }
}

#[tokio::test]
async fn only_an_admitted_delegated_flow_uses_its_owner_row_without_cards() {
    for delegates in [true, false] {
        let planes = app_planes();
        let mut facts = planes.routes.get(1, 1).unwrap();
        let agent = facts.identity.agent_project_id.clone();
        let id = seed(
            &planes,
            GrantHolder::Head {
                agent_id: agent.clone(),
            },
        );
        let mut stamp = super::stamp(&agent);
        stamp.attributes.flow_id = Some("flow".into());
        stamp.attributes.delegates = delegates;
        facts.principal = Some(Principal::Reserved {
            module_id: "basal".into(),
        });
        facts = facts.with_scope(Some(stamp));
        assert_eq!(
            crate::permission_scope::authorizing_holder(&facts).is_some(),
            delegates
        );
        assert!(crate::permission_scope::minting_holder(&facts).is_none());
        let service = planes.consent_test.as_ref().unwrap().clone();
        let (reply, planes) = dispatch(planes, facts.clone(), "deny").await;
        assert_eq!(reply["outcome"] == "granted", delegates, "{reply}");
        assert!(service.calls().is_empty(), "a flow cannot raise a card");
        if delegates {
            let advisory = planes.management.would_ask(&crate::management::parse_would_ask(json!({
                "agent_id":agent, "flow_id":"flow", "items":[{"tool":"computer_use","target":"com.example.Editor","level":4}]
            }).as_object().unwrap()).ok().unwrap());
            assert_eq!(advisory["items"][0]["verdict"], "yes");
            let store = planes.management.agent_grants();
            store.revoke(&id, store.now_ms()).unwrap();
            let (reply, _) = dispatch(planes, facts, "allow_conversation").await;
            assert_ne!(reply["outcome"], "granted", "revoked owner grant: {reply}");
        }
    }
}
