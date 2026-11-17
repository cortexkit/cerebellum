//! Holder admission is exercised by the same management dispatch that native
//! app actions use, with a code-signature fixture and an isolated grant store.

use super::*;
use crate::agent_grants::{AgentGrant, GrantHolder, GrantSubject};
use crate::test_support::HANG_GUARD;

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
    let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
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
        let (reply, planes) = dispatch(planes, facts, "allow_30m").await;
        assert_ne!(reply["outcome"], "granted", "missing {missing}: {reply}");
        let store = planes.management.agent_grants();
        assert_eq!(store.live_rows(None, store.now_ms()).unwrap(), before);
    }
}

fn parent_only_facts(planes: &Planes) -> crate::AcceptedBindFacts {
    let mut facts = planes
        .routes
        .get(1, 1)
        .unwrap()
        .with_scope(Some(crate::cingulate_client::worker_vectors::worker_stamp()));
    // Production workers inherit identity from their parent, not bind attributes.
    facts.agent_project_id_attested = false;
    facts.identity.agent_project_id = "untrusted-bind-project".into();
    facts
}

#[tokio::test]
async fn cursor_avatar_identity_is_the_stamped_head_or_resolved_workers_head() {
    let planes = app_planes();
    let mut head = planes.routes.get(1, 1).unwrap();
    head.identity.agent_project_id = "forged-project-directory".into();
    head.scope = None;
    assert_eq!(crate::permission_scope::cursor_agent(&head, None), None);
    head.scope = Some(
        serde_json::from_value(crate::permission_scope::test_support::live_head()["scope"].clone())
            .unwrap(),
    );
    assert_eq!(
        crate::permission_scope::cursor_agent(&head, None).as_deref(),
        Some("test-project")
    );

    let worker = parent_only_facts(&planes);
    assert_eq!(crate::permission_scope::cursor_agent(&worker, None), None);
    crate::permission_scope::test_support::describe(
        &planes,
        crate::permission_scope::test_support::live_head(),
    );
    let resolved = crate::permission_scope::resolve_worker(&worker, &planes.scopes)
        .await
        .unwrap();
    assert_eq!(
        crate::permission_scope::cursor_agent(&worker, resolved.as_ref()).as_deref(),
        Some("test-project")
    );
}

#[tokio::test]
async fn parent_only_worker_mints_and_lists_under_the_described_heads_agent_id() {
    let planes = app_planes();
    let facts = parent_only_facts(&planes);
    let (reply, planes) = dispatch(planes, facts, "allow_30m").await;
    assert_eq!(reply["outcome"], "granted", "{reply}");
    let store = planes.management.agent_grants();
    let rows = store
        .live_rows(Some("test-project"), store.now_ms())
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        serde_json::to_value(&rows[0].holder).unwrap(),
        json!({
            "kind":"worker", "agent_id":"test-project", "scope_ref":"sc_worker"
        })
    );
    assert!(store
        .live_rows(Some("untrusted-bind-project"), store.now_ms())
        .unwrap()
        .is_empty());
}

#[tokio::test]
async fn revived_worker_reuses_its_grant_but_a_fresh_scope_ref_asks_again() {
    let planes = app_planes();
    let facts = parent_only_facts(&planes);
    let (_, requests) = crate::permission_scope::test_support::describe(
        &planes,
        crate::permission_scope::test_support::live_head(),
    );
    let (reply, planes) = dispatch(planes, facts.clone(), "allow_30m").await;
    assert_eq!(reply["outcome"], "granted", "{reply}");
    let mut revived = facts.clone();
    revived.scope.as_mut().unwrap().scope_epoch += 1;
    let (reply, planes) = dispatch(planes, revived.clone(), "deny").await;
    assert_eq!(
        reply["outcome"], "granted",
        "a revival keeps its grant: {reply}"
    );
    revived.scope.as_mut().unwrap().scope_ref = "fresh-task".into();
    let (reply, planes) = dispatch(planes, revived, "deny").await;
    assert_ne!(
        reply["outcome"], "granted",
        "a fresh task must ask: {reply}"
    );
    assert_eq!(reply["outcome"], "consent_denied", "{reply}");
    let requests = requests.lock().unwrap();
    assert_eq!(
        requests.len(),
        3,
        "one describe per call, not per grant lookup"
    );
    for request in requests.iter() {
        assert_eq!(
            request,
            &json!({"op":"scope.describe", "owner":{"kind":"reserved","module_id":"prefrontal-core"}, "ref":"sc_head_alf"})
        );
    }
    let store = planes.management.agent_grants();
    assert_eq!(store.live_rows(None, store.now_ms()).unwrap().len(), 1);
}

#[tokio::test]
async fn a_head_ending_between_calls_refuses_even_an_existing_worker_grant() {
    let planes = app_planes();
    let facts = parent_only_facts(&planes);
    let (answer, requests) = crate::permission_scope::test_support::describe(
        &planes,
        crate::permission_scope::test_support::live_head(),
    );
    let (reply, planes) = dispatch(planes, facts.clone(), "allow_30m").await;
    assert_eq!(reply["outcome"], "granted", "{reply}");
    for status in ["ended", "not_live"] {
        answer.lock().unwrap()["status"] = json!(status);
        answer.lock().unwrap()["scope"] = Value::Null;
        let (reply, _) = dispatch(planes.clone(), facts.clone(), "allow_30m").await;
        assert_eq!(reply["reason"], "no_agent_session", "{reply}");
        assert_eq!(reply["detail"]["retryable"], false);
    }
    // The live first call asks once. Each ended or not-live head also asks the
    // other prefrontal registration name, which may carry the same session
    // across the rename, before refusing.
    assert_eq!(requests.lock().unwrap().len(), 5);
}

#[tokio::test]
async fn an_unsynced_head_owner_is_unavailable_never_gone() {
    for status in ["live", "not_live", "ended"] {
        let planes = app_planes();
        let facts = parent_only_facts(&planes);
        let mut answer = crate::permission_scope::test_support::live_head();
        answer["owner_synced"] = json!(false);
        answer["status"] = json!(status);
        crate::permission_scope::test_support::describe(&planes, answer);
        let (reply, planes) = dispatch(planes, facts, "allow_30m").await;
        assert_eq!(reply["reason"], "worker_head_unavailable", "{reply}");
        assert_eq!(reply["detail"]["retryable"], true);
        let store = planes.management.agent_grants();
        assert!(store.live_rows(None, store.now_ms()).unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_describe_failure_never_defaults_to_a_worker_holder() {
    let planes = app_planes();
    let facts = parent_only_facts(&planes);
    let mut answer = crate::permission_scope::test_support::live_head();
    // A control error or malformed response cannot establish an identity.
    answer["op"] = json!("not-scope-describe");
    let (_, requests) = crate::permission_scope::test_support::describe(&planes, answer);
    let (reply, planes) = dispatch(planes, facts, "allow_30m").await;
    assert_eq!(reply["reason"], "worker_head_unavailable", "{reply}");
    // Both prefrontal registration names are asked; neither answer establishes
    // an identity, so the call still refuses.
    let owners: Vec<_> = requests
        .lock()
        .unwrap()
        .iter()
        .map(|request| request["owner"]["module_id"].clone())
        .collect();
    assert_eq!(owners, [json!("prefrontal-core"), json!("prefrontal")]);
    let store = planes.management.agent_grants();
    assert!(store.live_rows(None, store.now_ms()).unwrap().is_empty());
}

#[tokio::test]
async fn parent_owner_epoch_kind_and_carrier_must_match_the_admitted_worker() {
    for alteration in [
        "parent-owner",
        "worker-owner",
        "parent-epoch",
        "head-kind",
        "head-ref",
        "head-record-epoch",
        "head-agent",
        "unauthorized",
        "carrier",
    ] {
        let planes = app_planes();
        let mut facts = parent_only_facts(&planes);
        let mut answer = crate::permission_scope::test_support::live_head();
        let stamp = facts.scope.as_mut().unwrap();
        match alteration {
            "parent-owner" => stamp.parent.as_mut().unwrap().owner = Principal::Direct,
            "worker-owner" => stamp.owner = Principal::Direct,
            "parent-epoch" => stamp.parent.as_mut().unwrap().scope_epoch += 1,
            "head-kind" => answer["scope"]["kind"] = json!("worker"),
            "head-ref" => answer["scope"]["ref"] = json!("another-head"),
            "head-record-epoch" => answer["scope"]["scope_epoch"] = json!(8),
            "head-agent" => answer["scope"]["attributes"] = json!({}),
            "unauthorized" => stamp.owner_authorized = false,
            "carrier" => facts.principal = Some(Principal::Direct),
            _ => unreachable!(),
        }
        crate::permission_scope::test_support::describe(&planes, answer);
        let (reply, planes) = dispatch(planes, facts, "allow_30m").await;
        if alteration == "carrier" {
            assert_eq!(reply["code"], "session_caller_not_admitted", "{reply}");
        } else {
            assert_eq!(reply["reason"], "no_agent_session", "{alteration}: {reply}");
        }
        let store = planes.management.agent_grants();
        assert!(store.live_rows(None, store.now_ms()).unwrap().is_empty());
    }
}

#[tokio::test]
async fn a_parent_epoch_mismatch_refuses_a_live_head() {
    let planes = app_planes();
    let facts = parent_only_facts(&planes);
    let mut answer = crate::permission_scope::test_support::live_head();
    answer["scope_epoch"] = json!(8);
    crate::permission_scope::test_support::describe(&planes, answer);
    let (reply, _) = dispatch(planes, facts, "allow_30m").await;
    assert_eq!(reply["reason"], "no_agent_session", "{reply}");
}

#[tokio::test]
async fn no_daemon_connection_refuses_instead_of_defaulting_to_a_holder() {
    let planes = app_planes();
    planes.routes.insert(1, 1, parent_only_facts(&planes));
    let (planes, script) = super::worker::scripted_consent(planes, "allow_30m");
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(app_request(1), &tx, &planes)
        .await
        .unwrap();
    let reply = wire_reply(&mut rx).await;
    assert_eq!(reply["reason"], "worker_head_unavailable", "{reply}");
    assert_eq!(reply["detail"]["retryable"], true);
    assert!(script.calls().is_empty());
    let store = planes.management.agent_grants();
    assert!(store.live_rows(None, store.now_ms()).unwrap().is_empty());
}

#[tokio::test]
async fn worker_describe_spends_only_the_calls_remaining_deadline() {
    let planes = app_planes();
    let facts = parent_only_facts(&planes);
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    planes.scopes.control.connect(&tx);
    let deadline = tokio::time::Instant::now() + Duration::from_millis(10);
    let result = tokio::time::timeout(
        HANG_GUARD,
        crate::call_context::CALL_DEADLINE.scope(
            deadline,
            crate::permission_scope::resolve_worker(&facts, &planes.scopes),
        ),
    )
    .await
    .expect("the call deadline must bound an unanswered describe");
    assert!(matches!(
        result,
        Err(crate::permission_scope::HeadRefusal::Unavailable)
    ));
    let request = rx.try_recv().unwrap();
    assert_eq!(request.header.channel, 0);
    assert_eq!(planes.scopes.control.outstanding(), 0);
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
            let (reply, _) = dispatch(planes, facts, "allow_30m").await;
            assert_ne!(reply["outcome"], "granted", "revoked owner grant: {reply}");
        }
    }
}
