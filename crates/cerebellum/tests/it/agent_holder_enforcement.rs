use super::*;
use crate::support::HANG_GUARD;
use cerebellum::agent_grants::{AgentGrant, AgentGrants, BrowserTarget, GrantHolder, GrantSubject};

fn store() -> Arc<AgentGrants> {
    Arc::new(AgentGrants::in_memory(Some("test-machine".into())))
}
fn planes(store: Arc<AgentGrants>) -> (Planes, Arc<RecordingLauncher>) {
    let (mut planes, launcher) = flow_planes();
    planes.management = Arc::new(
        cerebellum::management::ManagementPlane::new(Arc::new(
            cerebellum::management::PlatformResolver::new(),
        ))
        .with_agent_grants(store.clone()),
    );
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .unwrap()
            .with_grants_installed(
                cerebellum::authorization::GrantStore::default().with_agent_grants(store),
            ),
    );
    (planes, launcher)
}
fn seed(store: &Arc<AgentGrants>, target: BrowserTarget) -> String {
    let now = store.now_ms();
    store
        .upsert(
            AgentGrant {
                id: String::new(),
                holder: GrantHolder::Head {
                    agent_id: "pj-scope-agent".into(),
                },
                subject: GrantSubject::Origin("https://page.example:8443".into()),
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
fn navigate() -> Value {
    json!({"action":"navigate", "url":"https://page.example:8443/page", "intent":"read the page", "severity":{"tier":3,"credential":false,"financial":false}})
}

#[tokio::test]
async fn unified_browser_dispatch_requires_delegation_and_the_correct_target() {
    for (delegates, target) in [
        (true, BrowserTarget::AgentProfile),
        (false, BrowserTarget::AgentProfile),
        (true, BrowserTarget::UserBrowser),
    ] {
        let store = store();
        let id = seed(&store, target);
        let (planes, launcher) = planes(store.clone());
        let mut stamp = flow_stamp();
        stamp.attributes.delegates = delegates;
        bind_flow_wire(&planes, Some(stamp), reserved("basal")).await;
        if delegates && target == BrowserTarget::AgentProfile {
            let launched = flow_wire_call(&planes, 1, json!({"action":"launch"})).await;
            assert_eq!(launched["outcome"], "launched", "{launched}");
        }
        let reply = flow_wire_call(&planes, 2, navigate()).await;
        assert_eq!(
            reply["outcome"] == "ok",
            delegates && target == BrowserTarget::AgentProfile,
            "{reply}"
        );
        if delegates && target == BrowserTarget::AgentProfile {
            assert!(launcher.effects.lock().unwrap().contains(&"navigate"));
            store.revoke(&id, store.now_ms()).unwrap();
            let next = flow_wire_call(&planes, 3, navigate()).await;
            assert_eq!(next["outcome"], "consent_unavailable", "{next}");
            assert_eq!(next["detail"]["reason"], "unattended_flow");
        } else {
            assert!(!launcher.effects.lock().unwrap().contains(&"navigate"));
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn revoking_the_delegated_browser_row_stops_the_production_inflight_action() {
    let store = store();
    let id = seed(&store, BrowserTarget::AgentProfile);
    let (planes, launcher) = planes(store.clone());
    bind_flow_wire(&planes, Some(flow_stamp()), reserved("basal")).await;
    let launched = flow_wire_call(&planes, 1, json!({"action":"launch"})).await;
    assert_eq!(launched["outcome"], "launched", "{launched}");
    let held = launcher.navigate_hold.hold();
    let (tx, mut rx) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(request(2, "browser_use", navigate()), &tx, &planes)
        .await
        .unwrap();
    effect_seen(&launcher, "navigate").await;
    assert!(store.is_in_use(&id));
    store.revoke(&id, store.now_ms()).unwrap();
    let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    let reply: Value = serde_json::from_slice(&reply.body).unwrap();
    assert_ne!(reply["outcome"], "ok", "{reply}");
    assert!(reply.to_string().contains("cancelled"), "{reply}");
    drop(held);
}
