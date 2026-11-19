//! Managed website cards under a stamped worker scope, through real dispatch.

use super::*;

pub(super) fn describe_head(planes: &Planes, agent: &str) {
    let (tx, mut rx) = mpsc::channel::<Frame>(8);
    if !planes.scopes.control.connect(&tx) {
        return;
    }
    let planes = planes.clone();
    let agent = agent.to_owned();
    tokio::spawn(async move {
        let _connection = tx;
        while let Some(frame) = rx.recv().await {
            assert_eq!(frame.header.channel, 0);
            let request: Value = serde_json::from_slice(&frame.body).unwrap();
            assert_eq!(
                request,
                json!({"op":"scope.describe", "owner":{"kind":"reserved","module_id":"prefrontal"}, "ref":"sc_head_alf"})
            );
            let reply = Frame::build(FrameType::Response, Flags::new(false, Priority::Passive, false), 0, 0, frame.header.corr,
                serde_json::to_vec(&json!({
                    "op":"scope.describe", "status":"live", "scope_epoch":7,
                    "daemon_incarnation":"daemon-test", "owner_synced":true, "owner_configured":true,
                    "scope":{"owner":request["owner"], "owner_authorized":true,
                        "ref":"sc_head_alf", "scope_epoch":7, "kind":"head", "attributes":{"agent_id":agent}}
                })).unwrap()).unwrap();
            let (writer, _replies) = mpsc::channel(8);
            cerebellum::handle_frame_for_test(reply, &writer, &planes)
                .await
                .unwrap();
        }
    });
}

fn worker(conversation: &str) -> Session<'_> {
    Session {
        kind: "subagent",
        ..Session::primary(conversation, AGENT).asking()
    }
}

#[tokio::test]
async fn worker_website_card_grants_only_the_worker_scope() {
    let mut fixture = Fixture::new();
    let route = fixture.route(worker("worker-granted")).await;
    let mut offered = Vec::new();
    let reply = fixture
        .call_answering(
            &route,
            "browser.navigate",
            navigation(&format!("{PUBLIC}/"), 3),
            json!({"decision":"allow_30m"}),
            |card| offered.push(option_ids(card)),
        )
        .await;
    assert_authorized(&reply, "worker conversation answer");
    assert_eq!(offered, [vec!["allow_30m", "allow_all_sites_30m", "deny"]]);
    assert_eq!(permission_support::count(&fixture.planes), 1);
    let rows = permission_support::rows(&fixture.store, AGENT);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].holder,
        cerebellum::agent_grants::GrantHolder::Worker {
            agent_id: AGENT.into(),
            scope_ref: "sc_worker_worker-granted".into()
        }
    );
    assert_eq!(
        rows[0].expires_at_ms,
        Some(rows[0].granted_at_ms + 1_800_000)
    );

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
    fixture.seed(AGENT, GrantSubject::AllSites, 3, &[]);
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
async fn worker_website_cards_never_offer_or_apply_permanent_grants() {
    for in_advance in [false, true] {
        for id in ["allow_origin_always", "allow_all_sites_always"] {
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
                [vec!["allow_30m", "allow_all_sites_30m", "deny"]],
                "{id}, advance={in_advance}"
            );
            if !in_advance {
                assert_refused(&reply, id);
                assert_eq!(
                    reply["detail"]["decision"], "unrecognized_answer",
                    "{reply}"
                );
            }
            assert_eq!(permission_support::count(&fixture.planes), 0, "{id}");
            assert!(
                permission_support::rows(&fixture.store, AGENT).is_empty(),
                "{id}"
            );
        }
    }
}
