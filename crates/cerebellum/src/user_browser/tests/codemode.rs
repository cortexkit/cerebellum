//! A codemode run acts in the person's Chrome exactly as its head route does:
//! its claims, snapshots, refs and quarantine are keyed by the head's route,
//! its site cards go to the head's session and are held rather than parked,
//! and withdrawing it cancels its extension work.

use super::*;
use subc_protocol::call_mode::CallMode;
use subc_protocol::scope::{ParentState, ScopeAttributes, ScopeKind, ScopeParent, ScopeStamp};
use subc_protocol::{Flags, FrameType, Priority};

/// The run route's channel. The fixture binds its head routes on channels 1
/// and 2, both under the `card-tests` head scope; a run borrows the first.
const RUN: u16 = 9;
const HEAD: Route = Route {
    channel: 1,
    epoch: 1,
};

#[tokio::test]
async fn program_page_reads_unfold_with_large_default_and_explicit_lower_cap() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.top_level_only = true;
        let ids: Vec<_> = (0..800).map(|i| format!("item-{i}")).collect();
        let mut nodes = vec![
            json!({"nodeId":"root","ignored":false,"role":{"value":"RootWebArea"},"name":{"value":"Many items"},"backendDOMNodeId":1,"frameId":"main","childIds":ids}),
        ];
        nodes.extend((0..800).map(|i| json!({"nodeId":format!("item-{i}"),"ignored":false,"role":{"value":"button"},"name":{"value":format!("Item {i} {}", "label ".repeat(20))},"backendDOMNodeId":100+i})));
        state.ax_override = Some(json!({"nodes":nodes}));
    }
    let (direct, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert!(
        direct["state_text"].as_str().unwrap().contains("more"),
        "{direct}"
    );
    bind_run(&fixture, false).await;
    for action in ["snapshot", "navigate"] {
        let mut args = snapshot_args(&tab);
        if action == "navigate" {
            args = json!({"browser":"user","action":"navigate","tab":tab,"url":"https://example.com/go","intent":"read page","severity":{"tier":1,"credential":false,"financial":false},"read_page":true});
        }
        for max_bytes in [None, Some(7000)] {
            let mut args = args.clone();
            if let Some(max_bytes) = max_bytes {
                args["max_bytes"] = json!(max_bytes);
            }
            let wire = fixture.finish(start_run(&fixture, args, None)).await;
            let reply = structured(&wire);
            assert_eq!(reply["outcome"], "ok", "{wire}");
            let page = if action == "navigate" {
                &reply["read_page"]
            } else {
                reply
            };
            let text = page["state_text"].as_str().unwrap();
            assert!(!text.contains("more lines"), "{page}");
            if let Some(max_bytes) = max_bytes {
                assert!(text.len() <= max_bytes);
                assert!(text.contains("max_bytes"), "{page}");
            } else {
                assert!(text.len() > 65_536, "only {} bytes", text.len());
                assert!(text.contains("Item 799"));
                assert!(text.len() <= 262_144);
            }
        }
    }
}

fn core() -> subc_protocol::Principal {
    subc_protocol::Principal::Reserved {
        module_id: "prefrontal-core".into(),
    }
}

/// Bind a Basal codemode run on channel 9 under the fixture's head scope.
/// `held` declares the held-reply reader on the run's bind.
async fn bind_run(fixture: &Fixture, held: bool) {
    let stamp = ScopeStamp::new(core(), "run", 1, ScopeKind::Ephemeral)
        .with_attributes(
            ScopeAttributes::new()
                .with_agent_id(Some("test-project".into()))
                .with_run_id(Some("run-test".into())),
        )
        .with_owner_authorized(true)
        .with_parent(Some(ScopeParent::new(core(), "card-tests", 1)))
        .with_parent_state(Some(ParentState::Linked));
    let mut capabilities =
        vec![cortexkit_role_tool_provider::TOOL_RESULT_V1_CAPABILITY.to_string()];
    if held {
        capabilities.push(cortexkit_role_tool_provider::HELD_REPLY_V1.into());
    }
    let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
        route_channel: RUN,
        epoch: 1,
        principal: Some(subc_protocol::Principal::Reserved {
            module_id: "basal".into(),
        }),
        identity: subc_protocol::BindIdentity::new("run", "misleading-session"),
        admission_facts: None,
        consumer_capabilities: Some(capabilities),
        target: subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        },
        scope: Some(stamp),
        role_versions: None,
        call_mode: Some(CallMode::Codemode),
    };
    let frame = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        0,
        0,
        1,
        serde_json::to_vec(&bind).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(4);
    crate::handle_frame_for_test(frame, &writer, &fixture.planes)
        .await
        .unwrap();
    let ack = tokio::time::timeout(HANG_GUARD, replies.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        ack.header.ty,
        FrameType::Response,
        "{}",
        String::from_utf8_lossy(&ack.body)
    );
    assert!(fixture
        .planes
        .routes
        .get(RUN, 1)
        .unwrap()
        .codemode_head
        .is_some());
}

fn run_frame(corr: u64, args: Value, key: Option<&str>) -> Frame {
    let mut body = json!({"name":"browser_use","arguments":args});
    if let Some(key) = key {
        body["call_key"] = json!(key);
    }
    Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        RUN,
        1,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

/// [`Fixture::start`] on the run route, with an optional `call_key`.
fn start_run(fixture: &Fixture, args: Value, key: Option<&str>) -> Started {
    *fixture.site.decision.lock().unwrap() = "allow_30m".into();
    let corr = fixture.corr.fetch_add(1, Ordering::Relaxed);
    let frame = run_frame(corr, args, key);
    let registration = fixture.planes.cancellations.register((RUN, 1, corr));
    let (writer, replies) = mpsc::channel(16);
    let planes = fixture.planes.clone();
    let arrival = crate::browser_queue::arrive(&frame, &planes);
    let task = tokio::spawn(crate::computer_grants::tests::with_live(async move {
        let _registration = registration;
        crate::browser_queue::scope(
            arrival,
            crate::handle_route_request(frame, &writer, &planes),
        )
        .await
        .unwrap();
    }));
    Started {
        corr,
        replies,
        task,
    }
}

/// The user-browser reply inside the run's tool-result/v1 result.
fn structured(reply: &Value) -> &Value {
    &reply["structuredContent"]
}

/// Close a route the way the daemon does, with a GOODBYE frame.
async fn goodbye(fixture: &Fixture, channel: u16) {
    let frame = Frame::build(
        FrameType::Goodbye,
        crate::control_flags(),
        channel,
        1,
        0,
        vec![],
    )
    .unwrap();
    let (writer, _replies) = mpsc::channel(4);
    crate::handle_frame_for_test(frame, &writer, &fixture.planes)
        .await
        .unwrap();
    assert!(fixture.planes.routes.get(channel, 1).is_none());
}

#[tokio::test]
async fn a_run_acts_on_the_tab_its_head_claimed() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (head_read, cards) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(head_read["outcome"], "ok", "{head_read}");
    assert_eq!(cards.len(), 1);
    bind_run(&fixture, false).await;
    let reply = fixture
        .finish(start_run(&fixture, snapshot_args(&tab), None))
        .await;
    assert_eq!(structured(&reply)["outcome"], "ok", "{reply}");
    assert!(structured(&reply)["state_text"]
        .as_str()
        .is_some_and(|text| text.contains("Go")));
    assert_eq!(
        fixture.site.cards.lock().unwrap().len(),
        1,
        "the run reads under the head's site grant"
    );
    let status = fixture
        .finish(start_run(
            &fixture,
            json!({"browser":"user","action":"status"}),
            None,
        ))
        .await;
    assert_eq!(
        structured(&status)["tabs"],
        json!([{"tab":tab,"claim":"claimed_by_this_route","interaction_epoch":1}]),
        "{status}"
    );
}

#[tokio::test]
async fn a_run_acts_on_a_tab_claimed_on_its_heads_newer_tools_route() {
    let fixture = Fixture::new();
    let tab = fixture.claim(2).await;
    let (snapshot, _) = fixture.snapshot(2, &tab, "allow_30m").await;
    bind_run(&fixture, false).await;
    let reply = fixture
        .finish(start_run(
            &fixture,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            None,
        ))
        .await;
    assert_eq!(structured(&reply)["outcome"], "ok", "{reply}");
    assert_eq!(
        fixture
            .planes
            .user_browser
            .target()
            .state()
            .claims
            .get(&tab),
        Some(&HEAD)
    );
    assert!(!fixture.state.lock().unwrap().inputs.is_empty());
}

#[tokio::test]
async fn other_scopes_and_unattested_routes_cannot_borrow_a_heads_tab() {
    for change in [
        "owner",
        "ref",
        "epoch",
        "worker",
        "flow",
        "unscoped",
        "unauthorized",
        "unattested",
        "principal",
    ] {
        let fixture = Fixture::new();
        let tab = fixture.claim(1).await;
        let mut facts = fixture.planes.routes.get(2, 1).unwrap();
        let mut scope = facts.scope.clone().unwrap();
        match change {
            "owner" => {
                scope.owner = subc_protocol::Principal::Reserved {
                    module_id: "another-owner".into(),
                }
            }
            "ref" => scope.scope_ref = "other-head".into(),
            "epoch" => scope.scope_epoch += 1,
            "worker" => {
                scope.kind = ScopeKind::Worker;
                scope.parent = Some(ScopeParent::new(core(), "card-tests", 1));
                scope.parent_state = Some(ParentState::Linked);
            }
            "flow" => scope.attributes.flow_id = Some("flow".into()),
            "unauthorized" => scope.owner_authorized = false,
            "unattested" => {}
            "principal" => {
                facts.principal = Some(subc_protocol::Principal::Reserved {
                    module_id: "basal".into(),
                })
            }
            "unscoped" => {}
            _ => unreachable!(),
        }
        facts = facts.with_scope((change != "unscoped").then_some(scope));
        if change == "unattested" {
            facts.agent_project_id_attested = false;
        }
        // An identical conversation label must not bridge distinct authorities.
        facts.identity.conversation_key = fixture
            .planes
            .routes
            .get(1, 1)
            .unwrap()
            .identity
            .conversation_key;
        fixture.planes.routes.insert(2, 1, facts);
        assert_eq!(
            crate::codemode::user_browser_route(&fixture.planes, 2, 1).unwrap(),
            Route {
                channel: 2,
                epoch: 1
            },
            "{change}"
        );
        let (reply, _) = fixture.snapshot(2, &tab, "allow_30m").await;
        // Worker and flow admission can refuse before the tab-ownership check.
        assert_ne!(reply["outcome"], "ok", "{change}: {reply}");
        assert!(fixture.state.lock().unwrap().inputs.is_empty());
    }
}

#[tokio::test]
async fn a_noncanonical_head_route_goodbye_keeps_claims_and_refs_for_the_run() {
    let fixture = Fixture::new();
    let tab = fixture.claim(2).await;
    let (snapshot, _) = fixture.snapshot(2, &tab, "allow_30m").await;
    bind_run(&fixture, false).await;
    goodbye(&fixture, 2).await;
    assert_eq!(
        fixture
            .planes
            .user_browser
            .target()
            .state()
            .claims
            .get(&tab),
        Some(&HEAD)
    );
    let reply = fixture
        .finish(start_run(
            &fixture,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            None,
        ))
        .await;
    assert_eq!(structured(&reply)["outcome"], "ok", "{reply}");
}

#[tokio::test]
async fn closing_the_canonical_head_route_requires_a_new_claim_on_the_remaining_route() {
    let fixture = Fixture::new();
    let tab = fixture.claim(2).await;
    let (snapshot, _) = fixture.snapshot(2, &tab, "allow_30m").await;
    bind_run(&fixture, false).await;
    goodbye(&fixture, HEAD.channel).await;
    {
        let state = fixture.planes.user_browser.target().state();
        assert!(!state.claims.contains_key(&tab));
        assert!(!state
            .snapshots
            .contains_key(snapshot["snapshot_id"].as_str().unwrap()));
    }
    for reply in [
        fixture.snapshot(2, &tab, "allow_30m").await.0,
        structured(
            &fixture
                .finish(start_run(&fixture, snapshot_args(&tab), None))
                .await,
        )
        .clone(),
    ] {
        assert_eq!(reply["reason"], "tab_not_claimed_by_route", "{reply}");
    }
    let reclaimed = fixture.claim(2).await;
    assert_eq!(reclaimed, tab);
    assert_eq!(
        fixture
            .planes
            .user_browser
            .target()
            .state()
            .claims
            .get(&tab),
        Some(&Route {
            channel: 2,
            epoch: 1
        })
    );
    let reply = fixture
        .finish(start_run(&fixture, snapshot_args(&tab), None))
        .await;
    assert_eq!(structured(&reply)["outcome"], "ok", "{reply}");
}

#[tokio::test]
async fn only_a_definitive_head_scope_end_releases_its_claims_and_refs() {
    for status in ["ended", "unreadable", "uncertain"] {
        let fixture = Fixture::new();
        let tab = fixture.claim(2).await;
        let (snapshot, _) = fixture.snapshot(2, &tab, "allow_30m").await;
        let key = crate::scope_watch::ScopeKey::from_stamp(
            fixture
                .planes
                .routes
                .get(1, 1)
                .unwrap()
                .scope
                .as_ref()
                .unwrap(),
        );
        // A separate head with the same conversation label must retain its tab.
        let mut other = fixture.planes.routes.get(2, 1).unwrap();
        other.scope.as_mut().unwrap().scope_ref = "other-head".into();
        fixture.planes.routes.insert(3, 1, other);
        let mut other_tab = fixture.state.lock().unwrap().tabs[&tab].clone();
        other_tab.owner = None;
        fixture
            .state
            .lock()
            .unwrap()
            .tabs
            .insert("other-tab".into(), other_tab);
        let (claimed, _) = fixture
            .call(
                3,
                json!({"browser":"user","action":"claim_tab","tab":"other-tab"}),
                "allow_30m",
            )
            .await;
        assert_eq!(claimed["outcome"], "ok", "{claimed}");

        let (writer, mut replies) = mpsc::channel(8);
        let close =
            Frame::build(FrameType::Goodbye, crate::control_flags(), 2, 1, 0, vec![]).unwrap();
        crate::handle_frame_for_test(close, &writer, &fixture.planes)
            .await
            .unwrap();
        let question = tokio::time::timeout(HANG_GUARD, replies.recv())
            .await
            .unwrap()
            .unwrap();
        let body: Value = serde_json::from_slice(&question.body).unwrap();
        assert_eq!(body["op"], "scope.describe");
        assert_eq!(body["ref"], "card-tests");
        let (ty, answer) = match status {
            "unreadable" => (
                FrameType::Error,
                json!({"code":"unavailable","message":"try again"}),
            ),
            "uncertain" => (
                FrameType::Response,
                json!({"op":"scope.describe","status":"not_live","daemon_incarnation":"test","owner_synced":false,"owner_configured":true}),
            ),
            _ => (
                FrameType::Response,
                json!({"op":"scope.describe","status":"ended","scope_epoch":1,"daemon_incarnation":"test","owner_synced":true,"owner_configured":true}),
            ),
        };
        let response = Frame::build(
            ty,
            crate::control_flags(),
            0,
            0,
            question.header.corr,
            serde_json::to_vec(&answer).unwrap(),
        )
        .unwrap();
        crate::handle_frame_for_test(response, &writer, &fixture.planes)
            .await
            .unwrap();
        until_frozen(|| fixture.planes.scopes.conversations(&key).is_empty()).await;
        {
            let state = fixture.planes.user_browser.target().state();
            assert_eq!(
                state.claims.contains_key(&tab),
                status != "ended",
                "{status}"
            );
            assert_eq!(
                state
                    .snapshots
                    .contains_key(snapshot["snapshot_id"].as_str().unwrap()),
                status != "ended",
                "{status}"
            );
            assert_eq!(
                state.claims.get("other-tab"),
                Some(&Route {
                    channel: 3,
                    epoch: 1
                })
            );
        }
        let (read, _) = fixture.snapshot(1, &tab, "allow_30m").await;
        if status == "ended" {
            assert_eq!(read["reason"], "tab_not_claimed_by_route", "{read}");
            // The extension processed the existing Goodbye before this inventory.
            let (inventory, _) = fixture
                .call(3, json!({"browser":"user","action":"status"}), "deny")
                .await;
            assert!(
                inventory["tabs"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|row| row["tab"] == tab && row["claim"] == "unclaimed_handed"),
                "{inventory}"
            );
            let state = fixture.state.lock().unwrap();
            assert!(state.tabs[&tab].group);
            assert!(state.tabs[&tab].handed);
            assert!(state.tabs[&tab].owner.is_none());
        } else {
            assert_eq!(read["outcome"], "ok", "{status}: {read}");
        }
    }
}

#[tokio::test]
async fn a_tab_the_run_claims_is_still_the_heads_after_the_run_route_goodbye() {
    let fixture = Fixture::new();
    bind_run(&fixture, false).await;
    let claimed = fixture
        .finish(start_run(
            &fixture,
            json!({"browser":"user","action":"claim_tab","tab":"handed"}),
            None,
        ))
        .await;
    assert_eq!(structured(&claimed)["outcome"], "ok", "{claimed}");
    let tab = structured(&claimed)["tab"].as_str().unwrap().to_owned();
    goodbye(&fixture, RUN).await;
    assert_eq!(
        fixture
            .planes
            .user_browser
            .target()
            .state()
            .claims
            .get(&tab),
        Some(&HEAD)
    );
    // The extension saw the run's GOODBYE before this read, and the read
    // reaches the tab only while the extension still counts it as the head's.
    let (read, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    assert_eq!(read["outcome"], "ok", "{read}");
}

#[tokio::test]
async fn a_run_route_goodbye_leaves_the_heads_claims_and_snapshots_untouched() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    let (snapshot, _) = fixture.snapshot(1, &tab, "allow_30m").await;
    let snapshot_id = snapshot["snapshot_id"].as_str().unwrap().to_owned();
    bind_run(&fixture, false).await;
    let status = fixture
        .finish(start_run(
            &fixture,
            json!({"browser":"user","action":"status"}),
            None,
        ))
        .await;
    assert_eq!(structured(&status)["outcome"], "ok", "{status}");
    goodbye(&fixture, RUN).await;
    {
        let state = fixture.planes.user_browser.target().state();
        assert_eq!(state.claims.get(&tab), Some(&HEAD));
        assert!(state.snapshots.contains_key(&snapshot_id));
        assert!(!state.ended_routes.contains(&HEAD));
    }
    // The head still acts on a ref from its earlier read, with no new card.
    let (clicked, cards) = fixture
        .call(
            1,
            click(&tab, &snapshot, &reference(&snapshot, "Go")),
            "allow_30m",
        )
        .await;
    assert_eq!(clicked["outcome"], "ok", "{clicked}");
    assert!(cards.is_empty(), "{cards:?}");
}

#[tokio::test]
async fn a_held_site_card_is_approved_and_the_runs_retry_acts_without_a_second_card() {
    let script = ScriptedCingulate::new().accept_execution_reports();
    let fixture = Fixture::scripted(&script);
    bind_run(&fixture, true).await;
    let open = json!({"browser":"user","action":"open_tab","url":"https://example.com/start"});
    script
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id":"el_site_run"})),
        )
        .then(
            wire::CONSENT_DETACH,
            Reply::Result(
                json!({"elicitation_id":"el_site_run","state":"pending","detached":true}),
            ),
        );
    let tabs = fixture.state.lock().unwrap().tabs.len();
    let held = fixture
        .finish(start_run(&fixture, open.clone(), Some("run-open")))
        .await;
    assert_eq!(held["held"]["reason"], "consent", "{held}");
    assert_eq!(held["held"]["detail"]["ask_id"], "el_site_run", "{held}");
    assert_eq!(held["held"]["detail"]["origin"], "https://example.com");
    assert_ne!(held["isError"], true, "{held}");
    // Raised to the head's session and detached at once: never parked.
    assert_eq!(
        script.methods(),
        [wire::CONSENT_REQUEST, wire::CONSENT_DETACH]
    );
    for scope in script.scopes() {
        assert_eq!(scope.scope_ref, "card-tests");
    }
    assert!(fixture.planes.calls.has_pending_consents());
    assert_eq!(
        fixture.state.lock().unwrap().tabs.len(),
        tabs,
        "a held card opens no tab"
    );

    // The person approves. The run's next call reads that answer, which
    // stores the site grant, and then opens and loads the page under it.
    script
        .then(
            wire::CONSENT_ANSWERS,
            Reply::Result(json!({"records":[{"elicitation_id":"el_site_run","state":"answered","answered_choice_id":"allow_30m"}],"cursor":1})),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"cursor":1})));
    let retry = fixture
        .finish(start_run(&fixture, open, Some("run-open-retry")))
        .await;
    assert!(retry.get("held").is_none(), "{retry}");
    assert_eq!(structured(&retry)["outcome"], "ok", "{retry}");
    let opened = structured(&retry)["tab"].as_str().unwrap();
    assert_eq!(
        fixture.state.lock().unwrap().tabs[opened].url,
        "https://example.com/start"
    );
    assert_eq!(
        script
            .methods()
            .iter()
            .filter(|method| *method == wire::CONSENT_REQUEST)
            .count(),
        1,
        "the approved retry raised a second card"
    );
    assert!(!fixture.planes.calls.has_pending_consents());
}

/// A fixture whose head already holds a standing site grant for
/// https://example.com in the person's Chrome, so a run's reads there need
/// no card.
fn granted_fixture() -> Fixture {
    let store = Arc::new(crate::agent_grants::AgentGrants::in_memory(Some(
        "test-machine".into(),
    )));
    let now = store.now_ms();
    store
        .upsert(
            crate::agent_grants::AgentGrant {
                id: String::new(),
                holder: crate::agent_grants::GrantHolder::Head {
                    agent_id: "test-project".into(),
                },
                subject: crate::agent_grants::GrantSubject::Origin("https://example.com".into()),
                browser_target: Some(crate::agent_grants::BrowserTarget::UserBrowser),
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
        .unwrap();
    Fixture::with_agent_grants(None, Some(store))
}

#[tokio::test]
async fn withdrawing_a_run_call_cancels_its_in_flight_extension_plan() {
    // The head's standing site grant lets the run's open_tab reach its
    // first page read without a card.
    let fixture = granted_fixture();
    bind_run(&fixture, false).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.plan_count = 0;
        state.cancels = 0;
        state.hang_action = Some("cdp");
    }
    let started = start_run(
        &fixture,
        json!({"browser":"user","action":"open_tab","url":"https://example.com/start"}),
        Some("run-hang"),
    );
    until(|| fixture.state.lock().unwrap().plan_count == 1).await;
    // The hanging plan would also be cancelled when its action deadline
    // passes. Freeze the clock so only the withdrawal can cancel it here.
    tokio::time::pause();
    let (writer, mut replies) = mpsc::channel(4);
    let withdraw = Frame::build(
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        RUN,
        1,
        900,
        serde_json::to_vec(&json!({"name":"tool.withdraw","arguments":{"call_key":"run-hang"}}))
            .unwrap(),
    )
    .unwrap();
    crate::handle_frame_for_test(withdraw, &writer, &fixture.planes)
        .await
        .unwrap();
    until_frozen(|| fixture.state.lock().unwrap().cancels == 1).await;
    let answer = tokio::time::timeout(HANG_GUARD, replies.recv())
        .await
        .unwrap()
        .unwrap();
    let answer: Value = serde_json::from_slice(&answer.body).unwrap();
    assert_eq!(answer["answer"], "already_started", "{answer}");
    let reply = fixture.finish(started).await;
    assert_eq!(reply["code"], "cancelled", "{reply}");
}

/// Wait for `check` on a paused clock without letting it move: this loop never
/// leaves the runtime idle, so the clock never auto-advances and no timer can
/// fire meanwhile. The real-clock bound is only a hang guard.
async fn until_frozen(mut check: impl FnMut() -> bool) {
    let started = std::time::Instant::now();
    while !check() {
        assert!(
            started.elapsed() < HANG_GUARD,
            "the step was not reached while the clock was frozen"
        );
        tokio::task::yield_now().await;
    }
}

#[tokio::test]
async fn a_run_is_held_back_by_a_quarantine_on_its_heads_tab() {
    let fixture = Fixture::new();
    let tab = fixture.claim(1).await;
    bind_run(&fixture, false).await;
    // A head click whose mouse input was never confirmed leaves the tab
    // quarantined under the head's route.
    let args = click(&tab, &json!({"snapshot_id":"s1"}), "e1");
    let budget = crate::budgets::user_browser_call("click", &args).unwrap();
    let stuck = fixture
        .planes
        .user_browser
        .target()
        .execution(HEAD, "click", &args, budget);
    stuck.begin(true);
    stuck.finish(false);
    // The head's own call on that tab is refused, and the run's call is
    // refused the same way.
    for (channel, corr) in [(HEAD.channel, 901), (RUN, 902), (2, 903)] {
        let frame = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            1,
            corr,
            serde_json::to_vec(&json!({"name":"browser_use","arguments":snapshot_args(&tab)}))
                .unwrap(),
        )
        .unwrap();
        let _registration = fixture.planes.cancellations.register((channel, 1, corr));
        let arrival = crate::browser_queue::arrive(&frame, &fixture.planes);
        let entered = crate::browser_queue::scope(
            arrival,
            crate::browser_queue::enter(&frame, &fixture.planes),
        )
        .await;
        assert!(
            matches!(
                entered,
                Err(crate::browser_queue::QueueRefusal::TargetBusy {
                    reason: Some(crate::browser_session::HELD_INPUT_UNCONFIRMED),
                    ..
                })
            ),
            "channel {channel} was not held back by the head's quarantine"
        );
    }
}

/// Make the fixture's head route on `channel` a management-surface route.
fn set_surface(fixture: &Fixture, channel: u16, surface: crate::RouteSurface) {
    let mut facts = fixture.planes.routes.get(channel, 1).unwrap();
    facts.surface = surface;
    fixture.planes.routes.insert(channel, 1, facts);
}

/// The head's direct calls on `head_channel` claim and read a tab; the run must
/// act on that tab, and a tab the run claims must be the head's on that route.
async fn run_shares_the_heads_route(fixture: &Fixture, head_channel: u16) {
    fixture.state.lock().unwrap().tabs.insert(
        "handed2".into(),
        DoubleTab {
            owner: None,
            handed: true,
            group: true,
            url: "https://example.com/".into(),
            loader: 1,
            interaction: 1,
        },
    );
    let head = Route {
        channel: head_channel,
        epoch: 1,
    };
    let tab = fixture.claim(head_channel).await;
    let (read, cards) = fixture.snapshot(head_channel, &tab, "allow_30m").await;
    assert_eq!(read["outcome"], "ok", "{read}");
    assert_eq!(cards.len(), 1);
    bind_run(fixture, false).await;

    let run_read = fixture
        .finish(start_run(fixture, snapshot_args(&tab), None))
        .await;
    assert_eq!(structured(&run_read)["outcome"], "ok", "{run_read}");
    let claimed = fixture
        .finish(start_run(
            fixture,
            json!({"browser":"user","action":"claim_tab","tab":"handed2"}),
            None,
        ))
        .await;
    assert_eq!(structured(&claimed)["outcome"], "ok", "{claimed}");
    let run_tab = structured(&claimed)["tab"].as_str().unwrap().to_owned();
    assert_eq!(
        fixture
            .planes
            .user_browser
            .target()
            .state()
            .claims
            .get(&run_tab),
        Some(&head)
    );
    let (head_read, cards) = fixture.snapshot(head_channel, &run_tab, "allow_30m").await;
    assert_eq!(head_read["outcome"], "ok", "{head_read}");
    assert!(cards.is_empty(), "{cards:?}");
}

#[tokio::test]
async fn the_heads_oldest_bound_tools_route_keeps_its_chrome_work_over_a_newer_lower_channel() {
    let fixture = Fixture::new();
    // Rebind channel 1 so it is newer than channel 2 while keeping the lower
    // channel number, as a short-lived tools route opened after the head's
    // long-lived one would be.
    let facts = fixture.planes.routes.remove(1, 1).unwrap();
    fixture.planes.routes.insert(1, 1, facts);
    assert!(fixture.planes.routes.bind_sequence(2, 1) < fixture.planes.routes.bind_sequence(1, 1));
    run_shares_the_heads_route(&fixture, 2).await;
}

#[tokio::test]
async fn a_head_management_route_bound_first_does_not_take_the_runs_chrome_work() {
    let fixture = Fixture::new();
    // Channel 1, the head's oldest route, becomes a management route; its
    // tools route is channel 2.
    set_surface(&fixture, 1, crate::RouteSurface::Management);
    run_shares_the_heads_route(&fixture, 2).await;
}

#[tokio::test]
async fn a_run_whose_head_has_no_tools_route_is_refused_before_the_extension() {
    let fixture = Fixture::new();
    set_surface(&fixture, 1, crate::RouteSurface::Management);
    set_surface(&fixture, 2, crate::RouteSurface::Management);
    bind_run(&fixture, false).await;
    let reply = fixture
        .finish(start_run(
            &fixture,
            json!({"browser":"user","action":"status"}),
            None,
        ))
        .await;
    assert_eq!(reply["code"], "run_parent_unavailable", "{reply}");
    assert!(
        reply["message"]
            .as_str()
            .is_some_and(|message| message.contains("no open tool route")),
        "{reply}"
    );
    let state = fixture.state.lock().unwrap();
    assert!(state.commands.is_empty(), "{:?}", state.commands);
    assert_eq!(state.attaches, 0);
}

#[tokio::test]
async fn a_run_route_goodbye_cancels_its_hanging_plan_and_keeps_the_heads_claims() {
    let fixture = granted_fixture();
    let tab = fixture.claim(1).await;
    bind_run(&fixture, false).await;
    {
        let mut state = fixture.state.lock().unwrap();
        state.plan_count = 0;
        state.cancels = 0;
        state.hang_action = Some("cdp");
    }
    let mut started = start_run(&fixture, snapshot_args(&tab), None);
    until(|| fixture.state.lock().unwrap().plan_count == 1).await;
    // As in the withdraw test: with the clock frozen, the plan's action
    // deadline cannot be what cancels it.
    tokio::time::pause();
    goodbye(&fixture, RUN).await;
    until_frozen(|| fixture.state.lock().unwrap().cancels == 1).await;
    assert_eq!(
        fixture
            .planes
            .user_browser
            .target()
            .state()
            .claims
            .get(&tab),
        Some(&HEAD)
    );
    tokio::time::timeout(HANG_GUARD, &mut started.task)
        .await
        .expect("the run's call ends when its route closes")
        .unwrap();
    assert!(
        started.replies.try_recv().is_err(),
        "a closed route got a reply"
    );
}

#[tokio::test]
async fn a_run_without_the_held_reader_gets_held_unsupported_for_a_site_card() {
    let script = ScriptedCingulate::new();
    let fixture = Fixture::scripted(&script);
    let tab = fixture.claim(1).await;
    bind_run(&fixture, false).await;
    script
        .then(
            wire::CONSENT_REQUEST,
            Reply::Result(json!({"elicitation_id":"el_site_old"})),
        )
        .then(
            wire::CONSENT_DETACH,
            Reply::Result(
                json!({"elicitation_id":"el_site_old","state":"pending","detached":true}),
            ),
        );
    let reply = fixture
        .finish(start_run(&fixture, snapshot_args(&tab), Some("old-key")))
        .await;
    assert_eq!(reply["errorCode"], "held_unsupported", "{reply}");
    assert_eq!(reply["isError"], true);
    assert!(reply.get("held").is_none(), "{reply}");
    let detail = &structured(&reply)["detail"];
    assert_eq!(detail["step"], "consent", "{reply}");
    assert_eq!(detail["origin"], "https://example.com", "{reply}");
    assert_eq!(detail["ask_id"], "el_site_old", "{reply}");
    assert!(!fixture.planes.calls.has_pending_consents());
    assert_eq!(
        script.methods(),
        [wire::CONSENT_REQUEST, wire::CONSENT_DETACH]
    );
    assert!(fixture.state.lock().unwrap().captures.is_empty());
}
