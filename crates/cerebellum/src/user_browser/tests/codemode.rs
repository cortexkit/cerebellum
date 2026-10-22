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
    let mut capabilities = vec![cortexkit_role_tool_provider::CONTENT_V1_CAPABILITY.to_string()];
    if held {
        capabilities.push(cortexkit_role_tool_provider::HELD_REPLY_V1.into());
    }
    let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
        route_channel: RUN,
        epoch: 1,
        principal: Some(subc_protocol::Principal::Reserved {
            module_id: "basal".into(),
        }),
        identity: subc_protocol::BindIdentity::new("/untrusted/run", "run", "misleading-session"),
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

/// The user-browser reply inside the run's content-v1 tool result.
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

#[tokio::test]
async fn withdrawing_a_run_call_cancels_its_in_flight_extension_plan() {
    // The head's standing site grant lets the run's open_tab reach its
    // first page read without a card.
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
    let fixture = Fixture::with_agent_grants(None, Some(store));
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
    for (channel, corr) in [(HEAD.channel, 901), (RUN, 902)] {
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
