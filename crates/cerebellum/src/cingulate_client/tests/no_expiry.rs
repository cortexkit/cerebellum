use super::*;
use crate::cingulate_client::desk::{CardLifecycle, ExecutionReport};
use crate::cingulate_client::features::CingulateFeatures;
use crate::cingulate_client::wire::{Execution, ExecutionReason};
use sha2::{Digest, Sha256};

const ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/vectors/consent-no-expiry-v1/"
);
fn raw(name: &str) -> Vec<u8> {
    std::fs::read(format!("{ROOT}{name}")).unwrap()
}
fn corpus(name: &str) -> Value {
    serde_json::from_slice(&raw(name)).unwrap()
}
fn features(enabled: bool) -> CingulateFeatures {
    CingulateFeatures {
        option_group: true,
        single_use: false,
        no_expiry: enabled,
    }
}
fn saved_card(kind: CardKind) -> RaisedCard {
    RaisedCard {
        elicitation_id: "el_1".into(),
        session: live_call("sc_head_alf").0.session().clone(),
        kind,
        subject: "login".into(),
        grant_ids: vec!["allow_once".into()],
        decline_id: "deny".into(),
        next_steps: Default::default(),
        applied: false,
        lifecycle: CardLifecycle {
            agent_id: Some("agent-alf".into()),
            ..Default::default()
        },
    }
}
fn store_with(card: RaisedCard) -> Arc<MemoryStore> {
    let store = Arc::new(MemoryStore::default());
    store.save(&[card]).unwrap();
    store
}
fn answered_now() -> Value {
    let mut answer = corpus("execution-reason-reply.json")["result"].clone();
    answer.as_object_mut().unwrap().remove("execution");
    answer.as_object_mut().unwrap().remove("execution_reason");
    answer
}

#[test]
fn published_no_expiry_corpus_is_byte_pinned() {
    let manifest = raw("SHA256SUMS");
    assert_eq!(
        format!("{:x}", Sha256::digest(&manifest)),
        "30a702ac0a13c5e3ab5cb9087af8ccc229ba5f6444d83f7a53e81fd19881fcbd"
    );
    let mut names = Vec::new();
    for row in std::str::from_utf8(&manifest).unwrap().lines() {
        let (hash, name) = row.split_once("  ").unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(raw(name))), hash, "{name}");
        names.push(name.to_string());
    }
    let mut present: Vec<_> = std::fs::read_dir(ROOT)
        .unwrap()
        .map(|file| file.unwrap().file_name().into_string().unwrap())
        .filter(|name| name != "SHA256SUMS")
        .collect();
    names.sort();
    present.sort();
    assert_eq!(names, present);
}

#[tokio::test]
async fn mutation_expiry_is_omitted_only_for_advertised_peers_on_every_card() {
    for enabled in [false, true] {
        for (kind, name, body, deadline) in todays_cards() {
            let peer = ScriptedCingulate::new();
            peer.report_features(Some(features(enabled)));
            peer.then(wire::CONSENT_REQUEST, created());
            let desk = ConsentDesk::new(Arc::new(peer.clone()));
            let (live, _) = live_call("sc_head_alf");
            desk.session(&live)
                .await
                .unwrap()
                .raise(request_for(kind, &body, deadline), name)
                .await
                .unwrap();
            let params = &peer.calls()[0].1;
            if enabled {
                assert!(params.get("expires_in_ms").is_none(), "{name}");
            } else {
                assert_eq!(
                    params["expires_in_ms"],
                    deadline.as_millis() as u64,
                    "{name}"
                );
            }
        }
    }
}

#[tokio::test]
async fn no_deadline_request_and_reason_pin_the_published_wire_bytes() {
    let request = corpus("no-deadline-request.json");
    let mut params = request["params"].clone();
    params["expires_in_ms"] = json!(1_800_000);
    let card = CardRequest {
        kind: CardKind::AppControl,
        params,
        grant_ids: vec!["allow_once".into()],
        decline_id: "deny".into(),
        next_steps: Default::default(),
    };
    let peer = ScriptedCingulate::new();
    peer.report_features(Some(features(true)));
    peer.then(
        wire::CONSENT_REQUEST,
        Reply::Result(corpus("no-deadline-reply.json")["result"].clone()),
    );
    peer.then(
        wire::CONSENT_GET,
        Reply::Result(corpus("no-deadline-future-get-reply.json")["result"].clone()),
    );
    let desk = ConsentDesk::new(Arc::new(peer.clone()));
    let (live, _) = live_call("sc_head_alf");
    let mut session = desk.session(&live).await.unwrap();
    let id = session.raise(card, "app").await.unwrap();
    assert_eq!(
        wire::envelope(wire::CONSENT_REQUEST, peer.calls()[0].1.clone()),
        raw("no-deadline-request.json")
    );
    assert_eq!(
        session.get(&id).await.unwrap().state,
        wire::CardState::Pending
    );
    assert_eq!(
        wire::envelope(
            wire::CONSENT_REPORT_EXECUTION,
            wire::report_execution_with_reason(
                "el_1",
                Execution::ApprovedNotExecuted,
                Some(ExecutionReason::SessionEnded)
            )
        ),
        raw("execution-reason-request.json")
    );
}

#[tokio::test]
async fn an_answer_two_days_after_settlement_survives_ack_and_restart_until_used() {
    let card = saved_card(CardKind::LoginImport);
    let store = store_with(card);
    let peer = ScriptedCingulate::new();
    peer.then(
        wire::CONSENT_ANSWERS,
        Reply::Result(json!({"records":[answered_now()],"cursor":1})),
    )
    .then(wire::CONSENT_ACK, Reply::Result(json!({"ok":true})));
    let clock = Arc::new(|| 10_000_010_000 + 2 * 24 * 60 * 60 * 1000);
    let desk =
        ConsentDesk::with_store(Arc::new(peer.clone()), store.clone()).with_clock(clock.clone());
    let (live, _) = live_call("sc_head_alf");
    desk.session(&live)
        .await
        .unwrap()
        .drain_answers(&mut |_, _, _| Ok(Apply::Applied))
        .await
        .unwrap();
    drop(desk);
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store).with_clock(clock);
    assert_eq!(
        desk.take_single_use_approval(live.session(), "login"),
        Some(("el_1".into(), "allow_once".into()))
    );
    assert!(desk
        .take_single_use_approval(live.session(), "login")
        .is_none());
    desk.finish_execution("el_1", Execution::Executed, None)
        .unwrap();
    let _session = desk.session(&live).await.unwrap();
    assert!(desk.raised("el_1").unwrap().lifecycle.report_undeliverable);
    assert_eq!(peer.methods(), [wire::CONSENT_ANSWERS, wire::CONSENT_ACK]);
}

#[tokio::test]
async fn mutation_tombstone_is_answer_lost_and_never_a_login_approval() {
    let store = store_with(saved_card(CardKind::LoginCapture));
    let peer = ScriptedCingulate::new();
    peer.then(wire::CONSENT_ANSWERS, Reply::Result(json!({"records":[{"elicitation_id":"el_1","state":"expired","settled_at":10000}],"cursor":1})))
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok":true})));
    let desk = ConsentDesk::with_store(Arc::new(peer), store);
    let (live, _) = live_call("sc_head_alf");
    let mut observed = Vec::new();
    desk.session(&live)
        .await
        .unwrap()
        .drain_answers(&mut |_, _, ending| {
            observed.push(ending.clone());
            Ok(Apply::Applied)
        })
        .await
        .unwrap();
    assert_eq!(observed, [Ending::NoAnswer]);
    assert!(desk
        .take_single_use_approval(live.session(), "login")
        .is_none());
    assert!(desk.take_lost_answer(live.session(), "login"));
    assert!(!desk.take_lost_answer(live.session(), "login"));
}

#[tokio::test]
async fn mutation_execution_is_reported_once_across_restart() {
    let mut card = saved_card(CardKind::LoginImport);
    card.lifecycle.answered = true;
    let store = store_with(card);
    let peer = ScriptedCingulate::new();
    peer.then(
        wire::CONSENT_REPORT_EXECUTION,
        Reply::Result(answered_now()),
    );
    let (live, _) = live_call("sc_head_alf");
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store.clone());
    desk.session(&live)
        .await
        .unwrap()
        .report_execution("el_1", Execution::Executed)
        .await
        .unwrap();
    drop(desk);
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store);
    desk.session(&live)
        .await
        .unwrap()
        .report_execution("el_1", Execution::Executed)
        .await
        .unwrap();
    assert_eq!(peer.methods(), [wire::CONSENT_REPORT_EXECUTION]);
    assert!(desk.raised("el_1").unwrap().lifecycle.reported);
}

#[tokio::test]
async fn each_execution_and_reason_is_negotiated_on_the_scripted_wire() {
    for enabled in [false, true] {
        for (execution, reason) in [
            (Execution::Executed, None),
            (Execution::OutcomeUnknown, None),
            (
                Execution::ApprovedNotExecuted,
                Some(ExecutionReason::SessionEnded),
            ),
            (
                Execution::ApprovedNotExecuted,
                Some(ExecutionReason::TargetGone),
            ),
            (
                Execution::ApprovedNotExecuted,
                Some(ExecutionReason::GrantStoreUnavailable),
            ),
            (
                Execution::ApprovedNotExecuted,
                Some(ExecutionReason::RefusedAtDispatch),
            ),
        ] {
            let mut card = saved_card(CardKind::AppControl);
            card.lifecycle.answered = true;
            let store = store_with(card);
            let peer = ScriptedCingulate::new();
            peer.report_features(Some(features(enabled)));
            peer.then(
                wire::CONSENT_REPORT_EXECUTION,
                Reply::Result(answered_now()),
            );
            let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store);
            let (live, _) = live_call("sc_head_alf");
            desk.session(&live)
                .await
                .unwrap()
                .report_execution_reason("el_1", execution, reason)
                .await
                .unwrap();
            let params = &peer.calls()[0].1;
            assert_eq!(params["execution"], execution.as_str());
            assert_eq!(
                params.get("reason").and_then(Value::as_str),
                enabled
                    .then_some(reason)
                    .flatten()
                    .map(ExecutionReason::as_str)
            );
        }
    }
    assert!(wire::report_execution_with_reason(
        "el_1",
        Execution::Executed,
        Some(ExecutionReason::SessionEnded)
    )
    .get("reason")
    .is_none());
}

#[tokio::test]
async fn a_report_not_found_is_undeliverable_but_get_not_found_is_still_no_answer() {
    let mut card = saved_card(CardKind::LoginImport);
    card.lifecycle.answered = true;
    card.lifecycle.acked = true;
    let store = store_with(card);
    let peer = ScriptedCingulate::new();
    peer.then(
        wire::CONSENT_REPORT_EXECUTION,
        Reply::Refused("elicitation_not_found"),
    );
    let (live, _) = live_call("sc_head_alf");
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store.clone());
    desk.session(&live)
        .await
        .unwrap()
        .report_execution("el_1", Execution::Executed)
        .await
        .unwrap();
    drop(desk);
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store);
    let mut session = desk.session(&live).await.unwrap();
    assert!(desk.raised("el_1").unwrap().lifecycle.report_undeliverable);
    assert!(!desk.raised("el_1").unwrap().lifecycle.reported);
    peer.then(wire::CONSENT_GET, Reply::Refused("elicitation_not_found"));
    assert_eq!(session.get("el_1").await, Err(Ending::NoAnswer));
    assert_eq!(
        peer.methods(),
        [wire::CONSENT_REPORT_EXECUTION, wire::CONSENT_GET]
    );
}

#[tokio::test]
async fn report_not_owner_is_undeliverable_only_after_ack_and_never_changes_get_semantics() {
    for acked in [false, true] {
        let mut card = saved_card(CardKind::LoginCapture);
        card.lifecycle.answered = true;
        card.lifecycle.acked = acked;
        let store = store_with(card);
        let peer = ScriptedCingulate::new();
        peer.then(
            wire::CONSENT_REPORT_EXECUTION,
            Reply::Refused("elicitation_not_owner"),
        );
        let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store);
        let (live, _) = live_call("sc_head_alf");
        let mut session = desk.session(&live).await.unwrap();
        session
            .report_execution("el_1", Execution::Executed)
            .await
            .unwrap();
        assert_eq!(
            desk.raised("el_1").unwrap().lifecycle.report_undeliverable,
            acked
        );
        assert_eq!(desk.has_pending_reports(), !acked);
        peer.then(wire::CONSENT_GET, Reply::Refused("elicitation_not_owner"));
        assert_eq!(session.get("el_1").await, Err(Ending::NoAnswer));
    }
}

#[test]
fn execution_refusal_reasons_name_session_target_store_and_dispatch() {
    use crate::computer_grants::{execution_refusal_reason, login_execution_outcome};
    for (reply, expected) in [
        (
            json!({"outcome":"cancelled"}),
            ExecutionReason::SessionEnded,
        ),
        (
            json!({"outcome":"refused","reason":"target_gone"}),
            ExecutionReason::TargetGone,
        ),
        (
            json!({"outcome":"refused","reason":"profile_not_found"}),
            ExecutionReason::TargetGone,
        ),
        (
            json!({"outcome":"refused","detail":{"reason":"grant_store_write_failed"}}),
            ExecutionReason::GrantStoreUnavailable,
        ),
        (
            json!({"outcome":"refused","reason":"screen_locked"}),
            ExecutionReason::RefusedAtDispatch,
        ),
    ] {
        assert_eq!(execution_refusal_reason(&reply), Some(expected));
        assert_eq!(
            login_execution_outcome(&reply, "captured"),
            (Execution::ApprovedNotExecuted, Some(expected))
        );
    }
}

#[tokio::test]
async fn a_lost_report_response_is_read_back_after_restart_without_reporting_twice() {
    let mut card = saved_card(CardKind::LoginCapture);
    card.lifecycle.answered = true;
    let store = store_with(card);
    let peer = ScriptedCingulate::new();
    peer.then(wire::CONSENT_REPORT_EXECUTION, Reply::Transport);
    let (live, _) = live_call("sc_head_alf");
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store.clone());
    desk.session(&live)
        .await
        .unwrap()
        .report_execution("el_1", Execution::Executed)
        .await
        .unwrap();
    assert!(desk.has_pending_reports());
    drop(desk);
    let mut committed = answered_now();
    committed["execution"] = json!("executed");
    peer.then(wire::CONSENT_GET, Reply::Result(committed));
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store)
        .with_clock(Arc::new(|| 10_000_010_001));
    let _session = desk.session(&live).await.unwrap();
    assert_eq!(
        peer.methods(),
        [wire::CONSENT_REPORT_EXECUTION, wire::CONSENT_GET]
    );
    assert!(desk.raised("el_1").unwrap().lifecycle.reported);
}

#[tokio::test]
async fn a_requester_report_replaces_a_scope_end_backstop_after_an_uncertain_send() {
    let mut card = saved_card(CardKind::LoginImport);
    card.lifecycle.answered = true;
    let store = store_with(card);
    let peer = ScriptedCingulate::new();
    peer.then(wire::CONSENT_REPORT_EXECUTION, Reply::Transport);
    let (live, _) = live_call("sc_head_alf");
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store.clone());
    desk.session(&live)
        .await
        .unwrap()
        .report_execution("el_1", Execution::Executed)
        .await
        .unwrap();
    drop(desk);
    peer.then(
        wire::CONSENT_GET,
        Reply::Result(corpus("execution-reason-reply.json")["result"].clone()),
    );
    let mut executed = answered_now();
    executed["execution"] = json!("executed");
    peer.then(wire::CONSENT_REPORT_EXECUTION, Reply::Result(executed));
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store)
        .with_clock(Arc::new(|| 10_000_010_001));
    let _session = desk.session(&live).await.unwrap();
    assert!(desk.raised("el_1").unwrap().lifecycle.reported);
    assert_eq!(
        peer.methods(),
        [
            wire::CONSENT_REPORT_EXECUTION,
            wire::CONSENT_GET,
            wire::CONSENT_REPORT_EXECUTION
        ]
    );
    assert_eq!(peer.calls().last().unwrap().1["execution"], "executed");
}

#[test]
fn a_claimed_but_unused_approval_reports_session_ended_instead_of_unknown() {
    let mut card = saved_card(CardKind::LoginImport);
    card.lifecycle.answered = true;
    card.lifecycle.approval = Some("allow_once".into());
    let store = store_with(card.clone());
    let peer = ScriptedCingulate::new();
    let desk = ConsentDesk::with_store(Arc::new(peer), store);
    assert!(desk
        .take_single_use_approval(&card.session, "login")
        .is_some());
    desk.forget_session(&card.session).unwrap();
    assert_eq!(
        desk.raised("el_1").unwrap().lifecycle.final_report,
        Some(ExecutionReport {
            execution: Execution::ApprovedNotExecuted,
            reason: Some(ExecutionReason::SessionEnded)
        })
    );
}

#[tokio::test]
async fn a_late_one_call_app_or_takeover_permission_reports_refused_without_dispatch() {
    for kind in [CardKind::AppControl, CardKind::Takeover] {
        let store = store_with(saved_card(kind));
        let peer = ScriptedCingulate::new();
        peer.report_features(Some(features(true)));
        peer.then(
            wire::CONSENT_ANSWERS,
            Reply::Result(json!({"records":[answered_now()],"cursor":1})),
        )
        .then(wire::CONSENT_ACK, Reply::Result(json!({"ok":true})));
        let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store)
            .with_clock(Arc::new(|| 10_000_010_001));
        let (live, _) = live_call("sc_head_alf");
        desk.session(&live)
            .await
            .unwrap()
            .drain_answers(&mut |_, _, _| Ok(Apply::Applied))
            .await
            .unwrap();
        assert_eq!(
            desk.raised("el_1").unwrap().lifecycle.final_report,
            Some(ExecutionReport {
                execution: Execution::ApprovedNotExecuted,
                reason: Some(ExecutionReason::RefusedAtDispatch)
            })
        );
        assert!(!desk.raised("el_1").unwrap().lifecycle.dispatch_started);
        peer.then(
            wire::CONSENT_REPORT_EXECUTION,
            Reply::Result(answered_now()),
        );
        let _session = desk.session(&live).await.unwrap();
        assert_eq!(
            peer.calls().last().unwrap().1["reason"],
            "refused_at_dispatch"
        );
    }
}

#[tokio::test]
async fn a_dead_sessions_report_uses_any_live_call_but_agent_b_cannot_apply_agent_a_answer() {
    let mut card = saved_card(CardKind::LoginCapture);
    card.lifecycle.answered = true;
    let store = store_with(card.clone());
    let peer = ScriptedCingulate::new();
    peer.report_features(Some(features(true)));
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store.clone());
    desk.forget_session(&card.session).unwrap();
    drop(desk);
    let live = LiveCall::new(
        Some(&stamp("agent-b", Some("agent-b"))),
        Arc::new(TestHold(AtomicBool::new(true))),
    )
    .unwrap();
    peer.then(
        wire::CONSENT_REPORT_EXECUTION,
        Reply::Result(answered_now()),
    );
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store);
    let _session = desk.session(&live).await.unwrap();
    assert_eq!(peer.calls()[0].1["reason"], "session_ended");

    // The same transport owner does not confer the raising agent's authority.
    card.lifecycle.answered = false;
    let store = store_with(card);
    let peer = ScriptedCingulate::new();
    peer.then(
        wire::CONSENT_ANSWERS,
        Reply::Result(json!({"records":[answered_now()],"cursor":1})),
    );
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store);
    let mut applied = false;
    let report = desk
        .session(&live)
        .await
        .unwrap()
        .drain_answers(&mut |_, _, _| {
            applied = true;
            Ok(Apply::Applied)
        })
        .await
        .unwrap();
    assert!(!applied);
    assert!(report.acked.is_none());
    assert!(desk
        .take_single_use_approval(live.session(), "login")
        .is_none());
    assert_eq!(peer.methods(), [wire::CONSENT_ANSWERS]);
}

#[tokio::test(start_paused = true)]
async fn every_120_second_give_up_detaches_including_a_hung_await_and_user_browser_hold() {
    for enabled in [false, true] {
        for kind in CardKind::ALL {
            for hangs in [false, true] {
                let peer = ScriptedCingulate::new();
                peer.report_features(Some(features(enabled)));
                peer.then(wire::CONSENT_REQUEST, created())
                    .then(
                        wire::CONSENT_AWAIT,
                        if hangs {
                            Reply::Hang
                        } else {
                            Reply::Result(pending())
                        },
                    )
                    .then(wire::CONSENT_DETACH, Reply::Result(detached()));
                let desk = ConsentDesk::new(Arc::new(peer.clone()));
                let (live, _) = live_call("sc_head_alf");
                let mut session = desk.session(&live).await.unwrap();
                let id = session.raise(vector_card(kind), "subject").await.unwrap();
                let start = tokio::time::Instant::now();
                let result = if kind == CardKind::UserBrowserSite {
                    session
                        .hold(&id, Duration::from_secs(120), std::future::pending())
                        .await
                } else {
                    session
                        .park(&id, Duration::from_secs(120), std::future::pending())
                        .await
                };
                assert_eq!(result, InCall::Pending { ask_id: id });
                assert!(start.elapsed() <= Duration::from_secs(120));
                assert_eq!(
                    peer.methods(),
                    [
                        wire::CONSENT_REQUEST,
                        wire::CONSENT_AWAIT,
                        wire::CONSENT_DETACH
                    ],
                    "{kind:?} hangs={hangs}"
                );
                assert_eq!(peer.calls()[1].1["timeout_ms"], 120_000);
            }
        }
    }
}

#[test]
fn registry_upgrade_is_lazy_and_an_interrupted_dispatch_becomes_unknown() {
    let scratch = Scratch::new("no-expiry-lazy");
    let store = Arc::new(scratch.store());
    let mut card = saved_card(CardKind::LoginImport);
    card.lifecycle = CardLifecycle::default();
    store.save(&[card.clone()]).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(store.path()).unwrap()).unwrap()["version"],
        1
    );
    let peer = ScriptedCingulate::new();
    let desk = ConsentDesk::with_store(Arc::new(peer.clone()), store.clone());
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(store.path()).unwrap()).unwrap()["version"],
        1
    );
    desk.begin_execution("el_1").unwrap();
    drop(desk);
    assert_eq!(
        serde_json::from_slice::<Value>(&std::fs::read(store.path()).unwrap()).unwrap()["version"],
        2
    );
    let desk = ConsentDesk::with_store(Arc::new(peer), store);
    assert_eq!(
        desk.raised("el_1").unwrap().lifecycle.final_report,
        Some(ExecutionReport {
            execution: Execution::OutcomeUnknown,
            reason: None
        })
    );
}
