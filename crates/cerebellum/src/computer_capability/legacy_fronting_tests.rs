//! Callers authorized by held takeover and the takeover-dispatch review use
//! shared cleanup without app-use admission.

#![cfg(target_os = "macos")]

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug)]
enum Caller {
    Image,
    Chord,
    SystemChord,
}

const CALLERS: [Caller; 3] = [Caller::Image, Caller::Chord, Caller::SystemChord];

fn namespace(terminal: &Arc<crate::TerminalArbiter>) -> usize {
    Arc::as_ptr(terminal) as usize
}

fn under_terminal() -> Arc<crate::TerminalArbiter> {
    let terminal = super::under_terminal();
    terminal.set_late_fronting_namespace_for_test(namespace(&terminal));
    terminal
}

impl Caller {
    fn request(self) -> (&'static str, Value) {
        match self {
            Self::Image => ("computer.read_state", bring_to_front_read()),
            Self::Chord => ("computer.keys", command_chord()),
            Self::SystemChord => (
                "computer.keys",
                json!({"target": support::TARGET_BUNDLE_ID, "keys": ["command", "space"]}),
            ),
        }
    }

    fn in_call_end(self) -> u64 {
        match self {
            Self::Image => 600,
            Self::Chord | Self::SystemChord => 400,
        }
    }

    async fn rig(self) -> Rig {
        let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
        grant_takeover(&rig).await;
        rig.read().await;
        rig.screen.state().late_watch_after_ms = self.in_call_end();
        assert!(!rig.plane.app_use_fronting_admitted);
        rig
    }

    async fn call(self, rig: &Rig, terminal: &Arc<crate::TerminalArbiter>) -> Value {
        let (name, args) = self.request();
        rig.call_under(terminal, name, args).await
    }

    fn assert_failed(self, reply: &Value) {
        if matches!(self, Self::Image) {
            assert_eq!(reply["outcome"], "completed", "{reply}");
            assert!(reply.get("image").is_none(), "{reply}");
            assert_eq!(
                reply["image_unavailable"]["reason"], "restore_failed",
                "{reply}"
            );
        } else {
            assert_eq!(reply["outcome"], "restore_failed", "{reply}");
            assert_eq!(reply["effect_status"], "not_dispatched", "{reply}");
        }
        if reply.get("fronting").is_some() {
            assert_eq!(reply["fronting"]["fronted"], false, "{reply}");
            assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
        }
    }
}

fn recorder(terminal: &crate::TerminalArbiter) -> tokio::sync::mpsc::UnboundedReceiver<Value> {
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    terminal.set_late_fronting_recorder(Arc::new(move |record| {
        tx.send(record).unwrap();
    }));
    rx
}

async fn cleanup(rx: &mut tokio::sync::mpsc::UnboundedReceiver<Value>) -> Value {
    tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
        .await
        .expect("the caller must hand its pending activation to late cleanup")
        .expect("the cleanup recorder must stay connected")
}

async fn landing_after_reply(caller: Caller) {
    for evidence in [
        "quiet",
        "input",
        "unreadable",
        "gap",
        "third_app",
        "unknown",
    ] {
        let rig = caller.rig().await;
        let gate = Arc::new(AtomicBool::new(false));
        {
            let mut state = rig.screen.state();
            state.front_delay_ms = Some(800);
            state.late_watch_gate = Some(gate.clone());
        }
        let terminal = under_terminal();
        let reply = caller.call(&rig, &terminal).await;
        caller.assert_failed(&reply);
        assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
        let mut rx = recorder(&terminal);
        {
            let mut state = rig.screen.state();
            // The OS lands independently after the reply, not as an action retry.
            state.now = 800;
            state.pending_front_at = None;
            rig.desk.state().frontmost = Some(TARGET);
            match evidence {
                "input" => state.last_input_ms = Some(350),
                "unreadable" => state.observer = false,
                "gap" => state.coverage_start_ms = 1,
                "third_app" | "unknown" => {
                    state.pending_front_at = None;
                    rig.desk.state().frontmost = (evidence == "third_app").then_some(999);
                }
                _ => {}
            }
        }
        terminal.start_late_fronting(None);
        gate.store(true, Ordering::Release);
        let record = cleanup(&mut rx).await;
        assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
        assert_eq!(record["cleanup"], "restore");
        assert_eq!(record["previous_pid"], PREVIOUS);
        assert_eq!(record["target_pid"], TARGET);
        if evidence == "quiet" {
            assert_eq!(record["restore"], "restored");
            assert_eq!(record["activation_latency_ms"], 800);
            assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
            assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
        } else {
            assert_eq!(record["restore"], "skipped_person", "{evidence}: {record}");
            assert_eq!(rig.screen.log(), ["front:4242"]);
        }
        // Neither capture nor posting may run after the action's frontmost-
        // confirmation deadline, even when cleanup observes a late activation.
        assert!(!rig
            .screen
            .log()
            .iter()
            .any(|event| event == "post" || event == "read"));
        caller.assert_failed(&reply);
        assert!(!rig.lock.held());
        assert!(rx.try_recv().is_err(), "one cleanup row per activation");
    }
}

#[tokio::test]
async fn legacy_takeover_image_landing_after_reply_restores_without_capturing() {
    landing_after_reply(Caller::Image).await;
}

#[tokio::test]
async fn legacy_takeover_chord_landing_after_reply_restores_without_posting() {
    landing_after_reply(Caller::Chord).await;
    landing_after_reply(Caller::SystemChord).await;
}

#[tokio::test(start_paused = true)]
async fn legacy_fronting_waits_for_focus_ownership_before_snapshot_or_request() {
    for caller in CALLERS {
        let rig = caller.rig().await;
        let held = rig
            .lock
            .take(&crate::CancelHandle::pending())
            .await
            .unwrap();
        let terminal = under_terminal();
        let task = {
            let rig = rig.clone();
            tokio::spawn(async move { caller.call(&rig, &terminal).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rig.screen.log().is_empty(), "{caller:?}");
        // A different app owns focus when the lock finally becomes available.
        // The restore must use that snapshot, not the focus seen before waiting.
        rig.desk.state().frontmost = Some(200);
        drop(held);
        let reply = task.await.unwrap();
        assert_eq!(
            reply["fronting"]["restore"], "restored",
            "{caller:?}: {reply}"
        );
        assert_eq!(rig.screen.frontmost(), Some(200));
        let action = if matches!(caller, Caller::Image) {
            "read"
        } else {
            "post"
        };
        assert_eq!(rig.screen.log(), ["front:4242", action, "restore:200"]);
        assert!(!rig.lock.held());
    }
}

#[tokio::test]
async fn legacy_takeover_keeps_its_admission_without_a_prior_read() {
    for caller in CALLERS {
        let rig = unadmitted(AppUse::Background, mail_desk(), true).await;
        grant_takeover(&rig).await;
        assert!(!rig.seen_marks_recorded());
        let reply = caller.call(&rig, &under_terminal()).await;
        let action = if matches!(caller, Caller::Image) {
            "read"
        } else {
            "post"
        };
        assert_eq!(
            rig.screen.log(),
            ["front:4242", action, "restore:100"],
            "{caller:?}: {reply}"
        );
        assert_eq!(reply["fronting"]["restore"], "restored");
        assert!(!rig.lock.held());
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_takeover_still_checks_an_existing_baseline_after_the_lock_wait() {
    for caller in CALLERS {
        let rig = unadmitted(AppUse::Background, support::focused_text_desk(), true).await;
        grant_takeover(&rig).await;
        rig.read().await;
        let held = rig
            .lock
            .take(&crate::CancelHandle::pending())
            .await
            .unwrap();
        let terminal = under_terminal();
        let task = {
            let rig = rig.clone();
            tokio::spawn(async move { caller.call(&rig, &terminal).await })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(rig.screen.log().is_empty());
        rig.desk.state().focus = support::DeskFocus::Nothing;
        drop(held);
        let reply = task.await.unwrap();
        assert_eq!(
            reply["outcome"], "state_changed_by_person",
            "{caller:?}: {reply}"
        );
        assert!(rig.screen.log().is_empty());
        assert!(!rig.lock.held());
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_lock_busy_or_cancel_stops_before_activation() {
    for caller in CALLERS {
        for cancel_wait in [false, true] {
            let rig = caller.rig().await;
            let held = rig
                .lock
                .take(&crate::CancelHandle::pending())
                .await
                .unwrap();
            let cancel = crate::CancelHandle::pending();
            let terminal = under_terminal();
            let task = {
                let (rig, cancel) = (rig.clone(), cancel.clone());
                tokio::spawn(async move {
                    let (name, args) = caller.request();
                    crate::CALL_TERMINAL
                        .scope(terminal, rig.serve(name, args, cancel))
                        .await
                })
            };
            if cancel_wait {
                tokio::time::sleep(Duration::from_millis(200)).await;
                cancel.cancel();
            }
            let reply = task.await.unwrap();
            let reason = if cancel_wait {
                "cancelled"
            } else {
                "fronting_busy"
            };
            assert_eq!(
                reply["fronting"]["not_fronted_reason"], reason,
                "{caller:?}: {reply}"
            );
            assert!(reply.get("image").is_none());
            assert!(rig.screen.log().is_empty());
            drop(held);
        }
    }
}

#[tokio::test(start_paused = true)]
async fn legacy_admission_is_rechecked_after_waiting_for_the_lock() {
    for caller in CALLERS {
        for lost in ["app", "takeover", "terminal", "held_input"] {
            let rig = caller.rig().await;
            let held = rig
                .lock
                .take(&crate::CancelHandle::pending())
                .await
                .unwrap();
            let terminal = under_terminal();
            let task = {
                let (rig, terminal) = (rig.clone(), terminal.clone());
                tokio::spawn(async move { caller.call(&rig, &terminal).await })
            };
            tokio::time::sleep(Duration::from_millis(200)).await;
            assert!(rig.screen.log().is_empty());
            match lost {
                "app" | "takeover" => {
                    let store = rig.management.computer_grants().agent_grants();
                    let revoked = store
                        .revoke_matching(store.now_ms(), |row| {
                            let is_takeover = matches!(
                                row.subject,
                                crate::agent_grants::GrantSubject::WholeComputer
                            );
                            is_takeover == (lost == "takeover")
                        })
                        .unwrap();
                    assert!(!revoked.is_empty());
                }
                "terminal" => {
                    terminal.stop(crate::TerminalCause::Deadline);
                }
                "held_input" => rig.leave_held_input_unconfirmed(),
                _ => unreachable!(),
            }
            drop(held);
            let reply = task.await.unwrap();
            assert!(rig.screen.log().is_empty(), "{caller:?}/{lost}: {reply}");
            assert!(reply.get("image").is_none());
            assert!(!rig.lock.held());
        }
    }
}

#[tokio::test]
async fn legacy_cleanup_cannot_race_a_new_front_on_another_target() {
    let management = apps_management();
    Who::fixture()
        .grant(&management, support::TARGET_BUNDLE_ID)
        .await;
    Who::fixture()
        .grant(&management, &other_app().bundle_identity)
        .await;
    let rig = rig_admitting(AppUse::Background, mail_desk(), management, false, true);
    grant_takeover(&rig).await;
    rig.read().await;
    rig.screen.state().front_delay_ms = Some(800);
    let terminal = under_terminal();
    let reply = Caller::Chord.call(&rig, &terminal).await;
    Caller::Chord.assert_failed(&reply);
    let gate = Arc::new(AtomicBool::new(false));
    rig.screen.state().late_watch_gate = Some(gate.clone());
    let mut rx = recorder(&terminal);
    terminal.start_late_fronting(None);
    let other = rig
        .call_under(
            &under_terminal(),
            "computer.read_state",
            json!({
                "target": other_app().bundle_identity, "include_image": true, "bring_to_front": true
            }),
        )
        .await;
    assert_eq!(
        other["fronting"]["not_fronted_reason"], "fronting_busy",
        "{other}"
    );
    assert_eq!(rig.screen.log(), ["front:4242"]);
    gate.store(true, Ordering::Release);
    assert_eq!(cleanup(&mut rx).await["restore"], "restored");
    assert!(!rig.lock.held());
}

#[tokio::test]
async fn legacy_pending_cancel_and_new_call_outrank_route_close() {
    for caller in CALLERS {
        for stop in ["cancel", "new_call"] {
            let rig = caller.rig().await;
            rig.screen.state().front_delay_ms = Some(800);
            let terminal = under_terminal();
            let reply = caller.call(&rig, &terminal).await;
            caller.assert_failed(&reply);
            terminal.stop(crate::TerminalCause::RouteClosed);
            if stop == "cancel" {
                crate::terminal_arbiter::cancel_late_fronting_request(
                    namespace(&terminal),
                    (1, 1, 1),
                );
            } else {
                assert!(crate::terminal_arbiter::cancel_late_fronting_target(
                    rig.lock.domain(),
                    TARGET
                ));
            }
            {
                let mut state = rig.screen.state();
                state.now = 800;
                state.pending_front_at = None;
            }
            rig.desk.state().frontmost = Some(TARGET);
            let mut rx = recorder(&terminal);
            terminal.start_late_fronting(None);
            assert_eq!(cleanup(&mut rx).await["restore"], "failed");
            assert_eq!(rig.screen.log(), ["front:4242"], "{caller:?}/{stop}");
            assert!(!rig.lock.held());
        }
    }
}

#[tokio::test]
async fn legacy_route_close_only_restores_an_already_landed_quiet_target() {
    for caller in CALLERS {
        for evidence in ["quiet", "input", "unreadable", "third_app", "pending"] {
            let rig = caller.rig().await;
            rig.screen.state().front_delay_ms = Some(800);
            let terminal = under_terminal();
            let reply = caller.call(&rig, &terminal).await;
            caller.assert_failed(&reply);
            if evidence != "pending" {
                let mut state = rig.screen.state();
                state.now = 800;
                state.pending_front_at = None;
                if evidence == "input" {
                    state.last_input_ms = Some(500);
                }
                if evidence == "unreadable" {
                    state.observer = false;
                }
                rig.desk.state().frontmost =
                    Some(if evidence == "third_app" { 999 } else { TARGET });
            }
            crate::terminal_arbiter::cancel_late_fronting_route(namespace(&terminal), 1, 1);
            let mut rx = recorder(&terminal);
            terminal.start_late_fronting(None);
            let record = cleanup(&mut rx).await;
            if evidence == "quiet" {
                assert_eq!(record["restore"], "restored");
                assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
            } else {
                assert_eq!(rig.screen.log(), ["front:4242"], "{caller:?}/{evidence}");
            }
            assert_eq!(
                rig.screen.state().now,
                if evidence == "pending" {
                    caller.in_call_end()
                } else {
                    800
                }
            );
            assert!(!rig.lock.held());
        }
    }
}

#[tokio::test]
async fn legacy_late_cleanup_has_one_absolute_end_and_releases_before_journaling() {
    for caller in CALLERS {
        let rig = caller.rig().await;
        rig.screen.state().front_delay_ms = Some(6000);
        let terminal = under_terminal();
        let reply = caller.call(&rig, &terminal).await;
        caller.assert_failed(&reply);
        rig.screen.state().now = 4900;
        let (entered, seen) = tokio::sync::oneshot::channel();
        let entered = StdMutex::new(Some(entered));
        let gate = Arc::new((StdMutex::new(false), std::sync::Condvar::new()));
        let wait_gate = gate.clone();
        terminal.set_late_fronting_recorder(Arc::new(move |_| {
            entered.lock().unwrap().take().unwrap().send(()).unwrap();
            let (lock, changed) = &*wait_gate;
            let (_guard, result) = changed
                .wait_timeout_while(
                    lock.lock().unwrap(),
                    crate::test_support::HANG_GUARD,
                    |done| !*done,
                )
                .unwrap();
            assert!(!result.timed_out(), "journal gate timed out");
        }));
        terminal.start_late_fronting(None);
        tokio::time::timeout(crate::test_support::HANG_GUARD, seen)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rig.screen.state().now, 5000);
        assert_eq!(rig.screen.log(), ["front:4242"]);
        assert!(
            !rig.lock.held(),
            "slow persistence must not retain focus ownership"
        );
        {
            let (lock, changed) = &*gate;
            *lock.lock().unwrap() = true;
            changed.notify_all();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_held_input_settles_before_restore_and_unknown_release_forgoes_it() {
    for release_ok in [true, false] {
        let rig = Caller::Chord.rig().await;
        rig.screen.state().release_ok = release_ok;
        let reply = chord_cancelled_mid_post(&rig).await;
        if release_ok {
            assert_eq!(
                rig.screen.log(),
                ["front:4242", "post", "release", "restore:100"]
            );
            assert_eq!(reply["fronting"]["restore"], "restored");
            assert_eq!(reply["detail"]["held_state"], "released");
        } else {
            assert_eq!(rig.screen.log(), ["front:4242", "post", "release"]);
            assert_eq!(reply["fronting"]["restore"], "failed");
            assert_eq!(reply["detail"]["held_state"], "unknown");
        }
        assert!(
            !rig.lock.held(),
            "terminal cleanup must finish even when release is unknown"
        );
    }
}

#[tokio::test]
async fn legacy_running_watch_cancel_and_route_close_reach_the_same_obligation() {
    for caller in CALLERS {
        for stop in ["cancel", "route"] {
            let rig = caller.rig().await;
            let gate = Arc::new(AtomicBool::new(false));
            {
                let mut state = rig.screen.state();
                state.front_delay_ms = Some(800);
                state.late_watch_gate = Some(gate.clone());
            }
            let terminal = under_terminal();
            let reply = caller.call(&rig, &terminal).await;
            caller.assert_failed(&reply);
            let mut rx = recorder(&terminal);
            terminal.start_late_fronting(None);
            if stop == "cancel" {
                crate::terminal_arbiter::cancel_late_fronting_request(
                    namespace(&terminal),
                    (1, 1, 1),
                );
            } else {
                crate::terminal_arbiter::cancel_late_fronting_route(namespace(&terminal), 1, 1);
            }
            gate.store(true, Ordering::Release);
            assert_eq!(cleanup(&mut rx).await["restore"], "failed");
            assert_eq!(rig.screen.log(), ["front:4242"]);
            assert!(!rig.lock.held());
        }
    }
}

#[tokio::test]
async fn legacy_new_call_waits_for_an_in_flight_restore_without_blocking_tokio() {
    for caller in CALLERS {
        let rig = caller.rig().await;
        rig.screen.state().front_delay_ms = Some(800);
        let terminal = under_terminal();
        let reply = caller.call(&rig, &terminal).await;
        caller.assert_failed(&reply);
        let started = Arc::new(tokio::sync::Notify::new());
        let release = Arc::new(AtomicBool::new(false));
        {
            let mut state = rig.screen.state();
            state.restore_started = Some(started.clone());
            state.restore_until = Some(release.clone());
        }
        let mut rx = recorder(&terminal);
        terminal.start_late_fronting(None);
        tokio::time::timeout(crate::test_support::HANG_GUARD, started.notified())
            .await
            .unwrap();
        let next_terminal = under_terminal();
        let next = rig.call_under(
            &next_terminal,
            "computer.read_state",
            json!({"target":support::TARGET_BUNDLE_ID}),
        );
        tokio::pin!(next);
        let premature = tokio::select! {
            reply = &mut next => Some(reply),
            () = tokio::time::sleep(Duration::from_millis(30)) => None,
        };
        // Release even on failure, so a failed assertion cannot strand a thread.
        release.store(true, Ordering::Release);
        assert!(
            premature.is_none(),
            "new dispatch overtook the restore: {premature:?}"
        );
        assert_eq!(next.await["outcome"], "completed");
        assert_eq!(cleanup(&mut rx).await["restore"], "restored");
        assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
        assert!(!rig.lock.held());
    }
}

#[tokio::test]
async fn legacy_late_cleanup_round_trips_through_the_existing_journal_reader() {
    use cerebellum_computer::audit::ComputerJournalCodec;
    use cerebellum_core::journal::storage::JournalStorage;

    for caller in CALLERS {
        let rig = caller.rig().await;
        let storage = InMemoryJournalStorage::new();
        let mut plane = Arc::try_unwrap(rig.plane)
            .ok()
            .expect("fixture plane is unshared");
        plane.audit = Arc::new(StdMutex::new(support::audit_with_storage(storage.clone())));
        let rig = Rig {
            plane: Arc::new(plane),
            ..rig
        };
        rig.screen.state().front_delay_ms = Some(800);
        let terminal = under_terminal();
        let reply = caller.call(&rig, &terminal).await;
        caller.assert_failed(&reply);
        // Keep the recorder installed by ComputerPlane::serve: this tests the
        // actual route-to-audit binding, not a parallel test journal callback.
        terminal.start_late_fronting(None);
        tokio::time::timeout(crate::test_support::HANG_GUARD, async {
            loop {
                if journal_results(&rig)
                    .iter()
                    .any(|row| row["cleanup"] == "restore")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("cleanup must reach the existing journal");

        let bytes = serde_json::to_vec(&storage.load().unwrap()).unwrap();
        let durable: cerebellum_core::journal::DurableState =
            serde_json::from_slice(&bytes).unwrap();
        let durable = serde_json::to_value(durable).unwrap();
        let export = rig.plane.audit.lock().unwrap().journal().export_bytes();
        let mut cleanups = 0;
        for row in serde_json::Deserializer::from_slice(&export).into_iter::<Value>() {
            let row =
                ComputerJournalCodec::decode_entry(row.unwrap().to_string().as_bytes()).unwrap();
            let Some(result) = row.get("completed_result") else {
                continue;
            };
            let result: Vec<u8> = serde_json::from_value(result.clone()).unwrap();
            let result: Value = serde_json::from_slice(&result).unwrap();
            if result["cleanup"] != "restore" {
                continue;
            }
            cleanups += 1;
            assert_eq!(row["phase"], "finalized");
            let obligation = rig
                .plane
                .audit
                .lock()
                .unwrap()
                .read_obligation_audit(row["sequence"].as_u64().unwrap())
                .unwrap();
            let descriptor: cerebellum_computer::audit::ComputerPlaneDescriptor =
                serde_json::from_slice(&obligation.descriptor_bytes).unwrap();
            assert_eq!(
                descriptor.capability,
                if matches!(caller, Caller::Image) {
                    cerebellum_computer::audit::ComputerCapability::ReadState
                } else {
                    cerebellum_computer::audit::ComputerCapability::Keys
                }
            );
            let sequence = row["sequence"].as_u64().unwrap().to_string();
            assert_eq!(durable["entries"][&sequence]["kind"], "finalized_committed");
            let identity = support::identity();
            assert_eq!(row["identity"]["principal"], identity.principal);
            assert_eq!(
                row["identity"]["conversation_key"],
                identity.conversation_key
            );
            assert_eq!(
                row["identity"]["agent_project_id"],
                identity.agent_project_id
            );
            assert_eq!(
                result,
                json!({"cleanup":"restore", "restore":"restored",
                "previous_pid":100, "target_pid":4242, "activation_latency_ms":800,
                "person_input_during_fronting":false,
                "auth":"not_applicable", "routes":{"public":0,"skylight":0},
                "release_routes":{"public":0,"skylight":0}})
            );
        }
        assert_eq!(cleanups, 1);
        caller.assert_failed(&reply);
        assert!(!rig.lock.held());
    }
}
