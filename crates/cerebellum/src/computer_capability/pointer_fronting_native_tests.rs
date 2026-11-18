//! Native post delegation composed with the real plane, terminal and journal.
//! Platform reads and the poster are injected; no native input is delivered.

use super::*;
use cerebellum_computer::platform::macos::test_support::{
    post_observed_pointer, PointerPrimitives,
};
use cerebellum_computer::platform::process_event::{ProcessEventTarget, ProcessGenerationReading};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Condvar, Mutex as StdMutex};
use std::time::Instant;

impl PointerHost {
    pub(super) fn post_native(
        &mut self,
        observation: ObservedUnit<'_, ()>,
    ) -> Result<UnitPosted, SequencePostFailure> {
        let screen = self.base.0.clone();
        assert!(screen
            .state()
            .pointer
            .held
            .as_ref()
            .unwrap()
            .global_send_outstanding());
        let action = screen.state().pointer.action.clone().unwrap();
        let contained = Arc::new(AtomicBool::new(false));
        let in_guard = contained.clone();
        let guard = self.guard.clone();
        let final_drain = contained.clone();
        let post_screen = screen.clone();
        let observation_at = Instant::now() + Duration::from_secs(3600);
        let started = observation_at - Duration::from_millis(screen.state().now);
        let (_tx, rx) = std::sync::mpsc::channel();
        let tap = cerebellum_macos::SessionEventTap::from_test_channel(rx);
        let result = post_observed_pointer(
            &action,
            ProcessEventTarget {
                pid: TARGET,
                start_time_micros: 123,
            },
            GlobalPointerGuard(Arc::new(move |deadline| {
                (guard.0)(deadline)?;
                in_guard.store(true, Ordering::SeqCst);
                Ok(())
            })),
            started,
            PointerPrimitives {
                observation_at,
                live_at: observation_at,
                generation: ProcessGenerationReading::Started(123),
                frontmost: Some(TARGET),
                drain: Box::new(move |_, _| {
                    if final_drain.load(Ordering::SeqCst) {
                        screen.state().log.push("native-final-drain".into());
                    }
                }),
                post: Box::new(move |_| {
                    assert!(contained.load(Ordering::SeqCst));
                    assert_eq!(post_screen.log().last().unwrap(), "native-final-drain");
                    post_screen.state().log.push("native-post-enter".into());
                    let hook = post_screen.state().pointer.native_post.take();
                    if let Some(hook) = hook {
                        (hook.0)();
                    }
                    post_screen.state().log.push("native-post-return".into());
                }),
            },
            ObservedUnit {
                tap: &tap,
                watcher: observation.watcher,
                probe: observation.probe,
                heartbeat: observation.heartbeat,
                cancelled: observation.cancelled,
                deadline_ms: observation.deadline_ms,
                cutoff: observation.cutoff,
            },
        );
        self.abort = observation.watcher.abort_decision();
        result
    }
}

async fn native_fixture(scroll: bool) -> (Rig, &'static str, Value) {
    let (rig, image) = fixture().await;
    rig.screen.state().pointer.native = true;
    if scroll {
        rig.desk.state().topmost_window = Some(WINDOW);
        (
            rig,
            "computer.takeover_scroll",
            json!({
                "target": support::TARGET_BUNDLE_ID, "axis": "vertical", "amount_lines": 2
            }),
        )
    } else {
        (
            rig,
            "computer.takeover_move",
            json!({"image_id": image, "to": {"x": 10, "y": 20}}),
        )
    }
}

#[derive(Default)]
struct PostGate {
    entered: AtomicBool,
    released: StdMutex<bool>,
    wake: Condvar,
}

impl PostGate {
    fn block(&self) {
        let mut released = self.released.lock().unwrap();
        self.entered.store(true, Ordering::SeqCst);
        while !*released {
            released = self.wake.wait(released).unwrap();
        }
    }
    fn release(&self) {
        *self.released.lock().unwrap() = true;
        self.wake.notify_all();
    }
}

struct UnblockOnDrop(Arc<PostGate>);
impl Drop for UnblockOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

// Do not let Tokio auto-advance its paused clock while a blocking worker is
// reaching the poster. The test advances time only after that handshake.
async fn reached(flag: &AtomicBool) {
    while !flag.load(Ordering::SeqCst) {
        tokio::task::yield_now().await;
    }
}

#[tokio::test(start_paused = true)]
async fn native_move_and_scroll_stalled_posts_quarantine_before_terminal_restore() {
    for scroll in [false, true] {
        let (rig, name, arguments) = native_fixture(scroll).await;
        let gate = Arc::new(PostGate::default());
        let _unblock = UnblockOnDrop(gate.clone());
        let blocked = gate.clone();
        rig.screen.state().pointer.native_post =
            Some(support::DeskHook(Arc::new(move || blocked.block())));
        let done = Arc::new(AtomicBool::new(false));
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let input = StdMutex::new(Some((rig.clone(), arguments, done.clone())));
        planes.route_test_handler = Some(Arc::new(move || {
            let (rig, arguments, done) = input.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _ = rig.call(name, arguments).await;
                done.store(true, Ordering::SeqCst);
                std::future::pending::<()>().await;
            })
        }));
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        crate::handle_frame(route_request(), &tx, &planes)
            .await
            .unwrap();
        reached(&gate.entered).await;
        assert_eq!(
            rig.screen.log(),
            ["front:4242", "native-final-drain", "native-post-enter"]
        );
        assert!(rig.plane.held_input.global_send_outstanding());
        crate::handle_frame(route_cancel(), &tx, &planes)
            .await
            .unwrap();
        // A live spawn_blocking post prevents Tokio's automatic clock
        // advancement. Drive only the paused clock while cleanup waits.
        let mut reply = None;
        for _ in 0..1000 {
            tokio::task::yield_now().await;
            if let Ok(frame) = rx.try_recv() {
                reply = Some(frame);
                break;
            }
            tokio::time::advance(Duration::from_millis(10)).await;
        }
        let reply = reply.expect("terminal cleanup did not reply on the controlled clock");
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply["outcome"], "restore_failed", "{name}: {reply}");
        assert_eq!(reply["detail"]["held_state"], "unknown", "{reply}");
        assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
        assert!(!done.load(Ordering::SeqCst));
        assert!(rig.plane.held_input.unconfirmed());
        assert!(rig.plane.held_input.pending_release().is_err());
        assert!(
            rig.lock.held(),
            "the outstanding global send retains exclusion"
        );
        assert_eq!(
            rig.screen.log(),
            ["front:4242", "native-final-drain", "native-post-enter"]
        );
        gate.release();
        reached(&done).await;
        assert_eq!(
            rig.screen.log(),
            [
                "front:4242",
                "native-final-drain",
                "native-post-enter",
                "native-post-return"
            ]
        );
        assert!(!rig.plane.held_input.global_send_outstanding());
        assert!(!rig.plane.held_input.unconfirmed());
        assert!(!rig.lock.held());
        assert!(
            rx.try_recv().is_err(),
            "a late native result cannot send a second terminal"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn native_move_and_scroll_success_then_failed_restore_reply_and_journal() {
    for scroll in [false, true] {
        let (rig, name, arguments) = native_fixture(scroll).await;
        let screen = rig.screen.clone();
        rig.screen.state().pointer.native_post = Some(support::DeskHook(Arc::new(move || {
            screen.state().comes_forward = false;
        })));
        let reply = rig.call_under(&under_terminal(), name, arguments).await;
        assert_eq!(reply["outcome"], "restore_failed", "{name}: {reply}");
        assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
        assert_eq!(
            rig.screen.log(),
            [
                "front:4242",
                "native-final-drain",
                "native-post-enter",
                "native-post-return",
                "restore:100"
            ]
        );
        assert_eq!(rig.screen.frontmost(), Some(TARGET));
        assert!(!rig.plane.held_input.unconfirmed());
        assert!(!rig.plane.held_input.global_send_outstanding());
        assert!(!rig.lock.held());
        let rows = journal_results(&rig);
        let actuation: Vec<_> = rows
            .iter()
            .filter(|row| row["outcome"] == "handler_returned")
            .collect();
        assert_eq!(actuation.len(), 1, "{rows:?}");
        assert_eq!(actuation[0]["fronting"]["fronted"], true);
        assert_eq!(actuation[0]["fronting"]["restore"], "failed", "{rows:?}");
    }
}
