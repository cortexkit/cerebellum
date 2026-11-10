//! Isolated route arbitration for the manually approved desk probe. The probe
//! supplies its own computer plane; this wrapper supplies the terminal that
//! owns any release or restore, exactly as the frame loop does.

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use subc_protocol::{Frame, FrameType, PROTOCOL_VERSION};
use tokio::sync::mpsc;

use crate::{CancelHandle, HealthState, JournalPersistence, Planes, TerminalArbiter};

pub struct DeskProbeCalls {
    planes: Planes,
    correlation: AtomicU64,
}

impl Default for DeskProbeCalls {
    fn default() -> Self {
        Self {
            planes: Planes::with_browser_config_journaling(
                Arc::new(HealthState::new()),
                None,
                JournalPersistence::Isolated,
            ),
            correlation: AtomicU64::new(1),
        }
    }
}

impl DeskProbeCalls {
    /// Use the same isolated consent desk as the probe's question carrier, so
    /// terminal settlement reaches the desk that recorded the answer.
    pub fn with_consent_desk(
        mut self,
        desk: Arc<crate::cingulate_client::desk::ConsentDesk>,
    ) -> Self {
        self.planes.consent = desk;
        self
    }

    /// Run a computer call with production terminal arbitration, deadlines and
    /// release/restore cleanup, without a daemon or the person's journal.
    pub async fn serve<F, Fut>(&self, name: &'static str, call: F) -> Value
    where
        F: FnOnce(CancelHandle) -> Fut,
        Fut: Future<Output = Value> + Send + 'static,
    {
        let action = name
            .strip_prefix("computer.")
            .expect("a computer probe call");
        let correlation = self.correlation.fetch_add(1, Ordering::Relaxed);
        let request = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            crate::control_flags(),
            1,
            1,
            correlation,
            serde_json::to_vec(&json!({
                "name": crate::flat_tools::COMPUTER_USE, "arguments": {"action": action}
            }))
            .unwrap(),
        )
        .unwrap();
        let terminal = Arc::new(TerminalArbiter::new(request.clone()));
        let registration = self.planes.cancellations.register((1, 1, correlation));
        *registration.handle.0.terminal.lock().unwrap() = Some(Arc::downgrade(&terminal));
        let work = call(registration.handle.clone());
        let (proxy, outgoing) = mpsc::channel(1);
        let (writer, mut replies) = mpsc::channel(1);
        let now = tokio::time::Instant::now();
        let route = crate::terminal_arbiter::run_arbitrated_route(
            async move {
                let reply = work.await;
                let response = Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Response,
                    request.header.flags,
                    1,
                    1,
                    correlation,
                    serde_json::to_vec(&reply).unwrap(),
                )
                .unwrap();
                crate::send(&proxy, response).await
            },
            outgoing,
            writer,
            self.planes.clone(),
            registration,
            Arc::new(self.planes.health.enter_request()),
            terminal,
            now + Duration::from_millis(crate::budgets::COMPUTER_ENVELOPE_MS),
            now + Duration::from_millis(crate::budgets::COMPUTER_REPLY_MAX_MS),
        );
        route.await;
        let reply = replies
            .recv()
            .await
            .expect("the probe route's terminal reply");
        serde_json::from_slice(&reply.body).expect("a JSON terminal reply")
    }
}

/// Pending activations observed by the bounded cleanup task, with milliseconds
/// from request to landing. Reading these records does not sample the desktop.
pub fn take_fronting_landings() -> Vec<(u32, u64)> {
    crate::terminal_arbiter::take_landings()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::terminal_arbiter::{FrontingMode, FrontingPurpose, RestoreHost, RestoreObligation};
    use std::sync::Mutex;

    #[tokio::test]
    async fn a_probe_call_installs_the_terminal_needed_by_temporary_fronting() {
        assert!(TerminalArbiter::current().is_none());
        let calls = DeskProbeCalls::default();
        let reply = calls
            .serve("computer.keys", |cancel| async move {
                assert!(!cancel.is_cancelled());
                assert!(TerminalArbiter::current().is_some());
                json!({"outcome": "completed"})
            })
            .await;
        assert_eq!(reply, json!({"outcome": "completed"}));
        assert!(TerminalArbiter::current().is_none());
    }

    struct Screen {
        front: u32,
        events: Vec<&'static str>,
    }

    struct FakeHost(Arc<Mutex<Screen>>);

    impl RestoreHost for FakeHost {
        fn now_ms(&mut self) -> u64 {
            10
        }

        fn pause_ms(&mut self, _: u64) {}

        fn frontmost_pid(&mut self) -> Option<u32> {
            Some(self.0.lock().unwrap().front)
        }

        fn request_front(&mut self, pid: u32) -> bool {
            let mut screen = self.0.lock().unwrap();
            screen.events.push("restore");
            screen.front = pid;
            true
        }

        fn hardware_input_snapshot(
            &mut self,
        ) -> Option<crate::computer::dispatch::HardwareInputSnapshot> {
            Some(crate::computer::dispatch::HardwareInputSnapshot {
                coverage_start_ms: 0,
                last_input_ms: None,
            })
        }
    }

    #[tokio::test]
    async fn probe_terminal_cleanup_releases_before_restoring_an_undecided_front() {
        let screen = Arc::new(Mutex::new(Screen {
            front: 200,
            events: Vec::new(),
        }));
        let worker_screen = Arc::clone(&screen);
        let reply = DeskProbeCalls::default()
            .serve("computer.keys", |_| async move {
                let terminal = TerminalArbiter::current().unwrap();
                let cell = terminal
                    .register_restore(RestoreObligation {
                        previous_pid: 100,
                        target_pid: 200,
                        target_name: "scratch".into(),
                        mode: FrontingMode::Background,
                        purpose: FrontingPurpose::NeedsFront,
                        lock: Box::new(()),
                        host: Box::new(FakeHost(Arc::clone(&worker_screen))),
                    })
                    .unwrap();
                assert!(cell.begin_front_attempt(10));
                cell.front_attempt_returned();
                terminal.set_release(async move {
                    worker_screen.lock().unwrap().events.push("release");
                    crate::HeldState::Released
                });
                json!({"outcome": "completed"})
            })
            .await;
        assert_eq!(reply["fronting"]["restore"], "restored");
        let screen = screen.lock().unwrap();
        assert_eq!(screen.front, 100);
        assert_eq!(screen.events, ["release", "restore"]);
    }
}
