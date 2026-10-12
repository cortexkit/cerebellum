//! Bounded blocking work on the browser management paths.
//!
//! `browser.present` and the idle close before a login import run their
//! blocking browser work on the blocking pool, inside the call's terminal
//! decision, never on the call's async task. The background poll that watches
//! a presented handoff takes one browser work permit per job, counts a stuck
//! job as a detached worker, records the handoff's ending through the bounded
//! call-record settle, and stops by the handoff's duration.

use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;

use crate::call_record_supervisor::settle_call_record;
use crate::{
    browser_session, handoff_ending, journal, BrowserConfig, Planes, RouteIdentity,
    TerminalArbiter, CALL_TERMINAL,
};

/// Close the conversation's idle session ahead of a login import, returning
/// the URL it showed. Reading that URL and closing the browser are blocking
/// browser work, so they run on the blocking pool under the import call's
/// work permit, never on the call's async task.
pub(crate) async fn close_idle_for_import_off_task(
    planes: &Planes,
    route_key: &str,
    config: &BrowserConfig,
) -> Result<
    Result<(Value, Option<String>), browser_session::IdleCloseRefusal>,
    tokio::task::JoinError,
> {
    let sessions = planes.sessions.clone();
    let route_key = route_key.to_owned();
    let config = config.clone();
    on_call_blocking_pool(move || sessions.close_idle_for_import(&route_key, &config)).await
}

/// Run blocking browser work for the current call on the blocking pool, never
/// on the call's async task. The work runs with the call's `TerminalArbiter`
/// in scope, so a session operation it starts is recorded as the call's. If
/// the call is answered while that operation is still running, the session
/// is in execution quarantine until the operation ends: other calls on it are
/// refused at once as `target_busy` instead of queueing behind the stuck
/// driver lock.
pub(crate) async fn on_call_blocking_pool<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    let terminal = TerminalArbiter::current();
    tokio::task::spawn_blocking(move || match terminal {
        Some(terminal) => CALL_TERMINAL.sync_scope(terminal, work),
        None => work(),
    })
    .await
}

/// Records a handoff's ending against the keyed call that presented it, and
/// says whether the record was written. Blocking store work: it runs on the
/// blocking pool under a call-record permit.
pub(crate) type HandoffSettle =
    Arc<dyn Fn(journal::call_records::HandoffEnding) -> bool + Send + Sync>;

/// What one turn of the background handoff poll observed.
enum HandoffPollTurn {
    /// No browser work permit was free, so nothing was read this turn. The
    /// handoff stays open, as it does after a failed read.
    Skipped,
    /// The poll job was still running when the poll had to stop. It is left
    /// to finish on its own, counted as a detached worker until it does.
    Stuck,
    Polled(Result<browser_session::HandoffPollResult, tokio::task::JoinError>),
}

/// Watch a presented handoff in the background until it ends, journal its
/// ending, and record that ending against the keyed call that presented it.
///
/// The poll belongs to no call, and its result is never a call's terminal.
/// It stops by `HANDOFF_DURATION_MS` after it starts, whatever the record
/// write returns: its last turn falls at that moment, when the handoff has
/// expired, and that turn is itself bounded. A record left unwritten stays
/// `Started` and is read as an unknown outcome when the store next opens.
pub(crate) fn spawn_handoff_poll(
    planes: &Planes,
    identity: RouteIdentity,
    generation: u64,
    deadline_ms: u64,
    settle: Option<HandoffSettle>,
) -> tokio::task::JoinHandle<()> {
    let planes = planes.clone();
    tokio::spawn(async move {
        let interval = Duration::from_millis(browser_session::HANDOFF_POLL_INTERVAL_MS);
        let stop_at = tokio::time::Instant::now()
            + Duration::from_millis(browser_session::HANDOFF_DURATION_MS);
        loop {
            let next = tokio::time::Instant::now() + interval;
            let last = next >= stop_at;
            tokio::time::sleep_until(next.min(stop_at)).await;
            let polled =
                match poll_handoff_turn(&planes, &identity, generation, deadline_ms, stop_at).await
                {
                    HandoffPollTurn::Polled(polled) => polled,
                    HandoffPollTurn::Stuck => break,
                    HandoffPollTurn::Skipped if last => break,
                    HandoffPollTurn::Skipped => continue,
                };
            let ending = match polled {
                Ok(browser_session::HandoffPollResult::Open) if last => break,
                Ok(browser_session::HandoffPollResult::Open) => continue,
                Ok(browser_session::HandoffPollResult::Closed(close)) => {
                    if close.should_journal {
                        let _ = planes
                            .browser
                            .journal_handoff_closed(&identity, &close)
                            .await;
                    }
                    handoff_ending(close.outcome)
                }
                Ok(browser_session::HandoffPollResult::Gone) | Err(_) => {
                    journal::call_records::HandoffEnding::HandoffInterrupted
                }
            };
            let Some(settle) = &settle else {
                break;
            };
            let written = Arc::new(std::sync::OnceLock::new());
            let settled = Arc::clone(&written);
            let settle = Arc::clone(settle);
            settle_call_record(&planes, move || {
                let _ = settled.set(settle(ending));
            })
            .await;
            match written.get() {
                // A failed write is tried again on the next turn, while the
                // handoff's time lasts.
                Some(false) if !last => continue,
                // Written; or failed on the last turn; or still running past
                // its bound, in which case the late write is left to finish
                // on its own rather than started a second time.
                Some(_) | None => break,
            }
        }
    })
}

/// Run one handoff poll on the blocking pool. The poll takes one work permit
/// of the browser plane, moved into the blocking job, so the permit is
/// returned only when the job finishes, even if this function has stopped
/// waiting for it.
async fn poll_handoff_turn(
    planes: &Planes,
    identity: &RouteIdentity,
    generation: u64,
    deadline_ms: u64,
    stop_at: tokio::time::Instant,
) -> HandoffPollTurn {
    let Some(permit) = planes.sessions.try_job_permit() else {
        return HandoffPollTurn::Skipped;
    };
    let sessions = planes.sessions.clone();
    let clock = Arc::clone(&planes.lease_clock);
    let route_key = identity.conversation_key.clone();
    let mut job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        sessions.poll_handoff(&route_key, generation, deadline_ms, clock.as_ref())
    });
    // How long the job may take: its three reads at `deadline_ms` each, plus
    // `WRITE_BACKSTOP_SLACK`, the time the write backstop lets a command run
    // past its own cap. A job still running after that has a command the
    // backstop is ending, and the session refuses other calls meanwhile; the
    // job is counted in health as a detached worker and waited for only
    // until the poll's stop.
    let bound = Duration::from_millis(deadline_ms.saturating_mul(3))
        + browser_session::WRITE_BACKSTOP_SLACK;
    if let Ok(polled) = tokio::time::timeout(bound, &mut job).await {
        return HandoffPollTurn::Polled(polled);
    }
    let detached = planes.health.enter_detached_worker();
    if let Ok(polled) = tokio::time::timeout_at(stop_at, &mut job).await {
        return HandoffPollTurn::Polled(polled);
    }
    tokio::spawn(async move {
        let _detached = detached;
        let _ = job.await;
    });
    HandoffPollTurn::Stuck
}

#[cfg(test)]
mod tests {
    //! Blocking browser work on the management paths: `browser.present`, the
    //! idle close before a login import, the background handoff poll, and a
    //! capture's consent and handoff parks.

    use super::*;
    use crate::browser_session::{
        CleanupStage, NavigationDriveError, OwnedBrowserProcess, ProcessControlFailure,
        SessionCleanup, SessionCleanupOutcome,
    };
    use crate::{
        budgets, computer_grants, handle_frame, login_capture, management, route_limits,
        ProfileDisposition,
    };
    use serde_json::json;
    use std::collections::BTreeSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Condvar, Mutex};
    use subc_protocol::{Flags, Frame, FrameType, Priority};
    use tokio::sync::mpsc;

    const ORIGIN: &str = "https://login.example.com";

    /// How long a held step stays held at most, in real time. A test whose
    /// own runtime thread is stuck behind the held step then sees the step
    /// released and fails its "still held" check, rather than hanging.
    const HOLD_BACKSTOP: Duration = Duration::from_secs(10);

    /// Parks the fake browser at one named step until released, standing for
    /// a CDP command whose write never completes.
    #[derive(Default)]
    struct StepHold {
        held: Mutex<Option<&'static str>>,
        wake: Condvar,
        passed: Mutex<Vec<&'static str>>,
    }

    impl StepHold {
        fn pass(&self, step: &'static str) {
            self.passed.lock().unwrap().push(step);
            let held = self.held.lock().unwrap();
            drop(
                self.wake
                    .wait_while(held, |held| *held == Some(step))
                    .unwrap(),
            );
        }

        fn hold(self: &Arc<Self>, step: &'static str) -> Released {
            *self.held.lock().unwrap() = Some(step);
            let backstop = Arc::clone(self);
            std::thread::spawn(move || {
                std::thread::sleep(HOLD_BACKSTOP);
                backstop.release();
            });
            Released(Arc::clone(self))
        }

        fn release(&self) {
            *self.held.lock().unwrap() = None;
            self.wake.notify_all();
        }

        /// How many times the browser has reached `step`.
        fn reached(&self, step: &'static str) -> usize {
            self.passed
                .lock()
                .unwrap()
                .iter()
                .filter(|passed| **passed == step)
                .count()
        }

        fn holding(&self, step: &'static str) -> bool {
            *self.held.lock().unwrap() == Some(step)
        }
    }

    /// Releases the held step when dropped, so a failing test still lets the
    /// parked thread end.
    struct Released(Arc<StepHold>);

    impl Drop for Released {
        fn drop(&mut self) {
            self.0.release();
        }
    }

    /// A browser on `ORIGIN` whose reads and fronting pass through a hold.
    struct HeldProcess(Arc<StepHold>);

    impl OwnedBrowserProcess for HeldProcess {
        fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
            self.0.pass("present");
            Ok(())
        }

        fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
            self.0.pass("main_frame_url");
            Ok(format!("{ORIGIN}/account"))
        }

        fn cookie_names_for_origin(
            &mut self,
            _: &str,
            _: &str,
            _: u64,
        ) -> Result<BTreeSet<String>, NavigationDriveError> {
            self.0.pass("cookie_names");
            Ok(BTreeSet::new())
        }

        fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
            Ok(false)
        }

        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
    }

    struct Finished;

    impl SessionCleanup for Finished {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            Ok(SessionCleanupOutcome::Complete)
        }
    }

    /// Management planes on route 4/1 with a ready durable session for that
    /// route's conversation, and `workers` blocking-worker permits on the
    /// browser plane. Returns the conversation key.
    fn planes_with_session(hold: &Arc<StepHold>, workers: usize) -> (Planes, String) {
        let mut planes = crate::tests::management_bound_planes(4, 1);
        let config = BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 600_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        };
        planes.browser_config = Some(config.clone());
        planes.sessions = planes
            .sessions
            .clone()
            .with_blocking_workers_for_test(workers);
        let route = planes
            .routes
            .get(4, 1)
            .unwrap()
            .identity
            .conversation_key
            .clone();
        let _ = planes.sessions.acquire_launch_slot(&route);
        planes
            .sessions
            .establish_ready(
                &route,
                ProfileDisposition::Durable,
                &config,
                planes.lease_clock.as_ref(),
                Box::new(HeldProcess(Arc::clone(hold))),
                Box::new(Finished),
            )
            .expect("a ready session");
        (planes, route)
    }

    fn management_frame(corr: u64, method: &str, params: Value) -> Frame {
        Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            corr,
            serde_json::to_vec(&json!({"method": method, "params": params})).unwrap(),
        )
        .unwrap()
    }

    /// Wait, in real time, until `done` holds. Yields to the runtime between
    /// checks rather than sleeping on its clock, which a paused clock would
    /// not move while a blocking job runs.
    async fn until(what: &str, done: impl Fn() -> bool) {
        let give_up = std::time::Instant::now() + HOLD_BACKSTOP + Duration::from_secs(5);
        while !done() {
            assert!(std::time::Instant::now() < give_up, "never: {what}");
            std::thread::sleep(Duration::from_millis(1));
            tokio::task::yield_now().await;
        }
    }

    /// A present whose fronting command never returns is answered by the
    /// call's envelope, before its reply deadline. The runtime keeps running
    /// meanwhile, and the call's permits and the session's quarantine last
    /// as long as the blocked job.
    #[tokio::test(start_paused = true)]
    async fn a_present_blocked_in_the_browser_is_answered_by_its_envelope() {
        let hold = Arc::new(StepHold::default());
        // One call's pair of permits and no more.
        let (planes, route) = planes_with_session(&hold, 2);
        let held = hold.hold("present");
        let frame = management_frame(41, management::PRESENT, json!({"origin": ORIGIN}));
        let (envelope_ms, reply_ms) = route_limits(&frame, &planes);
        let (writer, mut rx) = mpsc::channel(8);
        let arrived = tokio::time::Instant::now();
        handle_frame(frame, &writer, &planes).await.unwrap();

        until("the present reaches the browser", || {
            hold.reached("present") == 1
        })
        .await;
        assert!(
            hold.holding("present"),
            "the runtime ran again only once the blocked present was released"
        );

        tokio::time::advance(Duration::from_millis(envelope_ms)).await;
        let reply = loop {
            if let Ok(reply) = rx.try_recv() {
                break reply;
            }
            assert!(
                arrived.elapsed() < Duration::from_millis(reply_ms),
                "no terminal frame by the reply deadline"
            );
            tokio::time::advance(Duration::from_millis(500)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        };
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply.header.corr, 41);
        assert_eq!(body["outcome"], "action_deadline_exceeded", "{body}");
        assert_eq!(body["detail"]["dispatched"], false, "{body}");

        assert!(hold.holding("present"));
        assert!(
            planes.sessions.try_call_permits().is_none(),
            "the answered call gave its permits back while its job was still running"
        );
        assert!(
            planes.sessions.execution_quarantine(&route).is_some(),
            "the session admits calls while the answered call's job still drives it"
        );
        drop(held);
        until("the permits come back once the job ends", || {
            planes.sessions.try_call_permits().is_some()
        })
        .await;
    }

    /// The idle close before a login import reads the page's URL and closes
    /// the browser on the blocking pool: the runtime keeps running while that
    /// read is blocked, and the close completes once it returns.
    #[tokio::test]
    async fn an_idle_close_for_import_blocked_in_the_browser_leaves_the_runtime_running() {
        let hold = Arc::new(StepHold::default());
        let (planes, route) = planes_with_session(&hold, 8);
        let config = planes.browser_config.clone().unwrap();
        let held = hold.hold("main_frame_url");
        let closing = {
            let planes = planes.clone();
            tokio::spawn(
                async move { close_idle_for_import_off_task(&planes, &route, &config).await },
            )
        };
        until("the idle close reads the page's URL", || {
            hold.reached("main_frame_url") == 1
        })
        .await;
        assert!(
            hold.holding("main_frame_url"),
            "the runtime ran again only once the blocked read was released"
        );
        drop(held);
        let (closed, url) = closing.await.unwrap().unwrap().unwrap();
        assert_eq!(closed["outcome"], "closed", "{closed}");
        assert_eq!(url, Some(format!("{ORIGIN}/account")));
    }

    fn route_identity(planes: &Planes) -> RouteIdentity {
        planes.routes.get(4, 1).unwrap().identity.clone()
    }

    /// With no session left, every poll ends the handoff as interrupted, and
    /// here every record write fails. The writes are retried, but the poll
    /// stops by the handoff's duration rather than polling on.
    #[tokio::test(start_paused = true)]
    async fn a_handoff_poll_whose_record_write_fails_stops_by_the_handoff_duration() {
        let planes = crate::tests::management_bound_planes(4, 1);
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        let settle: HandoffSettle = Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            false
        });
        let poll = spawn_handoff_poll(&planes, route_identity(&planes), 1, 100, Some(settle));
        tokio::time::timeout(
            Duration::from_millis(browser_session::HANDOFF_DURATION_MS + 1),
            poll,
        )
        .await
        .expect("the poll outlived the handoff")
        .unwrap();
        assert!(
            attempts.load(Ordering::SeqCst) > 1,
            "a failed write is tried again while the handoff lasts"
        );
    }

    /// A record write that never returns, as when the call-record store is
    /// blocked in `sync_all`, ends the poll at the settle bound. The write is
    /// left running rather than started again.
    #[tokio::test(start_paused = true)]
    async fn a_handoff_poll_whose_record_write_hangs_ends_at_the_settle_bound() {
        let planes = crate::tests::management_bound_planes(4, 1);
        let store = Arc::new(StepHold::default());
        let held = store.hold("finish_handoff");
        let blocked = Arc::clone(&store);
        let settle: HandoffSettle = Arc::new(move |_| {
            blocked.pass("finish_handoff");
            true
        });
        let poll = spawn_handoff_poll(&planes, route_identity(&planes), 1, 100, Some(settle));
        // Let the poll start its first wait before the clock moves.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(
            browser_session::HANDOFF_POLL_INTERVAL_MS,
        ))
        .await;
        until("the poll starts the record write", || {
            store.reached("finish_handoff") == 1
        })
        .await;
        // The poll arms the record write's `CALL_RECORD_SETTLE_MS` timer
        // before the write starts, so the poll must end within that bound of
        // now.
        let write_started = tokio::time::Instant::now();
        while !poll.is_finished() {
            assert!(
                write_started.elapsed() <= Duration::from_millis(budgets::CALL_RECORD_SETTLE_MS),
                "the poll waited on the write past its bound"
            );
            tokio::time::advance(Duration::from_millis(100)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        assert_eq!(
            store.reached("finish_handoff"),
            1,
            "the write was started again"
        );
        assert!(
            store.holding("finish_handoff"),
            "the poll ended only once the write was released"
        );
        drop(held);
    }

    /// With no browser work permit free, no poll job runs: the handoff stays
    /// open, nothing is recorded, and the poll still stops by the handoff's
    /// duration.
    #[tokio::test(start_paused = true)]
    async fn a_handoff_poll_with_no_permit_free_reads_nothing() {
        let mut planes = crate::tests::management_bound_planes(4, 1);
        planes.sessions = planes.sessions.clone().with_blocking_workers_for_test(0);
        let attempts = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&attempts);
        let settle: HandoffSettle = Arc::new(move |_| {
            counted.fetch_add(1, Ordering::SeqCst);
            true
        });
        let poll = spawn_handoff_poll(&planes, route_identity(&planes), 1, 100, Some(settle));
        tokio::time::timeout(
            Duration::from_millis(browser_session::HANDOFF_DURATION_MS + 1),
            poll,
        )
        .await
        .expect("the poll outlived the handoff")
        .unwrap();
        assert_eq!(
            attempts.load(Ordering::SeqCst),
            0,
            "a poll ran without a permit"
        );
    }

    /// A poll job blocked in the browser counts as a detached worker once it
    /// has run past its three reads at `deadline_ms` each plus
    /// `WRITE_BACKSTOP_SLACK` (the time the write backstop lets a command
    /// overrun before ending the browser). The poll still stops by the
    /// handoff's duration, leaving the job counted until it ends.
    #[tokio::test(start_paused = true)]
    async fn a_stuck_handoff_poll_is_a_detached_worker_and_the_poll_still_stops() {
        let hold = Arc::new(StepHold::default());
        let (planes, route) = planes_with_session(&hold, 8);
        let deadline_ms = 100;
        let presented = planes
            .sessions
            .present_for_profile(
                &route,
                &route,
                "default",
                ORIGIN,
                deadline_ms,
                planes.lease_clock.as_ref(),
            )
            .unwrap_or_else(|_| panic!("the handoff opens"));
        let held = hold.hold("cookie_names");
        let started = tokio::time::Instant::now();
        let poll = spawn_handoff_poll(
            &planes,
            route_identity(&planes),
            presented.generation,
            deadline_ms,
            None,
        );
        // Let the poll start its first wait before the clock moves.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        tokio::time::advance(Duration::from_millis(
            browser_session::HANDOFF_POLL_INTERVAL_MS,
        ))
        .await;
        until("the poll reads the cookie names", || {
            hold.reached("cookie_names") == 2
        })
        .await;
        assert_eq!(planes.health.detached_workers(), 0);

        let stop = Duration::from_millis(browser_session::HANDOFF_DURATION_MS);
        while planes.health.detached_workers() == 0 {
            assert!(started.elapsed() < stop, "the stuck poll was never counted");
            tokio::time::advance(Duration::from_millis(100)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        assert!(
            started.elapsed()
                <= Duration::from_millis(
                    browser_session::HANDOFF_POLL_INTERVAL_MS + 3 * deadline_ms + 100
                ) + browser_session::WRITE_BACKSTOP_SLACK,
            "counted late: {:?}",
            started.elapsed()
        );
        while !poll.is_finished() {
            assert!(
                started.elapsed() <= stop,
                "the poll outlived the handoff behind a stuck job"
            );
            tokio::time::advance(Duration::from_secs(1)).await;
            for _ in 0..8 {
                tokio::task::yield_now().await;
            }
        }
        assert!(hold.holding("cookie_names"));
        assert_eq!(planes.health.detached_workers(), 1);
        drop(held);
        until("the detached poll job ends", || {
            planes.health.detached_workers() == 0
        })
        .await;
    }

    /// A capture whose consent is answered just inside the consent park, and
    /// whose sign-in window then runs its whole duration, answers with its own
    /// result: the route's backstop deadline for `browser.capture_login` (its
    /// envelope, from `route_limits`) does not fire, and the reply comes
    /// before the browser tool's reply deadline.
    #[tokio::test(start_paused = true)]
    async fn a_capture_with_near_limit_consent_and_handoff_answers_inside_its_envelope() {
        let fixture = login_capture::test_support::fixture_with(|env| {
            env.handoff_duration = Duration::from_millis(browser_session::HANDOFF_DURATION_MS);
            env.poll_interval = Duration::from_millis(browser_session::HANDOFF_POLL_INTERVAL_MS);
        });
        // The person never completes the sign-in, so the window stays open
        // for its whole duration.
        fixture.launcher.script.lock().unwrap().logs_in = false;
        let planes = crate::tests::capture_planes(&fixture);
        let frame = management_frame(
            51,
            management::CAPTURE_LOGIN,
            json!({
                "credential_domain": "ollama.com",
                "account": "work",
                "fetch_url": "https://ollama.com/settings",
                "login_url": "https://ollama.com/signin",
            }),
        );
        let (envelope_ms, _) = route_limits(&frame, &planes);
        let (writer, mut rx) = mpsc::channel(8);
        let arrived = tokio::time::Instant::now();
        handle_frame(frame, &writer, &planes).await.unwrap();
        let question = rx.recv().await.expect("a consent card");
        assert_eq!(question.header.ty, FrameType::Request);

        let consent_wait = computer_grants::CONSENT_PARK_LIMIT - Duration::from_secs(1);
        tokio::time::sleep_until(arrived + consent_wait).await;
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_near_limit"}),
        ));
        let reply = rx.recv().await.expect("the capture's reply");
        let elapsed = arrived.elapsed();
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply.header.corr, 51);
        assert_eq!(body["outcome"], "expired", "{body}");
        assert!(
            elapsed >= consent_wait + Duration::from_millis(browser_session::HANDOFF_DURATION_MS),
            "the handoff ended early: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(envelope_ms),
            "the envelope would have fired: {elapsed:?}"
        );
        assert!(elapsed < Duration::from_millis(budgets::BROWSER_REPLY_MAX_MS));
    }
}
