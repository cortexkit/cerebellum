use super::*;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};

const GUARD: Duration = Duration::from_secs(3);

#[derive(Clone, Default)]
struct Clock(Arc<AtomicU64>);
impl MonotonicClock for Clock {
    fn now(&self) -> MonoInstant {
        MonoInstant::from_nanos(self.0.load(Ordering::Acquire))
    }
}
fn config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 1000,
        termination_grace_period_ms: 50,
        browser_idle_timeout_ms: 1000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 1000,
    }
}

struct State {
    alive: AtomicBool,
    kills: AtomicU64,
    reaps: AtomicU64,
    cleanups: AtomicU64,
    reads: AtomicU64,
    quiet_epoch: AtomicU64,
    seen: AtomicU64,
    jobs: AtomicU64,
    block_call: AtomicBool,
    block_idle: AtomicBool,
    block_reap: AtomicBool,
    firehose: AtomicBool,
    cookie_added: AtomicBool,
    credential_present: AtomicBool,
    entered: SyncSender<()>,
    release: Mutex<Receiver<()>>,
    graceful: SyncSender<()>,
    fail_cookie: AtomicBool,
    dropped_alive: AtomicBool,
    fail_readiness: AtomicBool,
}
impl State {
    fn pause(&self) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}
impl BrowserKiller for State {
    fn kill_exact_generation(&self) -> KillOutcome {
        self.kills.fetch_add(1, Ordering::Relaxed);
        self.alive.store(false, Ordering::Release);
        let _ = self.entered.try_send(());
        KillOutcome::Dead
    }
}
impl BrowserExitProbe for State {
    fn generation_matches(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}
struct Process {
    pipe: UnixStream,
    state: Arc<State>,
}
impl Drop for Process {
    fn drop(&mut self) {
        self.state
            .dropped_alive
            .store(self.state.alive.load(Ordering::Acquire), Ordering::Release);
    }
}
impl OwnedBrowserProcess for Process {
    fn connection_quiet_epoch(&self) -> u64 {
        self.state.quiet_epoch.load(Ordering::Acquire)
    }
    fn connection_readiness(&self) -> std::io::Result<Option<OwnedFd>> {
        if self.state.fail_readiness.load(Ordering::Acquire) {
            return Err(std::io::Error::other(
                "simulated readiness registration failure",
            ));
        }
        self.pipe.try_clone().map(|fd| Some(fd.into()))
    }
    fn service_connection(&mut self) -> Result<bool, NavigationDriveError> {
        assert!(
            drive_context().is_none(),
            "idle work inherited a foreground terminal"
        );
        self.state.reads.fetch_add(1, Ordering::Relaxed);
        if self.state.block_idle.swap(false, Ordering::AcqRel) {
            self.state.pause();
        }
        if self.state.firehose.load(Ordering::Acquire) {
            return Ok(true);
        }
        let mut data = [0; 1024];
        match self.pipe.read(&mut data) {
            Ok(0) => Err(NavigationDriveError::ConnectorFailure),
            Ok(n) if data[..n].contains(&255) => Err(NavigationDriveError::ConnectorFailure),
            Ok(n) => {
                self.state.seen.fetch_add(n as u64, Ordering::Relaxed);
                Ok(true)
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                self.state.quiet_epoch.fetch_add(1, Ordering::Relaxed);
                Ok(false)
            }
            Err(_) => Err(NavigationDriveError::ConnectorFailure),
        }
    }
    fn set_read_frames(
        &mut self,
        _: Vec<crate::snapshot_store::FrameDocument>,
    ) -> Result<(), NavigationDriveError> {
        assert!(
            drive_context().is_some(),
            "operation lost its DriveScope on the owner thread"
        );
        if self.state.block_call.swap(false, Ordering::AcqRel) {
            self.state.pause();
        }
        self.state.jobs.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
        Ok("https://example.test/login".into())
    }
    fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
        Ok(())
    }
    fn cookie_names_for_origin(
        &mut self,
        _: &str,
        _: &str,
        _: u64,
    ) -> Result<BTreeSet<String>, NavigationDriveError> {
        if self.state.block_call.swap(false, Ordering::AcqRel) {
            self.state.pause();
        }
        if self.state.fail_cookie.load(Ordering::Acquire) {
            return Err(NavigationDriveError::Unavailable);
        }
        let mut names = BTreeSet::from(["baseline".into()]);
        if self.state.cookie_added.load(Ordering::Acquire) {
            names.insert("new-cookie-name".into());
        }
        Ok(names)
    }
    fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
        Ok(self.state.credential_present.load(Ordering::Acquire))
    }
    fn generation_matches(&self) -> bool {
        self.state.alive.load(Ordering::Acquire)
    }
    fn shutdown_killer(&self) -> Option<Arc<dyn BrowserKiller>> {
        Some(self.state.clone())
    }
    fn exit_probe(&self) -> Option<Arc<dyn BrowserExitProbe>> {
        Some(self.state.clone())
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        self.state.alive.store(false, Ordering::Release);
        let _ = self.state.graceful.try_send(());
        Ok(())
    }
    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(!self.generation_matches())
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        self.state.kill_exact_generation();
        Ok(())
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        if self.state.block_reap.swap(false, Ordering::AcqRel) {
            self.state.pause();
        }
        self.state.alive.store(false, Ordering::Release);
        self.state.reaps.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}
struct Cleanup(Arc<State>);
impl SessionCleanup for Cleanup {
    fn custody_holder_id(&self) -> Option<&str> {
        Some("isolated-profile-custody")
    }
    fn prove_profile_unused(&self) -> Result<(), String> {
        if self.0.alive.load(Ordering::Acquire) {
            Err("still alive".into())
        } else {
            Ok(())
        }
    }
    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
        assert!(!self.0.alive.load(Ordering::Acquire));
        assert!(self.0.reaps.load(Ordering::Acquire) > 0);
        self.0.cleanups.fetch_add(1, Ordering::Relaxed);
        Ok(SessionCleanupOutcome::Complete)
    }
}
struct Fixture {
    state: Arc<State>,
    peer: UnixStream,
    entered: Receiver<()>,
    release: SyncSender<()>,
    graceful: Receiver<()>,
}
fn fixture() -> (Box<dyn OwnedBrowserProcess>, Fixture) {
    let (pipe, peer) = UnixStream::pair().unwrap();
    pipe.set_nonblocking(true).unwrap();
    let (entered, receive) = sync_channel(2);
    let (release, wait) = sync_channel(2);
    let (graceful, grace) = sync_channel(2);
    let state = Arc::new(State {
        alive: AtomicBool::new(true),
        kills: AtomicU64::new(0),
        reaps: AtomicU64::new(0),
        cleanups: AtomicU64::new(0),
        reads: AtomicU64::new(0),
        quiet_epoch: AtomicU64::new(0),
        seen: AtomicU64::new(0),
        jobs: AtomicU64::new(0),
        block_call: AtomicBool::new(false),
        block_idle: AtomicBool::new(false),
        block_reap: AtomicBool::new(false),
        firehose: AtomicBool::new(false),
        cookie_added: AtomicBool::new(false),
        credential_present: AtomicBool::new(true),
        entered,
        release: Mutex::new(wait),
        graceful,
        fail_cookie: AtomicBool::new(false),
        dropped_alive: AtomicBool::new(false),
        fail_readiness: AtomicBool::new(false),
    });
    (
        Box::new(Process {
            pipe,
            state: state.clone(),
        }),
        Fixture {
            state,
            peer,
            entered: receive,
            release,
            graceful: grace,
        },
    )
}
fn establish(
    sessions: &BrowserSessions,
    route: &str,
    clock: &Clock,
    process: Box<dyn OwnedBrowserProcess>,
    state: &Arc<State>,
) -> String {
    assert!(matches!(
        sessions.acquire_launch_slot(route),
        LaunchSlot::Acquired { .. }
    ));
    let (id, _, _) = sessions
        .establish_ready(
            route,
            ProfileDisposition::Durable,
            &config(),
            clock,
            process,
            Box::new(Cleanup(state.clone())),
        )
        .unwrap();
    assert!(sessions
        .active_cell(route)
        .unwrap()
        .unwrap()
        .worker
        .get()
        .is_some());
    id
}
fn operation(sessions: &BrowserSessions, route: &str) -> OperationGuard {
    let cell = sessions.active_cell(route).unwrap().unwrap();
    let mut meta = recovered(cell.meta());
    sessions.admit(&cell, &mut meta, false)
}

#[test]
fn a_quiet_owner_blocks_without_readiness_wakeups_or_polling_reads() {
    let (process, fixture) = fixture();
    let mut worker = ConnectionWorker::start(
        process,
        Arc::new(|| true),
        Arc::new(|| panic!("quiet session reset")),
    )
    .ok()
    .unwrap();
    worker.measure(|_| ()).unwrap();
    // Even allowing one finishing WouldBlock turn, a 5 ms polling loop would
    // perform at least ten reads in this interval.
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(worker.metrics().ready_wakes.load(Ordering::Relaxed), 0);
    assert!(fixture.state.reads.load(Ordering::Relaxed) <= 2);
    worker.wait_until_reaped().unwrap();
    assert!(worker.0.join.lock().unwrap().is_none());
}

#[test]
fn a_blocked_route_does_not_hold_another_routes_worker_or_driver_lock() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (a, fixture_a) = fixture();
    let (b, fixture_b) = fixture();
    let a_id = establish(&sessions, "a", &clock, a, &fixture_a.state);
    let b_id = establish(&sessions, "b", &clock, b, &fixture_b.state);
    fixture_a.state.block_call.store(true, Ordering::Release);
    let mut a_operation = operation(&sessions, "a");
    let blocked = std::thread::spawn(move || a_operation.set_read_frames(vec![]));
    fixture_a.entered.recv_timeout(GUARD).unwrap();
    assert!(
        sessions
            .active_cell("a")
            .unwrap()
            .unwrap()
            .try_driver()
            .is_some(),
        "mailbox wait held the old driver mutex"
    );
    let (done, wait) = sync_channel(1);
    let mut b_operation = operation(&sessions, "b");
    let healthy =
        std::thread::spawn(move || done.send(b_operation.set_read_frames(vec![])).unwrap());
    assert_eq!(wait.recv_timeout(GUARD).unwrap(), Ok(()));
    assert_eq!(fixture_b.state.jobs.load(Ordering::Relaxed), 1);
    fixture_a.release.send(()).unwrap();
    assert_eq!(blocked.join().unwrap(), Ok(()));
    healthy.join().unwrap();
    assert_eq!(sessions.close("a", &a_id, &config())["outcome"], "closed");
    assert_eq!(sessions.close("b", &b_id, &config())["outcome"], "closed");
}

#[test]
fn close_expiry_and_unbind_join_one_owner_and_wait_for_worker_reap() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, fixture) = fixture();
    let id = establish(&sessions, "route", &clock, process, &fixture.state);
    fixture.state.block_reap.store(true, Ordering::Release);
    clock.0.store(2_000_000_000, Ordering::Release);
    let barrier = Arc::new(std::sync::Barrier::new(4));
    std::thread::scope(|scope| {
        for reason in 0..3 {
            let sessions = &sessions;
            let clock = &clock;
            let id = &id;
            let barrier = barrier.clone();
            scope.spawn(move || {
                barrier.wait();
                match reason {
                    0 => {
                        let _ = sessions.close("route", id, &config());
                    }
                    1 => {
                        sessions.expire_idle("route", clock, &config());
                    }
                    _ => sessions.teardown_route(
                        "route",
                        BrowserSessionTerminalOutcome::RouteUnbound,
                        &config(),
                    ),
                }
            });
        }
        barrier.wait();
        fixture.entered.recv_timeout(GUARD).unwrap();
        assert_eq!(fixture.state.cleanups.load(Ordering::Relaxed), 0);
        assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 0);
        fixture.release.send(()).unwrap();
    });
    assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.state.cleanups.load(Ordering::Relaxed), 1);
    assert!(matches!(
        sessions.accept_dispatch("route", &clock),
        DispatchAdmission::NoSession
    ));
}

#[test]
fn an_idle_wedged_owner_cannot_block_exact_kill_or_release_custody_without_ack() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, fixture) = fixture();
    fixture.state.block_idle.store(true, Ordering::Release);
    let id = establish(&sessions, "route", &clock, process, &fixture.state);
    fixture.entered.recv_timeout(GUARD).unwrap();
    let (done, wait) = sync_channel(1);
    let closing = sessions.clone();
    let close_id = id.clone();
    let close = std::thread::spawn(move || {
        done.send(closing.close("route", &close_id, &config()))
            .unwrap()
    });
    let result = wait
        .recv_timeout(GUARD)
        .expect("close waited for cooperation from the wedged idle owner");
    assert_eq!(result["outcome"], "cleanup_failure");
    assert!(fixture.state.kills.load(Ordering::Acquire) >= 1);
    assert!(!fixture.state.alive.load(Ordering::Acquire));
    assert_eq!(fixture.state.cleanups.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 0);
    assert!(matches!(
        sessions.acquire_launch_slot("route"),
        LaunchSlot::Occupied { .. } | LaunchSlot::Refused(_)
    ));
    assert!(matches!(
        sessions.accept_dispatch("route", &clock),
        DispatchAdmission::NoSession
    ));
    close.join().unwrap();
    fixture.release.send(()).unwrap();
    fixture.graceful.recv_timeout(GUARD).unwrap();
    assert_eq!(sessions.close("route", &id, &config())["outcome"], "closed");
    assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.state.cleanups.load(Ordering::Relaxed), 1);
}

fn terminal() -> Arc<crate::TerminalArbiter> {
    let frame = subc_protocol::Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        subc_protocol::FrameType::Request,
        crate::wire::control_flags(),
        9,
        3,
        1,
        serde_json::to_vec(&json!({"name":crate::browser::SCREENSHOT})).unwrap(),
    )
    .unwrap();
    Arc::new(crate::TerminalArbiter::new(frame))
}

#[test]
fn cancelled_queued_jobs_keep_their_admission_until_ack_and_never_dispatch() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, fixture) = fixture();
    let id = establish(&sessions, "route", &clock, process, &fixture.state);
    fixture.state.block_call.store(true, Ordering::Release);
    let mut first = operation(&sessions, "route");
    let active = std::thread::spawn(move || first.set_read_frames(vec![]));
    fixture.entered.recv_timeout(GUARD).unwrap();
    let terminal = terminal();
    let mut second = crate::CALL_TERMINAL.sync_scope(terminal.clone(), || {
        match sessions.accept_dispatch("route", &clock) {
            DispatchAdmission::Accepted(operation) => operation,
            _ => panic!("admission failed"),
        }
    });
    let (done, wait) = sync_channel(1);
    terminal.stop(crate::TerminalCause::Cancelled);
    let queued = std::thread::spawn(move || done.send(second.set_read_frames(vec![])).unwrap());
    assert!(matches!(
        wait.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    assert_eq!(
        recovered(sessions.active_cell("route").unwrap().unwrap().meta()).pending_operations,
        2
    );
    fixture.release.send(()).unwrap();
    assert_eq!(active.join().unwrap(), Ok(()));
    assert!(wait.recv_timeout(GUARD).unwrap().is_err());
    queued.join().unwrap();
    assert_eq!(
        fixture.state.jobs.load(Ordering::Relaxed),
        1,
        "the cancelled job reached its process adapter"
    );
    assert_eq!(
        recovered(sessions.active_cell("route").unwrap().unwrap().meta()).pending_operations,
        0
    );
    sessions.close("route", &id, &config());
}

#[test]
fn handoff_ticks_coalesce_and_expiry_cannot_be_completed_by_a_late_poll() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, fixture) = fixture();
    let id = establish(&sessions, "route", &clock, process, &fixture.state);
    let handoff = sessions
        .present("route", "https://example.test", 1000, &clock)
        .unwrap();
    let lease = sessions.lease_deadline_for_test("route").unwrap();
    clock.0.store(100_000_000, Ordering::Release);
    fixture.state.block_call.store(true, Ordering::Release);
    fixture.state.cookie_added.store(true, Ordering::Release);
    fixture
        .state
        .credential_present
        .store(false, Ordering::Release);
    let polling = sessions.clone();
    let poll_clock = clock.clone();
    let generation = handoff.generation;
    let poll =
        std::thread::spawn(move || polling.poll_handoff("route", generation, 1000, &poll_clock));
    fixture.entered.recv_timeout(GUARD).unwrap();
    let another = sessions.clone();
    let another_clock = clock.clone();
    let (coalesced, tick) = sync_channel(1);
    let second = std::thread::spawn(move || {
        coalesced
            .send(another.poll_handoff("route", generation, 1000, &another_clock))
            .unwrap()
    });
    let early_tick = tick.recv_timeout(Duration::from_millis(50));
    assert_eq!(
        recovered(sessions.active_cell("route").unwrap().unwrap().meta()).pending_operations,
        1
    );
    assert_eq!(
        sessions.lease_deadline_for_test("route"),
        Some(lease),
        "timer work renewed the person's session lease"
    );
    clock
        .0
        .store((HANDOFF_DURATION_MS + 1) * 1_000_000, Ordering::Release);
    fixture.release.send(()).unwrap();
    let result = poll.join().unwrap();
    second.join().unwrap();
    assert!(
        matches!(early_tick, Ok(HandoffPollResult::Open)),
        "a missed poll tick queued behind the active poll"
    );
    assert!(
        matches!(result, HandoffPollResult::Closed(ref closed) if closed.outcome == HandoffOutcome::Expired)
    );
    assert!(
        matches!(sessions.poll_handoff("route", generation, 1000, &clock), HandoffPollResult::Closed(ref closed) if closed.outcome == HandoffOutcome::Expired)
    );
    sessions.close("route", &id, &config());
}

#[test]
fn idle_overload_kills_the_exact_session_then_refuses_with_no_session() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, mut fixture) = fixture();
    establish(&sessions, "route", &clock, process, &fixture.state);
    let lease = sessions.lease_deadline_for_test("route");
    fixture.peer.write_all(&[255]).unwrap();
    fixture.entered.recv_timeout(GUARD).unwrap();
    assert_eq!(sessions.lease_deadline_for_test("route"), lease);
    assert_eq!(fixture.state.kills.load(Ordering::Acquire), 1);
    assert!(matches!(
        sessions.accept_dispatch("route", &clock),
        DispatchAdmission::NoSession
    ));
    sessions.observe_exits_all(&config());
    assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.state.cleanups.load(Ordering::Relaxed), 1);
    assert_eq!(
        sessions.status("route", &clock, UNIX_EPOCH)["terminal_outcome"],
        "connector_failure"
    );
}

#[test]
fn sustained_readability_resets_instead_of_retaining_an_unbounded_backlog() {
    let (process, fixture) = fixture();
    fixture.state.firehose.store(true, Ordering::Release);
    let (reset, wait) = sync_channel(1);
    let mut worker = ConnectionWorker::start(
        process,
        Arc::new(|| true),
        Arc::new(move || {
            reset.send(()).unwrap();
        }),
    )
    .ok()
    .unwrap();
    worker.0.readable_limit_ns.store(0, Ordering::Release);
    wait.recv_timeout(GUARD)
        .expect("the continuous-readability bound did not reset the connection");
    assert!(worker.0.failed.load(Ordering::Acquire));
    assert!(fixture.state.reads.load(Ordering::Relaxed) >= 16);
    fixture.state.firehose.store(false, Ordering::Release);
    worker.wait_until_reaped().unwrap();
}

#[test]
fn an_expired_handoff_generation_closes_even_when_its_cookie_job_times_out() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, fixture) = fixture();
    let id = establish(&sessions, "route", &clock, process, &fixture.state);
    sessions
        .signed_in
        .initialize_profile("route", "default", "fresh", true)
        .unwrap();
    assert!(!sessions.signed_in.has_login_evidence("route", "default"));
    let handoff = sessions
        .present("route", "https://example.test", 1000, &clock)
        .unwrap();
    fixture.state.block_call.store(true, Ordering::Release);
    fixture.state.fail_cookie.store(true, Ordering::Release);
    let polling = sessions.clone();
    let poll_clock = clock.clone();
    let poll = std::thread::spawn(move || {
        polling.poll_handoff("route", handoff.generation, 1000, &poll_clock)
    });
    fixture.entered.recv_timeout(GUARD).unwrap();
    clock
        .0
        .store((HANDOFF_DURATION_MS + 1) * 1_000_000, Ordering::Release);
    fixture.release.send(()).unwrap();
    assert!(
        matches!(poll.join().unwrap(), HandoffPollResult::Closed(ref closed) if closed.outcome == HandoffOutcome::Expired)
    );
    assert!(
        sessions.signed_in.has_login_evidence("route", "default"),
        "a failed late poll must not turn an unobserved login into a signed-out baseline"
    );
    assert!(sessions
        .signed_in
        .is_signed_in("route", "default", "https://example.test"));
    sessions.close("route", &id, &config());
}

#[test]
fn an_owner_panic_kills_and_quarantines_until_the_child_is_reaped_and_joined() {
    let (process, fixture) = fixture();
    let state = fixture.state.clone();
    let mut worker = ConnectionWorker::start(
        process,
        Arc::new(|| true),
        Arc::new(move || {
            state.kill_exact_generation();
        }),
    )
    .ok()
    .unwrap();
    assert!(worker
        .measure(|_| panic!("simulate a failed connection owner"))
        .is_err());
    fixture.entered.recv_timeout(GUARD).unwrap();
    assert!(!worker
        .0
        .join
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .is_finished());
    assert_eq!(fixture.state.reaps.load(Ordering::Acquire), 0);
    assert!(
        worker.measure(|_| ()).is_ok(),
        "process-control mailbox was lost with the protocol loop"
    );
    assert!(worker
        .invoke::<(), NavigationDriveError>(false, |_| panic!("a quarantined job was dispatched"))
        .is_err());
    worker.wait_until_reaped().unwrap();
    assert_eq!(fixture.state.kills.load(Ordering::Acquire), 1);
    assert!(!fixture.state.dropped_alive.load(Ordering::Acquire));
}

#[test]
fn an_input_observer_panic_waits_for_the_owner_ack_before_unwinding_its_caller() {
    let (process, fixture) = fixture();
    let mut worker = ConnectionWorker::start(process, Arc::new(|| true), Arc::new(|| {}))
        .ok()
        .unwrap();
    let input = worker.clone();
    let state = fixture.state.clone();
    let (done, wait) = sync_channel(1);
    let call = std::thread::spawn(move || {
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            input
                .input::<(), NavigationDriveError>(
                    &mut |_| panic!("simulate a failed input observer"),
                    move |_, dispatched| {
                        dispatched(BrowserInputEvent::Press(BrowserClickPosition {
                            x_css: 1.0,
                            y_css: 1.0,
                        }));
                        state.pause();
                        Ok(())
                    },
                )
                .unwrap();
        }));
        done.send(panic.is_err()).unwrap();
    });
    fixture.entered.recv_timeout(GUARD).unwrap();
    let early = wait.recv_timeout(Duration::from_millis(50));
    fixture.release.send(()).unwrap();
    call.join().unwrap();
    assert!(matches!(early, Err(std::sync::mpsc::RecvTimeoutError::Timeout)), "observer panic dropped the foreground caller before the connection acknowledged completion");
    assert!(wait.recv_timeout(GUARD).unwrap());
    worker.wait_until_reaped().unwrap();
}

#[test]
fn timer_jobs_do_not_erase_a_readable_streak_unless_they_reach_would_block() {
    let (mut process, _fixture) = fixture();
    let mut since = Some(Instant::now() - Duration::from_secs(31));
    run_job(process.as_mut(), Box::new(|_| {}), &mut since);
    assert!(
        since.is_some_and(|since| since.elapsed() >= Duration::from_secs(30)),
        "a timer job reset overload accounting without draining the pipe"
    );
    run_job(
        process.as_mut(),
        Box::new(|process| {
            assert!(!process.service_connection().unwrap());
        }),
        &mut since,
    );
    assert!(
        since.is_none(),
        "a foreground read reached quiet but kept the old overload streak"
    );
}

#[test]
fn the_rollout_switch_chooses_an_owner_only_when_a_session_is_created() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (a, fixture_a) = fixture();
    let a_id = establish(&sessions, "new", &clock, a, &fixture_a.state);
    let worker = sessions
        .active_cell("new")
        .unwrap()
        .unwrap()
        .worker
        .get()
        .unwrap()
        .clone();
    let sessions = sessions.with_continuous_servicing(false);
    let (b, fixture_b) = fixture();
    sessions.acquire_launch_slot("old");
    let (b_id, _, _) = sessions
        .establish_ready(
            "old",
            ProfileDisposition::Durable,
            &config(),
            &clock,
            b,
            Box::new(Cleanup(fixture_b.state.clone())),
        )
        .unwrap();
    assert!(sessions
        .active_cell("old")
        .unwrap()
        .unwrap()
        .worker
        .get()
        .is_none());
    let sessions = sessions.with_continuous_servicing(true);
    assert!(
        sessions
            .active_cell("old")
            .unwrap()
            .unwrap()
            .worker
            .get()
            .is_none(),
        "a live legacy pipe moved to a second reader"
    );
    assert!(Arc::ptr_eq(
        &worker.0,
        &sessions
            .active_cell("new")
            .unwrap()
            .unwrap()
            .worker
            .get()
            .unwrap()
            .0
    ));
    sessions.close("new", &a_id, &config());
    sessions.close("old", &b_id, &config());
}

#[test]
fn a_readiness_failure_cannot_silently_create_a_legacy_session() {
    let sessions = BrowserSessions::default();
    let clock = Clock::default();
    let (process, fixture) = fixture();
    fixture.state.fail_readiness.store(true, Ordering::Release);
    sessions.acquire_launch_slot("route");
    let Err(UnestablishedBrowser {
        mut process,
        mut cleanup,
    }) = sessions.try_establish_ready(
        "route",
        ProfileDisposition::Durable,
        &config(),
        &clock,
        process,
        Box::new(Cleanup(fixture.state.clone())),
    )
    else {
        panic!("readiness failure silently selected legacy ownership");
    };
    assert!(sessions
        .active_cell("route")
        .unwrap()
        .unwrap()
        .worker
        .get()
        .is_none());
    assert_eq!(fixture.state.reads.load(Ordering::Relaxed), 0);
    assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 0);
    process.force_terminate().unwrap();
    process.wait_until_reaped().unwrap();
    cleanup.after_reap().unwrap();
    assert_eq!(fixture.state.reaps.load(Ordering::Relaxed), 1);
    assert_eq!(fixture.state.cleanups.load(Ordering::Relaxed), 1);
}
