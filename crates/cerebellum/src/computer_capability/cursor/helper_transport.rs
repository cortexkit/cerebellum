use super::helper_health::{ExitReason, HelperGauges, HELPER_GAUGES, SCREEN_LOCKED};
use super::*;
use cerebellum_computer::pointer_query::{self, QueryProvider};
use cerebellum_macos::ProcessGeneration;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc as pipe,
};

static SHARED: OnceLock<Service> = OnceLock::new();

pub(super) fn shared() -> &'static Service {
    SHARED.get_or_init(|| Service::start(NativeLauncher, &HELPER_GAUGES))
}

pub(super) fn install_queries() {
    pointer_query::set_provider(Some(shared().provider()));
    let service = shared().clone();
    pointer_query::set_prewarm_provider(Some(Arc::new(move |deadline| service.prewarm(deadline))));
}

pub(super) fn shutdown() {
    pointer_query::set_provider(None);
    pointer_query::set_prewarm_provider(None);
    if let Some(service) = SHARED.get() {
        service.stop();
    }
}

trait Helper: Send + 'static {
    fn alive(&self) -> bool;
    fn try_wait_status(&mut self) -> Option<i32> {
        None
    }
    fn generation(&self) -> ProcessGeneration;
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()>;
    fn wait_ready(&mut self, deadline: Instant) -> Result<(), &'static str>;
    fn query(&mut self, point: [f64; 2], deadline: Instant) -> Result<Option<u32>, &'static str>;
}

trait Launcher: Send + 'static {
    type Helper: Helper;
    fn screen_unlocked(&self) -> bool;
    fn launch(&mut self, deadline: Option<Instant>) -> Result<Self::Helper, &'static str>;
    fn now(&self) -> Instant {
        Instant::now()
    }
}

pub(super) struct Written {
    pub(super) written: bool,
    pub(super) generation: Option<ProcessGeneration>,
    pub(super) failure: NoFrameReason,
}

impl Written {
    fn refused(failure: NoFrameReason) -> Self {
        Self {
            written: false,
            generation: None,
            failure,
        }
    }
}

enum Command {
    Prewarm {
        deadline: Instant,
        reply: pipe::SyncSender<Result<(), &'static str>>,
    },
    Visual {
        owner: Arc<State>,
        bytes: Vec<u8>,
        launches: bool,
        reply: pipe::SyncSender<Written>,
    },
    Query {
        point: [f64; 2],
        deadline: Instant,
        reply: pipe::SyncSender<Result<Option<u32>, &'static str>>,
    },
    ReplyReaderEnded(ProcessGeneration),
    Stop,
}

#[derive(Clone)]
pub(super) struct Service {
    tx: pipe::SyncSender<Command>,
    stopped: Arc<AtomicBool>,
}

impl Service {
    fn start<L: Launcher>(launcher: L, gauges: &'static HelperGauges) -> Self {
        let (tx, rx) = pipe::sync_channel(CAPACITY);
        let stopped = Arc::new(AtomicBool::new(false));
        let ending = stopped.clone();
        if std::thread::Builder::new()
            .name("agent-helper-transport".into())
            .spawn(move || {
                let mut worker = Worker {
                    launcher,
                    helper: None,
                    restarts: RestartLimit::default(),
                    gauges,
                };
                while let Ok(command) = rx.recv() {
                    if ending.load(Ordering::Acquire) {
                        break;
                    }
                    match command {
                        Command::Prewarm { deadline, reply } => {
                            let result = worker.ensure(true, Some(deadline)).and_then(|()| {
                                worker.helper.as_mut().unwrap().wait_ready(deadline)
                            });
                            let _ = reply.try_send(result);
                        }
                        Command::Query {
                            point,
                            deadline,
                            reply,
                        } => {
                            let result = worker.ensure(true, Some(deadline)).and_then(|()| {
                                worker.helper.as_mut().unwrap().query(point, deadline)
                            });
                            match result {
                                Err("mouse-down recipient helper disconnected") => {
                                    worker.drop_helper(ExitReason::SenderDisconnect)
                                }
                                Err("mouse-down recipient helper request write failed") => {
                                    worker.drop_helper(ExitReason::PipeWriteFailure)
                                }
                                Err("mouse-down recipient helper reply malformed") => {
                                    worker.drop_helper(ExitReason::ReplyMalformed)
                                }
                                _ => {}
                            }
                            let _ = reply.try_send(result);
                        }
                        Command::Visual {
                            owner,
                            bytes,
                            launches,
                            reply,
                        } => {
                            // Cosmetic writes retain their existing launch behavior,
                            // but reuse the same helper process and restart allowance.
                            let written = worker.write_visual(&owner, &bytes, launches);
                            let _ = reply.try_send(written);
                        }
                        Command::ReplyReaderEnded(generation) => {
                            if worker
                                .helper
                                .as_ref()
                                .is_some_and(|helper| helper.generation() == generation)
                            {
                                worker.reap_exited();
                            }
                        }
                        Command::Stop => break,
                    }
                }
                worker.drop_helper(if ending.load(Ordering::Acquire) {
                    ExitReason::Shutdown
                } else {
                    ExitReason::SenderDisconnect
                });
            })
            .is_err()
        {
            stopped.store(true, Ordering::Release);
        }
        Self { tx, stopped }
    }

    fn provider(&self) -> QueryProvider {
        let service = self.clone();
        Arc::new(move |point, deadline| service.query(point, deadline))
    }

    fn prewarm(&self, deadline: Instant) -> Result<(), &'static str> {
        if self.stopped.load(Ordering::Acquire) || Instant::now() >= deadline {
            return Err("mouse-down recipient helper launch budget exceeded");
        }
        let (reply, answer) = pipe::sync_channel(1);
        self.tx
            .try_send(Command::Prewarm { deadline, reply })
            .map_err(|_| "mouse-down recipient helper transport busy or unavailable")?;
        answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "mouse-down recipient helper launch budget exceeded")?
    }

    fn query(&self, point: [f64; 2], deadline: Instant) -> Result<Option<u32>, &'static str> {
        if self.stopped.load(Ordering::Acquire) {
            return Err("mouse-down recipient helper transport stopped");
        }
        if Instant::now() >= deadline {
            return Err("mouse-down recipient helper launch/query budget exceeded");
        }
        let (reply, answer) = pipe::sync_channel(1);
        self.tx
            .try_send(Command::Query {
                point,
                deadline,
                reply,
            })
            .map_err(|_| "mouse-down recipient helper transport busy or unavailable")?;
        let result = answer
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| "mouse-down recipient helper launch/query budget exceeded")?;
        if Instant::now() >= deadline {
            return Err("mouse-down recipient helper launch/query budget exceeded");
        }
        result
    }

    pub(super) fn write(&self, owner: &Arc<State>, line: &CursorLine) -> Written {
        let Some(bytes) = line.encode_line() else {
            return Written::refused(NoFrameReason::EncodeLine);
        };
        let (reply, answer) = pipe::sync_channel(1);
        if self.stopped.load(Ordering::Acquire)
            || self
                .tx
                .try_send(Command::Visual {
                    owner: owner.clone(),
                    bytes,
                    launches: line.launches_helper(),
                    reply,
                })
                .is_err()
        {
            return Written::refused(NoFrameReason::Transport);
        }
        answer
            .recv()
            .unwrap_or_else(|_| Written::refused(NoFrameReason::Transport))
    }

    fn stop(&self) {
        self.stopped.store(true, Ordering::Release);
        let _ = self.tx.try_send(Command::Stop);
    }
}

struct Worker<L: Launcher> {
    launcher: L,
    helper: Option<L::Helper>,
    restarts: RestartLimit,
    gauges: &'static HelperGauges,
}

impl<L: Launcher> Worker<L> {
    fn drop_helper(&mut self, cause: ExitReason) {
        if let Some(mut helper) = self.helper.take() {
            let status = helper.try_wait_status();
            self.gauges.exit(cause, status);
        }
    }

    fn reap_exited(&mut self) {
        if let Some(status) = self.helper.as_mut().and_then(Helper::try_wait_status) {
            self.gauges.exit(ExitReason::ChildExited, Some(status));
            self.helper.take();
        }
    }

    fn write_visual(&mut self, owner: &State, bytes: &[u8], launches: bool) -> Written {
        if owner.stopped.load(Ordering::Acquire) {
            return Written::refused(NoFrameReason::Stopped);
        }
        if let Err(error) = self.ensure(launches, None) {
            return Written::refused(if error == SCREEN_LOCKED {
                NoFrameReason::ScreenLockedOrUnreadable
            } else {
                NoFrameReason::HelperUnavailable
            });
        }
        if owner.stopped.load(Ordering::Acquire) {
            return Written::refused(NoFrameReason::Stopped);
        }
        let helper = self.helper.as_mut().unwrap();
        match helper.write(bytes) {
            Ok(()) => Written {
                written: true,
                generation: Some(helper.generation()),
                failure: NoFrameReason::Transport,
            },
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                self.drop_helper(ExitReason::PipeWouldBlock);
                Written::refused(NoFrameReason::PipeWouldBlock)
            }
            Err(_) => {
                self.drop_helper(ExitReason::PipeWriteFailure);
                Written::refused(NoFrameReason::PipeWrite)
            }
        }
    }

    fn ensure(&mut self, launches: bool, deadline: Option<Instant>) -> Result<(), &'static str> {
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            if launches {
                self.gauges
                    .start_failed("mouse-down recipient helper launch budget exceeded");
            }
            return Err("mouse-down recipient helper launch budget exceeded");
        }
        if !self.launcher.screen_unlocked() {
            if launches {
                self.gauges.start_failed(SCREEN_LOCKED);
            }
            return Err(SCREEN_LOCKED);
        }
        self.reap_exited();
        if self.helper.as_ref().is_some_and(|helper| !helper.alive()) {
            self.drop_helper(ExitReason::ChildUnverified);
        }
        if self.helper.is_none() {
            if !launches {
                return Err("mouse-down recipient helper unavailable");
            }
            if !self.restarts.admit(self.launcher.now()) {
                self.gauges
                    .start_failed("mouse-down recipient helper restart limit reached");
                return Err("mouse-down recipient helper restart limit reached");
            }
            let helper = self
                .launcher
                .launch(deadline)
                .inspect_err(|error| self.gauges.start_failed(error))?;
            // A slow spawn may finish after its caller has already refused.
            // Drop that child rather than retain a late startup as readiness.
            if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                self.gauges
                    .start_failed("mouse-down recipient helper launch budget exceeded");
                return Err("mouse-down recipient helper launch budget exceeded");
            }
            self.gauges.started(helper.generation());
            self.helper = Some(helper);
        }
        Ok(())
    }
}

struct NativeLauncher;
struct NativeHelper {
    child: cerebellum_macos::ReleasedChild,
    pipe: Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>>,
    client: pointer_query::Client,
}

impl Drop for NativeHelper {
    fn drop(&mut self) {
        cerebellum_macos::register_cursor_generation(None);
    }
}

impl Helper for NativeHelper {
    fn alive(&self) -> bool {
        let generation = self.child.generation();
        cerebellum_macos::process_start_time_micros(generation.pid)
            == Some(generation.start_time_micros)
    }
    fn generation(&self) -> ProcessGeneration {
        self.child.generation()
    }
    fn try_wait_status(&mut self) -> Option<i32> {
        self.child.try_wait_status()
    }
    fn wait_ready(&mut self, deadline: Instant) -> Result<(), &'static str> {
        if Instant::now() >= deadline {
            return Err("mouse-down recipient helper launch budget exceeded");
        }
        self.client
            .wait_ready(deadline.saturating_duration_since(Instant::now()))
    }
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        use std::io::Write;
        self.pipe
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .write_all(bytes)
    }
    fn query(&mut self, point: [f64; 2], deadline: Instant) -> Result<Option<u32>, &'static str> {
        if Instant::now() >= deadline {
            return Err("mouse-down recipient helper query budget exceeded");
        }
        self.client.window_at(
            point,
            deadline
                .saturating_duration_since(Instant::now())
                .min(pointer_query::QUERY_TIMEOUT),
        )
    }
}

impl Launcher for NativeLauncher {
    type Helper = NativeHelper;
    fn screen_unlocked(&self) -> bool {
        cerebellum_macos::screen_is_locked() == Some(false)
    }
    fn launch(&mut self, deadline: Option<Instant>) -> Result<NativeHelper, &'static str> {
        use pointer_query::{Client, Reply, MAX_REPLY_BYTES};
        use std::io::{BufRead, Read};
        let pinned = HELPER_EXECUTABLE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let executable = helper_launch_path(pinned.as_ref())
            .ok_or("mouse-down recipient helper pinned executable unavailable")?;
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err("mouse-down recipient helper launch budget exceeded");
        }
        let (barred, pipe, replies) =
            cerebellum_macos::spawn_barred_cursor(&executable, &["--agent-cursor".into()])
                .map_err(|_| "mouse-down recipient helper spawn failed")?;
        if !pinned
            .as_ref()
            .is_some_and(|pin| pin.accepts_child(barred.generation().pid))
        {
            HELPER_BINARY_UNAVAILABLE.store(true, Ordering::Relaxed);
            return Err("mouse-down recipient helper pinned child verification failed");
        }
        if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err("mouse-down recipient helper launch budget exceeded");
        }
        let child = barred
            .release()
            .map_err(|_| "mouse-down recipient helper release failed")?;
        drop(pinned);
        let pipe: Arc<std::sync::Mutex<Box<dyn std::io::Write + Send>>> =
            Arc::new(std::sync::Mutex::new(Box::new(std::fs::File::from(pipe))));
        let (tx, rx) = pipe::sync_channel(32);
        let generation = child.generation();
        std::thread::Builder::new()
            .name("cursor-pointer-replies".into())
            .spawn(move || {
                let mut reader = std::io::BufReader::new(std::fs::File::from(replies));
                loop {
                    let mut line = Vec::new();
                    let read = reader
                        .by_ref()
                        .take(MAX_REPLY_BYTES + 1)
                        .read_until(b'\n', &mut line);
                    if !matches!(read, Ok(1..)) {
                        break;
                    }
                    let reply =
                        if line.len() as u64 > MAX_REPLY_BYTES || line.last() != Some(&b'\n') {
                            Err("mouse-down recipient helper reply malformed")
                        } else {
                            serde_json::from_slice::<Reply>(&line)
                                .map_err(|_| "mouse-down recipient helper reply malformed")
                        };
                    let malformed = reply.is_err();
                    if tx.try_send(reply).is_err() || malformed {
                        break;
                    }
                }
                HELPER_GAUGES.reply_reader_disconnected();
                if let Some(service) = SHARED.get() {
                    let _ = service.tx.try_send(Command::ReplyReaderEnded(generation));
                }
            })
            .map_err(|_| "mouse-down recipient helper reply reader start failed")?;
        cerebellum_macos::register_cursor_generation(Some(child.generation()));
        Ok(NativeHelper {
            child,
            client: Client::new(pipe.clone(), rx),
            pipe,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    static TEST_GAUGES: HelperGauges = HelperGauges::new();

    struct Stats {
        launches: usize,
        writes: usize,
        queries: usize,
        preparations: usize,
        alive: bool,
        now: Instant,
        wait_status: Option<i32>,
        write_error: Option<std::io::ErrorKind>,
        screen_locked: Option<bool>,
        launch_fails: bool,
    }
    struct FakeLauncher {
        stats: Arc<Mutex<Stats>>,
    }
    struct FakeHelper(Arc<Mutex<Stats>>);
    impl Helper for FakeHelper {
        fn alive(&self) -> bool {
            self.0.lock().unwrap().alive
        }
        fn try_wait_status(&mut self) -> Option<i32> {
            self.0.lock().unwrap().wait_status.take()
        }
        fn generation(&self) -> ProcessGeneration {
            ProcessGeneration {
                pid: 42,
                start_time_micros: 123,
            }
        }
        fn wait_ready(&mut self, _: Instant) -> Result<(), &'static str> {
            self.0.lock().unwrap().preparations += 1;
            Ok(())
        }
        fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
            let mut stats = self.0.lock().unwrap();
            stats.writes += 1;
            stats.write_error.map_or(Ok(()), |kind| Err(kind.into()))
        }
        fn query(&mut self, _: [f64; 2], _: Instant) -> Result<Option<u32>, &'static str> {
            self.0.lock().unwrap().queries += 1;
            Ok(Some(77))
        }
    }
    impl Launcher for FakeLauncher {
        type Helper = FakeHelper;
        fn screen_unlocked(&self) -> bool {
            self.stats.lock().unwrap().screen_locked == Some(false)
        }
        fn now(&self) -> Instant {
            self.stats.lock().unwrap().now
        }
        fn launch(&mut self, _: Option<Instant>) -> Result<FakeHelper, &'static str> {
            let mut stats = self.stats.lock().unwrap();
            stats.launches += 1;
            if stats.launch_fails {
                return Err("mouse-down recipient helper pinned executable unavailable");
            }
            stats.alive = true;
            Ok(FakeHelper(self.stats.clone()))
        }
    }
    fn fixture(screen: Option<bool>, fail: bool) -> (Service, Arc<Mutex<Stats>>) {
        fixture_counting(screen, fail, &TEST_GAUGES)
    }

    fn fixture_counting(
        screen: Option<bool>,
        fail: bool,
        gauges: &'static HelperGauges,
    ) -> (Service, Arc<Mutex<Stats>>) {
        let stats = Arc::new(Mutex::new(Stats {
            launches: 0,
            writes: 0,
            queries: 0,
            preparations: 0,
            alive: false,
            now: Instant::now(),
            wait_status: None,
            write_error: None,
            screen_locked: screen,
            launch_fails: fail,
        }));
        (
            Service::start(
                FakeLauncher {
                    stats: stats.clone(),
                },
                gauges,
            ),
            stats,
        )
    }
    fn deadline() -> Instant {
        Instant::now() + Duration::from_millis(50)
    }

    #[test]
    fn health_distinguishes_a_refused_launch_from_a_child_exit() {
        static GAUGES: HelperGauges = HelperGauges::new();
        let (refusing, _) = fixture_counting(Some(false), true, &GAUGES);
        assert!(refusing.prewarm(deadline()).is_err());
        assert!(refusing.prewarm(deadline()).is_err());
        refusing.stop();

        let (service, stats) = fixture_counting(Some(false), false, &GAUGES);
        assert_eq!(service.prewarm(deadline()), Ok(()));
        stats.lock().unwrap().wait_status = Some(7 << 8);
        assert!(service.prewarm(deadline()).is_err());
        let report = GAUGES.report();
        assert_eq!(report["cursorHelperStartOutcomes"]["pin_failure"], 1);
        assert_eq!(report["cursorHelperStartOutcomes"]["started"], 1);
        assert_eq!(report["cursorHelperStartOutcomes"]["restart_limit"], 2);
        assert_eq!(report["cursorHelperLastStartFailure"], "restart_limit");
        assert_eq!(report["cursorHelperExitReasons"]["child_exited"], 1);
        assert_eq!(report["cursorHelperLastWaitStatus"], 7 << 8);
        assert!(report["cursorHelperPid"].is_null());
        service.stop();
    }

    #[test]
    fn prewarmed_helper_is_reused_by_the_bracket_query_without_drawing() {
        let (service, stats) = fixture(Some(false), false);
        assert_eq!(service.prewarm(deadline()), Ok(()));
        {
            let stats = stats.lock().unwrap();
            assert_eq!(stats.launches, 1);
            assert_eq!(stats.preparations, 1);
            assert_eq!(stats.queries, 0);
            assert_eq!(stats.writes, 0);
        }
        assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
        let stats = stats.lock().unwrap();
        assert_eq!(
            stats.launches, 1,
            "the bracket must reuse the prepared child"
        );
        assert_eq!(stats.queries, 1);
        assert_eq!(stats.writes, 0);
        service.stop();
    }

    #[test]
    fn failed_prewarm_preserves_the_restart_limit_and_query_refusal() {
        let (service, stats) = fixture(Some(false), true);
        assert_eq!(
            service.prewarm(deadline()),
            Err("mouse-down recipient helper pinned executable unavailable")
        );
        assert_eq!(
            service.query([10.0, 20.0], deadline()),
            Err("mouse-down recipient helper restart limit reached")
        );
        let stats = stats.lock().unwrap();
        assert_eq!(stats.launches, 1);
        assert_eq!(stats.queries, 0);
        assert_eq!(stats.writes, 0);
        service.stop();
    }

    #[test]
    fn pointer_query_launches_without_a_badge_even_when_cursor_drawing_is_off() {
        for drawing in [false, true] {
            let (cursor, mut visual_lines) = Coordinator::channel();
            cursor.enable(drawing);
            assert_eq!(cursor.enabled(), drawing);
            while visual_lines.try_recv().is_ok() {}
            let (service, stats) = fixture(Some(false), false);
            let query = service.provider();
            assert_eq!(query([10.0, 20.0], deadline()), Ok(Some(77)));
            cursor.end("agent-with-no-badge");
            assert_eq!(query([10.0, 20.0], deadline()), Ok(Some(77)));
            let stats = stats.lock().unwrap();
            assert_eq!((stats.launches, stats.queries, stats.writes), (1, 2, 0));
            assert!(
                !matches!(visual_lines.try_recv(), Ok(line) if !matches!(line, CursorLine::Hide(_)))
            );
            service.stop();
        }
    }

    #[test]
    fn pointer_query_launch_failure_names_the_failed_step() {
        let (service, stats) = fixture(Some(false), true);
        assert_eq!(
            service.query([10.0, 20.0], deadline()),
            Err("mouse-down recipient helper pinned executable unavailable")
        );
        assert_eq!(stats.lock().unwrap().launches, 1);
        assert_eq!(stats.lock().unwrap().queries, 0);
        service.stop();
    }

    #[test]
    fn locked_or_unreadable_screen_never_launches_a_query_helper() {
        for screen in [None, Some(true)] {
            let (service, stats) = fixture(screen, false);
            assert_eq!(
                service.prewarm(deadline()),
                Err("mouse-down recipient helper screen locked or unreadable")
            );
            assert_eq!(
                service.query([10.0, 20.0], deadline()),
                Err("mouse-down recipient helper screen locked or unreadable")
            );
            assert_eq!(stats.lock().unwrap().launches, 0);
            service.stop();
        }
    }

    #[test]
    fn next_preview_retries_after_unlock_without_spending_a_launch_attempt_while_locked() {
        let (service, stats) = fixture(Some(true), false);
        let owner = Arc::new(State::default());
        let line = CursorLine::Preview(CursorPreview {
            preview_agent: "agent".into(),
            preview_generation: 1,
            preview_slot: 0,
            preview_window: 12,
            preview_app: "TextEdit".into(),
            preview_aspect: [100.0, 100.0],
            preview_label: None,
            preview_fallback: None,
            preview_icon_path: None,
        });
        let locked = service.write(&owner, &line);
        assert!(!locked.written);
        assert_eq!(locked.failure, NoFrameReason::ScreenLockedOrUnreadable);
        assert_eq!(stats.lock().unwrap().launches, 0);
        stats.lock().unwrap().screen_locked = Some(false);
        assert!(service.write(&owner, &line).written);
        assert_eq!(stats.lock().unwrap().launches, 1);
        service.stop();
    }

    #[test]
    fn repeated_failed_launches_retry_on_demand_after_the_cause_is_gone() {
        let (service, stats) = fixture(Some(false), true);
        for _ in 0..2 {
            assert_eq!(
                service.prewarm(deadline()),
                Err("mouse-down recipient helper pinned executable unavailable")
            );
            assert_eq!(
                service.prewarm(deadline()),
                Err("mouse-down recipient helper restart limit reached")
            );
            stats.lock().unwrap().now += Duration::from_secs(60);
        }
        assert_eq!(stats.lock().unwrap().launches, 2);
        stats.lock().unwrap().launch_fails = false;
        assert_eq!(service.prewarm(deadline()), Ok(()));
        assert_eq!(stats.lock().unwrap().launches, 3);
        service.stop();
    }

    #[test]
    fn queries_and_visuals_share_the_same_child_and_restart_limit() {
        let (service, stats) = fixture(Some(false), false);
        assert!(
            service
                .write(
                    &Arc::new(State::default()),
                    &CursorLine::Picture(CursorEvent {
                        agent: "agent".into(),
                        initial: 'A',
                        to: [10.0, 20.0],
                        target: None,
                        window: None,
                        resting: true,
                        label: None,
                        kind: CursorKind::Reading,
                        serial: 1,
                        avatar_rgba: None,
                        avatar_update: false,
                        avatar_tint: None,
                        motion: PictureMotion::still(),
                    })
                )
                .written
        );
        assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
        {
            let mut stats = stats.lock().unwrap();
            assert_eq!(stats.launches, 1);
            stats.alive = false;
            stats.now += Duration::from_secs(61);
        }
        assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
        {
            let mut stats = stats.lock().unwrap();
            assert_eq!(stats.launches, 2);
            stats.alive = false;
        }
        assert_eq!(
            service.query([10.0, 20.0], deadline()),
            Err("mouse-down recipient helper restart limit reached")
        );
        assert_eq!(stats.lock().unwrap().launches, 2);
        stats.lock().unwrap().now += Duration::from_secs(60);
        assert_eq!(service.query([10.0, 20.0], deadline()), Ok(Some(77)));
        assert_eq!(stats.lock().unwrap().launches, 3);
        service.stop();
    }

    #[test]
    fn an_expired_fronting_budget_never_starts_a_helper() {
        let (service, stats) = fixture(Some(false), false);
        assert_eq!(
            service.query([10.0, 20.0], Instant::now()),
            Err("mouse-down recipient helper launch/query budget exceeded")
        );
        assert_eq!(stats.lock().unwrap().launches, 0);
        service.stop();
    }

    #[test]
    fn slow_launch_cannot_extend_the_call_budget_or_issue_a_late_query() {
        slow_launch(false);
    }

    #[test]
    fn timed_out_prewarm_leaves_the_later_query_fail_closed() {
        slow_launch(true);
    }

    fn slow_launch(prewarm: bool) {
        struct SlowLauncher {
            started: pipe::SyncSender<()>,
            release: pipe::Receiver<()>,
            dropped: pipe::SyncSender<()>,
            queries: Arc<std::sync::atomic::AtomicUsize>,
        }
        struct LateHelper(pipe::SyncSender<()>, Arc<std::sync::atomic::AtomicUsize>);
        impl Drop for LateHelper {
            fn drop(&mut self) {
                let _ = self.0.try_send(());
            }
        }
        impl Helper for LateHelper {
            fn alive(&self) -> bool {
                true
            }
            fn wait_ready(&mut self, _: Instant) -> Result<(), &'static str> {
                panic!("late helper must be dropped before readiness")
            }
            fn generation(&self) -> ProcessGeneration {
                ProcessGeneration {
                    pid: 42,
                    start_time_micros: 123,
                }
            }
            fn write(&mut self, _: &[u8]) -> std::io::Result<()> {
                panic!("no visual command")
            }
            fn query(&mut self, _: [f64; 2], _: Instant) -> Result<Option<u32>, &'static str> {
                self.1.fetch_add(1, Ordering::Relaxed);
                Ok(Some(77))
            }
        }
        impl Launcher for SlowLauncher {
            type Helper = LateHelper;
            fn screen_unlocked(&self) -> bool {
                true
            }
            fn launch(&mut self, _: Option<Instant>) -> Result<LateHelper, &'static str> {
                self.started.send(()).unwrap();
                self.release.recv().unwrap();
                Ok(LateHelper(self.dropped.clone(), self.queries.clone()))
            }
        }
        let (start, started) = pipe::sync_channel(1);
        let (release, released) = pipe::sync_channel(1);
        let (drop, dropped) = pipe::sync_channel(1);
        let queries = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let service = Service::start(
            SlowLauncher {
                started: start,
                release: released,
                dropped: drop,
                queries: queries.clone(),
            },
            &TEST_GAUGES,
        );
        let query = service.clone();
        let call = std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_millis(100);
            if prewarm {
                query.prewarm(deadline)
            } else {
                query.query([10.0, 20.0], deadline).map(|_| ())
            }
        });
        started.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(
            call.join().unwrap(),
            Err(if prewarm {
                "mouse-down recipient helper launch budget exceeded"
            } else {
                "mouse-down recipient helper launch/query budget exceeded"
            })
        );
        release.send(()).unwrap();
        dropped.recv_timeout(Duration::from_secs(1)).unwrap();
        if prewarm {
            assert_eq!(
                service.query([10.0, 20.0], deadline()),
                Err("mouse-down recipient helper restart limit reached")
            );
        }
        assert_eq!(queries.load(Ordering::Relaxed), 0);
        service.stop();
    }
}
