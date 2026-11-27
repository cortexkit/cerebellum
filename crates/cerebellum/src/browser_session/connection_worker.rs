//! A session-local owner. Mailboxes carry operations, never protocol frames.

use super::*;
use std::os::fd::OwnedFd;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::JoinHandle;
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;

type Job = Box<dyn FnOnce(&mut dyn OwnedBrowserProcess) + Send>;

#[derive(Default)]
pub struct WorkerMetrics {
    pub ready_wakes: AtomicU64,
    pub idle_turns: AtomicU64,
    pub longest_quantum_ns: AtomicU64,
    pub longest_readable_streak_ns: AtomicU64,
}

struct Shared {
    jobs: mpsc::Sender<Job>,
    control: mpsc::Sender<Job>,
    stop: AtomicBool,
    reaped: AtomicBool,
    failed: AtomicBool,
    join: Mutex<Option<JoinHandle<()>>>,
    metrics: Arc<WorkerMetrics>,
    killer: Option<Arc<dyn BrowserKiller>>,
    exit: Option<Arc<dyn BrowserExitProbe>>,
    admits: Arc<dyn Fn() -> bool + Send + Sync>,
    failure: Arc<dyn Fn() + Send + Sync>,
    readable_limit_ns: AtomicU64,
}

impl Shared {
    fn fail(&self) {
        if !self.failed.swap(true, Ordering::AcqRel) {
            (self.failure)();
        }
    }
}

struct OwnerExit(std::sync::Weak<Shared>);
impl Drop for OwnerExit {
    fn drop(&mut self) {
        if let Some(state) = self.0.upgrade() {
            if !state.stop.load(Ordering::Acquire) {
                state.fail();
            }
        }
    }
}

/// Cloneable command handle; it never contains, reads, or writes the pipe.
#[derive(Clone)]
pub struct ConnectionWorker(Arc<Shared>);

pub enum StartFailure {
    Unsupported(Box<dyn OwnedBrowserProcess>),
    Unavailable(Box<dyn OwnedBrowserProcess>),
}

impl ConnectionWorker {
    pub fn start(
        process: Box<dyn OwnedBrowserProcess>,
        admits: Arc<dyn Fn() -> bool + Send + Sync>,
        failed: Arc<dyn Fn() + Send + Sync>,
    ) -> Result<Self, StartFailure> {
        let fd = match process.connection_readiness() {
            Ok(Some(fd)) => fd,
            Ok(None) => return Err(StartFailure::Unsupported(process)),
            Err(_) => return Err(StartFailure::Unavailable(process)),
        };
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
        {
            Ok(runtime) => runtime,
            Err(_) => return Err(StartFailure::Unavailable(process)),
        };
        let readiness = {
            let _entered = runtime.enter();
            // Tokio 1.53.3 deprecated its safe constructors in favour of unsafe
            // register; cerebellum forbids unsafe code. This use remains sound:
            // AsyncFd takes ownership of an OwnedFd that is never replaced or
            // closed elsewhere. Retain the existing READABLE | WRITABLE interests.
            #[allow(deprecated)]
            match AsyncFd::new(fd) {
                Ok(readiness) => readiness,
                Err(_) => return Err(StartFailure::Unavailable(process)),
            }
        };
        let (jobs, mut rx) = mpsc::channel(1);
        let (control, mut controls) = mpsc::channel(1);
        let shared = Arc::new(Shared {
            jobs,
            control,
            stop: AtomicBool::new(false),
            reaped: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            join: Mutex::new(None),
            metrics: Arc::new(WorkerMetrics::default()),
            killer: process.shutdown_killer(),
            exit: process.exit_probe(),
            admits,
            failure: Arc::clone(&failed),
            readable_limit_ns: AtomicU64::new(30_000_000_000),
        });
        // Retain custody if thread creation fails: the caller gets the original
        // process back, rather than dropping an unreaped browser in spawn's closure.
        let pending = Arc::new(Mutex::new(Some(process)));
        let take = Arc::clone(&pending);
        let weak = Arc::downgrade(&shared);
        let metrics = Arc::clone(&shared.metrics);
        let thread = std::thread::Builder::new()
            .name("browser-connection".into())
            .spawn(move || {
                let mut process = take.lock().unwrap().take().unwrap();
                // Mark failure before the process destructor can wait on a child.
                let _exit = OwnerExit(weak.clone());
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    process.enable_connection_service();
                    runtime.block_on(run(
                        process.as_mut(),
                        readiness,
                        &mut rx,
                        &mut controls,
                        weak.clone(),
                        metrics,
                    ));
                }));
                if result.is_err() {
                    if let Some(state) = weak.upgrade() {
                        state.fail();
                    }
                    // Protocol state may be partial after a panic. Only reject
                    // queued calls and accept process-control/reap jobs from here.
                    runtime.block_on(finish_failed(
                        process.as_mut(),
                        &mut rx,
                        &mut controls,
                        weak,
                    ));
                }
            });
        match thread {
            Ok(thread) => {
                *shared.join.lock().unwrap() = Some(thread);
                Ok(Self(shared))
            }
            Err(_) => Err(StartFailure::Unavailable(
                pending.lock().unwrap().take().unwrap(),
            )),
        }
    }

    pub fn metrics(&self) -> Arc<WorkerMetrics> {
        Arc::clone(&self.0.metrics)
    }

    /// Internal probe hook; executes on the owner rather than sampling the
    /// waiting caller's CPU clock. It adds no browser capability or tool.
    pub fn measure<T: Send + 'static>(
        &self,
        sample: impl FnOnce(&mut dyn OwnedBrowserProcess) -> T + Send + 'static,
    ) -> Result<T, NavigationDriveError> {
        self.invoke(true, move |process| Ok(sample(process)))
    }

    pub(super) fn invoke<T: Send + 'static, E: WorkerError>(
        &self,
        control: bool,
        call: impl FnOnce(&mut dyn OwnedBrowserProcess) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E> {
        self.invoke_until(control, None, call)
    }

    fn invoke_until<T: Send + 'static, E: WorkerError>(
        &self,
        control: bool,
        deadline: Option<Instant>,
        call: impl FnOnce(&mut dyn OwnedBrowserProcess) -> Result<T, E> + Send + 'static,
    ) -> Result<T, E> {
        let context = drive_context();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let shared = Arc::clone(&self.0);
        let job = Box::new(move |process: &mut dyn OwnedBrowserProcess| {
            if !control
                && !shared.failed.load(Ordering::Acquire)
                && process.service_connection().is_err()
            {
                shared.fail();
            }
            let result = if !control
                && (shared.failed.load(Ordering::Acquire)
                    || !(shared.admits)()
                    || context
                        .as_ref()
                        .and_then(|c| c.terminal.as_ref())
                        .is_some_and(|terminal| terminal.gate.stopped()))
            {
                Err(E::unavailable())
            } else {
                let _scope =
                    context.map(|context| DriveScope::enter(context.terminal, &context.watch));
                call(process)
            };
            let _ = tx.send(result);
        });
        let sender = if control {
            &self.0.control
        } else {
            &self.0.jobs
        };
        if control {
            sender.try_send(job).map_err(|_| E::unavailable())?;
        } else {
            sender.blocking_send(job).map_err(|_| E::unavailable())?;
        }
        // The caller retains its OperationGuard, lane and permits until the owner
        // acknowledges completion, including cancellation and paired input release.
        if control {
            let deadline = deadline.unwrap_or_else(|| {
                Instant::now() + Duration::from_millis(crate::budgets::EXIT_OBSERVATION_MS)
            });
            rx.recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .map_err(|_| {
                    self.0.fail();
                    E::unavailable()
                })?
        } else {
            rx.recv().map_err(|_| E::unavailable())?
        }
    }

    fn stop_and_join(&self) -> Result<(), ProcessControlFailure> {
        if let Some(thread) = self.0.join.lock().unwrap().take() {
            thread
                .join()
                .map_err(|_| ProcessControlFailure::new(ProcessControlStep::ReapWait))?;
        }
        Ok(())
    }
}

async fn run(
    process: &mut dyn OwnedBrowserProcess,
    readiness: AsyncFd<OwnedFd>,
    jobs: &mut mpsc::Receiver<Job>,
    controls: &mut mpsc::Receiver<Job>,
    shared: std::sync::Weak<Shared>,
    metrics: Arc<WorkerMetrics>,
) {
    let mut unhealthy = false;
    let mut readable_since = None;
    loop {
        if shared
            .upgrade()
            .is_none_or(|state| state.stop.load(Ordering::Acquire))
        {
            break;
        }
        if let Ok(job) = controls.try_recv() {
            run_job(process, job, &mut readable_since);
        } else if let Ok(job) = jobs.try_recv() {
            run_job(process, job, &mut readable_since);
        }
        let Some(state) = shared.upgrade() else { break };
        if state.stop.load(Ordering::Acquire) {
            break;
        }
        let readable_limit = Duration::from_nanos(state.readable_limit_ns.load(Ordering::Acquire));
        drop(state);
        if !unhealthy {
            let started = Instant::now();
            let mut progress = true;
            let mut read_any = false;
            // One existing read per turn, at most sixteen reads (1 MiB) or
            // two milliseconds before the independent control path is revisited.
            for _ in 0..16 {
                metrics.idle_turns.fetch_add(1, Ordering::Relaxed);
                match process.service_connection() {
                    Ok(true) => {
                        read_any = true;
                        readable_since.get_or_insert(started);
                    }
                    Ok(false) => {
                        progress = false;
                        break;
                    }
                    Err(_) => {
                        unhealthy = true;
                        break;
                    }
                }
                if started.elapsed() >= Duration::from_millis(2) {
                    break;
                }
            }
            metrics.longest_quantum_ns.fetch_max(
                started.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                Ordering::Relaxed,
            );
            if read_any || readable_since.is_some() {
                if let Some(since) = readable_since {
                    metrics.longest_readable_streak_ns.fetch_max(
                        since.elapsed().as_nanos().min(u64::MAX as u128) as u64,
                        Ordering::Relaxed,
                    );
                }
            }
            if progress {
                let since = readable_since.get_or_insert(started);
                if since.elapsed() >= readable_limit {
                    unhealthy = true;
                }
            } else {
                readable_since = None;
            }
            if unhealthy {
                if let Some(state) = shared.upgrade() {
                    state.fail();
                }
            } else if progress {
                continue;
            }
        }
        tokio::select! {
            biased;
            job = controls.recv() => match job { Some(job) => run_job(process, job, &mut readable_since), None => break },
            job = jobs.recv() => match job { Some(job) => run_job(process, job, &mut readable_since), None => break },
            ready = readiness.readable(), if !unhealthy => {
                match ready {
                    Ok(mut guard) => { guard.clear_ready(); metrics.ready_wakes.fetch_add(1, Ordering::Relaxed); }
                    Err(_) => { unhealthy = true; if let Some(state) = shared.upgrade() { state.fail(); } }
                }
            }
        }
    }
}

fn run_job(process: &mut dyn OwnedBrowserProcess, job: Job, readable_since: &mut Option<Instant>) {
    let quiet_epoch = process.connection_quiet_epoch();
    let started = Instant::now();
    job(process);
    if quiet_epoch != process.connection_quiet_epoch() {
        *readable_since = None;
    } else if let Some(since) = readable_since {
        // Exclude foreground execution from the idle overload allowance.
        // Running a job does not prove unread input was drained; only an
        // observed WouldBlock clears the streak.
        *since += started.elapsed();
    }
}

async fn finish_failed(
    process: &mut dyn OwnedBrowserProcess,
    jobs: &mut mpsc::Receiver<Job>,
    controls: &mut mpsc::Receiver<Job>,
    shared: std::sync::Weak<Shared>,
) {
    loop {
        if shared
            .upgrade()
            .is_none_or(|state| state.stop.load(Ordering::Acquire))
        {
            break;
        }
        let job = tokio::select! {
            biased;
            job = controls.recv() => job,
            job = jobs.recv() => job,
        };
        let Some(job) = job else {
            break;
        };
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| job(process)));
    }
}

pub(super) trait WorkerError: Send + 'static {
    fn unavailable() -> Self;
}
impl WorkerError for NavigationDriveError {
    fn unavailable() -> Self {
        Self::Unavailable
    }
}
impl WorkerError for ClickDriveError {
    fn unavailable() -> Self {
        Self::Navigation(NavigationDriveError::Unavailable)
    }
}
impl WorkerError for ClickPointDriveError {
    fn unavailable() -> Self {
        Self::Navigation(NavigationDriveError::Unavailable)
    }
}
impl WorkerError for ProcessControlFailure {
    fn unavailable() -> Self {
        Self::new(ProcessControlStep::ReapWait)
    }
}

// Each adapter copies only capability arguments into a bounded operation job.
// Borrowed callbacks stay on the waiting caller's thread and are acknowledged
// before the owner continues, so the caller records each dispatched mouse press
// and its paired release in browser state before any subsequent owner action.
macro_rules! forward {
    (fn $name:ident(&mut self $(, $arg:ident : $ty:ty)*) -> $result:ty;
     $prep:block => $call:expr) => {
        #[allow(clippy::too_many_arguments)]
        fn $name(&mut self $(, $arg: $ty)*) -> $result {
            let call = $prep;
            self.invoke(false, bind(call, $call))
        }
    };
}

fn bind<A, R>(args: A, factory: impl FnOnce(A) -> R) -> R {
    factory(args)
}

impl ConnectionWorker {
    fn input<T: Send + 'static, E: WorkerError>(
        &self,
        callback: &mut dyn FnMut(BrowserInputEvent),
        call: impl FnOnce(&mut dyn OwnedBrowserProcess, &mut dyn FnMut(BrowserInputEvent)) -> Result<T, E>
            + Send
            + 'static,
    ) -> Result<T, E> {
        enum Reply<T, E> {
            Input(BrowserInputEvent, std::sync::mpsc::SyncSender<()>),
            Done(Result<T, E>),
        }
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        let context = drive_context();
        let state = Arc::clone(&self.0);
        self.0
            .jobs
            .blocking_send(Box::new(move |driver| {
                if !state.failed.load(Ordering::Acquire) && driver.service_connection().is_err() {
                    state.fail();
                }
                if state.failed.load(Ordering::Acquire)
                    || !(state.admits)()
                    || context
                        .as_ref()
                        .and_then(|c| c.terminal.as_ref())
                        .is_some_and(|terminal| terminal.gate.stopped())
                {
                    let _ = tx.send(Reply::Done(Err(E::unavailable())));
                    return;
                }
                let _scope =
                    context.map(|context| DriveScope::enter(context.terminal, &context.watch));
                let result = call(driver, &mut |event| {
                    let (ack, wait) = std::sync::mpsc::sync_channel(0);
                    if tx.send(Reply::Input(event, ack)).is_ok() {
                        let _ = wait.recv();
                    }
                });
                let _ = tx.send(Reply::Done(result));
            }))
            .map_err(|_| E::unavailable())?;
        let mut callback_panic = None;
        let result = loop {
            match rx.recv() {
                Ok(Reply::Input(event, ack)) => {
                    if callback_panic.is_none() {
                        callback_panic =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                callback(event)
                            }))
                            .err();
                        if callback_panic.is_some() {
                            self.0.fail();
                        }
                    }
                    let _ = ack.send(());
                }
                Ok(Reply::Done(result)) => break result,
                Err(_) => break Err(E::unavailable()),
            }
        };
        // An observing callback may panic, but it must not drop the operation's
        // permits while the owner can still be dispatching or releasing input.
        if let Some(panic) = callback_panic {
            std::panic::resume_unwind(panic);
        }
        result
    }
}

#[cfg(test)]
#[path = "connection_worker_tests.rs"]
mod tests;

impl OwnedBrowserProcess for ConnectionWorker {
    fn has_unjoined_connection_owner(&self) -> bool {
        self.0
            .join
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .is_some()
    }
    fn connection_metadata(&mut self) -> crate::browser::navigation::ConnectionMetadata {
        self.invoke(true, |p| {
            Ok::<_, NavigationDriveError>(p.connection_metadata())
        })
        .unwrap_or_default()
    }
    forward!(fn present(&mut self, context: &str, deadline: u64) -> Result<(), NavigationDriveError>;
        { (context.to_owned(), deadline) } => |(context, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.present(&context, deadline));
    forward!(fn cookie_names_for_origin(&mut self, context: &str, origin: &str, deadline: u64) -> Result<BTreeSet<String>, NavigationDriveError>;
        { (context.to_owned(), origin.to_owned(), deadline) } => |(context, origin, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.cookie_names_for_origin(&context, &origin, deadline));
    forward!(fn main_frame_url(&mut self, context: &str, deadline: u64) -> Result<String, NavigationDriveError>;
        { (context.to_owned(), deadline) } => |(context, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.main_frame_url(&context, deadline));
    forward!(fn committed_document(&mut self, context: &str, deadline: u64) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError>;
        { (context.to_owned(), deadline) } => |(context, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.committed_document(&context, deadline));
    forward!(fn has_credential_field(&mut self, context: &str, deadline: u64) -> Result<bool, NavigationDriveError>;
        { (context.to_owned(), deadline) } => |(context, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.has_credential_field(&context, deadline));

    fn navigate(
        &mut self,
        context: &str,
        url: &str,
        wait: NavigationWait,
        deadline: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let (context, url, mut owned) = (context.to_owned(), url.to_owned(), tracker.clone());
        let (result, updated) = self.invoke(false, move |p| {
            let result = p.navigate(&context, &url, wait, deadline, &mut owned);
            Ok::<_, NavigationDriveError>((result, owned))
        })?;
        *tracker = updated;
        result
    }
    forward!(fn snapshot(&mut self, context: &str, mode: SnapshotKind, deadline: u64) -> Result<BrowserSnapshotObservation, NavigationDriveError>;
        { (context.to_owned(), mode, deadline) } => |(context, mode, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.snapshot(&context, mode, deadline));
    forward!(fn snapshot_classified(&mut self, context: &str, mode: SnapshotKind, epoch: u64, origin: &str, deadline: u64) -> Result<BrowserSnapshotObservation, NavigationDriveError>;
        { (context.to_owned(), mode, epoch, origin.to_owned(), deadline) } => |(context, mode, epoch, origin, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.snapshot_classified(&context, mode, epoch, &origin, deadline));
    forward!(fn snapshot_subtree_classified(&mut self, context: &str, mode: SnapshotKind, reference: &crate::snapshot_store::RefRecord, epoch: u64, origin: &str, deadline: u64) -> Result<BrowserSnapshotObservation, NavigationDriveError>;
        { (context.to_owned(), mode, reference.clone(), epoch, origin.to_owned(), deadline) } => |(context, mode, reference, epoch, origin, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.snapshot_subtree_classified(&context, mode, &reference, epoch, &origin, deadline));
    #[allow(clippy::too_many_arguments)]
    fn snapshot_protected(
        &mut self,
        context: &str,
        mode: SnapshotKind,
        reference: Option<&crate::snapshot_store::RefRecord>,
        epoch: u64,
        origin: &str,
        filled: &[BackendNodeIdentity],
        deadline: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let (context, reference, origin, filled) = (
            context.to_owned(),
            reference.cloned(),
            origin.to_owned(),
            filled.to_vec(),
        );
        self.invoke(false, move |p| {
            p.snapshot_protected(
                &context,
                mode,
                reference.as_ref(),
                epoch,
                &origin,
                &filled,
                deadline,
            )
        })
    }
    forward!(fn frame_documents(&mut self, context: &str, deadline: u64) -> Result<Vec<crate::snapshot_store::FrameDocument>, NavigationDriveError>;
        { (context.to_owned(), deadline) } => |(context, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.frame_documents(&context, deadline));
    forward!(fn set_read_frames(&mut self, frames: Vec<crate::snapshot_store::FrameDocument>) -> Result<(), NavigationDriveError>;
        { frames } => |frames| move |p: &mut dyn OwnedBrowserProcess| p.set_read_frames(frames));
    forward!(fn prepare_frame(&mut self, context: &str, frame: &crate::snapshot_store::FrameDocument, deadline: u64) -> Result<bool, NavigationDriveError>;
        { (context.to_owned(), frame.clone(), deadline) } => |(context, frame, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.prepare_frame(&context, &frame, deadline));
    fn point_frame_document(&mut self) -> Option<crate::snapshot_store::FrameDocument> {
        self.invoke(false, |p| {
            Ok::<_, NavigationDriveError>(p.point_frame_document())
        })
        .ok()
        .flatten()
    }
    forward!(fn scroll(&mut self, context: &str, target: &BrowserScrollTarget, deadline: u64) -> Result<(), NavigationDriveError>;
        { (context.to_owned(), target.clone(), deadline) } => |(context, target, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.scroll(&context, &target, deadline));
    forward!(fn screenshot(&mut self, context: &str, epoch: u64, deadline: u64, full: bool, max_bytes: usize) -> Result<BrowserScreenshotObservation, NavigationDriveError>;
        { (context.to_owned(), epoch, deadline, full, max_bytes) } => |(context, epoch, deadline, full, max_bytes)| move |p: &mut dyn OwnedBrowserProcess| p.screenshot(&context, epoch, deadline, full, max_bytes));

    fn click(
        &mut self,
        context: &str,
        identity: &BackendNodeIdentity,
        deadline: u64,
        callback: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let (context, identity) = (context.to_owned(), identity.clone());
        self.input(callback, move |p, callback| {
            p.click(&context, &identity, deadline, callback)
        })
    }
    forward!(fn classify_point(&mut self, context: &str, position: BrowserClickPosition, epoch: u64, url: &str, deadline: u64) -> Result<Result<crate::classification::NonTypeClassificationRecord, crate::classification::ClassificationUnavailable>, NavigationDriveError>;
        { (context.to_owned(), position, epoch, url.to_owned(), deadline) } => |(context, position, epoch, url, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.classify_point(&context, position, epoch, &url, deadline));
    #[allow(clippy::too_many_arguments)]
    fn click_point_classified(
        &mut self,
        context: &str,
        position: BrowserClickPosition,
        epoch: u64,
        url: &str,
        expected: &crate::classification::NonTypeClassificationRecord,
        deadline: u64,
        callback: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let (context, url, expected) = (context.to_owned(), url.to_owned(), expected.clone());
        self.input(callback, move |p, callback| {
            p.click_point_classified(
                &context, position, epoch, &url, &expected, deadline, callback,
            )
        })
    }
    fn click_point(
        &mut self,
        context: &str,
        position: BrowserClickPosition,
        deadline: u64,
        callback: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        let context = context.to_owned();
        self.input(callback, move |p, callback| {
            p.click_point(&context, position, deadline, callback)
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn click_classified(
        &mut self,
        context: &str,
        identity: &BackendNodeIdentity,
        epoch: u64,
        origin: &str,
        expected: Option<&crate::classification::NonTypeClassificationRecord>,
        deadline: u64,
        callback: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let (context, identity, origin, expected) = (
            context.to_owned(),
            identity.clone(),
            origin.to_owned(),
            expected.cloned(),
        );
        self.input(callback, move |p, callback| {
            p.click_classified(
                &context,
                &identity,
                epoch,
                &origin,
                expected.as_ref(),
                deadline,
                callback,
            )
        })
    }
    fn press_key_classified(
        &mut self,
        context: &str,
        target: &crate::browser::keys::KeyTarget,
        deadline: u64,
        callback: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        let (context, target) = (context.to_owned(), target.clone());
        self.input(callback, move |p, callback| {
            p.press_key_classified(&context, &target, deadline, callback)
        })
    }
    forward!(fn type_classified(&mut self, context: &str, target: &crate::browser_type::TypeDispatch, text: &str, clear: bool, deadline: u64) -> Result<crate::browser_type::BrowserTypeResult, NavigationDriveError>;
        { (context.to_owned(), target.clone(), zeroize::Zeroizing::new(text.to_owned()), clear, deadline) } => |(context, target, text, clear, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.type_classified(&context, &target, &text, clear, deadline));
    forward!(fn check_fill_login(&mut self, context: &str, dispatch: &crate::browser::fill::FillDispatch, deadline: u64) -> Result<Option<&'static str>, NavigationDriveError>;
        { (context.to_owned(), dispatch.clone(), deadline) } => |(context, dispatch, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.check_fill_login(&context, &dispatch, deadline));
    forward!(fn fill_login(&mut self, context: &str, dispatch: &crate::browser::fill::FillDispatch, deadline: u64) -> Result<crate::browser::fill::FillOutcome, NavigationDriveError>;
        { (context.to_owned(), dispatch.clone(), deadline) } => |(context, dispatch, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.fill_login(&context, &dispatch, deadline));
    forward!(fn clear_filled(&mut self, context: &str, fields: &[crate::browser::fill::FilledField], deadline: u64) -> Result<(), NavigationDriveError>;
        { (context.to_owned(), fields.to_vec(), deadline) } => |(context, fields, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.clear_filled(&context, &fields, deadline));
    forward!(fn filled_fields_state(&mut self, context: &str, fields: &[crate::browser::fill::FilledField], deadline: u64) -> Result<crate::browser::fill::FilledFieldsState, NavigationDriveError>;
        { (context.to_owned(), fields.to_vec(), deadline) } => |(context, fields, deadline)| move |p: &mut dyn OwnedBrowserProcess| p.filled_fields_state(&context, &fields, deadline));

    fn generation_matches(&self) -> bool {
        self.0
            .exit
            .as_ref()
            .is_some_and(|probe| probe.generation_matches())
    }
    fn generation_gone(&self) -> bool {
        self.0
            .exit
            .as_ref()
            .is_some_and(|probe| probe.generation_gone())
    }
    fn shutdown_killer(&self) -> Option<Arc<dyn BrowserKiller>> {
        self.0.killer.clone()
    }
    fn exit_probe(&self) -> Option<Arc<dyn BrowserExitProbe>> {
        self.0.exit.clone()
    }
    fn release_held_input(&mut self, deadline: u64) -> Result<(), NavigationDriveError> {
        let end = Instant::now() + Duration::from_millis(deadline);
        self.invoke_until(true, Some(end), move |p| {
            p.release_held_input(end.saturating_duration_since(Instant::now()).as_millis() as u64)
        })
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        self.invoke(true, |p| p.request_graceful_termination())
    }
    fn request_graceful_termination_with_budget(
        &mut self,
        budget: Duration,
    ) -> Result<Duration, ProcessControlFailure> {
        let deadline = Instant::now() + budget;
        self.invoke_until(true, Some(deadline), move |p| {
            p.request_graceful_termination_with_budget(
                deadline.saturating_duration_since(Instant::now()),
            )
        })
    }
    fn wait_for_exit(&mut self, budget: Duration) -> Result<bool, ProcessControlFailure> {
        let deadline = Instant::now() + budget;
        self.invoke_until(true, Some(deadline), move |p| {
            p.wait_for_exit(deadline.saturating_duration_since(Instant::now()))
        })
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        match self
            .0
            .killer
            .as_ref()
            .map(|killer| killer.kill_exact_generation())
        {
            Some(KillOutcome::Dead) => Ok(()),
            Some(_) => Err(ProcessControlFailure::new(
                ProcessControlStep::ForcedTermination,
            )),
            None => self.invoke(true, |p| p.force_terminate()),
        }
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        if self.0.reaped.load(Ordering::Acquire) {
            return self.stop_and_join();
        }
        let state = Arc::clone(&self.0);
        self.invoke(true, move |p| {
            let result = p.wait_until_reaped();
            if result.is_ok() {
                state.reaped.store(true, Ordering::Release);
                state.stop.store(true, Ordering::Release);
            }
            result
        })?;
        self.stop_and_join()
    }
}
