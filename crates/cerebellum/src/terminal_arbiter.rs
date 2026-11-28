//! Single terminal ownership and bounded cleanup for route requests.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use subc_protocol::{Frame, FrameType};
use tokio::sync::mpsc;

use crate::egress::{request_id, terminal_frame};
use crate::{
    budgets, call_context, control_flags, flat_tools, forward_recording_reply, send,
    settle_call_record, wall_clock_ms, ModuleError, PendingSettlement, Planes,
    RequestCancellationGuard,
};

#[cfg(test)]
pub(crate) use cerebellum_computer::fronting_clock::now as fronting_now;

#[cfg(not(test))]
pub(crate) fn fronting_now() -> std::time::Instant {
    std::time::Instant::now()
}

/// When each fronting lock still held for a held-key release that had not
/// settled by its call's reply began to be held that way, in wall-clock
/// milliseconds. Such a lock is the one fronting lock with no time bound
/// (see [`RestoreCell::reply_sent_before_release`]), so module health reports it.
static UNSETTLED_RELEASE_LOCKS: std::sync::Mutex<Vec<u64>> = std::sync::Mutex::new(Vec::new());

/// How many fronting locks are held for unsettled releases, and since when
/// the oldest of them has been, in wall-clock milliseconds.
pub(crate) fn unsettled_release_fronting_locks() -> (usize, Option<u64>) {
    let held = UNSETTLED_RELEASE_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    (held.len(), held.iter().min().copied())
}

fn unsettled_release_lock_ended(since_ms: u64) {
    let mut held = UNSETTLED_RELEASE_LOCKS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(index) = held.iter().position(|at| *at == since_ms) {
        held.swap_remove(index);
    }
}

/// Tracks whether ordinary external mutations may start. Once a terminal
/// decision stops dispatch, only held-input release may proceed.
#[derive(Default)]
pub struct DispatchGate(
    std::sync::atomic::AtomicU8,
    std::sync::Mutex<Option<Arc<crate::grant_enforcement::CallGrants>>>,
    std::sync::Mutex<Vec<(Arc<crate::cingulate_client::desk::ConsentDesk>, String)>>,
);

impl DispatchGate {
    pub(crate) fn bind_grants(&self, grants: Arc<crate::grant_enforcement::CallGrants>) {
        *self.1.lock().unwrap() = Some(grants);
    }

    pub fn begin_mutation(&self) -> bool {
        if self
            .1
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|grants| !grants.is_live())
        {
            self.stop();
            return false;
        }
        use std::sync::atomic::Ordering::SeqCst;
        if self
            .2
            .lock()
            .unwrap()
            .iter()
            .any(|(desk, id)| desk.begin_execution(id).is_err())
        {
            self.stop();
            return false;
        }
        let mut bits = self.0.load(SeqCst);
        loop {
            if bits & 2 != 0 {
                return false;
            }
            match self.0.compare_exchange(bits, bits | 1, SeqCst, SeqCst) {
                Ok(_) => return true,
                Err(current) => bits = current,
            }
        }
    }

    pub fn stopped(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst) & 2 != 0
    }

    fn stop(&self) -> bool {
        self.0.fetch_or(2, std::sync::atomic::Ordering::SeqCst) & 1 != 0
    }
}

#[derive(Clone, Copy)]
pub enum CallStep {
    Admission,
    Queue,
    Consent,
    Preflight,
    Dispatch,
    Release,
}

impl CallStep {
    fn name(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Queue => "queue",
            Self::Consent => "consent",
            Self::Preflight => "preflight",
            Self::Dispatch => "dispatch",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Copy)]
pub enum TerminalCause {
    Deadline,
    Cancelled,
    RouteClosed,
    Draining,
}

impl TerminalCause {
    fn name(self) -> &'static str {
        match self {
            Self::Deadline => "action_deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::RouteClosed => "route_closed",
            Self::Draining => "module_draining",
        }
    }
}

#[derive(Clone, Copy)]
pub enum HeldState {
    NoneHeld,
    Released,
    Unknown,
}

impl HeldState {
    fn name(self) -> &'static str {
        match self {
            Self::NoneHeld => "none_held",
            Self::Released => "released",
            Self::Unknown => "unknown",
        }
    }
}

type ReleaseJob = std::pin::Pin<Box<dyn std::future::Future<Output = HeldState> + Send>>;

/// What a call's restore obligation needs from the platform to put the
/// previous application back: the frontmost read, the front request and a
/// clock to wait on, plus the session observer's hardware input timestamps
/// for the restore decision. It is built when the obligation is registered,
/// and is `Send`, so terminal cleanup can run it on a blocking thread when
/// the worker that fronted is stuck or gone.
///
/// Its clock must be the one the worker reads the front instant from, since
/// the decision compares the two.
pub trait RestoreHost: Send {
    /// Milliseconds on the host's clock.
    fn now_ms(&mut self) -> u64;
    /// Wait before checking the front again.
    fn pause_ms(&mut self, milliseconds: u64);
    /// The frontmost application's pid, or `None` when it cannot be read.
    fn frontmost_pid(&mut self) -> Option<u32>;
    /// Ask the application `pid` runs to become frontmost. `false` when the
    /// request itself was refused.
    fn request_front(&mut self, pid: u32) -> bool;
    fn request_front_while(
        &mut self,
        pid: u32,
        check: &mut dyn crate::computer::platform::RestoreWriteCheck,
    ) -> bool {
        check.permit() && self.request_front(pid)
    }
    /// A second way to ask for `pid`, the application a restore puts back,
    /// to come to the front, for when [`Self::request_front`] has not taken
    /// effect. `false` when the host has none or the request was refused.
    fn request_front_fallback(&mut self, _pid: u32) -> bool {
        false
    }
    fn request_front_fallback_while(
        &mut self,
        pid: u32,
        check: &mut dyn crate::computer::platform::RestoreWriteCheck,
    ) -> bool {
        check.permit() && self.request_front_fallback(pid)
    }
    /// The process-wide session observer's hardware input timestamps, on
    /// this host's clock. `None` when unavailable, which the decision reads
    /// as no input seen.
    fn hardware_input_snapshot(
        &mut self,
    ) -> Option<crate::computer::dispatch::HardwareInputSnapshot>;
}

/// The process-wide fronting lock, as a held guard. Dropping it releases the
/// lock, which happens exactly once: when the restore decision completes, or
/// when the obligation is refused at registration.
pub type FrontingLockGuard = Box<dyn Send + 'static>;

/// The `fronting.mode` a reply reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontingMode {
    Foreground,
    Background,
}

impl FrontingMode {
    fn name(self) -> &'static str {
        match self {
            Self::Foreground => "foreground",
            Self::Background => "background",
        }
    }
}

/// The `fronting.purpose` of a temporary front, which is the only kind of
/// front that owes a restore.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontingPurpose {
    /// An action that only works with its application in front.
    NeedsFront,
    /// A `bring_to_front` image read.
    BringToFront,
}

impl FrontingPurpose {
    fn name(self) -> &'static str {
        match self {
            Self::NeedsFront => "needs_front",
            Self::BringToFront => "bring_to_front",
        }
    }
}

/// A promise to put the previous application back after a temporary front,
/// handed to the call's [`TerminalArbiter`] before the first front request so
/// that terminal cleanup can keep it if the worker does not.
pub struct RestoreObligation {
    /// The application that was frontmost before, read with the fronting
    /// lock held.
    pub previous_pid: u32,
    /// The application about to be fronted.
    pub target_pid: u32,
    /// The target's display name, used in a failed restore's remedy when
    /// the target is the application left in front.
    pub target_name: String,
    pub mode: FrontingMode,
    pub purpose: FrontingPurpose,
    /// Held until the restore decision completes.
    pub lock: FrontingLockGuard,
    pub host: Box<dyn RestoreHost>,
    /// The bracket's gate, which holds the front attempt and the front's
    /// bound. `None` for a front with no bracket gate: the cell then keeps
    /// its own, with no bound.
    pub gate: Option<Arc<crate::computer::dispatch::CutoffGate>>,
}

/// Registration was refused because the call's terminal reply is already
/// chosen. The obligation was dropped, which released its fronting lock;
/// the worker must not front.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreRegistrationRefused;

impl RestoreRegistrationRefused {
    /// The fronting stop the worker reports, which replies `cancelled`.
    pub fn stop(self) -> crate::computer::dispatch::FrontingStop {
        crate::computer::dispatch::FrontingStop::TerminalAlreadyChosen
    }
}

/// The result of a restore obligation's one restore decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreDecided {
    pub restore: crate::computer::dispatch::RestoreStatus,
    /// Hardware input arrived after the front.
    pub person_input_during_fronting: bool,
    pub input_coverage_unavailable: bool,
    /// How long the restore took, timed by the side that ran the decision,
    /// not by a side that only awaited it; `None` when no restore was timed.
    pub restore_ms: Option<u64>,
    /// A front request was made. `false` when cleanup took the obligation
    /// before the worker fronted, so the worker never did.
    pub front_requested: bool,
}

/// How long, in real milliseconds, terminal cleanup waits for the decision
/// of a worker that ended without a reply before abandoning it unrestored.
/// The owner's sequence is itself bounded by the front wait and the restore
/// wait; this only keeps a missing decision from holding the fronting lock
/// forever.
const OWNER_GONE_AFTER_MS: u64 =
    2 * (crate::computer::dispatch::FRONT_WAIT_MS + crate::computer::dispatch::RESTORE_WAIT_MS);

/// A registered restore obligation, shared by the worker whose bracket
/// fronts and the call's terminal cleanup. The worker's bracket thread is its
/// one owner: it makes the one restore decision ([`RestoreCell::decide`])
/// once its front is over and any held input released. Terminal cleanup
/// never restores: it stops a front not yet requested, or waits, bounded,
/// for the owner's decision ([`RestoreCell::await_owner`]). A restore after
/// the call returned is only ever the late watch's, once the owner handed
/// the obligation to it. The front attempt and the front's bound live in the
/// obligation's [`crate::computer::dispatch::CutoffGate`]. The fronting lock
/// is released when the decision completes, unless a picture read or the
/// late watch still needs it.
pub struct RestoreCell {
    previous_pid: u32,
    target_pid: u32,
    target_name: String,
    mode: FrontingMode,
    purpose: FrontingPurpose,
    inner: std::sync::Mutex<RestoreCellInner>,
    changed: std::sync::Condvar,
    /// The front attempt and the front's bound; shared with the bracket
    /// when the front runs in one.
    gate: Arc<crate::computer::dispatch::CutoffGate>,
    pending_watch: late_fronting::PendingRegistration,
    #[cfg(all(feature = "desk-probe", target_os = "macos"))]
    probe_timing: probe_timing::ProbeTiming,
}

struct RestoreCellInner {
    /// The first restore request missed its deadline, so the late watch is
    /// owed the obligation.
    handoff_owed: bool,
    /// The late watch took the host and the fronting lock. Only from here may
    /// a reply say the restore was handed off.
    watch_holds: bool,
    late_start: Option<Box<dyn FnOnce() + Send>>,
    /// The restore host, which carries the previous application's identity
    /// as it was bound before the front. It moves, never copied, from the
    /// owner's decision to the late watch.
    host: Option<Box<dyn RestoreHost>>,
    lock: Option<FrontingLockGuard>,
    /// The owner took the host and can still write focus. Abandonment must
    /// not release the fronting lock until that decision finishes.
    deciding: bool,
    decided: Option<RestoreDecided>,
    front_confirmed: bool,
    pending_since: Option<u64>,
    /// The decision already put back the landing that `pending_since` is
    /// watched for, so the late watch starts with the previous application
    /// restored and only a further landing needs it.
    pending_restored: bool,
    /// Picture reads still running while the target may be in front. The
    /// fronting lock is kept until the last one returns, even when the
    /// decision completed first, so no other front starts under a capture.
    reads_in_flight: usize,
    /// The call's reply went out while the owner still waited for a key
    /// release to settle (see [`RestoreCell::reply_sent_before_release`]):
    /// the wall-clock milliseconds since which the fronting lock has been
    /// held for it. Cleared by the owner's decision.
    release_wait: Option<u64>,
}

impl RestoreCell {
    fn new(
        obligation: RestoreObligation,
        domain: usize,
        namespace: usize,
        request: crate::egress::RequestId,
    ) -> Self {
        Self {
            previous_pid: obligation.previous_pid,
            target_pid: obligation.target_pid,
            target_name: obligation.target_name,
            mode: obligation.mode,
            purpose: obligation.purpose,
            inner: std::sync::Mutex::new(RestoreCellInner {
                handoff_owed: false,
                watch_holds: false,
                late_start: None,
                host: Some(obligation.host),
                lock: Some(obligation.lock),
                deciding: false,
                decided: None,
                front_confirmed: false,
                pending_since: None,
                pending_restored: false,
                reads_in_flight: 0,
                release_wait: None,
            }),
            changed: std::sync::Condvar::new(),
            gate: obligation
                .gate
                .unwrap_or_else(|| Arc::new(crate::computer::dispatch::CutoffGate::new())),
            pending_watch: late_fronting::register_pending(
                domain,
                obligation.target_pid,
                namespace,
                request,
            ),
            #[cfg(all(feature = "desk-probe", target_os = "macos"))]
            probe_timing: probe_timing::ProbeTiming::new(obligation.target_pid),
        }
    }

    fn inner(&self) -> std::sync::MutexGuard<'_, RestoreCellInner> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn target_pid(&self) -> u32 {
        self.target_pid
    }

    /// The worker is about to request the front at `front_instant_ms`, on
    /// the restore host's clock. `false` when cleanup already stopped the
    /// front or its bound left no time: the worker must not front.
    pub fn begin_front_attempt(&self, front_instant_ms: u64) -> bool {
        let began = self.gate.begin_front_attempt(front_instant_ms);
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        if began {
            self.probe_timing.begin();
        }
        began
    }

    /// The front request and its wait returned.
    pub fn front_attempt_returned(&self) {
        self.gate.front_attempt_returned();
    }

    pub fn front_confirmed(&self) {
        let mut inner = self.inner();
        inner.front_confirmed = true;
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        self.probe_timing.confirmed_front();
        drop(inner);
    }

    pub fn was_front_confirmed(&self) -> bool {
        self.inner().front_confirmed
    }

    /// The decision, once it has completed.
    pub fn decided(&self) -> Option<RestoreDecided> {
        self.inner().decided
    }

    #[cfg(windows)]
    pub(crate) fn settled_windows_restore(&self) -> bool {
        let inner = self.inner();
        inner.pending_since.is_none()
            && inner.reads_in_flight == 0
            && inner.decided.is_some_and(|result| {
                result.restore == cerebellum_computer::dispatch::RestoreStatus::Restored
            })
    }

    /// Whether the front is ending: nothing new may start. The restore
    /// reserve started, the owner began its restore, or the call's terminal
    /// cleanup stopped the front.
    pub fn cleanup_taken(&self) -> bool {
        self.gate.closed()
    }

    /// A picture read is starting while the target may be in front. The
    /// fronting lock is kept until the returned hold is dropped, whenever
    /// the decision completes, but for at most `lifetime`: a read still
    /// running then (a synchronous step that never returns) is counted out
    /// as a read whose capture timed out, the lock is released as for one,
    /// and module health reports it (`pictureReadsPastLifetime`). Whatever
    /// that read later acquires is refused by its fence, whose deadline has
    /// long passed.
    pub fn hold_lock_for_read(self: &Arc<Self>, lifetime: Duration) -> Option<ReadLockHold> {
        self.hold_read_with_watchdog(lifetime, |watch| {
            std::thread::Builder::new()
                .name("picture-read-lifetime".into())
                .spawn(watch)
                .is_ok()
        })
    }

    fn hold_read_with_watchdog(
        self: &Arc<Self>,
        lifetime: Duration,
        spawn: impl FnOnce(Box<dyn FnOnce() + Send>) -> bool,
    ) -> Option<ReadLockHold> {
        {
            let mut inner = self.inner();
            if self.gate.closed() || inner.lock.is_none() {
                return None;
            }
            inner.reads_in_flight += 1;
        }
        let ended = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (returned, wait) = std::sync::mpsc::channel::<()>();
        let cell = Arc::clone(self);
        let expiry_ended = Arc::clone(&ended);
        let expires_at = std::time::Instant::now() + lifetime;
        if !spawn(Box::new(move || {
            if let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
                wait.recv_timeout(expires_at.saturating_duration_since(std::time::Instant::now()))
            {
                // Counted as stalled before claiming the read, so a hold
                // dropped at this moment never takes the count below zero.
                STALLED_PICTURE_READS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if expiry_ended.swap(true, std::sync::atomic::Ordering::AcqRel) {
                    STALLED_PICTURE_READS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                } else {
                    STALLED_PICTURE_READS_TOTAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    cell.read_outlived_lifetime();
                }
            }
        })) {
            // Refuse before entering native capture if we cannot bound its hold.
            self.read_ended();
            return None;
        }
        Some(ReadLockHold {
            cell: Arc::clone(self),
            ended,
            _returned: returned,
        })
    }

    /// One picture read no longer holds the fronting lock: release it when
    /// none does, the decision has completed, and nothing else keeps it.
    fn read_ended(&self) {
        self.read_released(false);
    }

    /// A picture read outlived its lifetime. Its owner is inside a native
    /// call it cannot leave, so the fronting lock is released without
    /// waiting for the owner's decision: other fronts must not wait on a
    /// stalled capture for ever. The owner still decides once it returns.
    fn read_outlived_lifetime(&self) {
        self.read_released(true);
    }

    fn read_released(&self, outlived: bool) {
        let mut inner = self.inner();
        inner.reads_in_flight = inner.reads_in_flight.saturating_sub(1);
        let lock = if inner.reads_in_flight == 0
            && (outlived || inner.decided.is_some())
            && inner.pending_since.is_none()
        {
            inner.lock.take()
        } else {
            None
        };
        let late_start = if inner.reads_in_flight == 0 && inner.decided.is_some() {
            inner.late_start.take()
        } else {
            None
        };
        drop(inner);
        drop(lock);
        if let Some(start) = late_start {
            start();
        }
    }

    /// Whether a late watch is owed for an activation this cell did not see
    /// through.
    #[cfg(test)]
    pub(crate) fn late_watch_pending(&self) -> bool {
        self.inner().pending_since.is_some()
    }

    /// Make the one restore decision. Only the owner calls this, on the
    /// bracket's thread, once its front is over and any input it pressed has
    /// been released. Blocking: it reads the front, may request the previous
    /// application and waits for it. A second call returns the first
    /// decision.
    ///
    /// An app-use front keeps its bound here: an unconfirmed activation is
    /// watched for only until the restore reserve starts. The deadline is
    /// checked before reading focus and at the first restore write. A refused
    /// request is reported failed and leaves the obligation to the late watch,
    /// with the host that carries the previous application's identity as it was
    /// bound before the front.
    pub fn decide(&self) -> RestoreDecided {
        self.decide_entered(fronting_now())
    }

    pub(crate) fn decide_entered(&self, entered: std::time::Instant) -> RestoreDecided {
        // A key still down at the deadline is the named exception: the
        // restore follows its confirmed release without a deadline.
        self.decide_bounded(!self.gate.held_past_deadline(), entered)
    }

    /// [`Self::decide`]; `timed` false runs it with no write deadline, for
    /// the restore that follows a release confirmed only after the deadline.
    fn decide_bounded(&self, timed: bool, entered: std::time::Instant) -> RestoreDecided {
        use crate::computer::dispatch::FrontAttemptState;
        if let Some(decided) = self.decided() {
            return decided;
        }
        self.gate.end_front();
        let front_instant_ms = match self.gate.attempt_state() {
            FrontAttemptState::NotStarted => {
                return self.complete(self.inner(), Self::not_needed());
            }
            FrontAttemptState::Dispatching { front_instant_ms }
            | FrontAttemptState::Dispatched { front_instant_ms } => front_instant_ms,
        };
        let (confirmed, mut host) = match self.take_host_to_decide() {
            Ok(claim) => claim,
            Err(decided) => return decided,
        };
        let started = fronting_now();
        let deadline = self.gate.deadline();
        let native_overrun = self.gate.native_overrun_until();
        if !timed && deadline.is_some() {
            restore_preparation::record_held_release(native_overrun.is_some());
        }
        let write_deadline = deadline.filter(|_| timed).map(|deadline| {
            restore_preparation::WriteDeadline::new(
                deadline,
                self.gate.reserve_start(),
                started,
                native_overrun,
            )
            .with_tail_from(entered)
        });
        let mut adapter = RestoreDecisionHost {
            host: host.as_mut(),
            _target: self.target_pid,
            write_deadline,
            #[cfg(all(feature = "desk-probe", target_os = "macos"))]
            probe_timing: &self.probe_timing,
        };
        let outcome = crate::computer::dispatch::restore_after_front_attempt(
            &mut adapter,
            self.previous_pid,
            self.target_pid,
            front_instant_ms,
            crate::computer::dispatch::RESTORE_WAIT_MS,
            confirmed,
        );
        // The owner's own restores train the reserve, a refused request too:
        // each sample runs to the native write it reached.
        let expired = adapter.write_deadline.as_ref().is_some_and(|guard| {
            guard.record_sample();
            guard.expired
        });
        self.finish_decision(outcome, expired, confirmed, front_instant_ms, host)
    }

    /// The owner's decision for a bracket that deferred its restore because
    /// a key may have been held, once settling that release ended at
    /// `settled_at`, `confirmed` when every key is known to be up.
    ///
    /// An unconfirmed release restores nothing: the previous application
    /// would receive the held key. A release confirmed before the deadline is
    /// followed at once by the restore under that deadline. One confirmed
    /// only after it is the named exception to the bound: the restore follows
    /// it without a deadline. When the call's reply already went out before
    /// it settled, that restore is one attempt that puts the previous
    /// application back only while the target is in front and nothing since
    /// the front shows the person using it.
    pub(crate) fn decide_after_release(
        &self,
        confirmed: bool,
        settled_at: std::time::Instant,
        entered: std::time::Instant,
    ) -> RestoreDecided {
        if let Some(decided) = self.decided() {
            return decided;
        }
        if !confirmed {
            return self.forgo();
        }
        self.gate.all_released();
        if self
            .gate
            .deadline()
            .is_none_or(|deadline| settled_at < deadline)
        {
            return self.decide_bounded(true, entered);
        }
        if self.inner().release_wait.is_some() {
            return self.restore_after_late_release();
        }
        self.decide_bounded(false, entered)
    }

    /// Terminal cleanup's part in the obligation; it never restores. A front
    /// not yet requested is stopped, and the decision is that nothing needs
    /// restoring. Otherwise nothing new may start, and this waits until
    /// `give_up` at most for the owner's decision: `None` when the owner has
    /// not decided by then. Blocking.
    pub fn await_owner(&self, give_up: std::time::Instant) -> Option<RestoreDecided> {
        if self.gate.stop_front() {
            return Some(self.complete(self.inner(), Self::not_needed()));
        }
        let (inner, _) = self
            .changed
            .wait_timeout_while(
                self.inner(),
                give_up.saturating_duration_since(std::time::Instant::now()),
                |inner| inner.decided.is_none(),
            )
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        inner.decided
    }

    /// The call's reply goes out while the owner still waits for a key
    /// release to settle. The reply reports the restore failed; the owner
    /// keeps the host and the fronting lock, and decides once the release
    /// settles. Until then module health counts the lock as held for an
    /// unsettled release: the one fronting lock with no time bound.
    pub(crate) fn reply_sent_before_release(&self) {
        let mut inner = self.inner();
        if inner.decided.is_some() || inner.release_wait.is_some() {
            return;
        }
        let since_ms = wall_clock_ms();
        UNSETTLED_RELEASE_LOCKS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push(since_ms);
        inner.release_wait = Some(since_ms);
    }

    /// Retire a front after its worker sends no reply, unless the owner is
    /// already deciding. Nothing is restored on abandonment, the fronting
    /// lock is released, and a front that may have happened is reported failed.
    pub(crate) fn abandon_undecided(&self) {
        let inner = self.inner();
        if inner.decided.is_none() && !inner.deciding {
            self.forgo_locked(inner);
        }
    }

    fn take_host_to_decide(&self) -> Result<(bool, Box<dyn RestoreHost>), RestoreDecided> {
        let mut inner = self.inner();
        if let Some(decided) = inner.decided {
            return Err(decided);
        }
        let Some(host) = inner.host.take() else {
            return Err(self.failed());
        };
        inner.deciding = true;
        Ok((inner.front_confirmed, host))
    }

    /// Record a decision the owner made: a first request refused at the
    /// deadline reads as failed, and an activation the action never confirmed,
    /// or a refused request, leaves the host to the late watch.
    fn finish_decision(
        &self,
        mut outcome: crate::computer::dispatch::RestoreOutcome,
        expired: bool,
        confirmed: bool,
        front_instant_ms: u64,
        host: Box<dyn RestoreHost>,
    ) -> RestoreDecided {
        if expired {
            outcome.restore = self.failed().restore;
            outcome.restore_ms = None;
        }
        // An activation the action never confirmed is always left to the
        // late watch, even one restored here: the same activation can land
        // again after this decision.
        if (expired || !confirmed)
            && !matches!(
                outcome.restore,
                crate::computer::dispatch::RestoreStatus::NotNeeded
            )
        {
            let mut inner = self.inner();
            inner.pending_since = Some(front_instant_ms);
            inner.handoff_owed |= expired;
            inner.pending_restored = matches!(
                outcome.restore,
                crate::computer::dispatch::RestoreStatus::Restored
            );
            inner.host = Some(host);
        }
        self.complete(
            self.inner(),
            RestoreDecided {
                restore: outcome.restore,
                person_input_during_fronting: outcome.person_input_during_fronting,
                input_coverage_unavailable: outcome.input_coverage_unavailable,
                restore_ms: outcome.restore_ms,
                front_requested: true,
            },
        )
    }

    /// A decision that found nothing fronted.
    fn not_needed() -> RestoreDecided {
        RestoreDecided {
            restore: crate::computer::dispatch::RestoreStatus::NotNeeded,
            person_input_during_fronting: false,
            input_coverage_unavailable: false,
            restore_ms: None,
            front_requested: false,
        }
    }

    /// A native refusal with the original window still foreground leaves
    /// nothing in flight for the owner or a late watcher to put back.
    pub(crate) fn front_attempt_denied(&self) -> RestoreDecided {
        self.gate.end_front();
        let mut inner = self.inner();
        inner.host.take();
        self.complete(inner, Self::not_needed())
    }

    /// The owner's decision without any restore, because a key or button may
    /// still be held and restoring would deliver it to the previous
    /// application. A front that may have happened is reported failed,
    /// naming the target left in front; one that never happened is
    /// `not_needed`.
    pub(crate) fn forgo(&self) -> RestoreDecided {
        self.forgo_locked(self.inner())
    }

    fn forgo_locked(
        &self,
        mut inner: std::sync::MutexGuard<'_, RestoreCellInner>,
    ) -> RestoreDecided {
        use crate::computer::dispatch::FrontAttemptState;
        if let Some(decided) = inner.decided {
            return decided;
        }
        self.gate.end_front();
        let decided = match self.gate.attempt_state() {
            FrontAttemptState::NotStarted => Self::not_needed(),
            FrontAttemptState::Dispatching { .. } | FrontAttemptState::Dispatched { .. } => {
                self.failed()
            }
        };
        inner.host.take();
        self.complete(inner, decided)
    }

    /// The restore after a release that settled confirmed only after the
    /// call's reply: one attempt, only while the target is in front and
    /// nothing since the front says the person is using it, since the
    /// release may have settled long after the reply.
    fn restore_after_late_release(&self) -> RestoreDecided {
        use crate::computer::dispatch::FrontAttemptState;
        self.gate.end_front();
        let since = match self.gate.attempt_state() {
            FrontAttemptState::NotStarted => {
                return self.complete(self.inner(), Self::not_needed());
            }
            FrontAttemptState::Dispatching { front_instant_ms }
            | FrontAttemptState::Dispatched { front_instant_ms } => front_instant_ms,
        };
        let mut host = match self.take_host_to_decide() {
            Ok((_, host)) => host,
            Err(decided) => return decided,
        };
        let restored = {
            let mut adapter = RestoreDecisionHost {
                host: host.as_mut(),
                _target: self.target_pid,
                write_deadline: None,
                #[cfg(all(feature = "desk-probe", target_os = "macos"))]
                probe_timing: &self.probe_timing,
            };
            crate::computer::dispatch::watch_late_activation(
                &mut adapter,
                self.previous_pid,
                self.target_pid,
                since,
                u64::MAX,
                crate::computer::dispatch::LateWatch::FirstAttempt,
                &|| false,
            )
            .0
        };
        self.complete(
            self.inner(),
            RestoreDecided {
                restore: restored,
                ..self.failed()
            },
        )
    }

    /// A restore reported failed with the target named as left in front.
    fn failed(&self) -> RestoreDecided {
        RestoreDecided {
            restore: crate::computer::dispatch::RestoreStatus::Failed {
                left_in_front: Some(self.target_pid),
            },
            person_input_during_fronting: false,
            input_coverage_unavailable: false,
            restore_ms: None,
            front_requested: true,
        }
    }

    /// Release the fronting lock unless a picture read or the late watch
    /// still needs it, then record the decision and wake any waiter, so a
    /// waiter that sees the decision never sees the lock still held. Only
    /// the first decision counts.
    fn complete(
        &self,
        mut inner: std::sync::MutexGuard<'_, RestoreCellInner>,
        decided: RestoreDecided,
    ) -> RestoreDecided {
        if let Some(first) = inner.decided {
            return first;
        }
        if let Some(since_ms) = inner.release_wait.take() {
            unsettled_release_lock_ended(since_ms);
        }
        let late_start = if inner.reads_in_flight == 0 {
            inner.late_start.take()
        } else {
            None
        };
        if inner.pending_since.is_none() && inner.reads_in_flight == 0 {
            // Dropping the guard only releases the lock; it calls nothing
            // that takes this cell's mutex.
            drop(inner.lock.take());
        }
        inner.deciding = false;
        inner.decided = Some(decided);
        drop(inner);
        self.changed.notify_all();
        if let Some(start) = late_start {
            start();
        }
        decided
    }

    /// Write the decision into a terminal reply body: `fronting.restore`, and
    /// for a failed restore the outcome `restore_failed`, which outranks every
    /// other outcome, with a remedy naming the application left in front.
    /// The body's `detail` and `effect_status` are kept.
    fn disclose(&self, body: &mut Value, decided: RestoreDecided) {
        use crate::computer::dispatch::RestoreStatus;
        let Some(object) = body.as_object_mut() else {
            return;
        };
        let fronting = object.entry("fronting").or_insert_with(|| {
            let mut fronting = json!({
                "mode": self.mode.name(),
                "fronted": self.was_front_confirmed(),
                "purpose": self.purpose.name(),
            });
            if !decided.front_requested {
                // Cleanup took the obligation before the front was
                // dispatched, which the stop table names `cancelled`.
                fronting["not_fronted_reason"] = json!("cancelled");
            }
            fronting
        });
        let Some(fronting) = fronting.as_object_mut() else {
            return;
        };
        let restore = match decided.restore {
            RestoreStatus::NotNeeded => "not_needed",
            RestoreStatus::Restored => "restored",
            RestoreStatus::SkippedPerson { .. } => "skipped_person",
            RestoreStatus::Failed { .. } => "failed",
        };
        fronting.insert("restore".into(), json!(restore));
        if decided.person_input_during_fronting {
            fronting.insert("person_input_during_fronting".into(), json!(true));
        }
        if let RestoreStatus::Failed { left_in_front } = decided.restore {
            object.insert("outcome".into(), json!("restore_failed"));
            let remedy = if left_in_front == Some(self.target_pid) {
                format!(
                    "{} was left in front; switch back to the application you were using",
                    self.target_name
                )
            } else {
                "the application that was in front before could not be put back; switch back to the application you were using".to_owned()
            };
            // A shortcut that already sent keys keeps saying which.
            let sent = object
                .get("remedy")
                .and_then(Value::as_str)
                .and_then(crate::computer_capability::keystrokes::keys_sent_in)
                .map(str::to_owned);
            let mut remedy = match sent {
                Some(sent) => format!("{sent} {remedy}"),
                None => remedy,
            };
            let inner = self.inner();
            if inner.handoff_owed && inner.watch_holds {
                remedy.push_str(". The first restore request missed its deadline; the restore was handed off to a short-lived watcher that can retry only while the target remains in front and continuous input observation shows no person input.");
            } else if inner.handoff_owed
                || (self.gate.deadline().is_some()
                    && inner.late_start.is_some()
                    && inner.decided.is_none())
            {
                // The owner has not decided, or has missed the deadline but
                // the late watch does not hold the obligation yet: nothing
                // may be said to be handed off until it does.
                remedy.push_str(". Restore cleanup is still running; if its first request misses the deadline, a short-lived watcher can retry only while the target remains in front and continuous input observation shows no person input.");
            }
            object.insert("remedy".into(), json!(remedy));
        } else if let RestoreStatus::SkippedPerson { now_front } = decided.restore {
            let explanation = if decided.input_coverage_unavailable {
                Some(format!(
                    "Cerebellum couldn't watch for person input throughout the attempt to bring {} forward, so it left focus alone. Check hardwareInputObserver in module health before bringing an app forward again.",
                    self.target_name
                ))
            } else if decided.person_input_during_fronting {
                let focus = if now_front == Some(self.target_pid) {
                    format!("{} was left in front", self.target_name)
                } else {
                    "focus was left alone".to_owned()
                };
                Some(format!("The person used the mouse or keyboard during fronting, so {focus}. Don't bring apps forward again until the person is idle."))
            } else {
                None
            };
            if let Some(mut explanation) = explanation {
                if let Some(prior) = object.get("remedy").and_then(Value::as_str) {
                    explanation.push(' ');
                    explanation.push_str(prior);
                }
                object.insert("remedy".into(), json!(explanation));
            }
        }
    }
}

/// Keeps the fronting lock while a picture read runs; see
/// [`RestoreCell::hold_lock_for_read`]. Dropping it releases the lock when
/// the decision has completed and no late watch has taken it over, unless
/// the read's lifetime already counted it out.
pub struct ReadLockHold {
    cell: Arc<RestoreCell>,
    /// The read was counted out, by returning or by outliving its lifetime.
    ended: Arc<std::sync::atomic::AtomicBool>,
    /// Dropped with the hold, which wakes the lifetime watchdog.
    _returned: std::sync::mpsc::Sender<()>,
}

impl Drop for ReadLockHold {
    fn drop(&mut self) {
        if self.ended.swap(true, std::sync::atomic::Ordering::AcqRel) {
            // Counted out at its lifetime; it has returned at last.
            STALLED_PICTURE_READS.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        } else {
            self.cell.read_ended();
        }
    }
}

/// Picture reads counted out at their lifetime that have not returned yet.
static STALLED_PICTURE_READS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
/// Picture reads counted out at their lifetime since the module started.
static STALLED_PICTURE_READS_TOTAL: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Picture reads that outlived their lifetime: how many have still not
/// returned, and how many there have been since the module started.
pub(crate) fn stalled_picture_reads() -> (usize, u64) {
    (
        STALLED_PICTURE_READS.load(std::sync::atomic::Ordering::Relaxed),
        STALLED_PICTURE_READS_TOTAL.load(std::sync::atomic::Ordering::Relaxed),
    )
}

/// Presents a [`RestoreHost`] as the bracket host the shared restore
/// decision runs against. The decision reads the front and the hardware input
/// timestamps, may request the previous application, and waits; it creates
/// no input tap and posts no input, so those methods are never reached.
struct RestoreDecisionHost<'a> {
    host: &'a mut dyn RestoreHost,
    _target: u32,
    /// The owner's first restore request's deadline, when it has one. The
    /// late watch has none.
    write_deadline: Option<restore_preparation::WriteDeadline>,
    #[cfg(all(feature = "desk-probe", target_os = "macos"))]
    probe_timing: &'a probe_timing::ProbeTiming,
}

impl crate::computer::dispatch::FrontingBracketHost for RestoreDecisionHost<'_> {
    type Tap = ();

    fn restore_wait_left_ms(&mut self) -> Option<u64> {
        self.write_deadline
            .as_ref()
            .and_then(restore_preparation::WriteDeadline::wait_left)
            .map(|left| u64::try_from(left.as_millis()).unwrap_or(u64::MAX))
    }

    fn restore_deadline_missed(&mut self) -> bool {
        self.write_deadline
            .as_mut()
            .is_some_and(restore_preparation::WriteDeadline::missed)
    }

    fn restore_preparation_started(&mut self) {
        if let Some(guard) = &mut self.write_deadline {
            guard.preparation_started();
        }
    }

    fn now_ms(&mut self) -> u64 {
        self.host.now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        if milliseconds > 0 {
            self.host.pause_ms(milliseconds);
        }
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        let started = fronting_now();
        let frontmost = self.host.frontmost_pid();
        if let Some(guard) = &mut self.write_deadline {
            guard.os_read(started, fronting_now());
        }
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        self.probe_timing.frontmost_observed(frontmost);
        frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        let mut check = restore_preparation::NativeWriteCheck {
            deadline: self.write_deadline.as_mut(),
        };
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        {
            probe_timing::request_restore(
                &mut *self.host,
                self.probe_timing,
                pid,
                probe_timing::RestoreSlot::First,
                &mut check,
            )
        }
        #[cfg(not(all(feature = "desk-probe", target_os = "macos")))]
        self.host.request_front_while(pid, &mut check)
    }
    fn request_front_fallback(&mut self, pid: u32) -> bool {
        let mut check = restore_preparation::NativeWriteCheck {
            deadline: self.write_deadline.as_mut(),
        };
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        {
            probe_timing::request_restore(
                &mut *self.host,
                self.probe_timing,
                pid,
                probe_timing::RestoreSlot::Second,
                &mut check,
            )
        }
        #[cfg(not(all(feature = "desk-probe", target_os = "macos")))]
        self.host.request_front_fallback_while(pid, &mut check)
    }
    fn late_activation_observed(&mut self, _latency_ms: u64) {
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        late_fronting::note_landing(self._target, _latency_ms);
        #[cfg(all(feature = "desk-probe", target_os = "macos"))]
        self.probe_timing.late_landing();
    }
    fn our_pid(&self) -> i64 {
        i64::from(std::process::id())
    }
    fn create_tap(&mut self) -> Option<()> {
        None
    }
    fn read_idle(&mut self) -> crate::computer::platform::IdleReading {
        crate::computer::platform::IdleReading::Unreadable(
            crate::computer::platform::IdleUnreadable::TableUnavailable,
        )
    }
    fn drain(&mut self, _tap: &()) -> Vec<crate::computer::dispatch::SourcedInputEvent> {
        Vec::new()
    }
    fn post_heartbeat(&mut self) -> crate::computer::dispatch::HeartbeatProbe {
        unreachable!("the restore decision posts no heartbeat")
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        _probe: crate::computer::dispatch::HeartbeatProbe,
        _watcher: &mut crate::computer::dispatch::SeizeWatcher,
    ) -> crate::computer::dispatch::HeartbeatObservation {
        crate::computer::dispatch::HeartbeatObservation::Missed
    }
    fn post_unit(
        &mut self,
        _index: usize,
    ) -> Result<crate::computer::dispatch::UnitPosted, crate::computer::platform::SequencePostFailure>
    {
        unreachable!("the restore decision posts no input")
    }
    fn hardware_input_snapshot(
        &mut self,
    ) -> Option<crate::computer::dispatch::HardwareInputSnapshot> {
        self.host.hardware_input_snapshot()
    }
}

pub(crate) struct TerminalState {
    pub(crate) chosen: Option<Frame>,
    pub(crate) cause: Option<TerminalCause>,
    pub(crate) possibly_dispatched: bool,
    reply_finalized: bool,
    step: CallStep,
    release: Option<ReleaseJob>,
    /// A temporary front's restore obligation. Kept apart from `release`, so
    /// a chord holding Command owes both; `held_state` is derived from
    /// `release` alone.
    restore: Option<Arc<RestoreCell>>,
    pub(crate) settlement: Option<PendingSettlement>,
    /// Run once, under this state's lock, at the moment the terminal is
    /// chosen, then dropped. They hold this lock while they run, so each must
    /// be constant-time and non-blocking: no I/O, no await, and no lock but
    /// the one small cell it closes (a posting interval in the own-input
    /// ledger).
    on_terminal: Vec<TerminalHook>,
    /// Told, when the terminal is chosen, whether a stop chose it.
    reply_watchers: Vec<tokio::sync::oneshot::Sender<bool>>,
}

type TerminalHook = Box<dyn FnOnce() + Send>;
mod late_fronting;
#[cfg(all(feature = "desk-probe", target_os = "macos"))]
pub(crate) mod probe_timing;
pub(crate) mod restore_preparation;
#[cfg(test)]
pub(crate) use late_fronting::hold_watch_for_test;
#[cfg(all(feature = "desk-probe", target_os = "macos"))]
pub(crate) use late_fronting::take_landings;
pub(crate) use late_fronting::{
    cancel_late_fronting_all, cancel_late_fronting_request, cancel_late_fronting_route,
    cancel_late_fronting_target,
};
type LateFrontingRecorder = Arc<dyn Fn(Value) + Send + Sync>;

/// One decision shared by the route task and its workers. A worker retains this
/// handle when detached, but cannot change a terminal that has already won.
pub struct TerminalArbiter {
    pub gate: DispatchGate,
    pub(crate) witness: cerebellum_core::dispatch_witness::DispatchWitness,
    pub(crate) witness_committed: std::sync::atomic::AtomicBool,
    pub(crate) gate_dispatched: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) state: std::sync::Mutex<TerminalState>,
    request: Frame,
    changed: tokio::sync::Notify,
    consent_desk: std::sync::Mutex<Option<Arc<crate::cingulate_client::desk::ConsentDesk>>>,
    /// The agent whose cursor badge this call drew, if it drew one. Only
    /// computer calls draw badges, so a cancel that finds one here cancelled a
    /// computer call and can hide that agent's badge.
    cursor_agent: std::sync::Mutex<Option<String>>,
    late_fronting_recorder: std::sync::Mutex<Option<LateFrontingRecorder>>,
    pub(crate) fronting_domain: std::sync::atomic::AtomicUsize,
    route_namespace: std::sync::atomic::AtomicUsize,
}

tokio::task_local! {
    pub static CALL_TERMINAL: Arc<TerminalArbiter>;
}

impl TerminalArbiter {
    pub(crate) fn new(request: Frame) -> Self {
        Self {
            gate: DispatchGate::default(),
            witness: cerebellum_core::dispatch_witness::DispatchWitness::armed(),
            witness_committed: std::sync::atomic::AtomicBool::new(false),
            gate_dispatched: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            state: std::sync::Mutex::new(TerminalState {
                chosen: None,
                cause: None,
                possibly_dispatched: false,
                reply_finalized: false,
                step: CallStep::Admission,
                release: None,
                restore: None,
                settlement: None,
                on_terminal: Vec::new(),
                reply_watchers: Vec::new(),
            }),
            request,
            changed: tokio::sync::Notify::new(),
            consent_desk: std::sync::Mutex::new(None),
            cursor_agent: std::sync::Mutex::new(None),
            late_fronting_recorder: std::sync::Mutex::new(None),
            fronting_domain: std::sync::atomic::AtomicUsize::new(0),
            route_namespace: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    pub fn current() -> Option<Arc<Self>> {
        CALL_TERMINAL.try_with(Arc::clone).ok()
    }

    /// Give a direct plane fixture the restore owner supplied by production
    /// route arbitration. Pending activation cleanup keeps that owner after
    /// the fixture's reply, just as it does after a route reply.
    #[doc(hidden)]
    pub async fn scope_for_test<T>(
        request: Frame,
        future: impl std::future::Future<Output = T>,
    ) -> T {
        let terminal = Arc::new(Self::new(request));
        let result = CALL_TERMINAL.scope(Arc::clone(&terminal), future).await;
        terminal.start_late_fronting(None);
        result
    }

    pub(crate) fn set_late_fronting_recorder(&self, recorder: LateFrontingRecorder) {
        *self.late_fronting_recorder.lock().unwrap() = Some(recorder);
    }

    #[cfg(test)]
    pub(crate) fn record_late_fronting_for_test(&self, result: Value) {
        self.late_fronting_recorder
            .lock()
            .unwrap()
            .as_ref()
            .unwrap()(result);
    }

    pub(crate) fn start_late_fronting(&self, restore: Option<&Arc<RestoreCell>>) {
        let (cell, cause) = {
            let state = self.state.lock().unwrap();
            (
                restore.cloned().or_else(|| state.restore.clone()),
                state.cause,
            )
        };
        if let Some(cell) = cell {
            let request = request_id(&self.request);
            let domain = self
                .fronting_domain
                .load(std::sync::atomic::Ordering::Acquire);
            let namespace = self
                .route_namespace
                .load(std::sync::atomic::Ordering::Acquire);
            let recorder = self.late_fronting_recorder.lock().unwrap().clone();
            let weak = Arc::downgrade(&cell);
            let start = move || {
                if let Some(cell) = weak.upgrade() {
                    late_fronting::start(&cell, request, domain, namespace, cause, recorder);
                }
            };
            let mut inner = cell.inner();
            if inner.decided.is_none() || inner.reads_in_flight > 0 {
                // Terminal cleanup can give up waiting before the restore
                // owner hands the host and lock to the late activation watcher.
                inner.late_start.get_or_insert_with(|| Box::new(start));
            } else {
                drop(inner);
                start();
            }
        }
    }

    /// Isolate caller fixtures that exercise route-wide cleanup cancellation.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn set_late_fronting_namespace_for_test(&self, namespace: usize) {
        self.route_namespace
            .store(namespace, std::sync::atomic::Ordering::Release);
    }

    /// The route this call arrived on, as `(channel, epoch)`.
    pub(crate) fn route(&self) -> (u16, u32) {
        (self.request.header.channel, self.request.header.epoch)
    }

    pub(crate) fn note_cursor_agent(&self, agent: &str) {
        *self
            .cursor_agent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(agent.to_owned());
    }

    pub(crate) fn cursor_agent(&self) -> Option<String> {
        self.cursor_agent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Grant application is not execution. Retain the answered card until the
    /// action's single terminal decision establishes what actually happened.
    pub(crate) fn track_consent(
        &self,
        desk: Arc<crate::cingulate_client::desk::ConsentDesk>,
        id: &str,
    ) {
        if !desk
            .raised(id)
            .is_some_and(|card| card.lifecycle.answered && card.lifecycle.final_report.is_none())
        {
            return;
        }
        let mut cards = self.gate.2.lock().unwrap();
        if !cards.iter().any(|(_, existing)| existing == id) {
            cards.push((desk, id.to_string()));
        }
    }

    pub(crate) fn track_grant_consent(&self, id: &str) {
        if let Some(desk) = self.consent_desk.lock().unwrap().clone() {
            self.track_consent(desk, id);
        }
    }

    fn finish_consent(&self, reply: &Frame) {
        use crate::cingulate_client::wire::{Execution, ExecutionReason};
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        let dispatched = self.state.lock().unwrap().possibly_dispatched
            || self.gate.0.load(std::sync::atomic::Ordering::SeqCst) & 1 != 0;
        let outcome = body["outcome"].as_str().unwrap_or_default();
        if outcome == "consent_pending" && !dispatched {
            // A grant can authorize classification before the action needs a
            // second permission. Waiting for that answer is not a refusal of
            // the earlier grant; its card still belongs to a future retry.
            return;
        }
        let refused_before_dispatch =
            body["input_dispatched"] == false || body["detail"]["dispatched"] == false;
        let success = reply.header.ty == FrameType::Response
            && matches!(
                outcome,
                "ok" | "completed"
                    | "launched"
                    | "launched_no_window"
                    | "already_running"
                    | "navigated"
                    | "opened"
                    | "clicked"
                    | "typed"
                    | "snapshot"
                    | "screenshot"
                    | "read"
            );
        if success
            && serde_json::from_slice::<Value>(&self.request.body)
                .ok()
                .is_some_and(|request| {
                    request["name"] == "browser_use"
                        && request["arguments"]["action"] == "open_grant"
                })
        {
            // Saving or checking permission does not run the browser action
            // that will eventually consume it.
            return;
        }
        let execution = if matches!(outcome, "dispatch_outcome_unknown" | "outcome_unknown") {
            Execution::OutcomeUnknown
        } else if body["effect_status"] == "not_dispatched" {
            Execution::ApprovedNotExecuted
        } else if success {
            Execution::Executed
        } else if refused_before_dispatch {
            Execution::ApprovedNotExecuted
        } else if dispatched {
            Execution::Executed
        } else {
            Execution::ApprovedNotExecuted
        };
        let reason = (execution == Execution::ApprovedNotExecuted).then(|| {
            crate::computer_grants::execution_refusal_reason(&body)
                .unwrap_or(ExecutionReason::RefusedAtDispatch)
        });
        for (desk, id) in self.gate.2.lock().unwrap().iter() {
            let _ = desk.finish_execution(id, execution, reason);
        }
    }

    /// Accounting guards can outlive a reply during worker cleanup, but may
    /// no longer authorize a new consent route or card once it is finalized.
    pub(crate) fn consent_call_held(&self) -> bool {
        !self.state.lock().unwrap().reply_finalized
    }

    #[cfg(test)]
    pub(crate) fn finalize_reply_for_test(&self) {
        self.state.lock().unwrap().reply_finalized = true;
    }

    pub fn set_step(&self, step: CallStep) {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_none() {
            state.step = step;
        }
    }

    /// Register only when a key or mouse-button press may still be held. The
    /// caller must move the release capacity permit into this job so a timeout
    /// cannot return that capacity while backend release work is still running.
    pub fn set_release(
        &self,
        release: impl std::future::Future<Output = HeldState> + Send + 'static,
    ) {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_none() {
            state.release = Some(Box::pin(release));
        }
    }

    /// Register the restore obligation of a temporary front, before its
    /// first front request. Independent of [`Self::set_release`]: a call may
    /// owe both, and terminal cleanup releases held input first.
    ///
    /// Refused when the terminal reply is already chosen: the obligation is
    /// dropped, releasing its fronting lock, and the worker must not front.
    /// A call fronts once, so a second registration is refused too while the
    /// first one's decision has not completed.
    pub fn register_restore(
        &self,
        obligation: RestoreObligation,
    ) -> Result<Arc<RestoreCell>, RestoreRegistrationRefused> {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some()
            || state
                .restore
                .as_ref()
                .is_some_and(|cell| cell.decided().is_none())
        {
            drop(state);
            drop(obligation);
            return Err(RestoreRegistrationRefused);
        }
        let cell = Arc::new(RestoreCell::new(
            obligation,
            self.fronting_domain
                .load(std::sync::atomic::Ordering::Acquire),
            self.route_namespace
                .load(std::sync::atomic::Ordering::Acquire),
            request_id(&self.request),
        ));
        state.restore = Some(Arc::clone(&cell));
        Ok(cell)
    }

    #[cfg(windows)]
    pub(crate) fn replace_windows_restore(
        &self,
        previous: &Arc<RestoreCell>,
        obligation: RestoreObligation,
    ) -> Result<Arc<RestoreCell>, RestoreRegistrationRefused> {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some()
            || state.reply_finalized
            || !state
                .restore
                .as_ref()
                .is_some_and(|cell| Arc::ptr_eq(cell, previous))
            || !previous.settled_windows_restore()
        {
            return Err(RestoreRegistrationRefused);
        }
        let cell = Arc::new(RestoreCell::new(
            obligation,
            self.fronting_domain
                .load(std::sync::atomic::Ordering::Acquire),
            self.route_namespace
                .load(std::sync::atomic::Ordering::Acquire),
            request_id(&self.request),
        ));
        state.restore = Some(Arc::clone(&cell));
        Ok(cell)
    }

    fn choose(&self, result: Option<Frame>, cause: TerminalCause) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some() {
            return false;
        }
        let dispatched = self.gate.stop();
        let committed = self.witness.committed();
        self.witness_committed
            .store(committed, std::sync::atomic::Ordering::SeqCst);
        self.gate_dispatched
            .store(dispatched, std::sync::atomic::Ordering::SeqCst);
        for hook in std::mem::take(&mut state.on_terminal) {
            hook();
        }
        state.cause = result.is_none().then_some(cause);
        for watcher in std::mem::take(&mut state.reply_watchers) {
            let _ = watcher.send(result.is_none());
        }
        state.possibly_dispatched = dispatched || committed;
        state.chosen = Some(result.unwrap_or_else(|| {
            let possible = dispatched || committed;
            let body = if possible {
                // Consent can be the last checkpoint even after its approval
                // starts a mutation. The gate/witness is stronger evidence:
                // never describe a possibly dispatched action as still queued
                // or waiting for permission.
                let step = match state.step {
                    CallStep::Admission
                    | CallStep::Queue
                    | CallStep::Consent
                    | CallStep::Preflight => CallStep::Dispatch,
                    step => step,
                };
                json!({"outcome":"dispatch_outcome_unknown",
                    "effect_status":"effect_indeterminate", "detail":{
                        "reason":cause.name(), "dispatched":true, "step":step.name(),
                        "held_state":if state.release.is_some() { "unknown" } else { "none_held" }},
                    "remedy":"read the state before retrying"})
            } else if matches!(cause, TerminalCause::Deadline) {
                json!({"outcome":"action_deadline_exceeded",
                    "detail":{"dispatched":false,"step":state.step.name()}})
            } else {
                let request: Value =
                    serde_json::from_slice(&self.request.body).unwrap_or(Value::Null);
                if request["name"].as_str().is_some_and(|name| {
                    name == flat_tools::BROWSER_USE || name.starts_with("browser.")
                }) {
                    json!({"outcome":cause.name(), "context":null})
                } else if request["name"].as_str().is_some_and(|name| {
                    name == flat_tools::COMPUTER_USE || name.starts_with("computer.")
                }) {
                    json!({"outcome":cause.name(), "attempts":0})
                } else {
                    json!({"outcome":cause.name()})
                }
            };
            Frame::build_with_version(
                self.request.header.ver,
                FrameType::Response,
                control_flags(),
                self.request.header.channel,
                self.request.header.epoch,
                self.request.header.corr,
                serde_json::to_vec(&body).expect("terminal body serializes"),
            )
            .expect("terminal frame fits")
        }));
        self.changed.notify_one();
        true
    }

    /// Register `close` to run under the terminal-state lock when the terminal
    /// is chosen. Returns true when registered. Returns false, running
    /// nothing, when the terminal was already chosen: the caller must then do
    /// the work of `close` itself. Either way it happens exactly once.
    ///
    /// A worker publishes a posting interval this way as soon as it opens one,
    /// so no interval stays open after its call's terminal, however long the
    /// worker itself stays blocked. `close` must be constant-time and
    /// non-blocking; see `TerminalState::on_terminal`.
    pub fn publish_or_close(&self, close: Box<dyn FnOnce() + Send>) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some() {
            return false;
        }
        state.on_terminal.push(close);
        true
    }

    pub fn stop(&self, cause: TerminalCause) -> bool {
        self.choose(None, cause)
    }

    fn complete(&self, frame: Frame) -> bool {
        self.choose(Some(frame), TerminalCause::Deadline)
    }

    /// Whether a Cancel frame for this call has already chosen its reply.
    ///
    /// A Cancel picks the reply here, synchronously, before the call's own
    /// work can see that it was cancelled. Until cleanup ends, a worker reply
    /// with the same stop outcome can still replace that body (see
    /// `preserve_stop_refusal`). A call parked on a consent card that ends
    /// because of the Cancel checks this and sends no reply of its own, so
    /// the bytes on the wire cannot depend on whether its reply would have
    /// reached the route before cleanup ended.
    pub(crate) fn answered_by_cancel(&self) -> bool {
        matches!(
            self.state.lock().unwrap().cause,
            Some(TerminalCause::Cancelled)
        )
    }

    /// Resolves to whether a stop (Cancel, deadline, route close or drain)
    /// chose this call's reply, rather than a reply the call's own work sent;
    /// at once when the reply is already chosen. Errs when the call ends with
    /// no reply chosen at all.
    pub(crate) fn watch_reply(&self) -> tokio::sync::oneshot::Receiver<bool> {
        let (watcher, chosen) = tokio::sync::oneshot::channel();
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some() {
            let _ = watcher.send(state.cause.is_some());
        } else {
            state.reply_watchers.push(watcher);
        }
        chosen
    }

    fn preserve_stop_refusal(&self, reply: Frame) {
        let mut state = self.state.lock().unwrap();
        if state.reply_finalized || state.possibly_dispatched {
            return;
        }
        let Some(cause) = state.cause else {
            return;
        };
        if matches!(cause, TerminalCause::Deadline) {
            return;
        }
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        let same_stop = match reply.header.ty {
            FrameType::Error => {
                body["code"] == cause.name()
                    || (matches!(cause, TerminalCause::RouteClosed) && body["code"] == "cancelled")
            }
            FrameType::Response => {
                body["outcome"] == cause.name()
                    || (body["outcome"] == "authorization_denied"
                        && (body["detail"]["decision"] == cause.name()
                            || (matches!(cause, TerminalCause::Draining)
                                && body["detail"]["decision"] == "draining")))
            }
            _ => false,
        };
        if same_stop {
            // The stop decision is final. During bounded cleanup, its existing
            // before-dispatch refusal may supply the legacy wire shape. Never
            // adopt success, or any result after dispatch may have begun.
            state.chosen = Some(reply);
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_arbitrated_route(
    worker: impl std::future::Future<Output = Result<(), ModuleError>> + Send + 'static,
    mut outgoing: mpsc::Receiver<Frame>,
    writer: mpsc::Sender<Frame>,
    planes: Planes,
    cancellation: RequestCancellationGuard,
    guard: Arc<cerebellum_core::dispatch::InFlightGuard>,
    terminal: Arc<TerminalArbiter>,
    envelope_end: tokio::time::Instant,
    connection_end: tokio::time::Instant,
) {
    terminal.route_namespace.store(
        cancellation.registry.namespace(),
        std::sync::atomic::Ordering::Release,
    );
    *terminal.consent_desk.lock().unwrap() = Some(Arc::clone(&planes.consent));
    let execution = Arc::new(std::sync::Mutex::new(Some(Arc::clone(&guard))));
    let worker_execution = Arc::clone(&execution);
    // Supply in-flight accounting only while polling active route work. After
    // its terminal reply, the worker keeps its lane guards until it ends, but
    // the detached-worker counter replaces its in-flight request count.
    let mut worker = Box::pin(worker);
    let guarded = std::future::poll_fn(move |cx| {
        let guard = worker_execution.lock().unwrap().clone();
        match guard {
            Some(guard) => call_context::ROUTE_GUARD.sync_scope(guard, || worker.as_mut().poll(cx)),
            None => worker.as_mut().poll(cx),
        }
    });
    let mut job = Box::pin(call_context::CALL_DEADLINE.scope(
        envelope_end,
        CALL_TERMINAL.scope(Arc::clone(&terminal), guarded),
    ));
    let request = request_id(&terminal.request);
    let mut drain = planes.drain_signal.subscribe();
    let mut finished = false;
    loop {
        if terminal.state.lock().unwrap().chosen.is_some() {
            break;
        }
        tokio::select! {
            biased;
            out = outgoing.recv() => if let Some(out) = out {
                if terminal_frame(&out, request) {
                    if !terminal.complete(out.clone()) { terminal.preserve_stop_refusal(out); }
                } else {
                    if !matches!(tokio::time::timeout_at(envelope_end.min(connection_end), send(&writer, out)).await, Ok(Ok(()))) {
                        outgoing.close();
                        terminal.stop(TerminalCause::Deadline);
                    }
                }
            },
            result = &mut job => {
                finished = true;
                let _ = result;
                while let Ok(out) = outgoing.try_recv() {
                    if terminal_frame(&out, request) { if !terminal.complete(out.clone()) { terminal.preserve_stop_refusal(out); } }
                    else { let _ = tokio::time::timeout_at(connection_end, send(&writer, out)).await; }
                }
                break;
            },
            _ = terminal.changed.notified() => {},
            _ = tokio::time::sleep_until(envelope_end) => { terminal.stop(TerminalCause::Deadline); },
            _ = cancellation.handle.cancelled() => {
                terminal.stop(if planes.routes.get(request.0, request.1).is_none() {
                    TerminalCause::RouteClosed
                } else { TerminalCause::Cancelled });
            },
            _ = async { while !*drain.borrow_and_update() { if drain.changed().await.is_err() { break; } } } => {
                terminal.stop(TerminalCause::Draining);
            },
        }
    }
    let (chosen, release, restore, pending) = {
        let mut state = terminal.state.lock().unwrap();
        (
            state.chosen.clone(),
            state.release.take(),
            state.restore.take(),
            state.settlement.take(),
        )
    };
    if let Some(mut chosen) = chosen {
        if release.is_none() && restore.is_none() && !finished {
            // When no held-input release or restore is needed, use their
            // RELEASE_BUDGET_MS allowance for cooperative cancellation
            // cleanup, so the call can end its consent wait before the caller
            // receives the refusal. A stuck worker is detached after the same
            // bounded window.
            let cleanup = async {
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut job => { finished = true; break; },
                        Some(out) = outgoing.recv() => if terminal_frame(&out, request) {
                            terminal.preserve_stop_refusal(out);
                        } else { let _ = send(&writer, out).await; },
                    }
                }
            };
            let _ =
                tokio::time::timeout(Duration::from_millis(budgets::RELEASE_BUDGET_MS), cleanup)
                    .await;
        }
        while let Ok(out) = outgoing.try_recv() {
            if terminal_frame(&out, request) {
                terminal.preserve_stop_refusal(out);
            } else {
                let _ = tokio::time::timeout_at(connection_end, send(&writer, out)).await;
            }
        }
        {
            let mut state = terminal.state.lock().unwrap();
            state.reply_finalized = true;
            if let Some(reply) = &state.chosen {
                chosen = reply.clone();
            }
        }
        // Held-input release first, then the restore, within one shared
        // RELEASE_BUDGET_MS: restoring while a key may still be held would
        // deliver it to the previous application.
        let suffix_end =
            tokio::time::Instant::now() + Duration::from_millis(budgets::RELEASE_BUDGET_MS);
        let mut held = None;
        // A release still running when its window ends. With a restore
        // obligation, the owner still restores once it settles; the reply
        // only says the restore failed for now.
        let mut unsettled_release = None;
        if let Some(release) = release {
            let mut release_job = tokio::spawn(release);
            held = Some(
                match tokio::time::timeout_at(suffix_end, &mut release_job).await {
                    Ok(Ok(held)) => held,
                    Ok(Err(_)) => HeldState::Unknown,
                    Err(_) => {
                        unsettled_release = Some(release_job);
                        HeldState::Unknown
                    }
                },
            );
        }
        if let (Some(cell), Some(_)) = (&restore, &unsettled_release) {
            cell.reply_sent_before_release();
        }
        let decided = match &restore {
            Some(cell) => Some(finish_restore(Arc::clone(cell), suffix_end).await),
            None => None,
        };
        if let Some(release_job) = unsettled_release {
            detach_release(release_job, &planes);
        }
        terminal.start_late_fronting(restore.as_ref());
        if let Some(held) = held {
            chosen = rebuild_body(chosen, |body| {
                if body["outcome"] == "dispatch_outcome_unknown" {
                    body["detail"]["held_state"] = json!(held.name());
                }
            });
        }
        // Consent learns what the action itself did, before a failed restore
        // replaces the outcome naming it.
        terminal.finish_consent(&chosen);
        if let (Some(cell), Some(decided)) = (&restore, decided) {
            if chosen.header.ty == FrameType::Response {
                chosen = rebuild_body(chosen, |body| cell.disclose(body, decided));
            }
        }
        if serde_json::from_slice::<Value>(&chosen.body)
            .ok()
            .is_some_and(|body| body["outcome"] == "route_closed")
        {
            // This closed route produced no before-dispatch refusal to send.
            // Remove its pending delivery deadline so it cannot kill unrelated
            // routes. Queued browser calls that produced Error(cancelled) above
            // still send that frame and await the writer's flush acknowledgement.
            planes.egress_deadlines.delivered(&[request]);
            if let Some(mut pending) = pending {
                if let Some(ticket) = pending.ticket.take() {
                    let calls = Arc::clone(&planes.calls);
                    settle_call_record(&planes, move || {
                        calls.settle_unknown(ticket, wall_clock_ms())
                    })
                    .await;
                }
            }
        } else if let Some(mut pending) = pending {
            let _ = tokio::time::timeout_at(
                connection_end,
                forward_recording_reply(chosen, &mut pending, &writer, &planes),
            )
            .await;
        } else {
            let _ = tokio::time::timeout_at(connection_end, send(&writer, chosen)).await;
        }
    } else {
        if let Some(cell) = restore {
            // The worker sent no reply. After a bounded wait for a restore
            // decision, abandon only if the owner did not take the host.
            // An owner already deciding must keep the lock until it ends.
            let detached = planes.health.enter_detached_worker();
            let decision = tokio::task::spawn_blocking(move || {
                let give_up =
                    std::time::Instant::now() + Duration::from_millis(OWNER_GONE_AFTER_MS);
                if cell.await_owner(give_up).is_none() {
                    cell.abandon_undecided();
                }
                terminal.start_late_fronting(Some(&cell));
            });
            tokio::spawn(async move {
                let _detached = detached;
                let _ = decision.await;
            });
        }
        if let Some(mut pending) = pending {
            if let Some(ticket) = pending.ticket.take() {
                let calls = Arc::clone(&planes.calls);
                settle_call_record(&planes, move || {
                    calls.settle_unknown(ticket, wall_clock_ms())
                })
                .await;
            }
        }
    }
    execution.lock().unwrap().take();
    drop(guard);
    drop(cancellation);
    // Keep the route future and its lane leases alive until it really ends.
    // A detached worker's terminal reply has already been chosen, so any
    // later terminal it produces must be discarded.
    let detached = (!finished).then(|| planes.health.enter_detached_worker());
    tokio::spawn(async move {
        let mut detached = detached;
        loop {
            tokio::select! {
                out = outgoing.recv() => match out {
                    Some(out) if !terminal_frame(&out, request) => { let _ = send(&writer, out).await; },
                    Some(_) => {},
                    None if finished => break,
                    None => { let _ = (&mut job).await; break; },
                },
                _ = &mut job, if !finished => { finished = true; detached.take(); },
            }
        }
    });
}

/// Keep a release that outlived its window running detached until it ends.
fn detach_release(release_job: tokio::task::JoinHandle<HeldState>, planes: &Planes) {
    let detached = planes.health.enter_detached_worker();
    tokio::spawn(async move {
        let _detached = detached;
        let _ = release_job.await;
    });
}

/// Terminal cleanup's half of a restore obligation, after held-input
/// release. It never restores: the bracket's thread owns the decision. A
/// front not yet requested is stopped and needs no restore; otherwise this
/// waits on a blocking thread, until `end` at most, for the owner's
/// decision. One not made by then is reported failed for now; the owner
/// still makes it, and a late watch it owes starts once it has.
async fn finish_restore(cell: Arc<RestoreCell>, end: tokio::time::Instant) -> RestoreDecided {
    let waiter = Arc::clone(&cell);
    let give_up =
        std::time::Instant::now() + end.saturating_duration_since(tokio::time::Instant::now());
    let wait = tokio::task::spawn_blocking(move || waiter.await_owner(give_up));
    match tokio::time::timeout_at(end, wait).await {
        Ok(Ok(Some(decided))) => decided,
        Ok(Ok(None) | Err(_)) | Err(_) => cell.failed(),
    }
}

/// Apply `update` to a JSON reply body and rebuild the frame, so the wire
/// body length agrees with the update. A body that does not parse, or that
/// `update` leaves unchanged, keeps its original bytes.
fn rebuild_body(frame: Frame, update: impl FnOnce(&mut Value)) -> Frame {
    let Ok(original) = serde_json::from_slice::<Value>(&frame.body) else {
        return frame;
    };
    let mut body = original.clone();
    update(&mut body);
    let body = cerebellum_computer::audit::FinalFrontingResult::new(body).into_value();
    if body == original {
        return frame;
    }
    Frame::build_with_version(
        frame.header.ver,
        frame.header.ty,
        frame.header.flags,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
        serde_json::to_vec(&body).expect("terminal body serializes"),
    )
    .expect("terminal frame fits")
}

#[cfg(test)]
mod consent_execution_tests {
    use super::*;
    use crate::cingulate_client::card::CardKind;
    use crate::cingulate_client::desk::{CardLifecycle, ConsentDesk, RaisedCard, RegistryStore};
    use crate::cingulate_client::double::ScriptedCingulate;
    use crate::cingulate_client::live_call::SessionKey;
    use crate::cingulate_client::wire::{Execution, ExecutionReason};

    struct Saved(std::sync::Mutex<Vec<RaisedCard>>);
    impl RegistryStore for Saved {
        fn load(&self) -> Result<Vec<RaisedCard>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save(&self, cards: &[RaisedCard]) -> Result<(), String> {
            *self.0.lock().unwrap() = cards.to_vec();
            Ok(())
        }
    }

    #[test]
    fn durable_browser_app_and_takeover_cards_wait_through_another_pending_permission() {
        for (kind, choice) in [
            (CardKind::UserBrowserSite, "allow_origin_always"),
            (CardKind::AppControl, "allow_30m"),
            (CardKind::Takeover, "computer_30m"),
        ] {
            let store = Arc::new(Saved(std::sync::Mutex::new(vec![RaisedCard {
                elicitation_id: "el_saved".into(),
                session: SessionKey {
                    owner: "owner".into(),
                    scope_ref: "scope".into(),
                    scope_epoch: 1,
                },
                kind,
                subject: "target".into(),
                grant_ids: vec![choice.into()],
                decline_id: "deny".into(),
                next_steps: Default::default(),
                applied: true,
                lifecycle: CardLifecycle {
                    answered: true,
                    answer_choice: Some(choice.into()),
                    deferred_use: true,
                    ..Default::default()
                },
            }])));
            let desk = Arc::new(ConsentDesk::with_store(
                Arc::new(ScriptedCingulate::new()),
                store.clone(),
            ));
            for dispatch in [false, true] {
                let request =
                    Frame::build(FrameType::Request, control_flags(), 1, 1, 1, vec![]).unwrap();
                let terminal = TerminalArbiter::new(request);
                terminal.track_consent(Arc::clone(&desk), "el_saved");
                if dispatch {
                    assert!(terminal.gate.begin_mutation());
                }
                let body = if dispatch {
                    json!({"outcome":"ok"})
                } else {
                    json!({"outcome":"consent_pending","input_dispatched":false})
                };
                let reply = Frame::build(
                    FrameType::Response,
                    control_flags(),
                    1,
                    1,
                    1,
                    serde_json::to_vec(&body).unwrap(),
                )
                .unwrap();
                terminal.finish_consent(&reply);
                let card = &store.load().unwrap()[0];
                if dispatch {
                    assert_eq!(
                        card.lifecycle.final_report.unwrap().execution,
                        Execution::Executed,
                        "{kind:?}"
                    );
                } else {
                    assert_eq!(card.lifecycle.final_report, None, "{kind:?}");
                    assert!(!card.lifecycle.dispatch_started);
                }
            }
        }
    }

    #[test]
    fn final_action_reports_distinguish_dispatch_refusal_and_postdispatch_deadline() {
        for kind in [
            CardKind::AppControl,
            CardKind::Takeover,
            CardKind::WebsiteAccessInCall,
            CardKind::UserBrowserSite,
        ] {
            for (dispatch, body, execution, reason) in [
                (true, json!({"outcome":"ok"}), Execution::Executed, None),
                (
                    true,
                    json!({"outcome":"consent_pending"}),
                    Execution::Executed,
                    None,
                ),
                (
                    false,
                    json!({"outcome":"ok","input_dispatched":false}),
                    Execution::Executed,
                    None,
                ),
                (
                    true,
                    json!({"outcome":"dispatch_outcome_unknown"}),
                    Execution::OutcomeUnknown,
                    None,
                ),
                (
                    true,
                    json!({"outcome":"refused","effect_status":"not_dispatched","reason":"target_gone"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::TargetGone),
                ),
                (
                    false,
                    json!({"outcome":"refused","reason":"screen_locked"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::RefusedAtDispatch),
                ),
                (
                    false,
                    json!({"outcome":"refused","reason":"target_gone"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::TargetGone),
                ),
                (
                    false,
                    json!({"outcome":"refused","reason":"grant_store_write_failed"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::GrantStoreUnavailable),
                ),
                (
                    false,
                    json!({"outcome":"route_closed"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::SessionEnded),
                ),
            ] {
                let store = Arc::new(Saved(std::sync::Mutex::new(vec![RaisedCard {
                    elicitation_id: "el_final".into(),
                    session: SessionKey {
                        owner: "owner".into(),
                        scope_ref: "scope".into(),
                        scope_epoch: 1,
                    },
                    kind,
                    subject: "target".into(),
                    grant_ids: vec!["allow".into()],
                    decline_id: "deny".into(),
                    next_steps: Default::default(),
                    applied: true,
                    lifecycle: CardLifecycle {
                        answered: true,
                        ..Default::default()
                    },
                }])));
                let peer = ScriptedCingulate::new();
                let desk = Arc::new(ConsentDesk::with_store(
                    Arc::new(peer.clone()),
                    store.clone(),
                ));
                let request =
                    Frame::build(FrameType::Request, control_flags(), 1, 1, 1, vec![]).unwrap();
                let terminal = TerminalArbiter::new(request);
                terminal.track_consent(Arc::clone(&desk), "el_final");
                assert!(
                    desk.raised("el_final")
                        .unwrap()
                        .lifecycle
                        .final_report
                        .is_none(),
                    "waiting to run is not an execution"
                );
                if dispatch {
                    assert!(terminal.gate.begin_mutation());
                }
                let reply = Frame::build(
                    FrameType::Response,
                    control_flags(),
                    1,
                    1,
                    1,
                    serde_json::to_vec(&body).unwrap(),
                )
                .unwrap();
                terminal.finish_consent(&reply);
                let report = store.load().unwrap()[0].lifecycle.final_report.unwrap();
                assert_eq!(
                    (report.execution, report.reason),
                    (execution, reason),
                    "{kind:?}: {body}"
                );
                terminal.finish_consent(
                    &Frame::build(
                        FrameType::Response,
                        control_flags(),
                        1,
                        1,
                        1,
                        serde_json::to_vec(&json!({"outcome":"ok"})).unwrap(),
                    )
                    .unwrap(),
                );
                assert_eq!(
                    store.load().unwrap()[0].lifecycle.final_report,
                    Some(report),
                    "a late worker result replaced the terminal outcome"
                );
                assert_eq!(peer.opens(), 0, "finalization opened a background route");
            }
        }
    }
}

#[cfg(test)]
mod arbiter_egress_tests {
    use super::*;
    use crate::egress::{drain_writer, ConnectionDeadlines};
    use crate::{
        browser, build_error_frame, computer, handle_frame, management, route_limits,
        run_connection, write_frame, BrowserSurface, HealthConfig, ModuleConfig, EGRESS_BUFFER,
        HELLO_CORR, PROTOCOL_VERSION,
    };
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use subc_protocol::session::ModuleControlResponse;
    use tokio::io::AsyncWrite;

    fn frame(ty: FrameType, corr: u64, body: Vec<u8>) -> Frame {
        Frame::build_with_version(PROTOCOL_VERSION, ty, control_flags(), 1, 1, corr, body).unwrap()
    }

    fn hello_ack() -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::HelloAck,
            control_flags(),
            0,
            0,
            HELLO_CORR,
            serde_json::to_vec(
                &json!({"negotiated_ver":PROTOCOL_VERSION,"subc_ops":[],"subc_capabilities":[]}),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn request() -> Frame {
        frame(
            FrameType::Request,
            1,
            serde_json::to_vec(&json!({
                "method":management::OPEN_TARGET,"params":{"bundle_identity":"com.example.Nothing"}
            }))
            .unwrap(),
        )
    }

    fn body(terminal: &TerminalArbiter) -> Value {
        serde_json::from_slice(&terminal.state.lock().unwrap().chosen.as_ref().unwrap().body)
            .unwrap()
    }

    #[test]
    fn terminal_hooks_run_once_per_terminal_and_never_after_it() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let causes: [Option<TerminalCause>; 5] = [
            None,
            Some(TerminalCause::Deadline),
            Some(TerminalCause::Cancelled),
            Some(TerminalCause::RouteClosed),
            Some(TerminalCause::Draining),
        ];
        for cause in causes {
            let terminal = TerminalArbiter::new(request());
            let runs = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&runs);
            assert!(terminal.publish_or_close(Box::new(move || {
                counted.fetch_add(1, SeqCst);
            })));
            assert_eq!(runs.load(SeqCst), 0, "a hook runs only at the terminal");
            match cause {
                Some(cause) => assert!(terminal.stop(cause)),
                None => assert!(terminal.complete(frame(
                    FrameType::Response,
                    1,
                    br#"{"outcome":"ok"}"#.to_vec()
                ))),
            }
            assert_eq!(runs.load(SeqCst), 1, "the hook ran once at the terminal");
            assert!(!terminal.stop(TerminalCause::Cancelled));
            assert_eq!(runs.load(SeqCst), 1, "a second choice runs nothing");
            let late = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&late);
            assert!(
                !terminal.publish_or_close(Box::new(move || {
                    counted.fetch_add(1, SeqCst);
                })),
                "registration after the terminal is reported to the caller"
            );
            assert_eq!(late.load(SeqCst), 0, "and its hook is never run");
        }
    }

    #[test]
    fn second_terminal_cannot_replace_success_or_unknown_and_seals_dispatch() {
        let success = TerminalArbiter::new(request());
        assert!(success.gate.begin_mutation());
        assert!(success.complete(frame(
            FrameType::Response,
            1,
            br#"{"outcome":"ok"}"#.to_vec()
        )));
        assert!(!success.stop(TerminalCause::Deadline));
        assert_eq!(body(&success)["outcome"], "ok");
        assert!(!success.gate.begin_mutation());

        let expired = TerminalArbiter::new(request());
        assert!(expired.gate.begin_mutation());
        expired.set_step(CallStep::Dispatch);
        assert!(expired.stop(TerminalCause::Deadline));
        assert!(!expired.complete(frame(
            FrameType::Response,
            1,
            br#"{"outcome":"ok"}"#.to_vec()
        )));
        assert!(!expired.stop(TerminalCause::Cancelled));
        assert_eq!(body(&expired)["outcome"], "dispatch_outcome_unknown");
        assert_eq!(
            body(&expired)["detail"]["reason"],
            "action_deadline_exceeded"
        );
        assert!(!expired.gate.begin_mutation());
        assert!(expired
            .gate_dispatched
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn cooperative_stop_keeps_legacy_refusal_but_not_success_or_late_reply() {
        let terminal = TerminalArbiter::new(request());
        terminal.stop(TerminalCause::Cancelled);
        let refusal =
            build_error_frame(PROTOCOL_VERSION, 1, 1, 1, "cancelled", "cancelled in queue")
                .unwrap();
        terminal.preserve_stop_refusal(refusal.clone());
        assert_eq!(
            terminal.state.lock().unwrap().chosen.as_ref(),
            Some(&refusal)
        );
        terminal.preserve_stop_refusal(frame(
            FrameType::Response,
            1,
            br#"{"outcome":"ok","detail":{"decision":"cancelled"}}"#.to_vec(),
        ));
        assert_eq!(
            terminal.state.lock().unwrap().chosen.as_ref(),
            Some(&refusal)
        );
        terminal.state.lock().unwrap().reply_finalized = true;
        terminal.preserve_stop_refusal(
            build_error_frame(PROTOCOL_VERSION, 1, 1, 1, "cancelled", "late replacement").unwrap(),
        );
        assert_eq!(
            terminal.state.lock().unwrap().chosen.as_ref(),
            Some(&refusal)
        );

        let unknown = TerminalArbiter::new(request());
        assert!(unknown.gate.begin_mutation());
        unknown.stop(TerminalCause::Cancelled);
        unknown.preserve_stop_refusal(refusal);
        assert_eq!(body(&unknown)["outcome"], "dispatch_outcome_unknown");
    }

    #[test]
    fn terminal_shapes_pass_frozen_schemas_in_every_named_phase() {
        for step in [
            CallStep::Admission,
            CallStep::Queue,
            CallStep::Consent,
            CallStep::Preflight,
            CallStep::Dispatch,
            CallStep::Release,
        ] {
            let deadline = TerminalArbiter::new(request());
            deadline.set_step(step);
            deadline.stop(TerminalCause::Deadline);
            browser::validate_browser_result("browser.navigate", &body(&deadline)).unwrap();
            computer::platform::vocabulary::validate_capability_result(
                "computer.read_state",
                &body(&deadline),
            )
            .unwrap();
            fronting_terminal_bodies_pass(&body(&deadline));
            for cause in [
                TerminalCause::Deadline,
                TerminalCause::Cancelled,
                TerminalCause::RouteClosed,
                TerminalCause::Draining,
            ] {
                let unknown = TerminalArbiter::new(request());
                unknown.set_step(step);
                unknown.witness.mark_committed();
                unknown.stop(cause);
                let reply = body(&unknown);
                assert_eq!(
                    reply["detail"]["step"],
                    if matches!(step, CallStep::Release) {
                        "release"
                    } else {
                        "dispatch"
                    }
                );
                browser::validate_browser_result("browser.navigate", &reply).unwrap();
                browser::validate_browser_result(management::CAPTURE_LOGIN, &reply).unwrap();
                computer::platform::vocabulary::validate_capability_result(
                    "computer.read_state",
                    &reply,
                )
                .unwrap();
                fronting_terminal_bodies_pass(&reply);
            }
        }
    }

    /// Every terminal body is checked against each fronting row's result
    /// schema, as it is and as it reads after a front: carrying `fronting`,
    /// and with a failed restore turning the outcome into `restore_failed`
    /// while the body's `detail` and `effect_status` are kept. Each reply must
    /// satisfy the whole result schema, including the keystroke rows.
    fn fronting_terminal_bodies_pass(terminal: &Value) {
        use computer::platform::vocabulary::validate_capability_result;
        let mut fronted = terminal.clone();
        fronted["fronting"] = json!({"mode":"background", "fronted":true,
            "purpose":"needs_front", "restore":"restored"});
        let mut restore_failed = fronted.clone();
        restore_failed["fronting"]["restore"] = json!("failed");
        restore_failed["outcome"] = json!("restore_failed");
        restore_failed["remedy"] =
            json!("Mail was left in front; switch back to the application you were using");
        for capability in [
            "computer.read_state",
            "computer.press_element",
            "computer.press_point",
            "computer.write_text",
            "computer.type",
            "computer.keys",
            "computer.open_app",
        ] {
            for reply in [terminal, &fronted, &restore_failed] {
                validate_capability_result(capability, reply)
                    .unwrap_or_else(|error| panic!("{capability}: {reply}: {error}"));
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn management_envelope_replies_and_counts_worker_until_it_really_ends() {
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let (ready, started) = tokio::sync::oneshot::channel();
        let (finish, ended) = tokio::sync::oneshot::channel();
        let inputs = std::sync::Mutex::new(Some((ready, ended)));
        planes.route_test_handler = Some(Arc::new(move || {
            let (ready, ended) = inputs.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                ready.send(()).unwrap();
                ended.await.unwrap();
                assert!(!terminal.gate.begin_mutation());
            })
        }));
        let (tx, mut rx) = mpsc::channel(8);
        let arrival = tokio::time::Instant::now();
        let (envelope_ms, reply_ms) = route_limits(&request(), &planes);
        handle_frame(request(), &tx, &planes).await.unwrap();
        started.await.unwrap();
        tokio::time::advance(Duration::from_millis(envelope_ms)).await;
        let reply = rx.recv().await.unwrap();
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown");
        assert_eq!(reply["detail"]["step"], "dispatch");
        assert!(arrival.elapsed() <= Duration::from_millis(reply_ms));
        let ModuleControlResponse::HealthCheck {
            status,
            metrics: Some(metrics),
            ..
        } = planes.health.report()
        else {
            panic!("health report")
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Degraded);
        assert_eq!(metrics["detachedWorkers"], 1);
        assert_eq!(metrics["inFlightActions"], 0);
        finish.send(()).unwrap();
        while planes.health.detached_workers() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(
            rx.try_recv().is_err(),
            "late completion sent a second terminal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn envelope_expiry_names_each_phase_through_production_route() {
        for step in [
            CallStep::Admission,
            CallStep::Queue,
            CallStep::Consent,
            CallStep::Preflight,
            CallStep::Dispatch,
        ] {
            let mut planes = crate::tests::management_bound_planes(1, 1);
            let (ready, started) = tokio::sync::oneshot::channel();
            let (finish, finished) = tokio::sync::oneshot::channel();
            let input = std::sync::Mutex::new(Some((ready, finished)));
            planes.route_test_handler = Some(Arc::new(move || {
                let (ready, finished) = input.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    let terminal = TerminalArbiter::current().unwrap();
                    terminal.set_step(step);
                    ready.send(()).unwrap();
                    let _ = finished.await;
                    assert!(!terminal.gate.begin_mutation());
                })
            }));
            let (envelope_ms, reply_ms) = route_limits(&request(), &planes);
            let arrival = tokio::time::Instant::now();
            let (tx, mut rx) = mpsc::channel(8);
            handle_frame(request(), &tx, &planes).await.unwrap();
            started.await.unwrap();
            tokio::time::advance(Duration::from_millis(envelope_ms)).await;
            let reply = rx.recv().await.unwrap();
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "action_deadline_exceeded");
            assert_eq!(body["detail"]["step"], step.name());
            assert_eq!(body["detail"]["dispatched"], false);
            browser::validate_browser_result(management::CAPTURE_LOGIN, &body).unwrap();
            assert!(arrival.elapsed() <= Duration::from_millis(reply_ms));
            finish.send(()).unwrap();
            while planes.health.detached_workers() != 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_close_and_drain_after_dispatch_keep_one_unknown_terminal() {
        for cause in [
            TerminalCause::Cancelled,
            TerminalCause::RouteClosed,
            TerminalCause::Draining,
        ] {
            let mut planes = crate::tests::management_bound_planes(1, 1);
            let (ready, started) = tokio::sync::oneshot::channel();
            let (finish, finished) = tokio::sync::oneshot::channel();
            let input = std::sync::Mutex::new(Some((ready, finished)));
            planes.route_test_handler = Some(Arc::new(move || {
                let (ready, finished) = input.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    let terminal = TerminalArbiter::current().unwrap();
                    terminal.set_step(CallStep::Dispatch);
                    assert!(terminal.gate.begin_mutation());
                    ready.send(()).unwrap();
                    let _ = finished.await;
                    assert!(!terminal.gate.begin_mutation());
                })
            }));
            let (tx, mut rx) = mpsc::channel(8);
            handle_frame(request(), &tx, &planes).await.unwrap();
            started.await.unwrap();
            let stop = match cause {
                TerminalCause::Cancelled => frame(FrameType::Cancel, 1, Vec::new()),
                TerminalCause::RouteClosed => frame(FrameType::Goodbye, 0, Vec::new()),
                TerminalCause::Draining => Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Push,
                    control_flags(),
                    0,
                    0,
                    0,
                    serde_json::to_vec(
                        &json!({"op":"module.draining","reason":"restart","deadline_ms":123}),
                    )
                    .unwrap(),
                )
                .unwrap(),
                TerminalCause::Deadline => unreachable!(),
            };
            handle_frame(stop, &tx, &planes).await.unwrap();
            let reply = rx.recv().await.unwrap();
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "dispatch_outcome_unknown");
            assert_eq!(body["detail"]["reason"], cause.name());
            assert_eq!(planes.health.detached_workers(), 1);
            finish.send(()).unwrap();
            while planes.health.detached_workers() != 0 {
                tokio::task::yield_now().await;
            }
            assert!(rx.try_recv().is_err());
        }
    }

    struct NeverWriter;
    impl AsyncWrite for NeverWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn successful_enqueue_is_not_delivery_and_never_writer_fails_connection() {
        let planes = crate::tests::management_bound_planes(1, 1);
        let deadlines = Arc::clone(&planes.egress_deadlines);
        let (mut peer, mut reader) = tokio::io::duplex(64 * 1024);
        write_frame(&mut peer, &hello_ack()).await.unwrap();
        write_frame(&mut peer, &request()).await.unwrap();
        let config = ModuleConfig {
            connection_file_path: PathBuf::new(),
            module_id: "egress-test".into(),
            health: HealthConfig::DEFAULT,
            agent_cursor: false,
            browser: BrowserSurface::NotConfigured,
        };
        let arrival = tokio::time::Instant::now();
        let (_, reply_ms) = route_limits(&request(), &planes);
        let result = run_connection(&mut reader, NeverWriter, &config, planes).await;
        assert!(
            matches!(result, Err(ModuleError::Message(message)) if message.contains("terminal delivery deadline"))
        );
        assert_eq!(arrival.elapsed(), Duration::from_millis(reply_ms));
        assert_eq!(deadlines.pending.lock().unwrap().len(), 1);
    }

    struct MeteredWriter {
        rate: u64,
        waiting: Option<Pin<Box<tokio::time::Sleep>>>,
        bytes: Arc<std::sync::atomic::AtomicU64>,
        flushed: Arc<std::sync::atomic::AtomicU64>,
        flushes: Arc<std::sync::atomic::AtomicUsize>,
        start: tokio::time::Instant,
        flush_time: Duration,
    }
    impl MeteredWriter {
        fn new(rate: u64) -> Self {
            Self {
                rate,
                waiting: None,
                bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                flushed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                flushes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                start: tokio::time::Instant::now(),
                flush_time: Duration::ZERO,
            }
        }
        fn wait_until(&mut self, cx: &mut Context<'_>, end: tokio::time::Instant) -> Poll<()> {
            let sleep = self
                .waiting
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(end)));
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.waiting = None;
            Poll::Ready(())
        }
    }
    impl AsyncWrite for MeteredWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let bytes = self.bytes.load(std::sync::atomic::Ordering::SeqCst) + buf.len() as u64;
            let end = self.start
                + self.flush_time
                + Duration::from_nanos((bytes * 1_000_000_000).div_ceil(self.rate));
            if self.wait_until(cx, end).is_pending() {
                return Poll::Pending;
            }
            self.bytes
                .fetch_add(buf.len() as u64, std::sync::atomic::Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let bytes = self.bytes.load(std::sync::atomic::Ordering::SeqCst);
            let flush_time = self.flush_time + Duration::from_millis(budgets::EGRESS_FLUSH_MS);
            let end = self.start
                + flush_time
                + Duration::from_nanos((bytes * 1_000_000_000).div_ceil(self.rate));
            if self.wait_until(cx, end).is_pending() {
                return Poll::Pending;
            }
            self.flush_time = flush_time;
            self.flushed.store(
                self.bytes.load(std::sync::atomic::Ordering::SeqCst),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_producers_cannot_defer_flush_past_one_buffer() {
        let deadlines = Arc::new(ConnectionDeadlines::default());
        let (tx, rx) = mpsc::channel(EGRESS_BUFFER);
        let writer = MeteredWriter::new(budgets::EGRESS_MIN_BYTES_PER_S);
        let bytes = Arc::clone(&writer.bytes);
        let flushed = Arc::clone(&writer.flushed);
        let flushes = Arc::clone(&writer.flushes);
        let message = frame(FrameType::Push, 2, vec![0; 8192]);
        let frame_bytes = subc_protocol::HEADER_LEN as u64 + message.body.len() as u64;
        for _ in 0..EGRESS_BUFFER {
            tx.send(message.clone()).await.unwrap();
        }
        let producer = tokio::spawn(async move {
            loop {
                if tx.send(message.clone()).await.is_err() {
                    break;
                }
            }
        });
        let job = tokio::spawn(drain_writer(writer, rx, deadlines));
        while flushes.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::time::advance(Duration::from_millis(1)).await;
            if flushes.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                assert!(
                    bytes.load(std::sync::atomic::Ordering::SeqCst)
                        <= EGRESS_BUFFER as u64 * frame_bytes,
                    "writer passed a full batch without flushing"
                );
            }
        }
        assert_eq!(
            flushed.load(std::sync::atomic::Ordering::SeqCst),
            EGRESS_BUFFER as u64 * frame_bytes
        );
        job.abort();
        producer.abort();
        let _ = job.await;
        let _ = producer.await;
    }

    #[tokio::test(start_paused = true)]
    async fn maximum_frames_at_throughput_floor_deliver_within_egress_budget() {
        let deadlines = Arc::new(ConnectionDeadlines::default());
        let (tx, rx) = mpsc::channel(EGRESS_BUFFER);
        let arrival = tokio::time::Instant::now();
        let writer = MeteredWriter::new(budgets::EGRESS_MIN_BYTES_PER_S);
        let flushed = Arc::clone(&writer.flushed);
        let job = tokio::spawn(drain_writer(writer, rx, Arc::clone(&deadlines)));
        // Use real maximum-size frame bodies; the writer charges actual bytes,
        // including transport framing, rather than a scaled timing surrogate.
        for _ in 0..2 * EGRESS_BUFFER - 1 {
            tx.send(frame(
                FrameType::Push,
                2,
                vec![0; subc_protocol::MAX_FRAME_BODY_LEN as usize],
            ))
            .await
            .unwrap();
        }
        let end = arrival + Duration::from_millis(budgets::EGRESS_SEND_MS);
        deadlines.arm((1, 1, 1), end);
        tx.send(frame(
            FrameType::Response,
            1,
            vec![0; subc_protocol::MAX_FRAME_BODY_LEN as usize],
        ))
        .await
        .unwrap();
        let delivered = async {
            loop {
                let changed = deadlines.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if deadlines.pending.lock().unwrap().is_empty() {
                    break;
                }
                changed.await;
            }
        };
        tokio::select! {
            biased;
            _ = delivered => {},
            _ = deadlines.expired() => panic!("floor-rate peer lost its delivery deadline at {:?}; flushed {}", arrival.elapsed(), flushed.load(std::sync::atomic::Ordering::SeqCst)),
        }
        assert!(arrival.elapsed() <= Duration::from_millis(budgets::EGRESS_SEND_MS));
        assert_eq!(
            flushed.load(std::sync::atomic::Ordering::SeqCst),
            2 * EGRESS_BUFFER as u64
                * (subc_protocol::HEADER_LEN as u64 + subc_protocol::MAX_FRAME_BODY_LEN as u64)
        );
        job.abort();
        let _ = job.await;
    }

    #[tokio::test(start_paused = true)]
    async fn below_floor_and_waiting_producers_fail_connection_by_deadline() {
        let planes = crate::tests::management_bound_planes(1, 1);
        let deadlines = Arc::clone(&planes.egress_deadlines);
        let (mut peer, mut reader) = tokio::io::duplex(64 * 1024);
        write_frame(&mut peer, &hello_ack()).await.unwrap();
        let (_, reply_ms) = route_limits(&request(), &planes);
        for corr in 1..=3 * EGRESS_BUFFER as u64 {
            let mut request = request();
            request.header.corr = corr;
            write_frame(&mut peer, &request).await.unwrap();
        }
        let config = ModuleConfig {
            connection_file_path: PathBuf::new(),
            module_id: "egress-test".into(),
            health: HealthConfig::DEFAULT,
            agent_cursor: false,
            browser: BrowserSurface::NotConfigured,
        };
        let arrival = tokio::time::Instant::now();
        // One byte per second is below the declared floor and leaves more than
        // two channel buffers' worth of independent route senders suspended.
        let writer = MeteredWriter::new(1);
        let flushed = Arc::clone(&writer.flushed);
        let result = run_connection(&mut reader, writer, &config, planes).await;
        assert!(
            matches!(result, Err(ModuleError::Message(message)) if message.contains("terminal delivery deadline"))
        );
        assert_eq!(arrival.elapsed(), Duration::from_millis(reply_ms));
        assert!(deadlines.pending.lock().unwrap().len() > 2 * EGRESS_BUFFER);
        assert_eq!(flushed.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod terminal_suffix_tests {
    use super::*;
    use crate::{
        handle_frame, journal, management, route_limits, CallObservation, PROTOCOL_VERSION,
    };
    use journal::call_records::{
        Begin, CallRecordError, CallRecordStorage, CallRecords, InMemoryCallRecordStorage,
    };

    struct BlockSettle {
        memory: InMemoryCallRecordStorage,
        writes: std::sync::atomic::AtomicUsize,
        blocked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl BlockSettle {
        fn before_write(&self) {
            if self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 1
            {
                let _ = self.blocked.lock().unwrap().take().unwrap().send(());
                let _ = self.release.lock().unwrap().recv();
            }
        }
    }
    impl CallRecordStorage for BlockSettle {
        fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
            self.memory.load()
        }
        fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
            self.before_write();
            self.memory.append(bytes, version)
        }
        fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
            self.before_write();
            self.memory.replace(bytes, version)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_release_and_settlement_keep_unknown_and_forward_within_suffix() {
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let memory = InMemoryCallRecordStorage::new();
        let (settle_entered, settling) = tokio::sync::oneshot::channel();
        let (finish_settle, settle_release) = std::sync::mpsc::channel();
        planes.calls = Arc::new(CallRecords::open(
            Box::new(BlockSettle {
                memory: memory.clone(),
                writes: std::sync::atomic::AtomicUsize::new(0),
                blocked: std::sync::Mutex::new(Some(settle_entered)),
                release: std::sync::Mutex::new(settle_release),
            }),
            0,
        ));
        let Begin::Execute(ticket) =
            planes
                .calls
                .begin("suffix-principal", "suffix-key", "conversation", 0)
        else {
            panic!("admission")
        };
        let (ready, started) = tokio::sync::oneshot::channel();
        let (finish_worker, worker_done) = tokio::sync::oneshot::channel();
        let (finish_release, release_done) = tokio::sync::oneshot::channel();
        let inputs = std::sync::Mutex::new(Some((ticket, ready, worker_done, release_done)));
        planes.route_test_handler = Some(Arc::new(move || {
            let (ticket, ready, worker_done, release_done) = inputs.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                terminal.set_release(async move {
                    let _ = release_done.await;
                    HeldState::Released
                });
                terminal.state.lock().unwrap().settlement = Some(PendingSettlement {
                    ticket: Some(ticket),
                    observation: CallObservation::new(),
                    unattributed_at_start:
                        cerebellum_core::dispatch_witness::unattributed_commit_count(),
                    request: (1, 1, 1),
                });
                ready.send(()).unwrap();
                let _ = worker_done.await;
                // Late evidence is diagnostic only; it cannot change settlement.
                terminal.witness.mark_committed();
            })
        }));
        let request = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            1,
            1,
            1,
            serde_json::to_vec(&json!({"method":management::OPEN_TARGET,"params":{}})).unwrap(),
        )
        .unwrap();
        let (envelope_ms, reply_ms) = route_limits(&request, &planes);
        let arrival = tokio::time::Instant::now();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(request, &tx, &planes).await.unwrap();
        started.await.unwrap();
        tokio::time::advance(Duration::from_millis(envelope_ms)).await;
        settling.await.unwrap();
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_SETTLE_MS)).await;
        let reply = rx.recv().await.unwrap();
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "dispatch_outcome_unknown");
        assert_eq!(body["detail"]["held_state"], "unknown");
        assert!(arrival.elapsed() <= Duration::from_millis(reply_ms));
        assert!(
            arrival.elapsed()
                <= Duration::from_millis(
                    envelope_ms + budgets::RELEASE_BUDGET_MS + budgets::CALL_RECORD_SETTLE_MS
                )
        );
        finish_worker.send(()).unwrap();
        finish_release.send(()).unwrap();
        finish_settle.send(()).unwrap();
        let replay = tokio::task::spawn_blocking({
            let calls = Arc::clone(&planes.calls);
            move || {
                calls.begin(
                    "suffix-principal",
                    "suffix-key",
                    "conversation",
                    wall_clock_ms(),
                )
            }
        })
        .await
        .unwrap();
        let Begin::Replay(replay) = replay else {
            panic!("settled replay")
        };
        assert_eq!(replay.readdressed(PROTOCOL_VERSION, 1, 1, 1), reply);
        while planes.health.detached_workers() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(rx.try_recv().is_err());
    }
}

#[cfg(test)]
impl RestoreCell {
    /// Queue a watchdog that expires when the test runs it with the read still held.
    pub(crate) fn hold_read_with_manual_watchdog(
        self: &Arc<Self>,
    ) -> Option<(ReadLockHold, impl FnOnce())> {
        let mut watchdog = None;
        let hold = self.hold_read_with_watchdog(Duration::ZERO, |run| {
            watchdog = Some(run);
            true
        })?;
        Some((hold, watchdog.unwrap()))
    }
}

#[cfg(test)]
mod restore_slot_tests {
    use super::*;
    use crate::computer::dispatch::{
        not_fronted_reason, HardwareInputSnapshot, NotFrontedReason, RestoreStatus,
    };
    use crate::{handle_frame, management, PROTOCOL_VERSION};
    use cerebellum_computer::fronting_clock::{advance, FakeClock};
    use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
    use std::sync::Mutex;

    const PREVIOUS: u32 = 10;
    const TARGET: u32 = 20;
    const THIRD: u32 = 30;

    /// The screen a fake restore host sees: a clock that only moves when the
    /// decision pauses, the frontmost application, and every request.
    struct Screen {
        now: u64,
        frontmost: Option<u32>,
        /// Whether a front request brings its application forward.
        comes_forward: bool,
        snapshot: Option<HardwareInputSnapshot>,
        requests: Vec<u32>,
        /// When each request was made, on the same clock as the deadline.
        requested_at: Vec<std::time::Instant>,
        focus_delay: Option<Duration>,
        focus_gate: Option<(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>)>,
        /// Release and restore steps in the order they happened.
        log: Vec<&'static str>,
    }

    type SharedScreen = Arc<Mutex<Screen>>;

    fn screen(comes_forward: bool) -> SharedScreen {
        Arc::new(Mutex::new(Screen {
            now: 0,
            frontmost: Some(TARGET),
            comes_forward,
            // Restore-race tests model continuous observation unless they
            // explicitly replace it; missing coverage now forbids restoration.
            snapshot: Some(HardwareInputSnapshot {
                coverage_start_ms: 0,
                last_input_ms: None,
            }),
            requests: Vec::new(),
            requested_at: Vec::new(),
            focus_delay: None,
            focus_gate: None,
            log: Vec::new(),
        }))
    }

    struct FakeHost(SharedScreen);

    impl RestoreHost for FakeHost {
        fn now_ms(&mut self) -> u64 {
            self.0.lock().unwrap().now
        }
        fn pause_ms(&mut self, milliseconds: u64) {
            self.0.lock().unwrap().now += milliseconds;
            advance(Duration::from_millis(milliseconds));
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            let (delay, gate) = {
                let mut screen = self.0.lock().unwrap();
                (screen.focus_delay.take(), screen.focus_gate.take())
            };
            if let Some((ready, resume)) = gate {
                ready.send(()).unwrap();
                resume
                    .recv_timeout(crate::test_support::HANG_GUARD)
                    .unwrap();
            }
            if let Some(delay) = delay {
                assert!(advance(delay));
            }
            self.0.lock().unwrap().frontmost
        }
        fn request_front(&mut self, pid: u32) -> bool {
            let mut screen = self.0.lock().unwrap();
            screen.requests.push(pid);
            screen.requested_at.push(fronting_now());
            screen.log.push("restore");
            if screen.comes_forward {
                screen.frontmost = Some(pid);
            }
            true
        }
        fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
            self.0.lock().unwrap().snapshot
        }
    }

    /// Stands in for the fronting lock's guard; counts its releases.
    struct CountedLock(Arc<AtomicUsize>);

    impl Drop for CountedLock {
        fn drop(&mut self) {
            self.0.fetch_add(1, SeqCst);
        }
    }

    fn obligation(screen: &SharedScreen, releases: &Arc<AtomicUsize>) -> RestoreObligation {
        RestoreObligation {
            previous_pid: PREVIOUS,
            target_pid: TARGET,
            target_name: "Mail".into(),
            mode: FrontingMode::Background,
            purpose: FrontingPurpose::NeedsFront,
            lock: Box::new(CountedLock(Arc::clone(releases))),
            host: Box::new(FakeHost(Arc::clone(screen))),
            gate: None,
        }
    }

    fn request() -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            1,
            1,
            1,
            serde_json::to_vec(&json!({
                "method":management::OPEN_TARGET,"params":{"bundle_identity":"com.example.Nothing"}
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn cancel() -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Cancel,
            control_flags(),
            1,
            1,
            1,
            Vec::new(),
        )
        .unwrap()
    }

    fn body(terminal: &TerminalArbiter) -> Value {
        serde_json::from_slice(&terminal.state.lock().unwrap().chosen.as_ref().unwrap().body)
            .unwrap()
    }

    /// Plays a worker's in-flight front request returning, with the target
    /// now in front, once cleanup has closed the gate to new work. The gate
    /// has no deadline in these tests, so it closes only when cleanup runs.
    fn return_front_after_take(cell: &RestoreCell, shared: &SharedScreen) {
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while !cell.cleanup_taken() {
            assert!(
                std::time::Instant::now() < give_up,
                "cleanup never took the cell"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        {
            let mut screen = shared.lock().unwrap();
            assert!(
                screen.requests.is_empty(),
                "cleanup restored under the front"
            );
            screen.log.push("front_returned");
            screen.frontmost = Some(TARGET);
        }
        cell.front_confirmed();
        cell.front_attempt_returned();
    }

    /// A registered cell whose bracket gate has a bound: the restore reserve
    /// starts `reserve_in` from now and the deadline `deadline_in` from now.
    fn bounded_cell(
        terminal: &TerminalArbiter,
        shared: &SharedScreen,
        releases: &Arc<AtomicUsize>,
        reserve_in: Duration,
        deadline_in: Duration,
    ) -> (
        Arc<RestoreCell>,
        Arc<crate::computer::dispatch::CutoffGate>,
        std::time::Instant,
    ) {
        // Fake screens have independent fronting locks. Give each its own
        // watch domain so parallel tests using TARGET don't share a watch.
        terminal
            .fronting_domain
            .store(Arc::as_ptr(shared) as usize, SeqCst);
        let gate = Arc::new(crate::computer::dispatch::CutoffGate::new());
        let mut obligation = obligation(shared, releases);
        obligation.gate = Some(Arc::clone(&gate));
        let cell = terminal.register_restore(obligation).unwrap();
        assert!(cell.begin_front_attempt(0));
        cell.front_attempt_returned();
        // Bound once the front was requested, so even a reserve already
        // started has a front to restore.
        let now = fronting_now();
        let deadline = now + deadline_in;
        gate.set_bound(now + reserve_in, deadline);
        (cell, gate, deadline)
    }

    #[test]
    fn abandon_leaves_the_lock_with_an_owner_inside_the_restore_decision() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let (cell, _, _) = bounded_cell(
            &terminal,
            &shared,
            &releases,
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        cell.front_confirmed();
        let (ready, reading) = std::sync::mpsc::channel();
        let (resume, gate) = std::sync::mpsc::channel();
        shared.lock().unwrap().focus_gate = Some((ready, gate));
        let (after_abandon, decision) = std::thread::scope(|scope| {
            let owner = scope.spawn(|| cell.decide());
            reading
                .recv_timeout(crate::test_support::HANG_GUARD)
                .unwrap();
            assert!(cell.await_owner(std::time::Instant::now()).is_none());
            cell.abandon_undecided();
            let after_abandon = releases.load(SeqCst);
            resume.send(()).unwrap();
            (after_abandon, owner.join().unwrap())
        });
        assert_eq!(
            after_abandon, 0,
            "abandon must not release the deciding owner's lock"
        );
        assert_eq!(decision.restore, RestoreStatus::Restored);
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[tokio::test]
    async fn a_worker_that_sends_no_reply_still_hands_an_expired_restore_to_the_watch() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let recorder_called = Arc::new(tokio::sync::Notify::new());
        let inputs = Mutex::new(Some((
            Arc::clone(&shared),
            Arc::clone(&releases),
            Arc::clone(&recorder_called),
        )));
        let mut planes = crate::tests::management_bound_planes(1, 1);
        planes.route_test_handler = Some(Arc::new(move || {
            let (shared, releases, recorder) = inputs.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_late_fronting_recorder(Arc::new(move |_| recorder.notify_one()));
                let (cell, gate, _) = bounded_cell(
                    &terminal,
                    &shared,
                    &releases,
                    Duration::ZERO,
                    Duration::ZERO,
                );
                cell.front_confirmed();
                let past = std::time::Instant::now() - Duration::from_millis(1);
                gate.set_bound(past, past);
                assert!(matches!(
                    cell.decide().restore,
                    RestoreStatus::Failed { .. }
                ));
                assert!(shared.lock().unwrap().requests.is_empty());
            })
        }));
        let (tx, _rx) = mpsc::channel(8);
        handle_frame(request(), &tx, &planes).await.unwrap();
        tokio::time::timeout(crate::test_support::HANG_GUARD, recorder_called.notified())
            .await
            .expect("the terminal's no-reply path never started the watch");
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
    }

    #[test]
    fn a_slow_restore_focus_read_refuses_the_primary_write_and_hands_off_after_terminal() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let expired = restore_preparation::expired_writes();
        let os_delay = restore_preparation::expired_os_delay();
        let (cell, decided) = FakeClock::frozen().run(|| {
            let (cell, _gate, _) = bounded_cell(
                &terminal,
                &shared,
                &releases,
                Duration::ZERO,
                Duration::from_millis(10),
            );
            cell.front_confirmed();
            // The owner's native focus read stalls past the deadline. The
            // terminal has already stopped waiting for the owner to return.
            shared.lock().unwrap().focus_delay = Some(Duration::from_millis(30));
            terminal.start_late_fronting(Some(&cell));
            let decided = cell.decide();
            (cell, decided)
        });
        assert_eq!(
            decided.restore,
            RestoreStatus::Failed {
                left_in_front: Some(TARGET)
            }
        );
        assert!(decided.restore_ms.is_none());
        assert!(restore_preparation::expired_writes() > expired);
        assert!(
            restore_preparation::expired_os_delay() > os_delay,
            "the stalled read is counted as a native stall, not our own overrun"
        );
        let mut reply = json!({"outcome": "completed", "effect_status": "effect_indeterminate"});
        cell.disclose(&mut reply, decided);
        assert_eq!(reply["outcome"], "restore_failed");
        assert_eq!(reply["fronting"]["restore"], "failed");
        assert_eq!(reply["effect_status"], "effect_indeterminate");
        assert!(
            reply["remedy"]
                .as_str()
                .unwrap()
                .contains("restore was handed off"),
            "{reply}"
        );
        let end = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while releases.load(SeqCst) == 0 && std::time::Instant::now() < end {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(releases.load(SeqCst), 1, "late watch took the obligation");
        assert_eq!(
            shared.lock().unwrap().requests,
            [PREVIOUS],
            "only the watch wrote"
        );
    }

    #[test]
    fn a_missed_deadline_is_disclosed_as_handed_off_only_once_the_watch_holds_it() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let (cell, gate, _) = bounded_cell(
            &terminal,
            &shared,
            &releases,
            Duration::from_secs(60),
            Duration::from_secs(120),
        );
        cell.front_confirmed();
        // A picture read still holds the fronting lock, so the late watch
        // cannot take the obligation yet.
        let hold = cell
            .hold_read_with_watchdog(Duration::from_secs(60), |_| true)
            .expect("a bounded hold");
        gate.set_bound(
            std::time::Instant::now() - Duration::from_millis(1),
            std::time::Instant::now() - Duration::from_millis(1),
        );
        let decided = cell.decide();
        assert!(matches!(decided.restore, RestoreStatus::Failed { .. }));
        terminal.start_late_fronting(Some(&cell));
        let remedy = |cell: &RestoreCell| {
            let mut reply = json!({"outcome": "completed"});
            cell.disclose(&mut reply, decided);
            reply["remedy"].as_str().unwrap().to_owned()
        };
        let before = remedy(&cell);
        assert!(
            !before.contains("handed off") && before.contains("still running"),
            "a known miss the watch does not hold yet is not a handoff: {before}"
        );
        drop(hold);
        let after = remedy(&cell);
        assert!(
            after.contains("restore was handed off"),
            "the watch holds it now: {after}"
        );
    }

    #[test]
    fn untimed_restores_after_held_release_count_with_and_without_a_native_overrun() {
        for native_overrun in [false, true] {
            let shared = screen(true);
            let releases = Arc::new(AtomicUsize::new(0));
            let terminal = TerminalArbiter::new(request());
            let (cell, gate, _) = bounded_cell(
                &terminal,
                &shared,
                &releases,
                Duration::from_secs(60),
                Duration::from_secs(120),
            );
            cell.front_confirmed();
            assert!(gate.begin_post(true));
            let released = std::time::Instant::now();
            let deadline = released - Duration::from_millis(10);
            gate.set_bound(deadline - Duration::from_millis(50), deadline);
            if native_overrun {
                gate.native_call(deadline - Duration::from_millis(1), released);
            }

            let count = || {
                let (native, no_native) = restore_preparation::held_release_counts();
                if native_overrun {
                    native
                } else {
                    no_native
                }
            };
            let before = count();
            let decided = cell.decide_after_release(true, released, released);
            assert_eq!(decided.restore, RestoreStatus::Restored);
            assert!(
                count() > before,
                "missing count for native overrun = {native_overrun}"
            );
            assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
            assert_eq!(releases.load(SeqCst), 1);
        }
    }

    #[test]
    fn a_release_settling_at_150_of_200_ms_is_restored_by_the_owner_inside_the_deadline() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        FakeClock::frozen().run(|| {
            let (cell, gate, deadline) = bounded_cell(
                &terminal,
                &shared,
                &releases,
                Duration::from_millis(150),
                Duration::from_millis(200),
            );
            cell.front_confirmed();
            assert!(
                gate.begin_post(true),
                "a press whose release has not settled"
            );
            // Settle exactly at the reserve start, with 50 ms left to restore.
            assert!(advance(Duration::from_millis(150)));
            let released = fronting_now();
            let samples = restore_preparation::samples_recorded_on_this_thread();
            let decided = cell.decide_after_release(true, released, released);
            let screen = shared.lock().unwrap();
            assert_eq!(screen.requests, [PREVIOUS], "the owner restored at once");
            assert!(screen.requested_at[0] >= released, "never under the hold");
            assert!(
                screen.requested_at[0] <= deadline,
                "the release settled in time, so the restore is still bound by the deadline"
            );
            assert_eq!(decided.restore, RestoreStatus::Restored);
            assert!(
                restore_preparation::samples_recorded_on_this_thread() > samples,
                "the write ran under the original write deadline and trained the reserve"
            );
            assert!(!gate.input_held());
            assert_eq!(releases.load(SeqCst), 1);
        });
    }

    #[test]
    fn an_owner_watching_an_unconfirmed_activation_requests_the_restore_at_the_reserve_by_the_deadline(
    ) {
        let shared = screen(true);
        // The target has not yet become frontmost, so the owner's polls
        // advance the clock to the start of the reserve.
        shared.lock().unwrap().frontmost = Some(PREVIOUS);
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let (cell, decided, reserve_start, deadline) = FakeClock::frozen().run(|| {
            let (cell, gate, deadline) = bounded_cell(
                &terminal,
                &shared,
                &releases,
                Duration::from_millis(40),
                Duration::from_millis(140),
            );
            let reserve_start = gate.reserve_start().unwrap();
            let decided = cell.decide();
            (cell, decided, reserve_start, deadline)
        });
        let screen = shared.lock().unwrap();
        assert_eq!(screen.requests, [PREVIOUS], "one write, the owner's own");
        assert!(
            screen.requested_at[0] + Duration::from_millis(1) >= reserve_start,
            "it watched until the reserve started, sleeping no part of it"
        );
        assert!(
            screen.requested_at[0] <= deadline,
            "and wrote by the deadline"
        );
        assert!(
            matches!(decided.restore, RestoreStatus::Failed { .. }),
            "a landing never seen is not reported restored"
        );
        assert!(cell.late_watch_pending(), "the late watch is owed it");
    }

    #[test]
    fn a_picture_read_without_a_watchdog_is_not_admitted() {
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&screen(true), &releases))
            .unwrap();
        assert!(cell
            .hold_read_with_watchdog(Duration::from_secs(10), |_| false)
            .is_none());
        cell.decide();
        assert_eq!(releases.load(SeqCst), 1, "a refused read keeps no hold");
    }

    #[test]
    fn a_picture_read_that_never_returns_releases_the_lock_at_its_lifetime() {
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&screen(true), &releases))
            .unwrap();
        let (_, total_before) = stalled_picture_reads();
        // The read's synchronous step never returns: its hold is never
        // dropped during the test's wait.
        let (hold, expire) = cell.hold_read_with_manual_watchdog().unwrap();
        cell.decide();
        assert_eq!(releases.load(SeqCst), 0, "kept while the read runs");
        expire();
        assert_eq!(releases.load(SeqCst), 1, "released at the read's lifetime");
        let (still_running, total) = stalled_picture_reads();
        assert!(still_running >= 1, "health shows the read still running");
        assert!(total > total_before, "health counts the stalled read");
        // The read returns at last: nothing is released twice.
        drop(hold);
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[test]
    fn the_real_picture_watchdog_releases_a_stalled_read() {
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&screen(true), &releases))
            .unwrap();
        // Exercise the actual timer and its thread rather than the manual
        // watchdog. Only assert after expiry so descheduling cannot make an
        // assertion about a still-live read fail.
        let _hold = cell.hold_lock_for_read(Duration::from_secs(1)).unwrap();
        cell.decide();
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while releases.load(SeqCst) == 0 && std::time::Instant::now() < give_up {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(releases.load(SeqCst), 1, "released at the read's lifetime");
    }

    #[test]
    fn restore_slot_is_separate_from_release_and_held_state_follows_release_only() {
        let releases = Arc::new(AtomicUsize::new(0));
        let restore_only = TerminalArbiter::new(request());
        assert!(restore_only.gate.begin_mutation());
        restore_only
            .register_restore(obligation(&screen(true), &releases))
            .unwrap();
        restore_only.stop(TerminalCause::Cancelled);
        assert_eq!(body(&restore_only)["outcome"], "dispatch_outcome_unknown");
        assert_eq!(
            body(&restore_only)["detail"]["held_state"],
            "none_held",
            "a restore obligation alone holds no input"
        );

        let both = TerminalArbiter::new(request());
        assert!(both.gate.begin_mutation());
        both.set_release(async { HeldState::Released });
        both.register_restore(obligation(&screen(true), &releases))
            .unwrap();
        {
            let state = both.state.lock().unwrap();
            assert!(state.release.is_some() && state.restore.is_some());
        }
        both.stop(TerminalCause::Cancelled);
        assert_eq!(body(&both)["detail"]["held_state"], "unknown");
        let state = both.state.lock().unwrap();
        assert!(
            state.release.is_some() && state.restore.is_some(),
            "a chord holding Command keeps both obligations"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_piece_rearm_replaces_only_a_confirmed_restore_while_terminal_is_open() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        let terminal = TerminalArbiter::new(request());
        let first = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        assert!(terminal
            .replace_windows_restore(&first, obligation(&shared, &releases))
            .is_err());
        first.begin_front_attempt(0);
        first.front_attempt_returned();
        first.front_confirmed();
        assert_eq!(first.decide().restore, RestoreStatus::Restored);
        let next = terminal
            .replace_windows_restore(&first, obligation(&shared, &releases))
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &next));
        assert!(terminal
            .replace_windows_restore(&first, obligation(&shared, &releases))
            .is_err());
        assert!(terminal
            .replace_windows_restore(&next, obligation(&shared, &releases))
            .is_err());
        terminal.stop(TerminalCause::Cancelled);
        assert!(terminal
            .replace_windows_restore(&next, obligation(&shared, &releases))
            .is_err());
    }

    #[test]
    fn registration_after_a_chosen_terminal_is_refused_as_cancelled_and_frees_the_lock() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        let terminal = TerminalArbiter::new(request());
        assert!(terminal.stop(TerminalCause::Cancelled));
        let refused = terminal
            .register_restore(obligation(&shared, &releases))
            .err()
            .expect("a chosen terminal refuses the obligation");
        assert_eq!(
            not_fronted_reason(refused.stop()),
            NotFrontedReason::Cancelled
        );
        assert_eq!(releases.load(SeqCst), 1, "the refused lock was released");
        assert!(terminal.state.lock().unwrap().restore.is_none());
        assert!(shared.lock().unwrap().requests.is_empty());
    }

    #[test]
    fn a_second_registration_waits_for_the_first_decision() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        let terminal = TerminalArbiter::new(request());
        let first = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        assert!(terminal
            .register_restore(obligation(&shared, &releases))
            .is_err());
        first.decide();
        assert!(terminal
            .register_restore(obligation(&shared, &releases))
            .is_ok());
    }

    #[test]
    fn the_cell_runs_the_restore_decision_exactly_once() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        assert!(cell.begin_front_attempt(0));
        // The target is in front when the attempt returns, as the worker saw.
        cell.front_confirmed();
        cell.front_attempt_returned();
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        let (worker, cleanup) = std::thread::scope(|scope| {
            let worker = scope.spawn(|| cell.decide());
            let cleanup = scope.spawn(|| cell.await_owner(give_up));
            (worker.join().unwrap(), cleanup.join().unwrap())
        });
        assert_eq!(Some(worker), cleanup, "both sides see the one decision");
        assert_eq!(worker.restore, RestoreStatus::Restored);
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
        assert_eq!(releases.load(SeqCst), 1, "the lock was released once");
        assert_eq!(cell.decide(), worker);
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
    }

    #[test]
    fn cleanup_before_the_front_prevents_it_and_reports_not_needed() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        let decided = cell
            .await_owner(std::time::Instant::now())
            .expect("nothing was fronted, so cleanup decides at once");
        assert_eq!(decided.restore, RestoreStatus::NotNeeded);
        assert!(!decided.front_requested);
        assert_eq!(releases.load(SeqCst), 1);
        assert!(
            !cell.begin_front_attempt(5),
            "a worker resuming after cleanup does not front"
        );
        assert_eq!(cell.decide(), decided);
        assert!(shared.lock().unwrap().requests.is_empty());
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[test]
    fn cleanup_during_a_front_request_waits_for_the_owner_which_decides_once() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        shared.lock().unwrap().frontmost = Some(PREVIOUS);
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        assert!(cell.begin_front_attempt(0));
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        let decided = std::thread::scope(|scope| {
            let cleanup = scope.spawn(|| cell.await_owner(give_up));
            // The worker's front request returns, then its owner decides.
            return_front_after_take(&cell, &shared);
            let owner = cell.decide();
            assert_eq!(cleanup.join().unwrap(), Some(owner));
            owner
        });
        assert_eq!(decided.restore, RestoreStatus::Restored);
        let screen = shared.lock().unwrap();
        assert_eq!(screen.log, ["front_returned", "restore"]);
        assert_eq!(screen.requests, [PREVIOUS]);
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[test]
    fn a_person_switch_with_input_skips_the_restore() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        {
            let mut screen = shared.lock().unwrap();
            screen.frontmost = Some(THIRD);
            screen.snapshot = Some(HardwareInputSnapshot {
                coverage_start_ms: 0,
                last_input_ms: Some(5),
            });
        }
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        assert!(cell.begin_front_attempt(1));
        cell.front_attempt_returned();
        let decided = cell.decide();
        assert_eq!(
            decided.restore,
            RestoreStatus::SkippedPerson {
                now_front: Some(THIRD)
            }
        );
        assert!(decided.person_input_during_fronting);
        assert!(shared.lock().unwrap().requests.is_empty());
        let mut body = json!({"outcome":"completed"});
        cell.disclose(&mut body, decided);
        assert_eq!(body["outcome"], "completed", "skipped_person is no failure");
        assert_eq!(body["fronting"]["restore"], "skipped_person");
        assert_eq!(body["fronting"]["person_input_during_fronting"], true);
        assert!(body["remedy"]
            .as_str()
            .unwrap()
            .contains("Don't bring apps forward again"));
    }

    #[test]
    fn a_restore_with_no_hardware_coverage_explains_why_it_left_focus_alone() {
        let releases = Arc::new(AtomicUsize::new(0));
        let shared = screen(true);
        shared.lock().unwrap().snapshot = None;
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&shared, &releases))
            .unwrap();
        assert!(cell.begin_front_attempt(1));
        cell.front_confirmed();
        cell.front_attempt_returned();
        let decided = cell.decide();
        assert!(!decided.person_input_during_fronting);
        assert!(shared.lock().unwrap().requests.is_empty());
        let mut body = json!({"outcome":"completed"});
        cell.disclose(&mut body, decided);
        assert!(body["fronting"]
            .get("person_input_during_fronting")
            .is_none());
        assert!(
            body["remedy"]
                .as_str()
                .is_some_and(|remedy| remedy.contains("couldn't watch for person input")
                    && remedy.contains("left focus alone")),
            "{body}"
        );
    }

    #[test]
    fn a_failed_restore_becomes_restore_failed_keeping_detail_and_effect_status() {
        let releases = Arc::new(AtomicUsize::new(0));
        let terminal = TerminalArbiter::new(request());
        let cell = terminal
            .register_restore(obligation(&screen(false), &releases))
            .unwrap();
        assert!(cell.begin_front_attempt(0));
        cell.front_confirmed();
        cell.front_attempt_returned();
        let failed = RestoreDecided {
            restore: RestoreStatus::Failed {
                left_in_front: Some(TARGET),
            },
            person_input_during_fronting: false,
            input_coverage_unavailable: false,
            restore_ms: None,
            front_requested: true,
        };
        for outcome in [
            "completed",
            "dispatch_outcome_unknown",
            "action_deadline_exceeded",
        ] {
            let mut body = json!({"outcome":outcome, "effect_status":"effect_indeterminate",
                "detail":{"reason":"cancelled","dispatched":true,"step":"dispatch",
                    "held_state":"none_held"},
                "remedy":"read the state before retrying"});
            cell.disclose(&mut body, failed);
            assert_eq!(body["outcome"], "restore_failed", "outranks {outcome}");
            assert_eq!(body["effect_status"], "effect_indeterminate");
            assert_eq!(body["detail"]["reason"], "cancelled");
            assert_eq!(body["fronting"]["restore"], "failed");
            assert_eq!(body["fronting"]["fronted"], true);
            assert!(body["remedy"]
                .as_str()
                .unwrap()
                .starts_with("Mail was left"));
            crate::computer::platform::vocabulary::validate_capability_result(
                "computer.press_element",
                &body,
            )
            .unwrap();
        }
    }

    /// Run one route whose worker is `worker`, then cancel it once the worker
    /// signals, and return the wire reply's body. On the paused clock, the
    /// reply comes within the one RELEASE_BUDGET_MS that release and restore
    /// share.
    async fn cancelled_route<F>(
        worker: impl FnOnce(Arc<TerminalArbiter>) -> F + Send + 'static,
    ) -> Value
    where
        F: std::future::Future<Output = ()> + Send + 'static,
    {
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let (ready, started) = tokio::sync::oneshot::channel::<()>();
        let input = Mutex::new(Some((worker, ready)));
        planes.route_test_handler = Some(Arc::new(move || {
            let (worker, ready) = input.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                let work = worker(terminal);
                let _ = ready.send(());
                work.await;
            })
        }));
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(request(), &tx, &planes).await.unwrap();
        started.await.unwrap();
        let cancelled_at = tokio::time::Instant::now();
        handle_frame(cancel(), &tx, &planes).await.unwrap();
        let reply = rx.recv().await.unwrap();
        assert!(
            cancelled_at.elapsed() <= Duration::from_millis(budgets::RELEASE_BUDGET_MS),
            "release and restore share one RELEASE_BUDGET_MS"
        );
        serde_json::from_slice(&reply.body).unwrap()
    }

    /// How a test's worker, the obligation's one owner, ends its front once
    /// terminal cleanup has stopped it.
    #[derive(Clone, Copy)]
    enum Owner {
        /// It sees the stop and restores.
        Restores,
        /// Its own release of a held key settled unconfirmed: it restores
        /// nothing.
        ReleaseUnconfirmed,
        /// It never returns from settling a held key's release.
        StuckInRelease,
    }

    /// Play the owner's side on its own thread, as a bracket that notices
    /// the stop at its next check.
    fn own_until_stopped(cell: Arc<RestoreCell>, owner: Owner) {
        if let Owner::StuckInRelease = owner {
            // A worker stuck settling its release still holds its
            // obligation, as the real worker's hooks do.
            std::mem::forget(cell);
            return;
        }
        std::thread::spawn(move || {
            let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while !cell.cleanup_taken() && std::time::Instant::now() < give_up {
                std::thread::sleep(Duration::from_millis(1));
            }
            match owner {
                Owner::Restores => {
                    cell.decide();
                }
                Owner::ReleaseUnconfirmed => {
                    let now = std::time::Instant::now();
                    cell.decide_after_release(false, now, now);
                }
                Owner::StuckInRelease => {}
            }
        });
    }

    /// A worker that registers the obligation, fronts the target, and then
    /// stays blocked until the route is cancelled; its bracket, the
    /// obligation's owner, then ends the front as `owner` says.
    fn fronted_worker(
        shared: SharedScreen,
        releases: Arc<AtomicUsize>,
        release: Option<ReleaseJob>,
        owner: Owner,
    ) -> impl FnOnce(
        Arc<TerminalArbiter>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
           + Send
           + 'static {
        move |terminal| {
            if let Some(release) = release {
                terminal.set_release(release);
            }
            let cell = terminal
                .register_restore(obligation(&shared, &releases))
                .unwrap();
            assert!(cell.begin_front_attempt(0));
            cell.front_confirmed();
            cell.front_attempt_returned();
            own_until_stopped(cell, owner);
            Box::pin(std::future::pending())
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_after_a_front_restores_and_reports_it_in_the_terminal_body() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let reply = cancelled_route(fronted_worker(
            Arc::clone(&shared),
            Arc::clone(&releases),
            None,
            Owner::Restores,
        ))
        .await;
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown");
        assert_eq!(reply["detail"]["held_state"], "none_held");
        assert_eq!(reply["fronting"]["restore"], "restored");
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_after_a_front_with_the_restore_failing_replies_restore_failed() {
        let shared = screen(false);
        let releases = Arc::new(AtomicUsize::new(0));
        let reply = cancelled_route(fronted_worker(
            Arc::clone(&shared),
            Arc::clone(&releases),
            None,
            Owner::Restores,
        ))
        .await;
        assert_eq!(reply["outcome"], "restore_failed");
        assert_eq!(reply["effect_status"], "effect_indeterminate");
        assert_eq!(reply["detail"]["reason"], "cancelled");
        assert_eq!(reply["fronting"]["restore"], "failed");
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn held_input_is_released_before_the_restore_and_both_are_reported() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let log = Arc::clone(&shared);
        let release: ReleaseJob = Box::pin(async move {
            log.lock().unwrap().log.push("release");
            HeldState::Released
        });
        let reply = cancelled_route(fronted_worker(
            Arc::clone(&shared),
            Arc::clone(&releases),
            Some(release),
            Owner::Restores,
        ))
        .await;
        assert_eq!(shared.lock().unwrap().log, ["release", "restore"]);
        assert_eq!(reply["detail"]["held_state"], "released");
        assert_eq!(reply["fronting"]["restore"], "restored");
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown");
    }

    #[tokio::test(start_paused = true)]
    async fn an_unconfirmed_release_requests_no_restore_and_replies_restore_failed() {
        let unknown: fn(SharedScreen) -> ReleaseJob = |_| Box::pin(async { HeldState::Unknown });
        let stalled: fn(SharedScreen) -> ReleaseJob = |_| Box::pin(std::future::pending());
        // A release that settles unconfirmed gives up the restore and the
        // lock. One that never settles keeps the lock: the owner, still
        // settling it, restores only if the release is ever confirmed.
        for (release, owner, lock_releases) in [
            (unknown, Owner::ReleaseUnconfirmed, 1),
            (stalled, Owner::StuckInRelease, 0),
        ] {
            let shared = screen(true);
            let releases = Arc::new(AtomicUsize::new(0));
            let reply = cancelled_route(fronted_worker(
                Arc::clone(&shared),
                Arc::clone(&releases),
                Some(release(Arc::clone(&shared))),
                owner,
            ))
            .await;
            let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while releases.load(SeqCst) < lock_releases && std::time::Instant::now() < give_up {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert!(
                shared.lock().unwrap().requests.is_empty(),
                "no restore is requested while a key may be held"
            );
            assert_eq!(reply["outcome"], "restore_failed");
            assert_eq!(reply["detail"]["held_state"], "unknown");
            assert_eq!(reply["fronting"]["restore"], "failed");
            assert!(reply["remedy"]
                .as_str()
                .unwrap()
                .starts_with("Mail was left"));
            assert_eq!(releases.load(SeqCst), lock_releases);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup_before_the_front_leaves_a_resumed_worker_unfronted() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let (resume, resumed) = tokio::sync::oneshot::channel::<()>();
        let (fronted, front_answer) = tokio::sync::oneshot::channel::<bool>();
        let host_screen = Arc::clone(&shared);
        let lock_releases = Arc::clone(&releases);
        let reply = cancelled_route(move |terminal: Arc<TerminalArbiter>| {
            let cell = terminal
                .register_restore(obligation(&host_screen, &lock_releases))
                .unwrap();
            async move {
                let _ = resumed.await;
                let _ = fronted.send(cell.begin_front_attempt(0));
            }
        })
        .await;
        assert_eq!(reply["fronting"]["restore"], "not_needed");
        assert_eq!(reply["fronting"]["fronted"], false);
        assert_eq!(reply["fronting"]["not_fronted_reason"], "cancelled");
        resume.send(()).unwrap();
        assert!(
            !front_answer.await.unwrap(),
            "the resumed worker never fronts"
        );
        assert!(shared.lock().unwrap().requests.is_empty());
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_during_a_front_request_waits_for_it_then_decides_once() {
        let shared = screen(true);
        shared.lock().unwrap().frontmost = Some(PREVIOUS);
        let releases = Arc::new(AtomicUsize::new(0));
        let hop_screen = Arc::clone(&shared);
        let lock_releases = Arc::clone(&releases);
        let reply = cancelled_route(move |terminal: Arc<TerminalArbiter>| {
            let cell = terminal
                .register_restore(obligation(&hop_screen, &lock_releases))
                .unwrap();
            assert!(cell.begin_front_attempt(0));
            // The worker's front request runs in its own blocking hop, and
            // its owner decides once it returned.
            std::thread::spawn(move || {
                return_front_after_take(&cell, &hop_screen);
                cell.decide();
            });
            std::future::pending::<()>()
        })
        .await;
        assert_eq!(reply["fronting"]["restore"], "restored");
        assert_eq!(reply["fronting"]["fronted"], true);
        let screen = shared.lock().unwrap();
        assert_eq!(screen.log, ["front_returned", "restore"]);
        assert_eq!(screen.requests, [PREVIOUS]);
        assert_eq!(releases.load(SeqCst), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn a_restore_unfinished_at_the_budget_is_reported_failed_and_its_owner_finishes_it() {
        /// A host whose restore request blocks its thread until the test lets
        /// it go, or for a few real seconds at most.
        struct StuckHost {
            inner: FakeHost,
            started: std::sync::mpsc::Sender<()>,
            release: std::sync::mpsc::Receiver<()>,
        }
        impl RestoreHost for StuckHost {
            fn now_ms(&mut self) -> u64 {
                self.inner.now_ms()
            }
            fn pause_ms(&mut self, milliseconds: u64) {
                self.inner.pause_ms(milliseconds);
            }
            fn frontmost_pid(&mut self) -> Option<u32> {
                self.inner.frontmost_pid()
            }
            fn request_front(&mut self, pid: u32) -> bool {
                let _ = self.started.send(());
                let _ = self.release.recv_timeout(Duration::from_secs(5));
                self.inner.request_front(pid)
            }
            fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
                self.inner.hardware_input_snapshot()
            }
        }

        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let (started, decision_started) = std::sync::mpsc::channel();
        let (let_go, release) = std::sync::mpsc::channel();
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let input = Mutex::new(Some((
            Arc::clone(&shared),
            Arc::clone(&releases),
            started,
            release,
        )));
        let (ready, worker_started) = tokio::sync::oneshot::channel::<()>();
        let ready = Mutex::new(Some(ready));
        planes.route_test_handler = Some(Arc::new(move || {
            let (shared, releases, started, release) = input.lock().unwrap().take().unwrap();
            let ready = ready.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                let mut obligation = obligation(&shared, &releases);
                obligation.host = Box::new(StuckHost {
                    inner: FakeHost(shared),
                    started,
                    release,
                });
                let cell = terminal.register_restore(obligation).unwrap();
                assert!(cell.begin_front_attempt(0));
                cell.front_confirmed();
                cell.front_attempt_returned();
                own_until_stopped(Arc::clone(&cell), Owner::Restores);
                let _ = ready.send(());
                std::future::pending::<()>().await;
            })
        }));
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(request(), &tx, &planes).await.unwrap();
        worker_started.await.unwrap();
        handle_frame(cancel(), &tx, &planes).await.unwrap();
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while decision_started.try_recv().is_err() {
            assert!(
                std::time::Instant::now() < give_up,
                "the decision never started"
            );
            tokio::task::yield_now().await;
        }
        // The decision is blocked in its restore request; let the shared
        // budget run out under it.
        tokio::time::advance(Duration::from_millis(budgets::RELEASE_BUDGET_MS)).await;
        let reply = rx.recv().await.unwrap();
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply["outcome"], "restore_failed");
        assert_eq!(reply["fronting"]["restore"], "failed");
        // The owner keeps deciding after the reply: once let go, it completes
        // its restore request and releases the fronting lock.
        let_go.send(()).unwrap();
        while releases.load(SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < give_up,
                "the detached decision never ended"
            );
            tokio::task::yield_now().await;
        }
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
    }

    #[tokio::test(start_paused = true)]
    async fn a_write_refused_at_its_deadline_is_disclosed_as_handed_off_once_the_watch_holds_it() {
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let (let_owner_decide, owner_can_decide) = std::sync::mpsc::channel();
        let input = Mutex::new(Some((
            Arc::clone(&shared),
            Arc::clone(&releases),
            owner_can_decide,
        )));
        let (ready, worker_started) = tokio::sync::oneshot::channel();
        let ready = Mutex::new(Some(ready));
        planes.route_test_handler = Some(Arc::new(move || {
            let (shared, releases, owner_can_decide) = input.lock().unwrap().take().unwrap();
            let ready = ready.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                let (cell, gate, _) = bounded_cell(
                    &terminal,
                    &shared,
                    &releases,
                    Duration::ZERO,
                    Duration::ZERO,
                );
                cell.front_confirmed();
                // The bound is already in the past, so the first restore
                // write is refused.
                let past = std::time::Instant::now() - Duration::from_millis(1);
                gate.set_bound(past, past);
                // Terminal cleanup normally starts the watch. Arm it here so
                // cancellation can test a handoff that has already happened.
                terminal.start_late_fronting(Some(&cell));
                let owner_cell = Arc::clone(&cell);
                std::thread::spawn(move || {
                    owner_can_decide
                        .recv_timeout(crate::test_support::HANG_GUARD)
                        .unwrap();
                    owner_cell.decide();
                });
                let _ = ready.send(cell);
                std::future::pending::<()>().await;
            })
        }));
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(request(), &tx, &planes).await.unwrap();
        let cell = worker_started.await.unwrap();
        let_owner_decide.send(()).unwrap();
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while !cell.inner().watch_holds {
            assert!(
                std::time::Instant::now() < give_up,
                "the late watch never took the restore obligation"
            );
            tokio::task::yield_now().await;
        }
        handle_frame(cancel(), &tx, &planes).await.unwrap();
        let reply = rx.recv().await.unwrap();
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply["outcome"], "restore_failed");
        let remedy = reply["remedy"].as_str().unwrap();
        assert!(
            remedy.contains("restore was handed off"),
            "a known miss the watch holds is disclosed as a handoff: {remedy}"
        );
        assert!(!remedy.contains("still running"), "{remedy}");
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        while releases.load(SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < give_up,
                "the handed-off restore never ended"
            );
            tokio::task::yield_now().await;
        }
    }
    #[tokio::test(start_paused = true)]
    async fn a_worker_decision_reaches_its_own_reply_with_one_restore_request() {
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let shared = screen(true);
        let releases = Arc::new(AtomicUsize::new(0));
        let input = Mutex::new(Some((Arc::clone(&shared), Arc::clone(&releases))));
        planes.route_test_handler = Some(Arc::new(move || {
            let (shared, releases) = input.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                let cell = terminal
                    .register_restore(obligation(&shared, &releases))
                    .unwrap();
                assert!(cell.begin_front_attempt(0));
                cell.front_confirmed();
                cell.front_attempt_returned();
                assert_eq!(cell.decide().restore, RestoreStatus::Restored);
                let ok = Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Response,
                    control_flags(),
                    1,
                    1,
                    1,
                    br#"{"outcome":"ok"}"#.to_vec(),
                )
                .unwrap();
                assert!(terminal.complete(ok));
                std::future::pending::<()>().await;
            })
        }));
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(request(), &tx, &planes).await.unwrap();
        let reply = rx.recv().await.unwrap();
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply["outcome"], "ok");
        assert_eq!(
            reply["fronting"],
            json!({"mode":"background","fronted":true,"purpose":"needs_front",
                "restore":"restored"})
        );
        assert_eq!(shared.lock().unwrap().requests, [PREVIOUS]);
        assert_eq!(releases.load(SeqCst), 1);
    }
}
