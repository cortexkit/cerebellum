//! What keeps a temporary front inside its bound once the target is in
//! front: checks a keystroke unit makes before each of its own posts, and a
//! timer that starts the restore when the bound passes while the bracket's
//! own thread is still busy in a unit.
//!
//! What the bound means: after the deadline nothing new is posted or
//! captured, and by the deadline the restore of the previous application
//! has been requested. The restore's confirmation is reported, not promised
//! within the bound: the person's application may come back late.
//!
//! The timer is armed before the front is requested and can fire before the
//! bound to leave time to prepare the restore. Firing stops new posts at once
//! and begins the restore decision, even while the front request is
//! still in flight, unless a key or button may be held: a restore under a
//! held key would hand that key to the previous application, so then the
//! unit's own paired releases run first and the bracket restores after
//! them, as on any other stop. The timer and the bracket reach the restore
//! through the same once-only decision, so the restore runs once whichever
//! gets there first.

use crate::platform::{FrontedKeyGuard, ProcessEventRefusal};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::Instant;

/// The per-post checks for a keystroke unit posted while its target is in
/// front: the target is still the frontmost application, the unit has not
/// been stopped, and the bracket's absolute deadline has not passed; then
/// the post is committed on the cutoff gate. The sequence runs them after
/// the window listing and transport authentication. The final generation
/// lookup follows the focus read and precedes stop and commitment.
///
/// A post refused here was never made, so the refusal is
/// [`ProcessEventRefusal::Cancelled`], which a reply reads as no post call
/// for this event. Presses the unit already posted are released as on any
/// other stop.
pub struct FrontedKeyChecks<'a, N, F> {
    pub target_pid: u32,
    /// On the bracket's clock, as `now_ms` reads it.
    pub deadline_ms: u64,
    pub now_ms: N,
    pub frontmost_pid: F,
    /// The bracket's cutoff, when a timer is armed for it.
    pub cutoff: Option<&'a CutoffGate>,
}

impl<N, F> FrontedKeyGuard for FrontedKeyChecks<'_, N, F>
where
    N: FnMut() -> u64,
    F: FnMut() -> Option<u32>,
{
    fn before_post(
        &mut self,
        press: bool,
        cancelled: &dyn Fn() -> bool,
        revalidate: &mut dyn FnMut() -> Result<(), ProcessEventRefusal>,
    ) -> Result<(), ProcessEventRefusal> {
        // A numeric PID can survive a replacement during the focus read.
        // Check its identity once more before checking stop and committing.
        if (self.frontmost_pid)() != Some(self.target_pid) {
            return Err(ProcessEventRefusal::Cancelled);
        }
        revalidate()?;
        if cancelled() {
            return Err(ProcessEventRefusal::Cancelled);
        }
        // The absolute deadline itself, not only whether the timer has run:
        // a late-scheduled timer must not leave a post open past it.
        if (self.now_ms)() >= self.deadline_ms {
            return Err(ProcessEventRefusal::Cancelled);
        }
        // Last, because this commits the post: the cutoff stays held from
        // here until the post returns, and after a press until its release,
        // so the timer never restores while the post is in flight.
        if self.cutoff.is_some_and(|cutoff| !cutoff.begin_post(press)) {
            return Err(ProcessEventRefusal::Cancelled);
        }
        Ok(())
    }

    fn all_released(&mut self) {
        if let Some(cutoff) = self.cutoff {
            cutoff.all_released();
        }
    }
}

/// The state a bracket shares with its cutoff timer.
#[derive(Debug, Default)]
pub struct CutoffGate(Mutex<GateState>);

#[derive(Debug, Default)]
struct GateState {
    /// The bound passed: no new post may start.
    fired: bool,
    /// The bracket began its own restore, so the timer has nothing to start.
    disarmed: bool,
    /// A post is in flight, or a press may be down.
    held: bool,
    deferred_for_post: bool,
    /// The timer started the restore.
    restore_started_by_cutoff: bool,
    /// The absolute deadline the timer was armed for.
    deadline: Option<Instant>,
}

impl CutoffGate {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A post is about to start. `false` once the cutoff fired: the post
    /// must not be made. Otherwise the post is committed under the gate's
    /// lock: the gate is held until [`Self::all_released`], so the timer will
    /// not restore while the post is in flight. A self-contained post is
    /// released once it returns; a `press` only once its release has.
    pub fn begin_post(&self, _press: bool) -> bool {
        let mut state = self.state();
        if state.fired || state.deadline.is_some_and(|at| Instant::now() >= at) {
            return false;
        }
        state.held = true;
        true
    }

    /// No post is in flight and nothing the unit pressed is still down.
    pub fn all_released(&self) {
        let mut state = self.state();
        if state.held && state.deadline.is_some_and(|at| Instant::now() >= at) {
            state.deferred_for_post = true;
        }
        state.held = false;
    }

    /// A committed post or its paired key release was still in progress when
    /// the deadline passed, so the restore had to wait for it to finish.
    pub fn restore_deferred_for_post(&self) -> bool {
        self.state().deferred_for_post
    }

    /// Whether the bound passed.
    pub fn fired(&self) -> bool {
        self.state().fired
    }

    /// Record the absolute deadline the timer is armed for, so a check need
    /// not wait for the timer's thread to have run.
    pub fn set_deadline(&self, deadline: Instant) {
        self.state().deadline = Some(deadline);
    }

    /// Whether the bound passed: the timer fired, or the absolute deadline
    /// is behind the clock even if the timer has not run yet.
    pub fn past_deadline(&self) -> bool {
        let state = self.state();
        state.fired
            || state
                .deadline
                .is_some_and(|deadline| Instant::now() >= deadline)
    }

    /// The bracket is starting its own restore; a timer firing after this
    /// starts nothing.
    pub fn disarm(&self) {
        self.state().disarmed = true;
    }

    /// Whether the timer, not the bracket, started the restore.
    pub fn restore_started_by_cutoff(&self) -> bool {
        self.state().restore_started_by_cutoff
    }

    /// The bound passed. Returns whether the timer should start the restore
    /// itself: not when the bracket already began one, and not while a key
    /// may be held.
    pub(super) fn fire(&self) -> bool {
        let mut state = self.state();
        if state.disarmed {
            return false;
        }
        state.fired = true;
        if state.held {
            state.deferred_for_post = true;
            return false;
        }
        state.restore_started_by_cutoff = true;
        true
    }
}

/// A thread that fires a [`CutoffGate`] at an absolute `deadline`, and then
/// runs `restore` unless the gate says not to. It holds no lock while
/// `restore` runs. Finishing it, or dropping it, stops a timer that has not
/// fired and waits for one that has, so no timer outlives its bracket.
///
/// The deadline is an instant the caller stamped before the front was
/// requested, not a span measured from when the thread happens to start, so
/// a slow registration or a late-scheduled thread cannot move the cutoff
/// later than the bound. A deadline already past fires at once.
pub struct CutoffTimer {
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

/// The timer's planned wake and the time it returned from waiting, before
/// taking any bracket locks or running restore code.
#[derive(Clone, Copy, Debug)]
pub struct CutoffWake {
    pub scheduled_at: Instant,
    pub woke_at: Instant,
}

impl CutoffTimer {
    /// `None` when no thread could be started; the caller must then not
    /// front, since nothing would enforce the bound.
    pub fn arm(
        gate: Arc<CutoffGate>,
        deadline: Instant,
        restore: Box<dyn FnOnce() + Send>,
    ) -> Option<Self> {
        Self::arm_with_wake(gate, deadline, Box::new(move |_| restore()))
    }

    /// Like [`Self::arm`], handing the restore its planned and actual wake
    /// times so preparation accounting includes the entire cutoff path.
    pub fn arm_with_wake(
        gate: Arc<CutoffGate>,
        deadline: Instant,
        restore: Box<dyn FnOnce(CutoffWake) + Send>,
    ) -> Option<Self> {
        gate.set_deadline(deadline);
        let (stop, stopped) = mpsc::channel::<()>();
        let (ready, started) = mpsc::sync_channel(1);
        let thread = std::thread::Builder::new()
            .name("fronting-cutoff".into())
            .spawn(move || {
                if ready.send(()).is_err() {
                    return;
                }
                // Only the deadline passing fires the cutoff; the sender being
                // dropped means the bracket finished first.
                let remaining = deadline.saturating_duration_since(Instant::now());
                if let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(remaining) {
                    let wake = CutoffWake {
                        scheduled_at: deadline,
                        woke_at: Instant::now(),
                    };
                    if gate.fire() {
                        restore(wake);
                    }
                }
            })
            .ok()?;
        // Do not let activation outrun thread startup. The absolute cutoff
        // still holds if the OS preempts this thread after it signals ready.
        started.recv().ok()?;
        Some(Self {
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Stop the timer if it has not fired, and wait for any restore it
    /// started to return.
    pub fn finish(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        drop(self.stop.take());
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for CutoffTimer {
    fn drop(&mut self) {
        self.stop_and_join();
    }
}
