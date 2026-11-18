//! What keeps a temporary front inside its bound once the target is in
//! front: the checks a keystroke unit makes before each of its own posts,
//! and the one record of the bound that the bracket, its restore cell and
//! the call's terminal cleanup share.
//!
//! What the bound means: after the deadline nothing new is posted or
//! captured, and by the deadline the restore of the previous application
//! has been requested. The restore's confirmation is reported, not promised
//! within the bound: the person's application may come back late.
//!
//! One owner runs the whole front in sequence on the bracket's thread:
//! front, act, release held input, restore. Nothing else ever performs the
//! restore while the call runs. The bound is kept by that owner alone,
//! through two instants stamped before the front is requested:
//!
//! - **The start of the restore reserve** (`reserve_start`): the deadline
//!   minus the time a restore has lately taken to prepare. A post, a picture
//!   capture or the target's front write may begin only before it, and every
//!   wait the owner controls ends at it, so whatever was admitted still
//!   leaves the restore its whole reserve. From it, the owner only releases
//!   held input and restores.
//! - **The deadline**: the first native restore request must be made by it.
//!   A request that can no longer be made by then is refused, reported as a
//!   failed restore and handed to the bounded late watch.
//!
//! The call's terminal cleanup never restores. It may stop a front that has
//! not been requested yet, which then never happens, and otherwise waits a
//! bounded time for the owner's decision.

use super::FrontAttemptState;
use crate::platform::{FrontedKeyGuard, ProcessEventRefusal};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// The per-post checks for a keystroke unit posted while its target is in
/// front: the target is still the frontmost application and still the
/// granted process generation, the unit has not been stopped, and the
/// bracket's absolute deadline has not passed; then the post is committed
/// on the cutoff gate. The sequence runs them after the window listing and
/// transport authentication. Focus is read once, then the focused pid's
/// generation is validated, so a pid reused by another process fails; stop,
/// the deadline and commitment follow, with no further read between that
/// validation and the post. Focus moving to another application during the
/// generation lookup is the accepted race with delivery: the post still goes
/// only to the granted process.
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
    /// The bracket's cutoff gate, when the front has one.
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
        // One consistent check: focus first, then the focused pid's
        // generation against the granted one, so a pid that passed to
        // another process fails here. Nothing but stop, the deadline and the
        // commit follows it before the post: no further focus or identity
        // read reopens the window between validation and commit.
        if (self.frontmost_pid)() != Some(self.target_pid) {
            return Err(ProcessEventRefusal::Cancelled);
        }
        revalidate()?;
        if cancelled() {
            return Err(ProcessEventRefusal::Cancelled);
        }
        if (self.now_ms)() >= self.deadline_ms {
            return Err(ProcessEventRefusal::Cancelled);
        }
        // Last, because this commits the post: it is refused from the start
        // of the restore reserve, and input counts as held from here until
        // the post returns, and after a press until its release.
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

/// Whether input this front posted may still be down or in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputHold {
    Released,
    /// `press` when a key or button may be down until its paired release,
    /// not only a self-contained post in flight.
    Held {
        press: bool,
    },
}

/// The record a bracket, its restore cell and the call's terminal cleanup
/// share. Only plain data: nothing here calls the platform, and the lock is
/// never held across a platform call.
#[derive(Debug)]
struct GateState {
    attempt: FrontAttemptState,
    /// Terminal cleanup stopped the front: no front write, post or capture
    /// not yet committed may start.
    stopped: bool,
    /// When the owner began ending the front, for its restore or because
    /// the bracket ended. Nothing new starts after it.
    ended_at: Option<Instant>,
    input: InputHold,
    /// A key or button this front pressed was still down when the deadline
    /// passed, and its release settled only after it.
    held_past_deadline: bool,
    /// The start of the restore reserve: nothing new starts from here.
    reserve_start: Option<Instant>,
    /// The absolute deadline for the first restore request.
    deadline: Option<Instant>,
    /// When the latest native call the owner made while the target was in
    /// front returned, if that call was still running at the deadline.
    native_overrun_until: Option<Instant>,
}

impl Default for GateState {
    fn default() -> Self {
        Self {
            attempt: FrontAttemptState::NotStarted,
            stopped: false,
            ended_at: None,
            input: InputHold::Released,
            held_past_deadline: false,
            reserve_start: None,
            deadline: None,
            native_overrun_until: None,
        }
    }
}

impl GateState {
    fn closed(&self, now: Instant) -> bool {
        self.stopped || self.ended_at.is_some() || self.reserve_start.is_some_and(|at| now >= at)
    }
}

/// The bound of one temporary front, shared by its bracket, its restore
/// cell and the call's terminal cleanup; see the module documentation. It
/// owns nothing: the bracket's thread is the only side that performs the
/// restore, and this only says when it must.
#[derive(Debug, Default)]
pub struct CutoffGate {
    state: Mutex<GateState>,
}

impl CutoffGate {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Stamp the front's bound before anything is fronted: the start of the
    /// restore reserve and the absolute deadline for the first restore
    /// request. A reserve start after the deadline is taken as the deadline.
    pub fn set_bound(&self, reserve_start: Instant, deadline: Instant) {
        let mut state = self.state();
        state.reserve_start = Some(reserve_start.min(deadline));
        state.deadline = Some(deadline);
    }

    /// The start of the restore reserve, when the front has a bound.
    pub fn reserve_start(&self) -> Option<Instant> {
        self.state().reserve_start
    }

    /// The absolute deadline for the first restore request, when the front
    /// has one.
    pub fn deadline(&self) -> Option<Instant> {
        self.state().deadline
    }

    /// How long a wait may still last before the restore reserve starts:
    /// zero once it has, and `None` when the front has no bound.
    pub fn time_to_reserve_start(&self) -> Option<Duration> {
        self.state()
            .reserve_start
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// Whether nothing new may start: the restore reserve has started, the
    /// owner began ending the front, or terminal cleanup stopped it.
    pub fn closed(&self) -> bool {
        self.state().closed(Instant::now())
    }

    /// A post is about to start. `false` once the gate is closed: the post
    /// must not be made. Otherwise the post is committed and input counts
    /// as held until [`Self::all_released`]. A self-contained post is
    /// released once it returns; a `press` only once its release has.
    pub fn begin_post(&self, press: bool) -> bool {
        let mut state = self.state();
        if state.closed(Instant::now()) {
            return false;
        }
        let pressed = matches!(state.input, InputHold::Held { press: true });
        state.input = InputHold::Held {
            press: press || pressed,
        };
        true
    }

    /// No post is in flight and nothing the unit pressed is still down. A
    /// press still down at the deadline is recorded here, at its release:
    /// the restore then follows the release without a deadline.
    pub fn all_released(&self) {
        let mut state = self.state();
        let now = Instant::now();
        if state.input == (InputHold::Held { press: true })
            && state.deadline.is_some_and(|deadline| now >= deadline)
        {
            state.held_past_deadline = true;
        }
        state.input = InputHold::Released;
    }

    /// Whether input this front posted may still be down or in flight.
    pub fn input_held(&self) -> bool {
        matches!(self.state().input, InputHold::Held { .. })
    }

    /// Whether a key or button was still down when the deadline passed: the
    /// named exception to the bound, where the restore follows the confirmed
    /// release without a deadline.
    pub fn held_past_deadline(&self) -> bool {
        self.state().held_past_deadline
    }

    /// The front request is about to be made at `front_instant_ms`. `false`
    /// when the gate is closed or a front was already attempted: the front
    /// must not be requested.
    pub fn begin_front_attempt(&self, front_instant_ms: u64) -> bool {
        let mut state = self.state();
        if state.closed(Instant::now()) || state.attempt != FrontAttemptState::NotStarted {
            return false;
        }
        state.attempt = FrontAttemptState::Dispatching { front_instant_ms };
        true
    }

    /// The front request and its wait returned.
    pub fn front_attempt_returned(&self) {
        let mut state = self.state();
        if let FrontAttemptState::Dispatching { front_instant_ms } = state.attempt {
            state.attempt = FrontAttemptState::Dispatched { front_instant_ms };
        }
    }

    pub fn attempt_state(&self) -> FrontAttemptState {
        self.state().attempt
    }

    /// Terminal cleanup ends the call: nothing not yet committed may start,
    /// and a front not yet requested never will be. `true` when no front
    /// was ever requested, so nothing needs restoring; otherwise the owner
    /// still makes the one restore decision.
    pub fn stop_front(&self) -> bool {
        let mut state = self.state();
        state.stopped = true;
        state.attempt == FrontAttemptState::NotStarted
    }

    /// The owner begins ending the front: it is about to restore, or the
    /// bracket ended. Nothing new starts afterwards. Only the first call
    /// counts.
    pub fn end_front(&self) {
        let mut state = self.state();
        if state.ended_at.is_none() {
            state.ended_at = Some(Instant::now());
        }
    }

    /// Whether the owner began ending the front only once the restore
    /// reserve had started: the front reached its cutoff while the bracket
    /// was still busy in a unit.
    pub fn ended_past_cutoff(&self) -> bool {
        let state = self.state();
        match (state.ended_at, state.reserve_start) {
            (Some(ended), Some(reserve_start)) => ended >= reserve_start,
            _ => false,
        }
    }

    /// The owner made a native call from `started` to `finished` while the
    /// target was in front. Only a call still running at the deadline is
    /// kept: it is what a missed restore deadline can be attributed to.
    pub fn native_call(&self, started: Instant, finished: Instant) {
        let mut state = self.state();
        if state
            .deadline
            .is_some_and(|deadline| started <= deadline && finished > deadline)
        {
            state.native_overrun_until = Some(finished);
        }
    }

    /// When the latest native call that was still running at the deadline
    /// returned; see [`Self::native_call`].
    pub fn native_overrun_until(&self) -> Option<Instant> {
        self.state().native_overrun_until
    }
}
