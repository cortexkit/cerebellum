//! What keeps a temporary front inside its bound once the target is in
//! front: checks a keystroke unit makes before each of its own posts, a
//! timer that takes over the restore when the restore reserve starts, and
//! the one state that says who owns the restore decision.
//!
//! What the bound means: after the deadline nothing new is posted or
//! captured, and by the deadline the restore of the previous application
//! has been requested. The restore's confirmation is reported, not promised
//! within the bound: the person's application may come back late.
//!
//! Who decides the restore is fixed by time, not by who gets there first.
//! The bound has two phases, split at the start of the restore reserve (the
//! deadline minus the time a restore has lately taken to prepare):
//!
//! - **Phase A, before the reserve starts.** The action's own cleanup, or
//!   the call's terminal cleanup, may claim the decision and carry it out.
//!   It checks between its steps that phase A still holds and caps its
//!   sleeps at the start of the reserve. A read it is already inside cannot
//!   be cut short, so when phase A ends during that read the owner simply
//!   loses: what the read returned is never used, and its write is refused.
//! - **Phase B, from the start of the reserve.** The timer owns the decision
//!   outright, whatever a phase-A owner is doing, and decides on its own
//!   restore host, so it never waits for a phase-A owner to return.
//!
//! While a key or button may be held, the timer waits for its release: a
//! restore under a held key would hand that key to the previous
//! application. A release that settles before the deadline lets the timer
//! restore at once against the original deadline. A hold still unsettled at
//! the deadline is the one exception to the bound: the decision then passes
//! to whoever settles the release, and the restore follows the confirmed
//! release without a deadline.
//!
//! Every change of owner happens under [`CutoffGate`]'s one mutex, which
//! guards only plain data. No focus read, sleep or native write is made
//! while it is held, so a stalled system call can never hold up a change of
//! owner.

use super::FrontAttemptState;
use crate::platform::{FrontedKeyGuard, ProcessEventRefusal};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

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

/// Who owns the decision about the first restore request: see the module
/// documentation for the two phases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestorePhase {
    /// Phase A, before the restore reserve starts. `claimed` once an
    /// ordinary owner (the action's cleanup or the terminal's) has taken the
    /// decision; it keeps it only while phase A lasts.
    Ordinary { claimed: bool },
    /// Phase B: the timer owns the decision. `awaiting_release` while it
    /// waits for input that may be held to be released before restoring.
    Timer { awaiting_release: bool },
    /// Input was still held when the deadline passed. The decision passes to
    /// whoever settles that release; the restore follows the confirmed
    /// release with no deadline. `claimed` once one has taken it.
    AfterRelease { claimed: bool },
    /// The first restore request was made, or decided against. `by_timer`
    /// says the timer made that decision.
    Done { by_timer: bool },
}

/// Where the gate's timer is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TimerState {
    NotArmed,
    /// Waiting for the start of the reserve.
    Armed,
    /// It took its turn at the start of the reserve. `ended` once its
    /// bracket finished while it still waited for held input, which only the
    /// bracket's caller can release.
    Turn {
        ended: bool,
    },
    /// Stopped before its turn.
    Stopped,
}

/// Whether input this front posted may still be down or in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputHold {
    Released,
    Held,
}

/// The state a bracket, its restore cell and its cutoff timer share: the
/// restore owner, the front attempt, whether input may be held, and the two
/// instants that bound the front. Only plain data: nothing here calls the
/// platform, and the lock is never held across a platform call.
#[derive(Debug)]
struct GateState {
    phase: RestorePhase,
    /// Numbers ordinary claims, so an owner that lost its claim never mistakes
    /// a later owner's claim for its own.
    claim: u64,
    timer: TimerState,
    attempt: FrontAttemptState,
    input: InputHold,
    /// The start of the restore reserve: no post starts and no picture is
    /// acquired from here, and phase B begins here when a timer is armed.
    closes_at: Option<Instant>,
    /// The absolute deadline for the first restore request.
    deadline: Option<Instant>,
}

impl Default for GateState {
    fn default() -> Self {
        Self {
            phase: RestorePhase::Ordinary { claimed: false },
            claim: 0,
            timer: TimerState::NotArmed,
            attempt: FrontAttemptState::NotStarted,
            input: InputHold::Released,
            closes_at: None,
            deadline: None,
        }
    }
}

impl GateState {
    /// Phase A ends at the start of the reserve, whether or not the timer's
    /// thread has run yet: the clock alone moves the decision to the timer.
    fn advance(&mut self, now: Instant) {
        if self.timer == TimerState::Armed
            && matches!(self.phase, RestorePhase::Ordinary { .. })
            && self.closed(now)
        {
            self.phase = RestorePhase::Timer {
                awaiting_release: false,
            };
        }
    }

    fn closed(&self, now: Instant) -> bool {
        self.closes_at.is_some_and(|at| now >= at)
    }

    fn holds(&self, ticket: &OrdinaryTicket) -> bool {
        self.claim == ticket.0
            && matches!(
                self.phase,
                RestorePhase::Ordinary { claimed: true }
                    | RestorePhase::AfterRelease { claimed: true }
                    | RestorePhase::Done { by_timer: false }
            )
    }
}

/// The claim an ordinary owner holds; see [`CutoffGate::claim_ordinary`].
#[derive(Debug, PartialEq, Eq)]
pub struct OrdinaryTicket(u64);

/// What an ordinary owner may do once it asked for the decision.
#[derive(Debug, PartialEq, Eq)]
pub enum OrdinaryClaim {
    /// Nothing was fronted, and now nothing will be: the decision is made,
    /// and no restore is needed.
    PreventedFront,
    /// The owner holds the decision. It keeps it only while
    /// [`CutoffGate::ordinary_holds`] says so.
    Decide {
        ticket: OrdinaryTicket,
        /// When the front was requested: the floor for person input.
        front_instant_ms: u64,
        /// The front request has not returned yet.
        in_flight: bool,
        /// The first restore request must be made by the deadline. `false`
        /// only when input was still held at the deadline.
        write_deadline: bool,
    },
    /// Another owner holds the decision: wait for it.
    Await,
}

/// What a cleanup that must not restore (input may still be held) gets.
#[derive(Debug, PartialEq, Eq)]
pub enum ForgoClaim {
    /// Nothing was fronted, and now nothing will be.
    PreventedFront,
    /// Taken without a restore. The front was requested at this instant.
    Taken { front_instant_ms: u64 },
    /// Another owner holds the decision: wait for it.
    Await,
}

/// How a wait for another owner's decision ended.
#[derive(Debug, PartialEq, Eq)]
pub enum Awaited {
    /// The first restore request was made or decided against.
    Decided,
    /// The decision came back unowned and may be claimed.
    Claimable,
    TimedOut,
}

/// The state a bracket shares with its restore cell and cutoff timer; see
/// the module documentation.
#[derive(Debug, Default)]
pub struct CutoffGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl CutoffGate {
    pub fn new() -> Self {
        Self::default()
    }

    fn state(&self) -> MutexGuard<'_, GateState> {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        state.advance(Instant::now());
        state
    }

    fn changed(&self, state: MutexGuard<'_, GateState>) {
        drop(state);
        self.changed.notify_all();
    }

    /// Who owns the restore decision now.
    pub fn phase(&self) -> RestorePhase {
        self.state().phase
    }

    /// A post is about to start. `false` once phase A is over or cleanup has
    /// taken the decision: the post must not be made. Otherwise the post is
    /// committed under the gate's lock and input counts as held until
    /// [`Self::all_released`], so the timer will not restore while the post
    /// is in flight. A self-contained post is released once it returns; a
    /// `press` only once its release has.
    pub fn begin_post(&self, _press: bool) -> bool {
        let mut state = self.state();
        if state.phase != (RestorePhase::Ordinary { claimed: false })
            || state.closed(Instant::now())
        {
            return false;
        }
        state.input = InputHold::Held;
        true
    }

    /// No post is in flight and nothing the unit pressed is still down. A
    /// timer waiting for this proceeds at once.
    pub fn all_released(&self) {
        let mut state = self.state();
        state.input = InputHold::Released;
        self.changed(state);
    }

    /// Whether the timer took its turn at the start of the reserve.
    pub fn fired(&self) -> bool {
        matches!(self.state().timer, TimerState::Turn { .. })
    }

    /// Record when the gate closes to new posts and pictures, so a check
    /// need not wait for the timer's thread to have run.
    pub fn set_deadline(&self, closes_at: Instant) {
        self.state().closes_at = Some(closes_at);
    }

    /// Whether the gate closed: the timer took its turn, or the start of the
    /// reserve is behind the clock even if the timer has not run yet.
    pub fn past_deadline(&self) -> bool {
        let state = self.state();
        matches!(state.timer, TimerState::Turn { .. }) || state.closed(Instant::now())
    }

    /// Whether the timer, not an ordinary owner, made the restore decision.
    pub fn restore_started_by_cutoff(&self) -> bool {
        matches!(
            self.state().phase,
            RestorePhase::Timer { .. } | RestorePhase::Done { by_timer: true }
        )
    }

    /// Whether some owner has taken the decision: nothing new may start.
    pub fn restore_taken(&self) -> bool {
        self.state().phase != (RestorePhase::Ordinary { claimed: false })
    }

    /// The front request is about to be made at `front_instant_ms`. `false`
    /// when an owner already took the decision or a front was already
    /// attempted: the front must not be requested.
    pub fn begin_front_attempt(&self, front_instant_ms: u64) -> bool {
        let mut state = self.state();
        if state.phase != (RestorePhase::Ordinary { claimed: false })
            || state.attempt != FrontAttemptState::NotStarted
        {
            return false;
        }
        state.attempt = FrontAttemptState::Dispatching { front_instant_ms };
        true
    }

    /// The front request and its wait returned, whoever owns the decision.
    pub fn front_attempt_returned(&self) {
        let mut state = self.state();
        if let FrontAttemptState::Dispatching { front_instant_ms } = state.attempt {
            state.attempt = FrontAttemptState::Dispatched { front_instant_ms };
        }
        self.changed(state);
    }

    pub fn attempt_state(&self) -> FrontAttemptState {
        self.state().attempt
    }

    /// Wait at most `timeout` for a front request in flight to return. For
    /// an owner with no deadline only: a timed owner never waits for it.
    pub fn wait_front_attempt(&self, timeout: Duration) -> FrontAttemptState {
        let state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                matches!(state.attempt, FrontAttemptState::Dispatching { .. })
            })
            .unwrap_or_else(PoisonError::into_inner);
        state.attempt
    }

    /// An ordinary owner asks for the decision. In phase A, or after a hold
    /// at the deadline, the first to ask gets it; any other answer is
    /// [`OrdinaryClaim::Await`], and the owner then waits with
    /// [`Self::await_owner`] without delaying the timer.
    pub fn claim_ordinary(&self) -> OrdinaryClaim {
        let mut state = self.state();
        let after_release = match state.phase {
            RestorePhase::Ordinary { claimed: false } => false,
            RestorePhase::AfterRelease { claimed: false } => true,
            _ => return OrdinaryClaim::Await,
        };
        let (front_instant_ms, in_flight) = match state.attempt {
            FrontAttemptState::NotStarted => {
                state.phase = RestorePhase::Done { by_timer: false };
                self.changed(state);
                return OrdinaryClaim::PreventedFront;
            }
            FrontAttemptState::Dispatching { front_instant_ms } => (front_instant_ms, true),
            FrontAttemptState::Dispatched { front_instant_ms } => (front_instant_ms, false),
        };
        state.claim += 1;
        state.phase = if after_release {
            RestorePhase::AfterRelease { claimed: true }
        } else {
            RestorePhase::Ordinary { claimed: true }
        };
        OrdinaryClaim::Decide {
            ticket: OrdinaryTicket(state.claim),
            front_instant_ms,
            in_flight,
            write_deadline: !after_release,
        }
    }

    /// A cleanup that knows input may still be held takes the decision
    /// without restoring. It may also end a timer that is only waiting for
    /// that input's release, since that timer could not restore anyway.
    pub fn claim_forgo(&self) -> ForgoClaim {
        let mut state = self.state();
        if !matches!(
            state.phase,
            RestorePhase::Ordinary { claimed: false }
                | RestorePhase::AfterRelease { claimed: false }
                | RestorePhase::Timer {
                    awaiting_release: true
                }
        ) {
            return ForgoClaim::Await;
        }
        state.phase = RestorePhase::Done { by_timer: false };
        let claim = match state.attempt {
            FrontAttemptState::NotStarted => ForgoClaim::PreventedFront,
            FrontAttemptState::Dispatching { front_instant_ms }
            | FrontAttemptState::Dispatched { front_instant_ms } => {
                ForgoClaim::Taken { front_instant_ms }
            }
        };
        self.changed(state);
        claim
    }

    /// Wait at most `timeout` until another owner decided, or the decision
    /// came back unowned. `forgo` also counts a timer waiting for a release
    /// as claimable, for [`Self::claim_forgo`]. The gate's lock is released
    /// while waiting.
    pub fn await_owner(&self, timeout: Duration, forgo: bool) -> Awaited {
        let claimable = |phase: RestorePhase| {
            matches!(
                phase,
                RestorePhase::Ordinary { claimed: false }
                    | RestorePhase::AfterRelease { claimed: false }
            ) || (forgo
                && phase
                    == RestorePhase::Timer {
                        awaiting_release: true,
                    })
        };
        let state = self.state();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, timeout, |state| {
                state.advance(Instant::now());
                !matches!(state.phase, RestorePhase::Done { .. }) && !claimable(state.phase)
            })
            .unwrap_or_else(PoisonError::into_inner);
        if matches!(state.phase, RestorePhase::Done { .. }) {
            Awaited::Decided
        } else if claimable(state.phase) {
            Awaited::Claimable
        } else {
            Awaited::TimedOut
        }
    }

    /// Whether the ordinary owner holding `ticket` still owns the decision.
    /// Asked between its steps: once phase A is over it must stop and write
    /// nothing, whatever its last read said.
    pub fn ordinary_holds(&self, ticket: &OrdinaryTicket) -> bool {
        self.state().holds(ticket)
    }

    /// How long the owner holding `ticket` may still sleep before phase A
    /// ends; `None` when nothing will end its ownership on time.
    pub fn ordinary_time_left(&self, ticket: &OrdinaryTicket) -> Option<Duration> {
        let state = self.state();
        let timed = state.timer == TimerState::Armed
            && state.phase == (RestorePhase::Ordinary { claimed: true })
            && state.claim == ticket.0;
        timed
            .then_some(state.closes_at)
            .flatten()
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// The owner holding `ticket` makes its restore request, or ends its
    /// decision without one. `true` when it still owned the decision, which
    /// is then made: the timer has nothing to do. `false` when it lost it:
    /// it must not write, and its result is not the decision.
    pub fn settle_ordinary(&self, ticket: &OrdinaryTicket) -> bool {
        let mut state = self.state();
        if !state.holds(ticket) {
            return false;
        }
        state.phase = RestorePhase::Done { by_timer: false };
        self.changed(state);
        true
    }

    /// The timer finished its decision.
    pub fn timer_decided(&self) {
        let mut state = self.state();
        if let RestorePhase::Timer { .. } = state.phase {
            state.phase = RestorePhase::Done { by_timer: true };
        }
        self.changed(state);
    }

    fn arm(&self, closes_at: Instant, deadline: Instant) {
        let mut state = self.state();
        state.closes_at = Some(closes_at);
        state.deadline = Some(deadline);
        state.timer = TimerState::Armed;
    }

    /// The timer's turn at the start of the reserve. `None` when it has
    /// nothing to restore: an ordinary owner already decided, input stayed
    /// held through the deadline, or its bracket ended while input it cannot
    /// see released was held. Otherwise it owns the decision and must make
    /// it at once; `Some(Some(at))` when it first waited for a release that
    /// settled at `at`.
    fn take_turn(&self) -> Option<Option<Instant>> {
        let mut state = self.state();
        if state.timer == TimerState::Stopped
            || matches!(
                state.phase,
                RestorePhase::Done { .. } | RestorePhase::AfterRelease { .. }
            )
        {
            return None;
        }
        state.timer = TimerState::Turn { ended: false };
        let mut released_at = None;
        while state.input == InputHold::Held {
            state.phase = RestorePhase::Timer {
                awaiting_release: true,
            };
            let now = Instant::now();
            if state.timer == (TimerState::Turn { ended: true }) {
                // Only the bracket's caller can settle this release now. It
                // decides with the deadline still in force.
                state.phase = RestorePhase::Ordinary { claimed: false };
                self.changed(state);
                return None;
            }
            if state.deadline.is_none_or(|deadline| now >= deadline) {
                // The one exception to the bound: the restore follows the
                // confirmed release, however late.
                state.phase = RestorePhase::AfterRelease { claimed: false };
                self.changed(state);
                return None;
            }
            self.changed.notify_all();
            let remaining = state.deadline.map_or(Duration::ZERO, |deadline| {
                deadline.saturating_duration_since(now)
            });
            state = self
                .changed
                .wait_timeout(state, remaining)
                .unwrap_or_else(PoisonError::into_inner)
                .0;
            if matches!(state.phase, RestorePhase::Done { .. }) {
                // A cleanup that knows the input is held took the decision.
                return None;
            }
            released_at = Some(Instant::now());
        }
        state.phase = RestorePhase::Timer {
            awaiting_release: false,
        };
        self.changed(state);
        Some(released_at)
    }

    /// The bracket is finishing. A timer stays armed when an ordinary owner
    /// is deciding in phase A, since only the timer can take over if that
    /// owner stalls; otherwise it is stopped, or told its bracket ended.
    fn end_timer(&self) {
        let mut state = self.state();
        match state.timer {
            TimerState::Armed if state.phase == (RestorePhase::Ordinary { claimed: true }) => {}
            TimerState::Armed => state.timer = TimerState::Stopped,
            TimerState::Turn { .. } => state.timer = TimerState::Turn { ended: true },
            TimerState::NotArmed | TimerState::Stopped => {}
        }
        self.changed(state);
    }
}

#[cfg(test)]
impl CutoffGate {
    /// The timer's turn as a single-threaded test plays it: where the real
    /// timer would wait for held input to be released, this returns `false`
    /// and leaves the timer waiting, and a later call after the release
    /// returns `true`.
    pub(super) fn fire(&self) -> bool {
        let mut state = self.state();
        if matches!(
            state.phase,
            RestorePhase::Done { .. } | RestorePhase::AfterRelease { .. }
        ) {
            return false;
        }
        state.timer = TimerState::Turn { ended: false };
        let awaiting_release = state.input == InputHold::Held;
        state.phase = RestorePhase::Timer { awaiting_release };
        !awaiting_release
    }
}

/// Test seams for callers outside this crate that drive the timer's side of
/// the decision by hand.
#[doc(hidden)]
impl CutoffGate {
    /// Arm without a timer thread, as [`CutoffTimer::arm_with_wake`] does.
    pub fn arm_for_test(&self, closes_at: Instant, deadline: Instant) {
        self.arm(closes_at, deadline);
    }

    /// The timer's turn, as its thread takes it.
    pub fn take_timer_turn_for_test(&self) -> Option<Option<Instant>> {
        self.take_turn()
    }
}

/// A thread that takes the timer's turn on a [`CutoffGate`] at the start of
/// the restore reserve, and then runs `restore` when the gate gives it the
/// decision. It holds no lock while `restore` runs. Finishing it, or
/// dropping it, stops a timer that is not needed and waits for one that is,
/// so no timer outlives its bracket.
///
/// Both instants are ones the caller stamped before the front was
/// requested, not spans measured from when the thread happens to start, so
/// a slow registration or a late-scheduled thread cannot move the cutoff
/// later than the bound. A start already past takes the turn at once.
pub struct CutoffTimer {
    gate: Arc<CutoffGate>,
    stop: Option<mpsc::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

/// When the timer's restore preparation was planned to start and when it
/// actually could, before taking any bracket locks or running restore code.
/// After a wait for held input, both are the moment the release settled.
#[derive(Clone, Copy, Debug)]
pub struct CutoffWake {
    pub scheduled_at: Instant,
    pub woke_at: Instant,
}

impl CutoffTimer {
    /// `None` when no thread could be started; the caller must then not
    /// front, since nothing would enforce the bound. The reserve starts at
    /// the deadline itself.
    pub fn arm(
        gate: Arc<CutoffGate>,
        deadline: Instant,
        restore: Box<dyn FnOnce() + Send>,
    ) -> Option<Self> {
        Self::arm_with_wake(gate, deadline, deadline, Box::new(move |_| restore()))
    }

    /// Like [`Self::arm`], with the reserve starting at `closes_at`, ahead
    /// of `deadline`, and handing the restore its planned and actual start
    /// so preparation accounting includes the entire timer path.
    pub fn arm_with_wake(
        gate: Arc<CutoffGate>,
        closes_at: Instant,
        deadline: Instant,
        restore: Box<dyn FnOnce(CutoffWake) + Send>,
    ) -> Option<Self> {
        gate.arm(closes_at, deadline);
        let (stop, stopped) = mpsc::channel::<()>();
        let (ready, started) = mpsc::sync_channel(1);
        let thread_gate = Arc::clone(&gate);
        let thread = std::thread::Builder::new()
            .name("fronting-cutoff".into())
            .spawn(move || {
                if ready.send(()).is_err() {
                    return;
                }
                let remaining = closes_at.saturating_duration_since(Instant::now());
                match stopped.recv_timeout(remaining) {
                    Err(RecvTimeoutError::Timeout) => {}
                    // The bracket finished. The turn is still taken when an
                    // ordinary owner is deciding, so a stall there is covered.
                    _ => {
                        if thread_gate.state().timer != TimerState::Armed {
                            return;
                        }
                        std::thread::sleep(closes_at.saturating_duration_since(Instant::now()));
                    }
                }
                let woke_at = Instant::now();
                if let Some(released_at) = thread_gate.take_turn() {
                    let wake = match released_at {
                        Some(at) => CutoffWake {
                            scheduled_at: at,
                            woke_at: at,
                        },
                        None => CutoffWake {
                            scheduled_at: closes_at,
                            woke_at,
                        },
                    };
                    restore(wake);
                }
            })
            .ok()?;
        // Do not let activation outrun thread startup. The absolute instants
        // still hold if the OS preempts this thread after it signals ready.
        started.recv().ok()?;
        Some(Self {
            gate,
            stop: Some(stop),
            thread: Some(thread),
        })
    }

    /// Stop the timer if nothing needs its turn, and wait for any restore it
    /// started to return.
    pub fn finish(mut self) {
        self.stop_and_join();
    }

    fn stop_and_join(&mut self) {
        self.gate.end_timer();
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
