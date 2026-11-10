//! The needs-front press: a press on an element that reads disabled while
//! its application is in the background.
//!
//! Some applications disable window buttons (Mail's Send among them) while
//! they are not frontmost, so the press can only work with the application in
//! front. [`run_fronting_press`] brings it forward for that press and then
//! runs the shared restore decision, in a fixed order:
//!
//! 1. the needs-front pre-read: the element's enabled state and the
//!    frontmost application;
//! 2. the badge schedule and arrival hold, with the hold's own person check;
//! 3. the process-wide fronting lock;
//! 4. the held-input guard, the target-change guard, then the idle gate with
//!    the observer heartbeat;
//! 5. cancellation and the dispatch gate re-checked, then the restore
//!    obligation registered;
//! 6. the front, waiting at most [`FRONT_WAIT_MS`];
//! 7. the enabled poll, every [`FRONTING_POLL_MS`] for at most
//!    [`ENABLE_POLL_MS`], else `element_disabled`;
//! 8. the press;
//! 9. the settle, at most the plan's settle bound, ended early by the
//!    person's input;
//! 10. the restore decision.
//!
//! During the poll, and before every press, the seize watcher is drained and
//! focus, cancellation and the dispatch gate are checked; any of them stops
//! the run before the press, and the restore decision still runs. The
//! watcher is drained during each fronted settle too: the person's keys
//! would land in the target while it is in front, so their input ends the
//! settle, no later step is pressed, and the restore decision runs at once.
//! A press
//! whose element is enabled, or whose application is already frontmost,
//! takes the ordinary path and never touches the fronting lock.
//!
//! A batch of presses fronts once, at the first step that needs it, keeps the
//! lock through the rest of the run, and makes one restore decision after the
//! last step's settle. Only that first fronted step waits for the badge to
//! arrive, and no later step may wait on consent, a lane or a person while
//! the target is in front.
//!
//! Everything platform-specific is behind [`FrontingPressHost`], so the order
//! and the bound are driven by a fake clock in tests.

use std::time::Instant;

use super::reason::FrontingStop;
use super::restore::{restore_after_front, wait_for_front, RESTORE_WAIT_MS};
use super::{FrontingBracketHost, RestoreStatus, FRONTING_POLL_MS};
use crate::dispatch::seize::{
    begin_observed_sequence, heartbeat_liveness, observe_drained_events, AbortDecision,
    AbortReason, ObservedPostRefusal, ObservedSequenceHooks, ObserverLiveness, SeizeWatcher,
    UserIdleEstimator,
};

/// How long the front waits for the target to come forward, in milliseconds.
pub const FRONT_WAIT_MS: u64 = 300;

/// How long a fronted press polls its element for becoming enabled, in
/// milliseconds.
pub const ENABLE_POLL_MS: u64 = 500;

/// The default settle bound after a fronted press, in milliseconds.
pub const PRESS_SETTLE_BOUND_MS: u64 = 500;

/// How long a fronting path waits for the process-wide fronting lock before
/// it stops with `fronting_busy`, in milliseconds.
pub const FRONTING_LOCK_WAIT_MS: u64 = 1_000;

/// The bound on the time a needs-front press run keeps its target in front,
/// counted from the front request until the restore is seen, for `steps`
/// fronted presses: the front wait, each step's enabled poll and settle, and
/// the restore wait. The badge's arrival comes before the front and is not
/// counted.
pub const fn press_fronting_bound_ms(steps: usize) -> u64 {
    FRONT_WAIT_MS + (steps as u64) * (ENABLE_POLL_MS + PRESS_SETTLE_BOUND_MS) + RESTORE_WAIT_MS
}

/// [`press_fronting_bound_ms`] for a single press.
pub const PRESS_FRONTING_BOUND_MS: u64 = press_fronting_bound_ms(1);

const _: () = assert!(PRESS_FRONTING_BOUND_MS == 1_600);

/// What a press run is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressPlan {
    pub target_pid: u32,
    /// Presses in the run, in order: one, or up to the batch limit.
    pub steps: usize,
    /// How long each fronted press may settle.
    pub settle_bound_ms: u64,
    pub maximum_seize_detection_latency_ms: u32,
}

/// The needs-front pre-read of one step's element.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressPreRead {
    /// Whether the element reads enabled; `None` when that could not be read.
    pub enabled: Option<bool>,
    /// The frontmost application's pid, when it could be read.
    pub frontmost: Option<u32>,
}

impl PressPreRead {
    /// A press needs its application in front only when the element reads
    /// disabled while that application is not frontmost. An element whose
    /// state cannot be read is not known to be disabled, and takes the
    /// ordinary path.
    pub fn needs_front(self, target_pid: u32) -> bool {
        self.enabled == Some(false) && self.frontmost != Some(target_pid)
    }
}

/// Who runs the restore decision at the end of a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreClaim {
    /// The run took the obligation, and runs the decision itself.
    Run,
    /// Terminal cleanup took it first and decided; this is what it decided.
    TakenByCleanup(RestoreStatus),
}

/// The platform a press run uses, beyond what a bracket uses.
pub trait FrontingPressHost: FrontingBracketHost {
    /// Step 1: read step `step`'s element enabled state and the frontmost
    /// application, in one blocking hop.
    fn pre_read(&mut self, step: usize) -> PressPreRead;
    /// Step 2: schedule the badge for `step` and, with `wait_for_arrival`,
    /// hold until it arrives. `false` when the person check that follows the
    /// hold found the target changed.
    fn hold_for_badge(&mut self, step: usize, wait_for_arrival: bool) -> bool;
    /// Step 3: take the process-wide fronting lock, waiting at most
    /// `wait_ms`. `false` when it was not taken in time.
    fn take_fronting_lock(&mut self, wait_ms: u64) -> bool;
    /// Guard (0): no release posted by an earlier call is still unconfirmed.
    /// Never posts a release itself.
    fn held_input_confirmed(&mut self) -> bool;
    /// Guard (1): whether the person changed the target since the agent last
    /// read it. `None` when that could not be checked.
    fn person_changed_target(&mut self) -> Option<bool>;
    /// Whether the caller cancelled.
    fn cancelled(&mut self) -> bool;
    /// Whether the dispatch gate still admits a mutation.
    fn dispatch_gate_open(&mut self) -> bool;
    /// Step 5: register the restore obligation for a front of `target` over
    /// `previous`. `false` when the call's terminal reply is already chosen.
    fn register_restore_obligation(&mut self, previous: u32, target: u32) -> bool;
    /// The front request is about to be made at `front_instant_ms`. `false`
    /// when cleanup already took the obligation, so no front may happen.
    fn begin_front_attempt(&mut self, front_instant_ms: u64) -> bool;
    /// The front request and its wait returned.
    fn front_attempt_returned(&mut self);
    fn front_confirmed(&mut self) {}
    /// Admit a step while the target is in front. `false` when admitting it
    /// would wait on consent, a lane or a person.
    fn admit_fronted_step(&mut self, step: usize) -> bool;
    /// Step 7: whether step `step`'s element reads enabled now.
    fn element_enabled(&mut self, step: usize) -> Option<bool>;
    /// Step 8: journal the press intent and press step `step`'s element.
    /// `true` when the press took effect.
    fn press(&mut self, step: usize) -> bool;
    /// Step 9: let step `step`'s press settle, for at most `bound_ms`.
    ///
    /// `person_acted` must be asked before every wait of the settle, and the
    /// settle must end as soon as it answers `true`: the person is using the
    /// input devices, and while the target is in front their keys would land
    /// in it. A settle that ends that way must not record what the
    /// application looks like after their input as what the agent was last
    /// shown, or the next person check would miss it.
    fn settle(
        &mut self,
        step: usize,
        bound_ms: u64,
        person_acted: &mut dyn FnMut(&mut Self) -> bool,
    ) -> SettleEnd;
    /// Step 10: take the restore obligation for the decision, unless terminal
    /// cleanup already has.
    fn claim_restore(&mut self) -> RestoreClaim;
    /// The restore decision is complete; release the fronting lock.
    fn finish_fronting(&mut self, restore: RestoreStatus);
}

/// How a press's settle ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettleEnd {
    /// It saw the press's effect or ran to its bound, with no input from
    /// the person.
    Quiet,
    /// The person's input ended it early.
    PersonInput,
}

/// Why a press run stopped before pressing every step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PressRunStop {
    /// Stopped before the target came to the front; the reply names the
    /// reason through [`super::not_fronted_reason`].
    NotFronted(FrontingStop),
    /// The target was in front, and input, focus loss, a cancel or a closed
    /// gate stopped the run before the next press.
    Interrupted(FrontingStop),
    /// The element still read disabled after the enabled poll.
    ElementDisabled,
    /// Admitting a step would have waited while the target was in front.
    StepNeedsWait,
    /// A press did not take effect.
    PressFailed,
}

/// What a press run did, whatever it ended with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PressFrontingReport {
    pub steps_pressed: usize,
    pub stop: Option<PressRunStop>,
    /// The step the run stopped at, when it stopped.
    pub stopped_at: Option<usize>,
    /// The step at which the front was requested, when one was.
    pub fronted_at_step: Option<usize>,
    pub previous_frontmost: Option<u32>,
    pub restore: RestoreStatus,
    pub person_input_during_fronting: bool,
    /// From the front request until the restore decision finished.
    pub fronted_interval_ms: u64,
    /// The bound that interval is held to.
    pub bound_ms: u64,
    /// The interval ran past the bound. Not a stop: a press that took effect
    /// is returned with this set rather than refused.
    pub fronting_bound_exceeded: bool,
    /// The observer's abort, when one stopped the run.
    pub abort: Option<AbortDecision>,
}

/// The observation a fronted run holds from the idle gate onwards.
struct Fronted<Tap> {
    tap: Tap,
    watcher: SeizeWatcher,
    previous: u32,
    /// When the front was requested; `None` when the target was already
    /// frontmost by the time the lock was held, so nothing was fronted.
    front_instant_ms: Option<u64>,
}

/// Run a press, fronting its application when the press needs it.
pub fn run_fronting_press<H: FrontingPressHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    plan: PressPlan,
) -> PressFrontingReport {
    let mut report = PressFrontingReport {
        steps_pressed: 0,
        stop: None,
        stopped_at: None,
        fronted_at_step: None,
        previous_frontmost: None,
        restore: RestoreStatus::NotNeeded,
        person_input_during_fronting: false,
        fronted_interval_ms: 0,
        bound_ms: 0,
        fronting_bound_exceeded: false,
        abort: None,
    };
    let our_pid = host.our_pid();
    let mut lock_held = false;
    let mut obligation_registered = false;
    let mut fronted: Option<Fronted<H::Tap>> = None;

    let stopped = 'steps: {
        for step in 0..plan.steps {
            if fronted.is_none() {
                // 1. The pre-read decides whether this step needs the front.
                let pre_read = host.pre_read(step);
                if !pre_read.needs_front(plan.target_pid) {
                    // The ordinary press path: no lock, no front.
                    if !host.hold_for_badge(step, true) {
                        break 'steps Some((
                            step,
                            PressRunStop::NotFronted(FrontingStop::PersonChangedTarget),
                        ));
                    }
                    if !host.press(step) {
                        break 'steps Some((step, PressRunStop::PressFailed));
                    }
                    report.steps_pressed += 1;
                    host.settle(step, plan.settle_bound_ms, &mut unfronted_settle::<H>);
                    continue;
                }
                // 2. The badge arrives before anything is fronted.
                if !host.hold_for_badge(step, true) {
                    break 'steps Some((
                        step,
                        PressRunStop::NotFronted(FrontingStop::PersonChangedTarget),
                    ));
                }
                // 3. The fronting lock.
                if !host.take_fronting_lock(FRONTING_LOCK_WAIT_MS) {
                    break 'steps Some((
                        step,
                        PressRunStop::NotFronted(FrontingStop::FrontingLockTimedOut),
                    ));
                }
                lock_held = true;
                // 4-6. The guards, the obligation and the front.
                let fronting = front_target(
                    host,
                    estimator,
                    plan,
                    step,
                    FrontProgress {
                        obligation_registered: &mut obligation_registered,
                        fronted: &mut fronted,
                        abort: &mut report.abort,
                    },
                );
                if let Some(session) = fronted.as_ref() {
                    report.previous_frontmost = Some(session.previous);
                    if session.front_instant_ms.is_some() {
                        report.fronted_at_step = Some(step);
                    }
                }
                if let Err(stop) = fronting {
                    break 'steps Some((step, PressRunStop::NotFronted(stop)));
                }
            } else {
                // A later step of a fronted batch: nothing may wait while the
                // target is in front, and the badge glides without a hold.
                if !host.admit_fronted_step(step) {
                    break 'steps Some((step, PressRunStop::StepNeedsWait));
                }
                if !host.hold_for_badge(step, false) {
                    break 'steps Some((
                        step,
                        PressRunStop::Interrupted(FrontingStop::PersonChangedTarget),
                    ));
                }
            }
            let Some(session) = fronted.as_mut() else {
                unreachable!("a step that is not on the ordinary path has fronted its target");
            };

            // 7. Poll the element until it reads enabled.
            let poll_start = host.now_ms();
            loop {
                if let Some(stop) =
                    check_before_press(host, session, our_pid, plan.target_pid, step)
                {
                    report.abort = session.watcher.abort_decision();
                    break 'steps Some((step, PressRunStop::Interrupted(stop)));
                }
                if host.element_enabled(step) == Some(true) {
                    break;
                }
                if host.now_ms().saturating_sub(poll_start) >= ENABLE_POLL_MS {
                    break 'steps Some((step, PressRunStop::ElementDisabled));
                }
                host.pause_ms(FRONTING_POLL_MS);
            }

            // 8. Press, after the same checks once more.
            if let Some(stop) = check_before_press(host, session, our_pid, plan.target_pid, step) {
                report.abort = session.watcher.abort_decision();
                break 'steps Some((step, PressRunStop::Interrupted(stop)));
            }
            if !host.press(step) {
                break 'steps Some((step, PressRunStop::PressFailed));
            }
            session.watcher.take_post_slot();
            report.steps_pressed += 1;

            // 9. Settle, draining the watcher before every wait. Input that is
            // not ours ends the settle; the press already took effect, so
            // the stop belongs to the next step, if there is one, and the
            // restore decision follows at once.
            let ended = host.settle(step, plan.settle_bound_ms, &mut |host: &mut H| {
                let drained = host.drain(&session.tap);
                observe_drained_events(&mut session.watcher, drained, our_pid, step + 1);
                session.watcher.abort_decision().is_some()
            });
            if ended == SettleEnd::PersonInput {
                report.abort = session.watcher.abort_decision();
                if step + 1 == plan.steps {
                    break 'steps None;
                }
                let stop = report
                    .abort
                    .map_or(FrontingStop::UserSeizedControl, |abort| {
                        FrontingStop::from_abort(abort.reason)
                    });
                break 'steps Some((step + 1, PressRunStop::Interrupted(stop)));
            }
        }
        None
    };
    if let Some((step, stop)) = stopped {
        report.stopped_at = Some(step);
        report.stop = Some(stop);
    }

    // 10. The restore decision, once, whatever the run ended with.
    if obligation_registered {
        let session = fronted.as_ref();
        match host.claim_restore() {
            RestoreClaim::Run => {
                let restore = match session {
                    Some(Fronted {
                        previous,
                        front_instant_ms: Some(front_instant_ms),
                        ..
                    }) => {
                        let outcome = restore_after_front(
                            host,
                            *previous,
                            plan.target_pid,
                            *front_instant_ms,
                            RESTORE_WAIT_MS,
                        );
                        report.person_input_during_fronting = outcome.person_input_during_fronting;
                        report.fronted_interval_ms =
                            outcome.finished_at_ms.saturating_sub(*front_instant_ms);
                        outcome.restore
                    }
                    _ => RestoreStatus::NotNeeded,
                };
                report.restore = restore;
                host.finish_fronting(restore);
            }
            RestoreClaim::TakenByCleanup(restore) => {
                report.restore = restore;
                if let Some(Fronted {
                    front_instant_ms: Some(front_instant_ms),
                    ..
                }) = session
                {
                    report.fronted_interval_ms = host.now_ms().saturating_sub(*front_instant_ms);
                }
            }
        }
    } else if lock_held {
        host.finish_fronting(RestoreStatus::NotNeeded);
    }

    if let Some(step) = report.fronted_at_step {
        report.bound_ms = press_fronting_bound_ms(plan.steps - step);
        report.fronting_bound_exceeded = report.fronted_interval_ms > report.bound_ms;
    }
    if matches!(
        report.abort,
        Some(AbortDecision {
            reason: AbortReason::UserSeizedControl,
            ..
        })
    ) {
        estimator.clear_carry();
    }
    report
}

/// Where [`front_target`] leaves what it got done, whether or not it ends
/// with a stop: a stop after the front request still needs the observation
/// and the front instant for the restore decision.
struct FrontProgress<'a, Tap> {
    obligation_registered: &'a mut bool,
    fronted: &'a mut Option<Fronted<Tap>>,
    abort: &'a mut Option<AbortDecision>,
}

/// Steps 4 to 6, with the fronting lock held: the held-input guard, the
/// target-change guard, the idle gate, the re-check of cancellation and the
/// dispatch gate, the restore obligation, and the front.
fn front_target<H: FrontingPressHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    plan: PressPlan,
    step: usize,
    progress: FrontProgress<'_, H::Tap>,
) -> Result<(), FrontingStop> {
    // 4. Guard (0), then guard (1), then the idle gate.
    if !host.held_input_confirmed() {
        return Err(FrontingStop::HeldInputUnconfirmed);
    }
    match host.person_changed_target() {
        Some(false) => {}
        Some(true) => return Err(FrontingStop::PersonChangedTarget),
        None => return Err(FrontingStop::PersonCheckUnreadable),
    }
    // Read with the lock held, so it can never be another agent's
    // temporarily fronted application.
    let Some(previous) = host.frontmost_pid() else {
        return Err(FrontingStop::PreviousUnknown);
    };
    let our_pid = host.our_pid();
    let mut watcher = SeizeWatcher::new(plan.maximum_seize_detection_latency_ms);
    for _ in step..plan.steps {
        watcher.queue_post();
    }
    let host_cell = std::cell::RefCell::new(&mut *host);
    let begun = begin_observed_sequence(
        estimator,
        &mut watcher,
        our_pid,
        Instant::now(),
        ObservedSequenceHooks {
            create_tap: || host_cell.borrow_mut().create_tap(),
            read_idle: || host_cell.borrow_mut().read_idle(),
            drain: |tap: &Option<H::Tap>| match tap {
                Some(tap) => host_cell.borrow_mut().drain(tap),
                None => Vec::new(),
            },
            post_heartbeat: || host_cell.borrow_mut().post_heartbeat(),
        },
    );
    let (tap, probe) = match begun {
        Ok((Some(tap), _user_idle, probe)) => (tap, probe),
        Ok((None, _, _)) => return Err(FrontingStop::ObserverUnavailable),
        Err(refusal) => {
            if matches!(
                refusal,
                ObservedPostRefusal::AlreadyAborted(AbortReason::UserSeizedControl)
            ) {
                estimator.clear_carry();
            }
            *progress.abort = watcher.abort_decision();
            return Err(watcher
                .abort_decision()
                .map_or(FrontingStop::ObserverUnavailable, |abort| {
                    FrontingStop::from_abort(abort.reason)
                }));
        }
    };
    let observation = host.observe_heartbeat(&tap, probe, &mut watcher);
    if let Some(abort) = watcher.abort_decision() {
        estimator.clear_carry();
        *progress.abort = Some(abort);
        return Err(FrontingStop::from_abort(abort.reason));
    }
    if heartbeat_liveness(probe, observation) == ObserverLiveness::Blind {
        return Err(FrontingStop::ObserverBlind);
    }

    // 5. Nothing is fronted for a call that is already ending.
    if host.cancelled() {
        return Err(FrontingStop::Cancelled);
    }
    if !host.dispatch_gate_open() {
        return Err(FrontingStop::DispatchGateClosed);
    }
    if !host.register_restore_obligation(previous, plan.target_pid) {
        return Err(FrontingStop::TerminalAlreadyChosen);
    }
    *progress.obligation_registered = true;
    let session = progress.fronted.insert(Fronted {
        tap,
        watcher,
        previous,
        front_instant_ms: None,
    });
    if previous == plan.target_pid {
        // Someone brought the target forward while this run waited for the
        // lock; there is nothing to front and nothing to put back.
        return Ok(());
    }

    // 6. The front. The interval is counted from the request.
    let front_instant_ms = host.now_ms();
    if !host.begin_front_attempt(front_instant_ms) {
        return Err(FrontingStop::CleanupTookObligation);
    }
    session.front_instant_ms = Some(front_instant_ms);
    let requested = host.request_front(plan.target_pid);
    let came_forward =
        requested && wait_for_front(host, plan.target_pid, front_instant_ms, FRONT_WAIT_MS);
    if came_forward {
        host.front_confirmed();
    }
    host.front_attempt_returned();
    if !came_forward {
        return Err(FrontingStop::FrontFailed);
    }
    Ok(())
}

/// The settle check for a press on the ordinary path. Nothing is in front
/// for it, so the person's input goes where they aim it and does not end the
/// settle.
fn unfronted_settle<H>(_host: &mut H) -> bool {
    false
}

/// The checks before every poll and every press while the target is in
/// front: input that is not ours, focus, cancellation and the dispatch gate.
fn check_before_press<H: FrontingPressHost>(
    host: &mut H,
    session: &mut Fronted<H::Tap>,
    our_pid: i64,
    target_pid: u32,
    step: usize,
) -> Option<FrontingStop> {
    let drained = host.drain(&session.tap);
    observe_drained_events(&mut session.watcher, drained, our_pid, step);
    if let Some(abort) = session.watcher.abort_decision() {
        return Some(FrontingStop::from_abort(abort.reason));
    }
    if host.frontmost_pid() != Some(target_pid) {
        session
            .watcher
            .abort(AbortReason::FocusMismatch, step, None);
        return Some(FrontingStop::FocusMoved);
    }
    if host.cancelled() {
        return Some(FrontingStop::Cancelled);
    }
    if !host.dispatch_gate_open() {
        return Some(FrontingStop::DispatchGateClosed);
    }
    None
}

#[cfg(test)]
mod tests;
