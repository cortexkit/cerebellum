//! The fronting bracket: bring a background application forward, post
//! keystrokes to it, and put the previous application back.
//!
//! Some applications (Chromium and Electron ones among them) drop keystrokes
//! posted to their process while they are in the background, so delivering to
//! them means making them frontmost. Fronting an application can take the
//! person's own keystrokes, so the bracket runs under the same guards the
//! observed pointer sequence does, through the same functions: the idle gate
//! and heartbeat in [`begin_observed_sequence`], and the per-post heartbeat,
//! focus and seize checks in [`dispatch_observed_post_in_order`]. Any input
//! that is not ours stops it.
//!
//! The time the target spends in front is bounded. Text that cannot be posted
//! inside one bounded interval is split into chunks, and the previous
//! application is restored between chunks. How much fits is measured while
//! posting rather than assumed: each unit's post time and each restore's
//! latency are timed, and a chunk ends when the next unit and a restore would
//! no longer fit.
//!
//! Everything platform-specific is behind [`FrontingBracketHost`], so the
//! ordering, the chunking and the bound are driven by a fake clock in tests.
//!
//! A build admitted to app-use fronting ([`FrontingAdmission`]) changes two
//! things about how a bracket ends: the restore runs the shared restore
//! decision ([`decide_restore`]), which leaves the person in an application
//! they switched to themselves, and a post failure that may have left a key
//! held defers the restore to the caller instead of putting the previous
//! application back under a held modifier. Without admission a bracket
//! behaves as it always has.

mod latency;
mod press;
mod reason;
mod restore;

pub use latency::UNIT_POST_COST_MAX_AGE;
// Only the macOS keystroke host keeps unit post costs process-wide.
#[cfg(target_os = "macos")]
pub(crate) use latency::{measured_unit_post_cost_ms, record_unit_post_cost_ms};
pub use press::*;
pub use reason::*;
pub use restore::*;

use std::cell::RefCell;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::seize::SourcedInputKind;
use super::seize::{
    begin_observed_sequence, dispatch_observed_post_in_order, observe_drained_events,
    AbortDecision, AbortReason, HeartbeatObservation, HeartbeatProbe, ObservedPostRefusal,
    ObservedSequenceHooks, SeizeWatcher, SourcedInputEvent, UserIdleEstimator,
};
use crate::platform::{HeldStateDisposition, IdleReading, SequencePostFailure};

/// How often a fronting or restore request is checked for having taken
/// effect, in milliseconds. Small against the bracket's bound, so the check
/// itself does not use up the interval.
pub const FRONTING_POLL_MS: u64 = 2;

/// What one unit's posting did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct UnitPosted {
    pub posts_returned: u64,
    pub generation_verifications: u64,
}

/// The observation already admitted by the bracket, shared with a gesture
/// that contains several posts. No unit may start a second idle sequence.
pub struct ObservedUnit<'a, T> {
    pub tap: &'a T,
    pub watcher: &'a mut SeizeWatcher,
    pub probe: HeartbeatProbe,
    pub heartbeat: HeartbeatObservation,
    pub cancelled: &'a dyn Fn() -> bool,
    pub deadline_ms: u64,
}

/// The platform a bracket runs on.
///
/// A unit must not be split across a restore: one image read, one character
/// of typed text, one whole key chord, or one complete pointer gesture. Held
/// modifiers or mouse buttons must never cross a restore.
pub trait FrontingBracketHost {
    type Tap;

    /// Milliseconds on the bracket's clock.
    fn now_ms(&mut self) -> u64;
    /// Wait before checking again whether a fronting request took effect.
    fn pause_ms(&mut self, milliseconds: u64);
    /// The frontmost application's pid, or `None` when it cannot be read.
    fn frontmost_pid(&mut self) -> Option<u32>;
    /// Ask the application `pid` runs to become frontmost. `false` when the
    /// request itself was refused.
    fn request_front(&mut self, pid: u32) -> bool;
    /// A second way to ask for `pid` to come to the front, used by a restore
    /// only when [`Self::request_front`] has not taken effect within
    /// [`RESTORE_FALLBACK_AFTER_MS`]. `false` when the host has none or the
    /// request was refused.
    fn request_front_fallback(&mut self, _pid: u32) -> bool {
        false
    }
    /// Optional diagnostic observation; it never authorizes more action input.
    fn late_activation_observed(&mut self, _latency_ms: u64) {}
    /// The action's confirmation wait ended. Later observations belong only
    /// to cleanup and must not turn the refused action into a confirmed front.
    fn front_attempt_finished(&mut self) {}
    /// A hooked caller owns pending-activation cleanup; ordinary hosts use
    /// the same bounded confirmation-aware decision directly.
    fn restore_front_attempt(
        &mut self,
        previous: u32,
        target: u32,
        since: u64,
        wait_ms: u64,
        activation_observed: bool,
    ) -> RestoreOutcome {
        restore_after_front_attempt(self, previous, target, since, wait_ms, activation_observed)
    }
    /// The largest of the last eight restore costs in this process, shared
    /// across calls and targets. Hosts with an isolated clock may keep their
    /// own samples instead.
    fn measured_restore_latency_ms(&mut self) -> Option<u64> {
        latency::measured_restore_latency_ms()
    }
    /// Retain a completed restore's cost, or a conservative timeout cost.
    /// Skipped restores and already-frontmost targets supply no sample.
    fn record_restore_latency_ms(&mut self, milliseconds: u64) {
        latency::record_restore_latency_ms(milliseconds);
    }
    /// The largest recent unit post cost this host keeps, reserved for the
    /// first unit of a bracket before the bracket has timed one of its own.
    /// The default keeps none, which reserves nothing; a host that posts
    /// keystrokes keeps them process-wide, each for
    /// [`UNIT_POST_COST_MAX_AGE`].
    fn measured_unit_post_cost_ms(&mut self) -> Option<u64> {
        None
    }
    /// Retain a posted unit's cost. The default keeps nothing.
    fn record_unit_post_cost_ms(&mut self, _milliseconds: u64) {}
    /// Our own pid as input sources carry it.
    fn our_pid(&self) -> i64;
    /// Checks on the target that need no front, run before each front is
    /// requested so their cost is not spent inside the bounded interval. A
    /// failure stops the bracket before that front: nothing is fronted and
    /// nothing posted for the chunk. The default has no such checks.
    fn before_front(&mut self) -> Result<(), SequencePostFailure> {
        Ok(())
    }
    /// Start watching session input. `None` when no observer can be started.
    fn create_tap(&mut self) -> Option<Self::Tap>;
    /// Time since the last hardware input.
    fn read_idle(&mut self) -> IdleReading;
    /// Input the observer saw since it was last drained.
    fn drain(&mut self, tap: &Self::Tap) -> Vec<SourcedInputEvent>;
    /// Post the observer's heartbeat marker.
    fn post_heartbeat(&mut self) -> HeartbeatProbe;
    /// Wait for the heartbeat to come back through the observer, feeding
    /// anything else it sees to the watcher.
    fn observe_heartbeat(
        &mut self,
        tap: &Self::Tap,
        probe: HeartbeatProbe,
        watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation;
    /// Post unit `index` to the target process, checking its generation
    /// before each post.
    fn post_unit(&mut self, index: usize) -> Result<UnitPosted, SequencePostFailure>;
    fn post_observed_unit(
        &mut self,
        index: usize,
        _observation: ObservedUnit<'_, Self::Tap>,
    ) -> Result<UnitPosted, SequencePostFailure> {
        self.post_unit(index)
    }
    /// Complete any platform-specific observation tail after restoration.
    fn finish_observation(
        &mut self,
        _tap: &Self::Tap,
        _estimator: &mut UserIdleEstimator,
        _user_idle: IdleReading,
        _idle_read_at: Instant,
    ) {
    }
    /// The process-wide session observer's hardware input timestamps, on
    /// this host's clock, for the restore decision. `None` when unavailable,
    /// which cannot establish safe inactivity, so the decision leaves focus
    /// alone instead of requesting the previous application.
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        None
    }
}

/// Whether the previous application is back in front.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "restore", rename_all = "snake_case")]
pub enum RestoreStatus {
    /// Nothing was fronted, so there was nothing to put back.
    NotNeeded,
    /// The previous application is frontmost again.
    Restored,
    /// It could not be put back. `left_in_front` is what was frontmost when
    /// the bracket gave up, when that could be read.
    Failed { left_in_front: Option<u32> },
    /// Not put back, on purpose: the person switched to `now_front` with
    /// hardware input while the target was in front, and is left there.
    ///
    /// In memory only. It is skipped by serde, so it can never be written to
    /// storage (serializing it is an error) or read back from it.
    #[serde(skip)]
    SkippedPerson { now_front: Option<u32> },
}

/// Why a bracket stopped before posting every unit.
#[derive(Debug, Clone, PartialEq)]
pub enum BracketStop {
    /// The frontmost application could not be read, so it could not have been
    /// restored; nothing was fronted.
    PreviousUnknown,
    /// No input observer could be started; nothing was fronted.
    ObserverUnavailable,
    /// The target did not become frontmost within the bound.
    FrontFailed,
    /// A chunk could not fit inside the bound, or ran past it.
    BoundExceeded,
    /// The idle gate refused, the observer went blind, focus moved, or input
    /// that was not ours arrived.
    Aborted(AbortDecision),
    /// The caller cancelled at a chunk boundary.
    Cancelled,
    /// A post failed; the failure says what was left held.
    PostFailed(SequencePostFailure),
    /// The previous application could not be put back, so no further chunk
    /// was fronted.
    RestoreFailed,
}

/// What a bracket did, whatever it ended with.
#[derive(Debug, Clone, PartialEq)]
pub struct BracketReport {
    /// The application that was frontmost before, and is restored after.
    pub previous_frontmost: Option<u32>,
    pub chunks: u32,
    pub units_posted: usize,
    pub posts_returned: u64,
    pub generation_verifications: u64,
    /// The longest time the target spent in front, from the fronting request
    /// to the restore being seen.
    pub longest_fronted_interval_ms: u64,
    /// The slowest unit post and restore seen, which is what decided where
    /// each chunk ended.
    pub slowest_unit_ms: u64,
    pub slowest_restore_ms: u64,
    pub restore: RestoreStatus,
    pub stop: Option<BracketStop>,
    /// The stop is `BoundExceeded` only because recent unit posts in this
    /// process were slow: the front and the restore alone would have fit.
    /// That reserve ages out, so a later retry can be admitted.
    pub waiting_out_slow_post: bool,
}

impl BracketReport {
    /// Whether every unit was posted inside the bound and the previous
    /// application is back. A skipped restore is not held: the previous
    /// application is not back, even though nothing failed.
    pub fn held(&self, maximum_interval_ms: u64) -> bool {
        self.stop.is_none()
            && matches!(
                self.restore,
                RestoreStatus::Restored | RestoreStatus::NotNeeded
            )
            && self.longest_fronted_interval_ms <= maximum_interval_ms
    }
}

/// What the bracket is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BracketPlan {
    pub target_pid: u32,
    pub units: usize,
    pub maximum_interval_ms: u64,
    pub maximum_seize_detection_latency_ms: u32,
}

/// Which fronting rules this build is admitted to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FrontingAdmission {
    /// The takeover review and the app-use review are both bound. Only then
    /// does a bracket skip the restore after a person's own switch, and hold
    /// the restore back after a post failure that may have left a key held.
    pub app_use_fronting_admitted: bool,
}

/// A restore the bracket did not run because a key may still be held: no
/// application is brought back while a chord's modifier may be down, since
/// it would land on that application. The caller settles the held input and
/// then runs [`finish_deferred_restore`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeferredRestore {
    pub previous: u32,
    pub target: u32,
    /// When the front that is still to be undone was requested, on the
    /// host's clock; the floor for hardware input in the restore decision.
    pub front_instant_ms: u64,
}

/// What an admitted bracket did: the report, and the two facts only the
/// admitted rules produce.
#[derive(Debug, Clone, PartialEq)]
pub struct BracketOutcome {
    pub report: BracketReport,
    /// Hardware input arrived after a front, whether the previous application
    /// was then restored or the restore was skipped.
    pub person_input_during_fronting: bool,
    /// Set when the restore waits on the held input being settled. Until
    /// [`finish_deferred_restore`] runs, `report.restore` is `Failed` naming
    /// what is in front, which is what the call reports if it never does.
    pub deferred_restore: Option<DeferredRestore>,
}

/// Wait until `pid` is frontmost, for at most `budget_ms` from `since_ms`.
fn await_front<H: FrontingBracketHost>(
    host: &RefCell<&mut H>,
    pid: u32,
    since_ms: u64,
    budget_ms: u64,
) -> bool {
    loop {
        if host.borrow_mut().frontmost_pid() == Some(pid) {
            return true;
        }
        let now = host.borrow_mut().now_ms();
        if now.saturating_sub(since_ms) >= budget_ms {
            return false;
        }
        host.borrow_mut().pause_ms(FRONTING_POLL_MS);
    }
}

/// Run the bracket.
///
/// The previous application is read first, and nothing is fronted when it
/// cannot be, because it could not be put back. The idle gate and the
/// observer heartbeat run once, before anything is fronted. Each chunk then
/// fronts the target, posts units through the per-post checks, and restores
/// the previous application; the cancel signal and the observer are consulted
/// at every chunk boundary, and the observer again between units. Every stop
/// after a front still restores.
///
/// This is the bracket without app-use fronting admission; see
/// [`run_fronting_bracket_with`].
pub fn run_fronting_bracket<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    plan: BracketPlan,
    cancelled: &dyn Fn() -> bool,
) -> BracketReport {
    run_fronting_bracket_with(
        host,
        estimator,
        plan,
        FrontingAdmission::default(),
        cancelled,
    )
    .report
}

/// Run the bracket under `admission`.
///
/// Without app-use fronting admission this is exactly
/// [`run_fronting_bracket`]. With it, each chunk's restore runs the shared
/// restore decision: a restore skipped because the person switched to
/// another application ends the bracket with a stop when units remain, so
/// the target is not fronted over the person again. A post failure whose
/// held state is `Unknown` ends the bracket without any restore request and
/// hands the restore to the caller as [`BracketOutcome::deferred_restore`].
pub fn run_fronting_bracket_with<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    plan: BracketPlan,
    admission: FrontingAdmission,
    cancelled: &dyn Fn() -> bool,
) -> BracketOutcome {
    let unfronted = |report| BracketOutcome {
        report,
        person_input_during_fronting: false,
        deferred_restore: None,
    };
    let mut report = BracketReport {
        previous_frontmost: None,
        chunks: 0,
        units_posted: 0,
        posts_returned: 0,
        generation_verifications: 0,
        longest_fronted_interval_ms: 0,
        slowest_unit_ms: 0,
        slowest_restore_ms: 0,
        restore: RestoreStatus::NotNeeded,
        stop: None,
        waiting_out_slow_post: false,
    };
    let Some(previous) = host.frontmost_pid() else {
        report.stop = Some(BracketStop::PreviousUnknown);
        return unfronted(report);
    };
    report.previous_frontmost = Some(previous);

    let our_pid = host.our_pid();
    let host = RefCell::new(host);
    let mut watcher = SeizeWatcher::new(plan.maximum_seize_detection_latency_ms);
    for _ in 0..plan.units {
        watcher.queue_post();
    }
    let idle_read_at = Instant::now();
    let begun = begin_observed_sequence(
        estimator,
        &mut watcher,
        our_pid,
        idle_read_at,
        ObservedSequenceHooks {
            create_tap: || host.borrow_mut().create_tap(),
            read_idle: || host.borrow_mut().read_idle(),
            drain: |tap: &Option<H::Tap>| match tap {
                Some(tap) => host.borrow_mut().drain(tap),
                None => Vec::new(),
            },
            post_heartbeat: || host.borrow_mut().post_heartbeat(),
        },
    );
    let (tap, user_idle, probe) = match begun {
        Ok((Some(tap), user_idle, probe)) => (tap, user_idle, probe),
        Ok((None, _, _)) => {
            report.stop = Some(BracketStop::ObserverUnavailable);
            return unfronted(report);
        }
        Err(refusal) => {
            if matches!(
                refusal,
                ObservedPostRefusal::AlreadyAborted(AbortReason::UserSeizedControl)
            ) {
                estimator.clear_carry();
            }
            report.stop = Some(match watcher.abort_decision() {
                Some(abort) => BracketStop::Aborted(abort),
                None => BracketStop::ObserverUnavailable,
            });
            return unfronted(report);
        }
    };
    let heartbeat = host
        .borrow_mut()
        .observe_heartbeat(&tap, probe, &mut watcher);
    // A missed echo is a refusal before any activation, even when no input
    // event happened to give the watcher a separate abort reason.
    watcher.observe_heartbeat(super::seize::heartbeat_liveness(probe, heartbeat), 0);
    if let Some(abort) = watcher.abort_decision() {
        estimator.clear_carry();
        report.stop = Some(BracketStop::Aborted(abort));
        return unfronted(report);
    }

    let admitted = admission.app_use_fronting_admitted;
    let mut person_input = false;
    let mut deferred_restore = None;
    let bound = plan.maximum_interval_ms;
    let mut next_unit = 0;
    while next_unit < plan.units {
        if cancelled() {
            report.stop = Some(BracketStop::Cancelled);
            break;
        }
        let drained = host.borrow_mut().drain(&tap);
        observe_drained_events(&mut watcher, drained, our_pid, next_unit);
        if let Some(abort) = watcher.abort_decision() {
            report.stop = Some(BracketStop::Aborted(abort));
            break;
        }

        // Front the target. The interval is counted from the request, so the
        // time the application takes to come forward is inside the bound.
        // Checks that need no front run first, outside it.
        if let Err(failure) = host.borrow_mut().before_front() {
            report.stop = Some(BracketStop::PostFailed(failure));
            break;
        }
        let fronted_at = host.borrow_mut().now_ms();
        report.chunks += 1;
        let requested =
            plan.target_pid == previous || host.borrow_mut().request_front(plan.target_pid);
        let mut front_ok = requested;
        while front_ok {
            let drained = host.borrow_mut().drain(&tap);
            observe_drained_events(&mut watcher, drained, our_pid, next_unit);
            if cancelled() || watcher.abort_decision().is_some() {
                front_ok = false;
                break;
            }
            if host.borrow_mut().frontmost_pid() == Some(plan.target_pid) {
                break;
            }
            if host.borrow_mut().now_ms().saturating_sub(fronted_at) >= bound {
                front_ok = false;
                break;
            }
            host.borrow_mut().pause_ms(FRONTING_POLL_MS);
        }
        host.borrow_mut().front_attempt_finished();
        if !front_ok {
            report.stop = Some(if cancelled() {
                BracketStop::Cancelled
            } else {
                watcher
                    .abort_decision()
                    .map(BracketStop::Aborted)
                    .unwrap_or(BracketStop::FrontFailed)
            });
            restore(
                &host,
                &mut report,
                Chunk {
                    previous,
                    target: plan.target_pid,
                    fronted_at,
                    bound,
                    activation_observed: false,
                },
                admitted,
                &mut person_input,
            );
            break;
        }

        let front_latency = host.borrow_mut().now_ms().saturating_sub(fronted_at);
        let mut chunk_units = 0;
        let mut stop = None;
        while next_unit < plan.units {
            let now = host.borrow_mut().now_ms();
            let elapsed = now.saturating_sub(fronted_at);
            // Without a restore measurement, reserve the full restore allowance.
            // The person's app may return more slowly than the target fronts.
            // A refused first call still restores and learns its cost.
            let restore_latency = if previous == plan.target_pid {
                0
            } else {
                host.borrow_mut()
                    .measured_restore_latency_ms()
                    .unwrap_or(RESTORE_WAIT_MS)
            };
            // Until this bracket has timed a unit of its own, reserve the
            // slowest unit post the host measured recently, so a post that
            // has lately been slow is not started where it would overrun.
            let unit_cost = if report.units_posted == 0 {
                host.borrow_mut().measured_unit_post_cost_ms().unwrap_or(0)
            } else {
                report.slowest_unit_ms
            };
            let without_unit = elapsed.saturating_add(
                restore_latency
                    .max(report.slowest_restore_ms)
                    .max(front_latency),
            );
            let expected = without_unit.saturating_add(unit_cost);
            if expected > bound {
                if chunk_units == 0 {
                    stop = Some(BracketStop::BoundExceeded);
                    // Only the reserve for recent slow posts kept it from
                    // fitting, so a later retry can succeed once it ages out.
                    report.waiting_out_slow_post =
                        report.units_posted == 0 && without_unit <= bound;
                }
                break;
            }
            let index = next_unit;
            let posted = dispatch_observed_post_in_order(
                &mut watcher,
                index,
                probe,
                |_| heartbeat,
                || host.borrow_mut().frontmost_pid() == Some(plan.target_pid),
                || (),
            );
            let posted = posted.map(|_| {
                host.borrow_mut().post_observed_unit(
                    index,
                    ObservedUnit {
                        tap: &tap,
                        watcher: &mut watcher,
                        probe,
                        heartbeat,
                        cancelled,
                        deadline_ms: fronted_at.saturating_add(bound),
                    },
                )
            });
            match posted {
                Ok(Ok(unit)) => {
                    watcher.take_post_slot();
                    report.units_posted += 1;
                    report.posts_returned += unit.posts_returned;
                    report.generation_verifications += unit.generation_verifications;
                    let after = host.borrow_mut().now_ms();
                    let unit_cost = after.saturating_sub(now);
                    report.slowest_unit_ms = report.slowest_unit_ms.max(unit_cost);
                    host.borrow_mut().record_unit_post_cost_ms(unit_cost);
                    chunk_units += 1;
                    next_unit += 1;
                }
                Ok(Err(failure)) => {
                    report.posts_returned += failure.posts_returned;
                    stop = Some(BracketStop::PostFailed(failure));
                    break;
                }
                Err(_) => {
                    stop = watcher.abort_decision().map(BracketStop::Aborted);
                    if stop.is_none() {
                        stop = Some(BracketStop::ObserverUnavailable);
                    }
                    break;
                }
            }
            let drained = host.borrow_mut().drain(&tap);
            observe_drained_events(&mut watcher, drained, our_pid, next_unit);
            if let Some(abort) = watcher.abort_decision() {
                stop = Some(BracketStop::Aborted(abort));
                break;
            }
        }

        // A key may still be down after this failure. Bringing the previous
        // application back now would hand it the held modifier, so an
        // admitted bracket stops here with the target in front and leaves
        // the restore to the caller, which settles the held input first.
        if admitted
            && matches!(
                &stop,
                Some(BracketStop::PostFailed(failure))
                    if failure.held_state == HeldStateDisposition::Unknown
            )
            && previous != plan.target_pid
        {
            let now = host.borrow_mut().now_ms();
            report.longest_fronted_interval_ms = report
                .longest_fronted_interval_ms
                .max(now.saturating_sub(fronted_at));
            report.restore = RestoreStatus::Failed {
                left_in_front: host.borrow_mut().frontmost_pid(),
            };
            deferred_restore = Some(DeferredRestore {
                previous,
                target: plan.target_pid,
                front_instant_ms: fronted_at,
            });
            report.stop = stop;
            break;
        }

        let interval = restore(
            &host,
            &mut report,
            Chunk {
                previous,
                target: plan.target_pid,
                fronted_at,
                bound,
                activation_observed: true,
            },
            admitted,
            &mut person_input,
        );
        if stop.is_some() {
            report.stop = stop;
            break;
        }
        if matches!(report.restore, RestoreStatus::Failed { .. }) {
            if next_unit < plan.units {
                report.stop = Some(BracketStop::RestoreFailed);
            }
            break;
        }
        if let RestoreStatus::SkippedPerson { .. } = report.restore {
            // The person switched to another application while the target
            // was in front and was left there. Fronting the target again for
            // the next chunk would pull them back out of it, so the bracket
            // stops as it does for any input that is not ours.
            if next_unit < plan.units {
                report.stop = Some(BracketStop::Aborted(AbortDecision {
                    reason: AbortReason::UserSeizedControl,
                    stopped_action_index: next_unit,
                    detection_latency_ms: None,
                    platform_delivery_latency_ms: None,
                    sourced_input_kind: Some(SourcedInputKind::Hardware),
                    maximum_detection_latency_ms: plan.maximum_seize_detection_latency_ms,
                    queued_posts_cancelled: u32::try_from(plan.units - next_unit)
                        .unwrap_or(u32::MAX),
                }));
            }
            break;
        }
        if interval > bound {
            // Past the bound with units still to post: stop, so the target is
            // not fronted again. Once every unit is posted the keystrokes have
            // landed, and the overrun is reported through the interval rather
            // than as a stop, which would refuse an action that took effect.
            if next_unit < plan.units {
                report.stop = Some(BracketStop::BoundExceeded);
            }
            break;
        }
    }

    match &report.stop {
        Some(BracketStop::Aborted(abort))
            if matches!(abort.reason, AbortReason::UserSeizedControl) =>
        {
            estimator.clear_carry();
        }
        _ => {}
    }
    host.borrow_mut()
        .finish_observation(&tap, estimator, user_idle, idle_read_at);
    BracketOutcome {
        report,
        person_input_during_fronting: person_input,
        deferred_restore,
    }
}

/// Finish a restore an admitted bracket deferred because a key may have been
/// held. `released` says whether settling the held input confirmed every
/// release. When it did, the restore decision runs as at any other chunk
/// end, waiting at most `wait_ms`. When it did not, nothing is requested,
/// since the previous application would receive the held key, and the
/// restore is reported failed, naming what is in front.
pub fn finish_deferred_restore<H: FrontingBracketHost>(
    host: &mut H,
    outcome: &mut BracketOutcome,
    released: bool,
    wait_ms: u64,
) {
    let Some(deferred) = outcome.deferred_restore.take() else {
        return;
    };
    if !released {
        outcome.report.restore = RestoreStatus::Failed {
            left_in_front: host.frontmost_pid(),
        };
        return;
    }
    let restore_at = host.now_ms();
    let restored = restore_after_front(
        host,
        deferred.previous,
        deferred.target,
        deferred.front_instant_ms,
        wait_ms,
    );
    remember_restore(
        host,
        restored.restore,
        restored.finished_at_ms.saturating_sub(restore_at),
    );
    outcome.person_input_during_fronting |= restored.person_input_during_fronting;
    outcome.report.longest_fronted_interval_ms = outcome.report.longest_fronted_interval_ms.max(
        restored
            .finished_at_ms
            .saturating_sub(deferred.front_instant_ms),
    );
    outcome.report.restore = restored.restore;
}

/// Use the observed bracket for one read, without posting a key or pointer event.
/// The observer heartbeat, idle gate, bound and restore are identical to keys.
pub fn run_fronting_read<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    plan: BracketPlan,
    cancelled: &dyn Fn() -> bool,
    read: &mut dyn FnMut(),
) -> BracketReport {
    run_fronting_read_with(
        host,
        estimator,
        plan,
        FrontingAdmission::default(),
        cancelled,
        read,
    )
    .report
}

/// [`run_fronting_read`] under `admission`, with the same restore decision
/// as [`run_fronting_bracket_with`].
pub fn run_fronting_read_with<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    mut plan: BracketPlan,
    admission: FrontingAdmission,
    cancelled: &dyn Fn() -> bool,
    read: &mut dyn FnMut(),
) -> BracketOutcome {
    struct ReadingHost<'a, H> {
        host: &'a mut H,
        read: &'a mut dyn FnMut(),
    }
    impl<H: FrontingBracketHost> FrontingBracketHost for ReadingHost<'_, H> {
        type Tap = H::Tap;
        fn now_ms(&mut self) -> u64 {
            self.host.now_ms()
        }
        fn pause_ms(&mut self, ms: u64) {
            self.host.pause_ms(ms);
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            self.host.frontmost_pid()
        }
        fn request_front(&mut self, pid: u32) -> bool {
            self.host.request_front(pid)
        }
        fn request_front_fallback(&mut self, pid: u32) -> bool {
            self.host.request_front_fallback(pid)
        }
        fn front_attempt_finished(&mut self) {
            self.host.front_attempt_finished();
        }
        fn restore_front_attempt(
            &mut self,
            previous: u32,
            target: u32,
            since: u64,
            wait_ms: u64,
            activation_observed: bool,
        ) -> RestoreOutcome {
            self.host
                .restore_front_attempt(previous, target, since, wait_ms, activation_observed)
        }
        fn measured_restore_latency_ms(&mut self) -> Option<u64> {
            self.host.measured_restore_latency_ms()
        }
        fn record_restore_latency_ms(&mut self, milliseconds: u64) {
            self.host.record_restore_latency_ms(milliseconds);
        }
        fn our_pid(&self) -> i64 {
            self.host.our_pid()
        }
        fn create_tap(&mut self) -> Option<Self::Tap> {
            self.host.create_tap()
        }
        fn read_idle(&mut self) -> IdleReading {
            self.host.read_idle()
        }
        fn drain(&mut self, tap: &Self::Tap) -> Vec<SourcedInputEvent> {
            self.host.drain(tap)
        }
        fn post_heartbeat(&mut self) -> HeartbeatProbe {
            self.host.post_heartbeat()
        }
        fn observe_heartbeat(
            &mut self,
            tap: &Self::Tap,
            probe: HeartbeatProbe,
            watcher: &mut SeizeWatcher,
        ) -> HeartbeatObservation {
            self.host.observe_heartbeat(tap, probe, watcher)
        }
        fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
            (self.read)();
            Ok(UnitPosted::default())
        }
        // Forwarded, not left to the default: the default reports no input,
        // which would restore over a person's own switch.
        fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
            self.host.hardware_input_snapshot()
        }
    }
    plan.units = 1;
    run_fronting_bracket_with(
        &mut ReadingHost { host, read },
        estimator,
        plan,
        admission,
        cancelled,
    )
}

/// One chunk's front, as its restore needs it.
struct Chunk {
    previous: u32,
    target: u32,
    fronted_at: u64,
    bound: u64,
    activation_observed: bool,
}

/// Put the previous application back and record how long the target was in
/// front. Returns that interval.
///
/// When `admitted`, the shared restore decision runs first and may leave the
/// person in an application they switched to; hardware input seen since the
/// front is recorded in `person_input` either way.
fn restore<H: FrontingBracketHost>(
    host: &RefCell<&mut H>,
    report: &mut BracketReport,
    chunk: Chunk,
    admitted: bool,
    person_input: &mut bool,
) -> u64 {
    let Chunk {
        previous,
        target,
        fronted_at,
        bound,
        activation_observed,
    } = chunk;
    if previous == target {
        report.restore = RestoreStatus::NotNeeded;
        let now = host.borrow_mut().now_ms();
        let interval = now.saturating_sub(fronted_at);
        report.longest_fronted_interval_ms = report.longest_fronted_interval_ms.max(interval);
        return interval;
    }
    let restore_at = host.borrow_mut().now_ms();
    if admitted || !activation_observed {
        let outcome = host.borrow_mut().restore_front_attempt(
            previous,
            target,
            fronted_at,
            bound,
            activation_observed,
        );
        *person_input |= outcome.person_input_during_fronting;
        if !matches!(outcome.restore, RestoreStatus::SkippedPerson { .. }) {
            report.slowest_restore_ms = report
                .slowest_restore_ms
                .max(outcome.finished_at_ms.saturating_sub(restore_at));
        }
        remember_restore(
            *host.borrow_mut(),
            outcome.restore,
            outcome.finished_at_ms.saturating_sub(restore_at),
        );
        let interval = outcome.finished_at_ms.saturating_sub(fronted_at);
        report.longest_fronted_interval_ms = report.longest_fronted_interval_ms.max(interval);
        report.restore = outcome.restore;
        return interval;
    }
    // A failed request is not given up on at once: the previous application
    // being left behind the target is the failure this exists to prevent, so
    // the whole bound is spent trying before it is reported.
    let _ = host.borrow_mut().request_front(previous);
    let restored = await_front(host, previous, restore_at, bound);
    let now = host.borrow_mut().now_ms();
    report.slowest_restore_ms = report
        .slowest_restore_ms
        .max(now.saturating_sub(restore_at));
    let interval = now.saturating_sub(fronted_at);
    report.longest_fronted_interval_ms = report.longest_fronted_interval_ms.max(interval);
    report.restore = if restored {
        RestoreStatus::Restored
    } else {
        RestoreStatus::Failed {
            left_in_front: host.borrow_mut().frontmost_pid(),
        }
    };
    remember_restore(
        *host.borrow_mut(),
        report.restore,
        now.saturating_sub(restore_at),
    );
    interval
}

/// A failed wait is only a lower bound on restore cost, not evidence of a
/// fast restore. Reserve at least the normal cleanup allowance after one.
fn remember_restore<H: FrontingBracketHost>(host: &mut H, status: RestoreStatus, elapsed: u64) {
    match status {
        RestoreStatus::Restored => host.record_restore_latency_ms(elapsed),
        RestoreStatus::Failed { .. } => {
            host.record_restore_latency_ms(elapsed.max(RESTORE_WAIT_MS));
        }
        RestoreStatus::NotNeeded | RestoreStatus::SkippedPerson { .. } => {}
    }
}

#[cfg(test)]
mod tests;
