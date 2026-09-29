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

use std::cell::RefCell;
use std::time::Instant;

use serde::{Deserialize, Serialize};

use super::seize::{
    begin_observed_sequence, dispatch_observed_post_in_order, observe_drained_events,
    AbortDecision, AbortReason, HeartbeatObservation, HeartbeatProbe, ObservedPostRefusal,
    ObservedSequenceHooks, SeizeWatcher, SourcedInputEvent, UserIdleEstimator,
};
use crate::platform::{IdleReading, SequencePostFailure};

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

/// The platform a bracket runs on.
///
/// A unit is the smallest run of events that must not be split across a
/// restore: one character of typed text, or one whole key chord, whose
/// modifiers must never stay held while another application is in front.
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
    /// Our own pid as input sources carry it.
    fn our_pid(&self) -> i64;
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
}

impl BracketReport {
    /// Whether every unit was posted inside the bound and the previous
    /// application is back.
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
pub fn run_fronting_bracket<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    plan: BracketPlan,
    cancelled: &dyn Fn() -> bool,
) -> BracketReport {
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
    };
    let Some(previous) = host.frontmost_pid() else {
        report.stop = Some(BracketStop::PreviousUnknown);
        return report;
    };
    report.previous_frontmost = Some(previous);

    let our_pid = host.our_pid();
    let host = RefCell::new(host);
    let mut watcher = SeizeWatcher::new(plan.maximum_seize_detection_latency_ms);
    for _ in 0..plan.units {
        watcher.queue_post();
    }
    let begun = begin_observed_sequence(
        estimator,
        &mut watcher,
        our_pid,
        Instant::now(),
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
    let (tap, probe) = match begun {
        Ok((Some(tap), _user_idle, probe)) => (tap, probe),
        Ok((None, _, _)) => {
            report.stop = Some(BracketStop::ObserverUnavailable);
            return report;
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
            return report;
        }
    };
    let heartbeat = host
        .borrow_mut()
        .observe_heartbeat(&tap, probe, &mut watcher);
    if let Some(abort) = watcher.abort_decision() {
        estimator.clear_carry();
        report.stop = Some(BracketStop::Aborted(abort));
        return report;
    }

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
        let fronted_at = host.borrow_mut().now_ms();
        report.chunks += 1;
        let requested =
            plan.target_pid == previous || host.borrow_mut().request_front(plan.target_pid);
        if !requested || !await_front(&host, plan.target_pid, fronted_at, bound) {
            report.stop = Some(BracketStop::FrontFailed);
            restore(
                &host,
                &mut report,
                previous,
                plan.target_pid,
                fronted_at,
                bound,
            );
            break;
        }

        // Before any restore has been timed, coming forward is the best
        // guide to how long going back will take.
        let front_latency = host.borrow_mut().now_ms().saturating_sub(fronted_at);
        let mut chunk_units = 0;
        let mut stop = None;
        while next_unit < plan.units {
            let now = host.borrow_mut().now_ms();
            let elapsed = now.saturating_sub(fronted_at);
            // What the next unit and the restore after it are expected to
            // cost, from the slowest of each seen so far.
            let expected =
                elapsed + report.slowest_unit_ms + report.slowest_restore_ms.max(front_latency);
            if expected > bound {
                if chunk_units == 0 {
                    stop = Some(BracketStop::BoundExceeded);
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
                || host.borrow_mut().post_unit(index),
            );
            match posted {
                Ok(Ok(unit)) => {
                    watcher.take_post_slot();
                    report.units_posted += 1;
                    report.posts_returned += unit.posts_returned;
                    report.generation_verifications += unit.generation_verifications;
                    let after = host.borrow_mut().now_ms();
                    report.slowest_unit_ms = report.slowest_unit_ms.max(after.saturating_sub(now));
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

        let interval = restore(
            &host,
            &mut report,
            previous,
            plan.target_pid,
            fronted_at,
            bound,
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
    report
}

/// Put the previous application back and record how long the target was in
/// front. Returns that interval.
fn restore<H: FrontingBracketHost>(
    host: &RefCell<&mut H>,
    report: &mut BracketReport,
    previous: u32,
    target: u32,
    fronted_at: u64,
    bound: u64,
) -> u64 {
    if previous == target {
        report.restore = RestoreStatus::NotNeeded;
        let now = host.borrow_mut().now_ms();
        return now.saturating_sub(fronted_at);
    }
    let restore_at = host.borrow_mut().now_ms();
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
    interval
}

#[cfg(test)]
mod tests;
