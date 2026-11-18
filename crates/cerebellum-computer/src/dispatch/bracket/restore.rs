//! The one restore decision every temporary front ends with, and the state of
//! a front attempt that cleanup may race.
//!
//! After this module fronts an application for a moment, the previous
//! application is put back only with continuous observation and a readable
//! frontmost application. Unknown coverage leaves focus alone. Every caller decides with
//! [`decide_restore`] on the same evidence, the process-wide hardware input
//! snapshot floored at the front instant, so a worker and the terminal
//! cleanup that may race it cannot disagree.
//!
//! Nothing here touches a platform: the evidence is handed in, and the
//! requests go through [`FrontingBracketHost`], so every rule is tested on
//! every host with a fake clock.

use super::{FrontingBracketHost, RestoreStatus, FRONTING_POLL_MS};

/// How long a restore waits for the previous application to come back to the
/// front, in milliseconds, counted from the restore request.
pub const RESTORE_WAIT_MS: u64 = 300;

/// How long a restore waits for its first request to take effect before it
/// also asks the second way ([`FrontingBracketHost::request_front_fallback`]),
/// in milliseconds from the request. Fronts made by the first route have been
/// seen to land within about 140 ms on a desk, so a request still without
/// effect after this long is unlikely to land at all.
pub const RESTORE_FALLBACK_AFTER_MS: u64 = 150;
/// The hardware input the session observer has seen, on the clock of the host
/// that reports it.
///
/// It holds only timestamps of key, button and scroll input, never their
/// content and never which application they went to. A switch made with a
/// trackpad gesture alone (a Space swipe, Mission Control) is not in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareInputSnapshot {
    /// The observer has watched without a gap since this instant.
    pub coverage_start_ms: u64,
    /// The newest hardware input it saw, when it saw any. Input this module
    /// posted itself is not counted.
    pub last_input_ms: Option<u64>,
}

impl HardwareInputSnapshot {
    /// The observer's own readings, when its gap-free coverage began and its
    /// newest hardware input, put on a host clock that counts milliseconds
    /// from `origin`. An instant before `origin` reads as 0: the observer is
    /// process-wide and usually began long before the host, and an input that
    /// old is before any front the host makes, so it cannot read as input
    /// since that front.
    pub fn from_instants(
        origin: std::time::Instant,
        coverage_start: std::time::Instant,
        last_input: Option<std::time::Instant>,
    ) -> Self {
        let millis = |at: std::time::Instant| {
            u64::try_from(at.saturating_duration_since(origin).as_millis()).unwrap_or(u64::MAX)
        };
        Self {
            // Round coverage up: rounding down could hide a gap that began
            // just after the front within the same millisecond bucket.
            coverage_start_ms: u64::try_from(
                coverage_start
                    .saturating_duration_since(origin)
                    .as_nanos()
                    .div_ceil(1_000_000),
            )
            .unwrap_or(u64::MAX),
            last_input_ms: last_input.map(millis),
        }
    }
}

/// Whether input may have arrived since the front. Equality is conservative:
/// millisecond truncation cannot order two events in the same bucket. Unknown
/// coverage is not evidence of inactivity.
pub fn hardware_input_since(
    snapshot: Option<HardwareInputSnapshot>,
    front_instant_ms: u64,
) -> bool {
    match snapshot {
        Some(snapshot) if snapshot.coverage_start_ms <= front_instant_ms => snapshot
            .last_input_ms
            .is_some_and(|last| last >= front_instant_ms),
        _ => true,
    }
}

fn observed_input_since(snapshot: Option<HardwareInputSnapshot>, since_ms: u64) -> bool {
    snapshot
        .and_then(|snapshot| snapshot.last_input_ms)
        .is_some_and(|last| last >= since_ms)
}

fn covers(snapshot: Option<HardwareInputSnapshot>, since_ms: u64) -> bool {
    snapshot.is_some_and(|snapshot| snapshot.coverage_start_ms <= since_ms)
}

/// What to do about the previous application once a temporary front ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestoreDecision {
    /// Ask for the previous application back. `person_input_during_fronting`
    /// says hardware input arrived since the front, which the reply discloses.
    Restore { person_input_during_fronting: bool },
    /// Leave the front alone: the person switched to `now_front` themselves.
    SkipPerson { now_front: Option<u32> },
}

/// The restore decision.
///
/// An unreadable frontmost or a third application leaves focus alone. A virtual
/// desktop gesture may switch applications without a key/button/scroll event, so lack
/// of that evidence cannot attribute the switch to the module.
pub fn decide_restore(
    previous: u32,
    target: u32,
    frontmost: Option<u32>,
    input_since_front: bool,
) -> RestoreDecision {
    match frontmost {
        Some(now_front) if now_front != target && now_front != previous => {
            RestoreDecision::SkipPerson {
                now_front: Some(now_front),
            }
        }
        None => RestoreDecision::SkipPerson { now_front: None },
        _ => RestoreDecision::Restore {
            person_input_during_fronting: input_since_front,
        },
    }
}

/// What one run of the restore decision did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreOutcome {
    pub restore: RestoreStatus,
    /// Hardware input arrived after the front, whether or not it led to a
    /// skipped restore.
    pub person_input_during_fronting: bool,
    /// The decision could not establish continuous observation from the front.
    pub input_coverage_unavailable: bool,
    /// When the previous application was seen back in front, or the decision
    /// otherwise finished, on the host's clock.
    pub finished_at_ms: u64,
    /// How long this restore took, from the start of the decision that ran
    /// it to `finished_at_ms`, as timed by whoever ran that decision. `None`
    /// when the caller did not run it itself, for instance when it awaited
    /// a decision another thread had already made: its own wait says
    /// nothing about what the restore cost, so it is no timing sample.
    pub restore_ms: Option<u64>,
}

/// Run the restore decision against `host` and carry it out: read the
/// frontmost application and the hardware input snapshot, then either leave
/// the person where they went or request the previous application and wait
/// at most `wait_ms` for it.
///
/// `previous == target` means nothing was fronted, so nothing is requested.
pub fn restore_after_front<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    target: u32,
    front_instant_ms: u64,
    wait_ms: u64,
) -> RestoreOutcome {
    restore_after_front_attempt(host, previous, target, front_instant_ms, wait_ms, true)
}

/// Settle a requested activation before declaring restoration confirmed.
/// An elapsed fronting wait does not cancel the operating system's request.
/// Until the target has actually been observed, seeing the previous app is
/// not evidence that the target cannot still arrive. The watch never posts
/// input, and consumes the same allowance as the subsequent restore.
pub fn restore_after_front_attempt<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    target: u32,
    front_instant_ms: u64,
    wait_ms: u64,
    activation_observed: bool,
) -> RestoreOutcome {
    restore_attempt(
        host,
        previous,
        target,
        front_instant_ms,
        wait_ms,
        activation_observed,
        !activation_observed,
    )
}

fn restore_attempt<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    target: u32,
    front_instant_ms: u64,
    wait_ms: u64,
    activation_observed: bool,
    require_quiet: bool,
) -> RestoreOutcome {
    let started = host.now_ms();
    let mut outcome = untimed_restore_attempt(
        host,
        previous,
        target,
        front_instant_ms,
        wait_ms,
        activation_observed,
        require_quiet,
    );
    outcome.restore_ms = Some(outcome.finished_at_ms.saturating_sub(started));
    outcome
}

fn untimed_restore_attempt<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    target: u32,
    front_instant_ms: u64,
    wait_ms: u64,
    activation_observed: bool,
    require_quiet: bool,
) -> RestoreOutcome {
    let started = host.now_ms();
    if previous != target && !activation_observed {
        loop {
            let frontmost = host.frontmost_pid();
            let snapshot = host.hardware_input_snapshot();
            let input = observed_input_since(snapshot, front_instant_ms);
            let input_coverage_unavailable = !covers(snapshot, front_instant_ms);
            if frontmost == Some(target) {
                let latency = host.now_ms().saturating_sub(front_instant_ms);
                host.late_activation_observed(latency);
            }
            if require_quiet && input {
                return RestoreOutcome {
                    restore: RestoreStatus::SkippedPerson {
                        now_front: frontmost,
                    },
                    person_input_during_fronting: true,
                    input_coverage_unavailable,
                    finished_at_ms: host.now_ms(),
                    restore_ms: None,
                };
            }
            if frontmost == Some(target) {
                break;
            }
            if input_coverage_unavailable || frontmost != Some(previous) {
                return RestoreOutcome {
                    restore: RestoreStatus::SkippedPerson {
                        now_front: frontmost,
                    },
                    person_input_during_fronting: input,
                    input_coverage_unavailable,
                    finished_at_ms: host.now_ms(),
                    restore_ms: None,
                };
            }
            if host.now_ms().saturating_sub(started) >= wait_ms {
                return RestoreOutcome {
                    restore: RestoreStatus::Failed {
                        left_in_front: frontmost,
                    },
                    person_input_during_fronting: input,
                    input_coverage_unavailable: false,
                    finished_at_ms: host.now_ms(),
                    restore_ms: None,
                };
            }
            host.pause_ms(FRONTING_POLL_MS);
        }
    }
    let wait_ms = wait_ms.saturating_sub(host.now_ms().saturating_sub(started));
    if previous == target {
        return RestoreOutcome {
            restore: RestoreStatus::NotNeeded,
            person_input_during_fronting: false,
            input_coverage_unavailable: false,
            finished_at_ms: host.now_ms(),
            restore_ms: None,
        };
    }
    let first_front = host.frontmost_pid();
    let first_snapshot = host.hardware_input_snapshot();
    let requested_at = host.now_ms();
    // Revalidate immediately before requesting the previous application. These
    // reads shrink the race; they are not atomic with WindowServer activation.
    let snapshot = host.hardware_input_snapshot();
    let frontmost = host.frontmost_pid();
    // Disclose only observed input. Unknown coverage independently skips the
    // restore below; it must not be reported as a person event that was seen.
    let input = observed_input_since(snapshot, front_instant_ms);
    let input_coverage_unavailable =
        !covers(first_snapshot, front_instant_ms) || !covers(snapshot, front_instant_ms);
    if input_coverage_unavailable
        || (require_quiet && input)
        || first_front != frontmost
        || first_snapshot != snapshot
    {
        return RestoreOutcome {
            restore: RestoreStatus::SkippedPerson {
                now_front: frontmost,
            },
            person_input_during_fronting: input,
            input_coverage_unavailable,
            finished_at_ms: host.now_ms(),
            restore_ms: None,
        };
    }
    match decide_restore(previous, target, frontmost, input) {
        RestoreDecision::SkipPerson { now_front } => RestoreOutcome {
            restore: RestoreStatus::SkippedPerson { now_front },
            person_input_during_fronting: input,
            input_coverage_unavailable: false,
            finished_at_ms: host.now_ms(),
            restore_ms: None,
        },
        RestoreDecision::Restore {
            person_input_during_fronting,
        } => {
            let restore = request_restore(
                host,
                RestoreRequest {
                    previous,
                    target,
                    front_instant_ms,
                    require_quiet,
                },
                requested_at,
                wait_ms,
            );
            RestoreOutcome {
                restore,
                person_input_during_fronting,
                input_coverage_unavailable: false,
                finished_at_ms: host.now_ms(),
                restore_ms: None,
            }
        }
    }
}

/// Observation-only cleanup for an activation the call did not see through:
/// one that was still pending at reply time, or one that landed after the
/// action gave up. It never dispatches the action that timed out.
///
/// It watches until `watch_ms` after `requested_at`, the front request.
/// With [`LateWatch::WholeWindow`], whenever the target is in front and no
/// person input has arrived since the front, it asks for the previous
/// application back, both ways (as `request_restore` does), and asks again
/// after any request that did not take effect. After a restore it keeps
/// watching, so an activation that lands a second time is put back too.
/// With [`LateWatch::FirstAttempt`] it makes at most one restore attempt and
/// returns as soon as that attempt ends, or at once when the target is not
/// in front, so a caller that must end quickly is held for one restore wait
/// at most.
///
/// It stops at the first person input or gap in observer coverage. Both
/// leave focus alone, but a gap is not an observed person event. If the
/// previous application was already back, input there does not change the
/// restore result. The watch also stops when a third application comes to
/// the front or the front cannot be read, on `stop`, and at the window's end.
///
/// Returns the restore status as the watch ended, the latency of the first
/// landing it saw, and whether person input arrived while the target could
/// still be in front. [`watch_late_activation_ending`] also says why it
/// stopped.
pub fn watch_late_activation<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    target: u32,
    requested_at: u64,
    watch_ms: u64,
    watch: LateWatch,
    stop: &dyn Fn() -> bool,
) -> (RestoreStatus, Option<u64>, bool) {
    let ended =
        watch_late_activation_ending(host, previous, target, requested_at, watch_ms, watch, stop);
    (ended.restore, ended.first_landing_ms, ended.person_input)
}

/// How a late watch ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LateWatchEnd {
    pub restore: RestoreStatus,
    /// The latency of the first landing the watch saw.
    pub first_landing_ms: Option<u64>,
    /// Person input arrived while the target could still be in front.
    pub person_input: bool,
    /// The watch left focus alone because the input observer could not show
    /// gap-free coverage since the front, not because of person input or a
    /// third application. A restore status of `SkippedPerson` alone does not
    /// tell these apart. The observer counts each such gap in its own health
    /// (`hardwareInputObserver.coverage_gap_count`), or reports itself not
    /// running when it never covered the front.
    pub coverage_lost: bool,
}

/// [`watch_late_activation`], saying also why the watch stopped.
pub fn watch_late_activation_ending<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    target: u32,
    requested_at: u64,
    watch_ms: u64,
    watch: LateWatch,
    stop: &dyn Fn() -> bool,
) -> LateWatchEnd {
    let end = requested_at.saturating_add(watch_ms);
    let mut first_landing = None;
    let mut target_was_front = false;
    let mut restored = matches!(
        watch,
        LateWatch::WholeWindow {
            already_restored: true
        }
    );
    let first_attempt_only = watch == LateWatch::FirstAttempt;
    loop {
        let front = host.frontmost_pid();
        let snapshot = host.hardware_input_snapshot();
        let input = observed_input_since(snapshot, requested_at);
        let now = host.now_ms();
        let target_front = front == Some(target);
        if target_front {
            restored = false;
            // Reported once per landing, not once per poll while it stays.
            if !target_was_front {
                let latency = now.saturating_sub(requested_at);
                host.late_activation_observed(latency);
                first_landing.get_or_insert(latency);
            }
        }
        target_was_front = target_front;
        let ending = |restore, person_input, coverage_lost| LateWatchEnd {
            restore,
            first_landing_ms: first_landing,
            person_input,
            coverage_lost,
        };
        if input || !covers(snapshot, requested_at) {
            if restored {
                return ending(RestoreStatus::Restored, false, false);
            }
            return ending(
                RestoreStatus::SkippedPerson { now_front: front },
                input,
                !input,
            );
        }
        let settled = || {
            if restored {
                RestoreStatus::Restored
            } else {
                RestoreStatus::Failed {
                    left_in_front: front,
                }
            }
        };
        if stop() || now >= end || (first_attempt_only && front == Some(previous)) {
            return ending(settled(), false, false);
        }
        if target_front {
            let result = restore_attempt(
                host,
                previous,
                target,
                requested_at,
                RESTORE_WAIT_MS.min(end.saturating_sub(now)),
                true,
                true,
            );
            if first_attempt_only {
                let coverage_lost = result.input_coverage_unavailable
                    && !result.person_input_during_fronting
                    && matches!(result.restore, RestoreStatus::SkippedPerson { .. });
                return ending(
                    result.restore,
                    result.person_input_during_fronting,
                    coverage_lost,
                );
            }
            match result.restore {
                RestoreStatus::Restored => {
                    restored = true;
                    target_was_front = false;
                }
                RestoreStatus::SkippedPerson { .. } if result.person_input_during_fronting => {
                    return ending(result.restore, true, false);
                }
                // Not back yet, or a reading changed under the decision:
                // look again, and ask again while the window lasts.
                _ => host.pause_ms(FRONTING_POLL_MS),
            }
            continue;
        }
        if front != Some(previous) {
            let restore = if restored {
                RestoreStatus::Restored
            } else {
                RestoreStatus::SkippedPerson { now_front: front }
            };
            return ending(restore, false, false);
        }
        host.pause_ms(10);
    }
}

/// How long a late watch goes on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateWatch {
    /// The ordinary late watch: to the end of its window, putting the
    /// previous application back after every landing. `already_restored`
    /// says the call itself already put back a landing it did not see
    /// through, so the watch starts with the previous application back.
    WholeWindow { already_restored: bool },
    /// One restore attempt for a target already in front, for a caller that
    /// is shutting down and must not wait out the window.
    FirstAttempt,
}

/// What a restore request puts back, and the evidence that must still hold
/// before it asks the second way.
pub(super) struct RestoreRequest {
    pub(super) previous: u32,
    pub(super) target: u32,
    /// When the front was requested: the floor for person input.
    pub(super) front_instant_ms: u64,
    /// Person input since the front forbids the second request.
    pub(super) require_quiet: bool,
}

/// Request the previous application back and wait at most `wait_ms` from
/// `requested_at_ms` for it: `Restored`, or `Failed` naming what is in front.
///
/// A refused first request asks the host's second route at once; an accepted
/// request gets [`RESTORE_FALLBACK_AFTER_MS`] to take effect first. Either
/// way, the second route is asked only while the target is still the
/// application in front, the input observer has watched without a gap since
/// the front, and, when `require_quiet`, no person input has arrived since it.
pub(super) fn request_restore<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    request: RestoreRequest,
    requested_at_ms: u64,
    wait_ms: u64,
) -> RestoreStatus {
    let previous = request.previous;
    let first_accepted = host.request_front(previous);
    let first_wait = if first_accepted {
        RESTORE_FALLBACK_AFTER_MS.min(wait_ms)
    } else {
        0
    };
    if wait_for_front(host, previous, requested_at_ms, first_wait) {
        return RestoreStatus::Restored;
    }
    if first_wait < wait_ms {
        let target_in_front = host.frontmost_pid() == Some(request.target);
        let snapshot = host.hardware_input_snapshot();
        let covered =
            snapshot.is_some_and(|snapshot| snapshot.coverage_start_ms <= request.front_instant_ms);
        let input = hardware_input_since(snapshot, request.front_instant_ms);
        if target_in_front && covered && !(request.require_quiet && input) {
            let _ = host.request_front_fallback(previous);
        }
    }
    if wait_for_front(host, previous, requested_at_ms, wait_ms) {
        RestoreStatus::Restored
    } else {
        RestoreStatus::Failed {
            left_in_front: host.frontmost_pid(),
        }
    }
}

/// Wait until `pid` is frontmost, for at most `budget_ms` from `since_ms`.
pub(super) fn wait_for_front<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    pid: u32,
    since_ms: u64,
    budget_ms: u64,
) -> bool {
    loop {
        if host.frontmost_pid() == Some(pid) {
            return true;
        }
        if host.now_ms().saturating_sub(since_ms) >= budget_ms {
            return false;
        }
        host.pause_ms(FRONTING_POLL_MS);
    }
}

/// Where one front attempt is, as the restore obligation records it.
///
/// It moves only forward, `NotStarted` to `Dispatching` to `Dispatched`, and
/// only under the obligation's own lock, so the worker that fronts and the
/// cleanup that may end the call early always agree on whether a front can
/// have happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrontAttemptState {
    /// No front has been requested, and none will be once cleanup has taken
    /// the obligation.
    NotStarted,
    /// The front request is being made and waited for. The instant is when
    /// it was made, and is the floor for hardware input afterwards.
    Dispatching { front_instant_ms: u64 },
    /// The front attempt returned, whether or not the target came forward.
    Dispatched { front_instant_ms: u64 },
}

/// What cleanup must do with the obligation it has just taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupTake {
    /// Taken before any front: the worker will not front, the restore is
    /// `not_needed`, and the fronting lock can be released.
    PreventedFront,
    /// A front attempt is in flight: wait for it to return (at most the
    /// front wait), then run the restore decision.
    AwaitFrontAttempt,
    /// The front was requested at this instant: run the restore decision with
    /// it as the floor.
    Decide { front_instant_ms: u64 },
    /// The other side took the obligation first; await its decision instead
    /// of running a second one.
    AlreadyTaken,
}

/// The front-attempt half of a restore obligation: the state, and whether
/// cleanup has taken it. Whichever of the worker's own cleanup or the
/// terminal cleanup calls [`FrontAttempt::take`] first runs the restore
/// decision; the other gets [`CleanupTake::AlreadyTaken`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontAttempt {
    state: FrontAttemptState,
    taken: bool,
}

impl Default for FrontAttempt {
    fn default() -> Self {
        Self::new()
    }
}

impl FrontAttempt {
    pub const fn new() -> Self {
        Self {
            state: FrontAttemptState::NotStarted,
            taken: false,
        }
    }

    pub fn state(&self) -> FrontAttemptState {
        self.state
    }

    /// Whether cleanup has taken the obligation.
    pub fn taken(&self) -> bool {
        self.taken
    }

    /// The worker is about to request the front at `front_instant_ms`.
    /// `false` means cleanup took the obligation first, or a front was
    /// already attempted, and the worker must not front.
    pub fn begin_dispatch(&mut self, front_instant_ms: u64) -> bool {
        if self.taken || self.state != FrontAttemptState::NotStarted {
            return false;
        }
        self.state = FrontAttemptState::Dispatching { front_instant_ms };
        true
    }

    /// The front request and its wait returned. Recorded even when cleanup
    /// took the obligation meanwhile, because that cleanup is waiting for it.
    pub fn attempt_returned(&mut self) {
        if let FrontAttemptState::Dispatching { front_instant_ms } = self.state {
            self.state = FrontAttemptState::Dispatched { front_instant_ms };
        }
    }

    /// Take the obligation for cleanup.
    pub fn take(&mut self) -> CleanupTake {
        if self.taken {
            return CleanupTake::AlreadyTaken;
        }
        self.taken = true;
        match self.state {
            FrontAttemptState::NotStarted => CleanupTake::PreventedFront,
            FrontAttemptState::Dispatching { .. } => CleanupTake::AwaitFrontAttempt,
            FrontAttemptState::Dispatched { front_instant_ms } => {
                CleanupTake::Decide { front_instant_ms }
            }
        }
    }

    /// The floor for the restore decision once the attempt has returned:
    /// `None` while it is still in flight or when no front was requested.
    pub fn decision_floor(&self) -> Option<u64> {
        match self.state {
            FrontAttemptState::Dispatched { front_instant_ms } => Some(front_instant_ms),
            FrontAttemptState::NotStarted | FrontAttemptState::Dispatching { .. } => None,
        }
    }
}
