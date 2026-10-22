//! The one restore decision every temporary front ends with, and the state of
//! a front attempt that cleanup may race.
//!
//! After this module fronts an application for a moment, the previous
//! application is put back, with one exception: when another application is
//! now frontmost and the person touched a key, a button or the scroll wheel
//! since the front, the person went somewhere on purpose, and dragging them
//! back would undo their own switch. Every caller decides with
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
            coverage_start_ms: millis(coverage_start),
            last_input_ms: last_input.map(millis),
        }
    }
}

/// Whether hardware input arrived strictly after `front_instant_ms`.
///
/// An unavailable snapshot, or one whose coverage began after the front,
/// cannot say what happened in between, and counts as no input seen. That
/// keeps the default the restore, which is what happened before this decision
/// existed.
pub fn hardware_input_since(
    snapshot: Option<HardwareInputSnapshot>,
    front_instant_ms: u64,
) -> bool {
    match snapshot {
        Some(snapshot) if snapshot.coverage_start_ms <= front_instant_ms => snapshot
            .last_input_ms
            .is_some_and(|last| last > front_instant_ms),
        _ => false,
    }
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
/// The restore is skipped only when an application that is neither the
/// target nor the previous one is frontmost AND hardware input was seen since
/// the front. A switch with no hardware input, such as a pressed link opening
/// the browser, was caused by the action itself, so the previous application
/// is still restored. An unreadable frontmost application is not known to be
/// another one, so it restores too.
pub fn decide_restore(
    previous: u32,
    target: u32,
    frontmost: Option<u32>,
    input_since_front: bool,
) -> RestoreDecision {
    match frontmost {
        Some(now_front) if input_since_front && now_front != target && now_front != previous => {
            RestoreDecision::SkipPerson {
                now_front: Some(now_front),
            }
        }
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
    /// When the previous application was seen back in front, or the decision
    /// otherwise finished, on the host's clock.
    pub finished_at_ms: u64,
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
    if previous == target {
        return RestoreOutcome {
            restore: RestoreStatus::NotNeeded,
            person_input_during_fronting: false,
            finished_at_ms: host.now_ms(),
        };
    }
    let frontmost = host.frontmost_pid();
    let input = hardware_input_since(host.hardware_input_snapshot(), front_instant_ms);
    match decide_restore(previous, target, frontmost, input) {
        RestoreDecision::SkipPerson { now_front } => RestoreOutcome {
            restore: RestoreStatus::SkippedPerson { now_front },
            person_input_during_fronting: input,
            finished_at_ms: host.now_ms(),
        },
        RestoreDecision::Restore {
            person_input_during_fronting,
        } => {
            let requested_at = host.now_ms();
            let restore = request_restore(host, previous, requested_at, wait_ms);
            RestoreOutcome {
                restore,
                person_input_during_fronting,
                finished_at_ms: host.now_ms(),
            }
        }
    }
}

/// Request the previous application back and wait at most `wait_ms` from
/// `requested_at_ms` for it: `Restored`, or `Failed` naming what is in front.
///
/// A refused request is not given up on at once: the previous application
/// left behind the target is the failure this exists to prevent, so the
/// whole wait is spent before reporting it.
pub(super) fn request_restore<H: FrontingBracketHost + ?Sized>(
    host: &mut H,
    previous: u32,
    requested_at_ms: u64,
    wait_ms: u64,
) -> RestoreStatus {
    let _ = host.request_front(previous);
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
