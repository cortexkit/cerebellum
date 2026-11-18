//! Recent restore and keystroke-post costs, retained across calls without
//! persisting desktop state.

use std::sync::Mutex;
use std::time::{Duration, Instant};

pub(super) const RESTORE_SAMPLES: usize = 8;

/// Shared across target applications for this cerebellum process. A restore
/// returns to the person's application, not the action's target, so a PID-only
/// target cache would miss that cost and could confuse reused PIDs. App-use
/// needs-front brackets keep their own real-restore history.
static RESTORE_LATENCIES: Mutex<RestoreLatencies> = Mutex::new(RestoreLatencies::new());

pub(super) struct RestoreLatencies {
    samples: [u64; RESTORE_SAMPLES],
    len: usize,
    next: usize,
}

impl RestoreLatencies {
    pub(super) const fn new() -> Self {
        Self {
            samples: [0; RESTORE_SAMPLES],
            len: 0,
            next: 0,
        }
    }

    pub(super) fn record(&mut self, milliseconds: u64) {
        self.samples[self.next] = milliseconds;
        self.next = (self.next + 1) % RESTORE_SAMPLES;
        self.len = (self.len + 1).min(RESTORE_SAMPLES);
    }

    pub(super) fn maximum(&self) -> Option<u64> {
        self.samples[..self.len].iter().copied().max()
    }

    pub(super) fn oldest_first(&self) -> impl Iterator<Item = u64> + '_ {
        let oldest = if self.len == RESTORE_SAMPLES {
            self.next
        } else {
            0
        };
        (0..self.len).map(move |offset| self.samples[(oldest + offset) % RESTORE_SAMPLES])
    }
}

pub(super) fn measured_restore_latency_ms() -> Option<u64> {
    RESTORE_LATENCIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .maximum()
}

pub(super) fn record_restore_latency_ms(milliseconds: u64) {
    RESTORE_LATENCIES
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .record(milliseconds);
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
const UNIT_POST_SAMPLES: usize = 8;

/// How long a unit post's measured cost counts toward the reserve for the
/// first unit of a later bracket. Only a posted unit is measured, and a
/// bracket refused by this reserve posts nothing, so a sample count alone
/// would keep one slow post in the reserve until the process restarts. With
/// an age limit, a slow post refuses later brackets for at most this long.
pub const UNIT_POST_COST_MAX_AGE: Duration = Duration::from_secs(60);

/// Shared across target applications for this cerebellum process, like the
/// restore costs: what makes a post slow (the window server's load, for one)
/// is not a property of one target.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
static UNIT_POST_COSTS: Mutex<UnitPostCosts> = Mutex::new(UnitPostCosts::new());

/// The last eight unit post costs, each with when it was measured. The clock
/// is passed in so tests run on fixed instants.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) struct UnitPostCosts {
    samples: [Option<(u64, Instant)>; UNIT_POST_SAMPLES],
    next: usize,
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
impl UnitPostCosts {
    pub(crate) const fn new() -> Self {
        Self {
            samples: [None; UNIT_POST_SAMPLES],
            next: 0,
        }
    }

    pub(crate) fn record(&mut self, milliseconds: u64, at: Instant) {
        self.samples[self.next] = Some((milliseconds, at));
        self.next = (self.next + 1) % UNIT_POST_SAMPLES;
    }

    /// The largest cost measured less than [`UNIT_POST_COST_MAX_AGE`] before
    /// `now`, or `None` when no sample is that recent.
    pub(crate) fn maximum(&self, now: Instant) -> Option<u64> {
        self.samples
            .iter()
            .flatten()
            .filter(|(_, at)| now.saturating_duration_since(*at) < UNIT_POST_COST_MAX_AGE)
            .map(|(milliseconds, _)| *milliseconds)
            .max()
    }
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn measured_unit_post_cost_ms(now: Instant) -> Option<u64> {
    UNIT_POST_COSTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .maximum(now)
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub(crate) fn record_unit_post_cost_ms(milliseconds: u64, at: Instant) {
    UNIT_POST_COSTS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .record(milliseconds, at);
}
