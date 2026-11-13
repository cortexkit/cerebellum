//! Recent restore costs, retained across calls without persisting desktop state.

use std::sync::Mutex;

const RESTORE_SAMPLES: usize = 8;

/// Shared across target applications for this cerebellum process. A restore
/// returns to the person's application, not the action's target, so a PID-only
/// target cache would miss that cost and could confuse reused PIDs. Keeping
/// only eight samples lets a transient stall age out through later restores,
/// including restores after a pre-post refusal.
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
