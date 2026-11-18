//! How long the cutoff's restore takes to prepare: from the moment the
//! cutoff starts the restore decision to the moment it makes the native
//! restore request. The cutoff fires that much before the bracket's
//! deadline, so the request itself is made by the deadline.
//!
//! Kept in memory like the restore samples: the largest of the last few
//! measurements, never below `RESTORE_PREPARATION_RESERVE_MS` and never
//! above `RESTORE_PREPARATION_RESERVE_MAX_MS`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

/// How many recent preparations count.
const SAMPLES: usize = 8;

static PREPARATIONS: Mutex<VecDeque<u64>> = Mutex::new(VecDeque::new());
static EXPIRED_WRITES: AtomicU64 = AtomicU64::new(0);

pub(crate) fn expired_writes() -> u64 {
    EXPIRED_WRITES.load(Ordering::Relaxed)
}

/// Admission for the first native restore request, after the safety reads
/// and platform preparation. A fallback after a timely primary request is
/// still governed by the ordinary restore confirmation and safety checks.
pub(super) struct WriteDeadline {
    deadline: Instant,
    started: Instant,
    measure: bool,
    committed_at: Option<Instant>,
    pub(super) expired: bool,
}

impl WriteDeadline {
    pub(super) fn new(deadline: Instant, started: Instant, measure: bool) -> Self {
        Self {
            deadline,
            started,
            measure,
            committed_at: None,
            expired: false,
        }
    }

    pub(super) fn permit(&mut self) -> bool {
        if self.expired || self.committed_at.is_some() {
            return self.committed_at.is_some();
        }
        let now = Instant::now();
        if now > self.deadline {
            self.expired = true;
            EXPIRED_WRITES.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        self.committed_at = Some(now);
        true
    }

    pub(super) fn record_sample(&self) {
        if let (true, Some(at)) = (self.measure, self.committed_at) {
            let nanos = at.saturating_duration_since(self.started).as_nanos();
            record(u64::try_from(nanos.div_ceil(1_000_000)).unwrap_or(u64::MAX));
        }
    }
}

/// Keep one measured preparation, in milliseconds.
fn record(milliseconds: u64) {
    let mut samples = PREPARATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    samples.push_back(milliseconds);
    while samples.len() > SAMPLES {
        samples.pop_front();
    }
}

/// How far before the deadline the cutoff fires, in milliseconds.
pub(crate) fn reserve_ms() -> u64 {
    let slowest = PREPARATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .max()
        .unwrap_or(0);
    slowest.clamp(
        crate::budgets::RESTORE_PREPARATION_RESERVE_MS,
        crate::budgets::RESTORE_PREPARATION_RESERVE_MAX_MS,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_reserve_stays_within_its_floor_and_cap() {
        let floor = crate::budgets::RESTORE_PREPARATION_RESERVE_MS;
        let cap = crate::budgets::RESTORE_PREPARATION_RESERVE_MAX_MS;
        assert!(reserve_ms() >= floor && reserve_ms() <= cap);
        assert_eq!(
            [0, floor - 1, floor, floor + 1, cap, cap + 1, u64::MAX]
                .map(|slowest| slowest.clamp(floor, cap)),
            [floor, floor, floor, floor + 1, cap, cap, cap]
        );
    }
}
