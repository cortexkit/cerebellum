//! How long the cutoff's restore takes to prepare: from the moment the
//! cutoff starts the restore decision to the moment it makes the native
//! restore request. The cutoff fires that much before the bracket's
//! deadline, so the request itself is made by the deadline.
//!
//! Kept in memory like the restore samples: the largest of the last few
//! measurements, never below `RESTORE_PREPARATION_RESERVE_MS` and never
//! above `RESTORE_PREPARATION_RESERVE_MAX_MS`.

use std::collections::VecDeque;
use std::sync::Mutex;

/// How many recent preparations count.
const SAMPLES: usize = 8;

static PREPARATIONS: Mutex<VecDeque<u64>> = Mutex::new(VecDeque::new());

/// Keep one measured preparation, in milliseconds.
pub(crate) fn record(milliseconds: u64) {
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
