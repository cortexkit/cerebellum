//! Time from the start of the owner's restore preparation to the first
//! native restore write: the reads and setup the restore makes once it
//! stops waiting, which the restore reserve must cover so that a restore
//! begun at the start of the reserve still makes its request by the
//! deadline. Samples come only from the bracket owner's own restores.
//!
//! Kept in memory like the restore samples: the largest of the last few
//! measurements, never below `RESTORE_PREPARATION_RESERVE_MS` and never
//! above `RESTORE_PREPARATION_RESERVE_MAX_MS`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cerebellum_computer::platform::RestoreWriteCheck;

/// How many recent preparations count.
const SAMPLES: usize = 8;

static PREPARATIONS: Mutex<VecDeque<u64>> = Mutex::new(VecDeque::new());
static EXPIRED_WRITES: AtomicU64 = AtomicU64::new(0);
static EXPIRED_OS_DELAY: AtomicU64 = AtomicU64::new(0);
static EXPIRED_INTERNAL: AtomicU64 = AtomicU64::new(0);

pub(crate) fn expired_writes() -> u64 {
    EXPIRED_WRITES.load(Ordering::Relaxed)
}

pub(crate) fn expired_os_delay() -> u64 {
    EXPIRED_OS_DELAY.load(Ordering::Relaxed)
}

pub(crate) fn expired_internal() -> u64 {
    EXPIRED_INTERNAL.load(Ordering::Relaxed)
}

/// The last check before a native restore write: the first write must be
/// inside its deadline.
pub(super) struct NativeWriteCheck<'a> {
    pub(super) deadline: Option<&'a mut WriteDeadline>,
}

impl RestoreWriteCheck for NativeWriteCheck<'_> {
    fn permit(&mut self) -> bool {
        self.deadline.as_mut().is_none_or(|guard| guard.permit())
    }

    fn identity_read(&mut self, started: Instant, finished: Instant) {
        if let Some(guard) = &mut self.deadline {
            guard.os_read(started, finished);
        }
    }
}

/// Admission for the first native restore request, after the safety reads
/// and platform preparation. A fallback after a timely primary request is
/// still governed by the ordinary restore confirmation and safety checks.
pub(super) struct WriteDeadline {
    deadline: Instant,
    /// When the restore reserve starts: the decision waits no longer.
    reserve_start: Option<Instant>,
    /// When the owner began this decision's restore preparation.
    started: Instant,
    boundary_at: Option<Instant>,
    /// The first boundary was the native write itself, not a miss found
    /// before it.
    reached_write: bool,
    os_reads: Duration,
    /// A native call, the owner's own before the decision or a read inside
    /// it, was still running when the deadline passed.
    deadline_during_os_read: bool,
    /// When the owner's last native call before this decision returned, if
    /// that call was still running at the deadline.
    native_overrun_until: Option<Instant>,
    pub(super) expired: bool,
}

impl WriteDeadline {
    pub(super) fn new(
        deadline: Instant,
        reserve_start: Option<Instant>,
        started: Instant,
        native_overrun_until: Option<Instant>,
    ) -> Self {
        Self {
            deadline,
            reserve_start,
            started,
            boundary_at: None,
            reached_write: false,
            os_reads: Duration::ZERO,
            deadline_during_os_read: native_overrun_until.is_some(),
            native_overrun_until,
            expired: false,
        }
    }

    /// How long the decision may still wait before it must prepare its
    /// request: zero once the reserve has started.
    pub(super) fn wait_left(&self) -> Option<Duration> {
        self.reserve_start
            .map(|at| at.saturating_duration_since(Instant::now()))
    }

    /// The decision stopped waiting: what follows is its preparation.
    pub(super) fn preparation_started(&mut self) {
        if self.boundary_at.is_none() {
            self.started = Instant::now();
            self.os_reads = Duration::ZERO;
        }
    }

    /// At the first native restore write: admitted only by the deadline,
    /// and the outcome is fixed at this first boundary.
    pub(super) fn permit(&mut self) -> bool {
        if self.boundary_at.is_some() {
            return !self.expired;
        }
        let now = Instant::now();
        self.boundary_at = Some(now);
        self.reached_write = true;
        if now > self.deadline {
            self.expire(now);
            return false;
        }
        true
    }

    /// Before a native call that precedes the first write: once the deadline
    /// has passed, that write can no longer be made in time, and the miss is
    /// counted here as it would be at the write.
    pub(super) fn missed(&mut self) -> bool {
        if self.boundary_at.is_some() {
            return self.expired;
        }
        let now = Instant::now();
        if now > self.deadline {
            self.boundary_at = Some(now);
            self.expire(now);
        }
        self.expired
    }

    fn expire(&mut self, at: Instant) {
        self.expired = true;
        EXPIRED_WRITES.fetch_add(1, Ordering::Relaxed);
        if self.expiry_during_os(at) {
            EXPIRED_OS_DELAY.fetch_add(1, Ordering::Relaxed);
        } else {
            EXPIRED_INTERNAL.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(super) fn os_read(&mut self, started: Instant, finished: Instant) {
        if self.boundary_at.is_none() {
            self.os_reads += finished.saturating_duration_since(started);
            self.deadline_during_os_read |= started <= self.deadline && finished > self.deadline;
        }
    }

    fn expiry_during_os(&self, at: Instant) -> bool {
        // Our own work is what ran since the owner's stalled call returned,
        // or since the decision began, less its native reads.
        let running_since = self
            .native_overrun_until
            .map_or(self.started, |until| until.min(self.started));
        let own_work = at
            .saturating_duration_since(running_since)
            .saturating_sub(self.os_reads);
        // Attribute the expiry to a native call only if one was still running
        // at the deadline and our own work stayed inside its allowance.
        // Preemption elsewhere is indistinguishable from internal waiting; do
        // not count that as a native stall.
        self.deadline_during_os_read
            && own_work <= Duration::from_millis(crate::budgets::RESTORE_PREPARATION_SLACK_MS)
    }

    fn sample_ms(&self) -> Option<u64> {
        if !self.reached_write {
            return None;
        }
        let nanos = self
            .boundary_at?
            .saturating_duration_since(self.started)
            .as_nanos();
        Some(u64::try_from(nanos.div_ceil(1_000_000)).unwrap_or(u64::MAX))
    }

    /// Keep this decision's preparation, when it reached a native write.
    pub(super) fn record_sample(&self) {
        if let Some(ms) = self.sample_ms() {
            record(ms);
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
    #[cfg(test)]
    RECORDED_ON_THIS_THREAD.with(|count| count.set(count.get() + 1));
}

#[cfg(test)]
thread_local! {
    static RECORDED_ON_THIS_THREAD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many preparations this thread recorded, so a test can tell its own
/// sample from those of tests running beside it.
#[cfg(test)]
pub(crate) fn samples_recorded_on_this_thread() -> usize {
    RECORDED_ON_THIS_THREAD.with(std::cell::Cell::get)
}

/// How far before the deadline the restore reserve starts, in milliseconds.
pub(crate) fn reserve_ms() -> u64 {
    let slowest = PREPARATIONS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .max()
        .unwrap_or(0);
    slowest
        .saturating_add(crate::budgets::RESTORE_PREPARATION_SLACK_MS)
        .clamp(
            crate::budgets::RESTORE_PREPARATION_RESERVE_MS,
            crate::budgets::RESTORE_PREPARATION_RESERVE_MAX_MS,
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sample_covers_the_preparation_but_not_the_wait_before_it() {
        let entered = Instant::now();
        let deadline = entered + Duration::from_secs(60);
        let mut guard = WriteDeadline::new(deadline, Some(deadline), entered, None);
        // The decision waits for an unconfirmed activation first; that wait
        // is not the restore's cost.
        std::thread::sleep(Duration::from_millis(30));
        guard.preparation_started();
        let prepared_from = Instant::now();
        // Its own reads and setup are.
        std::thread::sleep(Duration::from_millis(15));
        assert!(guard.permit(), "inside the deadline");
        let sample = guard.sample_ms().expect("the write was reached");
        let wait_and_preparation = Instant::now().duration_since(entered).as_millis() as u64;
        assert!(sample >= 15, "the preparation counts: {sample}");
        assert!(
            sample < wait_and_preparation
                && u128::from(sample)
                    <= Instant::now().duration_since(prepared_from).as_millis() + 1,
            "the wait before it does not: {sample} of {wait_and_preparation}"
        );
    }

    #[test]
    fn a_miss_found_before_the_write_counts_once_and_supplies_no_sample() {
        let started = Instant::now();
        let mut guard = WriteDeadline::new(started, Some(started), started, None);
        std::thread::sleep(Duration::from_millis(2));
        let before = expired_writes();
        assert!(guard.missed(), "the deadline is behind the clock");
        assert!(guard.missed(), "and stays missed");
        assert!(!guard.permit(), "no write follows a miss");
        assert!(expired_writes() > before);
        assert_eq!(guard.sample_ms(), None, "no write was reached");
    }

    #[test]
    fn expiry_attribution_requires_os_evidence_within_the_internal_allowance() {
        let started = Instant::now();
        let plus = |ms| started + Duration::from_millis(ms);
        let mut guard = WriteDeadline::new(plus(50), Some(plus(30)), plus(1), None);
        assert!(
            !guard.expiry_during_os(plus(55)),
            "internal work alone is not an OS stall"
        );
        guard.os_read(plus(5), plus(53));
        assert!(
            guard.expiry_during_os(plus(55)),
            "known OS read straddled the deadline"
        );
        assert!(
            !guard.expiry_during_os(plus(75)),
            "unaccounted time exceeded our allowance"
        );
        // The owner's own native call, before the decision, ran past the
        // deadline: the owner reached its restore only once it returned.
        let stalled = WriteDeadline::new(plus(50), Some(plus(30)), plus(55), Some(plus(54)));
        assert!(
            stalled.expiry_during_os(plus(56)),
            "a native call before the decision was still running at the deadline"
        );
        assert!(
            !stalled.expiry_during_os(plus(80)),
            "our own work after that call returned outran the allowance"
        );
    }

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
