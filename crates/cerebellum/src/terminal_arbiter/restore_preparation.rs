//! Time from the planned cutoff wake to the first native restore write.
//! Starting at the planned wake includes timer wake-up, gate and cell
//! ownership, and caller-side setup, not just the OS checks.
//!
//! Kept in memory like the restore samples: the largest of the last few
//! measurements, never below `RESTORE_PREPARATION_RESERVE_MS` and never
//! above `RESTORE_PREPARATION_RESERVE_MAX_MS`.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use cerebellum_computer::dispatch::CutoffWake;
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

/// The last check before a native restore write: the side writing must
/// still own the decision, and the first write must be inside its deadline.
pub(super) struct NativeWriteCheck<'a> {
    pub(super) owner: &'a super::DecisionOwner<'a>,
    pub(super) deadline: Option<&'a mut WriteDeadline>,
    /// Told at once when the deadline refuses the write.
    pub(super) cell: Option<&'a super::RestoreCell>,
}

impl RestoreWriteCheck for NativeWriteCheck<'_> {
    fn permit(&mut self) -> bool {
        // Ownership first: a write refused because the timer took over is
        // not this owner's expiry, and is not counted as one.
        if !self.owner.commit() {
            return false;
        }
        let Some(guard) = self.deadline.as_mut() else {
            return true;
        };
        let permitted = guard.permit();
        if !permitted && guard.expired {
            if let Some(cell) = self.cell {
                cell.publish_expired_write();
            }
        }
        permitted
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
    started: Instant,
    wake: Option<CutoffWake>,
    boundary_at: Option<Instant>,
    os_reads: Duration,
    deadline_during_os_read: bool,
    pub(super) expired: bool,
}

impl WriteDeadline {
    pub(super) fn new(deadline: Instant, started: Instant, wake: Option<CutoffWake>) -> Self {
        Self {
            deadline,
            started,
            wake,
            boundary_at: None,
            os_reads: Duration::ZERO,
            deadline_during_os_read: false,
            expired: false,
        }
    }

    pub(super) fn permit(&mut self) -> bool {
        if self.boundary_at.is_some() {
            return !self.expired;
        }
        let now = Instant::now();
        self.boundary_at = Some(now);
        if now > self.deadline {
            self.expired = true;
            EXPIRED_WRITES.fetch_add(1, Ordering::Relaxed);
            if self.expiry_during_os(now) {
                EXPIRED_OS_DELAY.fetch_add(1, Ordering::Relaxed);
            } else {
                EXPIRED_INTERNAL.fetch_add(1, Ordering::Relaxed);
            }
            return false;
        }
        true
    }

    pub(super) fn os_read(&mut self, started: Instant, finished: Instant) {
        if self.boundary_at.is_none() {
            self.os_reads += finished.saturating_duration_since(started);
            self.deadline_during_os_read |= started <= self.deadline && finished > self.deadline;
        }
    }

    fn expiry_during_os(&self, at: Instant) -> bool {
        let running_since = self.wake.map_or(self.started, |wake| wake.woke_at);
        let own_work = at
            .saturating_duration_since(running_since)
            .saturating_sub(self.os_reads);
        // If the timer woke too late it had no opportunity to run any code.
        // Otherwise attribute expiry to a tagged read only if our own work
        // was inside its allowance. Preemption elsewhere is indistinguishable
        // from internal waiting; do not count that as an OS read stall.
        self.wake.is_some_and(|wake| wake.woke_at > self.deadline)
            || (self.deadline_during_os_read
                && own_work <= Duration::from_millis(crate::budgets::RESTORE_PREPARATION_SLACK_MS))
    }

    fn sample_ms(&self) -> Option<u64> {
        let wake = self.wake?;
        let nanos = self
            .boundary_at?
            .saturating_duration_since(wake.scheduled_at)
            .as_nanos();
        Some(u64::try_from(nanos.div_ceil(1_000_000)).unwrap_or(u64::MAX))
    }

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

/// How far before the deadline the cutoff fires, in milliseconds.
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
    fn cutoff_reserve_includes_an_internal_handoff_before_the_native_write() {
        use cerebellum_computer::dispatch::{CutoffGate, CutoffTimer};
        use std::sync::{mpsc, Arc};

        let (reply, result) = mpsc::channel();
        let scheduled_at = Instant::now() + Duration::from_millis(20);
        let deadline = scheduled_at
            + Duration::from_millis(crate::budgets::RESTORE_PREPARATION_RESERVE_MAX_MS);
        let timer = CutoffTimer::arm_with_wake(
            Arc::new(CutoffGate::new()),
            scheduled_at,
            deadline,
            Box::new(move |wake| {
                // A delayed internal handoff, before the restore owns a cell.
                std::thread::sleep(Duration::from_millis(20));
                let restore_entered = Instant::now();
                let mut guard = WriteDeadline::new(deadline, restore_entered, Some(wake));
                // The fake native write has the same final admission as AX.
                let write = guard.permit().then(Instant::now);
                reply
                    .send((write, guard.sample_ms(), wake, restore_entered))
                    .unwrap();
            }),
        )
        .unwrap();
        let (write, sample, wake, restore_entered) = result
            .recv_timeout(crate::test_support::HANG_GUARD)
            .unwrap();
        timer.finish();
        assert!(
            write.is_some_and(|at| at <= deadline),
            "bounded caller delay still allows writing: {write:?}"
        );
        assert_eq!(wake.scheduled_at, scheduled_at);
        let pre_decision_ms = restore_entered.duration_since(scheduled_at).as_millis() as u64;
        assert!(pre_decision_ms >= 20);
        assert!(
            sample.unwrap() >= pre_decision_ms,
            "sample must include the handoff before restore starts"
        );
    }

    #[test]
    fn expiry_attribution_requires_os_evidence_within_the_internal_allowance() {
        let scheduled_at = Instant::now();
        let plus = |ms| scheduled_at + Duration::from_millis(ms);
        let mut guard = WriteDeadline::new(
            plus(50),
            scheduled_at,
            Some(CutoffWake {
                scheduled_at,
                woke_at: plus(1),
            }),
        );
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
        let late_wake = WriteDeadline::new(
            plus(50),
            plus(54),
            Some(CutoffWake {
                scheduled_at,
                woke_at: plus(54),
            }),
        );
        assert!(
            late_wake.expiry_during_os(plus(55)),
            "waiting thread was not scheduled in time"
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
