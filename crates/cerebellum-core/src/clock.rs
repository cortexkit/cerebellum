//! Monotonic clock abstraction.
//!
//! Health derives ages as `now - instant` from a single monotonic clock
//! sample. Production uses [`SystemClock`] (a thin wrapper over
//! [`std::time::Instant::now`]); tests use [`FakeClock`] for deterministic,
//! driven advancement. Both implement [`MonotonicClock`].
//!
//! A [`MonoInstant`] is nanoseconds since the clock's own epoch. The system
//! clock's epoch is the process start; the fake clock's epoch is its
//! construction. Two instants from the *same clock* subtract to a non-negative
//! duration under monotonic ordering; instants from different clocks are not
//! comparable (the dispatch state and health lane always share one clock).
//! Ages saturate at zero if a fake or platform clock violates monotonic
//! ordering (see [`MonotonicClock::age_since`]); a backwards clock never
//! produces a negative (degraded) age.

use std::time::{Duration, Instant};

/// A monotonic instant: nanoseconds since the clock's own epoch. Comparable
/// only to other instants from the same clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct MonoInstant(Duration);

impl MonoInstant {
    /// Construct an instant from a duration since the clock's epoch.
    pub fn from_duration(d: Duration) -> Self {
        Self(d)
    }

    /// The raw nanoseconds since the clock's epoch.
    pub fn as_nanos(&self) -> u64 {
        // `Duration::as_nanos` returns `u128`; clamp to u64. A u64 of nanoseconds
        // is ~584 years, so this is safe for any realistic monotonic session.
        self.0.as_nanos() as u64
    }

    /// Reconstruct a [`MonoInstant`] from nanoseconds since the clock epoch.
    pub fn from_nanos(nanos: u64) -> Self {
        Self::from_duration(Duration::from_nanos(nanos))
    }

    /// The instant `after` later than this one, on the same clock.
    ///
    /// Saturating, so a deadline far enough ahead to overflow becomes the
    /// furthest representable instant rather than wrapping to the past. Wrapping
    /// would turn a long grant into one that had already expired, which reads as
    /// a revocation nobody performed.
    pub fn saturating_add(&self, after: Duration) -> Self {
        Self(self.0.saturating_add(after))
    }
}

/// A monotonic clock that can be sampled for the current instant and can
/// compute an age (duration since a previously sampled instant).
pub trait MonotonicClock {
    /// Sample the clock's current instant.
    fn now(&self) -> MonoInstant;

    /// Compute `now - instant`, saturating at zero if the clock has not
    /// advanced past `instant` (e.g. a fake clock driven backwards, or a
    /// platform monotonicity violation). A non-advancing or backwards clock
    /// never produces a degraded age.
    fn age_since(&self, instant: MonoInstant) -> Duration {
        let now = self.now();
        now.0.saturating_sub(instant.0)
    }
}

/// The platform monotonic clock. Its epoch is the moment [`SystemClock::new`]
/// is first called (lazily, per clock instance); instants are durations since
/// that epoch.
#[derive(Debug, Clone)]
pub struct SystemClock {
    epoch: Instant,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemClock {
    /// Create a system clock. The epoch is captured now.
    pub fn new() -> Self {
        Self {
            epoch: Instant::now(),
        }
    }
}

impl MonotonicClock for SystemClock {
    fn now(&self) -> MonoInstant {
        MonoInstant(self.epoch.elapsed())
    }
}

/// A deterministic fake monotonic clock for tests. The clock starts at an
/// arbitrary epoch (zero) and advances only when [`FakeClock::advance`] is
/// called, so tests drive health boundaries exactly without sleeping.
#[derive(Debug, Clone, Default)]
pub struct FakeClock {
    offset: Duration,
}

impl FakeClock {
    /// Create a fake clock at epoch zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Advance the fake clock by `delta`. The clock is monotonic by
    /// construction; pass a positive [`Duration`].
    pub fn advance(&mut self, delta: Duration) {
        self.offset += delta;
    }

    /// The current fake instant.
    pub fn instant(&self) -> MonoInstant {
        MonoInstant(self.offset)
    }
}

impl MonotonicClock for FakeClock {
    fn now(&self) -> MonoInstant {
        self.instant()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// Two clocks never agree about one lease, so a module must keep ONE.
    ///
    /// `SystemClock`'s epoch is fixed per instance, so instants from two of them
    /// are not comparable even though the type system says they are: a lease
    /// stamped by one reads as long expired to the other. That was the mechanism
    /// behind a live defect where `computer.open_target` answered `already_held`
    /// with ten minutes remaining while every computer action refused
    /// `no_lease` -- a remedy loop, because the refusal's remedy was the call
    /// that had just succeeded. It stayed invisible while the module's uptime was
    /// under the grant window and was total past it, which is why every live
    /// probe had passed: each ran minutes after a restart.
    #[test]
    fn two_system_clocks_disagree_about_the_same_moment() {
        let first = SystemClock::new();
        std::thread::sleep(Duration::from_millis(20));
        let second = SystemClock::new();

        let from_first = first.now();
        let from_second = second.now();
        assert!(
            from_second < from_first,
            "the later clock must read a smaller instant for the same moment: \
             {from_second:?} against {from_first:?}"
        );
        // The gap is the size of the error: a lease minted on `second` and
        // checked against `first` loses exactly this much of its life, and a
        // module up longer than the grant loses all of it.
        let gap = Duration::from_nanos(from_first.as_nanos() - from_second.as_nanos());
        assert!(
            gap >= Duration::from_millis(15),
            "the epochs must differ by roughly the delay between them, not {gap:?}"
        );
    }
}
