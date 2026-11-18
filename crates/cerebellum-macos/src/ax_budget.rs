//! A per-thread cap on accessibility messaging timeouts, and on waits for a
//! system callback.
//!
//! Each accessibility message this process sends waits for the target's reply
//! for at most its messaging timeout. A call that has only a little of its
//! work budget left must not let one message wait longer than that, so a
//! worker thread records its call's deadline here before it starts, and every
//! accessibility entry point takes the smaller of its own fixed timeout and
//! the time left.
//!
//! The callback cap is separate: a thread that must stop waiting on the
//! system by an instant (a temporary front's restore reserve, say) records it
//! here, and every wait for a ScreenCaptureKit or window-list callback ends
//! by then. A call's work budget does not cap those waits.
//!
//! Both caps are per thread on purpose. Calls on different applications run
//! at once on different worker threads, and one call's budget must never cap
//! or extend another's. A guard restores the previous value when it is
//! dropped, so a worker thread reused from the blocking pool starts uncapped.

use std::cell::Cell;
use std::time::{Duration, Instant};

thread_local! {
    static CALL_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
    static CALLBACK_DEADLINE: Cell<Option<Instant>> = const { Cell::new(None) };
}

/// The shortest timeout ever set. Zero must never be passed to the platform:
/// a messaging timeout of zero means "use the system default", which is the
/// unbounded wait this cap exists to prevent.
pub const MINIMUM_MESSAGING_TIMEOUT: Duration = Duration::from_millis(1);

/// Restores the thread's previous deadline when dropped.
#[must_use = "the cap applies only while the guard is alive"]
pub struct AxCallBudget {
    previous: Option<Instant>,
}

impl Drop for AxCallBudget {
    fn drop(&mut self) {
        CALL_DEADLINE.with(|deadline| deadline.set(self.previous));
    }
}

/// Cap every accessibility message this thread sends at `deadline` until the
/// returned guard is dropped. A nested cap never extends an outer one.
pub fn bound_messages_until(deadline: Instant) -> AxCallBudget {
    CALL_DEADLINE.with(|current| {
        let previous = current.get();
        current.set(Some(previous.map_or(deadline, |outer| outer.min(deadline))));
        AxCallBudget { previous }
    })
}

/// The time left before this thread's call deadline, or `None` when no cap
/// is set. Zero once the deadline has passed.
pub fn remaining() -> Option<Duration> {
    CALL_DEADLINE.with(|deadline| {
        deadline
            .get()
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    })
}

/// The messaging timeout to set in place of `fixed`: never longer than the
/// time this thread's call has left, and never zero.
pub fn messaging_timeout(fixed: Duration) -> Duration {
    let bounded = remaining().map_or(fixed, |left| left.min(fixed));
    bounded.max(MINIMUM_MESSAGING_TIMEOUT)
}

/// [`messaging_timeout`] in the seconds the platform call takes.
pub fn messaging_timeout_seconds(fixed_seconds: f32) -> f32 {
    messaging_timeout(Duration::from_secs_f32(fixed_seconds.max(0.0))).as_secs_f32()
}

/// Restores the thread's previous callback-wait deadline when dropped.
#[must_use = "the cap applies only while the guard is alive"]
pub struct CallbackWaitBudget {
    previous: Option<Instant>,
}

impl Drop for CallbackWaitBudget {
    fn drop(&mut self) {
        CALLBACK_DEADLINE.with(|deadline| deadline.set(self.previous));
    }
}

/// End every wait this thread makes for a system callback by `deadline`
/// until the returned guard is dropped. A nested cap never extends an outer
/// one.
pub fn bound_callback_waits_until(deadline: Instant) -> CallbackWaitBudget {
    CALLBACK_DEADLINE.with(|current| {
        let previous = current.get();
        current.set(Some(previous.map_or(deadline, |outer| outer.min(deadline))));
        CallbackWaitBudget { previous }
    })
}

/// How long to wait for a system callback in place of `fixed`: never past
/// this thread's callback deadline. Zero once it has passed: the caller then
/// stops waiting at once.
pub fn callback_wait(fixed: Duration) -> Duration {
    CALLBACK_DEADLINE.with(|deadline| {
        deadline.get().map_or(fixed, |deadline| {
            fixed.min(deadline.saturating_duration_since(Instant::now()))
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn without_a_cap_the_fixed_timeout_stands() {
        assert_eq!(
            messaging_timeout(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        assert_eq!(remaining(), None);
    }

    #[test]
    fn a_cap_shortens_a_longer_timeout_and_never_reaches_zero() {
        let _cap = bound_messages_until(Instant::now() + Duration::from_millis(200));
        assert!(messaging_timeout(Duration::from_secs(2)) <= Duration::from_millis(200));
        assert_eq!(
            messaging_timeout(Duration::from_millis(50)),
            Duration::from_millis(50)
        );
        drop(_cap);
        let _spent = bound_messages_until(Instant::now() - Duration::from_secs(1));
        assert_eq!(
            messaging_timeout(Duration::from_secs(2)),
            MINIMUM_MESSAGING_TIMEOUT
        );
    }

    #[test]
    fn the_guard_restores_the_outer_cap_and_an_inner_cap_never_extends_it() {
        let outer_deadline = Instant::now() + Duration::from_millis(100);
        let outer = bound_messages_until(outer_deadline);
        {
            let _inner = bound_messages_until(Instant::now() + Duration::from_secs(60));
            assert!(remaining().unwrap() <= Duration::from_millis(100));
        }
        assert!(remaining().unwrap() <= Duration::from_millis(100));
        drop(outer);
        assert_eq!(remaining(), None);
    }

    #[test]
    fn a_cap_on_one_thread_does_not_reach_another() {
        let _cap = bound_messages_until(Instant::now());
        std::thread::spawn(|| assert_eq!(remaining(), None))
            .join()
            .unwrap();
    }

    #[test]
    fn a_callback_cap_ends_the_wait_at_its_deadline_and_only_on_its_thread() {
        assert_eq!(
            callback_wait(Duration::from_secs(2)),
            Duration::from_secs(2)
        );
        let deadline = Instant::now() + Duration::from_millis(100);
        let outer = bound_callback_waits_until(deadline);
        assert!(callback_wait(Duration::from_secs(2)) <= Duration::from_millis(100));
        {
            let _later = bound_callback_waits_until(Instant::now() + Duration::from_secs(60));
            assert!(
                callback_wait(Duration::from_secs(2)) <= Duration::from_millis(100),
                "an inner cap never extends the outer one"
            );
        }
        std::thread::spawn(|| {
            assert_eq!(
                callback_wait(Duration::from_secs(2)),
                Duration::from_secs(2)
            )
        })
        .join()
        .unwrap();
        assert_eq!(remaining(), None, "the messaging cap is separate");
        drop(outer);
        let _past = bound_callback_waits_until(Instant::now() - Duration::from_millis(1));
        assert_eq!(callback_wait(Duration::from_secs(2)), Duration::ZERO);
    }
}
