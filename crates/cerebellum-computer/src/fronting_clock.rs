//! The clock for bracket cutoffs and restore writes. Tests may freeze it
//! per thread so unrelated fronting tests can still run in parallel.

use std::time::Instant;

pub fn now() -> Instant {
    #[cfg(feature = "test-support")]
    if let Some(clock) = FakeClock::current() {
        return clock.now();
    }
    Instant::now()
}

#[cfg(feature = "test-support")]
pub use fake::{advance, FakeClock};

#[cfg(feature = "test-support")]
mod fake {
    use std::cell::RefCell;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    thread_local! {
        static CLOCK: RefCell<Option<FakeClock>> = const { RefCell::new(None) };
    }

    #[derive(Clone)]
    pub struct FakeClock(Arc<Mutex<Instant>>);

    impl FakeClock {
        pub fn frozen() -> Self {
            Self(Arc::new(Mutex::new(Instant::now())))
        }

        pub fn now(&self) -> Instant {
            *self.0.lock().unwrap()
        }

        pub fn current() -> Option<Self> {
            CLOCK.with(|clock| clock.borrow().clone())
        }

        /// Use this clock only for `run` on the calling thread. Another
        /// thread may enter the same clock explicitly.
        pub fn run<R>(&self, run: impl FnOnce() -> R) -> R {
            struct Reset(Option<FakeClock>);
            impl Drop for Reset {
                fn drop(&mut self) {
                    CLOCK.replace(self.0.take());
                }
            }
            let _reset = Reset(CLOCK.replace(Some(self.clone())));
            run()
        }
    }

    /// Advance the current virtual clock, if any. Return whether the delay
    /// was simulated, so a fake host can otherwise use a real wait.
    pub fn advance(duration: Duration) -> bool {
        let Some(clock) = FakeClock::current() else {
            return false;
        };
        *clock.0.lock().unwrap() += duration;
        true
    }
}
