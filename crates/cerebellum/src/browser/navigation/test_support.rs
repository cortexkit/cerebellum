use std::time::{Duration, Instant};

use super::NavigationClock;

pub(super) struct FakeClock {
    now: Instant,
}

impl FakeClock {
    pub(super) fn new() -> Self {
        Self {
            now: Instant::now(),
        }
    }
}

impl NavigationClock for FakeClock {
    fn now(&mut self) -> Instant {
        self.now
    }

    fn sleep(&mut self, duration: Duration) {
        self.now += duration;
    }
}
