//! Passive timing records for the manual desk probe, never reply fields.

use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Milliseconds from the front request. Missing values mean the corresponding
/// confirmation was not observed, not that it took zero milliseconds.
#[derive(Clone, Debug)]
pub struct FrontingTiming {
    pub target_pid: u32,
    pub confirmed_front_ms: Option<f64>,
    pub late_landing_ms: Option<f64>,
    pub restore_confirmed_ms: Option<f64>,
}

struct State {
    started: Option<Instant>,
    timing: FrontingTiming,
}

static ATTEMPTS: Mutex<Vec<Arc<Mutex<State>>>> = Mutex::new(Vec::new());

#[derive(Clone)]
pub(super) struct ProbeTiming(Arc<Mutex<State>>);

impl ProbeTiming {
    pub(super) fn new(target_pid: u32) -> Self {
        Self(Arc::new(Mutex::new(State {
            started: None,
            timing: FrontingTiming {
                target_pid,
                confirmed_front_ms: None,
                late_landing_ms: None,
                restore_confirmed_ms: None,
            },
        })))
    }

    pub(super) fn begin(&self) {
        let mut state = self.0.lock().unwrap();
        if state.started.is_none() {
            state.started = Some(Instant::now());
            ATTEMPTS.lock().unwrap().push(Arc::clone(&self.0));
        }
    }

    pub(super) fn confirmed_front(&self) {
        let mut state = self.0.lock().unwrap();
        if let Some(started) = state.started {
            state
                .timing
                .confirmed_front_ms
                .get_or_insert_with(|| started.elapsed().as_secs_f64() * 1000.0);
        }
    }

    pub(super) fn late_landing(&self) {
        let mut state = self.0.lock().unwrap();
        if let Some(started) = state.started {
            state
                .timing
                .late_landing_ms
                .get_or_insert_with(|| started.elapsed().as_secs_f64() * 1000.0);
        }
    }

    pub(super) fn restored(&self) {
        let mut state = self.0.lock().unwrap();
        if let Some(started) = state.started {
            state
                .timing
                .restore_confirmed_ms
                .get_or_insert_with(|| started.elapsed().as_secs_f64() * 1000.0);
        }
    }
}

pub(crate) fn take_timings() -> Vec<FrontingTiming> {
    let attempts = std::mem::take(&mut *ATTEMPTS.lock().unwrap());
    attempts
        .into_iter()
        .map(|state| state.lock().unwrap().timing.clone())
        .collect()
}
