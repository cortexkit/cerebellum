//! Phase stamps for one explicitly armed picture attempt in the desk probe.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

static ACTIVE: Mutex<Option<Attempt>> = Mutex::new(None);
static NEXT_ATTEMPT: AtomicU64 = AtomicU64::new(0);

struct Attempt {
    window: u32,
    token: u64,
    stamps: Vec<(&'static str, Instant)>,
}

pub fn begin_picture_timing_for_probe(window: u32) {
    *ACTIVE.lock().unwrap() = Some(Attempt {
        window,
        token: NEXT_ATTEMPT.fetch_add(1, Ordering::Relaxed),
        stamps: Vec::new(),
    });
}

pub fn take_picture_timing_for_probe() -> Vec<(&'static str, Instant)> {
    ACTIVE
        .lock()
        .unwrap()
        .take()
        .map_or_else(Vec::new, |a| a.stamps)
}

pub(crate) fn token(window: u32) -> Option<u64> {
    ACTIVE
        .lock()
        .unwrap()
        .as_ref()
        .filter(|a| a.window == window)
        .map(|a| a.token)
}

pub(crate) fn enumeration_token() -> Option<u64> {
    ACTIVE.lock().unwrap().as_ref().map(|a| a.token)
}

pub(crate) fn stamp(token: Option<u64>, phase: &'static str) {
    let Some(token) = token else { return };
    let now = Instant::now();
    if let Some(attempt) = ACTIVE.lock().unwrap().as_mut().filter(|a| a.token == token) {
        attempt.stamps.push((phase, now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn picture_probe_excludes_other_windows_and_late_completions() {
        begin_picture_timing_for_probe(41);
        let first = token(41);
        stamp(token(42), "other window");
        stamp(first, "first capture requested");
        assert_eq!(
            take_picture_timing_for_probe()[0].0,
            "first capture requested"
        );

        begin_picture_timing_for_probe(41);
        stamp(first, "late first completion");
        stamp(token(41), "second capture requested");
        let stamps = take_picture_timing_for_probe();
        assert_eq!(stamps.len(), 1);
        assert_eq!(stamps[0].0, "second capture requested");
    }
}
