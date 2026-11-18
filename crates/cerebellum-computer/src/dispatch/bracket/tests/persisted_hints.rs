//! A restore history on disk may only make admission stricter. Each test
//! writes a history this module would never have written itself and checks
//! that the first shortcut after loading it is treated as cold: it may front
//! once to calibrate, but sends nothing on the strength of the file.

use super::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const BOUND: u64 = 200;
const DAY_MS: u64 = 24 * 60 * 60 * 1000;

struct Home(PathBuf);

impl Home {
    fn with_samples(document: &str) -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ck-restore-hints-{}-{id}", std::process::id()));
        let path = dir.join("cortexkit/cerebellum/restore-latency/samples.json");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, document).unwrap();
        Self(dir)
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn now_unix_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis(),
    )
    .unwrap()
}

/// A version-2 document with one sample per `(ms, age_ms)` pair.
fn dated(samples: &[(u64, u64)]) -> String {
    let now = now_unix_ms();
    let samples: Vec<String> = samples
        .iter()
        .map(|(ms, age)| format!("{{\"ms\":{ms},\"at_unix_ms\":{}}}", now - age))
        .collect();
    format!("{{\"version\":2,\"samples\":[{}]}}", samples.join(","))
}

/// The first shortcut after loading `document` must not send: the file
/// leaves the predictor cold, so the call fronts once to calibrate.
fn assert_loads_cold(document: &str) {
    let home = Home::with_samples(document);
    let predictor = RestorePredictor::open(Some(&home.0));
    assert_eq!(predictor.maximum(), None, "trusted {document}");
    let mut desk = FakeDesk::new();
    let first = run_fronting_bracket_with_predictor(
        &mut desk,
        &mut UserIdleEstimator::new(),
        BracketPlan {
            maximum_interval_ms: BOUND,
            ..plan(1)
        },
        admitted(),
        &|| false,
        Some(&predictor),
    )
    .report;
    assert!(desk.posted.is_empty(), "sent on {document}: {first:?}");
    assert_eq!(first.stop, Some(BracketStop::BoundExceeded));
    assert!(first.restore_calibrated, "{first:?}");
}

#[test]
fn a_history_of_zero_restores_leaves_the_predictor_cold() {
    assert_loads_cold("{\"version\":1,\"samples_ms\":[0,0,0,0,0,0,0,0]}");
    assert_loads_cold(&dated(&[(0, 0); 8]));
}

#[test]
fn a_history_below_the_realistic_floor_leaves_the_predictor_cold() {
    assert_loads_cold("{\"version\":1,\"samples_ms\":[5,5]}");
    // One implausible sample discredits the whole file, even beside a
    // believable one.
    assert_loads_cold(&dated(&[(39, 0), (120, 0)]));
}

#[test]
fn a_stale_or_undated_history_leaves_the_predictor_cold() {
    // Version 1 carries no measurement times, so its age is unknown.
    assert_loads_cold("{\"version\":1,\"samples_ms\":[120]}");
    assert_loads_cold(&dated(&[(120, 8 * DAY_MS), (60, 7 * DAY_MS)]));
}

#[test]
fn a_history_measured_in_the_future_or_above_the_ceiling_leaves_the_predictor_cold() {
    let now = now_unix_ms();
    assert_loads_cold(&format!(
        "{{\"version\":2,\"samples\":[{{\"ms\":120,\"at_unix_ms\":{}}}]}}",
        now + DAY_MS
    ));
    assert_loads_cold(&dated(&[(10_001, 0)]));
}

#[test]
fn only_the_fresh_samples_of_a_partly_stale_history_count() {
    let home = Home::with_samples(&dated(&[(250, 8 * DAY_MS), (120, DAY_MS)]));
    assert_eq!(RestorePredictor::open(Some(&home.0)).maximum(), Some(120));
}
