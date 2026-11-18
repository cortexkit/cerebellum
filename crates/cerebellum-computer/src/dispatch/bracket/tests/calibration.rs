use super::super::restore_predictor::{MIN_RESTORE_SAMPLE_MS, RESTORE_SAMPLE_MAX_AGE};
use super::*;
use cerebellum_core::format_floor::{floor_path, read_floors};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

const BOUND: u64 = 200;

fn shortcut(desk: &mut FakeDesk, predictor: &RestorePredictor) -> BracketOutcome {
    run_fronting_bracket_with_predictor(
        desk,
        &mut UserIdleEstimator::new(),
        BracketPlan {
            maximum_interval_ms: BOUND,
            ..plan(1)
        },
        admitted(),
        &|| false,
        Some(predictor),
    )
}

#[test]
fn empty_restore_history_does_not_deadlock_needs_front_shortcuts() {
    let mut desk = FakeDesk::new();
    let predictor = RestorePredictor::open(None);

    let first = shortcut(&mut desk, &predictor).report;
    assert_eq!(first.stop, Some(BracketStop::BoundExceeded));
    assert_eq!(first.posts_returned, 0);
    assert!(desk.posted.is_empty());
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert_eq!(first.restore, RestoreStatus::Restored);
    assert_eq!(first.longest_fronted_interval_ms, 12);
    assert!(first.restore_calibrated);
    // The fake desk restores in 6 ms; a kept sample is never below the floor.
    assert_eq!(predictor.maximum(), Some(MIN_RESTORE_SAMPLE_MS));

    let retry = shortcut(&mut desk, &predictor).report;
    assert_eq!(retry.units_posted, 1, "retry after first use: {retry:?}");
    assert!(retry.held(BOUND));
}

#[test]
fn a_recent_slow_restore_does_not_deadlock_needs_front_shortcuts() {
    let mut desk = FakeDesk::new();
    let home = DataHome::scratch();
    let predictor = home.start();
    predictor.record(95, None, Instant::now());
    predictor.record(250, None, Instant::now());

    let refresh = shortcut(&mut desk, &predictor).report;
    assert_eq!(refresh.stop, Some(BracketStop::BoundExceeded));
    assert!(refresh.restore_calibrated);
    assert!(desk.posted.is_empty());
    assert_eq!(predictor.maximum(), Some(95), "retain in-budget history");
    assert_eq!(
        home.start().maximum(),
        Some(95),
        "don't reload the stale peak"
    );

    let retry = shortcut(&mut desk, &predictor).report;
    assert_eq!(retry.units_posted, 1, "retry after refreshing: {retry:?}");
    assert!(retry.held(BOUND));

    // The fresh slow restore came from a real shortcut, not a fabricated
    // reserve. It must count again even though an earlier refresh succeeded.
    desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
    desk.restore_latency_ms = Some(250);
    let slow = shortcut(&mut desk, &predictor).report;
    assert_eq!(slow.units_posted, 1);
    assert_eq!(predictor.maximum(), Some(250));
    desk.front_requests.clear();
    let blocked = shortcut(&mut desk, &predictor).report;
    assert!(blocked.waiting_out_slow_restore);
    assert_eq!(blocked.units_posted, 0);
    assert!(desk.front_requests.is_empty(), "refresh is rate-limited");
}

#[test]
fn a_calibration_already_in_flight_makes_another_call_refuse_without_fronting() {
    let predictor = RestorePredictor::open(None);
    let _in_flight = predictor.try_calibrate(None, Instant::now()).unwrap();
    let mut desk = FakeDesk::new();
    let refused = shortcut(&mut desk, &predictor).report;
    assert_eq!(refused.stop, Some(BracketStop::BoundExceeded));
    assert_eq!(refused.posts_returned, 0);
    assert!(desk.front_requests.is_empty());
}

#[test]
fn a_slow_predictor_can_calibrate_again_after_sixty_seconds() {
    let predictor = RestorePredictor::open(None);
    let start = Instant::now();
    drop(predictor.try_calibrate(None, start).unwrap());
    predictor.record(250, None, start);
    assert!(predictor
        .try_calibrate(Some(250), start + Duration::from_secs(59))
        .is_none());
    assert!(predictor
        .try_calibrate(Some(250), start + Duration::from_secs(60))
        .is_some());
}

#[test]
fn a_failed_cold_calibration_prevents_another_front_for_sixty_seconds() {
    let predictor = RestorePredictor::open(None);
    let mut desk = FakeDesk::new();
    desk.refuse_front_of = Some(PREVIOUS);
    let failed = shortcut(&mut desk, &predictor).report;
    assert_eq!(failed.stop, Some(BracketStop::RestoreFailed));
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    // A failed restore counts as at least the full cleanup allowance.
    assert!(predictor.maximum() >= Some(RESTORE_WAIT_MS));
    let failed_sample = predictor.maximum();

    // The person put their previous app back; another shortcut would need
    // to front again, but must not while the calibration cooldown is active.
    desk.set_frontmost(PREVIOUS);
    desk.front_requests.clear();
    let retry = shortcut(&mut desk, &predictor).report;
    assert!(
        desk.front_requests.is_empty(),
        "unexpected front: {retry:?}"
    );
    assert_eq!(retry.stop, Some(BracketStop::BoundExceeded));
    assert_eq!(retry.posts_returned, 0);
    assert!(predictor
        .try_calibrate(failed_sample, Instant::now() + Duration::from_secs(60))
        .is_some());
}

#[test]
fn calibration_will_not_front_over_an_active_person_or_restore_over_their_switch() {
    let predictor = RestorePredictor::open(None);
    let mut desk = FakeDesk::new();
    desk.idle_ms = 10;
    let active = shortcut(&mut desk, &predictor).report;
    assert!(matches!(active.stop, Some(BracketStop::Aborted(_))));
    assert!(desk.front_requests.is_empty());

    let mut desk = FakeDesk::new();
    desk.switch_on_second_sample = true;
    desk.input_on_second_sample = true;
    let switched = shortcut(&mut desk, &predictor);
    assert!(matches!(
        switched.report.stop,
        Some(BracketStop::Aborted(_))
    ));
    assert!(switched.person_input_during_fronting);
    assert_eq!(desk.front_requests, [TARGET]);
    assert_eq!(desk.frontmost, Some(THIRD));
    assert!(desk.posted.is_empty());
    assert_eq!(predictor.maximum(), None);
}

#[test]
fn an_over_budget_calibration_finishes_cleanup_and_remembers_a_timeout_as_the_full_allowance() {
    let predictor = RestorePredictor::open(None);
    let mut desk = FakeDesk::new();
    desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
    desk.refuse_front_of = Some(PREVIOUS);
    let failed = shortcut(&mut desk, &predictor).report;
    assert!(matches!(failed.stop, Some(BracketStop::RestoreFailed)));
    assert!(failed.longest_fronted_interval_ms > BOUND);
    // A timeout says only that the restore took at least this long, so it
    // is kept as no less than the cleanup allowance, never as a fast sample.
    assert!(predictor.maximum() >= Some(RESTORE_WAIT_MS));

    let predictor = RestorePredictor::open(None);
    let mut desk = FakeDesk::new();
    desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
    desk.restore_latency_ms = Some(250);
    let slow = shortcut(&mut desk, &predictor).report;
    assert_eq!(slow.stop, Some(BracketStop::BoundExceeded));
    assert!(!slow.restore_calibrated);
    assert_eq!(slow.restore, RestoreStatus::Restored);
    assert_eq!(slow.longest_fronted_interval_ms, 256);
    assert_eq!(predictor.maximum(), Some(250));
    assert!(desk.posted.is_empty());
}

#[test]
fn an_activation_after_the_calibration_deadline_is_only_seen_by_cleanup() {
    let predictor = RestorePredictor::open(None);
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = BOUND + 6;
    desk.restore_latency_ms = Some(8);
    desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
    let late = shortcut(&mut desk, &predictor).report;
    assert_eq!(late.stop, Some(BracketStop::FrontFailed));
    assert_eq!(late.restore, RestoreStatus::Restored);
    assert_eq!(late.longest_fronted_interval_ms, BOUND + 14);
    assert!(!late.restore_calibrated);
    assert!(desk.posted.is_empty());
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
}

struct DataHome(PathBuf);

impl DataHome {
    fn scratch() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("ck-restore-test-{}-{id}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }

    fn samples_path(&self) -> PathBuf {
        self.0
            .join("cortexkit/cerebellum/restore-latency/samples.json")
    }

    fn start(&self) -> RestorePredictor {
        RestorePredictor::open(Some(&self.0))
    }
}

impl Drop for DataHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn the_first_calibration_is_durable_and_a_restart_can_send_on_the_first_call() {
    let home = DataHome::scratch();
    let floor = floor_path(&home.0, "restore-latency");
    let predictor = home.start();
    assert!(!floor.exists());
    assert!(!home.samples_path().exists());
    let mut desk = FakeDesk::new();
    assert!(shortcut(&mut desk, &predictor).report.restore_calibrated);
    drop(predictor);
    assert_eq!(read_floors(&floor).unwrap()["restore-latency"], 2);

    let restarted = home.start();
    let mut new_desk = FakeDesk::new();
    assert_eq!(restarted.maximum(), Some(MIN_RESTORE_SAMPLE_MS));
    let first = shortcut(&mut new_desk, &restarted).report;
    assert_eq!(first.units_posted, 1);
    assert!(!first.restore_calibrated);
    assert!(first.held(BOUND));
}

#[test]
fn a_malformed_history_loads_empty_and_can_be_replaced_by_calibration() {
    let home = DataHome::scratch();
    let path = home.samples_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        b"{\"version\":1,\"samples_ms\":[\"not milliseconds\"]}",
    )
    .unwrap();
    let predictor = home.start();
    assert_eq!(predictor.maximum(), None);
    let mut desk = FakeDesk::new();
    assert!(shortcut(&mut desk, &predictor).report.restore_calibrated);
    assert!(desk.posted.is_empty());
    assert_eq!(home.start().maximum(), Some(MIN_RESTORE_SAMPLE_MS));
}

#[test]
fn a_burst_only_checkpoints_once_and_the_next_checkpoint_keeps_eight_in_order() {
    let home = DataHome::scratch();
    let predictor = home.start();
    let start = Instant::now();
    predictor.record(99, None, start);
    for sample in 41..=48 {
        predictor.record(sample, None, start + Duration::from_millis(sample));
    }
    assert_eq!(predictor.maximum(), Some(48));
    assert_eq!(home.start().maximum(), Some(99));
    predictor.record(50, None, start + Duration::from_secs(1));
    let bytes = std::fs::read(home.samples_path()).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(document["version"], 2);
    let samples = document["samples"].as_array().unwrap();
    let costs: Vec<u64> = samples
        .iter()
        .map(|sample| sample["ms"].as_u64().unwrap())
        .collect();
    assert_eq!(costs, [42, 43, 44, 45, 46, 47, 48, 50]);
    assert!(samples
        .iter()
        .all(|sample| sample["at_unix_ms"].as_u64().is_some_and(|at| at > 0)));
}

#[test]
fn a_restore_slower_than_the_checkpoint_is_not_lost_to_an_immediate_restart() {
    let home = DataHome::scratch();
    let predictor = home.start();
    let start = Instant::now();
    predictor.record(10, None, start);
    predictor.record(8, None, start + Duration::from_millis(1));
    predictor.record(250, None, start + Duration::from_millis(2));
    assert_eq!(home.start().maximum(), Some(250));
}

#[test]
fn samples_in_memory_stop_counting_after_the_maximum_age() {
    let predictor = RestorePredictor::open(None);
    let start = 1_800_000_000_000;
    predictor.record_at(120, None, Instant::now(), start);
    let age = u64::try_from(RESTORE_SAMPLE_MAX_AGE.as_millis()).unwrap();
    assert_eq!(predictor.maximum_at(start + age - 1), Some(120));
    assert_eq!(predictor.maximum_at(start + age), None);
}
