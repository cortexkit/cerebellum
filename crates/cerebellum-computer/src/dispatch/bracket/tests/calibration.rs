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
    assert_eq!(predictor.maximum(), Some(6));

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
fn an_over_budget_calibration_finishes_cleanup_and_only_remembers_real_restores() {
    let predictor = RestorePredictor::open(None);
    let mut desk = FakeDesk::new();
    desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
    desk.refuse_front_of = Some(PREVIOUS);
    let failed = shortcut(&mut desk, &predictor).report;
    assert!(matches!(failed.stop, Some(BracketStop::RestoreFailed)));
    assert!(failed.longest_fronted_interval_ms > BOUND);
    assert_eq!(predictor.maximum(), None, "a timeout is not a sample");

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
    assert_eq!(read_floors(&floor).unwrap()["restore-latency"], 1);

    let restarted = home.start();
    let mut new_desk = FakeDesk::new();
    assert_eq!(restarted.maximum(), Some(6));
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
    assert_eq!(home.start().maximum(), Some(6));
}

#[test]
fn a_burst_only_checkpoints_once_and_the_next_checkpoint_keeps_eight_in_order() {
    let home = DataHome::scratch();
    let predictor = home.start();
    let start = Instant::now();
    predictor.record(99, None, start);
    for sample in 2..=9 {
        predictor.record(sample, None, start + Duration::from_millis(sample));
    }
    assert_eq!(predictor.maximum(), Some(9));
    assert_eq!(home.start().maximum(), Some(99));
    predictor.record(10, None, start + Duration::from_secs(1));
    let bytes = std::fs::read(home.samples_path()).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
        serde_json::json!({"version": 1, "samples_ms": [3, 4, 5, 6, 7, 8, 9, 10]})
    );
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
