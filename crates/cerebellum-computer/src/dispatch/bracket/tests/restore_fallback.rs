use super::*;
use crate::dispatch::bracket::restore::{request_restore, RestoreRequest};

fn restore(desk: &mut FakeDesk, require_quiet: bool) -> RestoreStatus {
    let requested_at = desk.now;
    request_restore(
        desk,
        RestoreRequest {
            previous: PREVIOUS,
            target: TARGET,
            front_instant_ms: 100,
            require_quiet,
        },
        requested_at,
        300,
    )
}

fn fronted_desk() -> FakeDesk {
    let mut desk = FakeDesk::new();
    desk.advance(200);
    desk.set_frontmost(TARGET);
    desk.restore_latency_ms = Some(20);
    desk.fallback_restores = true;
    desk
}

#[test]
fn refused_first_restore_requests_fallback_without_waiting() {
    let mut desk = fronted_desk();
    desk.refused_restores = true;
    assert_eq!(restore(&mut desk, true), RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [PREVIOUS]);
    assert_eq!(desk.fallback_requests, [PREVIOUS]);
    assert_eq!(desk.fallback_request_times, [200]);
    assert_eq!(desk.now, 220, "the fallback still needs confirmation");
    assert!(desk.posted.is_empty());
}

#[test]
fn accepted_first_restore_keeps_the_150_ms_fallback_wait() {
    let mut desk = fronted_desk();
    desk.ignored_restores = 1;
    assert_eq!(restore(&mut desk, true), RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [PREVIOUS]);
    assert_eq!(desk.fallback_request_times, [350]);
    assert_eq!(desk.now, 370);
}

#[test]
fn accepted_first_restore_that_lands_needs_no_fallback() {
    let mut desk = fronted_desk();
    assert_eq!(restore(&mut desk, true), RestoreStatus::Restored);
    assert!(desk.fallback_requests.is_empty());
    assert_eq!(desk.now, 220);
}

#[test]
fn refused_first_restore_still_checks_person_input_coverage_and_front() {
    for guard in ["input", "coverage", "third_app", "unknown_front"] {
        let mut desk = fronted_desk();
        desk.refused_restores = true;
        match guard {
            "input" => desk.hardware_input_ms = Some(200),
            "coverage" => desk.observer_lost = true,
            "third_app" => desk.set_frontmost(THIRD),
            "unknown_front" => desk.frontmost = None,
            _ => unreachable!(),
        }
        assert!(matches!(
            restore(&mut desk, true),
            RestoreStatus::Failed { .. }
        ));
        assert!(desk.fallback_requests.is_empty(), "{guard}");
        assert_eq!(desk.now, 500, "{guard}: keep the 300 ms confirmation limit");
    }
}

#[test]
fn refused_first_restore_does_not_extend_the_300_ms_limit() {
    let mut desk = fronted_desk();
    desk.refused_restores = true;
    desk.fallback_restores = false;
    assert_eq!(
        restore(&mut desk, true),
        RestoreStatus::Failed {
            left_in_front: Some(TARGET)
        }
    );
    assert_eq!(desk.fallback_request_times, [200]);
    assert_eq!(desk.now, 500);
}
