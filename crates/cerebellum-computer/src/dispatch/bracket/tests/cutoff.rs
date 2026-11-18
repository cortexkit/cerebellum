//! The cutoff gate on its own: it closes to new posts, fronts and captures
//! at the start of the restore reserve, whatever any thread is doing, and
//! records what a missed restore deadline can be attributed to. It performs
//! nothing: the bracket's owner reads it.

use super::*;
use crate::platform::FrontedKeyGuard;
use std::time::{Duration, Instant};

fn checks(
    gate: &CutoffGate,
) -> FrontedKeyChecks<'_, impl FnMut() -> u64, impl FnMut() -> Option<u32>> {
    FrontedKeyChecks {
        target_pid: TARGET,
        deadline_ms: 1_000,
        now_ms: || 0,
        frontmost_pid: || Some(TARGET),
        cutoff: Some(gate),
    }
}

#[test]
fn a_post_is_refused_once_the_restore_reserve_starts() {
    let gate = CutoffGate::new();
    let deadline = Instant::now() + Duration::from_secs(3600);
    gate.set_bound(Instant::now() + Duration::from_secs(1800), deadline);
    assert!(
        checks(&gate)
            .before_post(false, &|| false, &mut || Ok(()))
            .is_ok(),
        "inside the bound, before the reserve"
    );
    gate.all_released();
    // The reserve has started; the deadline itself is still far off.
    gate.set_bound(Instant::now() - Duration::from_millis(1), deadline);
    assert_eq!(
        checks(&gate).before_post(true, &|| false, &mut || Ok(())),
        Err(crate::platform::ProcessEventRefusal::Cancelled),
        "now >= reserve start: the post is not begun, though the deadline is still ahead"
    );
    assert!(!gate.begin_post(false));
    assert!(!gate.input_held(), "a refused post holds nothing");
    assert!(!gate.begin_front_attempt(0), "nor is a front begun");
}

#[test]
fn a_committed_press_counts_as_held_until_its_release() {
    let gate = CutoffGate::new();
    let mut keys = checks(&gate);
    assert!(keys.before_post(true, &|| false, &mut || Ok(())).is_ok());
    assert!(gate.input_held(), "the press is committed and may be down");
    keys.all_released();
    assert!(!gate.input_held());
}

#[test]
fn the_reserve_never_starts_after_the_deadline() {
    let gate = CutoffGate::new();
    let deadline = Instant::now() + Duration::from_secs(60);
    gate.set_bound(deadline + Duration::from_secs(60), deadline);
    assert_eq!(gate.reserve_start(), Some(deadline));
    assert!(gate.time_to_reserve_start().unwrap() <= Duration::from_secs(60));
    assert!(
        CutoffGate::new().time_to_reserve_start().is_none(),
        "no bound"
    );
}

#[test]
fn cleanup_stops_a_front_not_yet_requested_and_only_closes_one_already_requested() {
    let unfronted = CutoffGate::new();
    assert!(unfronted.stop_front(), "nothing was fronted");
    assert!(!unfronted.begin_front_attempt(0), "and nothing will be");
    assert!(unfronted.closed());

    let fronted = CutoffGate::new();
    assert!(fronted.begin_front_attempt(7));
    assert!(
        !fronted.stop_front(),
        "a requested front still needs its restore"
    );
    assert!(fronted.closed(), "but nothing new starts");
    assert!(!fronted.begin_post(true));
    assert_eq!(
        fronted.attempt_state(),
        FrontAttemptState::Dispatching {
            front_instant_ms: 7
        }
    );
}

#[test]
fn ending_the_front_closes_it_and_says_whether_the_cutoff_had_passed() {
    let early = CutoffGate::new();
    early.set_bound(
        Instant::now() + Duration::from_secs(60),
        Instant::now() + Duration::from_secs(120),
    );
    early.end_front();
    assert!(early.closed());
    assert!(!early.ended_past_cutoff());

    let late = CutoffGate::new();
    late.set_bound(Instant::now(), Instant::now() + Duration::from_secs(120));
    std::thread::sleep(Duration::from_millis(2));
    late.end_front();
    assert!(late.ended_past_cutoff());
}

#[test]
fn only_a_native_call_still_running_at_the_deadline_is_kept() {
    let gate = CutoffGate::new();
    let start = Instant::now();
    let plus = |ms| start + Duration::from_millis(ms);
    gate.set_bound(plus(30), plus(50));
    gate.native_call(plus(1), plus(40));
    assert_eq!(
        gate.native_overrun_until(),
        None,
        "returned before the deadline"
    );
    gate.native_call(plus(45), plus(70));
    assert_eq!(gate.native_overrun_until(), Some(plus(70)));
    gate.native_call(plus(71), plus(90));
    assert_eq!(
        gate.native_overrun_until(),
        Some(plus(70)),
        "a later call that began after the deadline is our own lateness"
    );
}
