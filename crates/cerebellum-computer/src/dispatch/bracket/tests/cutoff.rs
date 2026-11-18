//! The cutoff gate and timer on their own: the timer stops new posts and
//! starts the restore at the bound, except while a key may be held, and no
//! timer outlives the bracket that armed it.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn counting_restore(count: &Arc<AtomicUsize>) -> Box<dyn FnOnce() + Send> {
    let count = Arc::clone(count);
    Box::new(move || {
        count.fetch_add(1, Ordering::SeqCst);
    })
}

/// Wait for `condition`, failing the test after a generous guard.
fn eventually(condition: impl Fn() -> bool) {
    let give_up = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(Instant::now() < give_up, "timed out");
        std::thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn at_the_bound_the_cutoff_stops_new_posts_and_starts_the_restore() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(20),
        counting_restore(&restores),
    )
    .unwrap();
    eventually(|| restores.load(Ordering::SeqCst) == 1);
    assert!(gate.fired());
    assert!(!gate.begin_post(false), "no post starts after the cutoff");
    assert!(!gate.begin_post(true));
    timer.finish();
    assert!(gate.restore_started_by_cutoff());
    assert_eq!(restores.load(Ordering::SeqCst), 1);
}

#[test]
fn the_cutoff_fires_at_its_stamped_deadline_however_late_it_is_armed() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    let stamped = Instant::now();
    let deadline = stamped + Duration::from_millis(100);
    // Registration took longer than the whole bound before the timer was
    // armed; the cutoff must not then wait a further bound.
    std::thread::sleep(Duration::from_millis(200));
    let armed = Instant::now();
    let timer = CutoffTimer::arm(Arc::clone(&gate), deadline, counting_restore(&restores)).unwrap();
    eventually(|| restores.load(Ordering::SeqCst) == 1);
    assert!(
        armed.elapsed() < Duration::from_millis(80),
        "a deadline already past fires at once, not a bound after arming"
    );
    timer.finish();
}

#[test]
fn the_cutoff_never_restores_while_a_key_may_be_held() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_post(true), "a press before the bound");
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(5),
        counting_restore(&restores),
    )
    .unwrap();
    eventually(|| gate.fired());
    // The unit sees the cutoff at its next post and releases what it holds;
    // the bracket restores after that, not the timer.
    assert!(!gate.begin_post(true));
    gate.all_released();
    timer.finish();
    assert_eq!(restores.load(Ordering::SeqCst), 0);
    assert!(!gate.restore_started_by_cutoff());
}

#[test]
fn a_bracket_that_restores_first_leaves_the_timer_nothing_to_do() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_front_attempt(0));
    gate.front_attempt_returned();
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(100),
        counting_restore(&restores),
    )
    .unwrap();
    let OrdinaryClaim::Decide { ticket, .. } = gate.claim_ordinary() else {
        panic!("phase A is open to the bracket's own restore");
    };
    assert!(gate.settle_ordinary(&ticket), "decided inside phase A");
    std::thread::sleep(Duration::from_millis(150));
    timer.finish();
    assert_eq!(restores.load(Ordering::SeqCst), 0);
    assert!(!gate.fired());
}

#[test]
fn finishing_before_the_bound_stops_the_timer_without_waiting_for_it() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_secs(3600),
        counting_restore(&restores),
    )
    .unwrap();
    let finishing = Instant::now();
    timer.finish();
    assert!(finishing.elapsed() < Duration::from_secs(5));
    assert_eq!(restores.load(Ordering::SeqCst), 0);
    assert!(!gate.fired());
    assert!(gate.begin_post(true), "an unfired gate admits posts");
}

#[test]
fn key_checks_refuse_a_press_once_the_cutoff_fired_and_mark_a_press_held() {
    let gate = CutoffGate::new();
    let mut checks = FrontedKeyChecks {
        target_pid: TARGET,
        deadline_ms: 1_000,
        now_ms: || 0,
        frontmost_pid: || Some(TARGET),
        cutoff: Some(&gate),
    };
    use crate::platform::FrontedKeyGuard;
    assert!(checks.before_post(true, &|| false, &mut || Ok(())).is_ok());
    assert!(!gate.fire(), "held: the timer must not restore");
    assert!(
        checks
            .before_post(false, &|| false, &mut || Ok(()))
            .is_err(),
        "no post after the cutoff"
    );
    checks.all_released();
}

#[test]
fn a_passed_deadline_counts_before_the_timer_has_run() {
    let gate = CutoffGate::new();
    assert!(!gate.past_deadline(), "no deadline yet");
    gate.set_deadline(Instant::now() + Duration::from_secs(3600));
    assert!(!gate.past_deadline());
    gate.set_deadline(Instant::now() - Duration::from_millis(1));
    assert!(!gate.fired(), "the timer has not run");
    assert!(gate.past_deadline(), "the clock alone closes it");
    assert!(
        !gate.begin_post(true),
        "an expired gate cannot commit a post"
    );
    assert!(gate.fire(), "a refused post does not block restore");
}

#[test]
fn a_hold_that_clears_before_the_deadline_lets_the_timer_restore_at_once() {
    let gate = Arc::new(CutoffGate::new());
    let wakes = Arc::new(std::sync::Mutex::new(Vec::new()));
    assert!(gate.begin_post(true), "a press inside phase A");
    let armed = Instant::now();
    let deadline = armed + Duration::from_millis(200);
    let recorded = Arc::clone(&wakes);
    let timer = CutoffTimer::arm_with_wake(
        Arc::clone(&gate),
        armed + Duration::from_millis(20),
        deadline,
        Box::new(move |wake| recorded.lock().unwrap().push((wake, Instant::now()))),
    )
    .unwrap();
    eventually(|| {
        gate.phase()
            == RestorePhase::Timer {
                awaiting_release: true,
            }
    });
    std::thread::sleep(Duration::from_millis(130).saturating_sub(armed.elapsed()));
    let released = Instant::now();
    gate.all_released();
    eventually(|| !wakes.lock().unwrap().is_empty());
    timer.finish();
    let (wake, ran_at) = wakes.lock().unwrap()[0];
    assert!(
        ran_at < deadline,
        "the timer restores as soon as the release settles, inside the deadline"
    );
    assert!(
        wake.scheduled_at >= released,
        "preparation is timed from the release"
    );
    assert!(gate.restore_started_by_cutoff());
}

#[test]
fn a_hold_through_the_deadline_passes_the_decision_to_the_release_without_a_deadline() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_front_attempt(0));
    gate.front_attempt_returned();
    assert!(gate.begin_post(true));
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(5),
        counting_restore(&restores),
    )
    .unwrap();
    eventually(|| gate.phase() == RestorePhase::AfterRelease { claimed: false });
    gate.all_released();
    timer.finish();
    assert_eq!(restores.load(Ordering::SeqCst), 0);
    assert!(matches!(
        gate.claim_ordinary(),
        OrdinaryClaim::Decide {
            write_deadline: false,
            ..
        }
    ));
}

#[test]
fn an_ordinary_owner_loses_the_decision_when_the_reserve_starts() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_front_attempt(0));
    gate.front_attempt_returned();
    let closes_at = Instant::now() + Duration::from_millis(60);
    let timer = CutoffTimer::arm_with_wake(
        Arc::clone(&gate),
        closes_at,
        closes_at + Duration::from_millis(100),
        Box::new({
            let restores = Arc::clone(&restores);
            move |_| {
                restores.fetch_add(1, Ordering::SeqCst);
            }
        }),
    )
    .unwrap();
    let OrdinaryClaim::Decide { ticket, .. } = gate.claim_ordinary() else {
        panic!("phase A is open to an ordinary owner");
    };
    assert!(gate.ordinary_holds(&ticket));
    assert!(gate
        .ordinary_time_left(&ticket)
        .is_some_and(|left| left <= Duration::from_millis(60)));
    assert_eq!(gate.claim_ordinary(), OrdinaryClaim::Await, "one owner");
    // The owner is busy (a read it cannot cut short) across the reserve.
    std::thread::sleep(closes_at.saturating_duration_since(Instant::now()));
    assert!(
        !gate.ordinary_holds(&ticket),
        "the clock alone ends phase A, before the timer thread runs"
    );
    assert!(
        !gate.settle_ordinary(&ticket),
        "a lost owner cannot settle: it writes nothing"
    );
    eventually(|| restores.load(Ordering::SeqCst) == 1);
    timer.finish();
    assert!(gate.restore_started_by_cutoff());
}

#[test]
fn finishing_while_an_ordinary_owner_decides_keeps_the_timer_for_its_turn() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_front_attempt(0));
    gate.front_attempt_returned();
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(40),
        counting_restore(&restores),
    )
    .unwrap();
    let OrdinaryClaim::Decide { .. } = gate.claim_ordinary() else {
        panic!("phase A is open to an ordinary owner");
    };
    // The owner stalls; the bracket finishing must not take its backstop.
    timer.finish();
    assert_eq!(restores.load(Ordering::SeqCst), 1);
}

#[test]
fn a_bracket_ending_under_a_hold_returns_the_decision_with_its_deadline() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_front_attempt(0));
    gate.front_attempt_returned();
    assert!(gate.begin_post(true), "a press whose release failed");
    let timer = CutoffTimer::arm_with_wake(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(5),
        Instant::now() + Duration::from_secs(3600),
        Box::new({
            let restores = Arc::clone(&restores);
            move |_| {
                restores.fetch_add(1, Ordering::SeqCst);
            }
        }),
    )
    .unwrap();
    eventually(|| {
        gate.phase()
            == RestorePhase::Timer {
                awaiting_release: true,
            }
    });
    let finishing = Instant::now();
    timer.finish();
    assert!(
        finishing.elapsed() < Duration::from_secs(5),
        "the caller settles the release only after the bracket returns"
    );
    assert_eq!(restores.load(Ordering::SeqCst), 0);
    assert!(matches!(
        gate.claim_ordinary(),
        OrdinaryClaim::Decide {
            write_deadline: true,
            ..
        }
    ));
}

#[test]
fn a_cleanup_that_knows_input_is_held_ends_a_timer_waiting_for_the_release() {
    let gate = Arc::new(CutoffGate::new());
    let restores = Arc::new(AtomicUsize::new(0));
    assert!(gate.begin_front_attempt(3));
    assert!(gate.begin_post(true));
    let timer = CutoffTimer::arm_with_wake(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(5),
        Instant::now() + Duration::from_secs(3600),
        Box::new({
            let restores = Arc::clone(&restores);
            move |_| {
                restores.fetch_add(1, Ordering::SeqCst);
            }
        }),
    )
    .unwrap();
    eventually(|| {
        gate.phase()
            == RestorePhase::Timer {
                awaiting_release: true,
            }
    });
    assert_eq!(
        gate.claim_forgo(),
        ForgoClaim::Taken {
            front_instant_ms: 3
        }
    );
    timer.finish();
    assert_eq!(restores.load(Ordering::SeqCst), 0);
    assert_eq!(gate.phase(), RestorePhase::Done { by_timer: false });
}
