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
    let timer = CutoffTimer::arm(
        Arc::clone(&gate),
        Instant::now() + Duration::from_millis(5),
        counting_restore(&restores),
    )
    .unwrap();
    gate.disarm();
    std::thread::sleep(Duration::from_millis(30));
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
    assert!(checks.before_post(true, &|| false).is_ok());
    assert!(!gate.fire(), "held: the timer must not restore");
    assert!(
        checks.before_post(false, &|| false).is_err(),
        "no post after the cutoff"
    );
    checks.all_released();
}
