//! The hard cutoff of an app-use front, run through the real hooks and
//! restore cell: the timer starts the restore at the bound while the
//! bracket's own thread is still blocked, the restore runs once whichever
//! side reaches the cell first, and a unit that may hold a key is never
//! restored under.

use super::*;
use cerebellum_computer::dispatch::BracketPlan;
use std::time::Instant;

/// The bracket's bound, in real milliseconds for the timer.
const BOUND_MS: u64 = 100;

fn app_use_hooks() -> (CellHooks, Arc<std::sync::atomic::AtomicUsize>) {
    let releases = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hooks = CellHooks::new(ObligationParts {
        terminal: under_terminal(),
        lock: Some(Box::new(CountedLock(Arc::clone(&releases)))),
        target_name: "Mail".into(),
        mode: crate::terminal_arbiter::FrontingMode::Background,
        purpose: crate::terminal_arbiter::FrontingPurpose::NeedsFront,
        restore_fallback: true,
    });
    (hooks, releases)
}

fn lock_releases(releases: &std::sync::atomic::AtomicUsize) -> usize {
    releases.load(std::sync::atomic::Ordering::SeqCst)
}

fn plan() -> BracketPlan {
    BracketPlan {
        target_pid: TARGET,
        units: 1,
        maximum_interval_ms: BOUND_MS,
        maximum_seize_detection_latency_ms: 50,
    }
}

fn restores(screen: &Screen) -> usize {
    let restore = format!("restore:{PREVIOUS}");
    screen
        .log()
        .iter()
        .filter(|entry| **entry == restore)
        .count()
}

#[test]
fn a_blocked_picture_read_has_its_restore_started_by_the_cutoff_exactly_once() {
    let screen = Screen::new(&mail_desk());
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = screen.clone();
    let mut restored_while_reading = false;
    let started = Instant::now();
    let mut read = || {
        // The capture blocks until something else puts the previous
        // application back, as a capture stuck in the window server would.
        let give_up = Instant::now() + crate::test_support::HANG_GUARD;
        while Instant::now() < give_up {
            if restores(&reader) > 0 {
                restored_while_reading = true;
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut read),
    );
    assert!(
        restored_while_reading,
        "no restore while the read was blocked: {:?}",
        screen.log()
    );
    assert!(started.elapsed() >= Duration::from_millis(BOUND_MS));
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(restores(&screen), 1, "one restore: {:?}", screen.log());
    assert_eq!(screen.frontmost(), Some(PREVIOUS));
    let end = hooks.end();
    assert_eq!(
        end.cell.and_then(|cell| cell.decided()).map(|d| d.restore),
        Some(RestoreStatus::Restored),
        "the worker and the timer shared the cell's one decision"
    );
    assert_eq!(lock_releases(&releases), 1, "the lock was released once");
}

#[test]
fn a_unit_that_may_hold_a_key_past_the_bound_is_never_restored_under() {
    let screen = Screen::new(&mail_desk());
    // The fake chord does not check the cutoff at each of its posts, so the
    // bracket holds the cutoff for the whole unit.
    screen.state().post_blocks_ms = 3 * BOUND_MS;
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        None,
    );
    let log = screen.log();
    assert_eq!(
        log,
        [
            format!("front:{TARGET}"),
            "post".to_owned(),
            "post-done".to_owned(),
            format!("restore:{PREVIOUS}"),
        ],
        "the restore waited for the unit"
    );
    assert!(!outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(lock_releases(&releases), 1);
}

#[test]
fn a_bracket_inside_its_bound_restores_itself_and_leaves_no_timer_running() {
    let screen = Screen::new(&mail_desk());
    let (hooks, _releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        None,
    );
    assert!(!outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.units_posted, 1);
    assert_eq!(restores(&screen), 1);
    std::thread::sleep(Duration::from_millis(2 * BOUND_MS));
    assert_eq!(restores(&screen), 1, "nothing restored after the bracket");
}

/// When the restore was first requested, measured from `started`.
fn first_restore_after(screen: &Screen, started: Instant) -> Duration {
    screen
        .state()
        .restore_requested_at
        .first()
        .map(|at| at.saturating_duration_since(started))
        .expect("a restore was requested")
}

/// A picture read that blocks until the previous application is back.
fn blocked_read(screen: &Screen) -> impl FnMut() + '_ {
    move || {
        let give_up = Instant::now() + crate::test_support::HANG_GUARD;
        while Instant::now() < give_up && restores(screen) == 0 {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn a_slow_registration_does_not_move_the_cutoff_past_the_bound() {
    let screen = Screen::new(&mail_desk());
    // Registration takes most of the bound before the timer is armed. The
    // cutoff counts from the stamp made before it, not from the arming.
    screen.state().register_blocks_ms = BOUND_MS * 4 / 5;
    let (hooks, _releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = screen.clone();
    let mut read = blocked_read(&reader);
    let started = Instant::now();
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut read),
    );
    let restored_after = first_restore_after(&screen, started);
    assert!(
        restored_after < Duration::from_millis(BOUND_MS + BOUND_MS / 2),
        "the restore was requested {restored_after:?} after the bracket began, past the bound"
    );
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(restores(&screen), 1, "{:?}", screen.log());
}

#[test]
fn a_registration_that_outlasts_the_bound_fronts_nothing() {
    let screen = Screen::new(&mail_desk());
    screen.state().register_blocks_ms = BOUND_MS * 3 / 2;
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        None,
    );
    assert!(
        !screen.log().iter().any(|entry| entry.starts_with("front:")),
        "the bound passed before the front was requested: {:?}",
        screen.log()
    );
    assert_eq!(outcome.report.units_posted, 0);
    assert_eq!(outcome.report.restore, RestoreStatus::NotNeeded);
    assert_eq!(lock_releases(&releases), 1);
}

#[test]
fn the_cutoff_requests_the_restore_at_once_while_the_activation_is_still_in_flight() {
    let screen = Screen::new(&mail_desk());
    // The activation request blocks well past the bound.
    let front_blocks_ms = 2 * BOUND_MS;
    screen.state().front_blocks_ms = front_blocks_ms;
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let started = Instant::now();
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        None,
    );
    let log = screen.log();
    assert_eq!(
        log,
        [
            format!("front:{TARGET}"),
            format!("restore:{PREVIOUS}"),
            "front-returned".to_owned(),
        ],
        "the restore is requested at the cutoff, not after the activation returns"
    );
    // The hard bound on the restore request: the cutoff, plus scheduling.
    let restored_after = first_restore_after(&screen, started);
    assert!(
        restored_after < Duration::from_millis(BOUND_MS + BOUND_MS / 2),
        "restore requested {restored_after:?} after the bracket began"
    );
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.units_posted, 0);
    // The activation landed after the restore request: the late watch is
    // owed it, and keeps the fronting lock until it has run.
    let cell = hooks.cell().expect("registered");
    assert!(cell.late_watch_pending(), "{log:?}");
    assert_eq!(lock_releases(&releases), 0);
}

#[test]
fn a_picture_read_past_admission_when_the_cutoff_fires_keeps_the_lock_and_acquires_nothing() {
    let screen = Screen::new(&mail_desk());
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = hooks.clone();
    let mut released_during_read = None;
    let mut acquired = false;
    // As a fronted picture read does: hold the lock, pass admission, block
    // in the visibility inspection, then ask the fence right before the
    // pixels would be requested.
    let mut read = || {
        let _hold = reader.hold_lock_for_read();
        let give_up = Instant::now() + crate::test_support::HANG_GUARD;
        while Instant::now() < give_up
            && !reader.cell().is_some_and(|cell| cell.decided().is_some())
        {
            std::thread::sleep(Duration::from_millis(1));
        }
        released_during_read = Some(lock_releases(&releases));
        acquired = reader.picture_may_acquire();
    };
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut read),
    );
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(restores(&screen), 1, "{:?}", screen.log());
    assert_eq!(
        released_during_read,
        Some(0),
        "the cutoff's restore must not release the fronting lock under a read in flight"
    );
    assert!(!acquired, "no pixels are acquired once the cutoff fired");
    assert_eq!(
        lock_releases(&releases),
        1,
        "released once the read returned"
    );
}

#[test]
fn a_picture_read_inside_the_bound_may_acquire() {
    let screen = Screen::new(&mail_desk());
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = hooks.clone();
    let mut acquired = false;
    let mut read = || {
        let _hold = reader.hold_lock_for_read();
        acquired = reader.picture_may_acquire();
    };
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut read),
    );
    assert!(acquired);
    assert!(!outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(lock_releases(&releases), 1);
}

#[test]
fn a_restore_the_cutoff_ran_is_sampled_at_its_own_cost_not_the_readers_wait() {
    let screen = Screen::new(&mail_desk());
    {
        // The first request to put the previous application back is ignored,
        // so the restore takes its fallback after the fallback delay.
        let mut state = screen.state();
        state.restores_ignored = 1;
        state.fallback_works = true;
    }
    let (hooks, _releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = screen.clone();
    let mut read = || {
        // Blocks until the previous application is back, so the bracket's
        // thread reads the cutoff's decision only once the restore is done.
        let give_up = Instant::now() + crate::test_support::HANG_GUARD;
        while Instant::now() < give_up && reader.frontmost() != Some(PREVIOUS) {
            std::thread::sleep(Duration::from_millis(1));
        }
    };
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut read),
    );
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    let sampled = screen.state().measured_restore_ms;
    assert!(
        sampled >= Some(cerebellum_computer::dispatch::RESTORE_FALLBACK_AFTER_MS),
        "the restore took at least the fallback delay, but was sampled at {sampled:?}"
    );
}
