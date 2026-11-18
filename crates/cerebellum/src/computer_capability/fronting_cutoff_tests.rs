//! The bound of an app-use front, run through the real hooks and restore
//! cell. The bracket's own thread is the one owner of the front: nothing
//! restores while it is still busy, it restores exactly once when it comes
//! back, a unit that may hold a key is never restored under, and a front
//! write stalled past the deadline leaves the restore to the late watch.

use super::*;
use cerebellum_computer::dispatch::BracketPlan;
use std::time::Instant;

/// The bracket's bound, in real milliseconds.
const BOUND_MS: u64 = crate::budgets::FRONTING_BRACKET_MS;

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

/// Block, as a capture stuck in the window server would, until the restore
/// reserve of `hooks`' front has started.
fn block_past_reserve_start(hooks: &CellHooks) {
    let until = hooks
        .picture_wait_until()
        .expect("an app-use front has a bound");
    std::thread::sleep(until.saturating_duration_since(Instant::now()) + Duration::from_millis(2));
}

#[test]
fn a_picture_read_blocked_past_the_reserve_start_is_restored_by_its_owner_exactly_once() {
    let screen = Screen::new(&mail_desk());
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = screen.clone();
    let blocked = hooks.clone();
    let mut restored_while_reading = None;
    let mut read = || {
        block_past_reserve_start(&blocked);
        restored_while_reading = Some(restores(&reader) > 0);
    };
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut read),
    );
    assert_eq!(
        restored_while_reading,
        Some(false),
        "nothing restores while the owner is still in its read: {:?}",
        screen.log()
    );
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(restores(&screen), 1, "one restore: {:?}", screen.log());
    assert_eq!(screen.frontmost(), Some(PREVIOUS));
    let end = hooks.end();
    assert_eq!(
        end.cell.and_then(|cell| cell.decided()).map(|d| d.restore),
        Some(RestoreStatus::Restored),
        "the cell holds the owner's one decision"
    );
    assert_eq!(lock_releases(&releases), 1, "the lock was released once");
}

#[test]
fn a_unit_that_may_hold_a_key_past_the_bound_is_never_restored_under() {
    let screen = Screen::new(&mail_desk());
    // The fake chord does not check the cutoff at each of its posts, so the
    // bracket counts the whole unit as holding a key.
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
    // Held through the deadline: the restore follows the release without
    // one, rather than being refused.
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(lock_releases(&releases), 1);
}

#[test]
fn a_bracket_inside_its_bound_restores_itself_and_nothing_restores_after_it() {
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

#[test]
fn a_slow_registration_does_not_move_the_cutoff_past_the_bound() {
    let screen = Screen::new(&mail_desk());
    // Registration takes most of the bound. The reserve counts from the
    // stamp made before it, not from when registration returned.
    screen.state().register_blocks_ms = BOUND_MS * 2 / 5;
    let (hooks, _releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let blocked = hooks.clone();
    let mut read = || block_past_reserve_start(&blocked);
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
fn a_front_write_stalled_past_the_deadline_hands_the_restore_to_the_late_watch() {
    let screen = Screen::new(&mail_desk());
    // The activation request blocks well past the bound, as a native stall
    // the cap on the target's messages cannot cut short.
    screen.state().front_blocks_ms = 2 * BOUND_MS;
    screen.state().front_ignores_cap = true;
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let expired = crate::terminal_arbiter::restore_preparation::expired_writes();
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
        [format!("front:{TARGET}"), "front-returned".to_owned()],
        "the owner, back past the deadline, writes no restore of its own"
    );
    assert!(matches!(
        outcome.report.restore,
        RestoreStatus::Failed { .. }
    ));
    assert!(crate::terminal_arbiter::restore_preparation::expired_writes() > expired);
    assert!(outcome.report.restore_started_by_cutoff);
    assert_eq!(outcome.report.units_posted, 0);
    // The late watch is owed the restore, and keeps the fronting lock until
    // it has run.
    let cell = hooks.cell().expect("registered");
    assert!(cell.late_watch_pending(), "{log:?}");
    assert_eq!(lock_releases(&releases), 0);
}

#[test]
fn a_hung_target_front_write_is_capped_at_the_reserve_start_and_the_restore_is_made_by_the_deadline(
) {
    let screen = Screen::new(&mail_desk());
    // The target does not answer its front write for far longer than the
    // bound; its messaging timeout is what ends the wait.
    screen.state().front_blocks_ms = 30 * BOUND_MS;
    let (hooks, _releases) = app_use_hooks();
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
    assert_eq!(
        screen.log(),
        [
            format!("front:{TARGET}"),
            "front-timed-out".to_owned(),
            format!("restore:{PREVIOUS}"),
        ],
        "the hung write gave up at the cap, then the owner restored"
    );
    let restored_after = first_restore_after(&screen, started);
    assert!(
        restored_after <= Duration::from_millis(BOUND_MS),
        "restore requested {restored_after:?} after the bracket began, past the deadline"
    );
    assert_eq!(outcome.report.units_posted, 0);
    assert!(
        screen.state().target_wait_until.is_none(),
        "the cap is lifted once the restore begins"
    );
}

#[test]
fn an_already_frontmost_picture_runs_with_a_fence_and_a_bounded_hold() {
    let screen = Screen::new(&mail_desk());
    screen.desk.state().frontmost = Some(TARGET);
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let mut read_ran = false;
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        plan(),
        &|| false,
        boxed.as_mut(),
        Some(&mut || {
            read_ran = true;
            assert!(
                hooks.picture_may_acquire(),
                "an in-time picture is admitted"
            );
            let cell = hooks.cell().expect("a no-switch read owns a cell");
            let _hold = cell
                .hold_lock_for_read(Duration::from_millis(2 * BOUND_MS))
                .unwrap();
            block_past_reserve_start(&hooks);
            assert!(!hooks.picture_may_acquire(), "native acquisition is fenced");
            assert_eq!(
                lock_releases(&releases),
                0,
                "held while capture is still within its lifetime"
            );
            let give_up = Instant::now() + crate::test_support::HANG_GUARD;
            while lock_releases(&releases) == 0 && Instant::now() < give_up {
                std::thread::sleep(Duration::from_millis(1));
            }
            assert_eq!(
                lock_releases(&releases),
                1,
                "the watchdog lets another front proceed"
            );
        }),
    );
    assert!(read_ran);
    assert!(hooks.cutoff_fired(), "the read ended past its cutoff");
    assert_eq!(outcome.report.restore, RestoreStatus::NotNeeded);
    assert!(!outcome.report.restore_started_by_cutoff);
    assert!(
        screen.log().is_empty(),
        "neither a front nor a restore was requested"
    );
    assert_eq!(screen.frontmost(), Some(TARGET));
    assert_eq!(lock_releases(&releases), 1);
}

#[test]
fn a_picture_read_past_admission_when_the_cutoff_passes_keeps_the_lock_and_acquires_nothing() {
    let screen = Screen::new(&mail_desk());
    let (hooks, releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let reader = hooks.clone();
    let mut released_during_read = None;
    let mut acquired = true;
    // As a fronted picture read does: hold the lock, pass admission, block
    // in the visibility inspection, then ask the fence right before the
    // pixels would be requested.
    let mut read = || {
        let _hold = reader.hold_lock_for_read().expect("bounded hold");
        block_past_reserve_start(&reader);
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
        "the fronting lock is not released under a read in flight"
    );
    assert!(!acquired, "no pixels are acquired once the reserve started");
    assert_eq!(
        lock_releases(&releases),
        1,
        "released once the read returned and the restore was decided"
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
        let _hold = reader.hold_lock_for_read().expect("bounded hold");
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
fn a_restore_after_a_long_read_is_sampled_at_its_own_cost_not_the_readers_wait() {
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
    let blocked = hooks.clone();
    let mut read = || block_past_reserve_start(&blocked);
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

#[test]
fn a_picture_may_not_acquire_once_the_reserve_starts_whatever_the_owner_is_doing() {
    let screen = Screen::new(&mail_desk());
    let (hooks, _releases) = app_use_hooks();
    let mut boxed = boxed_hooks(&hooks);
    let gate = Arc::new(cerebellum_computer::dispatch::CutoffGate::new());
    let far = Instant::now() + Duration::from_secs(3600);
    gate.set_bound(far, far);
    assert!(boxed.register(
        PREVIOUS,
        TARGET,
        Box::new(FakeRestore(screen.clone())),
        &gate
    ));
    assert!(hooks.picture_may_acquire(), "inside the bound");
    // The owner is busy elsewhere; the clock alone closes the fence.
    gate.set_bound(Instant::now() - Duration::from_millis(1), far);
    assert!(!hooks.picture_may_acquire());
}
