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
