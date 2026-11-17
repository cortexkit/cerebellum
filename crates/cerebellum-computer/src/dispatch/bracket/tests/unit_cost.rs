//! The reserve for recent unit post costs, replayed against twenty
//! Command-A chords measured on a live macOS desktop with about 400 windows.

use super::*;
use latency::{RestoreLatencies, UnitPostCosts, UNIT_POST_COST_MAX_AGE};

/// Each measured Command-A attempt to a background TextEdit, in whole
/// milliseconds: request to
/// target frontmost, target frontmost to restore request (the chord's post),
/// and restore request to the person's application confirmed back. Attempts
/// 1 and 18 were refused before posting, so their post was never measured.
const RUN: [(u64, u64, u64); 20] = [
    (100, 0, 25),
    (25, 80, 14),
    (19, 151, 24),
    (26, 115, 42),
    (36, 85, 13),
    (36, 108, 20),
    (32, 114, 22),
    (37, 76, 23),
    (27, 77, 17),
    (32, 87, 17),
    (32, 87, 19),
    (24, 75, 17),
    (33, 71, 11),
    (32, 85, 15),
    (17, 63, 19),
    (36, 132, 17),
    (48, 187, 17),
    (60, 0, 32),
    (50, 167, 36),
    (37, 183, 17),
];
/// The measured attempts were spaced this far apart.
const ATTEMPT_SPACING_MS: u64 = 5_100;
/// What a chord's post costs once the window-server listing is read before
/// the front: two generation checks and one post call per event.
const POST_WITHOUT_LISTING_MS: u64 = 3;

/// Replay the measured attempts (`RUN`) in one process: the restore and unit post costs carry
/// from attempt to attempt, seeded with the run's first measured restore. `post`
/// gives each attempt's post cost from the measured one. Returns each attempt's
/// report, in order.
fn replay(post: impl Fn(u64) -> u64) -> Vec<BracketReport> {
    let mut restores = RestoreLatencies::new();
    restores.record(RUN[0].2);
    let mut units = Some(UnitPostCosts::new());
    let origin = std::time::Instant::now();
    let mut reports = Vec::new();
    for (index, (front, run_post, restore)) in RUN.into_iter().enumerate() {
        let mut desk = FakeDesk::new();
        desk.restore_latencies = std::mem::replace(&mut restores, RestoreLatencies::new());
        desk.unit_costs = units.take();
        desk.clock_origin = origin;
        desk.clock_offset_ms = index as u64 * ATTEMPT_SPACING_MS;
        desk.front_latency_ms = front;
        desk.unit_ms = post(run_post);
        desk.restore_latency_ms = Some(restore);
        reports.push(run(&mut desk, 1));
        restores = std::mem::replace(&mut desk.restore_latencies, RestoreLatencies::new());
        units = desk.unit_costs.take();
    }
    reports
}

/// The attempts, numbered from 1, that posted their chord.
fn posted(reports: &[BracketReport]) -> Vec<usize> {
    reports
        .iter()
        .enumerate()
        .filter(|(_, report)| report.units_posted > 0)
        .map(|(index, _)| index + 1)
        .collect()
}

/// With the measured post costs, a chord posts only while no slow post is
/// in the reserve: the second attempt (no post measured yet) and the
/// fourteenth (the second attempt's sample is past its minute). Every other
/// attempt refuses before posting, instead of the 17 overruns measured on the desktop.
#[test]
fn the_desk_runs_slow_posts_refuse_later_chords_before_posting() {
    let reports = replay(|post| post);
    assert_eq!(posted(&reports), vec![2, 14], "{reports:#?}");
    for (index, report) in reports.iter().enumerate() {
        let attempt = index + 1;
        if report.units_posted > 0 {
            continue;
        }
        assert_eq!(report.posts_returned, 0, "attempt {attempt}: {report:?}");
        assert_eq!(
            report.stop,
            Some(BracketStop::BoundExceeded),
            "attempt {attempt}: {report:?}"
        );
        // Attempt 1's front fills the allowance. Later slow-post reserves
        // refuse before activation, so their unmeasured front cost is irrelevant.
        assert_eq!(
            report.waiting_out_slow_post,
            attempt != 1,
            "attempt {attempt}: {report:?}"
        );
    }
}

/// A 90 ms post refuses chords that would otherwise fit until a minute has
/// passed since it was measured, and the first chord after that is admitted.
#[test]
fn a_slow_post_is_waited_out_and_then_ages_out() {
    let origin = std::time::Instant::now();
    let chord_at = |offset_ms: u64| {
        let mut desk = FakeDesk::new();
        let mut costs = UnitPostCosts::new();
        costs.record(90, origin);
        desk.unit_costs = Some(costs);
        desk.clock_origin = origin;
        desk.clock_offset_ms = offset_ms;
        let report = run(&mut desk, 1);
        (report, desk.posted)
    };
    let max_age = UNIT_POST_COST_MAX_AGE.as_millis() as u64;

    let (report, posted) = chord_at(max_age - 1_000);
    assert_eq!(report.stop, Some(BracketStop::BoundExceeded), "{report:?}");
    assert!(report.waiting_out_slow_post, "{report:?}");
    assert!(posted.is_empty(), "{posted:?}");

    let (report, posted) = chord_at(max_age);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(posted, vec![0]);
    assert!(report.held(100), "{report:?}");
}

/// Once the listing is read before the front, a chord's post is a few
/// milliseconds, and the reserve for it admits every attempt whose front and
/// restore fit. Attempt 1's front fills the allowance; attempts 18 and 19 came
/// forward in 60 and 50 ms, and that front time is also reserved for the
/// restore. Attempt 19's front and restore fill the bound exactly, so its
/// 3 ms post reserve is what refuses it, and a retry may fit. Every admitted
/// chord holds the bound.
#[test]
fn with_the_listing_read_before_the_front_the_reserve_admits_the_run() {
    let reports = replay(|_| POST_WITHOUT_LISTING_MS);
    let refused: Vec<usize> = (1..=RUN.len())
        .filter(|attempt| !posted(&reports).contains(attempt))
        .collect();
    assert_eq!(refused, vec![1, 18, 19], "{reports:#?}");
    for (index, report) in reports.iter().enumerate() {
        let attempt = index + 1;
        if report.units_posted > 0 {
            assert!(report.held(100), "attempt {attempt}: {report:?}");
        } else {
            assert_eq!(
                report.waiting_out_slow_post,
                attempt == 19,
                "attempt {attempt}: {report:?}"
            );
        }
    }
}
