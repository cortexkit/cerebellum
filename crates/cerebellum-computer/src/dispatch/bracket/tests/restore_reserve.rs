//! The reserve for recent restore costs, replayed against the twenty
//! Command-A chords of a desk run on which every restore of the person's
//! application took about 175 ms, because the first restore route never took
//! effect and the second one is asked only 150 ms in.

use super::*;
use latency::{RestoreLatencies, UnitPostCosts};

/// Request to target frontmost for each attempt that fronted, in whole
/// milliseconds (the run's seventh chord was refused before its front).
const FRONTS: [u64; 19] = [
    88, 39, 35, 28, 24, 32, 39, 44, 37, 28, 28, 23, 26, 21, 27, 30, 29, 62, 24,
];
/// Restore request to the person's application confirmed back, every attempt.
const RESTORE_MS: u64 = 175;
const ATTEMPT_SPACING_MS: u64 = 5_100;

/// Replay the attempts in one process, as after a restart, with a 3 ms post
/// and the call's 300 ms restore wait. Returns each attempt's report.
fn replay() -> Vec<BracketReport> {
    let mut restores = RestoreLatencies::new();
    let mut units = Some(UnitPostCosts::new());
    let origin = std::time::Instant::now();
    let mut reports = Vec::new();
    for (index, front) in FRONTS.into_iter().enumerate() {
        let mut desk = FakeDesk::new();
        desk.restore_latencies = std::mem::replace(&mut restores, RestoreLatencies::new());
        desk.unit_costs = units.take();
        desk.clock_origin = origin;
        desk.clock_offset_ms = index as u64 * ATTEMPT_SPACING_MS;
        desk.front_latency_ms = front;
        desk.unit_ms = 3;
        desk.restore_latency_ms = Some(RESTORE_MS);
        desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
        reports.push(run(&mut desk, 1));
        restores = std::mem::replace(&mut desk.restore_latencies, RestoreLatencies::new());
        units = desk.unit_costs.take();
    }
    reports
}

/// Every chord refuses before posting. The first refuses with no restore
/// measured yet, and the eighteenth's 62 ms front, counted again for its own
/// restore, overruns by itself; every other refusal is only the measured
/// slow restores, and says so, so the agent is told the person's application
/// was slow to come back rather than to send shorter text.
#[test]
fn slow_restores_refuse_later_chords_and_mark_the_refusal_as_waiting_on_them() {
    let reports = replay();
    for (index, report) in reports.iter().enumerate() {
        let attempt = index + 1;
        assert_eq!(report.units_posted, 0, "attempt {attempt}: {report:?}");
        assert_eq!(
            report.stop,
            Some(BracketStop::BoundExceeded),
            "attempt {attempt}: {report:?}"
        );
        assert!(
            !report.waiting_out_slow_post,
            "attempt {attempt}: {report:?}"
        );
        assert_eq!(
            report.waiting_out_slow_restore,
            ![1, 18].contains(&attempt),
            "attempt {attempt}: {report:?}"
        );
    }
}

/// A chord whose own front leaves room for its post and a restore as fast as
/// its front is admitted when recent restores were fast, and the flag stays
/// clear.
#[test]
fn a_chord_that_fits_is_not_marked_as_waiting_on_slow_restores() {
    let mut desk = FakeDesk::new();
    desk.restore_latencies.record(20);
    desk.front_latency_ms = 25;
    desk.unit_ms = 3;
    desk.restore_latency_ms = Some(20);
    let report = run(&mut desk, 1);
    assert_eq!(report.stop, None, "{report:?}");
    assert!(!report.waiting_out_slow_restore, "{report:?}");
}
