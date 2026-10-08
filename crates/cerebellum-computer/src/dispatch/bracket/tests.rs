//! The bracket against a fake platform with its own clock, so the bound,
//! the chunking and every way a bracket can stop are checked without a
//! desktop.

use super::*;
use crate::dispatch::seize::{HeartbeatMarker, OBSERVED_DISPATCH_IDLE_MS};
use crate::platform::{HeldStateDisposition, ProcessEventRefusal};

const TARGET: u32 = 200;
const PREVIOUS: u32 = 100;
const OUR_PID: i64 = 7;

/// A desktop on a fake clock. A fronting request takes effect after
/// `front_latency_ms`; each unit takes `unit_ms` to post.
struct FakeDesk {
    now: u64,
    frontmost: Option<u32>,
    pending_front: Option<(u32, u64)>,
    front_latency_ms: u64,
    unit_ms: u64,
    /// Fronting requests for this pid are ignored.
    refuse_front_of: Option<u32>,
    /// Input from another source appears once this many units are posted.
    input_after_units: Option<usize>,
    idle_ms: u64,
    posted: Vec<usize>,
    /// Every interval the target spent frontmost, measured by the desk.
    fronted_since: Option<u64>,
    fronted_intervals: Vec<u64>,
    /// Which application was frontmost when each unit was posted.
    frontmost_at_post: Vec<Option<u32>>,
}

impl FakeDesk {
    fn new() -> Self {
        Self {
            now: 0,
            frontmost: Some(PREVIOUS),
            pending_front: None,
            front_latency_ms: 5,
            unit_ms: 4,
            refuse_front_of: None,
            input_after_units: None,
            idle_ms: OBSERVED_DISPATCH_IDLE_MS + 500,
            posted: Vec::new(),
            fronted_since: None,
            fronted_intervals: Vec::new(),
            frontmost_at_post: Vec::new(),
        }
    }

    fn advance(&mut self, milliseconds: u64) {
        self.now += milliseconds;
        if let Some((pid, at)) = self.pending_front {
            if self.now >= at {
                self.set_frontmost(pid);
                self.pending_front = None;
            }
        }
    }

    fn set_frontmost(&mut self, pid: u32) {
        if self.frontmost == Some(TARGET) && pid != TARGET {
            let since = self.fronted_since.take().unwrap();
            self.fronted_intervals.push(self.now - since);
        }
        if pid == TARGET && self.frontmost != Some(TARGET) {
            self.fronted_since = Some(self.now);
        }
        self.frontmost = Some(pid);
    }
}

impl FrontingBracketHost for FakeDesk {
    type Tap = ();

    fn now_ms(&mut self) -> u64 {
        self.now
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.advance(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        if self.refuse_front_of == Some(pid) {
            return true;
        }
        if pid == TARGET {
            // The interval runs from the request, as the bracket counts it.
            self.fronted_since = Some(self.now);
        }
        self.pending_front = Some((pid, self.now + self.front_latency_ms));
        true
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn create_tap(&mut self) -> Option<()> {
        Some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        IdleReading::Milliseconds(self.idle_ms)
    }
    fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
        match self.input_after_units {
            Some(after) if self.posted.len() >= after => {
                self.input_after_units = None;
                vec![SourcedInputEvent {
                    source_unix_process_id: 0,
                    detection_latency_ms: 1,
                    platform_delivery_latency_ms: None,
                }]
            }
            _ => Vec::new(),
        }
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        HeartbeatProbe {
            marker: HeartbeatMarker::new(1),
            posted_at_ms: self.now,
            our_pid: OUR_PID,
        }
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        probe: HeartbeatProbe,
        _watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        HeartbeatObservation::Seen {
            marker: probe.marker,
            source_unix_process_id: OUR_PID,
            observed_at_ms: probe.posted_at_ms,
        }
    }
    fn post_unit(&mut self, index: usize) -> Result<UnitPosted, SequencePostFailure> {
        self.frontmost_at_post.push(self.frontmost);
        self.posted.push(index);
        self.advance(self.unit_ms);
        Ok(UnitPosted {
            posts_returned: 2,
            generation_verifications: 4,
        })
    }
}

fn plan(units: usize) -> BracketPlan {
    BracketPlan {
        target_pid: TARGET,
        units,
        maximum_interval_ms: 100,
        maximum_seize_detection_latency_ms: 50,
    }
}

fn run(desk: &mut FakeDesk, units: usize) -> BracketReport {
    run_fronting_bracket(desk, &mut UserIdleEstimator::new(), plan(units), &|| false)
}

#[test]
fn already_frontmost_units_still_report_their_bound_overrun() {
    let mut desk = FakeDesk::new();
    desk.set_frontmost(TARGET);
    desk.unit_ms = 101;
    let report = run(&mut desk, 1);
    assert_eq!(report.units_posted, 1);
    assert_eq!(report.restore, RestoreStatus::NotNeeded);
    assert_eq!(report.longest_fronted_interval_ms, 101);
    assert!(!report.held(100));
}

/// Sixty units at 4 ms each cannot fit one 100 ms interval, so the text is
/// split into chunks; every interval the desk measured stays within the
/// bound, every unit was posted while the target was in front, in order, and
/// the previous application is back at the end.
#[test]
fn long_text_is_chunked_so_every_fronted_interval_fits_the_bound() {
    let mut desk = FakeDesk::new();
    let report = run(&mut desk, 60);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.units_posted, 60);
    assert!(report.chunks > 1, "{report:?}");
    assert_eq!(desk.posted, (0..60).collect::<Vec<_>>());
    assert!(desk
        .frontmost_at_post
        .iter()
        .all(|pid| *pid == Some(TARGET)));
    assert_eq!(desk.fronted_intervals.len() as u32, report.chunks);
    assert!(
        desk.fronted_intervals
            .iter()
            .all(|interval| *interval <= 100),
        "{:?}",
        desk.fronted_intervals
    );
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
    assert!(report.held(100));
}

/// A short text fits one chunk.
#[test]
fn short_text_is_one_chunk() {
    let mut desk = FakeDesk::new();
    let report = run(&mut desk, 5);
    assert_eq!(report.chunks, 1);
    assert_eq!(report.units_posted, 5);
    assert!(report.held(100));
}

/// A target that never comes forward posts nothing and is reported as a
/// failed front, with the previous application still in front.
#[test]
fn a_target_that_does_not_come_forward_is_a_front_failure_with_no_posts() {
    let mut desk = FakeDesk::new();
    desk.refuse_front_of = Some(TARGET);
    let report = run(&mut desk, 5);
    assert_eq!(report.stop, Some(BracketStop::FrontFailed));
    assert!(desk.posted.is_empty());
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

/// When the previous application will not come back, the bracket says so,
/// names what was left in front, and fronts nothing more.
#[test]
fn a_failed_restore_names_the_application_left_in_front() {
    let mut desk = FakeDesk::new();
    desk.refuse_front_of = Some(PREVIOUS);
    let report = run(&mut desk, 60);
    assert_eq!(
        report.restore,
        RestoreStatus::Failed {
            left_in_front: Some(TARGET)
        }
    );
    assert_eq!(report.stop, Some(BracketStop::RestoreFailed));
    assert_eq!(report.chunks, 1);
    assert!(report.units_posted < 60);
    assert!(!report.held(100));
}

/// A cancel is honoured at the next chunk boundary: the chunk in progress
/// finishes, the previous application is restored, and nothing more is
/// fronted.
#[test]
fn a_cancel_mid_bracket_stops_at_the_chunk_boundary_after_restoring() {
    let mut desk = FakeDesk::new();
    let chunks_started = std::cell::Cell::new(0);
    let desk_ref = &mut desk;
    let report = {
        let cancel = || {
            chunks_started.set(chunks_started.get() + 1);
            chunks_started.get() > 1
        };
        run_fronting_bracket(desk_ref, &mut UserIdleEstimator::new(), plan(60), &cancel)
    };
    assert_eq!(report.stop, Some(BracketStop::Cancelled));
    assert_eq!(report.chunks, 1);
    assert!(report.units_posted > 0 && report.units_posted < 60);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

/// Input from the person mid-chunk stops the bracket before the next unit,
/// and the previous application is still put back.
#[test]
fn input_that_is_not_ours_stops_the_bracket_and_still_restores() {
    let mut desk = FakeDesk::new();
    desk.input_after_units = Some(3);
    let report = run(&mut desk, 20);
    match report.stop {
        Some(BracketStop::Aborted(abort)) => {
            assert_eq!(abort.reason, AbortReason::UserSeizedControl)
        }
        other => panic!("expected a seize abort, got {other:?}"),
    }
    assert_eq!(report.units_posted, 3);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

/// A person who touched the machine within the idle threshold gets nothing
/// fronted and nothing posted.
#[test]
fn a_person_at_the_desk_is_refused_by_the_idle_gate_before_anything_is_fronted() {
    let mut desk = FakeDesk::new();
    desk.idle_ms = 10;
    let report = run(&mut desk, 5);
    match report.stop {
        Some(BracketStop::Aborted(abort)) => {
            assert!(matches!(abort.reason, AbortReason::IdleGateRefused(_)))
        }
        other => panic!("expected the idle gate, got {other:?}"),
    }
    assert_eq!(report.chunks, 0);
    assert!(desk.posted.is_empty());
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

/// A front that eats the whole bound leaves no room for a unit, so nothing
/// is posted and the bound is reported rather than exceeded.
#[test]
fn a_front_slower_than_the_bound_posts_nothing() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 98;
    let report = run(&mut desk, 5);
    assert_eq!(report.stop, Some(BracketStop::BoundExceeded));
    assert!(desk.posted.is_empty());
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

/// Every unit posted, and only putting the previous application back ran
/// past the bound. The keystrokes were delivered, so this is not a stop: a
/// stop becomes a refusal on the wire, and a refusal for keystrokes that
/// landed would make a caller send them again. The overrun stays visible in
/// the report, which is what the reply discloses.
#[test]
fn a_restore_that_overruns_after_the_last_unit_is_disclosed_not_a_stop() {
    let mut desk = FakeDesk::new();
    // Front and restore each take 49 ms: the one unit fits the prediction
    // (49 + 49 <= 100), and the real interval is 49 + 4 + 49 > 100.
    desk.front_latency_ms = 49;
    let report = run(&mut desk, 1);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.units_posted, 1);
    assert_eq!(desk.posted, vec![0]);
    assert!(report.longest_fronted_interval_ms > 100, "{report:?}");
    assert!(!report.held(100));
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

/// A post failure stops the bracket with the failure's own report.
#[test]
fn a_post_failure_is_reported_with_what_it_left_held() {
    struct Failing(FakeDesk);
    impl FrontingBracketHost for Failing {
        type Tap = ();
        fn now_ms(&mut self) -> u64 {
            self.0.now_ms()
        }
        fn pause_ms(&mut self, milliseconds: u64) {
            self.0.pause_ms(milliseconds)
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            self.0.frontmost_pid()
        }
        fn request_front(&mut self, pid: u32) -> bool {
            self.0.request_front(pid)
        }
        fn our_pid(&self) -> i64 {
            OUR_PID
        }
        fn create_tap(&mut self) -> Option<()> {
            Some(())
        }
        fn read_idle(&mut self) -> IdleReading {
            self.0.read_idle()
        }
        fn drain(&mut self, tap: &()) -> Vec<SourcedInputEvent> {
            self.0.drain(tap)
        }
        fn post_heartbeat(&mut self) -> HeartbeatProbe {
            self.0.post_heartbeat()
        }
        fn observe_heartbeat(
            &mut self,
            tap: &(),
            probe: HeartbeatProbe,
            watcher: &mut SeizeWatcher,
        ) -> HeartbeatObservation {
            self.0.observe_heartbeat(tap, probe, watcher)
        }
        fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
            Err(SequencePostFailure {
                posts_returned: 1,
                refusal: ProcessEventRefusal::Cancelled,
                held_state: HeldStateDisposition::Unknown,
            })
        }
    }
    let mut desk = Failing(FakeDesk::new());
    let report = run_fronting_bracket(&mut desk, &mut UserIdleEstimator::new(), plan(5), &|| false);
    assert!(matches!(report.stop, Some(BracketStop::PostFailed(_))));
    assert_eq!(report.posts_returned, 1);
    assert_eq!(desk.0.frontmost, Some(PREVIOUS));
}
