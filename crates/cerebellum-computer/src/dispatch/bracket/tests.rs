//! The bracket against a fake platform with its own clock, so the bound,
//! the chunking and every way a bracket can stop are checked without a
//! desktop.

use super::*;
use crate::dispatch::seize::{HeartbeatMarker, IdleGateRefusal, OBSERVED_DISPATCH_IDLE_MS};
use crate::platform::{HeldStateDisposition, ProcessEventRefusal};

const TARGET: u32 = 200;
const PREVIOUS: u32 = 100;
const THIRD: u32 = 300;
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
    /// Every fronting request, in order.
    front_requests: Vec<u32>,
    /// The newest hardware input the process-wide observer saw.
    hardware_input_ms: Option<u64>,
    /// `(unit, pid, input)`: once unit `unit` is posted, the application with
    /// `pid` comes to the front, with hardware input recorded when `input` is
    /// set.
    switch_after_unit: Option<(usize, u32, bool)>,
    /// Set by a fronted read; the next frontmost read then sees the person's
    /// switch to `THIRD`, with hardware input.
    switch_after_read: Option<std::rc::Rc<std::cell::Cell<bool>>>,
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
            front_requests: Vec::new(),
            hardware_input_ms: None,
            switch_after_unit: None,
            switch_after_read: None,
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
        if let Some(read) = &self.switch_after_read {
            if read.replace(false) {
                self.set_frontmost(THIRD);
                self.hardware_input_ms = Some(self.now);
            }
        }
        self.frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.front_requests.push(pid);
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
        if let Some((after, pid, input)) = self.switch_after_unit {
            if after == index {
                self.set_frontmost(pid);
                if input {
                    self.hardware_input_ms = Some(self.now);
                }
            }
        }
        Ok(UnitPosted {
            posts_returned: 2,
            generation_verifications: 4,
        })
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: self.hardware_input_ms,
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

fn admitted() -> FrontingAdmission {
    FrontingAdmission {
        app_use_fronting_admitted: true,
    }
}

fn run_admitted(desk: &mut FakeDesk, units: usize) -> BracketOutcome {
    run_fronting_bracket_with(
        desk,
        &mut UserIdleEstimator::new(),
        plan(units),
        admitted(),
        &|| false,
    )
}

/// A desk whose unit posts fail, leaving `held_state` behind.
struct FailingDesk {
    desk: FakeDesk,
    held_state: HeldStateDisposition,
}

impl FrontingBracketHost for FailingDesk {
    type Tap = ();
    fn now_ms(&mut self) -> u64 {
        self.desk.now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.desk.pause_ms(milliseconds)
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.desk.frontmost_pid()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.desk.request_front(pid)
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn create_tap(&mut self) -> Option<()> {
        Some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        self.desk.read_idle()
    }
    fn drain(&mut self, tap: &()) -> Vec<SourcedInputEvent> {
        self.desk.drain(tap)
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        self.desk.post_heartbeat()
    }
    fn observe_heartbeat(
        &mut self,
        tap: &(),
        probe: HeartbeatProbe,
        watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        self.desk.observe_heartbeat(tap, probe, watcher)
    }
    fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
        Err(SequencePostFailure {
            posts_returned: 1,
            refusal: ProcessEventRefusal::Cancelled,
            held_state: self.held_state,
        })
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.desk.hardware_input_snapshot()
    }
}

fn failing(held_state: HeldStateDisposition) -> FailingDesk {
    FailingDesk {
        desk: FakeDesk::new(),
        held_state,
    }
}

fn run_failing(desk: &mut FailingDesk, admission: FrontingAdmission) -> BracketOutcome {
    run_fronting_bracket_with(
        desk,
        &mut UserIdleEstimator::new(),
        plan(5),
        admission,
        &|| false,
    )
}

/// A two-unit chord whose first chunk ended with the person switching to a
/// third application by hand: the restore is skipped, and the bracket stops
/// there, so the target is never fronted over the person a second time.
#[test]
fn a_skipped_restore_stops_the_bracket_so_no_later_chunk_fronts() {
    let mut desk = FakeDesk::new();
    // One 60 ms unit and its restore fill a 100 ms chunk, so each unit is
    // its own chunk.
    desk.unit_ms = 60;
    desk.switch_after_unit = Some((0, THIRD, true));
    let outcome = run_admitted(&mut desk, 2);
    let report = &outcome.report;
    assert_eq!(
        report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert_eq!(desk.front_requests, [TARGET], "no second front, no restore");
    assert_eq!(report.chunks, 1);
    assert_eq!(report.units_posted, 1);
    match report.stop {
        Some(BracketStop::Aborted(abort)) => {
            assert_eq!(abort.reason, AbortReason::UserSeizedControl);
            assert_eq!(abort.stopped_action_index, 1);
        }
        ref other => panic!("expected the person's switch to stop the bracket, got {other:?}"),
    }
    assert!(outcome.person_input_during_fronting);
    assert!(!report.held(100));
    assert_eq!(desk.frontmost, Some(THIRD));
}

/// The same switch in a build without app-use fronting admission is put
/// back, and the next chunk fronts again, exactly as before.
#[test]
fn without_admission_a_persons_switch_is_restored_as_before() {
    let mut desk = FakeDesk::new();
    desk.unit_ms = 60;
    desk.switch_after_unit = Some((0, THIRD, true));
    let report = run(&mut desk, 2);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS, TARGET, PREVIOUS]);
    assert_eq!(report.units_posted, 2);
    assert_eq!(report.stop, None);
}

/// A third application the action itself brought forward, with no hardware
/// input, is restored over.
#[test]
fn a_switch_with_no_hardware_input_is_restored() {
    let mut desk = FakeDesk::new();
    desk.switch_after_unit = Some((0, THIRD, false));
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert!(!outcome.person_input_during_fronting);
}

/// Hardware input while the target stays in front restores, and is
/// disclosed.
#[test]
fn input_while_the_target_stays_in_front_restores_and_is_disclosed() {
    let mut desk = FakeDesk::new();
    desk.switch_after_unit = Some((0, TARGET, true));
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert!(outcome.person_input_during_fronting);
}

/// Under admission, a post failure that may have left a key held ends the
/// bracket with no restore request: the previous application would receive
/// the held key. The restore is handed to the caller, and until it runs the
/// report names the target left in front.
#[test]
fn an_admitted_post_failure_with_unknown_held_state_requests_no_restore() {
    let mut desk = failing(HeldStateDisposition::Unknown);
    let outcome = run_failing(&mut desk, admitted());
    assert!(matches!(
        outcome.report.stop,
        Some(BracketStop::PostFailed(_))
    ));
    assert_eq!(
        desk.desk.front_requests,
        [TARGET],
        "no request_front(previous)"
    );
    assert_eq!(desk.desk.frontmost, Some(TARGET));
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::Failed {
            left_in_front: Some(TARGET)
        }
    );
    assert_eq!(
        outcome.deferred_restore,
        Some(DeferredRestore {
            previous: PREVIOUS,
            target: TARGET,
            front_instant_ms: 0,
        })
    );
}

/// Once settling confirms the release, the deferred restore runs the
/// restore decision and brings the previous application back.
#[test]
fn a_deferred_restore_runs_once_the_release_is_confirmed() {
    let mut desk = failing(HeldStateDisposition::Unknown);
    let mut outcome = run_failing(&mut desk, admitted());
    finish_deferred_restore(&mut desk, &mut outcome, true, 100);
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(outcome.deferred_restore, None);
    assert_eq!(desk.desk.front_requests, [TARGET, PREVIOUS]);
    assert_eq!(desk.desk.frontmost, Some(PREVIOUS));
}

/// A release that stays unconfirmed requests no restore at all, and the
/// restore is reported failed with the target named as left in front.
#[test]
fn a_deferred_restore_with_an_unconfirmed_release_requests_nothing() {
    let mut desk = failing(HeldStateDisposition::Unknown);
    let mut outcome = run_failing(&mut desk, admitted());
    finish_deferred_restore(&mut desk, &mut outcome, false, 100);
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::Failed {
            left_in_front: Some(TARGET)
        }
    );
    assert_eq!(outcome.deferred_restore, None);
    assert_eq!(desk.desk.front_requests, [TARGET]);
}

/// A post failure whose sequence posted every release itself restores in
/// the bracket, as it always did.
#[test]
fn an_admitted_post_failure_that_released_everything_restores_in_the_bracket() {
    for held_state in [
        HeldStateDisposition::NoneHeld,
        HeldStateDisposition::Released { posts_returned: 1 },
    ] {
        let mut desk = failing(held_state);
        let outcome = run_failing(&mut desk, admitted());
        assert_eq!(
            outcome.report.restore,
            RestoreStatus::Restored,
            "{held_state:?}"
        );
        assert_eq!(outcome.deferred_restore, None);
        assert_eq!(desk.desk.front_requests, [TARGET, PREVIOUS]);
    }
}

/// Without admission, even an unknown held state restores right away, which
/// is today's order.
#[test]
fn without_admission_an_unknown_post_failure_restores_as_before() {
    let mut desk = failing(HeldStateDisposition::Unknown);
    let outcome = run_failing(&mut desk, FrontingAdmission::default());
    assert_eq!(outcome.report.restore, RestoreStatus::Restored);
    assert_eq!(outcome.deferred_restore, None);
    assert_eq!(desk.desk.front_requests, [TARGET, PREVIOUS]);
}

/// A fronted read decides its restore on the host's hardware input, not the
/// default of none: the reading wrapper forwards the snapshot.
#[test]
fn a_fronted_read_skips_the_restore_after_the_persons_switch() {
    let mut desk = FakeDesk::new();
    let read_happened = std::rc::Rc::new(std::cell::Cell::new(false));
    desk.switch_after_read = Some(read_happened.clone());
    let outcome = run_fronting_read_with(
        &mut desk,
        &mut UserIdleEstimator::new(),
        plan(1),
        admitted(),
        &|| false,
        &mut || read_happened.set(true),
    );
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
}

#[test]
fn a_skipped_restore_is_not_held() {
    let mut desk = FakeDesk::new();
    desk.switch_after_unit = Some((0, THIRD, true));
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(outcome.report.stop, None, "every unit was posted");
    assert!(matches!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson { .. }
    ));
    assert!(!outcome.report.held(100));
}

/// The skipped restore lives in memory only: it cannot be serialized, and
/// no stored form decodes to it. The stored variants are unchanged.
#[test]
fn a_skipped_restore_is_never_serialized() {
    assert!(serde_json::to_value(RestoreStatus::SkippedPerson {
        now_front: Some(THIRD)
    })
    .is_err());
    assert!(serde_json::from_value::<RestoreStatus>(serde_json::json!({
        "restore": "skipped_person",
        "now_front": 300
    }))
    .is_err());
    for stored in [
        RestoreStatus::NotNeeded,
        RestoreStatus::Restored,
        RestoreStatus::Failed {
            left_in_front: Some(TARGET),
        },
    ] {
        let value = serde_json::to_value(stored).unwrap();
        assert_eq!(
            serde_json::from_value::<RestoreStatus>(value).unwrap(),
            stored
        );
    }
    assert_eq!(
        serde_json::to_value(RestoreStatus::Restored).unwrap(),
        serde_json::json!({"restore": "restored"})
    );
}

#[test]
fn hardware_input_counts_only_after_the_front_and_only_under_coverage() {
    let snapshot = |coverage_start_ms, last_input_ms| {
        Some(HardwareInputSnapshot {
            coverage_start_ms,
            last_input_ms,
        })
    };
    let front = 1_000;
    let cases = [
        (None, false, "no snapshot"),
        (snapshot(0, None), false, "no input at all"),
        (snapshot(0, Some(999)), false, "input before the front"),
        (
            snapshot(0, Some(1_000)),
            false,
            "input at the front instant",
        ),
        (snapshot(0, Some(1_001)), true, "input after the front"),
        (
            snapshot(1_000, Some(1_001)),
            true,
            "coverage from the front",
        ),
        (
            snapshot(1_001, Some(1_500)),
            false,
            "coverage began after the front",
        ),
    ];
    for (snapshot, expected, case) in cases {
        assert_eq!(hardware_input_since(snapshot, front), expected, "{case}");
    }
}

#[test]
fn the_restore_is_skipped_only_for_another_app_with_hardware_input() {
    let restore = |input| RestoreDecision::Restore {
        person_input_during_fronting: input,
    };
    let cases = [
        (
            Some(THIRD),
            true,
            RestoreDecision::SkipPerson {
                now_front: Some(THIRD),
            },
        ),
        (Some(THIRD), false, restore(false)),
        (Some(TARGET), true, restore(true)),
        (Some(TARGET), false, restore(false)),
        (Some(PREVIOUS), true, restore(true)),
        (None, true, restore(true)),
        (None, false, restore(false)),
    ];
    for (frontmost, input, expected) in cases {
        assert_eq!(
            decide_restore(PREVIOUS, TARGET, frontmost, input),
            expected,
            "frontmost {frontmost:?}, input {input}"
        );
    }
}

/// The restore decision a terminal cleanup runs, against the same desk.
#[test]
fn restore_after_front_requests_nothing_when_it_skips() {
    let mut desk = FakeDesk::new();
    desk.set_frontmost(THIRD);
    desk.hardware_input_ms = Some(10);
    let outcome = restore_after_front(&mut desk, PREVIOUS, TARGET, 5, RESTORE_WAIT_MS);
    assert_eq!(
        outcome.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert!(desk.front_requests.is_empty());

    let mut desk = FakeDesk::new();
    desk.set_frontmost(TARGET);
    let outcome = restore_after_front(&mut desk, PREVIOUS, TARGET, 0, RESTORE_WAIT_MS);
    assert_eq!(outcome.restore, RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [PREVIOUS]);

    let mut desk = FakeDesk::new();
    let outcome = restore_after_front(&mut desk, TARGET, TARGET, 0, RESTORE_WAIT_MS);
    assert_eq!(outcome.restore, RestoreStatus::NotNeeded);
    assert!(desk.front_requests.is_empty());
}

/// The front attempt moves only forward, and whoever takes it first decides.
#[test]
fn the_front_attempt_states_decide_what_cleanup_does() {
    // Taken before any front: the worker may not front.
    let mut attempt = FrontAttempt::new();
    assert_eq!(attempt.state(), FrontAttemptState::NotStarted);
    assert_eq!(attempt.take(), CleanupTake::PreventedFront);
    assert!(!attempt.begin_dispatch(5));
    assert_eq!(attempt.state(), FrontAttemptState::NotStarted);
    assert_eq!(attempt.take(), CleanupTake::AlreadyTaken);

    // Taken while the front is in flight: wait for it, then decide.
    let mut attempt = FrontAttempt::new();
    assert!(attempt.begin_dispatch(5));
    assert_eq!(
        attempt.state(),
        FrontAttemptState::Dispatching {
            front_instant_ms: 5
        }
    );
    assert_eq!(attempt.decision_floor(), None);
    assert_eq!(attempt.take(), CleanupTake::AwaitFrontAttempt);
    attempt.attempt_returned();
    assert_eq!(
        attempt.state(),
        FrontAttemptState::Dispatched {
            front_instant_ms: 5
        }
    );
    assert_eq!(attempt.decision_floor(), Some(5));
    assert_eq!(attempt.take(), CleanupTake::AlreadyTaken);

    // Taken after the front returned: decide at once, floored at the front.
    let mut attempt = FrontAttempt::new();
    assert!(attempt.begin_dispatch(7));
    assert!(!attempt.begin_dispatch(9), "one front per obligation");
    attempt.attempt_returned();
    assert_eq!(
        attempt.take(),
        CleanupTake::Decide {
            front_instant_ms: 7
        }
    );
    assert_eq!(attempt.take(), CleanupTake::AlreadyTaken);
}

/// Every fronting stop maps to its reason, and every reason is reached.
#[test]
fn every_fronting_stop_maps_to_its_not_fronted_reason() {
    use crate::platform::IdleUnreadable;
    use std::collections::HashSet;
    let below = IdleGateRefusal::BelowThreshold {
        threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
        hid_idle_ms: 10,
        user_idle_ms: 10,
    };
    let unreadable = IdleGateRefusal::Unreadable(IdleUnreadable::TableUnavailable);
    let table = [
        (
            FrontingStop::HeldInputUnconfirmed,
            NotFrontedReason::HeldInputUnconfirmed,
        ),
        (
            FrontingStop::PersonChangedTarget,
            NotFrontedReason::PersonChangedTarget,
        ),
        (
            FrontingStop::PersonCheckUnreadable,
            NotFrontedReason::ObserverUnavailable,
        ),
        (
            FrontingStop::ObserverUnavailable,
            NotFrontedReason::ObserverUnavailable,
        ),
        (
            FrontingStop::IdleGateRefused(unreadable),
            NotFrontedReason::ObserverUnavailable,
        ),
        (
            FrontingStop::ObserverBlind,
            NotFrontedReason::ObserverUnavailable,
        ),
        (
            FrontingStop::InputMonitoringNotLive,
            NotFrontedReason::ObserverUnavailable,
        ),
        (
            FrontingStop::IdleGateRefused(below),
            NotFrontedReason::PersonActive,
        ),
        (
            FrontingStop::UserSeizedControl,
            NotFrontedReason::PersonActive,
        ),
        (FrontingStop::FocusMoved, NotFrontedReason::PersonActive),
        (
            FrontingStop::PreviousUnknown,
            NotFrontedReason::PreviousUnknown,
        ),
        (FrontingStop::FrontFailed, NotFrontedReason::FrontFailed),
        (FrontingStop::BoundExceeded, NotFrontedReason::FrontFailed),
        (FrontingStop::Cancelled, NotFrontedReason::Cancelled),
        (
            FrontingStop::DispatchGateClosed,
            NotFrontedReason::Cancelled,
        ),
        (
            FrontingStop::TerminalAlreadyChosen,
            NotFrontedReason::Cancelled,
        ),
        (
            FrontingStop::CleanupTookObligation,
            NotFrontedReason::Cancelled,
        ),
        (
            FrontingStop::FrontingLockTimedOut,
            NotFrontedReason::FrontingBusy,
        ),
        (FrontingStop::Unattended, NotFrontedReason::Unattended),
        (
            FrontingStop::FrontingNotAdmitted,
            NotFrontedReason::FrontingUnavailable,
        ),
    ];
    for (stop, reason) in table {
        assert_eq!(not_fronted_reason(stop), reason, "{stop:?}");
    }
    let reached: HashSet<_> = table.iter().map(|(_, reason)| *reason).collect();
    assert_eq!(reached, NotFrontedReason::ALL.into_iter().collect());

    // Only the target-change guard's own finding says the person used the
    // target.
    for (stop, reason) in table {
        if reason == NotFrontedReason::PersonChangedTarget {
            assert_eq!(stop, FrontingStop::PersonChangedTarget);
        }
    }
    // Every reason has its own remedy, and its wire value is its serde name.
    let remedies: HashSet<_> = NotFrontedReason::ALL.iter().map(|r| r.remedy()).collect();
    assert_eq!(remedies.len(), NotFrontedReason::ALL.len());
    for reason in NotFrontedReason::ALL {
        assert_eq!(
            serde_json::to_value(reason).unwrap(),
            serde_json::json!(reason.as_str())
        );
    }
}

#[test]
fn observer_aborts_and_unfronted_bracket_stops_map_to_fronting_stops() {
    let below = IdleGateRefusal::BelowThreshold {
        threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
        hid_idle_ms: 10,
        user_idle_ms: 10,
    };
    let aborts = [
        (
            AbortReason::UserSeizedControl,
            FrontingStop::UserSeizedControl,
        ),
        (
            AbortReason::ObserverUnavailable,
            FrontingStop::ObserverUnavailable,
        ),
        (
            AbortReason::SeizeLatencyBoundExceeded,
            FrontingStop::ObserverBlind,
        ),
        (
            AbortReason::IdleGateRefused(below),
            FrontingStop::IdleGateRefused(below),
        ),
        (AbortReason::FocusMismatch, FrontingStop::FocusMoved),
    ];
    for (abort, stop) in aborts {
        assert_eq!(FrontingStop::from_abort(abort), stop, "{abort:?}");
    }
    let decision = AbortDecision {
        reason: AbortReason::FocusMismatch,
        stopped_action_index: 0,
        detection_latency_ms: None,
        platform_delivery_latency_ms: None,
        sourced_input_kind: None,
        maximum_detection_latency_ms: 50,
        queued_posts_cancelled: 0,
    };
    let stops = [
        (
            BracketStop::PreviousUnknown,
            Some(FrontingStop::PreviousUnknown),
        ),
        (
            BracketStop::ObserverUnavailable,
            Some(FrontingStop::ObserverUnavailable),
        ),
        (BracketStop::FrontFailed, Some(FrontingStop::FrontFailed)),
        (
            BracketStop::BoundExceeded,
            Some(FrontingStop::BoundExceeded),
        ),
        (
            BracketStop::Aborted(decision),
            Some(FrontingStop::FocusMoved),
        ),
        (BracketStop::Cancelled, Some(FrontingStop::Cancelled)),
        (BracketStop::RestoreFailed, None),
        (
            BracketStop::PostFailed(SequencePostFailure {
                posts_returned: 0,
                refusal: ProcessEventRefusal::Cancelled,
                held_state: HeldStateDisposition::NoneHeld,
            }),
            None,
        ),
    ];
    for (bracket_stop, stop) in stops {
        assert_eq!(
            FrontingStop::from_bracket_stop(&bracket_stop),
            stop,
            "{bracket_stop:?}"
        );
    }
}

/// The macOS host turns the process-wide observer's instants into a snapshot on
/// its own millisecond clock. An input from before the host existed reads as 0,
/// so it never counts as input since a front; one after the front does.
#[test]
fn observer_instants_map_onto_the_host_clock() {
    use std::time::{Duration, Instant};
    let before_host = Instant::now();
    let origin = before_host + Duration::from_millis(10);

    let snapshot = HardwareInputSnapshot::from_instants(
        origin,
        before_host,
        Some(origin + Duration::from_millis(250)),
    );
    assert_eq!(
        snapshot,
        HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: Some(250),
        }
    );
    assert!(hardware_input_since(Some(snapshot), 100));
    assert!(!hardware_input_since(Some(snapshot), 250));

    let old_input = HardwareInputSnapshot::from_instants(origin, before_host, Some(before_host));
    assert_eq!(old_input.last_input_ms, Some(0));
    assert!(!hardware_input_since(Some(old_input), 0));

    // Coverage that began after the front cannot speak for the time between.
    let late_coverage = HardwareInputSnapshot::from_instants(
        origin,
        origin + Duration::from_millis(400),
        Some(origin + Duration::from_millis(500)),
    );
    assert!(!hardware_input_since(Some(late_coverage), 100));
}
