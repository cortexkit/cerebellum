//! The bracket against a fake platform with its own clock, so the bound,
//! the chunking and every way a bracket can stop are checked without a
//! desktop.

use super::*;
use crate::dispatch::seize::{HeartbeatMarker, IdleGateRefusal, OBSERVED_DISPATCH_IDLE_MS};
use crate::platform::{HeldStateDisposition, ProcessEventRefusal};

mod listing;
mod restore_reserve;
mod unit_cost;

const TARGET: u32 = 200;
const PREVIOUS: u32 = 100;
const THIRD: u32 = 300;
const OUR_PID: i64 = 7;
const WHOLE_WINDOW: LateWatch = LateWatch::WholeWindow {
    already_restored: false,
};

/// A desktop on a fake clock. A fronting request takes effect after
/// `front_latency_ms`; each unit takes `unit_ms` to post.
struct FakeDesk {
    now: u64,
    frontmost: Option<u32>,
    pending_front: Option<(u32, u64)>,
    front_latency_ms: u64,
    restore_latency_ms: Option<u64>,
    /// Callers with registered restore cleanup give it a separate allowance.
    restore_wait_ms: Option<u64>,
    restore_latencies: latency::RestoreLatencies,
    unit_ms: u64,
    /// Fronting requests for this pid are ignored.
    refuse_front_of: Option<u32>,
    /// Input from another source appears once this many units are posted.
    input_after_units: Option<usize>,
    idle_ms: u64,
    posted: Vec<usize>,
    /// A cancellation signal set by the first completed unit, not by polling.
    cancel_after_first_unit: Option<std::rc::Rc<std::cell::Cell<bool>>>,
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
    missed_heartbeat: bool,
    observer_lost: bool,
    snapshot_reads: usize,
    lose_observer_on_second_sample: bool,
    switch_on_second_sample: bool,
    input_on_second_sample: bool,
    /// This many requests to bring `PREVIOUS` back are ignored, as an
    /// application that does not answer the first route does.
    ignored_restores: usize,
    /// Whether the second route brings `PREVIOUS` back.
    fallback_restores: bool,
    /// Every request made the second way, in order.
    fallback_requests: Vec<u32>,
    /// The target comes to the front again at each of these instants, as
    /// an activation the platform delivers more than once does.
    landings_at: Vec<u64>,
    /// Hardware input arrives at this instant.
    input_at: Option<u64>,
    /// A window-server listing read through the production routing, when
    /// set; units are then posted through it too.
    listing: Option<listing::Listing>,
    /// Unit post costs kept as a keystroke host keeps them, when set.
    unit_costs: Option<latency::UnitPostCosts>,
    /// The instant the desk clock's zero stands for, plus an offset, so a
    /// sequence of desks can replay calls seconds apart on fixed instants.
    clock_origin: std::time::Instant,
    clock_offset_ms: u64,
}

impl FakeDesk {
    fn new() -> Self {
        // Most scenarios start with a warm predictor. Each desk owns its
        // history so parallel tests never share process-wide measurements.
        let mut restore_latencies = latency::RestoreLatencies::new();
        restore_latencies.record(5);
        Self {
            now: 0,
            frontmost: Some(PREVIOUS),
            pending_front: None,
            front_latency_ms: 5,
            restore_latency_ms: None,
            restore_wait_ms: None,
            restore_latencies,
            unit_ms: 4,
            refuse_front_of: None,
            input_after_units: None,
            idle_ms: OBSERVED_DISPATCH_IDLE_MS + 500,
            posted: Vec::new(),
            cancel_after_first_unit: None,
            fronted_since: None,
            fronted_intervals: Vec::new(),
            frontmost_at_post: Vec::new(),
            front_requests: Vec::new(),
            hardware_input_ms: None,
            switch_after_unit: None,
            switch_after_read: None,
            missed_heartbeat: false,
            observer_lost: false,
            snapshot_reads: 0,
            lose_observer_on_second_sample: false,
            switch_on_second_sample: false,
            input_on_second_sample: false,
            ignored_restores: 0,
            fallback_restores: false,
            fallback_requests: Vec::new(),
            landings_at: Vec::new(),
            input_at: None,
            listing: None,
            unit_costs: None,
            clock_origin: std::time::Instant::now(),
            clock_offset_ms: 0,
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
        let now = self.now;
        if self.landings_at.first().is_some_and(|at| *at <= now) {
            self.landings_at.remove(0);
            self.set_frontmost(TARGET);
        }
        if self.input_at.is_some_and(|at| at <= now) {
            self.hardware_input_ms = self.input_at.take();
        }
    }

    /// The desk clock's present as an instant.
    fn instant(&self) -> std::time::Instant {
        self.clock_origin + std::time::Duration::from_millis(self.clock_offset_ms + self.now)
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
        if pid == PREVIOUS && self.ignored_restores > 0 {
            self.ignored_restores -= 1;
            return true;
        }
        if pid == TARGET {
            // The interval runs from the request, as the bracket counts it.
            self.fronted_since = Some(self.now);
        }
        let latency = if pid == PREVIOUS {
            self.restore_latency_ms.unwrap_or(self.front_latency_ms)
        } else {
            self.front_latency_ms
        };
        self.pending_front = Some((pid, self.now + latency));
        true
    }
    fn request_front_fallback(&mut self, pid: u32) -> bool {
        self.fallback_requests.push(pid);
        if !self.fallback_restores {
            return false;
        }
        let latency = self.restore_latency_ms.unwrap_or(self.front_latency_ms);
        self.pending_front = Some((pid, self.now + latency));
        true
    }
    fn restore_front_attempt(
        &mut self,
        previous: u32,
        target: u32,
        since: u64,
        wait_ms: u64,
        activation_observed: bool,
    ) -> RestoreOutcome {
        let wait_ms = self.restore_wait_ms.unwrap_or(wait_ms);
        restore_after_front_attempt(self, previous, target, since, wait_ms, activation_observed)
    }
    fn measured_restore_latency_ms(&mut self) -> Option<u64> {
        self.restore_latencies.maximum()
    }
    fn record_restore_latency_ms(&mut self, milliseconds: u64) {
        self.restore_latencies.record(milliseconds);
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn before_front(&mut self) -> Result<(), SequencePostFailure> {
        listing::before_front(self)
    }
    fn measured_unit_post_cost_ms(&mut self) -> Option<u64> {
        let now = self.instant();
        self.unit_costs.as_ref()?.maximum(now)
    }
    fn record_unit_post_cost_ms(&mut self, milliseconds: u64) {
        let now = self.instant();
        if let Some(costs) = &mut self.unit_costs {
            costs.record(milliseconds, now);
        }
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
        if self.missed_heartbeat {
            return HeartbeatObservation::Missed;
        }
        HeartbeatObservation::Seen {
            marker: probe.marker,
            source_unix_process_id: OUR_PID,
            observed_at_ms: probe.posted_at_ms,
        }
    }
    fn post_unit(&mut self, index: usize) -> Result<UnitPosted, SequencePostFailure> {
        self.frontmost_at_post.push(self.frontmost);
        self.posted.push(index);
        let posted = listing::post_chord(self)?;
        self.advance(self.unit_ms);
        if let Some(cancel) = &self.cancel_after_first_unit {
            cancel.set(true);
        }
        if let Some((after, pid, input)) = self.switch_after_unit {
            if after == index {
                self.set_frontmost(pid);
                if input {
                    self.hardware_input_ms = Some(self.now);
                }
            }
        }
        Ok(posted)
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.snapshot_reads += 1;
        if self.snapshot_reads == 2 && self.switch_on_second_sample {
            self.set_frontmost(THIRD);
        }
        if self.snapshot_reads == 2 && self.input_on_second_sample {
            self.hardware_input_ms = Some(self.now);
        }
        if self.observer_lost || (self.lose_observer_on_second_sample && self.snapshot_reads >= 2) {
            return None;
        }
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
    desk.restore_latencies = latency::RestoreLatencies::new();
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
    let cancelled = std::rc::Rc::new(std::cell::Cell::new(false));
    desk.cancel_after_first_unit = Some(cancelled.clone());
    let report = run_fronting_bracket(&mut desk, &mut UserIdleEstimator::new(), plan(60), &|| {
        cancelled.get()
    });
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

#[test]
fn a_measured_slow_restore_refuses_the_next_call_before_posting() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 25;
    desk.restore_latency_ms = Some(124);
    desk.restore_wait_ms = Some(RESTORE_WAIT_MS);
    let mut warmup = plan(1);
    warmup.maximum_interval_ms = 500;
    let first = run_fronting_bracket_with(
        &mut desk,
        &mut UserIdleEstimator::new(),
        warmup,
        admitted(),
        &|| false,
    );
    assert_eq!(first.report.units_posted, 1);
    assert_eq!(first.report.slowest_restore_ms, 124);
    assert_eq!(first.report.restore, RestoreStatus::Restored);
    desk.posted.clear();
    desk.front_requests.clear();

    let next = run_admitted(&mut desk, 1);
    assert_eq!(next.report.stop, Some(BracketStop::BoundExceeded));
    assert_eq!(next.report.units_posted, 0);
    assert_eq!(next.report.posts_returned, 0);
    assert!(desk.posted.is_empty());
    assert_eq!(desk.front_requests, vec![TARGET, PREVIOUS]);
    assert_eq!(next.report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
}

#[test]
fn a_cold_predictor_refuses_before_posting_and_learns_for_a_retry() {
    let mut desk = FakeDesk::new();
    desk.restore_latencies = latency::RestoreLatencies::new();
    desk.front_latency_ms = 25;
    desk.restore_latency_ms = Some(10);
    let first = run_admitted(&mut desk, 1);
    assert_eq!(first.report.stop, Some(BracketStop::BoundExceeded));
    assert_eq!(first.report.units_posted, 0);
    assert_eq!(first.report.posts_returned, 0);
    assert!(desk.posted.is_empty());
    assert_eq!(desk.front_requests, vec![TARGET, PREVIOUS]);
    assert_eq!(first.report.restore, RestoreStatus::Restored);
    assert_eq!(desk.measured_restore_latency_ms(), Some(10));

    let retry = run_admitted(&mut desk, 1);
    assert_eq!(retry.report.stop, None);
    assert_eq!(retry.report.units_posted, 1);
    assert!(retry.report.held(100));
}

#[test]
fn a_slow_restore_ages_out_after_eight_later_refused_call_restores() {
    let mut desk = FakeDesk::new();
    desk.restore_latencies.record(1046);
    desk.restore_latency_ms = Some(4);
    for later_restore in 1..=8 {
        let outcome = run_admitted(&mut desk, 1);
        assert_eq!(outcome.report.stop, Some(BracketStop::BoundExceeded));
        assert_eq!(outcome.report.units_posted, 0);
        assert_eq!(outcome.report.restore, RestoreStatus::Restored);
        assert_eq!(desk.frontmost, Some(PREVIOUS));
        assert_eq!(
            desk.measured_restore_latency_ms(),
            Some(if later_restore < 8 { 1046 } else { 4 }),
        );
    }
    assert!(desk.posted.is_empty());
    let retry = run_admitted(&mut desk, 1);
    assert_eq!(retry.report.stop, None);
    assert_eq!(retry.report.units_posted, 1);
    assert!(retry.report.held(100));
}

#[test]
fn skipped_restores_do_not_age_samples_and_failed_waits_are_not_fast_samples() {
    let mut desk = FakeDesk::new();
    desk.restore_latencies = latency::RestoreLatencies::new();
    for _ in 0..8 {
        remember_restore(&mut desk, RestoreStatus::Restored, 124);
    }
    for _ in 0..8 {
        remember_restore(&mut desk, RestoreStatus::NotNeeded, 0);
        remember_restore(
            &mut desk,
            RestoreStatus::SkippedPerson {
                now_front: Some(THIRD),
            },
            0,
        );
    }
    assert_eq!(desk.measured_restore_latency_ms(), Some(124));
    remember_restore(
        &mut desk,
        RestoreStatus::Failed {
            left_in_front: Some(TARGET),
        },
        10,
    );
    assert_eq!(desk.measured_restore_latency_ms(), Some(RESTORE_WAIT_MS));
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
        fn measured_restore_latency_ms(&mut self) -> Option<u64> {
            self.0.measured_restore_latency_ms()
        }
        fn record_restore_latency_ms(&mut self, milliseconds: u64) {
            self.0.record_restore_latency_ms(milliseconds);
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
    fn measured_restore_latency_ms(&mut self) -> Option<u64> {
        self.desk.measured_restore_latency_ms()
    }
    fn record_restore_latency_ms(&mut self, milliseconds: u64) {
        self.desk.record_restore_latency_ms(milliseconds);
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

/// Absence of key/button/scroll evidence cannot distinguish an action's switch
/// from a person's Space gesture, so a third application is left alone.
#[test]
fn a_switch_with_no_hardware_input_leaves_the_third_app_alone() {
    let mut desk = FakeDesk::new();
    desk.switch_after_unit = Some((0, THIRD, false));
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
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
fn hardware_input_is_conservative_for_same_bucket_and_unknown_coverage() {
    let snapshot = |coverage_start_ms, last_input_ms| {
        Some(HardwareInputSnapshot {
            coverage_start_ms,
            last_input_ms,
        })
    };
    let front = 1_000;
    let cases = [
        (None, true, "no snapshot"),
        (snapshot(0, None), false, "no input at all"),
        (snapshot(0, Some(999)), false, "input before the front"),
        (snapshot(0, Some(1_000)), true, "input at the front instant"),
        (snapshot(0, Some(1_001)), true, "input after the front"),
        (
            snapshot(1_000, Some(1_001)),
            true,
            "coverage from the front",
        ),
        (
            snapshot(1_001, Some(1_500)),
            true,
            "coverage began after the front",
        ),
    ];
    for (snapshot, expected, case) in cases {
        assert_eq!(hardware_input_since(snapshot, front), expected, "{case}");
    }
}

#[test]
fn the_restore_leaves_unknown_or_third_application_focus_alone() {
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
        (
            Some(THIRD),
            false,
            RestoreDecision::SkipPerson {
                now_front: Some(THIRD),
            },
        ),
        (Some(TARGET), true, restore(true)),
        (Some(TARGET), false, restore(false)),
        (Some(PREVIOUS), true, restore(true)),
        (None, true, RestoreDecision::SkipPerson { now_front: None }),
        (None, false, RestoreDecision::SkipPerson { now_front: None }),
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
        (FrontingStop::TargetNotRead, NotFrontedReason::TargetNotRead),
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
    assert!(hardware_input_since(Some(snapshot), 250));

    let old_input = HardwareInputSnapshot::from_instants(origin, before_host, Some(before_host));
    assert_eq!(old_input.last_input_ms, Some(0));
    assert!(hardware_input_since(Some(old_input), 0));

    // Coverage that began after the front cannot speak for the time between.
    let late_coverage = HardwareInputSnapshot::from_instants(
        origin,
        origin + Duration::from_millis(400),
        Some(origin + Duration::from_millis(500)),
    );
    assert!(hardware_input_since(Some(late_coverage), 100));
}

#[test]
fn missed_initial_heartbeat_never_requests_front() {
    let mut desk = FakeDesk::new();
    desk.missed_heartbeat = true;
    let report = run(&mut desk, 1);
    assert!(report.stop.is_some());
    assert!(desk.front_requests.is_empty());
    assert!(desk.posted.is_empty());
}

#[test]
fn restore_with_lost_observer_coverage_leaves_focus_alone() {
    let mut desk = FakeDesk::new();
    desk.observer_lost = true;
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(TARGET)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
    assert!(
        !outcome.person_input_during_fronting,
        "unknown coverage is not a recorded person event"
    );
}

#[test]
fn restore_rechecks_observer_coverage_immediately_before_request() {
    let mut desk = FakeDesk::new();
    desk.lose_observer_on_second_sample = true;
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(TARGET)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
}

#[test]
fn restore_rechecks_frontmost_after_the_last_activity_sample() {
    let mut desk = FakeDesk::new();
    desk.switch_on_second_sample = true;
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
}

#[test]
fn restore_new_activity_during_final_sampling_leaves_focus_alone() {
    let mut desk = FakeDesk::new();
    desk.input_on_second_sample = true;
    let outcome = run_admitted(&mut desk, 1);
    assert_eq!(
        outcome.report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(TARGET)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
}

#[test]
fn pending_activation_is_not_restored_just_because_previous_is_still_frontmost() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 800;
    desk.restore_latency_ms = Some(2);
    desk.request_front(TARGET);
    desk.advance(100);
    let reply = restore_after_front_attempt(&mut desk, PREVIOUS, TARGET, 0, 300, false);
    assert!(matches!(reply.restore, RestoreStatus::Failed { .. }));
    assert_eq!(desk.now, 400);
    assert_eq!(desk.front_requests, [TARGET]);
    let (restore, latency, input) =
        watch_late_activation(&mut desk, PREVIOUS, TARGET, 0, 5_000, WHOLE_WINDOW, &|| {
            false
        });
    assert_eq!(restore, RestoreStatus::Restored);
    assert_eq!(latency, Some(800));
    assert!(!input);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert!(
        desk.posted.is_empty(),
        "late cleanup must never post the refused chord"
    );
}

#[test]
fn late_activation_watch_leaves_person_input_and_unknown_coverage_alone() {
    for unknown in [false, true] {
        let mut desk = FakeDesk::new();
        desk.front_latency_ms = 800;
        desk.request_front(TARGET);
        desk.advance(800);
        if unknown {
            desk.observer_lost = true;
        } else {
            desk.hardware_input_ms = Some(500);
        }
        let (restore, _, input) =
            watch_late_activation(&mut desk, PREVIOUS, TARGET, 0, 5_000, WHOLE_WINDOW, &|| {
                false
            });
        assert!(matches!(restore, RestoreStatus::SkippedPerson { .. }));
        assert!(input);
        assert_eq!(desk.front_requests, [TARGET]);
        assert_eq!(desk.frontmost, Some(TARGET));
        assert!(desk.posted.is_empty());
    }
}

#[test]
fn late_activation_watch_has_a_hard_end_and_honors_stop() {
    for stop in [false, true] {
        let mut desk = FakeDesk::new();
        desk.refuse_front_of = Some(TARGET);
        desk.request_front(TARGET);
        let (restore, latency, _) =
            watch_late_activation(&mut desk, PREVIOUS, TARGET, 0, 5_000, WHOLE_WINDOW, &|| {
                stop
            });
        assert!(matches!(restore, RestoreStatus::Failed { .. }));
        assert_eq!(latency, None);
        assert_eq!(desk.now, if stop { 0 } else { 5_000 });
        assert_eq!(desk.front_requests, [TARGET]);
        assert!(desk.posted.is_empty());
    }
}

/// A desk run where the target's activation landed 109 ms after the
/// request, past the 100 ms bound, and the person's application did not
/// answer the request to come back, neither in the call nor in the late
/// watch. The second route must put it back, with no person input.
#[test]
fn a_late_landing_whose_restore_request_is_ignored_is_put_back_the_second_way() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 109;
    desk.restore_latency_ms = Some(20);
    desk.ignored_restores = usize::MAX;
    desk.fallback_restores = true;
    desk.request_front(TARGET);
    desk.advance(100);
    let reply = restore_after_front_attempt(&mut desk, PREVIOUS, TARGET, 0, 300, false);
    // The late watch follows every landing the call did not see through, as
    // the terminal arbiter starts it.
    let already_restored = reply.restore == RestoreStatus::Restored;
    let (restore, _, input) = watch_late_activation(
        &mut desk,
        PREVIOUS,
        TARGET,
        0,
        5_000,
        LateWatch::WholeWindow { already_restored },
        &|| false,
    );
    assert_eq!(desk.frontmost, Some(PREVIOUS), "the person's app is back");
    assert_eq!(reply.restore, RestoreStatus::Restored);
    assert_eq!(restore, RestoreStatus::Restored);
    assert!(!input);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert_eq!(desk.fallback_requests, [PREVIOUS]);
    assert!(desk.posted.is_empty());
}

#[test]
fn late_watch_keeps_asking_until_the_previous_application_comes_back() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 800;
    desk.restore_latency_ms = Some(20);
    // The first three requests are ignored, and there is no second route.
    desk.ignored_restores = 3;
    desk.request_front(TARGET);
    desk.advance(400);
    let (restore, latency, input) =
        watch_late_activation(&mut desk, PREVIOUS, TARGET, 0, 5_000, WHOLE_WINDOW, &|| {
            false
        });
    assert_eq!(restore, RestoreStatus::Restored);
    assert_eq!(latency, Some(800));
    assert!(!input);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
    assert_eq!(
        desk.front_requests,
        [TARGET, PREVIOUS, PREVIOUS, PREVIOUS, PREVIOUS]
    );
    assert_eq!(desk.fallback_requests, [PREVIOUS, PREVIOUS, PREVIOUS]);
    assert!(desk.posted.is_empty());
}

#[test]
fn late_watch_puts_back_an_activation_that_lands_twice() {
    for already_restored in [false, true] {
        let mut desk = FakeDesk::new();
        desk.restore_latency_ms = Some(20);
        if already_restored {
            // The call saw the landing and put it back itself.
            desk.landings_at = vec![460];
        } else {
            desk.front_latency_ms = 800;
            desk.request_front(TARGET);
            desk.landings_at = vec![1_500];
        }
        desk.advance(400);
        let (restore, _, input) = watch_late_activation(
            &mut desk,
            PREVIOUS,
            TARGET,
            0,
            5_000,
            LateWatch::WholeWindow { already_restored },
            &|| false,
        );
        // Play the rest of the window on the desk, watched or not.
        while desk.now < 5_000 {
            desk.advance(10);
        }
        assert_eq!(
            desk.frontmost,
            Some(PREVIOUS),
            "second landing put back (already restored: {already_restored})"
        );
        assert_eq!(restore, RestoreStatus::Restored);
        assert!(!input);
        let restores = desk
            .front_requests
            .iter()
            .filter(|pid| **pid == PREVIOUS)
            .count();
        assert_eq!(restores, if already_restored { 1 } else { 2 });
        assert!(desk.posted.is_empty());
    }
}

#[test]
fn late_watch_leaves_a_later_landing_alone_after_person_input() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 800;
    desk.restore_latency_ms = Some(20);
    desk.input_at = Some(1_000);
    desk.landings_at = vec![1_500];
    desk.request_front(TARGET);
    desk.advance(400);
    let (restore, latency, input) =
        watch_late_activation(&mut desk, PREVIOUS, TARGET, 0, 5_000, WHOLE_WINDOW, &|| {
            false
        });
    assert_eq!(restore, RestoreStatus::Restored);
    assert_eq!(latency, Some(800));
    assert!(
        !input,
        "the input came after the restore, in the person's app"
    );
    assert!(desk.now < 1_500, "the watch ended at the person's input");
    while desk.now < 5_000 {
        desk.advance(10);
    }
    assert_eq!(desk.frontmost, Some(TARGET));
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
}

#[test]
fn the_route_close_watch_makes_one_restore_attempt_and_returns() {
    for answered in [true, false] {
        let mut desk = FakeDesk::new();
        desk.restore_latency_ms = Some(20);
        if !answered {
            desk.ignored_restores = usize::MAX;
        }
        desk.request_front(TARGET);
        desk.advance(800);
        // A further landing the ordinary watch would wait for.
        desk.landings_at = vec![1_500];
        let (restore, latency, input) = watch_late_activation(
            &mut desk,
            PREVIOUS,
            TARGET,
            0,
            5_000,
            LateWatch::FirstAttempt,
            &|| false,
        );
        assert!(!input);
        assert_eq!(latency, Some(800));
        if answered {
            assert_eq!(restore, RestoreStatus::Restored);
            assert_eq!(desk.frontmost, Some(PREVIOUS));
        } else {
            assert!(matches!(restore, RestoreStatus::Failed { .. }));
        }
        assert!(
            desk.now <= 800 + RESTORE_WAIT_MS + FRONTING_POLL_MS,
            "held for one restore wait at most, not the window: {}",
            desk.now
        );
        assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    }
}

#[test]
fn unhooked_front_timeout_does_not_claim_a_pending_activation_was_restored() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 800;
    let report = run(&mut desk, 1);
    assert_eq!(report.stop, Some(BracketStop::FrontFailed));
    assert!(matches!(report.restore, RestoreStatus::Failed { .. }));
    assert_eq!(desk.front_requests, [TARGET]);
    assert!(desk.posted.is_empty());
}

#[test]
fn a_timed_out_activation_landing_during_in_call_cleanup_does_not_restore_over_input() {
    let mut desk = FakeDesk::new();
    desk.front_latency_ms = 200;
    desk.request_front(TARGET);
    desk.advance(200);
    desk.hardware_input_ms = Some(150);
    let outcome = restore_after_front_attempt(&mut desk, PREVIOUS, TARGET, 0, 300, false);
    assert!(matches!(
        outcome.restore,
        RestoreStatus::SkippedPerson { .. }
    ));
    assert!(outcome.person_input_during_fronting);
    assert_eq!(desk.front_requests, [TARGET]);
    assert_eq!(desk.frontmost, Some(TARGET));
    assert!(desk.posted.is_empty());
}
