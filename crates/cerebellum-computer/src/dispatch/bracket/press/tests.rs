//! The needs-front press against a fake desk with its own clock, so the
//! order of the ten steps, the bound and every way a run can end are checked
//! without a desktop. The clock only moves when the run waits, which makes
//! every timing claim here exact rather than a real-clock guess.

use super::*;
use crate::dispatch::bracket::{
    not_fronted_reason, CutoffGate, HardwareInputSnapshot, NotFrontedReason, OrdinaryClaim,
    UnitPosted,
};
use crate::dispatch::seize::{
    HeartbeatMarker, HeartbeatObservation, HeartbeatProbe, SourcedInputEvent,
    OBSERVED_DISPATCH_IDLE_MS,
};
use crate::platform::{IdleReading, SequencePostFailure};

const TARGET: u32 = 200;
const PREVIOUS: u32 = 100;
const THIRD: u32 = 300;
const OUR_PID: i64 = 7;
const START_MS: u64 = 10_000;
/// How often the fake settle asks whether the person acted, as the real
/// settle polls the application.
const SETTLE_POLL_MS: u64 = 50;

/// What one step's element and the person do.
#[derive(Debug, Clone, Copy, Default)]
struct StepScript {
    /// What the pre-read sees while the application is in the background.
    background_enabled: bool,
    /// The poll, counted from one, at which the element first reads enabled
    /// once fronted. `None`: it never does.
    enabled_on_poll: Option<usize>,
    /// During the settle, the application with this pid comes to the front.
    switch_to_during_settle: Option<u32>,
    /// During the settle, the person presses a key or a button.
    hardware_input_during_settle: bool,
    /// This many milliseconds into the settle, the person presses a key,
    /// which the run's own observer drains at the settle's next check.
    tap_input_into_settle_ms: Option<u64>,
}

impl StepScript {
    fn disabled_in_background() -> Self {
        Self {
            background_enabled: false,
            enabled_on_poll: Some(1),
            ..Self::default()
        }
    }
}

/// A desk on a fake clock. A fronting request takes effect after
/// `front_latency_ms`.
struct PressDesk {
    now: u64,
    frontmost: Option<u32>,
    pending_front: Option<(u32, u64)>,
    front_latency_ms: u64,
    /// Fronting requests for this pid are ignored.
    refuse_front_of: Option<u32>,
    /// Every fronting request, in order.
    front_requests: Vec<u32>,
    steps: Vec<StepScript>,
    polls: Vec<usize>,
    pressed: Vec<usize>,
    badge_ms: u64,
    badge_holds: Vec<(usize, bool)>,
    /// The person changes the target, with hardware input, while the badge
    /// is on its way; the hold's own check has already passed.
    change_target_during_badge: bool,
    target_changed: bool,
    lock_wait_ms: u64,
    lock_busy: bool,
    locks_taken: u32,
    finishes: Vec<RestoreStatus>,
    held_input_confirmed: bool,
    /// The newest hardware input, which the idle reading and the snapshot
    /// both report.
    last_hardware_input_ms: Option<u64>,
    /// At this (step, poll) the person presses a key, which the run's own
    /// observer drains at its next check.
    tap_input_on_poll: Option<(usize, usize)>,
    pending_tap_input: bool,
    cancel_once_fronted: bool,
    /// Cleanup takes the obligation as soon as it is registered, as if the
    /// worker were paused right after registering it.
    cleanup_takes_at_registration: bool,
    attempt: CutoffGate,
    press_ms: u64,
    /// `None`: each settle takes its whole bound.
    settle_ms: Option<u64>,
    /// How long each settle actually took, in order.
    settled_ms: Vec<u64>,
    log: Vec<&'static str>,
}

impl PressDesk {
    fn new(steps: Vec<StepScript>) -> Self {
        let count = steps.len();
        Self {
            now: START_MS,
            frontmost: Some(PREVIOUS),
            pending_front: None,
            front_latency_ms: 5,
            refuse_front_of: None,
            front_requests: Vec::new(),
            steps,
            polls: vec![0; count],
            pressed: Vec::new(),
            badge_ms: 200,
            badge_holds: Vec::new(),
            change_target_during_badge: false,
            target_changed: false,
            lock_wait_ms: 0,
            lock_busy: false,
            locks_taken: 0,
            finishes: Vec::new(),
            held_input_confirmed: true,
            last_hardware_input_ms: None,
            tap_input_on_poll: None,
            pending_tap_input: false,
            cancel_once_fronted: false,
            cleanup_takes_at_registration: false,
            attempt: CutoffGate::new(),
            press_ms: 10,
            settle_ms: None,
            settled_ms: Vec::new(),
            log: Vec::new(),
        }
    }

    fn single() -> Self {
        Self::new(vec![StepScript::disabled_in_background()])
    }

    fn advance(&mut self, milliseconds: u64) {
        self.now += milliseconds;
        if let Some((pid, at)) = self.pending_front {
            if self.now >= at {
                self.frontmost = Some(pid);
                self.pending_front = None;
            }
        }
    }

    fn person_input_now(&mut self) {
        self.last_hardware_input_ms = Some(self.now);
    }

    fn requests_for(&self, pid: u32) -> usize {
        self.front_requests.iter().filter(|p| **p == pid).count()
    }
}

impl FrontingBracketHost for PressDesk {
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
        self.log.push(if pid == TARGET {
            "front"
        } else {
            "restore_request"
        });
        self.front_requests.push(pid);
        if self.refuse_front_of != Some(pid) {
            self.pending_front = Some((pid, self.now + self.front_latency_ms));
        }
        true
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn create_tap(&mut self) -> Option<()> {
        Some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        self.log.push("idle");
        IdleReading::Milliseconds(match self.last_hardware_input_ms {
            Some(at) => self.now - at,
            None => self.now + OBSERVED_DISPATCH_IDLE_MS,
        })
    }
    fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
        if std::mem::take(&mut self.pending_tap_input) {
            vec![SourcedInputEvent {
                source_unix_process_id: 0,
                detection_latency_ms: 1,
                platform_delivery_latency_ms: None,
            }]
        } else {
            Vec::new()
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
    fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
        unreachable!("a press run posts no units")
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: self.last_hardware_input_ms,
        })
    }
}

impl FrontingPressHost for PressDesk {
    fn pre_read(&mut self, step: usize) -> PressPreRead {
        self.log.push("pre_read");
        PressPreRead {
            enabled: Some(self.steps[step].background_enabled),
            frontmost: self.frontmost,
        }
    }
    fn hold_for_badge(&mut self, step: usize, wait_for_arrival: bool) -> bool {
        self.log.push("badge");
        self.badge_holds.push((step, wait_for_arrival));
        if self.change_target_during_badge {
            self.change_target_during_badge = false;
            self.target_changed = true;
            self.person_input_now();
        }
        if wait_for_arrival {
            self.advance(self.badge_ms);
        }
        true
    }
    fn take_fronting_lock(&mut self, wait_ms: u64) -> bool {
        self.log.push("lock");
        if self.lock_busy {
            self.advance(wait_ms);
            return false;
        }
        self.advance(self.lock_wait_ms);
        self.locks_taken += 1;
        true
    }
    fn held_input_confirmed(&mut self) -> bool {
        self.log.push("guard0");
        self.held_input_confirmed
    }
    fn person_changed_target(&mut self) -> Option<bool> {
        self.log.push("guard1");
        Some(self.target_changed)
    }
    fn cancelled(&mut self) -> bool {
        self.cancel_once_fronted && self.frontmost == Some(TARGET)
    }
    fn dispatch_gate_open(&mut self) -> bool {
        true
    }
    fn register_restore_obligation(&mut self, previous: u32, target: u32) -> bool {
        assert_eq!((previous, target), (PREVIOUS, TARGET));
        self.log.push("register");
        if self.cleanup_takes_at_registration {
            assert_eq!(self.attempt.claim_ordinary(), OrdinaryClaim::PreventedFront);
        }
        true
    }
    fn begin_front_attempt(&mut self, front_instant_ms: u64) -> bool {
        self.attempt.begin_front_attempt(front_instant_ms)
    }
    fn front_attempt_returned(&mut self) {
        self.attempt.front_attempt_returned();
    }
    fn admit_fronted_step(&mut self, _step: usize) -> bool {
        true
    }
    fn element_enabled(&mut self, step: usize) -> Option<bool> {
        self.log.push("poll");
        self.polls[step] += 1;
        if self.tap_input_on_poll == Some((step, self.polls[step])) {
            self.pending_tap_input = true;
            self.person_input_now();
        }
        Some(
            self.steps[step]
                .enabled_on_poll
                .is_some_and(|on| self.polls[step] >= on),
        )
    }
    fn press(&mut self, step: usize) -> bool {
        self.log.push("press");
        self.pressed.push(step);
        self.advance(self.press_ms);
        true
    }
    fn settle(
        &mut self,
        step: usize,
        bound_ms: u64,
        person_acted: &mut dyn FnMut(&mut Self) -> bool,
    ) -> SettleEnd {
        self.log.push("settle");
        let length = self.settle_ms.unwrap_or(bound_ms);
        let script = self.steps[step];
        let start = self.now;
        // Waits in the real settle's poll interval, asking before each one,
        // as the real settle does.
        loop {
            if person_acted(self) {
                self.settled_ms.push(self.now - start);
                return SettleEnd::PersonInput;
            }
            let elapsed = self.now - start;
            if elapsed >= length {
                break;
            }
            self.advance(SETTLE_POLL_MS.min(length - elapsed));
            if script
                .tap_input_into_settle_ms
                .is_some_and(|at| self.now - start == at)
            {
                self.pending_tap_input = true;
                self.person_input_now();
            }
        }
        self.settled_ms.push(self.now - start);
        if let Some(pid) = script.switch_to_during_settle {
            self.frontmost = Some(pid);
        }
        if script.hardware_input_during_settle {
            self.person_input_now();
        }
        SettleEnd::Quiet
    }
    fn claim_restore(&mut self) -> RestoreClaim {
        self.log.push("claim");
        if self.attempt.restore_taken() {
            return RestoreClaim::TakenByCleanup(RestoreStatus::NotNeeded);
        }
        RestoreClaim::Run
    }
    fn finish_fronting(&mut self, restore: RestoreStatus) {
        self.log.push("finish");
        self.finishes.push(restore);
    }
}

fn plan(steps: usize) -> PressPlan {
    PressPlan {
        target_pid: TARGET,
        steps,
        settle_bound_ms: PRESS_SETTLE_BOUND_MS,
        maximum_seize_detection_latency_ms: 50,
    }
}

fn run(desk: &mut PressDesk) -> PressFrontingReport {
    let steps = desk.steps.len();
    run_fronting_press(desk, &mut UserIdleEstimator::new(), plan(steps))
}

#[test]
fn the_single_press_bound_is_sixteen_hundred_milliseconds() {
    assert_eq!(PRESS_FRONTING_BOUND_MS, 1_600);
    assert_eq!(FRONT_WAIT_MS, 300);
    assert_eq!(ENABLE_POLL_MS, 500);
    assert_eq!(RESTORE_WAIT_MS, 300);
    // A batch: the front, each step's poll and settle, the restore.
    assert_eq!(press_fronting_bound_ms(3), 300 + 3 * 1_000 + 300);
}

/// The ten steps run in the stated order, the press settles fully, and the
/// previous application is back inside the bound.
#[test]
fn a_needs_front_press_runs_its_steps_in_order_and_settles_within_the_bound() {
    let mut desk = PressDesk::single();
    let report = run(&mut desk);
    assert_eq!(
        desk.log,
        [
            "pre_read",
            "badge",
            "lock",
            "guard0",
            "guard1",
            "idle",
            "register",
            "front",
            "poll",
            "press",
            "settle",
            "claim",
            "restore_request",
            "finish",
        ]
    );
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.steps_pressed, 1);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert_eq!(report.bound_ms, PRESS_FRONTING_BOUND_MS);
    assert!(!report.fronting_bound_exceeded, "{report:?}");
    assert!(report.fronted_interval_ms >= PRESS_SETTLE_BOUND_MS);
    assert!(!report.person_input_during_fronting);
    assert_eq!(desk.finishes, [RestoreStatus::Restored]);
}

#[test]
fn an_element_enabled_on_the_second_poll_is_pressed() {
    let mut desk = PressDesk::new(vec![StepScript {
        enabled_on_poll: Some(2),
        ..StepScript::disabled_in_background()
    }]);
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(desk.polls, [2]);
    assert_eq!(desk.pressed, [0]);
    assert_eq!(report.restore, RestoreStatus::Restored);
}

/// Still disabled once the poll has run for its whole 500 ms: the press is
/// refused `element_disabled`, nothing is pressed, and the previous
/// application is still put back.
#[test]
fn an_element_still_disabled_at_the_poll_limit_is_refused_and_still_restored() {
    let mut desk = PressDesk::new(vec![StepScript {
        enabled_on_poll: None,
        ..StepScript::disabled_in_background()
    }]);
    let report = run(&mut desk);
    assert_eq!(report.stop, Some(PressRunStop::ElementDisabled));
    assert_eq!(report.stopped_at, Some(0));
    assert!(desk.pressed.is_empty());
    assert!(!desk.log.contains(&"press"));
    // Polled every FRONTING_POLL_MS from the first poll through 500 ms.
    assert_eq!(
        desk.polls,
        [(ENABLE_POLL_MS / FRONTING_POLL_MS) as usize + 1]
    );
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
}

/// A press that took effect but whose settle ran long is returned with the
/// overrun disclosed, not refused.
#[test]
fn a_press_that_overran_the_bound_is_returned_with_the_overrun_disclosed() {
    let mut desk = PressDesk::single();
    desk.settle_ms = Some(1_700);
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.steps_pressed, 1);
    assert!(report.fronted_interval_ms > PRESS_FRONTING_BOUND_MS);
    assert!(report.fronting_bound_exceeded);
    assert_eq!(report.restore, RestoreStatus::Restored);
}

/// A cancel once the target is in front stops the run before the press, and
/// the restore decision still runs.
#[test]
fn a_cancel_after_fronting_presses_nothing_and_still_restores() {
    let mut desk = PressDesk::single();
    desk.cancel_once_fronted = true;
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::Interrupted(FrontingStop::Cancelled))
    );
    assert!(desk.pressed.is_empty());
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
    assert_eq!(desk.finishes, [RestoreStatus::Restored]);
}

/// Input during the enabled poll stops the run with no press intent, and
/// the restore decision still runs and discloses the input.
#[test]
fn input_during_the_poll_journals_no_press_and_still_runs_the_restore_decision() {
    let mut desk = PressDesk::new(vec![StepScript {
        enabled_on_poll: Some(3),
        ..StepScript::disabled_in_background()
    }]);
    desk.tap_input_on_poll = Some((0, 1));
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::Interrupted(FrontingStop::UserSeizedControl))
    );
    assert!(!desk.log.contains(&"press"), "{:?}", desk.log);
    assert!(desk.pressed.is_empty());
    assert!(desk.log.ends_with(&["claim", "restore_request", "finish"]));
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert!(report.person_input_during_fronting);
    assert_eq!(
        not_fronted_reason(FrontingStop::UserSeizedControl),
        NotFrontedReason::PersonActive
    );
}

/// Input while the target stays frontmost is not a switch: the previous
/// application is restored, and the input is disclosed.
#[test]
fn input_while_the_target_stays_frontmost_restores_and_discloses_the_input() {
    let mut desk = PressDesk::new(vec![StepScript {
        hardware_input_during_settle: true,
        ..StepScript::disabled_in_background()
    }]);
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert!(report.person_input_during_fronting);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
}

/// The person switched to a third application with hardware input while
/// the target was in front: they are left there, and no restore is
/// requested.
#[test]
fn a_switch_to_a_third_app_with_hardware_input_skips_the_restore() {
    let mut desk = PressDesk::new(vec![StepScript {
        switch_to_during_settle: Some(THIRD),
        hardware_input_during_settle: true,
        ..StepScript::disabled_in_background()
    }]);
    let report = run(&mut desk);
    assert_eq!(
        report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert_eq!(desk.requests_for(PREVIOUS), 0, "{:?}", desk.front_requests);
    assert_eq!(desk.frontmost, Some(THIRD));
    assert!(report.person_input_during_fronting);
    assert_eq!(
        desk.finishes,
        [RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }]
    );
}

/// A third-app switch without key/button/scroll evidence cannot safely be
/// attributed to the press: a virtual-desktop gesture may make the same switch.
#[test]
fn a_press_leaves_a_third_app_alone_without_hardware_evidence() {
    let mut desk = PressDesk::new(vec![StepScript {
        switch_to_during_settle: Some(THIRD),
        ..StepScript::disabled_in_background()
    }]);
    let report = run(&mut desk);
    assert_eq!(
        report.restore,
        RestoreStatus::SkippedPerson {
            now_front: Some(THIRD)
        }
    );
    assert_eq!(desk.front_requests, [TARGET]);
    assert_eq!(desk.frontmost, Some(THIRD));
    assert!(!report.person_input_during_fronting);
}

#[test]
fn a_previous_application_that_will_not_come_back_is_a_failed_restore() {
    let mut desk = PressDesk::single();
    desk.refuse_front_of = Some(PREVIOUS);
    let report = run(&mut desk);
    assert_eq!(report.steps_pressed, 1);
    assert_eq!(
        report.restore,
        RestoreStatus::Failed {
            left_in_front: Some(TARGET)
        }
    );
    assert_eq!(desk.finishes.len(), 1);
}

/// A batch whose every step needs the front fronts once, holds the badge
/// only for the first step, and makes one restore decision at the end.
#[test]
fn a_batch_fronts_once_and_makes_one_restore_decision() {
    let mut desk = PressDesk::new(vec![StepScript::disabled_in_background(); 3]);
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(desk.pressed, [0, 1, 2]);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert_eq!(desk.locks_taken, 1);
    assert_eq!(desk.badge_holds, [(0, true), (1, false), (2, false)]);
    assert_eq!(desk.log.iter().filter(|e| **e == "pre_read").count(), 1);
    assert_eq!(desk.finishes, [RestoreStatus::Restored]);
    assert_eq!(report.bound_ms, press_fronting_bound_ms(3));
    assert!(!report.fronting_bound_exceeded, "{report:?}");
}

/// The person changes the target while the badge is on its way, then
/// leaves the desk quiet for more than the idle threshold while the run
/// waits for the lock. The idle gate alone would pass; the target-change
/// guard after the lock refuses before anything is fronted.
#[test]
fn a_target_change_during_badge_arrival_is_refused_after_a_quiet_lock_wait() {
    let mut desk = PressDesk::single();
    desk.change_target_during_badge = true;
    desk.badge_ms = 300;
    desk.lock_wait_ms = 900;
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::NotFronted(FrontingStop::PersonChangedTarget))
    );
    assert!(desk.now - desk.last_hardware_input_ms.unwrap() > OBSERVED_DISPATCH_IDLE_MS);
    assert!(desk.front_requests.is_empty());
    assert!(desk.pressed.is_empty());
    assert_eq!(
        not_fronted_reason(FrontingStop::PersonChangedTarget),
        NotFrontedReason::PersonChangedTarget
    );
    // The lock was taken, so it is released, with nothing to put back.
    assert_eq!(desk.finishes, [RestoreStatus::NotNeeded]);
}

/// A press on an element that is enabled in the background takes the
/// ordinary path: it never asks for the fronting lock, so it can never be
/// `fronting_busy`, even while another agent holds the lock.
#[test]
fn a_background_press_on_an_enabled_element_never_waits_on_the_fronting_lock() {
    let mut desk = PressDesk::new(vec![StepScript {
        background_enabled: true,
        ..StepScript::default()
    }]);
    desk.lock_busy = true;
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.steps_pressed, 1);
    assert!(!desk.log.contains(&"lock"), "{:?}", desk.log);
    assert!(desk.front_requests.is_empty());
    assert_eq!(report.restore, RestoreStatus::NotNeeded);
    assert!(desk.finishes.is_empty());
}

/// The badge's first appearance takes the whole arrival cap, the element
/// enables late in the poll, and the press settles for its whole bound: the
/// badge comes before the front request, so it does not count, and the run
/// stays inside the bound.
#[test]
fn a_first_badge_appearance_late_enablement_and_full_settle_stay_within_the_bound() {
    let mut desk = PressDesk::new(vec![StepScript {
        enabled_on_poll: Some(240),
        ..StepScript::disabled_in_background()
    }]);
    desk.badge_ms = 1_090;
    desk.front_latency_ms = 290;
    desk.press_ms = 0;
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.steps_pressed, 1);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert!(
        report.fronted_interval_ms > 290 + 400 + PRESS_SETTLE_BOUND_MS,
        "{report:?}"
    );
    assert!(!report.fronting_bound_exceeded, "{report:?}");
}

#[test]
fn a_busy_fronting_lock_stops_at_its_limit_with_nothing_fronted() {
    let mut desk = PressDesk::single();
    desk.lock_busy = true;
    let before = desk.now;
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::NotFronted(FrontingStop::FrontingLockTimedOut))
    );
    assert_eq!(
        desk.now - before,
        desk.badge_ms + FRONTING_LOCK_WAIT_MS,
        "the wait ends at the lock limit"
    );
    assert!(desk.front_requests.is_empty());
    assert!(desk.finishes.is_empty());
}

#[test]
fn an_unconfirmed_held_release_stops_fronting_before_the_front() {
    let mut desk = PressDesk::single();
    desk.held_input_confirmed = false;
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::NotFronted(FrontingStop::HeldInputUnconfirmed))
    );
    assert!(desk.front_requests.is_empty());
    assert!(!desk.log.contains(&"guard1"));
}

/// Cleanup that takes the obligation right after it is registered, before
/// the front, prevents the front; its own decision stands, and the run does
/// not release the lock a second time.
#[test]
fn cleanup_that_takes_the_obligation_before_the_front_prevents_it() {
    let mut desk = PressDesk::single();
    desk.cleanup_takes_at_registration = true;
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::NotFronted(
            FrontingStop::CleanupTookObligation
        ))
    );
    assert!(desk.front_requests.is_empty());
    assert_eq!(report.restore, RestoreStatus::NotNeeded);
    assert!(desk.finishes.is_empty());
}

/// A settle with no input from the person runs to its bound: the watch on
/// the settle never ends it early on its own.
#[test]
fn a_quiet_settle_runs_to_its_bound() {
    let mut desk = PressDesk::single();
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(desk.settled_ms, [PRESS_SETTLE_BOUND_MS]);
    assert_eq!(report.abort, None);
    assert!(!report.person_input_during_fronting);
    assert_eq!(report.restore, RestoreStatus::Restored);
}

/// The person types while a fronted press settles: their keys would land in
/// the target, so the settle ends at the next check rather than at its
/// bound, the restore decision runs straight after it, and the input is
/// reported the way input before a press is. The press itself took effect,
/// so the run has no stop.
#[test]
fn input_during_the_settle_ends_it_early_and_restores_at_once() {
    let mut desk = PressDesk::new(vec![StepScript {
        tap_input_into_settle_ms: Some(100),
        ..StepScript::disabled_in_background()
    }]);
    let report = run(&mut desk);
    assert_eq!(report.stop, None, "{report:?}");
    assert_eq!(report.steps_pressed, 1);
    assert_eq!(desk.settled_ms, [100], "the settle ends at the next check");
    assert!(
        desk.log
            .ends_with(&["press", "settle", "claim", "restore_request", "finish"]),
        "{:?}",
        desk.log
    );
    assert_eq!(
        report.abort.map(|abort| abort.reason),
        Some(AbortReason::UserSeizedControl)
    );
    assert!(report.person_input_during_fronting);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
    assert_eq!(desk.frontmost, Some(PREVIOUS));
    assert_eq!(desk.finishes, [RestoreStatus::Restored]);
}

/// In a batch, input during one step's settle stops the run before the next
/// step does anything, not even schedule its badge, and that next step is
/// reported stopped by the person, as input before a press is.
#[test]
fn input_during_a_batch_settle_stops_the_next_step_and_restores_at_once() {
    let mut desk = PressDesk::new(vec![
        StepScript {
            tap_input_into_settle_ms: Some(150),
            ..StepScript::disabled_in_background()
        },
        StepScript::disabled_in_background(),
    ]);
    let report = run(&mut desk);
    assert_eq!(
        report.stop,
        Some(PressRunStop::Interrupted(FrontingStop::UserSeizedControl))
    );
    assert_eq!(report.stopped_at, Some(1));
    assert_eq!(desk.pressed, [0]);
    assert_eq!(desk.settled_ms, [150]);
    assert_eq!(desk.badge_holds, [(0, true)], "the next step never began");
    assert!(
        desk.log
            .ends_with(&["press", "settle", "claim", "restore_request", "finish"]),
        "{:?}",
        desk.log
    );
    assert!(report.person_input_during_fronting);
    assert_eq!(report.restore, RestoreStatus::Restored);
    assert_eq!(desk.front_requests, [TARGET, PREVIOUS]);
}
