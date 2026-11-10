//! App-use fronting: the decision table, the fronting lock, the one-way
//! front, and the fronting paths served through the plane against a fake
//! platform whose screen records every front and restore request.

use super::fronting::*;
use super::*;
use cerebellum_computer::dispatch::{
    not_fronted_reason, FrontingBracketHost, FrontingStop, HardwareInputSnapshot, HeartbeatMarker,
    HeartbeatObservation, HeartbeatProbe, IdleGateRefusal, NotFrontedReason, RestoreStatus,
    SeizeWatcher, SourcedInputEvent, UnitPosted, UserIdleEstimator, OBSERVED_DISPATCH_IDLE_MS,
};
use cerebellum_computer::platform::IdleReading;
use cerebellum_core::config::AppUse;
use std::time::Duration;

// ---------------------------------------------------------------------------
// The decision table
// ---------------------------------------------------------------------------

fn admission(mode: AppUse, attended: bool, admitted: bool, takeover_held: bool) -> Admission {
    Admission {
        mode,
        attended,
        app_use_fronting_admitted: admitted,
        // A build carrying the app-use review carries the takeover review
        // too; a build without it is tested with the bracket admitted, as
        // today's release builds are.
        bracket_admitted: true,
        takeover_held,
    }
}

/// Every combination of mode, attendance and admission, for the three
/// things the setting decides: whether a background `bring_to_front` image
/// read answers `image_needs_takeover`, whether a Command chord to a
/// background application answers `modifier_chord_needs_foreground`, and
/// whether anything fronts.
#[test]
fn mode_attendance_and_admission_decide_takeover_chords_and_fronting() {
    for mode in [AppUse::Foreground, AppUse::Background] {
        for attended in [true, false] {
            for admitted in [true, false] {
                let without_takeover = admission(mode, attended, admitted, false);
                let case = format!("{mode:?} attended={attended} admitted={admitted}");

                // Fronting outside the takeover bracket: only attended and
                // admitted, and otherwise the reason says which.
                let expected = match (attended, admitted) {
                    (false, _) => Err(FrontingStop::Unattended),
                    (true, false) => Err(FrontingStop::FrontingNotAdmitted),
                    (true, true) => Ok(()),
                };
                assert_eq!(without_takeover.may_front(), expected, "{case}");

                // A Command chord to a background application.
                let route = chord_route(without_takeover, false, true, false);
                let expected = match (attended, admitted) {
                    (false, _) => ChordRoute::Refuse(ChordRefusal::TakeoverNotForFlows),
                    (true, true) => ChordRoute::FrontWithAppGrant,
                    (true, false) => ChordRoute::Refuse(ChordRefusal::ModifierChordNeedsForeground),
                };
                assert_eq!(route, expected, "{case}");
                if attended && admitted {
                    assert_ne!(
                        route,
                        ChordRoute::Refuse(ChordRefusal::ModifierChordNeedsForeground),
                        "an attended, admitted session never answers \
                         modifier_chord_needs_foreground: {case}"
                    );
                }
                // Plain typing and a frontmost target never front.
                assert_eq!(
                    chord_route(without_takeover, false, false, false),
                    ChordRoute::PerProcess
                );
                assert_eq!(
                    chord_route(without_takeover, true, true, false),
                    ChordRoute::PerProcess
                );

                // The image read: without takeover a background
                // bring_to_front still needs takeover in every case; in
                // foreground mode a successful front removes the need.
                let (bring, takeover) = image_fronting(without_takeover, true, false);
                assert!(bring && !takeover, "{case}: image_needs_takeover");
                let (bring, takeover) = image_fronting(without_takeover, true, true);
                match mode {
                    AppUse::Foreground => assert!(!bring && !takeover, "{case}"),
                    AppUse::Background => assert!(bring && !takeover, "{case}"),
                }
                // With takeover held, only an attended background read runs
                // the temporary bracket; foreground mode never does.
                let with_takeover = admission(mode, attended, admitted, true);
                let (_, takeover) = image_fronting(with_takeover, true, false);
                assert_eq!(
                    takeover,
                    mode == AppUse::Background && attended,
                    "{case} with takeover"
                );
            }
        }
    }
    // A build without the app-use review keeps today's takeover rules.
    let held = admission(AppUse::Background, true, false, true);
    assert_eq!(
        chord_route(held, false, true, false),
        ChordRoute::TakeoverBracket
    );
    let unreviewed = Admission {
        bracket_admitted: false,
        ..held
    };
    assert_eq!(
        chord_route(unreviewed, false, true, false),
        ChordRoute::Refuse(ChordRefusal::KeystrokesNeedForeground)
    );
}

/// A system shortcut, which acts outside the application, takes the
/// takeover route in every case: frontmost or not, and whether or not this
/// build fronts under the app grant. A chord acting inside the application,
/// destructive or not, keeps the app grant's route.
#[test]
fn system_wide_chords_take_the_takeover_route_and_in_app_chords_keep_the_app_grant() {
    for mode in [AppUse::Foreground, AppUse::Background] {
        for admitted in [true, false] {
            for frontmost in [true, false] {
                let case = format!("{mode:?} admitted={admitted} frontmost={frontmost}");
                let without = admission(mode, true, admitted, false);
                let held = admission(mode, true, admitted, true);
                assert_eq!(
                    chord_route(without, frontmost, true, true),
                    ChordRoute::Refuse(ChordRefusal::ModifierChordNeedsForeground),
                    "a system shortcut without takeover: {case}"
                );
                assert_eq!(
                    chord_route(held, frontmost, true, true),
                    ChordRoute::TakeoverBracket,
                    "a system shortcut with takeover: {case}"
                );
                assert_eq!(
                    chord_route(
                        Admission {
                            bracket_admitted: false,
                            ..held
                        },
                        frontmost,
                        true,
                        true
                    ),
                    ChordRoute::Refuse(ChordRefusal::KeystrokesNeedForeground),
                    "a system shortcut in a build without the takeover review: {case}"
                );
                assert_eq!(
                    chord_route(
                        admission(mode, false, admitted, true),
                        frontmost,
                        true,
                        true
                    ),
                    ChordRoute::Refuse(ChordRefusal::TakeoverNotForFlows),
                    "a system shortcut in an unattended session: {case}"
                );
                // An in-app chord, such as Command-Q, keeps today's route.
                let in_app = if frontmost {
                    ChordRoute::PerProcess
                } else if admitted {
                    ChordRoute::FrontWithAppGrant
                } else {
                    ChordRoute::Refuse(ChordRefusal::ModifierChordNeedsForeground)
                };
                assert_eq!(
                    chord_route(without, frontmost, true, false),
                    in_app,
                    "{case}"
                );
            }
        }
    }
}

/// Each `fronting.restore` value and every reason the reply can carry
/// appear on the wire as the vocabulary names them.
#[test]
fn every_restore_value_and_reason_reaches_the_reply() {
    let cases = [
        (
            Fronting::untouched(AppUse::Background),
            "not_needed",
            "none",
        ),
        (
            Fronting::untouched(AppUse::Foreground),
            "not_needed",
            "foreground_mode",
        ),
        (
            Fronting::one_way(AppUse::Foreground),
            "left_in_front",
            "foreground_mode",
        ),
        (
            Fronting::temporary(
                AppUse::Background,
                Purpose::NeedsFront,
                RestoreStatus::Restored,
                true,
            ),
            "restored",
            "needs_front",
        ),
        (
            Fronting::temporary(
                AppUse::Background,
                Purpose::BringToFront,
                RestoreStatus::SkippedPerson { now_front: Some(3) },
                true,
            ),
            "skipped_person",
            "bring_to_front",
        ),
        (
            Fronting::temporary(
                AppUse::Background,
                Purpose::NeedsFront,
                RestoreStatus::Failed {
                    left_in_front: Some(4),
                },
                false,
            ),
            "failed",
            "needs_front",
        ),
    ];
    for (fronting, restore, purpose) in cases {
        let value = fronting.to_value();
        assert_eq!(value["restore"], restore, "{value}");
        assert_eq!(value["purpose"], purpose, "{value}");
    }
    let stops = [
        FrontingStop::HeldInputUnconfirmed,
        FrontingStop::PersonChangedTarget,
        FrontingStop::ObserverUnavailable,
        FrontingStop::IdleGateRefused(IdleGateRefusal::BelowThreshold {
            threshold_ms: OBSERVED_DISPATCH_IDLE_MS,
            hid_idle_ms: 1,
            user_idle_ms: 1,
        }),
        FrontingStop::PreviousUnknown,
        FrontingStop::FrontFailed,
        FrontingStop::Cancelled,
        FrontingStop::FrontingLockTimedOut,
        FrontingStop::Unattended,
        FrontingStop::FrontingNotAdmitted,
        FrontingStop::TargetNotRead,
    ];
    let mut seen = std::collections::BTreeSet::new();
    for stop in stops {
        let value = Fronting::stopped(AppUse::Foreground, Purpose::ForegroundMode, stop).to_value();
        assert_eq!(value["fronted"], false);
        seen.insert(value["not_fronted_reason"].as_str().unwrap().to_owned());
    }
    let all: std::collections::BTreeSet<_> = NotFrontedReason::ALL
        .iter()
        .map(|reason| reason.as_str().to_owned())
        .collect();
    assert_eq!(seen, all, "every reason has a stop that produces it");
}

/// A `not_fronted` refusal, and replies carrying each kind of `fronting`,
/// pass every listed action's frozen result schema as withholding
/// enforcement checks it.
#[test]
fn fronting_replies_pass_the_frozen_result_schemas() {
    let refused = not_fronted_reply(Fronting::stopped(
        AppUse::Foreground,
        Purpose::ForegroundMode,
        FrontingStop::FrontingLockTimedOut,
    ));
    for capability in [
        "computer.read_state",
        "computer.press_element",
        "computer.press_point",
        "computer.write_text",
        "computer.open_app",
    ] {
        cerebellum_computer::platform::vocabulary::validate_capability_result(capability, &refused)
            .unwrap_or_else(|error| panic!("{capability}: {error:?}"));
    }
    let mut completed = json!({"outcome": "completed"});
    Fronting::temporary(
        AppUse::Background,
        Purpose::NeedsFront,
        RestoreStatus::SkippedPerson { now_front: None },
        true,
    )
    .apply(&mut completed);
    completed["fronting_bound_exceeded"] = json!(true);
    cerebellum_computer::platform::vocabulary::validate_capability_result(
        "computer.press_element",
        &completed,
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// The fronting lock
// ---------------------------------------------------------------------------

/// A caller queued behind a front takes the lock as soon as that front's
/// restore decision releases it, and one queued behind a front that holds
/// it past the limit stops `fronting_busy` at exactly the limit.
#[tokio::test(start_paused = true)]
async fn the_fronting_lock_serializes_fronts_and_stops_busy_at_its_limit() {
    let lock = FrontingLock::isolated();
    let cancel = crate::CancelHandle::pending();

    let held = lock.take(&cancel).await.unwrap();
    let release_at = tokio::time::Instant::now() + Duration::from_millis(600);
    tokio::spawn(async move {
        tokio::time::sleep_until(release_at).await;
        drop(held);
    });
    let queued = tokio::time::Instant::now();
    let taken = lock.take(&cancel).await;
    assert!(taken.is_ok(), "taken once the first front released it");
    assert_eq!(queued.elapsed(), Duration::from_millis(600));
    drop(taken);

    let _held = lock.take(&cancel).await.unwrap();
    let queued = tokio::time::Instant::now();
    assert_eq!(
        lock.take(&cancel).await.err(),
        Some(FrontingStop::FrontingLockTimedOut)
    );
    assert_eq!(
        queued.elapsed(),
        Duration::from_millis(crate::budgets::FRONTING_LOCK_WAIT_MS)
    );
    assert_eq!(
        not_fronted_reason(FrontingStop::FrontingLockTimedOut),
        NotFrontedReason::FrontingBusy
    );
}

/// A cancel while waiting for the lock stops the wait at once.
#[tokio::test(start_paused = true)]
async fn a_cancel_while_waiting_for_the_lock_stops_at_once() {
    let lock = FrontingLock::isolated();
    let cancel = crate::CancelHandle::pending();
    let _held = lock.take(&cancel).await.unwrap();
    let waiter = {
        let lock = lock.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move { lock.take(&cancel).await.err() })
    };
    tokio::time::sleep(Duration::from_millis(100)).await;
    let started = tokio::time::Instant::now();
    cancel.cancel();
    assert_eq!(waiter.await.unwrap(), Some(FrontingStop::Cancelled));
    assert_eq!(started.elapsed(), Duration::ZERO);
}

// ---------------------------------------------------------------------------
// A fake screen: the frontmost application lives in the desk the plane reads
// from, and every front and restore request is logged in order.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn a_global_drag_starting_after_guard_zero_waits_until_the_front_finishes() {
    use super::held_input::{HeldInput, HeldPress};
    let lock = FrontingLock::isolated();
    let cancel = crate::CancelHandle::pending();
    let held = Arc::new(HeldInput::default());
    let screen = Screen::new(&mail_desk());
    let front = lock.take(&cancel).await.unwrap();
    assert!(held_input_confirmed(&held), "guard zero passed");

    let drag = SyntheticAction::drag_pointer(
        cerebellum_computer::platform::SyntheticPoint { x: 1.0, y: 1.0 },
        cerebellum_computer::platform::SyntheticPoint { x: 2.0, y: 2.0 },
    );
    let send = held.begin_global_send(
        HeldPress::global(&other_app(), &drag).unwrap(),
        Some(under_terminal()),
        &lock,
        &cancel,
    );
    tokio::pin!(send);
    // Poll registration in the gap after guard zero, before request_front.
    tokio::select! {
        biased;
        _ = &mut send => panic!("global drag registered between guard zero and the front"),
        () = tokio::task::yield_now() => {}
    }
    assert!(!held.global_send_outstanding());
    FakeSession(screen.clone()).request_front(4242);
    assert_eq!(screen.log(), ["front:4242"]);
    drop(front);
    let ticket = send.await.unwrap();
    assert!(held.global_send_outstanding());
    assert!(
        lock.held(),
        "the send retains the exclusion until discharge"
    );
    assert!(!held_input_confirmed(&held));
    ticket.settle(HeldStateDisposition::NoneHeld, |_| false);
    assert!(!lock.held());
    assert!(held_input_confirmed(&held));

    let unknown = held
        .begin_global_send(
            HeldPress::global(&other_app(), &drag).unwrap(),
            None,
            &lock,
            &cancel,
        )
        .await
        .unwrap();
    drop(unknown);
    assert!(
        lock.held(),
        "an unknown global release retains the exclusion in quarantine"
    );
    assert!(!held_input_confirmed(&held));
}

#[allow(dead_code)]
mod support {
    use crate as cerebellum;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/it/support/computer.rs"
    ));
}

use cerebellum_computer::app_state::source::{ElementFacts, RawElement};
use cerebellum_computer::capture::InMemoryCaptureBackend;
use cerebellum_computer::platform::{
    AccessibilityTreeRequest, AccessibilityTreeResult, AttendancePreconditionRequest,
    AttendancePreconditionResult, CapabilityAdvertisementContext, CapabilityDeclaration,
    DispatchResult, DriverError, EffectObservationRequest, EffectObservationResult, EffectStatus,
    ElementResolutionRequest, ElementResolutionResult, FocusQueryRequest, FocusQueryResult,
    FrontedDispatchHooks, FrontedDispatchRequest, FrontingRestoreHost, FrontingSession,
    FrontingSnapshot, GlobalDispatchRequest, HeldStateDisposition, InputObservationRequest,
    InputObservationResult, InputObserverLiveness, PlatformDriver, ProcessEventRefusal,
    ProcessGrant, RestoreHostSource, SemanticDispatchRequest, SequencePostFailure,
    SyntheticDispatchRequest,
};
use cerebellum_core::journal::{InMemoryJournalStorage, ValidatedSeverityTaxonomy};

const TARGET: u32 = 4242;
const PREVIOUS: u32 = 100;
const THIRD: u32 = 300;
const OUR_PID: i64 = 7;

struct ScreenState {
    pointer: pointer_tests::Script,
    now: u64,
    idle_ms: u64,
    observer: bool,
    comes_forward: bool,
    front_delay_ms: Option<u64>,
    pending_front_at: Option<u64>,
    late_watch_gate: Option<Arc<std::sync::atomic::AtomicBool>>,
    late_watch_after_ms: u64,
    coverage_start_ms: u64,
    restore_started: Option<Arc<tokio::sync::Notify>>,
    restore_until: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// Every front and restore request, and every post and release, in
    /// order.
    log: Vec<String>,
    last_input_ms: Option<u64>,
    /// A chord's post fails with its keys possibly still held.
    post_unknown: bool,
    /// Whether the paired release of held keys returns.
    release_ok: bool,
    /// These elements of the desk read enabled while the target is
    /// fronted, and disabled again once another application is.
    enable_on_front: Vec<u64>,
    /// A chord's post stays in flight, with its keys down, until this call's
    /// terminal is chosen, and then fails with them possibly held.
    hold_until_stopped: Option<Arc<crate::TerminalArbiter>>,
    /// Told when the chord's post begins.
    posting: Option<Arc<tokio::sync::Notify>>,
    /// Told when a paired release of held keys begins.
    releasing: Option<Arc<tokio::sync::Notify>>,
    /// The release, once begun, chooses this call's terminal with this
    /// cause, as the work deadline passing during it would.
    release_ends_call: Option<(Arc<crate::TerminalArbiter>, crate::TerminalCause)>,
    /// The release, once begun, stays in flight until this call's terminal
    /// is chosen.
    release_until_stopped: Option<Arc<crate::TerminalArbiter>>,
    /// The release, once begun, stays in flight until this is set.
    release_until: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// The release logs `released` when it returns, after staying in flight
    /// a little longer, so a restore made before it returned shows up in
    /// the log ahead of it.
    log_release_end: bool,
    /// The person presses a key, which the run's own observer drains at its
    /// next check.
    person_key_pending: bool,
}

#[derive(Clone)]
struct Screen {
    state: Arc<StdMutex<ScreenState>>,
    desk: support::Desk,
}

impl Screen {
    fn new(desk: &support::Desk) -> Self {
        desk.state().frontmost = Some(PREVIOUS);
        Self {
            state: Arc::new(StdMutex::new(ScreenState {
                pointer: pointer_tests::Script::default(),
                now: 0,
                idle_ms: OBSERVED_DISPATCH_IDLE_MS + 500,
                observer: true,
                comes_forward: true,
                front_delay_ms: None,
                pending_front_at: None,
                late_watch_gate: None,
                late_watch_after_ms: 400,
                coverage_start_ms: 0,
                restore_started: None,
                restore_until: None,
                log: Vec::new(),
                last_input_ms: None,
                post_unknown: false,
                release_ok: true,
                enable_on_front: Vec::new(),
                hold_until_stopped: None,
                posting: None,
                releasing: None,
                release_ends_call: None,
                release_until_stopped: None,
                release_until: None,
                log_release_end: false,
                person_key_pending: false,
            })),
            desk: desk.clone(),
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, ScreenState> {
        self.state.lock().unwrap()
    }

    fn log(&self) -> Vec<String> {
        self.state().log.clone()
    }

    fn frontmost(&self) -> Option<u32> {
        self.desk.state().frontmost
    }

    fn front(&self, who: &str, pid: u32) -> bool {
        let (comes_forward, enable) = {
            let mut state = self.state();
            state.log.push(format!("{who}:{pid}"));
            if pid == TARGET {
                if let Some(delay) = state.front_delay_ms {
                    state.pending_front_at = Some(state.now + delay);
                    return true;
                }
            }
            (state.comes_forward, state.enable_on_front.clone())
        };
        if comes_forward {
            let mut desk = self.desk.state();
            desk.frontmost = Some(pid);
            for token in enable {
                if let Some(element) = desk.elements.get_mut(&token) {
                    element.enabled = Some(pid == TARGET);
                }
            }
        }
        true
    }

    fn snapshot(&self) -> Option<HardwareInputSnapshot> {
        let state = self.state();
        if !state.observer {
            return None;
        }
        Some(HardwareInputSnapshot {
            coverage_start_ms: state.coverage_start_ms,
            last_input_ms: state.last_input_ms,
        })
    }

    fn advance(&self, milliseconds: u64) {
        let gate = {
            let state = self.state();
            (state.now >= state.late_watch_after_ms)
                .then(|| state.late_watch_gate.clone())
                .flatten()
        };
        if let Some(gate) = gate {
            let end = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while !gate.load(std::sync::atomic::Ordering::Acquire) {
                assert!(
                    std::time::Instant::now() < end,
                    "late watcher gate timed out"
                );
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let landed = {
            let mut state = self.state();
            state.now += milliseconds;
            if state.pending_front_at.is_some_and(|at| at <= state.now) {
                state.pending_front_at = None;
                true
            } else {
                false
            }
        };
        if landed {
            self.desk.state().frontmost = Some(TARGET);
        }
    }

    fn probe(&self) -> HeartbeatProbe {
        HeartbeatProbe {
            marker: HeartbeatMarker::new(1),
            posted_at_ms: self.state().now,
            our_pid: OUR_PID,
        }
    }
}

fn seen(probe: HeartbeatProbe) -> HeartbeatObservation {
    HeartbeatObservation::Seen {
        marker: probe.marker,
        source_unix_process_id: OUR_PID,
        observed_at_ms: probe.posted_at_ms,
    }
}

struct FakeRestore(Screen);

impl FrontingRestoreHost for FakeRestore {
    fn now_ms(&mut self) -> u64 {
        self.0.state().now
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.0.advance(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.0.frontmost()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        let (started, until) = {
            let state = self.0.state();
            (state.restore_started.clone(), state.restore_until.clone())
        };
        if let Some(started) = started {
            started.notify_one();
        }
        if let Some(until) = until {
            let end = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while !until.load(std::sync::atomic::Ordering::Acquire) {
                assert!(std::time::Instant::now() < end, "restore gate timed out");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        self.0.front("restore", pid)
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.0.snapshot()
    }
}

struct FakeSession(Screen);

impl FrontingSession for FakeSession {
    fn now_ms(&mut self) -> u64 {
        self.0.state().now
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.0.advance(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.0.frontmost()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.0.front("front", pid)
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn open_observer(&mut self) -> bool {
        self.0.state().observer
    }
    fn read_idle(&mut self) -> IdleReading {
        IdleReading::Milliseconds(self.0.state().idle_ms)
    }
    fn drain(&mut self) -> Vec<SourcedInputEvent> {
        if std::mem::take(&mut self.0.state().person_key_pending) {
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
        self.0.probe()
    }
    fn observe_heartbeat(
        &mut self,
        probe: HeartbeatProbe,
        _watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        seen(probe)
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.0.snapshot()
    }
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost> {
        Box::new(FakeRestore(self.0.clone()))
    }
    fn user_idle(&self) -> Arc<StdMutex<UserIdleEstimator>> {
        Arc::new(StdMutex::new(UserIdleEstimator::new()))
    }
}

/// The keystroke bracket's host on the fake screen.
struct FakeBracket(Screen);

impl RestoreHostSource for FakeBracket {
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost> {
        Box::new(FakeRestore(self.0.clone()))
    }
}

impl FrontingBracketHost for FakeBracket {
    type Tap = ();
    fn now_ms(&mut self) -> u64 {
        self.0.state().now
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.0.advance(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.0.frontmost()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.0.front("front", pid)
    }
    fn our_pid(&self) -> i64 {
        OUR_PID
    }
    fn create_tap(&mut self) -> Option<()> {
        self.0.state().observer.then_some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        IdleReading::Milliseconds(self.0.state().idle_ms)
    }
    fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
        Vec::new()
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        self.0.probe()
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        probe: HeartbeatProbe,
        _watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        seen(probe)
    }
    fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
        let (mut unknown, hold, posting) = {
            let mut state = self.0.state();
            state.log.push("post".into());
            (
                state.post_unknown,
                state.hold_until_stopped.clone(),
                state.posting.take(),
            )
        };
        if let Some(posting) = posting {
            posting.notify_one();
        }
        if let Some(terminal) = hold {
            let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while !terminal.gate.stopped() && std::time::Instant::now() < give_up {
                std::thread::yield_now();
            }
            unknown = true;
        }
        if unknown {
            return Err(SequencePostFailure {
                posts_returned: 1,
                refusal: ProcessEventRefusal::Cancelled,
                held_state: HeldStateDisposition::Unknown,
            });
        }
        Ok(UnitPosted {
            posts_returned: 4,
            generation_verifications: 8,
        })
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        self.0.snapshot()
    }
}

/// A platform driver over the fake screen. It runs the real hooked bracket
/// for a fronted chord and the real session for every other front.
struct FakeDriver {
    screen: Screen,
    hooks: Option<Box<dyn FrontedDispatchHooks>>,
    pointer_guard: Option<cerebellum_computer::platform::GlobalPointerGuard>,
}

impl PlatformDriver for FakeDriver {
    fn capability_declarations(
        &self,
        _context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        Vec::new()
    }
    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        Err(DriverError::Unsupported("the fake reads no tree"))
    }
    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        Err(DriverError::Unsupported("the fake resolves nothing"))
    }
    fn dispatch_semantic(
        &mut self,
        _request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("the fake dispatches nothing"))
    }
    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        self.screen.state().log.push("post".into());
        Ok(DispatchResult {
            accepted_by_platform: true,
            effect_status: EffectStatus::EffectIndeterminate,
            unreadable_subtrees: 0,
            delivery_posts_returned: 1,
            delivery_generation_verifications: 2,
        })
    }
    fn dispatch_global(
        &mut self,
        request: GlobalDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        pointer_tests::dispatch(self, request, cancelled)
    }
    fn accept_pointer_fronting(
        &mut self,
        guard: cerebellum_computer::platform::GlobalPointerGuard,
    ) -> bool {
        if self.screen.state().pointer.reject_pointer {
            return false;
        }
        self.pointer_guard = Some(guard);
        true
    }
    fn release_held(
        &mut self,
        _target: &ProcessGrant,
        _action: &SyntheticAction,
    ) -> Result<u64, DriverError> {
        let (ok, releasing, ends_call, until_stopped, until) = {
            let mut state = self.screen.state();
            state.log.push("release".into());
            (
                state.release_ok,
                state.releasing.take(),
                state.release_ends_call.take(),
                state.release_until_stopped.clone(),
                state.release_until.clone(),
            )
        };
        if let Some(releasing) = releasing {
            releasing.notify_one();
        }
        if let Some((terminal, cause)) = ends_call {
            terminal.stop(cause);
        }
        let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
        if let Some(terminal) = until_stopped {
            while !terminal.gate.stopped() && std::time::Instant::now() < give_up {
                std::thread::yield_now();
            }
        }
        if let Some(until) = until {
            while !until.load(std::sync::atomic::Ordering::SeqCst)
                && std::time::Instant::now() < give_up
            {
                std::thread::yield_now();
            }
        }
        if self.screen.state().log_release_end {
            std::thread::sleep(Duration::from_millis(100));
            self.screen.state().log.push("released".into());
        }
        if ok {
            Ok(2)
        } else {
            Err(DriverError::Unsupported("the release did not return"))
        }
    }
    fn dispatch_fronted(
        &mut self,
        request: FrontedDispatchRequest,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<cerebellum_computer::dispatch::BracketReport, DriverError> {
        let plan = cerebellum_computer::dispatch::BracketPlan {
            target_pid: request.synthetic.target.pid,
            units: 1,
            maximum_interval_ms: request.maximum_interval_ms,
            maximum_seize_detection_latency_ms: request.maximum_seize_detection_latency_ms,
        };
        let mut host = FakeBracket(self.screen.clone());
        let mut estimator = UserIdleEstimator::new();
        Ok(match self.hooks.take() {
            Some(mut hooks) => {
                cerebellum_computer::platform::run_hooked_fronted(
                    &mut host,
                    &mut estimator,
                    plan,
                    cancelled,
                    hooks.as_mut(),
                    None,
                )
                .report
            }
            None => cerebellum_computer::dispatch::run_fronting_bracket(
                &mut host,
                &mut estimator,
                plan,
                cancelled,
            ),
        })
    }
    fn read_fronted(
        &mut self,
        target: &ProcessGrant,
        maximum_interval_ms: u64,
        cancelled: &dyn Fn() -> bool,
        read: &mut dyn FnMut(),
    ) -> Result<cerebellum_computer::dispatch::BracketReport, DriverError> {
        let plan = cerebellum_computer::dispatch::BracketPlan {
            target_pid: target.pid,
            units: 1,
            maximum_interval_ms,
            maximum_seize_detection_latency_ms: 50,
        };
        let screen = self.screen.clone();
        let mut logged_read = || {
            screen.state().log.push("read".into());
            read();
        };
        let mut host = FakeBracket(self.screen.clone());
        let mut estimator = UserIdleEstimator::new();
        Ok(match self.hooks.take() {
            Some(mut hooks) => {
                cerebellum_computer::platform::run_hooked_fronted(
                    &mut host,
                    &mut estimator,
                    plan,
                    cancelled,
                    hooks.as_mut(),
                    Some(&mut logged_read),
                )
                .report
            }
            None => cerebellum_computer::dispatch::run_fronting_read(
                &mut host,
                &mut estimator,
                plan,
                cancelled,
                &mut logged_read,
            ),
        })
    }
    fn fronting_session(&mut self) -> Result<Box<dyn FrontingSession>, DriverError> {
        Ok(Box::new(FakeSession(self.screen.clone())))
    }
    fn accept_fronted_dispatch_hooks(&mut self, hooks: Box<dyn FrontedDispatchHooks>) -> bool {
        if self.screen.state().pointer.reject_hooks {
            return false;
        }
        self.hooks = Some(hooks);
        true
    }
    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        Ok(FocusQueryResult {
            matches_target: true,
        })
    }
    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported(
            "the fake captures no fronting state",
        ))
    }
    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: true,
            raw_hid_live: true,
            self_echo_filter_live: true,
        }
    }
    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Ok(InputObservationResult {
            human_or_ambiguous_input: false,
            detection_latency_ms: 1,
        })
    }
    fn observe_effect(
        &mut self,
        _request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        Ok(EffectObservationResult {
            status: EffectStatus::EffectIndeterminate,
            failure_reason: Some("post_condition_undeclarable".to_string()),
        })
    }
    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        Ok(AttendancePreconditionResult {
            valid: true,
            lease_generation: Some("fixture-lease".into()),
            age_ms: Some(1),
        })
    }
    fn session_locked(&self) -> Option<bool> {
        Some(false)
    }
}

// ---------------------------------------------------------------------------
// The plane over the fake screen
// ---------------------------------------------------------------------------

type Plane = ComputerPlane<
    InMemoryCaptureBackend,
    support::TestRedactor,
    ValidatedSeverityTaxonomy,
    InMemoryJournalStorage,
    FakeDriver,
>;

/// A config file holding one `app_use`, never changing.
struct FixedConfig(&'static str);

impl super::app_use::ConfigFiles for FixedConfig {
    fn modified(&self, _path: &std::path::Path) -> std::io::Result<std::time::SystemTime> {
        Ok(std::time::SystemTime::UNIX_EPOCH)
    }
    fn read_to_string(&self, _path: &std::path::Path) -> std::io::Result<String> {
        Ok(self.0.to_owned())
    }
}

fn app_use_file(mode: AppUse) -> super::app_use::LiveAppUse {
    let live = super::app_use::LiveAppUse::new(
        Some(PathBuf::from(
            "/fixture/home/.config/cortexkit/cerebellum.jsonc",
        )),
        Arc::new(FixedConfig(match mode {
            AppUse::Foreground => r#"{"computer_use":{"app_use":"foreground"}}"#,
            AppUse::Background => r#"{"computer_use":{"app_use":"background"}}"#,
        })),
    );
    live.approve_fixture();
    live
}

/// A window with a Send button.
fn mail_desk() -> support::Desk {
    support::Desk::new(vec![RawElement::fixture(1, "AXWindow")
        .titled("Mail")
        .with_children(vec![RawElement::fixture(10, "AXButton").titled("Send")])])
    .with_element(
        10,
        support::DeskElement {
            facts: ElementFacts {
                title: Some("Send".into()),
                ..support::facts("AXButton", &["AXPress"])
            },
            ..support::DeskElement::default()
        },
    )
}

#[derive(Clone)]
struct Rig {
    plane: Arc<Plane>,
    screen: Screen,
    desk: support::Desk,
    management: Arc<crate::management::ManagementPlane>,
    lock: FrontingLock,
}

async fn rig(mode: AppUse, desk: support::Desk) -> Rig {
    rig_with(mode, desk, support::granted_management().await)
}

fn rig_with(
    mode: AppUse,
    desk: support::Desk,
    management: Arc<crate::management::ManagementPlane>,
) -> Rig {
    rig_admitting(mode, desk, management, true, true)
}

/// A rig whose plane has the admissions a release build derives from its
/// reviews: `app_use` admits fronting outside the keystroke bracket, and
/// `bracket` admits that bracket.
fn rig_admitting(
    mode: AppUse,
    desk: support::Desk,
    management: Arc<crate::management::ManagementPlane>,
    app_use: bool,
    bracket: bool,
) -> Rig {
    let screen = Screen::new(&desk);
    let lock = FrontingLock::isolated();
    let driver_screen = screen.clone();
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        support::audit(),
        ResultSchemaEnforcement::Withhold,
        move || FakeDriver {
            screen: driver_screen.clone(),
            hooks: None,
            pointer_guard: None,
        },
    )
    .with_permission_liveness(support::live_permissions())
    .with_app_state_source(desk.source())
    .with_app_use(app_use_file(mode))
    .with_app_use_fronting_admitted(app_use)
    .with_fronting_bracket_admitted(bracket)
    .with_fronting_lock(lock.clone());
    Rig {
        plane: Arc::new(plane),
        screen,
        desk,
        management,
        lock,
    }
}

/// Who a call comes from: the conversation its identity names, and the
/// caller its grants are held for.
#[derive(Clone)]
struct Who {
    identity: cerebellum_core::journal::JournalIdentity,
}

impl Who {
    /// The fixture conversation every other test here acts in.
    fn fixture() -> Self {
        Self {
            identity: support::identity(),
        }
    }

    /// A consent context that can ask nobody, for this conversation.
    fn consent(&self) -> crate::computer_grants::ConsentContext {
        crate::computer_grants::ConsentContext::without_carrier(Self::caller(
            &self.identity.conversation_key,
        ))
    }

    /// Another conversation of the same agent.
    fn conversation(key: &str) -> Self {
        let mut identity = support::identity();
        identity.conversation_key = key.to_owned();
        Self { identity }
    }

    fn caller(key: &str) -> crate::computer_grants::GrantCaller {
        crate::computer_grants::GrantCaller::new(key.to_owned(), support::GRANTEE.to_owned(), false)
    }

    /// Hold the app grant for `bundle` for this conversation, answering its
    /// question "allow for 30 minutes".
    async fn grant(&self, management: &crate::management::ManagementPlane, bundle: &str) {
        let carrier = support::ScriptedCarrier::answering(&["allow_30m"]);
        let (_drain, drain) = tokio::sync::watch::channel(false);
        std::mem::forget(_drain);
        let consent = crate::computer_grants::ConsentContext::new(
            Self::caller(&self.identity.conversation_key),
            Some(Arc::new(carrier.clone()) as Arc<dyn crate::computer_grants::QuestionCarrier>),
            Arc::new(crate::computer_grants::AlwaysOpenRoute),
            drain,
            None,
        );
        management
            .admit_app(bundle, &consent, &crate::CancelHandle::pending())
            .await
            .expect("the fixture grant is answered allow_30m");
    }
}

/// A resolver for several running fixture applications, which also names
/// the application a pid belongs to.
struct Apps(Vec<ProcessGrant>);

impl crate::management::TargetResolver for Apps {
    fn resolve(&self, bundle_identity: &str) -> cerebellum_computer::platform::TargetResolution {
        self.0
            .iter()
            .find(|grant| grant.bundle_identity == bundle_identity)
            .map_or(
                cerebellum_computer::platform::TargetResolution::NotRunning,
                |grant| cerebellum_computer::platform::TargetResolution::Resolved(grant.clone()),
            )
    }
    fn process_for_pid(&self, pid: u32) -> Option<ProcessGrant> {
        self.0.iter().find(|grant| grant.pid == pid).cloned()
    }
    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn crate::computer_grants::AppCode> {
        Arc::new(support::InjectedCode::default())
    }
}

/// A second running application, of another bundle.
fn other_app() -> ProcessGrant {
    ProcessGrant {
        pid: 5151,
        bundle_identity: "com.example.Other".into(),
        process_generation_evidence: "1700000000000001".into(),
    }
}

fn apps_management() -> Arc<crate::management::ManagementPlane> {
    Arc::new(crate::management::ManagementPlane::new(Arc::new(Apps(
        vec![support::grant(), other_app()],
    ))))
}

impl Rig {
    /// The same plane, desk and screen, with the config file now saying
    /// `mode`.
    fn with_mode(self, mode: AppUse) -> Self {
        let plane = Arc::try_unwrap(self.plane)
            .ok()
            .expect("no other handle on the plane")
            .with_app_use(app_use_file(mode));
        Self {
            plane: Arc::new(plane),
            ..self
        }
    }

    async fn serve(&self, name: &str, arguments: Value, cancel: crate::CancelHandle) -> Value {
        self.serve_as(&Who::fixture(), name, arguments, cancel)
            .await
    }

    async fn serve_as(
        &self,
        who: &Who,
        name: &str,
        arguments: Value,
        cancel: crate::CancelHandle,
    ) -> Value {
        let clock = cerebellum_core::clock::FakeClock::new();
        self.plane
            .serve(
                servable(name).expect("served"),
                &arguments,
                ServeContext {
                    cancel,
                    grantee: support::GRANTEE,
                    identity: who.identity.clone(),
                    management: &self.management,
                    consent: who.consent(),
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .unwrap_or_else(|error| panic!("{name} replied outside its row: {error:?}"))
    }

    /// Serve under a call arbiter, as the route serves every call, so a
    /// temporary front has somewhere to register its restore obligation.
    async fn call_under(
        &self,
        terminal: &Arc<crate::TerminalArbiter>,
        name: &str,
        arguments: Value,
    ) -> Value {
        crate::CALL_TERMINAL
            .scope(Arc::clone(terminal), self.call(name, arguments))
            .await
    }

    async fn call(&self, name: &str, arguments: Value) -> Value {
        self.serve(name, arguments, crate::CancelHandle::pending())
            .await
    }

    async fn read(&self) -> Value {
        self.call(
            "computer.read_state",
            json!({"target": support::TARGET_BUNDLE_ID}),
        )
        .await
    }

    /// The id of the Send button, from a read made while the target was not
    /// fronted (the read is made in background mode's sense: it does not
    /// change the front).
    async fn send_id(&self) -> String {
        let reply = self.read().await;
        let tree = reply["state_text"].as_str().unwrap();
        tree.lines()
            .find(|line| line.contains("Send"))
            .unwrap_or_else(|| panic!("no Send in {tree}"))
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    }

    fn seen_marks_recorded(&self) -> bool {
        self.management
            .app_state_sessions()
            .last_seen(&support::identity().conversation_key, &support::grant())
            .is_some()
    }

    /// Leave a press posted by some earlier call unconfirmed released: its
    /// paired release was posted and did not return.
    fn leave_held_input_unconfirmed(&self) {
        let action = SyntheticAction::KeyCombination {
            key: cerebellum_computer::platform::SyntheticKey::A,
            modifiers: SyntheticKeyModifiers {
                command: true,
                ..Default::default()
            },
        };
        let press = super::held_input::HeldPress::per_process(&support::grant(), &action).unwrap();
        let ticket = self.plane.held_input.begin_send(press, None);
        ticket.settle(HeldStateDisposition::Unknown, |_| false);
        assert!(!held_input_confirmed(&self.plane.held_input));
    }
}

fn under_terminal() -> Arc<crate::TerminalArbiter> {
    use subc_protocol::{Frame, FrameType, PROTOCOL_VERSION};
    Arc::new(crate::TerminalArbiter::new(
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            crate::wire::control_flags(),
            1,
            1,
            1,
            serde_json::to_vec(&json!({"name":"computer_use"})).unwrap(),
        )
        .unwrap(),
    ))
}

/// Foreground mode: a read of an application in the background brings it to
/// the front one way, before the read, and asks for nothing back.
#[tokio::test]
async fn a_foreground_read_fronts_its_application_one_way() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    let reply = rig.read().await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"],
        json!({"mode":"foreground","fronted":true,"purpose":"foreground_mode",
            "restore":"left_in_front"})
    );
    assert_eq!(rig.screen.log(), ["front:4242"], "no restore is requested");
    assert_eq!(rig.screen.frontmost(), Some(TARGET));
    assert!(!rig.lock.held(), "a one-way front releases the lock");
    // Already frontmost: nothing to do, and the lock is not taken.
    let reply = rig.read().await;
    assert_eq!(reply["fronting"]["fronted"], false, "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242"]);
}

/// The idle gate refusing a foreground read's front leaves the read
/// unfronted, saying the person is active, and records what it showed; once
/// the person is idle the next read fronts.
#[tokio::test]
async fn a_foreground_read_falls_back_unfronted_while_the_person_is_active() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    rig.screen.state().idle_ms = 200;
    let reply = rig.read().await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"]["fronted"], false);
    assert_eq!(reply["fronting"]["not_fronted_reason"], "person_active");
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(
        rig.seen_marks_recorded(),
        "the fallback read records seen marks"
    );

    rig.screen.state().idle_ms = OBSERVED_DISPATCH_IDLE_MS + 500;
    let reply = rig.read().await;
    assert_eq!(reply["fronting"]["fronted"], true, "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242"]);
}

/// Guard (0) across agents: a release another call left unconfirmed keeps
/// both a foreground read and a background needs-front press from asking
/// for any front.
#[tokio::test]
async fn an_unconfirmed_release_keeps_every_fronting_path_from_fronting() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    rig.leave_held_input_unconfirmed();
    let reply = rig.read().await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"],
        "held_input_unconfirmed"
    );

    let rig = rig.with_mode(AppUse::Background);
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "not_fronted", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"],
        "held_input_unconfirmed"
    );
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    assert!(rig.desk.state().presses.is_empty());
}

/// A cancel while a foreground read waits for the fronting lock reads
/// nothing, captures nothing and records no seen marks.
#[tokio::test(start_paused = true)]
async fn a_cancel_while_waiting_for_the_lock_reads_nothing() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    let held = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let cancel = crate::CancelHandle::pending();
    let call = {
        let (rig, cancel) = (rig.clone(), cancel.clone());
        tokio::spawn(async move {
            rig.serve(
                "computer.read_state",
                json!({"target": support::TARGET_BUNDLE_ID, "include_image": true}),
                cancel,
            )
            .await
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    cancel.cancel();
    let reply = call.await.unwrap();
    drop(held);
    assert_eq!(reply["outcome"], "cancelled", "{reply}");
    assert_eq!(reply["fronting"]["not_fronted_reason"], "cancelled");
    assert!(reply.get("image").is_none());
    assert_eq!(rig.desk.state().focus_reads, 0, "no accessibility read");
    assert!(!rig.seen_marks_recorded());
    assert!(rig.screen.log().is_empty());
}

/// Another call's front holding the lock past its limit leaves a foreground
/// read unfronted with `fronting_busy`, at exactly the limit; a background
/// press on an enabled element never waits on the lock at all.
#[tokio::test(start_paused = true)]
async fn a_busy_lock_stops_a_front_at_its_limit_and_never_holds_an_ordinary_press() {
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    let held = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let reply = rig.read().await;
    assert_eq!(reply["fronting"]["not_fronted_reason"], "fronting_busy");
    assert_eq!(
        started.elapsed(),
        Duration::from_millis(crate::budgets::FRONTING_LOCK_WAIT_MS)
    );

    let rig = rig.with_mode(AppUse::Background);
    let send = rig.send_id().await;
    let started = tokio::time::Instant::now();
    let reply = rig
        .call("computer.press_element", json!({"element_id": send}))
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(
        reply.get("fronting").is_none(),
        "background mode with nothing fronted replies as before: {reply}"
    );
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(rig.desk.state().presses, [10]);
    drop(held);
}

fn command_chord() -> Value {
    json!({"keys": ["command", "c"], "target": support::TARGET_BUNDLE_ID})
}

/// Background mode: a Command chord to an application in the background
/// fronts it under the app grant alone, posts, and puts the previous
/// application back through the call's restore obligation.
#[tokio::test]
async fn a_background_command_chord_fronts_posts_and_restores() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(reply["target_fronted"], true, "{reply}");
    assert_eq!(
        reply["fronting"],
        json!({"mode":"background","fronted":true,"purpose":"needs_front",
            "restore":"restored"})
    );
    assert_eq!(rig.screen.log(), ["front:4242", "post", "restore:100"]);
    assert!(
        !rig.lock.held(),
        "released when the restore decision completed"
    );
}

/// A chord whose post failed with a key possibly held: the previous
/// application comes back only after the paired release is confirmed, and
/// never when it is not, which replies `restore_failed`.
#[tokio::test]
async fn a_chord_that_may_hold_a_key_restores_only_after_the_release_is_confirmed() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    rig.screen.state().post_unknown = true;
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "post", "release", "restore:100"],
        "{reply}"
    );
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    assert!(!rig.lock.held());

    let rig = self::rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    {
        let mut state = rig.screen.state();
        state.post_unknown = true;
        state.release_ok = false;
    }
    let terminal = under_terminal();
    let reply = rig
        .call_under(&terminal, "computer.keys", command_chord())
        .await;
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "post", "release"],
        "no restore is requested while the key may be held: {reply}"
    );
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "failed");
    assert!(
        rig.lock.held(),
        "the obligation keeps the lock until terminal cleanup takes it"
    );
}

/// Background mode: a press on a button the application disables while it
/// is in the background fronts it, waits for the button to read enabled,
/// presses, and restores.
#[tokio::test]
async fn a_press_on_a_button_disabled_in_the_background_fronts_presses_and_restores() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"],
        json!({"mode":"background","fronted":true,"purpose":"needs_front",
            "restore":"restored"})
    );
    assert_eq!(rig.desk.state().presses, [10]);
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
    assert!(!rig.lock.held());
}

/// Still disabled once the enabled poll ends: refused `element_disabled`,
/// nothing pressed, and the previous application restored.
#[tokio::test]
async fn a_press_still_disabled_in_front_refuses_and_restores() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "element_disabled", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    assert!(rig.desk.state().presses.is_empty());
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
}

/// A third application is left alone even without key/button/scroll evidence:
/// a virtual-desktop gesture can make the same switch without such an event.
/// Observed person input is still disclosed only when it was actually seen.
#[tokio::test]
async fn a_third_app_switch_is_left_alone_with_or_without_hardware_evidence() {
    for input in [true, false] {
        let rig = rig(AppUse::Background, mail_desk()).await;
        let send = rig.send_id().await;
        rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
        rig.screen.state().enable_on_front = vec![10];
        let (desk, screen) = (rig.desk.clone(), rig.screen.clone());
        rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
            desk.state().frontmost = Some(THIRD);
            if input {
                let mut state = screen.state();
                state.last_input_ms = Some(state.now + 1);
                state.now += 2;
            }
        })));
        let reply = rig
            .call_under(
                &under_terminal(),
                "computer.press_element",
                json!({"element_id": send}),
            )
            .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert_eq!(reply["fronting"]["restore"], "skipped_person", "{reply}");
        assert_eq!(rig.screen.log(), ["front:4242"], "no restore request");
        if input {
            assert_eq!(reply["fronting"]["person_input_during_fronting"], true);
        } else {
            assert!(reply["fronting"]
                .get("person_input_during_fronting")
                .is_none());
        }
    }
}

/// Hooks whose obligation terminal cleanup takes the moment it is
/// registered, before the front request: what a cancel that lands between
/// the two does.
struct CleanupFirst(CellHooks);

impl FrontedDispatchHooks for CleanupFirst {
    fn register(&mut self, previous: u32, target: u32, host: Box<dyn FrontingRestoreHost>) -> bool {
        let registered = self.0.register(previous, target, host);
        if let Some(cell) = self.0.cell() {
            let decided = std::thread::scope(|scope| scope.spawn(|| cell.decide()).join().unwrap());
            assert_eq!(decided.restore, RestoreStatus::NotNeeded);
        }
        registered
    }
    fn begin_front_attempt(&mut self, front_instant_ms: u64) -> bool {
        self.0.begin_front_attempt(front_instant_ms)
    }
    fn front_attempt_returned(&mut self) {
        self.0.front_attempt_returned();
    }
    fn decide_restore(&mut self) -> cerebellum_computer::platform::HookedRestore {
        self.0.decide_restore()
    }
    fn finished(&mut self, outcome: &cerebellum_computer::dispatch::BracketOutcome) {
        self.0.finished(outcome);
    }
}

/// Stands in for the fronting lock's guard, counting its releases.
struct CountedLock(Arc<std::sync::atomic::AtomicUsize>);

impl Drop for CountedLock {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Cleanup that takes the obligation after it is registered and before the
/// front leaves the worker unfronted: no front request ever follows, the
/// restore is `not_needed`, and the lock is released once.
#[test]
fn cleanup_before_the_front_leaves_the_worker_unfronted() {
    let screen = Screen::new(&mail_desk());
    let releases = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let hooks = CellHooks::new(ObligationParts {
        terminal: under_terminal(),
        lock: Some(Box::new(CountedLock(Arc::clone(&releases)))),
        target_name: "Mail".into(),
        mode: crate::terminal_arbiter::FrontingMode::Background,
        purpose: crate::terminal_arbiter::FrontingPurpose::NeedsFront,
    });
    let mut cleanup_first = CleanupFirst(hooks.clone());
    let outcome = cerebellum_computer::platform::run_hooked_fronted(
        &mut FakeBracket(screen.clone()),
        &mut UserIdleEstimator::new(),
        cerebellum_computer::dispatch::BracketPlan {
            target_pid: TARGET,
            units: 1,
            maximum_interval_ms: 100,
            maximum_seize_detection_latency_ms: 50,
        },
        &|| false,
        &mut cleanup_first,
        None,
    );
    assert!(screen.log().is_empty(), "{:?}", screen.log());
    assert_eq!(outcome.report.restore, RestoreStatus::NotNeeded);
    assert_eq!(outcome.report.units_posted, 0);
    let end = hooks.end();
    assert_eq!(
        hooked_fronting(AppUse::Background, Purpose::NeedsFront, &end).not_fronted_reason,
        Some(NotFrontedReason::Cancelled)
    );
    assert_eq!(
        releases.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "the lock was released once"
    );
}

// ---------------------------------------------------------------------------
// Through the call's route: terminal cleanup and the worker share one
// restore obligation.
// ---------------------------------------------------------------------------

fn route_request() -> subc_protocol::Frame {
    subc_protocol::Frame::build_with_version(
        crate::PROTOCOL_VERSION,
        subc_protocol::FrameType::Request,
        crate::wire::control_flags(),
        1,
        1,
        1,
        serde_json::to_vec(&json!({
            "method": crate::management::OPEN_TARGET,
            "params": {"bundle_identity": "com.example.Nothing"},
        }))
        .unwrap(),
    )
    .unwrap()
}

fn route_cancel() -> subc_protocol::Frame {
    subc_protocol::Frame::build_with_version(
        crate::PROTOCOL_VERSION,
        subc_protocol::FrameType::Cancel,
        crate::wire::control_flags(),
        1,
        1,
        1,
        Vec::new(),
    )
    .unwrap()
}

/// One call served on a real route, through `run_arbitrated_route`.
struct Routed {
    /// The body of the one reply the route sent.
    reply: Value,
    /// Told once the worker's own call has returned, however late.
    worker_done: Arc<tokio::sync::Notify>,
    /// The route's outgoing frames after that reply.
    rx: tokio::sync::mpsc::Receiver<subc_protocol::Frame>,
}

/// Serve `name` on a route as the call's worker. `prepare` runs first, in
/// the worker, with the call's terminal arbiter. When `cancel_at` is given,
/// the route is cancelled after that notification fires.
async fn routed(
    rig: &Rig,
    name: &'static str,
    arguments: Value,
    prepare: impl FnOnce(&Rig, Arc<crate::TerminalArbiter>) + Send + 'static,
    cancel_at: Option<Arc<tokio::sync::Notify>>,
) -> Routed {
    let mut planes = crate::tests::management_bound_planes(1, 1);
    let worker_done = Arc::new(tokio::sync::Notify::new());
    let input = StdMutex::new(Some((
        rig.clone(),
        prepare,
        Arc::clone(&worker_done),
        arguments,
    )));
    planes.route_test_handler = Some(Arc::new(move || {
        let (rig, prepare, done, arguments) = input.lock().unwrap().take().unwrap();
        Box::pin(async move {
            prepare(&rig, crate::TerminalArbiter::current().unwrap());
            let _ = rig.call(name, arguments).await;
            done.notify_one();
            std::future::pending::<()>().await;
        })
    }));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(route_request(), &tx, &planes)
        .await
        .unwrap();
    if let Some(stage) = cancel_at {
        tokio::time::timeout(crate::test_support::HANG_GUARD, stage.notified())
            .await
            .expect("the worker never reached the moment to cancel at");
        crate::handle_frame(route_cancel(), &tx, &planes)
            .await
            .unwrap();
    }
    let reply = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
        .await
        .expect("the route never replied")
        .unwrap();
    Routed {
        reply: serde_json::from_slice(&reply.body).unwrap(),
        worker_done,
        rx,
    }
}

impl Routed {
    /// Wait for the worker's own call to return, then check the route sent
    /// nothing after its one reply.
    async fn worker_finished_silently(&mut self) {
        tokio::time::timeout(crate::test_support::HANG_GUARD, self.worker_done.notified())
            .await
            .expect("the worker never returned");
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            self.rx.try_recv().is_err(),
            "the route sent a frame after its one reply"
        );
    }
}

/// Serve a Command chord on a route whose post stays in flight with its
/// keys down, cancel the route once the post has begun, and return the
/// wire reply's body.
async fn chord_cancelled_mid_post(rig: &Rig) -> Value {
    rig.read().await;
    let posting = Arc::new(tokio::sync::Notify::new());
    rig.screen.state().posting = Some(Arc::clone(&posting));
    routed(
        rig,
        "computer.keys",
        command_chord(),
        |rig, terminal| rig.screen.state().hold_until_stopped = Some(terminal),
        Some(posting),
    )
    .await
    .reply
}

/// A cancel while a chord holds Command in front of a background
/// application: the key is released first, then the previous application is
/// restored, once, and the reply reports both.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_cancel_a_held_command_is_released_before_the_restore() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let reply = chord_cancelled_mid_post(&rig).await;
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "post", "release", "restore:100"],
        "{reply}"
    );
    assert_eq!(reply["outcome"], "dispatch_outcome_unknown", "{reply}");
    assert_eq!(reply["detail"]["held_state"], "released");
    assert_eq!(reply["fronting"]["restore"], "restored");
    assert!(!rig.lock.held());
}

/// The same cancel when the release never returns: no restore request at
/// all, and the reply is `restore_failed`, naming the application left in
/// front.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn under_cancel_an_unconfirmed_release_requests_no_restore() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.screen.state().release_ok = false;
    let reply = chord_cancelled_mid_post(&rig).await;
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "post", "release"],
        "{reply}"
    );
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(reply["detail"]["held_state"], "unknown");
    assert_eq!(reply["fronting"]["restore"], "failed");
    assert!(reply["remedy"]
        .as_str()
        .unwrap()
        .contains("was left in front"));
    assert!(!rig.lock.held(), "terminal cleanup released the lock");
}

/// This module's own front is written into what the agent was shown at the
/// moment it is seen. Input the person made in another application before
/// the front then does not refuse a later action on the target, even when
/// the action that fronted it was refused before it could record anything.
#[tokio::test]
async fn input_before_a_foreground_front_does_not_refuse_the_next_action() {
    let rig = rig(AppUse::Background, support::focused_text_desk()).await;
    rig.read().await;
    assert!(rig.screen.log().is_empty());
    rig.desk.state().input.push((0, std::time::Instant::now()));
    let rig = rig.with_mode(AppUse::Foreground);
    let typing = json!({"target": support::TARGET_BUNDLE_ID, "text": "hi"});

    rig.desk.state().elements.get_mut(&2).unwrap().facts.subrole = Some("AXSecureTextField".into());
    let reply = rig.call("computer.type", typing.clone()).await;
    assert_eq!(reply["outcome"], "secure_field_refused", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242"]);

    rig.desk.state().elements.get_mut(&2).unwrap().facts.subrole = None;
    let reply = rig.call("computer.type", typing).await;
    assert_ne!(reply["outcome"], "state_changed_by_person", "{reply}");
    assert_eq!(reply["fronting"]["purpose"], "foreground_mode", "{reply}");
}

/// Guard (1): a change the person made to the target since the last read
/// leaves a foreground read unfronted, saying so; that read records what it
/// showed, so the next read fronts.
#[tokio::test]
async fn a_changed_target_falls_back_once_and_the_next_read_fronts() {
    let rig = rig(AppUse::Background, support::focused_text_desk()).await;
    rig.read().await;
    rig.desk.state().focus = support::DeskFocus::Nothing;
    let rig = rig.with_mode(AppUse::Foreground);
    let reply = rig.read().await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"],
        "person_changed_target"
    );
    assert!(rig.screen.log().is_empty());
    let reply = rig.read().await;
    assert_eq!(reply["fronting"]["fronted"], true, "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242"]);
}

/// A foreground action other than a read does not go ahead unfronted when
/// its front stopped: it refuses `not_fronted` with the reason, having done
/// nothing.
#[tokio::test]
async fn a_foreground_press_whose_front_stopped_refuses_not_fronted() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    let rig = rig.with_mode(AppUse::Foreground);
    rig.screen.state().idle_ms = 200;
    let reply = rig
        .call("computer.press_element", json!({"element_id": send}))
        .await;
    assert_eq!(reply["outcome"], "not_fronted", "{reply}");
    assert_eq!(reply["fronting"]["not_fronted_reason"], "person_active");
    assert!(rig.desk.state().presses.is_empty());
    assert!(rig.screen.log().is_empty());
}

// ---------------------------------------------------------------------------
// open_app
// ---------------------------------------------------------------------------

/// A desk on which Safari is installed and opening it reports `opened`.
fn installed_desk(already_running: bool) -> support::Desk {
    let desk = mail_desk();
    {
        let mut state = desk.state();
        state.installed.apps = vec![cerebellum_computer::app_state::source::InstalledApp {
            name: "Safari".into(),
            bundle_identity: support::TARGET_BUNDLE_ID.into(),
            path: PathBuf::from("/Applications/Safari.app"),
        }];
        state.opened.already_running = already_running;
        state.opened.has_window = true;
    }
    desk
}

/// Foreground mode: `open_app` brings a running application to the front
/// one way, and a launched one once it reports its window, through the same
/// front every action uses. The launch itself never activates. Background
/// mode fronts neither.
#[tokio::test]
async fn open_app_fronts_a_running_or_launched_app_only_in_foreground_mode() {
    for (mode, already_running) in [
        (AppUse::Foreground, true),
        (AppUse::Foreground, false),
        (AppUse::Background, true),
        (AppUse::Background, false),
    ] {
        let management = apps_management();
        Who::fixture()
            .grant(&management, support::TARGET_BUNDLE_ID)
            .await;
        let rig = rig_with(mode, installed_desk(already_running), management);
        let reply = rig
            .call("computer.open_app", json!({"target": "Safari"}))
            .await;
        let case = format!("{mode:?} already_running={already_running}: {reply}");
        let outcome = if already_running {
            "already_running"
        } else {
            "launched"
        };
        assert_eq!(reply["outcome"], outcome, "{case}");
        assert!(
            !rig.desk.state().opens[0].activates,
            "the launch never activates: {case}"
        );
        match mode {
            AppUse::Foreground => {
                assert_eq!(
                    reply["fronting"],
                    json!({"mode":"foreground","fronted":true,"purpose":"foreground_mode",
                        "restore":"left_in_front"}),
                    "{case}"
                );
                assert_eq!(rig.screen.log(), ["front:4242"], "{case}");
            }
            AppUse::Background => {
                assert!(reply.get("fronting").is_none(), "{case}");
                assert!(rig.screen.log().is_empty(), "{case}");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// bring_to_front under takeover, through the call's restore obligation
// ---------------------------------------------------------------------------

/// Background mode: a `bring_to_front` image read under held takeover fronts
/// the application, reads it while in front, and puts the previous
/// application back through the call's one restore decision.
#[tokio::test]
async fn a_bring_to_front_read_fronts_reads_and_restores_once() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let carrier = support::ScriptedCarrier::answering(&["computer_30m"]);
    rig.management
        .computer_grants()
        .require(
            &crate::computer_grants::GrantNeed::Takeover,
            &support::relayed(&carrier),
            &crate::CancelHandle::pending(),
        )
        .await
        .unwrap();
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.read_state",
            json!({"target": support::TARGET_BUNDLE_ID, "include_image": true,
                "bring_to_front": true}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "read", "restore:100"],
        "{reply}"
    );
    assert_eq!(
        reply["fronting"],
        json!({"mode":"background","fronted":true,"purpose":"bring_to_front",
            "restore":"restored"}),
        "{reply}"
    );
    assert!(!rig.lock.held());
}

// ---------------------------------------------------------------------------
// Held input blocks every front, across conversations and applications
// ---------------------------------------------------------------------------

/// A press another conversation posted to another application, whose
/// release never returned, still keeps this conversation's foreground front
/// of its own application from happening: a key held anywhere would land on
/// whatever application comes to the front.
#[tokio::test]
async fn a_press_left_held_by_another_conversation_on_another_app_blocks_every_front() {
    let management = apps_management();
    let (a, b) = (Who::fixture(), Who::conversation("conversation-b"));
    a.grant(&management, support::TARGET_BUNDLE_ID).await;
    b.grant(&management, &other_app().bundle_identity).await;
    let rig = rig_with(AppUse::Background, support::focused_text_desk(), management);

    // Conversation A reads its application, then sends a chord to it: the
    // post fails with the keys possibly down, and the paired release never
    // returns.
    rig.read().await;
    {
        let mut state = rig.screen.state();
        state.post_unknown = true;
        state.release_ok = false;
    }
    let held = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(held["outcome"], "restore_failed", "{held}");
    assert!(!held_input_confirmed(&rig.plane.held_input));
    rig.screen.state().log.clear();
    rig.desk.state().frontmost = Some(PREVIOUS);

    // Conversation B, in foreground mode, reads its application Y.
    let rig = rig.with_mode(AppUse::Foreground);
    let reply = rig
        .serve_as(
            &b,
            "computer.read_state",
            json!({"target": other_app().bundle_identity}),
            crate::CancelHandle::pending(),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["fronting"]["not_fronted_reason"], "held_input_unconfirmed",
        "{reply}"
    );
    assert!(
        rig.screen.log().is_empty(),
        "no front was requested: {:?}",
        rig.screen.log()
    );
}

// ---------------------------------------------------------------------------
// Lost authorization while a front waits for the lock
// ---------------------------------------------------------------------------

/// A foreground read waiting for the fronting lock when its authorization
/// ends reads nothing, captures nothing and records no seen marks. Revoking
/// the app grant cancels the call where it waits; a dispatch gate closed
/// with no cancel at all (here, the call's deadline) is caught the moment the
/// lock is taken.
#[tokio::test(start_paused = true)]
async fn lost_authorization_while_waiting_for_the_lock_reads_nothing() {
    let read = json!({"target": support::TARGET_BUNDLE_ID, "include_image": true});
    for revoke in [true, false] {
        // A background read first gives the target a seen mark, so the
        // assertions below can show it was neither read again nor replaced.
        let rig = rig(AppUse::Background, mail_desk()).await;
        rig.read().await;
        let marks_at = rig
            .management
            .app_state_sessions()
            .last_seen(&support::identity().conversation_key, &support::grant())
            .unwrap()
            .at;
        let rig = rig.with_mode(AppUse::Foreground);
        let reads = rig.desk.state().focus_reads;
        let held = rig
            .lock
            .take(&crate::CancelHandle::pending())
            .await
            .unwrap();
        let terminal = under_terminal();
        let call = {
            let (rig, terminal, read) = (rig.clone(), Arc::clone(&terminal), read.clone());
            tokio::spawn(
                async move { rig.call_under(&terminal, "computer.read_state", read).await },
            )
        };
        tokio::time::sleep(Duration::from_millis(200)).await;
        if revoke {
            // Revoking the app grant cancels the call where it waits.
            let store = rig.management.computer_grants().agent_grants();
            let revoked = store.revoke_matching(store.now_ms(), |_| true).unwrap();
            assert!(!revoked.is_empty(), "the app grant was revoked");
        } else {
            // The dispatch gate closes with no cancel at all, as when the
            // call's deadline passes. It is caught the moment the lock is
            // taken.
            terminal.stop(crate::TerminalCause::Deadline);
        }
        drop(held);
        let reply = call.await.unwrap();
        let case = format!("revoke={revoke}: {reply}");
        assert_ne!(reply["outcome"], "completed", "{case}");
        assert_eq!(
            reply["fronting"]["not_fronted_reason"], "cancelled",
            "{case}"
        );
        assert!(
            reply.get("image").is_none() && reply.get("image_unavailable").is_none(),
            "no capture: {case}"
        );
        assert_eq!(
            rig.desk.state().focus_reads,
            reads,
            "no accessibility read: {case}"
        );
        assert_eq!(
            rig.management
                .app_state_sessions()
                .last_seen(&support::identity().conversation_key, &support::grant())
                .unwrap()
                .at,
            marks_at,
            "no seen-mark update: {case}"
        );
        assert!(rig.screen.log().is_empty(), "{case}");
    }
}

// ---------------------------------------------------------------------------
// Terminal cleanup and the worker, through the route
// ---------------------------------------------------------------------------

/// The work deadline passes while the worker is releasing a chord's held
/// key. The release comes first; a confirmed release is then followed by
/// exactly one restore, and one that does not confirm within the shared
/// release budget gives `restore_failed` with no restore request at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_deadline_passing_during_the_release_restores_only_after_it() {
    for confirmed in [true, false] {
        let rig = rig(AppUse::Background, mail_desk()).await;
        rig.read().await;
        let finish_release = Arc::new(std::sync::atomic::AtomicBool::new(confirmed));
        {
            let mut state = rig.screen.state();
            state.post_unknown = true;
            state.release_ok = confirmed;
            state.release_until = Some(Arc::clone(&finish_release));
        }
        let mut routed = routed(
            &rig,
            "computer.keys",
            command_chord(),
            |rig, terminal| {
                rig.screen.state().release_ends_call =
                    Some((terminal, crate::TerminalCause::Deadline));
            },
            None,
        )
        .await;
        finish_release.store(true, std::sync::atomic::Ordering::SeqCst);
        routed.worker_finished_silently().await;
        let reply = &routed.reply;
        if confirmed {
            assert_eq!(
                rig.screen.log(),
                ["front:4242", "post", "release", "restore:100"],
                "{reply}"
            );
            assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
            assert_eq!(reply["detail"]["held_state"], "released", "{reply}");
        } else {
            assert_eq!(
                rig.screen.log(),
                ["front:4242", "post", "release"],
                "{reply}"
            );
            assert_eq!(reply["outcome"], "restore_failed", "{reply}");
            assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
        }
        assert!(!rig.lock.held());
    }
}

/// A cancel arriving while the worker settles the held key races its normal
/// end: the restore waits for the settled release, exactly one restore
/// request is made, and the worker finishing afterwards adds none.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_racing_the_settle_makes_one_restore_after_the_release() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    let releasing = Arc::new(tokio::sync::Notify::new());
    {
        let mut state = rig.screen.state();
        state.post_unknown = true;
        state.releasing = Some(Arc::clone(&releasing));
        state.log_release_end = true;
    }
    let mut routed = routed(
        &rig,
        "computer.keys",
        command_chord(),
        |rig, terminal| rig.screen.state().release_until_stopped = Some(terminal),
        Some(releasing),
    )
    .await;
    routed.worker_finished_silently().await;
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "post", "release", "released", "restore:100"],
        "{}",
        routed.reply
    );
    assert_eq!(routed.reply["outcome"], "dispatch_outcome_unknown");
    assert_eq!(routed.reply["detail"]["held_state"], "released");
    assert_eq!(routed.reply["fronting"]["restore"], "restored");
    assert!(!rig.lock.held());
}

/// A needs-front press whose worker is blocked inside the press when the
/// call is cancelled. `switch` makes the person switch to a third
/// application first, with hardware input when `input` is set.
async fn press_cancelled_while_blocked(switch: bool, input: bool) -> (Rig, Routed) {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let pressing = Arc::new(tokio::sync::Notify::new());
    let terminal_slot: Arc<StdMutex<Option<Arc<crate::TerminalArbiter>>>> = Arc::default();
    {
        let (desk, screen, pressing, slot) = (
            rig.desk.clone(),
            rig.screen.clone(),
            Arc::clone(&pressing),
            Arc::clone(&terminal_slot),
        );
        rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
            if switch {
                desk.state().frontmost = Some(THIRD);
            }
            if input {
                let mut state = screen.state();
                state.last_input_ms = Some(state.now + 1);
                state.now += 2;
            }
            pressing.notify_one();
            let terminal = slot.lock().unwrap().clone().unwrap();
            let give_up = std::time::Instant::now() + crate::test_support::HANG_GUARD;
            while !terminal.gate.stopped() && std::time::Instant::now() < give_up {
                std::thread::yield_now();
            }
        })));
    }
    let routed = routed(
        &rig,
        "computer.press_element",
        json!({"element_id": send}),
        move |_, terminal| *terminal_slot.lock().unwrap() = Some(terminal),
        Some(pressing),
    )
    .await;
    (rig, routed)
}

/// A cancel while the worker is blocked in the press of a needs-front press:
/// terminal cleanup makes the one restore request. When the press returns
/// later, the worker neither fronts again nor restores again, and the route
/// sends nothing after its one reply. (The worker here returns its reply to
/// the test harness rather than to the route, so this checks the route's
/// side only.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_cancel_while_blocked_in_the_press_restores_once() {
    let (rig, mut routed) = press_cancelled_while_blocked(false, false).await;
    assert_eq!(
        routed.reply["fronting"]["restore"], "restored",
        "{}",
        routed.reply
    );
    routed.worker_finished_silently().await;
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
    assert_eq!(rig.desk.state().presses, [10]);
    assert!(!rig.lock.held());
}

/// The person switched to a third application with hardware input while the
/// target was in front, and the call is then cancelled: terminal cleanup's
/// decision reads the restore host's input snapshot and leaves them there.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_person_switch_with_input_under_cancel_is_skipped_by_cleanup() {
    let (rig, mut routed) = press_cancelled_while_blocked(true, true).await;
    assert_eq!(
        routed.reply["fronting"]["restore"], "skipped_person",
        "{}",
        routed.reply
    );
    assert_eq!(
        routed.reply["fronting"]["person_input_during_fronting"],
        true
    );
    routed.worker_finished_silently().await;
    assert_eq!(rig.screen.log(), ["front:4242"], "no restore request");
}

// ---------------------------------------------------------------------------
// Batches, the press's own fronting outcomes, and the journal's records
// ---------------------------------------------------------------------------

/// A window with a Send and an Archive button, both of which the
/// application disables while it is in the background.
fn two_button_desk() -> support::Desk {
    support::Desk::new(vec![RawElement::fixture(1, "AXWindow")
        .titled("Mail")
        .with_children(vec![
            RawElement::fixture(10, "AXButton").titled("Send"),
            RawElement::fixture(11, "AXButton").titled("Archive"),
        ])])
    .with_element(
        10,
        support::DeskElement {
            facts: ElementFacts {
                title: Some("Send".into()),
                ..support::facts("AXButton", &["AXPress"])
            },
            ..support::DeskElement::default()
        },
    )
    .with_element(
        11,
        support::DeskElement {
            facts: ElementFacts {
                title: Some("Archive".into()),
                ..support::facts("AXButton", &["AXPress"])
            },
            ..support::DeskElement::default()
        },
    )
}

/// The ids of the Send and Archive buttons, from a background read, with
/// both buttons then reading disabled until the target is fronted.
async fn two_disabled_buttons(rig: &Rig) -> (String, String) {
    let reply = rig.read().await;
    let tree = reply["state_text"].as_str().unwrap();
    let id_of = |label: &str| {
        tree.lines()
            .find(|line| line.contains(label))
            .unwrap_or_else(|| panic!("no {label} in {tree}"))
            .split_whitespace()
            .next()
            .unwrap()
            .to_owned()
    };
    let ids = (id_of("Send"), id_of("Archive"));
    for token in [10, 11] {
        rig.desk.state().elements.get_mut(&token).unwrap().enabled = Some(false);
    }
    rig.screen.state().enable_on_front = vec![10, 11];
    ids
}

/// The open results of the journal's finalized and rejected rows, in order.
/// Every entry is decoded with the codec's own entry decoder.
fn journal_results(rig: &Rig) -> Vec<Value> {
    let bytes = cerebellum_computer::audit::lock_audit(&rig.plane.audit)
        .journal()
        .export_bytes();
    let mut results = Vec::new();
    for entry in serde_json::Deserializer::from_slice(&bytes).into_iter::<Value>() {
        let entry = entry.expect("each entry is a JSON object");
        let entry = cerebellum_computer::audit::ComputerJournalCodec::decode_entry(
            entry.to_string().as_bytes(),
        )
        .expect("the codec decodes every entry");
        let Some(material) = entry
            .get("completed_result")
            .or_else(|| entry.get("rejection_material"))
        else {
            continue;
        };
        let material: Vec<u8> = serde_json::from_value(material.clone()).unwrap();
        results.push(serde_json::from_slice(&material).expect("an open JSON result"));
    }
    results
}

/// The `fronting` member of a row, decoded with the journal's record type.
fn row_fronting(row: &Value) -> cerebellum_computer::audit::FrontingRecord {
    serde_json::from_value(row["fronting"].clone())
        .unwrap_or_else(|error| panic!("no fronting record in {row}: {error}"))
}

/// A batch of two presses on buttons the application disables in the
/// background brings it forward once, presses both with it in front, and
/// makes one restore decision after the last press.
#[tokio::test]
async fn a_batch_fronts_once_and_restores_once_after_its_last_press() {
    let rig = rig(AppUse::Background, two_button_desk()).await;
    let (send, archive) = two_disabled_buttons(&rig).await;
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_ids": [send, archive]}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(reply.get("stopped_at").is_none(), "{reply}");
    assert_eq!(
        reply["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["outcome"].clone())
            .collect::<Vec<_>>(),
        [json!("completed"), json!("completed")]
    );
    assert_eq!(
        reply["fronting"],
        json!({"mode":"background","fronted":true,"purpose":"needs_front",
            "restore":"restored"})
    );
    assert_eq!(rig.desk.state().presses, [10, 11]);
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "restore:100"],
        "one front and one restore for the whole batch"
    );
    assert!(!rig.lock.held());
}

/// A later step whose admission would have to ask the person, because the
/// app grant is no longer held, stops the batch there with `stopped_at`
/// instead of waiting with the application in front; the restore decision
/// still runs.
#[tokio::test]
async fn a_batch_step_that_would_wait_stops_the_run_and_still_restores() {
    let rig = rig(AppUse::Background, two_button_desk()).await;
    let (send, archive) = two_disabled_buttons(&rig).await;
    let management = rig.management.clone();
    rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
        let store = management.computer_grants().agent_grants();
        let _ = store.revoke_matching(store.now_ms(), |_| true);
    })));
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_ids": [send, archive]}),
        )
        .await;
    assert_eq!(reply["stopped_at"], 2, "{reply}");
    assert_eq!(reply["steps"][0]["outcome"], "completed", "{reply}");
    assert_eq!(
        reply["steps"][1]["outcome"], "consent_unavailable",
        "{reply}"
    );
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    assert_eq!(
        rig.desk.state().presses,
        [10],
        "the later step was not pressed"
    );
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
    assert!(!rig.lock.held());
}

/// A press on an element that reads disabled while its application is
/// already frontmost takes the ordinary path: it refuses at once, never
/// waiting on a fronting lock another call holds, and fronts nothing.
#[tokio::test(start_paused = true)]
async fn a_disabled_press_on_a_frontmost_app_never_waits_on_the_lock() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.desk.state().frontmost = Some(TARGET);
    let held = rig
        .lock
        .take(&crate::CancelHandle::pending())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "element_disabled", "{reply}");
    assert!(started.elapsed() < Duration::from_millis(100));
    assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    drop(held);
}

/// The previous application could not be put back after a fronted press:
/// the reply is `restore_failed` with a remedy naming the target left in
/// front and its bundle identity, and none of the keystroke rows' restore
/// fields.
#[tokio::test]
async fn a_failed_press_restore_discloses_only_the_press_fields() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let screen = rig.screen.clone();
    rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
        // The previous application will not come back.
        screen.state().comes_forward = false;
    })));
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "restore_failed", "{reply}");
    assert_eq!(
        reply["bundle_identity"],
        support::TARGET_BUNDLE_ID,
        "{reply}"
    );
    assert!(
        reply["remedy"]
            .as_str()
            .unwrap()
            .contains("was left in front"),
        "{reply}"
    );
    assert_eq!(reply["fronting"]["restore"], "failed", "{reply}");
    for field in [
        "detail",
        "effect_status",
        "posts_returned",
        "target_fronted",
        "held_state",
    ] {
        assert!(reply.get(field).is_none(), "{field} in {reply}");
    }
    assert_eq!(rig.desk.state().presses, [10]);
}

/// A fronted press that took effect after its front outlasted the bound is
/// returned as completed, saying so, rather than refused.
#[tokio::test]
async fn a_press_that_took_effect_past_the_bound_says_so() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let screen = rig.screen.clone();
    rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
        screen.state().now += 2 * cerebellum_computer::dispatch::PRESS_FRONTING_BOUND_MS;
    })));
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting_bound_exceeded"], true, "{reply}");
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");

    // Within the bound, the reply does not carry the field at all.
    let rig = rig_again(AppUse::Background).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(reply.get("fronting_bound_exceeded").is_none(), "{reply}");
}

async fn rig_again(mode: AppUse) -> Rig {
    rig(mode, mail_desk()).await
}

/// The rows of a fronted press record how its front ended: the press's
/// finalized row, and a refusal's rejected row, each carry the fronting the
/// reply reports, and a still-disabled element is refused once.
#[tokio::test]
async fn fronted_press_rows_record_how_the_front_ended() {
    use cerebellum_computer::audit::{
        FrontingRecordMode, FrontingRecordPurpose, FrontingRecordRestore,
    };
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    let rows = journal_results(&rig);
    let pressed: Vec<_> = rows
        .iter()
        .filter(|row| row["outcome"] == "completed")
        .collect();
    assert_eq!(pressed.len(), 1, "{rows:?}");
    let record = row_fronting(pressed[0]);
    assert_eq!(record.mode, FrontingRecordMode::Background);
    assert!(record.fronted);
    assert_eq!(record.purpose, FrontingRecordPurpose::NeedsFront);
    assert_eq!(record.restore, FrontingRecordRestore::Restored);
    assert_eq!(record.preview_frames, 0);

    // Still disabled in front: one refusal, written after the restore.
    let rig = rig_again(AppUse::Background).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "element_disabled", "{reply}");
    let rows = journal_results(&rig);
    let refused: Vec<_> = rows
        .iter()
        .filter(|row| row["outcome"] == "element_disabled")
        .collect();
    assert_eq!(refused.len(), 1, "one refusal, not two: {rows:?}");
    let record = row_fronting(refused[0]);
    assert!(record.fronted);
    assert_eq!(record.restore, FrontingRecordRestore::Restored);
}

/// A foreground read's row records its one-way front under `fronting`, and
/// an ordinary background press, which had no reason to front, writes its
/// row exactly as before, with no `fronting` member.
#[tokio::test]
async fn read_and_ordinary_press_rows_record_their_fronting() {
    use cerebellum_computer::audit::{FrontingRecordPurpose, FrontingRecordRestore};
    let rig = rig(AppUse::Foreground, mail_desk()).await;
    let reply = rig.read().await;
    assert_eq!(reply["fronting"]["fronted"], true, "{reply}");
    let rows = journal_results(&rig);
    let read = rows
        .iter()
        .find(|row| row.get("element_count").is_some())
        .unwrap_or_else(|| panic!("no read row in {rows:?}"));
    let record = row_fronting(read);
    assert!(record.fronted);
    assert_eq!(record.purpose, FrontingRecordPurpose::ForegroundMode);
    assert_eq!(record.restore, FrontingRecordRestore::LeftInFront);
    assert!(
        rows.iter().all(|row| row["outcome"] != "fronted"),
        "the read's own row records the front: {rows:?}"
    );

    let rig = rig_again(AppUse::Background).await;
    let send = rig.send_id().await;
    let reply = rig
        .call("computer.press_element", json!({"element_id": send}))
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    let rows = journal_results(&rig);
    let pressed = rows
        .iter()
        .find(|row| row["outcome"] == "completed")
        .unwrap_or_else(|| panic!("no press row in {rows:?}"));
    assert!(pressed.get("fronting").is_none(), "{pressed}");
    assert!(
        rows.iter().all(|row| row.get("fronting").is_none()),
        "{rows:?}"
    );
}

/// In foreground mode even a reply that ended before any front was tried
/// says how the action used the front; the same reply in background mode,
/// where nothing had a reason to front, carries no `fronting` at all.
#[tokio::test]
async fn only_foreground_mode_adds_fronting_to_a_reply_that_never_fronted() {
    for mode in [AppUse::Foreground, AppUse::Background] {
        let rig = rig(mode, mail_desk()).await;
        let reply = rig
            .call("computer.press_element", json!({"element_id": "e999"}))
            .await;
        assert_ne!(reply["outcome"], "completed", "{mode:?}: {reply}");
        match mode {
            AppUse::Foreground => assert_eq!(
                reply["fronting"],
                json!({"mode":"foreground","fronted":false,"purpose":"foreground_mode",
                    "restore":"not_needed"}),
                "{reply}"
            ),
            AppUse::Background => {
                assert!(reply.get("fronting").is_none(), "{reply}");
            }
        }
        assert!(rig.screen.log().is_empty(), "{:?}", rig.screen.log());
    }
}

/// A foreground press fronts and then presses: its own row records the
/// one-way front, and no separate `fronted` row is written for it.
#[tokio::test]
async fn a_foreground_press_records_its_front_on_its_own_row() {
    use cerebellum_computer::audit::FrontingRecordRestore;
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    let rig = rig.with_mode(AppUse::Foreground);
    let reply = rig
        .call("computer.press_element", json!({"element_id": send}))
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "left_in_front", "{reply}");
    let rows = journal_results(&rig);
    assert!(
        rows.iter().all(|row| row["outcome"] != "fronted"),
        "{rows:?}"
    );
    let pressed = rows
        .iter()
        .find(|row| row["outcome"] == "completed")
        .unwrap_or_else(|| panic!("no press row in {rows:?}"));
    assert_eq!(
        row_fronting(pressed).restore,
        FrontingRecordRestore::LeftInFront
    );
}

/// A foreground front followed by a refusal before the action wrote any row
/// of its own: the front is journaled on its own rejected row, with outcome
/// `fronted`, once.
#[tokio::test]
async fn a_front_then_an_early_refusal_writes_its_own_fronted_row() {
    use cerebellum_computer::audit::FrontingRecordRestore;
    // Read in background mode, which fronts nothing, so the keystrokes have
    // something the conversation was shown to check the person against.
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    let rig = rig.with_mode(AppUse::Foreground);
    // The keystrokes are refused once the front is done, when the focused
    // element they would go to cannot be read.
    rig.desk.state().focus = support::DeskFocus::Unreadable;
    let before = journal_results(&rig).len();
    let reply = rig
        .call(
            "computer.type",
            json!({"text": "hi", "target": support::TARGET_BUNDLE_ID}),
        )
        .await;
    assert_eq!(reply["fronting"]["fronted"], true, "{reply}");
    assert_ne!(reply["outcome"], "delivery_unconfirmed", "{reply}");
    assert_eq!(rig.screen.log(), ["front:4242"]);
    let rows = journal_results(&rig);
    let fronted: Vec<_> = rows[before..]
        .iter()
        .filter(|row| row["outcome"] == "fronted")
        .collect();
    assert_eq!(fronted.len(), 1, "{rows:?}");
    let record = row_fronting(fronted[0]);
    assert!(record.fronted);
    assert_eq!(record.restore, FrontingRecordRestore::LeftInFront);
    assert_eq!(
        fronted[0]["grant_identity"]["bundle_identity"],
        support::TARGET_BUNDLE_ID
    );
}

/// A background Command chord's actuation row records its temporary front,
/// and it still decodes with the row type as it was before the record
/// existed.
#[tokio::test]
async fn a_chord_row_records_its_front_and_decodes_with_the_older_type() {
    use cerebellum_computer::audit::{
        ActuationOutcome, FrontingRecordPurpose, FrontingRecordRestore, RecordedActuationOutcome,
    };
    /// `RecordedActuationOutcome` as it was before it gained `fronting`.
    #[derive(serde::Deserialize)]
    struct BeforeFronting {
        #[serde(flatten)]
        outcome: ActuationOutcome,
        #[serde(flatten, default)]
        #[allow(dead_code)]
        routes: cerebellum_computer::platform::input_route::InputRouteEvidence,
    }
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    let reply = rig
        .call_under(&under_terminal(), "computer.keys", command_chord())
        .await;
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    let rows = journal_results(&rig);
    let actuation = rows
        .iter()
        .find(|row| row.get("fronting").is_some() && row["outcome"] == "handler_returned")
        .unwrap_or_else(|| panic!("no actuation row with fronting in {rows:?}"));
    let recorded: RecordedActuationOutcome = serde_json::from_value(actuation.clone()).unwrap();
    let record = recorded
        .fronting
        .expect("the chord's row records its front");
    assert!(record.fronted);
    assert_eq!(record.purpose, FrontingRecordPurpose::NeedsFront);
    assert_eq!(record.restore, FrontingRecordRestore::Restored);
    let older: BeforeFronting = serde_json::from_value(actuation.clone()).unwrap();
    assert_eq!(older.outcome, recorded.outcome);
}

/// The person types into the target while a fronted press settles, moving
/// its focus. The settle ends on their input and the previous application
/// is restored, but what the target looked like after their input is never
/// recorded as what the conversation was shown: the agent's next press on
/// it is refused as for any change the person made since the last read.
#[tokio::test]
async fn input_during_a_fronted_settle_keeps_the_next_press_from_acting_unseen() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let (desk, screen) = (rig.desk.clone(), rig.screen.clone());
    rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
        desk.state().focus = support::DeskFocus::Element(10);
        let mut state = screen.state();
        state.person_key_pending = true;
        state.last_input_ms = Some(state.now + 1);
        state.now += 2;
    })));
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    assert_eq!(reply["fronting"]["person_input_during_fronting"], true);
    assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);

    let again = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(again["outcome"], "state_changed_by_person", "{again}");
    assert_eq!(again["reason"], "focus_changed", "{again}");
    assert_eq!(
        rig.desk.state().presses,
        [10],
        "the second press sent nothing"
    );
    assert!(!rig.lock.held());
}

// ---------------------------------------------------------------------------
// Admission, the seen baseline and guard (0) against session-wide sends
// ---------------------------------------------------------------------------

#[path = "fronting_admission_tests.rs"]
mod admission;

#[tokio::test(start_paused = true)]
async fn person_input_requests_restore_before_a_slow_settle_read() {
    use cerebellum_computer::app_state::source::ElementHandle;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, ElementActionError, RawAppState, ReadBounds, WindowMark,
    };

    struct SlowSettleSource {
        desk: support::Desk,
        screen: Screen,
        input_at: Arc<StdMutex<Option<u64>>>,
    }
    impl AppStateSource for SlowSettleSource {
        fn reports_screen_geometry(&self) -> bool {
            self.desk.reports_screen_geometry()
        }
        fn element_frame(&self, element: &ElementHandle) -> Option<[f64; 4]> {
            self.desk.element_frame(element)
        }
        fn display_frames(&self) -> Option<Vec<[f64; 4]>> {
            self.desk.display_frames()
        }
        fn read_app_state(
            &self,
            target: &ProcessGrant,
            bounds: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            if self.input_at.lock().unwrap().is_some() {
                let mut state = self.screen.state();
                state.log.push("slow_read".into());
                // The fake screen clock is paused between host operations.
                // An AX read after input would hold it for four seconds.
                state.now += 4_000;
            }
            self.desk.read_app_state(target, bounds)
        }
        fn element_facts(&self, e: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
            self.desk.element_facts(e)
        }
        fn element_enabled(&self, e: &ElementHandle) -> Option<bool> {
            self.desk.element_enabled(e)
        }
        fn press(&self, e: &ElementHandle) -> Result<(), ElementActionError> {
            self.desk.press(e)
        }
        fn focused_element(
            &self,
            g: &ProcessGrant,
        ) -> Result<Option<ElementHandle>, ElementActionError> {
            self.desk.focused_element(g)
        }
        fn focused_window(
            &self,
            g: &ProcessGrant,
        ) -> Result<Option<WindowMark>, ElementActionError> {
            self.desk.focused_window(g)
        }
        fn frontmost_pid(&self) -> Option<u32> {
            self.desk.frontmost_pid()
        }
        fn hardware_input(
            &self,
            g: &ProcessGrant,
        ) -> Result<(std::time::Instant, Option<std::time::Instant>), ElementActionError> {
            self.desk.hardware_input(g)
        }
        fn time_since_last_input(&self) -> Option<Duration> {
            self.desk.time_since_last_input()
        }
    }
    let mut rig = rig(AppUse::Background, mail_desk()).await;
    let send = rig.send_id().await;
    rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
    rig.screen.state().enable_on_front = vec![10];
    let input_at = Arc::new(StdMutex::new(None));
    Arc::get_mut(&mut rig.plane)
        .expect("no call is running")
        .app_state_source = Arc::new(SlowSettleSource {
        desk: rig.desk.clone(),
        screen: rig.screen.clone(),
        input_at: input_at.clone(),
    });
    let (screen, stamp) = (rig.screen.clone(), input_at.clone());
    rig.desk.state().on_press = Some(support::DeskHook(Arc::new(move || {
        let mut state = screen.state();
        state.person_key_pending = true;
        state.last_input_ms = Some(state.now + 1);
        state.now += 2;
        *stamp.lock().unwrap() = Some(state.now);
    })));
    let reply = rig
        .call_under(
            &under_terminal(),
            "computer.press_element",
            json!({"element_id": send}),
        )
        .await;
    assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
    assert_eq!(
        rig.screen.log(),
        ["front:4242", "restore:100"],
        "restore must precede any slow final AX read"
    );
    let elapsed = rig.screen.state().now - input_at.lock().unwrap().unwrap();
    assert!(
        elapsed <= 50,
        "person input to restore took {elapsed} ms, beyond one settle poll"
    );
}

// ---------------------------------------------------------------------------
// Settle read budgets
// ---------------------------------------------------------------------------

/// A slow application on a paused clock: a read needs `needs` to visit the
/// whole tree and takes no real time. Given less, it returns what it reached
/// by its bound, the first window only, marked `read_bound_reached` as the
/// platform reader marks a timed-out read.
mod settle_read_budget {
    use super::element_actions::{settle_and_observe_view, PersonWatch};
    use cerebellum_computer::app_state::session::AppStateSessions;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, AppStateSource, ElementValue, FixtureElementToken, RawAppState,
        RawElement, ReadBounds,
    };
    use cerebellum_computer::platform::ProcessGrant;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    const CONVERSATION: &str = "settle-budget";
    /// Longer than the 50 ms settle poll interval.
    const SLOW_READ: Duration = Duration::from_millis(400);

    fn window(token: u64, title: &str) -> RawElement {
        RawElement {
            handle: Arc::new(FixtureElementToken(token)),
            role: Some("AXWindow".into()),
            subrole: None,
            title: Some(title.into()),
            description: None,
            value_description: None,
            value: ElementValue::Absent,
            value_settable: false,
            selected: false,
            enabled: true,
            focused: false,
            main_window: false,
            focused_window: false,
            expanded: None,
            menu_visible: false,
            closed_menu_children: 0,
            url: None,
            children: Vec::new(),
            unreadable_children: 0,
        }
    }

    fn tree(second_title: &str) -> RawAppState {
        RawAppState {
            roots: vec![window(1, "Documents"), window(2, second_title)],
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        }
    }

    struct SlowApp {
        current: Mutex<RawAppState>,
        timeouts: Mutex<Vec<Duration>>,
    }

    impl AppStateSource for SlowApp {
        fn read_app_state(
            &self,
            _target: &ProcessGrant,
            bounds: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            self.timeouts.lock().unwrap().push(bounds.timeout);
            let mut read = self.current.lock().unwrap().clone();
            if bounds.timeout < SLOW_READ {
                read.roots.truncate(1);
                read.read_bound_reached = true;
            }
            Ok(read)
        }
    }

    fn grant() -> ProcessGrant {
        ProcessGrant {
            pid: 77,
            bundle_identity: "com.example.slow".into(),
            process_generation_evidence: "generation-77".into(),
        }
    }

    /// The baseline holds the "Downloads" tree; the application now shows
    /// "Applications" in its second window.
    fn changed_app() -> (SlowApp, AppStateSessions) {
        let sessions = AppStateSessions::new();
        sessions.observe(CONVERSATION, &grant(), &tree("Downloads"));
        let app = SlowApp {
            current: Mutex::new(tree("Applications")),
            timeouts: Mutex::new(Vec::new()),
        };
        (app, sessions)
    }

    /// An action that did not front the application waits for its effect
    /// with the ordinary read budget, so a slow application's whole tree is
    /// read and shown, not the part a 50 ms poll reaches.
    #[test]
    fn an_unwatched_settle_reads_a_slow_application_whole() {
        let (app, sessions) = changed_app();
        let observed = settle_and_observe_view(
            &app,
            &sessions,
            CONVERSATION,
            &grant(),
            Duration::from_millis(200),
            false,
            PersonWatch::NotWatched,
            None,
            None,
        )
        .expect("the changed application is observed")
        .read;
        assert_eq!(
            *app.timeouts.lock().unwrap(),
            [ReadBounds::default().timeout],
            "an unwatched read keeps the ordinary read budget"
        );
        assert!(observed.complete, "the observed read is the whole tree");
        assert_eq!(observed.roots.len(), 2, "both windows are shown");
        assert!(
            !sessions.differs_from_baseline(CONVERSATION, &grant(), &tree("Applications")),
            "the whole new tree is the baseline"
        );
    }

    /// While the application is in front, a read is bounded by the time
    /// left in the settle window. A read cut short by that bound is neither
    /// shown nor adopted: the reply carries no diff and the earlier baseline
    /// stays.
    #[test]
    fn a_watched_settle_adopts_nothing_from_a_read_cut_short() {
        let (app, sessions) = changed_app();
        let window = Duration::from_millis(200);
        let observed = settle_and_observe_view(
            &app,
            &sessions,
            CONVERSATION,
            &grant(),
            window,
            false,
            PersonWatch::Watched(&mut || false),
            None,
            None,
        );
        assert!(observed.is_none(), "a partial read is not shown");
        let timeouts = app.timeouts.lock().unwrap().clone();
        assert_eq!(timeouts.len(), 1, "the settle stopped at the partial read");
        assert!(
            // Not the ordinary four-second budget. The time left may reach
            // zero on a loaded host, which still cuts the read short.
            timeouts[0] <= window,
            "the read was bounded by the settle window: {timeouts:?}"
        );
        assert!(
            !sessions.differs_from_baseline(CONVERSATION, &grant(), &tree("Downloads")),
            "the earlier baseline is unchanged"
        );
    }
}

#[path = "pointer_fronting_tests.rs"]
mod pointer_tests;

#[tokio::test]
async fn a_pending_chord_landing_after_its_reply_only_restores_and_never_posts() {
    for evidence in ["quiet", "input", "unreadable"] {
        let rig = rig(AppUse::Background, mail_desk()).await;
        rig.read().await;
        let gate = Arc::new(std::sync::atomic::AtomicBool::new(false));
        {
            let mut state = rig.screen.state();
            state.front_delay_ms = Some(800);
            state.late_watch_gate = Some(Arc::clone(&gate));
        }
        let terminal = under_terminal();
        let reply = rig
            .call_under(&terminal, "computer.keys", command_chord())
            .await;
        assert_eq!(reply["outcome"], "restore_failed", "{reply}");
        assert_eq!(reply["effect_status"], "not_dispatched");
        assert_eq!(reply["fronting"]["fronted"], false);
        assert_eq!(reply["fronting"]["restore"], "failed");
        assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        terminal.set_late_fronting_recorder(Arc::new(move |record| {
            tx.send(record).unwrap();
        }));
        terminal.start_late_fronting(None);
        {
            let mut state = rig.screen.state();
            if evidence == "input" {
                state.last_input_ms = Some(400);
            }
            if evidence == "unreadable" {
                state.observer = false;
            }
        }
        gate.store(true, std::sync::atomic::Ordering::Release);
        let record = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        if evidence == "quiet" {
            assert_eq!(record["restore"], "restored");
            assert_eq!(record["activation_latency_ms"], 800);
            assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
            assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
        } else {
            assert_eq!(record["restore"], "skipped_person");
            assert_eq!(record["person_input_during_fronting"], true);
            assert_eq!(rig.screen.log(), ["front:4242"]);
        }
        assert!(!rig.screen.log().iter().any(|event| event == "post"));
        // The immutable terminal reply remains honest after late cleanup.
        assert_eq!(reply["fronting"]["restore"], "failed");
    }
}

#[tokio::test]
async fn late_fronting_route_close_restores_only_with_quiet_known_input_coverage() {
    for evidence in ["quiet", "input", "unreadable"] {
        let rig = rig(AppUse::Background, mail_desk()).await;
        rig.read().await;
        rig.screen.state().front_delay_ms = Some(800);
        let terminal = under_terminal();
        let reply = rig
            .call_under(&terminal, "computer.keys", command_chord())
            .await;
        assert_eq!(reply["fronting"]["restore"], "failed");
        {
            let mut state = rig.screen.state();
            state.now = 800;
            state.pending_front_at = None;
            if evidence == "input" {
                state.last_input_ms = Some(500);
            }
            if evidence == "unreadable" {
                state.observer = false;
            }
        }
        rig.desk.state().frontmost = Some(TARGET);
        terminal.stop(crate::terminal_arbiter::TerminalCause::RouteClosed);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        terminal.set_late_fronting_recorder(Arc::new(move |record| {
            tx.send(record).unwrap();
        }));
        terminal.start_late_fronting(None);
        let record = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        if evidence == "quiet" {
            assert_eq!(record["restore"], "restored");
            assert_eq!(rig.screen.frontmost(), Some(PREVIOUS));
        } else {
            assert_eq!(record["restore"], "skipped_person");
            assert_eq!(rig.screen.frontmost(), Some(TARGET));
        }
        assert!(!rig.screen.log().iter().any(|event| event == "post"));
    }
}

#[tokio::test]
async fn a_new_app_call_before_watcher_start_still_ends_the_pending_watch() {
    let rig = rig(AppUse::Background, mail_desk()).await;
    rig.read().await;
    rig.screen.state().front_delay_ms = Some(800);
    let terminal = under_terminal();
    let reply = rig
        .call_under(&terminal, "computer.keys", command_chord())
        .await;
    assert_eq!(reply["fronting"]["restore"], "failed");
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    terminal.set_late_fronting_recorder(Arc::new(move |record| {
        tx.send(record).unwrap();
    }));
    assert!(crate::terminal_arbiter::cancel_late_fronting_target(
        rig.lock.domain(),
        TARGET
    ));
    terminal.start_late_fronting(None);
    let record = tokio::time::timeout(crate::test_support::HANG_GUARD, rx.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(record["restore"], "failed");
    assert_eq!(rig.screen.log(), ["front:4242"]);
    assert_eq!(rig.screen.state().now, 400);
}

#[tokio::test]
async fn failed_late_fronting_journal_writes_increment_the_quiet_health_counter() {
    for fault in [
        "advance_allocator",
        "commit_dispatch",
        "commit_finalization",
    ] {
        let rig = rig_admitting(
            AppUse::Background,
            mail_desk(),
            support::granted_management().await,
            false,
            true,
        );
        let carrier = support::ScriptedCarrier::answering(&["computer_30m"]);
        rig.management
            .computer_grants()
            .require(
                &crate::computer_grants::GrantNeed::Takeover,
                &support::relayed(&carrier),
                &crate::CancelHandle::pending(),
            )
            .await
            .unwrap();
        rig.read().await;
        let terminal = under_terminal();
        let reply = rig
            .call_under(&terminal, "computer.keys", command_chord())
            .await;
        assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
        let before = super::late_fronting_journal_failures();
        rig.plane
            .audit
            .lock()
            .unwrap()
            .journal_mut()
            .arm_fault(fault, 1);
        terminal.record_late_fronting_for_test(json!({"cleanup":"restore", "restore":"restored"}));
        assert_eq!(
            super::late_fronting_journal_failures(),
            before + 1,
            "fault {fault} was not counted"
        );
    }
}
