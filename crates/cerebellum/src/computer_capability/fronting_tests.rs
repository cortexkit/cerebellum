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
                let route = chord_route(without_takeover, false, true);
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
                    chord_route(without_takeover, false, false),
                    ChordRoute::PerProcess
                );
                assert_eq!(
                    chord_route(without_takeover, true, true),
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
    assert_eq!(chord_route(held, false, true), ChordRoute::TakeoverBracket);
    let unreviewed = Admission {
        bracket_admitted: false,
        ..held
    };
    assert_eq!(
        chord_route(unreviewed, false, true),
        ChordRoute::Refuse(ChordRefusal::KeystrokesNeedForeground)
    );
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
    now: u64,
    idle_ms: u64,
    observer: bool,
    comes_forward: bool,
    /// Every front and restore request, and every post and release, in
    /// order.
    log: Vec<String>,
    last_input_ms: Option<u64>,
    /// A chord's post fails with its keys possibly still held.
    post_unknown: bool,
    /// Whether the paired release of held keys returns.
    release_ok: bool,
    /// Once the target is fronted, this element of the desk reads enabled.
    enable_on_front: Option<u64>,
    /// A chord's post stays in flight, with its keys down, until this call's
    /// terminal is chosen, and then fails with them possibly held.
    hold_until_stopped: Option<Arc<crate::TerminalArbiter>>,
    /// Told when the chord's post begins.
    posting: Option<tokio::sync::oneshot::Sender<()>>,
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
                now: 0,
                idle_ms: OBSERVED_DISPATCH_IDLE_MS + 500,
                observer: true,
                comes_forward: true,
                log: Vec::new(),
                last_input_ms: None,
                post_unknown: false,
                release_ok: true,
                enable_on_front: None,
                hold_until_stopped: None,
                posting: None,
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
            (state.comes_forward, state.enable_on_front)
        };
        if comes_forward {
            let mut desk = self.desk.state();
            desk.frontmost = Some(pid);
            if pid == TARGET {
                if let Some(token) = enable {
                    if let Some(element) = desk.elements.get_mut(&token) {
                        element.enabled = Some(true);
                    }
                }
            }
        }
        true
    }

    fn snapshot(&self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: self.state().last_input_ms,
        })
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
        self.0.state().now += milliseconds;
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.0.frontmost()
    }
    fn request_front(&mut self, pid: u32) -> bool {
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
        self.0.state().now += milliseconds;
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
        Vec::new()
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
        self.0.state().now += milliseconds;
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
            let _ = posting.send(());
        }
        if let Some(terminal) = hold {
            let give_up = std::time::Instant::now() + Duration::from_secs(10);
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
        _request: GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("the fake posts nothing globally"))
    }
    fn release_held(
        &mut self,
        _target: &ProcessGrant,
        _action: &SyntheticAction,
    ) -> Result<u64, DriverError> {
        let ok = {
            let mut state = self.screen.state();
            state.log.push("release".into());
            state.release_ok
        };
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
    fn fronting_session(&mut self) -> Result<Box<dyn FrontingSession>, DriverError> {
        Ok(Box::new(FakeSession(self.screen.clone())))
    }
    fn accept_fronted_dispatch_hooks(&mut self, hooks: Box<dyn FrontedDispatchHooks>) -> bool {
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
    super::app_use::LiveAppUse::new(
        Some(PathBuf::from(
            "/fixture/home/.config/cortexkit/cerebellum.jsonc",
        )),
        Arc::new(FixedConfig(match mode {
            AppUse::Foreground => r#"{"computer_use":{"app_use":"foreground"}}"#,
            AppUse::Background => r#"{"computer_use":{"app_use":"background"}}"#,
        })),
    )
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
    let screen = Screen::new(&desk);
    let lock = FrontingLock::isolated();
    let driver_screen = screen.clone();
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        support::audit(),
        ResultSchemaEnforcement::Withhold,
        move || FakeDriver {
            screen: driver_screen.clone(),
            hooks: None,
        },
    )
    .with_permission_liveness(support::live_permissions())
    .with_app_state_source(desk.source())
    .with_app_use(app_use_file(mode))
    .with_app_use_fronting_admitted(true)
    .with_fronting_bracket_admitted(true)
    .with_fronting_lock(lock.clone());
    Rig {
        plane: Arc::new(plane),
        screen,
        desk,
        management: support::granted_management().await,
        lock,
    }
}

impl Rig {
    async fn serve(&self, name: &str, arguments: Value, cancel: crate::CancelHandle) -> Value {
        let clock = cerebellum_core::clock::FakeClock::new();
        self.plane
            .serve(
                servable(name).expect("served"),
                &arguments,
                ServeContext {
                    cancel,
                    grantee: support::GRANTEE,
                    identity: support::identity(),
                    management: &self.management,
                    consent: support::no_relay(),
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

    let rig = Rig {
        plane: Arc::new(
            Arc::try_unwrap(rig.plane)
                .ok()
                .unwrap()
                .with_app_use(app_use_file(AppUse::Background)),
        ),
        ..rig
    };
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

    let rig = Rig {
        plane: Arc::new(
            Arc::try_unwrap(rig.plane)
                .ok()
                .unwrap()
                .with_app_use(app_use_file(AppUse::Background)),
        ),
        ..rig
    };
    let send = rig.send_id().await;
    let started = tokio::time::Instant::now();
    let reply = rig
        .call("computer.press_element", json!({"element_id": send}))
        .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert_eq!(reply["fronting"]["purpose"], "none");
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
    rig.screen.state().enable_on_front = Some(10);
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

/// The person switching to a third application with hardware input while
/// the target is in front is left there: no restore request. The same
/// switch without hardware input was the press's own doing, and the
/// previous application is restored.
#[tokio::test]
async fn a_person_switch_with_input_is_left_alone_and_one_without_is_restored() {
    for input in [true, false] {
        let rig = rig(AppUse::Background, mail_desk()).await;
        let send = rig.send_id().await;
        rig.desk.state().elements.get_mut(&10).unwrap().enabled = Some(false);
        rig.screen.state().enable_on_front = Some(10);
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
        if input {
            assert_eq!(reply["fronting"]["restore"], "skipped_person", "{reply}");
            assert_eq!(reply["fronting"]["person_input_during_fronting"], true);
            assert_eq!(rig.screen.log(), ["front:4242"], "no restore request");
        } else {
            assert_eq!(reply["fronting"]["restore"], "restored", "{reply}");
            assert_eq!(rig.screen.log(), ["front:4242", "restore:100"]);
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

/// Serve a Command chord on a route whose post stays in flight with its
/// keys down, cancel the route once the post has begun, and return the
/// wire reply's body.
async fn chord_cancelled_mid_post(rig: &Rig) -> Value {
    let mut planes = crate::tests::management_bound_planes(1, 1);
    let (posting, posted) = tokio::sync::oneshot::channel();
    rig.screen.state().posting = Some(posting);
    let input = StdMutex::new(Some(rig.clone()));
    planes.route_test_handler = Some(Arc::new(move || {
        let rig = input.lock().unwrap().take().unwrap();
        Box::pin(async move {
            let terminal = crate::TerminalArbiter::current().unwrap();
            rig.screen.state().hold_until_stopped = Some(terminal);
            let _ = rig.call("computer.keys", command_chord()).await;
            std::future::pending::<()>().await;
        })
    }));
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);
    crate::handle_frame(route_request(), &tx, &planes)
        .await
        .unwrap();
    posted.await.unwrap();
    crate::handle_frame(route_cancel(), &tx, &planes)
        .await
        .unwrap();
    let reply = rx.recv().await.unwrap();
    serde_json::from_slice(&reply.body).unwrap()
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
