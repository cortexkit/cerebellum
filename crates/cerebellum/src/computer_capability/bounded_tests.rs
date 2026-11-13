//! Bounded-call behaviour of the computer plane that needs no platform:
//! execution quarantine, blocking-worker permits, the posting-interval
//! handshake with the call's terminal decision, and the four ways held-input
//! quarantine clears.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use cerebellum_computer::app_state::person::OwnInputLedger;
use cerebellum_computer::platform::{
    HeldStateDisposition, ProcessGrant, SyntheticAction, SyntheticKey, SyntheticKeyModifiers,
    SyntheticPoint,
};
use serde_json::json;
use subc_protocol::{Frame, FrameType};

use super::held_input::{self, HeldInput, HeldPress};
use super::quarantine::{self, CallWork, ExecutionQuarantine};
use crate::blocking_permits::PermitPool;
use crate::{HeldState, TerminalArbiter, TerminalCause};

const EDITOR: &str = "com.example.Editor";
const VIEWER: &str = "com.example.Viewer";

fn terminal() -> Arc<TerminalArbiter> {
    Arc::new(TerminalArbiter::new(
        Frame::build_with_version(
            crate::PROTOCOL_VERSION,
            FrameType::Request,
            crate::control_flags(),
            1,
            1,
            1,
            serde_json::to_vec(&json!({"name":"computer_use","arguments":{"action":"keys"}}))
                .unwrap(),
        )
        .unwrap(),
    ))
}

fn grant(pid: u32, bundle_identity: &str) -> ProcessGrant {
    ProcessGrant {
        pid,
        bundle_identity: bundle_identity.into(),
        process_generation_evidence: format!("generation-{pid}"),
    }
}

fn chord() -> SyntheticAction {
    SyntheticAction::key_combination(SyntheticKey::A, SyntheticKeyModifiers::NONE)
}

fn press(pid: u32) -> HeldPress {
    HeldPress::per_process(&grant(pid, EDITOR), &chord()).unwrap()
}

#[test]
fn a_worker_quarantines_its_app_by_pid_or_bundle_only_while_it_outlives_its_answer() {
    let registry = Arc::new(ExecutionQuarantine::default());
    let call = terminal();
    let lease = registry.enter(
        Some(EDITOR.into()),
        "computer.press_element",
        Some(call.clone()),
    );
    assert_eq!(
        registry.busy(None, None, Some(EDITOR)),
        None,
        "a worker whose call is still running is not stuck"
    );
    lease.bind(&grant(42, EDITOR));
    call.stop(TerminalCause::Deadline);
    assert_eq!(
        registry.busy(None, None, Some("COM.EXAMPLE.EDITOR")),
        Some("computer.press_element"),
        "the bundle identity matches"
    );
    assert_eq!(
        registry.busy(None, Some(42), Some(VIEWER)),
        Some("computer.press_element"),
        "the pid matches even when the call names another bundle"
    );
    assert_eq!(
        registry.busy(None, Some(43), Some(VIEWER)),
        None,
        "another application proceeds"
    );
    assert_eq!(
        registry.busy(Some(&lease), Some(42), Some(EDITOR)),
        None,
        "a call never finds itself busy"
    );
    drop(lease);
    assert_eq!(registry.busy(None, Some(42), Some(EDITOR)), None);
    assert!(
        registry.is_empty(),
        "quarantine clears when the worker ends"
    );
}

#[test]
fn a_call_takes_its_two_permits_together_and_a_resolution_takes_one() {
    let pool = PermitPool::new(4);
    let first = pool.try_call().expect("two of four permits");
    let second = pool.try_call().expect("the other two");
    assert!(pool.try_call().is_none(), "no permit is free");
    assert!(pool.try_resolution().is_none());
    drop(first.take_release());
    assert_eq!(pool.available(), 1);
    assert!(
        pool.try_call().is_none(),
        "one free permit is not taken by a call that needs two"
    );
    assert_eq!(pool.available(), 1, "a refused call takes nothing");
    let resolution = pool.try_resolution().expect("one permit for a query");
    assert_eq!(pool.available(), 0);
    let job = Arc::new(first);
    let running = Arc::clone(&job);
    drop(job);
    assert_eq!(
        pool.available(),
        0,
        "the work permit stays taken while a job still holds it"
    );
    drop(running);
    assert_eq!(pool.available(), 1);
    drop((resolution, second));
    assert_eq!(pool.available(), 4);
}

#[test]
fn a_published_posting_interval_closes_when_the_terminal_is_chosen() {
    let ledger = Arc::new(OwnInputLedger::new());
    let call = terminal();
    let work = CallWork::new(Some(call.clone()), Duration::from_secs(1), None, None);
    let posting = ledger.begin_posting(None);
    work.publish_posting(&ledger, &posting);
    assert!(ledger.has_open_posting(), "the worker is still posting");
    call.stop(TerminalCause::Deadline);
    assert!(
        !ledger.has_open_posting(),
        "the terminal closed the interval although the worker never returned"
    );
    ledger.end_posting(posting);
    assert!(!ledger.has_open_posting());
}

#[test]
fn a_worker_publishing_after_the_terminal_closes_its_own_interval_at_once() {
    let ledger = Arc::new(OwnInputLedger::new());
    let call = terminal();
    let work = CallWork::new(Some(call.clone()), Duration::from_secs(1), None, None);
    call.stop(TerminalCause::Cancelled);
    // The terminal was chosen after the worker opened its interval but before
    // it published it; the worker then stays blocked in its post.
    let posting = ledger.begin_posting(None);
    assert!(ledger.has_open_posting());
    work.publish_posting(&ledger, &posting);
    assert!(
        !ledger.has_open_posting(),
        "no interval stays open after the terminal"
    );
    // The worker's own close, whenever it finally returns, changes nothing.
    ledger.end_posting(posting);
    assert!(!ledger.has_open_posting());
}

#[tokio::test]
async fn the_work_deadline_pauses_while_the_call_waits_on_a_person() {
    CallWork::new(None, Duration::from_secs(1), None, None)
        .scope(async {
            let before = CallWork::current().deadline();
            {
                let _parked = quarantine::park_clock().expect("a call has a work context");
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            assert!(
                CallWork::current().deadline() >= before + Duration::from_millis(50),
                "the time parked was added back to the work budget"
            );
        })
        .await;
    assert!(
        quarantine::park_clock().is_none(),
        "outside a call nothing is counted"
    );
}

#[tokio::test]
async fn held_input_clears_when_the_late_worker_reports_its_presses_released() {
    let held = Arc::new(HeldInput::default());
    let call = terminal();
    let ticket = held.begin_send(press(42), Some(call.clone()));
    let reported = ticket.outcome();
    assert!(!held.unconfirmed(), "a running send is not yet unconfirmed");
    call.stop(TerminalCause::Deadline);
    assert!(held.unconfirmed(), "the worker outlived its answer");
    assert!(
        held.pending_release().is_err(),
        "nothing may release under it"
    );
    let settled = ticket.settle(HeldStateDisposition::Released { posts_returned: 1 }, |_| {
        panic!("the sequence released its own presses; no reaper runs")
    });
    assert!(matches!(settled, HeldState::Released));
    assert!(matches!(reported.await, HeldState::Released));
    assert!(
        held.is_clear(),
        "clearing path 1: the late worker's own release"
    );
}

#[test]
fn held_input_clears_when_the_reaper_releases_after_the_worker_ends() {
    let held = Arc::new(HeldInput::default());
    let call = terminal();
    let ticket = held.begin_send(press(42), Some(call.clone()));
    call.stop(TerminalCause::Deadline);
    let reaped = AtomicUsize::new(0);
    let settled = ticket.settle(HeldStateDisposition::Unknown, |press| {
        assert_eq!(press.grant.pid, 42);
        reaped.fetch_add(1, Ordering::SeqCst);
        true
    });
    assert!(matches!(settled, HeldState::Released));
    assert_eq!(reaped.load(Ordering::SeqCst), 1);
    assert!(
        held.is_clear(),
        "clearing path 2: the reaper's paired release"
    );
}

#[test]
fn a_later_call_releases_held_input_itself_only_once_no_send_is_outstanding() {
    let held = Arc::new(HeldInput::default());
    let call = terminal();
    let ticket = held.begin_send(press(42), Some(call.clone()));
    call.stop(TerminalCause::Deadline);
    assert!(matches!(
        ticket.settle(HeldStateDisposition::Unknown, |_| false),
        HeldState::Unknown
    ));
    assert!(
        held.unconfirmed(),
        "quarantined even after the worker ended"
    );

    // Another worker with a possibly-held send is alive: a release now could
    // be overtaken by its delayed press, so no later call may clear anything.
    let alive = held.begin_send(press(42), Some(terminal()));
    assert!(held.pending_release().is_err());
    // Its delayed press lands and is unconfirmed too: still covered.
    assert!(matches!(
        alive.settle(HeldStateDisposition::Unknown, |_| false),
        HeldState::Unknown
    ));
    assert!(held.unconfirmed());

    let pending = held
        .pending_release()
        .expect("no send is outstanding now")
        .expect("both presses are quarantined");
    assert_eq!(pending.presses.len(), 2);
    let released = AtomicUsize::new(0);
    assert!(held_input::release_pending(&held, pending, |_| {
        released.fetch_add(1, Ordering::SeqCst);
        true
    }));
    assert_eq!(released.load(Ordering::SeqCst), 2);
    assert!(
        held.is_clear(),
        "clearing path 3: a later call's own release"
    );
}

#[test]
fn a_partial_release_by_a_later_call_confirms_nothing() {
    let held = Arc::new(HeldInput::default());
    for pid in [42, 43] {
        let ticket = held.begin_send(press(pid), Some(terminal()));
        ticket.settle(HeldStateDisposition::Unknown, |_| false);
    }
    let pending = held.pending_release().unwrap().unwrap();
    let mut first = true;
    assert!(!held_input::release_pending(&held, pending, |_| {
        std::mem::replace(&mut first, false)
    }));
    assert!(held.unconfirmed());
}

#[test]
fn process_exit_discharges_presses_routed_only_to_that_process() {
    let held = Arc::new(HeldInput::default());
    held.begin_send(press(42), Some(terminal()))
        .settle(HeldStateDisposition::Unknown, |_| false);
    // A stuck worker's outstanding press to the same process.
    let stuck_call = terminal();
    let stuck = held.begin_send(press(42), Some(stuck_call.clone()));
    stuck_call.stop(TerminalCause::Deadline);
    assert!(held.unconfirmed());

    held.discharge_exited(|pid, generation| !(pid == 42 && generation == "generation-42"));
    assert!(
        !held.unconfirmed(),
        "clearing path 4: the exited process's presses were discharged"
    );
    drop(stuck);
    assert!(
        !held.unconfirmed(),
        "a discharged send that ends unsettled is not quarantined again"
    );
}

#[test]
fn process_exit_leaves_global_held_input_quarantined() {
    let held = Arc::new(HeldInput::default());
    let drag = SyntheticAction::drag_pointer(
        SyntheticPoint { x: 1.0, y: 1.0 },
        SyntheticPoint { x: 2.0, y: 2.0 },
    );
    let global = HeldPress::global(&grant(42, EDITOR), &drag).unwrap();
    for held_press in [press(42), global] {
        held.begin_send(held_press, Some(terminal()))
            .settle(HeldStateDisposition::Unknown, |_| false);
    }
    held.discharge_exited(|_, _| false);
    assert!(
        held.unconfirmed(),
        "global held input stays quarantined after the target exits"
    );
    let pending = held.pending_release().unwrap().unwrap();
    assert_eq!(pending.presses.len(), 1);
    assert!(matches!(
        pending.presses[0].1.route,
        held_input::HeldRoute::Global
    ));
    assert!(
        !held_input::release_pending(&held, pending, |press| {
            held_input::release_one(press, &mut UnreachableDriver)
        }),
        "global input has no per-process release"
    );
    assert!(held.unconfirmed());
}

#[test]
fn an_action_without_a_press_is_not_tracked() {
    let point = SyntheticPoint { x: 1.0, y: 1.0 };
    assert!(
        HeldPress::per_process(&grant(42, EDITOR), &SyntheticAction::move_pointer(point)).is_none()
    );
    assert!(HeldPress::per_process(&grant(42, EDITOR), &chord()).is_some());
}

#[test]
fn bounded_refusals_pass_every_rows_frozen_result_schema() {
    for id in cerebellum_computer::platform::COMPUTER_CAPABILITY_ROW_IDS {
        let capability = super::servable(id).unwrap();
        for reply in [
            quarantine::target_busy_reply("computer.read_state", "queue"),
            quarantine::capacity_exhausted_reply("queue", "target resolution"),
            quarantine::stopped_before_dispatch_reply(),
            held_input::held_input_unconfirmed_reply(id),
        ] {
            let reply = super::serialize::refused_in_queue(capability, reply);
            cerebellum_computer::platform::vocabulary::validate_capability_result(id, &reply)
                .unwrap_or_else(|error| panic!("{id}: {error:?}: {reply}"));
            if matches!(id, "computer.type" | "computer.keys") {
                assert_eq!(reply["effect_status"], "not_dispatched", "{id}: {reply}");
            }
        }
    }
}

/// An element source that counts presses: a press after the call's stop is
/// an external call the gate must have refused.
#[cfg(target_os = "macos")]
struct CountingPresses(AtomicUsize);

#[cfg(target_os = "macos")]
impl cerebellum_computer::app_state::source::AppStateSource for CountingPresses {
    fn reports_screen_geometry(&self) -> bool {
        true
    }
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: cerebellum_computer::app_state::source::ReadBounds,
    ) -> Result<
        cerebellum_computer::app_state::source::RawAppState,
        cerebellum_computer::app_state::source::AppStateReadError,
    > {
        Err(cerebellum_computer::app_state::source::AppStateReadError::Unreadable)
    }
    fn element_facts(
        &self,
        _: &cerebellum_computer::app_state::source::ElementHandle,
    ) -> Result<
        cerebellum_computer::app_state::source::ElementFacts,
        cerebellum_computer::app_state::source::ElementActionError,
    > {
        Ok(cerebellum_computer::app_state::source::ElementFacts {
            pid: Some(42),
            role: Some("AXButton".into()),
            subrole: None,
            title: None,
            actions: vec!["AXPress".into()],
            value_settable: false,
            selected_text_settable: false,
        })
    }
    fn element_frame(
        &self,
        _: &cerebellum_computer::app_state::source::ElementHandle,
    ) -> Option<[f64; 4]> {
        Some([10.0, 10.0, 20.0, 20.0])
    }
    fn display_frames(&self) -> Option<Vec<[f64; 4]>> {
        Some(vec![[0.0, 0.0, 100.0, 100.0]])
    }
    fn press(
        &self,
        _: &cerebellum_computer::app_state::source::ElementHandle,
    ) -> Result<(), cerebellum_computer::app_state::source::ElementActionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[cfg(target_os = "macos")]
#[test]
fn an_element_press_after_the_stop_is_never_sent_and_is_journaled_as_stopped() {
    use cerebellum_computer::audit::{lock_audit, AuditToken, ComputerCapability};
    let audit = Arc::new(std::sync::Mutex::new(
        super::computer_audit(crate::JournalPersistence::Isolated).unwrap(),
    ));
    let call = terminal();
    call.stop(TerminalCause::Deadline);
    let token = AuditToken::new(audit.clone(), Arc::new(quarantine::ArbiterGate(Some(call))));
    let target = grant(42, EDITOR);
    let identity = cerebellum_computer::audit::journal_identity(
        "direct:agent",
        "conversation",
        "project",
        cerebellum_core::identity::SessionKind::Primary,
    );
    let mut journal = super::element_actions::ElementJournal::new(
        token,
        identity,
        ComputerCapability::PressElement,
        &target,
    );
    let source = CountingPresses(AtomicUsize::new(0));
    let handle: cerebellum_computer::app_state::source::ElementHandle = Arc::new(
        cerebellum_computer::app_state::source::FixtureElementToken(1),
    );
    let reply =
        super::element_actions::press_blocking(&source, &mut journal, &target, "e1", &handle);
    assert_eq!(reply["outcome"], "action_deadline_exceeded", "{reply}");
    assert_eq!(
        source.0.load(Ordering::SeqCst),
        0,
        "no press after the stop"
    );
    assert_eq!(
        lock_audit(&audit).journal().unfinalized_dispatch_count(),
        0,
        "the reserved entry was closed, not left open"
    );
}

/// A driver whose every method is unreachable: releasing global input must
/// not touch the platform at all.
struct UnreachableDriver;

impl cerebellum_computer::platform::PlatformDriver for UnreachableDriver {
    fn capability_declarations(
        &self,
        _: &cerebellum_computer::platform::CapabilityAdvertisementContext,
    ) -> Vec<cerebellum_computer::platform::CapabilityDeclaration> {
        unreachable!()
    }
    fn read_accessibility_tree(
        &mut self,
        _: cerebellum_computer::platform::AccessibilityTreeRequest,
    ) -> Result<
        cerebellum_computer::platform::AccessibilityTreeResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn resolve_element(
        &mut self,
        _: cerebellum_computer::platform::ElementResolutionRequest,
    ) -> Result<
        cerebellum_computer::platform::ElementResolutionResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn dispatch_semantic(
        &mut self,
        _: cerebellum_computer::platform::SemanticDispatchRequest,
    ) -> Result<
        cerebellum_computer::platform::DispatchResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn dispatch_per_pid(
        &mut self,
        _: cerebellum_computer::platform::SyntheticDispatchRequest,
        _: &dyn Fn() -> bool,
    ) -> Result<
        cerebellum_computer::platform::DispatchResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn dispatch_global(
        &mut self,
        _: cerebellum_computer::platform::GlobalDispatchRequest,
        _: &dyn Fn() -> bool,
    ) -> Result<
        cerebellum_computer::platform::DispatchResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn release_held(
        &mut self,
        _: &ProcessGrant,
        _: &SyntheticAction,
    ) -> Result<u64, cerebellum_computer::platform::DriverError> {
        unreachable!("global input must not be released per process")
    }
    fn query_focus(
        &mut self,
        _: cerebellum_computer::platform::FocusQueryRequest,
    ) -> Result<
        cerebellum_computer::platform::FocusQueryResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn fronting_snapshot(
        &mut self,
        _: &ProcessGrant,
    ) -> Result<
        cerebellum_computer::platform::FrontingSnapshot,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn input_observer_liveness(&self) -> cerebellum_computer::platform::InputObserverLiveness {
        unreachable!()
    }
    fn observe_input(
        &mut self,
        _: cerebellum_computer::platform::InputObservationRequest,
    ) -> Result<
        cerebellum_computer::platform::InputObservationResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn observe_effect(
        &mut self,
        _: cerebellum_computer::platform::EffectObservationRequest,
    ) -> Result<
        cerebellum_computer::platform::EffectObservationResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
    fn verify_attendance(
        &mut self,
        _: cerebellum_computer::platform::AttendancePreconditionRequest,
    ) -> Result<
        cerebellum_computer::platform::AttendancePreconditionResult,
        cerebellum_computer::platform::DriverError,
    > {
        unreachable!()
    }
}

#[test]
fn quarantine_checks_do_not_wait_for_another_bind_to_finish_late_cleanup() {
    let registry = Arc::new(ExecutionQuarantine::default());
    let call = terminal();
    let domain = Arc::as_ptr(&registry) as usize;
    call.fronting_domain.store(domain, Ordering::Release);
    let watch = crate::terminal_arbiter::hold_watch_for_test(domain, 42);
    let lease = registry.enter(Some(EDITOR.into()), "computer.keys", Some(call));
    let binding = std::thread::spawn(move || lease.bind(&grant(42, EDITOR)));
    let end = std::time::Instant::now() + crate::test_support::HANG_GUARD;
    while !watch.stopped() && std::time::Instant::now() < end {
        std::thread::yield_now();
    }
    assert!(watch.stopped(), "bind never reached the pending watcher");
    let (tx, rx) = std::sync::mpsc::channel();
    let checking = std::thread::spawn(move || {
        tx.send(registry.busy(None, Some(43), Some(VIEWER)))
            .unwrap();
    });
    let checked = rx.recv_timeout(Duration::from_millis(500));
    // Release the fake watcher even when the assertion will fail, so the
    // test's two worker threads never outlive their isolated registry.
    drop(watch);
    binding.join().unwrap();
    checking.join().unwrap();
    assert_eq!(
        checked,
        Ok(None),
        "an unrelated quarantine lookup waited for cleanup"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn binding_awaits_late_cleanup_without_blocking_the_tokio_worker() {
    let registry = Arc::new(ExecutionQuarantine::default());
    let call = terminal();
    let domain = Arc::as_ptr(&registry) as usize;
    call.fronting_domain.store(domain, Ordering::Release);
    let watch = crate::terminal_arbiter::hold_watch_for_test(domain, 42);
    let lease = registry.enter(
        Some(EDITOR.into()),
        "computer.keys",
        Some(Arc::clone(&call)),
    );
    let work = CallWork::new(Some(call), Duration::from_secs(30), Some(lease), None);
    let binding_registry = Arc::clone(&registry);
    let binding =
        tokio::spawn(async move { work.bind(&binding_registry, &grant(42, EDITOR)).await });
    let end = std::time::Instant::now() + crate::test_support::HANG_GUARD;
    while !watch.stopped() && std::time::Instant::now() < end {
        tokio::task::yield_now().await;
    }
    assert!(watch.stopped(), "bind never reached the pending watcher");
    assert!(
        !binding.is_finished(),
        "the Tokio worker resumed only after cleanup timed out"
    );
    assert_eq!(registry.busy(None, Some(43), Some(VIEWER)), None);
    drop(watch);
    assert_eq!(binding.await.unwrap(), None);
}

/// An application whose field never shows the typed text and whose every
/// read is slow, standing in for a backgrounded Electron app after a long
/// `type`: what a worker finds once its call has already been answered.
struct NeverShowsText {
    reads: AtomicUsize,
    text_reads: AtomicUsize,
}

impl cerebellum_computer::app_state::source::AppStateSource for NeverShowsText {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: cerebellum_computer::app_state::source::ReadBounds,
    ) -> Result<
        cerebellum_computer::app_state::source::RawAppState,
        cerebellum_computer::app_state::source::AppStateReadError,
    > {
        self.reads.fetch_add(1, Ordering::SeqCst);
        std::thread::sleep(Duration::from_millis(100));
        Ok(cerebellum_computer::app_state::source::RawAppState {
            roots: Vec::new(),
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        })
    }

    fn text_value(
        &self,
        _: &cerebellum_computer::app_state::source::ElementHandle,
    ) -> Result<Option<String>, cerebellum_computer::app_state::source::ElementActionError> {
        self.text_reads.fetch_add(1, Ordering::SeqCst);
        Ok(Some(String::new()))
    }
}

/// Once the call has been answered, the readback that would confirm typed
/// text stops at its next poll instead of running to its deadline: until it
/// returns, the worker keeps the application marked busy for every call.
#[test]
fn typed_text_readback_stops_once_the_call_is_answered() {
    let source = NeverShowsText {
        reads: AtomicUsize::new(0),
        text_reads: AtomicUsize::new(0),
    };
    let focus = super::keystrokes::TargetFocus {
        handle: Arc::new(cerebellum_computer::app_state::source::FixtureElementToken(
            1,
        )),
        before: Some(String::new()),
    };
    let call = terminal();
    let gate = quarantine::ArbiterGate(Some(call.clone()));
    let stopped = || cerebellum_computer::dispatch::MutationGate::stopped(&gate);
    let stopper = {
        let call = call.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            call.stop(TerminalCause::Cancelled);
        })
    };
    let started = std::time::Instant::now();
    let confirmed = super::keystrokes::await_typed_text(
        &source,
        &focus,
        "hello",
        Duration::from_secs(5),
        &stopped,
    );
    stopper.join().unwrap();
    assert!(!confirmed);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "the readback ran {:?} past an answered call",
        started.elapsed()
    );
}

/// The settle after a `type` or `keys` reads nothing once the call has been
/// answered; with the call still open it reads as before.
#[test]
fn the_keystroke_settle_reads_nothing_once_the_call_is_answered() {
    use super::element_actions::{settle_and_observe_view, PersonWatch};
    use cerebellum_computer::app_state::session::AppStateSessions;
    let target = grant(42, EDITOR);
    for answered in [false, true] {
        let source = NeverShowsText {
            reads: AtomicUsize::new(0),
            text_reads: AtomicUsize::new(0),
        };
        let sessions = AppStateSessions::new();
        let stopped = || answered;
        let started = std::time::Instant::now();
        let settled = settle_and_observe_view(
            &source,
            &sessions,
            "conversation",
            &target,
            Duration::from_secs(3),
            false,
            PersonWatch::StopWhen(&stopped),
            None,
            None,
        );
        let reads = source.reads.load(Ordering::SeqCst);
        if answered {
            assert!(settled.is_none());
            assert_eq!(reads, 0, "an answered call's settle read the app");
            assert!(started.elapsed() < Duration::from_millis(500));
        } else {
            assert!(settled.is_some());
            assert!(reads >= 1);
        }
    }
}

/// An application whose focused element, focused window, frontmost state
/// and hardware-input observer the test sets.
struct FocusDesk {
    focused: AtomicUsize,
    window_title: std::sync::Mutex<String>,
    frontmost: std::sync::Mutex<Option<u32>>,
    hardware: std::sync::Mutex<Result<(std::time::Instant, Option<std::time::Instant>), ()>>,
}

impl FocusDesk {
    fn new(covered_since: std::time::Instant) -> Self {
        Self {
            focused: AtomicUsize::new(1),
            window_title: std::sync::Mutex::new("General".into()),
            frontmost: std::sync::Mutex::new(Some(42)),
            hardware: std::sync::Mutex::new(Ok((covered_since, None))),
        }
    }
}

impl cerebellum_computer::app_state::source::AppStateSource for FocusDesk {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: cerebellum_computer::app_state::source::ReadBounds,
    ) -> Result<
        cerebellum_computer::app_state::source::RawAppState,
        cerebellum_computer::app_state::source::AppStateReadError,
    > {
        Ok(cerebellum_computer::app_state::source::RawAppState {
            roots: Vec::new(),
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        })
    }

    fn focused_element(
        &self,
        _: &ProcessGrant,
    ) -> Result<
        Option<cerebellum_computer::app_state::source::ElementHandle>,
        cerebellum_computer::app_state::source::ElementActionError,
    > {
        Ok(Some(Arc::new(
            cerebellum_computer::app_state::source::FixtureElementToken(
                self.focused.load(Ordering::SeqCst) as u64,
            ),
        )))
    }

    fn element_facts(
        &self,
        _: &cerebellum_computer::app_state::source::ElementHandle,
    ) -> Result<
        cerebellum_computer::app_state::source::ElementFacts,
        cerebellum_computer::app_state::source::ElementActionError,
    > {
        Ok(cerebellum_computer::app_state::source::ElementFacts {
            role: Some("AXTextArea".into()),
            title: Some("Message #general".into()),
            ..Default::default()
        })
    }

    fn focused_window(
        &self,
        _: &ProcessGrant,
    ) -> Result<
        Option<cerebellum_computer::app_state::source::WindowMark>,
        cerebellum_computer::app_state::source::ElementActionError,
    > {
        Ok(Some(cerebellum_computer::app_state::source::WindowMark {
            handle: Arc::new(cerebellum_computer::app_state::source::FixtureElementToken(
                100,
            )),
            title: Some(self.window_title.lock().unwrap().clone()),
        }))
    }

    fn frontmost_pid(&self) -> Option<u32> {
        *self.frontmost.lock().unwrap()
    }

    fn hardware_input(
        &self,
        _: &ProcessGrant,
    ) -> Result<
        (std::time::Instant, Option<std::time::Instant>),
        cerebellum_computer::app_state::source::ElementActionError,
    > {
        (*self.hardware.lock().unwrap()).map_err(|()| {
            cerebellum_computer::app_state::source::ElementActionError::UnsupportedOnPlatform
        })
    }
}

/// The conversation has read the desk; then `change` is applied and the
/// check before the next action is asked.
fn person_check_after(
    change: impl FnOnce(&FocusDesk),
) -> (
    Result<super::element_actions::PersonCheck, ()>,
    cerebellum_computer::app_state::session::AppStateSessions,
    FocusDesk,
) {
    use cerebellum_computer::app_state::person::SeenMarks;
    let target = grant(42, EDITOR);
    let desk = FocusDesk::new(std::time::Instant::now());
    let sessions = cerebellum_computer::app_state::session::AppStateSessions::new();
    sessions.observe(
        "conversation",
        &target,
        &cerebellum_computer::app_state::source::RawAppState {
            roots: Vec::new(),
            focused: None,
            unreadable_subtrees: 0,
            read_bound_reached: false,
        },
    );
    sessions.remember_seen("conversation", &target, SeenMarks::read(&desk, &target));
    change(&desk);
    let checked = super::element_actions::person_check_before_action(
        &desk,
        &sessions,
        "conversation",
        &target,
    );
    (checked, sessions, desk)
}

/// The application moved its own focus (Discord after a server switch) while
/// in front, and the observer saw no input at all: the action goes ahead,
/// says where focus went, and the next check compares against the new focus.
#[test]
fn an_app_only_focus_move_proceeds_with_one_disclosed_line() {
    use super::element_actions::PersonCheck;
    let (checked, sessions, desk) = person_check_after(|desk| {
        desk.focused.store(2, Ordering::SeqCst);
    });
    match checked {
        Ok(PersonCheck::AppMovedFocus(line)) => assert_eq!(
            line,
            "Focus moved to \"Message #general\" on its own since your last read."
        ),
        other => panic!("an app-only focus move refused: {other:?}"),
    }
    let again = super::element_actions::person_check_before_action(
        &desk,
        &sessions,
        "conversation",
        &grant(42, EDITOR),
    );
    assert!(matches!(again, Ok(PersonCheck::Unchanged)), "{again:?}");
}

/// The same focus move refuses when anything weakens the evidence that the
/// person did not cause it: hardware input since the read, a changed window,
/// an observer gap or outage, or a target in the background.
#[test]
fn a_focus_move_refuses_unless_the_app_is_in_front_and_provably_untouched() {
    use super::element_actions::PersonCheck;
    use cerebellum_computer::app_state::person::PersonChange;
    type Weakening = (&'static str, fn(&FocusDesk));
    let cases: [Weakening; 5] = [
        ("a hardware key since the read", |desk| {
            desk.hardware.lock().unwrap().as_mut().unwrap().1 = Some(std::time::Instant::now());
        }),
        ("a window change", |desk| {
            *desk.window_title.lock().unwrap() = "Delete Server?".into();
        }),
        ("an observer that restarted after the read", |desk| {
            desk.hardware.lock().unwrap().as_mut().unwrap().0 = std::time::Instant::now();
        }),
        ("an observer outage", |desk| {
            *desk.hardware.lock().unwrap() = Err(());
        }),
        ("a background target", |desk| {
            *desk.frontmost.lock().unwrap() = Some(7);
        }),
    ];
    for (name, weaken) in cases {
        let (checked, _, _) = person_check_after(|desk| {
            std::thread::sleep(Duration::from_millis(2));
            desk.focused.store(2, Ordering::SeqCst);
            weaken(desk);
        });
        let refused = matches!(
            checked,
            Ok(PersonCheck::Changed(
                PersonChange::FocusChanged | PersonChange::WindowChanged
            ))
        );
        assert!(refused, "{name}: {checked:?}");
    }
}
