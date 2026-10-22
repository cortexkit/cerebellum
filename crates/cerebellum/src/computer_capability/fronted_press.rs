//! The needs-front press: a press on an element that reads disabled while
//! its application is in the background.
//!
//! Some applications disable window buttons (Mail's Send among them) while
//! they are not frontmost. Such a press brings the application forward for
//! that press alone and then runs the call's one restore decision, in the
//! fixed order of [`run_fronting_press`]: the pre-read and the badge were
//! already done on the async side, then the fronting lock, the guards, the
//! restore obligation, the front, the enabled poll, the press, the settle and
//! the restore decision.

use super::*;
use crate::computer_capability::fronting::{
    absorb_own_front, decide_with_restore_budget, held_input_confirmed, not_fronted_reply,
    stop_ends_call, FrontCall, Fronting, ObligationParts, Purpose, FRONT_SEIZE_LATENCY_MS,
};
use crate::terminal_arbiter::{FrontingPurpose, RestoreCell, RestoreDecided};
use cerebellum_computer::dispatch::{
    not_fronted_reason, run_fronting_press, FrontingBracketHost, FrontingPressHost, FrontingStop,
    HeartbeatObservation, HeartbeatProbe, PressPlan, PressPreRead, PressRunStop, RestoreClaim,
    RestoreStatus, SeizeWatcher, SourcedInputEvent, UnitPosted,
};
use cerebellum_computer::platform::{FrontingSession, IdleReading, SequencePostFailure};
use cerebellum_core::config::AppUse;

/// What [`ComputerPlane::press_fronted`] presses, and for whom.
pub(super) struct FrontedPress<'a> {
    pub(super) identity: JournalIdentity,
    pub(super) management: &'a ManagementPlane,
    pub(super) consent: &'a ConsentContext,
    pub(super) cancel: &'a CancelHandle,
    pub(super) sessions: Arc<AppStateSessions>,
    pub(super) capability: ComputerCapability,
    pub(super) grant: ProcessGrant,
    pub(super) element_id: String,
    pub(super) handle: ElementHandle,
    /// What the hit test of a point press read, carried to the press's row.
    pub(super) reads: Option<&'static str>,
    pub(super) gate: Arc<BadgeGate>,
    pub(super) work: super::super::quarantine::CallWork,
    pub(super) settle: Duration,
    pub(super) view: super::super::StateView,
}

/// The platform and the call, as the press run sees them from its blocking
/// thread.
struct FrontedPressHost<'a, 'j, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    session: Box<dyn FrontingSession>,
    source: &'a dyn AppStateSource,
    sessions: &'a AppStateSessions,
    conversation_key: &'a str,
    grant: &'a ProcessGrant,
    element_id: &'a str,
    handle: &'a ElementHandle,
    journal: &'a mut ElementJournal<'j, R, T, S>,
    held: &'a super::super::held_input::HeldInput,
    cancel: &'a CancelHandle,
    gate: &'a BadgeGate,
    expand_menus: bool,
    parts: Option<ObligationParts>,
    cell: Option<Arc<RestoreCell>>,
    decided: Option<RestoreDecided>,
    change: Option<PersonChange>,
    press_reply: Option<Value>,
    observed: Option<SessionRead>,
}

impl<R, T, S> FrontingBracketHost for FrontedPressHost<'_, '_, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    type Tap = ();

    fn now_ms(&mut self) -> u64 {
        self.session.as_mut().now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.session.as_mut().pause_ms(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.session.as_mut().frontmost_pid()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.session.as_mut().request_front(pid)
    }
    fn our_pid(&self) -> i64 {
        self.session.as_ref().our_pid()
    }
    fn create_tap(&mut self) -> Option<()> {
        self.session.as_mut().open_observer().then_some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        self.session.as_mut().read_idle()
    }
    fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
        self.session.as_mut().drain()
    }
    fn post_heartbeat(&mut self) -> HeartbeatProbe {
        self.session.as_mut().post_heartbeat()
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        probe: HeartbeatProbe,
        watcher: &mut SeizeWatcher,
    ) -> HeartbeatObservation {
        self.session.as_mut().observe_heartbeat(probe, watcher)
    }
    fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
        // A press posts no input; the run never asks for a unit.
        Ok(UnitPosted::default())
    }
    fn hardware_input_snapshot(
        &mut self,
    ) -> Option<cerebellum_computer::dispatch::HardwareInputSnapshot> {
        self.session.as_mut().hardware_input_snapshot()
    }
}

impl<R, T, S> FrontingPressHost for FrontedPressHost<'_, '_, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    fn pre_read(&mut self, _step: usize) -> PressPreRead {
        // The async side already read it disabled with the application in
        // the background, which is why this run exists.
        PressPreRead {
            enabled: Some(false),
            frontmost: None,
        }
    }
    fn hold_for_badge(&mut self, _step: usize, _wait_for_arrival: bool) -> bool {
        // Held on the async side, with its own person check, before the lock.
        true
    }
    fn take_fronting_lock(&mut self, _wait_ms: u64) -> bool {
        // Taken on the async side, after the call's app lane.
        self.parts.is_some()
    }
    fn held_input_confirmed(&mut self) -> bool {
        held_input_confirmed(self.held)
    }
    fn person_changed_target(&mut self) -> Option<bool> {
        match person_change_since_seen(
            self.source,
            self.sessions,
            self.conversation_key,
            self.grant,
        ) {
            Ok(None) => Some(false),
            Ok(Some(change)) => {
                self.change = Some(change);
                Some(true)
            }
            Err(()) => None,
        }
    }
    fn cancelled(&mut self) -> bool {
        self.cancel.is_cancelled()
    }
    fn dispatch_gate_open(&mut self) -> bool {
        self.gate.begin_mutation()
    }
    fn register_restore_obligation(&mut self, previous: u32, target: u32) -> bool {
        let host = self.session.as_ref().restore_host();
        let Some(parts) = self.parts.as_mut() else {
            return false;
        };
        match parts.register(previous, target, host) {
            Some(cell) => {
                self.cell = Some(cell);
                true
            }
            None => false,
        }
    }
    fn begin_front_attempt(&mut self, front_instant_ms: u64) -> bool {
        self.cell
            .as_ref()
            .is_some_and(|cell| cell.begin_front_attempt(front_instant_ms))
    }
    fn front_attempt_returned(&mut self) {
        if let Some(cell) = &self.cell {
            cell.front_attempt_returned();
        }
        if self.session.as_mut().frontmost_pid() == Some(self.grant.pid) {
            absorb_own_front(
                self.source,
                self.sessions,
                self.conversation_key,
                self.grant,
            );
        }
    }
    fn admit_fronted_step(&mut self, _step: usize) -> bool {
        // One press per run: a later step never waits while the target is in
        // front, because there is none.
        false
    }
    fn element_enabled(&mut self, _step: usize) -> Option<bool> {
        self.source.element_enabled(self.handle)
    }
    fn press(&mut self, _step: usize) -> bool {
        let mut reply = press_blocking(
            self.source,
            self.journal,
            self.grant,
            self.element_id,
            self.handle,
        );
        if self.gate.refused_for_end() {
            reply = cancelled_before_dispatch_reply();
        }
        let pressed = reply["outcome"] == "completed";
        self.press_reply = Some(reply);
        pressed
    }
    fn settle(&mut self, _step: usize, bound_ms: u64) {
        self.observed = settle_and_observe_view(
            self.source,
            self.sessions,
            self.conversation_key,
            self.grant,
            Duration::from_millis(bound_ms),
            self.expand_menus,
        );
    }
    fn claim_restore(&mut self) -> RestoreClaim {
        let Some(cell) = self.cell.clone() else {
            return RestoreClaim::TakenByCleanup(RestoreStatus::NotNeeded);
        };
        // The call's one decision, which terminal cleanup may already have
        // made; either way this run reports it.
        let decided = decide_with_restore_budget(&cell);
        self.decided = Some(decided);
        if decided.restore == RestoreStatus::Restored {
            absorb_own_front(
                self.source,
                self.sessions,
                self.conversation_key,
                self.grant,
            );
        }
        RestoreClaim::TakenByCleanup(decided.restore)
    }
    fn finish_fronting(&mut self, _restore: RestoreStatus) {
        // Releases a lock that never reached a registered obligation.
        self.parts.take();
    }
}

/// Journal the press's one `element_disabled` refusal and answer it.
fn refuse_disabled<R, T, S>(
    source: &dyn AppStateSource,
    journal: &mut ElementJournal<'_, R, T, S>,
    element_id: &str,
    handle: &ElementHandle,
) -> Value
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    let facts = source.element_facts(handle).ok();
    let role = journal_role(facts.as_ref());
    if journal.refused(&role, "element_disabled").is_err() {
        return audit_unavailable_reply(false);
    }
    element_disabled_reply(
        facts.as_ref().and_then(|facts| facts.title.as_deref()),
        element_id,
        true,
    )
}

/// Replace a press reply with `restore_failed` when the previous application
/// could not be put back. Only fields the press rows declare are written: the
/// outcome, a remedy naming what was left in front, and the bundle identity
/// when that is the target.
fn disclose_failed_press_restore(
    reply: &mut Value,
    restore: RestoreStatus,
    grant: &ProcessGrant,
    app_name: &str,
) {
    let RestoreStatus::Failed { left_in_front } = restore else {
        return;
    };
    let left = match left_in_front {
        Some(pid) if pid == grant.pid => {
            reply["bundle_identity"] = json!(grant.bundle_identity);
            app_name.to_owned()
        }
        Some(pid) => format!("the application with pid {pid}"),
        None => "an application that could not be identified".to_owned(),
    };
    reply["outcome"] = json!("restore_failed");
    reply["remedy"] = json!(format!(
        "{left} was left in front and the application that was in front before could not be \
         put back; tell the person before anything else"
    ));
}

impl<B, R, T, S, D> crate::computer_capability::ComputerPlane<B, R, T, S, D>
where
    B: cerebellum_computer::capture::CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: cerebellum_computer::platform::PlatformDriver + 'static,
{
    /// Press an element that reads disabled while its application is in
    /// the background, bringing the application forward for the press.
    pub(super) async fn press_fronted(&self, press: FrontedPress<'_>) -> Value {
        let FrontedPress {
            identity,
            management,
            consent,
            cancel,
            sessions,
            capability,
            grant,
            element_id,
            handle,
            reads,
            gate,
            work,
            settle,
            view,
        } = press;
        let mode = super::super::app_use::call_mode().unwrap_or(AppUse::Background);
        let app_name = management.application_name(&grant);
        let source = self.app_state_source.clone();
        let parts = self
            .prepare_temporary_front(
                FrontCall {
                    grant: &grant,
                    consent,
                    cancel,
                    management,
                    conversation_key: &identity.conversation_key,
                },
                FrontingPurpose::NeedsFront,
                false,
            )
            .await;
        let audit = AuditToken::new(self.audit.clone(), gate.clone());
        let parts = match parts {
            Ok(parts) => Some(parts),
            Err(prepared) => {
                if prepared.stop != FrontingStop::FrontingNotAdmitted {
                    let fronting = Fronting::stopped(mode, Purpose::NeedsFront, prepared.stop);
                    return if stop_ends_call(prepared.stop) {
                        let mut reply = cancelled_before_dispatch_reply();
                        fronting.apply(&mut reply);
                        reply
                    } else {
                        not_fronted_reply(fronting)
                    };
                }
                // Nothing can own the restore, so the press is refused as in
                // a build that cannot front.
                None
            }
        };
        let make_driver = self.make_synthetic_driver.clone();
        let held = self.held_input.clone();
        let cancel = cancel.clone();
        let conversation_key = identity.conversation_key.clone();
        tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = AccessibilityReadScope::new(grant.pid, reads);
            let mut journal = ElementJournal::new(audit, identity, capability, &grant);
            let session = parts
                .as_ref()
                .and_then(|_| make_driver().fronting_session().ok());
            let (Some(parts), Some(session)) = (parts, session) else {
                let reply = refuse_disabled(source.as_ref(), &mut journal, &element_id, &handle);
                let _ = journal.finish();
                return reply;
            };
            let estimator = session.user_idle();
            let mut estimator = estimator
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let expand_menus =
                sessions.zoom_expands_menus(&conversation_key, &grant, view.zoom.as_deref());
            let mut host = FrontedPressHost {
                session,
                source: source.as_ref(),
                sessions: &sessions,
                conversation_key: &conversation_key,
                grant: &grant,
                element_id: &element_id,
                handle: &handle,
                journal: &mut journal,
                held: &held,
                cancel: &cancel,
                gate: &gate,
                expand_menus,
                parts: Some(parts),
                cell: None,
                decided: None,
                change: None,
                press_reply: None,
                observed: None,
            };
            let report = run_fronting_press(
                &mut host,
                &mut estimator,
                PressPlan {
                    target_pid: grant.pid,
                    steps: 1,
                    settle_bound_ms: u64::try_from(settle.as_millis()).unwrap_or(u64::MAX),
                    maximum_seize_detection_latency_ms: FRONT_SEIZE_LATENCY_MS,
                },
            );
            drop(estimator);
            let FrontedPressHost {
                decided,
                change,
                press_reply,
                observed,
                ..
            } = host;
            let fronting = match decided {
                Some(decided) if decided.front_requested => Fronting::temporary(
                    mode,
                    Purpose::NeedsFront,
                    decided.restore,
                    decided.person_input_during_fronting,
                ),
                Some(_) => Fronting::stopped(
                    mode,
                    Purpose::NeedsFront,
                    FrontingStop::CleanupTookObligation,
                ),
                None => Fronting {
                    purpose: Purpose::NeedsFront,
                    ..Fronting::untouched(mode)
                },
            };
            let mut reply = match report.stop {
                None | Some(PressRunStop::PressFailed) | Some(PressRunStop::StepNeedsWait) => {
                    let mut reply = press_reply.unwrap_or_else(|| audit_unavailable_reply(false));
                    if reply["outcome"] == "completed" {
                        add_diff_view(&mut reply, observed.as_ref(), &view);
                        if report.fronting_bound_exceeded {
                            reply["fronting_bound_exceeded"] = json!(true);
                        }
                    }
                    reply
                }
                Some(PressRunStop::ElementDisabled) => {
                    refuse_disabled(source.as_ref(), &mut journal, &element_id, &handle)
                }
                Some(PressRunStop::NotFronted(FrontingStop::PersonChangedTarget)) => match change {
                    Some(change) => state_changed_by_person_reply(&app_name, change),
                    None => not_fronted_reply(Fronting::stopped(
                        mode,
                        Purpose::NeedsFront,
                        FrontingStop::PersonChangedTarget,
                    )),
                },
                Some(PressRunStop::NotFronted(stop) | PressRunStop::Interrupted(stop))
                    if stop_ends_call(stop) =>
                {
                    cancelled_before_dispatch_reply()
                }
                Some(PressRunStop::NotFronted(stop)) => {
                    not_fronted_reply(Fronting::stopped(mode, Purpose::NeedsFront, stop))
                }
                Some(PressRunStop::Interrupted(stop)) => {
                    // In front, then stopped before the press: nothing was
                    // pressed, and the reply says why the front was not used.
                    not_fronted_reply(Fronting {
                        not_fronted_reason: Some(not_fronted_reason(stop)),
                        ..fronting
                    })
                }
            };
            if journal.finish().is_err() {
                return audit_unavailable_reply(report.steps_pressed > 0);
            }
            let mut fronting = fronting;
            if let Some(PressRunStop::Interrupted(stop) | PressRunStop::NotFronted(stop)) =
                report.stop
            {
                if !fronting.fronted {
                    fronting = Fronting::stopped(mode, Purpose::NeedsFront, stop);
                } else {
                    fronting.not_fronted_reason = Some(not_fronted_reason(stop));
                }
            }
            if let Some(decided) = decided {
                disclose_failed_press_restore(&mut reply, decided.restore, &grant, &app_name);
            }
            fronting.apply(&mut reply);
            reply
        })
        .await
        .unwrap_or_else(|_| audit_unavailable_reply(true))
    }
}
