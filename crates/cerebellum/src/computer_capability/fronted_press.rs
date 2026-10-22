//! The needs-front press: a press on an element that reads disabled while
//! its application is in the background.
//!
//! Some applications disable window buttons (Mail's Send among them) while
//! they are not frontmost. Such a press brings the application forward for
//! that press and then runs the call's one restore decision, in the fixed
//! order of [`run_fronting_press`]: the pre-read and the badge were already
//! done on the async side, then the fronting lock, the guards, the restore
//! obligation, the front, the enabled poll, the press, the settle and the
//! restore decision.
//!
//! A press that is one step of a batch takes the rest of the batch with it:
//! the application is brought forward once, the later steps are pressed while
//! it stays in front, each without waiting for its badge, and one restore
//! decision follows the last step's settle. A later step whose admission
//! would have to ask the person stops the run there instead of waiting with
//! the application in front.

use super::*;
use crate::computer_capability::fronting::{
    absorb_own_front, decide_with_restore_budget, held_input_confirmed, not_fronted_reply,
    stop_ends_call, target_unchanged_since_seen, FrontCall, Fronting, ObligationParts, PrepareStop,
    Purpose, FRONT_SEIZE_LATENCY_MS,
};
use crate::terminal_arbiter::{FrontingPurpose, RestoreCell, RestoreDecided};
use cerebellum_computer::dispatch::{
    not_fronted_reason, run_fronting_press, FrontingBracketHost, FrontingPressHost, FrontingStop,
    HeartbeatObservation, HeartbeatProbe, PressPlan, PressPreRead, PressRunStop, RestoreClaim,
    RestoreStatus, SeizeWatcher, SourcedInputEvent, UnitPosted,
};
use cerebellum_computer::platform::{FrontingSession, IdleReading, SequencePostFailure};
use cerebellum_core::config::AppUse;

/// One press of a run: the element, by the id the conversation was shown
/// and its handle.
pub(super) struct PressStep {
    pub(super) element_id: String,
    pub(super) handle: ElementHandle,
}

/// What the later steps of a batch need, gathered on the async side, to be
/// pressed while their application is in front.
pub(super) struct LaterSteps {
    steps: Vec<PressStep>,
    /// One badge identity per later step. Captured here because the
    /// task-locals naming the acting agent do not follow work onto the
    /// blocking thread that presses.
    badges: Vec<Option<super::super::cursor::Identity>>,
    /// Schedules each later step's badge as the call's first press did: in
    /// background mode inside the preview, which the badge stays in while
    /// the application is in front for the batch.
    scheduler: super::super::preview_call::Badges,
    /// The runtime the badges' own work is spawned on.
    runtime: tokio::runtime::Handle,
    /// Whether the batch application's grant is held now, so a step can be
    /// admitted without asking the person anything.
    admitted: Box<dyn Fn() -> bool + Send>,
}

/// Gather what pressing `steps` while the application is in front needs.
pub(super) fn later_steps(
    scheduler: &super::super::preview_call::Badges,
    management: &ManagementPlane,
    consent: &ConsentContext,
    grant: &ProcessGrant,
    agent_project_id: &str,
    steps: Vec<PressStep>,
) -> LaterSteps {
    let grants = management.computer_grants().clone();
    let caller = consent.caller.clone();
    let need = management.app_need(
        &grant.bundle_identity,
        grant,
        management.application_name(grant),
    );
    LaterSteps {
        badges: steps
            .iter()
            .map(|_| {
                Some(super::super::cursor::Identity::current(
                    agent_project_id.to_owned(),
                ))
            })
            .collect(),
        steps,
        scheduler: scheduler.clone(),
        runtime: tokio::runtime::Handle::current(),
        admitted: Box::new(move || grants.holds(&caller, &need)),
    }
}

/// How a fronted run ended, for the reply that ends the action: whether the
/// front outlasted its bound, what fronting reports, and the fields a failed
/// restore puts on the reply.
pub(super) struct FrontedEnding {
    fronting: Fronting,
    bound_exceeded: bool,
    restore_failed: Option<serde_json::Map<String, Value>>,
}

impl FrontedEnding {
    pub(super) fn apply(&self, reply: &mut Value) {
        // A press that took effect is returned even when the front outlasted
        // its bound, saying so, rather than refused.
        if self.bound_exceeded && reply["outcome"] == "completed" {
            reply["fronting_bound_exceeded"] = json!(true);
        }
        if let (Some(fields), Some(object)) = (&self.restore_failed, reply.as_object_mut()) {
            for (name, value) in fields {
                object.insert(name.clone(), value.clone());
            }
        }
        self.fronting.apply(reply);
    }
}

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
    /// The batch's later steps, pressed in this run once the application is
    /// in front; `None` for a press alone.
    pub(super) later: Option<LaterSteps>,
}

/// The platform and the call, as the press run sees them from its blocking
/// thread. Step 0 is the press that needed the front; any later steps are a
/// batch's.
struct FrontedPressHost<'a, R, T, S>
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
    steps: &'a [PressStep],
    /// One journal per step, each finished only after the restore decision
    /// so its row records how the front ended.
    journals: Vec<ElementJournal<'a, R, T, S>>,
    held: &'a super::super::held_input::HeldInput,
    cancel: &'a CancelHandle,
    gate: &'a BadgeGate,
    expand_menus: bool,
    later: Option<LaterSteps>,
    parts: Option<ObligationParts>,
    cell: Option<Arc<RestoreCell>>,
    decided: Option<RestoreDecided>,
    change: Option<PersonChange>,
    /// Guard (1) stopped the front because the conversation never read the
    /// application. The run itself only knows the guard did not pass, and
    /// reports `PersonCheckUnreadable`; this says which stop it was.
    never_read: bool,
    press_replies: Vec<Option<Value>>,
    observed: Vec<Option<SessionRead>>,
}

impl<R, T, S> FrontingBracketHost for FrontedPressHost<'_, R, T, S>
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

impl<R, T, S> FrontingPressHost for FrontedPressHost<'_, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    fn pre_read(&mut self, _step: usize) -> PressPreRead {
        // The async side already read the first step disabled with the
        // application in the background, which is why this run exists; the
        // run fronts at that step, so no later step is pre-read.
        PressPreRead {
            enabled: Some(false),
            frontmost: None,
        }
    }
    fn hold_for_badge(&mut self, step: usize, _wait_for_arrival: bool) -> bool {
        if step == 0 {
            // Held on the async side, with its own person check, before the
            // lock.
            return true;
        }
        // A later step's badge glides while the step goes ahead; nothing
        // waits for it with the application in front.
        if let Some(later) = self.later.as_mut() {
            if let Some(badge) = later.badges.get_mut(step - 1).and_then(Option::take) {
                let _runtime = later.runtime.enter();
                let _ = later.scheduler.schedule(
                    badge,
                    cerebellum_computer::cursor::CursorKind::Press,
                    self.grant.clone(),
                    super::super::cursor::ReadAim {
                        preferred: Some(self.steps[step].handle.clone()),
                        focused: None,
                    },
                    None,
                    super::super::cursor::WindowChoice::Element,
                );
            }
        }
        // The person check every press makes before it is sent. The marks
        // it compares against were taken when the previous step settled.
        match person_change_since_seen(
            self.source,
            self.sessions,
            self.conversation_key,
            self.grant,
        ) {
            Ok(None) => true,
            Ok(Some(change)) => {
                self.change = Some(change);
                false
            }
            Err(()) => false,
        }
    }
    fn take_fronting_lock(&mut self, _wait_ms: u64) -> bool {
        // Taken on the async side, after the call's app lane.
        self.parts.is_some()
    }
    fn held_input_confirmed(&mut self) -> bool {
        held_input_confirmed(self.held)
    }
    fn person_changed_target(&mut self) -> Option<bool> {
        // The press is input to the application once it is in front, so the
        // front needs what the conversation was shown of it to check the
        // person against.
        match target_unchanged_since_seen(
            self.source,
            self.sessions,
            self.conversation_key,
            self.grant,
            true,
        ) {
            Ok(()) => Some(false),
            Err(PrepareStop {
                change: Some(change),
                ..
            }) => {
                self.change = Some(change);
                Some(true)
            }
            Err(stopped) => {
                self.never_read = stopped.stop == FrontingStop::TargetNotRead;
                None
            }
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
        // Every step of a batch is in the application whose lane the call
        // holds, so only the grant could make a step wait: admitted when it
        // is held now, and otherwise the run stops rather than ask the
        // person with the application in front.
        self.later.as_ref().is_some_and(|later| (later.admitted)())
    }
    fn element_enabled(&mut self, step: usize) -> Option<bool> {
        self.source.element_enabled(&self.steps[step].handle)
    }
    fn press(&mut self, step: usize) -> bool {
        let pressed = &self.steps[step];
        let mut reply = press_blocking(
            self.source,
            &mut self.journals[step],
            self.grant,
            &pressed.element_id,
            &pressed.handle,
        );
        if self.gate.refused_for_end() {
            reply = cancelled_before_dispatch_reply();
        }
        let done = reply["outcome"] == "completed";
        self.press_replies[step] = Some(reply);
        done
    }
    fn settle(&mut self, step: usize, bound_ms: u64) {
        self.observed[step] = settle_and_observe_view(
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

/// The refusal of a batch step that would have had to ask the person while
/// the application was in front.
fn step_needs_wait_reply() -> Value {
    json!({
        "outcome": "consent_unavailable",
        "remedy": "this step would have had to ask the person while the application was in \
                   front, so it was not pressed and the batch stopped here; the previous \
                   application was put back. Press the remaining elements in a new call",
    })
}

/// The fields that replace a press reply's when the previous application
/// could not be put back. Only fields the press rows declare are written:
/// the outcome, a remedy naming what was left in front, and the bundle
/// identity when that is the target.
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
    /// the background, bringing the application forward for the press and,
    /// in a batch, for the batch's later steps.
    pub(super) async fn press_fronted(&self, press: FrontedPress<'_>) -> PressDone {
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
            later,
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
                    input_follows: true,
                },
                FrontingPurpose::NeedsFront,
                false,
            )
            .await;
        let audit = self.audit.clone();
        let parts = match parts {
            Ok(parts) => Some(parts),
            Err(prepared) => {
                if prepared.stop != FrontingStop::FrontingNotAdmitted {
                    let fronting = Fronting::stopped(mode, Purpose::NeedsFront, prepared.stop);
                    return PressDone::alone(if stop_ends_call(prepared.stop) {
                        let mut reply = cancelled_before_dispatch_reply();
                        fronting.apply(&mut reply);
                        reply
                    } else {
                        not_fronted_reply(fronting)
                    });
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
            let mut later = later;
            let mut steps = vec![PressStep { element_id, handle }];
            if let Some(later) = later.as_mut() {
                steps.append(&mut later.steps);
            }
            let mut journals: Vec<_> = steps
                .iter()
                .map(|_| {
                    let mut journal = ElementJournal::new(
                        AuditToken::new(audit.clone(), gate.clone()),
                        identity.clone(),
                        capability,
                        &grant,
                    );
                    journal.hold_refusals();
                    journal
                })
                .collect();
            let session = parts
                .as_ref()
                .and_then(|_| make_driver().fronting_session().ok());
            let (Some(parts), Some(session)) = (parts, session) else {
                let journal = &mut journals[0];
                if let Some(record) = Fronting::untouched(mode).row_record() {
                    journal.set_fronting(record);
                }
                let reply = refuse_disabled(
                    source.as_ref(),
                    journal,
                    &steps[0].element_id,
                    &steps[0].handle,
                );
                let _ = journal.finish();
                return PressDone::alone(reply);
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
                steps: &steps,
                journals,
                held: &held,
                cancel: &cancel,
                gate: &gate,
                expand_menus,
                later,
                parts: Some(parts),
                cell: None,
                decided: None,
                change: None,
                never_read: false,
                press_replies: steps.iter().map(|_| None).collect(),
                observed: steps.iter().map(|_| None).collect(),
            };
            let mut report = run_fronting_press(
                &mut host,
                &mut estimator,
                PressPlan {
                    target_pid: grant.pid,
                    steps: steps.len(),
                    settle_bound_ms: u64::try_from(settle.as_millis()).unwrap_or(u64::MAX),
                    maximum_seize_detection_latency_ms: FRONT_SEIZE_LATENCY_MS,
                },
            );
            drop(estimator);
            let FrontedPressHost {
                mut journals,
                decided,
                change,
                never_read,
                press_replies,
                mut observed,
                ..
            } = host;
            if never_read
                && report.stop
                    == Some(PressRunStop::NotFronted(
                        FrontingStop::PersonCheckUnreadable,
                    ))
            {
                report.stop = Some(PressRunStop::NotFronted(FrontingStop::TargetNotRead));
            }
            let mut fronting = match decided {
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
            if let Some(PressRunStop::Interrupted(stop) | PressRunStop::NotFronted(stop)) =
                report.stop
            {
                if !fronting.fronted {
                    fronting = Fronting::stopped(mode, Purpose::NeedsFront, stop);
                } else {
                    fronting.not_fronted_reason = Some(not_fronted_reason(stop));
                }
            }
            // Every step up to the one the run stopped at was attempted; each
            // gets its own reply, the batch's steps in order.
            let attempted = report.stopped_at.map_or(steps.len(), |step| step + 1);
            let default_view = super::super::StateView::default();
            let mut replies = Vec::with_capacity(attempted);
            for (step, pressed) in press_replies.into_iter().enumerate().take(attempted) {
                let step_view = if step == 0 { &view } else { &default_view };
                let stop = report.stop.filter(|_| report.stopped_at == Some(step));
                let reply = match stop {
                    None | Some(PressRunStop::PressFailed) => {
                        let mut reply = pressed.unwrap_or_else(|| audit_unavailable_reply(false));
                        if reply["outcome"] == "completed" {
                            add_diff_view(&mut reply, observed[step].take().as_ref(), step_view);
                        }
                        reply
                    }
                    Some(PressRunStop::StepNeedsWait) => step_needs_wait_reply(),
                    Some(PressRunStop::ElementDisabled) => refuse_disabled(
                        source.as_ref(),
                        &mut journals[step],
                        &steps[step].element_id,
                        &steps[step].handle,
                    ),
                    Some(
                        PressRunStop::NotFronted(FrontingStop::PersonChangedTarget)
                        | PressRunStop::Interrupted(FrontingStop::PersonChangedTarget),
                    ) if change.is_some() => {
                        state_changed_by_person_reply(&app_name, change.expect("checked above"))
                    }
                    Some(PressRunStop::NotFronted(stop) | PressRunStop::Interrupted(stop))
                        if stop_ends_call(stop) =>
                    {
                        cancelled_before_dispatch_reply()
                    }
                    // In front or not, nothing was pressed at this step, and
                    // the reply says why the front was not used.
                    Some(PressRunStop::NotFronted(_) | PressRunStop::Interrupted(_)) => {
                        not_fronted_reply(fronting)
                    }
                };
                replies.push(reply);
            }
            // The rows are written now that the restore decision is made, so
            // each records how the front ended.
            let mut journaled = true;
            for journal in &mut journals {
                journal.set_fronting(fronting.record());
                journaled &= journal.finish().is_ok();
            }
            if !journaled {
                if let Some(last) = replies.last_mut() {
                    *last = audit_unavailable_reply(report.steps_pressed > 0);
                }
            }
            let mut restore_failed = json!({});
            if let Some(decided) = decided {
                disclose_failed_press_restore(
                    &mut restore_failed,
                    decided.restore,
                    &grant,
                    &app_name,
                );
            }
            let mut replies = replies.into_iter();
            PressDone {
                reply: replies
                    .next()
                    .unwrap_or_else(|| audit_unavailable_reply(false)),
                later: replies.collect(),
                ending: Some(FrontedEnding {
                    fronting,
                    bound_exceeded: report.fronting_bound_exceeded,
                    restore_failed: restore_failed
                        .as_object()
                        .filter(|fields| !fields.is_empty())
                        .cloned(),
                }),
            }
        })
        .await
        .unwrap_or_else(|_| PressDone::alone(audit_unavailable_reply(true)))
    }
}
