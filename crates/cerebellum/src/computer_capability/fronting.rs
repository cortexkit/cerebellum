//! Bringing an application to the front for an action, under the person's
//! `computer_use.app_use` setting.
//!
//! In foreground mode each listed action brings its application to the
//! front, one way, before anything else. In background mode only an action
//! that cannot work in the background brings it forward, for that action
//! alone, and the previous application is put back afterwards. Either kind
//! of front:
//!
//! - takes the process-wide fronting lock first, after the call's app lane,
//!   waiting at most [`crate::budgets::FRONTING_LOCK_WAIT_MS`];
//! - then runs three guards in order: no release of held input from an
//!   earlier call is still unconfirmed, the person has not changed the target
//!   since the agent last read it, and the idle gate with the observer
//!   heartbeat;
//! - and stops at the first that fails, naming why in the reply's
//!   `fronting.not_fronted_reason`.
//!
//! Nothing fronts in an unattended session, or in a build whose release does
//! not carry the app-use review.

use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration, Instant};

use cerebellum_computer::app_state::person::SeenMarks;
use cerebellum_computer::app_state::session::AppStateSessions;
use cerebellum_computer::app_state::source::AppStateSource;
use cerebellum_computer::dispatch::{
    begin_observed_sequence, heartbeat_liveness, not_fronted_reason, AbortReason, BracketOutcome,
    DeferredRestore, FrontingBracketHost, FrontingStop, NotFrontedReason, ObservedPostRefusal,
    ObservedSequenceHooks, ObserverLiveness, RestoreStatus, SeizeWatcher, UserIdleEstimator,
    FRONTING_POLL_MS,
};
use cerebellum_computer::platform::{
    FrontedDispatchHooks, FrontingRestoreHost, HookedRestore, ProcessGrant,
};
use cerebellum_core::config::AppUse;
use serde_json::{json, Value};

use crate::budgets::{FRONTING_LOCK_WAIT_MS, FRONT_WAIT_MS, RESTORE_AX_MS};
use crate::terminal_arbiter::{
    FrontingLockGuard, FrontingMode, FrontingPurpose, RestoreCell, RestoreDecided, RestoreHost,
    RestoreObligation, TerminalArbiter,
};

/// How fast the observer must report input that is not ours while a front is
/// prepared, in milliseconds: the bound the fronted image read uses.
pub(crate) const FRONT_SEIZE_LATENCY_MS: u32 = 50;

/// The fronting lock. One per process in a running module, so no two calls,
/// from any conversation, front applications over each other, and none
/// records another call's temporarily fronted application as the one to put
/// back.
#[derive(Clone)]
pub(crate) struct FrontingLock(Arc<tokio::sync::Mutex<()>>);

static PROCESS_FRONTING_LOCK: LazyLock<FrontingLock> =
    LazyLock::new(|| FrontingLock(Arc::default()));

impl FrontingLock {
    pub(crate) fn process_wide() -> Self {
        PROCESS_FRONTING_LOCK.clone()
    }

    /// A lock no other plane shares.
    #[cfg(test)]
    pub(crate) fn isolated() -> Self {
        Self(Arc::default())
    }

    /// Take the lock, waiting at most `FRONTING_LOCK_WAIT_MS`. A cancel while
    /// waiting stops at once.
    pub(crate) async fn take(
        &self,
        cancel: &crate::CancelHandle,
    ) -> Result<tokio::sync::OwnedMutexGuard<()>, FrontingStop> {
        let wait = tokio::time::timeout(
            Duration::from_millis(FRONTING_LOCK_WAIT_MS),
            Arc::clone(&self.0).lock_owned(),
        );
        tokio::select! {
            biased;
            () = cancel.cancelled() => Err(FrontingStop::Cancelled),
            taken = wait => taken.map_err(|_| FrontingStop::FrontingLockTimedOut),
        }
    }

    /// Whether some call holds the lock now.
    #[cfg(test)]
    pub(crate) fn held(&self) -> bool {
        self.0.try_lock().is_err()
    }
}

/// Guard (0): no press posted by an earlier call is still unconfirmed
/// released. It never posts a release itself; a held key or button would
/// land on whatever application this module brings forward.
pub(crate) fn held_input_confirmed(held: &super::held_input::HeldInput) -> bool {
    matches!(held.pending_release(), Ok(None))
}

/// The reply's `fronting.purpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    ForegroundMode,
    NeedsFront,
    BringToFront,
    None,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundMode => "foreground_mode",
            Self::NeedsFront => "needs_front",
            Self::BringToFront => "bring_to_front",
            Self::None => "none",
        }
    }
}

/// The reply's `fronting.restore`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Restore {
    NotNeeded,
    /// A one-way front: the target stays in front on purpose.
    LeftInFront,
    Restored,
    SkippedPerson,
    Failed,
}

impl Restore {
    pub(crate) fn of(status: RestoreStatus) -> Self {
        match status {
            RestoreStatus::NotNeeded => Self::NotNeeded,
            RestoreStatus::Restored => Self::Restored,
            RestoreStatus::SkippedPerson { .. } => Self::SkippedPerson,
            RestoreStatus::Failed { .. } => Self::Failed,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::NotNeeded => "not_needed",
            Self::LeftInFront => "left_in_front",
            Self::Restored => "restored",
            Self::SkippedPerson => "skipped_person",
            Self::Failed => "failed",
        }
    }
}

/// What one action did with the front of the screen, as its reply's
/// `fronting` object says it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Fronting {
    pub(crate) mode: AppUse,
    pub(crate) fronted: bool,
    pub(crate) purpose: Purpose,
    pub(crate) restore: Restore,
    pub(crate) not_fronted_reason: Option<NotFrontedReason>,
    pub(crate) person_input_during_fronting: bool,
}

impl Fronting {
    /// Nothing was, or needed to be, fronted: background mode with no
    /// needs-front action, or a target that was already frontmost.
    pub(crate) fn untouched(mode: AppUse) -> Self {
        Self {
            mode,
            fronted: false,
            purpose: match mode {
                AppUse::Foreground => Purpose::ForegroundMode,
                AppUse::Background => Purpose::None,
            },
            restore: Restore::NotNeeded,
            not_fronted_reason: None,
            person_input_during_fronting: false,
        }
    }

    /// Fronting for `purpose` stopped with `stop`; nothing was fronted.
    pub(crate) fn stopped(mode: AppUse, purpose: Purpose, stop: FrontingStop) -> Self {
        Self {
            mode,
            fronted: false,
            purpose,
            restore: Restore::NotNeeded,
            not_fronted_reason: Some(not_fronted_reason(stop)),
            person_input_during_fronting: false,
        }
    }

    /// Foreground mode's one-way front brought the target forward.
    pub(crate) fn one_way(mode: AppUse) -> Self {
        Self {
            mode,
            fronted: true,
            purpose: Purpose::ForegroundMode,
            restore: Restore::LeftInFront,
            not_fronted_reason: None,
            person_input_during_fronting: false,
        }
    }

    /// A temporary front for `purpose` that ended with `restore`.
    pub(crate) fn temporary(
        mode: AppUse,
        purpose: Purpose,
        restore: RestoreStatus,
        person_input_during_fronting: bool,
    ) -> Self {
        Self {
            mode,
            fronted: true,
            purpose,
            restore: Restore::of(restore),
            not_fronted_reason: None,
            person_input_during_fronting,
        }
    }

    pub(crate) fn to_value(self) -> Value {
        let mut value = json!({
            "mode": match self.mode {
                AppUse::Foreground => "foreground",
                AppUse::Background => "background",
            },
            "fronted": self.fronted,
            "purpose": self.purpose.as_str(),
            "restore": self.restore.as_str(),
        });
        if let Some(reason) = self.not_fronted_reason {
            value["not_fronted_reason"] = json!(reason.as_str());
        }
        if self.person_input_during_fronting {
            value["person_input_during_fronting"] = json!(true);
        }
        value
    }

    /// Write this as `reply.fronting`.
    pub(crate) fn apply(self, reply: &mut Value) {
        if let Some(object) = reply.as_object_mut() {
            object.insert("fronting".into(), self.to_value());
        }
    }
}

/// The refusal of an action that needed its application in front when
/// fronting stopped: nothing was done.
pub(crate) fn not_fronted_reply(fronting: Fronting) -> Value {
    let reason = fronting
        .not_fronted_reason
        .unwrap_or(NotFrontedReason::FrontFailed);
    let mut reply = json!({
        "outcome": "not_fronted",
        "remedy": format!("Nothing was done: {}.", reason.remedy()),
    });
    fronting.apply(&mut reply);
    reply
}

/// Whether a stop ends the call rather than leaving it to go on unfronted:
/// a cancel, a closed dispatch gate or a terminal reply already chosen. Such
/// a call starts no fallback read, capture or seen-mark update.
pub(crate) fn stop_ends_call(stop: FrontingStop) -> bool {
    not_fronted_reason(stop) == NotFrontedReason::Cancelled
}

/// What decides whether an action may front: the call's mode, whether a
/// person attends the session, and the release reviews this build carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Admission {
    pub(crate) mode: AppUse,
    pub(crate) attended: bool,
    /// The takeover review and the app-use review are both bound.
    pub(crate) app_use_fronting_admitted: bool,
    /// The takeover review is bound: today's keystroke bracket.
    pub(crate) bracket_admitted: bool,
    /// The caller holds the takeover grant.
    pub(crate) takeover_held: bool,
}

impl Admission {
    /// Whether fronting outside today's takeover bracket may happen at all.
    pub(crate) fn may_front(self) -> Result<(), FrontingStop> {
        if !self.attended {
            Err(FrontingStop::Unattended)
        } else if !self.app_use_fronting_admitted {
            Err(FrontingStop::FrontingNotAdmitted)
        } else {
            Ok(())
        }
    }
}

/// Why a modifier chord to a background application is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChordRefusal {
    /// An unattended session never brings an application forward.
    TakeoverNotForFlows,
    /// No takeover grant, and this build cannot front under the app grant.
    ModifierChordNeedsForeground,
    /// Takeover is held, but this build carries no review of the bracket.
    KeystrokesNeedForeground,
}

/// How a keystroke reaches its application.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ChordRoute {
    /// Posted to the process, with no front: plain typing, or a target that
    /// is frontmost.
    PerProcess,
    /// A modifier chord to a background application, fronted for the chord
    /// under the app grant alone.
    FrontWithAppGrant,
    /// Today's takeover bracket, for a build without the app-use review.
    TakeoverBracket,
    Refuse(ChordRefusal),
}

/// The route of one keystroke action. `shortcut` is a chord holding Command,
/// Control or Option, which background applications do not reliably
/// receive.
pub(crate) fn chord_route(admission: Admission, frontmost: bool, shortcut: bool) -> ChordRoute {
    if frontmost || !shortcut {
        ChordRoute::PerProcess
    } else if !admission.attended {
        ChordRoute::Refuse(ChordRefusal::TakeoverNotForFlows)
    } else if admission.app_use_fronting_admitted {
        ChordRoute::FrontWithAppGrant
    } else if !admission.takeover_held {
        ChordRoute::Refuse(ChordRefusal::ModifierChordNeedsForeground)
    } else if !admission.bracket_admitted {
        ChordRoute::Refuse(ChordRefusal::KeystrokesNeedForeground)
    } else {
        ChordRoute::TakeoverBracket
    }
}

/// The image read's `(bring_to_front, takeover)` once the mode is applied.
/// Foreground mode runs no temporary bracket: a read whose one-way front
/// succeeded ignores `bring_to_front`, and one whose front did not happen
/// asks for takeover as background mode would. Background mode keeps today's
/// rule: the bracket runs only under held takeover in an attended session.
pub(crate) fn image_fronting(
    admission: Admission,
    bring_to_front: bool,
    fronted_one_way: bool,
) -> (bool, bool) {
    match admission.mode {
        AppUse::Foreground => (bring_to_front && !fronted_one_way, false),
        AppUse::Background => (
            bring_to_front,
            bring_to_front && admission.attended && admission.takeover_held,
        ),
    }
}

/// A one-way front that went through.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OneWayFront {
    /// The application that was frontmost before.
    pub(crate) previous: u32,
    /// `false` when the target was already frontmost, so nothing was fronted.
    pub(crate) fronted: bool,
}

/// Foreground mode's one-way front, with the fronting lock and guards (0)
/// and (1) already passed: the frontmost read, the idle gate and observer
/// heartbeat, `admit` (cancellation and the dispatch gate), the front request,
/// and a wait of at most `FRONT_WAIT_MS` for the target to come forward. It
/// never restores.
pub(crate) fn front_one_way<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
    target: u32,
    admit: &mut dyn FnMut() -> Option<FrontingStop>,
) -> Result<OneWayFront, FrontingStop> {
    let Some(previous) = host.frontmost_pid() else {
        return Err(FrontingStop::PreviousUnknown);
    };
    if previous == target {
        return Ok(OneWayFront {
            previous,
            fronted: false,
        });
    }
    observe_before_front(host, estimator)?;
    if let Some(stop) = admit() {
        return Err(stop);
    }
    let requested_at = host.now_ms();
    if !host.request_front(target) {
        return Err(FrontingStop::FrontFailed);
    }
    loop {
        if host.frontmost_pid() == Some(target) {
            return Ok(OneWayFront {
                previous,
                fronted: true,
            });
        }
        if host.now_ms().saturating_sub(requested_at) >= FRONT_WAIT_MS {
            return Err(FrontingStop::FrontFailed);
        }
        host.pause_ms(FRONTING_POLL_MS);
    }
}

/// Guard (2): the idle gate, then the observer heartbeat, as the bracket and
/// the needs-front press run them before anything is fronted.
fn observe_before_front<H: FrontingBracketHost>(
    host: &mut H,
    estimator: &mut UserIdleEstimator,
) -> Result<(), FrontingStop> {
    let our_pid = host.our_pid();
    let mut watcher = SeizeWatcher::new(FRONT_SEIZE_LATENCY_MS);
    let host_cell = std::cell::RefCell::new(&mut *host);
    let begun = begin_observed_sequence(
        estimator,
        &mut watcher,
        our_pid,
        Instant::now(),
        ObservedSequenceHooks {
            create_tap: || host_cell.borrow_mut().create_tap(),
            read_idle: || host_cell.borrow_mut().read_idle(),
            drain: |tap: &Option<H::Tap>| match tap {
                Some(tap) => host_cell.borrow_mut().drain(tap),
                None => Vec::new(),
            },
            post_heartbeat: || host_cell.borrow_mut().post_heartbeat(),
        },
    );
    let (tap, probe) = match begun {
        Ok((Some(tap), _user_idle, probe)) => (tap, probe),
        Ok((None, _, _)) => return Err(FrontingStop::ObserverUnavailable),
        Err(refusal) => {
            if matches!(
                refusal,
                ObservedPostRefusal::AlreadyAborted(AbortReason::UserSeizedControl)
            ) {
                estimator.clear_carry();
            }
            return Err(watcher
                .abort_decision()
                .map_or(FrontingStop::ObserverUnavailable, |abort| {
                    FrontingStop::from_abort(abort.reason)
                }));
        }
    };
    let observation = host.observe_heartbeat(&tap, probe, &mut watcher);
    if let Some(abort) = watcher.abort_decision() {
        estimator.clear_carry();
        return Err(FrontingStop::from_abort(abort.reason));
    }
    if heartbeat_liveness(probe, observation) == ObserverLiveness::Blind {
        return Err(FrontingStop::ObserverBlind);
    }
    Ok(())
}

/// Write the target's focus and window, as they are now, into what the
/// conversation was last shown of it, at the moment this module's own front
/// or restore was seen. The focus and window change the front caused is then
/// not taken for the person's, and only hardware input after this instant
/// counts at the next person check. A target the conversation never read
/// keeps having no marks.
pub(crate) fn absorb_own_front(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
) {
    if sessions.last_seen(conversation_key, grant).is_some() {
        sessions.remember_seen(conversation_key, grant, SeenMarks::read(source, grant));
    }
}

/// A platform restore host as the terminal arbiter's [`RestoreHost`].
pub(crate) struct PlatformRestoreHost(pub(crate) Box<dyn FrontingRestoreHost>);

impl RestoreHost for PlatformRestoreHost {
    fn now_ms(&mut self) -> u64 {
        self.0.now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.0.pause_ms(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.0.frontmost_pid()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.0.request_front(pid)
    }
    fn hardware_input_snapshot(
        &mut self,
    ) -> Option<cerebellum_computer::dispatch::HardwareInputSnapshot> {
        self.0.hardware_input_snapshot()
    }
}

/// Run `cell`'s restore decision under its own accessibility budget of
/// `RESTORE_AX_MS`, not the call's remaining work budget: the decision is
/// run on a fresh thread, which carries no outer deadline, so a call whose
/// work deadline already passed still puts the previous application back.
pub(crate) fn decide_with_restore_budget(cell: &RestoreCell) -> RestoreDecided {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                #[cfg(target_os = "macos")]
                let _ax = cerebellum_macos::ax_budget::bound_messages_until(
                    Instant::now() + Duration::from_millis(RESTORE_AX_MS),
                );
                #[cfg(not(target_os = "macos"))]
                let _ = RESTORE_AX_MS;
                cell.decide()
            })
            .join()
            .unwrap_or_else(|_| cell.decide())
    })
}

/// What a temporary front's obligation carries before it is registered.
pub(crate) struct ObligationParts {
    pub(crate) terminal: Arc<TerminalArbiter>,
    pub(crate) lock: Option<FrontingLockGuard>,
    pub(crate) target_name: String,
    pub(crate) mode: FrontingMode,
    pub(crate) purpose: FrontingPurpose,
}

impl ObligationParts {
    /// Register the obligation for a front of `target` over `previous`.
    /// `None` when the call's terminal reply is already chosen; the lock is
    /// then released and nothing may be fronted.
    pub(crate) fn register(
        &mut self,
        previous: u32,
        target: u32,
        host: Box<dyn FrontingRestoreHost>,
    ) -> Option<Arc<RestoreCell>> {
        let lock = self.lock.take()?;
        self.terminal
            .register_restore(RestoreObligation {
                previous_pid: previous,
                target_pid: target,
                target_name: self.target_name.clone(),
                mode: self.mode,
                purpose: self.purpose,
                lock,
                host: Box::new(PlatformRestoreHost(host)),
            })
            .ok()
    }
}

#[derive(Default)]
struct HooksState {
    parts: Option<ObligationParts>,
    cell: Option<Arc<RestoreCell>>,
    refused: bool,
    decided: Option<RestoreDecided>,
    finished: Option<(Option<DeferredRestore>, bool)>,
}

/// The hooks a fronted dispatch or read runs its obligation through, shared
/// between the driver that runs the bracket and the call that reads what
/// happened afterwards.
#[derive(Clone)]
pub(crate) struct CellHooks(Arc<StdMutex<HooksState>>);

/// What the call learns from its hooks once the bracket returned.
pub(crate) struct HookedEnd {
    /// The registered obligation, when one was registered.
    pub(crate) cell: Option<Arc<RestoreCell>>,
    /// Registration was refused because the terminal was already chosen.
    pub(crate) refused: bool,
    /// The decision, when one ran.
    pub(crate) decided: Option<RestoreDecided>,
    /// The bracket's outcome reached the hooks: what it deferred, and
    /// whether hardware input arrived while the target was in front.
    pub(crate) finished: Option<(Option<DeferredRestore>, bool)>,
}

impl CellHooks {
    pub(crate) fn new(parts: ObligationParts) -> Self {
        Self(Arc::new(StdMutex::new(HooksState {
            parts: Some(parts),
            ..HooksState::default()
        })))
    }

    fn state(&self) -> std::sync::MutexGuard<'_, HooksState> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// What the bracket left. Any lock still unregistered is released here.
    pub(crate) fn end(&self) -> HookedEnd {
        let mut state = self.state();
        state.parts.take();
        HookedEnd {
            cell: state.cell.clone(),
            refused: state.refused,
            decided: state.decided,
            finished: state.finished,
        }
    }

    fn cell(&self) -> Option<Arc<RestoreCell>> {
        self.state().cell.clone()
    }
}

impl FrontedDispatchHooks for CellHooks {
    fn register(&mut self, previous: u32, target: u32, host: Box<dyn FrontingRestoreHost>) -> bool {
        let mut state = self.state();
        let Some(parts) = state.parts.as_mut() else {
            return false;
        };
        match parts.register(previous, target, host) {
            Some(cell) => {
                state.cell = Some(cell);
                true
            }
            None => {
                state.refused = true;
                false
            }
        }
    }

    fn begin_front_attempt(&mut self, front_instant_ms: u64) -> bool {
        self.cell()
            .is_some_and(|cell| cell.begin_front_attempt(front_instant_ms))
    }

    fn front_attempt_returned(&mut self) {
        if let Some(cell) = self.cell() {
            cell.front_attempt_returned();
        }
    }

    fn decide_restore(&mut self) -> HookedRestore {
        let Some(cell) = self.cell() else {
            return HookedRestore {
                restore: RestoreStatus::NotNeeded,
                person_input_during_fronting: false,
            };
        };
        let decided = decide_with_restore_budget(&cell);
        self.state().decided = Some(decided);
        HookedRestore {
            restore: decided.restore,
            person_input_during_fronting: decided.person_input_during_fronting,
        }
    }

    fn finished(&mut self, outcome: &BracketOutcome) {
        self.state().finished = Some((
            outcome.deferred_restore,
            outcome.person_input_during_fronting,
        ));
    }
}

/// The trait object the driver is handed.
pub(crate) fn boxed_hooks(hooks: &CellHooks) -> Box<dyn FrontedDispatchHooks> {
    Box::new(hooks.clone())
}

/// What a call asks of foreground mode's one-way front.
pub(crate) struct FrontCall<'a> {
    pub(crate) grant: &'a ProcessGrant,
    pub(crate) consent: &'a crate::computer_grants::ConsentContext,
    pub(crate) cancel: &'a crate::CancelHandle,
    pub(crate) management: &'a crate::management::ManagementPlane,
    pub(crate) conversation_key: &'a str,
}

/// How foreground mode's one-way front ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ForegroundFront {
    pub(crate) fronting: Fronting,
    /// Why it did not front, when it did not.
    pub(crate) stop: Option<FrontingStop>,
    /// The change guard (1) found, when it stopped there.
    pub(crate) change: Option<cerebellum_computer::app_state::person::PersonChange>,
}

impl ForegroundFront {
    fn stopped(stop: FrontingStop) -> Self {
        Self {
            fronting: Fronting::stopped(AppUse::Foreground, Purpose::ForegroundMode, stop),
            stop: Some(stop),
            change: None,
        }
    }

    /// Whether the front was attempted and stopped, as opposed to never
    /// being possible in this session or build. Foreground-mode actions that
    /// cannot front at all go ahead unfronted and say so.
    pub(crate) fn attempted_and_stopped(&self) -> bool {
        matches!(
            self.stop,
            Some(stop) if !matches!(stop, FrontingStop::Unattended | FrontingStop::FrontingNotAdmitted)
        )
    }

    /// The refusal an action other than a read gives when its front stopped,
    /// or `None` when it goes ahead. A change guard (1) found refuses as any
    /// action on a changed application does.
    pub(crate) fn refusal(&self, app_name: &str) -> Option<Value> {
        if !self.attempted_and_stopped() {
            return None;
        }
        let mut reply = match self.change {
            Some(change) => super::element_actions::state_changed_by_person_reply(app_name, change),
            None => return Some(not_fronted_reply(self.fronting)),
        };
        self.fronting.apply(&mut reply);
        Some(reply)
    }
}

impl<B, R, T, S, D> super::ComputerPlane<B, R, T, S, D>
where
    B: super::CaptureBackend + Send + 'static,
    R: super::Redactor + Send + 'static,
    T: super::SeverityTaxonomy + Send + 'static,
    S: super::JournalStorage + Send + 'static,
    D: super::PlatformDriver + 'static,
{
    /// The fronting admission of the call being served.
    pub(super) fn fronting_admission(
        &self,
        consent: &crate::computer_grants::ConsentContext,
        takeover_held: bool,
    ) -> Admission {
        Admission {
            mode: super::app_use::call_mode().unwrap_or(AppUse::Background),
            attended: !consent.unattended,
            app_use_fronting_admitted: self.app_use_fronting_admitted,
            bracket_admitted: self.fronting_bracket_admitted,
            takeover_held,
        }
    }

    /// Foreground mode's one-way front of `call.grant`, made before anything
    /// else the action does, the badge included. `None` in background mode.
    ///
    /// A target already frontmost needs nothing and takes no lock. Otherwise
    /// the fronting lock is taken, the dispatch gate checked, guard (0) and
    /// guard (1) run, and then the idle gate, the front and its wait run in
    /// one blocking hop. The seen marks absorb the front once it is seen.
    pub(super) async fn front_for_foreground(
        &self,
        call: FrontCall<'_>,
    ) -> Option<ForegroundFront> {
        let admission = self.fronting_admission(call.consent, false);
        if admission.mode != AppUse::Foreground {
            return None;
        }
        if let Err(stop) = admission.may_front() {
            return Some(ForegroundFront::stopped(stop));
        }
        if self.app_state_source.frontmost_pid() == Some(call.grant.pid) {
            return Some(ForegroundFront {
                fronting: Fronting::untouched(AppUse::Foreground),
                stop: None,
                change: None,
            });
        }
        let lock = match self.fronting_lock.take(call.cancel).await {
            Ok(lock) => lock,
            Err(stop) => return Some(ForegroundFront::stopped(stop)),
        };
        let work = super::quarantine::CallWork::current();
        // Checked before any guard reads the application: a call whose
        // authorization was lost while it waited reads nothing more.
        if !work.begin_mutation() {
            return Some(ForegroundFront::stopped(FrontingStop::DispatchGateClosed));
        }
        if !held_input_confirmed(&self.held_input) {
            return Some(ForegroundFront::stopped(FrontingStop::HeldInputUnconfirmed));
        }
        let source = self.app_state_source.clone();
        let sessions = call.management.app_state_sessions().clone();
        let conversation_key = call.conversation_key.to_owned();
        let grant = call.grant.clone();
        let make_driver = self.make_synthetic_driver.clone();
        let cancel = call.cancel.clone();
        let fronted = tokio::task::spawn_blocking(move || {
            let _lock = lock;
            let _ax = work.bound_ax();
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(grant.pid, None);
            match super::element_actions::person_change_since_seen(
                source.as_ref(),
                &sessions,
                &conversation_key,
                &grant,
            ) {
                Ok(None) => {}
                Ok(Some(change)) => return Err((FrontingStop::PersonChangedTarget, Some(change))),
                Err(()) => return Err((FrontingStop::PersonCheckUnreadable, None)),
            }
            let mut session = make_driver()
                .fronting_session()
                .map_err(|_| (FrontingStop::FrontingNotAdmitted, None))?;
            let estimator = session.user_idle();
            let mut estimator = estimator
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let front = front_one_way(&mut session, &mut estimator, grant.pid, &mut || {
                if cancel.is_cancelled() {
                    Some(FrontingStop::Cancelled)
                } else if work.stopped() {
                    Some(FrontingStop::DispatchGateClosed)
                } else {
                    None
                }
            })
            .map_err(|stop| (stop, None))?;
            if front.fronted {
                absorb_own_front(source.as_ref(), &sessions, &conversation_key, &grant);
            }
            Ok(front)
        })
        .await
        .unwrap_or(Err((FrontingStop::FrontFailed, None)));
        Some(match fronted {
            Ok(front) if front.fronted => ForegroundFront {
                fronting: Fronting::one_way(AppUse::Foreground),
                stop: None,
                change: None,
            },
            Ok(_) => ForegroundFront {
                fronting: Fronting::untouched(AppUse::Foreground),
                stop: None,
                change: None,
            },
            Err((stop, change)) => ForegroundFront {
                change,
                ..ForegroundFront::stopped(stop)
            },
        })
    }
}

/// Why a temporary front could not be prepared.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PrepareStop {
    pub(crate) stop: FrontingStop,
    /// The change guard (1) found, when it stopped there.
    pub(crate) change: Option<cerebellum_computer::app_state::person::PersonChange>,
}

impl From<FrontingStop> for PrepareStop {
    fn from(stop: FrontingStop) -> Self {
        Self { stop, change: None }
    }
}

impl<B, R, T, S, D> super::ComputerPlane<B, R, T, S, D>
where
    B: super::CaptureBackend + Send + 'static,
    R: super::Redactor + Send + 'static,
    T: super::SeverityTaxonomy + Send + 'static,
    S: super::JournalStorage + Send + 'static,
    D: super::PlatformDriver + 'static,
{
    /// Everything a temporary front needs before the blocking work that
    /// fronts: the fronting lock, guard (0), guard (1), and the call's
    /// terminal arbiter, which owns the restore obligation so that terminal
    /// cleanup can put the previous application back if the worker does not.
    /// A call served without an arbiter cannot hand its restore to anyone,
    /// so it does not front at all.
    ///
    /// With `guards` false, guards (0) and (1) are left to the caller, which
    /// runs them itself under the lock: the needs-front press does, in its
    /// fixed order.
    pub(crate) async fn prepare_temporary_front(
        &self,
        call: FrontCall<'_>,
        purpose: FrontingPurpose,
        guards: bool,
    ) -> Result<ObligationParts, PrepareStop> {
        let work = super::quarantine::CallWork::current();
        let Some(terminal) = work.terminal.clone() else {
            return Err(FrontingStop::FrontingNotAdmitted.into());
        };
        let lock = self.fronting_lock.take(call.cancel).await?;
        if work.stopped() {
            return Err(FrontingStop::DispatchGateClosed.into());
        }
        let parts = ObligationParts {
            terminal,
            lock: Some(Box::new(lock)),
            target_name: call.management.application_name(call.grant),
            mode: match super::app_use::call_mode().unwrap_or(AppUse::Background) {
                AppUse::Foreground => FrontingMode::Foreground,
                AppUse::Background => FrontingMode::Background,
            },
            purpose,
        };
        if !guards {
            return Ok(parts);
        }
        if !held_input_confirmed(&self.held_input) {
            return Err(FrontingStop::HeldInputUnconfirmed.into());
        }
        let source = self.app_state_source.clone();
        let sessions = call.management.app_state_sessions().clone();
        let conversation_key = call.conversation_key.to_owned();
        let grant = call.grant.clone();
        let changed = tokio::task::spawn_blocking(move || {
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(grant.pid, None);
            super::element_actions::person_change_since_seen(
                source.as_ref(),
                &sessions,
                &conversation_key,
                &grant,
            )
        })
        .await
        .unwrap_or(Err(()));
        match changed {
            Ok(None) => {}
            Ok(Some(change)) => {
                return Err(PrepareStop {
                    stop: FrontingStop::PersonChangedTarget,
                    change: Some(change),
                })
            }
            Err(()) => return Err(FrontingStop::PersonCheckUnreadable.into()),
        }
        Ok(parts)
    }
}

/// The reply's `fronting` for a temporary front run through `hooks`, once
/// it ended. `purpose` is what it was for.
pub(crate) fn hooked_fronting(mode: AppUse, purpose: Purpose, end: &HookedEnd) -> Fronting {
    if end.refused {
        return Fronting::stopped(mode, purpose, FrontingStop::TerminalAlreadyChosen);
    }
    match (&end.cell, end.decided) {
        (Some(_), Some(decided)) if decided.front_requested => Fronting::temporary(
            mode,
            purpose,
            decided.restore,
            decided.person_input_during_fronting || end.finished.is_some_and(|(_, input)| input),
        ),
        (Some(_), Some(_)) => Fronting::stopped(mode, purpose, FrontingStop::CleanupTookObligation),
        _ => Fronting {
            purpose,
            ..Fronting::untouched(mode)
        },
    }
}

/// End a chord's hooked bracket once the held input is settled. A bracket
/// whose post failed with a key possibly held deferred its restore: when
/// settling `held` confirmed the release (or nothing was held), the one
/// restore decision runs now and `bracket` reports it. When the release is
/// not confirmed, no restore is requested at all, since the previous
/// application would receive the held key; the bracket keeps reporting the
/// target left in front, and terminal cleanup, finding the release
/// unconfirmed, reports the restore failed without requesting one and
/// releases the fronting lock.
pub(crate) fn finish_after_release(
    hooks: &CellHooks,
    held: Option<crate::HeldState>,
    bracket: Option<&mut cerebellum_computer::dispatch::BracketReport>,
) -> HookedEnd {
    let mut end = hooks.end();
    let deferred = end.finished.is_some_and(|(deferred, _)| deferred.is_some());
    if let (Some(cell), true) = (&end.cell, deferred) {
        let released = matches!(
            held,
            None | Some(crate::HeldState::Released | crate::HeldState::NoneHeld)
        );
        if released {
            let decided = decide_with_restore_budget(cell);
            end.decided = Some(decided);
            if let Some(bracket) = bracket {
                bracket.restore = decided.restore;
            }
        }
    }
    end
}

/// The reply's `fronting` for a chord run through `end`'s hooks: a deferred
/// restore that never ran reports `failed`, as the reply's `restore_failed`
/// does.
pub(crate) fn chord_fronting(mode: AppUse, end: &HookedEnd) -> Fronting {
    let deferred = end.finished.is_some_and(|(deferred, _)| deferred.is_some());
    if end.cell.is_some() && end.decided.is_none() && deferred {
        return Fronting::temporary(
            mode,
            Purpose::NeedsFront,
            RestoreStatus::Failed {
                left_in_front: None,
            },
            end.finished.is_some_and(|(_, input)| input),
        );
    }
    hooked_fronting(mode, Purpose::NeedsFront, end)
}
