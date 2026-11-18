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
//! Nothing fronts in an unattended session. Outside app-use admission, only
//! image and chord brackets authorized by held takeover and the
//! `takeover-dispatch` review may front.

use std::sync::{Arc, LazyLock, Mutex as StdMutex};
use std::time::{Duration, Instant};

use cerebellum_computer::app_state::person::SeenMarks;
use cerebellum_computer::app_state::session::AppStateSessions;
use cerebellum_computer::app_state::source::AppStateSource;
use cerebellum_computer::audit::{
    FrontingRecord, FrontingRecordMode, FrontingRecordPurpose, FrontingRecordRestore,
};
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
    pub(crate) fn domain(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
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

/// Guard (0): no press posted by an earlier call has a release that is
/// still unconfirmed, and no send posted to the session as a whole is still
/// in flight in any call. It never posts a release itself; a held key or button
/// would land on whatever application this module brings forward.
///
/// A send in flight to one process keeps its keys in that process, so it
/// does not stop a front. A session-wide send, such as a takeover drag
/// holding the mouse button, goes to whatever is under the pointer or in
/// front. Takeover drags also hold the fronting lock from registration to
/// discharge, so a drag cannot start between this check and the front request.
/// This snapshot also catches quarantined per-process input.
pub(crate) fn held_input_confirmed(held: &super::held_input::HeldInput) -> bool {
    !held.global_send_outstanding() && matches!(held.pending_release(), Ok(None))
}

/// The reply's `fronting.purpose`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    ForegroundMode,
    NeedsFront,
    None,
}

impl Purpose {
    fn as_str(self) -> &'static str {
        match self {
            Self::ForegroundMode => "foreground_mode",
            Self::NeedsFront => "needs_front",
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
        *reply = cerebellum_computer::audit::FinalFrontingResult::new(reply.take()).into_value();
    }

    /// Whether this says nothing beyond "background mode, nothing to do":
    /// no front was made, attempted or refused. Such a call's reply and row
    /// stay exactly as they were before fronting existed, since they are
    /// most calls' replies and rows.
    pub(crate) fn is_untouched_background(self) -> bool {
        self == Self::untouched(AppUse::Background)
    }

    /// The record the action's row carries: `None` for an untouched
    /// background call, whose row stays as it was.
    pub(crate) fn row_record(self) -> Option<FrontingRecord> {
        (!self.is_untouched_background()).then(|| self.record())
    }

    /// The journal's text-free form of this, as the action's row records it.
    /// No preview is drawn for an action yet, so the frame count is zero.
    pub(crate) fn record(self) -> FrontingRecord {
        FrontingRecord {
            mode: match self.mode {
                AppUse::Foreground => FrontingRecordMode::Foreground,
                AppUse::Background => FrontingRecordMode::Background,
            },
            fronted: self.fronted,
            purpose: match self.purpose {
                Purpose::ForegroundMode => FrontingRecordPurpose::ForegroundMode,
                Purpose::NeedsFront => FrontingRecordPurpose::NeedsFront,
                Purpose::None => FrontingRecordPurpose::None,
            },
            restore: match self.restore {
                Restore::NotNeeded => FrontingRecordRestore::NotNeeded,
                Restore::LeftInFront => FrontingRecordRestore::LeftInFront,
                Restore::Restored => FrontingRecordRestore::Restored,
                Restore::SkippedPerson => FrontingRecordRestore::SkippedPerson,
                Restore::Failed => FrontingRecordRestore::Failed,
            },
            not_fronted_reason: self.not_fronted_reason,
            person_input_during_fronting: self.person_input_during_fronting,
            preview_frames: 0,
        }
    }
}

/// A foreground one-way front this call made whose action has not yet
/// written a journal row of its own.
#[derive(Clone)]
pub(crate) struct PendingFrontRow {
    pub(crate) grant: ProcessGrant,
    pub(crate) fronting: Fronting,
}

/// What the code serving a call learns of the call's one-way front once the
/// action returned.
#[derive(Default)]
pub(crate) struct CallFrontEnd {
    /// The one-way front the call made, if it made one. A reply that ended
    /// without saying how it used the front reports this.
    pub(crate) fronting: Option<Fronting>,
    /// That front, when no row of the action recorded it.
    pub(crate) unrecorded: Option<PendingFrontRow>,
}

type CallFront = Arc<StdMutex<CallFrontEnd>>;

tokio::task_local! {
    static CALL_FRONT: CallFront;
}

/// Run `action` while recording any one-way front it makes, returned with
/// its reply so the caller can report and journal that front.
pub(crate) async fn tracking_call_front<F: std::future::Future>(
    action: F,
) -> (F::Output, CallFrontEnd) {
    let cell = CallFront::default();
    let output = CALL_FRONT.scope(Arc::clone(&cell), action).await;
    let end = std::mem::take(
        &mut *cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner),
    );
    (output, end)
}

/// Remember that this call brought `grant` to the front one way. Until the
/// action writes a row of its own, the front is journaled by the code that
/// serves the call, so a front followed by an early refusal is never
/// unrecorded. Outside a tracked call this does nothing.
fn note_one_way_front(grant: &ProcessGrant, fronting: Fronting) {
    let _ = CALL_FRONT.try_with(|cell| {
        let mut end = cell
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        end.fronting = Some(fronting);
        end.unrecorded = Some(PendingFrontRow {
            grant: grant.clone(),
            fronting,
        });
    });
}

/// The action is about to write its own row, which records the front, so
/// the call need not journal it separately. Call it on the async side, before
/// the blocking work that writes the row.
pub(crate) fn action_row_started() {
    let _ = CALL_FRONT.try_with(|cell| {
        cell.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .unrecorded
            .take();
    });
}

/// The rejected row for a front no row of the action recorded: outcome
/// `fronted`, the front's record and the grant, and nothing else.
pub(crate) fn fronted_row_material(pending: &PendingFrontRow) -> Vec<u8> {
    json!({
        "outcome": "fronted",
        "fronting": pending.fronting.record(),
        "grant_identity": pending.grant,
    })
    .to_string()
    .into_bytes()
}

/// The refusal of an action that needed its application in front when
/// fronting stopped: nothing was done.
pub(crate) fn not_fronted_reply(fronting: Fronting) -> Value {
    let reason = fronting
        .not_fronted_reason
        .unwrap_or(NotFrontedReason::FrontFailed);
    // A target never read is answered with its remedy alone, which already
    // says what to do in a sentence of its own.
    let remedy = if reason == NotFrontedReason::TargetNotRead {
        reason.remedy().to_owned()
    } else {
        format!("Nothing was done: {}.", reason.remedy())
    };
    let mut reply = json!({
        "outcome": "not_fronted",
        "remedy": remedy,
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
    /// An older agent run without a head route: it may use standing grants
    /// but has no person to ask, so it is treated as unattended for
    /// fronting a picture, as the takeover grant once required.
    pub(crate) agent_run: bool,
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
    /// No takeover grant, and either this build cannot front under the app
    /// grant or the chord acts outside the application, which the app grant
    /// does not cover.
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
    /// Today's takeover bracket: for a build without the app-use review, and
    /// for a system-wide chord in any build.
    TakeoverBracket,
    Refuse(ChordRefusal),
}

/// The route of one keystroke action. `shortcut` is a chord holding Command,
/// Control or Option, which background applications do not reliably
/// receive. `system_wide` is a chord the operating system acts on outside
/// the application, such as Spotlight or the application switcher: the app
/// grant covers only what is done inside the granted application, so such a
/// chord takes the takeover route whether or not the application is in
/// front.
pub(crate) fn chord_route(
    admission: Admission,
    frontmost: bool,
    shortcut: bool,
    system_wide: bool,
) -> ChordRoute {
    if system_wide {
        takeover_route(admission)
    } else if frontmost || !shortcut {
        ChordRoute::PerProcess
    } else if !admission.attended {
        ChordRoute::Refuse(ChordRefusal::TakeoverNotForFlows)
    } else if admission.app_use_fronting_admitted {
        ChordRoute::FrontWithAppGrant
    } else {
        takeover_route(admission)
    }
}

/// The takeover bracket, for a caller holding the takeover grant in an
/// attended session of a build that carries the takeover review; otherwise
/// the refusal naming what is missing.
fn takeover_route(admission: Admission) -> ChordRoute {
    if !admission.attended {
        ChordRoute::Refuse(ChordRefusal::TakeoverNotForFlows)
    } else if !admission.takeover_held {
        ChordRoute::Refuse(ChordRefusal::ModifierChordNeedsForeground)
    } else if !admission.bracket_admitted {
        ChordRoute::Refuse(ChordRefusal::KeystrokesNeedForeground)
    } else {
        ChordRoute::TakeoverBracket
    }
}

impl Admission {
    /// A picture fronted under the app's own grant needs the app-use fronting
    /// review (which a build binds only together with the bracket review),
    /// an attended session, and a caller that is not an older agent run.
    pub(super) fn may_front_image(self) -> Result<(), FrontingStop> {
        if !self.attended || self.agent_run {
            Err(FrontingStop::Unattended)
        } else if !self.app_use_fronting_admitted || !self.bracket_admitted {
            Err(FrontingStop::FrontingNotAdmitted)
        } else {
            Ok(())
        }
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
pub(crate) struct PlatformRestoreHost {
    pub(crate) host: Box<dyn FrontingRestoreHost>,
    /// Whether a restore may also ask the platform's second route to the
    /// front. Only app-use fronts allow it; takeover fronts restore only
    /// through the accessibility request that the review bound as
    /// `takeover_dispatch_review_revision` admitted.
    pub(crate) fallback: bool,
}

impl RestoreHost for PlatformRestoreHost {
    fn now_ms(&mut self) -> u64 {
        self.host.now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.host.pause_ms(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        self.host.frontmost_pid()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.host.request_front(pid)
    }
    fn request_front_while(
        &mut self,
        pid: u32,
        check: &mut dyn cerebellum_computer::platform::RestoreWriteCheck,
    ) -> bool {
        self.host.request_front_while(pid, check)
    }
    fn request_front_fallback(&mut self, pid: u32) -> bool {
        self.fallback && self.host.request_front_fallback(pid)
    }
    fn request_front_fallback_while(
        &mut self,
        pid: u32,
        check: &mut dyn cerebellum_computer::platform::RestoreWriteCheck,
    ) -> bool {
        self.fallback && self.host.request_front_fallback_while(pid, check)
    }
    fn hardware_input_snapshot(
        &mut self,
    ) -> Option<cerebellum_computer::dispatch::HardwareInputSnapshot> {
        self.host.hardware_input_snapshot()
    }
}

/// Run `cell`'s restore decision under its own accessibility budget of
/// `RESTORE_AX_MS`, not the call's remaining work budget: the decision is
/// run on a fresh thread, which carries no outer deadline, so a call whose
/// work deadline already passed still puts the previous application back.
pub(crate) fn decide_with_restore_budget(cell: &RestoreCell) -> RestoreDecided {
    with_restore_budget(cell, RestoreCell::decide)
}

type RestoreDecision = fn(&RestoreCell) -> RestoreDecided;

fn with_restore_budget(cell: &RestoreCell, decide: RestoreDecision) -> RestoreDecided {
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                // A fresh thread carries no outer deadline: only the
                // restore's own budget caps its accessibility messages.
                #[cfg(target_os = "macos")]
                let _ax = cerebellum_macos::ax_budget::bound_messages_until(
                    Instant::now() + Duration::from_millis(RESTORE_AX_MS),
                );
                #[cfg(not(target_os = "macos"))]
                let _ = RESTORE_AX_MS;
                decide(cell)
            })
            .join()
            .unwrap_or_else(|_| decide(cell))
    })
}

/// What a temporary front's obligation carries before it is registered.
pub(crate) struct ObligationParts {
    pub(crate) terminal: Arc<TerminalArbiter>,
    pub(crate) lock: Option<FrontingLockGuard>,
    pub(crate) target_name: String,
    pub(crate) mode: FrontingMode,
    pub(crate) purpose: FrontingPurpose,
    /// The restore may use the platform's second route to the front when
    /// the first has not taken effect. Set for app-use fronts only: a
    /// takeover front keeps the single restore route admitted under
    /// `takeover_dispatch_review_revision`.
    pub(crate) restore_fallback: bool,
}

impl ObligationParts {
    /// Register the obligation for a front of `target` over `previous`.
    /// `None` when the call's terminal reply is already chosen; the lock is
    /// then released and nothing may be fronted.
    /// `gate` is the bracket's, when the front runs in one.
    pub(crate) fn register(
        &mut self,
        previous: u32,
        target: u32,
        host: Box<dyn FrontingRestoreHost>,
        gate: Option<Arc<cerebellum_computer::dispatch::CutoffGate>>,
    ) -> Option<Arc<RestoreCell>> {
        let lock = self.lock.take()?;
        let mut host = host;
        // Every restore route checks it is still putting back this process,
        // so a pid reused meanwhile is never brought forward. Remembered for
        // every front: takeover fronts have no second route
        // (`restore_fallback` stays false), but their one route checks it
        // too.
        if previous != target {
            host.remember_previous(previous);
        }
        self.terminal
            .register_restore(RestoreObligation {
                previous_pid: previous,
                target_pid: target,
                target_name: self.target_name.clone(),
                mode: self.mode,
                purpose: self.purpose,
                lock,
                host: Box::new(PlatformRestoreHost {
                    host,
                    fallback: self.restore_fallback,
                }),
                gate,
            })
            .ok()
    }
}

#[derive(Default)]
struct HooksState {
    report: Option<cerebellum_computer::dispatch::BracketReport>,
    parts: Option<ObligationParts>,
    cell: Option<Arc<RestoreCell>>,
    refused: bool,
    decided: Option<RestoreDecided>,
    finished: Option<(Option<DeferredRestore>, bool)>,
    /// The bracket's gate for this front, once registered.
    cutoff: Option<Arc<cerebellum_computer::dispatch::CutoffGate>>,
}

/// The hooks a fronted dispatch or read runs its obligation through, shared
/// between the driver that runs the bracket and the call that reads what
/// happened afterwards.
#[derive(Clone)]
pub(crate) struct CellHooks(Arc<StdMutex<HooksState>>);

/// What the call learns from its hooks once the bracket returned.
pub(crate) struct HookedEnd {
    pub(crate) report: Option<cerebellum_computer::dispatch::BracketReport>,
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
            report: state.report.clone(),
            cell: state.cell.clone(),
            refused: state.refused,
            decided: state.decided,
            finished: state.finished,
        }
    }

    pub(crate) fn cell(&self) -> Option<Arc<RestoreCell>> {
        self.state().cell.clone()
    }

    /// Run `decide` on the cell under the restore's own budget, and keep
    /// what it decided.
    fn decide_using(&self, decide: RestoreDecision) -> HookedRestore {
        let Some(cell) = self.cell() else {
            return HookedRestore {
                restore: RestoreStatus::NotNeeded,
                person_input_during_fronting: false,
                input_coverage_unavailable: false,
                restore_ms: None,
            };
        };
        let decided = with_restore_budget(&cell, decide);
        self.state().decided = Some(decided);
        HookedRestore {
            restore: decided.restore,
            person_input_during_fronting: decided.person_input_during_fronting,
            input_coverage_unavailable: decided.input_coverage_unavailable,
            restore_ms: decided.restore_ms,
        }
    }

    /// Whether a picture read may still acquire pixels: the restore reserve
    /// has not started (whatever this thread is doing), the owner has not
    /// begun its restore and cleanup has not stopped the front. Asked
    /// immediately before the pixels are requested, by the completion before
    /// any are copied, and again once they arrived, so a read that was
    /// already under way when the bound passed requests no pixels, copies
    /// none, or has what it copied withheld.
    pub(crate) fn picture_may_acquire(&self) -> bool {
        let (cutoff, cell) = {
            let state = self.state();
            (state.cutoff.clone(), state.cell.clone())
        };
        !cutoff.is_some_and(|cutoff| cutoff.closed())
            && !cell.is_some_and(|cell| cell.cleanup_taken())
    }

    /// When a picture read's waits for the system must end: the start of the
    /// restore reserve, when the front has one.
    pub(crate) fn picture_wait_until(&self) -> Option<Instant> {
        self.state()
            .cutoff
            .as_ref()
            .and_then(|cutoff| cutoff.reserve_start())
    }

    /// Whether the front reached its cutoff, the start of the restore
    /// reserve, before the bracket ended it.
    pub(crate) fn cutoff_fired(&self) -> bool {
        self.state()
            .cutoff
            .as_ref()
            .is_some_and(|cutoff| cutoff.ended_past_cutoff())
    }

    /// Keep the fronting lock for a picture read under way, until the hold
    /// is dropped; see [`RestoreCell::hold_lock_for_read`].
    pub(crate) fn hold_lock_for_read(&self) -> Option<crate::terminal_arbiter::ReadLockHold> {
        self.cell()?.hold_lock_for_read(Duration::from_millis(
            crate::budgets::PICTURE_READ_LIFETIME_MS,
        ))
    }

    /// What the hooks hold now, without releasing an unregistered lock as
    /// [`CellHooks::end`] does: for a row finalized while the call still runs.
    pub(crate) fn peek(&self) -> HookedEnd {
        let state = self.state();
        HookedEnd {
            report: state.report.clone(),
            cell: state.cell.clone(),
            refused: state.refused,
            decided: state.decided,
            finished: state.finished,
        }
    }
}

impl FrontedDispatchHooks for CellHooks {
    fn uses_needs_front_restore_predictor(&self) -> bool {
        self.state().parts.as_ref().is_some_and(|parts| {
            parts.restore_fallback && parts.purpose == FrontingPurpose::NeedsFront
        })
    }

    fn register(
        &mut self,
        previous: u32,
        target: u32,
        host: Box<dyn FrontingRestoreHost>,
        gate: &Arc<cerebellum_computer::dispatch::CutoffGate>,
    ) -> bool {
        let mut state = self.state();
        let Some(parts) = state.parts.as_mut() else {
            return false;
        };
        match parts.register(previous, target, host, Some(Arc::clone(gate))) {
            Some(cell) => {
                state.cell = Some(cell);
                state.cutoff = Some(Arc::clone(gate));
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

    fn target_front_permitted(&self) -> bool {
        self.cell().is_some_and(|cell| !cell.cleanup_taken())
    }

    fn front_attempt_returned(&mut self) {
        if let Some(cell) = self.cell() {
            cell.front_attempt_returned();
        }
    }

    fn front_confirmed(&mut self) {
        if let Some(cell) = self.cell() {
            cell.front_confirmed();
        }
    }

    fn decide_restore(&mut self) -> HookedRestore {
        self.decide_using(RestoreCell::decide)
    }

    fn finished(&mut self, outcome: &BracketOutcome) {
        self.state().report = Some(outcome.report.clone());
        self.state().finished = Some((
            outcome.deferred_restore,
            outcome.person_input_during_fronting,
        ));
    }

    /// App-use fronts (shortcuts and pictures under the app's own grant)
    /// get an absolute restore deadline, with the restore reserve starting
    /// early by the restore's measured preparation time
    /// ([`crate::terminal_arbiter::restore_preparation`]). Fronts made under
    /// the takeover (mouse-and-keyboard) grant keep their existing bounds.
    fn restore_reserve_ms(&self) -> Option<u64> {
        self.state()
            .parts
            .as_ref()
            .is_some_and(|parts| parts.restore_fallback)
            .then(crate::terminal_arbiter::restore_preparation::reserve_ms)
    }
}

/// The trait object the driver is handed.
pub(crate) fn boxed_hooks(hooks: &CellHooks) -> Box<dyn FrontedDispatchHooks> {
    Box::new(hooks.clone())
}

/// What a call asks of a front: foreground mode's one-way front or a
/// temporary one.
pub(crate) struct FrontCall<'a> {
    pub(crate) grant: &'a ProcessGrant,
    pub(crate) consent: &'a crate::computer_grants::ConsentContext,
    pub(crate) cancel: &'a crate::CancelHandle,
    pub(crate) management: &'a crate::management::ManagementPlane,
    pub(crate) conversation_key: &'a str,
    /// The action sends input to the application once it is in front: a
    /// press, keys, typing or a write. Such a front needs something the
    /// conversation was shown of the application to check the person
    /// against; see [`target_unchanged_since_seen`]. A read and `open_app`
    /// send no input.
    pub(crate) input_follows: bool,
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
            agent_run: consent.agent_run,
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
        let input_follows = call.input_follows;
        let make_driver = self.make_synthetic_driver.clone();
        let cancel = call.cancel.clone();
        let fronted = tokio::task::spawn_blocking(move || -> Result<OneWayFront, PrepareStop> {
            let _lock = lock;
            let _ax = work.bound_ax();
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(grant.pid, None);
            target_unchanged_since_seen(
                source.as_ref(),
                &sessions,
                &conversation_key,
                &grant,
                input_follows,
            )?;
            let mut session = make_driver()
                .fronting_session()
                .map_err(|_| PrepareStop::from(FrontingStop::FrontingNotAdmitted))?;
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
            .map_err(PrepareStop::from)?;
            if front.fronted {
                absorb_own_front(source.as_ref(), &sessions, &conversation_key, &grant);
            }
            Ok(front)
        })
        .await
        .unwrap_or(Err(FrontingStop::FrontFailed.into()));
        Some(match fronted {
            Ok(front) if front.fronted => {
                let fronting = Fronting::one_way(AppUse::Foreground);
                note_one_way_front(call.grant, fronting);
                ForegroundFront {
                    fronting,
                    stop: None,
                    change: None,
                }
            }
            Ok(_) => ForegroundFront {
                fronting: Fronting::untouched(AppUse::Foreground),
                stop: None,
                change: None,
            },
            Err(prepared) => ForegroundFront {
                change: prepared.change,
                ..ForegroundFront::stopped(prepared.stop)
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

/// Cleanup ownership does not confer app-use authority. The takeover route
/// must retain takeover-dispatch admission and its held takeover grant after
/// waiting for focus ownership.
enum TemporaryFrontAuthority<'a> {
    AppUse,
    AppRead(&'a crate::computer_grants::GrantAdmission),
    Takeover(&'a crate::computer_grants::GrantAdmission),
}

impl From<FrontingStop> for PrepareStop {
    fn from(stop: FrontingStop) -> Self {
        Self { stop, change: None }
    }
}

/// Guard (1): the person has not changed the target since this conversation
/// was last shown it.
///
/// A conversation that was never shown the target has nothing to compare
/// against. When `require_seen`, that stops the front with
/// `TargetNotRead`: the front would hand the target input chosen
/// without ever looking at it, and the person check, which exists to catch a
/// target that is not what the agent saw, cannot run. A front followed by no
/// input (a read, `open_app`) goes ahead without one. Takeover-authorized
/// brackets also retain their existing ability to run without a baseline.
pub(crate) fn target_unchanged_since_seen(
    source: &dyn AppStateSource,
    sessions: &AppStateSessions,
    conversation_key: &str,
    grant: &ProcessGrant,
    require_seen: bool,
) -> Result<(), PrepareStop> {
    if require_seen && sessions.last_seen(conversation_key, grant).is_none() {
        return Err(FrontingStop::TargetNotRead.into());
    }
    match super::element_actions::person_change_since_seen(
        source,
        sessions,
        conversation_key,
        grant,
    ) {
        Ok(None) => Ok(()),
        Ok(Some(change)) => Err(PrepareStop {
            stop: FrontingStop::PersonChangedTarget,
            change: Some(change),
        }),
        Err(()) => Err(FrontingStop::PersonCheckUnreadable.into()),
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
    /// Every caller checks the fronting admission before it gets here. It is
    /// checked again once the lock is held, so a caller that skipped its own
    /// check still fronts nothing in a build or session that may not front.
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
        Box::pin(self.prepare_front_with_authority(
            call,
            purpose,
            guards,
            TemporaryFrontAuthority::AppUse,
        ))
        .await
    }

    /// Prepare a picture-only bracket with this call's app admission.
    pub(super) async fn prepare_image_front(
        &self,
        call: FrontCall<'_>,
        admission: &crate::computer_grants::GrantAdmission,
    ) -> Result<ObligationParts, PrepareStop> {
        Box::pin(self.prepare_front_with_authority(
            call,
            FrontingPurpose::NeedsFront,
            true,
            TemporaryFrontAuthority::AppRead(admission),
        ))
        .await
    }

    /// Prepare a takeover-authorized chord bracket. Obtaining the shared
    /// hooks does not enable app-grant-only fronting for these chords.
    pub(crate) async fn prepare_takeover_front(
        &self,
        call: FrontCall<'_>,
        purpose: FrontingPurpose,
        admission: &crate::computer_grants::GrantAdmission,
    ) -> Result<ObligationParts, PrepareStop> {
        // Preparation contains the lock wait and blocking guard future. Keep
        // that state off the nested wire handler's debug poll stack.
        Box::pin(self.prepare_front_with_authority(
            call,
            purpose,
            true,
            TemporaryFrontAuthority::Takeover(admission),
        ))
        .await
    }

    async fn prepare_front_with_authority(
        &self,
        call: FrontCall<'_>,
        purpose: FrontingPurpose,
        guards: bool,
        authority: TemporaryFrontAuthority<'_>,
    ) -> Result<ObligationParts, PrepareStop> {
        let work = super::quarantine::CallWork::current();
        let Some(terminal) = work.terminal.clone() else {
            return Err(FrontingStop::FrontingNotAdmitted.into());
        };
        let lock = self.fronting_lock.take(call.cancel).await?;
        // App-use input needs a prior read; takeover brackets historically do
        // not. Both routes still compare any baseline the conversation has.
        let require_seen =
            matches!(&authority, TemporaryFrontAuthority::AppUse) && call.input_follows;
        let restore_fallback = !matches!(&authority, TemporaryFrontAuthority::Takeover(_));
        match authority {
            TemporaryFrontAuthority::AppUse => {
                self.fronting_admission(call.consent, false).may_front()?;
            }
            TemporaryFrontAuthority::AppRead(admission) => {
                self.fronting_admission(call.consent, false)
                    .may_front_image()?;
                if !admission.commit() {
                    return Err(FrontingStop::DispatchGateClosed.into());
                }
            }
            TemporaryFrontAuthority::Takeover(admission) => {
                if call.consent.unattended {
                    return Err(FrontingStop::Unattended.into());
                }
                if !self.fronting_bracket_admitted {
                    return Err(FrontingStop::FrontingNotAdmitted.into());
                }
                if !call.management.computer_grants().holds(
                    &call.consent.caller,
                    &crate::computer_grants::GrantNeed::Takeover,
                ) {
                    return Err(FrontingStop::DispatchGateClosed.into());
                }
                // Recheck the actual app admission, including one-time consent,
                // rather than requiring a new standing app grant.
                if !admission.commit() {
                    return Err(FrontingStop::DispatchGateClosed.into());
                }
            }
        }
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
            restore_fallback,
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
        tokio::task::spawn_blocking(move || {
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(grant.pid, None);
            target_unchanged_since_seen(
                source.as_ref(),
                &sessions,
                &conversation_key,
                &grant,
                require_seen,
            )
        })
        .await
        .unwrap_or(Err(FrontingStop::PersonCheckUnreadable.into()))?;
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
        (Some(cell), Some(decided)) if decided.front_requested => Fronting {
            fronted: cell.was_front_confirmed(),
            ..Fronting::temporary(
                mode,
                purpose,
                decided.restore,
                decided.person_input_during_fronting
                    || end.finished.is_some_and(|(_, input)| input),
            )
        },
        (Some(_), Some(_)) => Fronting::stopped(mode, purpose, FrontingStop::CleanupTookObligation),
        _ => Fronting {
            purpose,
            ..Fronting::untouched(mode)
        },
    }
}

/// End a hooked synthetic bracket once the held input is settled; `held`
/// is how settling it ended, at `settled_at`. A bracket whose post failed
/// with a key possibly held deferred its restore, and its owner decides it
/// now ([`RestoreCell::decide_after_release`]): a release confirmed (or
/// nothing held) before the deadline restores at once under that deadline;
/// one confirmed after it restores without one; an unconfirmed release
/// requests no restore at all, since the previous application would receive
/// the held key, and reports the target left in front. A release still
/// running when the reply was due was already reported failed by terminal
/// cleanup, which kept the fronting lock for this decision.
pub(crate) fn finish_after_release(
    hooks: &CellHooks,
    held: Option<crate::HeldState>,
    settled_at: Instant,
    bracket: Option<&mut cerebellum_computer::dispatch::BracketReport>,
) -> HookedEnd {
    let mut end = hooks.end();
    let deferred = end.finished.is_some_and(|(deferred, _)| deferred.is_some());
    if let (Some(cell), true) = (&end.cell, deferred) {
        let released = matches!(
            held,
            None | Some(crate::HeldState::Released | crate::HeldState::NoneHeld)
        );
        let decided = std::thread::scope(|scope| {
            scope
                .spawn(|| {
                    #[cfg(target_os = "macos")]
                    let _ax = cerebellum_macos::ax_budget::bound_messages_until(
                        Instant::now() + Duration::from_millis(RESTORE_AX_MS),
                    );
                    cell.decide_after_release(released, settled_at)
                })
                .join()
                .unwrap_or_else(|_| cell.decide_after_release(released, settled_at))
        });
        hooks.state().decided = Some(decided);
        end.decided = Some(decided);
        // An unconfirmed release leaves the bracket's own report of what it
        // left in front.
        if let (Some(bracket), true) = (bracket, released) {
            bracket.restore = decided.restore;
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

/// The `fronting` a chord's journal row records when the dispatcher
/// finalizes it, which is before any deferred restore runs. A bracket whose
/// post may have left a key held defers its restore until the release is
/// confirmed; at the moment the row is written the target is still in front
/// and nothing has been decided, so the row records it left in front rather
/// than guessing whether the restore will fail. Every other end is recorded
/// as the reply reports it.
pub(crate) fn keystroke_row_fronting(mode: AppUse, end: &HookedEnd) -> Fronting {
    let deferred = end.finished.is_some_and(|(deferred, _)| deferred.is_some());
    if end.cell.is_some() && end.decided.is_none() && deferred {
        return Fronting {
            restore: Restore::LeftInFront,
            ..chord_fronting(mode, end)
        };
    }
    chord_fronting(mode, end)
}
