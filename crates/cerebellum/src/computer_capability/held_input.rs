//! Held-input quarantine for the computer plane's synthetic keyboard and
//! mouse.
//!
//! A key or button press this module posted may still be down when its call
//! ends: the worker can be stuck inside a post, or its paired release can
//! fail. Nothing can confirm a physical release from a hung backend, so the
//! contract is an honest report: while any press may still be held, input
//! actions are refused with `held_input_unconfirmed` instead of typing into
//! a session that may have a modifier stuck down.
//!
//! The quarantine clears on exactly one of four events:
//!
//! 1. the stuck worker returns late and its own sequence reports the presses
//!    released (or never held);
//! 2. after the worker ends, its reaper posts the paired releases and they all
//!    return;
//! 3. a later input call posts the paired releases itself and they all
//!    return, which is allowed only once no worker with a possibly-held send
//!    is alive, so a delayed press cannot land after the release;
//! 4. the target process generations exit, which discharges only presses
//!    routed exclusively to those processes. Global input stays quarantined.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use cerebellum_computer::platform::{
    HeldStateDisposition, PlatformDriver, ProcessGrant, SyntheticAction,
};
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::{HeldState, TerminalArbiter};

/// How a possibly-held press was delivered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HeldRoute {
    /// Posted to one process generation; that process exiting releases it.
    Process { pid: u32, generation: String },
    /// Posted to the session as a whole; no process exit releases it.
    Global,
}

/// One action whose posts may have left a key or button held.
#[derive(Debug, Clone)]
pub(crate) struct HeldPress {
    pub(crate) route: HeldRoute,
    pub(crate) grant: ProcessGrant,
    pub(crate) action: SyntheticAction,
}

impl HeldPress {
    /// The press an action posted per process to `grant` may leave held, or
    /// `None` when the action has no press at all.
    pub(crate) fn per_process(grant: &ProcessGrant, action: &SyntheticAction) -> Option<Self> {
        Self::new(
            HeldRoute::Process {
                pid: grant.pid,
                generation: grant.process_generation_evidence.clone(),
            },
            grant,
            action,
        )
    }

    pub(crate) fn global(grant: &ProcessGrant, action: &SyntheticAction) -> Option<Self> {
        Self::new(HeldRoute::Global, grant, action)
    }

    fn new(route: HeldRoute, grant: &ProcessGrant, action: &SyntheticAction) -> Option<Self> {
        action
            .step_roles()
            .contains(&cerebellum_computer::platform::process_event::SyntheticStepRole::Press)
            .then(|| Self {
                route,
                grant: grant.clone(),
                action: action.clone(),
            })
    }
}

struct Outstanding {
    press: HeldPress,
    terminal: Option<Arc<TerminalArbiter>>,
    /// Set when the press's process exited while the worker was still alive.
    discharged: bool,
}

impl Outstanding {
    /// A worker still running after its call was answered: whatever it posts
    /// next, and whatever it already posted, is unconfirmed.
    fn stuck(&self) -> bool {
        !self.discharged
            && self
                .terminal
                .as_ref()
                .is_some_and(|terminal| terminal.gate.stopped())
    }
}

#[derive(Default)]
struct State {
    outstanding: BTreeMap<u64, Outstanding>,
    quarantined: BTreeMap<u64, HeldPress>,
}

/// The held-input state of one plane's synthetic keyboard and mouse.
#[derive(Default)]
pub(crate) struct HeldInput {
    state: Mutex<State>,
    next: AtomicU64,
}

/// Presses a later call must release before it may post.
pub(crate) struct PendingRelease {
    pub(crate) presses: Vec<(u64, HeldPress)>,
}

impl HeldInput {
    /// Track a send before it is posted. The ticket must be settled with how
    /// the send ended; dropping it unsettled counts as unknown.
    pub(crate) fn begin_send(
        self: &Arc<Self>,
        press: HeldPress,
        terminal: Option<Arc<TerminalArbiter>>,
    ) -> SendTicket {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.state.lock().unwrap().outstanding.insert(
            id,
            Outstanding {
                press,
                terminal,
                discharged: false,
            },
        );
        let (settled, _) = watch::channel(None);
        SendTicket {
            held: Arc::clone(self),
            id,
            settled,
            done: false,
        }
    }

    /// Whether input may be held that nothing has confirmed released.
    pub(crate) fn unconfirmed(&self) -> bool {
        let state = self.state.lock().unwrap();
        !state.quarantined.is_empty() || state.outstanding.values().any(Outstanding::stuck)
    }

    /// The presses a later input call must release first. `Err` while a
    /// stuck worker's send is outstanding, and, when presses are quarantined,
    /// while any worker with a possibly-held send is alive: a release then
    /// could be overtaken by that worker's delayed press.
    pub(crate) fn pending_release(&self) -> Result<Option<PendingRelease>, ()> {
        let state = self.state.lock().unwrap();
        if state.outstanding.values().any(Outstanding::stuck) {
            return Err(());
        }
        if state.quarantined.is_empty() {
            return Ok(None);
        }
        if state
            .outstanding
            .values()
            .any(|outstanding| !outstanding.discharged)
        {
            return Err(());
        }
        Ok(Some(PendingRelease {
            presses: state
                .quarantined
                .iter()
                .map(|(id, press)| (*id, press.clone()))
                .collect(),
        }))
    }

    /// The paired releases for `released` all returned: those presses are no
    /// longer held.
    pub(crate) fn released(&self, released: &[u64]) {
        let mut state = self.state.lock().unwrap();
        for id in released {
            state.quarantined.remove(id);
        }
    }

    /// Discharge presses routed only to process generations that have exited.
    /// `alive` answers whether the pid still runs the generation the press
    /// was posted to. Global presses are never discharged this way.
    pub(crate) fn discharge_exited(&self, alive: impl Fn(u32, &str) -> bool) {
        let mut state = self.state.lock().unwrap();
        let exited = |press: &HeldPress| match &press.route {
            HeldRoute::Process { pid, generation } => !alive(*pid, generation),
            HeldRoute::Global => false,
        };
        state.quarantined.retain(|_, press| !exited(press));
        for outstanding in state.outstanding.values_mut() {
            if exited(&outstanding.press) {
                outstanding.discharged = true;
            }
        }
    }

    fn settle(&self, id: u64, held: HeldState) {
        let mut state = self.state.lock().unwrap();
        let Some(outstanding) = state.outstanding.remove(&id) else {
            return;
        };
        if matches!(held, HeldState::Unknown) && !outstanding.discharged {
            state.quarantined.insert(id, outstanding.press);
        }
    }

    #[cfg(test)]
    pub(crate) fn is_clear(&self) -> bool {
        let state = self.state.lock().unwrap();
        state.quarantined.is_empty() && state.outstanding.is_empty()
    }
}

/// One tracked send. Settled once, by the worker, when its post returns.
pub(crate) struct SendTicket {
    held: Arc<HeldInput>,
    id: u64,
    settled: watch::Sender<Option<HeldState>>,
    done: bool,
}

impl SendTicket {
    /// The press this send may leave held.
    pub(crate) fn press(&self) -> Option<HeldPress> {
        self.held
            .state
            .lock()
            .unwrap()
            .outstanding
            .get(&self.id)
            .map(|outstanding| outstanding.press.clone())
    }

    /// How the send ended, as the call's terminal reply reports it. Resolves
    /// when the ticket settles; a ticket dropped unsettled reads as unknown.
    pub(crate) fn outcome(&self) -> impl std::future::Future<Output = HeldState> + Send + 'static {
        let mut settled = self.settled.subscribe();
        async move {
            match settled.wait_for(Option::is_some).await {
                Ok(held) => held.unwrap_or(HeldState::Unknown),
                Err(_) => HeldState::Unknown,
            }
        }
    }

    /// Settle with the sequence's own report. An unknown held state is
    /// handed to `reaper`, which posts the paired releases now that the
    /// worker has returned and reports whether they all returned.
    pub(crate) fn settle(
        mut self,
        disposition: HeldStateDisposition,
        reaper: impl FnOnce(&HeldPress) -> bool,
    ) -> HeldState {
        let held = match disposition {
            HeldStateDisposition::NoneHeld => HeldState::NoneHeld,
            HeldStateDisposition::Released { .. } => HeldState::Released,
            HeldStateDisposition::Unknown => match self.press() {
                Some(press) if reaper(&press) => HeldState::Released,
                _ => HeldState::Unknown,
            },
        };
        self.finish(held);
        held
    }

    fn finish(&mut self, held: HeldState) {
        self.done = true;
        self.held.settle(self.id, held);
        self.settled.send_replace(Some(held));
    }
}

impl Drop for SendTicket {
    fn drop(&mut self) {
        if !self.done {
            self.finish(HeldState::Unknown);
        }
    }
}

/// The held state a dispatch result leaves, from the sequence's own report.
pub(crate) fn disposition_of<T>(
    result: &Result<T, cerebellum_computer::dispatch::DispatchError>,
) -> HeldStateDisposition {
    use cerebellum_computer::dispatch::DispatchError;
    match result {
        Err(DispatchError::Cancelled { held_state, .. })
        | Err(DispatchError::SyntheticSequenceFailed { held_state, .. }) => *held_state,
        // A sequence that returned posted each release with its press, and a
        // refusal other than the two above stopped before any press.
        Ok(_) | Err(_) => HeldStateDisposition::NoneHeld,
    }
}

/// Post the paired releases for one press. Only a press posted to one
/// process can be released this way; global input has no per-process route,
/// so it stays unconfirmed.
pub(crate) fn release_one<D: PlatformDriver>(press: &HeldPress, driver: &mut D) -> bool {
    match press.route {
        HeldRoute::Process { .. } => driver.release_held(&press.grant, &press.action).is_ok(),
        HeldRoute::Global => false,
    }
}

/// A later input call's own paired releases. The quarantine clears only when
/// every release returns; a partial release confirms nothing.
pub(crate) fn release_pending<D: PlatformDriver>(
    held: &HeldInput,
    pending: PendingRelease,
    driver: &mut D,
) -> bool {
    let mut released = Vec::new();
    for (id, press) in pending.presses {
        if !release_one(&press, driver) {
            return false;
        }
        released.push(id);
    }
    held.released(&released);
    true
}

/// The refusal for an input action while held input is unconfirmed.
pub(crate) fn held_input_unconfirmed_reply(call: &str) -> Value {
    json!({
        "outcome": "target_busy",
        "detail": {
            "reason": "held_input_unconfirmed",
            "dispatched": false,
            "step": "preflight",
            "call": call,
            "held_state": "unknown",
        },
        "remedy": "held input could not be confirmed released; the next input action retries \
                   the release first",
    })
}
