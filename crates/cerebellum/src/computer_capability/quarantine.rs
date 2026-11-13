//! Capacity, stuck-worker quarantine and per-call work context for the
//! computer plane.
//!
//! Three things keep one hung application from stalling the plane:
//!
//! - **Permits.** Blocking platform work runs on a bounded pool. A call takes
//!   one work permit and one release permit, atomically, when it acquires its
//!   execution lane; a target-resolution query takes one work permit of its
//!   own. With no permit free the call is refused before anything is
//!   dispatched, so a run of stuck threads cannot grow without bound.
//! - **Execution quarantine.** While a call's blocking worker outlives the
//!   call's terminal decision, its application is marked busy for every
//!   conversation, by pid and by bundle identity. New calls on it are refused
//!   at once rather than queued behind a worker that may never return.
//! - **The call's work context.** Each blocking worker is handed the call's
//!   dispatch gate, work deadline and quarantine lease as values captured on
//!   the async side; a worker never looks up task-local state itself.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cerebellum_computer::app_state::person::{OwnInputLedger, Posting};
use cerebellum_computer::dispatch::MutationGate;
use cerebellum_computer::platform::ProcessGrant;
use serde_json::{json, Value};

use crate::blocking_permits::CallPermits;
use crate::TerminalArbiter;

/// The call's terminal decision as a dispatch gate for blocking workers.
/// A call served outside a route (a direct test of the plane) has no terminal
/// decision, and its gate never closes.
pub(crate) struct ArbiterGate(pub(crate) Option<Arc<TerminalArbiter>>);

impl MutationGate for ArbiterGate {
    fn begin_mutation(&self) -> bool {
        self.0
            .as_ref()
            .is_none_or(|terminal| terminal.gate.begin_mutation())
    }

    fn stopped(&self) -> bool {
        self.0
            .as_ref()
            .is_some_and(|terminal| terminal.gate.stopped())
    }
}

struct Entry {
    id: u64,
    pid: Option<u32>,
    bundle_identity: Option<String>,
    action: &'static str,
    terminal: Option<Arc<TerminalArbiter>>,
}

impl Entry {
    /// A worker counts as stuck once its call has been answered while it is
    /// still running: the call's gate is stopped and the entry is still here.
    fn stuck(&self) -> bool {
        self.terminal
            .as_ref()
            .is_some_and(|terminal| terminal.gate.stopped())
    }

    fn matches(&self, pid: Option<u32>, bundle_identity: Option<&str>) -> bool {
        (pid.is_some() && self.pid == pid)
            || bundle_identity.is_some_and(|wanted| {
                self.bundle_identity
                    .as_deref()
                    .is_some_and(|held| held.eq_ignore_ascii_case(wanted))
            })
    }
}

/// The plane-wide register of live call workers, separate from the
/// per-conversation lanes so a stuck worker is visible to every conversation.
#[derive(Default)]
pub(crate) struct ExecutionQuarantine {
    entries: Mutex<Vec<Entry>>,
    next: AtomicU64,
}

impl ExecutionQuarantine {
    /// Register a call's worker on its application. The returned lease
    /// removes the entry when the last holder drops it, which is when the
    /// worker really ends.
    pub(crate) fn enter(
        self: &Arc<Self>,
        bundle_identity: Option<String>,
        action: &'static str,
        terminal: Option<Arc<TerminalArbiter>>,
    ) -> Arc<WorkerLease> {
        let id = self.next.fetch_add(1, Ordering::SeqCst);
        self.entries.lock().unwrap().push(Entry {
            id,
            pid: None,
            bundle_identity,
            action,
            terminal,
        });
        Arc::new(WorkerLease {
            registry: Arc::clone(self),
            id,
        })
    }

    /// The stuck action holding this application, if any. A call never
    /// matches its own entry.
    pub(crate) fn busy(
        &self,
        own: Option<&WorkerLease>,
        pid: Option<u32>,
        bundle_identity: Option<&str>,
    ) -> Option<&'static str> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|entry| own.is_none_or(|own| own.id != entry.id))
            .find(|entry| entry.stuck() && entry.matches(pid, bundle_identity))
            .map(|entry| entry.action)
    }

    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.lock().unwrap().is_empty()
    }
}

/// One call worker's entry in the [`ExecutionQuarantine`].
pub(crate) struct WorkerLease {
    registry: Arc<ExecutionQuarantine>,
    id: u64,
}

impl WorkerLease {
    /// Record the process the call acts on, now that it is known, so a call
    /// naming the application only by pid matches too.
    pub(crate) fn bind(&self, grant: &ProcessGrant) {
        let terminal = {
            let mut entries = self.registry.entries.lock().unwrap();
            let Some(entry) = entries.iter_mut().find(|entry| entry.id == self.id) else {
                return;
            };
            entry.pid = Some(grant.pid);
            entry.bundle_identity = Some(grant.bundle_identity.clone());
            entry.terminal.clone()
        };
        // The cleanup wait owns no quarantine lock: another application must
        // still be able to enter, leave, or check this registry immediately.
        if let Some(terminal) = terminal {
            if !crate::terminal_arbiter::cancel_late_fronting_target(
                terminal
                    .fronting_domain
                    .load(std::sync::atomic::Ordering::Acquire),
                grant.pid,
            ) {
                terminal.stop(crate::terminal_arbiter::TerminalCause::Deadline);
            }
        }
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        self.registry
            .entries
            .lock()
            .unwrap()
            .retain(|entry| entry.id != self.id);
    }
}

/// The refusal for a call on an application a stuck worker still holds.
pub(crate) fn target_busy_reply(stuck_action: &str, step: &str) -> Value {
    json!({
        "outcome": "target_busy",
        "detail": {"dispatched": false, "step": step, "call": stuck_action},
        "remedy": format!(
            "an earlier {stuck_action} on this application has not returned; nothing was done. \
             Retry later or check the app"
        ),
    })
}

/// The refusal for a call that found no blocking-worker capacity free.
pub(crate) fn capacity_exhausted_reply(step: &str, call: &str) -> Value {
    json!({
        "outcome": "blocking_capacity_exhausted",
        "detail": {"dispatched": false, "step": step, "call": call},
        "remedy": "too many earlier actions are still running; nothing was done. Retry later",
    })
}

/// The reply a worker returns when its call was stopped before the action
/// could start. The call's terminal decision has already been sent, so this
/// reply is evidence for the journal and for direct callers of the plane.
pub(crate) fn stopped_before_dispatch_reply() -> Value {
    json!({
        "outcome": "action_deadline_exceeded",
        "detail": {"dispatched": false, "step": "dispatch"},
    })
}

/// What one call's blocking workers are handed, captured on the async side.
#[derive(Clone)]
pub(crate) struct CallWork {
    pub(crate) terminal: Option<Arc<TerminalArbiter>>,
    gate: Arc<dyn MutationGate>,
    started: Instant,
    budget: Duration,
    parked: Arc<Mutex<Duration>>,
    lease: Option<Arc<WorkerLease>>,
    permits: Option<Arc<CallPermits>>,
    disclosures: Arc<Mutex<Vec<String>>>,
}

tokio::task_local! {
    static CALL_WORK: CallWork;
}

impl CallWork {
    pub(crate) fn new(
        terminal: Option<Arc<TerminalArbiter>>,
        budget: Duration,
        lease: Option<Arc<WorkerLease>>,
        permits: Option<Arc<CallPermits>>,
    ) -> Self {
        Self {
            gate: Arc::new(ArbiterGate(terminal.clone())),
            terminal,
            started: Instant::now(),
            budget,
            parked: Arc::new(Mutex::new(Duration::ZERO)),
            lease,
            permits,
            disclosures: Arc::default(),
        }
    }

    /// The work context of a call served outside the plane's `serve`, such
    /// as a direct test of one handler: an open gate and no quarantine.
    fn unmanaged() -> Self {
        Self::new(
            None,
            Duration::from_millis(crate::budgets::MAX_ACTION_WORK_MS),
            None,
            None,
        )
    }

    /// Run `future` with this as its call's work context.
    pub(crate) async fn scope<T>(self, future: impl std::future::Future<Output = T>) -> T {
        CALL_WORK.scope(self, future).await
    }

    /// The current call's work context. Read on the async side only; the
    /// value is then moved into the blocking job.
    pub(crate) fn current() -> Self {
        CALL_WORK
            .try_with(Clone::clone)
            .unwrap_or_else(|_| Self::unmanaged())
    }

    pub(crate) fn gate(&self) -> Arc<dyn MutationGate> {
        Arc::clone(&self.gate)
    }

    pub(crate) fn begin_mutation(&self) -> bool {
        self.gate.begin_mutation()
    }

    pub(crate) fn stopped(&self) -> bool {
        self.gate.stopped()
    }

    /// When the work budget ends: lane acquisition plus the budget, with the
    /// time parked on a person added back. macOS caps its accessibility
    /// messages by it, and an action waiting for its badge to arrive is not
    /// sent once it has passed.
    pub(crate) fn deadline(&self) -> Instant {
        self.started + self.budget + *self.parked.lock().unwrap()
    }

    /// Cap this thread's accessibility messages at the call's remaining work
    /// budget for as long as the guard lives. Taken inside each blocking job.
    #[cfg(target_os = "macos")]
    pub(crate) fn bound_ax(&self) -> cerebellum_macos::ax_budget::AxCallBudget {
        cerebellum_macos::ax_budget::bound_messages_until(self.deadline())
    }

    /// Other platforms set no accessibility messaging timeouts.
    #[cfg(not(target_os = "macos"))]
    pub(crate) fn bound_ax(&self) -> NoAxBudget {
        NoAxBudget
    }

    /// Record the process this call acts on, and refuse it when a stuck
    /// worker from another call holds that process.
    pub(crate) async fn bind(
        &self,
        quarantine: &ExecutionQuarantine,
        grant: &ProcessGrant,
    ) -> Option<Value> {
        if let Some(lease) = &self.lease {
            let lease = Arc::clone(lease);
            let grant = grant.clone();
            // Every production caller is an async serving task. A condvar
            // wait belongs on the blocking pool, never a Tokio worker.
            if tokio::task::spawn_blocking(move || lease.bind(&grant))
                .await
                .is_err()
            {
                if let Some(terminal) = &self.terminal {
                    terminal.stop(crate::terminal_arbiter::TerminalCause::Deadline);
                }
                return Some(stopped_before_dispatch_reply());
            }
        }
        quarantine
            .busy(
                self.lease.as_deref(),
                Some(grant.pid),
                Some(&grant.bundle_identity),
            )
            .map(|stuck| target_busy_reply(stuck, "preflight"))
    }

    pub(crate) fn permits(&self) -> Option<&Arc<CallPermits>> {
        self.permits.as_ref()
    }

    /// Keep a line for the call's reply that says something the call
    /// noticed and acted on, such as the application moving its own focus.
    pub(crate) fn disclose(&self, line: String) {
        self.disclosures.lock().unwrap().push(line);
    }

    /// The lines kept by [`Self::disclose`], once.
    pub(crate) fn take_disclosures(&self) -> Vec<String> {
        std::mem::take(&mut *self.disclosures.lock().unwrap())
    }

    /// Publish an open posting interval to the call's terminal decision, so
    /// the interval is closed when the terminal is chosen even if this worker
    /// stays blocked in the post. When the terminal has already been chosen,
    /// the interval is closed here and now, before any further step.
    pub(crate) fn publish_posting(&self, ledger: &Arc<OwnInputLedger>, posting: &Posting) {
        let Some(terminal) = &self.terminal else {
            return;
        };
        let start = posting.start();
        let closing = Arc::clone(ledger);
        if !terminal.publish_or_close(Box::new(move || closing.end_posting_at(start))) {
            ledger.end_posting_at(start);
        }
    }
}

/// Stands in for the macOS accessibility budget guard where there is none.
#[cfg(not(target_os = "macos"))]
pub(crate) struct NoAxBudget;

/// Adds the time a call spends waiting on a person to its work deadline.
/// Taken on the async side where a consent wait begins; dropped when it ends.
pub(crate) struct ParkClock {
    parked: Arc<Mutex<Duration>>,
    since: Instant,
}

impl Drop for ParkClock {
    fn drop(&mut self) {
        *self.parked.lock().unwrap() += self.since.elapsed();
    }
}

/// Start counting a consent wait against the current call, if it has a work
/// context.
pub(crate) fn park_clock() -> Option<ParkClock> {
    CALL_WORK
        .try_with(|work| ParkClock {
            parked: Arc::clone(&work.parked),
            since: Instant::now(),
        })
        .ok()
}
