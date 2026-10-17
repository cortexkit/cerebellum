//! Single terminal ownership and bounded cleanup for route requests.

use std::sync::Arc;
use std::time::Duration;

use serde_json::{json, Value};
use subc_protocol::{Frame, FrameType};
use tokio::sync::mpsc;

use crate::egress::{request_id, terminal_frame};
use crate::{
    budgets, call_context, control_flags, flat_tools, forward_recording_reply, send,
    settle_call_record, wall_clock_ms, ModuleError, PendingSettlement, Planes,
    RequestCancellationGuard,
};

/// Tracks whether ordinary external mutations may start. Once a terminal
/// decision stops dispatch, only held-input release may proceed.
#[derive(Default)]
pub struct DispatchGate(
    std::sync::atomic::AtomicU8,
    std::sync::Mutex<Option<Arc<crate::grant_enforcement::CallGrants>>>,
    std::sync::Mutex<Vec<(Arc<crate::cingulate_client::desk::ConsentDesk>, String)>>,
);

impl DispatchGate {
    pub(crate) fn bind_grants(&self, grants: Arc<crate::grant_enforcement::CallGrants>) {
        *self.1.lock().unwrap() = Some(grants);
    }

    pub fn begin_mutation(&self) -> bool {
        if self
            .1
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|grants| !grants.is_live())
        {
            self.stop();
            return false;
        }
        use std::sync::atomic::Ordering::SeqCst;
        if self
            .2
            .lock()
            .unwrap()
            .iter()
            .any(|(desk, id)| desk.begin_execution(id).is_err())
        {
            self.stop();
            return false;
        }
        let mut bits = self.0.load(SeqCst);
        loop {
            if bits & 2 != 0 {
                return false;
            }
            match self.0.compare_exchange(bits, bits | 1, SeqCst, SeqCst) {
                Ok(_) => return true,
                Err(current) => bits = current,
            }
        }
    }

    pub fn stopped(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::SeqCst) & 2 != 0
    }

    fn stop(&self) -> bool {
        self.0.fetch_or(2, std::sync::atomic::Ordering::SeqCst) & 1 != 0
    }
}

#[derive(Clone, Copy)]
pub enum CallStep {
    Admission,
    Queue,
    Consent,
    Preflight,
    Dispatch,
    Release,
}

impl CallStep {
    fn name(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Queue => "queue",
            Self::Consent => "consent",
            Self::Preflight => "preflight",
            Self::Dispatch => "dispatch",
            Self::Release => "release",
        }
    }
}

#[derive(Clone, Copy)]
pub enum TerminalCause {
    Deadline,
    Cancelled,
    RouteClosed,
    Draining,
}

impl TerminalCause {
    fn name(self) -> &'static str {
        match self {
            Self::Deadline => "action_deadline_exceeded",
            Self::Cancelled => "cancelled",
            Self::RouteClosed => "route_closed",
            Self::Draining => "module_draining",
        }
    }
}

#[derive(Clone, Copy)]
pub enum HeldState {
    NoneHeld,
    Released,
    Unknown,
}

impl HeldState {
    fn name(self) -> &'static str {
        match self {
            Self::NoneHeld => "none_held",
            Self::Released => "released",
            Self::Unknown => "unknown",
        }
    }
}

type ReleaseJob = std::pin::Pin<Box<dyn std::future::Future<Output = HeldState> + Send>>;

pub(crate) struct TerminalState {
    pub(crate) chosen: Option<Frame>,
    pub(crate) cause: Option<TerminalCause>,
    pub(crate) possibly_dispatched: bool,
    reply_finalized: bool,
    step: CallStep,
    release: Option<ReleaseJob>,
    pub(crate) settlement: Option<PendingSettlement>,
    /// Run once, under this state's lock, at the moment the terminal is
    /// chosen, then dropped. They hold this lock while they run, so each must
    /// be constant-time and non-blocking: no I/O, no await, and no lock but
    /// the one small cell it closes (a posting interval in the own-input
    /// ledger).
    on_terminal: Vec<TerminalHook>,
}

type TerminalHook = Box<dyn FnOnce() + Send>;

/// One decision shared by the route task and its workers. A worker retains this
/// handle when detached, but cannot change a terminal that has already won.
pub struct TerminalArbiter {
    pub gate: DispatchGate,
    pub(crate) witness: cerebellum_core::dispatch_witness::DispatchWitness,
    pub(crate) witness_committed: std::sync::atomic::AtomicBool,
    pub(crate) gate_dispatched: Arc<std::sync::atomic::AtomicBool>,
    pub(crate) state: std::sync::Mutex<TerminalState>,
    request: Frame,
    changed: tokio::sync::Notify,
    consent_desk: std::sync::Mutex<Option<Arc<crate::cingulate_client::desk::ConsentDesk>>>,
    /// The agent whose cursor badge this call drew, if it drew one. Only
    /// computer calls draw badges, so a cancel that finds one here cancelled a
    /// computer call and can hide that agent's badge.
    cursor_agent: std::sync::Mutex<Option<String>>,
}

tokio::task_local! {
    pub static CALL_TERMINAL: Arc<TerminalArbiter>;
}

impl TerminalArbiter {
    pub(crate) fn new(request: Frame) -> Self {
        Self {
            gate: DispatchGate::default(),
            witness: cerebellum_core::dispatch_witness::DispatchWitness::armed(),
            witness_committed: std::sync::atomic::AtomicBool::new(false),
            gate_dispatched: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            state: std::sync::Mutex::new(TerminalState {
                chosen: None,
                cause: None,
                possibly_dispatched: false,
                reply_finalized: false,
                step: CallStep::Admission,
                release: None,
                settlement: None,
                on_terminal: Vec::new(),
            }),
            request,
            changed: tokio::sync::Notify::new(),
            consent_desk: std::sync::Mutex::new(None),
            cursor_agent: std::sync::Mutex::new(None),
        }
    }

    pub fn current() -> Option<Arc<Self>> {
        CALL_TERMINAL.try_with(Arc::clone).ok()
    }

    /// The route this call arrived on, as `(channel, epoch)`.
    pub(crate) fn route(&self) -> (u16, u32) {
        (self.request.header.channel, self.request.header.epoch)
    }

    pub(crate) fn note_cursor_agent(&self, agent: &str) {
        *self
            .cursor_agent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(agent.to_owned());
    }

    pub(crate) fn cursor_agent(&self) -> Option<String> {
        self.cursor_agent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Grant application is not execution. Retain the answered card until the
    /// action's single terminal decision establishes what actually happened.
    pub(crate) fn track_consent(
        &self,
        desk: Arc<crate::cingulate_client::desk::ConsentDesk>,
        id: &str,
    ) {
        if !desk
            .raised(id)
            .is_some_and(|card| card.lifecycle.answered && card.lifecycle.final_report.is_none())
        {
            return;
        }
        let mut cards = self.gate.2.lock().unwrap();
        if !cards.iter().any(|(_, existing)| existing == id) {
            cards.push((desk, id.to_string()));
        }
    }

    pub(crate) fn track_grant_consent(&self, id: &str) {
        if let Some(desk) = self.consent_desk.lock().unwrap().clone() {
            self.track_consent(desk, id);
        }
    }

    fn finish_consent(&self, reply: &Frame) {
        use crate::cingulate_client::wire::{Execution, ExecutionReason};
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        let dispatched = self.state.lock().unwrap().possibly_dispatched
            || self.gate.0.load(std::sync::atomic::Ordering::SeqCst) & 1 != 0;
        let outcome = body["outcome"].as_str().unwrap_or_default();
        let refused_before_dispatch =
            body["input_dispatched"] == false || body["detail"]["dispatched"] == false;
        let success = reply.header.ty == FrameType::Response
            && matches!(
                outcome,
                "ok" | "completed"
                    | "launched"
                    | "launched_no_window"
                    | "already_running"
                    | "navigated"
                    | "opened"
                    | "clicked"
                    | "typed"
                    | "snapshot"
                    | "screenshot"
                    | "read"
            );
        let execution = if matches!(outcome, "dispatch_outcome_unknown" | "outcome_unknown") {
            Execution::OutcomeUnknown
        } else if body["effect_status"] == "not_dispatched" {
            Execution::ApprovedNotExecuted
        } else if success {
            Execution::Executed
        } else if refused_before_dispatch {
            Execution::ApprovedNotExecuted
        } else if dispatched {
            Execution::Executed
        } else {
            Execution::ApprovedNotExecuted
        };
        let reason = (execution == Execution::ApprovedNotExecuted).then(|| {
            crate::computer_grants::execution_refusal_reason(&body)
                .unwrap_or(ExecutionReason::RefusedAtDispatch)
        });
        for (desk, id) in self.gate.2.lock().unwrap().iter() {
            let _ = desk.finish_execution(id, execution, reason);
        }
    }

    /// Accounting guards can outlive a reply during worker cleanup, but may
    /// no longer authorize a new consent route or card once it is finalized.
    pub(crate) fn consent_call_held(&self) -> bool {
        !self.state.lock().unwrap().reply_finalized
    }

    #[cfg(test)]
    pub(crate) fn finalize_reply_for_test(&self) {
        self.state.lock().unwrap().reply_finalized = true;
    }

    pub fn set_step(&self, step: CallStep) {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_none() {
            state.step = step;
        }
    }

    /// Register only when a key or mouse-button press may still be held. The
    /// caller must move the release capacity permit into this job so a timeout
    /// cannot return that capacity while backend release work is still running.
    pub fn set_release(
        &self,
        release: impl std::future::Future<Output = HeldState> + Send + 'static,
    ) {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_none() {
            state.release = Some(Box::pin(release));
        }
    }

    fn choose(&self, result: Option<Frame>, cause: TerminalCause) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some() {
            return false;
        }
        let dispatched = self.gate.stop();
        let committed = self.witness.committed();
        self.witness_committed
            .store(committed, std::sync::atomic::Ordering::SeqCst);
        self.gate_dispatched
            .store(dispatched, std::sync::atomic::Ordering::SeqCst);
        for hook in std::mem::take(&mut state.on_terminal) {
            hook();
        }
        state.cause = result.is_none().then_some(cause);
        state.possibly_dispatched = dispatched || committed;
        state.chosen = Some(result.unwrap_or_else(|| {
            let possible = dispatched || committed;
            let body = if possible {
                // Consent can be the last checkpoint even after its approval
                // starts a mutation. The gate/witness is stronger evidence:
                // never describe a possibly dispatched action as still queued
                // or waiting for permission.
                let step = match state.step {
                    CallStep::Admission
                    | CallStep::Queue
                    | CallStep::Consent
                    | CallStep::Preflight => CallStep::Dispatch,
                    step => step,
                };
                json!({"outcome":"dispatch_outcome_unknown",
                    "effect_status":"effect_indeterminate", "detail":{
                        "reason":cause.name(), "dispatched":true, "step":step.name(),
                        "held_state":if state.release.is_some() { "unknown" } else { "none_held" }},
                    "remedy":"read the state before retrying"})
            } else if matches!(cause, TerminalCause::Deadline) {
                json!({"outcome":"action_deadline_exceeded",
                    "detail":{"dispatched":false,"step":state.step.name()}})
            } else {
                let request: Value =
                    serde_json::from_slice(&self.request.body).unwrap_or(Value::Null);
                if request["name"].as_str().is_some_and(|name| {
                    name == flat_tools::BROWSER_USE || name.starts_with("browser.")
                }) {
                    json!({"outcome":cause.name(), "context":null})
                } else if request["name"].as_str().is_some_and(|name| {
                    name == flat_tools::COMPUTER_USE || name.starts_with("computer.")
                }) {
                    json!({"outcome":cause.name(), "attempts":0})
                } else {
                    json!({"outcome":cause.name()})
                }
            };
            Frame::build_with_version(
                self.request.header.ver,
                FrameType::Response,
                control_flags(),
                self.request.header.channel,
                self.request.header.epoch,
                self.request.header.corr,
                serde_json::to_vec(&body).expect("terminal body serializes"),
            )
            .expect("terminal frame fits")
        }));
        self.changed.notify_one();
        true
    }

    /// Register `close` to run under the terminal-state lock when the terminal
    /// is chosen. Returns true when registered. Returns false, running
    /// nothing, when the terminal was already chosen: the caller must then do
    /// the work of `close` itself. Either way it happens exactly once.
    ///
    /// A worker publishes a posting interval this way as soon as it opens one,
    /// so no interval stays open after its call's terminal, however long the
    /// worker itself stays blocked. `close` must be constant-time and
    /// non-blocking; see `TerminalState::on_terminal`.
    pub fn publish_or_close(&self, close: Box<dyn FnOnce() + Send>) -> bool {
        let mut state = self.state.lock().unwrap();
        if state.chosen.is_some() {
            return false;
        }
        state.on_terminal.push(close);
        true
    }

    pub fn stop(&self, cause: TerminalCause) -> bool {
        self.choose(None, cause)
    }

    fn complete(&self, frame: Frame) -> bool {
        self.choose(Some(frame), TerminalCause::Deadline)
    }

    fn preserve_stop_refusal(&self, reply: Frame) {
        let mut state = self.state.lock().unwrap();
        if state.reply_finalized || state.possibly_dispatched {
            return;
        }
        let Some(cause) = state.cause else {
            return;
        };
        if matches!(cause, TerminalCause::Deadline) {
            return;
        }
        let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
        let same_stop = match reply.header.ty {
            FrameType::Error => {
                body["code"] == cause.name()
                    || (matches!(cause, TerminalCause::RouteClosed) && body["code"] == "cancelled")
            }
            FrameType::Response => {
                body["outcome"] == cause.name()
                    || (body["outcome"] == "authorization_denied"
                        && (body["detail"]["decision"] == cause.name()
                            || (matches!(cause, TerminalCause::Draining)
                                && body["detail"]["decision"] == "draining")))
            }
            _ => false,
        };
        if same_stop {
            // The stop decision is final. During bounded cleanup, its existing
            // before-dispatch refusal may supply the legacy wire shape. Never
            // adopt success, or any result after dispatch may have begun.
            state.chosen = Some(reply);
        }
    }
}
#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_arbitrated_route(
    worker: impl std::future::Future<Output = Result<(), ModuleError>> + Send + 'static,
    mut outgoing: mpsc::Receiver<Frame>,
    writer: mpsc::Sender<Frame>,
    planes: Planes,
    cancellation: RequestCancellationGuard,
    guard: Arc<cerebellum_core::dispatch::InFlightGuard>,
    terminal: Arc<TerminalArbiter>,
    envelope_end: tokio::time::Instant,
    connection_end: tokio::time::Instant,
) {
    *terminal.consent_desk.lock().unwrap() = Some(Arc::clone(&planes.consent));
    let execution = Arc::new(std::sync::Mutex::new(Some(Arc::clone(&guard))));
    let worker_execution = Arc::clone(&execution);
    // Supply in-flight accounting only while polling active route work. After
    // its terminal reply, the worker keeps its lane guards until it ends, but
    // the detached-worker counter replaces its in-flight request count.
    let mut worker = Box::pin(worker);
    let guarded = std::future::poll_fn(move |cx| {
        let guard = worker_execution.lock().unwrap().clone();
        match guard {
            Some(guard) => call_context::ROUTE_GUARD.sync_scope(guard, || worker.as_mut().poll(cx)),
            None => worker.as_mut().poll(cx),
        }
    });
    let mut job = Box::pin(call_context::CALL_DEADLINE.scope(
        envelope_end,
        CALL_TERMINAL.scope(Arc::clone(&terminal), guarded),
    ));
    let request = request_id(&terminal.request);
    let mut drain = planes.drain_signal.subscribe();
    let mut finished = false;
    loop {
        if terminal.state.lock().unwrap().chosen.is_some() {
            break;
        }
        tokio::select! {
            biased;
            out = outgoing.recv() => if let Some(out) = out {
                if terminal_frame(&out, request) {
                    if !terminal.complete(out.clone()) { terminal.preserve_stop_refusal(out); }
                } else {
                    if !matches!(tokio::time::timeout_at(envelope_end.min(connection_end), send(&writer, out)).await, Ok(Ok(()))) {
                        outgoing.close();
                        terminal.stop(TerminalCause::Deadline);
                    }
                }
            },
            result = &mut job => {
                finished = true;
                let _ = result;
                while let Ok(out) = outgoing.try_recv() {
                    if terminal_frame(&out, request) { if !terminal.complete(out.clone()) { terminal.preserve_stop_refusal(out); } }
                    else { let _ = tokio::time::timeout_at(connection_end, send(&writer, out)).await; }
                }
                break;
            },
            _ = terminal.changed.notified() => {},
            _ = tokio::time::sleep_until(envelope_end) => { terminal.stop(TerminalCause::Deadline); },
            _ = cancellation.handle.cancelled() => {
                terminal.stop(if planes.routes.get(request.0, request.1).is_none() {
                    TerminalCause::RouteClosed
                } else { TerminalCause::Cancelled });
            },
            _ = async { while !*drain.borrow_and_update() { if drain.changed().await.is_err() { break; } } } => {
                terminal.stop(TerminalCause::Draining);
            },
        }
    }
    let (chosen, release, pending) = {
        let mut state = terminal.state.lock().unwrap();
        (
            state.chosen.clone(),
            state.release.take(),
            state.settlement.take(),
        )
    };
    if let Some(mut chosen) = chosen {
        if release.is_none() && !finished {
            // When no held-input release is needed, use its RELEASE_BUDGET_MS
            // allowance for cooperative cancellation cleanup, so the call can
            // end its consent wait before the caller receives the refusal. A
            // stuck worker is detached after the same bounded window.
            let cleanup = async {
                loop {
                    tokio::select! {
                        biased;
                        _ = &mut job => { finished = true; break; },
                        Some(out) = outgoing.recv() => if terminal_frame(&out, request) {
                            terminal.preserve_stop_refusal(out);
                        } else { let _ = send(&writer, out).await; },
                    }
                }
            };
            let _ =
                tokio::time::timeout(Duration::from_millis(budgets::RELEASE_BUDGET_MS), cleanup)
                    .await;
        }
        while let Ok(out) = outgoing.try_recv() {
            if terminal_frame(&out, request) {
                terminal.preserve_stop_refusal(out);
            } else {
                let _ = tokio::time::timeout_at(connection_end, send(&writer, out)).await;
            }
        }
        {
            let mut state = terminal.state.lock().unwrap();
            state.reply_finalized = true;
            if let Some(reply) = &state.chosen {
                chosen = reply.clone();
            }
        }
        if let Some(release) = release {
            let health = Arc::clone(&planes.health);
            let mut release_job = tokio::spawn(release);
            let held = match tokio::time::timeout(
                Duration::from_millis(budgets::RELEASE_BUDGET_MS),
                &mut release_job,
            )
            .await
            {
                Ok(Ok(held)) => held,
                Ok(Err(_)) => HeldState::Unknown,
                Err(_) => {
                    let detached = health.enter_detached_worker();
                    tokio::spawn(async move {
                        let _detached = detached;
                        let _ = release_job.await;
                    });
                    HeldState::Unknown
                }
            };
            let mut body: Value = serde_json::from_slice(&chosen.body).unwrap_or(Value::Null);
            if body["outcome"] == "dispatch_outcome_unknown" {
                body["detail"]["held_state"] = json!(held.name());
                chosen.body = serde_json::to_vec(&body).expect("terminal body serializes");
                // Rebuild below so the wire body length agrees with the update.
                chosen = Frame::build_with_version(
                    chosen.header.ver,
                    chosen.header.ty,
                    chosen.header.flags,
                    chosen.header.channel,
                    chosen.header.epoch,
                    chosen.header.corr,
                    chosen.body,
                )
                .expect("terminal frame fits");
            }
        }
        terminal.finish_consent(&chosen);
        if serde_json::from_slice::<Value>(&chosen.body)
            .ok()
            .is_some_and(|body| body["outcome"] == "route_closed")
        {
            // This closed route produced no before-dispatch refusal to send.
            // Remove its pending delivery deadline so it cannot kill unrelated
            // routes. Queued browser calls that produced Error(cancelled) above
            // still send that frame and await the writer's flush acknowledgement.
            planes.egress_deadlines.delivered(&[request]);
            if let Some(mut pending) = pending {
                if let Some(ticket) = pending.ticket.take() {
                    let calls = Arc::clone(&planes.calls);
                    settle_call_record(&planes, move || {
                        calls.settle_unknown(ticket, wall_clock_ms())
                    })
                    .await;
                }
            }
        } else if let Some(mut pending) = pending {
            let _ = tokio::time::timeout_at(
                connection_end,
                forward_recording_reply(chosen, &mut pending, &writer, &planes),
            )
            .await;
        } else {
            let _ = tokio::time::timeout_at(connection_end, send(&writer, chosen)).await;
        }
    } else if let Some(mut pending) = pending {
        if let Some(ticket) = pending.ticket.take() {
            let calls = Arc::clone(&planes.calls);
            settle_call_record(&planes, move || {
                calls.settle_unknown(ticket, wall_clock_ms())
            })
            .await;
        }
    }
    execution.lock().unwrap().take();
    drop(guard);
    drop(cancellation);
    // Keep the route future and its lane leases alive until it really ends.
    // A detached worker's terminal reply has already been chosen, so any
    // later terminal it produces must be discarded.
    let detached = (!finished).then(|| planes.health.enter_detached_worker());
    tokio::spawn(async move {
        let mut detached = detached;
        loop {
            tokio::select! {
                out = outgoing.recv() => match out {
                    Some(out) if !terminal_frame(&out, request) => { let _ = send(&writer, out).await; },
                    Some(_) => {},
                    None if finished => break,
                    None => { let _ = (&mut job).await; break; },
                },
                _ = &mut job, if !finished => { finished = true; detached.take(); },
            }
        }
    });
}

#[cfg(test)]
mod consent_execution_tests {
    use super::*;
    use crate::cingulate_client::card::CardKind;
    use crate::cingulate_client::desk::{CardLifecycle, ConsentDesk, RaisedCard, RegistryStore};
    use crate::cingulate_client::double::ScriptedCingulate;
    use crate::cingulate_client::live_call::SessionKey;
    use crate::cingulate_client::wire::{Execution, ExecutionReason};

    struct Saved(std::sync::Mutex<Vec<RaisedCard>>);
    impl RegistryStore for Saved {
        fn load(&self) -> Result<Vec<RaisedCard>, String> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn save(&self, cards: &[RaisedCard]) -> Result<(), String> {
            *self.0.lock().unwrap() = cards.to_vec();
            Ok(())
        }
    }

    #[test]
    fn final_action_reports_distinguish_dispatch_refusal_and_postdispatch_deadline() {
        for kind in [
            CardKind::AppControl,
            CardKind::Takeover,
            CardKind::WebsiteAccessInCall,
            CardKind::UserBrowserSite,
        ] {
            for (dispatch, body, execution, reason) in [
                (true, json!({"outcome":"ok"}), Execution::Executed, None),
                (
                    false,
                    json!({"outcome":"ok","input_dispatched":false}),
                    Execution::Executed,
                    None,
                ),
                (
                    true,
                    json!({"outcome":"dispatch_outcome_unknown"}),
                    Execution::OutcomeUnknown,
                    None,
                ),
                (
                    true,
                    json!({"outcome":"refused","effect_status":"not_dispatched","reason":"target_gone"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::TargetGone),
                ),
                (
                    false,
                    json!({"outcome":"refused","reason":"screen_locked"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::RefusedAtDispatch),
                ),
                (
                    false,
                    json!({"outcome":"refused","reason":"target_gone"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::TargetGone),
                ),
                (
                    false,
                    json!({"outcome":"refused","reason":"grant_store_write_failed"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::GrantStoreUnavailable),
                ),
                (
                    false,
                    json!({"outcome":"route_closed"}),
                    Execution::ApprovedNotExecuted,
                    Some(ExecutionReason::SessionEnded),
                ),
            ] {
                let store = Arc::new(Saved(std::sync::Mutex::new(vec![RaisedCard {
                    elicitation_id: "el_final".into(),
                    session: SessionKey {
                        owner: "owner".into(),
                        scope_ref: "scope".into(),
                        scope_epoch: 1,
                    },
                    kind,
                    subject: "target".into(),
                    grant_ids: vec!["allow".into()],
                    decline_id: "deny".into(),
                    next_steps: Default::default(),
                    applied: true,
                    lifecycle: CardLifecycle {
                        answered: true,
                        ..Default::default()
                    },
                }])));
                let peer = ScriptedCingulate::new();
                let desk = Arc::new(ConsentDesk::with_store(
                    Arc::new(peer.clone()),
                    store.clone(),
                ));
                let request =
                    Frame::build(FrameType::Request, control_flags(), 1, 1, 1, vec![]).unwrap();
                let terminal = TerminalArbiter::new(request);
                terminal.track_consent(Arc::clone(&desk), "el_final");
                assert!(
                    desk.raised("el_final")
                        .unwrap()
                        .lifecycle
                        .final_report
                        .is_none(),
                    "waiting to run is not an execution"
                );
                if dispatch {
                    assert!(terminal.gate.begin_mutation());
                }
                let reply = Frame::build(
                    FrameType::Response,
                    control_flags(),
                    1,
                    1,
                    1,
                    serde_json::to_vec(&body).unwrap(),
                )
                .unwrap();
                terminal.finish_consent(&reply);
                let report = store.load().unwrap()[0].lifecycle.final_report.unwrap();
                assert_eq!(
                    (report.execution, report.reason),
                    (execution, reason),
                    "{kind:?}: {body}"
                );
                terminal.finish_consent(
                    &Frame::build(
                        FrameType::Response,
                        control_flags(),
                        1,
                        1,
                        1,
                        serde_json::to_vec(&json!({"outcome":"ok"})).unwrap(),
                    )
                    .unwrap(),
                );
                assert_eq!(
                    store.load().unwrap()[0].lifecycle.final_report,
                    Some(report),
                    "a late worker result replaced the terminal outcome"
                );
                assert_eq!(peer.opens(), 0, "finalization opened a background route");
            }
        }
    }
}

#[cfg(test)]
mod arbiter_egress_tests {
    use super::*;
    use crate::egress::{drain_writer, ConnectionDeadlines};
    use crate::{
        browser, build_error_frame, computer, handle_frame, management, route_limits,
        run_connection, write_frame, BrowserSurface, HealthConfig, ModuleConfig, EGRESS_BUFFER,
        HELLO_CORR, PROTOCOL_VERSION,
    };
    use std::future::Future;
    use std::path::PathBuf;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use subc_protocol::session::ModuleControlResponse;
    use tokio::io::AsyncWrite;

    fn frame(ty: FrameType, corr: u64, body: Vec<u8>) -> Frame {
        Frame::build_with_version(PROTOCOL_VERSION, ty, control_flags(), 1, 1, corr, body).unwrap()
    }

    fn hello_ack() -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::HelloAck,
            control_flags(),
            0,
            0,
            HELLO_CORR,
            serde_json::to_vec(
                &json!({"negotiated_ver":PROTOCOL_VERSION,"subc_ops":[],"subc_capabilities":[]}),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn request() -> Frame {
        frame(
            FrameType::Request,
            1,
            serde_json::to_vec(&json!({
                "method":management::OPEN_TARGET,"params":{"bundle_identity":"com.example.Nothing"}
            }))
            .unwrap(),
        )
    }

    fn body(terminal: &TerminalArbiter) -> Value {
        serde_json::from_slice(&terminal.state.lock().unwrap().chosen.as_ref().unwrap().body)
            .unwrap()
    }

    #[test]
    fn terminal_hooks_run_once_per_terminal_and_never_after_it() {
        use std::sync::atomic::{AtomicUsize, Ordering::SeqCst};
        let causes: [Option<TerminalCause>; 5] = [
            None,
            Some(TerminalCause::Deadline),
            Some(TerminalCause::Cancelled),
            Some(TerminalCause::RouteClosed),
            Some(TerminalCause::Draining),
        ];
        for cause in causes {
            let terminal = TerminalArbiter::new(request());
            let runs = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&runs);
            assert!(terminal.publish_or_close(Box::new(move || {
                counted.fetch_add(1, SeqCst);
            })));
            assert_eq!(runs.load(SeqCst), 0, "a hook runs only at the terminal");
            match cause {
                Some(cause) => assert!(terminal.stop(cause)),
                None => assert!(terminal.complete(frame(
                    FrameType::Response,
                    1,
                    br#"{"outcome":"ok"}"#.to_vec()
                ))),
            }
            assert_eq!(runs.load(SeqCst), 1, "the hook ran once at the terminal");
            assert!(!terminal.stop(TerminalCause::Cancelled));
            assert_eq!(runs.load(SeqCst), 1, "a second choice runs nothing");
            let late = Arc::new(AtomicUsize::new(0));
            let counted = Arc::clone(&late);
            assert!(
                !terminal.publish_or_close(Box::new(move || {
                    counted.fetch_add(1, SeqCst);
                })),
                "registration after the terminal is reported to the caller"
            );
            assert_eq!(late.load(SeqCst), 0, "and its hook is never run");
        }
    }

    #[test]
    fn second_terminal_cannot_replace_success_or_unknown_and_seals_dispatch() {
        let success = TerminalArbiter::new(request());
        assert!(success.gate.begin_mutation());
        assert!(success.complete(frame(
            FrameType::Response,
            1,
            br#"{"outcome":"ok"}"#.to_vec()
        )));
        assert!(!success.stop(TerminalCause::Deadline));
        assert_eq!(body(&success)["outcome"], "ok");
        assert!(!success.gate.begin_mutation());

        let expired = TerminalArbiter::new(request());
        assert!(expired.gate.begin_mutation());
        expired.set_step(CallStep::Dispatch);
        assert!(expired.stop(TerminalCause::Deadline));
        assert!(!expired.complete(frame(
            FrameType::Response,
            1,
            br#"{"outcome":"ok"}"#.to_vec()
        )));
        assert!(!expired.stop(TerminalCause::Cancelled));
        assert_eq!(body(&expired)["outcome"], "dispatch_outcome_unknown");
        assert_eq!(
            body(&expired)["detail"]["reason"],
            "action_deadline_exceeded"
        );
        assert!(!expired.gate.begin_mutation());
        assert!(expired
            .gate_dispatched
            .load(std::sync::atomic::Ordering::SeqCst));
    }

    #[test]
    fn cooperative_stop_keeps_legacy_refusal_but_not_success_or_late_reply() {
        let terminal = TerminalArbiter::new(request());
        terminal.stop(TerminalCause::Cancelled);
        let refusal =
            build_error_frame(PROTOCOL_VERSION, 1, 1, 1, "cancelled", "cancelled in queue")
                .unwrap();
        terminal.preserve_stop_refusal(refusal.clone());
        assert_eq!(
            terminal.state.lock().unwrap().chosen.as_ref(),
            Some(&refusal)
        );
        terminal.preserve_stop_refusal(frame(
            FrameType::Response,
            1,
            br#"{"outcome":"ok","detail":{"decision":"cancelled"}}"#.to_vec(),
        ));
        assert_eq!(
            terminal.state.lock().unwrap().chosen.as_ref(),
            Some(&refusal)
        );
        terminal.state.lock().unwrap().reply_finalized = true;
        terminal.preserve_stop_refusal(
            build_error_frame(PROTOCOL_VERSION, 1, 1, 1, "cancelled", "late replacement").unwrap(),
        );
        assert_eq!(
            terminal.state.lock().unwrap().chosen.as_ref(),
            Some(&refusal)
        );

        let unknown = TerminalArbiter::new(request());
        assert!(unknown.gate.begin_mutation());
        unknown.stop(TerminalCause::Cancelled);
        unknown.preserve_stop_refusal(refusal);
        assert_eq!(body(&unknown)["outcome"], "dispatch_outcome_unknown");
    }

    #[test]
    fn terminal_shapes_pass_frozen_schemas_in_every_named_phase() {
        for step in [
            CallStep::Admission,
            CallStep::Queue,
            CallStep::Consent,
            CallStep::Preflight,
            CallStep::Dispatch,
            CallStep::Release,
        ] {
            let deadline = TerminalArbiter::new(request());
            deadline.set_step(step);
            deadline.stop(TerminalCause::Deadline);
            browser::validate_browser_result("browser.navigate", &body(&deadline)).unwrap();
            computer::platform::vocabulary::validate_capability_result(
                "computer.read_state",
                &body(&deadline),
            )
            .unwrap();
            for cause in [
                TerminalCause::Deadline,
                TerminalCause::Cancelled,
                TerminalCause::RouteClosed,
                TerminalCause::Draining,
            ] {
                let unknown = TerminalArbiter::new(request());
                unknown.set_step(step);
                unknown.witness.mark_committed();
                unknown.stop(cause);
                let reply = body(&unknown);
                assert_eq!(
                    reply["detail"]["step"],
                    if matches!(step, CallStep::Release) {
                        "release"
                    } else {
                        "dispatch"
                    }
                );
                browser::validate_browser_result("browser.navigate", &reply).unwrap();
                browser::validate_browser_result(management::CAPTURE_LOGIN, &reply).unwrap();
                computer::platform::vocabulary::validate_capability_result(
                    "computer.read_state",
                    &reply,
                )
                .unwrap();
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn management_envelope_replies_and_counts_worker_until_it_really_ends() {
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let (ready, started) = tokio::sync::oneshot::channel();
        let (finish, ended) = tokio::sync::oneshot::channel();
        let inputs = std::sync::Mutex::new(Some((ready, ended)));
        planes.route_test_handler = Some(Arc::new(move || {
            let (ready, ended) = inputs.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                ready.send(()).unwrap();
                ended.await.unwrap();
                assert!(!terminal.gate.begin_mutation());
            })
        }));
        let (tx, mut rx) = mpsc::channel(8);
        let arrival = tokio::time::Instant::now();
        let (envelope_ms, reply_ms) = route_limits(&request(), &planes);
        handle_frame(request(), &tx, &planes).await.unwrap();
        started.await.unwrap();
        tokio::time::advance(Duration::from_millis(envelope_ms)).await;
        let reply = rx.recv().await.unwrap();
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply["outcome"], "dispatch_outcome_unknown");
        assert_eq!(reply["detail"]["step"], "dispatch");
        assert!(arrival.elapsed() <= Duration::from_millis(reply_ms));
        let ModuleControlResponse::HealthCheck {
            status,
            metrics: Some(metrics),
            ..
        } = planes.health.report()
        else {
            panic!("health report")
        };
        assert_eq!(status, subc_protocol::session::HealthStatus::Degraded);
        assert_eq!(metrics["detachedWorkers"], 1);
        assert_eq!(metrics["inFlightActions"], 0);
        finish.send(()).unwrap();
        while planes.health.detached_workers() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(
            rx.try_recv().is_err(),
            "late completion sent a second terminal"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn envelope_expiry_names_each_phase_through_production_route() {
        for step in [
            CallStep::Admission,
            CallStep::Queue,
            CallStep::Consent,
            CallStep::Preflight,
            CallStep::Dispatch,
        ] {
            let mut planes = crate::tests::management_bound_planes(1, 1);
            let (ready, started) = tokio::sync::oneshot::channel();
            let (finish, finished) = tokio::sync::oneshot::channel();
            let input = std::sync::Mutex::new(Some((ready, finished)));
            planes.route_test_handler = Some(Arc::new(move || {
                let (ready, finished) = input.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    let terminal = TerminalArbiter::current().unwrap();
                    terminal.set_step(step);
                    ready.send(()).unwrap();
                    let _ = finished.await;
                    assert!(!terminal.gate.begin_mutation());
                })
            }));
            let (envelope_ms, reply_ms) = route_limits(&request(), &planes);
            let arrival = tokio::time::Instant::now();
            let (tx, mut rx) = mpsc::channel(8);
            handle_frame(request(), &tx, &planes).await.unwrap();
            started.await.unwrap();
            tokio::time::advance(Duration::from_millis(envelope_ms)).await;
            let reply = rx.recv().await.unwrap();
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "action_deadline_exceeded");
            assert_eq!(body["detail"]["step"], step.name());
            assert_eq!(body["detail"]["dispatched"], false);
            browser::validate_browser_result(management::CAPTURE_LOGIN, &body).unwrap();
            assert!(arrival.elapsed() <= Duration::from_millis(reply_ms));
            finish.send(()).unwrap();
            while planes.health.detached_workers() != 0 {
                tokio::task::yield_now().await;
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancel_close_and_drain_after_dispatch_keep_one_unknown_terminal() {
        for cause in [
            TerminalCause::Cancelled,
            TerminalCause::RouteClosed,
            TerminalCause::Draining,
        ] {
            let mut planes = crate::tests::management_bound_planes(1, 1);
            let (ready, started) = tokio::sync::oneshot::channel();
            let (finish, finished) = tokio::sync::oneshot::channel();
            let input = std::sync::Mutex::new(Some((ready, finished)));
            planes.route_test_handler = Some(Arc::new(move || {
                let (ready, finished) = input.lock().unwrap().take().unwrap();
                Box::pin(async move {
                    let terminal = TerminalArbiter::current().unwrap();
                    terminal.set_step(CallStep::Dispatch);
                    assert!(terminal.gate.begin_mutation());
                    ready.send(()).unwrap();
                    let _ = finished.await;
                    assert!(!terminal.gate.begin_mutation());
                })
            }));
            let (tx, mut rx) = mpsc::channel(8);
            handle_frame(request(), &tx, &planes).await.unwrap();
            started.await.unwrap();
            let stop = match cause {
                TerminalCause::Cancelled => frame(FrameType::Cancel, 1, Vec::new()),
                TerminalCause::RouteClosed => frame(FrameType::Goodbye, 0, Vec::new()),
                TerminalCause::Draining => Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::Push,
                    control_flags(),
                    0,
                    0,
                    0,
                    serde_json::to_vec(
                        &json!({"op":"module.draining","reason":"restart","deadline_ms":123}),
                    )
                    .unwrap(),
                )
                .unwrap(),
                TerminalCause::Deadline => unreachable!(),
            };
            handle_frame(stop, &tx, &planes).await.unwrap();
            let reply = rx.recv().await.unwrap();
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "dispatch_outcome_unknown");
            assert_eq!(body["detail"]["reason"], cause.name());
            assert_eq!(planes.health.detached_workers(), 1);
            finish.send(()).unwrap();
            while planes.health.detached_workers() != 0 {
                tokio::task::yield_now().await;
            }
            assert!(rx.try_recv().is_err());
        }
    }

    struct NeverWriter;
    impl AsyncWrite for NeverWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            _: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Poll::Pending
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    #[tokio::test(start_paused = true)]
    async fn successful_enqueue_is_not_delivery_and_never_writer_fails_connection() {
        let planes = crate::tests::management_bound_planes(1, 1);
        let deadlines = Arc::clone(&planes.egress_deadlines);
        let (mut peer, mut reader) = tokio::io::duplex(64 * 1024);
        write_frame(&mut peer, &hello_ack()).await.unwrap();
        write_frame(&mut peer, &request()).await.unwrap();
        let config = ModuleConfig {
            connection_file_path: PathBuf::new(),
            module_id: "egress-test".into(),
            health: HealthConfig::DEFAULT,
            agent_cursor: false,
            browser: BrowserSurface::NotConfigured,
        };
        let arrival = tokio::time::Instant::now();
        let (_, reply_ms) = route_limits(&request(), &planes);
        let result = run_connection(&mut reader, NeverWriter, &config, planes).await;
        assert!(
            matches!(result, Err(ModuleError::Message(message)) if message.contains("terminal delivery deadline"))
        );
        assert_eq!(arrival.elapsed(), Duration::from_millis(reply_ms));
        assert_eq!(deadlines.pending.lock().unwrap().len(), 1);
    }

    struct MeteredWriter {
        rate: u64,
        waiting: Option<Pin<Box<tokio::time::Sleep>>>,
        bytes: Arc<std::sync::atomic::AtomicU64>,
        flushed: Arc<std::sync::atomic::AtomicU64>,
        flushes: Arc<std::sync::atomic::AtomicUsize>,
        start: tokio::time::Instant,
        flush_time: Duration,
    }
    impl MeteredWriter {
        fn new(rate: u64) -> Self {
            Self {
                rate,
                waiting: None,
                bytes: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                flushed: Arc::new(std::sync::atomic::AtomicU64::new(0)),
                flushes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                start: tokio::time::Instant::now(),
                flush_time: Duration::ZERO,
            }
        }
        fn wait_until(&mut self, cx: &mut Context<'_>, end: tokio::time::Instant) -> Poll<()> {
            let sleep = self
                .waiting
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(end)));
            if sleep.as_mut().poll(cx).is_pending() {
                return Poll::Pending;
            }
            self.waiting = None;
            Poll::Ready(())
        }
    }
    impl AsyncWrite for MeteredWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            let bytes = self.bytes.load(std::sync::atomic::Ordering::SeqCst) + buf.len() as u64;
            let end = self.start
                + self.flush_time
                + Duration::from_nanos((bytes * 1_000_000_000).div_ceil(self.rate));
            if self.wait_until(cx, end).is_pending() {
                return Poll::Pending;
            }
            self.bytes
                .fetch_add(buf.len() as u64, std::sync::atomic::Ordering::SeqCst);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            let bytes = self.bytes.load(std::sync::atomic::Ordering::SeqCst);
            let flush_time = self.flush_time + Duration::from_millis(budgets::EGRESS_FLUSH_MS);
            let end = self.start
                + flush_time
                + Duration::from_nanos((bytes * 1_000_000_000).div_ceil(self.rate));
            if self.wait_until(cx, end).is_pending() {
                return Poll::Pending;
            }
            self.flush_time = flush_time;
            self.flushed.store(
                self.bytes.load(std::sync::atomic::Ordering::SeqCst),
                std::sync::atomic::Ordering::SeqCst,
            );
            self.flushes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test(start_paused = true)]
    async fn continuous_producers_cannot_defer_flush_past_one_buffer() {
        let deadlines = Arc::new(ConnectionDeadlines::default());
        let (tx, rx) = mpsc::channel(EGRESS_BUFFER);
        let writer = MeteredWriter::new(budgets::EGRESS_MIN_BYTES_PER_S);
        let bytes = Arc::clone(&writer.bytes);
        let flushed = Arc::clone(&writer.flushed);
        let flushes = Arc::clone(&writer.flushes);
        let message = frame(FrameType::Push, 2, vec![0; 8192]);
        let frame_bytes = subc_protocol::HEADER_LEN as u64 + message.body.len() as u64;
        for _ in 0..EGRESS_BUFFER {
            tx.send(message.clone()).await.unwrap();
        }
        let producer = tokio::spawn(async move {
            loop {
                if tx.send(message.clone()).await.is_err() {
                    break;
                }
            }
        });
        let job = tokio::spawn(drain_writer(writer, rx, deadlines));
        while flushes.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::time::advance(Duration::from_millis(1)).await;
            if flushes.load(std::sync::atomic::Ordering::SeqCst) == 0 {
                assert!(
                    bytes.load(std::sync::atomic::Ordering::SeqCst)
                        <= EGRESS_BUFFER as u64 * frame_bytes,
                    "writer passed a full batch without flushing"
                );
            }
        }
        assert_eq!(
            flushed.load(std::sync::atomic::Ordering::SeqCst),
            EGRESS_BUFFER as u64 * frame_bytes
        );
        job.abort();
        producer.abort();
        let _ = job.await;
        let _ = producer.await;
    }

    #[tokio::test(start_paused = true)]
    async fn maximum_frames_at_throughput_floor_deliver_within_egress_budget() {
        let deadlines = Arc::new(ConnectionDeadlines::default());
        let (tx, rx) = mpsc::channel(EGRESS_BUFFER);
        let arrival = tokio::time::Instant::now();
        let writer = MeteredWriter::new(budgets::EGRESS_MIN_BYTES_PER_S);
        let flushed = Arc::clone(&writer.flushed);
        let job = tokio::spawn(drain_writer(writer, rx, Arc::clone(&deadlines)));
        // Use real maximum-size frame bodies; the writer charges actual bytes,
        // including transport framing, rather than a scaled timing surrogate.
        for _ in 0..2 * EGRESS_BUFFER - 1 {
            tx.send(frame(
                FrameType::Push,
                2,
                vec![0; subc_protocol::MAX_FRAME_BODY_LEN as usize],
            ))
            .await
            .unwrap();
        }
        let end = arrival + Duration::from_millis(budgets::EGRESS_SEND_MS);
        deadlines.arm((1, 1, 1), end);
        tx.send(frame(
            FrameType::Response,
            1,
            vec![0; subc_protocol::MAX_FRAME_BODY_LEN as usize],
        ))
        .await
        .unwrap();
        let delivered = async {
            loop {
                let changed = deadlines.changed.notified();
                tokio::pin!(changed);
                changed.as_mut().enable();
                if deadlines.pending.lock().unwrap().is_empty() {
                    break;
                }
                changed.await;
            }
        };
        tokio::select! {
            biased;
            _ = delivered => {},
            _ = deadlines.expired() => panic!("floor-rate peer lost its delivery deadline at {:?}; flushed {}", arrival.elapsed(), flushed.load(std::sync::atomic::Ordering::SeqCst)),
        }
        assert!(arrival.elapsed() <= Duration::from_millis(budgets::EGRESS_SEND_MS));
        assert_eq!(
            flushed.load(std::sync::atomic::Ordering::SeqCst),
            2 * EGRESS_BUFFER as u64
                * (subc_protocol::HEADER_LEN as u64 + subc_protocol::MAX_FRAME_BODY_LEN as u64)
        );
        job.abort();
        let _ = job.await;
    }

    #[tokio::test(start_paused = true)]
    async fn below_floor_and_waiting_producers_fail_connection_by_deadline() {
        let planes = crate::tests::management_bound_planes(1, 1);
        let deadlines = Arc::clone(&planes.egress_deadlines);
        let (mut peer, mut reader) = tokio::io::duplex(64 * 1024);
        write_frame(&mut peer, &hello_ack()).await.unwrap();
        let (_, reply_ms) = route_limits(&request(), &planes);
        for corr in 1..=3 * EGRESS_BUFFER as u64 {
            let mut request = request();
            request.header.corr = corr;
            write_frame(&mut peer, &request).await.unwrap();
        }
        let config = ModuleConfig {
            connection_file_path: PathBuf::new(),
            module_id: "egress-test".into(),
            health: HealthConfig::DEFAULT,
            agent_cursor: false,
            browser: BrowserSurface::NotConfigured,
        };
        let arrival = tokio::time::Instant::now();
        // One byte per second is below the declared floor and leaves more than
        // two channel buffers' worth of independent route senders suspended.
        let writer = MeteredWriter::new(1);
        let flushed = Arc::clone(&writer.flushed);
        let result = run_connection(&mut reader, writer, &config, planes).await;
        assert!(
            matches!(result, Err(ModuleError::Message(message)) if message.contains("terminal delivery deadline"))
        );
        assert_eq!(arrival.elapsed(), Duration::from_millis(reply_ms));
        assert!(deadlines.pending.lock().unwrap().len() > 2 * EGRESS_BUFFER);
        assert_eq!(flushed.load(std::sync::atomic::Ordering::SeqCst), 0);
    }
}

#[cfg(test)]
mod terminal_suffix_tests {
    use super::*;
    use crate::{
        handle_frame, journal, management, route_limits, CallObservation, PROTOCOL_VERSION,
    };
    use journal::call_records::{
        Begin, CallRecordError, CallRecordStorage, CallRecords, InMemoryCallRecordStorage,
    };

    struct BlockSettle {
        memory: InMemoryCallRecordStorage,
        writes: std::sync::atomic::AtomicUsize,
        blocked: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        release: std::sync::Mutex<std::sync::mpsc::Receiver<()>>,
    }
    impl BlockSettle {
        fn before_write(&self) {
            if self
                .writes
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                == 1
            {
                let _ = self.blocked.lock().unwrap().take().unwrap().send(());
                let _ = self.release.lock().unwrap().recv();
            }
        }
    }
    impl CallRecordStorage for BlockSettle {
        fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
            self.memory.load()
        }
        fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
            self.before_write();
            self.memory.append(bytes, version)
        }
        fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
            self.before_write();
            self.memory.replace(bytes, version)
        }
    }

    #[tokio::test(start_paused = true)]
    async fn blocked_release_and_settlement_keep_unknown_and_forward_within_suffix() {
        let mut planes = crate::tests::management_bound_planes(1, 1);
        let memory = InMemoryCallRecordStorage::new();
        let (settle_entered, settling) = tokio::sync::oneshot::channel();
        let (finish_settle, settle_release) = std::sync::mpsc::channel();
        planes.calls = Arc::new(CallRecords::open(
            Box::new(BlockSettle {
                memory: memory.clone(),
                writes: std::sync::atomic::AtomicUsize::new(0),
                blocked: std::sync::Mutex::new(Some(settle_entered)),
                release: std::sync::Mutex::new(settle_release),
            }),
            0,
        ));
        let Begin::Execute(ticket) =
            planes
                .calls
                .begin("suffix-principal", "suffix-key", "conversation", 0)
        else {
            panic!("admission")
        };
        let (ready, started) = tokio::sync::oneshot::channel();
        let (finish_worker, worker_done) = tokio::sync::oneshot::channel();
        let (finish_release, release_done) = tokio::sync::oneshot::channel();
        let inputs = std::sync::Mutex::new(Some((ticket, ready, worker_done, release_done)));
        planes.route_test_handler = Some(Arc::new(move || {
            let (ticket, ready, worker_done, release_done) = inputs.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let terminal = TerminalArbiter::current().unwrap();
                terminal.set_step(CallStep::Dispatch);
                assert!(terminal.gate.begin_mutation());
                terminal.set_release(async move {
                    let _ = release_done.await;
                    HeldState::Released
                });
                terminal.state.lock().unwrap().settlement = Some(PendingSettlement {
                    ticket: Some(ticket),
                    observation: CallObservation::new(),
                    unattributed_at_start:
                        cerebellum_core::dispatch_witness::unattributed_commit_count(),
                    request: (1, 1, 1),
                });
                ready.send(()).unwrap();
                let _ = worker_done.await;
                // Late evidence is diagnostic only; it cannot change settlement.
                terminal.witness.mark_committed();
            })
        }));
        let request = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            control_flags(),
            1,
            1,
            1,
            serde_json::to_vec(&json!({"method":management::OPEN_TARGET,"params":{}})).unwrap(),
        )
        .unwrap();
        let (envelope_ms, reply_ms) = route_limits(&request, &planes);
        let arrival = tokio::time::Instant::now();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(request, &tx, &planes).await.unwrap();
        started.await.unwrap();
        tokio::time::advance(Duration::from_millis(envelope_ms)).await;
        settling.await.unwrap();
        tokio::time::advance(Duration::from_millis(budgets::CALL_RECORD_SETTLE_MS)).await;
        let reply = rx.recv().await.unwrap();
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "dispatch_outcome_unknown");
        assert_eq!(body["detail"]["held_state"], "unknown");
        assert!(arrival.elapsed() <= Duration::from_millis(reply_ms));
        assert!(
            arrival.elapsed()
                <= Duration::from_millis(
                    envelope_ms + budgets::RELEASE_BUDGET_MS + budgets::CALL_RECORD_SETTLE_MS
                )
        );
        finish_worker.send(()).unwrap();
        finish_release.send(()).unwrap();
        finish_settle.send(()).unwrap();
        let replay = tokio::task::spawn_blocking({
            let calls = Arc::clone(&planes.calls);
            move || {
                calls.begin(
                    "suffix-principal",
                    "suffix-key",
                    "conversation",
                    wall_clock_ms(),
                )
            }
        })
        .await
        .unwrap();
        let Begin::Replay(replay) = replay else {
            panic!("settled replay")
        };
        assert_eq!(replay.readdressed(PROTOCOL_VERSION, 1, 1, 1), reply);
        while planes.health.detached_workers() != 0 {
            tokio::task::yield_now().await;
        }
        assert!(rx.try_recv().is_err());
    }
}
