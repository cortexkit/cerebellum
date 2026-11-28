//! Authenticated user-browser transport and non-replaying action lifecycle.
//!
//! Transport admission checks peer identity before reading the framed hello.
//! After admission, each relay contains a closed [`Message`]: `id`, `epoch`,
//! and a `body` tagged by `type`. The server sends Attach with a command, waits
//! for Attached, sends Dispatch exactly once, waits for Dispatched, then waits
//! for Completed/Refused. An extension must not execute input during Attach.
//! Dispatched and every terminal acknowledgement report `input_dispatched`.
//! Completed, Refused and Cancelled acknowledge debugger detachment as well.
//!
//! A large result uses ReplyStart (UTF-8 JSON byte count), ordered ReplyChunk
//! strings, then ReplyEnd. Each chunk and the whole transfer have independent
//! bounded deadlines. A result is not exposed until it is complete. No message
//! may exceed 1 MiB when serialized for Chrome. Commands above that limit are
//! refused locally rather than split or partially executed.
//!
//! Cancel stops attachment, input and chunk production; the extension replies
//! Cancelled only after detaching. Goodbye also releases the named route's
//! claims, without closing tabs. Missing cancellation acknowledgement closes
//! the connection: another action must never run beside a possibly attached
//! action. Socket loss makes the extension detach and stop all work. Neither
//! endpoint retries commands, including after a new connection epoch.

use crate::CancelHandle;
use cerebellum_bridge_protocol::MAX_FRAME_BYTES;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, watch};

pub const QUEUE_DEADLINE: Duration = Duration::from_secs(30);
pub const HOST_HELLO_DEADLINE: Duration = Duration::from_secs(5);
pub const ATTACH_DEADLINE: Duration = Duration::from_secs(5);
pub const DISPATCH_DEADLINE: Duration = Duration::from_secs(5);
pub const REPLY_DEADLINE: Duration = Duration::from_secs(30);
pub const CHUNK_DEADLINE: Duration = Duration::from_secs(5);
pub const CANCEL_DEADLINE: Duration = Duration::from_secs(2);
pub const WRITE_DEADLINE: Duration = Duration::from_secs(5);
pub const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
pub const MAX_CHUNK_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub channel: u16,
    pub epoch: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Message {
    pub id: u64,
    pub epoch: u64,
    pub body: MessageBody,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum MessageBody {
    Attach {
        route: Route,
        command: Value,
    },
    Attached,
    Dispatch,
    Dispatched {
        input_dispatched: bool,
    },
    Completed {
        result: Value,
        input_dispatched: bool,
        detached: bool,
    },
    Refused {
        reason: String,
        input_dispatched: bool,
        detached: bool,
    },
    Cancel,
    Cancelled {
        input_dispatched: bool,
        detached: bool,
    },
    Goodbye {
        route: Route,
    },
    ReplyStart {
        bytes: usize,
        input_dispatched: bool,
    },
    ReplyChunk {
        sequence: u32,
        data: String,
    },
    ReplyEnd {
        input_dispatched: bool,
        detached: bool,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionPhase {
    Queued,
    Attaching,
    Dispatched,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Terminal {
    Completed,
    Refused,
    Cancelled,
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NotConnected,
    ConnectionBusy,
    UnsignedPeer,
    WrongUser,
    ParentAttestationInvalid,
    ExtensionOriginMismatch,
    ProtocolMismatch,
    ProtocolError,
    QueueDeadline,
    AttachDeadline,
    DispatchDeadline,
    ReplyDeadline,
    ChunkDeadline,
    CancelDeadline,
    ConnectionLost,
    CommandTooLarge,
    CancelRequested,
    RouteGoodbye,
    ExtensionRefused,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ActionOutcome {
    pub id: u64,
    pub epoch: u64,
    pub phases: Vec<ActionPhase>,
    pub terminal: Terminal,
    pub reason: Option<Reason>,
    pub extension_reason: Option<String>,
    /// Null means dispatch was sent but the extension's input acknowledgement
    /// was lost. It must not be misreported as no input having occurred.
    pub input_dispatched: Option<bool>,
    pub result: Option<Value>,
    pub remedy: Option<&'static str>,
}

impl ActionOutcome {
    fn finish(&mut self, terminal: Terminal, reason: Option<Reason>) {
        self.terminal = terminal;
        self.reason = reason;
        self.remedy = match terminal {
            Terminal::OutcomeUnknown => Some("Read the tab again before deciding what to do; the command was not replayed."),
            _ if reason == Some(Reason::NotConnected) => Some("Load the Chrome extension and connect its native host, then use open_tab or claim_tab."),
            _ => None,
        };
    }
}

struct Connection {
    epoch: u64,
    outgoing: mpsc::Sender<Message>,
    closed: watch::Sender<bool>,
    /// The first reason passed to [`Connection::close`]: Goodbye could not
    /// enter the full writer queue, a reply could not be delivered, or the
    /// module shut down. Close only signals the socket tasks; they end the
    /// connection afterwards, so this reason wins over what they then see.
    ending: Option<DisconnectReason>,
}

impl Connection {
    fn close(&mut self, reason: DisconnectReason) {
        self.ending.get_or_insert(reason);
        self.closed.send_replace(true);
    }
}

/// The closed set of words health uses for why the latest user-browser
/// connection ended, indexed by [`DisconnectReason`]. Each word names only
/// what cerebellum itself observed:
///
/// - `peer_closed`: the native host closed the socket (end of file, including
///   a frame cut short by that close);
/// - `read_error`: reading from the socket failed for another reason;
/// - `protocol_error`: the host sent a frame that is not a valid relay message;
/// - `write_stalled`: a frame write passed its deadline, or Goodbye found the
///   writer queue full;
/// - `write_error`: a frame write failed for another reason;
/// - `reply_undeliverable`: a reply from the host could not be handed to its
///   waiting action;
/// - `cancel_deadline`: cleanup of a failed or cancelled action got no usable
///   detach acknowledgement in time (missing, late, or contradicting input
///   already reported as dispatched);
/// - `shutdown`: the module stopped the bridge.
pub const DISCONNECT_REASONS: [&str; 8] = [
    "peer_closed",
    "read_error",
    "protocol_error",
    "write_stalled",
    "write_error",
    "reply_undeliverable",
    "cancel_deadline",
    "shutdown",
];

/// Why a user-browser connection ended; see [`DISCONNECT_REASONS`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisconnectReason {
    PeerClosed,
    ReadError,
    ProtocolError,
    WriteStalled,
    WriteError,
    ReplyUndeliverable,
    CancelDeadline,
    Shutdown,
}

impl DisconnectReason {
    pub fn word(self) -> &'static str {
        DISCONNECT_REASONS[self as usize]
    }
}

/// Process-lifetime connection history for the health reply: counts, two
/// wall-clock times and one reason word, never anything that identifies a
/// route, agent, tab or page. Everything is an atomic, so the health lane
/// reads it without touching the bridge or any lock a stuck connection holds.
pub struct ConnectionGauges {
    connections: AtomicU64,
    /// Unix milliseconds of the latest accepted connection; 0 means none.
    connected_at_ms: AtomicU64,
    disconnects: AtomicU64,
    /// Unix milliseconds of the latest end; 0 means none.
    disconnected_at_ms: AtomicU64,
    /// Index into [`DISCONNECT_REASONS`] plus one; 0 means none.
    last_reason: AtomicU8,
}

impl ConnectionGauges {
    pub(crate) const fn new() -> Self {
        Self {
            connections: AtomicU64::new(0),
            connected_at_ms: AtomicU64::new(0),
            disconnects: AtomicU64::new(0),
            disconnected_at_ms: AtomicU64::new(0),
            last_reason: AtomicU8::new(0),
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    fn record_connected(&self) {
        self.connected_at_ms
            .store(wall_clock_ms(), Ordering::Relaxed);
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    fn record_disconnected(&self, reason: DisconnectReason) {
        self.last_reason.store(reason as u8 + 1, Ordering::Relaxed);
        self.disconnected_at_ms
            .store(wall_clock_ms(), Ordering::Relaxed);
        self.disconnects.fetch_add(1, Ordering::Relaxed);
    }

    /// Add `userBrowserConnections`, `userBrowserConnectedAtMs`,
    /// `userBrowserDisconnects`, `userBrowserDisconnectedAtMs` and
    /// `userBrowserLastDisconnectReason` to a health metrics object. The two
    /// times and the reason are `null` until the first connection or end.
    pub(crate) fn insert_into(&self, metrics: &mut serde_json::Map<String, Value>) {
        let time = |at: &AtomicU64| match at.load(Ordering::Relaxed) {
            0 => Value::Null,
            ms => Value::from(ms),
        };
        let reason = match self.last_reason.load(Ordering::Relaxed) {
            0 => Value::Null,
            index => DISCONNECT_REASONS
                .get(usize::from(index) - 1)
                .map_or(Value::Null, |word| Value::from(*word)),
        };
        metrics.insert(
            "userBrowserConnections".into(),
            Value::from(self.connections.load(Ordering::Relaxed)),
        );
        metrics.insert(
            "userBrowserConnectedAtMs".into(),
            time(&self.connected_at_ms),
        );
        metrics.insert(
            "userBrowserDisconnects".into(),
            Value::from(self.disconnects.load(Ordering::Relaxed)),
        );
        metrics.insert(
            "userBrowserDisconnectedAtMs".into(),
            time(&self.disconnected_at_ms),
        );
        metrics.insert("userBrowserLastDisconnectReason".into(), reason);
    }
}

/// Wall-clock Unix milliseconds, never 0 so that 0 can mean "never".
fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
        })
        .max(1)
}

struct State {
    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    next_epoch: u64,
    next_id: u64,
    stopped: bool,
    connection: Option<Connection>,
    replies: BTreeMap<u64, mpsc::Sender<MessageBody>>,
    calls: BTreeMap<u64, (Route, CancelHandle)>,
    controls: BTreeMap<u64, CallControl>,
    /// Whether the socket writer wrote each action's Attach (`true`) or
    /// dropped it because the action had already been cancelled (`false`),
    /// as it first judged that Attach.
    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    attaches_written: BTreeMap<u64, bool>,
}

struct Inner {
    state: Mutex<State>,
    lane: tokio::sync::Mutex<()>,
    target: crate::user_browser::UserBrowser,
    gauges: &'static ConnectionGauges,
}

#[derive(Clone)]
pub struct UserBrowserBridge(Arc<Inner>);

#[derive(Clone)]
struct CallControl {
    terminal: Option<Arc<crate::TerminalArbiter>>,
    deadline: Option<tokio::time::Instant>,
    execution: Option<Arc<crate::user_browser::UserExecution>>,
    _permits: Option<Arc<crate::blocking_permits::CallPermits>>,
}

impl CallControl {
    fn current() -> Self {
        Self {
            terminal: crate::TerminalArbiter::current(),
            deadline: crate::user_browser::EXECUTION
                .try_with(|execution| execution.deadline())
                .ok()
                .or_else(|| crate::call_context::CALL_DEADLINE.try_with(|end| *end).ok()),
            execution: crate::user_browser::EXECUTION.try_with(Arc::clone).ok(),
            _permits: crate::user_browser::EXECUTION_PERMITS
                .try_with(Arc::clone)
                .ok(),
        }
    }

    fn live(&self) -> bool {
        if self
            .deadline
            .is_some_and(|end| tokio::time::Instant::now() >= end)
        {
            if let Some(terminal) = &self.terminal {
                terminal.stop(crate::TerminalCause::Deadline);
            }
            return false;
        }
        !self
            .terminal
            .as_ref()
            .is_some_and(|terminal| terminal.gate.stopped())
            && !self
                .execution
                .as_ref()
                .is_some_and(|execution| execution.stopped())
    }
}

impl Default for UserBrowserBridge {
    fn default() -> Self {
        Self::new()
    }
}

impl UserBrowserBridge {
    pub fn new() -> Self {
        Self::with_user_grants(Arc::new(
            crate::browser_standing_grants::StandingBrowserGrants::in_memory(),
        ))
    }

    pub(crate) fn with_user_grants(
        grants: Arc<crate::browser_standing_grants::StandingBrowserGrants>,
    ) -> Self {
        Self::with_gauges(grants, &crate::USER_BROWSER_CONNECTION_GAUGES)
    }

    /// A bridge that records its connection history into `gauges` instead of
    /// the process-wide health gauges, so a test can read exact values while
    /// other tests connect their own bridges.
    #[cfg(all(test, unix))]
    pub(crate) fn with_gauges_for_test(gauges: &'static ConnectionGauges) -> Self {
        Self::with_gauges(
            Arc::new(crate::browser_standing_grants::StandingBrowserGrants::in_memory()),
            gauges,
        )
    }

    fn with_gauges(
        grants: Arc<crate::browser_standing_grants::StandingBrowserGrants>,
        gauges: &'static ConnectionGauges,
    ) -> Self {
        // Keep epochs exactly representable by JavaScript. A daemon restart and
        // each Chrome extension service-worker reconnect need distinct epochs
        // so neither can consume the previous connection's replies.
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).expect("connection epoch entropy unavailable");
        #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
        let epoch = (u64::from_le_bytes(random) & ((1 << 52) - 1)).max(1);
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
                next_epoch: epoch,
                next_id: 1,
                stopped: false,
                connection: None,
                replies: BTreeMap::new(),
                calls: BTreeMap::new(),
                controls: BTreeMap::new(),
                #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
                attaches_written: BTreeMap::new(),
            }),
            lane: tokio::sync::Mutex::new(()),
            target: crate::user_browser::UserBrowser::new(grants),
            gauges,
        }))
    }

    pub(crate) fn target(&self) -> &crate::user_browser::UserBrowser {
        &self.0.target
    }

    #[cfg(test)]
    pub(crate) fn connect_for_policy_test(&self) -> (u64, mpsc::Receiver<Message>) {
        let (epoch, receiver, _) = self.connect().expect("isolated extension double connects");
        (epoch, receiver)
    }

    #[cfg(test)]
    pub(crate) fn receive_for_policy_test(&self, message: Message) {
        self.receive(message);
    }

    #[cfg(test)]
    pub(crate) fn disconnect_for_policy_test(&self, epoch: u64) {
        self.disconnect(epoch, DisconnectReason::PeerClosed);
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.0
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn connected_epoch(&self) -> Option<u64> {
        self.state()
            .connection
            .as_ref()
            .map(|connection| connection.epoch)
    }

    /// Call only after acquiring the request's FIFO turn in `browser_queue` and
    /// verifying route ownership of the named tab and site consent for
    /// `browser:"user"`. This bridge checks transport provenance, not permission
    /// to execute browser actions.
    pub async fn invoke(
        &self,
        route: Route,
        command: Value,
        cancel: CancelHandle,
    ) -> ActionOutcome {
        let bridge = self.clone();
        let control = CallControl::current();
        // Dropping the caller must still let the extension detach from Chrome.
        // Carry its dispatch gate and deadline into cleanup so it cannot start
        // fresh work after the reply, and retain its permits until cleanup ends.
        // Tokio does not inherit these task-local values across spawn.
        tokio::spawn(async move {
            let action = bridge.invoke_inner(route, command, cancel.clone(), &control);
            tokio::pin!(action);
            let outcome = if let Some(end) = control.deadline {
                tokio::select! {
                    biased;
                    outcome = &mut action => outcome,
                    _ = tokio::time::sleep_until(end) => {
                        if let Some(terminal) = &control.terminal {
                            terminal.stop(crate::TerminalCause::Deadline);
                        }
                        cancel.cancel();
                        action.await
                    }
                }
            } else {
                action.await
            };
            if let Some(execution) = &control.execution {
                execution.finish(!matches!(
                    outcome.reason,
                    Some(Reason::CancelDeadline | Reason::ConnectionLost)
                ));
            }
            outcome
        })
        .await
        .expect("bridge action task panicked")
    }

    pub fn goodbye(&self, route: Route) {
        self.0.target.end_route(route);
        let mut state = self.state();
        for (owner, cancel) in state.calls.values() {
            if *owner == route {
                cancel.cancel();
            }
        }
        if let Some(connection) = state.connection.as_mut() {
            let message = Message {
                id: 0,
                epoch: connection.epoch,
                body: MessageBody::Goodbye { route },
            };
            // A saturated writer cannot promise timely Goodbye or detach.
            if connection.outgoing.try_send(message).is_err() {
                connection.close(DisconnectReason::WriteStalled);
            }
        }
    }

    pub fn shutdown(&self) {
        self.0.target.disconnect();
        let mut state = self.state();
        state.stopped = true;
        for (_, cancel) in state.calls.values() {
            cancel.cancel();
        }
        if let Some(connection) = state.connection.as_mut() {
            connection.close(DisconnectReason::Shutdown);
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    fn connect(&self) -> Result<(u64, mpsc::Receiver<Message>, watch::Receiver<bool>), Reason> {
        let mut state = self.state();
        if state.stopped {
            return Err(Reason::NotConnected);
        }
        if state.connection.is_some() {
            return Err(Reason::ConnectionBusy);
        }
        let epoch = state.next_epoch;
        state.next_epoch = state.next_epoch.checked_add(1).expect("epoch exhausted");
        let (outgoing, receiver) = mpsc::channel(16);
        let (closed, stop) = watch::channel(false);
        state.connection = Some(Connection {
            epoch,
            outgoing,
            closed,
            ending: None,
        });
        self.0.gauges.record_connected();
        Ok((epoch, receiver, stop))
    }

    /// End the connection with this epoch, if it is still the current one.
    /// `reason` is what the caller saw; a reason recorded earlier by whoever
    /// first asked the connection to close takes precedence.
    fn disconnect(&self, epoch: u64, reason: DisconnectReason) {
        let mut state = self.state();
        if state.connection.as_ref().map(|c| c.epoch) == Some(epoch) {
            self.0.target.disconnect();
            if let Some(connection) = state.connection.take() {
                connection.closed.send_replace(true);
                self.0
                    .gauges
                    .record_disconnected(connection.ending.unwrap_or(reason));
            }
            state.replies.clear();
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    fn receive(&self, message: Message) {
        let mut state = self.state();
        if state.connection.as_ref().map(|c| c.epoch) != Some(message.epoch) {
            return;
        }
        let undeliverable = state
            .replies
            .get(&message.id)
            .is_some_and(|sender| sender.try_send(message.body).is_err());
        if undeliverable {
            if let Some(connection) = state.connection.as_mut() {
                connection.close(DisconnectReason::ReplyUndeliverable);
            }
        }
    }

    #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
    pub(super) fn should_send(&self, message: &Message) -> bool {
        let mut state = self.state();
        if state.stopped || state.connection.as_ref().map(|c| c.epoch) != Some(message.epoch) {
            return false;
        }
        match message.body {
            MessageBody::Attach { .. } | MessageBody::Dispatch => {
                let registered = state.calls.get(&message.id);
                let send = registered.is_some_and(|(_, cancel)| !cancel.is_cancelled())
                    && state
                        .controls
                        .get(&message.id)
                        .is_none_or(CallControl::live);
                if registered.is_some() && matches!(message.body, MessageBody::Attach { .. }) {
                    state.attaches_written.entry(message.id).or_insert(send);
                }
                send
            }
            // The writer judges an action's Attach before the Cancel queued
            // behind it. When it dropped that Attach, the extension has no
            // entry to cancel and would never answer, so the receipt the
            // cleanup waits for is given here instead of sending the Cancel.
            // An Attach that was written, or not yet judged, keeps the Cancel.
            MessageBody::Cancel if state.attaches_written.get(&message.id) == Some(&false) => {
                if let Some(sender) = state.replies.get(&message.id) {
                    let _ = sender.try_send(MessageBody::Cancelled {
                        input_dispatched: false,
                        detached: true,
                    });
                }
                false
            }
            _ => true,
        }
    }

    async fn invoke_inner(
        &self,
        route: Route,
        command: Value,
        cancel: CancelHandle,
        control: &CallControl,
    ) -> ActionOutcome {
        let (id, epoch, outgoing, mut closed) = {
            let mut state = self.state();
            let id = state.next_id;
            state.next_id += 1;
            match &state.connection {
                Some(c) => (
                    id,
                    c.epoch,
                    Some(c.outgoing.clone()),
                    Some(c.closed.subscribe()),
                ),
                None => (id, 0, None, None),
            }
        };
        let mut outcome = ActionOutcome {
            id,
            epoch,
            phases: vec![ActionPhase::Queued],
            terminal: Terminal::Refused,
            reason: None,
            extension_reason: None,
            input_dispatched: Some(false),
            result: None,
            remedy: None,
        };
        let Some(outgoing) = outgoing else {
            outcome.finish(Terminal::Refused, Some(Reason::NotConnected));
            return outcome;
        };
        let closed = closed.as_mut().expect("connected action has close signal");
        self.state().calls.insert(id, (route, cancel.clone()));
        self.state().controls.insert(id, control.clone());
        let _registration = Registration {
            bridge: self.clone(),
            id,
        };
        let _turn = tokio::select! {
            biased;
            _ = cancel.cancelled() => { outcome.finish(Terminal::Cancelled, Some(Reason::CancelRequested)); return outcome; }
            _ = wait_closed(closed) => { outcome.finish(Terminal::Refused, Some(Reason::ConnectionLost)); return outcome; }
            turn = tokio::time::timeout(QUEUE_DEADLINE, self.0.lane.lock()) => match turn {
                Ok(turn) => turn,
                Err(_) => { outcome.finish(Terminal::Refused, Some(Reason::QueueDeadline)); return outcome; }
            },
        };
        if self.connected_epoch() != Some(epoch) {
            outcome.finish(Terminal::Refused, Some(Reason::ConnectionLost));
            return outcome;
        }
        if !control.live() {
            outcome.finish(Terminal::Cancelled, Some(Reason::CancelRequested));
            return outcome;
        }
        if let Some(execution) = &control.execution {
            execution.begin(false);
        }
        let held = command["commands"].as_array().is_some_and(|commands| {
            commands.iter().any(|command| {
                matches!(
                    command["params"]["type"].as_str(),
                    Some("mousePressed" | "keyDown" | "rawKeyDown")
                )
            })
        });
        let mutating = crate::user_browser::mutating_plan(&command);
        let attach = Message {
            id,
            epoch,
            body: MessageBody::Attach { route, command },
        };
        if serde_json::to_vec(&attach).map_or(true, |bytes| bytes.len() > MAX_MESSAGE_BYTES) {
            outcome.finish(Terminal::Refused, Some(Reason::CommandTooLarge));
            return outcome;
        }
        let (sender, mut replies) = mpsc::channel(16);
        self.state().replies.insert(id, sender);
        outcome.phases.push(ActionPhase::Attaching);
        let mut failure = send_message(&outgoing, attach, &cancel, closed).await.err();
        // An Attach refused here never reached the writer queue, so the
        // extension cannot have heard of this action.
        let attach_queued = failure.is_none();
        if failure.is_none() {
            failure = match next_reply(
                &mut replies,
                &cancel,
                closed,
                ATTACH_DEADLINE,
                Reason::AttachDeadline,
            )
            .await
            {
                Ok(MessageBody::Attached) => None,
                Ok(MessageBody::Refused {
                    reason,
                    input_dispatched: false,
                    detached: true,
                }) => {
                    outcome.extension_reason = Some(reason);
                    outcome.finish(Terminal::Refused, Some(Reason::ExtensionRefused));
                    return outcome;
                }
                Ok(_) => Some(Reason::ProtocolError),
                Err(reason) => Some(reason),
            };
        }
        if failure.is_none() {
            // Once Dispatch is handed to the writer, input may have occurred
            // even if the acknowledgement never comes back. Never resend it.
            let dispatch = Message {
                id,
                epoch,
                body: MessageBody::Dispatch,
            };
            let allowed = control.live()
                && (!mutating
                    || control.terminal.as_ref().is_none_or(|terminal| {
                        terminal.set_step(crate::CallStep::Dispatch);
                        terminal.gate.begin_mutation()
                    }));
            if allowed {
                if let Some(execution) = &control.execution {
                    execution.begin(held);
                    if held {
                        if let (Some(terminal), Some(permits)) =
                            (&control.terminal, &control._permits)
                        {
                            execution.release_receipt(terminal, permits);
                        }
                    }
                }
            }
            let sent = if allowed {
                send_message(&outgoing, dispatch, &cancel, closed).await
            } else {
                Err(Reason::CancelRequested)
            };
            match sent {
                Ok(()) => {
                    outcome.phases.push(ActionPhase::Dispatched);
                    outcome.input_dispatched = None;
                    failure = match next_reply(
                        &mut replies,
                        &cancel,
                        closed,
                        DISPATCH_DEADLINE,
                        Reason::DispatchDeadline,
                    )
                    .await
                    {
                        Ok(MessageBody::Dispatched { input_dispatched }) => {
                            outcome.input_dispatched = Some(input_dispatched);
                            None
                        }
                        Ok(_) => Some(Reason::ProtocolError),
                        Err(reason) => Some(reason),
                    };
                }
                Err(reason) => failure = Some(reason),
            }
        }
        if failure.is_none() {
            failure = self
                .collect_reply(&mut outcome, &mut replies, &cancel, closed)
                .await
                .err();
            if failure.is_none() {
                return outcome;
            }
        }
        let reason = failure.expect("failed phase has a reason");
        if reason == Reason::ConnectionLost {
            if outcome.phases.contains(&ActionPhase::Dispatched)
                && outcome.input_dispatched != Some(true)
            {
                outcome.input_dispatched = None;
            }
            outcome.finish(
                if outcome.phases.contains(&ActionPhase::Dispatched) {
                    Terminal::OutcomeUnknown
                } else {
                    Terminal::Refused
                },
                Some(reason),
            );
            return outcome;
        }
        let terminal = if reason == Reason::CancelRequested {
            Terminal::Cancelled
        } else if outcome.phases.contains(&ActionPhase::Dispatched) {
            Terminal::OutcomeUnknown
        } else {
            Terminal::Refused
        };
        // Prevent an Attach or Dispatch still queued in the socket writer from
        // being sent after this action has begun cancellation or timed out.
        cancel.cancel();
        if !attach_queued {
            outcome.finish(terminal, Some(reason));
            return outcome;
        }
        // Cleanup is bounded separately, and deliberately ignores an already
        // cancelled request while waiting for the extension's detach receipt.
        let cleanup = async {
            outgoing
                .send(Message {
                    id,
                    epoch,
                    body: MessageBody::Cancel,
                })
                .await
                .map_err(|_| ())?;
            loop {
                match replies.recv().await {
                    Some(MessageBody::Cancelled {
                        input_dispatched,
                        detached: true,
                    }) => return Ok(input_dispatched),
                    // The extension may have finished the action before it
                    // saw the Cancel: it then ignores the Cancel, and the
                    // detached terminal it already sent is the proof that it
                    // let go. Its content is discarded; only its
                    // `input_dispatched` value is kept.
                    Some(
                        MessageBody::Completed {
                            input_dispatched,
                            detached: true,
                            ..
                        }
                        | MessageBody::Refused {
                            input_dispatched,
                            detached: true,
                            ..
                        }
                        | MessageBody::ReplyEnd {
                            input_dispatched,
                            detached: true,
                        },
                    ) => return Ok(input_dispatched),
                    Some(_) => {}
                    None => return Err(()),
                }
            }
        };
        match tokio::time::timeout(CANCEL_DEADLINE, cleanup).await {
            Ok(Ok(input)) if outcome.input_dispatched != Some(true) || input => {
                outcome.input_dispatched = Some(input);
                outcome.finish(terminal, Some(reason));
            }
            _ => {
                self.disconnect(epoch, DisconnectReason::CancelDeadline);
                if outcome.phases.contains(&ActionPhase::Dispatched)
                    && outcome.input_dispatched != Some(true)
                {
                    outcome.input_dispatched = None;
                }
                outcome.finish(
                    if outcome.phases.contains(&ActionPhase::Dispatched) {
                        Terminal::OutcomeUnknown
                    } else {
                        terminal
                    },
                    Some(Reason::CancelDeadline),
                );
            }
        }
        outcome
    }

    async fn collect_reply(
        &self,
        outcome: &mut ActionOutcome,
        replies: &mut mpsc::Receiver<MessageBody>,
        cancel: &CancelHandle,
        closed: &mut watch::Receiver<bool>,
    ) -> Result<(), Reason> {
        let deadline = tokio::time::Instant::now() + REPLY_DEADLINE;
        let message = next_reply(
            replies,
            cancel,
            closed,
            REPLY_DEADLINE,
            Reason::ReplyDeadline,
        )
        .await?;
        match message {
            MessageBody::Completed {
                result,
                input_dispatched,
                detached: true,
            } => {
                confirm_input(outcome, input_dispatched)?;
                outcome.result = Some(result);
                outcome.finish(Terminal::Completed, None);
                Ok(())
            }
            MessageBody::Refused {
                reason,
                input_dispatched,
                detached: true,
            } => {
                confirm_input(outcome, input_dispatched)?;
                outcome.extension_reason = Some(reason);
                outcome.finish(Terminal::Refused, Some(Reason::ExtensionRefused));
                Ok(())
            }
            MessageBody::ReplyStart {
                bytes,
                input_dispatched,
            } if bytes <= MAX_FRAME_BYTES => {
                confirm_input(outcome, input_dispatched)?;
                let mut buffer = String::new();
                let mut sequence = 0;
                loop {
                    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                    let (wait, reason) = if remaining < CHUNK_DEADLINE {
                        (remaining, Reason::ReplyDeadline)
                    } else {
                        (CHUNK_DEADLINE, Reason::ChunkDeadline)
                    };
                    match next_reply(replies, cancel, closed, wait, reason).await? {
                        MessageBody::ReplyChunk {
                            sequence: received,
                            data,
                        } if received == sequence
                            && data.len() <= MAX_CHUNK_BYTES
                            && buffer.len() + data.len() <= bytes =>
                        {
                            if data.is_empty() {
                                return Err(Reason::ProtocolError);
                            }
                            buffer.push_str(&data);
                            sequence += 1;
                        }
                        MessageBody::ReplyEnd {
                            input_dispatched,
                            detached: true,
                        } if buffer.len() == bytes => {
                            confirm_input(outcome, input_dispatched)?;
                            outcome.result = Some(
                                serde_json::from_str(&buffer).map_err(|_| Reason::ProtocolError)?,
                            );
                            outcome.finish(Terminal::Completed, None);
                            return Ok(());
                        }
                        _ => return Err(Reason::ProtocolError),
                    }
                }
            }
            _ => Err(Reason::ProtocolError),
        }
    }
}

fn confirm_input(outcome: &mut ActionOutcome, input: bool) -> Result<(), Reason> {
    if outcome.input_dispatched == Some(true) && !input {
        return Err(Reason::ProtocolError);
    }
    outcome.input_dispatched = Some(input);
    Ok(())
}

struct Registration {
    bridge: UserBrowserBridge,
    id: u64,
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self.bridge.state();
        state.calls.remove(&self.id);
        state.controls.remove(&self.id);
        state.replies.remove(&self.id);
        #[cfg(any(target_os = "macos", target_os = "linux", windows, test))]
        state.attaches_written.remove(&self.id);
    }
}

async fn wait_closed(closed: &mut watch::Receiver<bool>) {
    let _ = closed.wait_for(|value| *value).await;
}

async fn send_message(
    outgoing: &mpsc::Sender<Message>,
    message: Message,
    cancel: &CancelHandle,
    closed: &mut watch::Receiver<bool>,
) -> Result<(), Reason> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Reason::CancelRequested),
        _ = wait_closed(closed) => Err(Reason::ConnectionLost),
        result = tokio::time::timeout(WRITE_DEADLINE, outgoing.send(message)) => match result {
            Ok(Ok(())) => Ok(()),
            _ => Err(Reason::ConnectionLost),
        },
    }
}

async fn next_reply(
    replies: &mut mpsc::Receiver<MessageBody>,
    cancel: &CancelHandle,
    closed: &mut watch::Receiver<bool>,
    duration: Duration,
    reason: Reason,
) -> Result<MessageBody, Reason> {
    tokio::select! {
        biased;
        _ = cancel.cancelled() => Err(Reason::CancelRequested),
        _ = wait_closed(closed) => Err(Reason::ConnectionLost),
        result = tokio::time::timeout(duration, replies.recv()) => match result {
            Ok(Some(message)) => Ok(message),
            Ok(None) => Err(Reason::ConnectionLost),
            Err(_) => Err(reason),
        },
    }
}

#[cfg(any(target_os = "macos", target_os = "linux", windows, all(unix, test)))]
mod admission;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(any(target_os = "macos", target_os = "linux", windows, all(unix, test)))]
mod listener;
#[cfg(any(target_os = "macos", target_os = "linux", windows, all(unix, test)))]
pub use listener::BridgeListener;
#[cfg(any(target_os = "macos", target_os = "linux", windows, all(unix, test)))]
mod session;
#[cfg(any(target_os = "macos", target_os = "linux", all(unix, test)))]
mod socket;
#[cfg(windows)]
mod windows;

#[cfg(test)]
mod tests;
