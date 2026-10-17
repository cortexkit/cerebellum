//! Authenticated user-browser transport and non-replaying action lifecycle.
//!
//! Socket framing and host admission live in `cerebellum-bridge-protocol`.
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
}

struct State {
    #[cfg(any(target_os = "macos", test))]
    next_epoch: u64,
    next_id: u64,
    stopped: bool,
    connection: Option<Connection>,
    replies: BTreeMap<u64, mpsc::Sender<MessageBody>>,
    calls: BTreeMap<u64, (Route, CancelHandle)>,
    controls: BTreeMap<u64, CallControl>,
}

struct Inner {
    state: Mutex<State>,
    lane: tokio::sync::Mutex<()>,
    target: crate::user_browser::UserBrowser,
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
        // Keep epochs exactly representable by JavaScript. A daemon restart and
        // each Chrome extension service-worker reconnect need distinct epochs
        // so neither can consume the previous connection's replies.
        let mut random = [0; 8];
        getrandom::getrandom(&mut random).expect("connection epoch entropy unavailable");
        #[cfg(any(target_os = "macos", test))]
        let epoch = (u64::from_le_bytes(random) & ((1 << 52) - 1)).max(1);
        Self(Arc::new(Inner {
            state: Mutex::new(State {
                #[cfg(any(target_os = "macos", test))]
                next_epoch: epoch,
                next_id: 1,
                stopped: false,
                connection: None,
                replies: BTreeMap::new(),
                calls: BTreeMap::new(),
                controls: BTreeMap::new(),
            }),
            lane: tokio::sync::Mutex::new(()),
            target: crate::user_browser::UserBrowser::new(grants),
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
        self.disconnect(epoch);
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
        let state = self.state();
        for (owner, cancel) in state.calls.values() {
            if *owner == route {
                cancel.cancel();
            }
        }
        if let Some(connection) = &state.connection {
            let message = Message {
                id: 0,
                epoch: connection.epoch,
                body: MessageBody::Goodbye { route },
            };
            // A saturated writer cannot promise timely Goodbye or detach.
            if connection.outgoing.try_send(message).is_err() {
                connection.closed.send_replace(true);
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
        if let Some(connection) = &state.connection {
            connection.closed.send_replace(true);
        }
    }

    #[cfg(any(target_os = "macos", test))]
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
        });
        Ok((epoch, receiver, stop))
    }

    fn disconnect(&self, epoch: u64) {
        let mut state = self.state();
        if state.connection.as_ref().map(|c| c.epoch) == Some(epoch) {
            self.0.target.disconnect();
            if let Some(connection) = state.connection.take() {
                connection.closed.send_replace(true);
            }
            state.replies.clear();
        }
    }

    #[cfg(any(target_os = "macos", test))]
    fn receive(&self, message: Message) {
        let state = self.state();
        if state.connection.as_ref().map(|c| c.epoch) != Some(message.epoch) {
            return;
        }
        if let Some(sender) = state.replies.get(&message.id) {
            if sender.try_send(message.body).is_err() {
                if let Some(connection) = &state.connection {
                    connection.closed.send_replace(true);
                }
            }
        }
    }

    #[cfg(any(target_os = "macos", test))]
    pub(super) fn should_send(&self, message: &Message) -> bool {
        let state = self.state();
        if state.stopped || state.connection.as_ref().map(|c| c.epoch) != Some(message.epoch) {
            return false;
        }
        match message.body {
            MessageBody::Attach { .. } | MessageBody::Dispatch => {
                state
                    .calls
                    .get(&message.id)
                    .is_some_and(|(_, cancel)| !cancel.is_cancelled())
                    && state
                        .controls
                        .get(&message.id)
                        .is_none_or(CallControl::live)
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
                self.disconnect(epoch);
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

#[cfg(any(target_os = "macos", all(unix, test)))]
mod socket;
#[cfg(any(target_os = "macos", all(unix, test)))]
pub use socket::BridgeListener;

#[cfg(test)]
mod tests;
