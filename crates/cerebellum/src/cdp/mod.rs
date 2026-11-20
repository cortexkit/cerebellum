//! Small, fail-closed CDP wire vertical used by the browser plane.
//!
//! The browser adapter owns the socket; this module owns message framing,
//! command correlation, identity checks, and bounded pending/event state.  It
//! intentionally does not know about Chromium's page model or grant policy.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use serde::Serialize;
use serde_json::{Map, Value};
use zeroize::Zeroizing;

pub const MAX_MESSAGE_BYTES: usize = 67_108_864;
pub const MAX_PENDING_COMMANDS: usize = 4_096;
pub const MAX_QUEUED_EVENTS: usize = 65_536;
pub const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
pub const COMMAND_TIMEOUT: Duration = Duration::from_millis(30_000);

/// Incrementally decodes the NUL-delimited framing used by a CDP pipe.
///
/// The decoder moves with the pipe after launch readiness so bytes from one
/// descriptor are never split across independent framing states.
#[derive(Debug, Default)]
pub struct CdpFrameDecoder {
    frame: Vec<u8>,
    discarding_oversized_frame: bool,
}

impl CdpFrameDecoder {
    pub fn push(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        for &byte in bytes {
            if byte == 0 {
                if self.discarding_oversized_frame {
                    self.discarding_oversized_frame = false;
                    self.frame.clear();
                } else {
                    frames.push(std::mem::take(&mut self.frame));
                }
                continue;
            }
            if self.discarding_oversized_frame {
                continue;
            }
            if self.frame.len() == MAX_MESSAGE_BYTES {
                self.frame.clear();
                self.discarding_oversized_frame = true;
                continue;
            }
            self.frame.push(byte);
        }
        frames
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CdpError {
    InvalidUtf8,
    MessageTooLarge { bytes: usize, bound: usize },
    InvalidJson,
    TrailingBytes,
    BinaryMessage,
    InvalidCommand(&'static str),
    ProtocolFailure(&'static str),
    UnknownResponseId(u64),
    DuplicateResponseId(u64),
    PendingCapacity,
    IdExhausted,
    DeadlineExpired,
    SessionMismatch,
}

impl fmt::Display for CdpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUtf8 => f.write_str("cdp message is not UTF-8"),
            Self::MessageTooLarge { bytes, bound } => {
                write!(f, "cdp message is {bytes} bytes; bound is {bound}")
            }
            Self::InvalidJson => f.write_str("invalid cdp JSON"),
            Self::TrailingBytes => f.write_str("trailing bytes after cdp JSON value"),
            Self::BinaryMessage => f.write_str("binary cdp messages are not supported"),
            Self::InvalidCommand(reason) | Self::ProtocolFailure(reason) => f.write_str(reason),
            Self::UnknownResponseId(id) => write!(f, "unknown cdp response id {id}"),
            Self::DuplicateResponseId(id) => write!(f, "duplicate cdp response id {id}"),
            Self::PendingCapacity => f.write_str("cdp pending-command capacity exhausted"),
            Self::IdExhausted => f.write_str("cdp command id exhausted"),
            Self::DeadlineExpired => f.write_str("cdp command deadline expired"),
            Self::SessionMismatch => f.write_str("cdp session identity mismatch"),
        }
    }
}
impl std::error::Error for CdpError {}

#[derive(Clone, PartialEq)]
pub struct CdpCommand {
    pub id: u64,
    pub method: String,
    pub params: Option<Map<String, Value>>,
    pub session_id: Option<String>,
    pub committed_at: Instant,
}

impl fmt::Debug for CdpCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CdpCommand")
            .field("id", &self.id)
            .field("method", &self.method)
            .field("params", &"<withheld>")
            .field("session_id", &self.session_id)
            .field("committed_at", &self.committed_at)
            .finish()
    }
}

#[derive(Serialize)]
struct CommandFrame<'a, P: Serialize> {
    id: u64,
    method: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    params: Option<&'a P>,
    #[serde(rename = "sessionId", skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
}

#[derive(Default)]
struct SerializedLength(usize);

impl std::io::Write for SerializedLength {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl CdpCommand {
    pub fn json_bytes(&self) -> Result<Vec<u8>, CdpError> {
        let frame = self.frame(self.params.as_ref());
        let bytes = serde_json::to_vec(&frame).map_err(|_| CdpError::InvalidJson)?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CdpError::MessageTooLarge {
                bytes: bytes.len(),
                bound: MAX_MESSAGE_BYTES,
            });
        }
        Ok(bytes)
    }

    fn frame<'a, P: Serialize>(&'a self, params: Option<&'a P>) -> CommandFrame<'a, P> {
        CommandFrame {
            id: self.id,
            method: &self.method,
            params,
            session_id: self.session_id.as_deref(),
        }
    }

    /// Borrow credential params directly from their zeroizing owner. No JSON
    /// value tree or pending command owns a second copy of the credentials.
    pub(crate) fn sensitive_json_bytes<P: Serialize>(
        &self,
        params: &P,
    ) -> Result<Zeroizing<Vec<u8>>, CdpError> {
        let frame = self.frame(Some(params));
        let mut length = SerializedLength::default();
        serde_json::to_writer(&mut length, &frame).map_err(|_| CdpError::InvalidJson)?;
        if length.0 > MAX_MESSAGE_BYTES {
            return Err(CdpError::MessageTooLarge {
                bytes: length.0,
                bound: MAX_MESSAGE_BYTES,
            });
        }
        // Size before writing secrets: growing a Vec could leave an unwiped
        // allocation behind. Reserve the pipe delimiter too, then write only
        // through a fixed slice, which cannot reallocate even on encoding error.
        let mut bytes = Zeroizing::new(vec![0; length.0 + 1]);
        serde_json::to_writer(std::io::Cursor::new(&mut bytes[..length.0]), &frame)
            .map_err(|_| CdpError::InvalidJson)?;
        bytes.truncate(length.0);
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CdpResponse {
    pub id: u64,
    pub session_id: Option<String>,
    pub result: Option<Map<String, Value>>,
    pub error: Option<Map<String, Value>>,
    /// A validated late response to a command whose caller stopped waiting.
    pub abandoned: bool,
}

/// Conservative capacity accounting for retained JSON, including map nodes.
/// It measures metadata ownership, not renderer memory or transient decoding.
pub(crate) fn retained_json_bytes(value: &Value) -> usize {
    match value {
        Value::String(s) => 64 + s.capacity(),
        Value::Array(values) => {
            64 + values.capacity() * std::mem::size_of::<Value>()
                + values.iter().map(retained_json_bytes).sum::<usize>()
        }
        Value::Object(values) => retained_object_bytes(values),
        _ => 64,
    }
}

pub(crate) fn retained_object_bytes(values: &Map<String, Value>) -> usize {
    values
        .iter()
        .map(|(k, v)| 256 + k.capacity() + retained_json_bytes(v))
        .sum()
}

#[derive(Debug, Clone, PartialEq)]
pub struct CdpEvent {
    pub method: String,
    pub params: Option<Map<String, Value>>,
    pub session_id: Option<String>,
    /// The message's other top-level members. `params` is moved out into
    /// [`Self::params`] rather than copied, so it is not repeated here.
    pub raw: Value,
}

#[derive(Debug, Clone)]
struct Pending {
    command: CdpCommand,
    deadline: Instant,
}

/// A custody-scoped target/session/frame association. Renderer supplied values
/// cannot create an association; only an explicit attachment operation can.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    pub target_id: String,
    pub session_id: String,
    pub frame_ids: Vec<String>,
    pub context_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdentityError {
    Duplicate,
    Unknown,
    ConflictingContext,
    InvalidLifecycle,
}

/// Maps CDP target, session, and frame identities to exactly one browser
/// context. Transport framing is kept separate so renderer data cannot establish
/// context ownership.
#[derive(Debug, Default)]
pub struct IdentityMap {
    targets: BTreeMap<String, Attachment>,
    sessions: BTreeMap<String, String>,
    frames: BTreeMap<String, String>,
}
impl IdentityMap {
    pub(crate) fn retained_bytes(&self) -> usize {
        self.targets
            .iter()
            .map(|(key, a)| {
                256 + key.capacity()
                    + a.target_id.capacity()
                    + a.session_id.capacity()
                    + a.context_key.capacity()
                    + a.frame_ids.iter().map(|s| 24 + s.capacity()).sum::<usize>()
            })
            .sum::<usize>()
            + self
                .sessions
                .iter()
                .chain(self.frames.iter())
                .map(|(k, v)| 128 + k.capacity() + v.capacity())
                .sum::<usize>()
    }
    pub fn new() -> Self {
        Self::default()
    }
    pub fn attach(&mut self, attachment: Attachment) -> Result<(), IdentityError> {
        if attachment.target_id.is_empty()
            || attachment.session_id.is_empty()
            || attachment.context_key.is_empty()
        {
            return Err(IdentityError::InvalidLifecycle);
        }
        if self.targets.contains_key(&attachment.target_id)
            || self.sessions.contains_key(&attachment.session_id)
            || attachment
                .frame_ids
                .iter()
                .any(|frame| self.frames.contains_key(frame))
        {
            return Err(IdentityError::Duplicate);
        }
        if attachment.frame_ids.iter().any(String::is_empty) {
            return Err(IdentityError::InvalidLifecycle);
        }
        let context = attachment.context_key.clone();
        self.sessions
            .insert(attachment.session_id.clone(), context.clone());
        for frame in &attachment.frame_ids {
            self.frames.insert(frame.clone(), context.clone());
        }
        self.targets
            .insert(attachment.target_id.clone(), attachment);
        Ok(())
    }
    pub fn detach(
        &mut self,
        target_id: &str,
        session_id: &str,
    ) -> Result<Attachment, IdentityError> {
        let attachment = self.targets.get(target_id).ok_or(IdentityError::Unknown)?;
        if attachment.session_id != session_id {
            return Err(IdentityError::ConflictingContext);
        }
        let attachment = self.targets.remove(target_id).expect("checked above");
        self.sessions.remove(session_id);
        for frame in &attachment.frame_ids {
            self.frames.remove(frame);
        }
        Ok(attachment)
    }
    pub fn context_for(
        &self,
        target_id: &str,
        session_id: &str,
        frame_id: Option<&str>,
    ) -> Result<&str, IdentityError> {
        let target = self.targets.get(target_id).ok_or(IdentityError::Unknown)?;
        let context = self
            .sessions
            .get(session_id)
            .ok_or(IdentityError::Unknown)?;
        if context != &target.context_key {
            return Err(IdentityError::ConflictingContext);
        }
        if let Some(frame_id) = frame_id {
            if self.frames.get(frame_id) != Some(context) {
                return Err(IdentityError::ConflictingContext);
            }
        }
        Ok(context.as_str())
    }
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

/// Correlates one managed-CDP connection. It is deliberately transport
/// agnostic, making protocol failures testable without opening a socket.
#[derive(Debug)]
pub struct CdpTransport {
    next_id: u64,
    pending: BTreeMap<u64, Pending>,
    completed: BTreeMap<u64, Completion>,
    events: VecDeque<CdpEvent>,
    event_limit: usize,
    closed: bool,
}

#[derive(Debug)]
enum Completion {
    Received,
    Abandoned { session_id: Option<String> },
}

impl Default for CdpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl CdpTransport {
    pub(crate) fn retained_metadata(&self) -> (usize, usize, usize) {
        let abandoned = self
            .completed
            .values()
            .filter(|c| matches!(c, Completion::Abandoned { .. }))
            .count();
        let bytes = self
            .pending
            .values()
            .map(|p| {
                256 + p.command.method.capacity()
                    + p.command.session_id.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
            + self
                .completed
                .values()
                .map(|c| {
                    128 + match c {
                        Completion::Received => 0,
                        Completion::Abandoned { session_id } => {
                            session_id.as_ref().map_or(0, String::capacity)
                        }
                    }
                })
                .sum::<usize>();
        (self.pending.len(), abandoned, bytes)
    }
    pub fn new() -> Self {
        Self {
            next_id: 1,
            pending: BTreeMap::new(),
            completed: BTreeMap::new(),
            events: VecDeque::new(),
            event_limit: MAX_QUEUED_EVENTS,
            closed: false,
        }
    }

    pub fn with_event_limit(event_limit: usize) -> Self {
        let mut transport = Self::new();
        transport.event_limit = event_limit;
        transport
    }

    pub fn is_closed(&self) -> bool {
        self.closed
    }
    pub fn pending_len(&self) -> usize {
        self.pending.len()
    }
    /// Stop waiting without closing the connection. Retain correlation and
    /// session identity so only this request's late response can be discarded.
    pub fn abandon_command(&mut self, id: u64) {
        if let Some(pending) = self.pending.remove(&id) {
            self.completed.insert(
                id,
                Completion::Abandoned {
                    session_id: pending.command.session_id,
                },
            );
        }
    }
    pub fn queued_event_len(&self) -> usize {
        self.events.len()
    }

    pub fn issue_command(
        &mut self,
        method: impl Into<String>,
        params: Option<Map<String, Value>>,
        session_id: Option<String>,
        now: Instant,
    ) -> Result<CdpCommand, CdpError> {
        if self.closed {
            return Err(CdpError::ProtocolFailure("cdp transport is closed"));
        }
        // An unanswered abandonment must keep its session tombstone for the
        // lifetime of the transport. Reserve space for those as well as pending
        // commands; never trade correlation safety for another command slot.
        if self.pending.len()
            + self
                .completed
                .values()
                .filter(|completion| matches!(completion, Completion::Abandoned { .. }))
                .count()
            >= MAX_PENDING_COMMANDS
        {
            return Err(CdpError::PendingCapacity);
        }
        let method = method.into();
        if method.is_empty() || method.len() > 4096 {
            return Err(CdpError::InvalidCommand("method is empty or over-bound"));
        }
        if let Some(session) = &session_id {
            if session.is_empty() || session.len() > 4096 {
                return Err(CdpError::InvalidCommand("sessionId is empty or over-bound"));
            }
        }
        let id = self.next_id;
        if id == 0 || id > MAX_SAFE_INTEGER {
            self.closed = true;
            return Err(CdpError::IdExhausted);
        }
        self.next_id = id.checked_add(1).unwrap_or(MAX_SAFE_INTEGER + 1);
        let command = CdpCommand {
            id,
            method,
            params,
            session_id,
            committed_at: now,
        };
        // Serialize before adding the command to pending state: a command that
        // cannot be represented must never become an unresolvable pending item.
        command.json_bytes()?;
        if self.pending.len() + self.completed.len() >= MAX_PENDING_COMMANDS {
            if let Some(id) = self.completed.iter().find_map(|(id, completion)| {
                matches!(completion, Completion::Received).then_some(*id)
            }) {
                // Retired received IDs are never reused. A duplicate outside
                // this window still fails closed as an unknown response.
                self.completed.remove(&id);
            }
        }
        self.pending.insert(
            id,
            Pending {
                // Correlation needs metadata, never the value-bearing params.
                command: CdpCommand {
                    id: command.id,
                    method: command.method.clone(),
                    params: None,
                    session_id: command.session_id.clone(),
                    committed_at: command.committed_at,
                },
                deadline: now + COMMAND_TIMEOUT,
            },
        );
        Ok(command)
    }

    pub fn expire(&mut self, now: Instant) -> Vec<CdpCommand> {
        let expired = self.pending.values().any(|pending| pending.deadline <= now);
        if !expired {
            return Vec::new();
        }
        self.closed = true;
        std::mem::take(&mut self.pending)
            .into_values()
            .map(|pending| pending.command)
            .collect()
    }

    pub fn accept_binary(&mut self, _bytes: &[u8]) -> Result<(), CdpError> {
        self.closed = true;
        Err(CdpError::BinaryMessage)
    }

    pub fn pending_command(&self, id: u64) -> Option<&CdpCommand> {
        self.pending.get(&id).map(|pending| &pending.command)
    }

    pub fn take_response(&mut self, bytes: &[u8]) -> Result<CdpResponse, CdpError> {
        let result = self.take_response_inner(bytes);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    /// Consume a valid response without closing the transport for an invalid
    /// observation. Browser startup must keep listening after arbitrary frames,
    /// while established sessions continue to use [`Self::take_response`] and
    /// fail closed on the same protocol errors.
    pub fn observe_response(&mut self, bytes: &[u8]) -> Result<CdpResponse, CdpError> {
        self.take_response_inner(bytes)
    }

    /// [`Self::take_response`] for a message the caller has already parsed
    /// with [`parse_json_message`], so a frame is never parsed twice. Its
    /// result or error moves into the response without a copy.
    pub fn take_response_value(&mut self, value: Value) -> Result<CdpResponse, CdpError> {
        let result = self.response_from_value(value);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn take_response_inner(&mut self, bytes: &[u8]) -> Result<CdpResponse, CdpError> {
        self.response_from_value(parse_json_message(bytes)?)
    }

    fn response_from_value(&mut self, value: Value) -> Result<CdpResponse, CdpError> {
        let Value::Object(mut object) = value else {
            return Err(CdpError::ProtocolFailure("cdp message is not an object"));
        };
        let id = object
            .get("id")
            .and_then(Value::as_u64)
            .ok_or(CdpError::ProtocolFailure(
                "terminal cdp response has no positive id",
            ))?;
        if id == 0 || id > MAX_SAFE_INTEGER {
            return Err(CdpError::ProtocolFailure("cdp response id is out of range"));
        }
        let (expected_session, abandoned) = match self.completed.get(&id) {
            Some(Completion::Received) => return Err(CdpError::DuplicateResponseId(id)),
            Some(Completion::Abandoned { session_id }) => (session_id, true),
            None => (
                &self
                    .pending
                    .get(&id)
                    .ok_or(CdpError::UnknownResponseId(id))?
                    .command
                    .session_id,
                false,
            ),
        };
        let session_id = parse_optional_string(object.get("sessionId"))?;
        if &session_id != expected_session {
            return Err(CdpError::SessionMismatch);
        }
        let result = match object.remove("result") {
            Some(Value::Object(map)) => Some(map),
            Some(_) => return Err(CdpError::ProtocolFailure("cdp result is not an object")),
            None => None,
        };
        let error = match object.remove("error") {
            Some(Value::Object(map)) => Some(map),
            Some(_) => return Err(CdpError::ProtocolFailure("cdp error is not an object")),
            None => None,
        };
        if result.is_some() == error.is_some() {
            return Err(CdpError::ProtocolFailure(
                "cdp response must contain exactly one of result or error",
            ));
        }
        self.pending.remove(&id);
        self.completed.insert(id, Completion::Received);
        Ok(CdpResponse {
            id,
            session_id,
            result,
            error,
            abandoned,
        })
    }

    pub fn accept_event(&mut self, bytes: &[u8]) -> Result<CdpEvent, CdpError> {
        let result = self.accept_event_inner(bytes);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    /// Queue a valid startup event without making a malformed observation close
    /// the transport. Events remain bounded by the normal event queue limit.
    pub fn observe_event(&mut self, bytes: &[u8]) -> Result<CdpEvent, CdpError> {
        self.accept_event_inner(bytes)
    }

    fn accept_event_inner(&mut self, bytes: &[u8]) -> Result<CdpEvent, CdpError> {
        let event = event_from_value(parse_json_message(bytes)?)?;
        if self.events.len() >= self.event_limit.min(MAX_QUEUED_EVENTS) {
            return Err(CdpError::ProtocolFailure("cdp event queue overflow"));
        }
        self.events.push_back(event.clone());
        Ok(event)
    }

    /// Validate an event the caller has already parsed with
    /// [`parse_json_message`] and hand it back without queuing it: an
    /// established driver applies each event as it reads it, so a queued copy
    /// would only be dropped again. A malformed event closes the transport,
    /// as [`Self::accept_event`] does.
    pub fn take_event(&mut self, value: Value) -> Result<CdpEvent, CdpError> {
        let result = event_from_value(value);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    pub fn pop_event(&mut self) -> Option<CdpEvent> {
        self.events.pop_front()
    }

    pub fn close(&mut self) {
        self.closed = true;
        self.pending.clear();
        self.events.clear();
    }
}

fn event_from_value(value: Value) -> Result<CdpEvent, CdpError> {
    let Value::Object(mut object) = value else {
        return Err(CdpError::ProtocolFailure("cdp event is not an object"));
    };
    if object.contains_key("id") {
        return Err(CdpError::ProtocolFailure("response supplied as event"));
    }
    let method = object
        .get("method")
        .and_then(Value::as_str)
        .filter(|method| !method.is_empty())
        .ok_or(CdpError::ProtocolFailure("cdp event has no method"))?
        .to_owned();
    let params = match object.remove("params") {
        None => None,
        Some(Value::Object(map)) => Some(map),
        Some(_) => {
            return Err(CdpError::ProtocolFailure(
                "cdp event params is not an object",
            ))
        }
    };
    let session_id = parse_optional_string(object.get("sessionId"))?;
    Ok(CdpEvent {
        method,
        params,
        session_id,
        raw: Value::Object(object),
    })
}

#[cfg(test)]
thread_local! {
    /// How many messages [`parse_json_message`] parsed on this thread.
    pub(crate) static PARSED_MESSAGES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn parse_optional_string(value: Option<&Value>) -> Result<Option<String>, CdpError> {
    match value {
        None => Ok(None),
        Some(Value::String(value)) if !value.is_empty() && value.len() <= 4096 => {
            Ok(Some(value.clone()))
        }
        Some(Value::Null) => Ok(None),
        Some(_) => Err(CdpError::ProtocolFailure("cdp sessionId is malformed")),
    }
}

pub fn parse_json_message(bytes: &[u8]) -> Result<Value, CdpError> {
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(CdpError::MessageTooLarge {
            bytes: bytes.len(),
            bound: MAX_MESSAGE_BYTES,
        });
    }
    #[cfg(test)]
    PARSED_MESSAGES.with(|parsed| parsed.set(parsed.get() + 1));
    let bytes = replace_lone_surrogate_escapes(bytes);
    let text = std::str::from_utf8(&bytes).map_err(|_| CdpError::InvalidUtf8)?;
    let mut stream = serde_json::Deserializer::from_str(text).into_iter::<Value>();
    let value = stream
        .next()
        .ok_or(CdpError::InvalidJson)?
        .map_err(|_| CdpError::InvalidJson)?;
    if stream.next().is_some() {
        return Err(CdpError::TrailingBytes);
    }
    Ok(value)
}

/// Replace every `\u` escape of an unpaired UTF-16 surrogate with `\ufffd`.
///
/// Chrome writes page strings as UTF-16 and escapes each non-ASCII code unit
/// as `\uXXXX`. A JavaScript string may hold half of a surrogate pair -- a
/// page that cut text in the middle of an emoji, say -- and Chrome sends that
/// half as it is: measured against Chrome 154 (2026-10-01), a button whose
/// text a script set to `"cut \ud83d"` came back from
/// `Accessibility.getChildAXNodes` with the name `"cut \ud83d"`
/// (`examples/handoff_attachment_probe.rs`). Such an escape names no Unicode
/// character, so serde_json refuses the whole message, and the read waiting
/// on it failed for as long as the page showed that text.
///
/// The replacement character is what the browser itself produces when it
/// encodes such a string as UTF-8. A surrogate pair, every other escape and
/// every other byte are left untouched, and both escapes are six bytes long,
/// so nothing else in the message moves. Anything that is still not valid
/// JSON afterwards is left for the parser to refuse.
fn replace_lone_surrogate_escapes(bytes: &[u8]) -> std::borrow::Cow<'_, [u8]> {
    const REPLACEMENT: &[u8; 6] = b"\\ufffd";
    let mut replaced: Option<Vec<u8>> = None;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'\\' {
            index += 1;
            continue;
        }
        // A backslash and the byte after it are one escape, so the `u` of an
        // escaped backslash followed by text (`\\ud83d`) is never read as
        // the start of a `\u` escape.
        let Some(unit) = escaped_code_unit(bytes, index) else {
            index += 2;
            continue;
        };
        let lone = match unit {
            0xD800..=0xDBFF => {
                if escaped_code_unit(bytes, index + 6)
                    .is_some_and(|next| (0xDC00..=0xDFFF).contains(&next))
                {
                    // A whole pair: step over both halves.
                    index += 12;
                    continue;
                }
                true
            }
            0xDC00..=0xDFFF => true,
            _ => false,
        };
        if lone {
            replaced.get_or_insert_with(|| bytes.to_vec())[index..index + 6]
                .copy_from_slice(REPLACEMENT);
        }
        index += 6;
    }
    match replaced {
        Some(bytes) => std::borrow::Cow::Owned(bytes),
        None => std::borrow::Cow::Borrowed(bytes),
    }
}

/// The code unit named by a `\uXXXX` escape starting at `at`, if one does.
fn escaped_code_unit(bytes: &[u8], at: usize) -> Option<u16> {
    let escape = bytes.get(at..at.checked_add(6)?)?;
    if escape[0] != b'\\' || escape[1] != b'u' {
        return None;
    }
    let digits = std::str::from_utf8(&escape[2..]).ok()?;
    if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    u16::from_str_radix(digits, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_commands_never_expose_params_in_debug_or_pending_state() {
        const SECRET: &str = "cdp-password-and-otp-67cb";
        let mut transport = CdpTransport::new();
        let command = transport
            .issue_command(
                "Runtime.callFunctionOn",
                serde_json::json!({"arguments":[{"value":SECRET}]})
                    .as_object()
                    .cloned(),
                Some("session".into()),
                Instant::now(),
            )
            .unwrap();
        let wire = String::from_utf8(command.json_bytes().unwrap()).unwrap();
        assert!(
            wire.contains(SECRET),
            "the command really contains credential material"
        );
        assert!(
            !format!("{command:?} {transport:?}").contains(SECRET),
            "Debug exposed credential material"
        );
        assert!(
            transport.pending[&command.id].command.params.is_none(),
            "pending correlation must not retain command params"
        );
    }

    #[test]
    fn sensitive_params_serialize_borrowed_into_a_fixed_zeroizing_frame() {
        #[derive(Serialize)]
        struct Params<'a> {
            value: &'a str,
        }
        let secret = Zeroizing::new("password-é-\"\\\n-otp-123456".to_string());
        let mut transport = CdpTransport::new();
        let command = transport
            .issue_command(
                "Runtime.callFunctionOn",
                None,
                Some("session".into()),
                Instant::now(),
            )
            .unwrap();
        let mut bytes: Zeroizing<Vec<u8>> = command
            .sensitive_json_bytes(&Params { value: &secret })
            .unwrap();
        assert!(
            bytes.capacity() > bytes.len(),
            "the pipe delimiter must not cause reallocation"
        );
        bytes.push(0);
        let parsed: Value = serde_json::from_slice(&bytes[..bytes.len() - 1]).unwrap();
        assert_eq!(
            parsed,
            serde_json::json!({"id":command.id,"method":"Runtime.callFunctionOn","sessionId":"session","params":{"value":secret.as_str()}})
        );
        assert!(command.params.is_none());
        assert!(transport.pending[&command.id].command.params.is_none());
        assert!(!format!("{transport:?} {command:?}").contains(secret.as_str()));
    }
    use serde_json::json;

    #[test]
    fn a_lone_surrogate_escape_parses_as_the_replacement_character() {
        let parsed = |text: &str| {
            parse_json_message(text.as_bytes())
                .map(|value| value["s"].as_str().unwrap().to_string())
        };
        // Chrome's own bytes: half of an emoji at the end of a string, and
        // a low half with nothing before it.
        assert_eq!(parsed(r#"{"s":"cut \ud83d"}"#).unwrap(), "cut \u{fffd}");
        assert_eq!(parsed(r#"{"s":"\ude00 x"}"#).unwrap(), "\u{fffd} x");
        // A high half followed by another high half: only the first is
        // lone, and the second pairs with the low half after it.
        assert_eq!(
            parsed(r#"{"s":"\ud83d\ud83d\ude00"}"#).unwrap(),
            "\u{fffd}\u{1f600}"
        );
        // A high half followed by an escape that is not a low half.
        assert_eq!(parsed(r#"{"s":"\ud83d\u0041"}"#).unwrap(), "\u{fffd}A");
        // A pair, an escaped backslash before text that looks like an
        // escape, and plain text are all read as they were.
        assert_eq!(parsed(r#"{"s":"\ud83d\ude00"}"#).unwrap(), "\u{1f600}");
        assert_eq!(parsed(r#"{"s":"\\ud83d"}"#).unwrap(), "\\ud83d");
        assert_eq!(parsed(r#"{"s":"\\\ud83d"}"#).unwrap(), "\\\u{fffd}");
        assert_eq!(parsed(r#"{"s":"plain"}"#).unwrap(), "plain");
        // A malformed escape is still refused.
        assert_eq!(parsed(r#"{"s":"\ud8"}"#), Err(CdpError::InvalidJson));
    }

    #[test]
    fn an_event_with_a_lone_surrogate_does_not_close_the_transport() {
        let mut cdp = CdpTransport::new();
        let event = cdp
            .accept_event(
                br#"{"method":"DOM.characterDataModified","params":{"nodeId":5,"characterData":"cut \ud83d"},"sessionId":"s"}"#,
            )
            .unwrap();
        assert_eq!(
            event.params.unwrap()["characterData"],
            json!("cut \u{fffd}")
        );
        assert!(!cdp.is_closed());
    }

    #[test]
    fn commands_correlate_out_of_order_and_require_one_terminal_member() {
        let now = Instant::now();
        let mut cdp = CdpTransport::new();
        let first = cdp.issue_command("Page.enable", None, None, now).unwrap();
        let second = cdp
            .issue_command("Runtime.enable", None, None, now)
            .unwrap();
        let response = serde_json::to_vec(&json!({"id":second.id,"result":{}})).unwrap();
        assert_eq!(cdp.take_response(&response).unwrap().id, second.id);
        let response = serde_json::to_vec(&json!({"id":first.id,"error":{"code":-1}})).unwrap();
        assert!(cdp.take_response(&response).unwrap().error.is_some());
        let invalid = serde_json::to_vec(&json!({"id":first.id,"result":{},"error":{}})).unwrap();
        assert!(matches!(
            cdp.take_response(&invalid),
            Err(CdpError::DuplicateResponseId(_))
        ));
    }

    #[test]
    fn malformed_and_trailing_messages_fail_closed() {
        assert!(matches!(
            parse_json_message(br"{} {}"),
            Err(CdpError::TrailingBytes)
        ));
        assert!(matches!(
            parse_json_message(&[0xff]),
            Err(CdpError::InvalidUtf8)
        ));
    }
    #[test]
    fn audit_completed_history_is_bounded_without_evicting_abandoned_identity() {
        let mut transport = CdpTransport::new();
        let now = Instant::now();
        let abandoned = transport
            .issue_command("Runtime.evaluate", None, Some("old-page".into()), now)
            .unwrap();
        transport.abandon_command(abandoned.id);
        for _ in 0..MAX_PENDING_COMMANDS * 2 {
            let command = transport
                .issue_command("Runtime.evaluate", None, Some("page".into()), now)
                .unwrap();
            let bytes = serde_json::to_vec(
                &serde_json::json!({"id":command.id,"sessionId":"page","result":{}}),
            )
            .unwrap();
            assert!(!transport.take_response(&bytes).unwrap().abandoned);
            assert!(transport.completed.len() <= MAX_PENDING_COMMANDS);
        }
        let late = serde_json::to_vec(
            &serde_json::json!({"id":abandoned.id,"sessionId":"old-page","result":{}}),
        )
        .unwrap();
        assert!(transport.take_response(&late).unwrap().abandoned);
        assert_eq!(
            transport.take_response(&late),
            Err(CdpError::DuplicateResponseId(abandoned.id))
        );
    }

    #[test]
    fn audit_unanswered_abandonments_bound_admission_and_keep_session_checks() {
        let mut transport = CdpTransport::new();
        let now = Instant::now();
        for _ in 0..MAX_PENDING_COMMANDS {
            let command = transport
                .issue_command("Runtime.evaluate", None, Some("page".into()), now)
                .unwrap();
            transport.abandon_command(command.id);
        }
        assert_eq!(transport.pending_len(), 0);
        assert!(matches!(
            transport.issue_command("Runtime.evaluate", None, None, now),
            Err(CdpError::PendingCapacity)
        ));
        assert_eq!(transport.completed.len(), MAX_PENDING_COMMANDS);
        assert_eq!(
            transport.take_response(br#"{"id":1,"sessionId":"other","result":{}}"#),
            Err(CdpError::SessionMismatch)
        );
    }

    #[test]
    fn abandoned_commands_release_capacity_and_validate_late_replies() {
        let mut transport = CdpTransport::new();
        let now = Instant::now();
        let command = transport
            .issue_command(
                "Accessibility.getRootAXNode",
                None,
                Some("page".into()),
                now,
            )
            .unwrap();
        transport.abandon_command(command.id);
        assert_eq!(transport.pending_len(), 0);
        assert!(!transport.is_closed());
        assert!(transport.expire(now + COMMAND_TIMEOUT).is_empty());
        let wrong_session = serde_json::to_vec(
            &serde_json::json!({"id":command.id,"sessionId":"other","result":{}}),
        )
        .unwrap();
        assert_eq!(
            transport.take_response(&wrong_session),
            Err(CdpError::SessionMismatch)
        );
        // Use a fresh transport because a session mismatch correctly closes it.
        let mut transport = CdpTransport::new();
        let command = transport
            .issue_command(
                "Accessibility.getRootAXNode",
                None,
                Some("page".into()),
                now,
            )
            .unwrap();
        transport.abandon_command(command.id);
        let bytes = serde_json::to_vec(
            &serde_json::json!({"id":command.id,"sessionId":"page","result":{}}),
        )
        .unwrap();
        assert!(transport.take_response(&bytes).unwrap().abandoned);
        assert_eq!(
            transport.take_response(&bytes),
            Err(CdpError::DuplicateResponseId(command.id))
        );
    }
}
