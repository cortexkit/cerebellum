//! Small, fail-closed CDP wire vertical used by the browser plane.
//!
//! The browser adapter owns the socket; this module owns message framing,
//! command correlation, identity checks, and bounded pending/event state.  It
//! intentionally does not know about Chromium's page model or grant policy.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

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

#[derive(Debug, Clone, PartialEq)]
pub struct CdpCommand {
    pub id: u64,
    pub method: String,
    pub params: Option<Map<String, Value>>,
    pub session_id: Option<String>,
    pub committed_at: Instant,
}

impl CdpCommand {
    pub fn json_bytes(&self) -> Result<Vec<u8>, CdpError> {
        let mut object = Map::new();
        object.insert("id".into(), Value::Number(self.id.into()));
        object.insert("method".into(), Value::String(self.method.clone()));
        if let Some(params) = &self.params {
            object.insert("params".into(), Value::Object(params.clone()));
        }
        if let Some(session_id) = &self.session_id {
            object.insert("sessionId".into(), Value::String(session_id.clone()));
        }
        let bytes =
            serde_json::to_vec(&Value::Object(object)).map_err(|_| CdpError::InvalidJson)?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(CdpError::MessageTooLarge {
                bytes: bytes.len(),
                bound: MAX_MESSAGE_BYTES,
            });
        }
        Ok(bytes)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CdpResponse {
    pub id: u64,
    pub session_id: Option<String>,
    pub result: Option<Map<String, Value>>,
    pub error: Option<Map<String, Value>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CdpEvent {
    pub method: String,
    pub params: Option<Map<String, Value>>,
    pub session_id: Option<String>,
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
    completed: BTreeMap<u64, ()>,
    events: VecDeque<CdpEvent>,
    event_limit: usize,
    closed: bool,
}

impl Default for CdpTransport {
    fn default() -> Self {
        Self::new()
    }
}

impl CdpTransport {
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
        if self.pending.len() >= MAX_PENDING_COMMANDS {
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
        self.pending.insert(
            id,
            Pending {
                command: command.clone(),
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

    fn take_response_inner(&mut self, bytes: &[u8]) -> Result<CdpResponse, CdpError> {
        let value = parse_json_message(bytes)?;
        let object = value
            .as_object()
            .ok_or(CdpError::ProtocolFailure("cdp message is not an object"))?;
        let id = object
            .get("id")
            .and_then(Value::as_u64)
            .ok_or(CdpError::ProtocolFailure(
                "terminal cdp response has no positive id",
            ))?;
        if id == 0 || id > MAX_SAFE_INTEGER {
            return Err(CdpError::ProtocolFailure("cdp response id is out of range"));
        }
        if self.completed.contains_key(&id) {
            return Err(CdpError::DuplicateResponseId(id));
        }
        let pending = self
            .pending
            .get(&id)
            .ok_or(CdpError::UnknownResponseId(id))?;
        let session_id = parse_optional_string(object.get("sessionId"))?;
        if session_id != pending.command.session_id {
            return Err(CdpError::SessionMismatch);
        }
        let result = match object.get("result") {
            Some(Value::Object(map)) => Some(map.clone()),
            Some(_) => return Err(CdpError::ProtocolFailure("cdp result is not an object")),
            None => None,
        };
        let error = match object.get("error") {
            Some(Value::Object(map)) => Some(map.clone()),
            Some(_) => return Err(CdpError::ProtocolFailure("cdp error is not an object")),
            None => None,
        };
        if result.is_some() == error.is_some() {
            return Err(CdpError::ProtocolFailure(
                "cdp response must contain exactly one of result or error",
            ));
        }
        self.pending.remove(&id);
        self.completed.insert(id, ());
        Ok(CdpResponse {
            id,
            session_id,
            result,
            error,
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
        let value = parse_json_message(bytes)?;
        let object = value
            .as_object()
            .ok_or(CdpError::ProtocolFailure("cdp event is not an object"))?;
        if object.contains_key("id") {
            return Err(CdpError::ProtocolFailure("response supplied as event"));
        }
        let method = object
            .get("method")
            .and_then(Value::as_str)
            .filter(|method| !method.is_empty())
            .ok_or(CdpError::ProtocolFailure("cdp event has no method"))?;
        let params = match object.get("params") {
            None => None,
            Some(Value::Object(map)) => Some(map.clone()),
            Some(_) => {
                return Err(CdpError::ProtocolFailure(
                    "cdp event params is not an object",
                ))
            }
        };
        let session_id = parse_optional_string(object.get("sessionId"))?;
        if self.events.len() >= self.event_limit.min(MAX_QUEUED_EVENTS) {
            return Err(CdpError::ProtocolFailure("cdp event queue overflow"));
        }
        let event = CdpEvent {
            method: method.to_string(),
            params,
            session_id,
            raw: value,
        };
        self.events.push_back(event.clone());
        Ok(event)
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
    let text = std::str::from_utf8(bytes).map_err(|_| CdpError::InvalidUtf8)?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

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
}
