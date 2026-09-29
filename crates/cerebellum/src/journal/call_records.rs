//! One record per tool call that arrived with a `call_key`, so a resent call is
//! answered from what the first one did instead of running again, and so
//! `tool.withdraw` can say what became of a call.
//!
//! # Why this exists
//!
//! A relay that loses a reply cannot tell whether the call ran. Without a
//! record, resending a keystroke or a click types or clicks twice. So every
//! caller that mints a `call_key` (the key is opaque here: Broca's
//! `<lineage_id>:<wal_seq>`, Claude Code's `cc:<tool_use id>`, Prefrontal's
//! `pf:<relay record id>`) gets one record per `(route principal, call_key)`.
//! The principal is part of the key because two callers can mint the same
//! string, and one caller's key must never answer for another's call. The
//! model's own `tool_call_id` is display-only and is never stored or used as a
//! key.
//!
//! # What is durable and what is not
//!
//! The durable file (`call_records.jsonl` beside the audit journal) holds only
//! closed, text-free facts: principal, call_key, the scope identity (always
//! absent for now, see [`ScopeIdentity`]), the state, the outcome code, a
//! refusal reason code, `effect_status`, `posts_returned` and timestamps. It
//! never holds arguments, element ids, labels, typed text or reply bodies: a
//! reply to a read or a typing call can carry screen text, and this directory is
//! backed up. The full reply is held only in a bounded in-memory cache
//! ([`CACHE_MAX_REPLIES`], [`CACHE_MAX_BYTES`], [`CACHE_MAX_AGE`]), dropped when
//! the conversation ends. Once it is gone, or after a restart, a resend or
//! withdraw is answered from the durable facts, saying the body is no longer
//! retained. A resent call is never run again.
//!
//! # Ordering
//!
//! The `started` record is written and synced before the call does anything
//! with an effect (before any grant question, journal reservation or input).
//! Its settled state is written when the call's reply is sent, which is after
//! the call's own audit entry finalized, so this file never says a call replied
//! while its audit entry is still open. A process that died between the two
//! leaves `started` on disk; the next start reads it as `unknown`: the call may
//! or may not have run.
//!
//! # Bounds
//!
//! Records are kept for [`RETENTION`] (48 hours, longer than a runner's restart
//! sweep) and at most [`MAX_RECORDS`]. A key that aged out answers
//! `unknown_call`, exactly as one never seen does. That is the one way
//! `unknown_call` can be said of a key this module once accepted.
//!
//! # Calls without a key
//!
//! Run exactly as before, with no record, so they cannot be deduplicated or
//! withdrawn. The reply does not yet say so: every reply body is a capability
//! result validated against a closed, published schema, and a field saying it
//! would need a new vocabulary version.

use std::collections::{HashMap, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subc_protocol::{Frame, FrameType, Principal};

/// The file name under the journal data home.
pub const CALL_RECORD_FILE: &str = "call_records.jsonl";

/// The only file version this build reads or writes.
pub const CALL_RECORD_VERSION: u64 = 1;

/// The file's format, as the format floor and staging name it.
pub const CALL_RECORD_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new("call-records", CALL_RECORD_VERSION);

/// The name `tool.withdraw` arrives under on a tool route.
pub const WITHDRAW_OPERATION: &str = "tool.withdraw";

/// The longest `call_key` accepted, in bytes (all of them ASCII).
pub const CALL_KEY_MAX_BYTES: usize = 256;

/// How long a record is kept after it was last written.
pub const RETENTION: Duration = Duration::from_secs(48 * 60 * 60);

/// The most records kept. The oldest settled ones go first; a call still
/// running is never dropped.
pub const MAX_RECORDS: usize = 20_000;

/// The most reply bodies held in memory for resends.
pub const CACHE_MAX_REPLIES: usize = 256;

/// The most reply bytes held in memory for resends, all replies together.
pub const CACHE_MAX_BYTES: usize = 32 * 1024 * 1024;

/// A single reply larger than this is not held at all: one screenshot must not
/// push every other reply out.
pub const CACHE_MAX_REPLY_BYTES: usize = 4 * 1024 * 1024;

/// How long a reply body is held for resends.
pub const CACHE_MAX_AGE: Duration = Duration::from_secs(30 * 60);

/// Whether `key` is an acceptable `call_key`: 1 to 256 printable ASCII
/// characters (space through tilde).
///
/// The single place the bound is checked. The shared wire crate is adding the
/// same field with its own validator to the same bound; when this module moves
/// to that release, this body becomes a call to it and nothing else changes.
pub fn valid_call_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= CALL_KEY_MAX_BYTES
        && key.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
}

/// The label a record stores for the route's verified principal.
pub fn principal_label(principal: Option<&Principal>) -> String {
    match principal {
        Some(Principal::Reserved { module_id }) => format!("reserved:{module_id}"),
        Some(Principal::Direct) => "direct".to_string(),
        Some(Principal::Unverified) => "unverified".to_string(),
        None => "absent".to_string(),
    }
}

/// The scope a call ran under: `(owner, ref, scope_epoch)`.
///
/// Always absent today. The daemon does not yet stamp a scope on the route
/// bind, and a scope named in a request body is caller-chosen, so recording
/// one would put an identity nobody verified into an audit record. When the
/// daemon stamps scopes, [`CallRecords::begin`]'s caller fills this from the
/// stamp and nowhere else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeIdentity {
    pub owner: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub scope_epoch: u64,
}

/// Where a recorded call stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    /// Accepted and running in this process.
    Started,
    /// Replied with a result.
    Replied,
    /// Replied with a refusal: an error frame, or a consent denial.
    Refused,
    /// Started, and no reply was recorded: the module stopped, or the route
    /// closed, before the call answered. It may or may not have run.
    Unknown,
}

/// One call, as written to the durable file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecord {
    pub principal: String,
    pub call_key: String,
    #[serde(default)]
    pub scope: Option<ScopeIdentity>,
    pub state: CallState,
    /// The reply's `outcome`, or the error frame's code.
    #[serde(default)]
    pub outcome: Option<String>,
    /// Why a refused call was refused, as `tool.withdraw` reports it.
    #[serde(default)]
    pub refusal_reason: Option<String>,
    #[serde(default)]
    pub effect_status: Option<String>,
    #[serde(default)]
    pub posts_returned: Option<u64>,
    pub started_at_ms: u64,
    #[serde(default)]
    pub settled_at_ms: Option<u64>,
}

impl CallRecord {
    fn last_written_ms(&self) -> u64 {
        self.settled_at_ms.unwrap_or(self.started_at_ms)
    }
}

/// Why the durable file could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallRecordError {
    Unreadable(String),
    Corrupt(String),
    /// Written by a newer build: this one does not read it and must not
    /// overwrite it.
    UnknownVersion(u64),
    WriteFailed(String),
}

impl CallRecordError {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unreadable(_) => "call_records_unreadable",
            Self::Corrupt(_) => "call_records_corrupt",
            Self::UnknownVersion(_) => "call_records_version_unknown",
            Self::WriteFailed(_) => "call_records_write_failed",
        }
    }
}

impl std::fmt::Display for CallRecordError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable(detail) => write!(formatter, "call records unreadable: {detail}"),
            Self::Corrupt(detail) => write!(formatter, "call records corrupt: {detail}"),
            Self::UnknownVersion(found) => write!(
                formatter,
                "call records are version {found}; this build reads version {CALL_RECORD_VERSION}"
            ),
            Self::WriteFailed(detail) => {
                write!(formatter, "call records could not be written: {detail}")
            }
        }
    }
}

/// Where the durable file lives.
pub trait CallRecordStorage: Send + Sync {
    /// The whole file, or `None` if it was never written.
    fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError>;
    /// Append bytes and sync them before returning.
    fn append(&self, bytes: &[u8]) -> Result<(), CallRecordError>;
    /// Replace the whole file atomically.
    fn replace(&self, bytes: &[u8]) -> Result<(), CallRecordError>;
}

/// The file held in memory. Clones share it, so opening a second
/// [`CallRecords`] over a clone models a restart.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCallRecordStorage {
    bytes: Arc<Mutex<Option<Vec<u8>>>>,
}

impl InMemoryCallRecordStorage {
    pub fn new() -> Self {
        Self::default()
    }

    /// What a durable file would hold now, for tests that check it.
    pub fn contents(&self) -> Option<Vec<u8>> {
        self.bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}

impl CallRecordStorage for InMemoryCallRecordStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
        Ok(self.contents())
    }

    fn append(&self, bytes: &[u8]) -> Result<(), CallRecordError> {
        self.bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(Vec::new)
            .extend_from_slice(bytes);
        Ok(())
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), CallRecordError> {
        *self.bytes.lock().unwrap_or_else(PoisonError::into_inner) = Some(bytes.to_vec());
        Ok(())
    }
}

/// The file on disk.
#[derive(Debug, Clone)]
pub struct FilesystemCallRecordStorage {
    path: PathBuf,
    floor: cerebellum_core::format_floor::FormatFloor,
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl FilesystemCallRecordStorage {
    /// A file at `path`, raising the format floor that governs that location:
    /// the operator's floor inside the module's data directory, none elsewhere.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let floor = cerebellum_core::format_floor::FormatFloor::governing(&path);
        Self { path, floor }
    }

    /// Raise `floor` instead of the one chosen from the file's location.
    pub fn with_format_floor(mut self, floor: cerebellum_core::format_floor::FormatFloor) -> Self {
        self.floor = floor;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    fn raise_floor(&self) -> Result<(), CallRecordError> {
        // Before anything is written: a file in this format with no floor
        // naming it would let staging pass a build that cannot read it.
        self.floor
            .raise(CALL_RECORD_FORMAT)
            .map_err(|error| CallRecordError::WriteFailed(error.to_string()))
    }

    fn directory(&self) -> PathBuf {
        self.path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

impl CallRecordStorage for FilesystemCallRecordStorage {
    fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError> {
        match File::open(&self.path) {
            Ok(mut file) => {
                let mut bytes = Vec::new();
                file.read_to_end(&mut bytes)
                    .map_err(|error| CallRecordError::Unreadable(error.to_string()))?;
                Ok(Some(bytes))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(CallRecordError::Unreadable(error.to_string())),
        }
    }

    fn append(&self, bytes: &[u8]) -> Result<(), CallRecordError> {
        self.raise_floor()?;
        let failed = |error: std::io::Error| CallRecordError::WriteFailed(error.to_string());
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(failed)?;
        file.write_all(bytes).map_err(failed)?;
        file.sync_data().map_err(failed)
    }

    fn replace(&self, bytes: &[u8]) -> Result<(), CallRecordError> {
        self.raise_floor()?;
        let failed = |error: std::io::Error| CallRecordError::WriteFailed(error.to_string());
        let directory = self.directory();
        fs::create_dir_all(&directory).map_err(failed)?;
        let temporary = directory.join(format!(
            ".{CALL_RECORD_FILE}.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        // Written beside the target and renamed over it, so a crash mid-write
        // leaves the old file or the new one, never half of one.
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&temporary, &self.path)?;
            if let Ok(directory) = File::open(&directory) {
                let _ = directory.sync_all();
            }
            Ok(())
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written.map_err(failed)
    }
}

/// A terminal reply held in memory so a resend gets the same bytes.
#[derive(Debug, Clone)]
pub struct CachedReply {
    frame: Frame,
}

impl CachedReply {
    /// The recorded reply, readdressed to the request now being answered.
    pub fn readdressed(&self, ver: u8, channel: u16, epoch: u32, corr: u64) -> Frame {
        let mut frame = self.frame.clone();
        frame.header.ver = ver;
        frame.header.channel = channel;
        frame.header.epoch = epoch;
        frame.header.corr = corr;
        frame
    }

    /// The reply body as JSON, when it is a result rather than an error.
    pub fn result(&self) -> Option<Value> {
        (self.frame.header.ty == FrameType::Response)
            .then(|| serde_json::from_slice(&self.frame.body).ok())
            .flatten()
    }
}

/// What the call's reply said, reduced to what may be recorded.
#[derive(Debug, Clone)]
pub struct Settlement {
    state: CallState,
    outcome: Option<String>,
    refusal_reason: Option<String>,
    effect_status: Option<String>,
    posts_returned: Option<u64>,
    /// The open question a `consent_pending` reply named. Memory only: a
    /// restart withdraws every open question anyway.
    ask_id: Option<String>,
    reply: CachedReply,
}

impl Settlement {
    /// Read the facts to record from the call's terminal frame.
    ///
    /// Only closed codes are taken, each checked to look like one, so a reply
    /// that put text where a code belongs records nothing for it.
    pub fn from_reply(frame: &Frame) -> Self {
        let body: Value = serde_json::from_slice(&frame.body).unwrap_or(Value::Null);
        let reply = CachedReply {
            frame: frame.clone(),
        };
        if frame.header.ty == FrameType::Error {
            let code = code(body.get("code"));
            return Self {
                state: CallState::Refused,
                refusal_reason: code.clone(),
                outcome: code,
                effect_status: None,
                posts_returned: None,
                ask_id: None,
                reply,
            };
        }
        let outcome = code(body.get("outcome"));
        // A person's denial, as the computer plane words it and as the browser
        // plane words it (a refused authorization whose question was declined).
        let denied = outcome.as_deref() == Some("consent_denied")
            || (outcome.as_deref() == Some("authorization_denied")
                && body.pointer("/detail/decision").and_then(Value::as_str) == Some("declined"));
        let ask_id = (outcome.as_deref() == Some("consent_pending"))
            .then(|| {
                body.get("ask_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        Self {
            state: if denied {
                CallState::Refused
            } else {
                CallState::Replied
            },
            refusal_reason: denied.then(|| "denied".to_string()),
            outcome,
            effect_status: code(body.get("effect_status")),
            posts_returned: body.get("posts_returned").and_then(Value::as_u64),
            ask_id,
            reply,
        }
    }
}

/// A value read as a code only if it looks like one: a short run of lowercase
/// letters, digits and underscores.
fn code(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    let shaped = !text.is_empty()
        && text.len() <= 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    shaped.then(|| text.to_string())
}

/// Permission to run a call, handed out once per `(principal, call_key)`.
#[must_use = "a started call must be settled"]
#[derive(Debug)]
pub struct CallTicket {
    key: Key,
}

/// What to do with a keyed call.
#[derive(Debug)]
pub enum Begin {
    /// First time seen, and recorded durably: run it.
    Execute(CallTicket),
    /// The first call with this key is still running.
    InFlight,
    /// The first call replied, and its reply is held: send it again.
    Replay(CachedReply),
    /// The first call replied, and its body is no longer held.
    NotRetained { outcome: Option<String> },
    /// The first call started and never recorded a reply.
    OutcomeUnknown,
    /// No record can be written, so the call is not run: it could not be
    /// protected against a resend.
    Unavailable(CallRecordError),
}

/// What is known about a call, for `tool.withdraw`.
#[derive(Debug, Clone)]
pub struct CallSnapshot {
    pub state: CallState,
    pub outcome: Option<String>,
    pub refusal_reason: Option<String>,
    pub ask_id: Option<String>,
    pub reply: Option<CachedReply>,
}

/// The result of looking a key up for `tool.withdraw`.
#[derive(Debug)]
pub enum Lookup {
    /// The caller raised this call.
    Own(CallSnapshot),
    /// Another principal raised a call with this key; this caller may not
    /// withdraw it.
    OtherPrincipal,
    /// No record has this key.
    Unknown,
    Unavailable(CallRecordError),
}

/// The `tool.withdraw` answer for a recorded call.
///
/// A function of the record alone, never of live state such as whether a
/// question is still open, so every permitted caller and every repeat gets the
/// same bytes.
pub fn withdraw_answer(snapshot: &CallSnapshot) -> Value {
    match snapshot.state {
        CallState::Started | CallState::Unknown => {
            json!({"answer": "already_started", "outcome": "unknown"})
        }
        CallState::Refused => json!({
            "answer": "refused",
            "reason": snapshot
                .refusal_reason
                .clone()
                .or_else(|| snapshot.outcome.clone())
                .unwrap_or_else(|| "refused".to_string()),
        }),
        // The call only asked a person and never acted. Cerebellum holds no
        // call to run later, so it is guaranteed never to run.
        CallState::Replied if snapshot.outcome.as_deref() == Some("consent_pending") => {
            json!({"answer": "withdrawn"})
        }
        CallState::Replied => match snapshot.reply.as_ref().and_then(CachedReply::result) {
            Some(result) => json!({"answer": "completed", "result": result}),
            None => json!({
                "answer": "completed",
                "outcome": snapshot.outcome,
                "result_retained": false,
            }),
        },
    }
}

type Key = (String, String);

#[derive(Debug)]
struct Entry {
    record: CallRecord,
    conversation_key: String,
    ask_id: Option<String>,
    reply: Option<CachedReply>,
    reply_bytes: usize,
    cached_at: Option<Instant>,
}

impl Entry {
    fn snapshot(&self) -> CallSnapshot {
        CallSnapshot {
            state: self.record.state,
            outcome: self.record.outcome.clone(),
            refusal_reason: self.record.refusal_reason.clone(),
            ask_id: self.ask_id.clone(),
            reply: self.reply.clone(),
        }
    }
}

#[derive(Debug)]
struct Inner {
    /// Why the durable file cannot be used, if it cannot. Keyed calls are then
    /// refused rather than run unprotected.
    broken: Option<CallRecordError>,
    header_written: bool,
    appended_since_compaction: usize,
    entries: HashMap<Key, Entry>,
    cached: VecDeque<Key>,
    cached_bytes: usize,
}

/// The call records of one module process.
pub struct CallRecords {
    storage: Box<dyn CallRecordStorage>,
    inner: Mutex<Inner>,
}

impl std::fmt::Debug for CallRecords {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CallRecords")
            .finish_non_exhaustive()
    }
}

fn header() -> Vec<u8> {
    let mut line = serde_json::to_vec(&json!({
        "format": CALL_RECORD_FORMAT.name,
        "version": CALL_RECORD_VERSION,
    }))
    .expect("the header serializes");
    line.push(b'\n');
    line
}

fn line(record: &CallRecord) -> Result<Vec<u8>, CallRecordError> {
    let mut line = serde_json::to_vec(record)
        .map_err(|error| CallRecordError::WriteFailed(error.to_string()))?;
    line.push(b'\n');
    Ok(line)
}

/// Read the file into records, latest line per key winning.
///
/// A last line without its newline is a write the crash interrupted. It is
/// ignored: the record is written before the call acts, so an interrupted
/// write means the call never went ahead.
fn parse(bytes: &[u8]) -> Result<Vec<CallRecord>, CallRecordError> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| CallRecordError::Corrupt(error.to_string()))?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    // `split` leaves the text after the last newline: empty for a whole file,
    // a torn record otherwise. Either way it is not a record.
    lines.pop();
    let mut lines = lines.into_iter();
    let Some(first) = lines.next() else {
        return Ok(Vec::new());
    };
    let header: Value =
        serde_json::from_str(first).map_err(|error| CallRecordError::Corrupt(error.to_string()))?;
    // Read before the records, so a file from a newer build is reported as a
    // version this build does not read rather than as corruption: the remedy
    // differs (run the newer build, not repair).
    let Some(version) = header.get("version").and_then(Value::as_u64) else {
        return Err(CallRecordError::Corrupt(
            "the header names no version".to_string(),
        ));
    };
    if version != CALL_RECORD_VERSION {
        return Err(CallRecordError::UnknownVersion(version));
    }
    if header.get("format").and_then(Value::as_str) != Some(CALL_RECORD_FORMAT.name) {
        return Err(CallRecordError::Corrupt(
            "the header names another format".to_string(),
        ));
    }
    lines
        .filter(|line| !line.is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| CallRecordError::Corrupt(error.to_string()))
        })
        .collect()
}

impl CallRecords {
    /// The operator's records under the cerebellum data home, beside the audit
    /// journal so they share its backup enrolment.
    pub fn open_durable(now_ms: u64) -> Self {
        match cerebellum_core::journal::journal_data_path(CALL_RECORD_FILE) {
            Ok(path) => Self::open(Box::new(FilesystemCallRecordStorage::new(path)), now_ms),
            Err(error) => Self::broken(CallRecordError::Unreadable(format!("{error:?}"))),
        }
    }

    /// Records that start empty and are discarded with the process.
    pub fn in_memory() -> Self {
        Self::open(Box::new(InMemoryCallRecordStorage::new()), 0)
    }

    fn broken(error: CallRecordError) -> Self {
        Self {
            storage: Box::new(InMemoryCallRecordStorage::new()),
            inner: Mutex::new(Inner {
                broken: Some(error),
                header_written: false,
                appended_since_compaction: 0,
                entries: HashMap::new(),
                cached: VecDeque::new(),
                cached_bytes: 0,
            }),
        }
    }

    /// Open over `storage`, reconciling what a previous process left.
    ///
    /// A record still `started` belonged to a process that stopped before the
    /// call replied; it becomes `unknown`. Records past retention are dropped.
    /// If anything changed the file is rewritten at once, so the reconciled
    /// state is what the next start reads too.
    pub fn open(storage: Box<dyn CallRecordStorage>, now_ms: u64) -> Self {
        let loaded = storage.load().and_then(|bytes| match bytes {
            None => Ok(None),
            Some(bytes) => parse(&bytes).map(Some),
        });
        let (records, existed) = match loaded {
            Ok(Some(records)) => (records, true),
            Ok(None) => (Vec::new(), false),
            Err(error) => {
                let mut broken = Self::broken(error);
                broken.storage = storage;
                return broken;
            }
        };
        let mut inner = Inner {
            broken: None,
            header_written: existed,
            appended_since_compaction: 0,
            entries: HashMap::new(),
            cached: VecDeque::new(),
            cached_bytes: 0,
        };
        let line_count = records.len();
        let mut reconciled = false;
        for mut record in records {
            if record.state == CallState::Started {
                record.state = CallState::Unknown;
                reconciled = true;
            }
            let key = (record.principal.clone(), record.call_key.clone());
            inner.entries.insert(
                key,
                Entry {
                    record,
                    conversation_key: String::new(),
                    ask_id: None,
                    reply: None,
                    reply_bytes: 0,
                    cached_at: None,
                },
            );
        }
        let records = Self {
            storage,
            inner: Mutex::new(inner),
        };
        {
            let mut inner = records.lock();
            let dropped = Self::apply_retention(&mut inner, now_ms);
            if existed && (reconciled || dropped || line_count != inner.entries.len()) {
                if let Err(error) = records.compact(&mut inner) {
                    inner.broken = Some(error);
                }
            }
        }
        records
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Drop settled records past retention, then the oldest settled ones past
    /// the count bound. Returns whether anything was dropped.
    fn apply_retention(inner: &mut Inner, now_ms: u64) -> bool {
        let before = inner.entries.len();
        let horizon = now_ms.saturating_sub(RETENTION.as_millis() as u64);
        inner.entries.retain(|_, entry| {
            entry.record.state == CallState::Started || entry.record.last_written_ms() >= horizon
        });
        if inner.entries.len() > MAX_RECORDS {
            let mut settled: Vec<(u64, Key)> = inner
                .entries
                .iter()
                .filter(|(_, entry)| entry.record.state != CallState::Started)
                .map(|(key, entry)| (entry.record.last_written_ms(), key.clone()))
                .collect();
            settled.sort();
            let excess = inner.entries.len() - MAX_RECORDS;
            for (_, key) in settled.into_iter().take(excess) {
                inner.entries.remove(&key);
            }
        }
        let dropped = inner.entries.len() != before;
        if dropped {
            let entries = &inner.entries;
            inner.cached.retain(|key| entries.contains_key(key));
            inner.cached_bytes = entries.values().map(|entry| entry.reply_bytes).sum();
        }
        dropped
    }

    /// Rewrite the file as one line per kept record.
    fn compact(&self, inner: &mut Inner) -> Result<(), CallRecordError> {
        let mut bytes = header();
        let mut records: Vec<&CallRecord> =
            inner.entries.values().map(|entry| &entry.record).collect();
        records.sort_by(|left, right| {
            (left.started_at_ms, &left.principal, &left.call_key).cmp(&(
                right.started_at_ms,
                &right.principal,
                &right.call_key,
            ))
        });
        for record in records {
            bytes.extend(line(record)?);
        }
        self.storage.replace(&bytes)?;
        inner.header_written = true;
        inner.appended_since_compaction = 0;
        Ok(())
    }

    fn write(
        &self,
        inner: &mut Inner,
        record: &CallRecord,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        if !inner.header_written {
            let mut bytes = header();
            bytes.extend(line(record)?);
            self.storage.replace(&bytes)?;
            inner.header_written = true;
            return Ok(());
        }
        self.storage.append(&line(record)?)?;
        inner.appended_since_compaction += 1;
        if inner.appended_since_compaction >= MAX_RECORDS {
            Self::apply_retention(inner, now_ms);
            self.compact(inner)?;
        }
        Ok(())
    }

    /// Drop a held reply that has outlived the cache's age bound.
    fn expire_reply(inner: &mut Inner, key: &Key) {
        let Some(entry) = inner.entries.get_mut(key) else {
            return;
        };
        if entry
            .cached_at
            .is_some_and(|cached_at| cached_at.elapsed() > CACHE_MAX_AGE)
        {
            entry.reply = None;
            entry.cached_at = None;
            inner.cached_bytes -= std::mem::take(&mut entry.reply_bytes);
        }
    }

    /// Decide what to do with a call carrying `call_key` from `principal`.
    ///
    /// For a key not seen before, the `started` record is synced to disk
    /// before this returns [`Begin::Execute`].
    pub fn begin(
        &self,
        principal: &str,
        call_key: &str,
        conversation_key: &str,
        now_ms: u64,
    ) -> Begin {
        let mut inner = self.lock();
        if let Some(error) = inner.broken.clone() {
            return Begin::Unavailable(error);
        }
        let key: Key = (principal.to_string(), call_key.to_string());
        Self::expire_reply(&mut inner, &key);
        if let Some(entry) = inner.entries.get(&key) {
            return match entry.record.state {
                CallState::Started => Begin::InFlight,
                CallState::Unknown => Begin::OutcomeUnknown,
                CallState::Replied | CallState::Refused => match &entry.reply {
                    Some(reply) => Begin::Replay(reply.clone()),
                    None => Begin::NotRetained {
                        outcome: entry.record.outcome.clone(),
                    },
                },
            };
        }
        let record = CallRecord {
            principal: principal.to_string(),
            call_key: call_key.to_string(),
            scope: None,
            state: CallState::Started,
            outcome: None,
            refusal_reason: None,
            effect_status: None,
            posts_returned: None,
            started_at_ms: now_ms,
            settled_at_ms: None,
        };
        if let Err(error) = self.write(&mut inner, &record, now_ms) {
            return Begin::Unavailable(error);
        }
        inner.entries.insert(
            key.clone(),
            Entry {
                record,
                conversation_key: conversation_key.to_string(),
                ask_id: None,
                reply: None,
                reply_bytes: 0,
                cached_at: None,
            },
        );
        Begin::Execute(CallTicket { key })
    }

    /// Record the call's reply. Call before the reply is sent, so a resend
    /// that follows the reply always finds it.
    ///
    /// A failed write leaves `started` on disk, which a later start reads as
    /// `unknown`: never re-run, only less informative.
    pub fn settle(&self, ticket: CallTicket, settlement: Settlement, now_ms: u64) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let Some(entry) = inner.entries.get_mut(&ticket.key) else {
            return;
        };
        entry.record.state = settlement.state;
        entry.record.outcome = settlement.outcome;
        entry.record.refusal_reason = settlement.refusal_reason;
        entry.record.effect_status = settlement.effect_status;
        entry.record.posts_returned = settlement.posts_returned;
        entry.record.settled_at_ms = Some(now_ms);
        entry.ask_id = settlement.ask_id;
        let record = entry.record.clone();
        let _ = self.write(inner, &record, now_ms);
        let size = settlement.reply.frame.body.len();
        if size <= CACHE_MAX_REPLY_BYTES {
            if let Some(entry) = inner.entries.get_mut(&ticket.key) {
                entry.reply = Some(settlement.reply);
                entry.reply_bytes = size;
                entry.cached_at = Some(Instant::now());
                inner.cached_bytes += size;
                inner.cached.push_back(ticket.key);
            }
            while inner.cached.len() > CACHE_MAX_REPLIES || inner.cached_bytes > CACHE_MAX_BYTES {
                let Some(oldest) = inner.cached.pop_front() else {
                    break;
                };
                if let Some(entry) = inner.entries.get_mut(&oldest) {
                    entry.reply = None;
                    entry.cached_at = None;
                    let freed = std::mem::take(&mut entry.reply_bytes);
                    inner.cached_bytes -= freed;
                }
            }
        }
    }

    /// Record that the call ended without a reply: its route closed first.
    /// It may have acted, so it answers as `unknown` from now on.
    pub fn settle_unknown(&self, ticket: CallTicket, now_ms: u64) {
        let mut inner = self.lock();
        let Some(entry) = inner.entries.get_mut(&ticket.key) else {
            return;
        };
        entry.record.state = CallState::Unknown;
        entry.record.settled_at_ms = Some(now_ms);
        let record = entry.record.clone();
        let _ = self.write(&mut inner, &record, now_ms);
    }

    /// Look a key up for `tool.withdraw` from `principal`.
    pub fn lookup(&self, principal: &str, call_key: &str) -> Lookup {
        let mut inner = self.lock();
        if let Some(error) = inner.broken.clone() {
            return Lookup::Unavailable(error);
        }
        let key: Key = (principal.to_string(), call_key.to_string());
        Self::expire_reply(&mut inner, &key);
        if let Some(entry) = inner.entries.get(&key) {
            return Lookup::Own(entry.snapshot());
        }
        // The owner of the call's scope may also withdraw it. That needs the
        // scope stamped on the route by the daemon, which does not exist yet;
        // until it does, only the principal that raised the call may.
        if inner
            .entries
            .keys()
            .any(|(_, recorded_key)| recorded_key == call_key)
        {
            return Lookup::OtherPrincipal;
        }
        Lookup::Unknown
    }

    /// How many calls are recorded.
    pub fn record_count(&self) -> usize {
        self.lock().entries.len()
    }

    /// Drop every held reply of a conversation whose last route closed. The
    /// durable facts stay, so later answers say the body is not retained.
    pub fn end_conversation(&self, conversation_key: &str) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let mut freed = 0;
        for entry in inner.entries.values_mut() {
            if entry.conversation_key == conversation_key && entry.reply.is_some() {
                entry.reply = None;
                entry.cached_at = None;
                freed += std::mem::take(&mut entry.reply_bytes);
            }
        }
        inner.cached_bytes -= freed;
        let entries = &inner.entries;
        inner
            .cached
            .retain(|key| entries.get(key).is_some_and(|entry| entry.reply.is_some()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::{Flags, Priority, PROTOCOL_VERSION};

    fn reply(body: Value) -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            1,
            1,
            7,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    }

    fn executed(begin: Begin) -> CallTicket {
        match begin {
            Begin::Execute(ticket) => ticket,
            other => panic!("expected to execute, got {other:?}"),
        }
    }

    #[test]
    fn the_key_bound_is_one_to_256_printable_ascii_characters() {
        assert!(valid_call_key("a"));
        assert!(valid_call_key("pf:0193 ~ x"));
        assert!(valid_call_key(&"k".repeat(256)));
        assert!(!valid_call_key(""));
        assert!(!valid_call_key(&"k".repeat(257)));
        assert!(!valid_call_key("tab\there"));
        assert!(!valid_call_key("é"));
        assert!(!valid_call_key("line\n"));
    }

    /// A process that died after writing `started` and before the reply: the
    /// file on disk is reopened, and the call reads as possibly run, never as
    /// unknown and never as runnable.
    #[test]
    fn a_started_record_left_by_a_crash_reads_as_outcome_unknown_after_reopening_from_disk() {
        let directory = std::env::temp_dir().join(format!(
            "cerebellum-call-records-{}-{}",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&directory).unwrap();
        let path = directory.join(CALL_RECORD_FILE);
        let storage = || {
            Box::new(FilesystemCallRecordStorage::new(&path).with_format_floor(
                cerebellum_core::format_floor::FormatFloor::at(directory.join("floor.json")),
            )) as Box<dyn CallRecordStorage>
        };

        let first = CallRecords::open(storage(), 1_000);
        let _ticket = executed(first.begin("reserved:prefrontal-core", "pf:1", "c", 1_000));
        drop(first);

        let reopened = CallRecords::open(storage(), 2_000);
        assert!(matches!(
            reopened.begin("reserved:prefrontal-core", "pf:1", "c", 2_000),
            Begin::OutcomeUnknown
        ));
        match reopened.lookup("reserved:prefrontal-core", "pf:1") {
            Lookup::Own(snapshot) => assert_eq!(
                withdraw_answer(&snapshot),
                json!({"answer": "already_started", "outcome": "unknown"})
            ),
            other => panic!("expected the call's own record, got {other:?}"),
        }
        let floor = fs::read_to_string(directory.join("floor.json")).unwrap();
        assert!(floor.contains("call-records"), "{floor}");
        let _ = fs::remove_dir_all(&directory);
    }

    #[test]
    fn a_settled_call_answers_from_disk_after_a_restart_without_its_body() {
        let storage = InMemoryCallRecordStorage::new();
        let first = CallRecords::open(Box::new(storage.clone()), 1_000);
        let ticket = executed(first.begin("direct", "k", "c", 1_000));
        first.settle(
            ticket,
            Settlement::from_reply(&reply(
                json!({"outcome": "delivery_unconfirmed", "posts_returned": 2}),
            )),
            1_001,
        );
        drop(first);

        let reopened = CallRecords::open(Box::new(storage), 2_000);
        assert!(matches!(
            reopened.begin("direct", "k", "c", 2_000),
            Begin::NotRetained { outcome: Some(ref outcome) } if outcome == "delivery_unconfirmed"
        ));
        let Lookup::Own(snapshot) = reopened.lookup("direct", "k") else {
            panic!("the record survived the restart");
        };
        assert_eq!(
            withdraw_answer(&snapshot),
            json!({"answer": "completed", "outcome": "delivery_unconfirmed", "result_retained": false})
        );
    }

    #[test]
    fn a_torn_last_line_is_ignored_and_a_newer_version_is_refused() {
        let storage = InMemoryCallRecordStorage::new();
        storage
            .replace(
                format!(
                    "{}{{\"principal\":\"dir",
                    String::from_utf8(header()).unwrap()
                )
                .as_bytes(),
            )
            .unwrap();
        let records = CallRecords::open(Box::new(storage), 0);
        assert!(matches!(records.lookup("direct", "k"), Lookup::Unknown));

        let newer = InMemoryCallRecordStorage::new();
        newer
            .replace(b"{\"format\":\"call-records\",\"version\":2}\n")
            .unwrap();
        let records = CallRecords::open(Box::new(newer.clone()), 0);
        assert!(matches!(
            records.begin("direct", "k", "c", 0),
            Begin::Unavailable(CallRecordError::UnknownVersion(2))
        ));
        assert_eq!(
            newer.contents().unwrap(),
            b"{\"format\":\"call-records\",\"version\":2}\n",
            "a newer build's file was overwritten"
        );
    }

    #[test]
    fn a_record_past_retention_answers_unknown_call() {
        let storage = InMemoryCallRecordStorage::new();
        let first = CallRecords::open(Box::new(storage.clone()), 1_000);
        let ticket = executed(first.begin("direct", "k", "c", 1_000));
        first.settle(
            ticket,
            Settlement::from_reply(&reply(json!({"outcome": "ok"}))),
            1_000,
        );
        drop(first);
        let later = 1_001 + RETENTION.as_millis() as u64;
        let reopened = CallRecords::open(Box::new(storage), later);
        assert!(matches!(reopened.lookup("direct", "k"), Lookup::Unknown));
    }

    #[test]
    fn replies_past_the_cache_bound_are_dropped_oldest_first() {
        let records = CallRecords::in_memory();
        for index in 0..=CACHE_MAX_REPLIES {
            let ticket = executed(records.begin("direct", &format!("k{index}"), "c", 1));
            records.settle(
                ticket,
                Settlement::from_reply(&reply(json!({"outcome": "ok"}))),
                1,
            );
        }
        assert!(matches!(
            records.begin("direct", "k0", "c", 1),
            Begin::NotRetained { .. }
        ));
        assert!(matches!(
            records.begin("direct", &format!("k{CACHE_MAX_REPLIES}"), "c", 1),
            Begin::Replay(_)
        ));
        records.end_conversation("c");
        assert!(matches!(
            records.begin("direct", &format!("k{CACHE_MAX_REPLIES}"), "c", 1),
            Begin::NotRetained { .. }
        ));
    }

    #[test]
    fn only_code_shaped_values_are_recorded() {
        let settlement = Settlement::from_reply(&reply(json!({
            "outcome": "Typed secret text",
            "effect_status": "effect_indeterminate",
        })));
        assert_eq!(settlement.outcome, None);
        assert_eq!(
            settlement.effect_status.as_deref(),
            Some("effect_indeterminate")
        );
    }
}
