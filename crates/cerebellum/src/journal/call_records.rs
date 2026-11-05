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
//! closed, text-free facts: principal, call_key, the scope identity (from the
//! daemon's stamp on the call's route, see [`ScopeIdentity`]), the state, the outcome code, a
//! refusal reason code, `effect_status`, `posts_returned` and timestamps. Login
//! handoffs also keep a canonical origin, scope and closed settlement codes,
//! never the observations used to recognize login. It
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
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use cerebellum_core::journal::CallOriginRecord;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use subc_protocol::{Frame, FrameType, Principal};

mod late;
pub use late::{ConsentEnding, HandoffEnding, HeldHandoff};

/// The file name under the journal data home.
pub const CALL_RECORD_FILE: &str = "call_records.jsonl";

/// The highest file version this build writes, and the newest it reads.
///
/// Version 3 adds text-free login handoff state and acknowledgements. Older
/// files advance to version 3 only when a handoff is recorded; ordinary calls
/// still use the version 2 format so placing a build does not close rollback.
/// Version 4 adds capture handoffs and their closed settlement vocabulary.
/// Only the first capture handoff requires reader 4; `browser.present` handoffs
/// remain readable by reader 3.
/// Version 5 adds consent custody. Only a held consent reply requires reader 5.
/// Version 6 adds scope-ended and unobserved-deposit settlements. Only the first
/// entry of either kind requires reader 6; startup and ordinary late-result pulls
/// do not raise the file's minimum reader version.
pub const CALL_RECORD_VERSION: u64 = 6;

const ORDINARY_CALL_RECORD_VERSION: u64 = 2;
const HANDOFF_CALL_RECORD_VERSION: u64 = 3;

/// The oldest file version this build reads.
const OLDEST_READ_CALL_RECORD_VERSION: u64 = 1;

/// The file's format, as the format floor and staging name it.
pub const CALL_RECORD_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new("call-records", CALL_RECORD_VERSION);

/// The name `tool.withdraw` arrives under on a tool route.
pub const WITHDRAW_OPERATION: &str = "tool.withdraw";

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

/// Whether `key` is an acceptable `call_key`, by the shared wire crate's own
/// rule (1 to 256 printable ASCII characters, 0x21 to 0x7E, no space), so every
/// provider and carrier agrees on the same bound.
pub fn valid_call_key(key: &str) -> bool {
    subc_protocol::tool_call::validate_call_key(key).is_ok()
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
/// Taken only from the scope stamp the daemon put on the call's route bind,
/// never from a request body: a scope named in a request is caller-chosen, so
/// recording it would put an identity nobody verified into an audit record.
/// Absent for a call on a route opened without a scope.
///
/// These are identifiers (a principal label, the owner's opaque session ref,
/// a number), not screen text. The field has been part of this file's format
/// since its first version, so recording it changes no format version.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ScopeIdentity {
    pub owner: String,
    #[serde(rename = "ref")]
    pub reference: String,
    pub scope_epoch: u64,
}

impl ScopeIdentity {
    /// The identity a daemon scope stamp names.
    pub fn from_stamp(stamp: &subc_protocol::scope::ScopeStamp) -> Self {
        Self {
            owner: principal_label(Some(&stamp.owner)),
            reference: stamp.scope_ref.clone(),
            scope_epoch: stamp.scope_epoch,
        }
    }
}

/// Where a recorded call stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallState {
    /// Accepted and running in this process.
    Started,
    /// A dispatch was committed and the reply is final: the action ran.
    Replied,
    /// Nothing was dispatched, and that is proven (see [`DispatchEvidence`]):
    /// the action never ran.
    Refused,
    /// Nothing was dispatched: the call stopped to ask a person
    /// (`consent_pending`). It never ran, and never will, since cerebellum
    /// holds no call to run later.
    Asked,
    /// It may or may not have run: a dispatch was committed and its effect is
    /// indeterminate, or nothing proves that no dispatch was committed, or no
    /// reply was recorded (the module stopped, or the route closed, first).
    Unknown,
}

/// One call, as written to the durable file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallRecord {
    pub principal: String,
    /// Opaque caller identity, not a page address: preserve even URL-shaped
    /// keys exactly for idempotency after restart and for echoing in late_results.
    /// URL projection or hashing would change the caller's wire identity.
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
    /// The caller behind a relayed call, as the first call with this key
    /// named it. Attribution only: the record is found by `principal` and
    /// `call_key` alone, so a resend naming another origin is still the same
    /// call. Omitted when the call named no origin.
    #[serde(default, skip_serializing_if = "CallOriginRecord::is_absent")]
    pub origin: CallOriginRecord,
    pub started_at_ms: u64,
    #[serde(default)]
    pub settled_at_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<HeldHandoff>,
}

impl CallRecord {
    fn required_version(&self) -> u64 {
        match &self.handoff {
            Some(handoff) if handoff.requires_reader_6() => CALL_RECORD_VERSION,
            Some(handoff) if handoff.is_consent() => 5,
            Some(handoff) if handoff.is_capture() => 4,
            Some(_) => HANDOFF_CALL_RECORD_VERSION,
            None => ORDINARY_CALL_RECORD_VERSION,
        }
    }

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
///
/// Filesystem storage records the minimum reader version in a format-floor
/// file before writing data. Staging checks that file and rejects a build
/// whose reader is too old; the bytes must never get ahead of that safeguard.
pub trait CallRecordStorage: Send + Sync {
    /// The whole file, or `None` if it was never written.
    fn load(&self) -> Result<Option<Vec<u8>>, CallRecordError>;
    /// Append and sync bytes after recording `version` as the minimum reader.
    /// `version` is the log header's version, not this build's reader maximum.
    fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError>;
    /// Replace the file atomically after recording its minimum reader `version`.
    fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError>;
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

    fn append(&self, bytes: &[u8], _version: u64) -> Result<(), CallRecordError> {
        self.bytes
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert_with(Vec::new)
            .extend_from_slice(bytes);
        Ok(())
    }

    fn replace(&self, bytes: &[u8], _version: u64) -> Result<(), CallRecordError> {
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

    fn raise_floor(&self, version: u64) -> Result<(), CallRecordError> {
        // Before anything is written: a file in this format with no floor
        // naming it would let staging pass a build that cannot read it.
        self.floor
            .raise(cerebellum_core::format_floor::DurableFormat::new(
                CALL_RECORD_FORMAT.name,
                version,
            ))
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

    fn append(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
        self.raise_floor(version)?;
        let failed = |error: std::io::Error| CallRecordError::WriteFailed(error.to_string());
        let mut file = cerebellum_core::private_fs::open_append(&self.path).map_err(failed)?;
        file.write_all(bytes).map_err(failed)?;
        file.sync_data().map_err(failed)
    }

    fn replace(&self, bytes: &[u8], version: u64) -> Result<(), CallRecordError> {
        self.raise_floor(version)?;
        let failed = |error: std::io::Error| CallRecordError::WriteFailed(error.to_string());
        let directory = self.directory();
        cerebellum_core::private_fs::create_dir_all(&directory).map_err(failed)?;
        let temporary = directory.join(format!(
            ".{CALL_RECORD_FILE}.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        // Written beside the target and renamed over it, so a crash mid-write
        // leaves the old file or the new one, never half of one.
        let written = (|| {
            let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
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
    /// The id of the consent question a `consent_pending` reply left open, so
    /// a withdrawal can close it. Kept in memory only: a module restart closes
    /// every open consent question, so after one there is nothing to close.
    ask_id: Option<String>,
    reply: CachedReply,
}

/// What the handler observed while the call ran, beside its reply.
///
/// `refused` needs positive evidence that nothing was dispatched: a runner
/// reads `refused` as "never ran" and may run the action again, so a wrong
/// `refused` is a double execution. Everything ambiguous settles as unknown.
#[derive(Debug, Clone, Copy, Default)]
pub struct DispatchEvidence {
    /// The terminal arbiter observed the dispatch gate's sticky dispatch bit.
    /// It can be set before the witness is committed, so either bit rules out
    /// proof that the call never dispatched.
    pub gate_dispatched: bool,
    /// The request's witness was marked at a plane's dispatch commitment.
    pub committed: bool,
    /// The call reached a plane every one of whose dispatches passes a
    /// commitment that marks the witness, so an unmarked witness means none
    /// was made.
    pub commit_point: bool,
    /// A commitment no request could claim happened while the call ran. It
    /// might have been this call's, so the call's unmarked witness proves
    /// nothing.
    pub unattributed_commit: bool,
    /// The reply is one the tool handler sends from its checks before any
    /// plane is reached (a malformed request, an unbound route, a refused
    /// caller or capability).
    pub refused_before_dispatch: bool,
}

impl Settlement {
    /// Read the facts to record from the call's terminal frame and what the
    /// handler observed.
    ///
    /// Only closed codes are taken, each checked to look like one, so a reply
    /// that put text where a code belongs records nothing for it.
    pub fn from_reply(frame: &Frame, evidence: DispatchEvidence) -> Self {
        let body: Value = serde_json::from_slice(&frame.body).unwrap_or(Value::Null);
        let reply = CachedReply {
            frame: frame.clone(),
        };
        let is_error = frame.header.ty == FrameType::Error;
        let structured = body.get("structuredContent").unwrap_or(&body);
        let outcome = if is_error {
            code(body.get("code"))
        } else {
            code(structured.get("outcome"))
        };
        let effect_status = code(structured.get("effect_status"));
        let indeterminate = is_error
            || outcome.as_deref() == Some("dispatch_outcome_unknown")
            || effect_status.as_deref() == Some("effect_indeterminate");
        let never_dispatched = !evidence.gate_dispatched
            && !evidence.committed
            && !evidence.unattributed_commit
            && (evidence.refused_before_dispatch || evidence.commit_point);
        let state = if evidence.committed {
            if indeterminate {
                CallState::Unknown
            } else {
                CallState::Replied
            }
        } else if !never_dispatched {
            CallState::Unknown
        } else if outcome.as_deref() == Some("consent_pending") {
            CallState::Asked
        } else {
            CallState::Refused
        };
        // A person's denial, as the computer plane words it and as the browser
        // plane words it (a refused authorization whose question was declined).
        let denied = outcome.as_deref() == Some("consent_denied")
            || (outcome.as_deref() == Some("authorization_denied")
                && body.pointer("/detail/decision").and_then(Value::as_str) == Some("declined"));
        let refusal_reason = (state == CallState::Refused).then(|| {
            if denied {
                "denied".to_string()
            } else {
                outcome
                    .clone()
                    .unwrap_or_else(|| "not_dispatched".to_string())
            }
        });
        let ask_id = (state == CallState::Asked)
            .then(|| {
                body.get("ask_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .flatten();
        Self {
            state,
            refusal_reason,
            outcome,
            effect_status,
            posts_returned: body.get("posts_returned").and_then(Value::as_u64),
            ask_id,
            reply,
        }
    }

    /// An admission that finished after its caller stopped waiting must never
    /// authorize execution. Keep the unavailable frame for replay, with the
    /// durable reason distinguishing this refusal from a store write failure.
    pub fn admission_timeout(frame: &Frame) -> Self {
        let mut settlement = Self::from_reply(
            frame,
            DispatchEvidence {
                refused_before_dispatch: true,
                ..DispatchEvidence::default()
            },
        );
        settlement.refusal_reason = Some("call_record_admission_timeout".to_string());
        settlement
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
    /// The scope the call was recorded under, which decides whether a scope's
    /// owner may withdraw it.
    pub scope: Option<ScopeIdentity>,
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
        CallState::Asked => json!({"answer": "withdrawn"}),
        CallState::Replied => match snapshot.reply.as_ref().and_then(CachedReply::result) {
            Some(result) => {
                json!({"answer": "completed", "result": result, "result_retained": true})
            }
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
    consent_ended: bool,
    // Capture can start depositing after its held reply. Process-local only:
    // pending captures restart as handoff_interrupted, without a dispatch mark.
    held_dispatched: bool,
    record: CallRecord,
    conversation_key: String,
    ask_id: Option<String>,
    reply: Option<CachedReply>,
    reply_bytes: usize,
    cached_at: Option<Instant>,
    late_seq: Option<u64>,
}

impl Entry {
    fn snapshot(&self) -> CallSnapshot {
        CallSnapshot {
            scope: self.record.scope.clone(),
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
    /// The header actually written, not the highest version this build reads.
    /// It increases only when a record needs newer fields, and never decreases.
    file_version: u64,
    appended_since_compaction: usize,
    entries: HashMap<Key, Entry>,
    cached: VecDeque<Key>,
    cached_bytes: usize,
    incarnation: String,
    late_heads: HashMap<String, u64>,
    handoffs: HashMap<String, Key>,
    ended_scopes: std::collections::HashSet<ScopeIdentity>,
}

/// The call records of one module process.
pub struct CallRecords {
    pub(crate) display: std::sync::OnceLock<crate::tool_display::WeakRecords>,
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

fn header(version: u64) -> Vec<u8> {
    let mut line = serde_json::to_vec(&json!({
        "format": CALL_RECORD_FORMAT.name,
        "version": version,
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
///
/// Also says which version the file's header names (the current one for an
/// empty file), so an older file can be rewritten under the current header.
fn parse_versioned(bytes: &[u8]) -> Result<(u64, Vec<CallRecord>), CallRecordError> {
    let text =
        std::str::from_utf8(bytes).map_err(|error| CallRecordError::Corrupt(error.to_string()))?;
    let mut lines: Vec<&str> = text.split('\n').collect();
    // `split` leaves the text after the last newline: empty for a whole file,
    // a torn record otherwise. Either way it is not a record.
    lines.pop();
    let mut lines = lines.into_iter();
    let Some(first) = lines.next() else {
        return Ok((ORDINARY_CALL_RECORD_VERSION, Vec::new()));
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
    if !(OLDEST_READ_CALL_RECORD_VERSION..=CALL_RECORD_VERSION).contains(&version) {
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
        .collect::<Result<_, _>>()
        .map(|records| (version, records))
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
            display: std::sync::OnceLock::new(),
            storage: Box::new(InMemoryCallRecordStorage::new()),
            inner: Mutex::new(Inner {
                broken: Some(error),
                header_written: false,
                file_version: ORDINARY_CALL_RECORD_VERSION,
                appended_since_compaction: 0,
                entries: HashMap::new(),
                cached: VecDeque::new(),
                cached_bytes: 0,
                incarnation: late::incarnation(),
                late_heads: HashMap::new(),
                handoffs: HashMap::new(),
                ended_scopes: Default::default(),
            }),
        }
    }

    /// Open over `storage`, reconciling what a previous process left.
    ///
    /// A record still `started` belonged to a process that stopped before the
    /// call replied; it becomes `unknown`. Records past retention are dropped.
    /// If anything changed the file is rewritten at once, so the reconciled
    /// state is what the next start reads too.
    ///
    /// Files with headers 1 or 2 are left unchanged until a record is written.
    /// Ordinary writes keep version 2 (migrating v1 as before), which builds
    /// with version 2 readers can still read. Present requires reader 3 and
    /// capture requires reader 4. Saving that minimum reader in the format
    /// floor makes staging reject an incompatible rollback build, and the file
    /// header lets an older reader refuse before decoding unfamiliar state.
    /// Starting or polling must not prevent returning to a compatible build.
    /// A crashed record can be reconciled in memory again on the next start
    /// without rewriting the file.
    pub fn open(storage: Box<dyn CallRecordStorage>, now_ms: u64) -> Self {
        let loaded = storage.load().and_then(|bytes| match bytes {
            None => Ok(None),
            Some(bytes) if bytes.is_empty() => Ok(None),
            Some(bytes) => parse_versioned(&bytes).map(Some),
        });
        let (records, existed, file_version) = match loaded {
            Ok(Some((version, records))) => (records, true, version),
            Ok(None) => (Vec::new(), false, ORDINARY_CALL_RECORD_VERSION),
            Err(error) => {
                let mut broken = Self::broken(error);
                broken.storage = storage;
                return broken;
            }
        };
        let mut inner = Inner {
            broken: None,
            header_written: existed,
            file_version,
            appended_since_compaction: 0,
            entries: HashMap::new(),
            cached: VecDeque::new(),
            cached_bytes: 0,
            incarnation: late::incarnation(),
            late_heads: HashMap::new(),
            handoffs: HashMap::new(),
            ended_scopes: Default::default(),
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
                    consent_ended: false,
                    held_dispatched: false,
                    record,
                    conversation_key: String::new(),
                    ask_id: None,
                    reply: None,
                    reply_bytes: 0,
                    cached_at: None,
                    late_seq: None,
                },
            );
        }
        let records = Self {
            display: std::sync::OnceLock::new(),
            storage,
            inner: Mutex::new(inner),
        };
        {
            let mut inner = records.lock();
            // Resolve pending handoffs only after selecting the last journal
            // row for each call key. An older pending row may be followed by
            // a saved result or acknowledgement that must not be overwritten.
            reconciled |= late::reconcile(&mut inner, now_ms);
            if let Err(error) = records.bound_late(&mut inner, now_ms) {
                inner.broken = Some(error);
            }
            let dropped = Self::apply_retention(&mut inner, now_ms);
            if existed
                && file_version >= HANDOFF_CALL_RECORD_VERSION
                && (reconciled || dropped || line_count != inner.entries.len())
            {
                if let Err(error) = records.compact(&mut inner, file_version) {
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
            entry.record.state == CallState::Started
                || late::unacked(&entry.record)
                || entry.record.last_written_ms() >= horizon
        });
        if inner.entries.len() > MAX_RECORDS {
            let mut settled: Vec<(u64, Key)> = inner
                .entries
                .iter()
                .filter(|(_, entry)| {
                    entry.record.state != CallState::Started && !late::unacked(&entry.record)
                })
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
    fn compact(&self, inner: &mut Inner, version: u64) -> Result<(), CallRecordError> {
        let mut bytes = header(version);
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
        self.storage.replace(&bytes, version)?;
        inner.header_written = true;
        inner.file_version = version;
        inner.appended_since_compaction = 0;
        Ok(())
    }

    fn write(
        &self,
        inner: &mut Inner,
        record: &CallRecord,
        now_ms: u64,
    ) -> Result<(), CallRecordError> {
        let version = inner.file_version.max(record.required_version());
        if !inner.header_written {
            let mut bytes = header(version);
            bytes.extend(line(record)?);
            self.storage.replace(&bytes, version)?;
            inner.header_written = true;
            inner.file_version = version;
            return Ok(());
        }
        // Upgrade only for fields the incoming record needs. An unnecessary
        // version 3 header would record minimum reader 3 in the format floor,
        // making staging reject an otherwise compatible version 2 build just
        // because the relay puts a call key on every tool request.
        if inner.file_version < version {
            self.compact(inner, version)?;
        }
        self.storage.append(&line(record)?, inner.file_version)?;
        inner.appended_since_compaction += 1;
        if inner.appended_since_compaction >= MAX_RECORDS {
            Self::apply_retention(inner, now_ms);
            self.compact(inner, version)?;
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
        self.begin_scoped(principal, call_key, conversation_key, None, now_ms)
    }

    /// [`Self::begin`] for a call whose route carries a daemon scope stamp:
    /// a new record stores `scope`. A key already recorded is answered from
    /// its record exactly as [`Self::begin`] answers it.
    pub fn begin_scoped(
        &self,
        principal: &str,
        call_key: &str,
        conversation_key: &str,
        scope: Option<ScopeIdentity>,
        now_ms: u64,
    ) -> Begin {
        self.begin_attributed(
            principal,
            call_key,
            conversation_key,
            scope,
            CallOriginRecord::Absent,
            now_ms,
        )
    }

    /// [`Self::begin_scoped`] for a call that names the caller behind it: a
    /// new record stores `origin`. The origin takes no part in finding the
    /// record, so a key already recorded is answered exactly as
    /// [`Self::begin_scoped`] answers it, whatever origin either call named.
    pub fn begin_attributed(
        &self,
        principal: &str,
        call_key: &str,
        conversation_key: &str,
        scope: Option<ScopeIdentity>,
        origin: CallOriginRecord,
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
                CallState::Unknown if entry.reply.is_none() => Begin::OutcomeUnknown,
                CallState::Replied | CallState::Refused | CallState::Asked | CallState::Unknown => {
                    match &entry.reply {
                        Some(reply) => Begin::Replay(reply.clone()),
                        None => Begin::NotRetained {
                            outcome: entry.record.outcome.clone(),
                        },
                    }
                }
            };
        }
        let record = CallRecord {
            principal: principal.to_string(),
            call_key: call_key.to_string(),
            scope,
            state: CallState::Started,
            outcome: None,
            refusal_reason: None,
            effect_status: None,
            posts_returned: None,
            origin,
            started_at_ms: now_ms,
            settled_at_ms: None,
            handoff: None,
        };
        if let Err(error) = self.write(&mut inner, &record, now_ms) {
            return Begin::Unavailable(error);
        }
        inner.entries.insert(
            key.clone(),
            Entry {
                consent_ended: false,
                held_dispatched: false,
                record,
                conversation_key: conversation_key.to_string(),
                ask_id: None,
                reply: None,
                reply_bytes: 0,
                cached_at: None,
                late_seq: None,
            },
        );
        Begin::Execute(CallTicket { key })
    }

    /// Record the call's reply. The handler waits for this write before sending
    /// the frame only within its settlement budget; a late write preserves the
    /// same terminal reply while a retry may still find the call in flight.
    ///
    /// A failed write leaves `started` on disk, which a later start reads as
    /// `unknown`: never re-run, only less informative.
    pub fn settle(&self, ticket: CallTicket, mut settlement: Settlement, now_ms: u64) {
        let mut guard = self.lock();
        let inner = &mut *guard;
        let Some(entry) = inner.entries.get_mut(&ticket.key) else {
            return;
        };
        if let Some(result) = late::settled_result(&entry.record) {
            // A fast resume may settle before the initial held reply is cached.
            // Preserve that ending instead of caching an already-obsolete hold.
            settlement.state = entry.record.state;
            settlement.outcome = entry.record.outcome.clone();
            settlement.refusal_reason = entry.record.refusal_reason.clone();
            settlement.reply.frame.body =
                serde_json::to_vec(&result).expect("handoff result serializes");
        }
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
        if entry.record.outcome.as_deref()
            == Some(cortexkit_role_tool_provider::late_results::reasons::SCOPE_ENDED)
        {
            return;
        }
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
        // A scope's owner withdrawing a call it did not raise names the
        // carrier and comes through [`Self::lookup_exact`] instead; here only
        // the principal that raised the call finds it.
        if inner
            .entries
            .keys()
            .any(|(_, recorded_key)| recorded_key == call_key)
        {
            return Lookup::OtherPrincipal;
        }
        Lookup::Unknown
    }

    /// The call `call_key` raised by exactly `carrier`, for a scope owner's
    /// withdraw: [`Lookup::Own`] with the carrier's record, or
    /// [`Lookup::Unknown`]. Never matched by key alone, so a key another
    /// principal also used can never answer for the carrier's call.
    pub fn lookup_exact(&self, carrier: &str, call_key: &str) -> Lookup {
        let mut inner = self.lock();
        if let Some(error) = inner.broken.clone() {
            return Lookup::Unavailable(error);
        }
        let key: Key = (carrier.to_string(), call_key.to_string());
        Self::expire_reply(&mut inner, &key);
        match inner.entries.get(&key) {
            Some(entry) => Lookup::Own(entry.snapshot()),
            None => Lookup::Unknown,
        }
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

    /// A call whose dispatch was committed.
    fn ran() -> DispatchEvidence {
        DispatchEvidence {
            committed: true,
            commit_point: true,
            ..DispatchEvidence::default()
        }
    }

    fn executed(begin: Begin) -> CallTicket {
        match begin {
            Begin::Execute(ticket) => ticket,
            other => panic!("expected to execute, got {other:?}"),
        }
    }

    #[test]
    fn the_key_bound_is_the_wire_crates_one_to_256_printable_non_space_ascii() {
        assert!(valid_call_key("a"));
        assert!(valid_call_key("pf:0193~x"));
        assert!(valid_call_key(&"k".repeat(256)));
        assert!(!valid_call_key(""));
        assert!(!valid_call_key(&"k".repeat(257)));
        assert!(!valid_call_key("pf:0193 x"), "space is outside the bound");
        assert!(!valid_call_key("tab\there"));
        assert!(!valid_call_key("é"));
        assert!(!valid_call_key("line\n"));
    }

    /// A process that died after writing `started` and before the reply: the
    /// file on disk is reopened, and the call reads as possibly run, never as
    /// unknown and never as runnable.
    #[test]
    fn a_started_record_left_by_a_crash_reads_as_outcome_unknown_after_reopening_from_disk() {
        let scratch = ScratchDirectory::new("crash");
        let directory = scratch.0.clone();
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
    }

    #[test]
    fn a_settled_call_answers_from_disk_after_a_restart_without_its_body() {
        let storage = InMemoryCallRecordStorage::new();
        let first = CallRecords::open(Box::new(storage.clone()), 1_000);
        let ticket = executed(first.begin("direct", "k", "c", 1_000));
        first.settle(
            ticket,
            Settlement::from_reply(
                &reply(json!({"outcome": "delivery_unconfirmed", "posts_returned": 2})),
                ran(),
            ),
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
                    String::from_utf8(header(2)).unwrap()
                )
                .as_bytes(),
                2,
            )
            .unwrap();
        let records = CallRecords::open(Box::new(storage), 0);
        assert!(matches!(records.lookup("direct", "k"), Lookup::Unknown));

        let newer = InMemoryCallRecordStorage::new();
        let future_version = CALL_RECORD_VERSION + 1;
        let future_bytes = header(future_version);
        newer.replace(&future_bytes, future_version).unwrap();
        let records = CallRecords::open(Box::new(newer.clone()), 0);
        assert!(matches!(
            records.begin("direct", "k", "c", 0),
            Begin::Unavailable(CallRecordError::UnknownVersion(version)) if version == future_version
        ));
        assert_eq!(
            newer.contents().unwrap(),
            future_bytes,
            "a newer build's file was overwritten"
        );
    }

    /// A version 1 file as the previous build wrote it: one settled call and
    /// one a crash left `started`, which opening reconciles.
    const V1_FILE: &str = concat!(
        "{\"format\":\"call-records\",\"version\":1}\n",
        "{\"principal\":\"reserved:prefrontal-core\",\"call_key\":\"pf:v1\",",
        "\"scope\":null,\"state\":\"replied\",\"outcome\":\"ok\",",
        "\"refusal_reason\":null,\"effect_status\":null,\"posts_returned\":null,",
        "\"started_at_ms\":10,\"settled_at_ms\":20}\n",
        "{\"principal\":\"reserved:prefrontal-core\",\"call_key\":\"pf:v1-started\",",
        "\"scope\":null,\"state\":\"started\",\"outcome\":null,",
        "\"refusal_reason\":null,\"effect_status\":null,\"posts_returned\":null,",
        "\"started_at_ms\":15,\"settled_at_ms\":null}\n",
    );

    /// A fresh directory for one test, removed when the guard drops, which
    /// includes a test that fails part way: a cleanup line at the end of the
    /// test body never runs after a failed assertion, and the directory would
    /// stay behind in the temporary folder.
    struct ScratchDirectory(PathBuf);

    impl ScratchDirectory {
        fn new(name: &str) -> Self {
            let directory = std::env::temp_dir().join(format!(
                "cerebellum-call-records-{name}-{}-{}",
                std::process::id(),
                TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&directory).unwrap();
            Self(directory)
        }
    }

    impl Drop for ScratchDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    /// A v1 file on disk with its own format floor, in a fresh directory.
    fn v1_on_disk(name: &str) -> (ScratchDirectory, PathBuf, PathBuf) {
        let scratch = ScratchDirectory::new(name);
        let path = scratch.0.join(CALL_RECORD_FILE);
        fs::write(&path, V1_FILE).unwrap();
        let floor = scratch.0.join("floor.json");
        (scratch, path, floor)
    }

    fn open_on_disk(path: &Path, floor: &Path, now_ms: u64) -> CallRecords {
        CallRecords::open(
            Box::new(
                FilesystemCallRecordStorage::new(path)
                    .with_format_floor(cerebellum_core::format_floor::FormatFloor::at(floor)),
            ),
            now_ms,
        )
    }

    /// Starting this build over a version 1 file, and answering from it,
    /// writes nothing: the file keeps its bytes and the call-records floor is
    /// not raised, so the previous build can still be placed again.
    #[test]
    fn a_version_1_file_is_read_as_it_stands_while_no_call_is_recorded() {
        let (_scratch, path, floor) = v1_on_disk("v1-no-call");
        let records = open_on_disk(&path, &floor, 30);

        // Both records are read, the started one reconciled in memory.
        assert!(matches!(
            records.begin("reserved:prefrontal-core", "pf:v1", "c", 40),
            Begin::NotRetained { outcome } if outcome.as_deref() == Some("ok")
        ));
        assert!(matches!(
            records.begin("reserved:prefrontal-core", "pf:v1-started", "c", 40),
            Begin::OutcomeUnknown
        ));
        drop(records);

        assert_eq!(fs::read_to_string(&path).unwrap(), V1_FILE);
        assert!(
            !floor.exists(),
            "opening raised the floor: {}",
            fs::read_to_string(&floor).unwrap_or_default()
        );
    }

    #[test]
    fn a_version_2_file_is_not_upgraded_by_startup_or_a_late_pull() {
        let (_scratch, path, floor) = v1_on_disk("v2-no-call");
        let v2 = V1_FILE.replacen("\"version\":1", "\"version\":2", 1);
        fs::write(&path, &v2).unwrap();
        let records = open_on_disk(&path, &floor, 30);
        let reply = records
            .late_results(
                "reserved:prefrontal-core",
                &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
                40,
            )
            .unwrap();
        assert!(reply.entries.is_empty());
        assert_eq!(fs::read_to_string(&path).unwrap(), v2);
        assert!(
            !floor.exists(),
            "a read-only start prevented rollback to version 2"
        );
    }

    /// Ordinary calls write no handoff fields, preserving the version 2
    /// encoding that builds with version 2 readers already understand.
    #[test]
    fn an_ordinary_call_moves_a_version_1_file_to_version_2() {
        let (_scratch, path, floor) = v1_on_disk("v1-one-call");
        let records = open_on_disk(&path, &floor, 30);
        let _ticket = executed(records.begin_attributed(
            "reserved:prefrontal-core",
            "pf:v2",
            "c",
            None,
            CallOriginRecord::OriginInvalid,
            40,
        ));
        drop(records);

        let written = fs::read_to_string(&path).unwrap();
        let mut lines = written.lines();
        assert_eq!(
            lines.next(),
            Some("{\"format\":\"call-records\",\"version\":2}"),
            "{written}"
        );
        let records: Vec<CallRecord> = lines
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        let state_of = |key: &str| {
            records
                .iter()
                .rev()
                .find(|record| record.call_key == key)
                .map(|record| (record.state, record.origin.clone()))
        };
        assert_eq!(
            state_of("pf:v1"),
            Some((CallState::Replied, CallOriginRecord::Absent))
        );
        assert_eq!(
            state_of("pf:v1-started"),
            Some((CallState::Unknown, CallOriginRecord::Absent))
        );
        assert_eq!(
            state_of("pf:v2"),
            Some((CallState::Started, CallOriginRecord::OriginInvalid))
        );
        let floors = cerebellum_core::format_floor::read_floors(&floor).unwrap();
        assert_eq!(floors.get("call-records"), Some(&2));
    }

    #[test]
    fn a_keyed_non_handoff_call_keeps_a_version_2_file_and_floor() {
        let (_scratch, path, floor) = v1_on_disk("v2-ordinary-call");
        let v2 = V1_FILE.replacen("\"version\":1", "\"version\":2", 1);
        fs::write(&path, &v2).unwrap();
        let records = open_on_disk(&path, &floor, 30);
        let ticket = executed(records.begin_attributed(
            "reserved:prefrontal-core",
            "pf:ordinary",
            "c",
            None,
            CallOriginRecord::OriginInvalid,
            40,
        ));
        records.settle(
            ticket,
            Settlement::from_reply(&reply(json!({"outcome":"ok"})), ran()),
            50,
        );
        let written = fs::read_to_string(&path).unwrap();
        assert_eq!(
            written.lines().next(),
            Some("{\"format\":\"call-records\",\"version\":2}")
        );
        assert!(
            !written.contains("\"handoff\""),
            "an ordinary call acquired handoff fields"
        );
        assert_eq!(
            cerebellum_core::format_floor::read_floors(&floor)
                .unwrap()
                .get("call-records"),
            Some(&2)
        );
    }

    #[test]
    fn first_consent_hold_upgrades_the_file_and_floor_without_losing_old_calls() {
        let (_scratch, path, floor) = v1_on_disk("consent-reader");
        let records = open_on_disk(&path, &floor, 30);
        let scope = ScopeIdentity {
            owner: "reserved:prefrontal-core".into(),
            reference: "run".into(),
            scope_epoch: 1,
        };
        let _ticket =
            executed(records.begin_scoped("reserved:basal", "consent-key", "c", Some(scope), 40));
        assert_eq!(
            cerebellum_core::format_floor::read_floors(&floor)
                .unwrap()
                .get("call-records"),
            Some(&2)
        );
        records
            .hold_consent("reserved:basal", "consent-key", "ask", 50)
            .unwrap();
        assert_eq!(
            cerebellum_core::format_floor::read_floors(&floor)
                .unwrap()
                .get("call-records"),
            Some(&5)
        );
        assert_eq!(
            fs::read_to_string(&path).unwrap().lines().next(),
            Some("{\"format\":\"call-records\",\"version\":5}")
        );
        drop(records);
        let reopened = open_on_disk(&path, &floor, 60);
        assert!(
            matches!(reopened.begin("reserved:prefrontal-core", "pf:v1", "c", 70), Begin::NotRetained { outcome } if outcome.as_deref() == Some("ok"))
        );
        let late = reopened
            .late_results(
                "reserved:basal",
                &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
                70,
            )
            .unwrap();
        assert_eq!(late.entries[0].extra["detail"]["consent"], "withdrawn");
    }

    #[test]
    fn a_fresh_ordinary_call_starts_in_version_2() {
        let storage = InMemoryCallRecordStorage::new();
        let records = CallRecords::open(Box::new(storage.clone()), 0);
        let _ticket = executed(records.begin("reserved:prefrontal-core", "pf:ordinary", "c", 10));
        let written = String::from_utf8(storage.contents().unwrap()).unwrap();
        assert_eq!(
            written.lines().next(),
            Some("{\"format\":\"call-records\",\"version\":2}")
        );
    }

    #[test]
    fn an_empty_journal_does_not_activate_the_capture_format() {
        let storage = InMemoryCallRecordStorage::new();
        storage.replace(b"", 2).unwrap();
        let records = CallRecords::open(Box::new(storage.clone()), 0);
        assert_eq!(storage.contents().unwrap(), b"");
        let _ticket = executed(records.begin("reserved:prefrontal-core", "pf:ordinary", "c", 10));
        let written = String::from_utf8(storage.contents().unwrap()).unwrap();
        assert_eq!(
            written.lines().next(),
            Some("{\"format\":\"call-records\",\"version\":2}")
        );
    }

    #[test]
    fn a_record_past_retention_answers_unknown_call() {
        let storage = InMemoryCallRecordStorage::new();
        let first = CallRecords::open(Box::new(storage.clone()), 1_000);
        let ticket = executed(first.begin("direct", "k", "c", 1_000));
        first.settle(
            ticket,
            Settlement::from_reply(&reply(json!({"outcome": "ok"})), ran()),
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
                Settlement::from_reply(&reply(json!({"outcome": "ok"})), ran()),
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
        let settlement = Settlement::from_reply(
            &reply(json!({
                "outcome": "Typed secret text",
                "effect_status": "effect_indeterminate",
            })),
            ran(),
        );
        assert_eq!(settlement.outcome, None);
        assert_eq!(
            settlement.effect_status.as_deref(),
            Some("effect_indeterminate")
        );
    }

    /// `refused` only with proof nothing was dispatched; anything ambiguous is
    /// unknown.
    #[test]
    fn a_call_is_refused_only_when_nothing_can_have_been_dispatched() {
        let refusal = || reply(json!({"outcome": "no_grant", "effect_status": "not_dispatched"}));
        let state = |evidence| Settlement::from_reply(&refusal(), evidence).state;
        let reached_plane = DispatchEvidence {
            commit_point: true,
            ..DispatchEvidence::default()
        };
        assert_eq!(state(reached_plane), CallState::Refused);
        assert_eq!(
            Settlement::from_reply(&refusal(), reached_plane)
                .refusal_reason
                .as_deref(),
            Some("no_grant")
        );
        // No commit point: the op could have acted without one.
        assert_eq!(state(DispatchEvidence::default()), CallState::Unknown);
        // A commit nobody could claim happened meanwhile.
        assert_eq!(
            state(DispatchEvidence {
                unattributed_commit: true,
                ..reached_plane
            }),
            CallState::Unknown
        );
        // Committed: it ran, whatever the reply's words.
        assert_eq!(state(ran()), CallState::Replied);
        let indeterminate = reply(
            json!({"outcome": "delivery_unconfirmed", "effect_status": "effect_indeterminate"}),
        );
        assert_eq!(
            Settlement::from_reply(&indeterminate, ran()).state,
            CallState::Unknown
        );
        let pending = reply(json!({"outcome": "consent_pending", "ask_id": "ask-1"}));
        let asked = Settlement::from_reply(&pending, reached_plane);
        assert_eq!(asked.state, CallState::Asked);
        assert_eq!(asked.ask_id.as_deref(), Some("ask-1"));
    }

    #[test]
    fn terminal_gate_and_witness_settlement_truth_table() {
        let unknown = reply(json!({
            "outcome": "dispatch_outcome_unknown",
            "effect_status": "effect_indeterminate",
            "detail": {"dispatched": true, "reason": "action_deadline_exceeded"}
        }));
        let refusal = reply(json!({"outcome": "action_deadline_exceeded"}));
        for gate_dispatched in [false, true] {
            for committed in [false, true] {
                for refused_before_dispatch in [false, true] {
                    let evidence = DispatchEvidence {
                        gate_dispatched,
                        committed,
                        commit_point: true,
                        refused_before_dispatch,
                        ..DispatchEvidence::default()
                    };
                    assert_eq!(
                        Settlement::from_reply(&unknown, evidence).state,
                        if gate_dispatched || committed { CallState::Unknown } else { CallState::Refused },
                        "gate={gate_dispatched}, witness={committed}, refusal={refused_before_dispatch}"
                    );
                    if !committed {
                        assert_eq!(
                            Settlement::from_reply(&refusal, evidence).state,
                            if gate_dispatched {
                                CallState::Unknown
                            } else {
                                CallState::Refused
                            }
                        );
                    }
                }
            }
        }
        assert_eq!(
            Settlement::from_reply(
                &reply(json!({"outcome": "ok"})),
                DispatchEvidence {
                    gate_dispatched: true,
                    ..ran()
                }
            )
            .state,
            CallState::Replied
        );
    }
}
