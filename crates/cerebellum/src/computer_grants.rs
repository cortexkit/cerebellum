//! Permission for the computer plane: app grants, the takeover grant, and the
//! consent a call waits for.
//!
//! Two grants exist, and nothing else admits a computer action:
//!
//! * An **app grant** covers every non-takeover action inside one application
//!   (reading its state, pressing, writing text, typing, key presses, waiting
//!   on it). It is asked once per application per conversation, with the
//!   answers `allow_conversation`, `allow_always` and `deny`.
//! * A **takeover grant** covers driving the one real system pointer and
//!   bringing an application forward to type into it. It is keyed by the
//!   conversation alone, because either can reach any application, and it is
//!   never offered "always": a stale approval must not
//!   be able to take the screen from someone who is not watching.
//!
//! A call that needs a grant it does not hold asks the question itself and
//! waits for the answer, up to [`CONSENT_PARK_LIMIT`]. The question outlives
//! that wait: an answer that arrives later still writes the grant, and the
//! caller, told `consent_pending`, retries once woken.
//!
//! "Always" answers are written to a small versioned file of their own, bound
//! to this machine's hardware identity so that a copy restored onto another
//! machine grants nothing there. The file is read once when the module starts;
//! if it cannot be read, no "always" grant applies and the failure is
//! disclosed, rather than the file being treated as empty and overwritten.
//!
//! An app grant is also bound to the code-signing identity of the process it
//! was made for. A bundle identity is only what an application says about
//! itself, and any application can say it is `com.hnc.Discord`; a signature
//! that validates can only come from whoever holds the signing key. So when
//! a grant is made, the process's designated requirement is recorded, and
//! every use checks the process in front of it against that requirement. A
//! process that does not satisfy it holds no grant, and the person is asked
//! again, told that the application's signature changed. A process whose
//! signature cannot be read is refused: nothing is admitted unchecked.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_core::consent::OnceDispatchToken;
use cerebellum_core::dispatch::InFlightGuard;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::elicit::AskOutcome;
use crate::CancelHandle;

/// The file name of the "always" grant store, under the journal data home.
pub const GRANT_STORE_FILE: &str = "computer_grants.json";

/// The only store format this build reads or writes.
///
/// Version 2 added the code-signing identity to each record. A version 1
/// file is refused like any other version this build does not read: its
/// records name no signer, so none of them could grant anything.
pub const GRANT_STORE_VERSION: u64 = 2;

/// The grant store's format, as the format floor and staging name it.
pub const GRANT_STORE_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new("computer-grants", GRANT_STORE_VERSION);

/// How long a call waits in place for the person's answer before replying
/// `consent_pending`.
///
/// Long enough for a person who is at the desk to read and answer the prompt,
/// so the common case returns the call's real result with no second call; short
/// enough that the agent is not left holding a call open while the person is
/// away. The question itself stays open longer (see the deadlines below).
pub const CONSENT_PARK_LIMIT: Duration = Duration::from_secs(120);

/// How long an app question stays open.
///
/// The same span a browser origin grant question stays open: both are answered
/// from a phone, and a person takes minutes to notice a phone prompt.
pub const APP_QUESTION_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// How long a takeover question stays open.
///
/// Short on purpose. Approving a takeover hands the agent the real pointer, and
/// an approval given long after the ask may arrive when nobody is watching the
/// screen it takes.
pub const TAKEOVER_QUESTION_DEADLINE: Duration = Duration::from_secs(5 * 60);

const ALLOW_CONVERSATION: &str = "allow_conversation";
const ALLOW_ALWAYS: &str = "allow_always";
const DENY: &str = "deny";

// ---------------------------------------------------------------------------
// The durable store
// ---------------------------------------------------------------------------

/// One "always allow" answer, as written to the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AlwaysGrantRecord {
    /// The daemon-attested durable agent identity the person answered for.
    pub agent_project_id: String,
    pub bundle_identity: String,
    /// The Apple Developer Team ID of the application the person approved.
    /// Absent for Apple's own applications, which are signed by Apple rather
    /// than by a team.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_id: Option<String>,
    /// The designated requirement of the application the person approved, in
    /// its text form. Every use checks the running process against it. A
    /// record without one grants nothing, since there is nothing to check the
    /// process against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub designated_requirement: Option<String>,
    /// The hardware identity of the machine the answer was given on. A record
    /// naming any other machine grants nothing here, so restoring a backup onto
    /// a different machine cannot carry the person's trust across.
    pub machine_uuid: String,
    pub created_at_ms: u64,
}

/// The whole store, loaded and saved in one piece.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantStoreState {
    pub version: u64,
    pub records: Vec<AlwaysGrantRecord>,
}

impl Default for GrantStoreState {
    fn default() -> Self {
        Self {
            version: GRANT_STORE_VERSION,
            records: Vec::new(),
        }
    }
}

/// Why the store could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GrantStoreError {
    /// The file exists and could not be read.
    Unreadable { detail: String },
    /// The file was read and is not a store this build understands.
    Corrupt { detail: String },
    /// The file names a format version this build does not read.
    UnknownVersion { found: u64 },
    /// Writing the file failed; the previous file is left as it was.
    WriteFailed { detail: String },
    /// This host offers no machine identity to bind a record to.
    NoMachineIdentity,
}

impl GrantStoreError {
    /// The one-word code a reply or the health report carries.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "grant_store_unreadable",
            Self::Corrupt { .. } => "grant_store_corrupt",
            Self::UnknownVersion { .. } => "grant_store_version_unknown",
            Self::WriteFailed { .. } => "grant_store_write_failed",
            Self::NoMachineIdentity => "machine_identity_unavailable",
        }
    }
}

impl std::fmt::Display for GrantStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { detail } => {
                write!(formatter, "the grant store is unreadable: {detail}")
            }
            Self::Corrupt { detail } => write!(formatter, "the grant store is corrupt: {detail}"),
            Self::UnknownVersion { found } => write!(
                formatter,
                "the grant store is version {found}; this build reads version {GRANT_STORE_VERSION}"
            ),
            Self::WriteFailed { detail } => {
                write!(formatter, "the grant store could not be written: {detail}")
            }
            Self::NoMachineIdentity => {
                write!(
                    formatter,
                    "this host has no machine identity to bind a grant to"
                )
            }
        }
    }
}

/// Where "always" grants are kept.
///
/// Whole-state load and save, the same shape as the audit journal's storage,
/// so the in-memory binding models a restart the same way: a second store
/// opened over the same binding reads what the first one saved.
pub trait GrantStorage: Send + Sync {
    /// Read the whole store. A store that was never written reads as empty.
    fn load(&self) -> Result<GrantStoreState, GrantStoreError>;
    /// Replace the whole store.
    fn save(&self, state: &GrantStoreState) -> Result<(), GrantStoreError>;
}

/// A store held in memory. Clones share state, so a clone models reopening the
/// store after a module restart.
#[derive(Debug, Clone, Default)]
pub struct InMemoryGrantStorage {
    state: Arc<Mutex<GrantStoreState>>,
}

impl InMemoryGrantStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl GrantStorage for InMemoryGrantStorage {
    fn load(&self) -> Result<GrantStoreState, GrantStoreError> {
        Ok(self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone())
    }

    fn save(&self, state: &GrantStoreState) -> Result<(), GrantStoreError> {
        *self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = state.clone();
        Ok(())
    }
}

/// The store as a JSON file, replaced atomically on every save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemGrantStorage {
    path: PathBuf,
    floor: cerebellum_core::format_floor::FormatFloor,
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl FilesystemGrantStorage {
    /// A store at `path`, raising the format floor that governs where it is:
    /// the operator's floor under the module's data directory, none for a
    /// store anywhere else.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let floor = cerebellum_core::format_floor::FormatFloor::governing(&path);
        Self { path, floor }
    }

    /// Raise `floor` instead of the one chosen from the store's location.
    pub fn with_format_floor(mut self, floor: cerebellum_core::format_floor::FormatFloor) -> Self {
        self.floor = floor;
        self
    }

    /// The operator's store under the cerebellum data home, beside the audit
    /// journal so it is covered by the same backup enrolment.
    pub fn production() -> Result<Self, GrantStoreError> {
        cerebellum_core::journal::journal_data_path(GRANT_STORE_FILE)
            .map(Self::new)
            .map_err(|error| GrantStoreError::Unreadable {
                detail: format!("{error:?}"),
            })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl GrantStorage for FilesystemGrantStorage {
    fn load(&self) -> Result<GrantStoreState, GrantStoreError> {
        let mut bytes = Vec::new();
        match File::open(&self.path) {
            Ok(mut file) => {
                file.read_to_end(&mut bytes)
                    .map_err(|error| GrantStoreError::Unreadable {
                        detail: error.to_string(),
                    })?;
            }
            // Never written: no "always" answer has been given on this machine.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(GrantStoreState::default())
            }
            Err(error) => {
                return Err(GrantStoreError::Unreadable {
                    detail: error.to_string(),
                })
            }
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|error| GrantStoreError::Corrupt {
                detail: error.to_string(),
            })?;
        // The version is read before the records, so a file from a newer build
        // is reported as a version this build does not read rather than as
        // corruption: the remedy differs (run the newer build, not repair).
        let Some(version) = value.get("version").and_then(Value::as_u64) else {
            return Err(GrantStoreError::Corrupt {
                detail: "version is missing or is not an unsigned integer".to_string(),
            });
        };
        if version != GRANT_STORE_FORMAT.version {
            return Err(GrantStoreError::UnknownVersion { found: version });
        }
        serde_json::from_value(value).map_err(|error| GrantStoreError::Corrupt {
            detail: error.to_string(),
        })
    }

    fn save(&self, state: &GrantStoreState) -> Result<(), GrantStoreError> {
        let failed = |error: std::io::Error| GrantStoreError::WriteFailed {
            detail: error.to_string(),
        };
        // Before anything is written: a store in this format on disk with no
        // floor naming it would let staging pass a build that cannot read it.
        self.floor
            .raise(GRANT_STORE_FORMAT)
            .map_err(|error| GrantStoreError::WriteFailed {
                detail: error.to_string(),
            })?;
        let bytes =
            serde_json::to_vec_pretty(state).map_err(|error| GrantStoreError::WriteFailed {
                detail: error.to_string(),
            })?;
        let directory = self
            .path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        fs::create_dir_all(&directory).map_err(failed)?;
        let file_name = self
            .path
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| GRANT_STORE_FILE.to_string());
        let temporary = directory.join(format!(
            ".{file_name}.{}.{}.tmp",
            std::process::id(),
            TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        // Written beside the target and renamed over it, so a crash mid-write
        // leaves either the old store or the new one, never half of one.
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
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

/// This machine's hardware identity, or `None` where none can be read.
///
/// On macOS this is the IOPlatformUUID, read from the kernel with a bounded
/// wait. It survives a reinstall of the operating system and differs between
/// machines, so a record bound to it does not travel with a backup. Elsewhere
/// there is no source yet. A host without one, or one whose read fails, is
/// never offered "always", and the listing reports every stored record as
/// belonging to another machine.
pub fn this_machine_uuid() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        cerebellum_macos::hardware_uuid(Duration::from_secs(2))
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// The last load result of the operator's durable store, for the health reply.
///
/// Process-wide because the health lane reads only atomics; only the
/// filesystem store opened by a running module reports here.
const STORE_STATE_NOT_OPENED: u8 = 0;
const STORE_STATE_LOADED: u8 = 1;
const STORE_STATE_UNREADABLE: u8 = 2;

static DURABLE_STORE_STATE: AtomicU8 = AtomicU8::new(STORE_STATE_NOT_OPENED);

/// The health reply's `computerGrantStore`: whether "always" grants are in
/// force (`loaded`), withheld because the store could not be read
/// (`unreadable`), or the store has not been opened in this process.
pub fn durable_grant_store_health() -> &'static str {
    match DURABLE_STORE_STATE.load(Ordering::Acquire) {
        STORE_STATE_LOADED => "loaded",
        STORE_STATE_UNREADABLE => "unreadable",
        _ => "not_opened",
    }
}

// ---------------------------------------------------------------------------
// Who is asking, and what they need
// ---------------------------------------------------------------------------

/// The identity a grant is checked against, taken from the route's accepted
/// bind and never from a request body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantCaller {
    pub conversation_key: String,
    pub agent_project_id: String,
    /// Whether the daemon attested both the agent project id and the session
    /// kind. Only then may an "always" answer be offered, stored or honoured:
    /// an unattested project id came from a caller-controlled fallback, and
    /// a durable grant keyed by it would be a permission anyone could claim.
    pub durable_identity_attested: bool,
}

/// The code-signing identity of an application's running process, as it is
/// recorded when a grant is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppIdentity {
    /// The Apple Developer Team ID of the signing certificate. Absent for
    /// ad-hoc code and for Apple's own applications.
    pub team_id: Option<String>,
    /// The rule any process must satisfy to count as this application. For
    /// ad-hoc code it names the exact build by its code hash.
    pub designated_requirement: String,
    /// Signed without a certificate: the signature names one build and no
    /// signer, so the next build of the same application will not satisfy it.
    pub ad_hoc: bool,
    /// The code satisfies the requirement `anchor apple`: Apple signed it.
    pub apple_anchored: bool,
}

impl AppIdentity {
    /// Whether a grant bound to this identity can be offered "always".
    ///
    /// Only for a signature another developer cannot produce and the next
    /// release of the same application keeps: a team's certificate, or
    /// Apple's own anchor. An ad-hoc signature names a single build, and
    /// unsigned code names nothing, so neither can carry a standing answer.
    pub fn names_a_lasting_signer(&self) -> bool {
        !self.ad_hoc && (self.team_id.is_some() || self.apple_anchored)
    }
}

/// Why an application's code-signing identity could not be read or checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AppIdentityUnreadable {
    /// This platform has no reader for code-signing identities.
    NoReader,
    /// The application carries no signature, so there is nothing to bind a
    /// grant to.
    Unsigned,
    /// The reading failed, or took longer than it is allowed to.
    Failed { detail: String },
}

impl AppIdentityUnreadable {
    fn remedy(&self) -> &'static str {
        match self {
            Self::NoReader => {
                "this platform reads no code-signing identity yet, so no application grant can \
                 be bound to the application and nothing was done"
            }
            Self::Unsigned => {
                "the application is not code-signed, so no grant can be bound to it and \
                 nothing was done"
            }
            Self::Failed { .. } => {
                "the application's code-signing identity could not be read, so whether it is \
                 the application that was approved is unknown and nothing was done; retry"
            }
        }
    }

    fn refusal(&self) -> ConsentRefusal {
        ConsentRefusal::Unavailable {
            reason: "app_identity_unreadable",
            remedy: self.remedy(),
        }
    }
}

/// The code-signing identity of one resolved process, read on demand.
///
/// Behind a trait so the grant logic can be exercised with injected
/// identities on every host, while the real reading lives only where the
/// operating system provides one.
pub trait AppCode: Send + Sync {
    /// Read the process's identity, to record with a grant made for it.
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable>;
    /// Whether the process satisfies a designated requirement recorded
    /// earlier: `Ok(false)` when it was read and does not.
    fn satisfies(&self, designated_requirement: &str) -> Result<bool, AppIdentityUnreadable>;
}

/// The identity source for a platform that has no reader: every reading is
/// refused, so no app grant is ever admitted there unchecked.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoIdentityReader;

impl AppCode for NoIdentityReader {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        Err(AppIdentityUnreadable::NoReader)
    }
    fn satisfies(&self, _designated_requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        Err(AppIdentityUnreadable::NoReader)
    }
}

/// A process signed by one fixed team, for this crate's own tests of paths
/// that hold an app grant but are not about signatures.
#[cfg(all(test, target_os = "macos"))]
pub(crate) struct SignedByFixtureTeam;

#[cfg(all(test, target_os = "macos"))]
impl AppCode for SignedByFixtureTeam {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        Ok(AppIdentity {
            team_id: Some("FIXTURE001".to_string()),
            designated_requirement: "certificate leaf[subject.OU] = \"FIXTURE001\"".to_string(),
            ad_hoc: false,
            apple_anchored: false,
        })
    }
    fn satisfies(&self, designated_requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        Ok(designated_requirement == self.identity()?.designated_requirement)
    }
}

/// Which grant a call needs.
#[derive(Clone)]
pub enum GrantNeed {
    /// The app grant for one application.
    App {
        bundle_identity: String,
        /// What the person sees the application called: its running name, or
        /// the bundle identity when no name could be read.
        display_name: String,
        /// The code of the process the call resolved, which a grant is
        /// recorded against and checked against.
        code: Arc<dyn AppCode>,
    },
    /// The conversation's takeover grant.
    Takeover,
}

impl std::fmt::Debug for GrantNeed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::App {
                bundle_identity,
                display_name,
                ..
            } => formatter
                .debug_struct("App")
                .field("bundle_identity", bundle_identity)
                .field("display_name", display_name)
                .finish_non_exhaustive(),
            Self::Takeover => formatter.write_str("Takeover"),
        }
    }
}

impl GrantNeed {
    fn grant_kind(&self) -> &'static str {
        match self {
            Self::App { .. } => "app",
            Self::Takeover => "takeover",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Subject {
    App {
        conversation_key: String,
        bundle_identity: String,
    },
    Takeover {
        conversation_key: String,
    },
}

impl Subject {
    fn of(caller: &GrantCaller, need: &GrantNeed) -> Self {
        match need {
            GrantNeed::App {
                bundle_identity, ..
            } => Self::App {
                conversation_key: caller.conversation_key.clone(),
                bundle_identity: bundle_identity.clone(),
            },
            GrantNeed::Takeover => Self::Takeover {
                conversation_key: caller.conversation_key.clone(),
            },
        }
    }

    fn conversation_key(&self) -> &str {
        match self {
            Self::App {
                conversation_key, ..
            }
            | Self::Takeover { conversation_key } => conversation_key,
        }
    }
}

// ---------------------------------------------------------------------------
// The carrier and the route a call arrived on
// ---------------------------------------------------------------------------

/// Puts a question to whoever is on the other end of the route and reports how
/// it ended.
pub trait QuestionCarrier: Send + Sync {
    fn put(
        &self,
        question: Value,
        deadline: Duration,
    ) -> Pin<Box<dyn Future<Output = AskOutcome> + Send>>;
}

/// What a waiting call needs to know about the route it arrived on.
pub trait RouteLiveness: Send + Sync {
    /// Whether the route the call arrived on is still bound.
    fn route_open(&self) -> bool;
    /// Whether any bound route still carries the call's conversation.
    fn conversation_open(&self) -> bool;
}

/// A route that never closes, for callers with no route of their own.
#[derive(Debug, Clone, Copy, Default)]
pub struct AlwaysOpenRoute;

impl RouteLiveness for AlwaysOpenRoute {
    fn route_open(&self) -> bool {
        true
    }
    fn conversation_open(&self) -> bool {
        true
    }
}

/// Everything a call needs to ask for a grant and wait for the answer.
pub struct ConsentContext {
    pub caller: GrantCaller,
    /// How to reach a person, or `None` when the route declared it cannot
    /// relay a question.
    pub carrier: Option<Arc<dyn QuestionCarrier>>,
    pub route: Arc<dyn RouteLiveness>,
    /// Becomes `true` when the module starts draining for a restart.
    pub drain: watch::Receiver<bool>,
    /// The request's in-flight guard, parked while the call waits on a person
    /// so the wait is not counted as busy or aged as a stuck action.
    pub park_guard: Option<Arc<InFlightGuard>>,
    /// How long the call waits in place. [`CONSENT_PARK_LIMIT`] in production.
    pub park_limit: Duration,
}

impl ConsentContext {
    pub fn new(
        caller: GrantCaller,
        carrier: Option<Arc<dyn QuestionCarrier>>,
        route: Arc<dyn RouteLiveness>,
        drain: watch::Receiver<bool>,
        park_guard: Option<Arc<InFlightGuard>>,
    ) -> Self {
        Self {
            caller,
            carrier,
            route,
            drain,
            park_guard,
            park_limit: CONSENT_PARK_LIMIT,
        }
    }

    /// A context whose route cannot relay a question and never drains, for a
    /// caller that holds grants already or expects none to be asked.
    pub fn without_carrier(caller: GrantCaller) -> Self {
        let (_never, drain) = watch::channel(false);
        Self::new(caller, None, Arc::new(AlwaysOpenRoute), drain, None)
    }

    pub fn with_park_limit(mut self, park_limit: Duration) -> Self {
        self.park_limit = park_limit;
        self
    }
}

// ---------------------------------------------------------------------------
// What a call gets back
// ---------------------------------------------------------------------------

/// A grant that admitted the call.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct GrantAdmission {
    /// Whether the call had to wait for an answer. A call that waited must
    /// re-resolve its target: the process may have changed while it waited.
    pub waited: bool,
    /// Set when the answer this call waited on was `allow_always`: whether it
    /// was written to the store, or why not.
    pub persisted: Option<Result<(), String>>,
}

impl GrantAdmission {
    /// Add the durable-write disclosure to a call's real reply.
    ///
    /// The reason goes into `reason` only when the reply does not already
    /// carry one of its own, which would otherwise be overwritten.
    pub fn decorate(&self, reply: &mut Value) {
        let (Some(persisted), Some(object)) = (self.persisted.as_ref(), reply.as_object_mut())
        else {
            return;
        };
        object.insert("grant_persisted".into(), Value::Bool(persisted.is_ok()));
        if let Err(reason) = persisted {
            object
                .entry("reason")
                .or_insert_with(|| Value::String(reason.clone()));
        }
    }
}

/// One real-pointer dispatch the takeover grant admitted.
///
/// Its fields are private so nothing outside this module can build one: the
/// token inside is the dispatch path's proof that the person agreed, and it
/// is reachable only through [`ComputerGrants::require_takeover_dispatch`].
#[derive(Debug)]
pub struct TakeoverDispatch {
    admission: GrantAdmission,
    token: OnceDispatchToken,
}

impl TakeoverDispatch {
    /// Whether the call waited for the person, and what became of an
    /// "always" answer, as for any other grant.
    pub fn admission(&self) -> &GrantAdmission {
        &self.admission
    }

    /// Hand the token to the one dispatch it was minted for.
    pub fn into_token(self) -> OnceDispatchToken {
        self.token
    }
}

/// Why a call is not admitted, each with the reply the caller acts on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsentRefusal {
    /// The person has been asked and has not answered yet.
    Pending { ask_id: String },
    /// The person declined, now or earlier in this conversation.
    Denied {
        grant_kind: &'static str,
        remembered: bool,
    },
    /// The person allowed it while several calls waited; another of them
    /// acted, and this one did not run.
    GrantedNotExecuted,
    /// Nobody could be asked, or the question ended with no usable answer.
    Unavailable {
        reason: &'static str,
        remedy: &'static str,
    },
    /// The module began draining while the call waited.
    Draining,
    /// The call's route unbound while it waited; nobody is left to answer.
    RouteClosed,
    /// The caller cancelled the request while it waited.
    Cancelled,
}

impl ConsentRefusal {
    /// The reply for this refusal, in the envelope every consent-capable row
    /// declares. For `Cancelled` this is only a bare fallback: the serving rows
    /// answer a cancel in their own existing cancel shape instead.
    pub fn reply(&self, bundle_identity: Option<&str>) -> Value {
        let mut reply = match self {
            Self::Pending { ask_id } => json!({
                "outcome": "consent_pending",
                "ask_id": ask_id,
                "remedy": "The person has been asked. You will be woken when they answer; \
                           then retry this call.",
            }),
            Self::Denied {
                grant_kind,
                remembered,
            } => {
                let remedy = if *grant_kind == "takeover" {
                    "The person declined the takeover for this conversation. Ask them in chat \
                     before trying to use the pointer again."
                } else {
                    "The person declined access to this application for this conversation. \
                     Ask them in chat before trying this application again."
                };
                let mut reply = json!({"outcome": "consent_denied", "remedy": remedy});
                if *remembered {
                    reply["reason"] = json!("denied_earlier_in_this_conversation");
                }
                reply
            }
            Self::GrantedNotExecuted => json!({
                "outcome": "consent_granted_not_executed",
                "remedy": "The person allowed it while several calls waited and another one \
                           ran. The grant is held: retry this call now.",
            }),
            Self::Unavailable { reason, remedy } => json!({
                "outcome": "consent_unavailable",
                "reason": reason,
                "remedy": remedy,
            }),
            Self::Draining => json!({
                "outcome": "module_draining",
                "remedy": "retry after the module restarts",
            }),
            Self::RouteClosed => json!({"outcome": "route_closed"}),
            Self::Cancelled => json!({"outcome": "cancelled"}),
        };
        if let (Some(bundle_identity), Self::Denied { grant_kind, .. }) = (bundle_identity, self) {
            if *grant_kind == "app" {
                reply["bundle_identity"] = json!(bundle_identity);
            }
        }
        reply
    }
}

// ---------------------------------------------------------------------------
// The grants
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
enum AlwaysState {
    /// Every record in the store, including ones naming other machines (kept
    /// so a save does not delete them, and so the listing can report them).
    Loaded(Vec<AlwaysGrantRecord>),
    /// The store could not be read; no "always" grant applies.
    Failed(GrantStoreError),
}

/// How a question ended, as its waiters see it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Settlement {
    Allowed {
        persisted: Option<Result<(), String>>,
    },
    Denied,
    Ended {
        reason: &'static str,
        remedy: &'static str,
    },
}

/// How a question ended, and which parked call (by join order) runs under the
/// answer. `None` until the question is settled.
type Settled = Option<(Settlement, Option<u64>)>;
type SettledSignal = watch::Sender<Settled>;
type SettledWatch = watch::Receiver<Settled>;

/// A question put to the person and not yet answered.
struct OpenQuestion {
    subject: Subject,
    /// The decisions the question offered. An answer outside them grants
    /// nothing.
    offered: Vec<&'static str>,
    /// The attested agent an `allow_always` answer is recorded for, present
    /// only when the question offered it.
    always_grantee: Option<String>,
    /// For an app question, the signing identity of the process the question
    /// was raised for. An allowing answer is bound to it.
    identity: Option<AppIdentity>,
    /// Calls parked on this question, by the order they joined.
    parked: BTreeSet<u64>,
    next_waiter: u64,
    settled: SettledSignal,
    asking: Option<tokio::task::AbortHandle>,
}

#[derive(Default)]
struct GrantState {
    /// Each conversation's app grants, by conversation and bundle identity,
    /// with the signing identity the grant was made for.
    conversation_apps: HashMap<(String, String), AppIdentity>,
    conversation_app_denies: HashSet<(String, String)>,
    takeovers: HashSet<String>,
    takeover_denies: HashSet<String>,
    questions: HashMap<String, OpenQuestion>,
    open_by_subject: BTreeMap<Subject, String>,
}

enum Standing {
    Granted,
    Denied,
    Asking,
    Unasked,
    /// A grant exists for the application's bundle identity, and the process
    /// answering to it now does not satisfy the signature it was made for.
    /// Carries this conversation's grant when it was one of those that
    /// failed, so it can be dropped; `None` when only "always" records failed.
    SignatureChanged {
        stale: Option<AppIdentity>,
    },
    /// The process's signature could not be read, so no grant can be applied
    /// to it.
    IdentityUnreadable(AppIdentityUnreadable),
}

/// Every computer grant this module holds, and the questions it is waiting on.
pub struct ComputerGrants {
    storage: Arc<dyn GrantStorage>,
    machine_uuid: Option<String>,
    always: Mutex<AlwaysState>,
    state: Mutex<GrantState>,
    /// Held across a read-modify-write of the store, so two concurrent writes
    /// cannot each save a copy missing the other's record.
    store_writes: Mutex<()>,
}

static NEXT_ASK: AtomicU64 = AtomicU64::new(1);

fn new_ask_id(grant_kind: &str) -> String {
    format!(
        "computer-{grant_kind}-consent-{}",
        NEXT_ASK.fetch_add(1, Ordering::Relaxed)
    )
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl ComputerGrants {
    /// Open the grants over a store, reading it once.
    ///
    /// A store that cannot be read leaves "always" grants withheld for the
    /// life of this module, and is never saved over: a corrupt file is
    /// evidence, and treating it as empty would erase the person's answers the
    /// next time anyone answered "always".
    pub fn open(storage: Arc<dyn GrantStorage>, machine_uuid: Option<String>) -> Self {
        let always = match storage.load() {
            Ok(state) if state.version == GRANT_STORE_VERSION => AlwaysState::Loaded(state.records),
            Ok(state) => AlwaysState::Failed(GrantStoreError::UnknownVersion {
                found: state.version,
            }),
            Err(error) => AlwaysState::Failed(error),
        };
        Self {
            storage,
            machine_uuid,
            always: Mutex::new(always),
            state: Mutex::new(GrantState::default()),
            store_writes: Mutex::new(()),
        }
    }

    /// Open the operator's store and report its state to the health reply.
    pub fn open_durable(machine_uuid: Option<String>) -> Self {
        let grants = match FilesystemGrantStorage::production() {
            Ok(storage) => Self::open(Arc::new(storage), machine_uuid),
            Err(error) => Self {
                storage: Arc::new(InMemoryGrantStorage::new()),
                machine_uuid,
                always: Mutex::new(AlwaysState::Failed(error)),
                state: Mutex::new(GrantState::default()),
                store_writes: Mutex::new(()),
            },
        };
        let health = match grants.store_error() {
            None => STORE_STATE_LOADED,
            Some(_) => STORE_STATE_UNREADABLE,
        };
        DURABLE_STORE_STATE.store(health, Ordering::Release);
        grants
    }

    /// Grants held only in memory, with no machine identity, so "always" is
    /// never offered. For tests and isolated planes.
    pub fn in_memory() -> Self {
        Self::open(Arc::new(InMemoryGrantStorage::new()), None)
    }

    /// Why the store could not be read, if it could not.
    pub fn store_error(&self) -> Option<GrantStoreError> {
        match &*lock(&self.always) {
            AlwaysState::Loaded(_) => None,
            AlwaysState::Failed(error) => Some(error.clone()),
        }
    }

    /// Whether a question to this caller about this process may offer
    /// `allow_always`.
    ///
    /// All four must hold: a daemon-attested identity to key the record by, a
    /// machine identity to bind it to, a store that was read, so that writing
    /// does not overwrite one that could not be, and a signature naming a
    /// signer that lasts beyond this one build.
    fn offers_always(&self, caller: &GrantCaller, identity: Option<&AppIdentity>) -> bool {
        caller.durable_identity_attested
            && self.machine_uuid.is_some()
            && matches!(&*lock(&self.always), AlwaysState::Loaded(_))
            && identity.is_some_and(AppIdentity::names_a_lasting_signer)
    }

    /// The designated requirement of each "always" record on this machine for
    /// the caller's app, or `None` for a record that names none.
    fn always_requirements(
        &self,
        caller: &GrantCaller,
        bundle_identity: &str,
    ) -> Vec<Option<String>> {
        if !caller.durable_identity_attested {
            return Vec::new();
        }
        let Some(machine) = self.machine_uuid.as_deref() else {
            return Vec::new();
        };
        match &*lock(&self.always) {
            AlwaysState::Loaded(records) => records
                .iter()
                .filter(|record| {
                    record.agent_project_id == caller.agent_project_id
                        && record.bundle_identity == bundle_identity
                        && record.machine_uuid == machine
                })
                .map(|record| record.designated_requirement.clone())
                .collect(),
            AlwaysState::Failed(_) => Vec::new(),
        }
    }

    fn standing(&self, caller: &GrantCaller, need: &GrantNeed) -> Standing {
        let subject = Subject::of(caller, need);
        let state = lock(&self.state);
        match need {
            GrantNeed::App {
                bundle_identity,
                code,
                ..
            } => {
                let key = (caller.conversation_key.clone(), bundle_identity.clone());
                // A deny given in this conversation holds even over an older
                // standing answer: the person said no to this conversation.
                if state.conversation_app_denies.contains(&key) {
                    return Standing::Denied;
                }
                let conversation = state.conversation_apps.get(&key).cloned();
                // Released before the signature checks, which read the
                // process and must not hold every other call up meanwhile.
                drop(state);
                let mut stale = None;
                let mut recorded = false;
                let always = self.always_requirements(caller, bundle_identity);
                let requirements = conversation
                    .iter()
                    .map(|identity| (Some(identity.designated_requirement.as_str()), true))
                    .chain(
                        always
                            .iter()
                            .map(|requirement| (requirement.as_deref(), false)),
                    );
                for (requirement, from_conversation) in requirements {
                    // A record that names no signature grants nothing, the
                    // same as a record from another machine: there is nothing
                    // to check the process against.
                    let Some(requirement) = requirement else {
                        continue;
                    };
                    recorded = true;
                    match code.satisfies(requirement) {
                        Ok(true) => return Standing::Granted,
                        Ok(false) => {
                            if from_conversation {
                                stale = conversation.clone();
                            }
                        }
                        Err(unreadable) => return Standing::IdentityUnreadable(unreadable),
                    }
                }
                if recorded {
                    return Standing::SignatureChanged { stale };
                }
                let state = lock(&self.state);
                match state.open_by_subject.get(&subject) {
                    Some(_) => Standing::Asking,
                    None => Standing::Unasked,
                }
            }
            // Only a takeover answer admits a takeover. An app grant says the
            // person trusts the agent inside one application; it says nothing
            // about handing over the pointer they are using.
            GrantNeed::Takeover => {
                if state.takeover_denies.contains(&caller.conversation_key) {
                    return Standing::Denied;
                }
                if state.takeovers.contains(&caller.conversation_key) {
                    return Standing::Granted;
                }
                match state.open_by_subject.get(&subject) {
                    Some(_) => Standing::Asking,
                    None => Standing::Unasked,
                }
            }
        }
    }

    /// Whether the caller holds the grant now, without asking anyone.
    pub fn holds(&self, caller: &GrantCaller, need: &GrantNeed) -> bool {
        matches!(self.standing(caller, need), Standing::Granted)
    }

    /// Admit a call under the grant it needs, asking the person and waiting
    /// for the answer when it is not held.
    pub async fn require(
        self: &Arc<Self>,
        need: &GrantNeed,
        context: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<GrantAdmission, ConsentRefusal> {
        let caller = &context.caller;
        let mut signature_changed = false;
        match self.standing(caller, need) {
            Standing::Granted => return Ok(GrantAdmission::default()),
            // Remembered, so a call after a refusal is answered at once and no
            // second question reaches the person's phone.
            Standing::Denied => {
                return Err(ConsentRefusal::Denied {
                    grant_kind: need.grant_kind(),
                    remembered: true,
                })
            }
            // Never admitted unchecked: a grant whose process cannot be
            // checked is a grant for whoever holds the bundle identity.
            Standing::IdentityUnreadable(unreadable) => return Err(unreadable.refusal()),
            Standing::Asking | Standing::Unasked => {}
            Standing::SignatureChanged { stale } => {
                signature_changed = true;
                if let Some(stale) = stale {
                    self.drop_conversation_grant(caller, need, &stale);
                }
            }
        }
        // The identity a grant made by this question is bound to. Read before
        // asking, so nobody is asked about a process no grant could be bound
        // to.
        let identity = match need {
            GrantNeed::App { code, .. } => {
                Some(code.identity().map_err(|unreadable| unreadable.refusal())?)
            }
            GrantNeed::Takeover => None,
        };
        let Some(carrier) = context.carrier.as_ref() else {
            // Nobody can be asked, so nothing can be granted. Reported as its
            // own outcome: waiting on a question that cannot be put would read
            // as the person being unresponsive for a fault on this side.
            return Err(ConsentRefusal::Unavailable {
                reason: "cannot_relay",
                remedy: "reconnect declaring the ability to relay a question to a person",
            });
        };

        let (waiter, mut settled) =
            self.join_or_ask(caller, need, carrier, identity, signature_changed);

        // Parked for the whole wait: a call waiting on a person is neither busy
        // nor stuck, and counting it as either would report a person reading
        // their phone as a wedged module. The token is dropped on every exit
        // below, which restores the count exactly once.
        let parked = context
            .park_guard
            .as_ref()
            .map(|guard| guard.park_on_consent());
        let mut drain = context.drain.clone();

        let ending = tokio::select! {
            result = settled.wait_for(Option::is_some) => match result {
                Ok(value) => {
                    let (settlement, executor) =
                        value.clone().expect("the wait ends only on a settlement");
                    Ending::Settled(settlement, executor)
                }
                // The question was dropped unsettled: the conversation it
                // belonged to ended while this call waited.
                Err(_) => Ending::Withdrawn,
            },
            _ = drain.wait_for(|draining| *draining) => Ending::Draining,
            _ = cancel.cancelled() => Ending::Cancelled,
            _ = tokio::time::sleep(context.park_limit) => Ending::TimedOut,
        };
        drop(parked);

        match ending {
            Ending::Settled(Settlement::Allowed { persisted }, executor) => {
                let this_call = waiter.id;
                drop(waiter);
                // One answer runs one waiting call: the first to have joined.
                // The others are told the grant is held and to retry, so an
                // answer to one prompt never fires a burst of actions.
                if executor != Some(this_call) {
                    return Err(ConsentRefusal::GrantedNotExecuted);
                }
                // The call proceeds under the grant it can see, not under the
                // signal that woke it.
                if !self.holds(caller, need) {
                    return Err(ConsentRefusal::Unavailable {
                        reason: "grant_not_recorded",
                        remedy: "retry this call",
                    });
                }
                Ok(GrantAdmission {
                    waited: true,
                    persisted,
                })
            }
            Ending::Settled(Settlement::Denied, _) => Err(ConsentRefusal::Denied {
                grant_kind: need.grant_kind(),
                remembered: false,
            }),
            Ending::Settled(Settlement::Ended { reason, remedy }, _) => {
                Err(ConsentRefusal::Unavailable { reason, remedy })
            }
            Ending::Withdrawn => Err(ConsentRefusal::Unavailable {
                reason: "question_withdrawn",
                remedy: "retry this call to ask again",
            }),
            // The question stays open: an answer that arrives later still
            // writes the grant, and the caller retries once woken.
            Ending::TimedOut => Err(ConsentRefusal::Pending {
                ask_id: waiter.ask_id.clone(),
            }),
            // The module is going away; nobody will be here to act on a
            // later answer.
            Ending::Draining => {
                self.leave(waiter, true);
                Err(ConsentRefusal::Draining)
            }
            Ending::Cancelled => {
                // The question is kept while the conversation that raised it is
                // still bound: the person can still answer, and the answer is
                // still wanted by the conversation's next call.
                let withdraw = !context.route.conversation_open();
                let route_open = context.route.route_open();
                self.leave(waiter, withdraw);
                if route_open {
                    Err(ConsentRefusal::Cancelled)
                } else {
                    Err(ConsentRefusal::RouteClosed)
                }
            }
        }
    }

    /// Admit one real-pointer dispatch under the conversation's takeover
    /// grant, asking the person and waiting for the answer when it is not held.
    ///
    /// This is the only place a [`OnceDispatchToken`] is made: the global
    /// dispatch path refuses to post without one, so a token is the proof
    /// that the person agreed to hand over the pointer. Only a takeover
    /// answer admits it; an app grant never does.
    pub async fn require_takeover_dispatch(
        self: &Arc<Self>,
        context: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<TakeoverDispatch, ConsentRefusal> {
        let admission = self.require(&GrantNeed::Takeover, context, cancel).await?;
        Ok(TakeoverDispatch {
            admission,
            token: OnceDispatchToken::admitted_by_takeover_grant(),
        })
    }

    /// Park the caller on the open question for this grant, or open one.
    ///
    /// A second call needing the same grant joins the question already out
    /// rather than putting another: two prompts for one decision is the prompt
    /// storm this design exists to prevent.
    fn join_or_ask(
        self: &Arc<Self>,
        caller: &GrantCaller,
        need: &GrantNeed,
        carrier: &Arc<dyn QuestionCarrier>,
        identity: Option<AppIdentity>,
        signature_changed: bool,
    ) -> (Waiter<'_>, SettledWatch) {
        let subject = Subject::of(caller, need);
        let offers_always =
            matches!(need, GrantNeed::App { .. }) && self.offers_always(caller, identity.as_ref());
        let mut state = lock(&self.state);
        if let Some(ask_id) = state.open_by_subject.get(&subject).cloned() {
            if let Some(question) = state.questions.get_mut(&ask_id) {
                let id = question.next_waiter;
                question.next_waiter += 1;
                question.parked.insert(id);
                let settled = question.settled.subscribe();
                return (
                    Waiter {
                        grants: self,
                        ask_id,
                        id,
                    },
                    settled,
                );
            }
        }

        let grant_kind = need.grant_kind();
        let offered: Vec<&'static str> = match need {
            GrantNeed::App { .. } if offers_always => vec![ALLOW_CONVERSATION, ALLOW_ALWAYS, DENY],
            GrantNeed::App { .. } | GrantNeed::Takeover => vec![ALLOW_CONVERSATION, DENY],
        };
        let deadline = match need {
            GrantNeed::App { .. } => APP_QUESTION_DEADLINE,
            GrantNeed::Takeover => TAKEOVER_QUESTION_DEADLINE,
        };
        let ask_id = new_ask_id(grant_kind);
        let body = question_body(&ask_id, need, &offered, signature_changed);
        let (settled_tx, settled) = watch::channel(None);
        state.questions.insert(
            ask_id.clone(),
            OpenQuestion {
                subject: subject.clone(),
                offered,
                always_grantee: offers_always.then(|| caller.agent_project_id.clone()),
                identity,
                parked: BTreeSet::from([0]),
                next_waiter: 1,
                settled: settled_tx,
                asking: None,
            },
        );
        state.open_by_subject.insert(subject, ask_id.clone());
        drop(state);

        // Asked on its own task, because the question outlives the call that
        // raised it: a call that stops waiting leaves the question open, and a
        // later answer still has to be applied.
        let grants = Arc::clone(self);
        let question = carrier.put(body, deadline);
        let settling_ask = ask_id.clone();
        let task = tokio::spawn(async move {
            let outcome = question.await;
            grants.settle(&settling_ask, outcome);
        });
        if let Some(open) = lock(&self.state).questions.get_mut(&ask_id) {
            open.asking = Some(task.abort_handle());
        }
        (
            Waiter {
                grants: self,
                ask_id,
                id: 0,
            },
            settled,
        )
    }

    /// Apply the answer to a question and release the calls waiting on it.
    ///
    /// An answer to a question this module no longer holds grants nothing: it
    /// was withdrawn with its conversation, or it was never asked here.
    pub fn settle(&self, ask_id: &str, outcome: AskOutcome) {
        let open = {
            let state = lock(&self.state);
            let Some(question) = state.questions.get(ask_id) else {
                return;
            };
            AnsweredQuestion {
                ask_id: ask_id.to_string(),
                subject: question.subject.clone(),
                offered: question.offered.clone(),
                always_grantee: question.always_grantee.clone(),
                identity: question.identity.clone(),
            }
        };
        // The grant, and for "always" the store, is written before any waiting
        // call is released, so a released call always finds the grant it was
        // released for.
        let settlement = self.apply_answer(&open, &outcome);
        self.release_waiters(&open.ask_id, settlement);
    }

    fn apply_answer(&self, open: &AnsweredQuestion, outcome: &AskOutcome) -> Settlement {
        let body = match outcome {
            AskOutcome::Answered(body) => body,
            AskOutcome::NoAnswer => {
                return Settlement::Ended {
                    reason: "no_answer",
                    remedy: "The person did not answer in time; retry this call to ask again.",
                }
            }
            AskOutcome::NotPutToAnyone => {
                return Settlement::Ended {
                    reason: "not_put_to_anyone",
                    remedy: "Nobody could be asked; retry when the person is available.",
                }
            }
            AskOutcome::Undeliverable => {
                return Settlement::Ended {
                    reason: "question_undeliverable",
                    remedy: "The question could not be sent; retry this call.",
                }
            }
        };
        // A decision the question did not offer is not consent to anything:
        // an "always" answer to a question that offered only this
        // conversation, or a word this module does not know.
        let decision = body
            .get("decision")
            .and_then(Value::as_str)
            .and_then(|decision| {
                open.offered
                    .iter()
                    .copied()
                    .find(|offered| *offered == decision)
            });
        match decision {
            Some(ALLOW_CONVERSATION) => {
                self.grant_conversation(&open.subject, open.identity.as_ref());
                Settlement::Allowed { persisted: None }
            }
            Some(ALLOW_ALWAYS) => {
                let written = match (
                    &open.subject,
                    open.always_grantee.as_deref(),
                    open.identity.as_ref(),
                ) {
                    (
                        Subject::App {
                            bundle_identity, ..
                        },
                        Some(grantee),
                        Some(identity),
                    ) => self.write_always(grantee, bundle_identity, identity),
                    _ => Err(GrantStoreError::NoMachineIdentity),
                };
                // A failed write still grants for this conversation: the
                // person said yes, and refusing the action because a file
                // could not be written would punish them for a fault here.
                if written.is_err() {
                    self.grant_conversation(&open.subject, open.identity.as_ref());
                }
                Settlement::Allowed {
                    persisted: Some(written.map_err(|error| error.reason_code().to_string())),
                }
            }
            Some(DENY) => {
                self.remember_deny(&open.subject);
                Settlement::Denied
            }
            _ => Settlement::Ended {
                reason: "unrecognized_answer",
                remedy: "The answer could not be read; retry this call to ask again.",
            },
        }
    }

    fn release_waiters(&self, ask_id: &str, settlement: Settlement) {
        let mut state = lock(&self.state);
        let Some(question) = state.questions.remove(ask_id) else {
            return;
        };
        if state
            .open_by_subject
            .get(&question.subject)
            .map(String::as_str)
            == Some(ask_id)
        {
            state.open_by_subject.remove(&question.subject);
        }
        let executor = question.parked.first().copied();
        let _ = question.settled.send(Some((settlement, executor)));
    }

    /// Record an allowing answer for the conversation.
    ///
    /// An app grant is recorded only with the identity it was asked for; a
    /// question raised without one cannot have been an app question, and a
    /// grant with nothing to check against would admit any process.
    fn grant_conversation(&self, subject: &Subject, identity: Option<&AppIdentity>) {
        let mut state = lock(&self.state);
        match subject {
            Subject::App {
                conversation_key,
                bundle_identity,
            } => {
                if let Some(identity) = identity {
                    state.conversation_apps.insert(
                        (conversation_key.clone(), bundle_identity.clone()),
                        identity.clone(),
                    );
                }
            }
            Subject::Takeover { conversation_key } => {
                state.takeovers.insert(conversation_key.clone());
            }
        }
    }

    fn remember_deny(&self, subject: &Subject) {
        let mut state = lock(&self.state);
        match subject {
            Subject::App {
                conversation_key,
                bundle_identity,
            } => {
                state
                    .conversation_app_denies
                    .insert((conversation_key.clone(), bundle_identity.clone()));
            }
            Subject::Takeover { conversation_key } => {
                state.takeover_denies.insert(conversation_key.clone());
            }
        }
    }

    /// Forget a conversation's app grant whose process no longer satisfies
    /// the signature it was made for, unless it was replaced meanwhile.
    fn drop_conversation_grant(&self, caller: &GrantCaller, need: &GrantNeed, stale: &AppIdentity) {
        let GrantNeed::App {
            bundle_identity, ..
        } = need
        else {
            return;
        };
        let key = (caller.conversation_key.clone(), bundle_identity.clone());
        let mut state = lock(&self.state);
        if state.conversation_apps.get(&key) == Some(stale) {
            state.conversation_apps.remove(&key);
        }
    }

    fn write_always(
        &self,
        grantee: &str,
        bundle_identity: &str,
        identity: &AppIdentity,
    ) -> Result<(), GrantStoreError> {
        let machine = self
            .machine_uuid
            .clone()
            .ok_or(GrantStoreError::NoMachineIdentity)?;
        let _writing = lock(&self.store_writes);
        let mut records = match &*lock(&self.always) {
            AlwaysState::Loaded(records) => records.clone(),
            AlwaysState::Failed(error) => return Err(error.clone()),
        };
        records.retain(|record| {
            !(record.agent_project_id == grantee
                && record.bundle_identity == bundle_identity
                && record.machine_uuid == machine)
        });
        records.push(AlwaysGrantRecord {
            agent_project_id: grantee.to_string(),
            bundle_identity: bundle_identity.to_string(),
            team_id: identity.team_id.clone(),
            designated_requirement: Some(identity.designated_requirement.clone()),
            machine_uuid: machine,
            created_at_ms: wall_clock_ms(),
        });
        self.storage.save(&GrantStoreState {
            version: GRANT_STORE_VERSION,
            records: records.clone(),
        })?;
        *lock(&self.always) = AlwaysState::Loaded(records);
        Ok(())
    }

    /// Take a waiting call off its question, and withdraw the question when
    /// asked to and no other call is waiting on it.
    fn leave(&self, waiter: Waiter<'_>, withdraw: bool) {
        let ask_id = waiter.ask_id.clone();
        drop(waiter);
        if !withdraw {
            return;
        }
        let mut state = lock(&self.state);
        let still_wanted = state
            .questions
            .get(&ask_id)
            .is_some_and(|question| !question.parked.is_empty());
        if still_wanted {
            return;
        }
        if let Some(question) = state.questions.remove(&ask_id) {
            withdraw_question(&mut state, &ask_id, question);
        }
    }

    /// Forget everything held for a conversation whose last route unbound.
    ///
    /// Its grants and remembered refusals go, and any question it raised is
    /// withdrawn, so an answer that arrives afterwards grants nothing.
    pub fn end_conversation(&self, conversation_key: &str) {
        let mut state = lock(&self.state);
        state
            .conversation_apps
            .retain(|(conversation, _), _| conversation != conversation_key);
        state
            .conversation_app_denies
            .retain(|(conversation, _)| conversation != conversation_key);
        state.takeovers.remove(conversation_key);
        state.takeover_denies.remove(conversation_key);
        let asked: Vec<String> = state
            .questions
            .iter()
            .filter(|(_, question)| question.subject.conversation_key() == conversation_key)
            .map(|(ask_id, _)| ask_id.clone())
            .collect();
        for ask_id in asked {
            if let Some(question) = state.questions.remove(&ask_id) {
                withdraw_question(&mut state, &ask_id, question);
            }
        }
    }

    /// Whether a question is still open, for callers and tests that need to
    /// know if a late answer would still be applied.
    pub fn question_open(&self, ask_id: &str) -> bool {
        lock(&self.state).questions.contains_key(ask_id)
    }

    /// The durable "always" grants, for the operator's listing.
    ///
    /// Records naming another machine are listed apart: they grant nothing
    /// here, and an operator who restored a backup should be able to see that
    /// they arrived and were not honoured. Records on this machine that name
    /// no signature are listed apart for the same reason.
    pub fn list(&self) -> Value {
        let describe = |record: &AlwaysGrantRecord| {
            let mut described = json!({
                "grantee": record.agent_project_id,
                "bundle_identity": record.bundle_identity,
                "created_at_ms": record.created_at_ms,
            });
            if let Some(team_id) = &record.team_id {
                described["team_id"] = json!(team_id);
            }
            described
        };
        match &*lock(&self.always) {
            AlwaysState::Failed(error) => json!({
                "grants": [],
                "other_machine_grants": [],
                "unbound_grants": [],
                "store": {
                    "state": "unreadable",
                    "reason": error.reason_code(),
                    "detail": error.to_string(),
                },
            }),
            AlwaysState::Loaded(records) => {
                let here = |record: &&AlwaysGrantRecord| {
                    self.machine_uuid.as_deref() == Some(record.machine_uuid.as_str())
                };
                let bound = |record: &&AlwaysGrantRecord| record.designated_requirement.is_some();
                json!({
                    "grants": records
                        .iter()
                        .filter(|record| here(record) && bound(record))
                        .map(describe)
                        .collect::<Vec<_>>(),
                    "other_machine_grants": records
                        .iter()
                        .filter(|record| !here(record))
                        .map(describe)
                        .collect::<Vec<_>>(),
                    "unbound_grants": records
                        .iter()
                        .filter(|record| here(record) && !bound(record))
                        .map(describe)
                        .collect::<Vec<_>>(),
                    "store": {"state": "loaded"},
                })
            }
        }
    }

    /// Remove the durable grants for one agent and application.
    ///
    /// With `dry_run` nothing is written and the reply names what would be
    /// removed. A store that could not be read is never written: saving would
    /// replace the unreadable file, and with it any answer it still holds.
    pub fn revoke(&self, grantee: &str, bundle_identity: &str, dry_run: bool) -> Value {
        let _writing = lock(&self.store_writes);
        let records = match &*lock(&self.always) {
            AlwaysState::Loaded(records) => records.clone(),
            AlwaysState::Failed(error) => {
                return json!({
                    "outcome": "store_unavailable",
                    "reason": error.reason_code(),
                    "remedy": "repair or remove the grant store file, then restart the module",
                })
            }
        };
        let (removed, kept): (Vec<_>, Vec<_>) = records.into_iter().partition(|record| {
            record.agent_project_id == grantee && record.bundle_identity == bundle_identity
        });
        if removed.is_empty() {
            return json!({"outcome": "grant_not_found"});
        }
        let count = removed.len();
        if dry_run {
            return json!({"outcome": "would_revoke", "records": count});
        }
        if let Err(error) = self.storage.save(&GrantStoreState {
            version: GRANT_STORE_VERSION,
            records: kept.clone(),
        }) {
            return json!({
                "outcome": "revoke_failed",
                "reason": error.reason_code(),
                "remedy": "the grant is still in force; check the data directory is writable and retry",
            });
        }
        *lock(&self.always) = AlwaysState::Loaded(kept);
        json!({"outcome": "revoked", "records": count})
    }
}

fn withdraw_question(state: &mut GrantState, ask_id: &str, question: OpenQuestion) {
    if state
        .open_by_subject
        .get(&question.subject)
        .map(String::as_str)
        == Some(ask_id)
    {
        state.open_by_subject.remove(&question.subject);
    }
    // Stopping the task drops its registration with the elicitor, so an answer
    // that arrives afterwards is discarded as unsolicited.
    if let Some(asking) = question.asking {
        asking.abort();
    }
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// Display effects describe consent; settlement still validates the original offered words.
fn question_body(
    ask_id: &str,
    need: &GrantNeed,
    offered: &[&'static str],
    signature_changed: bool,
) -> Value {
    use crate::consent_card::*;
    let (title, prompt, target, deadline) = match need {
        GrantNeed::App { display_name, .. } => (
            format!("Allow access to {display_name}?"),
            "Covers reading and acting inside this application.".to_string(),
            Target { kind: TargetKind::App, label: display_name.clone() }, APP_QUESTION_DEADLINE,
        ),
        GrantNeed::Takeover => (
            "Allow control of your mouse and keyboard?".to_string(),
            "Takeover lets the agent bring apps to the front, type into them, and move your real mouse pointer. It is machine-wide for this conversation and can reach every application on the screen.".to_string(),
            Target { kind: TargetKind::Machine, label: "your mouse and keyboard".into() }, TAKEOVER_QUESTION_DEADLINE,
        ),
    };
    let options = offered
        .iter()
        .map(|id| match *id {
            ALLOW_CONVERSATION => ConsentOption::grant(*id, "Allow for this conversation"),
            ALLOW_ALWAYS => ConsentOption::grant(*id, "Always allow"),
            DENY => ConsentOption::decline(*id, "Don't allow"),
            _ => unreachable!("only known decisions are offered"),
        })
        .collect();
    let facts = if signature_changed {
        vec![Fact::new("Application changed", "This application's code signature has changed since it was approved, so it may not be the application you approved")]
    } else {
        vec![]
    };
    ConsentCard {
        title,
        prompt,
        target,
        facts,
        options,
        expires_in: deadline,
        material_damage: true,
        scope: None,
        duration: if offered.contains(&ALLOW_ALWAYS) {
            None
        } else {
            Some(json!("conversation"))
        },
    }
    .render(ask_id)
    .expect("computer consent has one decline")
}

/// What the answer to a question is applied against, copied out so the store
/// can be written without holding the grant state.
struct AnsweredQuestion {
    ask_id: String,
    subject: Subject,
    offered: Vec<&'static str>,
    always_grantee: Option<String>,
    identity: Option<AppIdentity>,
}

/// A call parked on a question. Dropping it takes the call off the question.
struct Waiter<'a> {
    grants: &'a ComputerGrants,
    ask_id: String,
    id: u64,
}

impl Drop for Waiter<'_> {
    fn drop(&mut self) {
        if let Some(question) = lock(&self.grants.state).questions.get_mut(&self.ask_id) {
            question.parked.remove(&self.id);
        }
    }
}

enum Ending {
    Settled(Settlement, Option<u64>),
    Withdrawn,
    TimedOut,
    Draining,
    Cancelled,
}

#[cfg(test)]
mod consent_card_tests {
    use super::*;

    #[test]
    fn takeover_card_has_a_decline_and_conversation_duration() {
        let body = question_body(
            "takeover",
            &GrantNeed::Takeover,
            &[ALLOW_CONVERSATION, DENY],
            false,
        );
        crate::consent_card::assert_contract(&body, &["allow_conversation", "deny"], "deny");
        assert_eq!(body["params"]["duration"], "conversation");
        assert_eq!(body["params"]["expires_in_ms"], 300_000);
    }
}
