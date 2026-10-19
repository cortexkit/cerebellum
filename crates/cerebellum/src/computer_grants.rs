//! Permission for the computer plane: app grants, the takeover grant, and the
//! consent a call waits for.
//!
//! App and whole-computer grants belong to an admitted head or worker holder,
//! not to the conversation that carried the question. Temporary answers last
//! thirty minutes on the wall clock. Each action retains its authorizing row;
//! revoking or narrowing that row stops the action rather than borrowing a
//! different covering grant.
//!
//! A call that needs a grant it does not hold asks the question itself and
//! waits for the answer, up to [`CONSENT_PARK_LIMIT`]. The question outlives
//! that wait: the session's next call drains a late answer and writes the
//! grant, and the caller, told `consent_pending`, retries once woken.
//!
//! The same question registry holds the login consent cards of
//! `browser.capture_login` and `browser.import_login` (see
//! [`ComputerGrants::require_login`]): they park the call the same way, and
//! end with the conversation the same way. A late answer to one is
//! remembered for the agent's retry rather than written as a grant.
//!
//! Granting answers are stored through `AgentGrants`, bound to this machine's
//! hardware identity so that a copy restored elsewhere grants nothing there.
//! An unreadable store withholds authority and is never overwritten.
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
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use cerebellum_core::consent::OnceDispatchToken;
use cerebellum_core::dispatch::InFlightGuard;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::watch;

use crate::cingulate_client::card::{consent_request, CardKind};
use crate::cingulate_client::desk::{
    Apply, ApplyFailed, ConsentDesk, DeskSession, Ending as CardEnding, InCall, LetGo, NoCard,
    RaisedCard,
};
use crate::cingulate_client::live_call::{LiveCall, NotLive};
use crate::cingulate_client::wire::{Execution, Record};
use crate::consent_drain::{AppliedSettlement, ConsentEffects};
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

/// Legacy deadline sent only to consent servers without no-expiry support.
///
/// The original thirty-minute lifetime matches browser site cards on those
/// servers, allowing time to notice a phone prompt.
pub const APP_QUESTION_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Legacy takeover deadline, retained for older consent servers. New servers
/// keep the card open until answered; dispatch still rechecks the live target.
pub const TAKEOVER_QUESTION_DEADLINE: Duration = Duration::from_secs(5 * 60);

const ALLOW_30M: &str = "allow_30m";
const ALLOW_ALWAYS: &str = "allow_always";
const COMPUTER_30M: &str = "computer_30m";
const COMPUTER_ALWAYS: &str = "computer_always";
const ALLOW_ONCE: &str = "allow_once";
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
        cerebellum_core::private_fs::create_dir_all(&directory).map_err(failed)?;
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
            let mut file = cerebellum_core::private_fs::create_new_file(&temporary)?;
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
    pub holder: Option<crate::agent_grants::GrantHolder>,
    pub conversation_key: String,
    pub agent_project_id: String,
    /// Whether the daemon attested both the agent project id and the session
    /// kind, and this is not a worker session. Only then may an "always"
    /// answer be offered or stored:
    /// an unattested project id came from a caller-controlled fallback, and
    /// a durable grant keyed by it would be a permission anyone could claim.
    pub durable_identity_attested: bool,
}

impl GrantCaller {
    /// For trusted embedders that already resolved a head. Routed requests set
    /// `holder` from accepted admission facts instead of using this constructor.
    pub fn new(
        conversation_key: String,
        agent_project_id: String,
        durable_identity_attested: bool,
    ) -> Self {
        Self {
            holder: Some(crate::agent_grants::GrantHolder::Head {
                agent_id: agent_project_id.clone(),
            }),
            conversation_key,
            agent_project_id,
            durable_identity_attested,
        }
    }
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
#[cfg(test)]
pub(crate) struct SignedByFixtureTeam;

#[cfg(test)]
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
    /// One login consent card: a login capability called with exactly these
    /// parameters in this conversation.
    Login {
        conversation_key: String,
        capability: LoginCapability,
        parameters: String,
    },
}

impl Subject {
    fn desk_subject(&self) -> String {
        use crate::cingulate_client::subject;
        match self {
            Self::App {
                conversation_key,
                bundle_identity,
            } => subject::app_control(conversation_key, bundle_identity),
            Self::Takeover { conversation_key } => subject::takeover(conversation_key),
            Self::Login {
                conversation_key,
                capability,
                parameters,
            } => match capability {
                LoginCapability::ImportLogin => subject::login_import(conversation_key, parameters),
                LoginCapability::CaptureLogin => {
                    subject::login_capture(conversation_key, parameters)
                }
            },
        }
    }
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
            | Self::Takeover { conversation_key }
            | Self::Login {
                conversation_key, ..
            } => conversation_key,
        }
    }
}

// ---------------------------------------------------------------------------
// The carrier and the route a call arrived on
// ---------------------------------------------------------------------------

/// The desk and live inbound call under which a permission card may be raised.
pub trait QuestionCarrier: Send + Sync {
    fn desk(&self) -> Arc<ConsentDesk>;
    fn live(&self) -> Result<LiveCall, NotLive>;
    fn requester_ref(&self) -> Option<String> {
        None
    }
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
    /// A flow (see `AcceptedBindFacts::flow_id`) has no person to ask: it may use
    /// its owner's persistent app grants, but never raises a consent question.
    pub unattended: bool,
    /// True for older runs without a provider-resolved head route: they may
    /// use existing permissions, but cannot ask a person. False for codemode
    /// runs admitted through a head route, which can ask that head's person
    /// without waiting for the answer inside the call.
    pub agent_run: bool,
    /// The admitted live session, or `None` when no agent session can ask.
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
            unattended: false,
            agent_run: false,
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
    row: Option<crate::agent_grants::GrantUse>,
    /// Whether the call had to wait for an answer. A call that waited must
    /// re-resolve its target: the process may have changed while it waited.
    pub waited: bool,
    /// Set when the answer this call waited on was `allow_always`: whether it
    /// was written to the store, or why not.
    pub persisted: Option<Result<(), String>>,
}

impl GrantAdmission {
    pub fn commit(&self) -> bool {
        self.row
            .as_ref()
            .is_none_or(crate::agent_grants::GrantUse::is_live)
    }
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
    /// A flow needs a durable application permission.
    MissingFlowGrant { detail: Value },
    /// The module began draining while the call waited.
    Draining,
    /// The call's route unbound while it waited; nobody is left to answer.
    RouteClosed,
    /// The caller cancelled the request while it waited.
    Cancelled,
    /// An earlier call still owns the queue; this call never dispatched.
    QueueWaitExpired,
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
            Self::MissingFlowGrant { detail } => {
                json!({"outcome":"consent_unavailable", "reason":"unattended_flow", "detail":detail, "remedy":"an unattended flow cannot ask a person; configure its owner's persistent app grant"})
            }
            Self::Draining => json!({
                "outcome": "module_draining",
                "remedy": "retry after the module restarts",
            }),
            Self::RouteClosed => json!({"outcome": "route_closed"}),
            Self::Cancelled => json!({"outcome": "cancelled"}),
            Self::QueueWaitExpired => json!({
                "outcome": "queue_wait_expired",
                "remedy": "an earlier action in this conversation is still running; nothing was dispatched for this call; retry",
            }),
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
// Login consent cards
// ---------------------------------------------------------------------------

/// The login capabilities that ask the person through a consent card held
/// here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum LoginCapability {
    /// `browser.capture_login`.
    CaptureLogin,
    /// `browser.import_login`.
    ImportLogin,
}

/// One login call's need for the person's consent.
pub struct LoginConsentRequest {
    /// The conversation and exact parameters the card is about. Detached
    /// answers remain usable until the session scope ends.
    pub conversation_key: String,
    pub capability: LoginCapability,
    /// Everything the answer is about, in one string compared exactly: a
    /// remembered answer is used only by a retry with the same parameters.
    pub parameters: String,
    /// How to reach the person.
    pub carrier: Arc<dyn QuestionCarrier>,
    pub cancel: Option<CancelHandle>,
    pub drain: watch::Receiver<bool>,
    pub route: Arc<dyn RouteLiveness>,
    /// The request's in-flight guard, parked while the call waits on the
    /// person, as for a computer grant.
    pub park_guard: Option<Arc<InFlightGuard>>,
}

/// How a login call's wait for consent ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoginConsent {
    /// The ending of the card this call waited on, or an answer the person
    /// gave to an earlier card for the same parameters after its call had
    /// returned. Each capability reads it exactly as it reads an answer that
    /// arrived in the call.
    Ended(LoginAnswer),
    /// The person has not answered within the call's wait. The card stays
    /// open, and an answer that arrives later is remembered for a retry.
    Pending { ask_id: String },
}

/// A login ending and its card. After using a late approval, the retry tells
/// Cingulate, the consent service, whether the approved action actually ran.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoginAnswer {
    pub ending: CardEnding,
    pub elicitation_id: Option<String>,
    pub taken_approval: bool,
}

/// The remedy a login call gives with `consent_pending`. The calling session
/// is woken when the card settles, and the late answer is used only by a
/// call with the same arguments.
pub const LOGIN_CONSENT_PENDING_REMEDY: &str = "The person hasn't answered yet; you'll be woken \
     when they do. Then call this again with the same arguments.";

// ---------------------------------------------------------------------------
// The grants
// ---------------------------------------------------------------------------

/// How a question ended, as its waiters see it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Settlement {
    Once,
    Allowed {
        persisted: Option<Result<(), String>>,
    },
    Denied,
    Ended {
        reason: &'static str,
        remedy: &'static str,
    },
    /// How a login card ended, handed to the calls waiting on it unread: each
    /// login capability turns the ending into its own reply. `allows` says
    /// the answer was one of the card's granting options, which only one
    /// waiting call may act on.
    Login {
        outcome: LoginAnswer,
        allows: bool,
    },
}

/// How a question ended and the elected holder's id, or `None` when another
/// session call applied a late answer. The watch remains empty until the
/// permission or remembered login refusal is stored.
type Settled = Option<(Settlement, Option<u64>)>;
type SettledSignal = watch::Sender<Settled>;
type SettledWatch = watch::Receiver<Settled>;

/// A question put to the person and not yet answered.
struct OpenQuestion {
    holder: Option<crate::agent_grants::GrantHolder>,
    subject: Subject,
    /// The decisions the question offered. An answer outside them grants
    /// nothing.
    offered: Vec<&'static str>,
    /// For an app question, the signing identity of the process the question
    /// was raised for. An allowing answer is bound to it.
    identity: Option<AppIdentity>,
    /// Calls parked on this question, by the order they joined.
    parked: BTreeSet<u64>,
    next_waiter: u64,
    settled: SettledSignal,
    completion: Arc<watch::Sender<bool>>,
    /// Set only for a login card: what its answers mean.
    login: Option<LoginCard>,
}

/// What settling a login card needs to know about it.
struct LoginCard {
    /// The option id whose effect is to decline.
    decline: Option<String>,
}

/// The card's explicit login refusal, kept until the session ends so a
/// retry does not prompt again for a decision the person already declined.
struct RememberedLoginAnswer {
    answer: LoginAnswer,
}

#[derive(Default)]
struct GrantState {
    conversation_app_denies: HashSet<(String, String)>,
    takeover_denies: HashSet<String>,
    creating: HashSet<String>,
    questions: HashMap<String, OpenQuestion>,
    /// Removed pending records stay available to joining callers while their
    /// elected caller stores the grant and marks the desk record applied.
    applying: HashMap<String, OpenQuestion>,
    open_by_subject: BTreeMap<Subject, String>,
    /// Late answers to login cards, by the card's subject.
    login_answers: HashMap<Subject, RememberedLoginAnswer>,
    /// How long a login call waits in place; [`CONSENT_PARK_LIMIT`] unless a
    /// test shortened it.
    login_park_limit: Option<Duration>,
}

enum Standing {
    Granted(crate::agent_grants::GrantUse),
    Denied,
    Asking,
    Unasked,
    /// A grant exists for the application's bundle identity, and the process
    /// answering to it now does not satisfy the signature it was made for.
    /// Carries this conversation's grant when it was one of those that
    /// failed, so it can be dropped; `None` when only "always" records failed.
    SignatureChanged,
    /// The process's signature could not be read, so no grant can be applied
    /// to it.
    IdentityUnreadable(AppIdentityUnreadable),
}

/// Every computer grant this module holds, and the questions it is waiting on.
pub struct ComputerGrants {
    agent_grants: Arc<crate::agent_grants::AgentGrants>,
    machine_uuid: Option<String>,
    state: Mutex<GrantState>,
    /// Held across a read-modify-write of the store, so two concurrent writes
    /// cannot each save a copy missing the other's record.
    creation: tokio::sync::Mutex<()>,
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
        let legacy = crate::agent_grants::LegacyGrantStores {
            apps: Arc::clone(&storage),
            browser: Arc::new(crate::browser_standing_grants::InMemoryStandingGrantStorage::new()),
            user_browser: Arc::new(
                crate::browser_standing_grants::InMemoryStandingGrantStorage::new(),
            ),
        };
        let agent_grants = Arc::new(crate::agent_grants::AgentGrants::open(
            Arc::new(crate::agent_grants::InMemoryAgentGrantStorage::default()),
            &legacy,
            Some(machine_uuid.clone().unwrap_or_else(|| "isolated".into())),
        ));
        Self {
            agent_grants,
            machine_uuid,
            state: Mutex::new(GrantState::default()),
            creation: tokio::sync::Mutex::new(()),
        }
    }

    /// Open the unified durable store without consulting migrated legacy files.
    pub fn open_durable(machine_uuid: Option<String>) -> Self {
        let grants = Arc::new(
            crate::agent_grants::AgentGrants::open_durable(machine_uuid)
                .unwrap_or_else(crate::agent_grants::AgentGrants::unavailable),
        );
        Self::note_durable_store_health(&grants);
        Self::in_memory().with_agent_grants(grants)
    }

    /// Grants held only in memory, with no machine identity, so "always" is
    /// never offered. For tests and isolated planes.
    pub fn in_memory() -> Self {
        Self::open(Arc::new(InMemoryGrantStorage::new()), None)
    }

    pub fn with_agent_grants(mut self, grants: Arc<crate::agent_grants::AgentGrants>) -> Self {
        self.machine_uuid = grants.machine_uuid().map(str::to_owned);
        self.agent_grants = grants;
        self
    }

    pub fn agent_grants(&self) -> &Arc<crate::agent_grants::AgentGrants> {
        &self.agent_grants
    }

    fn authorizing_row(
        &self,
        caller: &GrantCaller,
        need: &GrantNeed,
    ) -> Option<crate::agent_grants::GrantUse> {
        self.agent_grants.authorize(
            caller.holder.as_ref()?,
            crate::agent_grants::GrantDemand::computer(need),
        )
    }

    pub fn store_error(&self) -> Option<GrantStoreError> {
        self.agent_grants
            .store_error()
            .map(|error| GrantStoreError::Unreadable {
                detail: error.to_string(),
            })
    }

    /// Whether a question to this caller about this process may offer
    /// `allow_always`.
    ///
    /// All four must hold: a daemon-attested identity to key the record by, a
    /// machine identity to bind it to, a store that was read, so that writing
    /// does not overwrite one that could not be, and a signature naming a
    /// signer that lasts beyond this one build.
    fn offers_always(&self, caller: &GrantCaller, identity: Option<&AppIdentity>) -> bool {
        matches!(
            caller.holder,
            Some(crate::agent_grants::GrantHolder::Head { .. })
        ) && caller.durable_identity_attested
            && self.agent_grants.can_record()
            && self.machine_uuid.is_some()
            && identity.is_some_and(AppIdentity::names_a_lasting_signer)
    }

    /// Used by flow installation to predict whether an app action would ask.
    /// Dispatch separately verifies the running application's code signature.
    pub(crate) fn has_standing_app_grant(&self, agent_project_id: &str, bundle: &str) -> bool {
        self.agent_grants
            .live_rows(Some(agent_project_id), self.agent_grants.now_ms())
            .is_ok_and(|rows| {
                rows.iter().any(|row| {
                    matches!(row.holder, crate::agent_grants::GrantHolder::Head { .. })
                        && (row.subject == crate::agent_grants::GrantSubject::WholeComputer
                            || (row.subject
                                == crate::agent_grants::GrantSubject::App(bundle.into())
                                && row
                                    .designated_requirement
                                    .as_ref()
                                    .is_some_and(|requirement| !requirement.is_empty())))
                })
            })
    }

    pub(crate) fn has_exact_standing_app_grant(
        &self,
        agent: &str,
        bundle: &str,
        signer: &str,
    ) -> bool {
        self.agent_grants
            .live_rows(Some(agent), self.agent_grants.now_ms())
            .is_ok_and(|rows| {
                rows.iter().any(|row| {
                    matches!(row.holder, crate::agent_grants::GrantHolder::Head { .. })
                        && (row.subject == crate::agent_grants::GrantSubject::WholeComputer
                            || (row.subject
                                == crate::agent_grants::GrantSubject::App(bundle.into())
                                && row.designated_requirement.as_deref() == Some(signer)))
                })
            })
    }

    #[cfg(test)]
    pub(crate) fn seed_conversation_app_for_test(&self, conversation: &str, bundle: &str) {
        let _ = (conversation, bundle);
    }

    fn standing(&self, caller: &GrantCaller, need: &GrantNeed) -> Standing {
        if let Some(used) = self.authorizing_row(caller, need) {
            return Standing::Granted(used);
        }
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
                if !caller.conversation_key.is_empty()
                    && state.conversation_app_denies.contains(&key)
                {
                    return Standing::Denied;
                }
                // Released before the signature checks, which read the
                // process and must not hold every other call up meanwhile.
                drop(state);
                let mut recorded = false;
                let rows = self
                    .agent_grants
                    .live_rows(Some(&caller.agent_project_id), self.agent_grants.now_ms())
                    .unwrap_or_default();
                for row in rows.iter().filter(|row| {
                    caller.holder.as_ref() == Some(&row.holder)
                        && row.subject
                            == crate::agent_grants::GrantSubject::App(bundle_identity.clone())
                }) {
                    let requirement = row.designated_requirement.as_deref();
                    // A record that names no signature grants nothing, the
                    // same as a record from another machine: there is nothing
                    // to check the process against.
                    let Some(requirement) = requirement else {
                        continue;
                    };
                    recorded = true;
                    match code.satisfies(requirement) {
                        Ok(true) | Ok(false) => {}
                        Err(unreadable) => return Standing::IdentityUnreadable(unreadable),
                    }
                }
                if recorded {
                    return Standing::SignatureChanged;
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
                match state.open_by_subject.get(&subject) {
                    Some(_) => Standing::Asking,
                    None => Standing::Unasked,
                }
            }
        }
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn seed_takeover_for_test(&self, agent: &str) {
        let open = AnsweredQuestion {
            holder: Some(crate::agent_grants::GrantHolder::Head {
                agent_id: agent.into(),
            }),
            card_ref: "fixture-takeover".into(),
            subject: Subject::Takeover {
                conversation_key: String::new(),
            },
            offered: vec![],
            identity: None,
        };
        self.write_agent_answer(&open, false).unwrap();
    }

    /// Whether the caller holds the grant now, without asking anyone.
    pub fn holds(&self, caller: &GrantCaller, need: &GrantNeed) -> bool {
        matches!(self.standing(caller, need), Standing::Granted(_))
    }

    /// Admit one call under an existing grant or a card answered while held.
    pub async fn require(
        self: &Arc<Self>,
        need: &GrantNeed,
        context: &ConsentContext,
        cancel: &CancelHandle,
    ) -> Result<GrantAdmission, ConsentRefusal> {
        if context.agent_run && matches!(need, GrantNeed::Takeover) {
            return Err(ConsentRefusal::Unavailable {
                reason: "agent_run",
                remedy: "takeover requires an attended session",
            });
        }
        if context.unattended && matches!(need, GrantNeed::Takeover) {
            return Err(ConsentRefusal::Unavailable {
                reason: "takeover_not_for_flows",
                remedy: "takeover requires an attended session",
            });
        }
        let caller = &context.caller;
        let mut signature_changed = false;
        match self.standing(caller, need) {
            Standing::Granted(used) => {
                if let (Some(carrier), Some(id), Some(terminal)) = (
                    &context.carrier,
                    used.row().card_ref.as_deref(),
                    crate::TerminalArbiter::current(),
                ) {
                    terminal.track_consent(carrier.desk(), id);
                }
                crate::grant_enforcement::track(&used);
                return Ok(GrantAdmission {
                    row: Some(used),
                    ..GrantAdmission::default()
                });
            }
            Standing::Denied => {
                return Err(ConsentRefusal::Denied {
                    grant_kind: need.grant_kind(),
                    remembered: true,
                })
            }
            Standing::IdentityUnreadable(unreadable) => return Err(unreadable.refusal()),
            Standing::Asking | Standing::Unasked => {}
            Standing::SignatureChanged => {
                signature_changed = true;
            }
        }
        if context.agent_run {
            return Err(ConsentRefusal::Unavailable {
                reason: "agent_run",
                remedy: "an agent run cannot ask a person; configure standing grants in an attended session",
            });
        }
        if context.unattended {
            if let GrantNeed::App {
                bundle_identity,
                display_name,
                code,
            } = need
            {
                let identity = code.identity().map_err(|unreadable| unreadable.refusal())?;
                return Err(ConsentRefusal::MissingFlowGrant {
                    detail: json!({"reason":"unattended_flow", "grant":crate::management::encode_grant(json!({"tool":"computer_use", "target":bundle_identity, "signer":identity.designated_requirement, "level":4})), "grant_label":format!("control of {display_name}")}),
                });
            }
        }
        let carrier = context
            .carrier
            .as_ref()
            .ok_or_else(|| no_card(NoCard::NoAgentSession))?;
        let live = carrier
            .live()
            .map_err(|why| no_card(NoCard::of_not_live(why)))?;
        let desk = carrier.desk();
        let mut session = desk
            .session(&live)
            .await
            .map_err(|error| card_refusal(&CardEnding::of_refusal(&error)))?;
        let identity = match need {
            GrantNeed::App { code, .. } => {
                Some(code.identity().map_err(|unreadable| unreadable.refusal())?)
            }
            GrantNeed::Takeover => None,
        };
        let (waiter, settled, completion) = self
            .join_or_ask(
                caller,
                need,
                carrier,
                &live,
                &mut session,
                identity,
                signature_changed,
            )
            .await?;
        if crate::codemode::active() {
            crate::codemode::app(match need {
                GrantNeed::App {
                    bundle_identity, ..
                } => bundle_identity,
                GrantNeed::Takeover => "whole_computer",
            });
            return Err(ConsentRefusal::Pending {
                ask_id: waiter.ask_id.clone(),
            });
        }
        let parked = context
            .park_guard
            .as_ref()
            .map(|guard| guard.park_on_consent());
        let _park_clock = crate::computer_capability::park_clock();
        let mut drain = context.drain.clone();
        let cancelled = async {
            tokio::select! {
                _ = drain.wait_for(|value| *value) => LetGo::Withdraw,
                _ = cancel.cancelled() => if context.route.route_open() && context.route.conversation_open() { LetGo::Detach } else { LetGo::Withdraw },
            }
        };
        let result = self
            .wait_on_card(
                &desk,
                &mut session,
                &waiter,
                settled,
                completion,
                context.park_limit,
                cancelled,
            )
            .await;
        drop(parked);
        let result = if *context.drain.borrow() && matches!(result, Ending::Cancelled) {
            Ending::Draining
        } else {
            result
        };
        match result {
            Ending::Settled(Settlement::Once, executor) if executor == Some(waiter.id) => {
                if let Some(terminal) = crate::TerminalArbiter::current() {
                    terminal.track_consent(Arc::clone(&desk), &waiter.ask_id);
                }
                Ok(GrantAdmission {
                    waited: true,
                    ..GrantAdmission::default()
                })
            }
            Ending::Settled(Settlement::Once, _) => Err(ConsentRefusal::GrantedNotExecuted),
            Ending::Settled(Settlement::Allowed { persisted }, executor) => {
                if executor != Some(waiter.id) {
                    return Err(ConsentRefusal::GrantedNotExecuted);
                }
                let Some(used) = self.authorizing_row(caller, need) else {
                    let _ = desk.finish_execution(
                        &waiter.ask_id,
                        Execution::ApprovedNotExecuted,
                        Some(crate::cingulate_client::wire::ExecutionReason::GrantStoreUnavailable),
                    );
                    return Err(ConsentRefusal::Unavailable {
                        reason: "grant_not_recorded",
                        remedy: "retry this call",
                    });
                };
                crate::grant_enforcement::track(&used);
                if let Some(terminal) = crate::TerminalArbiter::current() {
                    terminal.track_consent(Arc::clone(&desk), &waiter.ask_id);
                }
                Ok(GrantAdmission {
                    row: Some(used),
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
            Ending::Settled(Settlement::Login { .. }, _) | Ending::Withdrawn => {
                Err(ConsentRefusal::Unavailable {
                    reason: "question_withdrawn",
                    remedy: "retry this call to ask again",
                })
            }
            Ending::TimedOut => Err(ConsentRefusal::Pending {
                ask_id: waiter.ask_id.clone(),
            }),
            Ending::Draining => {
                self.leave(waiter, true);
                Err(ConsentRefusal::Draining)
            }
            Ending::Cancelled => {
                let route_open = context.route.route_open();
                self.leave(
                    waiter,
                    !context.route.route_open() || !context.route.conversation_open(),
                );
                if route_open {
                    Err(ConsentRefusal::Cancelled)
                } else {
                    Err(ConsentRefusal::RouteClosed)
                }
            }
        }
    }

    /// Admit a real-pointer dispatch under a whole-computer row, asking and
    /// waiting for its answer when the caller holds no covering row.
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

    /// Join the open login card or take a late approval, under one park deadline.
    pub async fn require_login(
        self: &Arc<Self>,
        request: LoginConsentRequest,
        mut new_card: impl FnMut() -> Value,
    ) -> LoginConsent {
        let failed = |ending| {
            LoginConsent::Ended(LoginAnswer {
                ending,
                elicitation_id: None,
                taken_approval: false,
            })
        };
        let live = match request.carrier.live() {
            Ok(live) => live,
            Err(why) => return failed(CardEnding::NoCard(NoCard::of_not_live(why))),
        };
        let desk = request.carrier.desk();
        let mut session = match desk.session(&live).await {
            Ok(session) => session,
            Err(error) => return failed(CardEnding::of_refusal(&error)),
        };
        let subject = Subject::Login {
            conversation_key: request.conversation_key.clone(),
            capability: request.capability,
            parameters: request.parameters.clone(),
        };
        let key = subject.desk_subject();
        if desk.take_lost_answer(live.session(), &key) {
            return failed(CardEnding::NoAnswer);
        }
        let park_end = tokio::time::Instant::now() + self.login_park_limit();
        loop {
            let _creation = self.creation.lock().await;
            if let Some((ask_id, choice_id)) = desk.take_single_use_approval(live.session(), &key) {
                // A session call already read the late answer, stored this
                // approval, and acknowledged the answer feed.
                return LoginConsent::Ended(LoginAnswer {
                    ending: CardEnding::Granted { choice_id },
                    elicitation_id: Some(ask_id),
                    taken_approval: true,
                });
            }
            let joined = {
                let mut state = lock(&self.state);
                if let Some(answer) = state.login_answers.get(&subject) {
                    return LoginConsent::Ended(answer.answer.clone());
                }
                join_open(&mut state, &subject)
            };
            let (ask_id, id, settled, completion) = match joined {
                Some(joined) => joined,
                None => {
                    lock(&self.state).creating.insert(key.clone());
                    let _raising = Raising {
                        grants: self,
                        subject: key.clone(),
                    };
                    let body = new_card();
                    let kind = match request.capability {
                        LoginCapability::ImportLogin => CardKind::LoginImport,
                        LoginCapability::CaptureLogin => CardKind::LoginCapture,
                    };
                    let card = match consent_request(
                        kind,
                        &body,
                        crate::consent_card::LOGIN_CARD_LIFETIME,
                        request.carrier.requester_ref().as_deref(),
                        None,
                        None,
                    ) {
                        Ok(card) => card,
                        Err(_) => return failed(CardEnding::DeliveryFailed),
                    };
                    let decline = Some(card.decline_id.clone());
                    let ask_id = match desk.open_card_for(live.session(), &key) {
                        Some(card) => card.elicitation_id,
                        None => match if crate::codemode::active() {
                            session.raise_detached(card, &key).await
                        } else {
                            session.raise(card, &key).await
                        } {
                            Ok(id) => id,
                            Err(ending) => return failed(ending),
                        },
                    };
                    let (settled_tx, settled) = watch::channel(None);
                    let (completion_tx, completion) = watch::channel(false);
                    let mut state = lock(&self.state);
                    state.questions.insert(
                        ask_id.clone(),
                        OpenQuestion {
                            subject: subject.clone(),
                            offered: Vec::new(),
                            holder: None,
                            identity: None,
                            parked: BTreeSet::from([0]),
                            next_waiter: 1,
                            settled: settled_tx,
                            completion: Arc::new(completion_tx),
                            login: Some(LoginCard { decline }),
                        },
                    );
                    state
                        .open_by_subject
                        .insert(subject.clone(), ask_id.clone());
                    (ask_id, 0, settled, completion)
                }
            };
            drop(_creation);
            let waiter = Waiter {
                grants: self,
                ask_id,
                id,
            };
            if crate::codemode::active() {
                return LoginConsent::Pending {
                    ask_id: waiter.ask_id.clone(),
                };
            }
            let parked = request
                .park_guard
                .as_ref()
                .map(|guard| guard.park_on_consent());
            let _park_clock = crate::computer_capability::park_clock();
            let mut drain = request.drain.clone();
            let cancelled = async {
                tokio::select! {
                    _ = drain.wait_for(|value| *value) => LetGo::Withdraw,
                    _ = async { match &request.cancel { Some(cancel) => cancel.cancelled().await, None => std::future::pending().await } } => {
                        if request.route.route_open() && request.route.conversation_open() { LetGo::Detach } else { LetGo::Withdraw }
                    }
                }
            };
            let result = self
                .wait_on_card(
                    &desk,
                    &mut session,
                    &waiter,
                    settled,
                    completion,
                    park_end.saturating_duration_since(tokio::time::Instant::now()),
                    cancelled,
                )
                .await;
            drop(parked);
            match result {
                Ending::Settled(Settlement::Login { allows: true, .. }, executor)
                    if executor != Some(id) =>
                {
                    continue
                }
                Ending::Settled(
                    Settlement::Login {
                        mut outcome,
                        allows,
                    },
                    _,
                ) => {
                    if allows {
                        if let Some(id) = outcome.elicitation_id.as_deref() {
                            if desk.claim_execution(id).is_err() {
                                let _ = desk.finish_execution(id, Execution::ApprovedNotExecuted, Some(crate::cingulate_client::wire::ExecutionReason::GrantStoreUnavailable));
                                return failed(CardEnding::DeliveryFailed);
                            }
                        }
                        outcome.taken_approval = true;
                    }
                    return LoginConsent::Ended(outcome);
                }
                Ending::TimedOut => {
                    return LoginConsent::Pending {
                        ask_id: waiter.ask_id.clone(),
                    }
                }
                _ => {
                    if *request.drain.borrow()
                        || !request.route.route_open()
                        || !request.route.conversation_open()
                    {
                        self.leave(waiter, true);
                    }
                    return failed(CardEnding::Withdrawn);
                }
            }
        }
    }

    /// Shorten how long a login call waits in place, for tests that cannot
    /// wait the production two minutes. The card's own lifetime is unchanged.
    #[doc(hidden)]
    pub fn set_login_park_limit(&self, park_limit: Duration) {
        lock(&self.state).login_park_limit = Some(park_limit);
    }

    /// How long a login call waits in place before `consent_pending`.
    pub fn login_park_limit(&self) -> Duration {
        lock(&self.state)
            .login_park_limit
            .unwrap_or(CONSENT_PARK_LIMIT)
    }

    /// Whether an answer to a login card is remembered for a retry, for
    /// tests of when one is dropped.
    #[doc(hidden)]
    pub fn remembers_login_answer(&self) -> bool {
        !lock(&self.state).login_answers.is_empty()
    }

    /// Wait for the desk's answer or the elected caller's stored effect.
    #[allow(clippy::too_many_arguments)]
    async fn wait_on_card(
        &self,
        desk: &ConsentDesk,
        session: &mut DeskSession<'_>,
        waiter: &Waiter<'_>,
        settled: SettledWatch,
        mut completion: watch::Receiver<bool>,
        park: Duration,
        cancelled: impl std::future::Future<Output = LetGo>,
    ) -> Ending {
        let park_end = tokio::time::Instant::now() + park;
        let result = tokio::select! {
            result = session.park(&waiter.ask_id, park, cancelled) => Some(result),
            completed = async { completion.wait_for(|done| *done).await.is_ok() } => {
                if !completed {
                    if desk.raised(&waiter.ask_id).is_some() { let _ = session.withdraw(&waiter.ask_id).await; }
                    return Ending::Withdrawn;
                }
                None
            }
        };
        match result {
            Some(InCall::Settled(ending)) => {
                if let Ok(Some(signal)) = self.settle(&waiter.ask_id, &ending, Some(waiter.id)) {
                    // No waiting call may use the grant before the desk knows it was applied.
                    let _ = desk.mark_applied(&waiter.ask_id);
                    signal.send_replace(true);
                }
                if !*completion.borrow()
                    && tokio::time::timeout_at(park_end, completion.wait_for(|done| *done))
                        .await
                        .is_err()
                {
                    let _ = session.detach(&waiter.ask_id).await;
                    return Ending::TimedOut;
                }
            }
            Some(InCall::Pending { .. }) => return Ending::TimedOut,
            Some(InCall::Cancelled) => return Ending::Cancelled,
            Some(InCall::RouteClosed) => return Ending::Cancelled,
            None => {}
        }
        let result = settled.borrow().clone();
        result.map_or(Ending::Withdrawn, |(settlement, executor)| {
            Ending::Settled(settlement, executor)
        })
    }

    /// Join a card or raise it once, recording its returned id before awaiting.
    #[allow(clippy::too_many_arguments)]
    async fn join_or_ask(
        self: &Arc<Self>,
        caller: &GrantCaller,
        need: &GrantNeed,
        carrier: &Arc<dyn QuestionCarrier>,
        live: &LiveCall,
        session: &mut DeskSession<'_>,
        identity: Option<AppIdentity>,
        signature_changed: bool,
    ) -> Result<(Waiter<'_>, SettledWatch, watch::Receiver<bool>), ConsentRefusal> {
        let _creation = self.creation.lock().await;
        let subject = Subject::of(caller, need);
        if let Some((ask_id, id, settled, completion)) = join_open(&mut lock(&self.state), &subject)
        {
            return Ok((
                Waiter {
                    grants: self,
                    ask_id,
                    id,
                },
                settled,
                completion,
            ));
        }
        let offered = self.offered_choices(caller, need, identity.as_ref());
        let body = question_body(need, &offered, signature_changed, identity.as_ref());
        crate::permission_cards::require_grant_choice(&body, caller.holder.as_ref()).map_err(
            |error| ConsentRefusal::Unavailable {
                reason: error.reason(),
                remedy: error.remedy(),
            },
        )?;
        let kind = match need {
            GrantNeed::App { .. } => CardKind::AppControl,
            GrantNeed::Takeover => CardKind::Takeover,
        };
        let deadline = match need {
            GrantNeed::App { .. } => APP_QUESTION_DEADLINE,
            GrantNeed::Takeover => TAKEOVER_QUESTION_DEADLINE,
        };
        let desk = carrier.desk();
        let key = subject.desk_subject();
        lock(&self.state).creating.insert(key.clone());
        let _raising = Raising {
            grants: self,
            subject: key.clone(),
        };
        let ask_id = if let Some(card) = desk.open_card_for(live.session(), &key) {
            card.elicitation_id
        } else {
            let card = consent_request(
                kind,
                &body,
                deadline,
                carrier.requester_ref().as_deref(),
                None,
                None,
            )
            .map_err(|_| card_refusal(&CardEnding::DeliveryFailed))?;
            (if crate::codemode::active() {
                session.raise_detached(card, &key).await
            } else {
                session.raise(card, &key).await
            })
            .map_err(|ending| card_refusal(&ending))?
        };
        let (settled_tx, settled) = watch::channel(None);
        let (completion_tx, completion) = watch::channel(false);
        let mut state = lock(&self.state);
        state.questions.insert(
            ask_id.clone(),
            OpenQuestion {
                holder: caller.holder.clone(),
                subject: subject.clone(),
                offered,
                identity,
                parked: BTreeSet::from([0]),
                next_waiter: 1,
                settled: settled_tx,
                completion: Arc::new(completion_tx),
                login: None,
            },
        );
        state.open_by_subject.insert(subject, ask_id.clone());
        Ok((
            Waiter {
                grants: self,
                ask_id,
                id: 0,
            },
            settled,
            completion,
        ))
    }

    /// Elect the holder or drain by removing the pending record before writing.
    fn settle(
        &self,
        ask_id: &str,
        ending: &CardEnding,
        executor: Option<u64>,
    ) -> Result<Option<Arc<watch::Sender<bool>>>, ApplyFailed> {
        let open = {
            let mut state = lock(&self.state);
            if state
                .applying
                .get(ask_id)
                .is_some_and(|question| !*question.completion.borrow())
            {
                return Err(ApplyFailed(
                    "the elected caller is still storing the effect".into(),
                ));
            }
            let Some(question) = state.questions.remove(ask_id) else {
                return Ok(None);
            };
            let open = AnsweredQuestion {
                holder: question.holder.clone(),
                card_ref: ask_id.to_string(),
                subject: question.subject.clone(),
                offered: question.offered.clone(),
                identity: question.identity.clone(),
            };
            state.applying.insert(ask_id.to_string(), question);
            open
        };
        let settlement = if matches!(open.subject, Subject::Login { .. }) {
            Settlement::Login {
                outcome: LoginAnswer {
                    ending: ending.clone(),
                    elicitation_id: Some(ask_id.to_string()),
                    taken_approval: false,
                },
                allows: matches!(ending, CardEnding::Granted { .. }),
            }
        } else {
            self.apply_answer(&open, ending)
        };
        let mut state = lock(&self.state);
        let Some(question) = state.applying.get(ask_id) else {
            return Ok(None);
        };
        let completion = Arc::clone(&question.completion);
        if let (Some(card), CardEnding::Declined { choice_id }) = (&question.login, ending) {
            if card.decline.as_deref() == Some(choice_id) {
                state.login_answers.insert(
                    open.subject.clone(),
                    RememberedLoginAnswer {
                        answer: LoginAnswer {
                            ending: ending.clone(),
                            elicitation_id: Some(ask_id.to_string()),
                            taken_approval: false,
                        },
                    },
                );
            }
        }
        state
            .applying
            .get(ask_id)
            .unwrap()
            .settled
            .send_replace(Some((settlement, executor)));
        Ok(Some(completion))
    }

    fn apply_answer(&self, open: &AnsweredQuestion, outcome: &CardEnding) -> Settlement {
        let choice_id = match outcome {
            CardEnding::Granted { choice_id } => choice_id,
            CardEnding::Declined { choice_id } if choice_id == DENY => choice_id,
            CardEnding::Declined { .. } => {
                return Settlement::Ended {
                    reason: "unrecognized_answer",
                    remedy: "The answer did not name an offered granting option; retry this call.",
                }
            }
            CardEnding::NoAnswer => {
                return Settlement::Ended {
                    reason: "no_answer",
                    remedy: "The person did not answer in time; retry this call to ask again.",
                }
            }
            CardEnding::NotPutToAnyone => {
                return Settlement::Ended {
                    reason: "not_put_to_anyone",
                    // Not "retry": the question reached no person, and the
                    // next one goes the same way until the consent route can
                    // reach someone, so a retry loops.
                    remedy: "Nobody could be asked: the question was shown to no one, and the next call's question reaches no one either until the caller's consent route can put it to a person.",
                };
            }
            CardEnding::DeliveryFailed => {
                return Settlement::Ended {
                    reason: "undeliverable",
                    remedy: "The question could not be sent; retry this call.",
                }
            }
            CardEnding::Withdrawn => {
                return Settlement::Ended {
                    reason: "question_withdrawn",
                    remedy: "retry this call to ask again",
                }
            }
            CardEnding::NoCard(why) => {
                return Settlement::Ended {
                    reason: why.reason().unwrap_or("cancelled"),
                    remedy: why.remedy().unwrap_or("retry this call"),
                }
            }
        };
        // A choice not offered on the consent card is not consent,
        // including a forged permanent choice in a worker's answer.
        let decision = open
            .offered
            .iter()
            .copied()
            .find(|offered| *offered == choice_id);
        match decision {
            Some(ALLOW_ONCE) => Settlement::Once,
            Some(ALLOW_30M) | Some(ALLOW_ALWAYS) | Some(COMPUTER_30M) | Some(COMPUTER_ALWAYS) => match self
                .write_card_answer(open, choice_id)
            {
                Ok(()) => Settlement::Allowed {
                    persisted: matches!(choice_id.as_str(), ALLOW_ALWAYS | COMPUTER_ALWAYS).then_some(Ok(())),
                },
                Err(_) => Settlement::Ended {
                    reason: "grant_not_recorded",
                    remedy:
                        "the permission could not be stored; retry after repairing the grant store",
                },
            },
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

    /// A refusal suppresses repeated questions in this conversation, without
    /// changing the holder's independently revocable grants.
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
            Subject::Login { .. } => {}
        }
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
    /// Remembered refusals are cleared; agent grants are unchanged. Held cards
    /// are withdrawn by their callers; detached cards stay answerable until scope revocation.
    pub fn end_conversation(&self, conversation_key: &str) {
        let mut state = lock(&self.state);
        state
            .conversation_app_denies
            .retain(|(conversation, _)| conversation != conversation_key);
        state.takeover_denies.remove(conversation_key);
        state
            .login_answers
            .retain(|subject, _| subject.conversation_key() != conversation_key);
        let asked: Vec<String> = state
            .questions
            .iter()
            .filter(|(_, question)| {
                question.subject.conversation_key() == conversation_key
                    && !question.parked.is_empty()
            })
            .map(|(ask_id, _)| ask_id.clone())
            .collect();
        for ask_id in asked {
            if let Some(question) = state.questions.remove(&ask_id) {
                withdraw_question(&mut state, &ask_id, question);
            }
        }
    }

    /// Forget pending memory records when the session scope is revoked.
    pub(crate) fn forget_conversation_questions(&self, conversation_key: &str) {
        let mut state = lock(&self.state);
        state
            .questions
            .retain(|_, question| question.subject.conversation_key() != conversation_key);
        state
            .applying
            .retain(|_, question| question.subject.conversation_key() != conversation_key);
        state
            .open_by_subject
            .retain(|subject, _| subject.conversation_key() != conversation_key);
    }

    /// Close one open question, so an answer that arrives afterwards grants
    /// nothing. Returns whether it was open.
    ///
    /// For a call that already replied `consent_pending` and is being
    /// withdrawn: no call waits on the question any more, so closing it strands
    /// nobody.
    pub fn withdraw_question_by_id(&self, ask_id: &str) -> bool {
        let mut state = lock(&self.state);
        let Some(question) = state.questions.remove(ask_id) else {
            return false;
        };
        withdraw_question(&mut state, ask_id, question);
        true
    }

    /// Whether a question is still open, for callers and tests that need to
    /// know if a late answer would still be applied.
    pub fn question_open(&self, ask_id: &str) -> bool {
        lock(&self.state).questions.contains_key(ask_id)
    }

    /// List local, unexpired permanent app rows held by heads. Temporary and
    /// worker rows belong to the unified permissions inventory instead.
    pub fn list(&self) -> Value {
        self.list_agent_app_grants()
    }

    /// A dry run and a real revoke use the same local permanent-app predicate.
    pub fn revoke(&self, grantee: &str, bundle_identity: &str, dry_run: bool) -> Value {
        self.revoke_agent_app_grants(grantee, bundle_identity, dry_run)
    }
}

/// Subscribe before awaiting so a competing holder or drain can finish first.
fn join_open(
    state: &mut GrantState,
    subject: &Subject,
) -> Option<(String, u64, SettledWatch, watch::Receiver<bool>)> {
    let ask_id = state.open_by_subject.get(subject).cloned()?;
    if state
        .applying
        .get(&ask_id)
        .is_some_and(|question| *question.completion.borrow())
    {
        state.applying.remove(&ask_id);
        state.open_by_subject.remove(subject);
        return None;
    }
    let question = match state.questions.get_mut(&ask_id) {
        Some(question) => question,
        None => state.applying.get_mut(&ask_id)?,
    };
    let id = question.next_waiter;
    question.next_waiter += 1;
    question.parked.insert(id);
    Some((
        ask_id,
        id,
        question.settled.subscribe(),
        question.completion.subscribe(),
    ))
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
}

/// Display effects describe consent; settlement still validates the original offered words.
///
/// `identity` is the code-signing identity the grant will be recorded
/// against, read for the process the call resolved.
pub(crate) fn question_body(
    need: &GrantNeed,
    offered: &[&'static str],
    signature_changed: bool,
    identity: Option<&AppIdentity>,
) -> Value {
    use crate::consent_card::*;
    let (title, prompt, target, deadline) = match need {
        GrantNeed::App { display_name, .. } => (
            format!("Allow access to {display_name}?"),
            if signature_changed {
                "This application's code signature has changed since it was approved. Covers reading and acting inside this application.".to_string()
            } else {
                "Covers reading and acting inside this application.".to_string()
            },
            Target { kind: TargetKind::App, label: display_name.clone() }, APP_QUESTION_DEADLINE,
        ),
        GrantNeed::Takeover => (
            "Allow control of your mouse and keyboard?".to_string(),
            "Takeover lets the agent bring apps to the front, type into them, and move your real mouse pointer. It can reach every application on the screen. Touch your mouse or keyboard to stop it.".to_string(),
            Target { kind: TargetKind::Machine, label: "your mouse and keyboard".into() }, TAKEOVER_QUESTION_DEADLINE,
        ),
    };
    let grants = cards::render_options(need, offered);
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
        grants,
        decline: ConsentOption::decline(DENY, "Don't allow"),
        expires_in: deadline,
        material_damage: true,
        // Both kinds hold the call that needs the grant open while the person
        // decides (up to CONSENT_PARK_LIMIT), so the agent is blocked on it.
        urgency: Urgency::High,
        scope: grant_scope(need, identity),
        duration: None,
    }
    .render()
}

/// What an answer grants, named by the values the grant is recorded under.
///
/// An app grant is keyed on the bundle identity and is only honoured for a
/// process that still satisfies the signing identity read at ask time, so the
/// signer is named too: `team_id` as an "always" record stores it, or
/// `apple_anchored: true` for Apple's own applications, which have no Team ID.
/// The display name stays in the card's label.
/// A takeover grant hands over the machine's real pointer and keyboard.
fn grant_scope(need: &GrantNeed, identity: Option<&AppIdentity>) -> crate::consent_card::Scope {
    use crate::consent_card::Scope;
    match need {
        GrantNeed::App {
            bundle_identity, ..
        } => {
            let scope = Scope::new().with("app", bundle_identity.as_str());
            match identity {
                Some(AppIdentity {
                    team_id: Some(team_id),
                    ..
                }) => scope.with("team_id", team_id.as_str()),
                Some(identity) if identity.apple_anchored => scope.with("apple_anchored", true),
                _ => scope,
            }
        }
        GrantNeed::Takeover => Scope::new().with("takeover", "machine"),
    }
}

/// What the answer to a question is applied against, copied out so the store
/// can be written without holding the grant state.
struct AnsweredQuestion {
    holder: Option<crate::agent_grants::GrantHolder>,
    card_ref: String,
    subject: Subject,
    offered: Vec<&'static str>,
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
    fn takeover_card_has_a_decline_and_no_conversation_duration() {
        let body = question_body(
            &GrantNeed::Takeover,
            &[ALLOW_ONCE, COMPUTER_30M, COMPUTER_ALWAYS, DENY],
            false,
            None,
        );
        crate::consent_card::assert_contract(
            &body,
            &["allow_once", "computer_30m", "computer_always", "deny"],
            "deny",
        );
        assert!(body["params"].get("duration").is_none());
        assert_eq!(body["params"]["expires_in_ms"], 300_000);
        assert_eq!(body["params"]["urgency"], "high");
        assert_eq!(body["params"]["scope"], json!({"takeover": "machine"}));
    }
}

impl ConsentEffects for ComputerGrants {
    fn has_pending(&self, card: &RaisedCard) -> bool {
        let state = lock(&self.state);
        state.creating.contains(&card.subject)
            || state.questions.contains_key(&card.elicitation_id)
            || state.applying.contains_key(&card.elicitation_id)
    }

    fn apply(
        &self,
        card: &RaisedCard,
        _record: &Record,
        ending: &CardEnding,
    ) -> Result<AppliedSettlement, ApplyFailed> {
        if lock(&self.state).creating.contains(&card.subject) {
            return Err(ApplyFailed(
                "the raising call is still recording the question".into(),
            ));
        }
        let completion = self.settle(&card.elicitation_id, ending, None)?;
        Ok(AppliedSettlement {
            // A late login answer can be recorded from its durable card subject
            // even when the in-memory question was lost on restart.
            effect: if completion.is_some() || card.kind.single_use() {
                Apply::Applied
            } else {
                Apply::NoRecord
            },
            completion,
        })
    }
}

fn no_card(why: NoCard) -> ConsentRefusal {
    ConsentRefusal::Unavailable {
        reason: why.reason().unwrap_or("cancelled"),
        remedy: why.remedy().unwrap_or("retry this call"),
    }
}

fn card_refusal(ending: &CardEnding) -> ConsentRefusal {
    let (reason, remedy) = match ending {
        CardEnding::NoCard(why) => return no_card(*why),
        CardEnding::NoAnswer => (
            "no_answer",
            "The person did not answer in time; retry this call to ask again.",
        ),
        CardEnding::NotPutToAnyone => (
            "not_put_to_anyone",
            "Nobody could be asked; repair the consent answering surface before retrying.",
        ),
        CardEnding::DeliveryFailed => (
            "undeliverable",
            "The question could not be sent; retry this call.",
        ),
        CardEnding::Withdrawn => ("question_withdrawn", "retry this call to ask again"),
        CardEnding::Granted { .. } | CardEnding::Declined { .. } => (
            "unrecognized_answer",
            "The answer could not be read; retry this call to ask again.",
        ),
    };
    ConsentRefusal::Unavailable { reason, remedy }
}

impl ComputerGrants {
    pub(crate) fn register_drain(self: &Arc<Self>, drain: &crate::consent_drain::ConsentDrain) {
        for kind in [
            CardKind::AppControl,
            CardKind::Takeover,
            CardKind::LoginImport,
            CardKind::LoginCapture,
        ] {
            drain.register(kind, Arc::clone(self) as Arc<dyn ConsentEffects>);
        }
    }
}

pub(crate) fn admits_consent(facts: &crate::AcceptedBindFacts) -> bool {
    facts.admits_session_calls()
        && facts.agent_project_id_attested
        && facts.flow_id.is_none()
        && facts.scope.is_some()
}

pub(crate) async fn report_login_execution(
    carrier: &Arc<dyn QuestionCarrier>,
    answer: &LoginAnswer,
    reply: &Value,
    success: &str,
) {
    if !answer.taken_approval {
        return;
    }
    let Some(id) = answer.elicitation_id.as_deref() else {
        return;
    };
    let desk = carrier.desk();
    let (execution, reason) = login_execution_outcome(reply, success);
    if desk.finish_execution(id, execution, reason).is_err() {
        return;
    }
    let Ok(live) = carrier.live() else {
        return;
    };
    // Opening the live route retries the durable report, including a send whose
    // previous response was lost. No autonomous route is opened after a call ends.
    let _ = desk.session(&live).await;
}

pub(crate) fn execution_refusal_reason(
    reply: &Value,
) -> Option<crate::cingulate_client::wire::ExecutionReason> {
    use crate::cingulate_client::wire::ExecutionReason;
    let reason = reply["reason"]
        .as_str()
        .or_else(|| reply["detail"]["reason"].as_str())
        .unwrap_or_default();
    let outcome = reply["outcome"].as_str().unwrap_or_default();
    Some(
        if matches!(reason, "session_ended" | "scope_ended")
            || matches!(outcome, "session_ended" | "route_closed" | "cancelled")
        {
            ExecutionReason::SessionEnded
        } else if matches!(
            reason,
            "target_gone" | "app_not_found" | "profile_not_found"
        ) || matches!(
            outcome,
            "target_gone" | "app_not_found" | "profile_not_found"
        ) {
            ExecutionReason::TargetGone
        } else if reason.starts_with("grant_store_")
            || matches!(
                reason,
                "grant_not_recorded" | "vault_unreachable" | "vault_store_unavailable"
            )
        {
            ExecutionReason::GrantStoreUnavailable
        } else {
            ExecutionReason::RefusedAtDispatch
        },
    )
}

pub(crate) fn login_execution_outcome(
    reply: &Value,
    success: &str,
) -> (
    Execution,
    Option<crate::cingulate_client::wire::ExecutionReason>,
) {
    let outcome = reply["outcome"].as_str().unwrap_or_default();
    let reason = reply["reason"].as_str().unwrap_or_default();
    let execution = if outcome == success {
        Execution::Executed
    } else if matches!(outcome, "transfer_failed" | "internal_failure")
        || reason == "vault_call_failed"
        || (reason == "vault_deadline_exceeded"
            && reply["remedy"]
                .as_str()
                .is_some_and(|text| text.contains("may or may not")))
    {
        Execution::OutcomeUnknown
    } else {
        Execution::ApprovedNotExecuted
    };
    (
        execution,
        (execution == Execution::ApprovedNotExecuted)
            .then(|| execution_refusal_reason(reply))
            .flatten(),
    )
}

#[cfg(test)]
pub(crate) mod tests;

mod agent_enforcement;
mod cards;

/// While a newly raised card is being added to the in-memory pending map,
/// a concurrent answer drain must not mistake it for a record lost on restart.
struct Raising<'a> {
    grants: &'a ComputerGrants,
    subject: String,
}
impl Drop for Raising<'_> {
    fn drop(&mut self) {
        lock(&self.grants.state).creating.remove(&self.subject);
    }
}
