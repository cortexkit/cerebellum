//! Standing browser site grants, held per agent rather than per conversation.
//!
//! A browser site grant made from the site-access card normally lasts for the
//! conversation it was given in (see [`crate::authorization`]). The same card
//! can also offer three standing answers, kept here:
//!
//! * "Always allow": one registrable domain on default-port HTTPS, or an
//!   exact origin when domain scope is unavailable, at the requested ceiling,
//!   with the hazards the card disclosed.
//! * "Allow on all sites for 10 minutes" and "Always allow on all sites": every
//!   public origin, at a ceiling of at most [`MAX_ALL_SITES_LEVEL`], with no
//!   hazard at all, so no sign-in, payment or unverified form is ever covered.
//!
//! Rows are keyed by the daemon-attested `agentProjectId` of the agent the
//! person answered for, never by a name a caller supplies, and are consulted
//! only for a session attested as that same agent.
//!
//! The store follows the always-allow app store in [`crate::computer_grants`]:
//! one small versioned JSON file under the journal data home, replaced
//! atomically, raising its own format floor before every write, and bound to
//! this machine's hardware identity so that a backup restored onto another
//! machine grants nothing there. A file that cannot be read withholds every
//! standing grant and is never written over.

use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::authorization::{HazardClass, Severity, MUTATE_DURABLE, MUTATE_REVERSIBLE, OBSERVE};
use crate::classification::canonical_grant_origin;

/// The file name of the standing browser grant store, under the journal data
/// home beside the always-allow app store.
pub const STANDING_GRANT_STORE_FILE: &str = "browser_standing_grants.json";

/// The highest store format this build reads. Until a domain row is recorded,
/// writes stay in version 1 so an older binary can still read the store.
pub const STANDING_GRANT_STORE_VERSION: u64 = 2;

/// The store's format, as the format floor and staging name it.
pub const STANDING_GRANT_STORE_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new(
        "browser-standing-grants",
        STANDING_GRANT_STORE_VERSION,
    );

/// How long the "all sites for 10 minutes" answer lasts.
pub const ALL_SITES_SHORT_GRANT_MS: u64 = 30 * 60 * 1000;

/// The highest ceiling an all-sites row may carry: changes that can be undone.
/// Lasting changes are only ever granted for a named origin.
pub const MAX_ALL_SITES_LEVEL: u8 = MUTATE_REVERSIBLE;

/// What a standing row covers: an origin, a registrable domain, or all public sites.
///
/// On the wire `{"origin": "https://example.com"}`, `{"domain": "example.com"}`,
/// or `{"all_sites": true}`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(try_from = "SubjectWire", into = "SubjectWire")]
pub enum StandingSubject {
    Origin(String),
    Domain(String),
    AllSites,
}

impl StandingSubject {
    pub fn to_value(&self) -> Value {
        serde_json::to_value(self).expect("a subject serializes")
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    origin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    all_sites: Option<bool>,
}

impl TryFrom<SubjectWire> for StandingSubject {
    type Error = String;

    fn try_from(wire: SubjectWire) -> Result<Self, Self::Error> {
        match (wire.origin, wire.domain, wire.all_sites) {
            (Some(origin), None, None) => {
                if canonical_grant_origin(&origin).as_deref() != Some(origin.as_str()) {
                    return Err(format!(
                        "subject origin `{origin}` is not a canonical origin"
                    ));
                }
                Ok(Self::Origin(origin))
            }
            (None, Some(domain), None)
                if domain_scope(&format!("https://{domain}")).as_deref()
                    == Some(domain.as_str()) =>
            {
                Ok(Self::Domain(domain))
            }
            (None, None, Some(true)) => Ok(Self::AllSites),
            _ => Err("a subject names exactly one origin, or all_sites: true".to_string()),
        }
    }
}

impl From<StandingSubject> for SubjectWire {
    fn from(subject: StandingSubject) -> Self {
        match subject {
            StandingSubject::Origin(origin) => Self {
                origin: Some(origin),
                domain: None,
                all_sites: None,
            },
            StandingSubject::Domain(domain) => Self {
                origin: None,
                domain: Some(domain),
                all_sites: None,
            },
            StandingSubject::AllSites => Self {
                origin: None,
                domain: None,
                all_sites: Some(true),
            },
        }
    }
}

/// One standing answer, as written to the store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingBrowserGrant {
    /// The daemon-attested `agentProjectId` the person answered for.
    pub agent_id: String,
    pub subject: StandingSubject,
    /// The highest severity tier the row covers.
    pub max_level: u8,
    /// The form hazards the card disclosed. Always empty on an all-sites row.
    pub hazards: Vec<HazardClass>,
    /// When the row stops covering anything, in wall-clock milliseconds since
    /// the Unix epoch; `null` for a row that lasts until revoked.
    pub expires_at_ms: Option<u64>,
    pub granted_at_ms: u64,
    /// The `elicitation_id` of the answered card, as the vault deposit records
    /// its consent.
    pub consent_ref: String,
    /// When the row was revoked; a revoked row covers nothing and is kept so
    /// that what was granted, and when it was withdrawn, stays visible.
    pub revoked_at_ms: Option<u64>,
    /// The hardware identity of the machine the answer was given on. A row
    /// naming any other machine covers nothing here.
    pub machine_uuid: String,
}

impl StandingBrowserGrant {
    /// The ceiling this row grants, with the credential and financial flags
    /// set exactly as a conversation grant minted from the same disclosed
    /// hazards sets them.
    pub fn severity(&self) -> Severity {
        let has = |hazard| self.hazards.contains(&hazard);
        Severity::new(
            self.max_level,
            has(HazardClass::CredentialFormSubmit) || has(HazardClass::UnverifiedFormContents),
            has(HazardClass::FinancialFormSubmit) || has(HazardClass::UnverifiedFormContents),
        )
    }

    /// Whether the row is still in force at `now_ms`.
    pub fn is_live(&self, now_ms: u64) -> bool {
        self.revoked_at_ms.is_none() && self.expires_at_ms.is_none_or(|expires| now_ms < expires)
    }

    /// A stable name for the row, used as the identity of an authorization
    /// decision made under it so the decision can be re-checked at commit.
    pub fn key(&self) -> String {
        let subject = match &self.subject {
            StandingSubject::Origin(origin) => origin.as_str(),
            StandingSubject::Domain(domain) => domain.as_str(),
            StandingSubject::AllSites => "*",
        };
        format!("{}|{}|{}", self.consent_ref, subject, self.granted_at_ms)
    }

    /// The rules every row must satisfy. A file holding a row that breaks one
    /// is treated as corrupt rather than partly honoured.
    pub(crate) fn check(&self) -> Result<(), String> {
        if self.agent_id.is_empty() || self.consent_ref.is_empty() || self.machine_uuid.is_empty() {
            return Err("a row needs an agent_id, a consent_ref and a machine_uuid".into());
        }
        if !(OBSERVE..=MUTATE_DURABLE).contains(&self.max_level) {
            return Err(format!(
                "max_level {} is not a grantable tier",
                self.max_level
            ));
        }
        if let StandingSubject::Domain(domain) = &self.subject {
            if domain_scope(&format!("https://{domain}")).as_deref() != Some(domain.as_str()) {
                return Err("invalid registrable domain subject".into());
            }
        }
        let unique: BTreeSet<_> = self.hazards.iter().collect();
        if unique.len() != self.hazards.len() {
            return Err("a row lists a hazard twice".into());
        }
        if self.subject == StandingSubject::AllSites
            && (!self.hazards.is_empty() || self.max_level > MAX_ALL_SITES_LEVEL)
        {
            return Err("an all-sites row carries a hazard or a ceiling above 3".into());
        }
        Ok(())
    }

    /// The row as the listing shows it.
    pub fn describe(&self) -> Value {
        json!({
            "agent_id": self.agent_id,
            "subject": self.subject.to_value(),
            "max_level": self.max_level,
            "hazards": self.hazards,
            "expires_at_ms": self.expires_at_ms,
            "granted_at_ms": self.granted_at_ms,
            "consent_ref": self.consent_ref,
            "revoked_at_ms": self.revoked_at_ms,
        })
    }
}

/// The whole store, loaded and saved in one piece.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StandingGrantStoreState {
    pub version: u64,
    pub grants: Vec<StandingBrowserGrant>,
}

impl StandingGrantStoreState {
    pub(crate) fn check(&self) -> Result<(), StandingGrantStoreError> {
        if !(1..=STANDING_GRANT_STORE_VERSION).contains(&self.version) {
            return Err(StandingGrantStoreError::UnknownVersion {
                found: self.version,
            });
        }
        if self.version == 1
            && self
                .grants
                .iter()
                .any(|row| matches!(row.subject, StandingSubject::Domain(_)))
        {
            return Err(StandingGrantStoreError::Corrupt {
                detail: "domain rows require version 2".into(),
            });
        }
        for row in &self.grants {
            row.check()
                .map_err(|detail| StandingGrantStoreError::Corrupt { detail })?;
        }
        Ok(())
    }
}

impl Default for StandingGrantStoreState {
    fn default() -> Self {
        Self {
            version: 1,
            grants: Vec::new(),
        }
    }
}

/// Why the store could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StandingGrantStoreError {
    /// The file exists and could not be read.
    Unreadable { detail: String },
    /// The file was read and is not a store this build understands.
    Corrupt { detail: String },
    /// The file names a format version this build does not read.
    UnknownVersion { found: u64 },
    /// Writing the file failed; the previous file is left as it was.
    WriteFailed { detail: String },
    /// This host offers no machine identity to bind a row to.
    NoMachineIdentity,
}

impl StandingGrantStoreError {
    /// The one-word code a reply carries.
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unreadable { .. } => "standing_grant_store_unreadable",
            Self::Corrupt { .. } => "standing_grant_store_corrupt",
            Self::UnknownVersion { .. } => "standing_grant_store_version_unknown",
            Self::WriteFailed { .. } => "standing_grant_store_write_failed",
            Self::NoMachineIdentity => "machine_identity_unavailable",
        }
    }
}

impl std::fmt::Display for StandingGrantStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { detail } => {
                write!(
                    formatter,
                    "the standing browser grant store is unreadable: {detail}"
                )
            }
            Self::Corrupt { detail } => {
                write!(
                    formatter,
                    "the standing browser grant store is corrupt: {detail}"
                )
            }
            Self::UnknownVersion { found } => write!(
                formatter,
                "the standing browser grant store is version {found}; this build reads version \
                 {STANDING_GRANT_STORE_VERSION}"
            ),
            Self::WriteFailed { detail } => write!(
                formatter,
                "the standing browser grant store could not be written: {detail}"
            ),
            Self::NoMachineIdentity => write!(
                formatter,
                "this host has no machine identity to bind a standing grant to"
            ),
        }
    }
}

/// Where standing grants are kept: whole-state load and save, so a second
/// store opened over the same binding reads what the first one saved, which
/// is how a module restart is modelled.
pub trait StandingGrantStorage: Send + Sync {
    /// Read the whole store. A store that was never written reads as empty.
    fn load(&self) -> Result<StandingGrantStoreState, StandingGrantStoreError>;
    /// Replace the whole store.
    fn save(&self, state: &StandingGrantStoreState) -> Result<(), StandingGrantStoreError>;
}

/// A store held in memory. Clones share state, so a clone models reopening the
/// store after a module restart.
#[derive(Debug, Clone, Default)]
pub struct InMemoryStandingGrantStorage {
    state: Arc<Mutex<StandingGrantStoreState>>,
}

impl InMemoryStandingGrantStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl StandingGrantStorage for InMemoryStandingGrantStorage {
    fn load(&self) -> Result<StandingGrantStoreState, StandingGrantStoreError> {
        Ok(lock(&self.state).clone())
    }

    fn save(&self, state: &StandingGrantStoreState) -> Result<(), StandingGrantStoreError> {
        *lock(&self.state) = state.clone();
        Ok(())
    }
}

/// The store as a JSON file, replaced atomically on every save.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilesystemStandingGrantStorage {
    path: PathBuf,
    floor: cerebellum_core::format_floor::FormatFloor,
}

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

impl FilesystemStandingGrantStorage {
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
    pub fn production() -> Result<Self, StandingGrantStoreError> {
        cerebellum_core::journal::journal_data_path(STANDING_GRANT_STORE_FILE)
            .map(Self::new)
            .map_err(|error| StandingGrantStoreError::Unreadable {
                detail: format!("{error:?}"),
            })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl StandingGrantStorage for FilesystemStandingGrantStorage {
    fn load(&self) -> Result<StandingGrantStoreState, StandingGrantStoreError> {
        let mut bytes = Vec::new();
        match File::open(&self.path) {
            Ok(mut file) => {
                file.read_to_end(&mut bytes).map_err(|error| {
                    StandingGrantStoreError::Unreadable {
                        detail: error.to_string(),
                    }
                })?;
            }
            // Never written: no standing answer has been given on this machine.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(StandingGrantStoreState::default())
            }
            Err(error) => {
                return Err(StandingGrantStoreError::Unreadable {
                    detail: error.to_string(),
                })
            }
        }
        let value: Value =
            serde_json::from_slice(&bytes).map_err(|error| StandingGrantStoreError::Corrupt {
                detail: error.to_string(),
            })?;
        // The version is read before the rows, so a file from a newer build is
        // reported as a version this build does not read rather than as
        // corruption: the remedy differs (run the newer build, not repair).
        let Some(version) = value.get("version").and_then(Value::as_u64) else {
            return Err(StandingGrantStoreError::Corrupt {
                detail: "version is missing or is not an unsigned integer".to_string(),
            });
        };
        if !(1..=STANDING_GRANT_STORE_VERSION).contains(&version) {
            return Err(StandingGrantStoreError::UnknownVersion { found: version });
        }
        serde_json::from_value(value).map_err(|error| StandingGrantStoreError::Corrupt {
            detail: error.to_string(),
        })
    }

    fn save(&self, state: &StandingGrantStoreState) -> Result<(), StandingGrantStoreError> {
        let failed = |error: std::io::Error| StandingGrantStoreError::WriteFailed {
            detail: error.to_string(),
        };
        // Before anything is written: a store in this format on disk with no
        // floor naming it would let staging pass a build that cannot read it.
        self.floor
            .raise(cerebellum_core::format_floor::DurableFormat::new(
                STANDING_GRANT_STORE_FORMAT.name,
                state.version,
            ))
            .map_err(|error| StandingGrantStoreError::WriteFailed {
                detail: error.to_string(),
            })?;
        let bytes = serde_json::to_vec_pretty(state).map_err(|error| {
            StandingGrantStoreError::WriteFailed {
                detail: error.to_string(),
            }
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
            .unwrap_or_else(|| STANDING_GRANT_STORE_FILE.to_string());
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

/// The clock that stamps standing rows and decides when they expire, read as
/// wall-clock milliseconds since the Unix epoch.
///
/// A wall clock rather than the module's monotonic lease clock because a row
/// outlives the process: the lease clock's epoch is the module's start, so an
/// expiry stamped by one run would mean nothing to the next.
pub trait WallClock: Send + Sync {
    fn now_ms(&self) -> u64;
    fn subscribe(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        None
    }
}

/// The system's wall clock.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now_ms(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
            .unwrap_or(0)
    }
}

/// A wall clock that moves only when told to, for tests of expiry.
#[derive(Debug, Clone)]
pub struct ManualWallClock(Arc<AtomicU64>, tokio::sync::watch::Sender<u64>);

impl Default for ManualWallClock {
    fn default() -> Self {
        Self::at(0)
    }
}

impl ManualWallClock {
    pub fn at(now_ms: u64) -> Self {
        Self(
            Arc::new(AtomicU64::new(now_ms)),
            tokio::sync::watch::channel(now_ms).0,
        )
    }

    pub fn advance_ms(&self, by: u64) {
        self.0.fetch_add(by, Ordering::SeqCst);
        self.1.send_replace(self.0.load(Ordering::SeqCst));
    }
}

impl WallClock for ManualWallClock {
    fn subscribe(&self) -> Option<tokio::sync::watch::Receiver<u64>> {
        Some(self.1.subscribe())
    }
    fn now_ms(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Which standing rows a revocation removes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevokeTarget {
    /// Every standing browser row of the agent.
    Everything,
    /// The agent's row for one origin.
    Origin(String),
    /// The agent's row for one registrable domain.
    Domain(String),
    /// The agent's all-sites rows: both the thirty-minute row and the one that
    /// lasts until revoked.
    AllSites,
}

/// Every standing browser grant this module holds.
pub struct StandingBrowserGrants {
    storage: Arc<dyn StandingGrantStorage>,
    machine_uuid: Option<String>,
    rows: Mutex<Result<Vec<StandingBrowserGrant>, StandingGrantStoreError>>,
    version: AtomicU64,
    /// Held across a read-modify-write of the store, so two concurrent writes
    /// cannot each save a copy missing the other's row.
    writes: Mutex<()>,
    clock: Arc<dyn WallClock>,
}

impl std::fmt::Debug for StandingBrowserGrants {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StandingBrowserGrants")
            .field("machine_uuid", &self.machine_uuid)
            .field("rows", &*lock(&self.rows))
            .finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

impl StandingBrowserGrants {
    /// Open the grants over a store, reading it once.
    ///
    /// A store that cannot be read, or that holds a row breaking the rules in
    /// [`StandingBrowserGrant::check`], withholds every standing grant for the
    /// life of this module and is never saved over.
    pub fn open(storage: Arc<dyn StandingGrantStorage>, machine_uuid: Option<String>) -> Self {
        let mut version = 1;
        let rows = storage.load().and_then(|state| {
            version = state.version;
            state.check()?;
            Ok(state.grants)
        });
        Self {
            storage,
            machine_uuid,
            rows: Mutex::new(rows),
            version: AtomicU64::new(version),
            writes: Mutex::new(()),
            clock: Arc::new(SystemWallClock),
        }
    }

    /// Open the operator's store under the data home.
    pub fn open_durable(machine_uuid: Option<String>) -> Self {
        match FilesystemStandingGrantStorage::production() {
            Ok(storage) => Self::open(Arc::new(storage), machine_uuid),
            Err(error) => {
                let grants =
                    Self::open(Arc::new(InMemoryStandingGrantStorage::new()), machine_uuid);
                *lock(&grants.rows) = Err(error);
                grants
            }
        }
    }

    /// Grants held only in memory with no machine identity, so no standing
    /// answer is ever offered or stored. For tests and isolated planes.
    pub fn in_memory() -> Self {
        Self::open(Arc::new(InMemoryStandingGrantStorage::new()), None)
    }

    /// Stamp and expire rows by `clock` instead of the system wall clock.
    pub fn with_clock(mut self, clock: Arc<dyn WallClock>) -> Self {
        self.clock = clock;
        self
    }

    pub fn now_ms(&self) -> u64 {
        self.clock.now_ms()
    }

    /// Why the store could not be read, if it could not.
    pub fn store_error(&self) -> Option<StandingGrantStoreError> {
        lock(&self.rows).as_ref().err().cloned()
    }

    /// Whether a standing answer can be recorded here: a machine identity to
    /// bind it to, and a store that was read, so writing cannot overwrite one
    /// that could not be.
    pub fn can_record(&self) -> bool {
        self.machine_uuid.is_some() && lock(&self.rows).is_ok()
    }

    /// The live row of `agent_id` that covers an action needing `required` on
    /// `origin` with `required_hazards`, at `now_ms`.
    ///
    /// An origin row covers its own canonical origin when its ceiling and
    /// disclosed hazards cover the action. An all-sites row covers only a
    /// public origin, and only an action needing no hazard. Rows of another
    /// agent or another machine, revoked rows and expired rows cover nothing.
    pub fn covering_row(
        &self,
        agent_id: &str,
        origin: &str,
        required: Severity,
        required_hazards: &BTreeSet<HazardClass>,
        now_ms: u64,
    ) -> Option<StandingBrowserGrant> {
        let machine = self.machine_uuid.as_deref()?;
        if agent_id.is_empty() {
            return None;
        }
        let origin = canonical_grant_origin(origin)?;
        let rows = lock(&self.rows);
        let rows = rows.as_ref().ok()?;
        rows.iter()
            .filter(|row| row.agent_id == agent_id && row.machine_uuid == machine)
            .filter(|row| row.is_live(now_ms))
            .filter(|row| row.severity().covers(required))
            .filter(|row| {
                let listed: BTreeSet<HazardClass> = row.hazards.iter().copied().collect();
                required_hazards.is_subset(&listed)
            })
            .find(|row| match &row.subject {
                StandingSubject::Origin(granted) => *granted == origin,
                StandingSubject::Domain(domain) => domain_covers(domain, &origin),
                StandingSubject::AllSites => {
                    required_hazards.is_empty()
                        && row.max_level <= MAX_ALL_SITES_LEVEL
                        && origin_is_public(&origin)
                }
            })
            .cloned()
    }

    /// Whether the row named `key` (see [`StandingBrowserGrant::key`]) is
    /// still a live row of `agent_id` on this machine. Used at dispatch commit
    /// so a row revoked between authorization and commit admits nothing.
    pub fn row_is_live(&self, agent_id: &str, key: &str, now_ms: u64) -> bool {
        let Some(machine) = self.machine_uuid.as_deref() else {
            return false;
        };
        lock(&self.rows).as_ref().is_ok_and(|rows| {
            rows.iter().any(|row| {
                row.agent_id == agent_id
                    && row.machine_uuid == machine
                    && row.key() == key
                    && row.is_live(now_ms)
            })
        })
    }

    /// Keep history bounded while retaining the newest withdrawn rows in each scope.
    fn prune_non_live_rows(rows: &mut Vec<StandingBrowserGrant>) {
        let mut scopes = BTreeSet::new();
        for row in rows.iter() {
            scopes.insert((row.agent_id.clone(), row.subject.clone()));
        }
        for (agent_id, subject) in scopes {
            let mut old: Vec<_> = rows
                .iter()
                .enumerate()
                .filter(|(_, row)| {
                    row.agent_id == agent_id
                        && row.subject == subject
                        && row.revoked_at_ms.is_some()
                })
                .map(|(index, row)| (index, row.granted_at_ms))
                .collect();
            old.sort_by_key(|(_, granted_at)| std::cmp::Reverse(*granted_at));
            let mut remove: Vec<_> = old.into_iter().skip(20).map(|(index, _)| index).collect();
            remove.sort_unstable_by(|left, right| right.cmp(left));
            for index in remove {
                rows.remove(index);
            }
        }
    }

    /// Record a standing answer, lasting `lifetime_ms` from now or, with
    /// `None`, until revoked. A previous row of the same agent, subject, and
    /// machine is retained as revoked history, so the newest answer is in force.
    pub fn record(
        &self,
        agent_id: &str,
        subject: StandingSubject,
        max_level: u8,
        hazards: Vec<HazardClass>,
        lifetime_ms: Option<u64>,
        consent_ref: &str,
    ) -> Result<StandingBrowserGrant, StandingGrantStoreError> {
        let machine = self
            .machine_uuid
            .clone()
            .ok_or(StandingGrantStoreError::NoMachineIdentity)?;
        let granted_at_ms = self.now_ms();
        let row = StandingBrowserGrant {
            agent_id: agent_id.to_string(),
            subject,
            max_level,
            hazards,
            expires_at_ms: lifetime_ms.map(|lifetime| granted_at_ms.saturating_add(lifetime)),
            granted_at_ms,
            consent_ref: consent_ref.to_string(),
            revoked_at_ms: None,
            machine_uuid: machine.clone(),
        };
        row.check()
            .map_err(|detail| StandingGrantStoreError::Corrupt { detail })?;
        let _writing = lock(&self.writes);
        let mut rows = lock(&self.rows).clone()?;
        for previous in rows.iter_mut().filter(|previous| {
            previous.agent_id == row.agent_id
                && previous.subject == row.subject
                && previous.machine_uuid == machine
                && previous.is_live(granted_at_ms)
        }) {
            previous.revoked_at_ms = Some(granted_at_ms);
        }
        rows.push(row.clone());
        Self::prune_non_live_rows(&mut rows);
        self.storage.save(&StandingGrantStoreState {
            version: if self.version.load(Ordering::SeqCst) == 2
                || rows
                    .iter()
                    .any(|row| matches!(row.subject, StandingSubject::Domain(_)))
            {
                2
            } else {
                1
            },
            grants: rows.clone(),
        })?;
        if rows
            .iter()
            .any(|row| matches!(row.subject, StandingSubject::Domain(_)))
        {
            self.version.store(2, Ordering::SeqCst);
        }
        *lock(&self.rows) = Ok(rows);
        Ok(row)
    }

    /// Revoke the live rows of `agent_id` that `target` names. Only ever
    /// narrows what the agent holds; a revoked row stays in the file with the
    /// time it was revoked. The reply names how many rows were revoked.
    pub fn revoke(&self, agent_id: &str, target: &RevokeTarget) -> Value {
        let _writing = lock(&self.writes);
        let mut rows = match lock(&self.rows).clone() {
            Ok(rows) => rows,
            Err(error) => {
                return json!({
                    "outcome": "store_unavailable",
                    "revoked": 0,
                    "reason": error.reason_code(),
                    "remedy": "repair or remove the standing browser grant store file, then restart the module",
                })
            }
        };
        let now = self.now_ms();
        let mut revoked = 0_u64;
        for row in rows.iter_mut() {
            let named = row.agent_id == agent_id
                && match target {
                    RevokeTarget::Everything => true,
                    RevokeTarget::Origin(origin) => {
                        row.subject == StandingSubject::Origin(origin.clone())
                    }
                    RevokeTarget::Domain(domain) => {
                        row.subject == StandingSubject::Domain(domain.clone())
                    }
                    RevokeTarget::AllSites => row.subject == StandingSubject::AllSites,
                };
            if named && row.is_live(now) {
                row.revoked_at_ms = Some(now);
                revoked += 1;
            }
        }
        if revoked == 0 {
            return json!({"outcome": "nothing_to_revoke", "revoked": 0});
        }
        if let Err(error) = self.storage.save(&StandingGrantStoreState {
            version: if self.version.load(Ordering::SeqCst) == 2
                || rows
                    .iter()
                    .any(|row| matches!(row.subject, StandingSubject::Domain(_)))
            {
                2
            } else {
                1
            },
            grants: rows.clone(),
        }) {
            return json!({
                "outcome": "revoke_failed",
                "revoked": 0,
                "reason": error.reason_code(),
                "remedy": "the access is still in force; check the data directory is writable and retry",
            });
        }
        if rows
            .iter()
            .any(|row| matches!(row.subject, StandingSubject::Domain(_)))
        {
            self.version.store(2, Ordering::SeqCst);
        }
        *lock(&self.rows) = Ok(rows);
        json!({"outcome": "revoked", "revoked": revoked})
    }

    /// The live rows of `agent_id` on this machine, for the listing.
    pub fn live_rows(&self, agent_id: &str) -> Vec<StandingBrowserGrant> {
        let now = self.now_ms();
        let Some(machine) = self.machine_uuid.as_deref() else {
            return Vec::new();
        };
        lock(&self.rows).as_ref().map_or_else(
            |_| Vec::new(),
            |rows| {
                rows.iter()
                    .filter(|row| {
                        row.agent_id == agent_id && row.machine_uuid == machine && row.is_live(now)
                    })
                    .cloned()
                    .collect()
            },
        )
    }

    /// The store's state for a listing: `loaded`, or why it could not be read.
    pub fn store_state(&self) -> Value {
        match self.store_error() {
            None => json!({"state": "loaded"}),
            Some(error) => json!({
                "state": "unreadable",
                "reason": error.reason_code(),
                "detail": error.to_string(),
            }),
        }
    }
}

/// Whether a standing browser grant of `agent_id` covers an action needing
/// tier `level` on `origin` with `hazards`, at `now_ms`.
///
/// A plain lookup for callers that only need the yes or no, such as a check
/// of whether a browser action would raise a card. It answers for the agent
/// named, so the caller must have taken that name from an attested identity.
pub fn standing_browser_grant_covers(
    grants: &StandingBrowserGrants,
    agent_id: &str,
    origin: &str,
    level: u8,
    hazards: &BTreeSet<HazardClass>,
    now_ms: u64,
) -> bool {
    grants
        .covering_row(
            agent_id,
            origin,
            Severity::new(level, false, false),
            hazards,
            now_ms,
        )
        .is_some()
}

/// The registrable domain offered by a standing answer, only for public DNS
/// names on HTTPS's default port. Conversation answers do not use this scope.
pub fn domain_scope(origin: &str) -> Option<String> {
    let canonical = canonical_grant_origin(origin)?;
    let host = canonical.strip_prefix("https://")?;
    if host.contains(':') || host.parse::<IpAddr>().is_ok() || !origin_is_public(&canonical) {
        return None;
    }
    crate::public_suffix::registrable_domain(host)
}

pub fn always_subject(origin: String) -> StandingSubject {
    domain_scope(&origin).map_or(StandingSubject::Origin(origin), StandingSubject::Domain)
}

pub(crate) fn domain_covers(domain: &str, origin: &str) -> bool {
    let Some(host) = origin.strip_prefix("https://") else {
        return false;
    };
    !host.contains(':')
        && (host == domain
            || host
                .strip_suffix(domain)
                .is_some_and(|prefix| prefix.ends_with('.')))
}

/// Public-web access requires a registrable DNS name: single-label names can
/// resolve through local DNS search domains, and public suffixes alone do not
/// identify a site. Raw addresses and service ports are excluded too. An exact
/// per-site grant can still cover them. DNS resolution remains subject to the
/// connector's restricted-address policy.
pub fn origin_is_public(origin: &str) -> bool {
    let Some(canonical) = canonical_grant_origin(origin) else {
        return false;
    };
    let Some((_, authority)) = canonical.split_once("://") else {
        return false;
    };
    // Canonicalization removes the scheme's default port. Any remaining colon
    // is an unusual port or an IPv6 literal, neither covered by public access.
    if authority.contains(':') || authority.starts_with('[') {
        return false;
    }
    let host = authority.trim_end_matches('.');
    if host.is_empty()
        || host == "localhost"
        || host.ends_with(".localhost")
        || host == "local"
        || host.ends_with(".local")
        || host == "internal"
        || host.ends_with(".internal")
    {
        return false;
    }
    !host.rsplit('.').next().is_some_and(|label| {
        label.bytes().all(|byte| byte.is_ascii_digit())
            || label.starts_with("0x")
            || label.starts_with("0X")
    }) && crate::public_suffix::registrable_domain(host).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psl_not_last_two_labels() {
        assert_eq!(
            domain_scope("https://manager.example.co.uk"),
            Some("example.co.uk".into())
        );
    }

    #[test]
    fn private_suffix_tenants_do_not_share_domains() {
        assert_eq!(
            domain_scope("https://a.github.io"),
            Some("a.github.io".into())
        );
        assert_eq!(
            domain_scope("https://b.github.io"),
            Some("b.github.io".into())
        );
    }

    #[test]
    fn host_only_writes_keep_version_one_until_a_domain_is_recorded() {
        let storage = Arc::new(InMemoryStandingGrantStorage::new());
        let grants = StandingBrowserGrants::open(storage.clone(), Some("machine".into()));
        grants
            .record(
                "agent",
                StandingSubject::Origin("https://example.com".into()),
                2,
                vec![],
                None,
                "card",
            )
            .unwrap();
        assert_eq!(storage.load().unwrap().version, 1);
        grants
            .record(
                "agent",
                StandingSubject::Domain("example.com".into()),
                2,
                vec![],
                None,
                "domain-card",
            )
            .unwrap();
        assert_eq!(storage.load().unwrap().version, 2);
        grants.revoke("agent", &RevokeTarget::Domain("example.com".into()));
        assert_eq!(storage.load().unwrap().version, 2);
    }

    #[test]
    fn public_origins_are_told_apart_from_local_and_private_ones() {
        for public in ["https://example.com", "http://example.com"] {
            assert!(origin_is_public(public), "{public} should be public");
        }
        for local in [
            "https://example.com:8443",
            "http://93.184.216.34",
            "https://[2606:2800:220:1:248:1893:25c8:1946]",
            "https://device.local",
            "https://office.internal",
            "null",
            "file:///etc/passwd",
            "http://localhost",
            "http://localhost:3000",
            "http://app.localhost",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://[::1]",
            "http://10.1.2.3",
            "http://192.168.1.1",
            "http://172.16.0.9",
            "http://169.254.169.254",
            "http://[fe80::1]",
            "http://2130706433",
            "http://0x7f.1",
        ] {
            assert!(!origin_is_public(local), "{local} should not be public");
        }
    }

    #[test]
    fn public_dns_names_require_a_label_beyond_the_public_suffix() {
        for (origin, public) in [
            ("https://intranet", false),
            ("https://printer", false),
            ("https://router", false),
            ("https://intranet.", false),
            ("https://com", false),
            ("https://co.uk", false),
            ("https://github.io", false),
            ("https://example.123", false),
            ("https://example.123.", false),
            ("https://example.com", true),
            ("http://example.com", true),
            ("https://example.com.", true),
            ("https://foo.github.io", true),
            ("https://bbc.co.uk", true),
        ] {
            assert_eq!(origin_is_public(origin), public, "{origin}");
        }
    }

    #[test]
    fn a_subject_reads_and_writes_the_agreed_wire_shapes() {
        let origin = StandingSubject::Origin("https://example.com".into());
        assert_eq!(origin.to_value(), json!({"origin": "https://example.com"}));
        assert_eq!(
            StandingSubject::AllSites.to_value(),
            json!({"all_sites": true})
        );
        for refused in [
            json!({"all_sites": false}),
            json!({"origin": "https://example.com", "all_sites": true}),
            json!({"origin": "https://example.com/path"}),
            json!({}),
            json!({"origin": "https://example.com", "extra": 1}),
        ] {
            assert!(
                serde_json::from_value::<StandingSubject>(refused.clone()).is_err(),
                "{refused} was accepted"
            );
        }
    }
}
