//! Browser-profile registry and lifecycle boundary.
//!
//! This module is intentionally standalone and provides the browser-profile
//! registry and lifecycle boundary. Browser integration can declare it at the
//! crate root, while all filesystem operations begin from [`HeldManagedRoot`].
//! A caller-supplied string is never used directly as a profile path.

#![allow(clippy::result_large_err)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::error::Error;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// The immutable, bundled browser-profile registry artifact shipped with the crate.
pub const REGISTRY_ARTIFACT: &[u8] =
    include_bytes!("../../resources/ck-browser-profile-registry-v1.json");
pub const REGISTRY_ARTIFACT_ID: &str = "ck-browser-profile-registry";
pub const REGISTRY_ARTIFACT_REVISION: &str = "v1";
pub const REGISTRY_SCHEMA: &str = "ck-browser-profile-registry/v1";
/// The registry document's format, as the format floor and staging name it.
pub const REGISTRY_FORMAT: cerebellum_core::format_floor::DurableFormat =
    cerebellum_core::format_floor::DurableFormat::new(
        "profile-registry",
        cerebellum_core::format_floor::tag_version(REGISTRY_SCHEMA),
    );
const REGISTRY_FILE: &str = ".ck-browser-profile-registry-v1.json";
/// Append-only provenance for every re-identification of the managed root,
/// kept BESIDE the registry rather than inside it. A rebound root is trusted
/// from then on, so the rebind itself is the fact a later reader needs; a
/// record inside the registry would be replaced by the next rewrite of the
/// thing it describes. One JSON object per line, fsynced before the registry
/// starts trusting the new identity.
pub const PROFILE_ROOT_REBINDS_FILE: &str = ".ck-browser-profile-root-rebinds.jsonl";
/// The registry slot's sentinel, the only lock older builds know: they take
/// the slot by creating it exclusively and give it back by removing it.
const DURABLE_LOCK_FILE: &str = ".ck-browser-profile-durable-slot.lock";
/// A stable file this build holds an exclusive kernel lock on while it holds
/// the slot. It is never removed, and the kernel releases the lock when its
/// holder exits, however abruptly.
const DURABLE_KERNEL_LOCK_FILE: &str = ".ck-browser-profile-durable-slot.flock";
/// Where this build writes its sentinel before linking it into place, so the
/// sentinel never exists without its marker.
const DURABLE_LOCK_STAGING_FILE: &str = ".ck-browser-profile-durable-slot.lock.staged";
/// The contents of a sentinel created by a build that also holds the kernel
/// lock. An older build's sentinel is empty.
const DURABLE_LOCK_MARKER: &[u8] =
    b"held under the kernel lock on .ck-browser-profile-durable-slot.flock\n";
static UUID_COUNTER: AtomicU64 = AtomicU64::new(0);
const IMPLEMENTATION_MAGIC: &[u8] = b"ck-browser-profile-registry-implementation-bundle/v1\n";
const IMPLEMENTATION_SOURCE: &[u8] = include_bytes!("mod.rs");

/// The bundled registry artifact defines the complete set of valid profile states.
/// Values not listed by that artifact are rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileState {
    Provisional,
    Available,
    Attached,
    SealingTransition,
    Locked,
    Quarantined,
    Incomplete,
    Unavailable,
    Released,
    DeletionFailed,
}

impl ProfileState {
    fn legal_for(self, kind: ProfileKind) -> bool {
        kind == ProfileKind::Disposable || self != Self::DeletionFailed
    }
}

/// The two profile kinds whose records own filesystem directories: durable and disposable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileKind {
    Durable,
    Disposable,
}

/// The disposition supplied as a stamped fact. Validation checks the supplied
/// session-kind and disposition pair, but does not derive the disposition locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileDisposition {
    Durable,
    Disposable,
    None,
}

/// The session kind recorded in a validated bind context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Primary,
    Subagent,
    Ephemeral,
}

impl SessionKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Subagent => "subagent",
            Self::Ephemeral => "ephemeral",
        }
    }
}

impl ProfileDisposition {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Disposable => "disposable",
            Self::None => "none",
        }
    }

    fn valid_for(self, kind: SessionKind) -> bool {
        matches!(
            (kind, self),
            (SessionKind::Primary, Self::Durable)
                | (SessionKind::Subagent, Self::Disposable)
                | (SessionKind::Ephemeral, Self::None)
        )
    }
}

/// Facts presented to the strict validator.  This is an input-only type: the
/// lifecycle API accepts [`StampedBindContext`], not this carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindFacts {
    pub principal: String,
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: Option<String>,
    /// Whether daemon facts identified the kind. Distinct from `session_kind`
    /// being `Some`: a defaulted Primary is present and still unattested.
    pub session_kind_attested: bool,
    pub profile_disposition: Option<String>,
    pub effective_capability_scope: Option<Vec<String>>,
    pub provenance: String,
}

/// A daemon-stamped, already validated bind context.
///
/// The fields are private so callers cannot supply replacement identity, grant,
/// UUID, profile, or authority facts. Construction performs the pair check once
/// and records the immutable fact tuple in this value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedBindContext {
    principal: String,
    conversation_key: String,
    agent_project_id: String,
    session_kind: SessionKind,
    profile_disposition: ProfileDisposition,
    effective_capability_scope: Option<Vec<String>>,
}

pub type ValidatedBindContext = StampedBindContext;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindValidationError {
    MissingFact(&'static str),
    EmptyFact(&'static str),
    /// The named fact is present, but nobody attested it. Distinct from
    /// [`Self::MissingFact`]: asking the caller to supply the fact again would
    /// not create an attestation they do not have.
    MissingAttestation(&'static str),
    InvalidProvenance,
    UnknownSessionKind,
    UnknownDisposition,
    IncompatibleKindDisposition,
    InvalidScope,
}

impl fmt::Display for BindValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingFact(name) => write!(f, "missing stamped bind fact {name}"),
            Self::EmptyFact(name) => write!(f, "empty stamped bind fact {name}"),
            Self::MissingAttestation(name) => {
                write!(f, "missing attestation for stamped bind fact {name}")
            }
            Self::InvalidProvenance => write!(f, "bind facts are not daemon stamped"),
            Self::UnknownSessionKind => write!(f, "unknown session kind"),
            Self::UnknownDisposition => write!(f, "unknown profile disposition"),
            Self::IncompatibleKindDisposition => write!(f, "incompatible kind/disposition pair"),
            Self::InvalidScope => write!(f, "invalid effective capability scope"),
        }
    }
}
impl Error for BindValidationError {}

impl StampedBindContext {
    pub fn validate(facts: BindFacts) -> Result<Self, BindValidationError> {
        if facts.provenance != "daemon_attested_spec_a" {
            return Err(BindValidationError::InvalidProvenance);
        }
        for (name, value) in [
            ("principal", facts.principal.as_str()),
            ("conversation_key", facts.conversation_key.as_str()),
            ("agent_project_id", facts.agent_project_id.as_str()),
        ] {
            if value.is_empty() {
                return Err(BindValidationError::EmptyFact(name));
            }
        }
        let kind = facts
            .session_kind
            .ok_or(BindValidationError::MissingFact("session_kind"))
            .and_then(|value| match value.as_str() {
                "primary" => Ok(SessionKind::Primary),
                "subagent" => Ok(SessionKind::Subagent),
                "ephemeral" => Ok(SessionKind::Ephemeral),
                _ => Err(BindValidationError::UnknownSessionKind),
            })?;
        let disposition = facts
            .profile_disposition
            .ok_or(BindValidationError::MissingFact("profile_disposition"))
            .and_then(|value| match value.as_str() {
                "durable" => Ok(ProfileDisposition::Durable),
                "disposable" => Ok(ProfileDisposition::Disposable),
                "none" => Ok(ProfileDisposition::None),
                _ => Err(BindValidationError::UnknownDisposition),
            })?;
        if !disposition.valid_for(kind) {
            return Err(BindValidationError::IncompatibleKindDisposition);
        }
        // A defaulted kind arrives here as Some("primary"), so refusing absence
        // would admit it. Privilege attaches to Durable, and a kind nobody
        // stamped must not select that profile.
        if matches!(disposition, ProfileDisposition::Durable) && !facts.session_kind_attested {
            return Err(BindValidationError::MissingAttestation("session_kind"));
        }
        if let Some(scope) = &facts.effective_capability_scope {
            if scope.iter().any(|entry| entry.is_empty()) {
                return Err(BindValidationError::InvalidScope);
            }
        } else {
            return Err(BindValidationError::MissingFact(
                "effective_capability_scope",
            ));
        }
        Ok(Self {
            principal: facts.principal,
            conversation_key: facts.conversation_key,
            agent_project_id: facts.agent_project_id,
            session_kind: kind,
            profile_disposition: disposition,
            effective_capability_scope: facts.effective_capability_scope,
        })
    }

    pub fn principal(&self) -> &str {
        &self.principal
    }
    pub fn conversation_key(&self) -> &str {
        &self.conversation_key
    }
    pub fn agent_project_id(&self) -> &str {
        &self.agent_project_id
    }
    pub fn session_kind(&self) -> SessionKind {
        self.session_kind
    }
    pub fn profile_disposition(&self) -> ProfileDisposition {
        self.profile_disposition
    }
    pub fn effective_capability_scope(&self) -> Option<&[String]> {
        self.effective_capability_scope.as_deref()
    }

    fn fingerprint(&self) -> String {
        let mut bytes = Vec::new();
        for value in [
            self.principal.as_bytes(),
            self.conversation_key.as_bytes(),
            self.agent_project_id.as_bytes(),
            self.session_kind.as_str().as_bytes(),
            self.profile_disposition.as_str().as_bytes(),
        ] {
            bytes.extend_from_slice(&(value.len() as u32).to_be_bytes());
            bytes.extend_from_slice(value);
        }
        hex(&Sha256::digest(bytes))
    }
}

/// Construct a strict context without exposing an unvalidated alternative.
pub fn stamped_bind_context(facts: BindFacts) -> Result<StampedBindContext, BindValidationError> {
    StampedBindContext::validate(facts)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOrigin {
    RegistryOrStorage,
    CkcredDependency,
}

impl FailureOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RegistryOrStorage => "registry_or_storage",
            Self::CkcredDependency => "ckcred_dependency",
        }
    }
}

pub(crate) const PROFILE_REGISTRY_ROOT_INODE_CHANGED: &str =
    "profile_registry_managed_root_inode_changed";
pub(crate) const PROFILE_REGISTRY_ROOT_BIRTH_TIME_CHANGED: &str =
    "profile_registry_managed_root_birth_time_changed";
pub(crate) const PROFILE_REGISTRY_ROOT_PATH_CHANGED: &str =
    "profile_registry_managed_root_path_changed";
pub(crate) const PROFILE_REGISTRY_ROOT_IDENTITY_PREDATES_FACTS: &str =
    "profile_registry_managed_root_identity_predates_facts";
pub(crate) const PROFILE_REGISTRY_ROOT_BIRTH_TIME_UNAVAILABLE: &str =
    "profile_registry_managed_root_birth_time_unavailable";
pub(crate) const PROFILE_REGISTRY_POSSIBLY_MANAGED_PATH: &str =
    "profile_registry_possibly_managed_path";

/// The only authority data permitted to pass from profile lifecycle handling to
/// credential and grant handling: the project, session kind, and profile UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CkcredAuthority {
    pub project_id: String,
    pub session_kind: SessionKind,
    pub profile_uuid: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOutcome {
    ProfileBusy {
        profile_uuid: String,
    },
    ProfileGrantRequired {
        reason_code: &'static str,
    },
    NoSession {
        reason_code: &'static str,
    },
    StorageUnavailable {
        reason_code: &'static str,
        origin: FailureOrigin,
    },
    UntrustworthyRegistry {
        reason: UntrustworthyRegistryReason,
    },
    InternalFailure {
        reason_code: &'static str,
    },
}

impl ProfileOutcome {
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::ProfileBusy { .. } => "profile_busy",
            Self::ProfileGrantRequired { reason_code }
            | Self::NoSession { reason_code }
            | Self::StorageUnavailable { reason_code, .. }
            | Self::InternalFailure { reason_code } => reason_code,
            Self::UntrustworthyRegistry { reason } => untrustworthy_registry_reason_code(*reason),
        }
    }
}

impl fmt::Display for ProfileOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.reason_code())
    }
}

/// Stable identity for a directory and the held descriptor within one process
/// run.  Device and inode are the identity proof on Unix (the device cannot
/// move while this process holds the directory open; the identity persisted
/// across restarts is [`RootIdentityFacts`], which leaves the device out); metadata size is only a conservative fallback
/// on other platforms and never authorizes a target outside the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableIdentity {
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(not(unix))]
    len: u64,
    readonly: bool,
}

fn stable_identity(metadata: &fs::Metadata) -> StableIdentity {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        StableIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
            readonly: metadata.permissions().readonly(),
        }
    }
    #[cfg(not(unix))]
    {
        StableIdentity {
            len: metadata.len(),
            readonly: metadata.permissions().readonly(),
        }
    }
}

/// The version of the persisted managed-root identity written by this build.
///
/// Version 1 was a bare SHA-256 over the canonical path, the device number and
/// the inode. The device number is assigned at mount time on macOS and moves
/// across reboots, so every reboot made the same directory look like a
/// different one; and because only the hash was kept, nobody could tell a
/// reboot from a restore. Version 2 records the facts themselves in plaintext
/// and leaves the device out.
pub const ROOT_IDENTITY_FORMULA: u32 = 2;

/// A directory's creation time, split so it serializes as two exact integers.
/// `nanoseconds` is always in `0..1_000_000_000`; times before 1970 carry a
/// negative `unix_seconds` with a non-negative nanosecond part.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BirthTime {
    pub unix_seconds: i64,
    pub nanoseconds: u32,
}

impl BirthTime {
    /// Convert a timestamp, or `None` when it does not fit the stored range.
    pub fn from_system_time(time: SystemTime) -> Option<Self> {
        match time.duration_since(UNIX_EPOCH) {
            Ok(after) => Some(Self {
                unix_seconds: i64::try_from(after.as_secs()).ok()?,
                nanoseconds: after.subsec_nanos(),
            }),
            Err(error) => {
                let before = error.duration();
                let seconds = i64::try_from(before.as_secs()).ok()?;
                if before.subsec_nanos() == 0 {
                    Some(Self {
                        unix_seconds: -seconds,
                        nanoseconds: 0,
                    })
                } else {
                    Some(Self {
                        unix_seconds: -seconds - 1,
                        nanoseconds: 1_000_000_000 - before.subsec_nanos(),
                    })
                }
            }
        }
    }
}

impl fmt::Display for BirthTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:09}", self.unix_seconds, self.nanoseconds)
    }
}

/// What the filesystem reports about the managed root directory right now.
///
/// The device number is read but deliberately never part of the identity: on
/// macOS it is assigned when a volume mounts and changes across reboots for
/// the very same directory. It is carried here so a test can present a
/// different device and prove the identity does not depend on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootMetadataFacts {
    pub device: u64,
    pub inode: u64,
    /// `None` when the filesystem cannot report a creation time (for example
    /// overlayfs or NFS on Linux).
    pub birth_time: Option<BirthTime>,
}

/// Reads [`RootMetadataFacts`] from the root directory's metadata. Production
/// uses [`read_root_metadata_facts`]; tests substitute a reader to present a
/// different device, inode or birth time than the disk holds.
pub type RootFactsReader = fn(&fs::Metadata) -> RootMetadataFacts;

/// The production reader: `st_dev`/`st_ino` on Unix and
/// [`fs::Metadata::created`] (`st_birthtime` on macOS, statx `btime` on Linux).
pub fn read_root_metadata_facts(metadata: &fs::Metadata) -> RootMetadataFacts {
    let birth_time = metadata
        .created()
        .ok()
        .and_then(BirthTime::from_system_time);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        RootMetadataFacts {
            device: metadata.dev(),
            inode: metadata.ino(),
            birth_time,
        }
    }
    #[cfg(not(unix))]
    {
        // No stable inode is available through std off Unix; the length is
        // the same conservative stand-in the in-process stability check uses.
        RootMetadataFacts {
            device: 0,
            inode: metadata.len(),
            birth_time,
        }
    }
}

/// The persisted identity of the managed root in the current formula.
///
/// A replaced or restored directory always gets a new inode; a clone or backup
/// restore can keep the creation date but not the inode; a reboot keeps both.
/// Inode plus birth time therefore catches every replacement the pin exists
/// for without tripping on a reboot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootIdentityFacts {
    pub formula: u32,
    pub path: String,
    pub inode: u64,
    pub birth_time: BirthTime,
}

impl RootIdentityFacts {
    /// Build the current identity from a canonical path and the metadata read
    /// for it. A filesystem that cannot report birth time is refused rather
    /// than identified by inode alone: an inode can be reused once the old
    /// directory is gone, and birth time is what tells those two apart.
    pub fn observe(
        canonical_path: &Path,
        facts: &RootMetadataFacts,
    ) -> Result<Self, UntrustworthyRegistryReason> {
        let birth_time = facts
            .birth_time
            .ok_or(UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable)?;
        Ok(Self {
            formula: ROOT_IDENTITY_FORMULA,
            path: canonical_path.to_string_lossy().into_owned(),
            inode: facts.inode,
            birth_time,
        })
    }
}

impl fmt::Display for RootIdentityFacts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "path {} inode {} birth time {}",
            self.path, self.inode, self.birth_time
        )
    }
}

/// The managed-root identity as stored in a registry document.
///
/// Both forms live in the same `managed_root_identity` field so a registry
/// written before the fact-based formula still parses, and is refused by name
/// instead of as malformed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManagedRootIdentity {
    /// Formula 1: an opaque hash that included the device number. It cannot be
    /// checked against current facts, because the device it hashed has usually
    /// moved since, so it is only ever replaced by a recorded rebind.
    HashOnly(String),
    Facts(RootIdentityFacts),
}

impl fmt::Display for ManagedRootIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HashOnly(hash) => write!(f, "hash-only formula 1 digest {hash}"),
            Self::Facts(facts) => write!(f, "{facts}"),
        }
    }
}

/// Decide whether a stored identity still describes the observed root, naming
/// the fact that differs. Platform-neutral: every filesystem read happens in
/// the caller, so this can be exercised with any facts on any host.
pub fn verify_root_identity(
    stored: &ManagedRootIdentity,
    current: &RootIdentityFacts,
) -> Result<(), UntrustworthyRegistryReason> {
    let stored = match stored {
        ManagedRootIdentity::HashOnly(_) => {
            return Err(UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts)
        }
        ManagedRootIdentity::Facts(stored) => stored,
    };
    if stored.formula != ROOT_IDENTITY_FORMULA {
        return Err(UntrustworthyRegistryReason::UnsupportedRegistrySchema);
    }
    // Inode first: a new inode means a different directory, the case this pin
    // exists for, and it should be the reason reported when several differ.
    if stored.inode != current.inode {
        return Err(UntrustworthyRegistryReason::ManagedRootInodeChanged);
    }
    if stored.birth_time != current.birth_time {
        return Err(UntrustworthyRegistryReason::ManagedRootBirthTimeChanged);
    }
    if stored.path != current.path {
        return Err(UntrustworthyRegistryReason::ManagedRootPathChanged);
    }
    Ok(())
}

#[derive(Debug)]
pub enum RootError {
    Io(io::Error),
    NotDirectory,
    SymlinkNotAllowed,
    Unstable,
    OutsideRoot,
    InvalidTarget,
}
impl fmt::Display for RootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "managed root I/O: {e}"),
            Self::NotDirectory => write!(f, "managed root is not a directory"),
            Self::SymlinkNotAllowed => write!(f, "managed root or target is a symlink"),
            Self::Unstable => write!(f, "managed root identity changed"),
            Self::OutsideRoot => write!(f, "target escapes managed root"),
            Self::InvalidTarget => write!(f, "invalid profile target"),
        }
    }
}
impl Error for RootError {}
impl From<io::Error> for RootError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

/// A held managed-root directory handle.  The canonical string is only used to
/// revalidate containment; target access always revalidates against this handle.
#[derive(Debug)]
pub struct HeldManagedRoot {
    path: PathBuf,
    handle: File,
    identity: StableIdentity,
}

impl HeldManagedRoot {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RootError> {
        let supplied = path.as_ref();
        let link_meta = fs::symlink_metadata(supplied)?;
        if link_meta.file_type().is_symlink() {
            return Err(RootError::SymlinkNotAllowed);
        }
        if !link_meta.is_dir() {
            return Err(RootError::NotDirectory);
        }
        let canonical = fs::canonicalize(supplied)?;
        let handle = OpenOptions::new().read(true).open(&canonical)?;
        let metadata = handle.metadata()?;
        if !metadata.is_dir() {
            return Err(RootError::NotDirectory);
        }
        let identity = stable_identity(&metadata);
        Ok(Self {
            path: canonical,
            handle,
            identity,
        })
    }

    pub fn canonical_path(&self) -> &Path {
        &self.path
    }

    fn revalidate(&self) -> Result<(), RootError> {
        let current_path = fs::canonicalize(&self.path).map_err(RootError::Io)?;
        if current_path != self.path {
            return Err(RootError::Unstable);
        }
        let current = fs::symlink_metadata(&self.path)?;
        if current.file_type().is_symlink() || !current.is_dir() {
            return Err(RootError::Unstable);
        }
        let held = self.handle.metadata()?;
        if stable_identity(&held) != self.identity || stable_identity(&current) != self.identity {
            return Err(RootError::Unstable);
        }
        Ok(())
    }

    fn contained(&self, path: &Path) -> bool {
        path == self.path || path.strip_prefix(&self.path).is_ok()
    }

    fn target_path(&self, relative: &Path, create: bool) -> Result<PathBuf, RootError> {
        self.revalidate()?;
        if relative.is_absolute()
            || relative.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(RootError::InvalidTarget);
        }
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            return Err(RootError::InvalidTarget);
        }
        let target = self.path.join(relative);
        let mut cursor = self.path.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Err(RootError::InvalidTarget);
            };
            cursor.push(name);
            match fs::symlink_metadata(&cursor) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(RootError::SymlinkNotAllowed)
                }
                Ok(_) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => break,
                Err(error) => return Err(RootError::Io(error)),
            }
        }
        let parent = target.parent().ok_or(RootError::InvalidTarget)?;
        if create {
            fs::create_dir_all(parent)?;
        }
        let canonical_parent = fs::canonicalize(parent)?;
        if !self.contained(&canonical_parent) {
            return Err(RootError::OutsideRoot);
        }
        if target.exists() {
            let metadata = fs::symlink_metadata(&target)?;
            if metadata.file_type().is_symlink() {
                return Err(RootError::SymlinkNotAllowed);
            }
            let canonical_target = fs::canonicalize(&target)?;
            if !self.contained(&canonical_target) {
                return Err(RootError::OutsideRoot);
            }
        }
        Ok(target)
    }

    pub fn open_target(&self, relative: &Path) -> Result<TargetHandle, RootError> {
        let target = self.target_path(relative, false)?;
        let metadata = fs::symlink_metadata(&target).map_err(RootError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RootError::InvalidTarget);
        }
        let canonical = fs::canonicalize(&target)?;
        if !self.contained(&canonical) {
            return Err(RootError::OutsideRoot);
        }
        let handle = OpenOptions::new().read(true).open(&canonical)?;
        let identity = stable_identity(&handle.metadata()?);
        Ok(TargetHandle {
            path: canonical,
            handle,
            identity,
        })
    }
}

#[derive(Debug)]
pub struct TargetHandle {
    path: PathBuf,
    handle: File,
    identity: StableIdentity,
}
impl TargetHandle {
    pub fn canonical_path(&self) -> &Path {
        &self.path
    }
    pub fn revalidate(&self) -> Result<(), RootError> {
        let current = fs::symlink_metadata(&self.path)?;
        if current.file_type().is_symlink() || !current.is_dir() {
            return Err(RootError::Unstable);
        }
        let held = self.handle.metadata()?;
        if stable_identity(&held) != self.identity || stable_identity(&current) != self.identity {
            return Err(RootError::Unstable);
        }
        Ok(())
    }

    /// Consume the validated target handle before recursive deletion.  The
    /// caller retains the registry exclusion lock while this operation runs.
    pub fn remove_recursive(self) -> Result<(), RootError> {
        self.revalidate()?;
        let path = self.path;
        drop(self.handle);
        fs::remove_dir_all(path).map_err(RootError::Io)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactError {
    InvalidJson,
    MissingField(&'static str),
    WrongIdentifier,
    WrongRevision,
    InvalidSchema,
    UnknownField(String),
    InvalidProviderSet,
    InvalidTransitionTable,
    InvalidFixtures,
    DigestMismatch,
}
impl fmt::Display for ArtifactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidJson => write!(f, "invalid profile registry artifact JSON"),
            Self::MissingField(name) => write!(f, "artifact missing {name}"),
            Self::WrongIdentifier => write!(f, "wrong profile registry artifact identifier"),
            Self::WrongRevision => write!(f, "wrong profile registry artifact revision"),
            Self::InvalidSchema => write!(f, "invalid profile registry artifact schema"),
            Self::UnknownField(name) => write!(f, "unknown artifact field {name}"),
            Self::InvalidProviderSet => write!(f, "incomplete authoritative provider set"),
            Self::InvalidTransitionTable => write!(f, "incomplete transition table"),
            Self::InvalidFixtures => write!(f, "missing immutable expected-result fixtures"),
            Self::DigestMismatch => write!(f, "implementation digest mismatch"),
        }
    }
}
impl Error for ArtifactError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactGateReport {
    pub artifact_id: String,
    pub revision: String,
    pub implementation_digest: String,
    pub provider_ids: BTreeSet<String>,
    pub fixture_count: usize,
}

const REQUIRED_PROVIDERS: [&str; 5] = [
    "instance",
    "session",
    "attachment",
    "lock_owner",
    "supervised_process",
];
const REQUIRED_MEMBERS: [&str; 11] = [
    "adapter-configuration",
    "deletion-fencing-implementation",
    "fixture-set",
    "liveness-adapter/attachment",
    "liveness-adapter/instance",
    "liveness-adapter/lock_owner",
    "liveness-adapter/session",
    "liveness-adapter/supervised_process",
    "persistence-adapter",
    "registry-artifact",
    "transition-implementation",
];

fn object<'a>(
    value: &'a Value,
    key: &'static str,
) -> Result<&'a Map<String, Value>, ArtifactError> {
    value
        .get(key)
        .and_then(Value::as_object)
        .ok_or(ArtifactError::MissingField(key))
}
fn string_field<'a>(value: &'a Value, key: &'static str) -> Result<&'a str, ArtifactError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or(ArtifactError::MissingField(key))
}

fn artifact_value(bytes: &[u8]) -> Result<Value, ArtifactError> {
    serde_json::from_slice(bytes).map_err(|_| ArtifactError::InvalidJson)
}

fn validate_artifact(bytes: &[u8]) -> Result<(Value, ArtifactGateReport), ArtifactError> {
    let value = artifact_value(bytes)?;
    let root = value.as_object().ok_or(ArtifactError::InvalidSchema)?;
    let allowed = [
        "artifact_id",
        "revision",
        "schema",
        "managed_root",
        "implementation_digest",
        "schemas",
        "providers",
        "transitions",
        "recovery",
        "fixtures",
        "conformance",
    ];
    for key in root.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(ArtifactError::UnknownField(key.clone()));
        }
    }
    if string_field(&value, "artifact_id")? != REGISTRY_ARTIFACT_ID {
        return Err(ArtifactError::WrongIdentifier);
    }
    if string_field(&value, "revision")? != REGISTRY_ARTIFACT_REVISION {
        return Err(ArtifactError::WrongRevision);
    }
    if string_field(&value, "schema")? != REGISTRY_SCHEMA {
        return Err(ArtifactError::InvalidSchema);
    }
    let managed = object(&value, "managed_root")?;
    for key in [
        "config_id",
        "canonical",
        "directory",
        "readable",
        "stable_identity",
        "symlink_policy",
        "mount_boundary",
        "target_rule",
    ] {
        if !managed.contains_key(key) {
            return Err(ArtifactError::MissingField(key));
        }
    }
    let providers = object(&value, "providers")?;
    let complete = providers
        .get("complete_source_set")
        .and_then(Value::as_array)
        .ok_or(ArtifactError::InvalidProviderSet)?;
    let ids: BTreeSet<String> = complete
        .iter()
        .filter_map(Value::as_str)
        .map(ToOwned::to_owned)
        .collect();
    if ids.len() != REQUIRED_PROVIDERS.len()
        || REQUIRED_PROVIDERS.iter().any(|id| !ids.contains(*id))
    {
        return Err(ArtifactError::InvalidProviderSet);
    }
    let provider_defs = providers
        .get("required")
        .and_then(Value::as_array)
        .ok_or(ArtifactError::InvalidProviderSet)?;
    if provider_defs.len() != REQUIRED_PROVIDERS.len() {
        return Err(ArtifactError::InvalidProviderSet);
    }
    let transitions = value
        .get("transitions")
        .and_then(Value::as_array)
        .ok_or(ArtifactError::InvalidTransitionTable)?;
    let transition_ids: BTreeSet<&str> = transitions
        .iter()
        .filter_map(|entry| entry.get("id").and_then(Value::as_str))
        .collect();
    for id in [
        "durable_create",
        "durable_commit",
        "attach",
        "reuse",
        "abort",
        "release_durable",
        "release_disposable",
        "deletion_failed",
    ] {
        if !transition_ids.contains(id) {
            return Err(ArtifactError::InvalidTransitionTable);
        }
    }
    let fixtures = object(&value, "fixtures")?;
    if fixtures.get("expected_result_bytes_are_immutable") != Some(&Value::Bool(true)) {
        return Err(ArtifactError::InvalidFixtures);
    }
    let fixture_values = fixtures
        .get("expected_results")
        .and_then(Value::as_array)
        .ok_or(ArtifactError::InvalidFixtures)?;
    if fixture_values.len() < 20 {
        return Err(ArtifactError::InvalidFixtures);
    }
    let conformance = object(&value, "conformance")?;
    if conformance.get("passed") != Some(&Value::Bool(true)) {
        return Err(ArtifactError::InvalidFixtures);
    }
    let digest = object(&value, "implementation_digest")?;
    let digest_object = Value::Object(digest.clone());
    let digest_value = string_field(&digest_object, "value")?.to_string();
    if digest_value.len() != 64 || !digest_value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(ArtifactError::DigestMismatch);
    }
    let fixture_count = fixture_values.len();
    Ok((
        value,
        ArtifactGateReport {
            artifact_id: REGISTRY_ARTIFACT_ID.to_string(),
            revision: REGISTRY_ARTIFACT_REVISION.to_string(),
            implementation_digest: digest_value,
            provider_ids: ids,
            fixture_count,
        },
    ))
}

fn canonical_json(value: &Value) -> Vec<u8> {
    fn write(value: &Value, out: &mut Vec<u8>) {
        match value {
            Value::Null => out.extend_from_slice(b"null"),
            Value::Bool(value) => out.extend_from_slice(if *value { b"true" } else { b"false" }),
            Value::Number(value) => out.extend_from_slice(value.to_string().as_bytes()),
            Value::String(value) => {
                out.extend_from_slice(serde_json::to_string(value).unwrap().as_bytes())
            }
            Value::Array(values) => {
                out.push(b'[');
                for (index, item) in values.iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    write(item, out);
                }
                out.push(b']');
            }
            Value::Object(values) => {
                out.push(b'{');
                let mut keys: Vec<&String> = values.keys().collect();
                keys.sort();
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        out.push(b',');
                    }
                    out.extend_from_slice(serde_json::to_string(key).unwrap().as_bytes());
                    out.push(b':');
                    write(&values[key], out);
                }
                out.push(b'}');
            }
        }
    }
    let mut out = Vec::new();
    write(value, &mut out);
    out
}

fn artifact_for_digest(value: &Value) -> Value {
    let mut value = value.clone();
    if let Some(digest) = value
        .get_mut("implementation_digest")
        .and_then(Value::as_object_mut)
    {
        digest.insert("value".to_string(), Value::String(String::new()));
    }
    value
}

/// Build the canonical length-prefixed implementation bundle.  The digest
/// declaration is blanked only while hashing so an artifact can carry the
/// resulting digest without a self-referential fixed point.
pub fn implementation_bundle(artifact_bytes: &[u8]) -> Result<Vec<u8>, ArtifactError> {
    let artifact = artifact_value(artifact_bytes)?;
    let fixture_set = artifact
        .get("fixtures")
        .cloned()
        .ok_or(ArtifactError::MissingField("fixtures"))?;
    let adapter_configuration = serde_json::json!({
        "grant_verifier_adapter":"ckcred.grant.v1",
        "sealing_adapter":"ckcred.sealing.v1",
        "uuid_protocol":"external_frozen_protocol",
        "managed_root_config_id":"cerebellum.profile_root"
    });
    let mut members: Vec<(String, Vec<u8>)> = vec![
        (
            "registry-artifact".to_string(),
            canonical_json(&artifact_for_digest(&artifact)),
        ),
        (
            "transition-implementation".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "persistence-adapter".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "liveness-adapter/instance".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "liveness-adapter/session".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "liveness-adapter/attachment".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "liveness-adapter/lock_owner".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "liveness-adapter/supervised_process".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "deletion-fencing-implementation".to_string(),
            IMPLEMENTATION_SOURCE.to_vec(),
        ),
        (
            "adapter-configuration".to_string(),
            canonical_json(&adapter_configuration),
        ),
        ("fixture-set".to_string(), canonical_json(&fixture_set)),
    ];
    members.sort_by(|left, right| left.0.as_bytes().cmp(right.0.as_bytes()));
    let identifiers: Vec<&str> = members
        .iter()
        .map(|(identifier, _)| identifier.as_str())
        .collect();
    if identifiers != REQUIRED_MEMBERS.to_vec() {
        return Err(ArtifactError::InvalidFixtures);
    }
    let mut bundle = Vec::from(IMPLEMENTATION_MAGIC);
    bundle.extend_from_slice(&(members.len() as u32).to_be_bytes());
    for (identifier, content) in members {
        bundle.extend_from_slice(&(identifier.len() as u32).to_be_bytes());
        bundle.extend_from_slice(identifier.as_bytes());
        bundle.extend_from_slice(&(content.len() as u64).to_be_bytes());
        bundle.extend_from_slice(&content);
    }
    Ok(bundle)
}

pub fn implementation_digest_for(artifact_bytes: &[u8]) -> Result<String, ArtifactError> {
    Ok(hex(&Sha256::digest(implementation_bundle(artifact_bytes)?)))
}

/// Verify the artifact and its implementation-bound digest without using a
/// source-tree hash, build identifier, or ambient approval flag.
pub fn verify_implementation_digest(
    artifact_bytes: &[u8],
) -> Result<ArtifactGateReport, ArtifactError> {
    let (value, mut report) = validate_artifact(artifact_bytes)?;
    let computed = implementation_digest_for(artifact_bytes)?;
    if computed != report.implementation_digest {
        return Err(ArtifactError::DigestMismatch);
    }
    report.implementation_digest = computed;
    let _ = value;
    Ok(report)
}

/// Return the checked-in expected-result bytes.  The fixture runner consumes
/// these values as immutable inputs; it never derives expected results from the
/// state reached by an implementation under test.
pub fn immutable_fixture_expectations() -> Result<Vec<Value>, ArtifactError> {
    let artifact = artifact_value(REGISTRY_ARTIFACT)?;
    artifact
        .get("fixtures")
        .and_then(|fixtures| fixtures.get("expected_results"))
        .and_then(Value::as_array)
        .cloned()
        .ok_or(ArtifactError::InvalidFixtures)
}

#[derive(Debug, Clone)]
pub struct RegistryConfig {
    pub artifact_bytes: Vec<u8>,
    pub fixture_conformance: bool,
    pub uuid_protocol_compatible: bool,
    pub grant_verifier_available: bool,
    pub grant_accepted: bool,
    pub grant_authority: Option<CkcredAuthority>,
    pub sealing_available: bool,
    pub release_failure: bool,
    pub abort_failure: bool,
    pub deletion_failure_after_start: bool,
    /// How the managed root's identity facts are read from its metadata.
    pub root_facts: RootFactsReader,
}
impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            artifact_bytes: REGISTRY_ARTIFACT.to_vec(),
            fixture_conformance: true,
            uuid_protocol_compatible: false,
            grant_verifier_available: false,
            grant_accepted: true,
            grant_authority: None,
            sealing_available: false,
            release_failure: false,
            abort_failure: false,
            deletion_failure_after_start: false,
            root_facts: read_root_metadata_facts,
        }
    }
}

/// Untrusted registry conditions whose caller response must be chosen by value.
///
/// Display text remains diagnostic only; lifecycle refusal mapping matches this
/// closed enum so wording changes cannot alter the wire outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UntrustworthyRegistryReason {
    LockContentionWithoutOwnerProof,
    MalformedRegistry,
    UnsupportedRegistrySchema,
    /// The root's inode differs from the recorded one: the directory was
    /// replaced or restored.
    ManagedRootInodeChanged,
    /// Same inode, different creation time: the directory was recreated and
    /// happened to receive the old inode number.
    ManagedRootBirthTimeChanged,
    /// Same directory reached through a different canonical path: it or a
    /// parent was moved or renamed.
    ManagedRootPathChanged,
    /// The registry records the root with the hash-only formula, which cannot
    /// be checked against current facts. Only a recorded rebind replaces it.
    ManagedRootIdentityPredatesFacts,
    /// The filesystem holding the root cannot report a creation time, so the
    /// root cannot be identified. Never treated as an identity change.
    ManagedRootBirthTimeUnavailable,
    IntegrityMismatch,
    InvalidRegistryIdentity,
    NonCanonicalTarget,
    MissingRegistry,
    MissingRecord,
    MissingProfileUuid,
    PossiblyManagedPath,
    DurableKindConflict,
    DurableDeletionState,
    RecordTargetMissing,
}

impl fmt::Display for UntrustworthyRegistryReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let reason = match self {
            Self::LockContentionWithoutOwnerProof => "lock contention without positive owner proof",
            Self::MalformedRegistry => "malformed registry",
            Self::UnsupportedRegistrySchema => "unsupported registry schema",
            Self::ManagedRootInodeChanged => "managed root inode changed",
            Self::ManagedRootBirthTimeChanged => "managed root birth time changed",
            Self::ManagedRootPathChanged => "managed root canonical path changed",
            Self::ManagedRootIdentityPredatesFacts => {
                "managed root identity predates the fact-based formula"
            }
            Self::ManagedRootBirthTimeUnavailable => {
                "the filesystem holding the managed root cannot report birth time"
            }
            Self::IntegrityMismatch => "integrity mismatch",
            Self::InvalidRegistryIdentity => "invalid registry identity",
            Self::NonCanonicalTarget => "non-canonical target",
            Self::MissingRegistry => "missing registry",
            Self::MissingRecord => "missing record",
            Self::MissingProfileUuid => "missing profile UUID",
            Self::PossiblyManagedPath => "possibly managed path",
            Self::DurableKindConflict => "durable profile kind conflict",
            Self::DurableDeletionState => "durable profile deletion state",
            Self::RecordTargetMissing => "durable profile target missing",
        };
        f.write_str(reason)
    }
}

/// Stable wire code for a typed registry refusal.
pub const fn untrustworthy_registry_reason_code(
    reason: UntrustworthyRegistryReason,
) -> &'static str {
    match reason {
        UntrustworthyRegistryReason::LockContentionWithoutOwnerProof => {
            "profile_registry_lock_owner_unproven"
        }
        UntrustworthyRegistryReason::MalformedRegistry => "profile_registry_malformed",
        UntrustworthyRegistryReason::UnsupportedRegistrySchema => {
            "profile_registry_schema_unsupported"
        }
        UntrustworthyRegistryReason::ManagedRootInodeChanged => PROFILE_REGISTRY_ROOT_INODE_CHANGED,
        UntrustworthyRegistryReason::ManagedRootBirthTimeChanged => {
            PROFILE_REGISTRY_ROOT_BIRTH_TIME_CHANGED
        }
        UntrustworthyRegistryReason::ManagedRootPathChanged => PROFILE_REGISTRY_ROOT_PATH_CHANGED,
        UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts => {
            PROFILE_REGISTRY_ROOT_IDENTITY_PREDATES_FACTS
        }
        UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable => {
            PROFILE_REGISTRY_ROOT_BIRTH_TIME_UNAVAILABLE
        }
        UntrustworthyRegistryReason::IntegrityMismatch => "profile_registry_integrity_mismatch",
        UntrustworthyRegistryReason::InvalidRegistryIdentity => "profile_registry_identity_invalid",
        UntrustworthyRegistryReason::NonCanonicalTarget => "profile_target_non_canonical",
        UntrustworthyRegistryReason::MissingRegistry => "profile_registry_missing",
        UntrustworthyRegistryReason::MissingRecord => "profile_registry_record_missing",
        UntrustworthyRegistryReason::MissingProfileUuid => "profile_registry_profile_uuid_missing",
        UntrustworthyRegistryReason::PossiblyManagedPath => PROFILE_REGISTRY_POSSIBLY_MANAGED_PATH,
        UntrustworthyRegistryReason::DurableKindConflict => "profile_durable_kind_conflict",
        UntrustworthyRegistryReason::DurableDeletionState => "profile_durable_deletion_state",
        UntrustworthyRegistryReason::RecordTargetMissing => {
            "profile_registry_record_target_missing"
        }
    }
}

/// Actionable launch remedy for registry-root refusals that have a safe recovery.
pub const fn untrustworthy_registry_remedy(
    reason: UntrustworthyRegistryReason,
) -> Option<&'static str> {
    match reason {
        UntrustworthyRegistryReason::ManagedRootInodeChanged => Some(
            "the browser root directory was replaced or restored (its inode differs from the \
             recorded one); run rebind_profile_root to re-identify it; that operation \
             will itself refuse and name any directory the registry did not mint",
        ),
        UntrustworthyRegistryReason::ManagedRootBirthTimeChanged => Some(
            "the browser root directory was recreated (its creation time differs from the \
             recorded one); run rebind_profile_root to re-identify it; that operation \
             will itself refuse and name any directory the registry did not mint",
        ),
        UntrustworthyRegistryReason::ManagedRootPathChanged => Some(
            "the browser root is reached through a different canonical path than the recorded \
             one (it or a parent was moved); run rebind_profile_root to re-identify it; \
             that operation will itself refuse and name any directory the registry did not mint",
        ),
        UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts => Some(
            "the registry predates the fact-based root identity: it holds only a hash that \
             included a device number which changes across reboots, so it cannot be checked; \
             run rebind_profile_root once to record the root's path, inode, and birth \
             time; that operation will itself refuse and name any directory the registry did \
             not mint",
        ),
        UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable => Some(
            "the filesystem holding the browser root cannot report a directory birth time, so \
             the root cannot be identified; move the browser root to a filesystem that reports \
             birth time (APFS, ext4, btrfs, xfs); rebind_profile_root names the root \
             path and refuses for the same reason",
        ),
        UntrustworthyRegistryReason::PossiblyManagedPath => Some(
            "move or account for the unaccounted profile directories before running \
             rebind_profile_root; the rebind operation will not adopt them",
        ),
        UntrustworthyRegistryReason::LockContentionWithoutOwnerProof => None,
        UntrustworthyRegistryReason::MalformedRegistry => None,
        UntrustworthyRegistryReason::UnsupportedRegistrySchema => None,
        UntrustworthyRegistryReason::IntegrityMismatch => None,
        UntrustworthyRegistryReason::InvalidRegistryIdentity => None,
        UntrustworthyRegistryReason::NonCanonicalTarget => None,
        UntrustworthyRegistryReason::MissingRegistry => None,
        UntrustworthyRegistryReason::MissingRecord => None,
        UntrustworthyRegistryReason::MissingProfileUuid => None,
        UntrustworthyRegistryReason::DurableKindConflict => None,
        UntrustworthyRegistryReason::DurableDeletionState => None,
        UntrustworthyRegistryReason::RecordTargetMissing => None,
    }
}

#[derive(Debug)]
pub enum RegistryError {
    Root(RootError),
    Artifact(ArtifactError),
    Io(io::Error),
    UnknownField(String),
    UnsupportedState,
    Conflict,
    Untrustworthy(UntrustworthyRegistryReason),
    InvalidTransition,
}
impl fmt::Display for RegistryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Root(error) => write!(f, "{error}"),
            Self::Artifact(error) => write!(f, "{error}"),
            Self::Io(error) => write!(f, "profile registry I/O: {error}"),
            Self::UnknownField(field) => write!(f, "unknown profile registry field {field}"),
            Self::UnsupportedState => write!(f, "unsupported profile registry state"),
            Self::Conflict => write!(f, "profile registry identity conflict"),
            Self::Untrustworthy(reason) => write!(f, "untrustworthy profile registry: {reason}"),
            Self::InvalidTransition => write!(f, "invalid profile lifecycle transition"),
        }
    }
}
impl Error for RegistryError {}
impl From<RootError> for RegistryError {
    fn from(value: RootError) -> Self {
        Self::Root(value)
    }
}
impl From<ArtifactError> for RegistryError {
    fn from(value: ArtifactError) -> Self {
        Self::Artifact(value)
    }
}
impl From<io::Error> for RegistryError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SealState {
    Sealed,
    Available,
    Unsealed,
    Ambiguous,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub start_token: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RegistryRecord {
    pub project_id: String,
    pub kind: ProfileKind,
    pub target: String,
    pub transaction_id: String,
    pub state: ProfileState,
    pub owner_instance: String,
    pub profile_uuid: String,
    pub profile_name: Option<String>,
    pub session_id: Option<String>,
    pub attachment_id: Option<String>,
    pub process: Option<ProcessIdentity>,
    pub seal_state: SealState,
    pub quarantine: Option<QuarantineReason>,
    pub generation: u64,
    pub deletion_pending: bool,
    pub integrity: String,
}

fn release_attachment(record: &mut RegistryRecord) {
    record.state = ProfileState::Released;
    record.session_id = None;
    record.attachment_id = None;
    record.process = None;
    record.seal_state = if record.kind == ProfileKind::Durable {
        SealState::Sealed
    } else {
        SealState::Available
    };
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum QuarantineReason {
    UnregisteredProfileDirectory,
    MalformedProfileMetadata,
    ConflictingRegistryIdentity,
    AmbiguousOwnership,
    AmbiguousSealState,
    ManagedRootEscape,
    LivenessUnavailable,
    DeletionFailed,
}

impl QuarantineReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnregisteredProfileDirectory => "unregistered_profile_directory",
            Self::MalformedProfileMetadata => "malformed_profile_metadata",
            Self::ConflictingRegistryIdentity => "conflicting_registry_identity",
            Self::AmbiguousOwnership => "ambiguous_ownership",
            Self::AmbiguousSealState => "ambiguous_seal_state",
            Self::ManagedRootEscape => "managed_root_escape",
            Self::LivenessUnavailable => "liveness_unavailable",
            Self::DeletionFailed => "deletion_failed",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDocument {
    schema: String,
    managed_root_identity: ManagedRootIdentity,
    generation: u64,
    records: BTreeMap<String, RegistryRecord>,
    integrity: String,
}

/// Provenance recorded beside the registry before its root identity is changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindProvenance {
    pub ask_id: String,
    pub conversation_key: String,
    pub at_unix_ms: u64,
}

/// The exact registry transition a root rebind performed or would perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RebindReport {
    /// What the registry recorded, in whichever formula it was written.
    pub old_identity: ManagedRootIdentity,
    /// What the rebind records: always the current fact-based formula.
    pub new_identity: RootIdentityFacts,
    pub generation_before: u64,
    pub generation_after: u64,
    pub record_count: usize,
}

/// Closed reasons a managed-root identity rebind can refuse.
#[derive(Debug)]
pub enum RebindRefusal {
    RegistryMissing,
    MalformedRegistry,
    UnsupportedRegistrySchema,
    /// The stored document's digest does not verify. Checked before the
    /// identity compare: `AlreadyBound` is a statement about a document the
    /// registry has decided to trust, and it may not be made about bytes that
    /// fail their own digest.
    IntegrityMismatch,
    /// The stored identity already matches this root; nothing to heal.
    AlreadyBound,
    /// `profiles/` holds entries no record names. Never healed: rebinding
    /// would adopt directories nobody minted, and only that path can launder
    /// an attacker-placed profile into an attested launch.
    PossiblyManagedPath {
        unaccounted: Vec<String>,
    },
    /// The held root failed revalidation, or -- when a rebind is applied to a
    /// preview taken earlier -- the registry no longer matches what the
    /// person was shown. An elicited answer arrives minutes after its
    /// question; a root that changed in between is not the one consented to.
    RootUnstable,
    /// The filesystem holding the root cannot report a creation time, so no
    /// identity can be recorded for it. Names the root so the operator can
    /// see which filesystem is involved.
    BirthTimeUnavailable {
        root_path: PathBuf,
    },
    Io(io::Error),
}

/// Schema of each line in the rebind provenance file. Version 2 lines carry
/// the identities as written in the registry: `new_identity` is the
/// fact-based object, and `old_identity` is either that object or, for a
/// migration from the hash-only formula, the old digest string. Version 1
/// lines (both identities as digest strings) remain in older files untouched.
const PROFILE_ROOT_REBIND_RECORD_SCHEMA: &str = "ck-browser-profile-root-rebind/v2";

#[derive(Serialize)]
struct DurableRebindRecord<'a> {
    schema: &'static str,
    old_identity: &'a ManagedRootIdentity,
    new_identity: &'a RootIdentityFacts,
    generation_before: u64,
    generation_after: u64,
    record_count: usize,
    at_unix_ms: u64,
    elicited: DurableRebindElicitation<'a>,
}

#[derive(Serialize)]
struct DurableRebindElicitation<'a> {
    ask_id: &'a str,
    conversation_key: &'a str,
}

fn record_payload(record: &RegistryRecord) -> Value {
    let mut value = serde_json::to_value(record).expect("registry record is serializable");
    if let Some(object) = value.as_object_mut() {
        object.remove("integrity");
    }
    value
}
fn record_integrity(record: &RegistryRecord) -> String {
    hex(&Sha256::digest(canonical_json(&record_payload(record))))
}
fn document_payload(document: &RegistryDocument) -> Value {
    serde_json::json!({"schema":document.schema,"managed_root_identity":document.managed_root_identity,"generation":document.generation,"records":document.records})
}

/// The managed root's registry slot, held until dropped. The sentinel is
/// removed first, so an older build can take the slot again; the kernel lock
/// is released last, when the file field is dropped.
#[derive(Debug)]
pub struct RegistryLock {
    sentinel: PathBuf,
    _kernel_lock: File,
}
impl Drop for RegistryLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.sentinel);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::large_enum_variant)]
pub enum DurableResolution {
    TrustworthyExisting(RegistryRecord),
    AffirmativeAbsence,
    Untrustworthy(UntrustworthyRegistryReason),
    Unavailable,
}

#[derive(Debug)]
pub struct ProfileRegistry {
    root: Arc<HeldManagedRoot>,
    artifact: Value,
    artifact_report: ArtifactGateReport,
    config: RegistryConfig,
    instance_id: String,
    format_floor: cerebellum_core::format_floor::FormatFloor,
}

/// Read a registry document, refusing one from a newer build by its schema
/// before the strict parse. A newer document may carry fields this build
/// rejects, and it must read as an unsupported schema, not as malformed.
fn parse_registry_document(bytes: &[u8]) -> Result<RegistryDocument, RegistryDocumentRefusal> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| RegistryDocumentRefusal::Malformed)?;
    if let Some(schema) = value.get("schema").and_then(Value::as_str) {
        if REGISTRY_FORMAT
            .refuse_newer_tag(schema, REGISTRY_SCHEMA)
            .is_err()
        {
            return Err(RegistryDocumentRefusal::UnsupportedSchema);
        }
    }
    let document: RegistryDocument =
        serde_json::from_value(value).map_err(|_| RegistryDocumentRefusal::Malformed)?;
    if document.schema != REGISTRY_SCHEMA {
        return Err(RegistryDocumentRefusal::UnsupportedSchema);
    }
    Ok(document)
}

enum RegistryDocumentRefusal {
    Malformed,
    UnsupportedSchema,
}

fn empty_artifact_report() -> ArtifactGateReport {
    ArtifactGateReport {
        artifact_id: String::new(),
        revision: String::new(),
        implementation_digest: String::new(),
        provider_ids: BTreeSet::new(),
        fixture_count: 0,
    }
}

fn rebind_root_refusal(error: RootError) -> RebindRefusal {
    match error {
        RootError::Io(error) => RebindRefusal::Io(error),
        RootError::NotDirectory
        | RootError::SymlinkNotAllowed
        | RootError::Unstable
        | RootError::OutsideRoot
        | RootError::InvalidTarget => RebindRefusal::RootUnstable,
    }
}

fn rebind_registry_error(error: RegistryError) -> RebindRefusal {
    match error {
        RegistryError::Root(error) => rebind_root_refusal(error),
        RegistryError::Io(error) => RebindRefusal::Io(error),
        RegistryError::Untrustworthy(UntrustworthyRegistryReason::IntegrityMismatch) => {
            RebindRefusal::IntegrityMismatch
        }
        RegistryError::Artifact(error) => RebindRefusal::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("profile registry artifact error during rebind: {error}"),
        )),
        RegistryError::UnknownField(field) => RebindRefusal::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unknown profile registry field during rebind: {field}"),
        )),
        RegistryError::UnsupportedState => RebindRefusal::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported profile registry state during rebind",
        )),
        RegistryError::Conflict => RebindRefusal::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "profile registry conflict during rebind",
        )),
        RegistryError::Untrustworthy(reason) => RebindRefusal::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unexpected untrustworthy registry during rebind: {reason}"),
        )),
        RegistryError::InvalidTransition => RebindRefusal::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid profile registry transition during rebind",
        )),
    }
}

impl ProfileRegistry {
    pub fn open(root_path: impl AsRef<Path>) -> Result<Self, RegistryError> {
        Self::open_with_config(root_path, RegistryConfig::default())
    }

    pub fn open_with_config(
        root_path: impl AsRef<Path>,
        config: RegistryConfig,
    ) -> Result<Self, RegistryError> {
        let root = Arc::new(HeldManagedRoot::open(root_path)?);
        let gate = if config.fixture_conformance {
            artifact_value(&config.artifact_bytes)
                .ok()
                .zip(verify_implementation_digest(&config.artifact_bytes).ok())
        } else {
            None
        };
        let (artifact, artifact_report) =
            gate.unwrap_or_else(|| (Value::Null, empty_artifact_report()));
        let instance_id = format!(
            "instance-{}",
            &hex(&Sha256::digest(
                root.canonical_path().to_string_lossy().as_bytes()
            ))[..16]
        );
        let format_floor =
            cerebellum_core::format_floor::FormatFloor::governing(root.canonical_path());
        Ok(Self {
            root,
            artifact,
            artifact_report,
            config,
            instance_id,
            format_floor,
        })
    }

    /// Raise `floor` instead of the one chosen from the root's location.
    pub fn with_format_floor(mut self, floor: cerebellum_core::format_floor::FormatFloor) -> Self {
        self.format_floor = floor;
        self
    }

    /// Construct a disabled registry without touching registry or profile state.
    /// This is useful for an artifact-absent startup path and keeps uncertainty
    /// from turning into a destructive scan.
    pub fn disabled(
        root_path: impl AsRef<Path>,
        mut config: RegistryConfig,
    ) -> Result<Self, RegistryError> {
        config.artifact_bytes = b"{}".to_vec();
        let root = Arc::new(HeldManagedRoot::open(root_path)?);
        let format_floor =
            cerebellum_core::format_floor::FormatFloor::governing(root.canonical_path());
        Ok(Self {
            root,
            artifact: Value::Null,
            artifact_report: empty_artifact_report(),
            config,
            instance_id: "disabled".to_string(),
            format_floor,
        })
    }

    pub fn root(&self) -> &HeldManagedRoot {
        &self.root
    }
    pub fn artifact_report(&self) -> &ArtifactGateReport {
        &self.artifact_report
    }
    pub fn artifact_enabled(&self) -> bool {
        self.artifact != Value::Null
    }
    pub fn implementation_digest(&self) -> &str {
        &self.artifact_report.implementation_digest
    }
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }

    pub fn authority_projection(
        &self,
        context: &StampedBindContext,
        profile_uuid: &str,
    ) -> CkcredAuthority {
        CkcredAuthority {
            project_id: context.agent_project_id().to_string(),
            session_kind: context.session_kind(),
            profile_uuid: profile_uuid.to_string(),
        }
    }
    /// The managed root's identity as the filesystem reports it now.
    fn current_root_identity(&self) -> Result<RootIdentityFacts, RegistryError> {
        let metadata = self.root.handle.metadata()?;
        let facts = (self.config.root_facts)(&metadata);
        RootIdentityFacts::observe(self.root.canonical_path(), &facts)
            .map_err(RegistryError::Untrustworthy)
    }

    fn lock_path(&self) -> Result<PathBuf, RegistryError> {
        Ok(self.root.target_path(Path::new(DURABLE_LOCK_FILE), true)?)
    }

    /// Take the registry slot. Holders of this build exclude each other with
    /// an exclusive kernel lock, which an abrupt exit releases, so a crashed
    /// holder never leaves the slot stuck for them. Older builds still take
    /// the slot by creating the sentinel exclusively, so this build also
    /// creates it, marked as its own, and refuses while an unmarked one
    /// exists: that is a live older holder, or one that crashed, and nothing
    /// proves which. A marked sentinel found while the kernel lock is held
    /// was left by a holder of this build that has exited, and is taken over.
    fn acquire_slot_lock(&self) -> Result<RegistryLock, RegistryError> {
        let contention = || {
            RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::LockContentionWithoutOwnerProof,
            )
        };
        self.root.revalidate()?;
        let kernel_lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(
                self.root
                    .target_path(Path::new(DURABLE_KERNEL_LOCK_FILE), true)?,
            )?;
        match kernel_lock.try_lock() {
            Ok(()) => {}
            Err(fs::TryLockError::WouldBlock) => return Err(contention()),
            Err(fs::TryLockError::Error(error)) => return Err(error.into()),
        }
        let sentinel = self.lock_path()?;
        let staged = self
            .root
            .target_path(Path::new(DURABLE_LOCK_STAGING_FILE), true)?;
        // Only a holder of the kernel lock writes the staging file, so one
        // left over is from a holder that exited.
        match fs::remove_file(&staged) {
            Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
        let linked = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&staged)
            .and_then(|mut file| file.write_all(DURABLE_LOCK_MARKER))
            .and_then(|()| fs::hard_link(&staged, &sentinel));
        let _ = fs::remove_file(&staged);
        match linked {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                if !fs::read(&sentinel).is_ok_and(|bytes| bytes == DURABLE_LOCK_MARKER) {
                    return Err(contention());
                }
            }
            Err(error) => return Err(error.into()),
        }
        Ok(RegistryLock {
            sentinel,
            _kernel_lock: kernel_lock,
        })
    }

    fn acquire_rebind_slot_lock(&self) -> Result<RegistryLock, RebindRefusal> {
        self.acquire_slot_lock().map_err(rebind_registry_error)
    }

    fn read_rebind_document(&self) -> Result<RegistryDocument, RebindRefusal> {
        let path = self
            .root
            .target_path(Path::new(REGISTRY_FILE), false)
            .map_err(rebind_root_refusal)?;
        let mut bytes = Vec::new();
        match File::open(&path) {
            Ok(mut file) => file.read_to_end(&mut bytes).map_err(RebindRefusal::Io)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(RebindRefusal::RegistryMissing)
            }
            Err(error) => return Err(RebindRefusal::Io(error)),
        };
        let document = parse_registry_document(&bytes).map_err(|refusal| match refusal {
            RegistryDocumentRefusal::Malformed => RebindRefusal::MalformedRegistry,
            RegistryDocumentRefusal::UnsupportedSchema => RebindRefusal::UnsupportedRegistrySchema,
        })?;
        if hex(&Sha256::digest(canonical_json(&document_payload(
            &document,
        )))) != document.integrity
            || document
                .records
                .values()
                .any(|record| record_integrity(record) != record.integrity)
        {
            return Err(RebindRefusal::IntegrityMismatch);
        }
        Ok(document)
    }

    fn unaccounted_profile_paths(
        &self,
        document: &RegistryDocument,
    ) -> Result<Vec<String>, RebindRefusal> {
        self.root.revalidate().map_err(rebind_root_refusal)?;
        let profiles = self
            .root
            .target_path(Path::new("profiles"), false)
            .map_err(rebind_root_refusal)?;
        let metadata = match fs::symlink_metadata(&profiles) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(RebindRefusal::Io(error)),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(RebindRefusal::RootUnstable);
        }

        let accounted: BTreeSet<String> = document
            .records
            .values()
            .filter_map(|record| {
                Path::new(&record.target)
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
            })
            .collect();
        let mut unaccounted = BTreeSet::new();
        for entry in fs::read_dir(profiles).map_err(RebindRefusal::Io)? {
            let entry = entry.map_err(RebindRefusal::Io)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !accounted.contains(&name) {
                unaccounted.insert(name);
            }
        }
        Ok(unaccounted.into_iter().collect())
    }

    fn inspect_rebind_locked(&self) -> Result<(RegistryDocument, RebindReport), RebindRefusal> {
        let document = self.read_rebind_document()?;
        // A stored identity in a formula newer than this build must not be
        // overwritten by an older formula.
        if matches!(
            &document.managed_root_identity,
            ManagedRootIdentity::Facts(stored) if stored.formula != ROOT_IDENTITY_FORMULA
        ) {
            return Err(RebindRefusal::UnsupportedRegistrySchema);
        }
        let new_identity = match self.current_root_identity() {
            Ok(identity) => identity,
            Err(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable,
            )) => {
                return Err(RebindRefusal::BirthTimeUnavailable {
                    root_path: self.root.canonical_path().to_path_buf(),
                })
            }
            Err(error) => return Err(rebind_registry_error(error)),
        };
        if document.managed_root_identity == ManagedRootIdentity::Facts(new_identity.clone()) {
            return Err(RebindRefusal::AlreadyBound);
        }
        let unaccounted = self.unaccounted_profile_paths(&document)?;
        if !unaccounted.is_empty() {
            return Err(RebindRefusal::PossiblyManagedPath { unaccounted });
        }
        let generation_after = document.generation.checked_add(1).ok_or_else(|| {
            RebindRefusal::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "profile registry generation cannot advance",
            ))
        })?;
        let report = RebindReport {
            old_identity: document.managed_root_identity.clone(),
            new_identity,
            generation_before: document.generation,
            generation_after,
            record_count: document.records.len(),
        };
        Ok((document, report))
    }

    fn write_rebind_record(
        &self,
        report: &RebindReport,
        provenance: &RebindProvenance,
    ) -> Result<(), RebindRefusal> {
        let record = DurableRebindRecord {
            schema: PROFILE_ROOT_REBIND_RECORD_SCHEMA,
            old_identity: &report.old_identity,
            new_identity: &report.new_identity,
            generation_before: report.generation_before,
            generation_after: report.generation_after,
            record_count: report.record_count,
            at_unix_ms: provenance.at_unix_ms,
            elicited: DurableRebindElicitation {
                ask_id: &provenance.ask_id,
                conversation_key: &provenance.conversation_key,
            },
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|error| {
            RebindRefusal::Io(io::Error::new(io::ErrorKind::InvalidData, error))
        })?;
        bytes.push(b'\n');
        let path = self
            .root
            .target_path(Path::new(PROFILE_ROOT_REBINDS_FILE), true)
            .map_err(rebind_root_refusal)?;
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(RebindRefusal::Io)?;
        file.write_all(&bytes).map_err(RebindRefusal::Io)?;
        file.sync_all().map_err(RebindRefusal::Io)
    }

    fn rebind_managed_root_checked(
        &self,
        provenance: &RebindProvenance,
        expected: Option<&RebindReport>,
    ) -> Result<RebindReport, RebindRefusal> {
        let _lock = self.acquire_rebind_slot_lock()?;
        let (mut document, report) = self.inspect_rebind_locked()?;
        if expected.is_some_and(|expected| expected != &report) {
            return Err(RebindRefusal::RootUnstable);
        }
        self.write_rebind_record(&report, provenance)?;
        document.managed_root_identity = ManagedRootIdentity::Facts(report.new_identity.clone());
        document.generation = report.generation_after;
        self.write_document(document)
            .map_err(rebind_registry_error)?;
        Ok(report)
    }

    /// Read and validate the rebind situation without writing provenance or registry state.
    pub fn preview_rebind(&self) -> Result<RebindReport, RebindRefusal> {
        let _lock = self.acquire_rebind_slot_lock()?;
        self.inspect_rebind_locked().map(|(_, report)| report)
    }

    /// Re-identify a registry whose already-provenanced managed root was moved.
    ///
    /// > Healing an identity mismatch asserts "this is the same root I minted, moved". Adopting an
    /// > unaccounted path asserts "these profiles, which nobody minted, are now mine". The first
    /// > re-identifies a thing that already has a provenance; the second MANUFACTURES provenance. Only the
    /// > second can launder an attacker-placed directory into an attested launch.
    ///
    /// The durable provenance record is synced before the registry starts trusting
    /// the new identity. Unaccounted profile paths always refuse rather than being adopted.
    pub fn rebind_managed_root(
        &self,
        provenance: &RebindProvenance,
    ) -> Result<RebindReport, RebindRefusal> {
        self.rebind_managed_root_checked(provenance, None)
    }

    pub(crate) fn rebind_managed_root_from_preview(
        &self,
        provenance: &RebindProvenance,
        expected: &RebindReport,
    ) -> Result<RebindReport, RebindRefusal> {
        self.rebind_managed_root_checked(provenance, Some(expected))
    }

    fn read_document(&self) -> Result<Option<RegistryDocument>, RegistryError> {
        let path = self.root.target_path(Path::new(REGISTRY_FILE), false)?;
        let mut bytes = Vec::new();
        match File::open(&path) {
            Ok(mut file) => {
                file.read_to_end(&mut bytes)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        }
        let document = parse_registry_document(&bytes).map_err(|refusal| {
            RegistryError::Untrustworthy(match refusal {
                RegistryDocumentRefusal::Malformed => {
                    UntrustworthyRegistryReason::MalformedRegistry
                }
                RegistryDocumentRefusal::UnsupportedSchema => {
                    UntrustworthyRegistryReason::UnsupportedRegistrySchema
                }
            })
        })?;
        let current = self.current_root_identity()?;
        verify_root_identity(&document.managed_root_identity, &current)
            .map_err(RegistryError::Untrustworthy)?;
        if hex(&Sha256::digest(canonical_json(&document_payload(
            &document,
        )))) != document.integrity
        {
            return Err(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::IntegrityMismatch,
            ));
        }
        let mut durable_projects = BTreeSet::new();
        let mut targets = BTreeSet::new();
        for record in document.records.values() {
            if !targets.insert(record.target.clone()) {
                return Err(RegistryError::Conflict);
            }
            if record.kind == ProfileKind::Durable
                && !durable_projects.insert(record.project_id.clone())
            {
                return Err(RegistryError::Conflict);
            }
            if record_integrity(record) != record.integrity {
                return Err(RegistryError::Untrustworthy(
                    UntrustworthyRegistryReason::IntegrityMismatch,
                ));
            }
            if !record.state.legal_for(record.kind)
                || record.kind == ProfileKind::Durable && record.deletion_pending
            {
                return Err(RegistryError::UnsupportedState);
            }
            if record.profile_uuid.is_empty()
                || record.project_id.is_empty()
                || record.target.is_empty()
                || (record.kind == ProfileKind::Durable
                    && record.profile_name.as_deref() != Some("default"))
                || (record.kind == ProfileKind::Disposable && record.profile_name.is_some())
            {
                return Err(RegistryError::Untrustworthy(
                    UntrustworthyRegistryReason::InvalidRegistryIdentity,
                ));
            }
        }
        Ok(Some(document))
    }

    /// A registry for a root that has none yet. Fails when the root cannot be
    /// identified, so no registry is ever minted without a checkable identity.
    fn empty_document(&self) -> Result<RegistryDocument, RegistryError> {
        Ok(RegistryDocument {
            schema: REGISTRY_SCHEMA.to_string(),
            managed_root_identity: ManagedRootIdentity::Facts(self.current_root_identity()?),
            generation: 0,
            records: BTreeMap::new(),
            integrity: String::new(),
        })
    }

    fn write_document(&self, mut document: RegistryDocument) -> Result<(), RegistryError> {
        self.root.revalidate()?;
        // Before anything is written: a registry in this format on disk with
        // no floor naming it would let staging pass a build that cannot read
        // it. Reported as storage I/O, the outcome a failed write already has.
        self.format_floor
            .raise(REGISTRY_FORMAT)
            .map_err(|error| RegistryError::Io(io::Error::other(error)))?;
        document.integrity = hex(&Sha256::digest(canonical_json(&document_payload(
            &document,
        ))));
        let bytes = serde_json::to_vec(&document).map_err(|_| {
            RegistryError::Untrustworthy(UntrustworthyRegistryReason::IntegrityMismatch)
        })?;
        let path = self.root.target_path(Path::new(REGISTRY_FILE), true)?;
        let temporary = self
            .root
            .target_path(Path::new(".ck-browser-profile-registry-v1.tmp"), true)?;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .truncate(true)
                .write(true)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&temporary, &path)?;
        Ok(())
    }

    fn profile_target(&self, target: &str, create: bool) -> Result<PathBuf, RegistryError> {
        let path = Path::new(target);
        if path.is_absolute()
            || path.components().any(|component| {
                matches!(
                    component,
                    Component::ParentDir | Component::RootDir | Component::Prefix(_)
                )
            })
        {
            return Err(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::NonCanonicalTarget,
            ));
        }
        Ok(self.root.target_path(path, create)?)
    }

    /// Whether the profiles directory holds anything this registry did not mint.
    ///
    /// The question is whether an UNACCOUNTED directory sits where profiles
    /// belong, since that suggests a path someone else manages and minting into
    /// it could adopt or overwrite their data. A directory this registry has a
    /// record for is not such a thing.
    ///
    /// Asking only whether the directory is non-empty conflates those two, and
    /// the consequence is not subtle: the first agent to launch leaves a profile
    /// behind, so every LATER agent finds a non-empty directory, resolves to
    /// unavailable rather than absent, and can never mint a profile of its own.
    /// One agent per machine, with the second one refused by a check written to
    /// keep strangers out.
    fn conflicting_profile_path(&self) -> Result<bool, RegistryError> {
        self.root.revalidate()?;
        let profiles = self.root.target_path(Path::new("profiles"), false);
        let profiles = match profiles {
            Ok(path) => path,
            Err(RootError::Io(error)) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(false)
            }
            Err(error) => return Err(error.into()),
        };
        let metadata = match fs::symlink_metadata(&profiles) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Ok(true);
        }

        // Read the document directly rather than through a resolving helper,
        // because every caller of this check is itself deciding what a record
        // means and would otherwise recurse.
        let accounted: BTreeSet<String> = match self.read_document()? {
            Some(document) => document
                .records
                .values()
                .filter_map(|record| {
                    Path::new(&record.target)
                        .file_name()
                        .map(|name| name.to_string_lossy().into_owned())
                })
                .collect(),
            None => BTreeSet::new(),
        };

        for entry in fs::read_dir(profiles)? {
            let entry = entry?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !accounted.contains(&name) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    pub fn resolve_durable(&self, project_id: &str) -> Result<DurableResolution, RegistryError> {
        if !self.artifact_enabled() {
            return Ok(DurableResolution::Unavailable);
        }
        let _lock = self.acquire_slot_lock()?;
        let document = self.read_document()?;
        let Some(document) = document else {
            return if self.conflicting_profile_path()? {
                Ok(DurableResolution::Untrustworthy(
                    UntrustworthyRegistryReason::PossiblyManagedPath,
                ))
            } else {
                Ok(DurableResolution::AffirmativeAbsence)
            };
        };
        let Some(record) = document.records.get(project_id) else {
            return if self.conflicting_profile_path()? {
                Ok(DurableResolution::Untrustworthy(
                    UntrustworthyRegistryReason::PossiblyManagedPath,
                ))
            } else {
                Ok(DurableResolution::AffirmativeAbsence)
            };
        };
        if record.kind != ProfileKind::Durable {
            return Ok(DurableResolution::Untrustworthy(
                UntrustworthyRegistryReason::DurableKindConflict,
            ));
        }
        if record.state == ProfileState::DeletionFailed || record.deletion_pending {
            return Ok(DurableResolution::Untrustworthy(
                UntrustworthyRegistryReason::DurableDeletionState,
            ));
        }
        let target = self.profile_target(&record.target, false)?;
        if !target.exists() {
            return Ok(DurableResolution::Untrustworthy(
                UntrustworthyRegistryReason::RecordTargetMissing,
            ));
        }
        Ok(DurableResolution::TrustworthyExisting(record.clone()))
    }

    fn create_durable_record(
        &self,
        context: &StampedBindContext,
    ) -> Result<RegistryRecord, RegistryError> {
        let _lock = self.acquire_slot_lock()?;
        match self.resolve_without_lock(context.agent_project_id())? {
            DurableResolution::AffirmativeAbsence => {}
            DurableResolution::Untrustworthy(reason) => {
                return Err(RegistryError::Untrustworthy(reason));
            }
            DurableResolution::TrustworthyExisting(_) | DurableResolution::Unavailable => {
                return Err(RegistryError::Conflict);
            }
        }
        if !self.config.uuid_protocol_compatible {
            return Err(RegistryError::InvalidTransition);
        }
        let uuid = self.new_uuid(context, ProfileKind::Durable)?;
        let target = format!("profiles/{uuid}");
        let transaction_id = self.new_id("tx", context.conversation_key());
        let mut record = RegistryRecord {
            project_id: context.agent_project_id().to_string(),
            kind: ProfileKind::Durable,
            target: target.clone(),
            transaction_id,
            state: ProfileState::Provisional,
            owner_instance: self.instance_id.clone(),
            profile_uuid: uuid,
            profile_name: Some("default".to_string()),
            session_id: None,
            attachment_id: None,
            process: None,
            seal_state: SealState::Unsealed,
            quarantine: None,
            generation: 1,
            deletion_pending: false,
            integrity: String::new(),
        };
        record.integrity = record_integrity(&record);
        let mut document = match self.read_document()? {
            Some(document) => document,
            None => self.empty_document()?,
        };
        document
            .records
            .insert(context.agent_project_id().to_string(), record.clone());
        document.generation = document.generation.saturating_add(1);
        self.write_document(document)?;
        let target_path = self.profile_target(&target, true)?;
        fs::create_dir(&target_path)?;
        record.state = ProfileState::Available;
        record.seal_state = SealState::Available;
        record.generation = 2;
        record.integrity = record_integrity(&record);
        let mut document = self.read_document()?.ok_or(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::IntegrityMismatch,
        ))?;
        document
            .records
            .insert(context.agent_project_id().to_string(), record.clone());
        document.generation = document.generation.saturating_add(1);
        self.write_document(document)?;
        Ok(record)
    }

    fn resolve_without_lock(&self, project_id: &str) -> Result<DurableResolution, RegistryError> {
        let document = self.read_document()?;
        let Some(document) = document else {
            return if self.conflicting_profile_path()? {
                Ok(DurableResolution::Untrustworthy(
                    UntrustworthyRegistryReason::PossiblyManagedPath,
                ))
            } else {
                Ok(DurableResolution::AffirmativeAbsence)
            };
        };
        if let Some(record) = document.records.get(project_id) {
            return Ok(DurableResolution::TrustworthyExisting(record.clone()));
        }
        if self.conflicting_profile_path()? {
            Ok(DurableResolution::Untrustworthy(
                UntrustworthyRegistryReason::PossiblyManagedPath,
            ))
        } else {
            Ok(DurableResolution::AffirmativeAbsence)
        }
    }

    fn new_uuid(
        &self,
        context: &StampedBindContext,
        kind: ProfileKind,
    ) -> Result<String, RegistryError> {
        let seed = format!(
            "{}:{}:{}:{}:{}:{}",
            self.instance_id,
            context.conversation_key(),
            context.agent_project_id(),
            kind as u8,
            UUID_COUNTER.fetch_add(1, Ordering::Relaxed),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let digest = hex(&Sha256::digest(seed.as_bytes()));
        let uuid = format!(
            "{}-{}-{}-{}-{}",
            &digest[0..8],
            &digest[8..12],
            &digest[12..16],
            &digest[16..20],
            &digest[20..32]
        );
        // Whether a directory ALREADY OCCUPIES this uuid, not whether the path
        // could be resolved. `profile_target` answers the second: it validates
        // the shape and canonicalises the PARENT, checking existence only to
        // refuse a symlink, so it succeeds for any unused uuid the moment the
        // `profiles` directory exists at all.
        //
        // Reading it as a collision check made the FIRST agent on a machine
        // succeed — nothing had created `profiles` yet, so resolution failed and
        // the uuid was accepted — and every agent after it fail with a conflict
        // against a directory that does not exist. One browser profile per
        // machine, which is the opposite of what per-agent profiles are for.
        match self.profile_target(&format!("profiles/{uuid}"), false) {
            Ok(path) if path.exists() => return Err(RegistryError::Conflict),
            // An unresolvable path is not a collision: nothing occupies it.
            Ok(_) | Err(_) => {}
        }
        Ok(uuid)
    }

    fn new_id(&self, prefix: &str, entropy: &str) -> String {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        format!(
            "{prefix}-{}",
            &hex(&Sha256::digest(
                format!("{}:{entropy}:{millis}", self.instance_id).as_bytes()
            ))[..24]
        )
    }

    fn update_record<F>(
        &self,
        project_id: &str,
        mut update: F,
    ) -> Result<RegistryRecord, RegistryError>
    where
        F: FnMut(&mut RegistryRecord) -> Result<(), RegistryError>,
    {
        let _lock = self.acquire_slot_lock()?;
        let mut document = self.read_document()?.ok_or(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::MissingRegistry,
        ))?;
        let record = document
            .records
            .get_mut(project_id)
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::MissingRecord,
            ))?;
        update(record)?;
        record.generation = record.generation.saturating_add(1);
        record.integrity = record_integrity(record);
        let result = record.clone();
        document.generation = document.generation.saturating_add(1);
        self.write_document(document)?;
        Ok(result)
    }
}

/// Invocation-bound opaque values. Test constructors model values returned by the
/// trusted invocation-token provider; production callers receive tokens from it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InvocationToken {
    id: String,
}
impl InvocationToken {
    pub(crate) fn from_trusted_invocation(id: impl Into<String>) -> Self {
        Self { id: id.into() }
    }

    pub fn for_test(id: impl Into<String>) -> Self {
        Self::from_trusted_invocation(id)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct JournalReservationHandle {
    invocation_id: String,
    id: String,
}
impl JournalReservationHandle {
    pub(crate) fn from_recorded_reservation(
        invocation: &InvocationToken,
        id: impl Into<String>,
    ) -> Self {
        Self {
            invocation_id: invocation.id.clone(),
            id: id.into(),
        }
    }

    pub fn for_test(invocation: &InvocationToken, id: impl Into<String>) -> Self {
        Self::from_recorded_reservation(invocation, id)
    }
}
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DispatchCommitmentToken {
    invocation_id: String,
    reservation_id: String,
    id: String,
}
impl DispatchCommitmentToken {
    pub(crate) fn from_durable_commitment(
        invocation: &InvocationToken,
        reservation: &JournalReservationHandle,
        id: impl Into<String>,
    ) -> Self {
        Self {
            invocation_id: invocation.id.clone(),
            reservation_id: reservation.id.clone(),
            id: id.into(),
        }
    }

    pub fn for_test(
        invocation: &InvocationToken,
        reservation: &JournalReservationHandle,
        id: impl Into<String>,
    ) -> Self {
        Self::from_durable_commitment(invocation, reservation, id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortCause {
    DispatchCommitFailed,
    InvocationCancelled,
    Teardown,
}
impl AbortCause {
    /// The pinned wire name for this cause.  The strings are frozen by the
    /// profile-lifecycle contract, so they live with the enum rather than at
    /// the call site that will serialize them.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DispatchCommitFailed => "dispatch_commit_failed",
            Self::InvocationCancelled => "invocation_cancelled",
            Self::Teardown => "teardown",
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseCause {
    SessionEnd,
    ContextReplaced,
    SupervisorShutdown,
}
impl ReleaseCause {
    /// The stable wire name for this cause.  These strings are serialized into
    /// profile-lifecycle records, so their spellings must not change; the
    /// mapping lives with the enum rather than at the serializing call site.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SessionEnd => "session_end",
            Self::ContextReplaced => "context_replaced",
            Self::SupervisorShutdown => "supervisor_shutdown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenState {
    Closed,
    Open,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CurrentOpenSnapshot {
    pub open_state: OpenState,
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
    pub epoch: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinalContextAssociation {
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortTerminalState {
    Aborted,
    AbortFailedRecoveryOwned,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbortSignal {
    pub invocation_id: String,
    pub reservation_id: String,
    pub cause: AbortCause,
    pub state: AbortTerminalState,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivenessObservation {
    pub generation: u64,
    pub fence: u64,
    pub instance: Option<String>,
    pub session: Option<String>,
    pub attachment: Option<String>,
    pub lock_owner: Option<String>,
    pub supervised_process: Option<ProcessIdentity>,
    pub complete: bool,
    pub fresh: bool,
    pub consistent: bool,
}
impl LivenessObservation {
    pub fn all_absent(generation: u64, fence: u64) -> Self {
        Self {
            generation,
            fence,
            instance: None,
            session: None,
            attachment: None,
            lock_owner: None,
            supervised_process: None,
            complete: true,
            fresh: true,
            consistent: true,
        }
    }
    fn proves_absence(&self, generation: u64, fence: u64) -> bool {
        self.complete
            && self.fresh
            && self.consistent
            && self.generation == generation
            && self.fence == fence
            && self.instance.is_none()
            && self.session.is_none()
            && self.attachment.is_none()
            && self.lock_owner.is_none()
            && self.supervised_process.is_none()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletionFence {
    pub generation: u64,
    pub active: bool,
}
impl DeletionFence {
    pub fn held(generation: u64) -> Self {
        Self {
            generation,
            active: true,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PreparedKind {
    Creating(ProfileKind),
    Reuse,
}

/// The exact profile directory selected by preparation. The registry UUID stays
/// private; launch custody needs only the disposition and canonical delete target.
#[derive(Debug, Clone)]
pub struct PreparedProfileAttempt {
    disposition: ProfileDisposition,
    directory: PathBuf,
    freshly_created: bool,
}

impl PartialEq for PreparedProfileAttempt {
    fn eq(&self, other: &Self) -> bool {
        // New-directory status controls login-history coverage, not the identity
        // checked at custody release: that remains the selected directory and
        // whether it is a durable or disposable profile.
        self.disposition == other.disposition && self.directory == other.directory
    }
}
impl Eq for PreparedProfileAttempt {}

impl PreparedProfileAttempt {
    pub const fn freshly_created(&self) -> bool {
        self.freshly_created
    }
    pub const fn disposition(&self) -> ProfileDisposition {
        self.disposition
    }

    pub fn directory(&self) -> &Path {
        &self.directory
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedState {
    id: u64,
    invocation_id: String,
    reservation_id: String,
    context_fingerprint: String,
    conversation_key: String,
    project_id: String,
    kind: PreparedKind,
    freshly_created: bool,
    profile_uuid: Option<String>,
    profile_name: Option<String>,
    terminal: Option<AbortSignal>,
}

/// Opaque prepared state.  It intentionally exposes no identity or path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOpen {
    namespace: u64,
    id: u64,
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenedState {
    id: u64,
    invocation_id: String,
    reservation_id: String,
    conversation_key: String,
    project_id: String,
    kind: ProfileKind,
    profile_uuid: String,
    profile_name: Option<String>,
    release: Option<(ReleaseCause, Result<(), ProfileOutcome>)>,
    rollback_terminalized: Option<ReleaseCause>,
}
/// Opaque session-owned opened context handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedContext {
    namespace: u64,
    id: u64,
}

/// Opaque proof that the prepared profile record reached a terminal rollback
/// state. Custody release may occur only between this phase and completion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedRollback {
    namespace: u64,
    id: u64,
    cause: AbortCause,
}

/// Opaque proof that an opened profile record reached a terminal rollback state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedRollback {
    namespace: u64,
    id: u64,
    cause: ReleaseCause,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PrepareResult {
    Prepared(PreparedOpen),
    Closed(ProfileOutcome),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbortResult {
    Aborted(AbortSignal),
    Closed(ProfileOutcome),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchResult {
    Opened(OpenedContext),
    Closed(ProfileOutcome),
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReleaseResult {
    Released,
    Closed(ProfileOutcome),
}

struct AttachmentLiveness(
    std::sync::Arc<dyn crate::profile_custody::SupervisorLivenessProbe + Send + Sync>,
);

impl fmt::Debug for AttachmentLiveness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttachmentLiveness")
    }
}

impl Default for AttachmentLiveness {
    fn default() -> Self {
        Self(std::sync::Arc::new(
            crate::profile_custody::KernelSupervisorLiveness,
        ))
    }
}

/// The profile lifecycle coordinator. It is deliberately synchronous: browser
/// and journal adapters call it around their own asynchronous work and retain
/// only opaque handles across that boundary.
#[derive(Debug)]
pub struct ProfileLifecycle {
    attachment_liveness: AttachmentLiveness,
    registry: ProfileRegistry,
    namespace: u64,
    prepared: HashMap<u64, PreparedState>,
    opened: HashMap<u64, OpenedState>,
    sessions: HashMap<String, u64>,
    next_handle: u64,
    current: HashMap<String, CurrentOpenSnapshot>,
    final_contexts: HashMap<String, FinalContextAssociation>,
    abort_signals: Vec<AbortSignal>,
    deletion_excluded: BTreeSet<String>,
}

impl ProfileLifecycle {
    pub fn open(root: impl AsRef<Path>) -> Result<Self, RegistryError> {
        Self::open_with_config(root, RegistryConfig::default())
    }
    pub fn open_with_config(
        root: impl AsRef<Path>,
        config: RegistryConfig,
    ) -> Result<Self, RegistryError> {
        let registry = ProfileRegistry::open_with_config(root, config)?;
        let namespace = handle_namespace(registry.root());
        let mut lifecycle = Self {
            attachment_liveness: AttachmentLiveness::default(),
            registry,
            namespace,
            prepared: HashMap::new(),
            opened: HashMap::new(),
            sessions: HashMap::new(),
            next_handle: 1,
            current: HashMap::new(),
            final_contexts: HashMap::new(),
            abort_signals: Vec::new(),
            deletion_excluded: BTreeSet::new(),
        };
        // Resolution reports untrusted or newer registry data as a typed
        // refusal. Recovery must not turn that read-only refusal into an open
        // failure or attempt to rewrite data it does not understand.
        match lifecycle.recover_startup() {
            Ok(_) | Err(RegistryError::Untrustworthy(_)) => {}
            Err(error) => return Err(error),
        }
        Ok(lifecycle)
    }
    /// Raise `floor` for registry writes instead of the one chosen from the
    /// root's location.
    pub fn with_format_floor(mut self, floor: cerebellum_core::format_floor::FormatFloor) -> Self {
        self.registry = self.registry.with_format_floor(floor);
        self
    }
    pub fn disabled(root: impl AsRef<Path>) -> Result<Self, RegistryError> {
        let registry = ProfileRegistry::disabled(root, RegistryConfig::default())?;
        let namespace = handle_namespace(registry.root());
        Ok(Self {
            attachment_liveness: AttachmentLiveness::default(),
            registry,
            namespace,
            prepared: HashMap::new(),
            opened: HashMap::new(),
            sessions: HashMap::new(),
            next_handle: 1,
            current: HashMap::new(),
            final_contexts: HashMap::new(),
            abort_signals: Vec::new(),
            deletion_excluded: BTreeSet::new(),
        })
    }
    pub fn registry(&self) -> &ProfileRegistry {
        &self.registry
    }
    pub fn current_open(&self, conversation: &str) -> CurrentOpenSnapshot {
        self.current
            .get(conversation)
            .cloned()
            .unwrap_or(CurrentOpenSnapshot {
                open_state: OpenState::Closed,
                profile_uuid: None,
                profile_name: None,
                epoch: 0,
            })
    }
    pub fn final_context(
        &self,
        token: &DispatchCommitmentToken,
    ) -> Option<&FinalContextAssociation> {
        self.final_contexts.get(&token.id)
    }
    pub fn abort_signals(&self) -> &[AbortSignal] {
        &self.abort_signals
    }

    /// Report pending preparation ownership without exposing any profile
    /// identity or filesystem path.
    pub fn pending_preparation_count(&self) -> usize {
        self.prepared
            .values()
            .filter(|state| state.terminal.is_none())
            .count()
    }
    pub fn is_effectively_excluded(&self, profile_uuid: &str) -> bool {
        self.deletion_excluded.contains(profile_uuid)
    }

    fn next(&mut self) -> u64 {
        let id = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        id
    }
    fn closed_storage(&self, origin: FailureOrigin, reason_code: &'static str) -> PrepareResult {
        PrepareResult::Closed(ProfileOutcome::StorageUnavailable {
            reason_code,
            origin,
        })
    }

    fn closed_untrusted_root(&self, reason: UntrustworthyRegistryReason) -> PrepareResult {
        let outcome = match reason {
            UntrustworthyRegistryReason::ManagedRootInodeChanged
            | UntrustworthyRegistryReason::ManagedRootBirthTimeChanged
            | UntrustworthyRegistryReason::ManagedRootPathChanged
            | UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts
            | UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable
            | UntrustworthyRegistryReason::PossiblyManagedPath => {
                ProfileOutcome::UntrustworthyRegistry { reason }
            }
            UntrustworthyRegistryReason::LockContentionWithoutOwnerProof
            | UntrustworthyRegistryReason::MalformedRegistry
            | UntrustworthyRegistryReason::UnsupportedRegistrySchema
            | UntrustworthyRegistryReason::IntegrityMismatch
            | UntrustworthyRegistryReason::InvalidRegistryIdentity
            | UntrustworthyRegistryReason::NonCanonicalTarget
            | UntrustworthyRegistryReason::MissingRegistry
            | UntrustworthyRegistryReason::MissingRecord
            | UntrustworthyRegistryReason::MissingProfileUuid
            | UntrustworthyRegistryReason::DurableKindConflict
            | UntrustworthyRegistryReason::DurableDeletionState
            | UntrustworthyRegistryReason::RecordTargetMissing => {
                ProfileOutcome::StorageUnavailable {
                    reason_code: untrustworthy_registry_reason_code(reason),
                    origin: FailureOrigin::RegistryOrStorage,
                }
            }
        };
        PrepareResult::Closed(outcome)
    }

    pub fn prepare_context_open(
        &mut self,
        invocation: &InvocationToken,
        reservation: &JournalReservationHandle,
        context: &StampedBindContext,
    ) -> PrepareResult {
        // The gate is first.  In particular, no current session, registry,
        // target, grant, or CKCRED state is consulted while it is disabled.
        if !self.registry.artifact_enabled() {
            return self.closed_storage(
                FailureOrigin::RegistryOrStorage,
                "profile_registry_artifact_unavailable",
            );
        }
        if invocation.id != reservation.invocation_id {
            return PrepareResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "invocation_reservation_mismatch",
            });
        }
        let conversation = context.conversation_key().to_string();
        if let Some(existing_id) = self.sessions.get(&conversation).copied() {
            let Some(existing) = self.opened.get(&existing_id) else {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_opened_context_missing",
                );
            };
            let existing_project = existing.project_id.clone();
            let existing_kind = existing.kind;
            let existing_uuid = existing.profile_uuid.clone();
            let existing_name = existing.profile_name.clone();
            if existing_project != context.agent_project_id()
                || existing_kind != disposition_kind(context.profile_disposition())
            {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_reuse_binding_mismatch",
                );
            }
            let id = self.next();
            self.prepared.insert(
                id,
                PreparedState {
                    id,
                    invocation_id: invocation.id.clone(),
                    reservation_id: reservation.id.clone(),
                    context_fingerprint: context.fingerprint(),
                    conversation_key: conversation.clone(),
                    project_id: context.agent_project_id().to_string(),
                    kind: PreparedKind::Reuse,
                    freshly_created: false,
                    profile_uuid: Some(existing_uuid),
                    profile_name: existing_name,
                    terminal: None,
                },
            );
            return PrepareResult::Prepared(PreparedOpen {
                namespace: self.namespace,
                id,
            });
        }
        match context.profile_disposition() {
            ProfileDisposition::None => PrepareResult::Closed(ProfileOutcome::NoSession {
                reason_code: "no_session",
            }),
            ProfileDisposition::Disposable => {
                let uuid = match self.create_disposable(context) {
                    Ok(uuid) => uuid,
                    Err(_) => {
                        return self.closed_storage(
                            FailureOrigin::RegistryOrStorage,
                            "profile_disposable_creation_failed",
                        )
                    }
                };
                let id = self.next();
                self.prepared.insert(
                    id,
                    PreparedState {
                        id,
                        invocation_id: invocation.id.clone(),
                        reservation_id: reservation.id.clone(),
                        context_fingerprint: context.fingerprint(),
                        conversation_key: conversation,
                        project_id: context.agent_project_id().to_string(),
                        kind: PreparedKind::Creating(ProfileKind::Disposable),
                        freshly_created: true,
                        profile_uuid: Some(uuid),
                        profile_name: None,
                        terminal: None,
                    },
                );
                PrepareResult::Prepared(PreparedOpen {
                    namespace: self.namespace,
                    id,
                })
            }
            ProfileDisposition::Durable => {
                self.prepare_durable(invocation, reservation, context, conversation)
            }
        }
    }

    fn prepare_durable(
        &mut self,
        invocation: &InvocationToken,
        reservation: &JournalReservationHandle,
        context: &StampedBindContext,
        conversation: String,
    ) -> PrepareResult {
        if !self.registry.config.grant_verifier_available || !self.registry.config.sealing_available
        {
            return self.closed_storage(
                FailureOrigin::CkcredDependency,
                "profile_credential_dependencies_unavailable",
            );
        }
        let resolution = match self.registry.resolve_durable(context.agent_project_id()) {
            Ok(resolution) => resolution,
            Err(RegistryError::Untrustworthy(reason)) => return self.closed_untrusted_root(reason),
            Err(RegistryError::Root(RootError::Io(error)))
                if error.kind() == io::ErrorKind::NotFound =>
            {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_managed_root_missing",
                )
            }
            Err(RegistryError::Root(RootError::Io(error)))
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_managed_root_not_writable",
                )
            }
            Err(RegistryError::Root(RootError::Unstable)) => {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_managed_root_identity_changed",
                )
            }
            Err(RegistryError::Root(_)) => {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_managed_root_unavailable",
                )
            }
            Err(RegistryError::Io(error))
                if matches!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::ReadOnlyFilesystem
                ) =>
            {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_managed_root_not_writable",
                )
            }
            Err(_) => {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_durable_resolution_failed",
                )
            }
        };
        let mut freshly_created = false;
        let mut record = match resolution {
            DurableResolution::Untrustworthy(reason) => return self.closed_untrusted_root(reason),
            DurableResolution::Unavailable => {
                return self.closed_storage(
                    FailureOrigin::RegistryOrStorage,
                    "profile_registry_unavailable",
                )
            }
            DurableResolution::AffirmativeAbsence => {
                if !self.registry.config.uuid_protocol_compatible {
                    return PrepareResult::Closed(ProfileOutcome::NoSession {
                        reason_code: "no_session",
                    });
                }
                if !self.registry.config.grant_accepted
                    || self.registry.config.grant_authority.is_some()
                {
                    return PrepareResult::Closed(ProfileOutcome::ProfileGrantRequired {
                        reason_code: "durable_profile_grant_unavailable",
                    });
                }
                match self.registry.create_durable_record(context) {
                    Ok(record) => {
                        freshly_created = true;
                        record
                    }
                    Err(RegistryError::Untrustworthy(reason)) => {
                        return self.closed_untrusted_root(reason)
                    }
                    Err(_) => {
                        return self.closed_storage(
                            FailureOrigin::RegistryOrStorage,
                            "profile_durable_creation_failed",
                        )
                    }
                }
            }
            DurableResolution::TrustworthyExisting(record) => record,
        };
        // Grant verification must succeed before the profile's owner-specific
        // authority data is exposed. An unavailable adapter has already caused
        // rejection above, so only affirmative authority reaches preparation.
        let authority = self
            .registry
            .authority_projection(context, &record.profile_uuid);
        if !self.registry.config.grant_accepted
            || self
                .registry
                .config
                .grant_authority
                .as_ref()
                .is_some_and(|grant| grant != &authority)
        {
            return PrepareResult::Closed(ProfileOutcome::ProfileGrantRequired {
                reason_code: "durable_profile_grant_unavailable",
            });
        }
        if record.state == ProfileState::Attached {
            match self.recover_attachment(&record) {
                Ok(Some(released)) => record = released,
                Ok(None) => {}
                Err(_) => {
                    return self.closed_storage(
                        FailureOrigin::RegistryOrStorage,
                        "profile_attachment_recovery_failed",
                    )
                }
            }
        }
        if record.state == ProfileState::Attached || record.state == ProfileState::Locked {
            return PrepareResult::Closed(ProfileOutcome::ProfileBusy {
                profile_uuid: record.profile_uuid,
            });
        }
        if !matches!(
            record.state,
            ProfileState::Available | ProfileState::Released
        ) || !record.state.legal_for(ProfileKind::Durable)
            || record.seal_state == SealState::Ambiguous
        {
            return self.closed_storage(
                FailureOrigin::RegistryOrStorage,
                "profile_durable_state_invalid",
            );
        }
        let id = self.next();
        self.prepared.insert(
            id,
            PreparedState {
                id,
                invocation_id: invocation.id.clone(),
                reservation_id: reservation.id.clone(),
                context_fingerprint: context.fingerprint(),
                conversation_key: conversation,
                project_id: context.agent_project_id().to_string(),
                kind: PreparedKind::Creating(ProfileKind::Durable),
                freshly_created,
                profile_uuid: Some(record.profile_uuid),
                profile_name: Some("default".to_string()),
                terminal: None,
            },
        );
        PrepareResult::Prepared(PreparedOpen {
            namespace: self.namespace,
            id,
        })
    }

    fn create_disposable(&self, context: &StampedBindContext) -> Result<String, RegistryError> {
        let uuid = self.registry.new_uuid(context, ProfileKind::Disposable)?;
        let target = format!("profiles/{uuid}");
        let _lock = self.registry.acquire_slot_lock()?;
        if self.registry.profile_target(&target, false).is_ok() {
            return Err(RegistryError::Conflict);
        }
        let mut record = RegistryRecord {
            project_id: context.agent_project_id().to_string(),
            kind: ProfileKind::Disposable,
            target: target.clone(),
            transaction_id: self.registry.new_id("tx", context.conversation_key()),
            state: ProfileState::Provisional,
            owner_instance: self.registry.instance_id.clone(),
            profile_uuid: uuid.clone(),
            profile_name: None,
            session_id: Some(context.conversation_key().to_string()),
            attachment_id: None,
            process: None,
            seal_state: SealState::Available,
            quarantine: None,
            generation: 1,
            deletion_pending: false,
            integrity: String::new(),
        };
        record.integrity = record_integrity(&record);
        let mut document = match self.registry.read_document()? {
            Some(document) => document,
            None => self.registry.empty_document()?,
        };
        // Disposable records use a transaction-specific synthetic key, so they
        // are stored separately and cannot replace or claim the one durable
        // record associated with a project.
        document
            .records
            .insert(record.transaction_id.clone(), record.clone());
        document.generation = document.generation.saturating_add(1);
        self.registry.write_document(document)?;
        let target_path = self.registry.profile_target(&target, true)?;
        fs::create_dir(&target_path)?;
        record.state = ProfileState::Available;
        record.generation = 2;
        record.integrity = record_integrity(&record);
        let mut document = self
            .registry
            .read_document()?
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::IntegrityMismatch,
            ))?;
        document
            .records
            .insert(record.transaction_id.clone(), record);
        document.generation = document.generation.saturating_add(1);
        self.registry.write_document(document)?;
        Ok(uuid)
    }

    /// Return the disposition and canonical directory selected for this opaque
    /// preparation without exposing the registry's profile UUID.
    pub fn prepared_profile_attempt(
        &self,
        prepared: &PreparedOpen,
    ) -> Result<PreparedProfileAttempt, ProfileOutcome> {
        if prepared.namespace != self.namespace {
            return Err(ProfileOutcome::InternalFailure {
                reason_code: "prepared_namespace_mismatch",
            });
        }
        let state = self
            .prepared
            .get(&prepared.id)
            .ok_or(ProfileOutcome::InternalFailure {
                reason_code: "prepared_context_absent",
            })?;
        let uuid = state
            .profile_uuid
            .as_deref()
            .ok_or(ProfileOutcome::InternalFailure {
                reason_code: "prepared_profile_uuid_absent",
            })?;
        let record = self.registry.record_for_by_uuid(uuid).map_err(|_| {
            ProfileOutcome::StorageUnavailable {
                reason_code: "profile_preparation_record_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            }
        })?;
        let directory = self
            .registry
            .profile_target(&record.target, false)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_preparation_directory_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        Ok(PreparedProfileAttempt {
            disposition: match record.kind {
                ProfileKind::Durable => ProfileDisposition::Durable,
                ProfileKind::Disposable => ProfileDisposition::Disposable,
            },
            directory,
            freshly_created: state.freshly_created,
        })
    }

    /// Terminalize a prepared profile without releasing it or deleting its
    /// directory. The separate completion step lets the lock owner enforce
    /// terminalize-before-release and release-before-delete ordering.
    pub fn terminalize_prepared_rollback(
        &mut self,
        prepared: &PreparedOpen,
        cause: AbortCause,
    ) -> Result<PreparedRollback, ProfileOutcome> {
        if prepared.namespace != self.namespace {
            return Err(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_namespace_mismatch",
            });
        }
        let Some(state) = self.prepared.get(&prepared.id).cloned() else {
            return Err(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_context_absent",
            });
        };
        if let Some(signal) = state.terminal.as_ref() {
            if signal.cause != cause {
                return Err(ProfileOutcome::InternalFailure {
                    reason_code: "prepared_rollback_cause_mismatch",
                });
            }
        } else {
            if self.registry.config.abort_failure {
                return Err(ProfileOutcome::StorageUnavailable {
                    reason_code: "profile_rollback_terminalization_failed",
                    origin: FailureOrigin::RegistryOrStorage,
                });
            }
            if let PreparedKind::Creating(kind) = state.kind {
                let uuid =
                    state
                        .profile_uuid
                        .as_deref()
                        .ok_or(ProfileOutcome::InternalFailure {
                            reason_code: "prepared_rollback_profile_uuid_absent",
                        })?;
                self.terminalize_profile_record(uuid, kind)?;
            }
            let signal = AbortSignal {
                invocation_id: state.invocation_id,
                reservation_id: state.reservation_id,
                cause,
                state: AbortTerminalState::Aborted,
            };
            self.abort_signals.push(signal.clone());
            self.prepared
                .get_mut(&prepared.id)
                .expect("prepared state exists")
                .terminal = Some(signal);
        }
        Ok(PreparedRollback {
            namespace: prepared.namespace,
            id: prepared.id,
            cause,
        })
    }

    /// Complete a terminalized rollback after custody release. Disposable
    /// cleanup removes only the directory recorded in the supplied attempt.
    pub fn complete_prepared_rollback(
        &mut self,
        rollback: PreparedRollback,
        attempt: &PreparedProfileAttempt,
    ) -> AbortResult {
        if rollback.namespace != self.namespace {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_completion_namespace_mismatch",
            });
        }
        let Some(state) = self.prepared.get(&rollback.id).cloned() else {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_completion_context_absent",
            });
        };
        let Some(signal) = state.terminal.clone() else {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_not_terminalized",
            });
        };
        if signal.cause != rollback.cause {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_completion_cause_mismatch",
            });
        }
        let actual_attempt = match self.prepared_profile_attempt(&PreparedOpen {
            namespace: rollback.namespace,
            id: rollback.id,
        }) {
            Ok(value) => value,
            Err(error) => return AbortResult::Closed(error),
        };
        if &actual_attempt != attempt {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_rollback_attempt_mismatch",
            });
        }
        let result = match state.kind {
            PreparedKind::Creating(ProfileKind::Disposable) => {
                self.remove_prepared_disposable(&state)
            }
            PreparedKind::Reuse | PreparedKind::Creating(ProfileKind::Durable) => Ok(()),
        };
        match result {
            Ok(()) => AbortResult::Aborted(signal),
            Err(error) => AbortResult::Closed(error),
        }
    }

    pub fn abort_prepared_context(
        &mut self,
        prepared: PreparedOpen,
        cause: AbortCause,
    ) -> AbortResult {
        if prepared.namespace != self.namespace {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_abort_namespace_mismatch",
            });
        }
        let Some(state) = self.prepared.get(&prepared.id).cloned() else {
            return AbortResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_abort_context_absent",
            });
        };
        if let Some(signal) = state.terminal.clone() {
            if signal.cause != cause {
                return AbortResult::Closed(ProfileOutcome::InternalFailure {
                    reason_code: "prepared_abort_cause_mismatch",
                });
            }
            return match signal.state {
                AbortTerminalState::Aborted => AbortResult::Aborted(signal),
                AbortTerminalState::AbortFailedRecoveryOwned => {
                    AbortResult::Closed(ProfileOutcome::StorageUnavailable {
                        reason_code: "profile_abort_recovery_required",
                        origin: FailureOrigin::RegistryOrStorage,
                    })
                }
            };
        }
        let signal = AbortSignal {
            invocation_id: state.invocation_id.clone(),
            reservation_id: state.reservation_id.clone(),
            cause,
            state: AbortTerminalState::Aborted,
        };
        let result = match state.kind {
            PreparedKind::Reuse => Ok(()),
            PreparedKind::Creating(kind) => {
                if self.registry.config.abort_failure {
                    Err(ProfileOutcome::StorageUnavailable {
                        reason_code: "profile_abort_cleanup_failed",
                        origin: FailureOrigin::RegistryOrStorage,
                    })
                } else if kind == ProfileKind::Disposable {
                    self.remove_prepared_disposable(&state)
                } else {
                    self.remove_prepared_durable(&state)
                }
            }
        };
        match result {
            Ok(()) => {
                self.abort_signals.push(signal.clone());
                self.prepared
                    .get_mut(&prepared.id)
                    .expect("prepared state exists")
                    .terminal = Some(signal.clone());
                AbortResult::Aborted(signal)
            }
            Err(error) => {
                let signal = AbortSignal {
                    state: AbortTerminalState::AbortFailedRecoveryOwned,
                    ..signal
                };
                self.abort_signals.push(signal.clone());
                self.prepared
                    .get_mut(&prepared.id)
                    .expect("prepared state exists")
                    .terminal = Some(signal);
                AbortResult::Closed(error)
            }
        }
    }

    fn remove_prepared_disposable(&mut self, state: &PreparedState) -> Result<(), ProfileOutcome> {
        let Some(uuid) = &state.profile_uuid else {
            return Ok(());
        };
        let record = self.registry.record_for_by_uuid(uuid).map_err(|_| {
            ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_rollback_record_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            }
        })?;
        if self.registry.config.deletion_failure_after_start {
            self.deletion_excluded.insert(uuid.clone());
            let _ = self.registry.mark_deletion_failed(&record);
            return Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_rollback_deletion_failed",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        let handle = self
            .registry
            .root
            .open_target(Path::new(&record.target))
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_rollback_directory_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        handle
            .remove_recursive()
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_rollback_directory_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        self.registry
            .remove_record(&record.transaction_id)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_rollback_record_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
    }

    fn remove_prepared_durable(&self, state: &PreparedState) -> Result<(), ProfileOutcome> {
        let uuid = state
            .profile_uuid
            .as_deref()
            .ok_or(ProfileOutcome::InternalFailure {
                reason_code: "durable_rollback_profile_uuid_absent",
            })?;
        let record = self.registry.record_for_by_uuid(uuid).map_err(|_| {
            ProfileOutcome::StorageUnavailable {
                reason_code: "profile_durable_rollback_record_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            }
        })?;
        self.registry
            .remove_record(&record.transaction_id)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_durable_rollback_record_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
    }

    fn terminalize_profile_record(
        &self,
        uuid: &str,
        kind: ProfileKind,
    ) -> Result<(), ProfileOutcome> {
        self.registry
            .update_record_by_uuid(uuid, |record| {
                if record.profile_uuid != uuid || record.kind != kind {
                    return Err(RegistryError::Conflict);
                }
                release_attachment(record);
                record.deletion_pending = kind == ProfileKind::Disposable;
                Ok(())
            })
            .map(|_| ())
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_record_terminalization_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
    }

    pub fn launch_prepared_context(
        &mut self,
        prepared: PreparedOpen,
        token: &DispatchCommitmentToken,
    ) -> LaunchResult {
        if prepared.namespace != self.namespace {
            return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_launch_namespace_mismatch",
            });
        }
        let Some(state) = self.prepared.get(&prepared.id).cloned() else {
            return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_launch_context_absent",
            });
        };
        if state.invocation_id != token.invocation_id
            || state.reservation_id != token.reservation_id
        {
            return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_launch_commitment_mismatch",
            });
        }
        if state.terminal.is_some() {
            return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_launch_already_terminalized",
            });
        }
        let uuid = state
            .profile_uuid
            .clone()
            // The `else` below can only receive this missing UUID failure.
            .ok_or(ProfileOutcome::InternalFailure {
                reason_code: "prepared_launch_profile_uuid_absent",
            });
        let Ok(uuid) = uuid else {
            // This branch returns the same error because the UUID is missing, matching the `ok_or` failure above.
            return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "prepared_launch_profile_uuid_absent",
            });
        };
        if self.registry.config.release_failure && matches!(state.kind, PreparedKind::Creating(_)) {
            return LaunchResult::Closed(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_launch_release_failed",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        match state.kind {
            PreparedKind::Reuse => {
                let Some(existing_id) = self.sessions.get(&state.conversation_key).copied() else {
                    return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                        reason_code: "reused_profile_session_absent",
                    });
                };
                let Some(existing) = self.opened.get(&existing_id) else {
                    return LaunchResult::Closed(ProfileOutcome::InternalFailure {
                        reason_code: "reused_profile_opened_context_absent",
                    });
                };
                let opened = OpenedContext {
                    namespace: self.namespace,
                    id: existing.id,
                };
                self.prepared.remove(&state.id);
                self.final_contexts.insert(
                    token.id.clone(),
                    FinalContextAssociation {
                        profile_uuid: Some(existing.profile_uuid.clone()),
                        profile_name: existing.profile_name.clone(),
                    },
                );
                LaunchResult::Opened(opened)
            }
            PreparedKind::Creating(kind) => {
                let project = state.project_id.clone();
                let updated = if kind == ProfileKind::Disposable {
                    self.registry.update_record_by_uuid(&uuid, |record| {
                        if record.profile_uuid != uuid {
                            return Err(RegistryError::Conflict);
                        }
                        record.state = ProfileState::Attached;
                        record.session_id = Some(state.conversation_key.clone());
                        record.attachment_id = Some(format!("attachment-{}", state.id));
                        record.process = Some(ProcessIdentity {
                            pid: std::process::id(),
                            start_token: format!("s8-{}", state.id),
                        });
                        record.seal_state = SealState::Available;
                        Ok(())
                    })
                } else {
                    self.registry.update_record(&project, |record| {
                        if record.profile_uuid != uuid {
                            return Err(RegistryError::Conflict);
                        }
                        record.state = ProfileState::Attached;
                        record.session_id = Some(state.conversation_key.clone());
                        record.attachment_id = Some(format!("attachment-{}", state.id));
                        record.process = Some(ProcessIdentity {
                            pid: std::process::id(),
                            start_token: format!("s8-{}", state.id),
                        });
                        record.seal_state = SealState::Available;
                        Ok(())
                    })
                };
                if updated.is_err() {
                    return LaunchResult::Closed(ProfileOutcome::StorageUnavailable {
                        reason_code: "profile_launch_record_update_failed",
                        origin: FailureOrigin::RegistryOrStorage,
                    });
                }
                let id = self.next();
                let opened = OpenedState {
                    id,
                    invocation_id: state.invocation_id,
                    reservation_id: state.reservation_id,
                    conversation_key: state.conversation_key.clone(),
                    project_id: state.project_id,
                    kind,
                    profile_uuid: uuid.clone(),
                    profile_name: state.profile_name.clone(),
                    release: None,
                    rollback_terminalized: None,
                };
                self.sessions.insert(state.conversation_key.clone(), id);
                self.opened.insert(id, opened);
                self.prepared.remove(&state.id);
                self.set_open_snapshot(
                    &state.conversation_key,
                    Some(uuid.clone()),
                    state.profile_name.clone(),
                );
                self.final_contexts.insert(
                    token.id.clone(),
                    FinalContextAssociation {
                        profile_uuid: Some(uuid),
                        profile_name: state.profile_name,
                    },
                );
                LaunchResult::Opened(OpenedContext {
                    namespace: self.namespace,
                    id,
                })
            }
        }
    }

    fn set_open_snapshot(
        &mut self,
        conversation: &str,
        uuid: Option<String>,
        name: Option<String>,
    ) {
        let previous = self.current_open(conversation);
        let next = CurrentOpenSnapshot {
            open_state: if uuid.is_some() {
                OpenState::Open
            } else {
                OpenState::Closed
            },
            profile_uuid: uuid,
            profile_name: name,
            epoch: if previous.open_state == OpenState::Closed
                && previous.profile_uuid.is_none()
                && previous.profile_name.is_none()
            {
                1
            } else {
                previous.epoch.saturating_add(1)
            },
        };
        if previous.open_state != next.open_state
            || previous.profile_uuid != next.profile_uuid
            || previous.profile_name != next.profile_name
        {
            self.current.insert(conversation.to_string(), next);
        }
    }

    pub fn opened_profile_attempt(
        &self,
        opened: &OpenedContext,
    ) -> Result<PreparedProfileAttempt, ProfileOutcome> {
        if opened.namespace != self.namespace {
            return Err(ProfileOutcome::InternalFailure {
                reason_code: "opened_profile_attempt_namespace_mismatch",
            });
        }
        let state = self
            .opened
            .get(&opened.id)
            .ok_or(ProfileOutcome::InternalFailure {
                reason_code: "opened_profile_attempt_context_absent",
            })?;
        let record = self
            .registry
            .record_for_by_uuid(&state.profile_uuid)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_opened_record_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        let directory = self
            .registry
            .profile_target(&record.target, false)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_opened_directory_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        Ok(PreparedProfileAttempt {
            disposition: match state.kind {
                ProfileKind::Durable => ProfileDisposition::Durable,
                ProfileKind::Disposable => ProfileDisposition::Disposable,
            },
            directory,
            freshly_created: false,
        })
    }

    pub fn terminalize_opened_rollback(
        &mut self,
        opened: &OpenedContext,
        cause: ReleaseCause,
    ) -> Result<OpenedRollback, ProfileOutcome> {
        if opened.namespace != self.namespace {
            return Err(ProfileOutcome::InternalFailure {
                reason_code: "opened_rollback_namespace_mismatch",
            });
        }
        let state =
            self.opened
                .get(&opened.id)
                .cloned()
                .ok_or(ProfileOutcome::InternalFailure {
                    reason_code: "opened_rollback_context_absent",
                })?;
        if state
            .rollback_terminalized
            .is_some_and(|prior| prior != cause)
        {
            return Err(ProfileOutcome::InternalFailure {
                reason_code: "opened_rollback_cause_mismatch",
            });
        }
        if state.rollback_terminalized.is_none() {
            if self.registry.config.release_failure {
                return Err(ProfileOutcome::StorageUnavailable {
                    reason_code: "profile_opened_rollback_terminalization_failed",
                    origin: FailureOrigin::RegistryOrStorage,
                });
            }
            self.terminalize_profile_record(&state.profile_uuid, state.kind)?;
            self.opened
                .get_mut(&opened.id)
                .expect("opened state exists")
                .rollback_terminalized = Some(cause);
        }
        Ok(OpenedRollback {
            namespace: opened.namespace,
            id: opened.id,
            cause,
        })
    }

    pub fn complete_opened_rollback(
        &mut self,
        rollback: OpenedRollback,
        attempt: &PreparedProfileAttempt,
    ) -> ReleaseResult {
        if rollback.namespace != self.namespace {
            return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "opened_rollback_completion_namespace_mismatch",
            });
        }
        let opened = OpenedContext {
            namespace: rollback.namespace,
            id: rollback.id,
        };
        let actual_attempt = match self.opened_profile_attempt(&opened) {
            Ok(value) => value,
            Err(error) => return ReleaseResult::Closed(error),
        };
        if &actual_attempt != attempt {
            return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "opened_rollback_attempt_mismatch",
            });
        }
        let Some(state) = self.opened.get(&rollback.id).cloned() else {
            return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "opened_rollback_completion_context_absent",
            });
        };
        if state.rollback_terminalized != Some(rollback.cause) {
            return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "opened_rollback_completion_cause_mismatch",
            });
        }
        let outcome = match state.kind {
            ProfileKind::Disposable => self.release_disposable(&state),
            ProfileKind::Durable => Ok(()),
        };
        match outcome {
            Ok(()) => {
                self.sessions.remove(&state.conversation_key);
                self.set_open_snapshot(&state.conversation_key, None, None);
                self.opened
                    .get_mut(&rollback.id)
                    .expect("opened state exists")
                    .release = Some((rollback.cause, Ok(())));
                ReleaseResult::Released
            }
            Err(error) => ReleaseResult::Closed(error),
        }
    }

    pub fn release_context(&mut self, opened: OpenedContext, cause: ReleaseCause) -> ReleaseResult {
        if opened.namespace != self.namespace {
            return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "profile_release_namespace_mismatch",
            });
        }
        let Some(state) = self.opened.get(&opened.id).cloned() else {
            return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                reason_code: "profile_release_context_absent",
            });
        };
        if let Some((prior_cause, result)) = &state.release {
            if *prior_cause != cause {
                return ReleaseResult::Closed(ProfileOutcome::InternalFailure {
                    reason_code: "profile_release_cause_mismatch",
                });
            }
            return match result {
                Ok(()) => ReleaseResult::Released,
                Err(error) => ReleaseResult::Closed(error.clone()),
            };
        }
        let outcome = if self.registry.config.release_failure {
            Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_release_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
        } else {
            match state.kind {
                ProfileKind::Disposable => self.release_disposable(&state),
                ProfileKind::Durable => self.release_durable(&state),
            }
        };
        if outcome.is_ok() {
            self.sessions.remove(&state.conversation_key);
            self.set_open_snapshot(&state.conversation_key, None, None);
        } else {
            self.deletion_excluded.insert(state.profile_uuid.clone());
        }
        let stored = outcome.clone();
        self.opened
            .get_mut(&opened.id)
            .expect("opened state exists")
            .release = Some((cause, stored));
        match outcome {
            Ok(()) => ReleaseResult::Released,
            Err(error) => ReleaseResult::Closed(error),
        }
    }

    fn release_disposable(&mut self, state: &OpenedState) -> Result<(), ProfileOutcome> {
        let record = self
            .registry
            .record_for_by_uuid(&state.profile_uuid)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_release_record_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        let lock =
            self.registry
                .acquire_slot_lock()
                .map_err(|_| ProfileOutcome::StorageUnavailable {
                    reason_code: "profile_disposable_release_lock_unavailable",
                    origin: FailureOrigin::RegistryOrStorage,
                })?;
        let proof = LivenessObservation::all_absent(record.generation, record.generation);
        let fence = DeletionFence::held(record.generation);
        if !proof.proves_absence(record.generation, fence.generation) || !fence.active {
            drop(lock);
            return Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_release_liveness_unproven",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        let handle = self
            .registry
            .root
            .open_target(Path::new(&record.target))
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_release_directory_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        if self.registry.config.deletion_failure_after_start {
            self.registry
                .mark_deletion_failed_locked(&record)
                .map_err(|_| ProfileOutcome::StorageUnavailable {
                    reason_code: "profile_disposable_release_deletion_mark_failed",
                    origin: FailureOrigin::RegistryOrStorage,
                })?;
            return Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_release_deletion_failed",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        handle
            .remove_recursive()
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_release_directory_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        self.registry
            .remove_record_locked(&record.transaction_id)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_release_record_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
    }

    fn release_durable(&self, state: &OpenedState) -> Result<(), ProfileOutcome> {
        self.registry
            .update_record(&state.project_id, |record| {
                if record.profile_uuid != state.profile_uuid {
                    return Err(RegistryError::Conflict);
                }
                release_attachment(record);
                Ok(())
            })
            .map(|_| ())
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_durable_release_record_update_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
    }

    /// Explicit deletion proof used by recovery and conformance fixtures.  It
    /// refuses partial or stale provider observations before the first delete.
    pub fn delete_disposable_with_proof(
        &mut self,
        profile_uuid: &str,
        observation: LivenessObservation,
        fence: DeletionFence,
    ) -> Result<(), ProfileOutcome> {
        let record = self
            .registry
            .record_for_by_uuid(profile_uuid)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_record_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        if record.kind != ProfileKind::Disposable {
            return Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_kind_mismatch",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        if !observation.proves_absence(record.generation, fence.generation) || !fence.active {
            return Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_liveness_unproven",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        let _lock =
            self.registry
                .acquire_slot_lock()
                .map_err(|_| ProfileOutcome::StorageUnavailable {
                    reason_code: "profile_disposable_delete_lock_unavailable",
                    origin: FailureOrigin::RegistryOrStorage,
                })?;
        let handle = self
            .registry
            .root
            .open_target(Path::new(&record.target))
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_directory_unavailable",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        if self.registry.config.deletion_failure_after_start {
            self.deletion_excluded.insert(profile_uuid.to_string());
            self.registry
                .mark_deletion_failed_locked(&record)
                .map_err(|_| ProfileOutcome::StorageUnavailable {
                    reason_code: "profile_disposable_delete_deletion_mark_failed",
                    origin: FailureOrigin::RegistryOrStorage,
                })?;
            return Err(ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            });
        }
        handle
            .remove_recursive()
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_directory_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })?;
        self.registry
            .remove_record_locked(&record.transaction_id)
            .map_err(|_| ProfileOutcome::StorageUnavailable {
                reason_code: "profile_disposable_delete_record_delete_failed",
                origin: FailureOrigin::RegistryOrStorage,
            })
    }

    pub fn recover_startup(&mut self) -> Result<usize, RegistryError> {
        if !self.registry.artifact_enabled() {
            return Ok(0);
        }
        // A root with no registry has nothing to recover.
        let Some(document) = self.registry.read_document()? else {
            return Ok(0);
        };
        let mut recovered = 0;
        for record in document.records.values() {
            if record.state == ProfileState::DeletionFailed || record.deletion_pending {
                self.deletion_excluded.insert(record.profile_uuid.clone());
            }
            if record.state == ProfileState::Attached && record.process.is_none() {
                self.registry.mark_unavailable(record)?;
                self.deletion_excluded.insert(record.profile_uuid.clone());
                recovered += 1;
            } else if record.state == ProfileState::Attached
                && self.recover_attachment(record)?.is_some()
            {
                recovered += 1;
            }
        }
        Ok(recovered)
    }

    /// Re-read the attachment and its kernel-generation evidence while holding
    /// the registry slot. The registry's `s8-<handle>` start token names a local
    /// attachment, not a kernel process start time, so it cannot rule out pid
    /// reuse. A missing or unreadable custody journal leaves the attachment busy.
    fn recover_attachment(
        &self,
        original: &RegistryRecord,
    ) -> Result<Option<RegistryRecord>, RegistryError> {
        use crate::profile_custody::{
            current_supervisor_generation, recorded_profile_supervisor, SupervisorLiveness,
        };
        let _slot = self.registry.acquire_slot_lock()?;
        let Some(document) = self.registry.read_document()? else {
            return Ok(None);
        };
        let Some((key, record)) = document
            .records
            .iter()
            .find(|(_, record)| record.profile_uuid == original.profile_uuid)
        else {
            return Ok(None);
        };
        if record.state != ProfileState::Attached
            || record.process != original.process
            || record.attachment_id != original.attachment_id
            || record.generation != original.generation
        {
            return Ok(None);
        }
        let Some(process) = &record.process else {
            return Ok(None);
        };
        let directory = self.registry.profile_target(&record.target, false)?;
        let Ok(Some(owner)) = recorded_profile_supervisor(
            self.registry.root().canonical_path(),
            &directory,
            process.pid,
        ) else {
            return Ok(None);
        };
        let Ok(current) = current_supervisor_generation() else {
            return Ok(None);
        };
        if owner == current
            || self.attachment_liveness.0.observe(owner) != SupervisorLiveness::NotLive
        {
            return Ok(None);
        }
        self.registry
            .update_record_by_key_locked(key, |record| {
                release_attachment(record);
                record.deletion_pending = record.kind == ProfileKind::Disposable;
                Ok(())
            })
            .map(Some)
    }
}

fn handle_namespace(root: &HeldManagedRoot) -> u64 {
    let entropy = format!(
        "{}:{:?}",
        root.canonical_path().display(),
        SystemTime::now()
    );
    let digest = Sha256::digest(entropy.as_bytes());
    u64::from_be_bytes(digest[0..8].try_into().expect("digest has eight bytes"))
}

fn disposition_kind(disposition: ProfileDisposition) -> ProfileKind {
    match disposition {
        ProfileDisposition::Durable => ProfileKind::Durable,
        ProfileDisposition::Disposable => ProfileKind::Disposable,
        ProfileDisposition::None => ProfileKind::Disposable,
    }
}

impl ProfileRegistry {
    fn record_for_by_uuid(&self, profile_uuid: &str) -> Result<RegistryRecord, RegistryError> {
        let document = self.read_document()?.ok_or(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::MissingRegistry,
        ))?;
        document
            .records
            .values()
            .find(|record| record.profile_uuid == profile_uuid)
            .cloned()
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::MissingProfileUuid,
            ))
    }
    fn remove_record(&self, key: &str) -> Result<(), RegistryError> {
        let _lock = self.acquire_slot_lock()?;
        self.remove_record_locked(key)
    }

    fn remove_record_locked(&self, key: &str) -> Result<(), RegistryError> {
        let mut document = self.read_document()?.ok_or(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::IntegrityMismatch,
        ))?;
        document
            .records
            .remove(key)
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::MissingRecord,
            ))?;
        document.generation = document.generation.saturating_add(1);
        self.write_document(document)
    }
    fn mark_deletion_failed(&self, original: &RegistryRecord) -> Result<(), RegistryError> {
        let _lock = self.acquire_slot_lock()?;
        self.mark_deletion_failed_locked(original)
    }

    fn mark_deletion_failed_locked(&self, original: &RegistryRecord) -> Result<(), RegistryError> {
        self.update_record_by_key_locked(&original.transaction_id, |record| {
            if record.kind != ProfileKind::Disposable {
                return Err(RegistryError::UnsupportedState);
            }
            record.state = ProfileState::DeletionFailed;
            record.deletion_pending = true;
            record.quarantine = Some(QuarantineReason::DeletionFailed);
            Ok(())
        })
        .map(|_| ())
    }
    fn mark_unavailable(&self, original: &RegistryRecord) -> Result<(), RegistryError> {
        self.update_record_by_key(&original.transaction_id, |record| {
            record.state = ProfileState::Unavailable;
            record.quarantine = Some(QuarantineReason::LivenessUnavailable);
            Ok(())
        })
        .map(|_| ())
    }
    fn update_record_by_key<F>(&self, key: &str, update: F) -> Result<RegistryRecord, RegistryError>
    where
        F: FnMut(&mut RegistryRecord) -> Result<(), RegistryError>,
    {
        let _lock = self.acquire_slot_lock()?;
        self.update_record_by_key_locked(key, update)
    }

    fn update_record_by_key_locked<F>(
        &self,
        key: &str,
        mut update: F,
    ) -> Result<RegistryRecord, RegistryError>
    where
        F: FnMut(&mut RegistryRecord) -> Result<(), RegistryError>,
    {
        let mut document = self.read_document()?.ok_or(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::IntegrityMismatch,
        ))?;
        let record = document
            .records
            .get_mut(key)
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::MissingRecord,
            ))?;
        update(record)?;
        record.generation = record.generation.saturating_add(1);
        record.integrity = record_integrity(record);
        let result = record.clone();
        document.generation = document.generation.saturating_add(1);
        self.write_document(document)?;
        Ok(result)
    }

    fn update_record_by_uuid<F>(
        &self,
        uuid: &str,
        mut update: F,
    ) -> Result<RegistryRecord, RegistryError>
    where
        F: FnMut(&mut RegistryRecord) -> Result<(), RegistryError>,
    {
        let _lock = self.acquire_slot_lock()?;
        let mut document = self.read_document()?.ok_or(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::IntegrityMismatch,
        ))?;
        let key = document
            .records
            .iter()
            .find_map(|(key, record)| (record.profile_uuid == uuid).then(|| key.clone()))
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::MissingProfileUuid,
            ))?;
        let record = document
            .records
            .get_mut(&key)
            .ok_or(RegistryError::Untrustworthy(
                UntrustworthyRegistryReason::IntegrityMismatch,
            ))?;
        update(record)?;
        record.generation = record.generation.saturating_add(1);
        record.integrity = record_integrity(record);
        let result = record.clone();
        document.generation = document.generation.saturating_add(1);
        self.write_document(document)?;
        Ok(result)
    }
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(TABLE[(byte >> 4) as usize] as char);
        output.push(TABLE[(byte & 0xf) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests;
