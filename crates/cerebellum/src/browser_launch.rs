//! Crash-safe browser process creation through the durable journal.
//!
//! This module owns ordering and policy. Platform code returns process and
//! code-signing facts; the journal decides whether release may be reached.

#[cfg(target_os = "linux")]
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use cerebellum_core::journal::{
    CompletedResult, DispatchCommitmentToken as CoreDispatchCommitmentToken, DispatchMaterial,
    EncodedJournalState, FinalContextAssociation, JournalBinding, JournalCodecError,
    JournalConfig as CoreJournalConfig, JournalError as CoreJournalError, JournalIdentity,
    JournalStorage, PlaneJournalCodec, ProvisionalInput, RejectionInput, RejectionMaterial,
    UnavailablePolicy,
};
use serde::{Deserialize, Serialize};

pub use crate::browser_launch_readiness::*;
use crate::profile_custody::{
    classify_process_generation, GenerationObservation, StartTimeStability, SupervisorLiveness,
};

const GENERATION_SLOT: &str = "browser.launch.generation";
const ATTESTATION_SLOT: &str = "browser.launch.attestation";
/// Version 4 added `boot_id` to the process generation. When present, the
/// generation's start time is clock ticks since that boot, not epoch microseconds.
const LAUNCH_CODEC_VERSION: &str = "ck-browser-launch-attestation/v4";
const V3_LAUNCH_CODEC_VERSION: &str = "ck-browser-launch-attestation/v3";
const V2_LAUNCH_CODEC_VERSION: &str = "ck-browser-launch-attestation/v2";
const LEGACY_LAUNCH_CODEC_VERSION: &str = "ck-browser-launch-attestation/v1";

/// Exact route facts authorized for one launch attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchRouteIdentity {
    pub principal: String,
    pub conversation_key: String,
    pub agent_project_id: String,
    pub session_kind: cerebellum_core::identity::SessionKind,
}

/// Profile selected by trusted route identity and profile preparation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchProfileIdentity {
    pub profile_uuid: String,
    #[serde(with = "cerebellum_core::serde_base64::bytes_compat")]
    pub canonical_profile_path: Vec<u8>,
    pub disposition: cerebellum_core::identity::ProfileDisposition,
}

/// Guarantee established for the executable selected by launch policy.
///
/// A code-signing claim is an authenticated assertion by the signer, while an
/// image digest establishes only byte equality with a previously pinned image.
/// Keeping those guarantees as distinct variants prevents a digest from being
/// presented to a refusal caller as though it carried signing authenticity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutableIdentityClaim {
    CodeSigned {
        signing_identifier: String,
        unique_code_hash: String,
    },
    ImageDigest {
        sha256: String,
    },
}

impl ExecutableIdentityClaim {
    pub const fn claim_kind(&self) -> &'static str {
        match self {
            Self::CodeSigned { .. } => "code_signed",
            Self::ImageDigest { .. } => "image_digest",
        }
    }

    /// Whether this observed claim satisfies the configured identity.
    ///
    /// Lives on the claim rather than at the verifier, so that each kind states
    /// its own comparison and a kind added later must state one too. A match
    /// written at a call site needs a catch-all, a catch-all answers `false`,
    /// and `false` here means MISMATCH -- so an unhandled kind would be
    /// reported as "the identity differed" when the truth is that nothing
    /// compared it. That is the collapse this module has removed three times.
    ///
    /// Comparing a digest is not the same as producing one: Linux reads mapped
    /// images and attests the first image whose digest matches the configured
    /// identity. The configured digest must name the final binary: pinning a
    /// wrapper's digest attests and releases that wrapper before it can exec
    /// the real browser outside this barrier.
    pub fn matches_configured(&self, expected: &str) -> bool {
        match self {
            Self::CodeSigned {
                signing_identifier, ..
            } => expected == signing_identifier || expected == self.display_identity(),
            Self::ImageDigest { sha256 } => {
                expected == sha256 || expected == self.display_identity()
            }
        }
    }

    /// Render the platform identity for human-readable logs.
    pub fn display_identity(&self) -> String {
        match self {
            Self::CodeSigned {
                signing_identifier,
                unique_code_hash,
            } => format!("identifier={signing_identifier};cdhash={unique_code_hash}"),
            Self::ImageDigest { sha256 } => format!("sha256={sha256}"),
        }
    }
}

/// What was verified about the executable FILE before any process was created.
///
/// Deliberately not the same type as [`ExecutableIdentityClaim`], because the
/// two answer different questions: a file on disk versus the image mapped into
/// a running process. One macOS file can carry several signed architecture
/// slices, each with its own code hash, and the kernel decides which slice a
/// new process executes -- arm64e is reserved for platform binaries, and some
/// chips run a further subtype of it. Predicting that choice here would be a
/// copy of kernel policy that drifts without anyone noticing, so the pre-spawn
/// read collects EVERY slice of the file and the after-exec check asks only
/// whether the image that actually ran is one of them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "claim_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VerifiedExecutableIdentity {
    /// Every signed slice of a code-signed file, read before spawn.
    ///
    /// The serialized tag stays `code_signed` and the hash field accepts the
    /// single `unique_code_hash` string earlier records wrote, so a launch
    /// journal written before this module read slices still decodes; such a
    /// record simply verified one slice.
    #[serde(rename = "code_signed")]
    CodeSignedFile {
        signing_identifier: String,
        #[serde(
            alias = "unique_code_hash",
            deserialize_with = "deserialize_slice_code_hashes"
        )]
        slice_code_hashes: BTreeSet<String>,
    },
    /// Byte equality with a previously pinned image. A digest names one file's
    /// exact bytes, so there is no per-slice question to ask.
    ImageDigest { sha256: String },
}

/// Accept either the set this module writes or the single hash older records
/// carry, so one stored shape does not have to be migrated to be readable.
fn deserialize_slice_code_hashes<'de, D>(deserializer: D) -> Result<BTreeSet<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrSeveral {
        One(String),
        Several(BTreeSet<String>),
    }

    Ok(match OneOrSeveral::deserialize(deserializer)? {
        OneOrSeveral::One(hash) => BTreeSet::from([hash]),
        OneOrSeveral::Several(hashes) => hashes,
    })
}

impl VerifiedExecutableIdentity {
    pub const fn claim_kind(&self) -> &'static str {
        match self {
            Self::CodeSignedFile { .. } => "code_signed",
            Self::ImageDigest { .. } => "image_digest",
        }
    }

    /// Whether the image a process actually executed is one of the slices this
    /// file was verified to carry before spawn.
    ///
    /// Membership in the set read from THIS file, not signer equality: a file
    /// swapped between the pre-spawn read and exec is signed by whoever
    /// swapped it, and its code hashes are outside the set even when it keeps
    /// the same signing identifier. Both halves are required, so neither an
    /// unrelated program that happens to share a code hash nor a differently
    /// signed image with a familiar identifier is admitted.
    ///
    /// The kind pairs are written out rather than ending in a catch-all,
    /// because a catch-all answers `false`, `false` here means "the identity
    /// differed", and a kind added later would be reported as a mismatch when
    /// the truth is that nothing compared it.
    pub fn admits(&self, executed: &ExecutableIdentityClaim) -> bool {
        match (self, executed) {
            (
                Self::CodeSignedFile {
                    signing_identifier,
                    slice_code_hashes,
                },
                ExecutableIdentityClaim::CodeSigned {
                    signing_identifier: executed_identifier,
                    unique_code_hash,
                },
            ) => {
                signing_identifier == executed_identifier
                    && slice_code_hashes.contains(unique_code_hash)
            }
            (
                Self::ImageDigest { sha256 },
                ExecutableIdentityClaim::ImageDigest {
                    sha256: executed_sha256,
                },
            ) => sha256 == executed_sha256,
            (Self::CodeSignedFile { .. }, ExecutableIdentityClaim::ImageDigest { .. })
            | (Self::ImageDigest { .. }, ExecutableIdentityClaim::CodeSigned { .. }) => false,
        }
    }

    /// Whether this verified file satisfies the configured identity.
    ///
    /// Configuration pins a signer or a digest, never a slice: which slices a
    /// signed file carries is a property of the build, and an operator who had
    /// to list them would be re-pinning the browser on every universal update.
    pub fn matches_configured(&self, expected: &str) -> bool {
        match self {
            Self::CodeSignedFile {
                signing_identifier, ..
            } => expected == signing_identifier || expected == self.display_identity(),
            Self::ImageDigest { sha256 } => {
                expected == sha256 || expected == self.display_identity()
            }
        }
    }

    /// Render the verified file identity for human-readable logs and refusals.
    pub fn display_identity(&self) -> String {
        match self {
            Self::CodeSignedFile {
                signing_identifier,
                slice_code_hashes,
            } => format!(
                "identifier={signing_identifier};cdhashes={{{}}}",
                slice_code_hashes
                    .iter()
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            Self::ImageDigest { sha256 } => format!("sha256={sha256}"),
        }
    }
}

/// One executable image observed during an identity walk.
///
/// The path is diagnostic context for a human reading a refusal; it is never
/// part of identity and must not participate in any comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentityRecord {
    pub claim: ExecutableIdentityClaim,
    pub path: Option<PathBuf>,
}

impl PartialEq for ExecutableIdentityRecord {
    fn eq(&self, other: &Self) -> bool {
        self.claim == other.claim
    }
}

impl Eq for ExecutableIdentityRecord {}

/// Completeness of an executable identity walk, independent of vector length.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "completeness", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExecutableIdentityChain {
    /// The walk ended at an image matching the configured identity.
    WalkedToMatch { hops: Vec<ExecutableIdentityRecord> },
    /// The walk stopped at its hop bound before finding a matching image.
    StoppedAtHopLimit { hops: Vec<ExecutableIdentityRecord> },
    /// No walk was performed; the platform supplied one post-exec attestation.
    NoWalkPerformed {
        attestation: ExecutableIdentityRecord,
    },
}

impl ExecutableIdentityChain {
    fn matched_claim(&self) -> Option<&ExecutableIdentityClaim> {
        match self {
            Self::WalkedToMatch { hops } => hops.last().map(|hop| &hop.claim),
            Self::StoppedAtHopLimit { .. } => None,
            Self::NoWalkPerformed { attestation } => Some(&attestation.claim),
        }
    }
}

/// Executable identity checks completed before returning a successful browser launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutableIdentityCheckpoints {
    /// The configured executable's identity matched before spawning, and the
    /// image mapped into the new process matched again before it could run.
    BeforeSpawnAndAfterExec,
    /// The executable image could not be identified before spawning, so only
    /// the image mapped into the new process established identity before it ran.
    AfterExecOnly,
}

/// Whether launch preparation established executable identity before spawning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreSpawnIdentityVerification {
    Established,
    Unavailable,
}

impl PreSpawnIdentityVerification {
    fn completed_by_after_exec(self) -> ExecutableIdentityCheckpoints {
        match self {
            Self::Established => ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
            Self::Unavailable => ExecutableIdentityCheckpoints::AfterExecOnly,
        }
    }
}

/// The bytes of an `OsStr` as this platform represents them.
///
/// Deliberately platform-specific rather than normalised. These bytes are
/// attested: they record what was handed to the platform launcher, so a
/// conversion that made every platform agree would be recording a translation
/// rather than the submission. Unix hands the kernel bytes; Windows hands it
/// UTF-16 code units, and encoding those little-endian preserves the argument
/// exactly, including the unpaired surrogates a lossy conversion would destroy.
///
/// A reader therefore needs to know which platform produced a record before
/// interpreting its bytes. Nothing ships on Windows yet, so no ambiguous record
/// can exist; declaring the encoding in the record itself is a format change to
/// settle before one can.
fn os_bytes(value: &std::ffi::OsStr) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        value.as_bytes().to_vec()
    }
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;
        value.encode_wide().flat_map(u16::to_le_bytes).collect()
    }
}

/// The exact executable and argument bytes submitted to the platform launcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedLaunchVector {
    #[serde(with = "cerebellum_core::serde_base64::bytes_compat")]
    pub executable: Vec<u8>,
    #[serde(with = "cerebellum_core::serde_base64::byte_strings_compat")]
    pub arguments: Vec<Vec<u8>>,
    #[serde(with = "cerebellum_core::serde_base64::byte_string_pairs_compat")]
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
}

impl VerifiedLaunchVector {
    pub fn new(
        executable: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> Self {
        Self {
            executable: os_bytes(executable.as_os_str()),
            arguments: arguments
                .iter()
                .map(|argument| os_bytes(argument.as_os_str()))
                .collect(),
            environment: environment
                .iter()
                .map(|(name, value)| (os_bytes(name.as_os_str()), os_bytes(value.as_os_str())))
                .collect(),
        }
    }
}

/// Durable pre-effect record. This is committed before process creation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedLaunchIntent {
    pub format_version: String,
    pub launch_attempt_id: String,
    pub holder_id: String,
    pub route: LaunchRouteIdentity,
    pub profile: LaunchProfileIdentity,
    pub verified_executable_identity: VerifiedExecutableIdentity,
    pub launch_vector: VerifiedLaunchVector,
}

/// Exact process generation obtained from the kernel after suspended creation.
///
/// The field keeps its historical name, but `boot_id` decides its unit: with a
/// boot ID (Linux, from format version 4) it is clock ticks from that boot to
/// the process's creation; without one (macOS, and every earlier record) it is
/// microseconds since the Unix epoch. Readers only compare it for equality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserProcessGeneration {
    pub pid: u32,
    pub start_time_micros: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boot_id: Option<crate::profile_custody::BootId>,
}

#[cfg(target_os = "linux")]
impl From<cerebellum_linux::ProcessGeneration> for BrowserProcessGeneration {
    fn from(generation: cerebellum_linux::ProcessGeneration) -> Self {
        Self {
            pid: generation.pid,
            start_time_micros: generation.start_ticks,
            boot_id: Some(crate::profile_custody::BootId::from_bytes(
                generation.boot_id,
            )),
        }
    }
}

#[cfg(target_os = "macos")]
impl From<cerebellum_macos::ProcessGeneration> for BrowserProcessGeneration {
    fn from(generation: cerebellum_macos::ProcessGeneration) -> Self {
        Self {
            pid: generation.pid,
            start_time_micros: generation.start_time_micros,
            boot_id: None,
        }
    }
}

/// Durable generation-stage record written while the process remains barred.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchGenerationRecord {
    pub intent: AuthorizedLaunchIntent,
    pub process_generation: BrowserProcessGeneration,
}

/// Full attestation committed before the release byte can be sent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchAttestationRecord {
    pub generation: LaunchGenerationRecord,
    pub observed_executable_identity: ExecutableIdentityClaim,
    pub executable_identity_chain: ExecutableIdentityChain,
    pub executable_identity_checkpoints: ExecutableIdentityCheckpoints,
}

/// Durable result recorded when the launched browser session ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSessionCompletion {
    pub format_version: String,
    pub launch_attempt_id: String,
    pub terminal_outcome: crate::browser_session::BrowserSessionTerminalOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<crate::browser_launch_readiness::ProfileStartupIndeterminate>,
}

impl LaunchSessionCompletion {
    fn new(
        launch_attempt_id: &str,
        terminal_outcome: crate::browser_session::BrowserSessionTerminalOutcome,
    ) -> Self {
        Self {
            format_version: LAUNCH_CODEC_VERSION.to_string(),
            launch_attempt_id: launch_attempt_id.to_string(),
            terminal_outcome,
            failure: None,
        }
    }
}

/// What startup learned about the process named by one active launch record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredBrowserProcess {
    TerminatedAndReaped,
    StartTimeMismatch,
    NotRunning,
    Unattested,
}

/// Exact successful result for one record consumed by startup recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLaunchRecoveryOutcome {
    pub sequence: u64,
    pub process: RecoveredBrowserProcess,
    pub journal_action: cerebellum_core::journal::RecoveryAction,
}

/// The first failed obligation from a pass that still attempts every independent
/// cleanup resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserLaunchRecoveryFailure {
    JournalOpen,
    JournalRead { sequence: u64 },
    ProcessObservation { sequence: u64 },
    ProcessTermination { sequence: u64 },
    JournalTerminalization,
    ProfileCustodyRelease { sequence: u64 },
    InvalidIntent { sequence: u64 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrphanProcessControlFailure;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OrphanProfileCustodyFailure;

/// Kernel observation and process control used by startup recovery.
///
/// The orchestrator calls `terminate_and_reap` only after
/// [`crate::profile_custody::classify_process_generation`] finds the observed
/// generation to be exactly the recorded one. Implementations should repeat
/// that decision as close to signaling as the platform allows, so a PID reuse
/// between the two calls is refused too.
pub trait OrphanBrowserProcessControl {
    fn observed_start_time_micros(
        &mut self,
        pid: u32,
    ) -> Result<Option<u64>, OrphanProcessControlFailure>;

    /// Observe `generation.pid` in the unit `generation` was recorded in.
    ///
    /// The default reports [`Self::observed_start_time_micros`] as a start
    /// time fixed at creation, which is what macOS reports. A platform whose
    /// start time moves with the wall clock, or that records a boot ID, must
    /// override this: the default cannot compare a boot-and-ticks record and
    /// answers it `Unavailable`.
    fn observe_generation(
        &mut self,
        generation: BrowserProcessGeneration,
    ) -> GenerationObservation {
        match self.observed_start_time_micros(generation.pid) {
            Ok(Some(start_time)) => GenerationObservation::StartTime {
                start_time,
                stability: StartTimeStability::ClockStable,
            },
            Ok(None) => GenerationObservation::Absent,
            Err(OrphanProcessControlFailure) => GenerationObservation::Unreadable,
        }
    }
    fn terminate_and_reap(
        &mut self,
        generation: BrowserProcessGeneration,
    ) -> Result<(), OrphanProcessControlFailure>;
}

/// Release the exact profile claim identified by durable launch intent.
pub trait OrphanProfileCustody {
    fn release(
        &mut self,
        intent: &AuthorizedLaunchIntent,
    ) -> Result<(), OrphanProfileCustodyFailure>;
}

#[derive(Debug, Clone)]
struct ActiveLaunchAttempt {
    sequence: u64,
    intent: Option<AuthorizedLaunchIntent>,
    attested_generation: Option<BrowserProcessGeneration>,
}

/// Terminal mismatch record. The process is still barred when this is written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchIdentityMismatchRecord {
    pub generation: LaunchGenerationRecord,
    pub claim_kind: String,
    pub expected_identity: String,
    pub observed_identity: String,
}

/// Inputs whose route, profile, executable, arguments, and environment have
/// already been authorized before process creation begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedLaunchRequest {
    pub launch_attempt_id: String,
    pub holder_id: String,
    pub route: LaunchRouteIdentity,
    pub profile: LaunchProfileIdentity,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub verified_executable_identity: VerifiedExecutableIdentity,
    pub pre_spawn_identity_verification: PreSpawnIdentityVerification,
}

impl AttestedLaunchRequest {
    fn durable_intent(&self) -> AuthorizedLaunchIntent {
        AuthorizedLaunchIntent {
            format_version: LAUNCH_CODEC_VERSION.to_string(),
            launch_attempt_id: self.launch_attempt_id.clone(),
            holder_id: self.holder_id.clone(),
            route: self.route.clone(),
            profile: self.profile.clone(),
            verified_executable_identity: self.verified_executable_identity.clone(),
            launch_vector: VerifiedLaunchVector::new(
                &self.executable,
                &self.arguments,
                &self.environment,
            ),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchRecordStage {
    Intent,
    Generation,
    Attestation,
    IdentityMismatch,
}

/// Closed orchestration outcomes. Platform and storage details remain internal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttestedLaunchError {
    JournalRecordFailed {
        stage: LaunchRecordStage,
    },
    SpawnFailed,
    PlatformRefused {
        error: PlatformLaunchError,
    },
    ImageAttestationFailed {
        expected_identity: String,
    },
    ExecutableIdentityMismatch {
        claim_kind: String,
        expected_identity: String,
        observed_identity: String,
    },
    TerminationOrReapFailed,
    ReleaseFailed,
}

/// Journal operations needed by the ordering state machine.
pub trait LaunchJournalPort {
    type Handle;

    fn finalize_startup_failure(
        &mut self,
        launch_attempt_id: &str,
        failure: &crate::browser_launch_readiness::ProfileStartupIndeterminate,
    ) -> Result<(), CoreJournalError>;

    fn record_intent(
        &mut self,
        intent: &AuthorizedLaunchIntent,
    ) -> Result<Self::Handle, CoreJournalError>;
    fn record_generation(
        &mut self,
        handle: &mut Self::Handle,
        record: &LaunchGenerationRecord,
    ) -> Result<(), CoreJournalError>;
    fn commit_attestation(
        &mut self,
        handle: &mut Self::Handle,
        record: &LaunchAttestationRecord,
    ) -> Result<(), CoreJournalError>;
    fn record_identity_mismatch(
        &mut self,
        handle: &mut Self::Handle,
        record: &LaunchIdentityMismatchRecord,
    ) -> Result<(), CoreJournalError>;
}

/// Platform operation classes remain facts; orchestration maps them to its
/// closed launch outcomes without exposing operating-system details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformLaunchError {
    Spawn,
    ImageIdentity,
    ProcessControl,
    PtraceUnavailable,
    ExecChainUnresolved { chain: ExecutableIdentityChain },
    GenerationUnreadable,
    UnexpectedStop { signal: i32 },
    SignalStopLimitExceeded { last_signal: i32, limit: usize },
}

impl PlatformLaunchError {
    pub fn refusal(self) -> serde_json::Value {
        let (reason_code, remedy) = match self {
            Self::PtraceUnavailable => (
                "ptrace_unavailable",
                "grant CAP_SYS_PTRACE or lower ptrace_scope, then retry the launch".to_string(),
            ),
            Self::ExecChainUnresolved { .. } => (
                "exec_chain_unresolved",
                "configure the final executable image digest, then retry the launch".to_string(),
            ),
            Self::GenerationUnreadable => (
                "generation_unreadable",
                "restore readable procfs start-time access, then retry the launch".to_string(),
            ),
            Self::UnexpectedStop { signal } => (
                "unexpected_process_stop",
                format!("inspect unexpected process stop signal {signal}, then retry the launch"),
            ),
            Self::SignalStopLimitExceeded { last_signal, limit } => (
                "signal_stop_limit_exceeded",
                format!(
                    "inspect the signal storm after {limit} stops (last signal {last_signal}), then retry the launch"
                ),
            ),
            Self::Spawn | Self::ImageIdentity | Self::ProcessControl => (
                "platform_launch_failed",
                "inspect the platform launch failure and retry after correcting it".to_string(),
            ),
        };
        serde_json::json!({
            "outcome": "launch_refused",
            "reason_code": reason_code,
            "remedy": remedy,
        })
    }
}

/// A barred process exposes facts and terminal controls, not launch policy.
pub trait BarredLaunchProcess: Sized {
    type Released;

    fn generation(&self) -> BrowserProcessGeneration;
    fn executed_image_identity(&self) -> Result<ExecutableIdentityChain, PlatformLaunchError>;
    fn terminate_and_reap(self) -> Result<(), PlatformLaunchError>;
    fn release(self) -> Result<Self::Released, PlatformLaunchError>;
}

pub trait BarredProcessLauncher {
    type Process: BarredLaunchProcess;

    fn spawn_barred(
        &mut self,
        request: &AttestedLaunchRequest,
    ) -> Result<Self::Process, PlatformLaunchError>;
}

/// A released process paired with the exact durable attestation that authorized it.
pub struct ReleasedAttestedBrowser<P> {
    pub attestation: LaunchAttestationRecord,
    pub observed_executable_identity_chain: ExecutableIdentityChain,
    pub process: P,
    /// Monotonic instant sampled immediately after the barrier release returns.
    pub released_at: std::time::Instant,
}

/// Execute the crash-safe ordering state machine.
///
/// The call site deliberately uses a death-pipe guardian plus macOS suspended
/// spawn rather than a pathname check followed by ordinary `exec`. The target is
/// stopped before its first user-space instruction, so Security.framework can
/// attest the image the kernel actually mapped. Until release, EOF on the
/// guardian's pipe kills and reaps that target instead of resuming it.
pub fn launch_attested_with<J, L>(
    journal: &mut J,
    launcher: &mut L,
    request: &AttestedLaunchRequest,
) -> Result<
    ReleasedAttestedBrowser<<L::Process as BarredLaunchProcess>::Released>,
    AttestedLaunchError,
>
where
    J: LaunchJournalPort,
    L: BarredProcessLauncher,
{
    launch_attested_with_release_clock(journal, launcher, request, std::time::Instant::now)
}

pub(crate) fn launch_attested_with_release_clock<J, L, F>(
    journal: &mut J,
    launcher: &mut L,
    request: &AttestedLaunchRequest,
    mut released_at: F,
) -> Result<
    ReleasedAttestedBrowser<<L::Process as BarredLaunchProcess>::Released>,
    AttestedLaunchError,
>
where
    J: LaunchJournalPort,
    L: BarredProcessLauncher,
    F: FnMut() -> std::time::Instant,
{
    let intent = request.durable_intent();
    let mut handle =
        journal
            .record_intent(&intent)
            .map_err(|_| AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Intent,
            })?;

    let child = launcher
        .spawn_barred(request)
        .map_err(|error| match error {
            PlatformLaunchError::PtraceUnavailable
            | PlatformLaunchError::ExecChainUnresolved { .. }
            | PlatformLaunchError::GenerationUnreadable => {
                AttestedLaunchError::PlatformRefused { error }
            }
            _ => AttestedLaunchError::SpawnFailed,
        })?;
    let generation = LaunchGenerationRecord {
        intent,
        process_generation: child.generation(),
    };
    if journal.record_generation(&mut handle, &generation).is_err() {
        return match child.terminate_and_reap() {
            Ok(()) => Err(AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Generation,
            }),
            Err(_) => Err(AttestedLaunchError::TerminationOrReapFailed),
        };
    }

    let observed_chain = match child.executed_image_identity() {
        Ok(chain) => chain,
        Err(
            error @ (PlatformLaunchError::PtraceUnavailable
            | PlatformLaunchError::ExecChainUnresolved { .. }
            | PlatformLaunchError::GenerationUnreadable),
        ) => {
            let _ = child.terminate_and_reap();
            return Err(AttestedLaunchError::PlatformRefused { error });
        }
        Err(_) => {
            let expected_identity = request.verified_executable_identity.display_identity();
            return match child.terminate_and_reap() {
                Ok(()) => Err(AttestedLaunchError::ImageAttestationFailed { expected_identity }),
                Err(_) => Err(AttestedLaunchError::TerminationOrReapFailed),
            };
        }
    };

    let Some(observed) = observed_chain.matched_claim().cloned() else {
        let expected_identity = request.verified_executable_identity.display_identity();
        return match child.terminate_and_reap() {
            Ok(()) => Err(AttestedLaunchError::ImageAttestationFailed { expected_identity }),
            Err(_) => Err(AttestedLaunchError::TerminationOrReapFailed),
        };
    };

    if !request.verified_executable_identity.admits(&observed) {
        let mismatch = LaunchIdentityMismatchRecord {
            generation,
            claim_kind: request
                .verified_executable_identity
                .claim_kind()
                .to_string(),
            expected_identity: request.verified_executable_identity.display_identity(),
            observed_identity: observed.display_identity(),
        };
        let record_result = journal.record_identity_mismatch(&mut handle, &mismatch);
        let terminate_result = child.terminate_and_reap();
        if terminate_result.is_err() {
            return Err(AttestedLaunchError::TerminationOrReapFailed);
        }
        if record_result.is_err() {
            return Err(AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::IdentityMismatch,
            });
        }
        return Err(AttestedLaunchError::ExecutableIdentityMismatch {
            claim_kind: mismatch.claim_kind,
            expected_identity: mismatch.expected_identity,
            observed_identity: mismatch.observed_identity,
        });
    }

    let attestation = LaunchAttestationRecord {
        generation,
        observed_executable_identity: observed,
        executable_identity_chain: observed_chain.clone(),
        executable_identity_checkpoints: request
            .pre_spawn_identity_verification
            .completed_by_after_exec(),
    };
    if journal
        .commit_attestation(&mut handle, &attestation)
        .is_err()
    {
        return match child.terminate_and_reap() {
            Ok(()) => Err(AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Attestation,
            }),
            Err(_) => Err(AttestedLaunchError::TerminationOrReapFailed),
        };
    }

    let process = child.release().map_err(|error| {
        if matches!(
            error,
            PlatformLaunchError::PtraceUnavailable
                | PlatformLaunchError::ExecChainUnresolved { .. }
                | PlatformLaunchError::GenerationUnreadable
        ) {
            AttestedLaunchError::PlatformRefused { error }
        } else {
            AttestedLaunchError::ReleaseFailed
        }
    })?;
    Ok(ReleasedAttestedBrowser {
        attestation,
        observed_executable_identity_chain: observed_chain,
        process,
        released_at: released_at(),
    })
}

/// Codec for launch records carried as opaque bytes by the shared journal.
#[derive(Debug, Clone, Copy, Default)]
pub struct LaunchJournalCodec;

impl LaunchJournalCodec {
    fn encode(bytes: &[u8]) -> Result<EncodedJournalState, JournalCodecError> {
        if bytes.is_empty() {
            return Err(JournalCodecError::DescriptorRefused);
        }
        Ok(EncodedJournalState {
            durable_bytes: bytes.to_vec(),
            accounted_serialized_size: bytes.len() as u64,
            codec_version: LAUNCH_CODEC_VERSION.to_string(),
        })
    }
}

impl PlaneJournalCodec for LaunchJournalCodec {
    fn encode_provisional(
        &self,
        input: &ProvisionalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encode(&input.invocation_descriptor)
    }

    fn encode_dispatched(
        &self,
        input: &cerebellum_core::journal::DispatchedInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encode(&input.dispatch_material)
    }

    fn encode_rejection(
        &self,
        input: &RejectionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encode(&input.rejection_material)
    }

    fn encode_completion(
        &self,
        input: &cerebellum_core::journal::CompletionInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encode(&input.completed_result)
    }

    fn encode_reduced_terminal(
        &self,
        input: &cerebellum_core::journal::ReducedTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encode(input.reason.as_str().as_bytes())
    }

    fn encode_recovery_terminal(
        &self,
        input: &cerebellum_core::journal::RecoveryTerminalInput,
    ) -> Result<EncodedJournalState, JournalCodecError> {
        Self::encode(&input.dispatch_material)
    }
}

pub type LaunchCoreJournal<S> =
    JournalBinding<LaunchJournalCodec, UnavailablePolicy, UnavailablePolicy, S>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LaunchIntentHandle {
    reservation: cerebellum_core::journal::ReservationHandle,
    attachment_revision: u64,
}

impl LaunchIntentHandle {
    pub fn sequence(self) -> u64 {
        self.reservation.sequence()
    }
}

/// Durable launch records implemented on the filesystem-backed journal substrate.
pub struct DurableLaunchJournal<S: JournalStorage> {
    core: LaunchCoreJournal<S>,
    dispatched: HashMap<String, CoreDispatchCommitmentToken>,
}

impl<S: JournalStorage> DurableLaunchJournal<S> {
    pub fn open(
        config: CoreJournalConfig,
        storage: S,
    ) -> Result<Self, cerebellum_core::journal::BindingError> {
        let core = JournalBinding::new(
            LaunchJournalCodec,
            Some(UnavailablePolicy),
            Some(UnavailablePolicy),
            config,
            storage,
        )?;
        Ok(Self {
            core,
            dispatched: HashMap::new(),
        })
    }

    pub fn finalize_session(
        &mut self,
        launch_attempt_id: &str,
        terminal_outcome: crate::browser_session::BrowserSessionTerminalOutcome,
    ) -> Result<(), CoreJournalError> {
        self.finalize_completion(LaunchSessionCompletion::new(
            launch_attempt_id,
            terminal_outcome,
        ))
    }

    fn finalize_completion(
        &mut self,
        completion: LaunchSessionCompletion,
    ) -> Result<(), CoreJournalError> {
        let launch_attempt_id = &completion.launch_attempt_id;
        let token = self
            .dispatched
            .get(launch_attempt_id)
            .copied()
            .ok_or(CoreJournalError::InvalidHandle)?;
        let bytes = serde_json::to_vec(&completion).map_err(|_| CoreJournalError::CodecFailed)?;
        self.core.finalize_dispatched(
            token,
            CompletedResult {
                completed_result: bytes.clone(),
            },
            FinalContextAssociation {
                final_context: bytes,
            },
        )?;
        self.dispatched.remove(launch_attempt_id);
        Ok(())
    }

    pub fn read_attempt(
        &self,
        sequence: u64,
    ) -> Result<cerebellum_core::journal::ObligationAuditRecord, CoreJournalError> {
        self.core.read_obligation_audit(sequence)
    }

    fn active_launch_attempts(
        &self,
    ) -> Result<Vec<ActiveLaunchAttempt>, BrowserLaunchRecoveryFailure> {
        let mut attempts = Vec::new();
        for sequence in 1..self.core.next_sequence() {
            let Some(classification) = self.core.classify(sequence) else {
                continue;
            };
            let audit = self
                .core
                .read_obligation_audit(sequence)
                .map_err(|_| BrowserLaunchRecoveryFailure::JournalRead { sequence })?;
            let intent = serde_json::from_slice::<AuthorizedLaunchIntent>(&audit.descriptor_bytes)
                .ok()
                .filter(|intent| {
                    matches!(
                        intent.format_version.as_str(),
                        LAUNCH_CODEC_VERSION
                            | V3_LAUNCH_CODEC_VERSION
                            | V2_LAUNCH_CODEC_VERSION
                            | LEGACY_LAUNCH_CODEC_VERSION
                    )
                });
            let attested_generation = if classification
                == cerebellum_core::journal::RecoveryClassification::ProvisionalDispatched
            {
                intent.as_ref().and_then(|intent| {
                    audit
                        .attachment_slots
                        .iter()
                        .find(|attachment| attachment.slot == ATTESTATION_SLOT)
                        .and_then(|attachment| {
                            serde_json::from_slice::<LaunchAttestationRecord>(
                                &attachment.opaque_bytes,
                            )
                            .ok()
                        })
                        .filter(|attestation| {
                            attestation.generation.intent == *intent
                                && intent
                                    .verified_executable_identity
                                    .admits(&attestation.observed_executable_identity)
                                // Before version 4 the start time was always
                                // epoch microseconds; a boot ID there would
                                // pair a boot with the wrong unit.
                                && (intent.format_version == LAUNCH_CODEC_VERSION
                                    || attestation
                                        .generation
                                        .process_generation
                                        .boot_id
                                        .is_none())
                        })
                        .map(|attestation| attestation.generation.process_generation)
                })
            } else {
                None
            };
            attempts.push(ActiveLaunchAttempt {
                sequence,
                intent,
                attested_generation,
            });
        }
        Ok(attempts)
    }
}

/// Reclaim every launch record left active by an earlier module process.
///
/// Process decisions are completed before the neutral journal consumes active
/// records, preserving the attestation until it has served its only authority:
/// proving whether a signal is safe. Journal and custody cleanup then both run
/// even when process control failed, because they are independent obligations
/// and one resource's failure must not silently skip another's cleanup.
pub fn recover_browser_launches<S, P, C>(
    journal: &mut DurableLaunchJournal<S>,
    process: &mut P,
    custody: &mut C,
) -> Result<Vec<BrowserLaunchRecoveryOutcome>, BrowserLaunchRecoveryFailure>
where
    S: JournalStorage,
    P: OrphanBrowserProcessControl,
    C: OrphanProfileCustody,
{
    let attempts = journal.active_launch_attempts()?;
    let mut first_failure = None;
    let mut process_outcomes = BTreeMap::new();

    for attempt in &attempts {
        let outcome = match attempt.attested_generation {
            None => RecoveredBrowserProcess::Unattested,
            Some(generation) => {
                let observed = process.observe_generation(generation);
                match classify_process_generation(
                    generation.start_time_micros,
                    generation.boot_id,
                    observed,
                ) {
                    SupervisorLiveness::Live => match process.terminate_and_reap(generation) {
                        Ok(()) => RecoveredBrowserProcess::TerminatedAndReaped,
                        Err(OrphanProcessControlFailure) => {
                            first_failure.get_or_insert(
                                BrowserLaunchRecoveryFailure::ProcessTermination {
                                    sequence: attempt.sequence,
                                },
                            );
                            RecoveredBrowserProcess::Unattested
                        }
                    },
                    SupervisorLiveness::NotLive if observed == GenerationObservation::Absent => {
                        RecoveredBrowserProcess::NotRunning
                    }
                    SupervisorLiveness::NotLive => RecoveredBrowserProcess::StartTimeMismatch,
                    SupervisorLiveness::Unavailable => {
                        first_failure.get_or_insert(
                            BrowserLaunchRecoveryFailure::ProcessObservation {
                                sequence: attempt.sequence,
                            },
                        );
                        RecoveredBrowserProcess::Unattested
                    }
                }
            }
        };
        process_outcomes.insert(attempt.sequence, outcome);
    }

    let expected_sequences = attempts
        .iter()
        .map(|attempt| attempt.sequence)
        .collect::<BTreeSet<_>>();
    let recovered = journal.core.recover_active();
    let recovered_sequences = recovered
        .iter()
        .map(|outcome| outcome.action_obligation_id)
        .collect::<BTreeSet<_>>();
    if recovered_sequences != expected_sequences {
        first_failure.get_or_insert(BrowserLaunchRecoveryFailure::JournalTerminalization);
    }
    let journal_actions = recovered
        .into_iter()
        .map(|outcome| (outcome.action_obligation_id, outcome.recovery_action))
        .collect::<BTreeMap<_, _>>();

    for attempt in &attempts {
        match attempt.intent.as_ref() {
            Some(intent) => {
                if custody.release(intent).is_err() {
                    first_failure.get_or_insert(
                        BrowserLaunchRecoveryFailure::ProfileCustodyRelease {
                            sequence: attempt.sequence,
                        },
                    );
                }
            }
            None => {
                first_failure.get_or_insert(BrowserLaunchRecoveryFailure::InvalidIntent {
                    sequence: attempt.sequence,
                });
            }
        }
    }

    if let Some(failure) = first_failure {
        return Err(failure);
    }

    Ok(attempts
        .into_iter()
        .map(|attempt| BrowserLaunchRecoveryOutcome {
            sequence: attempt.sequence,
            process: process_outcomes[&attempt.sequence],
            journal_action: journal_actions[&attempt.sequence],
        })
        .collect())
}

impl DurableLaunchJournal<cerebellum_core::journal::FilesystemJournalStorage> {
    /// Open the production launch journal after creating its application-data
    /// directory and verifying that it can hold durable journal storage. A
    /// failed storage check prevents launch admission.
    pub fn open_filesystem(
        config: CoreJournalConfig,
    ) -> Result<Self, cerebellum_core::journal::BindingError> {
        let path = cerebellum_core::journal::journal_data_path("browser-launch.json")
            .map_err(cerebellum_core::journal::BindingError::Storage)?;
        let storage = cerebellum_core::journal::FilesystemJournalStorage::prepare(path)
            .map_err(cerebellum_core::journal::BindingError::Storage)?;
        Self::open(config, storage)
    }
}

impl<S: JournalStorage> LaunchJournalPort for DurableLaunchJournal<S> {
    fn finalize_startup_failure(
        &mut self,
        launch_attempt_id: &str,
        failure: &crate::browser_launch_readiness::ProfileStartupIndeterminate,
    ) -> Result<(), CoreJournalError> {
        let mut completion = LaunchSessionCompletion::new(
            launch_attempt_id,
            crate::browser_session::BrowserSessionTerminalOutcome::StartupIndeterminate,
        );
        completion.failure = Some(failure.clone());
        self.finalize_completion(completion)
    }

    type Handle = LaunchIntentHandle;

    fn record_intent(
        &mut self,
        intent: &AuthorizedLaunchIntent,
    ) -> Result<Self::Handle, CoreJournalError> {
        let identity = JournalIdentity {
            principal: intent.route.principal.clone(),
            conversation_key: intent.route.conversation_key.clone(),
            agent_project_id: intent.route.agent_project_id.clone(),
            session_kind: intent.route.session_kind,
        };
        let bytes = serde_json::to_vec(intent).map_err(|_| CoreJournalError::CodecFailed)?;
        self.core
            .reserve(identity, bytes)
            .map(|reservation| LaunchIntentHandle {
                reservation,
                attachment_revision: 0,
            })
    }

    fn record_generation(
        &mut self,
        handle: &mut Self::Handle,
        record: &LaunchGenerationRecord,
    ) -> Result<(), CoreJournalError> {
        let bytes = serde_json::to_vec(record).map_err(|_| CoreJournalError::CodecFailed)?;
        let revision = self.core.attach_obligation_material(
            handle.reservation,
            GENERATION_SLOT,
            handle.attachment_revision,
            bytes,
        )?;
        handle.attachment_revision = revision;
        Ok(())
    }

    fn commit_attestation(
        &mut self,
        handle: &mut Self::Handle,
        record: &LaunchAttestationRecord,
    ) -> Result<(), CoreJournalError> {
        let bytes = serde_json::to_vec(record).map_err(|_| CoreJournalError::CodecFailed)?;
        let revision = self.core.attach_obligation_material(
            handle.reservation,
            ATTESTATION_SLOT,
            0,
            bytes.clone(),
        )?;
        if revision != 1 {
            return Err(CoreJournalError::AttachmentFailed);
        }
        let commitment = self.core.commit_dispatched(
            handle.reservation,
            DispatchMaterial {
                dispatch_material: bytes,
                severity_inputs: None,
                grant_decision: b"authorized_browser_launch".to_vec(),
                governing_observation: None,
            },
        )?;
        self.dispatched.insert(
            record.generation.intent.launch_attempt_id.clone(),
            commitment,
        );
        Ok(())
    }

    fn record_identity_mismatch(
        &mut self,
        handle: &mut Self::Handle,
        record: &LaunchIdentityMismatchRecord,
    ) -> Result<(), CoreJournalError> {
        let bytes = serde_json::to_vec(record).map_err(|_| CoreJournalError::CodecFailed)?;
        let revision = self.core.attach_obligation_material(
            handle.reservation,
            ATTESTATION_SLOT,
            0,
            bytes.clone(),
        )?;
        if revision != 1 {
            return Err(CoreJournalError::AttachmentFailed);
        }
        self.core
            .finalize_rejected(
                handle.reservation,
                RejectionMaterial {
                    rejection_material: bytes,
                },
            )
            .map(|_| ())
    }
}

#[cfg(target_os = "linux")]
pub const LINUX_EXEC_CHAIN_HOP_LIMIT: usize = 8;

#[cfg(target_os = "linux")]
/// A queued wrapper exec should arrive quickly; this window sizes observation,
/// without pretending that a running image can prove it will never exec later.
/// Measured wrapper-to-browser deltas are 0.51–0.56 ms warm and 0.73–1.78 ms
/// cold after evicting 303.9 of 305.5 MiB with `POSIX_FADV_DONTNEED`.
/// `execve` reports `PTRACE_EVENT_EXEC` after headers and mappings, before the
/// whole image is paged in, so 100 ms provides about 56× cold headroom.
pub const LINUX_EXEC_CHAIN_PROBE_WINDOW: std::time::Duration =
    std::time::Duration::from_millis(100);

#[cfg(target_os = "linux")]
pub struct LinuxProcessLauncher {
    cdp_command_read_fd: std::os::fd::RawFd,
    cdp_response_write_fd: std::os::fd::RawFd,
}

#[cfg(target_os = "linux")]
impl LinuxProcessLauncher {
    pub fn new(
        cdp_command_read_fd: std::os::fd::RawFd,
        cdp_response_write_fd: std::os::fd::RawFd,
    ) -> Self {
        Self {
            cdp_command_read_fd,
            cdp_response_write_fd,
        }
    }

    fn spawn_raw(
        &self,
        executable: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> Result<cerebellum_linux::BarredChild, PlatformLaunchError> {
        cerebellum_linux::spawn_barred(
            executable,
            arguments,
            environment,
            self.cdp_command_read_fd,
            self.cdp_response_write_fd,
        )
        .map_err(|error| match error {
            cerebellum_linux::SpawnError::Ptrace(_) => PlatformLaunchError::PtraceUnavailable,
            _ => PlatformLaunchError::Spawn,
        })
    }

    pub(crate) fn probe_configured_executable(
        &mut self,
        executable: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        expected: &str,
    ) -> Result<LinuxDryRunObservation, PlatformLaunchError> {
        // Finality cannot be proven while the tracee is stopped at an exec
        // event. The probe therefore watches briefly for one more event after
        // the configured digest matches; a passing probe lets that image run
        // for the observation window before terminating it.
        let mut child = self.spawn_raw(executable, arguments, environment)?;
        let generation = child.generation();
        let result = (|| {
            let mut observed = cerebellum_linux::executed_image_identity(generation.pid)
                .map_err(map_linux_image_identity_error)?;
            let mut identity_chain = vec![linux_identity_record(&observed)];
            for _ in 0..=LINUX_EXEC_CHAIN_HOP_LIMIT {
                if observed.image_sha256 == expected {
                    let next_exec = child
                        .continue_to_next_exec_stop_with_deadline(
                            LINUX_EXEC_CHAIN_HOP_LIMIT + 1,
                            std::time::Instant::now() + LINUX_EXEC_CHAIN_PROBE_WINDOW,
                        )
                        .map_err(|error| {
                            map_linux_process_control_error_with_chain(error, &identity_chain)
                        })?;
                    if let Some(next_exec) = next_exec.as_ref() {
                        identity_chain.push(linux_identity_record(next_exec));
                    }
                    return Ok(LinuxDryRunObservation {
                        generation: BrowserProcessGeneration::from(generation),
                        observed,
                        next_exec,
                        identity_chain,
                    });
                }
                let Some(next) = child
                    .continue_to_next_exec_stop_with_deadline(
                        LINUX_EXEC_CHAIN_HOP_LIMIT,
                        std::time::Instant::now() + LINUX_EXEC_CHAIN_PROBE_WINDOW,
                    )
                    .map_err(|error| {
                        map_linux_process_control_error_with_chain(error, &identity_chain)
                    })?
                else {
                    return Ok(LinuxDryRunObservation {
                        generation: BrowserProcessGeneration::from(generation),
                        observed,
                        next_exec: None,
                        identity_chain,
                    });
                };
                identity_chain.push(linux_identity_record(&next));
                observed = next;
            }
            Err(PlatformLaunchError::ExecChainUnresolved {
                chain: ExecutableIdentityChain::StoppedAtHopLimit {
                    hops: identity_chain,
                },
            })
        })();
        let termination = child
            .terminate_and_reap()
            .map_err(map_linux_process_control_error);
        match termination {
            Ok(()) => result,
            Err(error) => Err(error),
        }
    }
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxDryRunObservation {
    pub generation: BrowserProcessGeneration,
    pub observed: cerebellum_linux::ExecutedImageIdentity,
    pub next_exec: Option<cerebellum_linux::ExecutedImageIdentity>,
    pub identity_chain: Vec<ExecutableIdentityRecord>,
}

#[cfg(target_os = "linux")]
pub struct LinuxBarredProcess(RefCell<cerebellum_linux::BarredChild>, String);

#[cfg(target_os = "linux")]
impl BarredLaunchProcess for LinuxBarredProcess {
    type Released = cerebellum_linux::ReleasedChild;

    fn generation(&self) -> BrowserProcessGeneration {
        BrowserProcessGeneration::from(self.0.borrow().generation())
    }

    fn executed_image_identity(&self) -> Result<ExecutableIdentityChain, PlatformLaunchError> {
        if self.1.is_empty() {
            return Err(PlatformLaunchError::ImageIdentity);
        }
        let expected = &self.1;
        let mut child = self.0.borrow_mut();
        let mut observed = cerebellum_linux::executed_image_identity(child.generation().pid)
            .map_err(map_linux_image_identity_error)?;
        let mut identity_chain = vec![linux_identity_record(&observed)];
        for _ in 0..=LINUX_EXEC_CHAIN_HOP_LIMIT {
            if observed.image_sha256 == *expected {
                return Ok(ExecutableIdentityChain::WalkedToMatch {
                    hops: identity_chain,
                });
            }
            let next = child
                .continue_to_next_exec_stop(LINUX_EXEC_CHAIN_HOP_LIMIT)
                .map_err(|error| {
                    map_linux_process_control_error_with_chain(error, &identity_chain)
                })?;
            identity_chain.push(linux_identity_record(&next));
            observed = next;
        }
        Err(PlatformLaunchError::ExecChainUnresolved {
            chain: ExecutableIdentityChain::StoppedAtHopLimit {
                hops: identity_chain,
            },
        })
    }

    fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
        self.0
            .into_inner()
            .terminate_and_reap()
            .map_err(map_linux_process_control_error)
    }

    fn release(self) -> Result<Self::Released, PlatformLaunchError> {
        self.0
            .into_inner()
            .release()
            .map_err(map_linux_process_control_error)
    }
}

#[cfg(target_os = "linux")]
fn linux_identity_record(
    identity: &cerebellum_linux::ExecutedImageIdentity,
) -> ExecutableIdentityRecord {
    ExecutableIdentityRecord {
        claim: ExecutableIdentityClaim::ImageDigest {
            sha256: identity.image_sha256.clone(),
        },
        path: Some(identity.resolved_path.clone()),
    }
}

#[cfg(target_os = "linux")]
fn map_linux_image_identity_error(
    error: cerebellum_linux::ImageIdentityError,
) -> PlatformLaunchError {
    match error {
        cerebellum_linux::ImageIdentityError::ProcessInspectionDenied
        | cerebellum_linux::ImageIdentityError::ProcessLayoutMismatch
        | cerebellum_linux::ImageIdentityError::ProcessStartTimeMissing => {
            PlatformLaunchError::GenerationUnreadable
        }
        cerebellum_linux::ImageIdentityError::GenerationChanged
        | cerebellum_linux::ImageIdentityError::Executable(_)
        | cerebellum_linux::ImageIdentityError::Read(_) => PlatformLaunchError::ImageIdentity,
        cerebellum_linux::ImageIdentityError::ProcessMissing => PlatformLaunchError::ProcessControl,
    }
}

#[cfg(target_os = "linux")]
fn map_linux_process_control_error_with_chain(
    error: cerebellum_linux::ProcessControlError,
    identity_chain: &[ExecutableIdentityRecord],
) -> PlatformLaunchError {
    if matches!(
        error,
        cerebellum_linux::ProcessControlError::ExecChainExhausted
    ) {
        PlatformLaunchError::ExecChainUnresolved {
            chain: ExecutableIdentityChain::StoppedAtHopLimit {
                hops: identity_chain.to_vec(),
            },
        }
    } else {
        map_linux_process_control_error(error)
    }
}

#[cfg(target_os = "linux")]
fn map_linux_process_control_error(
    error: cerebellum_linux::ProcessControlError,
) -> PlatformLaunchError {
    match error {
        cerebellum_linux::ProcessControlError::GenerationUnreadable => {
            PlatformLaunchError::GenerationUnreadable
        }
        cerebellum_linux::ProcessControlError::ExecChainExhausted => {
            PlatformLaunchError::ExecChainUnresolved {
                chain: ExecutableIdentityChain::StoppedAtHopLimit { hops: Vec::new() },
            }
        }
        cerebellum_linux::ProcessControlError::Ptrace(_) => PlatformLaunchError::PtraceUnavailable,
        cerebellum_linux::ProcessControlError::UnexpectedStop { signal } => {
            PlatformLaunchError::UnexpectedStop { signal }
        }
        cerebellum_linux::ProcessControlError::SignalStopLimitExceeded { last_signal, limit } => {
            PlatformLaunchError::SignalStopLimitExceeded { last_signal, limit }
        }
        cerebellum_linux::ProcessControlError::AlreadyReleased
        | cerebellum_linux::ProcessControlError::GenerationChanged
        | cerebellum_linux::ProcessControlError::Signal(_)
        | cerebellum_linux::ProcessControlError::Reap(_)
        | cerebellum_linux::ProcessControlError::ProcessExited => {
            PlatformLaunchError::ProcessControl
        }
    }
}

#[cfg(target_os = "linux")]
impl HandshakeProcess for cerebellum_linux::ReleasedChild {
    fn observe_exit(&mut self) -> Option<ChildExitStatus> {
        // Anything but an exact match reads as exited, as it did before the
        // generation carried a boot ID: this handle only reports, it never
        // signals on that answer.
        let generation = BrowserProcessGeneration::from(self.generation());
        match classify_process_generation(
            generation.start_time_micros,
            generation.boot_id,
            crate::profile_custody::linux_generation_observation(
                generation.pid,
                generation.boot_id,
            ),
        ) {
            SupervisorLiveness::Live => None,
            SupervisorLiveness::NotLive | SupervisorLiveness::Unavailable => {
                Some(ChildExitStatus::Unknown)
            }
        }
    }

    fn wait_and_reap(self) -> Result<(), PlatformLaunchError> {
        self.wait().map_err(map_linux_process_control_error)
    }

    fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
        self.terminate_and_reap()
            .map_err(map_linux_process_control_error)
    }
}

#[cfg(target_os = "linux")]
impl BarredProcessLauncher for LinuxProcessLauncher {
    type Process = LinuxBarredProcess;

    fn spawn_barred(
        &mut self,
        request: &AttestedLaunchRequest,
    ) -> Result<Self::Process, PlatformLaunchError> {
        self.spawn_raw(
            &request.executable,
            &request.arguments,
            &request.environment,
        )
        .map(|child| {
            let expected = match &request.verified_executable_identity {
                VerifiedExecutableIdentity::ImageDigest { sha256 } => sha256.clone(),
                VerifiedExecutableIdentity::CodeSignedFile { .. } => String::new(),
            };
            LinuxBarredProcess(RefCell::new(child), expected)
        })
    }
}

#[cfg(target_os = "macos")]
pub struct MacOsProcessLauncher {
    cdp_command_read_fd: std::os::fd::RawFd,
    cdp_response_write_fd: std::os::fd::RawFd,
}

#[cfg(target_os = "macos")]
impl MacOsProcessLauncher {
    pub fn new(
        cdp_command_read_fd: std::os::fd::RawFd,
        cdp_response_write_fd: std::os::fd::RawFd,
    ) -> Self {
        Self {
            cdp_command_read_fd,
            cdp_response_write_fd,
        }
    }
}

#[cfg(target_os = "macos")]
pub struct MacOsBarredProcess(cerebellum_macos::BarredChild, PathBuf);

#[cfg(target_os = "macos")]
impl BarredLaunchProcess for MacOsBarredProcess {
    type Released = cerebellum_macos::ReleasedChild;

    fn generation(&self) -> BrowserProcessGeneration {
        BrowserProcessGeneration::from(self.0.generation())
    }

    fn executed_image_identity(&self) -> Result<ExecutableIdentityChain, PlatformLaunchError> {
        let generation = self.0.generation();
        let observed = cerebellum_macos::executed_image_identity(generation.pid)
            .map_err(|_| PlatformLaunchError::ImageIdentity)?;
        if cerebellum_macos::process_start_time_micros(generation.pid)
            != Some(generation.start_time_micros)
        {
            return Err(PlatformLaunchError::ImageIdentity);
        }
        Ok(ExecutableIdentityChain::NoWalkPerformed {
            attestation: ExecutableIdentityRecord {
                claim: ExecutableIdentityClaim::CodeSigned {
                    signing_identifier: observed.signing_identifier,
                    unique_code_hash: observed.unique_code_hash,
                },
                path: Some(self.1.clone()),
            },
        })
    }

    fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
        self.0
            .terminate_and_reap()
            .map_err(|_| PlatformLaunchError::ProcessControl)
    }

    fn release(self) -> Result<Self::Released, PlatformLaunchError> {
        self.0
            .release()
            .map_err(|_| PlatformLaunchError::ProcessControl)
    }
}

#[cfg(target_os = "macos")]
impl HandshakeProcess for cerebellum_macos::ReleasedChild {
    fn observe_exit(&mut self) -> Option<ChildExitStatus> {
        let generation = self.generation();
        if cerebellum_macos::process_start_time_micros(generation.pid)
            == Some(generation.start_time_micros)
        {
            None
        } else {
            Some(ChildExitStatus::Unknown)
        }
    }

    fn wait_and_reap(self) -> Result<(), PlatformLaunchError> {
        self.wait().map_err(|_| PlatformLaunchError::ProcessControl)
    }

    fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
        self.terminate_and_reap()
            .map_err(|_| PlatformLaunchError::ProcessControl)
    }
}

#[cfg(target_os = "macos")]
impl BarredProcessLauncher for MacOsProcessLauncher {
    type Process = MacOsBarredProcess;

    fn spawn_barred(
        &mut self,
        request: &AttestedLaunchRequest,
    ) -> Result<Self::Process, PlatformLaunchError> {
        cerebellum_macos::spawn_barred(
            &request.executable,
            &request.arguments,
            &request.environment,
            self.cdp_command_read_fd,
            self.cdp_response_write_fd,
        )
        .map(|child| MacOsBarredProcess(child, request.executable.clone()))
        .map_err(|_| PlatformLaunchError::Spawn)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn process_stop_refusals_preserve_signal_diagnostics() {
        assert_eq!(
            PlatformLaunchError::UnexpectedStop { signal: 17 }.refusal(),
            serde_json::json!({
                "outcome": "launch_refused",
                "reason_code": "unexpected_process_stop",
                "remedy": "inspect unexpected process stop signal 17, then retry the launch",
            })
        );
        assert_eq!(
            PlatformLaunchError::SignalStopLimitExceeded {
                last_signal: 10,
                limit: 64,
            }
            .refusal(),
            serde_json::json!({
                "outcome": "launch_refused",
                "reason_code": "signal_stop_limit_exceeded",
                "remedy": "inspect the signal storm after 64 stops (last signal 10), then retry the launch",
            })
        );
    }

    /// A walk that stopped at its hop bound attests nothing.
    ///
    /// `matched_claim` returning None is what makes `attested_launch` terminate
    /// and reap the child with ImageAttestationFailed. If a truncated walk
    /// returned its LAST WALKED image instead, that image would be compared
    /// against the expected identity, and a chain longer than the bound whose
    /// last-walked hop happens to match would be attested -- a launch approved
    /// on a walk that never reached the image it was supposed to check. Measured
    /// wrapper chains run to four hops on Ubuntu, so "longer than the bound" is
    /// a real shape rather than a hypothetical one.
    ///
    /// Platform-neutral by construction: the enum is built directly rather than
    /// by launching anything, so Linux CI runs it too. The existing coverage is
    /// a Linux-gated live spawn that only exercises the matching case.
    #[test]
    fn a_truncated_identity_walk_yields_no_matched_claim() {
        fn record(sha: &str) -> ExecutableIdentityRecord {
            ExecutableIdentityRecord {
                claim: ExecutableIdentityClaim::ImageDigest {
                    sha256: sha.to_string(),
                },
                path: None,
            }
        }

        // Non-empty, and its last hop is a perfectly good claim -- which is the
        // point. The refusal must come from the walk being incomplete, not from
        // there being nothing to return.
        let truncated = ExecutableIdentityChain::StoppedAtHopLimit {
            hops: vec![record("aa"), record("bb")],
        };
        assert!(
            truncated.matched_claim().is_none(),
            "a walk that hit its hop bound reported a match"
        );

        let matched = ExecutableIdentityChain::WalkedToMatch {
            hops: vec![record("aa"), record("bb")],
        };
        assert_eq!(
            matched.matched_claim(),
            Some(&ExecutableIdentityClaim::ImageDigest {
                sha256: "bb".to_string()
            }),
            "a completed walk must attest the image it ended on"
        );

        // macOS supplies one post-exec attestation and no walk. It attests that
        // image: declining here would refuse every launch on that platform.
        let no_walk = ExecutableIdentityChain::NoWalkPerformed {
            attestation: record("cc"),
        };
        assert_eq!(
            no_walk.matched_claim(),
            Some(&ExecutableIdentityClaim::ImageDigest {
                sha256: "cc".to_string()
            }),
        );
    }
    use std::sync::{Arc, Mutex};

    use cerebellum_core::journal::{InMemoryJournalStorage, JournalConfig};

    use super::*;

    #[derive(Clone)]
    struct Events(Arc<Mutex<Vec<&'static str>>>);

    impl Events {
        fn new() -> Self {
            Self(Arc::new(Mutex::new(Vec::new())))
        }

        fn push(&self, event: &'static str) {
            self.0.lock().expect("event log").push(event);
        }

        fn snapshot(&self) -> Vec<&'static str> {
            self.0.lock().expect("event log").clone()
        }
    }

    struct RecordingOrphanProcess {
        observed: Result<Option<u64>, OrphanProcessControlFailure>,
        observation_calls: usize,
        termination_calls: usize,
        fail_termination: bool,
        events: Events,
    }

    impl RecordingOrphanProcess {
        fn new(observed: Result<Option<u64>, OrphanProcessControlFailure>, events: Events) -> Self {
            Self {
                observed,
                observation_calls: 0,
                termination_calls: 0,
                fail_termination: false,
                events,
            }
        }
    }

    impl OrphanBrowserProcessControl for RecordingOrphanProcess {
        fn observed_start_time_micros(
            &mut self,
            _pid: u32,
        ) -> Result<Option<u64>, OrphanProcessControlFailure> {
            self.observation_calls += 1;
            self.events.push("generation_observed");
            self.observed
        }

        fn terminate_and_reap(
            &mut self,
            _generation: BrowserProcessGeneration,
        ) -> Result<(), OrphanProcessControlFailure> {
            self.termination_calls += 1;
            self.events.push("orphan_terminated_and_reaped");
            if self.fail_termination {
                Err(OrphanProcessControlFailure)
            } else {
                Ok(())
            }
        }
    }

    struct RecordingOrphanCustody {
        releases: Vec<String>,
        fail: bool,
        events: Events,
    }

    impl RecordingOrphanCustody {
        fn new(events: Events) -> Self {
            Self {
                releases: Vec::new(),
                fail: false,
                events,
            }
        }
    }

    impl OrphanProfileCustody for RecordingOrphanCustody {
        fn release(
            &mut self,
            intent: &AuthorizedLaunchIntent,
        ) -> Result<(), OrphanProfileCustodyFailure> {
            self.releases.push(intent.holder_id.clone());
            self.events.push("profile_lock_released");
            if self.fail {
                Err(OrphanProfileCustodyFailure)
            } else {
                Ok(())
            }
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum FailJournalAt {
        Never,
        Intent,
        Generation,
        Attestation,
        Mismatch,
    }

    struct RecordingJournal {
        events: Events,
        fail: FailJournalAt,
        attestation: Arc<Mutex<Option<LaunchAttestationRecord>>>,
    }

    impl LaunchJournalPort for RecordingJournal {
        fn finalize_startup_failure(
            &mut self,
            _: &str,
            _: &crate::browser_launch_readiness::ProfileStartupIndeterminate,
        ) -> Result<(), CoreJournalError> {
            self.events.push("startup_finalized");
            Ok(())
        }

        type Handle = ();

        fn record_intent(
            &mut self,
            _intent: &AuthorizedLaunchIntent,
        ) -> Result<Self::Handle, CoreJournalError> {
            self.events.push("intent_recorded");
            if self.fail == FailJournalAt::Intent {
                Err(CoreJournalError::StorageUnavailable)
            } else {
                Ok(())
            }
        }

        fn record_generation(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchGenerationRecord,
        ) -> Result<(), CoreJournalError> {
            self.events.push("generation_recorded");
            if self.fail == FailJournalAt::Generation {
                Err(CoreJournalError::StorageUnavailable)
            } else {
                Ok(())
            }
        }

        fn commit_attestation(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchAttestationRecord,
        ) -> Result<(), CoreJournalError> {
            self.events.push("attestation_committed");
            *self.attestation.lock().expect("attestation recording") = Some(_record.clone());
            if self.fail == FailJournalAt::Attestation {
                Err(CoreJournalError::StorageUnavailable)
            } else {
                Ok(())
            }
        }

        fn record_identity_mismatch(
            &mut self,
            _handle: &mut Self::Handle,
            _record: &LaunchIdentityMismatchRecord,
        ) -> Result<(), CoreJournalError> {
            self.events.push("mismatch_recorded");
            if self.fail == FailJournalAt::Mismatch {
                Err(CoreJournalError::StorageUnavailable)
            } else {
                Ok(())
            }
        }
    }

    struct FakeBarredProcess {
        events: Events,
        observed: Result<ExecutableIdentityClaim, PlatformLaunchError>,
        generation: BrowserProcessGeneration,
    }

    impl Drop for FakeBarredProcess {
        fn drop(&mut self) {
            self.events.push("barred_dropped");
        }
    }

    struct FakeReleasedProcess;

    struct ImmediateExitProcess;

    impl crate::browser_session::OwnedBrowserProcess for ImmediateExitProcess {
        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(
            &mut self,
        ) -> Result<(), crate::browser_session::ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(
            &mut self,
            _grace_period: std::time::Duration,
        ) -> Result<bool, crate::browser_session::ProcessControlFailure> {
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), crate::browser_session::ProcessControlFailure> {
            unreachable!("graceful exit was already observed")
        }

        fn wait_until_reaped(
            &mut self,
        ) -> Result<(), crate::browser_session::ProcessControlFailure> {
            Ok(())
        }
    }

    struct JournalFinalizingCleanup {
        journal: Arc<Mutex<DurableLaunchJournal<InMemoryJournalStorage>>>,
        launch_attempt_id: String,
        terminal_outcome: Option<crate::browser_session::BrowserSessionTerminalOutcome>,
    }

    impl crate::browser_session::SessionCleanup for JournalFinalizingCleanup {
        fn set_terminal_outcome(
            &mut self,
            outcome: crate::browser_session::BrowserSessionTerminalOutcome,
        ) {
            self.terminal_outcome = Some(outcome);
        }

        fn after_reap(
            &mut self,
        ) -> Result<
            crate::browser_session::SessionCleanupOutcome,
            crate::browser_session::CleanupStage,
        > {
            let outcome = self
                .terminal_outcome
                .take()
                .ok_or(crate::browser_session::CleanupStage::RecordTerminalization)?;
            self.journal
                .lock()
                .map_err(|_| crate::browser_session::CleanupStage::RecordTerminalization)?
                .finalize_session(&self.launch_attempt_id, outcome)
                .map(|()| crate::browser_session::SessionCleanupOutcome::Complete)
                .map_err(|_| crate::browser_session::CleanupStage::RecordTerminalization)
        }
    }

    impl BarredLaunchProcess for FakeBarredProcess {
        type Released = FakeReleasedProcess;

        fn generation(&self) -> BrowserProcessGeneration {
            self.generation
        }

        fn executed_image_identity(&self) -> Result<ExecutableIdentityChain, PlatformLaunchError> {
            self.events.push("image_attested");
            self.observed
                .clone()
                .map(|identity| ExecutableIdentityChain::WalkedToMatch {
                    hops: vec![ExecutableIdentityRecord {
                        claim: identity,
                        path: None,
                    }],
                })
        }

        fn terminate_and_reap(self) -> Result<(), PlatformLaunchError> {
            self.events.push("terminated_and_reaped");
            Ok(())
        }

        fn release(self) -> Result<Self::Released, PlatformLaunchError> {
            self.events.push("released");
            Ok(FakeReleasedProcess)
        }
    }

    struct FakeLauncher {
        events: Events,
        observed: Result<ExecutableIdentityClaim, PlatformLaunchError>,
        spawn: Result<(), PlatformLaunchError>,
    }

    impl BarredProcessLauncher for FakeLauncher {
        type Process = FakeBarredProcess;

        fn spawn_barred(
            &mut self,
            _request: &AttestedLaunchRequest,
        ) -> Result<Self::Process, PlatformLaunchError> {
            self.events.push("spawned_barred");
            self.spawn.clone()?;
            Ok(FakeBarredProcess {
                events: self.events.clone(),
                observed: self.observed.clone(),
                generation: BrowserProcessGeneration {
                    pid: 42,
                    start_time_micros: 77,
                    boot_id: None,
                },
            })
        }
    }

    fn identity() -> ExecutableIdentityClaim {
        ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.browser".to_string(),
            unique_code_hash: "a1b2c3".to_string(),
        }
    }

    /// The pre-spawn read of a file carrying two slices, one of which is the
    /// image [`identity`] describes.
    fn verified_identity() -> VerifiedExecutableIdentity {
        VerifiedExecutableIdentity::CodeSignedFile {
            signing_identifier: "com.example.browser".to_string(),
            slice_code_hashes: BTreeSet::from(["a1b2c3".to_string(), "d4e5f6".to_string()]),
        }
    }

    #[test]
    fn executable_identity_chain_completeness_states_are_distinct() {
        let hop = ExecutableIdentityRecord {
            claim: identity(),
            path: Some(PathBuf::from("/Applications/Browser.app")),
        };
        let matched = ExecutableIdentityChain::WalkedToMatch {
            hops: vec![hop.clone()],
        };
        let bounded = ExecutableIdentityChain::StoppedAtHopLimit {
            hops: vec![hop.clone()],
        };
        let not_walked = ExecutableIdentityChain::NoWalkPerformed {
            attestation: hop.clone(),
        };

        assert_eq!(
            ExecutableIdentityRecord {
                claim: identity(),
                path: Some(PathBuf::from("/one")),
            },
            ExecutableIdentityRecord {
                claim: identity(),
                path: Some(PathBuf::from("/two")),
            }
        );
        assert_ne!(matched, bounded);
        assert_ne!(bounded, not_walked);
        assert_ne!(matched, not_walked);
    }

    fn request() -> AttestedLaunchRequest {
        AttestedLaunchRequest {
            launch_attempt_id: "attempt-1".to_string(),
            holder_id: "holder-1".to_string(),
            route: LaunchRouteIdentity {
                principal: "direct:agent".to_string(),
                conversation_key: "conversation-1".to_string(),
                agent_project_id: "project-1".to_string(),
                session_kind: cerebellum_core::identity::SessionKind::Primary,
            },
            profile: LaunchProfileIdentity {
                profile_uuid: "profile-1".to_string(),
                canonical_profile_path: b"/tmp/profile-1".to_vec(),
                disposition: cerebellum_core::identity::ProfileDisposition::Durable,
            },
            executable: PathBuf::from("/Applications/Browser.app/Contents/MacOS/Browser"),
            arguments: vec![OsString::from("--remote-debugging-pipe")],
            environment: vec![],
            verified_executable_identity: verified_identity(),
            pre_spawn_identity_verification: PreSpawnIdentityVerification::Established,
        }
    }

    /// A launch intent written by the v4 serializer, frozen before the format
    /// moved on. Recovery reads intents written by whichever build ran before
    /// this one, so an old record must still decode to the same profile and
    /// re-encode to the same bytes.
    #[test]
    fn frozen_v4_launch_intent_still_decodes_to_a_registry_profile() {
        let fixture = include_str!("../tests/fixtures/launch-intent-v4.json").trim();
        let intent: AuthorizedLaunchIntent =
            serde_json::from_str(fixture).expect("decode frozen v4 launch intent");
        assert_eq!(intent.format_version, "ck-browser-launch-attestation/v4");
        assert_eq!(intent.launch_attempt_id, "fixture-v4-attempt");
        assert_eq!(
            intent.profile.disposition,
            cerebellum_core::identity::ProfileDisposition::Durable
        );
        assert_eq!(serde_json::to_string(&intent).unwrap(), fixture);
    }

    #[test]
    fn v2_launch_records_encode_every_byte_field_as_base64() {
        let intent = request().durable_intent();
        let serialized = serde_json::to_value(&intent).expect("serialize v2 launch intent");

        assert_eq!(serialized["format_version"], LAUNCH_CODEC_VERSION);
        assert!(serialized["profile"]["canonical_profile_path"].is_string());
        assert!(serialized["launch_vector"]["executable"].is_string());
        assert!(serialized["launch_vector"]["arguments"][0].is_string());
        assert_eq!(
            serde_json::from_value::<AuthorizedLaunchIntent>(serialized)
                .expect("decode v2 launch intent"),
            intent
        );
    }

    #[test]
    fn frozen_v1_launch_descriptor_number_arrays_still_decode() {
        const V1_BYTES: &[u8] =
            include_bytes!("../../cerebellum-core/tests/fixtures/browser-launch-journal-v1.json");
        let stored: serde_json::Value =
            serde_json::from_slice(V1_BYTES).expect("parse exact v1 journal bytes");
        let descriptor = stored["state"]["entries"]["1"]["invocation_descriptor"]
            .as_array()
            .expect("v1 descriptor byte array")
            .iter()
            .map(|value| value.as_u64().expect("v1 byte") as u8)
            .collect::<Vec<_>>();

        let intent: AuthorizedLaunchIntent =
            serde_json::from_slice(&descriptor).expect("decode v1 launch descriptor");
        assert_eq!(intent.format_version, LEGACY_LAUNCH_CODEC_VERSION);
        assert_eq!(intent.launch_attempt_id, "fixture-launch-attempt");
        assert_eq!(intent.launch_vector.executable, vec![b'x'; 250]);
        assert_eq!(
            intent.profile.canonical_profile_path,
            b"/Users/fixture/Library/Application Support/CortexKit/Profiles/fixture"
        );
    }

    fn dispatch_attempt(
        journal: &mut DurableLaunchJournal<InMemoryJournalStorage>,
        request: &AttestedLaunchRequest,
    ) -> (u64, LaunchAttestationRecord) {
        dispatch_attempt_as(journal, request, LAUNCH_CODEC_VERSION, None)
    }

    /// Dispatch one attempt as a writer of `format_version` would have
    /// recorded it, so a reader can be driven against older records.
    fn dispatch_attempt_as(
        journal: &mut DurableLaunchJournal<InMemoryJournalStorage>,
        request: &AttestedLaunchRequest,
        format_version: &str,
        boot_id: Option<crate::profile_custody::BootId>,
    ) -> (u64, LaunchAttestationRecord) {
        let mut intent = request.durable_intent();
        intent.format_version = format_version.to_string();
        let mut handle = journal.record_intent(&intent).expect("record intent");
        let sequence = handle.sequence();
        let generation = LaunchGenerationRecord {
            intent,
            process_generation: BrowserProcessGeneration {
                pid: 42,
                start_time_micros: sequence,
                boot_id,
            },
        };
        journal
            .record_generation(&mut handle, &generation)
            .expect("record generation");
        let attestation = LaunchAttestationRecord {
            generation,
            observed_executable_identity: identity(),
            executable_identity_chain: ExecutableIdentityChain::NoWalkPerformed {
                attestation: ExecutableIdentityRecord {
                    claim: identity(),
                    path: None,
                },
            },
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
        };
        journal
            .commit_attestation(&mut handle, &attestation)
            .expect("commit attestation");
        (sequence, attestation)
    }

    #[test]
    fn a_handshake_failure_after_attestation_closes_the_journal_attempt() {
        use crate::browser_launch_readiness::{tests::fail_after_attestation, ProfileStartupCause};
        let mut journal = reopened_dispatched_journal(InMemoryJournalStorage::new());
        fail_after_attestation(&mut journal);
        assert!(journal.active_launch_attempts().unwrap().is_empty());
        assert!(journal.dispatched.is_empty());
        let completion = terminal_completion(&journal, 1);
        assert_eq!(
            completion.terminal_outcome.as_str(),
            "startup_indeterminate"
        );
        assert_eq!(
            completion.failure.unwrap().cause,
            ProfileStartupCause::DeadlineExpired
        );
    }

    #[test]
    fn a_startup_failure_record_is_not_an_orphan_on_the_next_start() {
        let storage = InMemoryJournalStorage::new();
        let mut journal = reopened_dispatched_journal(storage.clone());
        crate::browser_launch_readiness::tests::fail_after_attestation(&mut journal);
        drop(journal);
        let mut journal = reopened_dispatched_journal(storage);
        assert!(journal.active_launch_attempts().unwrap().is_empty());
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(None), events.clone());
        let mut custody = RecordingOrphanCustody::new(events);
        assert!(
            recover_browser_launches(&mut journal, &mut process, &mut custody)
                .unwrap()
                .is_empty()
        );
        assert_eq!(process.observation_calls, 0);
        assert!(custody.releases.is_empty());
    }

    #[test]
    fn v2_completion_fixture_reads_through_the_v4_reader() {
        let completion: LaunchSessionCompletion =
            serde_json::from_str(include_str!("../tests/fixtures/launch-completion-v2.json"))
                .unwrap();
        assert_eq!(
            completion.format_version,
            "ck-browser-launch-attestation/v2"
        );
        assert_eq!(completion.launch_attempt_id, "fixture-v2-session");
        assert_eq!(
            completion.terminal_outcome,
            crate::browser_session::BrowserSessionTerminalOutcome::Closed
        );
        assert_eq!(completion.failure, None);
        assert_eq!(LAUNCH_CODEC_VERSION, "ck-browser-launch-attestation/v4");
    }

    fn terminal_completion(
        journal: &DurableLaunchJournal<InMemoryJournalStorage>,
        sequence: u64,
    ) -> LaunchSessionCompletion {
        assert_eq!(sequence, 1);
        serde_json::from_slice(&journal.core.export_bytes()).expect("decode launch completion")
    }

    fn harness(
        fail: FailJournalAt,
        observed: Result<ExecutableIdentityClaim, PlatformLaunchError>,
    ) -> (RecordingJournal, FakeLauncher, Events) {
        let events = Events::new();
        (
            RecordingJournal {
                events: events.clone(),
                fail,
                attestation: Arc::new(Mutex::new(None)),
            },
            FakeLauncher {
                events: events.clone(),
                observed,
                spawn: Ok(()),
            },
            events,
        )
    }

    #[test]
    fn release_occurs_only_after_intent_generation_and_attestation_are_durable() {
        let (mut journal, mut launcher, events) = harness(FailJournalAt::Never, Ok(identity()));

        let result = launch_attested_with(&mut journal, &mut launcher, &request());

        match result {
            Ok(released) => {
                assert_eq!(
                    released.attestation.generation.process_generation,
                    BrowserProcessGeneration {
                        pid: 42,
                        start_time_micros: 77,
                        boot_id: None,
                    }
                );
                assert_eq!(
                    released.attestation.executable_identity_checkpoints,
                    ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec
                );
            }
            Err(error) => panic!("expected release, got {error:?}"),
        }
        assert_eq!(
            events.snapshot(),
            vec![
                "intent_recorded",
                "spawned_barred",
                "generation_recorded",
                "image_attested",
                "attestation_committed",
                "released",
                "barred_dropped",
            ]
        );
    }

    #[test]
    fn launch_without_pre_spawn_verification_records_after_exec_only() {
        let (mut journal, mut launcher, _) = harness(FailJournalAt::Never, Ok(identity()));
        let mut launch_request = request();
        launch_request.pre_spawn_identity_verification = PreSpawnIdentityVerification::Unavailable;

        let released = launch_attested_with(&mut journal, &mut launcher, &launch_request)
            .expect("release after barred-image attestation");

        assert_eq!(
            released.attestation.executable_identity_checkpoints,
            ExecutableIdentityCheckpoints::AfterExecOnly
        );
    }

    #[test]
    fn failed_intent_record_prevents_process_creation() {
        let (mut journal, mut launcher, events) = harness(FailJournalAt::Intent, Ok(identity()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        assert_eq!(
            outcome.map(|_| ()),
            Err(AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Intent,
            })
        );
        assert_eq!(events.snapshot(), vec!["intent_recorded"]);
    }

    #[test]
    fn failed_generation_record_terminates_without_release() {
        let (mut journal, mut launcher, events) =
            harness(FailJournalAt::Generation, Ok(identity()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        assert_eq!(
            outcome.map(|_| ()),
            Err(AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Generation,
            })
        );
        assert_eq!(
            events.snapshot(),
            vec![
                "intent_recorded",
                "spawned_barred",
                "generation_recorded",
                "terminated_and_reaped",
                "barred_dropped",
            ]
        );
    }

    #[test]
    fn release_before_durable_attestation_is_fenced() {
        let (mut journal, mut launcher, events) =
            harness(FailJournalAt::Attestation, Ok(identity()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        assert_eq!(
            outcome.map(|_| ()),
            Err(AttestedLaunchError::JournalRecordFailed {
                stage: LaunchRecordStage::Attestation,
            })
        );
        assert_eq!(
            events.snapshot(),
            vec![
                "intent_recorded",
                "spawned_barred",
                "generation_recorded",
                "image_attested",
                "attestation_committed",
                "terminated_and_reaped",
                "barred_dropped",
            ],
            "a failed durable attestation must terminate, never release"
        );
    }

    #[test]
    fn image_mismatch_records_exact_identities_then_terminates_without_release() {
        let observed = ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.substitute".to_string(),
            unique_code_hash: "deadbeef".to_string(),
        };
        let (mut journal, mut launcher, events) =
            harness(FailJournalAt::Never, Ok(observed.clone()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        assert_eq!(
            outcome.map(|_| ()),
            Err(AttestedLaunchError::ExecutableIdentityMismatch {
                claim_kind: "code_signed".to_string(),
                expected_identity: verified_identity().display_identity(),
                observed_identity: observed.display_identity(),
            })
        );
        assert_eq!(
            events.snapshot(),
            vec![
                "intent_recorded",
                "spawned_barred",
                "generation_recorded",
                "image_attested",
                "mismatch_recorded",
                "terminated_and_reaped",
                "barred_dropped",
            ]
        );
    }

    #[test]
    fn executed_slice_outside_the_verified_set_is_refused() {
        // Same signer, a code hash the pre-spawn read never saw. That is the
        // shape of a file swapped between the check and the exec: whoever
        // swapped it can sign under any identifier, but they cannot put their
        // code hash into a set that was read from the earlier file.
        let observed = ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.browser".to_string(),
            unique_code_hash: "c7c7c7".to_string(),
        };
        let (mut journal, mut launcher, events) =
            harness(FailJournalAt::Never, Ok(observed.clone()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        let Err(AttestedLaunchError::ExecutableIdentityMismatch {
            claim_kind,
            expected_identity,
            observed_identity,
        }) = outcome.map(|_| ())
        else {
            panic!("an executed image outside the verified set must be refused");
        };
        assert_eq!(claim_kind, "code_signed");
        // Carried out of the recorded mismatch verbatim, so the record names
        // every slice that would have been admitted rather than one of them.
        assert_eq!(
            expected_identity,
            "identifier=com.example.browser;cdhashes={a1b2c3,d4e5f6}"
        );
        assert_eq!(observed_identity, observed.display_identity());
        assert_eq!(
            events.snapshot(),
            vec![
                "intent_recorded",
                "spawned_barred",
                "generation_recorded",
                "image_attested",
                "mismatch_recorded",
                "terminated_and_reaped",
                "barred_dropped",
            ]
        );
    }

    #[test]
    fn executed_slice_inside_the_verified_set_is_admitted() {
        // Fixed against the refusal above: same request, same signer, and the
        // only difference is that this code hash is one the file was read to
        // carry. Set membership is therefore what separates the two outcomes,
        // not the signer and not equality with a single chosen slice.
        let observed = ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.browser".to_string(),
            unique_code_hash: "d4e5f6".to_string(),
        };
        let (mut journal, mut launcher, events) =
            harness(FailJournalAt::Never, Ok(observed.clone()));

        let released = launch_attested_with(&mut journal, &mut launcher, &request())
            .expect("an image whose slice was verified before spawn must be released");

        assert_eq!(released.attestation.observed_executable_identity, observed);
        assert_eq!(
            events.snapshot(),
            vec![
                "intent_recorded",
                "spawned_barred",
                "generation_recorded",
                "image_attested",
                "attestation_committed",
                "released",
                "barred_dropped",
            ]
        );
    }

    #[test]
    fn identifier_mismatch_is_refused_even_when_a_cdhash_matches() {
        // A code hash in the set is not an identity on its own: an image
        // signed by someone else is a different program however it was built.
        let observed = ExecutableIdentityClaim::CodeSigned {
            signing_identifier: "com.example.substitute".to_string(),
            unique_code_hash: "a1b2c3".to_string(),
        };
        let (mut journal, mut launcher, _) = harness(FailJournalAt::Never, Ok(observed.clone()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        assert_eq!(
            outcome.map(|_| ()),
            Err(AttestedLaunchError::ExecutableIdentityMismatch {
                claim_kind: "code_signed".to_string(),
                expected_identity: verified_identity().display_identity(),
                observed_identity: observed.display_identity(),
            })
        );
    }

    #[test]
    fn a_digest_never_admits_a_code_signed_image() {
        // The two kinds establish different guarantees, so one can never stand
        // in for the other however the strings compare.
        assert!(!VerifiedExecutableIdentity::ImageDigest {
            sha256: "a1b2c3".to_string(),
        }
        .admits(&identity()));
        assert!(
            !verified_identity().admits(&ExecutableIdentityClaim::ImageDigest {
                sha256: "a1b2c3".to_string(),
            })
        );
    }

    #[test]
    fn a_stored_single_code_hash_decodes_as_a_one_slice_set() {
        // Launch records written before this module read slices carry one
        // `unique_code_hash` string. They must still decode, and they mean
        // exactly what they said: one slice was verified.
        let stored = serde_json::json!({
            "claim_kind": "code_signed",
            "signing_identifier": "com.example.browser",
            "unique_code_hash": "a1b2c3",
        });

        let decoded: VerifiedExecutableIdentity =
            serde_json::from_value(stored).expect("decode a single-hash launch record");

        assert_eq!(
            decoded,
            VerifiedExecutableIdentity::CodeSignedFile {
                signing_identifier: "com.example.browser".to_string(),
                slice_code_hashes: BTreeSet::from(["a1b2c3".to_string()]),
            }
        );
        assert_eq!(
            serde_json::to_value(&decoded).expect("re-encode")["slice_code_hashes"],
            serde_json::json!(["a1b2c3"])
        );
    }

    #[test]
    fn durable_journal_retains_generation_and_attestation_records() {
        let storage = InMemoryJournalStorage::new();
        let mut journal = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            storage.clone(),
        )
        .expect("open launch journal");
        let intent = request().durable_intent();
        let mut handle = journal.record_intent(&intent).expect("record intent");
        let sequence = handle.sequence();
        let generation = LaunchGenerationRecord {
            intent,
            process_generation: BrowserProcessGeneration {
                pid: 42,
                start_time_micros: 77,
                boot_id: None,
            },
        };
        journal
            .record_generation(&mut handle, &generation)
            .expect("record generation");
        let attestation = LaunchAttestationRecord {
            generation,
            observed_executable_identity: identity(),
            executable_identity_chain: ExecutableIdentityChain::NoWalkPerformed {
                attestation: ExecutableIdentityRecord {
                    claim: identity(),
                    path: None,
                },
            },
            executable_identity_checkpoints: ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
        };
        journal
            .commit_attestation(&mut handle, &attestation)
            .expect("commit attestation");

        let reopened = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            storage,
        )
        .expect("reopen launch journal");
        let audit = reopened
            .read_attempt(sequence)
            .expect("read durable attempt");
        assert_eq!(
            audit.lifecycle,
            cerebellum_core::journal::LifecycleState::Dispatched
        );
        let stored = audit
            .attachment_slots
            .iter()
            .find(|attachment| attachment.slot == ATTESTATION_SLOT)
            .expect("attestation attachment");
        let decoded: LaunchAttestationRecord =
            serde_json::from_slice(&stored.opaque_bytes).expect("decode attestation");
        assert_eq!(decoded, attestation);

        let mut serialized: serde_json::Value =
            serde_json::from_slice(&stored.opaque_bytes).expect("decode attestation JSON");
        assert_eq!(
            serialized["executable_identity_checkpoints"],
            "before_spawn_and_after_exec"
        );
        serialized
            .as_object_mut()
            .expect("attestation object")
            .remove("executable_identity_checkpoints");
        assert!(
            serde_json::from_value::<LaunchAttestationRecord>(serialized).is_err(),
            "durable attestation accepted a missing checkpoint disclosure"
        );
    }

    fn reopened_dispatched_journal(
        storage: InMemoryJournalStorage,
    ) -> DurableLaunchJournal<InMemoryJournalStorage> {
        DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            storage,
        )
        .expect("reopen launch journal")
    }

    #[test]
    fn startup_recovery_terminates_exact_attested_generation_before_fresh_spawn() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let (sequence, _) = dispatch_attempt(&mut original, &request());
        drop(original);
        let mut journal = reopened_dispatched_journal(storage);
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(Some(sequence)), events.clone());
        let mut custody = RecordingOrphanCustody::new(events.clone());

        let outcomes = recover_browser_launches(&mut journal, &mut process, &mut custody)
            .expect("recover exact attested orphan");
        events.push("fresh_spawn");

        assert_eq!(
            outcomes,
            vec![BrowserLaunchRecoveryOutcome {
                sequence,
                process: RecoveredBrowserProcess::TerminatedAndReaped,
                journal_action: cerebellum_core::journal::RecoveryAction::DispatchFinalized,
            }]
        );
        assert_eq!(process.observation_calls, 1);
        assert_eq!(process.termination_calls, 1);
        assert_eq!(custody.releases, vec!["holder-1"]);
        assert_eq!(
            events.snapshot(),
            vec![
                "generation_observed",
                "orphan_terminated_and_reaped",
                "profile_lock_released",
                "fresh_spawn",
            ]
        );
        let audit = journal
            .read_attempt(sequence)
            .expect("read recovered attempt");
        assert_eq!(
            audit.lifecycle,
            cerebellum_core::journal::LifecycleState::Finalized
        );
        assert_eq!(
            audit.terminal_kind,
            Some(cerebellum_core::journal::TerminalKind::RecoveryDispatchFinalized)
        );
        assert_eq!(
            audit.reason,
            Some(cerebellum_core::journal::JournalReason::InterruptedAfterDispatch)
        );
    }

    /// An attestation written by version 3, before the generation carried a
    /// boot ID, still loads after the upgrade and is compared in the unit it
    /// was written in: epoch microseconds, never ticks since boot.
    #[test]
    fn a_v3_attestation_still_loads_and_takes_the_epoch_micros_arm() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let (sequence, _) =
            dispatch_attempt_as(&mut original, &request(), V3_LAUNCH_CODEC_VERSION, None);
        drop(original);
        let journal = reopened_dispatched_journal(storage);

        let attempts = journal.active_launch_attempts().expect("read v3 attempt");
        let generation = attempts[0]
            .attested_generation
            .expect("a v3 attestation is still attested");
        assert_eq!(generation.boot_id, None);
        assert_eq!(
            classify_process_generation(
                generation.start_time_micros,
                generation.boot_id,
                GenerationObservation::StartTime {
                    start_time: sequence,
                    stability: StartTimeStability::MovesWithWallClock,
                },
            ),
            SupervisorLiveness::Live
        );
        assert_eq!(
            classify_process_generation(
                generation.start_time_micros,
                generation.boot_id,
                GenerationObservation::BootTicks {
                    boot_id: crate::profile_custody::BootId::from_bytes([7; 16]),
                    start_ticks: sequence,
                },
            ),
            SupervisorLiveness::Unavailable,
            "a legacy start time is never compared as ticks"
        );
    }

    #[test]
    fn a_pre_v4_attestation_that_claims_a_boot_id_is_not_trusted() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        dispatch_attempt_as(
            &mut original,
            &request(),
            V3_LAUNCH_CODEC_VERSION,
            Some(crate::profile_custody::BootId::from_bytes([7; 16])),
        );
        drop(original);
        let journal = reopened_dispatched_journal(storage);

        let attempts = journal.active_launch_attempts().expect("read attempt");
        assert_eq!(attempts[0].attested_generation, None);
    }

    /// A platform observer reporting boot and ticks, as Linux does.
    struct BootTicksOrphan {
        observed: GenerationObservation,
        terminations: usize,
    }

    impl OrphanBrowserProcessControl for BootTicksOrphan {
        fn observed_start_time_micros(
            &mut self,
            _pid: u32,
        ) -> Result<Option<u64>, OrphanProcessControlFailure> {
            panic!("a boot-and-ticks record must not be observed as an epoch time")
        }

        fn observe_generation(
            &mut self,
            _generation: BrowserProcessGeneration,
        ) -> GenerationObservation {
            self.observed
        }

        fn terminate_and_reap(
            &mut self,
            _generation: BrowserProcessGeneration,
        ) -> Result<(), OrphanProcessControlFailure> {
            self.terminations += 1;
            Ok(())
        }
    }

    #[test]
    fn startup_recovery_terminates_a_boot_ticks_orphan_only_on_an_exact_match() {
        let boot = crate::profile_custody::BootId::from_bytes([7; 16]);
        for (observed, expected_process, expected_terminations) in [
            (
                GenerationObservation::BootTicks {
                    boot_id: boot,
                    start_ticks: 1,
                },
                RecoveredBrowserProcess::TerminatedAndReaped,
                1,
            ),
            (
                GenerationObservation::BootTicks {
                    boot_id: boot,
                    start_ticks: 2,
                },
                RecoveredBrowserProcess::StartTimeMismatch,
                0,
            ),
            (
                GenerationObservation::Absent,
                RecoveredBrowserProcess::NotRunning,
                0,
            ),
        ] {
            let storage = InMemoryJournalStorage::new();
            let mut original = reopened_dispatched_journal(storage.clone());
            let (sequence, _) =
                dispatch_attempt_as(&mut original, &request(), LAUNCH_CODEC_VERSION, Some(boot));
            assert_eq!(sequence, 1);
            drop(original);
            let mut journal = reopened_dispatched_journal(storage);
            let mut process = BootTicksOrphan {
                observed,
                terminations: 0,
            };
            let mut custody = RecordingOrphanCustody::new(Events::new());

            let outcomes = recover_browser_launches(&mut journal, &mut process, &mut custody)
                .expect("recover boot-and-ticks record");

            assert_eq!(outcomes[0].process, expected_process, "{observed:?}");
            assert_eq!(process.terminations, expected_terminations, "{observed:?}");
        }
    }

    #[test]
    fn startup_recovery_refuses_an_unreadable_boot_ticks_orphan_without_signalling() {
        let boot = crate::profile_custody::BootId::from_bytes([7; 16]);
        {
            let observed = GenerationObservation::Unreadable;
            let storage = InMemoryJournalStorage::new();
            let mut original = reopened_dispatched_journal(storage.clone());
            dispatch_attempt_as(&mut original, &request(), LAUNCH_CODEC_VERSION, Some(boot));
            drop(original);
            let mut journal = reopened_dispatched_journal(storage);
            let mut process = BootTicksOrphan {
                observed,
                terminations: 0,
            };
            let mut custody = RecordingOrphanCustody::new(Events::new());

            assert_eq!(
                recover_browser_launches(&mut journal, &mut process, &mut custody),
                Err(BrowserLaunchRecoveryFailure::ProcessObservation { sequence: 1 }),
                "{observed:?}"
            );
            assert_eq!(process.terminations, 0, "{observed:?}");
        }
    }

    #[test]
    fn startup_recovery_never_signals_a_pid_whose_start_time_differs() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let (sequence, _) = dispatch_attempt(&mut original, &request());
        drop(original);
        let mut journal = reopened_dispatched_journal(storage);
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(Some(sequence + 100)), events.clone());
        let mut custody = RecordingOrphanCustody::new(events);

        let outcomes = recover_browser_launches(&mut journal, &mut process, &mut custody)
            .expect("finalize recycled pid record");

        assert_eq!(
            outcomes[0].process,
            RecoveredBrowserProcess::StartTimeMismatch
        );
        assert_eq!(process.observation_calls, 1);
        assert_eq!(
            process.termination_calls, 0,
            "a PID match without the recorded start time has no signal authority"
        );
        assert_eq!(custody.releases, vec!["holder-1"]);
        assert_eq!(
            journal
                .read_attempt(sequence)
                .expect("read attempt")
                .terminal_kind,
            Some(cerebellum_core::journal::TerminalKind::RecoveryDispatchFinalized)
        );
    }

    #[test]
    fn startup_recovery_finalizes_a_gone_process_without_signalling() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let (sequence, _) = dispatch_attempt(&mut original, &request());
        drop(original);
        let mut journal = reopened_dispatched_journal(storage);
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(None), events.clone());
        let mut custody = RecordingOrphanCustody::new(events);

        let outcomes = recover_browser_launches(&mut journal, &mut process, &mut custody)
            .expect("finalize absent process record");

        assert_eq!(outcomes[0].process, RecoveredBrowserProcess::NotRunning);
        assert_eq!(process.termination_calls, 0);
        assert_eq!(custody.releases, vec!["holder-1"]);
        assert_eq!(
            journal
                .read_attempt(sequence)
                .expect("read attempt")
                .terminal_kind,
            Some(cerebellum_core::journal::TerminalKind::RecoveryDispatchFinalized)
        );
    }

    #[test]
    fn startup_recovery_never_observes_or_signals_an_unattested_record() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let intent = request().durable_intent();
        let handle = original.record_intent(&intent).expect("record intent");
        let sequence = handle.sequence();
        drop(original);
        let mut journal = reopened_dispatched_journal(storage);
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(Some(1)), events.clone());
        let mut custody = RecordingOrphanCustody::new(events);

        let outcomes = recover_browser_launches(&mut journal, &mut process, &mut custody)
            .expect("cancel unattested record");

        assert_eq!(
            outcomes,
            vec![BrowserLaunchRecoveryOutcome {
                sequence,
                process: RecoveredBrowserProcess::Unattested,
                journal_action: cerebellum_core::journal::RecoveryAction::Cancelled,
            }]
        );
        assert_eq!(process.observation_calls, 0);
        assert_eq!(process.termination_calls, 0);
        assert_eq!(custody.releases, vec!["holder-1"]);
        assert_eq!(
            journal.read_attempt(sequence),
            Err(CoreJournalError::ObligationUnknown)
        );
        assert_eq!(journal.core.classify(sequence), None);
        assert_eq!(journal.core.status().active_reservation_count, 0);
    }

    #[test]
    fn failed_process_recovery_still_terminalizes_journal_and_releases_custody() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let (sequence, _) = dispatch_attempt(&mut original, &request());
        drop(original);
        let mut journal = reopened_dispatched_journal(storage);
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(Some(sequence)), events.clone());
        process.fail_termination = true;
        let mut custody = RecordingOrphanCustody::new(events);

        let outcome = recover_browser_launches(&mut journal, &mut process, &mut custody);

        assert_eq!(
            outcome,
            Err(BrowserLaunchRecoveryFailure::ProcessTermination { sequence })
        );
        assert_eq!(custody.releases, vec!["holder-1"]);
        assert_eq!(
            journal
                .read_attempt(sequence)
                .expect("read attempt")
                .terminal_kind,
            Some(cerebellum_core::journal::TerminalKind::RecoveryDispatchFinalized)
        );
    }

    #[test]
    fn failed_custody_release_does_not_skip_journal_terminalization() {
        let storage = InMemoryJournalStorage::new();
        let mut original = reopened_dispatched_journal(storage.clone());
        let (sequence, _) = dispatch_attempt(&mut original, &request());
        drop(original);
        let mut journal = reopened_dispatched_journal(storage);
        let events = Events::new();
        let mut process = RecordingOrphanProcess::new(Ok(None), events.clone());
        let mut custody = RecordingOrphanCustody::new(events);
        custody.fail = true;

        let outcome = recover_browser_launches(&mut journal, &mut process, &mut custody);

        assert_eq!(
            outcome,
            Err(BrowserLaunchRecoveryFailure::ProfileCustodyRelease { sequence })
        );
        assert_eq!(
            journal
                .read_attempt(sequence)
                .expect("read attempt")
                .terminal_kind,
            Some(cerebellum_core::journal::TerminalKind::RecoveryDispatchFinalized)
        );
    }

    #[test]
    fn finalized_session_releases_exact_active_charge_and_records_typed_outcome() {
        let mut journal = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            InMemoryJournalStorage::new(),
        )
        .expect("open launch journal");
        assert_eq!(journal.core.active_reserved_bytes(), 0);
        assert_eq!(journal.core.retained_bytes(), 0);

        let request = request();
        let (sequence, _) = dispatch_attempt(&mut journal, &request);
        // Capacity now follows the complete durable reservation, not only the
        // attestation payload returned by the plane codec.
        let dispatched_charge = journal.core.active_reserved_bytes();
        assert_ne!(dispatched_charge, 0);
        assert_eq!(journal.core.retained_bytes(), dispatched_charge);

        journal
            .finalize_session(
                &request.launch_attempt_id,
                crate::browser_session::BrowserSessionTerminalOutcome::ModuleShutdown,
            )
            .expect("finalize launch session");
        let expected = LaunchSessionCompletion {
            format_version: LAUNCH_CODEC_VERSION.to_string(),
            launch_attempt_id: request.launch_attempt_id.clone(),
            terminal_outcome: crate::browser_session::BrowserSessionTerminalOutcome::ModuleShutdown,
            failure: None,
        };
        assert_eq!(journal.core.active_reserved_bytes(), 0);
        assert_ne!(journal.core.retained_bytes(), 0);
        assert_eq!(journal.core.status().active_reservation_count, 0);
        assert_eq!(journal.core.status().entry_count, 1);
        assert_eq!(terminal_completion(&journal, sequence), expected);
    }

    #[test]
    fn concurrent_session_teardowns_write_distinct_decodable_journal_records() {
        let mut journal = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            InMemoryJournalStorage::new(),
        )
        .expect("open launch journal");
        let mut first_request = request();
        first_request.launch_attempt_id = "concurrent-attempt-a".to_string();
        let mut second_request = request();
        second_request.launch_attempt_id = "concurrent-attempt-b".to_string();
        let (first_sequence, _) = dispatch_attempt(&mut journal, &first_request);
        let (second_sequence, _) = dispatch_attempt(&mut journal, &second_request);
        assert_ne!(first_sequence, second_sequence);

        let journal = Arc::new(Mutex::new(journal));
        let sessions = crate::browser_session::BrowserSessions::default();
        let clock = cerebellum_core::clock::FakeClock::new();
        let session_config = crate::browser_config::BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10,
            termination_grace_period_ms: 10,
            browser_idle_timeout_ms: 100,
            browser_exit_observation_deadline_ms: 10,
            navigation_settle_deadline_ms: 10,
        };
        for (route, launch_attempt_id) in [
            ("journal-route-a", first_request.launch_attempt_id.clone()),
            ("journal-route-b", second_request.launch_attempt_id.clone()),
        ] {
            let _ = sessions.acquire_launch_slot(route);
            let (_, _, cancelled) = sessions
                .establish_ready(
                    route,
                    cerebellum_core::identity::ProfileDisposition::Durable,
                    &session_config,
                    &clock,
                    Box::new(ImmediateExitProcess),
                    Box::new(JournalFinalizingCleanup {
                        journal: Arc::clone(&journal),
                        launch_attempt_id,
                        terminal_outcome: None,
                    }),
                )
                .expect("establish journal-backed session");
            assert!(!cancelled);
        }

        sessions.teardown_all(&session_config);

        let journal = journal.lock().expect("launch journal");
        for sequence in [first_sequence, second_sequence] {
            let record = journal
                .read_attempt(sequence)
                .expect("read terminal record");
            assert_eq!(record.action_obligation_id, sequence);
            assert_eq!(
                record.lifecycle,
                cerebellum_core::journal::LifecycleState::Finalized
            );
            assert_eq!(
                record.terminal_kind,
                Some(cerebellum_core::journal::TerminalKind::FinalizedCommitted)
            );
        }
        let bytes = journal.core.export_bytes();
        let mut completions = serde_json::Deserializer::from_slice(&bytes)
            .into_iter::<LaunchSessionCompletion>()
            .collect::<Result<Vec<_>, _>>()
            .expect("decode every launch completion");
        completions.sort_by(|left, right| left.launch_attempt_id.cmp(&right.launch_attempt_id));
        assert_eq!(
            completions,
            vec![
                LaunchSessionCompletion::new(
                    &first_request.launch_attempt_id,
                    crate::browser_session::BrowserSessionTerminalOutcome::ModuleShutdown,
                ),
                LaunchSessionCompletion::new(
                    &second_request.launch_attempt_id,
                    crate::browser_session::BrowserSessionTerminalOutcome::ModuleShutdown,
                ),
            ]
        );
    }

    #[test]
    fn repeated_launch_and_close_stays_within_retention_bound() {
        const RETENTION_BOUND: u64 = 16 * 1024;
        const CYCLES: usize = 256;
        let mut journal = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: RETENTION_BOUND,
                journal_max_entry_bytes: RETENTION_BOUND,
            },
            InMemoryJournalStorage::new(),
        )
        .expect("open launch journal");

        for cycle in 0..CYCLES {
            let mut request = request();
            request.launch_attempt_id = format!("attempt-{cycle}");
            let _ = dispatch_attempt(&mut journal, &request);
            assert_ne!(journal.core.active_reserved_bytes(), 0);
            journal
                .finalize_session(
                    &request.launch_attempt_id,
                    crate::browser_session::BrowserSessionTerminalOutcome::Closed,
                )
                .expect("finalize launch session");
            assert_eq!(journal.core.active_reserved_bytes(), 0);
        }

        let status = journal.core.status();
        assert_eq!(status.active_reservation_count, 0);
        assert_eq!(status.active_reserved_bytes, 0);
        assert!(status.retained_bytes <= RETENTION_BOUND);
        assert!(status.entry_count < CYCLES);
    }

    #[test]
    fn failed_session_finalization_keeps_exact_charge_for_retry() {
        let mut journal = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            InMemoryJournalStorage::new(),
        )
        .expect("open launch journal");
        let request = request();
        let _ = dispatch_attempt(&mut journal, &request);
        // A failed write retains the exact full-record charge calculated before
        // the attempt, so retry neither releases nor double-counts capacity.
        let dispatched_charge = journal.core.active_reserved_bytes();
        journal.core.arm_fault("commit_finalization", 1);

        assert_eq!(
            journal.finalize_session(
                &request.launch_attempt_id,
                crate::browser_session::BrowserSessionTerminalOutcome::Closed,
            ),
            Err(CoreJournalError::FinalizationPending)
        );
        assert_eq!(journal.core.active_reserved_bytes(), dispatched_charge);
        assert_eq!(journal.core.retained_bytes(), dispatched_charge);
        assert_eq!(journal.core.status().entry_count, 1);
        assert_eq!(journal.core.status().active_reservation_count, 1);

        assert_eq!(
            journal.finalize_session(
                &request.launch_attempt_id,
                crate::browser_session::BrowserSessionTerminalOutcome::Closed,
            ),
            Ok(())
        );
        assert_eq!(journal.core.active_reserved_bytes(), 0);
        assert_eq!(journal.core.status().entry_count, 1);
    }

    #[test]
    fn second_session_finalization_is_refused_without_double_counting() {
        let mut journal = DurableLaunchJournal::open(
            JournalConfig {
                journal_retention_bytes: 64 * 1024,
                journal_max_entry_bytes: 32 * 1024,
            },
            InMemoryJournalStorage::new(),
        )
        .expect("open launch journal");
        let request = request();
        let _ = dispatch_attempt(&mut journal, &request);
        assert_eq!(
            journal.finalize_session(
                &request.launch_attempt_id,
                crate::browser_session::BrowserSessionTerminalOutcome::Closed,
            ),
            Ok(())
        );
        let retained_after_first = journal.core.retained_bytes();
        assert_eq!(
            journal.finalize_session(
                &request.launch_attempt_id,
                crate::browser_session::BrowserSessionTerminalOutcome::Closed,
            ),
            Err(CoreJournalError::InvalidHandle)
        );
        assert_eq!(journal.core.retained_bytes(), retained_after_first);
        assert_eq!(journal.core.status().entry_count, 1);
    }

    #[test]
    fn macos_launch_seam_contains_no_browser_policy_vocabulary() {
        let seam = include_str!("../../cerebellum-macos/src/launch.rs");
        for policy_term in [
            "holder_id",
            "profile_uuid",
            "launch_attempt_id",
            "executable_identity_mismatch",
            "JournalStorage",
        ] {
            assert!(
                !seam.contains(policy_term),
                "raw macOS seam accumulated browser policy term {policy_term:?}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_real_launch_records_before_spawn_and_after_exec_checkpoints() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let executable = Path::new("/bin/sleep");
        let (expected_identity, pre_spawn_identity_verification) =
            crate::browser_executable_identity::verify_configured_executable(
                executable,
                "com.apple.sleep",
            )
            .expect("verify configured sleep executable before spawn");
        let mut launch_request = request();
        launch_request.executable = executable.to_path_buf();
        launch_request.arguments = vec![OsString::from("30")];
        launch_request.verified_executable_identity = expected_identity;
        launch_request.pre_spawn_identity_verification = pre_spawn_identity_verification;

        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let mut journal = RecordingJournal {
            events: Events::new(),
            fail: FailJournalAt::Never,
            attestation: Arc::new(Mutex::new(None)),
        };

        let released = launch_attested_with(&mut journal, &mut launcher, &launch_request)
            .expect("release pre-spawn-verified and re-attested image");

        assert_eq!(
            released.attestation.executable_identity_checkpoints,
            ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec
        );
        released
            .process
            .terminate_and_reap()
            .expect("reap released sleep fixture");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn actual_image_mismatch_never_runs_the_target() {
        use std::fs;
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "cerebellum-actual-image-mismatch-{}-{sequence}",
            std::process::id()
        ));
        fs::create_dir(&directory).expect("create mismatch directory");
        let effect = directory.join("effect");

        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let expected_child = cerebellum_macos::spawn_barred(
            Path::new("/bin/sleep"),
            &[OsString::from("30")],
            &[],
            command_child.as_raw_fd(),
            response_child.as_raw_fd(),
        )
        .expect("spawn expected image fixture");
        let expected = cerebellum_macos::executed_image_identity(expected_child.generation().pid)
            .expect("read expected image");
        expected_child
            .terminate_and_reap()
            .expect("reap expected image fixture");

        let mut launch_request = request();
        launch_request.executable = PathBuf::from("/bin/sh");
        launch_request.arguments = vec![
            OsString::from("-c"),
            OsString::from(format!("printf ran > '{}'", effect.display())),
        ];
        launch_request.verified_executable_identity = VerifiedExecutableIdentity::CodeSignedFile {
            signing_identifier: expected.signing_identifier,
            slice_code_hashes: BTreeSet::from([expected.unique_code_hash]),
        };

        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let events = Events::new();
        let mut journal = RecordingJournal {
            events,
            fail: FailJournalAt::Never,
            attestation: Arc::new(Mutex::new(None)),
        };

        let outcome = launch_attested_with(&mut journal, &mut launcher, &launch_request);

        match outcome {
            Err(AttestedLaunchError::ExecutableIdentityMismatch {
                claim_kind,
                expected_identity,
                observed_identity,
            }) => {
                assert_eq!(claim_kind, "code_signed");
                assert_eq!(
                    expected_identity,
                    launch_request
                        .verified_executable_identity
                        .display_identity()
                );
                assert!(
                    observed_identity.starts_with("identifier=com.apple.sh;cdhash="),
                    "unexpected running image identity: {observed_identity}"
                );
            }
            Err(other) => panic!("expected exact identity mismatch, got {other:?}"),
            Ok(_) => panic!("mismatched image was released"),
        }
        assert_eq!(
            fs::read(&effect)
                .expect_err("mismatched target must not create its effect")
                .kind(),
            std::io::ErrorKind::NotFound
        );
        fs::remove_dir_all(directory).expect("remove mismatch directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_identity_attestation_walks_from_a_wrapper_to_the_final_image() {
        use std::fs;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let path =
            std::env::temp_dir().join(format!("cerebellum-linux-wrapper-{}", std::process::id()));
        fs::write(&path, "#!/bin/sh\nexec /bin/sleep 30\n").expect("write wrapper fixture");
        let mut permissions = fs::metadata(&path).expect("wrapper metadata").permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("make wrapper executable");

        let expected = sha256_file_for_test(Path::new("/bin/sleep"));
        let mut launch_request = request();
        launch_request.executable = path.clone();
        launch_request.verified_executable_identity = VerifiedExecutableIdentity::ImageDigest {
            sha256: expected.clone(),
        };

        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let child = launcher
            .spawn_barred(&launch_request)
            .expect("spawn wrapper behind Linux barrier");
        assert_eq!(
            child
                .executed_image_identity()
                .expect("attest final image")
                .matched_claim()
                .expect("identity chain is matched")
                .display_identity(),
            format!("sha256={expected}")
        );
        child.terminate_and_reap().expect("reap wrapper fixture");
        fs::remove_file(path).expect("remove wrapper fixture");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_identity_attestation_accepts_a_terminal_image_at_the_hop_bound() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (root, paths) = linux_exec_chain_fixture(8, "exact-hop-bound");

        let mut launch_request = request();
        launch_request.executable = paths[0].clone();
        launch_request.verified_executable_identity = VerifiedExecutableIdentity::ImageDigest {
            sha256: sha256_file_for_test(Path::new("/bin/sleep")),
        };
        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let child = launcher
            .spawn_barred(&launch_request)
            .expect("spawn exact-bound chain fixture");
        assert!(child.executed_image_identity().is_ok());
        child
            .terminate_and_reap()
            .expect("reap exact-bound fixture");
        remove_linux_exec_chain_fixture(root, paths);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_identity_attestation_refuses_a_terminal_image_beyond_the_hop_bound() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let (root, paths) = linux_exec_chain_fixture(9, "beyond-hop-bound");
        let mut launch_request = request();
        launch_request.executable = paths[0].clone();
        launch_request.verified_executable_identity = VerifiedExecutableIdentity::ImageDigest {
            sha256: sha256_file_for_test(Path::new("/bin/sleep")),
        };
        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let child = launcher
            .spawn_barred(&launch_request)
            .expect("spawn beyond-bound chain fixture");
        let Err(PlatformLaunchError::ExecChainUnresolved { chain }) =
            child.executed_image_identity()
        else {
            panic!("beyond-bound chain must be refused with its traversed identities");
        };
        let ExecutableIdentityChain::StoppedAtHopLimit { hops } = chain else {
            panic!("beyond-bound chain must report the hop limit state");
        };
        assert_eq!(hops.len(), 9);
        assert!(hops.iter().all(|hop| hop.path.is_some()));
        drop(child);
        remove_linux_exec_chain_fixture(root, paths);
    }

    #[cfg(target_os = "linux")]
    fn linux_exec_chain_fixture(
        script_count: usize,
        label: &str,
    ) -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
        use std::fs;
        use std::os::unix::fs::PermissionsExt;

        let root =
            std::env::temp_dir().join(format!("cerebellum-linux-{label}-{}", std::process::id()));
        fs::create_dir(&root).expect("create chain fixture directory");
        let mut paths = Vec::new();
        for index in 0..script_count {
            let path = root.join(format!("hop-{index}"));
            let next = if index + 1 == script_count {
                "/bin/sleep".to_string()
            } else {
                root.join(format!("hop-{}", index + 1))
                    .display()
                    .to_string()
            };
            fs::write(&path, format!("#!/bin/sh\nexec {next} 30\n")).expect("write chain fixture");
            let mut permissions = fs::metadata(&path).expect("chain metadata").permissions();
            permissions.set_mode(0o700);
            fs::set_permissions(&path, permissions).expect("make chain fixture executable");
            paths.push(path);
        }
        (root, paths)
    }

    #[cfg(target_os = "linux")]
    fn remove_linux_exec_chain_fixture(root: std::path::PathBuf, paths: Vec<std::path::PathBuf>) {
        use std::fs;

        for path in paths {
            fs::remove_file(path).expect("remove chain fixture");
        }
        fs::remove_dir(root).expect("remove chain fixture directory");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_success_records_after_exec_only_checkpoint() {
        use std::fs;
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::PermissionsExt;
        use std::os::unix::net::UnixStream;

        let path = std::env::temp_dir().join(format!(
            "cerebellum-linux-checkpoint-{}",
            std::process::id()
        ));
        fs::write(&path, "#!/bin/sh\nexec /bin/sleep 30\n").expect("write checkpoint fixture");
        let mut permissions = fs::metadata(&path)
            .expect("checkpoint metadata")
            .permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(&path, permissions).expect("make checkpoint executable");

        let mut launch_request = request();
        launch_request.executable = path.clone();
        launch_request.verified_executable_identity = VerifiedExecutableIdentity::ImageDigest {
            sha256: sha256_file_for_test(Path::new("/bin/sleep")),
        };
        launch_request.pre_spawn_identity_verification = PreSpawnIdentityVerification::Unavailable;
        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            LinuxProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let mut journal = RecordingJournal {
            events: Events::new(),
            fail: FailJournalAt::Never,
            attestation: Arc::new(Mutex::new(None)),
        };
        let attestation = journal.attestation.clone();
        let released = launch_attested_with(&mut journal, &mut launcher, &launch_request)
            .expect("release Linux fixture after final-image attestation");
        assert_eq!(
            released.attestation.executable_identity_checkpoints,
            ExecutableIdentityCheckpoints::AfterExecOnly
        );
        assert_eq!(
            released.attestation.observed_executable_identity,
            ExecutableIdentityClaim::ImageDigest {
                sha256: sha256_file_for_test(Path::new("/bin/sleep")),
            }
        );
        let recorded = attestation
            .lock()
            .expect("recorded attestation")
            .clone()
            .expect("success path attestation");
        let ExecutableIdentityChain::WalkedToMatch { hops } = recorded.executable_identity_chain
        else {
            panic!("successful launch must record a completed identity chain");
        };
        assert_eq!(hops.len(), 2);
        // The interpreter and the final image are resolved from the filesystem
        // rather than named, because both are distribution details: /bin/sh is
        // dash on Debian and Ubuntu and bash on Fedora and Arch, and the split
        // between /bin and /usr/bin differs across usrmerge states. Naming
        // either one asserts which distribution the test is running on, which
        // is not the property under test.
        //
        // What IS under test survives that: the walk followed the script to its
        // interpreter and on to the image actually executed, rather than
        // reporting the script it was handed. Deriving the expectation from
        // canonicalize is not circular -- it is a filesystem fact, read by a
        // different mechanism than the exec-chain walk that produced the hops.
        let expected_interpreter =
            fs::canonicalize("/bin/sh").expect("the system shell resolves to a real image");
        let expected_final =
            fs::canonicalize("/bin/sleep").expect("the sleep binary resolves to a real image");
        assert_eq!(
            hops[0].path,
            Some(expected_interpreter),
            "the first hop must be the interpreter the script names"
        );
        assert_eq!(
            hops[1].path,
            Some(expected_final),
            "the last hop must be the image actually executed"
        );
        released
            .process
            .terminate_and_reap()
            .expect("reap checkpoint fixture");
        fs::remove_file(path).expect("remove checkpoint fixture");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_unreadable_generation_is_not_an_identity_mismatch() {
        assert_eq!(
            map_linux_image_identity_error(
                cerebellum_linux::ImageIdentityError::ProcessInspectionDenied
            ),
            PlatformLaunchError::GenerationUnreadable
        );
        assert_ne!(
            map_linux_image_identity_error(
                cerebellum_linux::ImageIdentityError::ProcessInspectionDenied
            ),
            PlatformLaunchError::ImageIdentity
        );
        assert_eq!(
            map_linux_image_identity_error(cerebellum_linux::ImageIdentityError::ProcessMissing),
            PlatformLaunchError::ProcessControl
        );
    }

    #[cfg(target_os = "linux")]
    fn sha256_file_for_test(path: &Path) -> String {
        use sha2::{Digest, Sha256};
        use std::fs;

        let digest = Sha256::digest(fs::read(path).expect("read digest fixture"));
        digest.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}

use serde_json::{json, Value};

use crate::profile::{
    untrustworthy_registry_reason_code, untrustworthy_registry_remedy, AbortCause, AbortResult,
    DispatchCommitmentToken, InvocationToken, JournalReservationHandle, LaunchResult,
    OpenedContext, PrepareResult, PreparedOpen, PreparedProfileAttempt, ProfileDisposition,
    ProfileLifecycle, ProfileOutcome, ReleaseCause, ReleaseResult, StampedBindContext,
    UntrustworthyRegistryReason,
};
use crate::profile_custody::{
    HolderId, ProfileCustodyAcquisition, ProfileCustodyClaim, ProfileCustodyJournal,
    ProfileCustodyKey, ProfileCustodyLocks, ProfileCustodyRelease, SupervisorLivenessProbe,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchCleanupStage {
    RecordTerminalization,
    CustodyRelease,
    DisposableDelete,
}

impl LaunchCleanupStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecordTerminalization => "record_terminalization",
            Self::CustodyRelease => "custody_release",
            Self::DisposableDelete => "disposable_delete",
        }
    }
}

/// Wire launch outcomes do not contain a profile UUID by construction. The only
/// profile contention identity this type can carry is a custody holder id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserLaunchOutcome {
    ProfileBusy { holder_id: HolderId },
    ProfileGrantRequired,
    ProfileRegistryUntrustedRoot { reason: UntrustworthyRegistryReason },
    ProfileStorageUnavailable { reason_code: &'static str },
    InternalFailure { reason_code: &'static str },
    CleanupFailure { stage: LaunchCleanupStage },
}

impl BrowserLaunchOutcome {
    pub fn as_json(&self) -> Value {
        match self {
            Self::ProfileBusy { holder_id } => {
                // Says WHY the profile is held, because the common cause looks
                // like a defect from the caller's seat. Two live sessions on one
                // project resolve to the SAME durable profile -- that is the
                // point, since a login set up once must survive -- and the
                // exclusive lock serializes them rather than letting both write.
                // A caller told only "busy" reasonably reports a bug; a caller
                // told another session holds it can wait or close the other one.
                json!({
                    "outcome": "profile_busy",
                    "holder_id": holder_id.as_str(),
                    "remedy": "another session holds this project's browser profile; \
                               close that session's browser or retry once it releases",
                })
            }
            Self::ProfileGrantRequired => json!({"outcome": "profile_grant_required"}),
            Self::ProfileRegistryUntrustedRoot { reason } => {
                let mut response = json!({
                    "outcome": "profile_registry_untrusted_root",
                    "reason_code": untrustworthy_registry_reason_code(*reason),
                });
                if let Some(remedy) = untrustworthy_registry_remedy(*reason) {
                    response["remedy"] = Value::String(remedy.to_string());
                }
                response
            }
            Self::ProfileStorageUnavailable { reason_code } => json!({
                "outcome": "profile_storage_unavailable",
                "reason_code": reason_code,
            }),
            Self::InternalFailure { reason_code } => json!({
                "outcome": "internal_failure",
                "reason_code": reason_code,
            }),
            Self::CleanupFailure { stage } => {
                json!({"outcome": "cleanup_failure", "stage": stage.as_str()})
            }
        }
    }
}

#[cfg(test)]
mod profile_registry_outcome_tests {
    use super::*;

    #[test]
    fn untrusted_root_remedies_are_typed_and_selective() {
        let identity_changed = BrowserLaunchOutcome::ProfileRegistryUntrustedRoot {
            reason: UntrustworthyRegistryReason::ManagedRootIdentityChanged,
        }
        .as_json();
        assert_eq!(
            identity_changed["remedy"],
            "run browser.rebind_profile_root to re-identify the restored or moved browser root; \
             that operation will itself refuse and name any directory the registry did not mint"
        );

        let possibly_managed = BrowserLaunchOutcome::ProfileRegistryUntrustedRoot {
            reason: UntrustworthyRegistryReason::PossiblyManagedPath,
        }
        .as_json();
        assert_eq!(
            possibly_managed["remedy"],
            "move or account for the unaccounted profile directories before running \
             browser.rebind_profile_root; the rebind operation will not adopt them"
        );

        let malformed = BrowserLaunchOutcome::ProfileRegistryUntrustedRoot {
            reason: UntrustworthyRegistryReason::MalformedRegistry,
        }
        .as_json();
        assert!(malformed.get("remedy").is_none(), "{malformed}");
    }
}

/// Exhaustive mapping for the profile API's closed outcome. In particular,
/// registry `ProfileBusy` is disagreement with an already-held custody claim and
/// cannot be reported as contention.
pub fn map_profile_outcome(outcome: ProfileOutcome) -> BrowserLaunchOutcome {
    match outcome {
        ProfileOutcome::ProfileBusy { profile_uuid: _ } => BrowserLaunchOutcome::InternalFailure {
            reason_code: "registry_profile_busy",
        },
        ProfileOutcome::ProfileGrantRequired { reason_code: _ } => {
            BrowserLaunchOutcome::ProfileGrantRequired
        }
        ProfileOutcome::NoSession { reason_code } => {
            BrowserLaunchOutcome::InternalFailure { reason_code }
        }
        ProfileOutcome::UntrustworthyRegistry { reason } => {
            BrowserLaunchOutcome::ProfileRegistryUntrustedRoot { reason }
        }
        ProfileOutcome::StorageUnavailable {
            reason_code,
            origin: _,
        } => BrowserLaunchOutcome::ProfileStorageUnavailable { reason_code },
        ProfileOutcome::InternalFailure { reason_code } => {
            BrowserLaunchOutcome::InternalFailure { reason_code }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldPreparedProfile {
    prepared: PreparedOpen,
    attempt: PreparedProfileAttempt,
    claim: ProfileCustodyClaim,
}

impl HeldPreparedProfile {
    pub fn holder_id(&self) -> &HolderId {
        self.claim.holder_id()
    }

    pub fn attempt(&self) -> &PreparedProfileAttempt {
        &self.attempt
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeldOpenedProfile {
    opened: OpenedContext,
    attempt: PreparedProfileAttempt,
    claim: ProfileCustodyClaim,
}

impl HeldOpenedProfile {
    pub fn holder_id(&self) -> &HolderId {
        self.claim.holder_id()
    }

    pub fn opened(&self) -> &OpenedContext {
        &self.opened
    }

    pub fn profile_directory(&self) -> &Path {
        self.attempt.directory()
    }
}

pub struct ProfileBoundLaunch<'a, J, P>
where
    J: ProfileCustodyJournal,
    P: SupervisorLivenessProbe,
{
    lifecycle: &'a mut ProfileLifecycle,
    locks: &'a mut ProfileCustodyLocks<J, P>,
}

impl<'a, J, P> ProfileBoundLaunch<'a, J, P>
where
    J: ProfileCustodyJournal,
    P: SupervisorLivenessProbe,
{
    pub fn new(
        lifecycle: &'a mut ProfileLifecycle,
        locks: &'a mut ProfileCustodyLocks<J, P>,
    ) -> Self {
        Self { lifecycle, locks }
    }

    /// Acquire the logical profile before the existing prepare API performs any
    /// profile mutation. Failure after acquisition enters the same rollback path
    /// even when preparation itself did not finish.
    pub fn acquire_and_prepare(
        &mut self,
        key: ProfileCustodyKey,
        invocation: &InvocationToken,
        reservation: &JournalReservationHandle,
        context: &StampedBindContext,
    ) -> Result<HeldPreparedProfile, BrowserLaunchOutcome> {
        let holder_id =
            self.locks
                .mint_holder()
                .map_err(|_| BrowserLaunchOutcome::InternalFailure {
                    reason_code: "custody_holder_mint",
                })?;
        let mut claim = match self.locks.acquire(key, holder_id) {
            Ok(ProfileCustodyAcquisition::Acquired(claim)) => claim,
            Ok(ProfileCustodyAcquisition::ProfileBusy { holder_id }) => {
                return Err(BrowserLaunchOutcome::ProfileBusy { holder_id })
            }
            Err(_) => {
                return Err(BrowserLaunchOutcome::InternalFailure {
                    reason_code: "custody_acquisition",
                })
            }
        };

        let prepared = match self
            .lifecycle
            .prepare_context_open(invocation, reservation, context)
        {
            PrepareResult::Prepared(prepared) => prepared,
            PrepareResult::Closed(outcome) => {
                let primary = map_profile_outcome(outcome);
                return match self.release_unprepared(&claim) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(cleanup),
                };
            }
        };
        let attempt = match self.lifecycle.prepared_profile_attempt(&prepared) {
            Ok(attempt) => attempt,
            Err(outcome) => {
                let primary = map_profile_outcome(outcome);
                return match self.rollback_prepared_parts(prepared, None, claim) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(cleanup),
                };
            }
        };
        if self
            .locks
            .bind_profile_directory(&mut claim, attempt.directory())
            .is_err()
        {
            return match self.rollback_prepared_parts(prepared, Some(attempt), claim) {
                Ok(()) => Err(BrowserLaunchOutcome::InternalFailure {
                    reason_code: "custody_profile_directory_bind",
                }),
                Err(cleanup) => Err(cleanup),
            };
        }
        Ok(HeldPreparedProfile {
            prepared,
            attempt,
            claim,
        })
    }

    pub fn launch_prepared(
        &mut self,
        held: HeldPreparedProfile,
        token: &DispatchCommitmentToken,
    ) -> Result<HeldOpenedProfile, BrowserLaunchOutcome> {
        if self.locks.verify_exact_holder(&held.claim).is_err() {
            return Err(BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::CustodyRelease,
            });
        }
        match self
            .lifecycle
            .launch_prepared_context(held.prepared.clone(), token)
        {
            LaunchResult::Opened(opened) => Ok(HeldOpenedProfile {
                opened,
                attempt: held.attempt,
                claim: held.claim,
            }),
            LaunchResult::Closed(outcome) => {
                let primary = map_profile_outcome(outcome);
                match self.rollback_prepared(held) {
                    Ok(()) => Err(primary),
                    Err(cleanup) => Err(cleanup),
                }
            }
        }
    }

    pub fn into_opened_rollback(self, held: HeldOpenedProfile) -> OpenedProfileRollback<'a, J, P> {
        OpenedProfileRollback {
            lifecycle: self.lifecycle,
            locks: self.locks,
            held: Some(held),
            cleanup_failure: None,
        }
    }

    /// Roll back a failure that happened before the profile API transferred the
    /// prepared handle into an opened context.
    pub fn rollback_prepared(
        &mut self,
        held: HeldPreparedProfile,
    ) -> Result<(), BrowserLaunchOutcome> {
        self.rollback_prepared_parts(held.prepared, Some(held.attempt), held.claim)
    }

    /// Roll back a failure after profile launch but before a ready session owns
    /// the profile. Callers invoke this only after any child has been reaped.
    pub fn rollback_opened(&mut self, held: HeldOpenedProfile) -> Result<(), BrowserLaunchOutcome> {
        self.locks.verify_exact_holder(&held.claim).map_err(|_| {
            BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::CustodyRelease,
            }
        })?;
        self.locks
            .record_rollback_terminalization(&held.claim)
            .map_err(|_| BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::RecordTerminalization,
            })?;
        let rollback = self
            .lifecycle
            .terminalize_opened_rollback(&held.opened, ReleaseCause::SessionEnd)
            .map_err(|_| BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::RecordTerminalization,
            })?;
        self.release_and_delete(&held.claim, &held.attempt)?;
        match self
            .lifecycle
            .complete_opened_rollback(rollback, &held.attempt)
        {
            ReleaseResult::Released => Ok(()),
            ReleaseResult::Closed(_) => Err(BrowserLaunchOutcome::CleanupFailure {
                stage: cleanup_stage_after_profile_completion(&held.attempt),
            }),
        }
    }

    fn rollback_prepared_parts(
        &mut self,
        prepared: PreparedOpen,
        attempt: Option<PreparedProfileAttempt>,
        claim: ProfileCustodyClaim,
    ) -> Result<(), BrowserLaunchOutcome> {
        self.locks.verify_exact_holder(&claim).map_err(|_| {
            BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::CustodyRelease,
            }
        })?;
        self.locks
            .record_rollback_terminalization(&claim)
            .map_err(|_| BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::RecordTerminalization,
            })?;
        let rollback = self
            .lifecycle
            .terminalize_prepared_rollback(&prepared, AbortCause::Teardown)
            .map_err(|_| BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::RecordTerminalization,
            })?;
        let attempt = attempt.ok_or(BrowserLaunchOutcome::CleanupFailure {
            stage: LaunchCleanupStage::RecordTerminalization,
        })?;
        self.release_and_delete(&claim, &attempt)?;
        match self
            .lifecycle
            .complete_prepared_rollback(rollback, &attempt)
        {
            AbortResult::Aborted(_) => Ok(()),
            AbortResult::Closed(_) => Err(BrowserLaunchOutcome::CleanupFailure {
                stage: cleanup_stage_after_profile_completion(&attempt),
            }),
        }
    }

    fn release_unprepared(
        &mut self,
        claim: &ProfileCustodyClaim,
    ) -> Result<(), BrowserLaunchOutcome> {
        self.locks
            .record_rollback_terminalization(claim)
            .map_err(|_| BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::RecordTerminalization,
            })?;
        match self.locks.release_exact(claim) {
            Ok(ProfileCustodyRelease::Released) => Ok(()),
            Ok(ProfileCustodyRelease::HolderMismatch { .. } | ProfileCustodyRelease::Missing)
            | Err(_) => Err(BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::CustodyRelease,
            }),
        }
    }

    fn release_and_delete(
        &mut self,
        claim: &ProfileCustodyClaim,
        attempt: &PreparedProfileAttempt,
    ) -> Result<(), BrowserLaunchOutcome> {
        if claim.profile_directory() != Some(attempt.directory()) {
            return Err(BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::CustodyRelease,
            });
        }
        if attempt.disposition() == ProfileDisposition::Disposable {
            self.locks.record_disposable_delete(claim).map_err(|_| {
                BrowserLaunchOutcome::CleanupFailure {
                    stage: LaunchCleanupStage::DisposableDelete,
                }
            })?;
        }
        match self.locks.release_exact(claim) {
            Ok(ProfileCustodyRelease::Released) => {}
            Ok(ProfileCustodyRelease::HolderMismatch { .. } | ProfileCustodyRelease::Missing)
            | Err(_) => {
                return Err(BrowserLaunchOutcome::CleanupFailure {
                    stage: LaunchCleanupStage::CustodyRelease,
                })
            }
        }
        Ok(())
    }
}

/// Readiness invokes this adapter only after it has confirmed the child is gone
/// and reaped. The held profile is consumed once, so a second callback cannot
/// repeat terminalization, release, or deletion.
pub struct OpenedProfileRollback<'a, J, P>
where
    J: ProfileCustodyJournal,
    P: SupervisorLivenessProbe,
{
    lifecycle: &'a mut ProfileLifecycle,
    locks: &'a mut ProfileCustodyLocks<J, P>,
    held: Option<HeldOpenedProfile>,
    cleanup_failure: Option<BrowserLaunchOutcome>,
}

impl<J, P> OpenedProfileRollback<'_, J, P>
where
    J: ProfileCustodyJournal,
    P: SupervisorLivenessProbe,
{
    pub fn cleanup_failure(&self) -> Option<&BrowserLaunchOutcome> {
        self.cleanup_failure.as_ref()
    }

    pub fn rollback_now(&mut self) -> Result<(), BrowserLaunchOutcome> {
        let held = self
            .held
            .take()
            .ok_or(BrowserLaunchOutcome::InternalFailure {
                reason_code: "opened_rollback_already_consumed",
            })?;
        match ProfileBoundLaunch::new(self.lifecycle, self.locks).rollback_opened(held) {
            Ok(()) => Ok(()),
            Err(outcome) => {
                self.cleanup_failure = Some(outcome.clone());
                Err(outcome)
            }
        }
    }
}

impl<J, P> FailedLaunchRollback for OpenedProfileRollback<'_, J, P>
where
    J: ProfileCustodyJournal,
    P: SupervisorLivenessProbe,
{
    fn rollback(
        &mut self,
        _failure: &ProfileStartupIndeterminate,
    ) -> Result<(), PlatformLaunchError> {
        self.rollback_now()
            .map_err(|_| PlatformLaunchError::ProcessControl)
    }

    fn rollback_attested(
        &mut self,
        _failure: &AttestedLaunchError,
    ) -> Result<(), PlatformLaunchError> {
        self.rollback_now()
            .map_err(|_| PlatformLaunchError::ProcessControl)
    }
}

fn cleanup_stage_after_profile_completion(attempt: &PreparedProfileAttempt) -> LaunchCleanupStage {
    if attempt.disposition() == ProfileDisposition::Disposable {
        LaunchCleanupStage::DisposableDelete
    } else {
        LaunchCleanupStage::RecordTerminalization
    }
}

/// This compile-time shape assertion fails if a future wire-facing outcome can
/// carry a profile UUID or profile path without updating the structural fence.
const _: fn(BrowserLaunchOutcome) = |outcome| match outcome {
    BrowserLaunchOutcome::ProfileBusy { holder_id: _ }
    | BrowserLaunchOutcome::ProfileGrantRequired
    | BrowserLaunchOutcome::ProfileRegistryUntrustedRoot { reason: _ }
    | BrowserLaunchOutcome::ProfileStorageUnavailable { reason_code: _ }
    | BrowserLaunchOutcome::InternalFailure { reason_code: _ }
    | BrowserLaunchOutcome::CleanupFailure { stage: _ } => {}
};
