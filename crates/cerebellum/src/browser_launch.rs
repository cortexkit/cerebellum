//! Crash-safe browser process creation through the durable journal.
//!
//! This module owns ordering and policy. Platform code returns process and
//! code-signing facts; the journal decides whether release may be reached.

use std::collections::HashMap;
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

const GENERATION_SLOT: &str = "browser.launch.generation";
const ATTESTATION_SLOT: &str = "browser.launch.attestation";
const LAUNCH_CODEC_VERSION: &str = "ck-browser-launch-attestation/v1";

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
    pub canonical_profile_path: Vec<u8>,
    pub disposition: cerebellum_core::identity::ProfileDisposition,
}

/// Signature identity recorded after verifying that the selected executable has
/// the expected code-signing identifier and unique code hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutableIdentity {
    pub signing_identifier: String,
    pub unique_code_hash: String,
}

impl ExecutableIdentity {
    pub fn display_identity(&self) -> String {
        format!(
            "identifier={};cdhash={}",
            self.signing_identifier, self.unique_code_hash
        )
    }
}

/// The exact executable and argument bytes submitted to the platform launcher.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedLaunchVector {
    pub executable: Vec<u8>,
    pub arguments: Vec<Vec<u8>>,
    pub environment: Vec<(Vec<u8>, Vec<u8>)>,
}

impl VerifiedLaunchVector {
    pub fn new(
        executable: &Path,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
    ) -> Self {
        use std::os::unix::ffi::OsStrExt;
        Self {
            executable: executable.as_os_str().as_bytes().to_vec(),
            arguments: arguments
                .iter()
                .map(|argument| argument.as_os_str().as_bytes().to_vec())
                .collect(),
            environment: environment
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_os_str().as_bytes().to_vec(),
                        value.as_os_str().as_bytes().to_vec(),
                    )
                })
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
    pub verified_executable_identity: ExecutableIdentity,
    pub launch_vector: VerifiedLaunchVector,
}

/// Exact process generation obtained from the kernel after suspended creation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserProcessGeneration {
    pub pid: u32,
    pub start_time_micros: u64,
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
    pub observed_executable_identity: ExecutableIdentity,
}

/// Durable result recorded when the launched browser session ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchSessionCompletion {
    pub format_version: String,
    pub launch_attempt_id: String,
    pub terminal_outcome: crate::browser_session::BrowserSessionTerminalOutcome,
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
        }
    }
}

/// Terminal mismatch record. The process is still barred when this is written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchIdentityMismatchRecord {
    pub generation: LaunchGenerationRecord,
    pub expected_identity: String,
    pub observed_identity: String,
}

/// Inputs whose route, profile, executable, arguments, and environment have
/// already been authorized and verified before process creation begins.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedLaunchRequest {
    pub launch_attempt_id: String,
    pub holder_id: String,
    pub route: LaunchRouteIdentity,
    pub profile: LaunchProfileIdentity,
    pub executable: PathBuf,
    pub arguments: Vec<OsString>,
    pub environment: Vec<(OsString, OsString)>,
    pub verified_executable_identity: ExecutableIdentity,
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
    ImageAttestationFailed {
        expected_identity: String,
    },
    ExecutableIdentityMismatch {
        expected_identity: String,
        observed_identity: String,
    },
    TerminationOrReapFailed,
    ReleaseFailed,
}

/// Journal operations needed by the ordering state machine.
pub trait LaunchJournalPort {
    type Handle;

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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformLaunchError {
    Spawn,
    ImageIdentity,
    ProcessControl,
}

/// A barred process exposes facts and terminal controls, not launch policy.
pub trait BarredLaunchProcess: Sized {
    type Released;

    fn generation(&self) -> BrowserProcessGeneration;
    fn executed_image_identity(&self) -> Result<ExecutableIdentity, PlatformLaunchError>;
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
        .map_err(|_| AttestedLaunchError::SpawnFailed)?;
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

    let observed = match child.executed_image_identity() {
        Ok(identity) => identity,
        Err(_) => {
            let expected_identity = request.verified_executable_identity.display_identity();
            return match child.terminate_and_reap() {
                Ok(()) => Err(AttestedLaunchError::ImageAttestationFailed { expected_identity }),
                Err(_) => Err(AttestedLaunchError::TerminationOrReapFailed),
            };
        }
    };

    if observed != request.verified_executable_identity {
        let mismatch = LaunchIdentityMismatchRecord {
            generation,
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
            expected_identity: mismatch.expected_identity,
            observed_identity: mismatch.observed_identity,
        });
    }

    let attestation = LaunchAttestationRecord {
        generation,
        observed_executable_identity: observed,
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

    let process = child
        .release()
        .map_err(|_| AttestedLaunchError::ReleaseFailed)?;
    Ok(ReleasedAttestedBrowser {
        attestation,
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
        let token = self
            .dispatched
            .get(launch_attempt_id)
            .copied()
            .ok_or(CoreJournalError::InvalidHandle)?;
        let completion = LaunchSessionCompletion::new(launch_attempt_id, terminal_outcome);
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
pub struct MacOsBarredProcess(cerebellum_macos::BarredChild);

#[cfg(target_os = "macos")]
impl BarredLaunchProcess for MacOsBarredProcess {
    type Released = cerebellum_macos::ReleasedChild;

    fn generation(&self) -> BrowserProcessGeneration {
        let generation = self.0.generation();
        BrowserProcessGeneration {
            pid: generation.pid,
            start_time_micros: generation.start_time_micros,
        }
    }

    fn executed_image_identity(&self) -> Result<ExecutableIdentity, PlatformLaunchError> {
        let generation = self.0.generation();
        let observed = cerebellum_macos::executed_image_identity(generation.pid)
            .map_err(|_| PlatformLaunchError::ImageIdentity)?;
        if cerebellum_macos::process_start_time_micros(generation.pid)
            != Some(generation.start_time_micros)
        {
            return Err(PlatformLaunchError::ImageIdentity);
        }
        Ok(ExecutableIdentity {
            signing_identifier: observed.signing_identifier,
            unique_code_hash: observed.unique_code_hash,
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
        .map(MacOsBarredProcess)
        .map_err(|_| PlatformLaunchError::Spawn)
    }
}

#[cfg(test)]
mod tests {
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
    }

    impl LaunchJournalPort for RecordingJournal {
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
        observed: Result<ExecutableIdentity, PlatformLaunchError>,
        generation: BrowserProcessGeneration,
    }

    impl Drop for FakeBarredProcess {
        fn drop(&mut self) {
            self.events.push("barred_dropped");
        }
    }

    struct FakeReleasedProcess;

    impl BarredLaunchProcess for FakeBarredProcess {
        type Released = FakeReleasedProcess;

        fn generation(&self) -> BrowserProcessGeneration {
            self.generation
        }

        fn executed_image_identity(&self) -> Result<ExecutableIdentity, PlatformLaunchError> {
            self.events.push("image_attested");
            self.observed.clone()
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
        observed: Result<ExecutableIdentity, PlatformLaunchError>,
        spawn: Result<(), PlatformLaunchError>,
    }

    impl BarredProcessLauncher for FakeLauncher {
        type Process = FakeBarredProcess;

        fn spawn_barred(
            &mut self,
            _request: &AttestedLaunchRequest,
        ) -> Result<Self::Process, PlatformLaunchError> {
            self.events.push("spawned_barred");
            self.spawn?;
            Ok(FakeBarredProcess {
                events: self.events.clone(),
                observed: self.observed.clone(),
                generation: BrowserProcessGeneration {
                    pid: 42,
                    start_time_micros: 77,
                },
            })
        }
    }

    fn identity() -> ExecutableIdentity {
        ExecutableIdentity {
            signing_identifier: "com.example.browser".to_string(),
            unique_code_hash: "a1b2c3".to_string(),
        }
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
            verified_executable_identity: identity(),
        }
    }

    fn dispatch_attempt(
        journal: &mut DurableLaunchJournal<InMemoryJournalStorage>,
        request: &AttestedLaunchRequest,
    ) -> (u64, LaunchAttestationRecord) {
        let intent = request.durable_intent();
        let mut handle = journal.record_intent(&intent).expect("record intent");
        let sequence = handle.sequence();
        let generation = LaunchGenerationRecord {
            intent,
            process_generation: BrowserProcessGeneration {
                pid: 42,
                start_time_micros: sequence,
            },
        };
        journal
            .record_generation(&mut handle, &generation)
            .expect("record generation");
        let attestation = LaunchAttestationRecord {
            generation,
            observed_executable_identity: identity(),
        };
        journal
            .commit_attestation(&mut handle, &attestation)
            .expect("commit attestation");
        (sequence, attestation)
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
        observed: Result<ExecutableIdentity, PlatformLaunchError>,
    ) -> (RecordingJournal, FakeLauncher, Events) {
        let events = Events::new();
        (
            RecordingJournal {
                events: events.clone(),
                fail,
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
            Ok(released) => assert_eq!(
                released.attestation.generation.process_generation,
                BrowserProcessGeneration {
                    pid: 42,
                    start_time_micros: 77,
                }
            ),
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
        let observed = ExecutableIdentity {
            signing_identifier: "com.example.substitute".to_string(),
            unique_code_hash: "deadbeef".to_string(),
        };
        let (mut journal, mut launcher, events) =
            harness(FailJournalAt::Never, Ok(observed.clone()));

        let outcome = launch_attested_with(&mut journal, &mut launcher, &request());

        assert_eq!(
            outcome.map(|_| ()),
            Err(AttestedLaunchError::ExecutableIdentityMismatch {
                expected_identity: identity().display_identity(),
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
            },
        };
        journal
            .record_generation(&mut handle, &generation)
            .expect("record generation");
        let attestation = LaunchAttestationRecord {
            generation,
            observed_executable_identity: identity(),
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
        let (sequence, attestation) = dispatch_attempt(&mut journal, &request);
        let dispatched_charge = serde_json::to_vec(&attestation).unwrap().len() as u64;
        assert_eq!(journal.core.active_reserved_bytes(), dispatched_charge);
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
        };
        let expected_terminal_bytes = serde_json::to_vec(&expected).unwrap().len() as u64;
        assert_eq!(journal.core.active_reserved_bytes(), 0);
        assert_eq!(journal.core.retained_bytes(), expected_terminal_bytes);
        assert_eq!(journal.core.status().active_reservation_count, 0);
        assert_eq!(journal.core.status().entry_count, 1);
        assert_eq!(terminal_completion(&journal, sequence), expected);
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
            let (_, attestation) = dispatch_attempt(&mut journal, &request);
            assert_eq!(
                journal.core.active_reserved_bytes(),
                serde_json::to_vec(&attestation).unwrap().len() as u64
            );
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
        let (_, attestation) = dispatch_attempt(&mut journal, &request);
        let dispatched_charge = serde_json::to_vec(&attestation).unwrap().len() as u64;
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
        launch_request.verified_executable_identity = ExecutableIdentity {
            signing_identifier: expected.signing_identifier,
            unique_code_hash: expected.unique_code_hash,
        };

        let (command_child, _command_parent) = UnixStream::pair().expect("command pair");
        let (_response_parent, response_child) = UnixStream::pair().expect("response pair");
        let mut launcher =
            MacOsProcessLauncher::new(command_child.as_raw_fd(), response_child.as_raw_fd());
        let events = Events::new();
        let mut journal = RecordingJournal {
            events,
            fail: FailJournalAt::Never,
        };

        let outcome = launch_attested_with(&mut journal, &mut launcher, &launch_request);

        match outcome {
            Err(AttestedLaunchError::ExecutableIdentityMismatch {
                expected_identity,
                observed_identity,
            }) => {
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
}

use serde_json::{json, Value};

use crate::profile::{
    AbortCause, AbortResult, DispatchCommitmentToken, InvocationToken, JournalReservationHandle,
    LaunchResult, OpenedContext, PrepareResult, PreparedOpen, PreparedProfileAttempt,
    ProfileDisposition, ProfileLifecycle, ProfileOutcome, ReleaseCause, ReleaseResult,
    StampedBindContext,
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
    ProfileStorageUnavailable,
    InternalFailure,
    CleanupFailure { stage: LaunchCleanupStage },
}

impl BrowserLaunchOutcome {
    pub fn as_json(&self) -> Value {
        match self {
            Self::ProfileBusy { holder_id } => {
                json!({"outcome": "profile_busy", "holder_id": holder_id.as_str()})
            }
            Self::ProfileGrantRequired => json!({"outcome": "profile_grant_required"}),
            Self::ProfileStorageUnavailable => {
                json!({"outcome": "profile_storage_unavailable"})
            }
            Self::InternalFailure => json!({"outcome": "internal_failure"}),
            Self::CleanupFailure { stage } => {
                json!({"outcome": "cleanup_failure", "stage": stage.as_str()})
            }
        }
    }
}

/// Exhaustive mapping for the profile API's closed outcome. In particular,
/// registry `ProfileBusy` is disagreement with an already-held custody claim and
/// cannot be reported as contention.
pub fn map_profile_outcome(outcome: ProfileOutcome) -> BrowserLaunchOutcome {
    match outcome {
        ProfileOutcome::ProfileBusy { profile_uuid: _ } => BrowserLaunchOutcome::InternalFailure,
        ProfileOutcome::ProfileGrantRequired { reason_code: _ } => {
            BrowserLaunchOutcome::ProfileGrantRequired
        }
        ProfileOutcome::NoSession { reason_code: _ } => BrowserLaunchOutcome::InternalFailure,
        ProfileOutcome::StorageUnavailable {
            reason_code: _,
            origin: _,
        } => BrowserLaunchOutcome::ProfileStorageUnavailable,
        ProfileOutcome::InternalFailure { reason_code: _ } => BrowserLaunchOutcome::InternalFailure,
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
        let holder_id = self
            .locks
            .mint_holder()
            .map_err(|_| BrowserLaunchOutcome::InternalFailure)?;
        let mut claim = match self.locks.acquire(key, holder_id) {
            Ok(ProfileCustodyAcquisition::Acquired(claim)) => claim,
            Ok(ProfileCustodyAcquisition::ProfileBusy { holder_id }) => {
                return Err(BrowserLaunchOutcome::ProfileBusy { holder_id })
            }
            Err(_) => return Err(BrowserLaunchOutcome::InternalFailure),
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
                Ok(()) => Err(BrowserLaunchOutcome::InternalFailure),
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
            .ok_or(BrowserLaunchOutcome::InternalFailure)?;
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
    | BrowserLaunchOutcome::ProfileStorageUnavailable
    | BrowserLaunchOutcome::InternalFailure
    | BrowserLaunchOutcome::CleanupFailure { stage: _ } => {}
};
