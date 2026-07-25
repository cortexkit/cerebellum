//! Canonical managed-Chromium custody and launch-quarantine primitives.
//!
//! This module is deliberately data-oriented.  Registration can validate a
//! release artifact without launching a browser, while the launch gate makes
//! the ordering needed by the enforcing connector explicit: inspect a child
//! while quarantine is closed, issue a proof for that exact child, then allow
//! execution.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::path::Path;

pub const CUSTODY_SCHEMA: &str = "ck-browser-custody/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyArtifact {
    pub schema: String,
    pub chromium_sha256: String,
    pub chromium_version: String,
    pub platform: String,
    pub ordered_args: Vec<String>,
    pub connector_endpoint_mode: String,
    pub resolver_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CustodyArtifactError {
    InvalidJson,
    TrailingBytes,
    NonCanonical,
    UnknownOrMissingField,
    InvalidField(&'static str),
    DigestMismatch,
    Io,
}

impl CustodyArtifact {
    /// Parse exactly one canonical RFC 8785-shaped JSON artifact.
    pub fn parse(bytes: &[u8]) -> Result<Self, CustodyArtifactError> {
        let value: Value = serde_json::from_slice(bytes).map_err(|error| {
            if error.is_data() {
                CustodyArtifactError::InvalidJson
            } else {
                CustodyArtifactError::TrailingBytes
            }
        })?;
        let canonical = canonical_json_bytes(&value);
        if canonical != bytes {
            return Err(CustodyArtifactError::NonCanonical);
        }
        let artifact: Self = serde_json::from_value(value)
            .map_err(|_| CustodyArtifactError::UnknownOrMissingField)?;
        artifact.validate()?;
        Ok(artifact)
    }

    pub fn parse_pinned(bytes: &[u8], expected_sha256: &str) -> Result<Self, CustodyArtifactError> {
        let artifact = Self::parse(bytes)?;
        if sha256_hex(bytes) != expected_sha256 {
            return Err(CustodyArtifactError::DigestMismatch);
        }
        Ok(artifact)
    }

    pub fn validate(&self) -> Result<(), CustodyArtifactError> {
        if self.schema != CUSTODY_SCHEMA {
            return Err(CustodyArtifactError::InvalidField("schema"));
        }
        if !valid_digest(&self.chromium_sha256) || self.chromium_sha256.chars().all(|c| c == '0') {
            return Err(CustodyArtifactError::InvalidField("chromium_sha256"));
        }
        if self.platform != "macos" {
            return Err(CustodyArtifactError::InvalidField("platform"));
        }
        if self.connector_endpoint_mode != "enforcing_connector_only" {
            return Err(CustodyArtifactError::InvalidField(
                "connector_endpoint_mode",
            ));
        }
        if self.resolver_mode != "connector_owned" {
            return Err(CustodyArtifactError::InvalidField("resolver_mode"));
        }
        let version_bytes = self.chromium_version.as_bytes();
        if !(1..=128).contains(&version_bytes.len())
            || matches!(
                self.chromium_version.to_ascii_lowercase().as_str(),
                "placeholder" | "tbd" | "unknown"
            )
        {
            return Err(CustodyArtifactError::InvalidField("chromium_version"));
        }
        if !(1..=256).contains(&self.ordered_args.len()) {
            return Err(CustodyArtifactError::InvalidField("ordered_args"));
        }
        if self
            .ordered_args
            .iter()
            .any(|arg| !(1..=4096).contains(&arg.len()) || forbidden_argument(arg))
        {
            return Err(CustodyArtifactError::InvalidField("ordered_args"));
        }
        Ok(())
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        canonical_json_bytes(&serde_json::to_value(self).expect("custody artifact serializes"))
    }

    pub fn digest(&self) -> String {
        sha256_hex(&self.canonical_bytes())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationObservation {
    pub executable_sha256: String,
    pub ordered_args: Vec<String>,
    pub connector_endpoint_mode: String,
    pub resolver_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistrationError {
    Artifact(CustodyArtifactError),
    ExecutableMismatch,
    ArgumentsMismatch,
    ConnectorModeMismatch,
    ResolverModeMismatch,
    ProfilePathMismatch,
}

/// Verify the selected executable and the fully expanded argument vector.
fn forbidden_argument(argument: &str) -> bool {
    let lower = argument.to_ascii_lowercase();
    lower == "--no-proxy-server"
        || lower == "--disable-proxy"
        || lower.starts_with("--proxy-bypass-list=") && lower.contains('*')
        || lower.starts_with("--proxy-server=direct://")
        || lower.starts_with("--proxy-pac-url=")
        || lower.starts_with("--remote-debugging-port=")
        || lower.starts_with("--remote-debugging-address=")
        || lower == "--load-extension"
        || lower.starts_with("--load-extension=")
        || lower.starts_with("--disable-extensions-except=")
        || lower.starts_with("--host-resolver-rules=")
        || lower.starts_with("--origin-to-force-quic=")
        || lower == "--enable-quic"
        || lower.starts_with("--enable-quic=")
        || lower == "--use-system-proxy"
        || lower == "--allow-running-insecure-content"
}

/// Return whether a fully expanded argument vector contains a forbidden
/// browser-owned or direct network path.
pub fn arguments_are_quarantinable(arguments: &[String]) -> bool {
    arguments
        .iter()
        .all(|argument| !forbidden_argument(argument))
}

pub fn verify_registration(
    artifact: &CustodyArtifact,
    observation: &RegistrationObservation,
) -> Result<(), RegistrationError> {
    artifact.validate().map_err(RegistrationError::Artifact)?;
    if observation.executable_sha256 != artifact.chromium_sha256 {
        return Err(RegistrationError::ExecutableMismatch);
    }
    if observation.ordered_args != artifact.ordered_args {
        return Err(RegistrationError::ArgumentsMismatch);
    }
    if observation.connector_endpoint_mode != artifact.connector_endpoint_mode {
        return Err(RegistrationError::ConnectorModeMismatch);
    }
    if observation.resolver_mode != artifact.resolver_mode {
        return Err(RegistrationError::ResolverModeMismatch);
    }
    Ok(())
}

/// Registration-time convenience wrapper that hashes the selected executable
/// from disk and compares the final expanded argument vector byte-for-byte.
pub fn verify_registration_path(
    artifact: &CustodyArtifact,
    executable: &Path,
    ordered_args: Vec<String>,
    connector_endpoint_mode: String,
    resolver_mode: String,
) -> Result<(), RegistrationError> {
    let executable_sha256 = sha256_file(executable).map_err(RegistrationError::Artifact)?;
    verify_registration(
        artifact,
        &RegistrationObservation {
            executable_sha256,
            ordered_args,
            connector_endpoint_mode,
            resolver_mode,
        },
    )
}

/// Verify the module-owned profile directory constraint for the common
/// inline Chromium form `--user-data-dir=<path>`.
pub fn verify_registration_in_profile_directory(
    artifact: &CustodyArtifact,
    observation: &RegistrationObservation,
    profile_directory: &Path,
) -> Result<(), RegistrationError> {
    verify_registration(artifact, observation)?;
    for argument in &observation.ordered_args {
        if let Some(value) = argument.strip_prefix("--user-data-dir=") {
            if !Path::new(value).starts_with(profile_directory) {
                return Err(RegistrationError::ProfilePathMismatch);
            }
        }
    }
    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String, CustodyArtifactError> {
    let bytes = std::fs::read(path).map_err(|_| CustodyArtifactError::Io)?;
    Ok(sha256_hex(&bytes))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Serialize JSON with recursively sorted object keys.  All S2 artifacts are
/// string/bool/array objects, so serde_json's shortest number representation is
/// sufficient for the closed artifact vocabulary.
pub fn canonical_json_bytes(value: &Value) -> Vec<u8> {
    fn write(value: &Value, output: &mut String) {
        match value {
            Value::Null => output.push_str("null"),
            Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) => output.push_str(&value.to_string()),
            Value::String(value) => {
                output.push_str(&serde_json::to_string(value).expect("string serializes"))
            }
            Value::Array(values) => {
                output.push('[');
                for (index, value) in values.iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    write(value, output);
                }
                output.push(']');
            }
            Value::Object(values) => {
                let mut keys: Vec<_> = values.keys().collect();
                keys.sort_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
                output.push('{');
                for (index, key) in keys.into_iter().enumerate() {
                    if index != 0 {
                        output.push(',');
                    }
                    output.push_str(&serde_json::to_string(key).expect("key serializes"));
                    output.push(':');
                    write(&values[key], output);
                }
                output.push('}');
            }
        }
    }
    let mut output = String::new();
    write(value, &mut output);
    output.into_bytes()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuarantineMechanism {
    Suspended,
    ProcessBound,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpawnObservation {
    pub process_id: u64,
    pub quarantine: Option<QuarantineMechanism>,
    pub executable_sha256: String,
    pub ordered_args: Vec<String>,
    pub connector_endpoint_mode: String,
    pub resolver_mode: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LaunchError {
    QuarantineNotEstablished,
    ProcessIdentityMismatch,
    InspectionUnavailable,
    ExecutableMismatch,
    ArgumentsMismatch,
    ConnectorModeMismatch,
    ResolverModeMismatch,
    ProofNotCurrent,
    MissingCommitment,
    ChildAlreadyReleased,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectorAdmissionProof {
    process_id: u64,
    custody_digest: String,
    generation: u64,
    nonce: u64,
}

impl ConnectorAdmissionProof {
    pub fn process_id(&self) -> u64 {
        self.process_id
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn custody_digest(&self) -> &str {
        &self.custody_digest
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchStage {
    Closed,
    Accepted,
    Released,
    Terminated,
}

/// A process-bound, restart-aware custody gate.  A proof from one generation
/// cannot authorize a replacement process in a later generation.
#[derive(Debug, Clone)]
pub struct LaunchQuarantine {
    artifact_digest: String,
    generation: u64,
    stage: LaunchStage,
    process_id: Option<u64>,
    commitment_sequence: Option<u64>,
    next_nonce: u64,
}

impl LaunchQuarantine {
    pub fn new(artifact: &CustodyArtifact) -> Self {
        Self {
            artifact_digest: artifact.digest(),
            generation: 1,
            stage: LaunchStage::Closed,
            process_id: None,
            commitment_sequence: None,
            next_nonce: 1,
        }
    }

    pub fn stage(&self) -> LaunchStage {
        self.stage
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Record the matching durable dispatch commitment.  A zero sequence is
    /// rejected because it cannot identify a journal commitment.
    pub fn commit_for_launch(&mut self, sequence: u64) -> Result<(), LaunchError> {
        if sequence == 0 || self.stage != LaunchStage::Closed || self.commitment_sequence.is_some()
        {
            return Err(LaunchError::MissingCommitment);
        }
        self.commitment_sequence = Some(sequence);
        Ok(())
    }

    pub fn verify_and_admit(
        &mut self,
        artifact: &CustodyArtifact,
        expected_process_id: u64,
        observation: &SpawnObservation,
    ) -> Result<ConnectorAdmissionProof, LaunchError> {
        if self.stage != LaunchStage::Closed {
            return Err(LaunchError::ChildAlreadyReleased);
        }
        if self.commitment_sequence.is_none() {
            return Err(LaunchError::MissingCommitment);
        }
        if artifact.digest() != self.artifact_digest {
            return Err(LaunchError::ExecutableMismatch);
        }
        let mechanism = observation
            .quarantine
            .ok_or(LaunchError::QuarantineNotEstablished)?;
        if !matches!(
            mechanism,
            QuarantineMechanism::Suspended | QuarantineMechanism::ProcessBound
        ) {
            return Err(LaunchError::QuarantineNotEstablished);
        }
        if observation.process_id != expected_process_id {
            return Err(LaunchError::ProcessIdentityMismatch);
        }
        let registration = RegistrationObservation {
            executable_sha256: observation.executable_sha256.clone(),
            ordered_args: observation.ordered_args.clone(),
            connector_endpoint_mode: observation.connector_endpoint_mode.clone(),
            resolver_mode: observation.resolver_mode.clone(),
        };
        verify_registration(artifact, &registration).map_err(|error| match error {
            RegistrationError::ExecutableMismatch => LaunchError::ExecutableMismatch,
            RegistrationError::ArgumentsMismatch => LaunchError::ArgumentsMismatch,
            RegistrationError::ConnectorModeMismatch => LaunchError::ConnectorModeMismatch,
            RegistrationError::ResolverModeMismatch => LaunchError::ResolverModeMismatch,
            RegistrationError::ProfilePathMismatch => LaunchError::InspectionUnavailable,
            RegistrationError::Artifact(_) => LaunchError::InspectionUnavailable,
        })?;
        self.process_id = Some(observation.process_id);
        self.stage = LaunchStage::Accepted;
        let proof = ConnectorAdmissionProof {
            process_id: observation.process_id,
            custody_digest: self.artifact_digest.clone(),
            generation: self.generation,
            nonce: self.next_nonce,
        };
        self.next_nonce = self.next_nonce.saturating_add(1);
        Ok(proof)
    }

    pub fn release(&mut self, proof: &ConnectorAdmissionProof) -> Result<(), LaunchError> {
        if self.stage != LaunchStage::Accepted || !self.proof_matches(proof) {
            return Err(LaunchError::ProofNotCurrent);
        }
        self.stage = LaunchStage::Released;
        Ok(())
    }

    pub fn proof_is_current(&self, proof: &ConnectorAdmissionProof, process_id: u64) -> bool {
        self.stage == LaunchStage::Released
            && proof.process_id == process_id
            && self.proof_matches(proof)
    }

    pub fn terminate(&mut self) {
        self.stage = LaunchStage::Terminated;
        self.process_id = None;
    }

    pub fn restart(&mut self) {
        self.generation = self.generation.saturating_add(1);
        self.stage = LaunchStage::Closed;
        self.process_id = None;
        self.commitment_sequence = None;
    }

    fn proof_matches(&self, proof: &ConnectorAdmissionProof) -> bool {
        Some(proof.process_id) == self.process_id
            && proof.custody_digest == self.artifact_digest
            && proof.generation == self.generation
    }
}
