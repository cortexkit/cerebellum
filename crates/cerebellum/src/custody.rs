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
///
/// THE PROXY REFUSALS BELOW GUARD A PROXY THIS MODULE DOES NOT YET CONFIGURE,
/// and they are listed here first because the list otherwise reads as evidence
/// that browser traffic is routed through one. `browser_launch_service` builds
/// its argument vector from `--remote-debugging-pipe`, `--user-data-dir`,
/// `--crash-dumps-dir`, `--no-first-run`, `--no-default-browser-check` and
/// `--no-startup-window`. It passes no
/// `--proxy-server`, so a launched browser reaches the network directly, and
/// refusing the arguments that would DISABLE a proxy forbids turning off
/// something nobody turned on.
///
/// WHAT DOES CONSTRAIN BROWSER EGRESS TODAY, so the true model arrives with the
/// correction: a navigation must use http or https, and its origin must be
/// covered by an action grant. Grants are minted only from an answered consent
/// question (`browser.open_grant` -> a question relayed to a person -> their
/// answer), never from configuration or from the caller's own request, so an
/// origin nobody approved cannot be navigated to. That leaves what a LOADED
/// PAGE's own scripts reach unconstrained by this module, which is the layer a
/// proxy would add.
///
/// `src/network/` holds the policy half of that intended proxy -- address
/// classification and admission accounting -- with no listener and no caller
/// outside its own directory. It is a model of an egress gate rather than one
/// that runs.
///
/// The refusals stay rather than being deleted, and the reason is the failure
/// mode of deleting them: whoever builds the proxy would have to REMEMBER to
/// restore them, and a proxy whose bypass arguments are admitted is worse than
/// no proxy, because it certifies a containment that one launch argument
/// defeats. Kept, they become load-bearing the moment a proxy exists.
/// `custody_tests::the_launch_vector_configures_no_proxy` fails at that moment
/// and names this pairing.
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

/// Admit a `browser.capture_login` launch vector only when it names exactly
/// one profile directory, and that directory is exactly
/// `<capture root>/<the fresh directory this capture created>`.
///
/// Every other launch takes its profile directory from the profile registry
/// and never reaches this check. A capture profile is deliberately NOT a
/// registry profile (the registry root is backed up; the capture root is not),
/// so this is the one place a launch may name a directory the registry did not
/// mint, and it is kept exact: no other directory under the root, no sibling
/// of the root, no `..` or `.` segments, and no second `--user-data-dir`.
/// Callers pass the root only after it was created and proven excluded from
/// backups.
pub fn capture_user_data_dir_admitted(
    arguments: &[String],
    capture_root: &Path,
    fresh_directory: &Path,
) -> bool {
    use std::path::Component;

    let plain = |path: &Path| {
        path.is_absolute()
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    };
    if !plain(capture_root) || !plain(fresh_directory) {
        return false;
    }
    let Ok(below_root) = fresh_directory.strip_prefix(capture_root) else {
        return false;
    };
    let mut below = below_root.components();
    if !matches!(
        (below.next(), below.next()),
        (Some(Component::Normal(_)), None)
    ) {
        return false;
    }
    if arguments
        .iter()
        .any(|argument| argument == "--user-data-dir")
    {
        return false;
    }
    let mut named = arguments
        .iter()
        .filter_map(|argument| argument.strip_prefix("--user-data-dir="));
    match (named.next(), named.next()) {
        (Some(value), None) => {
            // Compared as text as well as by components: `Path` equality
            // forgives a trailing slash or a doubled separator, and the
            // browser should be handed exactly the directory that was made.
            let value_path = Path::new(value);
            plain(value_path)
                && value_path == fresh_directory
                && value == fresh_directory.to_string_lossy()
        }
        _ => false,
    }
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
///
/// KEYS ARE ORDERED BY UTF-8 BYTES, WHICH IS NOT RFC 8785. That standard orders
/// by UTF-16 code units, and the two disagree for characters outside the basic
/// multilingual plane -- an emoji sorts after U+FFFD by bytes and before it by
/// code units. `classification.rs` and the computer plane's vocabulary artifact
/// implement the RFC 8785 order instead, so a value containing such a key would
/// digest differently here than there.
///
/// This is safe for the artifacts digested through this function, whose keys are
/// fixed ASCII identifiers declared in the schemas, and it is NOT safe for input
/// whose keys come from a page or any other untrusted source. Changing the order
/// invalidates every digest already computed with it, so a caller needing RFC
/// 8785 should use the implementation that provides it rather than converting
/// this one.
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

#[cfg(test)]
mod tests {
    use super::*;

    /// This crate canonicalizes JSON two different ways on purpose, and the
    /// difference is pinned here so that neither can be quietly changed into
    /// the other.
    ///
    /// Object keys are ordered by UTF-8 bytes for custody and address-policy
    /// artifacts, and by UTF-16 code units -- the RFC 8785 rule -- for
    /// classification records. The orders agree for ASCII and disagree above
    /// the basic multilingual plane, so a value carrying such a key digests
    /// differently under each. Both are correct for their own inputs, and
    /// changing either invalidates every digest already computed with it.
    ///
    /// The divergence is asserted rather than each order separately, because a
    /// reader who finds two functions named for the same job will otherwise
    /// read the difference as an inconsistency to tidy up.
    #[test]
    fn the_two_canonical_key_orders_are_deliberately_different() {
        // An emoji sorts after U+FFFD by UTF-8 bytes and before it by UTF-16
        // code units, so it separates the two orders in one value.
        let emoji = '\u{1F600}';
        let replacement = '\u{FFFD}';
        let value = serde_json::json!({ emoji.to_string(): 1, replacement.to_string(): 2 });

        let by_bytes = String::from_utf8(canonical_json_bytes(&value)).expect("utf8");
        let by_code_units =
            String::from_utf8(crate::classification::canonical_json_bytes(&value)).expect("utf8");

        assert!(
            by_bytes.find(replacement) < by_bytes.find(emoji),
            "custody orders object keys by UTF-8 bytes: {by_bytes}"
        );
        assert!(
            by_code_units.find(emoji) < by_code_units.find(replacement),
            "classification orders object keys by UTF-16 code units: {by_code_units}"
        );
        assert_ne!(
            by_bytes, by_code_units,
            "the two canonical forms must remain distinguishable"
        );

        // ASCII keys are why the difference is currently harmless: every
        // digested artifact declares fixed ASCII identifiers, and the two
        // orders agree there.
        let ascii = serde_json::json!({ "b": 1, "a": 2 });
        assert_eq!(
            canonical_json_bytes(&ascii),
            crate::classification::canonical_json_bytes(&ascii)
        );
    }
}

#[cfg(test)]
mod proxy_pairing_tests {
    /// A tripwire for the day someone configures a proxy or wires the connector.
    ///
    /// The refusals in `forbidden_argument` reject arguments that would DISABLE a
    /// proxy, and this module configures none, so today they forbid turning off
    /// something nobody turned on. That is a deliberate deferral rather than an
    /// oversight -- but a deferral recorded only in prose is one a future reader
    /// has to happen to read, and this particular gap is DISGUISED: a refusal
    /// list naming proxy arguments reads as evidence that egress is proxied.
    ///
    /// So the deferral is asserted instead. This test passes trivially now and
    /// FAILS the moment either half is built, naming what must be checked at
    /// exactly the point it stops being true.
    ///
    /// It asserts over SOURCE rather than behaviour deliberately: the property is
    /// "these two subsystems are not yet paired", which no runtime state exposes.
    #[test]
    fn the_launch_vector_configures_no_proxy() {
        let launch_service = include_str!("browser_launch_service.rs");
        // The vector is built from OsString literals, so the flag would appear
        // verbatim. Matching the flag rather than a value catches every form:
        // --proxy-server=..., --proxy-pac-url=..., --proxy-bypass-list=...
        let configures_proxy = launch_service
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .any(|line| line.contains("--proxy"));
        assert!(
            !configures_proxy,
            "the launch vector now configures a proxy: the bypass refusals in \
             forbidden_argument have become load-bearing. Verify the pairing -- \
             every argument that could disable or bypass the proxy must be \
             refused, and the address policy in src/network/ must be the thing \
             deciding admission rather than a model beside it. See the comment \
             on forbidden_argument."
        );

        // The companion half. A proxy could equally arrive by wiring the
        // connector to a listener rather than by adding a launch argument, and
        // that path would leave the assertion above green.
        let module = include_str!("network/mod.rs");
        let connector = include_str!("network/connector.rs");
        let has_listener = [module, connector]
            .iter()
            .any(|source| source.contains("TcpListener") || source.contains("UnixListener"));
        assert!(
            !has_listener,
            "src/network/ now binds a listener: the connector is becoming a real \
             egress gate rather than a policy model. The launch vector must point \
             the browser at it, or a browser that reaches the network directly \
             will run beside a gate that believes it is enforcing."
        );
    }
}

#[cfg(test)]
mod capture_user_data_dir_tests {
    use super::capture_user_data_dir_admitted;
    use std::path::Path;

    const ROOT: &str = "/private/var/folders/ab/T/ck-cerebellum-capture";
    const FRESH: &str = "/private/var/folders/ab/T/ck-cerebellum-capture/profile-1";

    fn arguments(user_data_dir: &str) -> Vec<String> {
        vec![
            "--remote-debugging-pipe".to_string(),
            format!("--user-data-dir={user_data_dir}"),
            format!("--crash-dumps-dir={FRESH}/crash-dumps"),
            "--no-first-run".to_string(),
        ]
    }

    fn admitted(arguments: &[String]) -> bool {
        capture_user_data_dir_admitted(arguments, Path::new(ROOT), Path::new(FRESH))
    }

    #[test]
    fn exactly_the_fresh_directory_is_admitted() {
        assert!(admitted(&arguments(FRESH)));
    }

    #[test]
    fn anything_else_is_refused() {
        for user_data_dir in [
            // A sibling of the fresh directory under the same root.
            "/private/var/folders/ab/T/ck-cerebellum-capture/profile-2",
            // The root itself.
            ROOT,
            // A sibling of the root that shares its name as a prefix.
            "/private/var/folders/ab/T/ck-cerebellum-capture-evil/profile-1",
            // Climbing out and back in.
            "/private/var/folders/ab/T/ck-cerebellum-capture/profile-1/../profile-1",
            "/private/var/folders/ab/T/ck-cerebellum-capture/../ck-cerebellum-capture/profile-1",
            // A current-directory segment and a trailing slash.
            "/private/var/folders/ab/T/ck-cerebellum-capture/./profile-1",
            "/private/var/folders/ab/T/ck-cerebellum-capture/profile-1/",
            // Below the fresh directory, and a relative path.
            "/private/var/folders/ab/T/ck-cerebellum-capture/profile-1/Default",
            "ck-cerebellum-capture/profile-1",
            // The managed registry root.
            "/Users/someone/.local/share/cortexkit/cerebellum/profiles/p",
        ] {
            assert!(!admitted(&arguments(user_data_dir)), "{user_data_dir}");
        }
    }

    #[test]
    fn a_second_or_missing_profile_argument_is_refused() {
        let mut twice = arguments(FRESH);
        twice.push(format!("--user-data-dir={FRESH}"));
        assert!(!admitted(&twice));
        let mut split = arguments(FRESH);
        split.push("--user-data-dir".to_string());
        assert!(!admitted(&split));
        let none = vec!["--remote-debugging-pipe".to_string()];
        assert!(!admitted(&none));
    }

    #[test]
    fn a_fresh_directory_not_directly_under_the_root_is_refused() {
        for fresh in [
            "/private/var/folders/ab/T/ck-cerebellum-capture/a/b",
            "/private/var/folders/ab/T/elsewhere/profile-1",
            "/private/var/folders/ab/T/ck-cerebellum-capture/../profile-1",
        ] {
            assert!(
                !capture_user_data_dir_admitted(
                    &arguments(fresh),
                    Path::new(ROOT),
                    Path::new(fresh)
                ),
                "{fresh}"
            );
        }
    }
}
