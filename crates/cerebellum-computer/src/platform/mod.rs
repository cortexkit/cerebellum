//! Bounded, OS-neutral computer-plane platform seam.
//!
//! This slice deliberately contains no window-server or accessibility bindings.
//! The macOS implementation is an injectable skeleton: it can prove whether a
//! capability is safe to advertise, while later slices provide the operations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub mod macos;

pub use macos::{
    MacOs26PlatformDriver, PrivateEnvelopeStartupProbe, StartupCapabilityProbe, StartupProbeInput,
    MACOS_MAJOR_VERSION,
};

pub mod vocabulary;
pub use vocabulary::{
    canonical_json_bytes, computed_vocabulary_sha256, implementation_source_lock_digest,
    validate_vocabulary, validate_vocabulary_digests, VocabularyDigestInputs,
    VocabularyValidationError, COMPUTER_ACTION_VOCABULARY_REVISION,
    COMPUTER_ACTION_VOCABULARY_SCHEMA_ID, COMPUTER_ACTION_VOCABULARY_SHA256,
};

/// The only capability support states permitted by the platform contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SupportState {
    Supported,
    Unsupported,
    ConsentGated,
}

/// Session-level synthetic dispatch modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DispatchMode {
    Background,
    Observed,
}

/// Closed action-kind taxonomy owned by the vocabulary artifact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Compose,
    MutateDurable,
    Observe,
}

/// Closed retry policy used by the vocabulary rows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    Idempotent,
    Deduplicated,
    ReconcileBeforeRetry,
    NeverAutomaticRetry,
}

/// Permission services are deliberately separate: one grant never substitutes
/// for another service's liveness proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionService {
    ScreenRecording,
    Accessibility,
    PostEvent,
    InputMonitoring,
    RawHidObservation,
}

/// Result of an off-main permission liveness probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PermissionLiveness {
    Live,
    Unavailable,
    GrantedPendingRelaunch,
    Unresolved,
}

/// A probe result includes the responsible process so settings-only reads cannot
/// be mistaken for proof about a different signed process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionProbeResult {
    pub service: PermissionService,
    pub liveness: PermissionLiveness,
    pub responsible_process: String,
    pub off_main: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PermissionLivenessReport {
    states: BTreeMap<PermissionService, PermissionLiveness>,
}

impl PermissionLivenessReport {
    pub fn from_results(results: impl IntoIterator<Item = PermissionProbeResult>) -> Self {
        Self {
            states: results
                .into_iter()
                .map(|result| (result.service, result.liveness))
                .collect(),
        }
    }

    pub fn state(&self, service: PermissionService) -> PermissionLiveness {
        self.states
            .get(&service)
            .copied()
            .unwrap_or(PermissionLiveness::Unresolved)
    }

    pub fn all_live(&self, services: &[PermissionService]) -> bool {
        services
            .iter()
            .all(|service| self.state(*service) == PermissionLiveness::Live)
    }
}

/// Immutable release inputs are optional until release binding. No field has an
/// implementation default: an absent value suppresses only rows that consume it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImmutableReleaseInputs {
    pub computer_action_vocabulary_revision: Option<String>,
    pub permission_matrix_revision: Option<String>,
    pub process_identity_primitive_revision: Option<String>,
    pub capture_residual_leakage_revision: Option<String>,
    pub attendance_contract_owner: Option<String>,
    pub attendance_contract_schema_id: Option<String>,
    pub attendance_contract_revision: Option<String>,
    pub input_review_revision: Option<String>,
    pub capture_review_revision: Option<String>,
    pub release_signing_topology_revision: Option<String>,
    pub cerebellum_core_contract_revision: Option<String>,
    pub c2_journal_pin_schema_id: Option<String>,
    pub c2_journal_pin_revision: Option<String>,
    pub vocabulary_digests: VocabularyDigestInputs,
}

impl ImmutableReleaseInputs {
    fn vocabulary_ready(&self) -> bool {
        self.computer_action_vocabulary_revision.as_deref()
            == Some(COMPUTER_ACTION_VOCABULARY_REVISION)
            && validate_vocabulary_digests(&self.vocabulary_digests).is_ok()
    }

    fn input_dispatch_ready(&self) -> bool {
        self.permission_matrix_revision.is_some()
            && self.process_identity_primitive_revision.is_some()
            && self.attendance_contract_owner.is_some()
            && self.attendance_contract_schema_id.is_some()
            && self.attendance_contract_revision.is_some()
            && self.input_review_revision.is_some()
            && self.release_signing_topology_revision.is_some()
            && self.cerebellum_core_contract_revision.is_some()
            && self.c2_journal_pin_schema_id.is_some()
            && self.c2_journal_pin_revision.is_some()
    }

    fn capture_ready(&self) -> bool {
        self.permission_matrix_revision.is_some()
            && self.capture_residual_leakage_revision.is_some()
            && self.capture_review_revision.is_some()
            && self.release_signing_topology_revision.is_some()
    }
}

/// A manifest-visible capability declaration. It contains no executor and
/// therefore cannot cause an input event by being inspected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityDeclaration {
    pub capability_id: String,
    pub action_kind: ActionKind,
    pub dispatch_modes: Vec<DispatchMode>,
    pub semantic_path: SupportState,
    pub synthetic_background: SupportState,
    pub synthetic_observed: SupportState,
    pub required_permissions: Vec<PermissionService>,
    pub retry_class: RetryClass,
    pub advertised: bool,
    pub suppression_reason: Option<String>,
}

/// Inputs needed to build declarations from the frozen artifact and startup
/// probes. The declaration builder never turns an unresolved field into a guess.
#[derive(Debug, Clone)]
pub struct CapabilityAdvertisementContext {
    pub inputs: ImmutableReleaseInputs,
    pub permissions: PermissionLivenessReport,
    pub startup: StartupCapabilityProbe,
}

/// A stable process identity tuple. The raw pid is intentionally not sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessGrant {
    pub pid: u32,
    pub bundle_identity: String,
    pub process_generation_evidence: String,
}

impl ProcessGrant {
    pub fn validate(&self) -> Result<(), DriverError> {
        if self.pid == 0
            || self.bundle_identity.is_empty()
            || self.process_generation_evidence.is_empty()
        {
            return Err(DriverError::InvalidRequest(
                "complete process grant required",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityTreeRequest {
    pub target: ProcessGrant,
    pub settle_interval_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityTreeResult {
    pub root_identifier: Option<String>,
    pub child_count: u32,
    pub handshake_attempted: bool,
    pub degenerate_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementResolutionRequest {
    pub root_identifier: String,
    pub element_identifier: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementResolutionResult {
    pub element_identifier: String,
    pub owning_process: ProcessGrant,
    pub semantic_actions: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDispatchRequest {
    pub element: ElementResolutionResult,
    pub action: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyntheticDispatchRequest {
    pub target: ProcessGrant,
    pub event_count: u8,
    pub coordinate_addressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchResult {
    pub accepted_by_platform: bool,
    pub effect_status: EffectStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedWindowEnumerationRequest {
    pub target: ProcessGrant,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedWindowCaptureRequest {
    pub target: ProcessGrant,
    pub window_ids: Vec<String>,
    pub include_cursor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedCaptureResult {
    pub generation: u64,
    pub window_count: u32,
    pub cursor_composited: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FocusQueryRequest {
    pub target: ProcessGrant,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FocusQueryResult {
    pub matches_target: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontingSnapshot {
    pub captured_at_ms: u64,
    pub frontmost_application_identity: Option<String>,
    pub target_windows: Vec<FrontingWindow>,
    pub completeness: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrontingWindow {
    pub observation_window_id: String,
    pub owning_process_generation: String,
    pub activation_state: String,
    pub z_order: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrontingComparison {
    Unchanged,
    DowngradeDetected,
    Indeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputObserverLiveness {
    pub session_tap_live: bool,
    pub raw_hid_live: bool,
    pub self_echo_filter_live: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputObservationRequest {
    pub maximum_latency_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InputObservationResult {
    pub human_or_ambiguous_input: bool,
    pub detection_latency_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectObservationRequest {
    pub predicate: String,
    pub deadline_ms: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectStatus {
    EffectObserved,
    NoEffectObserved,
    EffectIndeterminate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectObservationResult {
    pub status: EffectStatus,
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendancePreconditionRequest {
    pub conversation_id: String,
    pub target: ProcessGrant,
    pub maximum_lease_age_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttendancePreconditionResult {
    pub valid: bool,
    pub lease_generation: Option<String>,
    pub age_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    Unsupported(&'static str),
    InvalidRequest(&'static str),
    StartupRefused(&'static str),
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(op) => write!(f, "unsupported platform operation: {op}"),
            Self::InvalidRequest(reason) => write!(f, "invalid platform request: {reason}"),
            Self::StartupRefused(reason) => write!(f, "platform startup refused: {reason}"),
        }
    }
}
impl std::error::Error for DriverError {}

/// The complete bounded surface shared by future Windows, X11, and Wayland
/// backends. Implementations may refuse an operation, but may not broaden it.
pub trait PlatformDriver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration>;
    fn read_accessibility_tree(
        &mut self,
        request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError>;
    fn resolve_element(
        &mut self,
        request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError>;
    fn dispatch_semantic(
        &mut self,
        request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError>;
    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
    ) -> Result<DispatchResult, DriverError>;
    fn dispatch_global(
        &mut self,
        request: SyntheticDispatchRequest,
    ) -> Result<DispatchResult, DriverError>;
    fn enumerate_scoped_windows(
        &mut self,
        request: ScopedWindowEnumerationRequest,
    ) -> Result<Vec<String>, DriverError>;
    fn capture_scoped_windows(
        &mut self,
        request: ScopedWindowCaptureRequest,
    ) -> Result<ScopedCaptureResult, DriverError>;
    fn query_focus(&mut self, request: FocusQueryRequest) -> Result<FocusQueryResult, DriverError>;
    fn fronting_snapshot(&mut self, target: &ProcessGrant)
        -> Result<FrontingSnapshot, DriverError>;
    fn input_observer_liveness(&self) -> InputObserverLiveness;
    fn observe_input(
        &mut self,
        request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError>;
    fn observe_effect(
        &mut self,
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError>;
    fn verify_attendance(
        &mut self,
        request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError>;

    fn bounded_duration(milliseconds: u64) -> Result<Duration, DriverError> {
        if milliseconds > 300_000 {
            return Err(DriverError::InvalidRequest(
                "duration exceeds vocabulary bound",
            ));
        }
        Ok(Duration::from_millis(milliseconds))
    }
}

/// Names used by plane-boundary tell-tests. Keep this list in sync when adding
/// another type whose name would couple the core substrate to this plane.
pub const COMPUTER_PLANE_TYPE_IDENTIFIERS: &[&str] = &[
    "PlatformDriver",
    "MacOs26PlatformDriver",
    "ComputerActionVocabulary",
    "CapabilityDeclaration",
    "PermissionLivenessProbe",
    "PrivateEnvelopeStartupProbe",
    "StartupCapabilityProbe",
    "FrontingSnapshot",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_duration_rejects_values_above_five_minutes() {
        assert!(<MacOs26PlatformDriver as PlatformDriver>::bounded_duration(300_001).is_err());
        assert_eq!(
            <MacOs26PlatformDriver as PlatformDriver>::bounded_duration(300_000).unwrap(),
            Duration::from_millis(300_000)
        );
    }
}
