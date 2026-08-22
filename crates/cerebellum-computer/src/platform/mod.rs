//! Bounded, OS-neutral computer-plane platform seam.
//!
//! This slice deliberately contains no window-server or accessibility bindings.
//! The macOS implementation is an injectable skeleton: it can prove whether a
//! capability is safe to advertise, while later slices provide the operations.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub mod containment;
pub mod process_event;
pub mod severity;
pub use containment::*;
pub use process_event::*;
#[cfg(target_os = "macos")]
pub mod macos;

/// Converts raw operating-system permission readings into the
/// [`PermissionProbeResult`] values the startup probe consumes.
///
/// Compiled only on platforms that provide those readings; everything else in
/// this module is platform-neutral and built on every host.
#[cfg(target_os = "macos")]
pub mod native;

#[cfg(target_os = "macos")]
pub use macos::{
    MacOs26PlatformDriver, PrivateEnvelopeStartupProbe, StartupProbeInput, MACOS_MAJOR_VERSION,
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

/// Filters permission readings to the process responsible for the current module.
///
/// A reading attributed to another process cannot establish this module's grant,
/// even when the operating system reports that the other process is permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionLivenessProbe {
    pub responsible_process: String,
}

impl PermissionLivenessProbe {
    pub fn run(&self, results: &[PermissionProbeResult]) -> PermissionLivenessReport {
        PermissionLivenessReport::from_results(
            results
                .iter()
                .filter(|result| {
                    result.responsible_process == self.responsible_process && result.off_main
                })
                .cloned(),
        )
    }
}

/// Keeps only permission readings that can be credited to the identified process.
///
/// Without an identified responsible process, no reading is sufficient evidence
/// to advertise a capability, so the report remains unresolved for every service.
pub fn attributed_permission_liveness(
    responsible_process: Option<&str>,
    results: &[PermissionProbeResult],
) -> PermissionLivenessReport {
    responsible_process.map_or_else(PermissionLivenessReport::default, |process| {
        PermissionLivenessProbe {
            responsible_process: process.to_string(),
        }
        .run(results)
    })
}

/// Startup results that capability advertisement consumes on every platform.
///
/// Platform-specific probes populate this report; hosts without a supported
/// probe retain the default, which advertises no private envelope or grants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StartupCapabilityProbe {
    pub os_major: u16,
    pub private_envelope_recognized: bool,
    pub permissions: PermissionLivenessReport,
}

/// Immutable release inputs are optional until release binding. External values
/// attest to work performed outside this repository, so an absent value suppresses
/// only rows that consume it. The vocabulary digests are mirrors of checked-in
/// artifacts and are bound by the module from their independent local sources.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImmutableReleaseInputs {
    pub attendance_contract_owner: Option<String>,
    pub attendance_contract_revision: Option<String>,
    pub input_review_revision: Option<String>,
    pub capture_review_revision: Option<String>,
    pub semantic_actuation_review_revision: Option<String>,
    pub release_signing_topology_revision: Option<String>,
    pub vocabulary_digests: VocabularyDigestInputs,
}

impl ImmutableReleaseInputs {
    fn vocabulary_ready(&self) -> bool {
        validate_vocabulary_digests(&self.vocabulary_digests).is_ok()
    }

    fn input_dispatch_ready(&self) -> bool {
        self.attendance_contract_owner.is_some()
            && self.attendance_contract_revision.is_some()
            && self.input_review_revision.is_some()
            && self.release_signing_topology_revision.is_some()
    }

    fn capture_ready(&self) -> bool {
        self.capture_review_revision.is_some() && self.release_signing_topology_revision.is_some()
    }

    fn semantic_actuation_ready(&self) -> bool {
        self.semantic_actuation_review_revision.is_some()
            && self.release_signing_topology_revision.is_some()
    }
}

/// Builds the fixed declaration set from release inputs and startup evidence.
///
/// `platform_available` distinguishes a host that can serve the platform driver
/// from one that can only report the frozen vocabulary. The latter keeps all
/// rows visible for release evidence and may still advertise `computer.wait`,
/// because waiting has no platform operation to perform.
pub fn capability_declarations(
    context: &CapabilityAdvertisementContext,
    private_envelope_recognized: bool,
    platform_available: bool,
) -> Vec<CapabilityDeclaration> {
    [
        "computer.click",
        "computer.type",
        "computer.keys",
        "computer.scroll",
        "computer.move",
        "computer.drag",
        "computer.screenshot",
        "computer.wait",
    ]
    .into_iter()
    .map(|id| capability_declaration(id, context, private_envelope_recognized, platform_available))
    .collect()
}

fn capability_declaration(
    id: &str,
    context: &CapabilityAdvertisementContext,
    private_envelope_recognized: bool,
    platform_available: bool,
) -> CapabilityDeclaration {
    let action_kind = if id == "computer.drag" {
        ActionKind::MutateDurable
    } else if id == "computer.screenshot" || id == "computer.wait" {
        ActionKind::Observe
    } else {
        ActionKind::Compose
    };
    let retry_class = match id {
        "computer.scroll" => RetryClass::ReconcileBeforeRetry,
        "computer.move" | "computer.screenshot" | "computer.wait" => RetryClass::Idempotent,
        _ => RetryClass::NeverAutomaticRetry,
    };
    // Use the shared capability-vocabulary lookup instead of duplicating its
    // permission table. A second hand-written table could drift from the
    // vocabulary and produce incorrect declarations. If the lookup cannot
    // resolve an action or service, suppress that capability rather than using
    // a default or stopping the module.
    let (permissions, permission_lookup_failure) =
        match vocabulary::required_permission_services(id) {
            Ok(permissions) => (permissions, None),
            Err(error) => (
                Vec::new(),
                Some(format!("required permissions are not resolvable: {error}")),
            ),
        };
    let mut advertised = false;
    // A suppression reason is an operator-facing diagnosis, so it must
    // identify the missing layer. The application can already request a
    // closed-vocabulary AxAction, but no handler serves those requests over the
    // wire. Advertising this capability also requires the serving path to be
    // explicitly approved and enabled; the platform layer itself is present.
    let mut suppression_reason = permission_lookup_failure.clone().or_else(|| {
        Some(
            "no wire serving handler: the semantic mechanism is built, and serving it \
             awaits review and activation"
                .to_string(),
        )
    });
    if permission_lookup_failure.is_some() {
        // Keep the permission-lookup failure reason unchanged. It identifies
        // an inability to resolve required permissions, which is more useful
        // to the caller than a release-input status.
    } else if id == "computer.wait" {
        advertised = context.inputs.vocabulary_ready();
        suppression_reason =
            (!advertised).then(|| "computer action vocabulary input unresolved".to_string());
    } else if id == "computer.click" {
        suppression_reason = if !context.inputs.vocabulary_ready() {
            Some("computer action vocabulary input unresolved".to_string())
        } else if !context.inputs.semantic_actuation_ready() {
            if context.inputs.semantic_actuation_review_revision.is_none() {
                Some("semantic actuation review revision is not bound".to_string())
            } else {
                Some("release signing topology revision is not bound".to_string())
            }
        } else {
            None
        };
        advertised = suppression_reason.is_none();
    } else if id == "computer.screenshot" {
        // Named separately rather than as one combined reason. The
        // conditions fail for unrelated causes -- a missing release input is
        // a build-time omission, an unresolved permission is a property of
        // the machine -- and a reader given one message for both has to
        // rule out the other by hand.
        let liveness = context
            .startup
            .permissions
            .state(PermissionService::ScreenRecording);
        suppression_reason = if !context.inputs.vocabulary_ready() {
            Some("computer action vocabulary input unresolved".to_string())
        } else if !context.inputs.capture_ready() {
            Some("capture release input unresolved".to_string())
        } else {
            // Matching on the state rather than testing it against Live
            // keeps the accepting case an ordinary arm. A branch that can
            // "never" be reached is a crash waiting for the day the
            // surrounding condition changes.
            match liveness {
                PermissionLiveness::Live => None,
                PermissionLiveness::Unavailable => {
                    Some("screen recording permission is not granted".to_string())
                }
                PermissionLiveness::GrantedPendingRelaunch => Some(
                    "screen recording permission is granted but not usable until this \
                     process restarts"
                        .to_string(),
                ),
                // Nothing denied the permission; no usable reading was
                // recorded for it. A reading is discarded when it comes from
                // the process main thread, or when the system attributes the
                // grant to a process other than the one expected here.
                PermissionLiveness::Unresolved => {
                    Some("screen recording permission is not established".to_string())
                }
            }
        };
        advertised = suppression_reason.is_none();
    }
    // Evaluate the synthetic-input gate for reporting and review, but do not
    // let it advertise any capability here. Semantic actuation is governed
    // separately, so the five remaining actuating rows retain the unconditional
    // suppression set above.
    let _synthetic_inputs_resolved = context.inputs.input_dispatch_ready();
    CapabilityDeclaration {
        capability_id: id.to_string(),
        action_kind,
        dispatch_modes: if id == "computer.move" {
            vec![DispatchMode::Observed]
        } else if id == "computer.screenshot" || id == "computer.wait" {
            vec![]
        } else {
            vec![DispatchMode::Background, DispatchMode::Observed]
        },
        semantic_path: if matches!(id, "computer.click" | "computer.type" | "computer.scroll") {
            SupportState::Supported
        } else {
            SupportState::Unsupported
        },
        synthetic_background: if private_envelope_recognized {
            SupportState::Supported
        } else {
            SupportState::Unsupported
        },
        synthetic_observed: SupportState::ConsentGated,
        required_permissions: permissions,
        retry_class,
        // A capability whose permission requirements could not be read is
        // never advertised, whatever the rest of the gate concluded: a
        // permission that is not known cannot be checked, and offering the
        // capability would promise a check nobody performs.
        advertised: (platform_available || id == "computer.wait")
            && advertised
            && permission_lookup_failure.is_none(),
        suppression_reason,
    }
}

/// Accessibility action names a click may ask a control to run.
///
/// One owner, because two spellings of this string cannot disagree quietly:
/// the closed `AxAction` vocabulary parses exactly what macOS advertises, so a
/// caller-side shorthand is refused as unadvertised and every click fails. That
/// happened -- the wire handler said "press" while controls advertise
/// "AXPress" -- and no fixture could see it, because a test double advertises
/// whatever string the test also passes, so the two agree with each other and
/// with nothing real.
///
/// `the_click_action_names_match_the_framework_vocabulary` holds these against
/// the macOS spellings, so a future divergence fails a build rather than every
/// click.
pub const SEMANTIC_PRESS_ACTION: &str = "AXPress";
pub const SEMANTIC_CANCEL_ACTION: &str = "AXCancel";

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
/// One process that answers to a bundle identity, before any grant is made.
///
/// Carries only what a person needs to tell two instances apart. The generation
/// evidence that makes a grant is deliberately absent: resolution decides WHICH
/// process is meant, and reading identity evidence for a target that turns out to
/// be ambiguous would be work done for a request that cannot be served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetCandidate {
    pub pid: u32,
    /// How many windows this instance currently owns, so an operator choosing
    /// between two can tell a working instance from a stray one.
    pub window_count: usize,
}

/// What a bundle identity names right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetResolution {
    /// Exactly one process answers to it.
    Resolved(ProcessGrant),
    /// Nothing running answers to it.
    ///
    /// Distinct from ambiguity because the remedy differs: this one is answered
    /// by starting the application, and no choice by the user can resolve it.
    NotRunning,
    /// Several processes answer to it, so the identity does not name one.
    ///
    /// Refused rather than resolved to the frontmost, the oldest, or the first
    /// seen. Any of those derives the target from state the user did not choose
    /// and would not experience as a decision, which is the same objection that
    /// rules out taking the frontmost application as the target.
    ///
    /// The candidates travel with the refusal so a person can act on it. A bare
    /// "ambiguous" makes them reconstruct which instances exist before they can
    /// do anything about it.
    Ambiguous(Vec<TargetCandidate>),
    /// The window list could not be read, so nothing is known about the target.
    ///
    /// Distinct from `NotRunning`, which is a claim about the world. This says
    /// only that this process could not see, and the two have opposite remedies:
    /// one is answered by starting the application, and this one by finding out
    /// why the window server did not answer.
    ///
    /// The distinction is not theoretical. Under load the permission query can
    /// report capture as permitted while enumeration fails with a declined-TCC
    /// error in the same instant, so a transient window-server failure arrives
    /// wearing a permission denial's clothes. Reporting that as `NotRunning`
    /// tells someone their running application is not running.
    Unreadable,
}

impl TargetResolution {
    /// Decide what a bundle identity names, given every window on the machine.
    ///
    /// Takes the whole window list rather than a filtered one so the ambiguity
    /// is visible here: a caller that filtered first would have to decide which
    /// instance to filter for, which is the question being answered.
    ///
    /// `read_generation` runs only for a single resolved instance, so the
    /// ambiguous and not-running paths cost nothing.
    pub fn decide<F: FnOnce(u32) -> Option<String>>(
        bundle_identity: &str,
        windows: Option<&[(u32, String)]>,
        read_generation: F,
    ) -> Self {
        // The reading arrives as an Option rather than a slice so that the
        // difference between "the window server said there are no windows" and
        // "the window server did not answer" is decided here, in the half that
        // every host compiles and tests, rather than at the platform call site
        // that only macOS builds. Those two are one keystroke apart and mean
        // opposite things to whoever receives the answer.
        let Some(windows) = windows else {
            return Self::Unreadable;
        };
        let mut counts: BTreeMap<u32, usize> = BTreeMap::new();
        for (pid, identity) in windows {
            if identity == bundle_identity {
                *counts.entry(*pid).or_default() += 1;
            }
        }

        let mut instances = counts.into_iter();
        let Some((pid, window_count)) = instances.next() else {
            return Self::NotRunning;
        };
        let rest: Vec<(u32, usize)> = instances.collect();
        if !rest.is_empty() {
            let mut candidates = vec![TargetCandidate { pid, window_count }];
            candidates.extend(
                rest.into_iter()
                    .map(|(pid, window_count)| TargetCandidate { pid, window_count }),
            );
            return Self::Ambiguous(candidates);
        }

        // A process that owns windows but whose start time cannot be read is
        // treated as not running rather than resolved: a grant without
        // generation evidence cannot survive the target being replaced, which is
        // the whole reason the evidence is carried.
        match read_generation(pid) {
            Some(process_generation_evidence) => Self::Resolved(ProcessGrant {
                pid,
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence,
            }),
            None => Self::NotRunning,
        }
    }
}

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

/// The exact accessibility key under which an element must be unique.
///
/// Each form is matched independently. Naming one form never authorizes a
/// resolver or dispatcher to try the other.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessibilityElementName {
    Identifier(String),
    RoleAndTitle { role: String, title: String },
}

/// Which accessibility key form uniquely identified the element.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityKeyForm {
    Identifier,
    RoleAndTitle,
}

impl AccessibilityElementName {
    pub fn identifier(identifier: impl Into<String>) -> Self {
        Self::Identifier(identifier.into())
    }

    pub fn role_and_title(role: impl Into<String>, title: impl Into<String>) -> Self {
        Self::RoleAndTitle {
            role: role.into(),
            title: title.into(),
        }
    }

    pub fn is_usable(&self) -> bool {
        match self {
            Self::Identifier(identifier) => !identifier.is_empty(),
            Self::RoleAndTitle { role, .. } => !role.is_empty(),
        }
    }

    pub const fn key_form(&self) -> AccessibilityKeyForm {
        match self {
            Self::Identifier(_) => AccessibilityKeyForm::Identifier,
            Self::RoleAndTitle { .. } => AccessibilityKeyForm::RoleAndTitle,
        }
    }
}

/// The one predicate attribute a scoped accessibility read must retrieve.
///
/// Presence needs only a complete uniqueness search. The other variants read
/// exactly one attribute from the uniquely named element after that search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityReadbackAttribute {
    Presence,
    Focused,
    Enabled,
    Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityElementReadRequest {
    pub target: ProcessGrant,
    pub element_name: AccessibilityElementName,
    pub attribute: AccessibilityReadbackAttribute,
    pub deadline_ms: u32,
}

/// The scoped state read from one uniquely named accessibility element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityElementReadResult {
    pub element_name: AccessibilityElementName,
    pub present: bool,
    pub focused: Option<bool>,
    pub enabled: Option<bool>,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementResolutionRequest {
    pub root_identifier: String,
    pub element_name: AccessibilityElementName,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ElementResolutionResult {
    /// The exact key form that established uniqueness.
    pub element_name: AccessibilityElementName,
    /// The other supported key when the same resolved element reported one.
    #[serde(default)]
    pub alternate_name: Option<AccessibilityElementName>,
    pub owning_process: ProcessGrant,
    pub semantic_actions: Vec<String>,
    /// Subtrees omitted from the accessibility tree this resolution searched.
    pub unreadable_subtrees: u64,
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
    /// Subtrees omitted from the fresh accessibility tree used for this dispatch.
    pub unreadable_subtrees: u64,
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
    /// Which application to read when checking the condition.
    ///
    /// Carried rather than inferred: an observer that read whichever
    /// application was frontmost would check the condition against a window the
    /// action never touched, and report an effect belonging to something else.
    /// The grant is the only statement of which process the action was
    /// authorised against.
    pub target: ProcessGrant,
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

/// Why an accessibility tree could not be read.
///
/// These outcomes name the remedy available to a caller rather than the
/// framework status that produced them. A target that has exited, for example,
/// cannot become readable by retrying, while a deadline can.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessibilityReadFailure {
    PermissionRequired,
    TargetGone,
    TargetReplaced,
    TargetNotInspectable,
    RetryableDeadlineExceeded,
    TreeExceedsBound,
    IncompatiblePlatformValue,
    PlatformReadFailed,
}

impl fmt::Display for AccessibilityReadFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::PermissionRequired => "accessibility permission is required",
            Self::TargetGone => "target process is gone",
            Self::TargetReplaced => "target process was replaced",
            Self::TargetNotInspectable => "target process cannot be inspected",
            Self::RetryableDeadlineExceeded => "accessibility read deadline exceeded",
            Self::TreeExceedsBound => "accessibility tree exceeds the read bound",
            Self::IncompatiblePlatformValue => {
                "platform returned an incompatible accessibility value"
            }
            Self::PlatformReadFailed => "platform failed while reading accessibility data",
        })
    }
}

/// A semantic action failure split by the remedy available to its caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SemanticDriverError {
    ElementNameAmbiguous {
        key_form: AccessibilityKeyForm,
        match_count: u64,
    },
    ElementNotFound {
        key_form: AccessibilityKeyForm,
    },
    ActionNotAdvertised {
        action: String,
        advertised: Vec<String>,
    },
    ApplicationRefused {
        ax_error: i32,
    },
    AccessibilityPermissionUnavailable,
    TargetNoLongerCurrent {
        disposition: TargetDisposition,
    },
    Transient {
        deadline_ms: u64,
    },
    PathUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetDisposition {
    Gone,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DriverError {
    Unsupported(&'static str),
    InvalidRequest(&'static str),
    StartupRefused(&'static str),
    /// The accessibility tree could not be read.
    AccessibilityUnreadable(AccessibilityReadFailure),
    /// The tree was read and the named element is not in it.
    ElementNotFound,
    /// A semantic driver failure that tells the caller how the refused action can be handled.
    Semantic(SemanticDriverError),
}

impl From<AccessibilityReadFailure> for DriverError {
    fn from(failure: AccessibilityReadFailure) -> Self {
        Self::AccessibilityUnreadable(failure)
    }
}

impl fmt::Display for DriverError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(op) => write!(f, "unsupported platform operation: {op}"),
            Self::InvalidRequest(reason) => write!(f, "invalid platform request: {reason}"),
            Self::StartupRefused(reason) => write!(f, "platform startup refused: {reason}"),
            Self::AccessibilityUnreadable(failure) => {
                write!(f, "accessibility tree unreadable: {failure}")
            }
            Self::ElementNotFound => f.write_str("accessibility element not found"),
            Self::Semantic(failure) => write!(f, "semantic action refused: {failure:?}"),
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
    /// Read only the element and attribute named by a predicate.
    fn read_accessibility_element(
        &mut self,
        _request: AccessibilityElementReadRequest,
    ) -> Result<AccessibilityElementReadResult, DriverError> {
        Err(DriverError::Unsupported("scoped accessibility read"))
    }
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
pub(crate) struct PlatformNeutralTestDriver;

#[cfg(test)]
impl PlatformDriver for PlatformNeutralTestDriver {
    fn capability_declarations(
        &self,
        _context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        panic!("test driver must not execute platform operations")
    }

    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn dispatch_semantic(
        &mut self,
        _request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn dispatch_global(
        &mut self,
        _request: SyntheticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn input_observer_liveness(&self) -> InputObserverLiveness {
        panic!("test driver must not execute platform operations")
    }

    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn observe_effect(
        &mut self,
        _request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }
}

#[cfg(test)]
mod target_resolution_tests {
    use super::*;

    fn windows() -> Vec<(u32, String)> {
        vec![
            (100, "com.apple.Safari".to_string()),
            (100, "com.apple.Safari".to_string()),
            (200, "com.apple.Mail".to_string()),
        ]
    }

    fn generation(_pid: u32) -> Option<String> {
        Some("1700000000000000".to_string())
    }

    /// One instance resolves to a grant naming it.
    ///
    /// The accepting case, asserted because every other test here is a refusal:
    /// without it, resolution could refuse everything and they would all pass.
    #[test]
    fn a_single_instance_resolves() {
        let resolution = TargetResolution::decide("com.apple.Safari", Some(&windows()), generation);
        let TargetResolution::Resolved(grant) = resolution else {
            panic!("one instance must resolve, got {resolution:?}");
        };
        assert_eq!(grant.pid, 100);
        assert_eq!(grant.bundle_identity, "com.apple.Safari");
        assert!(grant.validate().is_ok());
    }

    /// Two instances refuse, and the refusal names both.
    ///
    /// Naming them is what makes the refusal actionable: a person choosing
    /// between instances needs to know they exist and which is which, and a bare
    /// "ambiguous" makes them reconstruct that before they can do anything.
    #[test]
    fn two_instances_refuse_and_name_themselves() {
        let mut many = windows();
        many.push((101, "com.apple.Safari".to_string()));

        let resolution = TargetResolution::decide("com.apple.Safari", Some(&many), |_| {
            panic!("identity evidence was read for a target that cannot be served")
        });
        let TargetResolution::Ambiguous(candidates) = resolution else {
            panic!("two instances must refuse, got {resolution:?}");
        };

        let named: Vec<u32> = candidates.iter().map(|candidate| candidate.pid).collect();
        assert_eq!(named, vec![100, 101]);
        assert_eq!(
            candidates[0].window_count, 2,
            "the refusal should say how many windows each instance owns"
        );
        assert_eq!(candidates[1].window_count, 1);
    }

    /// An identity nothing answers to is not running, rather than ambiguous.
    ///
    /// The two refusals have different remedies: this one is answered by
    /// starting the application, and no choice by the user resolves it.
    #[test]
    fn an_identity_nothing_answers_to_is_not_running() {
        assert_eq!(
            TargetResolution::decide("com.example.Absent", Some(&windows()), generation),
            TargetResolution::NotRunning
        );
    }

    /// An instance whose start time cannot be read does not resolve.
    ///
    /// A grant without generation evidence cannot tell the target from a
    /// replacement that inherits its process id, which is the whole reason the
    /// evidence is carried. Reported as not running because that is what the
    /// caller can act on: the process this identity named is not usable.
    #[test]
    fn an_instance_without_generation_evidence_does_not_resolve() {
        assert_eq!(
            TargetResolution::decide("com.apple.Safari", Some(&windows()), |_| None),
            TargetResolution::NotRunning
        );
    }

    /// A window list that could not be read is not the application being absent.
    ///
    /// The two answers send a person in opposite directions: absence is answered
    /// by starting the application, while an unreadable list says nothing about
    /// whether it is running at all. They are one keystroke apart at the call
    /// site, which is why the distinction is decided here rather than in the
    /// platform half that only one operating system compiles.
    ///
    /// Measured, not hypothetical: under concurrent load the screen-capture
    /// permission query reported permitted while enumeration failed in the same
    /// instant with a declined-permission error. Calling that "not running"
    /// tells someone to start a second copy of an application already in front
    /// of them, and the second copy then makes the target ambiguous.
    #[test]
    fn an_unread_window_list_is_unreadable_and_never_not_running() {
        let resolution = TargetResolution::decide("com.apple.Safari", None, |_| {
            panic!("a generation was read for a target nothing could see")
        });

        assert_eq!(resolution, TargetResolution::Unreadable);
        assert_ne!(
            resolution,
            TargetResolution::NotRunning,
            "an unreadable window list claimed the application is absent"
        );
    }

    /// An EMPTY window list, by contrast, is a real reading: the window server
    /// answered and nothing matched. This is the companion the previous test
    /// needs, because a decide that returned Unreadable for both would satisfy
    /// it while destroying the ability to say an application is not running.
    #[test]
    fn an_empty_window_list_is_a_reading_and_means_not_running() {
        let resolution = TargetResolution::decide("com.apple.Safari", Some(&[]), |_| {
            panic!("a generation was read for an absent target")
        });

        assert_eq!(resolution, TargetResolution::NotRunning);
    }

    /// Windows owned by other applications do not affect the decision.
    #[test]
    fn another_applications_windows_are_not_counted() {
        let resolution = TargetResolution::decide("com.apple.Mail", Some(&windows()), generation);
        let TargetResolution::Resolved(grant) = resolution else {
            panic!("one instance must resolve, got {resolution:?}");
        };
        assert_eq!(grant.pid, 200);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_duration_rejects_values_above_five_minutes() {
        assert!(<PlatformNeutralTestDriver as PlatformDriver>::bounded_duration(300_001).is_err());
        assert_eq!(
            <PlatformNeutralTestDriver as PlatformDriver>::bounded_duration(300_000).unwrap(),
            Duration::from_millis(300_000)
        );
    }

    #[test]
    fn an_unavailable_platform_advertises_only_the_platform_neutral_wait() {
        let digest = COMPUTER_ACTION_VOCABULARY_SHA256.to_string();
        let context = CapabilityAdvertisementContext {
            inputs: ImmutableReleaseInputs {
                vocabulary_digests: VocabularyDigestInputs {
                    manifest_digest: Some(digest.clone()),
                    source_lock_digest: Some(digest.clone()),
                    computed_artifact_digest: Some(digest),
                },
                ..ImmutableReleaseInputs::default()
            },
            permissions: PermissionLivenessReport::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let advertised: Vec<_> = capability_declarations(&context, false, false)
            .into_iter()
            .filter(|declaration| declaration.advertised)
            .map(|declaration| declaration.capability_id)
            .collect();

        assert_eq!(advertised, vec!["computer.wait"]);
    }
}
