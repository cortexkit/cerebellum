//! Bounded, OS-neutral computer-plane platform seam.
//!
//! This slice deliberately contains no window-server or accessibility bindings.
//! The macOS implementation is an injectable skeleton: it can prove whether a
//! capability is safe to advertise, while later slices provide the operations.

use cerebellum_core::consent::OnceDispatchToken;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::time::Duration;

pub mod blocked_chord;
pub mod containment;
pub mod input_route;
pub mod process_event;
pub mod severity;
pub mod synthetic;
pub use blocked_chord::*;
pub use containment::*;
pub use process_event::*;
pub use synthetic::*;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
mod macos_synthetic;
#[cfg(any(target_os = "windows", test))]
pub mod windows;

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
#[cfg(target_os = "windows")]
pub use windows::{WindowsPlatformDriver, WindowsUnsupportedCaptureBackend};

pub mod vocabulary;
pub use vocabulary::{
    canonical_json_bytes, computed_vocabulary_sha256, implementation_source_lock_digest,
    validate_vocabulary, validate_vocabulary_digests, VocabularyDigestInputs,
    VocabularyValidationError, COMPUTER_ACTION_VOCABULARY_REVISION,
    COMPUTER_ACTION_VOCABULARY_SCHEMA_ID, COMPUTER_ACTION_VOCABULARY_SHA256,
    COMPUTER_CAPABILITY_ROW_IDS,
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

/// Closed action-kind taxonomy that consent leases are keyed by.
///
/// The vocabulary artifact no longer carries it: each capability's kind is
/// stated once, by `ComputerCapability::action_kind`.
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
    /// The probe itself did not complete -- its thread panicked before it
    /// reported anything -- so nothing is known about the grant. Kept apart
    /// from `Unresolved` because the two send an operator to different
    /// places: an unresolved reading is answered in System Settings, a
    /// crashed probe is a module fault that no settings change repairs.
    ProbeFailed,
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
    probe_failed: bool,
}

impl PermissionLivenessReport {
    pub fn from_results(results: impl IntoIterator<Item = PermissionProbeResult>) -> Self {
        Self {
            states: results
                .into_iter()
                .map(|result| (result.service, result.liveness))
                .collect(),
            probe_failed: false,
        }
    }

    /// Mark every service `ProbeFailed` when the startup probe fails to return,
    /// so call-time refusals report a failed probe rather than a permission
    /// denial.
    pub fn probe_failed() -> Self {
        Self {
            states: BTreeMap::new(),
            probe_failed: true,
        }
    }

    pub fn state(&self, service: PermissionService) -> PermissionLiveness {
        if self.probe_failed {
            return PermissionLiveness::ProbeFailed;
        }
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
/// to execute a capability, so the report remains unresolved for every service.
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
/// probe retain the default, which establishes no private envelope or grants.
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
    pub global_dispatch_review_revision: Option<String>,
    pub capture_review_revision: Option<String>,
    pub semantic_actuation_review_revision: Option<String>,
    pub windows_actuation_review_revision: Option<String>,
    /// The review of `computer.read_state`: the application-state tree, its
    /// element ids, and its window image.
    pub app_state_review_revision: Option<String>,
    /// The review of `computer.press_element`, `computer.press_point` and
    /// `computer.write_text`: pressing and writing retained elements through
    /// accessibility, and the hit test that finds one under a point.
    pub element_addressed_review_revision: Option<String>,
    /// The review of anything that can take the person's input focus: the
    /// takeover pointer rows and the fronting bracket that brings a
    /// background application forward for keystrokes.
    pub takeover_dispatch_review_revision: Option<String>,
    /// The review of temporary target fronting for global pointer gestures,
    /// including a dedicated left-button click. Absent until that review binds.
    pub takeover_pointer_fronting_review_revision: Option<String>,
    /// The review of background app use: bringing an application forward
    /// outside the keystroke bracket (one-way fronting in foreground mode, and
    /// fronting a press or a modifier chord under the app grant alone, with
    /// its restore decision), and capturing a covered window's pixels for the
    /// preview outside capture custody. It gates no capability row; together
    /// with the takeover review it admits that fronting, and together with the
    /// capture review it admits that capture.
    pub app_use_fronting_review_revision: Option<String>,
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

    fn global_dispatch_ready(&self) -> bool {
        self.global_dispatch_review_revision.is_some()
            && self.release_signing_topology_revision.is_some()
    }

    /// Both reviews the takeover rows need: the review of the global pointer
    /// stream and its per-post checks, and the review of handing that pointer
    /// to the agent under a takeover grant. Neither covers the other.
    fn takeover_dispatch_ready(&self) -> bool {
        self.global_dispatch_ready() && self.takeover_dispatch_review_revision.is_some()
    }
}

/// Builds the fixed declaration set from release inputs and platform availability.
/// Permission readings remain diagnostic facts and never change the tool surface.
///
/// `platform_available` distinguishes a host that can serve the platform driver
/// from one that can only report the frozen vocabulary. The latter keeps all
/// rows visible for release evidence and may still advertise `computer.wait`,
/// because waiting has no platform operation to perform.
///
/// One declaration per current capability, in artifact order. Retired
/// capabilities are not declared at all: they are not something this module
/// offers, even as a withheld row.
pub fn capability_declarations(
    context: &CapabilityAdvertisementContext,
    platform_available: bool,
) -> Vec<CapabilityDeclaration> {
    crate::audit::ComputerCapability::ALL
        .into_iter()
        .map(|capability| capability_declaration(capability, context, platform_available))
        .collect()
}

/// One row's declaration.
///
/// The private-envelope flag was a parameter here and is gone: it gated
/// synthetic support on evidence that this build resolved private SkyLight
/// symbols, which no path uses. The flag still exists on the startup probe as a
/// reported fact; it decides nothing.
fn capability_declaration(
    capability: crate::audit::ComputerCapability,
    context: &CapabilityAdvertisementContext,
    platform_available: bool,
) -> CapabilityDeclaration {
    use crate::audit::ComputerCapability;
    let id = capability.capability_id();
    let action_kind = capability.action_kind();
    let retry_class = match capability {
        ComputerCapability::ReadState | ComputerCapability::Wait | ComputerCapability::ListApps => {
            RetryClass::Idempotent
        }
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
    // identify the missing layer. Rows that reach neither branch below are in
    // the vocabulary with no handler serving them over the wire yet, and no
    // release input can change that.
    let mut suppression_reason = permission_lookup_failure.clone().or_else(|| {
        Some(
            "no wire serving handler: the capability is in the vocabulary and is not \
             served yet"
                .to_string(),
        )
    });
    if permission_lookup_failure.is_some() {
        // Keep the permission-lookup failure reason unchanged. It identifies
        // an inability to resolve required permissions, which is more useful
        // to the caller than a release-input status.
    } else if matches!(
        id,
        "computer.read_state"
            | "computer.press_element"
            | "computer.press_point"
            | "computer.write_text"
            | "computer.open_app"
    ) {
        // State reads and element actions use accessibility; application launch
        // uses LaunchServices instead. Each is advertised on its own review.
        // Screen Recording is only needed for a state read's optional image.
        // Permission requirements are checked at call time, not while building
        // the prompt-visible tool surface.
        // Launch needs both the inventory review and action review: resolving
        // installed names and acting under a signer-bound grant are separate
        // surfaces. Like element actions, it also binds the release signer.
        let review_missing =
            if id == "computer.open_app" && context.inputs.app_state_review_revision.is_none() {
                Some("application state review revision is not bound")
            } else if id == "computer.read_state" {
                context
                    .inputs
                    .app_state_review_revision
                    .is_none()
                    .then_some("application state review revision is not bound")
            } else {
                context
                    .inputs
                    .element_addressed_review_revision
                    .is_none()
                    .then_some("element-addressed action review revision is not bound")
            };
        suppression_reason = if !platform_available {
            Some("no application-state reader on this platform".to_string())
        } else if !context.inputs.vocabulary_ready() {
            Some("computer action vocabulary input unresolved".to_string())
        } else if let Some(missing) = review_missing {
            Some(missing.to_string())
        } else if context.inputs.release_signing_topology_revision.is_none() {
            Some("release signing topology revision is not bound".to_string())
        } else {
            None
        };
        advertised = suppression_reason.is_none();
    } else if id == "computer.list_apps" {
        // Names, bundle identities and pids of running applications: no
        // window content, so no accessibility or screen grant is a condition.
        // It is part of reading application state and shares that review.
        suppression_reason = if !platform_available {
            Some("no application-state reader on this platform".to_string())
        } else if !context.inputs.vocabulary_ready() {
            Some("computer action vocabulary input unresolved".to_string())
        } else if context.inputs.app_state_review_revision.is_none() {
            Some("application state review revision is not bound".to_string())
        } else if context.inputs.release_signing_topology_revision.is_none() {
            Some("release signing topology revision is not bound".to_string())
        } else {
            None
        };
        advertised = suppression_reason.is_none();
    } else if id == "computer.wait" {
        advertised = context.inputs.vocabulary_ready();
        suppression_reason =
            (!advertised).then(|| "computer action vocabulary input unresolved".to_string());
    } else if matches!(id, "computer.type" | "computer.keys") {
        // Keystroke advertisement is a build-time decision. Startup permission
        // readings decide whether a call can proceed, not which schema is sent.
        suppression_reason = if !context.inputs.vocabulary_ready() {
            Some("computer action vocabulary input unresolved".to_string())
        } else if context.inputs.input_review_revision.is_none() {
            Some("synthetic input review revision is not bound".to_string())
        } else if context.inputs.attendance_contract_owner.is_none()
            || context.inputs.attendance_contract_revision.is_none()
        {
            Some("attendance contract inputs are not bound".to_string())
        } else if !context.inputs.input_dispatch_ready() {
            Some("release signing topology revision is not bound".to_string())
        } else {
            None
        };
        advertised = suppression_reason.is_none();
    } else if matches!(
        capability,
        ComputerCapability::TakeoverMove
            | ComputerCapability::TakeoverClick
            | ComputerCapability::TakeoverDrag
            | ComputerCapability::TakeoverScroll
    ) {
        // The real-pointer rows require both release reviews, independently of
        // the permissions that will be needed when a caller uses them.
        suppression_reason = if !platform_available {
            Some("no global pointer dispatch on this platform".to_string())
        } else if !context.inputs.vocabulary_ready() {
            Some("computer action vocabulary input unresolved".to_string())
        } else if context.inputs.global_dispatch_review_revision.is_none() {
            Some("global dispatch review revision is not bound".to_string())
        } else if context.inputs.takeover_dispatch_review_revision.is_none() {
            Some("takeover dispatch review revision is not bound".to_string())
        } else if capability == ComputerCapability::TakeoverClick
            && !context
                .inputs
                .takeover_pointer_fronting_review_revision
                .as_deref()
                .is_some_and(|value| {
                    !value.trim().is_empty()
                        && !["placeholder", "tbd", "unknown"]
                            .iter()
                            .any(|stand_in| value.eq_ignore_ascii_case(stand_in))
                })
        {
            Some("takeover pointer fronting review revision is not bound".to_string())
        } else if !context.inputs.takeover_dispatch_ready() {
            Some("release signing topology revision is not bound".to_string())
        } else if !DOWN_GESTURE_RECOVERY_MEASURED
            && (capability == ComputerCapability::TakeoverClick
                || (capability == ComputerCapability::TakeoverDrag
                    && context
                        .inputs
                        .takeover_pointer_fronting_review_revision
                        .as_deref()
                        .is_some_and(|value| {
                            !value.trim().is_empty()
                                && !["placeholder", "tbd", "unknown"]
                                    .iter()
                                    .any(|stand_in| value.eq_ignore_ascii_case(stand_in))
                        })))
        {
            Some("mouse-up routing measurement is not recorded".to_string())
        } else {
            None
        };
        advertised = suppression_reason.is_none();
    }

    // Which modes could carry this row at all, before asking whether any of them
    // is available in this build. The pointer rows are observed-only: the
    // frozen vocabulary gives them synthetic_paths ["global"] and no per_pid,
    // because the per-process path was measured not to carry pointer events.
    // The element rows act through accessibility, which reaches a backgrounded
    // application; wait dispatches nothing.
    let dispatch_modes = match capability {
        ComputerCapability::TakeoverMove
        | ComputerCapability::TakeoverClick
        | ComputerCapability::TakeoverDrag
        | ComputerCapability::TakeoverScroll => vec![DispatchMode::Observed],
        ComputerCapability::ReadState
        | ComputerCapability::PressElement
        | ComputerCapability::PressPoint
        | ComputerCapability::WriteText
        | ComputerCapability::OpenApp => vec![DispatchMode::Background],
        ComputerCapability::Type | ComputerCapability::Keys => {
            vec![DispatchMode::Background, DispatchMode::Observed]
        }
        _ => vec![],
    };

    // Claimed only where something serves the path the frozen row names,
    // rather than wherever the row names one. The press and write rows name
    // ax_press and ax_value, which the accessibility element actions serve
    // wherever the application-state reader exists.
    let semantic_support = if platform_available
        && matches!(
            capability,
            ComputerCapability::PressElement
                | ComputerCapability::PressPoint
                | ComputerCapability::WriteText
                | ComputerCapability::OpenApp
        ) {
        SupportState::Supported
    } else {
        SupportState::Unsupported
    };

    // Background delivery is claimed per SYNTHETIC EVENT CLASS, because the
    // per-process path carries one and not the other. Measured on macOS 26
    // against a native application, target backgrounded, focus sampled
    // throughout: a keystroke posted to the pid lands; a drag posted to the same
    // pid has no effect even with the target frontmost, while the SAME
    // constructed events posted globally do select. The events are right and the
    // per-process path does not carry pointer events.
    //
    // Only the keystroke rows post synthetic keyboard events; the element rows
    // post no events at all, so they claim no synthetic delivery either.
    let background_support = if platform_available
        && matches!(
            capability,
            ComputerCapability::Type | ComputerCapability::Keys
        ) {
        SupportState::Supported
    } else {
        SupportState::Unsupported
    };
    // Observed delivery is the global pointer stream. For the keystroke rows
    // it is never used over the wire, so only the takeover rows count it as
    // a working path, and only under both of their reviews.
    let observed_support = platform_available
        && dispatch_modes.contains(&DispatchMode::Observed)
        && context.inputs.takeover_dispatch_ready();
    CapabilityDeclaration {
        capability_id: id.to_string(),
        action_kind,
        dispatch_modes: dispatch_modes.clone(),
        // Mirroring the artifact made this declaration restate what the row
        // WANTS instead of what the driver can do, which is the same shape as a
        // frozen column nothing verifies: the claim and its subject never meet.
        semantic_path: semantic_support,
        // CGEventPostToPid delivers keystrokes to a background process, but it
        // does not deliver pointer events. Pointer events need global dispatch,
        // which moves the real cursor, so it is not background delivery.
        // The private-envelope flag records recognition of private SkyLight
        // symbols; it does not decide whether background delivery is supported.
        synthetic_background: background_support,
        // Derived from the dispatch modes rather than asserted beside them, so
        // the two cannot disagree about whether a row has an observed path.
        //
        // They did: the observing rows carry no observed dispatch mode because
        // they read rather than actuate, and this field once claimed
        // ConsentGated for them anyway -- an observed synthetic path, pending
        // consent, for capabilities that dispatch nothing.
        synthetic_observed: if dispatch_modes.contains(&DispatchMode::Observed) {
            SupportState::ConsentGated
        } else {
            SupportState::Unsupported
        },
        required_permissions: permissions,
        retry_class,
        // A capability whose permission requirements could not be read is
        // never advertised, whatever the rest of the gate concluded: a
        // permission that is not known cannot be checked, and offering the
        // capability would promise a check nobody performs.
        // An ACTUATING row must additionally have a delivery path that works.
        //
        // Every gate above answers whether we are ALLOWED to serve the row. None
        // of them asks whether anything can carry it. The two came apart once
        // already: the per-process path does not deliver pointer events, so the
        // pointer rows have no working background path, and binding a review
        // key would have advertised capabilities that cannot deliver -- the
        // defect this module already refuses one field over, where a permission
        // that cannot be read withholds its capability.
        //
        // ConsentGated deliberately does not count. It describes what the design
        // intends to offer once observed mode exists, and intent is not a path.
        //
        // Observing rows actuate nothing, so the requirement does not apply to
        // them. Keyed on action_kind rather than a list of names, so the line
        // between observing and actuating is drawn in one place.
        advertised: (platform_available || id == "computer.wait")
            && advertised
            && permission_lookup_failure.is_none()
            && (action_kind == ActionKind::Observe
                || semantic_support == SupportState::Supported
                || background_support == SupportState::Supported
                || observed_support),
        suppression_reason,
    }
}

/// Keep fronted button-down gestures unavailable until `mouse_up_routing_probe`
/// measures secure-focus, moved/closed windows and termination. The receipts
/// must establish how a held button can be released without acting on an
/// unrelated target after containment or sensitivity changes. Record that
/// justification in `.cortexkit/internal-docs/designs/takeover-pointer-fronting-review-packet.md`,
/// section "Live evidence still to collect", before changing this constant.
pub const DOWN_GESTURE_RECOVERY_MEASURED: bool = false;

/// Platform-neutral semantic action intents a semantic dispatch may carry.
pub const SEMANTIC_PRESS_ACTION: &str = "press";
pub const SEMANTIC_CANCEL_ACTION: &str = "cancel";

/// The closed action intents a platform semantic driver may receive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticActionIntent {
    Press,
    Cancel,
}

impl SemanticActionIntent {
    pub const ALL: [Self; 2] = [Self::Press, Self::Cancel];

    pub const fn wire_name(self) -> &'static str {
        match self {
            Self::Press => SEMANTIC_PRESS_ACTION,
            Self::Cancel => SEMANTIC_CANCEL_ACTION,
        }
    }

    pub fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            SEMANTIC_PRESS_ACTION => Some(Self::Press),
            SEMANTIC_CANCEL_ACTION => Some(Self::Cancel),
            _ => None,
        }
    }
}

/// Platforms with an authored semantic-action mapping table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SemanticActionPlatform {
    #[serde(rename = "macos")]
    MacOs,
    #[serde(rename = "windows")]
    Windows,
}

impl SemanticActionPlatform {
    pub const fn name(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Windows => "windows",
        }
    }
}

/// A known intent that the named platform cannot deliver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnsupportedSemanticAction {
    pub intent: SemanticActionIntent,
    pub platform: SemanticActionPlatform,
}

impl fmt::Display for UnsupportedSemanticAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "semantic action intent {} is unsupported on {}",
            self.intent.wire_name(),
            self.platform.name()
        )
    }
}

impl std::error::Error for UnsupportedSemanticAction {}

/// Map one closed wire intent to the exact action a platform receives.
///
/// The tuple match is deliberately exhaustive. A new intent or platform must
/// state every mapping or typed refusal here, and no caller-supplied string can
/// pass through as a platform action.
pub const fn delivered_semantic_action(
    platform: SemanticActionPlatform,
    intent: SemanticActionIntent,
) -> Result<&'static str, UnsupportedSemanticAction> {
    match (platform, intent) {
        (SemanticActionPlatform::MacOs, SemanticActionIntent::Press) => Ok("AXPress"),
        (SemanticActionPlatform::MacOs, SemanticActionIntent::Cancel) => Ok("AXCancel"),
        (SemanticActionPlatform::Windows, SemanticActionIntent::Press) => Ok("Invoke"),
        (SemanticActionPlatform::Windows, SemanticActionIntent::Cancel) => {
            Err(UnsupportedSemanticAction { intent, platform })
        }
    }
}

#[cfg(test)]
mod semantic_action_mapping_tests {
    use super::*;

    #[test]
    fn macos_press_delivers_axpress() {
        let delivered =
            delivered_semantic_action(SemanticActionPlatform::MacOs, SemanticActionIntent::Press)
                .expect("macOS serves press");

        assert_eq!(delivered, "AXPress");
    }

    #[test]
    fn windows_press_delivers_invoke() {
        let delivered =
            delivered_semantic_action(SemanticActionPlatform::Windows, SemanticActionIntent::Press)
                .expect("Windows serves press");

        assert_eq!(delivered, "Invoke");
    }

    #[test]
    fn windows_cancel_returns_a_typed_refusal_naming_intent_and_platform() {
        assert_eq!(
            delivered_semantic_action(
                SemanticActionPlatform::Windows,
                SemanticActionIntent::Cancel,
            ),
            Err(UnsupportedSemanticAction {
                intent: SemanticActionIntent::Cancel,
                platform: SemanticActionPlatform::Windows,
            })
        );
    }

    #[test]
    fn an_unknown_wire_action_has_no_platform_passthrough() {
        assert_eq!(SemanticActionIntent::from_wire_name("AXPress"), None);
        assert_eq!(
            SemanticActionIntent::from_wire_name("caller_knows_best"),
            None
        );
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

/// Static inputs needed to build declarations, plus startup diagnostic evidence.
/// The permission report is retained for callers, not consulted by advertisement.
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
    ///
    /// The reason travels with it because the remedies differ by platform and
    /// by cause, and a caller told only "unreadable" was being sent to check a
    /// macOS screen-recording grant on a Windows machine whose real problem was
    /// the session it ran in.
    Unreadable(UnreadableReason),
}

/// Why the target list could not be read well enough to answer.
///
/// Each variant names a different remedy. Collapsing them into one word was
/// measured to send a Windows caller a macOS remedy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "reason")]
pub enum UnreadableReason {
    /// The window server (macOS) or `EnumWindows` (Windows) did not answer.
    /// Remedy: retry; if it persists, the platform's permission or
    /// window-server state is the thing to check.
    WindowListUnavailable,
    /// The reading came from a session that cannot see the user's desktop, so
    /// an empty list describes this module's own visibility. Remedy: run from
    /// the console session.
    SessionNotInteractive {
        session_id: u32,
        console_session_id: u32,
    },
    /// No console session exists at all -- nobody is at the machine -- so no
    /// desktop can be observed from any session. Remedy: log a user in at
    /// the console.
    NoConsoleSession { session_id: u32 },
    /// Some windows' owners could not be opened, so the name may belong to a
    /// window this reading could not attribute. Remedy: retry, or name a
    /// process that is not protected.
    PartialWindowList { unreadable_owners: usize },
    /// Exactly one process answers to the name, but its start time could not
    /// be read, so no grant can carry the generation evidence that survives the
    /// target being replaced. The application IS running; starting another
    /// is the wrong remedy. Remedy: retry, then investigate why the process
    /// start time is unreadable for that pid.
    GenerationUnreadable { pid: u32 },
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
            return Self::Unreadable(UnreadableReason::WindowListUnavailable);
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
        // not resolved: a grant without generation evidence cannot survive the
        // target being replaced, which is the whole reason the evidence is
        // carried. But it is not NOT RUNNING either -- it visibly owns windows.
        // That answer stood here for a while and would have sent a caller to
        // start a second instance of an application already in front of them.
        match read_generation(pid) {
            Some(process_generation_evidence) => Self::Resolved(ProcessGrant {
                pid,
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence,
            }),
            None => Self::Unreadable(UnreadableReason::GenerationUnreadable { pid }),
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
    /// Subtrees omitted from this read because they did not answer.
    pub unreadable_subtrees: u64,
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
/// Presence reports whether any named match was observed, along with how many
/// parts were unreadable: an observed match proves presence, but an incomplete
/// search cannot prove absence. Attribute reads require a complete unique match.
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

/// The scoped state read for a named accessibility element, including any
/// unreadable parts that prevent callers from claiming absence or uniqueness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessibilityElementReadResult {
    pub element_name: AccessibilityElementName,
    pub present: bool,
    pub focused: Option<bool>,
    pub enabled: Option<bool>,
    pub value: Option<String>,
    /// Descendant parts the search could not inspect before reaching its bound.
    pub unreadable_subtrees: u64,
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

/// A request to deliver one synthetic input action to the granted process.
///
/// `PartialEq` but not `Eq`: the action's pointer variants carry
/// floating-point coordinates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SyntheticDispatchRequest {
    pub target: ProcessGrant,
    /// What to type, press, scroll, or point at. The event count and the
    /// coordinate-addressed flag are derived from this payload, never stated
    /// alongside it where they could disagree with it.
    pub action: SyntheticAction,
}

/// A global request that cannot be constructed without the token minted when
/// the takeover grant admits one dispatch.
///
/// The token is held by value and is neither cloneable nor defaultable. Timing
/// bounds travel with the request because the platform driver applies them
/// between the individual events of one synthetic action.
#[derive(Debug)]
pub struct GlobalDispatchRequest {
    pub synthetic: SyntheticDispatchRequest,
    pub once_dispatch_token: OnceDispatchToken,
    pub maximum_seize_detection_latency_ms: u32,
    pub minimum_inter_post_interval_ms: u32,
}

/// Revalidate the real wheel recipient before a non-fronting scroll post.
/// This callback may only inspect state; it must not front an app or move the pointer.
#[derive(Clone)]
pub struct GlobalScrollGuard(
    pub std::sync::Arc<dyn Fn() -> Result<(), &'static str> + Send + Sync>,
);

impl std::fmt::Debug for GlobalScrollGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GlobalScrollGuard")
    }
}

/// Revalidate coordinate containment immediately before each pointer post.
/// The callback owns its image/session data and may not post input itself.
/// The `Instant` it receives is the bracket's deadline, fixed when this module
/// asks the system to bring the target application forward. Recipient queries
/// (including a cursor-helper launch) must finish by it and never renew it.
#[derive(Clone)]
pub struct GlobalPointerGuard(
    pub std::sync::Arc<dyn Fn(std::time::Instant) -> Result<(), &'static str> + Send + Sync>,
);

impl std::fmt::Debug for GlobalPointerGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("GlobalPointerGuard")
    }
}

/// A per-process delivery to a target that is not frontmost, posted inside a
/// fronting bracket: the target is brought forward for at most
/// `maximum_interval_ms` at a time, under the idle gate and the seize
/// watcher, and the previous application is put back after each chunk.
#[derive(Debug, Clone, PartialEq)]
pub struct FrontedDispatchRequest {
    pub synthetic: SyntheticDispatchRequest,
    pub maximum_interval_ms: u64,
    pub maximum_seize_detection_latency_ms: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DispatchResult {
    pub accepted_by_platform: bool,
    pub effect_status: EffectStatus,
    /// Subtrees omitted from the fresh accessibility tree used for this dispatch.
    pub unreadable_subtrees: u64,
    /// Number of post calls that returned successfully from the delivery transport.
    #[serde(default)]
    pub delivery_posts_returned: u64,
    /// Number of target-generation checks that passed during delivery.
    /// Per-pid routing expects two checks for each returned post.
    #[serde(default)]
    pub delivery_generation_verifications: u64,
}

impl DispatchResult {
    /// Classify the binding as atomic only when every returned post has both
    /// target-generation checks; any other ratio is non-atomic.
    pub fn identity_to_delivery_binding(&self) -> containment::IdentityAtomicBinding {
        // A delivery that posted nothing has nothing to bind identity TO.
        //
        // Zero posts and zero checks satisfy the ratio below arithmetically,
        // so without this an empty delivery would earn the strongest binding
        // for having done nothing -- and `computer.type` accepts an empty
        // string, so that is reachable rather than theoretical. The ratio is
        // the right test for a delivery that happened; it says nothing about
        // one that did not.
        if self.delivery_posts_returned == 0 {
            return containment::IdentityAtomicBinding::NonAtomic;
        }
        match self.delivery_posts_returned.checked_mul(2) {
            Some(expected) if expected == self.delivery_generation_verifications => {
                containment::IdentityAtomicBinding::Atomic
            }
            _ => containment::IdentityAtomicBinding::NonAtomic,
        }
    }
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

/// Milliseconds since last input, or a reason the idle table could not be read.
///
/// Integer milliseconds rather than the float CoreGraphics reports, so the
/// reading and every refusal built from it stay `Eq` and can sit inside audit
/// records that are compared whole. Sub-millisecond idleness is not a
/// distinction this gate makes.
///
/// Unreadable is a first-class state: collapsing it to zero would look like
/// "just now" and collapsing it to infinity would look like "idle forever".
/// Either lie would pass or fail the idle gate for the wrong reason. A blind
/// tap counting pid-0 events would also invent a false idle, which is why
/// this reading is handed in rather than derived from the observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleReading {
    Milliseconds(u64),
    Unreadable(IdleUnreadable),
}

impl IdleReading {
    /// From the float seconds CoreGraphics reports. Negative or non-finite
    /// values are not a time since anything; they read as unreadable rather
    /// than as zero.
    pub fn from_seconds(seconds: f64) -> Self {
        if !seconds.is_finite() || seconds < 0.0 {
            return IdleReading::Unreadable(IdleUnreadable::TableUnavailable);
        }
        // Saturate rather than wrap: a reading past u64 milliseconds is idle.
        let ms = (seconds * 1000.0).floor();
        if ms >= u64::MAX as f64 {
            IdleReading::Milliseconds(u64::MAX)
        } else {
            IdleReading::Milliseconds(ms as u64)
        }
    }
}

/// Why the HID idle table could not be trusted as a number of seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdleUnreadable {
    /// The table itself did not answer.
    TableUnavailable,
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

/// Why a Windows desktop session cannot support a UI Automation read or action.
///
/// The session identifiers are retained in the refusal so a service session is
/// never mistaken for an empty target in the interactive console session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionProvenanceRefusal {
    OtherSession {
        session_id: u32,
        console_session_id: u32,
    },
    NoConsoleSession {
        session_id: u32,
    },
    Unreadable {
        last_error: u32,
    },
    NotApplicable,
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
    ActionUnsupported {
        intent: SemanticActionIntent,
        platform: SemanticActionPlatform,
    },
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

#[derive(Debug, Clone, PartialEq)]
pub enum DriverError {
    Unsupported(&'static str),
    InvalidRequest(&'static str),
    StartupRefused(&'static str),
    /// A synthetic event could not be constructed by the platform at all.
    EventConstructionFailed(&'static str),
    /// A synthetic input sequence stopped partway through. The payload says
    /// how many post calls returned before the stop and what was done about
    /// input state the posted events may have left held.
    SyntheticDispatchFailed(SequencePostFailure),
    /// The accessibility tree could not be read.
    AccessibilityUnreadable(AccessibilityReadFailure),
    /// Observed dispatch stopped before all of its events could be posted.
    ObservedDispatchAborted(crate::dispatch::AbortDecision),
    /// An observed stop whose paired release could not be confirmed. Keep
    /// both the stop evidence and held-state disposition for audit and cleanup.
    ObservedSequenceFailed {
        abort: crate::dispatch::AbortDecision,
        failure: Box<SequencePostFailure>,
    },
    /// The current Windows session cannot inspect the interactive desktop.
    SessionNotInspectable(SessionProvenanceRefusal),
    /// Windows cannot distinguish an unenumerated app from a hidden window.
    WindowVisibilityUnknown {
        pid: u32,
    },
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
            Self::EventConstructionFailed(reason) => {
                write!(f, "synthetic event construction failed: {reason}")
            }
            Self::SyntheticDispatchFailed(failure) => write!(
                f,
                "synthetic dispatch stopped after {} post call(s) returned: {:?}",
                failure.posts_returned, failure.refusal
            ),
            Self::AccessibilityUnreadable(failure) => {
                write!(f, "accessibility tree unreadable: {failure}")
            }
            Self::ObservedDispatchAborted(abort) => {
                write!(f, "observed dispatch aborted: {:?}", abort.reason)
            }
            Self::ObservedSequenceFailed { abort, failure } => write!(
                f,
                "observed dispatch aborted after {} post call(s): {:?}; held state {:?}",
                failure.posts_returned, abort.reason, failure.held_state
            ),
            Self::SessionNotInspectable(session) => {
                write!(
                    f,
                    "Windows session cannot inspect the console desktop: {session:?}"
                )
            }
            Self::WindowVisibilityUnknown { pid } => write!(
                f,
                "Windows could not establish enumerated window visibility for process {pid}"
            ),
            Self::ElementNotFound => f.write_str("accessibility element not found"),
            Self::Semantic(failure) => write!(f, "semantic action refused: {failure:?}"),
        }
    }
}
impl std::error::Error for DriverError {}

/// The complete bounded surface shared by future Windows, X11, and Wayland
/// backends. Implementations may refuse an operation, but may not broaden it.
pub trait PlatformDriver {
    /// Install containment for a non-fronting wheel dispatch. A driver that
    /// cannot check it at the post must refuse, not silently ignore the guard.
    fn accept_global_scroll_guard(&mut self, _guard: GlobalScrollGuard) -> bool {
        false
    }
    /// Install one separately admitted pointer-fronting unit. Unsupported
    /// drivers must refuse rather than dispatch without containment checks.
    fn accept_pointer_fronting(&mut self, _guard: GlobalPointerGuard) -> bool {
        false
    }
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
    /// Consume only aggregate transport facts; no key identity enters the journal.
    fn take_input_route_evidence(&mut self) -> input_route::InputRouteEvidence {
        input_route::InputRouteEvidence::default()
    }
    /// Selected transport for the audit intent, not a claim of delivery.
    fn per_process_transport(
        &self,
        _action: &SyntheticAction,
    ) -> Option<process_event::PerProcessTransport> {
        None
    }
    fn dispatch_per_pid(
        &mut self,
        request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError>;
    fn dispatch_global(
        &mut self,
        request: GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError>;
    /// Post only the releasing events of `action` to the granted process
    /// generation: the paired release for input a stopped or stuck call may
    /// have left held. Returns how many release posts returned.
    ///
    /// This is the one input path exempt from a stopped call's dispatch
    /// gate. It never posts a press, only the releases the action itself
    /// would have posted, through the same generation-checked routing. The
    /// default refuses, so a platform without it reports the held state as
    /// unknown rather than released.
    fn release_held(
        &mut self,
        _target: &ProcessGrant,
        _action: &SyntheticAction,
    ) -> Result<u64, DriverError> {
        Err(DriverError::Unsupported("paired release of held input"))
    }
    /// Post to a target that is not frontmost through a fronting bracket.
    /// Returns the bracket's report however it ended once it started; an
    /// error means it never started.
    fn dispatch_fronted(
        &mut self,
        _request: FrontedDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<crate::dispatch::BracketReport, DriverError> {
        Err(DriverError::Unsupported(
            "fronted per-process synthetic dispatch",
        ))
    }
    /// Run one image read inside the same observed front/restore bracket as keys.
    /// An error means the bracket never started; its callback must not run then.
    fn read_fronted(
        &mut self,
        _target: &ProcessGrant,
        _maximum_interval_ms: u64,
        _cancelled: &dyn Fn() -> bool,
        _read: &mut dyn FnMut(),
    ) -> Result<crate::dispatch::BracketReport, DriverError> {
        Err(DriverError::Unsupported("fronted image read"))
    }
    /// Open a session for bringing an application to the front outside the
    /// keystroke bracket: a one-way front in foreground mode, or the front of
    /// a press that only works with its application in front. The session
    /// reads and requests the front, and watches session input for the idle
    /// gate and the observer heartbeat. The default refuses, so a platform
    /// without it fronts nothing and its replies say `fronting_unavailable`.
    fn fronting_session(&mut self) -> Result<Box<dyn FrontingSession>, DriverError> {
        Err(DriverError::Unsupported("app-use fronting session"))
    }
    /// Run the next [`Self::dispatch_fronted`] or [`Self::read_fronted`]
    /// under app-use fronting admission, with `hooks` owning its front
    /// attempt and its one restore decision (see [`run_hooked_fronted`]).
    /// `false` when this platform cannot, in which case the hooks are
    /// dropped unused and the caller must not front through this driver. The
    /// default refuses.
    fn accept_fronted_dispatch_hooks(&mut self, hooks: Box<dyn FrontedDispatchHooks>) -> bool {
        drop(hooks);
        false
    }
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

    /// Whether the interactive session's screen is locked right now: `None`
    /// when this platform has no reader for it or the reading failed.
    ///
    /// A locked screen hides every application's interface from the
    /// accessibility API while the windows themselves stay listed, so a read
    /// returns an empty tree, an element lookup finds nothing, and posted input
    /// lands nowhere anyone can confirm. Callers read it fresh before acting
    /// rather than trusting an earlier answer, because the person can lock the
    /// screen at any moment. Defaults to unknown, never to unlocked, so a
    /// platform without a reader cannot pass for one that looked.
    fn session_locked(&self) -> Option<bool> {
        None
    }

    fn bounded_duration(milliseconds: u64) -> Result<Duration, DriverError> {
        if milliseconds > 300_000 {
            return Err(DriverError::InvalidRequest(
                "duration exceeds vocabulary bound",
            ));
        }
        Ok(Duration::from_millis(milliseconds))
    }
}

/// The platform side of a restore after a temporary front: the frontmost
/// read, the front request and a clock, plus the session observer's hardware
/// input timestamps for the restore decision. It is `Send`, so the call's
/// terminal cleanup can run the decision on another thread when the worker
/// that fronted is stuck or gone. Its clock is the clock of the session or
/// bracket it came from, so a front instant read there can be compared with
/// it.
pub trait FrontingRestoreHost: Send {
    fn now_ms(&mut self) -> u64;
    fn pause_ms(&mut self, milliseconds: u64);
    fn frontmost_pid(&mut self) -> Option<u32>;
    fn request_front(&mut self, pid: u32) -> bool;
    /// `None` when unavailable, which the decision reads as no input seen.
    fn hardware_input_snapshot(&mut self) -> Option<crate::dispatch::HardwareInputSnapshot>;
}

/// A fronting host that can hand out a [`FrontingRestoreHost`] on its own
/// clock.
pub trait RestoreHostSource {
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost>;
}

/// One fronting outside the keystroke bracket, as the platform provides it:
/// the same reads, requests and session observation the bracket uses, with
/// the observer's tap held inside. Built and used on one blocking thread, so
/// it need not be `Send`; [`FrontingSession::restore_host`] is.
pub trait FrontingSession {
    /// Milliseconds on the session's clock.
    fn now_ms(&mut self) -> u64;
    fn pause_ms(&mut self, milliseconds: u64);
    fn frontmost_pid(&mut self) -> Option<u32>;
    fn request_front(&mut self, pid: u32) -> bool;
    fn our_pid(&self) -> i64;
    /// Start watching session input. `false` when no observer can be
    /// started, which is how Input Monitoring that is not live shows.
    fn open_observer(&mut self) -> bool;
    fn read_idle(&mut self) -> IdleReading;
    /// Input the observer saw since it was last drained.
    fn drain(&mut self) -> Vec<crate::dispatch::SourcedInputEvent>;
    fn post_heartbeat(&mut self) -> crate::dispatch::HeartbeatProbe;
    fn observe_heartbeat(
        &mut self,
        probe: crate::dispatch::HeartbeatProbe,
        watcher: &mut crate::dispatch::SeizeWatcher,
    ) -> crate::dispatch::HeartbeatObservation;
    fn hardware_input_snapshot(&mut self) -> Option<crate::dispatch::HardwareInputSnapshot>;
    /// A restore host on this session's clock.
    fn restore_host(&self) -> Box<dyn FrontingRestoreHost>;
    /// The idle estimator the platform's other observed sequences share, so
    /// the idle gate reads the same carried history whichever path asks.
    fn user_idle(&self) -> std::sync::Arc<std::sync::Mutex<crate::dispatch::UserIdleEstimator>>;
}

/// A [`FrontingSession`] as the host the bracket's shared functions run
/// against. Its tap lives inside the session, so the bracket's tap is `()`.
/// A session posts no input of its own, so `post_unit` posts nothing.
impl crate::dispatch::FrontingBracketHost for Box<dyn FrontingSession> {
    type Tap = ();

    fn now_ms(&mut self) -> u64 {
        (**self).now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        (**self).pause_ms(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        (**self).frontmost_pid()
    }
    fn request_front(&mut self, pid: u32) -> bool {
        (**self).request_front(pid)
    }
    fn our_pid(&self) -> i64 {
        (**self).our_pid()
    }
    fn create_tap(&mut self) -> Option<()> {
        (**self).open_observer().then_some(())
    }
    fn read_idle(&mut self) -> IdleReading {
        (**self).read_idle()
    }
    fn drain(&mut self, _tap: &()) -> Vec<crate::dispatch::SourcedInputEvent> {
        (**self).drain()
    }
    fn post_heartbeat(&mut self) -> crate::dispatch::HeartbeatProbe {
        (**self).post_heartbeat()
    }
    fn observe_heartbeat(
        &mut self,
        _tap: &(),
        probe: crate::dispatch::HeartbeatProbe,
        watcher: &mut crate::dispatch::SeizeWatcher,
    ) -> crate::dispatch::HeartbeatObservation {
        (**self).observe_heartbeat(probe, watcher)
    }
    fn post_unit(
        &mut self,
        _index: usize,
    ) -> Result<crate::dispatch::UnitPosted, SequencePostFailure> {
        Ok(crate::dispatch::UnitPosted::default())
    }
    fn hardware_input_snapshot(&mut self) -> Option<crate::dispatch::HardwareInputSnapshot> {
        (**self).hardware_input_snapshot()
    }
}

/// One restore decision's result, as the hooks report it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HookedRestore {
    pub restore: crate::dispatch::RestoreStatus,
    pub person_input_during_fronting: bool,
}

/// What the caller of an admitted fronted dispatch owns around it: the
/// registration of the restore obligation before the first front request,
/// the front attempt's start and return, and the one restore decision, which
/// the caller shares with its terminal cleanup so it runs exactly once.
pub trait FrontedDispatchHooks: Send {
    /// Register the restore obligation for a front of `target` over
    /// `previous`, read with the fronting lock held. `host` is on the
    /// bracket's clock. `false` when the call's terminal reply is already
    /// chosen: nothing may be fronted.
    fn register(&mut self, previous: u32, target: u32, host: Box<dyn FrontingRestoreHost>) -> bool;
    /// The front request is about to be made at `front_instant_ms` on the
    /// bracket's clock. `false` when cleanup already took the obligation.
    fn begin_front_attempt(&mut self, front_instant_ms: u64) -> bool;
    /// The front request and its wait returned.
    fn front_attempt_returned(&mut self);
    /// The action observed its target frontmost, not merely a request return.
    fn front_confirmed(&mut self) {}
    /// Run, or await, the one restore decision.
    fn decide_restore(&mut self) -> HookedRestore;
    /// The bracket ended with `outcome`, whose restore is already the hooked
    /// decision. A `deferred_restore` in it is still owed: the caller settles
    /// the held input first.
    fn finished(&mut self, outcome: &crate::dispatch::BracketOutcome);
}

/// Where the hooked host is with the obligation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Registration {
    NotYet,
    /// The terminal was already chosen; nothing was fronted.
    Refused,
    /// Registered; `prevented` when cleanup took it before the front.
    Registered {
        prevented: bool,
    },
}

/// The bracket's host with the restore routed through the hooks: the real
/// host fronts the target, and only the hooks' decision ever asks for the
/// previous application back, so the decision runs once whichever of the
/// worker or terminal cleanup gets there first.
struct HookedHost<'a, H> {
    inner: &'a mut H,
    hooks: &'a mut dyn FrontedDispatchHooks,
    target: u32,
    /// The first frontmost read, which is the bracket's read of the
    /// application to put back.
    previous: Option<Option<u32>>,
    registration: Registration,
    dispatching: bool,
    decided: Option<HookedRestore>,
}

impl<H: crate::dispatch::FrontingBracketHost> HookedHost<'_, H> {
    fn returned(&mut self) {
        if self.dispatching {
            self.dispatching = false;
            self.hooks.front_attempt_returned();
        }
    }
}

impl<H: crate::dispatch::FrontingBracketHost + RestoreHostSource>
    crate::dispatch::FrontingBracketHost for HookedHost<'_, H>
{
    type Tap = H::Tap;

    fn now_ms(&mut self) -> u64 {
        self.inner.now_ms()
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        self.inner.pause_ms(milliseconds);
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        let frontmost = self.inner.frontmost_pid();
        if self.previous.is_none() {
            self.previous = Some(frontmost);
        }
        if self.dispatching && frontmost == Some(self.target) {
            self.hooks.front_confirmed();
            self.returned();
        }
        frontmost
    }
    fn request_front(&mut self, pid: u32) -> bool {
        if pid == self.target {
            if self.registration != Registration::NotYet {
                // One temporary front per call: a later chunk is not
                // fronted again under the same obligation.
                return false;
            }
            let Some(Some(previous)) = self.previous else {
                return false;
            };
            if !self
                .hooks
                .register(previous, self.target, self.inner.restore_host())
            {
                self.registration = Registration::Refused;
                return false;
            }
            let front_instant_ms = self.inner.now_ms();
            if !self.hooks.begin_front_attempt(front_instant_ms) {
                self.registration = Registration::Registered { prevented: true };
                return false;
            }
            self.registration = Registration::Registered { prevented: false };
            self.dispatching = true;
            let requested = self.inner.request_front(pid);
            // A platform can complete activation before its request returns.
            // Preserve that observation even if input aborts the next poll.
            if requested && self.inner.frontmost_pid() == Some(pid) {
                self.hooks.front_confirmed();
            }
            if !requested {
                self.returned();
            }
            return requested;
        }
        // The bracket asks for the previous application back: the hooks'
        // decision does that, or decides not to. Nothing was fronted when
        // registration was refused, so there is nothing to ask for.
        self.returned();
        if matches!(self.registration, Registration::Registered { .. }) && self.decided.is_none() {
            self.decided = Some(self.hooks.decide_restore());
        }
        true
    }
    fn our_pid(&self) -> i64 {
        self.inner.our_pid()
    }
    fn front_attempt_finished(&mut self) {
        self.returned();
    }
    fn restore_front_attempt(
        &mut self,
        _previous: u32,
        _target: u32,
        _since: u64,
        _wait_ms: u64,
        _activation_observed: bool,
    ) -> crate::dispatch::RestoreOutcome {
        self.returned();
        if !matches!(self.registration, Registration::Registered { .. }) {
            return crate::dispatch::RestoreOutcome {
                restore: crate::dispatch::RestoreStatus::NotNeeded,
                person_input_during_fronting: false,
                finished_at_ms: self.inner.now_ms(),
            };
        }
        let decided = match self.decided {
            Some(decided) => decided,
            None => {
                let decided = self.hooks.decide_restore();
                self.decided = Some(decided);
                decided
            }
        };
        crate::dispatch::RestoreOutcome {
            restore: decided.restore,
            person_input_during_fronting: decided.person_input_during_fronting,
            finished_at_ms: self.inner.now_ms(),
        }
    }
    fn create_tap(&mut self) -> Option<Self::Tap> {
        self.returned();
        self.inner.create_tap()
    }
    fn read_idle(&mut self) -> IdleReading {
        self.returned();
        self.inner.read_idle()
    }
    fn drain(&mut self, tap: &Self::Tap) -> Vec<crate::dispatch::SourcedInputEvent> {
        self.inner.drain(tap)
    }
    fn post_heartbeat(&mut self) -> crate::dispatch::HeartbeatProbe {
        self.returned();
        self.inner.post_heartbeat()
    }
    fn observe_heartbeat(
        &mut self,
        tap: &Self::Tap,
        probe: crate::dispatch::HeartbeatProbe,
        watcher: &mut crate::dispatch::SeizeWatcher,
    ) -> crate::dispatch::HeartbeatObservation {
        self.returned();
        self.inner.observe_heartbeat(tap, probe, watcher)
    }
    fn post_unit(
        &mut self,
        index: usize,
    ) -> Result<crate::dispatch::UnitPosted, SequencePostFailure> {
        self.returned();
        self.inner.post_unit(index)
    }
    fn post_observed_unit(
        &mut self,
        index: usize,
        observation: crate::dispatch::ObservedUnit<'_, Self::Tap>,
    ) -> Result<crate::dispatch::UnitPosted, SequencePostFailure> {
        self.returned();
        self.inner.post_observed_unit(index, observation)
    }
    fn finish_observation(
        &mut self,
        tap: &Self::Tap,
        estimator: &mut crate::dispatch::UserIdleEstimator,
        user_idle: IdleReading,
        idle_read_at: std::time::Instant,
    ) {
        self.inner
            .finish_observation(tap, estimator, user_idle, idle_read_at);
    }
    fn hardware_input_snapshot(&mut self) -> Option<crate::dispatch::HardwareInputSnapshot> {
        self.returned();
        self.inner.hardware_input_snapshot()
    }
}

/// Run a fronted dispatch (`read` is `None`) or a fronted image read, with
/// `hooks` owning the restore obligation. The caller must separately admit its
/// grant and review: app-use fronting and takeover pointer fronting share this
/// restore mechanism, not each other's permission.
///
/// The bracket runs as it does for any admitted caller, with two changes the
/// hooks make: the obligation is registered, and the front attempt started,
/// immediately before the one front request, so terminal cleanup that took
/// it first prevents the front; and the previous application is asked back
/// only by the hooks' restore decision, never by the bracket itself. The
/// returned outcome's restore is that decision. A post failure that may have
/// left a key held runs no decision: the outcome's `deferred_restore` is
/// left for the caller, which settles the held input first.
///
/// A registration refused, or a front cleanup prevented, ends the bracket as
/// cancelled with nothing restored, since nothing was fronted.
pub fn run_hooked_fronted<H: crate::dispatch::FrontingBracketHost + RestoreHostSource>(
    host: &mut H,
    estimator: &mut crate::dispatch::UserIdleEstimator,
    plan: crate::dispatch::BracketPlan,
    cancelled: &dyn Fn() -> bool,
    hooks: &mut dyn FrontedDispatchHooks,
    read: Option<&mut dyn FnMut()>,
) -> crate::dispatch::BracketOutcome {
    use crate::dispatch::{BracketStop, FrontingAdmission, RestoreStatus};
    let admission = FrontingAdmission {
        app_use_fronting_admitted: true,
    };
    let mut hooked = HookedHost {
        inner: host,
        hooks,
        target: plan.target_pid,
        previous: None,
        registration: Registration::NotYet,
        dispatching: false,
        decided: None,
    };
    let mut outcome = match read {
        None => crate::dispatch::run_fronting_bracket_with(
            &mut hooked,
            estimator,
            plan,
            admission,
            cancelled,
        ),
        Some(read) => crate::dispatch::run_fronting_read_with(
            &mut hooked,
            estimator,
            plan,
            admission,
            cancelled,
            read,
        ),
    };
    hooked.returned();
    match hooked.registration {
        Registration::NotYet => {}
        Registration::Refused | Registration::Registered { prevented: true } => {
            if let Registration::Registered { .. } = hooked.registration {
                if hooked.decided.is_none() {
                    hooked.decided = Some(hooked.hooks.decide_restore());
                }
            }
            outcome.report.restore = RestoreStatus::NotNeeded;
            outcome.report.stop = Some(BracketStop::Cancelled);
            outcome.deferred_restore = None;
        }
        Registration::Registered { prevented: false } => {
            if outcome.deferred_restore.is_none() {
                let decided = match hooked.decided {
                    Some(decided) => decided,
                    // The bracket made no restore request: it left the
                    // person where they switched to, or stopped without
                    // reaching its restore. The hooks decide either way.
                    None => hooked.hooks.decide_restore(),
                };
                outcome.report.restore = decided.restore;
                outcome.person_input_during_fronting |= decided.person_input_during_fronting;
            }
        }
    }
    hooked.hooks.finished(&outcome);
    outcome
}

/// A driver that performs nothing, for constructions that never legitimately
/// reach one.
///
/// This is the default synthetic driver a serving plane holds: capabilities
/// whose path never touches a driver (a screenshot, a wait) work with it, and
/// any construction that CAN dispatch synthetic input must name a real driver
/// instead. Every operation refuses by name rather than panicking, so an
/// accidental reach is an ordinary refusal instead of a crash.
#[derive(Debug, Default, Clone, Copy)]
pub struct UnsupportedPlatformDriver;

impl UnsupportedPlatformDriver {
    pub fn new() -> Self {
        Self
    }
}

impl PlatformDriver for UnsupportedPlatformDriver {
    fn capability_declarations(
        &self,
        _context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        Vec::new()
    }

    fn read_accessibility_tree(
        &mut self,
        _request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        Err(DriverError::Unsupported("accessibility tree read"))
    }

    fn resolve_element(
        &mut self,
        _request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        Err(DriverError::Unsupported("element resolution"))
    }

    fn dispatch_semantic(
        &mut self,
        _request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("semantic dispatch"))
    }

    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("per-process synthetic dispatch"))
    }

    fn dispatch_global(
        &mut self,
        _request: GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported("global synthetic dispatch"))
    }

    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        Err(DriverError::Unsupported("focus query"))
    }

    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported("fronting snapshot"))
    }

    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: false,
            raw_hid_live: false,
            self_echo_filter_live: false,
        }
    }

    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Err(DriverError::Unsupported("input observation"))
    }

    fn observe_effect(
        &mut self,
        _request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        Err(DriverError::Unsupported("effect observation"))
    }

    fn verify_attendance(
        &mut self,
        _request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        Err(DriverError::Unsupported("attendance verification"))
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
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        panic!("test driver must not execute platform operations")
    }

    fn dispatch_global(
        &mut self,
        _request: GlobalDispatchRequest,
        _cancelled: &dyn Fn() -> bool,
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
    /// A running instance whose start time cannot be read is not resolved --
    /// and it is not NOT RUNNING. It owns windows. The old answer here was
    /// NotRunning, which sends a person to start a second copy of an
    /// application already in front of them; the reason names the pid so the
    /// remedy can be about that process rather than about launching anything.
    #[test]
    fn an_instance_without_generation_evidence_is_unreadable_and_never_not_running() {
        let resolution = TargetResolution::decide("com.apple.Safari", Some(&windows()), |_| None);
        let TargetResolution::Unreadable(UnreadableReason::GenerationUnreadable { pid }) =
            resolution
        else {
            panic!("an unreadable generation must be Unreadable with its pid, got {resolution:?}");
        };
        assert_eq!(
            pid, 100,
            "the pid named is the one that owns Safari's windows"
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

        assert_eq!(
            resolution,
            TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable)
        );
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
        let advertised: Vec<_> = capability_declarations(&context, false)
            .into_iter()
            .filter(|declaration| declaration.advertised)
            .map(|declaration| declaration.capability_id)
            .collect();

        assert_eq!(advertised, vec!["computer.wait"]);
    }
}

#[cfg(test)]
mod hooked_fronted_tests {
    //! The hooked bracket on a fake desk: the hooks own the one front
    //! attempt and the one restore decision, and the bracket itself never
    //! asks for the previous application back.

    use super::*;
    use crate::dispatch::{
        BracketPlan, BracketStop, FrontingBracketHost, HardwareInputSnapshot, HeartbeatMarker,
        HeartbeatObservation, HeartbeatProbe, RestoreStatus, SeizeWatcher, SourcedInputEvent,
        UnitPosted, UserIdleEstimator, OBSERVED_DISPATCH_IDLE_MS,
    };
    use std::sync::{Arc, Mutex};

    const PREVIOUS: u32 = 100;
    const TARGET: u32 = 200;
    const OUR_PID: i64 = 7;

    #[derive(Default)]
    struct Screen {
        now: u64,
        frontmost: Option<u32>,
        /// Every front request, with who made it: the bracket's host or the
        /// restore host the hooks were given.
        requests: Vec<(&'static str, u32)>,
        /// Hook calls, in order.
        hooks: Vec<&'static str>,
        fail_post_holding_keys: bool,
    }

    type Shared = Arc<Mutex<Screen>>;

    struct Desk(Shared);

    struct Restorer(Shared);

    impl FrontingRestoreHost for Restorer {
        fn now_ms(&mut self) -> u64 {
            self.0.lock().unwrap().now
        }
        fn pause_ms(&mut self, milliseconds: u64) {
            self.0.lock().unwrap().now += milliseconds;
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            self.0.lock().unwrap().frontmost
        }
        fn request_front(&mut self, pid: u32) -> bool {
            let mut screen = self.0.lock().unwrap();
            screen.requests.push(("restore_host", pid));
            screen.frontmost = Some(pid);
            true
        }
        fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
            None
        }
    }

    impl RestoreHostSource for Desk {
        fn restore_host(&self) -> Box<dyn FrontingRestoreHost> {
            Box::new(Restorer(Arc::clone(&self.0)))
        }
    }

    impl FrontingBracketHost for Desk {
        type Tap = ();
        fn now_ms(&mut self) -> u64 {
            self.0.lock().unwrap().now
        }
        fn pause_ms(&mut self, milliseconds: u64) {
            self.0.lock().unwrap().now += milliseconds;
        }
        fn frontmost_pid(&mut self) -> Option<u32> {
            self.0.lock().unwrap().frontmost
        }
        fn request_front(&mut self, pid: u32) -> bool {
            let mut screen = self.0.lock().unwrap();
            screen.requests.push(("bracket", pid));
            screen.frontmost = Some(pid);
            true
        }
        fn our_pid(&self) -> i64 {
            OUR_PID
        }
        fn create_tap(&mut self) -> Option<()> {
            Some(())
        }
        fn read_idle(&mut self) -> IdleReading {
            IdleReading::Milliseconds(OBSERVED_DISPATCH_IDLE_MS + 500)
        }
        fn drain(&mut self, _tap: &()) -> Vec<SourcedInputEvent> {
            Vec::new()
        }
        fn post_heartbeat(&mut self) -> HeartbeatProbe {
            HeartbeatProbe {
                marker: HeartbeatMarker::new(1),
                posted_at_ms: self.now_ms(),
                our_pid: OUR_PID,
            }
        }
        fn observe_heartbeat(
            &mut self,
            _tap: &(),
            probe: HeartbeatProbe,
            _watcher: &mut SeizeWatcher,
        ) -> HeartbeatObservation {
            HeartbeatObservation::Seen {
                marker: probe.marker,
                source_unix_process_id: OUR_PID,
                observed_at_ms: probe.posted_at_ms,
            }
        }
        fn post_unit(&mut self, _index: usize) -> Result<UnitPosted, SequencePostFailure> {
            if self.0.lock().unwrap().fail_post_holding_keys {
                return Err(SequencePostFailure {
                    posts_returned: 1,
                    refusal: ProcessEventRefusal::Cancelled,
                    held_state: HeldStateDisposition::Unknown,
                });
            }
            Ok(UnitPosted {
                posts_returned: 2,
                generation_verifications: 4,
            })
        }
    }

    /// Hooks whose decision puts the previous application back through the
    /// restore host they were given, as the call's restore cell does.
    struct Hooks {
        screen: Shared,
        register: bool,
        begin: bool,
        host: Option<Box<dyn FrontingRestoreHost>>,
        previous: Option<u32>,
    }

    impl FrontedDispatchHooks for Hooks {
        fn register(
            &mut self,
            previous: u32,
            target: u32,
            host: Box<dyn FrontingRestoreHost>,
        ) -> bool {
            assert_eq!(target, TARGET);
            self.screen.lock().unwrap().hooks.push("register");
            self.previous = Some(previous);
            self.host = Some(host);
            self.register
        }
        fn begin_front_attempt(&mut self, _front_instant_ms: u64) -> bool {
            self.screen.lock().unwrap().hooks.push("begin");
            self.begin
        }
        fn front_attempt_returned(&mut self) {
            self.screen.lock().unwrap().hooks.push("returned");
        }
        fn decide_restore(&mut self) -> HookedRestore {
            self.screen.lock().unwrap().hooks.push("decide");
            if !self.begin {
                return HookedRestore {
                    restore: RestoreStatus::NotNeeded,
                    person_input_during_fronting: false,
                };
            }
            let host = self.host.as_mut().unwrap();
            host.request_front(self.previous.unwrap());
            HookedRestore {
                restore: RestoreStatus::Restored,
                person_input_during_fronting: false,
            }
        }
        fn finished(&mut self, _outcome: &crate::dispatch::BracketOutcome) {
            self.screen.lock().unwrap().hooks.push("finished");
        }
    }

    fn run(register: bool, begin: bool, fail: bool) -> (crate::dispatch::BracketOutcome, Shared) {
        let screen: Shared = Arc::new(Mutex::new(Screen {
            frontmost: Some(PREVIOUS),
            fail_post_holding_keys: fail,
            ..Screen::default()
        }));
        let mut hooks = Hooks {
            screen: Arc::clone(&screen),
            register,
            begin,
            host: None,
            previous: None,
        };
        let outcome = run_hooked_fronted(
            &mut Desk(Arc::clone(&screen)),
            &mut UserIdleEstimator::new(),
            BracketPlan {
                target_pid: TARGET,
                units: 1,
                maximum_interval_ms: 100,
                maximum_seize_detection_latency_ms: 50,
            },
            &|| false,
            &mut hooks,
            None,
        );
        (outcome, screen)
    }

    #[test]
    fn the_previous_application_is_asked_back_only_by_the_hooked_decision() {
        let (outcome, screen) = run(true, true, false);
        let screen = screen.lock().unwrap();
        assert_eq!(
            screen.requests,
            [("bracket", TARGET), ("restore_host", PREVIOUS)]
        );
        assert_eq!(
            screen.hooks,
            ["register", "begin", "returned", "decide", "finished"]
        );
        assert_eq!(outcome.report.restore, RestoreStatus::Restored);
        assert_eq!(outcome.report.stop, None);
        assert_eq!(outcome.report.units_posted, 1);
    }

    #[test]
    fn a_post_failure_with_keys_possibly_held_leaves_the_decision_to_the_caller() {
        let (outcome, screen) = run(true, true, true);
        let screen = screen.lock().unwrap();
        assert_eq!(screen.requests, [("bracket", TARGET)], "no restore request");
        assert!(!screen.hooks.contains(&"decide"), "{:?}", screen.hooks);
        assert!(outcome.deferred_restore.is_some());
    }

    #[test]
    fn cleanup_that_took_the_obligation_first_prevents_the_front() {
        let (outcome, screen) = run(true, false, false);
        let screen = screen.lock().unwrap();
        assert!(screen.requests.is_empty(), "{:?}", screen.requests);
        assert_eq!(screen.hooks, ["register", "begin", "decide", "finished"]);
        assert_eq!(outcome.report.restore, RestoreStatus::NotNeeded);
        assert_eq!(outcome.report.stop, Some(BracketStop::Cancelled));
        assert_eq!(outcome.report.units_posted, 0);
    }

    #[test]
    fn a_refused_registration_fronts_nothing_and_decides_nothing() {
        let (outcome, screen) = run(false, true, false);
        let screen = screen.lock().unwrap();
        assert!(screen.requests.is_empty(), "{:?}", screen.requests);
        assert_eq!(screen.hooks, ["register", "finished"]);
        assert_eq!(outcome.report.stop, Some(BracketStop::Cancelled));
        assert_eq!(outcome.report.units_posted, 0);
    }
}
