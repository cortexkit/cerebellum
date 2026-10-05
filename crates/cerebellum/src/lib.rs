//! ck-cerebellum library core — the subc wire seam, health-v2, identity,
//! principal default-deny, and the `browser.status` capability.
//!
//! The binary (`main.rs`) is a thin entry point that reads config from env and
//! calls [`run`]. The library exposes the module's internal handlers for
//! conformance tests.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod browser;
pub mod browser_config;
pub mod browser_crash_reports;
pub mod browser_executable_identity;
pub mod browser_launch;
pub mod browser_launch_readiness;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod browser_launch_service;
pub mod browser_session;
pub mod browser_standing_grants;
pub mod browser_type;
pub mod capability;
pub mod cdp;
pub mod classification;
pub mod computer_capability;
pub mod computer_grants;
pub mod connector_evidence;
mod consent_card;
#[cfg(test)]
mod content_named_fixture;
pub mod coordinate;
pub mod custody;
pub mod durable_formats;
pub mod elicit;
pub mod flat_tools;
pub mod journal;
pub mod journal_admin;
pub mod journal_pin;
mod launch_nonce;
pub mod launch_recovery;
pub mod login_capture;
pub mod login_import;
pub mod management;
pub mod manifest;
pub mod network;
pub mod profile;
pub mod profile_custody;
pub mod public_suffix;
pub mod scope_watch;
pub mod snapshot_store;
pub mod wire;

#[cfg(target_os = "macos")]
use std::collections::BTreeSet;
use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::json;
use serde_json::Value;

pub use cerebellum_computer as computer;

use crate::elicit::{Elicitor, SharedElicitor};
use crate::management::ManagementPlane;
use cerebellum_core::identity::RouteSurface;
use socket2::{SockRef, TcpKeepalive};
use subc_protocol::session::{
    ModuleControlRequest, ModuleControlResponse, MODULE_CONTROL_OP_HEALTH_CHECK,
};
use subc_protocol::{
    ErrorBody, Flags, Frame, FrameType, ModuleHelloAckBody, ModuleHelloBody, Priority,
    PROTOCOL_VERSION, SUBC_MODULE_ID_ENV,
};
use subc_transport::{authenticate_client, connection_file, read_frame, write_frame};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufWriter};
use tokio::net::TcpStream;
use tokio::sync::mpsc;

pub use browser::{BrowserCapability, BrowserPlane};
pub use browser_config::{BrowserConfig, BrowserConfigError};
pub use browser_type::{
    browser_type_dispatch_eligible, browser_type_eligibility, browser_type_geometry_eligible,
    browser_type_revalidation_eligible, BrowserTypeAuthorizer, BrowserTypeDriver,
    BrowserTypeExecutor, BrowserTypeJournal, BrowserTypeRequest, BrowserTypeResult,
    ClassificationFingerprint, ClassificationRecord, DeterministicTypeFixture,
    EligibilityPredicates, EvidenceEligibilityInput, FixtureMutation, FormDescendantClassification,
    JournalError, JournalEvent, RecordingAuthorizer, RecordingJournal, StaleReason,
    TypeDriverError, TypeGeometry, TypeTarget, BROWSER_EVIDENCE_ELIGIBILITY_SHA256,
};
pub use capability::{handle_browser_status, handle_browser_status_for_identity};
pub use cerebellum_core::config::{parse_config, Config, ConfigError, HealthConfig};
pub use cerebellum_core::health::HealthState;
pub use journal::core_adapter::{
    map_late_event_cause, map_recovery_action, map_recovery_classification,
    open_browser_core_journal, BrowserCoreJournal, BrowserJournalCodec,
    UnreachableBrowserLateEventCause,
};
// The observer lives behind a feature (not `cfg(test)`) because it now resides
// in the cerebellum-core dependency: a `test` build of this crate does not
// enable code in that dependency, so only the forwarded feature gates the seam.
#[cfg(feature = "test-observer")]
pub use cerebellum_core::identity::{take_test_observations, IdentityResolutionObservation};
pub use cerebellum_core::identity::{
    AcceptedBindFacts, LogicalProfileKey, ProfileDisposition, ProfileResolution, RouteIdentity,
    SessionKind,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserSurface {
    NotConfigured,
    Refused(BrowserConfigError),
    Available(BrowserConfig),
}
use cerebellum_core::principal::{
    principal_label, SESSION_CALLER_NOT_ADMITTED, SESSION_CALLER_NOT_ADMITTED_REMEDY,
};
pub use cerebellum_core::principal::{trust_for_principal, PrincipalTrust};
pub use wire::{build_error_frame, control_flags};

// Absorbs scheduling delay and the pipe handshake's own bounded steps.
const IN_FLIGHT_MARGIN_MS: u64 = 5_000;

fn derive_in_flight_age_stale_ms(browser: Option<&BrowserConfig>) -> u64 {
    let mut cap = computer_capability::MAX_WAIT_TIMEOUT_MS;
    if let Some(browser) = browser {
        cap = cap
            .max(browser.navigation_settle_deadline_ms)
            .max(browser.launch_handshake_deadline_ms)
            .max(
                browser
                    .termination_grace_period_ms
                    .saturating_add(browser.browser_exit_observation_deadline_ms),
            );
    }
    cap.saturating_add(IN_FLIGHT_MARGIN_MS)
}

const DEFAULT_MODULE_ID: &str = "cerebellum";
const HELLO_CORR: u64 = 1;
const EGRESS_BUFFER: usize = 64;
const TCP_KEEPALIVE_IDLE: Duration = Duration::from_secs(60);
const TCP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const TCP_KEEPALIVE_RETRIES: u32 = 4;

#[cfg(target_os = "macos")]
pub use computer::platform::StartupProbeInput;
pub use computer::platform::{
    CapabilityAdvertisementContext as ComputerCapabilityAdvertisementContext,
    CapabilityDeclaration as ComputerCapabilityDeclaration,
    ImmutableReleaseInputs as ComputerReleaseInputs, PermissionLiveness, PermissionLivenessReport,
    PermissionProbeResult, PermissionService, StartupCapabilityProbe,
};

/// A release gate outcome preserves the difference between an input that has not
/// been supplied and an implementation that failed a supplied compatibility
/// check.  Both outcomes suppress advertisement.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ComputerGateOutcome {
    Pass,
    MissingExternalInput { gate: String },
    ImplementationFailure { gate: String },
}

/// Release evidence records the fixed set of eight canonical computer
/// capability rows, while runtime advertisement and successfully exercised
/// behavior are counted independently.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerReleaseEvidence {
    pub frozen_row_count: usize,
    pub canonical_row_count: usize,
    pub advertised_row_count: usize,
    pub advertised_capabilities: Vec<String>,
    /// The capabilities the release gates admit, before requiring that the
    /// dispatcher can serve them.
    ///
    /// Advertisement is the conjunction of the two, so this is always a superset
    /// of `advertised_capabilities`. It is reported separately because the
    /// difference is the useful signal: a capability admitted here and missing
    /// there is one whose release inputs are complete and whose implementation
    /// is not, which is otherwise indistinguishable from a failed gate.
    pub gate_admitted_capabilities: Vec<String>,
    pub exercised_row_count: usize,
    pub functional_computer_plane: bool,
    pub scope: ComputerAdvertisementScope,
    pub gate_outcomes: Vec<ComputerGateOutcome>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComputerAdvertisementScope {
    AllFrozenRows,
    PartialRuntimeAdvertisement,
    EmptyRuntimeAdvertisement,
}

const COMPUTER_FROZEN_ROW_COUNT: usize = computer::platform::COMPUTER_CAPABILITY_ROW_IDS.len();
const COMPUTER_CAPABILITY_IDS: [&str; COMPUTER_FROZEN_ROW_COUNT] =
    computer::platform::COMPUTER_CAPABILITY_ROW_IDS;

type ComputerGateOutcomes = BTreeMap<&'static str, ComputerGateOutcome>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ComputerReleaseGateSource {
    External,
    VocabularyManifestDigest,
    VocabularySourceLockDigest,
    VocabularyComputedArtifactDigest,
    StruckSelfReferential { reason: &'static str },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ComputerReleaseGate {
    name: &'static str,
    source: ComputerReleaseGateSource,
}

/// Every release gate is listed here, including entries intentionally marked as
/// struck and excluded from evaluation because they lack independent evidence.
/// Keeping them in the table prevents a future change from restoring an
/// unsupported comparison.
const COMPUTER_RELEASE_GATE_TABLE: [ComputerReleaseGate; 22] = [
    ComputerReleaseGate {
        name: "vocabulary_manifest_digest",
        source: ComputerReleaseGateSource::VocabularyManifestDigest,
    },
    ComputerReleaseGate {
        name: "vocabulary_source_lock_digest",
        source: ComputerReleaseGateSource::VocabularySourceLockDigest,
    },
    ComputerReleaseGate {
        name: "vocabulary_computed_artifact_digest",
        source: ComputerReleaseGateSource::VocabularyComputedArtifactDigest,
    },
    ComputerReleaseGate {
        name: "attendance_contract_owner",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "attendance_contract_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "input_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "global_dispatch_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "capture_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "semantic_actuation_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "windows_actuation_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "app_state_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "element_addressed_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "takeover_dispatch_review_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "release_signing_topology_revision",
        source: ComputerReleaseGateSource::External,
    },
    ComputerReleaseGate {
        name: "computer_action_vocabulary_revision",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "The frozen artifact revision is independently validated by validate_vocabulary; this comparison only repeated an in-repository literal.",
        },
    },
    ComputerReleaseGate {
        name: "permission_matrix_revision",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
    ComputerReleaseGate {
        name: "capture_residual_leakage_revision",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
    ComputerReleaseGate {
        name: "process_identity_primitive_revision",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
    ComputerReleaseGate {
        name: "cerebellum_core_contract_revision",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
    ComputerReleaseGate {
        name: "c2_journal_pin_schema_id",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
    ComputerReleaseGate {
        name: "c2_journal_pin_revision",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
    ComputerReleaseGate {
        name: "attendance_contract_schema_id",
        source: ComputerReleaseGateSource::StruckSelfReferential {
            reason: "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing.",
        },
    },
];

fn pin_outcome(
    gate: &'static str,
    value: Option<&str>,
    expected: Option<&'static str>,
) -> ComputerGateOutcome {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return ComputerGateOutcome::MissingExternalInput {
            gate: gate.to_string(),
        };
    };
    if value.eq_ignore_ascii_case("placeholder")
        || value.eq_ignore_ascii_case("tbd")
        || value.eq_ignore_ascii_case("unknown")
    {
        return ComputerGateOutcome::ImplementationFailure {
            gate: gate.to_string(),
        };
    }
    if expected.is_some_and(|expected| value != expected) {
        return ComputerGateOutcome::ImplementationFailure {
            gate: gate.to_string(),
        };
    }
    ComputerGateOutcome::Pass
}

fn computer_gate_outcomes(
    context: &ComputerCapabilityAdvertisementContext,
) -> ComputerGateOutcomes {
    let inputs = &context.inputs;
    COMPUTER_RELEASE_GATE_TABLE
        .iter()
        .filter_map(|gate| {
            let outcome = match gate.source {
                ComputerReleaseGateSource::External => {
                    pin_outcome(gate.name, external_release_input(inputs, gate.name), None)
                }
                ComputerReleaseGateSource::VocabularyManifestDigest => pin_outcome(
                    gate.name,
                    inputs.vocabulary_digests.manifest_digest.as_deref(),
                    Some(computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256),
                ),
                ComputerReleaseGateSource::VocabularySourceLockDigest => pin_outcome(
                    gate.name,
                    inputs.vocabulary_digests.source_lock_digest.as_deref(),
                    Some(computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256),
                ),
                ComputerReleaseGateSource::VocabularyComputedArtifactDigest => pin_outcome(
                    gate.name,
                    inputs
                        .vocabulary_digests
                        .computed_artifact_digest
                        .as_deref(),
                    Some(computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256),
                ),
                ComputerReleaseGateSource::StruckSelfReferential { reason } => {
                    // The entry is kept as an auditable record, not evaluated as a
                    // release gate. Reading the reason here keeps the table's
                    // documentation coupled to the code that deliberately omits it.
                    let _ = reason;
                    return None;
                }
            };
            Some((gate.name, outcome))
        })
        .collect()
}

fn external_release_input<'a>(inputs: &'a ComputerReleaseInputs, gate: &str) -> Option<&'a str> {
    match gate {
        "attendance_contract_owner" => inputs.attendance_contract_owner.as_deref(),
        "attendance_contract_revision" => inputs.attendance_contract_revision.as_deref(),
        "input_review_revision" => inputs.input_review_revision.as_deref(),
        "global_dispatch_review_revision" => inputs.global_dispatch_review_revision.as_deref(),
        "capture_review_revision" => inputs.capture_review_revision.as_deref(),
        "semantic_actuation_review_revision" => {
            inputs.semantic_actuation_review_revision.as_deref()
        }
        "windows_actuation_review_revision" => inputs.windows_actuation_review_revision.as_deref(),
        "app_state_review_revision" => inputs.app_state_review_revision.as_deref(),
        "element_addressed_review_revision" => inputs.element_addressed_review_revision.as_deref(),
        "takeover_dispatch_review_revision" => inputs.takeover_dispatch_review_revision.as_deref(),
        "release_signing_topology_revision" => inputs.release_signing_topology_revision.as_deref(),
        _ => unreachable!("every external release gate has a bound input"),
    }
}

fn gate_passes(outcomes: &ComputerGateOutcomes, gate: &str) -> bool {
    matches!(outcomes.get(gate), Some(ComputerGateOutcome::Pass))
}

fn declaration_gate_passes(
    declaration: &ComputerCapabilityDeclaration,
    outcomes: &ComputerGateOutcomes,
) -> bool {
    let common = [
        "vocabulary_manifest_digest",
        "vocabulary_source_lock_digest",
        "vocabulary_computed_artifact_digest",
    ];
    if !common.iter().all(|gate| gate_passes(outcomes, gate)) {
        return false;
    }
    let id = declaration.capability_id.as_str();
    if matches!(
        id,
        "computer.read_state" | "computer.wait" | "computer.list_apps"
    ) {
        // Every read of application state is one reviewed surface: the state
        // tree with its element ids and image, the wait that polls that same
        // tree for a condition, and the list of running applications a
        // caller picks a target from. Keeping them under one key means a
        // single unbinding withdraws every read.
        // Signing topology is required as for every reviewed row, because
        // the accessibility grant it reads under is pinned to a stable
        // signature.
        [
            "app_state_review_revision",
            "release_signing_topology_revision",
        ]
        .iter()
        .all(|gate| gate_passes(outcomes, gate))
    } else if matches!(
        id,
        "computer.press_element" | "computer.press_point" | "computer.write_text"
    ) {
        // Pressing and writing through accessibility on retained elements,
        // and the hit test that finds an element under a point, are a
        // reviewed surface of their own, apart from reading the tree.
        [
            "element_addressed_review_revision",
            "release_signing_topology_revision",
        ]
        .iter()
        .all(|gate| gate_passes(outcomes, gate))
    } else if matches!(id, "computer.type" | "computer.keys") {
        [
            "attendance_contract_owner",
            "attendance_contract_revision",
            "input_review_revision",
            "release_signing_topology_revision",
        ]
        .iter()
        .all(|gate| gate_passes(outcomes, gate))
    } else if matches!(
        id,
        "computer.takeover_move" | "computer.takeover_drag" | "computer.takeover_scroll"
    ) {
        // The real-pointer rows need two reviews, and each is checked here
        // rather than trusted to the row's artifact: the row names only the
        // takeover review, while the global pointer stream they post through
        // stays under its own review of record.
        [
            "global_dispatch_review_revision",
            "takeover_dispatch_review_revision",
            "release_signing_topology_revision",
        ]
        .iter()
        .all(|gate| gate_passes(outcomes, gate))
    } else {
        // Every current row has its gate above; a row added without one is
        // never admitted.
        false
    }
}

fn canonical_declaration_is_complete(declarations: &[ComputerCapabilityDeclaration]) -> bool {
    declarations.len() == COMPUTER_FROZEN_ROW_COUNT
        && declarations
            .iter()
            .map(|declaration| declaration.capability_id.as_str())
            .eq(COMPUTER_CAPABILITY_IDS)
        && computer::platform::validate_vocabulary().is_ok()
}

/// The computer capabilities this module advertises.
///
/// Advertisement requires BOTH that the release gates pass AND that the
/// dispatcher can serve the capability. The second condition is not redundant:
/// the gates are satisfied by supplying release identifiers, which is a
/// configuration change, while the ability to serve a capability is a property
/// of the code -- so without this the identifiers alone would advertise
/// capabilities that every call to them rejects as an unknown method.
///
/// Deriving the advertised set from the dispatchable one, rather than comparing
/// the two afterwards, is what makes that state unauthorable instead of merely
/// detectable.
fn advertised_computer_declarations<'a>(
    declarations: &'a [ComputerCapabilityDeclaration],
    outcomes: &ComputerGateOutcomes,
) -> Vec<&'a ComputerCapabilityDeclaration> {
    gate_admitted_computer_declarations(declarations, outcomes)
        .into_iter()
        .filter(|declaration| dispatchable_tool(&declaration.capability_id).is_some())
        .collect()
}

/// The declarations the release gates admit, before the dispatchability
/// requirement is applied.
///
/// Kept separate from [`advertised_computer_declarations`] so that gate
/// behaviour -- which missing release identifier suppresses which capability --
/// stays observable independently of whether a capability can be served.
/// Collapsing the two would make an unserved capability indistinguishable from a
/// closed gate, and every gate would then look equally closed.
fn gate_admitted_computer_declarations<'a>(
    declarations: &'a [ComputerCapabilityDeclaration],
    outcomes: &ComputerGateOutcomes,
) -> Vec<&'a ComputerCapabilityDeclaration> {
    if !canonical_declaration_is_complete(declarations) {
        return Vec::new();
    }
    declarations
        .iter()
        .filter(|declaration| {
            declaration.advertised && declaration_gate_passes(declaration, outcomes)
        })
        .collect()
}

fn canonical_computer_declarations(
    context: &ComputerCapabilityAdvertisementContext,
) -> (Vec<ComputerCapabilityDeclaration>, ComputerGateOutcomes) {
    #[cfg(target_os = "windows")]
    let declarations = computer::platform::WindowsPlatformDriver::default().declarations(context);
    #[cfg(not(target_os = "windows"))]
    let declarations =
        computer::platform::capability_declarations(context, cfg!(target_os = "macos"));
    let outcomes = computer_gate_outcomes(context);
    (declarations, outcomes)
}

fn computer_tool(id: &str) -> Option<subc_protocol::manifest::Tool> {
    let artifact: Value =
        serde_json::from_slice(computer::platform::vocabulary::COMPUTER_ACTION_VOCABULARY_ARTIFACT)
            .ok()?;
    let row = artifact
        .get("rows")?
        .as_array()?
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(id))?;
    // The vocabulary no longer carries an action kind per row; the capability
    // states its own, once. An observing capability changes nothing and so
    // is pure; everything else may have effects nothing can fence.
    let observes = computer::audit::ComputerCapability::parse(id)?.action_kind()
        == computer::platform::ActionKind::Observe;
    let execution_mode = if observes {
        subc_protocol::manifest::ExecutionMode::Pure
    } else {
        subc_protocol::manifest::ExecutionMode::Unfenceable
    };
    // The scroll is the one takeover action a model could not work out the
    // grant of from its fields, so its description says so.
    let description = if id == "computer.takeover_scroll" {
        format!(
            "Computer-plane capability {id}. {}",
            flat_tools::TAKEOVER_SCROLL_NOTE
        )
    } else {
        format!("Computer-plane capability {id}.")
    };
    Some(subc_protocol::manifest::Tool {
        name: id.to_string(),
        description: Some(description),
        execution_mode,
        schema: row.get("request_schema")?.clone(),
    })
}

/// Build the typed module manifest using the standard computer capability
/// declarations and the compatibility checks that apply to the supplied context.
pub fn build_manifest_with_computer_plane(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
) -> subc_protocol::manifest::ModuleManifest {
    let mut manifest = manifest::build(module_id);
    let (declarations, outcomes) = canonical_computer_declarations(context);
    let subc_protocol::manifest::ProviderRole::ToolProvider { tools, .. } =
        &mut manifest.provides[0]
    else {
        return manifest;
    };
    let advertised = advertised_computer_declarations(&declarations, &outcomes);
    let admitted_names = advertised
        .iter()
        .map(|declaration| declaration.capability_id.clone())
        .collect::<Vec<_>>();
    for declaration in advertised {
        if let Some(tool) = computer_tool(&declaration.capability_id) {
            tools.push(tool);
        }
    }
    if let Some(tool) = flat_tools::computer_tool(&admitted_names) {
        tools.push(tool);
    }
    manifest
}

/// Produce release evidence for the runtime advertisement.  `exercised_rows`
/// is intentionally explicit: an advertisement alone is not evidence that a
/// functional computer action ran.
pub fn computer_release_evidence(
    context: &ComputerCapabilityAdvertisementContext,
) -> ComputerReleaseEvidence {
    computer_release_evidence_with_exercised_rows(context, 0)
}

pub fn computer_release_evidence_with_exercised_rows(
    context: &ComputerCapabilityAdvertisementContext,
    exercised_rows: usize,
) -> ComputerReleaseEvidence {
    let (declarations, gate_outcomes) = canonical_computer_declarations(context);
    let gate_admitted_capabilities: Vec<String> =
        gate_admitted_computer_declarations(&declarations, &gate_outcomes)
            .into_iter()
            .map(|declaration| declaration.capability_id.clone())
            .collect();
    let advertised_capabilities: Vec<String> =
        advertised_computer_declarations(&declarations, &gate_outcomes)
            .into_iter()
            .map(|declaration| declaration.capability_id.clone())
            .collect();
    let canonical_row_count = declarations.len();
    let advertised_row_count = advertised_capabilities.len();
    let scope = if advertised_row_count == COMPUTER_FROZEN_ROW_COUNT {
        ComputerAdvertisementScope::AllFrozenRows
    } else if advertised_row_count == 0 {
        ComputerAdvertisementScope::EmptyRuntimeAdvertisement
    } else {
        ComputerAdvertisementScope::PartialRuntimeAdvertisement
    };
    ComputerReleaseEvidence {
        frozen_row_count: COMPUTER_FROZEN_ROW_COUNT,
        canonical_row_count,
        advertised_row_count,
        advertised_capabilities,
        gate_admitted_capabilities,
        exercised_row_count: exercised_rows.min(advertised_row_count),
        functional_computer_plane: exercised_rows > 0 && advertised_row_count > 0,
        scope,
        gate_outcomes: gate_outcomes.into_values().collect(),
    }
}

/// Serialize the ordinary manifest plus a separate, machine-readable computer
/// release evidence extension.  The extension distinguishes the frozen scope
/// from what this process actually advertises.
pub fn serialize_manifest_with_computer_plane(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
) -> Value {
    serialize_manifest_with_computer_plane_configured(
        module_id,
        context,
        &BrowserSurface::NotConfigured,
    )
}

pub fn serialize_manifest_with_browser_configuration(
    module_id: &str,
    browser_surface: &BrowserSurface,
) -> Value {
    serialize_manifest_with_computer_plane_configured(
        module_id,
        &default_computer_context(),
        browser_surface,
    )
}

fn serialize_manifest_with_computer_plane_configured(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
    browser_surface: &BrowserSurface,
) -> Value {
    let browser_configured = matches!(browser_surface, BrowserSurface::Available(_));
    let mut manifest = build_manifest_with_computer_plane(module_id, context);
    if browser_configured {
        let subc_protocol::manifest::ProviderRole::ToolProvider { tools, .. } =
            &mut manifest.provides[0]
        else {
            return serde_json::to_value(manifest).expect("module manifest serializes");
        };
        let browser_tools = manifest::browser_control_tools()
            .into_iter()
            .chain(manifest::browser_wire_tools())
            .filter(|tool| dispatchable_tool_with_browser(&tool.name, true).is_some())
            .collect::<Vec<_>>();
        let admitted_names = browser_tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect::<Vec<_>>();
        tools.extend(browser_tools);
        if let Some(tool) = flat_tools::browser_tool(&admitted_names) {
            tools.push(tool);
        }
    }
    let mut value = serde_json::to_value(manifest).expect("module manifest serializes");
    // WHO CAN SEE THIS: a person, not the daemon.
    //
    // `ModuleManifestWire` -- the type subc deserializes a HELLO manifest into
    // -- is deliberately permissive, so a module built against a newer protocol
    // can still register with an older daemon. The cost of that tolerance is
    // that an unknown key is DROPPED RATHER THAN RETAINED: this field is
    // neither rejected nor stored, and nothing in subconscious reads it.
    //
    // So it is real for an operator reading `--manifest` output or a wire dump,
    // and invisible to the supervisor. Do not build a decision on the daemon
    // having seen it. When a daemon-side consumer exists, this becomes a typed
    // optional field in subc-protocol landed with that consumer -- which is the
    // path `provenance` took, after spending months produced and unread.
    value
        .as_object_mut()
        .expect("module manifest is an object")
        .insert(
            "computer_plane_release".to_string(),
            serde_json::to_value(computer_release_evidence(context))
                .expect("computer release evidence serializes"),
        );
    // Separates a refused browser surface from one that was never configured. Both
    // advertise no browser tools, so the absence of those tools cannot on its own
    // tell a broken pin from a build that has no browser support.
    //
    // The audience for this key is whoever reads the serialized manifest: an operator,
    // a wire dump, `--manifest` output. It is NOT the daemon. `ModuleManifestWire`
    // declares no matching field and no `deny_unknown_fields`, so an extra top-level
    // key is dropped at the parse boundary -- neither rejected nor retained. The
    // adjacent `computer_plane_release` key has the same property.
    //
    // Routing does not depend on it either way: no advertised browser tools already
    // means do not route, which is the correct outcome for both states. Anything that
    // needs this distinction daemon-side needs a typed field in subc-protocol, not
    // another key here.
    if let BrowserSurface::Refused(error) = browser_surface {
        let mut refusal = json!({
            "field": error.field,
            "reason_code": error.reason.reason_code(),
        });
        if let Some(detail) = error.reason.detail() {
            refusal
                .as_object_mut()
                .expect("browser refusal disclosure is an object")
                .insert("detail".to_string(), Value::String(detail.to_string()));
        }
        value
            .as_object_mut()
            .expect("module manifest is an object")
            .insert("browser_surface_refused".to_string(), refusal);
    }
    value
}

/// The tool names this module can actually serve, or `None` for a name it
/// cannot.
///
/// Named rather than inlined at the dispatch site so that the manifest can be
/// checked against it. Advertising a tool this rejects would offer the caller a
/// capability that fails as an unknown method, which is indistinguishable from
/// the module not having it at all -- except that the caller was told otherwise.
pub fn dispatchable_tool(name: &str) -> Option<&str> {
    dispatchable_tool_with_browser(name, false)
}

/// Whether the management dispatcher has an explicit arm for this operation.
pub fn dispatchable_management_operation(name: &str) -> bool {
    matches!(
        name,
        management::OPEN_TARGET
            | management::WOULD_ASK
            | management::LIST_APP_GRANTS
            | management::REVOKE_APP_GRANT
            | management::OPEN_GRANT
            | management::IMPORT_LOGIN
            | management::REBIND_PROFILE_ROOT
            | management::CAPTURE_LOGIN
            | management::CLEAR_LAUNCH_RECOVERY
            | management::REVOKE_ACCESS
            | management::REVOKE_GRANT
            | management::LIST_GRANTS
    ) || (matches!(name, management::PRESENT | management::RESUME)
        && browser::has_wire_dispatch_route(name))
}

/// The operator's own management operations: the ones served to a caller that
/// is not admitted to act in a conversation, and served to it outside any
/// conversation.
///
/// Each works on state that belongs to the machine or the operator rather than
/// to a conversation: the browser profile root, a browser launch record that
/// module startup kept because it could not prove that browser gone, and the
/// durable "always allow" app grants. None of them
/// needs a conversation's grants, so running them with no conversation costs
/// the operator nothing. Every other operation asks for, reads or acts under a
/// conversation's permissions, and is a session-bound call.
fn is_operator_operation(name: &str) -> bool {
    matches!(
        name,
        management::REBIND_PROFILE_ROOT
            | management::CLEAR_LAUNCH_RECOVERY
            | management::LIST_APP_GRANTS
            | management::REVOKE_APP_GRANT
            | management::REVOKE_GRANT
            | management::LIST_GRANTS
    )
}

/// The request fields of the standing-grant operations, checked in one
/// place: `Err` names the field and the reason code of the refusal.
mod standing_grant_params {
    use serde_json::{Map, Value};

    pub(super) type Refusal = (&'static str, &'static str);

    /// Refuse any field outside `allowed`, naming the first in sorted order.
    pub(super) fn only(params: &Map<String, Value>, allowed: &[&str]) -> Result<(), String> {
        match params
            .keys()
            .filter(|field| !allowed.contains(&field.as_str()))
            .min()
        {
            Some(field) => Err(field.clone()),
            None => Ok(()),
        }
    }

    /// An optional canonical origin a standing row could name.
    pub(super) fn origin(params: &Map<String, Value>) -> Result<Option<String>, Refusal> {
        match params.get("origin") {
            None => Ok(None),
            Some(Value::String(origin)) => {
                if crate::classification::canonical_grant_origin(origin).as_deref()
                    == Some(origin.as_str())
                {
                    Ok(Some(origin.clone()))
                } else {
                    Err(("origin", "invalid_origin"))
                }
            }
            Some(_) => Err(("origin", "wrong_type")),
        }
    }

    pub(super) fn domain(params: &Map<String, Value>) -> Result<Option<String>, Refusal> {
        match params.get("domain") {
            None => Ok(None),
            Some(Value::String(domain))
                if crate::browser_standing_grants::domain_scope(&format!("https://{domain}"))
                    .as_deref()
                    == Some(domain.as_str()) =>
            {
                Ok(Some(domain.clone()))
            }
            Some(Value::String(_)) => Err(("domain", "invalid_domain")),
            Some(_) => Err(("domain", "wrong_type")),
        }
    }

    /// The required, nonempty `agent_id` an operator names.
    pub(super) fn agent_id(params: &Map<String, Value>) -> Result<String, Refusal> {
        match params.get("agent_id") {
            Some(Value::String(agent)) if !agent.is_empty() => Ok(agent.clone()),
            Some(Value::String(_)) => Err(("agent_id", "empty_value")),
            Some(_) => Err(("agent_id", "wrong_type")),
            None => Err(("agent_id", "missing_field")),
        }
    }
}

/// The dispatch predicate, exposed so a test can compare the surface reporter
/// against it directly rather than against a copy of its rules.
pub fn dispatchable_tool_for_test(name: &str, browser_configured: bool) -> Option<&str> {
    dispatchable_tool_with_browser(name, browser_configured)
}

/// Every browser tool name this build would advertise, and whether a caller
/// could reach it, read through the same predicate `send_hello` filters on.
///
/// Exists because the reachable set is not obvious from any single file: a
/// capability can be implemented, tested against a real browser, and still
/// answer `unknown_method` because one predicate does not name it. Reading it
/// back from the production path is the only honest answer, and asking a person
/// to derive it from three files is how a wrong belief about it survives.
///
/// Reports rather than decides: it adds no capability and grants no authority.
pub fn browser_wire_surface(browser_configured: bool) -> Vec<(String, bool)> {
    manifest::browser_control_tools()
        .into_iter()
        .chain(manifest::browser_wire_tools())
        .map(|tool| {
            let reachable =
                dispatchable_tool_with_browser(&tool.name, browser_configured).is_some();
            (tool.name.clone(), reachable)
        })
        .collect()
}

/// Why a capability this module knows about cannot be served here.
///
/// A caller who names a capability we withhold and a caller who names something
/// invented get the same `unknown_method` today, and those need different next
/// actions: one should stop asking, the other should change something. Naming
/// which is the same rule the browser refusals already follow -- a refusal that
/// does not say what to do next costs a caller a support round trip to learn
/// something this module already knew.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapabilityWithheld {
    /// This build has no such capability. Nothing the caller changes helps.
    Unknown,
    /// A browser capability on a host with no browser configured.
    BrowserNotConfigured,
    /// Implemented, deliberately not admitted to the wire in this version.
    ///
    /// Distinct from [`Self::Unknown`] because the capability exists and its
    /// absence is a decision rather than a gap -- a caller who hears "unknown"
    /// may reasonably file a bug asking for something we built on purpose and
    /// withheld on purpose.
    NotAdmitted,
}

impl CapabilityWithheld {
    /// The wire reason code. Stable strings: callers branch on these.
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::Unknown => "unknown_method",
            Self::BrowserNotConfigured => "browser_not_configured",
            Self::NotAdmitted => "capability_not_admitted",
        }
    }

    /// What the caller should do, in the caller's own terms.
    pub const fn remedy(self) -> &'static str {
        match self {
            Self::Unknown => "this module does not provide that capability",
            Self::BrowserNotConfigured => {
                "configure browser.executable_path and browser.expected_identity in \
                 cerebellum.jsonc, then restart this module"
            }
            Self::NotAdmitted => {
                "this capability exists but is not served in this version; do not retry"
            }
        }
    }
}

/// Why a named capability is not dispatchable, for a caller that named one.
///
/// Returns `None` for a capability that IS dispatchable. Reads through the same
/// predicate dispatch uses rather than a second list, so the two cannot disagree
/// about what is served.
pub fn capability_withheld(name: &str, browser_configured: bool) -> Option<CapabilityWithheld> {
    if dispatchable_tool_with_browser(name, browser_configured).is_some() {
        return None;
    }
    let known_browser_name = browser_session::CONTROL_TOOLS.contains(&name)
        || browser::ALL_TOOLS.contains(&name)
        || name == flat_tools::BROWSER_USE
        || name == crate::browser_type::BROWSER_TYPE_TOOL;
    if !known_browser_name {
        // A current vocabulary row this build does not serve is withheld on
        // purpose; a retired computer capability, like any invented name, is
        // not something this module has at all.
        if computer::audit::ComputerCapability::parse(name).is_some() {
            return Some(CapabilityWithheld::NotAdmitted);
        }
        return Some(CapabilityWithheld::Unknown);
    }
    // A known browser name that would be dispatchable with a browser configured
    // is withheld by the HOST; one that would still be refused is withheld by
    // this VERSION. Asking the predicate rather than listing the admitted names
    // keeps this from becoming a third copy of that list.
    if !browser_configured && dispatchable_tool_with_browser(name, true).is_some() {
        Some(CapabilityWithheld::BrowserNotConfigured)
    } else {
        Some(CapabilityWithheld::NotAdmitted)
    }
}

fn dispatchable_tool_with_browser(name: &str, browser_configured: bool) -> Option<&str> {
    if browser_configured
        && (name == flat_tools::BROWSER_USE
            || browser_session::CONTROL_TOOLS.contains(&name)
            || (browser::BrowserCapability::parse(name).is_some()
                && browser::has_wire_dispatch_route(name)))
    {
        Some(name)
    } else if name == flat_tools::COMPUTER_USE || computer_capability::servable(name).is_some() {
        // A computer capability is dispatchable when this module can serve it,
        // which is a property of the code rather than of the host. Whether it is
        // ADVERTISED depends further on the audit gate and on this being macOS;
        // those are checked where the manifest is built, so a host that cannot
        // serve one never offers it.
        Some(name)
    } else {
        None
    }
}

/// What this system reports about the permissions the computer plane needs, and
/// which process it attributes them to.
///
/// Empty where there is nothing to ask. An empty reading resolves every service
/// to unknown rather than to denied, which is the honest answer: a host that
/// cannot be asked has not refused.
/// The probe thread panicked before reporting. Distinct from an empty reading
/// because the two mean different things to whoever reads the manifest: an
/// empty reading describes grants nobody could see, a panic describes a fault
/// in this module. Substituting an empty reading here would send an operator
/// to System Settings to fix a crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PermissionProbePanicked;

#[cfg(target_os = "macos")]
fn computer_permission_readings(
) -> Result<(Vec<PermissionProbeResult>, Option<String>), PermissionProbePanicked> {
    // Taken on a background thread, because a reading from the main thread is
    // discarded: the main thread of this process runs the module's event loop,
    // and what it can do is not evidence about the threads that will actually
    // perform captures. Probing here rather than on the startup thread is what
    // makes the reading count -- a probe taken on the main thread reports a
    // granted permission and the policy resolves it to unknown, so the plane
    // would advertise nothing on a machine where capture works.
    //
    // Joined immediately: this runs once at startup, and the answer is needed
    // before the manifest can be built.
    //
    // NO TEST HERE CAN CATCH THE REMOVAL OF THIS THREAD, which is why it must
    // not be read as ceremony. The test harness runs every test on a thread of
    // its own -- including under --test-threads=1 -- so a reading taken on the
    // caller's thread is already off-main and the policy accepts it either way.
    // The case arises only in the real binary, where startup runs on the main
    // thread: there, without this thread, the raw reading says granted and the
    // resolved liveness is unknown, so nothing is advertised.
    std::thread::spawn(|| {
        (
            computer::platform::native::probe_permissions(),
            computer::platform::native::responsible_process(),
        )
    })
    .join()
    .map_err(|_| PermissionProbePanicked)
}

#[cfg(not(target_os = "macos"))]
fn computer_permission_readings(
) -> Result<(Vec<PermissionProbeResult>, Option<String>), PermissionProbePanicked> {
    Ok((Vec::new(), None))
}

/// Collect the release attestations supplied to the compiler and derive the
/// vocabulary mirrors from their independent checked-in sources.
///
/// The eleven external identifiers use `option_env!` so a release invocation must
/// supply each attestation before compilation. Starting a binary with a new
/// environment value cannot manufacture a review after the binary was built.
fn compiled_release_inputs() -> ComputerReleaseInputs {
    let semantic_actuation_review_revision =
        option_env!("CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION");
    let windows_actuation_review_revision =
        option_env!("CEREBELLUM_WINDOWS_ACTUATION_REVIEW_REVISION");
    let app_state_review_revision = option_env!("CEREBELLUM_APP_STATE_REVIEW_REVISION");
    let element_addressed_review_revision =
        option_env!("CEREBELLUM_ELEMENT_ADDRESSED_REVIEW_REVISION");
    let takeover_dispatch_review_revision =
        option_env!("CEREBELLUM_TAKEOVER_DISPATCH_REVIEW_REVISION");
    let release_signing_topology_revision =
        option_env!("CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION");
    release_inputs_from_build_bindings(BuildReleaseBindings {
        attendance_contract_owner: option_env!("CEREBELLUM_ATTENDANCE_CONTRACT_OWNER"),
        attendance_contract_revision: option_env!("CEREBELLUM_ATTENDANCE_CONTRACT_REVISION"),
        input_review_revision: option_env!("CEREBELLUM_INPUT_REVIEW_REVISION"),
        global_dispatch_review_revision: option_env!("CEREBELLUM_GLOBAL_DISPATCH_REVIEW_REVISION"),
        capture_review_revision: option_env!("CEREBELLUM_CAPTURE_REVIEW_REVISION"),
        semantic_actuation_review_revision,
        windows_actuation_review_revision,
        app_state_review_revision,
        element_addressed_review_revision,
        takeover_dispatch_review_revision,
        release_signing_topology_revision,
    })
}

struct BuildReleaseBindings<'a> {
    attendance_contract_owner: Option<&'a str>,
    attendance_contract_revision: Option<&'a str>,
    input_review_revision: Option<&'a str>,
    global_dispatch_review_revision: Option<&'a str>,
    capture_review_revision: Option<&'a str>,
    semantic_actuation_review_revision: Option<&'a str>,
    windows_actuation_review_revision: Option<&'a str>,
    app_state_review_revision: Option<&'a str>,
    element_addressed_review_revision: Option<&'a str>,
    takeover_dispatch_review_revision: Option<&'a str>,
    release_signing_topology_revision: Option<&'a str>,
}

fn release_inputs_from_build_bindings(bindings: BuildReleaseBindings<'_>) -> ComputerReleaseInputs {
    let computed_vocabulary_digest = computer::platform::computed_vocabulary_sha256();
    ComputerReleaseInputs {
        attendance_contract_owner: bindings.attendance_contract_owner.map(str::to_owned),
        attendance_contract_revision: bindings.attendance_contract_revision.map(str::to_owned),
        input_review_revision: bindings.input_review_revision.map(str::to_owned),
        global_dispatch_review_revision: bindings
            .global_dispatch_review_revision
            .map(str::to_owned),
        capture_review_revision: bindings.capture_review_revision.map(str::to_owned),
        semantic_actuation_review_revision: bindings
            .semantic_actuation_review_revision
            .map(str::to_owned),
        windows_actuation_review_revision: bindings
            .windows_actuation_review_revision
            .map(str::to_owned),
        app_state_review_revision: bindings.app_state_review_revision.map(str::to_owned),
        element_addressed_review_revision: bindings
            .element_addressed_review_revision
            .map(str::to_owned),
        takeover_dispatch_review_revision: bindings
            .takeover_dispatch_review_revision
            .map(str::to_owned),
        release_signing_topology_revision: bindings
            .release_signing_topology_revision
            .map(str::to_owned),
        vocabulary_digests: computer::platform::VocabularyDigestInputs {
            // The manifest and computed-artifact mirrors are recalculated from
            // the frozen vocabulary, while the source-lock digest comes from its
            // separate checked-in file. Each is compared with its expected digest.
            manifest_digest: Some(computed_vocabulary_digest.clone()),
            source_lock_digest: computer::platform::implementation_source_lock_digest(),
            computed_artifact_digest: Some(computed_vocabulary_digest),
        },
    }
}

/// The computer-plane advertisement context used when sending HELLO.
///
/// Public so that a test can check the manifest this module really sends,
/// rather than one assembled to look like it.
///
/// The permission state is read from the system here rather than supplied,
/// because a capability is advertised on the strength of a grant and a grant
/// that is merely assumed is not one. The readings are cheap queries -- no
/// capture is performed, so this does not pay the first-capture cost that
/// contends with other processes.
pub fn default_computer_context() -> ComputerCapabilityAdvertisementContext {
    let readings = computer_permission_readings();
    let probe_panicked = readings.is_err();
    // A panicked probe contributes no readings; the report below is then
    // replaced wholesale so every service names the crash rather than an
    // absent grant.
    let (permission_results, responsible_process) = readings.unwrap_or((Vec::new(), None));
    #[cfg(not(target_os = "macos"))]
    let _ = responsible_process;
    #[cfg(target_os = "macos")]
    let mut startup = StartupCapabilityProbe::run(&StartupProbeInput {
        os_major: computer::platform::MACOS_MAJOR_VERSION,
        private_envelope_revision: None,
        resolved_private_symbols: BTreeSet::new(),
        permission_results,
        responsible_process,
    });
    #[cfg(not(target_os = "macos"))]
    let mut startup = StartupCapabilityProbe {
        permissions: PermissionLivenessReport::from_results(permission_results),
        ..Default::default()
    };
    if probe_panicked {
        startup.permissions = PermissionLivenessReport::probe_failed();
    }
    ComputerCapabilityAdvertisementContext {
        inputs: compiled_release_inputs(),
        permissions: startup.permissions.clone(),
        startup,
    }
}

/// Accepted bind facts retained for the lifetime of a route.
///
/// This is an in-memory route table, not a profile registry or storage layer.
/// It lets data-plane frames inherit the identity and effective scope that the
/// daemon accepted on `route.bind`.
#[derive(Clone, Default)]
pub struct RouteBindings {
    inner: Arc<RwLock<HashMap<(u16, u32), AcceptedBindFacts>>>,
    removed: Arc<tokio::sync::Notify>,
}

impl RouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, channel: u16, epoch: u32, facts: AcceptedBindFacts) {
        if let Ok(mut routes) = self.inner.write() {
            routes.insert((channel, epoch), facts);
        }
    }

    fn get(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        self.inner
            .read()
            .ok()
            .and_then(|routes| routes.get(&(channel, epoch)).cloned())
    }

    /// Return the facts recorded when this route was bound, unchanged.
    #[doc(hidden)]
    pub fn accepted_bind_for_test(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        self.get(channel, epoch)
    }

    fn remove(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        let facts = self
            .inner
            .write()
            .ok()
            .and_then(|mut routes| routes.remove(&(channel, epoch)));
        self.removed.notify_waiters();
        facts
    }

    async fn closed(&self, channel: u16, epoch: u32) {
        loop {
            let removed = self.removed.notified();
            tokio::pin!(removed);
            // Subscribe before checking so an unbind between the check and the
            // wait cannot leave a detached grant question alive on a dead route.
            removed.as_mut().enable();
            if self.get(channel, epoch).is_none() {
                return;
            }
            removed.await;
        }
    }

    /// Whether any bound route carries this conversation. Two routes may carry
    /// one conversation, so a conversation ends only when its last route does.
    fn carries_conversation(&self, conversation_key: &str) -> bool {
        self.inner.read().ok().is_some_and(|routes| {
            routes
                .values()
                .any(|facts| facts.identity.conversation_key == conversation_key)
        })
    }

    /// Whether any bound route was stamped with this session scope.
    fn carries_scope(&self, key: &scope_watch::ScopeKey) -> bool {
        !self.conversations_under_scope(key).is_empty()
    }

    /// The conversations of the bound routes stamped with this session scope.
    fn conversations_under_scope(
        &self,
        key: &scope_watch::ScopeKey,
    ) -> std::collections::BTreeSet<String> {
        self.inner
            .read()
            .map(|routes| {
                routes
                    .values()
                    .filter(|facts| facts.scope.as_ref().is_some_and(|stamp| key.names(stamp)))
                    .map(|facts| facts.identity.conversation_key.clone())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Watch one session scope whose route closed until the daemon says, one way
/// or the other, whether it ended. Runs on its own task, never on the frame
/// loop, and is the only watcher of its scope (see
/// [`scope_watch::ScopeRevocation::note_closed`]).
///
/// Only a definitive end ends anything (see [`scope_watch::classify`]). While
/// the answer is unresolved everything stays, and the scope is asked about
/// again when another route under it closes, or once per
/// [`scope_watch::SCOPE_RECHECK_INTERVAL`], but only while a
/// browser it opened is still open and no route under it is bound: a bound
/// route asks again itself when it closes, and with no browser open nothing is
/// running that a late end would have to stop.
async fn watch_scope(planes: Planes, writer: mpsc::Sender<Frame>, key: scope_watch::ScopeKey) {
    let mut drain = planes.drain_signal.subscribe();
    let closed_again = planes.scopes.closed_again(&key);
    loop {
        let answer = planes.scopes.describe(&writer, &key).await;
        if scope_watch::classify(answer.as_ref(), key.scope_epoch)
            == scope_watch::ScopeVerdict::Ended
        {
            let mut conversations = planes.scopes.finish(&key);
            // A route under the scope whose close has not reached this module
            // yet belongs to the ended session too.
            conversations.extend(planes.routes.conversations_under_scope(&key));
            revoke_scope(&planes, &conversations).await;
            return;
        }
        let browser_open = planes
            .scopes
            .conversations(&key)
            .iter()
            .any(|conversation_key| planes.sessions.has_open_session(conversation_key));
        if !browser_open || planes.routes.carries_scope(&key) {
            planes.scopes.finish(&key);
            return;
        }
        tokio::select! {
            _ = tokio::time::sleep(planes.scopes.recheck_interval) => {}
            // Another route under the scope closed: ask about it now.
            _ = closed_again.notified() => {}
            // A draining module closes every browser itself.
            _ = drain.wait_for(|draining| *draining) => {
                planes.scopes.finish(&key);
                return;
            }
        }
    }
}

/// Check a stamped `route.bind` against the highest epoch seen for its
/// session's `(owner, ref)`, before the route is bound and so before anything
/// is served on it. Returns whether the bind may go on to ordinary admission.
///
/// - A higher epoch than any seen means every lower one ended, as a `live`
///   answer at a higher epoch would say. The ended epochs' conversations lose
///   their browser grants, their "this conversation" app and takeover grants
///   and their open questions here, before this returns, so the new session
///   can never be served under what a person allowed the old one. Their
///   browsers are marked `scope_revoked` here too, so no call is admitted on
///   them, and the bounded teardown finishes on the blocking pool without
///   holding up the bind's reply.
/// - A lower epoch than one seen is an ended session: refused `scope_ended`,
///   the daemon's own code for an epoch that is not the live one, and never
///   bound.
///
/// Anything that is not a stamped bind passes untouched.
async fn scope_epoch_admits_bind(
    frame: &Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<bool, ModuleError> {
    let Ok(ModuleControlRequest::RouteBind {
        identity,
        scope: Some(stamp),
        ..
    }) = serde_json::from_slice::<ModuleControlRequest>(&frame.body)
    else {
        return Ok(true);
    };
    match planes.scopes.note_bind(&stamp, &identity.session) {
        scope_watch::BindEpoch::Current => Ok(true),
        scope_watch::BindEpoch::Advanced {
            ended_conversations,
        } => {
            for conversation_key in &ended_conversations {
                planes
                    .management
                    .end_browser_conversation(conversation_key)
                    .await;
                planes.management.end_conversation(conversation_key);
                cancel_conversation_cards(planes, conversation_key).await;
                if let Some(config) = planes.browser_config.as_ref() {
                    if let Some(finish) = planes.sessions.begin_teardown_route(
                        conversation_key,
                        browser_session::BrowserSessionTerminalOutcome::ScopeRevoked,
                        config,
                    ) {
                        tokio::task::spawn_blocking(finish);
                    }
                }
            }
            Ok(true)
        }
        scope_watch::BindEpoch::Stale { current } => {
            let refusal = build_error_frame(
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                "scope_ended",
                &format!(
                    "scope epoch {} has ended: epoch {current} of the same session scope has \
                     already been bound here",
                    stamp.scope_epoch
                ),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            send(writer, refusal).await?;
            Ok(false)
        }
    }
}

async fn cancel_conversation_cards(planes: &Planes, conversation_key: &str) {
    planes
        .elicitor
        .cancel_where(|channel, epoch| {
            planes
                .routes
                .get(channel, epoch)
                .is_some_and(|facts| facts.identity.conversation_key == conversation_key)
        })
        .await;
}

/// End what a session scope that definitively ended was allowed, for each
/// conversation its routes carried: the browser grant questions and the
/// computer consent questions it has open (so a late answer grants nothing),
/// its browser origin grants and "this conversation" app and takeover grants,
/// and its browser, closed as `scope_revoked`.
///
/// The questions and grants go first, so an answer landing while the browser
/// closes finds nothing to grant. The browser goes through the same bounded
/// close as any other teardown: in-flight operations get the configured grace,
/// and a kill happens only under the existing kill rules.
async fn revoke_scope(planes: &Planes, conversations: &std::collections::BTreeSet<String>) {
    for conversation_key in conversations {
        planes
            .management
            .end_browser_conversation(conversation_key)
            .await;
        planes.management.end_conversation(conversation_key);
        cancel_conversation_cards(planes, conversation_key).await;
        if let Some(config) = planes.browser_config.clone() {
            let sessions = planes.sessions.clone();
            let conversation_key = conversation_key.clone();
            // The teardown waits for in-flight work within its grace, so it
            // runs on the blocking pool.
            let _ = tokio::task::spawn_blocking(move || {
                sessions.teardown_route(
                    &conversation_key,
                    browser_session::BrowserSessionTerminalOutcome::ScopeRevoked,
                    &config,
                )
            })
            .await;
        }
    }
}

/// The route one computer call arrived on, as the call's consent wait sees it.
struct BoundRoute {
    routes: Arc<RouteBindings>,
    channel: u16,
    epoch: u32,
    conversation_key: String,
}

impl computer_grants::RouteLiveness for BoundRoute {
    fn route_open(&self) -> bool {
        self.routes.get(self.channel, self.epoch).is_some()
    }
    fn conversation_open(&self) -> bool {
        self.routes.carries_conversation(&self.conversation_key)
    }
}

/// Puts a consent question to the person on the other end of one route.
struct RouteCarrier {
    elicitor: SharedElicitor,
    writer: mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
}

impl computer_grants::QuestionCarrier for RouteCarrier {
    fn put(
        &self,
        question: Value,
        deadline: Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = elicit::AskOutcome> + Send>> {
        let elicitor = Arc::clone(&self.elicitor);
        let writer = self.writer.clone();
        let (channel, epoch) = (self.channel, self.epoch);
        Box::pin(async move {
            elicitor
                .ask(&writer, channel, epoch, question, deadline)
                .await
        })
    }
}

/// What a login call on this route needs to ask the person and wait: the
/// route's carrier, and the request's in-flight guard to park while it waits.
/// Called only once the route was checked to declare elicitation.
fn login_consent_request(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    (channel, epoch): (u16, u32),
    capability: computer_grants::LoginCapability,
    parameters: String,
) -> computer_grants::LoginConsentRequest {
    computer_grants::LoginConsentRequest {
        conversation_key: facts.identity.conversation_key.clone(),
        capability,
        parameters,
        carrier: Arc::new(RouteCarrier {
            elicitor: Arc::clone(&planes.elicitor),
            writer: writer.clone(),
            channel,
            epoch,
        }),
        park_guard: elicit::ROUTE_GUARD.try_with(Arc::clone).ok(),
    }
}

#[cfg(test)]
tokio::task_local! {
    static COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST: Duration;
}

/// Everything a computer call on this route needs to ask for a grant and wait.
///
/// The identity is the route's accepted bind, never the request body. The
/// request's in-flight guard is taken from the task scope the frame loop
/// spawned it under, so the wait is parked out of the busy gauge.
fn consent_context(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
) -> computer_grants::ConsentContext {
    let carrier: Option<Arc<dyn computer_grants::QuestionCarrier>> =
        facts.declares_elicitation().then(|| {
            Arc::new(RouteCarrier {
                elicitor: Arc::clone(&planes.elicitor),
                writer: writer.clone(),
                channel,
                epoch,
            }) as Arc<dyn computer_grants::QuestionCarrier>
        });
    let mut context = computer_grants::ConsentContext::new(
        computer_grants::GrantCaller {
            conversation_key: facts.identity.conversation_key.clone(),
            agent_project_id: facts.identity.agent_project_id.clone(),
            durable_identity_attested: facts.agent_project_id_attested
                && facts.session_kind_attested
                && facts.acts_as_agent,
        },
        carrier,
        Arc::new(BoundRoute {
            routes: Arc::clone(&planes.routes),
            channel,
            epoch,
            conversation_key: facts.identity.conversation_key.clone(),
        }),
        planes.drain_signal.subscribe(),
        elicit::ROUTE_GUARD.try_with(Arc::clone).ok(),
    );
    #[cfg(test)]
    if let Ok(limit) = COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST.try_with(|limit| *limit) {
        context.park_limit = limit;
    }
    context.unattended = facts.flow_id.is_some();
    if context.unattended {
        context.caller.conversation_key.clear();
    }
    context
}

/// The binary entry point: read config from env, load the health config
/// file, and run the module loop. Exposed publicly so the thin `main.rs`
/// binary can delegate here.
///
/// It also decides how the process ends: a SIGTERM ending does not return at
/// all, because the process re-raises the signal once teardown has finished.
pub async fn run_entry() -> Result<(), ModuleError> {
    // First, before anything can spawn a process: loading the browser
    // configuration can already run a browser probe, and a child started
    // before this read would inherit the launch-nonce pipe.
    launch_nonce::read_before_any_spawn();
    let config = ModuleConfig::from_env()?;
    conclude(run(config, |_| {}).await)
}

/// [`run_entry`] with the configuration supplied here instead of read from the
/// environment, and `prepare` applied to the planes before the module wires its
/// launch service. The ending is decided by the same code as in production.
///
/// For child-process tests, which need a running module that owns sessions to
/// tear down without launching real browsers.
#[doc(hidden)]
pub async fn run_entry_prepared_for_test(
    connection_file_path: PathBuf,
    browser: BrowserConfig,
    prepare: impl FnOnce(&mut Planes),
) -> Result<(), ModuleError> {
    let config = ModuleConfig {
        connection_file_path,
        module_id: DEFAULT_MODULE_ID.into(),
        health: HealthConfig::default(),
        browser: BrowserSurface::Available(browser),
    };
    conclude(run(config, prepare).await)
}

/// How a module run ended, which decides how the process exits.
enum ModuleEnding {
    /// The daemon connection ended (or could not be made). The process exits
    /// 0 for a clean end and 1 for an error, as it always has.
    Disconnected(Result<(), ModuleError>),
    /// SIGTERM arrived, and the shutdown teardown has finished.
    #[cfg(unix)]
    Terminated,
}

fn conclude(ending: ModuleEnding) -> Result<(), ModuleError> {
    match ending {
        ModuleEnding::Disconnected(result) => result,
        #[cfg(unix)]
        ModuleEnding::Terminated => die_by_sigterm(),
    }
}

/// End the process by SIGTERM with the default disposition, after the handler
/// has done the teardown.
///
/// Exiting 0 instead would tell the supervisor that the module stopped on
/// purpose, and a supervisor does not respawn a module that stopped on purpose.
/// Dying by the signal it was sent is what an unhandled SIGTERM looks like to
/// the parent, so the supervisor makes the same decision it would have made
/// without a handler. Only the SIGTERM ending comes here; the end of the daemon
/// connection still exits 0.
#[cfg(unix)]
fn die_by_sigterm() -> Result<(), ModuleError> {
    match signal_hook::low_level::emulate_default_handler(signal_hook::consts::SIGTERM) {
        // Not expected to return: the default action of SIGTERM ends the
        // process. Reported as an error so the exit is at least non-zero.
        Ok(()) => Err(ModuleError::Message(
            "SIGTERM was re-raised with its default action but the process survived".into(),
        )),
        Err(error) => Err(ModuleError::Message(format!(
            "re-raising SIGTERM failed: {error}"
        ))),
    }
}

/// The module's one shutdown teardown, reachable from every way it can end.
///
/// The first caller starts it on a blocking thread, and every caller, the first
/// included, then waits for that same run to finish. It is never started twice,
/// and a caller that stops waiting (its future dropped) does not stop it.
#[derive(Clone)]
struct ShutdownTeardown(Arc<ShutdownTeardownState>);

struct ShutdownTeardownState {
    sessions: browser_session::BrowserSessions,
    browser: Option<BrowserConfig>,
    idle_enforcer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    started: std::sync::atomic::AtomicBool,
    finished: tokio::sync::watch::Sender<bool>,
}

/// Marks the teardown finished when dropped, so a teardown that panicked still
/// releases everyone waiting for it rather than leaving them parked forever.
struct MarkTeardownFinished(Arc<ShutdownTeardownState>);

impl Drop for MarkTeardownFinished {
    fn drop(&mut self) {
        self.0.finished.send_replace(true);
    }
}

impl ShutdownTeardown {
    fn new(
        sessions: browser_session::BrowserSessions,
        browser: Option<BrowserConfig>,
        idle_enforcer: Option<tokio::task::JoinHandle<()>>,
    ) -> Self {
        let (finished, _) = tokio::sync::watch::channel(false);
        Self(Arc::new(ShutdownTeardownState {
            sessions,
            browser,
            idle_enforcer: std::sync::Mutex::new(idle_enforcer),
            started: std::sync::atomic::AtomicBool::new(false),
            finished,
        }))
    }

    async fn run_or_join(&self) {
        let mut finished = self.0.finished.subscribe();
        if !self
            .0
            .started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            let enforcer = self
                .0
                .idle_enforcer
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take();
            if let Some(enforcer) = enforcer {
                enforcer.abort();
            }
            let state = Arc::clone(&self.0);
            // On a blocking thread because the teardown waits on browser
            // processes, and the runtime must stay free to notice SIGTERM
            // while it does.
            tokio::task::spawn_blocking(move || {
                let finished = MarkTeardownFinished(state);
                if let Some(browser) = &finished.0.browser {
                    finished.0.sessions.teardown_all(browser);
                }
            });
        }
        // The sender lives as long as `self`, so this only returns once the
        // teardown has finished.
        let _ = finished.wait_for(|done| *done).await;
    }
}

struct ModuleConfig {
    connection_file_path: PathBuf,
    module_id: String,
    health: HealthConfig,
    browser: BrowserSurface,
}

impl ModuleConfig {
    fn from_env() -> Result<Self, ModuleError> {
        let connection_file_path = parse_subc_arg(std::env::args_os().skip(1))?;
        let module_id = std::env::var(SUBC_MODULE_ID_ENV)
            .ok()
            .filter(|v| !v.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
        // Load the health config file at boot. A missing file uses defaults;
        // a present-but-malformed file fails registration deterministically
        // rather than silently falling back (Spec A: zero, negative,
        // fractional, non-numeric, and unknown-member values are
        // configuration errors).
        let parsed = cerebellum_core::config::load_config_file().map_err(ModuleError::Config)?;
        let browser = match browser_config::load_browser_config_file() {
            Ok(None) => BrowserSurface::NotConfigured,
            Ok(Some(browser)) => match browser_config::validate_browser_config_at_load(&browser) {
                Ok(()) => BrowserSurface::Available(browser),
                Err(error) => BrowserSurface::Refused(error),
            },
            Err(error) => BrowserSurface::Refused(error),
        };
        Ok(Self {
            connection_file_path,
            module_id,
            health: parsed.health,
            browser,
        })
    }
}

async fn run(config: ModuleConfig, prepare: impl FnOnce(&mut Planes)) -> ModuleEnding {
    // Listening starts before the connection is made, so a SIGTERM that
    // arrives while connecting is held until the module can act on it rather
    // than ending the process with no teardown.
    #[cfg(unix)]
    let mut sigterm = listen_for_sigterm();
    let stream = match connect_to_subc(&config.connection_file_path).await {
        Ok(stream) => stream,
        Err(error) => return ModuleEnding::Disconnected(Err(error)),
    };
    let (mut read_half, write_half) = tokio::io::split(stream);

    let mut health_config = config.health;
    health_config.in_flight_age_stale_ms = derive_in_flight_age_stale_ms(match &config.browser {
        BrowserSurface::Available(browser) => Some(browser),
        _ => None,
    });
    let health_state = Arc::new(HealthState::with_config(health_config));
    let browser_config = match &config.browser {
        BrowserSurface::Available(browser) => Some(browser.clone()),
        BrowserSurface::NotConfigured | BrowserSurface::Refused(_) => None,
    };
    let mut planes = Planes::with_browser_config(Arc::clone(&health_state), browser_config.clone());
    // Captures deposit into the vault over a connection of their own, opened
    // with the same connection file as this one. Set before `prepare`, so a
    // test can put its own vault in its place.
    planes
        .capture
        .set_vault(Arc::new(login_capture::vault::ClaustrumVault::supervised(
            config.connection_file_path.clone(),
            config.module_id.clone(),
        )));
    prepare(&mut planes);
    // Recovery publishes the service before module_loop takes the transport, so
    // an attested orphan from a previous process cannot race a fresh spawn. That
    // ordering matters on every platform that can launch, not only the first one
    // that could.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    if planes.launch_service.is_none() {
        if let Some(browser) = browser_config.clone() {
            // Startup recovery belongs before `module_loop`: once that loop owns
            // the transport it can serve launch requests, so publishing the
            // production service any later would let a fresh spawn race an
            // attested orphan from the previous module process.
            let service = Arc::new(
                browser_launch_service::ProductionLaunchService::open_publishing(
                    browser,
                    JournalPersistence::Durable,
                    &planes.management.launch_recovery_registry(),
                ),
            );
            planes.capture.set_launcher(service.clone());
            planes.launch_service =
                Some(service as Arc<dyn browser_session::BrowserSessionLauncher>);
        }
    }
    // After launch recovery has terminated any capture browser a previous
    // module process left running, remove the profiles it left.
    planes.capture.sweep_at_startup();
    let idle_enforcer = browser_config.clone().map(|browser| {
        let sessions = planes.sessions.clone();
        let clock = Arc::clone(&planes.lease_clock);
        tokio::spawn(async move {
            let period = Duration::from_millis(
                browser
                    .browser_idle_timeout_ms
                    .min(browser.browser_exit_observation_deadline_ms)
                    .min(50),
            );
            loop {
                tokio::time::sleep(period).await;
                let sessions = sessions.clone();
                let clock = Arc::clone(&clock);
                let browser = browser.clone();
                let _ = tokio::task::spawn_blocking(move || {
                    sessions.observe_exits_all(&browser);
                    sessions.expire_all(clock.as_ref(), &browser);
                })
                .await;
            }
        })
    });
    let teardown = ShutdownTeardown::new(
        planes.sessions.clone(),
        browser_config.clone(),
        idle_enforcer,
    );
    let serving = serve_then_tear_down(&mut read_half, write_half, &config, planes, &teardown);
    #[cfg(unix)]
    let ending = end_on_disconnect_or_sigterm(serving, sigterm.as_mut(), &teardown).await;
    #[cfg(not(unix))]
    let ending = ModuleEnding::Disconnected(serving.await);
    ending
}

/// Set when the SIGTERM listener could not be installed, and read by the
/// health reply as `sigtermListener`. A counter rather than a print because the
/// module writes nothing to its standard streams: the daemon keeps them in a
/// backed-up file whose constant size is how printing is detected.
static SIGTERM_LISTENER_FAILED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(unix)]
fn listen_for_sigterm() -> Option<tokio::signal::unix::Signal> {
    listen_for_sigterm_with(|| {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    })
}

/// [`listen_for_sigterm`] with the installation supplied, so a test can drive
/// the failure branch.
#[cfg(unix)]
fn listen_for_sigterm_with(
    install: impl FnOnce() -> std::io::Result<tokio::signal::unix::Signal>,
) -> Option<tokio::signal::unix::Signal> {
    match install() {
        Ok(listener) => Some(listener),
        Err(_) => {
            // Without a listener SIGTERM keeps its default action: the module
            // still dies by the signal, just without its teardown, which is
            // how it behaved before it listened at all.
            SIGTERM_LISTENER_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
            None
        }
    }
}

/// The health reply's `sigtermListener`: `not_installed` only when installing
/// the listener failed. The listener is installed before the module connects,
/// so no health request can arrive before the attempt.
#[cfg(unix)]
fn sigterm_listener_state() -> &'static str {
    if SIGTERM_LISTENER_FAILED.load(std::sync::atomic::Ordering::Relaxed) {
        "not_installed"
    } else {
        "installed"
    }
}

/// There is no SIGTERM to listen for off unix, so no listener is ever
/// installed; `not_supported` says why rather than implying a failure.
#[cfg(not(unix))]
fn sigterm_listener_state() -> &'static str {
    let _ = &SIGTERM_LISTENER_FAILED;
    "not_supported"
}

/// Serve until the daemon connection ends or SIGTERM arrives, whichever is
/// first, and run the shutdown teardown either way.
///
/// On SIGTERM the connection future is dropped, which stops serving. A teardown
/// that the connection ending had already started keeps running on its own
/// thread and is joined here, never started a second time.
#[cfg(unix)]
async fn end_on_disconnect_or_sigterm(
    serving: impl std::future::Future<Output = Result<(), ModuleError>>,
    sigterm: Option<&mut tokio::signal::unix::Signal>,
    teardown: &ShutdownTeardown,
) -> ModuleEnding {
    let Some(sigterm) = sigterm else {
        return ModuleEnding::Disconnected(serving.await);
    };
    tokio::select! {
        biased;
        Some(()) = sigterm.recv() => {
            teardown.run_or_join().await;
            ModuleEnding::Terminated
        }
        result = serving => {
            // A SIGTERM that landed as the connection finished still decides
            // the ending: the sender asked for a death by signal.
            let terminated = tokio::select! {
                biased;
                Some(()) = sigterm.recv() => true,
                () = std::future::ready(()) => false,
            };
            if terminated {
                ModuleEnding::Terminated
            } else {
                ModuleEnding::Disconnected(result)
            }
        }
    }
}

/// Serve the daemon connection and, once it ends for any reason, close every
/// browser session before returning.
///
/// The daemon does not send a GOODBYE or a drain when it is cut (a
/// `launchctl bootout` kills it with no handler); a module learns by EOF. The
/// graceful stop therefore also runs on connection ending, even without a
/// drain notice. Sessions are torn down before the result is reported.
///
/// `run` builds its teardown itself, because SIGTERM must be able to join it,
/// and calls [`serve_then_tear_down`] directly; this wrapper is what the
/// in-process connection tests drive, and it runs that same function.
#[cfg(test)]
async fn serve_until_disconnect<R, W>(
    read_half: &mut R,
    write_half: W,
    config: &ModuleConfig,
    planes: Planes,
    browser_config: Option<&BrowserConfig>,
    idle_enforcer: Option<tokio::task::JoinHandle<()>>,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let teardown = ShutdownTeardown::new(
        planes.sessions.clone(),
        browser_config.cloned(),
        idle_enforcer,
    );
    serve_then_tear_down(read_half, write_half, config, planes, &teardown).await
}

/// The connection-ending half of [`serve_until_disconnect`], sharing its
/// teardown with whatever else can end the module.
async fn serve_then_tear_down<R, W>(
    read_half: &mut R,
    write_half: W,
    config: &ModuleConfig,
    planes: Planes,
    teardown: &ShutdownTeardown,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let consent_shutdown = ConsentShutdown(Arc::clone(&planes.drain_signal));
    let connection_result = run_connection(read_half, write_half, config, planes).await;
    drop(consent_shutdown);
    teardown.run_or_join().await;
    connection_result
}

/// Release consent waits even when SIGTERM drops the connection future.
struct ConsentShutdown(Arc<tokio::sync::watch::Sender<bool>>);

impl Drop for ConsentShutdown {
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

async fn connect_to_subc(connection_file_path: &PathBuf) -> Result<TcpStream, ModuleError> {
    let conn = connection_file::read(connection_file_path)
        .map_err(|e| ModuleError::Message(format!("reading connection file: {e}")))?;
    let endpoint = conn
        .endpoints
        .first()
        .ok_or_else(|| ModuleError::Message("connection file has no endpoints".into()))?;
    let addr = format!("{}:{}", endpoint.host, endpoint.port);
    let mut stream = TcpStream::connect(&addr)
        .await
        .map_err(|e| ModuleError::Message(format!("connect {addr}: {e}")))?;
    configure_tcp_keepalive(&stream)?;
    authenticate_client(&mut stream, &conn, std::time::Duration::from_secs(5))
        .await
        .map_err(|e| ModuleError::Message(format!("authenticate: {e}")))?;
    Ok(stream)
}

/// Enable keepalive soon enough to detect an idle peer that disappears without
/// sending FIN or RST. A healthy idle connection sends at most one probe after
/// each quiet minute; only an unresponsive peer incurs four retries at 15-second
/// intervals, bounding detection to roughly two minutes without waking a laptop
/// every few seconds. The kernel's multi-hour defaults are too slow for a module
/// whose supervisor can restart it as soon as the dead connection is reported.
fn configure_tcp_keepalive(stream: &TcpStream) -> Result<(), ModuleError> {
    let socket = SockRef::from(stream);
    let requested = TcpKeepalive::new()
        .with_time(TCP_KEEPALIVE_IDLE)
        .with_interval(TCP_KEEPALIVE_INTERVAL)
        .with_retries(TCP_KEEPALIVE_RETRIES);
    socket
        .set_tcp_keepalive(&requested)
        .map_err(|e| ModuleError::Message(format!("set TCP keepalive: {e}")))?;

    let enabled = socket
        .keepalive()
        .map_err(|e| ModuleError::Message(format!("read TCP keepalive enabled state: {e}")))?;
    // Read back what the platform will let us read back.
    //
    // The setter reporting success is not the same as the timings being in
    // force, and this keepalive is what notices a subc socket that died without
    // FIN or RST -- so a silently unapplied setting parks the module forever on
    // a dead connection. Unix exposes every knob it accepts, so every knob is
    // verified there.
    //
    // Windows accepts the same settings and exposes no per-knob getter, so the
    // timings there are set and unverified. That gap is stated rather than
    // hidden: reporting it as verified would be the more dangerous silence,
    // because the failure it guards against is invisible by construction.
    #[cfg(unix)]
    {
        let idle = socket
            .tcp_keepalive_time()
            .map_err(|e| ModuleError::Message(format!("read TCP keepalive idle time: {e}")))?;
        let interval = socket
            .tcp_keepalive_interval()
            .map_err(|e| ModuleError::Message(format!("read TCP keepalive interval: {e}")))?;
        let retries = socket
            .tcp_keepalive_retries()
            .map_err(|e| ModuleError::Message(format!("read TCP keepalive retry count: {e}")))?;
        if idle != TCP_KEEPALIVE_IDLE
            || interval != TCP_KEEPALIVE_INTERVAL
            || retries != TCP_KEEPALIVE_RETRIES
        {
            return Err(ModuleError::Message(format!(
                "TCP keepalive was not applied: idle={idle:?}, interval={interval:?}, retries={retries}"
            )));
        }
    }

    // Verified on every platform: whether keepalive is on at all. This is the
    // half that decides whether the socket is probed, and socket2 exposes it
    // everywhere, so no platform accepts the setting unchecked.
    if !enabled {
        return Err(ModuleError::Message(
            "TCP keepalive was not applied: the socket reports it disabled after being set".into(),
        ));
    }

    Ok(())
}

type WriterTaskResult = Result<Result<(), ModuleError>, ModuleError>;

fn normalize_writer_task_result(
    result: Result<Result<(), ModuleError>, tokio::task::JoinError>,
) -> WriterTaskResult {
    result.map_err(|e| ModuleError::Message(e.to_string()))
}

fn reconcile_connection_results(
    loop_result: Result<(), ModuleError>,
    writer_result: WriterTaskResult,
) -> Result<(), ModuleError> {
    match (loop_result, writer_result) {
        (Err(loop_err), _) => Err(loop_err),
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Ok(()), Ok(Err(writer_err))) => Err(ModuleError::Message(writer_err.to_string())),
        (Ok(()), Err(join_err)) => Err(join_err),
    }
}

fn report_writer_first(writer_result: WriterTaskResult) -> Result<(), ModuleError> {
    match writer_result {
        Ok(Ok(())) => Err(ModuleError::Message(
            "writer task exited while the connection loop was still active".into(),
        )),
        failed => reconcile_connection_results(Ok(()), failed),
    }
}

async fn run_connection<R, W>(
    read_half: &mut R,
    write_half: W,
    config: &ModuleConfig,
    planes: Planes,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let mut writer = tokio::spawn(drain_writer(write_half, rx));
    let mut loop_task = Box::pin(module_loop(read_half, tx.clone(), config, planes));

    let loop_result = tokio::select! {
        // Preserve the existing diagnostic precedence when both sides become
        // ready together: a concrete loop error is more specific than the
        // writer shutdown it can induce.
        biased;
        loop_result = &mut loop_task => loop_result,
        writer_result = &mut writer => {
            return report_writer_first(normalize_writer_task_result(writer_result));
        }
    };

    drop(loop_task);
    drop(tx);
    let writer_result = normalize_writer_task_result(writer.await);
    reconcile_connection_results(loop_result, writer_result)
}

/// Derive the bounded idle-wake cadence from the configured heartbeat stale
/// threshold. The wake fires at half the threshold (floored at 1 ms) so the
/// idle loop always re-stamps the heartbeat at least once well inside the
/// threshold, even if a wake is slightly delayed; idle therefore never trips a
/// false Degraded. The 1 ms floor avoids a zero-duration busy loop if a
/// deployment configures a 1 ms threshold. No new configuration knob is
/// introduced: the cadence simply tracks the existing stale threshold.
fn idle_wake_period(heartbeat_threshold: Duration) -> Duration {
    (heartbeat_threshold / 2).max(Duration::from_millis(1))
}

/// A source of bounded idle wake-ups for the dispatch loop. Each call returns a
/// fresh future that resolves when the next idle heartbeat re-stamp is due.
/// Production uses a fixed-period tokio timer ([`PeriodicIdleWake`]); tests
/// drive it deterministically.
trait IdleWake {
    fn next_wake(&mut self)
        -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>>;
}

/// Production idle wake: resolves every `period` on the tokio timer.
struct PeriodicIdleWake {
    period: Duration,
}

impl IdleWake for PeriodicIdleWake {
    fn next_wake(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(tokio::time::sleep(self.period))
    }
}

async fn module_loop<R>(
    read_half: &mut R,
    writer: mpsc::Sender<Frame>,
    config: &ModuleConfig,
    planes: Planes,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
{
    send_hello(&writer, config).await?;
    expect_hello_ack(read_half).await?;

    let mut idle_wake = PeriodicIdleWake {
        period: idle_wake_period(config.health.heartbeat_threshold()),
    };
    // Stamp and age the heartbeat with the SAME clock the insulated health lane
    // uses internally, so stamped instants and computed ages share one epoch.
    let clock = planes.health.clock().clone();

    let handler_planes = planes.clone();
    let handler = move |frame: Frame| {
        let writer = writer.clone();
        let planes = handler_planes.clone();
        async move { handle_frame(frame, &writer, &planes).await }
    };

    run_dispatch_loop(read_half, &planes.health, &clock, &mut idle_wake, handler).await
}

/// The bounded-idle-wake dispatch loop.
///
/// The heartbeat means "the dispatch loop is responsive", NOT "a frame arrived
/// recently". A frame-driven-only stamp would make every idle module self-report
/// a Degraded false positive once it sits idle longer than the stale threshold
/// (a log-noise lie under `on_degraded:Report`, an idle restart loop under
/// `on_degraded:Restart`). To keep an idle-but-healthy module Ok, the loop
/// re-stamps the heartbeat on a bounded idle wake while it is parked waiting for
/// the next frame.
///
/// Two asymmetries are load-bearing for Health-Path-Rule-v2 honesty:
///
/// 1. The idle wake wraps ONLY the `read_frame` await — never the handler.
///    Waiting for input is healthy, so it re-stamps. A handler that wedges the
///    loop leaves it parked past the read with no re-stamp, so the heartbeat
///    ages out and the module honestly reports Degraded. Re-stamping around the
///    handler would mask a real dispatch impairment.
///
/// 2. The read future is PINNED and re-polled across wakes — never dropped and
///    recreated (as `tokio::time::timeout(read_frame(..))` would). `read_frame`
///    performs `read_exact`-style reads and is not cancellation-safe: dropping it
///    partway through a frame loses the already-consumed bytes and the next read
///    mis-frames the stream. Re-polling the same pinned future preserves
///    partial-read state across idle wakes; a fresh read future is created only
///    when a frame actually completes.
async fn run_dispatch_loop<R, C, W, H, Fut>(
    read_half: &mut R,
    health_state: &Arc<HealthState>,
    clock: &C,
    idle_wake: &mut W,
    mut handler: H,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    C: cerebellum_core::clock::MonotonicClock,
    W: IdleWake,
    H: FnMut(Frame) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ModuleError>>,
{
    // Stamp the initial heartbeat so a freshly-started module reports healthy.
    health_state.stamp_heartbeat_with_clock(clock);

    loop {
        health_state.stamp_heartbeat_with_clock(clock);
        // Pin the read future once; it is re-polled across idle wakes below and
        // dropped only when a frame completes (see the function-level comment).
        let mut read = std::pin::pin!(read_frame(read_half));
        let frame = loop {
            let wake = idle_wake.next_wake();
            tokio::select! {
                // `biased` polls the read first so an available frame is always
                // processed before an idle re-stamp (a wake never pre-empts a
                // ready frame), and so the wake/frame ordering is deterministic.
                biased;
                result = &mut read => {
                    let Some(frame) =
                        result.map_err(|e| ModuleError::Message(e.to_string()))?
                    else {
                        return Ok(()); // clean EOF: subc closed the connection.
                    };
                    break frame;
                }
                _ = wake => {
                    // Bounded idle wake: still waiting for input (healthy), so
                    // re-stamp and keep awaiting the SAME pinned read.
                    health_state.stamp_heartbeat_with_clock(clock);
                }
            }
        };
        // The handler runs OUTSIDE the idle-wake select on purpose: a wedged
        // handler gets no re-stamp here, so it honestly goes stale (Degraded).
        if !handler(frame).await? {
            return Ok(());
        }
    }
}

async fn drain_writer<W>(write_half: W, mut rx: mpsc::Receiver<Frame>) -> Result<(), ModuleError>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = BufWriter::new(write_half);
    while let Some(frame) = rx.recv().await {
        write_frame(&mut writer, &frame)
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
        while let Ok(frame) = rx.try_recv() {
            write_frame(&mut writer, &frame)
                .await
                .map_err(|e| ModuleError::Message(e.to_string()))?;
        }
        writer
            .flush()
            .await
            .map_err(|e| ModuleError::Message(e.to_string()))?;
    }
    writer
        .flush()
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    Ok(())
}

async fn send_hello(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfig,
) -> Result<(), ModuleError> {
    let mut body = serde_json::to_value(ModuleHelloBody {
        manifest: manifest::build(&config.module_id),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            "route.status".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: launch_nonce::for_hello().map_err(|error| {
            ModuleError::Message(format!("cannot read the launch nonce: {error}"))
        })?,
    })
    .map_err(ModuleError::Json)?;
    body["manifest"] = serialize_manifest_with_computer_plane_configured(
        &config.module_id,
        &default_computer_context(),
        &config.browser,
    );
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn expect_hello_ack<R>(reader: &mut R) -> Result<ModuleHelloAckBody, ModuleError>
where
    R: AsyncRead + Unpin,
{
    let frame = read_frame(reader)
        .await
        .map_err(|e| ModuleError::Message(e.to_string()))?
        .ok_or_else(|| ModuleError::Message("connection closed before HELLO_ACK".into()))?;
    match frame.header.ty {
        FrameType::HelloAck => serde_json::from_slice(&frame.body).map_err(ModuleError::Json),
        FrameType::Error => {
            let body =
                serde_json::from_slice::<ErrorBody>(&frame.body).map_err(ModuleError::Json)?;
            Err(ModuleError::Message(format!(
                "subc rejected HELLO: {} — {}",
                body.code, body.message
            )))
        }
        ty => Err(ModuleError::Message(format!(
            "unexpected frame {ty:?} awaiting HELLO_ACK"
        ))),
    }
}

#[cfg(test)]
type RouteTestHandler =
    Arc<dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> + Send + Sync>;

/// A caller-owned interrupt signal; firing it never aborts the task that must
/// release held input and finalize the journal.
#[derive(Clone, Debug)]
pub struct CancelHandle(Arc<CancelSignal>);

/// The flag a polling loop reads, and a notifier for a call that waits on
/// something else (a person's answer) and must stop at once when cancelled.
#[derive(Debug, Default)]
pub struct CancelSignal {
    cancelled: std::sync::atomic::AtomicBool,
    notify: tokio::sync::Notify,
}

impl CancelHandle {
    pub fn pending() -> Self {
        Self(Arc::new(CancelSignal::default()))
    }
    pub fn for_uninterruptible_probe() -> Self {
        Self::pending()
    }
    pub fn cancel(&self) {
        self.0
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.0.notify.notify_waiters();
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
    /// Resolve once the handle is cancelled, immediately if it already is.
    pub async fn cancelled(&self) {
        loop {
            // Registered before the flag is read, so a cancel landing between
            // the read and the wait still wakes this.
            let notified = self.0.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.is_cancelled() {
                return;
            }
            notified.await;
        }
    }
}

type RequestKey = (u16, u32, u64);
type RequestCancelMap = std::collections::BTreeMap<RequestKey, CancelHandle>;

#[derive(Clone, Default)]
struct RequestCancellations(Arc<std::sync::Mutex<RequestCancelMap>>);

struct RequestCancellationGuard {
    registry: RequestCancellations,
    key: (u16, u32, u64),
    handle: CancelHandle,
}

impl RequestCancellations {
    fn register(&self, key: (u16, u32, u64)) -> RequestCancellationGuard {
        let handle = CancelHandle::pending();
        self.0.lock().unwrap().insert(key, handle.clone());
        RequestCancellationGuard {
            registry: self.clone(),
            key,
            handle,
        }
    }
    fn get(&self, key: (u16, u32, u64)) -> Option<CancelHandle> {
        self.0.lock().unwrap().get(&key).cloned()
    }
    fn cancel_route(&self, channel: u16, epoch: u32) {
        for ((c, e, _), handle) in self.0.lock().unwrap().iter() {
            if (*c, *e) == (channel, epoch) {
                handle.cancel();
            }
        }
    }
}

impl Drop for RequestCancellationGuard {
    fn drop(&mut self) {
        let mut registry = self.registry.0.lock().unwrap();
        // A reused correlation must not be removed by the older task's drop.
        if registry
            .get(&self.key)
            .is_some_and(|handle| Arc::ptr_eq(&handle.0, &self.handle.0))
        {
            registry.remove(&self.key);
        }
    }
}

/// The long-lived state a running module serves requests from.
///
/// Bundled rather than passed separately because these travel together
/// everywhere: the loop, the frame dispatcher, and each surface's handler all
/// need the same set, and threading them one by one meant every new one touched
/// every signature in the chain.
pub struct Planes {
    #[cfg(test)]
    route_test_handler: Option<RouteTestHandler>,
    pub health: Arc<HealthState>,
    cancellations: RequestCancellations,
    draining: Arc<std::sync::atomic::AtomicBool>,
    /// The same drain, as a signal a waiting task can await: a call parked on
    /// a person's answer must stop at once when the module drains, not at the
    /// end of its wait.
    drain_signal: Arc<tokio::sync::watch::Sender<bool>>,
    drain_notice: Arc<std::sync::OnceLock<(subc_protocol::RouteCloseReason, u64)>>,
    pub routes: Arc<RouteBindings>,
    pub browser: Arc<BrowserPlane>,
    pub browser_config: Option<BrowserConfig>,
    pub sessions: browser_session::BrowserSessions,
    pub lease_clock: Arc<cerebellum_core::clock::SystemClock>,
    pub launch_service: Option<Arc<dyn browser_session::BrowserSessionLauncher>>,
    pub management: Arc<ManagementPlane>,
    /// The computer plane or the single typed reason it was withheld.
    ///
    /// Keeping the outcome in one field prevents availability and its diagnostic
    /// from drifting into contradictory states.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub computer: Result<
        Arc<computer_capability::RunningComputerPlane>,
        computer_capability::ComputerPlaneUnavailable,
    >,
    /// The computer capabilities this build's release gates admit.
    ///
    /// Held so that DISPATCH can consult the same admission the manifest is
    /// built from. Advertisement already derives from dispatchability; without
    /// this the derivation runs one way only, and a build whose release
    /// identifiers are unbound advertises nothing while still serving a
    /// capability a caller names directly.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    pub computer_admitted: Arc<std::collections::BTreeSet<String>>,
    /// Questions this module has put to whoever is on the other end of a route.
    pub elicitor: SharedElicitor,
    /// `browser.capture_login`: one capture at a time, and its residue.
    pub capture: Arc<login_capture::CaptureModule>,
    /// One record per call that arrived with a `call_key`, so a resend is
    /// answered from it instead of running again.
    pub calls: Arc<journal::call_records::CallRecords>,
    /// Session scopes whose routes closed and whose end is not yet settled,
    /// and this module's channel-0 questions to the daemon about them.
    pub scopes: Arc<scope_watch::ScopeRevocation>,
}

/// Retention for the browser DRIVE journal: navigate, snapshot, click,
/// screenshot and their refusals.
///
/// Separate from the launch journal's 64 MiB because the entries are a
/// different size and the traffic a different shape. A drive record measured
/// ~730 bytes against a launch record's 8.7-11 KB, and a navigate with an
/// embedded read writes two of them -- so 8 MiB buys roughly 11,000 records,
/// about 5,500 navigate-and-read pairs.
///
/// Quote measured field numbers when re-sizing rather than fixture numbers. The
/// launch journal records that sizing against its fixture would have overstated
/// capacity by 44%, in the direction that runs out sooner than the comment
/// promises.
const BROWSER_DRIVE_JOURNAL_BYTES: u64 = 8 * 1024 * 1024;
const BROWSER_DRIVE_JOURNAL_MAX_ENTRY_BYTES: u64 = 64 * 1024;

/// Where a plane's audit journal is written.
///
/// Stated at every construction site rather than defaulted. Wiring the journal
/// with a durable default silently pointed the wire tests at the OPERATOR'S
/// audit data -- a gate run left three real records in a directory enrolled for
/// fleet backup, and every test passed. A default that is right for production
/// and wrong for tests fails in the direction nobody inspects.
///
/// Live probes take `Durable` deliberately: they drive real browsers against
/// real profiles, so their records describe real activity and belong on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JournalPersistence {
    /// The operator's journal under the data home.
    Durable,
    /// Held in memory and discarded with the plane. For tests.
    Isolated,
}

/// Where a journal that honours [`JournalPersistence`] keeps its state.
///
/// One storage type for both choices, so a plane's journal has the same type
/// whichever the caller picked. The alternative, a type per choice, would have
/// to be threaded through every plane that holds a journal, and a plane whose
/// type only admits the filesystem is how an isolated plane kept writing to the
/// operator's data home.
#[derive(Clone, Debug)]
pub enum PlaneJournalStorage {
    /// The operator's journal file under the data home.
    Filesystem(cerebellum_core::journal::FilesystemJournalStorage),
    /// A journal that starts empty and is discarded with the plane.
    InMemory(cerebellum_core::journal::InMemoryJournalStorage),
}

impl cerebellum_core::journal::JournalStorage for PlaneJournalStorage {
    fn load(
        &self,
    ) -> Result<cerebellum_core::journal::store::DurableState, cerebellum_core::journal::StorageError>
    {
        match self {
            Self::Filesystem(storage) => storage.load(),
            Self::InMemory(storage) => storage.load(),
        }
    }

    fn save(
        &self,
        state: &cerebellum_core::journal::store::DurableState,
    ) -> Result<(), cerebellum_core::journal::StorageError> {
        match self {
            Self::Filesystem(storage) => storage.save(state),
            Self::InMemory(storage) => storage.save(state),
        }
    }

    fn raise_format(
        &self,
        format: cerebellum_core::format_floor::DurableFormat,
    ) -> Result<(), cerebellum_core::journal::StorageError> {
        match self {
            Self::Filesystem(storage) => storage.raise_format(format),
            Self::InMemory(storage) => storage.raise_format(format),
        }
    }
}

impl Planes {
    /// A browser config with every deadline short and no executable, for
    /// tests. A running module builds through `with_browser_config` with the
    /// config it loaded, `None` when the file names no browser.
    pub fn new(health: Arc<HealthState>) -> Self {
        Self::with_browser_config_journaling(
            health,
            Some(Self::short_test_browser_config()),
            JournalPersistence::Isolated,
        )
    }

    fn short_test_browser_config() -> BrowserConfig {
        BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }
    }

    /// Build with a durable journal. What a running module uses.
    pub fn with_browser_config(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
    ) -> Self {
        Self::with_browser_config_journaling(health, browser_config, JournalPersistence::Durable)
    }

    /// Build with the journal written wherever the caller says.
    ///
    /// Tests take [`JournalPersistence::Isolated`]. A test that takes `Durable`
    /// writes into the operator's real audit data, which is what happened when
    /// this was a default rather than an argument.
    pub fn with_browser_config_journaling(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        journal: JournalPersistence,
    ) -> Self {
        Self::with_browser_config_journaling_and_standing_grants(
            health,
            browser_config,
            journal,
            None,
        )
    }

    /// Like [`Self::with_browser_config_journaling`], but keeps standing
    /// browser grants in `standing` when it is given. Without it, `journal`
    /// chooses: the operator's file for a durable plane, or memory that never
    /// offers a standing answer for an isolated one. Tests pass a store to
    /// have standing answers offered, to reopen a store across a restart, or
    /// to control the store's clock.
    pub fn with_browser_config_journaling_and_standing_grants(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        journal: JournalPersistence,
        standing: Option<Arc<browser_standing_grants::StandingBrowserGrants>>,
    ) -> Self {
        // The launch service picks its process launcher per platform and has
        // done since the Linux barrier landed. This wiring stayed macOS-only,
        // which left a merged Linux launcher unreachable and the refusal
        // blaming profile storage several layers away from the cause.
        //
        // Platforms without a launcher still get None: ProductionLaunchService
        // resolves one at construction, so this cannot advertise a launch it
        // cannot perform.
        let capture = Arc::new(login_capture::CaptureModule::new(
            login_capture::CaptureEnv::production(
                browser_config
                    .as_ref()
                    .map_or(30_000, |config| config.navigation_settle_deadline_ms),
            ),
        ));
        // Built before the launch service, which publishes what its startup
        // recovery kept into this plane's registry.
        // The operator's "always" grants are read from their store only for a
        // durable plane; an isolated plane keeps grants in memory and, with no
        // machine identity, never offers "always".
        // Standing browser grants follow the same rule, and are bound to the
        // same machine identity.
        let (computer_grants, durable_standing) = match journal {
            JournalPersistence::Durable => {
                let machine_uuid = computer_grants::this_machine_uuid();
                (
                    Arc::new(computer_grants::ComputerGrants::open_durable(
                        machine_uuid.clone(),
                    )),
                    Some(machine_uuid),
                )
            }
            JournalPersistence::Isolated => {
                (Arc::new(computer_grants::ComputerGrants::in_memory()), None)
            }
        };
        let standing = standing.unwrap_or_else(|| {
            Arc::new(match durable_standing {
                Some(machine_uuid) => {
                    browser_standing_grants::StandingBrowserGrants::open_durable(machine_uuid)
                }
                None => browser_standing_grants::StandingBrowserGrants::in_memory(),
            })
        });
        let management = Arc::new(
            ManagementPlane::with_computer_grants(
                Arc::new(management::PlatformResolver::new()),
                computer_grants,
            )
            .with_isolated_storage(journal == JournalPersistence::Isolated)
            .with_standing_browser_grants(standing),
        );
        #[cfg(any(target_os = "macos", target_os = "linux"))]
        let launch_service: Option<Arc<dyn browser_session::BrowserSessionLauncher>> =
            browser_config
                .clone()
                .filter(|config| {
                    config
                        .executable_path
                        .as_ref()
                        .is_some_and(|path| path.is_file())
                })
                .map(|config| {
                    // One service for route sessions and captures, so both
                    // write the one launch journal whose startup recovery
                    // reaps an orphan of either kind.
                    let service = Arc::new(
                        browser_launch_service::ProductionLaunchService::open_publishing(
                            config,
                            journal,
                            &management.launch_recovery_registry(),
                        ),
                    );
                    capture.set_launcher(service.clone());
                    service as Arc<dyn browser_session::BrowserSessionLauncher>
                });
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let launch_service = None;
        let sessions = browser_session::BrowserSessions::default();
        let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());
        let browser_grants = management.browser_grants();
        let browser = if let Some(config) = browser_config.as_ref() {
            Arc::new(
                BrowserPlane::with_session_gate(
                    sessions.clone(),
                    Arc::clone(&lease_clock),
                    config.navigation_settle_deadline_ms,
                )
                .with_result_schema_enforcement(
                    computer_capability::ResultSchemaEnforcement::Withhold,
                )
                .with_shared_grants(browser_grants)
                .with_journal_persistence(
                    matches!(journal, JournalPersistence::Durable),
                    journal::JournalConfig {
                        journal_retention_bytes: BROWSER_DRIVE_JOURNAL_BYTES,
                        journal_max_entry_bytes: BROWSER_DRIVE_JOURNAL_MAX_ENTRY_BYTES,
                    },
                ),
            )
        } else {
            // The action surface is unavailable without browser configuration,
            // but browser.import_login still journals its typed configuration
            // refusal on the management surface.
            Arc::new(
                BrowserPlane::new()
                    .with_result_schema_enforcement(
                        computer_capability::ResultSchemaEnforcement::Withhold,
                    )
                    .with_shared_grants(browser_grants)
                    .with_journal_persistence(
                        matches!(journal, JournalPersistence::Durable),
                        journal::JournalConfig {
                            journal_retention_bytes: BROWSER_DRIVE_JOURNAL_BYTES,
                            journal_max_entry_bytes: BROWSER_DRIVE_JOURNAL_MAX_ENTRY_BYTES,
                        },
                    ),
            )
        };
        let calls = Arc::new(match journal {
            JournalPersistence::Durable => {
                journal::call_records::CallRecords::open_durable(wall_clock_ms())
            }
            JournalPersistence::Isolated => journal::call_records::CallRecords::in_memory(),
        });
        #[cfg(target_os = "macos")]
        let global_dispatch_review_revision =
            compiled_release_inputs().global_dispatch_review_revision;
        #[cfg(target_os = "macos")]
        let takeover_dispatch_review_revision =
            compiled_release_inputs().takeover_dispatch_review_revision;
        Self {
            health,
            routes: Arc::new(RouteBindings::new()),
            browser,
            browser_config,
            sessions,
            lease_clock,
            launch_service,
            management,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer: computer_capability::computer_audit(journal).map(|audit| {
                // One idle estimator for the plane's lifetime: it exists to
                // remember the previous sequence's posts, which a per-dispatch
                // driver cannot do.
                #[cfg(target_os = "macos")]
                let user_idle = Arc::new(std::sync::Mutex::new(
                    cerebellum_computer::dispatch::UserIdleEstimator::new(),
                ));
                Arc::new(
                    computer_capability::ComputerPlane::with_synthetic_driver(
                        audit,
                        // Built fresh per dispatch: each platform driver caches
                        // accessibility trees, and a stale cache may name a process
                        // generation that is gone. Synthetic requests declare no
                        // post-condition, so their effects remain indeterminate.
                        move || {
                            let driver =
                                computer_capability::NativeComputerPlatformDriver::default()
                                    .without_expected_post_condition();
                            #[cfg(target_os = "macos")]
                            let driver = driver
                                .with_global_dispatch_review_revision(
                                    global_dispatch_review_revision.clone(),
                                )
                                .with_takeover_dispatch_review_revision(
                                    takeover_dispatch_review_revision.clone(),
                                )
                                .with_shared_user_idle(user_idle.clone());
                            driver
                        },
                    )
                    // The fronting bracket is served only by a build carrying
                    // its review; without it a background target is refused.
                    .with_fronting_bracket_admitted(
                        compiled_release_inputs()
                            .takeover_dispatch_review_revision
                            .is_some(),
                    ),
                )
            }),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer_admitted: Arc::new(
                computer_release_evidence(&default_computer_context())
                    .gate_admitted_capabilities
                    .into_iter()
                    .collect(),
            ),
            #[cfg(test)]
            route_test_handler: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            cancellations: RequestCancellations::default(),
            elicitor: Arc::new(Elicitor::new()),
            capture,
            calls,
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
        }
    }
}

/// The computer capabilities a test module admits.
///
/// Production reads this from the release gates. A test that went through those
/// gates would exercise release binding rather than the behaviour under test,
/// and would go silently green the day an identifier came unbound: every
/// request refused, and every assertion about a refusal still passing.
///
/// Only wait: it is the one served capability that needs no release review of
/// its own, so admitting it here stands in for nothing production withholds.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn test_admitted_computer_capabilities() -> Arc<std::collections::BTreeSet<String>> {
    Arc::new(std::iter::once("computer.wait".to_string()).collect())
}

impl Clone for Planes {
    fn clone(&self) -> Self {
        Self {
            #[cfg(test)]
            route_test_handler: self.route_test_handler.clone(),
            health: Arc::clone(&self.health),
            cancellations: self.cancellations.clone(),
            draining: self.draining.clone(),
            drain_signal: Arc::clone(&self.drain_signal),
            drain_notice: self.drain_notice.clone(),
            routes: Arc::clone(&self.routes),
            browser: Arc::clone(&self.browser),
            browser_config: self.browser_config.clone(),
            sessions: self.sessions.clone(),
            lease_clock: Arc::clone(&self.lease_clock),
            launch_service: self.launch_service.clone(),
            management: Arc::clone(&self.management),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer: self.computer.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer_admitted: Arc::clone(&self.computer_admitted),
            elicitor: Arc::clone(&self.elicitor),
            capture: Arc::clone(&self.capture),
            calls: Arc::clone(&self.calls),
            scopes: Arc::clone(&self.scopes),
        }
    }
}

/// Returns `Ok(false)` to stop the loop (graceful goodbye / EOF).
async fn handle_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<bool, ModuleError> {
    match frame.header.ty {
        FrameType::Ping if frame.header.channel == 0 => {
            let pong = Frame::build_with_version(
                frame.header.ver,
                FrameType::Pong,
                frame.header.flags,
                0,
                0,
                frame.header.corr,
                Vec::new(),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            send(writer, pong).await?;
            Ok(true)
        }
        // The daemon's answer to a control request this module sent on its own
        // connection (`scope.describe`). The daemon's requests to the module
        // arrive as requests, so a response or error on channel 0 can only be
        // one of these; it is handed to whoever asked, or dropped if nobody
        // still waits. Without this arm such an answer would be dropped by the
        // branches below, which know only questions asked on route channels,
        // so every describe would wait out its deadline as if unanswered.
        FrameType::Response | FrameType::Error if frame.header.channel == 0 => {
            let body = serde_json::from_slice(&frame.body).unwrap_or(serde_json::Value::Null);
            let answer = if frame.header.ty == FrameType::Response {
                scope_watch::ControlAnswer::Response(body)
            } else {
                scope_watch::ControlAnswer::Error(body)
            };
            planes.scopes.control.deliver(frame.header.corr, answer);
            Ok(true)
        }
        // An answer to a question this module asked. Requests are what we
        // ANSWER and responses are what we RECEIVE, so an inbound response can
        // only belong to an exchange we opened; the direction settles ownership
        // without a private correlation space.
        //
        // Without this arm the frame fell through to the catch-all and was
        // dropped, so a question waited out its whole deadline and reported that
        // nobody replied. That is indistinguishable from a consumer ignoring it,
        // which is why the absence could not have been noticed from the outside.
        FrameType::Response => {
            let body = serde_json::from_slice(&frame.body).unwrap_or(serde_json::Value::Null);
            if !planes
                .elicitor
                .deliver(frame.header.channel, frame.header.corr, body)
            {
                // Nobody was waiting: an answer that arrived after its deadline,
                // or a correlation this module never sent. Dropped deliberately
                // rather than acted on, because there is no exchange to complete
                // and a late answer must not revive an abandoned one.
            }
            Ok(true)
        }
        // An error frame in place of an answer: the consumer refused the
        // question instead of relaying it. The frame type settles direction,
        // as for a response: an error can only answer a request this module
        // sent, and on a route channel the only requests it sends are
        // questions. Ending it here keeps the question from waiting out its
        // whole deadline, up to half an hour, for an answer that cannot come.
        FrameType::Error if frame.header.channel != 0 => {
            planes
                .elicitor
                .refuse(frame.header.channel, frame.header.corr);
            Ok(true)
        }
        FrameType::Push if frame.header.channel == 0 => {
            if let Ok(subc_protocol::session::ModuleControlCommand::Draining {
                reason,
                deadline_ms,
            }) = serde_json::from_slice(&frame.body)
            {
                if planes.drain_notice.set((reason, deadline_ms)).is_ok() {
                    planes
                        .draining
                        .store(true, std::sync::atomic::Ordering::Release);
                    planes.drain_signal.send_replace(true);
                    planes.elicitor.cancel_where(|_, _| true).await;
                    // Spend the drain window flushing profiles, not waiting for the
                    // deadline. It is only an upper bound, never a scheduled start.
                    if let Some(config) = planes.browser_config.clone() {
                        let sessions = planes.sessions.clone();
                        tokio::task::spawn_blocking(move || sessions.teardown_all(&config));
                    }
                }
            }
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => {
            planes
                .elicitor
                .forget_route(frame.header.channel, frame.header.epoch);
            // Unbound before its requests are cancelled, so a call waiting on a
            // person sees the route gone when it wakes and answers
            // `route_closed` rather than a caller-requested cancel.
            let removed = planes
                .routes
                .remove(frame.header.channel, frame.header.epoch);
            planes
                .elicitor
                .set_unattended(frame.header.channel, frame.header.epoch, false);
            planes
                .cancellations
                .cancel_route(frame.header.channel, frame.header.epoch);
            if let Some(facts) = removed {
                let conversation_key = &facts.identity.conversation_key;
                let last_route = !planes.routes.carries_conversation(conversation_key);
                match facts.scope.as_ref() {
                    None => {
                        // A conversation's computer grants end with its last
                        // route: another route may still carry the same
                        // conversation.
                        if last_route {
                            planes.management.end_conversation(conversation_key);
                            planes.calls.end_conversation(conversation_key);
                        }
                        if let Some(config) = planes.browser_config.as_ref() {
                            planes.sessions.teardown_route(
                                conversation_key,
                                browser_session::BrowserSessionTerminalOutcome::RouteUnbound,
                                config,
                            );
                        }
                    }
                    // A route under a session scope closing is not the session
                    // ending: a client reconnect or a daemon restart closes it
                    // too, and the agent's browser and grants must survive
                    // those. The daemon is asked whether the scope ended, off
                    // this loop, and they end only on a definitive answer.
                    Some(stamp) => {
                        if last_route {
                            // Held reply bodies are a memory bound, not a
                            // permission: they go with the last route as always.
                            planes.calls.end_conversation(conversation_key);
                        }
                        let key = scope_watch::ScopeKey::from_stamp(stamp);
                        if planes.scopes.note_closed(&key, conversation_key) {
                            tokio::spawn(watch_scope(planes.clone(), writer.clone(), key));
                        }
                    }
                }
            }
            Ok(true)
        }
        FrameType::Cancel => {
            match (
                frame.header.channel,
                planes.cancellations.get((
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                )),
            ) {
                (0, _) => {}
                (_, Some(handle)) => handle.cancel(),
                // Replies commonly win the race. Unknown or late correlations
                // are explicitly ignored without a reply, error, or log.
                (_, None) => {}
            }
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            if scope_epoch_admits_bind(&frame, writer, planes).await? {
                handle_control_request(
                    frame,
                    writer,
                    &planes.health,
                    &planes.routes,
                    &planes.elicitor,
                )
                .await?;
            }
            Ok(true)
        }
        FrameType::Request => {
            if planes.draining.load(std::sync::atomic::Ordering::Acquire) {
                let (reason, deadline_ms) =
                    planes.drain_notice.get().expect("drain notice published");
                // The structured facts ride in `detail`: a consumer decodes
                // `ErrorBody { code, message, detail }` and drops keys it does
                // not know, so top-level extras would never reach it.
                let refusal = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Error,
                    control_flags(),
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    serde_json::to_vec(&ErrorBody {
                        code: "module_draining".to_string(),
                        message: "the module is draining for a restart; retry after it is back"
                            .to_string(),
                        detail: Some(json!({
                            "reason": reason,
                            "deadline_ms": deadline_ms,
                            "remedy": "retry after the module restarts",
                        })),
                    })
                    .map_err(ModuleError::Json)?,
                )
                .map_err(|e| ModuleError::Message(e.to_string()))?;
                send(writer, refusal).await?;
                return Ok(true);
            }
            let cancellation = planes.cancellations.register((
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
            ));
            let guard = planes.health.enter_request();
            let writer = writer.clone();
            let planes = planes.clone();
            tokio::spawn(elicit::ROUTE_GUARD.scope(Arc::new(guard), async move {
                #[cfg(test)]
                if let Some(handler) = &planes.route_test_handler {
                    handler().await;
                }
                let _cancellation = cancellation;
                let _ = handle_route_request(frame, &writer, &planes).await;
            }));
            Ok(true)
        }
        _ => Ok(true),
    }
}

/// Send a request to the surface its route was bound to.
///
/// The surface is read before the body is parsed, because the two surfaces take
/// different envelopes and neither can be decoded without knowing which arrived.
/// Parsing first and inferring the surface from the shape would let a caller
/// reach one surface by sending the other's envelope.
async fn handle_route_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;

    let Some(facts) = planes.routes.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "a request requires an accepted route.bind",
        )
        .await;
    };
    // A route of a session that a newer epoch has replaced, whose close has
    // not reached this module yet. Serving it could mint a grant under the
    // conversation the new session now holds.
    if facts
        .scope
        .as_ref()
        .is_some_and(|stamp| planes.scopes.is_superseded(stamp))
    {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "scope_ended",
            "this route's session scope has ended: a newer session under the same scope has \
             been bound",
        )
        .await;
    }

    match facts.surface {
        RouteSurface::Tools => handle_keyed_tool_request(frame, writer, planes).await,
        RouteSurface::Management => handle_management_request(frame, writer, &facts, planes).await,
        // A route bound to a surface this module does not advertise. Refused
        // with the surface named rather than served as one of the others, which
        // would answer a caller from an envelope it did not use.
        RouteSurface::Unsupported => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "unsupported_surface",
                "this route is bound to a surface this module does not serve",
            )
            .await
        }
    }
}

async fn handle_management_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;

    let Ok(request) = serde_json::from_slice::<serde_json::Value>(&frame.body) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "invalid_request",
            "request body not decodable",
        )
        .await;
    };
    let Some(object) = request.as_object() else {
        return send_invalid_request_response(writer, ver, channel, epoch, corr, "$", "wrong_type")
            .await;
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !matches!(field.as_str(), "method" | "params"))
        .min()
    {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            field,
            "unknown_field",
        )
        .await;
    }

    let Some(method) = object.get("method").and_then(serde_json::Value::as_str) else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "method",
            "missing_field",
        )
        .await;
    };
    if !dispatchable_management_operation(method) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "unknown_method",
            &format!("unknown method '{method}'"),
        )
        .await;
    }
    // Operator operations (list or revoke grants, profile-root rebind, and
    // launch-recovery clear) administer machine-wide grants and browser state.
    // A flow route never gets them, even when acting for its owner.
    if facts.flow_id.is_some() && is_operator_operation(method) {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("unattended_flow"),
        )
        .await;
    }
    if method == management::WOULD_ASK
        && !cerebellum_core::principal::admits_session_calls(&facts.principal)
    {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "grants.would_ask is reserved to reserved:prefrontal-core",
        )
        .await;
    }
    // Session admission, before any operation below asks a person, opens or
    // reads a grant, or writes the journal; see `send_session_caller_not_admitted`.
    // A caller not admitted to act in a conversation reaches only the
    // operator's operations, and those see these facts with every trace of
    // the conversation removed.
    let operator_facts;
    let facts = if method == management::WOULD_ASK || facts.admits_session_calls() {
        facts
    } else if is_operator_operation(method) {
        operator_facts = facts.outside_session_scope();
        &operator_facts
    } else {
        if let Some(refusal) = session_flow_refusal(facts) {
            return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
        }
        return send_session_caller_not_admitted(writer, ver, channel, epoch, corr, facts).await;
    };
    if let Some(refusal) = session_flow_refusal(facts) {
        return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
    }
    if facts.flow_id.is_some()
        && matches!(
            method,
            management::OPEN_GRANT
                | management::IMPORT_LOGIN
                | management::CAPTURE_LOGIN
                | management::PRESENT
                | management::CLEAR_LAUNCH_RECOVERY
                | management::REBIND_PROFILE_ROOT
        )
    {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("unattended_flow"),
        )
        .await;
    }
    let params = object
        .get("params")
        .cloned()
        .unwrap_or(serde_json::json!({}));
    let Some(params_object) = params.as_object() else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "params",
            "wrong_type",
        )
        .await;
    };

    if matches!(method, management::PRESENT | management::IMPORT_LOGIN) {
        if let Some(field) = params_object
            .keys()
            .filter(|field| field.as_str() != "origin")
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let Some(origin_value) = params_object.get("origin") else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origin",
                "missing_field",
            )
            .await;
        };
        let Some(origin) = origin_value.as_str() else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origin",
                "wrong_type",
            )
            .await;
        };
        if crate::classification::canonical_grant_origin(origin).as_deref() != Some(origin) {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origin",
                "invalid_origin",
            )
            .await;
        }
        let reply = if method == management::IMPORT_LOGIN {
            let reply =
                import_browser_login(planes, facts, writer, channel, epoch, corr, origin).await;
            match planes.browser.finish_reply(method, reply) {
                Ok(reply) => reply,
                Err(error) => return send_route_error(writer, ver, channel, epoch, corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!("the import reply violated its declared result schema ({error}); the import may already have completed, so do not retry based on this response"),
                ).await,
            }
        } else {
            present_browser_handoff(planes, &facts.identity, origin).await
        };
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::WOULD_ASK {
        let request = match management::parse_would_ask(params_object) {
            Ok(request) => request,
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        };
        let reply = planes.management.would_ask(&request);
        let items = reply["items"]
            .as_array()
            .expect("the evaluator returns items");
        let counts = json!({
            "item_count":items.len(),
            "yes":items.iter().filter(|i| i["verdict"] == "yes").count(),
            "no":items.iter().filter(|i| i["verdict"] == "no").count(),
            "would_ask":items.iter().filter(|i| i["verdict"] == "would_ask").count(),
        });
        if planes
            .browser
            .journal_would_ask(
                &facts.identity,
                principal_label(&facts.principal),
                &request.agent_id,
                &request.flow_id,
                counts,
            )
            .await
            .is_err()
        {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "journal_unavailable",
                "permission query could not be audited",
            )
            .await;
        }
        return match planes.browser.finish_reply(method, reply) {
            Ok(reply) => send_tool_response(writer, ver, channel, epoch, corr, reply).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!("the permission reply violated its declared result schema ({error})"),
                )
                .await
            }
        };
    }

    if method == management::CAPTURE_LOGIN {
        let request = match login_capture::parse_request(params_object) {
            Ok(request) => request,
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        };
        let reply =
            capture_browser_login(planes, facts, writer, channel, epoch, corr, &request).await;
        return match planes
            .browser
            .finish_reply(management::CAPTURE_LOGIN, reply)
        {
            Ok(reply) => send_tool_response(writer, ver, channel, epoch, corr, reply).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!(
                        "the capture reply violated its declared result schema ({error}); any \
                         captured file is deleted at its deadline, so capture again rather than \
                         retrying from this response"
                    ),
                )
                .await
            }
        };
    }

    if method == management::RESUME {
        if let Some(field) = params_object.keys().min() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let reply = resume_browser_handoff(planes, &facts.identity).await;
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::OPEN_TARGET {
        if let Some(field) = params_object
            .keys()
            .filter(|field| field.as_str() != "bundle_identity")
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let Some(bundle_identity) = params_object
            .get("bundle_identity")
            .and_then(serde_json::Value::as_str)
            .filter(|bundle| !bundle.is_empty())
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "bundle_identity",
                "missing_field",
            )
            .await;
        };
        // Waits for the person exactly as a computer action does, so it is
        // interruptible in the same ways.
        let cancel = planes
            .cancellations
            .get((channel, epoch, corr))
            .unwrap_or_else(CancelHandle::pending);
        let consent = consent_context(planes, facts, writer, channel, epoch);
        let reply = planes
            .management
            .open_target(bundle_identity, &consent, &cancel)
            .await;
        // The caller is gone when its route unbound mid-wait; nothing is sent.
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::LIST_APP_GRANTS {
        if let Some(field) = params_object.keys().min() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let reply = planes.management.computer_grants().list();
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if method == management::REVOKE_APP_GRANT {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "grantee" | "bundle_identity" | "dry_run"))
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let mut named = [None, None];
        for (slot, field) in named.iter_mut().zip(["grantee", "bundle_identity"]) {
            match params_object.get(field) {
                Some(serde_json::Value::String(value)) if !value.is_empty() => {
                    *slot = Some(value.clone())
                }
                Some(serde_json::Value::String(_)) => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        field,
                        "empty_value",
                    )
                    .await
                }
                other => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        field,
                        if other.is_some() {
                            "wrong_type"
                        } else {
                            "missing_field"
                        },
                    )
                    .await
                }
            }
        }
        let dry_run = match params_object.get("dry_run") {
            None => false,
            Some(serde_json::Value::Bool(dry_run)) => *dry_run,
            Some(_) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "dry_run",
                    "wrong_type",
                )
                .await
            }
        };
        let [Some(grantee), Some(bundle_identity)] = named else {
            unreachable!("both fields were checked above");
        };
        let reply = planes
            .management
            .computer_grants()
            .revoke(&grantee, &bundle_identity, dry_run);
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    if matches!(
        method,
        management::REVOKE_ACCESS | management::REVOKE_GRANT | management::LIST_GRANTS
    ) {
        let reply = match standing_grant_operation(method, params_object, facts, planes) {
            Ok(reply) => reply,
            Err(StandingGrantOperationRefusal::UnknownField(field)) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &field,
                    "unknown_field",
                )
                .await
            }
            Err(StandingGrantOperationRefusal::Invalid((field, reason))) => {
                return send_invalid_request_response(
                    writer, ver, channel, epoch, corr, field, reason,
                )
                .await
            }
        };
        // The agent's own revocation is reached from the browser tool, so its
        // reply is held to the result schema the tool declares for it.
        let reply = if method == management::REVOKE_ACCESS {
            match planes.browser.finish_reply(method, reply) {
                Ok(reply) => reply,
                Err(error) => {
                    return send_route_error(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        browser::RESULT_SCHEMA_VIOLATION_CODE,
                        &format!(
                            "the revoke_access reply violated its declared result schema \
                             ({error}); the access may already have been removed, so call \
                             revoke_access again rather than retrying from this response"
                        ),
                    )
                    .await
                }
            }
        } else {
            reply
        };
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
    }

    enum Settlement {
        BrowserGrant,
        ProfileRootRebind,
        LaunchRecoveryClear,
    }

    let (reply, question, settlement) = if method == management::OPEN_GRANT {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "origins" | "hazards" | "severity_tier"))
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let Some(origin_values) = params_object
            .get("origins")
            .and_then(serde_json::Value::as_array)
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origins",
                "missing_field",
            )
            .await;
        };
        let Some(origins) = origin_values
            .iter()
            .map(serde_json::Value::as_str)
            .map(|origin| origin.map(str::to_string))
            .collect::<Option<Vec<_>>>()
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "origins",
                "wrong_type",
            )
            .await;
        };
        let Some(hazard_values) = params_object
            .get("hazards")
            .and_then(serde_json::Value::as_array)
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "hazards",
                "missing_field",
            )
            .await;
        };
        let Some(hazards) = hazard_values
            .iter()
            .map(serde_json::Value::as_str)
            .map(|hazard| hazard.and_then(crate::authorization::HazardClass::from_wire))
            .collect::<Option<Vec<_>>>()
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "hazards",
                "unsupported_value",
            )
            .await;
        };
        // Optional: omitted keeps the ceiling the hazards imply. Out-of-range
        // integers are refused by the management plane below.
        let severity_tier = match params_object.get("severity_tier") {
            None => None,
            Some(value) => match value.as_u64() {
                Some(tier) => Some(u8::try_from(tier).unwrap_or(u8::MAX)),
                None => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        "severity_tier",
                        "wrong_type",
                    )
                    .await
                }
            },
        };
        let opened = planes
            .management
            .open_browser_grant_at_tier(
                &facts.identity.conversation_key,
                origins,
                hazards,
                severity_tier,
                facts.declares_elicitation(),
                standing_offer_agent(facts),
            )
            .await;
        let (reply, question) = match opened {
            Ok(opened) => opened,
            Err(management::BrowserGrantRequestError::InvalidOrigins) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "origins",
                    "unsupported_value",
                )
                .await
            }
            Err(management::BrowserGrantRequestError::UngrantableOrigin { value }) => {
                // The value is echoed so a caller holding several origins can
                // see which one was refused, `null` included.
                return send_tool_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    json!({
                        "outcome": "invalid_request",
                        "context": null,
                        "session": null,
                        "detail": {
                            "field": "origins",
                            "reason_code": "unsupported_value",
                            "value": value,
                        },
                    }),
                )
                .await;
            }
            Err(management::BrowserGrantRequestError::InvalidHazards) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "hazards",
                    "unsupported_value",
                )
                .await
            }
            Err(management::BrowserGrantRequestError::InvalidSeverityTier) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "severity_tier",
                    "out_of_range",
                )
                .await
            }
        };
        (reply, question, Settlement::BrowserGrant)
    } else if method == management::CLEAR_LAUNCH_RECOVERY {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "agent_project_id" | "sequence"))
            .min()
        {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        // The project is named explicitly: the operator clears another
        // project's record from their own desk route.
        let Some(agent_project_id) = params_object
            .get("agent_project_id")
            .and_then(serde_json::Value::as_str)
            .filter(|project| !project.is_empty())
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "agent_project_id",
                "missing_field",
            )
            .await;
        };
        let sequence = match params_object.get("sequence") {
            None => None,
            Some(value) => match value.as_u64() {
                Some(sequence) => Some(sequence),
                None => {
                    return send_invalid_request_response(
                        writer,
                        ver,
                        channel,
                        epoch,
                        corr,
                        "sequence",
                        "wrong_type",
                    )
                    .await
                }
            },
        };
        let (reply, question) = planes
            .management
            .open_launch_recovery_clear(agent_project_id, sequence, facts.declares_elicitation())
            .await;
        (reply, question, Settlement::LaunchRecoveryClear)
    } else {
        if let Some(field) = params_object.keys().min() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                field,
                "unknown_field",
            )
            .await;
        }
        let (reply, question) = planes
            .management
            .open_profile_root_rebind(
                &facts.identity.conversation_key,
                facts.declares_elicitation(),
            )
            .await;
        (reply, question, Settlement::ProfileRootRebind)
    };

    if let Some(question) = question {
        // Asked on its own task: the answer may be minutes away while this
        // caller is owed a reply now. The reply already says the request is
        // pending, so nothing is waiting on the question here.
        let elicitor = Arc::clone(&planes.elicitor);
        let management_plane = Arc::clone(&planes.management);
        let writer = writer.clone();
        tokio::spawn(async move {
            let outcome = elicitor
                .ask(&writer, channel, epoch, question.body, question.deadline)
                .await;
            // The whole ending is handed on, not just an answer or its absence:
            // the next request reports a question nobody was shown differently
            // from one a person left unanswered, and only the ending says which.
            match settlement {
                Settlement::BrowserGrant => {
                    management_plane
                        .settle_browser_grant_ending(&question.ask_id, Some(&outcome))
                        .await;
                }
                Settlement::ProfileRootRebind => {
                    management_plane
                        .settle_profile_root_rebind_ending(&question.ask_id, Some(&outcome))
                        .await;
                }
                Settlement::LaunchRecoveryClear => {
                    // Settled on this task because the clear re-reads the
                    // process table and writes the journal; the outcome is
                    // kept by the plane and reported on the next request.
                    management_plane
                        .settle_launch_recovery_clear_ending(&question.ask_id, &outcome)
                        .await;
                }
            }
        });
    }

    send_tool_response(writer, ver, channel, epoch, corr, reply).await
}

/// Why a standing-grant operation's request was refused before it ran.
enum StandingGrantOperationRefusal {
    UnknownField(String),
    Invalid(standing_grant_params::Refusal),
}

impl From<standing_grant_params::Refusal> for StandingGrantOperationRefusal {
    fn from(refusal: standing_grant_params::Refusal) -> Self {
        Self::Invalid(refusal)
    }
}

/// Serve `browser.revoke_access`, `browser.revoke_grant` or `grants.list`.
///
/// `browser.revoke_access` acts for the route's own agent, which must be
/// attested, since it names the rows it removes; it asks nobody because it
/// only narrows. The other two name the agent explicitly and are the
/// operator's (see `is_operator_operation`).
fn standing_grant_operation(
    method: &str,
    params: &serde_json::Map<String, Value>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
) -> Result<Value, StandingGrantOperationRefusal> {
    use browser_standing_grants::RevokeTarget;
    let standing = planes.management.standing_browser_grants();
    match method {
        management::REVOKE_ACCESS => {
            standing_grant_params::only(params, &["origin", "domain"])
                .map_err(StandingGrantOperationRefusal::UnknownField)?;
            let origin = standing_grant_params::origin(params)?;
            if !facts.agent_project_id_attested || !facts.acts_as_agent {
                return Ok(json!({
                    "outcome": "agent_not_attested",
                    "revoked": 0,
                    "remedy": "this route's agent identity is not attested, so it holds no standing browser access to remove",
                }));
            }
            let domain = standing_grant_params::domain(params)?;
            let target = match (origin, domain) {
                (Some(_), Some(_)) => return Err(("domain", "conflicting_fields").into()),
                (Some(origin), None) => RevokeTarget::Origin(origin),
                (None, Some(domain)) => RevokeTarget::Domain(domain),
                (None, None) => RevokeTarget::Everything,
            };
            Ok(standing.revoke(&facts.identity.agent_project_id, &target))
        }
        management::REVOKE_GRANT => {
            standing_grant_params::only(params, &["agent_id", "origin", "domain", "all_sites"])
                .map_err(StandingGrantOperationRefusal::UnknownField)?;
            let agent_id = standing_grant_params::agent_id(params)?;
            let origin = standing_grant_params::origin(params)?;
            let all_sites = match params.get("all_sites") {
                None => false,
                Some(Value::Bool(true)) => true,
                Some(Value::Bool(false)) => {
                    return Err(("all_sites", "unsupported_value").into());
                }
                Some(_) => return Err(("all_sites", "wrong_type").into()),
            };
            let domain = standing_grant_params::domain(params)?;
            if domain.is_some() && (origin.is_some() || all_sites) {
                return Err(("domain", "conflicting_fields").into());
            }
            let target = match (origin, all_sites) {
                (Some(_), true) => return Err(("all_sites", "conflicting_fields").into()),
                (Some(origin), false) => RevokeTarget::Origin(origin),
                (None, true) => RevokeTarget::AllSites,
                (None, false) => domain.map_or(RevokeTarget::Everything, RevokeTarget::Domain),
            };
            Ok(standing.revoke(&agent_id, &target))
        }
        _ => {
            standing_grant_params::only(params, &["agent_id"])
                .map_err(StandingGrantOperationRefusal::UnknownField)?;
            let agent_id = standing_grant_params::agent_id(params)?;
            let apps = planes.management.computer_grants().list();
            let app_grants: Vec<Value> = apps["grants"]
                .as_array()
                .map(|grants| {
                    grants
                        .iter()
                        .filter(|grant| grant["grantee"] == agent_id.as_str())
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            Ok(json!({
                "agent_id": agent_id,
                "browser": {
                    "grants": standing
                        .live_rows(&agent_id)
                        .iter()
                        .map(browser_standing_grants::StandingBrowserGrant::describe)
                        .collect::<Vec<_>>(),
                    "store": standing.store_state(),
                },
                "apps": {
                    "grants": app_grants,
                    "store": apps["store"].clone(),
                },
            }))
        }
    }
}

async fn import_browser_login(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
    corr: u64,
    origin: &str,
) -> Value {
    let durable = facts.identity.profile_disposition == ProfileDisposition::Durable;
    if let Err(result) = login_import::profile_precondition(origin, durable) {
        return journal_login_import_result(planes, &facts.identity, *result).await;
    }
    if !facts.declares_elicitation() {
        let result = login_import::ImportResult::refusal(
            origin,
            "elicitation_undeclared",
            "reconnect with a route that declares elicitation support",
        );
        return journal_login_import_result(planes, &facts.identity, result).await;
    }
    let location = match planes
        .management
        .durable_login_profile_location(&facts.identity.agent_project_id)
    {
        Ok(Some(location)) => location,
        Ok(None) => {
            let result = login_import::ImportResult::refusal(
                origin,
                "profile_not_durable",
                "launch the durable profile once so the profile registry can mint it",
            );
            return journal_login_import_result(planes, &facts.identity, result).await;
        }
        Err(_) => {
            let result = login_import::ImportResult::refusal(
                origin,
                "profile_not_durable",
                "restore access to the durable browser profile registry, then retry",
            );
            return journal_login_import_result(planes, &facts.identity, result).await;
        }
    };
    let Some(launch_executable) = planes
        .browser_config
        .as_ref()
        .and_then(|config| config.executable_path.as_deref())
    else {
        let result = login_import::ImportResult::refusal(
            origin,
            "launch_binary_unsupported",
            "configure a supported Chromium-family browser executable",
        );
        return journal_login_import_result(planes, &facts.identity, result).await;
    };
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        let result = login_import::ImportResult::refusal(
            origin,
            "launch_binary_unsupported",
            "run the module with a readable user home directory",
        );
        return journal_login_import_result(planes, &facts.identity, result).await;
    };
    let plan = match login_import::prepare_import(
        origin,
        &facts.identity.agent_project_id,
        launch_executable,
        location,
        login_import::ImportSettings::production(&home),
    ) {
        login_import::PreparedImport::Ready(plan) => plan,
        login_import::PreparedImport::Refused(result) => {
            return journal_login_import_result(planes, &facts.identity, result).await
        }
    };

    complete_login_import(
        planes,
        facts,
        writer,
        channel,
        epoch,
        plan,
        planes.cancellations.get((channel, epoch, corr)),
    )
    .await
}

async fn complete_login_import(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
    plan: login_import::LoginImportPlan,
    cancel: Option<CancelHandle>,
) -> Value {
    let consent = planes.management.computer_grants().require_login(
        login_consent_request(
            planes,
            facts,
            writer,
            (channel, epoch),
            computer_grants::LoginCapability::ImportLogin,
            plan.consent_parameters(),
        ),
        || {
            let ask_id = login_import::new_ask_id();
            let question = plan.question(&ask_id, &facts.identity.agent_project_id);
            (ask_id, question)
        },
    );
    // `None` when the caller cancelled the request before the question ended.
    // A cancel stops this call's wait; the card stays open, and an answer to
    // it is remembered for a retry.
    let answer = tokio::select! {
        consent = consent => match consent {
            computer_grants::LoginConsent::Ended(answer) => Some(answer),
            computer_grants::LoginConsent::Pending { ask_id } => {
                return journal_login_import_result(planes, &facts.identity, plan.pending(ask_id))
                    .await;
            }
        },
        () = async {
            match &cancel {
                Some(cancel) => cancel.cancelled().await,
                None => std::future::pending::<()>().await,
            }
        } => None,
    };
    let answer = if cancel.as_ref().is_some_and(CancelHandle::is_cancelled) {
        None
    } else {
        answer
    };
    let decision = match &answer {
        Some(elicit::AskOutcome::Answered(body)) => body.get("decision").and_then(Value::as_str),
        // None of these permits a transfer, and they are listed rather than
        // wildcarded so a future outcome has to be decided about here.
        Some(
            elicit::AskOutcome::NoAnswer
            | elicit::AskOutcome::NotPutToAnyone
            | elicit::AskOutcome::Undeliverable,
        )
        | None => None,
    };
    let mut reopen = None;
    if plan.permits_transfer(decision) {
        let status = planes.sessions.status(
            &facts.identity.conversation_key,
            planes.lease_clock.as_ref(),
            std::time::SystemTime::now(),
        );
        if status.get("outcome").and_then(Value::as_str) == Some("ready") {
            let Some(config) = planes.browser_config.as_ref() else {
                return journal_login_import_result(
                    planes,
                    &facts.identity,
                    plan.refusal("session_open", "browser.close"),
                )
                .await;
            };
            match planes
                .sessions
                .close_idle_for_import(&facts.identity.conversation_key, config)
            {
                Ok((closed, url)) if closed["outcome"] == "closed" => {
                    reopen = Some(url);
                    planes.browser.end_context(&facts.identity, false).await;
                }
                _ => {
                    return journal_login_import_result(
                        planes,
                        &facts.identity,
                        plan.refusal("session_open", "browser.close"),
                    )
                    .await
                }
            }
        }
    }
    let result = match &answer {
        Some(answer) => plan.conclude(answer),
        // A cancelled request is still recorded as not transferred, as it
        // always has been; its caller has stopped waiting for the reply.
        None => plan.decide(None),
    };
    let mut reply = journal_login_import_result(planes, &facts.identity, result).await;
    if let Some(url) = reopen {
        // Even a failed copy must not leave a session we closed unnecessarily down.
        let launched =
            handle_browser_control(browser_session::BROWSER_LAUNCH, &json!({}), facts, planes)
                .await;
        if launched["outcome"] == "launched" {
            let mut restored_url = None;
            if let Some(url) = url {
                if let Some(origin) = classification::canonical_origin_from_url(&url) {
                    let granted = planes
                        .management
                        .browser_grants()
                        .lock()
                        .await
                        .select_covering_grant(
                            &facts.identity.conversation_key,
                            authorization::Severity::new(1, false, false),
                            &origin,
                        )
                        .is_ok();
                    if granted {
                        let navigation = planes.browser.serve(&facts.identity, browser::BrowserCapability::Navigate,
                            &json!({"url":url,"intent":"Restore the page after importing login","severity":{"tier":1,"credential":false,"financial":false},"wait":"settle"})).await;
                        if let Ok(navigation) = navigation {
                            if matches!(navigation["outcome"].as_str(), Some("ok" | "not_settled"))
                            {
                                restored_url = navigation["url_final"].as_str().map(str::to_string);
                            }
                        }
                    }
                }
            }
            reply["relaunched"] = json!({"browser_session_id":launched["browser_session_id"],"restored_url":restored_url});
        } else {
            reply["relaunched"] = Value::Null;
            reply["detail"] = launched;
        }
    }
    reply
}

async fn journal_login_import_result(
    planes: &Planes,
    identity: &RouteIdentity,
    result: login_import::ImportResult,
) -> Value {
    if planes
        .browser
        .journal_login_import(
            identity,
            &result.origin,
            &result.outcome,
            result.browser.as_deref(),
            result.rows,
        )
        .await
        .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"journal_unavailable"});
    }
    result.to_value()
}

/// Run one `browser.capture_login` and journal it. The capture deletes its
/// throwaway profile before returning, and the record is written before the
/// reply, so neither a second copy of the session nor an unrecorded capture
/// exists when the caller hears back.
async fn capture_browser_login(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
    corr: u64,
    request: &login_capture::CaptureRequest,
) -> Value {
    // A cancel frame for this request, a Goodbye for its route, or the start
    // of a drain all end the capture with nothing written.
    let cancel = planes.cancellations.get((channel, epoch, corr));
    let draining = Arc::clone(&planes.draining);
    let outcome = planes
        .capture
        .run(
            request,
            login_capture::CaptureCall {
                accepted: facts,
                declares_elicitation: facts.declares_elicitation(),
                // The card is filed through the module's consent registry,
                // which holds the call for a bounded wait, keeps the card
                // open past it, and answers a retry from a late answer. The
                // deadline is the card's lifetime, which the registry owns.
                ask: |question: Value, _deadline| {
                    let ask_id = question["id"].as_str().unwrap_or_default().to_string();
                    planes.management.computer_grants().require_login(
                        login_consent_request(
                            planes,
                            facts,
                            writer,
                            (channel, epoch),
                            computer_grants::LoginCapability::CaptureLogin,
                            request.consent_parameters(),
                        ),
                        move || (ask_id.clone(), question.clone()),
                    )
                },
                cancelled: move || {
                    cancel.as_ref().is_some_and(CancelHandle::is_cancelled)
                        || draining.load(std::sync::atomic::Ordering::Acquire)
                },
            },
        )
        .await;
    // A deposit already made stays in the vault when this record cannot be
    // written: the vault cannot be asked to withdraw it, and its own audit
    // row, bound to the consent card's id, still describes it.
    if planes
        .browser
        .journal_login_capture(&facts.identity, outcome.journal)
        .await
        .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"journal_unavailable"});
    }
    outcome.reply
}

async fn present_browser_handoff(planes: &Planes, identity: &RouteIdentity, origin: &str) -> Value {
    let deadline_ms = planes
        .browser_config
        .as_ref()
        .map_or(30_000, |config| config.navigation_settle_deadline_ms);
    let presented = planes.sessions.present(
        &identity.conversation_key,
        origin,
        deadline_ms,
        planes.lease_clock.as_ref(),
    );
    let presented = match presented {
        Ok(presented) => presented,
        Err(browser_session::PresentRefusal::NoSession) => {
            return json!({"outcome":"no_session","remedy":"browser.launch"})
        }
        Err(browser_session::PresentRefusal::OriginMismatch { current_origin }) => {
            return json!({
                "outcome":"origin_mismatch",
                "current_origin":current_origin,
                "remedy":"browser.navigate",
            })
        }
        Err(browser_session::PresentRefusal::HandoffOpen) => {
            return json!({"outcome":"handoff_open","remedy":"browser.resume"})
        }
        Err(browser_session::PresentRefusal::PresentFailed { error_text }) => {
            return json!({
                "outcome":"present_failed",
                "error_text":error_text,
                "remedy":"browser.present",
            })
        }
    };

    if planes
        .browser
        .journal_handoff_opened(identity, origin)
        .await
        .is_err()
    {
        let _ = planes
            .sessions
            .resume(&identity.conversation_key, planes.lease_clock.as_ref());
        return json!({"outcome":"internal_failure"});
    }

    let sessions = planes.sessions.clone();
    let browser = Arc::clone(&planes.browser);
    let clock = Arc::clone(&planes.lease_clock);
    let identity = identity.clone();
    let route_key = identity.conversation_key.clone();
    let generation = presented.generation;
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(
                browser_session::HANDOFF_POLL_INTERVAL_MS,
            ))
            .await;
            let poll_sessions = sessions.clone();
            let poll_clock = Arc::clone(&clock);
            let poll_route = route_key.clone();
            let polled = tokio::task::spawn_blocking(move || {
                poll_sessions.poll_handoff(
                    &poll_route,
                    generation,
                    deadline_ms,
                    poll_clock.as_ref(),
                )
            })
            .await;
            match polled {
                Ok(browser_session::HandoffPollResult::Open) => {}
                Ok(browser_session::HandoffPollResult::Closed(close)) => {
                    let _ = browser.journal_handoff_closed(&identity, &close).await;
                    break;
                }
                Ok(browser_session::HandoffPollResult::Gone) | Err(_) => break,
            }
        }
    });

    json!({
        "outcome":"presented",
        "expires_in_ms":presented.expires_in_ms,
    })
}

#[doc(hidden)]
pub async fn present_browser_handoff_for_test(
    planes: &Planes,
    identity: &RouteIdentity,
    origin: &str,
) -> Value {
    present_browser_handoff(planes, identity, origin).await
}

async fn resume_browser_handoff(planes: &Planes, identity: &RouteIdentity) -> Value {
    let close = match planes
        .sessions
        .resume(&identity.conversation_key, planes.lease_clock.as_ref())
    {
        Ok(close) => close,
        Err(browser_session::ResumeRefusal::NoHandoff) => {
            return json!({"outcome":"no_handoff","remedy":"browser.present"})
        }
    };
    if close.should_journal {
        let _ = planes
            .browser
            .journal_handoff_closed(identity, &close)
            .await;
    }
    json!({
        "outcome":"resumed",
        "handoff":close.outcome.as_str(),
        "origin":close.origin,
    })
}

#[doc(hidden)]
pub async fn resume_browser_handoff_for_test(planes: &Planes, identity: &RouteIdentity) -> Value {
    resume_browser_handoff(planes, identity).await
}

async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
    elicitor: &elicit::Elicitor,
) -> Result<(), ModuleError> {
    let request = match serde_json::from_slice::<ModuleControlRequest>(&frame.body) {
        Ok(request) => request,
        // A control body this build does not recognise is answered on the
        // control channel and the loop goes on. Propagating the parse error
        // would end `module_loop`, which turns every future daemon-side
        // control op (a drain notice, for one) into an instant module exit,
        // the opposite of what an advisory notice asks for.
        Err(error) => {
            let frame = build_error_frame(
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                "unknown_control_op",
                &format!("cerebellum does not recognise this control request: {error}"),
            )
            .map_err(|e| ModuleError::Message(e.to_string()))?;
            return send(writer, frame).await;
        }
    };
    let response_body = match request {
        ModuleControlRequest::RouteBind {
            route_channel,
            epoch,
            principal,
            identity,
            admission_facts,
            consumer_capabilities,
            target,
            scope,
            // Cerebellum declares no versioned roles today.
            role_versions: _,
        } => {
            // Refuse non-first-party principals at bind; the only exception is a
            // Basal route that passes `flow_carrier_admitted`. The subc-mcp gateway
            // also keeps these tools off MCP surfaces. Whether a first-party caller
            // may act in a conversation is checked per call in
            // `send_session_caller_not_admitted`.
            let trust = trust_for_principal(&principal);
            if !trust.is_first_party()
                && !scope.as_ref().is_some_and(|stamp| {
                    cerebellum_core::identity::flow_carrier_admitted(stamp, &principal)
                })
            {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }

            // A capability scope stamped where it is no longer read would, if
            // ignored, leave the route with the permissive default scope. Refuse
            // the bind and bind nothing, so the route serves no request at all.
            if let Some(refusal) =
                AcceptedBindFacts::admission_facts_refusal(admission_facts.as_ref()).or_else(|| {
                    AcceptedBindFacts::scope_facts_refusal(
                        &principal,
                        scope.as_ref(),
                        admission_facts.as_ref(),
                    )
                })
            {
                let body = serde_json::to_vec(&subc_protocol::ErrorBody {
                    code: refusal.reason_code().to_string(),
                    message: refusal.message(),
                    detail: Some(refusal.detail()),
                })
                .map_err(ModuleError::Json)?;
                let frame = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Error,
                    control_flags(),
                    0,
                    0,
                    frame.header.corr,
                    body,
                )
                .map_err(|e| ModuleError::Message(e.to_string()))?;
                return send(writer, frame).await;
            }

            // Retain only facts from the accepted bind. Data-plane frames inherit
            // these facts by (channel, epoch); request bodies cannot replace them.
            let accepted_facts = AcceptedBindFacts::from_bind(
                &identity,
                principal.clone(),
                admission_facts.as_ref(),
                consumer_capabilities.as_deref(),
                &target,
            )
            // An authorized prefrontal-core scope stamp supplies identity and
            // delegation. Retaining it also lets call records name the scope
            // and lets its owner withdraw calls when the scope is revoked.
            .with_scope(scope);
            elicitor.set_unattended(
                route_channel,
                epoch,
                accepted_facts
                    .scope
                    .as_ref()
                    .is_some_and(|stamp| stamp.attributes.flow_id.is_some()),
            );
            route_bindings.insert(route_channel, epoch, accepted_facts);
            // Accept the bind — capability scope is checked at dispatch time.
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // Insulated health-v2 lane: the report is a mechanical mapper over
            // atomics stamped by the dispatch path. It never blocks on a lock
            // and never forms its own opinion (Health-Path-Rule-v2).
            with_process_gauges(health_state.report())
        }
    };
    let body = serde_json::to_vec(&response_body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        frame.header.ver,
        FrameType::Response,
        control_flags(),
        0,
        0,
        frame.header.corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

/// Send the pinned transport rejection for an ineligible principal.
async fn send_principal_denied(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    corr: u64,
    principal: &Option<subc_protocol::Principal>,
) -> Result<(), ModuleError> {
    let label = principal_label(principal);
    let frame = build_error_frame(
        ver,
        0,
        0,
        corr,
        "principal_denied",
        &format!(
            "cerebellum capabilities are first-party only; principal '{label}' is not eligible"
        ),
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

/// Refuse a call that would act in a conversation, made by a caller not
/// admitted to act in one.
///
/// Cerebellum's standing permissions (site grants, app grants, the takeover
/// grant) are keyed on the conversation a person gave them in. A route names
/// its conversation at bind, and every first-party module may open a route
/// under any conversation, so the conversation key alone would let AFT, Broca,
/// the routing module or a `direct` plugin reuse a permission the person gave
/// someone else, without being asked. Only Prefrontal's core module carries
/// sessions to cerebellum; everyone else is refused here.
///
/// Why at dispatch rather than at bind: a bind says who opened the route and
/// under which conversation, not which call will follow, and the operator's
/// own operations (see `is_operator_operation`) are legitimately served to
/// `direct` desk tools on routes that name a conversation. Refusing the bind
/// would refuse those too. So the bind is kept and every request is checked
/// against the daemon-stamped principal, at the one point in each surface's
/// handler where the request's name is known and nothing has yet read a grant,
/// asked a person or reserved a journal entry. The check reads only the
/// principal, so no fact a caller supplies can satisfy it.
async fn send_session_caller_not_admitted(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    facts: &AcceptedBindFacts,
) -> Result<(), ModuleError> {
    let label = principal_label(&facts.principal);
    let body = serde_json::to_vec(&ErrorBody {
        code: SESSION_CALLER_NOT_ADMITTED.to_string(),
        message: format!(
            "principal '{label}' is not admitted to act in a conversation: {}",
            SESSION_CALLER_NOT_ADMITTED_REMEDY
        ),
        detail: Some(json!({
            "principal": label,
            "remedy": SESSION_CALLER_NOT_ADMITTED_REMEDY,
        })),
    })
    .map_err(ModuleError::Json)?;
    let frame = Frame::build_with_version(
        ver,
        FrameType::Error,
        control_flags(),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

/// A tool-route request, with its optional `call_key` handled before the call
/// itself is.
///
/// A call carrying a key is recorded under `(route principal, call_key)`
/// before it can do anything, and a resend of the same key is answered from
/// that record instead of running again. A call without a key runs exactly as
/// it always has. `tool.withdraw` also arrives here: it is a tool-provider
/// operation on the same route, so it takes the tool envelope, never the
/// management one.
async fn handle_keyed_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    use journal::call_records::{self, Begin};

    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    // A body that does not decode, or is not an object, is left to the call's
    // own envelope check, which already refuses it by name.
    let Ok(Value::Object(mut object)) = serde_json::from_slice::<Value>(&frame.body) else {
        return handle_tool_request(frame, writer, planes, &CallObservation::new()).await;
    };
    let call_key = match object.remove("call_key") {
        None => None,
        Some(Value::String(key)) if call_records::valid_call_key(&key) => Some(key),
        Some(_) => {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_key",
                "wrong_type",
            )
            .await
        }
    };
    if object.get("name").and_then(Value::as_str) == Some(call_records::WITHDRAW_OPERATION) {
        // The key a withdrawal names is `arguments.call_key`. A second key on
        // the envelope would leave it unclear which call is meant.
        if call_key.is_some() {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_key",
                "unknown_field",
            )
            .await;
        }
        return handle_tool_withdraw(&object, (ver, channel, epoch, corr), writer, planes).await;
    }
    // Read once, here, so the call record and every audit row the call writes
    // carry the same value. An origin that fails validation never refuses the
    // call: it says who a relaying module claims to be acting for, which is
    // attribution, not authorization. It is recorded as absent with a marker
    // instead, and nothing below this point decides anything by it.
    let origin =
        cerebellum_core::journal::CallOriginRecord::from_request_member(object.get("origin"));
    let Some(call_key) = call_key else {
        return handle_tool_request(
            frame,
            writer,
            planes,
            &CallObservation::new().with_origin(origin),
        )
        .await;
    };
    let mut call = frame;
    call.body = serde_json::to_vec(&Value::Object(object)).map_err(ModuleError::Json)?;
    // Without an accepted bind there is no principal to record the call under.
    // Nothing is lost by not recording it: `handle_tool_request` refuses any
    // call on an unbound route (`route_not_bound`) before it does anything.
    let Some(facts) = planes.routes.get(channel, epoch) else {
        return handle_tool_request(
            call,
            writer,
            planes,
            &CallObservation::new().with_origin(origin),
        )
        .await;
    };
    let principal = call_records::principal_label(facts.principal.as_ref());
    // The call's record is synced to disk before the call may proceed. The write and
    // its fsync run on the blocking pool, not on this runtime thread, and the
    // call waits for them.
    let begun = {
        let calls = Arc::clone(&planes.calls);
        let conversation_key = facts.identity.conversation_key.clone();
        let call_key = call_key.clone();
        // The scope comes from the route's bind stamp, never from the request.
        let scope = facts
            .scope
            .as_ref()
            .map(call_records::ScopeIdentity::from_stamp);
        // Stored on a new record only; the record is still found by the
        // route's principal and the call key alone.
        let origin = origin.clone();
        tokio::task::spawn_blocking(move || {
            calls.begin_attributed(
                &principal,
                &call_key,
                &conversation_key,
                scope,
                origin,
                wall_clock_ms(),
            )
        })
        .await
        .unwrap_or_else(|error| {
            Begin::Unavailable(call_records::CallRecordError::WriteFailed(format!(
                "the record task did not finish: {error}"
            )))
        })
    };
    // A previous call result must not bypass current route admission. Preserve
    // that historical record, but do not expose its reply through a flow route.
    if !matches!(&begun, Begin::Execute(_)) {
        if let Some(refusal) = session_flow_refusal(&facts) {
            return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
        }
    }
    let ticket = match begun {
        Begin::Execute(ticket) => ticket,
        Begin::Replay(reply) => {
            return send(writer, reply.readdressed(ver, channel, epoch, corr)).await;
        }
        Begin::InFlight => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_in_flight",
                "a call with this call_key is still in flight; it is not run a second time. Wait \
                 for its reply, or ask what became of it with tool.withdraw",
            )
            .await;
        }
        Begin::NotRetained { outcome } => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_result_not_retained",
                &format!(
                    "a call with this call_key already replied with outcome '{}'; its result \
                     body is no longer retained, and the call is not run again",
                    outcome.as_deref().unwrap_or("unrecorded")
                ),
            )
            .await;
        }
        Begin::OutcomeUnknown => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_outcome_unknown",
                "a call with this call_key started and no reply was recorded (the module \
                 restarted or the route closed first); it may or may not have run, and it is \
                 not run again",
            )
            .await;
        }
        Begin::Unavailable(error) => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_record_unavailable",
                &format!(
                    "this call carries a call_key, and no record of it can be kept ({error}), so \
                     it was not run: a resend could not be told apart from a new call. Send it \
                     without a call_key to run it unprotected"
                ),
            )
            .await;
        }
    };

    // The call writes its frames into this channel rather than the route's, so
    // its terminal reply can be recorded before it is forwarded: a resend that
    // follows the reply must find it. Every other frame (a consent question,
    // say) is forwarded untouched.
    let (proxy, mut outgoing) = mpsc::channel::<Frame>(16);
    let mut pending = PendingSettlement {
        ticket: Some(ticket),
        observation: CallObservation::new().with_origin(origin),
        unattributed_at_start: cerebellum_core::dispatch_witness::unattributed_commit_count(),
        request: (channel, epoch, corr),
    };
    let result = {
        let observation = pending.observation.clone();
        let call = handle_tool_request(call, &proxy, planes, &observation);
        tokio::pin!(call);
        loop {
            tokio::select! {
                biased;
                Some(out) = outgoing.recv() => {
                    forward_recording_reply(out, &mut pending, writer, planes).await?;
                }
                result = &mut call => break result,
            }
        }
    };
    drop(proxy);
    while let Ok(out) = outgoing.try_recv() {
        forward_recording_reply(out, &mut pending, writer, planes).await?;
    }
    // No reply: the route closed while the call ran, so nobody is owed one.
    // The call may have acted, which is what the record now says.
    if let Some(ticket) = pending.ticket.take() {
        let calls = Arc::clone(&planes.calls);
        let _ = tokio::task::spawn_blocking(move || calls.settle_unknown(ticket, wall_clock_ms()))
            .await;
    }
    // A task the call started (a consent question still waiting for its answer)
    // can hold a clone of the channel past the call. Keep forwarding for it.
    let writer = writer.clone();
    tokio::spawn(async move {
        while let Some(out) = outgoing.recv().await {
            if send(&writer, out).await.is_err() {
                break;
            }
        }
    });
    result
}

/// What the tool handler watches while one request runs, so a keyed call's
/// record can say whether the action was dispatched, and who the request says
/// it was relayed for.
///
/// Armed for every tool request, keyed or not, so that in a running module a
/// dispatch commitment made under a detached witness always means a commit
/// site lost its request's witness.
#[derive(Clone)]
struct CallObservation {
    /// Marked at a plane's dispatch commitment for this request.
    dispatch: cerebellum_core::dispatch_witness::DispatchWitness,
    /// Set just before the request is handed to a plane every one of whose
    /// dispatches passes a commitment that marks `dispatch`.
    commit_point: Arc<std::sync::atomic::AtomicBool>,
    /// The request's `origin`, already validated, for the audit rows the call
    /// writes. Attribution only: admission reads the route's own facts.
    origin: cerebellum_core::journal::CallOriginRecord,
}

impl CallObservation {
    fn new() -> Self {
        Self {
            dispatch: cerebellum_core::dispatch_witness::DispatchWitness::armed(),
            commit_point: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            origin: cerebellum_core::journal::CallOriginRecord::Absent,
        }
    }

    fn with_origin(mut self, origin: cerebellum_core::journal::CallOriginRecord) -> Self {
        self.origin = origin;
        self
    }

    fn commit_point_follows(&self) {
        self.commit_point
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// A keyed call whose reply has not been recorded yet.
struct PendingSettlement {
    ticket: Option<journal::call_records::CallTicket>,
    observation: CallObservation,
    unattributed_at_start: u64,
    request: (u16, u32, u64),
}

/// Return true for replies sent by `handle_tool_request` before dispatch or
/// for a provider resource-busy refusal; neither case dispatched the tool.
fn refused_before_dispatch(reply: &Frame) -> bool {
    let body: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    match reply.header.ty {
        // The envelope and argument checks answer in the reply body.
        FrameType::Response => {
            matches!(
                body["outcome"].as_str(),
                Some("invalid_request" | "resource_busy")
            ) || (body["outcome"] == "consent_unavailable"
                && matches!(
                    body["detail"]["reason"].as_str(),
                    Some(
                        "flow_carrier_not_admitted" | "unattended_flow" | "takeover_not_for_flows"
                    )
                ))
        }
        FrameType::Error => body["code"].as_str().is_some_and(|code| {
            [
                "invalid_request",
                "route_not_bound",
                "capability_denied",
                "computer_plane_unavailable",
                "request_not_interruptible",
                cerebellum_core::principal::SESSION_CALLER_NOT_ADMITTED,
                CapabilityWithheld::Unknown.reason_code(),
                CapabilityWithheld::BrowserNotConfigured.reason_code(),
                CapabilityWithheld::NotAdmitted.reason_code(),
            ]
            .contains(&code)
        }),
        _ => false,
    }
}

/// Forward one frame of a keyed call, recording the call's reply first when
/// this frame is that reply.
async fn forward_recording_reply(
    out: Frame,
    pending: &mut PendingSettlement,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let is_reply = matches!(out.header.ty, FrameType::Response | FrameType::Error)
        && (out.header.channel, out.header.epoch, out.header.corr) == pending.request;
    if is_reply {
        if let Some(ticket) = pending.ticket.take() {
            let evidence = journal::call_records::DispatchEvidence {
                committed: pending.observation.dispatch.committed(),
                commit_point: pending
                    .observation
                    .commit_point
                    .load(std::sync::atomic::Ordering::SeqCst),
                unattributed_commit: cerebellum_core::dispatch_witness::unattributed_commit_count()
                    != pending.unattributed_at_start,
                refused_before_dispatch: refused_before_dispatch(&out),
            };
            // The call's record is written before its reply is forwarded, on
            // the blocking pool.
            let calls = Arc::clone(&planes.calls);
            let settlement = journal::call_records::Settlement::from_reply(&out, evidence);
            let _ = tokio::task::spawn_blocking(move || {
                calls.settle(ticket, settlement, wall_clock_ms())
            })
            .await;
        }
    }
    send(writer, out).await
}

/// `tool.withdraw {call_key, scope?, carrier?}`: what became of a recorded
/// call, and, for one that only asked a person, the question closed so it can
/// never act.
///
/// The answer is read from the record, so it is the same for every repeat and
/// for every caller permitted to ask. Two callers are permitted:
/// - the principal that raised the call (its carrier), as always;
/// - the owner of the session scope the call was recorded under, when the
///   daemon's stamp on the owner's own route says the owner is authorized
///   (`owner_authorized`), the route's principal is that owner, the call was
///   recorded under the same `(owner, ref, scope_epoch)`, and the request names
///   the carrier in `arguments.carrier`. The lookup stays exact on
///   `(carrier, call_key)`: a key is never matched on its own.
///
/// Everyone else is refused `withdraw_not_permitted`.
async fn handle_tool_withdraw(
    object: &serde_json::Map<String, Value>,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    use journal::call_records::{self, Lookup, ScopeIdentity};

    let invalid = |field: &str, reason: &'static str| Err((field.to_string(), reason));
    let checked = (|| {
        if let Some(field) = object
            .keys()
            .filter(|field| !matches!(field.as_str(), "name" | "arguments" | "progress_token"))
            .min()
        {
            return Err((field.clone(), "unknown_field"));
        }
        let arguments = match object.get("arguments") {
            None => return invalid("arguments", "missing_field"),
            Some(Value::Object(arguments)) => arguments,
            Some(_) => return invalid("arguments", "wrong_type"),
        };
        if let Some(field) = arguments
            .keys()
            .filter(|field| !matches!(field.as_str(), "call_key" | "scope" | "carrier"))
            .min()
        {
            return Err((format!("arguments.{field}"), "unknown_field"));
        }
        let call_key = match arguments.get("call_key") {
            None => return invalid("arguments.call_key", "missing_field"),
            Some(Value::String(key)) if call_records::valid_call_key(key) => key.clone(),
            Some(_) => return invalid("arguments.call_key", "wrong_type"),
        };
        // Only the shape is checked here. A scope named in the request is the
        // caller's own claim; below it is compared with the route's stamp and
        // never used in its place.
        let named_scope = match arguments.get("scope") {
            None => None,
            Some(scope) => {
                let named = scope.as_object().and_then(|scope| {
                    (scope.len() == 3).then_some(())?;
                    Some(ScopeIdentity {
                        owner: scope.get("owner")?.as_str()?.to_string(),
                        reference: scope.get("ref")?.as_str()?.to_string(),
                        scope_epoch: scope.get("scope_epoch")?.as_u64()?,
                    })
                });
                match named {
                    Some(named) => Some(named),
                    None => return invalid("arguments.scope", "wrong_type"),
                }
            }
        };
        // The carrier is a principal label such as `reserved:prefrontal-core`,
        // the form call records are kept under.
        let carrier = match arguments.get("carrier") {
            None => None,
            Some(Value::String(carrier)) if !carrier.is_empty() => Some(carrier.clone()),
            Some(_) => return invalid("arguments.carrier", "wrong_type"),
        };
        Ok((call_key, named_scope, carrier))
    })();
    let (call_key, named_scope, carrier) = match checked {
        Ok(checked) => checked,
        Err((field, reason)) => {
            return send_invalid_request_response(writer, ver, channel, epoch, corr, &field, reason)
                .await
        }
    };
    let Some(facts) = planes.routes.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "tool.withdraw requires an accepted route.bind",
        )
        .await;
    };
    let principal = call_records::principal_label(facts.principal.as_ref());
    let stamped = facts.scope.as_ref().map(ScopeIdentity::from_stamp);
    // A scope named in the request must be the one the daemon stamped on this
    // route. A mismatch is refused rather than resolved by preferring either:
    // the caller and the daemon disagree about which session this is. A route
    // opened without a scope has no stamp to compare with, and is answered as
    // it was before scopes.
    if let (Some(named), Some(stamped)) = (named_scope.as_ref(), stamped.as_ref()) {
        if named != stamped {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "arguments.scope",
                "unsupported_value",
            )
            .await;
        }
    }
    // The caller is its route's scope owner when the stamp names the route's
    // own principal as the owner. Whether that owner may act for its scope is
    // the daemon's `owner_authorized`, and nothing cerebellum keeps.
    let owner_stamp = facts
        .scope
        .as_ref()
        .filter(|stamp| facts.principal.as_ref() == Some(&stamp.owner));
    let lookup = match carrier.as_deref() {
        // Naming another principal's call is the owner's arm and nobody else's.
        Some(carrier) if carrier != principal => match owner_stamp {
            Some(stamp) if stamp.owner_authorized => {
                let scope = ScopeIdentity::from_stamp(stamp);
                match planes.calls.lookup_exact(carrier, &call_key) {
                    // Recorded under this owner's scope at this epoch: the
                    // owner gets exactly the answer the carrier would.
                    Lookup::Own(snapshot) if snapshot.scope.as_ref() == Some(&scope) => {
                        Lookup::Own(snapshot)
                    }
                    // Recorded under no scope, another scope, or an earlier
                    // session under the same ref: not this owner's call.
                    Lookup::Own(_) | Lookup::OtherPrincipal => Lookup::OtherPrincipal,
                    other => other,
                }
            }
            // The owner, but the daemon does not authorize it to act for its
            // scope.
            Some(_) => Lookup::OtherPrincipal,
            // A carrier may name only itself.
            None => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "arguments.carrier",
                    "unsupported_value",
                )
                .await
            }
        },
        // The caller's own call, which is today's rule and needs no scope.
        named_self => match planes.calls.lookup(&principal, &call_key) {
            Lookup::Own(snapshot) => Lookup::Own(snapshot),
            // An authorized owner asking about a call it did not raise must
            // say whose it is: the lookup is exact on the carrier, so without
            // one there is nothing to look up.
            _ if named_self.is_none()
                && owner_stamp.is_some_and(|stamp| stamp.owner_authorized) =>
            {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "arguments.carrier",
                    "missing_field",
                )
                .await
            }
            other => other,
        },
    };
    match lookup {
        Lookup::Own(snapshot) => {
            let answer = call_records::withdraw_answer(&snapshot);
            // The held action has already returned without executing. Stopping
            // the turn is not a refusal: its card may still record a late grant,
            // but acting on that grant requires a new call.
            send_tool_response(writer, ver, channel, epoch, corr, answer).await
        }
        Lookup::Unknown => {
            send_tool_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                json!({"answer": "unknown_call"}),
            )
            .await
        }
        Lookup::OtherPrincipal => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "withdraw_not_permitted",
                "only the principal that raised a call, or the authorized owner of the scope it \
                 was recorded under, may withdraw it",
            )
            .await
        }
        Lookup::Unavailable(error) => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "call_record_unavailable",
                &format!("the call records cannot be read ({error})"),
            )
            .await
        }
    }
}

async fn handle_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    call: &CallObservation,
) -> Result<(), ModuleError> {
    let route_bindings = &planes.routes;
    let channel = frame.header.channel;
    let epoch = frame.header.epoch;
    let corr = frame.header.corr;
    let ver = frame.header.ver;

    let request: serde_json::Value = match serde_json::from_slice(&frame.body) {
        Ok(v) => v,
        Err(e) => {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "invalid_request",
                &format!("request body not decodable: {e}"),
            )
            .await;
        }
    };

    let Some(object) = request.as_object() else {
        return send_invalid_request_response(writer, ver, channel, epoch, corr, "$", "wrong_type")
            .await;
    };

    // Tool-route envelopes are closed: a member not listed here is refused by
    // name as `unknown_field`. `progress_token` is an optional gateway
    // member, accepted for correlation but not used here. `origin` names the
    // caller behind a relayed call; it was read before this handler (see
    // `handle_keyed_tool_request`) and reaches it only through `call`.
    if let Some(field) = object
        .keys()
        .filter(|field| {
            !matches!(
                field.as_str(),
                "name" | "arguments" | "progress_token" | "origin" | "preset"
            )
        })
        .min()
    {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            field,
            "unknown_field",
        )
        .await;
    }

    // This provider declares no presets. An absent or null preset preserves
    // the existing service; it never selects a more capable preset implicitly.
    if let Some(preset) = object.get("preset").filter(|value| !value.is_null()) {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            json!({
                "outcome": "invalid_request",
                "context": null,
                "session": null,
                "detail": {
                    "field": "preset",
                    "reason_code": "unsupported_value",
                    "value": preset,
                },
            }),
        )
        .await;
    }

    let Some(name_value) = object.get("name") else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "name",
            "missing_field",
        )
        .await;
    };
    let Some(name) = name_value.as_str() else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "name",
            "wrong_type",
        )
        .await;
    };

    // Route admission is completed before decoding capability arguments.
    // Admitted routes may proceed to their handlers; denied routes perform no
    // reservation, context lookup, grant lookup, or CDP work.
    let known_capability = dispatchable_tool_with_browser(name, planes.browser_config.is_some());
    let Some(capability_name) = known_capability else {
        // Say WHICH kind of unavailable. A caller who named something this build
        // withholds and a caller who named something invented both arrive here,
        // and only one of them can do anything about it.
        let withheld = capability_withheld(name, planes.browser_config.is_some())
            .unwrap_or(CapabilityWithheld::Unknown);
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            withheld.reason_code(),
            &format!("'{name}' is not served here: {}", withheld.remedy()),
        )
        .await;
    };

    let Some(mut accepted_facts) = route_bindings.get(channel, epoch) else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "route_not_bound",
            "browser capability requires an accepted route.bind",
        )
        .await;
    };
    // This request's copy of the route identity carries its own witness, so a
    // browser dispatch committed for it marks this request and no other.
    accepted_facts.identity.witness = call.dispatch.clone();
    // And its own origin, so every audit row written for it names the caller
    // behind it. Set after the route lookup and read by nothing below that
    // admits, refuses or keys the call.
    accepted_facts.identity.origin = call.origin.clone();
    // Session admission, before the capability scope and before anything
    // below reads a grant, asks a person or reserves a journal entry; see
    // `send_session_caller_not_admitted`. Every tool call acts in the route's
    // conversation, so no tool is served outside one.
    if let Some(refusal) = session_flow_refusal(&accepted_facts) {
        return send_tool_response(writer, ver, channel, epoch, corr, refusal).await;
    }
    if !accepted_facts.admits_session_calls() {
        return send_session_caller_not_admitted(
            writer,
            ver,
            channel,
            epoch,
            corr,
            &accepted_facts,
        )
        .await;
    }
    if !accepted_facts.allows_capability(capability_name) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "capability_denied",
            "capability is outside the effective capability scope",
        )
        .await;
    }

    let Some(arguments) = object.get("arguments") else {
        return send_invalid_request_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "arguments",
            "missing_field",
        )
        .await;
    };

    let translated = if name == flat_tools::COMPUTER_USE {
        match flat_tools::translate_computer(arguments) {
            Ok(dispatch) => Some(dispatch),
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        }
    } else if name == flat_tools::BROWSER_USE {
        match flat_tools::translate_browser(arguments) {
            Ok(dispatch) => Some(dispatch),
            Err(error) => {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    &error.field,
                    error.reason,
                )
                .await
            }
        }
    } else {
        None
    };
    if let Some(flat_tools::FlatDispatch::Management { method, params }) = translated.as_ref() {
        let mut management_frame = frame.clone();
        management_frame.body = serde_json::to_vec(&json!({
            "method": method,
            "params": params,
        }))
        .expect("flat management request serializes");
        return handle_management_request(management_frame, writer, &accepted_facts, planes).await;
    }
    let (name, arguments) = match translated.as_ref() {
        Some(flat_tools::FlatDispatch::Computer {
            capability,
            arguments,
        })
        | Some(flat_tools::FlatDispatch::Browser {
            capability,
            arguments,
        }) => (capability.as_str(), arguments),
        Some(flat_tools::FlatDispatch::Management { .. }) => unreachable!("returned above"),
        None => (name, arguments),
    };

    if accepted_facts.flow_id.is_some() && !accepted_facts.acts_as_agent {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("unattended_flow"),
        )
        .await;
    }
    if accepted_facts.flow_id.is_some()
        && matches!(
            name,
            "computer.takeover_move" | "computer.takeover_drag" | "computer.takeover_scroll"
        )
    {
        return send_tool_response(
            writer,
            ver,
            channel,
            epoch,
            corr,
            flow_consent_refusal("takeover_not_for_flows"),
        )
        .await;
    }
    if browser_session::CONTROL_TOOLS.contains(&name) {
        // The admission refusal is a reply of this capability like any other,
        // so it goes through the same boundary. A refusal returned from above
        // `finish_reply` is never checked against the declared vocabulary, and
        // it is the reply a caller on a misconfigured route receives first.
        let result = match accepted_facts.control_operation_refusal(name) {
            Some(refusal) => json!({
                "outcome": "authorization_denied",
                "reason": refusal.reason_code(),
                "remedy": accepted_facts.control_refusal_remedy(refusal),
            }),
            None => handle_browser_control(name, arguments, &accepted_facts, planes).await,
        };
        return match planes.browser.finish_reply(name, result) {
            Ok(result) => send_tool_response(writer, ver, channel, epoch, corr, result).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!(
                        "the capability reply violated its frozen result schema ({error}); the \
                         operation may already have completed, so do not retry it based on this \
                         response"
                    ),
                )
                .await
            }
        };
    }

    // Routed by which plane serves the capability, before the browser handler
    // sees it. The two planes share a request envelope and nothing else, so a
    // computer capability reaching the browser handler would be reported as an
    // unknown method -- a refusal that describes the wrong subsystem.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if let Some(servable) = computer_capability::servable(name) {
        let clock = planes.lease_clock.as_ref();

        // Refused unless the release gates admitted it, so serving and
        // advertising answer to the same authority.
        //
        // Withholding a capability from the manifest is not by itself a gate.
        // Every capability name is fixed in the action vocabulary, which is a
        // published artifact, so a caller can name one without having seen it
        // in a manifest -- and before this check such a request was served.
        //
        // The code is the same one the browser plane answers for a withheld
        // tool, because it means the same thing: this build knows the name and
        // does not serve it. A consumer keys its handling on the code, and two
        // spellings of one fact would force it to keep a per-plane list.
        if !planes.computer_admitted.contains(name) {
            let withheld = CapabilityWithheld::NotAdmitted;
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                withheld.reason_code(),
                &format!("'{name}' is not served here: {}", withheld.remedy()),
            )
            .await;
        }

        // Distinct from withheld: the capability IS admitted, and this host
        // could not build the plane that serves it (an audit journal that will
        // not open, for instance). A caller can do nothing about a build that
        // withholds; an operator can do something about a host that cannot.
        let plane = match planes.computer.as_ref() {
            Ok(plane) => plane,
            Err(reason) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "computer_plane_unavailable",
                    &format!("the computer plane could not be built on this host: {reason}"),
                )
                .await;
            }
        };
        // Every production request registers its cancellation entry before the
        // task that reaches here is spawned, so the absent case is a module bug
        // rather than anything a caller can cause. It is a refusal and not an
        // `expect` because the invariant lives at a DIFFERENT call site than the
        // one that depends on it: a second entry point added later would satisfy
        // the compiler, panic in a spawned task, and leave an indeterminate
        // audit record instead of saying what was wrong. Refusing also cannot be
        // mistaken for the other repair: handing out a never-cancels handle here
        // would make the request uninterruptible and look like success.
        let Some(cancel) = planes.cancellations.get((channel, epoch, corr)) else {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "request_not_interruptible",
                "this request was not registered for interruption before dispatch; \
                 it was refused rather than served without a way to stop it",
            )
            .await;
        };
        // Every computer capability passes the audit journal's dispatch
        // commitment before its first input, so an unmarked witness after this
        // point means nothing was dispatched.
        call.commit_point_follows();
        let result = plane
            .serve(
                servable,
                arguments,
                computer_capability::ServeContext {
                    cancel,
                    // The durable agent identity, taken from the accepted bind
                    // rather than from the request: an identity a caller could
                    // choose is a lease granted to whoever asks for it.
                    grantee: &accepted_facts.identity.agent_project_id,
                    identity: cerebellum_core::journal::JournalIdentity {
                        witness: call.dispatch.clone(),
                        principal: accepted_facts
                            .principal
                            .as_ref()
                            .map(|principal| format!("{principal:?}"))
                            .unwrap_or_default(),
                        conversation_key: accepted_facts.identity.conversation_key.clone(),
                        agent_project_id: accepted_facts.identity.agent_project_id.clone(),
                        session_kind: accepted_facts.identity.session_kind,
                        origin: accepted_facts.identity.origin.clone(),
                    },
                    management: &planes.management,
                    consent: consent_context(planes, &accepted_facts, writer, channel, epoch),
                    clock,
                    // Wall-clock rather than the lease clock: this stamps a
                    // journal entry a person may later read against other
                    // records, where the lease clock only answers whether one
                    // moment came after another inside this process.
                    now_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|since| since.as_millis() as u64)
                        .unwrap_or_default(),
                },
                |_grant| computer_capability::native_capture_backend(),
            )
            .await;
        // A call whose route unbound while it waited on a person has nobody
        // to answer; its reply is dropped rather than sent to a closed route.
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return match result {
            Ok(result) => send_tool_response(writer, ver, channel, epoch, corr, result).await,
            Err(error) => {
                send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    "computer_result_schema_violation",
                    &format!(
                        "the capability reply violated its frozen result schema ({error}); the \
                         operation may already have completed, so do not retry it based on this \
                         response"
                    ),
                )
                .await
            }
        };
    }

    // ADMISSION AT THE TOP OF THIS FUNCTION ALREADY MADE THIS PARSE TOTAL, and
    // that is the problem with leaving the branch to something else: the
    // invariant lives in `dispatchable_tool_with_browser`, a different function
    // in a different part of this file, and a change there resurrects this arm
    // for whoever is reading THAT code. So this answers rather than delegating,
    // and it answers the SAME route-level envelope the admission check sends --
    // a resurrection then returns the reply the wire already documents instead
    // of a second spelling nobody tests.
    //
    // It used to call `browser::handle_tool`, which re-parsed the name it had
    // just been told does not parse and could therefore only ever return a
    // reply BODY of `{"outcome": "unknown_method"}` -- no `context`, which
    // `reply_schema` makes required, so it would have failed its own schema had
    // anything validated it. That helper is gone; nothing else called it.
    let Some(capability) = browser::BrowserCapability::parse(name) else {
        let withheld = CapabilityWithheld::Unknown;
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            withheld.reason_code(),
            &format!("'{name}' is not served here: {}", withheld.remedy()),
        )
        .await;
    };
    // These browser capabilities all pass `BrowserPlane::commit` before any
    // CDP command. `wait_for` has no dispatch commitment, so for it an
    // unmarked witness proves nothing.
    if capability != browser::BrowserCapability::WaitFor {
        call.commit_point_follows();
    }
    let result = serve_browser_with_consent(
        planes,
        &accepted_facts,
        writer,
        (channel, epoch, corr),
        capability,
        arguments,
        BROWSER_CONSENT_PARK_LIMIT
            .try_with(|limit| *limit)
            .unwrap_or(Duration::from_secs(120)),
    )
    .await;
    if planes.routes.get(channel, epoch).is_none() {
        return Ok(());
    }
    match result {
        Ok(result) => send_tool_response(writer, ver, channel, epoch, corr, result).await,
        Err(error) => {
            send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                browser::RESULT_SCHEMA_VIOLATION_CODE,
                &format!(
                    "the capability reply violated its frozen result schema ({error}); the \
                     operation may already have completed, so do not retry it based on this \
                     response"
                ),
            )
            .await
        }
    }
}

tokio::task_local! {
    static BROWSER_CONSENT_PARK_LIMIT: Duration;
}

/// Exercise the production dispatch with a shorter inline wait, without changing
/// the lifetime of the question that must still accept a late answer.
#[doc(hidden)]
pub async fn handle_browser_consent_deadline_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    deadline: Duration,
) -> Result<(), ModuleError> {
    BROWSER_CONSENT_PARK_LIMIT
        .scope(
            deadline,
            handle_tool_request_for_test_with_existing_planes(frame, writer, planes),
        )
        .await
}

/// Ask only after dispatch has returned its refusal and released its conversation
/// lane and session operation guard. A person reading a question must not block
/// another request or the session's idle sweep.
async fn serve_browser_with_consent(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    request: (u16, u32, u64),
    capability: browser::BrowserCapability,
    arguments: &Value,
    park_limit: Duration,
) -> Result<Value, cerebellum_computer::platform::vocabulary::CapabilityResultValidationError> {
    let mut reply = authorization::with_flow(
        facts.flow_id.is_some(),
        authorization::with_standing_caller(
            standing_caller(facts),
            planes.browser.serve(&facts.identity, capability, arguments),
        ),
    )
    .await?;
    let Some(scope) = reply.pointer("/detail/grant_request") else {
        return Ok(reply);
    };
    if facts.flow_id.is_some() {
        reply["outcome"] = json!("consent_unavailable");
        reply["detail"] = json!({"reason": "unattended_flow"});
        reply["remedy"] =
            json!("an unattended flow cannot ask a person; configure its owner's standing grant");
        return planes.browser.finish_reply(capability.name(), reply);
    }
    if !facts.declares_elicitation() {
        return Ok(reply);
    }
    let Some(cancel) = planes.cancellations.get(request) else {
        return Ok(reply);
    };
    let origins = scope["origins"].as_array().and_then(|values| {
        values
            .iter()
            .map(|value| value.as_str().map(str::to_owned))
            .collect::<Option<Vec<_>>>()
    });
    let hazards = scope["hazards"].as_array().and_then(|values| {
        values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .and_then(authorization::HazardClass::from_wire)
            })
            .collect::<Option<Vec<_>>>()
    });
    let tier = scope["severity_tier"]
        .as_u64()
        .and_then(|tier| u8::try_from(tier).ok());
    let (Some(origins), Some(hazards), Some(tier)) = (origins, hazards, tier) else {
        return Ok(reply);
    };
    let Ok((mut pending, Some(question))) = planes
        .management
        .open_in_call_browser_grant(
            &facts.identity.conversation_key,
            origins,
            hazards,
            Some(tier),
            standing_offer_agent(facts),
        )
        .await
    else {
        return Ok(reply);
    };
    let elicitor = Arc::clone(&planes.elicitor);
    let management = Arc::clone(&planes.management);
    let writer = writer.clone();
    let mut drain = planes.drain_signal.subscribe();
    let routes = Arc::clone(&planes.routes);
    let (channel, epoch, _) = request;
    // Keep the question alive after the call's wait expires so a late approval
    // still creates the browser grant. Cancellation, route closure and shutdown
    // instead remove the pending question from the answer registry.
    let mut settlement = tokio::spawn(async move {
        // `Err` names how the question was withdrawn before it ended.
        let ending = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err("cancelled"),
            _ = routes.closed(channel, epoch) => Err("route_closed"),
            _ = drain.wait_for(|draining| *draining) => Err("draining"),
            outcome = elicitor.ask(&writer, channel, epoch, question.body, question.deadline) => Ok(outcome),
        };
        let settled = management
            .settle_browser_grant_outcome(&question.ask_id, ending.as_ref().ok())
            .await;
        match (&ending, settled) {
            (_, management::BrowserGrantSettlement::Granted(_)) => "allow",
            // A granting answer whose grant was not recorded, or that came to
            // a question no longer held (withdrawn with its conversation
            // meanwhile), grants nothing.
            (
                _,
                management::BrowserGrantSettlement::NotRecorded { .. }
                | management::BrowserGrantSettlement::UnknownAsk,
            ) => "unavailable",
            (_, management::BrowserGrantSettlement::UnrecognizedAnswer) => "unrecognized_answer",
            (Ok(outcome), management::BrowserGrantSettlement::NotGranted) => {
                in_call_grant_decision(outcome)
            }
            (Err(withdrawn), management::BrowserGrantSettlement::NotGranted) => *withdrawn,
        }
    });
    let guard = elicit::ROUTE_GUARD.try_with(Arc::clone).ok();
    let parked = guard.as_ref().map(|guard| guard.park_on_consent());
    let answer = tokio::time::timeout(park_limit, &mut settlement).await;
    drop(parked);
    match answer {
        Ok(Ok("allow")) => {
            // Re-enter normal authorization, rather than treating the answer as
            // authority: the session or its origin may have changed meanwhile.
            authorization::with_standing_caller(
                standing_caller(facts),
                planes.browser.serve(&facts.identity, capability, arguments),
            )
            .await
        }
        Ok(decision) => {
            let decision = decision.unwrap_or("unavailable");
            reply["detail"]["decision"] = json!(decision);
            if let Some(remedy) = in_call_grant_remedy(decision) {
                reply["remedy"] = json!(remedy);
            }
            planes.browser.finish_reply(capability.name(), reply)
        }
        Err(_) => {
            pending["context"] = reply["context"].clone();
            planes.browser.finish_reply(capability.name(), pending)
        }
    }
}

/// Standing browser rows may authorize this route only when its agent is
/// daemon-attested and the route may act for that agent, never for an identity
/// taken from the caller-controlled project-root fallback.
fn standing_caller(facts: &AcceptedBindFacts) -> Option<authorization::StandingCaller> {
    (facts.agent_project_id_attested && facts.acts_as_agent).then(|| {
        authorization::StandingCaller {
            agent_id: facts.identity.agent_project_id.clone(),
        }
    })
}

/// The agent a site-access card on this route may offer standing answers for:
/// a primary session acting for its daemon-attested agent and session kind.
/// Worker and ephemeral sessions are offered this conversation only.
fn standing_offer_agent(facts: &AcceptedBindFacts) -> Option<&str> {
    (facts.flow_id.is_none()
        && facts.agent_project_id_attested
        && facts.acts_as_agent
        && facts.session_kind_attested
        && facts.identity.session_kind == cerebellum_core::identity::SessionKind::Primary)
        .then_some(facts.identity.agent_project_id.as_str())
}

/// The `detail.decision` a browser action held open on a grant question
/// reports when the question ended without an allowing answer.
///
/// Each ending keeps its own word because each calls for a different next
/// step; reporting a question nobody was shown the same way as one a person
/// ignored would send the caller to wait for an answer that cannot come.
fn in_call_grant_decision(ending: &elicit::AskOutcome) -> &'static str {
    match ending {
        elicit::AskOutcome::Answered(answer) => match answer["decision"].as_str() {
            Some("deny") => "declined",
            _ => "unrecognized_answer",
        },
        elicit::AskOutcome::NoAnswer => "no_answer",
        elicit::AskOutcome::NotPutToAnyone => "not_put_to_anyone",
        elicit::AskOutcome::Undeliverable => "undeliverable",
    }
}

/// What the caller should do after each [`in_call_grant_decision`]. It replaces
/// the remedy the `authorization_denied` refusal already carries (open the
/// grant and retry), which is right only for a question a person might still
/// answer. `None` keeps that remedy: the question was cancelled, its route
/// closed, or the module began draining before the question ended, so nothing
/// was decided.
fn in_call_grant_remedy(decision: &str) -> Option<&'static str> {
    match decision {
        "declined" => Some("the person declined this grant; ask again only if they change their mind"),
        "no_answer" => Some("the person was asked but did not answer in time; retry this action when they are available"),
        "not_put_to_anyone" => Some("the question was shown to no one, and repeating this action puts it to no one either until the caller's consent route can put it to a person"),
        "undeliverable" => Some("the question could not be sent; retry once, and if it fails again the module needs attention"),
        "unrecognized_answer" => Some("the answer was not one this question offered; retry this action to ask again"),
        _ => None,
    }
}

async fn handle_browser_control(
    name: &str,
    arguments: &Value,
    accepted: &AcceptedBindFacts,
    planes: &Planes,
) -> Value {
    let Some(config) = planes.browser_config.as_ref() else {
        return json!({"outcome": "internal_failure"});
    };
    let clock = planes.lease_clock.as_ref();
    match name {
        browser_session::BROWSER_STATUS => {
            if let Some(invalid) = browser_session::validate_empty_object(arguments) {
                return invalid;
            }
            planes.sessions.status(
                &accepted.identity.conversation_key,
                clock,
                std::time::SystemTime::now(),
            )
        }
        browser_session::BROWSER_CLOSE => {
            let browser_session_id = match browser_session::validate_close(arguments) {
                Ok(id) => id,
                Err(invalid) => return invalid,
            };
            let result = planes.sessions.close(
                &accepted.identity.conversation_key,
                browser_session_id,
                config,
            );
            if result["outcome"] == "closed" {
                planes.browser.end_context(&accepted.identity, false).await;
            }
            result
        }
        browser_session::BROWSER_LAUNCH => {
            if let Some(invalid) = browser_session::validate_empty_object(arguments) {
                return invalid;
            }
            if accepted.identity.profile_disposition == ProfileDisposition::None {
                return json!({"outcome": "no_profile", "profile_disposition": "none"});
            }
            let browser_session_id = match planes
                .sessions
                .acquire_launch_slot(&accepted.identity.conversation_key)
            {
                browser_session::LaunchSlot::Occupied { browser_session_id } => {
                    return json!({
                        "outcome": "browser_session_exists",
                        "browser_session_id": browser_session_id,
                    })
                }
                browser_session::LaunchSlot::Acquired { browser_session_id } => browser_session_id,
                browser_session::LaunchSlot::Refused(refusal) => return refusal,
            };
            let launch = if let Some(service) = planes.launch_service.clone() {
                let accepted = accepted.clone();
                let id = browser_session_id.clone();
                match tokio::task::spawn_blocking(move || {
                    let holder = accepted
                        .flow_id
                        .as_ref()
                        .map_or_else(cortexkit_resource_busy::Holder::head, |flow_id| {
                            cortexkit_resource_busy::Holder::flow(flow_id.clone())
                        });
                    profile_custody::with_lease_holder(holder, || service.launch(&accepted, &id))
                })
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(json!({"outcome": "internal_failure"})),
                }
            } else if config.executable_path.is_none() {
                Err(json!({"outcome": "executable_missing"}))
            } else if let Some(path) = config
                .executable_path
                .as_ref()
                .filter(|path| !path.is_file())
            {
                Err(json!({"outcome": "executable_missing", "expected_path": path}))
            } else {
                // No launcher exists, and the configuration is correct -- the
                // executable is present and is a file. Every other arm of this
                // chain names something the operator got wrong; this one is
                // reached BECAUSE they got it right, so blaming profile storage
                // sent them to check a disk that was never involved. The build
                // simply has no launcher wired for this platform.
                Err(json!({
                    "outcome": "browser_launch_unsupported",
                    "reason": "this build has no browser launcher for this platform",
                    "platform": std::env::consts::OS,
                }))
            };
            match launch {
                Ok(browser_session::LaunchedBrowser {
                    process,
                    cleanup,
                    executable_identity_checkpoints,
                }) => {
                    let Some((id, lease, cancelled)) = planes.sessions.establish_ready(
                        &accepted.identity.conversation_key,
                        accepted.identity.profile_disposition,
                        config,
                        clock,
                        process,
                        cleanup,
                    ) else {
                        planes
                            .sessions
                            .abandon_launch_slot(&accepted.identity.conversation_key);
                        planes.browser.end_context(&accepted.identity, false).await;
                        return json!({"outcome": "internal_failure"});
                    };
                    if cancelled {
                        let sessions = planes.sessions.clone();
                        let route_key = accepted.identity.conversation_key.clone();
                        let _ = tokio::task::spawn_blocking(move || {
                            sessions.wait_until_inactive(&route_key)
                        })
                        .await;
                        planes.browser.end_context(&accepted.identity, false).await;
                        return json!({
                            "outcome": "launch_cancelled",
                            "browser_session_id": id,
                        });
                    }
                    if planes
                        .browser
                        .open_context(accepted.identity.clone())
                        .await
                        .is_err()
                    {
                        planes.sessions.teardown_route(
                            &accepted.identity.conversation_key,
                            browser_session::BrowserSessionTerminalOutcome::CdpFailure,
                            config,
                        );
                        let terminal = planes.sessions.status(
                            &accepted.identity.conversation_key,
                            clock,
                            std::time::SystemTime::now(),
                        );
                        return if terminal["outcome"] == "cleanup_failure" {
                            terminal
                        } else {
                            json!({"outcome": "internal_failure"})
                        };
                    }
                    json!({
                        "outcome": "launched",
                        "browser_session_id": id,
                        "profile_disposition": accepted.identity.profile_disposition.as_str(),
                        "executable_identity_checkpoints": executable_identity_checkpoints,
                        "lease": lease.as_json(clock, std::time::SystemTime::now()),
                    })
                }
                Err(outcome) => {
                    planes
                        .sessions
                        .abandon_launch_slot(&accepted.identity.conversation_key);
                    outcome
                }
            }
        }
        _ => json!({"outcome": "internal_failure"}),
    }
}

fn flow_consent_refusal(reason: &str) -> Value {
    json!({"outcome": "consent_unavailable", "detail": {"reason": reason},
        "remedy": "an unattended flow cannot ask a person; configure its owner's standing grants"})
}

/// A scope stamp carrying `flow_id` marks a flow (see `AcceptedBindFacts::flow_id`).
/// Only a route that passes `flow_carrier_admitted` may act for it; every other
/// route carrying such a stamp is refused before capability dispatch.
fn session_flow_refusal(facts: &AcceptedBindFacts) -> Option<Value> {
    facts
        .scope
        .as_ref()
        .filter(|stamp| stamp.attributes.flow_id.is_some() && facts.flow_id.is_none())
        .map(|_| {
            json!({
                "outcome": "consent_unavailable",
                "detail": {"reason": "flow_carrier_not_admitted"},
                "remedy": "open the flow route through authorized reserved:basal",
            })
        })
}

async fn send_invalid_request_response(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    field: &str,
    reason_code: &str,
) -> Result<(), ModuleError> {
    send_tool_response(
        writer,
        ver,
        channel,
        epoch,
        corr,
        json!({
            "outcome": "invalid_request",
            "context": null,
            "session": null,
            "detail": {
                "field": field,
                "reason_code": reason_code,
            },
        }),
    )
    .await
}

async fn send_tool_response(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    body: Value,
) -> Result<(), ModuleError> {
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let response = Frame::build_with_version(
        ver,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        body,
    )
    .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, response).await
}

async fn send_route_error(
    writer: &mpsc::Sender<Frame>,
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    code: &str,
    message: &str,
) -> Result<(), ModuleError> {
    let frame = build_error_frame(ver, channel, epoch, corr, code, message)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

async fn send(writer: &mpsc::Sender<Frame>, frame: Frame) -> Result<(), ModuleError> {
    writer
        .send(frame)
        .await
        .map_err(|_| ModuleError::Message("egress channel closed".into()))
}

fn parse_subc_arg(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf, ModuleError> {
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        if arg == "--subc" {
            let value = args
                .next()
                .ok_or_else(|| ModuleError::Message("--subc requires a value".into()))?;
            return Ok(PathBuf::from(value));
        }
        if let Some(raw) = arg.to_str().and_then(|a| a.strip_prefix("--subc=")) {
            if raw.is_empty() {
                return Err(ModuleError::Message("--subc= requires a value".into()));
            }
            return Ok(PathBuf::from(raw));
        }
    }
    Err(ModuleError::Message(
        "--subc <connection-file> is required".into(),
    ))
}

#[derive(Debug)]
pub enum ModuleError {
    Message(String),
    Json(serde_json::Error),
    Config(ConfigError),
    BrowserConfig(BrowserConfigError),
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(m) => write!(f, "{m}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Config(e) => write!(f, "config: {e}"),
            Self::BrowserConfig(e) => write!(f, "config: {e}"),
        }
    }
}

impl std::error::Error for ModuleError {}

// ---------------------------------------------------------------------------
// Test-only public API: thin wrappers that the conformance test suite drives
// to exercise the real handlers without a live subc daemon.
// ---------------------------------------------------------------------------

pub struct ModuleConfigForTest {
    pub module_id: String,
}

pub async fn send_hello_for_test(
    writer: &mpsc::Sender<Frame>,
    config: &ModuleConfigForTest,
) -> Result<(), ModuleError> {
    let mut body = serde_json::to_value(ModuleHelloBody {
        manifest: manifest::build(&config.module_id),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            "route.status".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: None,
    })
    .map_err(ModuleError::Json)?;
    body["manifest"] =
        serialize_manifest_with_computer_plane(&config.module_id, &default_computer_context());
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

/// Build an eligible HELLO fixture with the browser-plane pins as the single
/// top-level manifest extension. Production status-only HELLOs use the normal
/// typed SUBC manifest path above when no release inputs are bound.
pub async fn send_hello_with_browser_plane_pins_for_test(
    writer: &mpsc::Sender<Frame>,
    module_id: &str,
    pins: &manifest::ManifestPinSet,
    common_artifacts_eligible: bool,
    extraction_evidence_eligible: bool,
) -> Result<(), ModuleError> {
    let mut body = serde_json::to_value(ModuleHelloBody {
        manifest: manifest::build(module_id),
        protocol_ver: PROTOCOL_VERSION,
        control_ops: Some(vec![
            "route.bind".to_string(),
            "route.status".to_string(),
            MODULE_CONTROL_OP_HEALTH_CHECK.to_string(),
        ]),
        launch_nonce: None,
    })
    .map_err(ModuleError::Json)?;
    let mut browser_manifest = manifest::serialize_with_browser_plane_pins(
        module_id,
        Some(pins),
        common_artifacts_eligible,
        extraction_evidence_eligible,
    );
    browser_manifest["computer_plane_release"] =
        serde_json::to_value(computer_release_evidence(&default_computer_context()))
            .map_err(ModuleError::Json)?;
    body["manifest"] = browser_manifest;
    let body = serde_json::to_vec(&body).map_err(ModuleError::Json)?;
    let frame = Frame::build(FrameType::Hello, control_flags(), 0, 0, HELLO_CORR, body)
        .map_err(|e| ModuleError::Message(e.to_string()))?;
    send(writer, frame).await
}

/// Add the process-wide gauges to a health reply:
///
/// - `crashReportLeftovers: {removed, failed}`, how a person learns that a
///   browser crash-report directory, which can hold page memory from an
///   agent's signed-in sessions, could not be deleted where no session was
///   there to report it;
/// - `sigtermListener`, whether SIGTERM will run the module's teardown or
///   just end the process (see [`sigterm_listener_state`]);
/// - `computerGrantStore`, whether the operator's "always allow" app grants are
///   in force, or withheld because their store could not be read.
///
/// All are atomics, so reading them keeps the health lane insulated, and
/// none changes the status.
fn with_process_gauges(mut report: ModuleControlResponse) -> ModuleControlResponse {
    if let ModuleControlResponse::HealthCheck {
        metrics: Some(serde_json::Value::Object(metrics)),
        ..
    } = &mut report
    {
        let counts = browser_crash_reports::leftover_counts();
        metrics.insert(
            "crashReportLeftovers".to_string(),
            serde_json::json!({"removed": counts.removed, "failed": counts.failed}),
        );
        metrics.insert(
            "sigtermListener".to_string(),
            serde_json::Value::from(sigterm_listener_state()),
        );
        metrics.insert(
            "computerGrantStore".to_string(),
            serde_json::Value::from(computer_grants::durable_grant_store_health()),
        );
    }
    report
}

pub async fn handle_control_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    handle_control_request(
        frame,
        writer,
        health_state,
        &route_bindings,
        &elicit::Elicitor::new(),
    )
    .await
}

pub async fn handle_control_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_control_request(
        frame,
        writer,
        health_state,
        route_bindings,
        &elicit::Elicitor::new(),
    )
    .await
}

/// The principal a test bind carries when it stands for a session's calls:
/// Prefrontal's core module, the only caller admitted to act in a conversation.
pub fn session_caller_principal_for_test() -> Option<subc_protocol::Principal> {
    Some(subc_protocol::Principal::Reserved {
        module_id: cerebellum_core::principal::SESSION_CALLER_MODULE_ID.to_string(),
    })
}

/// Install a synthetic accepted first-party bind for a test frame.
///
/// Older fixtures invoke only the data-plane helper, so this lets them exercise
/// the real bound-route path without weakening the production handler.
fn install_test_bind(route_bindings: &Arc<RouteBindings>, frame: &Frame) {
    let identity =
        subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string());
    route_bindings.insert(
        frame.header.channel,
        frame.header.epoch,
        AcceptedBindFacts::from_bind(
            &identity,
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
                "browserControlOperations": [
                    "browser.launch",
                    "browser.status",
                    "browser.close"
                ]
            })),
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
}

pub fn install_browser_test_bind(
    route_bindings: &Arc<RouteBindings>,
    channel: u16,
    epoch: u32,
    browser_control_operations: &[&str],
) {
    let identity =
        subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string());
    route_bindings.insert(
        channel,
        epoch,
        AcceptedBindFacts::from_bind(
            &identity,
            session_caller_principal_for_test(),
            Some(&json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
                "browserControlOperations": browser_control_operations,
            })),
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
}

pub fn install_browser_compatibility_test_bind(
    route_bindings: &Arc<RouteBindings>,
    channel: u16,
    epoch: u32,
) {
    let identity = subc_protocol::BindIdentity::new(
        "/caller/chosen/project",
        "test",
        "test-session".to_string(),
    );
    route_bindings.insert(
        channel,
        epoch,
        AcceptedBindFacts::from_bind(
            &identity,
            session_caller_principal_for_test(),
            Some(&json!({
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
                "browserControlOperations": ["browser.launch"],
            })),
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
}

/// A route opened by the session caller with no admission facts at all.
///
/// The shape a daemon produces when it is not configured to stamp admission
/// facts on the session caller's routes. The principal is the session caller
/// because any other principal is refused before its facts are read (see
/// `send_session_caller_not_admitted`), so only this one can reach the
/// missing-facts refusal.
#[doc(hidden)]
pub fn install_browser_direct_test_bind(
    route_bindings: &Arc<RouteBindings>,
    channel: u16,
    epoch: u32,
) {
    let identity = subc_protocol::BindIdentity::new(
        "/caller/chosen/project",
        "test",
        "test-session".to_string(),
    );
    route_bindings.insert(
        channel,
        epoch,
        AcceptedBindFacts::from_bind(
            &identity,
            session_caller_principal_for_test(),
            None,
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
}
#[cfg(test)]
pub fn browser_plane_with_shared_grants_for_test(
    grants: Arc<tokio::sync::Mutex<crate::authorization::GrantStore>>,
) -> BrowserPlane {
    BrowserPlane::new().with_shared_grants(grants)
}

pub async fn handle_frame_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<bool, ModuleError> {
    handle_frame(frame, writer, planes).await
}

pub async fn handle_tool_request_for_test_with_planes(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    install_test_bind(&planes.routes, &frame);
    handle_tool_request_for_test_with_existing_planes(frame, writer, planes).await
}

pub async fn handle_tool_request_for_test_with_existing_planes(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    // Direct handler tests bypass the frame reader. Register their cancellation
    // entry until the handler finishes, just as production does before spawning
    // the request, rather than letting a missing entry mean never cancellable.
    let _cancellation = planes.cancellations.register((
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    ));
    handle_keyed_tool_request(frame, writer, planes).await
}

/// The planes the tool-request test helpers drive: `Planes::new`'s short test
/// browser config, journaling in memory. A durable plane would write the
/// computer audit and launch journal into the operator's data home, which is
/// backed up and holds real browser profiles.
fn isolated_test_planes(health_state: &Arc<HealthState>) -> Planes {
    Planes::with_browser_config_journaling(
        Arc::clone(health_state),
        Some(Planes::short_test_browser_config()),
        JournalPersistence::Isolated,
    )
}

pub async fn handle_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    install_test_bind(&route_bindings, &frame);
    let mut planes = isolated_test_planes(health_state);
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = test_admitted_computer_capabilities();
    }
    handle_tool_request_for_test_with_existing_planes(frame, writer, &planes).await
}

/// Drive one tool request with an explicit admitted set.
///
/// Lets a test state which capabilities this build's release gates admit,
/// including none, which is what an unbound release resolves to.
pub async fn handle_tool_request_for_test_admitting(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    admitted: &[&str],
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    install_test_bind(&route_bindings, &frame);
    let mut planes = isolated_test_planes(health_state);
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = Arc::new(admitted.iter().map(|name| name.to_string()).collect());
    }
    #[cfg(not(target_os = "macos"))]
    let _ = admitted;
    handle_tool_request_for_test_with_existing_planes(frame, writer, &planes).await
}

/// Like [`handle_tool_request_for_test_admitting`] on a host with NO browser
/// configured, which is the shape an operator's machine has before
/// `cerebellum.jsonc` names an executable. `Planes::new` installs a browser
/// config with the executable unset, so it cannot mint the
/// `browser_not_configured` arm; this can.
pub async fn handle_tool_request_for_test_unconfigured_browser(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    admitted: &[&str],
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    install_test_bind(&route_bindings, &frame);
    let mut planes = Planes::with_browser_config_journaling(
        Arc::clone(health_state),
        None,
        JournalPersistence::Isolated,
    );
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = Arc::new(admitted.iter().map(|name| name.to_string()).collect());
    }
    #[cfg(not(target_os = "macos"))]
    let _ = admitted;
    handle_tool_request_for_test_with_existing_planes(frame, writer, &planes).await
}

pub async fn handle_tool_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let mut planes = isolated_test_planes(health_state);
    planes.routes = Arc::clone(route_bindings);
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = test_admitted_computer_capabilities();
    }
    handle_tool_request_for_test_with_existing_planes(frame, writer, &planes).await
}

#[cfg(test)]
mod tests {
    #[test]
    fn scope_admission_nondelegating_routes_do_not_read_or_offer_standing_grants() {
        use super::*;
        let core = Principal::Reserved {
            module_id: "prefrontal-core".into(),
        };
        let bind = subc_protocol::BindIdentity::new("/caller/project", "test", "conversation");
        let target = subc_protocol::RouteTarget::ToolProvider {
            module_id: "cerebellum".into(),
        };
        for delegates in [false, true] {
            let scope = subc_protocol::scope::ScopeStamp {
                owner: core.clone(),
                scope_ref: "head".into(),
                scope_epoch: 1,
                kind: subc_protocol::scope::ScopeKind::Head,
                parent: None,
                parent_state: None,
                attributes: subc_protocol::scope::ScopeAttributes {
                    agent_id: Some("pj-agent".into()),
                    delegates,
                    flow_id: None,
                },
                owner_authorized: true,
            };
            let facts =
                AcceptedBindFacts::from_bind(&bind, Some(core.clone()), None, None, &target)
                    .with_scope(Some(scope));
            assert_eq!(standing_caller(&facts).is_some(), delegates);
            assert_eq!(
                standing_offer_agent(&facts),
                if delegates { Some("pj-agent") } else { None }
            );
            let planes = Planes::with_browser_config_journaling(
                Arc::new(HealthState::new()),
                None,
                JournalPersistence::Isolated,
            );
            let (tx, _) = mpsc::channel(2);
            let consent = consent_context(&planes, &facts, &tx, 9, 3);
            assert_eq!(
                consent.caller.durable_identity_attested, delegates,
                "persistent app grants and Always allow use this same attestation"
            );
        }
    }

    /// The build script names exactly the attestations the compiler reads.
    ///
    /// The names live in two places: `option_env!` calls here, and exports in
    /// the release build script. Nothing else connects them, so a misspelling
    /// in either sets or reads a variable the other does not know.
    ///
    /// It fails CLOSED, which is what makes it worth a test: the build
    /// succeeds, the capability is silently withheld, and the gate report
    /// blames a missing attestation for one that was supplied. Measured before
    /// this existed -- a single transposed letter dropped computer.screenshot
    /// from a release build with no error anywhere.
    ///
    /// The script rejects an unknown CEREBELLUM_ variable at run time, which
    /// catches a typo in the script. This catches the other direction: a name
    /// changed here and not there.
    #[test]
    fn the_release_script_names_every_attestation_the_compiler_reads() {
        let source = include_str!("lib.rs");
        let script = include_str!("../../../scripts/release-build.sh");

        let read_here: std::collections::BTreeSet<&str> = source
            .split("option_env!(\"")
            .skip(1)
            .filter_map(|rest| rest.split('"').next())
            .filter(|name| name.starts_with("CEREBELLUM_"))
            .collect();

        assert_eq!(
            read_here.len(),
            11,
            "expected eleven attestations, found {read_here:?}"
        );

        for name in &read_here {
            assert!(
                script.contains(name),
                "{name} is read by the compiler and absent from the release script, \
                 so a release cannot bind it"
            );
        }
    }

    #[test]
    fn configured_browser_advertisement_and_dispatch_match_in_both_directions() {
        let manifest = serialize_manifest_with_browser_configuration(
            "cerebellum",
            &BrowserSurface::Available(browser_surface_config()),
        );
        let advertised: std::collections::BTreeSet<&str> = manifest["provides"]
            .as_array()
            .unwrap()
            .iter()
            .find(|role| role["role"] == "tool_provider")
            .unwrap()["tools"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .filter(|name| name.starts_with("browser."))
            .collect();
        let candidates = browser_session::CONTROL_TOOLS
            .into_iter()
            .chain(browser::ALL_TOOLS)
            .chain(["browser.type"]);
        let dispatchable: std::collections::BTreeSet<&str> = candidates
            .filter(|name| dispatchable_tool_with_browser(name, true).is_some())
            .collect();

        for name in &advertised {
            assert!(
                dispatchable.contains(name),
                "{name} is advertised but undispatchable"
            );
        }
        for name in &dispatchable {
            assert!(
                advertised.contains(name),
                "{name} is dispatchable but unadvertised"
            );
        }
        // click_point is admitted: its mapping is verified against a live
        // browser, which is what it was held back for. A page click listener
        // recorded (600,476) css where the module's mapping predicts 476.75 --
        // page truncation against probe rounding, not a mapping error, and a
        // scale error would have shown as a factor rather than a fraction.
        assert!(dispatchable.contains(browser::CLICK_POINT));
        // browser.type stays out on the credential-surface policy, which no
        // measurement changes.
        assert!(!dispatchable.contains("browser.type"));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn withheld_actions_are_refused_by_the_adapter_too() {
        let request = json!({
            "name": flat_tools::COMPUTER_USE,
            "arguments": {
                "action": "keys",
                "keys": ["s"],
                "target": "com.example.Editor"
            }
        });
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            7,
            1,
            99,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();
        let (tx, mut rx) = mpsc::channel(1);
        let health = Arc::new(HealthState::new());
        handle_tool_request_for_test_admitting(frame, &tx, &health, &[])
            .await
            .unwrap();
        let reply = rx.recv().await.expect("one refusal");
        assert_eq!(reply.header.ty, FrameType::Error);
        let error: ErrorBody = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(error.code, "capability_not_admitted");
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn folded_management_actions_match_the_management_route_on_the_same_bind() {
        let cases = [
            (
                flat_tools::BROWSER_USE,
                "open_grant",
                management::OPEN_GRANT,
                json!({"origins":["https://example.com"],"hazards":[]}),
            ),
            (
                flat_tools::BROWSER_USE,
                "present",
                management::PRESENT,
                json!({"origin":"https://example.com"}),
            ),
            (
                flat_tools::BROWSER_USE,
                "resume",
                management::RESUME,
                json!({}),
            ),
            (
                flat_tools::BROWSER_USE,
                "import_login",
                management::IMPORT_LOGIN,
                json!({"origin":"https://example.com"}),
            ),
        ];

        for (flat_name, action, method, params) in cases {
            let channel = 23;
            let epoch = 4;
            let mut planes = management_bound_planes(channel, epoch);
            planes.browser_config = Some(browser_surface_config());
            planes.management = Arc::new(ManagementPlane::new(Arc::new(OneRunning)));
            let facts = AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                session_caller_principal_for_test(),
                Some(&json!({
                    "agentProjectId": "test-project",
                    "sessionKind": "primary",
                    "effectiveCapabilityScope": ["*"]
                })),
                None,
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
            );
            planes.routes.insert(channel, epoch, facts.clone());

            let mut flat_arguments = params.clone();
            flat_arguments["action"] = json!(action);
            let flat_frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                channel,
                epoch,
                101,
                serde_json::to_vec(&json!({
                    "name": flat_name,
                    "arguments": flat_arguments,
                }))
                .unwrap(),
            )
            .unwrap();
            let management_frame = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                channel,
                epoch,
                102,
                serde_json::to_vec(&json!({"method":method,"params":params})).unwrap(),
            )
            .unwrap();
            let (tx, mut rx) = mpsc::channel(2);
            handle_tool_request(flat_frame, &tx, &planes, &CallObservation::new())
                .await
                .unwrap();
            handle_management_request(management_frame, &tx, &facts, &planes)
                .await
                .unwrap();
            let flat_reply: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
            let management_reply: Value =
                serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
            assert_eq!(flat_reply, management_reply, "{action} diverged");
            if action == "import_login" {
                assert_eq!(flat_reply["outcome"], "elicitation_undeclared");
            }
        }
    }

    #[test]
    fn in_flight_bound_derives_from_the_longest_declared_cap() {
        let mut config = browser_surface_config();
        config.navigation_settle_deadline_ms = 45_000;
        assert_eq!(derive_in_flight_age_stale_ms(None), 35_000);
        assert_eq!(derive_in_flight_age_stale_ms(Some(&config)), 50_000);
        assert!(
            derive_in_flight_age_stale_ms(Some(&config)) > computer_capability::MAX_WAIT_TIMEOUT_MS
        );
        assert!(
            derive_in_flight_age_stale_ms(Some(&config)) > config.navigation_settle_deadline_ms
        );
        config.launch_handshake_deadline_ms = 60_000;
        assert_eq!(derive_in_flight_age_stale_ms(Some(&config)), 65_000);
        config.termination_grace_period_ms = 40_000;
        config.browser_exit_observation_deadline_ms = 40_000;
        assert_eq!(derive_in_flight_age_stale_ms(Some(&config)), 85_000);
    }

    fn browser_surface_config() -> BrowserConfig {
        BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 100,
            termination_grace_period_ms: 100,
            browser_idle_timeout_ms: 30_000,
            browser_exit_observation_deadline_ms: 100,
            navigation_settle_deadline_ms: 100,
        }
    }

    fn browser_tools(manifest: &Value) -> Vec<&str> {
        manifest["provides"]
            .as_array()
            .expect("manifest provides is an array")
            .iter()
            .find(|role| role["role"] == "tool_provider")
            .expect("manifest has a tool provider")["tools"]
            .as_array()
            .expect("tool provider tools is an array")
            .iter()
            .filter_map(|tool| tool["name"].as_str())
            .filter(|name| name.starts_with("browser."))
            .collect()
    }

    #[test]
    fn available_browser_surface_advertises_tools_without_refusal_disclosure() {
        let manifest = serialize_manifest_with_browser_configuration(
            "cerebellum",
            &BrowserSurface::Available(browser_surface_config()),
        );

        assert!(browser_tools(&manifest).contains(&"browser.navigate"));
        assert!(manifest.get("browser_surface_refused").is_none());
    }

    #[test]
    fn not_configured_browser_surface_hides_tools_without_refusal_disclosure() {
        let manifest = serialize_manifest_with_browser_configuration(
            "cerebellum",
            &BrowserSurface::NotConfigured,
        );

        assert!(browser_tools(&manifest).is_empty());
        assert!(manifest.get("browser_surface_refused").is_none());
    }

    #[test]
    fn parse_refused_browser_surface_hides_tools_and_discloses_parse_reason() {
        let manifest = serialize_manifest_with_browser_configuration(
            "cerebellum",
            &BrowserSurface::Refused(BrowserConfigError {
                field: "browser".to_string(),
                reason: browser_config::BrowserConfigReason::Malformed(
                    "unexpected token".to_string(),
                ),
            }),
        );

        assert!(browser_tools(&manifest).is_empty());
        assert_eq!(
            manifest["browser_surface_refused"],
            json!({
                "field": "browser",
                "reason_code": "malformed",
                "detail": "unexpected token",
            })
        );
    }

    #[test]
    fn probe_refused_browser_surface_hides_tools_and_discloses_probe_reason() {
        let manifest = serialize_manifest_with_browser_configuration(
            "cerebellum",
            &BrowserSurface::Refused(BrowserConfigError {
                field: "browser.expected_identity".to_string(),
                reason: browser_config::BrowserConfigReason::ExecutableProbeFailed(
                    "process exited 1".to_string(),
                ),
            }),
        );

        assert!(browser_tools(&manifest).is_empty());
        assert_eq!(
            manifest["browser_surface_refused"],
            json!({
                "field": "browser.expected_identity",
                "reason_code": "executable_probe_failed",
                "detail": "process exited 1",
            })
        );
    }

    use super::*;
    use cerebellum_computer::platform::TargetResolution;
    use subc_protocol::Principal;

    /// A resolver that answers without consulting the machine.
    ///
    /// The real one reads the window server, which makes a test of frame
    /// ROUTING depend on which applications happen to be running and on a call
    /// that takes seconds. What is under test here is where a request is sent,
    /// so the answer it eventually gets should be a fixture rather than a
    /// property of the desk it runs on.
    struct NothingRunning;

    #[cfg(target_os = "macos")]
    struct OneRunning;

    #[cfg(target_os = "macos")]
    impl management::TargetResolver for OneRunning {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            TargetResolution::Resolved(cerebellum_computer::platform::ProcessGrant {
                pid: 4242,
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence: "test-generation".to_string(),
            })
        }

        fn app_code(
            &self,
            _grant: &cerebellum_computer::platform::ProcessGrant,
        ) -> Arc<dyn computer_grants::AppCode> {
            Arc::new(computer_grants::SignedByFixtureTeam)
        }
    }

    impl management::TargetResolver for NothingRunning {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            TargetResolution::NotRunning
        }
    }

    /// A management plane for frame-level tests, resolving nothing.
    fn test_management_plane() -> Arc<ManagementPlane> {
        Arc::new(ManagementPlane::new(Arc::new(NothingRunning)))
    }

    /// Minting through the management wire creates authority on the browser
    /// plane built by the production constructor.
    ///
    /// This is intentionally not a configured-grant fixture: the only authority
    /// the navigation may use is the answer delivered to the elicitation request.
    #[tokio::test]
    async fn an_elicited_browser_grant_admits_wire_navigation() {
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            Some(BrowserConfig {
                executable_path: None,
                expected_identity: None,
                launch_handshake_deadline_ms: 100,
                termination_grace_period_ms: 100,
                browser_idle_timeout_ms: 30_000,
                browser_exit_observation_deadline_ms: 100,
                navigation_settle_deadline_ms: 100,
            }),
            JournalPersistence::Isolated,
        );
        let identity = bind_identity_for_test();
        let admission = json!({
            "agentProjectId": "test-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
        });
        planes.routes.insert(
            4,
            1,
            AcceptedBindFacts::from_bind(
                &identity,
                session_caller_principal_for_test(),
                Some(&admission),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ManagementSurface {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        planes.routes.insert(
            9,
            3,
            AcceptedBindFacts::from_bind(
                &identity,
                session_caller_principal_for_test(),
                Some(&admission),
                None,
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );

        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let opening = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            71,
            serde_json::to_vec(&json!({
                "method": management::OPEN_GRANT,
                "params": {
                    "origins": ["https://requested.example"],
                    "hazards": [
                        "credential_form_submit",
                        "unverified_form_contents"
                    ]
                }
            }))
            .unwrap(),
        )
        .unwrap();
        handle_frame(opening, &writer_tx, &planes)
            .await
            .expect("the grant request enters the production frame dispatcher");

        let mut pending = None;
        let mut question = None;
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(1), writer_rx.recv())
                .await
                .expect("the management reply and question are prompt")
                .expect("the writer remains open");
            let body: Value = serde_json::from_slice(&frame.body).unwrap();
            if frame.header.ty == FrameType::Request {
                question = Some((frame, body));
            } else {
                pending = Some(body);
            }
        }
        let pending = pending.expect("the caller receives a pending reply");
        assert_eq!(pending["outcome"], "consent_pending", "{pending}");
        let (question_frame, question) = question.expect("the consumer receives a question");
        assert_eq!(
            question["params"]["scope"]["origins"],
            json!(["https://requested.example"])
        );
        assert_eq!(
            question["params"]["scope"]["hazards"],
            json!(["credential_form_submit", "unverified_form_contents"])
        );
        // A disclosed hazard raises the ceiling to tier 4 (mutate_durable).
        // The open_grant call replies consent_pending without waiting for the
        // answer, so the card is not an interrupting alert.
        assert_eq!(question["params"]["scope"]["tier"], 4);
        assert_eq!(question["params"]["urgency"], "normal");
        // The person must be told, in words they can act on, what the grant
        // unlocks: each disclosed hazard names the kind of form it allows.
        let message =
            json!([question["params"]["prompt"], question["params"]["facts"]]).to_string();
        for disclosed in [
            "requested.example",
            // A disclosed hazard mints the durable tier, so the question must
            // state that tier's whole reach, not only the form kinds.
            "It can also follow links that lead to other sites",
            "It can also submit sign-in forms and forms whose purpose it couldn't check",
            "It can't submit payment forms",
        ] {
            assert!(
                message.contains(disclosed),
                "question omitted {disclosed}: {question}"
            );
        }
        // A grant is usually answered from a phone, so the deadline the
        // question carries on the wire is the 30-minute one.
        assert_eq!(question["params"]["expires_in_ms"], json!(1_800_000));

        let answer = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            question_frame.header.channel,
            question_frame.header.epoch,
            question_frame.header.corr,
            serde_json::to_vec(&json!({"decision": "allow_conversation"})).unwrap(),
        )
        .unwrap();
        handle_frame(answer, &writer_tx, &planes)
            .await
            .expect("the affirmative answer reaches the elicitor");
        tokio::time::timeout(Duration::from_secs(1), async {
            while planes.browser.grant_count_for_test().await == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the answer mints a grant without blocking the original request");

        let navigation = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            9,
            3,
            72,
            serde_json::to_vec(&json!({
                "name": "browser.navigate",
                "arguments": {
                    "url": "https://requested.example/path",
                    "intent": "confirm the elicited authority reaches dispatch",
                    "wait": "none",
                    "severity": {"tier": 1, "credential": false, "financial": false}
                }
            }))
            .unwrap(),
        )
        .unwrap();
        handle_route_request(navigation, &writer_tx, &planes)
            .await
            .expect("the navigation reaches the browser wire handler");
        let navigated: Value =
            serde_json::from_slice(&writer_rx.recv().await.expect("navigation response").body)
                .unwrap();
        assert_ne!(navigated["outcome"], "authorization_denied", "{navigated}");
        assert_eq!(navigated["outcome"], "no_session", "{navigated}");
    }

    mod would_ask_tests {
        use super::*;
        use crate::computer_grants::{
            AlwaysGrantRecord, ComputerGrants, GrantStorage, GrantStoreState, InMemoryGrantStorage,
            GRANT_STORE_VERSION,
        };

        fn planes() -> Planes {
            let mut planes = open_grant_planes();
            let storage = Arc::new(InMemoryGrantStorage::new());
            storage
                .save(&GrantStoreState {
                    version: GRANT_STORE_VERSION,
                    records: vec![AlwaysGrantRecord {
                        agent_project_id: "owner".to_string(),
                        bundle_identity: "com.example.Always".to_string(),
                        team_id: Some("TEAM".to_string()),
                        designated_requirement: Some("test requirement".to_string()),
                        machine_uuid: "machine".to_string(),
                        created_at_ms: 1,
                    }],
                })
                .unwrap();
            planes.management = Arc::new(ManagementPlane::with_computer_grants(
                Arc::new(management::PlatformResolver::new()),
                Arc::new(ComputerGrants::open(storage, Some("machine".to_string()))),
            ));
            planes
        }

        async fn query(planes: &Planes, params: Value) -> Value {
            let (tx, mut rx) = mpsc::channel(8);
            let frame = Frame::build_with_version(
                subc_protocol::PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                4,
                1,
                500,
                serde_json::to_vec(&json!({"method":management::WOULD_ASK,"params":params}))
                    .unwrap(),
            )
            .unwrap();
            handle_frame(frame, &tx, planes).await.unwrap();
            let reply = next_frame(&mut rx).await;
            assert_ne!(reply.header.ty, FrameType::Request, "query raised a card");
            assert_eq!(planes.elicitor.outstanding(), 0);
            assert!(rx.try_recv().is_err(), "unexpected extra frame");
            serde_json::from_slice(&reply.body).unwrap()
        }

        #[tokio::test]
        async fn standing_only_and_count_only_audit() {
            let planes = planes();
            planes
                .management
                .computer_grants()
                .seed_conversation_app_for_test(
                    &planes.routes.get(4, 1).unwrap().identity.conversation_key,
                    "com.example.Session",
                );
            let reply = query(
                &planes,
                json!({"flow_id":"flow:test","agent_id":"owner","items":[
                    {"tool":"computer_use","target":"com.example.Always","level":4},
                    {"tool":"computer_use","target":"com.example.Missing"},
                    {"tool":"computer_use","target":"com.example.Session"}
                ]}),
            )
            .await;
            assert_eq!(
                reply,
                json!({"items":[
                    {"tool":"computer_use","target":"com.example.Always","verdict":"yes","reason":"standing_grant"},
                    {"tool":"computer_use","target":"com.example.Missing","verdict":"would_ask","reason":"no_standing_grant"},
                    {"tool":"computer_use","target":"com.example.Session","verdict":"would_ask","reason":"no_standing_grant"}
                ]})
            );
            let export = planes.browser.journal_export_for_test().await;
            let entries: Vec<journal::JournalEntry> = export
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(entries.len(), 1);
            assert_eq!(entries[0].identity.principal, "reserved:prefrontal-core");
            assert_eq!(
                entries[0].detail,
                Some(
                    json!({"event":"grants.would_ask","caller":{"agent_id":"owner","flow_id":"flow:test"},"counts":{"item_count":3,"yes":1,"no":0,"would_ask":2}})
                )
            );
            assert!(!export.contains("com.example"));
            let other = query(&planes, json!({"flow_id":"flow:test","agent_id":"other","items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
            assert_eq!(other["items"][0]["verdict"], "would_ask");
        }

        /// Planes whose management plane holds a durable-shaped standing browser
        /// store (a machine identity, so rows can be recorded), with one row
        /// for `owner` on `https://example.com` up to `max_level`.
        fn planes_with_standing_origin_row(max_level: u8) -> Planes {
            use crate::browser_standing_grants::{
                InMemoryStandingGrantStorage, StandingBrowserGrants, StandingSubject,
            };
            let mut planes = open_grant_planes();
            let standing = Arc::new(StandingBrowserGrants::open(
                Arc::new(InMemoryStandingGrantStorage::new()),
                Some("machine".to_string()),
            ));
            standing
                .record(
                    "owner",
                    StandingSubject::Origin("https://example.com".to_string()),
                    max_level,
                    Vec::new(),
                    None,
                    "el_test",
                )
                .unwrap();
            planes.management = Arc::new(
                ManagementPlane::with_computer_grants(
                    Arc::new(management::PlatformResolver::new()),
                    Arc::new(ComputerGrants::open(
                        Arc::new(InMemoryGrantStorage::new()),
                        Some("machine".to_string()),
                    )),
                )
                .with_standing_browser_grants(standing),
            );
            planes
        }

        #[tokio::test]
        async fn browser_without_a_standing_row_would_ask() {
            let reply = query(&planes(), json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"browser_use","target":"https://example.com","level":1}]})).await;
            assert_eq!(reply["items"][0]["verdict"], "would_ask");
            assert_eq!(reply["items"][0]["reason"], "no_standing_grant");
        }

        /// The install check answers browser items from the agent's standing
        /// site grants: covered at or below the row's level, `level_above_grant`
        /// above it, and nothing for another agent or another origin.
        #[tokio::test]
        async fn browser_answers_from_standing_site_grants() {
            let planes = planes_with_standing_origin_row(2);
            let reply = query(
                &planes,
                json!({"flow_id":"flow:test","agent_id":"owner","items":[
                    {"tool":"browser_use","target":"https://example.com","level":2},
                    {"tool":"browser_use","target":"https://example.com"},
                    {"tool":"browser_use","target":"https://example.com","level":3},
                    {"tool":"browser_use","target":"https://example.org","level":1}
                ]}),
            )
            .await;
            assert_eq!(
                reply,
                json!({"items":[
                    {"tool":"browser_use","target":"https://example.com","verdict":"yes","reason":"standing_grant"},
                    {"tool":"browser_use","target":"https://example.com","verdict":"yes","reason":"standing_grant"},
                    {"tool":"browser_use","target":"https://example.com","verdict":"would_ask","reason":"level_above_grant"},
                    {"tool":"browser_use","target":"https://example.org","verdict":"would_ask","reason":"no_standing_grant"}
                ]})
            );
            let other = query(&planes, json!({"flow_id":"flow:test","agent_id":"other","items":[{"tool":"browser_use","target":"https://example.com","level":1}]})).await;
            assert_eq!(other["items"][0]["reason"], "no_standing_grant");
        }

        #[tokio::test]
        async fn inputs_are_closed_and_targets_are_validated() {
            let planes = planes();
            for target in [
                json!("null"),
                Value::Null,
                json!("https://example.com/path"),
                json!(""),
            ] {
                let reply = query(&planes, json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"browser_use","target":target}]})).await;
                assert_eq!(reply["items"][0]["verdict"], "no", "{reply}");
                assert_eq!(reply["items"][0]["reason"], "invalid_target");
            }
            for (params, field) in [
                (
                    json!({"flow_id":"flow:test","agent_id":"owner","items":[],"extra":true}),
                    "extra",
                ),
                (
                    json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.App","extra":1}]}),
                    "items[0].extra",
                ),
                (
                    json!({"flow_id":"flow:test","agent_id":"owner","items":[]}),
                    "items",
                ),
                (
                    json!({"flow_id":"flow:test","agent_id":"owner","items":vec![json!({"tool":"computer_use","target":"com.example.App"});65]}),
                    "items",
                ),
                (
                    json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.App","level":5}]}),
                    "items[0].level",
                ),
                (
                    json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"other","target":"com.example.App"}]}),
                    "items[0].tool",
                ),
            ] {
                let reply = query(&planes, params).await;
                assert_eq!(reply["outcome"], "invalid_request", "{reply}");
                assert_eq!(reply["detail"]["field"], field, "{reply}");
            }
        }

        #[tokio::test]
        async fn flow_identity_is_required_bounded_and_audit_only() {
            let planes = planes();
            for flow in [
                Value::Null,
                json!(""),
                json!("has space"),
                json!("line\nfeed"),
                json!("é"),
                json!("a".repeat(257)),
            ] {
                let reply = query(&planes, json!({"agent_id":"owner","flow_id":flow,"items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
                assert_eq!(reply["outcome"], "invalid_request", "{reply}");
                assert_eq!(reply["detail"]["field"], "flow_id", "{reply}");
            }
            let missing = query(&planes, json!({"agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
            assert_eq!(missing["detail"]["field"], "flow_id");
            for flow in ["x".to_string(), "~".repeat(256)] {
                let reply = query(&planes, json!({"agent_id":"owner","flow_id":flow,"items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
                assert_eq!(reply["items"][0]["verdict"], "yes", "{reply}");
            }
        }

        #[test]
        fn result_schema_is_closed_and_withheld() {
            let planes = planes();
            for item in [
                json!({"tool":"computer_use","target":"com.example.App","verdict":"maybe","reason":"standing_grant"}),
                json!({"tool":"computer_use","target":"com.example.App","verdict":"yes","reason":"unknown"}),
                json!({"tool":"computer_use","target":"com.example.App","verdict":"yes","reason":"standing_grant","extra":true}),
            ] {
                assert!(planes
                    .browser
                    .finish_reply(management::WOULD_ASK, json!({"items":[item]}))
                    .is_err());
            }
            assert!(!browser::tool_definitions()
                .iter()
                .any(|(name, _, _)| *name == management::WOULD_ASK));
        }

        #[tokio::test]
        async fn only_prefrontal_core_is_admitted() {
            for principal in [
                Some(subc_protocol::Principal::Direct),
                Some(subc_protocol::Principal::Reserved {
                    module_id: "aft".to_string(),
                }),
                Some(subc_protocol::Principal::Reserved {
                    module_id: "alfonso-core".to_string(),
                }),
            ] {
                let planes = planes();
                planes.routes.insert(
                    4,
                    1,
                    AcceptedBindFacts::from_bind(
                        &bind_identity_for_test(),
                        principal,
                        None,
                        None,
                        &subc_protocol::RouteTarget::ManagementSurface {
                            module_id: "cerebellum".to_string(),
                        },
                    ),
                );
                let reply = query(&planes, json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"computer_use","target":"com.example.Always"}]})).await;
                assert_eq!(reply["code"], "principal_denied", "{reply}");
                assert!(planes.browser.journal_export_for_test().await.is_empty());
            }
        }
    }

    /// Planes with one management route (channel 4, epoch 1) whose consumer
    /// declares it can relay a question to a person.
    fn open_grant_planes() -> Planes {
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.routes.insert(
            4,
            1,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                session_caller_principal_for_test(),
                Some(&json!({
                    "agentProjectId": "test-project",
                    "sessionKind": "primary",
                    "effectiveCapabilityScope": ["*"],
                })),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ManagementSurface {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        planes
    }

    fn open_grant_frame(corr: u64) -> Frame {
        Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            corr,
            serde_json::to_vec(&json!({
                "method": management::OPEN_GRANT,
                "params": {"origins": ["https://requested.example"], "hazards": []}
            }))
            .unwrap(),
        )
        .unwrap()
    }

    /// One `browser.open_grant` through the production frame dispatcher: the
    /// caller's immediate reply, and the question frame sent to the consumer.
    async fn open_grant_over_wire(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
        corr: u64,
    ) -> (Value, Frame) {
        handle_frame(open_grant_frame(corr), writer, planes)
            .await
            .unwrap();
        let mut reply = None;
        let mut question = None;
        for _ in 0..2 {
            let frame = next_frame(rx).await;
            if frame.header.ty == FrameType::Request {
                question = Some(frame);
            } else {
                reply = Some(serde_json::from_slice(&frame.body).unwrap());
            }
        }
        (
            reply.expect("a pending reply"),
            question.expect("a question"),
        )
    }

    /// End `question` as described by `ending`: an answer carrying that
    /// decision word, or for `refused` an error frame in place of an answer,
    /// which is how a consumer with no handler for questions refuses one.
    async fn end_question(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        question: &Frame,
        ending: &str,
    ) {
        let (ty, body) = if ending == "refused" {
            (
                FrameType::Error,
                serde_json::to_vec(&ErrorBody {
                    code: "REVERSE_REQUEST_UNHANDLED".to_string(),
                    message: "no reverse-request handler is registered".to_string(),
                    detail: None,
                })
                .unwrap(),
            )
        } else {
            (
                FrameType::Response,
                serde_json::to_vec(&json!({"decision": ending})).unwrap(),
            )
        };
        let answer = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            ty,
            Flags::new(false, Priority::Interactive, false),
            question.header.channel,
            question.header.epoch,
            question.header.corr,
            body,
        )
        .unwrap();
        handle_frame(answer, writer, planes).await.unwrap();
    }

    #[tokio::test]
    async fn drain_ends_open_browser_card_with_correlated_cancel() {
        let planes = open_grant_planes();
        let (tx, mut rx) = mpsc::channel(8);
        let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 900).await;
        let draining = Frame::build(
            FrameType::Push,
            Flags::new(false, Priority::Interactive, false),
            0,
            0,
            0,
            serde_json::to_vec(
                &json!({"op":"module.draining", "reason":"restart", "deadline_ms":123}),
            )
            .unwrap(),
        )
        .unwrap();
        handle_frame(draining, &tx, &planes).await.unwrap();
        let cancel = next_frame(&mut rx).await;
        assert_eq!(cancel.header.ty, FrameType::Cancel);
        assert_eq!(
            (
                cancel.header.channel,
                cancel.header.epoch,
                cancel.header.corr
            ),
            (
                question.header.channel,
                question.header.epoch,
                question.header.corr
            )
        );
        browser_grants_settled(&planes).await;
        end_question(&planes, &tx, &question, "allow_conversation").await;
        assert_eq!(planes.management.browser_grant_count().await, 0);
    }

    #[tokio::test]
    async fn scope_revocation_ends_open_browser_card_with_correlated_cancel() {
        let planes = open_grant_planes();
        let (tx, mut rx) = mpsc::channel(8);
        let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 901).await;
        let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
        revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
        let cancel = next_frame(&mut rx).await;
        assert_eq!(cancel.header.ty, FrameType::Cancel);
        assert_eq!(
            (
                cancel.header.channel,
                cancel.header.epoch,
                cancel.header.corr
            ),
            (
                question.header.channel,
                question.header.epoch,
                question.header.corr
            )
        );
        end_question(&planes, &tx, &question, "allow_conversation").await;
        assert_eq!(planes.management.browser_grant_count().await, 0);
    }

    async fn browser_grants_settled(planes: &Planes) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while planes.management.browser_grant_pending_count().await != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the question settles");
    }

    /// A browser grant question settled by nobody being asked is named on the
    /// next request for the same grant, and no other ending is, while none of
    /// them grants anything.
    ///
    /// The caller's pending reply says to retry once the request has been
    /// answered. For a question nobody was shown that answer never comes, so
    /// the next reply has to say so; silence from a person who was asked is not
    /// reported this way, or the field would only repeat "not answered yet".
    #[tokio::test]
    async fn a_browser_grant_nobody_was_asked_is_named_on_the_next_request() {
        // The ending, and whether the next request reports it.
        let cases = [
            ("deny", false),
            ("no_answer", false),
            ("not_put_to_anyone", true),
            ("refused", true),
            ("undeliverable", false),
            ("some_future_word", false),
        ];
        for (ending, reported) in cases {
            let planes = open_grant_planes();
            let (writer, mut rx) = mpsc::channel::<Frame>(8);
            let first_ask = if ending == "undeliverable" {
                // A closed carrier: the question cannot be sent, and neither
                // can the reply, so only the settlement is observable.
                let (closed, mut closed_rx) = mpsc::channel::<Frame>(8);
                closed_rx.close();
                let _ = handle_frame(open_grant_frame(80), &closed, &planes).await;
                None
            } else {
                let (first, question) = open_grant_over_wire(&planes, &writer, &mut rx, 80).await;
                assert_eq!(first["outcome"], "consent_pending", "{first}");
                assert!(first.get("previous_request").is_none(), "{first}");
                end_question(&planes, &writer, &question, ending).await;
                Some(first["ask_id"].as_str().unwrap().to_string())
            };
            browser_grants_settled(&planes).await;
            assert_eq!(
                planes.management.browser_grant_count().await,
                0,
                "{ending} granted something"
            );

            let (next, _) = open_grant_over_wire(&planes, &writer, &mut rx, 81).await;
            assert_eq!(next["outcome"], "consent_pending", "{ending}: {next}");
            if reported {
                let previous = &next["previous_request"];
                assert_eq!(previous["ask_id"], json!(first_ask), "{ending}: {next}");
                assert_eq!(previous["disposition"], "not_put_to_anyone", "{next}");
                let remedy = previous["remedy"].as_str().unwrap().to_lowercase();
                for loop_word in ["ask again", "retry", "wait"] {
                    assert!(
                        !remedy.contains(loop_word),
                        "a question nobody was shown sends the caller round a loop: {remedy}"
                    );
                }
            } else {
                assert!(
                    next.get("previous_request").is_none(),
                    "{ending} was reported as unreached: {next}"
                );
            }
        }
    }

    /// Every ending of a grant question a browser action is held open on maps
    /// to its own decision word and remedy. The wire test drives each ending a
    /// consumer can produce; a question that could not be sent also fails the
    /// reply on the same closed writer, so its word is pinned here.
    #[test]
    fn each_in_call_grant_ending_has_its_own_decision_and_remedy() {
        let cases = [
            (
                elicit::AskOutcome::Answered(json!({"decision": "deny"})),
                "declined",
            ),
            (elicit::AskOutcome::NoAnswer, "no_answer"),
            (elicit::AskOutcome::NotPutToAnyone, "not_put_to_anyone"),
            (elicit::AskOutcome::Undeliverable, "undeliverable"),
            (
                elicit::AskOutcome::Answered(json!({"decision": "some_future_word"})),
                "unrecognized_answer",
            ),
        ];
        let mut remedies = std::collections::BTreeSet::new();
        for (ending, decision) in cases {
            assert_eq!(in_call_grant_decision(&ending), decision);
            let remedy = in_call_grant_remedy(decision).expect("a remedy");
            assert!(remedies.insert(remedy), "{decision} shares a remedy");
            if decision == "not_put_to_anyone" {
                let remedy = remedy.to_lowercase();
                for loop_word in ["ask again", "retry", "wait"] {
                    assert!(!remedy.contains(loop_word), "{remedy}");
                }
            }
        }
        // A question withdrawn before it ended keeps the refusal's remedy.
        for withdrawn in ["cancelled", "route_closed", "draining", "unavailable"] {
            assert_eq!(in_call_grant_remedy(withdrawn), None);
        }
    }

    /// Once a person is reached, the next `browser.open_grant` reply stops
    /// carrying `previous_request` for an earlier question nobody was shown. A
    /// question that could not be sent says nothing about whether a person is
    /// reachable, so `previous_request` keeps naming the earlier one.
    #[tokio::test]
    async fn reaching_a_person_retires_the_earlier_unreached_browser_grant_report() {
        let planes = open_grant_planes();
        let (writer, mut rx) = mpsc::channel::<Frame>(8);
        let (first, question) = open_grant_over_wire(&planes, &writer, &mut rx, 90).await;
        end_question(&planes, &writer, &question, "refused").await;
        browser_grants_settled(&planes).await;

        let (closed, mut closed_rx) = mpsc::channel::<Frame>(8);
        closed_rx.close();
        let _ = handle_frame(open_grant_frame(91), &closed, &planes).await;
        browser_grants_settled(&planes).await;

        let (second, question) = open_grant_over_wire(&planes, &writer, &mut rx, 92).await;
        assert_eq!(
            second["previous_request"]["ask_id"], first["ask_id"],
            "an undeliverable question retired the report: {second}"
        );
        end_question(&planes, &writer, &question, "no_answer").await;
        browser_grants_settled(&planes).await;

        let (third, _) = open_grant_over_wire(&planes, &writer, &mut rx, 93).await;
        assert!(
            third.get("previous_request").is_none(),
            "a stale unreached report survived reaching a person: {third}"
        );
    }

    /// The refusal names the exact target fact absent from the human disclosure.
    #[tokio::test]
    async fn a_wire_built_plane_names_the_undisclosed_target_hazard() {
        let management = ManagementPlane::new(Arc::new(NothingRunning));
        let question = management
            .browser_grant_question_for_test(
                "conversation",
                vec!["https://login.example".to_string()],
                vec![crate::authorization::HazardClass::FinancialFormSubmit],
            )
            .await;
        management
            .settle_browser_grant(
                &question.ask_id,
                Some(&json!({"decision": "allow_conversation"})),
            )
            .await;
        let browser = browser_plane_with_shared_grants_for_test(management.browser_grants());
        let route = RouteIdentity {
            conversation_key: "conversation".to_string(),
            ..RouteIdentity::from_bind(&bind_identity_for_test(), &Some(Principal::Direct))
        };
        browser.open_context(route.clone()).await.unwrap();
        let submit = crate::classification::ElementClassificationInput::new(
            crate::classification::NodeIdentityInput::new("target", "frame", 42),
            crate::classification::TargetKind::Button,
        )
        .form_owner(crate::classification::NodeIdentityInput::new(
            "target", "frame", 7,
        ))
        .associated_control(
            crate::classification::AssociatedFormControlInput::new(
                crate::classification::NodeIdentityInput::new("target", "frame", 8),
            )
            .with_tokens(["current-password"]),
        );
        let classification = crate::classification::classify_click(
            &crate::classification::NonTypeClassificationInput::new(
                0,
                submit,
                "https://login.example",
            ),
        )
        .unwrap();
        browser
            .same_document_url(
                &route,
                "https://login.example/page",
                crate::snapshot_store::SameDocumentChange::ReplaceState,
            )
            .await
            .unwrap();
        let retained = browser
            .retain_text_snapshot(
                &route,
                crate::snapshot_store::SnapshotKind::Ax,
                // A snapshot keeps only the refs its text names.
                &["e1", "e2"].map(|reference| crate::snapshot_store::AxRecord {
                    depth: 0,
                    role: "button".into(),
                    name: String::new(),
                    value: None,
                    reference: Some(reference.into()),
                }),
                None,
                vec![
                    crate::snapshot_store::RefRecord {
                        frame_document: None,
                        captured: crate::snapshot_store::SnapshotRef::new(
                            "e1", "button", "Sign in", 0,
                        )
                        .unwrap(),
                        frame_path: vec!["frame".to_string()],
                        backend_identity: Some(
                            crate::snapshot_store::BackendNodeIdentity::new("target", "frame", 42)
                                .unwrap(),
                        ),
                        raw_role: Some("button".to_string()),
                        raw_name: Some("Sign in".to_string()),
                        classification: Ok(Box::new(classification)),
                    },
                    crate::snapshot_store::RefRecord {
                        frame_document: None,
                        captured: crate::snapshot_store::SnapshotRef::new(
                            "e2", "button", "Continue", 0,
                        )
                        .unwrap(),
                        frame_path: vec!["frame".to_string()],
                        backend_identity: Some(
                            crate::snapshot_store::BackendNodeIdentity::new("target", "frame", 43)
                                .unwrap(),
                        ),
                        raw_role: Some("button".to_string()),
                        raw_name: Some("Continue".to_string()),
                        classification: Err(
                            crate::classification::ClassificationUnavailable::NotCaptured,
                        ),
                    },
                ],
                4096,
                None,
            )
            .await
            .unwrap();
        let result = browser
            .dispatch(
                &route,
                crate::browser::BrowserCapability::Click,
                &json!({
                    "ref": "e1",
                    "snapshot_id": retained["snapshot_id"],
                    "intent": "sign in",
                    "severity": {"tier": 4, "credential": true, "financial": false}
                }),
            )
            .await;

        assert_eq!(result["outcome"], "hazard_not_disclosed", "{result}");
        assert_eq!(
            result["detail"]["missing_hazard"], "credential_form_submit",
            "{result}"
        );
        assert_eq!(
            result["remedy"],
            "call browser.open_grant with the arguments in detail.grant_request, then retry",
            "{result}"
        );
        assert_eq!(
            result["detail"]["grant_request"]["hazards"],
            json!(["credential_form_submit"]),
            "{result}"
        );

        let unknown = browser
            .dispatch(
                &route,
                crate::browser::BrowserCapability::Click,
                &json!({
                    "ref": "e2",
                    "snapshot_id": retained["snapshot_id"],
                    "intent": "continue",
                    "severity": {"tier": 4, "credential": true, "financial": false}
                }),
            )
            .await;
        assert_eq!(
            unknown["outcome"], "classification_unavailable",
            "{unknown}"
        );
        assert_eq!(
            unknown["detail"]["classification_unavailable"],
            "not_captured"
        );
        assert!(unknown["detail"].get("required").is_none());
        assert!(unknown["detail"].get("grant_request").is_none());
        // No classification was captured, so the next step must capture it;
        // choosing another ref cannot repair missing document facts.
        let remedy = unknown["remedy"].as_str().unwrap();
        assert!(remedy.contains("capture target classification"));
        assert!(!remedy.contains("enclosing element"));
    }

    /// An answer arriving on a route reaches the question that asked it.
    ///
    /// The frame dispatcher previously had no arm for a response: it fell through
    /// to the catch-all and was dropped, so a question waited out its whole
    /// deadline and reported that nobody replied. That is indistinguishable from
    /// a consumer ignoring the question, which is why nothing outside the module
    /// could have detected the missing arm.
    ///
    /// Driven through `handle_frame` rather than through the elicitor directly,
    /// because the elicitor's own tests already pass with no arm at all. What is
    /// under test is the dispatcher routing the frame there.
    #[tokio::test]
    async fn a_response_frame_reaches_the_question_that_asked_it() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let elicitor: SharedElicitor = Arc::new(Elicitor::new());
        let health = Arc::new(HealthState::default());
        let routes = Arc::new(RouteBindings::new());
        let browser = Arc::new(BrowserPlane::new());

        // A question is outstanding, so there is something for the answer to
        // reach. Asked on its own task because it waits for the reply.
        let asking = {
            let elicitor = Arc::clone(&elicitor);
            let writer_tx = writer_tx.clone();
            tokio::spawn(async move {
                elicitor
                    .ask(
                        &writer_tx,
                        4,
                        1,
                        json!({"method": "elicitation/create"}),
                        Duration::from_secs(5),
                    )
                    .await
            })
        };
        let question = writer_rx.recv().await.expect("the question is sent");

        let answer = Frame::build(
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            question.header.channel,
            question.header.epoch,
            question.header.corr,
            br#"{"decision":"allow"}"#.to_vec(),
        )
        .unwrap();

        let planes = Planes {
            cancellations: RequestCancellations::default(),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health,
            routes,
            browser,
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            route_test_handler: None,
            elicitor: Arc::clone(&elicitor),
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
        };
        let keep_going = handle_frame(answer, &writer_tx, &planes)
            .await
            .expect("an answer is handled");
        assert!(keep_going, "handling an answer closed the connection");

        assert_eq!(
            asking.await.unwrap(),
            crate::elicit::AskOutcome::Answered(json!({"decision": "allow"})),
            "the answer did not reach the question"
        );
    }

    /// An answer nobody is waiting for is dropped without disturbing the loop.
    ///
    /// A late reply, or a correlation this module never sent. It must neither
    /// revive an abandoned question nor take the connection down: an unsolicited
    /// frame is a normal event on a shared route.
    #[tokio::test]
    async fn an_unsolicited_answer_is_dropped_without_closing_the_route() {
        let (writer_tx, _writer_rx) = mpsc::channel::<Frame>(8);
        let elicitor: SharedElicitor = Arc::new(Elicitor::new());

        let answer = Frame::build(
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            9_999,
            br#"{"decision":"allow"}"#.to_vec(),
        )
        .unwrap();

        let planes = Planes {
            cancellations: RequestCancellations::default(),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health: Arc::new(HealthState::default()),
            routes: Arc::new(RouteBindings::new()),
            browser: Arc::new(BrowserPlane::new()),
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            route_test_handler: None,
            elicitor: Arc::clone(&elicitor),
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
        };
        let keep_going = handle_frame(answer, &writer_tx, &planes)
            .await
            .expect("an unsolicited answer is handled");
        assert!(keep_going, "an unsolicited answer closed the connection");
        assert_eq!(elicitor.outstanding(), 0);
    }

    /// A management route is served by the management surface, not the tool one.
    ///
    /// The two take different envelopes, so a management request reaching the
    /// tool path is rejected as a malformed tool call: the caller is told its
    /// request was invalid when the module simply sent it to the wrong place.
    ///
    /// Driven through the real entry point, because a test calling the
    /// management handler directly would pass however the routing behaved.
    #[tokio::test]
    async fn a_management_route_is_served_by_the_management_surface() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = management_bound_planes(4, 1);

        let request = serde_json::json!({
            "method": management::OPEN_TARGET,
            "params": {
                "bundle_identity": "com.example.Nothing",
            },
        });
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            77,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        handle_route_request(frame, &writer_tx, &planes)
            .await
            .expect("a management request is served");

        let response = writer_rx.recv().await.expect("a response frame");
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        // The operation ran: it resolved the name and found nothing running.
        // Served by the tool path this would be a rejected envelope instead.
        assert_eq!(
            body["outcome"], "not_running",
            "a management request was not served by the management surface: {body}"
        );
    }

    #[tokio::test]
    async fn a_management_route_without_elicitation_gets_no_browser_grant_question() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = management_bound_planes(4, 1);
        let request = serde_json::json!({
            "method": management::OPEN_GRANT,
            "params": {
                "origins": ["https://example.test"],
                "hazards": ["unverified_form_contents"],
            },
        });
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            79,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        handle_route_request(frame, &writer_tx, &planes)
            .await
            .expect("the grant operation is served");
        let response = writer_rx.recv().await.expect("an immediate response");
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "consent_unavailable", "{body}");
        assert_eq!(planes.management.browser_grant_count().await, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), writer_rx.recv())
                .await
                .is_err(),
            "a consumer that did not declare elicitation received a question"
        );
    }

    #[tokio::test]
    async fn browser_present_and_import_login_reject_opaque_origin_before_side_effects() {
        for method in [management::PRESENT, management::IMPORT_LOGIN] {
            let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
            let planes = management_bound_planes(4, 1);
            let frame = Frame::build_with_version(
                subc_protocol::PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                4,
                1,
                105,
                serde_json::to_vec(&json!({"method": method, "params": {"origin": "null"}}))
                    .unwrap(),
            )
            .unwrap();

            handle_route_request(frame, &writer_tx, &planes)
                .await
                .expect("an opaque origin receives a response");
            let response = writer_rx.recv().await.expect("an invalid-request response");
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["outcome"], "invalid_request", "{method}: {body}");
            assert_eq!(body["detail"]["field"], "origin", "{method}: {body}");
            assert_eq!(
                body["detail"]["reason_code"], "invalid_origin",
                "{method}: {body}"
            );
            assert!(
                writer_rx.try_recv().is_err(),
                "{method} sent an elicitation frame"
            );
            assert!(
                planes.browser.operation_log().await.is_empty(),
                "{method} operated the browser"
            );
        }
    }

    #[tokio::test]
    async fn browser_import_login_params_are_exactly_closed() {
        let cases = [
            (
                json!({"method": management::IMPORT_LOGIN, "params": {"origin": "https://x.com", "extra": true}}),
                "extra",
                "unknown_field",
            ),
            (
                json!({"method": management::IMPORT_LOGIN, "params": {}}),
                "origin",
                "missing_field",
            ),
            (
                json!({"method": management::IMPORT_LOGIN, "params": {"origin": 7}}),
                "origin",
                "wrong_type",
            ),
            (
                json!({"method": management::IMPORT_LOGIN, "params": {"origin": "https://x.com/path"}}),
                "origin",
                "invalid_origin",
            ),
        ];

        for (correlation, (request, field, reason)) in cases.into_iter().enumerate() {
            let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
            let planes = management_bound_planes(4, 1);
            let frame = Frame::build_with_version(
                subc_protocol::PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                4,
                1,
                correlation as u64 + 100,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap();
            handle_route_request(frame, &writer_tx, &planes)
                .await
                .expect("the import request is answered");
            let response = writer_rx.recv().await.expect("an invalid-request response");
            let body: Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["outcome"], "invalid_request", "{body}");
            assert_eq!(body["detail"]["field"], field, "{body}");
            assert_eq!(body["detail"]["reason_code"], reason, "{body}");
        }
    }

    #[tokio::test]
    async fn browser_import_login_refuses_when_elicitation_was_not_declared() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = management_bound_planes(4, 1);
        let request = json!({
            "method": management::IMPORT_LOGIN,
            "params": {"origin": "https://x.com"},
        });
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            104,
            serde_json::to_vec(&request).unwrap(),
        )
        .unwrap();

        handle_route_request(frame, &writer_tx, &planes)
            .await
            .expect("the import request is answered");
        let response = writer_rx.recv().await.expect("an immediate refusal");
        let body: Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["outcome"], "elicitation_undeclared", "{body}");
        assert_eq!(
            body["remedy"], "reconnect with a route that declares elicitation support",
            "{body}"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), writer_rx.recv())
                .await
                .is_err(),
            "an undeclared elicitation question was sent"
        );
    }

    /// Planes whose management route declares elicitation, with the capture
    /// module running on the fixture's fakes and an in-memory journal.
    fn capture_planes(fixture: &login_capture::test_support::Fixture) -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.capture = Arc::clone(&fixture.module);
        let admission = json!({
            "agentProjectId": "test-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
        });
        planes.routes.insert(
            4,
            1,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                session_caller_principal_for_test(),
                Some(&admission),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ManagementSurface {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        planes
    }

    fn capture_request_frame(correlation: u64, params: Value) -> Frame {
        Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            correlation,
            serde_json::to_vec(&json!({
                "method": management::CAPTURE_LOGIN,
                "params": params,
            }))
            .unwrap(),
        )
        .unwrap()
    }

    fn ollama_capture_params() -> Value {
        json!({
            "credential_domain": "ollama.com",
            "account": "work",
            "fetch_url": "https://ollama.com/settings",
            "login_url": "https://ollama.com/signin",
        })
    }

    async fn next_frame(rx: &mut mpsc::Receiver<Frame>) -> Frame {
        tokio::time::timeout(Duration::from_secs(10), rx.recv())
            .await
            .expect("the capture answers promptly")
            .expect("the writer stays open")
    }

    /// Through the production frame dispatcher and the Withhold reply boundary:
    /// the planted cookie value reaches the vault request, and is absent from
    /// the question put to the person, the wire reply, and every decoded
    /// journal entry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_login_keeps_the_value_out_of_the_reply_the_journal_and_the_ask() {
        use login_capture::test_support::{contains_bytes, fixture, PLANTED_VALUE};

        let fixture = fixture();
        let planes = capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        handle_frame(
            capture_request_frame(301, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();

        let question = next_frame(&mut writer_rx).await;
        assert_eq!(question.header.ty, FrameType::Request);
        let asked: Value = serde_json::from_slice(&question.body).unwrap();
        assert_eq!(
            asked["params"]["prompt"],
            "insula will hold a copy of your ollama.com login."
        );
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_dispatch_301"}),
        ));
        let reply = next_frame(&mut writer_rx).await;
        assert_eq!(reply.header.corr, 301);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "captured", "{body}");
        // The answer's card id survives the real elicitor and becomes the
        // deposit's consent reference.
        assert_eq!(
            fixture.vault.request_params()[0]["consent_ref"],
            "el_dispatch_301"
        );

        // Positive control: the scanner finds the value where it was planted.
        let requests = fixture.vault.requests.lock().unwrap().clone();
        assert_eq!(requests.len(), 1);
        assert!(contains_bytes(&requests[0], PLANTED_VALUE));
        assert!(fixture.fs.files().is_empty());
        let cookie_bytes = fixture.vault.request_params()[0]["cookie"]
            .as_str()
            .unwrap()
            .len() as u64;

        assert!(
            !contains_bytes(&question.body, PLANTED_VALUE),
            "the ask leaked it"
        );
        assert!(
            !contains_bytes(&reply.body, PLANTED_VALUE),
            "the reply leaked it"
        );
        let export = planes.browser.journal_export_for_test().await;
        let entries = export
            .lines()
            .map(|line| serde_json::from_str::<journal::JournalEntry>(line).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(entries.len(), 1, "{export}");
        let Some(journal::JournalPayload::LoginCapture(payload)) = &entries[0].payload else {
            panic!("a capture is journaled with its own payload: {export}");
        };
        assert_eq!(payload.outcome, "captured:created");
        assert_eq!(payload.holder, "reserved:insula");
        assert_eq!(payload.credential_id, "cookie:ollama.com:work");
        assert_eq!(payload.bytes, cookie_bytes);
        assert_eq!(payload.deletion_succeeded, Some(true));
        for entry in &entries {
            let decoded = serde_json::to_vec(entry).unwrap();
            assert!(
                !contains_bytes(&decoded, PLANTED_VALUE),
                "the journal leaked it"
            );
            assert!(
                !contains_bytes(&decoded, "csrf"),
                "the journal named a cookie"
            );
        }
    }

    /// The reply leaves only after the throwaway profile is gone. The fake
    /// deletion is slow, so a reply sent ahead of it arrives while the profile
    /// still exists.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_reply_is_sent_only_after_the_profile_is_deleted() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        *fixture.fs.removal_delay.lock().unwrap() = Duration::from_millis(200);
        let planes = capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        handle_frame(
            capture_request_frame(302, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let question = next_frame(&mut writer_rx).await;
        planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_dispatch_302"}),
        );
        let reply = next_frame(&mut writer_rx).await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "captured", "{body}");
        let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
        assert!(
            !fixture.fs.exists(placement.profile_directory()),
            "the reply was sent while the throwaway profile still existed"
        );
        assert!(fixture
            .events
            .snapshot()
            .contains(&"profile_deleted".to_string()));
    }

    /// A cancel frame for the request, arriving while the question is open,
    /// ends the capture with nothing written. The card stays open: the person
    /// may still answer it, and that answer is kept for a retry rather than
    /// acted on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancel_during_consent_ends_the_capture_and_leaves_its_card_open() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        handle_frame(
            capture_request_frame(303, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let question = next_frame(&mut writer_rx).await;
        assert_eq!(question.header.ty, FrameType::Request);
        let cancel = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Cancel,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            303,
            Vec::new(),
        )
        .unwrap();
        handle_frame(cancel, &writer_tx, &planes).await.unwrap();
        let reply = next_frame(&mut writer_rx).await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "cancelled", "{body}");
        // The card outlives the cancelled call, so an answer to it is still
        // received; it is remembered, and nothing runs on it.
        assert_eq!(
            planes.elicitor.outstanding(),
            1,
            "the cancelled capture closed its card"
        );
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_cancelled"}),
        ));
        await_remembered(&planes, true).await;
        assert!(fixture.fs.contents().is_empty());
        assert_eq!(
            fixture
                .launcher
                .launches
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    /// Wait until a late login answer is, or is no longer, remembered. The
    /// answer is applied on the card's own task, a moment after it arrives.
    async fn await_remembered(planes: &Planes, expected: bool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while planes.management.computer_grants().remembers_login_answer() != expected {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the late answer was not applied");
    }

    /// The next frame, which must be the reply to request `corr` and not a
    /// new consent card.
    async fn reply_without_a_card(rx: &mut mpsc::Receiver<Frame>, corr: u64) -> Value {
        let frame = next_frame(rx).await;
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "a card was filed where none was expected: {body}"
        );
        assert_eq!(frame.header.corr, corr);
        body
    }

    /// The next frame, which must be a new consent card.
    async fn card(rx: &mut mpsc::Receiver<Frame>) -> (Frame, Value) {
        let frame = next_frame(rx).await;
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(
            frame.header.ty,
            FrameType::Request,
            "no card was filed: {body}"
        );
        (frame, body)
    }

    /// Send one capture request and run it until it replies
    /// `consent_pending`, returning the card it filed and the reply.
    async fn capture_until_pending(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
        corr: u64,
        params: Value,
    ) -> (Frame, Value) {
        handle_frame(capture_request_frame(corr, params), writer, planes)
            .await
            .unwrap();
        let (question, _) = card(rx).await;
        let reply = reply_without_a_card(rx, corr).await;
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        (question, reply)
    }

    /// Capture planes whose login calls wait a fraction of a second in place
    /// instead of the production two minutes. The card's own life is
    /// unchanged.
    fn short_wait_capture_planes(fixture: &login_capture::test_support::Fixture) -> Planes {
        let planes = capture_planes(fixture);
        planes
            .management
            .computer_grants()
            .set_login_park_limit(Duration::from_millis(300));
        planes
    }

    /// The capture card goes out with a thirty-minute life, and asks core
    /// only to notify the agent when it settles.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_capture_card_is_sent_for_thirty_minutes_notify_only() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        handle_frame(
            capture_request_frame(310, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let (_, asked) = card(&mut writer_rx).await;
        assert_eq!(asked["params"]["expires_in_ms"], 1_800_000, "{asked}");
        assert_eq!(asked["params"]["late_execution"], "notify_only", "{asked}");
    }

    /// Unanswered, the capture call is held for the park and then replies
    /// `consent_pending` naming the card, which stays registered so a later
    /// answer is still received. The park is shortened here; production's
    /// is the two minutes pinned at the end.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_capture_replies_consent_pending_after_the_park_and_keeps_its_card() {
        use login_capture::test_support::fixture;

        let production = capture_planes(&login_capture::test_support::fixture());
        assert_eq!(
            production.management.computer_grants().login_park_limit(),
            Duration::from_secs(120)
        );
        let fixture = fixture();
        let planes = short_wait_capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let started = std::time::Instant::now();
        handle_frame(
            capture_request_frame(311, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let (question, asked) = card(&mut writer_rx).await;
        let reply = next_frame(&mut writer_rx).await;
        assert_eq!(reply.header.corr, 311);
        assert!(started.elapsed() >= Duration::from_millis(300));
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "consent_pending", "{body}");
        assert_eq!(body["ask_id"], asked["id"], "{body}");
        assert_eq!(
            body["remedy"],
            computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
            "{body}"
        );
        assert_eq!(
            planes.elicitor.outstanding(),
            1,
            "the card was closed when the call returned"
        );
        assert!(fixture.fs.contents().is_empty());
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_late_311"}),
        ));
    }

    /// An approval that arrives after the call returned is used by the next
    /// call with the same parameters, which captures without a second card
    /// and names the approved card as its consent. A call with other
    /// parameters does not use it, and once used it is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_capture_approval_is_used_once_by_a_retry_with_the_same_parameters() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = short_wait_capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let (question, _) = capture_until_pending(
            &planes,
            &writer_tx,
            &mut writer_rx,
            320,
            ollama_capture_params(),
        )
        .await;
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_late_320"}),
        ));
        await_remembered(&planes, true).await;
        assert_eq!(
            fixture.vault.request_params().len(),
            0,
            "ran on a late answer"
        );

        // Another account: the approval is not for it, so it gets a card of
        // its own.
        let mut other = ollama_capture_params();
        other["account"] = json!("personal");
        let (other_card, _) =
            capture_until_pending(&planes, &writer_tx, &mut writer_rx, 321, other).await;
        assert_ne!(other_card.header.corr, question.header.corr);
        assert!(planes.management.computer_grants().remembers_login_answer());

        handle_frame(
            capture_request_frame(322, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let body = reply_without_a_card(&mut writer_rx, 322).await;
        assert_eq!(body["outcome"], "captured", "{body}");
        assert_eq!(
            fixture.vault.request_params()[0]["consent_ref"],
            "el_late_320"
        );
        assert!(!planes.management.computer_grants().remembers_login_answer());

        // Used once: the next call asks again.
        handle_frame(
            capture_request_frame(323, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        card(&mut writer_rx).await;
        assert_eq!(fixture.vault.request_params().len(), 1);
    }

    /// A refusal that arrives after the call returned refuses the retry
    /// with the same parameters as declined, without a second card.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_capture_refusal_declines_the_retry_without_a_card() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = short_wait_capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let (question, _) = capture_until_pending(
            &planes,
            &writer_tx,
            &mut writer_rx,
            330,
            ollama_capture_params(),
        )
        .await;
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "deny", "elicitation_id": "el_late_330"}),
        ));
        await_remembered(&planes, true).await;
        handle_frame(
            capture_request_frame(331, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let body = reply_without_a_card(&mut writer_rx, 331).await;
        assert_eq!(body["outcome"], "capture_consent_not_given", "{body}");
        assert_eq!(body["reason"], "deny", "{body}");
        assert_eq!(
            fixture
                .launcher
                .launches
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );
    }

    /// A retry while the card is still unanswered waits on that card rather
    /// than filing a second one.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_capture_retry_while_its_card_is_open_rejoins_it() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = short_wait_capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let (question, first) = capture_until_pending(
            &planes,
            &writer_tx,
            &mut writer_rx,
            340,
            ollama_capture_params(),
        )
        .await;
        handle_frame(
            capture_request_frame(341, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let second = reply_without_a_card(&mut writer_rx, 341).await;
        assert_eq!(second["outcome"], "consent_pending", "{second}");
        assert_eq!(second["ask_id"], first["ask_id"], "{second}");
        assert_eq!(planes.elicitor.outstanding(), 1);
        // The one card still answers the agent's next retry.
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_late_340"}),
        ));
        await_remembered(&planes, true).await;
    }

    /// Revoking the session scope drops an approval that arrived after its
    /// call returned, so the next call asks again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scope_revocation_drops_a_late_capture_approval() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = short_wait_capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let (question, _) = capture_until_pending(
            &planes,
            &writer_tx,
            &mut writer_rx,
            350,
            ollama_capture_params(),
        )
        .await;
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "allow", "elicitation_id": "el_late_350"}),
        ));
        await_remembered(&planes, true).await;
        let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
        revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
        assert!(!planes.management.computer_grants().remembers_login_answer());
        let (open_question, pending) = capture_until_pending(
            &planes,
            &writer_tx,
            &mut writer_rx,
            351,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(fixture.vault.request_params().len(), 0);
        // The revocation also closes a card still open, so its answer is
        // received by nothing.
        assert_eq!(planes.elicitor.outstanding(), 1, "{pending}");
        let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
        revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
        let cancel = next_frame(&mut writer_rx).await;
        assert_eq!(cancel.header.ty, FrameType::Cancel);
        assert_eq!(
            (
                cancel.header.channel,
                cancel.header.epoch,
                cancel.header.corr
            ),
            (
                open_question.header.channel,
                open_question.header.epoch,
                open_question.header.corr
            )
        );
        tokio::time::timeout(Duration::from_secs(5), async {
            while planes.elicitor.outstanding() != 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the open card was not closed");
    }

    /// A consumer that answers the question with an error frame (a client with
    /// no handler for questions does, at once) ends it immediately as a
    /// question nobody was shown. Before the error arm, the frame was dropped
    /// and the question waited out its five-minute deadline, then reported
    /// silence from a person who never saw a prompt.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_error_frame_answering_a_question_ends_it_as_not_put_to_anyone() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = capture_planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        handle_frame(
            capture_request_frame(304, ollama_capture_params()),
            &writer_tx,
            &planes,
        )
        .await
        .unwrap();
        let question = next_frame(&mut writer_rx).await;
        assert_eq!(question.header.ty, FrameType::Request);
        let refusal = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Error,
            Flags::new(false, Priority::Interactive, false),
            question.header.channel,
            question.header.epoch,
            question.header.corr,
            serde_json::to_vec(&ErrorBody {
                code: "REVERSE_REQUEST_UNHANDLED".to_string(),
                message: "no reverse-request handler is registered for elicitation".to_string(),
                detail: None,
            })
            .unwrap(),
        )
        .unwrap();
        handle_frame(refusal, &writer_tx, &planes).await.unwrap();
        // `next_frame` gives up after ten seconds; the question's own deadline
        // is thirty minutes and the call's wait two, so a reply inside that
        // window is the error ending it.
        let reply = next_frame(&mut writer_rx).await;
        assert_eq!(reply.header.corr, 304);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["outcome"], "capture_consent_not_given", "{body}");
        assert_eq!(body["reason"], "not_put_to_anyone", "{body}");
        assert_eq!(planes.elicitor.outstanding(), 0);
        assert!(fixture.fs.contents().is_empty());
    }

    #[tokio::test]
    async fn capture_login_params_are_exactly_closed() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let planes = capture_planes(&fixture);
        let mut missing_account = ollama_capture_params();
        missing_account.as_object_mut().unwrap().remove("account");
        let mut extra = ollama_capture_params();
        extra["holder"] = json!("someone-else");
        for (correlation, (params, field, reason)) in [
            (missing_account, "account", "missing_field"),
            (extra, "holder", "unknown_field"),
        ]
        .into_iter()
        .enumerate()
        {
            let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
            handle_route_request(
                capture_request_frame(310 + correlation as u64, params),
                &writer_tx,
                &planes,
            )
            .await
            .unwrap();
            let body: Value =
                serde_json::from_slice(&next_frame(&mut writer_rx).await.body).unwrap();
            assert_eq!(body["outcome"], "invalid_request", "{body}");
            assert_eq!(body["detail"]["field"], field, "{body}");
            assert_eq!(body["detail"]["reason_code"], reason, "{body}");
        }
        assert!(fixture.events.snapshot().is_empty());
    }

    /// The capture reply schema is closed at the module's own boundary: an
    /// undeclared field or a missing outcome is withheld rather than sent.
    #[test]
    fn the_capture_reply_boundary_withholds_what_the_schema_does_not_declare() {
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        assert!(planes
            .browser
            .finish_reply(
                management::CAPTURE_LOGIN,
                json!({"outcome": "captured", "cookie": "x"})
            )
            .is_err());
        assert!(planes
            .browser
            .finish_reply(management::CAPTURE_LOGIN, json!({"path": "/tmp/x"}))
            .is_err());
        // `commands` carried the `ck auth` commands a capture used to return
        // for storing its cookie file by hand; the schema no longer declares
        // it, so a reply carrying it is withheld.
        assert!(planes
            .browser
            .finish_reply(
                management::CAPTURE_LOGIN,
                json!({"outcome": "captured", "commands": ["ck auth put"]})
            )
            .is_err());
        assert!(planes
            .browser
            .finish_reply(
                management::CAPTURE_LOGIN,
                json!({"outcome": "captured", "credential_id": "cookie:x.com:a", "vault_outcome": "created", "record_version": 3})
            )
            .is_ok());
        assert!(planes
            .browser
            .finish_reply(
                management::CAPTURE_LOGIN,
                json!({"outcome": "captured", "vault_outcome": "kept"})
            )
            .is_err());
        assert!(planes
            .browser
            .finish_reply(management::CAPTURE_LOGIN, json!({"outcome": "made_up"}))
            .is_err());
        assert!(planes
            .browser
            .finish_reply(management::CAPTURE_LOGIN, json!({"outcome": "cancelled"}))
            .is_ok());
    }

    /// A route bound to a surface this module does not serve is refused as such.
    ///
    /// Not served as either of the surfaces it does: answering from an envelope
    /// the caller did not use produces a reply about a request nobody made.
    #[tokio::test]
    async fn an_unsupported_surface_is_refused_by_name() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = Planes {
            cancellations: RequestCancellations::default(),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health: Arc::new(HealthState::default()),
            routes: Arc::new(RouteBindings::new()),
            browser: Arc::new(BrowserPlane::new()),
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            #[cfg(test)]
            route_test_handler: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            elicitor: Arc::new(Elicitor::new()),
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
        };
        planes.routes.insert(
            6,
            1,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                Some(Principal::Direct),
                None,
                None,
                &subc_protocol::RouteTarget::InternalService {
                    module_id: "cerebellum".to_string(),
                    service_id: "anything".to_string(),
                },
            ),
        );

        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            6,
            1,
            78,
            b"{}".to_vec(),
        )
        .unwrap();

        handle_route_request(frame, &writer_tx, &planes)
            .await
            .expect("an unsupported surface is answered");

        // A transport-level error rather than an application outcome: no
        // operation ran, so there is no result to report. The surface is named
        // in the code so a caller can tell this from a request it got wrong.
        let response = writer_rx.recv().await.expect("a response frame");
        assert_eq!(response.header.ty, FrameType::Error);
        let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
        assert_eq!(body["code"], "unsupported_surface", "{body}");
    }

    fn bind_identity_for_test() -> subc_protocol::BindIdentity {
        subc_protocol::BindIdentity::new("/test/project", "test", "test-session".to_string())
    }

    /// Planes whose only route is bound to the management surface.
    pub(super) fn management_bound_planes(channel: u16, epoch: u32) -> Planes {
        let planes = Planes {
            cancellations: RequestCancellations::default(),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health: Arc::new(HealthState::default()),
            routes: Arc::new(RouteBindings::new()),
            browser: Arc::new(BrowserPlane::new()),
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            #[cfg(test)]
            route_test_handler: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            elicitor: Arc::new(Elicitor::new()),
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
        };
        planes.routes.insert(
            channel,
            epoch,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                session_caller_principal_for_test(),
                None,
                None,
                &subc_protocol::RouteTarget::ManagementSurface {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        planes
    }

    #[test]
    fn parse_subc_arg_accepts_space_separated() {
        let args = vec!["--subc".to_string().into(), "/tmp/conn.json".into()];
        assert_eq!(
            parse_subc_arg(args).unwrap(),
            PathBuf::from("/tmp/conn.json")
        );
    }

    #[test]
    fn parse_subc_arg_accepts_equals_form() {
        let args: Vec<OsString> = vec!["--subc=/tmp/conn.json".into()];
        assert_eq!(
            parse_subc_arg(args).unwrap(),
            PathBuf::from("/tmp/conn.json")
        );
    }

    #[test]
    fn parse_subc_arg_rejects_missing_value() {
        let args: Vec<OsString> = vec!["--subc".into()];
        assert!(parse_subc_arg(args).is_err());
    }

    #[test]
    fn parse_subc_arg_rejects_missing_flag() {
        let args: Vec<OsString> = vec!["--other".into()];
        assert!(parse_subc_arg(args).is_err());
    }

    #[test]
    fn default_module_id_is_cerebellum() {
        assert_eq!(DEFAULT_MODULE_ID, "cerebellum");
    }

    #[test]
    fn browser_status_is_the_single_capability() {
        assert_eq!(browser_session::BROWSER_STATUS, "browser.status");
    }

    #[test]
    fn principal_backstop_rejects_unverified() {
        let trust = trust_for_principal(&Some(Principal::Unverified));
        assert!(!trust.is_first_party());
    }

    #[test]
    fn principal_backstop_rejects_absent() {
        let trust = trust_for_principal(&None);
        assert!(!trust.is_first_party());
    }

    #[test]
    fn principal_backstop_accepts_direct() {
        let trust = trust_for_principal(&Some(Principal::Direct));
        assert!(trust.is_first_party());
    }

    #[test]
    fn principal_backstop_accepts_the_executive() {
        let trust = trust_for_principal(&Some(Principal::Reserved {
            module_id: "prefrontal-core".to_string(),
        }));
        assert!(trust.is_first_party());
    }

    #[test]
    fn principal_backstop_rejects_subc_mcp() {
        let trust = trust_for_principal(&Some(Principal::Reserved {
            module_id: "subc-mcp".to_string(),
        }));
        assert!(!trust.is_first_party());
    }

    #[test]
    fn malformed_canonical_declaration_set_never_reaches_manifest_filter() {
        let context = default_computer_context();
        let (mut declarations, _) = canonical_computer_declarations(&context);
        for declaration in &mut declarations {
            declaration.advertised = true;
        }
        declarations[0].capability_id = "computer.wait".to_string();
        let outcomes = COMPUTER_RELEASE_GATE_TABLE
            .iter()
            .filter(|gate| {
                !matches!(
                    gate.source,
                    ComputerReleaseGateSource::StruckSelfReferential { .. }
                )
            })
            .map(|gate| (gate.name, ComputerGateOutcome::Pass))
            .collect::<ComputerGateOutcomes>();
        assert!(advertised_computer_declarations(&declarations, &outcomes).is_empty());
    }

    #[test]
    fn build_bindings_preserve_absence_and_bind_only_the_supplied_capture_review() {
        let inputs = release_inputs_from_build_bindings(BuildReleaseBindings {
            attendance_contract_owner: None,
            attendance_contract_revision: None,
            input_review_revision: None,
            global_dispatch_review_revision: None,
            capture_review_revision: Some("cerebellum-capture-review/v1@cb1f669"),
            semantic_actuation_review_revision: None,
            windows_actuation_review_revision: None,
            app_state_review_revision: None,
            element_addressed_review_revision: None,
            takeover_dispatch_review_revision: None,
            release_signing_topology_revision: None,
        });
        assert_eq!(
            inputs,
            ComputerReleaseInputs {
                attendance_contract_owner: None,
                attendance_contract_revision: None,
                input_review_revision: None,
                global_dispatch_review_revision: None,
                capture_review_revision: Some("cerebellum-capture-review/v1@cb1f669".to_string()),
                semantic_actuation_review_revision: None,
                windows_actuation_review_revision: None,
                app_state_review_revision: None,
                element_addressed_review_revision: None,
                takeover_dispatch_review_revision: None,
                release_signing_topology_revision: None,
                vocabulary_digests: computer::platform::VocabularyDigestInputs {
                    manifest_digest: Some(
                        computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256.to_string(),
                    ),
                    source_lock_digest: Some(
                        computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256.to_string(),
                    ),
                    computed_artifact_digest: Some(
                        computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256.to_string(),
                    ),
                },
            }
        );
    }

    #[test]
    fn struck_gates_remain_recorded_and_are_not_evaluated() {
        let struck: Vec<_> = COMPUTER_RELEASE_GATE_TABLE
            .iter()
            .filter_map(|gate| match gate.source {
                ComputerReleaseGateSource::StruckSelfReferential { reason } => {
                    Some((gate.name, reason))
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            struck.iter().map(|(name, _)| *name).collect::<Vec<_>>(),
            vec![
                "computer_action_vocabulary_revision",
                "permission_matrix_revision",
                "capture_residual_leakage_revision",
                "process_identity_primitive_revision",
                "cerebellum_core_contract_revision",
                "c2_journal_pin_schema_id",
                "c2_journal_pin_revision",
                "attendance_contract_schema_id",
            ]
        );
        assert_eq!(
            struck[0].1,
            "The frozen artifact revision is independently validated by validate_vocabulary; this comparison only repeated an in-repository literal."
        );
        for (_, reason) in struck.iter().skip(1) {
            assert_eq!(
                *reason,
                "No production behavior reads this identifier; the former comparison repeated one in-repository literal and checked nothing."
            );
        }

        let context = ComputerCapabilityAdvertisementContext {
            inputs: release_inputs_from_build_bindings(BuildReleaseBindings {
                attendance_contract_owner: Some("fixture-attendance-owner"),
                attendance_contract_revision: Some("fixture-attendance-revision"),
                input_review_revision: Some("fixture-input-review"),
                global_dispatch_review_revision: Some("fixture-global-dispatch-review"),
                capture_review_revision: Some("fixture-capture-review"),
                semantic_actuation_review_revision: Some("fixture-semantic-actuation-review"),
                windows_actuation_review_revision: Some("fixture-windows-actuation-review"),
                app_state_review_revision: Some("fixture-app-state-review"),
                element_addressed_review_revision: Some("fixture-element-addressed-review"),
                takeover_dispatch_review_revision: Some("fixture-takeover-dispatch-review"),
                release_signing_topology_revision: Some("fixture-signing-topology"),
            }),
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let outcomes = computer_gate_outcomes(&context);
        assert_eq!(
            outcomes.into_values().collect::<Vec<_>>(),
            vec![ComputerGateOutcome::Pass; 14]
        );
    }

    /// The release gate itself holds the takeover rows to both reviews,
    /// whatever the declaration says. Each review is left unbound in turn
    /// through the attestation path while the declarations are taken as
    /// advertised, so only the gate stands between the rows and the manifest.
    #[test]
    fn the_release_gate_holds_the_takeover_rows_to_both_reviews() {
        let bindings = |global: Option<&'static str>, takeover: Option<&'static str>| {
            ComputerCapabilityAdvertisementContext {
                inputs: release_inputs_from_build_bindings(BuildReleaseBindings {
                    attendance_contract_owner: Some("fixture-attendance-owner"),
                    attendance_contract_revision: Some("fixture-attendance-revision"),
                    input_review_revision: Some("fixture-input-review"),
                    global_dispatch_review_revision: global,
                    capture_review_revision: Some("fixture-capture-review"),
                    semantic_actuation_review_revision: Some("fixture-semantic-actuation-review"),
                    windows_actuation_review_revision: Some("fixture-windows-actuation-review"),
                    app_state_review_revision: Some("fixture-app-state-review"),
                    element_addressed_review_revision: Some("fixture-element-addressed-review"),
                    takeover_dispatch_review_revision: takeover,
                    release_signing_topology_revision: Some("fixture-signing-topology"),
                }),
                permissions: Default::default(),
                startup: StartupCapabilityProbe::default(),
            }
        };
        let takeover_rows = [
            "computer.takeover_move",
            "computer.takeover_drag",
            "computer.takeover_scroll",
        ];
        let admitted = |context: &ComputerCapabilityAdvertisementContext| {
            let mut declarations = computer::platform::capability_declarations(context, true);
            for declaration in &mut declarations {
                declaration.advertised = true;
            }
            let outcomes = computer_gate_outcomes(context);
            gate_admitted_computer_declarations(&declarations, &outcomes)
                .into_iter()
                .map(|declaration| declaration.capability_id.clone())
                .collect::<Vec<_>>()
        };

        let both = admitted(&bindings(Some("fixture-global"), Some("fixture-takeover")));
        for row in takeover_rows {
            assert!(both.iter().any(|id| id == row), "{row}: {both:?}");
        }
        for (gate, context) in [
            (
                "global_dispatch_review_revision",
                bindings(None, Some("fixture-takeover")),
            ),
            (
                "takeover_dispatch_review_revision",
                bindings(Some("fixture-global"), None),
            ),
        ] {
            assert_eq!(
                computer_gate_outcomes(&context).get(gate),
                Some(&ComputerGateOutcome::MissingExternalInput {
                    gate: gate.to_string()
                })
            );
            let admitted = admitted(&context);
            for row in takeover_rows {
                assert!(!admitted.iter().any(|id| id == row), "{gate}: {row}");
            }
            assert!(
                admitted.iter().any(|id| id == "computer.type"),
                "{gate} withheld a row it does not govern: {admitted:?}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Connection liveness tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod connection_liveness_tests {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    struct FailingWriter;

    impl AsyncWrite for FailingWriter {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "writer-side sentinel",
            )))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn connection_test_config() -> ModuleConfig {
        ModuleConfig {
            connection_file_path: PathBuf::new(),
            module_id: DEFAULT_MODULE_ID.into(),
            health: HealthConfig {
                dispatch_heartbeat_stale_ms: 100,
                queue_age_stale_ms: 30_000,
                in_flight_age_stale_ms: 30_000,
            },
            browser: BrowserSurface::NotConfigured,
        }
    }

    #[tokio::test]
    async fn writer_failure_ends_connection_while_read_is_parked() {
        // A true vanished TCP peer requires a packet-filter rule that silently
        // drops traffic; closing a loopback peer would substitute EOF/RST and
        // test the wrong failure. This writer instead isolates the listener
        // contract after the kernel has diagnosed a write failure: the read peer
        // remains open and silent, so only hearing the writer can end the loop.
        let (_silent_peer, mut parked_reader) = tokio::io::duplex(1024);
        let config = connection_test_config();
        let planes = isolated_test_planes(&Arc::new(HealthState::with_config(config.health)));

        let result = tokio::time::timeout(
            Duration::from_secs(1),
            run_connection(&mut parked_reader, FailingWriter, &config, planes),
        )
        .await
        .expect("writer failure must end the connection while the read remains parked");
        let error = result.expect_err("the writer failure must be reported");
        assert_eq!(error.to_string(), "writer-side sentinel");
    }

    /// A cut daemon sends no GOODBYE and no drain; the module learns by EOF.
    /// The graceful stop its browsers get hangs off the connection ending, so
    /// this drives the production tail of `run` with a peer that simply goes
    /// away and asserts that every session is torn down with the shutdown
    /// outcome before the result is reported. `teardown_all` in isolation is
    /// covered elsewhere; this is the property that EOF reaches it.
    #[tokio::test]
    async fn daemon_eof_reaches_browser_teardown_before_the_result_is_reported() {
        shutdown_connection(false, false).await;
    }

    #[tokio::test]
    async fn draining_starts_browser_teardown_before_eof() {
        shutdown_connection(true, false).await;
    }

    #[tokio::test]
    async fn a_second_draining_does_not_tear_down_twice() {
        shutdown_connection(true, true).await;
    }

    async fn shutdown_connection(drain: bool, twice: bool) {
        use crate::browser_session::{
            BrowserSessionTerminalOutcome, CleanupStage, OwnedBrowserProcess,
            ProcessControlFailure, SessionCleanup, SessionCleanupOutcome,
        };
        use cerebellum_core::clock::FakeClock;
        use std::sync::Mutex;

        struct ExitingProcess;
        impl OwnedBrowserProcess for ExitingProcess {
            fn generation_matches(&self) -> bool {
                true
            }
            fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
                Ok(())
            }
            fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
                Ok(true)
            }
            fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
                unreachable!("graceful exit was already observed")
            }
            fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
                Ok(())
            }
        }
        struct RecordingFinalizer(Arc<Mutex<Vec<BrowserSessionTerminalOutcome>>>);
        impl SessionCleanup for RecordingFinalizer {
            fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
                self.0.lock().unwrap().push(outcome);
            }
            fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
                Ok(SessionCleanupOutcome::Complete)
            }
        }

        let browser = BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10,
            termination_grace_period_ms: 10,
            browser_idle_timeout_ms: 100,
            browser_exit_observation_deadline_ms: 10,
            navigation_settle_deadline_ms: 10,
        };
        let config = connection_test_config();
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::with_config(config.health)),
            Some(browser.clone()),
            JournalPersistence::Isolated,
        );
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let clock = FakeClock::new();
        for route in ["route-a", "route-b"] {
            let _ = planes.sessions.acquire_launch_slot(route);
            planes
                .sessions
                .establish_ready(
                    route,
                    cerebellum_core::identity::ProfileDisposition::Durable,
                    &browser,
                    &clock,
                    Box::new(ExitingProcess),
                    Box::new(RecordingFinalizer(Arc::clone(&outcomes))),
                )
                .expect("establish a ready session");
        }

        // The peer plays the daemon up to the point that matters: it answers
        // HELLO so the loop is serving, optionally drains while still connected,
        // then drops its end without a goodbye to exercise the EOF tail.
        let (daemon_end, module_end) = tokio::io::duplex(64 * 1024);
        let (mut module_read, module_write) = tokio::io::split(module_end);
        let observed_planes = planes.clone();
        let observed_outcomes = outcomes.clone();
        let peer =
            tokio::spawn(async move {
                let (mut daemon_read, mut daemon_write) = tokio::io::split(daemon_end);
                let hello = subc_transport::read_frame(&mut daemon_read)
                    .await
                    .expect("the module's HELLO is readable")
                    .expect("the module sends HELLO first");
                assert_eq!(hello.header.ty, FrameType::Hello);
                let ack = Frame::build_with_version(
                    PROTOCOL_VERSION,
                    FrameType::HelloAck,
                    Flags::new(false, Priority::Passive, false),
                    0,
                    0,
                    hello.header.corr,
                    serde_json::to_vec(&json!({
                        "negotiated_ver": PROTOCOL_VERSION,
                        "subc_ops": [],
                        "subc_capabilities": [],
                    }))
                    .unwrap(),
                )
                .unwrap();
                subc_transport::write_frame(&mut daemon_write, &ack)
                    .await
                    .expect("HELLO_ACK is written");
                if drain {
                    let notice =
                        |deadline| {
                            Frame::build_with_version(PROTOCOL_VERSION, FrameType::Push,
                    control_flags(), 0, 0, 0, serde_json::to_vec(&json!({
                        "op":"module.draining", "reason":"restart", "deadline_ms":deadline
                    })).unwrap()).unwrap()
                        };
                    subc_transport::write_frame(&mut daemon_write, &notice(123))
                        .await
                        .unwrap();
                    tokio::time::timeout(Duration::from_secs(2), async {
                        loop {
                            if observed_outcomes.lock().unwrap().len() == 2 {
                                break;
                            }
                            tokio::task::yield_now().await;
                        }
                    })
                    .await
                    .expect("drain must finalize browsers before EOF");
                    if twice {
                        subc_transport::write_frame(&mut daemon_write, &notice(456))
                            .await
                            .unwrap();
                        let ping = Frame::build_with_version(
                            PROTOCOL_VERSION,
                            FrameType::Ping,
                            control_flags(),
                            0,
                            0,
                            99,
                            vec![],
                        )
                        .unwrap();
                        subc_transport::write_frame(&mut daemon_write, &ping)
                            .await
                            .unwrap();
                        let pong = subc_transport::read_frame(&mut daemon_read)
                            .await
                            .unwrap()
                            .unwrap();
                        assert_eq!(pong.header.ty, FrameType::Pong);
                        assert_eq!(observed_planes.drain_notice.get().unwrap().1, 123);
                    }
                }
                // Dropping the daemon read and write halves delivers EOF to the module.
            });

        let result = tokio::time::timeout(
            Duration::from_secs(5),
            serve_until_disconnect(
                &mut module_read,
                module_write,
                &config,
                planes.clone(),
                Some(&browser),
                None,
            ),
        )
        .await
        .expect("EOF must end the connection");
        assert!(result.is_ok(), "a clean EOF is not an error: {result:?}");

        peer.await.expect("daemon assertions passed");
        let outcomes = outcomes.lock().unwrap();
        assert_eq!(
            outcomes.as_slice(),
            [
                BrowserSessionTerminalOutcome::ModuleShutdown,
                BrowserSessionTerminalOutcome::ModuleShutdown
            ],
            "both sessions must be torn down with the shutdown outcome by the time the \
             connection result is reported"
        );
    }

    #[test]
    fn loop_and_writer_failures_remain_distinguishable() {
        let loop_error = reconcile_connection_results(
            Err(ModuleError::Message("loop-side sentinel".into())),
            Ok(Err(ModuleError::Message("writer-side sentinel".into()))),
        )
        .expect_err("a loop failure must remain the primary diagnosis");
        assert_eq!(loop_error.to_string(), "loop-side sentinel");

        let writer_error = reconcile_connection_results(
            Ok(()),
            Ok(Err(ModuleError::Message("writer-side sentinel".into()))),
        )
        .expect_err("a writer failure must be reported when the loop was healthy");
        assert_eq!(writer_error.to_string(), "writer-side sentinel");
    }

    #[tokio::test]
    async fn tcp_keepalive_is_verified_on_the_connected_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(address), listener.accept());
        let client = client.unwrap();
        let (_server, _) = accepted.unwrap();

        configure_tcp_keepalive(&client).unwrap();

        let socket = SockRef::from(&client);
        assert!(socket.keepalive().unwrap());
        assert_eq!(socket.tcp_keepalive_time().unwrap(), TCP_KEEPALIVE_IDLE);
        assert_eq!(
            socket.tcp_keepalive_interval().unwrap(),
            TCP_KEEPALIVE_INTERVAL
        );
        assert_eq!(
            socket.tcp_keepalive_retries().unwrap(),
            TCP_KEEPALIVE_RETRIES
        );
    }
}

// ---------------------------------------------------------------------------
// Bounded-idle-wake dispatch loop tests (health-v2 idle-heartbeat fix).
//
// These drive the real `run_dispatch_loop` with a deterministic fake clock and a
// test-controlled idle wake (no wall-clock sleeps), asserting:
//   1. an idle module stays healthy well past the stale threshold (idle-healthy);
//   2. a wedged handler still lets the heartbeat go stale (honesty preserved);
//   3. a frame split across an idle-wake boundary reassembles uncorrupted
//      (pinned-read regression fence), with an ignored fail-before variant that
//      shows a dropped-and-recreated read (the `timeout()` shape) corrupts it.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod dispatch_idle_tests {
    use super::*;
    use cerebellum_core::clock::{FakeClock, MonoInstant, MonotonicClock};
    use cerebellum_core::health::health_check_with_clock;
    use std::sync::Mutex;
    use subc_protocol::session::HealthStatus;

    /// A fake clock shared between the spawned dispatch loop (which stamps the
    /// heartbeat by reading it) and the test (which advances it), so both observe
    /// the same epoch. They share one `FakeClock` behind an `Arc<Mutex<_>>`;
    /// locks are held only for the instant read/advance, never across an await,
    /// so the loop and the test cannot deadlock.
    ///
    /// This is a newtype rather than a bare `Arc<Mutex<FakeClock>>` because the
    /// `MonotonicClock` trait and `FakeClock` now live in `cerebellum-core`: the
    /// orphan rules permit this impl only for a type local to this crate. `Deref`
    /// keeps the existing `clock.lock()` call sites working unchanged.
    #[derive(Clone)]
    struct SharedFakeClock(Arc<Mutex<FakeClock>>);

    impl std::ops::Deref for SharedFakeClock {
        type Target = Mutex<FakeClock>;
        fn deref(&self) -> &Mutex<FakeClock> {
            &self.0
        }
    }

    impl MonotonicClock for SharedFakeClock {
        fn now(&self) -> MonoInstant {
            self.0.lock().unwrap().now()
        }
    }

    /// A test-controlled idle wake: resolves when the test sends a permit on the
    /// channel. When the channel closes (test drops the sender) the wake pends
    /// forever rather than busy-resolving, so the loop exits only via the
    /// transport (EOF), not a wake storm.
    struct TestIdleWake {
        rx: mpsc::UnboundedReceiver<()>,
    }

    impl IdleWake for TestIdleWake {
        fn next_wake(
            &mut self,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
            Box::pin(async move {
                match self.rx.recv().await {
                    Some(()) => {}
                    None => std::future::pending::<()>().await,
                }
            })
        }
    }

    /// Poll until the stamped heartbeat reaches `target` (nanoseconds since the
    /// fake clock epoch). Reads only the health state's atomic heartbeat, never
    /// the clock lock, so it cannot deadlock with the loop's stamping.
    async fn wait_for_heartbeat(state: &HealthState, target: Duration) {
        let target_nanos = target.as_nanos() as u64;
        for _ in 0..100_000 {
            if state.heartbeat_instant().as_nanos() >= target_nanos {
                return;
            }
            tokio::task::yield_now().await;
        }
        panic!("heartbeat did not reach {target:?}");
    }

    fn test_health_config() -> HealthConfig {
        HealthConfig {
            dispatch_heartbeat_stale_ms: 100,
            queue_age_stale_ms: 30000,
            in_flight_age_stale_ms: 30000,
        }
    }

    #[tokio::test]
    async fn idle_module_stays_healthy_well_past_stale_threshold() {
        // Threshold 100ms; idle for 1000ms (10x) with NO frames, firing a
        // bounded idle wake each step. Before the fix the heartbeat was stamped
        // only per frame, so idling past 100ms reported Degraded. With the
        // bounded idle wake the heartbeat is re-stamped on each wake and the
        // report stays Ok even though cumulative idle time far exceeds the
        // threshold.
        let health_state = Arc::new(HealthState::with_config(test_health_config()));
        let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

        let (writer_io, mut reader_io) = tokio::io::duplex(1024);
        let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
        let mut idle_wake = TestIdleWake { rx: wake_rx };

        // No frames arrive in this test; the handler must never run.
        let handler = |_frame: Frame| -> std::pin::Pin<
            Box<dyn std::future::Future<Output = Result<bool, ModuleError>> + Send>,
        > { Box::pin(async { panic!("no frame should arrive while idle") }) };

        let loop_health = Arc::clone(&health_state);
        let loop_clock = clock.clone();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut reader_io,
                &loop_health,
                &loop_clock,
                &mut idle_wake,
                handler,
            )
            .await
        });

        // Idle in 50ms steps for 1000ms. After each wake the heartbeat must be
        // re-stamped at the advanced clock, so the report stays Ok even once the
        // cumulative idle time is far past the 100ms threshold.
        let mut elapsed_ms = 0u64;
        for _ in 0..20 {
            elapsed_ms += 50;
            clock.lock().unwrap().advance(Duration::from_millis(50));
            wake_tx.send(()).unwrap();
            wait_for_heartbeat(&health_state, Duration::from_millis(elapsed_ms)).await;
            let report = health_check_with_clock(&health_state, &*clock.lock().unwrap());
            assert_eq!(
                report.status,
                HealthStatus::Ok,
                "idle module must stay healthy at {elapsed_ms}ms (threshold 100ms)"
            );
        }

        // The heartbeat tracked the clock all the way to 1000ms (10x the
        // threshold), proving each wake re-stamped rather than the heartbeat
        // being frozen at startup.
        assert_eq!(
            health_state.heartbeat_instant().as_nanos(),
            Duration::from_millis(1000).as_nanos() as u64,
            "heartbeat must track the idle wakes to 1000ms"
        );

        // Counterfactual (keeps the test non-vacuous): stop firing wakes and
        // advance past the threshold from the last stamp. The lane must now
        // report Degraded, proving the idle wake — not an always-healthy
        // short-circuit — is what kept it Ok.
        clock.lock().unwrap().advance(Duration::from_millis(200));
        let report = health_check_with_clock(&health_state, &*clock.lock().unwrap());
        assert_eq!(
            report.status,
            HealthStatus::Degraded,
            "without wakes the heartbeat must go stale"
        );

        // Clean shutdown: closing the transport gives the loop a clean EOF.
        drop(writer_io);
        drop(wake_tx);
        loop_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn wedged_handler_lets_heartbeat_go_stale() {
        // The idle wake wraps ONLY the read await, never the handler. A handler
        // that wedges leaves the loop parked past the read with no re-stamp, so
        // the heartbeat ages out and the report honestly goes Degraded — even
        // though idle wakes are available. This proves the fix does not paper
        // over a stuck handler.
        let health_state = Arc::new(HealthState::with_config(test_health_config()));
        let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

        let (mut writer_io, mut reader_io) = tokio::io::duplex(1024);
        let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
        let mut idle_wake = TestIdleWake { rx: wake_rx };

        // Handler that signals it was entered, then wedges forever.
        let (entered_tx, mut entered_rx) = mpsc::unbounded_channel::<()>();
        let handler = move |_frame: Frame| {
            let entered_tx = entered_tx.clone();
            async move {
                let _ = entered_tx.send(());
                std::future::pending::<Result<bool, ModuleError>>().await
            }
        };

        let loop_health = Arc::clone(&health_state);
        let loop_clock = clock.clone();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut reader_io,
                &loop_health,
                &loop_clock,
                &mut idle_wake,
                handler,
            )
            .await
        });

        // Deliver one frame so the loop reads it and enters the wedged handler.
        let frame = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            1,
            1,
            7,
            b"{}".to_vec(),
        )
        .unwrap();
        write_frame(&mut writer_io, &frame).await.unwrap();

        // Wait until the handler is entered: the loop is now parked in the
        // handler, past the read. The last heartbeat stamp was at the top of
        // that iteration (clock offset 0).
        entered_rx.recv().await.expect("handler must be entered");

        // Advance well past the threshold and fire idle wakes too: with the
        // handler wedged the loop is not in the read select, so the wakes are
        // never processed and never re-stamp. The heartbeat must age out.
        clock.lock().unwrap().advance(Duration::from_millis(500));
        for _ in 0..5 {
            let _ = wake_tx.send(());
            clock.lock().unwrap().advance(Duration::from_millis(100));
        }

        let report = health_check_with_clock(&health_state, &*clock.lock().unwrap());
        assert_eq!(
            report.status,
            HealthStatus::Degraded,
            "a wedged handler must let the heartbeat go stale"
        );
        assert!(
            report.ages.heartbeat_age > Duration::from_millis(100),
            "heartbeat age {:?} must exceed the 100ms threshold",
            report.ages.heartbeat_age
        );

        loop_task.abort();
    }

    /// Build a frame with a non-trivial body plus its full wire encoding, for
    /// the split-frame fence.
    fn split_test_frame() -> (Frame, Vec<u8>) {
        let body = b"split-frame-payload-0123456789".to_vec(); // 30 bytes
        let frame = Frame::build(
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            3,
            1,
            99,
            body,
        )
        .unwrap();
        let mut bytes = frame.header.encode().to_vec();
        bytes.extend_from_slice(&frame.body);
        (frame, bytes)
    }

    /// Drive the split-frame scenario deterministically: write part 1 of the
    /// frame, fire two idle wakes (the first ensures part 1 is consumed by the
    /// read; the second fires mid-frame), then write part 2. Returns true if the
    /// handler recorded the frame, false if the stream was corrupted (the
    /// handler was never called). No wall-clock timing drives the result — the
    /// 500ms recv timeout is only a hang guard for the corrupted case.
    async fn drive_split_frame<W>(
        writer_io: &mut W,
        clock: &Mutex<FakeClock>,
        wake_tx: &mpsc::UnboundedSender<()>,
        health_state: &HealthState,
        done_rx: &mut mpsc::UnboundedReceiver<()>,
        bytes: &[u8],
    ) -> bool
    where
        W: AsyncWrite + Unpin,
    {
        let mid = bytes.len() / 2;
        let (part1, part2) = bytes.split_at(mid);

        // Part 1: the read consumes it and awaits the rest.
        writer_io.write_all(part1).await.unwrap();

        // Wake #1: with the read polled first (biased select), this turn reads
        // part 1 into the pinned read before the wake branch re-stamps. Advance
        // the clock so the re-stamp lands at a distinctive instant we can await.
        clock.lock().unwrap().advance(Duration::from_millis(10));
        wake_tx.send(()).unwrap();
        wait_for_heartbeat(health_state, Duration::from_millis(10)).await;

        // Wake #2 fires MID-FRAME: the read holds part 1 but part 2 has not
        // arrived. A pinned read survives this; a dropped-and-recreated read
        // (the timeout shape) loses part 1 here and corrupts the stream.
        clock.lock().unwrap().advance(Duration::from_millis(10));
        wake_tx.send(()).unwrap();
        wait_for_heartbeat(health_state, Duration::from_millis(20)).await;

        // Deliver the rest of the frame.
        writer_io.write_all(part2).await.unwrap();

        // True if the handler recorded the frame; false on timeout (corruption).
        tokio::time::timeout(Duration::from_millis(500), done_rx.recv())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn split_frame_across_idle_wake_reassembles_uncorrupted() {
        // Regression fence: a frame whose bytes arrive split across an idle-wake
        // boundary must reassemble uncorrupted and be handled exactly once. The
        // pinned read future preserves partial-read progress across the wake.
        // (A `tokio::time::timeout(read_frame(..))` would drop the mid-frame
        // read and corrupt the stream — see the ignored fail-before variant
        // `split_frame_fail_before_dropped_read_corrupts`.)
        let health_state = Arc::new(HealthState::with_config(test_health_config()));
        let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

        let (mut writer_io, mut reader_io) = tokio::io::duplex(1024);
        let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
        let mut idle_wake = TestIdleWake { rx: wake_rx };

        let handled: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
        let handler_handled = Arc::clone(&handled);
        let handler = move |frame: Frame| {
            let handled = Arc::clone(&handler_handled);
            let done_tx = done_tx.clone();
            async move {
                handled.lock().unwrap().push(frame);
                let _ = done_tx.send(());
                Ok::<bool, ModuleError>(true)
            }
        };

        let loop_health = Arc::clone(&health_state);
        let loop_clock = clock.clone();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop(
                &mut reader_io,
                &loop_health,
                &loop_clock,
                &mut idle_wake,
                handler,
            )
            .await
        });

        let (expected, bytes) = split_test_frame();
        let handled_ok = drive_split_frame(
            &mut writer_io,
            &clock,
            &wake_tx,
            &health_state,
            &mut done_rx,
            &bytes,
        )
        .await;
        assert!(handled_ok, "frame must be handled (stream not corrupted)");

        let handled = handled.lock().unwrap().clone();
        assert_eq!(handled.len(), 1, "frame handled exactly once");
        assert_eq!(handled[0], expected, "frame reassembled uncorrupted");

        drop(writer_io);
        drop(wake_tx);
        loop_task.await.unwrap().unwrap();
    }

    /// A deliberately-broken variant of [`run_dispatch_loop`] that recreates the
    /// read future on every idle wake (what `tokio::time::timeout(read_frame(..))`
    /// effectively does, since a timeout drops its inner future on expiry). Used
    /// ONLY by the ignored fail-before test to demonstrate that dropping a
    /// mid-frame read corrupts the stream.
    async fn run_dispatch_loop_drop_read_on_wake<R, C, W, H, Fut>(
        read_half: &mut R,
        health_state: &Arc<HealthState>,
        clock: &C,
        idle_wake: &mut W,
        mut handler: H,
    ) -> Result<(), ModuleError>
    where
        R: AsyncRead + Unpin,
        C: cerebellum_core::clock::MonotonicClock,
        W: IdleWake,
        H: FnMut(Frame) -> Fut,
        Fut: std::future::Future<Output = Result<bool, ModuleError>>,
    {
        health_state.stamp_heartbeat_with_clock(clock);
        loop {
            health_state.stamp_heartbeat_with_clock(clock);
            let frame = loop {
                // The defect being demonstrated: a fresh read future on every
                // wake, so dropping the in-progress read loses any partial
                // frame bytes already consumed.
                let mut read = std::pin::pin!(read_frame(read_half));
                let wake = idle_wake.next_wake();
                tokio::select! {
                    biased;
                    result = &mut read => {
                        let Some(frame) =
                            result.map_err(|e| ModuleError::Message(e.to_string()))?
                        else {
                            return Ok(());
                        };
                        break frame;
                    }
                    _ = wake => {
                        health_state.stamp_heartbeat_with_clock(clock);
                        // `read` is dropped here, losing partial frame bytes.
                    }
                }
            };
            if !handler(frame).await? {
                return Ok(());
            }
        }
    }

    /// Fail-before demonstration (ignored by default). This is the SAME scenario
    /// and the SAME assertions as
    /// [`split_frame_across_idle_wake_reassembles_uncorrupted`], but run against
    /// the dropped-read loop above. Un-ignoring it makes it go RED: the mid-frame
    /// wake drops the partial read, part 1 is lost, and the stream mis-frames so
    /// the frame is never reassembled. That is exactly the regression the
    /// pinned-read fence guards against (e.g. a future "simplify to timeout()").
    #[ignore = "fail-before fence: goes RED against a dropped-read (timeout-style) loop"]
    #[tokio::test]
    async fn split_frame_fail_before_dropped_read_corrupts() {
        let health_state = Arc::new(HealthState::with_config(test_health_config()));
        let clock = SharedFakeClock(Arc::new(Mutex::new(FakeClock::new())));

        let (mut writer_io, mut reader_io) = tokio::io::duplex(1024);
        let (wake_tx, wake_rx) = mpsc::unbounded_channel::<()>();
        let mut idle_wake = TestIdleWake { rx: wake_rx };

        let handled: Arc<Mutex<Vec<Frame>>> = Arc::new(Mutex::new(Vec::new()));
        let (done_tx, mut done_rx) = mpsc::unbounded_channel::<()>();
        let handler_handled = Arc::clone(&handled);
        let handler = move |frame: Frame| {
            let handled = Arc::clone(&handler_handled);
            let done_tx = done_tx.clone();
            async move {
                handled.lock().unwrap().push(frame);
                let _ = done_tx.send(());
                Ok::<bool, ModuleError>(true)
            }
        };

        let loop_health = Arc::clone(&health_state);
        let loop_clock = clock.clone();
        let loop_task = tokio::spawn(async move {
            run_dispatch_loop_drop_read_on_wake(
                &mut reader_io,
                &loop_health,
                &loop_clock,
                &mut idle_wake,
                handler,
            )
            .await
        });

        let (expected, bytes) = split_test_frame();
        let handled_ok = drive_split_frame(
            &mut writer_io,
            &clock,
            &wake_tx,
            &health_state,
            &mut done_rx,
            &bytes,
        )
        .await;
        // Same assertions as the pinned test; they fail here because the
        // dropped-read loop corrupts the split frame.
        assert!(handled_ok, "frame must be handled (stream not corrupted)");
        let handled = handled.lock().unwrap().clone();
        assert_eq!(handled.len(), 1, "frame handled exactly once");
        assert_eq!(handled[0], expected, "frame reassembled uncorrupted");

        drop(writer_io);
        drop(wake_tx);
        let _ = loop_task.await;
    }
}

#[cfg(test)]
mod drain_tests {
    use super::*;

    fn planes() -> Planes {
        Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            None,
            JournalPersistence::Isolated,
        )
    }

    fn frame(ty: FrameType, channel: u16, body: Value) -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            ty,
            control_flags(),
            channel,
            1,
            7,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    }

    fn draining() -> Frame {
        frame(
            FrameType::Push,
            0,
            json!({"op":"module.draining", "reason":"restart", "deadline_ms":123}),
        )
    }

    fn count(planes: &Planes) -> u64 {
        let ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = planes.health.report()
        else {
            panic!("health reply")
        };
        metrics["inFlightActions"].as_u64().unwrap()
    }

    async fn await_count(planes: &Planes, expected: u64) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while count(planes) != expected {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("request accounting settles");
    }

    fn hold(planes: &mut Planes) -> tokio::sync::oneshot::Sender<()> {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let rx = std::sync::Mutex::new(Some(rx));
        planes.route_test_handler = Some(Arc::new(move || {
            let rx = rx.lock().unwrap().take().unwrap();
            Box::pin(async move {
                rx.await.unwrap();
            })
        }));
        tx
    }

    #[tokio::test]
    async fn in_flight_gauge_counts_live_route_requests() {
        let mut planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        let one = hold(&mut planes);
        handle_frame(frame(FrameType::Request, 1, json!({})), &tx, &planes)
            .await
            .unwrap();
        let oldest = planes.health.oldest_in_flight_instant().unwrap();
        let two = hold(&mut planes);
        handle_frame(frame(FrameType::Request, 2, json!({})), &tx, &planes)
            .await
            .unwrap();
        assert_eq!(count(&planes), 2);
        assert_eq!(planes.health.oldest_in_flight_instant(), Some(oldest));
        one.send(()).unwrap();
        rx.recv().await.unwrap();
        await_count(&planes, 1).await;
        assert!(planes.health.oldest_in_flight_instant().unwrap() >= oldest);
        two.send(()).unwrap();
        rx.recv().await.unwrap();
        await_count(&planes, 0).await;
        assert_eq!(planes.health.oldest_in_flight_instant(), None);
    }

    #[tokio::test]
    async fn a_panicking_handler_still_releases_its_in_flight_slot() {
        let mut planes = planes();
        planes.route_test_handler = Some(Arc::new(|| Box::pin(async { panic!("handler panic") })));
        let (tx, _rx) = mpsc::channel(8);
        handle_frame(frame(FrameType::Request, 1, json!({})), &tx, &planes)
            .await
            .unwrap();
        assert_eq!(count(&planes), 1);
        await_count(&planes, 0).await;
    }

    #[tokio::test]
    async fn draining_refuses_new_requests_and_lets_in_flight_finish() {
        let mut planes = super::tests::management_bound_planes(1, 1);
        let (tx, mut rx) = mpsc::channel(8);
        let release = hold(&mut planes);
        handle_frame(frame(FrameType::Request, 1, json!({"method": management::OPEN_TARGET, "params": {"bundle_identity":"com.example.Nothing"}})), &tx, &planes)
            .await
            .unwrap();
        handle_frame(draining(), &tx, &planes).await.unwrap();
        planes.route_test_handler = None;
        let mut invalid = frame(FrameType::Request, 2, json!({}));
        invalid.body = b"invalid JSON".to_vec();
        handle_frame(invalid, &tx, &planes).await.unwrap();
        let refusal: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(refusal["code"], "module_draining");
        assert_eq!(refusal["detail"]["reason"], "restart");
        assert_eq!(refusal["detail"]["deadline_ms"], 123);
        assert_eq!(
            refusal["detail"]["remedy"],
            "retry after the module restarts"
        );
        assert_eq!(count(&planes), 1);
        release.send(()).unwrap();
        let reply = rx.recv().await.unwrap();
        assert_eq!(reply.header.channel, 1);
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
        assert_eq!(body["outcome"], "not_running");
        await_count(&planes, 0).await;
    }

    #[tokio::test]
    async fn drain_does_not_wait_on_a_person() {
        let mut planes = super::tests::management_bound_planes(1, 1);
        let root =
            std::env::temp_dir().join(format!("consent-drain-{}", login_import::new_ask_id()));
        assert!(!root.exists());
        let executable = root.join("browser");
        let login_import::PreparedImport::Ready(plan) = login_import::prepare_import(
            "https://example.com",
            "project",
            &executable,
            login_import::DurableProfileLocation {
                managed_root: root.clone(),
                profile_directory: root.join("profile"),
            },
            login_import::ImportSettings::for_test(
                root.join("sqlite"),
                root.join("data"),
                root.join("cookies"),
                vec![login_import::BrowserSource {
                    id: "chrome",
                    display_name: "Chrome",
                    data_directory: "chrome".into(),
                    executable: executable.clone(),
                }],
            ),
        ) else {
            panic!("prepared import")
        };
        let (tx, mut rx) = mpsc::channel(8);
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        let inputs = std::sync::Mutex::new(Some((plan, result_tx)));
        let admitted_planes = planes.clone();
        let writer = tx.clone();
        // Start at import_login's prepared-plan boundary to avoid reading the
        // operator's cookie stores. Admission and consent use the real route task.
        planes.route_test_handler = Some(Arc::new(move || {
            let (plan, result_tx) = inputs.lock().unwrap().take().unwrap();
            let planes = admitted_planes.clone();
            let writer = writer.clone();
            Box::pin(async move {
                let facts = planes.routes.get(1, 1).unwrap();
                let result =
                    complete_login_import(&planes, &facts, &writer, 1, 1, plan, None).await;
                result_tx.send(result).unwrap();
            })
        }));
        handle_frame(
            frame(
                FrameType::Request,
                1,
                json!({"method":"browser.import_login", "params":{"origin":"https://example.com"}}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let question = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(question.header.ty, FrameType::Request);
        assert_eq!(count(&planes), 0);
        handle_frame(draining(), &tx, &planes).await.unwrap();
        assert_eq!(count(&planes), 0);
        let mut answer = frame(FrameType::Response, 1, json!({"decision":"deny"}));
        answer.header.corr = question.header.corr;
        handle_frame(answer, &tx, &planes).await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), result_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["outcome"], "no_answer");
        let cancel = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cancel.header.ty, FrameType::Cancel);
        assert_eq!(cancel.header.corr, question.header.corr);
        await_count(&planes, 0).await;
    }

    #[tokio::test]
    async fn an_unknown_control_push_is_ignored() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        assert!(handle_frame(
            frame(FrameType::Push, 0, json!({"op":"future.op"})),
            &tx,
            &planes
        )
        .await
        .unwrap());
        assert!(rx.try_recv().is_err());
        assert!(!planes.draining.load(std::sync::atomic::Ordering::Acquire));
    }
}

/// The import's consent card, filed from the prepared-plan boundary of
/// `browser.import_login` (as `drain_tests` does, so no test reads the
/// operator's own cookie stores). Nothing in the fixture's browsers holds a
/// copyable login, so the card's one granting option is `hand_off`.
#[cfg(test)]
mod login_import_consent_tests {
    use super::*;

    fn plan(root: &std::path::Path) -> login_import::LoginImportPlan {
        let executable = root.join("browser");
        let login_import::PreparedImport::Ready(plan) = login_import::prepare_import(
            "https://example.com",
            "project",
            &executable,
            login_import::DurableProfileLocation {
                managed_root: root.to_path_buf(),
                profile_directory: root.join("profile"),
            },
            login_import::ImportSettings::for_test(
                root.join("sqlite"),
                root.join("data"),
                root.join("cookies"),
                vec![login_import::BrowserSource {
                    id: "chrome",
                    display_name: "Chrome",
                    data_directory: "chrome".into(),
                    executable: executable.clone(),
                }],
            ),
        ) else {
            panic!("prepared import")
        };
        plan
    }

    fn root() -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "login-import-consent-{}",
            login_import::new_ask_id()
        ));
        assert!(!root.exists());
        root
    }

    fn short_wait_planes() -> Planes {
        let planes = super::tests::management_bound_planes(1, 1);
        planes
            .management
            .computer_grants()
            .set_login_park_limit(Duration::from_millis(300));
        planes
    }

    /// Run one import until it replies, returning the card it filed (if any)
    /// and the reply.
    async fn import(
        planes: &Planes,
        root: &std::path::Path,
        rx: &mut mpsc::Receiver<Frame>,
        writer: &mpsc::Sender<Frame>,
    ) -> (Option<Frame>, Value) {
        let facts = planes.routes.get(1, 1).unwrap();
        let running = {
            let planes = planes.clone();
            let writer = writer.clone();
            let plan = plan(root);
            tokio::spawn(async move {
                complete_login_import(&planes, &facts, &writer, 1, 1, plan, None).await
            })
        };
        let reply = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("the import replies")
            .unwrap();
        (rx.try_recv().ok(), reply)
    }

    async fn await_remembered(planes: &Planes) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !planes.management.computer_grants().remembers_login_answer() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the late answer was not applied");
    }

    #[tokio::test]
    async fn the_import_card_is_sent_for_thirty_minutes_notify_only() {
        let planes = short_wait_planes();
        let root = root();
        let (tx, mut rx) = mpsc::channel(8);
        let (question, reply) = import(&planes, &root, &mut rx, &tx).await;
        let question = question.expect("a card was filed");
        let asked: Value = serde_json::from_slice(&question.body).unwrap();
        assert_eq!(asked["params"]["expires_in_ms"], 1_800_000, "{asked}");
        assert_eq!(asked["params"]["late_execution"], "notify_only", "{asked}");
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        assert_eq!(reply["ask_id"], asked["id"], "{reply}");
        assert_eq!(
            reply["remedy"],
            computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
            "{reply}"
        );
        assert_eq!(planes.elicitor.outstanding(), 1);
    }

    /// A granting answer that arrives after the call returned is used by the
    /// retry with the same origin, with no second card, and only once.
    #[tokio::test]
    async fn a_late_import_approval_is_used_once_by_the_retry() {
        let planes = short_wait_planes();
        let root = root();
        let (tx, mut rx) = mpsc::channel(8);
        let (question, reply) = import(&planes, &root, &mut rx, &tx).await;
        let question = question.expect("a card was filed");
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "hand_off", "elicitation_id": "el_import"}),
        ));
        await_remembered(&planes).await;
        let (card, reply) = import(&planes, &root, &mut rx, &tx).await;
        assert!(card.is_none(), "a second card was filed");
        assert_eq!(reply["outcome"], "hand_off", "{reply}");
        let (card, reply) = import(&planes, &root, &mut rx, &tx).await;
        assert!(card.is_some(), "the approval was used twice");
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    }

    /// A refusal that arrives after the call returned refuses the retry as
    /// denied, with no second card.
    #[tokio::test]
    async fn a_late_import_refusal_denies_the_retry() {
        let planes = short_wait_planes();
        let root = root();
        let (tx, mut rx) = mpsc::channel(8);
        let (question, _) = import(&planes, &root, &mut rx, &tx).await;
        let question = question.expect("a card was filed");
        assert!(planes.elicitor.deliver(
            question.header.channel,
            question.header.corr,
            json!({"decision": "deny", "elicitation_id": "el_import"}),
        ));
        await_remembered(&planes).await;
        let (card, reply) = import(&planes, &root, &mut rx, &tx).await;
        assert!(card.is_none(), "a second card was filed");
        assert_eq!(reply["outcome"], "denied", "{reply}");
    }

    /// A question nobody was shown still ends the import at once, as itself.
    #[tokio::test]
    async fn a_card_nobody_was_shown_ends_the_import_at_once() {
        let planes = super::tests::management_bound_planes(1, 1);
        let root = root();
        let (tx, mut rx) = mpsc::channel(8);
        let facts = planes.routes.get(1, 1).unwrap();
        let running = {
            let planes = planes.clone();
            let writer = tx.clone();
            let plan = plan(&root);
            tokio::spawn(async move {
                complete_login_import(&planes, &facts, &writer, 1, 1, plan, None).await
            })
        };
        let question = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(planes
            .elicitor
            .refuse(question.header.channel, question.header.corr));
        let reply = tokio::time::timeout(Duration::from_secs(5), running)
            .await
            .expect("refused at once, not held for the park")
            .unwrap();
        assert_eq!(reply["outcome"], "not_put_to_anyone", "{reply}");
        assert!(!planes.management.computer_grants().remembers_login_answer());
    }
}

#[cfg(test)]
mod cancel_frame_tests {
    use super::*;

    fn planes() -> Planes {
        Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        )
    }

    fn frame(ty: FrameType, channel: u16, epoch: u32, corr: u64) -> Frame {
        Frame::build(ty, control_flags(), channel, epoch, corr, b"{}".to_vec()).unwrap()
    }

    #[tokio::test]
    async fn a_cancel_for_an_unknown_corr_is_ignored_by_name() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        for channel in [0, 7] {
            assert!(
                handle_frame(frame(FrameType::Cancel, channel, 1, 42), &tx, &planes)
                    .await
                    .unwrap()
            );
            assert!(matches!(
                rx.try_recv(),
                Err(mpsc::error::TryRecvError::Empty)
            ));
        }
        assert!(handle_frame(frame(FrameType::Ping, 0, 0, 43), &tx, &planes)
            .await
            .unwrap());
        assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Pong);
    }

    #[tokio::test]
    async fn a_cancel_after_the_reply_does_not_disturb_the_next_request() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(frame(FrameType::Request, 7, 1, 42), &tx, &planes)
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().header.corr, 42);
        tokio::task::yield_now().await;
        assert!(planes.cancellations.get((7, 1, 42)).is_none());
        handle_frame(frame(FrameType::Cancel, 7, 1, 42), &tx, &planes)
            .await
            .unwrap();
        handle_frame(frame(FrameType::Request, 7, 1, 43), &tx, &planes)
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().header.corr, 43);
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn route_close_cancels_every_request_on_that_route() {
        let mut planes = planes();
        let resume = Arc::new(tokio::sync::Notify::new());
        let parked = resume.clone();
        planes.route_test_handler = Some(Arc::new(move || {
            let parked = parked.clone();
            Box::pin(async move {
                parked.notified().await;
            })
        }));
        let (tx, _rx) = mpsc::channel(8);
        for (channel, epoch, corr) in [(7, 1, 42), (7, 1, 43), (7, 2, 44), (8, 1, 45)] {
            handle_frame(
                frame(FrameType::Request, channel, epoch, corr),
                &tx,
                &planes,
            )
            .await
            .unwrap();
        }
        let first = planes.cancellations.get((7, 1, 42)).unwrap();
        let second = planes.cancellations.get((7, 1, 43)).unwrap();
        let other_epoch = planes.cancellations.get((7, 2, 44)).unwrap();
        let other_channel = planes.cancellations.get((8, 1, 45)).unwrap();
        handle_frame(frame(FrameType::Cancel, 7, 1, 42), &tx, &planes)
            .await
            .unwrap();
        assert!(first.is_cancelled());
        assert!(!second.is_cancelled());
        handle_frame(frame(FrameType::Goodbye, 7, 1, 0), &tx, &planes)
            .await
            .unwrap();
        assert!(second.is_cancelled());
        assert!(!other_epoch.is_cancelled());
        assert!(!other_channel.is_cancelled());
        tokio::task::yield_now().await;
        resume.notify_waiters();
        tokio::task::yield_now().await;
        assert!(planes.cancellations.0.lock().unwrap().is_empty());
    }

    /// A request that reaches the computer plane without a cancellation entry is
    /// refused rather than served without a way to stop it.
    ///
    /// Production registers before spawning and both test entry points go
    /// through the same registration, so this state takes calling the handler
    /// directly to construct at all. That is the point: the invariant is held at
    /// a DIFFERENT call site than the one relying on it, so the day a second
    /// entry point forgets it, this says so on the wire rather than panicking
    /// inside a spawned task, where the only trace would be an indeterminate
    /// audit record.
    // macOS-only: the computer plane's admission field is target-gated, so on a
    // host without it this request is answered `unknown_method` long before the
    // check under test, and the assertion would pass for the wrong reason.
    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn an_unregistered_request_is_refused_rather_than_served_uninterruptibly() {
        let mut planes = planes();
        let route_bindings = Arc::new(RouteBindings::new());
        let request = Frame::build(
            FrameType::Request,
            control_flags(),
            7,
            1,
            42,
            serde_json::to_vec(&json!({"name": "computer.wait", "arguments": {}})).unwrap(),
        )
        .unwrap();
        install_test_bind(&route_bindings, &request);
        planes.routes = route_bindings;
        #[cfg(target_os = "macos")]
        {
            planes.computer_admitted = test_admitted_computer_capabilities();
        }
        let (tx, mut rx) = mpsc::channel(8);

        // Deliberately NOT registered: the only way to reach the state.
        handle_tool_request(request, &tx, &planes, &CallObservation::new())
            .await
            .unwrap();

        let reply = rx.recv().await.unwrap();
        assert_eq!(reply.header.ty, FrameType::Error);
        let body: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body["code"], "request_not_interruptible");
    }
}

#[cfg(all(test, unix))]
mod sigterm_listener_tests {
    use super::*;

    /// The health reply's metrics, from the module's own control handler.
    async fn health_metrics() -> serde_json::Value {
        let (tx, mut rx) = mpsc::channel(8);
        let request = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            subc_protocol::Flags::new(false, subc_protocol::Priority::Passive, false),
            0,
            0,
            1,
            serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
        )
        .unwrap();
        let health = Arc::new(HealthState::new());
        handle_control_request_for_test(request, &tx, &health)
            .await
            .unwrap();
        let reply = rx.recv().await.unwrap();
        let ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = serde_json::from_slice(&reply.body).unwrap()
        else {
            panic!("health reply")
        };
        metrics
    }

    /// A listener that could not be installed leaves SIGTERM ending the module
    /// with no teardown. Nothing is printed about it, so the health reply is
    /// where it shows.
    #[tokio::test]
    async fn a_sigterm_listener_that_failed_to_install_is_reported_on_the_health_reply() {
        let listener = listen_for_sigterm_with(|| Err(std::io::Error::other("fixture")));
        assert!(listener.is_none());
        assert_eq!(health_metrics().await["sigtermListener"], "not_installed");
    }
}

/// A computer call waiting on a person, driven through the frame loop: the
/// drain, the route's unbind and a Cancel frame each release it at once, and
/// the request is counted exactly once as in flight or as awaiting consent.
#[cfg(all(test, target_os = "macos"))]
mod computer_consent_wire_tests {
    use super::*;
    use cerebellum_computer::platform::{ProcessGrant, TargetResolution};

    const CHANNEL: u16 = 7;
    const EPOCH: u32 = 1;
    const CORR: u64 = 42;
    const APP: &str = "com.example.Editor";

    struct Running;

    impl management::TargetResolver for Running {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            TargetResolution::Resolved(ProcessGrant {
                pid: 4242,
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence: "1700000000000000".to_string(),
            })
        }

        fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn computer_grants::AppCode> {
            Arc::new(computer_grants::SignedByFixtureTeam)
        }
    }

    /// Planes with one tool route that declares it can relay a question, and
    /// with `computer.wait` admitted.
    fn planes() -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.management = Arc::new(ManagementPlane::new(Arc::new(Running)));
        // The production plane reads the real screen lock, and a locked
        // developer machine would refuse the wait before it asks anyone.
        // These tests are about the parked question, so the screen is unlocked.
        planes.computer =
            computer_capability::computer_audit(JournalPersistence::Isolated).map(|audit| {
                Arc::new(
                    computer_capability::ComputerPlane::with_synthetic_driver(audit, || {
                        computer_capability::NativeComputerPlatformDriver::default()
                            .without_expected_post_condition()
                    })
                    .with_session_lock_for_test(Some(false)),
                )
            });
        planes.computer_admitted = test_admitted_computer_capabilities();
        planes.routes.insert(
            CHANNEL,
            EPOCH,
            AcceptedBindFacts::from_bind(
                &subc_protocol::BindIdentity::new(
                    "/test/project",
                    "test",
                    "test-session".to_string(),
                ),
                session_caller_principal_for_test(),
                Some(&json!({
                    "agentProjectId": "test-project",
                    "sessionKind": "primary",
                    "effectiveCapabilityScope": ["*"],
                })),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        planes
    }

    fn frame(ty: FrameType, channel: u16, corr: u64, body: Value) -> Frame {
        Frame::build(
            ty,
            control_flags(),
            channel,
            if channel == 0 { 0 } else { EPOCH },
            corr,
            serde_json::to_vec(&body).unwrap(),
        )
        .unwrap()
    }

    fn wait_request() -> Frame {
        frame(
            FrameType::Request,
            CHANNEL,
            CORR,
            json!({
                "name": "computer.wait",
                "arguments": {
                    "app": APP,
                    "predicate": {"kind": "element_present", "element": {"Identifier": "ready"}},
                    "timeout_ms": 0,
                },
            }),
        )
    }

    /// `(inFlightActions, awaitingConsent)` from the health reply.
    fn counters(planes: &Planes) -> (u64, u64) {
        let ModuleControlResponse::HealthCheck {
            metrics: Some(metrics),
            ..
        } = planes.health.report()
        else {
            panic!("health reply")
        };
        (
            metrics["inFlightActions"].as_u64().unwrap(),
            metrics["awaitingConsent"].as_u64().unwrap(),
        )
    }

    async fn settle_to(planes: &Planes, expected: (u64, u64)) {
        tokio::time::timeout(Duration::from_secs(2), async {
            while counters(planes) != expected {
                tokio::time::sleep(Duration::from_millis(2)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "request accounting settled at {:?}, expected {expected:?}",
                counters(planes)
            )
        });
    }

    /// Send the wait and read the question it puts, with the call parked.
    async fn parked_call(
        planes: &Planes,
        tx: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
    ) -> String {
        handle_frame(wait_request(), tx, planes).await.unwrap();
        let question = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the call asked")
            .unwrap();
        assert_eq!(question.header.ty, FrameType::Request);
        let body: Value = serde_json::from_slice(&question.body).unwrap();
        assert_eq!(body["params"]["target"]["kind"], "app");
        settle_to(planes, (0, 1)).await;
        body["id"].as_str().unwrap().to_string()
    }

    async fn reply(rx: &mut mpsc::Receiver<Frame>) -> Value {
        let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the parked call answered at once")
            .unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
        assert_eq!(reply.header.corr, CORR);
        serde_json::from_slice(&reply.body).unwrap()
    }

    #[tokio::test]
    async fn withdrawing_an_asked_computer_call_keeps_its_late_app_grant() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        let mut request = wait_request();
        let mut body: Value = serde_json::from_slice(&request.body).unwrap();
        body["call_key"] = json!("pf:computer-pending");
        request.body = serde_json::to_vec(&body).unwrap();
        COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST
            .scope(
                Duration::from_millis(20),
                handle_tool_request_for_test_with_existing_planes(request, &tx, &planes),
            )
            .await
            .unwrap();
        let question = rx.recv().await.unwrap();
        assert_eq!(question.header.ty, FrameType::Request);
        assert_eq!(reply(&mut rx).await["outcome"], "consent_pending");
        handle_frame(
            frame(
                FrameType::Request,
                CHANNEL,
                CORR + 1,
                json!({"name":"tool.withdraw", "arguments":{"call_key":"pf:computer-pending"}}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let withdrawn: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(withdrawn["answer"], "withdrawn");
        handle_frame(
            frame(
                FrameType::Response,
                CHANNEL,
                question.header.corr,
                json!({"decision":"allow_conversation", "elicitation_id":"el_computer_late"}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();
        let caller = computer_grants::GrantCaller {
            conversation_key: facts.identity.conversation_key,
            agent_project_id: facts.identity.agent_project_id,
            durable_identity_attested: true,
        };
        let need = computer_grants::GrantNeed::App {
            bundle_identity: APP.into(),
            display_name: APP.into(),
            code: Arc::new(computer_grants::SignedByFixtureTeam),
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while !planes.management.computer_grants().holds(&caller, &need) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the late answer records the app grant");
        assert!(
            rx.try_recv().is_err(),
            "no cancelled card or resumed action"
        );
        settle_to(&planes, (0, 0)).await;
    }

    #[tokio::test]
    async fn a_drain_releases_a_parked_call_at_once_with_the_gauge_restored() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(wait_request(), &tx, &planes).await.unwrap();
        let question = rx.recv().await.unwrap();
        assert_eq!(question.header.ty, FrameType::Request);
        settle_to(&planes, (0, 1)).await;

        handle_frame(
            frame(
                FrameType::Push,
                0,
                0,
                json!({"op": "module.draining", "reason": "restart", "deadline_ms": 123}),
            ),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let mut answer = None;
        let mut cancellation = None;
        for _ in 0..2 {
            let frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            if frame.header.ty == FrameType::Cancel {
                cancellation = Some(frame);
            } else {
                answer = Some(serde_json::from_slice::<Value>(&frame.body).unwrap());
            }
        }
        let cancel = cancellation.expect("drain ends the app card at the carrier");
        assert_eq!(
            (
                cancel.header.channel,
                cancel.header.epoch,
                cancel.header.corr
            ),
            (
                question.header.channel,
                question.header.epoch,
                question.header.corr
            )
        );
        let body = answer.unwrap();
        assert_eq!(body["outcome"], "module_draining", "{body}");
        settle_to(&planes, (0, 0)).await;
    }

    #[tokio::test]
    async fn an_unbind_releases_a_parked_call_and_a_late_allow_grants_nothing() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        let ask_id = parked_call(&planes, &tx, &mut rx).await;
        let facts = planes.routes.get(CHANNEL, EPOCH).unwrap();

        handle_frame(
            frame(FrameType::Goodbye, CHANNEL, 0, json!({})),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        settle_to(&planes, (0, 0)).await;
        // The caller is gone, so nothing is sent back.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            rx.try_recv().is_err(),
            "a reply was sent to an unbound route"
        );
        let grants = planes.management.computer_grants();
        assert!(
            !grants.question_open(&ask_id),
            "the question outlived its conversation"
        );

        grants.settle(
            &ask_id,
            elicit::AskOutcome::Answered(json!({"decision": "allow_conversation"})),
        );
        let caller = computer_grants::GrantCaller {
            conversation_key: facts.identity.conversation_key.clone(),
            agent_project_id: facts.identity.agent_project_id.clone(),
            durable_identity_attested: false,
        };
        let need = computer_grants::GrantNeed::App {
            bundle_identity: APP.to_string(),
            display_name: APP.to_string(),
            code: Arc::new(computer_grants::SignedByFixtureTeam),
        };
        assert!(
            !grants.holds(&caller, &need),
            "a late allow on a withdrawn question granted"
        );
    }

    #[tokio::test]
    async fn a_cancel_releases_a_parked_call_and_keeps_the_question_for_the_conversation() {
        let planes = planes();
        let (tx, mut rx) = mpsc::channel(8);
        let ask_id = parked_call(&planes, &tx, &mut rx).await;

        handle_frame(
            frame(FrameType::Cancel, CHANNEL, CORR, json!({})),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let body = reply(&mut rx).await;
        assert_eq!(body["outcome"], "cancelled", "{body}");
        assert_eq!(body["attempts"], 0, "{body}");
        settle_to(&planes, (0, 0)).await;
        assert!(
            planes.management.computer_grants().question_open(&ask_id),
            "the conversation is still bound, so its question stays open"
        );
    }

    /// The grant operations answer on a management route.
    #[tokio::test]
    async fn the_grant_operations_answer_on_the_management_surface() {
        let planes = super::tests::management_bound_planes(4, 1);
        let (tx, mut rx) = mpsc::channel(8);
        for (corr, body) in [
            (
                1,
                json!({"method": management::LIST_APP_GRANTS, "params": {}}),
            ),
            (
                2,
                json!({
                    "method": management::REVOKE_APP_GRANT,
                    "params": {"grantee": "pj-a", "bundle_identity": APP},
                }),
            ),
            (
                3,
                json!({"method": management::REVOKE_APP_GRANT, "params": {"grantee": "pj-a"}}),
            ),
        ] {
            let request = Frame::build(
                FrameType::Request,
                control_flags(),
                4,
                1,
                corr,
                serde_json::to_vec(&body).unwrap(),
            )
            .unwrap();
            handle_route_request(request, &tx, &planes).await.unwrap();
        }
        let listed: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(listed["grants"], json!([]), "{listed}");
        assert_eq!(listed["store"]["state"], "loaded", "{listed}");
        let revoked: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(revoked["outcome"], "grant_not_found", "{revoked}");
        let refused: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(refused["outcome"], "invalid_request", "{refused}");
        assert_eq!(refused["detail"]["field"], "bundle_identity", "{refused}");
        assert_eq!(
            refused["detail"]["reason_code"], "missing_field",
            "{refused}"
        );
    }
}

/// A relayed `computer_use` call, driven through the production frame loop and
/// the tool handler, writes the caller behind it on its computer journal row.
#[cfg(all(test, target_os = "macos"))]
mod relayed_computer_call_tests {
    use super::*;
    use cerebellum_computer::app_state::source::{
        AppStateReadError, AppStateSource, RawAppState, ReadBounds,
    };
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
    use cerebellum_core::journal::{
        CallOriginRecord, InMemoryJournalStorage, JournalConfig, JournalStorage, OriginCarrier,
    };

    const CHANNEL: u16 = 7;
    const EPOCH: u32 = 1;
    const APP: &str = "com.example.Editor";

    struct Running;

    impl management::TargetResolver for Running {
        fn resolve(&self, bundle_identity: &str) -> TargetResolution {
            TargetResolution::Resolved(ProcessGrant {
                pid: 4242,
                bundle_identity: bundle_identity.to_string(),
                process_generation_evidence: "1700000000000000".to_string(),
            })
        }

        fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn computer_grants::AppCode> {
            Arc::new(computer_grants::SignedByFixtureTeam)
        }
    }

    /// An application whose state cannot be read. The plane journals such a
    /// read before it answers, so the call writes a row without touching a
    /// real application.
    struct Unreadable;

    impl AppStateSource for Unreadable {
        fn read_app_state(
            &self,
            _target: &ProcessGrant,
            _bounds: ReadBounds,
        ) -> Result<RawAppState, AppStateReadError> {
            Err(AppStateReadError::Unreadable)
        }
    }

    /// Planes whose computer journal is held in `storage`, in memory, with one
    /// tool route for the session caller that can relay a question.
    fn planes(storage: &InMemoryJournalStorage) -> Planes {
        planes_with_source(storage, Arc::new(Unreadable))
    }

    fn planes_with_source(
        storage: &InMemoryJournalStorage,
        source: Arc<dyn AppStateSource>,
    ) -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.management = Arc::new(ManagementPlane::new(Arc::new(Running)));
        let custody = CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 5_000,
                maximum_pin_lifetime_ms: 30_000,
                maximum_concurrently_pinned_artifacts: 8,
                maximum_total_pinned_artifact_bytes: 64 * 1024 * 1024,
                maximum_custody_attachment_bytes: 16 * 1024 * 1024,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .unwrap();
        let audit = cerebellum_computer::audit::ComputerAudit::new(
            cerebellum_computer::audit::redaction::ExcludeApplicationText,
            cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
            JournalConfig {
                journal_retention_bytes: 8 * 1024 * 1024,
                journal_max_entry_bytes: 64 * 1024,
            },
            PlaneJournalStorage::InMemory(storage.clone()),
            custody,
        )
        .unwrap();
        // The screen is pinned unlocked: a locked developer machine would
        // refuse the call before it reads anything.
        planes.computer = Ok(Arc::new(
            computer_capability::ComputerPlane::with_synthetic_driver(audit, || {
                computer_capability::NativeComputerPlatformDriver::default()
                    .without_expected_post_condition()
            })
            .with_session_lock_for_test(Some(false))
            .with_app_state_source(source),
        ));
        planes.computer_admitted = Arc::new(["computer.read_state".to_string()].into());
        planes.routes.insert(
            CHANNEL,
            EPOCH,
            AcceptedBindFacts::from_bind(
                &subc_protocol::BindIdentity::new(
                    "/test/project",
                    "test",
                    "test-session".to_string(),
                ),
                session_caller_principal_for_test(),
                Some(&json!({
                    "agentProjectId": "test-project",
                    "sessionKind": "primary",
                    "effectiveCapabilityScope": ["*"],
                })),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        planes
    }

    /// Send one `computer_use` read of the application, allow the app when
    /// the call asks, and return the computer journal's decoded entries.
    async fn read_state_rows(origin: Option<Value>) -> Vec<Value> {
        let storage = InMemoryJournalStorage::new();
        let planes = planes(&storage);
        let mut request = json!({
            "name": flat_tools::COMPUTER_USE,
            "arguments": {"action": "read_state", "target": APP},
        });
        if let Some(origin) = origin {
            request["origin"] = origin;
        }
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(
            Frame::build(
                FrameType::Request,
                control_flags(),
                CHANNEL,
                EPOCH,
                42,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap(),
            &tx,
            &planes,
        )
        .await
        .unwrap();
        let mut frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("the call answered or asked")
            .unwrap();
        if frame.header.ty == FrameType::Request {
            assert!(planes.elicitor.deliver(
                frame.header.channel,
                frame.header.corr,
                json!({"decision": "allow_conversation"}),
            ));
            frame = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .expect("the allowed call answered")
                .unwrap();
        }
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "{}",
            String::from_utf8_lossy(&frame.body)
        );
        assert_eq!(frame.header.corr, 42);

        let state = serde_json::to_value(storage.load().unwrap()).unwrap();
        state["entries"]
            .as_object()
            .into_iter()
            .flat_map(|entries| entries.values())
            .map(|entry| {
                let bytes = cerebellum_core::serde_base64::decode(entry["bytes"].as_str().unwrap())
                    .unwrap();
                serde_json::from_slice(&bytes).unwrap()
            })
            .collect()
    }

    async fn bind_basal_flow(
        planes: &Planes,
        tx: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
    ) {
        let stamp = subc_protocol::scope::ScopeStamp {
            owner: session_caller_principal_for_test().unwrap(),
            scope_ref: "flow-head".into(),
            scope_epoch: 1,
            kind: subc_protocol::scope::ScopeKind::Head,
            parent: None,
            parent_state: None,
            attributes: subc_protocol::scope::ScopeAttributes {
                agent_id: Some("test-project".into()),
                delegates: true,
                flow_id: Some("flow-computer".into()),
            },
            owner_authorized: true,
        };
        let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
            role_versions: None,
            route_channel: CHANNEL,
            epoch: EPOCH,
            target: subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            identity: subc_protocol::BindIdentity::new("/test/project", "test", "test-session"),
            principal: Some(subc_protocol::Principal::Reserved {
                module_id: "basal".into(),
            }),
            consumer_capabilities: Some(vec!["elicitation".into()]),
            admission_facts: None,
            scope: Some(stamp),
        };
        handle_frame(
            Frame::build(
                FrameType::Request,
                control_flags(),
                0,
                0,
                40,
                serde_json::to_vec(&bind).unwrap(),
            )
            .unwrap(),
            tx,
            planes,
        )
        .await
        .unwrap();
        let reply = rx.recv().await.unwrap();
        assert_eq!(
            reply.header.ty,
            FrameType::Response,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
    }

    #[tokio::test]
    async fn flow_persistent_app_grant_reads_and_missing_grant_never_reads() {
        use computer_grants::{
            AlwaysGrantRecord, ComputerGrants, GrantStorage, GrantStoreState, InMemoryGrantStorage,
            GRANT_STORE_VERSION,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountReads(Arc<AtomicUsize>);
        impl AppStateSource for CountReads {
            fn read_app_state(
                &self,
                _: &ProcessGrant,
                _: ReadBounds,
            ) -> Result<RawAppState, AppStateReadError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(AppStateReadError::Unreadable)
            }
        }
        for granted in [false, true] {
            let reads = Arc::new(AtomicUsize::new(0));
            let mut planes = planes_with_source(
                &InMemoryJournalStorage::new(),
                Arc::new(CountReads(reads.clone())),
            );
            let storage = Arc::new(InMemoryGrantStorage::new());
            storage
                .save(&GrantStoreState {
                    version: GRANT_STORE_VERSION,
                    records: if granted {
                        vec![AlwaysGrantRecord {
                            agent_project_id: "test-project".into(),
                            bundle_identity: APP.into(),
                            team_id: Some("FIXTURE001".into()),
                            designated_requirement: Some(
                                "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                            ),
                            machine_uuid: "machine".into(),
                            created_at_ms: 1,
                        }]
                    } else {
                        vec![]
                    },
                })
                .unwrap();
            planes.management = Arc::new(ManagementPlane::with_computer_grants(
                Arc::new(Running),
                Arc::new(ComputerGrants::open(storage, Some("machine".into()))),
            ));
            // A grant given in this conversation must not authorize the flow;
            // only the owner's persistent app grant may.
            planes
                .management
                .computer_grants()
                .seed_conversation_app_for_test("test-session", APP);
            planes.computer_admitted =
                Arc::new(["computer.read_state".into(), "computer.keys".into()].into());
            let (tx, mut rx) = mpsc::channel(8);
            bind_basal_flow(&planes, &tx, &mut rx).await;
            let request =
                json!({"name":"computer_use","arguments":{"action":"read_state","target":APP}});
            handle_frame(
                Frame::build(
                    FrameType::Request,
                    control_flags(),
                    CHANNEL,
                    EPOCH,
                    42,
                    serde_json::to_vec(&request).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            if granted {
                assert_eq!(reads.load(Ordering::SeqCst), 1, "{body}");
            } else {
                assert_eq!(body["outcome"], "consent_unavailable", "{body}");
                assert_eq!(body["reason"], "unattended_flow");
                assert_eq!(reads.load(Ordering::SeqCst), 0);
            }
            assert_eq!(planes.elicitor.outstanding(), 0);
            assert!(rx.try_recv().is_err());
            if granted {
                planes
                    .management
                    .computer_grants()
                    .seed_takeover_for_test("test-session");
                let keys = json!({"name":"computer_use","arguments":{"action":"keys","target":APP,"keys":["command","s"]}});
                handle_frame(
                    Frame::build(
                        FrameType::Request,
                        control_flags(),
                        CHANNEL,
                        EPOCH,
                        43,
                        serde_json::to_vec(&keys).unwrap(),
                    )
                    .unwrap(),
                    &tx,
                    &planes,
                )
                .await
                .unwrap();
                let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.header.ty, FrameType::Response);
                let body: Value = serde_json::from_slice(&reply.body).unwrap();
                assert_eq!(body["outcome"], "consent_unavailable", "{body}");
                assert_eq!(body["reason"], "takeover_not_for_flows", "{body}");
                assert_eq!(
                    reads.load(Ordering::SeqCst),
                    1,
                    "fronting keys must refuse before another app read"
                );
                assert_eq!(planes.elicitor.outstanding(), 0);
                assert!(rx.try_recv().is_err());
            }
        }
    }

    #[tokio::test]
    async fn flow_takeover_refuses_even_with_existing_takeover_grant() {
        let mut planes = planes(&InMemoryJournalStorage::new());
        planes.computer_admitted = Arc::new(
            [
                "computer.takeover_move".into(),
                "computer.takeover_drag".into(),
                "computer.takeover_scroll".into(),
            ]
            .into(),
        );
        let (tx, mut rx) = mpsc::channel(8);
        bind_basal_flow(&planes, &tx, &mut rx).await;
        planes
            .management
            .computer_grants()
            .seed_takeover_for_test("test-session");
        let image_id = planes.management.app_state_sessions().register_image(
            "test-session",
            cerebellum_computer::app_state::session::RegisteredImage {
                bundle_identity: APP.into(),
                pid: 4242,
                process_generation: "1700000000000000".into(),
                width_px: 100,
                height_px: 100,
                mapping: cerebellum_computer::app_state::image::ImageMapping::for_window(
                    (0.0, 0.0),
                    (100.0, 100.0),
                    (100, 100),
                    (100, 100),
                )
                .unwrap(),
            },
        );
        for (corr, action) in [
            (
                44,
                json!({"action":"takeover_scroll", "target":APP,"axis":"vertical","amount_lines":1}),
            ),
            (
                42,
                json!({"action":"takeover_move", "image_id":image_id, "to":{"x":1,"y":1}}),
            ),
            (
                43,
                json!({"action":"takeover_drag", "image_id":image_id, "from":{"x":1,"y":1},"to":{"x":2,"y":2}}),
            ),
        ] {
            let request = json!({"name":"computer_use","arguments":action});
            handle_frame(
                Frame::build(
                    FrameType::Request,
                    control_flags(),
                    CHANNEL,
                    EPOCH,
                    corr,
                    serde_json::to_vec(&request).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "consent_unavailable", "{body}");
            assert_eq!(body["detail"]["reason"], "takeover_not_for_flows", "{body}");
            assert_eq!(planes.elicitor.outstanding(), 0);
            assert!(rx.try_recv().is_err());
        }
    }

    #[tokio::test]
    async fn flow_scope_admission_blocks_computer_reads_before_consent() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct CountReads(Arc<AtomicUsize>);
        impl AppStateSource for CountReads {
            fn read_app_state(
                &self,
                _: &ProcessGrant,
                _: ReadBounds,
            ) -> Result<RawAppState, AppStateReadError> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err(AppStateReadError::Unreadable)
            }
        }
        let reads = Arc::new(AtomicUsize::new(0));
        let storage = InMemoryJournalStorage::new();
        let planes = planes_with_source(&storage, Arc::new(CountReads(reads.clone())));
        let (tx, mut rx) = mpsc::channel(8);
        for flow_id in [Some("flow-1".to_string()), None] {
            let stamp = subc_protocol::scope::ScopeStamp {
                owner: session_caller_principal_for_test().unwrap(),
                scope_ref: "head".into(),
                scope_epoch: 1,
                kind: subc_protocol::scope::ScopeKind::Head,
                parent: None,
                parent_state: None,
                attributes: subc_protocol::scope::ScopeAttributes {
                    agent_id: Some("test-project".into()),
                    delegates: true,
                    flow_id: flow_id.clone(),
                },
                owner_authorized: true,
            };
            let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
                role_versions: None,
                route_channel: CHANNEL,
                epoch: EPOCH,
                target: subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".into(),
                },
                identity: subc_protocol::BindIdentity::new("/test/project", "test", "test-session"),
                principal: session_caller_principal_for_test(),
                consumer_capabilities: Some(vec!["elicitation".into()]),
                admission_facts: Some(
                    json!({"agentProjectId":"test-project", "sessionKind":"primary"}),
                ),
                scope: Some(stamp),
            };
            handle_frame(
                Frame::build(
                    FrameType::Request,
                    control_flags(),
                    0,
                    0,
                    40,
                    serde_json::to_vec(&bind).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            assert_eq!(rx.recv().await.unwrap().header.ty, FrameType::Response);
            let request =
                json!({"name":"computer_use", "arguments":{"action":"read_state", "target":APP}});
            handle_frame(
                Frame::build(
                    FrameType::Request,
                    control_flags(),
                    CHANNEL,
                    EPOCH,
                    42,
                    serde_json::to_vec(&request).unwrap(),
                )
                .unwrap(),
                &tx,
                &planes,
            )
            .await
            .unwrap();
            let mut reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            if flow_id.is_some() {
                assert_eq!(reply.header.ty, FrameType::Response);
                assert_eq!(
                    serde_json::from_slice::<Value>(&reply.body).unwrap(),
                    json!({
                        "outcome":"consent_unavailable", "detail":{"reason":"flow_carrier_not_admitted"}, "remedy":"open the flow route through authorized reserved:basal"
                    })
                );
                assert_eq!(reads.load(Ordering::SeqCst), 0);
                assert_eq!(planes.elicitor.outstanding(), 0);
                assert!(
                    rx.try_recv().is_err(),
                    "a flow must not send an elicitation"
                );
            } else {
                assert_eq!(
                    reply.header.ty,
                    FrameType::Request,
                    "the attended route may ask for app consent"
                );
                assert!(planes.elicitor.deliver(
                    reply.header.channel,
                    reply.header.corr,
                    json!({"decision":"allow_conversation"})
                ));
                reply = tokio::time::timeout(Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply.header.ty, FrameType::Response);
                assert_eq!(
                    reads.load(Ordering::SeqCst),
                    1,
                    "the non-flow route actually reads synthetic app state"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_relayed_computer_call_names_its_origin_on_its_journal_row() {
        let rows = read_state_rows(Some(json!({
            "carrier": {"kind": "reserved", "module_id": "agent-host"},
            "call_key": "agent:read-1",
        })))
        .await;
        assert!(!rows.is_empty(), "the read wrote no journal row");
        let expected = serde_json::to_value(CallOriginRecord::Relayed {
            carrier: OriginCarrier::Reserved {
                module_id: "agent-host".to_string(),
            },
            call_key: "agent:read-1".to_string(),
        })
        .unwrap();
        for row in &rows {
            assert_eq!(row["codec_version"], "ck-computer-journal/v3", "{row}");
            assert_eq!(row["identity"]["origin"], expected, "{row}");
            // Still the route's own principal: the origin names who it acted
            // for, never who acted.
            assert!(
                row["identity"]["principal"]
                    .as_str()
                    .is_some_and(|principal| principal.contains("prefrontal-core")),
                "{row}"
            );
        }
    }

    #[tokio::test]
    async fn a_computer_call_naming_no_origin_writes_none_on_its_journal_row() {
        let rows = read_state_rows(None).await;
        assert!(!rows.is_empty(), "the read wrote no journal row");
        for row in &rows {
            assert!(row["identity"].get("origin").is_none(), "{row}");
        }
    }
}
