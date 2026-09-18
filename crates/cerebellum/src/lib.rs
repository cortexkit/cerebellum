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
pub mod browser_executable_identity;
pub mod browser_launch;
pub mod browser_launch_readiness;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod browser_launch_service;
pub mod browser_session;
pub mod browser_type;
pub mod capability;
pub mod cdp;
pub mod classification;
pub mod computer_capability;
pub mod connector_evidence;
pub mod coordinate;
pub mod custody;
pub mod elicit;
pub mod flat_tools;
pub mod journal;
pub mod journal_admin;
pub mod journal_pin;
pub mod login_import;
pub mod management;
pub mod manifest;
pub mod network;
pub mod profile;
pub mod profile_custody;
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
use cerebellum_core::clock::SystemClock;
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

pub use browser::{handle_tool as handle_browser_tool, BrowserCapability, BrowserPlane};
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
pub use cerebellum_core::principal::{trust_for_principal, PrincipalTrust};
pub use wire::{build_error_frame, control_flags};

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
    FrozenEightRows,
    PartialRuntimeAdvertisement,
    EmptyRuntimeAdvertisement,
}

const COMPUTER_FROZEN_ROW_COUNT: usize = 8;
const COMPUTER_CAPABILITY_IDS: [&str; COMPUTER_FROZEN_ROW_COUNT] = [
    "computer.click",
    "computer.type",
    "computer.keys",
    "computer.scroll",
    "computer.move",
    "computer.drag",
    "computer.screenshot",
    "computer.wait",
];

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
const COMPUTER_RELEASE_GATE_TABLE: [ComputerReleaseGate; 19] = [
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
        "release_signing_topology_revision" => inputs.release_signing_topology_revision.as_deref(),
        _ => unreachable!("every external release gate has a bound input"),
    }
}

fn gate_passes(outcomes: &ComputerGateOutcomes, gate: &str) -> bool {
    matches!(outcomes.get(gate), Some(ComputerGateOutcome::Pass))
}

fn declaration_gate_passes(
    declaration: &ComputerCapabilityDeclaration,
    context: &ComputerCapabilityAdvertisementContext,
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
    if id == "computer.screenshot" {
        context
            .startup
            .permissions
            .state(PermissionService::ScreenRecording)
            == PermissionLiveness::Live
            && [
                "capture_review_revision",
                "release_signing_topology_revision",
            ]
            .iter()
            .all(|gate| gate_passes(outcomes, gate))
    } else if id == "computer.click" {
        let platform_review = if cfg!(target_os = "windows") {
            "windows_actuation_review_revision"
        } else {
            "semantic_actuation_review_revision"
        };
        [platform_review, "release_signing_topology_revision"]
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
    } else if matches!(id, "computer.scroll" | "computer.move" | "computer.drag") {
        [
            "attendance_contract_owner",
            "attendance_contract_revision",
            "input_review_revision",
            "global_dispatch_review_revision",
            "release_signing_topology_revision",
        ]
        .iter()
        .all(|gate| gate_passes(outcomes, gate))
        // Deliberately NOT gated on private_envelope_recognized. That flag
        // asks whether this build resolved private SkyLight symbols, which
        // is evidence for a design this module does not use: per-process
        // delivery goes through the PUBLIC CGEventPostToPid, measured on
        // macOS 26 to reach an unfocused application with no focus change
        // and no private symbol involved.
        //
        // Requiring it would withhold every synthetic row forever, since
        // production supplies no envelope revision and no resolved symbols
        // by construction. The permissions the vocabulary names are what
        // actually gate these rows, and they are checked where every
        // declaration's permissions are checked.
    } else {
        declaration.capability_id == "computer.wait"
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
    context: &ComputerCapabilityAdvertisementContext,
    outcomes: &ComputerGateOutcomes,
) -> Vec<&'a ComputerCapabilityDeclaration> {
    gate_admitted_computer_declarations(declarations, context, outcomes)
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
    context: &ComputerCapabilityAdvertisementContext,
    outcomes: &ComputerGateOutcomes,
) -> Vec<&'a ComputerCapabilityDeclaration> {
    if !canonical_declaration_is_complete(declarations) {
        return Vec::new();
    }
    declarations
        .iter()
        .filter(|declaration| {
            declaration.advertised && declaration_gate_passes(declaration, context, outcomes)
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
    let artifact: Value = serde_json::from_slice(include_bytes!(
        "../../cerebellum-computer/resources/computer_action_vocabulary-v8.json"
    ))
    .ok()?;
    let row = artifact
        .get("rows")?
        .as_array()?
        .iter()
        .find(|row| row.get("capability_id").and_then(Value::as_str) == Some(id))?;
    let action_kind = row.get("action_kind").and_then(Value::as_str)?;
    let execution_mode = if action_kind == "observe" {
        subc_protocol::manifest::ExecutionMode::Pure
    } else {
        subc_protocol::manifest::ExecutionMode::Unfenceable
    };
    Some(subc_protocol::manifest::Tool {
        name: id.to_string(),
        description: Some(format!("Computer-plane capability {id}.")),
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
    let advertised = advertised_computer_declarations(&declarations, context, &outcomes);
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
        gate_admitted_computer_declarations(&declarations, context, &gate_outcomes)
            .into_iter()
            .map(|declaration| declaration.capability_id.clone())
            .collect();
    let advertised_capabilities: Vec<String> =
        advertised_computer_declarations(&declarations, context, &gate_outcomes)
            .into_iter()
            .map(|declaration| declaration.capability_id.clone())
            .collect();
    let canonical_row_count = declarations.len();
    let advertised_row_count = advertised_capabilities.len();
    let scope = if advertised_row_count == COMPUTER_FROZEN_ROW_COUNT {
        ComputerAdvertisementScope::FrozenEightRows
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
            | management::OPEN_GRANT
            | management::IMPORT_LOGIN
            | management::REBIND_PROFILE_ROOT
    ) || (matches!(name, management::PRESENT | management::RESUME)
        && browser::has_wire_dispatch_route(name))
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
/// The eight external identifiers use `option_env!` so a release invocation must
/// supply each attestation before compilation. Starting a binary with a new
/// environment value cannot manufacture a review after the binary was built.
fn compiled_release_inputs() -> ComputerReleaseInputs {
    let semantic_actuation_review_revision =
        option_env!("CEREBELLUM_SEMANTIC_ACTUATION_REVIEW_REVISION");
    let windows_actuation_review_revision =
        option_env!("CEREBELLUM_WINDOWS_ACTUATION_REVIEW_REVISION");
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

    fn remove(&self, channel: u16, epoch: u32) -> Option<AcceptedBindFacts> {
        self.inner
            .write()
            .ok()
            .and_then(|mut routes| routes.remove(&(channel, epoch)))
    }
}

/// The binary entry point: read config from env, load the health config
/// file, and run the module loop. Exposed publicly so the thin `main.rs`
/// binary can delegate here.
pub async fn run_entry() -> Result<(), ModuleError> {
    let config = ModuleConfig::from_env()?;
    run(config).await
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

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut read_half, write_half) = tokio::io::split(stream);

    let health_state = Arc::new(HealthState::with_config(config.health));
    let browser_config = match &config.browser {
        BrowserSurface::Available(browser) => Some(browser.clone()),
        BrowserSurface::NotConfigured | BrowserSurface::Refused(_) => None,
    };
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    let mut planes = Planes::with_browser_config(Arc::clone(&health_state), browser_config.clone());
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let planes = Planes::with_browser_config(Arc::clone(&health_state), browser_config.clone());
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
            planes.launch_service = Some(Arc::new(
                browser_launch_service::ProductionLaunchService::open(browser),
            ));
        }
    }
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
    let connection_result = serve_until_disconnect(
        &mut read_half,
        write_half,
        &config,
        planes,
        browser_config.as_ref(),
        idle_enforcer,
    )
    .await;

    connection_result
}

/// Serve the daemon connection and, once it ends for any reason, close every
/// browser session before returning.
///
/// The daemon does not send a GOODBYE or a drain when it is cut (a
/// `launchctl bootout` kills it with no handler); a module learns by EOF. The
/// graceful stop therefore also runs on connection ending, even without a
/// drain notice. Sessions are torn down before the result is reported.
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
    let connection_result = run_connection(read_half, write_half, config, planes.clone()).await;
    if let Some(enforcer) = idle_enforcer {
        enforcer.abort();
    }
    if let Some(browser) = browser_config {
        planes.sessions.teardown_all(browser);
    }

    connection_result
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
        launch_nonce: std::env::var(subc_protocol::SUBC_LAUNCH_NONCE_ENV)
            .ok()
            .filter(|value| !value.is_empty()),
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
    draining: Arc<std::sync::atomic::AtomicBool>,
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

impl Planes {
    /// A browser config with every deadline short and no executable, for
    /// tests. A running module builds through `with_browser_config` with the
    /// config it loaded, `None` when the file names no browser.
    pub fn new(health: Arc<HealthState>) -> Self {
        Self::with_browser_config(
            health,
            Some(BrowserConfig {
                executable_path: None,
                expected_identity: None,
                launch_handshake_deadline_ms: 100,
                termination_grace_period_ms: 100,
                browser_idle_timeout_ms: 30_000,
                browser_exit_observation_deadline_ms: 100,
                navigation_settle_deadline_ms: 100,
            }),
        )
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
        // The launch service picks its process launcher per platform and has
        // done since the Linux barrier landed. This wiring stayed macOS-only,
        // which left a merged Linux launcher unreachable and the refusal
        // blaming profile storage several layers away from the cause.
        //
        // Platforms without a launcher still get None: ProductionLaunchService
        // resolves one at construction, so this cannot advertise a launch it
        // cannot perform.
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
                .map(browser_launch_service::ProductionLaunchService::open)
                .map(|service| {
                    Arc::new(service) as Arc<dyn browser_session::BrowserSessionLauncher>
                });
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let launch_service = None;
        let sessions = browser_session::BrowserSessions::default();
        let lease_clock = Arc::new(cerebellum_core::clock::SystemClock::new());
        let management = Arc::new(ManagementPlane::new(Arc::new(
            management::PlatformResolver::new(),
        )));
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
        #[cfg(target_os = "macos")]
        let global_dispatch_review_revision =
            compiled_release_inputs().global_dispatch_review_revision;
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
            computer: computer_capability::production_audit().map(|audit| {
                // One idle estimator for the plane's lifetime: it exists to
                // remember the previous sequence's posts, which a per-dispatch
                // driver cannot do.
                #[cfg(target_os = "macos")]
                let user_idle = Arc::new(std::sync::Mutex::new(
                    cerebellum_computer::dispatch::UserIdleEstimator::new(),
                ));
                Arc::new(computer_capability::ComputerPlane::with_synthetic_driver(
                    audit,
                    // Built fresh per dispatch: each platform driver caches
                    // accessibility trees, and a stale cache may name a process
                    // generation that is gone. Synthetic requests declare no
                    // post-condition, so their effects remain indeterminate.
                    move || {
                        let driver = computer_capability::NativeComputerPlatformDriver::default()
                            .without_expected_post_condition();
                        #[cfg(target_os = "macos")]
                        let driver = driver
                            .with_global_dispatch_review_revision(
                                global_dispatch_review_revision.clone(),
                            )
                            .with_shared_user_idle(user_idle.clone());
                        driver
                    },
                ))
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
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            elicitor: Arc::new(Elicitor::new()),
        }
    }
}

/// The computer capabilities a test module admits.
///
/// Production reads this from the release gates. A test that went through those
/// gates would exercise release binding rather than the behaviour under test,
/// and would go silently green the day an identifier came unbound: every
/// request refused, and every assertion about a refusal still passing.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub fn test_admitted_computer_capabilities() -> Arc<std::collections::BTreeSet<String>> {
    #[cfg(target_os = "macos")]
    let capabilities = ["computer.click", "computer.screenshot", "computer.wait"].as_slice();
    #[cfg(target_os = "windows")]
    let capabilities = ["computer.click", "computer.wait"].as_slice();
    Arc::new(capabilities.iter().copied().map(str::to_string).collect())
}

impl Clone for Planes {
    fn clone(&self) -> Self {
        Self {
            #[cfg(test)]
            route_test_handler: self.route_test_handler.clone(),
            health: Arc::clone(&self.health),
            draining: self.draining.clone(),
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
            if let Some(facts) = planes
                .routes
                .remove(frame.header.channel, frame.header.epoch)
            {
                if let Some(config) = planes.browser_config.as_ref() {
                    planes.sessions.teardown_route(
                        &facts.identity.conversation_key,
                        browser_session::BrowserSessionTerminalOutcome::RouteUnbound,
                        config,
                    );
                }
            }
            Ok(true)
        }
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, writer, &planes.health, &planes.routes).await?;
            Ok(true)
        }
        FrameType::Request => {
            if planes.draining.load(std::sync::atomic::Ordering::Acquire) {
                let (reason, deadline_ms) =
                    planes.drain_notice.get().expect("drain notice published");
                let refusal = Frame::build_with_version(
                    frame.header.ver,
                    FrameType::Error,
                    frame.header.flags,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    serde_json::to_vec(&json!({
                        "code": "module_draining", "reason": reason, "deadline_ms": deadline_ms,
                        "message": "retry after the module restarts",
                        "remedy": "retry after the module restarts"
                    }))
                    .map_err(ModuleError::Json)?,
                )
                .map_err(|e| ModuleError::Message(e.to_string()))?;
                send(writer, refusal).await?;
                return Ok(true);
            }
            let guard = planes.health.enter_request();
            let writer = writer.clone();
            let planes = planes.clone();
            tokio::spawn(async move {
                let _guard = guard;
                #[cfg(test)]
                if let Some(handler) = &planes.route_test_handler {
                    handler().await;
                }
                let _ = handle_route_request(frame, &writer, &planes).await;
            });
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

    match facts.surface {
        RouteSurface::Tools => handle_tool_request(frame, writer, planes).await,
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
        if crate::classification::canonical_origin(origin).as_deref() != Some(origin) {
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
            import_browser_login(planes, facts, writer, channel, epoch, origin).await
        } else {
            present_browser_handoff(planes, &facts.identity, origin).await
        };
        return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
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

    enum Settlement {
        ComputerTarget,
        BrowserGrant,
        ProfileRootRebind,
    }

    let (reply, question, settlement) = if method == management::OPEN_TARGET {
        let Some(bundle_identity) = params_object
            .get("bundle_identity")
            .and_then(serde_json::Value::as_str)
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
        let Some(action_kind) = params_object
            .get("action_kind")
            .and_then(serde_json::Value::as_str)
            .and_then(management::action_kind_from_wire)
        else {
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "action_kind",
                "missing_field",
            )
            .await;
        };
        let grantee = facts.identity.agent_project_id.clone();
        let clock = SystemClock::default();
        let (reply, question) = planes
            .management
            .open_target(
                &grantee,
                bundle_identity,
                action_kind,
                facts.declares_elicitation(),
                &clock,
            )
            .await;
        (reply, question, Settlement::ComputerTarget)
    } else if method == management::OPEN_GRANT {
        if let Some(field) = params_object
            .keys()
            .filter(|field| !matches!(field.as_str(), "origins" | "hazards"))
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
        let opened = planes
            .management
            .open_browser_grant(
                &facts.identity.conversation_key,
                origins,
                hazards,
                facts.declares_elicitation(),
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
        };
        (reply, question, Settlement::BrowserGrant)
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
            let answer = match outcome {
                elicit::AskOutcome::Answered(body) => Some(body),
                elicit::AskOutcome::NoAnswer | elicit::AskOutcome::Undeliverable => None,
            };
            match settlement {
                Settlement::ComputerTarget => {
                    management_plane
                        .settle(&question.ask_id, answer.as_ref(), &SystemClock::default())
                        .await;
                }
                Settlement::BrowserGrant => {
                    management_plane
                        .settle_browser_grant(&question.ask_id, answer.as_ref())
                        .await;
                }
                Settlement::ProfileRootRebind => {
                    management_plane
                        .settle_profile_root_rebind(&question.ask_id, answer.as_ref())
                        .await;
                }
            }
        });
    }

    send_tool_response(writer, ver, channel, epoch, corr, reply).await
}

async fn import_browser_login(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
    origin: &str,
) -> Value {
    let status = planes.sessions.status(
        &facts.identity.conversation_key,
        planes.lease_clock.as_ref(),
        std::time::SystemTime::now(),
    );
    let session_open = status.get("outcome").and_then(Value::as_str) == Some("ready");
    let durable = facts.identity.profile_disposition == ProfileDisposition::Durable;
    if let Err(result) = login_import::profile_precondition(origin, durable, session_open) {
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

    let ask_id = login_import::new_ask_id();
    let question = plan.question(&ask_id, &facts.identity.agent_project_id);
    let answer = planes
        .elicitor
        .ask(
            writer,
            channel,
            epoch,
            question,
            login_import::ELICITATION_DEADLINE,
        )
        .await;
    let decision = match &answer {
        elicit::AskOutcome::Answered(body) => body.get("decision").and_then(Value::as_str),
        elicit::AskOutcome::NoAnswer | elicit::AskOutcome::Undeliverable => None,
    };
    if decision.is_some_and(|value| value.starts_with("transfer:")) {
        let status = planes.sessions.status(
            &facts.identity.conversation_key,
            planes.lease_clock.as_ref(),
            std::time::SystemTime::now(),
        );
        if status.get("outcome").and_then(Value::as_str) == Some("ready") {
            let result = plan.refusal("session_open", "browser.close");
            return journal_login_import_result(planes, &facts.identity, result).await;
        }
    }
    let result = plan.decide(decision);
    journal_login_import_result(planes, &facts.identity, result).await
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
        } => {
            // In-module principal default-deny backstop: the gateway policy
            // (subc-mcp) is the primary exclusion of cerebellum capabilities
            // from `mcp:*` surfaces. This check is the defense-in-depth backstop
            // that rejects a forged direct dispatch under a non-first-party
            // principal before any capability executes.
            let trust = trust_for_principal(&principal);
            if !trust.is_first_party() {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }

            // Retain only facts from the accepted bind. Data-plane frames inherit
            // these facts by (channel, epoch); request bodies cannot replace them.
            let accepted_facts = AcceptedBindFacts::from_bind(
                &identity,
                principal.clone(),
                admission_facts.as_ref(),
                consumer_capabilities.as_deref(),
                &target,
            );
            route_bindings.insert(route_channel, epoch, accepted_facts);
            // Accept the bind — capability scope is checked at dispatch time.
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // Insulated health-v2 lane: the report is a mechanical mapper over
            // atomics stamped by the dispatch path. It never blocks on a lock
            // and never forms its own opinion (Health-Path-Rule-v2).
            health_state.report()
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
    let label = principal
        .as_ref()
        .map(|p| match p {
            subc_protocol::Principal::Reserved { module_id } => {
                format!("reserved:{module_id}")
            }
            subc_protocol::Principal::Direct => "direct".to_string(),
            subc_protocol::Principal::Unverified => "unverified".to_string(),
        })
        .unwrap_or_else(|| "absent".to_string());
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

async fn handle_tool_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    let route_bindings = &planes.routes;
    let browser_plane = &planes.browser;
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

    // Tool-route envelopes are closed. `progress_token` is the only optional
    // gateway member; it is accepted for correlation but not used here.
    if let Some(field) = object
        .keys()
        .filter(|field| !matches!(field.as_str(), "name" | "arguments" | "progress_token"))
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

    let Some(accepted_facts) = route_bindings.get(channel, epoch) else {
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

    if browser_session::CONTROL_TOOLS.contains(&name) {
        let result = if accepted_facts.allows_control_operation(name) {
            handle_browser_control(name, arguments, &accepted_facts, planes).await
        } else {
            json!({"outcome": "authorization_denied"})
        };
        return send_tool_response(writer, ver, channel, epoch, corr, result).await;
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
        let result = plane
            .serve(
                servable,
                arguments,
                computer_capability::ServeContext {
                    // The durable agent identity, taken from the accepted bind
                    // rather than from the request: an identity a caller could
                    // choose is a lease granted to whoever asks for it.
                    grantee: &accepted_facts.identity.agent_project_id,
                    identity: cerebellum_core::journal::JournalIdentity {
                        principal: accepted_facts
                            .principal
                            .as_ref()
                            .map(|principal| format!("{principal:?}"))
                            .unwrap_or_default(),
                        conversation_key: accepted_facts.identity.conversation_key.clone(),
                        agent_project_id: accepted_facts.identity.agent_project_id.clone(),
                        session_kind: accepted_facts.identity.session_kind,
                    },
                    management: &planes.management,
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

    let Some(capability) = browser::BrowserCapability::parse(name) else {
        let result =
            browser::handle_tool(browser_plane, &accepted_facts.identity, name, arguments).await;
        return match result {
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
    };
    let result = browser_plane
        .serve(&accepted_facts.identity, capability, arguments)
        .await;
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
            };
            let launch = if let Some(service) = planes.launch_service.clone() {
                let accepted = accepted.clone();
                let id = browser_session_id.clone();
                match tokio::task::spawn_blocking(move || service.launch(&accepted, &id)).await {
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

pub async fn handle_control_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    handle_control_request(frame, writer, health_state, &route_bindings).await
}

pub async fn handle_control_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_control_request(frame, writer, health_state, route_bindings).await
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
            Some(subc_protocol::Principal::Direct),
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
            Some(subc_protocol::Principal::Direct),
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
            Some(subc_protocol::Principal::Direct),
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
    handle_tool_request(frame, writer, planes).await
}

pub async fn handle_tool_request_for_test_with_existing_planes(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
) -> Result<(), ModuleError> {
    handle_tool_request(frame, writer, planes).await
}

pub async fn handle_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    install_test_bind(&route_bindings, &frame);
    let mut planes = Planes::new(Arc::clone(health_state));
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = test_admitted_computer_capabilities();
    }
    handle_tool_request(frame, writer, &planes).await
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
    let mut planes = Planes::new(Arc::clone(health_state));
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = Arc::new(admitted.iter().map(|name| name.to_string()).collect());
    }
    #[cfg(not(target_os = "macos"))]
    let _ = admitted;
    handle_tool_request(frame, writer, &planes).await
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
    let mut planes = Planes::with_browser_config(Arc::clone(health_state), None);
    planes.routes = route_bindings;
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = Arc::new(admitted.iter().map(|name| name.to_string()).collect());
    }
    #[cfg(not(target_os = "macos"))]
    let _ = admitted;
    handle_tool_request(frame, writer, &planes).await
}

pub async fn handle_tool_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let mut planes = Planes::new(Arc::clone(health_state));
    planes.routes = Arc::clone(route_bindings);
    #[cfg(target_os = "macos")]
    {
        planes.computer_admitted = test_admitted_computer_capabilities();
    }
    handle_tool_request(frame, writer, &planes).await
}

#[cfg(test)]
mod tests {

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
            8,
            "expected eight attestations, found {read_here:?}"
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
                "action": "click",
                "target": {"by": "identifier", "identifier": "save"}
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
                flat_tools::COMPUTER_USE,
                "open_target",
                management::OPEN_TARGET,
                json!({"bundle_identity":"com.example.App","action_kind":"compose"}),
            ),
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
                Some(Principal::Direct),
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
            handle_tool_request(flat_frame, &tx, &planes).await.unwrap();
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
        let planes = Planes::with_browser_config(
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
                Some(Principal::Direct),
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
                Some(Principal::Direct),
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
            question["params"]["origins"],
            json!(["https://requested.example"])
        );
        assert_eq!(
            question["params"]["hazards"],
            json!(["credential_form_submit", "unverified_form_contents"])
        );
        let message = question["params"]["message"].as_str().unwrap();
        for disclosed in [
            "https://requested.example",
            "credential_form_submit",
            "unverified_form_contents",
        ] {
            assert!(
                message.contains(disclosed),
                "question omitted {disclosed}: {question}"
            );
        }

        let answer = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Response,
            Flags::new(false, Priority::Interactive, false),
            question_frame.header.channel,
            question_frame.header.epoch,
            question_frame.header.corr,
            serde_json::to_vec(&json!({"decision": "allow"})).unwrap(),
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
            .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow"})))
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
                &[],
                None,
                vec![
                    crate::snapshot_store::RefRecord {
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
                        classification: Some(Box::new(classification)),
                    },
                    crate::snapshot_store::RefRecord {
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
                        classification: None,
                    },
                ],
                4096,
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
            "call browser.open_grant to mint a grant that discloses detail.missing_hazard, then retry",
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
        assert_eq!(unknown["outcome"], "hazard_not_disclosed", "{unknown}");
        assert_eq!(
            unknown["detail"]["missing_hazard"], "unverified_form_contents",
            "{unknown}"
        );
        assert_eq!(
            unknown["remedy"],
            "call browser.open_grant to mint a grant that discloses detail.missing_hazard, then retry",
            "{unknown}"
        );
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
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            route_test_handler: None,
            elicitor: Arc::clone(&elicitor),
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
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            route_test_handler: None,
            elicitor: Arc::clone(&elicitor),
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
                "action_kind": "observe",
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

    /// A route bound to a surface this module does not serve is refused as such.
    ///
    /// Not served as either of the surfaces it does: answering from an envelope
    /// the caller did not use produces a reply about a request nobody made.
    #[tokio::test]
    async fn an_unsupported_surface_is_refused_by_name() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let planes = Planes {
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
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            elicitor: Arc::new(Elicitor::new()),
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
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            elicitor: Arc::new(Elicitor::new()),
        };
        planes.routes.insert(
            channel,
            epoch,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                Some(Principal::Direct),
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
            module_id: "prefrontal".to_string(),
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
        assert!(advertised_computer_declarations(&declarations, &context, &outcomes).is_empty());
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
                release_signing_topology_revision: Some("fixture-signing-topology"),
            }),
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let outcomes = computer_gate_outcomes(&context);
        assert_eq!(
            outcomes.into_values().collect::<Vec<_>>(),
            vec![ComputerGateOutcome::Pass; 11]
        );
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
                action_age_stale_ms: 30_000,
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
        let planes = Planes::new(Arc::new(HealthState::with_config(config.health)));

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
        let planes = Planes::with_browser_config(
            Arc::new(HealthState::with_config(config.health)),
            Some(browser.clone()),
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
            action_age_stale_ms: 30000,
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
        handle_frame(frame(FrameType::Request, 1, json!({"method": management::OPEN_TARGET, "params": {"bundle_identity":"com.example.Nothing", "action_kind":"observe"}})), &tx, &planes)
            .await
            .unwrap();
        handle_frame(draining(), &tx, &planes).await.unwrap();
        planes.route_test_handler = None;
        let mut invalid = frame(FrameType::Request, 2, json!({}));
        invalid.body = b"invalid JSON".to_vec();
        handle_frame(invalid, &tx, &planes).await.unwrap();
        let refusal: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
        assert_eq!(refusal["code"], "module_draining");
        assert_eq!(refusal["reason"], "restart");
        assert_eq!(refusal["deadline_ms"], 123);
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
