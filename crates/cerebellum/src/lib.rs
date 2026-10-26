//! ck-cerebellum library core — the subc wire seam, health-v2, identity,
//! principal default-deny, and the `browser.status` capability.
//!
//! The binary (`main.rs`) is a thin entry point that reads config from env and
//! calls [`run`]. The library exposes the module's internal handlers for
//! conformance tests.

#![forbid(unsafe_code)]
// Proving the route dispatcher's per-request worker future Send walks a very
// deep future type. At the default limit of 128 that proof overflowed, and
// under incremental compilation the overflowed and recomputed answers
// disagreed, so rustc aborted with "unstable fingerprints for
// evaluate_obligation" until the cache was cleaned.
#![recursion_limit = "256"]

pub mod agent_grants;
pub mod authorization;
mod blocking_permits;
pub mod browser;
pub mod browser_config;
mod browser_consent;
pub mod browser_crash_reports;
pub mod browser_executable_identity;
pub mod browser_launch;
pub mod browser_launch_readiness;
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub mod browser_launch_service;
mod browser_queue;
pub mod browser_session;
pub mod browser_signed_in;
pub mod browser_standing_grants;
pub mod browser_type;
pub mod budgets;
mod call_context;
#[cfg(test)]
mod call_mode_tests;
mod call_queue;
mod call_record_supervisor;
pub mod capability;
pub mod cdp;
pub mod cingulate_client;
pub mod classification;
mod codemode;
pub mod computer_capability;
pub mod computer_grants;
pub mod connector_evidence;
mod consent_card;
pub mod consent_drain;
#[cfg(test)]
mod content_named_fixture;
pub mod coordinate;
#[cfg(test)]
mod cursor_end_tests;
pub mod custody;
pub mod durable_formats;
mod egress;
pub mod flat_tools;
mod grant_enforcement;
pub mod journal;
pub mod journal_admin;
pub mod journal_pin;
mod launch_nonce;
pub mod launch_recovery;
pub mod login_capture;
mod login_fill_consent;
pub mod login_import;
pub mod management;
mod management_bounds;
pub mod manifest;
#[cfg(test)]
mod model_view_tests;
pub mod network;
mod open_app_history;
mod permission_cards;
mod permission_scope;
mod permissions;
mod private_content;
#[cfg(test)]
#[path = "../tests/support/private_content_marks.rs"]
mod private_content_marks_tests;
pub mod profile;
pub mod profile_custody;
pub mod public_suffix;
#[cfg(test)]
mod result_negotiation_tests;
#[cfg(test)]
mod route_future_size_tests;
pub mod scope_watch;
pub mod snapshot_store;
mod terminal_arbiter;
#[cfg(test)]
mod test_browser;
#[cfg(test)]
mod test_support;
mod tool_provider;
mod tool_result;
mod turn_ended;
#[cfg(test)]
#[path = "../tests/support/turn_stop_vectors.rs"]
mod turn_stop_vectors;
mod user_browser;
pub mod user_browser_bridge;
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

use crate::call_record_supervisor::{
    begin_call_record, call_record_unavailable, settle_call_record, CallRecordWorkers,
};
use crate::management::ManagementPlane;
use crate::management_bounds::{
    close_idle_for_import_off_task, on_call_blocking_pool, spawn_handoff_poll, HandoffSettle,
};
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
#[cfg(test)]
use tokio::io::AsyncWriteExt;
use tokio::io::{AsyncRead, AsyncWrite};
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
use egress::{drain_writer, request_id, ConnectionDeadlines};
use terminal_arbiter::run_arbitrated_route;
pub use terminal_arbiter::{
    CallStep, DispatchGate, HeldState, TerminalArbiter, TerminalCause, CALL_TERMINAL,
};
pub use wire::{build_error_frame, control_flags};

const DEFAULT_MODULE_ID: &str = "cerebellum";
const HELLO_CORR: u64 = 1;
const EGRESS_BUFFER: usize = budgets::EGRESS_BUFFER;

fn route_limits(frame: &Frame, planes: &Planes) -> (u64, u64) {
    let body = serde_json::from_slice::<Value>(&frame.body).unwrap_or(Value::Null);
    if planes
        .routes
        .get(frame.header.channel, frame.header.epoch)
        .is_some_and(|facts| facts.surface == RouteSurface::Management)
    {
        if let Some(limits) = budgets::MANAGEMENT_LIMITS
            .iter()
            .find(|limits| body["method"] == limits.method)
        {
            return (limits.envelope_ms, limits.reply_max_ms);
        }
    }
    if body["name"] == flat_tools::BROWSER_USE && body["arguments"]["browser"] == "user" {
        if let Some(budget) = budgets::user_browser_call(
            body["arguments"]["action"].as_str().unwrap_or_default(),
            &body["arguments"],
        ) {
            let envelope = budgets::CALL_RECORD_BEGIN_MS
                + budgets::BROWSER_QUEUE_WAIT_LIMIT_MS
                + budgets::user_consent_count(budget.action) * budgets::USER_CONSENT_MS
                + budget.work_ms;
            return (envelope, envelope + budgets::TERMINAL_SUFFIX_MS);
        }
    }
    if body["name"] == flat_tools::COMPUTER_USE {
        (
            budgets::COMPUTER_ENVELOPE_MS,
            budgets::COMPUTER_REPLY_MAX_MS,
        )
    } else {
        (budgets::BROWSER_ENVELOPE_MS, budgets::BROWSER_REPLY_MAX_MS)
    }
}

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
const COMPUTER_RELEASE_GATE_TABLE: [ComputerReleaseGate; 23] = [
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
    // Reported in release evidence but required by no capability row: it
    // admits fronting and preview capture inside rows that other gates admit.
    ComputerReleaseGate {
        name: "app_use_fronting_review_revision",
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
        "app_use_fronting_review_revision" => inputs.app_use_fronting_review_revision.as_deref(),
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
    } else if id == "computer.open_app" {
        // Launch selects a bundle from app state and acts under a signer-bound
        // app grant, so both surface reviews and the release signer must bind.
        [
            "app_state_review_revision",
            "element_addressed_review_revision",
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
    let mut declarations =
        computer::platform::WindowsPlatformDriver::default().declarations(context);
    #[cfg(not(target_os = "windows"))]
    let mut declarations =
        computer::platform::capability_declarations(context, cfg!(target_os = "macos"));
    // Driver declarations describe reviewed platform operations, not whether
    // this module can authorize them. A computer plane needs app grants for its
    // scoped actions; the production resolver cannot mint those without an
    // identity reader.
    // Withhold at the module assembly boundary so both HELLO and release
    // evidence agree, without changing driver-level review declarations. This
    // is a compile-time fact, not a probe of the person's grants or permissions.
    if !management::PlatformResolver::HAS_APP_IDENTITY_READER {
        for declaration in &mut declarations {
            declaration.advertised = false;
            declaration.suppression_reason =
                Some("no production app identity reader for computer grants".to_owned());
        }
    }
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
    build_manifest_with_computer_plane_and_provenance(
        module_id,
        context,
        manifest::build_provenance(),
    )
}

fn build_manifest_with_computer_plane_and_provenance(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
    provenance: Option<subc_protocol::manifest::ManifestProvenance>,
) -> subc_protocol::manifest::ModuleManifest {
    let mut manifest = manifest::build_with_provenance(module_id, provenance);
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

/// The registration manifest for offline `--manifest` inspection, without startup.
///
/// Advertisement depends on embedded build/release bindings, the target platform,
/// `SUBC_MODULE_ID`, and the read-only XDG cerebellum config. Missing, unreadable,
/// or invalid config uses the no-config surface. Valid browser config is parsed
/// but its executable is never probed: runtime executable-probe refusals and
/// `browser_surface_refused` are therefore not reported here.
///
/// No permission preflight, launch-nonce read, store, journal, runtime, or daemon
/// is needed. `provenance.launch_nonce_source` is omitted because launch delivery
/// is a runtime fact. Permission/startup readings do not affect advertisement or
/// `computer_plane_release`; that extension contains only compiled release facts.
pub fn manifest_for_inspection() -> Value {
    let module_id = std::env::var(SUBC_MODULE_ID_ENV)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MODULE_ID.to_string());
    let browser = cerebellum_core::config::config_path()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .and_then(|text| {
            parse_config(&text).ok()?;
            browser_config::parse_browser_config(&text).ok().flatten()
        })
        .map_or(BrowserSurface::NotConfigured, BrowserSurface::Available);
    let context = ComputerCapabilityAdvertisementContext {
        inputs: compiled_release_inputs(),
        permissions: Default::default(),
        startup: StartupCapabilityProbe::default(),
    };
    compose_manifest(
        &module_id,
        &context,
        &browser,
        manifest::build_offline_provenance(),
    )
}

fn serialize_manifest_with_computer_plane_configured(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
    browser_surface: &BrowserSurface,
) -> Value {
    compose_manifest(
        module_id,
        context,
        browser_surface,
        manifest::build_provenance(),
    )
}

fn compose_manifest(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
    browser_surface: &BrowserSurface,
    provenance: Option<subc_protocol::manifest::ManifestProvenance>,
) -> Value {
    let browser_configured = matches!(browser_surface, BrowserSurface::Available(_));
    let mut manifest =
        build_manifest_with_computer_plane_and_provenance(module_id, context, provenance);
    if browser_configured {
        let subc_protocol::manifest::ProviderRole::ToolProvider { tools, .. } =
            &mut manifest.provides[0]
        else {
            return serde_json::to_value(manifest).expect("module manifest serializes");
        };
        let browser_tools = tool_provider::browser_tools();
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
    name == private_content::QUERY
        || permissions::is_operation(name)
        || matches!(
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
                | management::SESSION_TURN_ENDED
        )
        || (matches!(name, management::PRESENT | management::RESUME)
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
        || name == crate::browser_type::BROWSER_TYPE_TOOL
        || name == browser::fill::FILL_LOGIN;
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
    // A reading taken on the event-loop main thread is discarded as unreliable,
    // so startup probes run on a spawned thread, joined before building the
    // manifest. Tests run off-main even with --test-threads=1, so no test catches
    // removing the spawned thread: its caller would already be off-main in tests.
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
/// The twelve external identifiers use `option_env!` so a release invocation must
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
    let app_use_fronting_review_revision =
        option_env!("CEREBELLUM_APP_USE_FRONTING_REVIEW_REVISION");
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
        app_use_fronting_review_revision,
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
    app_use_fronting_review_revision: Option<&'a str>,
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
        app_use_fronting_review_revision: bindings
            .app_use_fronting_review_revision
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

/// Whether the build carries an attestation that release evidence reports as
/// passing. An empty value or a stand-in such as "placeholder" binds nothing,
/// exactly as the release gate reports it.
#[cfg_attr(not(test), allow(dead_code))]
fn release_attestation_bound(gate: &'static str, value: Option<&str>) -> bool {
    matches!(pin_outcome(gate, value, None), ComputerGateOutcome::Pass)
}

/// The keystroke fronting bracket: bring a background application forward for
/// at most 100 ms, post, always restore, under the takeover grant. It also
/// admits a `bring_to_front` image read under held takeover. Only the takeover
/// review covers it, and the app-use review changes nothing here.
#[cfg_attr(
    not(any(test, target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn fronting_bracket_admitted(inputs: &ComputerReleaseInputs) -> bool {
    inputs.takeover_dispatch_review_revision.is_some()
}

/// Fronting outside the keystroke bracket: foreground mode's one-way front,
/// fronting a disabled press or a modifier chord under the app grant alone,
/// skipping the restore when the person switched apps, and holding the restore
/// until a held key's release is confirmed. It brings an application forward
/// as the takeover review's bracket does, but under rules that review never
/// covered, so both the takeover review and the app-use review must bind.
/// The vocabulary digests play no part.
#[cfg_attr(
    not(any(test, target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn app_use_fronting_admitted(inputs: &ComputerReleaseInputs) -> bool {
    release_attestation_bound(
        "takeover_dispatch_review_revision",
        inputs.takeover_dispatch_review_revision.as_deref(),
    ) && release_attestation_bound(
        "app_use_fronting_review_revision",
        inputs.app_use_fronting_review_revision.as_deref(),
    )
}

/// Capturing a covered window for the background-mode preview. The pixels
/// leave the module outside capture custody, so both the capture review and
/// the app-use review, whose scope names this exception, must bind. Without
/// it the preview shows the application's icon instead of a frame. The
/// vocabulary digests play no part.
#[cfg_attr(
    not(any(test, target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
fn preview_capture_admitted(inputs: &ComputerReleaseInputs) -> bool {
    release_attestation_bound(
        "capture_review_revision",
        inputs.capture_review_revision.as_deref(),
    ) && release_attestation_bound(
        "app_use_fronting_review_revision",
        inputs.app_use_fronting_review_revision.as_deref(),
    )
}

/// The computer-plane context for the HELLO message the module sends the daemon.
///
/// Public so that a test can check the manifest this module really sends,
/// rather than one assembled to look like it.
///
/// Permission readings are taken once at startup and never re-queried, by design.
/// A later grant is not seen until cerebellum restarts. Readings serve diagnostics
/// and call-time admission, not advertisement. The queries never request a grant,
/// so permission checks cannot change advertisement or raise a system permission
/// prompt.
pub fn default_computer_context() -> ComputerCapabilityAdvertisementContext {
    static CONTEXT: std::sync::OnceLock<ComputerCapabilityAdvertisementContext> =
        std::sync::OnceLock::new();
    CONTEXT.get_or_init(probe_computer_context).clone()
}

fn probe_computer_context() -> ComputerCapabilityAdvertisementContext {
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
    /// When each bound route's bind was accepted, as a sequence number that
    /// only grows. Re-recording an already-bound route's facts keeps its
    /// place. Writers lock `inner` before this; `bind_sequence` locks this
    /// alone or while `inner` is held, never the other way round.
    bind_order: Arc<std::sync::Mutex<BindOrder>>,
}

#[derive(Default)]
struct BindOrder {
    next: u64,
    sequence: HashMap<(u16, u32), u64>,
}

impl RouteBindings {
    pub fn new() -> Self {
        Self::default()
    }

    fn insert(&self, channel: u16, epoch: u32, facts: AcceptedBindFacts) {
        if let Ok(mut routes) = self.inner.write() {
            routes.insert((channel, epoch), facts);
            let mut order = self
                .bind_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let next = order.next;
            if let std::collections::hash_map::Entry::Vacant(entry) =
                order.sequence.entry((channel, epoch))
            {
                entry.insert(next);
                order.next += 1;
            }
        }
    }

    /// The order in which this route's bind was accepted among all routes
    /// bound now or before; lower is older.
    fn bind_sequence(&self, channel: u16, epoch: u32) -> Option<u64> {
        self.bind_order
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .sequence
            .get(&(channel, epoch))
            .copied()
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
        let facts = self.inner.write().ok().and_then(|mut routes| {
            self.bind_order
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .sequence
                .remove(&(channel, epoch));
            routes.remove(&(channel, epoch))
        });
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
            let _ = planes
                .consent
                .forget_session(&cingulate_client::live_call::SessionKey {
                    owner: serde_json::to_string(&key.owner).unwrap_or_default(),
                    scope_ref: key.scope_ref.clone(),
                    scope_epoch: key.scope_epoch,
                });
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
    // Runs borrow the resolved head route's conversation. A run being replaced
    // must not revoke the head conversation's grants or browser.
    if stamp.attributes.run_id.is_some() {
        if planes.routes.run_head(&stamp).ok().is_some_and(|head| {
            head.scope
                .as_ref()
                .is_some_and(|head| planes.scopes.is_superseded(head))
        }) {
            let refusal = codemode::ParentRefusal::NoLiveHead;
            send_route_error(
                writer,
                frame.header.ver,
                0,
                0,
                frame.header.corr,
                refusal.code(),
                refusal.message(),
            )
            .await?;
            return Ok(false);
        }
        return Ok(true);
    }
    match planes.scopes.note_bind(&stamp, &identity.session) {
        scope_watch::BindEpoch::Current => Ok(true),
        scope_watch::BindEpoch::Advanced {
            ended_conversations,
        } => {
            // Every lower epoch's session has ended, whether or not a route of
            // it is still bound: forget the cards they raised, here only.
            let _ = planes.consent.forget_sessions_before(
                &serde_json::to_string(&stamp.owner).unwrap_or_default(),
                &stamp.scope_ref,
                stamp.scope_epoch,
            );
            for conversation_key in &ended_conversations {
                planes
                    .management
                    .end_browser_conversation(conversation_key)
                    .await;
                planes.management.end_conversation(conversation_key);
                forget_conversation_cards(planes, conversation_key);
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

/// Forget the consent cards an ended conversation's sessions have open, here
/// only: the in-memory computer questions and every raised-card registry
/// entry of the sessions its still-bound routes carry. No route to Cingulate
/// is opened, because a route may be opened only while a live call from that
/// session is held, and an ended session has none. A late answer for a
/// forgotten card is then ignored by the next drain instead of granting
/// anything; Cingulate expires the card on the person's phone by itself.
fn forget_conversation_cards(planes: &Planes, conversation_key: &str) {
    planes
        .management
        .computer_grants()
        .forget_conversation_questions(conversation_key);
    let sessions: Vec<_> = planes
        .routes
        .inner
        .read()
        .expect("route bindings lock poisoned")
        .values()
        .filter(|facts| facts.identity.conversation_key == conversation_key)
        .filter_map(|facts| facts.scope.as_ref())
        .map(|stamp| cingulate_client::live_call::SessionKey {
            owner: serde_json::to_string(&stamp.owner).unwrap_or_default(),
            scope_ref: stamp.scope_ref.clone(),
            scope_epoch: stamp.scope_epoch,
        })
        .collect();
    for session in sessions {
        let _ = planes.consent.forget_session(&session);
    }
    let _ = planes
        .calls
        .end_consent_conversation(conversation_key, wall_clock_ms());
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
        forget_conversation_cards(planes, conversation_key);
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

/// Cingulate routes require a live call from an admitted head or worker session;
/// permission to write replies to an inbound route grants no such authority.
struct RouteCarrier {
    desk: Arc<cingulate_client::desk::ConsentDesk>,
    facts: AcceptedBindFacts,
    route: Arc<dyn computer_grants::RouteLiveness>,
    guard: Option<Arc<cerebellum_core::dispatch::InFlightGuard>>,
    call_key: Option<String>,
}

impl computer_grants::QuestionCarrier for RouteCarrier {
    fn desk(&self) -> Arc<cingulate_client::desk::ConsentDesk> {
        Arc::clone(&self.desk)
    }
    fn live(
        &self,
    ) -> Result<cingulate_client::live_call::LiveCall, cingulate_client::live_call::NotLive> {
        use cingulate_client::live_call::{LiveCall, NotLive};
        let stamp = permission_scope::card_stamp(&self.facts);
        if stamp.is_none() {
            return Err(NotLive::Unscoped);
        }
        let guard = self.guard.as_ref().ok_or(NotLive::CallEnded)?;
        LiveCall::from_inbound(stamp, guard, Arc::clone(&self.route)).map(|live| {
            live.with_authorizing_agent(
                permission_scope::authorizing_holder(&self.facts)
                    .map(|holder| holder.agent_id().to_string()),
            )
        })
    }
    fn requester_ref(&self) -> Option<String> {
        self.call_key.clone()
    }
}

/// The live agent-session call that can raise the login card, and the
/// in-flight guard that pauses busy accounting while the person decides.
fn login_consent_request(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    _writer: &mpsc::Sender<Frame>,
    (channel, epoch): (u16, u32),
    capability: computer_grants::LoginCapability,
    parameters: String,
    cancel: Option<CancelHandle>,
) -> computer_grants::LoginConsentRequest {
    computer_grants::LoginConsentRequest {
        conversation_key: facts.identity.conversation_key.clone(),
        capability,
        parameters,
        carrier: Arc::new(RouteCarrier {
            desk: Arc::clone(&planes.consent),
            facts: facts.clone(),
            route: Arc::new(BoundRoute {
                routes: Arc::clone(&planes.routes),
                channel,
                epoch,
                conversation_key: facts.identity.conversation_key.clone(),
            }),
            guard: call_context::ROUTE_GUARD.try_with(Arc::clone).ok(),
            call_key: call_context::current_call_key(),
        }),
        cancel,
        drain: planes.drain_signal.subscribe(),
        route: Arc::new(BoundRoute {
            routes: Arc::clone(&planes.routes),
            channel,
            epoch,
            conversation_key: facts.identity.conversation_key.clone(),
        }),
        park_guard: call_context::ROUTE_GUARD.try_with(Arc::clone).ok(),
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
    _writer: &mpsc::Sender<Frame>,
    channel: u16,
    epoch: u32,
) -> computer_grants::ConsentContext {
    let carrier: Option<Arc<dyn computer_grants::QuestionCarrier>> = Some(Arc::new(RouteCarrier {
        desk: Arc::clone(&planes.consent),
        facts: facts.clone(),
        route: Arc::new(BoundRoute {
            routes: Arc::clone(&planes.routes),
            channel,
            epoch,
            conversation_key: facts.identity.conversation_key.clone(),
        }),
        guard: call_context::ROUTE_GUARD.try_with(Arc::clone).ok(),
        call_key: call_context::current_call_key(),
    }));
    let mut context = computer_grants::ConsentContext::new(
        computer_grants::GrantCaller {
            holder: permission_scope::authorizing_holder(facts),
            conversation_key: facts.identity.conversation_key.clone(),
            agent_project_id: facts.identity.agent_project_id.clone(),
            durable_identity_attested: facts.agent_project_id_attested
                && facts.session_kind_attested
                && facts.acts_as_agent
                && !permission_scope::is_worker(facts),
        },
        carrier,
        Arc::new(BoundRoute {
            routes: Arc::clone(&planes.routes),
            channel,
            epoch,
            conversation_key: facts.identity.conversation_key.clone(),
        }),
        planes.drain_signal.subscribe(),
        call_context::ROUTE_GUARD.try_with(Arc::clone).ok(),
    );
    #[cfg(test)]
    if let Ok(limit) = COMPUTER_CONSENT_PARK_LIMIT_FOR_TEST.try_with(|limit| *limit) {
        context.park_limit = limit;
    }
    context.unattended = facts.flow_id.is_some();
    context.agent_run = codemode::legacy_run(facts);
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
    record_private_state_tightening();
    record_engram_catalog_write();
    conclude(run(config, read_live_settings_from_config_file, true).await)
}

/// Point the planes at the settings a running module re-reads from its config
/// file, `cerebellum.jsonc`, while it runs: today only `computer_use.app_use`.
///
/// Only [`run_entry`] calls this, because only it loaded that file to
/// register. Every plane constructor reads no config file, so in-process
/// tests, child-process tests through [`run_entry_prepared_for_test`] and
/// examples never act on the config of whoever runs them.
fn read_live_settings_from_config_file(planes: &mut Planes) {
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    if let Ok(computer) = &planes.computer {
        computer.read_app_use_from_config_file();
    }
    // No other platform builds a computer plane, so nothing reads app_use.
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let _ = planes;
}

#[cfg(all(test, any(target_os = "macos", target_os = "windows")))]
mod live_settings_tests {
    use super::*;

    /// The production entry is the one place a computer plane starts reading
    /// the person's config file; before that step the same planes read none.
    #[test]
    fn module_startup_points_the_computer_plane_at_the_config_file() {
        let expected = cerebellum_core::config::config_path();
        assert!(expected.is_some(), "this host has a config home");
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        let computer = planes.computer.as_ref().unwrap().clone();
        assert_eq!(computer.app_use_config_path_for_test(), None);
        read_live_settings_from_config_file(&mut planes);
        assert_eq!(computer.app_use_config_path_for_test(), expected);
    }
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
        agent_cursor: false,
        browser: BrowserSurface::Available(browser),
    };
    conclude(run(config, prepare, false).await)
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
    cursor: Option<computer_capability::cursor::Coordinator>,
    user_browser: user_browser_bridge::UserBrowserBridge,
    sessions: browser_session::BrowserSessions,
    browser: Option<BrowserConfig>,
    // Its in-use marker is removed last, once nothing more can be delivered.
    private_content: Arc<private_content::PrivateContent>,
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
        cursor: Option<computer_capability::cursor::Coordinator>,
        user_browser: user_browser_bridge::UserBrowserBridge,
        private_content: Arc<private_content::PrivateContent>,
    ) -> Self {
        let (finished, _) = tokio::sync::watch::channel(false);
        Self(Arc::new(ShutdownTeardownState {
            cursor,
            user_browser,
            sessions,
            browser,
            private_content,
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
            self.0.user_browser.shutdown();
            if let Some(cursor) = &self.0.cursor {
                cursor.shutdown();
            }
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
                // Serving has stopped, so no further reply can be delivered:
                // a clean ending may now tell the next start that every mark
                // reached disk. A crash never gets here and leaves the marker.
                finished.0.private_content.shut_down_cleanly();
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
    agent_cursor: bool,
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
            agent_cursor: parsed.computer_use.agent_cursor,
            browser,
        })
    }
}

async fn run(
    config: ModuleConfig,
    prepare: impl FnOnce(&mut Planes),
    enable_user_bridge: bool,
) -> ModuleEnding {
    #[cfg(not(target_os = "macos"))]
    let _ = enable_user_bridge;
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
    health_config.in_flight_age_stale_ms = budgets::IN_FLIGHT_AGE_STALE_MS;
    let health_state = Arc::new(HealthState::with_config(health_config));
    let browser_config = match &config.browser {
        BrowserSurface::Available(browser) => Some(browser.clone()),
        BrowserSurface::NotConfigured | BrowserSurface::Refused(_) => None,
    };
    let registry: Arc<dyn cingulate_client::desk::RegistryStore> =
        match cingulate_client::desk::FileRegistryStore::production() {
            Ok(store) => Arc::new(store),
            Err(error) => Arc::new(consent_drain::UnavailableRegistry(error)),
        };
    let mut planes = Planes::with_browser_config(Arc::clone(&health_state), browser_config.clone())
        .with_cingulate(
            Arc::new(cingulate_client::route::DaemonCingulate::supervised(
                config.connection_file_path.clone(),
                config.module_id.clone(),
            )),
            registry,
        );
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
    // Test entry points never bind the operator's runtime socket. Failure to
    // bind the extension listener leaves the Chrome extension disconnected;
    // the daemon-owned browser and browser_use advertisement are unaffected.
    #[cfg(target_os = "macos")]
    let _user_browser_listener = if enable_user_bridge && browser_config.is_some() {
        user_browser_bridge::BridgeListener::bind(planes.user_browser.clone()).ok()
    } else {
        None
    };
    if let Some(cursor) = planes_cursor(&planes) {
        #[cfg(target_os = "macos")]
        cursor.set_avatars(Arc::new(
            computer_capability::cursor::avatar::Avatars::supervised(
                config.connection_file_path.clone(),
                config.module_id.clone(),
            ),
        ));
        cursor.enable(config.agent_cursor);
    }
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
        planes_cursor(&planes),
        planes.user_browser.clone(),
        Arc::clone(&planes.private_content),
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
        planes_cursor(&planes),
        planes.user_browser.clone(),
        Arc::clone(&planes.private_content),
    );
    serve_then_tear_down(read_half, write_half, config, planes, &teardown).await
}

fn planes_cursor(planes: &Planes) -> Option<computer_capability::cursor::Coordinator> {
    #[cfg(test)]
    if let Some(cursor) = &planes.cursor_for_test {
        return Some(cursor.clone());
    }
    #[cfg(all(test, target_os = "macos"))]
    if let Some(plane) = &planes.computer_for_test {
        return Some(plane.cursor());
    }
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    {
        planes.computer.as_ref().ok().map(|plane| plane.cursor())
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let _ = planes;
        None
    }
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
    let deadlines = Arc::clone(&planes.egress_deadlines);
    let mut writer = tokio::spawn(drain_writer(write_half, rx, Arc::clone(&deadlines)));
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
        _ = deadlines.expired() => {
            writer.abort();
            let _ = writer.await;
            return Err(ModuleError::Message("terminal delivery deadline exceeded".into()));
        }
    };

    drop(loop_task);
    drop(tx);
    let writer_result = tokio::select! {
        result = &mut writer => normalize_writer_task_result(result),
        _ = deadlines.expired() => {
            writer.abort();
            let _ = writer.await;
            Err(ModuleError::Message("terminal delivery deadline exceeded".into()))
        }
    };
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

    planes.scopes.control.connect(&writer);

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
    terminal: std::sync::Mutex<Option<std::sync::Weak<TerminalArbiter>>>,
}

impl CancelHandle {
    pub fn pending() -> Self {
        Self(Arc::new(CancelSignal::default()))
    }
    pub fn for_uninterruptible_probe() -> Self {
        Self::pending()
    }
    pub fn cancel(&self) {
        self.stop_terminal(TerminalCause::Cancelled);
        self.0
            .cancelled
            .store(true, std::sync::atomic::Ordering::Release);
        self.0.notify.notify_waiters();
    }
    fn stop_terminal(&self, cause: TerminalCause) {
        if let Some(terminal) = self
            .0
            .terminal
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            terminal.stop(cause);
        }
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.cancelled.load(std::sync::atomic::Ordering::Acquire)
    }
    /// The agent whose cursor badge this request drew, if it was a computer
    /// call that drew one.
    fn cursor_agent(&self) -> Option<String> {
        self.0
            .terminal
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
            .and_then(|terminal| terminal.cursor_agent())
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
                handle.stop_terminal(TerminalCause::RouteClosed);
                handle.cancel();
            }
        }
    }

    fn stop_all(&self, cause: TerminalCause) {
        for handle in self.0.lock().unwrap().values() {
            handle.stop_terminal(cause);
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
    /// A cursor coordinator for the frame loop's end signals, on every
    /// platform, without building a computer plane.
    #[cfg(test)]
    cursor_for_test: Option<computer_capability::cursor::Coordinator>,
    /// Explicit frame-loop fixture injection. Ordinary tests retain the native
    /// plane and driver, rather than changing the platform for the whole suite.
    #[cfg(all(test, target_os = "macos"))]
    computer_for_test: Option<Arc<computer_capability::ScriptedComputerPlane>>,
    pub health: Arc<HealthState>,
    private_content: Arc<private_content::PrivateContent>,
    signed_in: Arc<browser_signed_in::SignedInDomains>,
    cancellations: RequestCancellations,
    run_calls: codemode::RunCalls,
    browser_queue: Arc<call_queue::ConversationQueue>,
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
    pub user_browser: user_browser_bridge::UserBrowserBridge,
    pub lease_clock: Arc<cerebellum_core::clock::SystemClock>,
    pub launch_service: Option<Arc<dyn browser_session::BrowserSessionLauncher>>,
    pub management: Arc<ManagementPlane>,
    /// Cards cerebellum raised and whether their answers have been acted on;
    /// the registry is shared by routes and persisted by the configured store.
    pub consent: Arc<cingulate_client::desk::ConsentDesk>,
    /// Serializes answer-feed reads per session and calls each flow's adapter
    /// to elect one caller to store the answer's permission or approval.
    pub consent_drain: Arc<consent_drain::ConsentDrain>,
    /// The user-browser site cards that calls in this process are raising or
    /// waiting on. Only the waiting call acts on such a card's answer, so the
    /// session drain must not withdraw these cards as abandoned.
    pub(crate) user_browser_cards: Arc<user_browser::SiteCardHolders>,
    #[cfg(test)]
    pub(crate) consent_test: Option<Arc<computer_grants::tests::CardService>>,
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
    /// `browser.capture_login`: one capture at a time, and its residue.
    pub capture: Arc<login_capture::CaptureModule>,
    /// One record per call that arrived with a `call_key`, so a resend is
    /// answered from it instead of running again.
    pub calls: Arc<journal::call_records::CallRecords>,
    /// Shared by keyed admissions and settlements on both tool planes. A timed
    /// out blocking write keeps its permit until the write actually ends.
    call_record_workers: Arc<CallRecordWorkers>,
    egress_deadlines: Arc<ConnectionDeadlines>,
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
    /// Configure how agent calls open Cingulate routes and persist the cards
    /// cerebellum raised, so a later call can apply their answers.
    pub fn with_cingulate(
        mut self,
        opener: Arc<dyn cingulate_client::route::CingulateOpener>,
        store: Arc<dyn cingulate_client::desk::RegistryStore>,
    ) -> Self {
        self.consent = Arc::new(cingulate_client::desk::ConsentDesk::with_store(
            opener, store,
        ));
        self.management
            .computer_grants()
            .register_drain(&self.consent_drain);
        browser_consent::register(&self);
        login_fill_consent::register(&self);
        user_browser::register(&self);
        self
    }

    /// Build isolated planes over a scripted consent service and a private
    /// registry. No journal or grant store is opened under the operator's home.
    #[doc(hidden)]
    pub fn with_cingulate_for_test(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        opener: Arc<dyn cingulate_client::route::CingulateOpener>,
        store: Arc<dyn cingulate_client::desk::RegistryStore>,
    ) -> Self {
        Self::with_browser_config_journaling(health, browser_config, JournalPersistence::Isolated)
            .with_cingulate(opener, store)
    }

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
        Self::with_browser_state(health, browser_config, journal, standing, None)
    }

    /// Build browser and permission services sharing the signed-in domain store;
    /// fixtures can reopen a private file without resolving the operator's data home.
    pub fn with_browser_state(
        health: Arc<HealthState>,
        browser_config: Option<BrowserConfig>,
        journal: JournalPersistence,
        standing: Option<Arc<browser_standing_grants::StandingBrowserGrants>>,
        signed_in: Option<Arc<browser_signed_in::SignedInDomains>>,
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
        let (computer_grants, agent_grants) = match journal {
            JournalPersistence::Durable => {
                let machine_uuid = computer_grants::this_machine_uuid();
                let grants = Arc::new(
                    agent_grants::AgentGrants::open_durable(machine_uuid.clone())
                        .unwrap_or_else(agent_grants::AgentGrants::unavailable),
                );
                computer_grants::ComputerGrants::note_durable_store_health(&grants);
                (
                    Arc::new(
                        computer_grants::ComputerGrants::in_memory()
                            .with_agent_grants(Arc::clone(&grants)),
                    ),
                    Some(grants),
                )
            }
            JournalPersistence::Isolated => {
                (Arc::new(computer_grants::ComputerGrants::in_memory()), None)
            }
        };
        let user_grants = Arc::new(browser_standing_grants::StandingBrowserGrants::in_memory());
        let standing = standing.unwrap_or_else(|| {
            Arc::new(browser_standing_grants::StandingBrowserGrants::in_memory())
        });
        let signed_in = signed_in.unwrap_or_else(|| {
            Arc::new(match journal {
                JournalPersistence::Durable => browser_signed_in::SignedInDomains::production(),
                JournalPersistence::Isolated => browser_signed_in::SignedInDomains::default(),
            })
        });
        let management = ManagementPlane::with_computer_grants(
            Arc::new(management::PlatformResolver::new()),
            computer_grants,
        )
        .with_isolated_storage(journal == JournalPersistence::Isolated)
        .with_standing_browser_grants(standing)
        .with_signed_in_domains(Arc::clone(&signed_in));
        let management = Arc::new(match agent_grants {
            Some(grants) => management.with_agent_grants(grants),
            None => management,
        });
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
                        )
                        .with_signed_in_domains(Arc::clone(&signed_in)),
                    );
                    capture.set_launcher(service.clone());
                    service as Arc<dyn browser_session::BrowserSessionLauncher>
                });
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        let launch_service = None;
        let sessions = browser_session::BrowserSessions::default()
            .with_signed_in_domains(Arc::clone(&signed_in))
            .with_health(Arc::clone(&health));
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
                )
                .with_login_material_source(browser::fill::production_login_material_source()),
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
            private_content: Arc::new(match journal {
                JournalPersistence::Durable => private_content::PrivateContent::production(),
                JournalPersistence::Isolated => private_content::PrivateContent::in_memory(),
            }),
            signed_in,
            routes: Arc::new(RouteBindings::new()),
            browser,
            browser_config,
            sessions,
            user_browser: user_browser_bridge::UserBrowserBridge::with_user_grants(user_grants),
            lease_clock,
            launch_service,
            management,
            consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
                consent_drain::UnconfiguredCingulate,
            ))),
            consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
            user_browser_cards: Arc::default(),
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
                    .with_launch_history(match journal {
                        JournalPersistence::Durable => {
                            open_app_history::LaunchHistory::production()
                        }
                        JournalPersistence::Isolated => {
                            open_app_history::LaunchHistory::in_memory()
                        }
                    })
                    // The fronting bracket is served only by a build carrying
                    // its review; without it a background target is refused.
                    .with_fronting_bracket_admitted(fronting_bracket_admitted(
                        &compiled_release_inputs(),
                    ))
                    // Fronting outside that bracket needs the app-use review
                    // as well; without it every such front is unavailable.
                    .with_app_use_fronting_admitted(app_use_fronting_admitted(
                        &compiled_release_inputs(),
                    ))
                    // The plane's one preview worker captures with the
                    // platform's capture, and only when the capture review
                    // and the app-use review both bind; otherwise every
                    // preview shows the application's icon.
                    .with_native_preview_capture(preview_capture_admitted(
                        &compiled_release_inputs(),
                    )),
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
            #[cfg(test)]
            cursor_for_test: None,
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            cancellations: RequestCancellations::default(),
            run_calls: codemode::RunCalls::default(),
            browser_queue: Arc::new(call_queue::ConversationQueue::default()),
            capture,
            calls,
            call_record_workers: Arc::new(CallRecordWorkers::default()),
            egress_deadlines: Arc::new(ConnectionDeadlines::default()),
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
            #[cfg(test)]
            consent_test: None,
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
            #[cfg(test)]
            cursor_for_test: self.cursor_for_test.clone(),
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: self.computer_for_test.clone(),
            health: Arc::clone(&self.health),
            private_content: Arc::clone(&self.private_content),
            signed_in: Arc::clone(&self.signed_in),
            cancellations: self.cancellations.clone(),
            run_calls: self.run_calls.clone(),
            browser_queue: self.browser_queue.clone(),
            draining: self.draining.clone(),
            drain_signal: Arc::clone(&self.drain_signal),
            drain_notice: self.drain_notice.clone(),
            routes: Arc::clone(&self.routes),
            browser: Arc::clone(&self.browser),
            browser_config: self.browser_config.clone(),
            sessions: self.sessions.clone(),
            user_browser: self.user_browser.clone(),
            lease_clock: Arc::clone(&self.lease_clock),
            launch_service: self.launch_service.clone(),
            management: Arc::clone(&self.management),
            consent: Arc::clone(&self.consent),
            consent_drain: Arc::clone(&self.consent_drain),
            user_browser_cards: Arc::clone(&self.user_browser_cards),
            #[cfg(test)]
            consent_test: self.consent_test.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer: self.computer.clone(),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            computer_admitted: Arc::clone(&self.computer_admitted),
            capture: Arc::clone(&self.capture),
            calls: Arc::clone(&self.calls),
            call_record_workers: Arc::clone(&self.call_record_workers),
            egress_deadlines: Arc::clone(&self.egress_deadlines),
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
        // still waits. Without this arm such an answer would fall to the
        // catch-all and be dropped, so every describe would wait out its
        // deadline as if unanswered. A response or error on a route channel
        // answers nothing this module sent (it never sends requests on a
        // route), so the catch-all drops those.
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
                    planes.cancellations.stop_all(TerminalCause::Draining);
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
            // Keyed by the closing route itself. A run's user-browser work is
            // keyed by its head route, so a run's goodbye releases none of the
            // head's claims or snapshots; the run's in-flight calls end through
            // `cancel_route` below.
            planes.user_browser.goodbye(user_browser_bridge::Route {
                channel: frame.header.channel,
                epoch: frame.header.epoch,
            });
            // The route's agent is done with the computer: its badge goes now
            // rather than resting on screen until it idles out.
            if let Some(cursor) = planes_cursor(planes) {
                cursor.end_route(frame.header.channel, frame.header.epoch);
            }
            // Unbound before its requests are cancelled, so a call waiting on a
            // person sees the route gone when it wakes and answers
            // `route_closed` rather than a caller-requested cancel.
            let removed = planes
                .routes
                .remove(frame.header.channel, frame.header.epoch);
            planes
                .cancellations
                .cancel_route(frame.header.channel, frame.header.epoch);
            if let Some(facts) = removed {
                let conversation_key = &facts.identity.conversation_key;
                let last_route = !planes.routes.carries_conversation(conversation_key);
                match facts.scope.as_ref() {
                    _ if facts.call_mode == subc_protocol::call_mode::CallMode::Codemode => {
                        // A run borrows the head conversation's browser and grants.
                        // Ending the run cancels its calls, not the head session.
                    }
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
                (_, Some(handle)) => {
                    handle.cancel();
                    // A stopped turn cancels its computer call; that call's
                    // badge must not linger as if the agent were still working.
                    // Calls that drew no badge leave every badge alone.
                    if let (Some(agent), Some(cursor)) =
                        (handle.cursor_agent(), planes_cursor(planes))
                    {
                        cursor.end(&agent);
                    }
                }
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
                    Some(&planes.call_record_workers),
                    Some(&planes.private_content),
                )
                .await?;
            }
            Ok(true)
        }
        FrameType::Request => {
            if writer.is_closed() {
                return Ok(true);
            }
            let arrived = tokio::time::Instant::now();
            let (envelope_ms, reply_ms) = route_limits(&frame, planes);
            let connection_end = arrived + Duration::from_millis(reply_ms);
            planes
                .egress_deadlines
                .arm(request_id(&frame), connection_end);
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
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            let computer_arrival = computer_capability::computer_arrival(&frame, planes);
            let browser_arrival = browser_queue::arrive(&frame, planes);
            let guard = Arc::new(planes.health.enter_request());
            let writer = writer.clone();
            let planes = planes.clone();
            let terminal = Arc::new(TerminalArbiter::new(frame.clone()));
            *cancellation.handle.0.terminal.lock().unwrap() = Some(Arc::downgrade(&terminal));
            let (proxy, outgoing) = mpsc::channel(16);
            let worker_planes = planes.clone();
            let browser_park_limit = BROWSER_CONSENT_PARK_LIMIT
                .try_with(|limit| *limit)
                .unwrap_or(Duration::from_secs(120));
            let worker = async move {
                let planes = worker_planes;
                #[cfg(test)]
                if let Some(handler) = &planes.route_test_handler {
                    handler().await;
                }
                if let Some(terminal) =
                    TerminalArbiter::current().filter(|terminal| terminal.gate.stopped())
                {
                    let cancelled_before_queue = {
                        let state = terminal.state.lock().unwrap();
                        !state.possibly_dispatched
                            && matches!(
                                state.cause,
                                Some(TerminalCause::Cancelled | TerminalCause::RouteClosed)
                            )
                    };
                    if browser_arrival.is_some() && cancelled_before_queue {
                        let refusal = browser_queue::QueueRefusal::Cancelled;
                        return send_route_error(
                            &proxy,
                            frame.header.ver,
                            frame.header.channel,
                            frame.header.epoch,
                            frame.header.corr,
                            refusal.code(),
                            refusal.remedy(),
                        )
                        .await;
                    }
                    return Ok(());
                }
                // Boxed so this worker's poll frame holds a pointer rather
                // than the whole handler: unoptimized builds give every
                // awaited future its own stack slot, and the nested route
                // handlers otherwise overflow a 2 MiB thread stack.
                let dispatch = Box::pin(browser_queue::scope(
                    browser_arrival,
                    Box::pin(handle_route_request(frame, &proxy, &planes)),
                ));
                let dispatch = BROWSER_CONSENT_PARK_LIMIT.scope(browser_park_limit, dispatch);
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                let result = computer_capability::serialized_call(computer_arrival, dispatch).await;
                #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                let result = dispatch.await;
                result
            };
            tokio::spawn(run_arbitrated_route(
                Box::pin(worker),
                outgoing,
                writer,
                planes,
                cancellation,
                guard,
                terminal,
                arrived + Duration::from_millis(envelope_ms),
                connection_end,
            ));
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
    if private_content::is_broca(&facts.principal) {
        // Broca's privacy decision must not queue behind a browser action or
        // consent drain. Its management route has no other authority.
        let request: Option<Value> = serde_json::from_slice(&frame.body).ok();
        if facts.surface != RouteSurface::Management
            || request
                .as_ref()
                .and_then(|body| body.get("method"))
                .and_then(Value::as_str)
                != Some(private_content::QUERY)
        {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "principal_denied",
                "reserved:broca may call only private_content.query",
            )
            .await;
        }
        return handle_management_request_observed(frame, writer, &facts, planes, None).await;
    }
    if let Err(refusal) = codemode::live_head(planes, &facts) {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            refusal.code(),
            refusal.message(),
        )
        .await;
    }
    if let Some(method) = permissions::refused_method(&frame, &facts) {
        return send_route_error(writer, ver, channel, epoch, corr, "principal_denied",
            &format!("reserved:cingulate may call only permissions.list or permissions.revoke, not '{method}'"))
            .await;
    }
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

    // Draining can apply a permission, so reject an unsupported tool mode before
    // reading or settling any consent answers for that call.
    if facts.surface == RouteSurface::Tools {
        if let Ok(request) = serde_json::from_slice::<Value>(&frame.body) {
            if let Some(name) = request.get("name").and_then(Value::as_str) {
                // A run (admitted head) acts in the person's Chrome as its head
                // does. A codemode route with no admitted head has no head to
                // act as, so it still cannot.
                if facts.call_mode == subc_protocol::call_mode::CallMode::Codemode
                    && facts.codemode_head.is_none()
                    && name == flat_tools::BROWSER_USE
                    && request["arguments"]["browser"] == "user"
                {
                    return tool_provider::send_error(ErrorBody {
                        code: "call_mode_unsupported".into(),
                        message: "a codemode route without an admitted head run cannot use the user-browser plane".into(),
                        detail: Some(json!({"tool":name,"mode":"codemode","action":request["arguments"]["action"]})),
                    }, (ver, channel, epoch, corr), writer).await;
                }
                if let Err(error) = tool_provider::check_call_mode(name, &facts.call_mode, planes) {
                    return tool_provider::send_error(error, (ver, channel, epoch, corr), writer)
                        .await;
                }
            }
        }
    }
    let worker = if facts.admits_session_calls() {
        match permission_scope::resolve_worker(&facts, &planes.scopes).await {
            Ok(worker) => worker,
            Err(refusal) => {
                let (reason, remedy) = match refusal {
                    permission_scope::HeadRefusal::NoHolder => (
                        "no_agent_session",
                        "open a worker route under a live head session",
                    ),
                    permission_scope::HeadRefusal::Unavailable => (
                        "worker_head_unavailable",
                        "retry when the daemon and scope owner are available",
                    ),
                };
                return send_tool_response(writer, ver, channel, epoch, corr, json!({
                    "outcome":"consent_unavailable", "reason":reason,
                    "detail":{"reason":reason, "retryable":refusal == permission_scope::HeadRefusal::Unavailable},
                    "remedy":remedy,
                })).await;
            }
        }
    } else {
        None
    };
    let cursor_agent = permission_scope::cursor_agent(&facts, worker.as_ref());
    let cursor_session = permission_scope::cursor_session(&facts);
    let detail = codemode::call_detail(&frame, &facts);
    permission_scope::WORKER_HOLDER
        .scope(
            worker,
            computer_capability::cursor::ACTING_AGENT.scope(
                cursor_agent,
                computer_capability::cursor::ACTING_SESSION.scope(
                    cursor_session,
                    codemode::CALL_DETAIL.scope(
                        std::cell::RefCell::new(detail),
                        dispatch_resolved_route(frame, writer, planes, &facts),
                    ),
                ),
            ),
        )
        .await
}

async fn dispatch_resolved_route(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    facts: &AcceptedBindFacts,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    if let Ok(live) = consent_drain::live_call(&frame, facts, planes) {
        // A failed drain is retried on a later call; it must not replace this
        // call's ordinary reply with a consent refusal.
        let _ = planes
            .consent_drain
            .run_recording(&planes.consent, &live, Some(&planes.calls))
            .await;
    }

    let dispatch = dispatch_bound_route(frame, writer, planes, facts);
    if facts.call_mode == subc_protocol::call_mode::CallMode::Codemode {
        let cancel = planes.cancellations.get((channel, epoch, corr));
        tokio::select! {
            biased;
            _ = planes.routes.closed(channel, epoch) => Ok(()),
            _ = async { if let Some(cancel) = cancel { cancel.cancelled().await } else { std::future::pending().await } } => {
                if planes.routes.get(channel, epoch).is_none() { return Ok(()); }
                send_route_error(writer, ver, channel, epoch, corr, "cancelled", "the agent run call was cancelled").await
            }
            result = dispatch => result,
        }
    } else {
        dispatch.await
    }
}

async fn dispatch_bound_route(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    facts: &AcceptedBindFacts,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    match facts.surface {
        // Boxed for the same stack-frame reason as the route worker's handler.
        RouteSurface::Tools => Box::pin(handle_keyed_tool_request(frame, writer, planes)).await,
        RouteSurface::Management => {
            Box::pin(handle_management_request(frame, writer, facts, planes)).await
        }
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
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Queue);
    }
    let _browser_guard = match browser_queue::enter(&frame, planes).await {
        Ok(guard) => guard,
        Err(outcome) => return send_queue_refusal(writer, &frame, planes, outcome).await,
    };
    let mut facts = facts.clone();
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Preflight);
        facts.identity.witness = terminal.witness.clone();
    }
    handle_management_request_observed(frame, writer, &facts, planes, None).await
}

async fn handle_management_request_observed(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    call_key: Option<&str>,
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
    if permissions::is_operation(method) {
        return permissions::handle(&frame, writer, facts, planes, method, object).await;
    }
    if method == private_content::QUERY {
        return private_content::handle(&frame, writer, facts, planes, object).await;
    }
    if method == management::SESSION_TURN_ENDED {
        return handle_session_turn_ended(
            writer,
            facts,
            planes,
            object,
            (ver, channel, epoch, corr),
        )
        .await;
    }
    // Operator operations (list or revoke grants, profile-root rebind, and
    // launch-recovery clear) administer machine-wide grants and browser state.
    // A flow route never gets them, even when acting for its owner.
    if (codemode::legacy_run(facts)
        || (facts.call_mode == subc_protocol::call_mode::CallMode::Codemode
            && matches!(
                method,
                management::CLEAR_LAUNCH_RECOVERY | management::REBIND_PROFILE_ROOT
            )))
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
            agent_run_consent_refusal(),
        )
        .await;
    }
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
        && !(facts.flow_id.is_some()
            && facts.acts_as_agent
            && facts.agent_project_id_attested
            && matches!(&facts.principal, Some(subc_protocol::Principal::Reserved { module_id }) if module_id == "basal"))
    {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "grants.would_ask requires reserved:prefrontal-core or an owner-authorized reserved:basal flow",
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
            let held = call_key.map(|key| {
                let principal = journal::call_records::principal_label(facts.principal.as_ref());
                let scope = facts
                    .scope
                    .as_ref()
                    .map(journal::call_records::ScopeIdentity::from_stamp)
                    .unwrap_or_else(|| journal::call_records::ScopeIdentity {
                        owner: principal.clone(),
                        reference: facts.identity.conversation_key.clone(),
                        scope_epoch: 0,
                    });
                (principal, key.to_owned(), scope)
            });
            present_browser_handoff(planes, &facts.identity, origin, held).await
        };
        let reply = match planes.browser.finish_reply(method, reply) {
            Ok(reply) => reply,
            Err(error) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    browser::RESULT_SCHEMA_VIOLATION_CODE,
                    &format!("the handoff reply violated its result schema: {error}"),
                )
                .await
            }
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
        if let Some(flow_id) = facts.flow_id.as_deref() {
            let field = if request.agent_id != facts.identity.agent_project_id {
                Some("agent_id")
            } else if request.flow_id != flow_id {
                Some("flow_id")
            } else {
                None
            };
            if let Some(field) = field {
                return send_invalid_request_response(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    field,
                    "scope_mismatch",
                )
                .await;
            }
        }
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
        let Some(call_key) = call_key else {
            return send_tool_response(writer, ver, channel, epoch, corr, json!({
                "outcome":"invalid_request",
                "detail":{
                    "field":"call_key",
                    "reason_code":"required",
                    "remedy":"capture_login needs a keyed call because its result arrives later as a notice; do not poll for it"
                }
            })).await;
        };
        let reply = capture_browser_login(
            planes,
            facts,
            writer,
            (channel, epoch, corr),
            &request,
            call_key,
        )
        .await;
        // A capture cancelled before the handoff sends no reply of its own:
        // the Cancel already chose this call's reply in its terminal arbiter.
        // Its own `{"outcome":"cancelled"}` would otherwise replace that
        // reply whenever it reached the route in time, so the bytes sent
        // would depend on scheduling.
        if reply["outcome"] == "cancelled"
            && TerminalArbiter::current().is_some_and(|terminal| terminal.answered_by_cancel())
        {
            return Ok(());
        }
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

    use cingulate_client::card::CardKind;

    let (mut reply, question, settlement) = if method == management::OPEN_GRANT {
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
            .open_browser_grant_for_holder(
                &facts.identity.conversation_key,
                origins,
                hazards,
                severity_tier,
                true,
                standing_offer_agent(facts),
                permission_scope::authorizing_holder(facts).as_ref(),
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
        (reply, question, CardKind::WebsiteAccessInAdvance)
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
            .open_launch_recovery_clear(agent_project_id, sequence, true)
            .await;
        (reply, question, CardKind::StuckProfileClearance)
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
            .open_profile_root_rebind(&facts.identity.conversation_key, true)
            .await;
        (reply, question, CardKind::ProfileReidentification)
    };

    if let Some(mut question) = question {
        if let Err(error) = question.bind_holder(permission_scope::minting_holder(facts)) {
            error.apply_to_reply(&mut reply);
            return send_tool_response(writer, ver, channel, epoch, corr, reply).await;
        }
        let raised = async {
            let live = browser_consent::live(facts, planes, channel, epoch)?;
            let mut session = planes
                .consent
                .session(&live)
                .await
                .map_err(|error| cingulate_client::desk::Ending::of_refusal(&error))?;
            browser_consent::raise(
                &planes.management,
                &planes.consent,
                &live,
                &mut session,
                settlement,
                &question,
                true,
            )
            .await
        }
        .await;
        match raised {
            Ok((ask_id, _)) => reply["ask_id"] = json!(ask_id),
            Err(ending) => {
                browser_consent::settle_failed(&planes.management, settlement, &question, &ending);
                browser_consent::unavailable(
                    &mut reply,
                    &ending,
                    if settlement == CardKind::StuckProfileClearance {
                        "keep"
                    } else {
                        management::BROWSER_GRANT_DECLINE
                    },
                );
            }
        }
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
            let holder = permission_scope::authorizing_holder(facts);
            if (planes.management.unified_agent_grants().is_some() && holder.is_none())
                || (planes.management.unified_agent_grants().is_none()
                    && (!facts.agent_project_id_attested || !facts.acts_as_agent))
            {
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
            if let Some(store) = planes.management.unified_agent_grants() {
                return Ok(management::retained_browser_ops::revoke_rows(
                    store,
                    agent_grants::BrowserTarget::AgentProfile,
                    &target,
                    |row_holder| Some(row_holder) == holder.as_ref(),
                ));
            }
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
            if let Some(store) = planes.management.unified_agent_grants() {
                return Ok(management::retained_browser_ops::revoke_rows(
                    store,
                    agent_grants::BrowserTarget::AgentProfile,
                    &target,
                    |holder| holder.agent_id() == agent_id,
                ));
            }
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
                "browser": planes.management.unified_agent_grants().map_or_else(|| json!({
                    "grants": standing
                        .live_rows(&agent_id)
                        .iter()
                        .map(browser_standing_grants::StandingBrowserGrant::describe)
                        .collect::<Vec<_>>(),
                    "store": standing.store_state(),
                }), |store| management::retained_browser_ops::listing(store, &agent_id)),
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
    if !computer_grants::admits_consent(facts) {
        if facts.flow_id.is_some() {
            return flow_consent_refusal("unattended_flow");
        }
        let why = cingulate_client::desk::NoCard::NoAgentSession;
        let result = login_import::ImportResult::refusal(
            origin,
            "consent_unavailable",
            why.remedy().unwrap(),
        );
        let mut reply = journal_login_import_result(planes, &facts.identity, result).await;
        reply["detail"] = json!({"reason":why.reason(),"remedy":why.remedy()});
        return reply;
    }
    let (location, profile_uuid) = match planes
        .management
        .durable_login_profile_identity(&facts.identity.agent_project_id)
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
    planes
        .browser
        .register_existing_profile(&facts.identity, &profile_uuid)
        .await;
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
    let request = login_consent_request(
        planes,
        facts,
        writer,
        (channel, epoch),
        computer_grants::LoginCapability::ImportLogin,
        plan.consent_parameters(),
        cancel.clone(),
    );
    let carrier = Arc::clone(&request.carrier);
    let consent = planes
        .management
        .computer_grants()
        .require_login(request, || plan.question(&facts.identity.agent_project_id));
    let consent = consent.await;
    let mut execution = None;
    let answer = match consent {
        computer_grants::LoginConsent::Ended(answer) => {
            if let cingulate_client::desk::Ending::NoCard(why) = answer.ending {
                return json!({"outcome":"consent_unavailable","detail":{"reason":why.reason(),"remedy":why.remedy()}});
            }
            if matches!(&answer.ending, cingulate_client::desk::Ending::Declined { choice_id } if choice_id != "deny")
            {
                return json!({"outcome":"unrecognized_answer","remedy":"The answer could not be read; retry this call to ask again."});
            }
            if answer.ending == cingulate_client::desk::Ending::Withdrawn
                && planes.draining.load(std::sync::atomic::Ordering::Acquire)
            {
                return json!({"outcome":"module_draining"});
            }
            if answer.ending == cingulate_client::desk::Ending::Withdrawn
                && !cancel.as_ref().is_some_and(CancelHandle::is_cancelled)
            {
                return json!({"outcome":"question_withdrawn","remedy":"retry this call to ask again"});
            }
            if answer.taken_approval {
                execution = Some(answer.clone());
            }
            Some(answer.ending)
        }
        computer_grants::LoginConsent::Pending { ask_id } => {
            return journal_login_import_result(planes, &facts.identity, plan.pending(ask_id))
                .await;
        }
    };

    let answer = if cancel.as_ref().is_some_and(CancelHandle::is_cancelled) {
        None
    } else {
        answer
    };
    // Journal or relaunch failures must not hide that the copy already ran.
    let mut execution_result = json!({"outcome":"not_run"});
    let reply = async {
        let decision = match &answer {
            Some(cingulate_client::desk::Ending::Granted { choice_id }) => Some(choice_id.as_str()),
            // None of these permits a transfer, and they are listed rather
            // than wildcarded so a future ending has to be decided about here.
            Some(
                cingulate_client::desk::Ending::Declined { .. }
                | cingulate_client::desk::Ending::NoAnswer
                | cingulate_client::desk::Ending::NotPutToAnyone
                | cingulate_client::desk::Ending::DeliveryFailed
                | cingulate_client::desk::Ending::Withdrawn
                | cingulate_client::desk::Ending::NoCard(_),
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
            let closed =
                close_idle_for_import_off_task(planes, &facts.identity.conversation_key, config)
                    .await;
            match closed {
                Ok(Ok((closed, url))) if closed["outcome"] == "closed" => {
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
    if plan.permits_transfer(decision) {
        if let Some(id) = execution.as_ref().and_then(|answer| answer.elicitation_id.as_deref()) {
            if planes.consent.begin_execution(id).is_err() {
                execution_result = json!({"outcome":"consent_unavailable", "reason":"grant_store_unavailable"});
                return execution_result.clone();
            }
        }
    }
    let result = match &answer {
        Some(answer) => plan.conclude(answer),
        // A caller stop authorizes no transfer and is not a person's denial.
        None => plan.cancelled(),
    };
    execution_result = result.to_value();
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
    }.await;
    if let Some(answer) = execution {
        computer_grants::report_login_execution(
            &carrier,
            &answer,
            &execution_result,
            "transferred",
        )
        .await;
    }
    reply
}

async fn journal_login_import_result(
    planes: &Planes,
    identity: &RouteIdentity,
    result: login_import::ImportResult,
) -> Value {
    if result.outcome == "transferred"
        && planes
            .browser
            .record_signed_in(&identity.agent_project_id, &result.origin)
            .await
            .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"signed_in_domains_unavailable"});
    }
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

/// Wait for consent and window handover, not the person's sign-in. The durable
/// obligation is saved before replying so a restart can settle it, and only
/// closed outcome codes, never the captured header, enter the late entry.
async fn capture_browser_login(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    writer: &mpsc::Sender<Frame>,
    address: (u16, u32, u64),
    request: &login_capture::CaptureRequest,
    call_key: &str,
) -> Value {
    let (channel, epoch, corr) = address;
    if !computer_grants::admits_consent(facts) {
        let why = if facts.flow_id.is_some() {
            return flow_consent_refusal("unattended_flow");
        } else {
            cingulate_client::desk::NoCard::NoAgentSession
        };
        return json!({"outcome":"consent_unavailable","detail":{"reason":why.reason(),"remedy":why.remedy()}});
    }
    // Before the sign-in window is handed to the person, cancellation of the
    // request also cancels consent. Once replied, the capture belongs to its
    // custodian, so closing the request must not stop sign-in. Module shutdown
    // still interrupts the capture and disposes its throwaway profile.
    let cancel = planes.cancellations.get((channel, epoch, corr));
    let draining = Arc::clone(&planes.draining);
    let cancel_for_capture = cancel.clone();
    let detached = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let detached_for_capture = Arc::clone(&detached);
    // The card is raised through the module's computer grants, which hold
    // the call for a bounded wait, leave the card open past it, and answer a
    // retry from a late approval; the capture reports to Cingulate what
    // became of an approval it used that way.
    let capture = Arc::clone(&planes.capture);
    let request = request.clone();
    let accepted = facts.clone();
    let grants = Arc::clone(planes.management.computer_grants());
    let consent = login_consent_request(
        planes,
        facts,
        writer,
        (channel, epoch),
        computer_grants::LoginCapability::CaptureLogin,
        request.consent_parameters(),
        cancel,
    );
    let (ready, handed_over) = tokio::sync::oneshot::channel();
    let mut handed_over = handed_over;
    let mut running = Box::pin(async move {
        capture
            .run_notifying(
                &request,
                login_capture::CaptureCall {
                    accepted: &accepted,
                    grants: &grants,
                    consent,
                    cancelled: move || {
                        (!detached_for_capture.load(std::sync::atomic::Ordering::Acquire)
                            && cancel_for_capture
                                .as_ref()
                                .is_some_and(CancelHandle::is_cancelled))
                            || draining.load(std::sync::atomic::Ordering::Acquire)
                    },
                },
                Some(ready),
            )
            .await
    });
    let handoff = tokio::select! {
        biased;
        ready = &mut handed_over => ready.ok(),
        outcome = &mut running => {
            return journal_capture_outcome(&planes.browser, &facts.identity, outcome).await;
        }
    };
    let Some(handoff) = handoff else {
        return journal_capture_outcome(&planes.browser, &facts.identity, running.await).await;
    };
    let principal = journal::call_records::principal_label(facts.principal.as_ref());
    let scope = facts
        .scope
        .as_ref()
        .map(journal::call_records::ScopeIdentity::from_stamp)
        .unwrap_or_else(|| journal::call_records::ScopeIdentity {
            owner: principal.clone(),
            reference: facts.identity.conversation_key.clone(),
            scope_epoch: 0,
        });
    let calls = Arc::clone(&planes.calls);
    let key = call_key.to_owned();
    let (save_principal, save_key, origin) =
        (principal.clone(), key.clone(), handoff.origin.clone());
    let saved = tokio::task::spawn_blocking(move || {
        calls.hold_capture(&save_principal, &save_key, scope, &origin, wall_clock_ms())
    })
    .await;
    if !matches!(saved, Ok(Ok(()))) {
        let _ = handoff.proceed.send(false);
        let _ = journal_capture_outcome(&planes.browser, &facts.identity, running.await).await;
        return json!({"outcome":"internal_failure","reason":"call_record_unavailable"});
    }
    detached.store(true, std::sync::atomic::Ordering::Release);
    let _ = handoff.proceed.send(true);
    let browser = Arc::clone(&planes.browser);
    let identity = facts.identity.clone();
    let calls = Arc::clone(&planes.calls);
    #[cfg(test)]
    let journal_finalization = planes.capture.take_journal_finalization();
    tokio::spawn(async move {
        let outcome = running.await;
        let ending = capture_ending(&outcome.reply);
        let _ = tokio::task::spawn_blocking(move || {
            calls.finish_handoff(&principal, &key, ending, wall_clock_ms())
        })
        .await;
        // Audit congestion must not hold back the capture's already-known result.
        let _ = journal_capture_outcome(&browser, &identity, outcome).await;
        #[cfg(test)]
        if let Some(finalized) = journal_finalization {
            let _ = finalized.send(());
        }
    });
    json!({
        "outcome":"capture_pending", "origin":handoff.origin,
        "expires_in_ms":handoff.expires_in_ms,
        "message":"The capture result will arrive later as a notice; do not poll for it."
    })
}

fn capture_ending(reply: &Value) -> journal::call_records::HandoffEnding {
    use journal::call_records::HandoffEnding;
    match reply["outcome"].as_str() {
        Some("captured") => HandoffEnding::Captured,
        Some("expired") if reply["reason"] != login_capture::LOGIN_NOT_VERIFIED => {
            HandoffEnding::Expired
        }
        Some(
            "expired"
            | "no_login_observed"
            | "capture_no_cookies_for_url"
            | "capture_header_unusable",
        ) => HandoffEnding::SessionInvalid,
        _ => HandoffEnding::HandoffInterrupted,
    }
}

async fn journal_capture_outcome(
    browser: &BrowserPlane,
    identity: &RouteIdentity,
    outcome: login_capture::CaptureOutcome,
) -> Value {
    // A deposit already made stays in the vault when this record cannot be
    // written: the vault cannot be asked to withdraw it, and its own audit
    // row, bound to the consent card's id, still describes it.
    if browser
        .journal_login_capture(identity, outcome.journal)
        .await
        .is_err()
    {
        return json!({"outcome":"internal_failure","reason":"journal_unavailable"});
    }
    outcome.reply
}

async fn present_browser_handoff(
    planes: &Planes,
    identity: &RouteIdentity,
    origin: &str,
    held: Option<(String, String, journal::call_records::ScopeIdentity)>,
) -> Value {
    let deadline_ms = planes
        .browser_config
        .as_ref()
        .map_or(30_000, |config| config.navigation_settle_deadline_ms);
    // Fronting the window and reading its cookies are blocking CDP commands
    // under the session's driver lock, so they run on the blocking pool, never
    // on this async task. The call took its work permit when it got its turn
    // in the conversation's queue, and keeps it until this job finishes: if
    // the call is answered (by its deadline, a cancel or a drain) before the
    // job returns, its route task is kept alive, holding the permit, until
    // then. So a stuck job keeps counting against the plane's capacity.
    let sessions = planes.sessions.clone();
    let clock = Arc::clone(&planes.lease_clock);
    let route_key = identity.conversation_key.clone();
    let profile = identity.agent_project_id.clone();
    let profile_name = browser_signed_in::SignedInDomains::profile_name(identity);
    let present_origin = origin.to_owned();
    let presented = on_call_blocking_pool(move || {
        sessions.present_for_profile(
            &route_key,
            &profile,
            &profile_name,
            &present_origin,
            deadline_ms,
            clock.as_ref(),
        )
    })
    .await;
    let Ok(presented) = presented else {
        return json!({"outcome":"internal_failure"});
    };
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

    if let Some((principal, key, scope)) = held.clone() {
        let calls = Arc::clone(&planes.calls);
        let conversation = identity.conversation_key.clone();
        let origin = origin.to_owned();
        let saved = tokio::task::spawn_blocking(move || {
            calls.hold_handoff(
                &principal,
                &key,
                &conversation,
                scope,
                &origin,
                wall_clock_ms(),
            )
        })
        .await;
        if !matches!(saved, Ok(Ok(()))) {
            let _ = planes
                .sessions
                .resume(&identity.conversation_key, planes.lease_clock.as_ref());
            return json!({"outcome":"internal_failure"});
        }
    }

    let settle = held.as_ref().map(|(principal, key, _)| {
        let calls = Arc::clone(&planes.calls);
        let (principal, key) = (principal.clone(), key.clone());
        Arc::new(move |ending| {
            calls
                .finish_handoff(&principal, &key, ending, wall_clock_ms())
                .is_ok()
        }) as HandoffSettle
    });
    spawn_handoff_poll(
        planes,
        identity.clone(),
        presented.generation,
        deadline_ms,
        settle,
    );

    if held.is_some() {
        json!({"outcome":"login_pending", "origin":origin, "expires_in_ms":presented.expires_in_ms})
    } else {
        json!({"outcome":"presented", "expires_in_ms":presented.expires_in_ms})
    }
}

fn handoff_ending(
    outcome: browser_session::HandoffOutcome,
) -> journal::call_records::HandoffEnding {
    use journal::call_records::HandoffEnding;
    match outcome {
        browser_session::HandoffOutcome::LoginObserved => HandoffEnding::LoginObserved,
        browser_session::HandoffOutcome::Expired => HandoffEnding::HandoffExpired,
        browser_session::HandoffOutcome::ClosedByCaller => HandoffEnding::ClosedByCaller,
    }
}

#[doc(hidden)]
pub async fn present_browser_handoff_for_test(
    planes: &Planes,
    identity: &RouteIdentity,
    origin: &str,
) -> Value {
    present_browser_handoff(planes, identity, origin, None).await
}

async fn resume_browser_handoff(planes: &Planes, identity: &RouteIdentity) -> Value {
    let calls = Arc::clone(&planes.calls);
    let sessions = planes.sessions.clone();
    let clock = Arc::clone(&planes.lease_clock);
    let conversation = identity.conversation_key.clone();
    let resumed = tokio::task::spawn_blocking(move || {
        calls.resume_handoff(&conversation, wall_clock_ms(), || {
            sessions.resume(&conversation, clock.as_ref())
        })
    })
    .await;
    let close = match resumed {
        Ok(Ok(close)) => close,
        Ok(Err(browser_session::ResumeRefusal::NoHandoff)) => {
            return json!({"outcome":"no_handoff","remedy":"browser.present"})
        }
        Err(_) => return json!({"outcome":"internal_failure"}),
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
    call_record_workers: Option<&CallRecordWorkers>,
    private_content: Option<&private_content::PrivateContent>,
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
            call_mode,
        } => {
            // Basal needs verified flow delegation or a resolved codemode head.
            // Cingulate may bind only to
            // this module's management surface, where its calls are limited to
            // permissions.list/revoke before any grant lookup. Neither needs
            // the unrelated powers that first-party membership would confer.
            let trust = trust_for_principal(&principal);
            if private_content::is_broca(&principal)
                && !private_content::bind_admitted(&principal, &target)
            {
                return send_principal_denied(
                    writer,
                    frame.header.ver,
                    frame.header.corr,
                    &principal,
                )
                .await;
            }
            let mode = call_mode
                .clone()
                .unwrap_or(subc_protocol::call_mode::CallMode::Classic);
            let run_candidate = scope.as_ref().is_some_and(|stamp| {
                cerebellum_core::identity::codemode_carrier_candidate(stamp, &principal, &mode)
            });
            if !trust.is_first_party()
                && !run_candidate
                && !scope.as_ref().is_some_and(|stamp| {
                    cerebellum_core::identity::flow_carrier_admitted(stamp, &principal)
                })
                && !permissions::bind_admitted(&principal, &target)
                && !private_content::bind_admitted(&principal, &target)
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

            let head = if run_candidate {
                match route_bindings.run_head(scope.as_ref().expect("run candidate has a scope")) {
                    Ok(head) => Some(head),
                    Err(refusal) => {
                        return send_route_error(
                            writer,
                            frame.header.ver,
                            0,
                            0,
                            frame.header.corr,
                            refusal.code(),
                            refusal.message(),
                        )
                        .await
                    }
                }
            } else {
                None
            };
            // A carrier may put any session id on a run bind. Construct its
            // identity from the admitted head instead, without consulting that id.
            let head_identity = head.as_ref().map(|head| {
                subc_protocol::BindIdentity::new(
                    head.identity.project_root.to_string_lossy().into_owned(),
                    "codemode-head",
                    head.identity.conversation_key.clone(),
                )
            });
            // Retain only facts from the accepted bind. Data-plane frames inherit
            // these facts by (channel, epoch); request bodies cannot replace them.
            let mut accepted_facts = AcceptedBindFacts::from_bind(
                head_identity.as_ref().unwrap_or(&identity),
                principal.clone(),
                admission_facts.as_ref(),
                consumer_capabilities.as_deref(),
                &target,
            )
            // An authorized prefrontal-core scope stamp supplies identity and
            // delegation. Retaining it also lets call records name the scope
            // and lets its owner withdraw calls when the scope is revoked.
            .with_scope(scope);
            accepted_facts.call_mode =
                call_mode.unwrap_or(subc_protocol::call_mode::CallMode::Classic);
            if let Some(head) = head {
                accepted_facts = accepted_facts.with_codemode_head(&head);
            }
            route_bindings.insert(route_channel, epoch, accepted_facts);
            // Accept the bind — capability scope is checked at dispatch time.
            ModuleControlResponse::RouteBindAck {}
        }
        ModuleControlRequest::HealthCheck {} => {
            // Insulated health-v2 lane: the report is a mechanical mapper over
            // atomics stamped by the dispatch path. It never blocks on a lock
            // and never forms its own opinion (Health-Path-Rule-v2).
            let mut report = with_process_gauges(health_state.report());
            if let ModuleControlResponse::HealthCheck {
                metrics: Some(Value::Object(metrics)),
                ..
            } = &mut report
            {
                metrics.insert(
                    "privateContentStore".into(),
                    json!(private_content.map_or("not_opened", |store| store.health())),
                );
            }
            let mut report = match call_record_workers {
                Some(workers) => workers.health_report(report),
                None => report,
            };
            if let ModuleControlResponse::HealthCheck {
                metrics: Some(Value::Object(metrics)),
                ..
            } = &mut report
            {
                let records = metrics
                    .get("detachedCallRecordWorkers")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let workers = metrics
                    .get("detachedWorkers")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                metrics.insert("detachedWorkers".into(), json!(workers + records));
            }
            report
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
    let object = serde_json::from_slice::<Value>(&frame.body).ok();
    let name = object.as_ref().and_then(|value| value["name"].as_str());
    let bind = planes.routes.get(frame.header.channel, frame.header.epoch);
    if let (Some(name), Some(facts)) = (name, bind.as_ref()) {
        if let Err(error) = tool_provider::check_call_mode(name, &facts.call_mode, planes) {
            return tool_provider::send_error(
                error,
                (
                    frame.header.ver,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                ),
                writer,
            )
            .await;
        }
    }
    // Result-reader support is a route declaration, never a call argument.
    // Older cores retain their exact legacy body until they declare the reader.
    let result_bind = name.zip(bind).map(|(name, bind)| (name.to_owned(), bind));
    tool_result::RESULT_BIND
        .scope(
            result_bind,
            tool_result::SETTLEMENT_NOTE_OMITTED.scope(
                std::cell::Cell::new(false),
                codemode::CALL_RECORDS.scope(
                    Arc::clone(&planes.calls),
                    handle_keyed_tool_request_inner(frame, writer, planes),
                ),
            ),
        )
        .await
}

async fn handle_keyed_tool_request_inner(
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
        return Box::pin(handle_tool_request(
            frame,
            writer,
            planes,
            &CallObservation::new(),
        ))
        .await;
    };
    if object.contains_key("schema_pin") {
        if let Err(error) = tool_provider::check_tool_call(&object, planes) {
            return tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await;
        }
    }
    let call_key = match object.remove("call_key") {
        None => None,
        Some(Value::String(key)) if call_records::valid_call_key(&key) => Some(key),
        Some(_) => {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(
                    "call_key",
                    "expected 1..256 printable non-space ASCII bytes",
                ),
                (ver, channel, epoch, corr),
                writer,
            )
            .await
        }
    };
    if tool_provider::is_operation(object.get("name").and_then(Value::as_str).unwrap_or("")) {
        if call_key.is_some() {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(
                    "call_key",
                    "provider operations take no envelope call key",
                ),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
        return tool_provider::serve(&object, (ver, channel, epoch, corr), writer, planes).await;
    }
    if object.get("name").and_then(Value::as_str) == Some(call_records::WITHDRAW_OPERATION) {
        // The key a withdrawal names is `arguments.call_key`. A second key on
        // the envelope would leave it unclear which call is meant.
        if call_key.is_some() {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(
                    "call_key",
                    "withdrawal names arguments.call_key only",
                ),
                (ver, channel, epoch, corr),
                writer,
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
    let flat_tool = matches!(
        object.get("name").and_then(Value::as_str),
        Some(flat_tools::BROWSER_USE | flat_tools::COMPUTER_USE)
    );
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
    // Install before durable admission finishes: a withdrawal can observe the
    // new record as soon as its write completes, before this task resumes.
    // Duplicate/replayed keys must not replace an executing call's handle.
    let _run_call = planes.run_calls.register(
        &facts,
        &call_key,
        planes.cancellations.get((channel, epoch, corr)),
    );
    // Only an admission completed within its budget can authorize execution.
    // The worker keeps its permit through any late refusal write.
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
        begin_call_record(planes, (ver, channel, epoch, corr), move || {
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
            // A reconnect can change its declared result reader without changing
            // the recorded action. Adapt only the encoding, never execute again.
            if flat_tool {
                if let Some(result) = reply.result() {
                    if result.get("held").is_some() {
                        let legacy = result.get("structuredContent").cloned().unwrap_or(result);
                        return call_context::CALL_KEY
                            .scope(
                                call_key.clone(),
                                private_content::send_reply(
                                    planes,
                                    &facts,
                                    private_content::replay_plane(&legacy),
                                    writer,
                                    (ver, channel, epoch, corr),
                                    legacy,
                                ),
                            )
                            .await;
                    }
                    let is_content = result.get("content").is_some()
                        && result.get("structuredContent").is_some();
                    let wants_content = tool_result::RESULT_BIND
                        .try_with(|binding| {
                            binding.as_ref().is_some_and(|(_, bind)| {
                                cortexkit_role_tool_provider::consumer_reads_tool_result_v1(
                                    bind.consumer_capabilities(),
                                )
                            })
                        })
                        .unwrap_or(false);
                    if is_content != wants_content {
                        let legacy = result.get("structuredContent").cloned().unwrap_or(result);
                        return private_content::send_reply(
                            planes,
                            &facts,
                            private_content::replay_plane(&legacy),
                            writer,
                            (ver, channel, epoch, corr),
                            legacy,
                        )
                        .await;
                    }
                }
            }
            let response = reply.readdressed(ver, channel, epoch, corr);
            if response.header.ty == FrameType::Response {
                if let Ok(delivered) = serde_json::from_slice::<Value>(&response.body) {
                    private_content::mark_delivered(
                        planes,
                        &facts,
                        private_content::replay_plane(&delivered),
                        &delivered,
                    )
                    .await;
                }
            }
            return send(writer, response).await;
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
            return send(
                writer,
                call_record_unavailable((ver, channel, epoch, corr), &error),
            )
            .await;
        }
    };

    if let Some(terminal) = TerminalArbiter::current() {
        let observation = CallObservation::new()
            .with_origin(origin)
            .with_key(call_key.clone());
        let mut pending = Some(PendingSettlement {
            ticket: Some(ticket),
            observation: observation.clone(),
            unattributed_at_start: cerebellum_core::dispatch_witness::unattributed_commit_count(),
            request: (channel, epoch, corr),
        });
        let late = {
            let mut state = terminal.state.lock().unwrap();
            if let Some(chosen) = &state.chosen {
                Some(chosen.clone())
            } else {
                state.settlement = pending.take();
                None
            }
        };
        if let Some(reply) = late {
            // Admission can finish after the terminal has already taken its
            // suffix. Settle that ticket to the chosen reply, never execute it.
            let evidence = journal::call_records::DispatchEvidence {
                gate_dispatched: false,
                committed: false,
                commit_point: false,
                unattributed_commit: false,
                refused_before_dispatch: refused_before_dispatch(&reply),
            };
            let settlement = journal::call_records::Settlement::from_reply(&reply, evidence);
            let calls = Arc::clone(&planes.calls);
            let ticket = pending
                .expect("late admission")
                .ticket
                .expect("admitted ticket");
            settle_call_record(planes, move || {
                calls.settle(ticket, settlement, wall_clock_ms())
            })
            .await;
            return Ok(());
        }
        return call_context::CALL_KEY
            .scope(
                call_key,
                Box::pin(handle_tool_request(call, writer, planes, &observation)),
            )
            .await;
    }

    // The call writes its frames into this channel rather than the route's, so
    // its terminal reply can be recorded before it is forwarded when the write
    // finishes within the settlement budget. Every other frame (a consent
    // question, say) is forwarded untouched.
    let (proxy, mut outgoing) = mpsc::channel::<Frame>(16);
    let mut pending = PendingSettlement {
        ticket: Some(ticket),
        observation: CallObservation::new()
            .with_origin(origin)
            .with_key(call_key.clone()),
        unattributed_at_start: cerebellum_core::dispatch_witness::unattributed_commit_count(),
        request: (channel, epoch, corr),
    };
    let result = {
        let observation = pending.observation.clone();
        let call = call_context::CALL_KEY.scope(
            call_key,
            Box::pin(handle_tool_request(call, &proxy, planes, &observation)),
        );
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
        settle_call_record(planes, move || {
            calls.settle_unknown(ticket, wall_clock_ms())
        })
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
    terminal: Option<std::sync::Weak<TerminalArbiter>>,
    /// Marked at a plane's dispatch commitment for this request.
    dispatch: cerebellum_core::dispatch_witness::DispatchWitness,
    /// Records whether an external mutation began before the terminal reply was
    /// chosen. Unlike `dispatch`, this covers the interval before the mutation's
    /// audit commitment marks the request's witness.
    gate_dispatched: Arc<std::sync::atomic::AtomicBool>,
    /// Set just before the request is handed to a plane every one of whose
    /// dispatches passes a commitment that marks `dispatch`.
    commit_point: Arc<std::sync::atomic::AtomicBool>,
    /// The request's `origin`, already validated, for the audit rows the call
    /// writes. Attribution only: admission reads the route's own facts.
    origin: cerebellum_core::journal::CallOriginRecord,
    call_key: Option<String>,
}

impl CallObservation {
    fn new() -> Self {
        let terminal = TerminalArbiter::current();
        Self {
            dispatch: terminal
                .as_ref()
                .map(|t| t.witness.clone())
                .unwrap_or_else(cerebellum_core::dispatch_witness::DispatchWitness::armed),
            gate_dispatched: terminal
                .as_ref()
                .map(|t| Arc::clone(&t.gate_dispatched))
                .unwrap_or_else(|| Arc::new(std::sync::atomic::AtomicBool::new(false))),
            commit_point: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            origin: cerebellum_core::journal::CallOriginRecord::Absent,
            call_key: None,
            terminal: terminal.as_ref().map(Arc::downgrade),
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

    fn with_key(mut self, key: String) -> Self {
        self.call_key = Some(key);
        self
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
    let envelope: Value = serde_json::from_slice(&reply.body).unwrap_or(Value::Null);
    let body = envelope.get("structuredContent").unwrap_or(&envelope);
    match reply.header.ty {
        // The envelope and argument checks answer in the reply body.
        FrameType::Response => {
            matches!(
                body["outcome"].as_str(),
                Some(
                    "invalid_request"
                        | "resource_busy"
                        | "action_deadline_exceeded"
                        | "target_busy"
                        | "blocking_capacity_exhausted"
                )
            ) || (body["outcome"] == "consent_unavailable"
                && matches!(
                    body["detail"]["reason"].as_str(),
                    Some(
                        "flow_carrier_not_admitted"
                            | "unattended_flow"
                            | "takeover_not_for_flows"
                            | "agent_run"
                    )
                ))
        }
        FrameType::Error => body["code"].as_str().is_some_and(|code| {
            [
                "invalid_request",
                "route_not_bound",
                "capability_denied",
                "computer_plane_unavailable",
                "call_record_unavailable",
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

/// Forward one frame of a keyed call. For its terminal reply, wait for the
/// record only within the settlement budget; a late write keeps that reply.
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
                gate_dispatched: pending
                    .observation
                    .gate_dispatched
                    .load(std::sync::atomic::Ordering::SeqCst),
                committed: pending
                    .observation
                    .terminal
                    .as_ref()
                    .and_then(std::sync::Weak::upgrade)
                    .map(|terminal| {
                        terminal
                            .witness_committed
                            .load(std::sync::atomic::Ordering::SeqCst)
                    })
                    .unwrap_or_else(|| pending.observation.dispatch.committed()),
                commit_point: pending
                    .observation
                    .commit_point
                    .load(std::sync::atomic::Ordering::SeqCst),
                unattributed_commit: cerebellum_core::dispatch_witness::unattributed_commit_count()
                    != pending.unattributed_at_start,
                refused_before_dispatch: refused_before_dispatch(&out),
            };
            // Freeze the evidence and reply before detaching the write, so late
            // worker completion cannot replace the terminal settlement.
            let calls = Arc::clone(&planes.calls);
            let settlement = journal::call_records::Settlement::from_reply(&out, evidence);
            settle_call_record(planes, move || {
                calls.settle(ticket, settlement, wall_clock_ms())
            })
            .await;
        }
    }
    send(writer, out).await
}

/// `tool.withdraw {call_key, scope?, carrier?}`: what became of a recorded
/// call, interrupting a live codemode call after authorization. Only a record
/// that merely asked a person guarantees its action will never run. The
/// question may still record a grant for a future call.
///
/// The answer is read from the record, so every permitted repeat gets the
/// same bytes. A carrier looks up only its own key; an authorized scope owner
/// may name another carrier. Every found record must match the route's scope.
/// An absent explicit carrier record answers `unknown_call`; an owner with no
/// own record must name a carrier. Neither reveals another carrier's keys.
/// Caller/scope mismatches are contract route
/// errors, and the daemon's `owner_authorized` stamp remains required when an
/// owner acts for another carrier.
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
            .filter(|field| {
                !matches!(
                    field.as_str(),
                    "name" | "arguments" | "progress_token" | "tool_call_id"
                )
            })
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
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::invalid_request(&field, reason),
                (ver, channel, epoch, corr),
                writer,
            )
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
    use cortexkit_role_tool_provider::scope::ScopeIdentity as WireScope;
    use cortexkit_role_tool_provider::withdraw::{
        check_record_scope, resolve_carrier, CallerProblem, CarrierResolution, WithdrawArguments,
    };
    let to_wire = |scope: &ScopeIdentity| WireScope {
        owner: scope.owner.clone(),
        scope_ref: scope.reference.clone(),
        scope_epoch: scope.scope_epoch,
    };
    let stamped = facts.scope.as_ref().map(ScopeIdentity::from_stamp);
    let wire_stamp = stamped.as_ref().map(to_wire);
    let mut arguments = WithdrawArguments::new(&call_key);
    arguments.scope = named_scope.as_ref().map(to_wire);
    arguments.carrier = carrier;
    let resolution = match resolve_carrier(&principal, wire_stamp.as_ref(), &arguments) {
        Ok(resolution) => resolution,
        Err(problem) => {
            return tool_provider::send_error(problem.error(), (ver, channel, epoch, corr), writer)
                .await;
        }
    };
    let (carrier, owner_as_carrier) = match resolution {
        CarrierResolution::Carrier(carrier) => (carrier, false),
        CarrierResolution::OwnerAsCarrier(carrier) => (carrier, true),
    };
    // The contract resolves the carrier; the daemon still decides whether a
    // scope owner may act for somebody else. A claimed owner is not authority.
    if carrier != principal
        && !facts
            .scope
            .as_ref()
            .is_some_and(|stamp| stamp.owner_authorized)
    {
        return tool_provider::send_error(
            CallerProblem::NotPermitted.error(),
            (ver, channel, epoch, corr),
            writer,
        )
        .await;
    }
    // Never search other principals' keys: even a refusal would disclose that
    // another carrier has a record with this opaque key.
    let lookup = planes.calls.lookup_exact(&carrier, &call_key);
    if let Lookup::Own(snapshot) = &lookup {
        let record_scope = snapshot.scope.as_ref().map(to_wire);
        if let Err(problem) = check_record_scope(record_scope.as_ref(), wire_stamp.as_ref()) {
            return tool_provider::send_error(problem.error(), (ver, channel, epoch, corr), writer)
                .await;
        }
    } else if owner_as_carrier && matches!(lookup, Lookup::Unknown | Lookup::OtherPrincipal) {
        return tool_provider::send_error(
            CallerProblem::CarrierRequired.error(),
            (ver, channel, epoch, corr),
            writer,
        )
        .await;
    }
    match lookup {
        Lookup::Own(snapshot) => {
            if let Some(cancel) =
                planes
                    .run_calls
                    .cancellation(&carrier, &call_key, stamped.as_ref())
            {
                cancel.cancel();
                if let (Some(agent), Some(cursor)) = (cancel.cursor_agent(), planes_cursor(planes))
                {
                    cursor.end(&agent);
                }
            }
            let answer = call_records::withdraw_answer(&snapshot);
            // Interruption does not undo dispatched input. Only a record that
            // merely asked a person proves the action will never run; a started
            // call keeps its honest outcome even after cancellation is fired.
            private_content::send_reply(
                planes,
                &facts,
                private_content::replay_plane(&answer),
                writer,
                (ver, channel, epoch, corr),
                answer,
            )
            .await
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
    let user = serde_json::from_slice::<Value>(&frame.body)
        .ok()
        .is_some_and(|body| {
            body["name"] == flat_tools::BROWSER_USE && body["arguments"]["browser"] == "user"
        });
    if !user {
        return Box::pin(handle_tool_request_enforced(frame, writer, planes, call)).await;
    }
    // Tag even admission/schema refusals, which never reach the user adapter.
    // Own calls bypass this forwarding path and keep their original bytes.
    let (tagged, mut replies) = mpsc::channel::<Frame>(16);
    let writer = writer.clone();
    let forwarding = tokio::spawn(async move {
        while let Some(frame) = replies.recv().await {
            let frame = if matches!(frame.header.ty, FrameType::Response | FrameType::Error) {
                let mut body: Value =
                    serde_json::from_slice(&frame.body).map_err(ModuleError::Json)?;
                body["browser"] = json!("user");
                Frame::build_with_version(
                    frame.header.ver,
                    frame.header.ty,
                    frame.header.flags,
                    frame.header.channel,
                    frame.header.epoch,
                    frame.header.corr,
                    serde_json::to_vec(&body).map_err(ModuleError::Json)?,
                )
                .map_err(|error| ModuleError::Message(error.to_string()))?
            } else {
                frame
            };
            send(&writer, frame).await?;
        }
        Ok::<(), ModuleError>(())
    });
    let result = Box::pin(handle_tool_request_enforced(frame, &tagged, planes, call)).await;
    drop(tagged);
    forwarding
        .await
        .map_err(|error| ModuleError::Message(error.to_string()))??;
    result
}

async fn handle_tool_request_enforced(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    call: &CallObservation,
) -> Result<(), ModuleError> {
    let key = (frame.header.channel, frame.header.epoch, frame.header.corr);
    // Passing a large handler by value through the grant watcher multiplies
    // debug poll-frame stack slots. Pin it once so normal completion and
    // cancellation cleanup carry only the pointer.
    let future = Box::pin(handle_tool_request_inner(frame, writer, planes, call));
    match planes.cancellations.get(key) {
        Some(cancel) => grant_enforcement::scope(cancel, future).await,
        None => future.await,
    }
}

async fn handle_tool_request_inner(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    call: &CallObservation,
) -> Result<(), ModuleError> {
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Queue);
    }
    let _browser_guard = match browser_queue::enter(&frame, planes).await {
        Ok(guard) => guard,
        Err(outcome) => return send_queue_refusal(writer, &frame, planes, outcome).await,
    };
    let route_bindings = &planes.routes;
    if let Some(terminal) = TerminalArbiter::current() {
        terminal.set_step(CallStep::Preflight);
    }
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
                "name"
                    | "arguments"
                    | "progress_token"
                    | "origin"
                    | "preset"
                    | "schema_pin"
                    | "tool_call_id"
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

    if object.contains_key("schema_pin") {
        if let Err(error) = tool_provider::check_tool_call(object, planes) {
            return tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await;
        }
    }

    // Route admission is completed before decoding capability arguments.
    // Admitted routes may proceed to their handlers; denied routes perform no
    // reservation, context lookup, grant lookup, or CDP work.
    // `browser.fill_login` is served only by a plane that was given a source
    // of login material, which no plane built for a running module is yet.
    let known_capability = dispatchable_tool_with_browser(name, planes.browser_config.is_some())
        .or_else(|| {
            browser::fill::admitted(name, &planes.browser, planes.browser_config.is_some())
        });
    let Some(capability_name) = known_capability else {
        if name == flat_tools::BROWSER_USE {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::tool_disabled(name),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
        // Say WHICH kind of unavailable. A caller who named something this build
        // withholds and a caller who named something invented both arrive here,
        // and only one of them can do anything about it.
        let withheld = capability_withheld(name, planes.browser_config.is_some())
            .unwrap_or(CapabilityWithheld::Unknown);
        if matches!(withheld, CapabilityWithheld::Unknown) {
            return tool_provider::send_error(
                cortexkit_role_tool_provider::errors::unknown_tool(name),
                (ver, channel, epoch, corr),
                writer,
            )
            .await;
        }
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
    if let Err(error) = tool_provider::check_tool_call(object, planes) {
        return tool_provider::send_error(error, (ver, channel, epoch, corr), writer).await;
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
        return handle_management_request_observed(
            management_frame,
            writer,
            &accepted_facts,
            planes,
            call.call_key.as_deref(),
        )
        .await;
    }
    if let Some(flat_tools::FlatDispatch::UserBrowser {
        action,
        capability,
        arguments,
    }) = translated.as_ref()
    {
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
        if let Some(capability) = capability {
            // The selector cannot widen the route's capability admission. In
            // particular, open_tab and claim_tab have launch's exact authority.
            if !accepted_facts.allows_capability(capability) {
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
            if let Some(refusal) = browser_session::CONTROL_TOOLS
                .contains(&capability.as_str())
                .then(|| accepted_facts.control_operation_refusal(capability))
                .flatten()
            {
                return send_tool_response(writer, ver, channel, epoch, corr, json!({"browser":"user","outcome":"authorization_denied","reason":refusal.reason_code(),"remedy":accepted_facts.control_refusal_remedy(refusal)})).await;
            }
        }
        call.commit_point_follows();
        // Claims, snapshots, refs and the extension's own route bookkeeping
        // are keyed by the route resolved here: the head's for a run, so a
        // run acts on its head's tabs and its claims outlive the run's route.
        // Cancellation and consent liveness stay on the inbound route.
        let browser_route = match codemode::user_browser_route(planes, channel, epoch) {
            Ok(route) => route,
            Err(refusal) => {
                return send_route_error(
                    writer,
                    ver,
                    channel,
                    epoch,
                    corr,
                    refusal.code(),
                    refusal.message(),
                )
                .await
            }
        };
        let result = user_browser::serve(
            planes,
            &accepted_facts,
            writer,
            (channel, epoch, corr),
            browser_route,
            action,
            arguments,
        )
        .await;
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return private_content::send_reply(
            planes,
            &accepted_facts,
            private_content::ReplyPlane::PersonBrowser,
            writer,
            (ver, channel, epoch, corr),
            result,
        )
        .await;
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
        Some(flat_tools::FlatDispatch::UserBrowser { .. }) => unreachable!("returned above"),
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
    if codemode::legacy_run(&accepted_facts)
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
            agent_run_consent_refusal(),
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
        let context = computer_capability::ServeContext {
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
                computer_order: None,
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
        };
        #[cfg(all(test, target_os = "macos"))]
        let result = if let Some(scripted) = &planes.computer_for_test {
            scripted
                .serve(servable, arguments, context, |_grant| {
                    computer_capability::native_capture_backend()
                })
                .await
        } else {
            plane
                .serve(servable, arguments, context, |_grant| {
                    computer_capability::native_capture_backend()
                })
                .await
        };
        #[cfg(not(all(test, target_os = "macos")))]
        let result = plane
            .serve(servable, arguments, context, |_grant| {
                computer_capability::native_capture_backend()
            })
            .await;
        // A call whose route unbound while it waited on a person has nobody
        // to answer; its reply is dropped rather than sent to a closed route.
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        return match result {
            Ok(result) => {
                private_content::send_reply(
                    planes,
                    &accepted_facts,
                    private_content::ReplyPlane::DesktopApp,
                    writer,
                    (ver, channel, epoch, corr),
                    result,
                )
                .await
            }
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
    if name == browser::fill::FILL_LOGIN {
        // A fill marks the dispatch commitment before its first CDP command,
        // so an unmarked witness proves nothing reached the page.
        call.commit_point_follows();
        let result = Box::pin(login_fill_consent::serve(
            planes,
            &accepted_facts,
            (channel, epoch, corr),
            arguments,
            BROWSER_CONSENT_PARK_LIMIT
                .try_with(|limit| *limit)
                .unwrap_or(Duration::from_secs(120)),
        ))
        .await;
        if planes.routes.get(channel, epoch).is_none() {
            return Ok(());
        }
        if TerminalArbiter::current().is_some_and(|terminal| terminal.answered_by_cancel()) {
            return Ok(());
        }
        return match result {
            Ok(result) => {
                private_content::send_reply(
                    planes,
                    &accepted_facts,
                    private_content::ReplyPlane::OwnBrowser,
                    writer,
                    (ver, channel, epoch, corr),
                    result,
                )
                .await
            }
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
    let result = Box::pin(serve_browser_with_consent(
        planes,
        &accepted_facts,
        writer,
        (channel, epoch, corr),
        capability,
        arguments,
        BROWSER_CONSENT_PARK_LIMIT
            .try_with(|limit| *limit)
            .unwrap_or(Duration::from_secs(120)),
    ))
    .await;
    if planes.routes.get(channel, epoch).is_none() {
        return Ok(());
    }
    // A Cancel already chose this call's reply in its terminal arbiter
    // (`{"outcome":"cancelled","context":null}` before dispatch, or the
    // uncertain-dispatch body after it). The call's own cancelled reply from
    // its site card carries the route's context instead, so sending it would
    // let scheduling decide which body the caller gets; send nothing.
    if TerminalArbiter::current().is_some_and(|terminal| terminal.answered_by_cancel()) {
        return Ok(());
    }
    match result {
        Ok(result) => {
            private_content::send_reply(
                planes,
                &accepted_facts,
                private_content::ReplyPlane::OwnBrowser,
                writer,
                (ver, channel, epoch, corr),
                result,
            )
            .await
        }
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
        .scope(deadline, async {
            handle_frame(frame, writer, planes).await.map(|_| ())
        })
        .await
}

/// Ask only after dispatch has returned its refusal and released its conversation
/// lane and session operation guard. The outer call queue preserves browser
/// order during consent, without holding CDP access or the session's idle sweep.
async fn serve_browser_with_consent(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    _writer: &mpsc::Sender<Frame>,
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
    if codemode::legacy_run(facts) {
        reply["outcome"] = json!("consent_unavailable");
        reply["detail"]["reason"] = json!("agent_run");
        reply["remedy"] = agent_run_consent_refusal()["remedy"].clone();
        return planes.browser.finish_reply(capability.name(), reply);
    }
    if facts.flow_id.is_some() {
        let detail = management::browser_missing_grant(
            scope["origins"][0].as_str().expect("grant request origin"),
            scope["severity_tier"].as_u64().expect("grant request tier"),
        );
        reply["outcome"] = json!("consent_unavailable");
        reply["detail"] = detail;
        reply["remedy"] =
            json!("an unattended flow cannot ask a person; configure its owner's standing grant");
        return planes.browser.finish_reply(capability.name(), reply);
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
    let Ok((mut pending, Some(mut question))) = planes
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
    if let Err(error) = question.bind_holder(permission_scope::minting_holder(facts)) {
        error.apply_to_reply(&mut reply);
        return planes.browser.finish_reply(capability.name(), reply);
    }
    use cingulate_client::desk::{Ending, InCall, LetGo};
    let live = match browser_consent::live(facts, planes, request.0, request.1) {
        Ok(live) => live,
        Err(ending) => {
            browser_consent::settle_failed(
                &planes.management,
                cingulate_client::card::CardKind::WebsiteAccessInCall,
                &question,
                &ending,
            );
            browser_consent::in_call_refusal(&mut reply, &ending);
            return planes.browser.finish_reply(capability.name(), reply);
        }
    };
    let mut session = match planes.consent.session(&live).await {
        Ok(session) => session,
        Err(error) => {
            let ending = Ending::of_refusal(&error);
            browser_consent::settle_failed(
                &planes.management,
                cingulate_client::card::CardKind::WebsiteAccessInCall,
                &question,
                &ending,
            );
            browser_consent::in_call_refusal(&mut reply, &ending);
            return planes.browser.finish_reply(capability.name(), reply);
        }
    };
    let (id, completion) = match browser_consent::raise(
        &planes.management,
        &planes.consent,
        &live,
        &mut session,
        cingulate_client::card::CardKind::WebsiteAccessInCall,
        &question,
        codemode::active(),
    )
    .await
    {
        Ok(raised) => raised,
        Err(ending) => {
            browser_consent::settle_failed(
                &planes.management,
                cingulate_client::card::CardKind::WebsiteAccessInCall,
                &question,
                &ending,
            );
            browser_consent::in_call_refusal(&mut reply, &ending);
            return planes.browser.finish_reply(capability.name(), reply);
        }
    };
    pending["ask_id"] = json!(id);
    if codemode::active() {
        pending["context"] = reply["context"].clone();
        return planes.browser.finish_reply(capability.name(), pending);
    }
    let mut drain = planes.drain_signal.subscribe();
    let mut draining = false;
    let cancelled = async {
        tokio::select! {
            biased;
            _ = drain.wait_for(|value| *value) => { draining = true; LetGo::Withdraw },
            _ = cancel.cancelled() => if planes.routes.get(request.0, request.1).is_some() && planes.routes.carries_conversation(&facts.identity.conversation_key) { LetGo::Detach } else { LetGo::Withdraw },
        }
    };
    let guard = call_context::ROUTE_GUARD.try_with(Arc::clone).ok();
    let parked = guard.as_ref().map(|guard| guard.park_on_consent());
    let (ending, settled) =
        browser_consent::park(planes, &mut session, &id, completion, park_limit, cancelled).await;
    drop(parked);
    match ending {
        InCall::Settled(_) if matches!(settled, management::BrowserGrantSettlement::Granted(_)) => {
            if let Some(terminal) = TerminalArbiter::current() {
                terminal.track_consent(Arc::clone(&planes.consent), &id);
            }
            authorization::with_standing_caller(
                standing_caller(facts),
                planes.browser.serve(&facts.identity, capability, arguments),
            )
            .await
        }
        InCall::Pending { .. } => {
            pending["context"] = reply["context"].clone();
            planes.browser.finish_reply(capability.name(), pending)
        }
        InCall::Cancelled if !draining => {
            // Stopping the call did not deny permission. Discard the original
            // grant refusal and its ask-again advice so a stopped turn cannot
            // start another consent loop.
            planes.browser.finish_reply(
                capability.name(),
                json!({
                    "outcome": "cancelled", "context": reply["context"],
                }),
            )
        }
        ending => {
            let decision = match &ending {
                InCall::Settled(ending) => {
                    if matches!(
                        settled,
                        management::BrowserGrantSettlement::NotRecorded { .. }
                            | management::BrowserGrantSettlement::UnknownAsk
                    ) {
                        "unavailable"
                    } else {
                        in_call_grant_decision(ending)
                    }
                }
                InCall::Cancelled if draining => "module_draining",
                InCall::Cancelled => "cancelled",
                InCall::RouteClosed => "route_closed",
                InCall::Pending { .. } => unreachable!(),
            };
            reply["detail"]["decision"] = json!(decision);
            if let Some(remedy) = in_call_grant_remedy(decision) {
                reply["remedy"] = json!(remedy);
            }
            planes.browser.finish_reply(capability.name(), reply)
        }
    }
}

/// Use the caller's accepted agent and session scope to resolve its holder.
/// For a flow, only an admitted stamp with `delegates` true identifies the
/// owner's head-agent row; a raw `agent_id` attribute is not authority.
fn standing_caller(facts: &AcceptedBindFacts) -> Option<authorization::StandingCaller> {
    permission_scope::authorizing_holder(facts)
        .map(|holder| authorization::StandingCaller { holder })
}

/// Only an admitted primary head may be offered a permanent site grant.
/// Workers and flows must never borrow a head's minting authority.
fn standing_offer_agent(facts: &AcceptedBindFacts) -> Option<&str> {
    matches!(
        permission_scope::minting_holder(facts),
        Some(agent_grants::GrantHolder::Head { .. })
    )
    .then_some(facts.identity.agent_project_id.as_str())
}

/// The `detail.decision` a browser action held open on a grant question
/// reports when the question ended without an allowing answer.
///
/// Each ending keeps its own word because each calls for a different next
/// step; reporting a question nobody was shown the same way as one a person
/// ignored would send the caller to wait for an answer that cannot come.
fn in_call_grant_decision(ending: &cingulate_client::desk::Ending) -> &'static str {
    browser_consent::word(ending, management::BROWSER_GRANT_DECLINE)
}

/// What the caller should do after each [`in_call_grant_decision`]. It replaces
/// the remedy the `authorization_denied` refusal already carries (open the
/// grant and retry), which is right only for a question a person might still
/// answer. Caller cancellation returns a separate `cancelled` result with no
/// grant remedy. `None` keeps the original remedy for other stop conditions.
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
            let browser_session_id = match planes.sessions.acquire_launch_slot_for_profile(
                &accepted.identity.conversation_key,
                (accepted.identity.profile_disposition == ProfileDisposition::Durable)
                    .then_some(accepted.identity.agent_project_id.as_str()),
            ) {
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

fn agent_run_consent_refusal() -> Value {
    json!({"outcome":"consent_unavailable", "reason":"agent_run", "detail":{"reason":"agent_run"},
        "remedy":"an agent run cannot ask a person; configure standing grants in an attended session"})
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

/// Adapter for `session.turn_ended`: admit, parse, hand off, acknowledge.
///
/// Interim: Prefrontal core calls this directly until the harness publishes a
/// turn-ended event this module subscribes to; then this adapter goes, and the
/// subscription calls [`computer_capability::cursor::Coordinator::turn_ended`]
/// the same way.
///
/// Only `reserved:prefrontal-core` may call it, by exact principal. A flow
/// carrier or another first-party module is refused like any other caller of
/// a Prefrontal-only operation. Once admitted and well formed, the reply is
/// always an acknowledgement, even for a session that drew no badge: the
/// caller learns nothing about which sessions used the computer. It writes no
/// journal and touches nothing but the cursor badge: it hides the badge, and
/// an action of that agent still waiting for its badge to arrive will not
/// start. It never touches an action already dispatched.
async fn handle_session_turn_ended(
    writer: &mpsc::Sender<Frame>,
    facts: &AcceptedBindFacts,
    planes: &Planes,
    object: &serde_json::Map<String, Value>,
    (ver, channel, epoch, corr): (u8, u16, u32, u64),
) -> Result<(), ModuleError> {
    if !cerebellum_core::principal::admits_session_calls(&facts.principal) {
        record_turn_ended_refused();
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            "session.turn_ended requires reserved:prefrontal-core",
        )
        .await;
    }
    let params = object.get("params").cloned().unwrap_or(json!({}));
    let Some(params) = params.as_object() else {
        record_turn_ended_refused();
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
    let request = match turn_ended::parse(params) {
        Ok(request) => request,
        Err(error) => {
            record_turn_ended_refused();
            return send_invalid_request_response(
                writer,
                ver,
                channel,
                epoch,
                corr,
                &error.field,
                error.reason,
            )
            .await;
        }
    };
    if let Some(cursor) = planes_cursor(planes) {
        let matched = cursor.turn_ended(
            &request.session_ref,
            Some(&request.scope_ref),
            request.outcome,
        );
        if matched {
            record_turn_ended_matched_badge();
        }
    }
    send_tool_response(
        writer,
        ver,
        channel,
        epoch,
        corr,
        json!({"acknowledged": true}),
    )
    .await?;
    record_turn_ended_received(request.at_ms);
    Ok(())
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
    let response = tool_response_frame(ver, channel, epoch, corr, body)?;
    send(writer, response).await
}

fn tool_response_frame(
    ver: u8,
    channel: u16,
    epoch: u32,
    corr: u64,
    body: Value,
) -> Result<Frame, ModuleError> {
    let held = codemode::held(&body);
    let mut body = if held.is_some() {
        body
    } else {
        codemode::unsupported(body)
    };
    let force_content = body["outcome"] == "held_unsupported";
    let tool_result_v1 = tool_result::RESULT_BIND
        .try_with(|binding| {
            binding.as_ref().is_some_and(|(tool, bind)| {
                matches!(
                    tool.as_str(),
                    flat_tools::BROWSER_USE | flat_tools::COMPUTER_USE
                ) && cortexkit_role_tool_provider::consumer_reads_tool_result_v1(
                    bind.consumer_capabilities(),
                )
            })
        })
        .unwrap_or(false);
    let body = if tool_result_v1 || force_content {
        tool_result::encode_with_held(body, held)?
    } else {
        if codemode::active() {
            if let Some(image) = body.get_mut("image").and_then(Value::as_object_mut) {
                image.remove("data_b64");
            }
        }
        serde_json::to_vec(&body).map_err(ModuleError::Json)?
    };
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
    Ok(response)
}

/// A quarantine refusal is a result of the browser capability, checked
/// against its frozen vocabulary; other queue refusals are route errors.
async fn send_queue_refusal(
    writer: &mpsc::Sender<Frame>,
    frame: &Frame,
    planes: &Planes,
    refusal: browser_queue::QueueRefusal,
) -> Result<(), ModuleError> {
    let (ver, channel, epoch, corr) = (
        frame.header.ver,
        frame.header.channel,
        frame.header.epoch,
        frame.header.corr,
    );
    if let Some((capability, mut body)) = refusal.response_body() {
        if capability == flat_tools::BROWSER_USE {
            // User tabs are not owned browser sessions, so do not validate
            // their queue refusal against a session action's result schema.
            // response_body already supplies the fixed outcome/detail/remedy
            // fields; add the user-target tag before sending it.
            body["browser"] = json!("user");
            return send_tool_response(writer, ver, channel, epoch, corr, body).await;
        }
        if let Ok(body) = planes.browser.finish_reply(capability, body) {
            return send_tool_response(writer, ver, channel, epoch, corr, body).await;
        }
    }
    send_route_error(
        writer,
        ver,
        channel,
        epoch,
        corr,
        refusal.code(),
        refusal.remedy(),
    )
    .await
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
}

impl std::fmt::Display for ModuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(m) => write!(f, "{m}"),
            Self::Json(e) => write!(f, "json: {e}"),
            Self::Config(e) => write!(f, "config: {e}"),
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

/// Number of startup attempts to tighten private data permissions that failed.
static PRIVATE_STATE_TIGHTEN_FAILURES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

fn record_private_state_tightening() {
    if let Some(home) = cerebellum_core::platform_dirs::data_home() {
        let root = home.join("cortexkit").join("cerebellum");
        let failures = cerebellum_core::private_fs::tighten_data_tree(&root);
        PRIVATE_STATE_TIGHTEN_FAILURES
            .fetch_add(failures as u64, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Number of startup attempts to write the backup catalog that failed.
static ENGRAM_CATALOG_WRITE_FAILURES: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);

/// Process-lifetime observations for the quiet session-turn-ended adapter.
/// Keeping only counts and the event timestamp lets health show whether core's
/// calls are reaching this module without exposing session or scope references.
static TURN_ENDED_RECEIVED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TURN_ENDED_REFUSED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TURN_ENDED_MATCHED_BADGE: std::sync::atomic::AtomicU64 =
    std::sync::atomic::AtomicU64::new(0);
static TURN_ENDED_LAST_AT_MS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
static TURN_ENDED_HAS_LAST_AT_MS: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

fn record_turn_ended_refused() {
    TURN_ENDED_REFUSED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn record_turn_ended_matched_badge() {
    TURN_ENDED_MATCHED_BADGE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

fn record_turn_ended_received(at_ms: u64) {
    TURN_ENDED_LAST_AT_MS.store(at_ms, std::sync::atomic::Ordering::Relaxed);
    TURN_ENDED_HAS_LAST_AT_MS.store(true, std::sync::atomic::Ordering::Release);
    TURN_ENDED_RECEIVED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
}

/// Process-lifetime history of the Chrome extension's native-host connection:
/// when it last connected and disconnected, and why it last ended. A drop of
/// this connection normally makes the extension release the tabs agents had
/// claimed and hand them back to the person, so health is where that drop can
/// be timed.
static USER_BROWSER_CONNECTION_GAUGES: user_browser_bridge::ConnectionGauges =
    user_browser_bridge::ConnectionGauges::new();

/// Write `engram-catalog.json` into the module's data directory, so the
/// fleet's backup module knows what that directory holds on every machine,
/// including a new one where nobody placed the file by hand.
///
/// Called only from the production entry point: tests write catalogs into
/// scratch directories through [`cerebellum_core::engram_catalog::write_catalog`]
/// and never into the operator's data home. A failure is counted for health
/// and never stops startup, since the module works without its catalog; only
/// backup coverage is missing.
fn record_engram_catalog_write() {
    if let Some(home) = cerebellum_core::platform_dirs::data_home() {
        let root = cerebellum_core::format_floor::module_directory(&home);
        if cerebellum_core::engram_catalog::write_catalog(&root).is_err() {
            ENGRAM_CATALOG_WRITE_FAILURES.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// Add the process-wide gauges to a health reply:
///
/// - `crashReportLeftovers: {removed, failed}`, counts of crash-report
///   directories removed or left behind when no session was available to report
///   them. These directories can contain page memory from signed-in sessions;
/// - `privateStateTightenFailures`, the number of state directories or files
///   whose owner-only mode could not be enforced at startup;
/// - `engramCatalogWriteFailures`, the number of startup attempts to write the
///   backup catalog (`engram-catalog.json`) that failed;
/// - on macOS, `previewCaptureRequests` and `previewFramesWritten`, how many
///   capture requests the background-mode preview has made and how many frame
///   lines it has written to the agent-cursor helper since the process
///   started, so an idle preview can be seen to cost nothing;
/// - `turnEndedReceived`, `turnEndedRefused`, and `turnEndedMatchedBadge`, the
///   process-lifetime counts for the quiet `session.turn_ended` adapter, plus
///   `turnEndedLastAtMs`, its last admitted event timestamp or `null`;
/// - `userBrowserConnections` and `userBrowserDisconnects`, how many Chrome
///   extension native-host connections were accepted (after the host's hello
///   was verified) and how many of them ended; `userBrowserConnectedAtMs` and
///   `userBrowserDisconnectedAtMs`, the wall-clock milliseconds of the latest
///   of each or `null`; and `userBrowserLastDisconnectReason`, one word from
///   [`user_browser_bridge::DISCONNECT_REASONS`] for the latest end or `null`;
/// - `sigtermListener`, whether SIGTERM will run the module's teardown or
///   just end the process (see [`sigterm_listener_state`]);
/// - `computerGrantStore`, whether the operator's "always allow" app grants are
///   in force, or withheld because their store could not be read;
/// - `openAppLaunchHistory`, whether optional timing history is available or
///   launches are using default waits after a read or write failure;
/// - `hardwareInputObserver: {state, disabled_reenabled_count}`, whether the
///   timestamp-only hardware observer is running and how often it recovered
///   from a disabled tap. Reading health never starts the observer.
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
        #[cfg(target_os = "macos")]
        {
            metrics.insert(
                "cursorAvatarMalformedRows".into(),
                json!(computer_capability::cursor::avatar::malformed_rows()),
            );
            metrics.insert(
                "cursorAvatarReadRefusals".into(),
                json!(computer_capability::cursor::avatar::read_refusals()),
            );
            metrics.insert(
                "previewCaptureRequests".into(),
                json!(computer_capability::preview_capture_requests()),
            );
            metrics.insert(
                "previewFramesWritten".into(),
                json!(computer_capability::preview_frames_written()),
            );
        }
        metrics.insert(
            "privateStateTightenFailures".to_string(),
            serde_json::Value::from(
                PRIVATE_STATE_TIGHTEN_FAILURES.load(std::sync::atomic::Ordering::Relaxed),
            ),
        );
        metrics.insert(
            "engramCatalogWriteFailures".to_string(),
            serde_json::Value::from(
                ENGRAM_CATALOG_WRITE_FAILURES.load(std::sync::atomic::Ordering::Relaxed),
            ),
        );
        metrics.insert(
            "turnEndedReceived".into(),
            json!(TURN_ENDED_RECEIVED.load(std::sync::atomic::Ordering::Relaxed)),
        );
        metrics.insert(
            "turnEndedRefused".into(),
            json!(TURN_ENDED_REFUSED.load(std::sync::atomic::Ordering::Relaxed)),
        );
        metrics.insert(
            "turnEndedMatchedBadge".into(),
            json!(TURN_ENDED_MATCHED_BADGE.load(std::sync::atomic::Ordering::Relaxed)),
        );
        let last_at_ms = if TURN_ENDED_HAS_LAST_AT_MS.load(std::sync::atomic::Ordering::Acquire) {
            json!(TURN_ENDED_LAST_AT_MS.load(std::sync::atomic::Ordering::Relaxed))
        } else {
            Value::Null
        };
        metrics.insert("turnEndedLastAtMs".into(), last_at_ms);
        USER_BROWSER_CONNECTION_GAUGES.insert_into(metrics);
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
        metrics.insert(
            "openAppLaunchHistory".to_string(),
            serde_json::Value::from(open_app_history::durable_history_health()),
        );
        #[cfg(target_os = "macos")]
        let (observer_state, reenabled_count) =
            cerebellum_macos::SessionEventTap::hardware_observer_health();
        #[cfg(not(target_os = "macos"))]
        let (observer_state, reenabled_count) = ("platform_unsupported", 0_u64);
        metrics.insert(
            "hardwareInputObserver".to_string(),
            serde_json::json!({"state": observer_state, "disabled_reenabled_count": reenabled_count}),
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
    handle_control_request(frame, writer, health_state, &route_bindings, None, None).await
}

pub async fn handle_control_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_control_request(frame, writer, health_state, route_bindings, None, None).await
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
    if call_context::ROUTE_GUARD.try_with(|_| ()).is_ok() {
        handle_keyed_tool_request(frame, writer, planes).await
    } else {
        call_context::ROUTE_GUARD
            .scope(
                Arc::new(planes.health.enter_request()),
                handle_keyed_tool_request(frame, writer, planes),
            )
            .await
    }
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

/// No permission card was raised: the planes' scripted Cingulate, when one is
/// installed, received no `consent.request`. Planes without one cannot raise a
/// card at all, because their Cingulate opener refuses every route.
#[cfg(test)]
fn assert_no_card_raised(planes: &Planes) {
    if let Some(consent) = planes.consent_test.as_ref() {
        assert!(
            consent
                .calls()
                .iter()
                .all(|(method, _)| method != "consent.request"),
            "a permission card was raised"
        );
    }
}

#[cfg(test)]
mod tests {
    mod capture_audit_tests;
    use crate::test_support::HANG_GUARD;
    #[tokio::test]
    async fn isolated_plane_without_profile_lifecycle_refuses_rebind_without_touching_data_home() {
        use super::*;
        use std::collections::BTreeMap;
        use std::fs;
        use std::path::PathBuf;

        fn snapshot(root: &std::path::Path) -> BTreeMap<PathBuf, Option<std::time::SystemTime>> {
            let mut entries = BTreeMap::new();
            let Ok(children) = fs::read_dir(root) else {
                return entries;
            };
            for child in children.flatten() {
                let path = child.path();
                let modified = child
                    .metadata()
                    .ok()
                    .and_then(|metadata| metadata.modified().ok());
                entries.insert(path, modified);
            }
            entries
        }

        let data_home = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/share"))
            });
        let browser_root = data_home.map(|root| root.join("cortexkit/cerebellum/browser"));
        let before = browser_root.as_deref().map(snapshot);

        let planes = Planes::new(Arc::new(HealthState::new()));
        let (reply, question) = planes
            .management
            .open_profile_root_rebind("isolated-rebind-test", true)
            .await;
        assert_eq!(reply["outcome"], "internal_failure");
        assert_eq!(reply["stage"], "profile_registry_unavailable");
        assert!(question.is_none());
        if let (Some(root), Some(before)) = (browser_root, before) {
            assert_eq!(
                snapshot(&root),
                before,
                "isolated rebind touched the operator browser data home"
            );
        }
    }

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
            let scope = subc_protocol::scope::ScopeStamp::new(
                core.clone(),
                "head",
                1,
                subc_protocol::scope::ScopeKind::Head,
            )
            .with_attributes(
                subc_protocol::scope::ScopeAttributes::new()
                    .with_agent_id(Some("pj-agent".into()))
                    .with_delegates(delegates),
            )
            .with_owner_authorized(true);
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
            12,
            "expected twelve attestations, found {read_here:?}"
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
        // Ordinary form composition is admitted; credential fields still refuse.
        assert!(dispatchable.contains(browser::TYPE));
    }

    #[cfg(target_os = "macos")]
    #[tokio::test]
    async fn withheld_actions_are_refused_by_the_adapter_too() {
        let keys_frame = || {
            let request = json!({
                "name": flat_tools::COMPUTER_USE,
                "arguments": {
                    "action": "keys",
                    "keys": ["s"],
                    "target": "com.example.Editor"
                }
            });
            Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Request,
                Flags::new(false, Priority::Interactive, false),
                7,
                1,
                99,
                serde_json::to_vec(&request).unwrap(),
            )
            .unwrap()
        };
        let refusal = |admitted: &'static [&'static str]| {
            let frame = keys_frame();
            async move {
                let (tx, mut rx) = mpsc::channel(1);
                let health = Arc::new(HealthState::new());
                handle_tool_request_for_test_admitting(frame, &tx, &health, admitted)
                    .await
                    .unwrap();
                let reply = rx.recv().await.expect("one refusal");
                assert_eq!(reply.header.ty, FrameType::Error);
                serde_json::from_slice::<ErrorBody>(&reply.body)
                    .unwrap()
                    .code
            }
        };
        // With some computer action admitted the tool is served, so the one
        // withheld action is refused by name at the adapter.
        assert_eq!(
            refusal(&["computer.read_state"]).await,
            "capability_not_admitted"
        );
        // With nothing admitted the catalog omits computer_use entirely, and
        // tool-provider/v1 refuses a call to an omitted tool as disabled.
        assert_eq!(refusal(&[]).await, "tool_disabled");
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
                assert_eq!(flat_reply["outcome"], "consent_unavailable");
                assert_eq!(flat_reply["detail"]["reason"], "no_agent_session");
            }
        }
    }

    #[test]
    fn in_flight_bound_covers_the_longest_work_and_release() {
        assert_eq!(
            budgets::IN_FLIGHT_AGE_STALE_MS,
            budgets::MAX_ACTION_WORK_MS + budgets::RELEASE_BUDGET_MS + budgets::IN_FLIGHT_MARGIN_MS
        );
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
        let mut planes = Planes::with_browser_config_journaling(
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
        planes.management = Arc::new(
            ManagementPlane::new(Arc::new(management::PlatformResolver::new())).with_agent_grants(
                Arc::new(agent_grants::AgentGrants::in_memory(Some(
                    "machine-test".into(),
                ))),
            ),
        );
        planes.browser = Arc::new(
            Arc::try_unwrap(planes.browser)
                .ok()
                .unwrap()
                .with_shared_grants(planes.management.browser_grants()),
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

        let planes = computer_grants::tests::CardService::install(planes, 4, 1);
        let tool_facts = planes.routes.get(9, 3).unwrap();
        planes.routes.insert(
            9,
            3,
            tool_facts.with_scope(planes.routes.get(4, 1).unwrap().scope),
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

        let frame = next_frame(&mut writer_rx).await;
        assert_ne!(frame.header.ty, FrameType::Request);
        let pending: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(pending["outcome"], "consent_pending", "{pending}");
        let question_frame = planes.consent_test.as_ref().unwrap().card(4, 1).await;
        let question: Value = serde_json::from_slice(&question_frame.body).unwrap();
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
        // Legacy peers still receive the original deadline; capable peers
        // omit it when the card is raised.
        assert_eq!(question["params"]["expires_in_ms"], json!(1_800_000));

        assert!(planes.consent_test.as_ref().unwrap().answer(
            question_frame.header.corr,
            cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
        ));
        assert_eq!(planes.browser.grant_count_for_test().await, 0);
        computer_grants::tests::drain_call(&planes, 4, 1).await;
        assert_eq!(
            planes
                .management
                .agent_grants()
                .live_rows(None, planes.management.agent_grants().now_ms())
                .unwrap()
                .len(),
            1
        );

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
            assert_no_card_raised(planes);
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
        async fn browser_without_a_standing_row_uses_public_baseline() {
            let reply = query(&planes(), json!({"flow_id":"flow:test","agent_id":"owner","items":[{"tool":"browser_use","target":"https://example.com","level":1}]})).await;
            assert_eq!(reply["items"][0]["verdict"], "yes");
            assert_eq!(reply["items"][0]["reason"], "public_web_baseline");
        }

        /// Public reads use the baseline across agents and origins; a requested
        /// tier above the baseline still needs a sufficient standing site grant.
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
                    {"tool":"browser_use","target":"https://example.com","verdict":"yes","reason":"public_web_baseline"},
                    {"tool":"browser_use","target":"https://example.com","verdict":"would_ask","reason":"level_above_grant"},
                    {"tool":"browser_use","target":"https://example.org","verdict":"yes","reason":"public_web_baseline"}
                ]})
            );
            let other = query(&planes, json!({"flow_id":"flow:test","agent_id":"other","items":[{"tool":"browser_use","target":"https://example.com","level":1}]})).await;
            assert_eq!(other["items"][0]["reason"], "public_web_baseline");
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

    /// Planes with an admitted agent-session management route and an answerable
    /// consent-service fixture (channel 4, epoch 1).
    fn open_grant_planes() -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        // Card-lifetime tests need an answer that can be recorded; isolated
        // browser defaults have no machine identity and offer no site grants.
        planes.management = Arc::new(
            ManagementPlane::new(Arc::new(management::PlatformResolver::new())).with_agent_grants(
                Arc::new(agent_grants::AgentGrants::in_memory(Some(
                    "test-machine".into(),
                ))),
            ),
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
        computer_grants::tests::CardService::install(planes, 4, 1)
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
    /// caller's immediate reply, and a synthetic inspection of the question
    /// received by the consent service.
    async fn open_grant_over_wire(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
        corr: u64,
    ) -> (Value, Frame) {
        handle_frame(open_grant_frame(corr), writer, planes)
            .await
            .unwrap();
        let frame = next_frame(rx).await;
        assert_ne!(frame.header.ty, FrameType::Request);
        let reply = serde_json::from_slice(&frame.body).unwrap();
        let question = planes.consent_test.as_ref().unwrap().card(4, 1).await;
        assert!(rx.try_recv().is_err(), "no reverse-lane question");
        (reply, question)
    }

    /// Script answers or expiry at the service, then apply them on a later call.
    /// Refusals (`not_put_to_anyone`, `refused`, `undeliverable`) are not settled
    /// feed records, so this helper updates their next-request notes directly.
    /// The browser_consent tests send those refusals as RPC errors instead.
    async fn end_question(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        question: &Frame,
        ending: &str,
    ) {
        let outcome = match ending {
            "no_answer" => cingulate_client::ScriptedAnswer::NoAnswer,
            "not_put_to_anyone" | "refused" => cingulate_client::ScriptedAnswer::NotPutToAnyone,
            "undeliverable" => cingulate_client::ScriptedAnswer::Undeliverable,
            _ => cingulate_client::ScriptedAnswer::Answered(json!({"decision":ending})),
        };
        assert!(planes
            .consent_test
            .as_ref()
            .unwrap()
            .answer(question.header.corr, outcome));
        if matches!(ending, "not_put_to_anyone" | "refused" | "undeliverable") {
            let ending = if ending == "undeliverable" {
                cingulate_client::desk::Ending::DeliveryFailed
            } else {
                cingulate_client::desk::Ending::NotPutToAnyone
            };
            planes
                .management
                .settle_browser_grant_ending(
                    &format!("el_test_{}", question.header.corr),
                    Some(&ending),
                )
                .await;
            planes
                .consent
                .mark_applied(&format!("el_test_{}", question.header.corr))
                .unwrap();
        } else if planes.routes.get(4, 1).is_some()
            && !planes.draining.load(std::sync::atomic::Ordering::SeqCst)
        {
            computer_grants::tests::drain_call(planes, 4, 1).await;
        }
        let _ = writer;
    }

    #[tokio::test]
    async fn drain_leaves_an_already_detached_browser_card_answerable() {
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
                &json!({"op":"module.draining","reason":"restart","deadline_ms":123}),
            )
            .unwrap(),
        )
        .unwrap();
        handle_frame(draining, &tx, &planes).await.unwrap();
        assert!(rx.try_recv().is_err());
        assert!(planes.consent_test.as_ref().unwrap().answer(
            question.header.corr,
            cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
        ));
        assert_eq!(planes.management.browser_grant_count().await, 0);
        assert!(planes
            .consent_test
            .as_ref()
            .unwrap()
            .calls()
            .iter()
            .all(|(method, _)| method != "consent.withdraw"));
    }

    #[tokio::test]
    async fn scope_revocation_forgets_detached_browser_card_without_a_route() {
        let planes = open_grant_planes();
        let (tx, mut rx) = mpsc::channel(8);
        let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 901).await;
        let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
        let count = planes.consent_test.as_ref().unwrap().calls().len();
        revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
        assert!(rx.try_recv().is_err());
        assert!(planes
            .consent
            .raised(&format!("el_test_{}", question.header.corr))
            .is_none());
        assert_eq!(planes.consent_test.as_ref().unwrap().calls().len(), count);
        assert_eq!(planes.management.browser_grant_count().await, 0);
    }

    /// A bind at a higher epoch of the same session scope forgets the cards
    /// the ended epoch raised, even after that epoch's route has closed, and
    /// opens no route to Cingulate to do it.
    #[tokio::test]
    async fn an_advanced_epoch_bind_forgets_the_ended_sessions_cards_without_a_route() {
        let planes = open_grant_planes();
        let (tx, mut rx) = mpsc::channel(8);
        let (_, question) = open_grant_over_wire(&planes, &tx, &mut rx, 902).await;
        let id = format!("el_test_{}", question.header.corr);
        assert!(planes.consent.raised(&id).is_some());
        let old = planes.routes.get(4, 1).unwrap();
        let old_stamp = old.scope.clone().unwrap();
        // The epoch-1 route was bound through the epoch check and has since
        // closed, so no bound route names the ended session any more.
        planes
            .scopes
            .note_bind(&old_stamp, &old.identity.conversation_key);
        planes.routes.remove(4, 1);
        let count = planes.consent_test.as_ref().unwrap().calls().len();

        let mut stamp = old_stamp;
        stamp.scope_epoch = 2;
        let bind = ModuleControlRequest::RouteBind {
            role_versions: None,
            call_mode: None,
            route_channel: 5,
            epoch: 1,
            target: subc_protocol::RouteTarget::ManagementSurface {
                module_id: "cerebellum".into(),
            },
            identity: bind_identity_for_test(),
            principal: session_caller_principal_for_test(),
            consumer_capabilities: None,
            admission_facts: Some(json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
            })),
            scope: Some(stamp),
        };
        let frame = Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            5,
            serde_json::to_vec(&bind).unwrap(),
        )
        .unwrap();
        assert!(handle_frame(frame, &tx, &planes).await.unwrap());
        let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            reply.header.ty,
            FrameType::Response,
            "{}",
            String::from_utf8_lossy(&reply.body)
        );
        assert!(
            planes.consent.raised(&id).is_none(),
            "the ended epoch's card is still in the registry"
        );
        assert_eq!(planes.consent_test.as_ref().unwrap().calls().len(), count);
        assert!(rx.try_recv().is_err());
    }

    async fn browser_grants_settled(planes: &Planes) {
        tokio::time::timeout(HANG_GUARD, async {
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
            let (first, question) = open_grant_over_wire(&planes, &writer, &mut rx, 80).await;
            assert_eq!(first["outcome"], "consent_pending", "{first}");
            assert!(first.get("previous_request").is_none(), "{first}");
            end_question(&planes, &writer, &question, ending).await;
            let first_ask = Some(first["ask_id"].as_str().unwrap().to_string());
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
                cingulate_client::desk::Ending::Declined {
                    choice_id: "deny".into(),
                },
                "declined",
            ),
            (cingulate_client::desk::Ending::NoAnswer, "no_answer"),
            (
                cingulate_client::desk::Ending::NotPutToAnyone,
                "not_put_to_anyone",
            ),
            (
                cingulate_client::desk::Ending::DeliveryFailed,
                "undeliverable",
            ),
            (
                cingulate_client::desk::Ending::Declined {
                    choice_id: "some_future_word".into(),
                },
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
            .settle_browser_grant(&question.ask_id, Some(&json!({"decision": "allow_30m"})))
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

    /// A response or error frame on a route channel is dropped without
    /// disturbing the loop.
    ///
    /// This module sends no requests on a route channel (permission cards go
    /// to Cingulate, the consent module, over a route of their own), so such a
    /// frame answers nothing here. It must neither be acted on nor take the
    /// connection down, and nothing is written back.
    #[tokio::test]
    async fn an_unsolicited_answer_is_dropped_without_closing_the_route() {
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);

        let planes = Planes {
            private_content: Arc::new(private_content::PrivateContent::in_memory()),
            signed_in: Arc::new(browser_signed_in::SignedInDomains::default()),
            cancellations: RequestCancellations::default(),
            run_calls: codemode::RunCalls::default(),
            browser_queue: Arc::new(call_queue::ConversationQueue::default()),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health: Arc::new(HealthState::default()),
            routes: Arc::new(RouteBindings::new()),
            browser: Arc::new(BrowserPlane::new()),
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            user_browser: user_browser_bridge::UserBrowserBridge::new(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
                consent_drain::UnconfiguredCingulate,
            ))),
            consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
            user_browser_cards: Arc::default(),
            #[cfg(test)]
            consent_test: None,
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            route_test_handler: None,
            cursor_for_test: None,
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: None,
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            call_record_workers: Arc::new(CallRecordWorkers::default()),
            egress_deadlines: Arc::new(ConnectionDeadlines::default()),
            scopes: Arc::new(scope_watch::ScopeRevocation::default()),
        };
        for ty in [FrameType::Response, FrameType::Error] {
            let answer = Frame::build(
                ty,
                Flags::new(false, Priority::Interactive, false),
                4,
                1,
                9_999,
                br#"{"decision":"allow"}"#.to_vec(),
            )
            .unwrap();
            let keep_going = handle_frame(answer, &writer_tx, &planes)
                .await
                .expect("an unsolicited answer is handled");
            assert!(keep_going, "an unsolicited {ty:?} closed the connection");
            assert!(
                writer_rx.try_recv().is_err(),
                "an unsolicited {ty:?} was answered"
            );
        }
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
    async fn a_management_route_without_an_agent_session_gets_no_browser_grant_question() {
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
    async fn browser_import_login_refuses_without_an_agent_session() {
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
        assert_eq!(body["outcome"], "consent_unavailable", "{body}");
        assert_eq!(body["detail"]["reason"], "no_agent_session", "{body}");
        assert_eq!(
            body["remedy"],
            "call from the agent session that needs the permission; it can raise the card",
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
    pub(super) fn capture_planes(fixture: &login_capture::test_support::Fixture) -> Planes {
        let mut planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::default()),
            None,
            JournalPersistence::Isolated,
        );
        planes.capture = Arc::clone(&fixture.module);
        planes.browser_config = Some(Planes::short_test_browser_config());
        let admission = json!({
            "agentProjectId": "test-project",
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": ["browser.capture_login"],
        });
        planes.routes.insert(
            4,
            1,
            AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                session_caller_principal_for_test(),
                Some(&admission),
                Some(&["elicitation".to_string()]),
                &subc_protocol::RouteTarget::ToolProvider {
                    module_id: "cerebellum".to_string(),
                },
            ),
        );
        computer_grants::tests::CardService::install(planes, 4, 1)
    }

    pub(super) fn capture_request_frame(correlation: u64, params: Value) -> Frame {
        let mut arguments = params;
        arguments["action"] = json!("capture_login");
        Frame::build_with_version(
            subc_protocol::PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            4,
            1,
            correlation,
            serde_json::to_vec(&json!({
                "name": flat_tools::BROWSER_USE,
                "call_key": format!("pf:capture-{correlation}"),
                "arguments": arguments,
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
        tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .expect("the capture answers promptly")
            .expect("the writer stays open")
    }

    /// One test's Cingulate and consent registry: a scripted Cingulate and a
    /// registry file of the test's own, so planes can be built again over the
    /// same file and the same Cingulate, as a restarted module would be.
    pub(super) struct ScriptedConsent {
        pub(super) script: Arc<cingulate_client::ScriptedCingulate>,
        dir: PathBuf,
    }

    impl ScriptedConsent {
        pub(super) fn new() -> Self {
            static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
            let dir = std::env::temp_dir().join(format!(
                "scripted-consent-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self {
                script: cingulate_client::ScriptedCingulate::new().accept_execution_reports(),
                dir,
            }
        }

        pub(super) fn store(&self) -> cingulate_client::desk::FileRegistryStore {
            cingulate_client::desk::FileRegistryStore::new(self.dir.join("cingulate_raised.json"))
        }

        /// `planes` with their consent desk raising cards with the script and
        /// keeping its registry in the test's file, and the route at
        /// `channel` bound to an admitted agent session.
        pub(super) fn wire(&self, planes: Planes, channel: u16, epoch: u32) -> Planes {
            let planes =
                planes.with_cingulate(Arc::new(Arc::clone(&self.script)), Arc::new(self.store()));
            let facts = planes.routes.get(channel, epoch).unwrap();
            planes.routes.insert(
                channel,
                epoch,
                facts.with_scope(Some(computer_grants::tests::stamp("test-project"))),
            );
            planes
        }

        /// Planes running the fixture's capture module behind the production
        /// frame dispatcher, on the route at channel 4. Each call builds them
        /// anew over the same registry.
        fn planes(&self, fixture: &login_capture::test_support::Fixture) -> Planes {
            let mut planes = Planes::with_browser_config_journaling(
                Arc::new(HealthState::default()),
                None,
                JournalPersistence::Isolated,
            );
            planes.capture = Arc::clone(&fixture.module);
            planes.browser_config = Some(Planes::short_test_browser_config());
            let admission = json!({
                "agentProjectId": "test-project",
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"],
                "browserControlOperations": ["browser.capture_login"],
            });
            planes.routes.insert(
                4,
                1,
                AcceptedBindFacts::from_bind(
                    &bind_identity_for_test(),
                    session_caller_principal_for_test(),
                    Some(&admission),
                    None,
                    &subc_protocol::RouteTarget::ToolProvider {
                        module_id: "cerebellum".to_string(),
                    },
                ),
            );
            self.wire(planes, 4, 1)
        }

        /// Cingulate raises the next card under `id`.
        pub(super) fn raises(&self, id: &str) -> &Self {
            self.script.then(
                cingulate_client::wire::CONSENT_REQUEST,
                cingulate_client::Reply::Result(json!({"elicitation_id": id})),
            );
            self
        }

        /// The person answers `choice` while the call holds card `id`.
        fn answered_in_call(&self, id: &str, choice: &str) -> &Self {
            self.script.then(
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::Reply::Result(
                    json!({"elicitation_id": id, "state": "answered", "answered_choice_id": choice}),
                ),
            );
            self
        }

        /// Card `id` is still open when the call stops holding it, and is
        /// detached.
        pub(super) fn unanswered(&self, id: &str) -> &Self {
            self.script
                .then(
                    cingulate_client::wire::CONSENT_AWAIT,
                    cingulate_client::Reply::Result(
                        json!({"elicitation_id": id, "state": "pending"}),
                    ),
                )
                .then(
                    cingulate_client::wire::CONSENT_DETACH,
                    cingulate_client::Reply::Result(
                        json!({"elicitation_id": id, "state": "pending", "detached": true}),
                    ),
                );
            self
        }

        /// The session's next call reads `records` from the answers feed and
        /// acknowledges them.
        pub(super) fn feed(&self, records: Value) -> &Self {
            self.script
                .then(
                    cingulate_client::wire::CONSENT_ANSWERS,
                    cingulate_client::Reply::Result(json!({"records": records, "cursor": 1})),
                )
                .then(
                    cingulate_client::wire::CONSENT_ACK,
                    cingulate_client::Reply::Result(json!({"cursor": 1})),
                );
            self
        }

        /// Cingulate takes a report of what became of approved card `id`.
        pub(super) fn takes_report(&self, id: &str) -> &Self {
            self.script.then(
                cingulate_client::wire::CONSENT_REPORT_EXECUTION,
                cingulate_client::Reply::Result(
                    json!({"elicitation_id": id, "state": "answered", "answered_choice_id": "allow"}),
                ),
            );
            self
        }

        pub(super) fn methods(&self) -> Vec<String> {
            self.script.methods()
        }

        /// The cards raised so far, as `consent.request` params.
        pub(super) fn cards(&self) -> Vec<Value> {
            self.script
                .calls()
                .into_iter()
                .filter(|(method, _)| method == cingulate_client::wire::CONSENT_REQUEST)
                .map(|(_, params)| params)
                .collect()
        }
    }

    impl Drop for ScriptedConsent {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    pub(super) fn late_answer(id: &str, choice: &str) -> Value {
        json!([{"elicitation_id": id, "state": "answered", "answered_choice_id": choice}])
    }

    /// Consent uses Cingulate's card service, not the incoming request route;
    /// that route receives only the initial reply, not the later settlement.
    async fn capture_initial_reply(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
        corr: u64,
        params: Value,
    ) -> Value {
        handle_frame(capture_request_frame(corr, params), writer, planes)
            .await
            .unwrap();
        let frame = next_frame(rx).await;
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(
            frame.header.ty,
            FrameType::Response,
            "a frame other than the reply reached the route: {body}"
        );
        assert_eq!(frame.header.corr, corr);
        body
    }

    async fn capture_reply(
        planes: &Planes,
        writer: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
        corr: u64,
        params: Value,
    ) -> Value {
        let credential_id = params["credential_domain"]
            .as_str()
            .zip(params["account"].as_str())
            .map(|(domain, account)| format!("cookie:{domain}:{account}"));
        let captured_before = match credential_id.as_deref() {
            Some(id) => capture_audit_tests::captured_count(planes, id).await,
            None => 0,
        };
        let body = capture_initial_reply(planes, writer, rx, corr, params).await;
        if body["outcome"] == "capture_pending" {
            let late = capture_stored_late(planes, corr).await;
            // Consent tests need the finished deposit and disposal result,
            // not merely confirmation that the sign-in window was handed over.
            let result = late["result"].clone();
            if result["outcome"] == "captured" {
                // Late results intentionally publish before the asynchronous
                // audit write. Wait for this capture's new row, not a row left
                // by an earlier successful request for the same credential.
                capture_audit_tests::wait_for_new_capture(
                    planes,
                    credential_id
                        .as_deref()
                        .expect("a captured request names a credential"),
                    captured_before,
                )
                .await;
            }
            result
        } else {
            body
        }
    }

    async fn capture_provider_op(
        planes: &Planes,
        channel: u16,
        name: &str,
        arguments: Value,
    ) -> Value {
        let mut arguments = arguments;
        if name == "late_results" {
            arguments["since"] = Value::Null;
        }
        let mut frame = capture_request_frame(90_000, ollama_capture_params());
        frame.header.channel = channel;
        frame.body = serde_json::to_vec(&json!({"name":name,"arguments":arguments})).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(frame, &tx, planes).await.unwrap();
        let reply = next_frame(&mut rx).await;
        assert_eq!(reply.header.ty, FrameType::Response);
        let reply: Value = serde_json::from_slice(&reply.body).unwrap();
        reply.get("structuredContent").cloned().unwrap_or(reply)
    }

    pub(super) async fn capture_late(planes: &Planes, corr: u64) -> Value {
        capture_stored_late(planes, corr).await;
        let reply = capture_provider_op(planes, 4, "late_results", json!({})).await;
        reply["entries"]
            .as_array()
            .expect("late-results serves entries")
            .iter()
            .find(|entry| entry["call_key"] == format!("pf:capture-{corr}"))
            .expect("the provider serves the stored settlement")
            .clone()
    }

    async fn capture_stored_late(planes: &Planes, corr: u64) -> Value {
        let principal = journal::call_records::principal_label(
            planes.routes.get(4, 1).unwrap().principal.as_ref(),
        );
        // Wait on CallRecords first: a late_results request also reads the
        // consent answer feed, which must not race the scripted Cingulate
        // report that a consumed approval was executed.
        tokio::time::timeout(HANG_GUARD, async {
            loop {
                let reply = planes
                    .calls
                    .late_results(
                        &principal,
                        &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
                        wall_clock_ms(),
                    )
                    .unwrap();
                let reply = serde_json::to_value(reply).unwrap();
                if let Some(entry) = reply["entries"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|entry| entry["call_key"] == format!("pf:capture-{corr}"))
                {
                    break entry.clone();
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the handed-over capture settles")
    }

    async fn interrupt_capture(planes: &Planes, corr: u64) {
        planes
            .draining
            .store(true, std::sync::atomic::Ordering::Release);
        let principal = journal::call_records::principal_label(
            planes.routes.get(4, 1).unwrap().principal.as_ref(),
        );
        tokio::time::timeout(HANG_GUARD, async {
            loop {
                let reply = planes
                    .calls
                    .late_results(
                        &principal,
                        &cortexkit_role_tool_provider::late_results::LateResultsRequest::new(),
                        wall_clock_ms(),
                    )
                    .unwrap();
                if reply
                    .entries
                    .iter()
                    .any(|entry| entry.call_key == format!("pf:capture-{corr}"))
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("drain disposes and settles the capture");
        // A draining dispatcher admits no new pulls. Resume fixture admission
        // only after the background capture has observed the drain and ended.
        planes
            .draining
            .store(false, std::sync::atomic::Ordering::Release);
    }

    fn this_session() -> cingulate_client::live_call::SessionKey {
        computer_grants::tests::session_key("test-project")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_returns_pending_without_waiting_for_sign_in() {
        // The handoff lasts ten hang guards while the call is allowed one: a
        // reply that waits for sign-in cannot arrive under load before this
        // guard, so the outcome still proves the call handed off promptly.
        let fixture = login_capture::test_support::fixture_with(|env| {
            env.handoff_duration = HANG_GUARD * 10;
            env.poll_interval = Duration::from_millis(20);
        });
        fixture.launcher.script.lock().unwrap().logs_in = false;
        let cingulate = ScriptedConsent::new();
        cingulate
            .raises("el_cap_prompt")
            .answered_in_call("el_cap_prompt", "allow");
        let planes = cingulate.planes(&fixture);
        let (tx, mut rx) = mpsc::channel(8);
        let reply = tokio::time::timeout(
            HANG_GUARD,
            capture_initial_reply(&planes, &tx, &mut rx, 340, ollama_capture_params()),
        )
        .await
        .expect("consent was answered; sign-in must not hold the call");
        assert_eq!(reply["outcome"], "capture_pending", "{reply}");
        assert_eq!(reply["origin"], "https://ollama.com");
        assert_eq!(reply["expires_in_ms"], (HANG_GUARD * 10).as_millis() as u64);
        assert!(reply["message"]
            .as_str()
            .unwrap()
            .contains("notice; do not poll"));
        assert_eq!(
            cingulate.methods().len(),
            2,
            "consent still completes in-call"
        );
        assert_eq!(fixture.vault.calls(), 0);
        let placement = fixture.launcher.placements.lock().unwrap()[0].clone();
        assert!(fixture.fs.exists(placement.profile_directory()));
        assert!(
            capture_provider_op(&planes, 4, "late_results", json!({})).await["entries"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        interrupt_capture(&planes, 340).await;
        assert_eq!(
            capture_late(&planes, 340).await["result"]["outcome"],
            "handoff_interrupted"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_late_entries_cover_all_endings_ack_and_custodian_isolation() {
        use login_capture::test_support::{fixture_with, ScriptedVerification};
        for (corr, expected) in [
            (341, "captured"),
            (342, "session_invalid"),
            (343, "expired"),
            (344, "handoff_interrupted"),
        ] {
            let fixture = fixture_with(|env| {
                env.handoff_duration = Duration::from_millis(150);
                env.poll_interval = Duration::from_millis(10);
            });
            {
                let mut script = fixture.launcher.script.lock().unwrap();
                if expected == "session_invalid" {
                    script.verifications = vec![ScriptedVerification::redirected_off_origin()];
                } else if expected != "captured" {
                    script.logs_in = false;
                }
            }
            let cingulate = ScriptedConsent::new();
            cingulate
                .raises("el_cap_end")
                .answered_in_call("el_cap_end", "allow");
            let planes = cingulate.planes(&fixture);
            let facts = planes.routes.get(4, 1).unwrap();
            planes.routes.insert(5, 1, AcceptedBindFacts::from_bind(
                &bind_identity_for_test(),
                Some(subc_protocol::Principal::Reserved { module_id: "prefrontal-routing".into() }),
                Some(&json!({"agentProjectId":"test-project","sessionKind":"primary","effectiveCapabilityScope":["*"]})),
                None,
                &subc_protocol::RouteTarget::ToolProvider { module_id: "cerebellum".into() },
            ).with_scope(facts.scope.clone()));
            let (tx, mut rx) = mpsc::channel(8);
            let reply =
                capture_initial_reply(&planes, &tx, &mut rx, corr, ollama_capture_params()).await;
            assert_eq!(reply["outcome"], "capture_pending", "{reply}");
            if expected == "handoff_interrupted" {
                interrupt_capture(&planes, corr).await;
            }
            let entry = capture_late(&planes, corr).await;
            assert_eq!(
                entry["result"],
                json!({"outcome":expected,"origin":"https://ollama.com"})
            );
            assert_eq!(entry["kind"], "result");
            assert_eq!(
                entry["custodian"],
                journal::call_records::principal_label(facts.principal.as_ref())
            );
            assert_eq!(entry["call_key"], format!("pf:capture-{corr}"));
            assert!(entry["settled_at"].as_u64().unwrap() > 0);
            browser::validate_browser_result(management::CAPTURE_LOGIN, &entry["result"]).unwrap();
            assert!(
                capture_provider_op(&planes, 5, "late_results", json!({})).await["entries"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "another custodian received the capture result"
            );
            let all = capture_provider_op(&planes, 4, "late_results", json!({})).await;
            assert_eq!(
                capture_provider_op(
                    &planes,
                    4,
                    "late_results.ack",
                    json!({"through":all["cursor"]})
                )
                .await,
                json!({})
            );
            assert!(
                capture_provider_op(&planes, 4, "late_results", json!({})).await["entries"]
                    .as_array()
                    .unwrap()
                    .is_empty(),
                "ack must remove the entry"
            );
            let replay =
                capture_initial_reply(&planes, &tx, &mut rx, corr, ollama_capture_params()).await;
            assert_eq!(
                replay["outcome"], expected,
                "an acknowledged call must not recreate a pending capture"
            );
            assert_eq!(
                fixture
                    .launcher
                    .launches
                    .load(std::sync::atomic::Ordering::Acquire),
                1
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_v4_floor_is_lazy_and_present_remains_v3() {
        use cerebellum_core::format_floor::{read_floors, DurableFormat, FormatFloor};
        use journal::call_records::{
            Begin, CallRecords, FilesystemCallRecordStorage, ScopeIdentity,
        };
        let fixture = login_capture::test_support::fixture();
        fixture.launcher.script.lock().unwrap().logs_in = false;
        let cingulate = ScriptedConsent::new();
        cingulate
            .raises("el_cap_floor")
            .answered_in_call("el_cap_floor", "allow");
        let path = cingulate.dir.join("call_records.jsonl");
        let floor_path = cingulate.dir.join("format-floor.json");
        let mut planes = cingulate.planes(&fixture);
        planes.calls = Arc::new(CallRecords::open(
            Box::new(
                FilesystemCallRecordStorage::new(path.clone())
                    .with_format_floor(FormatFloor::at(&floor_path)),
            ),
            wall_clock_ms(),
        ));
        assert!(!path.exists());
        assert!(
            !floor_path.exists(),
            "starting the build must not close rollback"
        );
        let facts = planes.routes.get(4, 1).unwrap();
        let principal = journal::call_records::principal_label(facts.principal.as_ref());
        assert!(matches!(
            planes.calls.begin(
                &principal,
                "pf:present-only",
                &facts.identity.conversation_key,
                wall_clock_ms()
            ),
            Begin::Execute(_)
        ));
        assert_eq!(
            read_floors(&floor_path).unwrap().get("call-records"),
            Some(&2)
        );
        planes
            .calls
            .hold_handoff(
                &principal,
                "pf:present-only",
                &facts.identity.conversation_key,
                ScopeIdentity::from_stamp(facts.scope.as_ref().unwrap()),
                "https://ollama.com",
                wall_clock_ms(),
            )
            .unwrap();
        let present_only = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            present_only.lines().next(),
            Some("{\"format\":\"call-records\",\"version\":3}")
        );
        assert_eq!(
            read_floors(&floor_path).unwrap().get("call-records"),
            Some(&3)
        );
        assert!(!present_only.contains("\"capture\""));
        let (tx, mut rx) = mpsc::channel(8);
        assert_eq!(
            capture_initial_reply(&planes, &tx, &mut rx, 347, ollama_capture_params()).await
                ["outcome"],
            "capture_pending"
        );
        let captured = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            captured.lines().next(),
            Some("{\"format\":\"call-records\",\"version\":4}")
        );
        assert!(captured.contains("\"capture\":true"));
        assert_eq!(
            read_floors(&floor_path).unwrap().get("call-records"),
            Some(&4)
        );
        let header: Value = serde_json::from_str(captured.lines().next().unwrap()).unwrap();
        assert!(
            DurableFormat::new("call-records", 3)
                .refuse_newer(header["version"].as_u64().unwrap())
                .is_err(),
            "a v3 reader must refuse before decoding capture state"
        );
        assert!(crate::durable_formats::readable_formats()
            .contains(&journal::call_records::CALL_RECORD_FORMAT));
        interrupt_capture(&planes, 347).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_restart_settles_interrupted_and_preserves_retention_and_format() {
        use journal::call_records::{CallRecords, FilesystemCallRecordStorage};
        let fixture = login_capture::test_support::fixture();
        fixture.launcher.script.lock().unwrap().logs_in = false;
        let cingulate = ScriptedConsent::new();
        cingulate
            .raises("el_cap_restart")
            .answered_in_call("el_cap_restart", "allow");
        let path = cingulate.dir.join("call_records.jsonl");
        let store = || {
            CallRecords::open(
                Box::new(FilesystemCallRecordStorage::new(path.clone())),
                wall_clock_ms(),
            )
        };
        let mut planes = cingulate.planes(&fixture);
        planes.calls = Arc::new(store());
        // Merely opening capture-capable planes does not write new state.
        assert!(!path.exists());
        let (tx, mut rx) = mpsc::channel(8);
        assert_eq!(
            capture_initial_reply(&planes, &tx, &mut rx, 345, ollama_capture_params()).await
                ["outcome"],
            "capture_pending"
        );
        let persisted = std::fs::read_to_string(&path).unwrap();
        assert!(
            persisted
                .lines()
                .any(|line| serde_json::from_str::<Value>(line).unwrap()["version"] == 4),
            "{persisted}"
        );
        assert!(!login_capture::test_support::contains_bytes(
            &persisted.into_bytes(),
            login_capture::test_support::PLANTED_VALUE
        ));
        let mut restarted = cingulate.planes(&fixture);
        restarted.calls = Arc::new(store());
        let entry = capture_late(&restarted, 345).await;
        assert_eq!(entry["result"]["outcome"], "handoff_interrupted");
        let principal = journal::call_records::principal_label(
            restarted.routes.get(4, 1).unwrap().principal.as_ref(),
        );
        let settled_at = entry["settled_at"].as_u64().unwrap();
        let request = cortexkit_role_tool_provider::late_results::LateResultsRequest::new();
        let before = restarted
            .calls
            .late_results(&principal, &request, settled_at + 24 * 60 * 60 * 1_000 - 1)
            .unwrap();
        assert_eq!(before.entries[0].kind, "result");
        let after = restarted
            .calls
            .late_results(&principal, &request, settled_at + 24 * 60 * 60 * 1_000 + 1)
            .unwrap();
        assert_eq!(after.entries[0].kind, "expired");
        assert!(after.entries[0].result.is_none());
        interrupt_capture(&planes, 345).await;
        capture_late(&planes, 345).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unkeyed_capture_is_refused_before_consent_or_browser_launch() {
        let fixture = login_capture::test_support::fixture();
        let cingulate = ScriptedConsent::new();
        let planes = cingulate.planes(&fixture);
        let mut frame = capture_request_frame(346, ollama_capture_params());
        let mut body: Value = serde_json::from_slice(&frame.body).unwrap();
        body.as_object_mut().unwrap().remove("call_key");
        frame.body = serde_json::to_vec(&body).unwrap();
        let (tx, mut rx) = mpsc::channel(8);
        handle_frame(frame, &tx, &planes).await.unwrap();
        let reply: Value = serde_json::from_slice(&next_frame(&mut rx).await.body).unwrap();
        assert_eq!(reply["outcome"], "invalid_request");
        assert_eq!(reply["detail"]["field"], "call_key");
        assert!(reply["detail"]["remedy"]
            .as_str()
            .unwrap()
            .contains("result arrives later"));
        assert!(cingulate.methods().is_empty());
        assert_eq!(
            fixture
                .launcher
                .launches
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );
    }

    #[tokio::test]
    async fn capture_login_without_live_carrier_refuses_before_readiness_or_effects() {
        use login_capture::test_support::{fixture, fixture_without_launcher};
        use std::sync::atomic::Ordering;

        for configured in [false, true] {
            let fixture = if configured {
                fixture()
            } else {
                fixture_without_launcher()
            };
            let cingulate = ScriptedConsent::new();
            let planes = cingulate.planes(&fixture);
            let admitted = planes.routes.get(4, 1).unwrap();
            assert!(computer_grants::admits_consent(&admitted));
            let facts = admitted.clone().with_scope(None);
            planes.routes.insert(4, 1, facts);
            let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
            let reply = capture_initial_reply(
                &planes,
                &writer_tx,
                &mut writer_rx,
                401,
                ollama_capture_params(),
            )
            .await;

            // A call without an admitted agent session gets the same refusal
            // whether or not a browser executable is configured; it cannot ask
            // the person to approve it.
            assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
            assert_eq!(reply["detail"]["reason"], "no_agent_session", "{reply}");

            // An admitted route is not sufficient after its call has ended. The
            // frame dispatcher normally installs an in-flight guard; invoking
            // this production handler without it exercises RouteCarrier::live's
            // CallEnded refusal before browser configuration is examined.
            planes.routes.insert(4, 1, admitted.clone());
            let request = login_capture::CaptureRequest {
                credential_domain: "ollama.com".into(),
                account: "work".into(),
                fetch_url: "https://ollama.com/settings".into(),
                login_url: "https://ollama.com/login".into(),
            };
            let consent = login_consent_request(
                &planes,
                &admitted,
                &writer_tx,
                (4, 1),
                computer_grants::LoginCapability::CaptureLogin,
                request.consent_parameters(),
                None,
            );
            assert!(matches!(
                consent.carrier.live(),
                Err(cingulate_client::live_call::NotLive::CallEnded)
            ));
            let reply = capture_browser_login(
                &planes,
                &admitted,
                &writer_tx,
                (4, 1, 402),
                &request,
                "ended-capture-call",
            )
            .await;
            assert_eq!(reply["outcome"], "consent_unavailable", "{reply}");
            assert!(cingulate.methods().is_empty());
            assert_eq!(cingulate.script.opens(), 0);
            assert_eq!(fixture.launcher.launches.load(Ordering::SeqCst), 0);
            assert_eq!(fixture.vault.opens.load(Ordering::SeqCst), 0);
            assert!(fixture.vault.requests.lock().unwrap().is_empty());
            assert!(fixture.fs.contents().is_empty());
            assert!(fixture.events.snapshot().is_empty());
        }
    }

    /// Through the production frame dispatcher and the Withhold reply boundary:
    /// the planted cookie value reaches the vault request, and is absent from
    /// the card put to the person, the pending reply, the late entry and every
    /// decoded journal entry.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_login_keeps_the_value_out_of_the_reply_the_journal_and_the_ask() {
        use login_capture::test_support::{contains_bytes, fixture, PLANTED_VALUE};

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate
            .raises("el_cap_301")
            .answered_in_call("el_cap_301", "allow");
        let mut planes = cingulate.planes(&fixture);
        let call_record_path = cingulate.dir.join("call_records.jsonl");
        planes.calls = Arc::new(journal::call_records::CallRecords::open(
            Box::new(journal::call_records::FilesystemCallRecordStorage::new(
                call_record_path.clone(),
            )),
            wall_clock_ms(),
        ));
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let journal_finalized = planes.capture.expect_journal_finalization();
        let body = capture_initial_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            301,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "capture_pending", "{body}");
        let late = capture_late(&planes, 301).await;
        assert_eq!(late["result"]["outcome"], "captured", "{late}");
        assert_eq!(
            cingulate.methods(),
            [
                cingulate_client::wire::CONSENT_REQUEST,
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::wire::CONSENT_REPORT_EXECUTION
            ]
        );
        let asked = cingulate.cards().remove(0);
        assert_eq!(
            asked["prompt"],
            "insula will hold a copy of your ollama.com login."
        );
        // The Cingulate card id becomes the deposit's consent reference.
        assert_eq!(
            fixture.vault.request_params()[0]["consent_ref"],
            "el_cap_301"
        );
        assert!(planes.consent.unapplied(&this_session()).is_empty());

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
            !contains_bytes(&serde_json::to_vec(&asked).unwrap(), PLANTED_VALUE),
            "the card leaked it"
        );
        assert!(
            !contains_bytes(&serde_json::to_vec(&body).unwrap(), PLANTED_VALUE),
            "the reply leaked it"
        );
        assert!(
            !contains_bytes(&serde_json::to_vec(&late).unwrap(), PLANTED_VALUE),
            "the late entry leaked it"
        );
        assert!(
            !contains_bytes(&std::fs::read(call_record_path).unwrap(), PLANTED_VALUE),
            "the call-record journal leaked it"
        );
        // The late result deliberately precedes the detached audit write.
        tokio::time::timeout(HANG_GUARD, journal_finalized)
            .await
            .expect("the capture audit finishes")
            .expect("the capture signals its audit finalization");
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

    /// A successful settlement leaves only after the throwaway profile is
    /// gone, even when deletion is slower than handing over the window.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn capture_settlement_is_served_only_after_the_profile_is_deleted() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        *fixture.fs.removal_delay.lock().unwrap() = Duration::from_millis(200);
        let cingulate = ScriptedConsent::new();
        cingulate
            .raises("el_cap_302")
            .answered_in_call("el_cap_302", "allow");
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let body = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            302,
            ollama_capture_params(),
        )
        .await;
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

    /// A cancel frame for the request, arriving while the card is open, ends
    /// the capture with nothing written. The card is detached rather than
    /// withdrawn, since the conversation is still there: the person may still
    /// answer it, and that answer is kept for a retry rather than acted on.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancel_during_consent_ends_the_capture_and_leaves_its_card_open() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_303");
        cingulate
            .script
            .then(
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::Reply::Hang,
            )
            .then(
                cingulate_client::wire::CONSENT_DETACH,
                cingulate_client::Reply::Result(
                    json!({"elicitation_id": "el_cap_303", "state": "pending", "detached": true}),
                ),
            );
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let request = capture_request_frame(303, ollama_capture_params());
        handle_frame_for_test(request.clone(), &writer_tx, &planes)
            .await
            .unwrap();
        tokio::time::timeout(HANG_GUARD, async {
            while cingulate.methods().len() < 2 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the call waits on its card");
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
        handle_frame_for_test(cancel.clone(), &writer_tx, &planes)
            .await
            .unwrap();
        let reply = next_frame(&mut writer_rx).await;
        let body: Value = serde_json::from_slice(&reply.body).unwrap();
        assert_eq!(body, json!({"context":null,"outcome":"cancelled"}));
        crate::turn_stop_vectors::check(
            "capture-login-card",
            "parked awaiting the 30-minute capture card before login handoff",
            &request,
            &cancel,
            Some(&reply),
        );
        tokio::time::timeout(HANG_GUARD, async {
            while cingulate.methods().len() < 3 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the cancelled call lets go of its card");
        assert_eq!(
            cingulate.methods(),
            [
                cingulate_client::wire::CONSENT_REQUEST,
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::wire::CONSENT_DETACH
            ]
        );
        // The card outlives the cancelled call, so an answer to it is still
        // received; it is remembered, and nothing runs on it.
        assert_eq!(
            planes.consent.unapplied(&this_session()).len(),
            1,
            "the cancelled capture closed its card"
        );
        cingulate.feed(late_answer("el_cap_303", "allow"));
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

    /// Which part of a cancelled capture finishes first, named for that part.
    #[derive(Clone, Copy, Debug)]
    enum CaptureCancelOrdering {
        /// The capture's own polling notices the cancel and ends the capture
        /// while Cingulate is still answering the card's detach.
        CapturePoll,
        /// The card wait, woken by the same cancel, ends the capture as soon
        /// as the detach is answered, before the capture's polling runs.
        ConsentWait,
        /// The turn stop sends its reply when its cleanup time runs out, and
        /// the capture ends only afterwards.
        TurnStop,
    }

    /// A capture_login cancelled while its card is open is answered with the
    /// turn-stop vector's bytes, exactly once, whichever part of the call
    /// finishes first, and the capture records itself as cancelled. Each
    /// ordering is forced: the test holds Cingulate's detach reply, and time
    /// is paused, so the capture's polling and the turn stop's cleanup
    /// deadline run only when every task is waiting.
    #[tokio::test(start_paused = true)]
    async fn a_cancelled_capture_sends_the_turn_stop_bytes_in_every_ordering() {
        use login_capture::test_support::fixture;

        for ordering in [
            CaptureCancelOrdering::CapturePoll,
            CaptureCancelOrdering::ConsentWait,
            CaptureCancelOrdering::TurnStop,
        ] {
            let fixture = fixture();
            let cingulate = ScriptedConsent::new();
            let (detach_called, detach_started) = tokio::sync::oneshot::channel();
            let (detach_reply, detach_response) = tokio::sync::oneshot::channel();
            cingulate.raises("el_cap_303");
            cingulate
                .script
                .then(
                    cingulate_client::wire::CONSENT_AWAIT,
                    cingulate_client::Reply::Hang,
                )
                .then(
                    cingulate_client::wire::CONSENT_DETACH,
                    cingulate_client::Reply::Controlled {
                        called: detach_called,
                        reply: detach_response,
                    },
                );
            let planes = cingulate.planes(&fixture);
            let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
            let request = capture_request_frame(303, ollama_capture_params());
            handle_frame_for_test(request.clone(), &writer_tx, &planes)
                .await
                .unwrap();
            tokio::time::timeout(HANG_GUARD, async {
                while cingulate.methods().len() < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the call waits on its card");
            let cancel = crate::turn_stop_vectors::cancel(&request);
            handle_frame_for_test(cancel.clone(), &writer_tx, &planes)
                .await
                .unwrap();
            tokio::time::timeout(HANG_GUARD, detach_started)
                .await
                .expect("the cancel detaches the card")
                .unwrap();
            let detached =
                json!({"elicitation_id": "el_cap_303", "state": "pending", "detached": true});
            let reply = match ordering {
                CaptureCancelOrdering::CapturePoll => {
                    // Paused time moves only while every task waits, so the
                    // capture's polling (every millisecond in this fixture)
                    // sees the cancel before the detach is answered.
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    detach_reply.send(detached).unwrap();
                    next_frame(&mut writer_rx).await
                }
                CaptureCancelOrdering::ConsentWait => {
                    // No time passes, so the polling timer cannot fire: the
                    // answered detach is what ends the capture.
                    detach_reply.send(detached).unwrap();
                    next_frame(&mut writer_rx).await
                }
                CaptureCancelOrdering::TurnStop => {
                    let reply = next_frame(&mut writer_rx).await;
                    assert!(
                        planes.browser.journal_export_for_test().await.is_empty(),
                        "the capture ended before the turn stop replied"
                    );
                    detach_reply.send(detached).unwrap();
                    reply
                }
            };
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(
                body,
                json!({"context":null,"outcome":"cancelled"}),
                "{ordering:?}"
            );
            crate::turn_stop_vectors::check(
                "capture-login-card",
                "parked awaiting the 30-minute capture card before login handoff",
                &request,
                &cancel,
                Some(&reply),
            );
            // The capture journals how it ended as its last step, so once the
            // entry is there the capture has finished and sent all it will.
            let export = tokio::time::timeout(HANG_GUARD, async {
                loop {
                    let export = planes.browser.journal_export_for_test().await;
                    if !export.is_empty() {
                        break export;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the cancelled capture ends");
            let entries = export
                .lines()
                .map(|line| serde_json::from_str::<journal::JournalEntry>(line).unwrap())
                .collect::<Vec<_>>();
            assert_eq!(entries.len(), 1, "{ordering:?}: {export}");
            let Some(journal::JournalPayload::LoginCapture(payload)) = &entries[0].payload else {
                panic!("{ordering:?}: a capture is journaled with its own payload: {export}");
            };
            assert_eq!(payload.outcome, "cancelled", "{ordering:?}");
            for _ in 0..100 {
                tokio::task::yield_now().await;
            }
            assert!(
                writer_rx.try_recv().is_err(),
                "{ordering:?}: a cancelled capture was answered twice"
            );
            assert!(fixture.fs.contents().is_empty());
        }
    }

    /// Apply a late login answer through the session's next call, then check
    /// whether its approval or explicit refusal was remembered.
    async fn await_remembered(planes: &Planes, expected: bool) {
        computer_grants::tests::drain_call(planes, 4, 1).await;
        assert_eq!(
            planes.consent.has_single_use_approvals()
                || planes.management.computer_grants().remembers_login_answer(),
            expected
        );
    }

    /// Older consent servers receive the original thirty-minute deadline.
    /// Late approval can authorize a matching retry, not launch a capture itself.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_capture_card_is_sent_for_thirty_minutes_with_late_execution() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_310").unanswered("el_cap_310");
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let body = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            310,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "consent_pending", "{body}");
        let asked = cingulate.cards().remove(0);
        assert_eq!(asked["expires_in_ms"], 1_800_000, "{asked}");
        assert_eq!(asked["late_execution"], "execute", "{asked}");
    }

    /// Unanswered, the capture call holds the card for the park (Cingulate
    /// is asked to wait that long), then detaches it and replies
    /// `consent_pending` naming it. The card stays registered, so a later
    /// answer is still received.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_capture_replies_consent_pending_after_the_park_and_keeps_its_card() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_311").unanswered("el_cap_311");
        let planes = cingulate.planes(&fixture);
        assert_eq!(
            planes.management.computer_grants().login_park_limit(),
            Duration::from_secs(120)
        );
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let body = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            311,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "consent_pending", "{body}");
        assert_eq!(body["ask_id"], "el_cap_311", "{body}");
        assert_eq!(
            body["remedy"],
            computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
            "{body}"
        );
        assert_eq!(
            cingulate.methods(),
            [
                cingulate_client::wire::CONSENT_REQUEST,
                cingulate_client::wire::CONSENT_AWAIT,
                cingulate_client::wire::CONSENT_DETACH
            ]
        );
        let held_for = cingulate.script.calls()[1].1["timeout_ms"]
            .as_u64()
            .unwrap();
        assert!(
            (110_000..=120_000).contains(&held_for),
            "the call held its card for {held_for} ms, not the park"
        );
        assert_eq!(
            planes.consent.unapplied(&this_session()).len(),
            1,
            "the card was closed when the call returned"
        );
        assert!(fixture.fs.contents().is_empty());
    }

    /// An approval that arrives after the call returned is used by the next
    /// call with the same parameters, which captures without a second card,
    /// names the approved card as its consent, and tells Cingulate the
    /// approved capture ran before settlement. A call with other parameters
    /// does not use it, and once used it is gone.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_capture_approval_is_used_once_by_a_retry_with_the_same_parameters() {
        use cingulate_client::wire::{
            CONSENT_ACK, CONSENT_ANSWERS, CONSENT_AWAIT, CONSENT_DETACH, CONSENT_REPORT_EXECUTION,
            CONSENT_REQUEST,
        };
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_320").unanswered("el_cap_320");
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let first = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            320,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(first["outcome"], "consent_pending", "{first}");
        cingulate.feed(late_answer("el_cap_320", "allow"));
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
        cingulate.raises("el_cap_321").unanswered("el_cap_321");
        let second = capture_reply(&planes, &writer_tx, &mut writer_rx, 321, other).await;
        assert_eq!(second["ask_id"], "el_cap_321", "{second}");
        assert!(planes.consent.has_single_use_approvals());

        // The same parameters: the approval is taken, the capture runs, and
        // its execution is reported before settlement. The session's open
        // card for the other account makes this call read the answers feed
        // first, which has nothing new.
        cingulate.feed(json!([])).takes_report("el_cap_320");
        let before = cingulate.methods().len();
        let body = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            322,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "captured", "{body}");
        assert_eq!(
            cingulate.methods()[before..],
            [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_REPORT_EXECUTION],
            "a taken approval must be reported before settlement, with no second card"
        );
        assert_eq!(
            cingulate.script.calls().last().unwrap().1,
            json!({"elicitation_id":"el_cap_320", "execution":"executed"})
        );
        assert_eq!(
            fixture.vault.request_params()[0]["consent_ref"],
            "el_cap_320"
        );
        assert!(
            !(planes.consent.has_single_use_approvals()
                || planes.management.computer_grants().remembers_login_answer())
        );

        // Used once: the next call asks again.
        cingulate
            .feed(json!([]))
            .raises("el_cap_323")
            .unanswered("el_cap_323");
        let before = cingulate.methods().len();
        let again = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            323,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(again["outcome"], "consent_pending", "{again}");
        assert_eq!(
            cingulate.methods()[before..],
            [
                CONSENT_ANSWERS,
                CONSENT_ACK,
                CONSENT_REQUEST,
                CONSENT_AWAIT,
                CONSENT_DETACH
            ]
        );
        assert_eq!(fixture.vault.request_params().len(), 1);
    }

    /// A capture approval given after its call returned survives a module
    /// restart: the restarted module's next call on the session reads it
    /// from the answers feed, acknowledges it, uses it once and reports that
    /// the capture ran, all before it replies. A second restart has nothing
    /// left to apply and opens no route to Cingulate.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_capture_approval_survives_a_restart_and_is_applied_once() {
        use cingulate_client::desk::RegistryStore;
        use cingulate_client::wire::{CONSENT_ACK, CONSENT_ANSWERS, CONSENT_REPORT_EXECUTION};
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_360").unanswered("el_cap_360");
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        {
            let planes = cingulate.planes(&fixture);
            let first = capture_reply(
                &planes,
                &writer_tx,
                &mut writer_rx,
                360,
                ollama_capture_params(),
            )
            .await;
            assert_eq!(first["outcome"], "consent_pending", "{first}");
        }
        assert_eq!(cingulate.store().load().unwrap().len(), 1);

        // The person approves while the module is down.
        let restarted = cingulate.planes(&fixture);
        cingulate
            .feed(late_answer("el_cap_360", "allow"))
            .takes_report("el_cap_360");
        let before = cingulate.methods().len();
        let body = capture_reply(
            &restarted,
            &writer_tx,
            &mut writer_rx,
            361,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "captured", "{body}");
        assert_eq!(
            cingulate.methods()[before..],
            [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_REPORT_EXECUTION]
        );
        assert_eq!(
            cingulate.script.calls().last().unwrap().1,
            json!({"elicitation_id":"el_cap_360", "execution":"executed"})
        );
        assert_eq!(fixture.vault.request_params().len(), 1);
        assert_eq!(
            fixture.vault.request_params()[0]["consent_ref"],
            "el_cap_360"
        );
        assert!(cingulate
            .store()
            .load()
            .unwrap()
            .iter()
            .all(|card| card.applied && card.lifecycle.acked));
        assert!(!restarted.consent.has_single_use_approvals());

        let again = cingulate.planes(&fixture);
        let opens = cingulate.script.opens();
        computer_grants::tests::drain_call(&again, 4, 1).await;
        assert_eq!(cingulate.script.opens(), opens, "nothing was left to apply");
        assert!(!again.consent.has_single_use_approvals());
        assert_eq!(fixture.vault.request_params().len(), 1);
    }

    /// A refusal that arrives after the call returned refuses the retry
    /// with the same parameters as declined, without a second card.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_capture_refusal_declines_the_retry_without_a_card() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_330").unanswered("el_cap_330");
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let first = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            330,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(first["outcome"], "consent_pending", "{first}");
        cingulate.feed(late_answer("el_cap_330", "deny"));
        await_remembered(&planes, true).await;
        let before = cingulate.cards().len();
        let body = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            331,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "capture_consent_not_given", "{body}");
        assert_eq!(body["reason"], "deny", "{body}");
        assert_eq!(cingulate.cards().len(), before, "a second card was raised");
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
        use cingulate_client::wire::{CONSENT_ACK, CONSENT_ANSWERS, CONSENT_AWAIT, CONSENT_DETACH};
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_340").unanswered("el_cap_340");
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        let first = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            340,
            ollama_capture_params(),
        )
        .await;
        cingulate.feed(json!([])).unanswered("el_cap_340");
        let before = cingulate.methods().len();
        let second = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            341,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(second["outcome"], "consent_pending", "{second}");
        assert_eq!(second["ask_id"], first["ask_id"], "{second}");
        assert_eq!(
            cingulate.methods()[before..],
            [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_AWAIT, CONSENT_DETACH],
            "the retry raised a second card"
        );
        assert_eq!(planes.consent.unapplied(&this_session()).len(), 1);
        // The one card still answers the agent's next retry.
        cingulate.feed(late_answer("el_cap_340", "allow"));
        await_remembered(&planes, true).await;
    }

    /// Revoking the session scope drops an approval that arrived after its
    /// call returned, so the next call asks again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn scope_revocation_drops_a_late_capture_approval() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.raises("el_cap_350").unanswered("el_cap_350");
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(16);
        capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            350,
            ollama_capture_params(),
        )
        .await;
        cingulate.feed(late_answer("el_cap_350", "allow"));
        await_remembered(&planes, true).await;
        let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
        revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
        assert!(
            !(planes.consent.has_single_use_approvals()
                || planes.management.computer_grants().remembers_login_answer())
        );
        cingulate.raises("el_cap_351").unanswered("el_cap_351");
        let pending = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            351,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(pending["outcome"], "consent_pending", "{pending}");
        assert_eq!(fixture.vault.request_params().len(), 0);
        assert_eq!(planes.consent.unapplied(&this_session()).len(), 1);
        // The revocation also forgets a card still open, so its answer is
        // received by nothing, and it opens no route to Cingulate.
        let calls = cingulate.methods().len();
        let conversation = planes.routes.get(4, 1).unwrap().identity.conversation_key;
        revoke_scope(&planes, &std::collections::BTreeSet::from([conversation])).await;
        assert!(
            planes.consent.unapplied(&this_session()).is_empty(),
            "the open card was not forgotten"
        );
        assert_eq!(cingulate.methods().len(), calls);
        assert!(
            writer_rx.try_recv().is_err(),
            "revocation sends nothing on the route"
        );
        assert!(!planes
            .management
            .computer_grants()
            .question_open(pending["ask_id"].as_str().unwrap()));
    }

    /// When Cingulate refuses to raise the card (the requester is refused),
    /// the capture ends at once with `not_put_to_anyone`: nobody was shown
    /// the card, which is not the same as a person who saw it and stayed
    /// silent.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_requester_refusal_ends_the_capture_as_not_put_to_anyone() {
        use login_capture::test_support::fixture;

        let fixture = fixture();
        let cingulate = ScriptedConsent::new();
        cingulate.script.then(
            cingulate_client::wire::CONSENT_REQUEST,
            cingulate_client::Reply::Refused("elicitation_requester_refused"),
        );
        let planes = cingulate.planes(&fixture);
        let (writer_tx, mut writer_rx) = mpsc::channel::<Frame>(8);
        let body = capture_reply(
            &planes,
            &writer_tx,
            &mut writer_rx,
            304,
            ollama_capture_params(),
        )
        .await;
        assert_eq!(body["outcome"], "capture_consent_not_given", "{body}");
        assert_eq!(body["reason"], "not_put_to_anyone", "{body}");
        assert_eq!(
            cingulate.methods(),
            [cingulate_client::wire::CONSENT_REQUEST]
        );
        assert!(planes.consent.unapplied(&this_session()).is_empty());
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
            private_content: Arc::new(private_content::PrivateContent::in_memory()),
            signed_in: Arc::new(browser_signed_in::SignedInDomains::default()),
            cancellations: RequestCancellations::default(),
            run_calls: codemode::RunCalls::default(),
            browser_queue: Arc::new(call_queue::ConversationQueue::default()),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health: Arc::new(HealthState::default()),
            routes: Arc::new(RouteBindings::new()),
            browser: Arc::new(BrowserPlane::new()),
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            user_browser: user_browser_bridge::UserBrowserBridge::new(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
                consent_drain::UnconfiguredCingulate,
            ))),
            consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
            user_browser_cards: Arc::default(),
            #[cfg(test)]
            consent_test: None,
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            #[cfg(test)]
            route_test_handler: None,
            #[cfg(test)]
            cursor_for_test: None,
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            call_record_workers: Arc::new(CallRecordWorkers::default()),
            egress_deadlines: Arc::new(ConnectionDeadlines::default()),
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
            private_content: Arc::new(private_content::PrivateContent::in_memory()),
            signed_in: Arc::new(browser_signed_in::SignedInDomains::default()),
            cancellations: RequestCancellations::default(),
            run_calls: codemode::RunCalls::default(),
            browser_queue: Arc::new(call_queue::ConversationQueue::default()),
            #[cfg(target_os = "macos")]
            computer_admitted: test_admitted_computer_capabilities(),
            health: Arc::new(HealthState::default()),
            routes: Arc::new(RouteBindings::new()),
            browser: Arc::new(BrowserPlane::new()),
            browser_config: None,
            sessions: browser_session::BrowserSessions::default(),
            user_browser: user_browser_bridge::UserBrowserBridge::new(),
            lease_clock: Arc::new(cerebellum_core::clock::SystemClock::new()),
            launch_service: None,
            management: test_management_plane(),
            consent: Arc::new(cingulate_client::desk::ConsentDesk::new(Arc::new(
                consent_drain::UnconfiguredCingulate,
            ))),
            consent_drain: Arc::new(consent_drain::ConsentDrain::default()),
            user_browser_cards: Arc::default(),
            #[cfg(test)]
            consent_test: None,
            #[cfg(target_os = "macos")]
            computer: Err(computer_capability::ComputerPlaneUnavailable::CaptureCustody),
            #[cfg(test)]
            route_test_handler: None,
            #[cfg(test)]
            cursor_for_test: None,
            #[cfg(all(test, target_os = "macos"))]
            computer_for_test: None,
            draining: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            drain_signal: Arc::new(tokio::sync::watch::channel(false).0),
            drain_notice: Arc::new(std::sync::OnceLock::new()),
            capture: login_capture::test_support::fixture().module,
            calls: Arc::new(journal::call_records::CallRecords::in_memory()),
            call_record_workers: Arc::new(CallRecordWorkers::default()),
            egress_deadlines: Arc::new(ConnectionDeadlines::default()),
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
            app_use_fronting_review_revision: None,
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
                app_use_fronting_review_revision: None,
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
                app_use_fronting_review_revision: Some("fixture-app-use-fronting-review"),
                release_signing_topology_revision: Some("fixture-signing-topology"),
            }),
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let outcomes = computer_gate_outcomes(&context);
        assert_eq!(
            outcomes.into_values().collect::<Vec<_>>(),
            vec![ComputerGateOutcome::Pass; 15]
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn fixed_input_hello_manifest_bytes_match_pre_inspection_builder() {
        let context = ComputerCapabilityAdvertisementContext {
            inputs: release_inputs_from_build_bindings(fully_bound_release_bindings()),
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let provenance = subc_protocol::manifest::ManifestProvenance::new()
            .with_build_git_sha(Some("0123456789abcdef0123456789abcdef01234567".to_string()))
            .with_wire_crate_version(Some("0.32.4".to_string()));
        let value = compose_manifest(
            "manifest-fixture",
            &context,
            &BrowserSurface::NotConfigured,
            Some(provenance),
        );
        // Fixed bytes, not computed by the code under test: the Linux pin was
        // taken from the builder HELLO used before `--manifest` shared it, with
        // these inputs. The macOS manifest also includes computer_use's
        // description, so its pin changes whenever that text changes; when it
        // does, confirm the old and new builders differ only by that text
        // before taking the new value.
        #[cfg(target_os = "linux")]
        let expected = "76dbb08edce1bb7742f5efc2686b7e2ec42ad623586d16d91be1fbd52fa15662";
        #[cfg(target_os = "macos")]
        let expected = "33166b72e5c0aefea0f0f6ec91a764a66a83684096d09f39bc21bc0baedee21d";
        use sha2::Digest;
        assert_eq!(
            format!("{:x}", sha2::Sha256::digest(value.to_string().as_bytes())),
            expected
        );
    }

    /// A daemon linking subc-protocol 0.32.11 must keep accepting this module's
    /// HELLO. The 0.32.12 and 0.33 wire crates added two manifest maps
    /// (`operation_payload`, `role_declarations`) that the older parser does
    /// not know; both are left out of the encoding while empty. Declaring
    /// either one would send HELLO bytes the older daemon was never tested
    /// against, so the HELLO manifest, with and without a browser, carries
    /// neither key.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn hello_manifest_declares_no_map_an_older_daemon_does_not_know() {
        let context = ComputerCapabilityAdvertisementContext {
            inputs: release_inputs_from_build_bindings(fully_bound_release_bindings()),
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        for surface in [
            BrowserSurface::NotConfigured,
            BrowserSurface::Available(browser_surface_config()),
        ] {
            // The same builder `send_hello` places in the HELLO body.
            let manifest =
                serialize_manifest_with_computer_plane_configured("cerebellum", &context, &surface);
            let keys: Vec<&String> = manifest.as_object().unwrap().keys().collect();
            assert!(keys.iter().any(|key| *key == "provides"), "{keys:?}");
            for newer in ["operation_payload", "role_declarations"] {
                assert!(
                    !keys.iter().any(|key| *key == newer),
                    "HELLO manifest declares `{newer}`: {keys:?}"
                );
            }
        }
    }

    /// Every external attestation bound, as a release build supplying all of
    /// them would compile it.
    fn fully_bound_release_bindings() -> BuildReleaseBindings<'static> {
        BuildReleaseBindings {
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
            app_use_fronting_review_revision: Some("fixture-app-use-fronting-review"),
            release_signing_topology_revision: Some("fixture-signing-topology"),
        }
    }

    /// The app-use review travels from its compile-time binding into the
    /// release inputs, is reported by release evidence like every other
    /// external attestation, and withholds no capability row when absent.
    #[test]
    fn app_use_fronting_review_is_reported_and_gates_no_row() {
        let bound = release_inputs_from_build_bindings(fully_bound_release_bindings());
        assert_eq!(
            bound.app_use_fronting_review_revision.as_deref(),
            Some("fixture-app-use-fronting-review")
        );
        let unbound = release_inputs_from_build_bindings(BuildReleaseBindings {
            app_use_fronting_review_revision: None,
            ..fully_bound_release_bindings()
        });
        assert_eq!(unbound.app_use_fronting_review_revision, None);

        let context = |inputs: ComputerReleaseInputs| ComputerCapabilityAdvertisementContext {
            inputs,
            permissions: Default::default(),
            startup: StartupCapabilityProbe::default(),
        };
        let bound = context(bound);
        let unbound = context(unbound);
        assert_eq!(
            computer_gate_outcomes(&bound).get("app_use_fronting_review_revision"),
            Some(&ComputerGateOutcome::Pass)
        );
        assert_eq!(
            computer_gate_outcomes(&unbound).get("app_use_fronting_review_revision"),
            Some(&ComputerGateOutcome::MissingExternalInput {
                gate: "app_use_fronting_review_revision".to_string(),
            })
        );

        // Every declaration is taken as advertised so that only the release
        // gate decides; the missing app-use review must withhold nothing.
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
        let with_review = admitted(&bound);
        assert!(
            with_review.len() > 1,
            "the fully bound fixture must admit the reviewed rows: {with_review:?}"
        );
        assert_eq!(admitted(&unbound), with_review);
    }

    /// The places where this module brings an application forward or captures
    /// a covered window, each named for the admission it needs.
    #[derive(Debug, Clone, Copy)]
    enum FrontingPath {
        ForegroundOneWayFront,
        NeedsFrontPress,
        ModifierChordUnderAppGrant,
        PersonSwitchRestoreSkip,
        HeldInputRestoreOrdering,
        KeystrokeBracketUnderTakeover,
        BringToFrontReadUnderTakeover,
        PreviewCapture,
    }

    const FRONTING_PATHS: [FrontingPath; 8] = [
        FrontingPath::ForegroundOneWayFront,
        FrontingPath::NeedsFrontPress,
        FrontingPath::ModifierChordUnderAppGrant,
        FrontingPath::PersonSwitchRestoreSkip,
        FrontingPath::HeldInputRestoreOrdering,
        FrontingPath::KeystrokeBracketUnderTakeover,
        FrontingPath::BringToFrontReadUnderTakeover,
        FrontingPath::PreviewCapture,
    ];

    fn path_admitted(path: FrontingPath, inputs: &ComputerReleaseInputs) -> bool {
        match path {
            FrontingPath::ForegroundOneWayFront
            | FrontingPath::NeedsFrontPress
            | FrontingPath::ModifierChordUnderAppGrant
            | FrontingPath::PersonSwitchRestoreSkip
            | FrontingPath::HeldInputRestoreOrdering => app_use_fronting_admitted(inputs),
            FrontingPath::KeystrokeBracketUnderTakeover
            | FrontingPath::BringToFrontReadUnderTakeover => fronting_bracket_admitted(inputs),
            FrontingPath::PreviewCapture => preview_capture_admitted(inputs),
        }
    }

    /// Each combination of the takeover, capture and app-use reviews against
    /// each fronting path and preview capture. The expected admissions are
    /// written out per row rather than derived, so a change to either
    /// predicate shows up as a named row. Every row is checked with valid and
    /// with missing vocabulary digests, which must change nothing.
    #[test]
    fn each_attestation_combination_admits_exactly_its_fronting_paths() {
        // (takeover, capture, app use) bound ->
        // (app-use fronting paths, takeover bracket paths, preview capture)
        type Reviews = (bool, bool, bool);
        type Admissions = (bool, bool, bool);
        let table: [(Reviews, Admissions); 8] = [
            ((false, false, false), (false, false, false)),
            ((true, false, false), (false, true, false)),
            ((false, true, false), (false, false, false)),
            ((false, false, true), (false, false, false)),
            ((true, true, false), (false, true, false)),
            ((true, false, true), (true, true, false)),
            ((false, true, true), (false, false, true)),
            ((true, true, true), (true, true, true)),
        ];
        for ((takeover, capture, app_use), (app_use_paths, bracket_paths, preview)) in table {
            let base = fully_bound_release_bindings();
            let inputs = release_inputs_from_build_bindings(BuildReleaseBindings {
                takeover_dispatch_review_revision: base
                    .takeover_dispatch_review_revision
                    .filter(|_| takeover),
                capture_review_revision: base.capture_review_revision.filter(|_| capture),
                app_use_fronting_review_revision: base
                    .app_use_fronting_review_revision
                    .filter(|_| app_use),
                ..fully_bound_release_bindings()
            });
            let mut without_digests = inputs.clone();
            without_digests.vocabulary_digests = Default::default();
            for inputs in [&inputs, &without_digests] {
                for path in FRONTING_PATHS {
                    let expected = match path {
                        FrontingPath::ForegroundOneWayFront
                        | FrontingPath::NeedsFrontPress
                        | FrontingPath::ModifierChordUnderAppGrant
                        | FrontingPath::PersonSwitchRestoreSkip
                        | FrontingPath::HeldInputRestoreOrdering => app_use_paths,
                        FrontingPath::KeystrokeBracketUnderTakeover
                        | FrontingPath::BringToFrontReadUnderTakeover => bracket_paths,
                        FrontingPath::PreviewCapture => preview,
                    };
                    assert_eq!(
                        path_admitted(path, inputs),
                        expected,
                        "{path:?} with takeover={takeover} capture={capture} \
                         app_use={app_use} digests={}",
                        inputs.vocabulary_digests.manifest_digest.is_some()
                    );
                }
            }
        }
    }

    /// A stand-in value is not a review. The release gate reports it as an
    /// implementation failure, and neither fronting outside the bracket nor
    /// preview capture may treat it as bound.
    #[test]
    fn a_stand_in_app_use_review_admits_no_fronting_and_no_preview_capture() {
        for stand_in in ["placeholder", "tbd", "unknown", " "] {
            let inputs = release_inputs_from_build_bindings(BuildReleaseBindings {
                app_use_fronting_review_revision: Some(stand_in),
                ..fully_bound_release_bindings()
            });
            assert!(!app_use_fronting_admitted(&inputs), "{stand_in:?}");
            assert!(!preview_capture_admitted(&inputs), "{stand_in:?}");
            assert!(fronting_bracket_admitted(&inputs), "{stand_in:?}");
        }
    }

    /// The computer plane a module builds takes its app-use fronting and
    /// preview-capture admissions from the release inputs compiled into this
    /// binary, and from nothing else. A test build is compiled without the
    /// release attestations, so here both must come out unadmitted; a plane
    /// wired to admit either regardless of its release fails here.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    #[tokio::test]
    async fn the_built_plane_admits_fronting_and_preview_capture_only_as_its_release_does() {
        let planes = Planes::new(Arc::new(HealthState::new()));
        let plane = planes
            .computer
            .as_ref()
            .unwrap_or_else(|_| panic!("an isolated module builds its computer plane"));
        let inputs = compiled_release_inputs();
        assert_eq!(
            plane.admits_app_use_fronting(),
            app_use_fronting_admitted(&inputs)
        );
        assert_eq!(
            plane.admits_preview_capture(),
            preview_capture_admitted(&inputs)
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
                    app_use_fronting_review_revision: Some("fixture-app-use-fronting-review"),
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
    use crate::test_support::HANG_GUARD;
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
            agent_cursor: false,
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
            HANG_GUARD,
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
                    tokio::time::timeout(HANG_GUARD, async {
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
            HANG_GUARD,
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
    use crate::test_support::HANG_GUARD;
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
        tokio::time::timeout(HANG_GUARD, done_rx.recv())
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
    use crate::test_support::HANG_GUARD;

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
        tokio::time::timeout(HANG_GUARD, async {
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
    async fn draining_refuses_new_requests_and_stops_in_flight() {
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
        assert_eq!(body["outcome"], "module_draining");
        await_count(&planes, 0).await;
    }

    #[tokio::test]
    async fn drain_does_not_wait_on_a_person() {
        let mut planes = computer_grants::tests::CardService::install(
            super::tests::management_bound_planes(1, 1),
            1,
            1,
        );
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
        let question = planes.consent_test.as_ref().unwrap().card(1, 1).await;
        assert_eq!(count(&planes), 0);
        handle_frame(draining(), &tx, &planes).await.unwrap();
        assert_eq!(count(&planes), 0);
        let result = tokio::time::timeout(HANG_GUARD, result_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(result["outcome"], "module_draining");
        let calls = planes.consent_test.as_ref().unwrap().calls();
        assert!(
            calls
                .iter()
                .any(|(method, params)| method == "consent.withdraw"
                    && params["elicitation_id"] == format!("el_test_{}", question.header.corr)),
            "the drain withdraws the card at Cingulate"
        );
        let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply.header.ty, FrameType::Response);
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
    use crate::test_support::HANG_GUARD;

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

    use super::tests::{late_answer, ScriptedConsent};
    use cingulate_client::wire::{
        CONSENT_ACK, CONSENT_ANSWERS, CONSENT_AWAIT, CONSENT_DETACH, CONSENT_REPORT_EXECUTION,
        CONSENT_REQUEST,
    };

    /// Planes whose management route (channel 1, epoch 1) belongs to an
    /// admitted agent session, and whose consent cards go to `consent`'s
    /// scripted Cingulate. Building them again over the same `consent`
    /// stands for a restarted module: same registry file, same Cingulate.
    fn planes(consent: &ScriptedConsent) -> Planes {
        consent.wire(super::tests::management_bound_planes(1, 1), 1, 1)
    }

    /// Run one import until it replies, returning the card it raised (its
    /// `consent.request` params), if any, and the reply.
    async fn import(
        planes: &Planes,
        consent: &ScriptedConsent,
        root: &std::path::Path,
        writer: &mpsc::Sender<Frame>,
    ) -> (Option<Value>, Value) {
        let raised_before = consent.cards().len();
        let facts = planes.routes.get(1, 1).unwrap();
        let running = {
            let planes = planes.clone();
            let writer = writer.clone();
            let plan = plan(root);
            tokio::spawn(async move {
                computer_grants::tests::with_live(complete_login_import(
                    &planes, &facts, &writer, 1, 1, plan, None,
                ))
                .await
            })
        };
        let reply = tokio::time::timeout(HANG_GUARD, running)
            .await
            .expect("the import replies")
            .unwrap();
        (consent.cards().into_iter().nth(raised_before), reply)
    }

    /// Let one call on the session read a consent answer that arrived after
    /// the import call returned, then check that it was stored for the next
    /// import (as a single-use approval or a remembered refusal).
    async fn await_remembered(planes: &Planes) {
        computer_grants::tests::drain_call(planes, 1, 1).await;
        assert!(
            planes.consent.has_single_use_approvals()
                || planes.management.computer_grants().remembers_login_answer()
        );
    }

    #[tokio::test]
    async fn cancelling_the_import_card_has_no_refusal_or_retry_advice() {
        let consent = ScriptedConsent::new();
        consent.raises("el_imp_stop");
        consent
            .script
            .then(CONSENT_AWAIT, cingulate_client::Reply::Hang)
            .then(
                CONSENT_DETACH,
                cingulate_client::Reply::Result(json!({
                    "elicitation_id":"el_imp_stop", "state":"pending", "detached":true,
                })),
            );
        let planes = planes(&consent);
        let root = root();
        let (tx, _rx) = mpsc::channel(8);
        let facts = planes.routes.get(1, 1).unwrap();
        let cancel = CancelHandle::pending();
        let waiting = computer_grants::tests::with_live(complete_login_import(
            &planes,
            &facts,
            &tx,
            1,
            1,
            plan(&root),
            Some(cancel.clone()),
        ));
        let stop = async {
            tokio::time::timeout(HANG_GUARD, async {
                while consent.methods().len() < 2 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("import is waiting on its card");
            cancel.cancel();
        };
        let (reply, ()) = tokio::time::timeout(HANG_GUARD, async { tokio::join!(waiting, stop) })
            .await
            .expect("cancelled import answers promptly");
        assert_eq!(reply["outcome"], "cancelled");
        assert!(reply.get("remedy").is_none());
        assert!(reply.get("grant_request").is_none());
        browser::validate_browser_result(management::IMPORT_LOGIN, &reply).unwrap();
        assert_eq!(
            consent.methods(),
            [CONSENT_REQUEST, CONSENT_AWAIT, CONSENT_DETACH]
        );
        assert_eq!(
            planes
                .consent
                .unapplied(&computer_grants::tests::session_key("test-project"))
                .len(),
            1,
            "the cancelled call leaves its card answerable but cannot transfer a login"
        );
        assert!(!root.join("profile").exists());
    }

    #[tokio::test]
    async fn the_import_card_is_sent_for_thirty_minutes_with_late_execution() {
        let consent = ScriptedConsent::new();
        consent.raises("el_imp_1").unanswered("el_imp_1");
        let planes = planes(&consent);
        let root = root();
        let (tx, _rx) = mpsc::channel(8);
        let (asked, reply) = import(&planes, &consent, &root, &tx).await;
        let asked = asked.expect("a card was raised");
        assert_eq!(asked["expires_in_ms"], 1_800_000, "{asked}");
        assert_eq!(asked["late_execution"], "execute", "{asked}");
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        assert_eq!(reply["ask_id"], "el_imp_1", "{reply}");
        assert_eq!(
            reply["remedy"],
            computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
            "{reply}"
        );
        assert_eq!(
            consent.methods(),
            [CONSENT_REQUEST, CONSENT_AWAIT, CONSENT_DETACH]
        );
        assert_eq!(
            planes
                .consent
                .unapplied(&computer_grants::tests::session_key("test-project"))
                .len(),
            1
        );
    }

    /// A granting answer that arrives after the call returned is used by the
    /// retry with the same origin, with no second card, and only once. The
    /// retry tells Cingulate what became of the approval before it replies.
    #[tokio::test]
    async fn a_late_import_approval_is_used_once_by_the_retry() {
        let consent = ScriptedConsent::new();
        consent.raises("el_imp_2").unanswered("el_imp_2");
        let planes = planes(&consent);
        let root = root();
        let (tx, _rx) = mpsc::channel(8);
        let (_, reply) = import(&planes, &consent, &root, &tx).await;
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        consent.feed(late_answer("el_imp_2", "hand_off"));
        await_remembered(&planes).await;
        consent.takes_report("el_imp_2");
        let (card, reply) = import(&planes, &consent, &root, &tx).await;
        assert!(card.is_none(), "a second card was raised");
        assert_eq!(reply["outcome"], "hand_off", "{reply}");
        assert_eq!(consent.methods().last().unwrap(), CONSENT_REPORT_EXECUTION);
        assert_eq!(
            consent.script.calls().last().unwrap().1["elicitation_id"],
            "el_imp_2"
        );
        consent.raises("el_imp_3").unanswered("el_imp_3");
        let (card, reply) = import(&planes, &consent, &root, &tx).await;
        assert!(card.is_some(), "the approval was used twice");
        assert_eq!(reply["outcome"], "consent_pending", "{reply}");
    }

    /// An import approval given after its call returned survives a module
    /// restart: on the restarted module, the session's next call reads it
    /// from the answers feed and acknowledges it, and the retry uses it once
    /// and reports it to Cingulate before replying. A second restart has
    /// nothing left to apply and opens no route to Cingulate.
    #[tokio::test]
    async fn a_late_import_approval_survives_a_restart_and_is_applied_once() {
        use cingulate_client::desk::RegistryStore;

        let consent = ScriptedConsent::new();
        consent
            .raises("el_imp_restart")
            .unanswered("el_imp_restart");
        let root = root();
        let (tx, _rx) = mpsc::channel(8);
        {
            let planes = planes(&consent);
            let (_, reply) = import(&planes, &consent, &root, &tx).await;
            assert_eq!(reply["outcome"], "consent_pending", "{reply}");
        }
        assert_eq!(consent.store().load().unwrap().len(), 1);

        // The person approves while the module is down.
        let restarted = planes(&consent);
        consent.feed(late_answer("el_imp_restart", "hand_off"));
        let before = consent.methods().len();
        computer_grants::tests::drain_call(&restarted, 1, 1).await;
        assert_eq!(consent.methods()[before..], [CONSENT_ANSWERS, CONSENT_ACK]);
        assert!(consent
            .store()
            .load()
            .unwrap()
            .iter()
            .all(|card| card.applied && card.lifecycle.acked));
        consent.takes_report("el_imp_restart");
        let (card, reply) = import(&restarted, &consent, &root, &tx).await;
        assert!(card.is_none(), "a second card was raised");
        assert_eq!(reply["outcome"], "hand_off", "{reply}");
        assert_eq!(
            consent.methods()[before..],
            [CONSENT_ANSWERS, CONSENT_ACK, CONSENT_REPORT_EXECUTION]
        );
        assert_eq!(
            consent.script.calls().last().unwrap().1["elicitation_id"],
            "el_imp_restart"
        );
        assert!(!restarted.consent.has_single_use_approvals());

        let again = planes(&consent);
        let opens = consent.script.opens();
        computer_grants::tests::drain_call(&again, 1, 1).await;
        assert_eq!(consent.script.opens(), opens, "nothing was left to apply");
        assert!(!again.consent.has_single_use_approvals());
    }

    /// A refusal that arrives after the call returned refuses the retry as
    /// denied, with no second card.
    #[tokio::test]
    async fn a_late_import_refusal_denies_the_retry() {
        let consent = ScriptedConsent::new();
        consent.raises("el_imp_4").unanswered("el_imp_4");
        let planes = planes(&consent);
        let root = root();
        let (tx, _rx) = mpsc::channel(8);
        import(&planes, &consent, &root, &tx).await;
        consent.feed(late_answer("el_imp_4", "deny"));
        await_remembered(&planes).await;
        let (card, reply) = import(&planes, &consent, &root, &tx).await;
        assert!(card.is_none(), "a second card was raised");
        assert_eq!(reply["outcome"], "denied", "{reply}");
    }

    /// When Cingulate refuses to raise the card, so nobody is shown it, the
    /// import ends at once with `not_put_to_anyone`.
    #[tokio::test]
    async fn a_card_nobody_was_shown_ends_the_import_at_once() {
        let consent = ScriptedConsent::new();
        consent.script.then(
            CONSENT_REQUEST,
            cingulate_client::Reply::Refused("elicitation_requester_refused"),
        );
        let planes = planes(&consent);
        let root = root();
        let (tx, _rx) = mpsc::channel(8);
        let (card, reply) = import(&planes, &consent, &root, &tx).await;
        assert!(card.is_some());
        assert_eq!(reply["outcome"], "not_put_to_anyone", "{reply}");
        assert_eq!(consent.methods(), [CONSENT_REQUEST]);
        assert!(!planes.management.computer_grants().remembers_login_answer());
    }

    /// Each way the import card can end without an answer gets its own
    /// outcome, and a choice the card did not offer is reported as
    /// `unrecognized_answer`, not as a refusal.
    #[test]
    fn every_unanswered_ending_concludes_as_itself() {
        use cingulate_client::desk::{Ending, NoCard};
        let root = root();
        for (ending, outcome) in [
            (
                Ending::Declined {
                    choice_id: "deny".into(),
                },
                "denied",
            ),
            (
                Ending::Declined {
                    choice_id: "maybe".into(),
                },
                "unrecognized_answer",
            ),
            (Ending::NoAnswer, "no_answer"),
            (Ending::NotPutToAnyone, "not_put_to_anyone"),
            (Ending::DeliveryFailed, "undeliverable"),
            (Ending::Withdrawn, "question_withdrawn"),
            (
                Ending::NoCard(NoCard::NoAgentSession),
                "consent_unavailable",
            ),
        ] {
            let result = plan(&root).conclude(&ending);
            assert_eq!(result.outcome, outcome, "{ending:?}");
            assert_eq!(result.remedy.is_some(), outcome != "denied", "{ending:?}");
            assert_eq!(result.rows, 0, "{ending:?}");
        }
        let result = plan(&root).conclude(&Ending::NoCard(NoCard::NoAgentSession));
        assert_eq!(result.reason, Some("no_agent_session"));
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

    /// A failed backup-catalog write is printed nowhere, so the health reply is
    /// where it shows. No test runs the production entry point, so the count
    /// here is the untouched zero.
    #[tokio::test]
    async fn the_backup_catalog_write_failure_count_is_on_the_health_reply() {
        assert_eq!(health_metrics().await["engramCatalogWriteFailures"], 0);
    }
}

#[cfg(all(test, target_os = "macos"))]
mod computer_consent_wire_tests;

/// A relayed `computer_use` call, driven through the production frame loop and
/// the tool handler, writes the caller behind it on its computer journal row.
#[cfg(all(test, target_os = "macos"))]
mod relayed_computer_call_tests {
    use super::*;
    use crate::test_support::HANG_GUARD;
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
            .with_permission_liveness(computer_capability::live_for_test())
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
        computer_grants::tests::CardService::install(planes, CHANNEL, EPOCH)
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
        let question = planes
            .consent_test
            .as_ref()
            .unwrap()
            .card(CHANNEL, EPOCH)
            .await;
        assert!(planes.consent_test.as_ref().unwrap().answer(
            question.header.corr,
            cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"}))
        ));
        let frame = tokio::time::timeout(HANG_GUARD, rx.recv())
            .await
            .unwrap()
            .unwrap();
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
        bind_basal_flow_target(
            planes,
            tx,
            rx,
            subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
        )
        .await;
    }

    async fn bind_basal_flow_target(
        planes: &Planes,
        tx: &mpsc::Sender<Frame>,
        rx: &mut mpsc::Receiver<Frame>,
        target: subc_protocol::RouteTarget,
    ) {
        let stamp = subc_protocol::scope::ScopeStamp::new(
            session_caller_principal_for_test().unwrap(),
            "flow-head",
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_attributes(
            subc_protocol::scope::ScopeAttributes::new()
                .with_agent_id(Some("test-project".into()))
                .with_delegates(true)
                .with_flow_id(Some("flow-computer".into())),
        )
        .with_owner_authorized(true);
        let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
            role_versions: None,
            call_mode: None,
            route_channel: CHANNEL,
            epoch: EPOCH,
            target,
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
            let audit_storage = InMemoryJournalStorage::new();
            let mut planes =
                planes_with_source(&audit_storage, Arc::new(CountReads(reads.clone())));
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
                Arc::new(ComputerGrants::open(
                    storage.clone(),
                    Some("machine".into()),
                )),
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
            let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
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
                let token = body["detail"]["grant"].as_str().unwrap();
                let label = body["detail"]["grant_label"].as_str().unwrap();
                let decoded = management::decode_grant(token).unwrap();
                assert_eq!(
                    decoded,
                    json!({"tool":"computer_use","target":APP,"signer":"certificate leaf[subject.OU] = \"FIXTURE001\"","level":4})
                );
                assert!(label.starts_with("control of "));
                bind_basal_flow_target(
                    &planes,
                    &tx,
                    &mut rx,
                    subc_protocol::RouteTarget::ManagementSurface {
                        module_id: "cerebellum".into(),
                    },
                )
                .await;
                let query = json!({"method":management::WOULD_ASK,"params":{"agent_id":"test-project","flow_id":"flow-computer","items":[{"grant":token}]}});
                for restored in [false, true] {
                    if restored {
                        storage
                            .save(&GrantStoreState {
                                version: GRANT_STORE_VERSION,
                                records: vec![AlwaysGrantRecord {
                                    agent_project_id: "test-project".into(),
                                    bundle_identity: APP.into(),
                                    team_id: Some("FIXTURE001".into()),
                                    designated_requirement: Some(
                                        "certificate leaf[subject.OU] = \"FIXTURE001\"".into(),
                                    ),
                                    machine_uuid: "machine".into(),
                                    created_at_ms: 1,
                                }],
                            })
                            .unwrap();
                        planes.management = Arc::new(ManagementPlane::with_computer_grants(
                            Arc::new(Running),
                            Arc::new(ComputerGrants::open(
                                storage.clone(),
                                Some("machine".into()),
                            )),
                        ));
                    }
                    handle_frame(
                        Frame::build(
                            FrameType::Request,
                            control_flags(),
                            CHANNEL,
                            EPOCH,
                            90,
                            serde_json::to_vec(&query).unwrap(),
                        )
                        .unwrap(),
                        &tx,
                        &planes,
                    )
                    .await
                    .unwrap();
                    let answer = rx.recv().await.unwrap();
                    assert_eq!(answer.header.ty, FrameType::Response);
                    let answer: Value = serde_json::from_slice(&answer.body).unwrap();
                    assert_eq!(
                        answer["items"][0]["verdict"],
                        if restored { "yes" } else { "would_ask" },
                        "{answer}"
                    );
                }
                let mut wrong_signer = decoded.clone();
                wrong_signer["signer"] = json!("another signer");
                let mut wrong_query = query.clone();
                wrong_query["params"]["items"][0]["grant"] =
                    json!(management::encode_grant(wrong_signer));
                handle_frame(
                    Frame::build(
                        FrameType::Request,
                        control_flags(),
                        CHANNEL,
                        EPOCH,
                        91,
                        serde_json::to_vec(&wrong_query).unwrap(),
                    )
                    .unwrap(),
                    &tx,
                    &planes,
                )
                .await
                .unwrap();
                let answer: Value = serde_json::from_slice(&rx.recv().await.unwrap().body).unwrap();
                assert_eq!(answer["items"][0]["verdict"], "would_ask", "{answer}");
                let journal = planes.browser.journal_export_for_test().await;
                assert!(!journal.is_empty());
                assert!(!journal.contains(token));
                assert!(!journal.contains(label));
                let audit = serde_json::to_value(audit_storage.load().unwrap()).unwrap();
                assert!(
                    audit["entries"].as_object().unwrap().is_empty(),
                    "a refused computer action must not create an action journal record"
                );
            }
            assert_no_card_raised(&planes);
            assert!(rx.try_recv().is_err());
            if granted {
                planes
                    .management
                    .computer_grants()
                    .seed_takeover_for_test("test-project");
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
                let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
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
                assert_no_card_raised(&planes);
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
            .seed_takeover_for_test("test-project");
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
            let reply = tokio::time::timeout(HANG_GUARD, rx.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply.header.ty, FrameType::Response);
            let body: Value = serde_json::from_slice(&reply.body).unwrap();
            assert_eq!(body["outcome"], "consent_unavailable", "{body}");
            assert_eq!(body["detail"]["reason"], "takeover_not_for_flows", "{body}");
            assert_no_card_raised(&planes);
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
            let stamp = subc_protocol::scope::ScopeStamp::new(
                session_caller_principal_for_test().unwrap(),
                "head",
                1,
                subc_protocol::scope::ScopeKind::Head,
            )
            .with_attributes(
                subc_protocol::scope::ScopeAttributes::new()
                    .with_agent_id(Some("test-project".into()))
                    .with_delegates(true)
                    .with_flow_id(flow_id.clone()),
            )
            .with_owner_authorized(true);
            let bind = subc_protocol::session::ModuleControlRequest::RouteBind {
                role_versions: None,
                call_mode: None,
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
            let mut reply = if flow_id.is_some() {
                tokio::time::timeout(HANG_GUARD, rx.recv())
                    .await
                    .unwrap()
                    .unwrap()
            } else {
                planes
                    .consent_test
                    .as_ref()
                    .unwrap()
                    .card(CHANNEL, EPOCH)
                    .await
            };
            if flow_id.is_some() {
                assert_eq!(reply.header.ty, FrameType::Response);
                assert_eq!(
                    serde_json::from_slice::<Value>(&reply.body).unwrap(),
                    json!({
                        "outcome":"consent_unavailable", "detail":{"reason":"flow_carrier_not_admitted"}, "remedy":"open the flow route through authorized reserved:basal"
                    })
                );
                assert_eq!(reads.load(Ordering::SeqCst), 0);
                assert_no_card_raised(&planes);
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
                assert!(planes.consent_test.as_ref().unwrap().answer(
                    reply.header.corr,
                    cingulate_client::ScriptedAnswer::Answered(json!({"decision":"allow_30m"})),
                ));
                reply = tokio::time::timeout(HANG_GUARD, rx.recv())
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

#[cfg(test)]
mod browser_login_fact_tests {
    use super::*;

    #[tokio::test]
    async fn only_successful_imports_record_a_signed_in_domain() {
        let signed_in = Arc::new(browser_signed_in::SignedInDomains::default());
        signed_in
            .initialize_profile("agent", "default", "new-agent-profile", true)
            .unwrap();
        signed_in
            .initialize_profile("other-agent", "default", "new-other-profile", true)
            .unwrap();
        let planes = Planes::with_browser_state(
            Arc::new(HealthState::new()),
            None,
            JournalPersistence::Isolated,
            None,
            Some(Arc::clone(&signed_in)),
        );
        let bind = subc_protocol::BindIdentity::new("/test/project", "test", "import-facts");
        let mut identity = RouteIdentity::from_bind(&bind, &None);
        identity.agent_project_id = "agent".into();
        for ending in ["denied", "hand_off", "transfer_failed"] {
            let result =
                login_import::ImportResult::refusal("https://login.example.com", ending, "retry");
            let reply = journal_login_import_result(&planes, &identity, result).await;
            assert_eq!(reply["outcome"], ending);
            assert!(!signed_in.is_signed_in("agent", "default", "https://account.example.com"));
        }
        let mut imported =
            login_import::ImportResult::refusal("https://login.example.com", "transferred", "");
        imported.remedy = None;
        imported.browser = Some("chrome".into());
        imported.rows = 1;
        let reply = journal_login_import_result(&planes, &identity, imported).await;
        assert_eq!(reply["outcome"], "transferred");
        assert!(signed_in.is_signed_in("agent", "default", "https://account.example.com"));
        assert!(!signed_in.is_signed_in("other-agent", "default", "https://account.example.com"));
    }
}
