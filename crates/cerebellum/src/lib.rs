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

mod control;
mod management_dispatch;
mod planes;
mod tool_dispatch;

pub use control::RouteBindings;
use control::*;
use management_dispatch::*;
pub use tool_dispatch::handle_browser_consent_deadline_for_test;
use tool_dispatch::*;

mod ability;
pub mod ability_helper;
pub mod ability_source;
mod agent_data;
pub mod agent_grants;
pub mod authorization;
mod blocking_permits;
pub mod browser;
pub mod browser_config;
mod browser_consent;
pub mod browser_crash_reports;
pub mod browser_executable_identity;
mod browser_held;
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
// Executable fixtures assert Unix modes and inode reuse.
mod channel_route;
#[cfg(all(test, unix))]
mod content_named_fixture;
pub mod coordinate;
#[cfg(test)]
mod cursor_end_tests;
pub mod custody;
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
#[doc(hidden)]
pub mod desk_probe;
#[cfg(test)]
mod dispatch_reply_tests;
pub mod durable_formats;
mod egress;
mod event_publish;
pub mod flat_tools;
mod grant_enforcement;
mod image_handles;
#[cfg(test)]
mod isolated_grants_tests;
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
pub mod outlook_guard;
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
mod registration;
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
mod tool_display;
mod tool_provider;
mod tool_result;
mod turn_ended;
// Only macOS draws the native badge. Other hosts compile this module for unit
// tests that parse turn hints, end matching badges, and exercise connection
// lifetime with a fake transport rather than a live NATS bus.
#[cfg(any(target_os = "macos", test))]
mod turn_hints;
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

/// Release evidence records the current set of canonical computer
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
const COMPUTER_RELEASE_GATE_TABLE: [ComputerReleaseGate; 24] = [
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
        name: "takeover_pointer_fronting_review_revision",
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
        "takeover_pointer_fronting_review_revision" => {
            inputs.takeover_pointer_fronting_review_revision.as_deref()
        }
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
        "computer.takeover_move"
            | "computer.takeover_drag"
            | "computer.takeover_scroll"
            | "computer.takeover_click"
    ) {
        // Global posting and takeover permission have separate reviews. The
        // click row additionally needs the pointer-fronting review; none of
        // these admissions is inferred from another row's artifact.
        (id != "computer.takeover_click"
            || gate_passes(outcomes, "takeover_pointer_fronting_review_revision"))
            && (cerebellum_computer::platform::DOWN_GESTURE_RECOVERY_MEASURED
                || (id != "computer.takeover_click"
                    && (id != "computer.takeover_drag"
                        || !gate_passes(outcomes, "takeover_pointer_fronting_review_revision"))))
            && [
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
        || name == cortexkit_role_tool_display::DISPLAY_READ
        || name == image_handles::RESOLVE
        || permissions::is_operation(name)
        || ability::is_operation(name)
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
/// External identifiers use `option_env!` so a release invocation must
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
        takeover_pointer_fronting_review_revision: option_env!(
            "CEREBELLUM_TAKEOVER_POINTER_FRONTING_REVIEW_REVISION"
        ),
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
    takeover_pointer_fronting_review_revision: Option<&'a str>,
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
        takeover_pointer_fronting_review_revision: bindings
            .takeover_pointer_fronting_review_revision
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

#[cfg_attr(
    not(any(test, target_os = "macos", target_os = "windows")),
    allow(dead_code)
)]
/// Release-review admission for temporary pointer fronting. This does not
/// replace the conversation's takeover permission, checked on each dispatch.
pub fn takeover_pointer_fronting_admitted(inputs: &ComputerReleaseInputs) -> bool {
    release_attestation_bound(
        "takeover_pointer_fronting_review_revision",
        inputs.takeover_pointer_fronting_review_revision.as_deref(),
    ) && release_attestation_bound(
        "takeover_dispatch_review_revision",
        inputs.takeover_dispatch_review_revision.as_deref(),
    ) && release_attestation_bound(
        "global_dispatch_review_revision",
        inputs.global_dispatch_review_revision.as_deref(),
    )
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

/// Watch one session scope whose route closed until the daemon says, one way
/// or the other, whether it ended. Runs on its own task, never on the frame
/// loop, and is the only watcher of its scope (see
/// [`scope_watch::ScopeRevocation::note_closed`]).
///
/// Only a definitive end ends anything (see [`scope_watch::classify`]). While
/// the answer is unresolved everything stays, and the scope is asked about
/// again when another route under it closes, or once per
/// [`scope_watch::SCOPE_RECHECK_INTERVAL`], but only while a
/// browser it opened is still open or an answered consent card awaits execution,
/// and no route under it is bound. A bound route asks again when it closes;
/// retained cards must learn a late session end even with no browser open.
async fn watch_scope(planes: Planes, writer: mpsc::Sender<Frame>, key: scope_watch::ScopeKey) {
    let mut drain = planes.drain_signal.subscribe();
    let closed_again = planes.scopes.closed_again(&key);
    let session = cingulate_client::live_call::SessionKey {
        owner: serde_json::to_string(&key.owner).unwrap_or_default(),
        scope_ref: key.scope_ref.clone(),
        scope_epoch: key.scope_epoch,
    };
    loop {
        let answer = planes.scopes.describe(&writer, &key).await;
        if held_scope_end(answer.as_ref(), &key) {
            settle_scope_holds(&planes, &key);
        }
        if scope_watch::classify(answer.as_ref(), key.scope_epoch)
            == scope_watch::ScopeVerdict::Ended
        {
            // A head may end after its last route closed. Release its retained
            // bridge alias too, but never let an old epoch's watcher release
            // claims after the session's scope epoch advances. Uncertain
            // answers release nothing.
            let stamp = subc_protocol::scope::ScopeStamp::new(
                key.owner.clone(),
                key.scope_ref.clone(),
                key.scope_epoch,
                subc_protocol::scope::ScopeKind::Head,
            );
            let newer_live_epoch = answer
                .as_ref()
                .is_some_and(|answer| answer.status == subc_protocol::scope::ScopeStatus::Live);
            // A live higher epoch is the same agent session even when its
            // replacement tools route has not reached this module yet.
            if !newer_live_epoch && !planes.scopes.is_superseded(&stamp) {
                if let Some(route) = planes.user_browser.target().end_session(&key) {
                    planes.user_browser.goodbye(route);
                }
                for route in planes.routes.user_browser_head_routes_under_scope(&key) {
                    planes.user_browser.goodbye(route);
                }
            }
            let mut conversations = planes.scopes.finish(&key);
            // A route under the scope whose close has not reached this module
            // yet belongs to the ended session too.
            conversations.extend(planes.routes.conversations_under_scope(&key));
            let _ = planes.consent.forget_session(&session);
            revoke_scope(&planes, &conversations).await;
            return;
        }
        let browser_open = planes
            .scopes
            .conversations(&key)
            .iter()
            .any(|conversation_key| planes.sessions.has_open_session(conversation_key));
        let consent_waiting = planes
            .consent
            .awaiting_execution_sessions()
            .contains(&session);
        let held_waiting = planes.calls.has_pending_scope(&held_scope_identity(&key));
        if (!browser_open
            && !consent_waiting
            && !held_waiting
            && !planes.user_browser.target().has_session(&key))
            || planes.routes.carries_scope(&key)
        {
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

fn held_scope_identity(key: &scope_watch::ScopeKey) -> journal::call_records::ScopeIdentity {
    journal::call_records::ScopeIdentity {
        owner: journal::call_records::principal_label(Some(&key.owner)),
        reference: key.scope_ref.clone(),
        scope_epoch: key.scope_epoch,
    }
}

fn held_scope_end(
    answer: Option<&scope_watch::DescribeAnswer>,
    key: &scope_watch::ScopeKey,
) -> bool {
    answer.is_some_and(|answer| {
        answer.status == subc_protocol::scope::ScopeStatus::Ended
            && answer.scope_epoch == Some(key.scope_epoch)
    })
}

/// Settle the held call without withdrawing its card or closing a browser
/// borrowed from the parent agent conversation. Capture observes the end through
/// its cancellation predicate; the persistent browser keeps its normal handoff
/// and teardown policy.
fn settle_scope_holds(planes: &Planes, key: &scope_watch::ScopeKey) {
    planes
        .browser_resumes
        .cancel_scope(&held_scope_identity(key));
    let _ = planes
        .calls
        .end_held_scope(&held_scope_identity(key), wall_clock_ms());
}

/// A codemode run borrows its parent agent conversation's browser and grants.
/// Watch only its held calls: ending the run must not revoke that conversation.
async fn watch_run_scope_holds(
    planes: Planes,
    writer: mpsc::Sender<Frame>,
    key: scope_watch::ScopeKey,
) {
    let mut drain = planes.drain_signal.subscribe();
    let closed_again = planes.scopes.closed_again(&key);
    while planes.calls.has_pending_scope(&held_scope_identity(&key)) {
        let answer = planes.scopes.describe(&writer, &key).await;
        if held_scope_end(answer.as_ref(), &key) {
            settle_scope_holds(&planes, &key);
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(planes.scopes.recheck_interval) => {}
            _ = closed_again.notified() => {}
            _ = drain.wait_for(|draining| *draining) => break,
        }
    }
    planes.scopes.finish(&key);
}

fn watch_retained_consent_scopes(planes: &Planes, writer: &mpsc::Sender<Frame>) {
    for session in planes.consent.awaiting_execution_sessions() {
        let Ok(owner) = serde_json::from_str(&session.owner) else {
            // An unreadable owner cannot establish that a session ended.
            continue;
        };
        let key = scope_watch::ScopeKey {
            owner,
            scope_ref: session.scope_ref,
            scope_epoch: session.scope_epoch,
        };
        if planes.scopes.note_retained(&key) {
            tokio::spawn(watch_scope(planes.clone(), writer.clone(), key));
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
    planes.browser_resumes.cancel_conversation(conversation_key);
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
    // before adoption would inherit the registration socket or launch-nonce pipe.
    let registration = registration::take_before_any_spawn()?;
    launch_nonce::read_before_any_spawn();
    #[cfg(target_os = "macos")]
    let cursor_executable = computer_capability::cursor::pin_helper_at_startup();
    let config = ModuleConfig::from_env()?;
    record_private_state_tightening();
    record_engram_catalog_write();
    cerebellum_computer::dispatch::load_needs_front_restore_predictor(
        cerebellum_core::platform_dirs::data_home().as_deref(),
    );
    let ending = run(
        config,
        read_live_settings_from_config_file,
        true,
        registration,
    )
    .await;
    #[cfg(target_os = "macos")]
    drop(cursor_executable);
    conclude(ending)
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
#[path = "lib_tests/live_settings_tests.rs"]
mod live_settings_tests;

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
    let registration = registration::take_before_any_spawn()?;
    launch_nonce::read_before_any_spawn();
    let config = ModuleConfig {
        connection_file_path,
        module_id: DEFAULT_MODULE_ID.into(),
        health: HealthConfig::default(),
        agent_cursor: false,
        browser: BrowserSurface::Available(browser),
    };
    conclude(run(config, prepare, false, registration).await)
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
/// The first caller starts it, and every caller, the first included, waits for
/// that same run to finish. Browser process waits use a blocking thread. It is
/// never started twice, and a caller that stops waiting does not stop it.
#[derive(Clone)]
struct ShutdownTeardown(Arc<ShutdownTeardownState>);

struct ShutdownTeardownState {
    browser_resumes: Arc<browser_held::Tasks>,
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
        browser_resumes: Arc<browser_held::Tasks>,
    ) -> Self {
        let (finished, _) = tokio::sync::watch::channel(false);
        Self(Arc::new(ShutdownTeardownState {
            browser_resumes,
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
        let resume_deadline =
            tokio::time::Instant::now() + browser_session::SHUTDOWN_TEARDOWN_BUDGET;
        let mut finished = self.0.finished.subscribe();
        if !self
            .0
            .started
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            self.0.browser_resumes.stop();
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
            // Wait for browser processes on a blocking thread while joining
            // asynchronous resumptions in parallel. The runtime stays free
            // to notice SIGTERM during those waits.
            tokio::spawn(async move {
                let finished = MarkTeardownFinished(state);
                let browser_state = Arc::clone(&finished.0);
                let browser = tokio::task::spawn_blocking(move || {
                    if let Some(browser) = &browser_state.browser {
                        browser_state.sessions.teardown_all(browser);
                    }
                });
                let resumes = finished.0.browser_resumes.stop_and_join(resume_deadline);
                let _ = tokio::join!(browser, resumes);
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
    registration: Option<registration::Stream>,
) -> ModuleEnding {
    #[cfg(not(target_os = "macos"))]
    let _ = enable_user_bridge;
    // Listening starts before the connection is made, so a SIGTERM that
    // arrives while connecting is held until the module can act on it rather
    // than ending the process with no teardown.
    #[cfg(unix)]
    let mut sigterm = listen_for_sigterm();
    let stream = match connect_to_subc(&config.connection_file_path, registration).await {
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
    planes
        .routes
        .display
        .connect(Arc::new(tool_display::DaemonDisplay::new(
            config.connection_file_path.clone(),
            config.module_id.clone(),
        )));
    planes
        .agent_data
        .set_door(Arc::new(agent_data::door::DaemonDoor::new(
            config.connection_file_path.clone(),
            config.module_id.clone(),
        )));
    // Captures deposit into the vault over a connection of their own, opened
    // with the same connection file as this one. Set before `prepare`, so a
    // test can put its own vault in its place.
    planes
        .capture
        .set_vault(Arc::new(login_capture::vault::ClaustrumVault::supervised(
            config.connection_file_path.clone(),
            config.module_id.clone(),
        )));
    planes.browser = Arc::new(
        Arc::try_unwrap(planes.browser)
            .ok()
            .expect("startup owns the browser plane")
            .with_login_material_source(Some(browser::fill::production_login_material_source(
                config.connection_file_path.clone(),
                config.module_id.clone(),
            ))),
    );
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
        Arc::clone(&planes.browser_resumes),
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
        Arc::clone(&planes.browser_resumes),
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

async fn connect_to_subc(
    connection_file_path: &PathBuf,
    registration: Option<registration::Stream>,
) -> Result<registration::Stream, ModuleError> {
    let conn = connection_file::read(connection_file_path)
        .map_err(|e| ModuleError::Message(format!("reading connection file: {e}")))?;
    let mut stream = if let Some(stream) = registration {
        stream
    } else {
        let endpoint = conn
            .endpoints
            .first()
            .ok_or_else(|| ModuleError::Message("connection file has no endpoints".into()))?;
        let addr = format!("{}:{}", endpoint.host, endpoint.port);
        let stream = TcpStream::connect(&addr)
            .await
            .map_err(|e| ModuleError::Message(format!("connect {addr}: {e}")))?;
        configure_tcp_keepalive(&stream)?;
        Box::new(stream) as registration::Stream
    };
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
    let _registration = registration::connect(&writer)?;
    #[cfg(not(test))]
    planes
        .calls
        .events
        .connect_and_reconcile(Arc::new(event_publish::BusTransport {
            connection_file: config.connection_file_path.clone(),
        }));
    #[cfg(target_os = "macos")]
    if let Some(cursor) = planes_cursor(&planes) {
        cursor.listen_for_turn_hints(Arc::new(turn_hints::LiveTransport::new(
            config.connection_file_path.clone(),
            config.module_id.clone(),
        )));
    }
    watch_retained_consent_scopes(&planes, &writer);

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
    // A handler may itself wait for the daemon's answer to a control request
    // this module sent, such as a claim mint for an outbound connection. That
    // answer arrives on this connection, so the loop hands it over while the
    // handler is still running instead of after it.
    let reply_planes = planes.clone();
    let take_reply = move |frame: Frame| {
        if frame.header.channel == 0
            && matches!(frame.header.ty, FrameType::Response | FrameType::Error)
            && deliver_control_reply(&frame, &reply_planes)
        {
            Ok(())
        } else {
            Err(frame)
        }
    };

    run_dispatch_loop_taking_replies(
        read_half,
        &planes.health,
        &clock,
        &mut idle_wake,
        take_reply,
        handler,
    )
    .await
}

/// How many frames the dispatch loop reads ahead while a handler runs, so that
/// the answer to a control request the handler awaits can still reach it. When
/// this many frames are waiting, the loop stops reading until the handler
/// ends; an answer stuck behind them then times out like any unanswered request.
const DISPATCH_LOOKAHEAD_FRAMES: usize = 32;

/// Read one frame and hand the reader back with it, so the loop can start the
/// next read on the same reader without holding two borrows of it.
async fn read_one<R>(reader: &mut R) -> (Result<Option<Frame>, String>, &mut R)
where
    R: AsyncRead + Unpin,
{
    let result = read_frame(reader).await.map_err(|e| e.to_string());
    (result, reader)
}

/// [`run_dispatch_loop_taking_replies`] for a loop with no control requests of
/// its own: every frame goes to `handler`, in arrival order.
#[cfg(test)]
async fn run_dispatch_loop<R, C, W, H, Fut>(
    read_half: &mut R,
    health_state: &Arc<HealthState>,
    clock: &C,
    idle_wake: &mut W,
    handler: H,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    C: cerebellum_core::clock::MonotonicClock,
    W: IdleWake,
    H: FnMut(Frame) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ModuleError>>,
{
    run_dispatch_loop_taking_replies(read_half, health_state, clock, idle_wake, Err, handler).await
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
///    partial-read state across idle wakes and across handlers; a fresh read
///    future is created only when a frame actually completes.
///
/// Handlers run one at a time, in arrival order. While one runs, the loop keeps
/// reading: `take_reply` is offered each frame read meanwhile and takes only an
/// answer to a control request this module is waiting for, which it delivers
/// at once. Every other frame waits, in order, for the handlers before it, up to
/// [`DISPATCH_LOOKAHEAD_FRAMES`]. Without this, a handler awaiting such an
/// answer would wait for a read that only its own completion can start, and
/// the request would always run out its deadline.
///
/// The end of the stream, or a read error, is reported only after the frames
/// read before it have been handled.
async fn run_dispatch_loop_taking_replies<R, C, W, T, H, Fut>(
    read_half: &mut R,
    health_state: &Arc<HealthState>,
    clock: &C,
    idle_wake: &mut W,
    mut take_reply: T,
    mut handler: H,
) -> Result<(), ModuleError>
where
    R: AsyncRead + Unpin,
    C: cerebellum_core::clock::MonotonicClock,
    W: IdleWake,
    T: FnMut(Frame) -> Result<(), Frame>,
    H: FnMut(Frame) -> Fut,
    Fut: std::future::Future<Output = Result<bool, ModuleError>>,
{
    // Stamp the initial heartbeat so a freshly-started module reports healthy.
    health_state.stamp_heartbeat_with_clock(clock);

    // One read future at a time, re-polled until it completes (see above).
    let mut read = std::pin::pin!(read_one(read_half));
    let mut waiting = std::collections::VecDeque::<Frame>::new();
    // How the stream ended, once a read has seen it end. No read is polled
    // after that.
    let mut ended: Option<Result<(), ModuleError>> = None;

    loop {
        health_state.stamp_heartbeat_with_clock(clock);
        let frame = if let Some(frame) = waiting.pop_front() {
            frame
        } else if let Some(ending) = ended.take() {
            return ending;
        } else {
            loop {
                let wake = idle_wake.next_wake();
                tokio::select! {
                    // `biased` polls the read first so an available frame is always
                    // processed before an idle re-stamp (a wake never pre-empts a
                    // ready frame), and so the wake/frame ordering is deterministic.
                    biased;
                    (result, reader) = &mut read => {
                        let Some(frame) = result.map_err(ModuleError::Message)? else {
                            return Ok(()); // clean EOF: subc closed the connection.
                        };
                        read.set(read_one(reader));
                        break frame;
                    }
                    _ = wake => {
                        // Bounded idle wake: still waiting for input (healthy), so
                        // re-stamp and keep awaiting the SAME pinned read.
                        health_state.stamp_heartbeat_with_clock(clock);
                    }
                }
            }
        };
        // The handler runs OUTSIDE the idle-wake select on purpose: a wedged
        // handler gets no re-stamp here, so it honestly goes stale (Degraded).
        let mut handling = std::pin::pin!(handler(frame));
        let keep_going = loop {
            tokio::select! {
                biased;
                result = &mut handling => break result?,
                (result, reader) = &mut read,
                    if ended.is_none() && waiting.len() < DISPATCH_LOOKAHEAD_FRAMES =>
                {
                    match result {
                        Ok(Some(frame)) => {
                            read.set(read_one(reader));
                            if let Err(frame) = take_reply(frame) {
                                waiting.push_back(frame);
                            }
                        }
                        Ok(None) => ended = Some(Ok(())),
                        Err(error) => ended = Some(Err(ModuleError::Message(error))),
                    }
                }
            }
        };
        if !keep_going {
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
    fn namespace(&self) -> usize {
        Arc::as_ptr(&self.0) as usize
    }
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
        terminal_arbiter::cancel_late_fronting_route(self.namespace(), channel, epoch);
        for ((c, e, _), handle) in self.0.lock().unwrap().iter() {
            if (*c, *e) == (channel, epoch) {
                handle.stop_terminal(TerminalCause::RouteClosed);
                handle.cancel();
            }
        }
    }

    fn stop_all(&self, cause: TerminalCause) {
        terminal_arbiter::cancel_late_fronting_all(self.namespace());
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
    agent_data: Arc<agent_data::Participant>,
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
    /// Screenshot bytes a codemode program may hand to Broca by handle.
    image_handles: Arc<image_handles::ImageHandles>,
    signed_in: Arc<browser_signed_in::SignedInDomains>,
    cancellations: RequestCancellations,
    operator_confirm: Arc<computer_capability::operator_confirm::Wire>,
    run_calls: codemode::RunCalls,
    browser_resumes: Arc<browser_held::Tasks>,
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
/// Live probes use `Isolated` too, unless they first require a scratch data
/// home so a durability probe cannot mix its records with the operator's data.
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

/// Hand a channel-0 response or error to the control request of this module's
/// that is waiting for it: operator confirmation, a claim mint or a scope query.
/// Returns whether one was waiting; an answer nobody waits for is dropped.
fn deliver_control_reply(frame: &Frame, planes: &Planes) -> bool {
    if planes.operator_confirm.deliver(frame) {
        return true;
    }
    let body = serde_json::from_slice(&frame.body).unwrap_or(serde_json::Value::Null);
    let answer = if frame.header.ty == FrameType::Response {
        scope_watch::ControlAnswer::Response(body)
    } else {
        scope_watch::ControlAnswer::Error(body)
    };
    if registration::deliver(frame.header.corr, &answer) {
        return true;
    }
    planes.scopes.control.deliver(frame.header.corr, answer)
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
        // connection (claim minting, scope queries or operator confirmation). The daemon's requests to the module
        // arrive as requests, so a response or error on channel 0 can only be
        // one of these; it is handed to whoever asked, or dropped if nobody
        // still waits. Without this arm such an answer would fall to the
        // catch-all and be dropped, so every describe would wait out its
        // deadline as if unanswered. A response or error on a route channel
        // answers nothing this module sent (it never sends requests on a
        // route), so the catch-all drops those.
        FrameType::Response | FrameType::Error if frame.header.channel == 0 => {
            deliver_control_reply(&frame, planes);
            Ok(true)
        }
        FrameType::Push if frame.header.channel == 0 => {
            if let Ok(subc_control::ClientControlPush::RouteClosed {
                module_id,
                reason: subc_protocol::RouteCloseReason::ScopeEnded,
                channels,
                ..
            }) = serde_json::from_slice(&frame.body)
            {
                if module_id == "cerebellum" {
                    let scopes: Vec<_> = planes
                        .routes
                        .inner
                        .read()
                        .expect("route bindings lock poisoned")
                        .iter()
                        .filter(|((channel, _), _)| channels.contains(channel))
                        .filter_map(|(_, facts)| {
                            facts.scope.as_ref().map(scope_watch::ScopeKey::from_stamp)
                        })
                        .collect();
                    for scope in scopes {
                        if cerebellum_core::principal::is_prefrontal(&scope.owner) {
                            // This push ends only one raw registration. Its
                            // renamed copy may still own the held call.
                            if planes.scopes.note_retained(&scope) {
                                tokio::spawn(watch_run_scope_holds(
                                    planes.clone(),
                                    writer.clone(),
                                    scope,
                                ));
                            } else {
                                planes.scopes.closed_again(&scope).notify_one();
                            }
                        } else {
                            settle_scope_holds(planes, &scope);
                        }
                    }
                }
            }
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
                    planes.browser_resumes.stop();
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
            // A retained head alias is custody for the session, not for this
            // transport. Its claims survive; only this route's in-flight calls
            // end through `cancel_route` below. Isolated routes still release.
            let closing_route = user_browser_bridge::Route {
                channel: frame.header.channel,
                epoch: frame.header.epoch,
            };
            if !planes.user_browser.target().retains_route(closing_route) {
                planes.user_browser.goodbye(closing_route);
            }
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
            planes.calls.abandon_browser_route(
                frame.header.channel,
                frame.header.epoch,
                wall_clock_ms(),
            );
            planes
                .browser_resumes
                .cancel_route(frame.header.channel, frame.header.epoch);
            if let Some(facts) = removed {
                let conversation_key = &facts.identity.conversation_key;
                let last_route = !planes.routes.carries_conversation(conversation_key);
                match facts.scope.as_ref() {
                    _ if facts.call_mode == subc_protocol::call_mode::CallMode::Codemode => {
                        // A run borrows the head conversation's browser and grants.
                        // Ending the run cancels its calls, not the head session.
                        if let Some(stamp) = facts.scope.as_ref() {
                            let key = scope_watch::ScopeKey::from_stamp(stamp);
                            if planes.calls.has_pending_scope(&held_scope_identity(&key))
                                && planes.scopes.note_closed(&key, conversation_key)
                            {
                                tokio::spawn(watch_run_scope_holds(
                                    planes.clone(),
                                    writer.clone(),
                                    key,
                                ));
                            }
                        }
                    }
                    None => {
                        // A conversation's computer grants end with its last
                        // route: another route may still carry the same
                        // conversation.
                        if last_route {
                            planes.management.end_conversation(conversation_key);
                            planes.calls.end_conversation(conversation_key);
                            planes.image_handles.end_conversation(conversation_key);
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
                            planes.image_handles.end_conversation(conversation_key);
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
            planes.browser_resumes.cancel_correlation((
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
            ));
            planes.calls.abandon_browser_correlation(
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
                wall_clock_ms(),
            );
            terminal_arbiter::cancel_late_fronting_request(
                planes.cancellations.namespace(),
                (frame.header.channel, frame.header.epoch, frame.header.corr),
            );
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
            let display = planes
                .routes
                .get(frame.header.channel, frame.header.epoch)
                .and_then(|facts| planes.routes.display.arm(&frame, &facts));
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
            let resumed_browser = browser_held::context();
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
                // Task locals do not cross spawn: carry only the already-claimed
                // browser continuation's key and consent id to its new guard.
                let dispatch = browser_held::with_context(resumed_browser, dispatch);
                let dispatch = BROWSER_CONSENT_PARK_LIMIT.scope(browser_park_limit, dispatch);
                #[cfg(any(target_os = "macos", target_os = "windows"))]
                let result = computer_capability::serialized_call(computer_arrival, dispatch).await;
                #[cfg(not(any(target_os = "macos", target_os = "windows")))]
                let result = dispatch.await;
                result
            };
            tokio::spawn(tool_display::ACTIVE.scope(
                display,
                run_arbitrated_route(
                    Box::pin(worker),
                    outgoing,
                    writer,
                    planes,
                    cancellation,
                    guard,
                    terminal,
                    arrived + Duration::from_millis(envelope_ms),
                    connection_end,
                ),
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
    tool_display::started();
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
    if facts
        .scope
        .as_ref()
        .is_some_and(|stamp| Some(&stamp.owner) != facts.principal.as_ref())
        && planes
            .routes
            .display
            .known_display_principal(facts.principal.as_ref())
    {
        let object = serde_json::from_slice::<Value>(&frame.body).ok();
        let name = object
            .as_ref()
            .and_then(|body| body["name"].as_str())
            .unwrap_or("unknown");
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "principal_denied",
            &format!("the display scope carrier may not call '{name}'; no live reads are declared"),
        )
        .await;
    }
    if facts.surface == RouteSurface::AgentData {
        return Box::pin(agent_data::handle(&frame, writer, &facts, planes)).await;
    }
    if facts.surface == RouteSurface::Management {
        let body = serde_json::from_slice::<Value>(&frame.body).ok();
        if body
            .as_ref()
            .is_some_and(|body| body["method"] == cortexkit_role_tool_display::DISPLAY_READ)
        {
            return handle_management_request_observed(frame, writer, &facts, planes, None).await;
        }
        // The tool-display contract names this op as `{name, arguments}`, the
        // shape the display server sends; cerebellum's own management ops use
        // `{method, params}`. Both reach the same read and the same caller check.
        if let Some(body) = body.filter(|body| {
            body["name"] == cortexkit_role_tool_display::DISPLAY_READ
                && body.get("method").is_none()
        }) {
            let arguments = body.get("arguments").cloned().unwrap_or(Value::Null);
            return send_display_read(
                writer,
                (ver, channel, epoch, corr),
                &facts,
                planes,
                arguments,
            )
            .await;
        }
    }
    if planes
        .routes
        .display
        .known_display_principal(facts.principal.as_ref())
    {
        let request = serde_json::from_slice::<Value>(&frame.body).ok();
        let name = request
            .as_ref()
            .and_then(|body| body["name"].as_str())
            .unwrap_or("unknown");
        if facts.surface != RouteSurface::Tools
            || !matches!(
                name,
                cortexkit_role_tool_provider::ops::TOOL_CATALOG
                    | cortexkit_role_tool_provider::ops::TOOL_VIEWS
            )
        {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "principal_denied",
                &format!(
                    "the display principal may call only tool.catalog and tool.views, not '{name}'"
                ),
            )
            .await;
        }
        return Box::pin(handle_keyed_tool_request_inner(frame, writer, planes)).await;
    }
    if private_content::is_broca(&facts.principal) {
        // Broca's privacy decision must not queue behind a browser action or
        // consent drain. Its management route has no other authority.
        let request: Option<Value> = serde_json::from_slice(&frame.body).ok();
        let method = request
            .as_ref()
            .and_then(|body| body.get("method"))
            .and_then(Value::as_str);
        if facts.surface != RouteSurface::Management
            || !matches!(
                method,
                Some(private_content::QUERY) | Some(image_handles::RESOLVE)
            )
        {
            return send_route_error(
                writer,
                ver,
                channel,
                epoch,
                corr,
                "principal_denied",
                "reserved:broca may call only private_content.query and image.resolve",
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

    let mut provider_operation = false;
    // Draining can apply a permission, so reject an unsupported tool mode before
    // reading or settling any consent answers for that call.
    if facts.surface == RouteSurface::Tools {
        if let Ok(request) = serde_json::from_slice::<Value>(&frame.body) {
            if let Some(name) = request.get("name").and_then(Value::as_str) {
                provider_operation = tool_provider::is_operation(name)
                    || name == journal::call_records::WITHDRAW_OPERATION;
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
    // Provider operations do not read or mint grants. Resolving their head
    // would make role discovery depend on consent authority and could return a
    // tool-call refusal where the caller expects a provider-operation answer.
    let worker = if facts.admits_session_calls() && !provider_operation {
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
                        codemode::CALL_MODE.scope(
                            facts.call_mode.clone(),
                            dispatch_resolved_route(frame, writer, planes, &facts),
                        ),
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
    if !browser_held::resuming() {
        if let Ok(live) = consent_drain::live_call(&frame, facts, planes) {
            // A failed drain is retried on a later call; it must not replace this
            // call's ordinary reply with a consent refusal.
            let _ = planes
                .consent_drain
                .run_recording(&planes.consent, &live, Some(&planes.calls))
                .await;
        }
        Box::pin(browser_held::run_ready(planes)).await;
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
        RouteSurface::AgentData => {
            Box::pin(agent_data::handle(&frame, writer, facts, planes)).await
        }
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

#[doc(hidden)]
pub async fn present_browser_handoff_for_test(
    planes: &Planes,
    identity: &RouteIdentity,
    origin: &str,
) -> Value {
    present_browser_handoff(planes, identity, origin, None).await
}

#[doc(hidden)]
pub async fn resume_browser_handoff_for_test(planes: &Planes, identity: &RouteIdentity) -> Value {
    resume_browser_handoff(planes, identity).await
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

/// The scope union `image.resolve` and `private_content.query` share, for
/// fixtures checking that one reaches what the other would.
#[doc(hidden)]
pub fn private_content_scope_union_for_test(
    planes: &Planes,
    scope: &str,
    parent: Option<&str>,
) -> Vec<String> {
    private_content::scope_union(planes, scope, parent)
}

/// The wall clock the handle fixtures read, so their clock matches the one
/// minting used.
pub fn wall_clock_ms_for_test() -> u64 {
    wall_clock_ms()
}

fn wall_clock_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| u64::try_from(since.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or_default()
}

fn mint_image_handle(planes: &Planes, facts: &AcceptedBindFacts, reply: &mut Value) {
    let Some(scope_ref) = private_content::capture_scope(facts) else {
        return;
    };
    let capture = image_handles::Capture {
        scope_ref,
        conversation_key: facts.identity.conversation_key.clone(),
        now_ms: wall_clock_ms(),
    };
    if let Some(handle) = planes.image_handles.mint(reply, &capture) {
        reply["image_handle"] = json!(handle);
    }
}

/// The line the model reads when its screenshot has no handle: the bytes were
/// returned, but a resolve has to send them back in one frame and they are
/// larger than that frame allows. The image itself is never re-encoded for
/// this: a handle must resolve to exactly the bytes the agent was shown.
const NO_HANDLE_NOTE: &str =
    "This screenshot is too large to be resolved by handle; take a viewport screenshot instead.";

/// Whether `reply` carries a screenshot that `mint_image_handle` left without
/// one only because it is over the size limit. A reply that got a handle, or
/// that has no image at all, is not this.
fn should_say_no_handle(reply: &Value) -> bool {
    if reply.get("image_handle").is_some() {
        return false;
    }
    reply
        .pointer("/image/data_b64")
        .and_then(Value::as_str)
        .is_some_and(|data| {
            cerebellum_core::serde_base64::decode(data)
                .is_ok_and(|bytes| bytes.len() > image_handles::IMAGE_HANDLE_MAX_BYTES)
        })
}

/// `mint_image_handle` with an explicit capture scope, for the wire fixtures:
/// they mint a handle for a scope they choose instead of a bound route.
pub fn mint_image_handle_for_test(
    planes: &Planes,
    facts: &AcceptedBindFacts,
    scope_ref: &str,
    reply: Value,
) -> Value {
    // Mint through the production path, with the capture scope the fixture
    // chose, so a fixture cannot testify to a handle production would not mint.
    let facts = facts.clone().with_scope(Some(
        subc_protocol::scope::ScopeStamp::new(
            subc_protocol::Principal::Reserved {
                module_id: "prefrontal-core".to_owned(),
            },
            scope_ref,
            1,
            subc_protocol::scope::ScopeKind::Head,
        )
        .with_owner_authorized(true),
    ));
    let mut reply = reply;
    mint_image_handle(planes, &facts, &mut reply);
    reply
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
    let body = if tool_result_v1 {
        tool_result::encode_with_held(body, held)?
    } else {
        if codemode::active() {
            // The image handle names the same bytes, so programmes this reply
            // can return a handle without the image being a round trip.
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
        // A login fill has its own result schema, outside the advertised
        // browser vocabulary, so its refusal is certified against that.
        let finished = if capability == browser::fill::FILL_LOGIN {
            planes.browser.finish_fill_reply(body)
        } else {
            planes.browser.finish_reply(capability, body)
        };
        if let Ok(body) = finished {
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
    let identity = subc_protocol::BindIdentity::new("test", "test-session".to_string());
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
    let identity = subc_protocol::BindIdentity::new("test", "test-session".to_string());
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

pub fn install_browser_unattested_project_test_bind(
    route_bindings: &Arc<RouteBindings>,
    channel: u16,
    epoch: u32,
) {
    let identity = subc_protocol::BindIdentity::new("test", "test-session".to_string());
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
    let identity = subc_protocol::BindIdentity::new("test", "test-session".to_string());
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

/// The tool path with a route stamped `scope_ref`, for fixtures whose captures
/// have to mint screenshot handles.
pub async fn handle_tool_request_for_test_with_planes_scoped(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    planes: &Planes,
    scope_ref: &str,
) -> Result<(), ModuleError> {
    install_test_bind(&planes.routes, &frame);
    let stamp = subc_protocol::scope::ScopeStamp::new(
        subc_protocol::Principal::Reserved {
            module_id: "prefrontal-core".to_owned(),
        },
        scope_ref,
        1,
        subc_protocol::scope::ScopeKind::Head,
    )
    .with_owner_authorized(true)
    .with_attributes(
        subc_protocol::scope::ScopeAttributes::new()
            .with_agent_id(Some("test-project".into()))
            .with_delegates(true),
    );
    if let Some(facts) = planes
        .routes
        .accepted_bind_for_test(frame.header.channel, frame.header.epoch)
    {
        planes.routes.insert_for_test(
            frame.header.channel,
            frame.header.epoch,
            facts.with_scope(Some(stamp)),
        );
    }
    Box::pin(tool_result::RESULT_BIND.scope(
        None,
        tool_result::SETTLEMENT_NOTE_OMITTED.scope(
            std::cell::Cell::new(false),
            tool_result::IMAGE_HANDLE_NOTE.scope(
                std::cell::RefCell::new(None),
                tool_result::APP_USE_NOTE.scope(
                    std::cell::RefCell::new(None),
                    handle_tool_request_for_test_with_existing_planes(frame, writer, planes),
                ),
            ),
        ),
    ))
    .await
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
#[path = "lib_tests/tests.rs"]
mod tests;

// ---------------------------------------------------------------------------
// Connection liveness tests.
// ---------------------------------------------------------------------------
#[cfg(test)]
#[path = "lib_tests/connection_liveness_tests.rs"]
mod connection_liveness_tests;

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
#[path = "lib_tests/dispatch_idle_tests.rs"]
mod dispatch_idle_tests;

#[cfg(test)]
#[path = "lib_tests/drain_tests.rs"]
mod drain_tests;

/// The import's consent card, filed from the prepared-plan boundary of
/// `browser.import_login` (as `drain_tests` does, so no test reads the
/// operator's own cookie stores). Nothing in the fixture's browsers holds a
/// copyable login, so the card's one granting option is `hand_off`.
#[cfg(test)]
#[path = "lib_tests/login_import_consent_tests.rs"]
mod login_import_consent_tests;

#[cfg(test)]
#[path = "lib_tests/cancel_frame_tests.rs"]
mod cancel_frame_tests;

#[cfg(all(test, unix))]
#[path = "lib_tests/sigterm_listener_tests.rs"]
mod sigterm_listener_tests;

#[cfg(all(test, target_os = "macos"))]
mod computer_consent_wire_tests;

/// A relayed `computer_use` call, driven through the production frame loop and
/// the tool handler, writes the caller behind it on its computer journal row.
#[cfg(all(test, target_os = "macos"))]
#[path = "lib_tests/relayed_computer_call_tests.rs"]
mod relayed_computer_call_tests;

#[cfg(test)]
#[path = "lib_tests/browser_login_fact_tests.rs"]
mod browser_login_fact_tests;
