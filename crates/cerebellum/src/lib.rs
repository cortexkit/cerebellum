//! ck-cerebellum library core — the subc wire seam, health-v2, identity,
//! principal default-deny, and the `browser.status` capability.
//!
//! The binary (`main.rs`) is a thin entry point that reads config from env and
//! calls [`run`]. The library exposes the module's internal handlers for
//! conformance tests.

#![forbid(unsafe_code)]

pub mod authorization;
pub mod browser;
pub mod browser_type;
pub mod capability;
pub mod cdp;
pub mod classification;
pub mod connector_evidence;
pub mod coordinate;
pub mod custody;
pub mod elicit;
pub mod journal;
pub mod journal_admin;
pub mod journal_pin;
pub mod manifest;
pub mod network;
pub mod profile;
pub mod profile_custody;
pub mod snapshot_store;
pub mod wire;

use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use serde_json::json;
use serde_json::Value;

pub use cerebellum_computer as computer;

use crate::elicit::{Elicitor, SharedElicitor};
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
    encode_browser_entry, map_late_event_cause, map_recovery_action, map_recovery_classification,
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
pub use cerebellum_core::principal::{trust_for_principal, PrincipalTrust};
pub use wire::{build_error_frame, control_flags};

const DEFAULT_MODULE_ID: &str = "cerebellum";
const HELLO_CORR: u64 = 1;
const EGRESS_BUFFER: usize = 64;
const BROWSER_STATUS_TOOL: &str = "browser.status";

/// The immutable substrate contract consumed by the computer adapter.  The
/// computer crate depends one-way on cerebellum-core; this crate only binds the
/// release identifier into the module manifest.
pub const CEREBELLUM_CORE_CONTRACT_REVISION: &str = "cerebellum-core-contract-v1";
/// The schema and revision identifiers used to describe computer capability
/// rows in release and audit evidence.
pub const COMPUTER_C2_JOURNAL_SCHEMA_ID: &str = "ck-computer-descriptor/v1";
pub const COMPUTER_C2_JOURNAL_REVISION: &str = "ck-computer-journal/v1";
pub const COMPUTER_CAPTURE_LEAKAGE_REVISION: &str = "capture-residual-leakage-v1";
pub const COMPUTER_PERMISSION_MATRIX_REVISION: &str = "permission-matrix-macos26-v1";
pub const COMPUTER_ATTENDANCE_SCHEMA_ID: &str = "ck-attendance-contract/v1";

pub use computer::platform::{
    CapabilityAdvertisementContext as ComputerCapabilityAdvertisementContext,
    CapabilityDeclaration as ComputerCapabilityDeclaration,
    ImmutableReleaseInputs as ComputerReleaseInputs, PermissionLiveness, PermissionLivenessReport,
    PermissionProbeResult, PermissionService, StartupCapabilityProbe, StartupProbeInput,
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
) -> Vec<ComputerGateOutcome> {
    let inputs = &context.inputs;
    let mut outcomes = vec![
        pin_outcome(
            "computer_action_vocabulary_revision",
            inputs.computer_action_vocabulary_revision.as_deref(),
            Some(computer::platform::COMPUTER_ACTION_VOCABULARY_REVISION),
        ),
        pin_outcome(
            "cerebellum_core_contract_revision",
            inputs.cerebellum_core_contract_revision.as_deref(),
            Some(CEREBELLUM_CORE_CONTRACT_REVISION),
        ),
        pin_outcome(
            "c2_journal_pin_schema_id",
            inputs.c2_journal_pin_schema_id.as_deref(),
            Some(COMPUTER_C2_JOURNAL_SCHEMA_ID),
        ),
        pin_outcome(
            "c2_journal_pin_revision",
            inputs.c2_journal_pin_revision.as_deref(),
            Some(COMPUTER_C2_JOURNAL_REVISION),
        ),
        pin_outcome(
            "process_identity_primitive_revision",
            inputs.process_identity_primitive_revision.as_deref(),
            Some(computer::platform::containment::PROCESS_IDENTITY_PRIMITIVE_REVISION),
        ),
        pin_outcome(
            "capture_residual_leakage_revision",
            inputs.capture_residual_leakage_revision.as_deref(),
            Some(COMPUTER_CAPTURE_LEAKAGE_REVISION),
        ),
        pin_outcome(
            "permission_matrix_revision",
            inputs.permission_matrix_revision.as_deref(),
            Some(COMPUTER_PERMISSION_MATRIX_REVISION),
        ),
        pin_outcome(
            "attendance_contract_owner",
            inputs.attendance_contract_owner.as_deref(),
            None,
        ),
        pin_outcome(
            "attendance_contract_schema_id",
            inputs.attendance_contract_schema_id.as_deref(),
            Some(COMPUTER_ATTENDANCE_SCHEMA_ID),
        ),
        pin_outcome(
            "attendance_contract_revision",
            inputs.attendance_contract_revision.as_deref(),
            None,
        ),
        pin_outcome(
            "input_review_revision",
            inputs.input_review_revision.as_deref(),
            None,
        ),
        pin_outcome(
            "capture_review_revision",
            inputs.capture_review_revision.as_deref(),
            None,
        ),
        pin_outcome(
            "release_signing_topology_revision",
            inputs.release_signing_topology_revision.as_deref(),
            None,
        ),
    ];
    let digest_inputs = &inputs.vocabulary_digests;
    outcomes.extend([
        pin_outcome(
            "vocabulary_manifest_digest",
            digest_inputs.manifest_digest.as_deref(),
            Some(computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256),
        ),
        pin_outcome(
            "vocabulary_source_lock_digest",
            digest_inputs.source_lock_digest.as_deref(),
            Some(computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256),
        ),
        pin_outcome(
            "vocabulary_computed_artifact_digest",
            digest_inputs.computed_artifact_digest.as_deref(),
            Some(computer::platform::COMPUTER_ACTION_VOCABULARY_SHA256),
        ),
    ]);
    outcomes
}

fn gate_passes(outcomes: &[ComputerGateOutcome], gate: &str) -> bool {
    let index = match gate {
        "computer_action_vocabulary_revision" => 0,
        "cerebellum_core_contract_revision" => 1,
        "c2_journal_pin_schema_id" => 2,
        "c2_journal_pin_revision" => 3,
        "process_identity_primitive_revision" => 4,
        "capture_residual_leakage_revision" => 5,
        "permission_matrix_revision" => 6,
        "attendance_contract_owner" => 7,
        "attendance_contract_schema_id" => 8,
        "attendance_contract_revision" => 9,
        "input_review_revision" => 10,
        "capture_review_revision" => 11,
        "release_signing_topology_revision" => 12,
        "vocabulary_manifest_digest" => 13,
        "vocabulary_source_lock_digest" => 14,
        "vocabulary_computed_artifact_digest" => 15,
        _ => return false,
    };
    outcomes
        .get(index)
        .is_some_and(|outcome| matches!(outcome, ComputerGateOutcome::Pass))
}

fn declaration_gate_passes(
    declaration: &ComputerCapabilityDeclaration,
    context: &ComputerCapabilityAdvertisementContext,
    outcomes: &[ComputerGateOutcome],
) -> bool {
    let common = [
        "computer_action_vocabulary_revision",
        "cerebellum_core_contract_revision",
        "c2_journal_pin_schema_id",
        "c2_journal_pin_revision",
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
                "process_identity_primitive_revision",
                "capture_residual_leakage_revision",
                "capture_review_revision",
                "release_signing_topology_revision",
            ]
            .iter()
            .all(|gate| gate_passes(outcomes, gate))
    } else if matches!(
        id,
        "computer.click"
            | "computer.type"
            | "computer.keys"
            | "computer.scroll"
            | "computer.move"
            | "computer.drag"
    ) {
        [
            "process_identity_primitive_revision",
            "permission_matrix_revision",
            "attendance_contract_owner",
            "attendance_contract_schema_id",
            "attendance_contract_revision",
            "input_review_revision",
            "release_signing_topology_revision",
        ]
        .iter()
        .all(|gate| gate_passes(outcomes, gate))
            && context.startup.private_envelope_recognized
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
    outcomes: &[ComputerGateOutcome],
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
/// stays observable while no computer capability is dispatchable. Collapsing the
/// two would make every gate look equally closed and hide which one is.
fn gate_admitted_computer_declarations<'a>(
    declarations: &'a [ComputerCapabilityDeclaration],
    context: &ComputerCapabilityAdvertisementContext,
    outcomes: &[ComputerGateOutcome],
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
) -> (Vec<ComputerCapabilityDeclaration>, Vec<ComputerGateOutcome>) {
    let driver = computer::platform::MacOs26PlatformDriver::new(&StartupProbeInput {
        os_major: context.startup.os_major,
        private_envelope_revision: if context.startup.private_envelope_recognized {
            Some(computer::platform::macos::PRIVATE_ENVELOPE_REVISION.to_string())
        } else {
            None
        },
        resolved_private_symbols: if context.startup.private_envelope_recognized {
            [computer::platform::macos::PRIVATE_PID_POST_SYMBOL.to_string()]
                .into_iter()
                .collect()
        } else {
            BTreeSet::new()
        },
        permission_results: Vec::new(),
        responsible_process: None,
    });
    let declarations = driver.declarations(context);
    let outcomes = computer_gate_outcomes(context);
    (declarations, outcomes)
}

fn computer_tool(id: &str) -> Option<subc_protocol::manifest::Tool> {
    let artifact: Value = serde_json::from_slice(include_bytes!(
        "../../cerebellum-computer/resources/computer_action_vocabulary-v1.json"
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
    for declaration in advertised_computer_declarations(&declarations, context, &outcomes) {
        if let Some(tool) = computer_tool(&declaration.capability_id) {
            tools.push(tool);
        }
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
        gate_outcomes,
    }
}

/// Serialize the ordinary manifest plus a separate, machine-readable computer
/// release evidence extension.  The extension distinguishes the frozen scope
/// from what this process actually advertises.
pub fn serialize_manifest_with_computer_plane(
    module_id: &str,
    context: &ComputerCapabilityAdvertisementContext,
) -> Value {
    let manifest = build_manifest_with_computer_plane(module_id, context);
    let mut value = serde_json::to_value(manifest).expect("module manifest serializes");
    value
        .as_object_mut()
        .expect("module manifest is an object")
        .insert(
            "computer_plane_release".to_string(),
            serde_json::to_value(computer_release_evidence(context))
                .expect("computer release evidence serializes"),
        );
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
    if name == BROWSER_STATUS_TOOL {
        Some(BROWSER_STATUS_TOOL)
    } else if browser::BrowserCapability::parse(name).is_some() {
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
#[cfg(target_os = "macos")]
fn computer_permission_readings() -> (Vec<PermissionProbeResult>, Option<String>) {
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
    // NO TEST HERE CAN CATCH THE REMOVAL OF THIS THREAD. The test harness runs
    // every test on a thread of its own -- including under --test-threads=1 --
    // so a reading taken on the caller's thread is already off-main and the
    // policy accepts it either way. The case only arises in the real binary,
    // where startup runs on the main thread. Verified there by running this
    // path inside the same runtime the binary uses: without the thread the
    // resolved liveness is unknown while the raw reading says granted, and with
    // it the resolved liveness is granted.
    std::thread::spawn(|| {
        (
            computer::platform::native::probe_permissions(),
            computer::platform::native::responsible_process(),
        )
    })
    .join()
    .unwrap_or_else(|_| (Vec::new(), None))
}

#[cfg(not(target_os = "macos"))]
fn computer_permission_readings() -> (Vec<PermissionProbeResult>, Option<String>) {
    (Vec::new(), None)
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
    let (permission_results, responsible_process) = computer_permission_readings();
    let startup = StartupCapabilityProbe::run(&StartupProbeInput {
        os_major: computer::platform::MACOS_MAJOR_VERSION,
        private_envelope_revision: None,
        resolved_private_symbols: BTreeSet::new(),
        permission_results,
        responsible_process,
    });
    ComputerCapabilityAdvertisementContext {
        inputs: ComputerReleaseInputs::default(),
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
        let health = cerebellum_core::config::load_config_file()
            .map_err(ModuleError::Config)?
            .health;
        Ok(Self {
            connection_file_path,
            module_id,
            health,
        })
    }
}

async fn run(config: ModuleConfig) -> Result<(), ModuleError> {
    let stream = connect_to_subc(&config.connection_file_path).await?;
    let (mut read_half, write_half) = tokio::io::split(stream);
    let (tx, rx) = mpsc::channel::<Frame>(EGRESS_BUFFER);
    let writer = tokio::spawn(drain_writer(write_half, rx));

    let health_state = Arc::new(HealthState::with_config(config.health));
    let route_bindings = Arc::new(RouteBindings::new());
    let browser_plane = Arc::new(BrowserPlane::new());
    let elicitor: SharedElicitor = Arc::new(Elicitor::new());
    let loop_result = module_loop(
        &mut read_half,
        tx.clone(),
        &config,
        Arc::clone(&health_state),
        Arc::clone(&route_bindings),
        browser_plane,
        elicitor,
    )
    .await;
    drop(tx);

    let writer_result = writer
        .await
        .map_err(|e| ModuleError::Message(e.to_string()));
    match (loop_result, writer_result) {
        (Err(loop_err), _) => Err(loop_err),
        (Ok(()), Ok(Ok(()))) => Ok(()),
        (Ok(()), Ok(Err(writer_err))) => Err(ModuleError::Message(writer_err.to_string())),
        (Ok(()), Err(join_err)) => Err(join_err),
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
    authenticate_client(&mut stream, &conn, std::time::Duration::from_secs(5))
        .await
        .map_err(|e| ModuleError::Message(format!("authenticate: {e}")))?;
    Ok(stream)
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
    health_state: Arc<HealthState>,
    route_bindings: Arc<RouteBindings>,
    browser_plane: Arc<BrowserPlane>,
    elicitor: SharedElicitor,
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
    let clock = health_state.clock().clone();

    let handler_health = Arc::clone(&health_state);
    let handler_routes = Arc::clone(&route_bindings);
    let handler_browser = Arc::clone(&browser_plane);
    let handler_elicitor = Arc::clone(&elicitor);
    let handler = move |frame: Frame| {
        let writer = writer.clone();
        let health = Arc::clone(&handler_health);
        let routes = Arc::clone(&handler_routes);
        let browser = Arc::clone(&handler_browser);
        let elicitor = Arc::clone(&handler_elicitor);
        async move { handle_frame(frame, &writer, &health, &routes, &browser, &elicitor).await }
    };

    run_dispatch_loop(read_half, &health_state, &clock, &mut idle_wake, handler).await
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
    body["manifest"] =
        serialize_manifest_with_computer_plane(&config.module_id, &default_computer_context());
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

/// Returns `Ok(false)` to stop the loop (graceful goodbye / EOF).
async fn handle_frame(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
    browser_plane: &Arc<BrowserPlane>,
    elicitor: &SharedElicitor,
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
            if !elicitor.deliver(frame.header.channel, frame.header.corr, body) {
                // Nobody was waiting: an answer that arrived after its deadline,
                // or a correlation this module never sent. Dropped deliberately
                // rather than acted on, because there is no exchange to complete
                // and a late answer must not revive an abandoned one.
            }
            Ok(true)
        }
        FrameType::Goodbye if frame.header.channel == 0 => Ok(false),
        FrameType::Goodbye => Ok(true),
        FrameType::Request if frame.header.channel == 0 => {
            handle_control_request(frame, writer, health_state, route_bindings).await?;
            Ok(true)
        }
        FrameType::Request => {
            let writer = writer.clone();
            let health_state = Arc::clone(health_state);
            let route_bindings = Arc::clone(route_bindings);
            let browser_plane = Arc::clone(browser_plane);
            tokio::spawn(async move {
                let _ = handle_tool_request(
                    frame,
                    &writer,
                    &health_state,
                    &route_bindings,
                    &browser_plane,
                )
                .await;
            });
            Ok(true)
        }
        _ => Ok(true),
    }
}

async fn handle_control_request(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    let request =
        serde_json::from_slice::<ModuleControlRequest>(&frame.body).map_err(ModuleError::Json)?;
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
    _health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
    browser_plane: &Arc<BrowserPlane>,
) -> Result<(), ModuleError> {
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
    let known_capability = dispatchable_tool(name);
    let Some(capability_name) = known_capability else {
        return send_route_error(
            writer,
            ver,
            channel,
            epoch,
            corr,
            "unknown_method",
            &format!("unknown method '{name}'"),
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

    if name == BROWSER_STATUS_TOOL {
        let result = handle_browser_status_for_identity(arguments, &accepted_facts.identity);
        return send_tool_response(writer, ver, channel, epoch, corr, result).await;
    }

    let result =
        browser::handle_tool(browser_plane, &accepted_facts.identity, name, arguments).await;
    send_tool_response(writer, ver, channel, epoch, corr, result).await
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

pub async fn handle_tool_request_for_test(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
) -> Result<(), ModuleError> {
    let route_bindings = Arc::new(RouteBindings::new());
    // Older unit fixtures invoke only the data-plane helper. Install a
    // synthetic accepted first-party bind so they still exercise the real
    // bound-route path without weakening the production handler.
    let identity = subc_protocol::BindIdentity {
        project_root: PathBuf::from("/test/project"),
        harness: "test".to_string(),
        session: "test-session".to_string(),
    };
    route_bindings.insert(
        frame.header.channel,
        frame.header.epoch,
        AcceptedBindFacts::from_bind(
            &identity,
            Some(subc_protocol::Principal::Direct),
            None,
            None,
            &subc_protocol::RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
        ),
    );
    handle_tool_request(
        frame,
        writer,
        health_state,
        &route_bindings,
        &Arc::new(BrowserPlane::new()),
    )
    .await
}

pub async fn handle_tool_request_for_test_with_bindings(
    frame: Frame,
    writer: &mpsc::Sender<Frame>,
    health_state: &Arc<HealthState>,
    route_bindings: &Arc<RouteBindings>,
) -> Result<(), ModuleError> {
    handle_tool_request(
        frame,
        writer,
        health_state,
        route_bindings,
        &Arc::new(BrowserPlane::new()),
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use subc_protocol::Principal;

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

        let keep_going = handle_frame(answer, &writer_tx, &health, &routes, &browser, &elicitor)
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

        let keep_going = handle_frame(
            answer,
            &writer_tx,
            &Arc::new(HealthState::default()),
            &Arc::new(RouteBindings::new()),
            &Arc::new(BrowserPlane::new()),
            &elicitor,
        )
        .await
        .expect("an unsolicited answer is handled");
        assert!(keep_going, "an unsolicited answer closed the connection");
        assert_eq!(elicitor.outstanding(), 0);
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
        assert_eq!(BROWSER_STATUS_TOOL, "browser.status");
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
        let driver = computer::platform::MacOs26PlatformDriver::default();
        let mut declarations = driver.declarations(&context);
        for declaration in &mut declarations {
            declaration.advertised = true;
        }
        declarations[0].capability_id = "computer.wait".to_string();
        let outcomes = (0..16)
            .map(|_| ComputerGateOutcome::Pass)
            .collect::<Vec<_>>();
        assert!(advertised_computer_declarations(&declarations, &context, &outcomes).is_empty());
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
