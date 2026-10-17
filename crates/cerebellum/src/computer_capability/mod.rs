//! Serving the computer plane's capabilities over the wire.
//!
//! This is the path from a tool request to the plane's policy layers: it
//! establishes that the caller may act on the application it is asking about,
//! performs the action, records it, and answers.
//!
//! THE ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE. An actuation is recorded
//! before the machine changes, and an observation whose result must be
//! accounted for is recorded before it is handed back — not merely before the
//! next action, and not asynchronously afterwards. An observation that reached
//! the caller while leaving no durable record is one nobody can account for
//! later.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use cerebellum_computer::app_state::image::{
    release_through_custody, ImageFronting, ImageUnavailable, ReleasedImage,
};
use cerebellum_computer::app_state::render::{render_state, StateHeader, StateRequest, Zoom};
// The browser plane's reply field, shared so that both planes' state reaches a
// host under one key.
use crate::browser::state_text::STATE_TEXT_FIELD;
use cerebellum_computer::app_state::person::{self, OwnInputLedger, SeenMarks};
use cerebellum_computer::app_state::session::{ElementResolution, RegisteredImage};
use cerebellum_computer::app_state::source::RunningApp;
use cerebellum_computer::app_state::source::{AppStateReadError, AppStateSource, ReadBounds};
use cerebellum_computer::app_state::AuditImageCustody;
use cerebellum_computer::audit::{
    lock_audit, AuditToken, ComputerAudit, ComputerCapability, SharedAudit,
};
use cerebellum_computer::capture::CaptureBackend;
use cerebellum_computer::dispatch::post_condition::PostCondition;
use cerebellum_computer::dispatch::{
    AttendanceContext, AttendanceLease, DispatchError, DispatchRequest, Dispatcher,
    ExpectedPostCondition, FrozenDispatchRow,
};
// Evidence is shaped on every platform: the indeterminate reply is not gated.
use cerebellum_computer::dispatch::WaitEvidence;
// The outcome and result types belong to a completed poll, which only the macOS
// handler performs -- and to the tests that shape its reply on any platform.
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_computer::dispatch::{wait_until_predicate, PlatformPredicatePoller};
#[cfg(any(target_os = "macos", target_os = "windows", test))]
use cerebellum_computer::dispatch::{WaitOutcome, WaitResult};
use cerebellum_computer::platform::containment::ContainmentRung as DispatchContainmentRung;
use cerebellum_computer::platform::vocabulary::{
    validate_capability_result, CapabilityResultValidationError,
};
use cerebellum_computer::platform::AccessibilityElementName;
#[cfg(target_os = "macos")]
pub(crate) type NativeComputerPlatformDriver = cerebellum_computer::platform::MacOs26PlatformDriver;
#[cfg(all(target_os = "macos", test))]
pub(crate) mod turn_stop_driver;
#[cfg(target_os = "windows")]
pub(crate) type NativeComputerPlatformDriver = cerebellum_computer::platform::WindowsPlatformDriver;
#[cfg(target_os = "macos")]
pub(crate) type NativeComputerCaptureBackend =
    cerebellum_computer::platform::native::NativeCaptureBackend;
#[cfg(target_os = "windows")]
pub(crate) type NativeComputerCaptureBackend =
    cerebellum_computer::platform::WindowsUnsupportedCaptureBackend;

#[cfg(target_os = "macos")]
pub(crate) fn native_capture_backend() -> NativeComputerCaptureBackend {
    NativeComputerCaptureBackend::new(std::time::Duration::from_secs(10))
}

#[cfg(target_os = "windows")]
pub(crate) fn native_capture_backend() -> NativeComputerCaptureBackend {
    cerebellum_computer::platform::WindowsUnsupportedCaptureBackend
}
use cerebellum_computer::platform::{
    blocked_chord, current_blocked_chord_platform, ActionKind, DispatchMode, EffectStatus,
    HeldStateDisposition, PermissionLiveness, PlatformDriver, SyntheticAction, SyntheticKey,
    SyntheticKeyModifiers, UnsupportedPlatformDriver,
};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::journal::JournalIdentity;
use cerebellum_core::journal::{
    CallerRefusalHistory, JournalStorage, Redactor, RefusalRing, RefusalRingConfig,
    SeverityTaxonomy,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

pub mod cursor;
mod element_actions;
pub mod image_freshness;
use image_freshness::{ImageFreshnessSource, NativeImageFreshnessSource};
mod read_image;
use read_image::ImageReadPlan;
mod held_input;
mod keystrokes;
mod open_app;
#[cfg(test)]
mod open_app_tests;
#[cfg(test)]
mod permission_tests;
mod permissions;
mod quarantine;
pub(crate) use quarantine::park_clock;
#[cfg(test)]
mod bounded_tests;
mod serialize;
#[cfg(test)]
#[cfg(target_os = "macos")]
pub(crate) use permissions::live_for_test;
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) use serialize::{arrive as computer_arrival, scope as serialized_call};
mod takeover;

use crate::computer_grants::{ConsentContext, ConsentRefusal};
use crate::management::{AppRefusal, ManagementPlane};

/// The computer plane as a running module holds it.
///
/// The parameters are fixed here rather than left open at every call site: the
/// severity table, redaction policy and storage are decisions this module makes
/// once, and spelling them at each use invites a caller substituting a different
/// redaction policy without that reading as a change of policy.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub type RunningComputerPlane = ComputerPlane<
    NativeComputerCaptureBackend,
    cerebellum_computer::audit::redaction::ExcludeApplicationText,
    cerebellum_core::journal::ValidatedSeverityTaxonomy,
    crate::PlaneJournalStorage,
    NativeComputerPlatformDriver,
>;

/// Why the computer plane cannot be assembled at boot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ComputerPlaneUnavailable {
    SeverityTaxonomy(cerebellum_computer::platform::severity::SeverityArtifactError),
    JournalStorage {
        path: PathBuf,
        error: cerebellum_core::journal::StorageError,
    },
    InvalidJournalConfiguration,
    CaptureCustody,
    AuditReconciliation(cerebellum_computer::audit::ComputerAuditError),
}

impl std::fmt::Display for ComputerPlaneUnavailable {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SeverityTaxonomy(error) => {
                write!(formatter, "the severity taxonomy is unloadable: {error}")
            }
            Self::JournalStorage { path, error } => write!(
                formatter,
                "journal storage at {} is unavailable: {error:?}",
                path.display()
            ),
            Self::InvalidJournalConfiguration => {
                formatter.write_str("the production journal configuration is invalid")
            }
            Self::CaptureCustody => formatter.write_str("capture custody could not be initialized"),
            Self::AuditReconciliation(error) => {
                write!(
                    formatter,
                    "computer audit startup reconciliation failed: {error:?}"
                )
            }
        }
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(clippy::result_large_err)]
fn reconcile_production_audit<R, T, S>(
    mut audit: ComputerAudit<R, T, S>,
    now_ms: u64,
) -> Result<ComputerAudit<R, T, S>, ComputerPlaneUnavailable>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    audit
        .startup_reconcile(now_ms)
        .map_err(ComputerPlaneUnavailable::AuditReconciliation)?;
    Ok(audit)
}

/// The audit a running module uses for the computer plane.
///
/// Every part is chosen so the capability gate can be satisfied honestly rather
/// than satisfied at all costs: the severity table is the pinned artifact, and
/// the redaction policy withholds application text rather than truncating it.
/// Binding a truncating policy here would satisfy the same gate while making an
/// application's own words durable in the journal.
///
/// The journal lives under
/// `~/.local/share/cortexkit/cerebellum/journal/computer.json`:
/// audit records are application data, not configuration. Initialization probes
/// that directory before capabilities are offered and preserves the exact refusal
/// reason instead of silently substituting process-local storage.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(clippy::result_large_err)]
pub fn production_audit() -> Result<RunningComputerAudit, ComputerPlaneUnavailable> {
    computer_audit(crate::JournalPersistence::Durable)
}

/// The audit type a module's computer plane journals through: application text
/// withheld, the pinned severity table, and a journal that is on disk or in
/// memory as the plane's [`crate::JournalPersistence`] chose.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub type RunningComputerAudit = ComputerAudit<
    cerebellum_computer::audit::redaction::ExcludeApplicationText,
    cerebellum_core::journal::ValidatedSeverityTaxonomy,
    crate::PlaneJournalStorage,
>;

/// The computer-plane audit with its journal where `persistence` says.
///
/// `Durable` is [`production_audit`]. `Isolated` keeps every other part --
/// severity table, redaction, custody bounds, startup reconciliation -- and
/// holds the journal in memory, so a test plane serves the same capabilities
/// without creating, probing or reconciling the operator's `computer.json`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[allow(clippy::result_large_err)]
pub fn computer_audit(
    persistence: crate::JournalPersistence,
) -> Result<RunningComputerAudit, ComputerPlaneUnavailable> {
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_core::journal::{
        journal_data_path, BindingError, FilesystemJournalStorage, InMemoryJournalStorage,
        JournalConfig,
    };

    // When the severity table cannot load, the computer plane has no severity
    // taxonomy, so initialization withholds every computer capability. Preserving
    // the typed failure rather than substituting a default keeps that refusal
    // diagnosable: a fabricated table would let capabilities advertise while
    // scoring their actions wrongly.
    let severity = cerebellum_computer::platform::severity::load_severity_taxonomy()
        .map_err(ComputerPlaneUnavailable::SeverityTaxonomy)?;

    // Only ever shown in the failure below, because the resolved path cannot be
    // reported when resolution is what failed. It must still name the real
    // location: an operator reading this error goes looking for the directory it
    // names, and a stale one sends them to a path nothing writes to.
    let (path, storage) = match persistence {
        crate::JournalPersistence::Durable => {
            let unresolved_path =
                PathBuf::from("~/.local/share/cortexkit/cerebellum/journal/computer.json");
            let path = journal_data_path("computer.json").map_err(|error| {
                ComputerPlaneUnavailable::JournalStorage {
                    path: unresolved_path,
                    error,
                }
            })?;
            let storage = FilesystemJournalStorage::prepare(&path).map_err(|error| {
                ComputerPlaneUnavailable::JournalStorage {
                    path: path.clone(),
                    error,
                }
            })?;
            (path, crate::PlaneJournalStorage::Filesystem(storage))
        }
        // No file exists to name, but a storage failure below still reports
        // a path; this one says where the journal was held instead.
        crate::JournalPersistence::Isolated => (
            PathBuf::from("<in-memory computer journal>"),
            crate::PlaneJournalStorage::InMemory(InMemoryJournalStorage::new()),
        ),
    };

    let custody = CaptureCustody::new(
        CustodyBounds {
            // How long a capture may take to be verified against its grant
            // before the verification is abandoned. The bound exists so a
            // window server that stops answering cannot hold a verification
            // open; the value is a starting point rather than a measurement.
            maximum_verification_duration_ms: 5_000,
            // How long a captured artifact may stay pinned awaiting its journal
            // entry. Bounded so a failure mid-write cannot retain pixels
            // indefinitely.
            maximum_pin_lifetime_ms: 30_000,
            maximum_concurrently_pinned_artifacts: 8,
            maximum_total_pinned_artifact_bytes: 64 * 1024 * 1024,
            maximum_custody_attachment_bytes: 16 * 1024 * 1024,
        },
        InMemoryGrantAuthority::default(),
        InMemoryCustodyStorage::new(),
    )
    .map_err(|_| ComputerPlaneUnavailable::CaptureCustody)?;

    let audit = ComputerAudit::new(
        cerebellum_computer::audit::redaction::ExcludeApplicationText,
        severity,
        JournalConfig {
            journal_retention_bytes: 8 * 1024 * 1024,
            journal_max_entry_bytes: 64 * 1024,
        },
        storage,
        custody,
    )
    .map_err(|error| match error {
        BindingError::Storage(error) => ComputerPlaneUnavailable::JournalStorage { path, error },
        BindingError::InvalidConfiguration => ComputerPlaneUnavailable::InvalidJournalConfiguration,
    })?;

    reconcile_production_audit(audit, 0)
}

/// A capability this module can serve, which cannot be constructed any other way.
///
/// A newtype rather than a plain capability because the alternative is a comment
/// claiming that only servable capabilities reach the handler, which nothing
/// enforces: `serve` is public, and a caller holding any capability could pass
/// one that has no implementation. Making the value unconstructible except
/// through the check means the handler's exhaustive match has no arm that exists
/// only to answer a case the type already excludes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Servable(Served);

/// The capabilities with a wire handler. Kept apart from
/// [`ComputerCapability`], which also names rows nothing serves yet and
/// retired capabilities the journal still reads, so the handler's match covers
/// exactly what it serves and nothing it would have to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Served {
    ReadState,
    PressElement,
    PressPoint,
    WriteText,
    Type,
    Keys,
    TakeoverMove,
    TakeoverDrag,
    TakeoverScroll,
    Wait,
    ListApps,
    OpenApp,
}

impl Servable {
    pub fn capability(self) -> ComputerCapability {
        match self.0 {
            Served::ReadState => ComputerCapability::ReadState,
            Served::PressElement => ComputerCapability::PressElement,
            Served::PressPoint => ComputerCapability::PressPoint,
            Served::WriteText => ComputerCapability::WriteText,
            Served::Type => ComputerCapability::Type,
            Served::Keys => ComputerCapability::Keys,
            Served::TakeoverMove => ComputerCapability::TakeoverMove,
            Served::TakeoverDrag => ComputerCapability::TakeoverDrag,
            Served::TakeoverScroll => ComputerCapability::TakeoverScroll,
            Served::Wait => ComputerCapability::Wait,
            Served::OpenApp => ComputerCapability::OpenApp,
            Served::ListApps => ComputerCapability::ListApps,
        }
    }
}

/// The computer-plane capabilities this module can actually serve.
///
/// Returns the capability rather than a boolean so a caller cannot ask about one
/// name and act on another. A capability absent here is one the manifest must
/// not advertise: advertising what cannot be served tells a caller it has a
/// facility that does not exist, and it discovers otherwise only by using it.
///
/// Every capability is listed by name rather than covered by a wildcard, so
/// adding one does not silently make it servable here: the match stops
/// compiling until the new capability is admitted or refused by name. A
/// retired capability id never reaches this match at all, because it parses to
/// no capability.
pub fn servable(name: &str) -> Option<Servable> {
    let served = match ComputerCapability::parse(name)? {
        ComputerCapability::Type => Served::Type,
        ComputerCapability::Keys => Served::Keys,
        ComputerCapability::Wait => Served::Wait,
        ComputerCapability::ReadState => Served::ReadState,
        ComputerCapability::PressElement => Served::PressElement,
        ComputerCapability::PressPoint => Served::PressPoint,
        ComputerCapability::WriteText => Served::WriteText,
        ComputerCapability::TakeoverMove => Served::TakeoverMove,
        ComputerCapability::TakeoverDrag => Served::TakeoverDrag,
        ComputerCapability::TakeoverScroll => Served::TakeoverScroll,
        ComputerCapability::OpenApp => Served::OpenApp,
        ComputerCapability::ListApps => Served::ListApps,
        // Readable from the journal only; never served.
        ComputerCapability::Click
        | ComputerCapability::Scroll
        | ComputerCapability::Move
        | ComputerCapability::Drag
        | ComputerCapability::Screenshot => return None,
    };
    Some(Servable(served))
}

/// Who is asking, and what this module needs to answer them.
///
/// Bundled rather than passed one by one because these travel together through
/// every capability: the identity that authorises the action is the same one
/// that appears in its journal entry, and separating them invites a handler
/// that authorises against one identity and records another.
pub struct ServeContext<'a, C: MonotonicClock> {
    /// The durable agent identity the action is attributed to.
    ///
    /// It must come from the route's accepted bind rather than from the
    /// request body: an identity a request can choose is a permission granted
    /// to whoever asks for it. This type cannot check that, which is why it is
    /// said here. The same holds for the identity inside `consent`, which
    /// decides which grants apply.
    pub grantee: &'a str,
    pub cancel: crate::CancelHandle,
    pub identity: JournalIdentity,
    pub management: &'a Arc<ManagementPlane>,
    /// Who is asking for which grant, how to ask the person, and what ends a
    /// wait for their answer.
    pub consent: ConsentContext,
    pub clock: &'a C,
    pub now_ms: u64,
}

impl<C: MonotonicClock> Clone for ServeContext<'_, C> {
    fn clone(&self) -> Self {
        Self {
            grantee: self.grantee,
            cancel: self.cancel.clone(),
            identity: self.identity.clone(),
            management: self.management,
            consent: ConsentContext {
                caller: self.consent.caller.clone(),
                unattended: self.consent.unattended,
                agent_run: self.consent.agent_run,
                carrier: self.consent.carrier.clone(),
                route: self.consent.route.clone(),
                drain: self.consent.drain.clone(),
                park_guard: self.consent.park_guard.clone(),
                park_limit: self.consent.park_limit,
            },
            clock: self.clock,
            now_ms: self.now_ms,
        }
    }
}

/// What the serving boundary does after detecting a result-schema violation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ResultSchemaEnforcement {
    /// Record the violation and preserve the reply while differences between
    /// the frozen result schemas and current serving behavior are identified and
    /// resolved.
    #[default]
    DetectOnly,
    /// Record the violation and withhold the reply. Enable this fail-closed mode
    /// only after all differences between the frozen result schemas and current
    /// serving behavior have been identified and resolved.
    Withhold,
}

/// One distinct result-schema violation observed at the serving boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResultSchemaFinding {
    pub error: CapabilityResultValidationError,
    pub occurrences: u64,
}

/// The typed detail retained when the session floor refuses a key chord.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ComputerRefusalReason {
    pub chord: String,
    pub reason: String,
}

/// What a served capability needs beyond the request itself.
///
/// The synthetic driver is the platform object that translates and posts input
/// events. It is a factory rather than an instance because a driver is
/// stateful -- the macOS one caches accessibility trees -- so each dispatch
/// builds a fresh one, the same discipline the click handler applies. The
/// default refuses every operation: a plane that was never given a real driver
/// can still serve observations, and an input action reaching it gets an
/// ordinary refusal rather than a panic.
pub struct ComputerPlane<B, R, T, S, D = UnsupportedPlatformDriver>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    /// Locked only for each journal step, never across platform work: one
    /// hung application must not stall journaling for every other one.
    audit: SharedAudit<R, T, S>,
    serializer: serialize::Serializer,
    /// Whether input this plane posted may still be held down.
    held_input: Arc<held_input::HeldInput>,
    /// Startup-only readings, retained so a grant made while running cannot
    /// silently enable dispatch before the module has restarted.
    permissions: cerebellum_computer::platform::PermissionLivenessReport,
    /// The capture backend type a pixel-returning row will capture with. No
    /// served row captures today, so nothing is held; the type stays so the
    /// plane's shape does not change when the state read's image arrives.
    capture_backend: std::marker::PhantomData<fn() -> B>,
    /// Where application state is read from: the platform's accessibility
    /// reader in a running module, a fixture in tests.
    app_state_source: Arc<dyn AppStateSource>,
    launch_history: Arc<crate::open_app_history::LaunchHistory>,
    image_freshness_source: Arc<dyn ImageFreshnessSource>,
    result_schema_enforcement: ResultSchemaEnforcement,
    result_schema_findings: StdMutex<BTreeMap<CapabilityResultValidationError, u64>>,
    refusal_ring: Mutex<RefusalRing<ComputerRefusalReason>>,
    make_synthetic_driver: Arc<dyn Fn() -> D + Send + Sync>,
    /// Whether this build's release review admits the fronting bracket, the
    /// only way keystrokes reach an application in the background. Without
    /// it such keystrokes are refused, and the refusal names only what the
    /// build can do instead.
    fronting_bracket_admitted: bool,
    /// Records when this module posted input, so an action's check for the
    /// person's use of an application does not mistake this module's own
    /// posts for the person's. One ledger for every conversation: a post
    /// counts as this module's whichever conversation asked for it.
    own_input: Arc<OwnInputLedger>,
    cursor: cursor::Coordinator,
    /// The screen-lock reading this crate's own tests serve under, in place of
    /// the machine's. Tests that drive the production plane through the frame
    /// loop must not refuse or disclose according to whether the developer's
    /// screen happens to be locked while they run.
    #[cfg(test)]
    session_lock_for_test: Option<Option<bool>>,
}

impl<B, R, T, S> ComputerPlane<B, R, T, S, UnsupportedPlatformDriver>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
{
    pub fn new(audit: ComputerAudit<R, T, S>) -> Self {
        Self::with_result_schema_enforcement(audit, ResultSchemaEnforcement::DetectOnly)
    }

    /// Construct a plane with an explicit result-schema enforcement mode.
    ///
    /// Production remains detect-only until differences between the frozen
    /// result schemas and current serving behavior have been identified and
    /// resolved. After that, use `Withhold` as the serving-boundary mode to
    /// prevent a divergent reply from being returned.
    pub fn with_result_schema_enforcement(
        audit: ComputerAudit<R, T, S>,
        result_schema_enforcement: ResultSchemaEnforcement,
    ) -> Self {
        Self::assemble(
            audit,
            result_schema_enforcement,
            Arc::new(UnsupportedPlatformDriver::new),
        )
    }
}

impl<B, R, T, S, D> ComputerPlane<B, R, T, S, D>
where
    B: CaptureBackend + Send + 'static,
    R: Redactor + Send + 'static,
    T: SeverityTaxonomy + Send + 'static,
    S: JournalStorage + Send + 'static,
    D: PlatformDriver + 'static,
{
    /// Construct a plane whose input actions dispatch through the driver this
    /// factory builds.
    ///
    /// This is the only construction under which the five input capabilities
    /// can post an event; [`ComputerPlane::new`] answers them with the
    /// refusing default driver instead.
    pub fn with_synthetic_driver(
        audit: ComputerAudit<R, T, S>,
        make_synthetic_driver: impl Fn() -> D + Send + Sync + 'static,
    ) -> Self {
        Self::with_synthetic_driver_and_result_schema_enforcement(
            audit,
            ResultSchemaEnforcement::DetectOnly,
            make_synthetic_driver,
        )
    }

    /// Construct a synthetic-input plane with an explicit result-schema policy.
    pub fn with_synthetic_driver_and_result_schema_enforcement(
        audit: ComputerAudit<R, T, S>,
        result_schema_enforcement: ResultSchemaEnforcement,
        make_synthetic_driver: impl Fn() -> D + Send + Sync + 'static,
    ) -> Self {
        Self::assemble(
            audit,
            result_schema_enforcement,
            Arc::new(make_synthetic_driver),
        )
    }

    fn assemble(
        audit: ComputerAudit<R, T, S>,
        result_schema_enforcement: ResultSchemaEnforcement,
        make_synthetic_driver: Arc<dyn Fn() -> D + Send + Sync>,
    ) -> Self {
        Self {
            audit: Arc::new(StdMutex::new(audit)),
            serializer: serialize::Serializer::default(),
            held_input: Arc::default(),
            permissions: crate::default_computer_context().startup.permissions,
            capture_backend: std::marker::PhantomData,
            app_state_source: native_app_state_source(),
            launch_history: Arc::new(crate::open_app_history::LaunchHistory::in_memory()),
            image_freshness_source: Arc::new(NativeImageFreshnessSource),
            result_schema_enforcement,
            result_schema_findings: StdMutex::new(BTreeMap::new()),
            refusal_ring: Mutex::new(
                RefusalRing::new_in_memory(RefusalRingConfig {
                    records_per_caller: 16,
                })
                .expect("the fixed computer refusal-ring capacity is valid"),
            ),
            make_synthetic_driver,
            fronting_bracket_admitted: false,
            own_input: Arc::new(OwnInputLedger::new()),
            cursor: cursor::Coordinator::default(),
            #[cfg(test)]
            session_lock_for_test: None,
        }
    }

    /// Supply the immutable startup readings used for call-time admission.
    /// Tests inject readings here instead of depending on the host's TCC state.
    pub fn with_permission_liveness(
        mut self,
        permissions: cerebellum_computer::platform::PermissionLivenessReport,
    ) -> Self {
        self.permissions = permissions;
        self
    }

    // Only a platform that builds a computer plane opens the durable store; on
    // Linux nothing calls this outside tests.
    #[cfg_attr(not(any(target_os = "macos", target_os = "windows")), allow(dead_code))]
    pub(crate) fn with_launch_history(
        mut self,
        history: crate::open_app_history::LaunchHistory,
    ) -> Self {
        self.launch_history = Arc::new(history);
        self
    }

    /// Serve as though the screen-lock reading were `state`, whatever the
    /// machine running the test reports. Only the macOS frame-loop tests
    /// serve the production plane, so it is compiled for them alone.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn with_session_lock_for_test(mut self, state: Option<bool>) -> Self {
        self.session_lock_for_test = Some(state);
        self
    }

    /// Allow keystrokes to reach an application in the background by bringing
    /// it forward briefly. Only a build whose release carries the review of
    /// that mechanism sets this; without it such keystrokes are refused.
    pub fn with_fronting_bracket_admitted(mut self, admitted: bool) -> Self {
        self.fronting_bracket_admitted = admitted;
        self
    }

    /// Read application state from `source` instead of the platform's reader.
    pub fn with_app_state_source(mut self, source: Arc<dyn AppStateSource>) -> Self {
        self.app_state_source = source;
        self
    }

    pub fn cursor(&self) -> cursor::Coordinator {
        self.cursor.clone()
    }

    /// Inject a memory-only cursor transport for deterministic desk doubles.
    #[doc(hidden)]
    pub fn with_cursor(mut self, cursor: cursor::Coordinator) -> Self {
        self.cursor = cursor;
        self
    }

    /// Read image freshness from `source` instead of the window server.
    pub fn with_image_freshness_source(mut self, source: Arc<dyn ImageFreshnessSource>) -> Self {
        self.image_freshness_source = source;
        self
    }

    /// How many journal sequences have been allocated.
    ///
    /// Exposed so a test can establish that an action was recorded WITHOUT
    /// reading the entries themselves, which would put a test in the position of
    /// interpreting the journal's contents to decide whether it was written to.
    pub async fn journal_entry_count(&self) -> u64 {
        lock_audit(&self.audit).journal().next_sequence()
    }

    /// The lifecycle state one journal obligation settled into, if it exists.
    ///
    /// Exposed so a test can establish that a dispatch outcome was FINALISED
    /// before the caller was answered -- a count of entries cannot distinguish
    /// a completed record from one left open mid-flight.
    pub async fn obligation_lifecycle(
        &self,
        action_obligation_id: u64,
    ) -> Option<cerebellum_core::journal::LifecycleState> {
        lock_audit(&self.audit)
            .read_obligation_audit(action_obligation_id)
            .ok()
            .map(|record| record.lifecycle)
    }

    /// Typed session-floor refusals retained for one caller.
    #[doc(hidden)]
    pub async fn refusal_history_for_test(
        &self,
        caller: &str,
    ) -> Option<CallerRefusalHistory<ComputerRefusalReason>> {
        self.refusal_ring.lock().await.history(caller).cloned()
    }

    /// Distinct result-schema violations detected so far, with occurrence counts.
    pub fn result_schema_findings(&self) -> Vec<ResultSchemaFinding> {
        let findings = self
            .result_schema_findings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        findings
            .iter()
            .map(|(error, occurrences)| ResultSchemaFinding {
                error: error.clone(),
                occurrences: *occurrences,
            })
            .collect()
    }

    fn finish_reply(
        &self,
        capability: ComputerCapability,
        reply: Value,
    ) -> Result<Value, CapabilityResultValidationError> {
        match validate_capability_result(capability.capability_id(), &reply) {
            Ok(()) => Ok(reply),
            Err(error) => {
                let mut findings = self
                    .result_schema_findings
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let occurrences = findings.entry(error.clone()).or_default();
                *occurrences = occurrences.saturating_add(1);
                drop(findings);

                match self.result_schema_enforcement {
                    ResultSchemaEnforcement::DetectOnly => Ok(reply),
                    ResultSchemaEnforcement::Withhold => Err(error),
                }
            }
        }
    }

    /// Serve one capability, detecting result-schema divergence before any reply
    /// leaves this common boundary.
    ///
    /// Detect-only mode records and preserves today's divergent replies. In
    /// withholding mode a violation is returned separately, so the wire can say
    /// that the operation may have happened without misreporting it as an action
    /// failure.
    pub async fn serve<C: MonotonicClock>(
        &self,
        capability: Servable,
        arguments: &Value,
        mut context: ServeContext<'_, C>,
        // The capture backend for the state read's window image, the one
        // served row that returns pixels.
        make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Result<Value, CapabilityResultValidationError> {
        // Before target lookup, consent or any platform work: offering a tool
        // does not imply the startup permission readings allow it to execute.
        if let Some(reply) = permissions::refusal(capability.capability(), &self.permissions) {
            let reply = match capability.0 {
                Served::Type | Served::Keys => {
                    synthetic_wire_envelope(keystrokes::refused_before_posting(reply))
                }
                _ => reply,
            };
            return self.finish_reply(capability.capability(), reply);
        }
        let admitted = match self.serialize(capability, arguments, &mut context).await {
            Ok(admitted) => admitted,
            Err(refusal) => {
                return self.finish_reply(
                    capability.capability(),
                    serialize::queued_refusal(capability, arguments, refusal),
                );
            }
        };
        // Execution-lane acquisition: the call's work budget starts here, and
        // so does its claim on blocking-worker capacity. Both permits are
        // taken now or the call is refused before anything is dispatched; no
        // permit is taken later, so exhaustion can never strike between an
        // action and the observation or release that follows it.
        let capability_id = capability.capability().capability_id();
        let Some(permits) = self.serializer.permits.try_call() else {
            return self.finish_reply(
                capability.capability(),
                serialize::refused_in_queue(
                    capability,
                    quarantine::capacity_exhausted_reply("queue", capability_id),
                ),
            );
        };
        if let Some(stuck) = self
            .serializer
            .quarantine
            .busy(None, None, admitted.app.as_deref())
        {
            return self.finish_reply(
                capability.capability(),
                serialize::refused_in_queue(
                    capability,
                    quarantine::target_busy_reply(stuck, "queue"),
                ),
            );
        }
        let terminal = crate::TerminalArbiter::current();
        let lease =
            self.serializer
                .quarantine
                .enter(admitted.app.clone(), capability_id, terminal.clone());
        let budget = capability_id
            .strip_prefix("computer.")
            .and_then(crate::budgets::computer)
            .map_or(crate::budgets::MAX_ACTION_WORK_MS, |budget| budget.work_ms);
        let work = quarantine::CallWork::new(
            terminal,
            std::time::Duration::from_millis(budget),
            Some(lease),
            Some(Arc::new(permits)),
        );
        let _lane = admitted.lane;
        // A locked screen hides application interfaces and cannot admit a new
        // launch either, so no call may mistake hidden windows for an
        // application with nothing there. Read after taking the app lock: the
        // screen may have locked while this call was queued, and consent and
        // dispatch must see that current reading.
        let lock_state = self.session_locked();
        if lock_state == Some(true) {
            let reply = match capability.0 {
                Served::Type | Served::Keys => synthetic_wire_envelope(
                    keystrokes::refused_before_posting(screen_locked_reply()),
                ),
                _ => screen_locked_reply(),
            };
            return self.finish_reply(capability.capability(), reply);
        }
        let grant_cancel = context.cancel.clone();
        let matched_app = Arc::new(std::sync::Mutex::new(None));
        // Capability work holds the app-consent wait and eventual platform
        // call. Keep that future on the heap before the grant watcher adds
        // polling and cancellation-cleanup frames around it.
        let mut reply = MATCHED_APP
            .scope(
                Arc::clone(&matched_app),
                crate::grant_enforcement::scope(
                    grant_cancel,
                    Box::pin(work.scope(async {
                        match capability.0 {
                            Served::ReadState => {
                                self.serve_read_state(arguments, context, make_backend)
                                    .await
                            }
                            Served::Wait => self.serve_wait(arguments, context).await,
                            Served::OpenApp => self.serve_open_app(arguments, context).await,
                            Served::ListApps => self.serve_list_apps(arguments, context).await,
                            Served::PressElement => {
                                self.serve_press_element(arguments, context).await
                            }
                            Served::PressPoint => self.serve_press_point(arguments, context).await,
                            Served::WriteText => self.serve_write_text(arguments, context).await,
                            Served::Type => synthetic_wire_envelope(
                                self.serve_synthetic(ComputerCapability::Type, arguments, context)
                                    .await,
                            ),
                            Served::Keys => synthetic_wire_envelope(
                                self.serve_synthetic(ComputerCapability::Keys, arguments, context)
                                    .await,
                            ),
                            Served::TakeoverMove => {
                                self.serve_takeover(
                                    ComputerCapability::TakeoverMove,
                                    arguments,
                                    context,
                                )
                                .await
                            }
                            Served::TakeoverDrag => {
                                self.serve_takeover(
                                    ComputerCapability::TakeoverDrag,
                                    arguments,
                                    context,
                                )
                                .await
                            }
                            Served::TakeoverScroll => {
                                self.serve_takeover(
                                    ComputerCapability::TakeoverScroll,
                                    arguments,
                                    context,
                                )
                                .await
                            }
                        }
                    })),
                ),
            )
            .await;
        // A target that named a running application only in part was taken
        // to mean the one application it fits; the reply names it, so the
        // caller can tell if that was not the application it meant.
        let matched_app = matched_app
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take();
        if let (Some(name), Some(object)) = (matched_app, reply.as_object_mut()) {
            object.insert("matched_app".into(), json!(name));
        }
        // The call went ahead without knowing whether the screen was locked.
        // Said on the reply so an empty tree or a missing element is not
        // taken for an application that has nothing there.
        if lock_state.is_none() {
            if let Some(object) = reply.as_object_mut() {
                object.insert("screen_lock_state".into(), json!("unknown"));
            }
        }
        self.finish_reply(capability.capability(), reply)
    }

    /// Whether the screen is locked now, read fresh from the platform driver.
    fn session_locked(&self) -> Option<bool> {
        #[cfg(test)]
        if let Some(state) = self.session_lock_for_test {
            return state;
        }
        (self.make_synthetic_driver)().session_locked()
    }

    /// The refusal for a call whose wait for the person's answer ended with
    /// the screen locked, or `None` when it may go on. `admission` supplies
    /// the grant-persistence disclosure the refusal still carries.
    ///
    /// A consent question can hold a call for minutes, and the person may lock
    /// the screen meanwhile, so the check made when the call arrived no longer
    /// holds. Nothing is acted on; the grant the answer produced stays held,
    /// so a retry once the screen is unlocked is admitted without asking again.
    fn locked_after_wait(
        &self,
        waited: bool,
        admission: &crate::computer_grants::GrantAdmission,
    ) -> Option<Value> {
        if !waited || self.session_locked() != Some(true) {
            return None;
        }
        let mut reply = screen_locked_reply();
        admission.decorate(&mut reply);
        Some(reply)
    }

    /// Read the named application's state as a text tree, numbering its
    /// elements for this conversation, with one image of its frontmost window
    /// when asked for.
    ///
    /// The read resets the diff baseline that later actions report against.
    /// Filters narrow what is shown, never what is read, so the baseline
    /// always covers everything the read reached.
    async fn serve_read_state<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
        make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Value {
        let mut parsed = match parse_read_state_request(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };
        parsed.target = match self.resolve_target_name(&parsed.target).await {
            Ok(bundle_identity) => bundle_identity,
            Err(refusal) => return refusal,
        };
        let ServeContext {
            cancel,
            grantee: _,
            identity,
            management,
            consent,
            clock: _,
            now_ms,
        } = context;
        let (grant, admission) = match management
            .admit_app(&parsed.target, &consent, &cancel)
            .await
        {
            Ok(admitted) => admitted,
            Err(AppRefusal::Consent(ConsentRefusal::Cancelled)) => {
                return json!({"outcome": "cancelled"})
            }
            Err(refusal) => return refusal.reply(&parsed.target),
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return locked;
        }
        let work = quarantine::CallWork::current();
        if let Some(mut busy) = work.bind(&self.serializer.quarantine, &grant) {
            admission.decorate(&mut busy);
            return busy;
        }
        let takeover = !consent.unattended
            && parsed.include_image
            && parsed.bring_to_front
            && management.computer_grants().retain_held(
                &consent.caller,
                &crate::computer_grants::GrantNeed::Takeover,
            );
        if parsed.include_image && parsed.bring_to_front && takeover {
            if let Some(mut refusal) = self
                .refuse_if_person_changed(management, &identity.conversation_key, &grant)
                .await
            {
                admission.decorate(&mut refusal);
                return refusal;
            }
        }
        let sessions = management.app_state_sessions().clone();
        let conversation_key = identity.conversation_key.clone();

        // An id from another application, another process generation or
        // another conversation names nothing here; refused before reading so
        // the caller learns it at once.
        let zoom = parsed.zoom.as_deref().map(Zoom::parse);
        if let Some(Zoom::Element(zoomed)) = zoom {
            match sessions.resolve(&conversation_key, zoomed) {
                ElementResolution::Live {
                    bundle_identity,
                    pid,
                    process_generation,
                    ..
                } if bundle_identity == grant.bundle_identity
                    && pid == grant.pid
                    && process_generation == grant.process_generation_evidence => {}
                ElementResolution::PreviousRun => {
                    let mut reply = element_actions::previous_run_reply();
                    admission.decorate(&mut reply);
                    return reply;
                }
                _ => {
                    let mut reply = stale_zoom_reply();
                    admission.decorate(&mut reply);
                    return reply;
                }
            }
        }

        let source = self.app_state_source.clone();
        let read_grant = grant.clone();
        self.cursor.schedule(
            cursor::Identity::current(identity.agent_project_id.clone()),
            cerebellum_computer::cursor::CursorKind::Reading,
            grant.clone(),
            self.app_state_source.clone(),
            None,
            None,
        );
        let expand_menus =
            sessions.zoom_expands_menus(&conversation_key, &grant, parsed.zoom.as_deref());
        let read_work = work.clone();
        let read = tokio::task::spawn_blocking(move || {
            let _ax = read_work.bound_ax();
            // Expanding menus presses them, so it is a mutation: a call stopped
            // while it waited for this worker reads nothing further.
            if expand_menus && !read_work.begin_mutation() {
                return None;
            }
            let _scope =
                cerebellum_computer::audit::AccessibilityReadScope::new(read_grant.pid, None);
            // Read before the tree, so a change the person makes while the
            // tree is read shows up at the next action rather than passing
            // as something this read showed.
            let seen = SeenMarks::read(source.as_ref(), &read_grant);
            let raw = if expand_menus {
                source.read_app_state_expanding_menus(&read_grant, ReadBounds::default())
            } else {
                source.read_app_state(&read_grant, ReadBounds::default())
            };
            Some((
                raw,
                cerebellum_computer::audit::AccessibilityReadScope::current(),
                Some(seen),
            ))
        })
        .await
        .unwrap_or(Some((Err(AppStateReadError::Unreadable), None, None)));
        let Some((raw, manual_accessibility, seen)) = read else {
            return quarantine::stopped_before_dispatch_reply();
        };
        let mut raw = match raw {
            Ok(raw) => raw,
            Err(AppStateReadError::TargetGone) => {
                let mut reply = json!({
                    "outcome": "not_running",
                    "bundle_identity": parsed.target,
                    "remedy": "the application quit while it was being read; start it and read again",
                });
                admission.decorate(&mut reply);
                return reply;
            }
            Err(error) => {
                let summary = cerebellum_computer::app_state::ReadStateSummary {
                    grant_identity: grant.clone(),
                    element_count: 0,
                    unreadable_subtrees: 1,
                };
                let mut reply = if self
                    .journal_state_read(
                        identity,
                        summary,
                        manual_accessibility,
                        now_ms,
                        None,
                        ImageReadPlan {
                            requested: parsed.include_image,
                            ..Default::default()
                        },
                    )
                    .await
                    .is_ok()
                {
                    unreadable_application_reply(error)
                } else {
                    read_audit_unavailable_reply()
                };
                admission.decorate(&mut reply);
                return reply;
            }
        };

        let unpopulated = raw.mark_unpopulated_content();
        let observed = sessions.observe(&conversation_key, &grant, &raw);
        let app_name = management.application_name(&grant);
        let mut rendered = render_state(
            &StateHeader {
                app_name: &app_name,
                focused_element_id: observed.focused_element_id.as_deref(),
            },
            &observed.roots,
            &StateRequest {
                zoom,
                roles: &parsed.role_filter,
                text: parsed.text_filter.as_deref(),
            },
        );
        if unpopulated > 0 {
            rendered.text.push_str("Accessibility content incomplete: a window or web area exposes only an empty shell; it may still be loading. Read again.\n");
        }
        if !rendered.zoom_found {
            let mut reply = stale_zoom_reply();
            admission.decorate(&mut reply);
            return reply;
        }

        let mut reply = json!({
            "outcome": "completed",
            STATE_TEXT_FIELD: rendered.text,
            "unreadable_subtrees": observed.unreadable_subtrees,
        });
        if let Some(focused) = observed.focused_element_id {
            reply["focused_element_id"] = json!(focused);
        }
        if let Some(truncation) = rendered.truncation {
            reply["truncation"] = json!({
                "reason": truncation.reason.as_str(),
                "omitted_elements": truncation.omitted_elements,
            });
        }
        fn count_elements(nodes: &[cerebellum_computer::app_state::source::RawElement]) -> usize {
            nodes
                .iter()
                .map(|node| 1 + count_elements(&node.children))
                .sum()
        }
        let summary = cerebellum_computer::app_state::ReadStateSummary {
            grant_identity: grant.clone(),
            element_count: count_elements(&raw.roots),
            unreadable_subtrees: raw.unreadable_subtrees,
        };
        // Screen Recording serves only the optional image, never the tree.
        // Do not construct a capture backend when the startup reading was not
        // live: a later grant still requires restarting this plane.
        let image_permission_live = self
            .permissions
            .state(cerebellum_computer::platform::PermissionService::ScreenRecording)
            == PermissionLiveness::Live;
        match self
            .journal_state_read(
                identity,
                summary,
                manual_accessibility,
                now_ms,
                (parsed.include_image && image_permission_live).then(|| make_backend(&grant)),
                ImageReadPlan {
                    requested: parsed.include_image,
                    bring_to_front: parsed.bring_to_front,
                    takeover,
                    bracket_admitted: self.fronting_bracket_admitted,
                    cancel: Some(cancel),
                    now_ms,
                    gate: None,
                },
            )
            .await
        {
            Ok((Some(image), _, fronting)) => {
                if let Some(fronting) = fronting {
                    reply["image_fronting"] = json!(fronting);
                }
                let image_id = sessions.register_image(
                    &conversation_key,
                    RegisteredImage {
                        bundle_identity: grant.bundle_identity.clone(),
                        pid: grant.pid,
                        process_generation: grant.process_generation_evidence.clone(),
                        width_px: image.width_px,
                        height_px: image.height_px,
                        mapping: image.mapping,
                    },
                );
                reply["image"] = json!({
                    "image_id": image_id,
                    "mime": "image/jpeg",
                    "data_b64": cerebellum_core::serde_base64::encode(&image.jpeg),
                    "width_px": image.width_px,
                    "height_px": image.height_px,
                });
            }
            Ok((None, Some(reason), fronting)) => {
                reply["image_unavailable"] = json!({"reason": reason.as_str()});
                if reason == ImageUnavailable::ImageNeedsTakeover {
                    reply["image_unavailable"]["detail"] = json!({
                        "grant": "takeover", "grant_label": "control of your mouse and keyboard",
                        "scope": {"takeover": "machine"},
                    });
                }
                if let Some(fronting) = fronting {
                    reply["image_fronting"] = json!(fronting);
                }
            }
            Ok((None, None, _)) => {
                if parsed.include_image && !image_permission_live {
                    reply["image_unavailable"] = json!({
                        "reason": ImageUnavailable::ScreenRecordingNotLive.as_str(),
                    });
                }
            }
            Err(_) => {
                let mut refusal = read_audit_unavailable_reply();
                admission.decorate(&mut refusal);
                return refusal;
            }
        }
        // The conversation is shown this state now, so whatever the person
        // did before it is no longer a change the agent has not seen.
        if let Some(seen) = seen {
            sessions.remember_seen(&conversation_key, &grant, seen);
        }
        admission.decorate(&mut reply);
        reply
    }

    /// Finalize one text-free state-read row, with or without an image.
    /// Pixels are released only through custody, after this same row is final.
    async fn journal_state_read(
        &self,
        identity: JournalIdentity,
        summary: cerebellum_computer::app_state::ReadStateSummary,
        manual_accessibility: Option<&'static str>,
        now_ms: u64,
        backend: Option<B>,
        image_plan: ImageReadPlan,
    ) -> Result<
        (
            Option<ReleasedImage>,
            Option<ImageUnavailable>,
            Option<ImageFronting>,
        ),
        ImageUnavailable,
    > {
        use cerebellum_computer::app_state::image::ImageCustody;
        let audit = self.audit.clone();
        let grant = summary.grant_identity.clone();
        let freshness = self.image_freshness_source.clone();
        let make_driver = self.make_synthetic_driver.clone();
        let own_input = self.own_input.clone();
        let input_source = self.app_state_source.clone();
        let work = quarantine::CallWork::current();
        let mut image_plan = image_plan;
        image_plan.gate = Some(work.gate());
        tokio::task::spawn_blocking(move || {
            let _ax = work.bound_ax();
            let _scope = cerebellum_computer::audit::AccessibilityReadScope::new(
                grant.pid,
                manual_accessibility,
            );
            let evidence =
                std::cell::RefCell::new(cerebellum_computer::app_state::ImageReadEvidence {
                    decision: image_plan
                        .requested
                        .then_some(cerebellum_computer::app_state::image::ImageDecision::Unknown),
                    fronting: None,
                });
            let mut custody = AuditImageCustody {
                audit: &audit,
                identity,
                now_ms,
                summary,
                finalized: false,
                image_evidence: &evidence,
            };
            let Some(backend) = backend else {
                let reservation = custody
                    .reserve()
                    .map_err(|_| ImageUnavailable::AuditUnavailable)?;
                custody
                    .finalize_read(reservation, false)
                    .map_err(|_| ImageUnavailable::AuditUnavailable)?;
                let reason =
                    (image_plan.requested && image_plan.bring_to_front && !image_plan.takeover)
                        .then_some(ImageUnavailable::ImageNeedsTakeover);
                return Ok((None, reason, None));
            };
            let image = release_through_custody(&mut custody, || {
                // The observed bracket posts a heartbeat, just as keys does;
                // do not mistake that input for the person's next action.
                let mut posting = (image_plan.bring_to_front && image_plan.takeover).then(|| {
                    let posting =
                        own_input.begin_posting(person::last_input_instant(input_source.as_ref()));
                    work.publish_posting(&own_input, &posting);
                    posting
                });
                let captured = read_image::capture(
                    backend,
                    &mut make_driver(),
                    freshness.as_ref(),
                    &grant,
                    &image_plan,
                    &evidence,
                    &mut || {
                        if let Some(posting) = posting.take() {
                            own_input.end_posting(posting);
                        }
                    },
                );
                if let Some(posting) = posting {
                    own_input.end_posting(posting);
                }
                captured
            });
            if !custody.finalized {
                return Err(ImageUnavailable::AuditUnavailable);
            }
            let fronting = evidence.into_inner().fronting;
            Ok(match image {
                Ok(image) => (Some(image), None, fronting),
                Err(reason) => (None, Some(reason), fronting),
            })
        })
        .await
        .unwrap_or(Err(ImageUnavailable::CaptureFailed))
    }

    /// Poll one accessibility predicate until it settles, expires, or is cancelled.
    ///
    /// The request names the application its predicate's elements live in, and
    /// the app grant that admits the wait is the grant for that application: a
    /// wait never borrows whichever application some earlier call selected.
    async fn serve_wait<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        let parsed = match parse_wait_request(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };
        let ServeContext {
            cancel,
            grantee: _,
            identity,
            management,
            consent,
            clock: _,
            now_ms: _,
        } = context;
        let (grant, admission) = match management.admit_app(&parsed.app, &consent, &cancel).await {
            Ok(admitted) => admitted,
            Err(AppRefusal::Consent(ConsentRefusal::Cancelled)) => {
                return cancelled_before_polling_reply(parsed.predicate)
            }
            Err(refusal) => return refusal.reply(&parsed.app),
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return locked;
        }

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let predicate = parsed.predicate;
            self.cursor.schedule(
                cursor::Identity::current(identity.agent_project_id.clone()),
                cerebellum_computer::cursor::CursorKind::Reading,
                grant.clone(),
                self.app_state_source.clone(),
                None,
                None,
            );
            let timeout_ms = parsed.timeout_ms;
            let work = quarantine::CallWork::current();
            if let Some(busy) = work.bind(&self.serializer.quarantine, &grant) {
                return busy;
            }
            let mut token = AuditToken::new(self.audit.clone(), work.gate());
            match tokio::task::spawn_blocking(move || {
                let _ax = work.bound_ax();
                let _scope =
                    cerebellum_computer::audit::AccessibilityReadScope::new(grant.pid, None);
                token.record_accessibility_read(identity, ComputerCapability::Wait, &grant, || {
                    let mut poller = PlatformPredicatePoller::new(
                        NativeComputerPlatformDriver::default(),
                        grant.clone(),
                    );
                    wait_until_predicate(&mut poller, predicate, timeout_ms, &|| {
                        cancel.is_cancelled()
                    })
                })
            })
            .await
            {
                Ok(Ok(result)) => {
                    let mut reply = wait_wire_reply(result);
                    admission.decorate(&mut reply);
                    reply
                }
                Ok(Err(_)) | Err(_) => {
                    wait_indeterminate_reply(None, json!({"reason": "polling_task_unavailable"}))
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (grant, cancel, identity);
            let mut reply = wait_indeterminate_reply(
                Some(parsed.predicate),
                json!({"reason": "scoped_accessibility_read_unsupported"}),
            );
            admission.decorate(&mut reply);
            reply
        }
    }

    /// Post one keystroke action into the application the request names.
    ///
    /// Shared by the two keystroke capabilities, which differ only in the
    /// request they parse. Both deliver to the named application's process in
    /// background mode, under that application's app grant.
    ///
    /// The ordering is not stylistic: authority is established before
    /// anything is journaled, the dispatcher reserves and commits the intent
    /// before the platform can receive an event, and the terminal state is
    /// finalised before this returns -- so a failing dispatch still leaves a
    /// completed audit record, never an open one.
    async fn serve_synthetic<C: MonotonicClock>(
        &self,
        capability: ComputerCapability,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        // Every refusal returned before the dispatch below is marked as having
        // posted nothing, so a caller knows it can retry it. A refusal left
        // unmarked reads as effect_indeterminate, which is the safe default
        // for any path added later without thought.
        use keystrokes::refused_before_posting as unposted;
        let mut parsed = match parse_synthetic_request(capability, arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return unposted(refusal),
        };
        let view = parse_state_view(arguments.as_object().expect("parsed object"))
            .expect("validated view");
        parsed.target = match self.resolve_target_name(&parsed.target).await {
            Ok(bundle_identity) => bundle_identity,
            Err(refusal) => return unposted(refusal),
        };

        let ServeContext {
            cancel,
            grantee,
            identity,
            management,
            consent,
            clock,
            now_ms: _,
        } = context;
        if let SyntheticAction::KeyCombination { key, modifiers } = &parsed.action {
            if let Some(blocked) = current_blocked_chord_platform()
                .and_then(|platform| blocked_chord(*modifiers, *key, platform))
            {
                // The parser sets `chord` on every KeyCombination it produces,
                // so this is Some today. The refusal must not depend on that
                // staying true: a blocked chord that panicked here would take
                // the module loop down instead of refusing, and the chord is
                // reconstructible from the parts that decided the block.
                let chord = parsed
                    .chord
                    .clone()
                    .unwrap_or_else(|| describe_chord(*modifiers, *key));
                self.record_blocked_chord(grantee, &chord, blocked.reason)
                    .await;
                return unposted(chord_blocked_refusal(&chord, blocked.reason));
            }
            // The session floor is checked before anything is asked or
            // escalated, so no grant can make a session-ending chord valid.
            parsed.action_kind = chord_action_kind(*modifiers);
        }
        // Keystrokes stay bound to the named application's process generation.
        let mode = DispatchMode::Background;
        let (mut grant, mut admission) = match management
            .admit_app(&parsed.target, &consent, &cancel)
            .await
        {
            Ok(admitted) => admitted,
            // A cancel while waiting on the person is answered the way a cancel
            // during posting is: nothing was posted and nothing is held.
            Err(AppRefusal::Consent(ConsentRefusal::Cancelled)) => {
                return unposted(synthetic_dispatch_refusal(&DispatchError::Cancelled {
                    posts_returned: 0,
                    held_state: HeldStateDisposition::NoneHeld,
                }))
            }
            Err(refusal) => return unposted(refusal.reply(&parsed.target)),
        };
        if let Some(locked) = self.locked_after_wait(admission.waited, &admission) {
            return unposted(locked);
        }
        if let Some(mut refusal) = self
            .refuse_if_person_changed(management, &identity.conversation_key, &grant)
            .await
        {
            admission.decorate(&mut refusal);
            return unposted(refusal);
        }
        let work = quarantine::CallWork::current();
        if let Some(mut busy) = work.bind(&self.serializer.quarantine, &grant) {
            admission.decorate(&mut busy);
            return unposted(busy);
        }
        if let Err(mut unconfirmed) = self
            .confirm_held_input_released(capability.capability_id(), management, &work)
            .await
        {
            admission.decorate(&mut unconfirmed);
            return unposted(unconfirmed);
        }

        if consent.unattended
            && keystrokes::key_delivery(
                &parsed.action,
                self.app_state_source.frontmost_pid() == Some(grant.pid),
                true,
            ) == keystrokes::KeyDelivery::BringForward
        {
            return unposted(
                ConsentRefusal::Unavailable {
                    reason: "takeover_not_for_flows",
                    remedy: "fronting keys requires an attended session",
                }
                .reply(None),
            );
        }
        // Before anything is posted or fronted: the target's own focused
        // element must be readable and must not be a secure field. Asked of
        // the target rather than of the frontmost application, because the
        // keystrokes go to the target whichever application is in front.
        let source = self.app_state_source.clone();
        let focus_grant = grant.clone();
        let focus_work = work.clone();
        let focus = tokio::task::spawn_blocking(move || {
            let _ax = focus_work.bound_ax();
            keystrokes::read_target_focus(source.as_ref(), &focus_grant)
        })
        .await
        .unwrap_or(Err(keystrokes::FocusRefusal::Unreadable));
        let focus = match focus {
            Ok(focus) => focus,
            Err(refusal) => {
                let mut reply = refusal.reply();
                admission.decorate(&mut reply);
                return unposted(reply);
            }
        };
        self.cursor.schedule(
            cursor::Identity::current(identity.agent_project_id.clone()),
            if capability == ComputerCapability::Type {
                cerebellum_computer::cursor::CursorKind::Type
            } else {
                cerebellum_computer::cursor::CursorKind::Keys
            },
            grant.clone(),
            self.app_state_source.clone(),
            focus.as_ref().map(|focus| focus.handle.clone()),
            None,
        );

        // Only shortcut modifiers need the fronting bracket. Plain typing
        // stays inside the target process without taking the person's focus.
        let capability_id = capability.capability_id();
        let frontmost = self.app_state_source.frontmost_pid();
        let mut bracket_bound = None;
        let delivery = keystrokes::key_delivery(
            &parsed.action,
            frontmost == Some(grant.pid),
            management.computer_grants().holds(
                &consent.caller,
                &crate::computer_grants::GrantNeed::Takeover,
            ),
        );
        // Focus may have moved while the focused element was read. Recheck
        // before choosing a delivery path that would require takeover.
        if consent.unattended && delivery != keystrokes::KeyDelivery::PerProcess {
            return unposted(
                ConsentRefusal::Unavailable {
                    reason: "takeover_not_for_flows",
                    remedy: "fronting keys requires an attended session",
                }
                .reply(None),
            );
        }
        if delivery == keystrokes::KeyDelivery::Refuse {
            let mut reply = keystrokes::modifier_chord_refusal();
            admission.decorate(&mut reply);
            return unposted(reply);
        }
        if delivery == keystrokes::KeyDelivery::BringForward {
            if !self.fronting_bracket_admitted {
                let mut reply = keystrokes::needs_foreground_reply();
                admission.decorate(&mut reply);
                return unposted(reply);
            }
            match management
                .computer_grants()
                .require(
                    &crate::computer_grants::GrantNeed::Takeover,
                    &consent,
                    &cancel,
                )
                .await
            {
                Ok(takeover) => {
                    if takeover.waited {
                        // The person may have taken a while; act only on the
                        // process that answers to the name now, and only if
                        // it is still the one the app grant was checked for.
                        match management.resolve_process(&parsed.target) {
                            Ok(current)
                                if current.pid == grant.pid
                                    && current.process_generation_evidence
                                        == grant.process_generation_evidence =>
                            {
                                grant = current;
                            }
                            Ok(_) | Err(_) => {
                                return unposted(
                                    management
                                        .resolve_process(&parsed.target)
                                        .err()
                                        .unwrap_or_else(|| {
                                            json!({
                                                "outcome": "not_running",
                                                "bundle_identity": parsed.target,
                                                "remedy": "the application restarted while the \
                                                           person was asked; retry",
                                            })
                                        }),
                                )
                            }
                        }
                    }
                    if takeover.persisted.is_some() {
                        admission.persisted = takeover.persisted;
                    }
                    if let Some(locked) = self.locked_after_wait(takeover.waited, &admission) {
                        return unposted(locked);
                    }
                }
                Err(ConsentRefusal::Cancelled) => {
                    return unposted(synthetic_dispatch_refusal(&DispatchError::Cancelled {
                        posts_returned: 0,
                        held_state: HeldStateDisposition::NoneHeld,
                    }))
                }
                Err(refusal) => {
                    let mut reply = refusal.reply(None);
                    admission.decorate(&mut reply);
                    return unposted(reply);
                }
            }
            bracket_bound = Some(
                cerebellum_computer::platform::vocabulary::frozen_row_bound_ms(
                    capability_id,
                    "maximum_fronting_bracket_interval_ms",
                )
                .unwrap_or(100),
            );
        }

        // Every served capability has a dispatch row; a missing one is a table
        // disagreement to report, not a reason to take the module down.
        let Some(mut row) = FrozenDispatchRow::for_capability(capability_id) else {
            return unposted(json!({
                "outcome": "not_servable",
                "remedy": "this capability has no dispatch row; report it",
            }));
        };
        if parsed.action_kind == ActionKind::MutateDurable {
            // The vocabulary's durable escalation is a property of the request,
            // not of the row: the dispatch runs under the escalated kind so
            // containment and audit evidence record what this action could do
            // rather than what an ordinary compose action could.
            row.action_kind = cerebellum_computer::platform::ActionKind::MutateDurable;
        }
        let dispatch_at_ms = clock.now().as_nanos() / 1_000_000;
        let expires_at_ms = dispatch_at_ms.saturating_add(row.maximum_attendance_lease_age_ms);
        let lease = match AttendanceLease::new(
            identity.conversation_key.clone(),
            grant.clone(),
            grantee,
            dispatch_at_ms,
            expires_at_ms,
            grant.process_generation_evidence.clone(),
            "cerebellum-serve-context-v1",
        ) {
            Ok(lease) => lease,
            Err(_) => {
                return unposted(synthetic_dispatch_refusal(
                    &DispatchError::AttendanceUnavailable,
                ))
            }
        };
        let attendance = AttendanceContext::background(
            identity.conversation_key.clone(),
            grant.clone(),
            grantee,
            lease,
            dispatch_at_ms,
            dispatch_at_ms,
            row.maximum_attendance_lease_age_ms,
            row.maximum_attendance_check_to_dispatch_interval_ms,
            true,
        );

        // Neither keystroke request schema declares a post-condition, so there
        // is no effect claim for the dispatcher to evaluate. The placeholder
        // exists because the dispatcher serializes a predicate before
        // dispatch; the production driver is built with post-condition
        // evaluation disabled, which records the effect as indeterminate.
        // Typed text is confirmed separately below, by reading the focused
        // element back.
        let expected = ExpectedPostCondition::new(
            "computer-synthetic-wire-no-effect-claim-v1",
            PostCondition::ElementPresent {
                element: parsed.placeholder_element,
            },
        );
        let typed_text = match &parsed.action {
            SyntheticAction::TypeText { text } => Some(text.clone()),
            _ => None,
        };
        let held_press = held_input::HeldPress::per_process(&grant, &parsed.action);
        let mut request = DispatchRequest::new(
            row,
            mode,
            grant.clone(),
            expected,
            attendance,
            dispatch_at_ms,
        )
        .with_synthetic(parsed.action);
        if let Some(bound) = bracket_bound {
            request = request.with_fronting_bracket(bound);
        }

        // The journal entry is reserved here, under a short lock, before the
        // blocking worker starts; the worker commits and finalizes it through
        // the token, so no audit lock is held across platform work.
        let mut token = AuditToken::new(self.audit.clone(), work.gate());
        if cerebellum_computer::dispatch::reserve_actuation_ahead(
            &mut token,
            identity.clone(),
            &request,
        )
        .is_err()
        {
            return unposted(synthetic_dispatch_refusal(&DispatchError::AuditUnavailable));
        }
        let ticket = self.track_held_input(held_press, &work);

        // Posting is synchronous and may take seconds. Keep the frame reader
        // runnable even on a single-thread runtime so Cancel can set the signal.
        let make_driver = self.make_synthetic_driver.clone();
        let conversation_key = identity.conversation_key.clone();
        let mut unposted_refusal = false;
        let own_input = self.own_input.clone();
        let input_source = self.app_state_source.clone();
        let dispatch_work = work.clone();
        let (dispatched, bracket) = tokio::task::spawn_blocking(move || {
            let _ax = dispatch_work.bound_ax();
            let cancelled = || cancel.is_cancelled();
            let mut dispatcher = Dispatcher::new(make_driver(), &cancelled);
            let posting =
                own_input.begin_posting(person::last_input_instant(input_source.as_ref()));
            dispatch_work.publish_posting(&own_input, &posting);
            let dispatched = dispatcher.dispatch(&mut token, identity, request);
            own_input.end_posting(posting);
            settle_held_input(ticket, &dispatched, make_driver.as_ref());
            (dispatched, dispatcher.last_bracket().cloned())
        })
        .await
        .unwrap_or((Err(DispatchError::Platform), None));
        let mut reply = match dispatched {
            Ok(report) => {
                let Some(containment_rung) = report.containment.rung() else {
                    return synthetic_dispatch_refusal(&DispatchError::AuditUnavailable);
                };
                // The rung alone cannot be acted on. Nine typed conditions
                // reduce to global_none -- coordinate addressing, a
                // non-structural delivery primitive, five identity states and
                // four fronting states -- and a caller's remedy differs between
                // them. Naming which one applied is the same typed-refusal
                // discipline the rest of this surface follows, and it is the
                // instrument this module needed to diagnose its own rung.
                //
                // target_fronted rides alongside rather than inside the rung
                // because it is a different claim: the rung says the input was
                // contained to a process, this says whether the window that
                // received it was pinned down. Through a fronting bracket it
                // says whether the target was brought forward and the previous
                // application put back inside the bound.
                //
                // The reason key is omitted rather than sent as null when no
                // condition denied the rung: absence is unambiguous here because
                // target_fronted is always present, so a caller can tell a build
                // that reports these from one that does not.
                let (target_fronted, forfeiture) = match (&bracket, bracket_bound) {
                    (Some(bracket), Some(bound)) => keystrokes::bracket_fronting(bracket, bound),
                    _ => (
                        report.containment.fronting_stable,
                        report
                            .containment
                            .forfeiture_reason
                            .map(|reason| reason.as_str()),
                    ),
                };
                synthetic_success_reply(
                    DispatchContainmentRung::as_str(containment_rung),
                    target_fronted,
                    effect_status_name(report.effect.status),
                    forfeiture,
                )
            }
            Err(refusal) => {
                // Decided from whether a post call was made, not from a zero
                // posts_returned: see `post_call_made` for why the two differ.
                unposted_refusal =
                    keystrokes::post_call_made(&refusal, bracket.as_ref()) == Some(false);
                let mut refused = keystrokes::dispatch_refusal_reply(&refusal);
                // A bracket that stopped part-way may already have posted
                // earlier chunks. Saying how many keeps a caller from retrying
                // text that partly landed as though none of it had.
                if let Some(bracket) = &bracket {
                    if refused.get("posts_returned").is_none() {
                        refused["posts_returned"] = json!(bracket.posts_returned);
                    }
                }
                refused
            }
        };
        // A previous application left behind the target is reported whatever
        // else happened, because the person's next keystrokes go to it.
        if let Some(bracket) = &bracket {
            keystrokes::disclose_failed_restore(&mut reply, bracket, &grant);
        }
        // Applied after the restore disclosure, which rewrites the reply: a
        // bracket can fail to put the previous application back without ever
        // posting, and that reply must still say nothing was posted.
        if unposted_refusal {
            reply = unposted(reply);
        }

        let posted = matches!(
            reply["outcome"].as_str(),
            Some("delivery_unconfirmed" | "restore_failed")
        );
        if posted {
            let source = self.app_state_source.clone();
            let sessions = management.app_state_sessions().clone();
            let settle = element_actions::settle_bound(capability);
            let effect_deadline = element_actions::effect_deadline(capability);
            let mut finished = reply;
            let observe_work = work.clone();
            reply = tokio::task::spawn_blocking(move || {
                let _ax = observe_work.bound_ax();
                // Polled up to the row's effect deadline rather than read once:
                // an application renders typed text some time after the posts
                // return, and a backgrounded Electron app takes the longest.
                if let (Some(text), Some(focused)) = (typed_text.as_deref(), focus.as_ref()) {
                    if finished["outcome"] == "delivery_unconfirmed"
                        && keystrokes::await_typed_text(
                            source.as_ref(),
                            focused,
                            text,
                            effect_deadline,
                        )
                    {
                        finished["outcome"] = json!("completed");
                        finished["effect_status"] = json!("effect_observed");
                    }
                }
                let observed = element_actions::settle_and_observe_view(
                    source.as_ref(),
                    &sessions,
                    &conversation_key,
                    &grant,
                    settle,
                    sessions.zoom_expands_menus(&conversation_key, &grant, view.zoom.as_deref()),
                );
                element_actions::add_diff_view(&mut finished, observed.as_ref(), &view);
                finished
            })
            .await
            .unwrap_or_else(|_| json!({"outcome": "delivery_unconfirmed"}));
        }
        admission.decorate(&mut reply);
        reply
    }

    /// Refuse an input action while input this plane posted may still be
    /// held, after first discharging presses whose processes have exited and
    /// then, when no worker with a possibly-held send is alive, posting the
    /// held presses' paired releases itself. Only when every release returns
    /// may the call go on.
    pub(super) async fn confirm_held_input_released(
        &self,
        call: &str,
        management: &ManagementPlane,
        work: &quarantine::CallWork,
    ) -> Result<(), Value> {
        self.held_input.discharge_exited(|pid, generation| {
            management
                .process_for_pid(pid)
                .is_some_and(|current| current.process_generation_evidence == generation)
        });
        let pending = match self.held_input.pending_release() {
            Ok(None) => return Ok(()),
            Ok(Some(pending)) => pending,
            Err(()) => return Err(held_input::held_input_unconfirmed_reply(call)),
        };
        let make_driver = self.make_synthetic_driver.clone();
        let held = self.held_input.clone();
        let release_work = work.clone();
        let released = tokio::task::spawn_blocking(move || {
            let _ax = release_work.bound_ax();
            let mut driver = make_driver();
            held_input::release_pending(&held, pending, |press| {
                held_input::release_one(press, &mut driver)
            })
        })
        .await
        .unwrap_or(false);
        if released {
            Ok(())
        } else {
            Err(held_input::held_input_unconfirmed_reply(call))
        }
    }

    /// Track a send that may leave a key or button held, and give the call's
    /// terminal decision a release window that reports how it ended. The
    /// call's release permit moves into that window, so its capacity returns
    /// only when the release work really ends.
    pub(super) fn track_held_input(
        &self,
        press: Option<held_input::HeldPress>,
        work: &quarantine::CallWork,
    ) -> Option<held_input::SendTicket> {
        let ticket = self.held_input.begin_send(press?, work.terminal.clone());
        if let Some(terminal) = &work.terminal {
            let outcome = ticket.outcome();
            let permit = work.permits().and_then(|permits| permits.take_release());
            terminal.set_release(async move {
                let _permit = permit;
                outcome.await
            });
        }
        Some(ticket)
    }

    async fn record_blocked_chord(&self, caller: &str, chord: &str, reason: &str) {
        let _ = self.refusal_ring.lock().await.record_refusal(
            caller,
            chord,
            ComputerRefusalReason {
                chord: chord.to_string(),
                reason: reason.to_string(),
            },
        );
    }

    /// The bundle identity a request's `target` names, which may be the
    /// application's display name, or the refusal for a name that matches
    /// no running application or several.
    ///
    /// A target spelled like a bundle identity (dotted, no spaces) is returned
    /// as it is, without listing anything, so the process lookup that follows
    /// still refuses one nobody runs as `not_running`. A display name is
    /// matched against the running applications; when they cannot be listed,
    /// the name is returned as it is and the process lookup refuses it as it
    /// would any unknown bundle identity.
    pub(crate) async fn resolve_target_name(&self, target: &str) -> Result<String, Value> {
        self.resolve_target_name_holding(target, None).await
    }

    /// [`Self::resolve_target_name`] with the listing query holding `hold`, a
    /// blocking-worker permit, until the query really ends.
    pub(crate) async fn resolve_target_name_holding(
        &self,
        target: &str,
        hold: Option<Arc<tokio::sync::OwnedSemaphorePermit>>,
    ) -> Result<String, Value> {
        if looks_like_bundle_identity(target) {
            return Ok(target.to_string());
        }
        let source = self.app_state_source.clone();
        let listed = tokio::task::spawn_blocking(move || {
            let _permit = hold;
            source.running_apps()
        })
        .await
        .unwrap_or(Err(AppStateReadError::Unreadable));
        match listed {
            Ok(apps) => match_target_name(target, &apps).map(|matched| {
                // `serve` writes this name on the reply as matched_app, so the
                // caller learns which application a partial name was taken to
                // mean. The queueing step that resolves a target before
                // `serve` runs has no MATCHED_APP slot, so it records nothing.
                if let Some(name) = matched.partial_name {
                    let _ = MATCHED_APP.try_with(|slot| {
                        *slot.lock().unwrap_or_else(|poison| poison.into_inner()) = Some(name);
                    });
                }
                matched.bundle_identity
            }),
            Err(_) => Ok(target.to_string()),
        }
    }

    /// Names and identities only, without any per-app grant. The read is
    /// bounded and journaled by count, never by application names.
    async fn serve_list_apps<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        let filter = match parse_list_apps_request(arguments) {
            Ok(filter) => filter,
            Err(refusal) => return refusal,
        };
        let source = self.app_state_source.clone();
        let listed = tokio::task::spawn_blocking(move || {
            let start = std::time::Instant::now();
            let mut running = source.running_apps()?;
            let mut installed = source
                .installed_apps(std::time::Duration::from_secs(2).saturating_sub(start.elapsed()));
            let filter = filter.as_deref();
            running.retain(|app| listed_by_filter(filter, &app.name, &app.bundle_identity));
            installed
                .apps
                .retain(|app| listed_by_filter(filter, &app.name, &app.bundle_identity));
            Ok::<_, AppStateReadError>((running, installed))
        })
        .await
        .unwrap_or(Err(AppStateReadError::Unreadable));
        let audit = self.audit.clone();
        let identity = context.identity;
        let summary = match &listed {
            Ok((apps, installed)) => {
                json!({"app_count": (apps.len() + installed.apps.iter().filter(|app| !apps.iter().any(|running| running.bundle_identity == app.bundle_identity)).map(|app| (&app.name, &app.bundle_identity)).collect::<std::collections::BTreeSet<_>>().len()).min(500)})
            }
            Err(_) => json!({"app_count":0,"listed":false}),
        };
        let journaled = tokio::task::spawn_blocking(move || {
            journal_list_apps(&mut lock_audit(&audit), identity, &summary)
        })
        .await
        .unwrap_or(Err(()));
        if journaled.is_err() {
            return json!({"outcome":"audit_unavailable","remedy":"the module could not record the listing, so it withheld it; retry shortly"});
        }
        match listed {
            Ok((mut running, installed)) => {
                running.sort_by(|a, b| {
                    a.name
                        .to_lowercase()
                        .cmp(&b.name.to_lowercase())
                        .then(a.pid.cmp(&b.pid))
                });
                let mut inactive: Vec<_> = installed
                    .apps
                    .into_iter()
                    .filter(|app| {
                        !running
                            .iter()
                            .any(|r| r.bundle_identity == app.bundle_identity)
                    })
                    .collect();
                inactive.sort_by(|a, b| {
                    a.name
                        .to_lowercase()
                        .cmp(&b.name.to_lowercase())
                        .then(a.bundle_identity.cmp(&b.bundle_identity))
                });
                let mut identities = std::collections::BTreeSet::new();
                inactive.retain(|app| {
                    identities.insert((app.name.clone(), app.bundle_identity.clone()))
                });
                let truncated = running.len() + inactive.len() > 500;
                running.truncate(500);
                inactive.truncate(500 - running.len());
                let mut text = running_apps_text(&running);
                text.push_str("installed (not running):\n");
                for app in &inactive {
                    text.push_str(&format!(
                        "{} · {}\n",
                        cerebellum_computer::app_state::render::one_line(&app.name),
                        cerebellum_computer::app_state::render::one_line(&app.bundle_identity)
                    ));
                }
                let mut apps: Vec<_> = running.iter().map(|app| json!({"name":app.name,"bundle_identity":app.bundle_identity,"running":true,"pid":app.pid,"frontmost":app.frontmost})).collect();
                apps.extend(inactive.iter().map(|app| json!({"name":app.name,"bundle_identity":app.bundle_identity,"running":false,"frontmost":false})));
                json!({"outcome":"completed", STATE_TEXT_FIELD:text, "apps":apps, "truncated":truncated,"installed_list":if installed.complete {"complete"} else {"partial"}})
            }
            Err(_) => {
                json!({"outcome":"targets_unreadable","unreadable":{"reason":"window_list_unavailable"},"remedy":"the running applications could not be read; retry, or name an application by bundle identity"})
            }
        }
    }
}

/// One text-free journal row for a `list_apps` call: the capability and the
/// count of applications listed, never their names, so a journal reader
/// learns that the list was read and not what was running.
fn journal_list_apps<R, T, S>(
    audit: &mut ComputerAudit<R, T, S>,
    identity: JournalIdentity,
    summary: &Value,
) -> Result<(), ()>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    use cerebellum_computer::audit::{
        ComputerPlaneDescriptor, ObservationState, TypedCaptureDispatch,
    };
    use cerebellum_computer::grounding::ContainmentRung;
    // The journal row records how narrowly an action was contained to one
    // process. Listing reads no process, so its scope is the whole machine.
    let rung = ContainmentRung::GlobalNone;
    let descriptor = ComputerPlaneDescriptor::new(
        ComputerCapability::ListApps,
        rung,
        ObservationState::HumanUnobserved,
    );
    let reservation = audit.reserve(identity, descriptor).map_err(|_| ())?;
    let dispatch = TypedCaptureDispatch::new(
        ComputerCapability::ListApps,
        rung,
        ObservationState::HumanUnobserved,
    )
    .dispatch_material(
        ComputerCapability::ListApps
            .capability_id()
            .as_bytes()
            .to_vec(),
    );
    let token = audit
        .commit_dispatched(reservation, &dispatch, b"session_route".to_vec(), None)
        .map_err(|_| ())?;
    audit
        .finalize_dispatched(
            token,
            serde_json::to_vec(summary).map_err(|_| ())?,
            Vec::new(),
        )
        .map_err(|_| ())?;
    Ok(())
}

/// The platform's application-state reader, or one that refuses where there
/// is none.
fn native_app_state_source() -> Arc<dyn AppStateSource> {
    #[cfg(target_os = "macos")]
    {
        Arc::new(cerebellum_computer::app_state::native::MacAppStateSource)
    }
    #[cfg(not(target_os = "macos"))]
    {
        Arc::new(cerebellum_computer::app_state::source::UnsupportedAppStateSource)
    }
}

/// The most roles one `role_filter` may name.
const MAX_ROLE_FILTERS: usize = 16;

/// Every field `computer.read_state` accepts. Only `target` is required.
const READ_STATE_REQUEST_FIELDS: [&str; 6] = [
    "target",
    "role_filter",
    "zoom",
    "text_filter",
    "include_image",
    "bring_to_front",
];
#[cfg(test)]
const READ_STATE_REQUIRED_FIELDS: [&str; 1] = ["target"];

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedReadState {
    target: String,
    role_filter: Vec<String>,
    /// An element id, or `menubar`; see [`Zoom::parse`].
    zoom: Option<String>,
    text_filter: Option<String>,
    include_image: bool,
    bring_to_front: bool,
}

fn invalid_read_state_request(field: &str, reason: &str) -> Value {
    json!({"outcome": "invalid_request", "field": field, "reason": reason})
}

fn optional_text(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<Option<String>, Value> {
    match object.get(field) {
        None => Ok(None),
        Some(Value::String(text)) if !text.trim().is_empty() => Ok(Some(text.clone())),
        Some(Value::String(_)) => Err(invalid_read_state_request(field, "empty_value")),
        Some(_) => Err(invalid_read_state_request(field, "wrong_type")),
    }
}

fn parse_read_state_request(arguments: &Value) -> Result<ParsedReadState, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid_read_state_request("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !READ_STATE_REQUEST_FIELDS.contains(&field.as_str()))
        .min()
    {
        return Err(invalid_read_state_request(field, "unknown_field"));
    }
    let target = match optional_text(object, "target")? {
        Some(target) => target,
        None => return Err(invalid_read_state_request("target", "missing_field")),
    };
    let view = parse_state_view(object)?;
    let include_image = match object.get("include_image") {
        None => false,
        Some(Value::Bool(include)) => *include,
        Some(_) => return Err(invalid_read_state_request("include_image", "wrong_type")),
    };
    let bring_to_front = match object.get("bring_to_front") {
        None => false,
        Some(Value::Bool(front)) => *front,
        Some(_) => return Err(invalid_read_state_request("bring_to_front", "wrong_type")),
    };
    Ok(ParsedReadState {
        target,
        role_filter: view.roles,
        zoom: view.zoom,
        text_filter: view.text,
        include_image,
        bring_to_front,
    })
}

#[derive(Clone, Default)]
pub(crate) struct StateView {
    roles: Vec<String>,
    zoom: Option<String>,
    text: Option<String>,
}

impl StateView {
    fn request(&self) -> StateRequest<'_> {
        StateRequest {
            zoom: self.zoom.as_deref().map(Zoom::parse),
            roles: &self.roles,
            text: self.text.as_deref(),
        }
    }
}

pub(crate) fn parse_state_view(
    object: &serde_json::Map<String, Value>,
) -> Result<StateView, Value> {
    let roles = match object.get("role_filter") {
        None => Vec::new(),
        Some(Value::String(role)) if !role.trim().is_empty() => vec![role.clone()],
        Some(Value::Array(roles)) if roles.is_empty() => {
            return Err(invalid_read_state_request("role_filter", "empty_value"))
        }
        Some(Value::Array(roles)) if roles.len() > MAX_ROLE_FILTERS => {
            return Err(invalid_read_state_request("role_filter", "exceeds_maximum"))
        }
        Some(Value::Array(roles)) => roles
            .iter()
            .map(|role| match role {
                Value::String(role) if !role.trim().is_empty() => Ok(role.clone()),
                Value::String(_) => Err(invalid_read_state_request("role_filter", "empty_value")),
                _ => Err(invalid_read_state_request("role_filter", "wrong_type")),
            })
            .collect::<Result<_, _>>()?,
        Some(Value::String(_)) => {
            return Err(invalid_read_state_request("role_filter", "empty_value"))
        }
        Some(_) => return Err(invalid_read_state_request("role_filter", "wrong_type")),
    };
    Ok(StateView {
        roles,
        zoom: optional_text(object, "zoom")?,
        text: optional_text(object, "text_filter")?,
    })
}

/// What a call refused for a locked screen tells its caller to do.
///
/// The web version is named because a browser page is driven through the
/// browser's own debugging protocol, which keeps working while the screen is
/// locked; the remedy is useful to someone away from the machine.
const SCREEN_LOCKED_REMEDY: &str = "The Mac's screen is locked, and macOS hides every app's \
     interface while it is. Try again once the screen is unlocked, or use the site's web version \
     with browser_use, which works while the screen is locked.";

/// The refusal every served row gives while the screen is locked.
fn screen_locked_reply() -> Value {
    json!({
        "outcome": "screen_locked",
        "reason": "screen_locked",
        "remedy": SCREEN_LOCKED_REMEDY,
    })
}

fn stale_zoom_reply() -> Value {
    json!({
        "outcome": "stale_element",
        "remedy": "zoom names no element of this application's current state; read the state \
                   again without it and zoom into an id from that read",
    })
}

/// Whether a target is spelled like a bundle identity (`com.apple.Safari`)
/// rather than a display name (`Safari`): dotted, with no spaces.
pub(crate) fn looks_like_bundle_identity(target: &str) -> bool {
    let target = target.trim();
    target.contains('.') && !target.contains(char::is_whitespace)
}

/// The one field `computer.list_apps` accepts: an optional `text_filter`,
/// returned trimmed, or `None` when absent or blank.
fn parse_list_apps_request(arguments: &Value) -> Result<Option<String>, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid_read_state_request("$", "wrong_type"));
    };
    if let Some(field) = object.keys().filter(|field| *field != "text_filter").min() {
        return Err(invalid_read_state_request(field, "unknown_field"));
    }
    match object.get("text_filter") {
        None => Ok(None),
        Some(Value::String(filter)) => {
            Ok(Some(filter.trim().to_string()).filter(|filter| !filter.is_empty()))
        }
        Some(_) => Err(invalid_read_state_request("text_filter", "wrong_type")),
    }
}

/// Whether an application is kept by a `list_apps` text filter: its name or
/// bundle identity contains the filter, ignoring case. A full Applications
/// folder is several hundred entries, so the filter lets a caller find one
/// installed application without reading all of them.
fn listed_by_filter(filter: Option<&str>, name: &str, bundle_identity: &str) -> bool {
    filter.is_none_or(|filter| {
        let filter = filter.to_lowercase();
        name.to_lowercase().contains(&filter) || bundle_identity.to_lowercase().contains(&filter)
    })
}

/// The running applications as `list_apps` prints them: one per line.
fn running_apps_text(apps: &[RunningApp]) -> String {
    if apps.is_empty() {
        return "No regular application is running.\n".to_string();
    }
    let mut text = String::new();
    for app in apps {
        let name = cerebellum_computer::app_state::render::one_line(&app.name);
        text.push_str(&format!(
            "{name} · {} · pid {}",
            app.bundle_identity, app.pid
        ));
        if app.frontmost {
            text.push_str(" · frontmost");
        }
        text.push('\n');
    }
    text
}

/// A target name resolved to a running application.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MatchedTarget {
    bundle_identity: String,
    /// The application's full name when the target named it only in part
    /// (a prefix or whole words of its name); `None` for an exact match.
    partial_name: Option<String>,
}

tokio::task_local! {
    /// Where name resolution leaves the full name of an application a call's
    /// target matched only in part, for `serve` to say on the reply.
    static MATCHED_APP: Arc<std::sync::Mutex<Option<String>>>;
}

/// Whether `wanted` names `name` in part: the name starts with it, or it is
/// one or more whole words of the name in order ("Context Dashboard" in
/// "Magic Context Dashboard"). Case is ignored. An empty `wanted` names
/// nothing, so it can never match every application at once.
fn names_in_part(name: &str, wanted: &str) -> bool {
    let name = name.trim().to_lowercase();
    let wanted = wanted.trim().to_lowercase();
    if wanted.is_empty() {
        return false;
    }
    if name.starts_with(&wanted) {
        return true;
    }
    let name_words: Vec<&str> = name.split_whitespace().collect();
    let wanted_words: Vec<&str> = wanted.split_whitespace().collect();
    name_words
        .windows(wanted_words.len())
        .any(|window| window == wanted_words.as_slice())
}

/// The candidates a refusal lists: each running application once per
/// process, as name, bundle identity and pid.
fn candidate_list(apps: &[&RunningApp]) -> Vec<Value> {
    apps.iter()
        .map(|app| {
            json!({
                "name": app.name,
                "bundle_identity": app.bundle_identity,
                "pid": app.pid,
            })
        })
        .collect()
}

/// The distinct bundle identities among `apps`, sorted.
fn distinct_identities<'a>(apps: &[&'a RunningApp]) -> Vec<&'a str> {
    let mut identities: Vec<&str> = apps
        .iter()
        .map(|app| app.bundle_identity.as_str())
        .collect();
    identities.sort_unstable();
    identities.dedup();
    identities
}

/// What a `target` given as a name resolves to among the running
/// applications: the one bundle identity carrying that name, or the refusal
/// that says why there is not exactly one.
///
/// A name is matched whole and without regard to case first. Only when no
/// application has exactly that name is it matched in part (see
/// [`names_in_part`]), so a model that shortens "Magic Context Dashboard"
/// to "Magic Context" still reaches it; the reply then names the application
/// it picked. A partial name fitting several applications is refused with
/// all of them listed, never guessed between. Several processes of one
/// application are one match here; resolving the bundle identity then
/// refuses them as `ambiguous` exactly as it always has.
fn match_target_name(target: &str, apps: &[RunningApp]) -> Result<MatchedTarget, Value> {
    let wanted = target.trim();
    if let Some(app) = apps
        .iter()
        .find(|app| app.bundle_identity.eq_ignore_ascii_case(wanted))
    {
        return Ok(MatchedTarget {
            bundle_identity: app.bundle_identity.clone(),
            partial_name: None,
        });
    }
    let named: Vec<&RunningApp> = apps
        .iter()
        .filter(|app| app.name.trim().eq_ignore_ascii_case(wanted))
        .collect();
    match distinct_identities(&named).as_slice() {
        [only] => {
            return Ok(MatchedTarget {
                bundle_identity: (*only).to_string(),
                partial_name: None,
            })
        }
        [] => {}
        _ => {
            return Err(json!({
                "outcome": "ambiguous_app",
                "target": wanted,
                "candidates": candidate_list(&named),
                // Named rather than chosen between: picking one would act on an
                // application the caller did not single out.
                "remedy": "several running applications have this name; retry with the bundle \
                           identity of the one you mean",
            }));
        }
    }
    let partly: Vec<&RunningApp> = apps
        .iter()
        .filter(|app| names_in_part(&app.name, wanted))
        .collect();
    match distinct_identities(&partly).as_slice() {
        [only] => Ok(MatchedTarget {
            bundle_identity: (*only).to_string(),
            partial_name: partly
                .iter()
                .find(|app| app.bundle_identity == *only)
                .map(|app| app.name.trim().to_string()),
        }),
        [] => Err(json!({
            "outcome": "no_running_app_named",
            "target": wanted,
            "remedy": "no running application has this name or bundle identity; list_apps shows \
                       the running applications, and any of their names or bundle identities \
                       is a target",
        })),
        _ => Err(json!({
            "outcome": "ambiguous_app",
            "target": wanted,
            "candidates": candidate_list(&partly),
            "remedy": "this name fits several running applications; retry with the full name or \
                       the bundle identity of the one you mean",
        })),
    }
}

/// A read the application did not answer at all. Reported as a completed
/// read of nothing, with the whole application counted as one unreadable
/// subtree, because that is what it is: nothing was seen, and nothing may be
/// concluded from the absence.
fn unreadable_application_reply(error: AppStateReadError) -> Value {
    let remedy = match error {
        AppStateReadError::AccessibilityNotPermitted => {
            "this module may not read other applications' accessibility trees; the \
             Accessibility permission must be granted to it again"
        }
        AppStateReadError::UnsupportedOnPlatform => "this platform has no application-state reader",
        AppStateReadError::TargetGone | AppStateReadError::Unreadable => {
            "the application did not answer; read again, and if it keeps not answering it may \
             be busy or hung"
        }
    };
    json!({
        "outcome": "completed",
        STATE_TEXT_FIELD: "",
        "unreadable_subtrees": 1,
        "reason": error.as_str(),
        "remedy": remedy,
    })
}

fn read_audit_unavailable_reply() -> Value {
    json!({
        "outcome": "audit_unavailable",
        "remedy": "the module could not record the read, so it withheld the result; retry shortly",
    })
}

pub(crate) const MAX_WAIT_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedWait {
    /// The bundle identity of the application the predicate's elements live
    /// in, and the one the admitting lease must be held for.
    app: String,
    predicate: PostCondition,
    timeout_ms: u64,
}

/// Every field `computer.wait` accepts. All three are required.
const WAIT_REQUEST_FIELDS: [&str; 3] = ["app", "predicate", "timeout_ms"];

/// The request fields a served capability's parser accepts, and the subset it
/// requires, in the parser's own terms.
///
/// The flat tool's schema is checked against this, and this is checked
/// against the parsers' behaviour, so neither can drift from what a request is
/// actually held to.
#[cfg(test)]
pub(crate) fn served_request_fields(
    capability: ComputerCapability,
) -> Option<(&'static [&'static str], &'static [&'static str])> {
    match capability {
        ComputerCapability::ReadState => {
            Some((&READ_STATE_REQUEST_FIELDS, &READ_STATE_REQUIRED_FIELDS))
        }
        ComputerCapability::Wait => Some((&WAIT_REQUEST_FIELDS, &WAIT_REQUEST_FIELDS)),
        ComputerCapability::PressElement => Some((
            &element_actions::PRESS_ELEMENT_FIELDS,
            &element_actions::PRESS_ELEMENT_REQUIRED,
        )),
        ComputerCapability::PressPoint => Some((
            &element_actions::PRESS_POINT_FIELDS,
            &element_actions::PRESS_POINT_REQUIRED,
        )),
        ComputerCapability::WriteText => Some((
            &element_actions::WRITE_TEXT_FIELDS,
            &element_actions::WRITE_TEXT_REQUIRED,
        )),
        ComputerCapability::OpenApp => Some((&["target", "url"], &["target"])),
        ComputerCapability::ListApps => Some((&["text_filter"], &[])),
        ComputerCapability::Type | ComputerCapability::Keys => {
            let fields = synthetic_request_fields(capability)?;
            Some((
                fields,
                if capability == ComputerCapability::Type {
                    &["target", "text"]
                } else {
                    &["keys", "target"]
                },
            ))
        }
        ComputerCapability::TakeoverMove
        | ComputerCapability::TakeoverDrag
        | ComputerCapability::TakeoverScroll => {
            let fields = takeover::request_fields(capability)?;
            Some((fields, fields))
        }
        _ => None,
    }
}

/// Parse a request for a served capability and keep only the verdict, so a
/// test can hold every served parser to the fields it declares without
/// reaching into each parser's result type.
#[cfg(test)]
pub(crate) fn parse_served_request(
    capability: ComputerCapability,
    arguments: &Value,
) -> Result<(), Value> {
    match capability {
        ComputerCapability::ReadState => parse_read_state_request(arguments).map(|_| ()),
        ComputerCapability::OpenApp => open_app::parse_request(arguments).map(|_| ()),
        ComputerCapability::ListApps => parse_list_apps_request(arguments).map(|_| ()),
        ComputerCapability::Wait => parse_wait_request(arguments).map(|_| ()),
        ComputerCapability::PressElement => {
            element_actions::parse_press_element(arguments).map(|_| ())
        }
        ComputerCapability::PressPoint => element_actions::parse_press_point(arguments).map(|_| ()),
        ComputerCapability::WriteText => element_actions::parse_write_text(arguments).map(|_| ()),
        ComputerCapability::TakeoverMove
        | ComputerCapability::TakeoverDrag
        | ComputerCapability::TakeoverScroll => {
            takeover::parse_request(capability, arguments).map(|_| ())
        }
        _ => parse_synthetic_request(capability, arguments).map(|_| ()),
    }
}

fn parse_wait_request(arguments: &Value) -> Result<ParsedWait, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid_wait_request("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !WAIT_REQUEST_FIELDS.contains(&field.as_str()))
        .min()
    {
        return Err(invalid_wait_request(field, "unknown_field"));
    }
    let app = match object.get("app") {
        Some(Value::String(app)) if !app.trim().is_empty() => app.clone(),
        Some(Value::String(_)) => return Err(invalid_wait_request("app", "empty_value")),
        Some(_) => return Err(invalid_wait_request("app", "wrong_type")),
        None => return Err(invalid_wait_request("app", "missing_field")),
    };
    let Some(predicate) = object.get("predicate") else {
        return Err(invalid_wait_request("predicate", "missing_field"));
    };
    let predicate = serde_json::from_value::<PostCondition>(predicate.clone())
        .map_err(|_| invalid_wait_request("predicate", "invalid_predicate"))?;
    if !predicate.element().is_usable() {
        return Err(invalid_wait_request("predicate", "unusable_element_name"));
    }
    let Some(timeout_ms) = object.get("timeout_ms").and_then(Value::as_u64) else {
        return Err(invalid_wait_request(
            "timeout_ms",
            if object.contains_key("timeout_ms") {
                "wrong_type"
            } else {
                "missing_field"
            },
        ));
    };
    if timeout_ms > MAX_WAIT_TIMEOUT_MS {
        return Err(invalid_wait_request("timeout_ms", "exceeds_maximum"));
    }
    Ok(ParsedWait {
        app,
        predicate,
        timeout_ms,
    })
}

/// A wait request that could not be parsed, refused as `invalid_request`
/// naming the field and why, like every other row that parses input.
fn invalid_wait_request(field: &str, reason: &str) -> Value {
    json!({
        "outcome": "invalid_request",
        "field": field,
        "reason": reason,
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn wait_wire_reply(result: WaitResult) -> Value {
    let outcome = match result.outcome {
        WaitOutcome::Settled => "predicate_satisfied",
        WaitOutcome::TimedOut => "timeout",
        WaitOutcome::Indeterminate => "indeterminate",
        WaitOutcome::Cancelled => "cancelled",
    };
    json!({
        "outcome": outcome,
        // Every polled outcome reports the engine's actual scoped-read count.
        "attempts": result.attempts,
        "evidence": serde_json::to_string(&result.evidence)
            .expect("the closed wait evidence type serializes"),
        "settle_path": "poll_with_deadline",
    })
}

fn wait_indeterminate_reply(predicate: Option<PostCondition>, reason: Value) -> Value {
    let evidence = match predicate {
        Some(predicate) => serde_json::to_string(&WaitEvidence::Indeterminate {
            predicate,
            readback: None,
            reason: reason.to_string(),
        })
        .expect("the closed wait evidence type serializes"),
        None => json!({
            "status": "indeterminate",
            "predicate": null,
            "readback": null,
            "reason": reason,
        })
        .to_string(),
    };
    json!({
        "outcome": "indeterminate",
        "evidence": evidence,
        "settle_path": "poll_with_deadline",
    })
}

/// The reply to a wait cancelled while it waited on the person, before any
/// poll: the same `cancelled` outcome a wait cancelled mid-poll returns, with
/// no reads attempted.
fn cancelled_before_polling_reply(predicate: PostCondition) -> Value {
    // No readback exists before polling. The evidence type already permits a
    // plain reason string; serializing a diagnostic object here would encode
    // JSON a second time inside that string.
    let evidence = WaitEvidence::Indeterminate {
        predicate,
        readback: None,
        reason: "cancelled_while_awaiting_consent".to_string(),
    };
    json!({
        "outcome": "cancelled", "attempts": 0,
        "evidence": serde_json::to_string(&evidence)
            .expect("the closed wait evidence type serializes"),
        "settle_path": "poll_with_deadline",
    })
}

fn effect_status_name(status: EffectStatus) -> &'static str {
    match status {
        EffectStatus::EffectObserved => "effect_observed",
        EffectStatus::NoEffectObserved => "no_effect_observed",
        EffectStatus::EffectIndeterminate => "effect_indeterminate",
    }
}

/// What one parsed synthetic-input request carries into the dispatch seam.
#[derive(Debug)]
struct ParsedSynthetic {
    action: SyntheticAction,
    /// The bundle identity of the application the keystrokes are for, whose
    /// app grant admits them.
    target: String,
    /// The wire spelling of a parsed key chord, retained for a floor refusal.
    chord: Option<String>,
    /// What the dispatch's audit and containment evidence record the action
    /// as: typing is a compose action, and a Command chord a durable one.
    action_kind: ActionKind,
    /// The element the placeholder post-condition names. It is never
    /// evaluated -- the keystroke schemas declare no post-condition -- so it
    /// labels the serialized predicate rather than naming a resolved target.
    placeholder_element: AccessibilityElementName,
}

fn chord_blocked_refusal(chord: &str, reason: &str) -> Value {
    json!({
        "outcome": "chord_blocked",
        "chord": chord,
        "reason": reason,
        "remedy": "do this yourself; no grant admits a session-ending chord",
    })
}

fn invalid_synthetic_request(field: &str, reason: &str) -> Value {
    // `field` and `reason` are declared by every synthetic row as of vocabulary
    // v8, so the wire envelope carries them to the caller. They stay in the value
    // this returns so in-module tests can assert which check refused, and so the
    // shape matches the other capabilities' refusals.
    json!({
        "outcome": "invalid_request",
        "field": field,
        "reason": reason,
    })
}

fn synthetic_field_reason(value: Option<&Value>) -> &'static str {
    if value.is_some() {
        "wrong_type"
    } else {
        "missing_field"
    }
}

/// A required non-empty string field, in the shape every `target` takes.
fn required_text(object: &serde_json::Map<String, Value>, field: &str) -> Result<String, Value> {
    match object.get(field) {
        Some(Value::String(text)) if !text.is_empty() => Ok(text.clone()),
        Some(Value::String(_)) => Err(invalid_synthetic_request(field, "empty_value")),
        other => Err(invalid_synthetic_request(
            field,
            synthetic_field_reason(other),
        )),
    }
}

/// The fields each keystroke capability's frozen request schema declares, so
/// an undeclared field is refused as unknown rather than silently dropped.
/// Every one of them is also required.
fn synthetic_request_fields(capability: ComputerCapability) -> Option<&'static [&'static str]> {
    match capability {
        ComputerCapability::Type => Some(&["target", "text", "role_filter", "text_filter", "zoom"]),
        ComputerCapability::Keys => Some(&["keys", "target", "role_filter", "text_filter", "zoom"]),
        _ => None,
    }
}

fn parse_synthetic_request(
    capability: ComputerCapability,
    arguments: &Value,
) -> Result<ParsedSynthetic, Value> {
    // serve() routes only the keystroke capabilities here. Anything else is
    // a dispatch-table disagreement, which is answered rather than panicked
    // on.
    let Some(allowed) = synthetic_request_fields(capability) else {
        return Err(json!({"outcome": "invalid_request"}));
    };
    let Some(object) = arguments.as_object() else {
        return Err(invalid_synthetic_request("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !allowed.contains(&field.as_str()))
        .min()
    {
        return Err(invalid_synthetic_request(field, "unknown_field"));
    }
    match capability {
        ComputerCapability::Type => {
            parse_state_view(object)?;
            parse_type_request(object)
        }
        ComputerCapability::Keys => {
            parse_state_view(object)?;
            parse_keys_request(object)
        }
        _ => Err(json!({"outcome": "invalid_request"})),
    }
}

fn parse_type_request(object: &serde_json::Map<String, Value>) -> Result<ParsedSynthetic, Value> {
    let target = required_text(object, "target")?;
    let text = match object.get("text") {
        Some(Value::String(text)) => text.clone(),
        other => {
            return Err(invalid_synthetic_request(
                "text",
                synthetic_field_reason(other),
            ))
        }
    };
    if text.is_empty() {
        // An empty type plans zero events, so returning success for it would
        // be a handler reporting an action it never performed.
        return Err(invalid_synthetic_request("text", "empty_value"));
    }
    // The frozen request schema bounds the text at 4096 characters.
    if text.chars().count() > 4_096 {
        return Err(invalid_synthetic_request("text", "exceeds_maximum"));
    }
    // Unicode typing follows the target's own insertion-point convention,
    // which replaces an active selection as ordinary typing does. Choosing
    // between replacing and inserting is what write_text's write_mode is for.
    Ok(ParsedSynthetic {
        action: SyntheticAction::type_text(text),
        target: target.clone(),
        chord: None,
        action_kind: ActionKind::Compose,
        placeholder_element: AccessibilityElementName::Identifier(target),
    })
}

fn parse_keys_request(object: &serde_json::Map<String, Value>) -> Result<ParsedSynthetic, Value> {
    let target = required_text(object, "target")?;
    let keys = match object.get("keys") {
        // The frozen request schema bounds the chord at 8 entries.
        Some(Value::Array(keys)) if !keys.is_empty() && keys.len() <= 8 => keys,
        Some(Value::Array(_)) => return Err(invalid_synthetic_request("keys", "invalid_length")),
        other => {
            return Err(invalid_synthetic_request(
                "keys",
                synthetic_field_reason(other),
            ))
        }
    };
    let mut modifiers = SyntheticKeyModifiers::NONE;
    let mut chord_key: Option<SyntheticKey> = None;
    let mut chord_names = Vec::with_capacity(keys.len());
    for name in keys {
        let Some(name) = name.as_str() else {
            return Err(invalid_synthetic_request("keys", "wrong_type"));
        };
        chord_names.push(name);
        match name {
            "command" => modifiers.command = true,
            "shift" => modifiers.shift = true,
            "option" => modifiers.option = true,
            "control" => modifiers.control = true,
            "windows" => {
                #[cfg(target_os = "windows")]
                {
                    modifiers.windows = true;
                }
                #[cfg(not(target_os = "windows"))]
                return Err(invalid_synthetic_request("keys", "unknown_key"));
            }
            _ => {
                let Some(key) = synthetic_key_from_wire(name) else {
                    return Err(invalid_synthetic_request("keys", "unknown_key"));
                };
                if chord_key.replace(key).is_some() {
                    // A chord is modifiers around ONE key. Two named keys are
                    // two actions, and serving them as one performs neither
                    // chord the caller asked for.
                    return Err(invalid_synthetic_request("keys", "multiple_keys"));
                }
            }
        }
    }
    let Some(key) = chord_key else {
        return Err(invalid_synthetic_request("keys", "missing_chord_key"));
    };
    Ok(ParsedSynthetic {
        action: SyntheticAction::key_combination(key, modifiers),
        target: target.clone(),
        chord: Some(chord_names.join("+")),
        // The session floor must run before durable-chord escalation; serve
        // classifies this only after the floor declines the exact chord.
        action_kind: ActionKind::Compose,
        placeholder_element: AccessibilityElementName::Identifier(target),
    })
}

/// The chord in the wire's own spelling, rebuilt from the parsed parts.
///
/// Used only when the parser's retained text is absent, which it is not
/// today; kept so a refusal never has to choose between a panic and an
/// empty chord field.
fn describe_chord(modifiers: SyntheticKeyModifiers, key: SyntheticKey) -> String {
    let mut parts = Vec::with_capacity(5);
    if modifiers.command {
        parts.push("command");
    }
    if modifiers.control {
        parts.push("control");
    }
    if modifiers.option {
        parts.push("option");
    }
    if modifiers.shift {
        parts.push("shift");
    }
    if modifiers.windows {
        parts.push("windows");
    }
    let key = format!("{key:?}").to_lowercase();
    parts.push(&key);
    parts.join("+")
}

/// What a key combination is recorded as in the dispatch's evidence.
///
/// A Command chord asks the target application to run one of the
/// application's OWN commands, and what those do is not enumerable from here:
/// Command-S saves, Command-Q quits, Command-W closes -- state that outlives
/// the session -- while Command-C copies. Because the plane cannot show any
/// Command chord to be session-scoped, every Command chord is recorded as
/// durable. A chord without Command is an editing or navigation keystroke.
/// This classifies the evidence only; the app grant is what admits either.
fn chord_action_kind(modifiers: SyntheticKeyModifiers) -> ActionKind {
    if modifiers.command {
        ActionKind::MutateDurable
    } else {
        ActionKind::Compose
    }
}

/// Settle a tracked send with the sequence's own report. When that report
/// leaves the held state unknown, the worker has now returned, so its paired
/// releases are posted here, outside the call's dispatch gate: a release is
/// the one input a stopped call may still send.
fn settle_held_input<T, D: PlatformDriver>(
    ticket: Option<held_input::SendTicket>,
    dispatched: &Result<T, DispatchError>,
    make_driver: &(dyn Fn() -> D + Send + Sync),
) {
    if let Some(ticket) = ticket {
        ticket.settle(held_input::disposition_of(dispatched), |press| {
            held_input::release_one(press, &mut make_driver())
        });
    }
}

fn synthetic_dispatch_refusal(refusal: &DispatchError) -> Value {
    if *refusal == DispatchError::DispatchStopped {
        return quarantine::stopped_before_dispatch_reply();
    }
    if let DispatchError::Cancelled {
        posts_returned,
        held_state,
    } = refusal
    {
        return json!({
            "outcome": "cancelled", "posts_returned": posts_returned,
            "reason": match held_state {
                HeldStateDisposition::NoneHeld => "caller_interrupted_none_held",
                HeldStateDisposition::Released { .. } => "caller_interrupted_held_input_released",
                HeldStateDisposition::Unknown => "caller_interrupted_held_state_unknown",
            },
            "remedy": "the action was interrupted by the caller; no retry is implied",
        });
    }
    let outcome = match refusal {
        DispatchError::SyntheticSequenceFailed {
            held_state: HeldStateDisposition::Unknown,
            ..
        } => "held_state_unknown",
        DispatchError::SyntheticSequenceFailed { .. } => "dispatch_failed",
        other => other.reason_code(),
    };
    let mut reply = json!({"outcome": outcome});
    if let DispatchError::SyntheticSequenceFailed {
        refusal:
            cerebellum_computer::platform::process_event::ProcessEventRefusal::PostCallFailed(failure),
        ..
    } = refusal
    {
        if failure.reason == cerebellum_computer::platform::input_route::PRIVATE_INPUT_AUTH_FAILED {
            if outcome != "held_state_unknown" {
                reply["outcome"] = json!("private_input_auth_failed");
            }
            reply["reason"] = json!("private_input_auth_failed");
            reply["remedy"] = json!("private keyboard authentication failed; no public retry was made. Read the state before retrying");
        }
    }
    if let DispatchError::SyntheticSequenceFailed { posts_returned, .. } = refusal {
        reply["posts_returned"] = json!(posts_returned);
    }
    reply
}

/// Give every synthetic-input outcome the result envelope its vocabulary row
/// declares.
///
/// Build the reply for a synthetic dispatch whose posts all went out.
///
/// Its outcome is `delivery_unconfirmed`: a post call returning says nothing
/// about whether the application received the keystrokes. Typed text is
/// upgraded to `completed` afterwards only when a read-back shows it arrived;
/// a chord never is.
///
/// Extracted from its one production call site so a test can assert the exact
/// shape this surface emits against the frozen result schema. The two had no
/// common point once, and that gap shipped: a pointer row emitted
/// `containment_rung` that its schema did not declare, and withholding mode
/// REJECTS an undeclared property rather than dropping it -- so an action that
/// really happened came back to the caller as a schema violation.
/// `every_synthetic_success_reply_survives_withholding` is what keeps the
/// builder and the schema from parting again.
fn synthetic_success_reply(
    containment_rung: &str,
    target_fronted: bool,
    effect_status: &str,
    forfeiture_reason: Option<&str>,
) -> Value {
    let mut reply = json!({
        "outcome": "delivery_unconfirmed",
        "containment_rung": containment_rung,
        "target_fronted": target_fronted,
        "effect_status": effect_status,
    });
    if let Some(reason) = forfeiture_reason {
        reply["containment_forfeited_because"] = json!(reason);
    }
    reply
}

/// Give every keystroke reply the envelope its row requires: an outcome, an
/// effect status, whether the target was fronted, and a containment rung.
///
/// A reply that set no effect status gets `effect_indeterminate`: the keys
/// may have landed. Only a refusal known to have made no post call says
/// `not_dispatched` (see `keystrokes::refused_before_posting`). The row
/// states the reader's side of this: a value a reader does not know is read
/// as `effect_indeterminate`, never as "did not run", so a status added
/// later can never make an older caller retry keys that landed.
fn synthetic_wire_envelope(mut reply: Value) -> Value {
    let object = reply
        .as_object_mut()
        .expect("synthetic input replies are objects");
    object
        .entry("outcome")
        .or_insert_with(|| Value::String("refused".to_string()));
    object
        .entry("effect_status")
        .or_insert_with(|| Value::String("effect_indeterminate".to_string()));
    // A refusal reaches here without having measured a fronting bracket, so the
    // honest default is false: not "the target was elsewhere" but "nothing
    // established that it was fronted". The field is declared required by every
    // synthetic row precisely so a caller never has to tell an absent claim from
    // a false one.
    object
        .entry("target_fronted")
        .or_insert_with(|| Value::Bool(false));
    object
        .entry("containment_rung")
        .or_insert_with(|| Value::String("global_none".to_string()));
    // Permission admission names the missing service and its startup state.
    // Bounded-call terminals carry dispatch and held-input evidence that callers
    // need before retrying. Preserve both kinds of diagnostics in the envelope.
    if !matches!(
        object.get("outcome").and_then(Value::as_str),
        Some(
            "permission_missing"
                | "action_deadline_exceeded"
                | "dispatch_outcome_unknown"
                | "target_busy"
                | "blocking_capacity_exhausted"
        )
    ) {
        object.remove("detail");
    }
    reply
}

/// Map a wire key name onto the neutral key it names.
///
/// The spellings are snake_case keyboard names, matching the modifier spellings
/// the same request carries, rather than any platform's keycode table.
///
/// This matches on a STRING, so it needs a catch-all and cannot itself refuse to
/// compile when a key joins the neutral vocabulary: the new key would be
/// silently unreachable from the wire. The exhaustive match in
/// `every_neutral_key_is_reachable_from_a_wire_name` holds that property
/// instead, and a new variant breaks its compile.
fn synthetic_key_from_wire(name: &str) -> Option<SyntheticKey> {
    Some(match name {
        "a" => SyntheticKey::A,
        "s" => SyntheticKey::S,
        "d" => SyntheticKey::D,
        "f" => SyntheticKey::F,
        "h" => SyntheticKey::H,
        "g" => SyntheticKey::G,
        "z" => SyntheticKey::Z,
        "x" => SyntheticKey::X,
        "c" => SyntheticKey::C,
        "v" => SyntheticKey::V,
        "section" => SyntheticKey::Section,
        "b" => SyntheticKey::B,
        "q" => SyntheticKey::Q,
        "w" => SyntheticKey::W,
        "e" => SyntheticKey::E,
        "r" => SyntheticKey::R,
        "y" => SyntheticKey::Y,
        "t" => SyntheticKey::T,
        "digit1" => SyntheticKey::Digit1,
        "digit2" => SyntheticKey::Digit2,
        "digit3" => SyntheticKey::Digit3,
        "digit4" => SyntheticKey::Digit4,
        "digit5" => SyntheticKey::Digit5,
        "digit6" => SyntheticKey::Digit6,
        "digit7" => SyntheticKey::Digit7,
        "digit8" => SyntheticKey::Digit8,
        "digit9" => SyntheticKey::Digit9,
        "digit0" => SyntheticKey::Digit0,
        "equal" => SyntheticKey::Equal,
        "minus" => SyntheticKey::Minus,
        "right_bracket" => SyntheticKey::RightBracket,
        "o" => SyntheticKey::O,
        "u" => SyntheticKey::U,
        "left_bracket" => SyntheticKey::LeftBracket,
        "i" => SyntheticKey::I,
        "p" => SyntheticKey::P,
        "return" => SyntheticKey::Return,
        "l" => SyntheticKey::L,
        "j" => SyntheticKey::J,
        "quote" => SyntheticKey::Quote,
        "k" => SyntheticKey::K,
        "semicolon" => SyntheticKey::Semicolon,
        "backslash" => SyntheticKey::Backslash,
        "comma" => SyntheticKey::Comma,
        "slash" => SyntheticKey::Slash,
        "n" => SyntheticKey::N,
        "m" => SyntheticKey::M,
        "period" => SyntheticKey::Period,
        "tab" => SyntheticKey::Tab,
        "space" => SyntheticKey::Space,
        "grave" => SyntheticKey::Grave,
        "backspace" => SyntheticKey::Backspace,
        "escape" => SyntheticKey::Escape,
        "f1" => SyntheticKey::F1,
        "f2" => SyntheticKey::F2,
        "f3" => SyntheticKey::F3,
        "f4" => SyntheticKey::F4,
        "f5" => SyntheticKey::F5,
        "f6" => SyntheticKey::F6,
        "f7" => SyntheticKey::F7,
        "f8" => SyntheticKey::F8,
        "f9" => SyntheticKey::F9,
        "f10" => SyntheticKey::F10,
        "f11" => SyntheticKey::F11,
        "f12" => SyntheticKey::F12,
        "f13" => SyntheticKey::F13,
        "f14" => SyntheticKey::F14,
        "f15" => SyntheticKey::F15,
        "f16" => SyntheticKey::F16,
        "f17" => SyntheticKey::F17,
        "f18" => SyntheticKey::F18,
        "f19" => SyntheticKey::F19,
        "f20" => SyntheticKey::F20,
        "keypad_decimal" => SyntheticKey::KeypadDecimal,
        "keypad_multiply" => SyntheticKey::KeypadMultiply,
        "keypad_plus" => SyntheticKey::KeypadPlus,
        "keypad_clear" => SyntheticKey::KeypadClear,
        "keypad_divide" => SyntheticKey::KeypadDivide,
        "keypad_enter" => SyntheticKey::KeypadEnter,
        "keypad_minus" => SyntheticKey::KeypadMinus,
        "keypad_equal" => SyntheticKey::KeypadEqual,
        "keypad0" => SyntheticKey::Keypad0,
        "keypad1" => SyntheticKey::Keypad1,
        "keypad2" => SyntheticKey::Keypad2,
        "keypad3" => SyntheticKey::Keypad3,
        "keypad4" => SyntheticKey::Keypad4,
        "keypad5" => SyntheticKey::Keypad5,
        "keypad6" => SyntheticKey::Keypad6,
        "keypad7" => SyntheticKey::Keypad7,
        "keypad8" => SyntheticKey::Keypad8,
        "keypad9" => SyntheticKey::Keypad9,
        "help" => SyntheticKey::Help,
        "home" => SyntheticKey::Home,
        "page_up" => SyntheticKey::PageUp,
        "forward_delete" => SyntheticKey::ForwardDelete,
        "end" => SyntheticKey::End,
        "page_down" => SyntheticKey::PageDown,
        "left_arrow" => SyntheticKey::LeftArrow,
        "right_arrow" => SyntheticKey::RightArrow,
        "down_arrow" => SyntheticKey::DownArrow,
        "up_arrow" => SyntheticKey::UpArrow,
        _ => return None,
    })
}

#[cfg(test)]
mod wait_tests {
    use super::*;
    use cerebellum_computer::dispatch::post_condition::ObservedElement;

    fn predicate() -> PostCondition {
        PostCondition::ElementEnabledIs {
            element: AccessibilityElementName::role_and_title("AXButton", "Save"),
            expected: true,
        }
    }

    fn readback(enabled: bool) -> ObservedElement {
        ObservedElement {
            present: true,
            focused: None,
            enabled: Some(enabled),
            value: None,
        }
    }

    #[test]
    fn wait_parses_the_shared_typed_predicate_with_role_and_title_addressing() {
        let expected = predicate();
        let parsed = parse_wait_request(&json!({
            "app": "com.example.Editor",
            "predicate": expected,
            "timeout_ms": 250,
        }))
        .expect("the typed predicate request parses");

        assert_eq!(parsed.app, "com.example.Editor");
        assert_eq!(parsed.predicate, predicate());
        assert_eq!(parsed.timeout_ms, 250);
    }

    #[test]
    fn request_inventory_is_timeout_ms_plus_a_typed_predicate_not_a_string() {
        let refusal = parse_wait_request(&json!({
            "app": "com.example.Editor",
            "predicate": "element_present",
            "timeout_ms": 250,
        }))
        .expect_err("the frozen artifact's string predicate remains a schema mismatch");

        assert_eq!(refusal["field"], "predicate");
        assert_eq!(refusal["reason"], "invalid_predicate");
    }

    #[test]
    fn duration_ms_has_no_wait_compatibility_path() {
        let refusal = parse_wait_request(&json!({
            "app": "com.example.Editor",
            "duration_ms": 25,
            "predicate": predicate(),
        }))
        .expect_err("the obsolete sleep request must stay unreachable");

        assert_eq!(refusal["outcome"], "invalid_request");
        assert_eq!(refusal["field"], "duration_ms");
        assert_eq!(refusal["reason"], "unknown_field");
        assert_eq!(
            validate_capability_result("computer.wait", &refusal),
            Ok(())
        );
    }

    /// Every served parser holds a request to exactly the fields it declares.
    ///
    /// `served_request_fields` is what the flat tool's parity test compares
    /// against, so it must describe the parsers as they behave rather than as
    /// someone listed them. Checked in both directions: a declared-required
    /// field that is missing is refused by name, a declared-optional one may be
    /// left out, and an undeclared one is refused as unknown.
    #[test]
    fn every_served_parser_holds_requests_to_its_declared_fields() {
        let samples = [
            (
                ComputerCapability::OpenApp,
                json!({"target":"com.example.Editor", "url":"synthetic-editor:page"}),
            ),
            (
                ComputerCapability::Type,
                json!({"target": "com.example.Editor", "text": "hi", "role_filter":["button"], "text_filter":"Save", "zoom":"menubar"}),
            ),
            (
                ComputerCapability::Keys,
                json!({"keys": ["s"], "target": "com.example.Editor", "role_filter":["button"], "text_filter":"Save", "zoom":"menubar"}),
            ),
            (
                ComputerCapability::Wait,
                json!({"app": "com.example.Editor", "predicate": predicate(), "timeout_ms": 250}),
            ),
            (
                ComputerCapability::TakeoverMove,
                json!({"image_id": "image-1", "to": {"x": 3, "y": 4}}),
            ),
            (
                ComputerCapability::TakeoverDrag,
                json!({"from": {"x": 1, "y": 2}, "image_id": "image-1", "to": {"x": 3, "y": 4}}),
            ),
            (
                ComputerCapability::TakeoverScroll,
                json!({"amount_lines": -3, "axis": "vertical", "target": "com.example.Editor"}),
            ),
        ];
        for (capability, sample) in samples {
            let (accepted, required) =
                served_request_fields(capability).expect("a served capability declares its fields");
            let sample_fields: Vec<&str> = sample
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            let mut declared: Vec<&str> = accepted.to_vec();
            declared.sort_unstable();
            assert_eq!(
                sample_fields, declared,
                "{capability:?} sample covers every field"
            );
            parse_served_request(capability, &sample)
                .unwrap_or_else(|refusal| panic!("{capability:?} sample refused: {refusal}"));
            for field in accepted {
                let mut without = sample.clone();
                without.as_object_mut().unwrap().remove(*field);
                let verdict = parse_served_request(capability, &without);
                if required.contains(field) {
                    let refusal = verdict.expect_err("a required field is required");
                    assert_eq!(refusal["field"], *field, "{capability:?}");
                    assert_eq!(refusal["reason"], "missing_field", "{capability:?}.{field}");
                } else {
                    assert!(
                        verdict.is_ok(),
                        "{capability:?}.{field} is declared optional"
                    );
                }
            }
            let mut extra = sample.clone();
            extra["undeclared"] = json!(true);
            let refusal = parse_served_request(capability, &extra)
                .expect_err("an undeclared field is refused");
            assert_eq!(refusal["field"], "undeclared", "{capability:?}");
            assert_eq!(refusal["reason"], "unknown_field", "{capability:?}");
        }
    }

    /// A wait names the application its predicate's elements live in. Without
    /// one there is nothing to resolve the predicate against except whichever
    /// application an earlier call selected, which is the hidden selection a
    /// named request exists to avoid, so the request is refused by name.
    #[test]
    fn a_wait_without_app_is_refused_as_a_missing_field() {
        for (request, reason) in [
            (
                json!({"predicate": predicate(), "timeout_ms": 250}),
                "missing_field",
            ),
            (
                json!({"app": "  ", "predicate": predicate(), "timeout_ms": 250}),
                "empty_value",
            ),
            (
                json!({"app": 7, "predicate": predicate(), "timeout_ms": 250}),
                "wrong_type",
            ),
        ] {
            let refusal = parse_wait_request(&request).expect_err("a wait names its app");
            assert_eq!(refusal["outcome"], "invalid_request");
            assert_eq!(refusal["field"], "app");
            assert_eq!(refusal["reason"], reason);
            assert_eq!(
                validate_capability_result("computer.wait", &refusal),
                Ok(())
            );
        }
    }

    #[test]
    fn all_wait_terminal_states_use_distinct_outcomes_and_the_current_settle_path() {
        let cases = [
            WaitResult {
                outcome: WaitOutcome::Settled,
                evidence: WaitEvidence::Settled {
                    predicate: predicate(),
                    readback: readback(true),
                },
                attempts: 1,
            },
            WaitResult {
                outcome: WaitOutcome::TimedOut,
                evidence: WaitEvidence::TimedOut {
                    predicate: predicate(),
                    readback: readback(false),
                },
                attempts: 3,
            },
            WaitResult {
                outcome: WaitOutcome::Indeterminate,
                evidence: WaitEvidence::Indeterminate {
                    predicate: predicate(),
                    readback: None,
                    reason: "target_not_inspectable".to_string(),
                },
                attempts: 1,
            },
        ];

        let replies: Vec<Value> = cases.into_iter().map(wait_wire_reply).collect();
        for reply in &replies {
            assert_eq!(reply["settle_path"], "poll_with_deadline");
            assert_eq!(validate_capability_result("computer.wait", reply), Ok(()));
        }
        assert_eq!(replies[0]["outcome"], "predicate_satisfied");
        assert_eq!(replies[1]["outcome"], "timeout");
        assert_eq!(replies[2]["outcome"], "indeterminate");

        let evidence: Vec<WaitEvidence> = replies
            .iter()
            .map(|reply| {
                serde_json::from_str(reply["evidence"].as_str().expect("evidence is a string"))
                    .expect("evidence carries the typed terminal state")
            })
            .collect();
        assert!(matches!(evidence[0], WaitEvidence::Settled { .. }));
        assert!(matches!(evidence[1], WaitEvidence::TimedOut { .. }));
        assert!(matches!(evidence[2], WaitEvidence::Indeterminate { .. }));
    }
}

#[cfg(test)]
mod synthetic_parse_tests {
    use super::*;

    const ALL_SYNTHETIC_KEYS: [SyntheticKey; 101] = [
        SyntheticKey::A,
        SyntheticKey::S,
        SyntheticKey::D,
        SyntheticKey::F,
        SyntheticKey::H,
        SyntheticKey::G,
        SyntheticKey::Z,
        SyntheticKey::X,
        SyntheticKey::C,
        SyntheticKey::V,
        SyntheticKey::Section,
        SyntheticKey::B,
        SyntheticKey::Q,
        SyntheticKey::W,
        SyntheticKey::E,
        SyntheticKey::R,
        SyntheticKey::Y,
        SyntheticKey::T,
        SyntheticKey::Digit1,
        SyntheticKey::Digit2,
        SyntheticKey::Digit3,
        SyntheticKey::Digit4,
        SyntheticKey::Digit5,
        SyntheticKey::Digit6,
        SyntheticKey::Digit7,
        SyntheticKey::Digit8,
        SyntheticKey::Digit9,
        SyntheticKey::Digit0,
        SyntheticKey::Equal,
        SyntheticKey::Minus,
        SyntheticKey::RightBracket,
        SyntheticKey::O,
        SyntheticKey::U,
        SyntheticKey::LeftBracket,
        SyntheticKey::I,
        SyntheticKey::P,
        SyntheticKey::Return,
        SyntheticKey::L,
        SyntheticKey::J,
        SyntheticKey::Quote,
        SyntheticKey::K,
        SyntheticKey::Semicolon,
        SyntheticKey::Backslash,
        SyntheticKey::Comma,
        SyntheticKey::Slash,
        SyntheticKey::N,
        SyntheticKey::M,
        SyntheticKey::Period,
        SyntheticKey::Tab,
        SyntheticKey::Space,
        SyntheticKey::Grave,
        SyntheticKey::Backspace,
        SyntheticKey::Escape,
        SyntheticKey::F1,
        SyntheticKey::F2,
        SyntheticKey::F3,
        SyntheticKey::F4,
        SyntheticKey::F5,
        SyntheticKey::F6,
        SyntheticKey::F7,
        SyntheticKey::F8,
        SyntheticKey::F9,
        SyntheticKey::F10,
        SyntheticKey::F11,
        SyntheticKey::F12,
        SyntheticKey::F13,
        SyntheticKey::F14,
        SyntheticKey::F15,
        SyntheticKey::F16,
        SyntheticKey::F17,
        SyntheticKey::F18,
        SyntheticKey::F19,
        SyntheticKey::F20,
        SyntheticKey::KeypadDecimal,
        SyntheticKey::KeypadMultiply,
        SyntheticKey::KeypadPlus,
        SyntheticKey::KeypadClear,
        SyntheticKey::KeypadDivide,
        SyntheticKey::KeypadEnter,
        SyntheticKey::KeypadMinus,
        SyntheticKey::KeypadEqual,
        SyntheticKey::Keypad0,
        SyntheticKey::Keypad1,
        SyntheticKey::Keypad2,
        SyntheticKey::Keypad3,
        SyntheticKey::Keypad4,
        SyntheticKey::Keypad5,
        SyntheticKey::Keypad6,
        SyntheticKey::Keypad7,
        SyntheticKey::Keypad8,
        SyntheticKey::Keypad9,
        SyntheticKey::Help,
        SyntheticKey::Home,
        SyntheticKey::PageUp,
        SyntheticKey::ForwardDelete,
        SyntheticKey::End,
        SyntheticKey::PageDown,
        SyntheticKey::LeftArrow,
        SyntheticKey::RightArrow,
        SyntheticKey::DownArrow,
        SyntheticKey::UpArrow,
    ];

    /// Every neutral key is reachable from the wire.
    ///
    /// synthetic_key_from_wire matches on a string, so it needs a catch-all and
    /// a key added to the enum compiles fine while being unreachable by any
    /// caller. The exhaustive match BELOW is the fence the parser cannot be:
    /// a new variant fails to compile here, which is what the parser's own doc
    /// promises and cannot deliver on its own.
    #[test]
    fn every_neutral_key_is_reachable_from_a_wire_name() {
        fn wire_name(key: SyntheticKey) -> &'static str {
            match key {
                SyntheticKey::A => "a",
                SyntheticKey::S => "s",
                SyntheticKey::D => "d",
                SyntheticKey::F => "f",
                SyntheticKey::H => "h",
                SyntheticKey::G => "g",
                SyntheticKey::Z => "z",
                SyntheticKey::X => "x",
                SyntheticKey::C => "c",
                SyntheticKey::V => "v",
                SyntheticKey::Section => "section",
                SyntheticKey::B => "b",
                SyntheticKey::Q => "q",
                SyntheticKey::W => "w",
                SyntheticKey::E => "e",
                SyntheticKey::R => "r",
                SyntheticKey::Y => "y",
                SyntheticKey::T => "t",
                SyntheticKey::Digit1 => "digit1",
                SyntheticKey::Digit2 => "digit2",
                SyntheticKey::Digit3 => "digit3",
                SyntheticKey::Digit4 => "digit4",
                SyntheticKey::Digit5 => "digit5",
                SyntheticKey::Digit6 => "digit6",
                SyntheticKey::Digit7 => "digit7",
                SyntheticKey::Digit8 => "digit8",
                SyntheticKey::Digit9 => "digit9",
                SyntheticKey::Digit0 => "digit0",
                SyntheticKey::Equal => "equal",
                SyntheticKey::Minus => "minus",
                SyntheticKey::RightBracket => "right_bracket",
                SyntheticKey::O => "o",
                SyntheticKey::U => "u",
                SyntheticKey::LeftBracket => "left_bracket",
                SyntheticKey::I => "i",
                SyntheticKey::P => "p",
                SyntheticKey::Return => "return",
                SyntheticKey::L => "l",
                SyntheticKey::J => "j",
                SyntheticKey::Quote => "quote",
                SyntheticKey::K => "k",
                SyntheticKey::Semicolon => "semicolon",
                SyntheticKey::Backslash => "backslash",
                SyntheticKey::Comma => "comma",
                SyntheticKey::Slash => "slash",
                SyntheticKey::N => "n",
                SyntheticKey::M => "m",
                SyntheticKey::Period => "period",
                SyntheticKey::Tab => "tab",
                SyntheticKey::Space => "space",
                SyntheticKey::Grave => "grave",
                SyntheticKey::Backspace => "backspace",
                SyntheticKey::Escape => "escape",
                SyntheticKey::F1 => "f1",
                SyntheticKey::F2 => "f2",
                SyntheticKey::F3 => "f3",
                SyntheticKey::F4 => "f4",
                SyntheticKey::F5 => "f5",
                SyntheticKey::F6 => "f6",
                SyntheticKey::F7 => "f7",
                SyntheticKey::F8 => "f8",
                SyntheticKey::F9 => "f9",
                SyntheticKey::F10 => "f10",
                SyntheticKey::F11 => "f11",
                SyntheticKey::F12 => "f12",
                SyntheticKey::F13 => "f13",
                SyntheticKey::F14 => "f14",
                SyntheticKey::F15 => "f15",
                SyntheticKey::F16 => "f16",
                SyntheticKey::F17 => "f17",
                SyntheticKey::F18 => "f18",
                SyntheticKey::F19 => "f19",
                SyntheticKey::F20 => "f20",
                SyntheticKey::KeypadDecimal => "keypad_decimal",
                SyntheticKey::KeypadMultiply => "keypad_multiply",
                SyntheticKey::KeypadPlus => "keypad_plus",
                SyntheticKey::KeypadClear => "keypad_clear",
                SyntheticKey::KeypadDivide => "keypad_divide",
                SyntheticKey::KeypadEnter => "keypad_enter",
                SyntheticKey::KeypadMinus => "keypad_minus",
                SyntheticKey::KeypadEqual => "keypad_equal",
                SyntheticKey::Keypad0 => "keypad0",
                SyntheticKey::Keypad1 => "keypad1",
                SyntheticKey::Keypad2 => "keypad2",
                SyntheticKey::Keypad3 => "keypad3",
                SyntheticKey::Keypad4 => "keypad4",
                SyntheticKey::Keypad5 => "keypad5",
                SyntheticKey::Keypad6 => "keypad6",
                SyntheticKey::Keypad7 => "keypad7",
                SyntheticKey::Keypad8 => "keypad8",
                SyntheticKey::Keypad9 => "keypad9",
                SyntheticKey::Help => "help",
                SyntheticKey::Home => "home",
                SyntheticKey::PageUp => "page_up",
                SyntheticKey::ForwardDelete => "forward_delete",
                SyntheticKey::End => "end",
                SyntheticKey::PageDown => "page_down",
                SyntheticKey::LeftArrow => "left_arrow",
                SyntheticKey::RightArrow => "right_arrow",
                SyntheticKey::DownArrow => "down_arrow",
                SyntheticKey::UpArrow => "up_arrow",
            }
        }

        for key in ALL_SYNTHETIC_KEYS {
            let name = wire_name(key);
            assert_eq!(
                super::synthetic_key_from_wire(name),
                Some(key),
                "{name} does not round-trip to the key it names"
            );
        }
    }

    fn parse(capability: ComputerCapability, arguments: Value) -> Result<ParsedSynthetic, Value> {
        parse_synthetic_request(capability, &arguments)
    }

    /// Every name in the wire table maps back to a distinct key, and the
    /// table itself has no duplicates: two names for one key would be a
    /// request either spelling could make with no way to tell them apart.
    #[test]
    fn the_wire_key_table_is_total_and_duplicate_free() {
        let names = [
            "a",
            "s",
            "d",
            "f",
            "h",
            "g",
            "z",
            "x",
            "c",
            "v",
            "section",
            "b",
            "q",
            "w",
            "e",
            "r",
            "y",
            "t",
            "digit1",
            "digit2",
            "digit3",
            "digit4",
            "digit5",
            "digit6",
            "digit7",
            "digit8",
            "digit9",
            "digit0",
            "equal",
            "minus",
            "right_bracket",
            "o",
            "u",
            "left_bracket",
            "i",
            "p",
            "return",
            "l",
            "j",
            "quote",
            "k",
            "semicolon",
            "backslash",
            "comma",
            "slash",
            "n",
            "m",
            "period",
            "tab",
            "space",
            "grave",
            "backspace",
            "escape",
            "f1",
            "f2",
            "f3",
            "f4",
            "f5",
            "f6",
            "f7",
            "f8",
            "f9",
            "f10",
            "f11",
            "f12",
            "f13",
            "f14",
            "f15",
            "f16",
            "f17",
            "f18",
            "f19",
            "f20",
            "keypad_decimal",
            "keypad_multiply",
            "keypad_plus",
            "keypad_clear",
            "keypad_divide",
            "keypad_enter",
            "keypad_minus",
            "keypad_equal",
            "keypad0",
            "keypad1",
            "keypad2",
            "keypad3",
            "keypad4",
            "keypad5",
            "keypad6",
            "keypad7",
            "keypad8",
            "keypad9",
            "help",
            "home",
            "page_up",
            "forward_delete",
            "end",
            "page_down",
            "left_arrow",
            "right_arrow",
            "down_arrow",
            "up_arrow",
        ];
        let keys: Vec<SyntheticKey> = names
            .iter()
            .map(|name| synthetic_key_from_wire(name).expect("every listed name maps"))
            .collect();
        let mut deduped = keys.clone();
        deduped.sort_by_key(|key| format!("{key:?}"));
        deduped.dedup();
        assert_eq!(keys.len(), deduped.len(), "the table has a duplicate");
        assert_eq!(synthetic_key_from_wire("cmd"), None);
        assert_eq!(synthetic_key_from_wire("S"), None);
    }

    /// The Windows modifier has a neutral representation for Windows lock,
    /// but macOS must refuse its wire spelling rather than dropping it.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_refuses_the_windows_modifier_as_an_unknown_key() {
        let refusal = parse(
            ComputerCapability::Keys,
            json!({"keys": ["windows", "l"], "target": "editor"}),
        )
        .expect_err("macOS has no Windows modifier");
        assert_eq!(refusal["field"], "keys");
        assert_eq!(refusal["reason"], "unknown_key");
    }

    /// The durable_chord override, asserted at the classification itself:
    /// Command escalates, everything else stays compose.
    #[test]
    fn only_a_command_chord_escalates_to_mutate_durable() {
        let command = SyntheticKeyModifiers {
            command: true,
            ..SyntheticKeyModifiers::NONE
        };
        assert_eq!(chord_action_kind(command), ActionKind::MutateDurable);
        for modifiers in [
            SyntheticKeyModifiers::NONE,
            SyntheticKeyModifiers {
                shift: true,
                ..SyntheticKeyModifiers::NONE
            },
            SyntheticKeyModifiers {
                option: true,
                ..SyntheticKeyModifiers::NONE
            },
            SyntheticKeyModifiers {
                control: true,
                ..SyntheticKeyModifiers::NONE
            },
            SyntheticKeyModifiers {
                shift: true,
                option: true,
                control: true,
                windows: false,
                command: false,
            },
        ] {
            assert_eq!(
                chord_action_kind(modifiers),
                ActionKind::Compose,
                "{modifiers:?} must not escalate"
            );
        }
    }

    /// A well-formed chord parses into the one key and its modifiers; two
    /// named keys are refused rather than served as one chord.
    #[test]
    fn a_chord_is_modifiers_around_exactly_one_key() {
        let parsed = parse(
            ComputerCapability::Keys,
            json!({"keys": ["command", "shift", "z"], "target": "editor"}),
        )
        .expect("a well-formed chord parses");
        assert_eq!(
            parsed.action,
            SyntheticAction::key_combination(
                SyntheticKey::Z,
                SyntheticKeyModifiers {
                    command: true,
                    shift: true,
                    ..SyntheticKeyModifiers::NONE
                },
            )
        );

        for keys in [
            json!(["a", "b"]),
            json!(["command"]),
            json!([]),
            json!(["not-a-key"]),
        ] {
            assert!(
                parse(
                    ComputerCapability::Keys,
                    json!({"keys": keys, "target": "editor"})
                )
                .is_err(),
                "{keys} parsed as a chord"
            );
        }
    }

    /// The frozen bound is enforced at parse: 4096 characters of text, and no
    /// empty text.
    #[test]
    fn the_frozen_request_bounds_are_enforced() {
        let long = "a".repeat(4_097);
        assert!(parse(
            ComputerCapability::Type,
            json!({"target": "editor", "text": long}),
        )
        .is_err());
        assert!(
            parse(
                ComputerCapability::Type,
                json!({"target": "editor", "text": ""}),
            )
            .is_err(),
            "an empty type plans no events and must not report success"
        );
    }

    /// An undeclared field is refused as unknown rather than silently
    /// dropped: the frozen schemas are closed.
    #[test]
    fn an_undeclared_field_is_refused_for_each_keystroke_row() {
        for (capability, mut request) in [
            (
                ComputerCapability::Type,
                json!({"target": "editor", "text": "hi"}),
            ),
            (
                ComputerCapability::Keys,
                json!({"keys": ["s"], "target": "editor"}),
            ),
        ] {
            request["speed"] = json!("fast");
            let refusal = parse(capability, request).expect_err("an unknown field must refuse");
            assert_eq!(refusal["field"], "speed");
            assert_eq!(refusal["reason"], "unknown_field");
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod startup_reconciliation_tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex as StdMutex};

    use cerebellum_computer::audit::redaction::ExcludeApplicationText;
    use cerebellum_computer::audit::{
        ComputerAuditError, ComputerPlaneDescriptor, ObservationState, TypedCaptureDispatch,
    };
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_computer::grounding::ContainmentRung;
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::{
        DurableState, JournalConfig, JournalError, JournalIdentity, JournalStorage, StorageError,
    };

    use super::*;

    #[derive(Clone, Default)]
    struct FailingRecoveryStorage {
        state: Arc<StdMutex<DurableState>>,
        fail_saves: Arc<AtomicBool>,
    }

    impl JournalStorage for FailingRecoveryStorage {
        fn load(&self) -> Result<DurableState, StorageError> {
            self.state
                .lock()
                .map(|state| state.clone())
                .map_err(|_| StorageError::LockPoisoned {
                    binding: "computer startup recovery test load".into(),
                })
        }

        fn save(&self, state: &DurableState) -> Result<(), StorageError> {
            if self.fail_saves.load(Ordering::SeqCst) {
                return Err(StorageError::LockPoisoned {
                    binding: "computer startup recovery test save".into(),
                });
            }
            *self.state.lock().map_err(|_| StorageError::LockPoisoned {
                binding: "computer startup recovery test save".into(),
            })? = state.clone();
            Ok(())
        }

        fn raise_format(
            &self,
            _format: cerebellum_core::format_floor::DurableFormat,
        ) -> Result<(), StorageError> {
            Ok(())
        }
    }

    fn custody() -> CaptureCustody {
        CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 100,
                maximum_pin_lifetime_ms: 100,
                maximum_concurrently_pinned_artifacts: 2,
                maximum_total_pinned_artifact_bytes: 1_000,
                maximum_custody_attachment_bytes: 1_000,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .unwrap()
    }

    #[test]
    fn construction_refuses_when_startup_reconciliation_cannot_commit() {
        let storage = FailingRecoveryStorage::default();
        let fail_saves = Arc::clone(&storage.fail_saves);
        let mut audit = ComputerAudit::new(
            ExcludeApplicationText,
            cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
            JournalConfig {
                journal_retention_bytes: 20_000,
                journal_max_entry_bytes: 4_000,
            },
            storage,
            custody(),
        )
        .unwrap();
        let descriptor = ComputerPlaneDescriptor::new(
            ComputerCapability::ReadState,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        );
        let handle = audit
            .reserve(
                JournalIdentity {
                    witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
                    principal: "prefrontal".into(),
                    conversation_key: "conversation-1".into(),
                    agent_project_id: "project-1".into(),
                    session_kind: SessionKind::Primary,
                    origin: Default::default(),
                    computer_order: None,
                },
                descriptor,
            )
            .unwrap();
        let dispatch = TypedCaptureDispatch::new(
            ComputerCapability::ReadState,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        )
        .dispatch_material(b"computer.read_state".to_vec());
        audit
            .commit_dispatched(handle, &dispatch, b"lease".to_vec(), None)
            .unwrap();
        fail_saves.store(true, Ordering::SeqCst);

        let error = match reconcile_production_audit(audit, 0) {
            Ok(_) => panic!("construction served with unreconciled audit state"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            ComputerPlaneUnavailable::AuditReconciliation(ComputerAuditError::Journal(
                JournalError::FinalizationPending,
            ))
        );
    }

    /// The production constructor must REACH reconciliation, which the test
    /// above does not establish: it calls `reconcile_production_audit`
    /// directly, so it proves the helper refuses and says nothing about
    /// whether anything calls it. Deleting the call from `production_audit`
    /// left that test green -- which is exactly how `startup_reconcile` came
    /// to have no caller at all, the gap this whole path was written to close.
    ///
    /// Asserted over the source because the behavioural route is not available
    /// here: `production_audit` resolves its journal through
    /// `journal_data_path`, so driving it would write into the real user data
    /// directory. A source assertion is weaker than a behavioural one and is
    /// the strongest available without making that path injectable, which is a
    /// larger change than this fence.
    #[test]
    fn the_production_constructor_reaches_startup_reconciliation() {
        let source = include_str!("mod.rs");
        // Split at the test module's own attribute, assembled at runtime so
        // this literal is not itself the first match. Writing the attribute
        // whole made the split land on THIS line, which put the test module --
        // and its direct call to the helper -- on the production side, so the
        // assertion passed while the production call site was deleted. A
        // scan whose delimiter appears in the scanner is green for a reason
        // unrelated to the property it claims to check.
        let module_attribute =
            format!("#[cfg(all({}, target_os = \"macos\")))]", "test").replace(")))]", "))]");
        let (production, _) = source
            .split_once(module_attribute.as_str())
            .expect("this module carries a macOS-gated test module");
        assert!(
            production.contains("reconcile_production_audit(audit, 0)"),
            "production_audit no longer reconciles the audit before serving. An \
             audit whose prior state was never restored cannot account for what \
             follows: a crash-orphaned actuation stays orphaned, and the entry \
             recording that a press may have landed is never resolved by anyone."
        );
    }
}

#[cfg(test)]
mod cancel_wire_tests {
    use super::*;
    use cerebellum_computer::audit::redaction::ExcludeApplicationText;
    use cerebellum_computer::capture::InMemoryCaptureBackend;
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_computer::dispatch::post_condition::ObservedElement;
    use cerebellum_core::journal::{InMemoryJournalStorage, JournalConfig};

    fn wait_predicate() -> PostCondition {
        PostCondition::ElementEnabledIs {
            element: AccessibilityElementName::identifier("element-1"),
            expected: true,
        }
    }

    fn cancelled_wait_reply() -> Value {
        wait_wire_reply(WaitResult {
            outcome: WaitOutcome::Cancelled,
            evidence: WaitEvidence::Cancelled {
                predicate: wait_predicate(),
                readback: ObservedElement::absent(),
            },
            attempts: 2,
        })
    }

    #[test]
    fn a_pre_poll_cancel_has_a_plain_reason_and_survives_withholding() {
        let reply = cancelled_before_polling_reply(wait_predicate());
        assert_eq!(reply["outcome"], "cancelled");
        assert_eq!(reply["attempts"], 0);
        let evidence: Value = serde_json::from_str(reply["evidence"].as_str().unwrap()).unwrap();
        assert_eq!(evidence["reason"], "cancelled_while_awaiting_consent");
        assert_eq!(evidence["readback"], Value::Null);
        validate_capability_result("computer.wait", &reply).unwrap();
    }

    #[test]
    fn a_cancelled_wait_is_not_reported_as_indeterminate() {
        let reply = cancelled_wait_reply();
        assert_eq!(reply["outcome"], "cancelled");
        let evidence: Value = serde_json::from_str(reply["evidence"].as_str().unwrap()).unwrap();
        assert_eq!(evidence["status"], "cancelled");
        assert!(evidence.get("reason").is_none());
    }

    #[test]
    fn a_cancelled_wait_reply_reports_the_returned_attempt_count() {
        assert_eq!(cancelled_wait_reply()["attempts"], 2);
    }

    #[test]
    fn the_cancelled_wait_reply_survives_withholding() {
        validate_capability_result("computer.wait", &cancelled_wait_reply())
            .expect("cancelled wait reply violates its frozen schema");
    }

    /// Every OTHER row's success reply must survive withholding too.
    ///
    /// The synthetic case above was found after it shipped; these three are the
    /// same question asked of the rows that were not implicated, so a future
    /// mint cannot break one of them quietly. Each builder is driven at its own
    /// production entry point rather than through a hand-written literal: a
    /// fixture that states the reply cannot notice the builder diverging from
    /// the schema, which is the whole defect class.
    /// The disclosure survives the enforcement layer, carrying the value it
    /// measured rather than the default.
    ///
    /// Aimed at the schema rather than at the builder: a field the builder sets
    /// correctly and the enforcement layer strips before it reaches a caller
    /// looks exactly like a field nobody set, and that failure has shipped from
    /// here before. So the assertion is on the reply AFTER withholding, and on
    /// a value that is NOT the default, since a default surviving proves only
    /// that something named "windows_enumeration" got through.
    #[test]
    fn every_wait_reply_survives_withholding() {
        for (outcome, evidence) in [
            (
                WaitOutcome::Settled,
                WaitEvidence::Settled {
                    predicate: wait_predicate(),
                    readback: ObservedElement::absent(),
                },
            ),
            (
                WaitOutcome::TimedOut,
                WaitEvidence::TimedOut {
                    predicate: wait_predicate(),
                    readback: ObservedElement::absent(),
                },
            ),
        ] {
            let wait = wait_wire_reply(WaitResult {
                outcome,
                evidence,
                attempts: 1,
            });
            validate_capability_result("computer.wait", &wait)
                .expect("wait success reply violates its frozen schema");
        }
        validate_capability_result(
            "computer.wait",
            &wait_indeterminate_reply(Some(wait_predicate()), json!("target_unreadable")),
        )
        .expect("wait indeterminate reply violates its frozen schema");
    }

    /// Every synthetic row's SUCCESS reply must survive withholding.
    ///
    /// Withholding REJECTS an undeclared property rather than dropping it, so a
    /// success reply carrying a field its row does not declare answers the
    /// caller with a schema violation for an action that happened. Asserting
    /// the refusal shapes is not enough — a refusal carries a different key set
    /// than a success, so the success path can be wrong while every refusal
    /// test stays green.
    #[test]
    fn every_synthetic_success_reply_survives_withholding() {
        for capability in [ComputerCapability::Type, ComputerCapability::Keys] {
            for forfeiture in [None, Some("identity_unavailable")] {
                let reply = synthetic_wire_envelope(synthetic_success_reply(
                    "pid_structural",
                    true,
                    "effect_indeterminate",
                    forfeiture,
                ));
                assert!(
                    reply.get("containment_rung").is_some(),
                    "{capability:?} success must state its rung"
                );
                validate_capability_result(capability.capability_id(), &reply).unwrap_or_else(
                    |error| {
                        panic!("{capability:?} success reply violates its frozen schema: {error}")
                    },
                );
            }
        }
    }

    #[tokio::test]
    async fn the_cancel_reply_carries_posts_returned_through_withholding() {
        let custody = CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 100,
                maximum_pin_lifetime_ms: 100,
                maximum_concurrently_pinned_artifacts: 2,
                maximum_total_pinned_artifact_bytes: 1000,
                maximum_custody_attachment_bytes: 1000,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .unwrap();
        let audit = ComputerAudit::new(
            ExcludeApplicationText,
            cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
            JournalConfig {
                journal_retention_bytes: 20000,
                journal_max_entry_bytes: 4000,
            },
            InMemoryJournalStorage::default(),
            custody,
        )
        .unwrap();
        let plane: ComputerPlane<InMemoryCaptureBackend, _, _, _> =
            ComputerPlane::with_result_schema_enforcement(audit, ResultSchemaEnforcement::Withhold)
                .with_permission_liveness(permissions::live_for_test());
        let (tx, mut rx) = tokio::sync::mpsc::channel(8);
        for capability in [ComputerCapability::Type, ComputerCapability::Keys] {
            let reply =
                synthetic_wire_envelope(synthetic_dispatch_refusal(&DispatchError::Cancelled {
                    posts_returned: 2,
                    held_state: HeldStateDisposition::Released { posts_returned: 1 },
                }));
            match plane.finish_reply(capability, reply) {
                Ok(reply) => crate::send_tool_response(&tx, 1, 7, 1, 42, reply)
                    .await
                    .unwrap(),
                Err(error) => crate::send_route_error(
                    &tx,
                    1,
                    7,
                    1,
                    42,
                    "computer_result_schema_violation",
                    &error.to_string(),
                )
                .await
                .unwrap(),
            }
            let frame = rx.recv().await.unwrap();
            assert_eq!(
                frame.header.ty,
                subc_protocol::FrameType::Response,
                "{}",
                String::from_utf8_lossy(&frame.body)
            );
            let wire: Value = serde_json::from_slice(&frame.body).unwrap();
            assert_eq!(wire["outcome"], "cancelled");
            assert_eq!(wire["posts_returned"], 2);
            assert_eq!(wire["reason"], "caller_interrupted_held_input_released");
            assert_eq!(
                wire["remedy"],
                "the action was interrupted by the caller; no retry is implied"
            );
        }
    }
}

#[cfg(test)]
mod outcome_tests;

#[cfg(all(test, target_os = "macos"))]
pub(crate) mod future_size_tests;

#[cfg(all(test, target_os = "macos"))]
pub(crate) type ScriptedComputerPlane = ComputerPlane<
    NativeComputerCaptureBackend,
    cerebellum_computer::audit::redaction::ExcludeApplicationText,
    cerebellum_core::journal::ValidatedSeverityTaxonomy,
    crate::PlaneJournalStorage,
    turn_stop_driver::Driver,
>;

#[cfg(all(test, target_os = "macos"))]
#[test]
fn unit_tests_keep_the_native_computer_driver_type() {
    assert_eq!(
        std::any::TypeId::of::<NativeComputerPlatformDriver>(),
        std::any::TypeId::of::<cerebellum_computer::platform::MacOs26PlatformDriver>(),
    );
}

#[cfg(test)]
mod name_match_tests {
    use super::*;

    fn app(name: &str, bundle_identity: &str, pid: u32) -> RunningApp {
        RunningApp {
            name: name.into(),
            bundle_identity: bundle_identity.into(),
            pid,
            frontmost: false,
        }
    }

    fn desk() -> Vec<RunningApp> {
        vec![
            app("Magic Context Dashboard", "com.example.dashboard", 1),
            app("Magic Mouse Utility", "com.example.mouse", 2),
            app("Mail", "com.apple.mail", 3),
            app("Mailspring", "com.example.mailspring", 4),
        ]
    }

    #[test]
    fn a_partial_name_fitting_one_app_resolves_and_names_it() {
        for wanted in [
            "Magic Context",
            "magic context dash",
            "Context Dashboard",
            "dashboard",
        ] {
            assert_eq!(
                match_target_name(wanted, &desk()).unwrap(),
                MatchedTarget {
                    bundle_identity: "com.example.dashboard".into(),
                    partial_name: Some("Magic Context Dashboard".into()),
                },
                "{wanted}"
            );
        }
    }

    #[test]
    fn an_exact_name_wins_over_a_longer_one_it_prefixes() {
        assert_eq!(
            match_target_name("mail", &desk()).unwrap(),
            MatchedTarget {
                bundle_identity: "com.apple.mail".into(),
                partial_name: None,
            }
        );
    }

    #[test]
    fn a_partial_name_fitting_several_apps_refuses_listing_them() {
        let refusal = match_target_name("Magic", &desk()).unwrap_err();
        assert_eq!(refusal["outcome"], "ambiguous_app");
        assert_eq!(refusal["target"], "Magic");
        let names: Vec<_> = refusal["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|candidate| candidate["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["Magic Context Dashboard", "Magic Mouse Utility"]);
    }

    #[test]
    fn a_word_inside_another_word_or_an_empty_name_matches_nothing() {
        for wanted in ["agic", "ontext Dash", "", "   "] {
            assert_eq!(
                match_target_name(wanted, &desk()).unwrap_err()["outcome"],
                "no_running_app_named",
                "{wanted:?}"
            );
        }
    }

    #[test]
    fn list_apps_takes_only_an_optional_text_filter() {
        assert_eq!(parse_list_apps_request(&json!({})), Ok(None));
        assert_eq!(
            parse_list_apps_request(&json!({"text_filter":"  Mail "})),
            Ok(Some("Mail".into()))
        );
        assert_eq!(
            parse_list_apps_request(&json!({"text_filter":" "})),
            Ok(None)
        );
        assert_eq!(
            parse_list_apps_request(&json!({"text_filter":3})).unwrap_err()["field"],
            "text_filter"
        );
        assert_eq!(
            parse_list_apps_request(&json!({"zoom":"x"})).unwrap_err()["field"],
            "zoom"
        );
        assert!(listed_by_filter(
            Some("MAIL"),
            "Mailspring",
            "com.example.mailspring"
        ));
        assert!(listed_by_filter(Some("apple.ma"), "Mail", "com.apple.mail"));
        assert!(!listed_by_filter(
            Some("mail"),
            "Calendar",
            "com.apple.iCal"
        ));
        assert!(listed_by_filter(None, "Calendar", "com.apple.iCal"));
    }
}
