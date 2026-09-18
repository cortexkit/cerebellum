//! Serving the computer plane's capabilities over the wire.
//!
//! This is the path from a tool request to the plane's policy layers: it
//! establishes that the caller may act on the application it is asking about,
//! performs the action, records it, and answers.
//!
//! THE ORDER MATTERS AND IT IS NOT THE OBVIOUS ONE. The action vocabulary
//! requires `computer.screenshot` to be recorded before its result is handed
//! back — not merely before the next action, and not asynchronously afterwards.
//! An observation that reached the caller while leaving no durable record is one
//! nobody can account for later.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex as StdMutex};

use cerebellum_computer::audit::{
    ComputerAudit, ComputerCapability, ComputerPlaneDescriptor, ObservationState,
    TypedCaptureDispatch,
};
use cerebellum_computer::capture::{
    CaptureArtifact, CaptureBackend, ScopedCaptureController, WindowCaptureRegion,
};
use cerebellum_computer::capture_custody::{CaptureScope, PixelArtifact};
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
use cerebellum_computer::grounding::ContainmentRung;
use cerebellum_computer::platform::containment::ContainmentRung as DispatchContainmentRung;
use cerebellum_computer::platform::vocabulary::{
    validate_capability_result, CapabilityResultValidationError,
};
use cerebellum_computer::platform::AccessibilityElementName;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use cerebellum_computer::platform::{
    AccessibilityKeyForm, AccessibilityReadFailure, AccessibilityTreeRequest, DriverError,
    ElementResolutionRequest, ElementResolutionResult, SemanticDispatchRequest,
    SemanticDriverError, TargetDisposition, SEMANTIC_CANCEL_ACTION, SEMANTIC_PRESS_ACTION,
};
#[cfg(target_os = "macos")]
pub(crate) type NativeComputerPlatformDriver = cerebellum_computer::platform::MacOs26PlatformDriver;
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
    blocked_chord, current_blocked_chord_platform, DispatchMode, EffectStatus,
    HeldStateDisposition, PlatformDriver, SyntheticAction, SyntheticKey, SyntheticKeyModifiers,
    SyntheticPoint, SyntheticScrollUnit, UnsupportedPlatformDriver,
};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::consent::{ActionKind, LeaseKey};
use cerebellum_core::journal::JournalIdentity;
use cerebellum_core::journal::{
    CallerRefusalHistory, JournalStorage, Redactor, RefusalRing, RefusalRingConfig,
    SeverityTaxonomy,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

use crate::management::{ActionAuthority, ManagementPlane};

/// The largest encoded image this module will hand to a caller.
///
/// The same bound the browser plane applies, for the same reason: the wire
/// refuses a larger one, so producing it would mean doing the work and then
/// discarding it at the boundary with an error that describes the transport
/// rather than the request.
pub const MAX_ENCODED_IMAGE_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CaptureRegion {
    x_px: u32,
    y_px: u32,
    width_px: u32,
    height_px: u32,
}

fn invalid_screenshot_request(field: &str, reason: &str) -> Value {
    json!({
        "outcome": "invalid_request",
        "field": field,
        "reason": reason,
    })
}

fn screenshot_region_component(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<u32, Value> {
    match object.get(field) {
        Some(Value::Number(value)) => value
            .as_u64()
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| invalid_screenshot_request(field, "invalid_value")),
        Some(_) => Err(invalid_screenshot_request(field, "wrong_type")),
        None => Err(invalid_screenshot_request(field, "missing_field")),
    }
}

fn parse_screenshot_region(arguments: &Value) -> Result<Option<CaptureRegion>, Value> {
    let Some(region) = arguments.get("region") else {
        return Ok(None);
    };
    let Some(object) = region.as_object() else {
        return Err(invalid_screenshot_request("region", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !matches!(field.as_str(), "x_px" | "y_px" | "width_px" | "height_px"))
        .min()
    {
        return Err(invalid_screenshot_request(field, "unknown_field"));
    }
    let parsed = CaptureRegion {
        x_px: screenshot_region_component(object, "x_px")?,
        y_px: screenshot_region_component(object, "y_px")?,
        width_px: screenshot_region_component(object, "width_px")?,
        height_px: screenshot_region_component(object, "height_px")?,
    };
    if parsed.width_px == 0 {
        return Err(invalid_screenshot_request("width_px", "invalid_value"));
    }
    if parsed.height_px == 0 {
        return Err(invalid_screenshot_request("height_px", "invalid_value"));
    }
    Ok(Some(parsed))
}

fn region_fits_window(region: &CaptureRegion, width_px: u32, height_px: u32) -> bool {
    region
        .x_px
        .checked_add(region.width_px)
        .is_some_and(|right| right <= width_px)
        && region
            .y_px
            .checked_add(region.height_px)
            .is_some_and(|bottom| bottom <= height_px)
}

fn capture_region(region: CaptureRegion) -> WindowCaptureRegion {
    WindowCaptureRegion {
        x_px: region.x_px,
        y_px: region.y_px,
        width_px: region.width_px,
        height_px: region.height_px,
    }
}

/// Give every screenshot outcome the result envelope declared by vocabulary v8.
///
/// `value` repeats the caller's request and `detail` exposes backend diagnostics;
/// neither is part of the public refusal contract. The remaining refusal fields
/// name actionable remedies and are declared by the frozen vocabulary.
fn screenshot_wire_reply(mut reply: Value) -> Value {
    let object = reply
        .as_object_mut()
        .expect("computer.screenshot replies are objects");
    object
        .entry("windows")
        .or_insert_with(|| Value::Array(Vec::new()));
    object.remove("value");
    object.remove("detail");
    reply
}

/// Give every click outcome the mandatory action-result envelope.
///
/// A refusal has no delivered containment or observed effect. A zero unreadable
/// count on a pre-read refusal means no tree read was attempted; callers receive
/// the measured count instead on paths that did read a tree.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn click_wire_envelope(mut reply: Value) -> Value {
    let object = reply
        .as_object_mut()
        .expect("computer.click replies are objects");
    object
        .entry("outcome")
        .or_insert_with(|| Value::String("refused".to_string()));
    object
        .entry("containment_rung")
        .or_insert_with(|| Value::String("global_none".to_string()));
    object
        .entry("effect_status")
        .or_insert_with(|| Value::String("effect_indeterminate".to_string()));
    object
        .entry("unreadable_subtrees")
        .or_insert_with(|| Value::from(0));
    // The typed reason is the public diagnosis. These values are implementation
    // diagnostics or repeat the invoked capability and do not identify a remedy.
    object.remove("ax_error");
    object.remove("capability");
    reply
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn click_refusal_after_read(mut refusal: Value, unreadable_subtrees: u64) -> Value {
    refusal
        .as_object_mut()
        .expect("computer.click refusals are objects")
        .insert(
            "unreadable_subtrees".to_string(),
            Value::from(unreadable_subtrees),
        );
    click_wire_envelope(refusal)
}

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
    cerebellum_core::journal::FilesystemJournalStorage,
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
pub fn production_audit() -> Result<
    ComputerAudit<
        cerebellum_computer::audit::redaction::ExcludeApplicationText,
        cerebellum_core::journal::ValidatedSeverityTaxonomy,
        cerebellum_core::journal::FilesystemJournalStorage,
    >,
    ComputerPlaneUnavailable,
> {
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_core::journal::{
        journal_data_path, BindingError, FilesystemJournalStorage, JournalConfig,
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
pub struct Servable(ComputerCapability);

impl Servable {
    pub fn capability(self) -> ComputerCapability {
        self.0
    }
}

/// The computer-plane capabilities this module can actually serve.
///
/// Returns the capability rather than a boolean so a caller cannot ask about one
/// name and act on another. A capability absent here is one the manifest must
/// not advertise: advertising what cannot be served tells a caller it has a
/// facility that does not exist, and it discovers otherwise only by using it.
///
/// Every frozen row is listed by name rather than covered by a wildcard, so
/// adding a capability to the vocabulary does not silently make it servable
/// here: the match stops compiling until the new row is admitted or refused by
/// name.
pub fn servable(name: &str) -> Option<Servable> {
    ComputerCapability::parse(name).map(
        |capability @ (ComputerCapability::Click
         | ComputerCapability::Type
         | ComputerCapability::Keys
         | ComputerCapability::Scroll
         | ComputerCapability::Move
         | ComputerCapability::Drag
         | ComputerCapability::Screenshot
         | ComputerCapability::Wait)| { Servable(capability) },
    )
}

/// Who is asking, and what this module needs to answer them.
///
/// Bundled rather than passed one by one because these travel together through
/// every capability: the identity that authorises the action is the same one
/// that appears in its journal entry, and separating them invites a handler
/// that authorises against one identity and records another.
pub struct ServeContext<'a, C: MonotonicClock> {
    /// The durable agent identity a lease is held by.
    ///
    /// Whatever the caller passes here decides which leases apply, so it must
    /// come from the route's accepted bind rather than from the request body: an
    /// identity a request can choose is a permission granted to whoever asks for
    /// it. This type cannot check that, which is why it is said here.
    pub grantee: &'a str,
    pub identity: JournalIdentity,
    pub management: &'a Arc<ManagementPlane>,
    pub clock: &'a C,
    pub now_ms: u64,
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
    audit: Mutex<ComputerAudit<R, T, S>>,
    capture: Mutex<Option<ScopedCaptureController<B>>>,
    result_schema_enforcement: ResultSchemaEnforcement,
    result_schema_findings: StdMutex<BTreeMap<CapabilityResultValidationError, u64>>,
    refusal_ring: Mutex<RefusalRing<ComputerRefusalReason>>,
    make_synthetic_driver: Arc<dyn Fn() -> D + Send + Sync>,
}

impl<B, R, T, S> ComputerPlane<B, R, T, S, UnsupportedPlatformDriver>
where
    B: CaptureBackend + Send,
    R: Redactor + Send,
    T: SeverityTaxonomy + Send,
    S: JournalStorage + Send,
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
    B: CaptureBackend + Send,
    R: Redactor + Send,
    T: SeverityTaxonomy + Send,
    S: JournalStorage + Send,
    D: PlatformDriver,
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
            audit: Mutex::new(audit),
            capture: Mutex::new(None),
            result_schema_enforcement,
            result_schema_findings: StdMutex::new(BTreeMap::new()),
            refusal_ring: Mutex::new(
                RefusalRing::new_in_memory(RefusalRingConfig {
                    records_per_caller: 16,
                })
                .expect("the fixed computer refusal-ring capacity is valid"),
            ),
            make_synthetic_driver,
        }
    }

    /// How many journal sequences have been allocated.
    ///
    /// Exposed so a test can establish that an action was recorded WITHOUT
    /// reading the entries themselves, which would put a test in the position of
    /// interpreting the journal's contents to decide whether it was written to.
    pub async fn journal_entry_count(&self) -> u64 {
        self.audit.lock().await.journal().next_sequence()
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
        self.audit
            .lock()
            .await
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
        context: ServeContext<'_, C>,
        make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Result<Value, CapabilityResultValidationError> {
        let served_capability = capability.capability();
        let reply = match served_capability {
            ComputerCapability::Wait => self.serve_wait(arguments, context).await,
            ComputerCapability::Screenshot => {
                self.serve_screenshot(arguments, context, make_backend)
                    .await
            }
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            ComputerCapability::Click => self.serve_click(arguments, context).await,
            ComputerCapability::Type
            | ComputerCapability::Keys
            | ComputerCapability::Scroll
            | ComputerCapability::Move
            | ComputerCapability::Drag => {
                self.serve_synthetic(served_capability, arguments, context)
                    .await
            }
            // Unreachable through `servable`, which is the only way a capability
            // arrives here. Answered rather than panicked: a dispatch table and
            // this match disagreeing is a bug to report, not a reason to take
            // the module down.
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            other => json!({
                "outcome": "not_servable",
                "capability": other.capability_id(),
                "remedy": "this capability is advertised but has no implementation; report it",
            }),
        };
        let reply = match served_capability {
            ComputerCapability::Screenshot => screenshot_wire_reply(reply),
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            ComputerCapability::Click => click_wire_envelope(reply),
            ComputerCapability::Type | ComputerCapability::Keys | ComputerCapability::Scroll => {
                synthetic_wire_envelope(reply, true)
            }
            ComputerCapability::Move | ComputerCapability::Drag => {
                synthetic_wire_envelope(reply, false)
            }
            ComputerCapability::Wait => reply,
            // The click reply above was already the not_servable answer on this
            // platform; it needs no envelope.
            #[cfg(not(any(target_os = "macos", target_os = "windows")))]
            ComputerCapability::Click => reply,
        };
        self.finish_reply(served_capability, reply)
    }

    /// Poll one accessibility predicate until it settles or its deadline passes.
    async fn serve_wait<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        let parsed = match parse_wait_request(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return wait_indeterminate_reply(None, refusal),
        };
        let ServeContext {
            grantee,
            identity: _,
            management,
            clock,
            now_ms: _,
        } = context;
        let grant = match management
            .authority_for(grantee, ActionKind::Observe, clock)
            .await
        {
            ActionAuthority::Admitted(grant) => grant,
            ActionAuthority::Refused(refusal) => {
                return wait_indeterminate_reply(Some(parsed.predicate), refusal)
            }
        };

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let predicate = parsed.predicate;
            let timeout_ms = parsed.timeout_ms;
            match tokio::task::spawn_blocking(move || {
                let mut poller =
                    PlatformPredicatePoller::new(NativeComputerPlatformDriver::default(), grant);
                wait_until_predicate(&mut poller, predicate, timeout_ms)
            })
            .await
            {
                Ok(result) => wait_wire_reply(result),
                Err(_) => {
                    wait_indeterminate_reply(None, json!({"reason": "polling_task_unavailable"}))
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = grant;
            wait_indeterminate_reply(
                Some(parsed.predicate),
                json!({"reason": "scoped_accessibility_read_unsupported"}),
            )
        }
    }

    /// Invoke the requested semantic action on one uniquely named element.
    #[cfg(any(target_os = "macos", target_os = "windows"))]
    async fn serve_click<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        let parsed = match parse_click_request(arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };

        let ServeContext {
            grantee,
            identity,
            management,
            clock,
            now_ms: _,
        } = context;
        let grant = match management
            .authority_for(grantee, ActionKind::Compose, clock)
            .await
        {
            ActionAuthority::Admitted(grant) => grant,
            ActionAuthority::Refused(refusal) => return refusal,
        };

        // Observation runs only when the caller named a post-condition. An
        // inferred one can be true before the press, so it would report an
        // effect for a click that did nothing.
        let mut driver = if parsed.expect.is_some() {
            NativeComputerPlatformDriver::default()
        } else {
            NativeComputerPlatformDriver::default().without_expected_post_condition()
        };
        let tree = match driver.read_accessibility_tree(AccessibilityTreeRequest {
            target: grant.clone(),
            settle_interval_ms: 500,
        }) {
            Ok(tree) => tree,
            Err(error) => {
                // The root itself was unreadable, so the omitted tree is one
                // unreadable subtree rather than a fabricated complete read.
                return click_driver_refusal(error, parsed.element_name.key_form(), 1);
            }
        };
        let unreadable_subtrees = tree.unreadable_subtrees;
        let Some(root_identifier) = tree.root_identifier else {
            return dispatch_refusal(DispatchError::SemanticPathUnavailable, unreadable_subtrees);
        };
        let element = match driver.resolve_element(ElementResolutionRequest {
            root_identifier,
            element_name: parsed.element_name.clone(),
        }) {
            Ok(element) => element,
            Err(error) => {
                return click_driver_refusal(
                    error,
                    parsed.element_name.key_form(),
                    unreadable_subtrees,
                )
            }
        };

        let row = FrozenDispatchRow::for_capability("computer.click")
            .expect("the frozen vocabulary contains computer.click");
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
                return dispatch_refusal(DispatchError::AttendanceUnavailable, unreadable_subtrees)
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

        let expected = match expected_post_condition_from_wire(&parsed) {
            Ok(expected) => expected,
            Err(refusal) => return click_refusal_after_read(refusal, unreadable_subtrees),
        };
        let mut request = DispatchRequest::new(
            row,
            DispatchMode::Background,
            grant,
            expected,
            attendance,
            dispatch_at_ms,
        );
        request.semantic = Some(click_semantic_request(&parsed, element));

        let mut audit = self.audit.lock().await;
        match Dispatcher::new(driver).dispatch(&mut audit, identity, request) {
            Ok(report) => {
                let Some(containment_rung) = report.containment.rung() else {
                    return dispatch_refusal(DispatchError::AuditUnavailable, unreadable_subtrees);
                };
                click_wire_reply(
                    DispatchContainmentRung::as_str(containment_rung),
                    report.platform_result.unreadable_subtrees,
                    parsed.expect.as_ref().map(|_| report.effect.status),
                )
            }
            Err(refusal) => dispatch_refusal(refusal, unreadable_subtrees),
        }
    }

    /// Photograph the windows of the application this conversation may observe.
    ///
    /// The request names no target by design — it carries a scope and nothing
    /// else — so which application it means comes from the lease, and a caller
    /// cannot point the plane at a process by naming it.
    async fn serve_screenshot<C: MonotonicClock>(
        &self,
        arguments: &Value,
        context: ServeContext<'_, C>,
        make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Value {
        let ServeContext {
            grantee,
            identity,
            management,
            clock,
            now_ms,
        } = context;

        let scope = match arguments.get("scope").and_then(Value::as_str) {
            Some("target_windows") => CaptureScope::PerWindow,
            // Refused here rather than attempted and refused deeper, so the
            // reason names the grant a caller would need rather than a backend
            // that declined.
            Some("display") => {
                return json!({
                    "outcome": "broad_grant_required",
                    "remedy": "whole-display capture needs a broad display grant, which this \
                               conversation does not hold",
                })
            }
            Some(other) => {
                return json!({
                    "outcome": "invalid_request",
                    "field": "scope",
                    "reason": "unknown_value",
                    "value": other,
                })
            }
            None => {
                return json!({
                    "outcome": "invalid_request",
                    "field": "scope",
                    "reason": "missing_field",
                })
            }
        };

        // The request schema pins this to false, so a caller asking for the
        // cursor is asking for something this action does not offer.
        // Answered as an invalid request rather than ignored: silently dropping
        // a parameter returns a picture the caller did not ask for.
        match arguments.get("include_cursor") {
            Some(Value::Bool(false)) => {}
            Some(_) => {
                return json!({
                    "outcome": "invalid_request",
                    "field": "include_cursor",
                    "reason": "unknown_value",
                })
            }
            None => {
                return json!({
                    "outcome": "invalid_request",
                    "field": "include_cursor",
                    "reason": "missing_field",
                })
            }
        }

        let region = match parse_screenshot_region(arguments) {
            Ok(region) => region,
            Err(refusal) => return refusal,
        };

        // Authority first, before anything is reserved or captured. A refusal
        // here has produced no pixels and no journal entry, so nothing has to be
        // undone.
        let grant = match management
            .authority_for(grantee, ActionKind::Observe, clock)
            .await
        {
            ActionAuthority::Admitted(grant) => grant,
            ActionAuthority::Refused(refusal) => return refusal,
        };

        let descriptor = ComputerPlaneDescriptor::new(
            ComputerCapability::Screenshot,
            // Reading pixels reaches no element and moves nothing, so it claims
            // no element-level containment.
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        );

        let mut audit = self.audit.lock().await;
        let handle = match audit.reserve(identity, descriptor) {
            Ok(handle) => handle,
            Err(error) => {
                return json!({
                    "outcome": "audit_unavailable",
                    "detail": format!("{error:?}"),
                    "remedy": "the action was not performed; retry once the journal is available",
                })
            }
        };

        let admission = match audit.prepare_capture(handle, scope, None, now_ms) {
            Ok(admission) => admission,
            Err(refusal) => {
                let _ = audit.finalize_rejected(handle, b"capture-not-admitted".to_vec());
                return json!({
                    "outcome": "capture_not_admitted",
                    "detail": format!("{:?}", refusal.cause),
                });
            }
        };

        // Captured only after the journal has reserved space for the record.
        // The other order can produce pixels the journal then refuses to
        // account for, which is an observation with no entry.
        let captured = {
            let mut capture = self.capture.lock().await;
            let controller = match capture.take() {
                Some(controller) if controller.target() == &grant => controller,
                // A controller bound to a different grant is discarded rather
                // than reused: it holds the enumeration of another process.
                _ => match ScopedCaptureController::with_v1_bounds(
                    make_backend(&grant),
                    grant.clone(),
                ) {
                    Ok(controller) => controller,
                    Err(error) => {
                        let _ = audit.finalize_rejected(handle, b"capture-unavailable".to_vec());
                        return json!({
                            "outcome": "capture_unavailable",
                            "detail": format!("{error:?}"),
                        });
                    }
                },
            };
            let mut controller = controller;
            if let Some(region) = region {
                let enumerated = match controller.enumerated_windows(now_ms) {
                    Ok(windows) => windows,
                    Err(error) => {
                        *capture = Some(controller);
                        let _ = audit.finalize_rejected(handle, b"capture-failed".to_vec());
                        return json!({
                            "outcome": "capture_failed",
                            "detail": format!("{error:?}"),
                        });
                    }
                };
                if enumerated.iter().any(|window| {
                    !region_fits_window(&region, window.frame.width, window.frame.height)
                }) {
                    *capture = Some(controller);
                    let _ = audit.finalize_rejected(handle, b"region-outside-window".to_vec());
                    return invalid_screenshot_request("region", "region_outside_window");
                }
            }
            let result = controller.capture_scoped_with_region(now_ms, region.map(capture_region));
            *capture = Some(controller);
            result
        };

        let captured = match captured {
            Ok(captured) => captured,
            Err(error) => {
                let _ = audit.finalize_rejected(handle, b"capture-failed".to_vec());
                return json!({
                    "outcome": "capture_failed",
                    "detail": format!("{error:?}"),
                });
            }
        };

        let mut windows = Vec::new();
        let mut prepared = Vec::new();
        let mut total_bytes = 0usize;
        for window in &captured.windows {
            let CaptureArtifact::Bytes(bytes) = &window.artifact else {
                continue;
            };
            if let Some(region) = region {
                if window.frame.width != region.width_px || window.frame.height != region.height_px
                {
                    let _ = audit.finalize_rejected(handle, b"region-not-honoured".to_vec());
                    return invalid_screenshot_request("region", "region_not_honoured");
                }
            }
            let width_px = window.frame.width;
            let height_px = window.frame.height;
            let bytes = bytes.clone();
            total_bytes += bytes.len();
            if total_bytes > MAX_ENCODED_IMAGE_BYTES {
                let _ = audit.finalize_rejected(handle, b"image-too-large".to_vec());
                return json!({
                    "outcome": "image_too_large",
                    "bytes": total_bytes,
                    "bound_bytes": MAX_ENCODED_IMAGE_BYTES,
                    "remedy": "capture fewer windows, or one at a time",
                });
            }
            windows.push(json!({
                "window_id": window.window_id,
                "width_px": width_px,
                "height_px": height_px,
                "image_png_b64": base64(&bytes),
            }));
            prepared.push((window.window_id.clone(), width_px, height_px, bytes));
        }

        // Admitted to custody before the result is built, so the pixels handed
        // back are the ones the journal accounts for.
        //
        // A capture that produced no window with pixels has nothing to account
        // for, and an artifact describing no image is refused by custody rather
        // than stored as an empty one. Reported as its own outcome, because a
        // target with no capturable window is a fact about the target rather
        // than a failure to retain what was captured.
        let Some((first_id, first_width, first_height, first_bytes)) = prepared.into_iter().next()
        else {
            let _ = audit.finalize_rejected(handle, b"no-window-captured".to_vec());
            return json!({
                "outcome": "no_window_captured",
                "remedy": "the target has no capturable window: open one, or capture a \
                           different application",
            });
        };

        // The artifact carries the encoded bytes and the dimensions they
        // describe. Custody charges the retention budget by size and refuses a
        // descriptor whose dimensions are zero, so passing a placeholder here
        // would both defeat that refusal and account for nothing.
        let artifact = PixelArtifact::per_window(
            first_bytes,
            now_ms,
            first_id,
            grant.pid,
            first_width,
            first_height,
        );
        let artifact_id = match audit.admit_capture(admission, artifact, now_ms) {
            Ok(artifact_id) => artifact_id,
            Err(refusal) => {
                let _ = audit.finalize_rejected(handle, b"capture-not-retained".to_vec());
                return json!({
                    "outcome": "capture_not_retained",
                    "detail": format!("{:?}", refusal.cause),
                });
            }
        };

        // Custody must hold what is about to be returned. Checked rather than
        // assumed because admission is the step that makes the pixels
        // accountable, and a reply carrying an image custody never took is
        // indistinguishable from a correct one at the wire.
        match audit.custody().artifact_readable(&artifact_id) {
            Ok(true) => {}
            Ok(false) => {
                let _ = audit.finalize_rejected(handle, b"capture-not-retained".to_vec());
                return json!({
                    "outcome": "capture_not_retained",
                    "detail": "the capture was not retained by custody",
                });
            }
            // A poisoned custody lock is a module fault, not a lost capture:
            // taking the picture again cannot help, and saying so keeps the
            // caller from retrying into the same wall.
            Err(cerebellum_computer::capture_custody::CustodyUnavailable) => {
                let _ = audit.finalize_rejected(handle, b"custody-unavailable".to_vec());
                return json!({
                    "outcome": "custody_unavailable",
                    "detail": "capture custody is unavailable in this module process; report the fault and do not retry the capture",
                });
            }
        }

        let dispatch = TypedCaptureDispatch::new(
            ComputerCapability::Screenshot,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        )
        .dispatch_material(b"computer.screenshot".to_vec());
        let token = match audit.commit_dispatched(handle, &dispatch, b"lease".to_vec(), None) {
            Ok(token) => token,
            Err(error) => {
                return json!({
                    "outcome": "audit_unavailable",
                    "detail": format!("{error:?}"),
                })
            }
        };

        // Finalized BEFORE the result is returned: an observation the caller
        // received while the journal entry stayed open is one nobody can account
        // for afterwards.
        if let Err(error) = audit.finalize_dispatched(
            token,
            b"captured".to_vec(),
            grant.bundle_identity.clone().into_bytes(),
        ) {
            return json!({
                "outcome": "audit_unavailable",
                "detail": format!("{error:?}"),
            });
        }

        json!({
            "outcome": "captured",
            "windows": windows,
        })
    }

    /// Post one synthetic input action into the application this conversation
    /// may act on.
    ///
    /// Shared by the five input capabilities, which differ in three ways and
    /// nowhere else: the request they parse, the action kind their lease must
    /// cover, and whether they deliver to the leased process (background) or
    /// to the pointer's location while a human watches (observed, which only
    /// `computer.move` is frozen as).
    ///
    /// The ordering is the click handler's and is not stylistic: authority is
    /// established before anything is journaled, the dispatcher reserves and
    /// commits the intent before the platform can receive an event, and the
    /// terminal state is finalised before this returns -- so a failing
    /// dispatch still leaves a completed audit record, never an open one.
    async fn serve_synthetic<C: MonotonicClock>(
        &self,
        capability: ComputerCapability,
        arguments: &Value,
        context: ServeContext<'_, C>,
    ) -> Value {
        let mut parsed = match parse_synthetic_request(capability, arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
        };

        let ServeContext {
            grantee,
            identity,
            management,
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
                return chord_blocked_refusal(&chord, blocked.reason);
            }
            // The session floor is checked before a Command chord escalates to
            // mutate_durable, so no lease can make a session-ending action valid.
            parsed.action_kind = chord_action_kind(*modifiers);
        }
        // Pointer events have no working per-process path, so scroll, move and
        // drag use the observed global path. Type and keys remain bound to the
        // leased process generation.
        let mode = match capability {
            ComputerCapability::Scroll | ComputerCapability::Move | ComputerCapability::Drag => {
                DispatchMode::Observed
            }
            _ => DispatchMode::Background,
        };
        // Global authority is deliberately stronger than the row's ordinary
        // action kind. It consumes a Once MutateDurable lease for the selected
        // target; a standing Until lease cannot manufacture the token carried
        // into the platform request.
        let (grant, once_dispatch_token) = match mode {
            DispatchMode::Background => match management
                .authority_for(grantee, parsed.action_kind, clock)
                .await
            {
                ActionAuthority::Admitted(grant) => (grant, None),
                ActionAuthority::Refused(refusal) => return refusal,
            },
            DispatchMode::Observed => {
                let grant = match management
                    .authority_for(grantee, ActionKind::MutateDurable, clock)
                    .await
                {
                    ActionAuthority::Admitted(grant) => grant,
                    ActionAuthority::Refused(_) => return once_dispatch_refusal(),
                };
                let key = LeaseKey {
                    grantee: grantee.to_string(),
                    bundle_identity: grant.bundle_identity.clone(),
                    action_kind: ActionKind::MutateDurable,
                };
                let Some(token) = management.admit_once_dispatch(&key, clock).await else {
                    return once_dispatch_refusal();
                };
                (grant, Some(token))
            }
        };

        let capability_id = capability.capability_id();
        let mut row = FrozenDispatchRow::for_capability(capability_id)
            .expect("the frozen vocabulary contains every servable capability");
        if parsed.action_kind == ActionKind::MutateDurable {
            // The vocabulary's durable escalation is a property of the request,
            // not of the row: the dispatch runs under the escalated kind so
            // containment and audit evidence record what this action could do
            // rather than what an ordinary compose action could.
            row.action_kind = cerebellum_computer::platform::ActionKind::MutateDurable;
        }
        let dispatch_at_ms = clock.now().as_nanos() / 1_000_000;
        let attendance = match mode {
            DispatchMode::Background => {
                let expires_at_ms =
                    dispatch_at_ms.saturating_add(row.maximum_attendance_lease_age_ms);
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
                        return synthetic_dispatch_refusal(&DispatchError::AttendanceUnavailable)
                    }
                };
                AttendanceContext::background(
                    identity.conversation_key.clone(),
                    grant.clone(),
                    grantee,
                    lease,
                    dispatch_at_ms,
                    dispatch_at_ms,
                    row.maximum_attendance_lease_age_ms,
                    row.maximum_attendance_check_to_dispatch_interval_ms,
                    true,
                )
            }
            DispatchMode::Observed => AttendanceContext::observed(
                identity.conversation_key.clone(),
                grant.clone(),
                grantee,
                dispatch_at_ms,
                dispatch_at_ms,
                true,
            ),
        };

        // None of the five request schemas declares a post-condition, so there
        // is no effect claim to evaluate. The placeholder exists because the
        // dispatcher serializes a predicate before dispatch; the production
        // driver is built with post-condition evaluation disabled, which
        // records the effect as indeterminate rather than claiming one a post
        // call cannot evidence.
        let expected = ExpectedPostCondition::new(
            "computer-synthetic-wire-no-effect-claim-v1",
            PostCondition::ElementPresent {
                element: parsed.placeholder_element,
            },
        );
        let mut request =
            DispatchRequest::new(row, mode, grant, expected, attendance, dispatch_at_ms)
                .with_synthetic(parsed.action);
        if let Some(token) = once_dispatch_token {
            request = request.with_once_dispatch_token(token);
        }

        let mut audit = self.audit.lock().await;
        match Dispatcher::new((self.make_synthetic_driver)())
            .dispatch(&mut audit, identity, request)
        {
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
                // received it was pinned down. An action can be fully contained
                // and land in a window nobody was looking at, and a caller that
                // cannot see both halves cannot tell that from an uncontained
                // one.
                //
                // The reason key is omitted rather than sent as null when no
                // condition denied the rung: absence is unambiguous here because
                // target_fronted is always present, so a caller can tell a build
                // that reports these from one that does not.
                let mut reply = json!({
                    "outcome": "completed",
                    "containment_rung": DispatchContainmentRung::as_str(containment_rung),
                    "target_fronted": report.containment.fronting_stable,
                    "effect_status": effect_status_name(report.effect.status),
                });
                if let Some(reason) = report.containment.forfeiture_reason {
                    reply["containment_forfeited_because"] = json!(reason.as_str());
                }
                reply
            }
            Err(refusal) => synthetic_dispatch_refusal(&refusal),
        }
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
}

const MAX_WAIT_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedWait {
    predicate: PostCondition,
    timeout_ms: u64,
}

fn parse_wait_request(arguments: &Value) -> Result<ParsedWait, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid_wait_request("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !matches!(field.as_str(), "predicate" | "timeout_ms"))
        .min()
    {
        return Err(invalid_wait_request(field, "unknown_field"));
    }
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
        predicate,
        timeout_ms,
    })
}

fn invalid_wait_request(field: &str, reason: &str) -> Value {
    json!({
        "reason": "invalid_request",
        "field": field,
        "detail": reason,
    })
}

#[cfg(any(target_os = "macos", target_os = "windows", test))]
fn wait_wire_reply(result: WaitResult) -> Value {
    let outcome = match result.outcome {
        WaitOutcome::Settled => "predicate_satisfied",
        WaitOutcome::TimedOut => "timeout",
        WaitOutcome::Indeterminate => "indeterminate",
    };
    json!({
        "outcome": outcome,
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

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug)]
struct ParsedClick {
    element_name: AccessibilityElementName,
    action: &'static str,
    expect: Option<ParsedExpect>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn click_semantic_request(
    parsed: &ParsedClick,
    element: ElementResolutionResult,
) -> SemanticDispatchRequest {
    SemanticDispatchRequest {
        element,
        action: parsed.action.to_owned(),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug)]
struct ParsedExpect {
    condition: String,
    attribute: Option<String>,
    value: Option<String>,
}

/// Read the tagged target object into the exact key form the resolver uses.
///
/// The two forms are not interchangeable: a control that is unique by role and
/// title may have no identifier, and rewriting the request as an identifier
/// would look up a different name and miss it.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn click_target_from_wire(target: &Value) -> Result<AccessibilityElementName, Value> {
    let Some(object) = target.as_object() else {
        return Err(invalid_click_request("target", field_reason(Some(target))));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !matches!(field.as_str(), "by" | "identifier" | "role" | "title"))
        .min()
    {
        return Err(invalid_click_request(field, "unknown_field"));
    }
    match object.get("by").and_then(Value::as_str) {
        Some("identifier") => {
            let Some(identifier) = object.get("identifier").and_then(Value::as_str) else {
                return Err(invalid_click_request(
                    "identifier",
                    field_reason(object.get("identifier")),
                ));
            };
            if identifier.is_empty() {
                return Err(invalid_click_request("identifier", "empty_value"));
            }
            if object.contains_key("role") || object.contains_key("title") {
                return Err(invalid_click_request(
                    "target",
                    "inconsistent_target_fields",
                ));
            }
            Ok(AccessibilityElementName::Identifier(identifier.to_string()))
        }
        Some("role_and_title") => {
            let Some(role) = object.get("role").and_then(Value::as_str) else {
                return Err(invalid_click_request(
                    "role",
                    field_reason(object.get("role")),
                ));
            };
            if role.is_empty() {
                return Err(invalid_click_request("role", "empty_value"));
            }
            if object.contains_key("identifier") {
                return Err(invalid_click_request(
                    "target",
                    "inconsistent_target_fields",
                ));
            }
            let title = match object.get("title") {
                None => String::new(),
                Some(Value::String(title)) => title.clone(),
                Some(_) => return Err(invalid_click_request("title", "wrong_type")),
            };
            Ok(AccessibilityElementName::role_and_title(role, title))
        }
        Some(_) => Err(invalid_click_request("by", "unknown_value")),
        None => Err(invalid_click_request("by", field_reason(object.get("by")))),
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn parse_click_request(arguments: &Value) -> Result<ParsedClick, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid_click_request("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| {
            !matches!(
                field.as_str(),
                "target" | "button" | "click_count" | "modifiers" | "action" | "expect"
            )
        })
        .min()
    {
        return Err(invalid_click_request(field, "unknown_field"));
    }
    let Some(target) = object.get("target") else {
        return Err(invalid_click_request("target", "missing_field"));
    };
    let element_name = click_target_from_wire(target)?;
    match object.get("button").and_then(Value::as_str) {
        Some("left") => {}
        Some(_) => {
            return Err(invalid_click_request(
                "button",
                "semantic_path_requires_left",
            ))
        }
        None => {
            return Err(invalid_click_request(
                "button",
                field_reason(object.get("button")),
            ))
        }
    }
    match object.get("click_count").and_then(Value::as_u64) {
        Some(1) => {}
        Some(_) => {
            return Err(invalid_click_request(
                "click_count",
                "semantic_path_requires_one",
            ))
        }
        None => {
            return Err(invalid_click_request(
                "click_count",
                field_reason(object.get("click_count")),
            ))
        }
    }
    let Some(modifiers) = object.get("modifiers").and_then(Value::as_array) else {
        return Err(invalid_click_request(
            "modifiers",
            field_reason(object.get("modifiers")),
        ));
    };
    if modifiers.iter().any(|modifier| !modifier.is_string()) {
        return Err(invalid_click_request("modifiers", "invalid_value"));
    }
    if !modifiers.is_empty() {
        return Err(invalid_click_request(
            "modifiers",
            "semantic_path_requires_empty",
        ));
    }
    // Omission preserves the original wire contract: before this field existed,
    // every computer.click requested the press intent.
    let action = match object.get("action") {
        None => SEMANTIC_PRESS_ACTION,
        Some(Value::String(action)) if action == SEMANTIC_PRESS_ACTION => SEMANTIC_PRESS_ACTION,
        Some(Value::String(action)) if action == SEMANTIC_CANCEL_ACTION => SEMANTIC_CANCEL_ACTION,
        Some(Value::String(_)) => return Err(invalid_click_request("action", "unknown_value")),
        Some(action) => return Err(invalid_click_request("action", field_reason(Some(action)))),
    };
    let expect = match object.get("expect") {
        None => None,
        Some(expect) => Some(parse_click_expect(expect)?),
    };
    Ok(ParsedClick {
        element_name,
        action,
        expect,
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn parse_click_expect(expect: &Value) -> Result<ParsedExpect, Value> {
    let Some(object) = expect.as_object() else {
        return Err(invalid_click_request("expect", field_reason(Some(expect))));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| !matches!(field.as_str(), "condition" | "attribute" | "value"))
        .min()
    {
        return Err(invalid_click_request(field, "unknown_field"));
    }
    let Some(condition) = object.get("condition").and_then(Value::as_str) else {
        return Err(invalid_click_request(
            "condition",
            field_reason(object.get("condition")),
        ));
    };
    if !matches!(
        condition,
        "element_attribute_equals"
            | "element_present"
            | "element_absent"
            | "focused_element_equals"
    ) {
        return Err(invalid_click_request("condition", "unknown_value"));
    }
    let attribute = match object.get("attribute") {
        None => None,
        Some(Value::String(attribute)) if !attribute.is_empty() => Some(attribute.clone()),
        Some(Value::String(_)) => return Err(invalid_click_request("attribute", "empty_value")),
        Some(_) => return Err(invalid_click_request("attribute", "wrong_type")),
    };
    let value = match object.get("value") {
        None => None,
        Some(Value::String(value)) => Some(value.clone()),
        Some(_) => return Err(invalid_click_request("value", "wrong_type")),
    };
    if condition == "element_attribute_equals" {
        if attribute.is_none() {
            return Err(invalid_click_request("attribute", "missing_field"));
        }
        if value.is_none() {
            return Err(invalid_click_request("value", "missing_field"));
        }
    }
    Ok(ParsedExpect {
        condition: condition.to_string(),
        attribute,
        value,
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn expected_post_condition_from_wire(parsed: &ParsedClick) -> Result<ExpectedPostCondition, Value> {
    let Some(expect) = parsed.expect.as_ref() else {
        // Placeholder only: the driver is marked as having no caller-supplied
        // condition and will not evaluate this or report it as a claim.
        return Ok(ExpectedPostCondition::new(
            "computer-click-wire-no-effect-claim-v1",
            PostCondition::ElementPresent {
                element: parsed.element_name.clone(),
            },
        ));
    };
    let element = parsed.element_name.clone();
    let condition = match expect.condition.as_str() {
        "element_present" => PostCondition::ElementPresent { element },
        "element_absent" => PostCondition::ElementAbsent { element },
        "focused_element_equals" => PostCondition::ElementFocused { element },
        "element_attribute_equals" => {
            let attribute = expect.attribute.as_deref().unwrap_or("");
            let value = expect.value.clone().unwrap_or_default();
            match attribute {
                "AXValue" | "value" | "AXValueDescription" => PostCondition::ElementValueEquals {
                    element,
                    expected: value,
                },
                "AXEnabled" | "enabled" => {
                    let expected = match value.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid_click_request("value", "invalid_value")),
                    };
                    PostCondition::ElementEnabledIs { element, expected }
                }
                "AXFocused" | "focused" if value == "true" => {
                    PostCondition::ElementFocused { element }
                }
                _ => return Err(invalid_click_request("attribute", "undeclarable_attribute")),
            }
        }
        _ => return Err(invalid_click_request("condition", "unknown_value")),
    };
    Ok(ExpectedPostCondition::new(
        "computer-click-wire-expect-v1",
        condition,
    ))
}

/// Build the click reply. A missing effect is a different fact from an
/// observed one: the caller who did not ask for a post-condition must not
/// receive a claim, even the coarser indeterminate one dressed as theirs.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn click_wire_reply(
    containment_rung: &str,
    unreadable_subtrees: u64,
    requested_effect: Option<EffectStatus>,
) -> Value {
    match requested_effect {
        Some(status) => json!({
            "outcome": "completed",
            "containment_rung": containment_rung,
            "effect_status": effect_status_name(status),
            "unreadable_subtrees": unreadable_subtrees,
        }),
        None => json!({
            "outcome": "handler_returned_no_effect_claim",
            "containment_rung": containment_rung,
            // The frozen result vocabulary has no distinct status for an
            // absent effect claim, so this is the honest coarser value.
            "effect_status": "effect_indeterminate",
            // How much of the application's accessibility tree did not
            // answer when this element was resolved. Uniqueness is
            // established against the tree that was READ -- an element
            // that does not answer cannot be named, resolved or
            // re-found, so it was never addressable -- and this count is
            // what tells the caller the universe was partial. Without it
            // the caller cannot distinguish a claim made over a complete
            // reading from one made over a fragment, which is the
            // difference between scoping the claim and quietly weakening
            // it. Zero means the tree was complete; the field is always
            // present, because an absent count would read as zero.
            "unreadable_subtrees": unreadable_subtrees,
        }),
    }
}

fn effect_status_name(status: EffectStatus) -> &'static str {
    match status {
        EffectStatus::EffectObserved => "effect_observed",
        EffectStatus::NoEffectObserved => "no_effect_observed",
        EffectStatus::EffectIndeterminate => "effect_indeterminate",
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn field_reason(value: Option<&Value>) -> &'static str {
    if value.is_some() {
        "wrong_type"
    } else {
        "missing_field"
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn invalid_click_request(field: &str, reason: &str) -> Value {
    click_wire_envelope(json!({
        "outcome": "invalid_request",
        "field": field,
        "reason": reason,
    }))
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn dispatch_refusal(refusal: DispatchError, unreadable_subtrees: u64) -> Value {
    let refusal =
        serde_json::to_value(refusal).expect("the closed dispatch refusal taxonomy serializes");
    click_refusal_after_read(refusal, unreadable_subtrees)
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn click_driver_refusal(
    error: DriverError,
    key_form: AccessibilityKeyForm,
    unreadable_subtrees: u64,
) -> Value {
    let refusal = match error {
        DriverError::Semantic(failure) => match failure {
            SemanticDriverError::ActionUnsupported { intent, platform } => {
                DispatchError::SemanticActionUnsupported { intent, platform }
            }
            SemanticDriverError::ElementNameAmbiguous {
                key_form,
                match_count,
            } => DispatchError::ElementNameAmbiguous {
                key_form,
                match_count,
            },
            SemanticDriverError::ElementNotFound { key_form } => {
                DispatchError::ElementNotFound { key_form }
            }
            SemanticDriverError::ActionNotAdvertised { action, advertised } => {
                DispatchError::ActionNotAdvertised { action, advertised }
            }
            SemanticDriverError::ApplicationRefused { ax_error } => {
                DispatchError::ApplicationRefused { ax_error }
            }
            SemanticDriverError::AccessibilityPermissionUnavailable => {
                DispatchError::AccessibilityPermissionUnavailable
            }
            SemanticDriverError::TargetNoLongerCurrent { disposition } => {
                DispatchError::TargetNoLongerCurrent { disposition }
            }
            SemanticDriverError::Transient { deadline_ms } => {
                DispatchError::SemanticDispatchTransient { deadline_ms }
            }
            SemanticDriverError::PathUnavailable => DispatchError::SemanticPathUnavailable,
        },
        DriverError::AccessibilityUnreadable(failure) => match failure {
            AccessibilityReadFailure::PermissionRequired => {
                DispatchError::AccessibilityPermissionUnavailable
            }
            AccessibilityReadFailure::TargetGone => DispatchError::TargetNoLongerCurrent {
                disposition: TargetDisposition::Gone,
            },
            AccessibilityReadFailure::TargetReplaced => DispatchError::TargetNoLongerCurrent {
                disposition: TargetDisposition::Replaced,
            },
            AccessibilityReadFailure::RetryableDeadlineExceeded => {
                DispatchError::SemanticDispatchTransient { deadline_ms: 3_000 }
            }
            AccessibilityReadFailure::TargetNotInspectable
            | AccessibilityReadFailure::TreeExceedsBound
            | AccessibilityReadFailure::IncompatiblePlatformValue
            | AccessibilityReadFailure::PlatformReadFailed => {
                DispatchError::SemanticPathUnavailable
            }
        },
        DriverError::ElementNotFound => DispatchError::ElementNotFound { key_form },
        DriverError::SessionNotInspectable(session) => {
            DispatchError::SessionNotInspectable { session }
        }
        DriverError::WindowVisibilityUnknown { pid } => {
            DispatchError::WindowVisibilityUnknown { pid }
        }
        DriverError::Unsupported(_)
        | DriverError::InvalidRequest(_)
        | DriverError::StartupRefused(_)
        | DriverError::EventConstructionFailed(_)
        | DriverError::SyntheticDispatchFailed(_)
        | DriverError::ObservedDispatchAborted(_) => DispatchError::SemanticPathUnavailable,
    };
    dispatch_refusal(refusal, unreadable_subtrees)
}

/// What one parsed synthetic-input request carries into the dispatch seam.
#[derive(Debug)]
struct ParsedSynthetic {
    action: SyntheticAction,
    /// The wire spelling of a parsed key chord, retained for a floor refusal.
    chord: Option<String>,
    /// The consent action kind the lease must cover. Usually the row's own
    /// kind; a durable chord or a drag takes the escalated kind the frozen
    /// vocabulary assigns to it.
    action_kind: ActionKind,
    /// The element the placeholder post-condition names. It is never
    /// evaluated -- the five schemas declare no post-condition -- so it labels
    /// the serialized predicate rather than naming a resolved target.
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

fn once_dispatch_refusal() -> Value {
    json!({
        "outcome": "once_grant_required",
        "remedy": "call computer.open_target for action_kind 'mutate_durable', choose the 'once' grant kind, then retry",
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

/// The fields each input capability's frozen request schema declares, so an
/// undeclared field is refused as unknown rather than silently dropped.
fn synthetic_request_fields(capability: ComputerCapability) -> Option<&'static [&'static str]> {
    match capability {
        ComputerCapability::Type => Some(&["target", "text", "replace_selection"]),
        ComputerCapability::Keys => Some(&["keys", "target"]),
        ComputerCapability::Scroll => Some(&["target", "axis", "amount_lines"]),
        ComputerCapability::Move => Some(&["to"]),
        ComputerCapability::Drag => Some(&["from", "to", "button", "modifiers"]),
        _ => None,
    }
}

fn parse_synthetic_request(
    capability: ComputerCapability,
    arguments: &Value,
) -> Result<ParsedSynthetic, Value> {
    // serve() routes only the five input capabilities here. Anything else is
    // a dispatch-table disagreement, which is answered rather than panicked
    // on, for the same reason the top-level match answers it.
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
        ComputerCapability::Type => parse_type_request(object),
        ComputerCapability::Keys => parse_keys_request(object),
        ComputerCapability::Scroll => parse_scroll_request(object),
        ComputerCapability::Move => parse_move_request(object),
        ComputerCapability::Drag => parse_drag_request(object),
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
    match object.get("replace_selection") {
        Some(Value::Bool(_)) => {}
        other => {
            return Err(invalid_synthetic_request(
                "replace_selection",
                synthetic_field_reason(other),
            ))
        }
    }
    // `replace_selection` is validated but not acted on: Unicode typing
    // follows the target's own insertion-point convention, which replaces an
    // active selection as ordinary typing does. The synthetic path has that
    // one behavior, and the field states the caller's expectation of it.
    Ok(ParsedSynthetic {
        action: SyntheticAction::type_text(text),
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
        chord: Some(chord_names.join("+")),
        // The session floor must run before durable-chord escalation; serve
        // classifies this only after the floor declines the exact chord.
        action_kind: ActionKind::Compose,
        placeholder_element: AccessibilityElementName::Identifier(target),
    })
}

/// The action kind a key combination runs under: the vocabulary's
/// `durable_chord` override applied to the chord just parsed.
///
/// A Command chord asks the target application to run one of the
/// application's OWN commands, and what those do is not enumerable from here:
/// Command-S saves, Command-Q quits, Command-W closes -- state that outlives
/// the session -- while Command-C copies. Because the plane cannot show any Command chord to be
/// session-scoped, every Command chord takes the durable side and requires a
/// `mutate_durable` lease. A chord without Command is an editing or
/// navigation keystroke, which is what `compose` covers.
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

fn chord_action_kind(modifiers: SyntheticKeyModifiers) -> ActionKind {
    if modifiers.command {
        ActionKind::MutateDurable
    } else {
        ActionKind::Compose
    }
}

fn parse_scroll_request(object: &serde_json::Map<String, Value>) -> Result<ParsedSynthetic, Value> {
    let target = required_text(object, "target")?;
    match object.get("axis") {
        Some(Value::String(axis)) if axis == "vertical" => {}
        Some(Value::String(axis)) if axis == "horizontal" => {
            // The frozen schema names both axes, but the event construction
            // this path serves builds a vertical wheel event only. Refused
            // rather than substituted: answering a horizontal scroll with a
            // vertical one scrolls somewhere the caller did not ask.
            return Err(invalid_synthetic_request("axis", "unsupported_value"));
        }
        Some(Value::String(_)) => return Err(invalid_synthetic_request("axis", "unknown_value")),
        other => {
            return Err(invalid_synthetic_request(
                "axis",
                synthetic_field_reason(other),
            ))
        }
    }
    let amount = match object.get("amount_lines") {
        // The frozen request schema bounds the amount to -100..=100 lines.
        Some(Value::Number(value)) => value
            .as_i64()
            .filter(|amount| (-100..=100).contains(amount))
            .ok_or_else(|| invalid_synthetic_request("amount_lines", "invalid_value")),
        other => Err(invalid_synthetic_request(
            "amount_lines",
            synthetic_field_reason(other),
        )),
    }?;
    let delta = i32::try_from(amount)
        .map_err(|_| invalid_synthetic_request("amount_lines", "invalid_value"))?;
    Ok(ParsedSynthetic {
        action: SyntheticAction::scroll(SyntheticScrollUnit::Line, delta),
        chord: None,
        action_kind: ActionKind::Compose,
        placeholder_element: AccessibilityElementName::Identifier(target),
    })
}

fn parse_move_request(object: &serde_json::Map<String, Value>) -> Result<ParsedSynthetic, Value> {
    let to = synthetic_point_from_wire(object, "to")?;
    Ok(ParsedSynthetic {
        action: SyntheticAction::move_pointer(to),
        chord: None,
        action_kind: ActionKind::Compose,
        // No element is named or resolved on this path; the label identifies
        // the capability in the serialized placeholder predicate.
        placeholder_element: AccessibilityElementName::Identifier("computer.move".to_string()),
    })
}

fn parse_drag_request(object: &serde_json::Map<String, Value>) -> Result<ParsedSynthetic, Value> {
    let from = synthetic_point_from_wire(object, "from")?;
    let to = synthetic_point_from_wire(object, "to")?;
    match object.get("button") {
        Some(Value::String(button)) if button == "left" => {}
        Some(Value::String(_)) => return Err(invalid_synthetic_request("button", "unknown_value")),
        other => {
            return Err(invalid_synthetic_request(
                "button",
                synthetic_field_reason(other),
            ))
        }
    }
    match object.get("modifiers") {
        Some(Value::Array(modifiers)) if modifiers.is_empty() => {}
        Some(Value::Array(_)) => {
            // The neutral drag action carries no modifiers, so a non-empty
            // list asks for an action this path cannot construct. Refused
            // rather than dropped: performing the drag without them is a
            // different action than the one requested.
            return Err(invalid_synthetic_request(
                "modifiers",
                "synthetic_path_requires_empty",
            ));
        }
        other => {
            return Err(invalid_synthetic_request(
                "modifiers",
                synthetic_field_reason(other),
            ))
        }
    }
    Ok(ParsedSynthetic {
        action: SyntheticAction::drag_pointer(from, to),
        chord: None,
        // The frozen row is mutate_durable outright: a drag moves or drops
        // whatever is under the pointer, which is not session-scoped state.
        action_kind: ActionKind::MutateDurable,
        placeholder_element: AccessibilityElementName::Identifier("computer.drag".to_string()),
    })
}

/// Read a point from its wire spelling, `"x,y"` in global display coordinates.
///
/// The frozen schemas carry points as strings rather than as objects. The two
/// components are split here and nowhere else, and anything that is not two
/// finite numbers is a request error rather than a point at the origin.
fn synthetic_point_from_wire(
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<SyntheticPoint, Value> {
    let text = match object.get(field) {
        Some(Value::String(text)) => text,
        other => {
            return Err(invalid_synthetic_request(
                field,
                synthetic_field_reason(other),
            ))
        }
    };
    let mut components = text.split(',');
    let parse_component = |component: Option<&str>| {
        component
            .and_then(|component| component.trim().parse::<f64>().ok())
            // `f64::from_str` accepts "NaN" and "inf", and a non-finite
            // coordinate names no point on any display.
            .filter(|value| value.is_finite())
    };
    match (
        parse_component(components.next()),
        parse_component(components.next()),
        components.next(),
    ) {
        (Some(x), Some(y), None) => Ok(SyntheticPoint { x, y }),
        _ => Err(invalid_synthetic_request(field, "invalid_value")),
    }
}

/// Name a synthetic dispatch failure by what the caller must know about it.
///
/// A sequence that stopped mid-flight is split from every other refusal
/// because its posted events may have left a key or button held in the
/// target: a caller answered a generic "refused" would send its next action
/// into an application whose held state it does not know. `held_state_unknown`
/// is that report; the typed detail -- how far the sequence got and why it
/// stopped -- is in the audit record the dispatcher finalised before this
/// answer.
fn synthetic_dispatch_refusal(refusal: &DispatchError) -> Value {
    let outcome = match refusal {
        DispatchError::SyntheticSequenceFailed {
            held_state: HeldStateDisposition::Unknown,
            ..
        } => "held_state_unknown",
        DispatchError::SyntheticSequenceFailed { .. } => "dispatch_failed",
        other => other.reason_code(),
    };
    json!({"outcome": outcome})
}

/// Give every synthetic-input outcome the result envelope its vocabulary row
/// declares.
///
/// The three focus-delivered rows declare `outcome`, `containment_rung` and
/// `effect_status`. `computer.move` and `computer.drag` declare no rung:
/// their delivery is coordinate-addressed and always records the weakest one,
/// so carrying the field would assert a distinction the row does not make.
/// `detail` is an implementation diagnostic and is stripped here rather than
/// shipped. The five rows declare `field`, `reason`, `remedy`, and `chord` so
/// a refusal tells callers what failed and how to continue.
fn synthetic_wire_envelope(mut reply: Value, carries_containment_rung: bool) -> Value {
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
    if carries_containment_rung {
        object
            .entry("containment_rung")
            .or_insert_with(|| Value::String("global_none".to_string()));
    } else {
        object.remove("containment_rung");
    }
    object.remove("detail");
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

/// Encode bytes as base64, the form the wire carries an image in.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            ALPHABET[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            ALPHABET[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod wait_tests {
    use super::*;
    use cerebellum_computer::dispatch::post_condition::ObservedElement;

    #[test]
    fn observed_dispatch_refusal_names_the_once_open_target_remedy() {
        let refusal = once_dispatch_refusal();
        assert_eq!(refusal["outcome"], "once_grant_required");
        let remedy = refusal["remedy"]
            .as_str()
            .expect("a typed remedy is present");
        assert!(remedy.contains("computer.open_target"));
        assert!(remedy.contains("once"));
        assert!(remedy.contains("mutate_durable"));
    }

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
            "predicate": expected,
            "timeout_ms": 250,
        }))
        .expect("the typed predicate request parses");

        assert_eq!(parsed.predicate, predicate());
        assert_eq!(parsed.timeout_ms, 250);
    }

    #[test]
    fn request_inventory_is_timeout_ms_plus_a_typed_predicate_not_a_string() {
        let refusal = parse_wait_request(&json!({
            "predicate": "element_present",
            "timeout_ms": 250,
        }))
        .expect_err("the frozen artifact's string predicate remains a schema mismatch");

        assert_eq!(refusal["field"], "predicate");
        assert_eq!(refusal["detail"], "invalid_predicate");
    }

    #[test]
    fn duration_ms_has_no_wait_compatibility_path() {
        let refusal = parse_wait_request(&json!({
            "duration_ms": 25,
            "predicate": predicate(),
        }))
        .expect_err("the obsolete sleep request must stay unreachable");

        assert_eq!(refusal["field"], "duration_ms");
        assert_eq!(refusal["detail"], "unknown_field");
        let reply = wait_indeterminate_reply(None, refusal);
        assert_eq!(reply["outcome"], "indeterminate");
        assert_eq!(reply["settle_path"], "poll_with_deadline");
        assert_eq!(validate_capability_result("computer.wait", &reply), Ok(()));
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

#[cfg(all(test, target_os = "macos"))]
mod click_refusal_tests {
    use super::*;

    #[test]
    fn wire_refusal_serialization_keeps_every_semantic_remedy_payload() {
        let cases = [
            (
                DispatchError::ElementNameAmbiguous {
                    key_form: AccessibilityKeyForm::Identifier,
                    match_count: 2,
                },
                json!({
                    "reason": "element_name_ambiguous",
                    "key_form": "identifier",
                    "match_count": 2,
                }),
            ),
            (
                DispatchError::ElementNotFound {
                    key_form: AccessibilityKeyForm::Identifier,
                },
                json!({
                    "reason": "element_not_found",
                    "key_form": "identifier",
                }),
            ),
            (
                DispatchError::ActionNotAdvertised {
                    action: "press".to_string(),
                    advertised: vec!["show_menu".to_string()],
                },
                json!({
                    "reason": "action_not_advertised",
                    "action": "press",
                    "advertised": ["show_menu"],
                }),
            ),
            (
                DispatchError::ApplicationRefused { ax_error: -25205 },
                json!({
                    "reason": "application_refused",
                }),
            ),
            (
                DispatchError::AccessibilityPermissionUnavailable,
                json!({"reason": "accessibility_permission_unavailable"}),
            ),
            (
                DispatchError::TargetNoLongerCurrent {
                    disposition: TargetDisposition::Replaced,
                },
                json!({
                    "reason": "target_no_longer_current",
                    "disposition": "replaced",
                }),
            ),
            (
                DispatchError::SemanticDispatchTransient { deadline_ms: 3_000 },
                json!({
                    "reason": "semantic_dispatch_transient",
                    "deadline_ms": 3_000,
                }),
            ),
            (
                DispatchError::SemanticPathUnavailable,
                json!({"reason": "semantic_path_unavailable"}),
            ),
        ];

        for (refusal, expected_payload) in cases {
            let mut actual = dispatch_refusal(refusal, 7);
            assert_eq!(actual["outcome"], "refused");
            assert_eq!(actual["containment_rung"], "global_none");
            assert_eq!(actual["effect_status"], "effect_indeterminate");
            assert_eq!(actual["unreadable_subtrees"], 7);
            let object = actual.as_object_mut().expect("the refusal is an object");
            object.remove("outcome");
            object.remove("containment_rung");
            object.remove("effect_status");
            object.remove("unreadable_subtrees");
            assert_eq!(
                actual, expected_payload,
                "a semantic remedy was changed at the wire boundary"
            );
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod click_vocabulary_v3_tests {
    use super::*;
    use cerebellum_computer::platform::macos::resolve_against_identifierless_save_fixture;

    fn left_click(target: Value) -> Value {
        json!({
            "target": target,
            "button": "left",
            "click_count": 1,
            "modifiers": [],
        })
    }

    #[derive(Debug, Default)]
    struct ActionRecordingPlatform {
        requested_action: Option<String>,
    }

    impl PlatformDriver for ActionRecordingPlatform {
        fn capability_declarations(
            &self,
            _context: &cerebellum_computer::platform::CapabilityAdvertisementContext,
        ) -> Vec<cerebellum_computer::platform::CapabilityDeclaration> {
            Vec::new()
        }

        fn read_accessibility_tree(
            &mut self,
            _request: AccessibilityTreeRequest,
        ) -> Result<cerebellum_computer::platform::AccessibilityTreeResult, DriverError> {
            Err(DriverError::Unsupported("test does not read a tree"))
        }

        fn resolve_element(
            &mut self,
            _request: ElementResolutionRequest,
        ) -> Result<ElementResolutionResult, DriverError> {
            Err(DriverError::Unsupported("test does not resolve an element"))
        }

        fn dispatch_semantic(
            &mut self,
            request: SemanticDispatchRequest,
        ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
            self.requested_action = Some(request.action);
            Ok(cerebellum_computer::platform::DispatchResult {
                accepted_by_platform: true,
                effect_status: EffectStatus::EffectIndeterminate,
                unreadable_subtrees: 0,
                delivery_posts_returned: 0,
                delivery_generation_verifications: 0,
            })
        }

        fn dispatch_per_pid(
            &mut self,
            _request: cerebellum_computer::platform::SyntheticDispatchRequest,
        ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
            Err(DriverError::Unsupported(
                "test does not dispatch synthetic input",
            ))
        }

        fn dispatch_global(
            &mut self,
            _request: cerebellum_computer::platform::GlobalDispatchRequest,
        ) -> Result<cerebellum_computer::platform::DispatchResult, DriverError> {
            Err(DriverError::Unsupported(
                "test does not dispatch synthetic input",
            ))
        }

        fn query_focus(
            &mut self,
            _request: cerebellum_computer::platform::FocusQueryRequest,
        ) -> Result<cerebellum_computer::platform::FocusQueryResult, DriverError> {
            Err(DriverError::Unsupported("test does not query focus"))
        }

        fn fronting_snapshot(
            &mut self,
            _target: &cerebellum_computer::platform::ProcessGrant,
        ) -> Result<cerebellum_computer::platform::FrontingSnapshot, DriverError> {
            Err(DriverError::Unsupported(
                "test does not inspect fronting state",
            ))
        }

        fn input_observer_liveness(&self) -> cerebellum_computer::platform::InputObserverLiveness {
            cerebellum_computer::platform::InputObserverLiveness {
                session_tap_live: false,
                raw_hid_live: false,
                self_echo_filter_live: false,
            }
        }

        fn observe_input(
            &mut self,
            _request: cerebellum_computer::platform::InputObservationRequest,
        ) -> Result<cerebellum_computer::platform::InputObservationResult, DriverError> {
            Err(DriverError::Unsupported("test does not observe input"))
        }

        fn observe_effect(
            &mut self,
            _request: cerebellum_computer::platform::EffectObservationRequest,
        ) -> Result<cerebellum_computer::platform::EffectObservationResult, DriverError> {
            Err(DriverError::Unsupported("test does not observe effects"))
        }

        fn verify_attendance(
            &mut self,
            _request: cerebellum_computer::platform::AttendancePreconditionRequest,
        ) -> Result<cerebellum_computer::platform::AttendancePreconditionResult, DriverError>
        {
            Err(DriverError::Unsupported("test does not verify attendance"))
        }
    }

    fn intent_that_reached_platform_driver(wire_request: Value) -> String {
        let parsed = parse_click_request(&wire_request).expect("the click request is valid");
        let semantic = click_semantic_request(
            &parsed,
            ElementResolutionResult {
                element_name: parsed.element_name.clone(),
                alternate_name: None,
                owning_process: cerebellum_computer::platform::ProcessGrant {
                    pid: 42,
                    bundle_identity: "com.example.target".into(),
                    process_generation_evidence: "generation-1".into(),
                },
                semantic_actions: vec![SEMANTIC_PRESS_ACTION.into(), SEMANTIC_CANCEL_ACTION.into()],
                unreadable_subtrees: 0,
            },
        );
        let mut platform = ActionRecordingPlatform::default();
        platform
            .dispatch_semantic(semantic)
            .expect("the recording platform accepts the action");
        platform
            .requested_action
            .expect("the action reached the platform boundary")
    }

    #[test]
    fn a_named_cancel_reaches_the_platform_driver_as_cancel_intent() {
        let mut request = left_click(json!({"by": "identifier", "identifier": "menu"}));
        request["action"] = json!("cancel");

        assert_eq!(
            intent_that_reached_platform_driver(request),
            SEMANTIC_CANCEL_ACTION
        );
    }

    #[test]
    fn an_absent_action_reaches_the_platform_driver_as_press_intent() {
        let request = left_click(json!({"by": "identifier", "identifier": "button"}));

        assert_eq!(
            intent_that_reached_platform_driver(request),
            SEMANTIC_PRESS_ACTION
        );
    }

    #[test]
    fn a_platform_action_name_is_still_an_unknown_wire_value() {
        let mut request = left_click(json!({"by": "identifier", "identifier": "button"}));
        request["action"] = json!("AXPress");

        assert_eq!(
            parse_click_request(&request)
                .expect_err("the wire accepts intents, not platform names"),
            click_wire_envelope(json!({
                "outcome": "invalid_request",
                "field": "action",
                "reason": "unknown_value",
            }))
        );
    }

    /// A role+title target reaches the resolver as that key form, and finds a
    /// control that an identifier of the same title cannot.
    ///
    /// If the handler accepted the object but then resolved by identifier, the
    /// Save button in this fixture would be invisible: it has no identifier.
    #[test]
    fn a_role_and_title_wire_target_resolves_where_an_identifier_cannot() {
        let name = click_target_from_wire(&json!({
            "by": "role_and_title",
            "role": "AXButton",
            "title": "Save",
        }))
        .expect("a well-formed role+title target parses");
        let resolved = resolve_against_identifierless_save_fixture(name.clone())
            .expect("role+title must find the identifierless Save button");
        assert_eq!(resolved.element_name, name);
        assert_eq!(
            resolved.element_name.key_form(),
            AccessibilityKeyForm::RoleAndTitle
        );

        let as_identifier = click_target_from_wire(&json!({
            "by": "identifier",
            "identifier": "Save",
        }))
        .expect("a well-formed identifier target parses");
        assert_eq!(
            resolve_against_identifierless_save_fixture(as_identifier),
            Err(DriverError::ElementNotFound),
            "resolving the same title as an identifier must not find the button"
        );
    }

    #[test]
    fn a_role_and_title_click_post_condition_keeps_the_actions_exact_key() {
        let target = json!({
            "by": "role_and_title",
            "role": "AXButton",
            "title": "Save",
        });
        let mut request = left_click(target);
        request["expect"] = json!({"condition": "element_present"});
        let parsed = parse_click_request(&request).expect("the click request parses");
        let expected = expected_post_condition_from_wire(&parsed)
            .expect("role-and-title can name its own post-condition");

        assert_eq!(expected.condition.element(), &parsed.element_name);
        assert_eq!(
            expected.condition.element().key_form(),
            AccessibilityKeyForm::RoleAndTitle
        );
    }

    #[test]
    fn serve_click_resolves_the_parsed_wire_target() {
        let source = include_str!("computer_capability.rs");
        let (production, _) = source
            .split_once("mod click_refusal_tests")
            .expect("serve_click sits above the refusal tests");
        assert!(
            production.contains("click_target_from_wire"),
            "serve_click no longer parses the tagged target object"
        );
        assert!(
            production.contains("element_name: parsed.element_name.clone()"),
            "serve_click parsed a target but did not resolve under that name"
        );
        assert!(
            !production.contains("AccessibilityElementName::Identifier(target_identifier"),
            "serve_click still rewrites the target as an identifier"
        );
    }

    #[test]
    fn a_non_left_button_is_refused_by_name() {
        let mut request = left_click(json!({"by": "identifier", "identifier": "ok"}));
        request["button"] = json!("right");
        let error = parse_click_request(&request).expect_err("right is not a semantic press");
        assert_eq!(error["outcome"], "invalid_request");
        assert_eq!(error["field"], "button");
        assert_eq!(error["reason"], "semantic_path_requires_left");
    }

    #[test]
    fn a_double_click_is_refused_by_name() {
        let mut request = left_click(json!({"by": "identifier", "identifier": "ok"}));
        request["click_count"] = json!(2);
        let error = parse_click_request(&request).expect_err("a double click is not a press");
        assert_eq!(error["outcome"], "invalid_request");
        assert_eq!(error["field"], "click_count");
        assert_eq!(error["reason"], "semantic_path_requires_one");
    }

    #[test]
    fn a_modifier_is_refused_by_name() {
        let mut request = left_click(json!({"by": "identifier", "identifier": "ok"}));
        request["modifiers"] = json!(["shift"]);
        let error = parse_click_request(&request).expect_err("a modifier is not a press");
        assert_eq!(error["outcome"], "invalid_request");
        assert_eq!(error["field"], "modifiers");
        assert_eq!(error["reason"], "semantic_path_requires_empty");
    }

    #[test]
    fn an_absent_expect_produces_no_effect_claim() {
        let parsed = parse_click_request(&left_click(json!({
            "by": "identifier",
            "identifier": "ok",
        })))
        .expect("a click without expect is well-formed");
        assert!(
            parsed.expect.is_none(),
            "an absent expect must not become a default condition"
        );
        let reply = click_wire_reply(
            "semantic_element",
            0,
            parsed.expect.as_ref().map(|_| EffectStatus::EffectObserved),
        );
        assert_eq!(reply["outcome"], "handler_returned_no_effect_claim");
        assert_eq!(reply["effect_status"], "effect_indeterminate");
    }

    #[test]
    fn a_supplied_expect_produces_an_effect_claim() {
        let mut request = left_click(json!({"by": "identifier", "identifier": "ok"}));
        request["expect"] = json!({"condition": "element_present"});
        let parsed = parse_click_request(&request).expect("a click with expect is well-formed");
        assert!(parsed.expect.is_some());
        let reply = click_wire_reply(
            "semantic_element",
            0,
            parsed.expect.as_ref().map(|_| EffectStatus::EffectObserved),
        );
        assert_eq!(reply["outcome"], "completed");
        assert_eq!(reply["effect_status"], "effect_observed");
    }

    #[test]
    fn serve_click_does_not_observe_when_expect_is_absent() {
        let source = include_str!("computer_capability.rs");
        let (production, _) = source
            .split_once("mod click_refusal_tests")
            .expect("serve_click sits above the refusal tests");
        assert!(
            production.contains("without_expected_post_condition"),
            "an absent expect must still skip effect observation"
        );
        assert!(
            production.contains("parsed.expect.is_some()"),
            "observation must be gated on the caller having named a condition"
        );
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

    /// The frozen bounds are enforced at parse: 4096 characters of text, an
    /// amount inside -100..=100, and a vertical axis only.
    #[test]
    fn the_frozen_request_bounds_are_enforced() {
        let long = "a".repeat(4_097);
        assert!(parse(
            ComputerCapability::Type,
            json!({"target": "editor", "text": long, "replace_selection": false}),
        )
        .is_err());
        assert!(
            parse(
                ComputerCapability::Type,
                json!({"target": "editor", "text": "", "replace_selection": false}),
            )
            .is_err(),
            "an empty type plans no events and must not report success"
        );
        for amount in [101, -101] {
            assert!(
                parse(
                    ComputerCapability::Scroll,
                    json!({"target": "editor", "axis": "vertical", "amount_lines": amount}),
                )
                .is_err(),
                "{amount} lines exceeded the frozen bound"
            );
        }
        assert!(
            parse(
                ComputerCapability::Scroll,
                json!({"target": "editor", "axis": "horizontal", "amount_lines": 3}),
            )
            .is_err(),
            "horizontal construction does not exist; it must refuse rather than substitute"
        );
    }

    /// Points parse from their `"x,y"` spelling; anything else is a request
    /// error, including the non-finite values `f64` parsing would accept.
    #[test]
    fn points_require_two_finite_components() {
        let parsed = parse(ComputerCapability::Move, json!({"to": "-12.5, 40"}))
            .expect("a well-formed point parses");
        assert_eq!(
            parsed.action,
            SyntheticAction::move_pointer(SyntheticPoint { x: -12.5, y: 40.0 })
        );
        for point in ["", "1", "1,2,3", "a,b", "NaN,2", "inf,2", "1,"] {
            assert!(
                parse(ComputerCapability::Move, json!({"to": point})).is_err(),
                "{point:?} parsed as a point"
            );
        }
    }

    /// A drag is mutate_durable outright, and its modifiers list must be
    /// empty because the neutral action carries none.
    #[test]
    fn a_drag_is_durable_and_carries_no_modifiers() {
        let parsed = parse(
            ComputerCapability::Drag,
            json!({"from": "1,2", "to": "3,4", "button": "left", "modifiers": []}),
        )
        .expect("a well-formed drag parses");
        assert_eq!(parsed.action_kind, ActionKind::MutateDurable);

        assert!(
            parse(
                ComputerCapability::Drag,
                json!({"from": "1,2", "to": "3,4", "button": "left", "modifiers": ["shift"]}),
            )
            .is_err(),
            "a drag with modifiers asks for an action this path cannot construct"
        );
        assert!(parse(
            ComputerCapability::Drag,
            json!({"from": "1,2", "to": "3,4", "button": "right", "modifiers": []}),
        )
        .is_err());
    }

    /// An undeclared field is refused as unknown rather than silently
    /// dropped: the frozen schemas are closed.
    #[test]
    fn an_undeclared_field_is_refused_for_each_of_the_five() {
        for (capability, mut request) in [
            (
                ComputerCapability::Type,
                json!({"target": "editor", "text": "hi", "replace_selection": false}),
            ),
            (
                ComputerCapability::Keys,
                json!({"keys": ["s"], "target": "editor"}),
            ),
            (
                ComputerCapability::Scroll,
                json!({"target": "editor", "axis": "vertical", "amount_lines": 1}),
            ),
            (ComputerCapability::Move, json!({"to": "1,2"})),
            (
                ComputerCapability::Drag,
                json!({"from": "1,2", "to": "3,4", "button": "left", "modifiers": []}),
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
    use cerebellum_computer::audit::{ComputerAuditError, TypedCaptureDispatch};
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
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
            ComputerCapability::Screenshot,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        );
        let handle = audit
            .reserve(
                JournalIdentity {
                    principal: "prefrontal".into(),
                    conversation_key: "conversation-1".into(),
                    agent_project_id: "project-1".into(),
                    session_kind: SessionKind::Primary,
                },
                descriptor,
            )
            .unwrap();
        let dispatch = TypedCaptureDispatch::new(
            ComputerCapability::Screenshot,
            ContainmentRung::PidStructural,
            ObservationState::HumanUnobserved,
        )
        .dispatch_material(b"computer.screenshot".to_vec());
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
        let source = include_str!("computer_capability.rs");
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
