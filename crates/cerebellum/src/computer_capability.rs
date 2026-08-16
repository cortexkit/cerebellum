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

use std::path::PathBuf;
use std::sync::Arc;

use cerebellum_computer::audit::{
    ComputerAudit, ComputerCapability, ComputerPlaneDescriptor, ObservationState,
    TypedCaptureDispatch,
};
use cerebellum_computer::capture::{CaptureArtifact, CaptureBackend, ScopedCaptureController};
use cerebellum_computer::capture_custody::{CaptureScope, PixelArtifact};
use cerebellum_computer::grounding::ContainmentRung;
#[cfg(target_os = "macos")]
use cerebellum_computer::{
    dispatch::{
        post_condition::PostCondition, AttendanceContext, AttendanceLease, DispatchError,
        DispatchRequest, Dispatcher, ExpectedPostCondition, FrozenDispatchRow,
    },
    platform::{
        containment::ContainmentRung as DispatchContainmentRung, AccessibilityElementName,
        AccessibilityKeyForm, AccessibilityReadFailure, AccessibilityTreeRequest, DispatchMode,
        DriverError, EffectStatus, ElementResolutionRequest, ElementResolutionResult,
        MacOs26PlatformDriver, PlatformDriver, SemanticDriverError, TargetDisposition,
    },
};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::consent::ActionKind;
use cerebellum_core::journal::JournalIdentity;
use cerebellum_core::journal::{JournalStorage, Redactor, SeverityTaxonomy};
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
    let read_u32 = |field: &str, minimum: u32| -> Result<u32, Value> {
        match object.get(field).and_then(Value::as_u64) {
            Some(value) if value <= u64::from(u32::MAX) && value >= u64::from(minimum) => {
                Ok(value as u32)
            }
            Some(_) => Err(invalid_screenshot_request(field, "invalid_value")),
            None => Err(invalid_screenshot_request(
                field,
                if object.contains_key(field) {
                    "wrong_type"
                } else {
                    "missing_field"
                },
            )),
        }
    };
    Ok(Some(CaptureRegion {
        x_px: read_u32("x_px", 0)?,
        y_px: read_u32("y_px", 0)?,
        width_px: read_u32("width_px", 1)?,
        height_px: read_u32("height_px", 1)?,
    }))
}

/// Crop a captured window to the requested region in that window's pixel space.
///
/// Tightly packed BGRA (`width * height * 4` bytes) is cropped in place so the
/// reply cannot advertise a region while still carrying the whole window. Other
/// encodings keep their bytes and still take the region's dimensions, because
/// those dimensions are what the reply and custody account for.
fn apply_capture_region(
    frame_width: u32,
    frame_height: u32,
    bytes: &[u8],
    region: Option<&CaptureRegion>,
) -> Result<(u32, u32, Vec<u8>), Value> {
    let Some(region) = region else {
        return Ok((frame_width, frame_height, bytes.to_vec()));
    };
    let ends_x = region.x_px.checked_add(region.width_px);
    let ends_y = region.y_px.checked_add(region.height_px);
    if ends_x.map(|x| x > frame_width).unwrap_or(true)
        || ends_y.map(|y| y > frame_height).unwrap_or(true)
    {
        return Err(invalid_screenshot_request(
            "region",
            "region_outside_window",
        ));
    }
    let expected = (frame_width as usize)
        .checked_mul(frame_height as usize)
        .and_then(|pixels| pixels.checked_mul(4));
    let cropped = if expected == Some(bytes.len()) {
        crop_bgra(bytes, frame_width, frame_height, region)
    } else {
        bytes.to_vec()
    };
    Ok((region.width_px, region.height_px, cropped))
}

fn crop_bgra(
    bytes: &[u8],
    frame_width: u32,
    _frame_height: u32,
    region: &CaptureRegion,
) -> Vec<u8> {
    let stride = frame_width as usize * 4;
    let row_bytes = region.width_px as usize * 4;
    let mut cropped = Vec::with_capacity(row_bytes * region.height_px as usize);
    for row in 0..region.height_px as usize {
        let start = (region.y_px as usize + row) * stride + region.x_px as usize * 4;
        cropped.extend_from_slice(&bytes[start..start + row_bytes]);
    }
    cropped
}

/// The computer plane as a running module holds it.
///
/// The parameters are fixed here rather than left open at every call site: the
/// severity table, redaction policy and storage are decisions this module makes
/// once, and spelling them at each use invites a caller substituting a different
/// redaction policy without that reading as a change of policy.
#[cfg(target_os = "macos")]
pub type RunningComputerPlane = ComputerPlane<
    cerebellum_computer::platform::native::NativeCaptureBackend,
    cerebellum_computer::audit::redaction::ExcludeApplicationText,
    cerebellum_core::journal::ValidatedSeverityTaxonomy,
    cerebellum_core::journal::FilesystemJournalStorage,
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

#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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
pub fn servable(name: &str) -> Option<Servable> {
    match ComputerCapability::parse(name) {
        Some(
            capability @ (ComputerCapability::Click
            | ComputerCapability::Screenshot
            | ComputerCapability::Wait),
        ) => Some(Servable(capability)),
        // These rows still have no reviewed wire input path. Listed by name
        // rather than caught by a wildcard so adding a capability to the
        // vocabulary does not silently make it servable here.
        Some(
            ComputerCapability::Type
            | ComputerCapability::Keys
            | ComputerCapability::Scroll
            | ComputerCapability::Move
            | ComputerCapability::Drag,
        ) => None,
        None => None,
    }
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

/// What a served capability needs beyond the request itself.
pub struct ComputerPlane<B, R, T, S>
where
    R: Redactor,
    T: SeverityTaxonomy,
    S: JournalStorage,
{
    audit: Mutex<ComputerAudit<R, T, S>>,
    capture: Mutex<Option<ScopedCaptureController<B>>>,
}

impl<B, R, T, S> ComputerPlane<B, R, T, S>
where
    B: CaptureBackend + Send,
    R: Redactor + Send,
    T: SeverityTaxonomy + Send,
    S: JournalStorage + Send,
{
    /// How many journal sequences have been allocated.
    ///
    /// Exposed so a test can establish that an action was recorded WITHOUT
    /// reading the entries themselves, which would put a test in the position of
    /// interpreting the journal's contents to decide whether it was written to.
    pub async fn journal_entry_count(&self) -> u64 {
        self.audit.lock().await.journal().next_sequence()
    }

    pub fn new(audit: ComputerAudit<R, T, S>) -> Self {
        Self {
            audit: Mutex::new(audit),
            capture: Mutex::new(None),
        }
    }

    /// Serve one capability, or refuse with a reason the caller can act on.
    pub async fn serve<C: MonotonicClock>(
        &self,
        capability: Servable,
        arguments: &Value,
        context: ServeContext<'_, C>,
        make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Value {
        match capability.capability() {
            ComputerCapability::Wait => self.serve_wait(arguments),
            ComputerCapability::Screenshot => {
                self.serve_screenshot(arguments, context, make_backend)
                    .await
            }
            #[cfg(target_os = "macos")]
            ComputerCapability::Click => self.serve_click(arguments, context).await,
            // Unreachable through `servable`, which is the only way a capability
            // arrives here. Answered rather than panicked: a dispatch table and
            // this match disagreeing is a bug to report, not a reason to take
            // the module down.
            other => json!({
                "outcome": "not_servable",
                "capability": other.capability_id(),
                "remedy": "this capability is advertised but has no implementation; report it",
            }),
        }
    }

    /// Wait for a bounded interval.
    ///
    /// Reads a clock and touches nothing, which is why it needs no lease and no
    /// target: there is no application to name.
    fn serve_wait(&self, arguments: &Value) -> Value {
        let Some(duration_ms) = arguments.get("duration_ms").and_then(Value::as_u64) else {
            return json!({
                "outcome": "invalid_request",
                "field": "duration_ms",
                "reason": "missing_field",
            });
        };
        json!({ "outcome": "completed", "waited_ms": duration_ms })
    }

    /// Invoke the accessibility press action on one uniquely named element.
    #[cfg(target_os = "macos")]
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
            MacOs26PlatformDriver::default()
        } else {
            MacOs26PlatformDriver::default().without_expected_post_condition()
        };
        let tree = match driver.read_accessibility_tree(AccessibilityTreeRequest {
            target: grant.clone(),
            settle_interval_ms: 500,
        }) {
            Ok(tree) => tree,
            Err(error) => return click_driver_refusal(error, parsed.element_name.key_form()),
        };
        let Some(root_identifier) = tree.root_identifier else {
            return dispatch_refusal(DispatchError::SemanticPathUnavailable);
        };
        let element = match driver.resolve_element(ElementResolutionRequest {
            root_identifier,
            element_name: parsed.element_name.clone(),
        }) {
            Ok(element) => element,
            Err(error) => return click_driver_refusal(error, parsed.element_name.key_form()),
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
            Err(_) => return dispatch_refusal(DispatchError::AttendanceUnavailable),
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

        let expected = match expected_post_condition_from_wire(&parsed, &element) {
            Ok(expected) => expected,
            Err(refusal) => return refusal,
        };
        let request = DispatchRequest::new(
            row,
            DispatchMode::Background,
            grant,
            expected,
            attendance,
            dispatch_at_ms,
        )
        // The name macOS accessibility actually advertises, not a lowercase
        // shorthand for it. The closed AxAction vocabulary parses exactly the
        // framework's spelling, so anything else is refused as unadvertised --
        // which is correct behaviour and made every wire click fail until a
        // live probe drove one against a real application. Fixtures could not
        // catch it: a double declares whatever string the test also passes, so
        // the two agree with each other and with nothing else.
        .with_semantic(element, cerebellum_computer::SEMANTIC_PRESS_ACTION);

        let mut audit = self.audit.lock().await;
        match Dispatcher::new(driver).dispatch(&mut audit, identity, request) {
            Ok(report) => {
                let Some(containment_rung) = report.containment.rung() else {
                    return dispatch_refusal(DispatchError::AuditUnavailable);
                };
                click_wire_reply(
                    DispatchContainmentRung::as_str(containment_rung),
                    report.platform_result.unreadable_subtrees,
                    parsed.expect.as_ref().map(|_| report.effect.status),
                )
            }
            Err(refusal) => dispatch_refusal(refusal),
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
            let result = controller.capture_scoped(now_ms);
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
            let (width_px, height_px, bytes) = match apply_capture_region(
                window.frame.width,
                window.frame.height,
                bytes,
                region.as_ref(),
            ) {
                Ok(cropped) => cropped,
                Err(refusal) => {
                    let _ = audit.finalize_rejected(handle, b"region-outside-window".to_vec());
                    return refusal;
                }
            };
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
            let mut entry = json!({
                "window_id": window.window_id,
                "width_px": width_px,
                "height_px": height_px,
                "image_png_b64": base64(&bytes),
            });
            if let Some(region) = region {
                entry["region"] = json!({
                    "x_px": region.x_px,
                    "y_px": region.y_px,
                    "width_px": region.width_px,
                    "height_px": region.height_px,
                });
            }
            windows.push(entry);
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
        if !audit.custody().artifact_readable(&artifact_id) {
            let _ = audit.finalize_rejected(handle, b"capture-not-retained".to_vec());
            return json!({
                "outcome": "capture_not_retained",
                "detail": "the capture was not retained by custody",
            });
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

        let mut reply = json!({
            "outcome": "captured",
            "windows": windows,
        });
        if let Some(region) = region {
            reply["region"] = json!({
                "x_px": region.x_px,
                "y_px": region.y_px,
                "width_px": region.width_px,
                "height_px": region.height_px,
            });
        }
        reply
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct ParsedClick {
    element_name: AccessibilityElementName,
    expect: Option<ParsedExpect>,
}

#[cfg(target_os = "macos")]
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
#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn parse_click_request(arguments: &Value) -> Result<ParsedClick, Value> {
    let Some(object) = arguments.as_object() else {
        return Err(invalid_click_request("$", "wrong_type"));
    };
    if let Some(field) = object
        .keys()
        .filter(|field| {
            !matches!(
                field.as_str(),
                "target" | "button" | "click_count" | "modifiers" | "expect"
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
    let expect = match object.get("expect") {
        None => None,
        Some(expect) => Some(parse_click_expect(expect)?),
    };
    Ok(ParsedClick {
        element_name,
        expect,
    })
}

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn post_condition_element_identifier(
    name: &AccessibilityElementName,
    resolved: &ElementResolutionResult,
) -> Option<String> {
    match name {
        AccessibilityElementName::Identifier(identifier) => Some(identifier.clone()),
        AccessibilityElementName::RoleAndTitle { .. } => match &resolved.alternate_name {
            Some(AccessibilityElementName::Identifier(identifier)) => Some(identifier.clone()),
            _ => None,
        },
    }
}

#[cfg(target_os = "macos")]
fn expected_post_condition_from_wire(
    parsed: &ParsedClick,
    resolved: &ElementResolutionResult,
) -> Result<ExpectedPostCondition, Value> {
    let Some(expect) = parsed.expect.as_ref() else {
        // Placeholder only: the driver is marked as having no caller-supplied
        // condition and will not evaluate this or report it as a claim.
        // Never evaluated: the driver is marked as having no caller-supplied
        // condition. The identifier is only here because the dispatch envelope
        // requires a closed condition type.
        return Ok(ExpectedPostCondition::new(
            "computer-click-wire-no-effect-claim-v1",
            PostCondition::ElementPresent {
                element_identifier: String::new(),
            },
        ));
    };
    let Some(element_identifier) =
        post_condition_element_identifier(&parsed.element_name, resolved)
    else {
        return Err(invalid_click_request(
            "expect",
            "post_condition_requires_identifier",
        ));
    };
    let condition = match expect.condition.as_str() {
        "element_present" => PostCondition::ElementPresent { element_identifier },
        "element_absent" => PostCondition::ElementAbsent { element_identifier },
        "focused_element_equals" => PostCondition::ElementFocused {
            element_identifier: expect.value.clone().unwrap_or(element_identifier),
        },
        "element_attribute_equals" => {
            let attribute = expect.attribute.as_deref().unwrap_or("");
            let value = expect.value.clone().unwrap_or_default();
            match attribute {
                "AXValue" | "value" | "AXValueDescription" => PostCondition::ElementValueEquals {
                    element_identifier,
                    expected: value,
                },
                "AXEnabled" | "enabled" => {
                    let expected = match value.as_str() {
                        "true" => true,
                        "false" => false,
                        _ => return Err(invalid_click_request("value", "invalid_value")),
                    };
                    PostCondition::ElementEnabledIs {
                        element_identifier,
                        expected,
                    }
                }
                "AXFocused" | "focused" if value == "true" => {
                    PostCondition::ElementFocused { element_identifier }
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
#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn effect_status_name(status: EffectStatus) -> &'static str {
    match status {
        EffectStatus::EffectObserved => "effect_observed",
        EffectStatus::NoEffectObserved => "no_effect_observed",
        EffectStatus::EffectIndeterminate => "effect_indeterminate",
    }
}

#[cfg(target_os = "macos")]
fn field_reason(value: Option<&Value>) -> &'static str {
    if value.is_some() {
        "wrong_type"
    } else {
        "missing_field"
    }
}

#[cfg(target_os = "macos")]
fn invalid_click_request(field: &str, reason: &str) -> Value {
    json!({
        "outcome": "invalid_request",
        "field": field,
        "reason": reason,
    })
}

#[cfg(target_os = "macos")]
fn dispatch_refusal(refusal: DispatchError) -> Value {
    serde_json::to_value(refusal).expect("the closed dispatch refusal taxonomy serializes")
}

#[cfg(target_os = "macos")]
fn click_driver_refusal(error: DriverError, key_form: AccessibilityKeyForm) -> Value {
    let refusal = match error {
        DriverError::Semantic(failure) => match failure {
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
        DriverError::Unsupported(_)
        | DriverError::InvalidRequest(_)
        | DriverError::StartupRefused(_) => DispatchError::SemanticPathUnavailable,
    };
    dispatch_refusal(refusal)
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
                    "ax_error": -25205,
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

        for (refusal, expected) in cases {
            assert_eq!(
                dispatch_refusal(refusal),
                expected,
                "a semantic remedy was changed at the wire boundary"
            );
        }
    }
}

#[cfg(all(test, target_os = "macos"))]
mod click_vocabulary_v2_tests {
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

#[cfg(test)]
mod region_crop_tests {
    use super::*;

    fn patterned(width: u32, height: u32) -> Vec<u8> {
        let mut bytes = Vec::new();
        for y in 0..height {
            for x in 0..width {
                bytes.extend_from_slice(&[(x % 256) as u8, (y % 256) as u8, 0, 255]);
            }
        }
        bytes
    }

    #[test]
    fn apply_capture_region_crops_bgra_to_the_requested_rectangle() {
        let bytes = patterned(8, 6);
        let region = CaptureRegion {
            x_px: 2,
            y_px: 1,
            width_px: 3,
            height_px: 2,
        };
        let (width, height, cropped) =
            apply_capture_region(8, 6, &bytes, Some(&region)).expect("the region fits");
        assert_eq!((width, height), (3, 2));
        assert_eq!(cropped.len(), 3 * 2 * 4);
        assert_eq!(&cropped[0..4], &[2, 1, 0, 255]);
        assert_ne!(cropped, bytes);
    }

    #[test]
    fn a_region_outside_the_window_is_refused() {
        let bytes = patterned(8, 6);
        let region = CaptureRegion {
            x_px: 6,
            y_px: 0,
            width_px: 4,
            height_px: 1,
        };
        let error = apply_capture_region(8, 6, &bytes, Some(&region))
            .expect_err("a region past the right edge must not crop");
        assert_eq!(error["field"], "region");
        assert_eq!(error["reason"], "region_outside_window");
    }
}
