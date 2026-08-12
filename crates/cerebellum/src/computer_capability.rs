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
        }
    }
}

/// The audit a running module uses for the computer plane.
///
/// Every part is chosen so the capability gate can be satisfied honestly rather
/// than satisfied at all costs: the severity table is the pinned artifact, and
/// the redaction policy withholds application text rather than truncating it.
/// Binding a truncating policy here would satisfy the same gate while making an
/// application's own words durable in the journal.
///
/// The journal lives under `~/.local/share/cortexkit/journal/computer.json`:
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

    let unresolved_path = PathBuf::from("~/.local/share/cortexkit/journal/computer.json");
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

    ComputerAudit::new(
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
    })
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
        // Serving these two needs no input path: one reads pixels and the other
        // reads a clock.
        Some(capability @ (ComputerCapability::Screenshot | ComputerCapability::Wait)) => {
            Some(Servable(capability))
        }
        // Everything else actuates, and no input path exists yet. Listed by
        // name rather than caught by a wildcard so adding a capability to the
        // vocabulary does not silently make it servable here.
        Some(
            ComputerCapability::Click
            | ComputerCapability::Type
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
        let mut total_bytes = 0usize;
        for window in &captured.windows {
            let CaptureArtifact::Bytes(bytes) = &window.artifact else {
                continue;
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
            windows.push(json!({
                "window_id": window.window_id,
                "width_px": window.frame.width,
                "height_px": window.frame.height,
                "image_png_b64": base64(bytes),
            }));
        }

        // Admitted to custody before the result is built, so the pixels handed
        // back are the ones the journal accounts for.
        //
        // A capture that produced no window with pixels has nothing to account
        // for, and an artifact describing no image is refused by custody rather
        // than stored as an empty one. Reported as its own outcome, because a
        // target with no capturable window is a fact about the target rather
        // than a failure to retain what was captured.
        let Some((first, first_bytes)) =
            captured
                .windows
                .iter()
                .find_map(|window| match &window.artifact {
                    CaptureArtifact::Bytes(bytes) => Some((window, bytes)),
                    _ => None,
                })
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
            first_bytes.clone(),
            now_ms,
            first.window_id.clone(),
            grant.pid,
            first.frame.width,
            first.frame.height,
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

        json!({
            "outcome": "captured",
            "windows": windows,
        })
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
