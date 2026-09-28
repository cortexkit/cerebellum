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

use cerebellum_computer::audit::{ComputerAudit, ComputerCapability};
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
    HeldStateDisposition, PlatformDriver, SyntheticAction, SyntheticKey, SyntheticKeyModifiers,
    UnsupportedPlatformDriver,
};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::journal::JournalIdentity;
use cerebellum_core::journal::{
    CallerRefusalHistory, JournalStorage, Redactor, RefusalRing, RefusalRingConfig,
    SeverityTaxonomy,
};
use serde_json::{json, Value};
use tokio::sync::Mutex;

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
    Type,
    Keys,
    Wait,
}

impl Servable {
    pub fn capability(self) -> ComputerCapability {
        match self.0 {
            Served::Type => ComputerCapability::Type,
            Served::Keys => ComputerCapability::Keys,
            Served::Wait => ComputerCapability::Wait,
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
        // In the vocabulary, with no wire handler yet.
        ComputerCapability::ReadState
        | ComputerCapability::PressElement
        | ComputerCapability::PressPoint
        | ComputerCapability::WriteText
        | ComputerCapability::TakeoverMove
        | ComputerCapability::TakeoverDrag
        | ComputerCapability::TakeoverScroll => return None,
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
    audit: Arc<Mutex<ComputerAudit<R, T, S>>>,
    /// The capture backend type a pixel-returning row will capture with. No
    /// served row captures today, so nothing is held; the type stays so the
    /// plane's shape does not change when the state read's image arrives.
    capture_backend: std::marker::PhantomData<fn() -> B>,
    result_schema_enforcement: ResultSchemaEnforcement,
    result_schema_findings: StdMutex<BTreeMap<CapabilityResultValidationError, u64>>,
    refusal_ring: Mutex<RefusalRing<ComputerRefusalReason>>,
    make_synthetic_driver: Arc<dyn Fn() -> D + Send + Sync>,
}

impl<B, R, T, S> ComputerPlane<B, R, T, S, UnsupportedPlatformDriver>
where
    B: CaptureBackend + Send,
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
    B: CaptureBackend + Send,
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
            audit: Arc::new(Mutex::new(audit)),
            capture_backend: std::marker::PhantomData,
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
        // The capture backend for a served row that returns pixels. None of
        // the rows served today does; the state read's image will.
        _make_backend: impl FnOnce(&cerebellum_computer::platform::ProcessGrant) -> B,
    ) -> Result<Value, CapabilityResultValidationError> {
        let reply = match capability.0 {
            Served::Wait => self.serve_wait(arguments, context).await,
            Served::Type => synthetic_wire_envelope(
                self.serve_synthetic(ComputerCapability::Type, arguments, context)
                    .await,
            ),
            Served::Keys => synthetic_wire_envelope(
                self.serve_synthetic(ComputerCapability::Keys, arguments, context)
                    .await,
            ),
        };
        self.finish_reply(capability.capability(), reply)
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
            identity: _,
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

        #[cfg(any(target_os = "macos", target_os = "windows"))]
        {
            let predicate = parsed.predicate;
            let timeout_ms = parsed.timeout_ms;
            match tokio::task::spawn_blocking(move || {
                let mut poller =
                    PlatformPredicatePoller::new(NativeComputerPlatformDriver::default(), grant);
                wait_until_predicate(&mut poller, predicate, timeout_ms, &|| {
                    cancel.is_cancelled()
                })
            })
            .await
            {
                Ok(result) => {
                    let mut reply = wait_wire_reply(result);
                    admission.decorate(&mut reply);
                    reply
                }
                Err(_) => {
                    wait_indeterminate_reply(None, json!({"reason": "polling_task_unavailable"}))
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        {
            let _ = (grant, cancel);
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
        let mut parsed = match parse_synthetic_request(capability, arguments) {
            Ok(parsed) => parsed,
            Err(refusal) => return refusal,
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
                return chord_blocked_refusal(&chord, blocked.reason);
            }
            // The session floor is checked before anything is asked or
            // escalated, so no grant can make a session-ending chord valid.
            parsed.action_kind = chord_action_kind(*modifiers);
        }
        // Keystrokes stay bound to the named application's process generation.
        let mode = DispatchMode::Background;
        let (grant, admission) = match management
            .admit_app(&parsed.target, &consent, &cancel)
            .await
        {
            Ok(admitted) => admitted,
            // A cancel while waiting on the person is answered the way a cancel
            // during posting is: nothing was posted and nothing is held.
            Err(AppRefusal::Consent(ConsentRefusal::Cancelled)) => {
                return synthetic_dispatch_refusal(&DispatchError::Cancelled {
                    posts_returned: 0,
                    held_state: HeldStateDisposition::NoneHeld,
                })
            }
            Err(refusal) => return refusal.reply(&parsed.target),
        };

        let capability_id = capability.capability_id();
        // Every served capability has a dispatch row; a missing one is a table
        // disagreement to report, not a reason to take the module down.
        let Some(mut row) = FrozenDispatchRow::for_capability(capability_id) else {
            return json!({
                "outcome": "not_servable",
                "remedy": "this capability has no dispatch row; report it",
            });
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
            Err(_) => return synthetic_dispatch_refusal(&DispatchError::AttendanceUnavailable),
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
        let request = DispatchRequest::new(row, mode, grant, expected, attendance, dispatch_at_ms)
            .with_synthetic(parsed.action);

        // Posting is synchronous and may take seconds. Keep the frame reader
        // runnable even on a single-thread runtime so Cancel can set the signal.
        let audit = self.audit.clone();
        let make_driver = self.make_synthetic_driver.clone();
        let dispatched = tokio::task::spawn_blocking(move || {
            let mut audit = audit.blocking_lock();
            Dispatcher::new(make_driver(), &|| cancel.is_cancelled())
                .dispatch(&mut audit, identity, request)
        })
        .await
        .unwrap_or(Err(DispatchError::Platform));
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
                // received it was pinned down. An action can be fully contained
                // and land in a window nobody was looking at, and a caller that
                // cannot see both halves cannot tell that from an uncontained
                // one.
                //
                // The reason key is omitted rather than sent as null when no
                // condition denied the rung: absence is unambiguous here because
                // target_fronted is always present, so a caller can tell a build
                // that reports these from one that does not.
                synthetic_success_reply(
                    DispatchContainmentRung::as_str(containment_rung),
                    report.containment.fronting_stable,
                    effect_status_name(report.effect.status),
                    report
                        .containment
                        .forfeiture_reason
                        .map(|reason| reason.as_str()),
                )
            }
            Err(refusal) => synthetic_dispatch_refusal(&refusal),
        };
        admission.decorate(&mut reply);
        reply
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
        ComputerCapability::Wait => Some((&WAIT_REQUEST_FIELDS, &WAIT_REQUEST_FIELDS)),
        ComputerCapability::Type | ComputerCapability::Keys => {
            let fields = synthetic_request_fields(capability)?;
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
        ComputerCapability::Wait => parse_wait_request(arguments).map(|_| ()),
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
    let mut reply = wait_indeterminate_reply(
        Some(predicate),
        json!({"reason": "cancelled_while_awaiting_consent"}),
    );
    reply["outcome"] = json!("cancelled");
    reply["attempts"] = json!(0);
    reply
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
        ComputerCapability::Type => Some(&["target", "text"]),
        ComputerCapability::Keys => Some(&["keys", "target"]),
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
        ComputerCapability::Type => parse_type_request(object),
        ComputerCapability::Keys => parse_keys_request(object),
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

fn synthetic_dispatch_refusal(refusal: &DispatchError) -> Value {
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
    if let DispatchError::SyntheticSequenceFailed { posts_returned, .. } = refusal {
        reply["posts_returned"] = json!(posts_returned);
    }
    reply
}

/// Give every synthetic-input outcome the result envelope its vocabulary row
/// declares.
///
/// Build the reply for a synthetic action that completed.
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
        "outcome": "completed",
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
                ComputerCapability::Type,
                json!({"target": "com.example.Editor", "text": "hi"}),
            ),
            (
                ComputerCapability::Keys,
                json!({"keys": ["s"], "target": "com.example.Editor"}),
            ),
            (
                ComputerCapability::Wait,
                json!({"app": "com.example.Editor", "predicate": predicate(), "timeout_ms": 250}),
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
                    principal: "prefrontal".into(),
                    conversation_key: "conversation-1".into(),
                    agent_project_id: "project-1".into(),
                    session_kind: SessionKind::Primary,
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
            ComputerPlane::with_result_schema_enforcement(audit, ResultSchemaEnforcement::Withhold);
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
