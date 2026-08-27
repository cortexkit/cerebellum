use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cerebellum::management::{ManagementPlane, TargetResolver};
use cerebellum_computer::audit::ComputerAudit;
use cerebellum_computer::capture::{
    BackendError, CaptureArtifact, CaptureBackend, EnumeratedWindow, WindowFrame,
};
use cerebellum_computer::capture_custody::{
    CaptureCustody, CaptureGrant, CaptureScope, CustodyBounds, InMemoryCustodyStorage,
    InMemoryGrantAuthority,
};
use cerebellum_computer::platform::{ProcessGrant, TargetResolution};
use cerebellum_core::clock::MonotonicClock;
use cerebellum_core::consent::ActionKind;
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::{
    DurableState, EffectClass, InMemoryJournalStorage, IoDiagnostic, IsolationClass, JournalConfig,
    JournalIdentity, JournalStorage, ObservabilityClass, Redactor, SeverityInputs, SeverityRecord,
    StorageError, ValidatedSeverityTaxonomy,
};
use serde_json::{json, Value};

pub const GRANTEE: &str = "pj-example";
pub const TARGET_BUNDLE_ID: &str = "com.apple.Safari";

#[derive(Clone)]
pub struct TestRedactor;

impl Redactor for TestRedactor {
    fn available(&self) -> bool {
        true
    }

    fn redact(
        &self,
        input: &str,
        _max_bytes: usize,
    ) -> Result<String, cerebellum_core::journal::RedactionUnavailable> {
        Ok(input.replace("secret", "[REDACTED]"))
    }
}

fn taxonomy() -> ValidatedSeverityTaxonomy {
    let effects = [
        EffectClass::Read,
        EffectClass::Mutate,
        EffectClass::Authorize,
    ];
    let isolations = [
        IsolationClass::ResourceScoped,
        IsolationClass::OwnerScoped,
        IsolationClass::Uncontained,
    ];
    let observations = [
        ObservabilityClass::HumanObserved,
        ObservabilityClass::HumanUnobserved,
    ];
    ValidatedSeverityTaxonomy::new(
        "computer-test-v1",
        effects.into_iter().flat_map(move |effect| {
            let isolations = isolations;
            let observations = observations;
            isolations.into_iter().flat_map(move |isolation| {
                let observations = observations;
                observations.into_iter().map(move |observation| {
                    (
                        SeverityInputs {
                            effect_class: effect,
                            isolation_class: isolation,
                            observability_class: observation,
                        },
                        SeverityRecord {
                            tier: if effect == EffectClass::Read { 1 } else { 2 },
                            credential: false,
                            financial: effect == EffectClass::Authorize,
                        },
                    )
                })
            })
        }),
    )
    .unwrap()
}

pub fn identity() -> JournalIdentity {
    JournalIdentity {
        principal: "prefrontal".into(),
        conversation_key: "conversation-1".into(),
        agent_project_id: "project-1".into(),
        session_kind: SessionKind::Primary,
    }
}

fn bounds() -> CustodyBounds {
    CustodyBounds {
        maximum_verification_duration_ms: 100,
        maximum_pin_lifetime_ms: 50,
        maximum_concurrently_pinned_artifacts: 4,
        maximum_total_pinned_artifact_bytes: 10_000,
        maximum_custody_attachment_bytes: 2_000,
    }
}

fn custody() -> CaptureCustody {
    let mut authority = InMemoryGrantAuthority::default();
    authority.insert(CaptureGrant::new(
        "grant-1",
        CaptureScope::PerWindow,
        0,
        1_000,
    ));
    CaptureCustody::new(bounds(), authority, InMemoryCustodyStorage::new()).unwrap()
}

pub fn audit() -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, InMemoryJournalStorage> {
    audit_with_storage(InMemoryJournalStorage::new())
}

fn audit_with_storage<S: JournalStorage>(
    storage: S,
) -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, S> {
    ComputerAudit::new(
        TestRedactor,
        taxonomy(),
        JournalConfig {
            journal_retention_bytes: 20_000,
            journal_max_entry_bytes: 4_000,
        },
        storage,
        custody(),
    )
    .unwrap()
}

// Shared by every test binary that includes this module; any one binary uses
// only part of it, so the parts are allowed to be unused per binary.
#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct FailAfterInitialization {
    saves: Arc<AtomicUsize>,
}

#[allow(dead_code)]
impl FailAfterInitialization {
    pub fn new() -> Self {
        Self {
            saves: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[allow(dead_code)]
pub fn failing_audit(
) -> ComputerAudit<TestRedactor, ValidatedSeverityTaxonomy, FailAfterInitialization> {
    audit_with_storage(FailAfterInitialization::new())
}

impl JournalStorage for FailAfterInitialization {
    fn load(&self) -> Result<DurableState, StorageError> {
        Ok(DurableState::default())
    }

    fn save(&self, _state: &DurableState) -> Result<(), StorageError> {
        if self.saves.fetch_add(1, Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(StorageError::TemporaryWrite {
                path: PathBuf::from("/unwritable/journal.tmp"),
                source: IoDiagnostic {
                    kind: std::io::ErrorKind::PermissionDenied,
                    message: "permission denied".to_string(),
                },
            })
        }
    }
}

/// A resolver that answers from a fixture instead of the window server.
pub struct Fixed(pub TargetResolution);

impl TargetResolver for Fixed {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.0.clone()
    }
}

/// A resolver whose answer can change after a lease is issued.
///
/// `authority_for` deliberately resolves again at serving time. This fixture
/// exercises refusal replies for a target that became ambiguous or unreadable
/// after consent, without reading the host window server.
#[allow(dead_code)]
#[derive(Clone)]
pub struct MutableTargetResolver {
    resolution: Arc<Mutex<TargetResolution>>,
}

#[allow(dead_code)]
impl MutableTargetResolver {
    pub fn new(resolution: TargetResolution) -> Self {
        Self {
            resolution: Arc::new(Mutex::new(resolution)),
        }
    }

    pub fn replace(&self, resolution: TargetResolution) {
        *self
            .resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = resolution;
    }
}

impl TargetResolver for MutableTargetResolver {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.resolution
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// A backend that captures successfully, to prove what a real capture produces.
///
/// Its counterpart refuses everything, and a suite holding only that one cannot
/// reach the code that builds a result from pixels: every test ends at the
/// failure branch. That gap let an artifact built with no bytes and zero
/// dimensions ship, which custody refused on the first real capture.
#[allow(dead_code)]
pub struct CapturingBackend {
    pub windows: Vec<EnumeratedWindow>,
    pub png: Vec<u8>,
}

impl CaptureBackend for CapturingBackend {
    fn screen_recording_liveness(&self) -> cerebellum_computer::platform::PermissionLiveness {
        cerebellum_computer::platform::PermissionLiveness::Live
    }

    fn enumerate_windows(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        Ok(self.windows.clone())
    }

    fn poll_window_change(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Option<cerebellum_computer::capture::WindowChange>, BackendError> {
        Ok(None)
    }

    fn capture_window(
        &mut self,
        request: &cerebellum_computer::capture::WindowCaptureRequest,
    ) -> Result<cerebellum_computer::capture::WindowCaptureFrame, BackendError> {
        let window = self
            .windows
            .iter()
            .find(|window| window.window_id == request.filter.window_id)
            .ok_or_else(|| BackendError::Capture("no such window".into()))?;
        let (frame, bytes) = match request.region {
            Some(region) => {
                let stride = window.frame.width as usize * 4;
                let row_bytes = region.width_px as usize * 4;
                let mut cropped = Vec::with_capacity(row_bytes * region.height_px as usize);
                for row in 0..region.height_px as usize {
                    let start = (region.y_px as usize + row) * stride + region.x_px as usize * 4;
                    cropped.extend_from_slice(&self.png[start..start + row_bytes]);
                }
                (
                    WindowFrame {
                        x: window.frame.x + region.x_px as i32,
                        y: window.frame.y + region.y_px as i32,
                        width: region.width_px,
                        height: region.height_px,
                    },
                    cropped,
                )
            }
            None => (window.frame, self.png.clone()),
        };
        Ok(cerebellum_computer::capture::WindowCaptureFrame {
            owner_identity: window.owner_identity.clone(),
            owner_identity_verified: true,
            frame,
            captured_at_ms: request.captured_at_ms,
            artifact: CaptureArtifact::Bytes(bytes),
            accessibility_root: None,
        })
    }

    fn capture_display(
        &mut self,
        _request: &cerebellum_computer::capture::BroadDisplayCaptureRequest,
    ) -> Result<cerebellum_computer::capture::CaptureArtifact, BackendError> {
        Err(BackendError::Capture("not served".into()))
    }

    fn begin_teardown(
        &mut self,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        Ok(cerebellum_computer::capture::BackendTeardownProgress::Complete)
    }

    fn poll_teardown(
        &mut self,
        _elapsed_ms: u64,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        Ok(cerebellum_computer::capture::BackendTeardownProgress::Complete)
    }
}

/// A backend that refuses every capture, to prove what survives a failure.
#[allow(dead_code)]
#[derive(Default)]
pub struct RefusingBackend {
    pub windows: Vec<EnumeratedWindow>,
}

impl CaptureBackend for RefusingBackend {
    fn screen_recording_liveness(&self) -> cerebellum_computer::platform::PermissionLiveness {
        cerebellum_computer::platform::PermissionLiveness::Live
    }

    fn enumerate_windows(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        Ok(self.windows.clone())
    }

    fn poll_window_change(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Option<cerebellum_computer::capture::WindowChange>, BackendError> {
        Ok(None)
    }

    fn capture_window(
        &mut self,
        _request: &cerebellum_computer::capture::WindowCaptureRequest,
    ) -> Result<cerebellum_computer::capture::WindowCaptureFrame, BackendError> {
        Err(BackendError::Capture("the window server refused".into()))
    }

    fn capture_display(
        &mut self,
        _request: &cerebellum_computer::capture::BroadDisplayCaptureRequest,
    ) -> Result<cerebellum_computer::capture::CaptureArtifact, BackendError> {
        Err(BackendError::Capture("not served".into()))
    }

    fn begin_teardown(
        &mut self,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        Ok(cerebellum_computer::capture::BackendTeardownProgress::Complete)
    }

    fn poll_teardown(
        &mut self,
        _elapsed_ms: u64,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        Ok(cerebellum_computer::capture::BackendTeardownProgress::Complete)
    }
}

pub fn grant() -> ProcessGrant {
    ProcessGrant {
        pid: 4242,
        bundle_identity: TARGET_BUNDLE_ID.to_string(),
        process_generation_evidence: "1700000000000000".to_string(),
    }
}

pub fn management() -> Arc<ManagementPlane> {
    management_with(Arc::new(Fixed(TargetResolution::Resolved(grant()))))
}

pub fn management_with(resolver: Arc<dyn TargetResolver>) -> Arc<ManagementPlane> {
    Arc::new(ManagementPlane::new(resolver))
}

#[allow(dead_code)]
pub fn request() -> Value {
    json!({ "scope": "target_windows", "include_cursor": false })
}

pub async fn grant_lease<C: MonotonicClock>(
    management: &ManagementPlane,
    action_kind: ActionKind,
    clock: &C,
) {
    let (reply, _question) = management
        .open_target(GRANTEE, TARGET_BUNDLE_ID, action_kind, true, clock)
        .await;
    let ask_id = reply["ask_id"]
        .as_str()
        .expect("an ask is minted")
        .to_string();
    assert!(
        management
            .settle(
                &ask_id,
                Some(&json!({"decision": "allow_10_minutes"})),
                clock
            )
            .await,
        "the fixture lease settles"
    );
}

/// A management plane holding a live observing lease for the fixture target.
#[allow(dead_code)]
pub async fn leased_management<C: MonotonicClock>(clock: &C) -> Arc<ManagementPlane> {
    let management = management();
    grant_lease(&management, ActionKind::Observe, clock).await;
    management
}
