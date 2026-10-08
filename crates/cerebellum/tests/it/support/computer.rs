use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use cerebellum::computer_grants::{
    AppCode, AppIdentity, AppIdentityUnreadable, ConsentContext, GrantCaller, QuestionCarrier,
};
use cerebellum::elicit::AskOutcome;
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
use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::{
    DurableState, EffectClass, InMemoryJournalStorage, IoDiagnostic, IsolationClass, JournalConfig,
    JournalIdentity, JournalStorage, ObservabilityClass, Redactor, SeverityInputs, SeverityRecord,
    StorageError, ValidatedSeverityTaxonomy,
};
use serde_json::{json, Value};

pub const GRANTEE: &str = "pj-example";
pub const TARGET_BUNDLE_ID: &str = "com.apple.Safari";

/// Explicit startup readings for tests of behavior beyond permission admission.
/// Never borrow the TCC state of the developer running the suite.
pub fn live_permissions() -> cerebellum_computer::platform::PermissionLivenessReport {
    use cerebellum_computer::platform::*;
    PermissionLivenessReport::from_results(
        [
            PermissionService::Accessibility,
            PermissionService::ScreenRecording,
            PermissionService::PostEvent,
            PermissionService::InputMonitoring,
        ]
        .into_iter()
        .map(|service| PermissionProbeResult {
            service,
            liveness: PermissionLiveness::Live,
            responsible_process: "ck-cerebellum".into(),
            off_main: true,
        }),
    )
}

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
        witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
        principal: "prefrontal".into(),
        conversation_key: "conversation-1".into(),
        agent_project_id: "project-1".into(),
        session_kind: SessionKind::Primary,
        origin: Default::default(),
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

/// The same audit, over storage the caller keeps a handle to.
///
/// Exposed so a test can read the journal BACK -- cloning
/// `InMemoryJournalStorage` shares its state -- which is the only way to assert
/// what a record does NOT contain.
pub fn audit_with_storage<S: JournalStorage>(
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

    fn raise_format(
        &self,
        _format: cerebellum_core::format_floor::DurableFormat,
    ) -> Result<(), StorageError> {
        Ok(())
    }
}

/// The Team ID the fixture application is signed by.
#[allow(dead_code)]
pub const FIXTURE_TEAM: &str = "FIXTURE001";

/// A code-signing identity signed by `team`, with the designated requirement
/// such an application states: its identifier, and a leaf certificate issued
/// to that team.
#[allow(dead_code)]
pub fn team_identity(team: &str) -> AppIdentity {
    AppIdentity {
        team_id: Some(team.to_string()),
        designated_requirement: format!(
            "identifier \"{TARGET_BUNDLE_ID}\" and anchor apple generic and \
             certificate leaf[subject.OU] = \"{team}\""
        ),
        ad_hoc: false,
        apple_anchored: false,
    }
}

/// The code of a resolved process, with an injected identity in place of a
/// real signature. A requirement is satisfied exactly when it is the
/// identity's own designated requirement, which is how a different signer
/// fails a recorded one. Clones share the identity, so a test can replace
/// the application behind a bundle identity after a grant was made.
#[derive(Clone)]
pub struct InjectedCode(Arc<Mutex<Result<AppIdentity, AppIdentityUnreadable>>>);

#[allow(dead_code)]
impl InjectedCode {
    pub fn new(identity: Result<AppIdentity, AppIdentityUnreadable>) -> Self {
        Self(Arc::new(Mutex::new(identity)))
    }

    pub fn replace(&self, identity: Result<AppIdentity, AppIdentityUnreadable>) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = identity;
    }

    fn current(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

impl Default for InjectedCode {
    fn default() -> Self {
        Self::new(Ok(team_identity(FIXTURE_TEAM)))
    }
}

impl AppCode for InjectedCode {
    fn identity(&self) -> Result<AppIdentity, AppIdentityUnreadable> {
        self.current()
    }

    fn satisfies(&self, designated_requirement: &str) -> Result<bool, AppIdentityUnreadable> {
        self.current()
            .map(|identity| identity.designated_requirement == designated_requirement)
    }
}

/// A resolver that answers from a fixture instead of the window server, and
/// whose process is signed by the fixture team.
pub struct Fixed(pub TargetResolution);

impl TargetResolver for Fixed {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.0.clone()
    }

    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(InjectedCode::default())
    }
}

/// A resolver that answers from a fixture, whose process's signature is the
/// shared injected one.
#[allow(dead_code)]
pub struct FixedWithCode(pub TargetResolution, pub InjectedCode);

impl TargetResolver for FixedWithCode {
    fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
        self.0.clone()
    }

    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(self.1.clone())
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

    fn app_code(&self, _grant: &ProcessGrant) -> Arc<dyn AppCode> {
        Arc::new(InjectedCode::default())
    }
}

/// A backend that captures successfully, to prove what a real capture produces.
///
/// Its counterpart refuses everything, and a suite holding only that one cannot
/// reach the code that builds a result from pixels: every test ends at the
/// failure branch. That gap let an artifact built with no bytes and zero
/// dimensions ship, which custody refused on the first real capture.
#[allow(dead_code)]
/// Captures, then reports a window change old enough to make the next
/// enumeration incomplete.
///
/// The completeness signal is not a property a backend states; it is derived
/// from how long ago a window change was observed against the controller's
/// re-enumeration bound. So the only way to drive it from outside is to hand
/// back a change with a stale timestamp, which is what a real host does when
/// the window list moved while nobody was looking.
pub struct StaleReenumerationBackend {
    pub inner: CapturingBackend,
    pub change_observed_at_ms: u64,
    pub polls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl CaptureBackend for StaleReenumerationBackend {
    fn screen_recording_liveness(&self) -> cerebellum_computer::platform::PermissionLiveness {
        self.inner.screen_recording_liveness()
    }

    fn enumerate_windows(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        self.inner.enumerate_windows(target)
    }

    fn poll_window_change(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Option<cerebellum_computer::capture::WindowChange>, BackendError> {
        self.polls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(Some(cerebellum_computer::capture::WindowChange {
            kind: cerebellum_computer::capture::WindowChangeKind::Created,
            observed_at_ms: self.change_observed_at_ms,
        }))
    }

    fn capture_window(
        &mut self,
        request: &cerebellum_computer::capture::WindowCaptureRequest,
    ) -> Result<cerebellum_computer::capture::WindowCaptureFrame, BackendError> {
        self.inner.capture_window(request)
    }

    fn capture_display(
        &mut self,
        request: &cerebellum_computer::capture::BroadDisplayCaptureRequest,
    ) -> Result<cerebellum_computer::capture::CaptureArtifact, BackendError> {
        self.inner.capture_display(request)
    }

    fn begin_teardown(
        &mut self,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        self.inner.begin_teardown()
    }

    fn poll_teardown(
        &mut self,
        elapsed_ms: u64,
    ) -> Result<cerebellum_computer::capture::BackendTeardownProgress, BackendError> {
        self.inner.poll_teardown(elapsed_ms)
    }
}

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

/// The caller every fixture acts as: the conversation and agent of
/// [`identity`], with an identity the daemon did not attest.
#[allow(dead_code)]
pub fn caller() -> GrantCaller {
    GrantCaller {
        conversation_key: identity().conversation_key,
        agent_project_id: GRANTEE.to_string(),
        durable_identity_attested: false,
    }
}

/// A consent context that can ask nobody. Enough for a caller that already
/// holds its grant, or that expects to be refused before any question.
#[allow(dead_code)]
pub fn no_relay() -> ConsentContext {
    ConsentContext::without_carrier(caller())
}

/// A consent context that asks through `carrier`.
#[allow(dead_code)]
pub fn relayed(carrier: &ScriptedCarrier) -> ConsentContext {
    let (_drain, drain) = tokio::sync::watch::channel(false);
    // The sender is leaked on purpose: a dropped sender would read as a closed
    // drain signal, which a fixture has no reason to model.
    std::mem::forget(_drain);
    ConsentContext::new(
        caller(),
        Some(Arc::new(carrier.clone()) as Arc<dyn QuestionCarrier>),
        Arc::new(cerebellum::computer_grants::AlwaysOpenRoute),
        drain,
        None,
    )
}

/// A carrier whose answers the test scripts.
///
/// Each question put through it is recorded. It is answered by the next queued
/// answer, if one was queued, or else waits until the test answers it with
/// [`ScriptedCarrier::answer_next`].
#[derive(Clone, Default)]
pub struct ScriptedCarrier {
    state: Arc<Mutex<ScriptState>>,
}

#[derive(Default)]
struct ScriptState {
    queued: std::collections::VecDeque<AskOutcome>,
    waiting: std::collections::VecDeque<tokio::sync::oneshot::Sender<AskOutcome>>,
    questions: Vec<Value>,
}

#[allow(dead_code)]
impl ScriptedCarrier {
    /// A carrier that answers each question, in order, with these decisions.
    pub fn answering(decisions: &[&str]) -> Self {
        let carrier = Self::default();
        for decision in decisions {
            carrier.queue(AskOutcome::Answered(json!({"decision": decision})));
        }
        carrier
    }

    pub fn queue(&self, outcome: AskOutcome) {
        self.state.lock().unwrap().queued.push_back(outcome);
    }

    /// Answer the oldest question still waiting. False when none is.
    pub fn answer_next(&self, outcome: AskOutcome) -> bool {
        let waiting = self.state.lock().unwrap().waiting.pop_front();
        waiting.is_some_and(|sender| sender.send(outcome).is_ok())
    }

    /// Every question put so far, in order.
    pub fn questions(&self) -> Vec<Value> {
        self.state.lock().unwrap().questions.clone()
    }
}

impl QuestionCarrier for ScriptedCarrier {
    fn put(
        &self,
        question: Value,
        _deadline: std::time::Duration,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = AskOutcome> + Send>> {
        let mut state = self.state.lock().unwrap();
        state.questions.push(question);
        if let Some(answer) = state.queued.pop_front() {
            return Box::pin(async move { answer });
        }
        let (sender, receiver) = tokio::sync::oneshot::channel();
        state.waiting.push_back(sender);
        Box::pin(async move { receiver.await.unwrap_or(AskOutcome::NoAnswer) })
    }
}

/// Hold the fixture application's app grant for the fixture conversation, by
/// answering its question "allow for this conversation".
pub async fn grant_app(management: &ManagementPlane) {
    let carrier = ScriptedCarrier::answering(&["allow_conversation"]);
    management
        .admit_app(
            TARGET_BUNDLE_ID,
            &relayed(&carrier),
            &cerebellum::CancelHandle::pending(),
        )
        .await
        .expect("the fixture grant is answered allow_conversation");
}

/// A management plane holding the fixture application's app grant.
#[allow(dead_code)]
pub async fn granted_management() -> Arc<ManagementPlane> {
    let management = management();
    grant_app(&management).await;
    management
}

// ---------------------------------------------------------------------------
// A desk of fixture elements the element actions and keystroke checks act on
// ---------------------------------------------------------------------------

use cerebellum_computer::app_state::source::{
    AppStateReadError, AppStateSource, ElementActionError, ElementFacts, ElementHandle,
    FixtureElementToken, HitScope, RawAppState, RawElement, ReadBounds, TextAttribute,
};

/// One element's behaviour on the desk.
#[derive(Debug, Clone, Default)]
pub struct DeskElement {
    pub facts: ElementFacts,
    pub value: Option<String>,
    /// `(start, length)` in UTF-16 code units.
    pub selection: Option<(usize, usize)>,
    /// Values the next reads return, in order, before `value` is read again.
    /// How a test makes a value change between two reads without a write.
    pub readbacks: std::collections::VecDeque<Option<String>>,
    /// Whether a write changes `value`. An application that accepts a write
    /// and keeps its old value is how a read-back mismatch is produced.
    pub applies_writes: bool,
}

/// What a hit test finds: an element token and the pid that owns it.
pub type DeskHit = (u64, Option<u32>);

/// What focus the desk reports for the target application.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeskFocus {
    Nothing,
    Unreadable,
    Element(u64),
}

#[derive(Debug)]
pub struct DeskState {
    pub cursor_frame: Option<[f64; 4]>,
    pub cursor_visible: bool,
    pub roots: Vec<RawElement>,
    /// Swapped in for `roots` by the first press or write, so the diff that
    /// follows has something to report.
    pub after_action: Option<Vec<RawElement>>,
    /// The application's focus after the first press or write, the way
    /// pressing a button can move focus to what it opened.
    pub focus_after_action: Option<DeskFocus>,
    pub focused_in_tree: Option<u64>,
    pub elements: std::collections::HashMap<u64, DeskElement>,
    pub focus: DeskFocus,
    pub frontmost: Option<u32>,
    /// What an application-scoped hit test finds, and what a system-wide one
    /// finds: an element token and the pid that owns it.
    pub application_hit: Option<(u64, Option<u32>)>,
    pub system_wide_hit: Option<(u64, Option<u32>)>,
    /// System-wide hits at particular desktop points, which take the place
    /// of `system_wide_hit` there. How a test puts two applications under
    /// the two ends of one drag.
    pub system_wide_hits_at: Vec<((f64, f64), DeskHit)>,
    pub presses: Vec<u64>,
    pub writes: Vec<(u64, TextAttribute)>,
    pub hit_scopes: Vec<HitScope>,
    pub focus_reads: usize,
    /// The target application's focused window: a token and its title.
    pub window: Option<(u64, Option<String>)>,
    /// Every key press, click and scroll the desk's input count has taken,
    /// with the pid that sent it (0 for the person's hardware) and when it
    /// was counted. Like the HID system's table, the count takes this
    /// module's own posts as well as the person's.
    pub input: Vec<(i64, std::time::Instant)>,
    pub hardware_coverage: Option<std::time::Instant>,
    /// The running applications `list_apps` lists and a target given by
    /// name is matched against; `None` when the list cannot be read.
    pub running: Option<Vec<cerebellum_computer::app_state::source::RunningApp>>,
    pub installed: cerebellum_computer::app_state::source::InstalledApps,
    pub signature: Option<cerebellum_computer::app_state::source::BundleSignature>,
    pub opens: Vec<cerebellum_computer::app_state::source::OpenAppBounds>,
    pub url_schemes: Vec<String>,
    pub opened_urls: Vec<String>,
    pub opened: cerebellum_computer::app_state::source::OpenedApp,
}

/// A fixture application: its tree, its elements' facts and text, its focus,
/// and which application is frontmost. Records every press, write and hit
/// test so a test can assert what was done rather than what was replied.
#[derive(Debug, Clone)]
pub struct Desk(pub Arc<Mutex<DeskState>>);

#[allow(dead_code)]
impl Desk {
    pub fn new(roots: Vec<RawElement>) -> Self {
        Self(Arc::new(Mutex::new(DeskState {
            cursor_frame: None,
            cursor_visible: false,
            roots,
            after_action: None,
            focus_after_action: None,
            focused_in_tree: None,
            elements: std::collections::HashMap::new(),
            focus: DeskFocus::Nothing,
            frontmost: Some(grant().pid),
            application_hit: None,
            system_wide_hit: None,
            system_wide_hits_at: Vec::new(),
            presses: Vec::new(),
            writes: Vec::new(),
            hit_scopes: Vec::new(),
            focus_reads: 0,
            window: None,
            input: Vec::new(),
            hardware_coverage: Some(std::time::Instant::now()),
            installed: cerebellum_computer::app_state::source::InstalledApps {
                apps: Vec::new(),
                complete: true,
            },
            signature: Some(cerebellum_computer::app_state::source::BundleSignature {
                signed: true,
                ad_hoc: false,
                team_id: Some(FIXTURE_TEAM.into()),
                designated_requirement: Some(team_identity(FIXTURE_TEAM).designated_requirement),
                apple_anchored: false,
            }),
            opens: Vec::new(),
            url_schemes: Vec::new(),
            opened_urls: Vec::new(),
            opened: cerebellum_computer::app_state::source::OpenedApp {
                pid: grant().pid,
                already_running: false,
                has_window: true,
                frontmost: false,
            },
            running: Some(vec![cerebellum_computer::app_state::source::RunningApp {
                name: "Safari".into(),
                bundle_identity: grant().bundle_identity,
                pid: grant().pid,
                frontmost: true,
            }]),
        })))
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, DeskState> {
        self.0.lock().unwrap()
    }

    pub fn with_element(self, token: u64, element: DeskElement) -> Self {
        self.state().elements.insert(token, element);
        self
    }

    pub fn source(&self) -> Arc<dyn AppStateSource> {
        Arc::new(self.clone())
    }
}

fn token_of(handle: &ElementHandle) -> Option<u64> {
    handle
        .as_any()
        .downcast_ref::<FixtureElementToken>()
        .map(|token| token.0)
}

fn fixture_handle(token: u64) -> ElementHandle {
    Arc::new(FixtureElementToken(token))
}

fn utf16_byte_offset(text: &str, utf16: usize) -> usize {
    let mut units = 0;
    for (byte, character) in text.char_indices() {
        if units >= utf16 {
            return byte;
        }
        units += character.len_utf16();
    }
    text.len()
}

impl AppStateSource for Desk {
    fn cursor_frame(&self, _: &ElementHandle) -> Option<[f64; 4]> {
        self.state().cursor_frame
    }

    fn visible_cursor_point(&self, _: &ProcessGrant, point: Option<[f64; 2]>) -> Option<[f64; 2]> {
        self.state()
            .cursor_visible
            .then_some(point.unwrap_or([112.0, 62.0]))
    }
    fn read_app_state(
        &self,
        _target: &ProcessGrant,
        _bounds: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        let state = self.state();
        Ok(RawAppState {
            roots: state.roots.clone(),
            focused: state.focused_in_tree.map(fixture_handle),
            unreadable_subtrees: 0,
            read_bound_reached: false,
        })
    }

    fn element_facts(&self, element: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        let token = token_of(element).ok_or(ElementActionError::Gone)?;
        self.state()
            .elements
            .get(&token)
            .map(|element| element.facts.clone())
            .ok_or(ElementActionError::Gone)
    }

    fn press(&self, element: &ElementHandle) -> Result<(), ElementActionError> {
        let token = token_of(element).ok_or(ElementActionError::Gone)?;
        let mut state = self.state();
        state.presses.push(token);
        if let Some(after) = state.after_action.take() {
            state.roots = after;
        }
        if let Some(focus) = state.focus_after_action.take() {
            state.focus = focus;
        }
        Ok(())
    }

    fn text_value(&self, element: &ElementHandle) -> Result<Option<String>, ElementActionError> {
        let token = token_of(element).ok_or(ElementActionError::Gone)?;
        let mut state = self.state();
        let element = state
            .elements
            .get_mut(&token)
            .ok_or(ElementActionError::Gone)?;
        if let Some(value) = element.readbacks.pop_front() {
            return Ok(value);
        }
        Ok(element.value.clone())
    }

    fn selected_range(
        &self,
        element: &ElementHandle,
    ) -> Result<Option<(usize, usize)>, ElementActionError> {
        let token = token_of(element).ok_or(ElementActionError::Gone)?;
        Ok(self
            .state()
            .elements
            .get(&token)
            .ok_or(ElementActionError::Gone)?
            .selection)
    }

    fn write_text(
        &self,
        element: &ElementHandle,
        attribute: TextAttribute,
        text: &str,
    ) -> Result<(), ElementActionError> {
        let token = token_of(element).ok_or(ElementActionError::Gone)?;
        let mut state = self.state();
        state.writes.push((token, attribute));
        if let Some(after) = state.after_action.take() {
            state.roots = after;
        }
        if let Some(focus) = state.focus_after_action.take() {
            state.focus = focus;
        }
        let element = state
            .elements
            .get_mut(&token)
            .ok_or(ElementActionError::Gone)?;
        if element.applies_writes {
            element.value = Some(match attribute {
                TextAttribute::Value => text.to_string(),
                TextAttribute::SelectedText => {
                    let before = element.value.clone().unwrap_or_default();
                    let (start, length) = element.selection.unwrap_or((0, 0));
                    let from = utf16_byte_offset(&before, start);
                    let to = utf16_byte_offset(&before, start + length);
                    format!("{}{}{}", &before[..from], text, &before[to..])
                }
            });
        }
        Ok(())
    }

    fn element_at(
        &self,
        scope: HitScope,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        let mut state = self.state();
        state.hit_scopes.push(scope);
        let hit = match scope {
            HitScope::Application { .. } => state.application_hit,
            HitScope::SystemWide => state
                .system_wide_hits_at
                .iter()
                .find(|(at, _)| (at.0 - point.0).abs() < 0.5 && (at.1 - point.1).abs() < 0.5)
                .map(|(_, hit)| *hit)
                .or(state.system_wide_hit),
        };
        Ok(hit.map(|(token, pid)| (fixture_handle(token), pid)))
    }

    fn focused_element(
        &self,
        _target: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        let mut state = self.state();
        state.focus_reads += 1;
        match state.focus {
            DeskFocus::Nothing => Ok(None),
            DeskFocus::Unreadable => Err(ElementActionError::Failed),
            DeskFocus::Element(token) => Ok(Some(fixture_handle(token))),
        }
    }

    fn frontmost_pid(&self) -> Option<u32> {
        self.state().frontmost
    }

    fn focused_window(
        &self,
        _target: &ProcessGrant,
    ) -> Result<Option<cerebellum_computer::app_state::source::WindowMark>, ElementActionError>
    {
        Ok(self.state().window.clone().map(|(token, title)| {
            cerebellum_computer::app_state::source::WindowMark {
                handle: fixture_handle(token),
                title,
            }
        }))
    }

    fn hardware_input(
        &self,
        _target: &ProcessGrant,
    ) -> Result<(std::time::Instant, Option<std::time::Instant>), ElementActionError> {
        let state = self.state();
        let since = state.hardware_coverage.ok_or(ElementActionError::Failed)?;
        let latest = state
            .input
            .iter()
            .filter(|(pid, _)| *pid == 0)
            .map(|(_, at)| *at)
            .max();
        Ok((since, latest))
    }

    /// The age of the newest counted input; an input counted for a moment
    /// still ahead reads as arriving now.
    fn time_since_last_input(&self) -> Option<std::time::Duration> {
        let latest = self.state().input.iter().map(|(_, at)| *at).max()?;
        Some(std::time::Instant::now().saturating_duration_since(latest))
    }

    fn installed_apps(
        &self,
        _timeout: std::time::Duration,
    ) -> cerebellum_computer::app_state::source::InstalledApps {
        self.state().installed.clone()
    }

    fn bundle_signature(
        &self,
        _app: &cerebellum_computer::app_state::source::InstalledApp,
    ) -> Result<cerebellum_computer::app_state::source::BundleSignature, AppStateReadError> {
        self.state()
            .signature
            .clone()
            .ok_or(AppStateReadError::Unreadable)
    }

    fn bundle_satisfies(
        &self,
        _app: &cerebellum_computer::app_state::source::InstalledApp,
        requirement: &str,
    ) -> bool {
        self.state().signature.as_ref().is_some_and(|signature| {
            signature.signed
                && !signature.ad_hoc
                && signature.designated_requirement.as_deref() == Some(requirement)
        })
    }

    fn open_app(
        &self,
        _app: &cerebellum_computer::app_state::source::InstalledApp,
        bounds: cerebellum_computer::app_state::source::OpenAppBounds,
    ) -> Result<cerebellum_computer::app_state::source::OpenedApp, AppStateReadError> {
        let mut state = self.state();
        state.opens.push(bounds);
        Ok(state.opened)
    }

    fn bundle_url_schemes(
        &self,
        _: &cerebellum_computer::app_state::source::InstalledApp,
    ) -> Result<Vec<String>, AppStateReadError> {
        Ok(self.state().url_schemes.clone())
    }

    fn open_app_url(
        &self,
        app: &cerebellum_computer::app_state::source::InstalledApp,
        url: &str,
        bounds: cerebellum_computer::app_state::source::OpenAppBounds,
    ) -> Result<cerebellum_computer::app_state::source::OpenedApp, AppStateReadError> {
        self.state().opened_urls.push(url.to_owned());
        self.open_app(app, bounds)
    }

    fn running_apps(
        &self,
    ) -> Result<Vec<cerebellum_computer::app_state::source::RunningApp>, AppStateReadError> {
        self.state()
            .running
            .clone()
            .ok_or(AppStateReadError::Unreadable)
    }
}

/// Facts for an ordinary element: the given role, owned by the fixture
/// process, offering the given actions.
#[allow(dead_code)]
pub fn facts(role: &str, actions: &[&str]) -> ElementFacts {
    ElementFacts {
        pid: Some(grant().pid),
        role: Some(role.to_string()),
        actions: actions.iter().map(|action| action.to_string()).collect(),
        ..ElementFacts::default()
    }
}

/// A plain text field focused in the fixture application, whose value
/// follows writes: the focus every keystroke test that is not about the
/// secure-field check starts from.
#[allow(dead_code)]
pub fn focused_text_desk() -> Desk {
    let desk = Desk::new(vec![RawElement::fixture(1, "AXWindow")
        .titled("Fixture")
        .with_children(vec![RawElement::fixture(2, "AXTextField")])])
    .with_element(
        2,
        DeskElement {
            facts: facts("AXTextField", &[]),
            value: Some(String::new()),
            applies_writes: true,
            ..DeskElement::default()
        },
    );
    desk.state().focus = DeskFocus::Element(2);
    desk
}
