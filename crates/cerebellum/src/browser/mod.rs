//! This module implements the six browser capabilities exposed by the browser plane.
//!
//! This module integrates route admission, journal and context interfaces, CDP
//! transport, and browser geometry, extraction, and screenshot primitives.
//! Browser-specific state is kept behind a per-context lane so CDP operations
//! and final verification cannot interleave across invocations.

pub mod extraction;
pub mod geometry;
pub mod navigation;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cerebellum_core::journal::{
    journal_data_path, CallerRefusalHistory, RefusalRing, RefusalRingConfig,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::authorization::{AuthorizationRequest, GrantStore, HazardClass, Severity};
use crate::coordinate::{
    capture_screenshot, map_pixel_to_css, validate_png_base64_dimensions, CoordinateError,
    InvalidCoordinatesReason, ScreenshotPayload, TransformInputs, ViewportObservation,
    MAX_ENCODED_PNG_BYTES,
};
use crate::journal;
use crate::journal::reservation::{
    CompletedResult, DispatchCommitmentToken, DispatchMaterial, FinalContextAssociation,
    RejectionMaterial, ReservationHandle,
};
use crate::journal::store::JournalStore;
use crate::journal::{
    Action as JournalAction, Capability as JournalCapability, GoverningObservation, GrantDecision,
    JournalError, JournalIdentity, JournalReasonCode, Outcome, SessionKind as JournalSessionKind,
};
use crate::snapshot_store::{
    self, AxRecord, BrowserSnapshotStore, DocumentEpoch, DocumentTransition, SameDocumentChange,
    SnapshotError, SnapshotKind, TextSnapshot, AX_SCHEMA, DOM_SCHEMA, MAX_REFS,
};
use cerebellum_core::identity::{RouteIdentity, SessionKind};

pub const NAVIGATE: &str = "browser.navigate";
pub const SNAPSHOT: &str = "browser.snapshot";
pub const CLICK: &str = "browser.click";
pub const SCREENSHOT: &str = "browser.screenshot";
pub const CLICK_POINT: &str = "browser.click_point";
pub const WAIT_FOR: &str = "browser.wait_for";
pub const ALL_TOOLS: [&str; 6] = [NAVIGATE, SNAPSHOT, CLICK, SCREENSHOT, CLICK_POINT, WAIT_FOR];

/// Whether a browser capability has a working module-wire dispatch route.
///
/// Deliberately admit only operations with working wire dispatch routes. The
/// omitted operations once returned `outcome: ok` with a fabricated `url_final`
/// even when no browser process existed.
pub fn has_wire_dispatch_route(name: &str) -> bool {
    matches!(name, NAVIGATE | SNAPSHOT | CLICK | SCREENSHOT)
}

pub const SETTLEMENT_MS: u64 = 30_000;
pub const QUIET_MS: u64 = 500;
const DEFAULT_READ_PAGE_MAX_BYTES: u64 = 5_000;
const DEFAULT_REFUSAL_RECORDS_PER_CALLER: usize = 64;
const BROWSER_REFUSAL_RING_FILE: &str = "browser-refusals.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserCapability {
    Navigate,
    Snapshot,
    Click,
    Screenshot,
    ClickPoint,
    WaitFor,
}
impl BrowserCapability {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Navigate => NAVIGATE,
            Self::Snapshot => SNAPSHOT,
            Self::Click => CLICK,
            Self::Screenshot => SCREENSHOT,
            Self::ClickPoint => CLICK_POINT,
            Self::WaitFor => WAIT_FOR,
        }
    }
    pub const fn is_unfenceable(self) -> bool {
        matches!(self, Self::Navigate | Self::Click | Self::ClickPoint)
    }
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            NAVIGATE => Self::Navigate,
            SNAPSHOT => Self::Snapshot,
            CLICK => Self::Click,
            SCREENSHOT => Self::Screenshot,
            CLICK_POINT => Self::ClickPoint,
            WAIT_FOR => Self::WaitFor,
            _ => return None,
        })
    }
}

/// Typed authorization decisions retained by the browser refusal ring.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotRefusalReason {
    NoGrant,
    OriginScope,
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserError {
    InvalidRequest {
        field: String,
        reason_code: &'static str,
    },
    NoSession,
    BrowserLaunchPending,
    StaleSnapshot {
        reason_code: &'static str,
    },
    RefNotFound {
        reference: String,
    },
    RefAmbiguous {
        candidate_count: usize,
    },
    ElementIntercepted,
    OutsideViewportAfterScroll {
        refusal: crate::browser_session::ViewportRefusal,
    },
    PointOutsideViewport {
        refusal: crate::browser_session::ViewportRefusal,
    },
    InvalidCoordinates {
        reason: InvalidCoordinatesReason,
    },
    ImageTooLarge {
        bytes: usize,
        bound_bytes: usize,
    },
    AuthorizationDenied {
        reason: &'static str,
    },
    HazardNotDisclosed {
        missing: HazardClass,
    },
    NavigationPolicyRejected {
        reason_code: &'static str,
    },
    NotSettled {
        url_final: Option<String>,
        lifecycle: Vec<String>,
        inflight_count: u64,
        deadline_ms: u64,
    },
    BrowserCrashed,
    Internal {
        reason_code: JournalReasonCode,
    },
}

impl BrowserError {
    fn outcome(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => "invalid_request",
            Self::NoSession => "no_session",
            Self::BrowserLaunchPending => "browser_launch_pending",
            Self::StaleSnapshot { .. } => "stale_snapshot",
            Self::RefNotFound { .. } => "ref_not_found",
            Self::RefAmbiguous { .. } => "ref_ambiguous",
            Self::ElementIntercepted => "element_intercepted",
            Self::OutsideViewportAfterScroll { .. } => "outside_viewport_after_scroll",
            Self::PointOutsideViewport { .. } => "point_outside_viewport",
            Self::InvalidCoordinates { .. } => "invalid_coordinates",
            Self::ImageTooLarge { .. } => "image_too_large",
            Self::AuthorizationDenied { .. } => "authorization_denied",
            Self::HazardNotDisclosed { .. } => "hazard_not_disclosed",
            Self::NavigationPolicyRejected { .. } => "navigation_policy_rejected",
            Self::NotSettled { .. } => "not_settled",
            Self::BrowserCrashed => "browser_crashed",
            Self::Internal { .. } => "internal_error",
        }
    }
    /// Tell a caller which action can change this refusal, or explicitly when none exists.
    fn remedy(&self) -> &'static str {
        match self {
            Self::InvalidRequest { .. } => {
                "correct detail.field according to detail.reason_code, then resubmit the request"
            }
            Self::NoSession => "call browser.launch, then retry the browser action",
            Self::BrowserLaunchPending => {
                "poll browser.status until the session is ready, then retry the browser action"
            }
            Self::StaleSnapshot { .. } => {
                "call browser.snapshot again and use only its new snapshot_id and refs"
            }
            Self::RefNotFound { .. } => {
                "choose a ref listed in the snapshot identified by snapshot_id"
            }
            Self::RefAmbiguous { .. } => {
                "take a fresh browser.snapshot and choose a ref that identifies exactly one current element"
            }
            Self::ElementIntercepted => {
                "take a fresh browser.snapshot and choose a ref that currently exposes a clickable position"
            }
            Self::OutsideViewportAfterScroll { .. } => {
                "take a fresh browser.snapshot and choose a ref whose resolved point can enter the visual viewport"
            }
            Self::PointOutsideViewport { .. } => {
                "call browser.screenshot again and choose a point inside its current visual viewport"
            }
            Self::InvalidCoordinates { reason } => reason.remedy(),
            Self::ImageTooLarge { .. } => {
                "use browser.snapshot for a text observation, or reduce the viewport before capturing another image"
            }
            Self::AuthorizationDenied { .. } => {
                "call browser.open_grant to mint a grant covering this action, then retry"
            }
            Self::HazardNotDisclosed { .. } => {
                "call browser.open_grant to mint a grant that discloses detail.missing_hazard, then retry"
            }
            Self::NavigationPolicyRejected { .. } => {
                "navigate to an http or https URL allowed by browser policy"
            }
            Self::NotSettled { .. } => {
                "call browser.snapshot to re-observe the page before depending on its current state"
            }
            Self::BrowserCrashed => {
                "no caller remedy in v1: this module does not reconnect a crashed browser"
            }
            Self::Internal { .. } => {
                "report this module failure with detail.reason_code and do not assume the action completed"
            }
        }
    }

    fn detail(&self) -> Option<Value> {
        Some(match self {
            Self::InvalidRequest { field, reason_code } => {
                json!({"field":field,"reason_code":reason_code})
            }
            Self::StaleSnapshot { reason_code } => json!({"reason_code":reason_code}),
            Self::RefNotFound { reference } => json!({"ref":reference}),
            Self::RefAmbiguous { candidate_count } => json!({"candidates":candidate_count}),
            Self::InvalidCoordinates { reason } => {
                json!({"reason_code":reason.reason_code()})
            }
            Self::ImageTooLarge { bytes, bound_bytes } => {
                json!({"bytes":bytes,"bound_bytes":bound_bytes})
            }
            Self::AuthorizationDenied { reason } => json!({"reason":reason}),
            Self::HazardNotDisclosed { missing } => {
                json!({"reason":"hazard_not_disclosed","missing_hazard":missing.as_str()})
            }
            Self::NotSettled {
                url_final,
                lifecycle,
                inflight_count,
                deadline_ms,
            } => {
                json!({"url_final":url_final,"lifecycle":lifecycle,"inflight_count":inflight_count,"deadline_ms":deadline_ms})
            }
            Self::NavigationPolicyRejected { reason_code } => json!({"reason_code":reason_code}),
            Self::Internal { reason_code } => json!({"reason_code":reason_code.as_str()}),
            Self::NoSession => {
                json!({"reason_code":"no_session","reason":"no browser session is open"})
            }
            Self::BrowserLaunchPending => json!({"reason_code":"browser_launch_pending"}),
            Self::ElementIntercepted => json!({}),
            Self::OutsideViewportAfterScroll { refusal } => {
                viewport_refusal_detail("outside_viewport_after_scroll", *refusal)
            }
            Self::PointOutsideViewport { refusal } => {
                viewport_refusal_detail("point_outside_viewport", *refusal)
            }
            Self::BrowserCrashed => json!({"reason_code":"browser_crashed"}),
        })
    }
}

fn viewport_refusal_detail(
    reason_code: &'static str,
    refusal: crate::browser_session::ViewportRefusal,
) -> Value {
    json!({
        "reason_code": reason_code,
        "point": {
            "x_css": refusal.position.x_css,
            "y_css": refusal.position.y_css,
        },
        "viewport": {
            "x_css": refusal.viewport.x_input_css,
            "y_css": refusal.viewport.y_input_css,
            "width_css": refusal.viewport.width_input_css,
            "height_css": refusal.viewport.height_input_css,
        },
    })
}

impl fmt::Display for BrowserError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.outcome())
    }
}
impl std::error::Error for BrowserError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserContextResult {
    pub profile_uuid: Option<String>,
    pub profile_name: Option<String>,
    pub session_kind_effective: &'static str,
    pub profile_disposition: &'static str,
}

impl BrowserContextResult {
    pub fn from_identity(identity: &RouteIdentity) -> Self {
        let (kind, disposition) = match identity.session_kind {
            SessionKind::Primary => ("primary", "durable"),
            SessionKind::Subagent => ("subagent", "disposable"),
            SessionKind::Ephemeral => ("ephemeral", "none"),
        };
        Self {
            profile_uuid: None,
            profile_name: (identity.session_kind != SessionKind::Ephemeral)
                .then(|| "default".to_string()),
            session_kind_effective: kind,
            profile_disposition: disposition,
        }
    }
    fn json(&self) -> Value {
        json!({"profile_uuid":self.profile_uuid,"profile_name":self.profile_name,"session_kind_effective":self.session_kind_effective,"profile_disposition":self.profile_disposition})
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tracker {
    pub url_final: Option<String>,
    pub lifecycle: Vec<String>,
    pub inflight_count: u64,
    pub settled: bool,
    pub load_observed: bool,
    quiet_since: Option<Instant>,
}
impl Tracker {
    pub fn token(&mut self, token: impl Into<String>) {
        self.lifecycle.push(token.into());
    }
    pub fn request_started(&mut self) {
        self.inflight_count = self.inflight_count.saturating_add(1);
        self.quiet_since = None;
        self.settled = false;
    }
    pub fn request_finished(&mut self, now: Instant) {
        self.inflight_count = self.inflight_count.saturating_sub(1);
        if self.inflight_count == 0 {
            self.quiet_since = Some(now);
        }
    }
    pub fn load(&mut self, now: Instant) {
        self.load_observed = true;
        self.token("load");
        if self.inflight_count == 0 {
            self.quiet_since = Some(now);
        }
    }
    pub fn poll_settlement(&mut self, now: Instant) -> bool {
        if self.load_observed
            && self.inflight_count == 0
            && self
                .quiet_since
                .is_some_and(|since| now.duration_since(since) >= Duration::from_millis(QUIET_MS))
        {
            if !self.settled {
                self.token("network_quiet");
            }
            self.settled = true;
        }
        self.settled
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LateEvent {
    DownloadBlocked,
    JsDialogDismissed,
    NavigationPolicyRejected { reason_code: String },
    AuthorizationDenied { reason: String },
}
impl LateEvent {
    fn outcome(&self) -> &'static str {
        match self {
            Self::DownloadBlocked => "unsupported_download",
            Self::JsDialogDismissed => "unsupported_js_dialog",
            Self::NavigationPolicyRejected { .. } => "navigation_policy_rejected",
            Self::AuthorizationDenied { .. } => "authorization_denied",
        }
    }

    fn remedy(&self) -> &'static str {
        match self {
            Self::DownloadBlocked => "choose an in-page action that does not start a download",
            Self::JsDialogDismissed => {
                "call browser.snapshot and continue from the page state after the dialog was dismissed"
            }
            Self::NavigationPolicyRejected { .. } => {
                "navigate to an http or https URL allowed by browser policy"
            }
            Self::AuthorizationDenied { .. } => {
                "call browser.open_grant to mint a grant covering this action, then retry"
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Reserve,
    FinalizeRejected,
    CommitDispatched,
    FinalizeDispatched,
    CdpObserve,
    CdpNavigate,
    CdpInputPress,
    CdpInputRelease,
    CloseContext,
}

/// One invocation-bound handle into the plane's journal store.
///
/// The reservation and commitment stay together so finalization cannot address
/// another invocation's entry. The journal store itself belongs to the plane.
struct JournalInvocation {
    browser_capability: BrowserCapability,
    capability: JournalCapability,
    handle: Option<ReservationHandle>,
    token: Option<DispatchCommitmentToken>,
    terminal: bool,
}

impl JournalInvocation {
    fn new(browser_capability: BrowserCapability) -> Self {
        Self {
            browser_capability,
            capability: journal_capability(browser_capability),
            handle: None,
            token: None,
            terminal: false,
        }
    }

    fn reserve(
        &mut self,
        store: &mut JournalStore,
        identity: JournalIdentity,
    ) -> Result<ReservationHandle, JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        if let Some(handle) = self.handle {
            return Ok(handle);
        }
        let handle = store.reserve(identity, self.capability)?;
        self.handle = Some(handle);
        Ok(handle)
    }

    fn commit_dispatched(
        &mut self,
        store: &mut JournalStore,
        material: DispatchMaterial,
    ) -> Result<DispatchCommitmentToken, JournalError> {
        let handle = self.handle.ok_or_else(JournalError::internal_failure)?;
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let token = store.commit_dispatched(handle, &material)?;
        self.token = Some(token);
        Ok(token)
    }

    fn finalize_rejected(
        &mut self,
        store: &mut JournalStore,
        material: RejectionMaterial,
    ) -> Result<(), JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let handle = self.handle.ok_or_else(JournalError::internal_failure)?;
        store.finalize_rejected(handle, &material).map(|_| {
            self.terminal = true;
        })
    }

    fn finalize_dispatched(
        &mut self,
        store: &mut JournalStore,
        context: FinalContextAssociation,
        result: CompletedResult,
    ) -> Result<(), JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let token = self.token.ok_or_else(JournalError::internal_failure)?;
        store
            .finalize_dispatched(token, &context, &result)
            .map(|_| {
                self.terminal = true;
            })
    }
}

/// Build the journal identity projection from the immutable route identity facts
/// established during route binding.
pub fn journal_identity(identity: &RouteIdentity) -> JournalIdentity {
    JournalIdentity {
        principal: "first_party".to_string(),
        conversation_key: identity.conversation_key.clone(),
        agent_project_id: identity.agent_project_id.clone(),
        session_kind: match identity.session_kind {
            SessionKind::Primary => JournalSessionKind::Primary,
            SessionKind::Subagent => JournalSessionKind::Subagent,
            SessionKind::Ephemeral => JournalSessionKind::Ephemeral,
        },
        profile_uuid: None,
        profile_name: (identity.session_kind != SessionKind::Ephemeral)
            .then(|| "default".to_string()),
    }
}

/// The action a dispatch performed, or None for an observation.
///
/// Observations return None rather than a placeholder: a snapshot performs no
/// navigation, and naming one would put a page load in the record of a read.
/// What a read is worth recording -- which page, when, under whose grant -- is
/// carried by the capability and identity beside this, not by an invented
/// action.
pub fn journal_action(capability: JournalCapability) -> Option<JournalAction> {
    Some(match capability {
        JournalCapability::Navigate => JournalAction::Navigate {
            url_redacted: "https://redacted.invalid".to_string(),
            wait: journal::NavigateWait::None,
        },
        JournalCapability::Click => JournalAction::Click {
            reference: "e1".to_string(),
            snapshot_id: "00000000000000000000000000000000".to_string(),
        },
        JournalCapability::ClickPoint => JournalAction::ClickPoint {
            snapshot_id: "00000000000000000000000000000000".to_string(),
            x_px: 0,
            y_px: 0,
        },
        JournalCapability::Type => JournalAction::Type {
            reference: "e1".to_string(),
            snapshot_id: "00000000000000000000000000000000".to_string(),
            text_bytes_utf8: 0,
            replace: false,
        },
        JournalCapability::Snapshot
        | JournalCapability::Screenshot
        | JournalCapability::WaitFor => return None,
    })
}

pub fn rejection_material(outcome: Outcome, detail: Value) -> RejectionMaterial {
    RejectionMaterial {
        intent_redacted: None,
        requested_severity: None,
        effective_severity: None,
        grant_decision: GrantDecision::not_reached(),
        governing_observation: GoverningObservation::observation_not_required(),
        action: None,
        locator: None,
        snapshot_ids: Vec::new(),
        outcome,
        detail,
    }
}

#[derive(Debug)]
struct ContextState {
    identity: RouteIdentity,
    epoch: DocumentEpoch,
    snapshots: BrowserSnapshotStore,
    tracker: Tracker,
    ended: bool,
    crashed: bool,
    next_snapshot_seed: u64,
}
impl ContextState {
    fn new(identity: RouteIdentity) -> Self {
        Self {
            identity,
            epoch: DocumentEpoch::new(),
            snapshots: BrowserSnapshotStore::new(8).expect("positive retention"),
            tracker: Tracker::default(),
            ended: false,
            crashed: false,
            next_snapshot_seed: 0,
        }
    }
    fn snapshot_id(&mut self, kind: SnapshotKind) -> String {
        self.next_snapshot_seed = self.next_snapshot_seed.saturating_add(1);
        snapshot_store::new_snapshot_id(format!(
            "{}:{}:{}",
            self.identity.conversation_key,
            kind.as_str(),
            self.next_snapshot_seed
        ))
    }
}

#[derive(Debug, Default)]
struct BrowserState {
    contexts: HashMap<String, ContextState>,
    late_events: HashMap<String, VecDeque<LateEvent>>,
    operations: Vec<(String, Operation)>,
    invocations: HashMap<String, Vec<BrowserInvocation>>,
}

#[derive(Debug, Clone, Copy)]
struct BrowserInvocation {
    capability: BrowserCapability,
    outcome: Option<Outcome>,
}

#[derive(Debug, Default)]
enum BrowserRefusalRing {
    #[default]
    Disabled,
    Durable(Option<RefusalRing<SnapshotRefusalReason>>),
    InMemory(RefusalRing<SnapshotRefusalReason>),
}

#[derive(Clone, Copy, Default)]
enum BrowserJournalMode {
    #[default]
    Disabled,
    Durable(journal::JournalConfig),
    InMemory(journal::JournalConfig),
}

impl BrowserJournalMode {
    fn open_store(self) -> Result<Option<JournalStore>, JournalError> {
        match self {
            Self::Disabled => Ok(None),
            Self::Durable(config) => JournalStore::new(config).map(Some),
            Self::InMemory(config) => JournalStore::new_in_memory(config).map(Some),
        }
    }

    fn is_enabled(self) -> bool {
        !matches!(self, Self::Disabled)
    }
}

#[derive(Default)]
struct BrowserJournalState {
    store: Option<JournalStore>,
    invocations: HashMap<String, Vec<JournalInvocation>>,
}

impl BrowserJournalState {
    fn active_invocation_mut(
        &mut self,
        key: &str,
        capability: BrowserCapability,
    ) -> Option<(&mut JournalStore, &mut JournalInvocation)> {
        let store = self.store.as_mut()?;
        let invocation = self
            .invocations
            .get_mut(key)?
            .iter_mut()
            .rev()
            .find(|invocation| {
                invocation.browser_capability == capability && !invocation.terminal
            })?;
        Some((store, invocation))
    }

    fn release_terminal_invocations(&mut self, key: &str) {
        if let Some(invocations) = self.invocations.get_mut(key) {
            invocations.retain(|invocation| !invocation.terminal);
            if invocations.is_empty() {
                self.invocations.remove(key);
            }
        }
    }
}

#[derive(Default)]
pub struct BrowserPlane {
    state: Arc<Mutex<BrowserState>>,
    lanes: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    grants: Arc<Mutex<GrantStore>>,
    journal_mode: BrowserJournalMode,
    refusal_ring: Arc<Mutex<BrowserRefusalRing>>,
    journal: Arc<Mutex<BrowserJournalState>>,
    session_gate: Option<(
        crate::browser_session::BrowserSessions,
        Arc<cerebellum_core::clock::SystemClock>,
        u64,
    )>,
}

impl BrowserPlane {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with_grants(grants: GrantStore) -> Self {
        Self {
            state: Arc::new(Mutex::new(BrowserState::default())),
            lanes: Arc::new(Mutex::new(HashMap::new())),
            grants: Arc::new(Mutex::new(grants)),
            journal_mode: BrowserJournalMode::Disabled,
            refusal_ring: Arc::new(Mutex::new(BrowserRefusalRing::Disabled)),
            journal: Arc::new(Mutex::new(BrowserJournalState::default())),
            session_gate: None,
        }
    }
    pub fn with_session_gate(
        sessions: crate::browser_session::BrowserSessions,
        clock: Arc<cerebellum_core::clock::SystemClock>,
        navigation_settle_deadline_ms: u64,
    ) -> Self {
        Self {
            session_gate: Some((sessions, clock, navigation_settle_deadline_ms)),
            ..Self::default()
        }
    }

    /// Install grants on a plane that already has a session gate.
    ///
    /// Separate from [`Self::with_grants`] because a driving capability needs
    /// both, and the two constructors each reach `Self::default()` for the
    /// half they do not set -- so calling one after the other would discard
    /// whichever was applied first.
    pub fn with_grants_installed(mut self, grants: GrantStore) -> Self {
        self.grants = Arc::new(Mutex::new(grants));
        self
    }

    pub(crate) fn with_shared_grants(mut self, grants: Arc<Mutex<GrantStore>>) -> Self {
        self.grants = grants;
        self
    }

    /// How many loaded journal stores this plane retains.
    pub async fn retained_journal_store_count_for_test(&self) -> usize {
        usize::from(self.journal.lock().await.store.is_some())
    }

    /// The journal as a reader sees it, for tests that drive the lifecycle.
    pub async fn journal_export_for_test(&self) -> String {
        self.journal
            .lock()
            .await
            .store
            .as_ref()
            .map(JournalStore::export)
            .unwrap_or_default()
    }

    #[cfg(test)]
    pub async fn grant_count_for_test(&self) -> usize {
        self.grants.lock().await.current_grants().count()
    }

    /// Install a journal on a plane that already has a session gate.
    ///
    /// Chainable for the reason `with_grants_installed` is: a driving capability
    /// needs the session gate too, and a constructor reaching `Self::default()`
    /// would discard it.
    ///
    /// It replaces a `with_journal` constructor that built a plane with NO
    /// session gate, which could not drive anything and had zero callers -- so
    /// every reserve, commit and finalize on this path was unreachable code
    /// behind a flag nothing set. That is why the lifecycle test below is the
    /// first execution any of it has had.
    pub fn with_journal_installed(mut self, config: journal::JournalConfig) -> Self {
        self.journal_mode = BrowserJournalMode::Durable(config);
        self.journal = Arc::new(Mutex::new(BrowserJournalState::default()));
        self.refusal_ring = Arc::new(Mutex::new(BrowserRefusalRing::Durable(None)));
        self
    }

    /// Install a journal that never touches the operator's durable audit data.
    ///
    /// Separate constructor rather than a parameter on the one above, so a
    /// fixture cannot reach the production path by leaving an argument at its
    /// default. The durable path is what a caller gets by asking for it.
    pub fn with_in_memory_journal(mut self, config: journal::JournalConfig) -> Self {
        self.journal_mode = BrowserJournalMode::InMemory(config);
        self.journal = Arc::new(Mutex::new(BrowserJournalState::default()));
        let ring = RefusalRing::new_in_memory(refusal_ring_config())
            .expect("the fixed browser refusal-ring capacity is valid");
        self.refusal_ring = Arc::new(Mutex::new(BrowserRefusalRing::InMemory(ring)));
        self
    }

    /// Serialize refusal state as JSON for test inspection.
    #[doc(hidden)]
    pub async fn refusal_ring_export_for_test(&self) -> String {
        let ring = self.refusal_ring.lock().await;
        let bytes = match &*ring {
            BrowserRefusalRing::Disabled | BrowserRefusalRing::Durable(None) => {
                return String::new()
            }
            BrowserRefusalRing::Durable(Some(ring)) | BrowserRefusalRing::InMemory(ring) => {
                ring.export_bytes()
            }
        }
        .expect("an in-process refusal state serializes");
        String::from_utf8(bytes).expect("JSON refusal state is UTF-8")
    }

    /// Typed refusal history for one caller.
    #[doc(hidden)]
    pub async fn refusal_history_for_test(
        &self,
        caller: &str,
    ) -> Option<CallerRefusalHistory<SnapshotRefusalReason>> {
        let ring = self.refusal_ring.lock().await;
        match &*ring {
            BrowserRefusalRing::Disabled | BrowserRefusalRing::Durable(None) => None,
            BrowserRefusalRing::Durable(Some(ring)) | BrowserRefusalRing::InMemory(ring) => {
                ring.history(caller).cloned()
            }
        }
    }

    /// Test seam for the per-context dispatch lane.
    ///
    /// The lane's mutual exclusion is an ordering property with no observable
    /// effect on any single call's result, so it cannot be asserted through the
    /// public dispatch surface alone.  Exposing the guard lets a test hold two
    /// lanes concurrently and observe that the same context never grants both.
    #[doc(hidden)]
    pub async fn lane_for_test(&self, key: &str) -> OwnedMutexGuard<()> {
        self.lane(key).await
    }

    async fn lane(&self, key: &str) -> OwnedMutexGuard<()> {
        let lane = {
            let mut lanes = self.lanes.lock().await;
            lanes
                .entry(key.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        lane.lock_owned().await
    }
    pub async fn open_context(&self, identity: RouteIdentity) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .entry(identity.conversation_key.clone())
            .or_insert_with(|| ContextState::new(identity));
        Ok(())
    }
    pub async fn end_context(&self, identity: &RouteIdentity, crashed: bool) {
        let _lane = self.lane(&identity.conversation_key).await;
        {
            let mut state = self.state.lock().await;
            if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
                context.ended = true;
                context.crashed = crashed;
                context.snapshots.begin_teardown();
                let _ = context.snapshots.complete_teardown();
            }
        }
        self.journal
            .lock()
            .await
            .invocations
            .remove(&identity.conversation_key);
    }
    pub async fn queue_event(&self, identity: &RouteIdentity, event: LateEvent) {
        let mut state = self.state.lock().await;
        state
            .late_events
            .entry(identity.conversation_key.clone())
            .or_default()
            .push_back(event);
    }
    pub async fn operation_log(&self) -> Vec<(String, Operation)> {
        self.state.lock().await.operations.clone()
    }

    /// Test seam for checking that nested browser operations retain distinct
    /// capability outcomes even when the durable journal cannot name one.
    pub async fn invocation_outcomes_for_test(
        &self,
        identity: &RouteIdentity,
    ) -> Vec<(BrowserCapability, Option<Outcome>)> {
        self.state
            .lock()
            .await
            .invocations
            .get(&identity.conversation_key)
            .into_iter()
            .flatten()
            .map(|invocation| (invocation.capability, invocation.outcome))
            .collect()
    }

    fn op(state: &mut BrowserState, key: &str, operation: Operation) {
        state.operations.push((key.to_string(), operation));
    }

    fn record_invocation_outcome(
        state: &mut BrowserState,
        key: &str,
        capability: BrowserCapability,
        outcome: Outcome,
    ) {
        if let Some(invocation) = state.invocations.get_mut(key).and_then(|invocations| {
            invocations.iter_mut().rev().find(|invocation| {
                invocation.capability == capability && invocation.outcome.is_none()
            })
        }) {
            invocation.outcome = Some(outcome);
        }
    }

    pub async fn dispatch(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        args: &Value,
    ) -> Value {
        // Route admission is performed by lib.rs. This lane is still required
        // for direct first-party callers because it serializes all CDP operations
        // for a conversation and prevents concurrent invocations from interleaving them.
        let _lane = self.lane(&identity.conversation_key).await;
        let start = self.state.lock().await.operations.len();
        let result = self.dispatch_inner(identity, capability, args).await;
        if let Err(error) = &result {
            self.terminal_on_error(identity, capability, start, error)
                .await;
        }
        self.result(identity, result).await
    }

    async fn dispatch_inner(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        match capability {
            BrowserCapability::Navigate => self.navigate(identity, args).await,
            BrowserCapability::Snapshot => self.snapshot(identity, args).await,
            BrowserCapability::Click => self.click(identity, args).await,
            BrowserCapability::Screenshot => self.screenshot(identity, args).await,
            BrowserCapability::ClickPoint => self.click_point(identity, args).await,
            BrowserCapability::WaitFor => self.wait_for(identity, args).await,
        }
    }

    async fn terminal_on_error(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        start: usize,
        error: &BrowserError,
    ) {
        let operations = self.state.lock().await.operations[start..].to_vec();
        let committed = operations
            .iter()
            .any(|(_, operation)| *operation == Operation::CommitDispatched);
        let finalized = operations.iter().any(|(_, operation)| {
            matches!(
                *operation,
                Operation::FinalizeRejected | Operation::FinalizeDispatched
            )
        });
        if finalized
            || !operations
                .iter()
                .any(|(_, operation)| *operation == Operation::Reserve)
        {
            return;
        }
        if committed {
            let mut state = self.state.lock().await;
            Self::record_invocation_outcome(
                &mut state,
                &identity.conversation_key,
                capability,
                Outcome::InternalError,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::FinalizeDispatched,
            );
            drop(state);
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                let _ = invocation.finalize_dispatched(
                    store,
                    FinalContextAssociation {
                        profile_uuid: None,
                        profile_name: None,
                    },
                    CompletedResult {
                        outcome: Outcome::InternalError,
                        detail: error
                            .detail()
                            .unwrap_or_else(|| json!({"reason_code":"internal_failure"})),
                    },
                );
            }
            journal.release_terminal_invocations(&identity.conversation_key);
        } else {
            let outcome = journal_outcome(error);
            let mut state = self.state.lock().await;
            Self::record_invocation_outcome(
                &mut state,
                &identity.conversation_key,
                capability,
                outcome,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::FinalizeRejected,
            );
            drop(state);
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                let _ = invocation.finalize_rejected(
                    store,
                    rejection_material(
                        outcome,
                        error
                            .detail()
                            .unwrap_or_else(|| json!({"reason_code":"internal_failure"})),
                    ),
                );
            }
            journal.release_terminal_invocations(&identity.conversation_key);
        }
    }

    async fn result(&self, identity: &RouteIdentity, result: Result<Value, BrowserError>) -> Value {
        let context = BrowserContextResult::from_identity(identity).json();
        match result {
            Ok(mut value) => {
                if let Some(object) = value.as_object_mut() {
                    object.insert("context".into(), context);
                }
                value
            }
            Err(error) => {
                let mut object = Map::new();
                object.insert("outcome".into(), Value::String(error.outcome().into()));
                object.insert("remedy".into(), Value::String(error.remedy().into()));
                object.insert("context".into(), context);
                if let Some(detail) = error.detail() {
                    object.insert("detail".into(), detail);
                }
                Value::Object(object)
            }
        }
    }

    async fn validate_request<'a>(
        &self,
        args: &'a Value,
        allowed: &[&str],
    ) -> Result<&'a Map<String, Value>, BrowserError> {
        let object = args
            .as_object()
            .ok_or_else(|| BrowserError::InvalidRequest {
                field: "$".into(),
                reason_code: "wrong_type",
            })?;
        if let Some(field) = object
            .keys()
            .filter(|field| !allowed.contains(&field.as_str()))
            .min()
        {
            return Err(BrowserError::InvalidRequest {
                field: field.clone(),
                reason_code: "unknown_field",
            });
        }
        Ok(object)
    }

    async fn reserve(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<Option<crate::browser_session::OperationGuard>, BrowserError> {
        self.reserve_inner(identity, capability, true).await
    }

    async fn reserve_without_journal(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<Option<crate::browser_session::OperationGuard>, BrowserError> {
        self.reserve_inner(identity, capability, false).await
    }

    async fn reserve_inner(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        persist_journal: bool,
    ) -> Result<Option<crate::browser_session::OperationGuard>, BrowserError> {
        let operation = if let Some((sessions, clock, _)) = &self.session_gate {
            match sessions.accept_dispatch(&identity.conversation_key, clock.as_ref()) {
                crate::browser_session::DispatchAdmission::Accepted(guard) => Some(guard),
                crate::browser_session::DispatchAdmission::LaunchPending => {
                    return if capability == BrowserCapability::Navigate {
                        Err(BrowserError::NoSession)
                    } else {
                        Err(BrowserError::BrowserLaunchPending)
                    }
                }
                crate::browser_session::DispatchAdmission::NoSession => {
                    return Err(BrowserError::NoSession)
                }
            }
        } else if matches!(
            capability,
            BrowserCapability::Navigate | BrowserCapability::Snapshot
        ) {
            return Err(BrowserError::NoSession);
        } else {
            None
        };
        if persist_journal && self.journal_mode.is_enabled() {
            let mut journal = self.journal.lock().await;
            if journal.store.is_none() {
                journal.store = self.journal_mode.open_store().map_err(map_journal_error)?;
            }
            let mut invocation = JournalInvocation::new(capability);
            invocation
                .reserve(
                    journal
                        .store
                        .as_mut()
                        .expect("an enabled journal mode opens one store"),
                    journal_identity(identity),
                )
                .map_err(map_journal_error)?;
            journal
                .invocations
                .entry(identity.conversation_key.clone())
                .or_default()
                .push(invocation);
        }
        let mut state = self.state.lock().await;
        state
            .invocations
            .entry(identity.conversation_key.clone())
            .or_default()
            .push(BrowserInvocation {
                capability,
                outcome: None,
            });
        Self::op(&mut state, &identity.conversation_key, Operation::Reserve);
        Ok(operation)
    }
    async fn commit(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<(), BrowserError> {
        if self.journal_mode.is_enabled() {
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                invocation
                    .commit_dispatched(
                        store,
                        DispatchMaterial {
                            intent_redacted: None,
                            requested_severity: None,
                            effective_severity: None,
                            grant_decision: GrantDecision::not_reached(),
                            action: journal_action(invocation.capability),
                            locator: None,
                            snapshot_ids: Vec::new(),
                            governing_observation: GoverningObservation::observation_not_required(),
                        },
                    )
                    .map_err(map_journal_error)?;
            }
        }
        let mut state = self.state.lock().await;
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::CommitDispatched,
        );
        Ok(())
    }
    async fn finalize(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
        outcome: Outcome,
        detail: Value,
    ) -> Result<(), BrowserError> {
        let mut state = self.state.lock().await;
        Self::record_invocation_outcome(
            &mut state,
            &identity.conversation_key,
            capability,
            outcome,
        );
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::FinalizeDispatched,
        );
        drop(state);
        if self.journal_mode.is_enabled() {
            let mut journal = self.journal.lock().await;
            if let Some((store, invocation)) =
                journal.active_invocation_mut(&identity.conversation_key, capability)
            {
                invocation
                    .finalize_dispatched(
                        store,
                        FinalContextAssociation {
                            profile_uuid: None,
                            profile_name: (identity.session_kind != SessionKind::Ephemeral)
                                .then(|| "default".to_string()),
                        },
                        CompletedResult { outcome, detail },
                    )
                    .map_err(map_journal_error)?;
            }
            journal.release_terminal_invocations(&identity.conversation_key);
        }
        Ok(())
    }

    async fn navigate(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(
                args,
                &[
                    "url",
                    "intent",
                    "wait",
                    "severity",
                    "read_page",
                    "max_bytes",
                ],
            )
            .await?;
        let url = required_string(object, "url", 1, 4096)?;
        let _intent = bounded_string(object, "intent", 0, 512)?;
        let read_page = match object.get("read_page") {
            None => false,
            Some(Value::Bool(value)) => *value,
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "read_page".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let read_max_bytes = optional_integer(object, "max_bytes", 1, 262_144)?
            .unwrap_or(DEFAULT_READ_PAGE_MAX_BYTES) as usize;
        let wait = match object.get("wait") {
            None => crate::browser_session::NavigationWait::Settle,
            Some(Value::String(value)) if value == "settle" => {
                crate::browser_session::NavigationWait::Settle
            }
            Some(Value::String(value)) if value == "none" => {
                crate::browser_session::NavigationWait::None
            }
            Some(Value::String(_)) => {
                return Err(BrowserError::InvalidRequest {
                    field: "wait".into(),
                    reason_code: "unsupported_value",
                })
            }
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "wait".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let requested_severity = parse_severity(object)?;
        let scheme = url
            .split_once(':')
            .map(|(scheme, _)| scheme)
            .unwrap_or_default();
        if scheme.is_empty()
            || !url.contains("://")
            || scheme.len() > 64
            || scheme.bytes().any(|byte| {
                !byte.is_ascii_lowercase()
                    && !byte.is_ascii_digit()
                    && byte != b'+'
                    && byte != b'-'
                    && byte != b'.'
            })
        {
            return Err(BrowserError::InvalidRequest {
                field: "url".into(),
                reason_code: "unsupported_value",
            });
        }
        let authority = url
            .split_once("://")
            .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
            .unwrap_or_default();
        if authority.is_empty() || authority.bytes().any(|byte| byte.is_ascii_whitespace()) {
            return Err(BrowserError::InvalidRequest {
                field: "url".into(),
                reason_code: "unsupported_value",
            });
        }
        if url.contains('@')
            && url.find("//").is_some_and(|start| {
                url[start + 2..]
                    .split('/')
                    .next()
                    .is_some_and(|authority| authority.contains('@'))
            })
        {
            return Err(BrowserError::InvalidRequest {
                field: "url".into(),
                reason_code: "unsupported_value",
            });
        }
        {
            let decision = self
                .grants
                .lock()
                .await
                .authorize(AuthorizationRequest::navigate(
                    &identity.conversation_key,
                    requested_severity,
                    url,
                    &identity.agent_project_id,
                ))
                .map_err(map_authorization_error)?;
            let origin = origin_from_url(url);
            if decision.evaluate_origin_scope(&origin).is_err() {
                return Err(BrowserError::AuthorizationDenied {
                    reason: "origin_scope",
                });
            }
        }
        if scheme != "http" && scheme != "https" {
            return Err(BrowserError::NavigationPolicyRejected {
                reason_code: "scheme_not_allowed",
            });
        }
        let Some(mut session_operation) =
            self.reserve(identity, BrowserCapability::Navigate).await?
        else {
            return Err(BrowserError::NoSession);
        };
        self.commit(identity, BrowserCapability::Navigate).await?;
        let tracker = {
            let mut state = self.state.lock().await;
            let tracker = {
                let context = state
                    .contexts
                    .entry(identity.conversation_key.clone())
                    .or_insert_with(|| ContextState::new(identity.clone()));
                let _ = context
                    .epoch
                    .replace(DocumentTransition::TopLevelDocumentReplaced);
                context.tracker = Tracker::default();
                context.tracker.token("navigation_started");
                context.tracker.clone()
            };
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpNavigate,
            );
            tracker
        };
        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
            .ok_or(BrowserError::NoSession)?;
        let route_key = identity.conversation_key.clone();
        let requested_url = url.to_string();
        let driven = tokio::task::spawn_blocking(move || {
            let mut tracker = tracker;
            let result = session_operation.navigate(
                &route_key,
                &requested_url,
                wait,
                deadline_ms,
                &mut tracker,
            );
            (session_operation, tracker, result)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let (session_operation, tracker, drive_result) = driven;
        session_operation.finish();
        {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            context.tracker = tracker.clone();
        }
        drive_result.map_err(map_navigation_drive_error)?;

        let should_settle = wait == crate::browser_session::NavigationWait::Settle;
        let outcome = if should_settle && !tracker.settled {
            Outcome::InternalError
        } else {
            Outcome::Success
        };
        self.finalize(
            identity,
            BrowserCapability::Navigate,
            outcome,
            json!({"outcome":if should_settle && !tracker.settled {"not_settled"} else {"ok"},"url_final":tracker.url_final,"lifecycle":tracker.lifecycle}),
        )
        .await?;
        let mut response = if should_settle && !tracker.settled {
            json!({
                "outcome":"not_settled",
                "remedy":"call browser.snapshot to re-observe the page before depending on its current state",
                "url_final":tracker.url_final,
                "lifecycle":tracker.lifecycle,
            })
        } else {
            json!({"outcome":"ok","url_final":tracker.url_final,"lifecycle":tracker.lifecycle})
        };
        if !read_page {
            return Ok(response);
        }

        // Action grants are not capability-scoped today, so a same-origin navigation
        // grant also admits a snapshot. The read still goes through snapshot
        // authorization against the landing URL because redirects can change origin.
        // If grants become action-scoped, this path must not inherit navigate authority.
        //
        // The read journals under its own capability. It did not when this landed
        // -- the vocabulary had no Snapshot member, so recording the read would
        // have written it as a navigation -- and that hole closed when the
        // members were added rather than by anything here changing.
        let read_start = self.state.lock().await.operations.len();
        let page = match self
            .capture_snapshot(identity, SnapshotKind::Ax, read_max_bytes, true)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                self.terminal_on_error(identity, BrowserCapability::Snapshot, read_start, &error)
                    .await;
                partial_error_result(&error)
            }
        };
        response
            .as_object_mut()
            .expect("navigation response is an object")
            .insert("read_page".into(), page);
        Ok(response)
    }

    async fn snapshot(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self.validate_request(args, &["mode", "max_bytes"]).await?;
        let kind = match object.get("mode") {
            None => SnapshotKind::Ax,
            Some(Value::String(value)) if value == "ax" => SnapshotKind::Ax,
            Some(Value::String(value)) if value == "dom_full" => SnapshotKind::DomFull,
            Some(Value::String(_)) => {
                return Err(BrowserError::InvalidRequest {
                    field: "mode".into(),
                    reason_code: "unsupported_value",
                })
            }
            Some(_) => {
                return Err(BrowserError::InvalidRequest {
                    field: "mode".into(),
                    reason_code: "wrong_type",
                })
            }
        };
        let max_bytes =
            optional_integer(object, "max_bytes", 1, 262_144)?.unwrap_or(65_536) as usize;
        self.capture_snapshot(identity, kind, max_bytes, true).await
    }

    async fn record_snapshot_refusal(
        &self,
        identity: &RouteIdentity,
        claimed_addressing: &str,
        reason: SnapshotRefusalReason,
    ) -> Result<(), BrowserError> {
        let mut binding = self.refusal_ring.lock().await;
        let ring = match &mut *binding {
            BrowserRefusalRing::Disabled => return Ok(()),
            BrowserRefusalRing::InMemory(ring) => ring,
            BrowserRefusalRing::Durable(slot) => {
                if slot.is_none() {
                    let path = journal_data_path(BROWSER_REFUSAL_RING_FILE).map_err(|_| {
                        BrowserError::Internal {
                            reason_code: JournalReasonCode::InternalFailure,
                        }
                    })?;
                    *slot = Some(RefusalRing::new(path, refusal_ring_config()).map_err(|_| {
                        BrowserError::Internal {
                            reason_code: JournalReasonCode::InternalFailure,
                        }
                    })?);
                }
                slot.as_mut().expect("initialized above")
            }
        };
        ring.record_refusal(&identity.agent_project_id, claimed_addressing, reason)
            .map_err(|_| BrowserError::Internal {
                reason_code: JournalReasonCode::InternalFailure,
            })
    }

    async fn capture_snapshot(
        &self,
        identity: &RouteIdentity,
        kind: SnapshotKind,
        max_bytes: usize,
        persist_journal: bool,
    ) -> Result<Value, BrowserError> {
        let (document_epoch, source_origin) = {
            let state = self.state.lock().await;
            let context = state
                .contexts
                .get(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?;
            (
                context.epoch.value(),
                context
                    .tracker
                    .url_final
                    .clone()
                    .unwrap_or_else(|| "null".into()),
            )
        };
        {
            let grants = self.grants.lock().await;
            let decision = match grants.authorize(AuthorizationRequest::snapshot(
                &identity.conversation_key,
                &source_origin,
                &identity.agent_project_id,
            )) {
                Ok(decision) => decision,
                Err(crate::authorization::AuthorizationError::NoGrant) => {
                    drop(grants);
                    self.record_snapshot_refusal(
                        identity,
                        &source_origin,
                        SnapshotRefusalReason::NoGrant,
                    )
                    .await?;
                    return Err(BrowserError::AuthorizationDenied { reason: "no_grant" });
                }
                Err(error) => return Err(map_authorization_error(error)),
            };
            if decision
                .evaluate_origin_scope(&origin_from_url(&source_origin))
                .is_err()
            {
                drop(grants);
                self.record_snapshot_refusal(
                    identity,
                    &source_origin,
                    SnapshotRefusalReason::OriginScope,
                )
                .await?;
                return Err(BrowserError::AuthorizationDenied {
                    reason: "origin_scope",
                });
            }
            if grants.commit(&decision).is_err() {
                drop(grants);
                self.record_snapshot_refusal(
                    identity,
                    &source_origin,
                    SnapshotRefusalReason::NoGrant,
                )
                .await?;
                return Err(BrowserError::AuthorizationDenied { reason: "no_grant" });
            }
        }
        let reservation = if persist_journal {
            self.reserve(identity, BrowserCapability::Snapshot).await?
        } else {
            self.reserve_without_journal(identity, BrowserCapability::Snapshot)
                .await?
        };
        let Some(mut session_operation) = reservation else {
            return Err(BrowserError::NoSession);
        };
        self.commit(identity, BrowserCapability::Snapshot).await?;
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
            .ok_or(BrowserError::NoSession)?;
        let route_key = identity.conversation_key.clone();
        let driven = tokio::task::spawn_blocking(move || {
            let result = session_operation.snapshot_classified(
                &route_key,
                kind,
                document_epoch,
                &source_origin,
                deadline_ms,
            );
            (session_operation, result)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let (session_operation, drive_result) = driven;
        session_operation.finish();
        let observation = drive_result.map_err(map_navigation_drive_error)?;
        let result = self
            .retain_text_snapshot_inner(
                identity,
                kind,
                &observation.records,
                observation.dom_text.as_deref(),
                observation.refs,
                max_bytes,
                kind == SnapshotKind::Ax && observation.ax_truncated,
                observation.refs_truncated,
            )
            .await?;
        let content_bytes = result
            .get("content")
            .and_then(Value::as_str)
            .map(str::len)
            .unwrap_or_default();
        let ref_count = result
            .get("refs")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or_default();
        self.finalize(
            identity,
            BrowserCapability::Snapshot,
            Outcome::Success,
            json!({
                "outcome": "ok",
                "snapshot_id": result["snapshot_id"],
                "content_bytes": content_bytes,
                "ref_count": ref_count,
                "truncated": result["truncated"],
                "refs_truncated": result["refs_truncated"],
            }),
        )
        .await?;
        Ok(result)
    }

    /// Retain a completed extraction observation supplied by the CDP adapter.
    /// The adapter performs DOM/AX traversal; this method performs bounded wire
    /// encoding and retention only.
    pub async fn retain_text_snapshot(
        &self,
        identity: &RouteIdentity,
        mode: SnapshotKind,
        records: &[AxRecord],
        dom_text: Option<&str>,
        refs: Vec<crate::snapshot_store::RefRecord>,
        max_bytes: usize,
    ) -> Result<Value, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        self.retain_text_snapshot_inner(
            identity, mode, records, dom_text, refs, max_bytes, false, false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn retain_text_snapshot_inner(
        &self,
        identity: &RouteIdentity,
        mode: SnapshotKind,
        records: &[AxRecord],
        dom_text: Option<&str>,
        refs: Vec<crate::snapshot_store::RefRecord>,
        max_bytes: usize,
        content_incomplete: bool,
        refs_incomplete: bool,
    ) -> Result<Value, BrowserError> {
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        if context.ended {
            return Err(BrowserError::NoSession);
        }
        let (content, encoded_truncated, schema) = match mode {
            SnapshotKind::Ax => {
                let (content, truncated) = snapshot_store::encode_ax_jsonl(records, max_bytes)
                    .map_err(map_snapshot_error)?;
                (content, truncated, AX_SCHEMA)
            }
            SnapshotKind::DomFull => {
                let (content, truncated) =
                    snapshot_store::encode_dom_text(dom_text.unwrap_or_default(), max_bytes);
                (content, truncated, DOM_SCHEMA)
            }
            SnapshotKind::Screenshot => {
                return Err(BrowserError::InvalidRequest {
                    field: "mode".into(),
                    reason_code: "unsupported_value",
                })
            }
        };
        let truncated = encoded_truncated || content_incomplete;
        let refs_truncated = refs.len() > MAX_REFS || refs_incomplete;
        let refs = refs.into_iter().take(MAX_REFS).collect::<Vec<_>>();
        let id = context.snapshot_id(mode);
        let snapshot = TextSnapshot {
            snapshot_id: id.clone(),
            kind: mode,
            document_epoch: context.epoch.value(),
            source_origin: context
                .tracker
                .url_final
                .clone()
                .unwrap_or_else(|| "null".into()),
            content_schema: schema,
            content,
            truncated,
            refs_truncated,
            refs,
        };
        context
            .snapshots
            .retain_text(snapshot.clone())
            .map_err(map_snapshot_error)?;
        let refs = snapshot.refs.iter().map(|reference| json!({"ref":reference.captured.reference,"role":reference.captured.role,"name":reference.captured.name,"nth":reference.captured.nth})).collect::<Vec<_>>();
        Ok(
            json!({"outcome":"ok","snapshot_id":snapshot.snapshot_id,"document_epoch":snapshot.document_epoch,"source_origin":snapshot.source_origin,"content_schema":snapshot.content_schema,"truncated":snapshot.truncated,"refs_truncated":snapshot.refs_truncated,"content":snapshot.content,"refs":refs}),
        )
    }

    async fn unpin_snapshot(&self, identity: &RouteIdentity, snapshot_id: &str) {
        let mut state = self.state.lock().await;
        if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
            context.snapshots.unpin(snapshot_id);
        }
    }

    pub async fn snapshot_pin_count_for_test(
        &self,
        identity: &RouteIdentity,
        snapshot_id: &str,
    ) -> usize {
        self.state
            .lock()
            .await
            .contexts
            .get(&identity.conversation_key)
            .map(|context| context.snapshots.pin_count(snapshot_id))
            .unwrap_or_default()
    }

    pub async fn text_snapshot_pin_count_for_test(
        &self,
        identity: &RouteIdentity,
        snapshot_id: &str,
    ) -> usize {
        self.snapshot_pin_count_for_test(identity, snapshot_id)
            .await
    }

    async fn click(&self, identity: &RouteIdentity, args: &Value) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["ref", "snapshot_id", "intent", "severity"])
            .await?;
        let reference = required_string(object, "ref", 2, 5)?;
        let snapshot_id = required_string(object, "snapshot_id", 32, 32)?;
        if !snapshot_store::valid_snapshot_id(snapshot_id) {
            return Err(BrowserError::InvalidRequest {
                field: "snapshot_id".into(),
                reason_code: "unsupported_value",
            });
        }
        if !snapshot_store::valid_ref(reference) {
            return Err(BrowserError::InvalidRequest {
                field: "ref".into(),
                reason_code: "unsupported_value",
            });
        }
        bounded_string(object, "intent", 0, 512)?;
        let requested_severity = parse_severity(object)?;
        if requested_severity.tier < 2 {
            return Err(BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_below_floor",
            });
        }
        let (backend_identity, classification, document_epoch, source_origin) = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let snapshot = context
                .snapshots
                .pin_text(snapshot_id, context.epoch.value())
                .map_err(map_snapshot_error)?;
            let Some(record) = snapshot
                .refs
                .iter()
                .find(|record| record.captured.reference == reference)
            else {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::RefNotFound {
                    reference: reference.to_string(),
                });
            };
            let Some(backend_identity) = record.backend_identity.clone() else {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::ElementIntercepted);
            };
            (
                backend_identity,
                record.classification.as_deref().cloned(),
                snapshot.document_epoch,
                snapshot.source_origin.clone(),
            )
        };

        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms);
        // Snapshot capture stores either validated form facts or `None` when the
        // DOM could not be classified. Authorization treats `None` as the distinct
        // unverified-form hazard. Before mouse input, `click_classified` recomputes
        // the record and refuses if it differs from this snapshot-time value.

        let authorization = {
            let grants = self.grants.lock().await;
            let request = match classification.as_ref() {
                Some(classification) => AuthorizationRequest::click(
                    &identity.conversation_key,
                    requested_severity,
                    snapshot_id,
                    &identity.agent_project_id,
                    classification,
                ),
                None => AuthorizationRequest::click_unverified(
                    &identity.conversation_key,
                    requested_severity,
                    snapshot_id,
                    &identity.agent_project_id,
                ),
            };
            grants.authorize(request).and_then(|decision| {
                decision
                    .evaluate_origin_scope(&origin_from_url(&source_origin))
                    .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                grants
                    .commit(&decision)
                    .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                Ok(decision)
            })
        };
        if let Err(error) = authorization {
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(map_authorization_error(error));
        }

        let reservation = self.reserve(identity, BrowserCapability::Click).await;
        let mut session_operation = match reservation {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::NoSession);
            }
            Err(error) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(error);
            }
        };
        if let Err(error) = self.commit(identity, BrowserCapability::Click).await {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(error);
        }
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let Some(deadline_ms) = deadline_ms else {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::NoSession);
        };
        let state = Arc::clone(&self.state);
        let route_key = identity.conversation_key.clone();
        let expected_classification = classification;
        let origin = source_origin;
        let driven = tokio::task::spawn_blocking(move || {
            let mut input_dispatched = |event| {
                let operation = match event {
                    crate::browser_session::BrowserInputEvent::Press(_) => Operation::CdpInputPress,
                    crate::browser_session::BrowserInputEvent::Release(_) => {
                        Operation::CdpInputRelease
                    }
                };
                let mut state = state.blocking_lock();
                Self::op(&mut state, &route_key, operation);
            };
            let result = session_operation.click_classified(
                &route_key,
                &backend_identity,
                document_epoch,
                &origin,
                expected_classification.as_ref(),
                deadline_ms,
                &mut input_dispatched,
            );
            (session_operation, result)
        })
        .await;
        let (session_operation, drive_result) = match driven {
            Ok(result) => result,
            Err(_) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                });
            }
        };
        session_operation.finish();
        self.unpin_snapshot(identity, snapshot_id).await;

        match drive_result {
            Ok(_) => {}
            Err(crate::browser_session::ClickDriveError::NoPosition) => {
                self.finalize(
                    identity,
                    BrowserCapability::Click,
                    Outcome::StaleSnapshot,
                    json!({}),
                )
                .await?;
                return Err(BrowserError::ElementIntercepted);
            }
            Err(crate::browser_session::ClickDriveError::ClassificationChanged) => {
                self.finalize(
                    identity,
                    BrowserCapability::Click,
                    Outcome::StaleSnapshot,
                    json!({"reason_code":"classification_changed"}),
                )
                .await?;
                return Err(BrowserError::StaleSnapshot {
                    reason_code: "classification_changed",
                });
            }
            Err(crate::browser_session::ClickDriveError::OutsideViewportAfterScroll(refusal)) => {
                let detail = viewport_refusal_detail("outside_viewport_after_scroll", refusal);
                self.finalize(
                    identity,
                    BrowserCapability::Click,
                    Outcome::StaleSnapshot,
                    detail,
                )
                .await?;
                return Err(BrowserError::OutsideViewportAfterScroll { refusal });
            }
            Err(crate::browser_session::ClickDriveError::Navigation(error)) => {
                return Err(map_navigation_drive_error(error));
            }
        }
        self.finalize(
            identity,
            BrowserCapability::Click,
            Outcome::Success,
            json!({"outcome":"ok","url_final":Value::Null,"lifecycle":[]}),
        )
        .await?;
        Ok(json!({"outcome":"ok","url_final":Value::Null,"lifecycle":[]}))
    }

    async fn screenshot(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self.validate_request(args, &["max_bytes"]).await?;
        let max_bytes = optional_integer(object, "max_bytes", 1, MAX_ENCODED_PNG_BYTES as u64)?
            .unwrap_or(MAX_ENCODED_PNG_BYTES as u64) as usize;
        let (document_epoch, source_origin) = {
            let state = self.state.lock().await;
            let context = state
                .contexts
                .get(&identity.conversation_key)
                .filter(|context| !context.ended)
                .ok_or(BrowserError::NoSession)?;
            (
                context.epoch.value(),
                context
                    .tracker
                    .url_final
                    .clone()
                    .unwrap_or_else(|| "null".into()),
            )
        };
        {
            let grants = self.grants.lock().await;
            let decision = grants
                .authorize(AuthorizationRequest::screenshot(
                    &identity.conversation_key,
                    &source_origin,
                    &identity.agent_project_id,
                ))
                .map_err(map_authorization_error)?;
            decision
                .evaluate_origin_scope(&origin_from_url(&source_origin))
                .map_err(|_| BrowserError::AuthorizationDenied {
                    reason: "origin_scope",
                })?;
            grants
                .commit(&decision)
                .map_err(|_| BrowserError::AuthorizationDenied { reason: "no_grant" })?;
        }
        let Some(mut session_operation) = self
            .reserve(identity, BrowserCapability::Screenshot)
            .await?
        else {
            return Err(BrowserError::NoSession);
        };
        self.commit(identity, BrowserCapability::Screenshot).await?;
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let deadline_ms = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
            .ok_or(BrowserError::NoSession)?;
        let route_key = identity.conversation_key.clone();
        let driven = tokio::task::spawn_blocking(move || {
            let result = session_operation.screenshot(&route_key, document_epoch, deadline_ms);
            (session_operation, result)
        })
        .await
        .map_err(|_| BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        })?;
        let (session_operation, drive_result) = driven;
        session_operation.finish();
        let observation = drive_result.map_err(map_navigation_drive_error)?;
        let bytes = observation.image_png_b64.len();
        if bytes > max_bytes {
            return Err(BrowserError::ImageTooLarge {
                bytes,
                bound_bytes: max_bytes,
            });
        }
        let png = validate_png_base64_dimensions(&observation.image_png_b64)
            .map_err(map_coordinate_error)?;
        let payload =
            ScreenshotPayload::new(observation.image_png_b64, png.width_px(), png.height_px());
        let result = self
            .retain_screenshot_inner(
                identity,
                payload,
                observation.before,
                observation.after,
                observation.invalidation_observed,
            )
            .await?;
        self.finalize(
            identity,
            BrowserCapability::Screenshot,
            Outcome::Success,
            json!({
                "outcome": "ok",
                "snapshot_id": result["snapshot_id"],
                "bytes": bytes,
                "image_width_px": result["image_width_px"],
                "image_height_px": result["image_height_px"],
            }),
        )
        .await?;
        Ok(result)
    }

    async fn click_point(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(
                args,
                &[
                    "snapshot_id",
                    "x_px",
                    "y_px",
                    "image_width_px",
                    "image_height_px",
                    "intent",
                    "severity",
                ],
            )
            .await?;
        let snapshot_id = required_string(object, "snapshot_id", 32, 32)?;
        if !snapshot_store::valid_snapshot_id(snapshot_id) {
            return Err(BrowserError::InvalidRequest {
                field: "snapshot_id".into(),
                reason_code: "unsupported_value",
            });
        }
        let x = required_signed_integer(object, "x_px")?;
        let y = required_signed_integer(object, "y_px")?;
        // The image the caller was addressing. A pixel coordinate means nothing
        // without the image it indexes, and these two numbers disagreeing with
        // what was retained is the only evidence available that the caller was
        // looking at a different copy of it.
        let addressed_width = required_signed_integer(object, "image_width_px")?;
        let addressed_height = required_signed_integer(object, "image_height_px")?;
        bounded_string(object, "intent", 0, 512)?;
        let requested_severity = parse_severity(object)?;
        if requested_severity.tier < 2 {
            return Err(BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_below_floor",
            });
        }
        let (position, source_origin) = {
            let mut state = self.state.lock().await;
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let screenshot = context
                .snapshots
                .pin(snapshot_id, SnapshotKind::Screenshot, context.epoch.value())
                .map_err(map_snapshot_error)?;
            // `pin` refuses a kind mismatch, so a non-screenshot should not reach
            // here. Return the typed refusal anyway rather than panicking, and
            // balance the pin if that invariant ever changes.
            let screenshot = match screenshot {
                snapshot_store::StoredSnapshot::Screenshot(snapshot) => snapshot,
                snapshot_store::StoredSnapshot::Text(_) => {
                    context.snapshots.unpin(snapshot_id);
                    return Err(map_snapshot_error(SnapshotError::WrongKind));
                }
            };
            // Checked before the coordinate is mapped and before anything is
            // dispatched. A coordinate from a differently-sized copy lands
            // inside the bounds of the retained image, so the mapping below
            // would succeed and actuate at a point the caller never chose.
            if i128::from(screenshot.image_width_px) != addressed_width
                || i128::from(screenshot.image_height_px) != addressed_height
            {
                context.snapshots.unpin(snapshot_id);
                return Err(BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::ImageSizeMismatch,
                });
            }

            let transform = TransformInputs::new(
                screenshot.input_rect,
                screenshot.device_scale_factor,
                screenshot.visual_viewport_scale,
            );
            let mapped = map_pixel_to_css(
                transform,
                screenshot.image_width_px,
                screenshot.image_height_px,
                x,
                y,
            );
            let (x_css, y_css) = match mapped {
                Ok(point) => point,
                Err(error) => {
                    context.snapshots.unpin(snapshot_id);
                    return Err(map_coordinate_error(error));
                }
            };
            (
                crate::browser_session::BrowserClickPosition { x_css, y_css },
                screenshot.source_origin,
            )
        };

        // A screenshot does not identify or classify the DOM element under the
        // point, so its grant must cover unverified form targets on that page.
        let authorization = {
            let grants = self.grants.lock().await;
            let request = AuthorizationRequest::click_point_unverified(
                &identity.conversation_key,
                requested_severity,
                snapshot_id,
                &identity.agent_project_id,
            );
            grants.authorize(request).and_then(|decision| {
                decision
                    .evaluate_origin_scope(&origin_from_url(&source_origin))
                    .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                grants
                    .commit(&decision)
                    .map_err(|_| crate::authorization::AuthorizationError::NoGrant)?;
                Ok(decision)
            })
        };
        if let Err(error) = authorization {
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(map_authorization_error(error));
        }

        let reservation = self.reserve(identity, BrowserCapability::ClickPoint).await;
        let mut session_operation = match reservation {
            Ok(Some(operation)) => operation,
            Ok(None) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::NoSession);
            }
            Err(error) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(error);
            }
        };
        if let Err(error) = self.commit(identity, BrowserCapability::ClickPoint).await {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(error);
        }
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
        }

        let Some(deadline_ms) = self
            .session_gate
            .as_ref()
            .map(|(_, _, deadline_ms)| *deadline_ms)
        else {
            session_operation.finish();
            self.unpin_snapshot(identity, snapshot_id).await;
            return Err(BrowserError::NoSession);
        };
        let state = Arc::clone(&self.state);
        let route_key = identity.conversation_key.clone();
        let driven = tokio::task::spawn_blocking(move || {
            let mut input_dispatched = |event| {
                let operation = match event {
                    crate::browser_session::BrowserInputEvent::Press(_) => Operation::CdpInputPress,
                    crate::browser_session::BrowserInputEvent::Release(_) => {
                        Operation::CdpInputRelease
                    }
                };
                let mut state = state.blocking_lock();
                Self::op(&mut state, &route_key, operation);
            };
            let result = session_operation.click_point(
                &route_key,
                position,
                deadline_ms,
                &mut input_dispatched,
            );
            (session_operation, result)
        })
        .await;
        let (session_operation, drive_result) = match driven {
            Ok(result) => result,
            Err(_) => {
                self.unpin_snapshot(identity, snapshot_id).await;
                return Err(BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                });
            }
        };
        session_operation.finish();
        self.unpin_snapshot(identity, snapshot_id).await;
        match drive_result {
            Ok(_) => {}
            Err(crate::browser_session::ClickPointDriveError::OutsideViewport(refusal)) => {
                let detail = viewport_refusal_detail("point_outside_viewport", refusal);
                self.finalize(
                    identity,
                    BrowserCapability::ClickPoint,
                    Outcome::StaleSnapshot,
                    detail,
                )
                .await?;
                return Err(BrowserError::PointOutsideViewport { refusal });
            }
            Err(crate::browser_session::ClickPointDriveError::Navigation(error)) => {
                return Err(map_navigation_drive_error(error));
            }
        }

        self.finalize(
            identity,
            BrowserCapability::ClickPoint,
            Outcome::Success,
            json!({"outcome":"ok","url_final":Value::Null,"lifecycle":[]}),
        )
        .await?;
        Ok(json!({"outcome":"ok","url_final":Value::Null,"lifecycle":[]}))
    }

    async fn wait_for(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self.validate_request(args, &["deadline_ms"]).await?;
        let deadline = optional_integer(object, "deadline_ms", 0, 30_000)?.unwrap_or(30_000);
        let _session_operation = self.reserve(identity, BrowserCapability::WaitFor).await?;
        let mut state = self.state.lock().await;
        if let Some(events) = state.late_events.get_mut(&identity.conversation_key) {
            if let Some(event) = events.pop_front() {
                let outcome = event.outcome();
                let remedy = event.remedy();
                let detail = match event {
                    LateEvent::NavigationPolicyRejected { reason_code } => {
                        json!({"reason_code":reason_code})
                    }
                    LateEvent::AuthorizationDenied { reason } => json!({"reason":reason}),
                    _ => json!({}),
                };
                return Ok(
                    json!({"outcome":outcome,"remedy":remedy,"detail":detail,"url_final":Value::Null,"lifecycle":[],"inflight_count":0}),
                );
            }
        }
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        if context.ended {
            return Err(BrowserError::NoSession);
        }
        let now = Instant::now();
        if context.tracker.poll_settlement(now) {
            return Ok(
                json!({"outcome":"ok","url_final":context.tracker.url_final,"lifecycle":context.tracker.lifecycle,"inflight_count":context.tracker.inflight_count}),
            );
        }
        let _ = deadline;
        Err(BrowserError::NotSettled {
            url_final: context.tracker.url_final.clone(),
            lifecycle: context.tracker.lifecycle.clone(),
            inflight_count: context.tracker.inflight_count,
            deadline_ms: deadline,
        })
    }

    /// Install a coherent screenshot produced by the browser screenshot adapter.
    /// This is the only path that retains clickable image state.
    pub async fn retain_screenshot(
        &self,
        identity: &RouteIdentity,
        payload: ScreenshotPayload,
        before: ViewportObservation,
        after: ViewportObservation,
        invalidation_observed: bool,
    ) -> Result<Value, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        self.retain_screenshot_inner(identity, payload, before, after, invalidation_observed)
            .await
    }

    async fn retain_screenshot_inner(
        &self,
        identity: &RouteIdentity,
        payload: ScreenshotPayload,
        before: ViewportObservation,
        after: ViewportObservation,
        invalidation_observed: bool,
    ) -> Result<Value, BrowserError> {
        let coherent = capture_screenshot(before, payload, after, invalidation_observed)
            .map_err(map_coordinate_error)?;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        let id = context.snapshot_id(SnapshotKind::Screenshot);
        let source_origin = context
            .tracker
            .url_final
            .clone()
            .unwrap_or_else(|| "null".into());
        let snapshot = coherent.into_snapshot(id.clone(), source_origin);
        let result = json!({"outcome":"ok","snapshot_id":snapshot.snapshot_id,"document_epoch":snapshot.document_epoch,"source_origin":snapshot.source_origin,"image_png_b64":snapshot.image_png_b64,"image_width_px":snapshot.image_width_px,"image_height_px":snapshot.image_height_px,"input_rect":{"x_input_css":snapshot.input_rect.x_input_css,"y_input_css":snapshot.input_rect.y_input_css,"width_input_css":snapshot.input_rect.width_input_css,"height_input_css":snapshot.input_rect.height_input_css},"device_scale_factor":snapshot.device_scale_factor,"visual_viewport_scale":snapshot.visual_viewport_scale});
        context
            .snapshots
            .retain_screenshot(snapshot)
            .map_err(map_snapshot_error)?;
        Ok(result)
    }

    pub async fn replace_document(
        &self,
        identity: &RouteIdentity,
        transition: DocumentTransition,
    ) -> Result<u64, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        let epoch = context
            .epoch
            .replace(transition)
            .map_err(map_snapshot_error)?;
        context.snapshots.invalidate_before(epoch);
        Ok(epoch)
    }

    pub async fn same_document_url(
        &self,
        identity: &RouteIdentity,
        url: impl Into<String>,
        change: SameDocumentChange,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        context.tracker.url_final = Some(url.into());
        let _ = context.epoch.same_document(change);
        Ok(())
    }

    pub async fn poll_settlement(
        &self,
        identity: &RouteIdentity,
        now: Instant,
    ) -> Result<bool, BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        Ok(state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .poll_settlement(now))
    }

    pub async fn observe_request_started(
        &self,
        identity: &RouteIdentity,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .request_started();
        Ok(())
    }

    pub async fn observe_request_finished(
        &self,
        identity: &RouteIdentity,
        now: Instant,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .request_finished(now);
        Ok(())
    }

    pub async fn observe_load(
        &self,
        identity: &RouteIdentity,
        now: Instant,
    ) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .load(now);
        Ok(())
    }

    pub async fn record_download(&self, identity: &RouteIdentity) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .token("download_blocked");
        state
            .late_events
            .entry(identity.conversation_key.clone())
            .or_default()
            .push_back(LateEvent::DownloadBlocked);
        Ok(())
    }

    pub async fn record_dialog(&self, identity: &RouteIdentity) -> Result<(), BrowserError> {
        let _lane = self.lane(&identity.conversation_key).await;
        let mut state = self.state.lock().await;
        state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?
            .tracker
            .token("js_dialog_dismissed");
        state
            .late_events
            .entry(identity.conversation_key.clone())
            .or_default()
            .push_back(LateEvent::JsDialogDismissed);
        Ok(())
    }

    /// Record-only policy events never enter the caller-visible FIFO.
    pub async fn record_subresource_policy_event(&self, _identity: &RouteIdentity) {}
}

/// Route-independent helper for callers that already have a BrowserPlane.
pub async fn handle_tool(
    plane: &BrowserPlane,
    identity: &RouteIdentity,
    name: &str,
    args: &Value,
) -> Value {
    match BrowserCapability::parse(name) {
        Some(capability) => plane.dispatch(identity, capability, args).await,
        None => json!({"outcome":"unknown_method"}),
    }
}

fn severity_schema() -> Value {
    json!({"type":"object","properties":{"tier":{"type":"integer","minimum":1,"maximum":5},"credential":{"type":"boolean"},"financial":{"type":"boolean"}},"required":["tier","credential","financial"],"additionalProperties":false})
}

pub fn tool_definitions() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            NAVIGATE,
            "Navigate managed Chromium through the enforcing connector. Set read_page to return a bounded snapshot of the landing page.",
            json!({"type":"object","properties":{"url":{"type":"string"},"intent":{"type":"string"},"wait":{"enum":["settle","none"]},"severity":severity_schema(),"read_page":{"type":"boolean","default":false,"description":"Return an accessibility snapshot of the landing page."},"max_bytes":{"type":"integer","minimum":1,"maximum":262144,"default":DEFAULT_READ_PAGE_MAX_BYTES,"description":"Maximum bytes of returned page text; this bounds returned text, not the page observed."}},"required":["url","intent","severity"],"additionalProperties":false}),
        ),
        (
            SNAPSHOT,
            "Capture a structured accessibility or DOM snapshot.",
            json!({"type":"object","properties":{"mode":{"enum":["ax","dom_full"]},"max_bytes":{"type":"integer"}},"additionalProperties":false}),
        ),
        (
            CLICK,
            "Click a retained structured reference.",
            json!({"type":"object","properties":{"ref":{"type":"string"},"snapshot_id":{"type":"string"},"intent":{"type":"string"},"severity":severity_schema()},"required":["ref","snapshot_id","intent","severity"],"additionalProperties":false}),
        ),
        (
            SCREENSHOT,
            "Capture the current visual viewport as PNG base64; max_bytes guards context size but does not reduce vision-token cost because vision APIs may downscale independently.",
            json!({"type":"object","properties":{"max_bytes":{"type":"integer","minimum":1,"maximum":MAX_ENCODED_PNG_BYTES}},"additionalProperties":false}),
        ),
        (
            CLICK_POINT,
            "Click a retained screenshot pixel. Coordinates address the image this module declared; pass its image_width_px and image_height_px so a coordinate taken from a resized copy is refused rather than mis-clicked.",
            json!({"type":"object","properties":{"snapshot_id":{"type":"string"},"x_px":{"type":"integer"},"y_px":{"type":"integer"},"image_width_px":{"type":"integer"},"image_height_px":{"type":"integer"},"intent":{"type":"string"},"severity":severity_schema()},"required":["snapshot_id","x_px","y_px","image_width_px","image_height_px","intent","severity"],"additionalProperties":false}),
        ),
        (
            WAIT_FOR,
            "Wait for browser settlement or a queued browser event.",
            json!({"type":"object","properties":{"deadline_ms":{"type":"integer","minimum":0,"maximum":30000}},"additionalProperties":false}),
        ),
    ]
}

fn parse_severity(object: &Map<String, Value>) -> Result<Severity, BrowserError> {
    let value = object
        .get("severity")
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity".into(),
            reason_code: "missing_field",
        })?;
    let value = value
        .as_object()
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity".into(),
            reason_code: "wrong_type",
        })?;
    if let Some(field) = value
        .keys()
        .filter(|field| !matches!(field.as_str(), "tier" | "credential" | "financial"))
        .min()
    {
        return Err(BrowserError::InvalidRequest {
            field: format!("severity.{field}"),
            reason_code: "unknown_field",
        });
    }
    let tier = match value.get("tier") {
        None => {
            return Err(BrowserError::InvalidRequest {
                field: "severity.tier".into(),
                reason_code: "missing_field",
            })
        }
        Some(Value::Number(number)) => {
            number
                .as_u64()
                .ok_or_else(|| BrowserError::InvalidRequest {
                    field: "severity.tier".into(),
                    reason_code: "out_of_range",
                })?
        }
        Some(_) => {
            return Err(BrowserError::InvalidRequest {
                field: "severity.tier".into(),
                reason_code: "wrong_type",
            })
        }
    };
    if !(1..=5).contains(&tier) {
        return Err(BrowserError::InvalidRequest {
            field: "severity.tier".into(),
            reason_code: "out_of_range",
        });
    }
    let credential = value
        .get("credential")
        .and_then(Value::as_bool)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity.credential".into(),
            reason_code: "wrong_type",
        })?;
    let financial = value
        .get("financial")
        .and_then(Value::as_bool)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: "severity.financial".into(),
            reason_code: "wrong_type",
        })?;
    Ok(Severity::new(tier as u8, credential, financial))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, BrowserError> {
    let value = object
        .get(field)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "missing_field",
        })?;
    let value = value.as_str().ok_or_else(|| BrowserError::InvalidRequest {
        field: field.into(),
        reason_code: "wrong_type",
    })?;
    if value.len() < min || value.len() > max {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "out_of_range",
        });
    }
    Ok(value)
}
fn bounded_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
    min: usize,
    max: usize,
) -> Result<&'a str, BrowserError> {
    required_string(object, field, min, max)
}
fn optional_integer(
    object: &Map<String, Value>,
    field: &str,
    min: u64,
    max: u64,
) -> Result<Option<u64>, BrowserError> {
    let Some(value) = object.get(field) else {
        return Ok(None);
    };
    let value = value.as_u64().ok_or_else(|| BrowserError::InvalidRequest {
        field: field.into(),
        reason_code: "wrong_type",
    })?;
    if value < min || value > max {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "out_of_range",
        });
    }
    Ok(Some(value))
}
fn partial_error_result(error: &BrowserError) -> Value {
    let mut result = Map::new();
    result.insert("outcome".into(), Value::String(error.outcome().into()));
    result.insert("remedy".into(), Value::String(error.remedy().into()));
    if let Some(detail) = error.detail() {
        result.insert("detail".into(), detail);
    }
    Value::Object(result)
}

fn required_signed_integer(object: &Map<String, Value>, field: &str) -> Result<i128, BrowserError> {
    let value = object
        .get(field)
        .ok_or_else(|| BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "missing_field",
        })?;
    let value = value.as_i64().ok_or_else(|| BrowserError::InvalidRequest {
        field: field.into(),
        reason_code: "wrong_type",
    })?;
    if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&value) {
        return Err(BrowserError::InvalidRequest {
            field: field.into(),
            reason_code: "out_of_range",
        });
    }
    Ok(value as i128)
}
fn refusal_ring_config() -> RefusalRingConfig {
    RefusalRingConfig {
        records_per_caller: DEFAULT_REFUSAL_RECORDS_PER_CALLER,
    }
}

fn map_authorization_error(error: crate::authorization::AuthorizationError) -> BrowserError {
    match error {
        crate::authorization::AuthorizationError::NoGrant => {
            BrowserError::AuthorizationDenied { reason: "no_grant" }
        }
        crate::authorization::AuthorizationError::HazardNotDisclosed(missing) => {
            BrowserError::HazardNotDisclosed { missing }
        }
        crate::authorization::AuthorizationError::SeverityBelowFloor => {
            BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_below_floor",
            }
        }
        crate::authorization::AuthorizationError::SeverityUnclassifiable => {
            BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_unclassifiable",
            }
        }
        _ => BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        },
    }
}
fn origin_from_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "null".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    format!(
        "{}://{}",
        scheme.to_ascii_lowercase(),
        authority.to_ascii_lowercase()
    )
}
fn journal_outcome(error: &BrowserError) -> Outcome {
    match error {
        BrowserError::InvalidRequest { .. } => Outcome::InvalidRequest,
        BrowserError::AuthorizationDenied { .. } | BrowserError::HazardNotDisclosed { .. } => {
            Outcome::Denied
        }
        BrowserError::StaleSnapshot { .. }
        | BrowserError::RefNotFound { .. }
        | BrowserError::RefAmbiguous { .. }
        | BrowserError::ElementIntercepted
        | BrowserError::OutsideViewportAfterScroll { .. }
        | BrowserError::PointOutsideViewport { .. } => Outcome::StaleSnapshot,
        BrowserError::NoSession
        | BrowserError::BrowserLaunchPending
        | BrowserError::Internal { .. }
        | BrowserError::BrowserCrashed
        | BrowserError::NotSettled { .. }
        | BrowserError::NavigationPolicyRejected { .. }
        | BrowserError::InvalidCoordinates { .. }
        | BrowserError::ImageTooLarge { .. } => Outcome::InternalError,
    }
}
/// One journal capability per browser capability, with no collapsing.
///
/// The three observations used to fold onto Navigate, so a read of a page in a
/// durable profile persisted as a page load. That is worse than not recording
/// it: an absent entry is honest about being absent, and a wrong one is read as
/// authoritative -- permanently, since the journal directory is enrolled for
/// fleet backup.
fn journal_capability(capability: BrowserCapability) -> JournalCapability {
    match capability {
        BrowserCapability::Navigate => JournalCapability::Navigate,
        BrowserCapability::Click => JournalCapability::Click,
        BrowserCapability::ClickPoint => JournalCapability::ClickPoint,
        BrowserCapability::Snapshot => JournalCapability::Snapshot,
        BrowserCapability::Screenshot => JournalCapability::Screenshot,
        BrowserCapability::WaitFor => JournalCapability::WaitFor,
    }
}
fn map_journal_error(error: JournalError) -> BrowserError {
    BrowserError::Internal {
        reason_code: error.reason_code,
    }
}

fn map_navigation_drive_error(error: crate::browser_session::NavigationDriveError) -> BrowserError {
    let reason_code = match error {
        crate::browser_session::NavigationDriveError::Unavailable
        | crate::browser_session::NavigationDriveError::ConnectorFailure => {
            JournalReasonCode::ConnectorFailure
        }
        crate::browser_session::NavigationDriveError::CdpFailure => JournalReasonCode::CdpFailure,
    };
    BrowserError::Internal { reason_code }
}

fn map_snapshot_error(error: SnapshotError) -> BrowserError {
    match error {
        SnapshotError::WrongKind => BrowserError::StaleSnapshot {
            reason_code: "snapshot_kind_mismatch",
        },
        SnapshotError::EpochMismatch => BrowserError::StaleSnapshot {
            reason_code: "document_epoch_changed",
        },
        SnapshotError::Evicted | SnapshotError::NotFound => BrowserError::StaleSnapshot {
            reason_code: "snapshot_evicted",
        },
        SnapshotError::Ambiguous { candidate_count } => {
            BrowserError::RefAmbiguous { candidate_count }
        }
        SnapshotError::RetentionFull => BrowserError::Internal {
            reason_code: JournalReasonCode::ResultSerializationLimit,
        },
        SnapshotError::EpochOverflow
        | SnapshotError::BoundExceeded
        | SnapshotError::InvalidId
        | SnapshotError::InvalidRef
        | SnapshotError::IdentityOutOfBounds
        | SnapshotError::Serialization
        | SnapshotError::Teardown => BrowserError::Internal {
            reason_code: JournalReasonCode::InternalFailure,
        },
    }
}
fn map_coordinate_error(error: CoordinateError) -> BrowserError {
    match error {
        CoordinateError::InvalidCoordinates { reason } => {
            BrowserError::InvalidCoordinates { reason }
        }
        CoordinateError::ImageTooLarge {
            encoded_bytes,
            bound_bytes,
        } => BrowserError::ImageTooLarge {
            bytes: encoded_bytes,
            bound_bytes,
        },
        CoordinateError::CdpFailure => BrowserError::Internal {
            reason_code: JournalReasonCode::CdpFailure,
        },
    }
}

#[cfg(test)]
mod tests {

    /// Each browser capability maps to its OWN journal capability.
    ///
    /// Asserting the mapping rather than the enum, which is the mistake I made
    /// first: a test over `Capability::as_str` checks that the names differ
    /// from each other and never calls the function that decides which name a
    /// dispatch gets. Restoring the old fold -- Snapshot onto Navigate -- left
    /// that test green, because the enum was still correct and the mapping was
    /// not what it examined.
    ///
    /// The pairs are literals so a mapping change cannot satisfy this by moving
    /// both sides at once, and the injectivity check is what actually catches a
    /// fold, since a fold produces a duplicate rather than a wrong name.
    #[test]
    fn every_browser_capability_journals_under_its_own_name() {
        use std::collections::BTreeSet;

        let pairs = [
            (BrowserCapability::Navigate, JournalCapability::Navigate),
            (BrowserCapability::Click, JournalCapability::Click),
            (BrowserCapability::ClickPoint, JournalCapability::ClickPoint),
            (BrowserCapability::Snapshot, JournalCapability::Snapshot),
            (BrowserCapability::Screenshot, JournalCapability::Screenshot),
            (BrowserCapability::WaitFor, JournalCapability::WaitFor),
        ];

        let mut journaled = BTreeSet::new();
        for (browser, expected) in pairs {
            let actual = journal_capability(browser);
            assert_eq!(
                actual, expected,
                "{browser:?} journals as {actual:?}, not as itself"
            );
            assert!(
                journaled.insert(actual.as_str()),
                "{browser:?} shares a journal name with another capability"
            );
        }
        assert_eq!(
            journaled.len(),
            6,
            "a browser capability was added without a journal name of its own"
        );
    }

    /// An observation records no action, and an actuation records one.
    ///
    /// Both directions, because asserting only the None side passes if every
    /// capability returns None, which would empty the record of every action
    /// this journal exists to hold.
    #[test]
    fn only_actuating_capabilities_record_an_action() {
        for capability in [
            JournalCapability::Snapshot,
            JournalCapability::Screenshot,
            JournalCapability::WaitFor,
        ] {
            assert!(
                journal_action(capability).is_none(),
                "{capability:?} is an observation and performs no action"
            );
        }
        for capability in [
            JournalCapability::Navigate,
            JournalCapability::Click,
            JournalCapability::ClickPoint,
            JournalCapability::Type,
        ] {
            assert!(
                journal_action(capability).is_some(),
                "{capability:?} actuates and must record what it did"
            );
        }
    }
    use super::*;
    use serde_json::json;

    fn identity() -> RouteIdentity {
        RouteIdentity::from_bind(
            &subc_protocol::BindIdentity {
                project_root: "/tmp/project".into(),
                harness: "test".into(),
                session: "conversation".into(),
            },
            &Some(subc_protocol::Principal::Direct),
        )
    }

    fn severity() -> Value {
        json!({"tier":1,"credential":false,"financial":false})
    }

    /// A grant covering this module's test conversation and origin.
    ///
    /// The authorization gate always runs and an empty store covers nothing, so
    /// a test about anything downstream of it must arrive holding the authority
    /// a real caller would hold.
    fn test_grants() -> GrantStore {
        GrantStore::new([crate::authorization::ActionGrant::new(
            "browser-mod-test-grant",
            1,
            identity().conversation_key.clone(),
            crate::authorization::Severity {
                tier: 4,
                credential: false,
                financial: false,
            },
            ["https://example.test"],
        )])
    }

    #[tokio::test]
    async fn authorization_refusals_with_different_remedies_have_distinct_wire_outcomes() {
        let plane = BrowserPlane::new();
        let identity = identity();
        let denied = plane
            .result(
                &identity,
                Err(BrowserError::AuthorizationDenied { reason: "no_grant" }),
            )
            .await;
        let undisclosed = plane
            .result(
                &identity,
                Err(BrowserError::HazardNotDisclosed {
                    missing: HazardClass::CredentialFormSubmit,
                }),
            )
            .await;

        assert_eq!(denied["outcome"], "authorization_denied");
        assert_eq!(undisclosed["outcome"], "hazard_not_disclosed");
        assert_ne!(
            denied["outcome"], undisclosed["outcome"],
            "refusals requiring different grants must not collapse to one wire outcome"
        );
        assert_eq!(
            undisclosed["detail"]["missing_hazard"],
            "credential_form_submit"
        );
    }

    #[tokio::test]
    async fn every_browser_error_serializes_its_exact_caller_remedy() {
        let cases = vec![
            (
                "invalid_request",
                BrowserError::InvalidRequest {
                    field: "url".to_string(),
                    reason_code: "wrong_type",
                },
                "invalid_request",
                "correct detail.field according to detail.reason_code, then resubmit the request",
            ),
            (
                "no_session",
                BrowserError::NoSession,
                "no_session",
                "call browser.launch, then retry the browser action",
            ),
            (
                "browser_launch_pending",
                BrowserError::BrowserLaunchPending,
                "browser_launch_pending",
                "poll browser.status until the session is ready, then retry the browser action",
            ),
            (
                "stale_snapshot",
                BrowserError::StaleSnapshot {
                    reason_code: "document_epoch_changed",
                },
                "stale_snapshot",
                "call browser.snapshot again and use only its new snapshot_id and refs",
            ),
            (
                "ref_not_found",
                BrowserError::RefNotFound {
                    reference: "e1".to_string(),
                },
                "ref_not_found",
                "choose a ref listed in the snapshot identified by snapshot_id",
            ),
            (
                "ref_ambiguous",
                BrowserError::RefAmbiguous { candidate_count: 2 },
                "ref_ambiguous",
                "take a fresh browser.snapshot and choose a ref that identifies exactly one current element",
            ),
            (
                "element_intercepted",
                BrowserError::ElementIntercepted,
                "element_intercepted",
                "take a fresh browser.snapshot and choose a ref that currently exposes a clickable position",
            ),
            (
                "coordinates_out_of_bounds",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::PointOutOfBounds,
                },
                "invalid_coordinates",
                "address a pixel inside the declared image: 0 <= x < image_width_px and 0 <= y < image_height_px",
            ),
            (
                "coordinates_non_finite",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::NonFiniteMetadata,
                },
                "invalid_coordinates",
                "take a fresh screenshot: this one's retained geometry cannot be mapped",
            ),
            (
                "coordinates_non_positive_dimensions",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::NonPositiveDimensions,
                },
                "invalid_coordinates",
                "take a fresh screenshot: this one reports no area to address",
            ),
            (
                "coordinates_conversion_failure",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::ConversionFailure,
                },
                "invalid_coordinates",
                "take a fresh screenshot: this one's retained geometry cannot be mapped",
            ),
            (
                "coordinates_image_size_mismatch",
                BrowserError::InvalidCoordinates {
                    reason: InvalidCoordinatesReason::ImageSizeMismatch,
                },
                "invalid_coordinates",
                "send coordinates in the space of the image this module declared, and pass its image_width_px and image_height_px. If a model was shown a resized copy, multiply its coordinates by declared/shown before sending them.",
            ),
            (
                "image_too_large",
                BrowserError::ImageTooLarge {
                    bytes: 20,
                    bound_bytes: 10,
                },
                "image_too_large",
                "use browser.snapshot for a text observation, or reduce the viewport before capturing another image",
            ),
            (
                "authorization_denied",
                BrowserError::AuthorizationDenied { reason: "no_grant" },
                "authorization_denied",
                "call browser.open_grant to mint a grant covering this action, then retry",
            ),
            (
                "hazard_not_disclosed",
                BrowserError::HazardNotDisclosed {
                    missing: HazardClass::CredentialFormSubmit,
                },
                "hazard_not_disclosed",
                "call browser.open_grant to mint a grant that discloses detail.missing_hazard, then retry",
            ),
            (
                "navigation_policy_rejected",
                BrowserError::NavigationPolicyRejected {
                    reason_code: "scheme_not_allowed",
                },
                "navigation_policy_rejected",
                "navigate to an http or https URL allowed by browser policy",
            ),
            (
                "not_settled",
                BrowserError::NotSettled {
                    url_final: Some("https://example.test/".to_string()),
                    lifecycle: vec!["load".to_string()],
                    inflight_count: 1,
                    deadline_ms: 1_000,
                },
                "not_settled",
                "call browser.snapshot to re-observe the page before depending on its current state",
            ),
            (
                "browser_crashed",
                BrowserError::BrowserCrashed,
                "browser_crashed",
                "no caller remedy in v1: this module does not reconnect a crashed browser",
            ),
            (
                "internal_error",
                BrowserError::Internal {
                    reason_code: JournalReasonCode::InternalFailure,
                },
                "internal_error",
                "report this module failure with detail.reason_code and do not assume the action completed",
            ),
        ];
        let plane = BrowserPlane::new();
        let identity = identity();

        for (name, error, expected_outcome, expected_remedy) in cases {
            let reply = plane.result(&identity, Err(error)).await;
            assert_eq!(
                reply["outcome"], expected_outcome,
                "wrong outcome for {name}"
            );
            assert_eq!(reply["remedy"], expected_remedy, "wrong remedy for {name}");
        }
    }

    #[test]
    fn every_late_browser_refusal_names_its_exact_caller_remedy() {
        let cases = [
            (
                LateEvent::DownloadBlocked,
                "choose an in-page action that does not start a download",
            ),
            (
                LateEvent::JsDialogDismissed,
                "call browser.snapshot and continue from the page state after the dialog was dismissed",
            ),
            (
                LateEvent::NavigationPolicyRejected {
                    reason_code: "scheme_not_allowed".to_string(),
                },
                "navigate to an http or https URL allowed by browser policy",
            ),
            (
                LateEvent::AuthorizationDenied {
                    reason: "no_grant".to_string(),
                },
                "call browser.open_grant to mint a grant covering this action, then retry",
            ),
        ];

        for (event, expected_remedy) in cases {
            assert_eq!(
                event.remedy(),
                expected_remedy,
                "wrong remedy for {event:?}"
            );
        }
    }

    #[tokio::test]
    async fn six_tools_have_closed_descriptors_and_browser_type_is_absent() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 6);
        assert!(!tools.iter().any(|(name, _, _)| *name == "browser.type"));
        assert!(tools
            .iter()
            .all(|(_, _, schema)| schema["additionalProperties"] == false));
        let (_, description, schema) = tools
            .iter()
            .find(|(name, _, _)| *name == SCREENSHOT)
            .expect("screenshot remains dispatchable even though wire advertisement filters it");
        assert!(description.contains("PNG base64"));
        assert_eq!(schema["properties"]["max_bytes"]["type"], "integer");
        assert_eq!(schema["properties"]["max_bytes"]["minimum"], 1);
        assert_eq!(
            schema["properties"]["max_bytes"]["maximum"],
            MAX_ENCODED_PNG_BYTES
        );
    }

    /// Every capability the dispatcher accepts is also advertised.
    ///
    /// `handle_tool` admits any name [`BrowserCapability::parse`] recognizes,
    /// while the manifest is built from [`tool_definitions`], which is a list
    /// rather than a match -- so a capability added to the enum and wired
    /// through dispatch stays dispatchable without ever being declared, and a
    /// test that only counts the list still sees the expected number. The
    /// exhaustive match below exists so that adding a variant fails to compile
    /// here, forcing that decision to be made rather than defaulted.
    #[test]
    fn every_dispatchable_capability_is_advertised() {
        fn enumerate(capability: BrowserCapability) -> BrowserCapability {
            match capability {
                BrowserCapability::Navigate
                | BrowserCapability::Snapshot
                | BrowserCapability::Click
                | BrowserCapability::Screenshot
                | BrowserCapability::ClickPoint
                | BrowserCapability::WaitFor => capability,
            }
        }

        let dispatchable = [
            BrowserCapability::Navigate,
            BrowserCapability::Snapshot,
            BrowserCapability::Click,
            BrowserCapability::Screenshot,
            BrowserCapability::ClickPoint,
            BrowserCapability::WaitFor,
        ]
        .map(enumerate);

        let advertised: Vec<&str> = tool_definitions()
            .iter()
            .map(|(name, _, _)| *name)
            .collect();
        for capability in dispatchable {
            assert!(
                advertised.contains(&capability.name()),
                "{} is dispatchable but not advertised",
                capability.name()
            );
        }
        assert_eq!(
            advertised.len(),
            dispatchable.len(),
            "a tool is advertised that no capability dispatches"
        );
    }

    #[tokio::test]
    async fn navigation_without_a_session_never_opens_an_operation_bracket() {
        let plane = BrowserPlane::new().with_grants_installed(test_grants());
        let identity = identity();
        plane.open_context(identity.clone()).await.unwrap();
        let request = json!({"url":"https://example.test/","intent":"go","severity":severity(),"wait":"none"});
        let result = plane
            .dispatch(&identity, BrowserCapability::Navigate, &request)
            .await;

        assert_eq!(result["outcome"], "no_session");
        assert!(plane.operation_log().await.is_empty());
    }

    #[tokio::test]
    async fn wait_consumes_late_event_before_session_state() {
        let plane = BrowserPlane::new();
        let identity = identity();
        plane
            .queue_event(&identity, LateEvent::DownloadBlocked)
            .await;
        let result = plane
            .dispatch(
                &identity,
                BrowserCapability::WaitFor,
                &json!({"deadline_ms":0}),
            )
            .await;
        assert_eq!(result["outcome"], "unsupported_download");
        assert_eq!(
            result["remedy"],
            "choose an in-page action that does not start a download"
        );
    }
}
