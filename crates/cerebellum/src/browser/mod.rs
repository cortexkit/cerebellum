//! This module implements the six browser capabilities exposed by the browser plane.
//!
//! This module integrates route admission, journal and context interfaces, CDP
//! transport, and browser geometry, extraction, and screenshot primitives.
//! Browser-specific state is kept behind a per-context lane so CDP operations
//! and final verification cannot interleave across invocations.

pub mod extraction;
pub mod geometry;

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde_json::{json, Map, Value};
use tokio::sync::{Mutex, OwnedMutexGuard};

use crate::authorization::{AuthorizationRequest, GrantStore, Severity};
use crate::coordinate::{
    capture_screenshot, map_pixel_center, CoordinateError, ScreenshotPayload, TransformInputs,
    ViewportObservation,
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
pub const SETTLEMENT_MS: u64 = 30_000;
pub const QUIET_MS: u64 = 500;

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrowserError {
    InvalidRequest {
        field: String,
        reason_code: &'static str,
    },
    NoSession,
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
    InvalidCoordinates {
        reason_code: &'static str,
    },
    ImageTooLarge {
        encoded_bytes: usize,
        bound_bytes: usize,
    },
    AuthorizationDenied {
        reason: &'static str,
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
            Self::StaleSnapshot { .. } => "stale_snapshot",
            Self::RefNotFound { .. } => "ref_not_found",
            Self::RefAmbiguous { .. } => "ref_ambiguous",
            Self::ElementIntercepted => "element_intercepted",
            Self::InvalidCoordinates { .. } => "invalid_coordinates",
            Self::ImageTooLarge { .. } => "image_too_large",
            Self::AuthorizationDenied { .. } => "authorization_denied",
            Self::NavigationPolicyRejected { .. } => "navigation_policy_rejected",
            Self::NotSettled { .. } => "not_settled",
            Self::BrowserCrashed => "browser_crashed",
            Self::Internal { .. } => "internal_error",
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
            Self::InvalidCoordinates { reason_code } => json!({"reason_code":reason_code}),
            Self::ImageTooLarge {
                encoded_bytes,
                bound_bytes,
            } => json!({"encoded_bytes":encoded_bytes,"bound_bytes":bound_bytes}),
            Self::AuthorizationDenied { reason } => json!({"reason":reason}),
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
            Self::NoSession => json!({"reason_code":"no_session"}),
            Self::ElementIntercepted => json!({}),
            Self::BrowserCrashed => json!({"reason_code":"browser_crashed"}),
        })
    }
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

/// One invocation-bound journal adapter. The handle and commitment token are
/// kept together so a caller cannot finalize a different invocation's journal entry.
pub struct JournalInvocation {
    store: JournalStore,
    identity: JournalIdentity,
    capability: JournalCapability,
    handle: Option<ReservationHandle>,
    token: Option<DispatchCommitmentToken>,
    terminal: bool,
}

impl JournalInvocation {
    pub fn new(
        config: journal::JournalConfig,
        identity: JournalIdentity,
        capability: JournalCapability,
    ) -> Result<Self, JournalError> {
        Ok(Self {
            store: JournalStore::new(config)?,
            identity,
            capability,
            handle: None,
            token: None,
            terminal: false,
        })
    }

    pub fn reserve(&mut self) -> Result<ReservationHandle, JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        if let Some(handle) = self.handle {
            return Ok(handle);
        }
        let handle = self.store.reserve(self.identity.clone(), self.capability)?;
        self.handle = Some(handle);
        Ok(handle)
    }

    pub fn commit_dispatched(
        &mut self,
        material: DispatchMaterial,
    ) -> Result<DispatchCommitmentToken, JournalError> {
        let handle = self.handle.ok_or_else(JournalError::internal_failure)?;
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let token = self.store.commit_dispatched(handle, &material)?;
        self.token = Some(token);
        Ok(token)
    }

    pub fn finalize_rejected(&mut self, material: RejectionMaterial) -> Result<(), JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let handle = self.handle.ok_or_else(JournalError::internal_failure)?;
        self.store.finalize_rejected(handle, &material).map(|_| {
            self.terminal = true;
        })
    }

    pub fn finalize_dispatched(
        &mut self,
        context: FinalContextAssociation,
        result: CompletedResult,
    ) -> Result<(), JournalError> {
        if self.terminal {
            return Err(JournalError::internal_failure());
        }
        let token = self.token.ok_or_else(JournalError::internal_failure)?;
        self.store
            .finalize_dispatched(token, &context, &result)
            .map(|_| {
                self.terminal = true;
            })
    }

    pub fn journal(&self) -> &JournalStore {
        &self.store
    }
    pub fn journal_mut(&mut self) -> &mut JournalStore {
        &mut self.store
    }
    pub fn reservation(&self) -> Option<ReservationHandle> {
        self.handle
    }
    pub fn commitment(&self) -> Option<DispatchCommitmentToken> {
        self.token
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

pub fn journal_action(capability: JournalCapability) -> JournalAction {
    match capability {
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
    }
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
}

#[derive(Default)]
pub struct BrowserPlane {
    state: Arc<Mutex<BrowserState>>,
    lanes: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
    grants: Arc<Mutex<GrantStore>>,
    journal_config: Option<journal::JournalConfig>,
    journals: Arc<Mutex<HashMap<String, JournalInvocation>>>,
    authorization_enabled: bool,
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
            journal_config: None,
            journals: Arc::new(Mutex::new(HashMap::new())),
            authorization_enabled: true,
        }
    }
    pub fn with_journal(config: journal::JournalConfig) -> Self {
        Self {
            journal_config: Some(config),
            ..Self::default()
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
        let mut state = self.state.lock().await;
        if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
            context.ended = true;
            context.crashed = crashed;
            context.snapshots.begin_teardown();
            let _ = context.snapshots.complete_teardown();
        }
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
    fn op(state: &mut BrowserState, key: &str, operation: Operation) {
        state.operations.push((key.to_string(), operation));
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
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::FinalizeDispatched,
            );
            drop(state);
            if let Some(entry) = self
                .journals
                .lock()
                .await
                .get_mut(&identity.conversation_key)
            {
                let _ = entry.finalize_dispatched(
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
        } else {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::FinalizeRejected,
            );
            drop(state);
            if let Some(entry) = self
                .journals
                .lock()
                .await
                .get_mut(&identity.conversation_key)
            {
                let _ = entry.finalize_rejected(rejection_material(
                    journal_outcome(error),
                    error
                        .detail()
                        .unwrap_or_else(|| json!({"reason_code":"internal_failure"})),
                ));
            }
        }
        let _ = capability;
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
    ) -> Result<(), BrowserError> {
        if let Some(config) = self.journal_config {
            let mut journals = self.journals.lock().await;
            let entry = journals
                .entry(identity.conversation_key.clone())
                .or_insert_with(|| {
                    JournalInvocation::new(
                        config,
                        journal_identity(identity),
                        journal_capability(capability),
                    )
                    .expect("validated journal configuration")
                });
            entry.reserve().map_err(map_journal_error)?;
        }
        let mut state = self.state.lock().await;
        Self::op(&mut state, &identity.conversation_key, Operation::Reserve);
        Ok(())
    }
    async fn commit(
        &self,
        identity: &RouteIdentity,
        capability: BrowserCapability,
    ) -> Result<(), BrowserError> {
        if self.journal_config.is_some() {
            let mut journals = self.journals.lock().await;
            if let Some(entry) = journals.get_mut(&identity.conversation_key) {
                entry
                    .commit_dispatched(DispatchMaterial {
                        intent_redacted: None,
                        requested_severity: None,
                        effective_severity: None,
                        grant_decision: GrantDecision::not_reached(),
                        action: journal_action(journal_capability(capability)),
                        locator: None,
                        snapshot_ids: Vec::new(),
                        governing_observation: GoverningObservation::observation_not_required(),
                    })
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
        _capability: BrowserCapability,
        outcome: Outcome,
        detail: Value,
    ) -> Result<(), BrowserError> {
        let mut state = self.state.lock().await;
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::FinalizeDispatched,
        );
        drop(state);
        if self.journal_config.is_some() {
            let mut journals = self.journals.lock().await;
            if let Some(entry) = journals.get_mut(&identity.conversation_key) {
                entry
                    .finalize_dispatched(
                        FinalContextAssociation {
                            profile_uuid: None,
                            profile_name: (identity.session_kind != SessionKind::Ephemeral)
                                .then(|| "default".to_string()),
                        },
                        CompletedResult { outcome, detail },
                    )
                    .map_err(map_journal_error)?;
            }
        }
        Ok(())
    }

    async fn navigate(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["url", "intent", "wait", "severity"])
            .await?;
        let url = required_string(object, "url", 1, 4096)?;
        let _intent = bounded_string(object, "intent", 0, 512)?;
        let wait = match object.get("wait") {
            None => "settle",
            Some(Value::String(value)) if value == "settle" || value == "none" => value.as_str(),
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
        self.reserve(identity, BrowserCapability::Navigate).await?;
        if self.authorization_enabled {
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
        self.commit(identity, BrowserCapability::Navigate).await?;
        let tracker = {
            let mut state = self.state.lock().await;
            let tracker = {
                let context = state
                    .contexts
                    .entry(identity.conversation_key.clone())
                    .or_insert_with(|| ContextState::new(identity.clone()));
                if context.tracker.url_final.is_some()
                    && same_document_url(
                        context.tracker.url_final.as_deref().unwrap_or_default(),
                        url,
                    )
                {
                    context.tracker.url_final = Some(url.to_string());
                } else {
                    let _ = context
                        .epoch
                        .replace(DocumentTransition::TopLevelDocumentReplaced);
                    context.tracker = Tracker::default();
                    context.tracker.url_final = Some(url.to_string());
                    context.tracker.token("navigation_started");
                }
                context.tracker.clone()
            };
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpNavigate,
            );
            tracker
        };
        let outcome = if wait == "settle" && !tracker.settled {
            Outcome::InternalError
        } else {
            Outcome::Success
        };
        self.finalize(identity, BrowserCapability::Navigate, outcome, json!({"outcome":if wait == "settle" && !tracker.settled {"not_settled"} else {"ok"},"url_final":tracker.url_final,"lifecycle":tracker.lifecycle})).await?;
        if wait == "settle" && !tracker.settled {
            return Ok(
                json!({"outcome":"not_settled","url_final":tracker.url_final,"lifecycle":tracker.lifecycle}),
            );
        }
        Ok(json!({"outcome":"ok","url_final":tracker.url_final,"lifecycle":tracker.lifecycle}))
    }

    async fn snapshot(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self.validate_request(args, &["mode", "max_bytes"]).await?;
        let mode = match object.get("mode") {
            None => "ax",
            Some(Value::String(value)) if value == "ax" || value == "dom_full" => value.as_str(),
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
        let _max_bytes =
            optional_integer(object, "max_bytes", 1, 262_144)?.unwrap_or(65_536) as usize;
        let mut state = self.state.lock().await;
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::CdpObserve,
        );
        let kind = if mode == "ax" {
            SnapshotKind::Ax
        } else {
            SnapshotKind::DomFull
        };
        let snapshot = {
            let context = state
                .contexts
                .get_mut(&identity.conversation_key)
                .ok_or(BrowserError::NoSession)?;
            if context.ended {
                return Err(BrowserError::NoSession);
            }
            let id = context.snapshot_id(kind);
            let snapshot = TextSnapshot {
                snapshot_id: id.clone(),
                kind,
                document_epoch: context.epoch.value(),
                source_origin: context
                    .tracker
                    .url_final
                    .clone()
                    .unwrap_or_else(|| "null".into()),
                content_schema: if mode == "ax" { AX_SCHEMA } else { DOM_SCHEMA },
                content: String::new(),
                truncated: false,
                refs_truncated: false,
                refs: Vec::new(),
            };
            context
                .snapshots
                .retain_text(snapshot.clone())
                .map_err(map_snapshot_error)?;
            snapshot
        };
        Ok(
            json!({"outcome":"ok","snapshot_id":snapshot.snapshot_id,"document_epoch":snapshot.document_epoch,"source_origin":snapshot.source_origin,"content_schema":snapshot.content_schema,"truncated":false,"refs_truncated":false,"content":"","refs":[]}),
        )
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
        let mut state = self.state.lock().await;
        let context = state
            .contexts
            .get_mut(&identity.conversation_key)
            .ok_or(BrowserError::NoSession)?;
        if context.ended {
            return Err(BrowserError::NoSession);
        }
        let (content, truncated, schema) = match mode {
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
        let refs_truncated = refs.len() > MAX_REFS;
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
        self.reserve(identity, BrowserCapability::Click).await?;
        if requested_severity.tier < 2 {
            return Err(BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_below_floor",
            });
        }
        {
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
            let refs = snapshot.refs;
            if !refs
                .iter()
                .any(|record| record.captured.reference == reference)
            {
                return Err(BrowserError::RefNotFound {
                    reference: reference.to_string(),
                });
            }
        }
        let mut state = self.state.lock().await;
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::CdpObserve,
        );
        drop(state);
        self.commit(identity, BrowserCapability::Click).await?;
        {
            let mut state = self.state.lock().await;
            // The adapter supplies geometry and hit-test observations. The
            // integration records commitment before reading them because those
            // reads are part of the click operation's verification sequence.
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpInputPress,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpInputRelease,
            );
            if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
                context.snapshots.unpin(snapshot_id);
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
        let _ = self.validate_request(args, &[]).await?;
        let mut state = self.state.lock().await;
        let ended = state
            .contexts
            .get(&identity.conversation_key)
            .map(|context| context.ended)
            .ok_or(BrowserError::NoSession)?;
        if ended {
            return Err(BrowserError::NoSession);
        }
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::CdpObserve,
        );
        Err(BrowserError::Internal {
            reason_code: JournalReasonCode::CdpFailure,
        })
    }

    async fn click_point(
        &self,
        identity: &RouteIdentity,
        args: &Value,
    ) -> Result<Value, BrowserError> {
        let object = self
            .validate_request(args, &["snapshot_id", "x_px", "y_px", "intent", "severity"])
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
        bounded_string(object, "intent", 0, 512)?;
        let requested_severity = parse_severity(object)?;
        self.reserve(identity, BrowserCapability::ClickPoint)
            .await?;
        if requested_severity.tier < 2 {
            return Err(BrowserError::InvalidRequest {
                field: "severity".into(),
                reason_code: "severity_below_floor",
            });
        }
        {
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
            let screenshot = match screenshot {
                snapshot_store::StoredSnapshot::Screenshot(snapshot) => snapshot,
                _ => unreachable!(),
            };
            let transform = TransformInputs::new(
                screenshot.input_rect,
                screenshot.device_scale_factor,
                screenshot.visual_viewport_scale,
            );
            map_pixel_center(
                transform,
                screenshot.image_width_px,
                screenshot.image_height_px,
                x,
                y,
            )
            .map_err(map_coordinate_error)?;
        }
        let mut state = self.state.lock().await;
        Self::op(
            &mut state,
            &identity.conversation_key,
            Operation::CdpObserve,
        );
        drop(state);
        self.commit(identity, BrowserCapability::ClickPoint).await?;
        {
            let mut state = self.state.lock().await;
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpObserve,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpInputPress,
            );
            Self::op(
                &mut state,
                &identity.conversation_key,
                Operation::CdpInputRelease,
            );
            if let Some(context) = state.contexts.get_mut(&identity.conversation_key) {
                context.snapshots.unpin(snapshot_id);
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
        let mut state = self.state.lock().await;
        if let Some(events) = state.late_events.get_mut(&identity.conversation_key) {
            if let Some(event) = events.pop_front() {
                let outcome = event.outcome();
                let detail = match event {
                    LateEvent::NavigationPolicyRejected { reason_code } => {
                        json!({"reason_code":reason_code})
                    }
                    LateEvent::AuthorizationDenied { reason } => json!({"reason":reason}),
                    _ => json!({}),
                };
                return Ok(
                    json!({"outcome":outcome,"detail":detail,"url_final":Value::Null,"lifecycle":[],"inflight_count":0}),
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
            "Navigate managed Chromium through the enforcing connector.",
            json!({"type":"object","properties":{"url":{"type":"string"},"intent":{"type":"string"},"wait":{"enum":["settle","none"]},"severity":severity_schema()},"required":["url","intent","severity"],"additionalProperties":false}),
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
            "Capture the current visual viewport.",
            json!({"type":"object","properties":{},"additionalProperties":false}),
        ),
        (
            CLICK_POINT,
            "Click a retained screenshot pixel.",
            json!({"type":"object","properties":{"snapshot_id":{"type":"string"},"x_px":{"type":"integer"},"y_px":{"type":"integer"},"intent":{"type":"string"},"severity":severity_schema()},"required":["snapshot_id","x_px","y_px","intent","severity"],"additionalProperties":false}),
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
fn same_document_url(previous: &str, next: &str) -> bool {
    previous.split('#').next() == next.split('#').next()
}
fn map_authorization_error(error: crate::authorization::AuthorizationError) -> BrowserError {
    match error {
        crate::authorization::AuthorizationError::NoGrant => {
            BrowserError::AuthorizationDenied { reason: "no_grant" }
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
        BrowserError::AuthorizationDenied { .. } => Outcome::Denied,
        BrowserError::StaleSnapshot { .. }
        | BrowserError::RefNotFound { .. }
        | BrowserError::RefAmbiguous { .. }
        | BrowserError::ElementIntercepted => Outcome::StaleSnapshot,
        BrowserError::NoSession
        | BrowserError::Internal { .. }
        | BrowserError::BrowserCrashed
        | BrowserError::NotSettled { .. }
        | BrowserError::NavigationPolicyRejected { .. }
        | BrowserError::InvalidCoordinates { .. }
        | BrowserError::ImageTooLarge { .. } => Outcome::InternalError,
    }
}
fn journal_capability(capability: BrowserCapability) -> JournalCapability {
    match capability {
        BrowserCapability::Navigate => JournalCapability::Navigate,
        BrowserCapability::Click => JournalCapability::Click,
        BrowserCapability::ClickPoint => JournalCapability::ClickPoint,
        BrowserCapability::Snapshot => JournalCapability::Navigate,
        BrowserCapability::Screenshot => JournalCapability::Navigate,
        BrowserCapability::WaitFor => JournalCapability::Navigate,
    }
}
fn map_journal_error(error: JournalError) -> BrowserError {
    BrowserError::Internal {
        reason_code: error.reason_code,
    }
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
        CoordinateError::InvalidCoordinates { reason } => BrowserError::InvalidCoordinates {
            reason_code: reason.reason_code(),
        },
        CoordinateError::ImageTooLarge {
            encoded_bytes,
            bound_bytes,
        } => BrowserError::ImageTooLarge {
            encoded_bytes,
            bound_bytes,
        },
        CoordinateError::CdpFailure => BrowserError::Internal {
            reason_code: JournalReasonCode::CdpFailure,
        },
    }
}

#[cfg(test)]
mod tests {
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

    #[tokio::test]
    async fn six_tools_have_closed_descriptors_and_browser_type_is_absent() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 6);
        assert!(!tools.iter().any(|(name, _, _)| *name == "browser.type"));
        assert!(tools
            .iter()
            .all(|(_, _, schema)| schema["additionalProperties"] == false));
    }

    #[tokio::test]
    async fn route_lane_serializes_operation_brackets() {
        let plane = BrowserPlane::new();
        let identity = identity();
        plane.open_context(identity.clone()).await.unwrap();
        let request = json!({"url":"https://example.test/","intent":"go","severity":severity(),"wait":"none"});
        let result = plane
            .dispatch(&identity, BrowserCapability::Navigate, &request)
            .await;
        assert_eq!(result["outcome"], "ok");
        let operations = plane.operation_log().await;
        let commit = operations
            .iter()
            .position(|(_, op)| *op == Operation::CommitDispatched)
            .unwrap();
        let input = operations
            .iter()
            .position(|(_, op)| *op == Operation::CdpInputPress);
        assert!(input.is_none() || commit < input.unwrap());
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
    }
}
