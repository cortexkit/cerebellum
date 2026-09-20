//! Computer-plane pixel custody and accessibility redaction.
//!
//! Pixel bytes are stored outside the journal.  The journal stores only a
//! descriptor attachment, and a capture becomes readable only after that
//! attachment is durable.  The storage model below is intentionally small and
//! deterministic so the same staged protocol can be used by a native store and
//! by the conformance fixtures.

use cerebellum_core::identity::SessionKind;
use cerebellum_core::journal::redaction::{redact_then_truncate, Redactor};
use cerebellum_core::journal::{
    ActionObligationId, JournalIdentity, JournalReason, ObligationAttachment, TerminalKind,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::{Arc, Mutex};

pub type CaptureArtifactId = String;
pub type RetentionPinId = String;

/// The only pixel capture scopes accepted by C2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureScope {
    PerWindow,
    BroadGrant,
}

/// A grant is explicit and cannot be inferred from a target or a caller label.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureGrant {
    pub grant_id: String,
    pub scope: CaptureScope,
    pub issued_at: u64,
    pub expires_at: u64,
    pub verifiable: bool,
    pub authorizes_durable_retention: bool,
}

impl CaptureGrant {
    pub fn new(
        grant_id: impl Into<String>,
        scope: CaptureScope,
        issued_at: u64,
        expires_at: u64,
    ) -> Self {
        Self {
            grant_id: grant_id.into(),
            scope,
            issued_at,
            expires_at,
            verifiable: true,
            authorizes_durable_retention: true,
        }
    }

    fn valid_for(&self, scope: CaptureScope, now: u64) -> Result<(), GrantFailure> {
        if self.expires_at <= now {
            return Err(GrantFailure::Expired);
        }
        if self.scope != scope {
            return Err(GrantFailure::ScopeMismatch);
        }
        if !self.verifiable || self.expires_at <= self.issued_at {
            return Err(GrantFailure::Unverifiable);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum GrantFailure {
    Absent,
    Expired,
    ScopeMismatch,
    Unverifiable,
}

/// A deterministic in-memory grant authority suitable for native bindings and
/// restart fixtures.  Grants are kept separate from artifacts and journal bytes.
#[derive(Debug, Clone, Default)]
pub struct InMemoryGrantAuthority {
    grants: BTreeMap<String, CaptureGrant>,
}

impl InMemoryGrantAuthority {
    pub fn insert(&mut self, grant: CaptureGrant) {
        self.grants.insert(grant.grant_id.clone(), grant);
    }

    pub fn grant(&self, grant_id: &str) -> Option<&CaptureGrant> {
        self.grants.get(grant_id)
    }

    fn validate(
        &self,
        grant_id: Option<&str>,
        scope: CaptureScope,
        now: u64,
    ) -> Result<Option<&CaptureGrant>, GrantFailure> {
        let Some(grant_id) = grant_id else {
            return if scope == CaptureScope::BroadGrant {
                Err(GrantFailure::Absent)
            } else {
                Ok(None)
            };
        };
        let grant = self.grants.get(grant_id).ok_or(GrantFailure::Absent)?;
        grant.valid_for(scope, now).map(|()| Some(grant))
    }
}

/// Bounds are release inputs.  There are no implementation defaults in the
/// custody protocol; the constructor rejects zero values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustodyBounds {
    pub maximum_verification_duration_ms: u64,
    pub maximum_pin_lifetime_ms: u64,
    pub maximum_concurrently_pinned_artifacts: u64,
    pub maximum_total_pinned_artifact_bytes: u64,
    pub maximum_custody_attachment_bytes: u64,
}

impl CustodyBounds {
    pub fn validate(self) -> Result<Self, CustodyUnavailable> {
        if self.maximum_verification_duration_ms == 0
            || self.maximum_pin_lifetime_ms == 0
            || self.maximum_concurrently_pinned_artifacts == 0
            || self.maximum_total_pinned_artifact_bytes == 0
            || self.maximum_custody_attachment_bytes == 0
        {
            return Err(CustodyUnavailable);
        }
        Ok(self)
    }
}

/// The closed descriptor stored in a journal attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureDescriptor {
    pub captured_at: u64,
    pub target_window_id: Option<String>,
    pub owning_process_id: Option<u32>,
    pub width_px: u32,
    pub height_px: u32,
    pub artifact_sha256: String,
    pub capture_scope: CaptureScope,
    pub grant_id: Option<String>,
}

impl CaptureDescriptor {
    fn validate(&self) -> Result<(), CaptureRefusedCause> {
        if self.width_px == 0 || self.height_px == 0 || self.artifact_sha256.len() != 64 {
            return Err(CaptureRefusedCause::CustodyUnavailable);
        }
        match self.capture_scope {
            CaptureScope::PerWindow => {
                if self.target_window_id.is_none() || self.owning_process_id.is_none() {
                    return Err(CaptureRefusedCause::CustodyUnavailable);
                }
            }
            CaptureScope::BroadGrant => {
                if self.target_window_id.is_some()
                    || self.owning_process_id.is_some()
                    || self.grant_id.is_none()
                {
                    return Err(CaptureRefusedCause::CustodyUnavailable);
                }
            }
        }
        if self.grant_id.as_deref().is_some_and(str::is_empty) {
            return Err(CaptureRefusedCause::CustodyUnavailable);
        }
        Ok(())
    }
}

/// Pixel bytes plus only the fields from which the closed descriptor is made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PixelArtifact {
    pub bytes: Vec<u8>,
    pub captured_at: u64,
    pub target_window_id: Option<String>,
    pub owning_process_id: Option<u32>,
    pub width_px: u32,
    pub height_px: u32,
    pub capture_scope: CaptureScope,
    pub grant_id: Option<String>,
}

impl PixelArtifact {
    pub fn per_window(
        bytes: Vec<u8>,
        captured_at: u64,
        target_window_id: impl Into<String>,
        owning_process_id: u32,
        width_px: u32,
        height_px: u32,
    ) -> Self {
        Self {
            bytes,
            captured_at,
            target_window_id: Some(target_window_id.into()),
            owning_process_id: Some(owning_process_id),
            width_px,
            height_px,
            capture_scope: CaptureScope::PerWindow,
            grant_id: None,
        }
    }

    pub fn broad_grant(
        bytes: Vec<u8>,
        captured_at: u64,
        width_px: u32,
        height_px: u32,
        grant_id: impl Into<String>,
    ) -> Self {
        Self {
            bytes,
            captured_at,
            target_window_id: None,
            owning_process_id: None,
            width_px,
            height_px,
            capture_scope: CaptureScope::BroadGrant,
            grant_id: Some(grant_id.into()),
        }
    }

    pub fn descriptor(&self) -> CaptureDescriptor {
        CaptureDescriptor {
            captured_at: self.captured_at,
            target_window_id: self.target_window_id.clone(),
            owning_process_id: self.owning_process_id,
            width_px: self.width_px,
            height_px: self.height_px,
            artifact_sha256: hex_digest(&Sha256::digest(&self.bytes)),
            capture_scope: self.capture_scope,
            grant_id: self.grant_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureAdmissionToken {
    token_id: u64,
    action_obligation_id: ActionObligationId,
    identity_digest: [u8; 32],
    capture_scope: CaptureScope,
    grant_digest: Option<[u8; 32]>,
    process_epoch: u64,
}

impl CaptureAdmissionToken {
    pub fn action_obligation_id(&self) -> ActionObligationId {
        self.action_obligation_id
    }

    pub fn capture_scope(&self) -> CaptureScope {
        self.capture_scope
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePrepareRefusalCause {
    ObligationNotDurable,
    ObligationAlreadyTerminal,
    ObligationUnknown,
    ObligationNotActive,
    ArtifactAlreadyAdmitted,
    PreparationAlreadyActive,
    GrantAbsent,
    GrantExpired,
    GrantScopeMismatch,
    GrantUnverifiable,
    BoundUnavailable,
    CustodyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturePrepareRefused {
    pub cause: CapturePrepareRefusalCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureRefusedCause {
    TokenInvalid,
    TokenConsumed,
    ArtifactAlreadyAdmitted,
    ObligationNotActive,
    IdentityMismatch,
    CaptureScopeMismatch,
    GrantExpired,
    GrantScopeMismatch,
    GrantUnverifiable,
    BoundUnavailable,
    JournalAttachmentFailed,
    CustodyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureRefused {
    pub cause: CaptureRefusedCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapturePinRefusalCause {
    GrantAbsent,
    GrantExpired,
    GrantScopeMismatch,
    GrantUnverifiable,
    ExpiryInvalid,
    ExpiryExceedsMaxPinLifetime,
    PinCountBoundReached,
    ArtifactBytesBoundReached,
    VerificationWindowClosed,
    ArtifactUnavailable,
    ObligationAlreadyTerminal,
    ObligationUnknown,
    BoundUnavailable,
    JournalAttachmentFailed,
    CustodyUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapturePinRefused {
    pub cause: CapturePinRefusalCause,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CustodyUnavailable;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CustodyError {
    StorageUnavailable,
    InvalidStagedAdmission,
    InvalidPendingPin,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionPin {
    pub retention_pin_id: RetentionPinId,
    pub grant_id: String,
    pub artifact_sha256: String,
    pub created_at: u64,
    pub expires_at: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PinTerminalState {
    Active,
    Released,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureReleaseResult {
    Released,
    RetentionPinUnknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CustodySweepResult {
    pub expired_pin_count: u64,
    pub unreadable_artifact_count: u64,
    pub deletion_attempt_count: u64,
    pub deletion_failure_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ArtifactState {
    PendingAttachment,
    Admitted,
}

#[derive(Debug, Clone)]
struct ArtifactRecord {
    obligation_id: ActionObligationId,
    descriptor: CaptureDescriptor,
    bytes: Option<Vec<u8>>,
    state: ArtifactState,
    readable: bool,
    verification_window_open: bool,
    attachment_revision: u64,
    retention_pin_id: Option<RetentionPinId>,
    deletion_pending: bool,
    deletion_failures_remaining: u64,
}

#[derive(Debug, Clone)]
struct PinRecord {
    pin: RetentionPin,
    state: PinTerminalState,
}

#[derive(Debug, Clone, Default)]
struct CustodyState {
    next_artifact_id: u64,
    next_pin_id: u64,
    next_token_id: u64,
    process_epoch: u64,
    terminal_cursor: u64,
    artifacts: BTreeMap<CaptureArtifactId, ArtifactRecord>,
    pins: BTreeMap<RetentionPinId, PinRecord>,
    pending_preparations: BTreeMap<u64, CaptureAdmissionToken>,
    consumed_tokens: BTreeSet<u64>,
    pending_pins: BTreeMap<RetentionPinId, (CaptureArtifactId, RetentionPin)>,
}

/// Clone this storage before opening a second process instance to model restart.
#[derive(Debug, Clone, Default)]
pub struct InMemoryCustodyStorage {
    state: Arc<Mutex<CustodyState>>,
}

impl InMemoryCustodyStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub struct StagedAdmission {
    pub artifact_id: CaptureArtifactId,
    pub action_obligation_id: ActionObligationId,
    pub descriptor: CaptureDescriptor,
}

#[derive(Debug, Clone)]
pub struct PendingPin {
    pub retention_pin_id: RetentionPinId,
    pub artifact_id: CaptureArtifactId,
    pub pin: RetentionPin,
}

/// A custody store with an explicit grant authority and immutable bounds.
#[derive(Debug, Clone)]
pub struct CaptureCustody {
    storage: InMemoryCustodyStorage,
    authority: InMemoryGrantAuthority,
    bounds: CustodyBounds,
    available: bool,
    clock_available: bool,
}

impl CaptureCustody {
    pub fn new(
        bounds: CustodyBounds,
        authority: InMemoryGrantAuthority,
        storage: InMemoryCustodyStorage,
    ) -> Result<Self, CustodyUnavailable> {
        Ok(Self {
            storage,
            authority,
            bounds: bounds.validate()?,
            available: true,
            clock_available: true,
        })
    }

    pub fn with_bounds(bounds: CustodyBounds) -> Result<Self, CustodyUnavailable> {
        Self::new(
            bounds,
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
    }

    pub fn bounds(&self) -> CustodyBounds {
        self.bounds
    }

    pub fn attachment_within_bound(&self, bytes: &[u8]) -> bool {
        bytes.len() as u64 <= self.bounds.maximum_custody_attachment_bytes
    }

    pub fn storage(&self) -> InMemoryCustodyStorage {
        self.storage.clone()
    }

    pub fn authority_mut(&mut self) -> &mut InMemoryGrantAuthority {
        &mut self.authority
    }

    /// Whether custody can retain a captured artifact at all.
    ///
    /// Read rather than asserted by a caller: whoever is deciding whether to
    /// offer a capture capability should not also be stating the answer, or the
    /// two can disagree with nothing to catch it.
    pub fn is_available(&self) -> bool {
        self.available
    }

    /// Whether custody has a clock, which every lifetime bound depends on.
    ///
    /// Separate from availability because the remedies differ: a storage fault
    /// and a missing clock disable the same capability for unrelated reasons.
    pub fn clock_is_available(&self) -> bool {
        self.clock_available
    }

    pub fn set_available(&mut self, available: bool) {
        self.available = available;
    }

    pub fn set_clock_available(&mut self, available: bool) {
        self.clock_available = available;
    }

    /// Startup invalidates every prior preparation exactly once.
    pub fn begin_process_epoch(&mut self) {
        if let Ok(mut state) = self.storage.state.lock() {
            state.process_epoch = state.process_epoch.saturating_add(1);
            let pending = std::mem::take(&mut state.pending_preparations);
            state
                .consumed_tokens
                .extend(pending.into_values().map(|token| token.token_id));
        }
    }

    fn unavailable(&self) -> bool {
        !self.available || !self.clock_available
    }

    /// Preparation checks deliberately put the terminal single-artifact test
    /// before the transient live-token test.
    #[allow(clippy::too_many_arguments)]
    pub fn prepare_capture(
        &mut self,
        action_obligation_id: ActionObligationId,
        identity: &JournalIdentity,
        obligation_durable: bool,
        obligation_active: bool,
        capture_scope: CaptureScope,
        grant_id: Option<String>,
        now: u64,
    ) -> Result<CaptureAdmissionToken, CapturePrepareRefused> {
        let mut state = self
            .storage
            .state
            .lock()
            .map_err(|_| CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::CustodyUnavailable,
            })?;

        if state.artifacts.values().any(|artifact| {
            artifact.obligation_id == action_obligation_id
                && artifact.state == ArtifactState::Admitted
        }) {
            return Err(CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::ArtifactAlreadyAdmitted,
            });
        }
        if state
            .pending_preparations
            .contains_key(&action_obligation_id)
        {
            return Err(CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::PreparationAlreadyActive,
            });
        }
        if !obligation_durable {
            return Err(CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::ObligationNotDurable,
            });
        }
        if !obligation_active {
            return Err(CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::ObligationNotActive,
            });
        }
        if self.unavailable() {
            return Err(CapturePrepareRefused {
                cause: if !self.clock_available {
                    CapturePrepareRefusalCause::BoundUnavailable
                } else {
                    CapturePrepareRefusalCause::CustodyUnavailable
                },
            });
        }
        let grant = self
            .authority
            .validate(grant_id.as_deref(), capture_scope, now)
            .map_err(|failure| CapturePrepareRefused {
                cause: map_prepare_grant_failure(failure),
            })?;
        let token_id = state.next_token_id.saturating_add(1);
        state.next_token_id = token_id;
        let token = CaptureAdmissionToken {
            token_id,
            action_obligation_id,
            identity_digest: identity_digest(identity),
            capture_scope,
            grant_digest: grant_id.as_deref().map(string_digest),
            process_epoch: state.process_epoch,
        };
        // The access above also makes the grant decision explicit in the token.
        let _ = grant;
        state
            .pending_preparations
            .insert(action_obligation_id, token);
        Ok(token)
    }

    pub fn cancel_capture_preparation(
        &mut self,
        token: CaptureAdmissionToken,
    ) -> Result<(), CapturePrepareRefused> {
        let mut state = self
            .storage
            .state
            .lock()
            .map_err(|_| CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::CustodyUnavailable,
            })?;
        if state
            .pending_preparations
            .remove(&token.action_obligation_id)
            .is_some()
        {
            state.consumed_tokens.insert(token.token_id);
            Ok(())
        } else {
            Err(CapturePrepareRefused {
                cause: CapturePrepareRefusalCause::CustodyUnavailable,
            })
        }
    }

    /// Write an unreadable pending artifact.  The caller must commit the
    /// matching journal attachment before calling [`commit_admission`].
    pub fn stage_admission(
        &mut self,
        token: CaptureAdmissionToken,
        identity: &JournalIdentity,
        obligation_active: bool,
        artifact: PixelArtifact,
        now: u64,
    ) -> Result<StagedAdmission, CaptureRefused> {
        let mut state = self.storage.state.lock().map_err(|_| CaptureRefused {
            cause: CaptureRefusedCause::CustodyUnavailable,
        })?;
        let token_state = state
            .pending_preparations
            .remove(&token.action_obligation_id);
        let Some(stored_token) = token_state else {
            return Err(CaptureRefused {
                cause: if state.consumed_tokens.contains(&token.token_id) {
                    CaptureRefusedCause::TokenConsumed
                } else {
                    CaptureRefusedCause::TokenInvalid
                },
            });
        };
        state.consumed_tokens.insert(token.token_id);
        if stored_token != token || token.process_epoch != state.process_epoch {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::TokenInvalid,
            });
        }
        if !obligation_active {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::ObligationNotActive,
            });
        }
        if identity_digest(identity) != token.identity_digest {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::IdentityMismatch,
            });
        }
        if artifact.capture_scope != token.capture_scope {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::CaptureScopeMismatch,
            });
        }
        if artifact.grant_id.as_deref().map(string_digest) != token.grant_digest {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::CaptureScopeMismatch,
            });
        }
        let grant = self
            .authority
            .validate(artifact.grant_id.as_deref(), artifact.capture_scope, now)
            .map_err(|failure| CaptureRefused {
                cause: map_capture_grant_failure(failure),
            })?;
        if state.artifacts.values().any(|existing| {
            existing.obligation_id == token.action_obligation_id
                && existing.state == ArtifactState::Admitted
        }) {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::ArtifactAlreadyAdmitted,
            });
        }
        if self.unavailable() {
            return Err(CaptureRefused {
                cause: CaptureRefusedCause::CustodyUnavailable,
            });
        }
        let descriptor = artifact.descriptor();
        descriptor
            .validate()
            .map_err(|cause| CaptureRefused { cause })?;
        if let Some(grant) = grant {
            if artifact.grant_id.as_deref() != Some(grant.grant_id.as_str()) {
                return Err(CaptureRefused {
                    cause: CaptureRefusedCause::GrantScopeMismatch,
                });
            }
        }
        let artifact_id = next_id(&mut state.next_artifact_id, "capture-artifact");
        state.artifacts.insert(
            artifact_id.clone(),
            ArtifactRecord {
                obligation_id: token.action_obligation_id,
                descriptor: descriptor.clone(),
                bytes: Some(artifact.bytes),
                state: ArtifactState::PendingAttachment,
                readable: false,
                verification_window_open: true,
                attachment_revision: 0,
                retention_pin_id: None,
                deletion_pending: false,
                deletion_failures_remaining: 0,
            },
        );
        Ok(StagedAdmission {
            artifact_id,
            action_obligation_id: token.action_obligation_id,
            descriptor,
        })
    }

    pub fn commit_admission(
        &mut self,
        staged: &StagedAdmission,
        attachment_revision: u64,
    ) -> Result<CaptureArtifactId, CustodyError> {
        let mut state = self
            .storage
            .state
            .lock()
            .map_err(|_| CustodyError::StorageUnavailable)?;
        let record = state
            .artifacts
            .get_mut(&staged.artifact_id)
            .ok_or(CustodyError::InvalidStagedAdmission)?;
        if record.state != ArtifactState::PendingAttachment || attachment_revision == 0 {
            return Err(CustodyError::InvalidStagedAdmission);
        }
        record.state = ArtifactState::Admitted;
        record.readable = true;
        record.attachment_revision = attachment_revision;
        Ok(staged.artifact_id.clone())
    }

    pub fn abort_admission(&mut self, staged: &StagedAdmission) -> Result<(), CustodyError> {
        let mut state = self
            .storage
            .state
            .lock()
            .map_err(|_| CustodyError::StorageUnavailable)?;
        if let Some(record) = state.artifacts.get_mut(&staged.artifact_id) {
            record.readable = false;
            record.deletion_pending = true;
            try_delete(record);
        }
        Ok(())
    }

    pub fn attachment_bytes(
        artifact_id: &str,
        descriptor: &CaptureDescriptor,
        retention_pin_id: Option<&str>,
    ) -> Result<Vec<u8>, CustodyError> {
        let value = json!({
            "artifact_id": artifact_id,
            "descriptor": descriptor,
            "retention_pin_id": retention_pin_id,
        });
        serde_json::to_vec(&value).map_err(|_| CustodyError::StorageUnavailable)
    }

    pub fn parse_attachment(
        bytes: &[u8],
    ) -> Result<(CaptureArtifactId, CaptureDescriptor, Option<RetentionPinId>), CustodyError> {
        let value: Value =
            serde_json::from_slice(bytes).map_err(|_| CustodyError::StorageUnavailable)?;
        let artifact_id = value
            .get("artifact_id")
            .and_then(Value::as_str)
            .ok_or(CustodyError::StorageUnavailable)?
            .to_string();
        let descriptor: CaptureDescriptor = serde_json::from_value(
            value
                .get("descriptor")
                .cloned()
                .ok_or(CustodyError::StorageUnavailable)?,
        )
        .map_err(|_| CustodyError::StorageUnavailable)?;
        let pin = match value.get("retention_pin_id") {
            Some(Value::Null) | None => None,
            Some(value) => Some(
                value
                    .as_str()
                    .ok_or(CustodyError::StorageUnavailable)?
                    .to_string(),
            ),
        };
        Ok((artifact_id, descriptor, pin))
    }

    pub fn prepare_pin(
        &mut self,
        artifact_id: &str,
        grant_id: Option<String>,
        expires_at: u64,
        now: u64,
    ) -> Result<PendingPin, CapturePinRefused> {
        if self.unavailable() {
            return Err(CapturePinRefused {
                cause: if !self.clock_available {
                    CapturePinRefusalCause::BoundUnavailable
                } else {
                    CapturePinRefusalCause::CustodyUnavailable
                },
            });
        }
        let mut state = self.storage.state.lock().map_err(|_| CapturePinRefused {
            cause: CapturePinRefusalCause::CustodyUnavailable,
        })?;
        let (capture_scope, artifact_sha256, readable, verification_window_open, bytes) = {
            let artifact = state.artifacts.get(artifact_id).ok_or(CapturePinRefused {
                cause: CapturePinRefusalCause::ArtifactUnavailable,
            })?;
            (
                artifact.descriptor.capture_scope,
                artifact.descriptor.artifact_sha256.clone(),
                artifact.readable,
                artifact.verification_window_open,
                artifact.bytes.as_ref().map_or(0, Vec::len) as u64,
            )
        };
        if !readable {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::ArtifactUnavailable,
            });
        }
        if !verification_window_open {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::VerificationWindowClosed,
            });
        }
        let grant = self
            .authority
            .validate(grant_id.as_deref(), capture_scope, now)
            .map_err(|failure| CapturePinRefused {
                cause: map_pin_grant_failure(failure),
            })?
            .ok_or(CapturePinRefused {
                cause: CapturePinRefusalCause::GrantAbsent,
            })?;
        let grant_id = grant.grant_id.clone();
        if !grant.authorizes_durable_retention {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::GrantUnverifiable,
            });
        }
        if expires_at <= now {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::ExpiryInvalid,
            });
        }
        if expires_at.saturating_sub(now) > self.bounds.maximum_pin_lifetime_ms {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::ExpiryExceedsMaxPinLifetime,
            });
        }
        let active_pins = state
            .pins
            .values()
            .filter(|record| record.state == PinTerminalState::Active)
            .count() as u64
            + state.pending_pins.len() as u64;
        if active_pins >= self.bounds.maximum_concurrently_pinned_artifacts {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::PinCountBoundReached,
            });
        }
        let pinned_bytes: u64 = state
            .pins
            .values()
            .filter(|record| record.state == PinTerminalState::Active)
            .filter_map(|record| {
                state
                    .artifacts
                    .values()
                    .find(|candidate| {
                        candidate.descriptor.artifact_sha256 == record.pin.artifact_sha256
                    })
                    .and_then(|candidate| candidate.bytes.as_ref())
                    .map(|value| value.len() as u64)
            })
            .sum();
        if pinned_bytes.saturating_add(bytes) > self.bounds.maximum_total_pinned_artifact_bytes {
            return Err(CapturePinRefused {
                cause: CapturePinRefusalCause::ArtifactBytesBoundReached,
            });
        }
        let pin_id = next_id(&mut state.next_pin_id, "retention-pin");
        let pin = RetentionPin {
            retention_pin_id: pin_id.clone(),
            grant_id,
            artifact_sha256,
            created_at: now,
            expires_at,
        };
        state
            .pending_pins
            .insert(pin_id.clone(), (artifact_id.to_string(), pin.clone()));
        Ok(PendingPin {
            retention_pin_id: pin_id,
            artifact_id: artifact_id.to_string(),
            pin,
        })
    }

    pub fn commit_pin(
        &mut self,
        pending: &PendingPin,
        attachment_revision: u64,
    ) -> Result<RetentionPinId, CustodyError> {
        let mut state = self
            .storage
            .state
            .lock()
            .map_err(|_| CustodyError::StorageUnavailable)?;
        let Some((artifact_id, pin)) = state.pending_pins.remove(&pending.retention_pin_id) else {
            return Err(CustodyError::InvalidPendingPin);
        };
        if artifact_id != pending.artifact_id || attachment_revision != 2 {
            state
                .pending_pins
                .insert(pending.retention_pin_id.clone(), (artifact_id, pin));
            return Err(CustodyError::InvalidPendingPin);
        }
        let artifact = state
            .artifacts
            .get_mut(&pending.artifact_id)
            .ok_or(CustodyError::InvalidPendingPin)?;
        if !artifact.readable || artifact.attachment_revision != 1 {
            return Err(CustodyError::InvalidPendingPin);
        }
        artifact.retention_pin_id = Some(pending.retention_pin_id.clone());
        artifact.attachment_revision = attachment_revision;
        state.pins.insert(
            pending.retention_pin_id.clone(),
            PinRecord {
                pin,
                state: PinTerminalState::Active,
            },
        );
        Ok(pending.retention_pin_id.clone())
    }

    pub fn abort_pin(&mut self, pending: &PendingPin) -> Result<(), CustodyError> {
        self.storage
            .state
            .lock()
            .map_err(|_| CustodyError::StorageUnavailable)?
            .pending_pins
            .remove(&pending.retention_pin_id);
        Ok(())
    }

    pub fn release_capture(&mut self, pin_id: &str) -> CaptureReleaseResult {
        let Ok(mut state) = self.storage.state.lock() else {
            return CaptureReleaseResult::RetentionPinUnknown;
        };
        let Some(record) = state.pins.get_mut(pin_id) else {
            return CaptureReleaseResult::RetentionPinUnknown;
        };
        if record.state == PinTerminalState::Active {
            record.state = PinTerminalState::Released;
            for artifact in state.artifacts.values_mut() {
                if artifact.retention_pin_id.as_deref() == Some(pin_id) {
                    destroy_artifact(artifact);
                }
            }
        }
        CaptureReleaseResult::Released
    }

    pub fn sweep_expired_captures(&mut self, now: u64) -> CustodySweepResult {
        let mut result = CustodySweepResult::default();
        let Ok(mut state) = self.storage.state.lock() else {
            result.deletion_failure_count = 1;
            return result;
        };
        let expired: Vec<_> = state
            .pins
            .iter()
            .filter(|(_, record)| {
                record.state == PinTerminalState::Active && record.pin.expires_at <= now
            })
            .map(|(id, _)| id.clone())
            .collect();
        for pin_id in expired {
            result.expired_pin_count += 1;
            if let Some(record) = state.pins.get_mut(&pin_id) {
                record.state = PinTerminalState::Expired;
            }
            for artifact in state.artifacts.values_mut() {
                if artifact.retention_pin_id.as_deref() == Some(pin_id.as_str()) {
                    destroy_artifact(artifact);
                    result.unreadable_artifact_count += 1;
                }
            }
        }
        result.deletion_attempt_count += retry_deletions(&mut state);
        result.deletion_failure_count += state
            .artifacts
            .values()
            .filter(|artifact| artifact.deletion_pending)
            .count() as u64;
        result
    }

    /// Consume the durable core terminal feed.  Replayed transitions are
    /// harmless because closure is guarded by the persisted window bit.
    pub fn apply_terminal_transition(
        &mut self,
        transition_cursor: u64,
        action_obligation_id: ActionObligationId,
        _kind: TerminalKind,
    ) -> CustodySweepResult {
        let Ok(mut state) = self.storage.state.lock() else {
            return CustodySweepResult {
                deletion_failure_count: 1,
                ..CustodySweepResult::default()
            };
        };
        if transition_cursor <= state.terminal_cursor {
            return CustodySweepResult::default();
        }
        state.terminal_cursor = transition_cursor;
        for artifact in state.artifacts.values_mut() {
            if artifact.obligation_id == action_obligation_id && artifact.verification_window_open {
                artifact.verification_window_open = false;
                if artifact.retention_pin_id.is_none() {
                    destroy_artifact(artifact);
                }
            }
        }
        CustodySweepResult {
            deletion_attempt_count: retry_deletions(&mut state),
            ..CustodySweepResult::default()
        }
    }

    /// Duration-based closure is independent of the journal transition feed.
    pub fn close_elapsed_windows(&mut self, now: u64) -> CustodySweepResult {
        let Ok(mut state) = self.storage.state.lock() else {
            return CustodySweepResult {
                deletion_failure_count: 1,
                ..CustodySweepResult::default()
            };
        };
        let mut result = CustodySweepResult::default();
        for artifact in state.artifacts.values_mut() {
            if artifact.verification_window_open
                && now.saturating_sub(artifact.descriptor.captured_at)
                    >= self.bounds.maximum_verification_duration_ms
            {
                artifact.verification_window_open = false;
                if artifact.retention_pin_id.is_none() {
                    destroy_artifact(artifact);
                    result.unreadable_artifact_count += 1;
                }
            }
        }
        result.deletion_attempt_count = retry_deletions(&mut state);
        result
    }

    /// Reconcile the pending write protocol from journal attachments before any
    /// caller-facing read is served.
    pub fn reconcile_attachments(
        &mut self,
        attachments: impl IntoIterator<Item = ObligationAttachment>,
    ) -> Result<(), CustodyError> {
        let mut state = self
            .storage
            .state
            .lock()
            .map_err(|_| CustodyError::StorageUnavailable)?;
        let mut committed_ids = BTreeSet::new();
        for attachment in attachments {
            if attachment.slot != CAPTURE_ATTACHMENT_SLOT {
                continue;
            }
            let (artifact_id, descriptor, pin_id) =
                Self::parse_attachment(&attachment.opaque_bytes)?;
            committed_ids.insert(artifact_id.clone());
            if let Some(record) = state.artifacts.get_mut(&artifact_id) {
                record.descriptor = descriptor;
                record.state = ArtifactState::Admitted;
                record.attachment_revision = attachment.revision;
                record.retention_pin_id = pin_id.clone();
                record.readable = record.bytes.is_some();
                if let Some(pin_id) = pin_id {
                    if let Some((_, pin)) = state.pending_pins.remove(&pin_id) {
                        state.pins.insert(
                            pin_id,
                            PinRecord {
                                pin,
                                state: PinTerminalState::Active,
                            },
                        );
                    }
                }
            }
        }
        let pending: Vec<_> = state
            .artifacts
            .iter()
            .filter(|(_, artifact)| artifact.state == ArtifactState::PendingAttachment)
            .map(|(id, _)| id.clone())
            .collect();
        for id in pending {
            if !committed_ids.contains(&id) {
                if let Some(record) = state.artifacts.get_mut(&id) {
                    destroy_artifact(record);
                }
            }
        }
        let _ = retry_deletions(&mut state);
        Ok(())
    }

    // The readers below answer `Err(CustodyUnavailable)` when the state lock
    // is poisoned, the same fact the admission and pin paths refuse on. They
    // used to fold that into `None`, which a caller reads as "this artifact
    // is not in custody", a remedy (take the capture again) that cannot help
    // when the store itself is unusable; every later call would fail the
    // same way and look like a fresh loss each time.
    pub fn artifact_obligation_id(
        &self,
        artifact_id: &str,
    ) -> Result<Option<ActionObligationId>, CustodyUnavailable> {
        let state = self.storage.state.lock().map_err(|_| CustodyUnavailable)?;
        Ok(state
            .artifacts
            .get(artifact_id)
            .map(|record| record.obligation_id))
    }

    pub fn capture_descriptor(
        &self,
        artifact_id: &str,
    ) -> Result<Option<CaptureDescriptor>, CustodyUnavailable> {
        let state = self.storage.state.lock().map_err(|_| CustodyUnavailable)?;
        Ok(state
            .artifacts
            .get(artifact_id)
            .map(|record| record.descriptor.clone()))
    }

    pub fn read_artifact(&self, artifact_id: &str) -> Result<Option<Vec<u8>>, CustodyUnavailable> {
        let state = self.storage.state.lock().map_err(|_| CustodyUnavailable)?;
        Ok(state.artifacts.get(artifact_id).and_then(|record| {
            if record.readable {
                record.bytes.clone()
            } else {
                None
            }
        }))
    }

    pub fn artifact_readable(&self, artifact_id: &str) -> Result<bool, CustodyUnavailable> {
        let state = self.storage.state.lock().map_err(|_| CustodyUnavailable)?;
        Ok(state
            .artifacts
            .get(artifact_id)
            .is_some_and(|record| record.readable))
    }
    pub fn terminal_cursor(&self) -> u64 {
        self.storage
            .state
            .lock()
            .map(|state| state.terminal_cursor)
            .unwrap_or(0)
    }

    pub fn obligation_ids(&self) -> Vec<ActionObligationId> {
        self.storage
            .state
            .lock()
            .map(|state| {
                state
                    .artifacts
                    .values()
                    .map(|artifact| artifact.obligation_id)
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn inject_deletion_failures(&mut self, artifact_id: &str, count: u64) {
        if let Ok(mut state) = self.storage.state.lock() {
            if let Some(record) = state.artifacts.get_mut(artifact_id) {
                record.deletion_failures_remaining = count;
            }
        }
    }

    pub fn artifact_attachment_revision(&self, artifact_id: &str) -> Option<u64> {
        self.storage.state.lock().ok().and_then(|state| {
            state
                .artifacts
                .get(artifact_id)
                .map(|record| record.attachment_revision)
        })
    }
}

pub const CAPTURE_ATTACHMENT_SLOT: &str = "computer.capture";

fn destroy_artifact(record: &mut ArtifactRecord) {
    record.readable = false;
    record.deletion_pending = true;
    try_delete(record);
}

fn try_delete(record: &mut ArtifactRecord) {
    if record.deletion_failures_remaining > 0 {
        record.deletion_failures_remaining -= 1;
        return;
    }
    record.bytes = None;
    record.deletion_pending = false;
}

fn retry_deletions(state: &mut CustodyState) -> u64 {
    let mut attempts = 0;
    for record in state
        .artifacts
        .values_mut()
        .filter(|record| record.deletion_pending)
    {
        attempts += 1;
        try_delete(record);
    }
    attempts
}

fn next_id(counter: &mut u64, prefix: &str) -> String {
    *counter = counter.saturating_add(1);
    format!("{prefix}-{}", *counter)
}

fn identity_digest(identity: &JournalIdentity) -> [u8; 32] {
    let bytes = serde_json::to_vec(identity).expect("journal identity is serializable");
    Sha256::digest(bytes).into()
}

fn string_digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn hex_digest(digest: &[u8]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn map_prepare_grant_failure(failure: GrantFailure) -> CapturePrepareRefusalCause {
    match failure {
        GrantFailure::Absent => CapturePrepareRefusalCause::GrantAbsent,
        GrantFailure::Expired => CapturePrepareRefusalCause::GrantExpired,
        GrantFailure::ScopeMismatch => CapturePrepareRefusalCause::GrantScopeMismatch,
        GrantFailure::Unverifiable => CapturePrepareRefusalCause::GrantUnverifiable,
    }
}

fn map_capture_grant_failure(failure: GrantFailure) -> CaptureRefusedCause {
    match failure {
        GrantFailure::Absent => CaptureRefusedCause::GrantUnverifiable,
        GrantFailure::Expired => CaptureRefusedCause::GrantExpired,
        GrantFailure::ScopeMismatch => CaptureRefusedCause::GrantScopeMismatch,
        GrantFailure::Unverifiable => CaptureRefusedCause::GrantUnverifiable,
    }
}

fn map_pin_grant_failure(failure: GrantFailure) -> CapturePinRefusalCause {
    match failure {
        GrantFailure::Absent => CapturePinRefusalCause::GrantAbsent,
        GrantFailure::Expired => CapturePinRefusalCause::GrantExpired,
        GrantFailure::ScopeMismatch => CapturePinRefusalCause::GrantScopeMismatch,
        GrantFailure::Unverifiable => CapturePinRefusalCause::GrantUnverifiable,
    }
}

/// Closed accessibility schema supplied by the C1 adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilitySchema {
    pub schema_id: String,
    pub text_fields: BTreeSet<String>,
}

impl AccessibilitySchema {
    pub fn new(
        schema_id: impl Into<String>,
        text_fields: impl IntoIterator<Item = String>,
    ) -> Self {
        Self {
            schema_id: schema_id.into(),
            text_fields: text_fields.into_iter().collect(),
        }
    }
}

/// A compact fixture representation of a validated accessibility snapshot.
/// The real adapter may use a richer tree, but every field is still enumerated
/// by the validated schema before any value is made durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessibilitySnapshot {
    pub schema_id: String,
    pub fields: BTreeMap<String, String>,
}

impl AccessibilitySnapshot {
    pub fn new(schema_id: impl Into<String>, fields: BTreeMap<String, String>) -> Self {
        Self {
            schema_id: schema_id.into(),
            fields,
        }
    }

    pub fn from_json(
        value: Value,
        schema: &AccessibilitySchema,
    ) -> Result<Self, AccessibilityRedactionError> {
        let object = value
            .as_object()
            .ok_or(AccessibilityRedactionError::SchemaValidationFailed)?;
        if object.keys().any(|key| !schema.text_fields.contains(key)) {
            return Err(AccessibilityRedactionError::UnknownField);
        }
        let mut fields = BTreeMap::new();
        for field in &schema.text_fields {
            let Some(value) = object.get(field) else {
                return Err(AccessibilityRedactionError::SchemaValidationFailed);
            };
            let Some(text) = value.as_str() else {
                return Err(AccessibilityRedactionError::SchemaValidationFailed);
            };
            fields.insert(field.clone(), text.to_string());
        }
        Ok(Self::new(schema.schema_id.clone(), fields))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessibilityEnvelope {
    pub snapshot_schema_id: String,
    pub redactor_id: String,
    pub redacted_snapshot_bytes: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessibilityRedactionPath {
    SuccessNotSelected,
    Durable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessibilityRedactionOutcome {
    SuccessNotSelected,
    PendingSuccess {
        envelope: AccessibilityEnvelope,
        descriptor_bytes: Vec<u8>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessibilityRedactionError {
    SchemaValidationFailed,
    UnknownField,
    RedactionUnavailable,
    DescriptorOversize,
}

/// Redact every field before constructing the only retained envelope.  When the
/// path is not selected, the successful result is intentionally atomic and does
/// not return any snapshot-derived bytes.
///
/// UNREACHED FROM PRODUCTION as of this writing: nothing in `crates/cerebellum`
/// constructs an `AccessibilitySnapshot`, so the only callers are tests.  It is
/// kept rather than deleted because the order here is a decision and not an
/// implementation: every field is redacted BEFORE any envelope exists, so a
/// field that cannot be redacted aborts while there are no bytes to leak.  An
/// author wiring accessibility text into the journal in a hurry would naturally
/// build the envelope first and redact into it, which passes the raw value
/// through on the failure path.
///
/// The comment above can go stale the day production does construct a snapshot,
/// so the decision itself is pinned by tests named for it rather than by this
/// paragraph: `a_field_that_cannot_be_redacted_refuses_rather_than_passing_the_value_through`
/// and `accessibility_path_is_atomic_when_not_selected_and_bounded_when_durable`
/// in `crates/cerebellum-computer/tests/c2_s2_audit.rs`.  Those survive the
/// rewiring, the rewrite, and this note being wrong.
pub fn redact_accessibility_snapshot<R: Redactor>(
    snapshot: AccessibilitySnapshot,
    schema: &AccessibilitySchema,
    redactor: &R,
    redactor_id: impl Into<String>,
    max_field_bytes: usize,
    max_descriptor_bytes: usize,
    path: AccessibilityRedactionPath,
) -> Result<AccessibilityRedactionOutcome, AccessibilityRedactionError> {
    if snapshot.schema_id != schema.schema_id
        || snapshot.fields.len() != schema.text_fields.len()
        || snapshot
            .fields
            .keys()
            .any(|field| !schema.text_fields.contains(field))
    {
        return Err(AccessibilityRedactionError::SchemaValidationFailed);
    }
    let mut redacted = BTreeMap::new();
    for field in &schema.text_fields {
        let value = snapshot
            .fields
            .get(field)
            .ok_or(AccessibilityRedactionError::SchemaValidationFailed)?;
        let value = redact_then_truncate(Some(redactor), value, max_field_bytes)
            .map_err(|_| AccessibilityRedactionError::RedactionUnavailable)?;
        redacted.insert(field, value);
    }
    let bytes = serde_json::to_vec(&redacted)
        .map_err(|_| AccessibilityRedactionError::DescriptorOversize)?;
    let envelope = AccessibilityEnvelope {
        snapshot_schema_id: schema.schema_id.clone(),
        redactor_id: redactor_id.into(),
        redacted_snapshot_bytes: bytes,
    };
    let descriptor_bytes = serde_json::to_vec(&envelope)
        .map_err(|_| AccessibilityRedactionError::DescriptorOversize)?;
    if descriptor_bytes.len() > max_descriptor_bytes {
        return Err(AccessibilityRedactionError::DescriptorOversize);
    }
    match path {
        AccessibilityRedactionPath::SuccessNotSelected => {
            Ok(AccessibilityRedactionOutcome::SuccessNotSelected)
        }
        AccessibilityRedactionPath::Durable => Ok(AccessibilityRedactionOutcome::PendingSuccess {
            envelope,
            descriptor_bytes,
        }),
    }
}

/// A value that can be used by conformance code to assert all live and recovery
/// terminal labels without depending on a stringly-typed fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CaptureTerminalKind {
    FinalizedCommitted,
    RejectedCommitted,
    RecoveryDispatchFinalized,
    RecoveryRejectionCommitted,
    RecoveryCancelled,
}

impl From<TerminalKind> for CaptureTerminalKind {
    fn from(value: TerminalKind) -> Self {
        match value {
            TerminalKind::FinalizedCommitted => Self::FinalizedCommitted,
            TerminalKind::RejectedCommitted => Self::RejectedCommitted,
            TerminalKind::RecoveryDispatchFinalized => Self::RecoveryDispatchFinalized,
            TerminalKind::RecoveryRejectionCommitted => Self::RecoveryRejectionCommitted,
            TerminalKind::RecoveryCancelled => Self::RecoveryCancelled,
        }
    }
}

impl fmt::Display for CustodyUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("custody_unavailable")
    }
}

impl std::error::Error for CustodyUnavailable {}

/// The minimal reduced journal reason used by accessibility failures.
pub const REDACTION_UNAVAILABLE_REASON: JournalReason = JournalReason::RedactionUnavailable;

/// Human-readable identity helper used by fixture builders.
pub fn identity(
    principal: impl Into<String>,
    conversation_key: impl Into<String>,
    agent_project_id: impl Into<String>,
    session_kind: SessionKind,
) -> JournalIdentity {
    JournalIdentity {
        principal: principal.into(),
        conversation_key: conversation_key.into(),
        agent_project_id: agent_project_id.into(),
        session_kind,
    }
}

/// A closed attachment view used by startup reconciliation tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureAttachment {
    pub artifact_id: CaptureArtifactId,
    pub descriptor: CaptureDescriptor,
    pub retention_pin_id: Option<RetentionPinId>,
}

impl CaptureAttachment {
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        CaptureCustody::attachment_bytes(
            &self.artifact_id,
            &self.descriptor,
            self.retention_pin_id.as_deref(),
        )
    }
}

/// Alias matching the terminology used by the public contract.
pub type CaptureCustodyStore = CaptureCustody;
pub type AdmissionToken = CaptureAdmissionToken;
pub type CaptureArtifact = PixelArtifact;
pub type CapturePrepareCause = CapturePrepareRefusalCause;
pub type CaptureAdmissionCause = CaptureRefusedCause;
pub type CapturePinCause = CapturePinRefusalCause;

#[cfg(test)]
mod reader_availability_tests {
    use super::*;

    fn custody() -> (CaptureCustody, Arc<Mutex<CustodyState>>) {
        let storage = InMemoryCustodyStorage::new();
        let state = Arc::clone(&storage.state);
        let bounds = CustodyBounds {
            maximum_verification_duration_ms: 100,
            maximum_pin_lifetime_ms: 50,
            maximum_concurrently_pinned_artifacts: 4,
            maximum_total_pinned_artifact_bytes: 10_000,
            maximum_custody_attachment_bytes: 2_000,
        };
        let custody =
            CaptureCustody::new(bounds, InMemoryGrantAuthority::default(), storage).unwrap();
        (custody, state)
    }

    /// An unknown artifact on a healthy store is absent: `Ok(None)` and
    /// `Ok(false)`, the answer a caller retries a capture on.
    #[test]
    fn an_unknown_artifact_on_a_healthy_store_is_absent() {
        let (custody, _) = custody();
        assert_eq!(custody.artifact_obligation_id("nope"), Ok(None));
        assert_eq!(custody.capture_descriptor("nope"), Ok(None));
        assert_eq!(custody.read_artifact("nope"), Ok(None));
        assert_eq!(custody.artifact_readable("nope"), Ok(false));
    }

    /// A poisoned store is unavailable, not empty. The wrong implementation
    /// (`lock().ok()` folded into the absent arm) answers exactly what the
    /// test above expects, so this is the case that tells the two apart: a
    /// thread panics while holding the state lock, and every reader must
    /// say the store is unusable rather than that the artifact is missing.
    #[test]
    fn a_poisoned_store_is_unavailable_not_absent() {
        let (custody, state) = custody();
        let poison = std::thread::spawn(move || {
            let _held = state.lock().unwrap();
            panic!("poison the custody state lock on purpose");
        });
        assert!(poison.join().is_err(), "the poisoning thread must panic");
        assert_eq!(
            custody.artifact_obligation_id("nope"),
            Err(CustodyUnavailable)
        );
        assert_eq!(custody.capture_descriptor("nope"), Err(CustodyUnavailable));
        assert_eq!(custody.read_artifact("nope"), Err(CustodyUnavailable));
        assert_eq!(custody.artifact_readable("nope"), Err(CustodyUnavailable));
    }
}
