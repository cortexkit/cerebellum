//! This module is deliberately an adapter boundary, not a CKCRED client.  A
//! later production integration supplies the verifier and sealing implementation.
//! The types here limit the browser plane to validated identity facts, an
//! immutable registry identity, and closed custody results.
//!
//! No method accepts grants, profile names, caller UUIDs, authority tuples,
//! custody metadata, or browser payloads.  Authority is projected once from
//! validated facts and the UUID supplied by the profile registry.

use std::collections::HashMap;

mod holder_lock;

#[cfg(all(target_os = "linux", test))]
pub(crate) use holder_lock::linux_current_generation;
#[cfg(target_os = "linux")]
pub(crate) use holder_lock::linux_generation_observation;
pub use holder_lock::{
    classify_process_generation, classify_supervisor_start_time, current_supervisor_generation,
    read_record_if_present, BootId, FilesystemProfileCustodyJournal, GenerationObservation,
    HolderId, KernelSupervisorLiveness, ProfileCustodyAcquisition, ProfileCustodyClaim,
    ProfileCustodyEvent, ProfileCustodyEventKind, ProfileCustodyJournal, ProfileCustodyKey,
    ProfileCustodyLockError, ProfileCustodyLockRecord, ProfileCustodyLocks, ProfileCustodyRelease,
    StartTimeStability, SupervisorGeneration, SupervisorLiveness, SupervisorLivenessProbe,
    CUSTODY_LOCK_FORMAT,
};

/// The caller-visible reason for an unavailable profile-storage operation.
pub const PROFILE_STORAGE_UNAVAILABLE_REASON: &str = "profile_storage_unavailable";
/// The caller-visible reason for a durable grant that was not affirmatively
/// accepted by the custody verifier.
pub const DURABLE_GRANT_UNAVAILABLE_REASON: &str = "durable_profile_grant_unavailable";
/// The caller-visible reason shared by an absent disposition and disabled first
/// durable creation.
pub const NO_SESSION_REASON: &str = "no_session";
/// The caller-visible reason for a failed continuation correlation.
pub const INTERNAL_FAILURE_REASON: &str = "internal_failure";

/// The only session-kind values accepted by the strict stamped-fact seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SessionKind {
    Primary,
    Subagent,
    Ephemeral,
}

impl SessionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Primary => "primary",
            Self::Subagent => "subagent",
            Self::Ephemeral => "ephemeral",
        }
    }
}

/// The disposition supplied as part of already validated stamped facts.  This
/// layer validates the project/session/disposition combination but never derives
/// a disposition from a caller request or a local default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileDisposition {
    Durable,
    Disposable,
    None,
}

impl ProfileDisposition {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Durable => "durable",
            Self::Disposable => "disposable",
            Self::None => "none",
        }
    }

    fn agrees_with(self, kind: SessionKind) -> bool {
        matches!(
            (kind, self),
            (SessionKind::Primary, Self::Durable)
                | (SessionKind::Subagent, Self::Disposable)
                | (SessionKind::Ephemeral, Self::None)
        )
    }
}

/// Facts that have already passed the daemon's strict project, session-kind,
/// and disposition validation.
///
/// The fields are private so callers cannot add authority or custody data after
/// validation.  This constructor accepts only already validated values; it is
/// not a parser or compatibility constructor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedStampedFacts {
    project_id: String,
    session_kind: SessionKind,
    disposition: ProfileDisposition,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactValidationError {
    EmptyProjectId,
    ProjectIdTooLong,
    DispositionMismatch,
}

impl ValidatedStampedFacts {
    pub const MAX_PROJECT_ID_BYTES: usize = 256;

    /// Construct facts for this custody boundary from values that have already
    /// passed the daemon's validation contract.
    pub fn from_validated(
        project_id: impl Into<String>,
        session_kind: SessionKind,
        disposition: ProfileDisposition,
    ) -> Result<Self, FactValidationError> {
        let project_id = project_id.into();
        if project_id.is_empty() {
            return Err(FactValidationError::EmptyProjectId);
        }
        if project_id.len() > Self::MAX_PROJECT_ID_BYTES {
            return Err(FactValidationError::ProjectIdTooLong);
        }
        if !disposition.agrees_with(session_kind) {
            return Err(FactValidationError::DispositionMismatch);
        }
        Ok(Self {
            project_id,
            session_kind,
            disposition,
        })
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub const fn session_kind(&self) -> SessionKind {
        self.session_kind
    }

    pub const fn disposition(&self) -> ProfileDisposition {
        self.disposition
    }
}

/// An immutable UUID resolved or provisioned by the profile registry.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileUuid(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileUuidError {
    Empty,
    TooLong,
}

impl ProfileUuid {
    pub const MAX_BYTES: usize = 128;

    pub fn new(value: impl Into<String>) -> Result<Self, ProfileUuidError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ProfileUuidError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(ProfileUuidError::TooLong);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The retry identity assigned by the durable profile-registry transaction.
/// It remains stable across retries of that transaction.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RetryIdentity(String);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetryIdentityError {
    Empty,
    TooLong,
}

impl RetryIdentity {
    pub const MAX_BYTES: usize = 256;

    pub fn new(value: impl Into<String>) -> Result<Self, RetryIdentityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(RetryIdentityError::Empty);
        }
        if value.len() > Self::MAX_BYTES {
            return Err(RetryIdentityError::TooLong);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The only registry identity data consumed by the custody boundary.
///
/// This is evidence about a registry record, not the record itself.  The
/// registry remains responsible for record schema, identity generation, lock
/// ownership, and persistence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistryIdentityEvidence {
    profile_uuid: ProfileUuid,
    retry_identity: RetryIdentity,
}

impl RegistryIdentityEvidence {
    pub fn new(profile_uuid: ProfileUuid, retry_identity: RetryIdentity) -> Self {
        Self {
            profile_uuid,
            retry_identity,
        }
    }

    pub fn profile_uuid(&self) -> &ProfileUuid {
        &self.profile_uuid
    }

    pub fn retry_identity(&self) -> &RetryIdentity {
        &self.retry_identity
    }
}

/// The exact authority projected to the CKCRED verifier.
///
/// There is intentionally no profile name, grant reference, path, lock, owner,
/// seal, or browser-state member in this type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTuple {
    project_id: String,
    session_kind: SessionKind,
    profile_uuid: ProfileUuid,
}

impl AuthorityTuple {
    fn from_facts(facts: &ValidatedStampedFacts, profile_uuid: &ProfileUuid) -> Self {
        Self {
            project_id: facts.project_id.clone(),
            session_kind: facts.session_kind,
            profile_uuid: profile_uuid.clone(),
        }
    }

    pub fn project_id(&self) -> &str {
        &self.project_id
    }

    pub const fn session_kind(&self) -> SessionKind {
        self.session_kind
    }

    pub fn profile_uuid(&self) -> &ProfileUuid {
        &self.profile_uuid
    }

    /// Return the closed wire-shaped authority object.  This is the only
    /// representation handed to a verifier adapter.
    pub fn as_json(&self) -> serde_json::Value {
        serde_json::json!({
            "project_id": self.project_id,
            "sessionKind": self.session_kind.as_str(),
            "profile_uuid": self.profile_uuid.as_str(),
        })
    }
}

/// The one non-caller-visible classification for a profile-storage failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureOrigin {
    RegistryOrStorage,
    CkcredDependency,
}

impl FailureOrigin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RegistryOrStorage => "registry_or_storage",
            Self::CkcredDependency => "ckcred_dependency",
        }
    }
}

/// Closed profile outcomes.  These values contain no custody or browser data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileOutcome {
    ProfileBusy { profile_uuid: ProfileUuid },
    ProfileGrantRequired,
    NoSession,
    ProfileStorageUnavailable { origin: FailureOrigin },
    InternalFailure,
}

impl ProfileOutcome {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::ProfileBusy { .. } => "profile_busy",
            Self::ProfileGrantRequired => "profile_grant_required",
            Self::NoSession => NO_SESSION_REASON,
            Self::ProfileStorageUnavailable { .. } => PROFILE_STORAGE_UNAVAILABLE_REASON,
            Self::InternalFailure => INTERNAL_FAILURE_REASON,
        }
    }

    pub const fn failure_origin(&self) -> Option<FailureOrigin> {
        match self {
            Self::ProfileStorageUnavailable { origin } => Some(*origin),
            _ => None,
        }
    }

    pub const fn grant_reason_code(&self) -> Option<&'static str> {
        match self {
            Self::ProfileGrantRequired => Some(DURABLE_GRANT_UNAVAILABLE_REASON),
            _ => None,
        }
    }

    pub fn disclosed_profile_uuid(&self) -> Option<&ProfileUuid> {
        match self {
            Self::ProfileBusy { profile_uuid } => Some(profile_uuid),
            _ => None,
        }
    }
}

/// Closed CKCRED adapter failures.  No adapter error text crosses this seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CkcredUnavailable {
    MissingAdapter,
    IncompatibleRevision,
    Timeout,
    Error,
    NonSuccess,
    Ambiguous,
}

/// Values returned by a local or manifest-bound custody adapter.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CkcredResult<T> {
    Success(T),
    Unavailable(CkcredUnavailable),
}

/// Closed authority decision.  Only `Affirmative` permits owner-specific
/// disclosure or a durable transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorityDecision {
    Affirmative,
    NonAffirmative,
}

/// Operations for which CKCRED compatibility and availability are evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CustodyOperation {
    GrantVerification,
    ExactUuidAuthorization,
    UnsealForOpen,
    SealForAvailability,
    SealForAbort,
    SealForRelease,
    SealForRecovery,
}

/// Whether the first-creation UUID protocol is frozen and enabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UuidProtocolAvailability {
    Enabled,
    Disabled,
}

/// S9's only external custody dependency.  It has no CKCRED crate or runtime
/// binding; production wiring supplies an implementation of this trait.
///
/// Every method receives the authority projected by [`AuthorityTuple`].  There
/// is no method parameter for caller grant material, profile names, paths,
/// browser payloads, or arbitrary custody metadata.
pub trait CustodyAdapter {
    fn availability(
        &mut self,
        operation: CustodyOperation,
        authority: &AuthorityTuple,
    ) -> CkcredResult<()>;

    fn verify_authority(&mut self, authority: &AuthorityTuple) -> CkcredResult<AuthorityDecision>;

    fn uuid_protocol(&mut self) -> UuidProtocolAvailability;

    fn authorize_exact_uuid(
        &mut self,
        authority: &AuthorityTuple,
        retry_identity: &RetryIdentity,
    ) -> CkcredResult<AuthorityDecision>;

    fn operate(
        &mut self,
        operation: CustodyOperation,
        authority: &AuthorityTuple,
        retry_identity: &RetryIdentity,
    ) -> CkcredResult<()>;
}

/// The registry's durable-slot resolution consumed by custody operations.
/// Only a confirmed existing identity or a confirmed absence may proceed; an
/// unavailable or untrustworthy result never starts first creation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DurableResolution {
    TrustworthyExisting(RegistryIdentityEvidence),
    AffirmativeAbsence { retry_identity: RetryIdentity },
    UntrustworthyOrUnavailable,
}

/// Whether the durable profile-registry record and the immutable registry
/// adapters required by this module are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryGate {
    Enabled,
    Unavailable,
}

/// Closed results for registry operations.  S9 maps all of them to the local
/// storage origin and does not expose persistence details.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryResult {
    Success,
    Unavailable,
}

/// Existing-record openability is intentionally separate from live-owner proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordOpenability {
    Openable,
    Unavailable,
}

/// A positive owner observation is the only evidence that can produce
/// `profile_busy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LiveOwnerProof {
    NoLiveOwner,
    PositiveLiveOwner,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockAcquisition {
    Acquired,
    Contended,
    Unavailable,
}

/// The registry and lifecycle boundary used by this module.  Its default
/// behavior is fail-closed, so an incomplete mock or missing implementation
/// cannot create, attach, release, or recover state.
pub trait RegistrySeam {
    fn gate(&mut self) -> RegistryGate;

    fn resolve_durable(&mut self, project_id: &str) -> DurableResolution;

    fn create_disposable(
        &mut self,
        facts: &ValidatedStampedFacts,
    ) -> Result<RegistryIdentityEvidence, RegistryResult> {
        let _ = facts;
        Err(RegistryResult::Unavailable)
    }

    fn begin_first_creation(
        &mut self,
        retry_identity: &RetryIdentity,
    ) -> Result<RegistryIdentityEvidence, RegistryResult> {
        let _ = retry_identity;
        Err(RegistryResult::Unavailable)
    }

    fn commit_first_creation(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Unavailable
    }

    fn validate_record(&mut self, identity: &RegistryIdentityEvidence) -> RecordOpenability {
        let _ = identity;
        RecordOpenability::Unavailable
    }

    fn live_owner(&mut self, identity: &RegistryIdentityEvidence) -> LiveOwnerProof {
        let _ = identity;
        LiveOwnerProof::Unavailable
    }

    fn acquire_lock(&mut self, identity: &RegistryIdentityEvidence) -> LockAcquisition {
        let _ = identity;
        LockAcquisition::Unavailable
    }

    fn revalidate_record(&mut self, identity: &RegistryIdentityEvidence) -> RecordOpenability {
        self.validate_record(identity)
    }

    fn attach(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Unavailable
    }

    fn detach(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Unavailable
    }

    fn release_lock(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Unavailable
    }

    fn mark_unavailable(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Unavailable
    }

    fn abort_restore(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.detach(identity)
    }

    fn close_context(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Success
    }

    fn transfer_to_live_session(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Success
    }

    fn recovery_complete(&mut self, identity: &RegistryIdentityEvidence) -> RegistryResult {
        let _ = identity;
        RegistryResult::Success
    }
}

/// The dispatch commitment token supplied by the dispatch boundary.  This local
/// opaque representation is sufficient to correlate a launch with its prepared
/// operation; it is not a journal implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DispatchCommitmentToken {
    invocation: String,
    retry_identity: RetryIdentity,
}

impl DispatchCommitmentToken {
    /// Test-only construction for standalone custody-boundary tests.  Production
    /// wiring will provide the real dispatch commitment type instead of this
    /// local fixture representation.
    pub fn for_fixture(invocation: impl Into<String>, retry_identity: RetryIdentity) -> Self {
        Self {
            invocation: invocation.into(),
            retry_identity,
        }
    }
}

/// An invocation-bound pre-launch state.  The fields are private and the value
/// is only useful with the coordinator that created it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedOpen {
    id: u64,
    invocation: String,
    identity: RegistryIdentityEvidence,
    authority: Option<AuthorityTuple>,
    disposition: ProfileDisposition,
}

impl PreparedOpen {
    pub fn invocation(&self) -> &str {
        &self.invocation
    }

    pub fn profile_uuid(&self) -> &ProfileUuid {
        self.identity.profile_uuid()
    }

    pub fn retry_identity(&self) -> &RetryIdentity {
        self.identity.retry_identity()
    }

    /// Produce the immutable identity-and-authority binding needed to recover a
    /// durable transaction.  It is derived only from a validated prepared
    /// durable transition.
    pub fn recovery_evidence(&self) -> Option<RecoveryEvidence> {
        self.authority.as_ref().map(|authority| RecoveryEvidence {
            identity: self.identity.clone(),
            authority: authority.clone(),
        })
    }
}

/// A live-session-owned context handle.  It publishes only the permitted
/// nullable association and retains the same UUID/retry identity as S8.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenedContext {
    id: u64,
    identity: RegistryIdentityEvidence,
    authority: Option<AuthorityTuple>,
    association: ProfileAssociation,
}

impl OpenedContext {
    pub fn profile_uuid(&self) -> &ProfileUuid {
        self.identity.profile_uuid()
    }

    pub fn retry_identity(&self) -> &RetryIdentity {
        self.identity.retry_identity()
    }

    pub fn association(&self) -> &ProfileAssociation {
        &self.association
    }

    pub fn recovery_evidence(&self) -> Option<RecoveryEvidence> {
        self.authority.as_ref().map(|authority| RecoveryEvidence {
            identity: self.identity.clone(),
            authority: authority.clone(),
        })
    }
}

/// The final immutable context association.  Disposable profiles deliberately
/// carry a null display name; no status-layer name is imported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileAssociation {
    profile_uuid: Option<ProfileUuid>,
    profile_name: Option<String>,
}

impl ProfileAssociation {
    pub fn profile_uuid(&self) -> Option<&ProfileUuid> {
        self.profile_uuid.as_ref()
    }

    pub fn profile_name(&self) -> Option<&str> {
        self.profile_name.as_deref()
    }
}

/// Recovery input bound to durable evidence that was established before the
/// process lost its live invocation.  Recovery accepts no replacement facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryEvidence {
    identity: RegistryIdentityEvidence,
    authority: AuthorityTuple,
}

impl RecoveryEvidence {
    pub fn profile_uuid(&self) -> &ProfileUuid {
        self.identity.profile_uuid()
    }

    pub fn retry_identity(&self) -> &RetryIdentity {
        self.identity.retry_identity()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbortCause {
    DispatchCommitFailed,
    InvocationCancelled,
    Teardown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseCause {
    SessionEnd,
    ContextReplaced,
    SupervisorShutdown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupClassification {
    None,
    PostLaunchFailure,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchFailure {
    outcome: ProfileOutcome,
    cleanup: CleanupClassification,
}

impl LaunchFailure {
    pub fn outcome(&self) -> &ProfileOutcome {
        &self.outcome
    }

    pub const fn cleanup_classification(&self) -> CleanupClassification {
        self.cleanup
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleResult {
    Completed,
    Failed(ProfileOutcome),
}

impl LifecycleResult {
    pub const fn is_completed(&self) -> bool {
        matches!(self, Self::Completed)
    }

    pub fn failure(&self) -> Option<&ProfileOutcome> {
        match self {
            Self::Completed => None,
            Self::Failed(outcome) => Some(outcome),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TerminalRecord<C> {
    cause: C,
    result: LifecycleResult,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PreparedRecord {
    prepared: PreparedOpen,
    terminal: Option<(AbortCause, LifecycleResult)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct OpenedRecord {
    context: OpenedContext,
    terminal: Option<TerminalRecord<ReleaseCause>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecoveryRecord {
    evidence: RecoveryEvidence,
    result: LifecycleResult,
}

/// Coordinates custody operations such as prepare, launch, abort, release, and
/// recovery with the profile registry.
pub struct CustodyCoordinator<R, C> {
    registry: R,
    custody: C,
    next_handle: u64,
    prepared: HashMap<u64, PreparedRecord>,
    opened: HashMap<u64, OpenedRecord>,
    recovery: HashMap<RetryIdentity, RecoveryRecord>,
}

impl<R, C> CustodyCoordinator<R, C>
where
    R: RegistrySeam,
    C: CustodyAdapter,
{
    pub fn new(registry: R, custody: C) -> Self {
        Self {
            registry,
            custody,
            next_handle: 1,
            prepared: HashMap::new(),
            opened: HashMap::new(),
            recovery: HashMap::new(),
        }
    }

    pub fn registry(&self) -> &R {
        &self.registry
    }

    pub fn registry_mut(&mut self) -> &mut R {
        &mut self.registry
    }

    pub fn custody(&self) -> &C {
        &self.custody
    }

    pub fn custody_mut(&mut self) -> &mut C {
        &mut self.custody
    }

    fn allocate_handle(&mut self) -> u64 {
        let id = self.next_handle;
        self.next_handle = self.next_handle.saturating_add(1);
        id
    }

    fn local_unavailable() -> ProfileOutcome {
        ProfileOutcome::ProfileStorageUnavailable {
            origin: FailureOrigin::RegistryOrStorage,
        }
    }

    fn custody_unavailable() -> ProfileOutcome {
        ProfileOutcome::ProfileStorageUnavailable {
            origin: FailureOrigin::CkcredDependency,
        }
    }

    fn map_custody<T>(result: CkcredResult<T>) -> Result<T, ProfileOutcome> {
        match result {
            CkcredResult::Success(value) => Ok(value),
            CkcredResult::Unavailable(_) => Err(Self::custody_unavailable()),
        }
    }

    fn cleanup_locked(
        &mut self,
        identity: &RegistryIdentityEvidence,
        authority: Option<&AuthorityTuple>,
        operation: Option<CustodyOperation>,
    ) -> ProfileOutcome {
        if let (Some(authority), Some(operation)) = (authority, operation) {
            let _ = self.custody.availability(operation, authority);
            let _ = self
                .custody
                .operate(operation, authority, identity.retry_identity());
        }
        let _ = self.registry.mark_unavailable(identity);
        let _ = self.registry.release_lock(identity);
        Self::local_unavailable()
    }

    /// Prepare a durable, disposable, or absent-disposition context.  Registry
    /// gating is always first; custody is never queried for disposable state.
    pub fn prepare(
        &mut self,
        facts: &ValidatedStampedFacts,
        invocation: impl Into<String>,
    ) -> Result<PreparedOpen, ProfileOutcome> {
        if self.registry.gate() != RegistryGate::Enabled {
            return Err(Self::local_unavailable());
        }
        let invocation = invocation.into();

        match facts.disposition() {
            ProfileDisposition::None => Err(ProfileOutcome::NoSession),
            ProfileDisposition::Disposable => {
                let identity = self
                    .registry
                    .create_disposable(facts)
                    .map_err(|_| Self::local_unavailable())?;
                let prepared = PreparedOpen {
                    id: self.allocate_handle(),
                    invocation,
                    identity,
                    authority: None,
                    disposition: ProfileDisposition::Disposable,
                };
                self.prepared.insert(
                    prepared.id,
                    PreparedRecord {
                        prepared: prepared.clone(),
                        terminal: None,
                    },
                );
                Ok(prepared)
            }
            ProfileDisposition::Durable => self.prepare_durable(facts, invocation),
        }
    }

    fn prepare_durable(
        &mut self,
        facts: &ValidatedStampedFacts,
        invocation: String,
    ) -> Result<PreparedOpen, ProfileOutcome> {
        let resolution = self.registry.resolve_durable(facts.project_id());
        match resolution {
            DurableResolution::UntrustworthyOrUnavailable => Err(Self::local_unavailable()),
            DurableResolution::TrustworthyExisting(identity) => {
                self.prepare_existing(facts, invocation, identity)
            }
            DurableResolution::AffirmativeAbsence { retry_identity } => {
                if self.custody.uuid_protocol() == UuidProtocolAvailability::Disabled {
                    return Err(ProfileOutcome::NoSession);
                }
                let identity = self
                    .registry
                    .begin_first_creation(&retry_identity)
                    .map_err(|_| Self::local_unavailable())?;
                if identity.retry_identity() != &retry_identity {
                    return Err(Self::local_unavailable());
                }
                let authority = AuthorityTuple::from_facts(facts, identity.profile_uuid());
                self.require_available(CustodyOperation::ExactUuidAuthorization, &authority)?;
                match Self::map_custody(
                    self.custody
                        .authorize_exact_uuid(&authority, identity.retry_identity()),
                )? {
                    AuthorityDecision::Affirmative => {}
                    AuthorityDecision::NonAffirmative => {
                        return Err(ProfileOutcome::ProfileGrantRequired)
                    }
                }
                if self.registry.commit_first_creation(&identity) != RegistryResult::Success {
                    return Err(Self::local_unavailable());
                }
                self.require_available(CustodyOperation::SealForAvailability, &authority)?;
                if Self::map_custody(self.custody.operate(
                    CustodyOperation::SealForAvailability,
                    &authority,
                    identity.retry_identity(),
                ))
                .is_err()
                {
                    let _ = self.registry.mark_unavailable(&identity);
                    return Err(Self::custody_unavailable());
                }
                if self.registry.attach(&identity) != RegistryResult::Success {
                    let _ = self.registry.mark_unavailable(&identity);
                    let _ = self.registry.release_lock(&identity);
                    return Err(Self::local_unavailable());
                }
                self.make_prepared(
                    invocation,
                    identity,
                    Some(authority),
                    ProfileDisposition::Durable,
                )
            }
        }
    }

    fn prepare_existing(
        &mut self,
        facts: &ValidatedStampedFacts,
        invocation: String,
        identity: RegistryIdentityEvidence,
    ) -> Result<PreparedOpen, ProfileOutcome> {
        let authority = AuthorityTuple::from_facts(facts, identity.profile_uuid());
        self.require_available(CustodyOperation::GrantVerification, &authority)?;
        match Self::map_custody(self.custody.verify_authority(&authority))? {
            AuthorityDecision::NonAffirmative => return Err(ProfileOutcome::ProfileGrantRequired),
            AuthorityDecision::Affirmative => {}
        }

        if self.registry.validate_record(&identity) != RecordOpenability::Openable {
            return Err(Self::local_unavailable());
        }
        match self.registry.live_owner(&identity) {
            LiveOwnerProof::PositiveLiveOwner => {
                return Err(ProfileOutcome::ProfileBusy {
                    profile_uuid: identity.profile_uuid().clone(),
                })
            }
            LiveOwnerProof::Unavailable => return Err(Self::local_unavailable()),
            LiveOwnerProof::NoLiveOwner => {}
        }
        match self.registry.acquire_lock(&identity) {
            LockAcquisition::Unavailable => return Err(Self::local_unavailable()),
            LockAcquisition::Contended => match self.registry.live_owner(&identity) {
                LiveOwnerProof::PositiveLiveOwner => {
                    return Err(ProfileOutcome::ProfileBusy {
                        profile_uuid: identity.profile_uuid().clone(),
                    })
                }
                LiveOwnerProof::NoLiveOwner | LiveOwnerProof::Unavailable => {
                    return Err(Self::local_unavailable())
                }
            },
            LockAcquisition::Acquired => {}
        }
        if self.registry.revalidate_record(&identity) != RecordOpenability::Openable {
            let _ = self.registry.release_lock(&identity);
            return Err(Self::local_unavailable());
        }
        self.require_available(CustodyOperation::UnsealForOpen, &authority)
            .inspect_err(|_| {
                let _ = self.registry.mark_unavailable(&identity);
                let _ = self.registry.release_lock(&identity);
            })?;
        if Self::map_custody(self.custody.operate(
            CustodyOperation::UnsealForOpen,
            &authority,
            identity.retry_identity(),
        ))
        .is_err()
        {
            let _ = self.registry.mark_unavailable(&identity);
            let _ = self.registry.release_lock(&identity);
            return Err(Self::custody_unavailable());
        }
        if self.registry.attach(&identity) != RegistryResult::Success {
            return Err(self.cleanup_locked(
                &identity,
                Some(&authority),
                Some(CustodyOperation::SealForAbort),
            ));
        }
        self.make_prepared(
            invocation,
            identity,
            Some(authority),
            ProfileDisposition::Durable,
        )
    }

    fn require_available(
        &mut self,
        operation: CustodyOperation,
        authority: &AuthorityTuple,
    ) -> Result<(), ProfileOutcome> {
        Self::map_custody(self.custody.availability(operation, authority)).map(|_| ())
    }

    fn make_prepared(
        &mut self,
        invocation: String,
        identity: RegistryIdentityEvidence,
        authority: Option<AuthorityTuple>,
        disposition: ProfileDisposition,
    ) -> Result<PreparedOpen, ProfileOutcome> {
        let prepared = PreparedOpen {
            id: self.allocate_handle(),
            invocation,
            identity,
            authority,
            disposition,
        };
        self.prepared.insert(
            prepared.id,
            PreparedRecord {
                prepared: prepared.clone(),
                terminal: None,
            },
        );
        Ok(prepared)
    }

    /// Consume a prepared state only with the dispatch commitment token for the
    /// same invocation and retry identity.
    pub fn launch(
        &mut self,
        prepared: &PreparedOpen,
        token: &DispatchCommitmentToken,
    ) -> Result<OpenedContext, LaunchFailure> {
        let Some(record) = self.prepared.get(&prepared.id).cloned() else {
            return Err(LaunchFailure {
                outcome: ProfileOutcome::InternalFailure,
                cleanup: CleanupClassification::None,
            });
        };
        if record.prepared != *prepared
            || record.terminal.is_some()
            || token.invocation != prepared.invocation
            || token.retry_identity != *prepared.retry_identity()
        {
            return Err(LaunchFailure {
                outcome: ProfileOutcome::InternalFailure,
                cleanup: CleanupClassification::None,
            });
        }
        if self
            .registry
            .transfer_to_live_session(prepared_identity(&record.prepared))
            != RegistryResult::Success
        {
            let outcome = self.post_launch_cleanup(&record.prepared);
            self.prepared.remove(&prepared.id);
            return Err(LaunchFailure {
                outcome,
                cleanup: CleanupClassification::PostLaunchFailure,
            });
        }
        self.prepared.remove(&prepared.id);
        let association = match record.prepared.disposition {
            ProfileDisposition::Durable => ProfileAssociation {
                profile_uuid: Some(record.prepared.profile_uuid().clone()),
                profile_name: Some("default".to_string()),
            },
            ProfileDisposition::Disposable => ProfileAssociation {
                profile_uuid: Some(record.prepared.profile_uuid().clone()),
                profile_name: None,
            },
            ProfileDisposition::None => ProfileAssociation {
                profile_uuid: None,
                profile_name: None,
            },
        };
        let context = OpenedContext {
            id: self.allocate_handle(),
            identity: record.prepared.identity,
            authority: record.prepared.authority,
            association,
        };
        self.opened.insert(
            context.id,
            OpenedRecord {
                context: context.clone(),
                terminal: None,
            },
        );
        Ok(context)
    }

    fn post_launch_cleanup(&mut self, prepared: &PreparedOpen) -> ProfileOutcome {
        let identity = prepared_identity(prepared);
        if prepared.disposition == ProfileDisposition::Durable {
            let Some(authority) = prepared.authority.as_ref() else {
                let _ = self.registry.mark_unavailable(identity);
                return Self::local_unavailable();
            };
            if self
                .require_available(CustodyOperation::SealForRelease, authority)
                .is_err()
                || Self::map_custody(self.custody.operate(
                    CustodyOperation::SealForRelease,
                    authority,
                    identity.retry_identity(),
                ))
                .is_err()
            {
                let _ = self.registry.mark_unavailable(identity);
                return Self::custody_unavailable();
            }
        }
        if self.registry.detach(identity) != RegistryResult::Success
            || self.registry.release_lock(identity) != RegistryResult::Success
        {
            let _ = self.registry.mark_unavailable(identity);
            return Self::local_unavailable();
        }
        ProfileOutcome::InternalFailure
    }

    /// Abort a prepared operation.  For durable operations, restore custody
    /// before removing the attachment and releasing the lock; if restoration
    /// fails, retain the bound evidence so a later recovery operation can finish
    /// the transaction.
    pub fn abort(&mut self, prepared: &PreparedOpen, cause: AbortCause) -> LifecycleResult {
        let Some(record) = self.prepared.get(&prepared.id).cloned() else {
            return LifecycleResult::Failed(ProfileOutcome::InternalFailure);
        };
        if record.prepared != *prepared {
            return LifecycleResult::Failed(ProfileOutcome::InternalFailure);
        }
        if let Some((recorded_cause, result)) = record.terminal {
            return if recorded_cause == cause {
                result
            } else {
                LifecycleResult::Failed(ProfileOutcome::InternalFailure)
            };
        }
        let identity = prepared_identity(&record.prepared);
        let result = if let Some(authority) = record.prepared.authority.as_ref() {
            if self
                .require_available(CustodyOperation::SealForAbort, authority)
                .is_err()
                || Self::map_custody(self.custody.operate(
                    CustodyOperation::SealForAbort,
                    authority,
                    identity.retry_identity(),
                ))
                .is_err()
            {
                let _ = self.registry.mark_unavailable(identity);
                LifecycleResult::Failed(Self::custody_unavailable())
            } else if self.registry.abort_restore(identity) != RegistryResult::Success
                || self.registry.release_lock(identity) != RegistryResult::Success
            {
                let _ = self.registry.mark_unavailable(identity);
                LifecycleResult::Failed(Self::local_unavailable())
            } else {
                LifecycleResult::Completed
            }
        } else if self.registry.abort_restore(identity) != RegistryResult::Success
            || self.registry.release_lock(identity) != RegistryResult::Success
        {
            let _ = self.registry.mark_unavailable(identity);
            LifecycleResult::Failed(Self::local_unavailable())
        } else {
            LifecycleResult::Completed
        };
        let record = self
            .prepared
            .get_mut(&prepared.id)
            .expect("prepared record exists");
        record.terminal = Some((cause, result.clone()));
        result
    }

    /// Release a returned context.  A first accepted cause fixes the retry
    /// identity; a conflicting cause never performs another lifecycle action.
    pub fn release(&mut self, context: &OpenedContext, cause: ReleaseCause) -> LifecycleResult {
        let Some(record) = self.opened.get(&context.id).cloned() else {
            return LifecycleResult::Failed(ProfileOutcome::InternalFailure);
        };
        if record.context != *context {
            return LifecycleResult::Failed(ProfileOutcome::InternalFailure);
        }
        if let Some(terminal) = record.terminal {
            return if terminal.cause == cause {
                terminal.result
            } else {
                LifecycleResult::Failed(ProfileOutcome::InternalFailure)
            };
        }
        let identity = &record.context.identity;
        let result = if self.registry.close_context(identity) != RegistryResult::Success {
            let _ = self.registry.mark_unavailable(identity);
            LifecycleResult::Failed(Self::local_unavailable())
        } else if let Some(authority) = record.context.authority.as_ref() {
            if self
                .require_available(CustodyOperation::SealForRelease, authority)
                .is_err()
                || Self::map_custody(self.custody.operate(
                    CustodyOperation::SealForRelease,
                    authority,
                    identity.retry_identity(),
                ))
                .is_err()
            {
                let _ = self.registry.mark_unavailable(identity);
                LifecycleResult::Failed(Self::custody_unavailable())
            } else if self.registry.detach(identity) != RegistryResult::Success
                || self.registry.release_lock(identity) != RegistryResult::Success
            {
                let _ = self.registry.mark_unavailable(identity);
                LifecycleResult::Failed(Self::local_unavailable())
            } else {
                LifecycleResult::Completed
            }
        } else if self.registry.detach(identity) != RegistryResult::Success
            || self.registry.release_lock(identity) != RegistryResult::Success
        {
            let _ = self.registry.mark_unavailable(identity);
            LifecycleResult::Failed(Self::local_unavailable())
        } else {
            LifecycleResult::Completed
        };
        let record = self
            .opened
            .get_mut(&context.id)
            .expect("opened record exists");
        record.terminal = Some(TerminalRecord {
            cause,
            result: result.clone(),
        });
        result
    }

    /// Recover an incomplete durable transaction using only previously bound
    /// evidence.  Recovery never reconstructs facts from a caller request.
    pub fn recover(&mut self, evidence: &RecoveryEvidence) -> LifecycleResult {
        let retry_identity = evidence.retry_identity().clone();
        if let Some(record) = self.recovery.get(&retry_identity) {
            return if record.evidence == *evidence {
                record.result.clone()
            } else {
                LifecycleResult::Failed(ProfileOutcome::InternalFailure)
            };
        }

        let result = if self.registry.gate() != RegistryGate::Enabled {
            LifecycleResult::Failed(Self::local_unavailable())
        } else if self
            .require_available(CustodyOperation::SealForRecovery, &evidence.authority)
            .is_err()
            || Self::map_custody(self.custody.operate(
                CustodyOperation::SealForRecovery,
                &evidence.authority,
                evidence.identity.retry_identity(),
            ))
            .is_err()
        {
            let _ = self.registry.mark_unavailable(&evidence.identity);
            LifecycleResult::Failed(Self::custody_unavailable())
        } else if self.registry.detach(&evidence.identity) != RegistryResult::Success
            || self.registry.release_lock(&evidence.identity) != RegistryResult::Success
            || self.registry.recovery_complete(&evidence.identity) != RegistryResult::Success
        {
            let _ = self.registry.mark_unavailable(&evidence.identity);
            LifecycleResult::Failed(Self::local_unavailable())
        } else {
            LifecycleResult::Completed
        };
        self.recovery.insert(
            retry_identity,
            RecoveryRecord {
                evidence: evidence.clone(),
                result: result.clone(),
            },
        );
        result
    }
}

fn prepared_identity(prepared: &PreparedOpen) -> &RegistryIdentityEvidence {
    &prepared.identity
}

/// Return whether the registry identity equals the identity stored in the
/// prepared operation, without exposing registry records or custody internals.
pub fn seam_identities_agree(
    registry_identity: &RegistryIdentityEvidence,
    prepared: &PreparedOpen,
) -> bool {
    registry_identity == &prepared.identity
}
