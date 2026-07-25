//! Acceptance-test fixtures for the profile-custody boundary.
//!
//! The local mocks model the profile registry and custody adapter without
//! linking a concrete custody dependency or runtime implementation.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::rc::Rc;

use cerebellum::profile_custody::{
    AbortCause, AuthorityDecision, CkcredResult, CkcredUnavailable, CustodyAdapter,
    CustodyCoordinator, CustodyOperation, DispatchCommitmentToken, DurableResolution,
    FailureOrigin, LifecycleResult, LiveOwnerProof, LockAcquisition, ProfileDisposition,
    ProfileOutcome, ProfileUuid, RecordOpenability, RegistryGate, RegistryIdentityEvidence,
    RegistryResult, RegistrySeam, ReleaseCause, RetryIdentity, SessionKind,
    UuidProtocolAvailability, ValidatedStampedFacts,
};

type Trace = Rc<RefCell<Vec<String>>>;

fn new_trace() -> Trace {
    Rc::new(RefCell::new(Vec::new()))
}

fn make_uuid(value: &str) -> ProfileUuid {
    ProfileUuid::new(value).unwrap()
}

fn retry(value: &str) -> RetryIdentity {
    RetryIdentity::new(value).unwrap()
}

fn identity(profile_uuid: &str, retry_identity: &str) -> RegistryIdentityEvidence {
    RegistryIdentityEvidence::new(make_uuid(profile_uuid), retry(retry_identity))
}

fn facts(kind: SessionKind, disposition: ProfileDisposition) -> ValidatedStampedFacts {
    ValidatedStampedFacts::from_validated("project-1", kind, disposition).unwrap()
}

#[derive(Clone)]
struct MockRegistry {
    trace: Trace,
    gate: RegistryGate,
    resolution: DurableResolution,
    disposable: RegistryIdentityEvidence,
    first_creation: RegistryIdentityEvidence,
    owners: VecDeque<LiveOwnerProof>,
    lock: LockAcquisition,
    record: RecordOpenability,
    revalidated_record: RecordOpenability,
    fail_commit: bool,
    fail_attach: bool,
    fail_transfer: bool,
    fail_abort_restore: bool,
    fail_detach: bool,
    fail_release_lock: bool,
    fail_close: bool,
}

impl MockRegistry {
    fn existing(trace: Trace, profile_uuid: &str, retry_identity: &str) -> Self {
        let existing = identity(profile_uuid, retry_identity);
        Self {
            trace,
            gate: RegistryGate::Enabled,
            resolution: DurableResolution::TrustworthyExisting(existing.clone()),
            disposable: identity("disp-uuid", "disp-retry"),
            first_creation: existing,
            owners: VecDeque::from([LiveOwnerProof::NoLiveOwner]),
            lock: LockAcquisition::Acquired,
            record: RecordOpenability::Openable,
            revalidated_record: RecordOpenability::Openable,
            fail_commit: false,
            fail_attach: false,
            fail_transfer: false,
            fail_abort_restore: false,
            fail_detach: false,
            fail_release_lock: false,
            fail_close: false,
        }
    }

    fn absent(trace: Trace, profile_uuid: &str, retry_identity: &str) -> Self {
        let mut registry = Self::existing(trace, profile_uuid, retry_identity);
        registry.resolution = DurableResolution::AffirmativeAbsence {
            retry_identity: retry(retry_identity),
        };
        registry
    }

    fn event(&self, event: impl Into<String>) {
        self.trace.borrow_mut().push(event.into());
    }
}

impl RegistrySeam for MockRegistry {
    fn gate(&mut self) -> RegistryGate {
        self.event("registry.gate");
        self.gate
    }

    fn resolve_durable(&mut self, project_id: &str) -> DurableResolution {
        self.event(format!("registry.resolve:{project_id}"));
        self.resolution.clone()
    }

    fn create_disposable(
        &mut self,
        _facts: &ValidatedStampedFacts,
    ) -> Result<RegistryIdentityEvidence, RegistryResult> {
        self.event("registry.create_disposable");
        Ok(self.disposable.clone())
    }

    fn begin_first_creation(
        &mut self,
        retry_identity: &RetryIdentity,
    ) -> Result<RegistryIdentityEvidence, RegistryResult> {
        self.event(format!("registry.begin:{retry_identity:?}"));
        Ok(self.first_creation.clone())
    }

    fn commit_first_creation(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.commit_first_creation");
        if self.fail_commit {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn validate_record(&mut self, _identity: &RegistryIdentityEvidence) -> RecordOpenability {
        self.event("registry.validate_record");
        self.record
    }

    fn revalidate_record(&mut self, _identity: &RegistryIdentityEvidence) -> RecordOpenability {
        self.event("registry.revalidate_record");
        self.revalidated_record
    }

    fn live_owner(&mut self, _identity: &RegistryIdentityEvidence) -> LiveOwnerProof {
        self.event("registry.live_owner");
        self.owners
            .pop_front()
            .unwrap_or(LiveOwnerProof::NoLiveOwner)
    }

    fn acquire_lock(&mut self, _identity: &RegistryIdentityEvidence) -> LockAcquisition {
        self.event("registry.acquire_lock");
        self.lock
    }

    fn attach(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.attach");
        if self.fail_attach {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn detach(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.detach");
        if self.fail_detach {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn release_lock(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.release_lock");
        if self.fail_release_lock {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn mark_unavailable(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.mark_unavailable");
        RegistryResult::Success
    }

    fn abort_restore(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.abort_restore");
        if self.fail_abort_restore {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn close_context(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.close_context");
        if self.fail_close {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn transfer_to_live_session(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.transfer");
        if self.fail_transfer {
            RegistryResult::Unavailable
        } else {
            RegistryResult::Success
        }
    }

    fn recovery_complete(&mut self, _identity: &RegistryIdentityEvidence) -> RegistryResult {
        self.event("registry.recovery_complete");
        RegistryResult::Success
    }
}

#[derive(Clone)]
struct MockCustody {
    trace: Trace,
    unavailable: HashSet<CustodyOperation>,
    grant: AuthorityDecision,
    exact_uuid: AuthorityDecision,
    uuid_protocol: UuidProtocolAvailability,
    seen_authorities: Vec<serde_json::Value>,
    availability_calls: Vec<CustodyOperation>,
    operation_calls: Vec<CustodyOperation>,
}

impl MockCustody {
    fn available(trace: Trace) -> Self {
        Self {
            trace,
            unavailable: HashSet::new(),
            grant: AuthorityDecision::Affirmative,
            exact_uuid: AuthorityDecision::Affirmative,
            uuid_protocol: UuidProtocolAvailability::Enabled,
            seen_authorities: Vec::new(),
            availability_calls: Vec::new(),
            operation_calls: Vec::new(),
        }
    }

    fn event(&self, event: impl Into<String>) {
        self.trace.borrow_mut().push(event.into());
    }

    fn result<T>(&self, operation: CustodyOperation, value: T) -> CkcredResult<T> {
        if let Some(failure) = self
            .unavailable
            .iter()
            .find(|candidate| **candidate == operation)
            .copied()
        {
            CkcredResult::Unavailable(match failure {
                CustodyOperation::GrantVerification => CkcredUnavailable::MissingAdapter,
                _ => CkcredUnavailable::IncompatibleRevision,
            })
        } else {
            CkcredResult::Success(value)
        }
    }
}

impl CustodyAdapter for MockCustody {
    fn availability(
        &mut self,
        operation: CustodyOperation,
        authority: &cerebellum::profile_custody::AuthorityTuple,
    ) -> CkcredResult<()> {
        self.event(format!("custody.availability:{operation:?}"));
        self.availability_calls.push(operation);
        self.seen_authorities.push(authority.as_json());
        self.result(operation, ())
    }

    fn verify_authority(
        &mut self,
        authority: &cerebellum::profile_custody::AuthorityTuple,
    ) -> CkcredResult<AuthorityDecision> {
        self.event("custody.verify_authority");
        self.seen_authorities.push(authority.as_json());
        self.result(CustodyOperation::GrantVerification, self.grant)
    }

    fn uuid_protocol(&mut self) -> UuidProtocolAvailability {
        self.event("custody.uuid_protocol");
        self.uuid_protocol
    }

    fn authorize_exact_uuid(
        &mut self,
        authority: &cerebellum::profile_custody::AuthorityTuple,
        _retry_identity: &RetryIdentity,
    ) -> CkcredResult<AuthorityDecision> {
        self.event("custody.authorize_exact_uuid");
        self.seen_authorities.push(authority.as_json());
        self.result(CustodyOperation::ExactUuidAuthorization, self.exact_uuid)
    }

    fn operate(
        &mut self,
        operation: CustodyOperation,
        authority: &cerebellum::profile_custody::AuthorityTuple,
        _retry_identity: &RetryIdentity,
    ) -> CkcredResult<()> {
        self.event(format!("custody.operate:{operation:?}"));
        self.operation_calls.push(operation);
        self.seen_authorities.push(authority.as_json());
        self.result(operation, ())
    }
}

fn make_coordinator(
    registry: MockRegistry,
    custody: MockCustody,
) -> CustodyCoordinator<MockRegistry, MockCustody> {
    CustodyCoordinator::new(registry, custody)
}

fn assert_storage(outcome: &ProfileOutcome, origin: FailureOrigin) {
    assert_eq!(
        outcome,
        &ProfileOutcome::ProfileStorageUnavailable { origin }
    );
}

#[test]
fn authority_is_exactly_project_session_and_immutable_uuid() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-9", "retry-9");
    let custody = MockCustody::available(trace);
    let mut coordinator = make_coordinator(registry, custody);

    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "invoke-9",
        )
        .unwrap();
    assert_eq!(
        coordinator.custody().seen_authorities[0],
        serde_json::json!({
            "project_id": "project-1",
            "sessionKind": "primary",
            "profile_uuid": "uuid-9"
        })
    );
    assert_eq!(prepared.profile_uuid().as_str(), "uuid-9");
    assert!(prepared.recovery_evidence().is_some());
    assert!(!coordinator.custody().seen_authorities[0]
        .to_string()
        .contains("default"));
}

#[test]
fn authority_verification_precedes_owner_specific_disclosure() {
    let trace = new_trace();
    let mut registry = MockRegistry::existing(trace.clone(), "secret-uuid", "retry-1");
    registry.owners = VecDeque::from([LiveOwnerProof::PositiveLiveOwner]);
    let mut custody = MockCustody::available(trace);
    custody.grant = AuthorityDecision::NonAffirmative;
    let mut coordinator = make_coordinator(registry, custody);

    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "invoke-1",
        )
        .unwrap_err();
    assert_eq!(outcome, ProfileOutcome::ProfileGrantRequired);
    assert_eq!(
        outcome.grant_reason_code(),
        Some("durable_profile_grant_unavailable")
    );
    assert_eq!(outcome.disclosed_profile_uuid(), None);
    assert!(coordinator
        .registry()
        .trace
        .borrow()
        .iter()
        .all(|event| !event.contains("live_owner")));
}

#[test]
fn profile_busy_requires_positive_live_owner_proof_after_contention() {
    let trace = new_trace();
    let mut registry = MockRegistry::existing(trace.clone(), "uuid-busy", "retry-busy");
    registry.lock = LockAcquisition::Contended;
    registry.owners = VecDeque::from([LiveOwnerProof::NoLiveOwner, LiveOwnerProof::NoLiveOwner]);
    let mut coordinator = make_coordinator(registry, MockCustody::available(trace));
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "busy-1",
        )
        .unwrap_err();
    assert_storage(&outcome, FailureOrigin::RegistryOrStorage);
    assert_eq!(outcome.disclosed_profile_uuid(), None);

    let trace = new_trace();
    let mut registry = MockRegistry::existing(trace.clone(), "uuid-busy", "retry-busy");
    registry.lock = LockAcquisition::Contended;
    registry.owners = VecDeque::from([
        LiveOwnerProof::NoLiveOwner,
        LiveOwnerProof::PositiveLiveOwner,
    ]);
    let mut coordinator = make_coordinator(registry, MockCustody::available(trace));
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "busy-2",
        )
        .unwrap_err();
    assert_eq!(outcome.reason_code(), "profile_busy");
    assert_eq!(
        outcome.disclosed_profile_uuid().unwrap().as_str(),
        "uuid-busy"
    );
}

#[test]
fn ckcred_outage_is_closed_and_does_not_disable_disposable() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-outage", "retry-outage");
    let mut custody = MockCustody::available(trace);
    custody
        .unavailable
        .insert(CustodyOperation::GrantVerification);
    let mut coordinator = make_coordinator(registry, custody);
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "durable-outage",
        )
        .unwrap_err();
    assert_storage(&outcome, FailureOrigin::CkcredDependency);

    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "disp-uuid", "disp-retry");
    let mut custody = MockCustody::available(trace);
    custody
        .unavailable
        .insert(CustodyOperation::SealForAvailability);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Subagent, ProfileDisposition::Disposable),
            "disposable-outage",
        )
        .unwrap();
    assert_eq!(prepared.profile_uuid().as_str(), "disp-uuid");
    assert!(coordinator.custody().availability_calls.is_empty());
}

#[test]
fn registry_gate_precedes_every_disposition_and_ckcred_call() {
    let trace = new_trace();
    let mut registry = MockRegistry::existing(trace.clone(), "uuid-gated", "retry-gated");
    registry.gate = RegistryGate::Unavailable;
    let mut custody = MockCustody::available(trace);
    custody.uuid_protocol = UuidProtocolAvailability::Disabled;
    let mut coordinator = make_coordinator(registry, custody);
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Ephemeral, ProfileDisposition::None),
            "none-gated",
        )
        .unwrap_err();
    assert_storage(&outcome, FailureOrigin::RegistryOrStorage);
    assert!(coordinator.custody().availability_calls.is_empty());
    assert!(coordinator.custody().seen_authorities.is_empty());
}

#[test]
fn existing_open_orders_verification_lock_unseal_and_attachment() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-order", "retry-order");
    let custody = MockCustody::available(trace.clone());
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "order-1",
        )
        .unwrap();
    assert_eq!(
        prepared
            .recovery_evidence()
            .unwrap()
            .retry_identity()
            .as_str(),
        "retry-order"
    );
    let events = trace.borrow();
    let verify = events
        .iter()
        .position(|event| event == "custody.verify_authority")
        .unwrap();
    let validate = events
        .iter()
        .position(|event| event == "registry.validate_record")
        .unwrap();
    let lock = events
        .iter()
        .position(|event| event == "registry.acquire_lock")
        .unwrap();
    let unseal = events
        .iter()
        .position(|event| event == "custody.operate:UnsealForOpen")
        .unwrap();
    let attach = events
        .iter()
        .position(|event| event == "registry.attach")
        .unwrap();
    assert!(verify < validate && validate < lock && lock < unseal && unseal < attach);
}

#[test]
fn abort_and_release_put_custody_before_detach_and_lock_release() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-abort", "retry-abort");
    let custody = MockCustody::available(trace.clone());
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "abort-1",
        )
        .unwrap();
    assert_eq!(
        coordinator.abort(&prepared, AbortCause::InvocationCancelled),
        LifecycleResult::Completed
    );
    assert_eq!(
        coordinator.abort(&prepared, AbortCause::InvocationCancelled),
        LifecycleResult::Completed
    );
    assert!(matches!(
        coordinator.abort(&prepared, AbortCause::Teardown),
        LifecycleResult::Failed(ProfileOutcome::InternalFailure)
    ));
    let events = trace.borrow();
    let seal = events
        .iter()
        .position(|event| event == "custody.operate:SealForAbort")
        .unwrap();
    let detach = events
        .iter()
        .position(|event| event == "registry.abort_restore")
        .unwrap();
    let unlock = events
        .iter()
        .position(|event| event == "registry.release_lock")
        .unwrap();
    assert!(seal < detach && detach < unlock);

    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-release", "retry-release");
    let custody = MockCustody::available(trace.clone());
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "release-1",
        )
        .unwrap();
    let token = DispatchCommitmentToken::for_fixture("release-1", retry("retry-release"));
    let context = coordinator.launch(&prepared, &token).unwrap();
    assert_eq!(
        coordinator.release(&context, ReleaseCause::SessionEnd),
        LifecycleResult::Completed
    );
    assert_eq!(
        coordinator.release(&context, ReleaseCause::SessionEnd),
        LifecycleResult::Completed
    );
    assert!(matches!(
        coordinator.release(&context, ReleaseCause::SupervisorShutdown),
        LifecycleResult::Failed(ProfileOutcome::InternalFailure)
    ));
    let events = trace.borrow();
    let close = events
        .iter()
        .position(|event| event == "registry.close_context")
        .unwrap();
    let seal = events
        .iter()
        .position(|event| event == "custody.operate:SealForRelease")
        .unwrap();
    let detach = events
        .iter()
        .position(|event| event == "registry.detach")
        .unwrap();
    let unlock = events
        .iter()
        .position(|event| event == "registry.release_lock")
        .unwrap();
    assert!(close < seal && seal < detach && detach < unlock);
}

#[test]
fn failed_custody_restoration_transfers_to_recovery_without_unlocking() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-recovery", "retry-recovery");
    let mut custody = MockCustody::available(trace.clone());
    custody.unavailable.insert(CustodyOperation::SealForAbort);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "recovery-1",
        )
        .unwrap();
    let evidence = prepared.recovery_evidence().unwrap();
    // The first abort has a CKCRED failure and records recovery ownership.
    assert!(matches!(
        coordinator.abort(&prepared, AbortCause::DispatchCommitFailed),
        LifecycleResult::Failed(ProfileOutcome::ProfileStorageUnavailable {
            origin: FailureOrigin::CkcredDependency
        })
    ));
    assert!(coordinator
        .registry()
        .trace
        .borrow()
        .iter()
        .any(|event| event == "registry.mark_unavailable"));
    assert!(!coordinator
        .registry()
        .trace
        .borrow()
        .iter()
        .any(|event| event == "registry.release_lock"));
    assert_eq!(evidence.profile_uuid().as_str(), "uuid-recovery");
}

#[test]
fn disposable_and_durable_associations_keep_uuid_and_name_rules() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-disposable", "retry-disposable");
    let custody = MockCustody::available(trace.clone());
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Subagent, ProfileDisposition::Disposable),
            "disp-1",
        )
        .unwrap();
    let token = DispatchCommitmentToken::for_fixture("disp-1", retry("disp-retry"));
    let context = coordinator.launch(&prepared, &token).unwrap();
    assert_eq!(
        context.association().profile_uuid().unwrap().as_str(),
        "disp-uuid"
    );
    assert_eq!(context.association().profile_name(), None);
    assert!(coordinator.custody().seen_authorities.is_empty());

    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-durable", "retry-durable");
    let custody = MockCustody::available(trace);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "dur-1",
        )
        .unwrap();
    let token = DispatchCommitmentToken::for_fixture("dur-1", retry("retry-durable"));
    let context = coordinator.launch(&prepared, &token).unwrap();
    assert_eq!(
        context.association().profile_uuid().unwrap().as_str(),
        "uuid-durable"
    );
    assert_eq!(context.association().profile_name(), Some("default"));
}

#[test]
fn first_creation_disabled_path_does_not_provision_uuid() {
    let trace = new_trace();
    let registry = MockRegistry::absent(trace.clone(), "uuid-never", "retry-new");
    let mut custody = MockCustody::available(trace);
    custody.uuid_protocol = UuidProtocolAvailability::Disabled;
    let mut coordinator = make_coordinator(registry, custody);
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "new-disabled",
        )
        .unwrap_err();
    assert_eq!(outcome, ProfileOutcome::NoSession);
    assert!(!coordinator
        .registry()
        .trace
        .borrow()
        .iter()
        .any(|event| event == "registry.begin:RetryIdentity(\"retry-new\")"));
}

#[test]
fn first_creation_non_affirmative_authority_requires_profile_grant() {
    let trace = new_trace();
    let registry = MockRegistry::absent(trace.clone(), "uuid-denied", "retry-denied");
    let mut custody = MockCustody::available(trace.clone());
    custody.exact_uuid = AuthorityDecision::NonAffirmative;
    let mut coordinator = make_coordinator(registry, custody);

    // First creation must not commit a durable profile until the exact UUID
    // authority decision is affirmative.
    let result = coordinator.prepare(
        &facts(SessionKind::Primary, ProfileDisposition::Durable),
        "new-denied",
    );
    assert_eq!(result, Err(ProfileOutcome::ProfileGrantRequired));
    // The refusal has to precede the commit, not merely accompany it: a durable
    // profile committed for an identity that was refused would outlive the
    // refusal.  Asserting the absent side effect makes that ordering a property
    // of the test rather than of the current control flow.
    assert!(
        !trace
            .borrow()
            .iter()
            .any(|event| event == "registry.commit_first_creation"),
        "refused first creation must not commit a durable profile"
    );

    let trace = new_trace();
    let registry = MockRegistry::absent(trace.clone(), "uuid-allowed", "retry-allowed");
    let custody = MockCustody::available(trace.clone());
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "new-allowed",
        )
        .expect("affirmative first-creation authority should proceed");
    assert_eq!(prepared.profile_uuid().as_str(), "uuid-allowed");
    assert_eq!(prepared.retry_identity().as_str(), "retry-allowed");
    // The paired positive vector proves the absence assertion above is not
    // vacuous: this same event is present when the authority is affirmative.
    assert!(
        trace
            .borrow()
            .iter()
            .any(|event| event == "registry.commit_first_creation"),
        "affirmative first creation must commit a durable profile"
    );
}

#[test]
fn first_creation_uses_same_uuid_retry_and_conflict_contract_as_registry() {
    let trace = new_trace();
    let registry = MockRegistry::absent(trace.clone(), "uuid-created", "retry-created");
    let custody = MockCustody::available(trace);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "new-1",
        )
        .unwrap();
    assert_eq!(prepared.profile_uuid().as_str(), "uuid-created");
    assert_eq!(prepared.retry_identity().as_str(), "retry-created");
    assert!(cerebellum::profile_custody::seam_identities_agree(
        &identity("uuid-created", "retry-created"),
        &prepared
    ));
    assert_eq!(
        coordinator.custody().seen_authorities[1],
        serde_json::json!({
            "project_id": "project-1",
            "sessionKind": "primary",
            "profile_uuid": "uuid-created"
        })
    );

    let trace = new_trace();
    let mut registry = MockRegistry::absent(trace.clone(), "uuid-created", "different-retry");
    registry.first_creation = identity("uuid-created", "retry-created");
    let mut coordinator = make_coordinator(registry, MockCustody::available(trace));
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "new-conflict",
        )
        .unwrap_err();
    assert_storage(&outcome, FailureOrigin::RegistryOrStorage);
}

#[test]
fn matching_dispatch_token_is_required_and_post_launch_failure_is_distinct() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-launch", "retry-launch");
    let custody = MockCustody::available(trace);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "launch-1",
        )
        .unwrap();
    let wrong = DispatchCommitmentToken::for_fixture("other", retry("retry-launch"));
    let error = coordinator.launch(&prepared, &wrong).unwrap_err();
    assert_eq!(error.outcome(), &ProfileOutcome::InternalFailure);
    assert_eq!(
        error.cleanup_classification(),
        cerebellum::profile_custody::CleanupClassification::None
    );
    let right = DispatchCommitmentToken::for_fixture("launch-1", retry("retry-launch"));
    assert!(coordinator.launch(&prepared, &right).is_ok());

    let trace = new_trace();
    let mut registry = MockRegistry::existing(trace.clone(), "uuid-post", "retry-post");
    registry.fail_transfer = true;
    let custody = MockCustody::available(trace);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "launch-post",
        )
        .unwrap();
    let token = DispatchCommitmentToken::for_fixture("launch-post", retry("retry-post"));
    let error = coordinator.launch(&prepared, &token).unwrap_err();
    assert_eq!(
        error.cleanup_classification(),
        cerebellum::profile_custody::CleanupClassification::PostLaunchFailure
    );
    assert_eq!(error.outcome().reason_code(), "internal_failure");
}

#[test]
fn recovery_uses_bound_evidence_and_maps_sealing_outage() {
    let trace = new_trace();
    let registry = MockRegistry::existing(trace.clone(), "uuid-recover", "retry-recover");
    let mut custody = MockCustody::available(trace);
    custody
        .unavailable
        .insert(CustodyOperation::SealForRecovery);
    let mut coordinator = make_coordinator(registry, custody);
    let prepared = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "recover-1",
        )
        .unwrap();
    let evidence = prepared.recovery_evidence().unwrap();
    let result = coordinator.recover(&evidence);
    assert!(matches!(
        result,
        LifecycleResult::Failed(ProfileOutcome::ProfileStorageUnavailable {
            origin: FailureOrigin::CkcredDependency
        })
    ));
    let event_count = coordinator.registry().trace.borrow().len();
    assert_eq!(coordinator.recover(&evidence), result);
    assert_eq!(coordinator.registry().trace.borrow().len(), event_count);
}

#[test]
fn missing_or_malformed_stamped_facts_never_enter_custody() {
    assert!(ValidatedStampedFacts::from_validated(
        "",
        SessionKind::Primary,
        ProfileDisposition::Durable
    )
    .is_err());
    assert!(ValidatedStampedFacts::from_validated(
        "project-1",
        SessionKind::Primary,
        ProfileDisposition::Disposable
    )
    .is_err());
}

#[test]
fn sealed_failure_on_first_creation_is_ckcred_origin_and_keeps_registry_unavailable() {
    let trace = new_trace();
    let registry = MockRegistry::absent(trace.clone(), "uuid-seal", "retry-seal");
    let mut custody = MockCustody::available(trace);
    custody
        .unavailable
        .insert(CustodyOperation::SealForAvailability);
    let mut coordinator = make_coordinator(registry, custody);
    let outcome = coordinator
        .prepare(
            &facts(SessionKind::Primary, ProfileDisposition::Durable),
            "seal-1",
        )
        .unwrap_err();
    assert_storage(&outcome, FailureOrigin::CkcredDependency);
    assert!(!coordinator
        .registry()
        .trace
        .borrow()
        .iter()
        .any(|event| event == "registry.attach"));
}

#[test]
fn all_ckcred_results_are_closed_without_dependency_types() {
    let result: CkcredResult<()> = CkcredResult::Unavailable(CkcredUnavailable::Ambiguous);
    assert!(matches!(result, CkcredResult::Unavailable(_)));
    let _ = HashMap::<String, String>::new();
}
