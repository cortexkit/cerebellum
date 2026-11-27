use super::*;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

static ROOT_COUNTER: AtomicU64 = AtomicU64::new(0);

fn root() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "ck-s8-{}-{}-{}",
        std::process::id(),
        ROOT_COUNTER.fetch_add(1, Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&path).unwrap();
    path
}
fn context(kind: &str, disposition: &str, conversation: &str) -> StampedBindContext {
    stamped_bind_context(BindFacts {
        principal: "direct:agent".into(),
        conversation_key: conversation.into(),
        agent_project_id: "project-1".into(),
        session_kind: Some(kind.into()),
        session_kind_attested: true,
        profile_disposition: Some(disposition.into()),
        effective_capability_scope: Some(vec!["browser.navigate".into()]),
        provenance: "daemon_attested_spec_a".into(),
    })
    .unwrap()
}
fn tokens(
    id: &str,
) -> (
    InvocationToken,
    JournalReservationHandle,
    DispatchCommitmentToken,
) {
    let invocation = InvocationToken::for_test(id);
    let reservation = JournalReservationHandle::for_test(&invocation, format!("reservation-{id}"));
    let token =
        DispatchCommitmentToken::for_test(&invocation, &reservation, format!("commitment-{id}"));
    (invocation, reservation, token)
}

struct AttachmentFixture {
    path: PathBuf,
    lifecycle: ProfileLifecycle,
    config: RegistryConfig,
}

impl AttachmentFixture {
    fn new(owner: crate::profile_custody::SupervisorGeneration) -> Self {
        use crate::profile_custody::{
            FilesystemProfileCustodyJournal, HolderId, ProfileCustodyEvent,
            ProfileCustodyEventKind, ProfileCustodyJournal,
        };
        let path = root();
        let config = RegistryConfig {
            grant_verifier_available: true,
            sealing_available: true,
            uuid_protocol_compatible: true,
            ..RegistryConfig::default()
        };
        let mut lifecycle = ProfileLifecycle::open_with_config(&path, config.clone()).unwrap();
        let (invocation, reservation, commitment) = tokens("old-attachment");
        let PrepareResult::Prepared(prepared) = lifecycle.prepare_context_open(
            &invocation,
            &reservation,
            &context("primary", "durable", "old-conversation"),
        ) else {
            panic!("prepare attachment");
        };
        let directory = lifecycle
            .prepared_profile_attempt(&prepared)
            .unwrap()
            .directory()
            .to_path_buf();
        assert!(matches!(
            lifecycle.launch_prepared_context(prepared, &commitment),
            LaunchResult::Opened(_)
        ));
        lifecycle
            .registry
            .update_record("project-1", |record| {
                record.process.as_mut().unwrap().pid = owner.pid;
                Ok(())
            })
            .unwrap();
        let mut journal =
            FilesystemProfileCustodyJournal::open(path.join(".ck-browser-profile-custody"))
                .unwrap();
        journal
            .record(&ProfileCustodyEvent {
                format_version: "ck-browser-profile-custody-event/v1".into(),
                kind: ProfileCustodyEventKind::ProfileDirectoryBind,
                holder_id: HolderId::from_recorded("old-holder"),
                supervisor: owner,
                profile_directory: Some(directory),
                evidence: None,
            })
            .unwrap();
        Self {
            path,
            lifecycle,
            config,
        }
    }

    fn record(&self) -> RegistryRecord {
        match self
            .lifecycle
            .registry
            .resolve_durable("project-1")
            .unwrap()
        {
            DurableResolution::TrustworthyExisting(record) => record,
            other => panic!("{other:?}"),
        }
    }

    fn prepare(&mut self) -> PrepareResult {
        let (invocation, reservation, _) = tokens("new-attachment");
        self.lifecycle.prepare_context_open(
            &invocation,
            &reservation,
            &context("primary", "durable", "new-conversation"),
        )
    }
}

impl Drop for AttachmentFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn dead_attachment_owner() -> crate::profile_custody::SupervisorGeneration {
    crate::profile_custody::SupervisorGeneration {
        pid: u32::MAX,
        start_time: 1,
        boot_id: None,
    }
}

#[test]
fn attached_dead_supervisor_is_released_at_startup() {
    let mut fixture = AttachmentFixture::new(dead_attachment_owner());
    fixture.lifecycle =
        ProfileLifecycle::open_with_config(&fixture.path, fixture.config.clone()).unwrap();
    let record = fixture.record();
    assert_eq!(record.state, ProfileState::Released);
    assert_eq!(record.seal_state, SealState::Sealed);
    assert!(
        record.process.is_none() && record.session_id.is_none() && record.attachment_id.is_none()
    );
}

#[test]
fn attached_dead_supervisor_allows_a_later_launch() {
    let mut fixture = AttachmentFixture::new(dead_attachment_owner());
    use crate::profile_custody::{ProfileCustodyKey, ProfileCustodyLocks};
    let mut locks = ProfileCustodyLocks::open_filesystem(&fixture.path).unwrap();
    let (invocation, reservation, commitment) = tokens("retry-launch");
    let mut launch =
        crate::browser_launch::ProfileBoundLaunch::new(&mut fixture.lifecycle, &mut locks);
    let held = launch
        .acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &invocation,
            &reservation,
            &context("primary", "durable", "new-conversation"),
        )
        .expect("launch recovers the dead attachment");
    let opened = launch
        .launch_prepared(held, &commitment)
        .expect("launch opens the recovered profile");
    launch.rollback_opened(opened).unwrap();
}

#[test]
fn attached_live_supervisor_stays_busy() {
    let mut fixture =
        AttachmentFixture::new(crate::profile_custody::current_supervisor_generation().unwrap());
    assert_eq!(fixture.lifecycle.recover_startup().unwrap(), 0);
    assert!(matches!(
        fixture.prepare(),
        PrepareResult::Closed(ProfileOutcome::ProfileBusy { .. })
    ));
    assert_eq!(fixture.record().state, ProfileState::Attached);
    assert_eq!(fixture.record().seal_state, SealState::Available);
}

struct UnreadableAttachmentOwner;
impl crate::profile_custody::SupervisorLivenessProbe for UnreadableAttachmentOwner {
    fn observe(
        &self,
        _: crate::profile_custody::SupervisorGeneration,
    ) -> crate::profile_custody::SupervisorLiveness {
        crate::profile_custody::SupervisorLiveness::Unavailable
    }
}

#[test]
fn attached_unreadable_supervisor_stays_busy() {
    let mut fixture = AttachmentFixture::new(dead_attachment_owner());
    fixture.lifecycle.attachment_liveness =
        AttachmentLiveness(std::sync::Arc::new(UnreadableAttachmentOwner));
    assert_eq!(fixture.lifecycle.recover_startup().unwrap(), 0);
    assert!(matches!(
        fixture.prepare(),
        PrepareResult::Closed(ProfileOutcome::ProfileBusy { .. })
    ));
    assert_eq!(fixture.record().state, ProfileState::Attached);
}

#[test]
fn attached_missing_generation_evidence_stays_busy() {
    let mut fixture = AttachmentFixture::new(dead_attachment_owner());
    fs::remove_file(
        fixture
            .path
            .join(".ck-browser-profile-custody/custody-events.jsonl"),
    )
    .unwrap();
    assert_eq!(fixture.lifecycle.recover_startup().unwrap(), 0);
    assert!(matches!(
        fixture.prepare(),
        PrepareResult::Closed(ProfileOutcome::ProfileBusy { .. })
    ));
}

#[test]
fn artifact_is_machine_readable_and_digest_bound() {
    let report = verify_implementation_digest(REGISTRY_ARTIFACT).unwrap();
    assert_eq!(report.artifact_id, REGISTRY_ARTIFACT_ID);
    assert_eq!(report.revision, REGISTRY_ARTIFACT_REVISION);
    assert_eq!(report.provider_ids.len(), 5);
    assert!(report.fixture_count >= 20);
    assert_eq!(
        report.implementation_digest,
        implementation_digest_for(REGISTRY_ARTIFACT).unwrap()
    );
}

#[test]
fn strict_matrix_accepts_three_pairs_and_rejects_cross_pairs() {
    for (kind, disposition) in [
        ("primary", "durable"),
        ("subagent", "disposable"),
        ("ephemeral", "none"),
    ] {
        assert!(context(kind, disposition, "c")
            .session_kind()
            .as_str()
            .starts_with(kind));
    }
    for (kind, disposition) in [
        ("primary", "disposable"),
        ("primary", "none"),
        ("subagent", "durable"),
        ("subagent", "none"),
        ("ephemeral", "durable"),
        ("ephemeral", "disposable"),
    ] {
        let error = StampedBindContext::validate(BindFacts {
            principal: "p".into(),
            conversation_key: "c".into(),
            agent_project_id: "a".into(),
            session_kind: Some(kind.into()),
            session_kind_attested: true,
            profile_disposition: Some(disposition.into()),
            effective_capability_scope: Some(vec![]),
            provenance: "daemon_attested_spec_a".into(),
        })
        .unwrap_err();
        assert_eq!(error, BindValidationError::IncompatibleKindDisposition);
    }
}

#[test]
fn root_is_held_and_target_containment_is_revalidated() {
    let path = root();
    let root = HeldManagedRoot::open(&path).unwrap();
    assert_eq!(root.canonical_path(), fs::canonicalize(&path).unwrap());
    assert!(root.target_path(Path::new("../outside"), false).is_err());
    fs::remove_dir_all(path).unwrap();
}

#[cfg(windows)]
#[test]
fn created_profile_target_parent_has_a_protected_owner_only_dacl() {
    use cortexkit_lease::test_support::{
        assert_broad_inherited, assert_owner_only, grant_everyone,
    };

    let path = root();
    grant_everyone(&path);
    let control = path.join("inherited-control");
    fs::write(&control, b"fixture").unwrap();
    assert_broad_inherited(&control);

    let root = HeldManagedRoot::open(&path).unwrap();
    let target = root
        .target_path(Path::new("profiles/new-profile"), true)
        .unwrap();
    let parent = target.parent().unwrap();
    assert_owner_only(parent, true, true);
    let held_parent = root.open_target(Path::new("profiles")).unwrap();
    assert_eq!(held_parent.canonical_path(), parent);
    held_parent.revalidate().unwrap();
    drop(held_parent);
    drop(root);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn root_identity_decision_is_platform_neutral_and_ignores_the_device() {
    let birth_time = BirthTime {
        unix_seconds: 1_723_600_000,
        nanoseconds: 5,
    };
    let facts = |device, inode, birth_time| RootMetadataFacts {
        device,
        inode,
        birth_time,
    };
    let path = Path::new("/profiles/root");
    let stored = ManagedRootIdentity::Facts(
        RootIdentityFacts::observe(path, &facts(16_777_230, 839_348_454, Some(birth_time)))
            .unwrap(),
    );
    let after_reboot =
        RootIdentityFacts::observe(path, &facts(16_777_233, 839_348_454, Some(birth_time)))
            .unwrap();
    assert_eq!(verify_root_identity(&stored, &after_reboot), Ok(()));

    let replaced =
        RootIdentityFacts::observe(path, &facts(16_777_233, 1, Some(birth_time))).unwrap();
    assert_eq!(
        verify_root_identity(&stored, &replaced),
        Err(UntrustworthyRegistryReason::ManagedRootInodeChanged)
    );
    assert_eq!(
        RootIdentityFacts::observe(path, &facts(16_777_233, 839_348_454, None)),
        Err(UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable)
    );
    assert_eq!(
        verify_root_identity(&ManagedRootIdentity::HashOnly("00".into()), &after_reboot),
        Err(UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts)
    );

    // Times before 1970 keep a non-negative nanosecond part.
    let before_epoch = UNIX_EPOCH - std::time::Duration::new(1, 250_000_000);
    assert_eq!(
        BirthTime::from_system_time(before_epoch),
        Some(BirthTime {
            unix_seconds: -2,
            nanoseconds: 750_000_000,
        })
    );
}

#[test]
fn untrustworthy_registry_reasons_map_to_refusals_by_value() {
    let path = root();
    let lifecycle = ProfileLifecycle::open(&path).unwrap();
    for (reason, reason_code) in [
        (
            UntrustworthyRegistryReason::ManagedRootInodeChanged,
            PROFILE_REGISTRY_ROOT_INODE_CHANGED,
        ),
        (
            UntrustworthyRegistryReason::ManagedRootBirthTimeChanged,
            PROFILE_REGISTRY_ROOT_BIRTH_TIME_CHANGED,
        ),
        (
            UntrustworthyRegistryReason::ManagedRootPathChanged,
            PROFILE_REGISTRY_ROOT_PATH_CHANGED,
        ),
        (
            UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts,
            PROFILE_REGISTRY_ROOT_IDENTITY_PREDATES_FACTS,
        ),
        (
            UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable,
            PROFILE_REGISTRY_ROOT_BIRTH_TIME_UNAVAILABLE,
        ),
        (
            UntrustworthyRegistryReason::PossiblyManagedPath,
            PROFILE_REGISTRY_POSSIBLY_MANAGED_PATH,
        ),
        (
            UntrustworthyRegistryReason::LockContentionWithoutOwnerProof,
            "profile_registry_lock_owner_unproven",
        ),
        (
            UntrustworthyRegistryReason::MalformedRegistry,
            "profile_registry_malformed",
        ),
        (
            UntrustworthyRegistryReason::UnsupportedRegistrySchema,
            "profile_registry_schema_unsupported",
        ),
        (
            UntrustworthyRegistryReason::IntegrityMismatch,
            "profile_registry_integrity_mismatch",
        ),
        (
            UntrustworthyRegistryReason::InvalidRegistryIdentity,
            "profile_registry_identity_invalid",
        ),
        (
            UntrustworthyRegistryReason::NonCanonicalTarget,
            "profile_target_non_canonical",
        ),
        (
            UntrustworthyRegistryReason::MissingRegistry,
            "profile_registry_missing",
        ),
        (
            UntrustworthyRegistryReason::MissingRecord,
            "profile_registry_record_missing",
        ),
        (
            UntrustworthyRegistryReason::MissingProfileUuid,
            "profile_registry_profile_uuid_missing",
        ),
        (
            UntrustworthyRegistryReason::DurableKindConflict,
            "profile_durable_kind_conflict",
        ),
        (
            UntrustworthyRegistryReason::DurableDeletionState,
            "profile_durable_deletion_state",
        ),
        (
            UntrustworthyRegistryReason::RecordTargetMissing,
            "profile_registry_record_target_missing",
        ),
    ] {
        let expected = match reason {
            UntrustworthyRegistryReason::ManagedRootInodeChanged
            | UntrustworthyRegistryReason::ManagedRootBirthTimeChanged
            | UntrustworthyRegistryReason::ManagedRootPathChanged
            | UntrustworthyRegistryReason::ManagedRootIdentityPredatesFacts
            | UntrustworthyRegistryReason::ManagedRootBirthTimeUnavailable
            | UntrustworthyRegistryReason::PossiblyManagedPath => {
                ProfileOutcome::UntrustworthyRegistry { reason }
            }
            UntrustworthyRegistryReason::LockContentionWithoutOwnerProof
            | UntrustworthyRegistryReason::MalformedRegistry
            | UntrustworthyRegistryReason::UnsupportedRegistrySchema
            | UntrustworthyRegistryReason::IntegrityMismatch
            | UntrustworthyRegistryReason::InvalidRegistryIdentity
            | UntrustworthyRegistryReason::NonCanonicalTarget
            | UntrustworthyRegistryReason::MissingRegistry
            | UntrustworthyRegistryReason::MissingRecord
            | UntrustworthyRegistryReason::MissingProfileUuid
            | UntrustworthyRegistryReason::DurableKindConflict
            | UntrustworthyRegistryReason::DurableDeletionState
            | UntrustworthyRegistryReason::RecordTargetMissing => {
                ProfileOutcome::StorageUnavailable {
                    reason_code,
                    origin: FailureOrigin::RegistryOrStorage,
                }
            }
        };
        assert_eq!(expected.reason_code(), reason_code);
        assert_eq!(
            lifecycle.closed_untrusted_root(reason),
            PrepareResult::Closed(expected)
        );
    }
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn disabled_gate_does_not_create_or_inspect_registry_state() {
    let path = root();
    let mut lifecycle = ProfileLifecycle::disabled(&path).unwrap();
    let (invocation, reservation, _) = tokens("disabled");
    let result = lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "c"),
    );
    assert_eq!(
        result,
        PrepareResult::Closed(ProfileOutcome::StorageUnavailable {
            reason_code: "profile_registry_artifact_unavailable",
            origin: FailureOrigin::RegistryOrStorage
        })
    );
    assert!(!path.join(REGISTRY_FILE).exists());
    assert_eq!(fs::read_dir(&path).unwrap().count(), 0);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn disposable_is_lazy_reusable_and_released_once() {
    let path = root();
    let mut lifecycle = ProfileLifecycle::open(&path).unwrap();
    let (invocation, reservation, token) = tokens("disposable");
    let prepared = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    assert_eq!(lifecycle.current_open("conversation").epoch, 0);
    let opened = match lifecycle.launch_prepared_context(prepared, &token) {
        LaunchResult::Opened(value) => value,
        other => panic!("{other:?}"),
    };
    let snapshot = lifecycle.current_open("conversation");
    assert_eq!(snapshot.open_state, OpenState::Open);
    assert_eq!(snapshot.epoch, 1);
    let (invocation2, reservation2, token2) = tokens("reuse");
    let prepared2 = match lifecycle.prepare_context_open(
        &invocation2,
        &reservation2,
        &context("subagent", "disposable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    let reused = match lifecycle.launch_prepared_context(prepared2, &token2) {
        LaunchResult::Opened(value) => value,
        other => panic!("{other:?}"),
    };
    assert_eq!(opened, reused);
    assert_eq!(lifecycle.current_open("conversation").epoch, 1);
    assert_eq!(
        lifecycle.release_context(opened.clone(), ReleaseCause::SessionEnd),
        ReleaseResult::Released
    );
    assert_eq!(
        lifecycle.release_context(opened, ReleaseCause::SessionEnd),
        ReleaseResult::Released
    );
    assert_eq!(lifecycle.current_open("conversation").epoch, 2);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn abort_is_terminal_and_conflicting_retry_cannot_launch() {
    let path = root();
    let mut lifecycle = ProfileLifecycle::open(&path).unwrap();
    let (invocation, reservation, token) = tokens("abort");
    let prepared = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        lifecycle.abort_prepared_context(prepared.clone(), AbortCause::Teardown),
        AbortResult::Aborted(_)
    ));
    assert!(matches!(
        lifecycle.abort_prepared_context(prepared.clone(), AbortCause::Teardown),
        AbortResult::Aborted(_)
    ));
    assert!(matches!(
        lifecycle.abort_prepared_context(prepared.clone(), AbortCause::InvocationCancelled),
        AbortResult::Closed(ProfileOutcome::InternalFailure { .. })
    ));
    assert!(matches!(
        lifecycle.launch_prepared_context(prepared, &token),
        LaunchResult::Closed(ProfileOutcome::InternalFailure { .. })
    ));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn durable_first_creation_is_disabled_without_uuid_protocol() {
    let path = root();
    let mut config = RegistryConfig {
        grant_verifier_available: true,
        sealing_available: true,
        ..RegistryConfig::default()
    };
    config.uuid_protocol_compatible = false;
    let mut lifecycle = ProfileLifecycle::open_with_config(&path, config).unwrap();
    let (invocation, reservation, _) = tokens("durable");
    let result = lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "conversation"),
    );
    assert_eq!(
        result,
        PrepareResult::Closed(ProfileOutcome::NoSession {
            reason_code: "no_session"
        })
    );
    assert!(!path.join(REGISTRY_FILE).exists());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn durable_creation_uses_exact_uuid_and_authority_tuple() {
    let path = root();
    let config = RegistryConfig {
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        uuid_protocol_compatible: true,
        ..RegistryConfig::default()
    };
    let mut lifecycle = ProfileLifecycle::open_with_config(&path, config).unwrap();
    let (invocation, reservation, token) = tokens("durable-create");
    let prepared = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    let opened = match lifecycle.launch_prepared_context(prepared, &token) {
        LaunchResult::Opened(value) => value,
        other => panic!("{other:?}"),
    };
    let snapshot = lifecycle.current_open("conversation");
    assert_eq!(snapshot.open_state, OpenState::Open);
    assert_eq!(snapshot.profile_name.as_deref(), Some("default"));
    assert!(snapshot.profile_uuid.is_some());
    let authority = lifecycle.registry().authority_projection(
        &context("primary", "durable", "conversation"),
        snapshot.profile_uuid.as_deref().unwrap(),
    );
    assert_eq!(authority.project_id, "project-1");
    assert_eq!(authority.session_kind, SessionKind::Primary);
    assert_eq!(
        lifecycle.release_context(opened, ReleaseCause::SessionEnd),
        ReleaseResult::Released
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn rejected_durable_grant_hides_owner_specific_state() {
    let path = root();
    let create_config = RegistryConfig {
        grant_verifier_available: true,
        grant_accepted: true,
        sealing_available: true,
        uuid_protocol_compatible: true,
        ..RegistryConfig::default()
    };
    let mut creator = ProfileLifecycle::open_with_config(&path, create_config).unwrap();
    let (invocation, reservation, token) = tokens("grant-owner");
    let prepared = match creator.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    let _opened = match creator.launch_prepared_context(prepared, &token) {
        LaunchResult::Opened(value) => value,
        other => panic!("{other:?}"),
    };
    drop(creator);
    let denied_config = RegistryConfig {
        grant_verifier_available: true,
        grant_accepted: false,
        sealing_available: true,
        uuid_protocol_compatible: true,
        ..RegistryConfig::default()
    };
    let mut denied = ProfileLifecycle::open_with_config(&path, denied_config).unwrap();
    let (invocation, reservation, _) = tokens("grant-denied");
    assert_eq!(
        denied.prepare_context_open(
            &invocation,
            &reservation,
            &context("primary", "durable", "other-conversation")
        ),
        PrepareResult::Closed(ProfileOutcome::ProfileGrantRequired {
            reason_code: "durable_profile_grant_unavailable"
        })
    );
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn deletion_failure_is_disposable_only_and_keeps_exclusion() {
    let path = root();
    let config = RegistryConfig {
        deletion_failure_after_start: true,
        ..RegistryConfig::default()
    };
    let mut lifecycle = ProfileLifecycle::open_with_config(&path, config).unwrap();
    let (invocation, reservation, token) = tokens("delete-failure");
    let prepared = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    let opened = match lifecycle.launch_prepared_context(prepared, &token) {
        LaunchResult::Opened(value) => value,
        other => panic!("{other:?}"),
    };
    let uuid = lifecycle.current_open("conversation").profile_uuid.unwrap();
    assert!(matches!(
        lifecycle.release_context(opened.clone(), ReleaseCause::SessionEnd),
        ReleaseResult::Closed(ProfileOutcome::StorageUnavailable { .. })
    ));
    assert!(lifecycle.is_effectively_excluded(&uuid));
    assert!(matches!(
        lifecycle.release_context(opened, ReleaseCause::SessionEnd),
        ReleaseResult::Closed(ProfileOutcome::StorageUnavailable { .. })
    ));
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn deletion_requires_complete_fresh_fenced_absence() {
    let path = root();
    let mut lifecycle = ProfileLifecycle::open(&path).unwrap();
    let (invocation, reservation, token) = tokens("delete");
    let prepared = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "conversation"),
    ) {
        PrepareResult::Prepared(value) => value,
        other => panic!("{other:?}"),
    };
    let opened = match lifecycle.launch_prepared_context(prepared, &token) {
        LaunchResult::Opened(value) => value,
        other => panic!("{other:?}"),
    };
    let uuid = lifecycle.current_open("conversation").profile_uuid.unwrap();
    let bad = LivenessObservation {
        complete: false,
        ..LivenessObservation::all_absent(2, 2)
    };
    assert!(lifecycle
        .delete_disposable_with_proof(&uuid, bad, DeletionFence::held(2))
        .is_err());
    assert!(matches!(
        lifecycle.release_context(opened, ReleaseCause::SessionEnd),
        ReleaseResult::Released
    ));
    fs::remove_dir_all(path).unwrap();
}

/// Names the managed root a slot helper process holds the registry slot in.
const SLOT_HELPER_ROOT: &str = "CK_TEST_PROFILE_SLOT_HELPER_ROOT";

/// Run only as a child process of the slot tests below: takes the registry
/// slot in the root they name, says so by creating `ready` beside it, and
/// holds the slot until killed.
#[test]
#[ignore = "a helper process for the registry slot tests"]
fn slot_helper_holds_the_registry_slot_until_killed() {
    let Some(root) = std::env::var_os(SLOT_HELPER_ROOT).map(PathBuf::from) else {
        return;
    };
    let registry = ProfileRegistry::open(&root).unwrap();
    let _slot = registry.acquire_slot_lock().unwrap();
    fs::write(root.with_file_name("ready"), b"").unwrap();
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}

/// A scratch managed root under `/tmp`, where tests that start child
/// processes keep their files.
fn slot_scratch() -> PathBuf {
    let scratch = PathBuf::from("/tmp").join(format!(
        "ck-s8-slot-{}-{}",
        std::process::id(),
        ROOT_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(scratch.join("root")).unwrap();
    scratch
}

fn contended(resolution: Result<DurableResolution, RegistryError>) -> bool {
    matches!(
        resolution,
        Err(RegistryError::Untrustworthy(
            UntrustworthyRegistryReason::LockContentionWithoutOwnerProof
        ))
    )
}

/// A holder killed while it holds the registry slot must not lock every later
/// open out of the managed root, while a live holder still excludes others.
#[test]
fn a_killed_slot_holder_does_not_lock_out_the_next_open() {
    let scratch = slot_scratch();
    let root = scratch.join("root");
    let mut helper = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "profile::tests::slot_helper_holds_the_registry_slot_until_killed",
            "--ignored",
        ])
        .env(SLOT_HELPER_ROOT, &root)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    let started = std::time::Instant::now();
    while !scratch.join("ready").exists() {
        assert!(
            helper.try_wait().unwrap().is_none(),
            "the helper exited before taking the slot"
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(60));
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let lifecycle = ProfileLifecycle::open(&root).unwrap();
    assert!(
        contended(lifecycle.registry().resolve_durable("project-2")),
        "a live holder must exclude a second writer"
    );
    helper.kill().unwrap();
    helper.wait().unwrap();
    let reopened = ProfileLifecycle::open(&root).unwrap();
    assert_eq!(
        reopened.registry().resolve_durable("project-2").unwrap(),
        DurableResolution::AffirmativeAbsence
    );
    assert!(!root.join(DURABLE_LOCK_FILE).exists());
    fs::remove_dir_all(scratch).unwrap();
}

/// Older builds take the slot by creating an empty sentinel exclusively. While
/// one holds it this build refuses, and while this build holds the slot an
/// older build's exclusive create fails; a clean release removes the sentinel.
#[test]
fn the_registry_slot_excludes_older_builds_both_ways() {
    let path = root();
    let lifecycle = ProfileLifecycle::open(&path).unwrap();
    let sentinel = path.join(DURABLE_LOCK_FILE);
    fs::write(&sentinel, b"").unwrap();
    assert!(contended(lifecycle.registry().resolve_durable("project-2")));
    assert!(
        sentinel.exists(),
        "an older build's sentinel is never removed"
    );
    fs::remove_file(&sentinel).unwrap();

    let slot = lifecycle.registry().acquire_slot_lock().unwrap();
    let older = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&sentinel);
    assert_eq!(older.unwrap_err().kind(), io::ErrorKind::AlreadyExists);
    drop(slot);
    assert!(!sentinel.exists());
    fs::remove_dir_all(path).unwrap();
}
