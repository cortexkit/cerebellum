use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use cerebellum::browser_launch::{
    map_profile_outcome, BrowserLaunchOutcome, LaunchCleanupStage, ProfileBoundLaunch,
};
use cerebellum::profile::{
    stamped_bind_context, BindFacts, DispatchCommitmentToken, DurableResolution, FailureOrigin,
    InvocationToken, JournalReservationHandle, LaunchResult, PrepareResult, ProfileLifecycle,
    ProfileOutcome, ProfileState, RegistryConfig,
};
use cerebellum::profile_custody::{
    classify_supervisor_start_time, read_record_if_present, ProfileCustodyAcquisition,
    ProfileCustodyEvent, ProfileCustodyEventKind, ProfileCustodyJournal, ProfileCustodyKey,
    ProfileCustodyLockError, ProfileCustodyLockRecord, ProfileCustodyLocks, ProfileCustodyRelease,
    SupervisorGeneration, SupervisorLiveness, SupervisorLivenessProbe,
};
use serde_json::{json, Value};

struct TestRoot(PathBuf);

impl TestRoot {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "cerebellum-profile-custody-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestRoot {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[derive(Clone, Default)]
struct RecordingJournal(Arc<Mutex<Vec<ProfileCustodyEvent>>>);

impl RecordingJournal {
    fn events(&self) -> Vec<ProfileCustodyEvent> {
        self.0.lock().unwrap().clone()
    }
}

impl ProfileCustodyJournal for RecordingJournal {
    fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()> {
        self.0.lock().unwrap().push(event.clone());
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct GenerationProbe {
    live: SupervisorGeneration,
}

impl SupervisorLivenessProbe for GenerationProbe {
    fn observe(&self, generation: SupervisorGeneration) -> SupervisorLiveness {
        if generation == self.live {
            SupervisorLiveness::Live
        } else {
            SupervisorLiveness::NotLive
        }
    }
}

#[derive(Clone)]
struct StaleBarrierProbe {
    live: SupervisorGeneration,
    stale_barrier: Arc<Barrier>,
}

impl SupervisorLivenessProbe for StaleBarrierProbe {
    fn observe(&self, generation: SupervisorGeneration) -> SupervisorLiveness {
        if generation == self.live {
            SupervisorLiveness::Live
        } else {
            SupervisorLiveness::NotLive
        }
    }

    fn stale_evidence_recorded(&self) {
        self.stale_barrier.wait();
    }
}

#[derive(Clone, Copy)]
struct AlwaysLive;

impl SupervisorLivenessProbe for AlwaysLive {
    fn observe(&self, _generation: SupervisorGeneration) -> SupervisorLiveness {
        SupervisorLiveness::Live
    }
}

struct FailStaleJournal;

impl ProfileCustodyJournal for FailStaleJournal {
    fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()> {
        if event.kind == ProfileCustodyEventKind::StaleBreak {
            Err(io::Error::other("stale evidence journal unavailable"))
        } else {
            Ok(())
        }
    }
}

#[derive(Clone, Copy)]
struct FailEventJournal {
    fail: ProfileCustodyEventKind,
}

impl ProfileCustodyJournal for FailEventJournal {
    fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()> {
        if event.kind == self.fail {
            Err(io::Error::other("requested journal failure"))
        } else {
            Ok(())
        }
    }
}

fn generation(pid: u32, start_time: u64) -> SupervisorGeneration {
    SupervisorGeneration { pid, start_time }
}

fn context(
    kind: &str,
    disposition: &str,
    conversation: &str,
) -> cerebellum::profile::StampedBindContext {
    stamped_bind_context(BindFacts {
        principal: "direct:agent".into(),
        conversation_key: conversation.into(),
        agent_project_id: "project-1".into(),
        session_kind: Some(kind.into()),
        session_kind_attested: true,
        profile_disposition: Some(disposition.into()),
        effective_capability_scope: Some(vec!["browser.launch".into()]),
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
    let commitment =
        DispatchCommitmentToken::for_test(&invocation, &reservation, format!("commitment-{id}"));
    (invocation, reservation, commitment)
}

fn durable_config() -> RegistryConfig {
    RegistryConfig {
        uuid_protocol_compatible: true,
        grant_verifier_available: true,
        sealing_available: true,
        ..RegistryConfig::default()
    }
}

fn profile_lock_paths(root: &Path) -> Vec<PathBuf> {
    let custody = root.join(".ck-browser-profile-custody");
    fs::read_dir(custody)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.len() == 69 && name.ends_with(".lock"))
        })
        .collect()
}

fn profile_lock_path(root: &Path) -> PathBuf {
    let paths = profile_lock_paths(root);
    assert_eq!(paths.len(), 1, "exactly one profile lock must exist");
    paths[0].clone()
}

fn profile_directory_count(root: &Path) -> usize {
    fs::read_dir(root.join("profiles"))
        .unwrap()
        .map(Result::unwrap)
        .count()
}

#[test]
fn one_supervisor_mints_distinct_holders_for_distinct_attempts() {
    let root = TestRoot::new("distinct-holders");
    let supervisor = generation(40, 4000);
    let locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();

    let first = locks.mint_holder().unwrap();
    let second = locks.mint_holder().unwrap();

    assert_ne!(first, second);
}

#[test]
fn a_second_attempt_names_the_winning_holder_and_prepares_no_second_profile() {
    let root = TestRoot::new("busy-holder");
    let supervisor = generation(41, 4100);
    let journal = RecordingJournal::default();
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        journal.clone(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let mut first_lifecycle =
        ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let (first_invocation, first_reservation, _) = tokens("first");
    let first = ProfileBoundLaunch::new(&mut first_lifecycle, &mut locks)
        .acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &first_invocation,
            &first_reservation,
            &context("primary", "durable", "conversation-one"),
        )
        .unwrap();
    let winner = first.holder_id().clone();
    let installed: Value =
        serde_json::from_slice(&fs::read(profile_lock_path(root.path())).unwrap()).unwrap();
    assert_eq!(installed["holder_id"], winner.as_str());
    assert_eq!(installed["supervisor_pid"], supervisor.pid);
    assert_eq!(installed["supervisor_start_time"], supervisor.start_time);
    assert!(installed.get("profile_uuid").is_none());
    assert_eq!(profile_directory_count(root.path()), 1);

    let mut second_lifecycle =
        ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let mut second_locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        journal,
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (second_invocation, second_reservation, _) = tokens("second");
    let outcome = ProfileBoundLaunch::new(&mut second_lifecycle, &mut second_locks)
        .acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &second_invocation,
            &second_reservation,
            &context("primary", "durable", "conversation-two"),
        )
        .unwrap_err();

    assert_eq!(
        outcome,
        BrowserLaunchOutcome::ProfileBusy { holder_id: winner }
    );
    assert_eq!(profile_directory_count(root.path()), 1);
    assert_eq!(second_lifecycle.pending_preparation_count(), 0);
}

#[test]
fn a_held_lock_and_registry_profile_busy_is_internal_failure() {
    let root = TestRoot::new("artifact-disagreement");
    let mut owner = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let (invocation, reservation, commitment) = tokens("existing-owner");
    let prepared = match owner.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "owner-conversation"),
    ) {
        PrepareResult::Prepared(prepared) => prepared,
        other => panic!("unexpected preparation: {other:?}"),
    };
    assert!(matches!(
        owner.launch_prepared_context(prepared, &commitment),
        LaunchResult::Opened(_)
    ));

    let supervisor = generation(42, 4200);
    let mut contender = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (next_invocation, next_reservation, _) = tokens("contender");
    let outcome = ProfileBoundLaunch::new(&mut contender, &mut locks)
        .acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &next_invocation,
            &next_reservation,
            &context("primary", "durable", "contender-conversation"),
        )
        .unwrap_err();

    assert_eq!(outcome, BrowserLaunchOutcome::InternalFailure);
    assert!(profile_lock_paths(root.path()).is_empty());
    assert_eq!(profile_directory_count(root.path()), 1);
}

#[test]
fn stale_generation_is_journaled_then_broken_but_live_generation_is_not() {
    let root = TestRoot::new("stale-live");
    let stale = generation(51, 5100);
    let current = generation(51, 5200);
    let key = ProfileCustodyKey::durable("project-1");
    let seed_journal = RecordingJournal::default();
    let mut seed = ProfileCustodyLocks::open(root.path(), stale, seed_journal, AlwaysLive).unwrap();
    let stale_holder = seed.mint_holder().unwrap();
    assert!(matches!(
        seed.acquire(key.clone(), stale_holder),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));

    let break_journal = RecordingJournal::default();
    let mut breaker = ProfileCustodyLocks::open(
        root.path(),
        current,
        break_journal.clone(),
        GenerationProbe { live: current },
    )
    .unwrap();
    let winner = breaker.mint_holder().unwrap();
    assert!(matches!(
        breaker.acquire(key.clone(), winner.clone()),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));
    let events = break_journal.events();
    assert_eq!(events[0].kind, ProfileCustodyEventKind::StaleBreak);
    assert_eq!(events[0].supervisor, stale);
    assert_eq!(events[1].kind, ProfileCustodyEventKind::HolderAcquire);

    let live_journal = RecordingJournal::default();
    let mut live_contender = ProfileCustodyLocks::open(
        root.path(),
        current,
        live_journal.clone(),
        GenerationProbe { live: current },
    )
    .unwrap();
    let loser = live_contender.mint_holder().unwrap();
    assert_eq!(
        live_contender.acquire(key, loser).unwrap(),
        ProfileCustodyAcquisition::ProfileBusy { holder_id: winner }
    );
    assert!(live_journal.events().is_empty());
}

#[test]
fn a_recycled_pid_with_a_different_start_time_is_not_the_recorded_process() {
    let root = TestRoot::new("pid-reuse");
    let recorded = generation(61, 6100);
    let recycled = generation(61, 6200);
    assert_eq!(
        classify_supervisor_start_time(recorded, Some(recorded.start_time)),
        SupervisorLiveness::Live
    );
    assert_eq!(
        classify_supervisor_start_time(recorded, Some(recycled.start_time)),
        SupervisorLiveness::NotLive
    );
    let key = ProfileCustodyKey::durable("project-1");
    let mut seed = ProfileCustodyLocks::open(
        root.path(),
        recorded,
        RecordingJournal::default(),
        AlwaysLive,
    )
    .unwrap();
    let old_holder = seed.mint_holder().unwrap();
    assert!(matches!(
        seed.acquire(key.clone(), old_holder),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));

    let mut breaker = ProfileCustodyLocks::open(
        root.path(),
        recycled,
        RecordingJournal::default(),
        GenerationProbe { live: recycled },
    )
    .unwrap();
    let new_holder = breaker.mint_holder().unwrap();
    assert!(matches!(
        breaker.acquire(key, new_holder),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));
}

#[test]
fn custody_lock_reader_exposes_the_validated_supervisor_generation() {
    let root = TestRoot::new("public-lock-reader");
    let lock = root.path().join("reader.lock");
    fs::write(
        &lock,
        r#"{"format_version":"ck-browser-profile-custody-lock/v1","holder_id":"reader-holder","supervisor_pid":17,"supervisor_start_time":1700,"profile_directory":null}"#,
    )
    .unwrap();

    let record: ProfileCustodyLockRecord = read_record_if_present(&lock)
        .unwrap()
        .expect("record is present");

    assert_eq!(record.supervisor(), generation(17, 1700));
}

#[test]
fn failed_acquisition_journal_prevents_lock_installation() {
    let root = TestRoot::new("acquisition-journal-failure");
    let supervisor = generation(70, 7000);
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        FailEventJournal {
            fail: ProfileCustodyEventKind::HolderAcquire,
        },
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let holder = locks.mint_holder().unwrap();

    assert!(matches!(
        locks.acquire(ProfileCustodyKey::durable("project-1"), holder),
        Err(ProfileCustodyLockError::Journal(_))
    ));
    assert!(profile_lock_paths(root.path()).is_empty());
}

#[test]
fn failed_stale_break_journal_prevents_the_mutation() {
    let root = TestRoot::new("stale-journal-failure");
    let stale = generation(71, 7100);
    let current = generation(71, 7200);
    let key = ProfileCustodyKey::durable("project-1");
    let mut seed =
        ProfileCustodyLocks::open(root.path(), stale, RecordingJournal::default(), AlwaysLive)
            .unwrap();
    let old_holder = seed.mint_holder().unwrap();
    assert!(matches!(
        seed.acquire(key.clone(), old_holder.clone()),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));

    let mut breaker = ProfileCustodyLocks::open(
        root.path(),
        current,
        FailStaleJournal,
        GenerationProbe { live: current },
    )
    .unwrap();
    let attempted = breaker.mint_holder().unwrap();
    assert!(matches!(
        breaker.acquire(key.clone(), attempted),
        Err(ProfileCustodyLockError::Journal(_))
    ));

    let mut observer =
        ProfileCustodyLocks::open(root.path(), stale, RecordingJournal::default(), AlwaysLive)
            .unwrap();
    let observer_holder = observer.mint_holder().unwrap();
    assert_eq!(
        observer.acquire(key, observer_holder).unwrap(),
        ProfileCustodyAcquisition::ProfileBusy {
            holder_id: old_holder
        }
    );
}

#[test]
fn concurrent_stale_breakers_have_one_winner_and_loser_names_it() {
    let root = TestRoot::new("concurrent-breakers");
    let stale = generation(81, 8100);
    let current = generation(81, 8200);
    let key = ProfileCustodyKey::durable("project-1");
    let mut seed =
        ProfileCustodyLocks::open(root.path(), stale, RecordingJournal::default(), AlwaysLive)
            .unwrap();
    let stale_holder = seed.mint_holder().unwrap();
    assert!(matches!(
        seed.acquire(key.clone(), stale_holder),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));

    let start_barrier = Arc::new(Barrier::new(3));
    let stale_barrier = Arc::new(Barrier::new(2));
    let mut threads = Vec::new();
    for _ in 0..2 {
        let root = root.path().to_path_buf();
        let key = key.clone();
        let start_barrier = start_barrier.clone();
        let stale_barrier = stale_barrier.clone();
        threads.push(thread::spawn(move || {
            let mut locks = ProfileCustodyLocks::open(
                root,
                current,
                RecordingJournal::default(),
                StaleBarrierProbe {
                    live: current,
                    stale_barrier,
                },
            )
            .unwrap();
            let holder = locks.mint_holder().unwrap();
            start_barrier.wait();
            locks.acquire(key, holder).unwrap()
        }));
    }
    start_barrier.wait();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();

    let winner = results
        .iter()
        .find_map(|result| match result {
            ProfileCustodyAcquisition::Acquired(claim) => Some(claim.holder_id().clone()),
            ProfileCustodyAcquisition::ProfileBusy { .. } => None,
        })
        .expect("one thread must acquire");
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, ProfileCustodyAcquisition::Acquired(_)))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| {
                matches!(
                    result,
                    ProfileCustodyAcquisition::ProfileBusy { holder_id }
                        if holder_id == &winner
                )
            })
            .count(),
        1
    );
}

#[test]
fn durable_rollback_leaves_directory_and_disposable_deletes_only_recorded_directory() {
    let durable_root = TestRoot::new("durable-rollback");
    let supervisor = generation(91, 9100);
    let mut durable_lifecycle =
        ProfileLifecycle::open_with_config(durable_root.path(), durable_config()).unwrap();
    let mut durable_locks = ProfileCustodyLocks::open(
        durable_root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (invocation, reservation, _) = tokens("durable-rollback");
    let mut service = ProfileBoundLaunch::new(&mut durable_lifecycle, &mut durable_locks);
    let held = service
        .acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &invocation,
            &reservation,
            &context("primary", "durable", "durable-conversation"),
        )
        .unwrap();
    let durable_directory = held.attempt().directory().to_path_buf();
    service.rollback_prepared(held).unwrap();
    assert!(durable_directory.is_dir());
    let durable_record = match durable_lifecycle
        .registry()
        .resolve_durable("project-1")
        .unwrap()
    {
        DurableResolution::TrustworthyExisting(record) => record,
        other => panic!("unexpected durable resolution after rollback: {other:?}"),
    };
    assert_eq!(durable_record.state, ProfileState::Released);

    let disposable_root = TestRoot::new("disposable-rollback");
    let mut disposable_lifecycle = ProfileLifecycle::open(disposable_root.path()).unwrap();
    let disposable_journal = RecordingJournal::default();
    let mut disposable_locks = ProfileCustodyLocks::open(
        disposable_root.path(),
        supervisor,
        disposable_journal.clone(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (invocation, reservation, _) = tokens("disposable-rollback");
    let holder = disposable_locks.mint_holder().unwrap();
    let mut service = ProfileBoundLaunch::new(&mut disposable_lifecycle, &mut disposable_locks);
    let held = service
        .acquire_and_prepare(
            ProfileCustodyKey::disposable("project-1", "subagent-conversation", &holder),
            &invocation,
            &reservation,
            &context("subagent", "disposable", "subagent-conversation"),
        )
        .unwrap();
    let disposable_directory = held.attempt().directory().to_path_buf();
    let sibling = disposable_root.path().join("profiles/sibling-must-survive");
    fs::create_dir(&sibling).unwrap();
    fs::write(sibling.join("marker"), b"not this attempt").unwrap();
    service.rollback_prepared(held).unwrap();
    assert!(!disposable_directory.exists());
    assert_eq!(
        fs::read(sibling.join("marker")).unwrap(),
        b"not this attempt"
    );
    assert_eq!(
        disposable_journal
            .events()
            .into_iter()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        vec![
            ProfileCustodyEventKind::HolderAcquire,
            ProfileCustodyEventKind::ProfileDirectoryBind,
            ProfileCustodyEventKind::RollbackTerminalization,
            ProfileCustodyEventKind::DisposableDelete,
            ProfileCustodyEventKind::HolderRelease,
        ]
    );
}

fn assert_cleanup_journal_failure(
    label: &str,
    event: ProfileCustodyEventKind,
    stage: LaunchCleanupStage,
) {
    let root = TestRoot::new(label);
    let supervisor = generation(95, 9500);
    let mut lifecycle = ProfileLifecycle::open(root.path()).unwrap();
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        FailEventJournal { fail: event },
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (invocation, reservation, _) = tokens(label);
    let key_holder = locks.mint_holder().unwrap();
    let mut service = ProfileBoundLaunch::new(&mut lifecycle, &mut locks);
    let held = service
        .acquire_and_prepare(
            ProfileCustodyKey::disposable("project-1", "conversation", &key_holder),
            &invocation,
            &reservation,
            &context("subagent", "disposable", "conversation"),
        )
        .unwrap();
    let directory = held.attempt().directory().to_path_buf();

    assert_eq!(
        service.rollback_prepared(held),
        Err(BrowserLaunchOutcome::CleanupFailure { stage })
    );
    assert!(directory.is_dir());
    assert_eq!(profile_lock_paths(root.path()).len(), 1);
}

#[test]
fn terminalization_journal_failure_prevents_cleanup_mutation() {
    assert_cleanup_journal_failure(
        "terminalization-journal",
        ProfileCustodyEventKind::RollbackTerminalization,
        LaunchCleanupStage::RecordTerminalization,
    );
}

#[test]
fn holder_release_journal_failure_prevents_lock_release() {
    assert_cleanup_journal_failure(
        "release-journal",
        ProfileCustodyEventKind::HolderRelease,
        LaunchCleanupStage::CustodyRelease,
    );
}

#[test]
fn durable_record_is_terminal_before_custody_release_begins() {
    let root = TestRoot::new("durable-terminal-before-release");
    let supervisor = generation(96, 9600);
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        FailEventJournal {
            fail: ProfileCustodyEventKind::HolderRelease,
        },
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (invocation, reservation, _) = tokens("durable-terminal-before-release");
    {
        let mut service = ProfileBoundLaunch::new(&mut lifecycle, &mut locks);
        let held = service
            .acquire_and_prepare(
                ProfileCustodyKey::durable("project-1"),
                &invocation,
                &reservation,
                &context("primary", "durable", "conversation"),
            )
            .unwrap();

        assert_eq!(
            service.rollback_prepared(held),
            Err(BrowserLaunchOutcome::CleanupFailure {
                stage: LaunchCleanupStage::CustodyRelease,
            })
        );
    }
    let record = match lifecycle.registry().resolve_durable("project-1").unwrap() {
        DurableResolution::TrustworthyExisting(record) => record,
        other => panic!("unexpected durable resolution after terminalization: {other:?}"),
    };
    assert_eq!(record.state, ProfileState::Released);
    assert_eq!(profile_lock_paths(root.path()).len(), 1);
}

#[test]
fn disposable_delete_journal_failure_prevents_directory_deletion() {
    assert_cleanup_journal_failure(
        "delete-journal",
        ProfileCustodyEventKind::DisposableDelete,
        LaunchCleanupStage::DisposableDelete,
    );
}

#[test]
fn pre_readiness_rollback_terminalizes_releases_and_deletes_after_profile_launch() {
    let root = TestRoot::new("pre-readiness-rollback");
    let supervisor = generation(96, 9600);
    let mut lifecycle = ProfileLifecycle::open(root.path()).unwrap();
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (invocation, reservation, commitment) = tokens("pre-readiness");
    let key_holder = locks.mint_holder().unwrap();
    let mut service = ProfileBoundLaunch::new(&mut lifecycle, &mut locks);
    let held = service
        .acquire_and_prepare(
            ProfileCustodyKey::disposable("project-1", "conversation", &key_holder),
            &invocation,
            &reservation,
            &context("subagent", "disposable", "conversation"),
        )
        .unwrap();
    let directory = held.attempt().directory().to_path_buf();
    let opened = service.launch_prepared(held, &commitment).unwrap();
    let mut rollback = service.into_opened_rollback(opened);

    rollback.rollback_now().unwrap();

    assert!(!directory.exists());
    assert!(profile_lock_paths(root.path()).is_empty());
    assert_eq!(rollback.cleanup_failure(), None);
}

#[test]
fn release_exact_refuses_a_mismatched_holder_without_removing_the_lock() {
    let root = TestRoot::new("mismatched-release");
    let supervisor = generation(98, 9800);
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let winner = locks.mint_holder().unwrap();
    let loser = locks.mint_holder().unwrap();
    let mut claim = match locks
        .acquire(
            ProfileCustodyKey::disposable("project-1", "conversation", &winner),
            winner,
        )
        .unwrap()
    {
        ProfileCustodyAcquisition::Acquired(claim) => claim,
        other => panic!("unexpected first acquisition: {other:?}"),
    };
    let directory = root.path().join("release-target");
    fs::create_dir(&directory).unwrap();
    locks
        .bind_profile_directory(&mut claim, &directory)
        .unwrap();
    let loser_claim = claim.with_holder_for_test(loser.clone());

    assert_eq!(
        locks.release_exact(&loser_claim).unwrap(),
        ProfileCustodyRelease::HolderMismatch {
            installed_holder_id: claim.holder_id().clone(),
        }
    );
    assert_eq!(profile_lock_paths(root.path()).len(), 1);
    assert!(directory.is_dir());
}

#[test]
fn mismatched_holder_rollback_releases_nothing_and_deletes_nothing() {
    let root = TestRoot::new("mismatched-holder");
    let supervisor = generation(101, 10100);
    let mut lifecycle = ProfileLifecycle::open(root.path()).unwrap();
    let mut locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let (invocation, reservation, _) = tokens("mismatched-holder");
    let key_holder = locks.mint_holder().unwrap();
    let mut service = ProfileBoundLaunch::new(&mut lifecycle, &mut locks);
    let held = service
        .acquire_and_prepare(
            ProfileCustodyKey::disposable("project-1", "conversation", &key_holder),
            &invocation,
            &reservation,
            &context("subagent", "disposable", "conversation"),
        )
        .unwrap();
    let directory = held.attempt().directory().to_path_buf();
    let lock_path = profile_lock_path(root.path());
    let mut lock: Value = serde_json::from_slice(&fs::read(&lock_path).unwrap()).unwrap();
    lock["holder_id"] = Value::String("holder-tampered-owner".to_string());
    fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();

    assert_eq!(
        service.rollback_prepared(held),
        Err(BrowserLaunchOutcome::CleanupFailure {
            stage: LaunchCleanupStage::CustodyRelease
        })
    );
    assert!(lock_path.exists());
    assert!(directory.is_dir());
}

fn assert_no_profile_uuid(value: &Value) {
    match value {
        Value::Object(object) => {
            assert!(!object.contains_key("profile_uuid"));
            for value in object.values() {
                assert_no_profile_uuid(value);
            }
        }
        Value::Array(values) => {
            for value in values {
                assert_no_profile_uuid(value);
            }
        }
        _ => {}
    }
}

#[cfg(unix)]
#[test]
fn registry_root_identity_refusal_is_not_reported_as_profile_storage_unavailable() {
    let root = TestRoot::new("registry-root-rebound");
    let durable_context = context("primary", "durable", "root-rebound-first");
    let (first_invocation, first_reservation, _) = tokens("root-rebound-first");
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    assert!(matches!(
        lifecycle.prepare_context_open(&first_invocation, &first_reservation, &durable_context,),
        PrepareResult::Prepared(_)
    ));
    drop(lifecycle);

    let previous_root = root.path().with_extension("previous-binding");
    fs::rename(root.path(), &previous_root).unwrap();
    fs::create_dir(root.path()).unwrap();
    for entry in fs::read_dir(&previous_root).unwrap() {
        let entry = entry.unwrap();
        fs::rename(entry.path(), root.path().join(entry.file_name())).unwrap();
    }

    let rebound_context = context("primary", "durable", "root-rebound-second");
    let (invocation, reservation, _) = tokens("root-rebound-second");
    let mut rebound_lifecycle =
        ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let outcome =
        match rebound_lifecycle.prepare_context_open(&invocation, &reservation, &rebound_context) {
            PrepareResult::Closed(outcome) => outcome,
            PrepareResult::Prepared(_) => panic!("rebound root must remain closed"),
        };
    assert_eq!(
        outcome,
        ProfileOutcome::StorageUnavailable {
            reason_code: "profile_registry_managed_root_identity_changed",
            origin: FailureOrigin::RegistryOrStorage,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_registry_untrusted_root",
            "reason_code": "profile_registry_managed_root_identity_changed",
        })
    );

    fs::remove_dir(previous_root).unwrap();
}

#[test]
fn unaccounted_profile_directory_reports_why_the_root_is_untrusted() {
    let root = TestRoot::new("possibly-managed-path");
    fs::create_dir_all(root.path().join("profiles/unaccounted-profile")).unwrap();
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let (invocation, reservation, _) = tokens("possibly-managed-path");

    let outcome = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "possibly-managed-path"),
    ) {
        PrepareResult::Closed(outcome) => outcome,
        PrepareResult::Prepared(_) => panic!("unaccounted profile directory must remain closed"),
    };
    assert_eq!(
        outcome,
        ProfileOutcome::StorageUnavailable {
            reason_code: "profile_registry_possibly_managed_path",
            origin: FailureOrigin::RegistryOrStorage,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_registry_untrusted_root",
            "reason_code": "profile_registry_possibly_managed_path",
        })
    );
}

#[cfg(unix)]
#[test]
fn missing_managed_root_still_reports_profile_storage_unavailable() {
    let root = TestRoot::new("missing-managed-root");
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    fs::remove_dir(root.path()).unwrap();

    let (invocation, reservation, _) = tokens("missing-managed-root");
    let outcome = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "missing-managed-root"),
    ) {
        PrepareResult::Closed(outcome) => outcome,
        PrepareResult::Prepared(_) => panic!("missing root must remain closed"),
    };
    assert_eq!(
        outcome,
        ProfileOutcome::StorageUnavailable {
            reason_code: "profile_storage_unavailable",
            origin: FailureOrigin::RegistryOrStorage,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({"outcome": "profile_storage_unavailable"})
    );
}

#[test]
fn internal_profile_busy_display_does_not_serialize_the_profile_uuid() {
    let outcome = ProfileOutcome::ProfileBusy {
        profile_uuid: "internal-profile-secret".to_string(),
    };

    assert_eq!(outcome.to_string(), "profile_busy");
    assert!(!outcome.to_string().contains("internal-profile-secret"));
}

#[test]
fn every_wire_outcome_is_structurally_profile_uuid_free() {
    let root = TestRoot::new("wire-shape");
    let supervisor = generation(111, 11100);
    let locks = ProfileCustodyLocks::open(
        root.path(),
        supervisor,
        RecordingJournal::default(),
        GenerationProbe { live: supervisor },
    )
    .unwrap();
    let holder = locks.mint_holder().unwrap();
    let outcomes = [
        BrowserLaunchOutcome::ProfileBusy { holder_id: holder },
        BrowserLaunchOutcome::ProfileGrantRequired,
        BrowserLaunchOutcome::ProfileRegistryUntrustedRoot {
            reason_code: "profile_registry_managed_root_identity_changed",
        },
        BrowserLaunchOutcome::ProfileStorageUnavailable,
        BrowserLaunchOutcome::InternalFailure,
        BrowserLaunchOutcome::CleanupFailure {
            stage: LaunchCleanupStage::RecordTerminalization,
        },
        BrowserLaunchOutcome::CleanupFailure {
            stage: LaunchCleanupStage::CustodyRelease,
        },
        BrowserLaunchOutcome::CleanupFailure {
            stage: LaunchCleanupStage::DisposableDelete,
        },
    ];
    for outcome in outcomes {
        assert_no_profile_uuid(&outcome.as_json());
    }
}
