use std::fs;
use std::io;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
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
    ProfileOutcome, ProfileState, RegistryConfig, UntrustworthyRegistryReason,
};
use cerebellum::profile_custody::{
    classify_process_generation, classify_supervisor_start_time, read_record_if_present, BootId,
    GenerationObservation, ProfileCustodyAcquisition, ProfileCustodyEvent, ProfileCustodyEventKind,
    ProfileCustodyJournal, ProfileCustodyKey, ProfileCustodyLockError, ProfileCustodyLockRecord,
    ProfileCustodyLocks, ProfileCustodyRelease, StartTimeStability, SupervisorGeneration,
    SupervisorLiveness, SupervisorLivenessProbe,
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
    SupervisorGeneration {
        pid,
        start_time,
        boot_id: None,
        #[cfg(windows)]
        generation_unit: None,
    }
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
fn registry_profile_busy_is_typed_with_a_recovery_remedy() {
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

    assert_eq!(outcome, BrowserLaunchOutcome::RegistryProfileBusy);
    let reply = outcome.as_json();
    assert_eq!(reply["outcome"], "profile_busy");
    assert_eq!(reply["reason_code"], "registry_profile_busy");
    assert!(reply["remedy"]
        .as_str()
        .unwrap()
        .contains("supervisor liveness"));
    assert!(reply["remedy"]
        .as_str()
        .unwrap()
        .contains("launch the browser"));
    assert!(profile_lock_paths(root.path()).is_empty());
    assert_eq!(profile_directory_count(root.path()), 1);
}

#[test]
fn lifecycle_internal_failures_keep_named_codes_on_the_launch_wire() {
    let root = TestRoot::new("named-internal-failures");
    let mut lifecycle = ProfileLifecycle::open(root.path()).unwrap();
    let invocation = InvocationToken::for_test("invocation-a");
    let reservation_invocation = InvocationToken::for_test("invocation-b");
    let reservation =
        JournalReservationHandle::for_test(&reservation_invocation, "reservation-mismatched");

    let mismatch = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "mismatched-reservation"),
    ) {
        PrepareResult::Closed(outcome) => outcome,
        PrepareResult::Prepared(_) => panic!("mismatched reservation was prepared"),
    };
    assert_eq!(
        mismatch,
        ProfileOutcome::InternalFailure {
            reason_code: "invocation_reservation_mismatch",
        }
    );
    assert_eq!(
        map_profile_outcome(mismatch).as_json(),
        json!({
            "outcome": "internal_failure",
            "reason_code": "invocation_reservation_mismatch",
        })
    );

    let (invocation, reservation, _) = tokens("committed-preparation");
    let prepared = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("subagent", "disposable", "mismatched-commitment"),
    ) {
        PrepareResult::Prepared(prepared) => prepared,
        PrepareResult::Closed(outcome) => panic!("preparation unexpectedly closed: {outcome:?}"),
    };
    let (_, _, different_commitment) = tokens("different-commitment");
    let mismatch = match lifecycle.launch_prepared_context(prepared, &different_commitment) {
        LaunchResult::Closed(outcome) => outcome,
        LaunchResult::Opened(_) => panic!("mismatched commitment opened a profile"),
    };
    assert_eq!(
        mismatch,
        ProfileOutcome::InternalFailure {
            reason_code: "prepared_launch_commitment_mismatch",
        }
    );
    assert_eq!(
        map_profile_outcome(mismatch).as_json(),
        json!({
            "outcome": "internal_failure",
            "reason_code": "prepared_launch_commitment_mismatch",
        })
    );
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
        classify_supervisor_start_time(
            recorded,
            Some(recorded.start_time),
            StartTimeStability::ClockStable
        ),
        SupervisorLiveness::Live
    );
    assert_eq!(
        classify_supervisor_start_time(
            recorded,
            Some(recycled.start_time),
            StartTimeStability::ClockStable
        ),
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
        ProfileOutcome::UntrustworthyRegistry {
            reason: UntrustworthyRegistryReason::ManagedRootInodeChanged,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_registry_untrusted_root",
            "reason_code": "profile_registry_managed_root_inode_changed",
            "remedy": "the browser root directory was replaced or restored (its inode differs from the recorded one); run rebind_profile_root to re-identify it; that operation will itself refuse and name any directory the registry did not mint",
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
        ProfileOutcome::UntrustworthyRegistry {
            reason: UntrustworthyRegistryReason::PossiblyManagedPath,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_registry_untrusted_root",
            "reason_code": "profile_registry_possibly_managed_path",
            "remedy": "move or account for the unaccounted profile directories before running rebind_profile_root; the rebind operation will not adopt them",
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
            reason_code: "profile_managed_root_missing",
            origin: FailureOrigin::RegistryOrStorage,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_storage_unavailable",
            "reason_code": "profile_managed_root_missing",
        })
    );
}

#[cfg(unix)]
#[test]
fn unwritable_managed_root_names_the_persistence_condition() {
    let root = TestRoot::new("unwritable-managed-root");
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let original_mode = fs::metadata(root.path()).unwrap().permissions().mode();
    let mut permissions = fs::metadata(root.path()).unwrap().permissions();
    permissions.set_mode(original_mode & !0o222);
    fs::set_permissions(root.path(), permissions).unwrap();

    let (invocation, reservation, _) = tokens("unwritable-managed-root");
    let outcome = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "unwritable-managed-root"),
    ) {
        PrepareResult::Closed(outcome) => outcome,
        PrepareResult::Prepared(_) => panic!("an unwritable root must remain closed"),
    };
    assert_eq!(
        outcome,
        ProfileOutcome::StorageUnavailable {
            reason_code: "profile_managed_root_identity_changed",
            origin: FailureOrigin::RegistryOrStorage,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_storage_unavailable",
            "reason_code": "profile_managed_root_identity_changed",
        })
    );

    let mut permissions = fs::metadata(root.path()).unwrap().permissions();
    permissions.set_mode(original_mode);
    fs::set_permissions(root.path(), permissions).unwrap();
}

#[test]
fn poisoned_profile_registry_lock_names_the_unproven_owner() {
    let root = TestRoot::new("poisoned-profile-registry-lock");
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    fs::write(
        root.path().join(".ck-browser-profile-durable-slot.lock"),
        b"poisoned",
    )
    .unwrap();

    let (invocation, reservation, _) = tokens("poisoned-profile-registry-lock");
    let outcome = match lifecycle.prepare_context_open(
        &invocation,
        &reservation,
        &context("primary", "durable", "poisoned-profile-registry-lock"),
    ) {
        PrepareResult::Closed(outcome) => outcome,
        PrepareResult::Prepared(_) => panic!("a poisoned registry lock must remain closed"),
    };
    assert_eq!(
        outcome,
        ProfileOutcome::StorageUnavailable {
            reason_code: "profile_registry_lock_owner_unproven",
            origin: FailureOrigin::RegistryOrStorage,
        }
    );
    assert_eq!(
        map_profile_outcome(outcome).as_json(),
        json!({
            "outcome": "profile_storage_unavailable",
            "reason_code": "profile_registry_lock_owner_unproven",
        })
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
            reason: UntrustworthyRegistryReason::ManagedRootInodeChanged,
        },
        BrowserLaunchOutcome::ProfileStorageUnavailable {
            reason_code: "fixture_storage_unavailable",
        },
        BrowserLaunchOutcome::InternalFailure {
            reason_code: "fixture_internal_failure",
        },
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

/// A live pid with a different start time is ambiguous where the reading moves
/// with the wall clock, and ambiguity must refuse rather than break the lock.
///
/// `NotLive` is the authority to seize a profile, so reading a clock step as a
/// dead holder would hand a live holder's profile to a second process and
/// journal it as a legitimate stale break. The same mismatch under a
/// clock-stable reading can only be reuse, and there it still breaks. An absent
/// pid is a gone holder under either reading.
#[test]
fn a_start_time_mismatch_refuses_where_the_reading_moves_with_the_clock() {
    let recorded = generation(61, 6100);
    let moved = Some(6100 + 7_201_000_000);
    assert_eq!(
        classify_supervisor_start_time(recorded, moved, StartTimeStability::MovesWithWallClock),
        SupervisorLiveness::Unavailable
    );
    assert_eq!(
        classify_supervisor_start_time(recorded, moved, StartTimeStability::ClockStable),
        SupervisorLiveness::NotLive
    );
    for stability in [
        StartTimeStability::ClockStable,
        StartTimeStability::MovesWithWallClock,
    ] {
        assert_eq!(
            classify_supervisor_start_time(recorded, None, stability),
            SupervisorLiveness::NotLive,
            "a pid no process holds is a gone holder under {stability:?}"
        );
        assert_eq!(
            classify_supervisor_start_time(recorded, Some(recorded.start_time), stability),
            SupervisorLiveness::Live,
        );
    }
}

/// The production probe recognises the running supervisor it recorded.
///
/// Drives the real `KernelSupervisorLiveness` against this process's own
/// generation, on whatever platform runs the suite. The recording side and the
/// observing side are written separately per platform, and they can drift: on
/// Linux the recording arm was wired while the observing arm still answered
/// `Unavailable` for everything, so a lock left by a crashed supervisor could
/// never be judged stale and wedged its profile for good. A platform whose
/// probe cannot read back what its supervisor records fails here.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_production_probe_reads_back_the_generation_this_supervisor_records() {
    use cerebellum::profile_custody::{current_supervisor_generation, KernelSupervisorLiveness};
    let own = current_supervisor_generation().expect("this platform records a supervisor");
    assert_eq!(
        KernelSupervisorLiveness.observe(own),
        SupervisorLiveness::Live
    );
}

const BOOT: BootId = BootId::from_bytes([0x3f; 16]);
const OTHER_BOOT: BootId = BootId::from_bytes([0xa1; 16]);

fn boot_ticks(boot_id: BootId, start_ticks: u64) -> GenerationObservation {
    GenerationObservation::BootTicks {
        boot_id,
        start_ticks,
    }
}

/// Only an exact match of boot and ticks is the recorded process. Neither half
/// moves with the wall clock, so this holds after a clock step as well.
#[test]
fn a_boot_ticks_record_is_live_on_an_exact_boot_and_tick_match() {
    assert_eq!(
        classify_process_generation(6100, Some(BOOT), boot_ticks(BOOT, 6100)),
        SupervisorLiveness::Live
    );
}

/// Every process of an earlier boot ended with it, so a record from another
/// boot names nobody now, however its ticks compare: its pid belongs to an
/// unrelated process and must not be treated as the holder.
#[test]
fn a_boot_ticks_record_from_another_boot_is_gone_even_when_ticks_agree() {
    assert_eq!(
        classify_process_generation(6100, Some(OTHER_BOOT), boot_ticks(BOOT, 6100)),
        SupervisorLiveness::NotLive
    );
}

/// In the same boot, a pid that started at other ticks has been reused. This
/// is no longer ambiguous: ticks since boot do not move with the clock.
#[test]
fn same_boot_different_ticks_is_pid_reuse_and_gone() {
    assert_eq!(
        classify_process_generation(6100, Some(BOOT), boot_ticks(BOOT, 6101)),
        SupervisorLiveness::NotLive
    );
}

#[test]
fn an_absent_pid_is_gone_for_either_record_kind() {
    for recorded_boot in [Some(BOOT), None] {
        assert_eq!(
            classify_process_generation(6100, recorded_boot, GenerationObservation::Absent),
            SupervisorLiveness::NotLive
        );
    }
}

/// `NotLive` lets a restore or respawn proceed over the pid, so failing to
/// read the boot must never produce it.
#[test]
fn an_unreadable_boot_id_is_unavailable_never_gone() {
    for recorded_boot in [Some(BOOT), None] {
        assert_eq!(
            classify_process_generation(
                6100,
                recorded_boot,
                GenerationObservation::BootIdUnreadable
            ),
            SupervisorLiveness::Unavailable
        );
    }
}

#[test]
fn an_unreadable_process_is_unavailable_never_gone() {
    for recorded_boot in [Some(BOOT), None] {
        assert_eq!(
            classify_process_generation(6100, recorded_boot, GenerationObservation::Unreadable),
            SupervisorLiveness::Unavailable
        );
    }
}

/// A record written before the boot ID holds epoch microseconds, which on
/// Linux move with the wall clock. A 7201 s step over a live holder must
/// refuse, not break the lock.
#[test]
fn a_legacy_record_whose_micros_moved_by_a_clock_step_is_unavailable_not_gone() {
    assert_eq!(
        classify_process_generation(
            6100,
            None,
            GenerationObservation::StartTime {
                start_time: 6100 + 7_201_000_000,
                stability: StartTimeStability::MovesWithWallClock,
            },
        ),
        SupervisorLiveness::Unavailable
    );
}

/// macOS records keep their rule: a stored start time that differs is reuse.
#[test]
fn a_clock_stable_record_keeps_its_existing_rule() {
    let observed = |start_time| GenerationObservation::StartTime {
        start_time,
        stability: StartTimeStability::ClockStable,
    };
    assert_eq!(
        classify_process_generation(6100, None, observed(6100)),
        SupervisorLiveness::Live
    );
    assert_eq!(
        classify_process_generation(6100, None, observed(6200)),
        SupervisorLiveness::NotLive
    );
}

#[test]
fn a_reading_in_the_other_unit_cannot_be_compared() {
    assert_eq!(
        classify_process_generation(
            6100,
            Some(BOOT),
            GenerationObservation::StartTime {
                start_time: 6100,
                stability: StartTimeStability::ClockStable,
            },
        ),
        SupervisorLiveness::Unavailable
    );
    assert_eq!(
        classify_process_generation(6100, None, boot_ticks(BOOT, 6100)),
        SupervisorLiveness::Unavailable
    );
}

/// A probe that answers through the neutral classifier from a scripted reading.
struct ScriptedObservation(GenerationObservation);

impl SupervisorLivenessProbe for ScriptedObservation {
    fn observe(&self, generation: SupervisorGeneration) -> SupervisorLiveness {
        classify_process_generation(generation.start_time, generation.boot_id, self.0)
    }
}

/// A lock written before this format carried a boot ID still loads, is read
/// in epoch microseconds, and does not wedge its profile: once its holder is
/// gone the next acquire breaks it and writes the current format.
#[test]
fn a_v1_custody_lock_still_loads_and_takes_the_legacy_arm() {
    let root = TestRoot::new("v1-lock-migration");
    let key = ProfileCustodyKey::durable("project-1");
    let legacy = generation(61, 6100);
    let mut seed =
        ProfileCustodyLocks::open(root.path(), legacy, RecordingJournal::default(), AlwaysLive)
            .unwrap();
    let old_holder = seed.mint_holder().unwrap();
    assert!(matches!(
        seed.acquire(key.clone(), old_holder.clone()),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));
    let lock = profile_lock_path(root.path());
    fs::write(
        &lock,
        format!(
            r#"{{"format_version":"ck-browser-profile-custody-lock/v1","holder_id":"{}","supervisor_pid":61,"supervisor_start_time":6100,"profile_directory":null}}"#,
            old_holder.as_str()
        ),
    )
    .unwrap();

    let record = read_record_if_present(&lock)
        .unwrap()
        .expect("v1 lock loads");
    assert_eq!(record.supervisor(), legacy);
    assert_eq!(
        classify_process_generation(
            legacy.start_time,
            legacy.boot_id,
            GenerationObservation::StartTime {
                start_time: 6100,
                stability: StartTimeStability::MovesWithWallClock,
            },
        ),
        SupervisorLiveness::Live,
        "an unmoved legacy start time is still its holder"
    );

    let current = SupervisorGeneration {
        pid: 62,
        start_time: 99,
        boot_id: Some(BOOT),
        #[cfg(windows)]
        generation_unit: None,
    };
    let mut contender = ProfileCustodyLocks::open(
        root.path(),
        current,
        RecordingJournal::default(),
        ScriptedObservation(GenerationObservation::Absent),
    )
    .unwrap();
    let new_holder = contender.mint_holder().unwrap();
    assert!(matches!(
        contender.acquire(key, new_holder),
        Ok(ProfileCustodyAcquisition::Acquired(_))
    ));
    let installed: Value = serde_json::from_slice(&fs::read(&lock).unwrap()).unwrap();
    assert_eq!(
        installed["format_version"],
        "ck-browser-profile-custody-lock/v2"
    );
    assert_eq!(
        installed["supervisor_boot_id"],
        "3f3f3f3f-3f3f-3f3f-3f3f-3f3f3f3f3f3f"
    );
    assert_eq!(
        read_record_if_present(&lock).unwrap().unwrap().supervisor(),
        current
    );
}

#[test]
fn a_v1_custody_lock_that_claims_a_boot_id_is_invalid() {
    let root = TestRoot::new("v1-lock-with-boot");
    let lock = root.path().join("claims-boot.lock");
    fs::write(
        &lock,
        r#"{"format_version":"ck-browser-profile-custody-lock/v1","holder_id":"h","supervisor_pid":17,"supervisor_start_time":1700,"supervisor_boot_id":"3f3f3f3f-3f3f-3f3f-3f3f-3f3f3f3f3f3f","profile_directory":null}"#,
    )
    .unwrap();
    assert!(matches!(
        read_record_if_present(&lock),
        Err(ProfileCustodyLockError::InvalidRecord)
    ));
}

/// Linux records the supervisor in boot and ticks, and the production probe
/// must compare it that way; macOS keeps its epoch reading with no boot ID.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[test]
fn the_supervisor_generation_carries_a_boot_id_exactly_on_linux() {
    use cerebellum::profile_custody::current_supervisor_generation;
    let own = current_supervisor_generation().expect("this platform records a supervisor");
    assert_eq!(own.boot_id.is_some(), cfg!(target_os = "linux"));
}

#[test]
fn cross_process_holder_without_lease_timing_keeps_profile_busy_wire_shape() {
    let root = TestRoot::new("remote-busy-holder");
    let remote = generation(901, 901000);
    let mut locks =
        ProfileCustodyLocks::open(root.path(), remote, RecordingJournal::default(), AlwaysLive)
            .unwrap();
    let holder = locks.mint_holder().unwrap();
    let claim = match locks
        .acquire(ProfileCustodyKey::durable("project-1"), holder.clone())
        .unwrap()
    {
        ProfileCustodyAcquisition::Acquired(claim) => claim,
        other => panic!("unexpected acquisition: {other:?}"),
    };
    let lock_path = profile_lock_path(root.path());
    let remote_record = fs::read(&lock_path).unwrap();
    locks.release_exact(&claim).unwrap();
    // Put the released lock record back, so the profile looks held by another
    // supervisor: the lock is on disk but this process has no timing for it.
    fs::write(&lock_path, remote_record).unwrap();
    let mut contender = ProfileCustodyLocks::open(
        root.path(),
        generation(902, 902000),
        RecordingJournal::default(),
        AlwaysLive,
    )
    .unwrap();
    let mut lifecycle = ProfileLifecycle::open_with_config(root.path(), durable_config()).unwrap();
    let (invocation, reservation, _) = tokens("remote-contender");
    let refusal = ProfileBoundLaunch::new(&mut lifecycle, &mut contender)
        .with_launch_timeout(100)
        .acquire_and_prepare(
            ProfileCustodyKey::durable("project-1"),
            &invocation,
            &reservation,
            &context("primary", "durable", "remote-contender"),
        )
        .unwrap_err()
        .as_json();
    assert_eq!(
        refusal,
        json!({
            "outcome":"profile_busy", "holder_id":holder.as_str(),
            "remedy":"another session holds this project's browser profile; close that session's browser or retry once it releases"
        })
    );
}
