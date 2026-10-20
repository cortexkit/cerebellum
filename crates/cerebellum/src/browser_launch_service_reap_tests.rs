use super::*;
use crate::browser_launch::{
    AuthorizedLaunchIntent, ExecutableIdentityChain, ExecutableIdentityCheckpoints,
    ExecutableIdentityClaim, ExecutableIdentityRecord, LaunchGenerationRecord, LaunchJournalPort,
    VerifiedLaunchVector,
};
use crate::launch_recovery::{ProcessFact, ProcessTable, ProcessUsers, Unreadable};
use cerebellum_core::identity::{RouteIdentity, RouteSurface, SessionKind};
use cerebellum_core::journal::InMemoryJournalStorage;

const PROJECT: &str = "project-1";
const SEQUENCE: u64 = 1;
const PLANTED_PID: u32 = 4_000_001;

fn test_config() -> BrowserConfig {
    BrowserConfig {
        executable_path: None,
        expected_identity: None,
        launch_handshake_deadline_ms: 100,
        termination_grace_period_ms: 100,
        browser_idle_timeout_ms: 30_000,
        browser_exit_observation_deadline_ms: 100,
        navigation_settle_deadline_ms: 100,
    }
}

fn accepted() -> AcceptedBindFacts {
    AcceptedBindFacts {
        identity: RouteIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            conversation_key: "conversation-2".into(),
            agent_project_id: PROJECT.into(),
            session_kind: SessionKind::Primary,
            profile_disposition: ProfileDisposition::Durable,
            project_root: PathBuf::from("/tmp"),
            origin: Default::default(),
        },
        principal: Some(subc_protocol::Principal::Direct),
        agent_project_id_attested: true,
        acts_as_agent: true,
        session_kind_attested: true,
        control_operations: Vec::new(),
        effective_capability_scope: None,
        consumer_capabilities: Vec::new(),
        surface: RouteSurface::Tools,
        scope: None,
        call_mode: subc_protocol::call_mode::CallMode::Classic,
        codemode_head: None,
        flow_id: None,
    }
}

fn lock_count(root: &Path) -> usize {
    std::fs::read_dir(root.join(PROFILE_CUSTODY_DIRECTORY))
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.len() == 69 && name.ends_with(".lock"))
        })
        .count()
}

fn singleton_lock_to(directory: &Path, target: &str) {
    std::os::unix::fs::symlink(target, directory.join("SingletonLock")).unwrap();
}

fn record_released_launch(journal: &mut ProductionLaunchJournal, intent: &AuthorizedLaunchIntent) {
    let mut handle = journal.record_intent(intent).unwrap();
    assert_eq!(handle.sequence(), SEQUENCE);
    let generation = LaunchGenerationRecord {
        intent: intent.clone(),
        process_generation: BrowserProcessGeneration {
            pid: PLANTED_PID,
            start_time_micros: 7,
            boot_id: None,
        },
    };
    journal.record_generation(&mut handle, &generation).unwrap();
    let claim = ExecutableIdentityClaim::CodeSigned {
        signing_identifier: "com.example.browser".into(),
        unique_code_hash: "abc123".into(),
    };
    journal
        .commit_attestation(
            &mut handle,
            &LaunchAttestationRecord {
                generation,
                observed_executable_identity: claim.clone(),
                executable_identity_chain: ExecutableIdentityChain::NoWalkPerformed {
                    attestation: ExecutableIdentityRecord { claim, path: None },
                },
                executable_identity_checkpoints:
                    ExecutableIdentityCheckpoints::BeforeSpawnAndAfterExec,
            },
        )
        .unwrap();
}

struct FailedReapProcess;

impl OwnedBrowserProcess for FailedReapProcess {
    fn generation_matches(&self) -> bool {
        false
    }
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
        Ok(true)
    }
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
        Ok(())
    }
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
        Err(ProcessControlFailure)
    }
}

struct FailedReapFixture {
    service: ProductionLaunchService,
    sessions: crate::browser_session::BrowserSessions,
    storage: InMemoryJournalStorage,
    id: String,
    directory: PathBuf,
    root: PathBuf,
    table: Arc<ReapProcessTable>,
    rollback: SharedRollback,
}

#[derive(Default)]
struct ReapProcessTable {
    directory: Mutex<PathBuf>,
    names_profile: AtomicBool,
    lock_pid_alive: AtomicBool,
}

impl ProcessTable for ReapProcessTable {
    fn this_user(&self) -> Option<u32> {
        Some(501)
    }
    fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
        Ok(vec![PLANTED_PID])
    }
    fn users(&self, _: u32) -> ProcessFact<ProcessUsers> {
        ProcessFact::Read(ProcessUsers {
            uid: 501,
            zombie: false,
        })
    }
    fn arguments(&self, _: u32) -> ProcessFact<Vec<OsString>> {
        ProcessFact::Read(if self.names_profile.load(Ordering::Acquire) {
            vec![OsString::from(format!(
                "--user-data-dir={}",
                self.directory.lock().unwrap().display()
            ))]
        } else {
            Vec::new()
        })
    }
    fn executable(&self, _: u32) -> Result<Option<PathBuf>, Unreadable> {
        Ok(self
            .lock_pid_alive
            .load(Ordering::Acquire)
            .then(|| PathBuf::from("/usr/bin/chromium")))
    }
    fn host_name(&self) -> Option<String> {
        Some("reap-test-host".into())
    }
}

impl FailedReapFixture {
    fn new() -> Self {
        let storage = InMemoryJournalStorage::new();
        let mut service = ProductionLaunchService::open_with_recovery(
            test_config(),
            ProfileStateRoot::for_persistence(crate::JournalPersistence::Isolated),
            |_, _| {
                (
                    Some(
                        DurableLaunchJournal::open(
                            launch_journal_config(),
                            crate::PlaneJournalStorage::InMemory(storage.clone()),
                        )
                        .unwrap(),
                    ),
                    None,
                    Default::default(),
                )
            },
        );
        let table = Arc::new(ReapProcessTable::default());
        Arc::get_mut(&mut service.recovery).unwrap().process_table = table.clone();
        let sessions = crate::browser_session::BrowserSessions::default();
        let id = match sessions.acquire_launch_slot("conversation-2") {
            crate::browser_session::LaunchSlot::Acquired { browser_session_id } => {
                browser_session_id
            }
            _ => panic!("empty session route"),
        };
        let held = service.take_launch_profile(&accepted(), &id).unwrap();
        let root = service.profile_root.resolve().unwrap();
        let directory = held.profile_directory.clone();
        *table.directory.lock().unwrap() = directory.clone();
        std::fs::write(directory.join("Local State"), b"{}").unwrap();
        let intent = AuthorizedLaunchIntent {
            format_version: "ck-browser-launch-attestation/v2".into(),
            launch_attempt_id: id.clone(),
            holder_id: held.holder_id,
            route: LaunchRouteIdentity {
                principal: "direct:agent".into(),
                conversation_key: "conversation-2".into(),
                agent_project_id: PROJECT.into(),
                session_kind: SessionKind::Primary,
            },
            profile: LaunchProfileIdentity {
                profile_uuid: held.profile_uuid,
                canonical_profile_path: path_bytes(&directory),
                disposition: LaunchProfile::Registry(ProfileDisposition::Durable),
            },
            verified_executable_identity:
                crate::browser_launch::VerifiedExecutableIdentity::CodeSignedFile {
                    signing_identifier: "com.example.browser".into(),
                    slice_code_hashes: std::collections::BTreeSet::from(["abc123".into()]),
                },
            launch_vector: VerifiedLaunchVector {
                executable: b"/Applications/Browser".to_vec(),
                arguments: Vec::new(),
                environment: Vec::new(),
            },
        };
        record_released_launch(service.journal.lock().unwrap().as_mut().unwrap(), &intent);
        let rollback = held.rollback.clone();
        sessions.establish_ready(
            "conversation-2",
            ProfileDisposition::Durable,
            &test_config(),
            &cerebellum_core::clock::FakeClock::default(),
            Box::new(FailedReapProcess),
            Box::new(ProductionSessionCleanup {
                reap_recovery: Some(SessionRecovery {
                    evidence: Arc::clone(&service.recovery),
                    durable_project: Some(PROJECT.into()),
                    journal_settled: false,
                    cleanup_result: None,
                }),
                journal: Arc::clone(&service.journal),
                launch_attempt_id: id.clone(),
                terminal_outcome: None,
                persistence: ProfilePersistenceCheck {
                    disposition: ProfileDisposition::Durable,
                    profile_directory: directory.clone(),
                    launch_started_at: SystemTime::UNIX_EPOCH,
                },
                profile: held.rollback,
                crash_reports: None,
            }),
        );
        let result = sessions.close("conversation-2", &id, &test_config());
        assert_eq!(result["stage"], "reap", "{result}");
        let fixture = Self {
            service,
            sessions,
            storage,
            id,
            directory,
            root,
            table,
            rollback,
        };
        assert!(fixture.active());
        assert_eq!(lock_count(&fixture.root), 1);
        assert!(fixture
            .service
            .take_and_return_profile_custody(&accepted(), "before-recovery")
            .is_err());
        fixture
    }

    fn active(&self) -> bool {
        DurableLaunchJournal::open(launch_journal_config(), self.storage.clone())
            .unwrap()
            .active_launch_record(SEQUENCE)
            .unwrap()
            .is_some()
    }

    fn close(&self) -> Value {
        self.sessions
            .close("conversation-2", &self.id, &test_config())
    }

    fn assert_held(&self, result: &Value, remedy: &str) {
        assert_eq!(result["outcome"], "cleanup_failure", "{result}");
        assert!(
            result["remedy"].as_str().unwrap().contains(remedy),
            "{result}"
        );
        assert!(
            result["remedy"].as_str().unwrap().contains("browser.close"),
            "{result}"
        );
        assert!(self.active());
        assert_eq!(lock_count(&self.root), 1);
        assert!(self
            .service
            .take_and_return_profile_custody(&accepted(), "still-held")
            .is_err());
    }
}

#[test]
fn failed_reap_close_recovers_and_settles_launch_reservation() {
    let fixture = FailedReapFixture::new();
    let result = fixture.close();
    assert_eq!(result["outcome"], "closed", "{result}");
    assert!(!fixture.active());
    assert_eq!(lock_count(&fixture.root), 0);
    assert_eq!(fixture.close()["outcome"], "closed");
}

#[test]
fn failed_reap_launch_recovers_same_route_and_shared_profile() {
    for route in ["conversation-2", "another-conversation"] {
        let fixture = FailedReapFixture::new();
        assert!(matches!(
            fixture
                .sessions
                .acquire_launch_slot_for_profile(route, Some(PROJECT)),
            crate::browser_session::LaunchSlot::Acquired { .. }
        ));
        assert!(!fixture.active());
        assert!(fixture
            .service
            .take_and_return_profile_custody(&accepted(), "after-recovery")
            .is_ok());
    }
}

#[test]
fn failed_reap_live_process_refuses_with_retry_remedy_and_keeps_custody() {
    let fixture = FailedReapFixture::new();
    fixture.table.names_profile.store(true, Ordering::Release);
    fixture.assert_held(&fixture.close(), "running process");
    match fixture
        .sessions
        .acquire_launch_slot_for_profile("conversation-2", Some(PROJECT))
    {
        crate::browser_session::LaunchSlot::Refused(result) => {
            fixture.assert_held(&result, "running process")
        }
        _ => panic!("launch ignored a process still using the profile"),
    }
    fixture.table.names_profile.store(false, Ordering::Release);
    assert_eq!(fixture.close()["outcome"], "closed");
}

#[test]
fn failed_reap_live_singleton_lock_keeps_custody_without_a_profile_process() {
    let fixture = FailedReapFixture::new();
    fixture.table.lock_pid_alive.store(true, Ordering::Release);
    singleton_lock_to(&fixture.directory, &format!("reap-test-host-{PLANTED_PID}"));
    fixture.assert_held(&fixture.close(), "running Chrome process");
    fixture.table.lock_pid_alive.store(false, Ordering::Release);
    assert_eq!(fixture.close()["outcome"], "closed");
}

#[test]
fn failed_reap_status_reports_closed_after_recovery() {
    let fixture = FailedReapFixture::new();
    assert_eq!(fixture.close()["outcome"], "closed");
    let result = fixture.sessions.status(
        "conversation-2",
        &cerebellum_core::clock::FakeClock::default(),
        SystemTime::now(),
    );
    assert_eq!(result["outcome"], "terminal", "{result}");
    assert_eq!(result["terminal_outcome"], "closed", "{result}");
}

#[test]
fn failed_reap_unrelated_profile_and_unknown_close_do_not_recover_it() {
    let fixture = FailedReapFixture::new();
    assert_eq!(
        fixture
            .sessions
            .close("conversation-2", "unknown-session", &test_config())["outcome"],
        "browser_session_not_found"
    );
    assert!(matches!(
        fixture
            .sessions
            .acquire_launch_slot_for_profile("unrelated-route", Some("another-project")),
        crate::browser_session::LaunchSlot::Acquired { .. }
    ));
    assert!(fixture.active());
    assert_eq!(lock_count(&fixture.root), 1);
    assert_eq!(fixture.close()["outcome"], "closed");
}

#[test]
fn failed_reap_concurrent_closes_share_one_settlement() {
    let fixture = FailedReapFixture::new();
    std::thread::scope(|scope| {
        let first = scope.spawn(|| fixture.close());
        let second = scope.spawn(|| fixture.close());
        assert_eq!(first.join().unwrap()["outcome"], "closed");
        assert_eq!(second.join().unwrap()["outcome"], "closed");
    });
    assert!(!fixture.active());
    assert_eq!(lock_count(&fixture.root), 0);
}

#[test]
fn failed_reap_cleanup_error_cannot_be_mistaken_for_success_on_retry() {
    let fixture = FailedReapFixture::new();
    fixture
        .rollback
        .state
        .lock()
        .unwrap()
        .as_mut()
        .unwrap()
        .rollback = Some(Box::new(|_, _| {
        Err(BrowserLaunchOutcome::CleanupFailure {
            stage: crate::browser_launch::LaunchCleanupStage::CustodyRelease,
        })
    }));
    for _ in 0..2 {
        let result = fixture.close();
        assert_eq!(result["outcome"], "cleanup_failure", "{result}");
        assert_eq!(result["stage"], "custody_release", "{result}");
        assert!(
            result["remedy"]
                .as_str()
                .unwrap()
                .contains("restart the module"),
            "{result}"
        );
        assert!(!fixture.active());
        assert_eq!(lock_count(&fixture.root), 1);
    }
}
