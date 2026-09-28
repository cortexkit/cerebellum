//! The format floor as each durable store of this module uses it.
//!
//! For every format a reader refuses, a record one version newer than this
//! build reads must be refused BY NAME -- as a newer build's record, never as
//! corruption or an invalid record -- because the remedy differs: run the
//! newer build, do not repair or delete. And every writer must raise the
//! floor before its first write, refusing the write when it cannot.
//!
//! Its own test binary, because one test points the data home at a scratch
//! directory, which only a child process can do without redirecting every
//! other test running beside it.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use cerebellum::computer_grants::{
    FilesystemGrantStorage, GrantStorage, GrantStoreError, GrantStoreState, InMemoryGrantStorage,
    GRANT_STORE_FORMAT,
};
use cerebellum_core::format_floor::{read_floors, FormatFloor, NewerWriter, FORMAT_FLOOR_FILE};
use cerebellum_core::journal::{
    FilesystemJournalStorage, InMemoryJournalStorage, JournalStorage, RefusalRing,
    RefusalRingConfig, StorageError,
};
use serde_json::json;

static NEXT: AtomicU64 = AtomicU64::new(0);

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "cerebellum-format-floor-{label}-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn floor(&self) -> PathBuf {
        self.0.join(FORMAT_FLOOR_FILE)
    }

    /// A floor path whose directory is a file, so no floor can be written.
    fn unwritable_floor(&self) -> PathBuf {
        let blocker = self.0.join("not-a-directory");
        fs::write(&blocker, b"file").unwrap();
        blocker.join(FORMAT_FLOOR_FILE)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

// ---- computer grant store ----

#[test]
fn a_grant_store_from_the_next_version_is_refused_by_name_not_as_corrupt() {
    let scratch = Scratch::new("grants-newer");
    let path = scratch.path().join("computer_grants.json");
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "version": GRANT_STORE_FORMAT.version + 1,
            "records": [{"a_field_this_build_does_not_know": true}],
            "added_later": {},
        }))
        .unwrap(),
    )
    .unwrap();
    assert_eq!(
        FilesystemGrantStorage::new(&path).load(),
        Err(GrantStoreError::UnknownVersion {
            found: GRANT_STORE_FORMAT.version + 1
        })
    );
}

#[test]
fn a_grant_store_save_raises_the_floor_before_writing() {
    let scratch = Scratch::new("grants-raise");
    let path = scratch.path().join("computer_grants.json");
    FilesystemGrantStorage::new(&path)
        .with_format_floor(FormatFloor::at(scratch.floor()))
        .save(&GrantStoreState::default())
        .unwrap();
    assert_eq!(
        read_floors(&scratch.floor())
            .unwrap()
            .get("computer-grants"),
        Some(&GRANT_STORE_FORMAT.version)
    );
}

#[test]
fn a_grant_store_save_without_a_floor_is_refused_and_writes_nothing() {
    let scratch = Scratch::new("grants-refuse");
    let path = scratch.path().join("computer_grants.json");
    let result = FilesystemGrantStorage::new(&path)
        .with_format_floor(FormatFloor::at(scratch.unwritable_floor()))
        .save(&GrantStoreState::default());
    assert!(
        matches!(&result, Err(GrantStoreError::WriteFailed { detail }) if detail.contains("format floor")),
        "{result:?}"
    );
    assert!(!path.exists());
}

// ---- profile custody lock ----

#[cfg(unix)]
mod custody {
    use super::*;
    use cerebellum::profile_custody::{
        read_record_if_present, ProfileCustodyAcquisition, ProfileCustodyEvent,
        ProfileCustodyJournal, ProfileCustodyKey, ProfileCustodyLockError, ProfileCustodyLocks,
        SupervisorGeneration, SupervisorLiveness, SupervisorLivenessProbe, CUSTODY_LOCK_FORMAT,
    };
    use std::sync::{Arc, Mutex};

    #[derive(Clone, Default)]
    struct RecordingJournal(Arc<Mutex<Vec<ProfileCustodyEvent>>>);

    impl ProfileCustodyJournal for RecordingJournal {
        fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()> {
            self.0.lock().unwrap().push(event.clone());
            Ok(())
        }
    }

    struct NothingLive;

    impl SupervisorLivenessProbe for NothingLive {
        fn observe(&self, _generation: SupervisorGeneration) -> SupervisorLiveness {
            SupervisorLiveness::NotLive
        }
    }

    const SUPERVISOR: SupervisorGeneration = SupervisorGeneration {
        pid: 41,
        start_time: 1_700,
        boot_id: None,
    };

    fn locks(
        root: &Path,
        journal: RecordingJournal,
        floor: FormatFloor,
    ) -> ProfileCustodyLocks<RecordingJournal, NothingLive> {
        ProfileCustodyLocks::open(root, SUPERVISOR, journal, NothingLive)
            .unwrap()
            .with_format_floor(floor)
    }

    /// Lock files in the custody directory, leaving out its coordination
    /// file and the custody event log.
    fn lock_files(root: &Path) -> Vec<String> {
        fs::read_dir(root.join(".ck-browser-profile-custody"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != ".coordination.lock" && name != "custody-events.jsonl")
            .collect()
    }

    #[test]
    fn a_custody_lock_from_the_next_version_is_refused_by_name_not_as_invalid() {
        let scratch = Scratch::new("lock-newer");
        let lock = scratch.path().join("newer.lock");
        fs::write(
            &lock,
            serde_json::to_vec(&json!({
                "format_version": format!(
                    "ck-browser-profile-custody-lock/v{}",
                    CUSTODY_LOCK_FORMAT.version + 1
                ),
                "holder_id": "holder-newer",
                "supervisor_pid": 17,
                "supervisor_start_time": 1700,
                "profile_directory": null,
                "a_field_this_build_does_not_know": true,
            }))
            .unwrap(),
        )
        .unwrap();
        match read_record_if_present(&lock) {
            Err(ProfileCustodyLockError::NewerWriter(newer)) => assert_eq!(
                newer,
                NewerWriter {
                    format: "profile-custody-lock",
                    found: CUSTODY_LOCK_FORMAT.version + 1,
                    supported: CUSTODY_LOCK_FORMAT.version,
                }
            ),
            other => panic!("a newer lock was not refused by name: {other:?}"),
        }
    }

    #[test]
    fn acquiring_a_lock_raises_the_floor_before_writing() {
        let scratch = Scratch::new("lock-raise");
        let root = scratch.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let mut locks = locks(
            &root,
            RecordingJournal::default(),
            FormatFloor::at(scratch.floor()),
        );
        let holder = locks.mint_holder().unwrap();
        assert!(matches!(
            locks.acquire(ProfileCustodyKey::durable("project-1"), holder),
            Ok(ProfileCustodyAcquisition::Acquired(_))
        ));
        assert_eq!(
            read_floors(&scratch.floor())
                .unwrap()
                .get("profile-custody-lock"),
            Some(&CUSTODY_LOCK_FORMAT.version)
        );
    }

    #[test]
    fn a_lock_without_a_floor_is_refused_and_nothing_is_written() {
        let scratch = Scratch::new("lock-refuse");
        let root = scratch.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let journal = RecordingJournal::default();
        let mut locks = locks(
            &root,
            journal.clone(),
            FormatFloor::at(scratch.unwritable_floor()),
        );
        let holder = locks.mint_holder().unwrap();
        let result = locks.acquire(ProfileCustodyKey::durable("project-1"), holder);
        assert!(
            matches!(result, Err(ProfileCustodyLockError::FormatFloor(_))),
            "{result:?}"
        );
        assert!(lock_files(&root).is_empty(), "{:?}", lock_files(&root));
        assert!(
            journal.0.lock().unwrap().is_empty(),
            "an event was journaled"
        );
    }
}

// ---- profile registry ----

#[cfg(unix)]
mod registry {
    use super::*;
    use cerebellum::profile::{
        read_root_metadata_facts, stamped_bind_context, BindFacts, InvocationToken,
        JournalReservationHandle, PrepareResult, ProfileLifecycle, RegistryConfig, RegistryError,
        UntrustworthyRegistryReason, REGISTRY_FORMAT,
    };

    const REGISTRY_FILE: &str = ".ck-browser-profile-registry-v1.json";

    fn registry_config() -> RegistryConfig {
        RegistryConfig {
            uuid_protocol_compatible: true,
            grant_verifier_available: true,
            grant_accepted: true,
            sealing_available: true,
            ..RegistryConfig::default()
        }
    }

    fn mint(lifecycle: &mut ProfileLifecycle) -> PrepareResult {
        let invocation = InvocationToken::for_test("invocation-floor");
        let reservation = JournalReservationHandle::for_test(&invocation, "reservation-floor");
        let context = stamped_bind_context(BindFacts {
            principal: "direct:agent".to_string(),
            conversation_key: "conversation-floor".to_string(),
            agent_project_id: "project-floor".to_string(),
            session_kind: Some("primary".to_string()),
            session_kind_attested: true,
            profile_disposition: Some("durable".to_string()),
            effective_capability_scope: Some(vec!["browser.launch".to_string()]),
            provenance: "daemon_attested_spec_a".to_string(),
        })
        .expect("strict profile context");
        lifecycle.prepare_context_open(&invocation, &reservation, &context)
    }

    #[test]
    fn a_registry_from_the_next_version_is_refused_by_name_not_as_malformed() {
        let scratch = Scratch::new("registry-newer");
        let root = scratch.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let canonical = fs::canonicalize(&root).unwrap();
        let facts = read_root_metadata_facts(&fs::metadata(&canonical).unwrap());
        // A plausible newer document: this build's fields, a newer schema,
        // and a field this build's strict reader would reject as malformed.
        let newer = json!({
            "schema": format!("ck-browser-profile-registry/v{}", REGISTRY_FORMAT.version + 1),
            "managed_root_identity": {
                "formula": 2,
                "path": canonical.to_string_lossy(),
                "inode": facts.inode,
                "birth_time": facts.birth_time.expect("test filesystem reports birth time"),
            },
            "generation": 0,
            "records": {},
            "integrity": "",
            "a_field_this_build_does_not_know": true,
        });
        fs::write(
            root.join(REGISTRY_FILE),
            serde_json::to_vec(&newer).unwrap(),
        )
        .unwrap();

        let lifecycle = ProfileLifecycle::open_with_config(&root, registry_config()).unwrap();
        match lifecycle.registry().resolve_durable("project-floor") {
            Err(RegistryError::Untrustworthy(reason)) => assert_eq!(
                reason,
                UntrustworthyRegistryReason::UnsupportedRegistrySchema
            ),
            other => panic!("a newer registry was not refused by its schema: {other:?}"),
        }
    }

    #[test]
    fn minting_a_registry_raises_the_floor_before_writing() {
        let scratch = Scratch::new("registry-raise");
        let root = scratch.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let mut lifecycle = ProfileLifecycle::open_with_config(&root, registry_config())
            .unwrap()
            .with_format_floor(FormatFloor::at(scratch.floor()));
        assert!(matches!(mint(&mut lifecycle), PrepareResult::Prepared(_)));
        assert_eq!(
            read_floors(&scratch.floor())
                .unwrap()
                .get("profile-registry"),
            Some(&REGISTRY_FORMAT.version)
        );
    }

    #[test]
    fn a_registry_without_a_floor_is_refused_and_nothing_is_written() {
        let scratch = Scratch::new("registry-refuse");
        let root = scratch.path().join("root");
        fs::create_dir_all(&root).unwrap();
        let mut lifecycle = ProfileLifecycle::open_with_config(&root, registry_config())
            .unwrap()
            .with_format_floor(FormatFloor::at(scratch.unwritable_floor()));
        let result = mint(&mut lifecycle);
        assert!(!matches!(result, PrepareResult::Prepared(_)), "{result:?}");
        assert!(!root.join(REGISTRY_FILE).exists());
    }
}

// ---- isolated stores and the operator's floor ----

const ISOLATED_CHILD: &str = "CEREBELLUM_FORMAT_FLOOR_ISOLATED_CHILD";

/// Isolated and in-memory stores never create or read the operator's floor.
///
/// The child runs with its data home pointed at a scratch directory whose
/// floor files (one per data tree) are DIRECTORIES: reading or rewriting one
/// fails, so any store that touched it would fail its write. A durable
/// journal under that data home is written last as the control, and must
/// fail, which shows the planted journal floor is where the operator's floor
/// resolves.
#[test]
fn isolated_stores_neither_create_nor_read_the_operator_floor() {
    if std::env::var_os(ISOLATED_CHILD).is_some() {
        write_through_isolated_stores();
        return;
    }
    let scratch = Scratch::new("isolated");
    let data_home = scratch.path().join("data");
    let module = data_home.join("cortexkit").join("cerebellum");
    let journal_floor = module.join("journal").join(FORMAT_FLOOR_FILE);
    let browser_floor = module.join("browser").join(FORMAT_FLOOR_FILE);
    fs::create_dir_all(&journal_floor).unwrap();
    fs::create_dir_all(&browser_floor).unwrap();

    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "isolated_stores_neither_create_nor_read_the_operator_floor",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(ISOLATED_CHILD, "1")
        .env("XDG_DATA_HOME", &data_home)
        .env(
            "SCRATCH_OUTSIDE_DATA_HOME",
            scratch.path().join("elsewhere"),
        )
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the child failed:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    // A filter matching nothing also succeeds, having tested nothing.
    assert!(
        stdout.contains("1 passed"),
        "the child ran no test:\n{stdout}"
    );

    let entries = |directory: &Path| {
        let mut names: Vec<_> = fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    };
    // Only the planted floors, and the journal floor's lock left by the
    // control.
    assert_eq!(
        entries(&module.join("journal")),
        [".format-floor.json.lock", FORMAT_FLOOR_FILE]
    );
    assert_eq!(entries(&module.join("browser")), [FORMAT_FLOOR_FILE]);
    assert!(entries(&journal_floor).is_empty());
    assert!(entries(&browser_floor).is_empty());
}

fn write_through_isolated_stores() {
    let data_home = PathBuf::from(std::env::var_os("XDG_DATA_HOME").unwrap());
    let elsewhere = PathBuf::from(std::env::var_os("SCRATCH_OUTSIDE_DATA_HOME").unwrap());
    fs::create_dir_all(&elsewhere).unwrap();
    let operator_journal = cerebellum_core::journal::journal_data_path("browser.json").unwrap();
    assert!(operator_journal.starts_with(&data_home));

    let state = cerebellum_core::journal::DurableState::default();
    InMemoryJournalStorage::new().save(&state).unwrap();
    FilesystemJournalStorage::new(elsewhere.join("browser.json"))
        .save(&state)
        .unwrap();
    let mut ring = RefusalRing::<String>::new_in_memory(RefusalRingConfig {
        records_per_caller: 1,
    })
    .unwrap();
    ring.record_refusal("caller", "address", "reason".to_string())
        .unwrap();
    InMemoryGrantStorage::new()
        .save(&GrantStoreState::default())
        .unwrap();
    FilesystemGrantStorage::new(elsewhere.join("computer_grants.json"))
        .save(&GrantStoreState::default())
        .unwrap();
    let grants = cerebellum::computer_grants::ComputerGrants::in_memory();
    assert!(grants.store_error().is_none());

    // The control: a journal under the data home is the operator's, and its
    // save reaches the planted floor and is refused.
    let result = FilesystemJournalStorage::new(&operator_journal).save(&state);
    assert!(
        matches!(result, Err(StorageError::FormatFloor(_))),
        "{result:?}"
    );
    assert!(!operator_journal.exists());
}
