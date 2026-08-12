//! Durable journal storage bindings.
//!
//! The in-memory binding is intentionally small but models restart correctly:
//! cloned bindings share durable state, while handles and tokens remain local to
//! the binding that minted them.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{DurableState, StorageError};

const JOURNAL_SCHEMA_VERSION: u64 = 1;
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredJournal {
    schema_version: u64,
    state: DurableState,
}

/// Storage contract used by the lifecycle binding.
pub trait JournalStorage: Clone {
    fn load(&self) -> Result<DurableState, StorageError>;
    fn save(&self, state: &DurableState) -> Result<(), StorageError>;
}

/// A process-independent durable state model for fixtures and compatibility
/// adapters. Cloning this value models opening the same journal after restart.
#[derive(Clone, Debug, Default)]
pub struct InMemoryJournalStorage {
    state: Arc<Mutex<DurableState>>,
}

impl InMemoryJournalStorage {
    pub fn new() -> Self {
        Self::default()
    }
}

impl JournalStorage for InMemoryJournalStorage {
    fn load(&self) -> Result<DurableState, StorageError> {
        self.state
            .lock()
            .map(|state| state.clone())
            .map_err(|_| StorageError::LockPoisoned {
                binding: "in-memory journal".to_string(),
            })
    }

    fn save(&self, state: &DurableState) -> Result<(), StorageError> {
        self.state
            .lock()
            .map(|mut current| {
                *current = state.clone();
            })
            .map_err(|_| StorageError::LockPoisoned {
                binding: "in-memory journal".to_string(),
            })
    }
}

/// A whole-state JSON journal stored with crash-atomic replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemJournalStorage {
    path: PathBuf,
}

impl FilesystemJournalStorage {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Create and verify the journal directory before capabilities are offered.
    ///
    /// The probe reduces the chance of discovering an unwritable directory at
    /// first use, but runtime writes still report failure because permissions and
    /// free space can change after boot.
    pub fn prepare(path: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let storage = Self::new(path);
        let directory = storage.directory();
        fs::create_dir_all(&directory).map_err(|source| StorageError::CreateDirectory {
            path: directory.clone(),
            source: io_diagnostic(source),
        })?;

        let probe = unique_sibling_path(&storage.path, "probe");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&probe)
            .map_err(|source| StorageError::ProbeWrite {
                path: probe.clone(),
                source: io_diagnostic(source),
            })?;
        file.write_all(b"journal storage probe")
            .map_err(|source| StorageError::ProbeWrite {
                path: probe.clone(),
                source: io_diagnostic(source),
            })?;
        file.sync_all().map_err(|source| StorageError::FileSync {
            path: probe.clone(),
            source: io_diagnostic(source),
        })?;
        drop(file);
        fs::remove_file(&probe).map_err(|source| StorageError::ProbeCleanup {
            path: probe,
            source: io_diagnostic(source),
        })?;
        sync_directory(&directory)?;
        Ok(storage)
    }

    fn directory(&self) -> PathBuf {
        self.path
            .parent()
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
    }

    fn read_existing(&self) -> Result<DurableState, StorageError> {
        let mut bytes = Vec::new();
        let mut file = File::open(&self.path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                StorageError::Missing {
                    path: self.path.clone(),
                    source: io_diagnostic(source),
                }
            } else {
                StorageError::Unreadable {
                    path: self.path.clone(),
                    source: io_diagnostic(source),
                }
            }
        })?;
        file.read_to_end(&mut bytes)
            .map_err(|source| StorageError::Unreadable {
                path: self.path.clone(),
                source: io_diagnostic(source),
            })?;

        let value: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|source| StorageError::Corrupt {
                path: self.path.clone(),
                source: source.to_string(),
            })?;
        let version = value
            .get("schema_version")
            .and_then(serde_json::Value::as_u64)
            .ok_or_else(|| StorageError::Corrupt {
                path: self.path.clone(),
                source: "schema_version is missing or is not an unsigned integer".to_string(),
            })?;
        if version != JOURNAL_SCHEMA_VERSION {
            return Err(StorageError::UnknownSchemaVersion {
                path: self.path.clone(),
                found: version,
                supported: JOURNAL_SCHEMA_VERSION,
            });
        }
        serde_json::from_value::<StoredJournal>(value)
            .map(|stored| stored.state)
            .map_err(|source| StorageError::Corrupt {
                path: self.path.clone(),
                source: source.to_string(),
            })
    }
}

impl JournalStorage for FilesystemJournalStorage {
    fn load(&self) -> Result<DurableState, StorageError> {
        match self.read_existing() {
            Ok(state) => Ok(state),
            // A missing file represents absence honestly. Corruption and read
            // failures are never converted to fresh state because that would
            // falsely claim that no audit history existed.
            Err(StorageError::Missing { .. }) => Ok(DurableState::fresh()),
            Err(error) => Err(error),
        }
    }

    fn save(&self, state: &DurableState) -> Result<(), StorageError> {
        let stored = StoredJournal {
            schema_version: JOURNAL_SCHEMA_VERSION,
            state: state.clone(),
        };
        let bytes =
            serde_json::to_vec_pretty(&stored).map_err(|source| StorageError::Serialization {
                path: self.path.clone(),
                source: source.to_string(),
            })?;
        let directory = self.directory();
        let temporary = unique_sibling_path(&self.path, "tmp");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .map_err(|source| StorageError::TemporaryWrite {
                path: temporary.clone(),
                source: io_diagnostic(source),
            })?;
        file.write_all(&bytes)
            .map_err(|source| StorageError::TemporaryWrite {
                path: temporary.clone(),
                source: io_diagnostic(source),
            })?;
        file.sync_all().map_err(|source| StorageError::FileSync {
            path: temporary.clone(),
            source: io_diagnostic(source),
        })?;
        drop(file);
        fs::rename(&temporary, &self.path).map_err(|source| StorageError::Rename {
            from: temporary,
            to: self.path.clone(),
            source: io_diagnostic(source),
        })?;
        sync_directory(&directory)
    }
}

/// Return the stable journal data path under `~/.local/share/cortexkit/journal/`.
///
/// Journal records are application data rather than configuration, so they do
/// not live beside `~/.config/cortexkit/cerebellum.jsonc`.
pub fn journal_data_path(file_name: &str) -> Result<PathBuf, StorageError> {
    let home = std::env::var_os("HOME")
        .filter(|value| !value.is_empty())
        .ok_or_else(|| StorageError::HomeDirectoryUnavailable {
            variable: "HOME".to_string(),
        })?;
    Ok(PathBuf::from(home)
        .join(".local")
        .join("share")
        .join("cortexkit")
        .join("journal")
        .join(file_name))
}

fn unique_sibling_path(target: &Path, role: &str) -> PathBuf {
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = target
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("journal");
    target.with_file_name(format!(
        ".{name}.{role}.{}.{}",
        std::process::id(),
        sequence
    ))
}

fn sync_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StorageError::DirectorySync {
            path: path.to_path_buf(),
            source: io_diagnostic(source),
        })
}

fn io_diagnostic(error: io::Error) -> super::IoDiagnostic {
    super::IoDiagnostic {
        kind: error.kind(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::{FilesystemJournalStorage, JournalStorage};
    use crate::journal::{DurableState, StorageError};

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct TemporaryDirectory(PathBuf);

    impl TemporaryDirectory {
        fn new(test_name: &str) -> Self {
            let sequence = DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cerebellum-journal-{test_name}-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("temporary journal directory");
            Self(path)
        }

        fn join(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TemporaryDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn state(sequence: u64) -> DurableState {
        DurableState {
            next_sequence: sequence,
            next_cursor: 7,
            oversize_flag: true,
            ..DurableState::default()
        }
    }

    #[test]
    fn saved_state_round_trips_through_a_new_binding() {
        let directory = TemporaryDirectory::new("round-trip");
        let path = directory.join("journal.json");
        FilesystemJournalStorage::new(&path)
            .save(&state(42))
            .expect("save state");

        let reopened = FilesystemJournalStorage::new(&path)
            .load()
            .expect("reload state");

        assert_eq!(reopened, state(42));
    }

    #[test]
    fn missing_file_yields_fresh_state() {
        let directory = TemporaryDirectory::new("missing");
        let path = directory.join("journal.json");
        let storage = FilesystemJournalStorage::new(&path);

        match storage
            .read_existing()
            .expect_err("the file itself is absent")
        {
            StorageError::Missing {
                path: error_path,
                source,
            } => {
                assert_eq!(error_path, path);
                assert_eq!(source.kind, std::io::ErrorKind::NotFound);
                assert!(!source.message.is_empty());
            }
            other => panic!("expected missing error, got {other:?}"),
        }
        let loaded = storage.load().expect("missing journal is a first run");
        assert_eq!(loaded.next_sequence, 1);
        assert_eq!(loaded.next_cursor, 1);
    }

    #[test]
    fn existing_unreadable_path_is_not_treated_as_missing() {
        let directory = TemporaryDirectory::new("unreadable");
        let path = directory.join("journal.json");
        fs::create_dir(&path).expect("create a path that cannot be read as a file");

        match FilesystemJournalStorage::new(&path)
            .load()
            .expect_err("an existing unreadable path must be reported")
        {
            StorageError::Unreadable {
                path: error_path,
                source,
            } => {
                assert_eq!(error_path, path);
                assert!(!source.message.is_empty());
            }
            other => panic!("expected unreadable error, got {other:?}"),
        }
    }

    #[test]
    fn corrupt_file_is_refused_without_starting_fresh_sequence() {
        let directory = TemporaryDirectory::new("corrupt");
        let path = directory.join("journal.json");
        let corrupt = b"{\"schema_version\":1,\"state\":";
        fs::write(&path, corrupt).expect("write corrupt journal");

        let error = FilesystemJournalStorage::new(&path)
            .load()
            .expect_err("corruption must not become fresh state");

        match error {
            StorageError::Corrupt {
                path: error_path,
                source,
            } => {
                assert_eq!(error_path, path);
                assert!(!source.is_empty());
            }
            other => panic!("expected corruption error, got {other:?}"),
        }
        assert_eq!(fs::read(&path).expect("corrupt file remains"), corrupt);
    }

    #[test]
    fn unknown_schema_version_has_its_own_error() {
        let directory = TemporaryDirectory::new("unknown-version");
        let path = directory.join("journal.json");
        fs::write(&path, br#"{"schema_version":2,"state":{}}"#).expect("write future journal");

        assert_eq!(
            FilesystemJournalStorage::new(&path).load(),
            Err(StorageError::UnknownSchemaVersion {
                path,
                found: 2,
                supported: 1,
            })
        );
    }

    #[test]
    fn truncated_uncommitted_temporary_file_cannot_replace_committed_state() {
        let directory = TemporaryDirectory::new("atomic");
        let path = directory.join("journal.json");
        let storage = FilesystemJournalStorage::new(&path);
        storage.save(&state(11)).expect("save committed state");
        fs::write(directory.join(".journal.json.tmp.crash"), b"{\"schema")
            .expect("simulate interrupted temporary write");

        assert_eq!(
            FilesystemJournalStorage::new(&path)
                .load()
                .expect("load committed state"),
            state(11)
        );
    }

    #[test]
    fn fault_injection_schedule_does_not_survive_restart() {
        let directory = TemporaryDirectory::new("faults");
        let path = directory.join("journal.json");
        let mut with_fault = state(9);
        with_fault.faults.insert("commit_dispatch".to_string(), 1);
        FilesystemJournalStorage::new(&path)
            .save(&with_fault)
            .expect("save state with process-local fault");

        let reopened = FilesystemJournalStorage::new(&path)
            .load()
            .expect("reload without process-local fault");

        assert!(reopened.faults.is_empty());
        with_fault.faults.clear();
        assert_eq!(reopened, with_fault);
    }

    #[test]
    fn boot_probe_reports_directory_creation_failure_exactly() {
        let directory = TemporaryDirectory::new("prepare-failure");
        let blocking_file = directory.join("not-a-directory");
        fs::write(&blocking_file, b"file").expect("write blocking file");
        let path = blocking_file.join("journal.json");

        match FilesystemJournalStorage::prepare(&path)
            .expect_err("a file cannot be used as the journal directory")
        {
            StorageError::CreateDirectory {
                path: error_path,
                source,
            } => {
                assert_eq!(error_path, blocking_file);
                assert!(!source.message.is_empty());
            }
            other => panic!("expected directory creation error, got {other:?}"),
        }
    }

    #[test]
    fn prepare_creates_and_probes_the_data_directory() {
        let directory = TemporaryDirectory::new("prepare");
        let path = directory.join("nested").join("journal.json");

        let storage = FilesystemJournalStorage::prepare(&path).expect("prepare journal storage");

        assert_eq!(storage.path(), Path::new(&path));
        assert!(path.parent().expect("journal parent").is_dir());
        assert_eq!(
            fs::read_dir(path.parent().expect("journal parent"))
                .expect("read journal directory")
                .count(),
            0
        );
    }
}
