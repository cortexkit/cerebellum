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

const JOURNAL_SCHEMA_VERSION: u64 = 2;
const LEGACY_JOURNAL_SCHEMA_VERSION: u64 = 1;
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

        let mut value: serde_json::Value =
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
        let migrated = version == LEGACY_JOURNAL_SCHEMA_VERSION;
        if migrated {
            migrate_v1_byte_arrays(&mut value).map_err(|source| StorageError::Corrupt {
                path: self.path.clone(),
                source,
            })?;
            value["schema_version"] = JOURNAL_SCHEMA_VERSION.into();
        } else if version != JOURNAL_SCHEMA_VERSION {
            return Err(StorageError::UnknownSchemaVersion {
                path: self.path.clone(),
                found: version,
                supported: JOURNAL_SCHEMA_VERSION,
            });
        }
        let mut state = serde_json::from_value::<StoredJournal>(value)
            .map(|stored| stored.state)
            .map_err(|source| StorageError::Corrupt {
                path: self.path.clone(),
                source: source.to_string(),
            })?;
        if migrated {
            refresh_migrated_accounting(&mut state).map_err(|source| StorageError::Corrupt {
                path: self.path.clone(),
                source,
            })?;
            // Rewrite only after the complete v1 state decoded. Atomic save keeps
            // the old audit trail intact if migration cannot be committed.
            self.save(&state)?;
        }
        Ok(state)
    }
}

fn refresh_migrated_accounting(state: &mut DurableState) -> Result<(), String> {
    for (sequence, reservation) in &mut state.reservations {
        super::refresh_reservation_charge(reservation)
            .map_err(|_| format!("could not account migrated reservation {sequence}"))?;
    }
    for (sequence, entry) in &mut state.entries {
        super::refresh_terminal_charge(entry)
            .map_err(|_| format!("could not account migrated entry {sequence}"))?;
    }
    Ok(())
}

fn migrate_v1_byte_arrays(value: &mut serde_json::Value) -> Result<(), String> {
    let state = value
        .get_mut("state")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| "v1 state is missing or is not an object".to_string())?;

    {
        let entries = state
            .get_mut("entries")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| "v1 state.entries is missing or is not an object".to_string())?;
        for (sequence, entry) in entries {
            let context = format!("v1 state.entries.{sequence}");
            let entry = entry
                .as_object_mut()
                .ok_or_else(|| format!("{context} is not an object"))?;
            migrate_byte_field(entry, "invocation_descriptor", &context, false)?;
            migrate_byte_field(entry, "bytes", &context, false)?;
            migrate_attachments(entry, &context)?;
        }
    }

    {
        let reservations = state
            .get_mut("reservations")
            .and_then(serde_json::Value::as_object_mut)
            .ok_or_else(|| "v1 state.reservations is missing or is not an object".to_string())?;
        for (sequence, reservation) in reservations {
            let context = format!("v1 state.reservations.{sequence}");
            let reservation = reservation
                .as_object_mut()
                .ok_or_else(|| format!("{context} is not an object"))?;
            migrate_byte_field(reservation, "invocation_descriptor", &context, false)?;
            let provisional = reservation
                .get_mut("provisional")
                .and_then(serde_json::Value::as_object_mut)
                .ok_or_else(|| format!("{context}.provisional is not an object"))?;
            migrate_byte_field(
                provisional,
                "durable_bytes",
                &format!("{context}.provisional"),
                false,
            )?;

            if let Some(marker) = reservation.get_mut("marker") {
                if !marker.is_null() && !marker.is_string() {
                    let marker = marker
                        .as_object_mut()
                        .ok_or_else(|| format!("{context}.marker has an invalid shape"))?;
                    if let Some(rejection) = marker.get_mut("rejection") {
                        let rejection = rejection.as_object_mut().ok_or_else(|| {
                            format!("{context}.marker.rejection is not an object")
                        })?;
                        migrate_byte_field(
                            rejection,
                            "rejection_material",
                            &format!("{context}.marker.rejection"),
                            false,
                        )?;
                    }
                }
            }

            if let Some(dispatch) = reservation.get_mut("dispatch") {
                if !dispatch.is_null() {
                    let dispatch = dispatch
                        .as_object_mut()
                        .ok_or_else(|| format!("{context}.dispatch is not an object"))?;
                    migrate_byte_field(
                        dispatch,
                        "dispatch_material",
                        &format!("{context}.dispatch"),
                        false,
                    )?;
                    migrate_byte_field(
                        dispatch,
                        "grant_decision",
                        &format!("{context}.dispatch"),
                        false,
                    )?;
                    migrate_byte_field(
                        dispatch,
                        "governing_observation",
                        &format!("{context}.dispatch"),
                        true,
                    )?;
                }
            }
            migrate_attachments(reservation, &context)?;
        }
    }
    Ok(())
}

fn migrate_attachments(
    record: &mut serde_json::Map<String, serde_json::Value>,
    context: &str,
) -> Result<(), String> {
    let attachments = record
        .get_mut("attachments")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(|| format!("{context}.attachments is missing or is not an object"))?;
    for (slot, attachment) in attachments {
        let attachment_context = format!("{context}.attachments.{slot}");
        let attachment = attachment
            .as_object_mut()
            .ok_or_else(|| format!("{attachment_context} is not an object"))?;
        migrate_byte_field(attachment, "opaque_bytes", &attachment_context, false)?;
    }
    Ok(())
}

fn migrate_byte_field(
    object: &mut serde_json::Map<String, serde_json::Value>,
    field: &str,
    context: &str,
    optional: bool,
) -> Result<(), String> {
    let value = object
        .get_mut(field)
        .ok_or_else(|| format!("{context}.{field} is missing"))?;
    if optional && value.is_null() {
        return Ok(());
    }
    let array = value
        .as_array()
        .ok_or_else(|| format!("{context}.{field} is not a byte array"))?;
    let bytes = array
        .iter()
        .enumerate()
        .map(|(index, value)| {
            value
                .as_u64()
                .and_then(|byte| u8::try_from(byte).ok())
                .ok_or_else(|| format!("{context}.{field}[{index}] is not a byte"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    *value = serde_json::Value::String(crate::serde_base64::encode(&bytes));
    Ok(())
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

/// Return the stable journal data path under
/// `~/.local/share/cortexkit/cerebellum/journal/`.
///
/// Journal records are application data rather than configuration, so they do
/// not live beside `~/.config/cortexkit/cerebellum.jsonc`.
///
/// UNDER the module's own directory rather than beside it, because the fleet's
/// backup enrollment resolves every declared path against `<data
/// home>/cortexkit/<module id>/` and refuses `..` outright. Data written to a
/// sibling directory is therefore not merely undeclared — it is UNDECLARABLE,
/// so it can be neither backed up nor deliberately excluded, and its absence
/// from a catalog looks identical to an oversight.
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
        .join("cerebellum")
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

    use super::{FilesystemJournalStorage, JournalStorage, JOURNAL_SCHEMA_VERSION};
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
    fn frozen_v1_journal_loads_and_migrates_without_losing_audit_bytes() {
        const V1_BYTES: &[u8] =
            include_bytes!("../../tests/fixtures/browser-launch-journal-v1.json");
        assert_eq!(V1_BYTES.len(), 131_428, "the frozen v1 literal changed");

        let directory = TemporaryDirectory::new("v1-migration");
        let path = directory.join("journal.json");
        fs::write(&path, V1_BYTES).expect("write exact pre-migration journal bytes");

        let state = FilesystemJournalStorage::new(&path)
            .load()
            .expect("load and migrate v1 journal");
        assert_eq!(state.next_sequence, 2);
        let entry = state.entries.get(&1).expect("migrated terminal entry");
        let descriptor: serde_json::Value = serde_json::from_slice(&entry.invocation_descriptor)
            .expect("decode retained launch descriptor");
        assert_eq!(
            descriptor["format_version"],
            "ck-browser-launch-attestation/v1"
        );
        assert_eq!(entry.codec_id, "ck-browser-launch-attestation/v1");
        assert_eq!(entry.attachments.len(), 2);
        assert!(entry.attachments.contains_key("browser.launch.attestation"));
        assert!(entry.attachments.contains_key("browser.launch.generation"));

        let migrated: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read atomically migrated journal"))
                .expect("parse migrated journal");
        assert_eq!(migrated["schema_version"], JOURNAL_SCHEMA_VERSION);
        let migrated_entry = &migrated["state"]["entries"]["1"];
        assert!(migrated_entry["invocation_descriptor"].is_string());
        assert!(migrated_entry["bytes"].is_string());
        assert!(
            migrated_entry["attachments"]["browser.launch.attestation"]["opaque_bytes"].is_string()
        );
        assert_eq!(
            migrated_entry["accounted_size"].as_u64(),
            Some(serde_json::to_vec(migrated_entry).unwrap().len() as u64),
            "migration must recalibrate accounting to the base64 entry"
        );
    }

    #[test]
    fn unrecognized_schema_version_is_typed_and_never_starts_fresh() {
        let directory = TemporaryDirectory::new("unknown-version");
        let path = directory.join("journal.json");
        fs::write(&path, br#"{"schema_version":3,"state":{}}"#).expect("write future journal");

        assert_eq!(
            FilesystemJournalStorage::new(&path).load(),
            Err(StorageError::UnknownSchemaVersion {
                path,
                found: 3,
                supported: 2,
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
