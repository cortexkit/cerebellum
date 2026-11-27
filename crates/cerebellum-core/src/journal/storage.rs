//! Durable journal storage bindings.
//!
//! The in-memory binding is intentionally small but models restart correctly:
//! cloned bindings share durable state, while handles and tokens remain local to
//! the binding that minted them.

use crate::private_fs;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

use super::{DurableState, StorageError};
use crate::format_floor::{DurableFormat, FormatFloor};

/// Version 4 adds position-based computer ordering to record identities.
/// Writes without that metadata remain at version 3, keeping rollback to an
/// origin-aware build possible until the first positioned record is written.
const JOURNAL_SCHEMA_VERSION: u64 = 4;
const ORIGIN_JOURNAL_SCHEMA_VERSION: u64 = 3;

/// The journal file format, shared by every audit journal this module keeps
/// (browser, computer and launch): they are written and read by this one
/// storage, so they rise and fall together.
pub const AUDIT_JOURNAL_FORMAT: DurableFormat =
    DurableFormat::new("audit-journal", JOURNAL_SCHEMA_VERSION);
const LEGACY_JOURNAL_SCHEMA_VERSION: u64 = 1;
const PREVIOUS_JOURNAL_SCHEMA_VERSION: u64 = 2;
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
    /// Raise the format floor governing this storage for a format about to
    /// be written into it: an entry or attachment format inside the journal.
    /// A storage with no floor (in memory, or outside the data home) returns
    /// `Ok` without touching anything.
    ///
    /// Required rather than defaulted: a wrapper that forgot to forward it
    /// would write decoded formats to the operator's disk with no floor.
    fn raise_format(&self, format: DurableFormat) -> Result<(), StorageError>;
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

    fn raise_format(&self, _format: DurableFormat) -> Result<(), StorageError> {
        Ok(())
    }
}

/// A whole-state JSON journal stored with crash-atomic replacement.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemJournalStorage {
    path: PathBuf,
    floor: FormatFloor,
}

impl FilesystemJournalStorage {
    /// A journal at `path`, raising the format floor that governs where it
    /// is: the operator's floor under the module's data directory, none for a
    /// journal anywhere else.
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let floor = FormatFloor::governing(&path);
        Self { path, floor }
    }

    /// Raise `floor` instead of the one chosen from the journal's location.
    pub fn with_format_floor(mut self, floor: FormatFloor) -> Self {
        self.floor = floor;
        self
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn format_floor(&self) -> &FormatFloor {
        &self.floor
    }

    /// Create and verify the journal directory before capabilities are offered.
    ///
    /// The probe reduces the chance of discovering an unwritable directory at
    /// first use, but runtime writes still report failure because permissions and
    /// free space can change after boot.
    pub fn prepare(path: impl Into<PathBuf>) -> Result<Self, StorageError> {
        let storage = Self::new(path);
        let directory = storage.directory();
        private_fs::create_dir_all(&directory).map_err(|source| StorageError::CreateDirectory {
            path: directory.clone(),
            source: io_diagnostic(source),
        })?;

        reclaim_abandoned_siblings(&storage.path);
        let probe = unique_sibling_path(&storage.path, "probe");
        let mut file =
            private_fs::create_new_file(&probe).map_err(|source| StorageError::ProbeWrite {
                path: probe.clone(),
                source: io_diagnostic(source),
            })?;
        // Removed by `cleanup` if writing or syncing the probe fails.
        let cleanup = RemoveUnlessKept::new(&probe);
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
        cleanup.keep();
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
            value["schema_version"] = ORIGIN_JOURNAL_SCHEMA_VERSION.into();
        } else if ![
            PREVIOUS_JOURNAL_SCHEMA_VERSION,
            ORIGIN_JOURNAL_SCHEMA_VERSION,
            JOURNAL_SCHEMA_VERSION,
        ]
        .contains(&version)
        {
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
    fn raise_format(&self, format: DurableFormat) -> Result<(), StorageError> {
        self.floor.raise(format).map_err(StorageError::FormatFloor)
    }

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
        let positioned = state
            .reservations
            .values()
            .map(|record| &record.identity)
            .chain(state.entries.values().map(|record| &record.identity))
            .any(|identity| !super::ComputerOrderRecord::is_legacy(&identity.computer_order));
        let schema_version = if positioned {
            JOURNAL_SCHEMA_VERSION
        } else {
            ORIGIN_JOURNAL_SCHEMA_VERSION
        };
        // Before anything is written: a journal in this format on disk with
        // no floor naming it would let staging pass a build that cannot read
        // it.
        self.floor
            .raise(DurableFormat::new(
                AUDIT_JOURNAL_FORMAT.name,
                schema_version,
            ))
            .map_err(StorageError::FormatFloor)?;
        let stored = StoredJournal {
            schema_version,
            state: state.clone(),
        };
        let bytes =
            serde_json::to_vec_pretty(&stored).map_err(|source| StorageError::Serialization {
                path: self.path.clone(),
                source: source.to_string(),
            })?;
        let directory = self.directory();
        let temporary = unique_sibling_path(&self.path, "tmp");
        let mut file = private_fs::create_new_file(&temporary).map_err(|source| {
            StorageError::TemporaryWrite {
                path: temporary.clone(),
                source: io_diagnostic(source),
            }
        })?;
        // From here every failure removes the snapshot: its name is unique to
        // this write, so nothing else would ever replace or read it.
        let cleanup = RemoveUnlessKept::new(&temporary);
        // Held while the snapshot is written, so a later startup never
        // reclaims the file of a live write (see `reclaim_abandoned_siblings`).
        let _ = file.try_lock();
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
            from: temporary.clone(),
            to: self.path.clone(),
            source: io_diagnostic(source),
        })?;
        cleanup.keep();
        sync_directory(&directory)
    }
}

/// Removes a file this module created when the work it was created for fails
/// before [`RemoveUnlessKept::keep`] is called.
struct RemoveUnlessKept<'a> {
    path: &'a Path,
    keep: bool,
}

impl<'a> RemoveUnlessKept<'a> {
    fn new(path: &'a Path) -> Self {
        Self { path, keep: false }
    }

    fn keep(mut self) {
        self.keep = true;
    }
}

impl Drop for RemoveUnlessKept<'_> {
    fn drop(&mut self) {
        if !self.keep {
            let _ = fs::remove_file(self.path);
        }
    }
}

/// A write's snapshot or probe left this long ago belongs to no live write.
/// Builds that do not lock their snapshots finish a write in moments, so the
/// age alone protects them.
const ABANDONED_AFTER: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// Remove snapshots and probes beside `target` that an earlier process left
/// when it exited mid-write: named for this journal by `unique_sibling_path`,
/// not locked by a live writer, and untouched for `ABANDONED_AFTER`. Best
/// effort: anything that cannot be checked is left alone.
fn reclaim_abandoned_siblings(target: &Path) {
    let (Some(directory), Some(name)) = (
        target.parent(),
        target.file_name().and_then(|name| name.to_str()),
    ) else {
        return;
    };
    let Ok(entries) = fs::read_dir(directory) else {
        return;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(rest) = file_name
            .to_str()
            .and_then(|file_name| file_name.strip_prefix(&format!(".{name}.")))
        else {
            continue;
        };
        let Some((role, numbers)) = rest.split_once('.') else {
            continue;
        };
        let named = matches!(role, "tmp" | "probe")
            && numbers.split_once('.').is_some_and(|(pid, sequence)| {
                [pid, sequence]
                    .iter()
                    .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
            });
        let path = entry.path();
        let abandoned = named
            && fs::symlink_metadata(&path).is_ok_and(|metadata| {
                metadata.is_file()
                    && metadata
                        .modified()
                        .ok()
                        .and_then(|modified| modified.elapsed().ok())
                        .is_some_and(|age| age >= ABANDONED_AFTER)
            })
            && File::open(&path).is_ok_and(|file| file.try_lock().is_ok());
        if abandoned {
            let _ = fs::remove_file(&path);
        }
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
    // The daemon's ladder, not a bare HOME read: an operator with
    // XDG_DATA_HOME set had the backup catalog resolving under it while the
    // journal was written under ~/.local/share -- undeclared and unbacked-up,
    // with both sides healthy.
    let data_home = crate::platform_dirs::data_home().ok_or_else(|| {
        StorageError::HomeDirectoryUnavailable {
            variable: "HOME".to_string(),
        }
    })?;
    Ok(data_home
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

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), StorageError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| StorageError::DirectorySync {
            path: path.to_path_buf(),
            source: io_diagnostic(source),
        })
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), StorageError> {
    // Windows cannot flush a directory through std::fs::File. The snapshot
    // itself is flushed before rename.
    Ok(())
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

    fn state_with_order(order: Option<crate::journal::ComputerOrderRecord>) -> DurableState {
        let identity = crate::journal::JournalIdentity {
            principal: "fixture".into(),
            conversation_key: "conversation".into(),
            agent_project_id: "project".into(),
            session_kind: crate::identity::SessionKind::Primary,
            origin: Default::default(),
            witness: crate::dispatch_witness::DispatchWitness::detached(),
            computer_order: order,
        };
        let mut state = state(2);
        state.reservations.insert(
            1,
            crate::journal::ReservationRecord {
                identity,
                invocation_descriptor: b"fixture".to_vec(),
                provisional: crate::journal::EncodedJournalState {
                    durable_bytes: b"{}".to_vec(),
                    accounted_serialized_size: 2,
                    codec_version: "fixture/v1".into(),
                },
                codec_id: "fixture/v1".into(),
                charge: 2,
                state: crate::journal::LifecycleState::Active,
                marker: None,
                dispatch: None,
                attachments: Default::default(),
            },
        );
        state
    }

    // Frozen origin-era identity fields, deliberately independent of the live
    // JournalIdentity type. Retagging a positioned record as v3 must not make
    // its new field readable by the strict rollback reader.
    #[derive(serde::Deserialize)]
    #[serde(deny_unknown_fields)]
    struct V3Identity {
        #[serde(rename = "principal")]
        _principal: String,
        #[serde(rename = "conversation_key")]
        _conversation_key: String,
        #[serde(rename = "agent_project_id")]
        _agent_project_id: String,
        #[serde(rename = "session_kind")]
        _session_kind: serde_json::Value,
        #[serde(default, rename = "origin")]
        _origin: Option<serde_json::Value>,
    }

    fn v3_reader(bytes: &[u8]) -> Result<(), String> {
        let stored: serde_json::Value =
            serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
        if stored["schema_version"].as_u64() != Some(3) {
            return Err("unsupported schema version".into());
        }
        for collection in ["reservations", "entries"] {
            for record in stored["state"][collection].as_object().unwrap().values() {
                serde_json::from_value::<V3Identity>(record["identity"].clone())
                    .map_err(|error| error.to_string())?;
            }
        }
        Ok(())
    }

    /// The names of the files beside the journal that a save or probe left.
    fn leftovers(directory: &TemporaryDirectory) -> Vec<String> {
        let mut names: Vec<_> = fs::read_dir(&directory.0)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .filter(|name| name.starts_with(".journal.json."))
            .collect();
        names.sort();
        names
    }

    /// A save that fails after writing its snapshot (here, the rename onto a
    /// directory) removes the snapshot, so repeated failures leave nothing.
    #[test]
    fn a_failed_save_leaves_no_snapshot_behind() {
        let directory = TemporaryDirectory::new("failed-save");
        let path = directory.join("journal.json");
        fs::create_dir_all(path.join("occupied")).unwrap();
        let storage = FilesystemJournalStorage::new(&path);
        for _ in 0..3 {
            assert!(matches!(
                storage.save(&state(2)),
                Err(StorageError::Rename { .. })
            ));
        }
        assert_eq!(leftovers(&directory), Vec::<String>::new());
    }

    /// Startup removes a snapshot an exited writer abandoned, but never the
    /// committed journal, a snapshot a live writer holds locked, a snapshot
    /// too recent to be abandoned, or another file's snapshot.
    #[test]
    fn startup_reclaims_only_abandoned_snapshots() {
        let directory = TemporaryDirectory::new("reclaim");
        let path = directory.join("journal.json");
        FilesystemJournalStorage::new(&path)
            .save(&state(2))
            .unwrap();
        let committed = fs::read(&path).unwrap();
        let an_hour_ago = std::time::SystemTime::now() - std::time::Duration::from_secs(3600);
        let snapshot = |name: &str, old: bool| {
            let file = directory.join(name);
            fs::write(&file, b"partial").unwrap();
            if old {
                fs::File::options()
                    .write(true)
                    .open(&file)
                    .unwrap()
                    .set_modified(an_hour_ago)
                    .unwrap();
            }
            file
        };
        snapshot(".journal.json.tmp.4000000000.1", true);
        snapshot(".journal.json.probe.4000000000.2", true);
        let live = snapshot(".journal.json.tmp.4000000001.3", true);
        let live = fs::File::open(live).unwrap();
        live.lock().unwrap();
        snapshot(".journal.json.tmp.4000000002.4", false);
        snapshot(".other.json.tmp.4000000000.5", true);
        FilesystemJournalStorage::prepare(&path).unwrap();
        assert_eq!(
            leftovers(&directory),
            [
                ".journal.json.tmp.4000000001.3",
                ".journal.json.tmp.4000000002.4"
            ]
        );
        assert!(directory.join(".other.json.tmp.4000000000.5").exists());
        assert_eq!(fs::read(&path).unwrap(), committed);
        drop(live);
    }

    #[test]
    fn v3_rollback_reader_rejects_positioned_records_but_current_reader_accepts_both() {
        use crate::journal::{ComputerOrderRecord, ComputerOrdering};
        let directory = TemporaryDirectory::new("position-reader");
        let path = directory.join("journal.json");
        let storage = FilesystemJournalStorage::new(&path);
        let legacy = state_with_order(None);
        storage.save(&legacy).unwrap();
        let bytes = fs::read(&path).unwrap();
        v3_reader(&bytes).expect("the rollback fixture reaches and accepts a v3 identity");
        assert_eq!(storage.load().unwrap(), legacy);
        for ordering in [ComputerOrdering::Position, ComputerOrdering::SkippedGap] {
            let positioned = state_with_order(Some(ComputerOrderRecord {
                message_index: Some(2),
                ordering,
            }));
            storage.save(&positioned).unwrap();
            let bytes = fs::read(&path).unwrap();
            let mut encoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(encoded["schema_version"], 4);
            assert_eq!(v3_reader(&bytes).unwrap_err(), "unsupported schema version");
            assert_eq!(storage.load().unwrap(), positioned);
            encoded["schema_version"] = 3.into();
            assert!(v3_reader(&serde_json::to_vec(&encoded).unwrap())
                .unwrap_err()
                .contains("computer_order"));
        }
    }

    #[test]
    fn unpositioned_records_keep_v3_and_leave_the_existing_floor_byte_identical() {
        use crate::journal::{ComputerOrderRecord, ComputerOrdering};
        let directory = TemporaryDirectory::new("position-unused");
        let path = directory.join("journal.json");
        let floor = directory.join("format-floor.json");
        let storage = FilesystemJournalStorage::new(&path)
            .with_format_floor(crate::format_floor::FormatFloor::at(&floor));
        storage.load().unwrap();
        assert!(!floor.exists(), "opening a journal raised a floor");
        storage.save(&state_with_order(None)).unwrap();
        let old_floor = fs::read(&floor).unwrap();
        assert_eq!(
            crate::format_floor::read_floors(&floor)
                .unwrap()
                .get("audit-journal"),
            Some(&3)
        );
        for message_index in [None, Some(2)] {
            storage
                .save(&state_with_order(Some(ComputerOrderRecord {
                    message_index,
                    ordering: ComputerOrdering::Arrival,
                })))
                .unwrap();
            let bytes = fs::read(&path).unwrap();
            let encoded: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(encoded["schema_version"], 3);
            assert!(encoded["state"]["reservations"]["1"]["identity"]
                .get("computer_order")
                .is_none());
            v3_reader(&bytes).unwrap();
            assert_eq!(fs::read(&floor).unwrap(), old_floor);
        }
    }

    #[test]
    fn positioned_record_requires_v4_floor_before_replacing_v3_journal() {
        use crate::journal::{ComputerOrderRecord, ComputerOrdering};
        let directory = TemporaryDirectory::new("position-floor-first");
        let path = directory.join("journal.json");
        let floor = directory.join("format-floor.json");
        let storage = FilesystemJournalStorage::new(&path)
            .with_format_floor(crate::format_floor::FormatFloor::at(&floor));
        storage.save(&state_with_order(None)).unwrap();
        let legacy = fs::read(&path).unwrap();
        let old_floor = fs::read(&floor).unwrap();
        // The v3 raise is cached. Blocking the next raise isolates the new v4
        // floor, rather than proving only that any journal write needs a floor.
        fs::remove_file(&floor).unwrap();
        fs::create_dir(&floor).unwrap();
        let positioned = state_with_order(Some(ComputerOrderRecord {
            message_index: Some(2),
            ordering: ComputerOrdering::Position,
        }));
        assert!(matches!(
            storage.save(&positioned),
            Err(StorageError::FormatFloor(_))
        ));
        assert_eq!(
            fs::read(&path).unwrap(),
            legacy,
            "a v4 record reached disk before its floor"
        );
        fs::remove_dir(&floor).unwrap();
        fs::write(&floor, old_floor).unwrap();
        storage.save(&positioned).unwrap();
        assert_eq!(
            crate::format_floor::read_floors(&floor)
                .unwrap()
                .get("audit-journal"),
            Some(&4)
        );
        assert_eq!(storage.load().unwrap(), positioned);
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

    #[cfg(windows)]
    #[test]
    fn windows_prepares_storage_and_reopens_a_replaced_snapshot() {
        let directory = TemporaryDirectory::new("prepare-and-replace");
        let path = directory.join("nested").join("journal.json");
        let storage = FilesystemJournalStorage::prepare(&path).expect("prepare journal storage");
        storage.save(&state(7)).expect("write the first snapshot");
        storage.save(&state(42)).expect("replace the snapshot");
        let reopened = FilesystemJournalStorage::new(&path).load().unwrap();
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
        assert_eq!(
            migrated["schema_version"], 3,
            "migration without ordering stays rollback-compatible"
        );
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
        fs::write(&path, br#"{"schema_version":5,"state":{}}"#).expect("write future journal");

        assert_eq!(
            FilesystemJournalStorage::new(&path).load(),
            Err(StorageError::UnknownSchemaVersion {
                path,
                found: 5,
                supported: 4,
            })
        );
    }

    /// A journal the previous build wrote (schema 2) loads, and is left as it
    /// was until the next save. Version 2 records holding identities are read
    /// by the computer journal's frozen fixture test in `cerebellum-computer`.
    #[test]
    fn a_version_2_journal_still_loads() {
        let directory = TemporaryDirectory::new("previous-version");
        let path = directory.join("journal.json");
        let written = state(3);
        FilesystemJournalStorage::new(&path)
            .save(&written)
            .expect("save");
        let mut stored: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        stored["schema_version"] = 2.into();
        let previous = serde_json::to_vec(&stored).unwrap();
        fs::write(&path, &previous).unwrap();

        assert_eq!(FilesystemJournalStorage::new(&path).load(), Ok(written));
        assert_eq!(fs::read(&path).unwrap(), previous, "loading rewrote it");
    }

    #[test]
    fn a_journal_from_the_next_version_is_refused_by_name_not_as_corrupt() {
        let directory = TemporaryDirectory::new("newer-writer");
        let path = directory.join("journal.json");
        // A newer build may add fields this build's strict reader rejects;
        // the version must be read, and refused, before any of them.
        let newer = serde_json::json!({
            "schema_version": JOURNAL_SCHEMA_VERSION + 1,
            "state": {"a_field_this_build_does_not_know": true},
            "another_new_top_level_field": 1,
        });
        fs::write(&path, serde_json::to_vec(&newer).unwrap()).expect("write newer journal");

        assert_eq!(
            FilesystemJournalStorage::new(&path).load(),
            Err(StorageError::UnknownSchemaVersion {
                path,
                found: JOURNAL_SCHEMA_VERSION + 1,
                supported: super::AUDIT_JOURNAL_FORMAT.version,
            })
        );
    }

    #[test]
    fn a_save_raises_the_format_floor_before_writing() {
        let directory = TemporaryDirectory::new("floor-raise");
        let path = directory.join("journal.json");
        let floor_path = directory.join("format-floor.json");
        FilesystemJournalStorage::new(&path)
            .with_format_floor(crate::format_floor::FormatFloor::at(&floor_path))
            .save(&state(3))
            .expect("save");

        let floors = crate::format_floor::read_floors(&floor_path).expect("read floors");
        assert_eq!(floors.get("audit-journal"), Some(&3));
    }

    #[test]
    fn a_floor_that_cannot_be_raised_refuses_the_save_and_writes_nothing() {
        let directory = TemporaryDirectory::new("floor-refuses");
        let path = directory.join("journal.json");
        let blocker = directory.join("not-a-directory");
        fs::write(&blocker, b"file").expect("plant a file where the floor's directory goes");
        let result = FilesystemJournalStorage::new(&path)
            .with_format_floor(crate::format_floor::FormatFloor::at(
                blocker.join("format-floor.json"),
            ))
            .save(&state(3));

        assert!(
            matches!(result, Err(StorageError::FormatFloor(_))),
            "{result:?}"
        );
        assert!(!path.exists(), "the journal was written without a floor");
    }

    #[test]
    fn a_journal_outside_the_data_home_raises_no_floor() {
        let directory = TemporaryDirectory::new("floor-isolated");
        let storage = FilesystemJournalStorage::new(directory.join("journal.json"));
        assert_eq!(storage.format_floor().path(), None);
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
