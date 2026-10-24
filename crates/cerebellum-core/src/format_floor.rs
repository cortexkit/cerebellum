//! The format floor: which durable record versions are already on disk.
//!
//! Every durable reader in this module is strict: it refuses a record whose
//! version it does not know. That is the right answer, but on its own it is
//! discovered only when a build meets such a record, and after a rollback that
//! happens in production: an older build that finds a lock written in a newer
//! format refuses it, and the profile stays locked until someone removes the
//! file by hand.
//!
//! Three pieces close that gap, and this file holds the shared parts of all
//! three:
//!
//! - A reader that meets a newer record refuses it by name ([`NewerWriter`]),
//!   so the refusal reads as "a newer build wrote this", never as corruption.
//! - A writer raises the floor for its format ([`FormatFloor::raise`]) before
//!   it first writes that format, so the floor file always names at least
//!   every version that is on disk.
//! - Staging compares the floor file against the versions a build can read,
//!   and refuses to hand over a build that could not read what is on disk.
//!
//! There is one floor file per data tree the module keeps, inside that tree:
//! `<data home>/cortexkit/cerebellum/journal/format-floor.json` for the
//! journals and the grant store, `.../browser/format-floor.json` for the
//! profile registry and custody locks. Each sits inside the tree it governs
//! because the trees are backed up separately (the journal travels between
//! machines, the browser profiles stay on theirs), and a floor must arrive
//! wherever its records do. Each is shaped
//! `{"version": 1, "floors": {"<format>": <version>, ...}}`. Floors only ever
//! rise: a lowered floor would let staging pass a build that cannot read a
//! record some other build already wrote.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use serde::{Deserialize, Serialize};

/// The floor file's name, directly inside each data tree it governs.
pub const FORMAT_FLOOR_FILE: &str = "format-floor.json";

/// The data trees under the module's directory that each keep a floor: every
/// durable store this module writes to the operator's disk lives in one.
pub const FLOOR_TREES: [&str; 3] = ["journal", "browser", "private-content"];

/// The floor file's own format. It is read by staging as well as by the
/// module, so it is versioned and refused by name like every other record.
pub const FORMAT_FLOOR_FORMAT: DurableFormat = DurableFormat::new("format-floor", 1);

static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// A durable format and the highest version of it this build reads and writes.
///
/// Each reader and writer takes its version from one of these, and the list a
/// build reports to staging is made of the same values, so what staging checks
/// is what the readers actually accept.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DurableFormat {
    /// The name the floor file and staging use for this format.
    pub name: &'static str,
    /// The highest version this build reads, which is also the one it writes.
    pub version: u64,
}

impl DurableFormat {
    pub const fn new(name: &'static str, version: u64) -> Self {
        Self { name, version }
    }

    /// Refuse a record whose version is newer than this build reads.
    ///
    /// Only a NEWER version is refused here. An older or otherwise unknown
    /// version is the reader's own business: some are migrated, some are
    /// refused for a different reason.
    pub fn refuse_newer(&self, found: u64) -> Result<(), NewerWriter> {
        if found > self.version {
            return Err(NewerWriter {
                format: self.name,
                found,
                supported: self.version,
            });
        }
        Ok(())
    }

    /// [`Self::refuse_newer`] for a format whose records carry their version
    /// as a tag like `ck-browser-profile-custody-lock/v2`. `current_tag` is
    /// the tag this build writes; a found tag in the same family with a higher
    /// number is refused by name. A tag from another family is not a newer
    /// version of this format, so it passes here and the caller refuses it
    /// for what it is.
    pub fn refuse_newer_tag(&self, found_tag: &str, current_tag: &str) -> Result<(), NewerWriter> {
        match tag_family_version(found_tag, current_tag) {
            Some(found) => self.refuse_newer(found),
            None => Ok(()),
        }
    }
}

/// The version number at the end of a tag such as
/// `ck-browser-profile-registry/v1`. Evaluated at compile time for the tags
/// this build writes, so a tag without a trailing `/v<number>` fails the build
/// rather than reporting version zero to staging.
pub const fn tag_version(tag: &str) -> u64 {
    let bytes = tag.as_bytes();
    let end = bytes.len();
    let mut start = end;
    while start > 0 && bytes[start - 1].is_ascii_digit() {
        start -= 1;
    }
    assert!(start < end, "a versioned tag ends in its version number");
    assert!(
        start >= 2 && bytes[start - 1] == b'v' && bytes[start - 2] == b'/',
        "a versioned tag ends in /v<number>"
    );
    let mut value: u64 = 0;
    let mut index = start;
    while index < end {
        value = value * 10 + (bytes[index] - b'0') as u64;
        index += 1;
    }
    value
}

/// The version of `found_tag` when it is in the same family as `current_tag`
/// (the same text up to the trailing number), or `None` when it is not.
fn tag_family_version(found_tag: &str, current_tag: &str) -> Option<u64> {
    let family = current_tag.trim_end_matches(|c: char| c.is_ascii_digit());
    let number = found_tag.strip_prefix(family)?;
    if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    // A number too large for u64 is still newer than anything this build
    // writes, and must not fall through to "not this format".
    Some(number.parse().unwrap_or(u64::MAX))
}

/// A record written by a newer build, refused by name.
///
/// The remedy is to run a build that reads it, not to repair or delete the
/// record, which is why this is never reported as corruption.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewerWriter {
    pub format: &'static str,
    pub found: u64,
    pub supported: u64,
}

impl fmt::Display for NewerWriter {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "newer_writer: the {} record is version {}, written by a newer build; \
             this build reads up to version {}",
            self.format, self.found, self.supported
        )
    }
}

impl std::error::Error for NewerWriter {}

/// Why the floor could not be read or raised.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorError {
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
        message: String,
    },
    Corrupt {
        path: PathBuf,
        detail: String,
    },
    NewerWriter {
        path: PathBuf,
        newer: NewerWriter,
    },
}

impl fmt::Display for FloorError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io {
                operation,
                path,
                message,
                ..
            } => write!(
                formatter,
                "format floor {operation} failed for {}: {message}",
                path.display()
            ),
            Self::Corrupt { path, detail } => write!(
                formatter,
                "format floor {} is not a floor file: {detail}",
                path.display()
            ),
            Self::NewerWriter { path, newer } => {
                write!(formatter, "format floor {}: {newer}", path.display())
            }
        }
    }
}

impl std::error::Error for FloorError {}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FloorDocument {
    version: u64,
    floors: BTreeMap<String, u64>,
}

/// The floors recorded at `path`. A missing file is floor zero for every
/// format: nothing that raises a floor has written there yet.
pub fn read_floors(path: &Path) -> Result<BTreeMap<String, u64>, FloorError> {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(BTreeMap::new()),
        Err(error) => return Err(io_error("read", path, error)),
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| FloorError::Corrupt {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    // The version is read before the rest, so a floor file from a newer build
    // is refused by name rather than as a shape this build does not know.
    let version = value
        .get("version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| FloorError::Corrupt {
            path: path.to_path_buf(),
            detail: "version is missing or is not an unsigned integer".to_string(),
        })?;
    FORMAT_FLOOR_FORMAT
        .refuse_newer(version)
        .map_err(|newer| FloorError::NewerWriter {
            path: path.to_path_buf(),
            newer,
        })?;
    if version != FORMAT_FLOOR_FORMAT.version {
        return Err(FloorError::Corrupt {
            path: path.to_path_buf(),
            detail: format!("unknown floor file version {version}"),
        });
    }
    let document: FloorDocument =
        serde_json::from_value(value).map_err(|error| FloorError::Corrupt {
            path: path.to_path_buf(),
            detail: error.to_string(),
        })?;
    Ok(document.floors)
}

/// The module's data directory under a data home, holding every data tree
/// this module writes to the operator's disk.
pub fn module_directory(data_home: &Path) -> PathBuf {
    data_home.join("cortexkit").join("cerebellum")
}

/// The floor file for one data tree (one of [`FLOOR_TREES`]) under a data
/// home.
pub fn floor_path(data_home: &Path, tree: &str) -> PathBuf {
    module_directory(data_home)
        .join(tree)
        .join(FORMAT_FLOOR_FILE)
}

/// Where a durable writer records the formats it has put on disk.
///
/// Cloning shares the "already raised" memory, so every store governed by the
/// same floor file raises each format at most once per process.
#[derive(Clone)]
pub struct FormatFloor {
    target: FloorTarget,
}

/// The versions already raised in this process, per format name.
type RaisedThisRun = Arc<Mutex<BTreeMap<String, u64>>>;

#[derive(Clone)]
enum FloorTarget {
    /// No file. For stores that are not the operator's: in-memory stores,
    /// isolated planes, and fixtures in scratch directories. Raising is a
    /// no-op, so such a store never creates or reads the operator's floor.
    Isolated,
    File {
        path: PathBuf,
        raised: RaisedThisRun,
    },
}

impl fmt::Debug for FormatFloor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.target {
            FloorTarget::Isolated => formatter.write_str("FormatFloor::Isolated"),
            FloorTarget::File { path, .. } => {
                write!(formatter, "FormatFloor::File({})", path.display())
            }
        }
    }
}

/// Two floors are the same when they write the same file; the in-process
/// memory is a cache of that file, not part of its identity.
impl PartialEq for FormatFloor {
    fn eq(&self, other: &Self) -> bool {
        self.path() == other.path()
    }
}

impl Eq for FormatFloor {}

impl FormatFloor {
    /// A floor that touches no file.
    pub fn isolated() -> Self {
        Self {
            target: FloorTarget::Isolated,
        }
    }

    /// A floor file at an explicit path, with its own in-process memory.
    /// Opening the same path again models a restart: the new value remembers
    /// nothing, and reads what the file says.
    pub fn at(path: impl Into<PathBuf>) -> Self {
        Self {
            target: FloorTarget::File {
                path: path.into(),
                raised: Arc::new(Mutex::new(BTreeMap::new())),
            },
        }
    }

    /// The floor file at `path`, sharing its in-process memory with every
    /// other store in this process that uses the same file.
    fn shared(path: PathBuf) -> Self {
        static SHARED: OnceLock<Mutex<BTreeMap<PathBuf, RaisedThisRun>>> = OnceLock::new();
        let raised = SHARED
            .get_or_init(|| Mutex::new(BTreeMap::new()))
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(path.clone())
            .or_default()
            .clone();
        Self {
            target: FloorTarget::File { path, raised },
        }
    }

    /// The floor that governs a store at `store_path`: the operator's floor
    /// file of the data tree the store lives in, and an isolated floor for a
    /// store in none of them.
    ///
    /// Chosen from where the store is rather than by each caller, because a
    /// production store that forgot to name its floor would write a newer
    /// format with no floor at all, and a test that named the operator's
    /// floor would write to the operator's disk. Where the store is decides
    /// both correctly without anyone having to remember.
    pub fn governing(store_path: &Path) -> Self {
        Self::governing_under(store_path, crate::platform_dirs::data_home().as_deref())
    }

    /// [`Self::governing`] against an explicit data home, so the choice can be
    /// tested without changing the process environment.
    pub fn governing_under(store_path: &Path, data_home: Option<&Path>) -> Self {
        let Some(data_home) = data_home else {
            return Self::isolated();
        };
        let module = module_directory(data_home);
        for tree in FLOOR_TREES {
            let tree_directory = module.join(tree);
            // Also compared canonically: a store opened through its canonical
            // path (the profile registry holds its root that way) is still
            // under a data home reached through a symlink.
            let inside = store_path.starts_with(&tree_directory)
                || fs::canonicalize(&tree_directory)
                    .is_ok_and(|canonical| store_path.starts_with(canonical));
            if inside {
                return Self::shared(tree_directory.join(FORMAT_FLOOR_FILE));
            }
        }
        Self::isolated()
    }

    /// The file this floor writes, or `None` for an isolated floor.
    pub fn path(&self) -> Option<&Path> {
        match &self.target {
            FloorTarget::Isolated => None,
            FloorTarget::File { path, .. } => Some(path),
        }
    }

    /// Make sure the floor for `format` is at least its version, before a
    /// record in that format is written. Call it before every write: after
    /// the first successful raise in this process it returns without touching
    /// the disk.
    ///
    /// An error means the floor could not be recorded, and the caller must
    /// not write the record: a newer format on disk with no floor naming it
    /// is exactly what lets staging pass a build that cannot read it.
    pub fn raise(&self, format: DurableFormat) -> Result<(), FloorError> {
        let FloorTarget::File { path, raised } = &self.target else {
            return Ok(());
        };
        let mut raised = raised.lock().unwrap_or_else(PoisonError::into_inner);
        if raised
            .get(format.name)
            .is_some_and(|recorded| *recorded >= format.version)
        {
            return Ok(());
        }
        raise_on_disk(path, format)?;
        raised.insert(format.name.to_string(), format.version);
        Ok(())
    }
}

/// Raise one floor in the file, never lowering any.
///
/// Serialized across processes by a lock file beside the floor, because the
/// file is rewritten whole: two processes raising different formats at once
/// would each write back what they read, and the second rename would lower
/// the floor the first one just raised.
fn raise_on_disk(path: &Path, format: DurableFormat) -> Result<(), FloorError> {
    let directory = path
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    crate::private_fs::create_dir_all(&directory)
        .map_err(|error| io_error("create directory", &directory, error))?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_else(|| FORMAT_FLOOR_FILE.to_string());
    let lock_path = directory.join(format!(".{file_name}.lock"));
    let lock = crate::private_fs::open_lock(&lock_path)
        .map_err(|error| io_error("open lock", &lock_path, error))?;
    lock.lock()
        .map_err(|error| io_error("lock", &lock_path, error))?;

    let mut floors = read_floors(path)?;
    let current = floors.get(format.name).copied().unwrap_or(0);
    if current >= format.version {
        return Ok(());
    }
    floors.insert(format.name.to_string(), format.version);
    let bytes = serde_json::to_vec_pretty(&FloorDocument {
        version: FORMAT_FLOOR_FORMAT.version,
        floors,
    })
    .map_err(|error| FloorError::Corrupt {
        path: path.to_path_buf(),
        detail: error.to_string(),
    })?;

    // Written beside the floor and renamed over it, so a crash leaves either
    // the old floor or the new one, never half of one.
    let temporary = directory.join(format!(
        ".{file_name}.{}.{}.tmp",
        std::process::id(),
        TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let written = (|| {
        let mut file = crate::private_fs::create_new_file(&temporary)
            .map_err(|error| io_error("temporary write", &temporary, error))?;
        file.write_all(&bytes)
            .map_err(|error| io_error("temporary write", &temporary, error))?;
        file.sync_all()
            .map_err(|error| io_error("temporary sync", &temporary, error))?;
        drop(file);
        fs::rename(&temporary, path).map_err(|error| io_error("replace", path, error))?;
        sync_directory(&directory)
    })();
    if written.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    written
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), FloorError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("directory sync", path, error))
}

/// Directories cannot be opened for syncing on this platform; the rename is
/// the durable step there.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), FloorError> {
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, error: io::Error) -> FloorError {
    FloorError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALPHA: DurableFormat = DurableFormat::new("alpha", 3);
    const BETA: DurableFormat = DurableFormat::new("beta", 1);

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "cerebellum-format-floor-{label}-{}-{}",
                std::process::id(),
                DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir_all(&path).expect("scratch directory");
            Self(path)
        }

        fn floor_path(&self) -> PathBuf {
            self.0.join(FORMAT_FLOOR_FILE)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn a_raise_records_the_version_in_the_floor_file() {
        let scratch = Scratch::new("raise");
        FormatFloor::at(scratch.floor_path()).raise(ALPHA).unwrap();
        let floors = read_floors(&scratch.floor_path()).unwrap();
        assert_eq!(floors.get("alpha"), Some(&3));
        let document: serde_json::Value =
            serde_json::from_slice(&fs::read(scratch.floor_path()).unwrap()).unwrap();
        assert_eq!(document["version"], 1);
    }

    #[test]
    fn the_floor_is_never_lowered() {
        let scratch = Scratch::new("never-lowered");
        FormatFloor::at(scratch.floor_path()).raise(ALPHA).unwrap();
        // A fresh floor value, as an older build would hold after a restart,
        // raising the same format at a lower version.
        FormatFloor::at(scratch.floor_path())
            .raise(DurableFormat::new("alpha", 2))
            .unwrap();
        assert_eq!(
            read_floors(&scratch.floor_path()).unwrap().get("alpha"),
            Some(&3)
        );
    }

    #[test]
    fn the_floor_survives_a_restart_and_keeps_other_formats() {
        let scratch = Scratch::new("restart");
        FormatFloor::at(scratch.floor_path()).raise(ALPHA).unwrap();
        // Restart: a new value with no memory, raising a different format.
        FormatFloor::at(scratch.floor_path()).raise(BETA).unwrap();
        let floors = read_floors(&scratch.floor_path()).unwrap();
        assert_eq!(floors.get("alpha"), Some(&3));
        assert_eq!(floors.get("beta"), Some(&1));
    }

    #[test]
    fn a_raise_already_made_in_this_process_does_no_file_io() {
        let scratch = Scratch::new("hot-path");
        let floor = FormatFloor::at(scratch.floor_path());
        floor.raise(ALPHA).unwrap();
        // With the file gone, a raise that touched the disk would recreate
        // it. The second raise must not.
        fs::remove_file(scratch.floor_path()).unwrap();
        floor.raise(ALPHA).unwrap();
        floor.clone().raise(ALPHA).unwrap();
        assert!(!scratch.floor_path().exists());
    }

    #[test]
    fn concurrent_raises_of_different_formats_keep_both() {
        let scratch = Scratch::new("concurrent");
        let threads: Vec<_> = (0..8)
            .map(|index| {
                let path = scratch.floor_path();
                std::thread::spawn(move || {
                    let name: &'static str = Box::leak(format!("format-{index}").into_boxed_str());
                    FormatFloor::at(path)
                        .raise(DurableFormat::new(name, index + 1))
                        .unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }
        let floors = read_floors(&scratch.floor_path()).unwrap();
        for index in 0..8_u64 {
            assert_eq!(floors.get(&format!("format-{index}")), Some(&(index + 1)));
        }
    }

    #[test]
    fn a_floor_that_cannot_be_written_is_an_error() {
        let scratch = Scratch::new("unwritable");
        // The floor's directory is a file, so nothing can be created in it.
        let blocker = scratch.0.join("not-a-directory");
        fs::write(&blocker, b"file").unwrap();
        let error = FormatFloor::at(blocker.join(FORMAT_FLOOR_FILE))
            .raise(ALPHA)
            .unwrap_err();
        assert!(matches!(error, FloorError::Io { .. }), "{error:?}");
    }

    #[test]
    fn a_missing_floor_file_is_floor_zero() {
        let scratch = Scratch::new("missing");
        assert!(read_floors(&scratch.floor_path()).unwrap().is_empty());
    }

    #[test]
    fn a_newer_floor_file_is_refused_by_name() {
        let scratch = Scratch::new("newer-floor");
        fs::write(
            scratch.floor_path(),
            br#"{"version": 2, "floors": {}, "added_later": true}"#,
        )
        .unwrap();
        assert_eq!(
            read_floors(&scratch.floor_path()),
            Err(FloorError::NewerWriter {
                path: scratch.floor_path(),
                newer: NewerWriter {
                    format: "format-floor",
                    found: 2,
                    supported: 1,
                },
            })
        );
        // Raising a floor over a newer floor file refuses too, and leaves the
        // file exactly as found rather than rewriting it in the older shape.
        assert!(FormatFloor::at(scratch.floor_path()).raise(ALPHA).is_err());
        assert!(fs::read_to_string(scratch.floor_path())
            .unwrap()
            .contains("added_later"));
    }

    #[test]
    fn a_corrupt_floor_file_refuses_the_raise() {
        let scratch = Scratch::new("corrupt");
        fs::write(scratch.floor_path(), b"not json").unwrap();
        assert!(matches!(
            FormatFloor::at(scratch.floor_path()).raise(ALPHA),
            Err(FloorError::Corrupt { .. })
        ));
    }

    #[test]
    fn an_isolated_floor_touches_no_file() {
        let floor = FormatFloor::isolated();
        assert_eq!(floor.path(), None);
        floor.raise(ALPHA).unwrap();
    }

    #[test]
    fn each_data_tree_is_governed_by_the_floor_inside_it() {
        let scratch = Scratch::new("governing");
        let data_home = scratch.0.join("data");
        let module = module_directory(&data_home);

        for (store, tree) in [
            (module.join("journal").join("browser.json"), "journal"),
            (
                module.join("journal").join("computer_grants.json"),
                "journal",
            ),
            // The profile registry's root is the tree directory itself.
            (module.join("browser"), "browser"),
            (
                module.join("browser").join(".ck-browser-profile-custody"),
                "browser",
            ),
        ] {
            assert_eq!(
                FormatFloor::governing_under(&store, Some(&data_home)).path(),
                Some(floor_path(&data_home, tree).as_path()),
                "{}",
                store.display()
            );
        }
        assert_eq!(
            floor_path(&data_home, "journal"),
            module.join("journal").join(FORMAT_FLOOR_FILE)
        );

        for elsewhere in [
            scratch.0.join("fixture").join("browser.json"),
            // Under the module but in no data tree.
            module.join("x.json"),
            module.join("journal-other").join("x.json"),
            data_home.join("cortexkit").join("other").join("x.json"),
            PathBuf::from("relative").join("browser.json"),
        ] {
            assert_eq!(
                FormatFloor::governing_under(&elsewhere, Some(&data_home)).path(),
                None,
                "{}",
                elsewhere.display()
            );
        }
        assert_eq!(
            FormatFloor::governing_under(&module.join("journal").join("x.json"), None).path(),
            None
        );
        // Choosing which floor governs a path creates nothing on disk.
        assert!(!data_home.exists());
    }

    #[test]
    fn stores_governed_by_one_file_share_what_was_raised() {
        let scratch = Scratch::new("shared");
        let data_home = scratch.0.join("data");
        let journal = module_directory(&data_home).join("journal");
        let first = FormatFloor::governing_under(&journal.join("a.json"), Some(&data_home));
        first.raise(ALPHA).unwrap();
        fs::remove_file(journal.join(FORMAT_FLOOR_FILE)).unwrap();
        let second = FormatFloor::governing_under(&journal.join("b.json"), Some(&data_home));
        second.raise(ALPHA).unwrap();
        assert!(!journal.join(FORMAT_FLOOR_FILE).exists());
    }

    #[test]
    fn tag_versions_are_read_from_the_trailing_number() {
        assert_eq!(tag_version("ck-browser-profile-custody-lock/v2"), 2);
        assert_eq!(tag_version("x/v10"), 10);
        let lock = DurableFormat::new("lock", 2);
        let current = "ck-lock/v2";
        assert_eq!(
            lock.refuse_newer_tag("ck-lock/v3", current),
            Err(NewerWriter {
                format: "lock",
                found: 3,
                supported: 2,
            })
        );
        assert_eq!(lock.refuse_newer_tag("ck-lock/v1", current), Ok(()));
        assert_eq!(lock.refuse_newer_tag("ck-lock/v2", current), Ok(()));
        // Another family, or no number, is not a newer version of this one.
        assert_eq!(lock.refuse_newer_tag("ck-other/v9", current), Ok(()));
        assert_eq!(lock.refuse_newer_tag("ck-lock/v", current), Ok(()));
        assert!(lock
            .refuse_newer_tag("ck-lock/v99999999999999999999999", current)
            .is_err());
    }
}
