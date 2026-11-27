//! Bounded, trimmable authorization-refusal storage.
//!
//! Refusals live beside rather than inside the actuation journal: the journal's
//! transition chain remains untrimmable, while repeated denials rotate within
//! the caller that produced them.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::format_floor::{DurableFormat, FloorError, FormatFloor};
use crate::private_fs;

const REFUSAL_RING_SCHEMA_VERSION: u64 = 1;

/// The refusal ring's file format.
pub const REFUSAL_RING_FORMAT: DurableFormat =
    DurableFormat::new("refusal-ring", REFUSAL_RING_SCHEMA_VERSION);
static TEMPORARY_FILE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// The maximum number of detailed refusals retained independently for each caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusalRingConfig {
    pub records_per_caller: usize,
}

impl RefusalRingConfig {
    fn validate(self) -> Result<(), RefusalRingError> {
        if self.records_per_caller == 0 {
            return Err(RefusalRingError::InvalidCapacity);
        }
        Ok(())
    }
}

/// One refusal decision, without data obtained from the addressed target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalRecord<R> {
    /// The claimed address, reduced to its origin when it is URL-shaped. This
    /// must never be enriched with a page title, body, or other target data: letting an
    /// unauthorized attempt trigger a privileged read would make auditing itself
    /// an exfiltration path.
    pub claimed_addressing: String,
    pub reason: R,
}

/// The retained details and lifetime aggregate for one caller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerRefusalHistory<R> {
    /// Number of refusals observed, including details that have rotated out.
    pub total_count: u64,
    /// Number of detailed rows rotated out of this caller's ring.
    pub evicted_count: u64,
    /// Explicit truncation marker for readers that do not interpret counters.
    pub trimmed: bool,
    pub records: VecDeque<RefusalRecord<R>>,
}

impl<R> Default for CallerRefusalHistory<R> {
    fn default() -> Self {
        Self {
            total_count: 0,
            evicted_count: 0,
            trimmed: false,
            records: VecDeque::new(),
        }
    }
}

/// Serialized reader shape and durable state for a refusal ring.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefusalRingState<R> {
    pub schema_version: u64,
    pub records_per_caller: usize,
    pub callers: BTreeMap<String, CallerRefusalHistory<R>>,
}

impl<R> RefusalRingState<R> {
    fn fresh(config: RefusalRingConfig) -> Self {
        Self {
            schema_version: REFUSAL_RING_SCHEMA_VERSION,
            records_per_caller: config.records_per_caller,
            callers: BTreeMap::new(),
        }
    }

    fn validate(&self, config: RefusalRingConfig) -> Result<(), RefusalRingError> {
        if self.schema_version != REFUSAL_RING_SCHEMA_VERSION {
            return Err(RefusalRingError::UnsupportedSchemaVersion {
                found: self.schema_version,
                supported: REFUSAL_RING_SCHEMA_VERSION,
            });
        }
        if self.records_per_caller != config.records_per_caller {
            return Err(RefusalRingError::CapacityMismatch {
                configured: config.records_per_caller,
                stored: self.records_per_caller,
            });
        }
        for (caller, history) in &self.callers {
            let retained = history.records.len() as u64;
            if history.records.len() > config.records_per_caller
                || history.total_count != history.evicted_count.saturating_add(retained)
                || history.trimmed != (history.evicted_count > 0)
            {
                return Err(RefusalRingError::Corrupt(format!(
                    "invalid refusal accounting for caller {caller:?}"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum RefusalRingError {
    InvalidCapacity,
    CapacityMismatch {
        configured: usize,
        stored: usize,
    },
    /// The file names a schema version this build does not read. A version
    /// above `supported` was written by a newer build.
    UnsupportedSchemaVersion {
        found: u64,
        supported: u64,
    },
    Corrupt(String),
    /// The format floor could not be raised, so the ring was not written.
    FormatFloor(FloorError),
    Serialization(String),
    Io {
        operation: &'static str,
        path: PathBuf,
        kind: io::ErrorKind,
        message: String,
    },
}

impl std::fmt::Display for RefusalRingError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCapacity => formatter.write_str("refusal ring capacity must be positive"),
            Self::CapacityMismatch { configured, stored } => write!(
                formatter,
                "refusal ring capacity mismatch: configured {configured}, stored {stored}"
            ),
            Self::UnsupportedSchemaVersion { found, supported } if found > supported => write!(
                formatter,
                "newer_writer: the refusal ring is schema version {found}, written by a newer \
                 build; this build reads up to version {supported}"
            ),
            Self::UnsupportedSchemaVersion { found, .. } => {
                write!(formatter, "unsupported refusal ring schema version {found}")
            }
            Self::FormatFloor(error) => write!(formatter, "refusal ring not written: {error}"),
            Self::Corrupt(message) => write!(formatter, "corrupt refusal ring: {message}"),
            Self::Serialization(message) => {
                write!(formatter, "refusal ring serialization failed: {message}")
            }
            Self::Io {
                operation,
                path,
                message,
                ..
            } => write!(
                formatter,
                "refusal ring {operation} failed for {}: {message}",
                path.display()
            ),
        }
    }
}

impl std::error::Error for RefusalRingError {}

#[derive(Debug)]
enum RefusalPersistence {
    Memory,
    Filesystem { path: PathBuf, floor: FormatFloor },
}

/// A durable or isolated refusal store with an independent ring for each caller.
#[derive(Debug)]
pub struct RefusalRing<R> {
    config: RefusalRingConfig,
    persistence: RefusalPersistence,
    state: RefusalRingState<R>,
}

impl<R> RefusalRing<R>
where
    R: Clone + Serialize + DeserializeOwned,
{
    /// Open the durable refusal ring at an explicit operator-data path.
    pub fn new(
        path: impl Into<PathBuf>,
        config: RefusalRingConfig,
    ) -> Result<Self, RefusalRingError> {
        config.validate()?;
        let path = path.into();
        prepare_path(&path)?;
        let state = load_state(&path, config)?;
        let floor = FormatFloor::governing(&path);
        Ok(Self {
            config,
            persistence: RefusalPersistence::Filesystem { path, floor },
            state,
        })
    }

    /// Raise `floor` instead of the one chosen from the ring's location. An
    /// in-memory ring has no file and ignores it.
    pub fn with_format_floor(mut self, floor: FormatFloor) -> Self {
        if let RefusalPersistence::Filesystem { floor: current, .. } = &mut self.persistence {
            *current = floor;
        }
        self
    }

    /// Open an isolated ring that cannot touch durable operator data.
    pub fn new_in_memory(config: RefusalRingConfig) -> Result<Self, RefusalRingError> {
        config.validate()?;
        Ok(Self {
            config,
            persistence: RefusalPersistence::Memory,
            state: RefusalRingState::fresh(config),
        })
    }

    /// Record the module's own refusal decision under the responsible caller.
    pub fn record_refusal(
        &mut self,
        caller: impl Into<String>,
        claimed_addressing: impl Into<String>,
        reason: R,
    ) -> Result<(), RefusalRingError> {
        let caller = caller.into();
        let claimed_addressing = claimed_addressing.into();
        let claimed_addressing = if claimed_addressing.contains("://") {
            reduce_url_to_origin(&claimed_addressing)
        } else {
            claimed_addressing
        };
        let mut next = self.state.clone();
        let history = next.callers.entry(caller).or_default();
        history.total_count = history.total_count.saturating_add(1);
        history.records.push_back(RefusalRecord {
            claimed_addressing,
            reason,
        });
        if history.records.len() > self.config.records_per_caller {
            history.records.pop_front();
            history.evicted_count = history.evicted_count.saturating_add(1);
            history.trimmed = true;
        }
        self.persist(&next)?;
        self.state = next;
        Ok(())
    }

    pub fn history(&self, caller: &str) -> Option<&CallerRefusalHistory<R>> {
        self.state.callers.get(caller)
    }

    pub fn state(&self) -> &RefusalRingState<R> {
        &self.state
    }

    pub fn export_bytes(&self) -> Result<Vec<u8>, RefusalRingError> {
        serde_json::to_vec(&self.state)
            .map_err(|error| RefusalRingError::Serialization(error.to_string()))
    }

    fn persist(&self, state: &RefusalRingState<R>) -> Result<(), RefusalRingError> {
        let RefusalPersistence::Filesystem { path, floor } = &self.persistence else {
            return Ok(());
        };
        floor
            .raise(REFUSAL_RING_FORMAT)
            .map_err(RefusalRingError::FormatFloor)?;
        let bytes = serde_json::to_vec(state)
            .map_err(|error| RefusalRingError::Serialization(error.to_string()))?;
        write_atomically(path, &bytes)
    }
}

/// A durable address keeps only its HTTP(S) origin, never login material or a
/// private path. Other URL schemes have no retained web origin.
pub fn reduce_url_to_origin(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => return "null".to_string(),
    };
    if scheme != "http" && scheme != "https" {
        return "null".to_string();
    }
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority
        .rsplit_once('@')
        .map_or(authority, |(_, value)| value);
    if authority.is_empty() {
        return "null".to_string();
    }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let Some(close) = stripped.find(']') else {
            return "null".to_string();
        };
        (
            &authority[..close + 2],
            authority[close + 2..].strip_prefix(':'),
        )
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() {
        return "null".to_string();
    }
    let host = host.to_ascii_lowercase();
    let default_port = if scheme == "http" { "80" } else { "443" };
    match port {
        Some(port) if !port.is_empty() && port != default_port => {
            format!("{scheme}://{host}:{port}")
        }
        _ => format!("{scheme}://{host}"),
    }
}

fn prepare_path(path: &Path) -> Result<(), RefusalRingError> {
    let directory = parent_directory(path);
    private_fs::create_dir_all(&directory)
        .map_err(|error| io_error("create directory", &directory, error))?;
    let probe = sibling_path(path, "probe");
    let mut file = private_fs::create_new_file(&probe)
        .map_err(|error| io_error("probe write", &probe, error))?;
    file.write_all(b"refusal ring storage probe")
        .map_err(|error| io_error("probe write", &probe, error))?;
    file.sync_all()
        .map_err(|error| io_error("probe sync", &probe, error))?;
    drop(file);
    fs::remove_file(&probe).map_err(|error| io_error("probe cleanup", &probe, error))?;
    sync_directory(&directory)
}

fn load_state<R>(
    path: &Path,
    config: RefusalRingConfig,
) -> Result<RefusalRingState<R>, RefusalRingError>
where
    R: DeserializeOwned,
{
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(RefusalRingState::fresh(config));
        }
        Err(error) => return Err(io_error("read", path, error)),
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|error| RefusalRingError::Corrupt(error.to_string()))?;
    // The version is read before the rest: a newer build may add fields this
    // build's strict reader rejects, and that file must be refused as newer,
    // not as corrupt.
    let version = value
        .get("schema_version")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| {
            RefusalRingError::Corrupt(
                "schema_version is missing or is not an unsigned integer".to_string(),
            )
        })?;
    if version != REFUSAL_RING_SCHEMA_VERSION {
        return Err(RefusalRingError::UnsupportedSchemaVersion {
            found: version,
            supported: REFUSAL_RING_SCHEMA_VERSION,
        });
    }
    let state: RefusalRingState<R> = serde_json::from_value(value)
        .map_err(|error| RefusalRingError::Corrupt(error.to_string()))?;
    state.validate(config)?;
    Ok(state)
}

fn write_atomically(path: &Path, bytes: &[u8]) -> Result<(), RefusalRingError> {
    let directory = parent_directory(path);
    let temporary = sibling_path(path, "tmp");
    let mut file = private_fs::create_new_file(&temporary)
        .map_err(|error| io_error("temporary write", &temporary, error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("temporary write", &temporary, error))?;
    file.sync_all()
        .map_err(|error| io_error("temporary sync", &temporary, error))?;
    drop(file);
    fs::rename(&temporary, path).map_err(|error| io_error("replace", path, error))?;
    sync_directory(&directory)
}

fn parent_directory(path: &Path) -> PathBuf {
    path.parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn sibling_path(path: &Path, role: &str) -> PathBuf {
    let sequence = TEMPORARY_FILE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("refusals.json");
    path.with_file_name(format!(
        ".{name}.{role}.{}.{}",
        std::process::id(),
        sequence
    ))
}

#[cfg(not(windows))]
fn sync_directory(path: &Path) -> Result<(), RefusalRingError> {
    fs::File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("directory sync", path, error))
}

#[cfg(windows)]
fn sync_directory(_path: &Path) -> Result<(), RefusalRingError> {
    // Windows cannot flush a directory through std::fs::File. The ring
    // snapshot itself is flushed before rename.
    Ok(())
}

fn io_error(operation: &'static str, path: &Path, error: io::Error) -> RefusalRingError {
    RefusalRingError::Io {
        operation,
        path: path.to_path_buf(),
        kind: error.kind(),
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use serde::{Deserialize, Serialize};

    use super::{RefusalRing, RefusalRingConfig, RefusalRingError, REFUSAL_RING_SCHEMA_VERSION};
    use crate::format_floor::{read_floors, FloorError, FormatFloor};

    static DIRECTORY_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(rename_all = "snake_case")]
    enum Reason {
        NoGrant,
        OriginScope,
    }

    fn config(records_per_caller: usize) -> RefusalRingConfig {
        RefusalRingConfig { records_per_caller }
    }

    #[test]
    fn url_shaped_app_targets_never_persist_path_query_or_fragment_tokens() {
        const TOKEN: &str = "refused-app-url-token-278d";
        const ADDRESS: &str = "https://user:password@host.example:8443/refused-app-url-token-278d/Alfonso?code=refused-app-url-token-278d#refused-app-url-token-278d";
        let directory = temporary_directory();
        let path = directory.join("refusals.json");
        let mut ring = RefusalRing::new(&path, config(2)).unwrap();
        ring.record_refusal("caller", ADDRESS, Reason::OriginScope)
            .unwrap();
        ring.record_refusal("caller", "/Applications/Alfonso.app", Reason::OriginScope)
            .unwrap();
        let mut planted = ring.state().clone();
        planted.callers.get_mut("caller").unwrap().records[0].claimed_addressing = ADDRESS.into();
        assert!(
            String::from_utf8(serde_json::to_vec(&planted).unwrap())
                .unwrap()
                .contains(TOKEN),
            "the scanner must detect a URL token planted in a real refusal record"
        );
        let durable = fs::read_to_string(&path).unwrap();
        assert!(
            !durable.contains(TOKEN),
            "URL-shaped app address leaked into durable refusal record: {durable}"
        );
        assert!(!durable.contains("password"));
        let reopened = RefusalRing::<Reason>::new(&path, config(2)).unwrap();
        let records = &reopened.history("caller").unwrap().records;
        assert_eq!(records[0].claimed_addressing, "https://host.example:8443");
        assert_eq!(records[1].claimed_addressing, "/Applications/Alfonso.app");
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn one_callers_spam_evicts_only_its_own_rows() {
        let mut ring = RefusalRing::new_in_memory(config(2)).unwrap();
        ring.record_refusal(
            "quiet",
            "https://first.quiet.example/private",
            Reason::NoGrant,
        )
        .unwrap();
        ring.record_refusal(
            "noisy",
            "https://one.noisy.example/private",
            Reason::NoGrant,
        )
        .unwrap();
        ring.record_refusal(
            "quiet",
            "https://second.quiet.example/private",
            Reason::OriginScope,
        )
        .unwrap();
        ring.record_refusal(
            "noisy",
            "https://two.noisy.example/private",
            Reason::NoGrant,
        )
        .unwrap();
        ring.record_refusal(
            "noisy",
            "https://three.noisy.example/private",
            Reason::OriginScope,
        )
        .unwrap();

        let quiet = ring.history("quiet").unwrap();
        assert_eq!(quiet.records.len(), 2);
        assert_eq!(
            quiet.records[0].claimed_addressing,
            "https://first.quiet.example"
        );
        assert_eq!(
            quiet.records[1].claimed_addressing,
            "https://second.quiet.example"
        );
        assert_eq!(quiet.total_count, 2);
        assert!(!quiet.trimmed);

        let noisy = ring.history("noisy").unwrap();
        assert_eq!(noisy.records.len(), 2);
        assert_eq!(
            noisy.records[0].claimed_addressing,
            "https://two.noisy.example"
        );
        assert_eq!(
            noisy.records[1].claimed_addressing,
            "https://three.noisy.example"
        );
    }

    #[test]
    fn aggregate_and_trim_marker_survive_detail_eviction() {
        let mut ring = RefusalRing::new_in_memory(config(2)).unwrap();
        for address in ["one", "two", "three", "four"] {
            ring.record_refusal("caller", address, Reason::OriginScope)
                .unwrap();
        }

        let history = ring.history("caller").unwrap();
        assert_eq!(history.total_count, 4);
        assert_eq!(history.evicted_count, 2);
        assert!(history.trimmed);
        assert_eq!(history.records.len(), 2);
    }

    #[test]
    fn durable_constructor_reopens_counters_and_rows() {
        let directory = temporary_directory();
        let path = directory.join("refusals.json");
        {
            let mut ring = RefusalRing::new(&path, config(1)).unwrap();
            ring.record_refusal("caller", "first", Reason::NoGrant)
                .unwrap();
            ring.record_refusal("caller", "second", Reason::OriginScope)
                .unwrap();
        }

        let ring = RefusalRing::<Reason>::new(&path, config(1)).unwrap();
        let history = ring.history("caller").unwrap();
        assert_eq!(history.total_count, 2);
        assert_eq!(history.evicted_count, 1);
        assert!(history.trimmed);
        assert_eq!(history.records[0].claimed_addressing, "second");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn refusal_record_cost_is_stable_and_smaller_than_an_actuation_entry() {
        fn measured_cost() -> usize {
            let mut ring = RefusalRing::new_in_memory(config(8)).unwrap();
            let before = ring.export_bytes().unwrap().len();
            ring.record_refusal(
                "agent-project",
                "https://claimed.example/path",
                Reason::OriginScope,
            )
            .unwrap();
            ring.export_bytes().unwrap().len() - before
        }

        let first = measured_cost();
        let second = measured_cost();
        assert_eq!(first, second, "identical samples must have identical cost");
        assert!(
            first < 730,
            "a {first}-byte refusal row is not smaller than the measured actuation entry"
        );
    }

    #[test]
    fn a_ring_from_the_next_version_is_refused_by_name_not_as_corrupt() {
        let directory = temporary_directory();
        let path = directory.join("refusals.json");
        // Carries a field this build's strict reader rejects, so a reader that
        // parsed before reading the version would call it corrupt.
        let newer = serde_json::json!({
            "schema_version": REFUSAL_RING_SCHEMA_VERSION + 1,
            "records_per_caller": 1,
            "callers": {},
            "a_field_this_build_does_not_know": true,
        });
        fs::write(&path, serde_json::to_vec(&newer).unwrap()).unwrap();

        let error = RefusalRing::<Reason>::new(&path, config(1)).unwrap_err();
        assert!(
            matches!(
                error,
                RefusalRingError::UnsupportedSchemaVersion { found, supported }
                    if found == REFUSAL_RING_SCHEMA_VERSION + 1
                        && supported == REFUSAL_RING_SCHEMA_VERSION
            ),
            "{error:?}"
        );
        assert!(error.to_string().starts_with("newer_writer:"), "{error}");

        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_record_raises_the_format_floor_before_writing() {
        let directory = temporary_directory();
        let path = directory.join("refusals.json");
        let floor_path = directory.join("format-floor.json");
        let mut ring = RefusalRing::new(&path, config(1))
            .unwrap()
            .with_format_floor(FormatFloor::at(&floor_path));
        ring.record_refusal("caller", "first", Reason::NoGrant)
            .unwrap();

        assert_eq!(
            read_floors(&floor_path).unwrap().get("refusal-ring"),
            Some(&REFUSAL_RING_SCHEMA_VERSION)
        );
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn a_floor_that_cannot_be_raised_refuses_the_record_and_writes_nothing() {
        let directory = temporary_directory();
        let path = directory.join("refusals.json");
        let blocker = directory.join("not-a-directory");
        fs::write(&blocker, b"file").unwrap();
        let mut ring = RefusalRing::new(&path, config(1))
            .unwrap()
            .with_format_floor(FormatFloor::at(blocker.join("format-floor.json")));

        let error = ring
            .record_refusal("caller", "first", Reason::NoGrant)
            .unwrap_err();
        assert!(
            matches!(error, RefusalRingError::FormatFloor(FloorError::Io { .. })),
            "{error:?}"
        );
        assert!(!path.exists(), "the ring was written without a floor");
        assert!(ring.history("caller").is_none());
        fs::remove_dir_all(directory).unwrap();
    }

    fn temporary_directory() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "cerebellum-refusal-ring-{}-{}",
            std::process::id(),
            DIRECTORY_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(&path).unwrap();
        path
    }
}
