use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const LOCK_DIRECTORY: &str = ".ck-browser-profile-custody";
const COORDINATION_FILE: &str = ".coordination.lock";
const JOURNAL_FILE: &str = "custody-events.jsonl";
const LOCK_FORMAT_VERSION: &str = "ck-browser-profile-custody-lock/v1";
const JOURNAL_FORMAT_VERSION: &str = "ck-browser-profile-custody-event/v1";

static IN_PROCESS_COORDINATION: OnceLock<Mutex<()>> = OnceLock::new();

/// The opaque identity of one launch attempt's profile claim.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HolderId(String);

impl HolderId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for HolderId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("HolderId").field(&self.0).finish()
    }
}

/// A process generation, rather than a pid alone, identifies the supervisor that
/// remains capable of owning a claim after pid reuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorGeneration {
    pub pid: u32,
    pub start_time: u64,
}

/// The logical profile selected before preparation. Callers cannot supply the
/// filename used for the lock artifact.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ProfileCustodyKey(String);

impl ProfileCustodyKey {
    pub fn durable(project_id: &str) -> Self {
        Self(format!("durable\0{project_id}"))
    }

    /// Disposable launches mint a new directory even when their route selector
    /// agrees, so their claim key includes the already-minted attempt holder.
    pub fn disposable(project_id: &str, conversation_key: &str, holder: &HolderId) -> Self {
        Self::disposable_route(project_id, conversation_key, holder.as_str())
    }

    pub fn disposable_route(project_id: &str, conversation_key: &str, attempt_id: &str) -> Self {
        Self(format!(
            "disposable\0{project_id}\0{conversation_key}\0{attempt_id}"
        ))
    }

    fn filename(&self) -> String {
        let digest = Sha256::digest(self.0.as_bytes());
        format!("{}.lock", hex(&digest))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCustodyLockRecord {
    format_version: String,
    holder_id: HolderId,
    supervisor_pid: u32,
    supervisor_start_time: u64,
    profile_directory: Option<PathBuf>,
}

impl ProfileCustodyLockRecord {
    fn new(holder_id: HolderId, supervisor: SupervisorGeneration) -> Self {
        Self {
            format_version: LOCK_FORMAT_VERSION.to_string(),
            holder_id,
            supervisor_pid: supervisor.pid,
            supervisor_start_time: supervisor.start_time,
            profile_directory: None,
        }
    }

    pub fn supervisor(&self) -> SupervisorGeneration {
        SupervisorGeneration {
            pid: self.supervisor_pid,
            start_time: self.supervisor_start_time,
        }
    }
}

/// Evidence returned by a generation-aware process observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SupervisorLiveness {
    Live,
    NotLive,
    Unavailable,
}

pub trait SupervisorLivenessProbe {
    fn observe(&self, generation: SupervisorGeneration) -> SupervisorLiveness;

    /// Test and platform probes may pause after stale evidence is durable. The
    /// acquisition algorithm must remain correct when several contenders reach
    /// this point before any of them mutates the lock.
    fn stale_evidence_recorded(&self) {}
}

/// Whether a platform's start-time reading survives a wall-clock step.
///
/// It decides what a live pid with a DIFFERENT start time means. macOS stores
/// the start time in the kernel at creation, so a difference can only be PID
/// reuse. Linux has no stored start time: the reading is `btime` plus ticks
/// since boot, and the kernel recomputes `btime` as realtime minus monotonic
/// on every read, so stepping the clock moves the start time of a process that
/// never changed. There a difference is either reuse or a clock step, and the
/// reading cannot tell which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StartTimeStability {
    /// Recorded at creation and never recomputed.
    ClockStable,
    /// Derived from the current wall clock on every read.
    MovesWithWallClock,
}

/// Compare the recorded generation to a kernel-observed start time.
///
/// Absence means no process holds the pid, so the holder is gone. A different
/// start time is reuse where the reading is clock-stable, and AMBIGUOUS where
/// it is not -- and ambiguity must not break the lock, because `NotLive` is not
/// a refusal but the authority to seize: a clock step would hand a live
/// holder's profile to a second process, and the journal would record it as a
/// legitimate stale break. The cost of `Unavailable` is that a genuinely
/// reused pid holds the profile until the reusing process exits, and that
/// refusal names its reason where a seizure would not.
pub fn classify_supervisor_start_time(
    recorded: SupervisorGeneration,
    observed_start_time: Option<u64>,
    stability: StartTimeStability,
) -> SupervisorLiveness {
    match observed_start_time {
        Some(start_time) if start_time == recorded.start_time => SupervisorLiveness::Live,
        Some(_) => match stability {
            StartTimeStability::ClockStable => SupervisorLiveness::NotLive,
            StartTimeStability::MovesWithWallClock => SupervisorLiveness::Unavailable,
        },
        None => SupervisorLiveness::NotLive,
    }
}

/// Production generation checks use the kernel start time and therefore reject a
/// recycled pid whose current process started at a different time.
#[derive(Debug, Clone, Copy, Default)]
pub struct KernelSupervisorLiveness;

impl SupervisorLivenessProbe for KernelSupervisorLiveness {
    fn observe(&self, generation: SupervisorGeneration) -> SupervisorLiveness {
        #[cfg(target_os = "macos")]
        {
            match cerebellum_macos::process_start_time(generation.pid) {
                cerebellum_macos::ProcessStartTime::Started(start_time) => {
                    classify_supervisor_start_time(
                        generation,
                        Some(start_time),
                        StartTimeStability::ClockStable,
                    )
                }
                cerebellum_macos::ProcessStartTime::NoSuchProcess => {
                    classify_supervisor_start_time(
                        generation,
                        None,
                        StartTimeStability::ClockStable,
                    )
                }
                cerebellum_macos::ProcessStartTime::NotPermitted
                | cerebellum_macos::ProcessStartTime::LayoutMismatch
                | cerebellum_macos::ProcessStartTime::Unclassified(_)
                | cerebellum_macos::ProcessStartTime::NoStartTime => {
                    SupervisorLiveness::Unavailable
                }
            }
        }

        // Linux records a supervisor's start time (see
        // `current_supervisor_generation`) and must read it back the same way,
        // or every lock a crashed supervisor leaves behind answers
        // `Unavailable` forever and wedges that profile. The reading moves with
        // the wall clock, so a mismatch stays ambiguous rather than stale.
        #[cfg(target_os = "linux")]
        {
            match cerebellum_linux::process_start_time(generation.pid) {
                cerebellum_linux::ProcessStartTime::Started(start_time) => {
                    classify_supervisor_start_time(
                        generation,
                        Some(start_time),
                        StartTimeStability::MovesWithWallClock,
                    )
                }
                cerebellum_linux::ProcessStartTime::NoSuchProcess => {
                    classify_supervisor_start_time(
                        generation,
                        None,
                        StartTimeStability::MovesWithWallClock,
                    )
                }
                cerebellum_linux::ProcessStartTime::NotPermitted
                | cerebellum_linux::ProcessStartTime::StatReadFailed
                | cerebellum_linux::ProcessStartTime::SystemTimeBaseUnavailable
                | cerebellum_linux::ProcessStartTime::LayoutMismatch
                | cerebellum_linux::ProcessStartTime::NoStartTime => {
                    SupervisorLiveness::Unavailable
                }
            }
        }

        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = generation;
            SupervisorLiveness::Unavailable
        }
    }
}

pub fn current_supervisor_generation() -> Result<SupervisorGeneration, ProfileCustodyLockError> {
    let pid = std::process::id();
    #[cfg(target_os = "macos")]
    {
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(start_time) => {
                Ok(SupervisorGeneration { pid, start_time })
            }
            _ => Err(ProfileCustodyLockError::SupervisorGenerationUnavailable),
        }
    }

    // Linux reads the same fact from procfs, in the same shape the macOS arm
    // consumes. It shipped with the Linux launch barrier and nothing called it,
    // so custody refused here and the refusal surfaced as unavailable storage
    // several layers up.
    #[cfg(target_os = "linux")]
    {
        match cerebellum_linux::process_start_time(pid) {
            cerebellum_linux::ProcessStartTime::Started(start_time) => {
                Ok(SupervisorGeneration { pid, start_time })
            }
            _ => Err(ProfileCustodyLockError::SupervisorGenerationUnavailable),
        }
    }

    // A platform with no start-time reading cannot distinguish this supervisor
    // from a later process that inherited its PID, and custody depends on that
    // distinction. Refusing is correct here; it is only wrong when a reading
    // exists and goes uncalled.
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = pid;
        Err(ProfileCustodyLockError::SupervisorGenerationUnavailable)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProfileCustodyEventKind {
    HolderAcquire,
    StaleBreak,
    ProfileDirectoryBind,
    RollbackTerminalization,
    HolderRelease,
    DisposableDelete,
}

/// The journal carries the evidence needed to diagnose custody mutation. It does
/// not carry a profile UUID because that identity is not part of lock custody.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileCustodyEvent {
    pub format_version: String,
    pub kind: ProfileCustodyEventKind,
    pub holder_id: HolderId,
    pub supervisor: SupervisorGeneration,
    pub profile_directory: Option<PathBuf>,
    pub evidence: Option<String>,
}

impl ProfileCustodyEvent {
    fn new(
        kind: ProfileCustodyEventKind,
        record: &ProfileCustodyLockRecord,
        evidence: Option<String>,
    ) -> Self {
        Self {
            format_version: JOURNAL_FORMAT_VERSION.to_string(),
            kind,
            holder_id: record.holder_id.clone(),
            supervisor: record.supervisor(),
            profile_directory: record.profile_directory.clone(),
            evidence,
        }
    }
}

pub trait ProfileCustodyJournal {
    fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()>;
}

/// An append-only filesystem journal. Each acknowledged event is flushed before
/// the guarded filesystem mutation begins.
pub struct FilesystemProfileCustodyJournal {
    file: File,
}

impl FilesystemProfileCustodyJournal {
    pub fn open(root: impl AsRef<Path>) -> io::Result<Self> {
        fs::create_dir_all(root.as_ref())?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(root.as_ref().join(JOURNAL_FILE))?;
        Ok(Self { file })
    }
}

impl ProfileCustodyJournal for FilesystemProfileCustodyJournal {
    /// Append one event as one `write` of the whole line.
    ///
    /// Several supervisors can hold this file open at once: custody exists to
    /// arbitrate between them, and a draining process overlaps its successor.
    /// `serde_json::to_writer` on an unbuffered `File` issues a write per
    /// fragment (brace, key, separator), and appenders interleave BETWEEN
    /// writes, so two events recorded together tear each other mid-line. A
    /// line-per-event reader then drops both, and a stale break reads as one
    /// that never happened. `O_APPEND` places a single line-sized write whole,
    /// so composing the line first confines interleaving to line boundaries.
    fn record(&mut self, event: &ProfileCustodyEvent) -> io::Result<()> {
        let mut line = serde_json::to_vec(event).map_err(io::Error::other)?;
        line.push(b'\n');
        self.file.write_all(&line)?;
        self.file.sync_all()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileCustodyClaim {
    key: ProfileCustodyKey,
    holder_id: HolderId,
    supervisor: SupervisorGeneration,
    profile_directory: Option<PathBuf>,
}

impl ProfileCustodyClaim {
    pub fn holder_id(&self) -> &HolderId {
        &self.holder_id
    }

    pub fn profile_directory(&self) -> Option<&Path> {
        self.profile_directory.as_deref()
    }

    pub fn with_holder_for_test(&self, holder_id: HolderId) -> Self {
        Self {
            holder_id,
            ..self.clone()
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileCustodyAcquisition {
    Acquired(ProfileCustodyClaim),
    ProfileBusy { holder_id: HolderId },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProfileCustodyRelease {
    Released,
    HolderMismatch { installed_holder_id: HolderId },
    Missing,
}

#[derive(Debug)]
pub enum ProfileCustodyLockError {
    Io(io::Error),
    InvalidRecord,
    SupervisorGenerationUnavailable,
    SupervisorLivenessUnavailable,
    Journal(io::Error),
    HolderMismatch,
    DirectoryMismatch,
}

impl From<io::Error> for ProfileCustodyLockError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

/// Filesystem-backed profile claims. A process-wide mutex and a filesystem lock
/// serialize the stale-check/remove/install transaction for threads and module
/// processes respectively.
pub struct ProfileCustodyLocks<J, P> {
    root: PathBuf,
    supervisor: SupervisorGeneration,
    journal: J,
    liveness: P,
}

impl<J, P> ProfileCustodyLocks<J, P>
where
    J: ProfileCustodyJournal,
    P: SupervisorLivenessProbe,
{
    pub fn open(
        managed_root: impl AsRef<Path>,
        supervisor: SupervisorGeneration,
        journal: J,
        liveness: P,
    ) -> Result<Self, ProfileCustodyLockError> {
        let root = managed_root.as_ref().join(LOCK_DIRECTORY);
        fs::create_dir_all(&root)?;
        let coordination_path = root.join(COORDINATION_FILE);
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(coordination_path)?;
        Ok(Self {
            root,
            supervisor,
            journal,
            liveness,
        })
    }

    pub fn mint_holder(&self) -> Result<HolderId, ProfileCustodyLockError> {
        let mut entropy = [0_u8; 32];
        File::open("/dev/urandom")?.read_exact(&mut entropy)?;
        Ok(HolderId(format!("holder-{}", hex(&entropy))))
    }

    pub fn acquire(
        &mut self,
        key: ProfileCustodyKey,
        holder_id: HolderId,
    ) -> Result<ProfileCustodyAcquisition, ProfileCustodyLockError> {
        let lock_path = self.root.join(key.filename());
        let stale = if let Some(installed) = read_record_if_present(&lock_path)? {
            match self.liveness.observe(installed.supervisor()) {
                SupervisorLiveness::Live => {
                    return Ok(ProfileCustodyAcquisition::ProfileBusy {
                        holder_id: installed.holder_id,
                    });
                }
                SupervisorLiveness::Unavailable => {
                    return Err(ProfileCustodyLockError::SupervisorLivenessUnavailable);
                }
                SupervisorLiveness::NotLive => {
                    let event = ProfileCustodyEvent::new(
                        ProfileCustodyEventKind::StaleBreak,
                        &installed,
                        Some("recorded_supervisor_generation_not_live".to_string()),
                    );
                    self.journal
                        .record(&event)
                        .map_err(ProfileCustodyLockError::Journal)?;
                    self.liveness.stale_evidence_recorded();
                    Some(installed)
                }
            }
        } else {
            None
        };

        let _process_guard = IN_PROCESS_COORDINATION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| io::Error::other("profile-custody mutex poisoned"))?;
        let coordination = self.lock_coordination_file()?;
        let current = read_record_if_present(&lock_path)?;
        let break_current = match (stale.as_ref(), current) {
            (Some(proved_stale), Some(current)) if &current == proved_stale => Some(current),
            (Some(_), Some(winner)) | (None, Some(winner)) => {
                drop(coordination);
                return Ok(ProfileCustodyAcquisition::ProfileBusy {
                    holder_id: winner.holder_id,
                });
            }
            (Some(_), None) | (None, None) => None,
        };

        let record = ProfileCustodyLockRecord::new(holder_id.clone(), self.supervisor);
        self.journal
            .record(&ProfileCustodyEvent::new(
                ProfileCustodyEventKind::HolderAcquire,
                &record,
                None,
            ))
            .map_err(ProfileCustodyLockError::Journal)?;
        if break_current.is_some() {
            fs::remove_file(&lock_path)?;
            sync_directory(&self.root)?;
        }
        match install_record(&self.root, &lock_path, &record) {
            Ok(()) => {
                drop(coordination);
                Ok(ProfileCustodyAcquisition::Acquired(ProfileCustodyClaim {
                    key,
                    holder_id,
                    supervisor: self.supervisor,
                    profile_directory: None,
                }))
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let winner = read_record(&lock_path)?;
                drop(coordination);
                Ok(ProfileCustodyAcquisition::ProfileBusy {
                    holder_id: winner.holder_id,
                })
            }
            Err(error) => Err(ProfileCustodyLockError::Io(error)),
        }
    }

    pub fn bind_profile_directory(
        &mut self,
        claim: &mut ProfileCustodyClaim,
        directory: &Path,
    ) -> Result<(), ProfileCustodyLockError> {
        let canonical = fs::canonicalize(directory)?;
        let _process_guard = IN_PROCESS_COORDINATION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| io::Error::other("profile-custody mutex poisoned"))?;
        let _coordination = self.lock_coordination_file()?;
        let path = self.root.join(claim.key.filename());
        let mut installed = read_record(&path)?;
        require_exact_holder(&installed, claim)?;
        if let Some(existing) = installed.profile_directory.as_ref() {
            if existing == &canonical {
                claim.profile_directory = Some(canonical);
                return Ok(());
            }
            return Err(ProfileCustodyLockError::DirectoryMismatch);
        }
        installed.profile_directory = Some(canonical.clone());
        let event = ProfileCustodyEvent::new(
            ProfileCustodyEventKind::ProfileDirectoryBind,
            &installed,
            None,
        );
        self.journal
            .record(&event)
            .map_err(ProfileCustodyLockError::Journal)?;
        replace_record(&self.root, &path, &installed)?;
        claim.profile_directory = Some(canonical);
        Ok(())
    }

    pub fn verify_exact_holder(
        &self,
        claim: &ProfileCustodyClaim,
    ) -> Result<(), ProfileCustodyLockError> {
        let _process_guard = IN_PROCESS_COORDINATION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| io::Error::other("profile-custody mutex poisoned"))?;
        let _coordination = self.lock_coordination_file()?;
        let installed = read_record(&self.root.join(claim.key.filename()))?;
        require_exact_holder(&installed, claim)?;
        if installed.profile_directory != claim.profile_directory {
            return Err(ProfileCustodyLockError::DirectoryMismatch);
        }
        Ok(())
    }

    pub fn record_rollback_terminalization(
        &mut self,
        claim: &ProfileCustodyClaim,
    ) -> Result<(), ProfileCustodyLockError> {
        self.record_for_exact_holder(claim, ProfileCustodyEventKind::RollbackTerminalization)
    }

    pub fn record_disposable_delete(
        &mut self,
        claim: &ProfileCustodyClaim,
    ) -> Result<(), ProfileCustodyLockError> {
        self.record_for_exact_holder(claim, ProfileCustodyEventKind::DisposableDelete)
    }

    pub fn release_exact(
        &mut self,
        claim: &ProfileCustodyClaim,
    ) -> Result<ProfileCustodyRelease, ProfileCustodyLockError> {
        let _process_guard = IN_PROCESS_COORDINATION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| io::Error::other("profile-custody mutex poisoned"))?;
        let _coordination = self.lock_coordination_file()?;
        let path = self.root.join(claim.key.filename());
        let Some(installed) = read_record_if_present(&path)? else {
            return Ok(ProfileCustodyRelease::Missing);
        };
        if installed.holder_id != claim.holder_id {
            return Ok(ProfileCustodyRelease::HolderMismatch {
                installed_holder_id: installed.holder_id,
            });
        }
        if installed.supervisor() != claim.supervisor
            || installed.profile_directory != claim.profile_directory
        {
            return Err(ProfileCustodyLockError::HolderMismatch);
        }
        self.journal
            .record(&ProfileCustodyEvent::new(
                ProfileCustodyEventKind::HolderRelease,
                &installed,
                None,
            ))
            .map_err(ProfileCustodyLockError::Journal)?;
        fs::remove_file(path)?;
        sync_directory(&self.root)?;
        Ok(ProfileCustodyRelease::Released)
    }

    fn record_for_exact_holder(
        &mut self,
        claim: &ProfileCustodyClaim,
        kind: ProfileCustodyEventKind,
    ) -> Result<(), ProfileCustodyLockError> {
        let _process_guard = IN_PROCESS_COORDINATION
            .get_or_init(|| Mutex::new(()))
            .lock()
            .map_err(|_| io::Error::other("profile-custody mutex poisoned"))?;
        let _coordination = self.lock_coordination_file()?;
        let installed = read_record(&self.root.join(claim.key.filename()))?;
        require_exact_holder(&installed, claim)?;
        if installed.profile_directory != claim.profile_directory {
            return Err(ProfileCustodyLockError::DirectoryMismatch);
        }
        let event = ProfileCustodyEvent::new(kind, &installed, None);
        self.journal
            .record(&event)
            .map_err(ProfileCustodyLockError::Journal)
    }

    fn lock_coordination_file(&self) -> Result<File, ProfileCustodyLockError> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(self.root.join(COORDINATION_FILE))?;
        file.lock()?;
        Ok(file)
    }
}

impl ProfileCustodyLocks<FilesystemProfileCustodyJournal, KernelSupervisorLiveness> {
    pub fn open_filesystem(
        managed_root: impl AsRef<Path>,
    ) -> Result<Self, ProfileCustodyLockError> {
        let supervisor = current_supervisor_generation()?;
        let journal_root = managed_root.as_ref().join(LOCK_DIRECTORY);
        let journal = FilesystemProfileCustodyJournal::open(&journal_root)?;
        Self::open(managed_root, supervisor, journal, KernelSupervisorLiveness)
    }
}

fn require_exact_holder(
    installed: &ProfileCustodyLockRecord,
    claim: &ProfileCustodyClaim,
) -> Result<(), ProfileCustodyLockError> {
    if installed.holder_id != claim.holder_id || installed.supervisor() != claim.supervisor {
        return Err(ProfileCustodyLockError::HolderMismatch);
    }
    Ok(())
}

pub fn read_record_if_present(
    path: &Path,
) -> Result<Option<ProfileCustodyLockRecord>, ProfileCustodyLockError> {
    match fs::read(path) {
        Ok(bytes) => decode_record(&bytes).map(Some),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(ProfileCustodyLockError::Io(error)),
    }
}

fn read_record(path: &Path) -> Result<ProfileCustodyLockRecord, ProfileCustodyLockError> {
    let bytes = fs::read(path)?;
    decode_record(&bytes)
}

fn decode_record(bytes: &[u8]) -> Result<ProfileCustodyLockRecord, ProfileCustodyLockError> {
    let record: ProfileCustodyLockRecord =
        serde_json::from_slice(bytes).map_err(|_| ProfileCustodyLockError::InvalidRecord)?;
    if record.format_version != LOCK_FORMAT_VERSION
        || record.holder_id.as_str().is_empty()
        || record.supervisor_pid == 0
        || record.supervisor_start_time == 0
    {
        return Err(ProfileCustodyLockError::InvalidRecord);
    }
    Ok(record)
}

fn install_record(
    root: &Path,
    destination: &Path,
    record: &ProfileCustodyLockRecord,
) -> io::Result<()> {
    let temporary = root.join(format!(".install-{}.tmp", record.holder_id.as_str()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)?;
        serde_json::to_writer(&mut file, record).map_err(io::Error::other)?;
        file.sync_all()?;
        fs::hard_link(&temporary, destination)?;
        sync_directory(root)
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn replace_record(
    root: &Path,
    destination: &Path,
    record: &ProfileCustodyLockRecord,
) -> io::Result<()> {
    let temporary = root.join(format!(".replace-{}.tmp", record.holder_id.as_str()));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .open(&temporary)?;
    serde_json::to_writer(&mut file, record).map_err(io::Error::other)?;
    file.sync_all()?;
    fs::rename(&temporary, destination)?;
    sync_directory(root)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

fn hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod journal_tests {
    use super::*;

    /// Concurrent supervisors appending to one custody log lose no event.
    ///
    /// Each thread opens its OWN handle, the way two supervisor processes do,
    /// and records events carrying a long evidence string so a fragment-wise
    /// writer spans many writes per line. Every complete line must parse and
    /// every event must be present: a torn pair of lines is dropped by any
    /// per-line reader and reads as events that never happened.
    #[test]
    fn concurrent_appenders_lose_no_custody_event() {
        let root = std::env::temp_dir().join(format!(
            "ck-custody-journal-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        const WRITERS: u32 = 8;
        const EVENTS: u32 = 200;
        let handles: Vec<_> = (0..WRITERS)
            .map(|writer| {
                let root = root.clone();
                std::thread::spawn(move || {
                    let mut journal = FilesystemProfileCustodyJournal::open(&root).unwrap();
                    for event in 0..EVENTS {
                        journal
                            .record(&ProfileCustodyEvent {
                                format_version: JOURNAL_FORMAT_VERSION.to_string(),
                                kind: ProfileCustodyEventKind::StaleBreak,
                                holder_id: HolderId(format!("holder-{writer}-{event}")),
                                supervisor: SupervisorGeneration {
                                    pid: writer,
                                    start_time: u64::from(event),
                                },
                                profile_directory: Some(PathBuf::from(format!(
                                    "profiles/{writer}/{event}"
                                ))),
                                evidence: Some("recorded_supervisor_generation_not_live".repeat(8)),
                            })
                            .unwrap();
                    }
                })
            })
            .collect();
        for handle in handles {
            handle.join().unwrap();
        }

        let text = fs::read_to_string(root.join(JOURNAL_FILE)).unwrap();
        let _ = fs::remove_dir_all(&root);
        let lines: Vec<&str> = text.lines().collect();
        let parsed = lines
            .iter()
            .filter(|line| serde_json::from_str::<ProfileCustodyEvent>(line).is_ok())
            .count();
        assert_eq!(
            lines.len(),
            (WRITERS * EVENTS) as usize,
            "one line per event"
        );
        assert_eq!(
            parsed,
            lines.len(),
            "{} of {} custody lines were torn by a concurrent appender",
            lines.len() - parsed,
            lines.len()
        );
    }
}
