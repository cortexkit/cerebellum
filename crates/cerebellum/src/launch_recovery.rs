//! Clearing a launch record that startup recovery could not settle.
//!
//! When startup recovery cannot prove that a browser from before the module
//! restarted is gone, it keeps that launch record active and holds the
//! profile's custody itself, so no second browser opens the same profile. For
//! one of the reasons (a dispatched record with no attestation this module
//! trusts) nothing a later start does can change the answer, so the profile
//! would stay refused forever. This module is the way out: an operator asks,
//! the module reads two independent pieces of evidence that no browser uses the
//! profile directory, a person consents, and only then is the record consumed
//! and the custody released.
//!
//! The pieces here are platform-neutral so the management surface compiles
//! everywhere: the registry the management plane consults, the typed preview,
//! refusals and evidence, and the readers of that evidence. The launch service
//! implements [`LaunchRecoveryClearer`] on the platforms that launch browsers.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{json, Value};

use crate::browser_launch::RecoveryPendingReason;

/// What an operator is asked to clear, read at request time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClearPreview {
    pub agent_project_id: String,
    /// The launch journal sequence of the record recovery kept active.
    pub sequence: u64,
    pub reason: RecoveryPendingReason,
    /// When the recorded browser started, when the record says so.
    pub launched_at: Option<String>,
    pub evidence: ProfileEvidence,
}

/// Two independent readings of whether any browser uses a profile directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProfileEvidence {
    pub processes: ProcessReading,
    pub singleton_lock: SingletonLockReading,
}

/// Whether a running process names the profile directory in its arguments.
///
/// Every Chrome process, helpers included, carries `--user-data-dir=<dir>`,
/// and it is how this module launches one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessReading {
    /// Every process of this user was read and none names the directory.
    NoneNamesDirectory { examined: usize },
    /// This process names the directory.
    NamedBy { pid: u32 },
    /// The process table, or one of this user's processes, could not be read.
    /// Never read as "none found".
    Unreadable,
}

/// What Chrome's own lock in the profile directory says.
///
/// Chrome keeps `SingletonLock` in its user-data directory while it runs: a
/// symbolic link whose target is `<host>-<pid>`. A browser that exited cleanly
/// removes it; one that crashed leaves it naming a pid that is gone or reused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SingletonLockReading {
    Absent,
    /// The lock names a pid no process holds now.
    PidNotAlive {
        pid: u32,
    },
    /// The lock names a live process that is not a Chrome executable, so the
    /// pid was reused after the browser that wrote it exited.
    PidNotABrowser {
        pid: u32,
    },
    /// The lock names a live Chrome process.
    LiveBrowser {
        pid: u32,
    },
    /// The lock was written on another host, so its pid cannot be checked here.
    OtherHost,
    /// The lock exists but could not be read or parsed.
    Unreadable,
}

impl ProfileEvidence {
    /// Both readings must say no browser uses the directory; anything unread
    /// refuses.
    pub fn permits_clear(&self) -> Result<(), ClearRefusal> {
        match self.processes {
            ProcessReading::NoneNamesDirectory { .. } => {}
            ProcessReading::NamedBy { pid } => return Err(ClearRefusal::ProfileInUse { pid }),
            ProcessReading::Unreadable => return Err(ClearRefusal::ProcessTableUnreadable),
        }
        match self.singleton_lock {
            SingletonLockReading::Absent
            | SingletonLockReading::PidNotAlive { .. }
            | SingletonLockReading::PidNotABrowser { .. } => Ok(()),
            SingletonLockReading::LiveBrowser { pid } => {
                Err(ClearRefusal::SingletonLockHeld { pid })
            }
            SingletonLockReading::OtherHost => Err(ClearRefusal::SingletonLockOtherHost),
            SingletonLockReading::Unreadable => Err(ClearRefusal::SingletonLockUnreadable),
        }
    }

    pub fn as_json(&self) -> Value {
        let processes = match self.processes {
            ProcessReading::NoneNamesDirectory { examined } => {
                json!({"reading": "none_names_profile", "examined": examined})
            }
            ProcessReading::NamedBy { pid } => json!({"reading": "named_by", "pid": pid}),
            ProcessReading::Unreadable => json!({"reading": "unreadable"}),
        };
        let singleton_lock = match self.singleton_lock {
            SingletonLockReading::Absent => json!({"reading": "absent"}),
            SingletonLockReading::PidNotAlive { pid } => {
                json!({"reading": "pid_not_alive", "pid": pid})
            }
            SingletonLockReading::PidNotABrowser { pid } => {
                json!({"reading": "pid_not_a_browser", "pid": pid})
            }
            SingletonLockReading::LiveBrowser { pid } => {
                json!({"reading": "live_browser", "pid": pid})
            }
            SingletonLockReading::OtherHost => json!({"reading": "other_host"}),
            SingletonLockReading::Unreadable => json!({"reading": "unreadable"}),
        };
        json!({"processes": processes, "singleton_lock": singleton_lock})
    }

    /// The readings in words, for the question a person is shown.
    pub fn describe(&self) -> String {
        let processes = match self.processes {
            ProcessReading::NoneNamesDirectory { examined } => format!(
                "none of the {examined} running process(es) of this user names the profile \
                 directory"
            ),
            ProcessReading::NamedBy { pid } => {
                format!("process {pid} names the profile directory")
            }
            ProcessReading::Unreadable => "the process table could not be read".to_string(),
        };
        let singleton_lock = match self.singleton_lock {
            SingletonLockReading::Absent => "Chrome's SingletonLock is absent".to_string(),
            SingletonLockReading::PidNotAlive { pid } => {
                format!("Chrome's SingletonLock names pid {pid}, which is not running")
            }
            SingletonLockReading::PidNotABrowser { pid } => format!(
                "Chrome's SingletonLock names pid {pid}, which now runs a program that is not \
                 Chrome"
            ),
            SingletonLockReading::LiveBrowser { pid } => {
                format!("Chrome's SingletonLock names running Chrome process {pid}")
            }
            SingletonLockReading::OtherHost => {
                "Chrome's SingletonLock was written on another host".to_string()
            }
            SingletonLockReading::Unreadable => {
                "Chrome's SingletonLock could not be read".to_string()
            }
        };
        format!("{processes}; {singleton_lock}")
    }
}

/// Why a clear was refused. Every refusal changes nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearRefusal {
    /// Startup recovery has not finished, so which profiles it kept is not
    /// known yet. Never read as "nothing kept".
    NotReady,
    /// Startup recovery in this process kept no launch record for this
    /// project (or not the one named).
    NotRetained,
    /// Recovery kept more than one record for this project; name one.
    Ambiguous {
        sequences: Vec<u64>,
    },
    /// The journal no longer holds the record active, or describes it
    /// differently from what recovery kept.
    JournalDisagrees,
    /// The launch journal could not be read or written.
    JournalUnavailable,
    ProfileInUse {
        pid: u32,
    },
    SingletonLockHeld {
        pid: u32,
    },
    ProcessTableUnreadable,
    SingletonLockUnreadable,
    SingletonLockOtherHost,
}

impl ClearRefusal {
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::NotReady => "not_ready",
            Self::NotRetained => "not_retained",
            Self::Ambiguous { .. } => "ambiguous",
            Self::JournalDisagrees => "journal_disagrees",
            Self::JournalUnavailable => "journal_unavailable",
            Self::ProfileInUse { .. } => "profile_in_use",
            Self::SingletonLockHeld { .. } => "singleton_lock_held",
            Self::ProcessTableUnreadable => "process_table_unreadable",
            Self::SingletonLockUnreadable => "singleton_lock_unreadable",
            Self::SingletonLockOtherHost => "singleton_lock_other_host",
        }
    }

    pub const fn remedy(&self) -> &'static str {
        match self {
            Self::NotReady => {
                "startup recovery has not finished, or no browser launch service is configured; \
                 retry once the module has started with a browser configured"
            }
            Self::NotRetained => {
                "startup recovery in this module process holds no launch record for this project; \
                 nothing needs clearing"
            }
            Self::Ambiguous { .. } => {
                "recovery holds several launch records for this project; pass one sequence"
            }
            Self::JournalDisagrees => {
                "the launch journal no longer matches what startup recovery kept; restart the \
                 module so recovery reads it again"
            }
            Self::JournalUnavailable => {
                "the launch journal could not be read or written; check its storage and retry"
            }
            Self::ProfileInUse { .. } => {
                "a running process uses this profile directory; quit it, then retry"
            }
            Self::SingletonLockHeld { .. } => {
                "Chrome's lock in this profile names a running Chrome process; quit it, then retry"
            }
            Self::ProcessTableUnreadable => {
                "the process table could not be read completely, so a browser using this profile \
                 cannot be ruled out; retry"
            }
            Self::SingletonLockUnreadable => {
                "Chrome's SingletonLock in this profile exists but could not be read; an operator \
                 must inspect it before a clear can be asked"
            }
            Self::SingletonLockOtherHost => {
                "Chrome's SingletonLock in this profile was written under another host name, so \
                 its process cannot be checked here; an operator must confirm no browser uses \
                 the profile and remove the lock before a clear can be asked"
            }
        }
    }

    pub fn as_json(&self) -> Value {
        let mut reply = json!({
            "outcome": "refused",
            "reason": self.reason_code(),
            "remedy": self.remedy(),
        });
        match self {
            Self::Ambiguous { sequences } => reply["sequences"] = json!(sequences),
            Self::ProfileInUse { pid } | Self::SingletonLockHeld { pid } => {
                reply["pid"] = json!(pid)
            }
            _ => {}
        }
        reply
    }
}

/// A clear that stopped after it had begun to write.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClearFailure {
    /// Refused before anything was written.
    Refused(ClearRefusal),
    /// The clear is recorded but the record could not be consumed; the next
    /// module start finishes it.
    Terminalization { sequence: u64 },
    /// The record is consumed but the profile's custody could not be given
    /// back; the next launch after this module exits breaks it as stale.
    CustodyRelease { sequence: u64 },
}

/// The side of a clear that owns the launch journal and profile custody.
pub trait LaunchRecoveryClearer: Send + Sync {
    /// Find the record recovery kept for `agent_project_id` and read the
    /// evidence, without changing anything.
    fn preview(
        &self,
        agent_project_id: &str,
        sequence: Option<u64>,
    ) -> Result<ClearPreview, ClearRefusal>;

    /// Re-check everything `preview` read, then record, consume and release.
    fn clear(&self, preview: &ClearPreview, ask_id: &str) -> Result<(), ClearFailure>;
}

/// Where the management plane finds the clearer, once startup recovery has
/// published it.
///
/// Empty until recovery finishes: an empty registry means "not looked yet",
/// and every request then refuses `not_ready`.
pub struct LaunchRecoveryRegistry {
    clearer: OnceLock<Arc<dyn LaunchRecoveryClearer>>,
    incarnation: String,
}

impl Default for LaunchRecoveryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl LaunchRecoveryRegistry {
    pub fn new() -> Self {
        Self {
            clearer: OnceLock::new(),
            incarnation: new_incarnation(),
        }
    }

    /// Publish the clearer after startup recovery has finished. Only the first
    /// publication counts; `false` for any later one.
    pub fn publish(&self, clearer: Arc<dyn LaunchRecoveryClearer>) -> bool {
        self.clearer.set(clearer).is_ok()
    }

    /// Identifies this module process's startup, so an answer to a question
    /// asked by an earlier process is recognised as such and does nothing.
    pub fn incarnation(&self) -> &str {
        &self.incarnation
    }

    pub fn preview(
        &self,
        agent_project_id: &str,
        sequence: Option<u64>,
    ) -> Result<ClearPreview, ClearRefusal> {
        match self.clearer.get() {
            Some(clearer) => clearer.preview(agent_project_id, sequence),
            None => Err(ClearRefusal::NotReady),
        }
    }

    pub fn clear(&self, preview: &ClearPreview, ask_id: &str) -> Result<(), ClearFailure> {
        match self.clearer.get() {
            Some(clearer) => clearer.clear(preview, ask_id),
            None => Err(ClearFailure::Refused(ClearRefusal::NotReady)),
        }
    }
}

/// A per-startup identity: the pid and the moment this registry was made,
/// plus a counter so two registries in one process (as tests build) differ.
fn new_incarnation() -> String {
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!(
        "{}-{nanos}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    )
}

/// Render a recorded browser start time for a person.
pub fn launched_at(start_time_micros: Option<u64>) -> Option<String> {
    start_time_micros.map(|micros| {
        crate::browser_session::render_rfc3339_millis(
            UNIX_EPOCH + std::time::Duration::from_micros(micros),
        )
    })
}

/// A process fact that could not be read. Never the same as "absent".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unreadable;

/// One fact about one process, as the operating system answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessFact<T> {
    Read(T),
    /// No process holds the pid (any more).
    Gone,
    /// The system refused to show it. Not evidence of whose process it is.
    NotPermitted,
    Unreadable,
}

/// Who runs a process, and whether it has exited and only waits to be reaped.
///
/// `uid` is the effective user: the credentials the process opens files with,
/// and the user the system itself goes by when it decides whether one process
/// may read another's arguments. A setuid program started by this user (such
/// as `login`, behind every Terminal window) runs as its owner, not as this
/// user, and its arguments are hidden for exactly that reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessUsers {
    pub uid: u32,
    pub zombie: bool,
}

/// The raw facts about running processes the evidence needs, behind a seam so
/// a test can answer them. What counts as "every process read" is decided once,
/// in [`user_process_arguments`], not by each platform.
pub trait ProcessTable {
    /// The user this module runs as.
    fn this_user(&self) -> Option<u32>;

    /// Every pid the system reports.
    fn process_ids(&self) -> Result<Vec<u32>, Unreadable>;

    /// Who runs `pid`. Must answer for another user's process too: that is
    /// the only evidence that lets a process be skipped.
    fn users(&self, pid: u32) -> ProcessFact<ProcessUsers>;

    fn arguments(&self, pid: u32) -> ProcessFact<Vec<OsString>>;

    /// The executable `pid` runs, `Ok(None)` when no process holds it.
    fn executable(&self, pid: u32) -> Result<Option<PathBuf>, Unreadable>;

    fn host_name(&self) -> Option<String>;
}

/// How many more times an unreadable process of this user is read before the
/// table counts as unreadable, and how long apart. A process part-way through
/// exiting or exec'ing refuses the argument read for a moment.
const UNREADABLE_RETRIES: u32 = 5;
const UNREADABLE_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(20);

/// The arguments of every running process of this module's user.
///
/// A process is skipped only on positive evidence: it is gone, it is a zombie,
/// or its effective user was read and is not this user. Another user's process
/// is skipped because without privilege its arguments cannot be read at all,
/// so "every process" means every process this module's user runs, which is
/// where this module launches its browsers; Chrome's lock, read separately,
/// does not depend on whose process holds the profile. A process whose user
/// cannot be read, or one of this user's whose arguments stay unreadable
/// (refused or not), makes the whole reading `Err`, so a clear is refused.
pub fn user_process_arguments(
    table: &dyn ProcessTable,
) -> Result<Vec<(u32, Vec<OsString>)>, Unreadable> {
    let this_user = table.this_user().ok_or(Unreadable)?;
    let mut processes = Vec::new();
    for pid in table.process_ids()? {
        match table.users(pid) {
            ProcessFact::Gone => continue,
            ProcessFact::Read(users) if users.zombie => continue,
            ProcessFact::Read(users) if users.uid != this_user => continue,
            ProcessFact::Read(_) => {}
            ProcessFact::NotPermitted | ProcessFact::Unreadable => return Err(Unreadable),
        }
        let mut retries = 0;
        loop {
            match table.arguments(pid) {
                ProcessFact::Read(arguments) => {
                    processes.push((pid, arguments));
                    break;
                }
                ProcessFact::Gone => break,
                ProcessFact::NotPermitted | ProcessFact::Unreadable => match table.users(pid) {
                    ProcessFact::Gone => break,
                    ProcessFact::Read(users) if users.zombie => break,
                    _ if retries < UNREADABLE_RETRIES => {
                        retries += 1;
                        std::thread::sleep(UNREADABLE_RETRY_PAUSE);
                    }
                    _ => return Err(Unreadable),
                },
            }
        }
    }
    Ok(processes)
}

/// Read both pieces of evidence for `profile_directory`.
///
/// `configured_executable` is the browser this module launches, recognised as
/// a Chrome executable whatever it is named.
pub fn read_profile_evidence(
    profile_directory: &Path,
    configured_executable: Option<&Path>,
    table: &dyn ProcessTable,
) -> ProfileEvidence {
    ProfileEvidence {
        processes: read_processes(profile_directory, table),
        singleton_lock: read_singleton_lock(profile_directory, configured_executable, table),
    }
}

fn read_processes(profile_directory: &Path, table: &dyn ProcessTable) -> ProcessReading {
    let Ok(processes) = user_process_arguments(table) else {
        return ProcessReading::Unreadable;
    };
    let examined = processes.len();
    for (pid, arguments) in processes {
        if names_profile_directory(&arguments, profile_directory) {
            return ProcessReading::NamedBy { pid };
        }
    }
    ProcessReading::NoneNamesDirectory { examined }
}

/// Whether an argument vector passes `profile_directory` as Chrome's
/// user-data directory, in either spelling Chrome accepts.
fn names_profile_directory(arguments: &[OsString], profile_directory: &Path) -> bool {
    let directory = profile_directory.as_os_str();
    let mut joined = OsString::from("--user-data-dir=");
    joined.push(directory);
    arguments.iter().enumerate().any(|(index, argument)| {
        *argument == joined
            || (argument == "--user-data-dir"
                && arguments
                    .get(index + 1)
                    .is_some_and(|next| next.as_os_str() == directory))
    })
}

fn read_singleton_lock(
    profile_directory: &Path,
    configured_executable: Option<&Path>,
    table: &dyn ProcessTable,
) -> SingletonLockReading {
    let lock = profile_directory.join("SingletonLock");
    match std::fs::symlink_metadata(&lock) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return SingletonLockReading::Absent
        }
        Err(_) => return SingletonLockReading::Unreadable,
        // Chrome writes a symbolic link. Anything else under that name is not
        // Chrome's lock, and cannot be read as one.
        Ok(metadata) if !metadata.file_type().is_symlink() => {
            return SingletonLockReading::Unreadable
        }
        Ok(_) => {}
    }
    let Ok(target) = std::fs::read_link(&lock) else {
        return SingletonLockReading::Unreadable;
    };
    let Some((host, pid)) = target.to_str().and_then(|text| text.rsplit_once('-')) else {
        return SingletonLockReading::Unreadable;
    };
    let Ok(pid) = pid.parse::<u32>() else {
        return SingletonLockReading::Unreadable;
    };
    let Some(this_host) = table.host_name() else {
        return SingletonLockReading::Unreadable;
    };
    if host != this_host {
        return SingletonLockReading::OtherHost;
    }
    match table.executable(pid) {
        Ok(None) => SingletonLockReading::PidNotAlive { pid },
        Ok(Some(executable)) if is_browser_executable(&executable, configured_executable) => {
            SingletonLockReading::LiveBrowser { pid }
        }
        Ok(Some(_)) => SingletonLockReading::PidNotABrowser { pid },
        Err(Unreadable) => SingletonLockReading::Unreadable,
    }
}

/// Whether an executable is Chrome or Chromium, a helper of either, or the
/// browser this module is configured to launch.
///
/// Read generously on purpose: a false "this is Chrome" refuses a clear the
/// operator can retry after checking, while a false "not Chrome" would clear a
/// profile a browser still has open.
fn is_browser_executable(executable: &Path, configured_executable: Option<&Path>) -> bool {
    if configured_executable.is_some_and(|configured| {
        configured == executable || configured.file_name() == executable.file_name()
    }) {
        return true;
    }
    executable.components().any(|component| {
        let name = component.as_os_str().to_string_lossy().to_lowercase();
        name.contains("chrome") || name.contains("chromium")
    })
}

/// The running system's process table.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub struct SystemProcessTable;

#[cfg(target_os = "macos")]
impl ProcessTable for SystemProcessTable {
    fn this_user(&self) -> Option<u32> {
        match cerebellum_macos::process_owner(std::process::id()) {
            cerebellum_macos::ProcessOwner::Running { uid, .. } => Some(uid),
            _ => None,
        }
    }

    fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
        cerebellum_macos::all_process_ids().map_err(|_| Unreadable)
    }

    fn users(&self, pid: u32) -> ProcessFact<ProcessUsers> {
        match cerebellum_macos::process_owner(pid) {
            cerebellum_macos::ProcessOwner::Running { uid, zombie } => {
                ProcessFact::Read(ProcessUsers { uid, zombie })
            }
            cerebellum_macos::ProcessOwner::NoSuchProcess => ProcessFact::Gone,
            cerebellum_macos::ProcessOwner::NotPermitted => ProcessFact::NotPermitted,
            cerebellum_macos::ProcessOwner::Unreadable(_) => ProcessFact::Unreadable,
        }
    }

    fn arguments(&self, pid: u32) -> ProcessFact<Vec<OsString>> {
        match cerebellum_macos::process_arguments(pid) {
            cerebellum_macos::ProcessArguments::Read(arguments) => ProcessFact::Read(arguments),
            cerebellum_macos::ProcessArguments::NoSuchProcess => ProcessFact::Gone,
            cerebellum_macos::ProcessArguments::Unreadable(1) => ProcessFact::NotPermitted,
            cerebellum_macos::ProcessArguments::Unreadable(_) => ProcessFact::Unreadable,
        }
    }

    fn executable(&self, pid: u32) -> Result<Option<PathBuf>, Unreadable> {
        match self.users(pid) {
            ProcessFact::Gone => return Ok(None),
            ProcessFact::Read(users) if users.zombie => return Ok(None),
            ProcessFact::Read(_) => {}
            ProcessFact::NotPermitted | ProcessFact::Unreadable => return Err(Unreadable),
        }
        cerebellum_macos::process_executable_path(pid).map_err(|_| Unreadable)
    }

    fn host_name(&self) -> Option<String> {
        cerebellum_macos::host_name()
    }
}

/// Map a failed read under `/proc` to what it says about the process.
#[cfg(target_os = "linux")]
fn proc_fact<T>(result: std::io::Result<T>) -> ProcessFact<T> {
    match result {
        Ok(value) => ProcessFact::Read(value),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => ProcessFact::Gone,
        // ESRCH: the process exited while its files were being read.
        Err(error) if error.raw_os_error() == Some(3) => ProcessFact::Gone,
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {
            ProcessFact::NotPermitted
        }
        Err(_) => ProcessFact::Unreadable,
    }
}

#[cfg(target_os = "linux")]
impl ProcessTable for SystemProcessTable {
    fn this_user(&self) -> Option<u32> {
        match self.users(std::process::id()) {
            ProcessFact::Read(users) => Some(users.uid),
            _ => None,
        }
    }

    fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
        let mut pids = Vec::new();
        for entry in std::fs::read_dir("/proc").map_err(|_| Unreadable)? {
            let entry = entry.map_err(|_| Unreadable)?;
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|name| name.parse::<u32>().ok())
            {
                pids.push(pid);
            }
        }
        Ok(pids)
    }

    /// Read from `status`, which any process may read, rather than from the
    /// owner of `/proc/<pid>`: a process that made itself non-dumpable (as
    /// Chrome's sandboxed helpers do) has that directory owned by root, which
    /// would read as another user's process.
    fn users(&self, pid: u32) -> ProcessFact<ProcessUsers> {
        let status = match proc_fact(std::fs::read_to_string(format!("/proc/{pid}/status"))) {
            ProcessFact::Read(status) => status,
            ProcessFact::Gone => return ProcessFact::Gone,
            ProcessFact::NotPermitted => return ProcessFact::NotPermitted,
            ProcessFact::Unreadable => return ProcessFact::Unreadable,
        };
        let field = |name: &str| {
            status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .map(str::trim)
        };
        // `Uid:` lists the real, effective, saved and filesystem user ids;
        // the effective one is second.
        let uids: Option<Vec<u32>> = field("Uid:").map(|value| {
            value
                .split_whitespace()
                .map(|id| id.parse().ok())
                .collect::<Option<Vec<u32>>>()
                .unwrap_or_default()
        });
        match (uids, field("State:")) {
            (Some(uids), Some(state)) if uids.len() == 4 => ProcessFact::Read(ProcessUsers {
                uid: uids[1],
                zombie: state.starts_with('Z'),
            }),
            _ => ProcessFact::Unreadable,
        }
    }

    fn arguments(&self, pid: u32) -> ProcessFact<Vec<OsString>> {
        use std::os::unix::ffi::OsStringExt;
        match proc_fact(std::fs::read(format!("/proc/{pid}/cmdline"))) {
            ProcessFact::Read(bytes) => ProcessFact::Read(
                bytes
                    .split(|byte| *byte == 0)
                    .filter(|argument| !argument.is_empty())
                    .map(|argument| OsString::from_vec(argument.to_vec()))
                    .collect(),
            ),
            ProcessFact::Gone => ProcessFact::Gone,
            ProcessFact::NotPermitted => ProcessFact::NotPermitted,
            ProcessFact::Unreadable => ProcessFact::Unreadable,
        }
    }

    fn executable(&self, pid: u32) -> Result<Option<PathBuf>, Unreadable> {
        match self.users(pid) {
            ProcessFact::Gone => return Ok(None),
            ProcessFact::Read(users) if users.zombie => return Ok(None),
            ProcessFact::Read(_) => {}
            ProcessFact::NotPermitted | ProcessFact::Unreadable => return Err(Unreadable),
        }
        match proc_fact(std::fs::read_link(format!("/proc/{pid}/exe"))) {
            ProcessFact::Read(path) => Ok(Some(path)),
            ProcessFact::Gone => Ok(None),
            // Another user's process hides its executable; it is alive, and
            // not knowing what it runs cannot rule out Chrome.
            ProcessFact::NotPermitted | ProcessFact::Unreadable => Err(Unreadable),
        }
    }

    fn host_name(&self) -> Option<String> {
        std::fs::read_to_string("/proc/sys/kernel/hostname")
            .ok()
            .map(|name| name.trim().to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_spellings_of_the_user_data_directory_are_recognised() {
        let directory = Path::new("/profiles/p1");
        let joined = vec![
            OsString::from("chrome"),
            OsString::from("--user-data-dir=/profiles/p1"),
        ];
        let split = vec![
            OsString::from("chrome"),
            OsString::from("--user-data-dir"),
            OsString::from("/profiles/p1"),
        ];
        let other = vec![OsString::from("--user-data-dir=/profiles/p10")];
        assert!(names_profile_directory(&joined, directory));
        assert!(names_profile_directory(&split, directory));
        assert!(!names_profile_directory(&other, directory));
    }

    /// Answers from a fixed list: pid 10 is this user's, whose arguments read
    /// as `arguments`; pid 20 is `other`'s, whose arguments are refused.
    struct FixedTable {
        users_of_10: ProcessFact<ProcessUsers>,
        arguments_of_10: ProcessFact<Vec<OsString>>,
    }

    const THIS_USER: u32 = 501;

    fn run_by(uid: u32) -> ProcessFact<ProcessUsers> {
        ProcessFact::Read(ProcessUsers { uid, zombie: false })
    }

    impl ProcessTable for FixedTable {
        fn this_user(&self) -> Option<u32> {
            Some(THIS_USER)
        }
        fn process_ids(&self) -> Result<Vec<u32>, Unreadable> {
            Ok(vec![10, 20])
        }
        fn users(&self, pid: u32) -> ProcessFact<ProcessUsers> {
            match pid {
                10 => self.users_of_10.clone(),
                _ => run_by(0),
            }
        }
        fn arguments(&self, pid: u32) -> ProcessFact<Vec<OsString>> {
            match pid {
                10 => self.arguments_of_10.clone(),
                _ => ProcessFact::NotPermitted,
            }
        }
        fn executable(&self, _pid: u32) -> Result<Option<PathBuf>, Unreadable> {
            Ok(None)
        }
        fn host_name(&self) -> Option<String> {
            None
        }
    }

    #[test]
    fn only_a_process_read_as_another_user_s_is_skipped() {
        let readable = FixedTable {
            users_of_10: run_by(THIS_USER),
            arguments_of_10: ProcessFact::Read(vec![OsString::from("x")]),
        };
        assert_eq!(
            user_process_arguments(&readable),
            Ok(vec![(10, vec![OsString::from("x")])])
        );
        for hidden in [ProcessFact::NotPermitted, ProcessFact::Unreadable] {
            let same_user_hidden = FixedTable {
                users_of_10: run_by(THIS_USER),
                arguments_of_10: hidden,
            };
            assert_eq!(user_process_arguments(&same_user_hidden), Err(Unreadable));
        }
        for unknown in [ProcessFact::NotPermitted, ProcessFact::Unreadable] {
            let unknown_user = FixedTable {
                users_of_10: unknown,
                arguments_of_10: ProcessFact::Read(Vec::new()),
            };
            assert_eq!(user_process_arguments(&unknown_user), Err(Unreadable));
        }
        let gone = FixedTable {
            users_of_10: ProcessFact::Gone,
            arguments_of_10: ProcessFact::NotPermitted,
        };
        assert_eq!(user_process_arguments(&gone), Ok(Vec::new()));
    }

    #[test]
    fn chrome_helpers_and_the_configured_browser_count_as_browsers() {
        assert!(is_browser_executable(
            Path::new("/Applications/Google Chrome.app/Contents/Frameworks/Helper"),
            None
        ));
        assert!(is_browser_executable(
            Path::new("/usr/lib/chromium/chromium"),
            None
        ));
        assert!(is_browser_executable(
            Path::new("/opt/custom/browser"),
            Some(Path::new("/opt/custom/browser"))
        ));
        assert!(!is_browser_executable(Path::new("/bin/sleep"), None));
    }
}
