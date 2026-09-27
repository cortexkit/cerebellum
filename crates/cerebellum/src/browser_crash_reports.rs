//! Where an agent browser's crash reports are written.
//!
//! On macOS, Chrome starts its crash handler (`chrome_crashpad_handler`) before
//! it reads `--user-data-dir`, and it takes the handler's database from the
//! DEFAULT user-data directory: the person's own
//! `~/Library/Application Support/Google/Chrome/Crashpad`
//! (chrome/app/chrome_main_delegate.cc, chrome/common/chrome_paths.cc). A crash
//! of an agent browser would therefore write a minidump -- which holds page
//! memory from the agent's signed-in sessions -- into the person's folder, where
//! Time Machine backs it up and the person's own upload consent decides whether
//! it is sent to Google.
//!
//! The `BREAKPAD_DUMP_LOCATION` environment variable, read in
//! `ChromeCrashReporterClient::Create` (chrome/app/chrome_crash_reporter_client.cc)
//! before the handler starts, moves that database to the path it names. A fresh
//! database has uploads switched off, so the handler then reads uploads as
//! disabled from the database's own settings instead of from the person's. The
//! switches that sound as if they turn crash reporting off
//! (`--disable-crash-reporter`, `--disable-breakpad`,
//! `--disable-crashpad-for-testing`) are not read by Chrome on macOS, so none of
//! them is used.
//!
//! Every macOS launch therefore gets its own directory under the per-user
//! temporary directory, is refused unless Time Machine reports that directory
//! excluded from backup, and deletes it when the session ends. Directories a
//! previous process left behind are found by their fixed name prefix and
//! deleted at startup.
//!
//! Linux needs none of this: there the launch environment points
//! `XDG_CONFIG_HOME` into the agent's own profile directory, and Chromium derives
//! its crash database from that, so crash reports already stay inside the
//! profile the agent owns.

use std::io;
use std::path::{Path, PathBuf};

/// The environment variable Chrome reads to relocate its crash database.
pub const BREAKPAD_DUMP_LOCATION: &str = "BREAKPAD_DUMP_LOCATION";

/// Every crash-report directory this module creates is named with this prefix,
/// followed by `<pid>-<process start time in microseconds>-<sequence>` of the
/// process that created it. The prefix is how startup finds directories left
/// by a process that died; the pid and start time are how it tells a dead
/// creator from a live one, even when the pid has since been reused.
pub const CRASH_REPORTS_DIRECTORY_PREFIX: &str = "ck-cerebellum-crashpad-";

/// Why a launch was refused before its browser was spawned, because the crash
/// reports it could write had nowhere safe to go.
///
/// There is deliberately no fallback: without a relocated database Chrome
/// writes into the person's own folder, which is exactly what this exists to
/// prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CrashReportRefusal {
    /// The per-user temporary directory could not be resolved, this process's
    /// own start time could not be read, or the directory could not be created.
    DirectoryUnavailable,
    /// Time Machine reported the directory as included in backups.
    BackedUp,
    /// `tmutil` did not answer before its deadline.
    ExclusionCheckTimedOut,
    /// `tmutil` could not be run, failed, or answered in a form not recognised.
    ExclusionCheckFailed,
}

impl CrashReportRefusal {
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::DirectoryUnavailable => "crash_reports_directory_unavailable",
            Self::BackedUp => "crash_reports_directory_backed_up",
            Self::ExclusionCheckTimedOut => "crash_reports_backup_check_timed_out",
            Self::ExclusionCheckFailed => "crash_reports_backup_check_failed",
        }
    }

    /// The launch refusal. No path is included: it names the per-user
    /// temporary directory, and the stage and reason are what a caller acts on.
    pub fn launch_refusal(self) -> serde_json::Value {
        serde_json::json!({
            "outcome": "internal_failure",
            "stage": "crash_reports_directory",
            "reason_code": self.reason_code(),
        })
    }
}

/// One launch's crash-report directory, deleted when the launch's session ends.
///
/// The session cleanup deletes it with [`Self::remove`], which reports failure
/// so the session records it. Dropping it without that call (a launch that
/// failed part-way) still deletes it, and writes a failure to standard error
/// because there is no session to record it in; the next startup's sweep
/// retries either way.
#[derive(Debug)]
pub struct CrashReportDirectory {
    path: PathBuf,
    removed: bool,
}

impl CrashReportDirectory {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Delete the directory and everything the crash handler wrote into it.
    /// A directory that is already gone counts as deleted.
    pub fn remove(mut self) -> io::Result<()> {
        self.removed = true;
        remove_directory(&self.path)
    }
}

impl Drop for CrashReportDirectory {
    fn drop(&mut self) {
        if self.removed {
            return;
        }
        self.removed = true;
        if let Err(error) = remove_directory(&self.path) {
            // The error's text carries no path, and the kind is enough to act
            // on; the directory itself is retried by the next startup's sweep.
            eprintln!(
                "ck-cerebellum: a browser crash-report directory could not be deleted ({:?}); \
                 the next start will retry",
                error.kind()
            );
        }
    }
}

fn remove_directory(path: &Path) -> io::Result<()> {
    match std::fs::remove_dir_all(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(target_os = "macos")]
pub use macos::*;

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::time::{Duration, Instant};

    /// How long `tmutil isexcluded` may take before the launch is refused.
    ///
    /// A healthy answer takes milliseconds. The bound exists because the check
    /// is a subprocess whose latency is not ours, on the launch path: an
    /// unbounded wait on it would hang the launch, and a refusal that arrives
    /// is worth more than an answer that never does.
    pub const EXCLUSION_CHECK_DEADLINE: Duration = Duration::from_secs(5);

    const EXCLUSION_CHECK_POLL_INTERVAL: Duration = Duration::from_millis(10);

    /// Builds the command that asks whether a path is excluded from backup.
    ///
    /// Production asks `tmutil`; a test substitutes a command with a known
    /// answer or one that never answers, so the parsing and the deadline are
    /// exercised without depending on this machine's backup configuration.
    pub trait BackupExclusionQuery {
        fn command(&self, path: &Path) -> Command;
    }

    /// `tmutil isexcluded <path>`, which prints `[Excluded]` or `[Included]`
    /// followed by the path.
    pub struct Tmutil;

    impl BackupExclusionQuery for Tmutil {
        fn command(&self, path: &Path) -> Command {
            let mut command = Command::new("/usr/bin/tmutil");
            command.arg("isexcluded").arg(path);
            command
        }
    }

    impl CrashReportDirectory {
        /// Create this launch's directory under the per-user temporary
        /// directory and confirm with `tmutil` that it is excluded from backup.
        pub fn create() -> Result<Self, CrashReportRefusal> {
            Self::create_with(&Tmutil, EXCLUSION_CHECK_DEADLINE)
        }

        /// [`Self::create`] with the exclusion query and its deadline supplied.
        pub fn create_with(
            query: &dyn BackupExclusionQuery,
            deadline: Duration,
        ) -> Result<Self, CrashReportRefusal> {
            static SEQUENCE: AtomicU64 = AtomicU64::new(0);
            let parent =
                crash_reports_parent().map_err(|_| CrashReportRefusal::DirectoryUnavailable)?;
            let (pid, start_time_micros) =
                own_generation().ok_or(CrashReportRefusal::DirectoryUnavailable)?;
            let path = parent.join(format!(
                "{CRASH_REPORTS_DIRECTORY_PREFIX}{pid}-{start_time_micros}-{}",
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            // `create`, not `create_dir_all`: a name that already exists is an
            // error rather than a directory shared with whoever made it.
            // Owner-only, because a minidump holds page memory from the agent's
            // signed-in sessions.
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .map_err(|_| CrashReportRefusal::DirectoryUnavailable)?;
            }
            let directory = Self {
                path,
                removed: false,
            };
            // Checked on the directory itself, after it exists and before the
            // browser can write anything into it. On refusal it is dropped,
            // which deletes it.
            check_excluded_from_backup(query, directory.path(), deadline)?;
            Ok(directory)
        }
    }

    /// The per-user temporary directory, resolved through symlinks.
    ///
    /// Resolved because on macOS it sits behind the `/var` -> `/private/var`
    /// symlink and Chrome reports the resolved path, so an unresolved one would
    /// not match what the crash handler is given.
    pub fn crash_reports_parent() -> io::Result<PathBuf> {
        std::env::temp_dir().canonicalize()
    }

    fn own_generation() -> Option<(u32, u64)> {
        let pid = std::process::id();
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(start) => Some((pid, start)),
            _ => None,
        }
    }

    /// Ask `query` whether `path` is excluded from backup, within `deadline`.
    ///
    /// Only an explicit `[Excluded]` answer admits the launch. On expiry the
    /// child is killed and not waited for, as the executable identity check
    /// does with its verifier: a process that does not answer may not answer a
    /// signal either, and waiting to reap it would bring the hang back.
    pub fn check_excluded_from_backup(
        query: &dyn BackupExclusionQuery,
        path: &Path,
        deadline: Duration,
    ) -> Result<(), CrashReportRefusal> {
        let deadline = Instant::now() + deadline;
        let mut child = query
            .command(path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| CrashReportRefusal::ExclusionCheckFailed)?;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        std::thread::sleep(EXCLUSION_CHECK_POLL_INTERVAL);
                        let _ = child.try_wait();
                        return Err(CrashReportRefusal::ExclusionCheckTimedOut);
                    }
                    std::thread::sleep(EXCLUSION_CHECK_POLL_INTERVAL);
                }
                Err(_) => return Err(CrashReportRefusal::ExclusionCheckFailed),
            }
        }
        let output = child
            .wait_with_output()
            .map_err(|_| CrashReportRefusal::ExclusionCheckFailed)?;
        if !output.status.success() {
            return Err(CrashReportRefusal::ExclusionCheckFailed);
        }
        let answer = String::from_utf8_lossy(&output.stdout);
        let answer = answer.trim_start();
        if answer.starts_with("[Excluded]") {
            Ok(())
        } else if answer.starts_with("[Included]") {
            Err(CrashReportRefusal::BackedUp)
        } else {
            Err(CrashReportRefusal::ExclusionCheckFailed)
        }
    }

    /// What a startup sweep did.
    #[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
    pub struct LeftoverSweep {
        pub removed: usize,
        /// Directories left by a dead process that could not be deleted.
        pub failed: usize,
    }

    /// Delete the crash-report directories that processes no longer running
    /// left under the per-user temporary directory, and write any failure to
    /// standard error.
    ///
    /// A directory whose creator is still running is kept: another module
    /// process on this machine may be running a browser that writes to it.
    pub fn remove_leftover_directories() -> LeftoverSweep {
        let Ok(parent) = crash_reports_parent() else {
            eprintln!(
                "ck-cerebellum: the temporary directory could not be resolved, so crash-report \
                 directories left by an earlier process were not looked for"
            );
            return LeftoverSweep::default();
        };
        let sweep = remove_leftover_directories_in(&parent, creator_is_running);
        if sweep.failed > 0 {
            eprintln!(
                "ck-cerebellum: {} crash-report director{} left by an earlier process could not \
                 be deleted; the next start will retry",
                sweep.failed,
                if sweep.failed == 1 { "y" } else { "ies" }
            );
        }
        sweep
    }

    /// [`remove_leftover_directories`] over `parent`, with the liveness of a
    /// creator (pid, start time) answered by `creator_is_live`.
    ///
    /// A name with the prefix whose suffix does not parse is deleted too:
    /// nothing this module creates has that shape, so no running process of
    /// ours can own it.
    pub fn remove_leftover_directories_in(
        parent: &Path,
        creator_is_live: impl Fn(u32, u64) -> bool,
    ) -> LeftoverSweep {
        let mut sweep = LeftoverSweep::default();
        let Ok(entries) = std::fs::read_dir(parent) else {
            return sweep;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(suffix) = name
                .to_str()
                .and_then(|name| name.strip_prefix(CRASH_REPORTS_DIRECTORY_PREFIX))
            else {
                continue;
            };
            // Only real directories: a symlink or a file with this name was not
            // made by this module, and following a symlink could delete
            // something elsewhere.
            if !entry.file_type().is_ok_and(|file_type| file_type.is_dir()) {
                continue;
            }
            if parse_creator(suffix).is_some_and(|(pid, start)| creator_is_live(pid, start)) {
                continue;
            }
            match remove_directory(&entry.path()) {
                Ok(()) => sweep.removed += 1,
                Err(_) => sweep.failed += 1,
            }
        }
        sweep
    }

    /// Whether the process that created a directory is still running.
    ///
    /// Anything but a confirmed different or missing process counts as
    /// running, so a directory is never deleted on an unreadable answer.
    fn creator_is_running(pid: u32, start_time_micros: u64) -> bool {
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(start) => start == start_time_micros,
            cerebellum_macos::ProcessStartTime::NoSuchProcess => false,
            _ => true,
        }
    }

    fn parse_creator(suffix: &str) -> Option<(u32, u64)> {
        let mut parts = suffix.split('-');
        let pid = parts.next()?.parse().ok()?;
        let start = parts.next()?.parse().ok()?;
        parts.next()?.parse::<u64>().ok()?;
        parts.next().is_none().then_some((pid, start))
    }

    /// Stand-ins for `tmutil`, shared with the launch service's tests.
    #[cfg(test)]
    pub(crate) mod test_support {
        use super::*;
        use std::sync::Mutex;

        /// Answers with a fixed shell script, which receives the queried path
        /// as `$0`, and remembers the last path it was asked about.
        pub(crate) struct ScriptedQuery {
            script: &'static str,
            pub(crate) asked: Mutex<Option<PathBuf>>,
        }

        impl ScriptedQuery {
            pub(crate) fn new(script: &'static str) -> Self {
                Self {
                    script,
                    asked: Mutex::new(None),
                }
            }

            /// What `tmutil isexcluded` prints for an excluded path.
            pub(crate) fn excluded() -> Self {
                Self::new(r#"printf '[Excluded]    %s\n' "$0""#)
            }

            /// What `tmutil isexcluded` prints for a path that is backed up.
            pub(crate) fn included() -> Self {
                Self::new(r#"printf '[Included]    %s\n' "$0""#)
            }

            /// A query that never answers.
            pub(crate) fn silent() -> Self {
                Self::new("exec /bin/sleep 30")
            }
        }

        impl BackupExclusionQuery for ScriptedQuery {
            fn command(&self, path: &Path) -> Command {
                *self.asked.lock().unwrap() = Some(path.to_path_buf());
                let mut command = Command::new("/bin/sh");
                command.arg("-c").arg(self.script).arg(path);
                command
            }
        }

        /// A directory created the way a launch creates one, with the backup
        /// check answered "excluded" whatever this machine's configuration.
        pub(crate) fn excluded_directory() -> CrashReportDirectory {
            CrashReportDirectory::create_with(&ScriptedQuery::excluded(), EXCLUSION_CHECK_DEADLINE)
                .expect("create a crash-report directory")
        }
    }

    #[cfg(test)]
    mod tests {
        use super::test_support::{excluded_directory, ScriptedQuery};
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        /// A private directory for one test, removed when the test ends.
        struct TestParent(PathBuf);

        impl TestParent {
            fn new(label: &str) -> Self {
                let path = std::env::temp_dir().join(format!(
                    "ck-crash-reports-test-{label}-{}-{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .expect("clock")
                        .as_nanos()
                ));
                std::fs::create_dir(&path).expect("create test parent");
                Self(path)
            }
        }

        impl Drop for TestParent {
            fn drop(&mut self) {
                let _ = std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(0o700));
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }

        fn own_start_time() -> u64 {
            own_generation().expect("this process's start time").1
        }

        #[test]
        fn an_excluded_answer_admits_the_directory() {
            let parent = TestParent::new("excluded");
            assert_eq!(
                check_excluded_from_backup(
                    &ScriptedQuery::excluded(),
                    &parent.0,
                    EXCLUSION_CHECK_DEADLINE
                ),
                Ok(())
            );
        }

        #[test]
        fn a_backed_up_directory_is_refused() {
            let parent = TestParent::new("included");
            assert_eq!(
                check_excluded_from_backup(
                    &ScriptedQuery::included(),
                    &parent.0,
                    EXCLUSION_CHECK_DEADLINE
                ),
                Err(CrashReportRefusal::BackedUp)
            );
        }

        #[test]
        fn a_backup_check_that_does_not_answer_in_time_is_refused_at_its_deadline() {
            let parent = TestParent::new("silent");
            let started = Instant::now();
            let result = check_excluded_from_backup(
                &ScriptedQuery::silent(),
                &parent.0,
                Duration::from_millis(200),
            );
            assert_eq!(result, Err(CrashReportRefusal::ExclusionCheckTimedOut));
            // The query sleeps for 30 s; returning well before that shows the
            // deadline ended the wait rather than the query finishing.
            assert!(
                started.elapsed() < Duration::from_secs(10),
                "the check waited {:?} for a query that never answers",
                started.elapsed()
            );
        }

        #[test]
        fn a_failed_or_unrecognised_answer_is_refused() {
            let parent = TestParent::new("unrecognised");
            for script in ["exit 1", "echo 'something else'", "true"] {
                assert_eq!(
                    check_excluded_from_backup(
                        &ScriptedQuery::new(script),
                        &parent.0,
                        EXCLUSION_CHECK_DEADLINE
                    ),
                    Err(CrashReportRefusal::ExclusionCheckFailed),
                    "{script}"
                );
            }
        }

        #[test]
        fn a_refused_directory_is_deleted_before_the_refusal_returns() {
            for (query, refusal) in [
                (ScriptedQuery::included(), CrashReportRefusal::BackedUp),
                (
                    ScriptedQuery::silent(),
                    CrashReportRefusal::ExclusionCheckTimedOut,
                ),
            ] {
                let result = CrashReportDirectory::create_with(&query, Duration::from_millis(200));
                assert_eq!(result.map(|_| ()), Err(refusal));
                let asked = query.asked.lock().unwrap().clone().expect("the query ran");
                assert!(
                    !asked.exists(),
                    "{} was left behind after a refusal",
                    asked.display()
                );
            }
        }

        #[test]
        fn a_launch_directory_is_owner_only_and_checked_before_it_is_returned() {
            let query = ScriptedQuery::excluded();
            let directory = CrashReportDirectory::create_with(&query, EXCLUSION_CHECK_DEADLINE)
                .expect("create a crash-report directory");
            assert_eq!(
                query.asked.lock().unwrap().as_deref(),
                Some(directory.path()),
                "the backup check must ask about the directory itself"
            );
            let mode = std::fs::metadata(directory.path())
                .expect("directory metadata")
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o700);
            let path = directory.path().to_path_buf();
            directory.remove().expect("remove the directory");
            assert!(!path.exists());
        }

        #[test]
        fn a_launch_directory_names_its_creator_so_a_sweep_keeps_it_while_this_process_runs() {
            let directory = excluded_directory();
            let name = directory
                .path()
                .file_name()
                .and_then(|name| name.to_str())
                .expect("a UTF-8 name")
                .to_string();
            let suffix = name
                .strip_prefix(CRASH_REPORTS_DIRECTORY_PREFIX)
                .expect("the fixed prefix");
            let (pid, start) = parse_creator(suffix).expect("a parseable creator");
            assert_eq!((pid, start), (std::process::id(), own_start_time()));
            assert!(creator_is_running(pid, start));
        }

        #[test]
        fn startup_sweep_removes_a_directory_left_by_a_process_that_is_gone() {
            let parent = TestParent::new("sweep");
            let pid = std::process::id();
            let start = own_start_time();
            // The same pid with a different start time is how a leftover from
            // an earlier process looks once its pid has been reused.
            let leftover = parent.0.join(format!(
                "{CRASH_REPORTS_DIRECTORY_PREFIX}{pid}-{}-0",
                start + 1
            ));
            std::fs::create_dir(&leftover).expect("plant leftover");
            std::fs::write(leftover.join("minidump"), b"page memory").expect("plant report");
            let unparseable = parent
                .0
                .join(format!("{CRASH_REPORTS_DIRECTORY_PREFIX}not-a-creator"));
            std::fs::create_dir(&unparseable).expect("plant unparseable leftover");
            let live = parent
                .0
                .join(format!("{CRASH_REPORTS_DIRECTORY_PREFIX}{pid}-{start}-0"));
            std::fs::create_dir(&live).expect("plant live directory");
            let unrelated = parent.0.join("someone-elses-directory");
            std::fs::create_dir(&unrelated).expect("plant unrelated directory");
            let elsewhere = TestParent::new("sweep-link-target");
            let link = parent.0.join(format!(
                "{CRASH_REPORTS_DIRECTORY_PREFIX}{pid}-{}-1",
                start + 1
            ));
            std::os::unix::fs::symlink(&elsewhere.0, &link).expect("plant symlink");

            let sweep = remove_leftover_directories_in(&parent.0, creator_is_running);

            assert_eq!(
                sweep,
                LeftoverSweep {
                    removed: 2,
                    failed: 0
                }
            );
            assert!(!leftover.exists(), "the leftover directory survived");
            assert!(!unparseable.exists(), "the unparseable leftover survived");
            assert!(live.is_dir(), "a running process's directory was deleted");
            assert!(
                unrelated.is_dir(),
                "a directory without the prefix was deleted"
            );
            assert!(elsewhere.0.is_dir(), "a symlink was followed");
        }

        #[test]
        fn startup_sweep_counts_a_leftover_it_could_not_delete() {
            let parent = TestParent::new("sweep-failure");
            let leftover = parent
                .0
                .join(format!("{CRASH_REPORTS_DIRECTORY_PREFIX}1-1-0"));
            std::fs::create_dir(&leftover).expect("plant leftover");
            std::fs::write(leftover.join("minidump"), b"page memory").expect("plant report");
            // Without write permission on the leftover, its contents cannot
            // be unlinked, so the delete fails.
            std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o500))
                .expect("make leftover unwritable");

            let sweep = remove_leftover_directories_in(&parent.0, |_, _| false);
            std::fs::set_permissions(&leftover, std::fs::Permissions::from_mode(0o700))
                .expect("restore leftover permissions");

            assert_eq!(
                sweep,
                LeftoverSweep {
                    removed: 0,
                    failed: 1
                }
            );
        }
    }
}
