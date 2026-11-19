//! The live `computer_use.app_use` setting.
//!
//! Each call takes the latest effective mode delivered by the daemon. A
//! foreground setting that the daemon did not attest as approved still needs
//! the person's operator confirmation, held only in memory.
//!
//! The legacy fallback costs one `stat` of the config file per call. When the file's
//! modification time is the one seen last time, the mode read last time is used
//! and nothing else happens. When it changed, the whole file is parsed again
//! with [`parse_config`], the same parser registration uses, so an edit that
//! breaks any key, or breaks the JSONC itself, is caught rather than read
//! around. A missing file means the default, background.
//!
//! A file that exists but cannot be read or parsed leaves the mode unknown.
//! Then every `computer_use` action refuses `config_invalid`, naming the file
//! and the error, until the file parses again: guessing a mode the person did
//! not choose could bring their apps to the front, or keep them in the
//! background, against their stated wish. Other tools never read this, and
//! registration is never re-run.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex as StdMutex};
use std::time::SystemTime;

use cerebellum_core::config::{parse_config, AppUse};
use serde_json::{json, Value};

use crate::settings::LiveSettings;

/// The two file operations the live read needs, so tests can supply a file
/// system whose modification times and contents they control.
pub(crate) trait ConfigFiles: Send + Sync {
    /// The file's last modification time: one `stat`.
    fn modified(&self, path: &Path) -> io::Result<SystemTime>;
    /// The file's whole contents.
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
}

/// The real file system.
struct NativeConfigFiles;

impl ConfigFiles for NativeConfigFiles {
    fn modified(&self, path: &Path) -> io::Result<SystemTime> {
        std::fs::metadata(path)?.modified()
    }

    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        std::fs::read_to_string(path)
    }
}

/// A config file that has always said `"app_use": "foreground"`.
struct ForegroundFile;

impl ConfigFiles for ForegroundFile {
    fn modified(&self, _path: &Path) -> io::Result<SystemTime> {
        Ok(SystemTime::UNIX_EPOCH)
    }

    fn read_to_string(&self, _path: &Path) -> io::Result<String> {
        Ok(r#"{"computer_use":{"app_use":"foreground"}}"#.to_owned())
    }
}

/// Why the mode could not be read: the file exists but did not parse, or
/// reading it failed for a reason other than its absence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigInvalid {
    pub(crate) path: PathBuf,
    pub(crate) error: String,
}

impl ConfigInvalid {
    /// The refusal every `computer_use` action gives while the file is
    /// unreadable. Nothing was looked up or dispatched.
    pub(crate) fn reply(&self) -> Value {
        json!({
            "outcome": "config_invalid",
            "remedy": format!(
                "The cerebellum config file {} could not be used: {}. No computer_use action \
                 runs until it parses again. Fix the file; the next call reads it again without \
                 a restart.",
                self.path.display(),
                self.error,
            ),
        })
    }
}

/// What the last `stat` saw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stamp {
    Absent,
    Modified(SystemTime),
}

/// The last outcome, kept with the stamp it was read under.
struct Reading {
    stamp: Stamp,
    outcome: Result<AppUse, ConfigInvalid>,
}

/// Defaults to background without reading a file. Only the legacy daemon
/// path can install a file source; managed settings replace that source.
pub(crate) struct LiveAppUse {
    state: StdMutex<State>,
    /// Only one caller reloads at a time, even if the awaiting call is cancelled.
    reload: Arc<tokio::sync::Semaphore>,
    approval: super::app_use_approval::Approval,
}

struct State {
    legacy: Option<Arc<LegacyFile>>,
    managed: LiveSettings,
}

struct LegacyFile {
    path: PathBuf,
    files: Arc<dyn ConfigFiles>,
    last: StdMutex<Option<Reading>>,
}

impl LegacyFile {
    fn new(path: PathBuf, files: Arc<dyn ConfigFiles>) -> Self {
        Self {
            path,
            files,
            last: StdMutex::new(None),
        }
    }

    fn settings(&self) -> Result<LiveSettings, ConfigInvalid> {
        let mut last = self
            .last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        read(&self.path, self.files.as_ref(), &mut last).map(|app_use| LiveSettings {
            app_use,
            approved: false,
        })
    }
}

impl LiveAppUse {
    pub(crate) fn new(path: Option<PathBuf>, files: Arc<dyn ConfigFiles>) -> Self {
        Self {
            approval: super::app_use_approval::Approval::default(),
            reload: Arc::new(tokio::sync::Semaphore::new(1)),
            state: StdMutex::new(State {
                legacy: path.map(|path| Arc::new(LegacyFile::new(path, files))),
                managed: LiveSettings::default(),
            }),
        }
    }

    /// Reading no file: every call is background.
    pub(crate) fn without_file() -> Self {
        Self::new(None, Arc::new(NativeConfigFiles))
    }

    /// Every call foreground, whatever any config file says: for tests about
    /// the on-screen badge, which background mode never draws.
    pub(crate) fn foreground_for_test() -> Self {
        let mut live = Self::new(
            Some(PathBuf::from("/fixed/app_use/foreground.jsonc")),
            Arc::new(ForegroundFile),
        );
        live.approval = super::app_use_approval::Approval::foreground_fixture();
        live
    }

    #[cfg(any(test, target_os = "macos", target_os = "windows"))]
    pub(crate) fn read_config_file(&self, path: PathBuf) {
        let mut state = self.lock();
        state.legacy = Some(Arc::new(LegacyFile::new(path, Arc::new(NativeConfigFiles))));
        self.approval.observe(None);
    }

    #[cfg(any(test, target_os = "macos", target_os = "windows"))]
    pub(crate) fn apply(&self, settings: LiveSettings) {
        let mut state = self.lock();
        state.legacy = None;
        state.managed = settings;
        self.approval
            .observe((!settings.approved).then_some(settings.app_use));
    }

    /// The file calls are read from, if any.
    #[cfg(test)]
    pub(crate) fn path(&self) -> Option<PathBuf> {
        self.lock().legacy.as_ref().map(|file| file.path.clone())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The mode for the call about to run.
    #[cfg(test)]
    pub(crate) fn current(&self) -> Result<AppUse, ConfigInvalid> {
        self.current_settings().map(|settings| settings.app_use)
    }

    #[cfg(test)]
    pub(crate) fn current_settings(&self) -> Result<LiveSettings, ConfigInvalid> {
        let state = self.lock();
        self.observe(
            state
                .legacy
                .as_ref()
                .map_or(Ok(state.managed), |file| file.settings()),
        )
    }

    pub(crate) async fn settings_for_call(&self) -> Result<LiveSettings, ConfigInvalid> {
        loop {
            if let Some(settings) = self.managed_settings() {
                return settings;
            }
            let permit = self
                .reload
                .clone()
                .acquire_owned()
                .await
                .expect("reload gate is never closed");
            let file = {
                let state = self.lock();
                let Some(file) = &state.legacy else {
                    return self.observe(Ok(state.managed));
                };
                file.clone()
            };
            let reading = file.clone();
            let result = tokio::task::spawn_blocking(move || (permit, reading.settings())).await;
            let state = self.lock();
            if state
                .legacy
                .as_ref()
                .is_none_or(|current| !Arc::ptr_eq(current, &file))
            {
                // The daemon replaced the legacy source during the reload.
                continue;
            }
            return match result {
                Ok((_permit, outcome)) => self.observe(outcome),
                Err(error) => self.observe(Err(ConfigInvalid {
                    path: file.path.clone(),
                    error: format!("its settings reload did not complete: {error}"),
                })),
            };
        }
    }

    fn managed_settings(&self) -> Option<Result<LiveSettings, ConfigInvalid>> {
        let state = self.lock();
        state
            .legacy
            .is_none()
            .then(|| self.observe(Ok(state.managed)))
    }

    fn observe(
        &self,
        outcome: Result<LiveSettings, ConfigInvalid>,
    ) -> Result<LiveSettings, ConfigInvalid> {
        self.approval.observe(
            outcome
                .as_ref()
                .ok()
                .filter(|settings| !settings.approved)
                .map(|settings| settings.app_use),
        );
        outcome
    }

    pub(crate) async fn approved_mode(
        &self,
        settings: LiveSettings,
        cancel: &crate::CancelHandle,
    ) -> AppUse {
        if settings.approved {
            settings.app_use
        } else {
            self.approval.resolve(settings.app_use, cancel).await
        }
    }

    #[cfg(test)]
    pub(super) fn approve_fixture(&self) {
        let _ = self.current();
        self.approval.approve_fixture();
    }
}

fn read(
    path: &Path,
    files: &dyn ConfigFiles,
    last: &mut Option<Reading>,
) -> Result<AppUse, ConfigInvalid> {
    let stamp = match files.modified(path) {
        Ok(modified) => Stamp::Modified(modified),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Stamp::Absent,
        Err(error) => {
            // Nothing is kept: the next call stats again and, once the
            // file can be read, parses it whatever its time says.
            *last = None;
            return Err(ConfigInvalid {
                path: path.to_path_buf(),
                error: format!("reading its metadata failed: {error}"),
            });
        }
    };
    if let Some(reading) = last.as_ref().filter(|reading| reading.stamp == stamp) {
        return reading.outcome.clone();
    }
    let (stamp, outcome) = match stamp {
        Stamp::Absent => (Stamp::Absent, Ok(AppUse::Background)),
        Stamp::Modified(_) => match files.read_to_string(path) {
            Ok(text) => (
                stamp,
                parse_config(&text)
                    .map(|config| config.computer_use.app_use)
                    .map_err(|error| ConfigInvalid {
                        path: path.to_path_buf(),
                        error: error.to_string(),
                    }),
            ),
            // Removed between the stat and the read: the same as
            // absent, and kept as absent so a file created later is
            // parsed when it appears.
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                (Stamp::Absent, Ok(AppUse::Background))
            }
            Err(error) => {
                *last = None;
                return Err(ConfigInvalid {
                    path: path.to_path_buf(),
                    error: format!("reading it failed: {error}"),
                });
            }
        },
    };
    *last = Some(Reading {
        stamp,
        outcome: outcome.clone(),
    });
    outcome
}

tokio::task_local! {
    /// The mode the running `computer_use` call was admitted under, read once
    /// when the call arrived so every step of the call agrees on it.
    static CALL_APP_USE: AppUse;
}

/// Run `work` as a call whose mode is `mode`.
pub(crate) async fn scope<F: std::future::Future>(mode: AppUse, work: F) -> F::Output {
    CALL_APP_USE.scope(mode, work).await
}

/// The mode of the `computer_use` call this task is serving, or `None`
/// outside one.
// Only this crate's tests read it so far. Code that acts differently in the
// two modes reads the call's mode through this function.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn call_mode() -> Option<AppUse> {
    CALL_APP_USE.try_with(|mode| *mode).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// One config file whose modification time only changes when a test says
    /// so, with a count of every stat and read made against it.
    #[derive(Default)]
    pub(super) struct FakeFiles {
        state: StdMutex<FakeState>,
    }

    #[derive(Default)]
    struct FakeState {
        /// `None` is a missing file.
        file: Option<(SystemTime, String)>,
        stat_error: Option<io::ErrorKind>,
        read_error: Option<io::ErrorKind>,
        stats: usize,
        reads: usize,
    }

    pub(super) fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000 + seconds)
    }

    impl FakeFiles {
        /// Write the file, giving it modification time `modified`.
        pub(super) fn write(&self, modified: SystemTime, text: &str) {
            self.state.lock().unwrap().file = Some((modified, text.to_owned()));
        }

        /// Replace the contents while keeping the modification time.
        fn rewrite_keeping_time(&self, text: &str) {
            let mut state = self.state.lock().unwrap();
            let modified = state.file.as_ref().unwrap().0;
            state.file = Some((modified, text.to_owned()));
        }

        pub(super) fn delete(&self) {
            self.state.lock().unwrap().file = None;
        }

        fn fail_stats(&self, kind: Option<io::ErrorKind>) {
            self.state.lock().unwrap().stat_error = kind;
        }

        fn fail_reads(&self, kind: Option<io::ErrorKind>) {
            self.state.lock().unwrap().read_error = kind;
        }

        /// Stats and reads made so far.
        pub(super) fn counts(&self) -> (usize, usize) {
            let state = self.state.lock().unwrap();
            (state.stats, state.reads)
        }
    }

    impl ConfigFiles for FakeFiles {
        fn modified(&self, _path: &Path) -> io::Result<SystemTime> {
            let mut state = self.state.lock().unwrap();
            state.stats += 1;
            if let Some(kind) = state.stat_error {
                return Err(io::Error::new(kind, "stat refused"));
            }
            state
                .file
                .as_ref()
                .map(|(modified, _)| *modified)
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }

        fn read_to_string(&self, _path: &Path) -> io::Result<String> {
            let mut state = self.state.lock().unwrap();
            state.reads += 1;
            if let Some(kind) = state.read_error {
                return Err(io::Error::new(kind, "read refused"));
            }
            state
                .file
                .as_ref()
                .map(|(_, text)| text.clone())
                .ok_or_else(|| io::Error::from(io::ErrorKind::NotFound))
        }
    }

    pub(super) const PATH: &str = "/fixture/home/.config/cortexkit/cerebellum.jsonc";
    pub(super) const FOREGROUND: &str = r#"{"computer_use":{"app_use":"foreground"}}"#;
    pub(super) const BACKGROUND: &str = r#"{"computer_use":{"app_use":"background"}}"#;

    pub(super) fn live() -> (LiveAppUse, Arc<FakeFiles>) {
        let files = Arc::new(FakeFiles::default());
        (
            LiveAppUse::new(Some(PathBuf::from(PATH)), files.clone()),
            files,
        )
    }

    #[test]
    fn a_missing_file_is_background_at_one_stat_per_call() {
        let (live, files) = live();
        for call in 1..=3 {
            assert_eq!(live.current(), Ok(AppUse::Background));
            assert_eq!(files.counts(), (call, 0));
        }
    }

    #[test]
    fn no_config_directory_is_background_without_any_file_access() {
        let files = Arc::new(FakeFiles::default());
        files.write(at(0), FOREGROUND);
        let live = LiveAppUse::new(None, files.clone());
        assert_eq!(live.current(), Ok(AppUse::Background));
        assert_eq!(files.counts(), (0, 0));
    }

    #[test]
    fn an_unchanged_time_uses_the_cached_mode_and_reads_nothing() {
        let (live, files) = live();
        files.write(at(0), FOREGROUND);
        assert_eq!(live.current(), Ok(AppUse::Foreground));
        assert_eq!(files.counts(), (1, 1));
        // Contents that would now parse to background are not read while the
        // time is unchanged: the call costs its one stat and nothing more.
        files.rewrite_keeping_time(BACKGROUND);
        for call in 2..=4 {
            assert_eq!(live.current(), Ok(AppUse::Foreground));
            assert_eq!(files.counts(), (call, 1));
        }
    }

    #[test]
    fn a_changed_time_re_parses_and_applies_to_that_call() {
        let (live, files) = live();
        files.write(at(0), BACKGROUND);
        assert_eq!(live.current(), Ok(AppUse::Background));
        files.write(at(1), FOREGROUND);
        assert_eq!(live.current(), Ok(AppUse::Foreground));
        assert_eq!(files.counts(), (2, 2));
        // A file without the key is background again.
        files.write(at(2), r#"{"computer_use":{"agent_cursor":false}}"#);
        assert_eq!(live.current(), Ok(AppUse::Background));
        // An earlier time is a change too: only equality is reused.
        files.write(at(1), FOREGROUND);
        assert_eq!(live.current(), Ok(AppUse::Foreground));
        assert_eq!(files.counts(), (4, 4));
    }

    #[test]
    fn a_deleted_file_is_background_and_a_recreated_one_is_read() {
        let (live, files) = live();
        files.write(at(0), FOREGROUND);
        assert_eq!(live.current(), Ok(AppUse::Foreground));
        files.delete();
        assert_eq!(live.current(), Ok(AppUse::Background));
        assert_eq!(live.current(), Ok(AppUse::Background));
        assert_eq!(files.counts(), (3, 1));
        // Recreated with the time it had before deletion: still read, since
        // the last stat saw no file at all.
        files.write(at(0), FOREGROUND);
        assert_eq!(live.current(), Ok(AppUse::Foreground));
        assert_eq!(files.counts(), (4, 2));
    }

    #[test]
    fn a_file_removed_between_stat_and_read_is_background() {
        let (live, files) = live();
        files.write(at(0), FOREGROUND);
        files.fail_reads(Some(io::ErrorKind::NotFound));
        assert_eq!(live.current(), Ok(AppUse::Background));
        // Kept as absent, so the same time is read again once readable.
        files.fail_reads(None);
        assert_eq!(live.current(), Ok(AppUse::Foreground));
    }

    /// Each way the whole-file parse can fail refuses with the file and the
    /// parser's own message, keeps refusing while the file is unchanged, and
    /// clears on the call after the file is fixed.
    #[test]
    fn a_parse_failure_refuses_naming_the_file_and_error_until_fixed() {
        for (broken, error) in [
            (
                r#"{"computer_use":{"app_use":"front"}}"#,
                r#"computer_use.app_use: expected one of "background", "foreground""#,
            ),
            (
                r#"{"computer_use":{"app_use":"foreground","colour":"blue"}}"#,
                "computer_use: unknown member `colour`",
            ),
            (
                r#"{"health":{"queue_age_stale_ms":0},"computer_use":{"app_use":"foreground"}}"#,
                "queue_age_stale_ms: expected a positive integer (got zero or negative)",
            ),
            (
                r#"{"computer_use":{"app_use":"foreground""#,
                "config: malformed document",
            ),
        ] {
            let (live, files) = live();
            files.write(at(0), FOREGROUND);
            assert_eq!(live.current(), Ok(AppUse::Foreground));
            files.write(at(1), broken);
            let refusal = live.current().unwrap_err();
            assert_eq!(refusal.path, PathBuf::from(PATH), "{broken}");
            assert!(refusal.error.contains(error), "{broken}: {}", refusal.error);
            let remedy = refusal.reply()["remedy"].as_str().unwrap().to_owned();
            assert!(remedy.contains(PATH) && remedy.contains(&refusal.error));
            assert_eq!(refusal.reply()["outcome"], "config_invalid");
            // Unchanged: the same refusal, from the cache.
            assert_eq!(live.current(), Err(refusal));
            assert_eq!(files.counts(), (3, 2), "{broken}");
            files.write(at(2), BACKGROUND);
            assert_eq!(live.current(), Ok(AppUse::Background), "{broken}");
        }
    }

    #[test]
    fn a_read_error_other_than_absence_refuses_and_retries_each_call() {
        for (stat, read) in [
            (Some(io::ErrorKind::PermissionDenied), None),
            (None, Some(io::ErrorKind::PermissionDenied)),
        ] {
            let (live, files) = live();
            files.write(at(0), FOREGROUND);
            files.fail_stats(stat);
            files.fail_reads(read);
            for _ in 0..2 {
                let refusal = live.current().unwrap_err();
                assert_eq!(refusal.path, PathBuf::from(PATH));
                assert!(refusal.error.contains("refused"), "{}", refusal.error);
            }
            // Nothing was cached, so the file is parsed as soon as it can be
            // read, though its time never changed.
            files.fail_stats(None);
            files.fail_reads(None);
            assert_eq!(live.current(), Ok(AppUse::Foreground));
        }
    }

    #[tokio::test]
    async fn the_call_mode_is_set_only_inside_its_scope() {
        assert_eq!(call_mode(), None);
        assert_eq!(
            scope(AppUse::Foreground, async { call_mode() }).await,
            Some(AppUse::Foreground)
        );
        assert_eq!(call_mode(), None);
    }
}

/// The setting as the plane serves it: checked on every row before anything
/// else, and live across edits made while the plane keeps running.
#[cfg(test)]
mod serve_tests {
    use super::tests::{at, live, BACKGROUND, FOREGROUND, PATH};
    use super::*;
    use crate::computer_capability::{
        permissions, servable, ComputerPlane, ResultSchemaEnforcement, ServeContext,
    };
    use cerebellum_computer::audit::redaction::ExcludeApplicationText;
    use cerebellum_computer::audit::{ComputerAudit, ComputerCapability};
    use cerebellum_computer::capture::InMemoryCaptureBackend;
    use cerebellum_computer::capture_custody::{
        CaptureCustody, CustodyBounds, InMemoryCustodyStorage, InMemoryGrantAuthority,
    };
    use cerebellum_computer::platform::TargetResolution;
    use cerebellum_core::clock::FakeClock;
    use cerebellum_core::journal::{
        InMemoryJournalStorage, JournalConfig, JournalIdentity, ValidatedSeverityTaxonomy,
    };
    use std::sync::atomic::{AtomicUsize, Ordering};

    type Plane = ComputerPlane<
        InMemoryCaptureBackend,
        ExcludeApplicationText,
        ValidatedSeverityTaxonomy,
        InMemoryJournalStorage,
    >;

    /// Counts target lookups, so a test can tell a refusal came before any.
    struct CountingResolver(Arc<AtomicUsize>);

    impl crate::management::TargetResolver for CountingResolver {
        fn resolve(&self, _bundle_identity: &str) -> TargetResolution {
            self.0.fetch_add(1, Ordering::SeqCst);
            TargetResolution::NotRunning
        }
    }

    fn audit(
    ) -> ComputerAudit<ExcludeApplicationText, ValidatedSeverityTaxonomy, InMemoryJournalStorage>
    {
        let custody = CaptureCustody::new(
            CustodyBounds {
                maximum_verification_duration_ms: 100,
                maximum_pin_lifetime_ms: 100,
                maximum_concurrently_pinned_artifacts: 2,
                maximum_total_pinned_artifact_bytes: 1000,
                maximum_custody_attachment_bytes: 1000,
            },
            InMemoryGrantAuthority::default(),
            InMemoryCustodyStorage::new(),
        )
        .unwrap();
        ComputerAudit::new(
            ExcludeApplicationText,
            cerebellum_computer::platform::severity::load_severity_taxonomy().unwrap(),
            JournalConfig {
                journal_retention_bytes: 20000,
                journal_max_entry_bytes: 4000,
            },
            InMemoryJournalStorage::default(),
            custody,
        )
        .unwrap()
    }

    fn plane(live: LiveAppUse) -> Plane {
        // Detect-only: the frozen result schemas predate `config_invalid`, and
        // these tests are about when the refusal is given, not its schema.
        ComputerPlane::with_result_schema_enforcement(audit(), ResultSchemaEnforcement::DetectOnly)
            .with_permission_liveness(permissions::live_for_test())
            .with_app_use(live)
    }

    /// Test binaries and examples build planes with these same
    /// constructors, so none of them may read the config file of whoever
    /// runs them. Only legacy startup explicitly installs a file source.
    #[test]
    fn a_plane_from_any_constructor_reads_no_config_file() {
        let planes: [Plane; 3] = [
            ComputerPlane::new(audit()),
            ComputerPlane::with_result_schema_enforcement(
                audit(),
                ResultSchemaEnforcement::Withhold,
            ),
            ComputerPlane::with_synthetic_driver(
                audit(),
                cerebellum_computer::platform::UnsupportedPlatformDriver::new,
            ),
        ];
        for plane in planes {
            assert_eq!(plane.app_use_config_path_for_test(), None);
            let path = PathBuf::from("fixture-settings.jsonc");
            plane.read_app_use_from_config_file(path.clone());
            assert_eq!(plane.app_use_config_path_for_test(), Some(path));
        }
    }

    fn identity() -> JournalIdentity {
        JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: "prefrontal".into(),
            conversation_key: "conversation-1".into(),
            agent_project_id: "project-1".into(),
            session_kind: cerebellum_core::identity::SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        }
    }

    async fn serve(
        plane: &Plane,
        management: &Arc<crate::management::ManagementPlane>,
        capability_id: &str,
        arguments: Value,
    ) -> Value {
        let clock = FakeClock::new();
        plane
            .serve(
                servable(capability_id).unwrap(),
                &arguments,
                ServeContext {
                    cancel: crate::CancelHandle::for_uninterruptible_probe(),
                    grantee: "project-1",
                    identity: identity(),
                    management,
                    consent: crate::computer_grants::ConsentContext::without_carrier(
                        crate::computer_grants::GrantCaller::new(
                            "conversation-1".into(),
                            "project-1".into(),
                            false,
                        ),
                    ),
                    clock: &clock,
                    now_ms: 10,
                },
                |_| InMemoryCaptureBackend::default(),
            )
            .await
            .expect("detect-only serving returns every reply")
    }

    fn management() -> (Arc<crate::management::ManagementPlane>, Arc<AtomicUsize>) {
        let lookups = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(crate::management::ManagementPlane::new(Arc::new(
                CountingResolver(lookups.clone()),
            ))),
            lookups,
        )
    }

    fn wait_arguments() -> Value {
        json!({
            "app": "com.example.Editor",
            "predicate": "element_enabled_is true Role:Title=AXButton:Save",
            "timeout_ms": 0,
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_stalled_legacy_stat_does_not_block_other_async_work() {
        struct StalledStat {
            entered: StdMutex<Option<tokio::sync::oneshot::Sender<()>>>,
            release: StdMutex<std::sync::mpsc::Receiver<()>>,
            released_by_task: Arc<std::sync::atomic::AtomicBool>,
        }

        impl ConfigFiles for StalledStat {
            fn modified(&self, _path: &Path) -> io::Result<SystemTime> {
                self.entered
                    .lock()
                    .unwrap()
                    .take()
                    .unwrap()
                    .send(())
                    .unwrap();
                let result = self
                    .release
                    .lock()
                    .unwrap()
                    .recv_timeout(crate::test_support::HANG_GUARD);
                self.released_by_task
                    .store(result.is_ok(), Ordering::SeqCst);
                Err(io::ErrorKind::NotFound.into())
            }

            fn read_to_string(&self, _path: &Path) -> io::Result<String> {
                panic!("the absent file is not read")
            }
        }

        let (entered, wait_for_stat) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        let released_by_task = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let files = Arc::new(StalledStat {
            entered: StdMutex::new(Some(entered)),
            release: StdMutex::new(released),
            released_by_task: released_by_task.clone(),
        });
        let plane = plane(LiveAppUse::new(Some(PathBuf::from(PATH)), files));
        let (management, _) = management();
        let other_task = tokio::spawn(async move {
            wait_for_stat.await.unwrap();
            release.send(()).unwrap();
        });
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        other_task.await.unwrap();
        assert!(
            released_by_task.load(Ordering::SeqCst),
            "the stat had to time out before the executor could advance"
        );
    }

    #[tokio::test]
    async fn an_unapproved_foreground_setting_reaches_serve_only_as_background() {
        let (live, files) = live();
        files.write(at(1), FOREGROUND);
        let plane = plane(live);
        let (management, _) = management();
        let note = crate::tool_result::APP_USE_NOTE
            .scope(std::cell::RefCell::new(None), async {
                serve(&plane, &management, "computer.wait", wait_arguments()).await;
                crate::tool_result::APP_USE_NOTE
                    .with(|note| note.borrow().clone())
                    .unwrap()
            })
            .await;
        assert_eq!(
            *plane.app_use_seen_for_test.lock().unwrap(),
            [Some(AppUse::Background)]
        );
        assert!(
            note.contains("unsupported"),
            "a call without a daemon carrier explains the fallback"
        );
    }

    /// Every served row, `wait`, `list_apps` and the four takeover actions
    /// included, refuses before lookup, journaling or any work while the file
    /// does not parse.
    #[tokio::test]
    async fn every_action_refuses_config_invalid_while_the_file_does_not_parse() {
        let (live, files) = live();
        files.write(at(0), r#"{"computer_use":{"app_use":"sideways"}}"#);
        let plane = plane(live);
        let (management, lookups) = management();
        let mut served = std::collections::BTreeSet::new();
        for capability in ComputerCapability::ALL {
            if servable(capability.capability_id()).is_none() {
                continue;
            }
            let before = plane.journal_entry_count().await;
            let reply = serve(&plane, &management, capability.capability_id(), json!({})).await;
            let id = capability.capability_id();
            assert_eq!(reply["outcome"], "config_invalid", "{id}: {reply}");
            assert!(served.insert(id), "{id} was checked twice");
            let remedy = reply["remedy"].as_str().unwrap();
            assert!(remedy.contains(PATH), "{id}: {remedy}");
            assert!(
                remedy.contains(
                    r#"computer_use.app_use: expected one of "background", "foreground""#
                ),
                "{id}: {remedy}"
            );
            if matches!(
                capability,
                ComputerCapability::Type | ComputerCapability::Keys
            ) {
                assert_eq!(reply["effect_status"], "not_dispatched", "{id}: {reply}");
            }
            assert_eq!(plane.journal_entry_count().await, before, "{id}");
        }
        assert_eq!(served.len(), 13, "every served row was checked");
        assert!(
            served.contains("computer.takeover_click"),
            "click must reach the config-invalid refusal"
        );
        assert_eq!(lookups.load(Ordering::SeqCst), 0);
        assert!(
            plane.app_use_seen_for_test.lock().unwrap().is_empty(),
            "no call's work began"
        );
        // One stat per call and one parse in all: the file never changed.
        assert_eq!(files.counts(), (13, 1));
    }

    /// The file is edited between calls to one plane that keeps running: each
    /// call works under the mode the file held when it arrived, a broken edit
    /// refuses, and fixing the file clears the refusal, all without a restart.
    #[tokio::test]
    async fn a_live_edit_reaches_the_next_call_without_a_restart() {
        let (live, files) = live();
        let plane = plane(live);
        let (management, _) = management();
        let seen = || plane.app_use_seen_for_test.lock().unwrap().clone();

        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(seen(), [Some(AppUse::Background)], "no file is background");

        files.write(at(1), FOREGROUND);
        // This test isolates reloads; supply operator approval explicitly.
        plane.app_use.approve_fixture();
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(seen().last(), Some(&Some(AppUse::Foreground)));

        files.write(at(2), r#"{"computer_use":{"app_use":"foreground""#);
        let reply = serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(reply["outcome"], "config_invalid", "{reply}");
        assert_eq!(seen().len(), 2, "the refused call did no work");

        files.write(at(3), BACKGROUND);
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(seen().last(), Some(&Some(AppUse::Background)));

        files.write(at(4), FOREGROUND);
        plane.app_use.approve_fixture();
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        files.delete();
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(
            seen(),
            [
                Some(AppUse::Background),
                Some(AppUse::Foreground),
                Some(AppUse::Background),
                Some(AppUse::Foreground),
                Some(AppUse::Background),
            ]
        );
    }

    /// Only `app_use` is live. An edit turning the agent cursor off is read
    /// with the file, but nothing acts on it: the cursor a running plane was
    /// started with stays as it was until the module restarts.
    #[tokio::test]
    async fn an_edit_to_agent_cursor_changes_nothing_while_running() {
        let (live, files) = live();
        let (cursor, mut lines) = crate::computer_capability::cursor::Coordinator::channel();
        let plane = plane(live).with_cursor(cursor);
        let (management, _) = management();
        files.write(
            at(1),
            r#"{"computer_use":{"agent_cursor":false,"app_use":"foreground"}}"#,
        );
        plane.app_use.approve_fixture();
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(
            plane.app_use_seen_for_test.lock().unwrap().as_slice(),
            [Some(AppUse::Foreground)]
        );
        // Turning the cursor off sends its transport a wake line; none came.
        assert!(lines.try_recv().is_err());
    }

    /// A file system whose every operation fails, to show that a plane serving
    /// with no config directory never touches the file system at all.
    struct NoFiles;

    impl ConfigFiles for NoFiles {
        fn modified(&self, _path: &Path) -> io::Result<SystemTime> {
            panic!("no config path, so nothing may be stat'ed")
        }

        fn read_to_string(&self, _path: &Path) -> io::Result<String> {
            panic!("no config path, so nothing may be read")
        }
    }

    #[tokio::test]
    async fn without_a_config_directory_every_call_is_background() {
        let plane = plane(LiveAppUse::new(None, Arc::new(NoFiles)));
        let (management, _) = management();
        serve(&plane, &management, "computer.wait", wait_arguments()).await;
        assert_eq!(
            plane.app_use_seen_for_test.lock().unwrap().as_slice(),
            [Some(AppUse::Background)]
        );
    }
}
