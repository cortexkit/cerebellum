//! In-memory stand-ins for every seam a capture touches, shared by this
//! module's tests and the management-dispatch tests in `lib.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use cerebellum_core::identity::AcceptedBindFacts;

use super::{
    BackupExclusion, CaptureBrowser, CaptureDriveError, CaptureEnv, CaptureFs,
    CaptureLaunchRefusal, CaptureLauncher, CaptureModule, CapturePlacement, CookieHeader,
    CookieHeaderError, DeletionScheduler, ResidueEntry, ToolError, WallClock,
};

/// A value planted in the fake browser's cookies so leak tests can look for it.
pub(crate) const PLANTED_VALUE: &str = "ck-planted-cookie-value-9e3b71";
pub(crate) const ROOT: &str = "/fake-tmp/ck-cerebellum-capture";

/// One ordered log every fake writes to, so a test can read the sequence of
/// effects across seams.
#[derive(Clone, Default)]
pub(crate) struct Events(Arc<Mutex<Vec<String>>>);

impl Events {
    pub(crate) fn push(&self, event: impl Into<String>) {
        self.0.lock().unwrap().push(event.into());
    }

    pub(crate) fn snapshot(&self) -> Vec<String> {
        self.0.lock().unwrap().clone()
    }

    pub(crate) fn contains_prefix(&self, prefix: &str) -> bool {
        self.snapshot()
            .iter()
            .any(|event| event.starts_with(prefix))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FakeEntry {
    Dir,
    File(Vec<u8>),
}

pub(crate) struct FakeFs {
    pub(crate) entries: Mutex<BTreeMap<PathBuf, (FakeEntry, SystemTime)>>,
    pub(crate) events: Events,
    pub(crate) clock: Arc<FakeClock>,
    /// Paths whose removal fails with PermissionDenied.
    pub(crate) undeletable: Mutex<BTreeSet<PathBuf>>,
    /// Every directory removal fails.
    pub(crate) directories_undeletable: AtomicBool,
    /// Held inside each directory removal, so a test can see whether anything
    /// raced past it.
    pub(crate) removal_delay: Mutex<Duration>,
}

impl FakeFs {
    pub(crate) fn new(events: Events, clock: Arc<FakeClock>) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            events,
            clock,
            undeletable: Mutex::new(BTreeSet::new()),
            directories_undeletable: AtomicBool::new(false),
            removal_delay: Mutex::new(Duration::ZERO),
        }
    }

    pub(crate) fn plant(&self, path: &Path, entry: FakeEntry, modified: SystemTime) {
        self.entries
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), (entry, modified));
    }

    pub(crate) fn exists(&self, path: &Path) -> bool {
        self.entries.lock().unwrap().contains_key(path)
    }

    /// Every entry other than the capture root itself.
    pub(crate) fn contents(&self) -> Vec<(PathBuf, FakeEntry)> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.as_path() != Path::new(ROOT))
            .map(|(path, (entry, _))| (path.clone(), entry.clone()))
            .collect()
    }

    pub(crate) fn files(&self) -> Vec<(PathBuf, Vec<u8>)> {
        self.contents()
            .into_iter()
            .filter_map(|(path, entry)| match entry {
                FakeEntry::File(bytes) => Some((path, bytes)),
                FakeEntry::Dir => None,
            })
            .collect()
    }

    fn refuse_removal(&self, path: &Path) -> bool {
        self.undeletable.lock().unwrap().contains(path)
    }
}

impl CaptureFs for FakeFs {
    fn prepare_root(&self, root: &Path) -> io::Result<()> {
        self.events.push("prepare_root");
        self.entries
            .lock()
            .unwrap()
            .entry(root.to_path_buf())
            .or_insert((FakeEntry::Dir, self.clock.now()));
        Ok(())
    }

    fn residue(&self, root: &Path) -> io::Result<Vec<ResidueEntry>> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.parent() == Some(root))
            .map(|(path, (entry, modified))| ResidueEntry {
                path: path.clone(),
                is_dir: *entry == FakeEntry::Dir,
                modified: Some(*modified),
            })
            .collect())
    }

    fn create_profile_dir(&self, path: &Path) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(path) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        entries.insert(path.to_path_buf(), (FakeEntry::Dir, self.clock.now()));
        self.events.push("profile_created");
        Ok(())
    }

    fn write_new_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(path) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        entries.insert(
            path.to_path_buf(),
            (FakeEntry::File(bytes.to_vec()), self.clock.now()),
        );
        self.events.push("file_written");
        Ok(())
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        if self.refuse_removal(path) {
            self.events.push("file_delete_failed");
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        match self.entries.lock().unwrap().remove(path) {
            Some(_) => {
                self.events.push("file_deleted");
                Ok(())
            }
            None => Err(io::ErrorKind::NotFound.into()),
        }
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        let delay = *self.removal_delay.lock().unwrap();
        if !delay.is_zero() {
            std::thread::sleep(delay);
        }
        if self.refuse_removal(path) || self.directories_undeletable.load(Ordering::SeqCst) {
            self.events.push("profile_delete_failed");
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        let mut entries = self.entries.lock().unwrap();
        let before = entries.len();
        entries.retain(|entry, _| !entry.starts_with(path));
        if entries.len() == before {
            return Err(io::ErrorKind::NotFound.into());
        }
        self.events.push("profile_deleted");
        Ok(())
    }
}

pub(crate) struct FakeExclusion {
    pub(crate) answer: Mutex<Result<bool, ToolError>>,
    pub(crate) add_fails: Mutex<Option<ToolError>>,
    pub(crate) events: Events,
}

impl BackupExclusion for FakeExclusion {
    fn tool_name(&self) -> &'static str {
        "tmutil"
    }

    fn add_exclusion(&self, _path: &Path) -> Result<(), ToolError> {
        self.events.push("tmutil_addexclusion");
        match *self.add_fails.lock().unwrap() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    fn is_excluded(&self, _path: &Path) -> Result<bool, ToolError> {
        self.events.push("tmutil_isexcluded");
        *self.answer.lock().unwrap()
    }
}

pub(crate) struct FakeClock(pub(crate) Mutex<SystemTime>);

impl FakeClock {
    pub(crate) fn at(time: SystemTime) -> Self {
        Self(Mutex::new(time))
    }

    pub(crate) fn advance(&self, by: Duration) {
        let mut now = self.0.lock().unwrap();
        *now += by;
    }
}

impl WallClock for FakeClock {
    fn now(&self) -> SystemTime {
        *self.0.lock().unwrap()
    }
}

type ScheduledDeletion = (SystemTime, Box<dyn FnOnce() + Send>);

#[derive(Default)]
pub(crate) struct FakeScheduler {
    pub(crate) scheduled: Mutex<Vec<ScheduledDeletion>>,
}

impl FakeScheduler {
    pub(crate) fn deadlines(&self) -> Vec<SystemTime> {
        self.scheduled
            .lock()
            .unwrap()
            .iter()
            .map(|(at, _)| *at)
            .collect()
    }

    /// Run every deletion whose deadline is at or before `now`.
    pub(crate) fn run_due(&self, now: SystemTime) {
        let due = {
            let mut scheduled = self.scheduled.lock().unwrap();
            let (due, pending): (Vec<_>, Vec<_>) =
                scheduled.drain(..).partition(|(at, _)| *at <= now);
            *scheduled = pending;
            due
        };
        for (_, delete) in due {
            delete();
        }
    }
}

impl DeletionScheduler for FakeScheduler {
    fn schedule(&self, at: SystemTime, delete: Box<dyn FnOnce() + Send>) {
        self.scheduled.lock().unwrap().push((at, delete));
    }
}

/// How the fake browser behaves once handed to the person.
#[derive(Clone)]
pub(crate) struct BrowserScript {
    /// Show a credential field and then log in on the next poll.
    pub(crate) logs_in: bool,
    /// Report the process gone at this poll (1-based).
    pub(crate) exits_at_poll: Option<usize>,
    /// Cookies CDP returns for the fetch URL, in order.
    pub(crate) cookies: Vec<(String, String)>,
    pub(crate) launch_refusal: Option<String>,
}

impl Default for BrowserScript {
    fn default() -> Self {
        Self {
            logs_in: true,
            exits_at_poll: None,
            cookies: vec![
                ("session".to_string(), PLANTED_VALUE.to_string()),
                ("csrf".to_string(), "t0k3n".to_string()),
            ],
            launch_refusal: None,
        }
    }
}

pub(crate) struct FakeLauncher {
    pub(crate) script: Mutex<BrowserScript>,
    pub(crate) events: Events,
    pub(crate) launches: AtomicUsize,
    pub(crate) placements: Mutex<Vec<CapturePlacement>>,
}

impl CaptureLauncher for FakeLauncher {
    fn launch_capture(
        &self,
        _accepted: &AcceptedBindFacts,
        _launch_attempt_id: &str,
        placement: &CapturePlacement,
    ) -> Result<Box<dyn CaptureBrowser>, CaptureLaunchRefusal> {
        self.launches.fetch_add(1, Ordering::SeqCst);
        self.placements.lock().unwrap().push(placement.clone());
        let script = self.script.lock().unwrap().clone();
        if let Some(stage) = script.launch_refusal {
            return Err(CaptureLaunchRefusal { stage });
        }
        self.events.push("browser_launched");
        Ok(Box::new(FakeBrowser {
            script,
            events: self.events.clone(),
            polls: 0,
            name_reads: 0,
            login_url: String::new(),
            closed: false,
        }))
    }
}

struct FakeBrowser {
    script: BrowserScript,
    events: Events,
    polls: usize,
    name_reads: usize,
    login_url: String,
    closed: bool,
}

impl CaptureBrowser for FakeBrowser {
    fn navigate(&mut self, url: &str, _deadline_ms: u64) -> Result<(), CaptureDriveError> {
        self.events.push(format!("navigate:{url}"));
        self.login_url = url.to_string();
        Ok(())
    }

    fn present(&mut self, _deadline_ms: u64) -> Result<(), CaptureDriveError> {
        self.events.push("present");
        Ok(())
    }

    fn main_frame_url(&mut self, _deadline_ms: u64) -> Result<String, CaptureDriveError> {
        Ok(self.login_url.clone())
    }

    fn has_credential_field(&mut self, _deadline_ms: u64) -> Result<bool, CaptureDriveError> {
        // Shown on the first poll, gone from the second: a completed login.
        Ok(self.script.logs_in && self.polls == 1)
    }

    fn cookie_names_for_origin(
        &mut self,
        origin: &str,
        _deadline_ms: u64,
    ) -> Result<BTreeSet<String>, CaptureDriveError> {
        self.name_reads += 1;
        self.events.push(format!("cookie_names:{origin}"));
        // The opening read and the first poll see no session cookie; it
        // appears once the person has submitted the form.
        if self.script.logs_in && self.name_reads >= 3 {
            Ok(BTreeSet::from(["session".to_string()]))
        } else {
            Ok(BTreeSet::new())
        }
    }

    fn cookie_request_header(
        &mut self,
        url: &str,
        _deadline_ms: u64,
    ) -> Result<Result<CookieHeader, CookieHeaderError>, CaptureDriveError> {
        self.events.push(format!("cookie_header:{url}"));
        Ok(CookieHeader::from_pairs(
            self.script
                .cookies
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        ))
    }

    fn exited(&mut self) -> bool {
        self.polls += 1;
        self.script.exits_at_poll == Some(self.polls)
    }

    fn close(&mut self) -> Result<(), CaptureDriveError> {
        if !self.closed {
            self.closed = true;
            self.events.push("browser_closed");
        }
        Ok(())
    }
}

/// Every fake, wired into one module.
pub(crate) struct Fixture {
    pub(crate) module: Arc<CaptureModule>,
    pub(crate) fs: Arc<FakeFs>,
    pub(crate) exclusion: Arc<FakeExclusion>,
    pub(crate) launcher: Arc<FakeLauncher>,
    pub(crate) scheduler: Arc<FakeScheduler>,
    pub(crate) clock: Arc<FakeClock>,
    pub(crate) events: Events,
}

pub(crate) fn fixture() -> Fixture {
    fixture_with(|_| {})
}

pub(crate) fn fixture_with(adjust: impl FnOnce(&mut CaptureEnv)) -> Fixture {
    let events = Events::default();
    let clock = Arc::new(FakeClock::at(
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_790_000_000),
    ));
    let fs = Arc::new(FakeFs::new(events.clone(), Arc::clone(&clock)));
    let exclusion = Arc::new(FakeExclusion {
        answer: Mutex::new(Ok(true)),
        add_fails: Mutex::new(None),
        events: events.clone(),
    });
    let scheduler = Arc::new(FakeScheduler::default());
    let launcher = Arc::new(FakeLauncher {
        script: Mutex::new(BrowserScript::default()),
        events: events.clone(),
        launches: AtomicUsize::new(0),
        placements: Mutex::new(Vec::new()),
    });
    let mut env = CaptureEnv {
        platform_supported: true,
        root: Some(PathBuf::from(ROOT)),
        exclusion: exclusion.clone(),
        fs: fs.clone(),
        clock: clock.clone(),
        scheduler: scheduler.clone(),
        file_lifetime: super::FILE_LIFETIME,
        handoff_duration: Duration::from_secs(5),
        poll_interval: Duration::from_millis(1),
        drive_deadline_ms: 100,
    };
    adjust(&mut env);
    let module = Arc::new(CaptureModule::new(env));
    module.set_launcher(launcher.clone());
    Fixture {
        module,
        fs,
        exclusion,
        launcher,
        scheduler,
        clock,
        events,
    }
}

/// Whether `haystack` holds `needle` anywhere. The leak tests first prove this
/// finds a planted value before trusting it to report an absence.
pub(crate) fn contains_bytes(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle.as_bytes())
}
