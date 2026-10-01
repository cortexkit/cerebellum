//! In-memory stand-ins for every seam a capture touches, shared by this
//! module's tests and the management-dispatch tests in `lib.rs`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cerebellum_core::identity::AcceptedBindFacts;
use serde_json::{json, Value};

use crate::browser_launch::BrowserProcessLiveness;

use super::vault::{BoxFuture, CookieVault, VaultReachError, VaultRoute};
use super::{
    BackupExclusion, CaptureBrowser, CaptureDriveError, CaptureEnv, CaptureFs,
    CaptureLaunchRefusal, CaptureLauncher, CaptureModule, CapturePlacement, CookieHeader,
    CookieHeaderError, ResidueEntry, SessionProbe, ToolError,
};

/// What one scripted verification load reports.
#[derive(Clone, Debug)]
pub(crate) enum ScriptedVerification {
    /// The load ended on this URL with this status, and the page did or did
    /// not show a credential field. `None` for the URL means the URL that
    /// was requested, as a working session leaves it.
    Ends {
        final_url: Option<String>,
        status: Option<u16>,
        credential_field: bool,
    },
    /// The browser could not carry out the load.
    DriveFails,
}

impl ScriptedVerification {
    /// A load that stays on the requested URL and answers 200.
    pub(crate) fn works() -> Self {
        Self::Ends {
            final_url: None,
            status: Some(200),
            credential_field: false,
        }
    }

    /// A load sent to the sign-in host, as Ollama sends an expired session.
    pub(crate) fn redirected_off_origin() -> Self {
        Self::Ends {
            final_url: Some("https://signin.ollama.com/?return=settings".to_string()),
            status: Some(200),
            credential_field: true,
        }
    }
}

/// Every verification the fake browsers ran, shared with the test.
#[derive(Clone, Default)]
pub(crate) struct Verifications {
    /// Start and end of each verification, in order.
    pub(crate) spans: Arc<Mutex<Vec<(Instant, Instant)>>>,
    in_flight: Arc<AtomicUsize>,
    /// The most verifications ever running at once.
    pub(crate) max_in_flight: Arc<AtomicUsize>,
}

impl Verifications {
    pub(crate) fn count(&self) -> usize {
        self.spans.lock().unwrap().len()
    }
}

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
    pub(crate) entries: Mutex<BTreeMap<PathBuf, FakeEntry>>,
    pub(crate) events: Events,
    /// Paths whose removal fails with PermissionDenied.
    pub(crate) undeletable: Mutex<BTreeSet<PathBuf>>,
    /// Every directory removal fails.
    pub(crate) directories_undeletable: AtomicBool,
    /// Held inside each directory removal, so a test can see whether anything
    /// raced past it.
    pub(crate) removal_delay: Mutex<Duration>,
}

impl FakeFs {
    pub(crate) fn new(events: Events) -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            events,
            undeletable: Mutex::new(BTreeSet::new()),
            directories_undeletable: AtomicBool::new(false),
            removal_delay: Mutex::new(Duration::ZERO),
        }
    }

    pub(crate) fn plant(&self, path: &Path, entry: FakeEntry) {
        self.entries
            .lock()
            .unwrap()
            .insert(path.to_path_buf(), entry);
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
            .map(|(path, entry)| (path.clone(), entry.clone()))
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
            .or_insert(FakeEntry::Dir);
        Ok(())
    }

    fn residue(&self, root: &Path) -> io::Result<Vec<ResidueEntry>> {
        Ok(self
            .entries
            .lock()
            .unwrap()
            .iter()
            .filter(|(path, _)| path.parent() == Some(root))
            .map(|(path, entry)| ResidueEntry {
                path: path.clone(),
                is_dir: *entry == FakeEntry::Dir,
            })
            .collect())
    }

    fn create_profile_dir(&self, path: &Path) -> io::Result<()> {
        let mut entries = self.entries.lock().unwrap();
        if entries.contains_key(path) {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        entries.insert(path.to_path_buf(), FakeEntry::Dir);
        self.events.push("profile_created");
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
    /// What `is_excluded` answers once an exclusion has been added, when set;
    /// otherwise it keeps answering `answer`.
    pub(crate) answer_after_add: Mutex<Option<Result<bool, ToolError>>>,
    pub(crate) added: std::sync::atomic::AtomicBool,
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
            None => {
                self.added.store(true, Ordering::SeqCst);
                Ok(())
            }
        }
    }

    fn is_excluded(&self, _path: &Path) -> Result<bool, ToolError> {
        self.events.push("tmutil_isexcluded");
        if self.added.load(Ordering::SeqCst) {
            if let Some(answer) = *self.answer_after_add.lock().unwrap() {
                return answer;
            }
        }
        *self.answer.lock().unwrap()
    }
}

/// What the fake vault answers to one deposit call.
#[derive(Clone, Debug)]
pub(crate) enum FakeReply {
    /// Stored, echoing the request's id.
    Stored { outcome: &'static str, version: u64 },
    /// The vault's refusal body.
    Refused {
        class: &'static str,
        code: &'static str,
    },
    /// Exactly this reply body.
    Raw(Value),
    /// The route fails instead of answering.
    Fails(VaultReachError),
    /// No answer, ever.
    Hangs,
}

impl FakeReply {
    pub(crate) fn refused(class: &'static str, code: &'static str) -> Self {
        Self::Refused { class, code }
    }
}

/// A vault behind the deposit seam: answers from a script and keeps every
/// request body it received. Test-only, so it holds the planted cookie; the
/// leak tests read the reply, the journal and errors, never this.
pub(crate) struct FakeVault {
    /// When set, opening the route fails this way.
    pub(crate) open_fails: Mutex<Option<VaultReachError>>,
    /// Answers in order, one per call; once they run out, every further call
    /// is answered as stored with outcome `created`.
    pub(crate) replies: Mutex<VecDeque<FakeReply>>,
    pub(crate) requests: Mutex<Vec<Vec<u8>>>,
    pub(crate) opens: AtomicUsize,
    pub(crate) events: Events,
}

impl FakeVault {
    pub(crate) fn script(&self, replies: impl IntoIterator<Item = FakeReply>) {
        *self.replies.lock().unwrap() = replies.into_iter().collect();
    }

    pub(crate) fn calls(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// The `params` of every request received, decoded.
    pub(crate) fn request_params(&self) -> Vec<Value> {
        self.requests
            .lock()
            .unwrap()
            .iter()
            .map(|body| serde_json::from_slice::<Value>(body).unwrap())
            .map(|request| request["params"].clone())
            .collect()
    }
}

/// The fixture's handle on its fake vault, which the module holds as a
/// `dyn CookieVault`.
pub(crate) struct SharedFakeVault(pub(crate) Arc<FakeVault>);

impl CookieVault for SharedFakeVault {
    fn open(&self) -> BoxFuture<'_, Result<Box<dyn VaultRoute>, VaultReachError>> {
        let vault = Arc::clone(&self.0);
        Box::pin(async move {
            vault.opens.fetch_add(1, Ordering::SeqCst);
            vault.events.push("vault_open");
            if let Some(error) = vault.open_fails.lock().unwrap().clone() {
                return Err(error);
            }
            Ok(Box::new(FakeRoute(vault)) as Box<dyn VaultRoute>)
        })
    }
}

struct FakeRoute(Arc<FakeVault>);

impl VaultRoute for FakeRoute {
    fn call<'a>(
        &'a mut self,
        request: &'a [u8],
    ) -> BoxFuture<'a, Result<Vec<u8>, VaultReachError>> {
        Box::pin(async move {
            let vault = &self.0;
            vault.events.push("vault_call");
            vault.requests.lock().unwrap().push(request.to_vec());
            let id = serde_json::from_slice::<Value>(request).unwrap()["params"]["id"].clone();
            let next = vault.replies.lock().unwrap().pop_front();
            let reply = match next.unwrap_or(FakeReply::Stored {
                outcome: "created",
                version: 1,
            }) {
                FakeReply::Stored { outcome, version } => {
                    json!({"result": {"id": id, "outcome": outcome, "record_version": version}})
                }
                FakeReply::Refused { class, code } => {
                    json!({"result": {"error": {"class": class, "code": code}}})
                }
                FakeReply::Raw(body) => body,
                FakeReply::Fails(error) => return Err(error),
                FakeReply::Hangs => std::future::pending().await,
            };
            Ok(serde_json::to_vec(&reply).unwrap())
        })
    }
}
/// How the fake browser behaves once handed to the person.
#[derive(Clone)]
pub(crate) struct BrowserScript {
    /// Show a credential field and then log in on the next poll.
    pub(crate) logs_in: bool,
    /// Report the process gone at this poll (1-based).
    pub(crate) exits_at_poll: Option<usize>,
    /// Answer every other liveness check with a failed reading instead of
    /// "running".
    pub(crate) liveness_unreadable: bool,
    /// Cookies CDP returns for the fetch URL, in order.
    pub(crate) cookies: Vec<(String, String)>,
    pub(crate) launch_refusal: Option<String>,
    /// Verification results in order; the last repeats once the rest are
    /// used.
    pub(crate) verifications: Vec<ScriptedVerification>,
    /// After the login, add a new cookie name on every poll, as a site that
    /// sets a fresh tracking cookie per request does.
    pub(crate) cookie_names_churn: bool,
}

impl Default for BrowserScript {
    fn default() -> Self {
        Self {
            logs_in: true,
            exits_at_poll: None,
            liveness_unreadable: false,
            cookies: vec![
                ("session".to_string(), PLANTED_VALUE.to_string()),
                ("csrf".to_string(), "t0k3n".to_string()),
            ],
            launch_refusal: None,
            verifications: vec![ScriptedVerification::works()],
            cookie_names_churn: false,
        }
    }
}

pub(crate) struct FakeLauncher {
    pub(crate) script: Mutex<BrowserScript>,
    pub(crate) events: Events,
    pub(crate) launches: AtomicUsize,
    pub(crate) placements: Mutex<Vec<CapturePlacement>>,
    pub(crate) verifications: Verifications,
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
            verifications: self.verifications.clone(),
            verified: 0,
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
    verifications: Verifications,
    verified: usize,
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
            let mut names = BTreeSet::from(["session".to_string()]);
            if self.script.cookie_names_churn {
                names.insert(format!("tracker-{}", self.name_reads));
            }
            Ok(names)
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

    fn verify_session(
        &mut self,
        url: &str,
        _deadline_ms: u64,
    ) -> Result<SessionProbe, CaptureDriveError> {
        let started = Instant::now();
        let running = self.verifications.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.verifications
            .max_in_flight
            .fetch_max(running, Ordering::SeqCst);
        self.events.push(format!("verify:{url}"));
        let scripted = self
            .script
            .verifications
            .get(self.verified)
            .or(self.script.verifications.last())
            .cloned()
            .unwrap_or(ScriptedVerification::DriveFails);
        self.verified += 1;
        // Held open briefly so a second verification started alongside this
        // one would be counted as running at the same time.
        std::thread::sleep(Duration::from_millis(2));
        self.verifications.in_flight.fetch_sub(1, Ordering::SeqCst);
        self.verifications
            .spans
            .lock()
            .unwrap()
            .push((started, Instant::now()));
        match scripted {
            ScriptedVerification::Ends {
                final_url,
                status,
                credential_field,
            } => Ok(SessionProbe {
                final_url: final_url.unwrap_or_else(|| url.to_string()),
                status,
                credential_field,
            }),
            ScriptedVerification::DriveFails => Err(CaptureDriveError),
        }
    }

    fn liveness(&mut self) -> BrowserProcessLiveness {
        self.polls += 1;
        if self.script.exits_at_poll == Some(self.polls) {
            BrowserProcessLiveness::Gone
        } else if self.script.liveness_unreadable {
            BrowserProcessLiveness::Unreadable
        } else {
            BrowserProcessLiveness::Live
        }
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
    pub(crate) vault: Arc<FakeVault>,
    pub(crate) events: Events,
}

pub(crate) fn fixture() -> Fixture {
    fixture_with(|_| {})
}

pub(crate) fn fixture_with(adjust: impl FnOnce(&mut CaptureEnv)) -> Fixture {
    let fixture = fixture_without_vault_with(adjust);
    fixture
        .module
        .set_vault(Arc::new(SharedFakeVault(Arc::clone(&fixture.vault))));
    fixture
}

/// A module that was never given a vault; its fake vault is unreachable to it.
pub(crate) fn fixture_without_vault() -> Fixture {
    fixture_without_vault_with(|_| {})
}

fn fixture_without_vault_with(adjust: impl FnOnce(&mut CaptureEnv)) -> Fixture {
    let events = Events::default();
    let fs = Arc::new(FakeFs::new(events.clone()));
    let exclusion = Arc::new(FakeExclusion {
        answer: Mutex::new(Ok(true)),
        answer_after_add: Mutex::new(None),
        added: std::sync::atomic::AtomicBool::new(false),
        add_fails: Mutex::new(None),
        events: events.clone(),
    });
    let launcher = Arc::new(FakeLauncher {
        script: Mutex::new(BrowserScript::default()),
        events: events.clone(),
        launches: AtomicUsize::new(0),
        placements: Mutex::new(Vec::new()),
        verifications: Verifications::default(),
    });
    let vault = Arc::new(FakeVault {
        open_fails: Mutex::new(None),
        replies: Mutex::new(VecDeque::new()),
        requests: Mutex::new(Vec::new()),
        opens: AtomicUsize::new(0),
        events: events.clone(),
    });
    let mut env = CaptureEnv {
        platform_supported: true,
        root: Some(PathBuf::from(ROOT)),
        exclusion: exclusion.clone(),
        fs: fs.clone(),
        handoff_duration: Duration::from_secs(5),
        poll_interval: Duration::from_millis(1),
        drive_deadline_ms: 100,
        // Short so the re-verification tests run in milliseconds; the tests
        // that measure spacing set their own.
        verification_min_spacing: Duration::from_millis(5),
        verification_retry_interval: Duration::from_millis(10),
        verification_deadline: Duration::from_millis(100),
        deposit_deadline: Duration::from_secs(5),
        // As many retries as production, with waits short enough for tests.
        deposit_backoff: vec![Duration::from_millis(1); super::vault::RETRY_BACKOFF.len()],
    };
    adjust(&mut env);
    let module = Arc::new(CaptureModule::new(env));
    module.set_launcher(launcher.clone());
    Fixture {
        module,
        fs,
        exclusion,
        launcher,
        vault,
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
