//! Fresh-login capture for `browser.capture_login`.
//!
//! A consumer (today only insula) needs one raw session cookie per provider.
//! Copying the person's live session would give it two holders, and some sites
//! sign one copy out. So this operation launches a THROWAWAY browser profile,
//! hands the window to the person to log in, and after the login is observed
//! reads the request `Cookie:` header for the one URL the holder will fetch.
//!
//! This is the only path in the module that holds a cookie VALUE. The value
//! goes to exactly one place: one 0600 file in a directory proven excluded from
//! backups, deleted after [`FILE_LIFETIME`]. It never reaches the wire reply,
//! the consent question, the journal, or a panic message: [`CookieHeader`] has
//! no `Display`, no `Serialize`, and a `Debug` that prints only its length.
//!
//! The vault write stays with the operator. The reply carries the two `ck auth`
//! commands that store the file and grant the holder read access, because
//! deposits are master-key gated and this module must never reach the
//! credentials provider.
//!
//! Everything that touches the host sits behind a seam ([`BackupExclusion`],
//! [`CaptureFs`], [`WallClock`], [`DeletionScheduler`], [`CaptureLauncher`]),
//! so the decisions below are exercised on any platform without a browser.

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_core::identity::AcceptedBindFacts;
use serde_json::{json, Map, Value};

use crate::elicit::AskOutcome;
use crate::journal::LoginCapturePayload;

/// The principal that will hold a captured login.
///
/// A fixed set rather than a request parameter: the holder is who the grant
/// command names, so a caller-chosen holder would be the caller choosing who
/// receives the person's login.
pub const HOLDER: &str = "reserved:insula";
/// How the holder is named to the person in the consent question.
const HOLDER_DISPLAY_NAME: &str = "insula";
/// How long the captured file exists before the module unlinks it, whether or
/// not the operator stored it.
pub const FILE_LIFETIME: Duration = Duration::from_secs(10 * 60);
/// The directory under the per-user temporary directory that holds the file
/// and the throwaway profile.
pub const CAPTURE_ROOT_NAME: &str = "ck-cerebellum-capture";
/// Every `tmutil` call on the capture path gets this long before it is killed
/// and reported as timed out. A healthy call answers in milliseconds; the bound
/// exists because a subprocess's latency is not ours to promise.
pub const TOOL_DEADLINE: Duration = Duration::from_secs(10);

/// How often a capture waiting on the person checks whether it was cancelled.
const CANCEL_CHECK_INTERVAL: Duration = Duration::from_millis(250);

/// The shortest gap between the end of one session verification and the start
/// of the next, whatever changed in between.
///
/// The login heuristic (a credential field came and went, the origin gained
/// cookie names, the page is back on the origin) can hold between the steps of
/// a multi-step sign-in, so a capture verifies before it reads anything: it
/// loads `fetch_url` in a background tab and checks the site served it as a
/// signed-in page. Each verification is a full page load the site sees, and a
/// page whose cookies churn changes the heuristic's inputs on every 2 s poll.
/// Five seconds keeps that to at most one load per two to three polls, while a
/// person who has just finished signing in waits at most about five seconds
/// longer for the capture.
pub const VERIFICATION_MIN_SPACING: Duration = Duration::from_secs(5);

/// How long a capture waits before verifying again when nothing the heuristic
/// reads (the origin's cookie NAMES and the page URL) has changed since the
/// last failed verification.
///
/// A sign-in can finish without changing either: the last step often rewrites
/// an existing session cookie in place, and the capture deliberately never
/// reads cookie values. Fifteen seconds still re-checks such a session within a
/// few polls, and bounds the loads over a ten-minute handoff to about forty.
pub const VERIFICATION_RETRY_INTERVAL: Duration = Duration::from_secs(15);

/// How long one verification load may take, from opening its background tab to
/// reading where it ended. The tab is closed on a separate short bound after
/// this, so a page that never finishes loading cannot keep it open.
pub const VERIFICATION_DEADLINE: Duration = Duration::from_secs(10);

/// The reply `reason` when a handoff ended after the login heuristic held at
/// least once but no verification ever showed a working session. It lets a
/// caller tell "nobody signed in" from "signed in, but the session the browser
/// holds does not load `fetch_url`".
pub const LOGIN_NOT_VERIFIED: &str = "login_not_verified";

const ALLOW_DECISION: &str = "allow";
const DENY_DECISION: &str = "deny";
const MAX_ACCOUNT_BYTES: usize = 128;

/// Every outcome the reply may carry. Declared once so the reply schema and
/// the code that builds replies cannot disagree about the vocabulary.
pub const OUTCOMES: [&str; 18] = [
    "captured",
    "no_login_observed",
    "expired",
    "cancelled",
    "capture_url_outside_domain",
    "capture_unsupported_on_platform",
    "capture_in_progress",
    "capture_residue_present",
    "capture_location_not_excluded",
    "capture_no_cookies_for_url",
    "capture_header_unusable",
    "capture_consent_not_given",
    "elicitation_undeclared",
    "capture_browser_unavailable",
    "capture_launch_failed",
    "capture_write_failed",
    "capture_profile_not_deleted",
    "internal_failure",
];

/// The closed reply schema. Undeclared properties are violations at the
/// module's own reply boundary, so a field that could carry cookie material
/// cannot be added to a reply without also being declared here.
pub fn reply_schema() -> Value {
    let string = || json!({"type": "string"});
    json!({
        "type": "object",
        "properties": {
            "outcome": {"type": "string", "enum": OUTCOMES},
            "path": string(),
            "bytes": {"type": "integer"},
            "expires_at": string(),
            "credential_id": string(),
            "holder": string(),
            "commands": {"type": "array", "items": {"type": "string"}},
            "replace_note": string(),
            "url": string(),
            "tool": string(),
            "reason": string(),
            "stage": string(),
            "remedy": string(),
        },
        "required": ["outcome"],
        "additionalProperties": false,
    })
}

/// The request schema, for the management operation and its flat facade.
pub fn request_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "credential_domain": {"type": "string"},
            "account": {"type": "string", "minLength": 1},
            "fetch_url": {"type": "string"},
            "login_url": {"type": "string"},
        },
        "required": ["credential_domain", "account", "fetch_url", "login_url"],
        "additionalProperties": false,
    })
}

// ---------------------------------------------------------------------------
// The request
// ---------------------------------------------------------------------------

/// A validated `browser.capture_login` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureRequest {
    pub credential_domain: String,
    pub account: String,
    pub fetch_url: String,
    pub login_url: String,
}

/// A malformed request, answered as `invalid_request` before anything else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidCaptureRequest {
    pub field: String,
    pub reason: &'static str,
}

const FIELDS: [&str; 4] = ["credential_domain", "account", "fetch_url", "login_url"];

/// Parse the closed parameter object.
///
/// The account is required and non-empty because the vault id is always
/// `cookie:<domain>:<account>`: insula reads a bare `cookie:<domain>` as a
/// fallback behind its own Chrome reader, and only the account-suffixed id
/// takes that reader out of the path. It is also limited to characters that
/// need no quoting, because it is printed inside shell commands the operator
/// runs.
pub fn parse_request(params: &Map<String, Value>) -> Result<CaptureRequest, InvalidCaptureRequest> {
    if let Some(field) = params
        .keys()
        .filter(|field| !FIELDS.contains(&field.as_str()))
        .min()
    {
        return Err(InvalidCaptureRequest {
            field: field.clone(),
            reason: "unknown_field",
        });
    }
    let mut values = Vec::with_capacity(FIELDS.len());
    for field in FIELDS {
        let value = params.get(field).ok_or_else(|| InvalidCaptureRequest {
            field: field.to_string(),
            reason: "missing_field",
        })?;
        let text = value.as_str().ok_or_else(|| InvalidCaptureRequest {
            field: field.to_string(),
            reason: "wrong_type",
        })?;
        values.push(text.to_string());
    }
    let [credential_domain, account, fetch_url, login_url]: [String; 4] =
        values.try_into().map_err(|_| InvalidCaptureRequest {
            field: "params".to_string(),
            reason: "wrong_type",
        })?;
    if !valid_domain(&credential_domain) {
        return Err(InvalidCaptureRequest {
            field: "credential_domain".to_string(),
            reason: "unsupported_value",
        });
    }
    if !valid_account(&account) {
        return Err(InvalidCaptureRequest {
            field: "account".to_string(),
            reason: "unsupported_value",
        });
    }
    Ok(CaptureRequest {
        credential_domain,
        account,
        fetch_url,
        login_url,
    })
}

impl CaptureRequest {
    /// The vault id the operator stores the capture under.
    pub fn credential_id(&self) -> String {
        format!("cookie:{}:{}", self.credential_domain, self.account)
    }

    /// The origin of the login page, which is where the login observation is
    /// keyed. Not the fetch URL's origin: the two can sit on different
    /// subdomains (factory.ai logs in at app. and fetches from api.).
    fn login_origin(&self) -> Option<String> {
        host_within_domain(&self.login_url, &self.credential_domain)
            .and_then(|host| crate::classification::canonical_origin(&format!("https://{host}")))
    }
}

fn valid_domain(domain: &str) -> bool {
    domain.len() <= 253 && domain.split('.').count() >= 2 && domain.split('.').all(valid_label)
}

fn valid_account(account: &str) -> bool {
    !account.is_empty()
        && account.len() <= MAX_ACCOUNT_BYTES
        && account.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@' | b'+')
        })
}

/// The URL's host when it is an https URL whose host is the credential domain
/// or a subdomain of it, and `None` otherwise.
///
/// Matching is on whole labels: `cs-data.qwencloud.com` is under
/// `qwencloud.com`, while `evilqwencloud.com` and `qwencloud.com.evil.net` are
/// not. The consent names the domain, so nothing outside it may be captured.
/// Credentials, explicit ports and whitespace are refused rather than
/// interpreted.
pub fn host_within_domain(url: &str, domain: &str) -> Option<String> {
    if url
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return None;
    }
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() || authority.contains(['@', ':', '[', ']']) || !authority.is_ascii() {
        return None;
    }
    let host = authority.to_ascii_lowercase();
    let within = host == domain
        || host
            .strip_suffix(domain)
            .and_then(|prefix| prefix.strip_suffix('.'))
            .is_some_and(|subdomain| subdomain.split('.').all(valid_label));
    within.then_some(host)
}

fn valid_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

// ---------------------------------------------------------------------------
// The captured value
// ---------------------------------------------------------------------------

/// One request `Cookie:` header value, `name=value; name=value`.
///
/// Deliberately has no `Clone`, `Display` or `Serialize`, and its `Debug`
/// prints only the length, so the value cannot reach a reply, a journal entry
/// or a panic message by formatting. The bytes are overwritten on drop.
pub struct CookieHeader(Vec<u8>);

/// Why a set of cookies could not become a header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CookieHeaderError {
    /// No cookie applies to the URL.
    Empty,
    /// A name or value carries a byte that would split or corrupt the header.
    Unusable,
}

impl CookieHeader {
    /// Build a request header from name/value pairs in the order given.
    ///
    /// Session cookies are included: this is a header for an HTTP client, not
    /// a profile that must survive a relaunch.
    pub fn from_pairs<'a>(
        pairs: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Result<Self, CookieHeaderError> {
        let mut header = Vec::new();
        for (name, value) in pairs {
            let unusable = |text: &str, forbid_separators: bool| {
                text.bytes().any(|byte| {
                    byte.is_ascii_control() || (forbid_separators && matches!(byte, b';' | b'='))
                })
            };
            if name.is_empty()
                || unusable(name, true)
                || unusable(value, false)
                || value.contains(';')
            {
                return Err(CookieHeaderError::Unusable);
            }
            if !header.is_empty() {
                header.extend_from_slice(b"; ");
            }
            header.extend_from_slice(name.as_bytes());
            header.push(b'=');
            header.extend_from_slice(value.as_bytes());
        }
        if header.is_empty() {
            return Err(CookieHeaderError::Empty);
        }
        Ok(Self(header))
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn bytes(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for CookieHeader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "CookieHeader(<{} bytes withheld>)", self.0.len())
    }
}

impl Drop for CookieHeader {
    fn drop(&mut self) {
        self.0.iter_mut().for_each(|byte| *byte = 0);
    }
}

// ---------------------------------------------------------------------------
// Seams
// ---------------------------------------------------------------------------

/// Why a backup-exclusion tool call did not produce an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolError {
    /// The tool ran past [`TOOL_DEADLINE`] and was killed.
    TimedOut,
    /// The tool could not be started, exited unsuccessfully, or printed
    /// something this module does not recognise.
    Failed,
    /// This platform has no such tool.
    Unsupported,
}

impl ToolError {
    fn as_str(self) -> &'static str {
        match self {
            Self::TimedOut => "timed_out",
            Self::Failed => "failed",
            Self::Unsupported => "unsupported",
        }
    }
}

/// Keeping the capture directory out of Time Machine.
pub trait BackupExclusion: Send + Sync {
    /// The tool named in a refusal.
    fn tool_name(&self) -> &'static str;
    /// Mark the path excluded (sticky; no root needed).
    fn add_exclusion(&self, path: &Path) -> Result<(), ToolError>;
    /// Whether the path currently reads as excluded.
    fn is_excluded(&self, path: &Path) -> Result<bool, ToolError>;
}

/// One entry found in the capture directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResidueEntry {
    pub path: PathBuf,
    pub is_dir: bool,
    pub modified: Option<SystemTime>,
}

/// Every file-system effect of a capture.
pub trait CaptureFs: Send + Sync {
    /// Create the capture root as a private (0700) directory if absent; refuse
    /// a symlink or non-directory in its place.
    fn prepare_root(&self, root: &Path) -> io::Result<()>;
    /// Everything currently in the capture root. A missing root is empty.
    fn residue(&self, root: &Path) -> io::Result<Vec<ResidueEntry>>;
    /// Create one fresh private directory; fail if anything is already there.
    fn create_profile_dir(&self, path: &Path) -> io::Result<()>;
    /// Create the file exclusively with mode 0600, write it in one call, and
    /// flush it to disk.
    fn write_new_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()>;
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
}

/// The wall clock, for `expires_at` and residue age.
pub trait WallClock: Send + Sync {
    fn now(&self) -> SystemTime;
}

/// Unlinks a captured file at its deadline.
pub trait DeletionScheduler: Send + Sync {
    /// Arrange for `delete` to run at `at`. `delete` records its own failure.
    fn schedule(&self, at: SystemTime, delete: Box<dyn FnOnce() + Send>);
}

/// Why a capture browser operation failed. Carries no page or cookie text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureDriveError;

/// Where a verification load of `fetch_url` ended. Carries no cookie, header
/// or page text: only the URL the tab settled on, the HTTP status of the main
/// document it settled on, and whether that page asks for a credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionProbe {
    pub final_url: String,
    /// `None` when no main-document response was seen, which never passes.
    pub status: Option<u16>,
    pub credential_field: bool,
}

/// Why a verification did not show a working session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationFailure {
    /// The load ended on another origin, as a site does when it sends an
    /// unauthenticated request to a separate sign-in host.
    OffOrigin,
    /// The load stayed on the origin but ended on a sign-in page.
    SignInPage,
    /// The main document's status was not 2xx, or none was seen.
    Status(Option<u16>),
    /// The browser could not carry out the load.
    Unreadable,
}

impl VerificationFailure {
    /// Words for the reply's remedy. Never names the final URL: a sign-in
    /// redirect can carry tokens in its query.
    fn describe(self) -> String {
        match self {
            Self::OffOrigin => "ended on another origin".to_string(),
            Self::SignInPage => "ended on a sign-in page".to_string(),
            Self::Status(Some(status)) => format!("answered HTTP {status}"),
            Self::Status(None) => "returned no page response".to_string(),
            Self::Unreadable => "could not be loaded".to_string(),
        }
    }
}

/// Path segments that name a sign-in page. A load of `fetch_url` that ends on
/// one of these, on `fetch_url`'s own origin, was redirected to sign in.
const SIGN_IN_PATH_SEGMENTS: [&str; 6] =
    ["login", "log-in", "signin", "sign-in", "sign_in", "logon"];

fn has_sign_in_segment(url: &str) -> bool {
    let Some((_, rest)) = url.split_once("://") else {
        return false;
    };
    let path = rest
        .split(['?', '#'])
        .next()
        .unwrap_or_default()
        .split_once('/')
        .map_or("", |(_, path)| path);
    path.split('/').any(|segment| {
        SIGN_IN_PATH_SEGMENTS
            .iter()
            .any(|sign_in| segment.eq_ignore_ascii_case(sign_in))
    })
}

/// Whether a verification load of `fetch_url` shows the session works the way
/// its holder will use it: the browser, with its own cookie jar, asked for
/// `fetch_url` and was served a 2xx page on `fetch_url`'s origin that is not a
/// sign-in page. All three are required; any one alone is what an expired
/// session also produces on some site.
pub fn session_verified(fetch_url: &str, probe: &SessionProbe) -> Result<(), VerificationFailure> {
    let expected = crate::browser_session::main_frame_origin(fetch_url);
    if expected == "null" || crate::browser_session::main_frame_origin(&probe.final_url) != expected
    {
        return Err(VerificationFailure::OffOrigin);
    }
    // A sign-in path only counts when `fetch_url` is not itself on one;
    // otherwise every load of it would read as a redirect to sign in.
    if probe.credential_field
        || (has_sign_in_segment(&probe.final_url) && !has_sign_in_segment(fetch_url))
    {
        return Err(VerificationFailure::SignInPage);
    }
    match probe.status {
        Some(200..=299) => Ok(()),
        status => Err(VerificationFailure::Status(status)),
    }
}

/// The throwaway browser a capture drives.
///
/// Separate from the route session's process trait on purpose: this is the
/// only browser surface that can read a cookie value, and keeping it off the
/// general trait means no route session can be asked for one.
pub trait CaptureBrowser: Send {
    fn navigate(&mut self, url: &str, deadline_ms: u64) -> Result<(), CaptureDriveError>;
    /// Front the window for the person.
    fn present(&mut self, deadline_ms: u64) -> Result<(), CaptureDriveError>;
    fn main_frame_url(&mut self, deadline_ms: u64) -> Result<String, CaptureDriveError>;
    fn has_credential_field(&mut self, deadline_ms: u64) -> Result<bool, CaptureDriveError>;
    /// Cookie NAMES for the login origin, for the login observation.
    fn cookie_names_for_origin(
        &mut self,
        origin: &str,
        deadline_ms: u64,
    ) -> Result<BTreeSet<String>, CaptureDriveError>;
    /// The request header Chrome would send to `url`, in the order CDP
    /// returns the cookies.
    fn cookie_request_header(
        &mut self,
        url: &str,
        deadline_ms: u64,
    ) -> Result<Result<CookieHeader, CookieHeaderError>, CaptureDriveError>;
    /// Load `url` in a separate background tab of this browser, with its own
    /// cookie jar, report where the load ended, and close the tab.
    ///
    /// The person's sign-in page is never touched and never loses focus, and
    /// no cookie value is read: the request is the browser's own, as the
    /// holder's will be. At most one such tab exists at a time.
    fn verify_session(
        &mut self,
        url: &str,
        deadline_ms: u64,
    ) -> Result<SessionProbe, CaptureDriveError>;
    /// Whether the browser process is running, has gone (for instance because
    /// the person closed the window), or cannot be told. Only `Gone` ends the
    /// handoff.
    fn liveness(&mut self) -> crate::browser_launch::BrowserProcessLiveness;
    /// Terminate and reap the browser and close its launch record. Safe to
    /// call more than once.
    fn close(&mut self) -> Result<(), CaptureDriveError>;
}

/// A launch refusal, reduced to the stage that refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureLaunchRefusal {
    pub stage: String,
}

/// Launches a capture browser into a proven placement.
pub trait CaptureLauncher: Send + Sync {
    fn launch_capture(
        &self,
        accepted: &AcceptedBindFacts,
        launch_attempt_id: &str,
        placement: &CapturePlacement,
    ) -> Result<Box<dyn CaptureBrowser>, CaptureLaunchRefusal>;
}

/// Where one capture's throwaway profile lives, constructed only here and only
/// after the root was created and proven excluded from backups. The launcher's
/// `--user-data-dir` guard compares against exactly these two paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturePlacement {
    root: PathBuf,
    profile_directory: PathBuf,
}

impl CapturePlacement {
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn profile_directory(&self) -> &Path {
        &self.profile_directory
    }
}

// ---------------------------------------------------------------------------
// Production seams
// ---------------------------------------------------------------------------

/// The capture root under the per-user temporary directory.
///
/// `$TMPDIR` on macOS is `/private/var/folders/…/T`: Time Machine excludes it
/// and Backblaze's mandatory rule excludes `/private/`. The module's own data
/// home is included in Time Machine, which is why the capture does not live
/// there. Canonicalized so the launcher's path guard compares real paths.
pub fn production_root() -> Option<PathBuf> {
    let temporary = std::env::temp_dir();
    let temporary = temporary.canonicalize().ok()?;
    Some(temporary.join(CAPTURE_ROOT_NAME))
}

/// `tmutil`, bounded by [`TOOL_DEADLINE`].
pub struct Tmutil {
    deadline: Duration,
}

impl Default for Tmutil {
    fn default() -> Self {
        Self {
            deadline: TOOL_DEADLINE,
        }
    }
}

impl Tmutil {
    #[cfg(target_os = "macos")]
    fn run(&self, arguments: &[&std::ffi::OsStr]) -> Result<String, ToolError> {
        run_bounded(Path::new("/usr/bin/tmutil"), arguments, self.deadline)
    }
}

impl BackupExclusion for Tmutil {
    fn tool_name(&self) -> &'static str {
        "tmutil"
    }

    #[cfg(target_os = "macos")]
    fn add_exclusion(&self, path: &Path) -> Result<(), ToolError> {
        self.run(&["addexclusion".as_ref(), path.as_os_str()])
            .map(|_| ())
    }

    #[cfg(not(target_os = "macos"))]
    fn add_exclusion(&self, _path: &Path) -> Result<(), ToolError> {
        let _ = self.deadline;
        Err(ToolError::Unsupported)
    }

    #[cfg(target_os = "macos")]
    fn is_excluded(&self, path: &Path) -> Result<bool, ToolError> {
        let output = self.run(&["isexcluded".as_ref(), path.as_os_str()])?;
        parse_isexcluded(&output)
    }

    #[cfg(not(target_os = "macos"))]
    fn is_excluded(&self, _path: &Path) -> Result<bool, ToolError> {
        Err(ToolError::Unsupported)
    }
}

/// Read `tmutil isexcluded` output. Anything but a clear `[Excluded]` or
/// `[Included]` is a failure, never an assumption of exclusion.
pub fn parse_isexcluded(output: &str) -> Result<bool, ToolError> {
    let first = output.trim_start();
    if first.starts_with("[Excluded]") {
        Ok(true)
    } else if first.starts_with("[Included]") {
        Ok(false)
    } else {
        Err(ToolError::Failed)
    }
}

/// Run a tool with a deadline, killing it on expiry.
///
/// On expiry the child is killed and, if it does not die promptly, abandoned
/// rather than waited on, for the reason `browser_executable_identity` gives:
/// a tool blocked in the kernel does not answer a signal either, and waiting
/// for it would bring back the hang the deadline exists to remove.
pub fn run_bounded(
    program: &Path,
    arguments: &[&std::ffi::OsStr],
    deadline: Duration,
) -> Result<String, ToolError> {
    const POLL: Duration = Duration::from_millis(10);
    let started = Instant::now();
    let mut command = std::process::Command::new(program);
    let mut child = crate::launch_nonce::without_launch_nonce(&mut command)
        .args(arguments)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|_| ToolError::Failed)?;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if started.elapsed() >= deadline => {
                let _ = child.kill();
                std::thread::sleep(POLL);
                let _ = child.try_wait();
                return Err(ToolError::TimedOut);
            }
            Ok(None) => std::thread::sleep(POLL),
            Err(_) => return Err(ToolError::Failed),
        }
    }
    let output = child.wait_with_output().map_err(|_| ToolError::Failed)?;
    if !output.status.success() {
        return Err(ToolError::Failed);
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// The real file system, with the permissions the design requires.
#[derive(Debug, Default)]
pub struct HostFs;

impl CaptureFs for HostFs {
    fn prepare_root(&self, root: &Path) -> io::Result<()> {
        match std::fs::symlink_metadata(root) {
            Ok(metadata) if metadata.file_type().is_dir() => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::AlreadyExists,
                    "the capture root is not a directory",
                ))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => create_private_dir(root)?,
            Err(error) => return Err(error),
        }
        set_private_dir_permissions(root)
    }

    fn residue(&self, root: &Path) -> io::Result<Vec<ResidueEntry>> {
        let entries = match std::fs::read_dir(root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut residue = Vec::new();
        for entry in entries {
            let entry = entry?;
            let metadata = std::fs::symlink_metadata(entry.path())?;
            residue.push(ResidueEntry {
                path: entry.path(),
                is_dir: metadata.file_type().is_dir(),
                modified: metadata.modified().ok(),
            });
        }
        residue.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(residue)
    }

    fn create_profile_dir(&self, path: &Path) -> io::Result<()> {
        create_private_dir(path)
    }

    fn write_new_file(&self, path: &Path, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir_all(path)
    }
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().mode(0o700).create(path)
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> {
    std::fs::DirBuilder::new().create(path)
}

#[cfg(unix)]
fn set_private_dir_permissions(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_dir_permissions(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// The system wall clock.
#[derive(Debug, Default)]
pub struct SystemWallClock;

impl WallClock for SystemWallClock {
    fn now(&self) -> SystemTime {
        SystemTime::now()
    }
}

/// Runs each deletion on the tokio runtime at its deadline. Outside a runtime
/// nothing is scheduled, and the file is left for the residue rule to report.
#[derive(Debug, Default)]
pub struct TokioDeletionScheduler;

impl DeletionScheduler for TokioDeletionScheduler {
    fn schedule(&self, at: SystemTime, delete: Box<dyn FnOnce() + Send>) {
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let wait = at.duration_since(SystemTime::now()).unwrap_or_default();
        runtime.spawn(async move {
            tokio::time::sleep(wait).await;
            delete();
        });
    }
}

// ---------------------------------------------------------------------------
// The capture module
// ---------------------------------------------------------------------------

/// Host facts and seams a capture runs against.
pub struct CaptureEnv {
    /// Whether this platform's placement proof exists. macOS only today.
    pub platform_supported: bool,
    /// The capture root, or `None` when the temporary directory is unusable.
    pub root: Option<PathBuf>,
    pub exclusion: Arc<dyn BackupExclusion>,
    pub fs: Arc<dyn CaptureFs>,
    pub clock: Arc<dyn WallClock>,
    pub scheduler: Arc<dyn DeletionScheduler>,
    pub file_lifetime: Duration,
    /// The same handoff bound `browser.present` uses.
    pub handoff_duration: Duration,
    /// The same poll interval `browser.present` uses.
    pub poll_interval: Duration,
    /// Deadline for each single browser operation.
    pub drive_deadline_ms: u64,
    /// See [`VERIFICATION_MIN_SPACING`].
    pub verification_min_spacing: Duration,
    /// See [`VERIFICATION_RETRY_INTERVAL`].
    pub verification_retry_interval: Duration,
    /// See [`VERIFICATION_DEADLINE`].
    pub verification_deadline: Duration,
}

impl CaptureEnv {
    /// The host this module runs on.
    pub fn production(drive_deadline_ms: u64) -> Self {
        Self {
            platform_supported: cfg!(target_os = "macos"),
            root: production_root(),
            exclusion: Arc::new(Tmutil::default()),
            fs: Arc::new(HostFs),
            clock: Arc::new(SystemWallClock),
            scheduler: Arc::new(TokioDeletionScheduler),
            file_lifetime: FILE_LIFETIME,
            handoff_duration: Duration::from_millis(crate::browser_session::HANDOFF_DURATION_MS),
            poll_interval: Duration::from_millis(crate::browser_session::HANDOFF_POLL_INTERVAL_MS),
            drive_deadline_ms,
            verification_min_spacing: VERIFICATION_MIN_SPACING,
            verification_retry_interval: VERIFICATION_RETRY_INTERVAL,
            verification_deadline: VERIFICATION_DEADLINE,
        }
    }
}

/// Module-owned capture state: one capture at a time, and the unlink failures
/// the residue refusal reports.
pub struct CaptureModule {
    env: CaptureEnv,
    launcher: Mutex<Option<Arc<dyn CaptureLauncher>>>,
    in_progress: Arc<Mutex<bool>>,
    /// Paths whose deletion failed, with the error kind. The residue refusal
    /// names the path from disk; this adds why the module could not remove it.
    failed_deletions: Arc<Mutex<BTreeMap<PathBuf, String>>>,
}

/// Everything a capture call needs from the route that made it.
pub struct CaptureCall<'a, Ask, Cancelled> {
    pub accepted: &'a AcceptedBindFacts,
    pub declares_elicitation: bool,
    /// Put one question to the person. The deadline is the ask's own.
    pub ask: Ask,
    /// Whether the caller cancelled the request, its route went away, or the
    /// module began draining.
    pub cancelled: Cancelled,
}

/// A finished capture: the reply to send and the journal record to write
/// first. When `captured_file` is set the reply names that file.
#[derive(Debug)]
pub struct CaptureOutcome {
    pub reply: Value,
    pub journal: LoginCapturePayload,
    pub captured_file: Option<PathBuf>,
}

enum HandoffEnd {
    /// The heuristic held and a verification load showed the session works.
    LoginVerified,
    /// `unverified` carries the last verification's failure when the login
    /// heuristic held at least once but no verification passed, and is `None`
    /// when the heuristic never held.
    Expired {
        unverified: Option<VerificationFailure>,
    },
    Exited {
        unverified: Option<VerificationFailure>,
    },
    Cancelled,
}

struct InProgress(Arc<Mutex<bool>>);

impl Drop for InProgress {
    fn drop(&mut self) {
        *self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = false;
    }
}

/// What the throwaway profile's disposal found.
struct Disposal {
    deleted: bool,
}

impl CaptureModule {
    pub fn new(env: CaptureEnv) -> Self {
        Self {
            env,
            launcher: Mutex::new(None),
            in_progress: Arc::new(Mutex::new(false)),
            failed_deletions: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    /// Publish the launcher. Set after startup recovery, so a capture never
    /// races the reaping of an orphan from an earlier module process.
    pub fn set_launcher(&self, launcher: Arc<dyn CaptureLauncher>) {
        *self
            .launcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(launcher);
    }

    fn launcher(&self) -> Option<Arc<dyn CaptureLauncher>> {
        self.launcher
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    fn try_begin(&self) -> Option<InProgress> {
        let mut busy = self
            .in_progress
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *busy {
            return None;
        }
        *busy = true;
        Some(InProgress(Arc::clone(&self.in_progress)))
    }

    /// Delete residue older than the file lifetime, and schedule deletion of
    /// anything younger at its own deadline. Run once at module startup, after
    /// launch recovery has terminated any orphaned capture browser.
    ///
    /// A module crash between writing a file and its deadline leaves the file
    /// here. A deletion that fails is recorded, and the next capture refuses
    /// with `capture_residue_present`: the module logs nothing, so that
    /// refusal is the report.
    pub fn sweep_at_startup(&self) {
        let Some(root) = self.env.root.clone() else {
            return;
        };
        let Ok(residue) = self.env.fs.residue(&root) else {
            return;
        };
        let now = self.env.clock.now();
        for entry in residue {
            let deadline = entry
                .modified
                .and_then(|modified| modified.checked_add(self.env.file_lifetime));
            match deadline {
                Some(deadline) if deadline > now => {
                    self.schedule_deletion(entry.path, entry.is_dir, deadline)
                }
                _ => {
                    delete_recording(
                        &self.env.fs,
                        &self.failed_deletions,
                        &entry.path,
                        entry.is_dir,
                    );
                }
            }
        }
    }

    fn schedule_deletion(&self, path: PathBuf, is_dir: bool, at: SystemTime) {
        let fs = Arc::clone(&self.env.fs);
        let failures = Arc::clone(&self.failed_deletions);
        self.env.scheduler.schedule(
            at,
            Box::new(move || {
                delete_recording(&fs, &failures, &path, is_dir);
            }),
        );
    }

    /// Remove a captured file now, for a capture whose record could not be
    /// written: nothing may outlive an attempt the journal does not describe.
    pub fn discard_captured_file(&self, path: &Path) {
        delete_recording(&self.env.fs, &self.failed_deletions, path, false);
    }

    /// Run one capture to its end. The throwaway profile is deleted before
    /// this returns, so a caller that sends the reply afterwards can never
    /// reply while a second copy of the session exists.
    pub async fn run<Ask, AskFuture, Cancelled>(
        &self,
        request: &CaptureRequest,
        call: CaptureCall<'_, Ask, Cancelled>,
    ) -> CaptureOutcome
    where
        Ask: FnOnce(Value, Duration) -> AskFuture,
        AskFuture: Future<Output = AskOutcome>,
        Cancelled: Fn() -> bool,
    {
        let record = Record::new(request);
        for url in [&request.login_url, &request.fetch_url] {
            if host_within_domain(url, &request.credential_domain).is_none() {
                return record.refused(
                    "capture_url_outside_domain",
                    json!({
                        "url": url,
                        "remedy": format!(
                            "use https URLs on {} or one of its subdomains; the consent names only that domain",
                            request.credential_domain
                        ),
                    }),
                );
            }
        }
        let Some(origin) = request.login_origin() else {
            return record.refused(
                "capture_url_outside_domain",
                json!({"url": request.login_url, "remedy": "use a canonical https login URL"}),
            );
        };
        if !self.env.platform_supported {
            return record.refused(
                "capture_unsupported_on_platform",
                json!({"remedy": "run the capture on macOS, the only platform whose backup exclusion this module can prove"}),
            );
        }
        if !call.declares_elicitation {
            return record.refused(
                "elicitation_undeclared",
                json!({"remedy": "reconnect with a route that declares elicitation support"}),
            );
        }
        let Some(launcher) = self.launcher() else {
            return record.refused(
                "capture_browser_unavailable",
                json!({"remedy": "configure a supported browser executable for this module"}),
            );
        };
        let Some(root) = self.env.root.clone() else {
            return record.refused(
                "capture_location_not_excluded",
                json!({"reason": "temporary_directory_unresolved", "remedy": "run the module with a usable per-user temporary directory"}),
            );
        };
        let Some(_custody) = self.try_begin() else {
            return record.refused(
                "capture_in_progress",
                json!({"remedy": "wait for the running capture to finish, then retry"}),
            );
        };
        if let Some(refusal) = self.residue_refusal(&root) {
            return record.refused("capture_residue_present", refusal);
        }

        if (call.cancelled)() {
            return record.ended("cancelled", None);
        }
        let question = consent_question(request, self.env.file_lifetime);
        // The question can wait minutes for a person, so a cancel is watched
        // for alongside it rather than only after it ends.
        let answer = {
            let asked = (call.ask)(question, crate::login_import::ELICITATION_DEADLINE);
            tokio::pin!(asked);
            let check = self.env.poll_interval.min(CANCEL_CHECK_INTERVAL);
            loop {
                tokio::select! {
                    answer = &mut asked => break Some(answer),
                    () = tokio::time::sleep(check) => {
                        if (call.cancelled)() {
                            break None;
                        }
                    }
                }
            }
        };
        let Some(answer) = answer else {
            return record.ended("cancelled", None);
        };
        if (call.cancelled)() {
            return record.ended("cancelled", None);
        }
        if let Some(reason) = consent_refusal(&answer) {
            return record.refused(
                "capture_consent_not_given",
                json!({"reason": reason, "remedy": consent_refusal_remedy(reason)}),
            );
        }

        // Placement: proven on every capture, because a person can change
        // Time Machine settings between two of them.
        let tool = self.env.exclusion.tool_name();
        let not_excluded = |reason: &str| {
            // A tool that did not answer says nothing about the exclusion, so
            // the caller is not sent to fix one that may already be in place.
            let remedy = match reason {
                "timed_out" => format!("{tool} did not answer in time; nothing was captured. Retry; if it keeps happening, check {tool} on this Mac"),
                _ => format!("make {tool} report {} as excluded, then retry", root.display()),
            };
            json!({
                "tool": tool,
                "path": root.display().to_string(),
                "reason": reason,
                "remedy": remedy,
            })
        };
        if self.env.fs.prepare_root(&root).is_err() {
            return record.refused(
                "capture_location_not_excluded",
                not_excluded("capture_directory_unusable"),
            );
        }
        // Read first, and add an exclusion only when the root is not already
        // excluded. The per-user temporary directory is excluded by Time
        // Machine's own rules, and `tmutil addexclusion` was measured at about
        // 11 s on this machine while `isexcluded` answers in under 1.5 s, so
        // adding unconditionally made every capture outrun its deadline on an
        // exclusion that was already in place.
        match self.env.exclusion.is_excluded(&root) {
            Ok(true) => {}
            Ok(false) => {
                if let Err(error) = self.env.exclusion.add_exclusion(&root) {
                    return record.refused(
                        "capture_location_not_excluded",
                        not_excluded(error.as_str()),
                    );
                }
                match self.env.exclusion.is_excluded(&root) {
                    Ok(true) => {}
                    Ok(false) => {
                        return record
                            .refused("capture_location_not_excluded", not_excluded("included"))
                    }
                    Err(error) => {
                        return record.refused(
                            "capture_location_not_excluded",
                            not_excluded(error.as_str()),
                        )
                    }
                }
            }
            Err(error) => {
                return record.refused(
                    "capture_location_not_excluded",
                    not_excluded(error.as_str()),
                )
            }
        }

        let capture_id = new_capture_id();
        let placement = CapturePlacement {
            root: root.clone(),
            profile_directory: root.join(format!("profile-{capture_id}")),
        };
        let file_path = root.join(format!("login-{capture_id}.cookie"));
        if self
            .env
            .fs
            .create_profile_dir(&placement.profile_directory)
            .is_err()
        {
            return record.refused(
                "capture_launch_failed",
                json!({"stage": "profile_directory", "remedy": "check the capture directory, then retry"}),
            );
        }

        let accepted = call.accepted.clone();
        let launch_placement = placement.clone();
        let launched = tokio::task::spawn_blocking(move || {
            launcher.launch_capture(
                &accepted,
                &format!("capture-{capture_id}"),
                &launch_placement,
            )
        })
        .await;
        let browser = match launched {
            Ok(Ok(browser)) => browser,
            Ok(Err(refusal)) => {
                let disposal = self.dispose(None, &placement).await;
                return record.with_deletion(disposal.deleted).refused(
                    "capture_launch_failed",
                    json!({"stage": refusal.stage, "remedy": "fix the browser launch named by stage, then retry"}),
                );
            }
            Err(_) => {
                let disposal = self.dispose(None, &placement).await;
                return record.with_deletion(disposal.deleted).refused(
                    "capture_launch_failed",
                    json!({"stage": "launch_task", "remedy": "retry the capture"}),
                );
            }
        };

        let (browser, end) = self
            .hand_off(browser, request, &origin, &call.cancelled)
            .await;
        let end = match end {
            Ok(end) => end,
            Err(stage) => {
                let disposal = self.dispose(browser, &placement).await;
                return record.with_deletion(disposal.deleted).refused(
                    "capture_launch_failed",
                    json!({"stage": stage, "remedy": "retry the capture"}),
                );
            }
        };
        let outcome_word = match end {
            HandoffEnd::LoginVerified => None,
            HandoffEnd::Expired { unverified } => Some(("expired", unverified)),
            HandoffEnd::Exited { unverified } => Some(("no_login_observed", unverified)),
            HandoffEnd::Cancelled => Some(("cancelled", None)),
        };
        if let Some((word, unverified)) = outcome_word {
            let disposal = self.dispose(browser, &placement).await;
            let record = record.with_deletion(disposal.deleted);
            return match unverified {
                None => record.ended(word, None),
                Some(failure) => record.ended_unverified(word, &request.fetch_url, failure),
            };
        }

        let Some(browser) = browser else {
            let disposal = self.dispose(None, &placement).await;
            return record.with_deletion(disposal.deleted).refused(
                "capture_launch_failed",
                json!({"stage": "handoff_poll", "remedy": "retry the capture"}),
            );
        };
        // Login verified: read the header the holder's own request would send.
        let fetch_url = request.fetch_url.clone();
        let deadline_ms = self.env.drive_deadline_ms;
        let (browser, header) = on_browser(browser, move |browser| {
            browser.cookie_request_header(&fetch_url, deadline_ms)
        })
        .await;
        let header = match header {
            Some(Ok(Ok(header))) => header,
            Some(Ok(Err(CookieHeaderError::Empty))) => {
                let disposal = self.dispose(browser, &placement).await;
                return record.with_deletion(disposal.deleted).refused(
                    "capture_no_cookies_for_url",
                    json!({"url": request.fetch_url, "remedy": "check fetch_url is the URL the holder requests after login, then capture again"}),
                );
            }
            Some(Ok(Err(CookieHeaderError::Unusable))) => {
                let disposal = self.dispose(browser, &placement).await;
                return record.with_deletion(disposal.deleted).refused(
                    "capture_header_unusable",
                    json!({"url": request.fetch_url, "remedy": "this site's cookies cannot be carried as one request header"}),
                );
            }
            Some(Err(CaptureDriveError)) | None => {
                let disposal = self.dispose(browser, &placement).await;
                return record.with_deletion(disposal.deleted).refused(
                    "capture_launch_failed",
                    json!({"stage": "cookie_read", "remedy": "retry the capture"}),
                );
            }
        };
        if (call.cancelled)() {
            drop(header);
            let disposal = self.dispose(browser, &placement).await;
            return record
                .with_deletion(disposal.deleted)
                .ended("cancelled", None);
        }

        let bytes = header.len() as u64;
        let written = self.env.fs.write_new_file(&file_path, header.bytes());
        drop(header);
        if written.is_err() {
            // An exclusive create that failed part-way may still have left a
            // file; remove it so the failure leaves nothing behind.
            let _ = self.env.fs.remove_file(&file_path);
            let disposal = self.dispose(browser, &placement).await;
            return record.with_deletion(disposal.deleted).refused(
                "capture_write_failed",
                json!({"path": file_path.display().to_string(), "remedy": "check the capture directory is writable, then retry"}),
            );
        }
        let expires_at = self
            .env
            .clock
            .now()
            .checked_add(self.env.file_lifetime)
            .unwrap_or(UNIX_EPOCH);
        // Scheduled before disposal so the file is covered by its deadline
        // even if what follows fails.
        self.schedule_deletion(file_path.clone(), false, expires_at);

        // From here a cancel changes nothing: the file exists and its deadline
        // deletes it. The profile goes first, and only then is anything
        // returned, so the session exists in exactly one place: the file.
        let disposal = self.dispose(browser, &placement).await;
        if !disposal.deleted {
            // A second copy of the session survives in the profile. Withdraw
            // the file rather than hand out one of two copies.
            delete_recording(&self.env.fs, &self.failed_deletions, &file_path, false);
            return record.with_deletion(false).refused(
                "capture_profile_not_deleted",
                json!({
                    "path": placement.profile_directory.display().to_string(),
                    "remedy": format!("remove {}, then capture again", placement.profile_directory.display()),
                }),
            );
        }

        let credential_id = request.credential_id();
        let reply = json!({
            "outcome": "captured",
            "path": file_path.display().to_string(),
            "bytes": bytes,
            "expires_at": crate::browser_session::render_rfc3339_millis(expires_at),
            "credential_id": credential_id,
            "holder": HOLDER,
            "commands": operator_commands(&credential_id, &file_path),
            "replace_note": replace_note(&credential_id),
        });
        CaptureOutcome {
            reply,
            journal: record.with_deletion(true).payload("captured", bytes),
            captured_file: Some(file_path),
        }
    }

    fn residue_refusal(&self, root: &Path) -> Option<Value> {
        let residue = match self.env.fs.residue(root) {
            Ok(residue) => residue,
            Err(_) => {
                return Some(json!({
                    "path": root.display().to_string(),
                    "reason": "capture_directory_unreadable",
                    "remedy": format!("make {} readable or remove it, then retry", root.display()),
                }))
            }
        };
        let first = residue.into_iter().next()?;
        let path = first.path.display().to_string();
        let failure = self
            .failed_deletions
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&first.path)
            .cloned();
        let mut refusal = json!({
            "path": path,
            "remedy": format!("remove {path}, then retry the capture"),
        });
        if let (Some(failure), Some(object)) = (failure, refusal.as_object_mut()) {
            object.insert(
                "reason".into(),
                Value::String(format!("deletion_failed:{failure}")),
            );
        }
        Some(refusal)
    }

    /// Hand the window to the person and wait until their session works,
    /// parked as a consent wait so the Busy gauge and in-flight age do not
    /// read a person's typing as a stuck module.
    ///
    /// Each poll first applies the login heuristic `browser.present` uses (a
    /// credential field came and went, the origin gained cookie names, the
    /// page is back on the origin). That heuristic also holds between the
    /// steps of a multi-step sign-in, so it only nominates a moment: the
    /// handoff ends as a login only when a verification load of `fetch_url`
    /// then passes [`session_verified`]. A failed verification keeps the
    /// handoff open for the person to finish; see [`VerificationRecord::due`]
    /// for when it is tried again.
    async fn hand_off<Cancelled: Fn() -> bool>(
        &self,
        browser: Box<dyn CaptureBrowser>,
        request: &CaptureRequest,
        origin: &str,
        cancelled: &Cancelled,
    ) -> (
        Option<Box<dyn CaptureBrowser>>,
        Result<HandoffEnd, &'static str>,
    ) {
        let deadline_ms = self.env.drive_deadline_ms;
        let login_url = request.login_url.clone();
        let opening_origin = origin.to_string();
        let (browser, opened) = on_browser(browser, move |browser| {
            browser.navigate(&login_url, deadline_ms)?;
            browser.present(deadline_ms)?;
            browser.cookie_names_for_origin(&opening_origin, deadline_ms)
        })
        .await;
        let opening_cookie_names = match opened {
            Some(Ok(names)) => names,
            Some(Err(CaptureDriveError)) => return (browser, Err("present")),
            None => return (browser, Err("present")),
        };
        let Some(mut browser) = browser else {
            return (None, Err("present"));
        };

        let guard = crate::elicit::ROUTE_GUARD.try_with(Arc::clone).ok();
        let _parked = guard.as_ref().map(|guard| guard.park_on_consent());
        let started = Instant::now();
        let mut saw_credential_field = false;
        let mut verification = VerificationRecord::default();
        loop {
            if cancelled() {
                return (Some(browser), Ok(HandoffEnd::Cancelled));
            }
            if started.elapsed() >= self.env.handoff_duration {
                return (
                    Some(browser),
                    Ok(HandoffEnd::Expired {
                        unverified: verification.last_failure(),
                    }),
                );
            }
            tokio::time::sleep(self.env.poll_interval).await;
            let poll_origin = origin.to_string();
            let saw = saw_credential_field;
            let opening = opening_cookie_names.clone();
            let (returned, polled) = on_browser(browser, move |browser| {
                // A liveness reading that failed is not evidence the person
                // closed the window, so the handoff stays open on it and the
                // login observation below still runs.
                if browser.liveness() == crate::browser_launch::BrowserProcessLiveness::Gone {
                    return Poll::Exited;
                }
                // Read failures leave the handoff open, as they do for
                // `browser.present`: a page mid-navigation fails a read.
                let Ok(current) = browser.cookie_names_for_origin(&poll_origin, deadline_ms) else {
                    return Poll::Open {
                        saw_credential_field: saw,
                    };
                };
                let Ok(url) = browser.main_frame_url(deadline_ms) else {
                    return Poll::Open {
                        saw_credential_field: saw,
                    };
                };
                let Ok(has_credential_field) = browser.has_credential_field(deadline_ms) else {
                    return Poll::Open {
                        saw_credential_field: saw,
                    };
                };
                if crate::browser_session::handoff_login_observed(
                    saw,
                    has_credential_field,
                    &opening,
                    &current,
                    &url,
                    &poll_origin,
                ) {
                    Poll::HeuristicHeld(HeuristicInputs {
                        cookie_names: current,
                        url,
                    })
                } else {
                    Poll::Open {
                        saw_credential_field: saw || has_credential_field,
                    }
                }
            })
            .await;
            let Some(returned) = returned else {
                return (None, Err("handoff_poll"));
            };
            browser = returned;
            let inputs = match polled {
                Some(Poll::HeuristicHeld(inputs)) => inputs,
                Some(Poll::Exited) => {
                    return (
                        Some(browser),
                        Ok(HandoffEnd::Exited {
                            unverified: verification.last_failure(),
                        }),
                    )
                }
                Some(Poll::Open {
                    saw_credential_field: saw,
                }) => {
                    saw_credential_field = saw;
                    continue;
                }
                None => return (Some(browser), Err("handoff_poll")),
            };
            if !verification.due(
                &inputs,
                Instant::now(),
                self.env.verification_min_spacing,
                self.env.verification_retry_interval,
            ) {
                continue;
            }
            // The handoff deadline bounds the verification too, so a load
            // started just before it cannot hold the person's window open past
            // the time the caller was promised.
            let budget = self
                .env
                .verification_deadline
                .min(self.env.handoff_duration.saturating_sub(started.elapsed()));
            let budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX);
            let verdict = if budget_ms == 0 {
                Err(VerificationFailure::Unreadable)
            } else {
                let fetch_url = request.fetch_url.clone();
                let (returned, probed) = on_browser(browser, move |browser| {
                    browser.verify_session(&fetch_url, budget_ms)
                })
                .await;
                let Some(returned) = returned else {
                    return (None, Err("session_verification"));
                };
                browser = returned;
                match probed {
                    Some(Ok(probe)) => session_verified(&request.fetch_url, &probe),
                    Some(Err(CaptureDriveError)) | None => Err(VerificationFailure::Unreadable),
                }
            };
            match verdict {
                Ok(()) => return (Some(browser), Ok(HandoffEnd::LoginVerified)),
                // Not the end of the handoff: the person may still be part way
                // through a multi-step sign-in.
                Err(failure) => verification.failed(inputs, failure, Instant::now()),
            }
        }
    }

    /// Close the browser and delete the throwaway profile. Runs on every exit
    /// path that created the profile directory; a failed delete is recorded
    /// and surfaces exactly like a failed file delete, as residue.
    async fn dispose(
        &self,
        browser: Option<Box<dyn CaptureBrowser>>,
        placement: &CapturePlacement,
    ) -> Disposal {
        if let Some(browser) = browser {
            let _ = on_browser(browser, |browser| browser.close()).await;
        }
        let deleted = delete_recording(
            &self.env.fs,
            &self.failed_deletions,
            &placement.profile_directory,
            true,
        );
        Disposal { deleted }
    }
}

enum Poll {
    Open { saw_credential_field: bool },
    HeuristicHeld(HeuristicInputs),
    Exited,
}

/// What the login heuristic read on a poll where it held. Names and a URL
/// only, never a cookie value.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HeuristicInputs {
    cookie_names: BTreeSet<String>,
    url: String,
}

/// One handoff's record of its failed verifications, used to decide when the
/// next verification may start. Verifications run one at a time on the
/// handoff's own task, so a second can never start while one is in flight.
#[derive(Default)]
struct VerificationRecord {
    /// What the heuristic read before the last failed verification, when that
    /// verification finished, and why it failed.
    last: Option<(HeuristicInputs, Instant, VerificationFailure)>,
}

impl VerificationRecord {
    /// Whether a poll on which the heuristic held should verify. The first
    /// such poll always does. After a failure the next waits at least
    /// `min_spacing`, and then goes ahead if the heuristic's inputs changed,
    /// or once `retry_interval` has passed if they did not.
    fn due(
        &self,
        inputs: &HeuristicInputs,
        now: Instant,
        min_spacing: Duration,
        retry_interval: Duration,
    ) -> bool {
        let Some((previous, finished, _)) = &self.last else {
            return true;
        };
        let since = now.saturating_duration_since(*finished);
        since >= retry_interval || (since >= min_spacing && previous != inputs)
    }

    fn failed(&mut self, inputs: HeuristicInputs, failure: VerificationFailure, at: Instant) {
        self.last = Some((inputs, at, failure));
    }

    /// The last failure, when the heuristic held but no verification passed.
    fn last_failure(&self) -> Option<VerificationFailure> {
        self.last.as_ref().map(|(_, _, failure)| *failure)
    }
}

/// Run blocking browser work off the async runtime, handing the browser back.
///
/// `None` for the browser means the blocking task itself failed (it
/// panicked); the browser is then gone, and its launch record is left for
/// crash recovery, which terminates it by exact generation.
async fn on_browser<T, F>(
    mut browser: Box<dyn CaptureBrowser>,
    work: F,
) -> (Option<Box<dyn CaptureBrowser>>, Option<T>)
where
    T: Send + 'static,
    F: FnOnce(&mut dyn CaptureBrowser) -> T + Send + 'static,
{
    match tokio::task::spawn_blocking(move || {
        let result = work(browser.as_mut());
        (browser, result)
    })
    .await
    {
        Ok((browser, result)) => (Some(browser), Some(result)),
        Err(_) => (None, None),
    }
}

/// Delete one path, recording a failure for the residue refusal. Returns
/// whether the path is gone.
fn delete_recording(
    fs: &Arc<dyn CaptureFs>,
    failures: &Arc<Mutex<BTreeMap<PathBuf, String>>>,
    path: &Path,
    is_dir: bool,
) -> bool {
    let result = if is_dir {
        fs.remove_dir_all(path)
    } else {
        fs.remove_file(path)
    };
    let mut failures = failures
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match result {
        Ok(()) => {
            failures.remove(path);
            true
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            failures.remove(path);
            true
        }
        Err(error) => {
            failures.insert(path.to_path_buf(), format!("{:?}", error.kind()));
            false
        }
    }
}

fn new_capture_id() -> String {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or_default();
    format!(
        "{nanos:x}-{:x}-{:x}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// How loudly the capture's consent card notifies. High because `run` holds
/// the `browser.capture_login` call open on the answer, with no shorter park:
/// the agent is blocked until the person decides or the question expires.
const CAPTURE_CONSENT_URGENCY: crate::consent_card::Urgency = crate::consent_card::Urgency::High;

/// Built before a browser exists so no captured cookie can enter the question.
pub fn consent_question(request: &CaptureRequest, file_lifetime: Duration) -> Value {
    use crate::consent_card::*;
    let minutes = file_lifetime.as_secs().div_ceil(60);
    let site = &request.credential_domain;
    ConsentCard {
        title: format!("Save your {site} login?"),
        prompt: format!("{HOLDER_DISPLAY_NAME} will hold a copy of your {site} login."),
        target: Target {
            kind: TargetKind::Site,
            label: site.clone(),
        },
        facts: vec![
            Fact::new("Account", &request.account),
            Fact::new(
                "Browser",
                "Sign in in a new, empty browser window; your own browser is not touched",
            ),
            Fact::new("Local copy", format!("Deleted after {minutes} minutes")),
            Fact::new(
                "Storage",
                format!("The operator stores the login for {HOLDER_DISPLAY_NAME} with ck auth put"),
            ),
        ],
        grants: vec![ConsentOption::grant(ALLOW_DECISION, "Allow")],
        decline: ConsentOption::decline(DENY_DECISION, "Don't allow"),
        expires_in: crate::login_import::ELICITATION_DEADLINE,
        material_damage: true,
        urgency: CAPTURE_CONSENT_URGENCY,
        // The two parts of the vault id the captured login is stored under
        // (see `CaptureRequest::credential_id`).
        scope: Scope::new()
            .with("credential_domain", request.credential_domain.as_str())
            .with("account", request.account.as_str()),
        duration: None,
    }
    .render(&format!("capture-login-{}", new_capture_id()))
}

/// `None` only for an affirmative answer. Every other ending -- a refusal,
/// silence, a question nobody was shown, one that never left, or a word this
/// module does not know -- is a refusal, named so the caller can tell them
/// apart.
fn consent_refusal(answer: &AskOutcome) -> Option<&'static str> {
    match answer {
        AskOutcome::Answered(body) => match body.get("decision").and_then(Value::as_str) {
            Some(ALLOW_DECISION) => None,
            Some(DENY_DECISION) => Some("deny"),
            _ => Some("unrecognized_answer"),
        },
        AskOutcome::NoAnswer => Some("no_answer"),
        AskOutcome::NotPutToAnyone => Some("not_put_to_anyone"),
        AskOutcome::Undeliverable => Some("undeliverable"),
    }
}

/// What a caller should do after each refusal [`consent_refusal`] names.
///
/// One remedy for all of them would be wrong for most: telling a caller to ask
/// again after a question nobody was shown sends it round a loop it cannot
/// leave, because the next question reaches nobody either.
fn consent_refusal_remedy(reason: &str) -> &'static str {
    match reason {
        "deny" => "nothing was captured; the person declined. Ask again only if they now want this login held.",
        "no_answer" => "nothing was captured; the person was asked but did not answer in time. Ask again when they are available.",
        "not_put_to_anyone" => "nothing was captured; the question reached nobody, so asking again will not help until a person can be reached through the caller's consent route.",
        "undeliverable" => "nothing was captured; the question could not be sent. Retry once; if it fails again, the module needs attention.",
        _ => "nothing was captured; the answer was not one this question offered. Ask again.",
    }
}

/// The two commands the operator runs: store the file under the credential
/// id, then grant the holder read access to exactly that id.
pub fn operator_commands(credential_id: &str, path: &Path) -> [String; 2] {
    [
        format!(
            "ck auth put --id {credential_id} --payload-file {}",
            shell_word(&path.display().to_string())
        ),
        format!(
            "ck auth grant --principal {HOLDER} --selector-kind exact --selector {credential_id} --operation read"
        ),
    ]
}

fn replace_note(credential_id: &str) -> String {
    format!(
        "If {credential_id} already exists in the vault, run the put with --replace instead of adding a new account suffix: insula refuses a second handle for one cookie family, so a re-capture replaces the same id. Cerebellum cannot tell which case applies because it never reads the vault."
    )
}

/// Quote a path for a POSIX shell only when it needs it.
fn shell_word(word: &str) -> String {
    if !word.is_empty()
        && word
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        word.to_string()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// The journal record an attempt accumulates.
struct Record {
    origin: String,
    credential_id: String,
    deletion_succeeded: Option<bool>,
}

impl Record {
    fn new(request: &CaptureRequest) -> Self {
        Self {
            origin: request.login_origin().unwrap_or_else(|| "null".to_string()),
            credential_id: request.credential_id(),
            deletion_succeeded: None,
        }
    }

    fn with_deletion(mut self, deleted: bool) -> Self {
        self.deletion_succeeded = Some(deleted);
        self
    }

    fn payload(&self, outcome: &str, bytes: u64) -> LoginCapturePayload {
        LoginCapturePayload {
            origin: self.origin.clone(),
            holder: HOLDER.to_string(),
            credential_id: self.credential_id.clone(),
            bytes,
            outcome: outcome.to_string(),
            deletion_succeeded: self.deletion_succeeded,
        }
    }

    fn refused(self, code: &'static str, mut detail: Value) -> CaptureOutcome {
        if let Some(object) = detail.as_object_mut() {
            object.insert("outcome".into(), Value::String(code.to_string()));
        }
        CaptureOutcome {
            reply: detail,
            journal: self.payload(&format!("refused:{code}"), 0),
            captured_file: None,
        }
    }

    /// A handoff that ended after the login heuristic held but no verification
    /// showed a working session. The journal records the plain outcome; the
    /// reply adds the reason and what the last verification found.
    fn ended_unverified(
        self,
        outcome: &'static str,
        fetch_url: &str,
        failure: VerificationFailure,
    ) -> CaptureOutcome {
        let mut ended = self.ended(
            outcome,
            Some(&format!(
                "the sign-in looked finished, but loading {fetch_url} with the browser's session {}; nothing was captured. Have the person finish signing in (every step, until {fetch_url} opens signed in), then capture again",
                failure.describe()
            )),
        );
        if let Some(object) = ended.reply.as_object_mut() {
            object.insert(
                "reason".into(),
                Value::String(LOGIN_NOT_VERIFIED.to_string()),
            );
        }
        ended
    }

    fn ended(self, outcome: &'static str, remedy: Option<&str>) -> CaptureOutcome {
        let mut reply = json!({"outcome": outcome});
        if let (Some(remedy), Some(object)) = (remedy, reply.as_object_mut()) {
            object.insert("remedy".into(), Value::String(remedy.to_string()));
        }
        CaptureOutcome {
            reply,
            journal: self.payload(outcome, 0),
            captured_file: None,
        }
    }
}

#[cfg(test)]
pub mod test_support;

#[cfg(test)]
mod tests;
