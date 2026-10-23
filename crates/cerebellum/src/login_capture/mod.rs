//! Fresh-login capture for `browser.capture_login`.
//!
//! A consumer (today only insula) needs one raw session cookie per provider.
//! Copying the person's live session would give it two holders, and some sites
//! sign one copy out. So this operation launches a THROWAWAY browser profile,
//! hands the window to the person to log in, and after the login is verified
//! reads the request `Cookie:` header for the one URL the holder will fetch.
//!
//! This is the only path in the module that holds a cookie VALUE. The value
//! goes to exactly one place: the vault. Once the person grants the consent
//! card, the capture deposits the header in claustrum with
//! `credential.deposit_cookie` (see [`vault`]), and the vault decides who may
//! read it. The deposit names the card the person tapped, the answer's
//! `elicitation_id`, as its `consent_ref`; an approval without one is refused
//! before the browser is launched. Nothing is written to disk by this module and no command is handed
//! back for anyone to run.
//!
//! The value never reaches the wire reply, the consent question, the journal,
//! or a panic message: [`CookieHeader`] has no `Display`, no `Serialize`, and
//! a `Debug` that prints only its length. It is moved into the request bytes
//! ([`vault_wire::deposit_request`]) and wiped there the moment those bytes
//! exist; the request bytes are wiped when the deposit ends. The reply carries
//! the vault's id, outcome and record version, and the journal the id, the
//! outcome or refusal code, and the header's length.
//!
//! The throwaway profile lives under the per-user temporary directory, is
//! proven excluded from backups before the browser starts (the profile holds
//! the session too), and is deleted before the deposit is made, so the login
//! exists in one place only once it is stored.
//!
//! Everything that touches the host sits behind a seam ([`BackupExclusion`],
//! [`CaptureFs`], [`CaptureLauncher`], [`vault::CookieVault`]), so the
//! decisions below are exercised on any platform without a browser or a
//! daemon.

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use cerebellum_core::identity::AcceptedBindFacts;
use serde_json::{json, Map, Value};

use crate::cingulate_client::desk::{Ending, NoCard};
use crate::computer_grants::{ComputerGrants, LoginAnswer, LoginConsent, LoginConsentRequest};
use crate::journal::LoginCapturePayload;

pub mod vault;
pub mod vault_wire;

/// The principal a captured login is for, as the consent card names it and
/// the journal records it.
///
/// The vault decides who may read a deposited cookie (its `browser-session`
/// category), and this module sends no holder with the deposit. The constant
/// is what the person is told, so it is fixed rather than a request
/// parameter: a caller-chosen holder would be the caller choosing whom the
/// person is told receives their login.
pub const HOLDER: &str = "reserved:insula";
/// How the holder is named to the person in the consent question.
const HOLDER_DISPLAY_NAME: &str = "insula";
/// The directory under the per-user temporary directory that holds the
/// throwaway profile.
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
pub const OUTCOMES: [&str; 22] = [
    "capture_pending",
    "session_invalid",
    "handoff_interrupted",
    "captured",
    "consent_pending",
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
    "consent_unavailable",
    "capture_browser_unavailable",
    "capture_launch_failed",
    "capture_not_stored",
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
            "credential_id": string(),
            "vault_outcome": {"type": "string", "enum": ["created", "replaced"]},
            "record_version": {"type": "integer"},
            "origin": string(),
            "expires_in_ms": {"type": "integer"},
            "message": string(),
            // Only on `consent_pending`: the consent card still open.
            "ask_id": string(),
            // Only on the residue, placement and profile-deletion refusals:
            // the capture directory or profile directory they are about.
            "path": string(),
            "url": string(),
            "tool": string(),
            "reason": string(),
            "stage": string(),
            "detail": {
                "type":"object", "properties":{"reason":string(),"remedy":string()},
                "required":["reason","remedy"], "additionalProperties":false
            },
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
/// takes that reader out of the path. It is also limited to a small character
/// set, because it becomes part of that id, and an id the vault refuses as
/// `invalid_id` would only be found after the person had signed in.
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
    /// Every request parameter, in one string compared exactly. A consent
    /// answer that arrives after its call returned is used only by a retry
    /// that matches it, so an approval for one account, site or URL never
    /// admits a capture of another.
    pub fn consent_parameters(&self) -> String {
        json!([
            self.credential_domain,
            self.account,
            self.fetch_url,
            self.login_url
        ])
        .to_string()
    }

    /// The vault id the capture is deposited under.
    pub fn credential_id(&self) -> String {
        format!("cookie:{}:{}", self.credential_domain, self.account)
    }

    /// The account label when it is an email address, which the deposit
    /// passes on as `email`; `None` for any other label, which the deposit
    /// then omits. A label is read as an email address when it has exactly
    /// one `@`, something before it, and a dotted domain after it.
    pub fn account_email(&self) -> Option<&str> {
        let (local, domain) = self.account.split_once('@')?;
        let email = !local.is_empty()
            && !domain.contains('@')
            && domain.split('.').count() >= 2
            && domain.split('.').all(|label| !label.is_empty());
        email.then_some(self.account.as_str())
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
        vault_wire::wipe(&mut self.0);
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

/// Keeping the capture directory, where the throwaway profile and its session
/// live while the person signs in, out of Time Machine.
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
    /// Remove a file found as residue (a cookie file a build that still wrote
    /// one left behind).
    fn remove_file(&self, path: &Path) -> io::Result<()>;
    fn remove_dir_all(&self, path: &Path) -> io::Result<()>;
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
    /// The heuristic held with no handoff time left to load anything.
    NotChecked,
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
            Self::NotChecked => "was not checked before the handoff ended".to_string(),
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
            Ok(None) if !before_deadline(started, Instant::now(), deadline) => {
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

/// The child is still inside its allowed tool window only while the measured
/// duration from `started` is strictly less than `deadline`.
fn before_deadline(started: Instant, now: Instant, deadline: Duration) -> bool {
    now.saturating_duration_since(started) < deadline
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
            });
        }
        residue.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(residue)
    }

    fn create_profile_dir(&self, path: &Path) -> io::Result<()> {
        create_private_dir(path)
    }

    fn remove_file(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_file(path)
    }

    fn remove_dir_all(&self, path: &Path) -> io::Result<()> {
        std::fs::remove_dir_all(path)
    }
}

fn create_private_dir(path: &Path) -> io::Result<()> {
    cerebellum_core::private_fs::create_dir(path)
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
    /// See [`vault::DEPOSIT_DEADLINE`].
    pub deposit_deadline: Duration,
    /// The wait before each retry of a transient vault refusal; its length is
    /// the number of retries. See [`vault::RETRY_BACKOFF`].
    pub deposit_backoff: Vec<Duration>,
}

impl CaptureEnv {
    /// The host this module runs on.
    pub fn production(drive_deadline_ms: u64) -> Self {
        Self {
            platform_supported: cfg!(target_os = "macos"),
            root: production_root(),
            exclusion: Arc::new(Tmutil::default()),
            fs: Arc::new(HostFs),
            handoff_duration: Duration::from_millis(crate::browser_session::HANDOFF_DURATION_MS),
            poll_interval: Duration::from_millis(crate::browser_session::HANDOFF_POLL_INTERVAL_MS),
            drive_deadline_ms,
            verification_min_spacing: VERIFICATION_MIN_SPACING,
            verification_retry_interval: VERIFICATION_RETRY_INTERVAL,
            verification_deadline: VERIFICATION_DEADLINE,
            deposit_deadline: vault::DEPOSIT_DEADLINE,
            deposit_backoff: vault::RETRY_BACKOFF.to_vec(),
        }
    }
}

/// Module-owned capture state: one capture at a time, and the deletion
/// failures the residue refusal reports.
pub struct CaptureModule {
    env: CaptureEnv,
    launcher: Mutex<Option<Arc<dyn CaptureLauncher>>>,
    vault: Mutex<Option<Arc<dyn vault::CookieVault>>>,
    in_progress: Arc<Mutex<bool>>,
    /// Paths whose deletion failed, with the error kind. The residue refusal
    /// names the path from disk; this adds why the module could not remove it.
    failed_deletions: Arc<Mutex<BTreeMap<PathBuf, String>>>,
}

/// Everything a capture call needs from the route that made it.
pub struct CaptureCall<'a, Cancelled> {
    pub accepted: &'a AcceptedBindFacts,
    /// The module's computer grants, which hold the login card: a call
    /// joins a card already open for the same capture, takes a late approval
    /// once, or raises the card with Cingulate and waits a bounded time in the
    /// call (see [`ComputerGrants::require_login`]).
    pub grants: &'a Arc<ComputerGrants>,
    /// This call's need for consent, with the live agent call the card is
    /// raised under.
    pub consent: LoginConsentRequest,
    /// Whether the caller cancelled the request, its route went away, or the
    /// module began draining.
    pub cancelled: Cancelled,
}

/// A finished capture: the reply to send and the journal record to write
/// first.
#[derive(Debug)]
pub struct CaptureOutcome {
    pub reply: Value,
    pub journal: LoginCapturePayload,
}

/// The window is ready, but observation waits until the caller has durably
/// recorded who must receive its settlement. A failed write aborts the capture.
pub(crate) struct CaptureHandoff {
    pub origin: String,
    pub expires_in_ms: u64,
    pub proceed: tokio::sync::oneshot::Sender<bool>,
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
            vault: Mutex::new(None),
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

    /// Publish the vault captures deposit into. Set at module startup, once
    /// the daemon's connection file is known; that is after this module is
    /// constructed, so it cannot be a constructor argument.
    pub fn set_vault(&self, vault: Arc<dyn vault::CookieVault>) {
        *self
            .vault
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(vault);
    }

    fn vault(&self) -> Option<Arc<dyn vault::CookieVault>> {
        self.vault
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

    /// Delete everything left in the capture root. Run once at module startup,
    /// after launch recovery has terminated any capture browser an earlier
    /// module process left running, so nothing there is in use: what is left
    /// is a throwaway profile a crashed capture never deleted, or a cookie
    /// file from a build that still wrote one.
    ///
    /// A deletion that fails is recorded, and the next capture refuses with
    /// `capture_residue_present`: the module logs nothing, so that refusal is
    /// the report.
    pub fn sweep_at_startup(&self) {
        let Some(root) = self.env.root.clone() else {
            return;
        };
        let Ok(residue) = self.env.fs.residue(&root) else {
            return;
        };
        for entry in residue {
            delete_recording(
                &self.env.fs,
                &self.failed_deletions,
                &entry.path,
                entry.is_dir,
            );
        }
    }

    /// Run one capture to its end. The throwaway profile is deleted before
    /// the login is deposited and before this returns, so the session exists
    /// in one place, the vault, by the time a caller hears back.
    ///
    /// A late approval this call took (an answer the person gave after an
    /// earlier capture call had stopped waiting) can be used only once, so
    /// Cingulate is told what became of it before this returns.
    pub async fn run<Cancelled>(
        &self,
        request: &CaptureRequest,
        call: CaptureCall<'_, Cancelled>,
    ) -> CaptureOutcome
    where
        Cancelled: Fn() -> bool,
    {
        self.run_notifying(request, call, None).await
    }

    pub(crate) async fn run_notifying<Cancelled>(
        &self,
        request: &CaptureRequest,
        call: CaptureCall<'_, Cancelled>,
        handoff: Option<tokio::sync::oneshot::Sender<CaptureHandoff>>,
    ) -> CaptureOutcome
    where
        Cancelled: Fn() -> bool,
    {
        let carrier = Arc::clone(&call.consent.carrier);
        let mut taken = None;
        let outcome = self.run_consented(request, call, &mut taken, handoff).await;
        if let Some(answer) = taken {
            crate::computer_grants::report_login_execution(
                &carrier,
                &answer,
                &outcome.reply,
                "captured",
            )
            .await;
        }
        outcome
    }

    /// The capture itself. `taken` is set once the call has taken a late
    /// approval, whatever happens after.
    async fn run_consented<Cancelled>(
        &self,
        request: &CaptureRequest,
        call: CaptureCall<'_, Cancelled>,
        taken: &mut Option<LoginAnswer>,
        handoff: Option<tokio::sync::oneshot::Sender<CaptureHandoff>>,
    ) -> CaptureOutcome
    where
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
        // Only a live call from an admitted agent session can raise the card.
        if let Err(not_live) = call.consent.carrier.live() {
            let why = NoCard::of_not_live(not_live);
            return record.refused(
                "consent_unavailable",
                json!({"detail":{"reason":why.reason(), "remedy":why.remedy()}}),
            );
        }
        let Some(launcher) = self.launcher() else {
            return record.refused(
                "capture_browser_unavailable",
                json!({"remedy": "configure a supported browser executable for this module"}),
            );
        };
        // With no vault to deposit into, the capture is refused before the
        // person is asked to sign in: the login could not be stored after.
        let Some(vault) = self.vault() else {
            return record.refused(
                "capture_not_stored",
                json!({
                    "credential_id": request.credential_id(),
                    "reason": VAULT_UNREACHABLE,
                    "remedy": "this module has no route to the vault, so nothing was captured; it needs a daemon connection",
                }),
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
        let question = consent_question(request);
        let consent_desk = call.consent.carrier.desk();
        // The consent wait owns detaching or withdrawing the card. A polling
        // cancellation must signal that wait and keep it alive until cleanup
        // finishes, even when Cingulate's detach reply is not ready yet.
        let answer = {
            let mut consent = call.consent;
            let cancel = consent
                .cancel
                .get_or_insert_with(crate::CancelHandle::pending)
                .clone();
            let asked = call.grants.require_login(consent, move || question.clone());
            tokio::pin!(asked);
            let check = self.env.poll_interval.min(CANCEL_CHECK_INTERVAL);
            loop {
                tokio::select! {
                    biased;
                    answer = &mut asked => break Some(answer),
                    () = tokio::time::sleep(check) => {
                        if (call.cancelled)() {
                            cancel.cancel();
                            let _ = (&mut asked).await;
                            break None;
                        }
                    }
                }
            }
        };
        let Some(answer) = answer else {
            return record.ended("cancelled", None);
        };
        let answer = match answer {
            LoginConsent::Ended(answer) => {
                if let Ending::NoCard(why) = answer.ending {
                    return record.refused(
                        "consent_unavailable",
                        json!({"detail":{"reason":why.reason(), "remedy":why.remedy()}}),
                    );
                }
                if answer.ending == Ending::Withdrawn {
                    // The consent wait watches the same cancel handle as the
                    // polling loop above, so a cancelled call can end either
                    // way, depending on which notices first. Both are the
                    // caller's cancellation, not a withdrawn question, and
                    // must give the same result.
                    if (call.cancelled)() {
                        return record.ended("cancelled", None);
                    }
                    return record.refused("capture_consent_not_given", json!({"reason":"question_withdrawn", "remedy":"retry this call to ask again"}));
                }
                if answer.taken_approval {
                    *taken = Some(answer.clone());
                }
                answer
            }
            // Nothing was launched: the capture runs only on a call made
            // while the person is at hand, so a later approval is kept for
            // the retry rather than acted on.
            LoginConsent::Pending { ask_id } => {
                return record.refused(
                    "consent_pending",
                    json!({
                        "ask_id": ask_id,
                        "remedy": crate::computer_grants::LOGIN_CONSENT_PENDING_REMEDY,
                    }),
                )
            }
        };
        if (call.cancelled)() {
            return record.ended("cancelled", None);
        }
        if let Some(reason) = consent_refusal(&answer.ending) {
            return record.refused(
                "capture_consent_not_given",
                json!({"reason": reason, "remedy": consent_refusal_remedy(reason)}),
            );
        }
        // The deposit's `consent_ref` is the Cingulate id of the card the
        // person approved, so the vault's audit row names a consent Cingulate
        // recorded. An id that cannot be a `consent_ref` is refused here,
        // before the person is asked to sign in for nothing. This module's own
        // id for the rendered card is never used instead: it is never sent,
        // so nothing could trace a reference built from it.
        let Some(consent_ref) = answered_elicitation_id(&answer) else {
            return record.refused(
                "capture_not_stored",
                json!({
                    "credential_id": request.credential_id(),
                    "reason": CONSENT_NOT_LINKABLE,
                    "remedy": "nothing was captured: the person approved, but the approved card's id cannot serve as the vault's consent reference, so the approval cannot be linked to the stored login. Retry; if it happens again, the module needs attention.",
                }),
            );
        };

        // Placement: proven on every capture, because a person can change
        // Time Machine settings between two of them.
        let tool = self.env.exclusion.tool_name();
        let not_excluded = |reason: &str| {
            // A tool that did not answer says nothing about the exclusion, so
            // the caller is not sent to fix one that may already be in place.
            let remedy = match reason {
                "timed_out" => format!("{tool} did not answer in time; nothing was captured. Retry; if it keeps happening, check {tool} on this computer"),
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
        if consent_desk.begin_execution(&consent_ref).is_err() {
            let disposal = self.dispose(None, &placement).await;
            return record.with_deletion(disposal.deleted).refused("consent_unavailable", json!({"reason":"grant_store_unavailable", "remedy":"The consent registry could not be saved; retry when storage is available."}));
        }
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
            .hand_off(browser, request, &origin, &call.cancelled, handoff)
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

        // The header moves into the request bytes and is wiped there as soon
        // as they exist; from here the request is the only copy of the cookie.
        let credential_id = request.credential_id();
        let bytes = header.len() as u64;
        let deposit_request = vault_wire::deposit_request(
            &credential_id,
            header,
            &consent_ref,
            request.account_email(),
        );
        // The profile goes before the deposit: once the login is stored, no
        // second copy of the session may exist. A cancel from here changes
        // nothing; the deposit is bounded by its own deadline.
        let disposal = self.dispose(browser, &placement).await;
        let record = record.with_deletion(disposal.deleted);
        let deposit_request = match deposit_request {
            Ok(deposit_request) => deposit_request,
            // Checked against the vault's cookie rules before anything is
            // sent, so an oversize or odd header gets its own answer rather
            // than the vault's generic `invalid_payload`.
            Err(vault_wire::RequestBuildError::CookieNotStorable) => {
                return record.not_stored(
                    bytes,
                    COOKIE_NOT_STORABLE,
                    Some(format!(
                        "this site's cookie header cannot be stored in the vault, which takes 1 to {} bytes with no control characters other than tab; nothing was stored.",
                        vault_wire::MAX_COOKIE_BYTES
                    )),
                )
            }
            Err(_) => return record.not_stored(bytes, REQUEST_UNBUILDABLE, None),
        };
        if !disposal.deleted {
            // A copy of the session survives in the profile, and a deposit
            // cannot be withdrawn, so nothing is stored.
            drop(deposit_request);
            return record.refused(
                "capture_profile_not_deleted",
                json!({
                    "path": placement.profile_directory.display().to_string(),
                    "remedy": format!("remove {}, then capture again", placement.profile_directory.display()),
                }),
            );
        }

        let end = vault::deposit(
            vault.as_ref(),
            deposit_request,
            &credential_id,
            self.env.deposit_deadline,
            &self.env.deposit_backoff,
        )
        .await;
        record.deposited(bytes, end, self.env.deposit_deadline)
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

    /// Hand the window to the person and observe it until their session works.
    /// The handover notification lets a keyed caller detach this observation
    /// from the request after durably recording its settlement obligation.
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
        handoff: Option<tokio::sync::oneshot::Sender<CaptureHandoff>>,
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
            let names = browser.cookie_names_for_origin(&opening_origin, deadline_ms)?;
            // Preserve the credential step even if sign-in finishes before the
            // first poll after the window is handed to the person.
            let credential_field = browser.has_credential_field(deadline_ms).unwrap_or(false);
            Ok((names, credential_field))
        })
        .await;
        let (opening_cookie_names, mut saw_credential_field) = match opened {
            Some(Ok(baseline)) => baseline,
            Some(Err(CaptureDriveError)) => return (browser, Err("present")),
            None => return (browser, Err("present")),
        };
        let Some(mut browser) = browser else {
            return (None, Err("present"));
        };

        if let Some(handoff) = handoff {
            let (proceed, saved) = tokio::sync::oneshot::channel();
            let ready = CaptureHandoff {
                origin: origin.to_owned(),
                expires_in_ms: self.env.handoff_duration.as_millis() as u64,
                proceed,
            };
            if handoff.send(ready).is_err() || saved.await != Ok(true) {
                return (Some(browser), Ok(HandoffEnd::Cancelled));
            }
        }

        let guard = crate::call_context::ROUTE_GUARD.try_with(Arc::clone).ok();
        let _parked = guard.as_ref().map(|guard| guard.park_on_consent());
        // The runtime's clock, so tests can run a full-length handoff in
        // paused time; in production it is the same monotonic clock.
        let started = tokio::time::Instant::now();
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
            // Neither the wait nor the reads below run past the handoff's
            // end, so the person's window is held no longer than promised.
            tokio::time::sleep(
                self.env
                    .poll_interval
                    .min(self.env.handoff_duration.saturating_sub(started.elapsed())),
            )
            .await;
            let left = self.env.handoff_duration.saturating_sub(started.elapsed());
            if left.is_zero() {
                // The deadline check at the top of the loop ends it.
                continue;
            }
            let poll_origin = origin.to_string();
            let saw = saw_credential_field;
            let opening = opening_cookie_names.clone();
            let (returned, polled) = on_browser(browser, move |browser| {
                let end = Instant::now() + left;
                // A liveness reading that failed is not evidence the person
                // closed the window, so the handoff stays open on it and the
                // login observation below still runs.
                if browser.liveness() == crate::browser_launch::BrowserProcessLiveness::Gone {
                    return Poll::Exited;
                }
                let still_open = Poll::Open {
                    saw_credential_field: saw,
                };
                // Read failures leave the handoff open, as they do for
                // `browser.present`: a page mid-navigation fails a read.
                let Some(cap) = read_cap(deadline_ms, end) else {
                    return still_open;
                };
                let Ok(current) = browser.cookie_names_for_origin(&poll_origin, cap) else {
                    return still_open;
                };
                let Some(cap) = read_cap(deadline_ms, end) else {
                    return still_open;
                };
                let Ok(url) = browser.main_frame_url(cap) else {
                    return still_open;
                };
                let Some(cap) = read_cap(deadline_ms, end) else {
                    return still_open;
                };
                let Ok(has_credential_field) = browser.has_credential_field(cap) else {
                    return still_open;
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
            if budget_ms == 0 {
                // The deadline check at the top of the loop ends the handoff
                // next. A failure an earlier verification found says more
                // than "no time was left", so it is kept when there is one.
                if verification.last_failure().is_none() {
                    verification.failed(inputs, VerificationFailure::NotChecked, Instant::now());
                }
                continue;
            }
            let fetch_url = request.fetch_url.clone();
            let (returned, probed) = on_browser(browser, move |browser| {
                browser.verify_session(&fetch_url, budget_ms)
            })
            .await;
            let Some(returned) = returned else {
                return (None, Err("session_verification"));
            };
            browser = returned;
            let verdict = match probed {
                Some(Ok(probe)) => session_verified(&request.fetch_url, &probe),
                Some(Err(CaptureDriveError)) | None => Err(VerificationFailure::Unreadable),
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

/// The deadline for one read of a handoff poll: its own cap, cut to what is
/// left before `end`. `None` once nothing is left, so no read starts that
/// could only run past the handoff's end.
fn read_cap(deadline_ms: u64, end: Instant) -> Option<u64> {
    let left = end.saturating_duration_since(Instant::now());
    let left_ms = u64::try_from(left.as_millis()).unwrap_or(u64::MAX);
    (left_ms > 0).then_some(deadline_ms.min(left_ms))
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

/// The `capture_not_stored` reason when an approval carries no usable id of
/// the card the person approved, so the deposit could not name its consent.
pub const CONSENT_NOT_LINKABLE: &str = "consent_not_linkable";

/// The Cingulate id of the card the person approved, when it can be a
/// `consent_ref`: printable ASCII with no whitespace, 1 to
/// [`vault_wire::MAX_CONSENT_REF_BYTES`] bytes. Anything else counts as absent
/// rather than being trimmed or truncated into an id Cingulate never issued.
fn answered_elicitation_id(answer: &LoginAnswer) -> Option<String> {
    if !matches!(answer.ending, Ending::Granted { .. }) {
        return None;
    }
    let id = answer.elicitation_id.as_deref()?;
    let usable = !id.is_empty()
        && id.len() <= vault_wire::MAX_CONSENT_REF_BYTES
        && id.bytes().all(|byte| byte.is_ascii_graphic());
    usable.then(|| id.to_string())
}

/// How loudly the capture's consent card notifies. High because `run` holds
/// the `browser.capture_login` call open on the answer for up to
/// `computer_grants::CONSENT_PARK_LIMIT`: the agent is blocked until the
/// person decides or that wait ends.
const CAPTURE_CONSENT_URGENCY: crate::consent_card::Urgency = crate::consent_card::Urgency::High;

/// Built before a browser exists so no captured cookie can enter the question.
pub fn consent_question(request: &CaptureRequest) -> Value {
    use crate::consent_card::*;
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
            Fact::new(
                "Storage",
                format!(
                    "Your login is stored in the vault for {HOLDER_DISPLAY_NAME}; the sign-in window is deleted afterwards"
                ),
            ),
            Fact::new(
                "Other browsers",
                "Some sites allow one sign-in at a time; signing in here may sign you out of this site in your other browsers.",
            ),
        ],
        grants: vec![ConsentOption::grant(ALLOW_DECISION, "Allow")],
        decline: ConsentOption::decline(DENY_DECISION, "Don't allow"),
        expires_in: crate::consent_card::LOGIN_CARD_LIFETIME,
        material_damage: true,
        urgency: CAPTURE_CONSENT_URGENCY,
        // The two parts of the vault id the captured login is stored under
        // (see `CaptureRequest::credential_id`).
        scope: Scope::new()
            .with("credential_domain", request.credential_domain.as_str())
            .with("account", request.account.as_str()),
        duration: None,
    }
    .render()
}

/// `None` only for an affirmative answer. Every other ending -- a refusal,
/// silence, a card nobody was shown, one that never left, or a choice the
/// card did not offer -- is a refusal, named so the caller can tell them
/// apart.
fn consent_refusal(ending: &Ending) -> Option<&'static str> {
    match ending {
        Ending::Granted { choice_id } if choice_id == ALLOW_DECISION => None,
        Ending::Declined { choice_id } if choice_id == DENY_DECISION => Some("deny"),
        Ending::Granted { .. } | Ending::Declined { .. } => Some("unrecognized_answer"),
        Ending::NoAnswer => Some("no_answer"),
        Ending::NotPutToAnyone => Some("not_put_to_anyone"),
        Ending::DeliveryFailed => Some("undeliverable"),
        Ending::Withdrawn => Some("question_withdrawn"),
        Ending::NoCard(why) => Some(why.reason().unwrap_or("undeliverable")),
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
        "no_answer" => "nothing was captured; the answer is unavailable or was lost. Ask again.",
        "not_put_to_anyone" => "nothing was captured; the question reached nobody, so asking again will not help until a person can be reached through the caller's consent route.",
        "undeliverable" => "nothing was captured; the question could not be sent. Retry once; if it fails again, the module needs attention.",
        _ => "nothing was captured; the answer was not one this question offered. Ask again.",
    }
}

/// The `capture_not_stored` reason when no route to the vault could be opened:
/// the module has none configured, or the daemon could not be connected to.
pub const VAULT_UNREACHABLE: &str = "vault_unreachable";
/// The reason when the daemon refused to open the route to the vault.
pub const VAULT_ROUTE_REFUSED: &str = "vault_route_refused";
/// The reason when the route failed after the request was sent.
pub const VAULT_CALL_FAILED: &str = "vault_call_failed";
/// The reason when the deposit did not finish inside its deadline.
pub const VAULT_DEADLINE_EXCEEDED: &str = "vault_deadline_exceeded";
/// The reason when the vault answered outside its contract.
pub const VAULT_REPLY_MALFORMED: &str = "vault_reply_malformed";
/// The reason when the deposit request could not be built from the capture.
pub const REQUEST_UNBUILDABLE: &str = "request_unbuildable";
/// The reason when the captured header breaks the vault's cookie rules (see
/// [`vault_wire::cookie_storable`]), so no deposit was attempted.
pub const COOKIE_NOT_STORABLE: &str = "cookie_not_storable";

const INTERNAL_FAULT: &str = "an internal fault in this module's deposit; nothing was stored and capturing again will not help. Report it.";

/// What the caller should do after a vault refusal, chosen by class first:
/// a transient refusal clears by itself whatever its code, and new codes may
/// join either class.
fn vault_refusal_remedy(refusal: &vault_wire::VaultRefusal, credential_id: &str) -> String {
    if refusal.is_transient() {
        return "the vault was busy and kept refusing through every retry; nothing was stored. Capture again shortly.".to_string();
    }
    match refusal.code.as_str() {
        "not_found" => "the vault refused the deposit because this module holds no deposit grant, or reached the vault without its module identity; nothing was stored. An operator must grant reserved:cerebellum the deposit operation on the browser-session category, then capture again.".to_string(),
        "not_permitted" => format!("an operator-managed vault record already holds {credential_id}; nothing was stored. Capture under another account label, or have the operator retire that record."),
        code if code.starts_with("invalid_") => INTERNAL_FAULT.to_string(),
        _ => "the vault refused the deposit; nothing was stored.".to_string(),
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
        }
    }

    /// How a deposit ended, as the reply and the journal record. The journal
    /// keeps the vault's outcome or the refusal's reason, and the header's
    /// length; never anything else from the vault's reply.
    fn deposited(self, bytes: u64, end: vault::DepositEnd, deadline: Duration) -> CaptureOutcome {
        let seconds = deadline.as_secs_f64();
        let (reason, remedy): (String, String) = match end {
            vault::DepositEnd::Stored(deposited) => {
                let vault_outcome = deposited.outcome.as_str();
                let reply = json!({
                    "outcome": "captured",
                    "credential_id": self.credential_id,
                    "vault_outcome": vault_outcome,
                    "record_version": deposited.record_version,
                });
                return CaptureOutcome {
                    reply,
                    journal: self.payload(&format!("captured:{vault_outcome}"), bytes),
                };
            }
            vault::DepositEnd::Refused(refusal) => {
                let remedy = vault_refusal_remedy(&refusal, &self.credential_id);
                (refusal.code, remedy)
            }
            vault::DepositEnd::Unreachable => (
                VAULT_UNREACHABLE.to_string(),
                "the daemon could not be reached to open a route to the vault; nothing was stored. Capture again once the daemon is running.".to_string(),
            ),
            vault::DepositEnd::RouteRefused { code } => (
                VAULT_ROUTE_REFUSED.to_string(),
                format!(
                    "the daemon refused to open a route to the vault ({}); nothing was stored. Check that claustrum is registered and that this module may reach it, then capture again.",
                    code.as_deref().unwrap_or("no code given")
                ),
            ),
            vault::DepositEnd::CallFailed { code } => (
                VAULT_CALL_FAILED.to_string(),
                format!(
                    "the route to the vault failed after the deposit was sent ({}), so the login may or may not be stored. Capturing again replaces it under the same id.",
                    code.as_deref().unwrap_or("connection closed")
                ),
            ),
            vault::DepositEnd::DeadlineExceeded { sent: true } => (
                VAULT_DEADLINE_EXCEEDED.to_string(),
                format!("the vault did not answer within {seconds} s, so the login may or may not be stored. Capturing again replaces it under the same id."),
            ),
            vault::DepositEnd::DeadlineExceeded { sent: false } => (
                VAULT_DEADLINE_EXCEEDED.to_string(),
                format!("the vault could not be reached within {seconds} s; nothing was stored. Capture again shortly."),
            ),
            vault::DepositEnd::RequestRejected => {
                (vault_wire::INVALID_PARAMS.to_string(), INTERNAL_FAULT.to_string())
            }
            vault::DepositEnd::Malformed => {
                (VAULT_REPLY_MALFORMED.to_string(), INTERNAL_FAULT.to_string())
            }
        };
        self.not_stored(bytes, &reason, Some(remedy))
    }

    /// The login was captured but is not in the vault, and nothing else holds
    /// it: the header and the request were wiped and the profile is gone.
    fn not_stored(self, bytes: u64, reason: &str, remedy: Option<String>) -> CaptureOutcome {
        let reply = json!({
            "outcome": "capture_not_stored",
            "credential_id": self.credential_id,
            "reason": reason,
            "remedy": remedy.unwrap_or_else(|| INTERNAL_FAULT.to_string()),
        });
        CaptureOutcome {
            reply,
            journal: self.payload(&format!("refused:capture_not_stored:{reason}"), bytes),
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
        }
    }
}

#[cfg(test)]
pub mod test_support;

#[cfg(test)]
mod tests;
