//! Route-owned browser session lifecycle, leases, and the common teardown ladder.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, LockResult, Mutex, MutexGuard, OnceLock, PoisonError, TryLockError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::browser::navigation::{BrowserScreenshotObservation, BrowserSnapshotObservation};
use crate::browser::Tracker;
use crate::browser_config::BrowserConfig;
use crate::browser_launch::ExecutableIdentityCheckpoints;
use crate::coordinate::InputRect;
use crate::snapshot_store::{BackendNodeIdentity, SnapshotKind};
use cerebellum_core::clock::{MonoInstant, MonotonicClock};
use serde_json::{json, Value};

use cerebellum_core::identity::{AcceptedBindFacts, ProfileDisposition};

pub const BROWSER_LAUNCH: &str = "browser.launch";
pub const BROWSER_STATUS: &str = "browser.status";
pub const BROWSER_CLOSE: &str = "browser.close";
pub const CONTROL_TOOLS: [&str; 3] = [BROWSER_LAUNCH, BROWSER_STATUS, BROWSER_CLOSE];

/// Stage named in the refusal a caller receives when the session table's lock
/// was poisoned by a thread that panicked while holding it.
pub const BROWSER_SESSION_LOCK_STAGE: &str = "browser_session_lock";

/// The one refusal shape for an internal failure at a named stage.
///
/// It carries no free-text detail. The only text available is the poison
/// error's Display, which says nothing the stage does not, and the closed
/// control-reply schemas declare `detail` as the invalid-request object, so a
/// string there would get the whole reply withheld as a schema violation.
pub fn internal_failure_reply(stage: &'static str) -> Value {
    json!({"outcome": "internal_failure", "stage": stage})
}

// A poisoned lock means some thread panicked while holding it, so the table
// behind it may be partly updated. The two helpers below are the only ways
// this module takes such a lock, and which one a site uses depends on what it
// is for:
//
// - A site that answers a caller REFUSES with `internal_failure_reply`. The
//   caller gets a reply it can act on instead of a panicked request task, which
//   it would only see as a hang until its own timeout.
// - A site that stops or cleans up browsers (teardown, idle expiry, exit
//   observation, and the waits inside them) RECOVERS the guard and carries on.
//   Stopping a browser is the safe direction: refusing to tear down after a
//   panic leaves browser processes running and profiles locked, which is worse
//   than proceeding over a table that may be partly stale.

/// Take a lock for a site that answers a caller, refusing if it is poisoned.
pub fn refuse_poisoned<T>(result: LockResult<T>, stage: &'static str) -> Result<T, Value> {
    result.map_err(|_| internal_failure_reply(stage))
}

/// Take a lock for a site that stops or cleans up browsers, recovering it if
/// it is poisoned.
fn recover_poisoned<T>(result: LockResult<T>) -> T {
    result.unwrap_or_else(PoisonError::into_inner)
}

/// Ten minutes gives a person time to complete password-manager and 2FA steps
/// without leaving an unattended browser under human control indefinitely.
pub const HANDOFF_DURATION_MS: u64 = 10 * 60 * 1_000;
/// Poll slowly enough not to contend with the person typing in the page.
pub const HANDOFF_POLL_INTERVAL_MS: u64 = 2_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserSessionTerminalOutcome {
    Closed,
    BrowserCrashed,
    ConnectorFailure,
    CdpFailure,
    IdleExpired,
    RouteUnbound,
    ModuleShutdown,
    CleanupFailure,
    StartupIndeterminate,
}

impl BrowserSessionTerminalOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::BrowserCrashed => "browser_crashed",
            Self::ConnectorFailure => "connector_failure",
            Self::CdpFailure => "cdp_failure",
            Self::IdleExpired => "idle_expired",
            Self::RouteUnbound => "route_unbound",
            Self::ModuleShutdown => "module_shutdown",
            Self::CleanupFailure => "cleanup_failure",
            Self::StartupIndeterminate => "startup_indeterminate",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserLease {
    idle_timeout_ms: u64,
    monotonic_deadline: MonoInstant,
}

impl BrowserLease {
    pub fn established<C: MonotonicClock>(idle_timeout_ms: u64, clock: &C) -> Self {
        Self {
            idle_timeout_ms,
            monotonic_deadline: clock
                .now()
                .saturating_add(Duration::from_millis(idle_timeout_ms)),
        }
    }

    fn renew<C: MonotonicClock>(&mut self, clock: &C) {
        self.monotonic_deadline = clock
            .now()
            .saturating_add(Duration::from_millis(self.idle_timeout_ms));
    }

    pub fn deadline(&self) -> MonoInstant {
        self.monotonic_deadline
    }

    pub fn as_json<C: MonotonicClock>(&self, clock: &C, wall_now: SystemTime) -> Value {
        let remaining_ns = self
            .monotonic_deadline
            .as_nanos()
            .saturating_sub(clock.now().as_nanos());
        let rendered = wall_now
            .checked_add(Duration::from_nanos(remaining_ns))
            .unwrap_or(wall_now);
        json!({
            "idle_timeout_ms": self.idle_timeout_ms,
            "idle_expires_at": render_rfc3339_millis(rendered),
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandoffOutcome {
    LoginObserved,
    Expired,
    ClosedByCaller,
}

impl HandoffOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LoginObserved => "login_observed",
            Self::Expired => "expired",
            Self::ClosedByCaller => "closed_by_caller",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Handoff {
    generation: u64,
    origin: String,
    opened_at: MonoInstant,
    expires_at: MonoInstant,
    opening_cookie_names: BTreeSet<String>,
    saw_credential_field: bool,
    cookie_names_added: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClosedHandoff {
    handoff: Handoff,
    outcome: HandoffOutcome,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum HandoffState {
    Open(Handoff),
    Closed(ClosedHandoff),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresentedHandoff {
    pub generation: u64,
    pub expires_in_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PresentRefusal {
    NoSession,
    OriginMismatch { current_origin: String },
    HandoffOpen,
    PresentFailed { error_text: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandoffClose {
    pub origin: String,
    pub outcome: HandoffOutcome,
    pub cookie_names_added: usize,
    pub should_journal: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandoffPollResult {
    Open,
    Closed(HandoffClose),
    Gone,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeRefusal {
    NoHandoff,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HumanInControl {
    pub origin: String,
    pub expires_in_ms: u64,
}

pub(crate) fn render_rfc3339_millis(time: SystemTime) -> String {
    let duration = time.duration_since(UNIX_EPOCH).unwrap_or_default();
    let seconds = duration.as_secs();
    let days = seconds / 86_400;
    let seconds_of_day = seconds % 86_400;
    let (year, month, day) = civil_from_days(days as i64);
    let hour = seconds_of_day / 3_600;
    let minute = seconds_of_day % 3_600 / 60;
    let second = seconds_of_day % 60;
    format!(
        "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{:03}Z",
        duration.subsec_millis()
    )
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CleanupStage {
    Reap,
    RecordTerminalization,
    CustodyRelease,
    DisposableDelete,
    /// Module shutdown could not stop the browser within its budget, so the
    /// profile's custody was deliberately left held; the next start's launch
    /// recovery stops the browser and releases it.
    CustodyHeld,
    /// The directory the browser's crash handler wrote to could not be
    /// deleted. It can hold page memory from the session, so a failure is
    /// reported rather than passed over; the next start retries the delete.
    CrashReportsDelete,
}

impl CleanupStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reap => "reap",
            Self::RecordTerminalization => "record_terminalization",
            Self::CustodyRelease => "custody_release",
            Self::DisposableDelete => "disposable_delete",
            Self::CustodyHeld => "custody_held",
            Self::CrashReportsDelete => "crash_reports_delete",
        }
    }
}

/// An observation made while session resources were being released.
///
/// `Complete` intentionally makes no persistence claim. Chrome does not expose
/// whether every profile write succeeded, so teardown can only name evidence
/// that puts durable state at risk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionCleanupOutcome {
    Complete,
    DurableStateAtRisk {
        local_state_not_written_since_launch: bool,
        profile_not_writable: bool,
    },
}

impl SessionCleanupOutcome {
    fn failed_signals(self) -> Option<Vec<&'static str>> {
        let Self::DurableStateAtRisk {
            local_state_not_written_since_launch,
            profile_not_writable,
        } = self
        else {
            return None;
        };
        let mut signals = Vec::with_capacity(2);
        if local_state_not_written_since_launch {
            signals.push("local_state_not_written_since_launch");
        }
        if profile_not_writable {
            signals.push("profile_not_writable");
        }
        Some(signals)
    }
}

/// A successful browser launch and the executable-identity checks it completed.
pub struct LaunchedBrowser {
    pub process: Box<dyn OwnedBrowserProcess>,
    pub cleanup: Box<dyn SessionCleanup>,
    pub executable_identity_checkpoints: ExecutableIdentityCheckpoints,
}

pub trait BrowserSessionLauncher: Send + Sync {
    fn launch(
        &self,
        accepted: &AcceptedBindFacts,
        browser_session_id: &str,
    ) -> Result<LaunchedBrowser, Value>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProcessControlFailure;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NavigationDriveError {
    Unavailable,
    /// The session's own state could not be read because a thread panicked
    /// while holding one of its locks.
    StateUnavailable,
    ConnectorFailure,
    CdpFailure,
    CommandFailed {
        error_text: String,
    },
    NavigationFailed {
        error_text: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NavigationWait {
    Settle,
    None,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BrowserClickPosition {
    pub x_css: f64,
    pub y_css: f64,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BrowserInputEvent {
    Press(BrowserClickPosition),
    Release(BrowserClickPosition),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JavaScriptDialogResponse {
    Dismissed,
}

impl JavaScriptDialogResponse {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dismissed => "dismissed",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserJavaScriptDialog {
    pub dialog_type: String,
    pub response: JavaScriptDialogResponse,
}

/// What a click did to the page's main frame, as observed after its input.
///
/// Only the main frame is reported. A subframe navigating is not the page
/// moving, so it is left out rather than reported as if it were.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClickNavigation {
    /// No main-frame navigation began within `window_ms` of the input
    /// release being acknowledged.
    NoneObserved { window_ms: u64 },
    /// The main frame changed URL without replacing its document, as a
    /// fragment link or `history.pushState` does.
    SameDocument { url: String },
    /// The main frame began navigating to another document. The tracker was
    /// driven by the same settle loop `browser.navigate` uses, and may or may
    /// not have committed or settled before the deadline.
    MainFrame(Box<Tracker>),
}

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserClickOutcome {
    Clicked {
        position: BrowserClickPosition,
        navigation: ClickNavigation,
    },
    JavaScriptDialogDismissed {
        position: BrowserClickPosition,
        dialogs: Vec<BrowserJavaScriptDialog>,
        navigation: ClickNavigation,
    },
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ViewportRefusal {
    pub position: BrowserClickPosition,
    pub viewport: InputRect,
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClickDriveError {
    NoPosition,
    Intercepted(serde_json::Value),
    ClassificationChanged,
    OutsideViewportAfterScroll(ViewportRefusal),
    Navigation(NavigationDriveError),
}

#[derive(Debug, Clone, PartialEq)]
pub enum ClickPointDriveError {
    OutsideViewport(ViewportRefusal),
    Navigation(NavigationDriveError),
}

impl From<NavigationDriveError> for ClickPointDriveError {
    fn from(error: NavigationDriveError) -> Self {
        Self::Navigation(error)
    }
}

pub trait OwnedBrowserProcess: Send {
    /// Front the process-owned page without exposing a general CDP command seam.
    fn present(
        &mut self,
        _context_key: &str,
        _deadline_ms: u64,
    ) -> Result<(), NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Read cookie names for one origin. Cookie values must be discarded inside
    /// the concrete driver and cannot be represented by this return type.
    fn cookie_names_for_origin(
        &mut self,
        _context_key: &str,
        _origin: &str,
        _deadline_ms: u64,
    ) -> Result<BTreeSet<String>, NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Read only the URL of the document the main frame has COMMITTED to.
    ///
    /// It must not report a navigation that is still pending: a pending
    /// destination names a page whose content is not yet what the browser
    /// shows. The CDP driver answers from `Page.getNavigationHistory`'s
    /// current entry, which moves only when a navigation commits.
    fn main_frame_url(
        &mut self,
        _context_key: &str,
        _deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Read the committed main-frame document: its URL, its history entry and
    /// its document loader. See `CommittedDocument` for what each identifies.
    ///
    /// Page reads authorize against this document's URL and refuse when it
    /// changes during the capture; actions refuse when it is no longer the
    /// document their snapshot was taken from. The default refuses, so a
    /// process that cannot say which document it shows can serve neither.
    fn committed_document(
        &mut self,
        _context_key: &str,
        _deadline_ms: u64,
    ) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Report only whether the current classified page contains a credential field.
    fn has_credential_field(
        &mut self,
        _context_key: &str,
        _deadline_ms: u64,
    ) -> Result<bool, NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Drive through the process-owned CDP connection. The default keeps test
    /// and non-production process adapters explicitly non-dispatchable.
    fn navigate(
        &mut self,
        _context_key: &str,
        _url: &str,
        _wait: NavigationWait,
        _deadline_ms: u64,
        _tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Read page structure through the process-owned CDP driver.
    ///
    /// This capability-specific method avoids exposing an unrestricted CDP command
    /// surface while still preserving the pipe's single-writer ownership.
    fn snapshot(
        &mut self,
        _context_key: &str,
        _mode: SnapshotKind,
        _deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Capture form classifications with refs from the same document epoch.
    fn snapshot_classified(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        _document_epoch: u64,
        _current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.snapshot(context_key, mode, deadline_ms)
    }

    /// Capture one visual viewport through the process-owned CDP driver.
    fn screenshot(
        &mut self,
        _context_key: &str,
        _document_epoch: u64,
        _deadline_ms: u64,
        _full: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        Err(NavigationDriveError::Unavailable)
    }

    /// Resolve and click one snapshot-backed DOM identity through the process-owned
    /// CDP driver. The callback records input only after its frame reaches the pipe.
    fn click(
        &mut self,
        _context_key: &str,
        _identity: &BackendNodeIdentity,
        _deadline_ms: u64,
        _input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        Err(ClickDriveError::Navigation(
            NavigationDriveError::Unavailable,
        ))
    }

    fn classify_point(
        &mut self,
        _context_key: &str,
        _position: BrowserClickPosition,
        _document_epoch: u64,
        _document_url: &str,
        _deadline_ms: u64,
    ) -> Result<
        Result<
            crate::classification::NonTypeClassificationRecord,
            crate::classification::ClassificationUnavailable,
        >,
        NavigationDriveError,
    > {
        Err(NavigationDriveError::Unavailable)
    }

    #[allow(clippy::too_many_arguments)]
    fn click_point_classified(
        &mut self,
        _context_key: &str,
        _position: BrowserClickPosition,
        _document_epoch: u64,
        _document_url: &str,
        _expected: &crate::classification::NonTypeClassificationRecord,
        _deadline_ms: u64,
        _input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        Err(ClickDriveError::ClassificationChanged)
    }

    /// Dispatch a screenshot-backed coordinate through the process-owned CDP driver.
    fn click_point(
        &mut self,
        _context_key: &str,
        _position: BrowserClickPosition,
        _deadline_ms: u64,
        _input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        Err(ClickPointDriveError::Navigation(
            NavigationDriveError::Unavailable,
        ))
    }

    /// Reclassify immediately before input and require the pinned classification
    /// to still describe the target. A process adapter that cannot perform that
    /// check must refuse rather than inherit the earlier authorization.
    #[allow(clippy::too_many_arguments)]
    fn click_classified(
        &mut self,
        _context_key: &str,
        _identity: &BackendNodeIdentity,
        _document_epoch: u64,
        _current_origin: &str,
        _expected: Option<&crate::classification::NonTypeClassificationRecord>,
        _deadline_ms: u64,
        _input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        Err(ClickDriveError::ClassificationChanged)
    }

    fn generation_matches(&self) -> bool;
    fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure>;
    fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure>;
    fn force_terminate(&mut self) -> Result<(), ProcessControlFailure>;
    fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure>;

    /// A handle that module shutdown can use to kill this browser without
    /// taking the session's driver lock. `None`, the default, means shutdown
    /// can only wait for a browser call already in progress to return on its
    /// own.
    fn shutdown_killer(&self) -> Option<Arc<dyn BrowserKiller>> {
        None
    }

    /// A read-only handle that tells whether this browser is still running,
    /// usable without the session's driver lock. `None`, the default, makes
    /// exit observation fall back to `generation_matches` when the driver
    /// lock is free.
    fn exit_probe(&self) -> Option<Arc<dyn BrowserExitProbe>> {
        None
    }
}

/// Kills one launched browser generation without going through the session's
/// driver lock.
///
/// Every browser driver call holds its session's driver lock for as long as
/// its CDP call takes. A shutdown that could reach a browser only through that
/// lock would therefore wait out whatever call happened to be in progress,
/// however long its deadline. This handle is kept beside the lock so shutdown
/// can end such a browser; the dying browser fails the call, which then gives
/// the lock back.
pub trait BrowserKiller: Send + Sync {
    /// Kill exactly the process generation this handle was made for, never a
    /// bare pid: by the time shutdown fires, the pid may name another process.
    /// Calling it again after it reported `Dead` changes nothing. On platforms
    /// whose generation-checked kill also reaps an owned child, it may reap;
    /// the session's normal reap path tolerates that.
    fn kill_exact_generation(&self) -> KillOutcome;
}

/// Tells whether one launched browser generation is still running, without
/// the session's driver lock. It only observes: it never signals or reaps.
pub trait BrowserExitProbe: Send + Sync {
    /// Whether the recorded process generation is still the running process.
    fn generation_matches(&self) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KillOutcome {
    /// The browser is dead: this call killed it, or it had already gone.
    Dead,
    /// Whether the pid still names this browser could not be confirmed, so
    /// nothing was signalled and the browser may still be running.
    Refused,
}

/// How long a module shutdown may spend closing browsers, measured from the
/// moment the shutdown starts.
///
/// The daemon's side of the contract: after a module's connection ends it
/// waits up to 25 s (the module drain deadline, 30 s by default but capped at
/// 25 s for modules), then sends SIGTERM, then SIGKILL half a second later.
/// Whatever teardown is still running at SIGKILL never releases profile
/// custody, which leaves the profile locked for the next launch. 20 s leaves
/// 5 s of that window for the process to exit and for anything unforeseen.
pub const SHUTDOWN_TEARDOWN_BUDGET: Duration = Duration::from_secs(20);

/// How long shutdown waits for browser operations already in progress before
/// it closes their browsers anyway. Closing a browser under an operation fails
/// that operation, which is the right result when the module is going away.
pub const SHUTDOWN_IN_FLIGHT_WAIT_MAX: Duration = Duration::from_secs(5);

/// Time kept free at the end of the shutdown budget for the steps that must
/// never be cut short: the forced kill and reap, then the session's after-reap
/// cleanup. That cleanup checks profile persistence (a stat and a small probe
/// write), finalizes the launch journal (an fsynced append), releases profile
/// custody (journal writes), and deletes the profile directory when it was
/// disposable. The deletion dominates: a used Chromium profile holds tens of
/// thousands of files and deleting one takes around a second on a local SSD, so
/// 5 s leaves several times that. The graceful-close wait is shortened so that
/// it never eats into this reserve.
pub const SHUTDOWN_CLEANUP_RESERVE: Duration = Duration::from_secs(5);

/// How often shutdown tries the driver lock again while a call in progress
/// holds it. `try_lock` is polled rather than parked on, so the wait for that
/// lock ends by the shutdown plan and not by the call's own deadline.
const SHUTDOWN_POLL: Duration = Duration::from_millis(5);

/// The time limits one module shutdown works within.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShutdownBudget {
    pub total: Duration,
    pub in_flight_wait_max: Duration,
    pub cleanup_reserve: Duration,
}

impl ShutdownBudget {
    pub const PRODUCTION: Self = Self {
        total: SHUTDOWN_TEARDOWN_BUDGET,
        in_flight_wait_max: SHUTDOWN_IN_FLIGHT_WAIT_MAX,
        cleanup_reserve: SHUTDOWN_CLEANUP_RESERVE,
    };
}

/// A shutdown budget turned into instants, fixed once when shutdown starts so
/// that a drain, the end of the connection and SIGTERM all share one deadline.
#[derive(Debug, Clone, Copy)]
struct ShutdownPlan {
    /// Until here, operations in progress are waited for.
    in_flight_until: Instant,
    /// A graceful close must be over by here, leaving the cleanup reserve.
    graceful_until: Instant,
    /// The end of the whole budget.
    deadline: Instant,
}

impl ShutdownPlan {
    fn starting_now(budget: ShutdownBudget) -> Self {
        let start = Instant::now();
        let before_reserve = budget.total.saturating_sub(budget.cleanup_reserve);
        Self {
            in_flight_until: start + budget.in_flight_wait_max.min(before_reserve),
            graceful_until: start + before_reserve,
            deadline: start + budget.total,
        }
    }
}

/// What shutdown keeps per live session beside the session locks: whether its
/// killer has been fired and whether that kill was confirmed, and how many
/// operations are in flight on it.
///
/// Lock order: this lock (L3 below) is always taken last, after the registry
/// lock or a session's meta lock, never before either. It is never held across
/// a kill, a wait, or any other I/O; killers fire with no lock held.
#[derive(Default)]
struct ShutdownSide {
    plan: Option<ShutdownPlan>,
    routes: HashMap<String, RouteKillSwitch>,
}

struct RouteKillSwitch {
    browser_session_id: String,
    in_flight: usize,
    kill_attempted: bool,
    killed: bool,
}

pub trait SessionCleanup: Send {
    fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
        let _ = outcome;
    }

    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage>;
}

// Session locking.
//
// Four kinds of lock guard the session table:
//
// - L1, the registry: which session is active on each route and the records
//   of the ones that ended. Held only for a lookup, an insert or a removal.
// - L2, one meta lock per session: its lifecycle, lease, pending-operation
//   count, terminal outcome, cleanup result, handoff and cleanup handle. Held
//   only briefly, and it has its own condition variable.
// - LD, one driver lock per session: the browser process and its CDP pipe. It
//   is the only lock held across CDP I/O, and it keeps one writer per pipe.
// - L3, the shutdown side (`ShutdownSide`).
//
// Order: L1 -> L2 -> L3, and LD -> L2 -> L3. L1 and LD are never held
// together, and LD is only ever taken with no other lock held. No kill, sleep
// or process I/O happens under L1, L2 or L3, and the only I/O under LD is a
// driver call. A thread drops L2 after a condition-variable wait before it
// takes LD, and drops LD before any wait on the registry's condition variable.
// Debug builds check every lock taken against these rules (`lock_scope`).
//
// So one route's slow CDP call holds only that session's LD: other routes, and
// status on the same route, never wait for it.
//
// Poison policy, per lock:
// - L1 and L2: a site that answers a caller refuses; release, teardown and
//   shutdown recover the guard.
// - LD: a driver call refuses (`NavigationDriveError::StateUnavailable`),
//   because a call that panicked mid-command may have left the pipe
//   half-written; teardown and shutdown recover it to stop the browser.

/// Debug-build bookkeeping of which session locks this thread holds, so the
/// lock order above is checked on every lock taken rather than only stated.
mod lock_scope {
    use std::cell::Cell;

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(super) enum Kind {
        Registry = 0,
        Meta = 1,
        Driver = 2,
    }

    thread_local! {
        static HELD: Cell<[u32; 3]> = const { Cell::new([0; 3]) };
    }

    fn held() -> [u32; 3] {
        HELD.with(Cell::get)
    }

    fn adjust(kind: Kind, up: bool) {
        if !cfg!(debug_assertions) {
            return;
        }
        HELD.with(|held| {
            let mut counts = held.get();
            let count = &mut counts[kind as usize];
            *count = if up {
                count.saturating_add(1)
            } else {
                count.saturating_sub(1)
            };
            held.set(counts);
        });
    }

    /// Marks one held lock of `kind` for as long as it lives.
    pub(super) struct Held(Kind);

    impl Held {
        /// Check the order before the lock is taken, then count it as held.
        pub(super) fn enter(kind: Kind) -> Self {
            let [registry, meta, driver] = held();
            match kind {
                Kind::Registry => debug_assert!(
                    registry == 0 && meta == 0 && driver == 0,
                    "the session registry lock is taken with no other session lock held"
                ),
                Kind::Meta => debug_assert!(
                    meta == 0,
                    "a session meta lock is never taken while another is held"
                ),
                Kind::Driver => debug_assert!(
                    registry == 0 && meta == 0 && driver == 0,
                    "a session driver lock is taken with no other session lock held"
                ),
            }
            adjust(kind, true);
            Self(kind)
        }

        /// Check that a thread parking on this lock's condition variable holds
        /// nothing that would stall another thread for the whole wait.
        pub(super) fn assert_may_park(&self) {
            let [registry, meta, driver] = held();
            match self.0 {
                Kind::Registry => debug_assert!(
                    meta == 0 && driver == 0,
                    "waiting on the registry holds no session meta or driver lock"
                ),
                Kind::Meta => debug_assert!(
                    registry == 0 && driver == 0,
                    "waiting on a session holds no registry or driver lock"
                ),
                Kind::Driver => debug_assert!(false, "nothing waits on a driver lock"),
            }
        }
    }

    impl Drop for Held {
        fn drop(&mut self) {
            adjust(self.0, false);
        }
    }
}

/// A held session lock, counted by `lock_scope` for as long as it lives.
struct Locked<'a, T> {
    guard: MutexGuard<'a, T>,
    held: lock_scope::Held,
}

impl<T> std::ops::Deref for Locked<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T> std::ops::DerefMut for Locked<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

/// `Ok` for a clean lock, `Err` carrying the recovered guard for a poisoned
/// one, so each site picks refusal or recovery by the policy above.
type LockAttempt<'a, T> = Result<Locked<'a, T>, Locked<'a, T>>;

fn take_lock<T>(mutex: &Mutex<T>, kind: lock_scope::Kind) -> LockAttempt<'_, T> {
    let held = lock_scope::Held::enter(kind);
    match mutex.lock() {
        Ok(guard) => Ok(Locked { guard, held }),
        Err(poisoned) => Err(Locked {
            guard: poisoned.into_inner(),
            held,
        }),
    }
}

/// Take a lock without parking; `None` when another thread holds it. A
/// poisoned lock is recovered here, because only shutdown uses this.
fn try_take_lock<T>(mutex: &Mutex<T>, kind: lock_scope::Kind) -> Option<Locked<'_, T>> {
    let held = lock_scope::Held::enter(kind);
    match mutex.try_lock() {
        Ok(guard) => Some(Locked { guard, held }),
        Err(TryLockError::Poisoned(poisoned)) => Some(Locked {
            guard: poisoned.into_inner(),
            held,
        }),
        Err(TryLockError::WouldBlock) => None,
    }
}

fn recovered<G>(attempt: Result<G, G>) -> G {
    attempt.unwrap_or_else(|guard| guard)
}

impl<'a, T> Locked<'a, T> {
    fn wait(self, wake: &Condvar) -> LockAttempt<'a, T> {
        self.held.assert_may_park();
        let Locked { guard, held } = self;
        match wake.wait(guard) {
            Ok(guard) => Ok(Locked { guard, held }),
            Err(poisoned) => Err(Locked {
                guard: poisoned.into_inner(),
                held,
            }),
        }
    }

    fn wait_timeout(self, wake: &Condvar, timeout: Duration) -> LockAttempt<'a, T> {
        self.held.assert_may_park();
        let Locked { guard, held } = self;
        match wake.wait_timeout(guard, timeout) {
            Ok((guard, _)) => Ok(Locked { guard, held }),
            Err(poisoned) => Err(Locked {
                guard: poisoned.into_inner().0,
                held,
            }),
        }
    }
}

/// Where one session is in its life, kept under its meta lock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    /// The launch slot is taken and the browser is still starting.
    Launching,
    /// The browser process is in the session's driver slot.
    Ready,
    /// One terminalizer took the process out of the driver slot. Only it may
    /// reap the process, run the after-reap cleanup and retire the session.
    TeardownOwned,
    /// Teardown finished; its result is in the cleanup fields.
    Retired,
    /// The launch failed before readiness and the slot was given back.
    Abandoned,
    /// Shutdown could not reach the browser in time. It may still be running
    /// with its profile open, so profile custody stays held and the route
    /// stays occupied: a second launch must not open the same profile. The
    /// next start's launch recovery kills that browser by its exact process
    /// generation, and only then releases custody.
    CustodyHeld,
}

impl Lifecycle {
    /// Nothing further will happen to the session: every wait on it ends here.
    fn is_settled(self) -> bool {
        matches!(self, Self::Retired | Self::Abandoned | Self::CustodyHeld)
    }
}

struct SessionMeta {
    lifecycle: Lifecycle,
    disposition: ProfileDisposition,
    lease: BrowserLease,
    pending_operations: usize,
    terminal: Option<BrowserSessionTerminalOutcome>,
    cleanup_failure: Option<CleanupStage>,
    cleanup_outcome: Option<SessionCleanupOutcome>,
    handoff: Option<HandoffState>,
    /// A `present` has been admitted and has not committed or given up yet.
    /// A second `present` is refused as `HandoffOpen` meanwhile.
    handoff_opening: bool,
    next_handoff_generation: u64,
    cleanup: Option<Box<dyn SessionCleanup>>,
}

impl SessionMeta {
    /// The call-admission fence. It decides whether a NEW driver call may
    /// start; it does not stop one already running. A call that passed it
    /// before the session went terminal finishes, including every CDP
    /// command it issues (a click's mouse press and its release), and only
    /// later calls are refused. "Terminal" therefore means "no new calls",
    /// not "no further writes to the browser".
    fn admits_calls(&self) -> bool {
        self.lifecycle == Lifecycle::Ready
            && self.terminal.is_none()
            && self.cleanup_failure.is_none()
    }

    fn record(&self, browser_session_id: &str) -> SessionRecord {
        SessionRecord {
            browser_session_id: browser_session_id.to_string(),
            disposition: self.disposition,
            lease: self.lease.clone(),
            terminal: self.terminal,
            cleanup_failure: self.cleanup_failure,
            cleanup_outcome: self.cleanup_outcome,
        }
    }
}

/// The part of a session that status and close report. An ended session is
/// kept on its route as one of these plain records.
#[derive(Clone)]
struct SessionRecord {
    browser_session_id: String,
    disposition: ProfileDisposition,
    lease: BrowserLease,
    terminal: Option<BrowserSessionTerminalOutcome>,
    cleanup_failure: Option<CleanupStage>,
    cleanup_outcome: Option<SessionCleanupOutcome>,
}

impl SessionRecord {
    fn status_json<C: MonotonicClock>(&self, clock: &C, wall_now: SystemTime) -> Value {
        if let Some(stage) = self.cleanup_failure {
            return json!({
                "outcome": "cleanup_failure",
                "browser_session_id": self.browser_session_id,
                "profile_disposition": self.disposition.as_str(),
                "stage": stage.as_str(),
            });
        }
        if let Some(failed_signals) = self
            .cleanup_outcome
            .and_then(SessionCleanupOutcome::failed_signals)
        {
            return json!({
                "outcome": "durable_state_at_risk",
                "browser_session_id": self.browser_session_id,
                "profile_disposition": self.disposition.as_str(),
                "failed_signals": failed_signals,
            });
        }
        if let Some(outcome) = self.terminal {
            return json!({
                "outcome": "terminal",
                "browser_session_id": self.browser_session_id,
                "terminal_outcome": outcome.as_str(),
            });
        }
        json!({
            "outcome": "ready",
            "browser_session_id": self.browser_session_id,
            "profile_disposition": self.disposition.as_str(),
            "lease": self.lease.as_json(clock, wall_now),
        })
    }

    fn close_result(&self) -> Value {
        if let Some(stage) = self.cleanup_failure {
            return json!({
                "outcome": "cleanup_failure",
                "browser_session_id": self.browser_session_id,
                "stage": stage.as_str(),
            });
        }
        if let Some(failed_signals) = self
            .cleanup_outcome
            .and_then(SessionCleanupOutcome::failed_signals)
        {
            return json!({
                "outcome": "durable_state_at_risk",
                "browser_session_id": self.browser_session_id,
                "failed_signals": failed_signals,
            });
        }
        json!({
            "outcome": self
                .terminal
                .unwrap_or(BrowserSessionTerminalOutcome::CleanupFailure)
                .as_str(),
            "browser_session_id": self.browser_session_id,
        })
    }
}

/// One browser session and its three per-session locks.
struct SessionCell {
    route_key: String,
    browser_session_id: String,
    /// L2 and its condition variable.
    meta: Mutex<SessionMeta>,
    wake: Condvar,
    /// LD: the process, and with it the CDP pipe.
    driver: Mutex<Option<Box<dyn OwnedBrowserProcess>>>,
    /// Set once when the browser is established and never changed, so
    /// shutdown can fire it without taking any lock.
    killer: OnceLock<Arc<dyn BrowserKiller>>,
    /// Set once when the browser is established, so exit observation can ask
    /// whether the browser is still running without waiting for a call in
    /// progress to give LD back.
    exit_probe: OnceLock<Arc<dyn BrowserExitProbe>>,
}

impl SessionCell {
    fn launching(route_key: &str, browser_session_id: String) -> Self {
        Self {
            route_key: route_key.to_string(),
            browser_session_id,
            meta: Mutex::new(SessionMeta {
                lifecycle: Lifecycle::Launching,
                disposition: ProfileDisposition::None,
                lease: BrowserLease {
                    idle_timeout_ms: 1,
                    monotonic_deadline: MonoInstant::from_nanos(0),
                },
                pending_operations: 0,
                terminal: None,
                cleanup_failure: None,
                cleanup_outcome: None,
                handoff: None,
                handoff_opening: false,
                next_handoff_generation: 0,
                cleanup: None,
            }),
            wake: Condvar::new(),
            driver: Mutex::new(None),
            killer: OnceLock::new(),
            exit_probe: OnceLock::new(),
        }
    }

    fn meta(&self) -> LockAttempt<'_, SessionMeta> {
        take_lock(&self.meta, lock_scope::Kind::Meta)
    }

    fn driver(&self) -> LockAttempt<'_, Option<Box<dyn OwnedBrowserProcess>>> {
        take_lock(&self.driver, lock_scope::Kind::Driver)
    }

    fn try_driver(&self) -> Option<Locked<'_, Option<Box<dyn OwnedBrowserProcess>>>> {
        try_take_lock(&self.driver, lock_scope::Kind::Driver)
    }

    fn notify(&self) {
        self.wake.notify_all();
    }

    /// Wait, without bound, until the session is settled. Joins another
    /// thread's teardown, so a poisoned lock is recovered as teardown does.
    fn wait_settled(&self) {
        let mut meta = recovered(self.meta());
        while !meta.lifecycle.is_settled() {
            meta = recovered(meta.wait(&self.wake));
        }
    }
}

#[derive(Default)]
struct RouteSlot {
    active: Option<Arc<SessionCell>>,
    retained: Vec<SessionRecord>,
    next_session: u64,
}

#[derive(Default)]
struct Registry {
    routes: HashMap<String, RouteSlot>,
}

#[derive(Clone, Default)]
pub struct BrowserSessions {
    /// L1 and the registry's condition variable.
    registry: Arc<(Mutex<Registry>, Condvar)>,
    /// L3.
    shutdown: Arc<Mutex<ShutdownSide>>,
}

#[derive(Debug)]
pub enum IdleCloseRefusal {
    Busy,
    Presented,
    Unavailable,
}

pub enum LaunchSlot {
    Acquired {
        browser_session_id: String,
    },
    Occupied {
        browser_session_id: String,
    },
    /// The session table could not be read; the value is the reply to send.
    Refused(Value),
}

pub enum DispatchAdmission {
    Accepted(OperationGuard),
    LaunchPending,
    NoSession,
    /// The session table's lock is poisoned, so whether a session exists is
    /// unknown. Distinct from `NoSession`, whose remedy (launch one) would be
    /// wrong when a session may well exist.
    StateUnavailable,
}

/// A launched browser that the session table would not take, handed back so
/// the caller decides how to stop it rather than it being installed into a
/// session nobody will tear down.
pub struct UnestablishedBrowser {
    pub process: Box<dyn OwnedBrowserProcess>,
    pub cleanup: Box<dyn SessionCleanup>,
}

impl std::fmt::Debug for UnestablishedBrowser {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("UnestablishedBrowser")
    }
}

/// Which per-session lock a test poisons.
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionLockForTest {
    Meta,
    Driver,
}

pub struct OperationGuard {
    sessions: BrowserSessions,
    /// The session this operation was admitted on. The route may hold a newer
    /// session by the time the operation ends, and its release must not touch
    /// that session's count.
    cell: Arc<SessionCell>,
    /// This operation is a `present` holding the handoff reservation.
    handoff_reservation: bool,
    finished: bool,
}

impl OperationGuard {
    pub fn finish(mut self) {
        self.release();
    }

    /// Run one driver call on this operation's own browser.
    ///
    /// LD is taken first, with no other lock held; the fence is then checked
    /// under the meta lock, which is dropped before the call, so the CDP call
    /// holds this session's LD and nothing else.
    fn drive<T, E>(
        &mut self,
        refused: impl Fn(NavigationDriveError) -> E,
        call: impl FnOnce(&mut dyn OwnedBrowserProcess) -> Result<T, E>,
    ) -> Result<T, E> {
        let mut driver = self
            .cell
            .driver()
            .map_err(|_| refused(NavigationDriveError::StateUnavailable))?;
        {
            let meta = self
                .cell
                .meta()
                .map_err(|_| refused(NavigationDriveError::StateUnavailable))?;
            if !meta.admits_calls() {
                return Err(refused(NavigationDriveError::Unavailable));
            }
        }
        let process = driver
            .as_mut()
            .ok_or_else(|| refused(NavigationDriveError::Unavailable))?;
        call(process.as_mut())
    }

    pub(crate) fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        self.drive(
            |error| error,
            |process| process.navigate(context_key, url, wait, deadline_ms, tracker),
        )
    }

    /// Read which document the main frame has committed to, so a page read
    /// or an action can check it against where the page actually is rather
    /// than against the last navigation this module started and watched.
    pub(crate) fn committed_document(
        &mut self,
        context_key: &str,
        deadline_ms: u64,
    ) -> Result<crate::snapshot_store::CommittedDocument, NavigationDriveError> {
        self.drive(
            |error| error,
            |process| process.committed_document(context_key, deadline_ms),
        )
    }

    pub(crate) fn snapshot_classified(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        self.drive(
            |error| error,
            |process| {
                process.snapshot_classified(
                    context_key,
                    mode,
                    document_epoch,
                    current_origin,
                    deadline_ms,
                )
            },
        )
    }

    pub(crate) fn screenshot(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        self.drive(
            |error| error,
            |process| process.screenshot(context_key, document_epoch, deadline_ms, full),
        )
    }

    pub(crate) fn classify_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        deadline_ms: u64,
    ) -> Result<
        Result<
            crate::classification::NonTypeClassificationRecord,
            crate::classification::ClassificationUnavailable,
        >,
        NavigationDriveError,
    > {
        self.drive(
            |error| error,
            |process| {
                process.classify_point(
                    context_key,
                    position,
                    document_epoch,
                    document_url,
                    deadline_ms,
                )
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn click_point_classified(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        document_epoch: u64,
        document_url: &str,
        expected: &crate::classification::NonTypeClassificationRecord,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.drive(ClickDriveError::Navigation, |process| {
            process.click_point_classified(
                context_key,
                position,
                document_epoch,
                document_url,
                expected,
                deadline_ms,
                input_dispatched,
            )
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn click_classified(
        &mut self,
        context_key: &str,
        identity: &BackendNodeIdentity,
        document_epoch: u64,
        current_origin: &str,
        expected: Option<&crate::classification::NonTypeClassificationRecord>,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickDriveError> {
        self.drive(ClickDriveError::Navigation, |process| {
            process.click_classified(
                context_key,
                identity,
                document_epoch,
                current_origin,
                expected,
                deadline_ms,
                input_dispatched,
            )
        })
    }

    /// Give the admission back while the caller holds this session's meta
    /// lock. The caller notifies the session's condition variable after
    /// dropping that lock.
    fn release_locked(&mut self, meta: &mut SessionMeta) {
        if self.finished {
            return;
        }
        self.finished = true;
        meta.pending_operations = meta.pending_operations.saturating_sub(1);
        if self.handoff_reservation {
            meta.handoff_opening = false;
        }
        if let Some(switch) = self
            .sessions
            .side()
            .routes
            .get_mut(&self.cell.route_key)
            .filter(|switch| switch.browser_session_id == self.cell.browser_session_id)
        {
            switch.in_flight = switch.in_flight.saturating_sub(1);
        }
    }

    fn release(&mut self) {
        if self.finished {
            return;
        }
        let cell = Arc::clone(&self.cell);
        {
            // Recovered rather than skipped: teardown waits for this count to
            // reach zero, so skipping the release on a poisoned lock would
            // stall every later teardown of this session forever.
            let mut meta = recovered(cell.meta());
            self.release_locked(&mut meta);
        }
        cell.notify();
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.release();
    }
}

/// Close an open handoff with `outcome`, leaving any other state in place.
fn close_open_handoff(
    handoff: &mut Option<HandoffState>,
    outcome: HandoffOutcome,
) -> Option<HandoffClose> {
    match handoff.take() {
        Some(HandoffState::Open(open)) => {
            let closed = ClosedHandoff {
                handoff: open,
                outcome,
            };
            let result = handoff_close(&closed, true);
            *handoff = Some(HandoffState::Closed(closed));
            Some(result)
        }
        other => {
            *handoff = other;
            None
        }
    }
}

impl BrowserSessions {
    fn registry(&self) -> LockAttempt<'_, Registry> {
        take_lock(&self.registry.0, lock_scope::Kind::Registry)
    }

    /// The route's active session, or `Err` when the registry is poisoned.
    fn active_cell(&self, route_key: &str) -> Result<Option<Arc<SessionCell>>, ()> {
        let registry = self.registry().map_err(|_| ())?;
        Ok(registry
            .routes
            .get(route_key)
            .and_then(|route| route.active.clone()))
    }

    fn active_cell_recovering(&self, route_key: &str) -> Option<Arc<SessionCell>> {
        recovered(self.registry())
            .routes
            .get(route_key)
            .and_then(|route| route.active.clone())
    }

    fn active_cells_recovering(&self) -> Vec<Arc<SessionCell>> {
        recovered(self.registry())
            .routes
            .values()
            .filter_map(|route| route.active.clone())
            .collect()
    }

    /// Count one admitted operation. Called with the session's meta lock held.
    fn admit(
        &self,
        cell: &Arc<SessionCell>,
        meta: &mut SessionMeta,
        handoff_reservation: bool,
    ) -> OperationGuard {
        meta.pending_operations = meta.pending_operations.saturating_add(1);
        if let Some(switch) = self
            .side()
            .routes
            .get_mut(&cell.route_key)
            .filter(|switch| switch.browser_session_id == cell.browser_session_id)
        {
            switch.in_flight = switch.in_flight.saturating_add(1);
        }
        OperationGuard {
            sessions: self.clone(),
            cell: Arc::clone(cell),
            handoff_reservation,
            finished: false,
        }
    }

    pub fn acquire_launch_slot(&self, route_key: &str) -> LaunchSlot {
        let mut registry = match self.registry() {
            Ok(registry) => registry,
            Err(_) => {
                return LaunchSlot::Refused(internal_failure_reply(BROWSER_SESSION_LOCK_STAGE))
            }
        };
        let route = registry.routes.entry(route_key.to_string()).or_default();
        if let Some(active) = route.active.as_ref() {
            return LaunchSlot::Occupied {
                browser_session_id: active.browser_session_id.clone(),
            };
        }
        route.next_session = route.next_session.saturating_add(1);
        let browser_session_id = format!(
            "browser-session-{}-{}",
            stable_route_id(route_key),
            route.next_session
        );
        route.active = Some(Arc::new(SessionCell::launching(
            route_key,
            browser_session_id.clone(),
        )));
        LaunchSlot::Acquired { browser_session_id }
    }

    /// Give back a launch slot whose launch failed before readiness.
    pub fn abandon_launch_slot(&self, route_key: &str) {
        let removed = {
            let mut registry = recovered(self.registry());
            let Some(route) = registry.routes.get_mut(route_key) else {
                return;
            };
            let Some(cell) = route.active.as_ref() else {
                return;
            };
            // Marked while the registry lock is still held, so an
            // establishment that already found this session sees it abandoned
            // and hands its browser back instead of installing it.
            {
                let mut meta = recovered(cell.meta());
                if meta.lifecycle != Lifecycle::Launching {
                    return;
                }
                meta.lifecycle = Lifecycle::Abandoned;
            }
            route.active.take()
        };
        if let Some(cell) = removed {
            cell.notify();
        }
        self.registry.1.notify_all();
    }

    /// Install a launched browser in the route's launching session.
    ///
    /// Returns the session id, its lease, and whether the session went
    /// terminal while the browser was starting (a close won the race), in
    /// which case the terminalizer now tears it down. A browser the table will
    /// not take (the slot was abandoned or the table is poisoned) is dropped
    /// here, outside every lock; use [`Self::try_establish_ready`] to get it
    /// back instead.
    pub fn establish_ready<C: MonotonicClock>(
        &self,
        route_key: &str,
        disposition: ProfileDisposition,
        config: &BrowserConfig,
        clock: &C,
        process: Box<dyn OwnedBrowserProcess>,
        cleanup: Box<dyn SessionCleanup>,
    ) -> Option<(String, BrowserLease, bool)> {
        self.try_establish_ready(route_key, disposition, config, clock, process, cleanup)
            .ok()
    }

    /// [`Self::establish_ready`], handing a refused browser back.
    pub fn try_establish_ready<C: MonotonicClock>(
        &self,
        route_key: &str,
        disposition: ProfileDisposition,
        config: &BrowserConfig,
        clock: &C,
        process: Box<dyn OwnedBrowserProcess>,
        cleanup: Box<dyn SessionCleanup>,
    ) -> Result<(String, BrowserLease, bool), UnestablishedBrowser> {
        let Ok(Some(cell)) = self.active_cell(route_key) else {
            return Err(UnestablishedBrowser { process, cleanup });
        };
        let killer = process.shutdown_killer();
        let exit_probe = process.exit_probe();
        // LD first, then the meta lock: the permitted order. Nothing has run
        // on this driver slot yet, so a poisoned one holds nothing to protect.
        let mut driver = recovered(cell.driver());
        let Ok(mut meta) = cell.meta() else {
            return Err(UnestablishedBrowser { process, cleanup });
        };
        if meta.lifecycle != Lifecycle::Launching {
            drop(meta);
            drop(driver);
            return Err(UnestablishedBrowser { process, cleanup });
        }
        *driver = Some(process);
        if let Some(killer) = killer {
            let _ = cell.killer.set(killer);
        }
        if let Some(exit_probe) = exit_probe {
            let _ = cell.exit_probe.set(exit_probe);
        }
        meta.disposition = disposition;
        meta.lease = BrowserLease::established(config.browser_idle_timeout_ms, clock);
        meta.cleanup = Some(cleanup);
        meta.lifecycle = Lifecycle::Ready;
        let result = (
            cell.browser_session_id.clone(),
            meta.lease.clone(),
            meta.terminal.is_some(),
        );
        // Registered while the meta lock is held, the permitted order, so
        // shutdown never sees the session ready without its switch.
        self.side().routes.insert(
            route_key.to_string(),
            RouteKillSwitch {
                browser_session_id: result.0.clone(),
                in_flight: 0,
                kill_attempted: false,
                killed: false,
            },
        );
        cell.notify();
        drop(meta);
        drop(driver);
        Ok(result)
    }

    #[doc(hidden)]
    pub fn wait_until_terminal_for_test(&self, route_key: &str) {
        let Some(cell) = self.active_cell_recovering(route_key) else {
            return;
        };
        let mut meta = recovered(cell.meta());
        while meta.terminal.is_none() && !meta.lifecycle.is_settled() {
            meta = recovered(meta.wait(&cell.wake));
        }
    }

    /// Wait for another thread's teardown of this route to finish. This joins
    /// a teardown, so it recovers a poisoned lock like the teardown does. A
    /// session whose custody shutdown had to leave held never leaves the
    /// route, so that ends the wait too.
    pub fn wait_until_inactive(&self, route_key: &str) {
        let mut registry = recovered(self.registry());
        loop {
            let Some(cell) = registry
                .routes
                .get(route_key)
                .and_then(|route| route.active.as_ref())
            else {
                return;
            };
            if recovered(cell.meta()).lifecycle == Lifecycle::CustodyHeld {
                return;
            }
            registry = recovered(registry.wait(&self.registry.1));
        }
    }

    /// Poison the session registry's lock by panicking on a thread that holds
    /// it, so tests can drive every entry point over a poisoned lock.
    #[doc(hidden)]
    pub fn poison_for_test(&self) {
        let sessions = self.clone();
        let _ = std::thread::spawn(move || {
            let _guard = sessions.registry();
            panic!("poisoning the browser session registry lock for a test");
        })
        .join();
    }

    /// Poison one of the route's active session's own locks.
    #[doc(hidden)]
    pub fn poison_session_lock_for_test(&self, route_key: &str, lock: SessionLockForTest) {
        let Some(cell) = self.active_cell_recovering(route_key) else {
            return;
        };
        let _ = std::thread::spawn(move || match lock {
            SessionLockForTest::Meta => {
                let _guard = cell.meta();
                panic!("poisoning a browser session meta lock for a test");
            }
            SessionLockForTest::Driver => {
                let _guard = cell.driver();
                panic!("poisoning a browser session driver lock for a test");
            }
        })
        .join();
    }

    #[doc(hidden)]
    pub fn lease_deadline_for_test(&self, route_key: &str) -> Option<MonoInstant> {
        let retained = {
            let registry = self.registry().ok()?;
            let route = registry.routes.get(route_key)?;
            match route.active.clone() {
                Some(cell) => Err(cell),
                None => Ok(route.retained.last().map(|record| record.lease.deadline())),
            }
        };
        match retained {
            Ok(deadline) => deadline,
            Err(cell) => Some(cell.meta().ok()?.lease.deadline()),
        }
    }

    /// Bring the browser's page to the front for a person to log in.
    ///
    /// An admitted operation: it passes the call fence, counts as pending (so
    /// idle expiry and teardown wait for it), and reserves the handoff so a
    /// second `present` is refused while this one runs. Its CDP calls hold
    /// only this session's driver lock. It commits only if the session is
    /// still ready and admitting calls.
    pub fn present<C: MonotonicClock>(
        &self,
        route_key: &str,
        origin: &str,
        deadline_ms: u64,
        clock: &C,
    ) -> Result<PresentedHandoff, PresentRefusal> {
        let cell = self
            .active_cell(route_key)
            .ok()
            .flatten()
            .ok_or(PresentRefusal::NoSession)?;
        let mut admission = {
            let mut meta = cell.meta().map_err(|_| PresentRefusal::NoSession)?;
            if !meta.admits_calls() || clock.now() >= meta.lease.deadline() {
                return Err(PresentRefusal::NoSession);
            }
            if meta.handoff_opening || matches!(meta.handoff, Some(HandoffState::Open(_))) {
                return Err(PresentRefusal::HandoffOpen);
            }
            meta.handoff_opening = true;
            self.admit(&cell, &mut meta, true)
        };

        let opening_cookie_names = {
            let mut driver = cell.driver().map_err(|_| PresentRefusal::NoSession)?;
            let process = driver.as_mut().ok_or(PresentRefusal::NoSession)?;
            let current_url = process
                .main_frame_url(route_key, deadline_ms)
                .map_err(|error| PresentRefusal::PresentFailed {
                    error_text: navigation_drive_error_text(error),
                })?;
            let current_origin = main_frame_origin(&current_url);
            if current_origin != origin {
                return Err(PresentRefusal::OriginMismatch { current_origin });
            }
            process.present(route_key, deadline_ms).map_err(|error| {
                PresentRefusal::PresentFailed {
                    error_text: navigation_drive_error_text(error),
                }
            })?;
            process
                .cookie_names_for_origin(route_key, origin, deadline_ms)
                .map_err(|error| PresentRefusal::PresentFailed {
                    error_text: navigation_drive_error_text(error),
                })?
        };

        let mut meta = cell.meta().map_err(|_| PresentRefusal::NoSession)?;
        if !meta.admits_calls() {
            return Err(PresentRefusal::NoSession);
        }
        let opened_at = clock.now();
        let expires_at = opened_at.saturating_add(Duration::from_millis(HANDOFF_DURATION_MS));
        meta.next_handoff_generation = meta.next_handoff_generation.saturating_add(1);
        let generation = meta.next_handoff_generation;
        meta.lease.renew(clock);
        meta.handoff = Some(HandoffState::Open(Handoff {
            generation,
            origin: origin.to_string(),
            opened_at,
            expires_at,
            opening_cookie_names,
            saw_credential_field: false,
            cookie_names_added: 0,
        }));
        admission.release_locked(&mut meta);
        drop(meta);
        cell.notify();
        Ok(PresentedHandoff {
            generation,
            expires_in_ms: HANDOFF_DURATION_MS,
        })
    }

    pub fn resume<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
    ) -> Result<HandoffClose, ResumeRefusal> {
        let cell = self
            .active_cell(route_key)
            .ok()
            .flatten()
            .ok_or(ResumeRefusal::NoHandoff)?;
        let mut meta = cell.meta().map_err(|_| ResumeRefusal::NoHandoff)?;
        let handoff = meta.handoff.take().ok_or(ResumeRefusal::NoHandoff)?;
        let (closed, should_journal) = match handoff {
            HandoffState::Open(handoff) => (
                ClosedHandoff {
                    outcome: if clock.now() >= handoff.expires_at {
                        HandoffOutcome::Expired
                    } else {
                        HandoffOutcome::ClosedByCaller
                    },
                    handoff,
                },
                true,
            ),
            HandoffState::Closed(closed) => (closed, false),
        };
        Ok(handoff_close(&closed, should_journal))
    }

    pub fn human_in_control<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
    ) -> Option<HumanInControl> {
        let cell = self.active_cell(route_key).ok()??;
        let meta = cell.meta().ok()?;
        match meta.handoff.as_ref()? {
            HandoffState::Open(handoff) => Some(HumanInControl {
                origin: handoff.origin.clone(),
                expires_in_ms: remaining_ms(handoff.expires_at, clock.now()),
            }),
            HandoffState::Closed(closed) if closed.outcome == HandoffOutcome::Expired => {
                Some(HumanInControl {
                    origin: closed.handoff.origin.clone(),
                    expires_in_ms: 0,
                })
            }
            HandoffState::Closed(_) => None,
        }
    }

    /// Check an open handoff for a completed login.
    ///
    /// An admitted operation like `present`: its three CDP reads hold only
    /// this session's driver lock, and its result is committed only if the
    /// same handoff is still open and the session still admits calls.
    pub fn poll_handoff<C: MonotonicClock>(
        &self,
        route_key: &str,
        generation: u64,
        deadline_ms: u64,
        clock: &C,
    ) -> HandoffPollResult {
        let Ok(Some(cell)) = self.active_cell(route_key) else {
            return HandoffPollResult::Gone;
        };
        let (mut admission, origin, opening_cookie_names, saw_credential_field) = {
            let Ok(mut meta) = cell.meta() else {
                return HandoffPollResult::Gone;
            };
            let Some(HandoffState::Open(handoff)) = meta.handoff.as_ref() else {
                return HandoffPollResult::Gone;
            };
            if handoff.generation != generation {
                return HandoffPollResult::Gone;
            }
            if clock.now() >= handoff.expires_at {
                return close_open_handoff(&mut meta.handoff, HandoffOutcome::Expired)
                    .map_or(HandoffPollResult::Gone, HandoffPollResult::Closed);
            }
            let origin = handoff.origin.clone();
            let opening_cookie_names = handoff.opening_cookie_names.clone();
            let saw_credential_field = handoff.saw_credential_field;
            if !meta.admits_calls() {
                return HandoffPollResult::Gone;
            }
            meta.lease.renew(clock);
            let admission = self.admit(&cell, &mut meta, false);
            (
                admission,
                origin,
                opening_cookie_names,
                saw_credential_field,
            )
        };

        let (current_cookie_names, main_frame_url, has_credential_field_now) = {
            let Ok(mut driver) = cell.driver() else {
                return HandoffPollResult::Gone;
            };
            let Some(process) = driver.as_mut() else {
                return HandoffPollResult::Gone;
            };
            let Ok(current_cookie_names) =
                process.cookie_names_for_origin(route_key, &origin, deadline_ms)
            else {
                return HandoffPollResult::Open;
            };
            let Ok(main_frame_url) = process.main_frame_url(route_key, deadline_ms) else {
                return HandoffPollResult::Open;
            };
            let Ok(has_credential_field_now) = process.has_credential_field(route_key, deadline_ms)
            else {
                return HandoffPollResult::Open;
            };
            (
                current_cookie_names,
                main_frame_url,
                has_credential_field_now,
            )
        };

        let Ok(mut meta) = cell.meta() else {
            return HandoffPollResult::Gone;
        };
        let still_open = matches!(
            meta.handoff.as_ref(),
            Some(HandoffState::Open(handoff)) if handoff.generation == generation
        );
        if !still_open || !meta.admits_calls() {
            return HandoffPollResult::Gone;
        }
        let cookie_names_added = current_cookie_names
            .difference(&opening_cookie_names)
            .count();
        let observed = handoff_login_observed(
            saw_credential_field,
            has_credential_field_now,
            &opening_cookie_names,
            &current_cookie_names,
            &main_frame_url,
            &origin,
        );
        if let Some(HandoffState::Open(handoff)) = meta.handoff.as_mut() {
            handoff.saw_credential_field |= has_credential_field_now;
            handoff.cookie_names_added = cookie_names_added;
        }
        let result = if observed {
            close_open_handoff(&mut meta.handoff, HandoffOutcome::LoginObserved)
                .map_or(HandoffPollResult::Gone, HandoffPollResult::Closed)
        } else {
            HandoffPollResult::Open
        };
        admission.release_locked(&mut meta);
        drop(meta);
        cell.notify();
        result
    }

    /// Report the route's session. Never takes a driver lock, so it answers
    /// at once even while a call on this route or another is in progress.
    pub fn status<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
        wall_now: SystemTime,
    ) -> Value {
        let cell = {
            let registry = match self.registry() {
                Ok(registry) => registry,
                Err(_) => return internal_failure_reply(BROWSER_SESSION_LOCK_STAGE),
            };
            let Some(route) = registry.routes.get(route_key) else {
                return json!({"outcome": "no_session"});
            };
            match route.active.clone() {
                Some(cell) => cell,
                None => {
                    return route
                        .retained
                        .last()
                        .map(|record| record.status_json(clock, wall_now))
                        .unwrap_or_else(|| json!({"outcome": "no_session"}))
                }
            }
        };
        let status = match cell.meta() {
            Ok(meta) => meta
                .record(&cell.browser_session_id)
                .status_json(clock, wall_now),
            Err(_) => internal_failure_reply(BROWSER_SESSION_LOCK_STAGE),
        };
        status
    }

    pub fn accept_dispatch<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
    ) -> DispatchAdmission {
        let cell = match self.active_cell(route_key) {
            Ok(Some(cell)) => cell,
            Ok(None) => return DispatchAdmission::NoSession,
            Err(()) => return DispatchAdmission::StateUnavailable,
        };
        let Ok(mut meta) = cell.meta() else {
            return DispatchAdmission::StateUnavailable;
        };
        // A session with no browser in its driver slot answers "launch
        // pending", as it did when the process lived in the table: that is a
        // launch still starting, or a teardown that has already taken the
        // process out.
        if matches!(
            meta.lifecycle,
            Lifecycle::Launching | Lifecycle::TeardownOwned
        ) {
            return DispatchAdmission::LaunchPending;
        }
        if !meta.admits_calls() {
            return DispatchAdmission::NoSession;
        }
        if clock.now() >= meta.lease.deadline() {
            return DispatchAdmission::NoSession;
        }
        meta.lease.renew(clock);
        DispatchAdmission::Accepted(self.admit(&cell, &mut meta, false))
    }

    pub fn expire_idle<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
        config: &BrowserConfig,
    ) -> bool {
        match self.active_cell_recovering(route_key) {
            Some(cell) => self.expire_cell(&cell, clock, config),
            None => false,
        }
    }

    fn expire_cell<C: MonotonicClock>(
        &self,
        cell: &Arc<SessionCell>,
        clock: &C,
        config: &BrowserConfig,
    ) -> bool {
        {
            let mut meta = recovered(cell.meta());
            let now = clock.now();
            if meta.lifecycle != Lifecycle::Ready
                || meta.terminal.is_some()
                || meta.pending_operations != 0
                || meta.handoff.as_ref().is_some_and(
                    |handoff| matches!(handoff, HandoffState::Open(open) if now < open.expires_at),
                )
                || now < meta.lease.deadline()
            {
                return false;
            }
            meta.terminal = Some(BrowserSessionTerminalOutcome::IdleExpired);
        }
        cell.notify();
        self.finish_teardown(
            cell,
            BrowserSessionTerminalOutcome::IdleExpired,
            configured_grace(config),
        );
        true
    }

    /// Tear down every session whose browser has exited on its own.
    ///
    /// Asks each browser's exit probe, which never waits for a call in
    /// progress. A browser without a probe is checked through its driver slot
    /// only when that slot is free; a busy one is looked at on the next sweep,
    /// and its call in progress fails on its own if the browser is gone.
    pub fn observe_exits_all(&self, config: &BrowserConfig) {
        for cell in self.active_cells_recovering() {
            {
                let meta = recovered(cell.meta());
                if meta.terminal.is_some() || meta.lifecycle != Lifecycle::Ready {
                    continue;
                }
            }
            let exited = match cell.exit_probe.get() {
                Some(probe) => !probe.generation_matches(),
                None => cell.try_driver().is_some_and(|driver| {
                    driver
                        .as_ref()
                        .is_some_and(|process| !process.generation_matches())
                }),
            };
            if exited {
                // The collected session itself, not whatever the route holds
                // now, so a session that replaced it is not torn down.
                self.teardown_cell(&cell, BrowserSessionTerminalOutcome::BrowserCrashed, config);
            }
        }
    }

    pub fn expire_all<C: MonotonicClock>(&self, clock: &C, config: &BrowserConfig) {
        for cell in self.active_cells_recovering() {
            self.expire_cell(&cell, clock, config);
        }
    }

    /// Reserve an idle durable session for import before reading its URL or closing it.
    /// Admission and the terminal transition share the meta lock, so neither a
    /// driver operation nor a human handoff can begin between them.
    pub fn close_idle_for_import(
        &self,
        route_key: &str,
        config: &BrowserConfig,
    ) -> Result<(Value, Option<String>), IdleCloseRefusal> {
        let cell = self
            .active_cell(route_key)
            .map_err(|_| IdleCloseRefusal::Unavailable)?
            .ok_or(IdleCloseRefusal::Unavailable)?;
        {
            let mut meta = cell.meta().map_err(|_| IdleCloseRefusal::Unavailable)?;
            if meta.handoff_opening || matches!(meta.handoff, Some(HandoffState::Open(_))) {
                return Err(IdleCloseRefusal::Presented);
            }
            if meta.pending_operations != 0 {
                return Err(IdleCloseRefusal::Busy);
            }
            if !meta.admits_calls() || meta.disposition != ProfileDisposition::Durable {
                return Err(IdleCloseRefusal::Unavailable);
            }
            meta.terminal = Some(BrowserSessionTerminalOutcome::Closed);
        }
        cell.notify();
        let url = cell.driver().ok().and_then(|mut driver| {
            driver
                .as_mut()?
                .main_frame_url(route_key, config.navigation_settle_deadline_ms)
                .ok()
        });
        let result = self.close(route_key, &cell.browser_session_id, config);
        Ok((result, url))
    }

    pub fn close(
        &self,
        route_key: &str,
        browser_session_id: &str,
        config: &BrowserConfig,
    ) -> Value {
        let cell = {
            let registry = match self.registry() {
                Ok(registry) => registry,
                Err(_) => return internal_failure_reply(BROWSER_SESSION_LOCK_STAGE),
            };
            let Some(route) = registry.routes.get(route_key) else {
                return json!({"outcome": "browser_session_not_found"});
            };
            if let Some(retained) = route
                .retained
                .iter()
                .find(|record| record.browser_session_id == browser_session_id)
            {
                return retained.close_result();
            }
            match route.active.as_ref() {
                Some(cell) if cell.browser_session_id == browser_session_id => Arc::clone(cell),
                _ => return json!({"outcome": "browser_session_not_found"}),
            }
        };
        {
            let mut meta = match cell.meta() {
                Ok(meta) => meta,
                Err(_) => return internal_failure_reply(BROWSER_SESSION_LOCK_STAGE),
            };
            if let Some(stage) = meta.cleanup_failure {
                return json!({
                    "outcome": "cleanup_failure",
                    "browser_session_id": browser_session_id,
                    "stage": stage.as_str(),
                });
            }
            match meta.lifecycle {
                Lifecycle::Retired => return meta.record(browser_session_id).close_result(),
                Lifecycle::Abandoned => return json!({"outcome": "browser_session_not_found"}),
                _ => {}
            }
            meta.terminal
                .get_or_insert(BrowserSessionTerminalOutcome::Closed);
        }
        cell.notify();
        // Whoever takes the process out of the driver slot owns the teardown;
        // a close that finds it gone joins that teardown instead.
        self.finish_teardown(
            &cell,
            BrowserSessionTerminalOutcome::Closed,
            configured_grace(config),
        );
        // The result is read from this session itself, so a newer session
        // launched on the route meanwhile cannot answer for it.
        let meta = match cell.meta() {
            Ok(meta) => meta,
            Err(_) => return internal_failure_reply(BROWSER_SESSION_LOCK_STAGE),
        };
        if meta.lifecycle == Lifecycle::Abandoned {
            return json!({"outcome": "browser_session_not_found"});
        }
        meta.record(browser_session_id).close_result()
    }

    pub fn teardown_route(
        &self,
        route_key: &str,
        reason: BrowserSessionTerminalOutcome,
        config: &BrowserConfig,
    ) {
        if let Some(cell) = self.active_cell_recovering(route_key) {
            self.teardown_cell(&cell, reason, config);
        }
    }

    fn teardown_cell(
        &self,
        cell: &Arc<SessionCell>,
        reason: BrowserSessionTerminalOutcome,
        config: &BrowserConfig,
    ) {
        {
            let mut meta = recovered(cell.meta());
            if meta.lifecycle.is_settled() {
                return;
            }
            meta.terminal.get_or_insert(reason);
        }
        cell.notify();
        self.finish_teardown(cell, reason, configured_grace(config));
    }

    /// Close every session because the module is shutting down, within
    /// [`ShutdownBudget::PRODUCTION`].
    ///
    /// Every way the module can end (a drain notice, the daemon connection
    /// ending, SIGTERM) comes here, and they share one deadline fixed by the
    /// first of them, so a later caller joins the teardown already running
    /// rather than granting itself a fresh budget.
    pub fn teardown_all(&self, config: &BrowserConfig) {
        self.teardown_all_within(config, ShutdownBudget::PRODUCTION);
    }

    /// [`Self::teardown_all`] under an explicit budget, so tests can observe
    /// the bound without sleeping for the production one.
    #[doc(hidden)]
    pub fn teardown_all_within(&self, config: &BrowserConfig, budget: ShutdownBudget) {
        let plan = *self
            .side()
            .plan
            .get_or_insert_with(|| ShutdownPlan::starting_now(budget));
        // Marking every session terminal in one pass stops any further call
        // from being admitted on any of them. Only the brief registry and meta
        // locks are taken, so nothing here waits on a call in progress.
        let cells = self.active_cells_recovering();
        for cell in &cells {
            {
                let mut meta = recovered(cell.meta());
                if !meta.lifecycle.is_settled() {
                    meta.terminal
                        .get_or_insert(BrowserSessionTerminalOutcome::ModuleShutdown);
                }
            }
            cell.notify();
        }
        let grace = configured_grace(config);
        // One thread per session, so the time taken is the slowest session's,
        // not the sum over sessions.
        std::thread::scope(|scope| {
            for cell in cells {
                scope.spawn(move || self.shutdown_cell(&cell, grace, &plan));
            }
        });
    }

    /// Tear one session down inside the shutdown plan.
    ///
    /// Every wait on this path ends by the plan: operations in progress are
    /// waited for until `in_flight_until`; the driver lock is sought until
    /// `graceful_until`; the graceful close gets whatever is left before
    /// `graceful_until`; and the kill, reap and after-reap cleanup run in the
    /// reserve that follows, ending at `deadline`. A browser that cannot be
    /// reached or finished in that time keeps its profile custody held (see
    /// [`Lifecycle::CustodyHeld`]).
    fn shutdown_cell(&self, cell: &Arc<SessionCell>, grace: Duration, plan: &ShutdownPlan) {
        let in_flight_at_cap = {
            let mut meta = recovered(cell.meta());
            loop {
                if meta.lifecycle.is_settled() {
                    return;
                }
                let now = Instant::now();
                if meta.lifecycle == Lifecycle::Launching {
                    // The launch is not ours to finish; once it delivers its
                    // browser, the session (already terminal) is torn down
                    // here like any other.
                    if now >= plan.deadline {
                        return;
                    }
                    meta = recovered(meta.wait_timeout(&cell.wake, plan.deadline - now));
                    continue;
                }
                if meta.pending_operations == 0 {
                    break false;
                }
                if now >= plan.in_flight_until {
                    break true;
                }
                meta = recovered(meta.wait_timeout(&cell.wake, plan.in_flight_until - now));
            }
        };
        if in_flight_at_cap {
            // Operations were still in progress when the in-flight wait ran
            // out. Killing the browser fails the call holding the driver lock,
            // which gives the lock back.
            self.kill_cell(cell, true);
        }

        let driver = loop {
            if let Some(driver) = cell.try_driver() {
                break Some(driver);
            }
            if Instant::now() >= plan.graceful_until {
                break None;
            }
            std::thread::sleep(SHUTDOWN_POLL);
        };
        let Some(mut driver) = driver else {
            // A call is still holding the driver lock: the killer was refused
            // or there is none. The browser may still be alive with its
            // profile open, so custody must not be released under it.
            self.hold_custody(cell, Lifecycle::Ready);
            return;
        };
        let Some(process) = driver.take() else {
            drop(driver);
            self.join_other_teardown(cell, plan);
            return;
        };
        let (terminal_outcome, cleanup) = {
            let mut meta = recovered(cell.meta());
            meta.lifecycle = Lifecycle::TeardownOwned;
            let terminal_outcome = *meta
                .terminal
                .get_or_insert(BrowserSessionTerminalOutcome::ModuleShutdown);
            (terminal_outcome, meta.cleanup.take())
        };
        drop(driver);
        let already_killed = self.cell_killed(cell);
        let grace = grace.min(
            plan.graceful_until
                .saturating_duration_since(Instant::now()),
        );
        self.teardown_within(
            cell,
            OwnedTeardown {
                process,
                cleanup,
                terminal_outcome,
                already_killed,
                grace,
            },
            plan,
        );
    }

    /// Another terminalizer owns this session's process. Join it without
    /// touching its state, and once only the reserve is left, kill its
    /// browser so that its graceful wait ends early.
    fn join_other_teardown(&self, cell: &Arc<SessionCell>, plan: &ShutdownPlan) {
        let mut killed = false;
        let mut meta = recovered(cell.meta());
        loop {
            if meta.lifecycle.is_settled() {
                return;
            }
            let now = Instant::now();
            if now >= plan.deadline {
                return;
            }
            if !killed && now >= plan.graceful_until {
                drop(meta);
                self.kill_cell(cell, false);
                killed = true;
                meta = recovered(cell.meta());
                continue;
            }
            let until = if killed {
                plan.deadline
            } else {
                plan.graceful_until
            };
            meta = recovered(meta.wait_timeout(&cell.wake, until - now));
        }
    }

    /// Run an owned teardown on its own thread and wait for it until the
    /// plan's deadline.
    ///
    /// None of the process and cleanup steps takes a deadline of its own:
    /// the reap waits for the process to be collected, and the after-reap
    /// cleanup does filesystem and journal work. If they overrun, custody is
    /// left held rather than letting the shutdown wait past its budget; the
    /// thread carries on, and if it does finish, it retires the session then.
    fn teardown_within(&self, cell: &Arc<SessionCell>, owned: OwnedTeardown, plan: &ShutdownPlan) {
        let slot = Arc::new(Mutex::new(Some(owned)));
        let run = {
            let sessions = self.clone();
            let cell = Arc::clone(cell);
            let slot = Arc::clone(&slot);
            move || {
                if let Some(owned) = recover_poisoned(slot.lock()).take() {
                    sessions.run_owned_teardown(&cell, owned);
                }
            }
        };
        if std::thread::Builder::new()
            .name("browser-shutdown-teardown".to_string())
            .spawn(run)
            .is_err()
        {
            // No thread could be started. The teardown then runs here,
            // without the deadline, rather than not at all.
            if let Some(owned) = recover_poisoned(slot.lock()).take() {
                self.run_owned_teardown(cell, owned);
            }
            return;
        }
        {
            let mut meta = recovered(cell.meta());
            loop {
                if meta.lifecycle.is_settled() {
                    return;
                }
                let now = Instant::now();
                if now >= plan.deadline {
                    break;
                }
                meta = recovered(meta.wait_timeout(&cell.wake, plan.deadline - now));
            }
        }
        self.hold_custody(cell, Lifecycle::TeardownOwned);
    }

    fn run_owned_teardown(&self, cell: &Arc<SessionCell>, owned: OwnedTeardown) {
        let OwnedTeardown {
            mut process,
            mut cleanup,
            terminal_outcome,
            already_killed,
            grace,
        } = owned;
        let outcome = if already_killed {
            // Already dead by the shutdown killer: a graceful close would only
            // write to a closed pipe, so all that is left is the reap.
            process.wait_until_reaped().map_err(|_| CleanupStage::Reap)
        } else {
            teardown_process_with_grace(process.as_mut(), grace)
        }
        .and_then(|()| {
            let cleanup = cleanup.as_mut().ok_or(CleanupStage::CustodyRelease)?;
            cleanup.set_terminal_outcome(terminal_outcome);
            cleanup.after_reap()
        });
        self.retire(cell, process, cleanup, outcome);
    }

    /// Leave the session active with its custody held, if it is still in the
    /// `expected` state. The route stays occupied, so no second browser opens
    /// the profile, and the call fence refuses every new call.
    fn hold_custody(&self, cell: &Arc<SessionCell>, expected: Lifecycle) {
        {
            let mut meta = recovered(cell.meta());
            if meta.lifecycle != expected {
                return;
            }
            meta.lifecycle = Lifecycle::CustodyHeld;
            meta.cleanup_failure = Some(CleanupStage::CustodyHeld);
        }
        cell.notify();
        self.registry.1.notify_all();
    }

    /// L3, always taken last.
    fn side(&self) -> MutexGuard<'_, ShutdownSide> {
        recover_poisoned(self.shutdown.lock())
    }

    /// Fire this session's shutdown killer, at most once per session, with no
    /// lock held. With `only_in_flight`, a session with no operation in flight
    /// is left alone: its browser still gets a graceful close.
    fn kill_cell(&self, cell: &SessionCell, only_in_flight: bool) {
        let fire = {
            let mut side = self.side();
            match side
                .routes
                .get_mut(&cell.route_key)
                .filter(|switch| switch.browser_session_id == cell.browser_session_id)
            {
                Some(switch)
                    if !switch.kill_attempted && (!only_in_flight || switch.in_flight != 0) =>
                {
                    switch.kill_attempted = true;
                    true
                }
                _ => false,
            }
        };
        if !fire {
            return;
        }
        let Some(killer) = cell.killer.get() else {
            return;
        };
        if killer.kill_exact_generation() == KillOutcome::Dead {
            if let Some(switch) = self
                .side()
                .routes
                .get_mut(&cell.route_key)
                .filter(|switch| switch.browser_session_id == cell.browser_session_id)
            {
                switch.killed = true;
            }
        }
    }

    fn cell_killed(&self, cell: &SessionCell) -> bool {
        self.side()
            .routes
            .get(&cell.route_key)
            .is_some_and(|switch| {
                switch.browser_session_id == cell.browser_session_id && switch.killed
            })
    }

    /// Record a finished teardown: the session moves from active to retained
    /// with its outcome, and its shutdown switch is dropped. Only the thread
    /// that took the process out of the driver slot calls this.
    fn retire(
        &self,
        cell: &Arc<SessionCell>,
        process: Box<dyn OwnedBrowserProcess>,
        cleanup: Option<Box<dyn SessionCleanup>>,
        outcome: Result<SessionCleanupOutcome, CleanupStage>,
    ) {
        // The retained record is built before the registry lock is taken.
        let mut record = recovered(cell.meta()).record(&cell.browser_session_id);
        match outcome {
            Ok(cleanup_outcome) => {
                // A shutdown that gave up waiting marked custody held; this
                // late finish did release it, so that mark no longer applies.
                record.cleanup_failure = None;
                record.cleanup_outcome = Some(cleanup_outcome);
            }
            Err(stage) => {
                record.cleanup_failure = Some(stage);
                record.terminal = Some(BrowserSessionTerminalOutcome::CleanupFailure);
            }
        }
        let removed = {
            let mut registry = recovered(self.registry());
            let removed = match registry.routes.get_mut(&cell.route_key) {
                Some(route)
                    if route
                        .active
                        .as_ref()
                        .is_some_and(|active| Arc::ptr_eq(active, cell)) =>
                {
                    route.retained.push(record.clone());
                    route.active.take()
                }
                _ => None,
            };
            {
                let mut meta = recovered(cell.meta());
                meta.lifecycle = Lifecycle::Retired;
                meta.terminal = record.terminal;
                meta.cleanup_failure = record.cleanup_failure;
                meta.cleanup_outcome = record.cleanup_outcome;
                let mut side = self.side();
                if side
                    .routes
                    .get(&cell.route_key)
                    .is_some_and(|switch| switch.browser_session_id == cell.browser_session_id)
                {
                    side.routes.remove(&cell.route_key);
                }
            }
            removed
        };
        cell.notify();
        self.registry.1.notify_all();
        // Dropped only now, with every lock released: a process handle that
        // was never reaped kills and waits for its child when dropped.
        drop(removed);
        drop(cleanup);
        drop(process);
    }

    /// Finish a teardown whose terminal outcome is already set.
    ///
    /// Waits for operations in progress to end and for the browser to be
    /// installed, then takes the process out of the driver slot. Whoever gets
    /// it owns the reap, the after-reap cleanup and the retirement; anyone
    /// who finds the slot empty joins that owner by waiting for the session
    /// to settle, and writes nothing.
    fn finish_teardown(
        &self,
        cell: &Arc<SessionCell>,
        reason: BrowserSessionTerminalOutcome,
        grace: Duration,
    ) {
        let terminal_outcome = {
            let mut meta = recovered(cell.meta());
            loop {
                if meta.lifecycle.is_settled() {
                    return;
                }
                if meta.lifecycle == Lifecycle::TeardownOwned {
                    break None;
                }
                if meta.lifecycle == Lifecycle::Ready && meta.pending_operations == 0 {
                    break Some(*meta.terminal.get_or_insert(reason));
                }
                meta = recovered(meta.wait(&cell.wake));
            }
        };
        let Some(terminal_outcome) = terminal_outcome else {
            cell.wait_settled();
            return;
        };
        // The meta lock is released above before the driver lock is taken.
        // No operation is admitted and the fence refuses new ones, so the
        // driver lock is free unless another terminalizer is taking it too.
        let owned = {
            let mut driver = recovered(cell.driver());
            driver.take().map(|process| {
                let mut meta = recovered(cell.meta());
                meta.lifecycle = Lifecycle::TeardownOwned;
                (process, meta.cleanup.take())
            })
        };
        let Some((mut process, mut cleanup)) = owned else {
            cell.wait_settled();
            return;
        };
        let outcome = teardown_process_with_grace(process.as_mut(), grace).and_then(|()| {
            let cleanup = cleanup.as_mut().ok_or(CleanupStage::CustodyRelease)?;
            cleanup.set_terminal_outcome(terminal_outcome);
            cleanup.after_reap()
        });
        self.retire(cell, process, cleanup, outcome);
    }
}

/// What the shutdown teardown thread takes over from `shutdown_cell`.
struct OwnedTeardown {
    process: Box<dyn OwnedBrowserProcess>,
    cleanup: Option<Box<dyn SessionCleanup>>,
    terminal_outcome: BrowserSessionTerminalOutcome,
    already_killed: bool,
    grace: Duration,
}

fn configured_grace(config: &BrowserConfig) -> Duration {
    Duration::from_millis(config.termination_grace_period_ms)
}

/// Login is observed only after a credential field has appeared and then gone,
/// while the cookie set grows and the page remains on the handoff origin.
///
/// A passkey-only or OAuth-only flow never shows a credential field, so it cannot
/// close by observation. The caller must use `browser.resume`, or let the handoff
/// expire; either path reports which outcome ended the handoff.
pub fn handoff_login_observed(
    saw_credential_field: bool,
    has_credential_field_now: bool,
    opening_cookie_names: &BTreeSet<String>,
    current_cookie_names: &BTreeSet<String>,
    main_frame_url: &str,
    handoff_origin: &str,
) -> bool {
    saw_credential_field
        && !has_credential_field_now
        && current_cookie_names
            .difference(opening_cookie_names)
            .next()
            .is_some()
        && main_frame_origin(main_frame_url) == handoff_origin
}

fn handoff_close(closed: &ClosedHandoff, should_journal: bool) -> HandoffClose {
    HandoffClose {
        origin: closed.handoff.origin.clone(),
        outcome: closed.outcome,
        cookie_names_added: closed.handoff.cookie_names_added,
        should_journal,
    }
}

fn remaining_ms(expires_at: MonoInstant, now: MonoInstant) -> u64 {
    expires_at.as_nanos().saturating_sub(now.as_nanos()) / 1_000_000
}

fn main_frame_origin(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return "null".to_string();
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    crate::classification::canonical_origin(&format!("{scheme}://{authority}"))
        .unwrap_or_else(|| "null".to_string())
}

fn navigation_drive_error_text(error: NavigationDriveError) -> String {
    match error {
        NavigationDriveError::CommandFailed { error_text }
        | NavigationDriveError::NavigationFailed { error_text } => error_text,
        NavigationDriveError::Unavailable => "browser driver unavailable".to_string(),
        NavigationDriveError::StateUnavailable => "browser session state unavailable".to_string(),
        NavigationDriveError::ConnectorFailure => "browser connector failure".to_string(),
        NavigationDriveError::CdpFailure => "browser CDP failure".to_string(),
    }
}

fn teardown_process_with_grace(
    process: &mut dyn OwnedBrowserProcess,
    grace_period: Duration,
) -> Result<(), CleanupStage> {
    if !process.generation_matches() {
        return process.wait_until_reaped().map_err(|_| CleanupStage::Reap);
    }
    process
        .request_graceful_termination()
        .map_err(|_| CleanupStage::Reap)?;
    let exited = process
        .wait_for_exit(grace_period)
        .map_err(|_| CleanupStage::Reap)?;
    if !exited {
        // The second generation check is the fence against signaling a recycled
        // PID after the graceful-wait interval gave another process time to appear.
        if process.generation_matches() {
            process.force_terminate().map_err(|_| CleanupStage::Reap)?;
        }
    }
    process.wait_until_reaped().map_err(|_| CleanupStage::Reap)
}

fn stable_route_id(route_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(route_key.as_bytes());
    digest[..8]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_empty_object(arguments: &Value) -> Option<Value> {
    let object = match arguments.as_object() {
        Some(object) => object,
        None => return Some(crate::capability::invalid_request("$", "wrong_type")),
    };
    object
        .keys()
        .min()
        .map(|field| crate::capability::invalid_request(field, "unknown_field"))
}

pub fn validate_close(arguments: &Value) -> Result<&str, Value> {
    let object = arguments
        .as_object()
        .ok_or_else(|| crate::capability::invalid_request("$", "wrong_type"))?;
    if let Some(field) = object
        .keys()
        .filter(|field| field.as_str() != "browser_session_id")
        .min()
    {
        return Err(crate::capability::invalid_request(field, "unknown_field"));
    }
    let value = object
        .get("browser_session_id")
        .ok_or_else(|| crate::capability::invalid_request("browser_session_id", "missing_field"))?;
    let value = value
        .as_str()
        .ok_or_else(|| crate::capability::invalid_request("browser_session_id", "wrong_type"))?;
    if value.is_empty() {
        return Err(crate::capability::invalid_request(
            "browser_session_id",
            "empty_value",
        ));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cerebellum_core::clock::FakeClock;

    fn config() -> BrowserConfig {
        BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10,
            termination_grace_period_ms: 10,
            browser_idle_timeout_ms: 100,
            browser_exit_observation_deadline_ms: 10,
            navigation_settle_deadline_ms: 10,
        }
    }

    struct RecordingProcess {
        events: Arc<Mutex<Vec<&'static str>>>,
        checks: usize,
        first_generation_match: bool,
        second_generation_match: bool,
    }

    impl OwnedBrowserProcess for RecordingProcess {
        fn generation_matches(&self) -> bool {
            if self.checks == 0 {
                self.first_generation_match
            } else {
                self.second_generation_match
            }
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            self.checks += 1;
            self.events.lock().unwrap().push("graceful");
            Ok(())
        }

        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            self.events.lock().unwrap().push("grace_wait");
            Ok(false)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("force");
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("reap");
            Ok(())
        }
    }

    struct SleepingExitProcess;

    impl OwnedBrowserProcess for SleepingExitProcess {
        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure> {
            std::thread::sleep(grace_period);
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            unreachable!("graceful exit was already observed")
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
    }

    struct FailingReapProcess;

    impl OwnedBrowserProcess for FailingReapProcess {
        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            unreachable!("graceful exit was already observed")
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Err(ProcessControlFailure)
        }
    }

    struct FailingCleanup(CleanupStage);

    impl SessionCleanup for FailingCleanup {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            Err(self.0)
        }
    }

    #[derive(Default)]
    struct RecordingCleanup(Arc<Mutex<Vec<&'static str>>>);

    impl SessionCleanup for RecordingCleanup {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            self.0.lock().unwrap().push("cleanup");
            Ok(SessionCleanupOutcome::Complete)
        }
    }

    struct RecordingFinalizer(Arc<Mutex<Vec<BrowserSessionTerminalOutcome>>>);

    impl SessionCleanup for RecordingFinalizer {
        fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
            self.0.lock().unwrap().push(outcome);
        }

        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            Ok(SessionCleanupOutcome::Complete)
        }
    }

    type TestReadySession = (
        String,
        Arc<Mutex<Vec<&'static str>>>,
        Arc<Mutex<Vec<&'static str>>>,
    );

    fn ready_session_on(
        sessions: &BrowserSessions,
        route: &str,
        clock: &FakeClock,
        second_generation_match: bool,
    ) -> TestReadySession {
        let _ = sessions.acquire_launch_slot(route);
        let process_events = Arc::new(Mutex::new(Vec::new()));
        let cleanup_events = Arc::new(Mutex::new(Vec::new()));
        let (id, _, cancelled) = sessions
            .establish_ready(
                route,
                ProfileDisposition::Durable,
                &config(),
                clock,
                Box::new(RecordingProcess {
                    events: Arc::clone(&process_events),
                    checks: 0,
                    first_generation_match: true,
                    second_generation_match,
                }),
                Box::new(RecordingCleanup(Arc::clone(&cleanup_events))),
            )
            .unwrap();
        assert!(!cancelled);
        (id, process_events, cleanup_events)
    }

    fn ready_session(
        sessions: &BrowserSessions,
        clock: &FakeClock,
        second_generation_match: bool,
    ) -> TestReadySession {
        ready_session_on(sessions, "route", clock, second_generation_match)
    }

    fn finalizing_session_on(
        sessions: &BrowserSessions,
        route: &str,
        clock: &FakeClock,
        first_generation_match: bool,
    ) -> (String, Arc<Mutex<Vec<BrowserSessionTerminalOutcome>>>) {
        let _ = sessions.acquire_launch_slot(route);
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let (id, _, cancelled) = sessions
            .establish_ready(
                route,
                ProfileDisposition::Durable,
                &config(),
                clock,
                Box::new(RecordingProcess {
                    events: Arc::new(Mutex::new(Vec::new())),
                    checks: 0,
                    first_generation_match,
                    second_generation_match: first_generation_match,
                }),
                Box::new(RecordingFinalizer(Arc::clone(&outcomes))),
            )
            .unwrap();
        assert!(!cancelled);
        (id, outcomes)
    }

    #[test]
    fn explicit_close_finalizes_once_with_closed_outcome() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (id, outcomes) = finalizing_session_on(&sessions, "route", &clock, true);

        assert_eq!(
            sessions.close("route", &id, &config()),
            json!({"outcome": "closed", "browser_session_id": id})
        );
        assert_eq!(
            sessions.close("route", &id, &config()),
            json!({"outcome": "closed", "browser_session_id": id})
        );
        assert_eq!(
            outcomes.lock().unwrap().as_slice(),
            [BrowserSessionTerminalOutcome::Closed]
        );
    }

    #[test]
    fn every_automatic_terminal_path_finalizes_once_with_its_exact_outcome() {
        let mut clock = FakeClock::new();

        let sessions = BrowserSessions::default();
        let (_, idle_outcomes) = finalizing_session_on(&sessions, "idle", &clock, true);
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        assert!(sessions.expire_idle("idle", &clock, &config()));
        assert!(!sessions.expire_idle("idle", &clock, &config()));
        assert_eq!(
            idle_outcomes.lock().unwrap().as_slice(),
            [BrowserSessionTerminalOutcome::IdleExpired]
        );

        let sessions = BrowserSessions::default();
        let (_, crash_outcomes) = finalizing_session_on(&sessions, "crash", &clock, false);
        sessions.observe_exits_all(&config());
        sessions.observe_exits_all(&config());
        assert_eq!(
            crash_outcomes.lock().unwrap().as_slice(),
            [BrowserSessionTerminalOutcome::BrowserCrashed]
        );

        for (route, reason) in [
            ("connector", BrowserSessionTerminalOutcome::ConnectorFailure),
            ("cdp", BrowserSessionTerminalOutcome::CdpFailure),
            ("unbind", BrowserSessionTerminalOutcome::RouteUnbound),
        ] {
            let sessions = BrowserSessions::default();
            let (_, outcomes) = finalizing_session_on(&sessions, route, &clock, true);
            sessions.teardown_route(route, reason, &config());
            sessions.teardown_route(route, reason, &config());
            assert_eq!(outcomes.lock().unwrap().as_slice(), [reason]);
        }

        let sessions = BrowserSessions::default();
        let (_, shutdown_outcomes) = finalizing_session_on(&sessions, "shutdown", &clock, true);
        sessions.teardown_all(&config());
        sessions.teardown_all(&config());
        assert_eq!(
            shutdown_outcomes.lock().unwrap().as_slice(),
            [BrowserSessionTerminalOutcome::ModuleShutdown]
        );
    }

    #[test]
    fn failed_journal_finalization_is_cleanup_failure_never_closed() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let _ = sessions.acquire_launch_slot("journal-failure");
        let (id, _, _) = sessions
            .establish_ready(
                "journal-failure",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(RecordingProcess {
                    events: Arc::new(Mutex::new(Vec::new())),
                    checks: 0,
                    first_generation_match: true,
                    second_generation_match: true,
                }),
                Box::new(FailingCleanup(CleanupStage::RecordTerminalization)),
            )
            .unwrap();

        assert_eq!(
            sessions.close("journal-failure", &id, &config()),
            json!({
                "outcome": "cleanup_failure",
                "browser_session_id": id,
                "stage": "record_terminalization",
            })
        );
        assert_eq!(
            sessions.status("journal-failure", &clock, UNIX_EPOCH),
            json!({
                "outcome": "cleanup_failure",
                "browser_session_id": id,
                "profile_disposition": "durable",
                "stage": "record_terminalization",
            })
        );
    }

    #[test]
    fn reap_and_cleanup_failures_are_exact_cleanup_failures() {
        let clock = FakeClock::new();
        let sessions = BrowserSessions::default();
        let _ = sessions.acquire_launch_slot("reap");
        let cleanup_events = Arc::new(Mutex::new(Vec::new()));
        let (reap_id, _, _) = sessions
            .establish_ready(
                "reap",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(FailingReapProcess),
                Box::new(RecordingCleanup(Arc::clone(&cleanup_events))),
            )
            .unwrap();
        assert_eq!(
            sessions.close("reap", &reap_id, &config()),
            json!({
                "outcome": "cleanup_failure",
                "browser_session_id": reap_id,
                "stage": "reap",
            })
        );
        assert!(cleanup_events.lock().unwrap().is_empty());

        let sessions = BrowserSessions::default();
        let _ = sessions.acquire_launch_slot("cleanup");
        let (cleanup_id, _, _) = sessions
            .establish_ready(
                "cleanup",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(RecordingProcess {
                    events: Arc::new(Mutex::new(Vec::new())),
                    checks: 0,
                    first_generation_match: true,
                    second_generation_match: true,
                }),
                Box::new(FailingCleanup(CleanupStage::CustodyRelease)),
            )
            .unwrap();
        assert_eq!(
            sessions.close("cleanup", &cleanup_id, &config()),
            json!({
                "outcome": "cleanup_failure",
                "browser_session_id": cleanup_id,
                "stage": "custody_release",
            })
        );
    }

    #[test]
    fn teardown_reaps_before_profile_cleanup() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (id, process, cleanup) = ready_session(&sessions, &clock, true);
        assert_eq!(sessions.close("route", &id, &config())["outcome"], "closed");
        assert_eq!(
            process.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
        assert_eq!(cleanup.lock().unwrap().as_slice(), ["cleanup"]);
    }

    #[test]
    fn recycled_generation_is_never_force_signalled() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (id, process, _) = ready_session(&sessions, &clock, false);
        assert_eq!(sessions.close("route", &id, &config())["outcome"], "closed");
        assert_eq!(
            process.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "reap"]
        );
    }

    struct PausingClock {
        now: MonoInstant,
        paused: std::sync::atomic::AtomicBool,
        entered: std::sync::mpsc::SyncSender<()>,
        release: Mutex<std::sync::mpsc::Receiver<()>>,
    }

    impl MonotonicClock for PausingClock {
        fn now(&self) -> MonoInstant {
            if !self.paused.swap(true, std::sync::atomic::Ordering::SeqCst) {
                self.entered.send(()).unwrap();
                self.release.lock().unwrap().recv().unwrap();
            }
            self.now
        }
    }

    #[test]
    fn acceptance_and_expiry_race_has_exactly_one_winner() {
        let sessions = Arc::new(BrowserSessions::default());
        let ready_clock = FakeClock::new();
        let _ = ready_session(&sessions, &ready_clock, true);
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let accept_clock = PausingClock {
            now: MonoInstant::from_duration(Duration::from_millis(
                config().browser_idle_timeout_ms - 1,
            )),
            paused: std::sync::atomic::AtomicBool::new(false),
            entered: entered_tx,
            release: Mutex::new(release_rx),
        };
        let accept = {
            let sessions = Arc::clone(&sessions);
            std::thread::spawn(move || {
                matches!(
                    sessions.accept_dispatch("route", &accept_clock),
                    DispatchAdmission::Accepted(_)
                )
            })
        };
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("acceptance reached the shared transition while holding its lock");

        let mut expiry_clock = FakeClock::new();
        expiry_clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        let (expiry_tx, expiry_rx) = std::sync::mpsc::sync_channel(1);
        let expiry_sessions = Arc::clone(&sessions);
        std::thread::spawn(move || {
            expiry_tx
                .send(expiry_sessions.expire_idle("route", &expiry_clock, &config()))
                .unwrap();
        });
        assert_eq!(
            expiry_rx.recv_timeout(Duration::from_millis(50)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout),
            "expiry completed while acceptance still owned the transition"
        );
        release_tx.send(()).unwrap();
        let accepted = accept.join().unwrap();
        let expired = expiry_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_ne!(accepted, expired);
    }

    struct BlockingReapProcess {
        entered_reap: std::sync::mpsc::SyncSender<()>,
        release_reap: std::sync::mpsc::Receiver<()>,
    }

    impl OwnedBrowserProcess for BlockingReapProcess {
        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            unreachable!("graceful exit was already observed")
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            self.entered_reap
                .send(())
                .map_err(|_| ProcessControlFailure)?;
            self.release_reap.recv().map_err(|_| ProcessControlFailure)
        }
    }

    #[test]
    fn close_does_not_report_success_before_reap_completes() {
        let sessions = Arc::new(BrowserSessions::default());
        let clock = FakeClock::new();
        let _ = sessions.acquire_launch_slot("route");
        let (entered_tx, entered_rx) = std::sync::mpsc::sync_channel(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(1);
        let (id, _, cancelled) = sessions
            .establish_ready(
                "route",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(BlockingReapProcess {
                    entered_reap: entered_tx,
                    release_reap: release_rx,
                }),
                Box::new(RecordingCleanup::default()),
            )
            .unwrap();
        assert!(!cancelled);

        let close_sessions = Arc::clone(&sessions);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            result_tx
                .send(close_sessions.close("route", &id, &config()))
                .unwrap();
        });
        entered_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("teardown reached the reap barrier");
        let early_result = result_rx.recv_timeout(Duration::from_millis(50));
        release_tx.send(()).unwrap();
        assert!(
            matches!(
                early_result,
                Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            ),
            "close returned successfully while reap was blocked"
        );
        let result = result_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("close returns after reap is released");
        assert_eq!(result["outcome"], "closed");
    }

    #[test]
    fn concurrent_closes_join_one_teardown() {
        let sessions = Arc::new(BrowserSessions::default());
        let clock = FakeClock::new();
        let (id, events, _) = ready_session(&sessions, &clock, true);
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let mut closers = Vec::new();
        for _ in 0..2 {
            let sessions = Arc::clone(&sessions);
            let barrier = Arc::clone(&barrier);
            let id = id.clone();
            closers.push(std::thread::spawn(move || {
                barrier.wait();
                sessions.close("route", &id, &config())
            }));
        }
        barrier.wait();
        for closer in closers {
            assert_eq!(closer.join().unwrap()["outcome"], "closed");
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
    }

    #[test]
    fn close_winning_before_readiness_joins_one_teardown() {
        let sessions = BrowserSessions::default();
        let id = match sessions.acquire_launch_slot("route") {
            LaunchSlot::Acquired { browser_session_id } => browser_session_id,
            LaunchSlot::Occupied { .. } => panic!("first launch slot was occupied"),
            LaunchSlot::Refused(refusal) => panic!("first launch slot was refused: {refusal}"),
        };
        let close_sessions = sessions.clone();
        let close_id = id.clone();
        let close = std::thread::spawn(move || close_sessions.close("route", &close_id, &config()));
        sessions.wait_until_terminal_for_test("route");

        let events = Arc::new(Mutex::new(Vec::new()));
        let (_, _, cancelled) = sessions
            .establish_ready(
                "route",
                ProfileDisposition::Durable,
                &config(),
                &FakeClock::new(),
                Box::new(RecordingProcess {
                    events: Arc::clone(&events),
                    checks: 0,
                    first_generation_match: true,
                    second_generation_match: true,
                }),
                Box::new(RecordingCleanup::default()),
            )
            .unwrap();
        assert!(cancelled);
        assert_eq!(close.join().unwrap()["outcome"], "closed");
        assert_eq!(
            events.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
    }

    #[test]
    fn observed_process_exit_reaps_without_signalling_and_records_crash() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let _ = sessions.acquire_launch_slot("route");
        let events = Arc::new(Mutex::new(Vec::new()));
        let cleanup = Arc::new(Mutex::new(Vec::new()));
        sessions.establish_ready(
            "route",
            ProfileDisposition::Durable,
            &config(),
            &clock,
            Box::new(RecordingProcess {
                events: Arc::clone(&events),
                checks: 0,
                first_generation_match: false,
                second_generation_match: false,
            }),
            Box::new(RecordingCleanup(Arc::clone(&cleanup))),
        );
        sessions.observe_exits_all(&config());
        assert_eq!(events.lock().unwrap().as_slice(), ["reap"]);
        assert_eq!(cleanup.lock().unwrap().as_slice(), ["cleanup"]);
        assert_eq!(
            sessions.status("route", &clock, UNIX_EPOCH)["terminal_outcome"],
            "browser_crashed"
        );
    }

    #[test]
    fn idle_expiry_runs_the_common_ladder() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let (_, process, cleanup) = ready_session(&sessions, &clock, true);
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        assert!(sessions.expire_idle("route", &clock, &config()));
        assert_eq!(
            process.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
        assert_eq!(cleanup.lock().unwrap().as_slice(), ["cleanup"]);
        assert_eq!(
            sessions.status("route", &clock, UNIX_EPOCH)["terminal_outcome"],
            "idle_expired"
        );
    }

    #[test]
    fn teardown_all_finishes_n_sessions_in_about_one_grace_period() {
        const SESSION_COUNT: u64 = 6;
        const GRACE_PERIOD_MS: u64 = 100;

        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let mut shutdown_config = config();
        shutdown_config.termination_grace_period_ms = GRACE_PERIOD_MS;
        for session in 0..SESSION_COUNT {
            let route = format!("route-{session}");
            let _ = sessions.acquire_launch_slot(&route);
            let (_, _, cancelled) = sessions
                .establish_ready(
                    &route,
                    ProfileDisposition::Durable,
                    &shutdown_config,
                    &clock,
                    Box::new(SleepingExitProcess),
                    Box::new(RecordingCleanup::default()),
                )
                .expect("establish sleeping session");
            assert!(!cancelled);
        }

        let started = std::time::Instant::now();
        sessions.teardown_all(&shutdown_config);
        let elapsed = started.elapsed();
        eprintln!(
            "teardown_all elapsed {elapsed:?} for {SESSION_COUNT} sessions with {GRACE_PERIOD_MS}ms grace"
        );

        assert!(
            elapsed >= Duration::from_millis(GRACE_PERIOD_MS),
            "the process double did not exercise the configured grace period: {elapsed:?}"
        );
        assert!(
            elapsed < Duration::from_millis(GRACE_PERIOD_MS * 4),
            "teardown scaled toward N grace periods: {elapsed:?}"
        );
        for session in 0..SESSION_COUNT {
            assert_eq!(
                sessions.status(&format!("route-{session}"), &clock, UNIX_EPOCH)
                    ["terminal_outcome"],
                "module_shutdown"
            );
        }
    }

    #[test]
    fn route_unbind_and_module_shutdown_run_the_common_ladder() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (_, route_process, _) = ready_session_on(&sessions, "route-a", &clock, true);
        let (_, shutdown_process, _) = ready_session_on(&sessions, "route-b", &clock, true);
        sessions.teardown_route(
            "route-a",
            BrowserSessionTerminalOutcome::RouteUnbound,
            &config(),
        );
        assert_eq!(
            sessions.status("route-a", &clock, UNIX_EPOCH)["terminal_outcome"],
            "route_unbound"
        );
        sessions.teardown_all(&config());
        assert_eq!(
            sessions.status("route-b", &clock, UNIX_EPOCH)["terminal_outcome"],
            "module_shutdown"
        );
        for events in [route_process, shutdown_process] {
            assert_eq!(
                events.lock().unwrap().as_slice(),
                ["graceful", "grace_wait", "force", "reap"]
            );
        }
    }

    #[test]
    fn status_and_close_do_not_renew_the_deadline() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let (id, _, _) = ready_session(&sessions, &clock, true);
        let deadline = sessions.lease_deadline_for_test("route").unwrap();
        clock.advance(Duration::from_millis(1));
        let _ = sessions.status("route", &clock, UNIX_EPOCH);
        assert_eq!(sessions.lease_deadline_for_test("route"), Some(deadline));
        let _ = sessions.close("route", &id, &config());
        assert_eq!(sessions.lease_deadline_for_test("route"), Some(deadline));
    }

    #[test]
    fn accepted_pending_operation_prevents_expiry() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let _ = ready_session(&sessions, &clock, true);
        let guard = match sessions.accept_dispatch("route", &clock) {
            DispatchAdmission::Accepted(guard) => guard,
            _ => panic!("ready session must accept dispatch"),
        };
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        let expiry_sessions = sessions.clone();
        let expiry_clock = clock.clone();
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let (result_tx, result_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            result_tx
                .send(expiry_sessions.expire_idle("route", &expiry_clock, &config()))
                .unwrap();
        });
        started_rx.recv().unwrap();
        let early_result = result_rx.recv_timeout(Duration::from_millis(100));
        guard.finish();
        if early_result.is_err() {
            let _ = result_rx.recv_timeout(Duration::from_secs(1));
        }
        assert!(
            matches!(early_result, Ok(false)),
            "idle expiry did not refuse while an accepted operation was pending"
        );
    }

    #[test]
    fn wall_clock_adjustment_does_not_move_idle_enforcement() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let _ = ready_session(&sessions, &clock, true);
        let _ = sessions.status(
            "route",
            &clock,
            UNIX_EPOCH + Duration::from_secs(31_536_000),
        );
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms - 1));
        assert!(!sessions.expire_idle("route", &clock, &config()));
        clock.advance(Duration::from_millis(1));
        assert!(sessions.expire_idle("route", &clock, &config()));
    }

    #[test]
    fn lease_renders_utc_milliseconds_without_moving_enforcement_deadline() {
        let clock = FakeClock::new();
        let lease = BrowserLease::established(100, &clock);
        let deadline = lease.deadline();
        assert_eq!(
            lease.as_json(&clock, UNIX_EPOCH)["idle_expires_at"],
            "1970-01-01T00:00:00.100Z"
        );
        assert_eq!(
            lease.as_json(&clock, UNIX_EPOCH + Duration::from_secs(10))["idle_expires_at"],
            "1970-01-01T00:00:10.100Z"
        );
        assert_eq!(lease.deadline(), deadline);
    }

    #[test]
    fn import_idle_close_races_operation_admission() {
        for _ in 0..50 {
            let sessions = BrowserSessions::default();
            let clock = FakeClock::new();
            ready_session(&sessions, &clock, true);
            let start = std::sync::Barrier::new(2);
            let done = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let operation = scope.spawn(|| {
                    start.wait();
                    let admitted = sessions.accept_dispatch("route", &clock);
                    done.wait();
                    admitted
                });
                start.wait();
                let closed = sessions.close_idle_for_import("route", &config());
                done.wait();
                match (operation.join().unwrap(), closed) {
                    (DispatchAdmission::Accepted(guard), Err(IdleCloseRefusal::Busy)) => {
                        guard.finish();
                        assert_eq!(
                            sessions.status("route", &clock, UNIX_EPOCH)["outcome"],
                            "ready"
                        );
                    }
                    (
                        DispatchAdmission::NoSession | DispatchAdmission::LaunchPending,
                        Ok((reply, _)),
                    ) => {
                        assert_eq!(reply["outcome"], "closed");
                        assert_eq!(
                            sessions.status("route", &clock, UNIX_EPOCH)["outcome"],
                            "terminal"
                        );
                    }
                    _ => panic!("admission and idle close must have exactly one winner"),
                }
            });
        }
    }

    #[test]
    fn import_idle_close_races_present() {
        for _ in 0..50 {
            let sessions = BrowserSessions::default();
            let clock = FakeClock::new();
            handoff_session(&sessions, &clock);
            let start = std::sync::Barrier::new(2);
            std::thread::scope(|scope| {
                let presentation = scope.spawn(|| {
                    start.wait();
                    sessions.present("route", "https://login.example", 100, &clock)
                });
                start.wait();
                let closed = sessions.close_idle_for_import("route", &config());
                match (presentation.join().unwrap(), closed) {
                    (Ok(_), Err(IdleCloseRefusal::Presented)) => {
                        assert_eq!(
                            sessions.status("route", &clock, UNIX_EPOCH)["outcome"],
                            "ready"
                        );
                    }
                    (Err(PresentRefusal::NoSession), Ok((reply, _))) => {
                        assert_eq!(reply["outcome"], "closed");
                        assert_eq!(
                            sessions.status("route", &clock, UNIX_EPOCH)["outcome"],
                            "terminal"
                        );
                    }
                    _ => panic!("present and idle close must have exactly one winner"),
                }
            });
        }
    }

    #[test]
    fn close_validation_is_exact() {
        assert_eq!(
            validate_close(&json!({})).unwrap_err(),
            crate::capability::invalid_request("browser_session_id", "missing_field")
        );
        assert_eq!(
            validate_close(&json!({"z": 1, "a": 2})).unwrap_err(),
            crate::capability::invalid_request("a", "unknown_field")
        );
    }

    #[derive(Clone)]
    struct HandoffFacts {
        cookie_names: Arc<Mutex<BTreeSet<String>>>,
        main_frame_url: Arc<Mutex<String>>,
        credential_field: Arc<Mutex<bool>>,
        observations: Arc<Mutex<Vec<&'static str>>>,
    }

    struct HandoffProcess(HandoffFacts);

    impl OwnedBrowserProcess for HandoffProcess {
        fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
            self.0.observations.lock().unwrap().push("present");
            Ok(())
        }

        fn cookie_names_for_origin(
            &mut self,
            _: &str,
            _: &str,
            _: u64,
        ) -> Result<BTreeSet<String>, NavigationDriveError> {
            self.0.observations.lock().unwrap().push("cookies");
            Ok(self.0.cookie_names.lock().unwrap().clone())
        }

        fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
            self.0.observations.lock().unwrap().push("url");
            Ok(self.0.main_frame_url.lock().unwrap().clone())
        }

        fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
            self.0.observations.lock().unwrap().push("credential");
            Ok(*self.0.credential_field.lock().unwrap())
        }

        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            Ok(())
        }
    }

    fn handoff_session(sessions: &BrowserSessions, clock: &FakeClock) -> HandoffFacts {
        let facts = HandoffFacts {
            cookie_names: Arc::new(Mutex::new(BTreeSet::from(["before".to_string()]))),
            main_frame_url: Arc::new(Mutex::new("https://login.example/account".to_string())),
            credential_field: Arc::new(Mutex::new(true)),
            observations: Arc::new(Mutex::new(Vec::new())),
        };
        let _ = sessions.acquire_launch_slot("route");
        sessions
            .establish_ready(
                "route",
                ProfileDisposition::Durable,
                &config(),
                clock,
                Box::new(HandoffProcess(facts.clone())),
                Box::new(RecordingCleanup::default()),
            )
            .expect("test handoff session becomes ready");
        facts
    }

    #[test]
    fn login_is_observed_only_when_all_four_facts_hold() {
        let opening = BTreeSet::from(["before".to_string()]);
        for saw_field in [false, true] {
            for has_field_now in [false, true] {
                for grown in [false, true] {
                    for same_origin in [false, true] {
                        let mut current = opening.clone();
                        if grown {
                            current.insert("authenticated".to_string());
                        }
                        let url = if same_origin {
                            "https://login.example/done"
                        } else {
                            "https://sso.example/done"
                        };
                        assert_eq!(
                            handoff_login_observed(
                                saw_field,
                                has_field_now,
                                &opening,
                                &current,
                                url,
                                "https://login.example",
                            ),
                            saw_field && !has_field_now && grown && same_origin,
                            "saw_field={saw_field}, has_field_now={has_field_now}, grown={grown}, same_origin={same_origin}",
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_password_step_with_2fa_pending_is_not_done() {
        let opening = BTreeSet::from(["before".to_string()]);
        let current = BTreeSet::from(["before".to_string(), "authenticated".to_string()]);
        assert!(!handoff_login_observed(
            true,
            true,
            &opening,
            &current,
            "https://login.example/2fa",
            "https://login.example",
        ));
    }

    #[test]
    fn an_sso_redirect_is_not_done() {
        let opening = BTreeSet::from(["before".to_string()]);
        let current = BTreeSet::from(["before".to_string(), "authenticated".to_string()]);
        assert!(!handoff_login_observed(
            true,
            false,
            &opening,
            &current,
            "https://sso.example/login",
            "https://login.example",
        ));
    }

    #[test]
    fn a_username_first_step_with_a_banner_cookie_is_not_done() {
        let opening = BTreeSet::from(["before".to_string()]);
        let current = BTreeSet::from(["before".to_string(), "cookie_banner".to_string()]);
        assert!(!handoff_login_observed(
            false,
            false,
            &opening,
            &current,
            "https://login.example/username",
            "https://login.example",
        ));
    }

    #[test]
    fn poll_reads_only_the_three_facts_in_order_and_closes_on_login() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let facts = handoff_session(&sessions, &clock);
        let presented = sessions
            .present("route", "https://login.example", 10, &clock)
            .unwrap();
        assert_eq!(
            sessions.poll_handoff("route", presented.generation, 10, &clock),
            HandoffPollResult::Open,
            "the first credential-bearing tick records the transition prerequisite"
        );
        facts
            .cookie_names
            .lock()
            .unwrap()
            .insert("authenticated".to_string());
        *facts.credential_field.lock().unwrap() = false;
        facts.observations.lock().unwrap().clear();

        let polled = sessions.poll_handoff("route", presented.generation, 10, &clock);
        assert!(matches!(
            polled,
            HandoffPollResult::Closed(HandoffClose {
                outcome: HandoffOutcome::LoginObserved,
                cookie_names_added: 1,
                ..
            })
        ));
        assert_eq!(
            facts.observations.lock().unwrap().as_slice(),
            ["cookies", "url", "credential"]
        );
    }

    #[test]
    fn expiry_closes_and_the_next_tool_call_says_so() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let _ = handoff_session(&sessions, &clock);
        sessions
            .present("route", "https://login.example", 10, &clock)
            .unwrap();
        clock.advance(Duration::from_millis(HANDOFF_DURATION_MS));

        let blocked = sessions
            .human_in_control("route", &clock)
            .expect("expired handoff remains a typed tool refusal until resume");
        assert_eq!(blocked.expires_in_ms, 0);
        let resumed = sessions.resume("route", &clock).unwrap();
        assert_eq!(resumed.outcome, HandoffOutcome::Expired);
    }

    #[test]
    fn idle_sweep_skips_a_route_with_an_open_handoff() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let _ = handoff_session(&sessions, &clock);
        sessions
            .present("route", "https://login.example", 10, &clock)
            .unwrap();
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        assert!(!sessions.expire_idle("route", &clock, &config()));

        clock.advance(Duration::from_millis(
            HANDOFF_DURATION_MS - config().browser_idle_timeout_ms,
        ));
        assert!(sessions.expire_idle("route", &clock, &config()));
    }

    fn lock_refusal() -> Value {
        json!({"outcome": "internal_failure", "stage": "browser_session_lock"})
    }

    /// Run `body` on its own thread and fail rather than hang if it never
    /// finishes: over a poisoned lock the likely failure is a wait that never
    /// wakes, not a panic.
    fn finishes_within(body: impl FnOnce() + Send + 'static) {
        let (done, finished) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            body();
            let _ = done.send(());
        });
        assert!(
            finished.recv_timeout(Duration::from_secs(10)).is_ok(),
            "did not finish over the poisoned session lock"
        );
    }

    #[test]
    fn poisoned_lock_refuses_every_caller_facing_entry_point_with_the_named_stage() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (id, process, _) = ready_session(&sessions, &clock, true);
        sessions.poison_for_test();

        assert_eq!(sessions.status("route", &clock, UNIX_EPOCH), lock_refusal());
        assert_eq!(sessions.close("route", &id, &config()), lock_refusal());
        match sessions.acquire_launch_slot("another-route") {
            LaunchSlot::Refused(refusal) => assert_eq!(refusal, lock_refusal()),
            LaunchSlot::Acquired { .. } | LaunchSlot::Occupied { .. } => {
                panic!("a launch slot was granted over a poisoned session lock")
            }
        }
        assert!(matches!(
            sessions.accept_dispatch("route", &clock),
            DispatchAdmission::StateUnavailable
        ));
        // A refused close must not have started a teardown it then abandoned.
        assert!(process.lock().unwrap().is_empty());
    }

    #[test]
    fn poisoned_lock_idle_sweep_still_stops_the_expired_session() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let (_, process, cleanup) = ready_session(&sessions, &clock, true);
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        sessions.poison_for_test();

        let sweeping = sessions.clone();
        finishes_within(move || {
            sweeping.observe_exits_all(&config());
            sweeping.expire_all(&clock, &config());
        });
        assert_eq!(
            process.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
        assert_eq!(cleanup.lock().unwrap().as_slice(), ["cleanup"]);
    }

    #[test]
    fn poisoned_lock_shutdown_teardown_still_stops_every_session() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (_, first, first_cleanup) = ready_session_on(&sessions, "route-a", &clock, true);
        let (_, second, second_cleanup) = ready_session_on(&sessions, "route-b", &clock, true);
        sessions.poison_for_test();

        let tearing_down = sessions.clone();
        finishes_within(move || tearing_down.teardown_all(&config()));
        for (process, cleanup) in [(first, first_cleanup), (second, second_cleanup)] {
            assert_eq!(
                process.lock().unwrap().as_slice(),
                ["graceful", "grace_wait", "force", "reap"]
            );
            assert_eq!(cleanup.lock().unwrap().as_slice(), ["cleanup"]);
        }
    }

    #[test]
    fn operation_released_over_a_poisoned_lock_does_not_stall_teardown() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (_, process, _) = ready_session(&sessions, &clock, true);
        let DispatchAdmission::Accepted(operation) = sessions.accept_dispatch("route", &clock)
        else {
            panic!("a ready session refused dispatch");
        };
        sessions.poison_for_test();
        operation.finish();

        let tearing_down = sessions.clone();
        finishes_within(move || {
            tearing_down.teardown_route(
                "route",
                BrowserSessionTerminalOutcome::RouteUnbound,
                &config(),
            )
        });
        assert_eq!(
            process.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
    }

    /// The daemon's side of the shutdown contract. After a module's connection
    /// ends, the daemon waits up to 25 s (the module drain deadline: 30 s by
    /// default, capped at 25 s for modules), then sends SIGTERM, and SIGKILL
    /// half a second later. Teardown still running at SIGKILL never releases
    /// profile custody. If either side changes, this figure and the test below
    /// are where the two have to be reconciled.
    const DAEMON_SIGTERM_AFTER_EOF: Duration = Duration::from_secs(25);

    /// The worst-case shutdown teardown, from the module's own constants.
    ///
    /// Every wait on the shutdown path is cut off by one plan: operations in
    /// progress are waited for until `in_flight_until`, the graceful close
    /// ends by `graceful_until`, and the kill, reap and after-reap cleanup run
    /// in the reserve that follows, which ends at `deadline`. Sessions are torn
    /// down on one thread each (`teardown_all_within` spawns one per route), so
    /// the session count does not multiply this; that is measured by
    /// `teardown_all_finishes_n_sessions_in_about_one_grace_period`.
    #[test]
    fn the_shutdown_teardown_budget_fits_before_the_daemons_sigterm() {
        let budget = ShutdownBudget::PRODUCTION;
        assert_eq!(budget.total, SHUTDOWN_TEARDOWN_BUDGET);
        assert_eq!(budget.in_flight_wait_max, SHUTDOWN_IN_FLIGHT_WAIT_MAX);
        assert_eq!(budget.cleanup_reserve, SHUTDOWN_CLEANUP_RESERVE);

        let plan = ShutdownPlan::starting_now(budget);
        let start = plan.deadline - SHUTDOWN_TEARDOWN_BUDGET;
        let in_flight_wait = plan.in_flight_until - start;
        let graceful_close = plan.graceful_until - plan.in_flight_until;
        let reserve = plan.deadline - plan.graceful_until;
        assert_eq!(in_flight_wait, SHUTDOWN_IN_FLIGHT_WAIT_MAX);
        assert_eq!(reserve, SHUTDOWN_CLEANUP_RESERVE);
        assert!(
            graceful_close > Duration::ZERO,
            "the in-flight wait and the cleanup reserve leave no time for a graceful close"
        );

        let worst_case = in_flight_wait + graceful_close + reserve;
        assert_eq!(worst_case, SHUTDOWN_TEARDOWN_BUDGET);
        assert!(
            worst_case < DAEMON_SIGTERM_AFTER_EOF,
            "worst-case shutdown teardown {worst_case:?} does not finish before the daemon's \
             SIGTERM at {DAEMON_SIGTERM_AFTER_EOF:?}"
        );
    }

    #[derive(Default)]
    struct KillSwitch {
        killed: Mutex<bool>,
        wake: Condvar,
        fired: std::sync::atomic::AtomicUsize,
    }

    struct SwitchKiller(Arc<KillSwitch>);

    impl BrowserKiller for SwitchKiller {
        fn kill_exact_generation(&self) -> KillOutcome {
            self.0
                .fired
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            *self.0.killed.lock().unwrap() = true;
            self.0.wake.notify_all();
            KillOutcome::Dead
        }
    }

    /// A browser whose screenshot call never returns until its shutdown
    /// killer fires, standing in for a CDP call with a very long deadline.
    struct StuckCallProcess {
        switch: Arc<KillSwitch>,
        events: Arc<Mutex<Vec<&'static str>>>,
        entered: std::sync::mpsc::Sender<()>,
    }

    impl OwnedBrowserProcess for StuckCallProcess {
        fn screenshot(
            &mut self,
            _: &str,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
            let _ = self.entered.send(());
            let mut killed = self.switch.killed.lock().unwrap();
            while !*killed {
                killed = self.switch.wake.wait(killed).unwrap();
            }
            Err(NavigationDriveError::CdpFailure)
        }

        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("graceful");
            Ok(())
        }

        fn wait_for_exit(&mut self, _: Duration) -> Result<bool, ProcessControlFailure> {
            self.events.lock().unwrap().push("grace_wait");
            Ok(false)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("force");
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("reap");
            Ok(())
        }

        fn shutdown_killer(&self) -> Option<Arc<dyn BrowserKiller>> {
            Some(Arc::new(SwitchKiller(Arc::clone(&self.switch))))
        }
    }

    /// A browser that never exits on its own. It records the graceful wait it
    /// was given and sleeps for it, up to `sleep_cap`.
    struct NeverExitingProcess {
        events: Arc<Mutex<Vec<&'static str>>>,
        graces: Arc<Mutex<Vec<Duration>>>,
        sleep_cap: Duration,
    }

    impl OwnedBrowserProcess for NeverExitingProcess {
        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("graceful");
            Ok(())
        }

        fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure> {
            self.events.lock().unwrap().push("grace_wait");
            self.graces.lock().unwrap().push(grace_period);
            std::thread::sleep(grace_period.min(self.sleep_cap));
            Ok(false)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("force");
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            self.events.lock().unwrap().push("reap");
            Ok(())
        }
    }

    /// Records when after-reap cleanup (custody release) ran.
    struct TimedCleanup(Arc<Mutex<Vec<Instant>>>);

    impl SessionCleanup for TimedCleanup {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            self.0.lock().unwrap().push(Instant::now());
            Ok(SessionCleanupOutcome::Complete)
        }
    }

    /// One session is stuck inside a browser call, holding the registry-wide
    /// lock; another is idle but its browser never exits, under a configured
    /// grace of an hour. Shutdown must still release custody for both inside
    /// the budget: the stuck browser is killed out of band once the in-flight
    /// wait is over, and the idle one's graceful wait is cut to what the budget
    /// has left before the cleanup reserve.
    #[test]
    fn a_stuck_call_and_a_huge_grace_still_release_custody_within_the_budget() {
        let budget = ShutdownBudget {
            total: Duration::from_millis(900),
            in_flight_wait_max: Duration::from_millis(150),
            cleanup_reserve: Duration::from_millis(300),
        };
        let mut shutdown_config = config();
        shutdown_config.termination_grace_period_ms = 3_600_000;
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();

        let switch = Arc::new(KillSwitch::default());
        let stuck_events = Arc::new(Mutex::new(Vec::new()));
        let stuck_released = Arc::new(Mutex::new(Vec::new()));
        let (entered, call_entered) = std::sync::mpsc::channel();
        let _ = sessions.acquire_launch_slot("stuck");
        sessions
            .establish_ready(
                "stuck",
                ProfileDisposition::Durable,
                &shutdown_config,
                &clock,
                Box::new(StuckCallProcess {
                    switch: Arc::clone(&switch),
                    events: Arc::clone(&stuck_events),
                    entered,
                }),
                Box::new(TimedCleanup(Arc::clone(&stuck_released))),
            )
            .unwrap();

        let idle_events = Arc::new(Mutex::new(Vec::new()));
        let idle_graces = Arc::new(Mutex::new(Vec::new()));
        let idle_released = Arc::new(Mutex::new(Vec::new()));
        let _ = sessions.acquire_launch_slot("idle");
        sessions
            .establish_ready(
                "idle",
                ProfileDisposition::Durable,
                &shutdown_config,
                &clock,
                Box::new(NeverExitingProcess {
                    events: Arc::clone(&idle_events),
                    graces: Arc::clone(&idle_graces),
                    sleep_cap: Duration::from_secs(2),
                }),
                Box::new(TimedCleanup(Arc::clone(&idle_released))),
            )
            .unwrap();

        let DispatchAdmission::Accepted(mut operation) = sessions.accept_dispatch("stuck", &clock)
        else {
            panic!("a ready session refused dispatch");
        };
        let caller = std::thread::spawn(move || {
            let result = operation.screenshot("context", 0, 3_600_000, false);
            operation.finish();
            result.is_err()
        });
        call_entered
            .recv_timeout(Duration::from_secs(5))
            .expect("the stuck call is in progress and holds the registry lock");

        let started = Instant::now();
        let (done, finished) = std::sync::mpsc::channel();
        let tearing_down = sessions.clone();
        std::thread::spawn(move || {
            tearing_down.teardown_all_within(&shutdown_config, budget);
            let _ = done.send(Instant::now());
        });
        let ended = finished
            .recv_timeout(budget.total + Duration::from_secs(2))
            .expect("shutdown teardown must end");

        // Scheduling and the 5 ms polls are the only time not on the plan.
        let slack = Duration::from_millis(100);
        assert!(
            ended - started <= budget.total + slack,
            "shutdown teardown took {:?} against a budget of {:?}",
            ended - started,
            budget.total
        );
        assert!(
            caller.join().unwrap(),
            "the killed browser fails the stuck call"
        );
        assert_eq!(
            switch.fired.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the stuck browser's killer fires once"
        );
        assert_eq!(
            stuck_events.lock().unwrap().as_slice(),
            ["reap"],
            "a killed browser is reaped, not asked to close"
        );
        assert_eq!(
            idle_events.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
        let graces = idle_graces.lock().unwrap();
        assert_eq!(graces.len(), 1);
        assert!(
            graces[0] <= budget.total - budget.cleanup_reserve,
            "the graceful wait {:?} was not cut to the budget",
            graces[0]
        );
        for (route, released) in [("stuck", &stuck_released), ("idle", &idle_released)] {
            let released = released.lock().unwrap();
            assert_eq!(released.len(), 1, "{route} custody released once");
            assert!(
                released[0] - started <= budget.total + slack,
                "{route} custody released after {:?}",
                released[0] - started
            );
            assert_eq!(
                sessions.status(route, &clock, UNIX_EPOCH)["terminal_outcome"],
                "module_shutdown"
            );
        }
    }

    /// A browser call on one route must not stall another route.
    ///
    /// Route A enters a screenshot that blocks until A's kill switch fires,
    /// standing in for a navigate waiting out a slow page under an operator's
    /// long settle deadline. While A is blocked, route B asks for its status,
    /// is admitted for an operation, and makes a driver call. Each of those
    /// should finish promptly, well before A is released.
    ///
    /// A driver call holds only its own session's driver lock, so nothing B
    /// does waits for A. The test prints what B measured, so a regression
    /// shows the size of the stall.
    #[test]
    fn a_blocked_driver_call_on_one_route_does_not_stall_another_route() {
        const A_HOLD: Duration = Duration::from_millis(1_000);
        const PROMPT: Duration = Duration::from_millis(100);
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();

        let a_switch = Arc::new(KillSwitch::default());
        let (a_entered, a_call_entered) = std::sync::mpsc::channel();
        let _ = sessions.acquire_launch_slot("route-a");
        sessions
            .establish_ready(
                "route-a",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(StuckCallProcess {
                    switch: Arc::clone(&a_switch),
                    events: Arc::new(Mutex::new(Vec::new())),
                    entered: a_entered,
                }),
                Box::new(RecordingCleanup::default()),
            )
            .unwrap();

        // B's switch is fired up front, so its screenshot reaches the driver
        // and returns `CdpFailure` at once. That error, unlike `Unavailable`,
        // proves the call got past the session checks into B's own browser.
        let b_switch = Arc::new(KillSwitch::default());
        *b_switch.killed.lock().unwrap() = true;
        let (b_entered, _b_call_entered) = std::sync::mpsc::channel();
        let _ = sessions.acquire_launch_slot("route-b");
        sessions
            .establish_ready(
                "route-b",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(StuckCallProcess {
                    switch: Arc::clone(&b_switch),
                    events: Arc::new(Mutex::new(Vec::new())),
                    entered: b_entered,
                }),
                Box::new(RecordingCleanup::default()),
            )
            .unwrap();

        let DispatchAdmission::Accepted(mut a_operation) =
            sessions.accept_dispatch("route-a", &clock)
        else {
            panic!("route A's ready session refused dispatch");
        };
        let a_caller = std::thread::spawn(move || {
            let result = a_operation.screenshot("context", 0, 3_600_000, false);
            a_operation.finish();
            result
        });
        a_call_entered
            .recv_timeout(Duration::from_secs(5))
            .expect("route A's call is in progress");

        // B's status and B's operation run on separate threads, both started
        // while A is blocked, so each one's wait is measured on its own rather
        // than the operation's wait hiding behind the status's.
        let (b_done, b_finished) = std::sync::mpsc::channel();
        let status_sessions = sessions.clone();
        let status_clock = clock.clone();
        let status_done = b_done.clone();
        let b_status = std::thread::spawn(move || {
            let started = Instant::now();
            let status = status_sessions.status("route-b", &status_clock, UNIX_EPOCH);
            let finished_at = Instant::now();
            let _ = status_done.send(());
            (status, finished_at - started, finished_at)
        });
        let call_sessions = sessions.clone();
        let call_clock = clock.clone();
        let b_call = std::thread::spawn(move || {
            let started = Instant::now();
            let DispatchAdmission::Accepted(mut operation) =
                call_sessions.accept_dispatch("route-b", &call_clock)
            else {
                panic!("route B's ready session refused dispatch");
            };
            let call = operation.screenshot("context", 0, 10, false);
            let finished_at = Instant::now();
            operation.finish();
            let _ = b_done.send(());
            (call.err(), finished_at - started, finished_at)
        });

        // Give B up to `A_HOLD` to finish on its own, then release A whatever
        // happened, so the test always ends.
        let deadline = Instant::now() + A_HOLD;
        for _ in 0..2 {
            let _ = b_finished.recv_timeout(deadline.saturating_duration_since(Instant::now()));
        }
        let a_released_at = Instant::now();
        *a_switch.killed.lock().unwrap() = true;
        a_switch.wake.notify_all();
        let (status, status_took, status_finished_at) = b_status.join().unwrap();
        let (call_error, call_took, call_finished_at) = b_call.join().unwrap();
        assert_eq!(
            a_caller.join().unwrap().err(),
            Some(NavigationDriveError::CdpFailure),
            "route A's call ends only when its switch fires"
        );
        let relative_to_release = |finished_at: Instant| {
            if finished_at < a_released_at {
                "before"
            } else {
                "after"
            }
        };
        eprintln!(
            "route B while route A was blocked for {A_HOLD:?}: status took {status_took:?} \
             (finished {} A was released); admission plus driver call took {call_took:?} \
             (finished {} A was released)",
            relative_to_release(status_finished_at),
            relative_to_release(call_finished_at),
        );

        assert_eq!(status["outcome"], "ready");
        assert_eq!(
            call_error,
            Some(NavigationDriveError::CdpFailure),
            "route B's call reached route B's own browser"
        );
        assert!(
            status_took < PROMPT && status_finished_at < a_released_at,
            "route B's status waited {status_took:?} behind route A's call"
        );
        assert!(
            call_took < PROMPT && call_finished_at < a_released_at,
            "route B's admission and driver call waited {call_took:?} behind route A's call"
        );
    }

    /// The shutdown cap is for shutdown only: an idle expiry still gives the
    /// browser the whole configured grace, however long.
    #[test]
    fn idle_expiry_still_honours_the_configured_grace() {
        let mut idle_config = config();
        idle_config.termination_grace_period_ms = 3_600_000;
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let graces = Arc::new(Mutex::new(Vec::new()));
        let _ = sessions.acquire_launch_slot("route");
        sessions
            .establish_ready(
                "route",
                ProfileDisposition::Durable,
                &idle_config,
                &clock,
                Box::new(NeverExitingProcess {
                    events: Arc::new(Mutex::new(Vec::new())),
                    graces: Arc::clone(&graces),
                    sleep_cap: Duration::from_millis(1),
                }),
                Box::new(RecordingCleanup::default()),
            )
            .unwrap();
        clock.advance(Duration::from_millis(idle_config.browser_idle_timeout_ms));

        assert!(sessions.expire_idle("route", &clock, &idle_config));
        assert_eq!(
            graces.lock().unwrap().as_slice(),
            [Duration::from_millis(3_600_000)]
        );
    }

    /// A barrier a test browser's call parks on until the test opens it.
    #[derive(Default)]
    struct Gate {
        open: Mutex<bool>,
        wake: Condvar,
        entered: std::sync::atomic::AtomicUsize,
    }

    impl Gate {
        fn opened() -> Arc<Self> {
            let gate = Arc::new(Self::default());
            gate.open();
            gate
        }

        fn pass(&self) {
            self.entered
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut open = self.open.lock().unwrap();
            while !*open {
                open = self.wake.wait(open).unwrap();
            }
        }

        fn open(&self) {
            *self.open.lock().unwrap() = true;
            self.wake.notify_all();
        }

        fn close(&self) {
            *self.open.lock().unwrap() = false;
        }

        /// Wait until `count` calls have reached the gate.
        fn wait_entered(&self, count: usize) {
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.entered.load(std::sync::atomic::Ordering::SeqCst) < count {
                assert!(Instant::now() < deadline, "no call reached the gate");
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    }

    /// A killer that can never confirm the generation, as when the pid can no
    /// longer be matched to the browser.
    #[derive(Default)]
    struct RefusingKiller(std::sync::atomic::AtomicUsize);

    impl BrowserKiller for RefusingKiller {
        fn kill_exact_generation(&self) -> KillOutcome {
            self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            KillOutcome::Refused
        }
    }

    /// A configurable browser double. Its page calls and its screenshot pass
    /// `call_gate`, its reap passes `reap_gate`, and `shutdown_killer` passes
    /// `killer_gate` (establishment asks for the killer after finding its
    /// session, so that gate holds an establishment mid-way).
    struct TestBrowser {
        events: Arc<Mutex<Vec<&'static str>>>,
        call_gate: Arc<Gate>,
        reap_gate: Arc<Gate>,
        killer_gate: Arc<Gate>,
        killer: Option<Arc<dyn BrowserKiller>>,
        /// When set, the graceful wait ends as soon as this switch is killed.
        exit_on_kill: Option<Arc<KillSwitch>>,
        panic_on_screenshot: bool,
    }

    impl TestBrowser {
        fn new(events: &Arc<Mutex<Vec<&'static str>>>) -> Self {
            Self {
                events: Arc::clone(events),
                call_gate: Gate::opened(),
                reap_gate: Gate::opened(),
                killer_gate: Gate::opened(),
                killer: None,
                exit_on_kill: None,
                panic_on_screenshot: false,
            }
        }

        fn push(&self, event: &'static str) {
            self.events.lock().unwrap().push(event);
        }
    }

    impl OwnedBrowserProcess for TestBrowser {
        fn present(&mut self, _: &str, _: u64) -> Result<(), NavigationDriveError> {
            self.push("present");
            Ok(())
        }

        fn cookie_names_for_origin(
            &mut self,
            _: &str,
            _: &str,
            _: u64,
        ) -> Result<BTreeSet<String>, NavigationDriveError> {
            self.push("cookies");
            Ok(BTreeSet::from(["before".to_string()]))
        }

        fn main_frame_url(&mut self, _: &str, _: u64) -> Result<String, NavigationDriveError> {
            self.call_gate.pass();
            self.push("url");
            Ok("https://login.example/account".to_string())
        }

        fn has_credential_field(&mut self, _: &str, _: u64) -> Result<bool, NavigationDriveError> {
            self.push("credential");
            Ok(true)
        }

        fn screenshot(
            &mut self,
            _: &str,
            _: u64,
            _: u64,
            _: bool,
        ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
            if self.panic_on_screenshot {
                panic!("a browser driver call panicked for a test");
            }
            self.call_gate.pass();
            self.push("screenshot");
            Err(NavigationDriveError::CdpFailure)
        }

        fn generation_matches(&self) -> bool {
            true
        }

        fn request_graceful_termination(&mut self) -> Result<(), ProcessControlFailure> {
            self.push("graceful");
            Ok(())
        }

        fn wait_for_exit(&mut self, grace_period: Duration) -> Result<bool, ProcessControlFailure> {
            self.push("grace_wait");
            let Some(switch) = self.exit_on_kill.as_ref() else {
                return Ok(true);
            };
            let deadline = Instant::now() + grace_period.min(Duration::from_secs(60));
            let mut killed = switch.killed.lock().unwrap();
            while !*killed {
                let now = Instant::now();
                if now >= deadline {
                    return Ok(false);
                }
                killed = switch.wake.wait_timeout(killed, deadline - now).unwrap().0;
            }
            Ok(true)
        }

        fn force_terminate(&mut self) -> Result<(), ProcessControlFailure> {
            self.push("force");
            Ok(())
        }

        fn wait_until_reaped(&mut self) -> Result<(), ProcessControlFailure> {
            self.reap_gate.pass();
            self.push("reap");
            Ok(())
        }

        fn shutdown_killer(&self) -> Option<Arc<dyn BrowserKiller>> {
            self.killer_gate.pass();
            self.killer.clone()
        }
    }

    /// Counts after-reap cleanups (custody releases), optionally parking on a
    /// gate first.
    struct GatedCleanup {
        gate: Arc<Gate>,
        released: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl SessionCleanup for GatedCleanup {
        fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage> {
            self.gate.pass();
            self.released
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(SessionCleanupOutcome::Complete)
        }
    }

    struct Established {
        id: String,
        events: Arc<Mutex<Vec<&'static str>>>,
        released: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Established {
        fn released(&self) -> usize {
            self.released.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn events(&self) -> Vec<&'static str> {
            self.events.lock().unwrap().clone()
        }
    }

    fn establish_test_browser(
        sessions: &BrowserSessions,
        route: &str,
        clock: &FakeClock,
        cleanup_gate: Arc<Gate>,
        configure: impl FnOnce(&mut TestBrowser),
    ) -> Established {
        let _ = sessions.acquire_launch_slot(route);
        let events = Arc::new(Mutex::new(Vec::new()));
        let released = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut browser = TestBrowser::new(&events);
        configure(&mut browser);
        let (id, _, cancelled) = sessions
            .establish_ready(
                route,
                ProfileDisposition::Durable,
                &config(),
                clock,
                Box::new(browser),
                Box::new(GatedCleanup {
                    gate: cleanup_gate,
                    released: Arc::clone(&released),
                }),
            )
            .unwrap();
        assert!(!cancelled);
        Established {
            id,
            events,
            released,
        }
    }

    /// Run `body` on a thread and hand back a receiver for its result.
    fn in_thread<T: Send + 'static>(
        body: impl FnOnce() -> T + Send + 'static,
    ) -> std::sync::mpsc::Receiver<T> {
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = sender.send(body());
        });
        receiver
    }

    const PROMPTLY: Duration = Duration::from_secs(2);
    /// Long enough for a thread to park on the condition it is waiting for.
    const PARKED: Duration = Duration::from_millis(50);

    fn short_budget() -> ShutdownBudget {
        ShutdownBudget {
            total: Duration::from_millis(600),
            in_flight_wait_max: Duration::from_millis(100),
            cleanup_reserve: Duration::from_millis(200),
        }
    }

    fn assert_still_running<T: std::fmt::Debug>(
        receiver: &std::sync::mpsc::Receiver<T>,
        what: &str,
    ) {
        assert_eq!(
            receiver.recv_timeout(PARKED).err(),
            Some(std::sync::mpsc::RecvTimeoutError::Timeout),
            "{what} returned early"
        );
    }

    #[test]
    fn close_before_readiness_then_an_abandoned_launch_lets_close_return() {
        let sessions = BrowserSessions::default();
        let LaunchSlot::Acquired { browser_session_id } = sessions.acquire_launch_slot("route")
        else {
            panic!("the first launch slot was not granted");
        };
        let closing = sessions.clone();
        let close = in_thread(move || closing.close("route", &browser_session_id, &config()));
        sessions.wait_until_terminal_for_test("route");
        assert_still_running(&close, "close before the launch settled");

        sessions.abandon_launch_slot("route");
        assert_eq!(
            close
                .recv_timeout(PROMPTLY)
                .expect("close returns once the launch is abandoned"),
            json!({"outcome": "browser_session_not_found"})
        );
        assert!(matches!(
            sessions.acquire_launch_slot("route"),
            LaunchSlot::Acquired { .. }
        ));
    }

    #[test]
    fn a_close_joining_another_terminalizer_waits_for_its_reap_and_reports_that_session() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let reap_gate = Arc::new(Gate::default());
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.reap_gate = Arc::clone(&reap_gate);
            });
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));

        let expiring = sessions.clone();
        let expiry = in_thread(move || expiring.expire_idle("route", &clock, &config()));
        reap_gate.wait_entered(1);
        let closing = sessions.clone();
        let id = session.id.clone();
        let close = in_thread(move || closing.close("route", &id, &config()));
        assert_still_running(&close, "a close joining a teardown blocked in its reap");

        reap_gate.open();
        assert!(expiry.recv_timeout(PROMPTLY).unwrap());
        assert_eq!(
            close.recv_timeout(PROMPTLY).unwrap(),
            json!({"outcome": "idle_expired", "browser_session_id": session.id})
        );
        assert_eq!(session.events(), ["graceful", "grace_wait", "reap"]);
        assert_eq!(session.released(), 1, "exactly one after-reap cleanup");
    }

    #[test]
    fn an_ended_session_is_reported_by_its_own_id_after_a_newer_one_ends() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let first = establish_test_browser(&sessions, "route", &clock, Gate::opened(), |_| {});
        assert_eq!(
            sessions.close("route", &first.id, &config())["outcome"],
            "closed"
        );

        let _ = sessions.acquire_launch_slot("route");
        let (second, _, _) = sessions
            .establish_ready(
                "route",
                ProfileDisposition::Durable,
                &config(),
                &clock,
                Box::new(TestBrowser::new(&Arc::new(Mutex::new(Vec::new())))),
                Box::new(FailingCleanup(CleanupStage::CustodyRelease)),
            )
            .unwrap();
        assert_eq!(
            sessions.close("route", &second, &config())["outcome"],
            "cleanup_failure"
        );
        assert_eq!(
            sessions.close("route", &first.id, &config()),
            json!({"outcome": "closed", "browser_session_id": first.id})
        );
        assert_eq!(first.released(), 1);
    }

    #[test]
    fn a_present_in_progress_holds_off_idle_expiry() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let call_gate = Arc::new(Gate::default());
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.call_gate = Arc::clone(&call_gate);
            });
        let presenting = sessions.clone();
        let present_clock = clock.clone();
        let present = in_thread(move || {
            presenting.present("route", "https://login.example", 10, &present_clock)
        });
        call_gate.wait_entered(1);

        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        let expiring = sessions.clone();
        let expiry_clock = clock.clone();
        let expiry = in_thread(move || expiring.expire_idle("route", &expiry_clock, &config()));
        let expired = expiry.recv_timeout(PROMPTLY);
        call_gate.open();
        assert_eq!(
            expired,
            Ok(false),
            "idle expiry ran under a present in progress"
        );
        assert!(present.recv_timeout(PROMPTLY).unwrap().is_ok());
        assert!(session.events().contains(&"present"));
    }

    #[test]
    fn a_close_during_present_waits_for_it_and_refuses_its_commit() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let call_gate = Arc::new(Gate::default());
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.call_gate = Arc::clone(&call_gate);
            });
        let presenting = sessions.clone();
        let present_clock = clock.clone();
        let present = in_thread(move || {
            presenting.present("route", "https://login.example", 10, &present_clock)
        });
        call_gate.wait_entered(1);

        let closing = sessions.clone();
        let id = session.id.clone();
        let close = in_thread(move || closing.close("route", &id, &config()));
        assert_still_running(&close, "close under a present in progress");
        call_gate.open();
        assert_eq!(
            present.recv_timeout(PROMPTLY).unwrap(),
            Err(PresentRefusal::NoSession),
            "a present whose session closed under it must not commit a handoff"
        );
        assert_eq!(close.recv_timeout(PROMPTLY).unwrap()["outcome"], "closed");
        assert_eq!(sessions.human_in_control("route", &clock), None);
    }

    #[test]
    fn a_second_present_is_refused_while_the_first_is_in_progress() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let call_gate = Arc::new(Gate::default());
        let _session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.call_gate = Arc::clone(&call_gate);
            });
        let presenting = sessions.clone();
        let first_clock = clock.clone();
        let first = in_thread(move || {
            presenting.present("route", "https://login.example", 10, &first_clock)
        });
        call_gate.wait_entered(1);

        let presenting = sessions.clone();
        let second_clock = clock.clone();
        let second = in_thread(move || {
            presenting.present("route", "https://login.example", 10, &second_clock)
        });
        let second_result = second.recv_timeout(PROMPTLY);
        call_gate.open();
        assert_eq!(second_result, Ok(Err(PresentRefusal::HandoffOpen)));
        assert!(first.recv_timeout(PROMPTLY).unwrap().is_ok());
    }

    #[test]
    fn an_establishment_racing_an_abandon_hands_the_browser_back() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let _ = sessions.acquire_launch_slot("route");
        let events = Arc::new(Mutex::new(Vec::new()));
        let killer_gate = Arc::new(Gate::default());
        let mut browser = TestBrowser::new(&events);
        browser.killer_gate = Arc::clone(&killer_gate);
        let establishing = sessions.clone();
        let establishment = in_thread(move || {
            establishing
                .try_establish_ready(
                    "route",
                    ProfileDisposition::Durable,
                    &config(),
                    &clock,
                    Box::new(browser),
                    Box::new(RecordingCleanup::default()),
                )
                .map(|(id, _, _)| id)
        });
        // The establishment has found its session and is paused before it
        // installs the browser; the launch slot is abandoned meanwhile.
        killer_gate.wait_entered(1);
        sessions.abandon_launch_slot("route");
        killer_gate.open();

        let Err(mut handed_back) = establishment.recv_timeout(PROMPTLY).unwrap() else {
            panic!("a browser was installed into an abandoned session");
        };
        handed_back.process.wait_until_reaped().unwrap();
        assert_eq!(events.lock().unwrap().as_slice(), ["reap"]);
        assert_eq!(
            sessions.status("route", &FakeClock::new(), UNIX_EPOCH),
            json!({"outcome": "no_session"})
        );
    }

    fn stuck_call_on(
        sessions: &BrowserSessions,
        route: &str,
        clock: &FakeClock,
        killer: Option<Arc<dyn BrowserKiller>>,
        cleanup_gate: Arc<Gate>,
    ) -> (Established, Arc<Gate>, std::sync::mpsc::Receiver<bool>) {
        let call_gate = Arc::new(Gate::default());
        let session = establish_test_browser(sessions, route, clock, cleanup_gate, |browser| {
            browser.call_gate = Arc::clone(&call_gate);
            browser.killer = killer;
        });
        let DispatchAdmission::Accepted(mut operation) = sessions.accept_dispatch(route, clock)
        else {
            panic!("a ready session refused dispatch");
        };
        let call = in_thread(move || {
            let failed = operation
                .screenshot("context", 0, 3_600_000, false)
                .is_err();
            operation.finish();
            failed
        });
        call_gate.wait_entered(1);
        (session, call_gate, call)
    }

    #[test]
    fn shutdown_leaves_custody_held_when_a_stuck_call_cannot_be_killed() {
        let refusing = Arc::new(RefusingKiller::default());
        for killer in [Some(Arc::clone(&refusing) as Arc<dyn BrowserKiller>), None] {
            let sessions = BrowserSessions::default();
            let clock = FakeClock::new();
            let (session, call_gate, call) =
                stuck_call_on(&sessions, "stuck", &clock, killer, Gate::opened());
            let budget = short_budget();

            let started = Instant::now();
            sessions.teardown_all_within(&config(), budget);
            let took = started.elapsed();
            assert!(
                took <= budget.total + Duration::from_millis(100),
                "shutdown took {took:?} against a budget of {:?}",
                budget.total
            );
            let held = json!({
                "outcome": "cleanup_failure",
                "browser_session_id": session.id,
                "profile_disposition": "durable",
                "stage": "custody_held",
            });
            assert_eq!(sessions.status("stuck", &clock, UNIX_EPOCH), held);
            assert!(
                matches!(
                    sessions.acquire_launch_slot("stuck"),
                    LaunchSlot::Occupied { .. }
                ),
                "a second launch could open the profile of a browser still running"
            );
            assert_eq!(
                session.released(),
                0,
                "custody was released under a live browser"
            );
            assert!(matches!(
                sessions.accept_dispatch("stuck", &clock),
                DispatchAdmission::NoSession
            ));
            assert_eq!(
                sessions.close("stuck", &session.id, &config())["stage"],
                "custody_held"
            );

            call_gate.open();
            assert!(call.recv_timeout(PROMPTLY).unwrap());
            assert_eq!(sessions.status("stuck", &clock, UNIX_EPOCH), held);
            assert_eq!(session.released(), 0);
        }
        assert_eq!(
            refusing.0.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the refusing killer is tried once"
        );
    }

    #[test]
    fn shutdown_cuts_another_terminalizers_huge_grace_and_joins_it() {
        let sessions = BrowserSessions::default();
        let mut clock = FakeClock::new();
        let switch = Arc::new(KillSwitch::default());
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.killer = Some(Arc::new(SwitchKiller(Arc::clone(&switch))));
                browser.exit_on_kill = Some(Arc::clone(&switch));
            });
        clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        let mut huge_grace = config();
        huge_grace.termination_grace_period_ms = 3_600_000;
        let expiring = sessions.clone();
        let expiry = in_thread(move || expiring.expire_idle("route", &clock, &huge_grace));
        let deadline = Instant::now() + PROMPTLY;
        while !session.events().contains(&"grace_wait") {
            assert!(
                Instant::now() < deadline,
                "the idle expiry never reached its grace wait"
            );
            std::thread::sleep(Duration::from_millis(1));
        }

        let budget = short_budget();
        let started = Instant::now();
        sessions.teardown_all_within(&config(), budget);
        let took = started.elapsed();
        assert!(
            took <= budget.total + Duration::from_millis(100),
            "shutdown took {took:?} against a budget of {:?}",
            budget.total
        );
        assert!(expiry.recv_timeout(PROMPTLY).unwrap());
        assert_eq!(switch.fired.load(std::sync::atomic::Ordering::SeqCst), 1);
        assert_eq!(session.events(), ["graceful", "grace_wait", "reap"]);
        assert_eq!(session.released(), 1);
        assert_eq!(
            sessions.status("route", &FakeClock::new(), UNIX_EPOCH)["terminal_outcome"],
            "idle_expired"
        );
    }

    #[test]
    fn shutdown_recovers_a_poisoned_driver_lock() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (_, process, cleanup) = ready_session(&sessions, &clock, true);
        sessions.poison_session_lock_for_test("route", SessionLockForTest::Driver);

        let DispatchAdmission::Accepted(mut operation) = sessions.accept_dispatch("route", &clock)
        else {
            panic!("a ready session refused dispatch");
        };
        assert_eq!(
            operation.screenshot("context", 0, 10, false).err(),
            Some(NavigationDriveError::StateUnavailable),
            "a driver call over a poisoned driver lock refuses"
        );
        operation.finish();

        sessions.teardown_all_within(&config(), short_budget());
        assert_eq!(
            process.lock().unwrap().as_slice(),
            ["graceful", "grace_wait", "force", "reap"]
        );
        assert_eq!(cleanup.lock().unwrap().as_slice(), ["cleanup"]);
        assert_eq!(
            sessions.status("route", &clock, UNIX_EPOCH)["terminal_outcome"],
            "module_shutdown"
        );
    }

    #[test]
    fn shutdown_leaves_custody_held_when_after_reap_overruns_the_budget() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let cleanup_gate = Arc::new(Gate::default());
        let session = establish_test_browser(
            &sessions,
            "route",
            &clock,
            Arc::clone(&cleanup_gate),
            |_| {},
        );
        let budget = short_budget();

        let started = Instant::now();
        sessions.teardown_all_within(&config(), budget);
        let took = started.elapsed();
        assert!(
            took <= budget.total + Duration::from_millis(100),
            "shutdown took {took:?} against a budget of {:?}",
            budget.total
        );
        assert_eq!(
            sessions.status("route", &clock, UNIX_EPOCH)["stage"],
            "custody_held"
        );
        assert!(matches!(
            sessions.acquire_launch_slot("route"),
            LaunchSlot::Occupied { .. }
        ));

        // The overrunning cleanup still finishes later, and then the session
        // is retired with its real outcome.
        cleanup_gate.open();
        let deadline = Instant::now() + PROMPTLY;
        while sessions.status("route", &clock, UNIX_EPOCH)["outcome"] != "terminal" {
            assert!(
                Instant::now() < deadline,
                "the late cleanup never retired the session"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            sessions.status("route", &clock, UNIX_EPOCH)["terminal_outcome"],
            "module_shutdown"
        );
        assert_eq!(session.released(), 1);
        assert!(matches!(
            sessions.acquire_launch_slot("route"),
            LaunchSlot::Acquired { .. }
        ));
    }

    #[test]
    fn a_panic_in_one_routes_driver_call_does_not_refuse_another_route() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let panicking =
            establish_test_browser(&sessions, "route-a", &clock, Gate::opened(), |browser| {
                browser.panic_on_screenshot = true;
            });
        let _other = establish_test_browser(&sessions, "route-b", &clock, Gate::opened(), |_| {});

        let DispatchAdmission::Accepted(mut operation) =
            sessions.accept_dispatch("route-a", &clock)
        else {
            panic!("route A refused dispatch");
        };
        let panicked = std::thread::spawn(move || {
            let _ = operation.screenshot("context", 0, 10, false);
        })
        .join();
        assert!(
            panicked.is_err(),
            "route A's driver call was meant to panic"
        );

        assert_eq!(
            sessions.status("route-b", &clock, UNIX_EPOCH)["outcome"],
            "ready"
        );
        let DispatchAdmission::Accepted(mut operation) =
            sessions.accept_dispatch("route-b", &clock)
        else {
            panic!("route B refused dispatch after a panic on route A");
        };
        assert_eq!(
            operation.screenshot("context", 0, 10, false).err(),
            Some(NavigationDriveError::CdpFailure),
            "route B's call reached route B's browser"
        );
        operation.finish();

        assert_eq!(
            sessions.status("route-a", &clock, UNIX_EPOCH)["outcome"],
            "ready"
        );
        let DispatchAdmission::Accepted(mut operation) =
            sessions.accept_dispatch("route-a", &clock)
        else {
            panic!("route A refused dispatch");
        };
        assert_eq!(
            operation.screenshot("context", 0, 10, false).err(),
            Some(NavigationDriveError::StateUnavailable)
        );
        operation.finish();
        assert_eq!(
            sessions.close("route-a", &panicking.id, &config())["outcome"],
            "closed"
        );
    }

    #[test]
    fn every_release_wakes_a_teardown_parked_on_pending_operations() {
        // An operation's release.
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let session = establish_test_browser(&sessions, "route", &clock, Gate::opened(), |_| {});
        let DispatchAdmission::Accepted(operation) = sessions.accept_dispatch("route", &clock)
        else {
            panic!("a ready session refused dispatch");
        };
        let closing = sessions.clone();
        let id = session.id.clone();
        let close = in_thread(move || closing.close("route", &id, &config()));
        assert_still_running(&close, "close under a pending operation");
        operation.finish();
        assert_eq!(close.recv_timeout(PROMPTLY).unwrap()["outcome"], "closed");

        // A handoff poll's release.
        let sessions = BrowserSessions::default();
        let call_gate = Gate::opened();
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.call_gate = Arc::clone(&call_gate);
            });
        let presented = sessions
            .present("route", "https://login.example", 10, &clock)
            .unwrap();
        call_gate.close();
        let polling = sessions.clone();
        let poll_clock = clock.clone();
        let poll =
            in_thread(move || polling.poll_handoff("route", presented.generation, 10, &poll_clock));
        call_gate.wait_entered(2);
        let closing = sessions.clone();
        let id = session.id.clone();
        let close = in_thread(move || closing.close("route", &id, &config()));
        assert_still_running(&close, "close under a handoff poll");
        call_gate.open();
        assert_eq!(
            poll.recv_timeout(PROMPTLY).unwrap(),
            HandoffPollResult::Gone
        );
        assert_eq!(close.recv_timeout(PROMPTLY).unwrap()["outcome"], "closed");
    }

    /// Park a waiter on "the session went terminal", then run `trigger`,
    /// whose teardown blocks in its reap so that no later notification can
    /// wake the waiter in place of the terminal one.
    fn terminal_waiter_wakes_on(
        trigger: impl FnOnce(BrowserSessions, String, FakeClock) + Send + 'static,
    ) {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let reap_gate = Arc::new(Gate::default());
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.reap_gate = Arc::clone(&reap_gate);
            });
        let waiting = sessions.clone();
        let waiter = in_thread(move || waiting.wait_until_terminal_for_test("route"));
        assert_still_running(&waiter, "the terminal waiter");

        let triggering = sessions.clone();
        let mut trigger_clock = clock.clone();
        trigger_clock.advance(Duration::from_millis(config().browser_idle_timeout_ms));
        let triggered = in_thread(move || trigger(triggering, session.id, trigger_clock));
        reap_gate.wait_entered(1);
        let woke = waiter.recv_timeout(PROMPTLY);
        reap_gate.open();
        triggered.recv_timeout(PROMPTLY).unwrap();
        assert!(woke.is_ok(), "the terminal waiter was not woken");
    }

    #[test]
    fn a_terminal_waiter_wakes_on_close() {
        terminal_waiter_wakes_on(|sessions, id, _| {
            sessions.close("route", &id, &config());
        });
    }

    #[test]
    fn a_terminal_waiter_wakes_on_teardown_route() {
        terminal_waiter_wakes_on(|sessions, _, _| {
            sessions.teardown_route(
                "route",
                BrowserSessionTerminalOutcome::RouteUnbound,
                &config(),
            );
        });
    }

    #[test]
    fn a_terminal_waiter_wakes_on_idle_expiry() {
        terminal_waiter_wakes_on(|sessions, _, clock| {
            assert!(sessions.expire_idle("route", &clock, &config()));
        });
    }

    #[test]
    fn a_terminal_waiter_wakes_on_the_shutdown_marking_pass() {
        terminal_waiter_wakes_on(|sessions, _, _| {
            sessions.teardown_all_within(
                &config(),
                ShutdownBudget {
                    total: Duration::from_secs(10),
                    in_flight_wait_max: Duration::from_secs(1),
                    cleanup_reserve: Duration::from_secs(5),
                },
            );
        });
    }

    #[test]
    fn waiting_for_a_route_to_go_inactive_wakes_on_abandon() {
        let sessions = BrowserSessions::default();
        let _ = sessions.acquire_launch_slot("route");
        let waiting = sessions.clone();
        let waiter = in_thread(move || waiting.wait_until_inactive("route"));
        assert_still_running(&waiter, "the inactivity waiter");
        sessions.abandon_launch_slot("route");
        assert!(waiter.recv_timeout(PROMPTLY).is_ok());
    }

    #[test]
    fn waiting_for_a_route_to_go_inactive_wakes_on_retire() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let reap_gate = Arc::new(Gate::default());
        let session =
            establish_test_browser(&sessions, "route", &clock, Gate::opened(), |browser| {
                browser.reap_gate = Arc::clone(&reap_gate);
            });
        let closing = sessions.clone();
        let close = in_thread(move || closing.close("route", &session.id, &config()));
        reap_gate.wait_entered(1);
        let waiting = sessions.clone();
        let waiter = in_thread(move || waiting.wait_until_inactive("route"));
        assert_still_running(&waiter, "the inactivity waiter");
        reap_gate.open();
        assert!(waiter.recv_timeout(PROMPTLY).is_ok());
        assert_eq!(close.recv_timeout(PROMPTLY).unwrap()["outcome"], "closed");
    }

    #[test]
    fn a_close_parked_behind_a_stuck_call_returns_when_shutdown_holds_custody() {
        let sessions = BrowserSessions::default();
        let clock = FakeClock::new();
        let (session, call_gate, call) =
            stuck_call_on(&sessions, "stuck", &clock, None, Gate::opened());
        let closing = sessions.clone();
        let id = session.id.clone();
        let close = in_thread(move || closing.close("stuck", &id, &config()));
        assert_still_running(&close, "close under a stuck call");
        let waiting = sessions.clone();
        let inactive = in_thread(move || waiting.wait_until_inactive("stuck"));

        sessions.teardown_all_within(&config(), short_budget());
        let closed = close.recv_timeout(PROMPTLY);
        let stopped_waiting = inactive.recv_timeout(PROMPTLY);
        call_gate.open();
        assert!(call.recv_timeout(PROMPTLY).unwrap());
        assert_eq!(
            closed.expect("the parked close was woken"),
            json!({
                "outcome": "cleanup_failure",
                "browser_session_id": session.id,
                "stage": "custody_held",
            })
        );
        assert!(
            stopped_waiting.is_ok(),
            "the inactivity waiter was not woken"
        );
    }
}
