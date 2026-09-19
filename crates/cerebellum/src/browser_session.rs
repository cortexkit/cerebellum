//! Route-owned browser session lifecycle, leases, and the common teardown ladder.

use std::collections::{BTreeSet, HashMap};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

fn render_rfc3339_millis(time: SystemTime) -> String {
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
}

impl CleanupStage {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reap => "reap",
            Self::RecordTerminalization => "record_terminalization",
            Self::CustodyRelease => "custody_release",
            Self::DisposableDelete => "disposable_delete",
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
    ConnectorFailure,
    CdpFailure,
    CommandFailed { error_text: String },
    NavigationFailed { error_text: String },
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

#[derive(Debug, Clone, PartialEq)]
pub enum BrowserClickOutcome {
    Clicked(BrowserClickPosition),
    JavaScriptDialogDismissed {
        position: BrowserClickPosition,
        dialogs: Vec<BrowserJavaScriptDialog>,
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

    /// Read only the current main-frame URL.
    fn main_frame_url(
        &mut self,
        _context_key: &str,
        _deadline_ms: u64,
    ) -> Result<String, NavigationDriveError> {
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
}

pub trait SessionCleanup: Send {
    fn set_terminal_outcome(&mut self, outcome: BrowserSessionTerminalOutcome) {
        let _ = outcome;
    }

    fn after_reap(&mut self) -> Result<SessionCleanupOutcome, CleanupStage>;
}

struct ReadySession {
    browser_session_id: String,
    disposition: ProfileDisposition,
    lease: BrowserLease,
    pending_operations: usize,
    terminal: Option<BrowserSessionTerminalOutcome>,
    cleanup_failure: Option<CleanupStage>,
    cleanup_outcome: Option<SessionCleanupOutcome>,
    handoff: Option<HandoffState>,
    next_handoff_generation: u64,
    process: Option<Box<dyn OwnedBrowserProcess>>,
    cleanup: Option<Box<dyn SessionCleanup>>,
}

impl ReadySession {
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
}

#[derive(Default)]
struct RouteSessions {
    active: Option<ReadySession>,
    retained: Vec<ReadySession>,
    next_session: u64,
}

#[derive(Default)]
struct SessionState {
    routes: HashMap<String, RouteSessions>,
}

#[derive(Clone, Default)]
pub struct BrowserSessions {
    inner: Arc<(Mutex<SessionState>, Condvar)>,
}

pub enum LaunchSlot {
    Acquired { browser_session_id: String },
    Occupied { browser_session_id: String },
}

pub enum DispatchAdmission {
    Accepted(OperationGuard),
    LaunchPending,
    NoSession,
}

pub struct OperationGuard {
    sessions: BrowserSessions,
    route_key: String,
    finished: bool,
}

impl OperationGuard {
    pub fn finish(mut self) {
        self.release();
    }

    pub(crate) fn navigate(
        &mut self,
        context_key: &str,
        url: &str,
        wait: NavigationWait,
        deadline_ms: u64,
        tracker: &mut Tracker,
    ) -> Result<(), NavigationDriveError> {
        let mut state = self
            .sessions
            .inner
            .0
            .lock()
            .map_err(|_| NavigationDriveError::Unavailable)?;
        let process = state
            .routes
            .get_mut(&self.route_key)
            .and_then(|route| route.active.as_mut())
            .filter(|session| session.terminal.is_none() && session.cleanup_failure.is_none())
            .and_then(|session| session.process.as_mut())
            .ok_or(NavigationDriveError::Unavailable)?;
        process.navigate(context_key, url, wait, deadline_ms, tracker)
    }

    pub(crate) fn snapshot_classified(
        &mut self,
        context_key: &str,
        mode: SnapshotKind,
        document_epoch: u64,
        current_origin: &str,
        deadline_ms: u64,
    ) -> Result<BrowserSnapshotObservation, NavigationDriveError> {
        let mut state = self
            .sessions
            .inner
            .0
            .lock()
            .map_err(|_| NavigationDriveError::Unavailable)?;
        let process = state
            .routes
            .get_mut(&self.route_key)
            .and_then(|route| route.active.as_mut())
            .filter(|session| session.terminal.is_none() && session.cleanup_failure.is_none())
            .and_then(|session| session.process.as_mut())
            .ok_or(NavigationDriveError::Unavailable)?;
        process.snapshot_classified(
            context_key,
            mode,
            document_epoch,
            current_origin,
            deadline_ms,
        )
    }

    pub(crate) fn screenshot(
        &mut self,
        context_key: &str,
        document_epoch: u64,
        deadline_ms: u64,
        full: bool,
    ) -> Result<BrowserScreenshotObservation, NavigationDriveError> {
        let mut state = self
            .sessions
            .inner
            .0
            .lock()
            .map_err(|_| NavigationDriveError::Unavailable)?;
        let process = state
            .routes
            .get_mut(&self.route_key)
            .and_then(|route| route.active.as_mut())
            .filter(|session| session.terminal.is_none() && session.cleanup_failure.is_none())
            .and_then(|session| session.process.as_mut())
            .ok_or(NavigationDriveError::Unavailable)?;
        process.screenshot(context_key, document_epoch, deadline_ms, full)
    }

    pub(crate) fn click_point(
        &mut self,
        context_key: &str,
        position: BrowserClickPosition,
        deadline_ms: u64,
        input_dispatched: &mut dyn FnMut(BrowserInputEvent),
    ) -> Result<BrowserClickOutcome, ClickPointDriveError> {
        let mut state = self
            .sessions
            .inner
            .0
            .lock()
            .map_err(|_| ClickPointDriveError::Navigation(NavigationDriveError::Unavailable))?;
        let process = state
            .routes
            .get_mut(&self.route_key)
            .and_then(|route| route.active.as_mut())
            .filter(|session| session.terminal.is_none() && session.cleanup_failure.is_none())
            .and_then(|session| session.process.as_mut())
            .ok_or(ClickPointDriveError::Navigation(
                NavigationDriveError::Unavailable,
            ))?;
        process.click_point(context_key, position, deadline_ms, input_dispatched)
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
        let mut state = self
            .sessions
            .inner
            .0
            .lock()
            .map_err(|_| ClickDriveError::Navigation(NavigationDriveError::Unavailable))?;
        let process = state
            .routes
            .get_mut(&self.route_key)
            .and_then(|route| route.active.as_mut())
            .filter(|session| session.terminal.is_none() && session.cleanup_failure.is_none())
            .and_then(|session| session.process.as_mut())
            .ok_or(ClickDriveError::Navigation(
                NavigationDriveError::Unavailable,
            ))?;
        process.click_classified(
            context_key,
            identity,
            document_epoch,
            current_origin,
            expected,
            deadline_ms,
            input_dispatched,
        )
    }

    fn release(&mut self) {
        if self.finished {
            return;
        }
        let (lock, wake) = &*self.sessions.inner;
        if let Ok(mut state) = lock.lock() {
            if let Some(session) = state
                .routes
                .get_mut(&self.route_key)
                .and_then(|route| route.active.as_mut())
            {
                session.pending_operations = session.pending_operations.saturating_sub(1);
            }
            wake.notify_all();
        }
        self.finished = true;
    }
}

impl Drop for OperationGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl BrowserSessions {
    pub fn acquire_launch_slot(&self, route_key: &str) -> LaunchSlot {
        let mut state = self.inner.0.lock().expect("browser session lock poisoned");
        let route = state.routes.entry(route_key.to_string()).or_default();
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
        route.active = Some(ReadySession {
            browser_session_id: browser_session_id.clone(),
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
            next_handoff_generation: 0,
            process: None,
            cleanup: None,
        });
        LaunchSlot::Acquired { browser_session_id }
    }

    pub fn abandon_launch_slot(&self, route_key: &str) {
        let mut state = self.inner.0.lock().expect("browser session lock poisoned");
        if let Some(route) = state.routes.get_mut(route_key) {
            route.active = None;
        }
        self.inner.1.notify_all();
    }

    pub fn establish_ready<C: MonotonicClock>(
        &self,
        route_key: &str,
        disposition: ProfileDisposition,
        config: &BrowserConfig,
        clock: &C,
        process: Box<dyn OwnedBrowserProcess>,
        cleanup: Box<dyn SessionCleanup>,
    ) -> Option<(String, BrowserLease, bool)> {
        let mut state = self.inner.0.lock().ok()?;
        let session = state.routes.get_mut(route_key)?.active.as_mut()?;
        session.disposition = disposition;
        session.lease = BrowserLease::established(config.browser_idle_timeout_ms, clock);
        session.process = Some(process);
        session.cleanup = Some(cleanup);
        let result = (
            session.browser_session_id.clone(),
            session.lease.clone(),
            session.terminal.is_some(),
        );
        self.inner.1.notify_all();
        Some(result)
    }

    #[doc(hidden)]
    pub fn wait_until_terminal_for_test(&self, route_key: &str) {
        let mut state = self.inner.0.lock().expect("browser session lock poisoned");
        while state
            .routes
            .get(route_key)
            .and_then(|route| route.active.as_ref())
            .is_some_and(|session| session.terminal.is_none())
        {
            state = self
                .inner
                .1
                .wait(state)
                .expect("browser session lock poisoned");
        }
    }

    pub fn wait_until_inactive(&self, route_key: &str) {
        let mut state = self.inner.0.lock().expect("browser session lock poisoned");
        while state
            .routes
            .get(route_key)
            .and_then(|route| route.active.as_ref())
            .is_some()
        {
            state = self
                .inner
                .1
                .wait(state)
                .expect("browser session lock poisoned");
        }
    }

    #[doc(hidden)]
    pub fn lease_deadline_for_test(&self, route_key: &str) -> Option<MonoInstant> {
        let state = self.inner.0.lock().ok()?;
        let route = state.routes.get(route_key)?;
        route
            .active
            .as_ref()
            .or_else(|| route.retained.last())
            .map(|session| session.lease.deadline())
    }

    pub fn present<C: MonotonicClock>(
        &self,
        route_key: &str,
        origin: &str,
        deadline_ms: u64,
        clock: &C,
    ) -> Result<PresentedHandoff, PresentRefusal> {
        let mut state = self.inner.0.lock().map_err(|_| PresentRefusal::NoSession)?;
        let session = state
            .routes
            .get_mut(route_key)
            .and_then(|route| route.active.as_mut())
            .filter(|session| {
                session.process.is_some()
                    && session.terminal.is_none()
                    && session.cleanup_failure.is_none()
                    && clock.now() < session.lease.deadline()
            })
            .ok_or(PresentRefusal::NoSession)?;
        if matches!(session.handoff, Some(HandoffState::Open(_))) {
            return Err(PresentRefusal::HandoffOpen);
        }

        let process = session.process.as_mut().ok_or(PresentRefusal::NoSession)?;
        let current_url = process
            .main_frame_url(route_key, deadline_ms)
            .map_err(|error| PresentRefusal::PresentFailed {
                error_text: navigation_drive_error_text(error),
            })?;
        let current_origin = main_frame_origin(&current_url);
        if current_origin != origin {
            return Err(PresentRefusal::OriginMismatch { current_origin });
        }
        process
            .present(route_key, deadline_ms)
            .map_err(|error| PresentRefusal::PresentFailed {
                error_text: navigation_drive_error_text(error),
            })?;
        let opening_cookie_names = process
            .cookie_names_for_origin(route_key, origin, deadline_ms)
            .map_err(|error| PresentRefusal::PresentFailed {
                error_text: navigation_drive_error_text(error),
            })?;

        let opened_at = clock.now();
        let expires_at = opened_at.saturating_add(Duration::from_millis(HANDOFF_DURATION_MS));
        session.next_handoff_generation = session.next_handoff_generation.saturating_add(1);
        let generation = session.next_handoff_generation;
        session.lease.renew(clock);
        session.handoff = Some(HandoffState::Open(Handoff {
            generation,
            origin: origin.to_string(),
            opened_at,
            expires_at,
            opening_cookie_names,
            saw_credential_field: false,
            cookie_names_added: 0,
        }));
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
        let mut state = self.inner.0.lock().map_err(|_| ResumeRefusal::NoHandoff)?;
        let session = state
            .routes
            .get_mut(route_key)
            .and_then(|route| route.active.as_mut())
            .ok_or(ResumeRefusal::NoHandoff)?;
        let handoff = session.handoff.take().ok_or(ResumeRefusal::NoHandoff)?;
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
        let state = self.inner.0.lock().ok()?;
        let handoff = state
            .routes
            .get(route_key)?
            .active
            .as_ref()?
            .handoff
            .as_ref()?;
        match handoff {
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

    pub fn poll_handoff<C: MonotonicClock>(
        &self,
        route_key: &str,
        generation: u64,
        deadline_ms: u64,
        clock: &C,
    ) -> HandoffPollResult {
        let mut state = match self.inner.0.lock() {
            Ok(state) => state,
            Err(_) => return HandoffPollResult::Gone,
        };
        let Some(session) = state
            .routes
            .get_mut(route_key)
            .and_then(|route| route.active.as_mut())
        else {
            return HandoffPollResult::Gone;
        };
        let Some(HandoffState::Open(handoff)) = session.handoff.as_ref() else {
            return HandoffPollResult::Gone;
        };
        if handoff.generation != generation {
            return HandoffPollResult::Gone;
        }
        if clock.now() >= handoff.expires_at {
            let HandoffState::Open(handoff) = session.handoff.take().expect("matched open handoff")
            else {
                unreachable!("matched open handoff changed under the session lock")
            };
            let closed = ClosedHandoff {
                handoff,
                outcome: HandoffOutcome::Expired,
            };
            let result = handoff_close(&closed, true);
            session.handoff = Some(HandoffState::Closed(closed));
            return HandoffPollResult::Closed(result);
        }

        let opening_cookie_names = handoff.opening_cookie_names.clone();
        let saw_credential_field = handoff.saw_credential_field;
        let origin = handoff.origin.clone();
        session.lease.renew(clock);
        let Some(process) = session.process.as_mut() else {
            return HandoffPollResult::Gone;
        };
        let current_cookie_names =
            match process.cookie_names_for_origin(route_key, &origin, deadline_ms) {
                Ok(names) => names,
                Err(_) => return HandoffPollResult::Open,
            };
        let main_frame_url = match process.main_frame_url(route_key, deadline_ms) {
            Ok(url) => url,
            Err(_) => return HandoffPollResult::Open,
        };
        let has_credential_field_now = match process.has_credential_field(route_key, deadline_ms) {
            Ok(value) => value,
            Err(_) => return HandoffPollResult::Open,
        };
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
        let Some(HandoffState::Open(handoff)) = session.handoff.as_mut() else {
            return HandoffPollResult::Gone;
        };
        handoff.saw_credential_field |= has_credential_field_now;
        handoff.cookie_names_added = cookie_names_added;
        if !observed {
            return HandoffPollResult::Open;
        }
        let HandoffState::Open(handoff) = session.handoff.take().expect("matched open handoff")
        else {
            unreachable!("matched open handoff changed under the session lock")
        };
        let closed = ClosedHandoff {
            handoff,
            outcome: HandoffOutcome::LoginObserved,
        };
        let result = handoff_close(&closed, true);
        session.handoff = Some(HandoffState::Closed(closed));
        HandoffPollResult::Closed(result)
    }

    pub fn status<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
        wall_now: SystemTime,
    ) -> Value {
        let state = self.inner.0.lock().expect("browser session lock poisoned");
        let Some(route) = state.routes.get(route_key) else {
            return json!({"outcome": "no_session"});
        };
        if let Some(active) = route.active.as_ref() {
            return active.status_json(clock, wall_now);
        }
        route
            .retained
            .last()
            .map(|session| session.status_json(clock, wall_now))
            .unwrap_or_else(|| json!({"outcome": "no_session"}))
    }

    pub fn accept_dispatch<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
    ) -> DispatchAdmission {
        let mut state = self.inner.0.lock().expect("browser session lock poisoned");
        let Some(session) = state
            .routes
            .get_mut(route_key)
            .and_then(|route| route.active.as_mut())
        else {
            return DispatchAdmission::NoSession;
        };
        if session.process.is_none() {
            return DispatchAdmission::LaunchPending;
        }
        if session.terminal.is_some() || session.cleanup_failure.is_some() {
            return DispatchAdmission::NoSession;
        }
        if clock.now() >= session.lease.deadline() {
            return DispatchAdmission::NoSession;
        }
        session.lease.renew(clock);
        session.pending_operations = session.pending_operations.saturating_add(1);
        DispatchAdmission::Accepted(OperationGuard {
            sessions: self.clone(),
            route_key: route_key.to_string(),
            finished: false,
        })
    }

    pub fn expire_idle<C: MonotonicClock>(
        &self,
        route_key: &str,
        clock: &C,
        config: &BrowserConfig,
    ) -> bool {
        let (lock, _) = &*self.inner;
        let mut state = lock.lock().expect("browser session lock poisoned");
        let Some(session) = state
            .routes
            .get_mut(route_key)
            .and_then(|route| route.active.as_mut())
        else {
            return false;
        };
        let now = clock.now();
        if session.process.is_none()
            || session.terminal.is_some()
            || session.pending_operations != 0
            || session.handoff.as_ref().is_some_and(
                |handoff| matches!(handoff, HandoffState::Open(open) if now < open.expires_at),
            )
            || now < session.lease.deadline()
        {
            return false;
        }
        session.terminal = Some(BrowserSessionTerminalOutcome::IdleExpired);
        drop(state);
        self.finish_teardown(
            route_key,
            BrowserSessionTerminalOutcome::IdleExpired,
            config,
        );
        true
    }

    pub fn observe_exits_all(&self, config: &BrowserConfig) {
        let route_keys = self
            .inner
            .0
            .lock()
            .expect("browser session lock poisoned")
            .routes
            .iter()
            .filter_map(|(route_key, route)| {
                route
                    .active
                    .as_ref()
                    .filter(|session| {
                        session.terminal.is_none()
                            && session
                                .process
                                .as_ref()
                                .is_some_and(|process| !process.generation_matches())
                    })
                    .map(|_| route_key.clone())
            })
            .collect::<Vec<_>>();
        for route_key in route_keys {
            self.teardown_route(
                &route_key,
                BrowserSessionTerminalOutcome::BrowserCrashed,
                config,
            );
        }
    }

    pub fn expire_all<C: MonotonicClock>(&self, clock: &C, config: &BrowserConfig) {
        let route_keys = self
            .inner
            .0
            .lock()
            .expect("browser session lock poisoned")
            .routes
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for route_key in route_keys {
            self.expire_idle(&route_key, clock, config);
        }
    }

    pub fn close(
        &self,
        route_key: &str,
        browser_session_id: &str,
        config: &BrowserConfig,
    ) -> Value {
        let terminalizer = {
            let mut state = self.inner.0.lock().expect("browser session lock poisoned");
            let Some(route) = state.routes.get_mut(route_key) else {
                return json!({"outcome": "browser_session_not_found"});
            };
            if let Some(retained) = route
                .retained
                .iter()
                .find(|session| session.browser_session_id == browser_session_id)
            {
                return close_result(retained);
            }
            let Some(session) = route.active.as_mut() else {
                return json!({"outcome": "browser_session_not_found"});
            };
            if session.browser_session_id != browser_session_id {
                return json!({"outcome": "browser_session_not_found"});
            }
            if let Some(stage) = session.cleanup_failure {
                return json!({
                    "outcome": "cleanup_failure",
                    "browser_session_id": browser_session_id,
                    "stage": stage.as_str(),
                });
            }
            let terminalizer = session.terminal.is_none();
            session
                .terminal
                .get_or_insert(BrowserSessionTerminalOutcome::Closed);
            self.inner.1.notify_all();
            terminalizer
        };
        if terminalizer {
            self.finish_teardown(route_key, BrowserSessionTerminalOutcome::Closed, config);
        } else {
            let mut state = self.inner.0.lock().expect("browser session lock poisoned");
            while state
                .routes
                .get(route_key)
                .and_then(|route| route.active.as_ref())
                .is_some()
            {
                state = self
                    .inner
                    .1
                    .wait(state)
                    .expect("browser session lock poisoned");
            }
        }
        let state = self.inner.0.lock().expect("browser session lock poisoned");
        state
            .routes
            .get(route_key)
            .and_then(|route| route.retained.last())
            .map(close_result)
            .unwrap_or_else(|| json!({"outcome": "browser_session_not_found"}))
    }

    pub fn teardown_route(
        &self,
        route_key: &str,
        reason: BrowserSessionTerminalOutcome,
        config: &BrowserConfig,
    ) {
        {
            let mut state = self.inner.0.lock().expect("browser session lock poisoned");
            let Some(session) = state
                .routes
                .get_mut(route_key)
                .and_then(|route| route.active.as_mut())
            else {
                return;
            };
            session.terminal.get_or_insert(reason);
        }
        self.finish_teardown(route_key, reason, config);
    }

    pub fn teardown_all(&self, config: &BrowserConfig) {
        let keys = self
            .inner
            .0
            .lock()
            .expect("browser session lock poisoned")
            .routes
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        std::thread::scope(|scope| {
            for key in keys {
                scope.spawn(move || {
                    self.teardown_route(
                        &key,
                        BrowserSessionTerminalOutcome::ModuleShutdown,
                        config,
                    );
                });
            }
        });
    }

    fn finish_teardown(
        &self,
        route_key: &str,
        reason: BrowserSessionTerminalOutcome,
        config: &BrowserConfig,
    ) {
        let (lock, wake) = &*self.inner;
        let (browser_session_id, terminal_outcome, mut process, mut cleanup) = {
            let mut state = lock.lock().expect("browser session lock poisoned");
            while state
                .routes
                .get(route_key)
                .and_then(|route| route.active.as_ref())
                .is_some_and(|session| session.pending_operations != 0)
            {
                state = wake.wait(state).expect("browser session lock poisoned");
            }
            let Some(session) = state
                .routes
                .get_mut(route_key)
                .and_then(|route| route.active.as_mut())
            else {
                return;
            };
            let terminal_outcome = *session.terminal.get_or_insert(reason);
            while state
                .routes
                .get(route_key)
                .and_then(|route| route.active.as_ref())
                .is_some_and(|session| session.process.is_none())
            {
                state = wake.wait(state).expect("browser session lock poisoned");
            }
            let Some(session) = state
                .routes
                .get_mut(route_key)
                .and_then(|route| route.active.as_mut())
            else {
                return;
            };
            let Some(process) = session.process.take() else {
                // Another terminalizer owns the process. Join its reap rather
                // than reporting success from a second close independently.
                while state
                    .routes
                    .get(route_key)
                    .and_then(|route| route.active.as_ref())
                    .is_some()
                {
                    state = wake.wait(state).expect("browser session lock poisoned");
                }
                return;
            };
            (
                session.browser_session_id.clone(),
                terminal_outcome,
                process,
                session.cleanup.take(),
            )
        };

        let outcome = teardown_process(process.as_mut(), config).and_then(|()| {
            let cleanup = cleanup.as_mut().ok_or(CleanupStage::CustodyRelease)?;
            cleanup.set_terminal_outcome(terminal_outcome);
            cleanup.after_reap()
        });

        let mut state = lock.lock().expect("browser session lock poisoned");
        let Some(route) = state.routes.get_mut(route_key) else {
            return;
        };
        if route
            .active
            .as_ref()
            .is_none_or(|session| session.browser_session_id != browser_session_id)
        {
            return;
        }
        let mut session = route.active.take().expect("matched active session");
        session.process = Some(process);
        session.cleanup = cleanup;
        match outcome {
            Ok(cleanup_outcome) => session.cleanup_outcome = Some(cleanup_outcome),
            Err(stage) => {
                session.cleanup_failure = Some(stage);
                session.terminal = Some(BrowserSessionTerminalOutcome::CleanupFailure);
            }
        }
        route.retained.push(session);
        wake.notify_all();
    }
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
        NavigationDriveError::ConnectorFailure => "browser connector failure".to_string(),
        NavigationDriveError::CdpFailure => "browser CDP failure".to_string(),
    }
}

fn close_result(session: &ReadySession) -> Value {
    if let Some(stage) = session.cleanup_failure {
        return json!({
            "outcome": "cleanup_failure",
            "browser_session_id": session.browser_session_id,
            "stage": stage.as_str(),
        });
    }
    if let Some(failed_signals) = session
        .cleanup_outcome
        .and_then(SessionCleanupOutcome::failed_signals)
    {
        return json!({
            "outcome": "durable_state_at_risk",
            "browser_session_id": session.browser_session_id,
            "failed_signals": failed_signals,
        });
    }
    json!({
        "outcome": session
            .terminal
            .unwrap_or(BrowserSessionTerminalOutcome::CleanupFailure)
            .as_str(),
        "browser_session_id": session.browser_session_id,
    })
}

fn teardown_process(
    process: &mut dyn OwnedBrowserProcess,
    config: &BrowserConfig,
) -> Result<(), CleanupStage> {
    if !process.generation_matches() {
        return process.wait_until_reaped().map_err(|_| CleanupStage::Reap);
    }
    process
        .request_graceful_termination()
        .map_err(|_| CleanupStage::Reap)?;
    let exited = process
        .wait_for_exit(Duration::from_millis(config.termination_grace_period_ms))
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
}
