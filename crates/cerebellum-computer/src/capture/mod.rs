//! Scoped ScreenCaptureKit capture policy and a deterministic backend seam.
//!
//! Scoped capture is deliberately expressed in terms of individual,
//! desktop-independent windows.  The controller owns the safety boundary: a
//! backend may enumerate more windows than the grant owns, but only a window
//! whose verified process identity exactly matches the grant is ever captured.
//! The production macOS binding can implement [`CaptureBackend`] without
//! changing this policy or widening it to a composited display filter.

use crate::platform::{PermissionLiveness, ProcessGrant};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;

/// This constant limits how long the controller may wait before re-enumerating
/// windows, matching the capture timing contract used by computer actions.
pub const MAXIMUM_WINDOW_REENUMERATION_INTERVAL_MS: u64 = 500;
/// The maximum time allowed for capture teardown after revocation.
pub const MAXIMUM_CAPTURE_TEARDOWN_INTERVAL_MS: u64 = 1_000;

/// All leakage values are explicit.  An omitted value is not an acceptable
/// capture result because callers must be able to distinguish a clean boundary
/// from an implementation that did not check it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeakageValue {
    Present,
    Absent,
    Unknown,
}

/// Closed leakage vocabulary for capture results.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureLeakageFlag {
    CursorComposited,
    DisplayDependentComposition,
    SelfWindowsIncluded,
    SharingTypeBypassOutsideProcessControl,
    WindowEnumerationIncomplete,
}

impl CaptureLeakageFlag {
    /// The complete v1 flag set, in stable wire order.
    pub const ALL: [Self; 5] = [
        Self::CursorComposited,
        Self::DisplayDependentComposition,
        Self::SelfWindowsIncluded,
        Self::SharingTypeBypassOutsideProcessControl,
        Self::WindowEnumerationIncomplete,
    ];
}

/// Every field is public so a journal adapter can serialize the exact closed
/// vocabulary without converting through an unbounded string-keyed map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureLeakageReport {
    pub cursor_composited: LeakageValue,
    pub display_dependent_composition: LeakageValue,
    pub self_windows_included: LeakageValue,
    pub sharing_type_bypass_outside_process_control: LeakageValue,
    pub window_enumeration_incomplete: LeakageValue,
}

impl CaptureLeakageReport {
    /// The safe residual flags for a desktop-independent scoped capture before
    /// dynamic enumeration is evaluated.
    pub const fn scoped() -> Self {
        Self {
            cursor_composited: LeakageValue::Absent,
            display_dependent_composition: LeakageValue::Absent,
            self_windows_included: LeakageValue::Absent,
            sharing_type_bypass_outside_process_control: LeakageValue::Present,
            window_enumeration_incomplete: LeakageValue::Absent,
        }
    }

    /// Broad display capture is intentionally described as composited and
    /// separately granted.  The sharing-type bypass remains outside this
    /// process's control and therefore is not guessed away.
    pub const fn broad(include_cursor: bool) -> Self {
        Self {
            cursor_composited: if include_cursor {
                LeakageValue::Present
            } else {
                LeakageValue::Absent
            },
            display_dependent_composition: LeakageValue::Present,
            self_windows_included: LeakageValue::Present,
            sharing_type_bypass_outside_process_control: LeakageValue::Unknown,
            window_enumeration_incomplete: LeakageValue::Absent,
        }
    }

    pub const fn with_enumeration_incomplete(mut self, incomplete: bool) -> Self {
        self.window_enumeration_incomplete = if incomplete {
            LeakageValue::Present
        } else {
            LeakageValue::Absent
        };
        self
    }

    /// Return the flags as a closed, stable map for generic journal encoders.
    pub fn as_map(&self) -> BTreeMap<CaptureLeakageFlag, LeakageValue> {
        CaptureLeakageFlag::ALL
            .into_iter()
            .map(|flag| {
                let value = match flag {
                    CaptureLeakageFlag::CursorComposited => self.cursor_composited,
                    CaptureLeakageFlag::DisplayDependentComposition => {
                        self.display_dependent_composition
                    }
                    CaptureLeakageFlag::SelfWindowsIncluded => self.self_windows_included,
                    CaptureLeakageFlag::SharingTypeBypassOutsideProcessControl => {
                        self.sharing_type_bypass_outside_process_control
                    }
                    CaptureLeakageFlag::WindowEnumerationIncomplete => {
                        self.window_enumeration_incomplete
                    }
                };
                (flag, value)
            })
            .collect()
    }

    pub fn is_scoped_safe(&self) -> bool {
        self.cursor_composited == LeakageValue::Absent
            && self.display_dependent_composition == LeakageValue::Absent
            && self.window_enumeration_incomplete != LeakageValue::Unknown
    }
}

/// A grant-bound window frame.  Dimensions are unsigned because a native
/// window cannot have a negative size; the origin may be negative on a display
/// arrangement with a secondary screen to the left or above the main screen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowFrame {
    pub x: i32,
    pub y: i32,
    pub width: u32,
    pub height: u32,
}

/// Window metadata returned by the platform enumerator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnumeratedWindow {
    pub window_id: String,
    pub owner_identity: ProcessGrant,
    /// This is separate from tuple equality: a caller-controlled label that
    /// happens to equal the grant is not process-identity evidence.
    pub owner_identity_verified: bool,
    pub frame: WindowFrame,
    pub accessibility_root: Option<String>,
}

impl EnumeratedWindow {
    fn matches_verified_target(&self, target: &ProcessGrant) -> bool {
        self.owner_identity_verified && self.owner_identity == *target && !self.window_id.is_empty()
    }
}

/// The only filter the scoped controller is allowed to request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DesktopIndependentWindowFilter {
    pub window_id: String,
    pub include_cursor: bool,
}

impl DesktopIndependentWindowFilter {
    pub fn new(window_id: impl Into<String>) -> Self {
        Self {
            window_id: window_id.into(),
            include_cursor: false,
        }
    }
}

/// A rectangle in the target window's own pixel space, origin at its top-left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WindowCaptureRegion {
    pub x_px: u32,
    pub y_px: u32,
    pub width_px: u32,
    pub height_px: u32,
}

/// A backend capture request always carries the grant, even though the window
/// list was already filtered. This makes the identity binding visible at the
/// platform seam and lets a native implementation re-check it before calling
/// `SCContentFilter(desktopIndependentWindow:)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCaptureRequest {
    pub target: ProcessGrant,
    pub filter: DesktopIndependentWindowFilter,
    pub captured_at_ms: u64,
    /// When set, the backend must capture this rectangle, not the whole window.
    pub region: Option<WindowCaptureRegion>,
}

/// Image data may stay in memory for tests or be represented by an artifact
/// reference when the native backend streams it to the retention owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureArtifact {
    Bytes(Vec<u8>),
    Reference(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowCaptureFrame {
    pub owner_identity: ProcessGrant,
    pub owner_identity_verified: bool,
    pub frame: WindowFrame,
    pub captured_at_ms: u64,
    pub artifact: CaptureArtifact,
    pub accessibility_root: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedWindow {
    pub window_id: String,
    pub owner_identity: ProcessGrant,
    pub captured_at_ms: u64,
    pub frame: WindowFrame,
    pub artifact: CaptureArtifact,
    pub accessibility_root: Option<String>,
    /// This is serialized evidence that the filter was per-window and not a
    /// display composition, rather than an inference made from the pixels.
    pub desktop_independent_filter: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowChangeKind {
    Created,
    Closed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowChange {
    pub kind: WindowChangeKind,
    /// The timestamp comes from the same monotonic domain as capture calls.
    pub observed_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedCaptureResult {
    pub windows: Vec<CapturedWindow>,
    pub enumeration_generation: u64,
    pub reenumeration_occurred: bool,
    pub cursor_compositing: LeakageValue,
    pub leakage: CaptureLeakageReport,
    pub maximum_window_reenumeration_interval_ms: u64,
    pub measured_reenumeration_interval_ms: Option<u64>,
}

impl ScopedCaptureResult {
    pub fn window_enumeration_incomplete(&self) -> LeakageValue {
        self.leakage.window_enumeration_incomplete
    }

    pub fn leakage_flags(&self) -> BTreeMap<CaptureLeakageFlag, LeakageValue> {
        self.leakage.as_map()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadDisplayGrant {
    pub grant_id: String,
}

impl BroadDisplayGrant {
    pub fn new(grant_id: impl Into<String>) -> Result<Self, CaptureError> {
        let grant_id = grant_id.into();
        if grant_id.trim().is_empty() {
            return Err(CaptureError::InvalidGrant);
        }
        Ok(Self { grant_id })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BroadDisplayCaptureRequest {
    pub include_cursor: bool,
    pub captured_at_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BroadDisplayCaptureResult {
    pub captured_at_ms: u64,
    pub artifact: CaptureArtifact,
    pub leakage: CaptureLeakageReport,
    pub broad_grant_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureSessionState {
    NotStarted,
    Active,
    PermissionPendingRelaunch,
    PermissionUnavailable,
    RevokedTeardownPending,
    RevokedTeardownComplete,
    RevokedTeardownDetached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TeardownProgress {
    Complete,
    Pending,
    Detached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TeardownStatus {
    pub progress: TeardownProgress,
    pub elapsed_ms: u64,
    pub maximum_interval_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptureError {
    PermissionUnavailable,
    PermissionPendingRelaunch,
    CaptureScopeUnavailable,
    BroadCaptureGrantRequired,
    InvalidGrant,
    TeardownInProgress,
    ScreenIsLocked,
    Backend(String),
}

impl fmt::Display for CaptureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionUnavailable => f.write_str("permission_unavailable"),
            Self::PermissionPendingRelaunch => f.write_str("permission_pending_relaunch"),
            Self::CaptureScopeUnavailable => f.write_str("capture_scope_unavailable"),
            Self::BroadCaptureGrantRequired => f.write_str("broad_display_grant_required"),
            Self::InvalidGrant => f.write_str("invalid broad display grant"),
            Self::TeardownInProgress => f.write_str("capture teardown in progress"),
            Self::ScreenIsLocked => f.write_str("screen is locked"),
            Self::Backend(reason) => write!(f, "capture backend failure: {reason}"),
        }
    }
}
impl std::error::Error for CaptureError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendError {
    Permission(String),
    Enumeration(String),
    Capture(String),
    ScreenLocked,
    Teardown(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Permission(reason)
            | Self::Enumeration(reason)
            | Self::Capture(reason)
            | Self::Teardown(reason) => f.write_str(reason),
            Self::ScreenLocked => f.write_str("screen is locked"),
        }
    }
}
impl std::error::Error for BackendError {}

impl From<BackendError> for CaptureError {
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::ScreenLocked => Self::ScreenIsLocked,
            error => Self::Backend(error.to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendTeardownProgress {
    Complete,
    Pending,
}

/// The native ScreenCaptureKit implementation is expected to make these calls
/// non-blocking.  In particular, teardown is split into begin/poll so a revoked
/// stream cannot wedge the health lane while the window-server releases it.
pub trait CaptureBackend {
    fn screen_recording_liveness(&self) -> PermissionLiveness;
    fn enumerate_windows(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError>;
    fn poll_window_change(
        &mut self,
        target: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError>;
    fn capture_window(
        &mut self,
        request: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError>;
    fn capture_display(
        &mut self,
        request: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError>;
    /// Begin teardown without waiting for the native stream to stop.
    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError>;
    /// Poll teardown using elapsed monotonic time; this operation must not wait.
    fn poll_teardown(&mut self, elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError>;
}

/// A capture controller binds one target grant to one backend and never stores a
/// broader display filter as a fallback for scoped requests.
pub struct ScopedCaptureController<B> {
    backend: B,
    target: ProcessGrant,
    state: CaptureSessionState,
    enumeration_generation: u64,
    maximum_reenumeration_interval_ms: u64,
    maximum_teardown_interval_ms: u64,
    teardown_started_ms: Option<u64>,
    broad_display_grant: Option<BroadDisplayGrant>,
    windows: Vec<EnumeratedWindow>,
}

impl<B: CaptureBackend> ScopedCaptureController<B> {
    pub fn new(
        backend: B,
        target: ProcessGrant,
        maximum_reenumeration_interval_ms: u64,
        maximum_teardown_interval_ms: u64,
    ) -> Result<Self, CaptureError> {
        target
            .validate()
            .map_err(|error| CaptureError::Backend(error.to_string()))?;
        if maximum_reenumeration_interval_ms == 0 || maximum_teardown_interval_ms == 0 {
            return Err(CaptureError::Backend(
                "capture timing bounds must be non-zero".into(),
            ));
        }
        Ok(Self {
            backend,
            target,
            state: CaptureSessionState::NotStarted,
            enumeration_generation: 0,
            maximum_reenumeration_interval_ms,
            maximum_teardown_interval_ms,
            teardown_started_ms: None,
            broad_display_grant: None,
            windows: Vec::new(),
        })
    }

    pub fn with_v1_bounds(backend: B, target: ProcessGrant) -> Result<Self, CaptureError> {
        Self::new(
            backend,
            target,
            MAXIMUM_WINDOW_REENUMERATION_INTERVAL_MS,
            MAXIMUM_CAPTURE_TEARDOWN_INTERVAL_MS,
        )
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The windows the controller last enumerated for this grant.
    ///
    /// Used by the serving handler to check a requested region against the
    /// window's own size before asking the backend to capture it.
    pub fn enumerated_windows(&mut self, now_ms: u64) -> Result<&[EnumeratedWindow], CaptureError> {
        self.refresh_if_needed(now_ms)?;
        Ok(&self.windows)
    }

    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    pub fn state(&self) -> CaptureSessionState {
        self.state
    }

    pub fn enumeration_generation(&self) -> u64 {
        self.enumeration_generation
    }

    pub fn target(&self) -> &ProcessGrant {
        &self.target
    }

    /// Capture one scoped frame.  A permission loss observed at this boundary
    /// stops frames immediately and starts asynchronous teardown.
    pub fn capture_scoped(&mut self, now_ms: u64) -> Result<ScopedCaptureResult, CaptureError> {
        self.capture_scoped_with_region(now_ms, None)
    }

    /// Capture one scoped frame, optionally restricted to a window-local region.
    pub fn capture_scoped_with_region(
        &mut self,
        now_ms: u64,
        region: Option<WindowCaptureRegion>,
    ) -> Result<ScopedCaptureResult, CaptureError> {
        self.ensure_capture_permission(now_ms)?;
        if matches!(
            self.state,
            CaptureSessionState::RevokedTeardownPending
                | CaptureSessionState::RevokedTeardownComplete
                | CaptureSessionState::RevokedTeardownDetached
        ) {
            return Err(CaptureError::PermissionUnavailable);
        }

        let (reenumeration_occurred, measured_interval, incomplete) =
            self.refresh_if_needed(now_ms)?;
        let mut windows = Vec::with_capacity(self.windows.len());
        for window in &self.windows {
            let request = WindowCaptureRequest {
                target: self.target.clone(),
                filter: DesktopIndependentWindowFilter::new(window.window_id.clone()),
                captured_at_ms: now_ms,
                region,
            };
            let frame = self
                .backend
                .capture_window(&request)
                .map_err(CaptureError::from)?;
            if !frame.owner_identity_verified || frame.owner_identity != self.target {
                // Never return pixels whose identity changed between enumeration
                // and capture.  A native implementation must re-enumerate rather
                // than quietly turning this into a broad display capture.
                return Err(CaptureError::CaptureScopeUnavailable);
            }
            if request.filter.include_cursor {
                return Err(CaptureError::CaptureScopeUnavailable);
            }
            windows.push(CapturedWindow {
                window_id: window.window_id.clone(),
                owner_identity: frame.owner_identity,
                captured_at_ms: frame.captured_at_ms,
                frame: frame.frame,
                artifact: frame.artifact,
                accessibility_root: frame.accessibility_root,
                desktop_independent_filter: true,
            });
        }
        self.state = CaptureSessionState::Active;
        Ok(ScopedCaptureResult {
            windows,
            enumeration_generation: self.enumeration_generation,
            reenumeration_occurred,
            cursor_compositing: LeakageValue::Absent,
            leakage: CaptureLeakageReport::scoped().with_enumeration_incomplete(incomplete),
            maximum_window_reenumeration_interval_ms: self.maximum_reenumeration_interval_ms,
            measured_reenumeration_interval_ms: measured_interval,
        })
    }

    /// Alias with an explicit frame-oriented name for stream adapters.
    pub fn capture_scoped_frame(
        &mut self,
        now_ms: u64,
    ) -> Result<ScopedCaptureResult, CaptureError> {
        self.capture_scoped(now_ms)
    }

    fn ensure_capture_permission(&mut self, now_ms: u64) -> Result<(), CaptureError> {
        match self.backend.screen_recording_liveness() {
            PermissionLiveness::Live => {
                if matches!(
                    self.state,
                    CaptureSessionState::PermissionPendingRelaunch
                        | CaptureSessionState::PermissionUnavailable
                ) {
                    self.state = CaptureSessionState::NotStarted;
                }
                Ok(())
            }
            PermissionLiveness::GrantedPendingRelaunch => {
                if self.enumeration_generation > 0 {
                    self.start_revocation_teardown(now_ms)?;
                } else {
                    self.state = CaptureSessionState::PermissionPendingRelaunch;
                }
                Err(CaptureError::PermissionPendingRelaunch)
            }
            PermissionLiveness::Unavailable | PermissionLiveness::Unresolved => {
                if self.enumeration_generation > 0 {
                    self.start_revocation_teardown(now_ms)?;
                } else {
                    self.state = CaptureSessionState::PermissionUnavailable;
                }
                Err(CaptureError::PermissionUnavailable)
            }
        }
    }

    fn refresh_if_needed(
        &mut self,
        now_ms: u64,
    ) -> Result<(bool, Option<u64>, bool), CaptureError> {
        let mut reenumerate = self.enumeration_generation == 0;
        let mut measured_interval = None;
        let mut incomplete = false;
        if !reenumerate {
            let change = self
                .backend
                .poll_window_change(&self.target)
                .map_err(CaptureError::from)?;
            if let Some(change) = change {
                reenumerate = true;
                let interval = now_ms.saturating_sub(change.observed_at_ms);
                measured_interval = Some(interval);
                incomplete = interval > self.maximum_reenumeration_interval_ms;
            }
        }
        if reenumerate {
            let mut windows = self
                .backend
                .enumerate_windows(&self.target)
                .map_err(CaptureError::from)?;
            // Compare each window's verified owner identity with the entire
            // target ProcessGrant; titles, window IDs, and raw process IDs alone
            // are not sufficient evidence of ownership.
            windows.retain(|window| window.matches_verified_target(&self.target));
            windows.sort_by(|left, right| left.window_id.cmp(&right.window_id));
            windows.dedup_by(|left, right| left.window_id == right.window_id);
            self.windows = windows;
            self.enumeration_generation = self.enumeration_generation.saturating_add(1);
        }
        Ok((reenumerate, measured_interval, incomplete))
    }

    /// Explicit asynchronous permission-revocation entry point for a native
    /// permission notification.  It is safe to call more than once.
    pub fn on_permission_revoked(&mut self, now_ms: u64) -> Result<TeardownStatus, CaptureError> {
        self.start_revocation_teardown(now_ms)?;
        self.teardown_status(now_ms)
    }

    fn start_revocation_teardown(&mut self, now_ms: u64) -> Result<(), CaptureError> {
        if self.teardown_started_ms.is_some() {
            return Ok(());
        }
        self.teardown_started_ms = Some(now_ms);
        self.windows.clear();
        self.state = CaptureSessionState::RevokedTeardownPending;
        match self.backend.begin_teardown().map_err(CaptureError::from)? {
            BackendTeardownProgress::Complete => {
                self.state = CaptureSessionState::RevokedTeardownComplete;
            }
            BackendTeardownProgress::Pending => {}
        }
        Ok(())
    }

    pub fn poll_teardown(&mut self, now_ms: u64) -> Result<TeardownStatus, CaptureError> {
        let Some(started_ms) = self.teardown_started_ms else {
            return Err(CaptureError::TeardownInProgress);
        };
        if self.state == CaptureSessionState::RevokedTeardownComplete {
            return Ok(TeardownStatus {
                progress: TeardownProgress::Complete,
                elapsed_ms: now_ms.saturating_sub(started_ms),
                maximum_interval_ms: self.maximum_teardown_interval_ms,
            });
        }
        if self.state == CaptureSessionState::RevokedTeardownDetached {
            return Ok(TeardownStatus {
                progress: TeardownProgress::Detached,
                elapsed_ms: now_ms.saturating_sub(started_ms),
                maximum_interval_ms: self.maximum_teardown_interval_ms,
            });
        }
        let elapsed_ms = now_ms.saturating_sub(started_ms);
        if elapsed_ms > self.maximum_teardown_interval_ms {
            // Detachment is the bounded safety action.  We do not wait for the
            // native stop call and health reporting remains independently live.
            self.state = CaptureSessionState::RevokedTeardownDetached;
            return Ok(TeardownStatus {
                progress: TeardownProgress::Detached,
                elapsed_ms,
                maximum_interval_ms: self.maximum_teardown_interval_ms,
            });
        }
        match self
            .backend
            .poll_teardown(elapsed_ms)
            .map_err(CaptureError::from)?
        {
            BackendTeardownProgress::Complete => {
                self.state = CaptureSessionState::RevokedTeardownComplete;
                Ok(TeardownStatus {
                    progress: TeardownProgress::Complete,
                    elapsed_ms,
                    maximum_interval_ms: self.maximum_teardown_interval_ms,
                })
            }
            BackendTeardownProgress::Pending => Ok(TeardownStatus {
                progress: TeardownProgress::Pending,
                elapsed_ms,
                maximum_interval_ms: self.maximum_teardown_interval_ms,
            }),
        }
    }

    fn teardown_status(&self, now_ms: u64) -> Result<TeardownStatus, CaptureError> {
        let Some(started_ms) = self.teardown_started_ms else {
            return Err(CaptureError::TeardownInProgress);
        };
        let progress = match self.state {
            CaptureSessionState::RevokedTeardownComplete => TeardownProgress::Complete,
            CaptureSessionState::RevokedTeardownDetached => TeardownProgress::Detached,
            _ => TeardownProgress::Pending,
        };
        Ok(TeardownStatus {
            progress,
            elapsed_ms: now_ms.saturating_sub(started_ms),
            maximum_interval_ms: self.maximum_teardown_interval_ms,
        })
    }

    /// A broad grant is an explicit capability input.  No scoped request calls
    /// this method and no scoped failure is allowed to create one implicitly.
    pub fn grant_broad_display(&mut self, grant: BroadDisplayGrant) -> Result<(), CaptureError> {
        if grant.grant_id.trim().is_empty() {
            return Err(CaptureError::InvalidGrant);
        }
        self.broad_display_grant = Some(grant);
        Ok(())
    }

    pub fn revoke_broad_display(&mut self) {
        self.broad_display_grant = None;
    }

    pub fn capture_display(
        &mut self,
        request: BroadDisplayCaptureRequest,
    ) -> Result<BroadDisplayCaptureResult, CaptureError> {
        match self.backend.screen_recording_liveness() {
            PermissionLiveness::Live => {}
            PermissionLiveness::GrantedPendingRelaunch => {
                return Err(CaptureError::PermissionPendingRelaunch)
            }
            PermissionLiveness::Unavailable | PermissionLiveness::Unresolved => {
                return Err(CaptureError::PermissionUnavailable)
            }
        }
        let grant = self
            .broad_display_grant
            .as_ref()
            .ok_or(CaptureError::BroadCaptureGrantRequired)?;
        let artifact = self
            .backend
            .capture_display(&request)
            .map_err(CaptureError::from)?;
        Ok(BroadDisplayCaptureResult {
            captured_at_ms: request.captured_at_ms,
            artifact,
            leakage: CaptureLeakageReport::broad(request.include_cursor),
            broad_grant_id: grant.grant_id.clone(),
        })
    }

    /// Health reporting is intentionally a local snapshot.  It does not poll
    /// or join the native teardown path, so a revoked stream cannot block it.
    pub fn health_snapshot(&self) -> CaptureHealthSnapshot {
        CaptureHealthSnapshot {
            state: self.state,
            teardown_in_flight: self.state == CaptureSessionState::RevokedTeardownPending,
            frames_enabled: self.state == CaptureSessionState::Active
                || self.state == CaptureSessionState::NotStarted,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptureHealthSnapshot {
    pub state: CaptureSessionState,
    pub teardown_in_flight: bool,
    pub frames_enabled: bool,
}

/// A deterministic backend used by conformance tests and by platform adapters
/// while ScreenCaptureKit bindings are unavailable on the host.
#[derive(Debug, Clone)]
pub struct InMemoryCaptureBackend {
    permission: PermissionLiveness,
    windows: Vec<EnumeratedWindow>,
    changes: VecDeque<WindowChange>,
    artifacts: BTreeMap<String, CaptureArtifact>,
    display_artifact: CaptureArtifact,
    window_requests: Vec<WindowCaptureRequest>,
    display_requests: Vec<BroadDisplayCaptureRequest>,
    teardown_behavior: TeardownBehavior,
    teardown_started: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TeardownBehavior {
    CompleteImmediately,
    CompleteAfter(u64),
    NeverCompletes,
}

impl Default for InMemoryCaptureBackend {
    fn default() -> Self {
        Self {
            permission: PermissionLiveness::Live,
            windows: Vec::new(),
            changes: VecDeque::new(),
            artifacts: BTreeMap::new(),
            display_artifact: CaptureArtifact::Bytes(Vec::new()),
            window_requests: Vec::new(),
            display_requests: Vec::new(),
            teardown_behavior: TeardownBehavior::CompleteImmediately,
            teardown_started: false,
        }
    }
}

impl InMemoryCaptureBackend {
    pub fn set_permission_liveness(&mut self, permission: PermissionLiveness) {
        self.permission = permission;
    }

    pub fn set_windows(&mut self, windows: Vec<EnumeratedWindow>) {
        self.windows = windows;
    }

    pub fn announce_window_change(&mut self, kind: WindowChangeKind, observed_at_ms: u64) {
        self.changes.push_back(WindowChange {
            kind,
            observed_at_ms,
        });
    }

    pub fn set_window_artifact(&mut self, window_id: impl Into<String>, artifact: CaptureArtifact) {
        self.artifacts.insert(window_id.into(), artifact);
    }

    pub fn set_display_artifact(&mut self, artifact: CaptureArtifact) {
        self.display_artifact = artifact;
    }

    pub fn set_teardown_behavior(&mut self, behavior: TeardownBehavior) {
        self.teardown_behavior = behavior;
    }

    pub fn window_requests(&self) -> &[WindowCaptureRequest] {
        &self.window_requests
    }

    pub fn display_requests(&self) -> &[BroadDisplayCaptureRequest] {
        &self.display_requests
    }

    pub fn teardown_started(&self) -> bool {
        self.teardown_started
    }
}

impl CaptureBackend for InMemoryCaptureBackend {
    fn screen_recording_liveness(&self) -> PermissionLiveness {
        self.permission
    }

    fn enumerate_windows(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        Ok(self.windows.clone())
    }

    fn poll_window_change(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError> {
        Ok(self.changes.pop_front())
    }

    fn capture_window(
        &mut self,
        request: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError> {
        if request.filter.include_cursor {
            return Err(BackendError::Capture(
                "scoped window filter requested cursor compositing".into(),
            ));
        }
        self.window_requests.push(request.clone());
        let window = self
            .windows
            .iter()
            .find(|window| window.window_id == request.filter.window_id)
            .ok_or_else(|| BackendError::Capture("window no longer exists".into()))?;
        let artifact = self
            .artifacts
            .get(&window.window_id)
            .cloned()
            .unwrap_or_else(|| CaptureArtifact::Bytes(Vec::new()));
        let (frame, artifact) = match request.region {
            Some(region) => (
                WindowFrame {
                    x: window.frame.x.saturating_add(region.x_px as i32),
                    y: window.frame.y.saturating_add(region.y_px as i32),
                    width: region.width_px,
                    height: region.height_px,
                },
                honour_capture_region(artifact, window.frame, region)?,
            ),
            None => (window.frame, artifact),
        };
        Ok(WindowCaptureFrame {
            owner_identity: window.owner_identity.clone(),
            owner_identity_verified: window.owner_identity_verified,
            frame,
            captured_at_ms: request.captured_at_ms,
            artifact,
            accessibility_root: window.accessibility_root.clone(),
        })
    }

    fn capture_display(
        &mut self,
        request: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        self.display_requests.push(request.clone());
        Ok(self.display_artifact.clone())
    }

    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError> {
        self.teardown_started = true;
        Ok(match self.teardown_behavior {
            TeardownBehavior::CompleteImmediately => BackendTeardownProgress::Complete,
            TeardownBehavior::CompleteAfter(_) | TeardownBehavior::NeverCompletes => {
                BackendTeardownProgress::Pending
            }
        })
    }

    fn poll_teardown(&mut self, elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError> {
        Ok(match self.teardown_behavior {
            TeardownBehavior::CompleteImmediately => BackendTeardownProgress::Complete,
            TeardownBehavior::CompleteAfter(after_ms) if elapsed_ms >= after_ms => {
                BackendTeardownProgress::Complete
            }
            TeardownBehavior::CompleteAfter(_) | TeardownBehavior::NeverCompletes => {
                BackendTeardownProgress::Pending
            }
        })
    }
}

fn honour_capture_region(
    artifact: CaptureArtifact,
    window: WindowFrame,
    region: WindowCaptureRegion,
) -> Result<CaptureArtifact, BackendError> {
    let CaptureArtifact::Bytes(bytes) = artifact else {
        return Ok(artifact);
    };
    let expected = (window.width as usize)
        .checked_mul(window.height as usize)
        .and_then(|pixels| pixels.checked_mul(4));
    if expected == Some(bytes.len()) {
        let right = region
            .x_px
            .checked_add(region.width_px)
            .filter(|right| *right <= window.width);
        let bottom = region
            .y_px
            .checked_add(region.height_px)
            .filter(|bottom| *bottom <= window.height);
        if right.is_none() || bottom.is_none() {
            return Err(BackendError::Capture(
                "window-local capture region lies outside the window".into(),
            ));
        }
        let stride = window.width as usize * 4;
        let row_bytes = region.width_px as usize * 4;
        let mut cropped = Vec::with_capacity(row_bytes * region.height_px as usize);
        for row in 0..region.height_px as usize {
            let start = (region.y_px as usize + row) * stride + region.x_px as usize * 4;
            cropped.extend_from_slice(&bytes[start..start + row_bytes]);
        }
        return Ok(CaptureArtifact::Bytes(cropped));
    }
    // An in-memory fixture may use encoded bytes that cannot be cropped here.
    // Preserve the region dimensions without relabelling the original image.
    Ok(CaptureArtifact::Bytes(vec![
        0;
        region.width_px as usize
            * region.height_px as usize
            * 4
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target() -> ProcessGrant {
        ProcessGrant {
            pid: 42,
            bundle_identity: "com.example.target".into(),
            process_generation_evidence: "generation-1".into(),
        }
    }

    fn window(id: &str, owner: &ProcessGrant, verified: bool) -> EnumeratedWindow {
        EnumeratedWindow {
            window_id: id.into(),
            owner_identity: owner.clone(),
            owner_identity_verified: verified,
            frame: WindowFrame {
                x: 0,
                y: 0,
                width: 100,
                height: 100,
            },
            accessibility_root: Some(format!("root-{id}")),
        }
    }

    /// Map a backend screen-locked failure to the distinct capture error so callers can
    /// recognize that unlocking the screen may resolve it.
    #[test]
    fn a_locked_backend_error_reaches_capture_callers_as_screen_is_locked() {
        assert_eq!(
            CaptureError::from(BackendError::ScreenLocked),
            CaptureError::ScreenIsLocked
        );
        assert_eq!(
            CaptureError::from(BackendError::Capture("window no longer exists".into())),
            CaptureError::Backend("window no longer exists".into())
        );
    }

    #[test]
    fn scoped_capture_filters_identity_per_window_and_disables_cursor() {
        let target = target();
        let other = ProcessGrant {
            pid: 43,
            bundle_identity: "com.example.other".into(),
            process_generation_evidence: "generation-other".into(),
        };
        let mut backend = InMemoryCaptureBackend::default();
        backend.set_windows(vec![
            window("target", &target, true),
            window("other", &other, true),
            window("unverified", &target, false),
        ]);
        let mut controller = ScopedCaptureController::with_v1_bounds(backend, target).unwrap();
        let result = controller.capture_scoped(100).unwrap();
        assert_eq!(result.windows.len(), 1);
        assert_eq!(result.windows[0].window_id, "target");
        assert!(
            !result.windows[0].desktop_independent_filter
                || result.cursor_compositing == LeakageValue::Absent
        );
        assert_eq!(result.leakage.cursor_composited, LeakageValue::Absent);
        assert_eq!(
            result.leakage.display_dependent_composition,
            LeakageValue::Absent
        );
        assert_eq!(result.leakage_flags().len(), CaptureLeakageFlag::ALL.len());
        assert!(controller
            .backend()
            .window_requests()
            .iter()
            .all(|request| !request.filter.include_cursor));
    }

    #[test]
    fn reenumeration_tracks_generation_and_bound_violation() {
        let target = target();
        let mut backend = InMemoryCaptureBackend::default();
        backend.set_windows(vec![window("one", &target, true)]);
        let mut controller =
            ScopedCaptureController::new(backend, target.clone(), 50, 1_000).unwrap();
        let first = controller.capture_scoped(100).unwrap();
        assert_eq!(first.enumeration_generation, 1);

        controller.backend_mut().set_windows(vec![
            window("one", &target, true),
            window("two", &target, true),
        ]);
        controller
            .backend_mut()
            .announce_window_change(WindowChangeKind::Created, 100);
        let second = controller.capture_scoped(120).unwrap();
        assert!(second.reenumeration_occurred);
        assert_eq!(second.measured_reenumeration_interval_ms, Some(20));
        assert_eq!(second.enumeration_generation, 2);
        assert_eq!(second.windows.len(), 2);
        assert_eq!(second.window_enumeration_incomplete(), LeakageValue::Absent);

        controller
            .backend_mut()
            .announce_window_change(WindowChangeKind::Closed, 120);
        let third = controller.capture_scoped(200).unwrap();
        assert_eq!(third.enumeration_generation, 3);
        assert_eq!(third.measured_reenumeration_interval_ms, Some(80));
        assert_eq!(third.window_enumeration_incomplete(), LeakageValue::Present);
    }

    #[test]
    fn broad_capture_requires_its_own_grant() {
        let target = target();
        let mut controller =
            ScopedCaptureController::with_v1_bounds(InMemoryCaptureBackend::default(), target)
                .unwrap();
        let request = BroadDisplayCaptureRequest {
            include_cursor: true,
            captured_at_ms: 10,
        };
        assert_eq!(
            controller.capture_display(request.clone()).unwrap_err(),
            CaptureError::BroadCaptureGrantRequired
        );
        controller
            .grant_broad_display(BroadDisplayGrant::new("broad-1").unwrap())
            .unwrap();
        let result = controller.capture_display(request).unwrap();
        assert_eq!(
            result.leakage.display_dependent_composition,
            LeakageValue::Present
        );
        assert_eq!(result.leakage.cursor_composited, LeakageValue::Present);
        assert_eq!(controller.backend().display_requests().len(), 1);
    }

    #[test]
    fn permission_states_and_bounded_teardown_do_not_emit_frames() {
        let target = target();
        let mut backend = InMemoryCaptureBackend::default();
        backend.set_windows(vec![window("one", &target, true)]);
        let mut controller = ScopedCaptureController::with_v1_bounds(backend, target).unwrap();
        controller
            .backend_mut()
            .set_permission_liveness(PermissionLiveness::GrantedPendingRelaunch);
        assert_eq!(
            controller.capture_scoped(0).unwrap_err(),
            CaptureError::PermissionPendingRelaunch
        );
        assert_eq!(
            controller.state(),
            CaptureSessionState::PermissionPendingRelaunch
        );

        controller
            .backend_mut()
            .set_permission_liveness(PermissionLiveness::Live);
        controller.capture_scoped(1).unwrap();
        controller
            .backend_mut()
            .set_permission_liveness(PermissionLiveness::Unavailable);
        assert_eq!(
            controller.capture_scoped(2).unwrap_err(),
            CaptureError::PermissionUnavailable
        );
        assert!(!controller.health_snapshot().frames_enabled);

        let status = controller.poll_teardown(2).unwrap();
        assert_eq!(status.progress, TeardownProgress::Complete);
        assert!(controller.backend().teardown_started());
    }

    #[test]
    fn teardown_detaches_after_bound_without_health_join() {
        let target = target();
        let mut backend = InMemoryCaptureBackend::default();
        backend.set_windows(vec![window("one", &target, true)]);
        backend.set_teardown_behavior(TeardownBehavior::NeverCompletes);
        let mut controller = ScopedCaptureController::new(backend, target, 500, 10).unwrap();
        controller.capture_scoped(0).unwrap();
        let status = controller.on_permission_revoked(5).unwrap();
        assert_eq!(status.progress, TeardownProgress::Pending);
        let health = controller.health_snapshot();
        assert!(health.teardown_in_flight);
        assert!(!health.frames_enabled);
        let detached = controller.poll_teardown(16).unwrap();
        assert_eq!(detached.progress, TeardownProgress::Detached);
        assert!(!controller.health_snapshot().teardown_in_flight);
    }
}
