//! Windows UI Automation driver and an explicitly unsupported capture backend.
//!
//! Operating-system calls are confined to `cfg(target_os = "windows")` blocks.
//! The decisions made from their readings remain ordinary Rust so every host can
//! exercise the fail-closed policy.

use super::*;
use crate::capture::{
    BackendError, BackendTeardownProgress, BroadDisplayCaptureRequest, CaptureArtifact,
    CaptureBackend, EnumeratedWindow, WindowCaptureFrame, WindowCaptureRequest, WindowChange,
};
use std::collections::BTreeMap;

pub const WINDOWS_ACTUATION_UNREVIEWED: &str = "windows_actuation_unreviewed";
const UIA_ROLE_PREFIX: &str = "uia_control_type:";

/// A capture backend whose type makes Windows capture absence explicit.
#[derive(Debug, Default, Clone, Copy)]
pub struct WindowsUnsupportedCaptureBackend;

impl CaptureBackend for WindowsUnsupportedCaptureBackend {
    fn platform_support(&self) -> Result<(), BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn screen_recording_liveness(&self) -> PermissionLiveness {
        PermissionLiveness::Unresolved
    }

    fn enumerate_windows(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn poll_window_change(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn capture_window(
        &mut self,
        _request: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn capture_display(
        &mut self,
        _request: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }

    fn poll_teardown(&mut self, _elapsed_ms: u64) -> Result<BackendTeardownProgress, BackendError> {
        Err(BackendError::UnsupportedOnPlatform)
    }
}

#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsSessionProvenance {
    Console {
        session_id: u32,
    },
    OtherSession {
        session_id: u32,
        console_session_id: u32,
    },
    NoConsoleSession {
        session_id: u32,
    },
    Unreadable {
        last_error: u32,
    },
    NotApplicable,
}

#[cfg(target_os = "windows")]
impl From<cerebellum_windows::SessionProvenance> for WindowsSessionProvenance {
    fn from(value: cerebellum_windows::SessionProvenance) -> Self {
        match value {
            cerebellum_windows::SessionProvenance::Console { session_id } => {
                Self::Console { session_id }
            }
            cerebellum_windows::SessionProvenance::OtherSession {
                session_id,
                console_session_id,
            } => Self::OtherSession {
                session_id,
                console_session_id,
            },
            cerebellum_windows::SessionProvenance::NoConsoleSession { session_id } => {
                Self::NoConsoleSession { session_id }
            }
            cerebellum_windows::SessionProvenance::Unreadable { last_error } => {
                Self::Unreadable { last_error }
            }
            cerebellum_windows::SessionProvenance::NotApplicable => Self::NotApplicable,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsWindowVisibility {
    Visible,
    NotVisible,
    Unknown,
}

#[cfg(target_os = "windows")]
impl From<cerebellum_windows::WindowVisibility> for WindowsWindowVisibility {
    fn from(value: cerebellum_windows::WindowVisibility) -> Self {
        match value {
            cerebellum_windows::WindowVisibility::Visible => Self::Visible,
            cerebellum_windows::WindowVisibility::NotVisible => Self::NotVisible,
            cerebellum_windows::WindowVisibility::Unknown => Self::Unknown,
        }
    }
}

/// Resolve an executable basename against a Windows top-level window reading.
///
/// On macOS a caller names a bundle identifier (`com.apple.TextEdit`). On
/// Windows the same caller names an executable basename (`notepad.exe`).
/// Windows has no bundle identifier; the two identities are deliberately
/// asymmetric. UWP frame windows may be owned by `ApplicationFrameHost.exe`
/// while the content process is the app's own executable; which identity a
/// caller must use for those apps is unmeasured.
///
/// Session provenance is gated before [`TargetResolution::decide`] so a
/// service-session empty list is not reported as the application being absent.
fn resolve_from_reading<F: FnOnce(u32) -> Option<String>>(
    executable_basename: &str,
    session: WindowsSessionProvenance,
    windows: Option<&[(u32, String)]>,
    unreadable_owners: usize,
    read_generation: F,
) -> Result<TargetResolution, DriverError> {
    require_console_session(session)?;
    let resolution = TargetResolution::decide(executable_basename, windows, read_generation);
    // A window whose owner could not be opened is absent from `windows`, so
    // "nothing named that" was decided over a list known to be short. The
    // missing window may be the one the caller means. Resolved and Ambiguous
    // stand -- they were found in what WAS read -- but NotRunning would claim
    // absence about processes this reading could not see.
    if unreadable_owners > 0 && matches!(resolution, TargetResolution::NotRunning) {
        return Ok(TargetResolution::Unreadable(
            UnreadableReason::PartialWindowList { unreadable_owners },
        ));
    }
    Ok(resolution)
}

/// Resolve an executable basename against this machine's top-level windows.
///
/// Gathers the window-owner reading, refuses a non-console session before
/// treating an empty list as not running, and then calls
/// [`TargetResolution::decide`]. Generation evidence is the process creation
/// `FILETIME` from [`cerebellum_windows::process_start_time`].
#[cfg(target_os = "windows")]
pub fn resolve_target(executable_basename: &str) -> TargetResolution {
    let reading = match cerebellum_windows::enumerate_top_level_windows() {
        Ok(reading) => reading,
        Err(_) => return TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable),
    };
    let named: Vec<(u32, String)> = reading
        .windows
        .iter()
        .filter_map(|window| match window {
            cerebellum_windows::TopLevelWindowOwner::Named {
                pid,
                executable_basename,
            } => Some((*pid, executable_basename.clone())),
            cerebellum_windows::TopLevelWindowOwner::Unreadable(_) => None,
        })
        .collect();
    let unreadable_owners = match reading.completeness {
        cerebellum_windows::WindowListCompleteness::Complete => 0,
        cerebellum_windows::WindowListCompleteness::Partial { unreadable_owners } => {
            unreadable_owners
        }
    };
    match resolve_from_reading(
        executable_basename,
        reading.session.into(),
        Some(named.as_slice()),
        unreadable_owners,
        |pid| match cerebellum_windows::process_start_time(pid) {
            cerebellum_windows::ProcessStartTime::Started(started) => Some(started.to_string()),
            cerebellum_windows::ProcessStartTime::NoSuchProcess
            | cerebellum_windows::ProcessStartTime::AccessDenied
            | cerebellum_windows::ProcessStartTime::Unclassified(_) => None,
        },
    ) {
        Ok(resolution) => resolution,
        // The only error `resolve_from_reading` produces is the session
        // refusal, and its remedy is "log in at the console", which the
        // generic word would have hidden behind a macOS permission hint.
        Err(DriverError::SessionNotInspectable(SessionProvenanceRefusal::OtherSession {
            session_id,
            console_session_id,
        })) => TargetResolution::Unreadable(UnreadableReason::SessionNotInteractive {
            session_id,
            console_session_id,
        }),
        Err(DriverError::SessionNotInspectable(SessionProvenanceRefusal::NoConsoleSession {
            session_id,
        })) => TargetResolution::Unreadable(UnreadableReason::NoConsoleSession { session_id }),
        Err(_) => TargetResolution::Unreadable(UnreadableReason::WindowListUnavailable),
    }
}

/// Everything a semantic dispatch decides before the platform is asked to do
/// anything, in the order it decides it, with the platform calls handed in.
///
/// The order is the property: PROVENANCE, then LIVENESS, then the intent, then
/// the invoke. Provenance first because a tree read from a service session
/// succeeds and describes this module's own desktop -- an element resolved
/// from it uniquely and correctly still names a control the user cannot see,
/// and invoking it would act on the wrong desktop with every other check
/// satisfied. So the refusal must land before resolution or liveness get a
/// say, and `invoke` must not have run. The platform calls arrive as closures
/// so this ordering compiles and is tested on every host; the FFI that fills
/// them compiles only on Windows.
fn dispatch_semantic_in_order<R, I>(
    session: WindowsSessionProvenance,
    request: &SemanticDispatchRequest,
    retain: R,
    invoke: I,
) -> Result<DispatchResult, DriverError>
where
    R: FnOnce(&ProcessGrant) -> Result<(), DriverError>,
    I: FnOnce(
        &ProcessGrant,
        &AccessibilityElementName,
        SemanticActionIntent,
    ) -> Result<DispatchResult, DriverError>,
{
    require_console_session(session)?;
    retain(&request.element.owning_process)?;
    let intent = SemanticActionIntent::from_wire_name(&request.action).ok_or(
        DriverError::InvalidRequest("unknown semantic action intent"),
    )?;
    let _delivered_action = delivered_semantic_action(SemanticActionPlatform::Windows, intent)
        .map_err(|refusal| {
            DriverError::Semantic(SemanticDriverError::ActionUnsupported {
                intent: refusal.intent,
                platform: refusal.platform,
            })
        })?;
    invoke(
        &request.element.owning_process,
        &request.element.element_name,
        intent,
    )
}

fn require_console_session(session: WindowsSessionProvenance) -> Result<(), DriverError> {
    match session {
        WindowsSessionProvenance::Console { .. } => Ok(()),
        WindowsSessionProvenance::OtherSession {
            session_id,
            console_session_id,
        } => Err(DriverError::SessionNotInspectable(
            SessionProvenanceRefusal::OtherSession {
                session_id,
                console_session_id,
            },
        )),
        WindowsSessionProvenance::NoConsoleSession { session_id } => {
            Err(DriverError::SessionNotInspectable(
                SessionProvenanceRefusal::NoConsoleSession { session_id },
            ))
        }
        WindowsSessionProvenance::Unreadable { last_error } => Err(
            DriverError::SessionNotInspectable(SessionProvenanceRefusal::Unreadable { last_error }),
        ),
        WindowsSessionProvenance::NotApplicable => Err(DriverError::SessionNotInspectable(
            SessionProvenanceRefusal::NotApplicable,
        )),
    }
}

fn require_enumerable_visibility(
    pid: u32,
    visibility: WindowsWindowVisibility,
) -> Result<(), DriverError> {
    match visibility {
        WindowsWindowVisibility::Visible | WindowsWindowVisibility::NotVisible => Ok(()),
        // `Unknown` commonly describes a UWP process that owns no EnumWindows
        // entry. This result type has nowhere to carry that third state, so the
        // driver refuses instead of relabelling it as a hidden window.
        WindowsWindowVisibility::Unknown => Err(DriverError::WindowVisibilityUnknown { pid }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsElement {
    process_id: u32,
    automation_id: Option<String>,
    control_type: i32,
    name: String,
    enabled: bool,
    focused: bool,
    children: Vec<WindowsElement>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct WindowsTreeReading {
    session: WindowsSessionProvenance,
    roots: Vec<WindowsElement>,
    unreadable_subtrees: usize,
}

#[derive(Debug, Clone)]
struct CachedWindowsTree {
    target: ProcessGrant,
    roots: Vec<WindowsElement>,
    unreadable_subtrees: usize,
}

fn root_cache_key(target: &ProcessGrant) -> String {
    format!(
        "windows-accessibility-root:{}:{}",
        target.pid, target.process_generation_evidence
    )
}

fn admit_tree_reading(
    target: &ProcessGrant,
    visibility: WindowsWindowVisibility,
    reading: WindowsTreeReading,
) -> Result<(String, CachedWindowsTree, AccessibilityTreeResult), DriverError> {
    // Provenance precedes every interpretation of the tree, including emptiness.
    // A service-session empty tree describes this module's desktop visibility,
    // not the target application's accessibility surface.
    require_console_session(reading.session)?;
    require_enumerable_visibility(target.pid, visibility)?;
    if reading.roots.is_empty() {
        return Err(AccessibilityReadFailure::TargetNotInspectable.into());
    }

    let root_identifier = root_cache_key(target);
    let child_count = u32::try_from(reading.roots.len()).unwrap_or(u32::MAX);
    let unreadable_subtrees = u64::try_from(reading.unreadable_subtrees).unwrap_or(u64::MAX);
    let result = AccessibilityTreeResult {
        root_identifier: Some(root_identifier.clone()),
        child_count,
        handshake_attempted: true,
        degenerate_reason: (reading.unreadable_subtrees > 0).then(|| {
            format!(
                "incomplete_accessibility_tree:{}_unreadable_subtrees",
                reading.unreadable_subtrees
            )
        }),
        unreadable_subtrees,
    };
    let cached = CachedWindowsTree {
        target: target.clone(),
        roots: reading.roots,
        unreadable_subtrees: reading.unreadable_subtrees,
    };
    Ok((root_identifier, cached, result))
}

fn control_type_role(control_type: i32) -> String {
    format!("{UIA_ROLE_PREFIX}{control_type}")
}

fn requested_control_type(role: &str) -> Option<i32> {
    role.strip_prefix(UIA_ROLE_PREFIX)?.parse().ok()
}

fn element_matches(element: &WindowsElement, name: &AccessibilityElementName) -> bool {
    match name {
        AccessibilityElementName::Identifier(identifier) => {
            element.automation_id.as_deref() == Some(identifier)
        }
        AccessibilityElementName::RoleAndTitle { role, title } => {
            requested_control_type(role) == Some(element.control_type) && element.name == *title
        }
    }
}

fn collect_matches<'a>(
    elements: &'a [WindowsElement],
    name: &AccessibilityElementName,
    matches: &mut Vec<&'a WindowsElement>,
) {
    for element in elements {
        if element_matches(element, name) {
            matches.push(element);
        }
        collect_matches(&element.children, name, matches);
    }
}

fn alternate_name(
    element: &WindowsElement,
    matched_by: &AccessibilityElementName,
) -> Option<AccessibilityElementName> {
    match matched_by {
        AccessibilityElementName::Identifier(_) => Some(AccessibilityElementName::RoleAndTitle {
            role: control_type_role(element.control_type),
            title: element.name.clone(),
        }),
        AccessibilityElementName::RoleAndTitle { .. } => element
            .automation_id
            .clone()
            .map(AccessibilityElementName::Identifier),
    }
}

fn matching_element<'a>(
    tree: &'a CachedWindowsTree,
    name: &AccessibilityElementName,
) -> Result<&'a WindowsElement, DriverError> {
    if !name.is_usable() {
        return Err(DriverError::InvalidRequest(
            "unusable accessibility element name",
        ));
    }
    let mut matches = Vec::new();
    collect_matches(&tree.roots, name, &mut matches);
    match matches.len() {
        0 => Err(DriverError::Semantic(
            SemanticDriverError::ElementNotFound {
                key_form: name.key_form(),
            },
        )),
        1 => Ok(matches[0]),
        match_count => Err(DriverError::Semantic(
            SemanticDriverError::ElementNameAmbiguous {
                key_form: name.key_form(),
                match_count: u64::try_from(match_count).unwrap_or(u64::MAX),
            },
        )),
    }
}

fn resolution_from_cached_tree(
    tree: &CachedWindowsTree,
    request: &ElementResolutionRequest,
) -> Result<ElementResolutionResult, DriverError> {
    let element = matching_element(tree, &request.element_name)?;
    Ok(ElementResolutionResult {
        element_name: request.element_name.clone(),
        alternate_name: alternate_name(element, &request.element_name),
        owning_process: tree.target.clone(),
        // UIA's Invoke pattern is checked again by the seam immediately before
        // invocation. This advertises only the neutral intent the driver knows
        // how to translate; it does not claim the handler will accept it.
        semantic_actions: vec![SemanticActionIntent::Press.wire_name().to_owned()],
        unreadable_subtrees: u64::try_from(tree.unreadable_subtrees).unwrap_or(u64::MAX),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsGrantVerification {
    Current,
    Gone,
    Replaced,
    Unreadable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WindowsProcessStartReading {
    Started(u64),
    Gone,
    Unreadable,
}

fn verify_process_generation(
    expected_generation: &str,
    reading: WindowsProcessStartReading,
) -> WindowsGrantVerification {
    match reading {
        WindowsProcessStartReading::Started(started)
            if started.to_string() == expected_generation =>
        {
            WindowsGrantVerification::Current
        }
        WindowsProcessStartReading::Started(_) => WindowsGrantVerification::Replaced,
        WindowsProcessStartReading::Gone => WindowsGrantVerification::Gone,
        WindowsProcessStartReading::Unreadable => WindowsGrantVerification::Unreadable,
    }
}

#[cfg(target_os = "windows")]
fn retain_current_target(
    target: &ProcessGrant,
) -> Result<cerebellum_windows::RetainedProcessHandle, WindowsGrantVerification> {
    use cerebellum_windows::{ProcessHandleError, ProcessStartTime};

    let retained =
        cerebellum_windows::retain_process_handle(target.pid).map_err(|error| match error {
            ProcessHandleError::NoSuchProcess => WindowsGrantVerification::Gone,
            ProcessHandleError::AccessDenied | ProcessHandleError::Unclassified(_) => {
                WindowsGrantVerification::Unreadable
            }
        })?;
    let reading = match cerebellum_windows::process_start_time(target.pid) {
        ProcessStartTime::Started(started) => WindowsProcessStartReading::Started(started),
        ProcessStartTime::NoSuchProcess => WindowsProcessStartReading::Gone,
        ProcessStartTime::AccessDenied | ProcessStartTime::Unclassified(_) => {
            WindowsProcessStartReading::Unreadable
        }
    };
    let verification = verify_process_generation(&target.process_generation_evidence, reading);
    match verification {
        WindowsGrantVerification::Current => Ok(retained),
        failure => Err(failure),
    }
}

#[cfg(target_os = "windows")]
fn accessibility_verification_error(verification: WindowsGrantVerification) -> DriverError {
    match verification {
        WindowsGrantVerification::Current => unreachable!("current verification is not an error"),
        WindowsGrantVerification::Gone => AccessibilityReadFailure::TargetGone.into(),
        WindowsGrantVerification::Replaced => AccessibilityReadFailure::TargetReplaced.into(),
        WindowsGrantVerification::Unreadable => {
            AccessibilityReadFailure::TargetNotInspectable.into()
        }
    }
}

#[cfg(target_os = "windows")]
fn semantic_verification_error(verification: WindowsGrantVerification) -> DriverError {
    let semantic = match verification {
        WindowsGrantVerification::Current => unreachable!("current verification is not an error"),
        WindowsGrantVerification::Gone => SemanticDriverError::TargetNoLongerCurrent {
            disposition: TargetDisposition::Gone,
        },
        WindowsGrantVerification::Replaced => SemanticDriverError::TargetNoLongerCurrent {
            disposition: TargetDisposition::Replaced,
        },
        WindowsGrantVerification::Unreadable => SemanticDriverError::PathUnavailable,
    };
    DriverError::Semantic(semantic)
}

#[cfg(target_os = "windows")]
fn map_read_failure(failure: cerebellum_windows::AccessibilityReadFailure) -> DriverError {
    let failure = match failure {
        cerebellum_windows::AccessibilityReadFailure::PermissionRequired => {
            AccessibilityReadFailure::PermissionRequired
        }
        cerebellum_windows::AccessibilityReadFailure::TargetGone => {
            AccessibilityReadFailure::TargetGone
        }
        cerebellum_windows::AccessibilityReadFailure::TargetReplaced => {
            AccessibilityReadFailure::TargetReplaced
        }
        cerebellum_windows::AccessibilityReadFailure::TargetNotInspectable => {
            AccessibilityReadFailure::TargetNotInspectable
        }
        cerebellum_windows::AccessibilityReadFailure::RetryableDeadlineExceeded => {
            AccessibilityReadFailure::RetryableDeadlineExceeded
        }
        cerebellum_windows::AccessibilityReadFailure::TreeExceedsBound => {
            AccessibilityReadFailure::TreeExceedsBound
        }
        cerebellum_windows::AccessibilityReadFailure::IncompatiblePlatformValue => {
            AccessibilityReadFailure::IncompatiblePlatformValue
        }
        cerebellum_windows::AccessibilityReadFailure::PlatformReadFailed => {
            AccessibilityReadFailure::PlatformReadFailed
        }
    };
    failure.into()
}

#[cfg(target_os = "windows")]
fn convert_element(element: cerebellum_windows::UiaElement) -> WindowsElement {
    WindowsElement {
        process_id: element.process_id,
        automation_id: element.identity.automation_id,
        control_type: element.identity.control_type_and_name.control_type,
        name: element.identity.control_type_and_name.name,
        enabled: element.enabled,
        focused: element.has_keyboard_focus,
        children: element.children.into_iter().map(convert_element).collect(),
    }
}

#[cfg(target_os = "windows")]
fn convert_tree(tree: cerebellum_windows::UiaAccessibilityTree) -> WindowsTreeReading {
    let unreadable_subtrees = match tree.completeness {
        cerebellum_windows::UiaTreeCompleteness::Complete => 0,
        cerebellum_windows::UiaTreeCompleteness::Incomplete {
            unreadable_subtrees,
        } => unreadable_subtrees,
    };
    WindowsTreeReading {
        session: tree.session.into(),
        roots: tree.roots.into_iter().map(convert_element).collect(),
        unreadable_subtrees,
    }
}

#[cfg(target_os = "windows")]
fn uia_element_name(
    name: &AccessibilityElementName,
) -> Result<cerebellum_windows::UiaElementName, DriverError> {
    match name {
        AccessibilityElementName::Identifier(identifier) if !identifier.is_empty() => Ok(
            cerebellum_windows::UiaElementName::automation_id(identifier.clone()),
        ),
        AccessibilityElementName::RoleAndTitle { role, title } => requested_control_type(role)
            .map(|control_type| {
                cerebellum_windows::UiaElementName::control_type_and_name(
                    control_type,
                    title.clone(),
                )
            })
            .ok_or(DriverError::InvalidRequest(
                "Windows accessibility role is not a UIA control type",
            )),
        _ => Err(DriverError::InvalidRequest(
            "unusable accessibility element name",
        )),
    }
}

#[cfg(target_os = "windows")]
fn map_invoke_error(
    error: cerebellum_windows::AccessibilityInvokeError,
    action: &str,
    deadline_ms: u64,
) -> DriverError {
    use cerebellum_windows::AccessibilityInvokeError;

    match error {
        AccessibilityInvokeError::Resolution(failure)
        | AccessibilityInvokeError::Invocation(failure) => match map_read_failure(failure) {
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PermissionRequired) => {
                DriverError::Semantic(SemanticDriverError::AccessibilityPermissionUnavailable)
            }
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TargetGone) => {
                semantic_verification_error(WindowsGrantVerification::Gone)
            }
            DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TargetReplaced) => {
                semantic_verification_error(WindowsGrantVerification::Replaced)
            }
            DriverError::AccessibilityUnreadable(
                AccessibilityReadFailure::RetryableDeadlineExceeded,
            ) => DriverError::Semantic(SemanticDriverError::Transient { deadline_ms }),
            _ => DriverError::Semantic(SemanticDriverError::PathUnavailable),
        },
        AccessibilityInvokeError::ElementNotFound { element_name } => {
            DriverError::Semantic(SemanticDriverError::ElementNotFound {
                key_form: match element_name {
                    cerebellum_windows::UiaElementName::AutomationId(_) => {
                        AccessibilityKeyForm::Identifier
                    }
                    cerebellum_windows::UiaElementName::ControlTypeAndName(_) => {
                        AccessibilityKeyForm::RoleAndTitle
                    }
                },
            })
        }
        AccessibilityInvokeError::ElementNameAmbiguous {
            element_name,
            match_count,
        } => DriverError::Semantic(SemanticDriverError::ElementNameAmbiguous {
            key_form: match element_name {
                cerebellum_windows::UiaElementName::AutomationId(_) => {
                    AccessibilityKeyForm::Identifier
                }
                cerebellum_windows::UiaElementName::ControlTypeAndName(_) => {
                    AccessibilityKeyForm::RoleAndTitle
                }
            },
            match_count: u64::try_from(match_count).unwrap_or(u64::MAX),
        }),
        AccessibilityInvokeError::InvokePatternUnavailable { .. } => {
            DriverError::Semantic(SemanticDriverError::ActionNotAdvertised {
                action: action.to_owned(),
                advertised: Vec::new(),
            })
        }
    }
}

fn accepted_invoke_result(unreadable_subtrees: usize) -> DispatchResult {
    DispatchResult {
        accepted_by_platform: true,
        effect_status: EffectStatus::EffectIndeterminate,
        unreadable_subtrees: u64::try_from(unreadable_subtrees).unwrap_or(u64::MAX),
        delivery_posts_returned: 0,
        delivery_generation_verifications: 0,
    }
}

/// Windows UI Automation implementation of `PlatformDriver`.
///
/// Accessibility reads and Invoke-pattern actions are implemented; capture and
/// synthetic input remain unavailable.
#[derive(Debug, Clone)]
pub struct WindowsPlatformDriver {
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    accessibility_trees: BTreeMap<String, CachedWindowsTree>,
    expected_post_condition_available: bool,
}

impl Default for WindowsPlatformDriver {
    fn default() -> Self {
        Self {
            accessibility_trees: BTreeMap::new(),
            expected_post_condition_available: true,
        }
    }
}

impl WindowsPlatformDriver {
    pub fn without_expected_post_condition(mut self) -> Self {
        self.expected_post_condition_available = false;
        self
    }

    pub fn declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        let mut declarations = super::capability_declarations(context, true);
        let windows_review_bound = context.inputs.windows_actuation_review_revision.is_some();
        let vocabulary_ready = context.inputs.vocabulary_ready();

        for declaration in &mut declarations {
            declaration.synthetic_background = SupportState::Unsupported;
            declaration.synthetic_observed =
                if declaration.dispatch_modes.contains(&DispatchMode::Observed) {
                    SupportState::ConsentGated
                } else {
                    SupportState::Unsupported
                };

            match declaration.capability_id.as_str() {
                "computer.wait" => {
                    declaration.advertised = windows_review_bound && vocabulary_ready;
                    declaration.suppression_reason = if !windows_review_bound {
                        Some(WINDOWS_ACTUATION_UNREVIEWED.to_owned())
                    } else if !vocabulary_ready {
                        Some("computer action vocabulary input unresolved".to_owned())
                    } else {
                        None
                    };
                }
                // The application-state reader is macOS accessibility; Windows
                // has none, and the Windows review never covered it.
                "computer.read_state" => {
                    declaration.advertised = false;
                    declaration.suppression_reason =
                        Some("no application-state reader on Windows".to_owned());
                }
                _ => {
                    // Consent-gated observed delivery cannot be used here, and
                    // Windows has no background synthetic path. Recompute
                    // `advertised` so only observations, supported semantic
                    // actions, or supported background synthetic actions remain.
                    // The accessibility-first rows are macOS-only, and the
                    // Windows review never covered them, so it admits none.
                    declaration.advertised = declaration.advertised
                        && (declaration.action_kind == ActionKind::Observe
                            || declaration.semantic_path == SupportState::Supported
                            || declaration.synthetic_background == SupportState::Supported);
                }
            }
        }
        declarations
    }
}

impl PlatformDriver for WindowsPlatformDriver {
    fn capability_declarations(
        &self,
        context: &CapabilityAdvertisementContext,
    ) -> Vec<CapabilityDeclaration> {
        self.declarations(context)
    }

    fn read_accessibility_tree(
        &mut self,
        request: AccessibilityTreeRequest,
    ) -> Result<AccessibilityTreeResult, DriverError> {
        request.target.validate()?;
        let timeout = Self::bounded_duration(u64::from(request.settle_interval_ms))?;

        #[cfg(target_os = "windows")]
        {
            require_console_session(cerebellum_windows::current_session_provenance().into())?;
            // Liveness before visibility. A process that has exited has no
            // enumerable window either, so checking visibility first reports a
            // dead target as "visibility unknown" -- which a caller reads as a
            // UWP application with no window rather than as a process that is
            // gone. Measured on the VM: pressing Close through this driver and
            // reading again said visibility-unknown where the seam's own probe
            // said TargetGone for the same process.
            //
            // The retained handle also pins the process object during the read.
            // It cannot travel in `ProcessGrant`, so the driver still rechecks the
            // grant's start time at each operation boundary.
            let _retained =
                retain_current_target(&request.target).map_err(accessibility_verification_error)?;
            let visibility: WindowsWindowVisibility =
                cerebellum_windows::enumerated_window_visibility(request.target.pid).into();
            require_enumerable_visibility(request.target.pid, visibility)?;
            let tree = cerebellum_windows::read_accessibility_tree(
                request.target.pid,
                cerebellum_windows::AccessibilityReadBounds {
                    timeout,
                    ..Default::default()
                },
            )
            .map_err(map_read_failure)?;
            let (root, cached, result) =
                admit_tree_reading(&request.target, visibility, convert_tree(tree))?;
            self.accessibility_trees.insert(root, cached);
            Ok(result)
        }

        #[cfg(not(target_os = "windows"))]
        {
            let _ = timeout;
            Err(DriverError::Unsupported("Windows accessibility tree read"))
        }
    }

    fn read_accessibility_element(
        &mut self,
        request: AccessibilityElementReadRequest,
    ) -> Result<AccessibilityElementReadResult, DriverError> {
        request.target.validate()?;
        let _ = Self::bounded_duration(u64::from(request.deadline_ms))?;
        #[cfg(target_os = "windows")]
        {
            let tree = self.read_accessibility_tree(AccessibilityTreeRequest {
                target: request.target,
                settle_interval_ms: request.deadline_ms,
            })?;
            let root = tree.root_identifier.ok_or(DriverError::ElementNotFound)?;
            let cached = self
                .accessibility_trees
                .get(&root)
                .ok_or(DriverError::ElementNotFound)?;
            let mut matches = Vec::new();
            collect_matches(&cached.roots, &request.element_name, &mut matches);
            if matches.len() > 1 {
                return Err(DriverError::Semantic(
                    SemanticDriverError::ElementNameAmbiguous {
                        key_form: request.element_name.key_form(),
                        match_count: u64::try_from(matches.len()).unwrap_or(u64::MAX),
                    },
                ));
            }
            let Some(element) = matches.first().copied() else {
                return Ok(AccessibilityElementReadResult {
                    element_name: request.element_name,
                    present: false,
                    focused: None,
                    enabled: None,
                    value: None,
                });
            };
            let (focused, enabled) = match request.attribute {
                AccessibilityReadbackAttribute::Presence => (None, None),
                AccessibilityReadbackAttribute::Focused => (Some(element.focused), None),
                AccessibilityReadbackAttribute::Enabled => (None, Some(element.enabled)),
                AccessibilityReadbackAttribute::Value => {
                    return Err(DriverError::Unsupported("Windows UIA value readback"))
                }
            };
            Ok(AccessibilityElementReadResult {
                element_name: request.element_name,
                present: true,
                focused,
                enabled,
                value: None,
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = request;
            Err(DriverError::Unsupported(
                "Windows scoped accessibility read",
            ))
        }
    }

    fn resolve_element(
        &mut self,
        request: ElementResolutionRequest,
    ) -> Result<ElementResolutionResult, DriverError> {
        #[cfg(target_os = "windows")]
        {
            let cached = self
                .accessibility_trees
                .get(&request.root_identifier)
                .ok_or(DriverError::ElementNotFound)?;
            let _retained =
                retain_current_target(&cached.target).map_err(accessibility_verification_error)?;
            resolution_from_cached_tree(cached, &request)
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("Windows element resolution"))
        }
    }

    fn dispatch_semantic(
        &mut self,
        request: SemanticDispatchRequest,
    ) -> Result<DispatchResult, DriverError> {
        #[cfg(target_os = "windows")]
        {
            dispatch_semantic_in_order(
                cerebellum_windows::current_session_provenance().into(),
                &request,
                |target| {
                    retain_current_target(target)
                        .map(|_retained| ())
                        .map_err(semantic_verification_error)
                },
                |target, element_name, _intent| {
                    let element_name = uia_element_name(element_name)?;
                    let bounds = cerebellum_windows::AccessibilityInvokeBounds::default();
                    let deadline_ms = u64::try_from(bounds.timeout.as_millis()).unwrap_or(u64::MAX);
                    let outcome = cerebellum_windows::invoke_accessibility_element(
                        target.pid,
                        &element_name,
                        bounds,
                    )
                    .map_err(|error| map_invoke_error(error, &request.action, deadline_ms))?;
                    match outcome {
                        cerebellum_windows::AccessibilityInvokeOutcome::HandlerReturned {
                            unreadable_subtrees,
                            ..
                        } => Ok(accepted_invoke_result(unreadable_subtrees)),
                    }
                },
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("Windows semantic dispatch"))
        }
    }

    fn dispatch_per_pid(
        &mut self,
        _request: SyntheticDispatchRequest,
        // Windows synthetic delivery is unsupported; no post loop can ignore an interrupt.
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported(
            "Windows per-process synthetic dispatch",
        ))
    }

    fn dispatch_global(
        &mut self,
        _request: GlobalDispatchRequest,
        // Windows synthetic delivery is unsupported; no post loop can ignore an interrupt.
        _cancelled: &dyn Fn() -> bool,
    ) -> Result<DispatchResult, DriverError> {
        Err(DriverError::Unsupported(
            "Windows global synthetic dispatch",
        ))
    }

    fn query_focus(
        &mut self,
        _request: FocusQueryRequest,
    ) -> Result<FocusQueryResult, DriverError> {
        Err(DriverError::Unsupported("Windows focus query"))
    }

    fn fronting_snapshot(
        &mut self,
        _target: &ProcessGrant,
    ) -> Result<FrontingSnapshot, DriverError> {
        Err(DriverError::Unsupported("Windows fronting snapshot"))
    }

    fn input_observer_liveness(&self) -> InputObserverLiveness {
        InputObserverLiveness {
            session_tap_live: false,
            raw_hid_live: false,
            self_echo_filter_live: false,
        }
    }

    fn observe_input(
        &mut self,
        _request: InputObservationRequest,
    ) -> Result<InputObservationResult, DriverError> {
        Err(DriverError::Unsupported("Windows input observation"))
    }

    fn observe_effect(
        &mut self,
        request: EffectObservationRequest,
    ) -> Result<EffectObservationResult, DriverError> {
        if !self.expected_post_condition_available {
            return Ok(EffectObservationResult {
                status: EffectStatus::EffectIndeterminate,
                failure_reason: Some("post_condition_undeclarable".to_owned()),
            });
        }
        #[cfg(target_os = "windows")]
        {
            use crate::dispatch::post_condition::{evaluate, ConditionOutcome, ObservedElement};
            use crate::dispatch::ExpectedPostCondition;

            let Ok(envelope) = serde_json::from_str::<ExpectedPostCondition>(&request.predicate)
            else {
                return Ok(EffectObservationResult {
                    status: EffectStatus::EffectIndeterminate,
                    failure_reason: Some("post_condition_undeclarable".to_owned()),
                });
            };
            let readback = match self.read_accessibility_element(AccessibilityElementReadRequest {
                target: request.target,
                element_name: envelope.condition.element().clone(),
                attribute: envelope.condition.readback_attribute(),
                deadline_ms: request.deadline_ms,
            }) {
                Ok(readback) => readback,
                Err(_) => {
                    return Ok(EffectObservationResult {
                        status: EffectStatus::EffectIndeterminate,
                        failure_reason: Some("observation_primitive_unavailable".to_owned()),
                    })
                }
            };
            let observed = ObservedElement {
                present: readback.present,
                focused: readback.focused,
                enabled: readback.enabled,
                value: readback.value,
            };
            let status = match evaluate(&envelope.condition, &observed) {
                ConditionOutcome::Satisfied => EffectStatus::EffectObserved,
                ConditionOutcome::Unsatisfied => EffectStatus::NoEffectObserved,
                ConditionOutcome::Indeterminate => EffectStatus::EffectIndeterminate,
            };
            Ok(EffectObservationResult {
                status,
                failure_reason: (status == EffectStatus::EffectIndeterminate)
                    .then(|| "post_condition_undeclarable".to_owned()),
            })
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = request;
            Err(DriverError::Unsupported("Windows effect observation"))
        }
    }

    fn verify_attendance(
        &mut self,
        request: AttendancePreconditionRequest,
    ) -> Result<AttendancePreconditionResult, DriverError> {
        request.target.validate()?;
        #[cfg(target_os = "windows")]
        let valid = retain_current_target(&request.target).is_ok();
        #[cfg(not(target_os = "windows"))]
        let valid = false;
        Ok(AttendancePreconditionResult {
            valid,
            lease_generation: None,
            age_ms: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::containment::{
        finalize_input_containment, ContainmentRung, DeliveryPrimitive,
    };

    fn permissions() -> PermissionLivenessReport {
        PermissionLivenessReport::from_results(
            [
                PermissionService::ScreenRecording,
                PermissionService::Accessibility,
                PermissionService::PostEvent,
                PermissionService::InputMonitoring,
            ]
            .into_iter()
            .map(|service| PermissionProbeResult {
                service,
                liveness: PermissionLiveness::Live,
                responsible_process: "fixture".to_owned(),
                off_main: true,
            }),
        )
    }

    fn fully_bound_inputs() -> ImmutableReleaseInputs {
        let digest = COMPUTER_ACTION_VOCABULARY_SHA256.to_owned();
        ImmutableReleaseInputs {
            attendance_contract_owner: Some("fixture-owner".to_owned()),
            attendance_contract_revision: Some("fixture-attendance".to_owned()),
            input_review_revision: Some("fixture-input".to_owned()),
            global_dispatch_review_revision: Some("fixture-global-review".to_owned()),
            capture_review_revision: Some("fixture-capture".to_owned()),
            semantic_actuation_review_revision: Some("fixture-macos-semantic".to_owned()),
            app_state_review_revision: Some("fixture-app-state-review".to_owned()),
            windows_actuation_review_revision: Some("fixture-windows-actuation".to_owned()),
            release_signing_topology_revision: Some("fixture-signing".to_owned()),
            vocabulary_digests: VocabularyDigestInputs {
                manifest_digest: Some(digest.clone()),
                source_lock_digest: Some(digest.clone()),
                computed_artifact_digest: Some(digest),
            },
        }
    }

    fn context(inputs: ImmutableReleaseInputs) -> CapabilityAdvertisementContext {
        let permissions = permissions();
        CapabilityAdvertisementContext {
            inputs,
            permissions: permissions.clone(),
            startup: StartupCapabilityProbe {
                permissions,
                ..Default::default()
            },
        }
    }

    fn advertised(context: &CapabilityAdvertisementContext) -> Vec<String> {
        WindowsPlatformDriver::default()
            .declarations(context)
            .into_iter()
            .filter(|declaration| declaration.advertised)
            .map(|declaration| declaration.capability_id)
            .collect()
    }

    #[test]
    fn fully_reviewed_windows_advertises_only_wait() {
        assert_eq!(
            advertised(&context(fully_bound_inputs())),
            vec!["computer.wait"]
        );
    }

    #[test]
    fn macos_review_cannot_admit_windows_when_windows_review_is_unbound() {
        let mut inputs = fully_bound_inputs();
        inputs.windows_actuation_review_revision = None;
        let declarations = WindowsPlatformDriver::default().declarations(&context(inputs));
        assert!(declarations
            .iter()
            .all(|declaration| !declaration.advertised));
        let wait = declarations
            .iter()
            .find(|declaration| declaration.capability_id == "computer.wait")
            .expect("the canonical declaration exists");
        assert_eq!(
            wait.suppression_reason.as_deref(),
            Some(WINDOWS_ACTUATION_UNREVIEWED)
        );
    }

    fn grant() -> ProcessGrant {
        ProcessGrant {
            pid: 41,
            bundle_identity: "notepad.exe".to_owned(),
            process_generation_evidence: "100".to_owned(),
        }
    }

    fn tree(session: WindowsSessionProvenance) -> WindowsTreeReading {
        WindowsTreeReading {
            session,
            roots: vec![WindowsElement {
                process_id: 41,
                automation_id: Some("save".to_owned()),
                control_type: 50_000,
                name: "Save".to_owned(),
                enabled: true,
                focused: false,
                children: Vec::new(),
            }],
            unreadable_subtrees: 0,
        }
    }

    /// Provenance refuses BEFORE liveness and before the invoke, and refuses an
    /// element that would otherwise be actuated -- unique, correct, and named
    /// both ways.
    ///
    /// This is the falsifying vector for the session gate. The reader-side
    /// test shows a service-session read is refused; it does not show that an
    /// actuation presented with such a tree refuses before doing anything. A
    /// change that moved the provenance check after resolution or after the
    /// liveness probe would pass every reader test and every live probe, and
    /// would invoke a control on a desktop the user cannot see. So: counts on
    /// the platform closures, asserted zero on the refusing arm.
    #[test]
    fn other_session_refuses_actuation_before_liveness_and_before_any_invoke() {
        use std::cell::Cell;

        let request = SemanticDispatchRequest {
            element: ElementResolutionResult {
                element_name: AccessibilityElementName::Identifier("save".to_owned()),
                alternate_name: Some(AccessibilityElementName::RoleAndTitle {
                    role: control_type_role(50_000),
                    title: "Save".to_owned(),
                }),
                owning_process: ProcessGrant {
                    pid: 41,
                    bundle_identity: "pid:41".to_owned(),
                    process_generation_evidence: "100".to_owned(),
                },
                semantic_actions: vec![SemanticActionIntent::Press.wire_name().to_owned()],
                unreadable_subtrees: 0,
            },
            action: SemanticActionIntent::Press.wire_name().to_owned(),
        };

        let retained = Cell::new(0u32);
        let invoked = Cell::new(0u32);
        let refused = dispatch_semantic_in_order(
            WindowsSessionProvenance::OtherSession {
                session_id: 0,
                console_session_id: 1,
            },
            &request,
            |_| {
                retained.set(retained.get() + 1);
                Ok(())
            },
            |_, _, _| {
                invoked.set(invoked.get() + 1);
                Ok(accepted_invoke_result(0))
            },
        );
        assert!(
            matches!(
                refused,
                Err(DriverError::SessionNotInspectable(
                    SessionProvenanceRefusal::OtherSession {
                        session_id: 0,
                        console_session_id: 1
                    }
                ))
            ),
            "a service-session actuation must refuse by provenance, got {refused:?}"
        );
        assert_eq!(
            retained.get(),
            0,
            "liveness was probed before provenance refused"
        );
        assert_eq!(
            invoked.get(),
            0,
            "the platform was asked to invoke on a refused actuation"
        );

        // The identical request from the console proceeds through both, in order.
        let order = std::cell::RefCell::new(Vec::new());
        let accepted = dispatch_semantic_in_order(
            WindowsSessionProvenance::Console { session_id: 1 },
            &request,
            |_| {
                order.borrow_mut().push("retain");
                Ok(())
            },
            |_, _, intent| {
                order.borrow_mut().push("invoke");
                assert_eq!(intent, SemanticActionIntent::Press);
                Ok(accepted_invoke_result(0))
            },
        );
        assert!(
            accepted.is_ok(),
            "the identical console actuation must proceed: {accepted:?}"
        );
        assert_eq!(*order.borrow(), ["retain", "invoke"]);
    }

    #[test]
    fn other_session_refuses_by_name_before_the_same_console_tree_proceeds() {
        let other = admit_tree_reading(
            &grant(),
            WindowsWindowVisibility::Visible,
            tree(WindowsSessionProvenance::OtherSession {
                session_id: 0,
                console_session_id: 1,
            }),
        );
        assert!(matches!(
            other,
            Err(DriverError::SessionNotInspectable(
                SessionProvenanceRefusal::OtherSession {
                    session_id: 0,
                    console_session_id: 1
                }
            ))
        ));

        let console = admit_tree_reading(
            &grant(),
            WindowsWindowVisibility::Visible,
            tree(WindowsSessionProvenance::Console { session_id: 1 }),
        );
        assert!(console.is_ok(), "the identical console tree must proceed");
    }

    #[test]
    fn other_session_refuses_target_resolution_by_name_before_the_same_console_windows_proceed() {
        let windows = vec![(41u32, "notepad.exe".to_owned())];
        let generation = |_pid: u32| Some("100".to_owned());

        let other = resolve_from_reading(
            "notepad.exe",
            WindowsSessionProvenance::OtherSession {
                session_id: 0,
                console_session_id: 1,
            },
            Some(&windows),
            0,
            generation,
        );
        assert!(matches!(
            other,
            Err(DriverError::SessionNotInspectable(
                SessionProvenanceRefusal::OtherSession {
                    session_id: 0,
                    console_session_id: 1
                }
            ))
        ));

        let console = resolve_from_reading(
            "notepad.exe",
            WindowsSessionProvenance::Console { session_id: 1 },
            Some(&windows),
            0,
            |_pid| Some("100".to_owned()),
        );
        let Ok(TargetResolution::Resolved(grant)) = console else {
            panic!("the identical console windows must proceed, got {console:?}");
        };
        assert_eq!(grant.pid, 41);
        assert_eq!(grant.bundle_identity, "notepad.exe");
        assert_eq!(grant.process_generation_evidence, "100");
    }

    /// A reading with unreadable owners is a list known to be short, so a
    /// name absent from it has not been shown absent from the machine.
    #[test]
    fn a_partial_window_list_cannot_claim_a_target_is_not_running() {
        let console = WindowsSessionProvenance::Console { session_id: 1 };
        let windows = vec![(41u32, "explorer.exe".to_owned())];
        let generation = |_pid: u32| Some("100".to_owned());

        // Complete list, name absent: a claim about the world, and permitted.
        let complete = resolve_from_reading("notepad.exe", console, Some(&windows), 0, generation);
        assert!(matches!(complete, Ok(TargetResolution::NotRunning)));

        // Same list, one owner unreadable: the missing window may be the one.
        let partial = resolve_from_reading("notepad.exe", console, Some(&windows), 1, generation);
        assert!(
            matches!(
                partial,
                Ok(TargetResolution::Unreadable(
                    UnreadableReason::PartialWindowList {
                        unreadable_owners: 1
                    }
                ))
            ),
            "a partial list must not assert absence, got {partial:?}"
        );

        // But a name FOUND in the partial list still resolves: presence was
        // observed, and the unread remainder cannot un-observe it.
        let found = resolve_from_reading("explorer.exe", console, Some(&windows), 1, generation);
        assert!(matches!(found, Ok(TargetResolution::Resolved(_))));
    }

    #[test]
    fn unknown_visibility_is_refused_without_becoming_not_visible() {
        assert_eq!(
            require_enumerable_visibility(41, WindowsWindowVisibility::Unknown),
            Err(DriverError::WindowVisibilityUnknown { pid: 41 })
        );
        assert!(require_enumerable_visibility(41, WindowsWindowVisibility::NotVisible).is_ok());
    }

    #[test]
    fn unique_invoke_uses_the_neutral_mapping_and_earns_semantic_element() {
        let (_, cached, _) = admit_tree_reading(
            &grant(),
            WindowsWindowVisibility::Visible,
            tree(WindowsSessionProvenance::Console { session_id: 1 }),
        )
        .expect("the console fixture is readable");
        let resolved = resolution_from_cached_tree(
            &cached,
            &ElementResolutionRequest {
                root_identifier: root_cache_key(&grant()),
                element_name: AccessibilityElementName::identifier("save"),
            },
        )
        .expect("the element key is unique");
        assert_eq!(resolved.semantic_actions, vec![SEMANTIC_PRESS_ACTION]);
        assert_eq!(
            delivered_semantic_action(SemanticActionPlatform::Windows, SemanticActionIntent::Press),
            Ok("Invoke")
        );
        let result = accepted_invoke_result(0);
        assert!(result.accepted_by_platform);
        let mut identity = crate::platform::containment::IdentityCheckEvidence::matched(
            &crate::platform::containment::ProcessIdentityPrimitive::pinned_v1(),
            0,
        );
        identity.identity_to_delivery_binding =
            crate::platform::containment::IdentityAtomicBinding::Atomic;
        let containment = finalize_input_containment(
            DeliveryPrimitive::SemanticAccessibility,
            false,
            Some(identity),
            None,
            false,
        )
        .expect("semantic element delivery is structurally contained");
        assert_eq!(containment.rung(), Some(ContainmentRung::SemanticElement));
    }

    #[test]
    fn process_generation_is_rechecked_without_trusting_the_pid() {
        assert_eq!(
            verify_process_generation("100", WindowsProcessStartReading::Started(100)),
            WindowsGrantVerification::Current
        );
        assert_eq!(
            verify_process_generation("100", WindowsProcessStartReading::Started(101)),
            WindowsGrantVerification::Replaced
        );
        assert_eq!(
            verify_process_generation("100", WindowsProcessStartReading::Gone),
            WindowsGrantVerification::Gone
        );
        assert_eq!(
            verify_process_generation("100", WindowsProcessStartReading::Unreadable),
            WindowsGrantVerification::Unreadable
        );
    }

    #[test]
    fn windows_declares_no_capture_capability() {
        let backend = WindowsUnsupportedCaptureBackend;
        assert_eq!(
            backend.platform_support(),
            Err(BackendError::UnsupportedOnPlatform)
        );
        // The only capture surface is the image a state read returns, and no
        // row that can return one is advertised on Windows.
        assert!(WindowsPlatformDriver::default()
            .declarations(&context(fully_bound_inputs()))
            .iter()
            .all(
                |declaration| declaration.capability_id != "computer.screenshot"
                    && !(declaration.capability_id == "computer.read_state"
                        && declaration.advertised)
            ));
    }
}
