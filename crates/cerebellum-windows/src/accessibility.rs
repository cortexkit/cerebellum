//! Bounded, read-only Windows UI Automation tree readings.

use std::time::{Duration, Instant};

/// Resource bounds applied to one UI Automation tree read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessibilityReadBounds {
    pub timeout: Duration,
    /// A root has depth zero.
    pub max_depth: usize,
    /// Shared by all roots and their descendants.
    pub max_elements: usize,
}

impl Default for AccessibilityReadBounds {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_depth: MAX_RECURSIVE_TREE_DEPTH,
            max_elements: 10_000,
        }
    }
}

/// Resource bounds applied while re-finding an element for one UI Automation invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccessibilityInvokeBounds {
    pub timeout: Duration,
    /// A root has depth zero.
    pub max_depth: usize,
    /// Shared by all roots and descendants inspected for one exact match.
    pub max_elements: usize,
}

impl Default for AccessibilityInvokeBounds {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_depth: MAX_RECURSIVE_TREE_DEPTH,
            max_elements: 10_000,
        }
    }
}

/// A rectangle reported in Windows desktop coordinates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UiaRectangle {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

/// The non-identifier key carried for every readable element.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UiaControlTypeAndName {
    pub control_type: i32,
    /// UIA uses an empty name for an untitled element, which remains meaningful
    /// when paired with its control type.
    pub name: String,
}

/// Both forms by which a later caller can name a current UIA element.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UiaElementIdentity {
    /// UIA commonly reports an empty automation ID; that is represented as absent.
    pub automation_id: Option<String>,
    pub control_type_and_name: UiaControlTypeAndName,
}

/// One exact UI Automation key used to re-find a current element.
///
/// Each form is matched independently. In particular, naming an automation ID
/// never permits a fallback to a control type and name pair.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UiaElementName {
    AutomationId(String),
    ControlTypeAndName(UiaControlTypeAndName),
}

impl UiaElementName {
    pub fn automation_id(automation_id: impl Into<String>) -> Self {
        Self::AutomationId(automation_id.into())
    }

    pub fn control_type_and_name(control_type: i32, name: impl Into<String>) -> Self {
        Self::ControlTypeAndName(UiaControlTypeAndName {
            control_type,
            name: name.into(),
        })
    }

    fn matches(&self, identity: &UiaElementIdentity) -> bool {
        match self {
            Self::AutomationId(expected) => identity.automation_id.as_deref() == Some(expected),
            Self::ControlTypeAndName(expected) => &identity.control_type_and_name == expected,
        }
    }

    fn alternate_name(&self, identity: &UiaElementIdentity) -> Option<Self> {
        match self {
            Self::AutomationId(_) => Some(Self::ControlTypeAndName(
                identity.control_type_and_name.clone(),
            )),
            Self::ControlTypeAndName(_) => identity
                .automation_id
                .as_ref()
                .map(|automation_id| Self::AutomationId(automation_id.clone())),
        }
    }
}

/// One readable control-view element and the descendants reported beneath it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiaElement {
    pub process_id: u32,
    pub identity: UiaElementIdentity,
    pub class_name: Option<String>,
    pub framework_id: Option<String>,
    pub enabled: bool,
    pub keyboard_focusable: bool,
    pub has_keyboard_focus: bool,
    pub password: bool,
    pub offscreen: bool,
    pub bounding_rectangle: UiaRectangle,
    pub children: Vec<UiaElement>,
    /// Direct child scopes reported by UIA but not read, including one marker for
    /// any unenumerated remainder when a resource bound stops child discovery.
    pub unreadable_children: Vec<AccessibilityReadFailure>,
}

/// Whether every UIA scope reported for the target was read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiaTreeCompleteness {
    Complete,
    Incomplete { unreadable_subtrees: usize },
}

/// The target's control-view roots and the completeness of their traversal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiaAccessibilityTree {
    /// A process can own more than one top-level window, so the raw reading is a
    /// forest rather than choosing one window on the caller's behalf.
    pub roots: Vec<UiaElement>,
    pub unreadable_roots: Vec<AccessibilityReadFailure>,
    pub completeness: UiaTreeCompleteness,
}

/// Why a UI Automation scope could not be read.
///
/// These variants deliberately mirror the platform-neutral failure vocabulary,
/// so the caller can preserve the cause instead of collapsing it at this seam.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessibilityReadFailure {
    PermissionRequired,
    TargetGone,
    TargetReplaced,
    TargetNotInspectable,
    RetryableDeadlineExceeded,
    TreeExceedsBound,
    IncompatiblePlatformValue,
    PlatformReadFailed,
}

/// What a UI Automation invocation establishes when its provider returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessibilityInvokeOutcome {
    /// The target's invoke-pattern handler returned success. This does not
    /// establish that the handler changed application or screen state.
    HandlerReturned {
        /// The exact key supplied by the caller and used for the unique match.
        matched_by: UiaElementName,
        /// The other supported key, when the matched element reported one.
        alternate_name: Option<UiaElementName>,
        /// Scopes omitted from the fresh element search before the invocation.
        unreadable_subtrees: usize,
        /// Whether the foreground window differed immediately after the provider
        /// handler returned from the window observed immediately before it ran.
        foreground_window_changed: bool,
    },
}

/// Why one UI Automation invocation could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessibilityInvokeError {
    /// Re-finding the current element could not finish.
    Resolution(AccessibilityReadFailure),
    ElementNotFound {
        element_name: UiaElementName,
    },
    ElementNameAmbiguous {
        element_name: UiaElementName,
        match_count: usize,
    },
    InvokePatternUnavailable {
        element_name: UiaElementName,
    },
    /// The provider did not return successfully from its invoke-pattern call.
    Invocation(AccessibilityReadFailure),
}

const MAX_RECURSIVE_TREE_DEPTH: usize = 32;

fn supported_depth(requested: usize) -> usize {
    requested.min(MAX_RECURSIVE_TREE_DEPTH)
}

struct Deadline {
    started: Instant,
    timeout: Duration,
}

impl Deadline {
    fn new(timeout: Duration) -> Self {
        Self {
            started: Instant::now(),
            timeout,
        }
    }

    fn remaining(&self) -> Result<Duration, AccessibilityReadFailure> {
        let remaining = self.timeout.saturating_sub(self.started.elapsed());
        if remaining.is_zero() {
            Err(AccessibilityReadFailure::RetryableDeadlineExceeded)
        } else {
            Ok(remaining)
        }
    }
}

#[derive(Clone)]
struct ElementSnapshot {
    process_id: u32,
    identity: UiaElementIdentity,
    class_name: Option<String>,
    framework_id: Option<String>,
    enabled: bool,
    keyboard_focusable: bool,
    has_keyboard_focus: bool,
    password: bool,
    offscreen: bool,
    bounding_rectangle: UiaRectangle,
}

struct RootSnapshot<Handle> {
    roots: Vec<Handle>,
    unreadable_roots: Vec<AccessibilityReadFailure>,
}

trait ElementSource {
    type Handle: Clone;

    fn roots(
        &mut self,
        pid: u32,
        max_roots: usize,
        deadline: &Deadline,
    ) -> Result<RootSnapshot<Self::Handle>, AccessibilityReadFailure>;
    fn same_element(
        &mut self,
        left: &Self::Handle,
        right: &Self::Handle,
        deadline: &Deadline,
    ) -> Result<bool, AccessibilityReadFailure>;
    fn snapshot(
        &mut self,
        element: &Self::Handle,
        deadline: &Deadline,
    ) -> Result<ElementSnapshot, AccessibilityReadFailure>;
    fn first_child(
        &mut self,
        element: &Self::Handle,
        deadline: &Deadline,
    ) -> Result<Option<Self::Handle>, AccessibilityReadFailure>;
    fn next_sibling(
        &mut self,
        parent: &Self::Handle,
        element: &Self::Handle,
        deadline: &Deadline,
    ) -> Result<Option<Self::Handle>, AccessibilityReadFailure>;
}

trait InvokeSource: ElementSource {
    type InvokePattern;
    type ForegroundWindow: PartialEq;

    fn current_invoke_pattern(
        &mut self,
        element: &Self::Handle,
        deadline: &Deadline,
    ) -> Result<Option<Self::InvokePattern>, AccessibilityReadFailure>;
    fn invoke_pattern(
        &mut self,
        pattern: &Self::InvokePattern,
        deadline: &Deadline,
    ) -> Result<(), AccessibilityReadFailure>;
    fn foreground_window(&mut self) -> Option<Self::ForegroundWindow>;
}

enum ElementRead {
    Readable(Box<UiaElement>),
    Unreadable(AccessibilityReadFailure),
    ReenteredAncestor,
}

struct TreeReadState<'a> {
    count: usize,
    unreadable_subtrees: usize,
    bounds: AccessibilityReadBounds,
    deadline: &'a Deadline,
}

fn requires_whole_read_stop(failure: AccessibilityReadFailure) -> bool {
    matches!(
        failure,
        AccessibilityReadFailure::PermissionRequired
            | AccessibilityReadFailure::TargetGone
            | AccessibilityReadFailure::TargetReplaced
    )
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TargetState {
    Same,
    Gone,
    Replaced,
    PermissionDenied,
    Unknown,
}

const HRESULT_ACCESS_DENIED: u32 = 0x8007_0005;
const UIA_E_ELEMENT_NOT_AVAILABLE: u32 = 0x8004_0201;
const UIA_E_PROXY_ASSEMBLY_NOT_LOADED: u32 = 0x8004_0203;
const UIA_E_NOT_SUPPORTED: u32 = 0x8004_0204;
const UIA_E_TIMEOUT: u32 = 0x8013_1505;
const HRESULT_WIN32_TIMEOUT: u32 = 0x8007_05b4;

fn failure_for_hresult(code: i32, target: TargetState) -> AccessibilityReadFailure {
    match target {
        TargetState::Gone => return AccessibilityReadFailure::TargetGone,
        TargetState::Replaced => return AccessibilityReadFailure::TargetReplaced,
        TargetState::PermissionDenied => return AccessibilityReadFailure::PermissionRequired,
        TargetState::Same | TargetState::Unknown => {}
    }

    match code as u32 {
        HRESULT_ACCESS_DENIED => AccessibilityReadFailure::PermissionRequired,
        UIA_E_TIMEOUT | HRESULT_WIN32_TIMEOUT => {
            AccessibilityReadFailure::RetryableDeadlineExceeded
        }
        UIA_E_ELEMENT_NOT_AVAILABLE | UIA_E_PROXY_ASSEMBLY_NOT_LOADED | UIA_E_NOT_SUPPORTED => {
            AccessibilityReadFailure::TargetNotInspectable
        }
        _ => AccessibilityReadFailure::PlatformReadFailed,
    }
}

#[cfg(test)]
fn read_tree_from<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    bounds: AccessibilityReadBounds,
) -> Result<UiaAccessibilityTree, AccessibilityReadFailure> {
    let deadline = Deadline::new(bounds.timeout);
    read_tree_before_deadline(source, pid, bounds, &deadline)
}

fn read_tree_before_deadline<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    bounds: AccessibilityReadBounds,
    deadline: &Deadline,
) -> Result<UiaAccessibilityTree, AccessibilityReadFailure> {
    let bounds = AccessibilityReadBounds {
        max_depth: supported_depth(bounds.max_depth),
        ..bounds
    };
    deadline.remaining()?;

    let root_snapshot = source.roots(pid, bounds.max_elements, deadline)?;
    if root_snapshot.roots.is_empty() {
        return Err(root_snapshot
            .unreadable_roots
            .first()
            .copied()
            .unwrap_or(AccessibilityReadFailure::TargetNotInspectable));
    }

    let mut state = TreeReadState {
        count: 0,
        unreadable_subtrees: root_snapshot.unreadable_roots.len(),
        bounds,
        deadline,
    };
    let mut roots = Vec::with_capacity(root_snapshot.roots.len());
    let mut unreadable_roots = root_snapshot.unreadable_roots;
    for root in &root_snapshot.roots {
        match read_element(source, root, 0, &mut Vec::new(), &mut state) {
            Ok(ElementRead::Readable(root)) => roots.push(*root),
            Ok(ElementRead::Unreadable(failure)) => {
                state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
                unreadable_roots.push(failure);
            }
            Ok(ElementRead::ReenteredAncestor) => {
                // A root has no ancestor, so the walk cannot report re-entry
                // here. Counted rather than asserted: this runs under a
                // dispatch that owns the module loop, and a panic on a
                // reachable path takes the process down with it. If the
                // impossible happens, an unreadable subtree is the truthful
                // reading -- a root we did not manage to read.
                state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
            }
            Err(failure) => return Err(failure),
        }
    }
    if roots.is_empty() {
        return Err(unreadable_roots
            .first()
            .copied()
            .unwrap_or(AccessibilityReadFailure::TargetNotInspectable));
    }

    let completeness = if state.unreadable_subtrees == 0 {
        UiaTreeCompleteness::Complete
    } else {
        UiaTreeCompleteness::Incomplete {
            unreadable_subtrees: state.unreadable_subtrees,
        }
    };
    Ok(UiaAccessibilityTree {
        roots,
        unreadable_roots,
        completeness,
    })
}

fn read_element<Source: ElementSource>(
    source: &mut Source,
    handle: &Source::Handle,
    depth: usize,
    ancestors: &mut Vec<Source::Handle>,
    state: &mut TreeReadState<'_>,
) -> Result<ElementRead, AccessibilityReadFailure> {
    // Compare only with the active path. A shared DAG element must still appear
    // beneath each parent, while an edge back to an ancestor is a lossless cut.
    // This comparison precedes every lossy bound check, including when no element
    // budget remains, so a cycle edge never makes a complete tree look partial.
    for ancestor in ancestors.iter() {
        match source.same_element(handle, ancestor, state.deadline) {
            Ok(true) => return Ok(ElementRead::ReenteredAncestor),
            Ok(false) => {}
            Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
            Err(failure) => return Ok(ElementRead::Unreadable(failure)),
        }
    }

    if depth > state.bounds.max_depth || state.count >= state.bounds.max_elements {
        return Ok(ElementRead::Unreadable(
            AccessibilityReadFailure::TreeExceedsBound,
        ));
    }
    state.count += 1;
    if let Err(failure) = state.deadline.remaining() {
        return Ok(ElementRead::Unreadable(failure));
    }

    let snapshot = match source.snapshot(handle, state.deadline) {
        Ok(snapshot) => snapshot,
        Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
        Err(failure) => return Ok(ElementRead::Unreadable(failure)),
    };

    let mut children = Vec::new();
    let mut unreadable_children = Vec::new();
    ancestors.push(handle.clone());
    let mut current = match source.first_child(handle, state.deadline) {
        Ok(child) => child,
        Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
        Err(failure) => {
            state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
            unreadable_children.push(failure);
            None
        }
    };
    while let Some(child) = current {
        let mut stop_remainder = false;
        match read_element(source, &child, depth.saturating_add(1), ancestors, state)? {
            ElementRead::Readable(child) => children.push(*child),
            ElementRead::Unreadable(failure) => {
                state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
                unreadable_children.push(failure);
                stop_remainder = matches!(
                    failure,
                    AccessibilityReadFailure::TreeExceedsBound
                        | AccessibilityReadFailure::RetryableDeadlineExceeded
                );
            }
            ElementRead::ReenteredAncestor => {}
        }
        if stop_remainder {
            break;
        }
        current = match source.next_sibling(handle, &child, state.deadline) {
            Ok(next) => next,
            Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
            Err(failure) => {
                state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
                unreadable_children.push(failure);
                None
            }
        };
    }
    ancestors.pop();

    Ok(ElementRead::Readable(Box::new(UiaElement {
        process_id: snapshot.process_id,
        identity: snapshot.identity,
        class_name: snapshot.class_name,
        framework_id: snapshot.framework_id,
        enabled: snapshot.enabled,
        keyboard_focusable: snapshot.keyboard_focusable,
        has_keyboard_focus: snapshot.has_keyboard_focus,
        password: snapshot.password,
        offscreen: snapshot.offscreen,
        bounding_rectangle: snapshot.bounding_rectangle,
        children,
        unreadable_children,
    })))
}

struct InvokeTarget<Handle> {
    handle: Handle,
    alternate_name: Option<UiaElementName>,
}

struct InvokeSearchState<'a, Handle> {
    element_name: &'a UiaElementName,
    count: usize,
    match_count: usize,
    found: Option<InvokeTarget<Handle>>,
    unreadable_subtrees: usize,
    bounds: AccessibilityInvokeBounds,
    deadline: &'a Deadline,
}

/// Walk every currently readable control-view scope to establish whether the
/// exact element key is unique. A read failure in one descendant is retained as
/// a count rather than silently turning a partial search into a complete one.
fn find_invoke_target<Source: ElementSource>(
    source: &mut Source,
    handle: &Source::Handle,
    depth: usize,
    ancestors: &mut Vec<Source::Handle>,
    state: &mut InvokeSearchState<'_, Source::Handle>,
) -> Result<(), AccessibilityReadFailure> {
    for ancestor in ancestors.iter() {
        match source.same_element(handle, ancestor, state.deadline) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
            Err(_) => {
                state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
                return Ok(());
            }
        }
    }

    if depth > state.bounds.max_depth || state.count >= state.bounds.max_elements {
        state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
        return Ok(());
    }
    state.count = state.count.saturating_add(1);
    state.deadline.remaining()?;

    let snapshot = match source.snapshot(handle, state.deadline) {
        Ok(snapshot) => snapshot,
        Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
        Err(_) => {
            state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
            return Ok(());
        }
    };
    if state.element_name.matches(&snapshot.identity) {
        state.match_count = state.match_count.saturating_add(1);
        if state.found.is_none() {
            state.found = Some(InvokeTarget {
                handle: handle.clone(),
                alternate_name: state.element_name.alternate_name(&snapshot.identity),
            });
        }
    }

    ancestors.push(handle.clone());
    let mut current = match source.first_child(handle, state.deadline) {
        Ok(child) => child,
        Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
        Err(_) => {
            state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
            None
        }
    };
    while let Some(child) = current {
        find_invoke_target(source, &child, depth.saturating_add(1), ancestors, state)?;
        current = match source.next_sibling(handle, &child, state.deadline) {
            Ok(next) => next,
            Err(failure) if requires_whole_read_stop(failure) => return Err(failure),
            Err(_) => {
                state.unreadable_subtrees = state.unreadable_subtrees.saturating_add(1);
                None
            }
        };
    }
    ancestors.pop();
    Ok(())
}

fn re_find_invoke_target<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    element_name: &UiaElementName,
    bounds: AccessibilityInvokeBounds,
    deadline: &Deadline,
) -> Result<(InvokeTarget<Source::Handle>, usize), AccessibilityInvokeError> {
    deadline
        .remaining()
        .map_err(AccessibilityInvokeError::Resolution)?;
    let roots = source
        .roots(pid, bounds.max_elements, deadline)
        .map_err(AccessibilityInvokeError::Resolution)?;
    if roots.roots.is_empty() {
        return Err(AccessibilityInvokeError::Resolution(
            roots
                .unreadable_roots
                .first()
                .copied()
                .unwrap_or(AccessibilityReadFailure::TargetNotInspectable),
        ));
    }

    let mut state = InvokeSearchState {
        element_name,
        count: 0,
        match_count: 0,
        found: None,
        unreadable_subtrees: roots.unreadable_roots.len(),
        bounds,
        deadline,
    };
    for root in &roots.roots {
        find_invoke_target(source, root, 0, &mut Vec::new(), &mut state)
            .map_err(AccessibilityInvokeError::Resolution)?;
    }
    if state.match_count > 1 {
        return Err(AccessibilityInvokeError::ElementNameAmbiguous {
            element_name: element_name.clone(),
            match_count: state.match_count,
        });
    }
    let target = state
        .found
        .ok_or_else(|| AccessibilityInvokeError::ElementNotFound {
            element_name: element_name.clone(),
        })?;
    Ok((target, state.unreadable_subtrees))
}

fn invoke_accessibility_from<Source: InvokeSource>(
    source: &mut Source,
    pid: u32,
    element_name: &UiaElementName,
    bounds: AccessibilityInvokeBounds,
) -> Result<AccessibilityInvokeOutcome, AccessibilityInvokeError> {
    let bounds = AccessibilityInvokeBounds {
        max_depth: supported_depth(bounds.max_depth),
        ..bounds
    };
    let deadline = Deadline::new(bounds.timeout);
    let (target, unreadable_subtrees) =
        re_find_invoke_target(source, pid, element_name, bounds, &deadline)?;

    let pattern = source
        .current_invoke_pattern(&target.handle, &deadline)
        .map_err(AccessibilityInvokeError::Invocation)?
        .ok_or_else(|| AccessibilityInvokeError::InvokePatternUnavailable {
            element_name: element_name.clone(),
        })?;

    // The uniqueness traversal is complete before this point. The two foreground
    // reads directly surround the only provider invocation, so the outcome reports
    // the window-server change that occurred across that call rather than assuming
    // that disabling UIA's automatic focus kept every provider from changing focus.
    let foreground_before = source.foreground_window();
    deadline
        .remaining()
        .map_err(AccessibilityInvokeError::Invocation)?;
    source
        .invoke_pattern(&pattern, &deadline)
        .map_err(AccessibilityInvokeError::Invocation)?;
    let foreground_after = source.foreground_window();
    deadline
        .remaining()
        .map_err(AccessibilityInvokeError::Invocation)?;

    Ok(AccessibilityInvokeOutcome::HandlerReturned {
        matched_by: element_name.clone(),
        alternate_name: target.alternate_name,
        unreadable_subtrees,
        foreground_window_changed: foreground_before != foreground_after,
    })
}

#[cfg(target_os = "windows")]
mod platform {
    use std::ffi::c_void;
    use std::mem;
    use std::ptr::{self, NonNull};
    use std::time::Duration;

    use windows_sys::core::{BSTR, GUID, HRESULT};
    use windows_sys::Win32::Foundation::{
        GetLastError, SetLastError, SysFreeString, SysStringLen, E_ACCESSDENIED, HWND, LPARAM, RECT,
    };
    use windows_sys::Win32::System::Com::{
        CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
        COINIT_MULTITHREADED,
    };
    use windows_sys::Win32::UI::Accessibility::{CUIAutomation8, UIA_InvokePatternId};
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        EnumWindows, GetForegroundWindow, GetWindowThreadProcessId,
    };

    use super::{
        failure_for_hresult, invoke_accessibility_from, read_tree_before_deadline,
        AccessibilityInvokeBounds, AccessibilityInvokeError, AccessibilityInvokeOutcome,
        AccessibilityReadBounds, AccessibilityReadFailure, Deadline, ElementSnapshot,
        ElementSource, InvokeSource, RootSnapshot, TargetState, UiaAccessibilityTree,
        UiaControlTypeAndName, UiaElementIdentity, UiaElementName, UiaRectangle,
    };
    use crate::windows::{process_start_time, ProcessStartTime};

    const IID_IUI_AUTOMATION2: GUID = GUID::from_u128(0x34723aff_0c9d_49d0_9896_7ab52df8cd8a);

    const IUNKNOWN_QUERY_INTERFACE: usize = 0;
    const IUNKNOWN_ADD_REF: usize = 1;
    const IUNKNOWN_RELEASE: usize = 2;
    const UIA_COMPARE_ELEMENTS: usize = 3;
    const UIA_ELEMENT_FROM_HANDLE: usize = 6;
    const UIA_CONTROL_VIEW_WALKER: usize = 14;

    const ELEMENT_GET_CURRENT_PATTERN: usize = 16;
    const INVOKE_PATTERN_INVOKE: usize = 3;
    const IID_IUI_AUTOMATION_INVOKE_PATTERN: GUID =
        GUID::from_u128(0xfb377fbe_8ea6_46d5_9c73_6499642d3059);
    // IUIAutomation contributes 55 methods after IUnknown. These are the
    // IUIAutomation2 property setters in the inherited COM vtable.
    const UIA2_PUT_AUTO_SET_FOCUS: usize = 59;
    const UIA2_PUT_CONNECTION_TIMEOUT: usize = 61;
    const UIA2_PUT_TRANSACTION_TIMEOUT: usize = 63;

    const WALKER_FIRST_CHILD: usize = 4;
    const WALKER_NEXT_SIBLING: usize = 6;

    const ELEMENT_CURRENT_PROCESS_ID: usize = 20;
    const ELEMENT_CURRENT_CONTROL_TYPE: usize = 21;
    const ELEMENT_CURRENT_NAME: usize = 23;
    const ELEMENT_CURRENT_HAS_KEYBOARD_FOCUS: usize = 26;
    const ELEMENT_CURRENT_IS_KEYBOARD_FOCUSABLE: usize = 27;
    const ELEMENT_CURRENT_IS_ENABLED: usize = 28;
    const ELEMENT_CURRENT_AUTOMATION_ID: usize = 29;
    const ELEMENT_CURRENT_CLASS_NAME: usize = 30;
    const ELEMENT_CURRENT_IS_PASSWORD: usize = 35;
    const ELEMENT_CURRENT_IS_OFFSCREEN: usize = 38;
    const ELEMENT_CURRENT_FRAMEWORK_ID: usize = 40;
    const ELEMENT_CURRENT_BOUNDING_RECTANGLE: usize = 43;

    /// Read the target's control-view UI Automation forest without invoking any
    /// control pattern or changing focus.
    pub fn read_accessibility_tree(
        pid: u32,
        bounds: AccessibilityReadBounds,
    ) -> Result<UiaAccessibilityTree, AccessibilityReadFailure> {
        // Microsoft documents UIA clients as prone to message-pump deadlocks on
        // a UI thread. Every read therefore owns a fresh, windowless MTA thread;
        // the caller's COM apartment is neither assumed nor changed, and no COM
        // pointer crosses the apartment boundary.
        std::thread::Builder::new()
            .name("cerebellum-uia-reader".to_owned())
            .spawn(move || read_on_mta(pid, bounds))
            .map_err(|_| AccessibilityReadFailure::PlatformReadFailed)?
            .join()
            .map_err(|_| AccessibilityReadFailure::PlatformReadFailed)?
    }

    /// Re-find one uniquely named current element and invoke its Invoke pattern.
    ///
    /// A result means only that the provider handler returned. It does not prove
    /// that the provider produced an application-visible effect.
    pub fn invoke_accessibility_element(
        pid: u32,
        element_name: &UiaElementName,
        bounds: AccessibilityInvokeBounds,
    ) -> Result<AccessibilityInvokeOutcome, AccessibilityInvokeError> {
        std::thread::Builder::new()
            .name("cerebellum-uia-invoker".to_owned())
            .spawn({
                let element_name = element_name.clone();
                move || invoke_on_mta(pid, &element_name, bounds)
            })
            .map_err(|_| {
                AccessibilityInvokeError::Invocation(AccessibilityReadFailure::PlatformReadFailed)
            })?
            .join()
            .map_err(|_| {
                AccessibilityInvokeError::Invocation(AccessibilityReadFailure::PlatformReadFailed)
            })?
    }

    fn read_on_mta(
        pid: u32,
        bounds: AccessibilityReadBounds,
    ) -> Result<UiaAccessibilityTree, AccessibilityReadFailure> {
        let _apartment = ComApartment::initialize()?;
        let initial_start = initial_process_start(pid)?;
        let deadline = Deadline::new(bounds.timeout);
        let remaining = deadline.remaining()?;
        let mut source = UiaSource::new(pid, initial_start, remaining)?;
        let tree = read_tree_before_deadline(&mut source, pid, bounds, &deadline)?;
        source.confirm_target()?;
        Ok(tree)
    }

    fn invoke_on_mta(
        pid: u32,
        element_name: &UiaElementName,
        bounds: AccessibilityInvokeBounds,
    ) -> Result<AccessibilityInvokeOutcome, AccessibilityInvokeError> {
        let _apartment =
            ComApartment::initialize().map_err(AccessibilityInvokeError::Invocation)?;
        let initial_start =
            initial_process_start(pid).map_err(AccessibilityInvokeError::Resolution)?;
        let deadline = Deadline::new(bounds.timeout);
        let remaining = deadline
            .remaining()
            .map_err(AccessibilityInvokeError::Resolution)?;
        let mut source = UiaSource::new(pid, initial_start, remaining)
            .map_err(AccessibilityInvokeError::Resolution)?;
        invoke_accessibility_from(&mut source, pid, element_name, bounds)
    }

    fn initial_process_start(pid: u32) -> Result<u64, AccessibilityReadFailure> {
        match process_start_time(pid) {
            ProcessStartTime::Started(start) => Ok(start),
            ProcessStartTime::NoSuchProcess => Err(AccessibilityReadFailure::TargetGone),
            ProcessStartTime::AccessDenied => Err(AccessibilityReadFailure::PermissionRequired),
            ProcessStartTime::Unclassified(_) => Err(AccessibilityReadFailure::PlatformReadFailed),
        }
    }

    fn milliseconds(duration: Duration) -> u32 {
        let millis = duration.as_millis().clamp(1, u128::from(u32::MAX));
        millis as u32
    }

    struct ComApartment;

    impl ComApartment {
        fn initialize() -> Result<Self, AccessibilityReadFailure> {
            // SAFETY: this fresh reader thread has not initialized COM. The guard
            // balances every successful initialization with one `CoUninitialize`.
            let result = unsafe { CoInitializeEx(ptr::null(), COINIT_MULTITHREADED as u32) };
            if result < 0 {
                Err(AccessibilityReadFailure::PlatformReadFailed)
            } else {
                Ok(Self)
            }
        }
    }

    impl Drop for ComApartment {
        fn drop(&mut self) {
            // SAFETY: this guard exists only after this thread successfully called
            // `CoInitializeEx`, and it is dropped on that same thread.
            unsafe { CoUninitialize() };
        }
    }

    struct ComPtr(NonNull<c_void>);

    impl ComPtr {
        unsafe fn from_raw(raw: *mut c_void) -> Option<Self> {
            NonNull::new(raw).map(Self)
        }

        fn as_raw(&self) -> *mut c_void {
            self.0.as_ptr()
        }

        fn query_interface(&self, iid: &GUID) -> Result<Option<Self>, HRESULT> {
            type QueryInterface =
                unsafe extern "system" fn(*mut c_void, *const GUID, *mut *mut c_void) -> HRESULT;
            // SAFETY: this is IUnknown::QueryInterface at the fixed inherited
            // vtable slot, and `iid` and `raw` remain valid throughout the call.
            let query_interface: QueryInterface =
                unsafe { mem::transmute(self.slot(IUNKNOWN_QUERY_INTERFACE)) };
            let mut raw = ptr::null_mut();
            // SAFETY: `self` is a live COM interface pointer and `raw` is writable.
            hresult(unsafe { query_interface(self.as_raw(), iid, &mut raw) })?;
            // SAFETY: a non-null successful COM out pointer carries one owned reference.
            Ok(unsafe { Self::from_raw(raw) })
        }

        unsafe fn slot(&self, index: usize) -> *const c_void {
            // SAFETY: every COM interface pointer starts with a pointer to its
            // immutable vtable, and callers supply an index from that interface's
            // documented inherited layout.
            let vtable = unsafe { *self.as_raw().cast::<*const *const c_void>() };
            unsafe { *vtable.add(index) }
        }
    }

    impl Clone for ComPtr {
        fn clone(&self) -> Self {
            type AddRef = unsafe extern "system" fn(*mut c_void) -> u32;
            // SAFETY: this is IUnknown::AddRef at the fixed inherited vtable slot.
            let add_ref: AddRef = unsafe { mem::transmute(self.slot(IUNKNOWN_ADD_REF)) };
            // SAFETY: `self` is a live COM interface pointer.
            unsafe { add_ref(self.as_raw()) };
            Self(self.0)
        }
    }

    impl Drop for ComPtr {
        fn drop(&mut self) {
            type Release = unsafe extern "system" fn(*mut c_void) -> u32;
            // SAFETY: this is IUnknown::Release at the fixed inherited vtable slot.
            let release: Release = unsafe { mem::transmute(self.slot(IUNKNOWN_RELEASE)) };
            // SAFETY: this wrapper owns one reference to the live COM pointer.
            unsafe { release(self.as_raw()) };
        }
    }

    struct OwnedBstr(BSTR);

    impl OwnedBstr {
        fn into_string(self) -> Result<String, AccessibilityReadFailure> {
            if self.0.is_null() {
                return Ok(String::new());
            }
            // SAFETY: `self.0` is an owned BSTR returned by a successful COM call.
            let len = unsafe { SysStringLen(self.0) } as usize;
            // SAFETY: a BSTR stores `len` initialized UTF-16 code units at its data
            // pointer. The allocation stays alive until this wrapper is dropped.
            let units = unsafe { std::slice::from_raw_parts(self.0, len) };
            String::from_utf16(units)
                .map_err(|_| AccessibilityReadFailure::IncompatiblePlatformValue)
        }
    }

    impl Drop for OwnedBstr {
        fn drop(&mut self) {
            // SAFETY: null is accepted, and a non-null value is the BSTR this
            // wrapper received from one successful COM property call.
            unsafe { SysFreeString(self.0) };
        }
    }

    struct UiaSource {
        pid: u32,
        initial_start: u64,
        automation: ComPtr,
        walker: ComPtr,
    }

    impl UiaSource {
        fn new(
            pid: u32,
            initial_start: u64,
            timeout: Duration,
        ) -> Result<Self, AccessibilityReadFailure> {
            let mut raw = ptr::null_mut();
            // SAFETY: the CLSID and IID identify the system UI Automation COM
            // class and IUIAutomation2; aggregation is disabled and `raw` is writable.
            let result = unsafe {
                CoCreateInstance(
                    &CUIAutomation8,
                    ptr::null_mut(),
                    CLSCTX_INPROC_SERVER,
                    &IID_IUI_AUTOMATION2,
                    &mut raw,
                )
            };
            if result < 0 {
                return Err(failure_for_hresult(result, TargetState::Same));
            }
            // SAFETY: a successful `CoCreateInstance` returned one owned reference.
            let automation = unsafe { ComPtr::from_raw(raw) }
                .ok_or(AccessibilityReadFailure::PlatformReadFailed)?;
            let timeout_ms = milliseconds(timeout);

            // `IUIAutomation2::put_AutoSetFocus(FALSE)` must precede every element
            // access. UIA otherwise permits operations to focus a control, which
            // would make this read change the state it is measuring.
            Self::put_uia_bool(&automation, UIA2_PUT_AUTO_SET_FOCUS, false)
                .map_err(|code| failure_for_hresult(code, TargetState::Same))?;
            Self::put_uia_timeout(&automation, UIA2_PUT_CONNECTION_TIMEOUT, timeout_ms)
                .map_err(|code| failure_for_hresult(code, TargetState::Same))?;
            Self::put_uia_timeout(&automation, UIA2_PUT_TRANSACTION_TIMEOUT, timeout_ms)
                .map_err(|code| failure_for_hresult(code, TargetState::Same))?;
            let walker = Self::interface_out(&automation, UIA_CONTROL_VIEW_WALKER)
                .map_err(|code| failure_for_hresult(code, TargetState::Same))?
                .ok_or(AccessibilityReadFailure::PlatformReadFailed)?;

            Ok(Self {
                pid,
                initial_start,
                automation,
                walker,
            })
        }

        fn target_state(&self) -> TargetState {
            match process_start_time(self.pid) {
                ProcessStartTime::Started(start) if start == self.initial_start => {
                    TargetState::Same
                }
                ProcessStartTime::Started(_) => TargetState::Replaced,
                ProcessStartTime::NoSuchProcess => TargetState::Gone,
                ProcessStartTime::AccessDenied => TargetState::PermissionDenied,
                ProcessStartTime::Unclassified(_) => TargetState::Unknown,
            }
        }

        fn confirm_target(&self) -> Result<(), AccessibilityReadFailure> {
            match self.target_state() {
                TargetState::Same => Ok(()),
                TargetState::Gone => Err(AccessibilityReadFailure::TargetGone),
                TargetState::Replaced => Err(AccessibilityReadFailure::TargetReplaced),
                TargetState::PermissionDenied => Err(AccessibilityReadFailure::PermissionRequired),
                TargetState::Unknown => Err(AccessibilityReadFailure::PlatformReadFailed),
            }
        }

        fn map_hresult(&self, code: HRESULT) -> AccessibilityReadFailure {
            failure_for_hresult(code, self.target_state())
        }

        fn prepare_call(&self, deadline: &Deadline) -> Result<(), AccessibilityReadFailure> {
            let timeout = milliseconds(deadline.remaining()?);
            Self::put_uia_timeout(&self.automation, UIA2_PUT_CONNECTION_TIMEOUT, timeout)
                .map_err(|code| self.map_hresult(code))?;
            Self::put_uia_timeout(&self.automation, UIA2_PUT_TRANSACTION_TIMEOUT, timeout)
                .map_err(|code| self.map_hresult(code))
        }

        fn put_uia_bool(interface: &ComPtr, slot: usize, value: bool) -> Result<(), HRESULT> {
            type Method = unsafe extern "system" fn(*mut c_void, i32) -> HRESULT;
            // SAFETY: `slot` names the BOOL property setter in IUIAutomation2.
            let method: Method = unsafe { mem::transmute(interface.slot(slot)) };
            // SAFETY: the interface is live and Win32 BOOL uses zero/one i32 values.
            let result = unsafe { method(interface.as_raw(), i32::from(value)) };
            hresult(result)
        }

        fn put_uia_timeout(interface: &ComPtr, slot: usize, timeout: u32) -> Result<(), HRESULT> {
            type Method = unsafe extern "system" fn(*mut c_void, u32) -> HRESULT;
            // SAFETY: `slot` names one DWORD timeout setter in IUIAutomation2.
            let method: Method = unsafe { mem::transmute(interface.slot(slot)) };
            // SAFETY: the interface is live and the timeout is passed by value.
            hresult(unsafe { method(interface.as_raw(), timeout) })
        }

        fn interface_out(interface: &ComPtr, slot: usize) -> Result<Option<ComPtr>, HRESULT> {
            type Method = unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> HRESULT;
            // SAFETY: `slot` names a no-argument COM method with one interface out pointer.
            let method: Method = unsafe { mem::transmute(interface.slot(slot)) };
            let mut raw = ptr::null_mut();
            // SAFETY: the interface is live and `raw` is writable.
            hresult(unsafe { method(interface.as_raw(), &mut raw) })?;
            // SAFETY: a non-null successful COM out pointer carries one owned reference.
            Ok(unsafe { ComPtr::from_raw(raw) })
        }

        fn element_from_handle(
            &self,
            hwnd: HWND,
        ) -> Result<Option<ComPtr>, AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(*mut c_void, HWND, *mut *mut c_void) -> HRESULT;
            // SAFETY: this is IUIAutomation::ElementFromHandle in the inherited vtable.
            let method: Method =
                unsafe { mem::transmute(self.automation.slot(UIA_ELEMENT_FROM_HANDLE)) };
            let mut raw = ptr::null_mut();
            // SAFETY: the automation interface and enumerated HWND are live for the
            // call, and `raw` is a writable interface out pointer.
            let result = unsafe { method(self.automation.as_raw(), hwnd, &mut raw) };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            // SAFETY: a non-null successful COM out pointer carries one owned reference.
            Ok(unsafe { ComPtr::from_raw(raw) })
        }

        fn compare_elements(
            &self,
            left: &ComPtr,
            right: &ComPtr,
        ) -> Result<bool, AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(
                *mut c_void,
                *mut c_void,
                *mut c_void,
                *mut i32,
            ) -> HRESULT;
            // SAFETY: this is IUIAutomation::CompareElements in the inherited vtable.
            let method: Method =
                unsafe { mem::transmute(self.automation.slot(UIA_COMPARE_ELEMENTS)) };
            let mut equal = 0;
            // SAFETY: all three interface pointers are live and `equal` is writable.
            let result = unsafe {
                method(
                    self.automation.as_raw(),
                    left.as_raw(),
                    right.as_raw(),
                    &mut equal,
                )
            };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            Ok(equal != 0)
        }

        fn walker_element(
            &self,
            slot: usize,
            element: &ComPtr,
        ) -> Result<Option<ComPtr>, AccessibilityReadFailure> {
            type Method =
                unsafe extern "system" fn(*mut c_void, *mut c_void, *mut *mut c_void) -> HRESULT;
            // SAFETY: `slot` names a tree-walker method with one element input and
            // one element out pointer.
            let method: Method = unsafe { mem::transmute(self.walker.slot(slot)) };
            let mut raw = ptr::null_mut();
            // SAFETY: the walker and element are live and `raw` is writable.
            let result = unsafe { method(self.walker.as_raw(), element.as_raw(), &mut raw) };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            // A null out pointer with S_OK is UIA's documented end-of-siblings marker.
            // SAFETY: a non-null successful COM out pointer carries one owned reference.
            Ok(unsafe { ComPtr::from_raw(raw) })
        }

        fn current_invoke_pattern(
            &self,
            element: &ComPtr,
        ) -> Result<Option<ComPtr>, AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> HRESULT;
            // SAFETY: this is IUIAutomationElement::GetCurrentPattern in the
            // documented inherited vtable, requesting UIA_InvokePatternId.
            let method: Method =
                unsafe { mem::transmute(element.slot(ELEMENT_GET_CURRENT_PATTERN)) };
            let mut raw = ptr::null_mut();
            // SAFETY: the element is live, the pattern ID is passed by value, and
            // `raw` is a writable interface out pointer for this synchronous call.
            let result = unsafe { method(element.as_raw(), UIA_InvokePatternId, &mut raw) };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            // GetCurrentPattern returns IUnknown. Query it for the Invoke-pattern
            // interface before using the pattern-specific vtable slot below.
            // SAFETY: a non-null successful COM out pointer carries one owned reference.
            let current = unsafe { ComPtr::from_raw(raw) };
            Ok(current
                .map(|current| {
                    current
                        .query_interface(&IID_IUI_AUTOMATION_INVOKE_PATTERN)
                        .map_err(|code| self.map_hresult(code))
                })
                .transpose()?
                .flatten())
        }

        fn invoke_pattern_handler(&self, pattern: &ComPtr) -> Result<(), AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(*mut c_void) -> HRESULT;
            // SAFETY: Invoke is the first IUIAutomationInvokePattern method after
            // IUnknown in the documented pattern vtable.
            let method: Method = unsafe { mem::transmute(pattern.slot(INVOKE_PATTERN_INVOKE)) };
            // SAFETY: `pattern` owns a live IUIAutomationInvokePattern reference.
            hresult(unsafe { method(pattern.as_raw()) }).map_err(|code| self.map_hresult(code))
        }

        fn element_i32(
            &self,
            element: &ComPtr,
            slot: usize,
        ) -> Result<i32, AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(*mut c_void, *mut i32) -> HRESULT;
            // SAFETY: `slot` names an i32-valued current-property getter.
            let method: Method = unsafe { mem::transmute(element.slot(slot)) };
            let mut value = 0;
            // SAFETY: the element is live and `value` is writable.
            let result = unsafe { method(element.as_raw(), &mut value) };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            Ok(value)
        }

        fn element_bool(
            &self,
            element: &ComPtr,
            slot: usize,
        ) -> Result<bool, AccessibilityReadFailure> {
            Ok(self.element_i32(element, slot)? != 0)
        }

        fn element_string(
            &self,
            element: &ComPtr,
            slot: usize,
        ) -> Result<String, AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(*mut c_void, *mut BSTR) -> HRESULT;
            // SAFETY: `slot` names a BSTR-valued current-property getter.
            let method: Method = unsafe { mem::transmute(element.slot(slot)) };
            let mut value = ptr::null();
            // SAFETY: the element is live and `value` is a writable BSTR out pointer.
            let result = unsafe { method(element.as_raw(), &mut value) };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            OwnedBstr(value).into_string()
        }

        fn element_rectangle(
            &self,
            element: &ComPtr,
        ) -> Result<UiaRectangle, AccessibilityReadFailure> {
            type Method = unsafe extern "system" fn(*mut c_void, *mut RECT) -> HRESULT;
            // SAFETY: this is IUIAutomationElement::get_CurrentBoundingRectangle.
            let method: Method =
                unsafe { mem::transmute(element.slot(ELEMENT_CURRENT_BOUNDING_RECTANGLE)) };
            let mut rectangle = RECT {
                left: 0,
                top: 0,
                right: 0,
                bottom: 0,
            };
            // SAFETY: the element is live and `rectangle` is writable.
            let result = unsafe { method(element.as_raw(), &mut rectangle) };
            hresult(result).map_err(|code| self.map_hresult(code))?;
            Ok(UiaRectangle {
                left: rectangle.left,
                top: rectangle.top,
                right: rectangle.right,
                bottom: rectangle.bottom,
            })
        }
    }

    impl ElementSource for UiaSource {
        type Handle = ComPtr;

        fn roots(
            &mut self,
            pid: u32,
            max_roots: usize,
            deadline: &Deadline,
        ) -> Result<RootSnapshot<Self::Handle>, AccessibilityReadFailure> {
            let windows = process_windows(pid, max_roots)?;
            let mut roots = Vec::with_capacity(windows.handles.len());
            let mut unreadable_roots = Vec::new();
            for hwnd in windows.handles {
                if let Err(failure) = self.prepare_call(deadline) {
                    if super::requires_whole_read_stop(failure) {
                        return Err(failure);
                    }
                    unreadable_roots.push(failure);
                    break;
                }
                match self.element_from_handle(hwnd) {
                    Ok(Some(element)) => roots.push(element),
                    Ok(None) => {
                        unreadable_roots.push(AccessibilityReadFailure::TargetNotInspectable)
                    }
                    Err(failure) if super::requires_whole_read_stop(failure) => {
                        return Err(failure)
                    }
                    Err(failure) => unreadable_roots.push(failure),
                }
            }
            if windows.exceeded_bound {
                unreadable_roots.push(AccessibilityReadFailure::TreeExceedsBound);
            }
            if roots.is_empty() && unreadable_roots.is_empty() {
                return Err(AccessibilityReadFailure::TargetNotInspectable);
            }
            Ok(RootSnapshot {
                roots,
                unreadable_roots,
            })
        }

        fn same_element(
            &mut self,
            left: &Self::Handle,
            right: &Self::Handle,
            deadline: &Deadline,
        ) -> Result<bool, AccessibilityReadFailure> {
            self.prepare_call(deadline)?;
            self.compare_elements(left, right)
        }

        fn snapshot(
            &mut self,
            element: &Self::Handle,
            deadline: &Deadline,
        ) -> Result<ElementSnapshot, AccessibilityReadFailure> {
            macro_rules! read {
                ($expression:expr) => {{
                    self.prepare_call(deadline)?;
                    $expression?
                }};
            }

            let process_id =
                u32::try_from(read!(self.element_i32(element, ELEMENT_CURRENT_PROCESS_ID)))
                    .map_err(|_| AccessibilityReadFailure::IncompatiblePlatformValue)?;
            let control_type = read!(self.element_i32(element, ELEMENT_CURRENT_CONTROL_TYPE));
            let name = read!(self.element_string(element, ELEMENT_CURRENT_NAME));
            let automation_id = read!(self.element_string(element, ELEMENT_CURRENT_AUTOMATION_ID));
            let class_name = read!(self.element_string(element, ELEMENT_CURRENT_CLASS_NAME));
            let framework_id = read!(self.element_string(element, ELEMENT_CURRENT_FRAMEWORK_ID));
            let enabled = read!(self.element_bool(element, ELEMENT_CURRENT_IS_ENABLED));
            let keyboard_focusable =
                read!(self.element_bool(element, ELEMENT_CURRENT_IS_KEYBOARD_FOCUSABLE));
            let has_keyboard_focus =
                read!(self.element_bool(element, ELEMENT_CURRENT_HAS_KEYBOARD_FOCUS));
            let password = read!(self.element_bool(element, ELEMENT_CURRENT_IS_PASSWORD));
            let offscreen = read!(self.element_bool(element, ELEMENT_CURRENT_IS_OFFSCREEN));
            let bounding_rectangle = read!(self.element_rectangle(element));

            Ok(ElementSnapshot {
                process_id,
                identity: UiaElementIdentity {
                    automation_id: nonempty(automation_id),
                    control_type_and_name: UiaControlTypeAndName { control_type, name },
                },
                class_name: nonempty(class_name),
                framework_id: nonempty(framework_id),
                enabled,
                keyboard_focusable,
                has_keyboard_focus,
                password,
                offscreen,
                bounding_rectangle,
            })
        }

        fn first_child(
            &mut self,
            element: &Self::Handle,
            deadline: &Deadline,
        ) -> Result<Option<Self::Handle>, AccessibilityReadFailure> {
            self.prepare_call(deadline)?;
            self.walker_element(WALKER_FIRST_CHILD, element)
        }

        fn next_sibling(
            &mut self,
            _parent: &Self::Handle,
            element: &Self::Handle,
            deadline: &Deadline,
        ) -> Result<Option<Self::Handle>, AccessibilityReadFailure> {
            self.prepare_call(deadline)?;
            self.walker_element(WALKER_NEXT_SIBLING, element)
        }
    }

    impl InvokeSource for UiaSource {
        type InvokePattern = ComPtr;
        type ForegroundWindow = HWND;

        fn current_invoke_pattern(
            &mut self,
            element: &Self::Handle,
            deadline: &Deadline,
        ) -> Result<Option<Self::InvokePattern>, AccessibilityReadFailure> {
            self.confirm_target()?;
            self.prepare_call(deadline)?;
            UiaSource::current_invoke_pattern(self, element)
        }

        fn invoke_pattern(
            &mut self,
            pattern: &Self::InvokePattern,
            _deadline: &Deadline,
        ) -> Result<(), AccessibilityReadFailure> {
            UiaSource::invoke_pattern_handler(self, pattern)
        }

        fn foreground_window(&mut self) -> Option<Self::ForegroundWindow> {
            // SAFETY: GetForegroundWindow takes no pointers and returns the current
            // thread-safe HWND value without transferring ownership.
            let window = unsafe { GetForegroundWindow() };
            (!window.is_null()).then_some(window)
        }
    }

    fn nonempty(value: String) -> Option<String> {
        if value.is_empty() {
            None
        } else {
            Some(value)
        }
    }

    fn hresult(result: HRESULT) -> Result<(), HRESULT> {
        if result < 0 {
            Err(result)
        } else {
            Ok(())
        }
    }

    struct ProcessWindows {
        handles: Vec<HWND>,
        exceeded_bound: bool,
    }

    fn process_windows(
        pid: u32,
        max_windows: usize,
    ) -> Result<ProcessWindows, AccessibilityReadFailure> {
        let mut search = WindowSearch {
            pid,
            max_windows,
            handles: Vec::with_capacity(max_windows.min(16)),
            exceeded_bound: false,
        };
        // SAFETY: this resets only the reader thread's last-error cell so a zero
        // after `EnumWindows` cannot be stale from an earlier call.
        unsafe { SetLastError(0) };
        // SAFETY: `search` remains alive through synchronous enumeration, and the
        // callback restores this exact pointer type without retaining it.
        let completed = unsafe {
            EnumWindows(
                Some(collect_process_window),
                (&mut search as *mut WindowSearch).cast::<c_void>() as LPARAM,
            )
        };
        if completed == 0 && !search.exceeded_bound {
            // SAFETY: this immediately follows the failed enumeration on the same thread.
            let error = unsafe { GetLastError() };
            if error != 0 {
                return Err(if error == E_ACCESSDENIED as u32 {
                    AccessibilityReadFailure::PermissionRequired
                } else {
                    AccessibilityReadFailure::PlatformReadFailed
                });
            }
            return Err(AccessibilityReadFailure::PlatformReadFailed);
        }
        Ok(ProcessWindows {
            handles: search.handles,
            exceeded_bound: search.exceeded_bound,
        })
    }

    struct WindowSearch {
        pid: u32,
        max_windows: usize,
        handles: Vec<HWND>,
        exceeded_bound: bool,
    }

    unsafe extern "system" fn collect_process_window(hwnd: HWND, lparam: LPARAM) -> i32 {
        // SAFETY: `process_windows` passes this pointer to synchronous enumeration
        // and keeps the `WindowSearch` alive until the callback can no longer run.
        let search = unsafe { &mut *(lparam as *mut WindowSearch) };
        let mut window_pid = 0;
        // SAFETY: `hwnd` comes from `EnumWindows` and `window_pid` is writable.
        if unsafe { GetWindowThreadProcessId(hwnd, &mut window_pid) } == 0
            || window_pid != search.pid
        {
            return 1;
        }
        if search.handles.len() >= search.max_windows {
            search.exceeded_bound = true;
            return 0;
        }
        search.handles.push(hwnd);
        1
    }
}

#[cfg(target_os = "windows")]
pub use platform::{invoke_accessibility_element, read_accessibility_tree};

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[derive(Clone)]
    struct FakeNode {
        snapshot: ElementSnapshot,
        children: Vec<usize>,
    }

    struct FakeSource {
        roots: Vec<usize>,
        nodes: HashMap<usize, FakeNode>,
        snapshot_failure: Option<(usize, AccessibilityReadFailure)>,
        children_failure: Option<(usize, AccessibilityReadFailure)>,
        current_pattern_failure: Option<(usize, AccessibilityReadFailure)>,
        invoke_failure: Option<AccessibilityReadFailure>,
        unavailable_patterns: Vec<usize>,
        foreground_windows: Vec<Option<usize>>,
        foreground_reads: usize,
        current_pattern_calls: Vec<usize>,
        invoke_pattern_calls: Vec<usize>,
        calls: usize,
    }

    impl FakeSource {
        fn new(roots: Vec<usize>, nodes: impl IntoIterator<Item = (usize, FakeNode)>) -> Self {
            Self {
                roots,
                nodes: nodes.into_iter().collect(),
                snapshot_failure: None,
                children_failure: None,
                current_pattern_failure: None,
                invoke_failure: None,
                unavailable_patterns: Vec::new(),
                foreground_windows: vec![None],
                foreground_reads: 0,
                current_pattern_calls: Vec::new(),
                invoke_pattern_calls: Vec::new(),
                calls: 0,
            }
        }
    }

    impl ElementSource for FakeSource {
        type Handle = usize;

        fn roots(
            &mut self,
            _pid: u32,
            max_roots: usize,
            _deadline: &Deadline,
        ) -> Result<RootSnapshot<Self::Handle>, AccessibilityReadFailure> {
            let split = self.roots.len().min(max_roots);
            Ok(RootSnapshot {
                roots: self.roots[..split].to_vec(),
                unreadable_roots: (split < self.roots.len())
                    .then_some(AccessibilityReadFailure::TreeExceedsBound)
                    .into_iter()
                    .collect(),
            })
        }

        fn same_element(
            &mut self,
            left: &Self::Handle,
            right: &Self::Handle,
            _deadline: &Deadline,
        ) -> Result<bool, AccessibilityReadFailure> {
            Ok(left == right)
        }

        fn snapshot(
            &mut self,
            element: &Self::Handle,
            _deadline: &Deadline,
        ) -> Result<ElementSnapshot, AccessibilityReadFailure> {
            self.calls += 1;
            if self
                .snapshot_failure
                .is_some_and(|(failed, _)| failed == *element)
            {
                return Err(self.snapshot_failure.expect("the failure was present").1);
            }
            self.nodes
                .get(element)
                .map(|node| node.snapshot.clone())
                .ok_or(AccessibilityReadFailure::PlatformReadFailed)
        }

        fn first_child(
            &mut self,
            element: &Self::Handle,
            _deadline: &Deadline,
        ) -> Result<Option<Self::Handle>, AccessibilityReadFailure> {
            if self
                .children_failure
                .is_some_and(|(failed, _)| failed == *element)
            {
                return Err(self.children_failure.expect("the failure was present").1);
            }
            Ok(self
                .nodes
                .get(element)
                .ok_or(AccessibilityReadFailure::PlatformReadFailed)?
                .children
                .first()
                .copied())
        }

        fn next_sibling(
            &mut self,
            parent: &Self::Handle,
            element: &Self::Handle,
            _deadline: &Deadline,
        ) -> Result<Option<Self::Handle>, AccessibilityReadFailure> {
            let children = &self
                .nodes
                .get(parent)
                .ok_or(AccessibilityReadFailure::PlatformReadFailed)?
                .children;
            let index = children
                .iter()
                .position(|candidate| candidate == element)
                .ok_or(AccessibilityReadFailure::PlatformReadFailed)?;
            Ok(children.get(index.saturating_add(1)).copied())
        }
    }

    impl InvokeSource for FakeSource {
        type InvokePattern = usize;
        type ForegroundWindow = usize;

        fn current_invoke_pattern(
            &mut self,
            element: &Self::Handle,
            _deadline: &Deadline,
        ) -> Result<Option<Self::InvokePattern>, AccessibilityReadFailure> {
            self.current_pattern_calls.push(*element);
            if self
                .current_pattern_failure
                .is_some_and(|(failed, _)| failed == *element)
            {
                return Err(self
                    .current_pattern_failure
                    .expect("the failure was present")
                    .1);
            }
            Ok((!self.unavailable_patterns.contains(element)).then_some(*element))
        }

        fn invoke_pattern(
            &mut self,
            pattern: &Self::InvokePattern,
            _deadline: &Deadline,
        ) -> Result<(), AccessibilityReadFailure> {
            self.invoke_pattern_calls.push(*pattern);
            self.invoke_failure.map_or(Ok(()), Err)
        }

        fn foreground_window(&mut self) -> Option<Self::ForegroundWindow> {
            let index = self.foreground_reads;
            self.foreground_reads = self.foreground_reads.saturating_add(1);
            self.foreground_windows
                .get(index)
                .copied()
                .or_else(|| self.foreground_windows.last().copied())
                .flatten()
        }
    }

    fn node(
        automation_id: Option<&str>,
        control_type: i32,
        name: &str,
        children: Vec<usize>,
    ) -> FakeNode {
        FakeNode {
            snapshot: ElementSnapshot {
                process_id: 42,
                identity: UiaElementIdentity {
                    automation_id: automation_id.map(str::to_owned),
                    control_type_and_name: UiaControlTypeAndName {
                        control_type,
                        name: name.to_owned(),
                    },
                },
                class_name: None,
                framework_id: None,
                enabled: true,
                keyboard_focusable: false,
                has_keyboard_focus: false,
                password: false,
                offscreen: false,
                bounding_rectangle: UiaRectangle {
                    left: 0,
                    top: 0,
                    right: 10,
                    bottom: 10,
                },
            },
            children,
        }
    }

    fn bounds(max_depth: usize, max_elements: usize) -> AccessibilityReadBounds {
        AccessibilityReadBounds {
            timeout: Duration::from_secs(1),
            max_depth,
            max_elements,
        }
    }

    fn invoke_bounds(max_depth: usize, max_elements: usize) -> AccessibilityInvokeBounds {
        AccessibilityInvokeBounds {
            timeout: Duration::from_secs(1),
            max_depth,
            max_elements,
        }
    }

    #[test]
    fn duplicate_current_key_returns_match_count_without_calling_a_pattern() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(None, 1, "root", vec![1, 2])),
                (1, node(Some("duplicate"), 2, "first", Vec::new())),
                (2, node(Some("duplicate"), 2, "second", Vec::new())),
            ],
        );
        let name = UiaElementName::automation_id("duplicate");

        assert_eq!(
            invoke_accessibility_from(&mut source, 42, &name, invoke_bounds(2, 3)),
            Err(AccessibilityInvokeError::ElementNameAmbiguous {
                element_name: name,
                match_count: 2,
            })
        );
        assert!(source.current_pattern_calls.is_empty());
        assert!(source.invoke_pattern_calls.is_empty());
    }

    #[test]
    fn fresh_resolution_rejects_a_key_that_became_ambiguous_after_a_tree_read() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(None, 1, "root", vec![1])),
                (1, node(Some("target"), 2, "first", Vec::new())),
            ],
        );
        let initial = read_tree_from(&mut source, 42, bounds(1, 2)).expect("constructed read");
        assert_eq!(initial.completeness, UiaTreeCompleteness::Complete);

        source
            .nodes
            .insert(2, node(Some("target"), 2, "second", Vec::new()));
        source
            .nodes
            .get_mut(&0)
            .expect("constructed root")
            .children
            .push(2);
        let name = UiaElementName::automation_id("target");

        assert_eq!(
            invoke_accessibility_from(&mut source, 42, &name, invoke_bounds(1, 3)),
            Err(AccessibilityInvokeError::ElementNameAmbiguous {
                element_name: name,
                match_count: 2,
            })
        );
        assert!(source.current_pattern_calls.is_empty());
        assert!(source.invoke_pattern_calls.is_empty());
    }

    #[test]
    fn a_returning_fake_handler_reports_its_return_and_foreground_change() {
        let mut source = FakeSource::new(
            vec![0],
            [(0, node(Some("save"), 50_000, "Save", Vec::new()))],
        );
        source.foreground_windows = vec![Some(10), Some(11)];
        let name = UiaElementName::control_type_and_name(50_000, "Save");

        assert_eq!(
            invoke_accessibility_from(&mut source, 42, &name, invoke_bounds(0, 1)),
            Ok(AccessibilityInvokeOutcome::HandlerReturned {
                matched_by: name,
                alternate_name: Some(UiaElementName::automation_id("save")),
                unreadable_subtrees: 0,
                foreground_window_changed: true,
            })
        );
        assert_eq!(source.current_pattern_calls, vec![0]);
        assert_eq!(source.invoke_pattern_calls, vec![0]);
        assert_eq!(source.foreground_reads, 2);
    }

    #[test]
    fn a_returning_fake_handler_discloses_an_unreadable_search_subtree() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(None, 1, "root", vec![1, 2])),
                (1, node(Some("save"), 50_000, "Save", Vec::new())),
                (2, node(Some("unreadable"), 50_000, "Other", Vec::new())),
            ],
        );
        source.snapshot_failure = Some((2, AccessibilityReadFailure::TargetNotInspectable));
        let name = UiaElementName::automation_id("save");

        assert_eq!(
            invoke_accessibility_from(&mut source, 42, &name, invoke_bounds(1, 3)),
            Ok(AccessibilityInvokeOutcome::HandlerReturned {
                matched_by: name,
                alternate_name: Some(UiaElementName::control_type_and_name(50_000, "Save")),
                unreadable_subtrees: 1,
                foreground_window_changed: false,
            })
        );
        assert_eq!(source.invoke_pattern_calls, vec![1]);
    }

    #[test]
    fn an_element_without_the_invoke_pattern_never_reaches_the_fake_handler() {
        let mut source = FakeSource::new(
            vec![0],
            [(0, node(Some("save"), 50_000, "Save", Vec::new()))],
        );
        source.unavailable_patterns.push(0);
        let name = UiaElementName::automation_id("save");

        assert_eq!(
            invoke_accessibility_from(&mut source, 42, &name, invoke_bounds(0, 1)),
            Err(AccessibilityInvokeError::InvokePatternUnavailable { element_name: name })
        );
        assert_eq!(source.current_pattern_calls, vec![0]);
        assert!(source.invoke_pattern_calls.is_empty());
        assert_eq!(source.foreground_reads, 0);
    }

    #[test]
    fn readable_elements_carry_both_supported_identity_forms() {
        let mut source = FakeSource::new(
            vec![0],
            [(0, node(Some("save"), 50_000, "Save", Vec::new()))],
        );

        let tree = read_tree_from(&mut source, 42, bounds(2, 2)).expect("constructed read");

        assert_eq!(
            tree.roots[0].identity,
            UiaElementIdentity {
                automation_id: Some("save".to_owned()),
                control_type_and_name: UiaControlTypeAndName {
                    control_type: 50_000,
                    name: "Save".to_owned(),
                },
            }
        );
    }

    #[test]
    fn an_ancestor_cycle_is_a_lossless_cut() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1])),
                (1, node(Some("child"), 2, "child", vec![0])),
            ],
        );

        let tree = read_tree_from(&mut source, 42, bounds(10, 10)).expect("cycle-safe read");

        assert_eq!(tree.completeness, UiaTreeCompleteness::Complete);
        assert_eq!(tree.roots[0].children.len(), 1);
        assert!(tree.roots[0].children[0].children.is_empty());
        assert!(tree.roots[0].children[0].unreadable_children.is_empty());
        assert_eq!(source.calls, 2);
    }

    #[test]
    fn a_shared_dag_node_is_read_beneath_each_parent() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1, 2])),
                (1, node(Some("left"), 2, "left", vec![3])),
                (2, node(Some("right"), 2, "right", vec![3])),
                (3, node(Some("shared"), 3, "shared", Vec::new())),
            ],
        );

        let tree = read_tree_from(&mut source, 42, bounds(10, 10)).expect("DAG read");

        assert_eq!(tree.completeness, UiaTreeCompleteness::Complete);
        assert_eq!(
            tree.roots[0].children[0].children[0]
                .identity
                .automation_id
                .as_deref(),
            Some("shared")
        );
        assert_eq!(
            tree.roots[0].children[1].children[0]
                .identity
                .automation_id
                .as_deref(),
            Some("shared")
        );
        assert_eq!(source.calls, 5);
    }

    #[test]
    fn a_depth_bound_marks_the_unread_remainder_without_discarding_the_root() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1])),
                (1, node(Some("child"), 2, "child", vec![2])),
                (2, node(Some("omitted"), 3, "omitted", Vec::new())),
            ],
        );

        let tree = read_tree_from(&mut source, 42, bounds(1, 10)).expect("partial tree");

        assert_eq!(
            tree.completeness,
            UiaTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
        assert_eq!(tree.roots[0].children.len(), 1);
        assert_eq!(
            tree.roots[0].children[0].unreadable_children,
            vec![AccessibilityReadFailure::TreeExceedsBound]
        );
    }

    #[test]
    fn an_element_bound_preserves_elements_read_before_it() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1, 2, 3])),
                (1, node(Some("first"), 2, "first", Vec::new())),
                (2, node(Some("second"), 2, "second", Vec::new())),
                (3, node(Some("omitted"), 2, "omitted", Vec::new())),
            ],
        );

        let tree = read_tree_from(&mut source, 42, bounds(4, 3)).expect("partial tree");

        assert_eq!(tree.roots[0].children.len(), 2);
        assert_eq!(
            tree.roots[0].unreadable_children,
            vec![AccessibilityReadFailure::TreeExceedsBound]
        );
        assert_eq!(
            tree.completeness,
            UiaTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
    }

    #[test]
    fn a_descendant_deadline_returns_the_partial_tree() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1, 2])),
                (1, node(Some("readable"), 2, "readable", Vec::new())),
                (2, node(Some("slow"), 2, "slow", Vec::new())),
            ],
        );
        source.snapshot_failure = Some((2, AccessibilityReadFailure::RetryableDeadlineExceeded));

        let tree = read_tree_from(&mut source, 42, bounds(4, 10)).expect("partial tree");

        assert_eq!(tree.roots[0].children.len(), 1);
        assert_eq!(
            tree.roots[0].unreadable_children,
            vec![AccessibilityReadFailure::RetryableDeadlineExceeded]
        );
        assert_eq!(
            tree.completeness,
            UiaTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
    }

    #[test]
    fn an_unreadable_descendant_is_counted_and_readable_siblings_survive() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1, 2, 3])),
                (1, node(Some("before"), 2, "before", Vec::new())),
                (2, node(Some("unreadable"), 2, "unreadable", Vec::new())),
                (3, node(Some("after"), 2, "after", Vec::new())),
            ],
        );
        source.snapshot_failure = Some((2, AccessibilityReadFailure::TargetNotInspectable));

        let tree = read_tree_from(&mut source, 42, bounds(4, 10)).expect("partial tree");

        assert_eq!(tree.roots[0].children.len(), 2);
        assert_eq!(
            tree.roots[0].unreadable_children,
            vec![AccessibilityReadFailure::TargetNotInspectable]
        );
        assert_eq!(
            tree.completeness,
            UiaTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
    }

    #[test]
    fn target_and_permission_changes_remain_whole_read_failures() {
        for failure in [
            AccessibilityReadFailure::PermissionRequired,
            AccessibilityReadFailure::TargetGone,
            AccessibilityReadFailure::TargetReplaced,
        ] {
            let mut source =
                FakeSource::new(vec![0], [(0, node(Some("root"), 1, "root", Vec::new()))]);
            source.snapshot_failure = Some((0, failure));

            assert_eq!(read_tree_from(&mut source, 42, bounds(2, 2)), Err(failure));
        }
    }

    #[test]
    fn an_incompatible_root_value_keeps_its_exact_failure() {
        let mut source = FakeSource::new(vec![0], [(0, node(Some("root"), 1, "root", Vec::new()))]);
        source.snapshot_failure = Some((0, AccessibilityReadFailure::IncompatiblePlatformValue));

        assert_eq!(
            read_tree_from(&mut source, 42, bounds(2, 2)),
            Err(AccessibilityReadFailure::IncompatiblePlatformValue)
        );
    }

    #[test]
    fn a_bound_that_prevents_any_root_is_a_typed_failure() {
        let mut source = FakeSource::new(vec![0], [(0, node(Some("root"), 1, "root", Vec::new()))]);

        assert_eq!(
            read_tree_from(&mut source, 42, bounds(2, 0)),
            Err(AccessibilityReadFailure::TreeExceedsBound)
        );
    }

    #[test]
    fn a_cycle_cut_precedes_exhausted_depth_and_element_bounds() {
        let mut source = FakeSource::new(
            vec![0],
            [
                (0, node(Some("root"), 1, "root", vec![1])),
                (1, node(Some("child"), 2, "child", vec![0])),
            ],
        );

        let tree = read_tree_from(&mut source, 42, bounds(1, 2))
            .expect("the repeated ancestor consumes no budget");

        assert_eq!(tree.completeness, UiaTreeCompleteness::Complete);
        assert_eq!(source.calls, 2);
    }

    #[test]
    fn a_deadline_during_root_child_discovery_keeps_the_readable_root() {
        let mut source = FakeSource::new(vec![0], [(0, node(Some("root"), 1, "root", vec![1]))]);
        source.children_failure = Some((0, AccessibilityReadFailure::RetryableDeadlineExceeded));

        let tree = read_tree_from(&mut source, 42, bounds(2, 2))
            .expect("root values survive child discovery timeout");

        assert!(tree.roots[0].children.is_empty());
        assert_eq!(
            tree.roots[0].unreadable_children,
            vec![AccessibilityReadFailure::RetryableDeadlineExceeded]
        );
        assert_eq!(
            tree.completeness,
            UiaTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
    }

    #[test]
    fn zero_timeout_stops_before_source_access() {
        let mut source = FakeSource::new(vec![0], [(0, node(Some("root"), 1, "root", Vec::new()))]);
        let result = read_tree_from(
            &mut source,
            42,
            AccessibilityReadBounds {
                timeout: Duration::ZERO,
                max_depth: 2,
                max_elements: 2,
            },
        );

        assert_eq!(
            result,
            Err(AccessibilityReadFailure::RetryableDeadlineExceeded)
        );
        assert_eq!(source.calls, 0);
    }

    #[test]
    fn hresult_categories_keep_distinct_recovery_paths() {
        assert_eq!(
            failure_for_hresult(0x8007_0005_u32 as i32, TargetState::Same),
            AccessibilityReadFailure::PermissionRequired
        );
        assert_eq!(
            failure_for_hresult(0x8013_1505_u32 as i32, TargetState::Same),
            AccessibilityReadFailure::RetryableDeadlineExceeded
        );
        assert_eq!(
            failure_for_hresult(0x8004_0201_u32 as i32, TargetState::Same),
            AccessibilityReadFailure::TargetNotInspectable
        );
        assert_eq!(
            failure_for_hresult(0x8000_4005_u32 as i32, TargetState::Same),
            AccessibilityReadFailure::PlatformReadFailed
        );
        assert_eq!(
            failure_for_hresult(0x8000_4005_u32 as i32, TargetState::Gone),
            AccessibilityReadFailure::TargetGone
        );
        assert_eq!(
            failure_for_hresult(0x8000_4005_u32 as i32, TargetState::Replaced),
            AccessibilityReadFailure::TargetReplaced
        );
        assert_eq!(
            failure_for_hresult(0x8000_4005_u32 as i32, TargetState::PermissionDenied),
            AccessibilityReadFailure::PermissionRequired
        );
        assert_eq!(
            failure_for_hresult(0x8000_4005_u32 as i32, TargetState::Unknown),
            AccessibilityReadFailure::PlatformReadFailed
        );
    }
}
