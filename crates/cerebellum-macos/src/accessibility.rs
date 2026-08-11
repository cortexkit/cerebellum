//! Raw macOS accessibility values and bounded action requests.

use std::fmt;
use std::time::{Duration, Instant};

/// One rectangle in macOS screen coordinates.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AxFrame {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

/// One accessibility element and the descendants reported beneath it.
#[derive(Debug, Clone, PartialEq)]
pub struct AxElement {
    pub role: Option<String>,
    pub subrole: Option<String>,
    pub title: Option<String>,
    pub value_description: Option<String>,
    pub identifier: Option<String>,
    pub enabled: Option<bool>,
    pub focused: Option<bool>,
    pub frame: Option<AxFrame>,
    pub actions: Vec<String>,
    pub children: Vec<AxElement>,
}

/// Resource bounds applied to one accessibility-tree read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxReadOptions {
    pub timeout: Duration,
    /// Root depth is zero, so a value of zero permits only the root.
    pub max_depth: usize,
    /// Includes the root element.
    pub max_elements: usize,
}

impl Default for AxReadOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_depth: 64,
            max_elements: 10_000,
        }
    }
}

/// A non-empty `AXIdentifier` used to re-find an accessibility element.
///
/// An action request searches the current tree for this exact identifier and
/// proceeds only when exactly one element reports it. Keeping only owned text
/// here ensures a request cannot reuse an `AXUIElement` retained from an older
/// tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AxElementName(String);

impl AxElementName {
    pub fn new(identifier: impl Into<String>) -> Result<Self, AxElementNameError> {
        let identifier = identifier.into();
        if identifier.is_empty() {
            Err(AxElementNameError::EmptyIdentifier)
        } else {
            Ok(Self(identifier))
        }
    }

    pub fn identifier(&self) -> &str {
        &self.0
    }
}

/// Why an accessibility element name could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxElementNameError {
    EmptyIdentifier,
}

impl fmt::Display for AxElementNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier => formatter.write_str("an AXIdentifier cannot be empty"),
        }
    }
}

impl std::error::Error for AxElementNameError {}

/// An audited macOS accessibility action name.
///
/// This closed vocabulary prevents caller-provided strings from becoming
/// framework commands. `AXRaise` is deliberately absent because raising a
/// window is wider than asking a control to invoke its own advertised action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AxAction {
    Press,
    Increment,
    Decrement,
    Confirm,
    Cancel,
    ShowMenu,
    ShowAlternateUi,
    ShowDefaultUi,
}

impl AxAction {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Press => "AXPress",
            Self::Increment => "AXIncrement",
            Self::Decrement => "AXDecrement",
            Self::Confirm => "AXConfirm",
            Self::Cancel => "AXCancel",
            Self::ShowMenu => "AXShowMenu",
            Self::ShowAlternateUi => "AXShowAlternateUI",
            Self::ShowDefaultUi => "AXShowDefaultUI",
        }
    }

    /// Recognise only the audited standard names, including when the name came
    /// from an element's advertised action list.
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "AXPress" => Some(Self::Press),
            "AXIncrement" => Some(Self::Increment),
            "AXDecrement" => Some(Self::Decrement),
            "AXConfirm" => Some(Self::Confirm),
            "AXCancel" => Some(Self::Cancel),
            "AXShowMenu" => Some(Self::ShowMenu),
            "AXShowAlternateUI" => Some(Self::ShowAlternateUi),
            "AXShowDefaultUI" => Some(Self::ShowDefaultUi),
            _ => None,
        }
    }
}

/// Resource bounds applied to one accessibility action request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxActionOptions {
    pub timeout: Duration,
    /// Application root depth is zero, so zero permits only the root.
    pub max_depth: usize,
    /// Includes the application root and every element inspected for uniqueness.
    pub max_elements: usize,
}

impl Default for AxActionOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            max_depth: 64,
            max_elements: 10_000,
        }
    }
}

/// What a successful accessibility action request establishes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxActionRequestOutcome {
    /// The target application's action handler returned success. Accessibility
    /// does not report whether the handler changed any visible state.
    HandlerReturned,
}

/// Why an accessibility action request could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxActionError {
    PermissionNotGranted,
    NoSuchProcess {
        pid: u32,
    },
    ProcessNotAccessible {
        pid: u32,
        ax_error: i32,
    },
    ElementNotFound {
        identifier: String,
    },
    ElementIdentifierAmbiguous {
        identifier: String,
    },
    ActionNotAdvertised {
        identifier: String,
        action: AxAction,
    },
    ApplicationRefusedAction {
        identifier: String,
        action: AxAction,
        ax_error: i32,
    },
    DeadlineExceeded {
        timeout: Duration,
    },
    DepthLimitExceeded {
        max_depth: usize,
        attempted_depth: usize,
    },
    ElementLimitExceeded {
        max_elements: usize,
        attempted_elements: usize,
    },
    UnexpectedValueType {
        attribute: &'static str,
    },
    SystemCallFailed {
        operation: &'static str,
        ax_error: i32,
    },
}

impl fmt::Display for AxActionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionNotGranted => {
                formatter.write_str("accessibility permission is not granted")
            }
            Self::NoSuchProcess { pid } => write!(formatter, "process {pid} does not exist"),
            Self::ProcessNotAccessible { pid, ax_error } => write!(
                formatter,
                "process {pid} did not expose accessibility values (AX error {ax_error})"
            ),
            Self::ElementNotFound { identifier } => {
                write!(formatter, "no element reports AXIdentifier {identifier:?}")
            }
            Self::ElementIdentifierAmbiguous { identifier } => write!(
                formatter,
                "more than one element reports AXIdentifier {identifier:?}"
            ),
            Self::ActionNotAdvertised { identifier, action } => write!(
                formatter,
                "element {identifier:?} did not advertise {}",
                action.name()
            ),
            Self::ApplicationRefusedAction {
                identifier,
                action,
                ax_error,
            } => write!(
                formatter,
                "element {identifier:?} refused {} (AX error {ax_error})",
                action.name()
            ),
            Self::DeadlineExceeded { timeout } => {
                write!(
                    formatter,
                    "the accessibility action request exceeded {timeout:?}"
                )
            }
            Self::DepthLimitExceeded {
                max_depth,
                attempted_depth,
            } => write!(
                formatter,
                "the accessibility tree reached depth {attempted_depth}, beyond {max_depth}"
            ),
            Self::ElementLimitExceeded {
                max_elements,
                attempted_elements,
            } => write!(
                formatter,
                "the accessibility tree reached element {attempted_elements}, beyond {max_elements}"
            ),
            Self::UnexpectedValueType { attribute } => write!(
                formatter,
                "{attribute} had an unexpected Core Foundation type"
            ),
            Self::SystemCallFailed {
                operation,
                ax_error,
            } => write!(formatter, "{operation} returned AX error {ax_error}"),
        }
    }
}

impl std::error::Error for AxActionError {}

impl From<AxReadError> for AxActionError {
    fn from(error: AxReadError) -> Self {
        match error {
            AxReadError::PermissionNotGranted => Self::PermissionNotGranted,
            AxReadError::NoSuchProcess { pid } => Self::NoSuchProcess { pid },
            AxReadError::ProcessNotAccessible { pid, ax_error } => {
                Self::ProcessNotAccessible { pid, ax_error }
            }
            AxReadError::DeadlineExceeded { timeout } => Self::DeadlineExceeded { timeout },
            AxReadError::DepthLimitExceeded {
                max_depth,
                attempted_depth,
            } => Self::DepthLimitExceeded {
                max_depth,
                attempted_depth,
            },
            AxReadError::ElementLimitExceeded {
                max_elements,
                attempted_elements,
            } => Self::ElementLimitExceeded {
                max_elements,
                attempted_elements,
            },
            AxReadError::UnexpectedValueType { attribute } => {
                Self::UnexpectedValueType { attribute }
            }
            AxReadError::SystemCallFailed {
                operation,
                ax_error,
            } => Self::SystemCallFailed {
                operation,
                ax_error,
            },
        }
    }
}

/// Why an accessibility-tree reading could not be completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxReadError {
    PermissionNotGranted,
    NoSuchProcess {
        pid: u32,
    },
    ProcessNotAccessible {
        pid: u32,
        ax_error: i32,
    },
    DeadlineExceeded {
        timeout: Duration,
    },
    DepthLimitExceeded {
        max_depth: usize,
        attempted_depth: usize,
    },
    ElementLimitExceeded {
        max_elements: usize,
        attempted_elements: usize,
    },
    UnexpectedValueType {
        attribute: &'static str,
    },
    SystemCallFailed {
        operation: &'static str,
        ax_error: i32,
    },
}

impl fmt::Display for AxReadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PermissionNotGranted => {
                formatter.write_str("accessibility permission is not granted")
            }
            Self::NoSuchProcess { pid } => write!(formatter, "process {pid} does not exist"),
            Self::ProcessNotAccessible { pid, ax_error } => write!(
                formatter,
                "process {pid} did not expose accessibility values (AX error {ax_error})"
            ),
            Self::DeadlineExceeded { timeout } => {
                write!(formatter, "the accessibility read exceeded {timeout:?}")
            }
            Self::DepthLimitExceeded {
                max_depth,
                attempted_depth,
            } => write!(
                formatter,
                "the accessibility tree reached depth {attempted_depth}, beyond {max_depth}"
            ),
            Self::ElementLimitExceeded {
                max_elements,
                attempted_elements,
            } => write!(
                formatter,
                "the accessibility tree reached element {attempted_elements}, beyond {max_elements}"
            ),
            Self::UnexpectedValueType { attribute } => {
                write!(
                    formatter,
                    "{attribute} had an unexpected Core Foundation type"
                )
            }
            Self::SystemCallFailed {
                operation,
                ax_error,
            } => write!(formatter, "{operation} returned AX error {ax_error}"),
        }
    }
}

impl std::error::Error for AxReadError {}

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

    fn remaining(&self) -> Result<Duration, AxReadError> {
        let remaining = self.timeout.saturating_sub(self.started.elapsed());
        if remaining.is_zero() {
            Err(AxReadError::DeadlineExceeded {
                timeout: self.timeout,
            })
        } else {
            Ok(remaining)
        }
    }

    fn has_expired(&self) -> bool {
        self.timeout
            .saturating_sub(self.started.elapsed())
            .is_zero()
    }
}

#[derive(Clone)]
struct ElementSnapshot<Handle> {
    role: Option<String>,
    subrole: Option<String>,
    title: Option<String>,
    value_description: Option<String>,
    identifier: Option<String>,
    enabled: Option<bool>,
    focused: Option<bool>,
    frame: Option<AxFrame>,
    actions: Vec<String>,
    children: Vec<Handle>,
}

#[derive(Debug, Clone)]
enum SourceError {
    Ax {
        operation: &'static str,
        code: i32,
    },
    Deadline,
    DepthLimitExceeded {
        max_depth: usize,
        attempted_depth: usize,
    },
    ElementLimitExceeded {
        max_elements: usize,
        attempted_elements: usize,
    },
    UnexpectedValueType {
        attribute: &'static str,
    },
}

#[derive(Clone, Copy)]
struct ChildBudget {
    max_depth: usize,
    attempted_depth: usize,
    max_elements: usize,
    counted_elements: usize,
}

impl ChildBudget {
    fn remaining_elements(self) -> usize {
        self.max_elements.saturating_sub(self.counted_elements)
    }
}

trait ElementSource {
    type Handle: Clone;

    fn process_exists(&mut self, pid: u32) -> bool;
    fn accessibility_is_permitted(&mut self) -> bool;
    fn application(&mut self, pid: u32, deadline: &Deadline) -> Result<Self::Handle, SourceError>;
    fn snapshot(
        &mut self,
        element: &Self::Handle,
        deadline: &Deadline,
        child_budget: ChildBudget,
    ) -> Result<ElementSnapshot<Self::Handle>, SourceError>;
}

struct ActionSearchSnapshot<Handle> {
    identifier: Option<String>,
    children: Vec<Handle>,
}

#[derive(Debug, Clone)]
enum PerformSourceError {
    Ax { code: i32 },
    Deadline,
}

trait ActionSource: ElementSource {
    fn action_search_snapshot(
        &mut self,
        element: &Self::Handle,
        deadline: &Deadline,
        child_budget: ChildBudget,
    ) -> Result<ActionSearchSnapshot<Self::Handle>, SourceError>;
    fn action_names(
        &mut self,
        element: &Self::Handle,
        deadline: &Deadline,
    ) -> Result<Vec<String>, SourceError>;
    fn prepare_action(&mut self, deadline: &Deadline) -> Result<(), PerformSourceError>;
    fn perform_action(
        &mut self,
        element: &Self::Handle,
        action: AxAction,
    ) -> Result<(), PerformSourceError>;
}

const AX_ERROR_FAILURE: i32 = -25_200;
const AX_ERROR_INVALID_UI_ELEMENT: i32 = -25_202;
const AX_ERROR_CANNOT_COMPLETE: i32 = -25_204;
const AX_ERROR_ACTION_UNSUPPORTED: i32 = -25_206;
const AX_ERROR_NOT_IMPLEMENTED: i32 = -25_208;
const AX_ERROR_API_DISABLED: i32 = -25_211;

fn map_source_error<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    deadline: &Deadline,
    error: SourceError,
) -> AxReadError {
    match error {
        SourceError::Deadline => AxReadError::DeadlineExceeded {
            timeout: deadline.timeout,
        },
        SourceError::DepthLimitExceeded {
            max_depth,
            attempted_depth,
        } => AxReadError::DepthLimitExceeded {
            max_depth,
            attempted_depth,
        },
        SourceError::ElementLimitExceeded {
            max_elements,
            attempted_elements,
        } => AxReadError::ElementLimitExceeded {
            max_elements,
            attempted_elements,
        },
        SourceError::UnexpectedValueType { attribute } => {
            AxReadError::UnexpectedValueType { attribute }
        }
        SourceError::Ax { operation, code } => {
            // A target can exit or the permission can change while a synchronous
            // framework call is in flight, so both readings are repeated after
            // the failure rather than inferred from their earlier values.
            if !source.process_exists(pid) {
                AxReadError::NoSuchProcess { pid }
            } else if code == AX_ERROR_API_DISABLED || !source.accessibility_is_permitted() {
                AxReadError::PermissionNotGranted
            } else if code == AX_ERROR_CANNOT_COMPLETE && deadline.has_expired() {
                AxReadError::DeadlineExceeded {
                    timeout: deadline.timeout,
                }
            } else if matches!(
                code,
                AX_ERROR_FAILURE
                    | AX_ERROR_INVALID_UI_ELEMENT
                    | AX_ERROR_CANNOT_COMPLETE
                    | AX_ERROR_NOT_IMPLEMENTED
            ) {
                AxReadError::ProcessNotAccessible {
                    pid,
                    ax_error: code,
                }
            } else {
                AxReadError::SystemCallFailed {
                    operation,
                    ax_error: code,
                }
            }
        }
    }
}

enum ActionSearchError {
    Source(SourceError),
    AmbiguousIdentifier,
}

struct ActionSearchState<'a, Handle> {
    element_name: &'a AxElementName,
    count: usize,
    found: Option<Handle>,
    options: AxActionOptions,
    deadline: &'a Deadline,
}

fn find_action_target<Source: ActionSource>(
    source: &mut Source,
    handle: &Source::Handle,
    depth: usize,
    state: &mut ActionSearchState<'_, Source::Handle>,
) -> Result<(), ActionSearchError> {
    if depth > state.options.max_depth {
        return Err(ActionSearchError::Source(SourceError::DepthLimitExceeded {
            max_depth: state.options.max_depth,
            attempted_depth: depth,
        }));
    }
    if state.count >= state.options.max_elements {
        return Err(ActionSearchError::Source(
            SourceError::ElementLimitExceeded {
                max_elements: state.options.max_elements,
                attempted_elements: state.count.saturating_add(1),
            },
        ));
    }
    state.count += 1;
    state
        .deadline
        .remaining()
        .map_err(|_| ActionSearchError::Source(SourceError::Deadline))?;

    let next_depth = depth.saturating_add(1);
    let child_budget = ChildBudget {
        max_depth: state.options.max_depth,
        attempted_depth: next_depth,
        max_elements: state.options.max_elements,
        counted_elements: state.count,
    };
    let snapshot = source
        .action_search_snapshot(handle, state.deadline, child_budget)
        .map_err(ActionSearchError::Source)?;
    if snapshot.identifier.as_deref() == Some(state.element_name.identifier()) {
        if state.found.is_some() {
            return Err(ActionSearchError::AmbiguousIdentifier);
        }
        state.found = Some(handle.clone());
    }

    for child in &snapshot.children {
        find_action_target(source, child, next_depth, state)?;
    }
    Ok(())
}

fn map_perform_error<Source: ActionSource>(
    source: &mut Source,
    pid: u32,
    element_name: &AxElementName,
    action: AxAction,
    deadline: &Deadline,
    error: PerformSourceError,
) -> AxActionError {
    match error {
        PerformSourceError::Deadline => AxActionError::DeadlineExceeded {
            timeout: deadline.timeout,
        },
        PerformSourceError::Ax { code } => {
            // The target or the grant can disappear while its synchronous action
            // handler runs, so current facts take precedence over the AX code.
            if !source.process_exists(pid) {
                AxActionError::NoSuchProcess { pid }
            } else if code == AX_ERROR_API_DISABLED || !source.accessibility_is_permitted() {
                AxActionError::PermissionNotGranted
            } else if code == AX_ERROR_CANNOT_COMPLETE && deadline.has_expired() {
                AxActionError::DeadlineExceeded {
                    timeout: deadline.timeout,
                }
            } else if code == AX_ERROR_INVALID_UI_ELEMENT {
                AxActionError::ElementNotFound {
                    identifier: element_name.identifier().to_owned(),
                }
            } else if code == AX_ERROR_ACTION_UNSUPPORTED {
                AxActionError::ApplicationRefusedAction {
                    identifier: element_name.identifier().to_owned(),
                    action,
                    ax_error: code,
                }
            } else if matches!(
                code,
                AX_ERROR_FAILURE | AX_ERROR_CANNOT_COMPLETE | AX_ERROR_NOT_IMPLEMENTED
            ) {
                AxActionError::ProcessNotAccessible {
                    pid,
                    ax_error: code,
                }
            } else {
                AxActionError::SystemCallFailed {
                    operation: "AXUIElementPerformAction",
                    ax_error: code,
                }
            }
        }
    }
}

fn request_action_from<Source: ActionSource>(
    source: &mut Source,
    pid: u32,
    element_name: &AxElementName,
    action: AxAction,
    options: AxActionOptions,
) -> Result<AxActionRequestOutcome, AxActionError> {
    if !source.process_exists(pid) {
        return Err(AxActionError::NoSuchProcess { pid });
    }
    if !source.accessibility_is_permitted() {
        return Err(AxActionError::PermissionNotGranted);
    }

    let deadline = Deadline::new(options.timeout);
    deadline.remaining()?;
    let root = source
        .application(pid, &deadline)
        .map_err(|error| AxActionError::from(map_source_error(source, pid, &deadline, error)))?;
    let mut search = ActionSearchState {
        element_name,
        count: 0,
        found: None,
        options,
        deadline: &deadline,
    };
    match find_action_target(source, &root, 0, &mut search) {
        Ok(()) => {}
        Err(ActionSearchError::Source(error)) => {
            return Err(map_source_error(source, pid, &deadline, error).into());
        }
        Err(ActionSearchError::AmbiguousIdentifier) => {
            return Err(AxActionError::ElementIdentifierAmbiguous {
                identifier: element_name.identifier().to_owned(),
            });
        }
    }
    let element = search.found.ok_or_else(|| AxActionError::ElementNotFound {
        identifier: element_name.identifier().to_owned(),
    })?;
    deadline.remaining()?;
    let advertised_actions = source
        .action_names(&element, &deadline)
        .map_err(|error| AxActionError::from(map_source_error(source, pid, &deadline, error)))?;
    if !advertised_actions
        .iter()
        .any(|advertised| advertised == action.name())
    {
        return Err(AxActionError::ActionNotAdvertised {
            identifier: element_name.identifier().to_owned(),
            action,
        });
    }

    deadline.remaining()?;
    source
        .prepare_action(&deadline)
        .map_err(|error| map_perform_error(source, pid, element_name, action, &deadline, error))?;
    deadline.remaining()?;
    source
        .perform_action(&element, action)
        .map_err(|error| map_perform_error(source, pid, element_name, action, &deadline, error))?;
    if deadline.has_expired() {
        return Err(AxActionError::DeadlineExceeded {
            timeout: deadline.timeout,
        });
    }
    Ok(AxActionRequestOutcome::HandlerReturned)
}

fn read_tree_from<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    options: AxReadOptions,
) -> Result<AxElement, AxReadError> {
    if !source.process_exists(pid) {
        return Err(AxReadError::NoSuchProcess { pid });
    }
    if !source.accessibility_is_permitted() {
        return Err(AxReadError::PermissionNotGranted);
    }

    let deadline = Deadline::new(options.timeout);
    deadline.remaining()?;
    let root = source
        .application(pid, &deadline)
        .map_err(|error| map_source_error(source, pid, &deadline, error))?;
    let mut count = 0;
    read_element(source, pid, &root, 0, &mut count, options, &deadline)
}

fn read_element<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    handle: &Source::Handle,
    depth: usize,
    count: &mut usize,
    options: AxReadOptions,
    deadline: &Deadline,
) -> Result<AxElement, AxReadError> {
    if depth > options.max_depth {
        return Err(AxReadError::DepthLimitExceeded {
            max_depth: options.max_depth,
            attempted_depth: depth,
        });
    }
    if *count >= options.max_elements {
        return Err(AxReadError::ElementLimitExceeded {
            max_elements: options.max_elements,
            attempted_elements: count.saturating_add(1),
        });
    }
    *count += 1;
    deadline.remaining()?;

    let next_depth = depth.saturating_add(1);
    let child_budget = ChildBudget {
        max_depth: options.max_depth,
        attempted_depth: next_depth,
        max_elements: options.max_elements,
        counted_elements: *count,
    };
    let snapshot = source
        .snapshot(handle, deadline, child_budget)
        .map_err(|error| map_source_error(source, pid, deadline, error))?;
    let mut children = Vec::with_capacity(snapshot.children.len());
    for child in &snapshot.children {
        children.push(read_element(
            source, pid, child, next_depth, count, options, deadline,
        )?);
    }

    Ok(AxElement {
        role: snapshot.role,
        subrole: snapshot.subrole,
        title: snapshot.title,
        value_description: snapshot.value_description,
        identifier: snapshot.identifier,
        enabled: snapshot.enabled,
        focused: snapshot.focused,
        frame: snapshot.frame,
        actions: snapshot.actions,
        children,
    })
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{c_int, c_void};
    use std::ptr::NonNull;

    use objc2_core_foundation::{CFRetained, CFString, CGPoint, CGSize};

    use super::{
        ActionSearchSnapshot, ActionSource, AxAction, AxActionError, AxActionOptions,
        AxActionRequestOutcome, AxElement, AxElementName, AxFrame, AxReadError, AxReadOptions,
        ChildBudget, Deadline, ElementSnapshot, ElementSource, PerformSourceError, SourceError,
        AX_ERROR_API_DISABLED,
    };

    type CfTypeRef = *const c_void;

    const AX_ERROR_SUCCESS: i32 = 0;
    const AX_ERROR_ATTRIBUTE_UNSUPPORTED: i32 = -25_205;
    const AX_ERROR_NO_VALUE: i32 = -25_212;
    const AX_VALUE_CGPOINT: u32 = 1;
    const AX_VALUE_CGSIZE: u32 = 2;
    const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;

    #[repr(C)]
    struct CfRange {
        location: isize,
        length: isize,
    }

    #[link(name = "ApplicationServices", kind = "framework")]
    extern "C" {
        fn AXIsProcessTrusted() -> bool;
        fn AXUIElementCreateApplication(pid: c_int) -> CfTypeRef;
        fn AXUIElementGetTypeID() -> usize;
        fn AXUIElementSetMessagingTimeout(element: CfTypeRef, timeout: f32) -> i32;
        fn AXUIElementCopyAttributeValue(
            element: CfTypeRef,
            attribute: CfTypeRef,
            value: *mut CfTypeRef,
        ) -> i32;
        fn AXUIElementCopyActionNames(element: CfTypeRef, names: *mut CfTypeRef) -> i32;
        fn AXUIElementPerformAction(element: CfTypeRef, action: CfTypeRef) -> i32;
        fn AXValueGetTypeID() -> usize;
        fn AXValueGetType(value: CfTypeRef) -> u32;
        fn AXValueGetValue(value: CfTypeRef, value_type: u32, output: *mut c_void) -> bool;
    }

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFRetain(value: CfTypeRef) -> CfTypeRef;
        fn CFRelease(value: CfTypeRef);
        fn CFGetTypeID(value: CfTypeRef) -> usize;
        fn CFStringGetTypeID() -> usize;
        fn CFStringGetLength(value: CfTypeRef) -> isize;
        fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
        fn CFStringGetBytes(
            value: CfTypeRef,
            range: CfRange,
            encoding: u32,
            loss_byte: u8,
            is_external_representation: bool,
            buffer: *mut u8,
            max_buffer_length: isize,
            used_buffer_length: *mut isize,
        ) -> isize;
        fn CFBooleanGetTypeID() -> usize;
        fn CFBooleanGetValue(value: CfTypeRef) -> bool;
        fn CFArrayGetTypeID() -> usize;
        fn CFArrayGetCount(array: CfTypeRef) -> isize;
        fn CFArrayGetValueAtIndex(array: CfTypeRef, index: isize) -> CfTypeRef;
        #[link_name = "kill"]
        fn process_signal(pid: c_int, signal: c_int) -> c_int;
        #[link_name = "__error"]
        fn errno_location() -> *mut c_int;
    }

    struct OwnedCf(NonNull<c_void>);

    impl OwnedCf {
        /// Takes ownership of a value returned by a Create or Copy function.
        unsafe fn from_created(value: CfTypeRef) -> Option<Self> {
            NonNull::new(value.cast_mut()).map(Self)
        }

        fn as_ptr(&self) -> CfTypeRef {
            self.0.as_ptr()
        }

        fn type_id(&self) -> usize {
            // SAFETY: this wrapper is built only from a non-null retained Core
            // Foundation value and keeps it alive for this call.
            unsafe { CFGetTypeID(self.as_ptr()) }
        }
    }

    impl Clone for OwnedCf {
        fn clone(&self) -> Self {
            // SAFETY: the value is non-null and alive through `self`; CFRetain
            // creates one ownership count for the returned wrapper.
            let retained = unsafe { CFRetain(self.as_ptr()) };
            Self(NonNull::new(retained.cast_mut()).expect("CFRetain returned null"))
        }
    }

    impl Drop for OwnedCf {
        fn drop(&mut self) {
            // SAFETY: this wrapper owns exactly one retain count acquired by a
            // Create, Copy, or CFRetain call.
            unsafe { CFRelease(self.as_ptr()) };
        }
    }

    struct MacElementSource {
        application: Option<OwnedCf>,
    }

    impl MacElementSource {
        fn new() -> Self {
            Self { application: None }
        }

        fn prepare_call(&self, deadline: &Deadline) -> Result<(), SourceError> {
            let remaining = deadline.remaining().map_err(|_| SourceError::Deadline)?;
            let Some(application) = &self.application else {
                return Err(SourceError::Ax {
                    operation: "AXUIElementSetMessagingTimeout",
                    code: AX_ERROR_API_DISABLED,
                });
            };
            let seconds = remaining.as_secs_f32().max(f32::MIN_POSITIVE);
            // SAFETY: `application` is a retained AXUIElement application value.
            // This setter changes only the timeout used by subsequent
            // accessibility messages to the target application.
            let code = unsafe { AXUIElementSetMessagingTimeout(application.as_ptr(), seconds) };
            if code == AX_ERROR_SUCCESS {
                Ok(())
            } else {
                Err(SourceError::Ax {
                    operation: "AXUIElementSetMessagingTimeout",
                    code,
                })
            }
        }

        fn copy_attribute(
            &self,
            element: &OwnedCf,
            attribute_name: &'static str,
            deadline: &Deadline,
        ) -> Result<Option<OwnedCf>, SourceError> {
            self.prepare_call(deadline)?;
            let attribute = CFString::from_static_str(attribute_name);
            let mut value = std::ptr::null();
            // SAFETY: both AX element and attribute are retained for the call,
            // and `value` points to writable storage for one returned reference.
            let code = unsafe {
                AXUIElementCopyAttributeValue(
                    element.as_ptr(),
                    CFRetained::as_ptr(&attribute).as_ptr().cast(),
                    &mut value,
                )
            };
            match code {
                AX_ERROR_SUCCESS => {
                    // SAFETY: a successful Copy call returns ownership of its
                    // non-null value to the caller.
                    unsafe { OwnedCf::from_created(value) }.map(Some).ok_or(
                        SourceError::UnexpectedValueType {
                            attribute: attribute_name,
                        },
                    )
                }
                AX_ERROR_ATTRIBUTE_UNSUPPORTED | AX_ERROR_NO_VALUE => Ok(None),
                code => Err(SourceError::Ax {
                    operation: "AXUIElementCopyAttributeValue",
                    code,
                }),
            }
        }

        fn string_attribute(
            &self,
            element: &OwnedCf,
            attribute: &'static str,
            deadline: &Deadline,
        ) -> Result<Option<String>, SourceError> {
            self.copy_attribute(element, attribute, deadline)?
                .map(|value| string_from_cf(&value, attribute))
                .transpose()
        }

        fn bool_attribute(
            &self,
            element: &OwnedCf,
            attribute: &'static str,
            deadline: &Deadline,
        ) -> Result<Option<bool>, SourceError> {
            let Some(value) = self.copy_attribute(element, attribute, deadline)? else {
                return Ok(None);
            };
            // SAFETY: this function takes no arguments and returns a stable Core
            // Foundation type identifier.
            if value.type_id() != unsafe { CFBooleanGetTypeID() } {
                return Err(SourceError::UnexpectedValueType { attribute });
            }
            // SAFETY: the type-id comparison above establishes that `value` is
            // a retained CFBoolean.
            Ok(Some(unsafe { CFBooleanGetValue(value.as_ptr()) }))
        }

        fn frame_attribute(
            &self,
            element: &OwnedCf,
            deadline: &Deadline,
        ) -> Result<Option<AxFrame>, SourceError> {
            let position = self.copy_attribute(element, "AXPosition", deadline)?;
            let size = self.copy_attribute(element, "AXSize", deadline)?;
            let (Some(position), Some(size)) = (position, size) else {
                return Ok(None);
            };
            if ax_value_type(&position) != Some(AX_VALUE_CGPOINT) {
                return Err(SourceError::UnexpectedValueType {
                    attribute: "AXPosition",
                });
            }
            if ax_value_type(&size) != Some(AX_VALUE_CGSIZE) {
                return Err(SourceError::UnexpectedValueType {
                    attribute: "AXSize",
                });
            }

            let mut point = CGPoint::default();
            let mut dimensions = CGSize::default();
            // SAFETY: each type check above matches the output structure passed
            // here, and both retained AXValue objects outlive these copies.
            let point_read = unsafe {
                AXValueGetValue(
                    position.as_ptr(),
                    AX_VALUE_CGPOINT,
                    (&mut point as *mut CGPoint).cast(),
                )
            };
            // SAFETY: the retained value was checked as a CGSize AXValue, and
            // `dimensions` is writable for exactly that structure.
            let size_read = unsafe {
                AXValueGetValue(
                    size.as_ptr(),
                    AX_VALUE_CGSIZE,
                    (&mut dimensions as *mut CGSize).cast(),
                )
            };
            if !point_read {
                return Err(SourceError::UnexpectedValueType {
                    attribute: "AXPosition",
                });
            }
            if !size_read {
                return Err(SourceError::UnexpectedValueType {
                    attribute: "AXSize",
                });
            }
            Ok(Some(AxFrame {
                x: point.x,
                y: point.y,
                width: dimensions.width,
                height: dimensions.height,
            }))
        }

        fn actions(
            &self,
            element: &OwnedCf,
            deadline: &Deadline,
        ) -> Result<Vec<String>, SourceError> {
            self.prepare_call(deadline)?;
            let mut names = std::ptr::null();
            // SAFETY: the element is retained for this call and `names` points
            // to writable storage for the copied array reference.
            let code = unsafe { AXUIElementCopyActionNames(element.as_ptr(), &mut names) };
            if code != AX_ERROR_SUCCESS {
                return Err(SourceError::Ax {
                    operation: "AXUIElementCopyActionNames",
                    code,
                });
            }
            // SAFETY: a successful Copy call returns ownership of its non-null
            // array to the caller.
            let names = unsafe { OwnedCf::from_created(names) }.ok_or(
                SourceError::UnexpectedValueType {
                    attribute: "AXActionNames",
                },
            )?;
            array_strings(&names, "AXActionNames")
        }

        fn children(
            &self,
            element: &OwnedCf,
            deadline: &Deadline,
            budget: ChildBudget,
        ) -> Result<Vec<OwnedCf>, SourceError> {
            let Some(children) = self.copy_attribute(element, "AXChildren", deadline)? else {
                return Ok(Vec::new());
            };
            // SAFETY: this function takes no arguments and returns a stable type
            // identifier.
            if children.type_id() != unsafe { CFArrayGetTypeID() } {
                return Err(SourceError::UnexpectedValueType {
                    attribute: "AXChildren",
                });
            }
            // SAFETY: the type-id comparison establishes that this is a retained
            // CFArray, so its count is readable while `children` is alive.
            let count = unsafe { CFArrayGetCount(children.as_ptr()) };
            let count = usize::try_from(count).map_err(|_| SourceError::UnexpectedValueType {
                attribute: "AXChildren",
            })?;
            // Check the array's reported size before retaining or allocating for
            // any child, so a malformed array cannot consume past either bound.
            if count > 0 && budget.attempted_depth > budget.max_depth {
                return Err(SourceError::DepthLimitExceeded {
                    max_depth: budget.max_depth,
                    attempted_depth: budget.attempted_depth,
                });
            }
            if count > budget.remaining_elements() {
                return Err(SourceError::ElementLimitExceeded {
                    max_elements: budget.max_elements,
                    attempted_elements: budget.max_elements.saturating_add(1),
                });
            }
            let mut copied = Vec::with_capacity(count);
            for index in 0..count {
                // SAFETY: the index is within the count read from this retained
                // array. The returned value remains borrowed through `children`.
                let child = unsafe { CFArrayGetValueAtIndex(children.as_ptr(), index as isize) };
                if child.is_null() {
                    return Err(SourceError::UnexpectedValueType {
                        attribute: "AXChildren",
                    });
                }
                // SAFETY: the borrowed child is non-null and alive through the
                // array, and AXUIElementGetTypeID returns a stable identifier.
                if unsafe { CFGetTypeID(child) } != unsafe { AXUIElementGetTypeID() } {
                    return Err(SourceError::UnexpectedValueType {
                        attribute: "AXChildren",
                    });
                }
                // SAFETY: the child is a non-null AXUIElement borrowed from the
                // live array; CFRetain gives the new wrapper independent lifetime.
                let retained = unsafe { CFRetain(child) };
                copied.push(OwnedCf(NonNull::new(retained.cast_mut()).ok_or(
                    SourceError::UnexpectedValueType {
                        attribute: "AXChildren",
                    },
                )?));
            }
            Ok(copied)
        }
    }

    impl ElementSource for MacElementSource {
        type Handle = OwnedCf;

        fn process_exists(&mut self, pid: u32) -> bool {
            let Ok(pid) = c_int::try_from(pid) else {
                return false;
            };
            if pid <= 0 {
                return false;
            }
            // SAFETY: signal zero sends nothing; it asks the kernel whether the
            // positive pid exists and accepts the pid by value.
            let result = unsafe { process_signal(pid, 0) };
            if result == 0 {
                true
            } else {
                // `ESRCH` is the only answer meaning no process exists. `EPERM`
                // and every other failure still describe a pid that some
                // process holds, which this call cannot signal rather than one
                // that is absent.
                // SAFETY: reads thread-local errno set by `process_signal` above.
                const ESRCH: c_int = 3;
                unsafe { errno_location().read() != ESRCH }
            }
        }

        fn accessibility_is_permitted(&mut self) -> bool {
            super::accessibility_is_permitted()
        }

        fn application(
            &mut self,
            pid: u32,
            deadline: &Deadline,
        ) -> Result<Self::Handle, SourceError> {
            deadline.remaining().map_err(|_| SourceError::Deadline)?;
            let pid = c_int::try_from(pid).map_err(|_| SourceError::Ax {
                operation: "AXUIElementCreateApplication",
                code: AX_ERROR_API_DISABLED,
            })?;
            // SAFETY: creates a retained application AXUIElement for a pid
            // passed by value and performs no operation on the target process.
            let application = unsafe { AXUIElementCreateApplication(pid) };
            // SAFETY: Create transfers one retain count when it returns non-null.
            let application = unsafe { OwnedCf::from_created(application) }.ok_or(
                SourceError::UnexpectedValueType {
                    attribute: "AXApplication",
                },
            )?;
            self.application = Some(application.clone());
            self.prepare_call(deadline)?;
            Ok(application)
        }

        fn snapshot(
            &mut self,
            element: &Self::Handle,
            deadline: &Deadline,
            child_budget: ChildBudget,
        ) -> Result<ElementSnapshot<Self::Handle>, SourceError> {
            Ok(ElementSnapshot {
                role: self.string_attribute(element, "AXRole", deadline)?,
                subrole: self.string_attribute(element, "AXSubrole", deadline)?,
                title: self.string_attribute(element, "AXTitle", deadline)?,
                value_description: self.string_attribute(
                    element,
                    "AXValueDescription",
                    deadline,
                )?,
                identifier: self.string_attribute(element, "AXIdentifier", deadline)?,
                enabled: self.bool_attribute(element, "AXEnabled", deadline)?,
                focused: self.bool_attribute(element, "AXFocused", deadline)?,
                frame: self.frame_attribute(element, deadline)?,
                actions: self.actions(element, deadline)?,
                children: self.children(element, deadline, child_budget)?,
            })
        }
    }

    impl ActionSource for MacElementSource {
        fn action_search_snapshot(
            &mut self,
            element: &Self::Handle,
            deadline: &Deadline,
            child_budget: ChildBudget,
        ) -> Result<ActionSearchSnapshot<Self::Handle>, SourceError> {
            Ok(ActionSearchSnapshot {
                identifier: self.string_attribute(element, "AXIdentifier", deadline)?,
                children: self.children(element, deadline, child_budget)?,
            })
        }

        fn action_names(
            &mut self,
            element: &Self::Handle,
            deadline: &Deadline,
        ) -> Result<Vec<String>, SourceError> {
            self.actions(element, deadline)
        }

        fn prepare_action(&mut self, deadline: &Deadline) -> Result<(), PerformSourceError> {
            self.prepare_call(deadline).map_err(|error| match error {
                SourceError::Deadline => PerformSourceError::Deadline,
                SourceError::Ax { code, .. } => PerformSourceError::Ax { code },
                // Setting a timeout reads no framework value and applies no tree
                // bound, so no other source error can originate here.
                other => unreachable!("unexpected timeout setup error: {other:?}"),
            })
        }

        fn perform_action(
            &mut self,
            element: &Self::Handle,
            action: AxAction,
        ) -> Result<(), PerformSourceError> {
            let action_name = CFString::from_static_str(action.name());
            // SAFETY: the element and action string are retained for this call.
            // The call asks the application to run one advertised handler. This
            // seam sends no synthetic event and makes no separate focus or
            // window-raising request.
            let code = unsafe {
                AXUIElementPerformAction(
                    element.as_ptr(),
                    CFRetained::as_ptr(&action_name).as_ptr().cast(),
                )
            };
            if code == AX_ERROR_SUCCESS {
                Ok(())
            } else {
                Err(PerformSourceError::Ax { code })
            }
        }
    }

    fn ax_value_type(value: &OwnedCf) -> Option<u32> {
        // SAFETY: AXValueGetTypeID takes no arguments and returns a stable type
        // identifier.
        if value.type_id() != unsafe { AXValueGetTypeID() } {
            return None;
        }
        // SAFETY: the type-id comparison establishes that `value` is a retained
        // AXValue.
        Some(unsafe { AXValueGetType(value.as_ptr()) })
    }

    fn string_from_cf(value: &OwnedCf, attribute: &'static str) -> Result<String, SourceError> {
        // SAFETY: CFStringGetTypeID takes no arguments and returns a stable type
        // identifier.
        if value.type_id() != unsafe { CFStringGetTypeID() } {
            return Err(SourceError::UnexpectedValueType { attribute });
        }
        // SAFETY: the type-id comparison establishes that this is a retained
        // CFString, so its UTF-16 length is readable.
        let length = unsafe { CFStringGetLength(value.as_ptr()) };
        if length < 0 {
            return Err(SourceError::UnexpectedValueType { attribute });
        }
        // SAFETY: asks for an allocation bound for the non-negative length and
        // fixed UTF-8 encoding; it dereferences no caller-provided memory.
        let maximum = unsafe { CFStringGetMaximumSizeForEncoding(length, CF_STRING_ENCODING_UTF8) };
        let capacity =
            usize::try_from(maximum).map_err(|_| SourceError::UnexpectedValueType { attribute })?;
        if capacity == 0 {
            return Ok(String::new());
        }

        let mut bytes = vec![0; capacity];
        let mut used = 0;
        // SAFETY: `value` is a retained CFString, the range spans its complete
        // UTF-16 length, and the output pointer and capacity describe `bytes`.
        let converted = unsafe {
            CFStringGetBytes(
                value.as_ptr(),
                CfRange {
                    location: 0,
                    length,
                },
                CF_STRING_ENCODING_UTF8,
                0,
                false,
                bytes.as_mut_ptr(),
                capacity as isize,
                &mut used,
            )
        };
        if converted != length {
            return Err(SourceError::UnexpectedValueType { attribute });
        }
        let used =
            usize::try_from(used).map_err(|_| SourceError::UnexpectedValueType { attribute })?;
        bytes.truncate(used);
        String::from_utf8(bytes).map_err(|_| SourceError::UnexpectedValueType { attribute })
    }

    fn array_strings(array: &OwnedCf, attribute: &'static str) -> Result<Vec<String>, SourceError> {
        // SAFETY: CFArrayGetTypeID takes no arguments and returns a stable type
        // identifier.
        if array.type_id() != unsafe { CFArrayGetTypeID() } {
            return Err(SourceError::UnexpectedValueType { attribute });
        }
        // SAFETY: the type-id comparison establishes that this is a retained
        // CFArray, so its count is readable.
        let count = unsafe { CFArrayGetCount(array.as_ptr()) };
        let count =
            usize::try_from(count).map_err(|_| SourceError::UnexpectedValueType { attribute })?;
        let mut strings = Vec::with_capacity(count);
        for index in 0..count {
            // SAFETY: the index is within the count read from this retained
            // array, and the borrowed item remains alive through `array`.
            let item = unsafe { CFArrayGetValueAtIndex(array.as_ptr(), index as isize) };
            if item.is_null() {
                return Err(SourceError::UnexpectedValueType { attribute });
            }
            // SAFETY: the borrowed item is non-null and alive through `array`;
            // CFRetain gives the temporary wrapper one independent retain count.
            let retained = unsafe { CFRetain(item) };
            let item = OwnedCf(
                NonNull::new(retained.cast_mut())
                    .ok_or(SourceError::UnexpectedValueType { attribute })?,
            );
            strings.push(string_from_cf(&item, attribute)?);
        }
        Ok(strings)
    }

    /// Whether macOS currently permits this process to read accessibility data.
    ///
    /// `AXIsProcessTrusted` is the non-prompting query. The variant taking an
    /// options dictionary can request a prompt and is deliberately not used.
    pub fn accessibility_is_permitted() -> bool {
        // SAFETY: takes no arguments, returns a Boolean reading, and does not
        // perform an accessibility action or present a permission prompt.
        unsafe { AXIsProcessTrusted() }
    }

    /// Read the accessibility tree macOS reports for `pid`.
    ///
    /// All framework calls are attribute or action-name copies. This function
    /// never performs an accessibility action and never changes focus.
    pub fn read_accessibility_tree(
        pid: u32,
        options: AxReadOptions,
    ) -> Result<AxElement, AxReadError> {
        super::read_tree_from(&mut MacElementSource::new(), pid, options)
    }

    /// Ask one process to run an action its uniquely named current element advertises.
    ///
    /// The element is found again by exact `AXIdentifier` within the supplied
    /// bounds; no retained handle from a previous read is accepted. A successful
    /// result says only that the application's handler returned success, not that
    /// the action changed application or screen state.
    pub fn request_accessibility_action(
        pid: u32,
        element_name: &AxElementName,
        action: AxAction,
        options: AxActionOptions,
    ) -> Result<AxActionRequestOutcome, AxActionError> {
        super::request_action_from(
            &mut MacElementSource::new(),
            pid,
            element_name,
            action,
            options,
        )
    }
}

#[cfg(target_os = "macos")]
pub use platform::{
    accessibility_is_permitted, read_accessibility_tree, request_accessibility_action,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct FakeSource {
        process_exists: bool,
        permitted: bool,
        nodes: Vec<ElementSnapshot<usize>>,
        snapshot_error: Option<SourceError>,
        snapshot_delay: Duration,
        calls: usize,
        action_search_error: Option<SourceError>,
        action_search_delay: Duration,
        action_name_error: Option<SourceError>,
        perform_error: Option<PerformSourceError>,
        perform_delay: Duration,
        process_disappears_on_perform: bool,
        permission_revoked_on_perform: bool,
        application_calls: usize,
        action_search_calls: usize,
        action_name_calls: usize,
        action_timeout_calls: usize,
        perform_attempts: Vec<(usize, AxAction)>,
        performed_actions: Vec<(usize, AxAction)>,
    }

    impl FakeSource {
        fn with_nodes(nodes: Vec<ElementSnapshot<usize>>) -> Self {
            Self {
                process_exists: true,
                permitted: true,
                nodes,
                snapshot_error: None,
                snapshot_delay: Duration::ZERO,
                calls: 0,
                action_search_error: None,
                action_search_delay: Duration::ZERO,
                action_name_error: None,
                perform_error: None,
                perform_delay: Duration::ZERO,
                process_disappears_on_perform: false,
                permission_revoked_on_perform: false,
                application_calls: 0,
                action_search_calls: 0,
                action_name_calls: 0,
                action_timeout_calls: 0,
                perform_attempts: Vec::new(),
                performed_actions: Vec::new(),
            }
        }
    }

    impl ElementSource for FakeSource {
        type Handle = usize;

        fn process_exists(&mut self, _pid: u32) -> bool {
            self.process_exists
        }

        fn accessibility_is_permitted(&mut self) -> bool {
            self.permitted
        }

        fn application(
            &mut self,
            _pid: u32,
            _deadline: &Deadline,
        ) -> Result<Self::Handle, SourceError> {
            self.application_calls += 1;
            Ok(0)
        }

        fn snapshot(
            &mut self,
            element: &Self::Handle,
            _deadline: &Deadline,
            _child_budget: ChildBudget,
        ) -> Result<ElementSnapshot<Self::Handle>, SourceError> {
            self.calls += 1;
            std::thread::sleep(self.snapshot_delay);
            if let Some(error) = &self.snapshot_error {
                return Err(error.clone());
            }
            Ok(self.nodes[*element].clone())
        }
    }

    impl ActionSource for FakeSource {
        fn action_search_snapshot(
            &mut self,
            element: &Self::Handle,
            _deadline: &Deadline,
            _child_budget: ChildBudget,
        ) -> Result<ActionSearchSnapshot<Self::Handle>, SourceError> {
            self.action_search_calls += 1;
            std::thread::sleep(self.action_search_delay);
            if let Some(error) = &self.action_search_error {
                return Err(error.clone());
            }
            let node = &self.nodes[*element];
            Ok(ActionSearchSnapshot {
                identifier: node.identifier.clone(),
                children: node.children.clone(),
            })
        }

        fn action_names(
            &mut self,
            element: &Self::Handle,
            _deadline: &Deadline,
        ) -> Result<Vec<String>, SourceError> {
            self.action_name_calls += 1;
            if let Some(error) = &self.action_name_error {
                return Err(error.clone());
            }
            Ok(self.nodes[*element].actions.clone())
        }

        fn prepare_action(&mut self, _deadline: &Deadline) -> Result<(), PerformSourceError> {
            self.action_timeout_calls += 1;
            Ok(())
        }

        fn perform_action(
            &mut self,
            element: &Self::Handle,
            action: AxAction,
        ) -> Result<(), PerformSourceError> {
            self.perform_attempts.push((*element, action));
            std::thread::sleep(self.perform_delay);
            if self.process_disappears_on_perform {
                self.process_exists = false;
            }
            if self.permission_revoked_on_perform {
                self.permitted = false;
            }
            if let Some(error) = &self.perform_error {
                return Err(error.clone());
            }
            self.performed_actions.push((*element, action));
            Ok(())
        }
    }

    fn node(children: Vec<usize>) -> ElementSnapshot<usize> {
        ElementSnapshot {
            role: None,
            subrole: None,
            title: None,
            value_description: None,
            identifier: None,
            enabled: None,
            focused: None,
            frame: None,
            actions: Vec::new(),
            children,
        }
    }

    fn populated_node(
        prefix: &str,
        enabled: bool,
        focused: bool,
        frame: AxFrame,
        children: Vec<usize>,
    ) -> ElementSnapshot<usize> {
        ElementSnapshot {
            // Distinct labels make field swaps visible rather than merely proving
            // that some string survived the traversal.
            role: Some(format!("{prefix}-role")),
            subrole: Some(format!("{prefix}-subrole")),
            title: Some(format!("{prefix}-title")),
            value_description: Some(format!("{prefix}-value-description")),
            identifier: Some(format!("{prefix}-identifier")),
            enabled: Some(enabled),
            focused: Some(focused),
            frame: Some(frame),
            actions: vec![
                format!("{prefix}-first-action"),
                format!("{prefix}-second-action"),
            ],
            children,
        }
    }

    fn options(max_depth: usize, max_elements: usize) -> AxReadOptions {
        AxReadOptions {
            timeout: Duration::from_secs(1),
            max_depth,
            max_elements,
        }
    }

    fn action_node(
        identifier: Option<&str>,
        actions: &[AxAction],
        children: Vec<usize>,
    ) -> ElementSnapshot<usize> {
        let mut node = node(children);
        node.identifier = identifier.map(str::to_owned);
        node.actions = actions
            .iter()
            .map(|action| action.name().to_owned())
            .collect();
        node
    }

    fn action_options(max_depth: usize, max_elements: usize) -> AxActionOptions {
        AxActionOptions {
            timeout: Duration::from_secs(1),
            max_depth,
            max_elements,
        }
    }

    fn element_name(identifier: &str) -> AxElementName {
        AxElementName::new(identifier).expect("non-empty test identifier")
    }

    #[test]
    fn missing_values_remain_absent() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        let tree = read_tree_from(&mut source, 42, options(0, 1)).expect("read root");

        assert_eq!(
            tree,
            AxElement {
                role: None,
                subrole: None,
                title: None,
                value_description: None,
                identifier: None,
                enabled: None,
                focused: None,
                frame: None,
                actions: Vec::new(),
                children: Vec::new(),
            }
        );
    }

    #[test]
    fn populated_parent_and_child_values_round_trip_without_swaps_or_loss() {
        let parent_frame = AxFrame {
            x: 11.0,
            y: 22.0,
            width: 33.0,
            height: 44.0,
        };
        let child_frame = AxFrame {
            x: 55.0,
            y: 66.0,
            width: 77.0,
            height: 88.0,
        };
        let mut source = FakeSource::with_nodes(vec![
            populated_node("parent", true, false, parent_frame, vec![1]),
            populated_node("child", false, true, child_frame, Vec::new()),
        ]);

        assert_eq!(
            read_tree_from(&mut source, 42, options(1, 2)),
            Ok(AxElement {
                role: Some("parent-role".to_string()),
                subrole: Some("parent-subrole".to_string()),
                title: Some("parent-title".to_string()),
                value_description: Some("parent-value-description".to_string()),
                identifier: Some("parent-identifier".to_string()),
                enabled: Some(true),
                focused: Some(false),
                frame: Some(parent_frame),
                actions: vec![
                    "parent-first-action".to_string(),
                    "parent-second-action".to_string(),
                ],
                children: vec![AxElement {
                    role: Some("child-role".to_string()),
                    subrole: Some("child-subrole".to_string()),
                    title: Some("child-title".to_string()),
                    value_description: Some("child-value-description".to_string()),
                    identifier: Some("child-identifier".to_string()),
                    enabled: Some(false),
                    focused: Some(true),
                    frame: Some(child_frame),
                    actions: vec![
                        "child-first-action".to_string(),
                        "child-second-action".to_string(),
                    ],
                    children: Vec::new(),
                }],
            })
        );
    }

    #[test]
    fn depth_beyond_the_bound_is_an_exact_error() {
        let mut source = FakeSource::with_nodes(vec![node(vec![1]), node(vec![2]), node(vec![])]);
        assert_eq!(
            read_tree_from(&mut source, 42, options(1, 10)),
            Err(AxReadError::DepthLimitExceeded {
                max_depth: 1,
                attempted_depth: 2,
            })
        );
    }

    #[test]
    fn elements_beyond_the_bound_are_an_exact_error() {
        let mut source = FakeSource::with_nodes(vec![node(vec![1, 2]), node(vec![]), node(vec![])]);
        assert_eq!(
            read_tree_from(&mut source, 42, options(10, 2)),
            Err(AxReadError::ElementLimitExceeded {
                max_elements: 2,
                attempted_elements: 3,
            })
        );
    }

    #[test]
    fn an_expired_deadline_stops_before_reading_an_element() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        let zero_deadline = AxReadOptions {
            timeout: Duration::ZERO,
            max_depth: 10,
            max_elements: 10,
        };
        assert_eq!(
            read_tree_from(&mut source, 42, zero_deadline),
            Err(AxReadError::DeadlineExceeded {
                timeout: Duration::ZERO,
            })
        );
        assert_eq!(source.calls, 0, "no element read should start after expiry");
    }

    #[test]
    fn a_missing_process_stops_before_the_permission_or_tree_read() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        source.process_exists = false;
        source.permitted = false;
        assert_eq!(
            read_tree_from(&mut source, 42, options(10, 10)),
            Err(AxReadError::NoSuchProcess { pid: 42 })
        );
        assert_eq!(source.calls, 0);
    }

    #[test]
    fn missing_permission_is_an_exact_error() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        source.permitted = false;
        assert_eq!(
            read_tree_from(&mut source, 42, options(10, 10)),
            Err(AxReadError::PermissionNotGranted)
        );
        assert_eq!(source.calls, 0);
    }

    #[test]
    fn an_inaccessible_process_is_not_reported_as_missing_or_timed_out() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        source.snapshot_error = Some(SourceError::Ax {
            operation: "AXUIElementCopyAttributeValue",
            code: AX_ERROR_CANNOT_COMPLETE,
        });
        assert_eq!(
            read_tree_from(&mut source, 42, options(10, 10)),
            Err(AxReadError::ProcessNotAccessible {
                pid: 42,
                ax_error: AX_ERROR_CANNOT_COMPLETE,
            })
        );
    }

    #[test]
    fn an_ax_call_that_outlives_the_deadline_is_reported_exactly() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        source.snapshot_delay = Duration::from_millis(20);
        source.snapshot_error = Some(SourceError::Ax {
            operation: "AXUIElementCopyAttributeValue",
            code: AX_ERROR_CANNOT_COMPLETE,
        });
        let short_deadline = AxReadOptions {
            timeout: Duration::from_millis(10),
            max_depth: 10,
            max_elements: 10,
        };

        assert_eq!(
            read_tree_from(&mut source, 42, short_deadline),
            Err(AxReadError::DeadlineExceeded {
                timeout: Duration::from_millis(10),
            })
        );
        assert_eq!(source.calls, 1, "the simulated AX call reached its timeout");
    }

    #[test]
    fn an_unrecognised_ax_error_keeps_its_operation_and_code() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        source.snapshot_error = Some(SourceError::Ax {
            operation: "AXUIElementCopyActionNames",
            code: -123,
        });
        assert_eq!(
            read_tree_from(&mut source, 42, options(10, 10)),
            Err(AxReadError::SystemCallFailed {
                operation: "AXUIElementCopyActionNames",
                ax_error: -123,
            })
        );
    }

    #[test]
    fn element_names_require_a_non_empty_exact_identifier() {
        assert_eq!(
            AxElementName::new(""),
            Err(AxElementNameError::EmptyIdentifier)
        );
        assert_eq!(
            AxElementName::new("toolbar.save")
                .expect("non-empty identifier")
                .identifier(),
            "toolbar.save"
        );
    }

    #[test]
    fn only_the_closed_standard_action_names_are_recognised() {
        let supported = [
            ("AXPress", AxAction::Press),
            ("AXIncrement", AxAction::Increment),
            ("AXDecrement", AxAction::Decrement),
            ("AXConfirm", AxAction::Confirm),
            ("AXCancel", AxAction::Cancel),
            ("AXShowMenu", AxAction::ShowMenu),
            ("AXShowAlternateUI", AxAction::ShowAlternateUi),
            ("AXShowDefaultUI", AxAction::ShowDefaultUi),
        ];
        for (name, action) in supported {
            assert_eq!(AxAction::from_name(name), Some(action));
            assert_eq!(action.name(), name);
        }
        assert_eq!(AxAction::from_name("AXRaise"), None);
        assert_eq!(AxAction::from_name("AXAppPrivateAction"), None);
        assert_eq!(AxAction::from_name("axpress"), None);
    }

    #[test]
    fn a_unique_current_identifier_with_an_advertised_action_reaches_its_handler() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node(Some("other"), &[AxAction::Press], vec![]),
            action_node(Some("target"), &[AxAction::Press], vec![]),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(2, 3),
            ),
            Ok(AxActionRequestOutcome::HandlerReturned)
        );
        assert_eq!(source.action_search_calls, 3);
        assert_eq!(source.action_name_calls, 1);
        assert_eq!(source.action_timeout_calls, 1);
        assert_eq!(source.perform_attempts, vec![(2, AxAction::Press)]);
        assert_eq!(source.performed_actions, vec![(2, AxAction::Press)]);
    }

    #[test]
    fn identifier_matching_is_exact_rather_than_prefix_or_first_non_empty() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node(Some("target.child"), &[AxAction::Press], vec![]),
            action_node(Some("target"), &[AxAction::Press], vec![]),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(2, 3),
            ),
            Ok(AxActionRequestOutcome::HandlerReturned)
        );
        assert_eq!(source.performed_actions, vec![(2, AxAction::Press)]);
    }

    #[test]
    fn an_identifier_absent_from_the_current_tree_is_an_exact_error() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1]),
            action_node(Some("other"), &[AxAction::Press], vec![]),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("missing"),
                AxAction::Press,
                action_options(2, 2),
            ),
            Err(AxActionError::ElementNotFound {
                identifier: "missing".to_owned(),
            })
        );
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn a_duplicate_identifier_is_refused_before_any_action_call() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node(Some("duplicate"), &[AxAction::Press], vec![]),
            action_node(Some("duplicate"), &[AxAction::Press], vec![]),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("duplicate"),
                AxAction::Press,
                action_options(2, 3),
            ),
            Err(AxActionError::ElementIdentifierAmbiguous {
                identifier: "duplicate".to_owned(),
            })
        );
        assert_eq!(source.action_name_calls, 0);
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn an_action_the_current_element_does_not_advertise_is_refused() {
        let mut source = FakeSource::with_nodes(vec![action_node(
            Some("target"),
            &[AxAction::ShowMenu],
            vec![],
        )]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::ActionNotAdvertised {
                identifier: "target".to_owned(),
                action: AxAction::Press,
            })
        );
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn a_missing_process_and_missing_permission_stop_before_refinding() {
        let target = action_node(Some("target"), &[AxAction::Press], vec![]);
        let mut missing = FakeSource::with_nodes(vec![target.clone()]);
        missing.process_exists = false;
        missing.permitted = false;
        assert_eq!(
            request_action_from(
                &mut missing,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::NoSuchProcess { pid: 42 })
        );
        assert_eq!(missing.action_search_calls, 0);

        let mut denied = FakeSource::with_nodes(vec![target]);
        denied.permitted = false;
        assert_eq!(
            request_action_from(
                &mut denied,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::PermissionNotGranted)
        );
        assert_eq!(denied.action_search_calls, 0);
    }

    #[test]
    fn an_expired_action_deadline_stops_before_refinding() {
        let mut source = FakeSource::with_nodes(vec![action_node(
            Some("target"),
            &[AxAction::Press],
            vec![],
        )]);
        let expired = AxActionOptions {
            timeout: Duration::ZERO,
            max_depth: 0,
            max_elements: 1,
        };

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                expired,
            ),
            Err(AxActionError::DeadlineExceeded {
                timeout: Duration::ZERO,
            })
        );
        assert_eq!(source.application_calls, 0);
        assert_eq!(source.action_search_calls, 0);
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn a_deadline_expiring_during_refinding_stops_before_the_next_element() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1]),
            action_node(Some("target"), &[AxAction::Press], vec![]),
        ]);
        source.action_search_delay = Duration::from_millis(20);
        let short = AxActionOptions {
            timeout: Duration::from_millis(10),
            max_depth: 1,
            max_elements: 2,
        };

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                short,
            ),
            Err(AxActionError::DeadlineExceeded {
                timeout: Duration::from_millis(10),
            })
        );
        assert_eq!(source.action_search_calls, 1);
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn an_action_handler_returning_after_the_deadline_is_not_reported_as_success() {
        let mut source = FakeSource::with_nodes(vec![action_node(
            Some("target"),
            &[AxAction::Press],
            vec![],
        )]);
        source.perform_delay = Duration::from_millis(20);
        let short = AxActionOptions {
            timeout: Duration::from_millis(10),
            max_depth: 0,
            max_elements: 1,
        };

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                short,
            ),
            Err(AxActionError::DeadlineExceeded {
                timeout: Duration::from_millis(10),
            })
        );
        assert_eq!(source.perform_attempts, vec![(0, AxAction::Press)]);
    }

    #[test]
    fn action_refinding_obeys_depth_and_element_bounds() {
        let nodes = vec![
            action_node(None, &[], vec![1]),
            action_node(None, &[], vec![2]),
            action_node(Some("target"), &[AxAction::Press], vec![]),
        ];
        let mut depth_bounded = FakeSource::with_nodes(nodes.clone());
        assert_eq!(
            request_action_from(
                &mut depth_bounded,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(1, 3),
            ),
            Err(AxActionError::DepthLimitExceeded {
                max_depth: 1,
                attempted_depth: 2,
            })
        );
        assert!(depth_bounded.perform_attempts.is_empty());

        let mut element_bounded = FakeSource::with_nodes(nodes);
        assert_eq!(
            request_action_from(
                &mut element_bounded,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(3, 2),
            ),
            Err(AxActionError::ElementLimitExceeded {
                max_elements: 2,
                attempted_elements: 3,
            })
        );
        assert!(element_bounded.perform_attempts.is_empty());
    }

    #[test]
    fn an_advertised_action_refused_by_the_application_keeps_the_exact_ax_code() {
        let mut source = FakeSource::with_nodes(vec![action_node(
            Some("target"),
            &[AxAction::Press],
            vec![],
        )]);
        source.perform_error = Some(PerformSourceError::Ax {
            code: AX_ERROR_ACTION_UNSUPPORTED,
        });

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::ApplicationRefusedAction {
                identifier: "target".to_owned(),
                action: AxAction::Press,
                ax_error: AX_ERROR_ACTION_UNSUPPORTED,
            })
        );
        assert_eq!(source.perform_attempts, vec![(0, AxAction::Press)]);
        assert!(source.performed_actions.is_empty());
    }

    #[test]
    fn generic_ax_failures_during_perform_remain_process_access_failures() {
        for code in [
            AX_ERROR_FAILURE,
            AX_ERROR_CANNOT_COMPLETE,
            AX_ERROR_NOT_IMPLEMENTED,
        ] {
            let mut source = FakeSource::with_nodes(vec![action_node(
                Some("target"),
                &[AxAction::Press],
                vec![],
            )]);
            source.perform_error = Some(PerformSourceError::Ax { code });
            assert_eq!(
                request_action_from(
                    &mut source,
                    42,
                    &element_name("target"),
                    AxAction::Press,
                    action_options(0, 1),
                ),
                Err(AxActionError::ProcessNotAccessible {
                    pid: 42,
                    ax_error: code,
                })
            );
        }
    }

    #[test]
    fn an_element_invalidated_during_its_action_call_is_not_reported_as_a_refusal() {
        let mut source = FakeSource::with_nodes(vec![action_node(
            Some("target"),
            &[AxAction::Press],
            vec![],
        )]);
        source.perform_error = Some(PerformSourceError::Ax {
            code: AX_ERROR_INVALID_UI_ELEMENT,
        });

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::ElementNotFound {
                identifier: "target".to_owned(),
            })
        );
    }

    #[test]
    fn process_and_permission_changes_during_the_action_override_a_generic_ax_error() {
        let target = action_node(Some("target"), &[AxAction::Press], vec![]);
        let mut gone = FakeSource::with_nodes(vec![target.clone()]);
        gone.process_disappears_on_perform = true;
        gone.perform_error = Some(PerformSourceError::Ax {
            code: AX_ERROR_FAILURE,
        });
        assert_eq!(
            request_action_from(
                &mut gone,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::NoSuchProcess { pid: 42 })
        );

        let mut revoked = FakeSource::with_nodes(vec![target]);
        revoked.permission_revoked_on_perform = true;
        revoked.perform_error = Some(PerformSourceError::Ax {
            code: AX_ERROR_FAILURE,
        });
        assert_eq!(
            request_action_from(
                &mut revoked,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::PermissionNotGranted)
        );
    }

    #[test]
    fn api_disabled_and_unknown_perform_errors_map_to_distinct_exact_outcomes() {
        let target = action_node(Some("target"), &[AxAction::Press], vec![]);
        let mut disabled = FakeSource::with_nodes(vec![target.clone()]);
        disabled.perform_error = Some(PerformSourceError::Ax {
            code: AX_ERROR_API_DISABLED,
        });
        assert_eq!(
            request_action_from(
                &mut disabled,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::PermissionNotGranted)
        );

        let mut unknown = FakeSource::with_nodes(vec![target]);
        unknown.perform_error = Some(PerformSourceError::Ax { code: -123 });
        assert_eq!(
            request_action_from(
                &mut unknown,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::SystemCallFailed {
                operation: "AXUIElementPerformAction",
                ax_error: -123,
            })
        );
    }

    #[test]
    fn a_source_reported_action_deadline_maps_to_the_exact_timeout() {
        let mut source = FakeSource::with_nodes(vec![action_node(
            Some("target"),
            &[AxAction::Press],
            vec![],
        )]);
        source.perform_error = Some(PerformSourceError::Deadline);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::DeadlineExceeded {
                timeout: Duration::from_secs(1),
            })
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_non_prompting_permission_query_returns() {
        let _ = accessibility_is_permitted();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_pid_outside_the_platform_range_is_reported_as_missing() {
        assert_eq!(
            read_accessibility_tree(u32::MAX, options(10, 10)),
            Err(AxReadError::NoSuchProcess { pid: u32::MAX })
        );
    }

    /// Reads a real tree only when the process hosting this test binary has been
    /// granted macOS Accessibility permission and exposes an application root.
    /// The grant belongs to that host process, not to this Rust crate.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_test_process_tree_is_read_when_it_exposes_accessibility_values() {
        let pid = std::process::id();
        match read_accessibility_tree(pid, options(16, 1_000)) {
            Ok(tree) => {
                assert_eq!(
                    tree.role.as_deref(),
                    Some("AXApplication"),
                    "the application root reports its AX role"
                );
                eprintln!(
                    "REAL AX SAMPLE pid={pid} role={:?} title={:?} children={}",
                    tree.role,
                    tree.title,
                    tree.children.len()
                );
            }
            Err(AxReadError::PermissionNotGranted) => {
                eprintln!(
                    "SKIPPED — LIVE AX TREE NOT TESTED: Accessibility permission is not granted to the process hosting this test binary"
                );
            }
            Err(AxReadError::ProcessNotAccessible { ax_error, .. }) => {
                eprintln!(
                    "SKIPPED — LIVE AX TREE NOT TESTED: the host test process exposes no application tree (AX error {ax_error})"
                );
            }
            Err(other) => panic!("reading the live test process failed unexpectedly: {other}"),
        }
    }
}
