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

/// One readable accessibility element and the descendants reported beneath it.
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
    /// Elements reported directly beneath this one whose values could not be
    /// read. Their descendants are not visited because no successful snapshot
    /// established an `AXChildren` list that could bound a traversal.
    pub unreadable_children: Vec<AxElementReadFailure>,
}

/// The framework failure that made one reported element unreadable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxElementReadFailure {
    Accessibility {
        operation: &'static str,
        ax_error: i32,
    },
    UnexpectedValueType {
        attribute: &'static str,
    },
    /// The traversal stopped here because it had gone as deep as it may.
    ///
    /// Distinct from an accessibility failure because the cause is OURS: the
    /// application answered, and the reader declined to go further. Real trees
    /// have been observed extending past any depth set, which a bound is the
    /// only defence against — and a recursive reader that kept descending would
    /// exhaust the stack and abort the process rather than refuse.
    DepthLimitReached {
        max_depth: usize,
    },
    /// The traversal stopped here because the whole read had produced as many
    /// elements as it may. Unlike the depth bound this is a shared budget, so
    /// once it is reached no further subtree is descended anywhere.
    ElementLimitReached {
        max_elements: usize,
    },
    /// The traversal stopped here because the read ran out of time.
    ///
    /// Kept distinct from the size bounds because it reports a different fact
    /// about the application rather than about our budget: a depth or element
    /// bound says the tree is LARGER than we chose to read, while this says the
    /// application is ANSWERING TOO SLOWLY to finish. Measured on this machine,
    /// three of thirteen running applications cannot be read to completion at
    /// any deadline, because their per-element cost grows faster than linearly
    /// -- so an operator seeing this marker should not conclude that a larger
    /// budget would help, which is exactly what the size markers imply.
    DeadlineReached {
        timeout: Duration,
    },
}

/// Whether every subtree reported during one read was readable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxTreeCompleteness {
    Complete,
    Incomplete { unreadable_subtrees: usize },
}

/// A readable application root and the completeness of its traversal.
///
/// THE ELEMENTS ARE NOT A SIMULTANEOUS SNAPSHOT. Each is read in turn from a
/// live application, so the earliest are older than the latest by however long
/// the traversal took -- and that gradient is widest exactly when the tree is
/// marked incomplete by a deadline, because reaching the deadline means the
/// read took the whole budget. A caller that treats the tree as an instant is
/// acting on positions the application may have since moved; frames especially
/// are a measurement rather than a promise.
///
/// The reader cannot narrow this, since it has no way to freeze another
/// process's UI. What the caller can do is re-read immediately before acting
/// and refuse when the two disagree, which is what the action path does when it
/// re-finds an element by identifier rather than reusing a handle from a tree.
#[derive(Debug, Clone, PartialEq)]
pub struct AxAccessibilityTree {
    pub root: AxElement,
    pub completeness: AxTreeCompleteness,
}

// This type deliberately does NOT deref to its root. Reaching the elements
// through `.root` costs one word and makes a caller name the thing it is
// skipping; a deref would let a partial tree be used exactly like a complete
// one, which is how "no element matched" comes to be reported for a tree that
// never read the part the element was in.

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
            max_depth: MAX_RECURSIVE_TREE_DEPTH,
            max_elements: 10_000,
        }
    }
}

/// An owned key used to re-find an accessibility element.
///
/// The safety property is that exactly one current element matches the supplied
/// key. `AXIdentifier` was only the original way to establish that property;
/// applications often expose a unique `AXRole` and `AXTitle` pair instead.
/// Neither form falls back to the other, and both are matched exactly. An
/// element with no `AXTitle` is represented by an empty title, so untitled
/// elements with the same role collide instead of being silently excluded.
/// Keeping only owned text here also prevents a request from reusing an
/// `AXUIElement` retained from an older tree.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AxElementName {
    Identifier(String),
    RoleAndTitle { role: String, title: String },
}

impl AxElementName {
    pub fn identifier(identifier: impl Into<String>) -> Result<Self, AxElementNameError> {
        let identifier = identifier.into();
        if identifier.is_empty() {
            Err(AxElementNameError::EmptyIdentifier)
        } else {
            Ok(Self::Identifier(identifier))
        }
    }

    pub fn role_and_title(
        role: impl Into<String>,
        title: impl Into<String>,
    ) -> Result<Self, AxElementNameError> {
        let role = role.into();
        if role.is_empty() {
            Err(AxElementNameError::EmptyRole)
        } else {
            Ok(Self::RoleAndTitle {
                role,
                title: title.into(),
            })
        }
    }

    fn matches(&self, identifier: Option<&str>, role: Option<&str>, title: Option<&str>) -> bool {
        match self {
            Self::Identifier(expected) => identifier == Some(expected.as_str()),
            Self::RoleAndTitle {
                role: expected_role,
                title: expected_title,
            } => {
                role == Some(expected_role.as_str()) && title.unwrap_or_default() == expected_title
            }
        }
    }

    fn alternate_name(
        &self,
        identifier: Option<&str>,
        role: Option<&str>,
        title: Option<&str>,
    ) -> Option<Self> {
        match self {
            Self::Identifier(_) => Some(Self::RoleAndTitle {
                role: role?.to_owned(),
                title: title.unwrap_or_default().to_owned(),
            }),
            Self::RoleAndTitle { .. } => identifier.map(|value| Self::Identifier(value.to_owned())),
        }
    }
}

impl fmt::Display for AxElementName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Identifier(identifier) => write!(formatter, "AXIdentifier {identifier:?}"),
            Self::RoleAndTitle { role, title } => {
                write!(formatter, "AXRole {role:?} and AXTitle {title:?}")
            }
        }
    }
}

/// Why an accessibility element name could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxElementNameError {
    EmptyIdentifier,
    EmptyRole,
}

impl fmt::Display for AxElementNameError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyIdentifier => formatter.write_str("an AXIdentifier cannot be empty"),
            Self::EmptyRole => formatter.write_str("an AXRole cannot be empty"),
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
            max_depth: MAX_RECURSIVE_TREE_DEPTH,
            max_elements: 10_000,
        }
    }
}

// Traversal and destruction both recurse through `AxElement::children`. Keeping
// the process-wide ceiling at the default depth bounds both call stacks even
// when a caller supplies `usize::MAX`; a returned bound names this effective
// ceiling so partial reads cannot masquerade as complete ones.
const MAX_RECURSIVE_TREE_DEPTH: usize = 32;

fn supported_tree_depth(requested: usize) -> usize {
    requested.min(MAX_RECURSIVE_TREE_DEPTH)
}

/// What a successful accessibility action request establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AxActionRequestOutcome {
    /// The target application's action handler returned success. Accessibility
    /// does not report whether the handler changed any visible state.
    HandlerReturned {
        /// The exact key supplied by the caller and used for the unique match.
        matched_by: AxElementName,
        /// The other supported key, when the matched element reported one.
        alternate_name: Option<AxElementName>,
        /// Subtrees omitted from the fresh accessibility tree used for the match.
        unreadable_subtrees: usize,
    },
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
        element_name: AxElementName,
    },
    ElementIdentifierAmbiguous {
        element_name: AxElementName,
        match_count: usize,
    },
    ActionNotAdvertised {
        element_name: AxElementName,
        action: AxAction,
        /// The exact action-name list read for this refusal.
        advertised: Vec<String>,
    },
    ApplicationRefusedAction {
        element_name: AxElementName,
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
            Self::ElementNotFound { element_name } => {
                write!(formatter, "no element reports {element_name}")
            }
            Self::ElementIdentifierAmbiguous {
                element_name,
                match_count,
            } => write!(formatter, "{match_count} elements report {element_name}"),
            Self::ActionNotAdvertised {
                element_name,
                action,
                ..
            } => write!(
                formatter,
                "element named by {element_name} did not advertise {}",
                action.name()
            ),
            Self::ApplicationRefusedAction {
                element_name,
                action,
                ax_error,
            } => write!(
                formatter,
                "element named by {element_name} refused {} (AX error {ax_error})",
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

enum ElementRead {
    Readable(Box<AxElement>),
    Unreadable(AxElementReadFailure),
    // Re-entering an ancestor loses no subtree: the same element is already
    // being traversed higher on this path. It must not share the unreadable
    // outcome used by lossy resource bounds.
    ReenteredAncestor,
}

struct TreeReadState<'a> {
    pid: u32,
    count: usize,
    unreadable_subtrees: usize,
    options: AxReadOptions,
    deadline: &'a Deadline,
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

    /// Whether two handles denote the same live accessibility element.
    fn same_element(&self, left: &Self::Handle, right: &Self::Handle) -> bool;
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
    role: Option<String>,
    title: Option<String>,
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

/// Separate a failed element reading from a failure of the process-wide read.
///
/// Only copy operations directed at the current element can make that element a
/// partial result. The mapped error is still consulted because the same call can
/// reveal that the process exited, permission was revoked, or the deadline
/// elapsed; those facts concern the whole traversal and must remain typed errors.
fn element_read_failure<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    deadline: &Deadline,
    error: SourceError,
) -> Result<AxElementReadFailure, AxReadError> {
    let element_failure = match &error {
        SourceError::Ax { operation, code }
            if matches!(
                *operation,
                "AXUIElementCopyAttributeValue" | "AXUIElementCopyActionNames"
            ) =>
        {
            Some(AxElementReadFailure::Accessibility {
                operation,
                ax_error: *code,
            })
        }
        SourceError::UnexpectedValueType { attribute } => {
            Some(AxElementReadFailure::UnexpectedValueType { attribute })
        }
        // The source refuses to descend past a bound before it allocates for
        // any child. That refusal is about THIS subtree, so it stops the
        // descent here rather than discarding everything already read.
        SourceError::DepthLimitExceeded { max_depth, .. } => {
            Some(AxElementReadFailure::DepthLimitReached {
                max_depth: *max_depth,
            })
        }
        SourceError::ElementLimitExceeded { max_elements, .. } => {
            Some(AxElementReadFailure::ElementLimitReached {
                max_elements: *max_elements,
            })
        }
        // A deadline is a bound, so it gets what the depth and element bounds
        // above get: below the root it marks only this subtree unreadable and
        // the traversal so far survives. Propagating it instead would discard
        // every element already read, which tells a caller nothing at all.
        SourceError::Deadline => Some(AxElementReadFailure::DeadlineReached {
            timeout: deadline.timeout,
        }),
        _ => None,
    };
    let mapped = map_source_error(source, pid, deadline, error);
    match (element_failure, mapped) {
        (
            Some(failure),
            AxReadError::ProcessNotAccessible { .. }
            | AxReadError::UnexpectedValueType { .. }
            | AxReadError::SystemCallFailed { .. }
            | AxReadError::DepthLimitExceeded { .. }
            | AxReadError::ElementLimitExceeded { .. }
            | AxReadError::DeadlineExceeded { .. },
        ) => Ok(failure),
        (_, error) => Err(error),
    }
}

enum ActionSearchError {
    Read(AxReadError),
}

struct ActionTarget<Handle> {
    handle: Handle,
    alternate_name: Option<AxElementName>,
}

struct ActionSearchState<'a, Handle> {
    pid: u32,
    element_name: &'a AxElementName,
    count: usize,
    match_count: usize,
    found: Option<ActionTarget<Handle>>,
    unreadable_subtrees: usize,
    options: AxActionOptions,
    deadline: &'a Deadline,
}

fn find_action_target<Source: ActionSource>(
    source: &mut Source,
    handle: &Source::Handle,
    depth: usize,
    ancestors: &mut Vec<Source::Handle>,
    state: &mut ActionSearchState<'_, Source::Handle>,
) -> Result<(), ActionSearchError> {
    // Identity is checked before bounds because revisiting an ancestor needs no
    // read and consumes no budget. Reporting that lossless stop as a depth or
    // element failure would make a fully explored cyclic graph look partial.
    if ancestors
        .iter()
        .any(|ancestor| source.same_element(handle, ancestor))
    {
        return Ok(());
    }
    if depth > state.options.max_depth {
        return Err(ActionSearchError::Read(AxReadError::DepthLimitExceeded {
            max_depth: state.options.max_depth,
            attempted_depth: depth,
        }));
    }
    if state.count >= state.options.max_elements {
        return Err(ActionSearchError::Read(AxReadError::ElementLimitExceeded {
            max_elements: state.options.max_elements,
            attempted_elements: state.count.saturating_add(1),
        }));
    }
    state.count += 1;
    state
        .deadline
        .remaining()
        .map_err(ActionSearchError::Read)?;

    let next_depth = depth.saturating_add(1);
    let child_budget = ChildBudget {
        max_depth: state.options.max_depth,
        attempted_depth: next_depth,
        max_elements: state.options.max_elements,
        counted_elements: state.count,
    };
    let snapshot = match source.action_search_snapshot(handle, state.deadline, child_budget) {
        Ok(snapshot) => snapshot,
        Err(error) if depth > 0 => {
            match element_read_failure(source, state.pid, state.deadline, error) {
                Ok(_) => {
                    state.unreadable_subtrees += 1;
                    return Ok(());
                }
                Err(error) => return Err(ActionSearchError::Read(error)),
            }
        }
        Err(error) => {
            return Err(ActionSearchError::Read(map_source_error(
                source,
                state.pid,
                state.deadline,
                error,
            )))
        }
    };
    if state.element_name.matches(
        snapshot.identifier.as_deref(),
        snapshot.role.as_deref(),
        snapshot.title.as_deref(),
    ) {
        state.match_count += 1;
        if state.found.is_none() {
            state.found = Some(ActionTarget {
                handle: handle.clone(),
                alternate_name: state.element_name.alternate_name(
                    snapshot.identifier.as_deref(),
                    snapshot.role.as_deref(),
                    snapshot.title.as_deref(),
                ),
            });
        }
    }

    ancestors.push(handle.clone());
    for child in &snapshot.children {
        find_action_target(source, child, next_depth, ancestors, state)?;
    }
    ancestors.pop();
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
                    element_name: element_name.clone(),
                }
            } else if code == AX_ERROR_ACTION_UNSUPPORTED {
                AxActionError::ApplicationRefusedAction {
                    element_name: element_name.clone(),
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
    let options = AxActionOptions {
        max_depth: supported_tree_depth(options.max_depth),
        ..options
    };
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
        pid,
        element_name,
        count: 0,
        match_count: 0,
        found: None,
        unreadable_subtrees: 0,
        options,
        deadline: &deadline,
    };
    match find_action_target(source, &root, 0, &mut Vec::new(), &mut search) {
        Ok(()) => {}
        Err(ActionSearchError::Read(error)) => return Err(error.into()),
    }
    if search.match_count > 1 {
        return Err(AxActionError::ElementIdentifierAmbiguous {
            element_name: element_name.clone(),
            match_count: search.match_count,
        });
    }
    let target = search.found.ok_or_else(|| AxActionError::ElementNotFound {
        element_name: element_name.clone(),
    })?;
    let element = target.handle;
    deadline.remaining()?;
    let advertised_actions = source
        .action_names(&element, &deadline)
        .map_err(|error| AxActionError::from(map_source_error(source, pid, &deadline, error)))?;
    if !advertised_actions
        .iter()
        .any(|advertised| advertised == action.name())
    {
        return Err(AxActionError::ActionNotAdvertised {
            element_name: element_name.clone(),
            action,
            advertised: advertised_actions,
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
    Ok(AxActionRequestOutcome::HandlerReturned {
        matched_by: element_name.clone(),
        alternate_name: target.alternate_name,
        unreadable_subtrees: search.unreadable_subtrees,
    })
}

fn read_tree_from<Source: ElementSource>(
    source: &mut Source,
    pid: u32,
    options: AxReadOptions,
) -> Result<AxAccessibilityTree, AxReadError> {
    let options = AxReadOptions {
        max_depth: supported_tree_depth(options.max_depth),
        ..options
    };
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
    let mut state = TreeReadState {
        pid,
        count: 0,
        unreadable_subtrees: 0,
        options,
        deadline: &deadline,
    };
    let root = match read_element(source, &root, 0, &mut Vec::new(), &mut state)? {
        ElementRead::Readable(root) => *root,
        ElementRead::Unreadable(_) | ElementRead::ReenteredAncestor => {
            unreachable!("the application root is never converted into a partial read")
        }
    };
    let completeness = if state.unreadable_subtrees == 0 {
        AxTreeCompleteness::Complete
    } else {
        AxTreeCompleteness::Incomplete {
            unreadable_subtrees: state.unreadable_subtrees,
        }
    };
    Ok(AxAccessibilityTree { root, completeness })
}

fn read_element<Source: ElementSource>(
    source: &mut Source,
    handle: &Source::Handle,
    depth: usize,
    ancestors: &mut Vec<Source::Handle>,
    state: &mut TreeReadState<'_>,
) -> Result<ElementRead, AxReadError> {
    // Identity is checked before bounds because revisiting an ancestor needs no
    // read and consumes no budget. A bound omits an unexplored subtree and is
    // therefore incomplete; a cycle edge merely points back into a subtree that
    // this path is already traversing.
    if ancestors
        .iter()
        .any(|ancestor| source.same_element(handle, ancestor))
    {
        return Ok(ElementRead::ReenteredAncestor);
    }

    // A bound marks THIS subtree unreadable rather than discarding the whole
    // read. Everything already traversed is still true, and a caller that
    // receives an incomplete tree already refuses the decisions that need a
    // complete one — whereas an aborted read tells it nothing at all. The root
    // itself is exempt below, since a tree with no root is not a partial
    // result.
    if depth > state.options.max_depth {
        if depth > 0 {
            state.unreadable_subtrees += 1;
            return Ok(ElementRead::Unreadable(
                AxElementReadFailure::DepthLimitReached {
                    max_depth: state.options.max_depth,
                },
            ));
        }
        return Err(AxReadError::DepthLimitExceeded {
            max_depth: state.options.max_depth,
            attempted_depth: depth,
        });
    }
    if state.count >= state.options.max_elements {
        if depth > 0 {
            state.unreadable_subtrees += 1;
            return Ok(ElementRead::Unreadable(
                AxElementReadFailure::ElementLimitReached {
                    max_elements: state.options.max_elements,
                },
            ));
        }
        return Err(AxReadError::ElementLimitExceeded {
            max_elements: state.options.max_elements,
            attempted_elements: state.count.saturating_add(1),
        });
    }
    state.count += 1;
    // Same treatment as the two size bounds above: at depth the subtree is
    // marked unreadable and everything already traversed is returned, while at
    // the root there is no partial result to return.
    if state.deadline.remaining().is_err() {
        if depth > 0 {
            state.unreadable_subtrees += 1;
            return Ok(ElementRead::Unreadable(
                AxElementReadFailure::DeadlineReached {
                    timeout: state.deadline.timeout,
                },
            ));
        }
        return Err(AxReadError::DeadlineExceeded {
            timeout: state.deadline.timeout,
        });
    }

    let next_depth = depth.saturating_add(1);
    let child_budget = ChildBudget {
        max_depth: state.options.max_depth,
        attempted_depth: next_depth,
        max_elements: state.options.max_elements,
        counted_elements: state.count,
    };
    let snapshot = match source.snapshot(handle, state.deadline, child_budget) {
        Ok(snapshot) => snapshot,
        // The parent already established that this descendant exists. Preserve
        // that fact as an unreadable entry rather than turning it into an absent
        // child or ending the application-wide read.
        Err(error) if depth > 0 => {
            let failure = element_read_failure(source, state.pid, state.deadline, error)?;
            state.unreadable_subtrees += 1;
            return Ok(ElementRead::Unreadable(failure));
        }
        Err(error) => return Err(map_source_error(source, state.pid, state.deadline, error)),
    };
    let mut children = Vec::with_capacity(snapshot.children.len());
    let mut unreadable_children = Vec::new();
    ancestors.push(handle.clone());
    for child in &snapshot.children {
        match read_element(source, child, next_depth, ancestors, state)? {
            ElementRead::Readable(child) => children.push(*child),
            ElementRead::Unreadable(failure) => unreadable_children.push(failure),
            ElementRead::ReenteredAncestor => {}
        }
    }
    ancestors.pop();

    Ok(ElementRead::Readable(Box::new(AxElement {
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
        unreadable_children,
    })))
}

#[cfg(target_os = "macos")]
mod platform {
    use std::ffi::{c_int, c_void};
    use std::ptr::NonNull;

    use objc2_core_foundation::{CFRetained, CFString, CGPoint, CGSize};

    use super::{
        ActionSearchSnapshot, ActionSource, AxAccessibilityTree, AxAction, AxActionError,
        AxActionOptions, AxActionRequestOutcome, AxElementName, AxFrame, AxReadError,
        AxReadOptions, ChildBudget, Deadline, ElementSnapshot, ElementSource, PerformSourceError,
        SourceError, AX_ERROR_API_DISABLED,
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
        fn CFEqual(left: CfTypeRef, right: CfTypeRef) -> bool;
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

        fn same_element(&self, left: &Self::Handle, right: &Self::Handle) -> bool {
            // SAFETY: both wrappers retain non-null Core Foundation values for
            // the duration of the comparison. `CFEqual` does not consume them.
            unsafe { CFEqual(left.as_ptr(), right.as_ptr()) }
        }

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
                role: self.string_attribute(element, "AXRole", deadline)?,
                title: self.string_attribute(element, "AXTitle", deadline)?,
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
    ) -> Result<AxAccessibilityTree, AxReadError> {
        super::read_tree_from(&mut MacElementSource::new(), pid, options)
    }

    /// Ask one process to run an action its uniquely named current element advertises.
    ///
    /// The element is found again by the exact supplied `AXIdentifier` or
    /// `AXRole`+`AXTitle` pair within the supplied bounds; no retained handle from
    /// a previous read is accepted. A successful result says only that the
    /// application's handler returned success, not that the action changed
    /// application or screen state.
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
        snapshot_error_at: Option<(usize, SourceError)>,
        snapshot_delay: Duration,
        application_delay: Duration,
        process_disappears_on_snapshot_error: bool,
        permission_revoked_on_snapshot_error: bool,
        calls: usize,
        action_search_error: Option<SourceError>,
        action_search_error_at: Option<(usize, SourceError)>,
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
                snapshot_error_at: None,
                snapshot_delay: Duration::ZERO,
                application_delay: Duration::ZERO,
                process_disappears_on_snapshot_error: false,
                permission_revoked_on_snapshot_error: false,
                calls: 0,
                action_search_error: None,
                action_search_error_at: None,
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

        fn same_element(&self, left: &Self::Handle, right: &Self::Handle) -> bool {
            left == right
        }

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
            std::thread::sleep(self.application_delay);
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
            let error = self.snapshot_error.clone().or_else(|| {
                self.snapshot_error_at
                    .as_ref()
                    .and_then(|(failing_element, error)| {
                        (element == failing_element).then(|| error.clone())
                    })
            });
            if let Some(error) = error {
                if self.process_disappears_on_snapshot_error {
                    self.process_exists = false;
                }
                if self.permission_revoked_on_snapshot_error {
                    self.permitted = false;
                }
                return Err(error);
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
            if let Some((failing_element, error)) = &self.action_search_error_at {
                if element == failing_element {
                    return Err(error.clone());
                }
            }
            let node = &self.nodes[*element];
            Ok(ActionSearchSnapshot {
                identifier: node.identifier.clone(),
                role: node.role.clone(),
                title: node.title.clone(),
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
        action_node_with_keys(identifier, None, None, actions, children)
    }

    fn action_node_with_keys(
        identifier: Option<&str>,
        role: Option<&str>,
        title: Option<&str>,
        actions: &[AxAction],
        children: Vec<usize>,
    ) -> ElementSnapshot<usize> {
        let mut node = node(children);
        node.identifier = identifier.map(str::to_owned);
        node.role = role.map(str::to_owned);
        node.title = title.map(str::to_owned);
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
        AxElementName::identifier(identifier).expect("non-empty test identifier")
    }

    fn role_title_name(role: &str, title: &str) -> AxElementName {
        AxElementName::role_and_title(role, title).expect("non-empty test role")
    }

    fn identifier_outcome(
        identifier: &str,
        alternate_name: Option<AxElementName>,
    ) -> AxActionRequestOutcome {
        AxActionRequestOutcome::HandlerReturned {
            matched_by: element_name(identifier),
            alternate_name,
            unreadable_subtrees: 0,
        }
    }

    #[test]
    fn missing_values_remain_absent() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        let tree = read_tree_from(&mut source, 42, options(0, 1)).expect("read root");

        assert_eq!(
            tree,
            AxAccessibilityTree {
                root: AxElement {
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
                    unreadable_children: Vec::new(),
                },
                completeness: AxTreeCompleteness::Complete,
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
            Ok(AxAccessibilityTree {
                root: AxElement {
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
                        unreadable_children: Vec::new(),
                    }],
                    unreadable_children: Vec::new(),
                },
                completeness: AxTreeCompleteness::Complete,
            })
        );
    }

    #[test]
    fn a_named_unreadable_element_preserves_readable_siblings_and_marks_tree_incomplete() {
        let mut source = FakeSource::with_nodes(vec![
            node(vec![1, 2, 3]),
            action_node(Some("readable-before"), &[], vec![]),
            action_node(Some("unreadable-named"), &[], vec![]),
            action_node(Some("readable-after"), &[], vec![]),
        ]);
        source.snapshot_error_at = Some((
            2,
            SourceError::Ax {
                operation: "AXUIElementCopyAttributeValue",
                code: AX_ERROR_FAILURE,
            },
        ));

        let tree = read_tree_from(&mut source, 42, options(1, 4))
            .expect("one unreadable descendant must not abort the tree read");

        assert_eq!(
            tree.completeness,
            AxTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
        assert_eq!(
            tree.root.children,
            vec![
                AxElement {
                    role: None,
                    subrole: None,
                    title: None,
                    value_description: None,
                    identifier: Some("readable-before".to_string()),
                    enabled: None,
                    focused: None,
                    frame: None,
                    actions: Vec::new(),
                    children: Vec::new(),
                    unreadable_children: Vec::new(),
                },
                AxElement {
                    role: None,
                    subrole: None,
                    title: None,
                    value_description: None,
                    identifier: Some("readable-after".to_string()),
                    enabled: None,
                    focused: None,
                    frame: None,
                    actions: Vec::new(),
                    children: Vec::new(),
                    unreadable_children: Vec::new(),
                },
            ]
        );
        assert_eq!(
            tree.root.unreadable_children,
            vec![AxElementReadFailure::Accessibility {
                operation: "AXUIElementCopyAttributeValue",
                ax_error: AX_ERROR_FAILURE,
            }]
        );
        assert_eq!(
            source.calls, 4,
            "the fixture must exercise readable elements on both sides of the failure"
        );
    }

    #[test]
    fn process_and_permission_loss_during_a_descendant_read_remain_whole_tree_errors() {
        let failure = SourceError::Ax {
            operation: "AXUIElementCopyAttributeValue",
            code: AX_ERROR_FAILURE,
        };

        let mut gone = FakeSource::with_nodes(vec![node(vec![1]), node(vec![])]);
        gone.snapshot_error_at = Some((1, failure.clone()));
        gone.process_disappears_on_snapshot_error = true;
        assert_eq!(
            read_tree_from(&mut gone, 42, options(1, 2)),
            Err(AxReadError::NoSuchProcess { pid: 42 })
        );

        let mut denied = FakeSource::with_nodes(vec![node(vec![1]), node(vec![])]);
        denied.snapshot_error_at = Some((1, failure));
        denied.permission_revoked_on_snapshot_error = true;
        assert_eq!(
            read_tree_from(&mut denied, 42, options(1, 2)),
            Err(AxReadError::PermissionNotGranted)
        );
    }

    #[test]
    fn an_ancestor_cycle_is_lossless_and_keeps_the_tree_complete() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(Some("application"), &[], vec![1]),
            action_node(Some("window"), &[], vec![0]),
        ]);

        let tree = read_tree_from(&mut source, 42, options(usize::MAX, usize::MAX))
            .expect("an ancestor edge is a lossless traversal stop");

        assert_eq!(tree.completeness, AxTreeCompleteness::Complete);
        assert_eq!(tree.root.identifier.as_deref(), Some("application"));
        assert_eq!(tree.root.children.len(), 1);
        assert_eq!(tree.root.children[0].identifier.as_deref(), Some("window"));
        assert_eq!(tree.root.children[0].children, Vec::new());
        assert_eq!(tree.root.children[0].unreadable_children, Vec::new());
        assert_eq!(source.calls, 2, "each cyclic element is read exactly once");
    }

    #[test]
    fn a_shared_dag_child_is_read_once_under_each_parent() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(Some("root"), &[], vec![1, 2]),
            action_node(Some("left"), &[], vec![3]),
            action_node(Some("right"), &[], vec![3]),
            action_node(Some("shared"), &[], vec![]),
        ]);

        let tree = read_tree_from(&mut source, 42, options(usize::MAX, usize::MAX))
            .expect("sharing outside the current path is not a cycle");

        assert_eq!(tree.completeness, AxTreeCompleteness::Complete);
        assert_eq!(tree.root.children.len(), 2);
        assert_eq!(
            tree.root.children[0].children[0].identifier.as_deref(),
            Some("shared")
        );
        assert_eq!(
            tree.root.children[1].children[0].identifier.as_deref(),
            Some("shared")
        );
        assert_eq!(
            source.calls, 5,
            "the shared element must be read along both non-cyclic paths"
        );
    }

    #[test]
    fn caller_supplied_depth_is_capped_at_the_stack_safe_limit() {
        let mut nodes: Vec<_> = (0..128).map(|index| node(vec![index + 1])).collect();
        nodes.push(node(vec![]));
        let mut source = FakeSource::with_nodes(nodes);

        let tree = read_tree_from(&mut source, 42, options(usize::MAX, usize::MAX))
            .expect("the structural depth cap returns a partial tree");
        let mut deepest = &tree.root;
        let mut elements = 1;
        while let Some(child) = deepest.children.first() {
            elements += 1;
            deepest = child;
        }

        assert_eq!(elements, MAX_RECURSIVE_TREE_DEPTH + 1);
        assert_eq!(
            deepest.unreadable_children,
            vec![AxElementReadFailure::DepthLimitReached {
                max_depth: MAX_RECURSIVE_TREE_DEPTH,
            }]
        );
        assert_eq!(
            tree.completeness,
            AxTreeCompleteness::Incomplete {
                unreadable_subtrees: 1,
            }
        );
    }

    #[test]
    fn a_ten_thousand_element_chain_reads_and_drops_on_a_small_stack() {
        const ELEMENTS: usize = 10_000;
        let thread = std::thread::Builder::new()
            .name("bounded-ax-deep-chain".to_string())
            .stack_size(128 * 1024)
            .spawn(|| {
                let mut nodes: Vec<_> = (0..ELEMENTS - 1)
                    .map(|index| node(vec![index + 1]))
                    .collect();
                nodes.push(node(vec![]));
                let mut source = FakeSource::with_nodes(nodes);
                let tree = read_tree_from(&mut source, 42, options(usize::MAX, usize::MAX))
                    .expect("a deep source is bounded before either recursive stack grows");
                assert_eq!(
                    tree.completeness,
                    AxTreeCompleteness::Incomplete {
                        unreadable_subtrees: 1,
                    }
                );
                assert_eq!(source.calls, MAX_RECURSIVE_TREE_DEPTH + 1);
                drop(tree);
            })
            .expect("create a small-stack thread");

        match thread.join() {
            Ok(()) => {}
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }

    /// Reaching the depth bound stops that subtree and keeps the rest.
    ///
    /// The bound is OUR limit rather than the application's failure, so what was
    /// already read is still true and is returned. Real trees have been observed
    /// extending past every depth tried, so discarding the read would mean
    /// returning nothing at all for such an application.
    ///
    /// The tree is marked incomplete so callers can disclose the omitted scope
    /// instead of treating the readable elements as the application's complete
    /// accessibility surface.
    #[test]
    fn reaching_the_depth_bound_stops_that_subtree_and_keeps_the_rest() {
        let mut source = FakeSource::with_nodes(vec![node(vec![1]), node(vec![2]), node(vec![])]);
        let tree = read_tree_from(&mut source, 42, options(1, 10)).expect("the read completes");

        assert_eq!(
            tree.completeness,
            AxTreeCompleteness::Incomplete {
                unreadable_subtrees: 1
            }
        );
        // The element AT the bound is present; only its children are missing,
        // and they are named as bounded rather than reported as absent.
        assert_eq!(tree.root.children.len(), 1);
        assert!(tree.root.children[0].children.is_empty());
        assert_eq!(
            tree.root.children[0].unreadable_children,
            vec![AxElementReadFailure::DepthLimitReached { max_depth: 1 }]
        );
    }

    /// The root itself hitting the bound is still a whole-read error.
    ///
    /// A tree with no root is not a partial result: there is nothing to return
    /// and nothing a caller could do with it.
    #[test]
    fn a_bound_that_stops_the_root_is_a_whole_read_error() {
        let mut source = FakeSource::with_nodes(vec![node(vec![])]);
        assert_eq!(
            read_tree_from(&mut source, 42, options(0, 0)),
            Err(AxReadError::ElementLimitExceeded {
                max_elements: 0,
                attempted_elements: 1,
            })
        );
    }

    /// Reaching the element budget stops further subtrees and keeps the rest.
    ///
    /// Unlike the depth bound this budget is shared across the whole read, so
    /// once it is reached nothing further is descended anywhere.
    #[test]
    fn reaching_the_element_budget_stops_further_subtrees_and_keeps_the_rest() {
        let mut source = FakeSource::with_nodes(vec![node(vec![1, 2]), node(vec![]), node(vec![])]);
        let tree = read_tree_from(&mut source, 42, options(10, 2)).expect("the read completes");

        assert_eq!(
            tree.completeness,
            AxTreeCompleteness::Incomplete {
                unreadable_subtrees: 1
            }
        );
        assert_eq!(tree.root.children.len(), 1);
        assert_eq!(
            tree.root.unreadable_children,
            vec![AxElementReadFailure::ElementLimitReached { max_elements: 2 }]
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

    /// A deadline reached below the root truncates that subtree and keeps the
    /// rest, the same treatment the depth and element bounds already get.
    ///
    /// This is what makes a slow application observable at all. Measured on
    /// this machine, three of thirteen running applications exceed every
    /// deadline tried, up to 40s, because their per-element cost grows faster
    /// than linearly -- so an all-or-nothing deadline returns literally nothing
    /// for them, at any budget. Nothing becomes actuatable: an incomplete tree
    /// cannot establish uniqueness, so the action path refuses it either way.
    #[test]
    fn a_deadline_below_the_root_truncates_that_subtree_and_keeps_the_rest() {
        let mut source =
            FakeSource::with_nodes(vec![node(vec![1, 2]), node(Vec::new()), node(Vec::new())]);
        // Injected rather than timed. A sleep-based fixture would assert over
        // wall-clock on a machine that also runs builds, and a sleep only ever
        // overshoots, so the count it proves would drift under load.
        source.snapshot_error_at = Some((2, SourceError::Deadline));
        let timeout = Duration::from_millis(50);
        let options = AxReadOptions {
            timeout,
            max_depth: 10,
            max_elements: 10,
        };

        let tree = read_tree_from(&mut source, 42, options).expect("a partial tree, not a refusal");
        assert_eq!(
            tree.completeness,
            AxTreeCompleteness::Incomplete {
                unreadable_subtrees: 1
            },
            "the truncated subtree must be counted, since a caller deciding \
             uniqueness needs to know the read is partial"
        );
        assert_eq!(
            tree.root.unreadable_children,
            vec![AxElementReadFailure::DeadlineReached { timeout }],
            "the reason must name the deadline: a size bound implies a larger \
             budget would help, and here no budget does"
        );
        assert_eq!(
            tree.root.children.len(),
            1,
            "everything read before the deadline is still true and must survive"
        );
    }

    /// The same truncation, reached by the reader's own budget check rather
    /// than by a source reporting a deadline.
    ///
    /// Two independent paths produce this marker and each can be deleted
    /// without the other noticing: the reader checks the remaining budget
    /// before descending, and the error mapping converts a source-reported
    /// deadline. The preceding test injects the error, so it exercises only the
    /// mapping; this one lets the clock run out, so it exercises only the
    /// check. Both are needed to fence the behaviour.
    #[test]
    fn an_elapsed_budget_truncates_the_next_element_rather_than_the_read() {
        let mut source = FakeSource::with_nodes(vec![node(vec![1]), node(Vec::new())]);
        // The root's own snapshot spends more than the whole budget, so by the
        // time its child is reached the clock has certainly run out. A sleep
        // only ever overshoots, so this cannot go the other way under load.
        source.snapshot_delay = Duration::from_millis(80);
        let timeout = Duration::from_millis(50);
        let options = AxReadOptions {
            timeout,
            max_depth: 10,
            max_elements: 10,
        };

        let tree = read_tree_from(&mut source, 42, options).expect("a partial tree, not a refusal");
        assert_eq!(
            tree.completeness,
            AxTreeCompleteness::Incomplete {
                unreadable_subtrees: 1
            }
        );
        assert_eq!(
            tree.root.unreadable_children,
            vec![AxElementReadFailure::DeadlineReached { timeout }]
        );
        assert_eq!(
            source.calls, 1,
            "the child was never snapshotted: the budget was spent before it was reached"
        );
    }

    /// The root is exempt: a tree with no root is not a partial result.
    ///
    /// The boundary is worth its own arm because it is where the graceful arm
    /// above is tempting to extend one step too far.
    #[test]
    fn a_deadline_at_the_root_is_still_a_hard_refusal() {
        let mut source = FakeSource::with_nodes(vec![node(Vec::new())]);
        // Spend the budget resolving the application, which the real source can
        // also do, so the root's own deadline check is the thing under test
        // rather than a later one.
        source.application_delay = Duration::from_millis(20);
        let options = AxReadOptions {
            timeout: Duration::from_millis(5),
            max_depth: 10,
            max_elements: 10,
        };

        assert_eq!(
            read_tree_from(&mut source, 42, options),
            Err(AxReadError::DeadlineExceeded {
                timeout: Duration::from_millis(5),
            })
        );
        assert_eq!(
            source.calls, 0,
            "the root was never snapshotted, so there is no partial tree to return"
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
    fn element_names_reject_empty_required_parts_and_keep_exact_values() {
        assert_eq!(
            AxElementName::identifier(""),
            Err(AxElementNameError::EmptyIdentifier)
        );
        assert_eq!(
            AxElementName::role_and_title("", "Save"),
            Err(AxElementNameError::EmptyRole)
        );
        assert_eq!(
            AxElementName::identifier("toolbar.save").expect("non-empty identifier"),
            AxElementName::Identifier("toolbar.save".to_owned())
        );
        assert_eq!(
            AxElementName::role_and_title("AXButton", "").expect("non-empty role"),
            AxElementName::RoleAndTitle {
                role: "AXButton".to_owned(),
                title: String::new(),
            }
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

    /// An element reachable by two paths is still entered on both of them.
    ///
    /// The cycle check is scoped to the CURRENT ANCESTOR PATH. Were it a global
    /// visited set, the second parent would find its child already seen and skip
    /// it, so the search would report ONE match where two paths reach the name
    /// and would actuate on an identifier whose uniqueness it never established.
    /// Refusing is the safe answer: this reader cannot tell one element reached
    /// twice from two elements answering to one name, and acting on either
    /// reading is how an action lands on a control nobody chose.
    ///
    /// The tree read has its own DAG fixture; this one drives the ACTION SEARCH,
    /// because that is the path where uniqueness is decided.
    #[test]
    fn an_element_reachable_by_two_paths_is_entered_on_both() {
        // root -> {left, right}, and BOTH point at the same `shared` node, which
        // carries the identifier being searched for.
        let mut source = FakeSource::with_nodes(vec![
            action_node(Some("root"), &[], vec![1, 2]),
            action_node(Some("left"), &[], vec![3]),
            action_node(Some("right"), &[], vec![3]),
            action_node(Some("target"), &[AxAction::Press], vec![]),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(usize::MAX, usize::MAX),
            ),
            Err(AxActionError::ElementIdentifierAmbiguous {
                element_name: element_name("target"),
                match_count: 2,
            })
        );
        assert!(
            source.performed_actions.is_empty(),
            "an action ran on an identifier whose uniqueness was not established"
        );
    }

    #[test]
    fn action_refinding_stops_an_ancestor_cycle_without_losing_uniqueness() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1]),
            action_node(Some("target"), &[AxAction::Press], vec![0]),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(usize::MAX, usize::MAX),
            ),
            Ok(identifier_outcome("target", None))
        );
        assert_eq!(source.action_search_calls, 2);
        assert_eq!(source.performed_actions, vec![(1, AxAction::Press)]);
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
            Ok(identifier_outcome("target", None))
        );
        assert_eq!(source.action_search_calls, 3);
        assert_eq!(source.action_name_calls, 1);
        assert_eq!(source.action_timeout_calls, 1);
        assert_eq!(source.perform_attempts, vec![(2, AxAction::Press)]);
        assert_eq!(source.performed_actions, vec![(2, AxAction::Press)]);
    }

    #[test]
    fn a_unique_role_and_title_reaches_its_handler_and_echoes_both_keys() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node_with_keys(
                Some("other-id"),
                Some("AXButton"),
                Some("Other"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("save-id"),
                Some("AXButton"),
                Some("Save"),
                &[AxAction::Press],
                vec![],
            ),
        ]);
        let matched_by = role_title_name("AXButton", "Save");

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &matched_by,
                AxAction::Press,
                action_options(2, 3),
            ),
            Ok(AxActionRequestOutcome::HandlerReturned {
                matched_by,
                alternate_name: Some(element_name("save-id")),
                unreadable_subtrees: 0,
            })
        );
        assert_eq!(source.performed_actions, vec![(2, AxAction::Press)]);
    }

    #[test]
    fn identifier_success_echoes_the_supplied_key_and_the_role_title_key() {
        let mut source = FakeSource::with_nodes(vec![action_node_with_keys(
            Some("save-id"),
            Some("AXButton"),
            Some("Save"),
            &[AxAction::Press],
            vec![],
        )]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("save-id"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Ok(identifier_outcome(
                "save-id",
                Some(role_title_name("AXButton", "Save")),
            ))
        );
    }

    #[test]
    fn an_identifier_request_does_not_fall_back_to_a_role_and_title_match() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2, 3, 4]),
            // This role+title resembles the requested identifier but carries no
            // identifier, so accepting it would silently change key forms.
            action_node_with_keys(
                None,
                Some("AXButton"),
                Some("target"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("shared-id"),
                Some("AXButton"),
                Some("Duplicate"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("shared-id"),
                Some("AXLink"),
                Some("Other"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("unique-id"),
                Some("AXButton"),
                Some("Duplicate"),
                &[AxAction::Press],
                vec![],
            ),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(2, 5),
            ),
            Err(AxActionError::ElementNotFound {
                element_name: element_name("target"),
            })
        );
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn an_absent_role_and_title_is_reported_with_the_supplied_key() {
        let mut source = FakeSource::with_nodes(vec![action_node_with_keys(
            Some("save-id"),
            Some("AXButton"),
            Some("Other"),
            &[AxAction::Press],
            vec![],
        )]);
        let missing_name = role_title_name("AXButton", "Save");

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &missing_name,
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::ElementNotFound {
                element_name: missing_name,
            })
        );
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn three_role_and_title_matches_are_refused_with_key_form_and_count() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2, 3]),
            action_node_with_keys(
                Some("first-id"),
                Some("AXButton"),
                Some("Save"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("second-id"),
                Some("AXButton"),
                Some("Save"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                None,
                Some("AXButton"),
                Some("Save"),
                &[AxAction::Press],
                vec![],
            ),
        ]);
        let ambiguous_name = role_title_name("AXButton", "Save");

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &ambiguous_name,
                AxAction::Press,
                action_options(2, 4),
            ),
            Err(AxActionError::ElementIdentifierAmbiguous {
                element_name: ambiguous_name,
                match_count: 3,
            })
        );
        assert_eq!(source.action_search_calls, 4);
        assert_eq!(source.action_name_calls, 0);
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn role_and_title_matching_is_exact() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node_with_keys(
                Some("upper-id"),
                Some("AXButton"),
                Some("SAVE"),
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("save-id"),
                Some("AXButton"),
                Some("Save"),
                &[AxAction::Press],
                vec![],
            ),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &role_title_name("AXButton", "Save"),
                AxAction::Press,
                action_options(2, 3),
            ),
            Ok(AxActionRequestOutcome::HandlerReturned {
                matched_by: role_title_name("AXButton", "Save"),
                alternate_name: Some(element_name("save-id")),
                unreadable_subtrees: 0,
            })
        );
        assert_eq!(source.performed_actions, vec![(2, AxAction::Press)]);
    }

    #[test]
    fn missing_and_empty_titles_share_one_role_title_key_and_are_ambiguous() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node_with_keys(
                Some("missing-title-id"),
                Some("AXButton"),
                None,
                &[AxAction::Press],
                vec![],
            ),
            action_node_with_keys(
                Some("empty-title-id"),
                Some("AXButton"),
                Some(""),
                &[AxAction::Press],
                vec![],
            ),
        ]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &role_title_name("AXButton", ""),
                AxAction::Press,
                action_options(2, 3),
            ),
            Err(AxActionError::ElementIdentifierAmbiguous {
                element_name: role_title_name("AXButton", ""),
                match_count: 2,
            })
        );
        assert!(source.perform_attempts.is_empty());
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
            Ok(identifier_outcome("target", None))
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
                element_name: element_name("missing"),
            })
        );
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn a_duplicate_identifier_in_scope_is_refused_before_any_action_call() {
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
                element_name: element_name("duplicate"),
                match_count: 2,
            })
        );
        assert_eq!(source.action_name_calls, 0);
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn a_fresh_action_search_refuses_when_the_tree_gained_a_duplicate() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1]),
            action_node(Some("target"), &[AxAction::Press], vec![]),
        ]);
        let initial =
            read_tree_from(&mut source, 42, options(1, 2)).expect("the initial tree is readable");
        assert_eq!(initial.completeness, AxTreeCompleteness::Complete);
        assert_eq!(initial.root.children.len(), 1);

        source.nodes[0].children.push(2);
        source
            .nodes
            .push(action_node(Some("target"), &[AxAction::Press], vec![]));

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &element_name("target"),
                AxAction::Press,
                action_options(1, 3),
            ),
            Err(AxActionError::ElementIdentifierAmbiguous {
                element_name: element_name("target"),
                match_count: 2,
            })
        );
        assert_eq!(source.action_search_calls, 3);
        assert_eq!(source.action_name_calls, 0);
        assert!(source.perform_attempts.is_empty());
    }

    #[test]
    fn an_incomplete_action_search_acts_and_discloses_the_partial_tree() {
        let mut source = FakeSource::with_nodes(vec![
            action_node(None, &[], vec![1, 2]),
            action_node_with_keys(
                Some("target-id"),
                Some("AXButton"),
                Some("Save"),
                &[AxAction::Press],
                vec![],
            ),
            action_node(Some("unreadable-named"), &[AxAction::Press], vec![]),
        ]);
        source.action_search_error_at = Some((
            2,
            SourceError::Ax {
                operation: "AXUIElementCopyAttributeValue",
                code: AX_ERROR_FAILURE,
            },
        ));

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &role_title_name("AXButton", "Save"),
                AxAction::Press,
                action_options(1, 3),
            ),
            Ok(AxActionRequestOutcome::HandlerReturned {
                matched_by: role_title_name("AXButton", "Save"),
                alternate_name: Some(element_name("target-id")),
                unreadable_subtrees: 1,
            })
        );
        assert_eq!(
            source.action_search_calls, 3,
            "the fixture must exercise successful and failed action-search reads"
        );
        assert_eq!(source.action_name_calls, 1);
        assert_eq!(source.perform_attempts, vec![(1, AxAction::Press)]);
    }

    #[test]
    fn an_action_the_current_element_does_not_advertise_is_refused() {
        let mut source = FakeSource::with_nodes(vec![action_node_with_keys(
            Some("target-id"),
            Some("AXButton"),
            Some("Save"),
            &[AxAction::ShowMenu],
            vec![],
        )]);

        assert_eq!(
            request_action_from(
                &mut source,
                42,
                &role_title_name("AXButton", "Save"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::ActionNotAdvertised {
                element_name: role_title_name("AXButton", "Save"),
                action: AxAction::Press,
                advertised: vec!["AXShowMenu".to_string()],
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
        let mut source = FakeSource::with_nodes(vec![action_node_with_keys(
            Some("target-id"),
            Some("AXButton"),
            Some("Save"),
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
                &role_title_name("AXButton", "Save"),
                AxAction::Press,
                action_options(0, 1),
            ),
            Err(AxActionError::ApplicationRefusedAction {
                element_name: role_title_name("AXButton", "Save"),
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
                element_name: element_name("target"),
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
                    tree.root.role.as_deref(),
                    Some("AXApplication"),
                    "the application root reports its AX role"
                );
                eprintln!(
                    "REAL AX SAMPLE pid={pid} role={:?} title={:?} children={}",
                    tree.root.role,
                    tree.root.title,
                    tree.root.children.len()
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
