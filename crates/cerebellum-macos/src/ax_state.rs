//! One application's windows, sheets and menu bar read as retained elements.
//!
//! Unlike the name-addressed reader in `accessibility`, this keeps a retained
//! reference to every element it reads, so a later read can tell whether it
//! is looking at the same element: two references to one element compare
//! equal under `CFEqual`. The references never leave this crate as anything
//! but the opaque [`AxRetainedElement`].
//!
//! Every call here reads. Nothing is pressed, focused, raised or written.

use std::ffi::{c_int, c_void};
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use objc2_core_foundation::{
    CFArray, CFBoolean, CFEqual, CFHash, CFNumber, CFRetained, CFString, CFType,
};

type CfTypeRef = *const c_void;

const AX_ERROR_SUCCESS: i32 = 0;
const AX_ERROR_API_DISABLED: i32 = -25_211;
const AX_ERROR_INVALID_ELEMENT: i32 = -25_202;
const AX_ERROR_CANNOT_COMPLETE: i32 = -25_204;
/// The `AXValue` type that stands in for an attribute that could not be read,
/// inside the array a multiple-attribute copy returns.
const AX_VALUE_ERROR_TYPE: u32 = 5;

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
    fn AXUIElementCopyMultipleAttributeValues(
        element: CfTypeRef,
        attributes: CfTypeRef,
        options: u32,
        values: *mut CfTypeRef,
    ) -> i32;
    fn AXUIElementIsAttributeSettable(
        element: CfTypeRef,
        attribute: CfTypeRef,
        settable: *mut u8,
    ) -> i32;
    fn AXValueGetTypeID() -> usize;
    fn AXValueGetType(value: CfTypeRef) -> u32;
}

extern "C" {
    fn CFGetTypeID(value: CfTypeRef) -> usize;
    #[link_name = "kill"]
    fn process_signal(pid: c_int, signal: c_int) -> c_int;
    #[link_name = "__error"]
    fn errno_location() -> *mut c_int;
}

/// A retained reference to one element of another application.
///
/// Opaque on purpose: nothing outside this crate can act on it, and the only
/// questions it answers are whether it names the same element as another
/// reference and a hash that agrees with that answer.
pub struct AxRetainedElement(pub(crate) CFRetained<CFType>);

// SAFETY: an AXUIElement is an immutable Core Foundation value naming an
// element in another process. Retain and release are thread-safe, and the
// accessibility calls made on it are messages to that process that may be
// sent from any thread.
unsafe impl Send for AxRetainedElement {}
// SAFETY: as above; no method mutates the reference.
unsafe impl Sync for AxRetainedElement {}

impl std::fmt::Debug for AxRetainedElement {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "AxRetainedElement({:x})", self.identity_hash())
    }
}

impl AxRetainedElement {
    /// Whether both references name the same element.
    pub fn same_element(&self, other: &Self) -> bool {
        CFEqual(Some(&self.0), Some(&other.0))
    }

    /// A hash that is equal for two references naming the same element.
    pub fn identity_hash(&self) -> u64 {
        CFHash(Some(&self.0)) as u64
    }

    pub(crate) fn as_ptr(&self) -> CfTypeRef {
        CFRetained::as_ptr(&self.0).as_ptr().cast()
    }
}

/// An element's `AXValue`, typed.
#[derive(Debug, Clone, PartialEq)]
pub enum AxStateValue {
    Absent,
    Text(String),
    Boolean(bool),
    Number(f64),
    Other,
}

/// One element and what the state tree needs of it.
#[derive(Debug)]
pub struct AxStateElement {
    pub element: AxRetainedElement,
    pub role: Option<String>,
    pub subrole: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub value_description: Option<String>,
    pub value: AxStateValue,
    pub value_settable: bool,
    pub selected: bool,
    pub enabled: bool,
    pub focused: bool,
    pub expanded: Option<bool>,
    pub children: Vec<AxStateElement>,
    /// Children this element reported that could not be read.
    pub unreadable_children: usize,
}

/// Everything one read of an application saw.
#[derive(Debug)]
pub struct AxAppState {
    pub roots: Vec<AxStateElement>,
    pub focused: Option<AxRetainedElement>,
    pub unreadable_subtrees: usize,
    /// Whether the read stopped at a bound before visiting everything.
    pub bound_reached: bool,
}

/// Why an application could not be read at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxAppStateError {
    NotPermitted,
    ProcessGone,
    /// The application did not answer for its own element.
    Unreadable {
        ax_error: i32,
    },
}

/// Bounds on one read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AxAppStateBounds {
    pub max_elements: usize,
    pub max_depth: usize,
    pub timeout: Duration,
}

/// The attributes read per element, in one message to the application.
const ATTRIBUTES: [&str; 11] = [
    "AXRole",
    "AXSubrole",
    "AXTitle",
    "AXDescription",
    "AXValueDescription",
    "AXValue",
    "AXSelected",
    "AXEnabled",
    "AXFocused",
    "AXExpanded",
    "AXChildren",
];

pub(crate) fn process_exists(pid: c_int) -> bool {
    // SAFETY: signal zero sends nothing; it asks whether the pid exists.
    let result = unsafe { process_signal(pid, 0) };
    if result == 0 {
        return true;
    }
    const ESRCH: c_int = 3;
    // SAFETY: reads this thread's errno, set by the call above.
    unsafe { errno_location().read() != ESRCH }
}

/// Take ownership of a value a Copy or Create call returned.
///
/// # Safety
///
/// `value` must be null or carry one retain count the caller owns.
pub(crate) unsafe fn owned(value: CfTypeRef) -> Option<CFRetained<CFType>> {
    NonNull::new(value.cast_mut().cast::<CFType>()).map(|value| CFRetained::from_raw(value))
}

fn type_id(value: &CFType) -> usize {
    // SAFETY: the value is a live Core Foundation object for this call.
    unsafe { CFGetTypeID((value as *const CFType).cast()) }
}

pub(crate) fn is_ax_element(value: &CFType) -> bool {
    // SAFETY: takes no arguments and returns a stable type identifier.
    type_id(value) == unsafe { AXUIElementGetTypeID() }
}

/// Whether a value in a multiple-attribute reply stands for a failed read.
fn is_error_marker(value: &CFType) -> bool {
    // SAFETY: takes no arguments and returns a stable type identifier.
    if type_id(value) != unsafe { AXValueGetTypeID() } {
        return false;
    }
    // SAFETY: the type check establishes this is an AXValue.
    unsafe { AXValueGetType((value as *const CFType).cast()) == AX_VALUE_ERROR_TYPE }
}

struct Reader {
    /// Every element already read, by hash. An element reachable twice -- an
    /// application that lists itself among its own children, which Electron
    /// applications do, or a child shared by two parents -- is read once, so
    /// a cycle cannot recurse until the depth bound and a shared element is
    /// not shown twice.
    visited_elements: std::collections::HashMap<u64, Vec<CFRetained<CFType>>>,
    names: CFRetained<CFArray<CFString>>,
    value_name: CFRetained<CFString>,
    deadline: Instant,
    max_elements: usize,
    max_depth: usize,
    visited: usize,
    unreadable: usize,
    bound_reached: bool,
}

enum ElementRead {
    Read(Box<AxStateElement>),
    Unreadable,
}

impl Reader {
    /// Record an element as read; false when it already was.
    fn first_visit(&mut self, element: &AxRetainedElement) -> bool {
        let seen = self
            .visited_elements
            .entry(element.identity_hash())
            .or_default();
        if seen
            .iter()
            .any(|earlier| CFEqual(Some(earlier), Some(&element.0)))
        {
            return false;
        }
        seen.push(element.0.clone());
        true
    }

    fn remaining_seconds(&self) -> Option<f32> {
        let remaining = self.deadline.checked_duration_since(Instant::now())?;
        (!remaining.is_zero()).then_some(remaining.as_secs_f32())
    }

    fn read(&mut self, element: AxRetainedElement, depth: usize) -> ElementRead {
        let Some(seconds) = self.remaining_seconds() else {
            self.bound_reached = true;
            return ElementRead::Unreadable;
        };
        // SAFETY: the element is retained; the timeout applies to messages
        // this process sends about it and changes nothing in the target.
        unsafe { AXUIElementSetMessagingTimeout(element.as_ptr(), seconds) };
        let mut values: CfTypeRef = std::ptr::null();
        // SAFETY: element and the attribute-name array are retained for the
        // call, and `values` is writable storage for one returned reference.
        let code = unsafe {
            AXUIElementCopyMultipleAttributeValues(
                element.as_ptr(),
                CFRetained::as_ptr(&self.names).as_ptr().cast(),
                0,
                &mut values,
            )
        };
        if code != AX_ERROR_SUCCESS {
            return ElementRead::Unreadable;
        }
        // SAFETY: a successful Copy returns one owned reference.
        let Some(values) = (unsafe { owned(values) }) else {
            return ElementRead::Unreadable;
        };
        let Ok(values) = values.downcast::<CFArray>() else {
            return ElementRead::Unreadable;
        };
        // SAFETY: the reply is an array of Core Foundation values.
        let values: &CFArray<CFType> = unsafe { values.cast_unchecked() };
        let value_at = |index: usize| -> Option<CFRetained<CFType>> {
            values.get(index).filter(|value| !is_error_marker(value))
        };
        let string_at = |index: usize| -> Option<String> {
            value_at(index)?
                .downcast_ref::<CFString>()
                .map(ToString::to_string)
        };
        let bool_at = |index: usize| -> Option<bool> {
            value_at(index)?
                .downcast_ref::<CFBoolean>()
                .map(CFBoolean::as_bool)
        };

        let value = match value_at(5) {
            None => AxStateValue::Absent,
            Some(value) => {
                if let Some(text) = value.downcast_ref::<CFString>() {
                    AxStateValue::Text(text.to_string())
                } else if let Some(flag) = value.downcast_ref::<CFBoolean>() {
                    AxStateValue::Boolean(flag.as_bool())
                } else if let Some(number) = value.downcast_ref::<CFNumber>() {
                    number
                        .as_f64()
                        .map_or(AxStateValue::Other, AxStateValue::Number)
                } else {
                    AxStateValue::Other
                }
            }
        };
        // Asked only where there is a value to set, so an element without one
        // costs no extra message.
        let value_settable = value != AxStateValue::Absent && {
            let mut settable = 0u8;
            // SAFETY: element and attribute name are retained for the call;
            // `settable` is writable storage for one Boolean.
            let code = unsafe {
                AXUIElementIsAttributeSettable(
                    element.as_ptr(),
                    CFRetained::as_ptr(&self.value_name).as_ptr().cast(),
                    &mut settable,
                )
            };
            code == AX_ERROR_SUCCESS && settable != 0
        };

        let mut read = AxStateElement {
            role: string_at(0),
            subrole: string_at(1),
            title: string_at(2),
            description: string_at(3),
            value_description: string_at(4),
            value,
            value_settable,
            selected: bool_at(6).unwrap_or(false),
            enabled: bool_at(7).unwrap_or(true),
            focused: bool_at(8).unwrap_or(false),
            expanded: bool_at(9),
            children: Vec::new(),
            unreadable_children: 0,
            element,
        };

        let children: Vec<AxRetainedElement> = value_at(10)
            .and_then(|children| children.downcast::<CFArray>().ok())
            .map(|children| {
                // SAFETY: AXChildren is documented as an array of elements;
                // each is type-checked below before use.
                let children: &CFArray<CFType> = unsafe { children.cast_unchecked() };
                children
                    .iter()
                    .filter(|child| is_ax_element(child))
                    .map(AxRetainedElement)
                    .collect()
            })
            .unwrap_or_default();
        if !children.is_empty() && depth >= self.max_depth {
            self.bound_reached = true;
            return ElementRead::Read(Box::new(read));
        }
        for child in children {
            if !self.first_visit(&child) {
                continue;
            }
            if self.visited >= self.max_elements {
                self.bound_reached = true;
                break;
            }
            self.visited += 1;
            match self.read(child, depth + 1) {
                ElementRead::Read(child) => read.children.push(*child),
                ElementRead::Unreadable => {
                    read.unreadable_children += 1;
                    self.unreadable += 1;
                }
            }
        }
        ElementRead::Read(Box::new(read))
    }
}

fn copy_attribute(
    element: &AxRetainedElement,
    name: &'static str,
) -> Result<Option<CFRetained<CFType>>, i32> {
    let attribute = CFString::from_static_str(name);
    let mut value: CfTypeRef = std::ptr::null();
    // SAFETY: element and attribute are retained for the call, and `value` is
    // writable storage for one returned reference.
    let code = unsafe {
        AXUIElementCopyAttributeValue(
            element.as_ptr(),
            CFRetained::as_ptr(&attribute).as_ptr().cast(),
            &mut value,
        )
    };
    if code == AX_ERROR_SUCCESS {
        // SAFETY: a successful Copy returns one owned reference.
        Ok(unsafe { owned(value) })
    } else {
        Err(code)
    }
}

fn elements_of(value: Option<CFRetained<CFType>>) -> Vec<AxRetainedElement> {
    value
        .and_then(|value| value.downcast::<CFArray>().ok())
        .map(|array| {
            // SAFETY: an element list is an array of Core Foundation values;
            // each is type-checked before use.
            let array: &CFArray<CFType> = unsafe { array.cast_unchecked() };
            array
                .iter()
                .filter(|item| is_ax_element(item))
                .map(AxRetainedElement)
                .collect()
        })
        .unwrap_or_default()
}

/// Read the application `pid` runs: every window, with the sheets and dialogs
/// attached to them beneath, and its menu bar, plus its own focused element.
///
/// Windows are taken from both the application's children and its window
/// list, because some applications report windows in only one of the two.
pub fn read_app_state(pid: u32, bounds: AxAppStateBounds) -> Result<AxAppState, AxAppStateError> {
    fn populated_web(nodes: &[AxStateElement]) -> bool {
        nodes.iter().any(|node| {
            (node.role.as_deref() == Some("AXWebArea") && !node.children.is_empty())
                || populated_web(&node.children)
        })
    }
    crate::manual_accessibility::read_with_manual_accessibility(
        |force| crate::manual_accessibility::prepare(pid, force),
        |timeout| read_app_state_once(pid, AxAppStateBounds { timeout, ..bounds }),
        |state| populated_web(&state.roots),
        std::thread::sleep,
        bounds.timeout,
    )
}

fn read_app_state_once(pid: u32, bounds: AxAppStateBounds) -> Result<AxAppState, AxAppStateError> {
    let Ok(pid) = c_int::try_from(pid) else {
        return Err(AxAppStateError::ProcessGone);
    };
    if pid <= 0 || !process_exists(pid) {
        return Err(AxAppStateError::ProcessGone);
    }
    // SAFETY: a non-prompting Boolean query.
    if !unsafe { AXIsProcessTrusted() } {
        return Err(AxAppStateError::NotPermitted);
    }
    // SAFETY: creates an application element for a pid passed by value; it
    // returns one owned reference or null.
    let application = unsafe { owned(AXUIElementCreateApplication(pid)) }
        .map(AxRetainedElement)
        .ok_or(AxAppStateError::Unreadable { ax_error: 0 })?;
    let deadline = Instant::now() + bounds.timeout;
    // SAFETY: as in `Reader::read`: the timeout applies to this element's
    // messages and changes nothing in the target.
    unsafe { AXUIElementSetMessagingTimeout(application.as_ptr(), bounds.timeout.as_secs_f32()) };

    let mut tops = match copy_attribute(&application, "AXChildren") {
        Ok(children) => elements_of(children),
        Err(AX_ERROR_API_DISABLED) => return Err(AxAppStateError::NotPermitted),
        Err(code @ (AX_ERROR_INVALID_ELEMENT | AX_ERROR_CANNOT_COMPLETE)) => {
            if !process_exists(pid) {
                return Err(AxAppStateError::ProcessGone);
            }
            return Err(AxAppStateError::Unreadable { ax_error: code });
        }
        Err(code) => return Err(AxAppStateError::Unreadable { ax_error: code }),
    };
    for window in elements_of(copy_attribute(&application, "AXWindows").unwrap_or(None)) {
        if !tops.iter().any(|top| top.same_element(&window)) {
            tops.push(window);
        }
    }
    let focused = copy_attribute(&application, "AXFocusedUIElement")
        .ok()
        .flatten()
        .filter(|value| is_ax_element(value))
        .map(AxRetainedElement);

    let names: Vec<CFRetained<CFString>> = ATTRIBUTES
        .iter()
        .map(|name| CFString::from_static_str(name))
        .collect();
    let mut reader = Reader {
        visited_elements: std::collections::HashMap::new(),
        names: CFArray::from_retained_objects(&names),
        value_name: CFString::from_static_str("AXValue"),
        deadline,
        max_elements: bounds.max_elements,
        max_depth: bounds.max_depth,
        visited: 0,
        unreadable: 0,
        bound_reached: false,
    };
    reader.first_visit(&application);
    let mut roots = Vec::new();
    for top in tops {
        if !reader.first_visit(&top) {
            continue;
        }
        if reader.visited >= reader.max_elements {
            reader.bound_reached = true;
            break;
        }
        reader.visited += 1;
        match reader.read(top, 0) {
            ElementRead::Read(root) => roots.push(*root),
            ElementRead::Unreadable => reader.unreadable += 1,
        }
    }
    Ok(AxAppState {
        roots,
        focused,
        unreadable_subtrees: reader.unreadable,
        bound_reached: reader.bound_reached,
    })
}
