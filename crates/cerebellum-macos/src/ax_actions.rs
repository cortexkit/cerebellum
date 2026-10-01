//! Acting on one retained element of another application: pressing it,
//! writing its text, finding the element under a point, reading its focused
//! element, and bringing its application to the front.
//!
//! Accessibility reads may opt Chromium into building its tree. Every function
//! here takes the retained element the state read produced, or a pid; no
//! handle leaves this crate as anything but the opaque
//! [`AxRetainedElement`].

use std::ffi::{c_int, c_void};

use objc2_core_foundation::{CFArray, CFBoolean, CFRetained, CFString, CFType};

use crate::ax_state::{is_ax_element, owned, process_exists, AxRetainedElement};

type CfTypeRef = *const c_void;

const AX_ERROR_SUCCESS: i32 = 0;
const AX_ERROR_INVALID_ELEMENT: i32 = -25_202;
const AX_ERROR_CANNOT_COMPLETE: i32 = -25_204;
const AX_ERROR_ATTRIBUTE_UNSUPPORTED: i32 = -25_205;
const AX_ERROR_ACTION_UNSUPPORTED: i32 = -25_206;
const AX_ERROR_NOT_IMPLEMENTED: i32 = -25_208;
const AX_ERROR_API_DISABLED: i32 = -25_211;
const AX_ERROR_NO_VALUE: i32 = -25_212;
/// The `AXValue` type carrying a `CFRange`.
const AX_VALUE_CF_RANGE_TYPE: u32 = 4;

/// How long one message to another application may take before it is given
/// up on. Long enough for a busy application to answer a press, short enough
/// that a hung one does not hold a call for the framework's default minute.
const MESSAGING_TIMEOUT_SECONDS: f32 = 2.0;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
struct CfRange {
    location: isize,
    length: isize,
}

#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn AXUIElementCreateApplication(pid: c_int) -> CfTypeRef;
    fn AXUIElementCreateSystemWide() -> CfTypeRef;
    fn AXUIElementSetMessagingTimeout(element: CfTypeRef, timeout: f32) -> i32;
    fn AXUIElementCopyAttributeValue(
        element: CfTypeRef,
        attribute: CfTypeRef,
        value: *mut CfTypeRef,
    ) -> i32;
    fn AXUIElementSetAttributeValue(
        element: CfTypeRef,
        attribute: CfTypeRef,
        value: CfTypeRef,
    ) -> i32;
    fn AXUIElementIsAttributeSettable(
        element: CfTypeRef,
        attribute: CfTypeRef,
        settable: *mut u8,
    ) -> i32;
    fn AXUIElementCopyActionNames(element: CfTypeRef, names: *mut CfTypeRef) -> i32;
    fn AXUIElementPerformAction(element: CfTypeRef, action: CfTypeRef) -> i32;
    fn AXUIElementCopyElementAtPosition(
        application: CfTypeRef,
        x: f32,
        y: f32,
        element: *mut CfTypeRef,
    ) -> i32;
    fn AXUIElementGetPid(element: CfTypeRef, pid: *mut c_int) -> i32;
    fn AXValueGetValue(value: CfTypeRef, value_type: u32, out: *mut c_void) -> bool;
}

/// Why an action on an element did not happen, or could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxElementActionError {
    /// This process may not use the accessibility API.
    NotPermitted,
    /// The element, or its application, no longer exists.
    ElementGone,
    /// The element does not offer the attribute or action asked for.
    Unsupported,
    /// The application answered with another accessibility error.
    Failed { ax_error: i32 },
}

fn classify(code: i32) -> AxElementActionError {
    match code {
        AX_ERROR_API_DISABLED => AxElementActionError::NotPermitted,
        AX_ERROR_INVALID_ELEMENT => AxElementActionError::ElementGone,
        AX_ERROR_ATTRIBUTE_UNSUPPORTED
        | AX_ERROR_ACTION_UNSUPPORTED
        | AX_ERROR_NOT_IMPLEMENTED
        | AX_ERROR_NO_VALUE => AxElementActionError::Unsupported,
        code => AxElementActionError::Failed { ax_error: code },
    }
}

fn require_trust() -> Result<(), AxElementActionError> {
    // SAFETY: a non-prompting Boolean query.
    if unsafe { AXIsProcessTrusted() } {
        Ok(())
    } else {
        Err(AxElementActionError::NotPermitted)
    }
}

fn bound_messages(element: CfTypeRef) {
    // SAFETY: the element is retained by the caller for the call; the timeout
    // applies to messages this process sends and changes nothing in the target.
    unsafe { AXUIElementSetMessagingTimeout(element, MESSAGING_TIMEOUT_SECONDS) };
}

fn copy(element: CfTypeRef, name: &'static str) -> Result<Option<CFRetained<CFType>>, i32> {
    let attribute = CFString::from_static_str(name);
    let mut value: CfTypeRef = std::ptr::null();
    // SAFETY: element and attribute are retained for the call, and `value` is
    // writable storage for one returned reference.
    let code = unsafe {
        AXUIElementCopyAttributeValue(
            element,
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

/// A string attribute; `Ok(None)` when the element has no such value or it is
/// not a string.
fn string(element: CfTypeRef, name: &'static str) -> Result<Option<String>, i32> {
    match copy(element, name) {
        Ok(value) => {
            Ok(value.and_then(|value| value.downcast_ref::<CFString>().map(ToString::to_string)))
        }
        Err(AX_ERROR_NO_VALUE | AX_ERROR_ATTRIBUTE_UNSUPPORTED) => Ok(None),
        Err(code) => Err(code),
    }
}

fn settable(element: CfTypeRef, name: &'static str) -> bool {
    let attribute = CFString::from_static_str(name);
    let mut flag = 0u8;
    // SAFETY: element and attribute are retained for the call; `flag` is
    // writable storage for one Boolean.
    let code = unsafe {
        AXUIElementIsAttributeSettable(
            element,
            CFRetained::as_ptr(&attribute).as_ptr().cast(),
            &mut flag,
        )
    };
    code == AX_ERROR_SUCCESS && flag != 0
}

fn element_pid(element: CfTypeRef) -> Option<u32> {
    let mut pid: c_int = 0;
    // SAFETY: the element is a live AXUIElement for the call; `pid` is
    // writable storage.
    let code = unsafe { AXUIElementGetPid(element, &mut pid) };
    (code == AX_ERROR_SUCCESS && pid > 0)
        .then(|| u32::try_from(pid).ok())
        .flatten()
}

/// Opt a renderer into exposing accessibility without activating its window.
/// Native applications normally reject this optional attribute.
pub fn enable_manual_accessibility(pid: u32) -> crate::ManualAccessibility {
    use crate::ManualAccessibility;
    let Ok(element) = application(pid) else {
        return ManualAccessibility::Failed(AX_ERROR_INVALID_ELEMENT);
    };
    let attribute = CFString::from_static_str("AXManualAccessibility");
    let value = CFBoolean::new(true);
    // SAFETY: all references remain alive for the call. A short messaging
    // timeout keeps an unresponsive renderer from extending the read retry.
    let code = unsafe {
        AXUIElementSetMessagingTimeout(element.as_ptr(), 0.05);
        AXUIElementSetAttributeValue(
            element.as_ptr(),
            CFRetained::as_ptr(&attribute).as_ptr().cast(),
            value as *const CFBoolean as CfTypeRef,
        )
    };
    match code {
        AX_ERROR_SUCCESS => ManualAccessibility::NewlyEnabled,
        AX_ERROR_ATTRIBUTE_UNSUPPORTED | AX_ERROR_NOT_IMPLEMENTED => {
            ManualAccessibility::NotSupported
        }
        code => ManualAccessibility::Failed(code),
    }
}

fn prepare_element(element: CfTypeRef) {
    if let Some(pid) = element_pid(element) {
        crate::manual_accessibility::prepare(pid, false);
    }
}

fn application(pid: u32) -> Result<AxRetainedElement, AxElementActionError> {
    let Ok(raw_pid) = c_int::try_from(pid) else {
        return Err(AxElementActionError::ElementGone);
    };
    if raw_pid <= 0 || !process_exists(raw_pid) {
        return Err(AxElementActionError::ElementGone);
    }
    // SAFETY: creates an application element for a pid passed by value; it
    // returns one owned reference or null.
    let element = unsafe { owned(AXUIElementCreateApplication(raw_pid)) }
        .map(AxRetainedElement)
        .ok_or(AxElementActionError::Failed { ax_error: 0 })?;
    bound_messages(element.as_ptr());
    Ok(element)
}

/// What an action needs to know about one element before acting on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AxElementFacts {
    /// The process the element belongs to.
    pub pid: Option<u32>,
    pub role: Option<String>,
    pub subrole: Option<String>,
    pub title: Option<String>,
    /// The actions the element advertises, as the application names them.
    pub actions: Vec<String>,
    pub value_settable: bool,
    pub selected_text_settable: bool,
}

/// Read what an action on `element` needs to decide: whose it is, what it is,
/// what it can do, and which of its text attributes may be written.
pub fn element_facts(element: &AxRetainedElement) -> Result<AxElementFacts, AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    prepare_element(pointer);
    bound_messages(pointer);
    let role = match string(pointer, "AXRole") {
        Ok(role) => role,
        Err(code) => return Err(classify(code)),
    };
    let subrole = string(pointer, "AXSubrole").unwrap_or(None);
    let title = string(pointer, "AXTitle").unwrap_or(None);
    let mut names: CfTypeRef = std::ptr::null();
    // SAFETY: the element is retained for the call; `names` is writable
    // storage for one returned reference.
    let code = unsafe { AXUIElementCopyActionNames(pointer, &mut names) };
    let actions = if code == AX_ERROR_SUCCESS {
        // SAFETY: a successful Copy returns one owned reference.
        unsafe { owned(names) }
            .and_then(|names| names.downcast::<CFArray>().ok())
            .map(|names| {
                // SAFETY: action names are documented as an array of strings;
                // each is type-checked before use.
                let names: &CFArray<CFType> = unsafe { names.cast_unchecked() };
                names
                    .iter()
                    .filter_map(|name| name.downcast_ref::<CFString>().map(ToString::to_string))
                    .collect()
            })
            .unwrap_or_default()
    } else if code == AX_ERROR_INVALID_ELEMENT {
        return Err(AxElementActionError::ElementGone);
    } else {
        Vec::new()
    };
    Ok(AxElementFacts {
        pid: element_pid(pointer),
        role,
        subrole,
        title,
        actions,
        value_settable: settable(pointer, "AXValue"),
        selected_text_settable: settable(pointer, "AXSelectedText"),
    })
}

/// Ask the element to perform `AXPress`. The pointer is never touched: this
/// is a message to the application, which runs the element's own handler.
pub fn press_element(element: &AxRetainedElement) -> Result<(), AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    prepare_element(pointer);
    bound_messages(pointer);
    let action = CFString::from_static_str("AXPress");
    // SAFETY: element and action name are retained for the call.
    let code =
        unsafe { AXUIElementPerformAction(pointer, CFRetained::as_ptr(&action).as_ptr().cast()) };
    if code == AX_ERROR_SUCCESS {
        Ok(())
    } else {
        Err(classify(code))
    }
}

/// The element's `AXValue` when it is a string; `Ok(None)` when it has no
/// value or a value of another type.
pub fn element_text_value(
    element: &AxRetainedElement,
) -> Result<Option<String>, AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    prepare_element(pointer);
    bound_messages(pointer);
    string(pointer, "AXValue").map_err(classify)
}

/// The element's selection as `(start, length)` in UTF-16 code units, which
/// is how the accessibility API counts text. `Ok(None)` when the element
/// reports no selection range.
pub fn element_selected_range(
    element: &AxRetainedElement,
) -> Result<Option<(usize, usize)>, AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    prepare_element(pointer);
    bound_messages(pointer);
    let value = match copy(pointer, "AXSelectedTextRange") {
        Ok(Some(value)) => value,
        Ok(None) | Err(AX_ERROR_NO_VALUE | AX_ERROR_ATTRIBUTE_UNSUPPORTED) => return Ok(None),
        Err(code) => return Err(classify(code)),
    };
    let mut range = CfRange::default();
    // SAFETY: `value` is retained for the call; the type argument asks for a
    // CFRange, and `range` is writable storage of that layout. The call
    // returns false, writing nothing, when the value holds another type.
    let read = unsafe {
        AXValueGetValue(
            CFRetained::as_ptr(&value).as_ptr().cast(),
            AX_VALUE_CF_RANGE_TYPE,
            (&mut range as *mut CfRange).cast(),
        )
    };
    if !read || range.location < 0 || range.length < 0 {
        return Ok(None);
    }
    Ok(Some((range.location as usize, range.length as usize)))
}

/// Which text attribute a write sets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxTextAttribute {
    /// `AXValue`: the element's whole text.
    Value,
    /// `AXSelectedText`: the current selection, which is the caret when
    /// nothing is selected.
    SelectedText,
}

/// Set one text attribute of the element to `text`.
///
/// A returned `Ok` means the application accepted the message, not that the
/// text is there: the caller reads the value back to find out.
pub fn write_element_text(
    element: &AxRetainedElement,
    attribute: AxTextAttribute,
    text: &str,
) -> Result<(), AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    prepare_element(pointer);
    bound_messages(pointer);
    let name = CFString::from_static_str(match attribute {
        AxTextAttribute::Value => "AXValue",
        AxTextAttribute::SelectedText => "AXSelectedText",
    });
    let value = CFString::from_str(text);
    // SAFETY: element, attribute name and value are retained for the call.
    let code = unsafe {
        AXUIElementSetAttributeValue(
            pointer,
            CFRetained::as_ptr(&name).as_ptr().cast(),
            CFRetained::as_ptr(&value).as_ptr().cast(),
        )
    };
    if code == AX_ERROR_SUCCESS {
        Ok(())
    } else {
        Err(classify(code))
    }
}

/// Where a hit test looks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AxHitScope {
    /// Only this process's elements: the hit belongs to it or to nothing.
    Application(u32),
    /// Whatever is on top at the point, in any application.
    SystemWide,
}

/// The element at a desktop point, in top-left screen coordinates, with the
/// pid of the process that owns it. `Ok(None)` when nothing is there.
pub fn element_at_position(
    scope: AxHitScope,
    x: f64,
    y: f64,
) -> Result<Option<(AxRetainedElement, Option<u32>)>, AxElementActionError> {
    require_trust()?;
    let root = match scope {
        AxHitScope::Application(pid) => {
            crate::manual_accessibility::prepare(pid, false);
            application(pid)?
        }
        AxHitScope::SystemWide => {
            // SAFETY: creates the system-wide element; returns one owned
            // reference or null.
            let element = unsafe { owned(AXUIElementCreateSystemWide()) }
                .map(AxRetainedElement)
                .ok_or(AxElementActionError::Failed { ax_error: 0 })?;
            bound_messages(element.as_ptr());
            element
        }
    };
    let mut hit: CfTypeRef = std::ptr::null();
    // SAFETY: the root element is retained for the call; `hit` is writable
    // storage for one returned reference.
    let code =
        unsafe { AXUIElementCopyElementAtPosition(root.as_ptr(), x as f32, y as f32, &mut hit) };
    match code {
        AX_ERROR_SUCCESS => {}
        AX_ERROR_NO_VALUE | AX_ERROR_CANNOT_COMPLETE | AX_ERROR_ATTRIBUTE_UNSUPPORTED => {
            // SAFETY: nothing is owned on failure, but release whatever a
            // misbehaving server may have written.
            let _ = unsafe { owned(hit) };
            return Ok(None);
        }
        code => return Err(classify(code)),
    }
    // SAFETY: a successful Copy returns one owned reference.
    let Some(hit) = (unsafe { owned(hit) }) else {
        return Ok(None);
    };
    if !is_ax_element(&hit) {
        return Ok(None);
    }
    let hit = AxRetainedElement(hit);
    let pid = element_pid(hit.as_ptr());
    Ok(Some((hit, pid)))
}

/// The element that has keyboard focus inside the application `pid` runs,
/// asked of that application rather than of whichever one is frontmost.
/// `Ok(None)` when the application reports no focused element.
pub fn focused_element(pid: u32) -> Result<Option<AxRetainedElement>, AxElementActionError> {
    crate::manual_accessibility::prepare(pid, false);
    require_trust()?;
    let application = application(pid)?;
    match copy(application.as_ptr(), "AXFocusedUIElement") {
        Ok(value) => Ok(value
            .filter(|value| is_ax_element(value))
            .map(AxRetainedElement)),
        Err(AX_ERROR_NO_VALUE) => Ok(None),
        Err(code) => Err(classify(code)),
    }
}

/// The window that is focused inside the application `pid` runs, with its
/// title, asked of that application rather than of whichever one is
/// frontmost. `Ok(None)` when the application reports no focused window; a
/// title that cannot be read is `None` beside the window.
pub fn focused_window(
    pid: u32,
) -> Result<Option<(AxRetainedElement, Option<String>)>, AxElementActionError> {
    crate::manual_accessibility::prepare(pid, false);
    require_trust()?;
    let application = application(pid)?;
    let window = match copy(application.as_ptr(), "AXFocusedWindow") {
        Ok(value) => value
            .filter(|value| is_ax_element(value))
            .map(AxRetainedElement),
        Err(AX_ERROR_NO_VALUE) => None,
        Err(code) => return Err(classify(code)),
    };
    Ok(window.map(|window| {
        bound_messages(window.as_ptr());
        let title = string(window.as_ptr(), "AXTitle").unwrap_or(None);
        (window, title)
    }))
}

/// Ask the application `pid` runs to become the active application.
///
/// A request, answered asynchronously: the caller watches which process is
/// frontmost to learn whether and when it took effect.
pub fn request_frontmost(pid: u32) -> Result<(), AxElementActionError> {
    require_trust()?;
    let application = application(pid)?;
    let name = CFString::from_static_str("AXFrontmost");
    let value = CFBoolean::new(true);
    // SAFETY: element, attribute name and the static Boolean are live for
    // the call.
    let code = unsafe {
        AXUIElementSetAttributeValue(
            application.as_ptr(),
            CFRetained::as_ptr(&name).as_ptr().cast(),
            (value as *const CFBoolean).cast(),
        )
    };
    if code == AX_ERROR_SUCCESS {
        Ok(())
    } else {
        Err(classify(code))
    }
}
