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
    fn AXUIElementCopyParameterizedAttributeValue(
        element: CfTypeRef,
        attribute: CfTypeRef,
        parameter: CfTypeRef,
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
    fn AXValueCreate(value_type: u32, value: *const c_void) -> CfTypeRef;
    fn AXValueGetTypeID() -> usize;
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    fn CFGetTypeID(value: CfTypeRef) -> usize;
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
    unsafe {
        AXUIElementSetMessagingTimeout(
            element,
            crate::ax_budget::messaging_timeout_seconds(MESSAGING_TIMEOUT_SECONDS),
        )
    };
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

/// Read position and size once without preparing the app or changing a shared
/// element's messaging timeout. The caller discards results past its deadline.
pub fn cursor_element_frame(element: &AxRetainedElement) -> Option<[f64; 4]> {
    require_trust().ok()?;
    let position = copy(element.as_ptr(), "AXPosition").ok()??;
    let size = copy(element.as_ptr(), "AXSize").ok()??;
    // Applications can expose an attribute of the wrong type. Only AXValue
    // objects may be passed to AXValueGetValue, even when the key is familiar.
    if unsafe {
        CFGetTypeID(CFRetained::as_ptr(&position).as_ptr().cast()) != AXValueGetTypeID()
            || CFGetTypeID(CFRetained::as_ptr(&size).as_ptr().cast()) != AXValueGetTypeID()
    } {
        return None;
    }
    let mut origin = [0.0f64; 2];
    let mut extent = [0.0f64; 2];
    // SAFETY: AXPosition/AXSize are documented AXValue CGPoint/CGSize values;
    // AXValueGetValue checks the requested type and writes two doubles.
    if !unsafe {
        AXValueGetValue(
            CFRetained::as_ptr(&position).as_ptr().cast(),
            1,
            origin.as_mut_ptr().cast(),
        )
    } || !unsafe {
        AXValueGetValue(
            CFRetained::as_ptr(&size).as_ptr().cast(),
            2,
            extent.as_mut_ptr().cast(),
        )
    } || !origin.iter().chain(extent.iter()).all(|v| v.is_finite())
        || extent.iter().any(|v| *v <= 0.0)
    {
        return None;
    }
    Some([origin[0], origin[1], extent[0], extent[1]])
}

/// Read-only selection bounds for a keyboard badge. Unsupported ranges or
/// parameterized attributes leave the caller's frame-centre fallback intact.
/// No text value is read, and each message uses the caller's AX deadline.
pub fn cursor_caret_frame(element: &AxRetainedElement) -> Option<[f64; 4]> {
    require_trust().ok()?;
    let pointer = element.as_ptr();
    bound_messages(pointer);
    let range = copy(pointer, "AXSelectedTextRange").ok()??;
    // SAFETY: the retained value must be an AXValue before it is decoded.
    if unsafe { CFGetTypeID(CFRetained::as_ptr(&range).as_ptr().cast()) != AXValueGetTypeID() } {
        return None;
    }
    let mut selected = CfRange::default();
    // SAFETY: CFRange is two signed machine words; the decoder checks its type.
    if !unsafe {
        AXValueGetValue(
            CFRetained::as_ptr(&range).as_ptr().cast(),
            AX_VALUE_CF_RANGE_TYPE,
            (&mut selected as *mut CfRange).cast(),
        )
    } || selected.location < 0
        || selected.length < 0
    {
        return None;
    }
    if crate::ax_budget::remaining().is_some_and(|left| left.is_zero()) {
        return None;
    }
    bound_messages(pointer);
    let attribute = CFString::from_static_str("AXBoundsForRange");
    let mut bounds: CfTypeRef = std::ptr::null();
    // SAFETY: element, attribute and range are retained; bounds receives one
    // owned reference. This API queries geometry and changes no selection.
    let code = unsafe {
        AXUIElementCopyParameterizedAttributeValue(
            pointer,
            CFRetained::as_ptr(&attribute).as_ptr().cast(),
            CFRetained::as_ptr(&range).as_ptr().cast(),
            &mut bounds,
        )
    };
    if code != AX_ERROR_SUCCESS {
        return None;
    }
    // SAFETY: a successful Copy returns one owned reference.
    let bounds = unsafe { owned(bounds) }?;
    // SAFETY: only AXValues may be passed to AXValueGetValue.
    if unsafe { CFGetTypeID(CFRetained::as_ptr(&bounds).as_ptr().cast()) != AXValueGetTypeID() } {
        return None;
    }
    let mut frame = [0.0f64; 4];
    // SAFETY: CGRect is four doubles; AXValue type 3 checks that layout.
    if !unsafe {
        AXValueGetValue(
            CFRetained::as_ptr(&bounds).as_ptr().cast(),
            3,
            frame.as_mut_ptr().cast(),
        )
    } || !frame.iter().all(|v| v.is_finite())
        || frame[2] < 0.0
        || frame[3] <= 0.0
    {
        return None;
    }
    Some(frame)
}

/// The window `element` sits in, for following it while the agent cursor
/// rests there. A window is its own window. Like the other cursor reads it
/// prepares nothing and changes no messaging timeout.
pub fn cursor_element_window(element: &AxRetainedElement) -> Option<AxRetainedElement> {
    require_trust().ok()?;
    if string(element.as_ptr(), "AXRole").ok()?.as_deref() == Some("AXWindow") {
        return Some(AxRetainedElement(element.0.clone()));
    }
    copy(element.as_ptr(), "AXWindow")
        .ok()?
        .filter(|value| is_ax_element(value))
        .map(AxRetainedElement)
}

/// `AXError _AXUIElementGetWindow(AXUIElementRef, CGWindowID *)`.
type GetWindow = unsafe extern "C" fn(CfTypeRef, *mut u32) -> i32;

extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const std::ffi::c_char) -> *mut c_void;
}

/// The window-server number (`CGWindowID`) of the window `element` sits in,
/// or `None` when that cannot be positively established.
///
/// The element's own `AXWindow` is asked for (a window is its own window),
/// and its number is read with the private `_AXUIElementGetWindow`, looked
/// up at run time (see `window_identity.rs`). An element with no window, such
/// as a menu bar item, a missing symbol and a failed call all answer `None`.
pub fn element_window_number(element: &AxRetainedElement) -> Option<u32> {
    require_trust().ok()?;
    bound_messages(element.as_ptr());
    let window = if string(element.as_ptr(), "AXRole").ok()?.as_deref() == Some("AXWindow") {
        AxRetainedElement(element.0.clone())
    } else {
        copy(element.as_ptr(), "AXWindow")
            .ok()?
            .filter(|value| is_ax_element(value))
            .map(AxRetainedElement)?
    };
    crate::window_identity::window_number_from(
        || {
            // SAFETY: RTLD_DEFAULT (-2 on macOS) searches every loaded image;
            // the accessibility framework is linked by this module, and the
            // name is a NUL-terminated C string.
            let symbol =
                unsafe { dlsym((-2isize) as *mut c_void, c"_AXUIElementGetWindow".as_ptr()) };
            if symbol.is_null() {
                None
            } else {
                // SAFETY: the symbol is the accessibility framework's
                // `AXError _AXUIElementGetWindow(AXUIElementRef, CGWindowID *)`,
                // the declaration window managers built on the accessibility
                // API use. AXError is a 32-bit integer and CGWindowID a 32-bit
                // unsigned integer, so the function type matches.
                Some(unsafe { std::mem::transmute::<*mut c_void, GetWindow>(symbol) })
            }
        },
        |get| {
            let mut number = 0u32;
            // SAFETY: the window element is retained for the call, and
            // `number` is writable storage for one CGWindowID.
            let code = unsafe { get(window.as_ptr(), &mut number) };
            (code, number)
        },
    )
}

/// The application's focused window, for a cursor picture with no element.
/// Unlike `focused_window` it prepares nothing in the application.
pub fn cursor_focused_window(pid: u32) -> Option<AxRetainedElement> {
    require_trust().ok()?;
    let application = application(pid).ok()?;
    copy(application.as_ptr(), "AXFocusedWindow")
        .ok()?
        .filter(|value| is_ax_element(value))
        .map(AxRetainedElement)
}

/// Cosmetic reads must not enable manual accessibility or reset the messaging
/// timeout of an element shared with dispatch. Never read AXValue here.
pub fn cursor_element_label(element: &AxRetainedElement) -> Option<(Option<String>, bool)> {
    require_trust().ok()?;
    let role = string(element.as_ptr(), "AXRole").ok()??;
    let subrole = string(element.as_ptr(), "AXSubrole").ok()?;
    let secure = role == "AXSecureTextField" || subrole.as_deref() == Some("AXSecureTextField");
    let title = if secure {
        None
    } else {
        string(element.as_ptr(), "AXTitle").ok()?
    };
    Some((title, secure))
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
        AXUIElementSetMessagingTimeout(
            element.as_ptr(),
            crate::ax_budget::messaging_timeout_seconds(0.05),
        );
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

/// The element's live `AXEnabled`. `None` when it cannot be read or is not a
/// Boolean, which a caller must treat as unknown rather than as disabled.
/// This is a read: nothing in the application is prepared or changed.
pub fn element_enabled(element: &AxRetainedElement) -> Option<bool> {
    require_trust().ok()?;
    let pointer = element.as_ptr();
    bound_messages(pointer);
    copy(pointer, "AXEnabled")
        .ok()?
        .and_then(|value| value.downcast_ref::<CFBoolean>().map(CFBoolean::as_bool))
}

/// The window's live `AXMinimized`. `None` when it cannot be read or is not
/// a Boolean, which a caller must treat as unknown: not known to be
/// minimized. This is a read: nothing in the application is prepared or
/// changed.
pub fn window_minimized(window: &AxRetainedElement) -> Option<bool> {
    require_trust().ok()?;
    let pointer = window.as_ptr();
    bound_messages(pointer);
    copy(pointer, "AXMinimized")
        .ok()?
        .and_then(|value| value.downcast_ref::<CFBoolean>().map(CFBoolean::as_bool))
}

/// Whether the application is hidden. Unknown visibility must not leave a
/// cosmetic badge floating over another application's window.
pub(crate) fn application_hidden(application: &AxRetainedElement) -> Option<bool> {
    require_trust().ok()?;
    let pointer = application.as_ptr();
    bound_messages(pointer);
    copy(pointer, "AXHidden")
        .ok()?
        .and_then(|value| value.downcast_ref::<CFBoolean>().map(CFBoolean::as_bool))
}

/// Read the application's hidden state without preparing or activating it.
pub fn application_is_hidden(pid: u32) -> Option<bool> {
    application_hidden(&application(pid).ok()?)
}

/// Ask the element to perform `AXPress`. The pointer is never touched: this
/// is a message to the application, which runs the element's own handler.
pub fn press_element(element: &AxRetainedElement) -> Result<(), AxElementActionError> {
    perform_element_action(element, "AXPress")
}

/// Ask the element to perform `AXShowMenu`. Like a press, this calls the
/// application's accessibility handler without moving the pointer.
pub fn show_element_menu(element: &AxRetainedElement) -> Result<(), AxElementActionError> {
    perform_element_action(element, "AXShowMenu")
}

fn perform_element_action(
    element: &AxRetainedElement,
    action: &'static str,
) -> Result<(), AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    prepare_element(pointer);
    bound_messages(pointer);
    let action = CFString::from_static_str(action);
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

/// Select text without bypassing the editor's own input handling. The range
/// must be settable and must subsequently be verified by the caller.
pub fn select_element_range(
    element: &AxRetainedElement,
    (start, length): (usize, usize),
) -> Result<(), AxElementActionError> {
    require_trust()?;
    let pointer = element.as_ptr();
    bound_messages(pointer);
    if !settable(pointer, "AXSelectedTextRange") {
        return Err(AxElementActionError::Unsupported);
    }
    let value = text_range_value((start, length))?;
    let name = CFString::from_static_str("AXSelectedTextRange");
    // SAFETY: element, attribute and range value are retained for this call.
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

fn text_range_value(
    (start, length): (usize, usize),
) -> Result<CFRetained<CFType>, AxElementActionError> {
    let range = CfRange {
        location: start
            .try_into()
            .map_err(|_| AxElementActionError::Unsupported)?,
        length: length
            .try_into()
            .map_err(|_| AxElementActionError::Unsupported)?,
    };
    // SAFETY: range has the CFRange layout and lives through the copying call.
    let value = unsafe { AXValueCreate(AX_VALUE_CF_RANGE_TYPE, (&range as *const CfRange).cast()) };
    // SAFETY: Create returns an owned reference, or null on failure.
    unsafe { owned(value) }.ok_or(AxElementActionError::Unsupported)
}

#[cfg(test)]
mod frontmost_write_tests {
    use super::*;

    /// The pid is replaced while the element is being resolved: the check
    /// after the lookup sees it, and nothing is written.
    #[test]
    fn a_pid_replaced_during_the_element_lookup_is_never_written() {
        let replaced = std::cell::Cell::new(false);
        let mut written = false;
        let result = write_if_still_ours(
            || {
                replaced.set(true);
                Ok(())
            },
            &mut || !replaced.get(),
            |_: &()| {
                written = true;
                AX_ERROR_SUCCESS
            },
        );
        assert_eq!(result, Err(AxElementActionError::ElementGone));
        assert!(!written, "AXFrontmost written for a replaced process");
    }

    #[test]
    fn an_unreplaced_pid_is_written() {
        let result = write_if_still_ours(|| Ok(()), &mut || true, |_: &()| AX_ERROR_SUCCESS);
        assert_eq!(result, Ok(AX_ERROR_SUCCESS));
    }
}

#[cfg(test)]
mod text_range_tests {
    use super::*;

    #[test]
    fn selection_ranges_roundtrip_as_cf_ranges_without_accessibility_input() {
        for range in [(0, 0), (0, 4), (3, 2)] {
            let value = text_range_value(range).unwrap();
            let mut read = CfRange::default();
            // SAFETY: the owned AXValue holds a CFRange and read is writable.
            assert!(unsafe {
                AXValueGetValue(
                    CFRetained::as_ptr(&value).as_ptr().cast(),
                    AX_VALUE_CF_RANGE_TYPE,
                    (&mut read as *mut CfRange).cast(),
                )
            });
            assert_eq!(
                (read.location, read.length),
                (range.0 as isize, range.1 as isize)
            );
        }
        assert!(text_range_value((usize::MAX, 0)).is_err());
        assert!(text_range_value((0, usize::MAX)).is_err());
    }
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

/// Read a live parent without treating a failed AX message as an absent parent.
pub fn element_parent(
    element: &AxRetainedElement,
) -> Result<Option<AxRetainedElement>, AxElementActionError> {
    require_trust()?;
    bound_messages(element.as_ptr());
    match copy(element.as_ptr(), "AXParent") {
        Ok(Some(value)) if is_ax_element(&value) => Ok(Some(AxRetainedElement(value))),
        Ok(None) | Err(AX_ERROR_NO_VALUE) => Ok(None),
        Ok(Some(_)) => Err(AxElementActionError::Failed { ax_error: 0 }),
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
    request_frontmost_while(pid, &mut || true)
}

/// [`request_frontmost`], asking `still_ours` after the application element
/// has been resolved from `pid` and immediately before `AXFrontmost` is
/// written. When it answers `false` (the process holding `pid` is no longer
/// the one the caller means), nothing is written and the request is refused
/// as [`AxElementActionError::ElementGone`].
///
/// This narrows the window for pid reuse to the write itself; it cannot
/// close it. The accessibility element names a pid, not a process
/// generation, and the system resolves that pid again when it delivers the
/// write, so a process that takes the pid between `still_ours` and that
/// delivery would receive the request.
pub fn request_frontmost_while(
    pid: u32,
    still_ours: &mut dyn FnMut() -> bool,
) -> Result<(), AxElementActionError> {
    #[cfg(feature = "desk-probe")]
    note_frontmost_call_for_probe(pid, None);
    require_trust()?;
    let code = write_frontmost(|| application(pid), still_ours)?;
    #[cfg(feature = "desk-probe")]
    note_frontmost_call_for_probe(pid, Some(code));
    frontmost_result(code)
}

fn write_frontmost<E: std::borrow::Borrow<AxRetainedElement>>(
    resolve: impl FnOnce() -> Result<E, AxElementActionError>,
    still_ours: &mut dyn FnMut() -> bool,
) -> Result<i32, AxElementActionError> {
    let name = CFString::from_static_str("AXFrontmost");
    let value = CFBoolean::new(true);
    // SAFETY: element, attribute name and the static Boolean are live for the
    // call.
    write_if_still_ours(resolve, still_ours, |application| unsafe {
        AXUIElementSetAttributeValue(
            application.borrow().as_ptr(),
            CFRetained::as_ptr(&name).as_ptr().cast(),
            (value as *const CFBoolean).cast(),
        )
    })
}

fn frontmost_result(code: i32) -> Result<(), AxElementActionError> {
    if code == AX_ERROR_SUCCESS {
        Ok(())
    } else {
        Err(classify(code))
    }
}

/// An application's accessibility element resolved ahead of time, so that a
/// later request to bring it forward (a restore at a deadline, say) makes no
/// lookup first: only the caller's identity check and the write remain.
pub struct PreparedFrontmost {
    pid: u32,
    application: AxRetainedElement,
}

impl PreparedFrontmost {
    /// The process id the element was resolved for.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// [`request_frontmost_while`] on the element resolved ahead of time:
    /// `still_ours` is asked immediately before `AXFrontmost` is written. The
    /// same race remains: the system resolves the pid again when it delivers
    /// the write.
    pub fn request_while(
        &self,
        still_ours: &mut dyn FnMut() -> bool,
    ) -> Result<(), AxElementActionError> {
        #[cfg(feature = "desk-probe")]
        note_frontmost_call_for_probe(self.pid, None);
        require_trust()?;
        let code = write_frontmost(
            || {
                // The element's messaging timeout follows this thread's
                // budget, not the one in force when it was resolved.
                bound_messages(self.application.as_ptr());
                Ok(&self.application)
            },
            still_ours,
        )?;
        #[cfg(feature = "desk-probe")]
        note_frontmost_call_for_probe(self.pid, Some(code));
        frontmost_result(code)
    }
}

/// Resolve `pid`'s application element now, for a later
/// [`PreparedFrontmost::request_while`].
pub fn prepare_frontmost(pid: u32) -> Result<PreparedFrontmost, AxElementActionError> {
    require_trust()?;
    Ok(PreparedFrontmost {
        pid,
        application: application(pid)?,
    })
}

/// Resolve the element, then ask `still_ours`, then write: the identity
/// check comes after the lookup so that nothing but the write follows it.
fn write_if_still_ours<E>(
    resolve: impl FnOnce() -> Result<E, AxElementActionError>,
    still_ours: &mut dyn FnMut() -> bool,
    write: impl FnOnce(&E) -> i32,
) -> Result<i32, AxElementActionError> {
    let element = resolve()?;
    if !still_ours() {
        return Err(AxElementActionError::ElementGone);
    }
    Ok(write(&element))
}

/// What the calling thread's latest [`request_frontmost`] did, for the manual
/// desk probe only: the pid it asked for and the raw accessibility error code
/// the write returned, `None` when it stopped before the write (no trust, or
/// no such process). The public result folds several codes into one error
/// kind, and the probe needs the exact code to tell a refused write from one
/// the application accepted without coming forward.
#[cfg(feature = "desk-probe")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrontmostCallForProbe {
    pub pid: u32,
    pub ax_error: Option<i32>,
}

#[cfg(feature = "desk-probe")]
thread_local! {
    static FRONTMOST_CALL_FOR_PROBE: std::cell::Cell<Option<FrontmostCallForProbe>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(feature = "desk-probe")]
fn note_frontmost_call_for_probe(pid: u32, ax_error: Option<i32>) {
    FRONTMOST_CALL_FOR_PROBE.set(Some(FrontmostCallForProbe { pid, ax_error }));
}

/// Take the calling thread's latest [`request_frontmost`] record. Per thread,
/// so a request made on another thread can never be read as this one's.
#[cfg(feature = "desk-probe")]
#[doc(hidden)]
pub fn take_frontmost_call_for_probe() -> Option<FrontmostCallForProbe> {
    FRONTMOST_CALL_FOR_PROBE.take()
}
