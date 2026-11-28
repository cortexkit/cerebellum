//! Short-lived, HWND-scoped UI Automation facts. COM objects stay on a
//! windowless thread in its multithreaded apartment.

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use windows_sys::Win32::System::Com::SAFEARRAY;
use windows_sys::Win32::System::Ole::{
    SafeArrayDestroy, SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetLBound, SafeArrayGetUBound,
};
use windows_sys::Win32::UI::Accessibility::{
    UIA_ExpandCollapsePatternId, UIA_SelectionItemPatternId, UIA_TextPatternId,
    UIA_TogglePatternId, UIA_ValuePatternId, UIA_E_ELEMENTNOTAVAILABLE, UIA_E_NOTSUPPORTED,
};

mod actuators;

type Failure = AccessibilityReadFailure;

const UIA_GET_FOCUSED_ELEMENT: usize = 8;
const WALKER_PARENT: usize = 3;
const ELEMENT_RUNTIME_ID: usize = 4;
const ELEMENT_NATIVE_WINDOW: usize = 36;
const IID_VALUE: GUID = GUID::from_u128(0xa94cd8b1_0844_4cd6_9d2d_640537ab39e9);
const IID_TEXT: GUID = GUID::from_u128(0x32eba289_3583_42c9_9c59_3b6d9a1e9b6a);

/// An opaque reference usable only in the MTA callback that obtained it.
pub struct UiaElementRef(ComPtr);

pub struct ScopedUia {
    source: UiaSource,
    deadline: Deadline,
}

/// Run a read on a windowless MTA with one end-to-end deadline. Timed-out COM
/// calls cannot be cancelled, so they keep their slot and captured data until
/// the callback really exits; otherwise repeated polls could spawn unbounded workers.
pub fn with_scoped_uia<T, E>(
    pid: u32,
    generation: u64,
    end: Instant,
    run: impl FnOnce(&ScopedUia) -> Result<T, E> + Send + 'static,
) -> Result<T, E>
where
    T: Send + 'static,
    E: From<Failure> + Send + 'static,
{
    const MAX_WORKERS: usize = 4;
    static WORKERS: AtomicUsize = AtomicUsize::new(0);
    struct Slot;
    impl Drop for Slot {
        fn drop(&mut self) {
            WORKERS.fetch_sub(1, Ordering::Release);
        }
    }
    let remaining = || end.saturating_duration_since(Instant::now());
    if remaining().is_zero() {
        return Err(Failure::RetryableDeadlineExceeded.into());
    }
    let mut workers = WORKERS.load(Ordering::Relaxed);
    loop {
        if workers >= MAX_WORKERS {
            return Err(Failure::PlatformReadFailed.into());
        }
        match WORKERS.compare_exchange_weak(
            workers,
            workers + 1,
            Ordering::Acquire,
            Ordering::Relaxed,
        ) {
            Ok(_) => break,
            Err(current) => workers = current,
        }
    }
    let slot = Slot;
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("cerebellum-uia-window".into())
        .spawn(move || {
            let result = (|| {
                let _apartment = ComApartment::initialize()?;
                let deadline = Deadline::new(end.saturating_duration_since(Instant::now()));
                let source = UiaSource::new(pid, generation, deadline.remaining()?)?;
                // Name the client so its interfaces release before CoUninitialize.
                let client = ScopedUia { source, deadline };
                run(&client)
            })();
            drop(slot);
            let _ = send.send(result);
        })
        .map_err(|_| Failure::PlatformReadFailed)?;
    let result = receive
        .recv_timeout(remaining())
        .map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => Failure::RetryableDeadlineExceeded,
            std::sync::mpsc::RecvTimeoutError::Disconnected => Failure::PlatformReadFailed,
        })?;
    if remaining().is_zero() {
        return Err(Failure::RetryableDeadlineExceeded.into());
    }
    result
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UiaPatterns {
    pub invoke: bool,
    pub toggle: bool,
    pub selection_item: bool,
    pub expand_collapse: bool,
    pub value_read_only: Option<bool>,
}

struct Array(NonNull<SAFEARRAY>);

impl Drop for Array {
    fn drop(&mut self) {
        // SAFETY: GetRuntimeId transferred ownership and no access is locked.
        unsafe { SafeArrayDestroy(self.0.as_ptr()) };
    }
}

impl Array {
    fn runtime_id(&self) -> Result<Vec<i32>, Failure> {
        let raw = self.0.as_ptr();
        let mut low = 0;
        let mut high = 0;
        // SAFETY: GetRuntimeId returns a one-dimensional array of 32-bit integers.
        // Check its dimensionality and bounds before indexing it.
        unsafe {
            if SafeArrayGetDim(raw) != 1
                || SafeArrayGetLBound(raw, 1, &mut low) < 0
                || SafeArrayGetUBound(raw, 1, &mut high) < 0
                || !high
                    .checked_sub(low)
                    .is_some_and(|delta| (0..128).contains(&delta))
            {
                return Err(Failure::IncompatiblePlatformValue);
            }
            (low..=high)
                .map(|index| {
                    let mut value = 0_i32;
                    hresult(SafeArrayGetElement(
                        raw,
                        &index,
                        (&mut value as *mut i32).cast(),
                    ))
                    .map_err(|_| Failure::IncompatiblePlatformValue)?;
                    Ok(value)
                })
                .collect()
        }
    }
}

impl ScopedUia {
    fn prepare(&self) -> Result<(), Failure> {
        self.source.prepare_call(&self.deadline)
    }

    fn map(&self, code: HRESULT) -> Failure {
        self.source.map_hresult(code)
    }

    pub fn at_window(&self, window: u32) -> Result<UiaElementRef, Failure> {
        self.prepare()?;
        self.source
            .element_from_handle(window as usize as HWND)?
            .map(UiaElementRef)
            .ok_or(Failure::TargetNotInspectable)
    }

    pub fn focused(&self) -> Result<Option<UiaElementRef>, Failure> {
        self.prepare()?;
        Ok(
            UiaSource::interface_out(&self.source.automation, UIA_GET_FOCUSED_ELEMENT)
                .map_err(|code| self.map(code))?
                .map(UiaElementRef),
        )
    }

    pub fn same(&self, a: &UiaElementRef, b: &UiaElementRef) -> Result<bool, Failure> {
        self.prepare()?;
        self.source.compare_elements(&a.0, &b.0)
    }

    fn neighbor(
        &self,
        slot: usize,
        element: &UiaElementRef,
    ) -> Result<Option<UiaElementRef>, Failure> {
        self.prepare()?;
        Ok(self
            .source
            .walker_element(slot, &element.0)?
            .map(UiaElementRef))
    }

    pub fn parent(&self, element: &UiaElementRef) -> Result<Option<UiaElementRef>, Failure> {
        self.neighbor(WALKER_PARENT, element)
    }

    pub fn child(&self, element: &UiaElementRef) -> Result<Option<UiaElementRef>, Failure> {
        self.neighbor(WALKER_FIRST_CHILD, element)
    }

    pub fn sibling(&self, element: &UiaElementRef) -> Result<Option<UiaElementRef>, Failure> {
        self.neighbor(WALKER_NEXT_SIBLING, element)
    }

    pub fn native_window(&self, element: &UiaElementRef) -> Result<Option<u32>, Failure> {
        self.prepare()?;
        type Method = unsafe extern "system" fn(*mut c_void, *mut HWND) -> HRESULT;
        let mut value: HWND = ptr::null_mut();
        // SAFETY: This slot is get_CurrentNativeWindowHandle; the out pointer is writable.
        unsafe {
            let method: Method = mem::transmute(element.0.slot(ELEMENT_NATIVE_WINDOW));
            hresult(method(element.0.as_raw(), &mut value)).map_err(|code| self.map(code))?;
        }
        Ok((!value.is_null()).then_some(value as usize as u32))
    }

    pub fn runtime_id(&self, element: &UiaElementRef) -> Result<Option<Vec<i32>>, Failure> {
        self.prepare()?;
        type Method = unsafe extern "system" fn(*mut c_void, *mut *mut SAFEARRAY) -> HRESULT;
        let mut array = ptr::null_mut();
        // SAFETY: This slot is GetRuntimeId, which writes an owned array on success.
        let result = unsafe {
            let method: Method = mem::transmute(element.0.slot(ELEMENT_RUNTIME_ID));
            method(element.0.as_raw(), &mut array)
        };
        let array = NonNull::new(array).map(Array);
        if result == UIA_E_ELEMENTNOTAVAILABLE as HRESULT {
            return Ok(None);
        }
        hresult(result).map_err(|code| self.map(code))?;
        array.map(|array| array.runtime_id()).transpose()
    }

    pub fn pid(&self, element: &UiaElementRef) -> Result<u32, Failure> {
        self.prepare()?;
        let pid = self
            .source
            .element_i32(&element.0, ELEMENT_CURRENT_PROCESS_ID)?;
        u32::try_from(pid)
            .ok()
            .filter(|pid| *pid != 0)
            .ok_or(Failure::IncompatiblePlatformValue)
    }

    pub fn control_type(&self, element: &UiaElementRef) -> Result<i32, Failure> {
        self.prepare()?;
        self.source
            .element_i32(&element.0, ELEMENT_CURRENT_CONTROL_TYPE)
    }

    pub fn name(&self, element: &UiaElementRef) -> Result<String, Failure> {
        self.prepare()?;
        self.source.element_string(&element.0, ELEMENT_CURRENT_NAME)
    }

    pub fn automation_id(&self, element: &UiaElementRef) -> Result<String, Failure> {
        self.prepare()?;
        self.source
            .element_string(&element.0, ELEMENT_CURRENT_AUTOMATION_ID)
    }

    pub fn class_name(&self, element: &UiaElementRef) -> Result<String, Failure> {
        self.prepare()?;
        self.source
            .element_string(&element.0, ELEMENT_CURRENT_CLASS_NAME)
    }

    pub fn password(&self, element: &UiaElementRef) -> Result<bool, Failure> {
        self.prepare()?;
        self.source
            .element_bool(&element.0, ELEMENT_CURRENT_IS_PASSWORD)
    }

    pub fn enabled(&self, element: &UiaElementRef) -> Result<bool, Failure> {
        self.prepare()?;
        self.source
            .element_bool(&element.0, ELEMENT_CURRENT_IS_ENABLED)
    }

    pub fn offscreen(&self, element: &UiaElementRef) -> Result<bool, Failure> {
        self.prepare()?;
        self.source
            .element_bool(&element.0, ELEMENT_CURRENT_IS_OFFSCREEN)
    }

    pub fn rectangle(&self, element: &UiaElementRef) -> Result<UiaRectangle, Failure> {
        self.prepare()?;
        self.source.element_rectangle(&element.0)
    }

    fn pattern(
        &self,
        element: &UiaElementRef,
        id: i32,
        iid: Option<&GUID>,
    ) -> Result<Option<ComPtr>, Failure> {
        self.prepare()?;
        type Method = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> HRESULT;
        let mut raw = ptr::null_mut();
        // SAFETY: The slot is GetCurrentPattern. On success, the out pointer owns one IUnknown reference.
        let result = unsafe {
            let method: Method = mem::transmute(element.0.slot(ELEMENT_GET_CURRENT_PATTERN));
            method(element.0.as_raw(), id, &mut raw)
        };
        if result == UIA_E_NOTSUPPORTED as HRESULT {
            return Ok(None);
        }
        hresult(result).map_err(|code| self.map(code))?;
        let Some(pattern) = (unsafe { ComPtr::from_raw(raw) }) else {
            return Ok(None);
        };
        if let Some(iid) = iid {
            self.prepare()?;
            pattern.query_interface(iid).map_err(|code| self.map(code))
        } else {
            Ok(Some(pattern))
        }
    }

    pub fn patterns(&self, element: &UiaElementRef) -> Result<UiaPatterns, Failure> {
        let value_read_only =
            if let Some(value) = self.pattern(element, UIA_ValuePatternId, Some(&IID_VALUE))? {
                self.prepare()?;
                // IUIAutomationValuePattern::get_CurrentIsReadOnly has a BOOL out parameter.
                Some(self.source.element_bool(&value, 5)?)
            } else {
                None
            };
        Ok(UiaPatterns {
            invoke: self.pattern(element, UIA_InvokePatternId, None)?.is_some(),
            toggle: self.pattern(element, UIA_TogglePatternId, None)?.is_some(),
            selection_item: self
                .pattern(element, UIA_SelectionItemPatternId, None)?
                .is_some(),
            expand_collapse: self
                .pattern(element, UIA_ExpandCollapsePatternId, None)?
                .is_some(),
            value_read_only,
        })
    }

    /// The raw current ValuePattern string. Callers classify the element before using this getter.
    pub fn current_value(&self, element: &UiaElementRef) -> Result<Option<String>, Failure> {
        let Some(value) = self.pattern(element, UIA_ValuePatternId, Some(&IID_VALUE))? else {
            return Ok(None);
        };
        self.prepare()?;
        // IUIAutomationValuePattern::get_CurrentValue has a BSTR out parameter.
        self.source.element_string(&value, 4).map(Some)
    }

    /// Document-relative UTF-16 offsets as reported by TextPattern. A missing
    /// or non-single selection cannot establish one caret position.
    pub fn text_selection(
        &self,
        element: &UiaElementRef,
    ) -> Result<Option<(usize, usize)>, Failure> {
        self.text_selection_with_limit(element, 64 * 1024, false)
    }

    /// Read the selection and check the full document against a caller's limit.
    /// Only a missing TextPattern is reported as `None`.
    pub fn bounded_text_selection(
        &self,
        element: &UiaElementRef,
        maximum_utf16: u32,
    ) -> Result<Option<(usize, usize)>, Failure> {
        self.text_selection_with_limit(element, maximum_utf16.min(64 * 1024), true)
    }

    fn text_selection_with_limit(
        &self,
        element: &UiaElementRef,
        maximum_utf16: u32,
        check_document: bool,
    ) -> Result<Option<(usize, usize)>, Failure> {
        let Some(text) = self.pattern(element, UIA_TextPatternId, Some(&IID_TEXT))? else {
            return Ok(None);
        };
        // IUIAutomationTextPattern::GetSelection and get_DocumentRange.
        let selections = self
            .interface(&text, 5)?
            .ok_or(Failure::PlatformReadFailed)?;
        self.prepare()?;
        // IUIAutomationTextRangeArray::get_Length has an int out parameter.
        if self.source.element_i32(&selections, 3)? != 1 {
            return if check_document {
                Err(Failure::PlatformReadFailed)
            } else {
                Ok(None)
            };
        }
        let selection = self.first_range(&selections)?;
        let document = self
            .interface(&text, 7)?
            .ok_or(Failure::PlatformReadFailed)?;
        if check_document {
            self.text_length(&document, maximum_utf16)?;
        }
        self.move_end_to_start(&document, &selection)?;
        Ok(Some((
            self.text_length(&document, maximum_utf16)?,
            self.text_length(&selection, maximum_utf16)?,
        )))
    }

    fn interface(&self, parent: &ComPtr, slot: usize) -> Result<Option<ComPtr>, Failure> {
        self.prepare()?;
        UiaSource::interface_out(parent, slot).map_err(|code| self.map(code))
    }

    fn first_range(&self, ranges: &ComPtr) -> Result<ComPtr, Failure> {
        self.prepare()?;
        type Method = unsafe extern "system" fn(*mut c_void, i32, *mut *mut c_void) -> HRESULT;
        let mut raw = ptr::null_mut();
        // SAFETY: This is IUIAutomationTextRangeArray::GetElement, and index zero exists.
        let result = unsafe {
            let method: Method = mem::transmute(ranges.slot(4));
            method(ranges.as_raw(), 0, &mut raw)
        };
        hresult(result).map_err(|code| self.map(code))?;
        // SAFETY: A non-null successful out pointer owns one reference.
        unsafe { ComPtr::from_raw(raw) }.ok_or(Failure::PlatformReadFailed)
    }

    fn move_end_to_start(&self, document: &ComPtr, selection: &ComPtr) -> Result<(), Failure> {
        self.prepare()?;
        type Method = unsafe extern "system" fn(*mut c_void, i32, *mut c_void, i32) -> HRESULT;
        // SAFETY: IUIAutomationTextRange::MoveEndpointByRange takes two live ranges
        // and endpoint enum values 1 (End) and 0 (Start).
        let result = unsafe {
            let method: Method = mem::transmute(document.slot(15));
            method(document.as_raw(), 1, selection.as_raw(), 0)
        };
        hresult(result).map_err(|code| self.map(code))
    }

    fn text_length(&self, range: &ComPtr, maximum_utf16: u32) -> Result<usize, Failure> {
        self.prepare()?;
        type Method = unsafe extern "system" fn(*mut c_void, i32, *mut BSTR) -> HRESULT;
        let mut value = ptr::null();
        // SAFETY: IUIAutomationTextRange::GetText takes a character bound and a
        // writable BSTR out pointer; its successful response transfers ownership.
        let result = unsafe {
            let method: Method = mem::transmute(range.slot(12));
            method(range.as_raw(), (maximum_utf16 + 1) as i32, &mut value)
        };
        hresult(result).map_err(|code| self.map(code))?;
        let text = OwnedBstr(value);
        // SAFETY: The owned BSTR stays live for the call; null has length zero.
        let len = unsafe { SysStringLen(text.0) };
        if len > maximum_utf16 {
            return Err(Failure::TreeExceedsBound);
        }
        Ok(len as usize)
    }
}
