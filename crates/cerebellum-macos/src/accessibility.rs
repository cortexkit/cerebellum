//! Read-only accessibility values reported by macOS.

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

const AX_ERROR_FAILURE: i32 = -25_200;
const AX_ERROR_INVALID_UI_ELEMENT: i32 = -25_202;
const AX_ERROR_CANNOT_COMPLETE: i32 = -25_204;
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
        AxElement, AxFrame, AxReadError, AxReadOptions, ChildBudget, Deadline, ElementSnapshot,
        ElementSource, SourceError, AX_ERROR_API_DISABLED,
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
            // This setter changes only the timeout used by subsequent reads.
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
                // ESRCH is the only answer that says no process exists. EPERM and
                // any other failure still describe a pid held by a process.
                // SAFETY: reads thread-local errno set by `process_signal` above.
                unsafe { errno_location().read() != 3 }
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
}

#[cfg(target_os = "macos")]
pub use platform::{accessibility_is_permitted, read_accessibility_tree};

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

    fn options(max_depth: usize, max_elements: usize) -> AxReadOptions {
        AxReadOptions {
            timeout: Duration::from_secs(1),
            max_depth,
            max_elements,
        }
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
                    "SKIPPED real accessibility tree read: this test process has no accessibility permission"
                );
            }
            Err(AxReadError::ProcessNotAccessible { ax_error, .. }) => {
                eprintln!(
                    "SKIPPED real accessibility tree read: the test binary exposes no application tree (AX error {ax_error})"
                );
            }
            Err(other) => panic!("reading the live test process failed unexpectedly: {other}"),
        }
    }
}
