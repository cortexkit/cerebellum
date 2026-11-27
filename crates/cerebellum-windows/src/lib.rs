//! A narrow seam over Windows process, pipe, window, and filesystem primitives.
//!
//! This crate exists so platform-neutral crates can keep their exact
//! `#![forbid(unsafe_code)]` boundary. It reports raw operating-system readings
//! and holds raw process references; callers decide what those readings mean.
//!
//! Keep additions small and mechanical. This is the auditable place for Windows
//! calls, not a place to move application policy.

// Windows APIs and their raw handles exist only on Windows. Keeping this module
// and its public surface behind the same gate makes other hosts build an empty
// library rather than a pretend implementation.
#[cfg(any(target_os = "windows", test))]
mod accessibility;
#[cfg(windows)]
mod devtools_pipe;
#[cfg(windows)]
mod file_identity;
#[cfg(any(target_os = "windows", test))]
mod session;
#[cfg(any(target_os = "windows", test))]
mod window_list;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use accessibility::{
    invoke_accessibility_element, read_accessibility_tree, AccessibilityInvokeBounds,
    AccessibilityInvokeError, AccessibilityInvokeOutcome, AccessibilityReadBounds,
    AccessibilityReadFailure, UiaAccessibilityTree, UiaControlTypeAndName, UiaElement,
    UiaElementIdentity, UiaElementName, UiaRectangle, UiaTreeCompleteness,
};
#[cfg(windows)]
pub use devtools_pipe::{spawn_with_devtools_pipe, DevToolsPipeReader, DevToolsProcess};
#[cfg(windows)]
pub use file_identity::{file_identity, FileIdentity};
#[cfg(target_os = "windows")]
pub use windows::{
    current_session_provenance, enumerate_top_level_windows, enumerated_window_visibility,
    process_start_time, retain_process_handle, ProcessHandleError, ProcessStartTime,
    RetainedProcessHandle, WindowVisibility,
};

// Pure data, so it is reachable wherever the readers that carry it are.
#[cfg(any(target_os = "windows", test))]
pub use session::SessionProvenance;
#[cfg(any(target_os = "windows", test))]
pub use window_list::{
    EnumerateWindowsError, TopLevelWindowOwner, TopLevelWindowReading, WindowListCompleteness,
    WindowOwnerUnreadable,
};
