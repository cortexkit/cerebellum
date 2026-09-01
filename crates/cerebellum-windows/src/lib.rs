//! A narrow seam over Windows process and window primitives, and nothing else.
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
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "windows")]
pub use windows::{
    enumerated_window_visibility, process_start_time, retain_process_handle, ProcessHandleError,
    ProcessStartTime, RetainedProcessHandle, WindowVisibility,
};
