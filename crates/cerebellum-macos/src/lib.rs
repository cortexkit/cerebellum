//! A narrow seam over macOS frameworks, and nothing else.
//!
//! This crate exists so that `cerebellum-computer` can keep
//! `#![forbid(unsafe_code)]`. That is not a style preference there: it is the
//! crate that will eventually synthesize input events, and `forbid` cannot be
//! overridden from inside a crate, so the guarantee holds for every module in
//! it without anyone having to enforce it. Calling into a C API requires
//! `unsafe`, so the calls live here instead and the guarantee stays exact.
//!
//! The bargain only works if this crate stays small and stays dumb. It returns
//! plain framework values and exposes one typed accessibility action request.
//! It decides nothing: not which permissions a capability needs, not whether a
//! grant counts, not what a missing reading implies. Every one of those lives in
//! the platform-neutral code, which is built and tested on every host rather
//! than only on this one.
//!
//! The action request asks an application to invoke one control action that the
//! application itself advertised. Synthetic input, direct focus changes, and
//! window-raising actions are intentionally outside this seam.
//!
//! Read anything added here as code that no continuous build can check.

// The accessibility traversal is compiled for unit tests on every host, so its
// input-bound checks run even where the macOS framework APIs are unavailable.
#[cfg(any(target_os = "macos", test))]
mod accessibility;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
pub use accessibility::{
    accessibility_is_permitted, read_accessibility_tree, request_accessibility_action,
    AxAccessibilityTree, AxAction, AxActionError, AxActionOptions, AxActionRequestOutcome,
    AxElement, AxElementName, AxElementNameError, AxElementReadFailure, AxFrame, AxReadError,
    AxReadOptions, AxTreeCompleteness,
};
#[cfg(target_os = "macos")]
pub use macos::{
    capture_window, encode_png, enumerate_windows, establish_window_server_connection,
    is_off_main_thread, process_start_time, process_start_time_micros, responsible_process,
    screen_capture_is_permitted, screen_is_locked, ProcessStartTime, RawCapture, RawWindow,
};
