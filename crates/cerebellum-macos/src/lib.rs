//! A narrow seam over macOS frameworks, and nothing else.
//!
//! This crate exists so that `cerebellum-computer` can keep
//! `#![forbid(unsafe_code)]`. That is not a style preference there: it is the
//! crate that owns input policy and dispatch, and `forbid` cannot be overridden
//! from inside a crate, so the guarantee holds for every module in it without
//! anyone having to enforce it. Calling into a C API requires `unsafe`, so raw
//! framework construction and delivery live here and the guarantee stays exact.
//!
//! The bargain only works if this crate stays small and stays dumb. It returns
//! plain framework values, exposes one typed accessibility action request, and
//! makes public CoreGraphics post calls. It decides nothing: not which
//! permissions a capability needs, not whether a grant counts, not what a
//! missing reading implies. Every one of those lives in the platform-neutral
//! code, which is built and tested on every host rather than only on this one.
//!
//! The action request asks an application to invoke one control action that the
//! application itself advertised. Input construction produces owned framework
//! events without targeting them, and each event-post request only forwards one
//! such event. The element actions press a retained element, write its text,
//! and ask an application to become frontmost; whether any of those may happen
//! is decided by the platform-neutral code that calls them.
//!
//! Read anything added here as code that no continuous build can check.

// The accessibility traversal is compiled for unit tests on every host, so its
// input-bound checks run even where the macOS framework APIs are unavailable.
#[cfg(any(target_os = "macos", test))]
mod accessibility;
#[cfg(target_os = "macos")]
mod ax_actions;
#[cfg(target_os = "macos")]
mod ax_state;
#[cfg(target_os = "macos")]
mod code_signing;
#[cfg(any(target_os = "macos", test))]
mod event_tap;
#[cfg(any(target_os = "macos", test))]
mod input;
#[cfg(target_os = "macos")]
mod launch;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
mod process_table;
#[cfg(target_os = "macos")]
mod window_image;

// The export gate MATCHES the module gate above. `accessibility` compiles off
// macOS under `test` on purpose, so its platform-neutral logic -- cycle
// detection, traversal bounds, name resolution -- stays covered on Linux CI.
// Exporting only on macOS left that module built with no public surface there,
// so items reachable only through these names read as dead code and failed the
// deny-warnings build. Two gates describing one decision have to agree.
#[cfg(any(target_os = "macos", test))]
pub use accessibility::{
    AxAccessibilityTree, AxAction, AxActionError, AxActionOptions, AxActionRequestOutcome,
    AxElement, AxElementName, AxElementNameError, AxElementReadError, AxElementReadFailure,
    AxElementReadback, AxFrame, AxReadError, AxReadOptions, AxReadbackAttribute,
    AxTreeCompleteness,
};
// The entry points themselves call the framework, so they exist only on macOS.
// The TYPES above do not, and that split is what lets the platform-neutral
// logic stay covered on Linux CI while the FFI stays where it belongs.
#[cfg(target_os = "macos")]
pub use accessibility::{
    accessibility_is_permitted, focused_application_pid, read_accessibility_element,
    read_accessibility_tree, request_accessibility_action, FocusReadError,
};
#[cfg(target_os = "macos")]
pub use ax_actions::{
    element_at_position, element_facts, element_selected_range, element_text_value,
    focused_element, press_element, request_frontmost, write_element_text, AxElementActionError,
    AxElementFacts, AxHitScope, AxTextAttribute,
};
#[cfg(target_os = "macos")]
pub use ax_state::{
    read_app_state, AxAppState, AxAppStateBounds, AxAppStateError, AxRetainedElement,
    AxStateElement, AxStateValue,
};
#[cfg(target_os = "macos")]
pub use code_signing::{
    code_satisfies_requirement, code_signing_identity, CodeSigningError, CodeSigningIdentity,
    RequirementCheck,
};
#[cfg(target_os = "macos")]
pub use event_tap::{uptime_now_ns, SessionEventTap};
#[cfg(any(target_os = "macos", test))]
pub use event_tap::{SessionEvent, SessionEventTapError};
#[cfg(target_os = "macos")]
pub use input::{
    event_post_access, heartbeat_marker_event, horizontal_scroll_wheel_event,
    input_monitoring_access, key_combination_events, mouse_drag_events, mouse_move_event,
    mouse_move_event_from_private_source, scroll_wheel_event, seconds_since_last_input,
    text_input_events,
};
#[cfg(any(target_os = "macos", test))]
pub use input::{
    EventPoint, EventSourceStateTable, InputEventConstructionError, InputMonitoringAccess,
    KeyModifiers, ScrollUnit, VirtualKey,
};
#[cfg(target_os = "macos")]
pub use launch::{
    executed_image_identity, process_descriptors, spawn_barred, terminate_exact_generation,
    BarredChild, ExecutedImageIdentity, ImageIdentityError, ProcessControlError, ProcessGeneration,
    ReleasedChild, SpawnError, TerminationOutcome,
};
#[cfg(target_os = "macos")]
pub use macos::{
    capture_window, encode_png, enumerate_windows, establish_window_server_connection,
    frontmost_process_id, hardware_uuid, is_off_main_thread, post_event_at_hid_tap_for_measurement,
    post_event_globally, post_event_to_pid, process_owner, process_start_time,
    process_start_time_micros, responsible_process, screen_capture_is_permitted, screen_is_locked,
    CaptureError, CaptureSourceRect, CgEventPostCall, OwnedCgEvent, ProcessOwner, ProcessStartTime,
    RawCapture, RawWindow,
};
#[cfg(target_os = "macos")]
pub use process_table::{
    all_process_ids, host_name, process_arguments, process_executable_path, ProcessArguments,
};
#[cfg(target_os = "macos")]
pub use window_image::{encode_scaled_jpeg, frontmost_window_id};
