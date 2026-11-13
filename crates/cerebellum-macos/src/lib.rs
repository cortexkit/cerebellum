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

// release-build.sh sets CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION for the
// compiler, even when its caller forwards feature flags. Those shipped builds
// must exclude the probe's ad-hoc parent identity, which does not seal libraries.
#[cfg(feature = "chrome-for-testing-parent-probe")]
const _: () = assert!(
    option_env!("CEREBELLUM_RELEASE_SIGNING_TOPOLOGY_REVISION").is_none(),
    "chrome-for-testing-parent-probe is forbidden in attested release builds"
);

// Pure Rust, so its tests run on every host.
pub mod ax_budget;
// The accessibility traversal is compiled for unit tests on every host, so its
// input-bound checks run even where the macOS framework APIs are unavailable.
#[cfg(any(target_os = "macos", test))]
mod accessibility;
#[cfg(target_os = "macos")]
mod applications;
#[cfg(target_os = "macos")]
mod ax_actions;
#[cfg(target_os = "macos")]
mod ax_state;
#[cfg(target_os = "macos")]
pub use applications::{
    application_url_schemes, installed_applications, open_application, open_application_with_url,
    responsible_pid, workspace_running_applications, ApplicationOpenResult, InstalledApplication,
    InstalledApplicationList, InstalledInventoryFailure,
};
#[cfg(target_os = "macos")]
mod code_signing;
#[cfg(any(target_os = "macos", test))]
mod event_tap;
#[cfg(any(target_os = "macos", test))]
mod input;
#[cfg(target_os = "macos")]
mod launch;
#[cfg(any(target_os = "macos", all(unix, test)))]
mod pinned_executable;
#[cfg(target_os = "macos")]
pub use pinned_executable::PinnedExecutable;
#[cfg(any(target_os = "macos", test))]
mod responsibility;
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
pub use responsibility::spawn_disclaimed_and_wait;
#[cfg(any(target_os = "macos", test))]
pub use responsibility::{require_responsibility_disclaim, ResponsibilityDisclaimUnavailable};
#[cfg(all(target_os = "macos", test))]
#[path = "../../cerebellum/src/content_named_fixture.rs"]
mod content_named_fixture;
// Pure geometry, so its tests run on every host. Off macOS only the tests use
// it, and the drawing constants they do not touch would read as dead code.
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod cursor_geometry;
#[cfg(target_os = "macos")]
mod cursor_overlay;
#[cfg(any(target_os = "macos", test))]
mod cursor_schedule;
// The badge's timings, shared with the module through one source file: this
// crate cannot depend on `cerebellum-computer`, which declares the same file
// as its own module. The module works out each picture's motion with it and
// sends that on the picture line; the helper takes only the entry's phase
// proportions and the idle fade from it, never a length of its own.
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
#[path = "../../cerebellum-computer/src/cursor_timeline.rs"]
mod cursor_timeline;
// Where the background-mode preview sits and where a window point lands in
// it, shared with the module through one source file in the same way: the
// module times the badge's glides inside a preview with the thumbnail sizes
// the helper draws.
#[cfg(any(target_os = "macos", test))]
#[allow(dead_code)]
#[path = "../../cerebellum-computer/src/preview_layout.rs"]
mod preview_layout;
// The preview's lifetime and line rules are host-neutral, so their tests run
// on every host; the window that draws them is macOS only. Off macOS only the
// tests use it, and the line fields only the drawing reads would read as dead
// code.
#[cfg(target_os = "macos")]
mod macos;
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod preview_schedule;
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
pub use cursor_overlay::{
    prepare_app_use_desk_probe, probe_overlay_capture_exclusion, with_app_use_desk_probe_run_loop,
};
#[cfg(target_os = "macos")]
pub use cursor_overlay::{
    probe_cursor_hide, probe_cursor_motion, probe_preview_hide, reduce_motion,
    render_cursor_gallery_png, run_agent_cursor, CursorMotion, GalleryShot, HideProbe, MotionProbe,
    OverlayAccent, OverlayColours, OverlayEvent, OverlayGesture, OverlayMessage, PictureTiming,
    PreviewHideProbe, ProbePass, AVATAR_PIXELS,
};
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
pub use macos::take_window_list_errors_for_probe;
#[cfg(target_os = "macos")]
pub use preview_schedule::{OverlayFrame, OverlayPreview, OverlayPreviewMotion, PreviewFallback};
#[cfg(target_os = "macos")]
mod peer_attestation;
#[cfg(target_os = "macos")]
mod process_table;
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
// The record-offset selection is pure and compiled for unit tests on every
// host; the calls into the private framework are macOS-only.
#[cfg(any(target_os = "macos", test))]
mod skylight;
#[cfg(target_os = "macos")]
mod window_follow;
#[cfg(target_os = "macos")]
pub use window_follow::{watch_window, AxWindowChange, AxWindowWatch};
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
mod pointer_probe;
// The fail-closed rule is pure Rust, so its tests run on every host; off
// macOS only those tests use it.
#[cfg(any(target_os = "macos", test))]
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
mod window_identity;
#[cfg(target_os = "macos")]
mod window_image;
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
pub use pointer_probe::{
    pointer_helper_startup_sample, PointerHelperStartupSample, PointerHelperState,
};
#[cfg(all(target_os = "macos", feature = "desk-probe"))]
pub use window_image::{
    current_app_activation_mode_raw, pointer_hit_test_startup_diagnosis,
    pointer_probe_own_window_count, pointer_probe_posting_permitted, prepare_pointer_hit_tests,
};
#[cfg(target_os = "macos")]
pub use window_image::{cursor_position, display_frames, pointer_window_at, visible_window_ids};
#[cfg(any(target_os = "macos", test))]
mod window_visibility;
#[cfg(any(target_os = "macos", test))]
pub use window_visibility::{VisibilityRule, WindowVisibility};

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
pub use ax_actions::enable_manual_accessibility;
#[cfg(target_os = "macos")]
pub use ax_actions::{
    application_is_hidden, cursor_caret_frame, cursor_element_frame, cursor_element_label,
    cursor_element_window, cursor_focused_window, element_at_position, element_enabled,
    element_facts, element_parent, element_selected_range, element_text_value,
    element_window_number, focused_element, focused_window, press_element, request_frontmost,
    select_element_range, show_element_menu, window_minimized, write_element_text,
    AxElementActionError, AxElementFacts, AxHitScope, AxTextAttribute,
};
#[cfg(target_os = "macos")]
pub use manual_accessibility::prepare_manual_accessibility;
#[cfg(any(target_os = "macos", test))]
mod manual_accessibility;
#[cfg(target_os = "macos")]
pub use ax_state::{
    read_app_state, read_app_state_with_menus, read_element_state, AxAppState, AxAppStateBounds,
    AxAppStateError, AxRetainedElement, AxStateElement, AxStateValue,
};
#[cfg(target_os = "macos")]
pub use code_signing::{
    bundle_code_satisfies_requirement, bundle_code_signing_identity, code_satisfies_requirement,
    code_signing_identity, CodeSigningError, CodeSigningIdentity, RequirementCheck,
};
#[cfg(target_os = "macos")]
pub use event_tap::{uptime_now_ns, SessionEventTap};
#[cfg(any(target_os = "macos", test))]
pub use event_tap::{SessionEvent, SessionEventTapError};
#[cfg(target_os = "macos")]
pub use input::{
    event_post_access, heartbeat_marker_event, horizontal_scroll_wheel_event,
    input_monitoring_access, key_combination_events, mouse_click_events, mouse_drag_events,
    mouse_move_event, mouse_move_event_from_private_source, scroll_wheel_event,
    seconds_since_last_deliberate_input, seconds_since_last_input, text_input_events,
};
#[cfg(any(target_os = "macos", test))]
pub use input::{
    EventPoint, EventSourceStateTable, InputEventConstructionError, InputMonitoringAccess,
    KeyModifiers, ScrollUnit, VirtualKey,
};
#[cfg(target_os = "macos")]
pub use launch::{
    executed_image_identity, process_descriptors, spawn_barred, spawn_barred_cursor,
    spawn_barred_stdin, terminate_exact_generation, BarredChild, ExecutedImageIdentity,
    ImageIdentityError, ProcessControlError, ProcessGeneration, ReleasedChild, SpawnError,
    TerminationOutcome,
};
#[cfg(target_os = "macos")]
pub use macos::{
    application_bundle_path, capture_window, encode_png, enumerate_windows,
    establish_window_server_connection, frontmost_process_id, hardware_uuid, is_off_main_thread,
    post_event_at_hid_tap_for_measurement, post_event_globally, post_event_to_pid, process_owner,
    process_start_time, process_start_time_micros, responsible_process, running_applications,
    screen_capture_is_permitted, screen_is_locked, CaptureError, CaptureSourceRect,
    CgEventPostCall, OwnedCgEvent, ProcessOwner, ProcessStartTime, RawCapture, RawWindow,
    RunningApplication,
};
#[cfg(any(target_os = "macos", test))]
pub use manual_accessibility::{ManualAccessibility, ManualAccessibilityScope};
#[cfg(target_os = "macos")]
pub use peer_attestation::{
    local_socket_peer_pid, parent_satisfies_chrome_requirement, peer_satisfies_requirement,
    ProcessRequirementError, CHROME_PARENT_REQUIREMENT,
};
#[cfg(all(target_os = "macos", feature = "chrome-for-testing-parent-probe"))]
pub use peer_attestation::{
    parent_satisfies_chrome_for_testing_probe_requirement, CHROME_FOR_TESTING_PARENT_PROBE_VERSION,
};
#[cfg(target_os = "macos")]
pub use process_table::{
    all_process_ids, host_name, process_arguments, process_executable_path, ProcessArguments,
};
#[cfg(target_os = "macos")]
pub use skylight::{
    keyboard_auth_available, post_key_to_pid, post_single_key_to_pid, skylight_available,
    OwnedKeyEvent, PostResult,
};
#[cfg(target_os = "macos")]
pub use window_image::{
    encode_scaled_jpeg, frontmost_window_id, process_window_counts, register_cursor_generation,
    topmost_window_at, visible_cursor_point, window_visibility, window_visibility_decision,
    ProcessWindowCounts,
};
