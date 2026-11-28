//! A narrow seam over Windows process, pipe, window, and filesystem primitives.
//!
//! This crate exists so platform-neutral crates can keep their exact
//! `#![forbid(unsafe_code)]` boundary. It reports raw operating-system readings
//! and holds raw process references; callers decide what those readings mean.
//!
//! Keep additions small and mechanical. This is the auditable place for Windows
//! calls, not a place to move application policy.

#![cfg_attr(
    all(windows, not(feature = "bridge-test-identities")),
    doc = "\nA normal build does not expose the fixture pipe constructor.\n\n```compile_fail,E0432\nuse cerebellum_windows::create_test_pipe_instance_default_security;\n```"
)]

// Windows APIs and their raw handles exist only on Windows. Keeping this module
// and its public surface behind the same gate makes other hosts build an empty
// library rather than a pretend implementation.
#[cfg(any(target_os = "windows", test))]
mod accessibility;
#[cfg(windows)]
mod browser_image;
#[cfg(windows)]
mod capture_facts;
#[cfg(windows)]
mod devtools_pipe;
#[cfg(windows)]
mod file_identity;
#[cfg(windows)]
mod foreground_events;
#[cfg(windows)]
pub mod identity;
#[cfg(windows)]
mod image_file_facts;
#[cfg(windows)]
mod input_facts;
#[cfg(windows)]
mod launch_facts;
#[cfg(windows)]
mod named_pipe;
#[cfg(windows)]
mod named_pipe_server;
#[cfg(any(windows, test))]
mod pe_product;
#[cfg(windows)]
mod pointer_facts;
#[cfg(windows)]
pub mod process;
#[cfg(windows)]
mod process_readings;
#[cfg(windows)]
mod registry_values;
#[cfg(any(target_os = "windows", test))]
mod session;
#[cfg(windows)]
mod signer_facts;
#[cfg(target_os = "windows")]
mod token_facts;
#[cfg(windows)]
mod window_identity_facts;
#[cfg(any(target_os = "windows", test))]
mod window_list;
#[cfg(windows)]
mod window_state_facts;
#[cfg(target_os = "windows")]
mod windows;
#[cfg(windows)]
pub mod writability;

#[cfg(windows)]
pub use accessibility::scoped::{with_scoped_uia, ScopedUia, UiaElementRef, UiaPatterns};
#[cfg(target_os = "windows")]
pub use accessibility::{
    invoke_accessibility_element, read_accessibility_tree, AccessibilityInvokeBounds,
    AccessibilityInvokeError, AccessibilityInvokeOutcome, AccessibilityReadBounds,
    AccessibilityReadFailure, UiaAccessibilityTree, UiaControlTypeAndName, UiaElement,
    UiaElementIdentity, UiaElementName, UiaRectangle, UiaTreeCompleteness,
};
#[cfg(windows)]
#[doc(hidden)]
pub use browser_image::timing::measure_image_check;
#[cfg(all(windows, feature = "bridge-test-identities"))]
pub use browser_image::timing::{trace_image_checks, ImageCheckTrace};
#[cfg(windows)]
pub use browser_image::{
    image_status, read_authenticode, read_catalog_signer, read_embedded_root_status,
    read_product_names, read_program_files_directory, read_system_directory, AuthenticodeReading,
    ImageReadError, MicrosoftRootReading, OpenedMachineDirectory, OpenedProcessImage,
    ProgramFilesDirectory, SignatureReading, SignerSubject,
};
#[cfg(windows)]
pub use capture_facts::{
    capture_support, first_window_jpeg, per_monitor_v2, set_process_per_monitor_v2,
    window_capture_properties, FrameReadError, WindowCaptureProperties, WindowFrameMetadata,
};
#[cfg(windows)]
pub use devtools_pipe::{spawn_with_devtools_pipe, DevToolsPipeReader, DevToolsProcess};
#[cfg(windows)]
pub use file_identity::{file_identity, FileIdentity};
#[cfg(windows)]
pub use foreground_events::{ForegroundEvent, ForegroundEvents};
#[cfg(windows)]
pub use image_file_facts::{
    lock_image_file, retain_image_process, ImageMappingReading, LockedImageFile,
    ProcessPackageFields,
};
#[cfg(windows)]
pub use input_facts::{
    async_key_down, input_tick, post_input, InputHooks, RawInputEvent, RawInputPost,
};
#[cfg(windows)]
pub use launch_facts::{
    activate_application, last_input_tick, package_applications, process_parents, read_shortcut,
    registered_packages, start_menu_directories, suspended_process, PackageApplication,
    RegisteredPackage, ShortcutFields, SuspendedProcess,
};
#[cfg(all(windows, feature = "bridge-test-identities"))]
pub use named_pipe::create_test_pipe_instance_default_security;
#[cfg(windows)]
pub use named_pipe::{
    named_pipe_client_pid, named_pipe_server_pid, open_named_pipe_client, wait_named_pipe,
    OverlappedPipe, ERROR_PIPE_BUSY,
};
#[cfg(windows)]
pub use named_pipe_server::create_named_pipe_instance;
#[cfg(windows)]
pub use pointer_facts::{
    cursor_position, gui_thread_capture, mouse_wheel_routing, virtual_screen, window_at_point,
};
#[cfg(windows)]
pub use process_readings::system_time_100ns;
#[cfg(windows)]
pub use registry_values::set_current_user_default_string;
#[cfg(windows)]
pub use signer_facts::{AuthenticodeFacts, SignerFields};
#[cfg(target_os = "windows")]
pub use token_facts::{
    current_process_token_elevation_type, current_process_token_facts,
    current_process_token_user_sid, TokenElevationType, TokenFacts,
};
#[cfg(windows)]
pub use window_identity_facts::{
    child_window_numbers, desktop_window_numbers, window_identity_facts, windows_system_directory,
    WindowIdentityFacts,
};
#[cfg(windows)]
pub use window_state_facts::{
    desktop_z_order, foreground_window_number, gui_thread_windows, input_desktop_name,
    root_window_number, set_foreground_window, window_owner, window_state_facts, GuiThreadWindows,
    WindowStateFacts,
};
#[cfg(target_os = "windows")]
pub use windows::{
    current_session_provenance, enumerate_top_level_windows, enumerated_window_visibility,
    process_start_time, retain_process_handle, retain_process_handle_for_image, ProcessHandleError,
    ProcessStartTime, RetainedProcessHandle, WindowVisibility,
};

// Pure data, so it is reachable wherever the readers that carry it are.
#[cfg(any(target_os = "windows", test))]
pub use session::SessionProvenance;
#[cfg(any(target_os = "windows", test))]
pub use window_list::{
    EnumerateWindowsError, TopLevelWindowOwner, TopLevelWindowReading, WindowListCompleteness,
    WindowOwnerUnreadable,
};
