//! Shared permission gates for tests that exercise live macOS services.
//!
//! The preflight is supplied by the caller so tests can use this module without
//! adding another framework path. The module is available to this crate's tests
//! and to dependent tests that explicitly enable the `test-support` feature.
#![allow(dead_code)] // Each test target uses only the permission helpers it needs.

#[derive(Clone, Copy)]
pub enum Permission {
    ScreenRecording,
    Accessibility,
    InputMonitoring,
}

/// Check Screen Recording with the supplied non-prompting preflight.
pub fn screen_recording_skip_reason(preflight: impl FnOnce() -> bool) -> Option<&'static str> {
    missing_permission(Permission::ScreenRecording, preflight)
}

/// Check Accessibility with the supplied non-prompting preflight.
pub fn accessibility_skip_reason(preflight: impl FnOnce() -> bool) -> Option<&'static str> {
    missing_permission(Permission::Accessibility, preflight)
}

/// Check Input Monitoring with the supplied non-prompting preflight.
pub fn input_monitoring_skip_reason(preflight: impl FnOnce() -> bool) -> Option<&'static str> {
    missing_permission(Permission::InputMonitoring, preflight)
}

/// Read a preflight for a custom test harness, which prints its own outcome.
pub fn missing_permission(
    permission: Permission,
    preflight: impl FnOnce() -> bool,
) -> Option<&'static str> {
    (!preflight()).then_some(match permission {
        Permission::ScreenRecording => {
            "Screen Recording is not granted to the process running this test"
        }
        Permission::Accessibility => {
            "Accessibility is not granted to the process running this test"
        }
        Permission::InputMonitoring => {
            "Input Monitoring is not granted to the process running this test"
        }
    })
}

/// Run an operation only after its check-only preflight succeeds.
pub fn run_after_permission_preflight<T>(
    permission: Permission,
    preflight: impl FnOnce() -> bool,
    operation: impl FnOnce() -> T,
) -> Result<T, &'static str> {
    match missing_permission(permission, preflight) {
        Some(reason) => Err(reason),
        None => Ok(operation()),
    }
}
