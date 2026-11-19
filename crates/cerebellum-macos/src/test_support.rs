//! Shared permission gates for tests that exercise live macOS services.
//!
//! The preflight is supplied by the caller so tests can use this module without
//! adding another framework path. The module is available to this crate's tests
//! and to dependent tests that explicitly enable the `test-support` feature.
//! Live operations run only with CEREBELLUM_DESK_TESTS=1; ordinary tests print
//! SKIPPED instead of depending on grants held by the process that built them.
#![allow(dead_code)] // Each test target uses only the permission helpers it needs.

const DESK_TEST_RUN_SWITCH: &str = "CEREBELLUM_DESK_TESTS";
const DESK_TEST_DISABLED: &str = "desk test not enabled";

#[derive(Clone, Copy)]
pub enum Permission {
    ScreenRecording,
    Accessibility,
    InputMonitoring,
}

fn desk_tests_enabled() -> bool {
    std::env::var_os(DESK_TEST_RUN_SWITCH).is_some_and(|value| value == "1")
}

/// A live operation needs both an explicit desk-test opt-in and its permission.
/// Check the opt-in first so an ordinary test run does not touch the live service.
fn live_permission_skip_reason(
    permission: Permission,
    desk_tests_enabled: bool,
    preflight: impl FnOnce() -> bool,
) -> Option<&'static str> {
    if !desk_tests_enabled {
        return Some(DESK_TEST_DISABLED);
    }
    missing_permission(permission, preflight)
}

/// Gate a live Screen Recording test on desk opt-in and the non-prompting preflight.
pub fn screen_recording_skip_reason(preflight: impl FnOnce() -> bool) -> Option<&'static str> {
    live_permission_skip_reason(Permission::ScreenRecording, desk_tests_enabled(), preflight)
}

/// Gate a live Accessibility test on desk opt-in and the non-prompting preflight.
pub fn accessibility_skip_reason(preflight: impl FnOnce() -> bool) -> Option<&'static str> {
    live_permission_skip_reason(Permission::Accessibility, desk_tests_enabled(), preflight)
}

/// Gate a live Input Monitoring test on desk opt-in and the non-prompting preflight.
pub fn input_monitoring_skip_reason(preflight: impl FnOnce() -> bool) -> Option<&'static str> {
    live_permission_skip_reason(Permission::InputMonitoring, desk_tests_enabled(), preflight)
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

/// Run a live operation only after desk opt-in and its check-only preflight succeed.
pub(crate) fn run_after_permission_preflight_with_opt_in<T>(
    desk_tests_enabled: bool,
    permission: Permission,
    preflight: impl FnOnce() -> bool,
    operation: impl FnOnce() -> T,
) -> Result<T, &'static str> {
    match live_permission_skip_reason(permission, desk_tests_enabled, preflight) {
        Some(reason) => Err(reason),
        None => Ok(operation()),
    }
}

/// Run a live operation only after desk opt-in and its check-only preflight succeed.
pub fn run_after_permission_preflight<T>(
    permission: Permission,
    preflight: impl FnOnce() -> bool,
    operation: impl FnOnce() -> T,
) -> Result<T, &'static str> {
    run_after_permission_preflight_with_opt_in(
        desk_tests_enabled(),
        permission,
        preflight,
        operation,
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_live_operation_without_desk_opt_in_is_not_reached() {
        let reached = std::cell::Cell::new(false);
        let result = super::run_after_permission_preflight_with_opt_in(
            false,
            super::Permission::ScreenRecording,
            || true,
            || reached.set(true),
        );

        assert_eq!(result, Err("desk test not enabled"));
        assert!(!reached.get());
    }

    #[test]
    fn desk_opt_in_does_not_bypass_the_permission_preflight() {
        let reached = std::cell::Cell::new(false);
        let result = super::run_after_permission_preflight_with_opt_in(
            true,
            super::Permission::ScreenRecording,
            || false,
            || reached.set(true),
        );

        assert_eq!(
            result,
            Err("Screen Recording is not granted to the process running this test")
        );
        assert!(!reached.get());
    }

    #[test]
    fn an_opted_in_permitted_operation_runs() {
        let result = super::run_after_permission_preflight_with_opt_in(
            true,
            super::Permission::ScreenRecording,
            || true,
            || 7,
        );
        assert_eq!(result, Ok(7));
    }
}
