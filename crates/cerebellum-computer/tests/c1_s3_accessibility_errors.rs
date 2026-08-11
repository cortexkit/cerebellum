use cerebellum_computer::platform::{AccessibilityReadFailure, DriverError};

#[test]
fn accessibility_read_failures_remain_typed_for_callers() {
    let cases = [
        AccessibilityReadFailure::PermissionRequired,
        AccessibilityReadFailure::TargetGone,
        AccessibilityReadFailure::TargetReplaced,
        AccessibilityReadFailure::TargetNotInspectable,
        AccessibilityReadFailure::RetryableDeadlineExceeded,
        AccessibilityReadFailure::TreeExceedsBound,
        AccessibilityReadFailure::IncompatiblePlatformValue,
        AccessibilityReadFailure::PlatformReadFailed,
    ];

    for failure in cases {
        assert_eq!(
            DriverError::from(failure),
            DriverError::AccessibilityUnreadable(failure),
            "the accessibility failure {failure:?} was flattened into another driver error"
        );
    }
}

#[test]
fn absent_element_is_not_an_unreadable_tree() {
    assert_eq!(
        DriverError::ElementNotFound.to_string(),
        "accessibility element not found"
    );
    assert_ne!(
        DriverError::ElementNotFound,
        DriverError::AccessibilityUnreadable(AccessibilityReadFailure::TargetGone),
        "a successfully read tree without the requested element must not be retried as unreadable"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn live_accessibility_tree_probe_runs_or_names_why_it_skipped() {
    use cerebellum_computer::platform::{
        native, AccessibilityTreeRequest, MacOs26PlatformDriver, PlatformDriver,
    };
    use std::time::Duration;

    let Some(target) = native::grant_for_pid(std::process::id(), Duration::from_millis(500)) else {
        eprintln!(
            "SKIP: the test process has no currently enumerable window, so no complete process grant can be constructed"
        );
        return;
    };

    let mut driver = MacOs26PlatformDriver::default();
    match driver.read_accessibility_tree(AccessibilityTreeRequest {
        target,
        settle_interval_ms: 500,
    }) {
        Ok(tree) => {
            assert!(
                tree.handshake_attempted,
                "a successful tree result must state that the read was attempted"
            );
            assert!(
                tree.root_identifier.is_some(),
                "a successful tree result must retain a root handle for later resolution"
            );
        }
        Err(DriverError::AccessibilityUnreadable(AccessibilityReadFailure::PermissionRequired)) => {
            eprintln!("SKIP: macOS Accessibility permission is not granted to this process");
        }
        Err(error) => panic!("live accessibility tree probe failed unexpectedly: {error}"),
    }
}
