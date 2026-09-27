//! A crash-report directory that could not be deleted outside a session is
//! reported on the health reply.
//!
//! The module prints nothing, so a failed delete in the startup sweep, or on a
//! launch that failed part-way, has no session reply to appear in. The health
//! reply's `crashReportLeftovers` counts are where a person reads it. This file
//! holds one test, so the process-wide counts start at zero and are this
//! test's alone.

#![cfg(target_os = "macos")]

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use serde_json::{json, Value};
use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

use cerebellum::browser_crash_reports::{
    sweep_leftover_directories_in, LeftoverSweep, CRASH_REPORTS_DIRECTORY_PREFIX,
};

/// The `crashReportLeftovers` metric from a health reply produced by the
/// module's own control handler.
async fn leftovers_on_the_health_reply() -> Value {
    let (tx, mut rx) = mpsc::channel(8);
    let request = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        1,
        serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
    )
    .unwrap();
    let health = std::sync::Arc::new(cerebellum_core::health::HealthState::new());
    cerebellum::handle_control_request_for_test(request, &tx, &health)
        .await
        .unwrap();
    let reply = rx.recv().await.unwrap();
    let ModuleControlResponse::HealthCheck {
        metrics: Some(metrics),
        ..
    } = serde_json::from_slice(&reply.body).unwrap()
    else {
        panic!("health reply")
    };
    metrics["crashReportLeftovers"].clone()
}

/// A private directory for the test, removed when it ends.
struct TestParent(PathBuf);

impl Drop for TestParent {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[tokio::test]
async fn a_leftover_the_startup_sweep_could_not_delete_is_counted_on_the_health_reply() {
    assert_eq!(
        leftovers_on_the_health_reply().await,
        json!({"removed": 0, "failed": 0})
    );

    let parent = TestParent(
        std::env::temp_dir().join(format!("ck-crash-report-health-{}", std::process::id())),
    );
    let _ = std::fs::remove_dir_all(&parent.0);
    std::fs::create_dir(&parent.0).expect("create test parent");
    let deletable = parent
        .0
        .join(format!("{CRASH_REPORTS_DIRECTORY_PREFIX}1-1-0"));
    std::fs::create_dir(&deletable).expect("plant a deletable leftover");
    let stuck = parent
        .0
        .join(format!("{CRASH_REPORTS_DIRECTORY_PREFIX}1-1-1"));
    std::fs::create_dir(&stuck).expect("plant a leftover that cannot be deleted");
    std::fs::write(stuck.join("minidump"), b"page memory").expect("plant a report");
    // Without write permission on the leftover its report cannot be unlinked,
    // so deleting it fails.
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o500))
        .expect("make the leftover unwritable");

    // Every planted creator counts as gone, as for a process that has exited.
    let sweep = sweep_leftover_directories_in(&parent.0, |_, _| false);
    std::fs::set_permissions(&stuck, std::fs::Permissions::from_mode(0o700))
        .expect("restore permissions");

    assert_eq!(
        sweep,
        LeftoverSweep {
            removed: 1,
            failed: 1
        }
    );
    assert_eq!(
        leftovers_on_the_health_reply().await,
        json!({"removed": 1, "failed": 1})
    );
}
