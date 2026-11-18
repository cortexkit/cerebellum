//! Health reports the hardware observer without starting a permission check
//! or a tap. This separate test binary owns its process-wide startup state.

use std::sync::Arc;

use serde_json::json;
use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

#[tokio::test]
async fn health_reports_hardware_observer_without_starting_it() {
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
    let health = Arc::new(cerebellum_core::health::HealthState::new());
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
    let state = if cfg!(target_os = "macos") {
        "not_started"
    } else {
        "platform_unsupported"
    };
    assert_eq!(
        metrics["hardwareInputObserver"],
        json!({"state": state, "disabled_reenabled_count": 0,
            "install_failure_count": 0, "coverage_gap_count": 0, "last_problem": null})
    );
}
