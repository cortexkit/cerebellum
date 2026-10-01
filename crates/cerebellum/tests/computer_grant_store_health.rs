// Separate binary: changes XDG_DATA_HOME and reads a process-wide grant-store health gauge.
//! A grant store that cannot be read is disclosed on the health reply.
//!
//! Its own test binary, because it points the data home at a scratch
//! directory through the environment, and the health gauge it reads is
//! process-wide. Nothing here touches the operator's data home: the test
//! refuses to write unless the resolved store path is inside its scratch
//! directory.

use std::sync::Arc;

use cerebellum::computer_grants::{durable_grant_store_health, ComputerGrants, GRANT_STORE_FILE};
use cerebellum::HealthState;
use serde_json::Value;
use subc_protocol::session::{ModuleControlRequest, ModuleControlResponse};
use subc_protocol::{Flags, Frame, FrameType, Priority, PROTOCOL_VERSION};
use tokio::sync::mpsc;

async fn health_metrics() -> Value {
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
    cerebellum::handle_control_request_for_test(request, &tx, &Arc::new(HealthState::new()))
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
    metrics
}

#[tokio::test]
async fn an_unreadable_grant_store_is_disclosed_on_the_health_reply() {
    let scratch = std::env::temp_dir().join(format!(
        "cerebellum-grant-health-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&scratch).unwrap();
    std::env::set_var("XDG_DATA_HOME", &scratch);
    let path = cerebellum_core::journal::journal_data_path(GRANT_STORE_FILE).unwrap();
    assert!(
        path.starts_with(&scratch),
        "the store resolved outside the scratch directory ({}); refusing to write",
        path.display()
    );
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not a grant store").unwrap();

    assert_eq!(health_metrics().await["computerGrantStore"], "not_opened");
    let grants = ComputerGrants::open_durable(Some("MACHINE".to_string()));
    assert!(grants.store_error().is_some());
    assert_eq!(durable_grant_store_health(), "unreadable");
    assert_eq!(health_metrics().await["computerGrantStore"], "unreadable");
    // Disclosed, not repaired: the unreadable file is left exactly as found.
    assert_eq!(std::fs::read(&path).unwrap(), b"not a grant store");
    let _ = std::fs::remove_dir_all(&scratch);
}
