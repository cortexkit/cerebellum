use super::*;

/// The health reply's metrics, from the module's own control handler.
async fn health_metrics() -> serde_json::Value {
    let (tx, mut rx) = mpsc::channel(8);
    let request = Frame::build_with_version(
        subc_protocol::PROTOCOL_VERSION,
        FrameType::Request,
        subc_protocol::Flags::new(false, subc_protocol::Priority::Passive, false),
        0,
        0,
        1,
        serde_json::to_vec(&ModuleControlRequest::HealthCheck {}).unwrap(),
    )
    .unwrap();
    let health = Arc::new(HealthState::new());
    handle_control_request_for_test(request, &tx, &health)
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

/// A listener that could not be installed leaves SIGTERM ending the module
/// with no teardown. Nothing is printed about it, so the health reply is
/// where it shows.
#[tokio::test]
async fn a_sigterm_listener_that_failed_to_install_is_reported_on_the_health_reply() {
    let listener = listen_for_sigterm_with(|| Err(std::io::Error::other("fixture")));
    assert!(listener.is_none());
    assert_eq!(health_metrics().await["sigtermListener"], "not_installed");
}

/// A failed backup-catalog write is printed nowhere, so the health reply is
/// where it shows. No test runs the production entry point, so the count
/// here is the untouched zero.
#[tokio::test]
async fn the_backup_catalog_write_failure_count_is_on_the_health_reply() {
    assert_eq!(health_metrics().await["engramCatalogWriteFailures"], 0);
}

#[tokio::test]
async fn bus_notice_counters_are_on_the_health_reply() {
    let metrics = health_metrics().await;
    assert!(metrics["busEventsPublished"].is_u64());
    assert!(metrics["busEventsFailed"].is_u64());
    let reason = metrics
        .get("busEventsLastFailureReason")
        .expect("last failure health key");
    assert!(
        reason.is_null()
            || matches!(
                reason.as_str(),
                Some("unavailable" | "timeout" | "overflow" | "expired")
            )
    );
}

#[tokio::test]
async fn audit_reservation_cleanup_failures_are_on_the_health_reply() {
    assert_eq!(
        health_metrics().await["auditReservationCleanupFailures"],
        json!(cerebellum_computer::audit::audit_reservation_cleanup_failures())
    );
}

#[tokio::test]
async fn late_fronting_journal_failures_are_on_the_health_reply() {
    assert_eq!(
        health_metrics().await["lateFrontingJournalFailures"],
        json!(computer_capability::late_fronting_journal_failures())
    );
}
