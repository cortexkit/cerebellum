#[allow(dead_code, unused_imports)]
#[path = "../src/capture/mod.rs"]
mod capture;

#[allow(dead_code, unused_imports)]
#[path = "../src/platform/mod.rs"]
mod platform;

use capture::{
    BroadDisplayCaptureRequest, BroadDisplayGrant, CaptureError, CaptureLeakageFlag,
    CaptureLeakageReport, CaptureSessionState, EnumeratedWindow, InMemoryCaptureBackend,
    LeakageValue, ScopedCaptureController, TeardownBehavior, TeardownProgress, WindowChangeKind,
    WindowFrame,
};
use platform::{PermissionLiveness, ProcessGrant};

fn target() -> ProcessGrant {
    ProcessGrant {
        pid: 7,
        bundle_identity: "com.example.target".into(),
        process_generation_evidence: "start-time-7".into(),
    }
}

fn window(id: &str, owner: &ProcessGrant, verified: bool) -> EnumeratedWindow {
    EnumeratedWindow {
        window_id: id.into(),
        owner_identity: owner.clone(),
        owner_identity_verified: verified,
        frame: WindowFrame {
            x: 0,
            y: 0,
            width: 320,
            height: 200,
        },
        accessibility_root: Some(format!("ax-root-{id}")),
    }
}

#[test]
fn scoped_capture_is_identity_bound_per_window_and_cursor_free() {
    let target = target();
    let other = ProcessGrant {
        pid: 8,
        bundle_identity: "com.example.other".into(),
        process_generation_evidence: "start-time-8".into(),
    };
    let mut backend = InMemoryCaptureBackend::default();
    backend.set_windows(vec![
        window("target", &target, true),
        window("overlap", &other, true),
        window("unverified", &target, false),
    ]);
    let mut controller = ScopedCaptureController::with_v1_bounds(backend, target).unwrap();

    let result = controller.capture_scoped(100).unwrap();
    assert_eq!(result.windows.len(), 1);
    assert_eq!(result.windows[0].window_id, "target");
    assert!(result.windows[0].desktop_independent_filter);
    assert_eq!(result.cursor_compositing, LeakageValue::Absent);
    assert_eq!(
        result.leakage.display_dependent_composition,
        LeakageValue::Absent
    );
    assert_eq!(result.leakage_flags().len(), CaptureLeakageFlag::ALL.len());
    assert!(controller
        .backend()
        .window_requests()
        .iter()
        .all(|request| !request.filter.include_cursor));
}

#[test]
fn creation_and_closure_reenumerate_and_report_slow_observation() {
    let target = target();
    let mut backend = InMemoryCaptureBackend::default();
    backend.set_windows(vec![window("main", &target, true)]);
    let mut controller = ScopedCaptureController::new(backend, target.clone(), 50, 1_000).unwrap();
    assert_eq!(
        controller
            .capture_scoped(10)
            .unwrap()
            .enumeration_generation,
        1
    );

    controller.backend_mut().set_windows(vec![
        window("main", &target, true),
        window("aux", &target, true),
    ]);
    controller
        .backend_mut()
        .announce_window_change(WindowChangeKind::Created, 10);
    let created = controller.capture_scoped(20).unwrap();
    assert_eq!(created.enumeration_generation, 2);
    assert_eq!(created.measured_reenumeration_interval_ms, Some(10));
    assert_eq!(created.windows.len(), 2);
    assert_eq!(
        created.window_enumeration_incomplete(),
        LeakageValue::Absent
    );

    controller
        .backend_mut()
        .set_windows(vec![window("main", &target, true)]);
    controller
        .backend_mut()
        .announce_window_change(WindowChangeKind::Closed, 20);
    let closed = controller.capture_scoped(100).unwrap();
    assert_eq!(closed.enumeration_generation, 3);
    assert_eq!(closed.windows.len(), 1);
    assert_eq!(closed.measured_reenumeration_interval_ms, Some(80));
    assert_eq!(
        closed.window_enumeration_incomplete(),
        LeakageValue::Present
    );
}

#[test]
fn broad_display_is_separately_granted_and_permission_states_fail_closed() {
    let target = target();
    let mut controller =
        ScopedCaptureController::with_v1_bounds(InMemoryCaptureBackend::default(), target).unwrap();
    let request = BroadDisplayCaptureRequest {
        include_cursor: true,
        captured_at_ms: 1,
    };
    assert_eq!(
        controller.capture_display(request.clone()).unwrap_err(),
        CaptureError::BroadCaptureGrantRequired
    );
    controller
        .grant_broad_display(BroadDisplayGrant::new("display-grant").unwrap())
        .unwrap();
    let display = controller.capture_display(request).unwrap();
    assert_eq!(
        display.leakage.display_dependent_composition,
        LeakageValue::Present
    );
    assert_eq!(display.leakage.cursor_composited, LeakageValue::Present);

    controller
        .backend_mut()
        .set_permission_liveness(PermissionLiveness::GrantedPendingRelaunch);
    assert_eq!(
        controller
            .capture_scoped(2)
            .expect_err("first grant must require relaunch"),
        CaptureError::PermissionPendingRelaunch
    );
    assert_eq!(
        controller.state(),
        CaptureSessionState::PermissionPendingRelaunch
    );
}

#[test]
fn revocation_stops_frames_and_detaches_slow_teardown_without_health_join() {
    let target = target();
    let mut backend = InMemoryCaptureBackend::default();
    backend.set_windows(vec![window("main", &target, true)]);
    backend.set_teardown_behavior(TeardownBehavior::NeverCompletes);
    let mut controller = ScopedCaptureController::with_v1_bounds(backend, target).unwrap();
    controller.capture_scoped(0).unwrap();

    let pending = controller.on_permission_revoked(5).unwrap();
    assert_eq!(pending.progress, TeardownProgress::Pending);
    assert!(!controller.health_snapshot().frames_enabled);
    assert!(controller.health_snapshot().teardown_in_flight);
    assert_eq!(
        controller.capture_scoped(6).unwrap_err(),
        CaptureError::PermissionUnavailable
    );

    let detached = controller.poll_teardown(1_006).unwrap();
    assert_eq!(detached.progress, TeardownProgress::Detached);
    assert!(!controller.health_snapshot().teardown_in_flight);
}

#[test]
fn leakage_report_has_the_closed_shape_even_for_direct_construction() {
    let report = CaptureLeakageReport::scoped();
    assert_eq!(report.as_map().len(), CaptureLeakageFlag::ALL.len());
}

#[test]
fn probe_owner_change_between_enumeration_and_capture_is_refused() {
    let target = target();
    let mut backend = InMemoryCaptureBackend::default();
    backend.set_windows(vec![window("target", &target, true)]);
    let mut controller = ScopedCaptureController::with_v1_bounds(backend, target).unwrap();
    // First capture enumerates and succeeds.
    assert_eq!(controller.capture_scoped(100).unwrap().windows.len(), 1);
    // The window keeps its id but is now owned by a DIFFERENT process, without
    // any enumeration event announcing it. Pixels must not be returned.
    let hostile = ProcessGrant {
        pid: 999,
        bundle_identity: "com.example.hostile".into(),
        process_generation_evidence: "start-time-999".into(),
    };
    controller
        .backend_mut()
        .set_windows(vec![window("target", &hostile, true)]);
    let result = controller.capture_scoped(150);
    assert!(
        result.is_err(),
        "capture returned pixels for a window whose owner changed after enumeration"
    );
}
