use super::*;

fn desktop() -> u32 {
    assert_eq!(
        WindowsElevation::read_current_process(),
        WindowsElevation::Medium
    );
    assert_eq!(
        cerebellum_windows::current_process_token_elevation_type(),
        Some(cerebellum_windows::TokenElevationType::Limited)
    );
    assert!(matches!(
        cerebellum_windows::current_session_provenance(),
        cerebellum_windows::SessionProvenance::Console { .. }
    ));
    assert_eq!(cerebellum_windows::input_desktop_name().unwrap(), "Default");
    assert_eq!(cerebellum_windows::capture_support(), Some(true));
    cerebellum_windows::set_process_per_monitor_v2();
    assert!(cerebellum_windows::per_monitor_v2());
    cerebellum_windows::foreground_window_number().expect("fixture runner foreground window")
}

fn number(name: &str) -> u32 {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("missing fixture input {name}"))
        .parse()
        .unwrap()
}

fn picture_rig(pid: u32) -> (crate::Planes, String) {
    let target = windows_identity::grant_for_pid(pid).expect("verified capture fixture");
    assert!(target.bundle_identity.starts_with("win-signed:"));
    let principal = target.bundle_identity.clone();
    let mut context = exact_inputs();
    context.inputs.windows_capture_review_revision = Some("picture-fixture".into());
    let planes = rig(&context, Arc::new(NativeFixture(target)), None);
    (planes, principal)
}

#[tokio::test]
#[ignore = "requires the split-token interactive Windows WGC runner and the covered, multi-window signed picture fixture"]
async fn wire_picture_is_scaled_and_registered_to_the_fixture_hwnd() {
    let foreground = desktop();
    let pid = number("CK_WINDOWS_CAPTURE_FIXTURE_PID");
    let expected_hwnd = number("CK_WINDOWS_CAPTURE_FIXTURE_HWND");
    assert_ne!(cerebellum_windows::window_owner(foreground).unwrap().0, pid);
    let (planes, target) = picture_rig(pid);
    let reply = wire(
        &planes,
        "read_state",
        json!({"target":target,"include_image":true}),
    )
    .await;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(
        reply["state_text"]
            .as_str()
            .unwrap()
            .lines()
            .filter(|line| line.split_whitespace().nth(1) == Some("window"))
            .count()
            >= 2
    );
    let id = reply["image"]["image_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"));
    let (hwnd, frame) = planes
        .management
        .app_state_sessions()
        .image_window_geometry("test-session", id)
        .expect("framed image");
    assert_eq!(hwnd, expected_hwnd);
    let expected = cerebellum_windows::window_state_facts(expected_hwnd)
        .unwrap()
        .bounds;
    assert_eq!(
        frame,
        Some([
            f64::from(expected.left),
            f64::from(expected.top),
            f64::from(expected.right - expected.left),
            f64::from(expected.bottom - expected.top)
        ])
    );
    let image = planes
        .management
        .app_state_sessions()
        .resolve_image("test-session", id)
        .unwrap();
    assert!(
        image.width_px < (expected.right - expected.left) as u32,
        "fixture window must need resampling"
    );
    let point = image.mapping.pixel_to_desktop(
        f64::from(image.width_px) / 2.0,
        f64::from(image.height_px) / 2.0,
    );
    assert!((point.0 - f64::from(expected.left + expected.right) / 2.0).abs() < 0.01);
    assert!((point.1 - f64::from(expected.top + expected.bottom) / 2.0).abs() < 0.01);
    assert_eq!(
        cerebellum_windows::foreground_window_number(),
        Some(foreground)
    );
}

#[tokio::test]
#[ignore = "requires the split-token interactive Windows WGC runner plus signed affinity-excluded and minimized picture fixtures"]
async fn wire_picture_capture_terminals_keep_the_tree_without_fronting() {
    let foreground = desktop();
    for (pid, reason) in [
        (
            number("CK_WINDOWS_CAPTURE_EXCLUDED_PID"),
            "capture_excluded",
        ),
        (
            number("CK_WINDOWS_CAPTURE_MINIMIZED_PID"),
            "no_window_captured",
        ),
    ] {
        let (planes, target) = picture_rig(pid);
        let reply = wire(
            &planes,
            "read_state",
            json!({"target":target,"include_image":true,"bring_to_front":true}),
        )
        .await;
        assert_eq!(reply["outcome"], "completed", "{reply}");
        assert!(reply["state_text"].is_string());
        assert_eq!(reply["image_unavailable"]["reason"], reason, "{reply}");
        assert!(
            reply.get("image").is_none() && reply.get("fronting").is_none(),
            "{reply}"
        );
        assert_eq!(
            cerebellum_windows::foreground_window_number(),
            Some(foreground)
        );
    }
}
