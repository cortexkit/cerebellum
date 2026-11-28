use super::*;
use cerebellum_computer::app_state::image::{ImageUnavailable, WindowImageCapture};
use cerebellum_computer::audit::ComputerAudit;
use cerebellum_computer::capture::*;
use cerebellum_computer::platform::PermissionLiveness;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

#[derive(Clone, Copy)]
enum Reading {
    Picture,
    Missing(ImageUnavailable),
    Late,
}

struct PictureBackend(Reading, Arc<AtomicUsize>);

impl CaptureBackend for PictureBackend {
    const BACKGROUND_WINDOW_PICTURE: bool = true;

    fn capture_background_picture(
        &mut self,
        grant: &ProcessGrant,
        cutoff: Instant,
        fence: &AcquisitionFence,
    ) -> Result<WindowImageCapture, ImageUnavailable> {
        self.1.fetch_add(1, Ordering::SeqCst);
        assert_eq!(grant, &support::grant());
        assert!(fence());
        match self.0 {
            Reading::Picture => (),
            Reading::Missing(reason) => return Err(reason),
            Reading::Late => std::thread::sleep(
                cutoff.saturating_duration_since(Instant::now()) + Duration::from_millis(1),
            ),
        }
        Ok(WindowImageCapture {
            window_id: "77".into(),
            owning_pid: grant.pid,
            window_origin: (-321.0, 79.0),
            window_points: (2273.0, 1217.0),
            captured_px: (2273, 1217),
            exact_axes: true,
            // A JPEG frame header declares a 1001 by 537 image.
            jpeg: vec![
                0xff, 0xd8, 0xff, 0xc0, 0, 8, 8, 2, 25, 3, 233, 1, 0xff, 0xd9,
            ],
        })
    }

    fn screen_recording_liveness(&self) -> PermissionLiveness {
        panic!("legacy capture")
    }
    fn enumerate_windows(
        &mut self,
        _: &ProcessGrant,
    ) -> Result<Vec<EnumeratedWindow>, BackendError> {
        panic!("legacy capture")
    }
    fn poll_window_change(
        &mut self,
        _: &ProcessGrant,
    ) -> Result<Option<WindowChange>, BackendError> {
        panic!("legacy capture")
    }
    fn capture_window(
        &mut self,
        _: &WindowCaptureRequest,
    ) -> Result<WindowCaptureFrame, BackendError> {
        panic!("legacy capture")
    }
    fn capture_display(
        &mut self,
        _: &BroadDisplayCaptureRequest,
    ) -> Result<CaptureArtifact, BackendError> {
        panic!("display capture")
    }
    fn begin_teardown(&mut self) -> Result<BackendTeardownProgress, BackendError> {
        panic!("legacy capture")
    }
    fn poll_teardown(&mut self, _: u64) -> Result<BackendTeardownProgress, BackendError> {
        panic!("legacy capture")
    }
}

struct Served {
    reply: Value,
    constructions: usize,
    attempts: usize,
    management: Arc<crate::management::ManagementPlane>,
}

async fn read<S: cerebellum_core::journal::JournalStorage + Send + 'static>(
    reading: Reading,
    argument: Option<bool>,
    recording: bool,
    bracket: bool,
    audit: ComputerAudit<support::TestRedactor, ValidatedSeverityTaxonomy, S>,
) -> Served {
    let desk = mail_desk();
    let screen = Screen::new(&desk);
    let driver_screen = screen.clone();
    let permissions = if recording {
        support::live_permissions()
    } else {
        use cerebellum_computer::platform::{
            PermissionLivenessReport, PermissionProbeResult, PermissionService,
        };
        PermissionLivenessReport::from_results([PermissionProbeResult {
            service: PermissionService::Accessibility,
            liveness: PermissionLiveness::Live,
            responsible_process: "fixture".into(),
            off_main: true,
        }])
    };
    let plane = ComputerPlane::with_synthetic_driver_and_result_schema_enforcement(
        audit,
        ResultSchemaEnforcement::Withhold,
        move || FakeDriver {
            screen: driver_screen.clone(),
            hooks: None,
            pointer_guard: None,
        },
    )
    .with_permission_liveness(permissions)
    .with_app_state_source(desk.source())
    .with_app_use(super::super::app_use::LiveAppUse::approved_for_test(
        AppUse::Background,
    ))
    .with_fronting_bracket_admitted(bracket);
    let management = support::granted_management().await;
    let who = Who::fixture();
    let mut arguments = json!({"target": support::TARGET_BUNDLE_ID, "include_image": true});
    if let Some(bring_to_front) = argument {
        arguments["bring_to_front"] = json!(bring_to_front);
    }
    let constructions = AtomicUsize::new(0);
    let attempts = Arc::new(AtomicUsize::new(0));
    let reply = plane
        .serve(
            servable("computer.read_state").unwrap(),
            &arguments,
            ServeContext {
                cancel: crate::CancelHandle::pending(),
                grantee: support::GRANTEE,
                identity: who.identity.clone(),
                management: &management,
                consent: who.consent(),
                clock: &cerebellum_core::clock::FakeClock::new(),
                now_ms: 10,
            },
            |_| {
                constructions.fetch_add(1, Ordering::SeqCst);
                PictureBackend(reading, Arc::clone(&attempts))
            },
        )
        .await
        .expect("reply passes Withhold-mode validation");
    assert!(
        screen.state().log.is_empty(),
        "picture issued an input or foreground operation"
    );
    Served {
        reply,
        constructions: constructions.load(Ordering::SeqCst),
        attempts: attempts.load(Ordering::SeqCst),
        management,
    }
}

fn missing(served: &Served, reason: &str) {
    let reply = &served.reply;
    assert_eq!(reply["outcome"], "completed", "{reply}");
    assert!(
        reply["state_text"]
            .as_str()
            .unwrap()
            .contains("window Mail"),
        "{reply}"
    );
    assert_eq!(reply["image_unavailable"]["reason"], reason, "{reply}");
    assert!(reply.get("image").is_none(), "{reply}");
}

#[tokio::test]
async fn unbound_recording_does_not_construct_the_picture_backend_or_attempt_fronting() {
    let served = read(Reading::Picture, Some(true), false, true, support::audit()).await;
    missing(&served, "screen_recording_not_live");
    assert_eq!((served.constructions, served.attempts), (0, 0));
    assert!(served.reply.get("fronting").is_none());
}

#[tokio::test]
async fn successful_picture_registers_the_exact_window_and_rounds_axes_independently() {
    let served = read(Reading::Picture, Some(true), true, true, support::audit()).await;
    assert_eq!(served.reply["outcome"], "completed", "{}", served.reply);
    assert!(served.reply.get("fronting").is_none());
    let image = &served.reply["image"];
    assert_eq!(image["width_px"], 1001);
    assert_eq!(image["height_px"], 537);
    let id = image["image_id"].as_str().unwrap();
    let sessions = served.management.app_state_sessions();
    let conversation = Who::fixture().identity.conversation_key;
    assert_eq!(
        sessions.image_window_geometry(&conversation, id),
        Some((77, Some([-321.0, 79.0, 2273.0, 1217.0])))
    );
    let mapping = sessions.resolve_image(&conversation, id).unwrap().mapping;
    let (x, y) = mapping.pixel_to_desktop(500.5, 268.5);
    assert!(
        (x - 815.5).abs() < 0.000001 && (y - 687.5).abs() < 0.000001,
        "{x}, {y}"
    );
}

async fn terminal(reason: ImageUnavailable, wire_reason: &str) {
    let served = read(
        Reading::Missing(reason),
        Some(true),
        true,
        true,
        support::audit(),
    )
    .await;
    missing(&served, wire_reason);
    assert_eq!((served.constructions, served.attempts), (1, 1));
    assert!(served.reply.get("fronting").is_none());
}

#[tokio::test]
async fn display_affinity_exclusion_is_terminal_on_the_wire() {
    terminal(ImageUnavailable::CaptureExcluded, "capture_excluded").await;
}

#[tokio::test]
async fn missing_cursor_control_is_terminal_on_the_wire() {
    terminal(ImageUnavailable::CaptureUnavailable, "capture_unavailable").await;
}

#[tokio::test]
async fn minimized_window_is_terminal_on_the_wire() {
    terminal(ImageUnavailable::NoWindowCaptured, "no_window_captured").await;
}

#[tokio::test]
async fn failed_background_picture_with_opt_out_or_no_opt_in_never_fronts() {
    for argument in [None, Some(false)] {
        let served = read(
            Reading::Missing(ImageUnavailable::CaptureFailed),
            argument,
            true,
            true,
            support::audit(),
        )
        .await;
        missing(&served, "capture_failed");
        assert!(served.reply.get("fronting").is_none());
    }
}

#[tokio::test]
async fn failed_background_picture_returns_the_shared_admission_refusal() {
    let served = read(
        Reading::Missing(ImageUnavailable::CaptureFailed),
        Some(true),
        true,
        false,
        support::audit(),
    )
    .await;
    missing(&served, "fronting_unavailable");
    assert_eq!(
        served.reply["fronting"]["not_fronted_reason"],
        "fronting_unavailable"
    );
}

#[tokio::test]
async fn a_picture_arriving_after_its_share_has_no_id_even_if_fronting_is_reviewed() {
    let served = read(Reading::Late, Some(true), true, true, support::audit()).await;
    assert_eq!((served.constructions, served.attempts), (1, 1));
    assert_eq!(served.reply["outcome"], "completed", "{}", served.reply);
    // Timer overshoot may consume the handoff reserve. Either result must
    // withhold the late frame and make no native foreground calls.
    match served.reply["image_unavailable"]["reason"].as_str() {
        Some("capture_failed") => assert!(served.reply.get("fronting").is_none()),
        Some("fronting_unavailable") => assert_eq!(
            served.reply["fronting"]["not_fronted_reason"],
            "observer_unavailable"
        ),
        _ => panic!("unexpected reply: {}", served.reply),
    }
    assert!(served.reply.get("image").is_none());
}

#[tokio::test]
async fn an_audit_failure_withholds_the_whole_background_read() {
    let served = read(
        Reading::Picture,
        Some(true),
        true,
        true,
        support::failing_audit(),
    )
    .await;
    assert_eq!(
        served.reply["outcome"], "audit_unavailable",
        "{}",
        served.reply
    );
    assert!(
        served.reply.get("state_text").is_none() && served.reply.get("image_unavailable").is_none()
    );
    assert_eq!(served.attempts, 0);
}
