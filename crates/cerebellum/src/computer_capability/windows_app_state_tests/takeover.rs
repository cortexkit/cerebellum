use super::*;
use cerebellum_computer::app_state::source::{
    ElementActionError, ElementFacts, ElementHandle, RawAppState, RawElement, ReadBounds,
};
use cerebellum_computer::platform::{DispatchResult, EffectStatus};

pub(super) const ROWS: [&str; 2] = ["computer.takeover_move", "computer.takeover_scroll"];
const WINDOW: u32 = 2468;

pub(super) fn block(context: &CapabilityAdvertisementContext) -> Option<&'static str> {
    if context.inputs.windows_takeover_review_revision.is_none() {
        Some("windows takeover review unbound")
    } else if context
        .inputs
        .windows_input_bracket_review_revision
        .is_none()
    {
        Some("windows input bracket review unbound")
    } else {
        app_state_block(context)
    }
}

fn inputs() -> CapabilityAdvertisementContext {
    let mut context = exact_inputs();
    context.inputs.windows_actuation_review_revision = None;
    context.inputs.windows_takeover_review_revision = Some("takeover-fixture".into());
    context.inputs.windows_input_bracket_review_revision = Some("input-fixture".into());
    context
}

#[test]
fn takeover_test_route_requires_every_key_but_not_fronting() {
    let context = inputs();
    assert!(ROWS.iter().all(|row| rows(&context).contains(*row)));
    assert!(!rows(&context).contains("computer.takeover_click"));
    assert!(!rows(&context).contains("computer.takeover_drag"));
    assert!(WindowsPlatformDriver::default()
        .declarations(&context)
        .iter()
        .all(|row| !row.advertised));
    for (index, reason) in [
        "windows app identity review unbound",
        "windows app state review unbound",
        "windows takeover review unbound",
        "windows input bracket review unbound",
        "release signing topology unbound",
        "computer action vocabulary input unresolved",
        "cerebellum is running elevated",
        "integrity unreadable",
    ]
    .into_iter()
    .enumerate()
    {
        let mut context = context.clone();
        match index {
            0 => context.inputs.windows_app_identity_review_revision = None,
            1 => context.inputs.windows_app_state_review_revision = None,
            2 => context.inputs.windows_takeover_review_revision = None,
            3 => context.inputs.windows_input_bracket_review_revision = None,
            4 => context.inputs.release_signing_topology_revision = None,
            5 => context.inputs.vocabulary_digests.manifest_digest = None,
            6 => context.startup.windows_elevation = WindowsElevation::ElevatedOrAboveMedium,
            _ => context.startup.windows_elevation = WindowsElevation::UnreadableOrBelowMedium,
        }
        assert_eq!(block(&context), Some(reason));
        assert!(ROWS.iter().all(|row| !rows(&context).contains(*row)));
    }
}

struct ScrollFixture {
    cursor: Option<(f64, f64)>,
    pid: u32,
    cursor_reads: AtomicUsize,
}

impl AppStateSource for ScrollFixture {
    fn read_app_state(
        &self,
        _: &ProcessGrant,
        _: ReadBounds,
    ) -> Result<RawAppState, AppStateReadError> {
        panic!("a wheel does not read or front an application tree")
    }

    fn cursor_position(&self) -> Option<(f64, f64)> {
        self.cursor_reads.fetch_add(1, Ordering::SeqCst);
        self.cursor
    }

    fn pointer_window_at(&self, point: (f64, f64)) -> Option<u32> {
        assert_eq!(Some(point), self.cursor);
        Some(WINDOW)
    }

    fn element_at_for_target(
        &self,
        target: &ProcessGrant,
        point: (f64, f64),
    ) -> Result<Option<(ElementHandle, Option<u32>)>, ElementActionError> {
        assert_eq!(target.pid, self.pid);
        assert_eq!(Some(point), self.cursor);
        Ok(Some((
            RawElement::fixture(1, "AXWindow").handle,
            Some(self.pid),
        )))
    }

    fn element_window_number(&self, _: &ElementHandle) -> Option<u32> {
        Some(WINDOW)
    }

    fn element_facts(&self, _: &ElementHandle) -> Result<ElementFacts, ElementActionError> {
        Ok(ElementFacts {
            role: Some("AXWindow".into()),
            pid: Some(self.pid),
            ..Default::default()
        })
    }

    fn focused_element(
        &self,
        _: &ProcessGrant,
    ) -> Result<Option<ElementHandle>, ElementActionError> {
        Ok(None)
    }
}

fn scroll_args(target: &str) -> Value {
    json!({"target":target,"axis":"vertical","amount_lines":1})
}

#[tokio::test]
async fn served_windows_scroll_is_non_fronting_and_requires_cursor_bracket_and_takeover_grant() {
    for (has_cursor, has_bracket, allow_grant, bind_fronting) in [
        (true, true, true, false),
        (true, true, true, true),
        (false, true, true, true),
        (true, true, false, true),
        (true, false, true, true),
    ] {
        let pid = std::process::id();
        let cerebellum_windows::ProcessStartTime::Started(start) =
            cerebellum_windows::process_start_time(pid)
        else {
            panic!("fixture process creation time unavailable");
        };
        let target = ProcessGrant {
            pid,
            bundle_identity: "Takeover fixture".into(),
            process_generation_evidence: start.to_string(),
        };
        let source = Arc::new(ScrollFixture {
            cursor: has_cursor.then_some((100.0, 150.0)),
            pid,
            cursor_reads: AtomicUsize::new(0),
        });
        let mut context = inputs();
        if !has_bracket {
            context.inputs.windows_input_bracket_review_revision = None;
        }
        if bind_fronting {
            context.inputs.windows_fronting_review_revision = Some("fronting-fixture".into());
        }
        let mut planes = rig(
            &context,
            Arc::new(NativeFixture(target.clone())),
            Some(source.clone()),
        );
        let driver_calls = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&driver_calls);
        let plane = Arc::get_mut(planes.computer.as_mut().unwrap()).unwrap();
        assert_eq!(
            plane.takeover_pointer_fronting_admitted,
            has_bracket && bind_fronting
        );
        plane.make_synthetic_driver = Arc::new(move || {
            let count = Arc::clone(&count);
            WindowsPlatformDriver::default().with_pointer_dispatch_fixture(
                move |request, hwnd, guard| {
                    assert!(request.action_is_admitted());
                    assert_eq!(hwnd, WINDOW);
                    (guard
                        .expect("non-fronted wheel requires its cursor guard")
                        .0)()
                    .unwrap();
                    count.fetch_add(1, Ordering::SeqCst);
                    Ok(DispatchResult {
                        accepted_by_platform: true,
                        effect_status: EffectStatus::EffectIndeterminate,
                        unreadable_subtrees: 0,
                        delivery_posts_returned: 1,
                        delivery_generation_verifications: 1,
                    })
                },
            )
        });
        let foreground = cerebellum_windows::foreground_window_number();
        let (frame, questions) = wire_frame_with_decision(
            &planes,
            "takeover_scroll",
            scroll_args(&target.bundle_identity),
            if allow_grant { "allow_once" } else { "deny" },
            || {},
        )
        .await;
        let reply: Value = serde_json::from_slice(&frame.body).unwrap();
        assert_eq!(frame.header.ty, if has_bracket { FrameType::Response } else { FrameType::Error }, "cursor={has_cursor} bracket={has_bracket} grant={allow_grant} fronting={bind_fronting}: {reply}");
        let posted = has_cursor && has_bracket && allow_grant;
        assert_eq!(
            driver_calls.load(Ordering::SeqCst),
            usize::from(posted),
            "{reply}"
        );
        assert_eq!(questions, usize::from(has_cursor && has_bracket), "{reply}");
        if posted {
            assert_eq!(reply["outcome"], "completed", "{reply}");
            assert!(source.time_since_last_input().is_none());
            assert!(source.cursor_reads.load(Ordering::SeqCst) >= 2);
        } else if !has_cursor {
            assert_eq!(reply["reason"], "point_in_another_window", "{reply}");
        }
        assert_eq!(cerebellum_windows::foreground_window_number(), foreground);
    }
}

/// The signed fixture's ordinary root must be foreground with the cursor on a
/// non-sensitive, non-child-HWND area. The fixture provides the point within
/// its captured image; no test moves the cursor through an unrelated window.
#[tokio::test]
#[ignore = "requires the signed Windows takeover fixture and a reviewed live mouse probe"]
async fn native_served_move_and_scroll_on_owned_signed_fixture() {
    assert_eq!(
        WindowsElevation::read_current_process(),
        WindowsElevation::Medium
    );
    assert_eq!(cerebellum_windows::input_desktop_name().unwrap(), "Default");
    let required = |name| {
        std::env::var(name).unwrap_or_else(|_| panic!("missing takeover fixture input {name}"))
    };
    let pid = required("CK_WINDOWS_TAKEOVER_FIXTURE_PID").parse().unwrap();
    let x: u32 = required("CK_WINDOWS_TAKEOVER_FIXTURE_IMAGE_X")
        .parse()
        .unwrap();
    let y: u32 = required("CK_WINDOWS_TAKEOVER_FIXTURE_IMAGE_Y")
        .parse()
        .unwrap();
    let target = windows_identity::grant_for_pid(pid).expect("fixture identity is readable");
    assert!(target.bundle_identity.starts_with("win-signed:"));
    let principal = target.bundle_identity.clone();
    let foreground =
        cerebellum_windows::foreground_window_number().expect("owned fixture foreground");
    assert_eq!(cerebellum_windows::window_owner(foreground).unwrap().0, pid);
    let mut context = inputs();
    context.inputs.windows_capture_review_revision = Some("capture-fixture".into());
    let planes = rig(&context, Arc::new(NativeFixture(target)), None);
    let state = wire(
        &planes,
        "read_state",
        json!({"target":principal,"include_image":true}),
    )
    .await;
    assert_eq!(state["outcome"], "completed", "{state}");
    let image = state["image"]["image_id"]
        .as_str()
        .expect("fixture background image");
    let moved = wire_with_decision(
        &planes,
        "takeover_move",
        json!({"image_id":image,"to":{"x":x,"y":y}}),
        "allow_once",
        || {},
    )
    .await
    .0;
    assert_eq!(moved["outcome"], "completed", "{moved}");
    // The move resets the system idle reading. Let the next wheel call clear the idle gate.
    tokio::time::sleep(Duration::from_millis(1100)).await;
    let scrolled = wire_with_decision(
        &planes,
        "takeover_scroll",
        scroll_args(&principal),
        "allow_once",
        || {},
    )
    .await
    .0;
    assert_eq!(scrolled["outcome"], "completed", "{scrolled}");
    assert_eq!(
        cerebellum_windows::foreground_window_number(),
        Some(foreground)
    );
}
