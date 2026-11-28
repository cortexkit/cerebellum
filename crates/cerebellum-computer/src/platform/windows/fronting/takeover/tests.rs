use super::*;
use cerebellum_core::consent::{OnceDispatchToken, TakeoverAction};
use std::sync::atomic::AtomicUsize;

const START: Pixel = (100, 200);
const END: Pixel = (105, 215);

fn point((x, y): Pixel) -> SyntheticPoint {
    SyntheticPoint {
        x: f64::from(x),
        y: f64::from(y),
    }
}

fn request(action: SyntheticAction, scope: TakeoverAction) -> GlobalDispatchRequest {
    GlobalDispatchRequest {
        synthetic: SyntheticDispatchRequest {
            action,
            target: ProcessGrant {
                pid: 42,
                bundle_identity: "fixture.exe".into(),
                process_generation_evidence: "1".into(),
            },
        },
        once_dispatch_token: OnceDispatchToken::admitted_by_takeover_grant(scope),
        maximum_seize_detection_latency_ms: 50,
        minimum_inter_post_interval_ms: 50,
    }
}

#[test]
fn wrong_action_token_stops_before_any_windows_placement_or_posts() {
    let mut driver = WindowsPlatformDriver::default();
    assert_eq!(
        driver.dispatch_global(
            request(
                SyntheticAction::move_pointer(point(START)),
                TakeoverAction::Scroll
            ),
            &|| panic!("a mismatched token must not reach the post path")
        ),
        Err(DriverError::InvalidRequest(
            "takeover token does not admit this action"
        ))
    );
}

#[test]
fn click_and_drag_are_withheld_before_desktop_or_observer_work() {
    for (action, scope) in [
        (
            SyntheticAction::ClickPointer {
                point: point(START),
            },
            TakeoverAction::Click,
        ),
        (
            SyntheticAction::drag_pointer(point(START), point(END)),
            TakeoverAction::Drag,
        ),
    ] {
        assert_eq!(
            WindowsPlatformDriver::default().dispatch_global(request(action, scope), &|| panic!(
                "a withheld gesture must not reach the post path"
            )),
            Err(DriverError::StartupRefused(
                "Windows button recovery measurement is not recorded"
            ))
        );
    }
}

#[test]
fn absolute_coordinates_round_trip_on_a_negative_origin_virtual_desktop() {
    let screen = [-1920, -300, 4480, 1740];
    for point in [(-1920, -300), (-1, -1), (0, 0), (2559, 1439)] {
        let (x, y) = normalize(point, screen).unwrap();
        assert_eq!(
            (
                i32::from(x) * screen[2] / 65_536 + screen[0],
                i32::from(y) * screen[3] / 65_536 + screen[1]
            ),
            point
        );
    }
    assert_eq!(normalize((2560, -300), screen), None);
    assert_eq!(physical_pointer_pixel((-0.1, f64::NAN)), None);
    assert_eq!(physical_pointer_pixel((-0.1, 5.9)), Some((-1, 5)));
}

#[test]
fn capture_and_wheel_routes_name_the_exact_hwnd_not_just_the_root() {
    let mut route = Route {
        root: 5,
        capture: None,
        wheel: Some(5),
    };
    let wheel = Step::Wheel {
        delta: 120,
        horizontal: false,
    };
    assert_eq!(route.recipient(wheel, false), Some(5));
    route.wheel = Some(6);
    assert_eq!(route.recipient(wheel, false), Some(6));
    route.capture = Some(6);
    assert_eq!(route.recipient(Step::Move(START), false), None);
    assert_eq!(route.recipient(Step::Move(START), true), Some(6));
    assert_eq!(route.recipient(Step::Up, true), Some(6));
    assert_eq!(route.recipient(Step::Down(START), false), None);
}

struct Covered {
    posted: Vec<Step>,
    checks: Vec<Step>,
    allow_release: bool,
}

impl Transport for Covered {
    fn pause(&self, _: Duration, _: bool) {}
    fn stopped(&self) -> Result<(), Stop> {
        Ok(())
    }
    fn post(&mut self, step: Step, held: bool, release: bool) -> Post {
        self.checks.push(step);
        if (step == Step::Move(END) && held) || (release && !self.allow_release) {
            return Post {
                submitted: false,
                passed_hook: false,
                result: Err(Stop::Route),
            };
        }
        self.posted.push(step);
        Post {
            submitted: true,
            passed_hook: true,
            result: Ok(()),
        }
    }
}

#[test]
fn a_cover_stops_the_drag_and_only_the_paired_release_is_considered() {
    let steps = plan(
        &SyntheticAction::drag_pointer(point(START), point(END)),
        true,
    )
    .unwrap();
    for allow_release in [true, false] {
        let mut transport = Covered {
            posted: Vec::new(),
            checks: Vec::new(),
            allow_release,
        };
        let refusal = run_steps(&mut transport, &steps, Duration::ZERO).unwrap_err();
        assert_eq!(transport.checks, steps);
        assert_eq!(refusal.posts_returned, 2);
        let mut expected = steps[..2].to_vec();
        if allow_release {
            expected.push(Step::Up);
        }
        assert_eq!(transport.posted, expected);
        assert_eq!(
            refusal.held_state,
            if allow_release {
                HeldStateDisposition::Released { posts_returned: 1 }
            } else {
                HeldStateDisposition::Unknown
            }
        );
    }
}

#[test]
fn takeover_refuses_the_keyboard_only_probe_before_any_payload() {
    let posted = Arc::new(AtomicUsize::new(0));
    let observer = NativeObserver::keyboard_only_probe_for_test(Arc::clone(&posted));
    let mut watcher = SeizeWatcher::new(50);
    let mut transport = Covered {
        posted: Vec::new(),
        checks: Vec::new(),
        allow_release: false,
    };
    let Err(DriverError::ObservedDispatchAborted(abort)) = run_observed(
        &observer,
        &mut watcher,
        &mut transport,
        &[Step::Move(START)],
        Duration::from_millis(50),
    ) else {
        panic!("takeover must fail closed when the zero-distance probe has no mouse echo");
    };
    assert_eq!(abort.reason, AbortReason::ObserverUnavailable);
    assert_eq!(abort.queued_posts_cancelled, 1);
    assert!(transport.checks.is_empty());
    assert!(transport.posted.is_empty());
    assert_eq!(
        posted.load(Ordering::Relaxed),
        2,
        "only the two harmless liveness probes were attempted"
    );
}
