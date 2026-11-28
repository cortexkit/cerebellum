use super::*;
use cerebellum_computer::dispatch::{BracketReport, CutoffGate, HardwareInputSnapshot};
use cerebellum_linux::x11::fixture::{self, CLIENT, NEW, OCCLUDER, OLD};
use std::io::Write;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::Instant as StdInstant;

fn environment(display: &str, authority: &str) -> Environment {
    Environment::from([
        ("DISPLAY".into(), display.into()),
        ("XAUTHORITY".into(), authority.into()),
    ])
}

async fn picture(planes: &crate::Planes, image: bool, front: bool) -> Value {
    let reply = wire_observing_consent(
        planes,
        "read_state",
        json!({"target": "Picture App", "include_image": image, "bring_to_front": front}),
        || {},
    )
    .await;
    assert!(state_text(&reply).contains("button Apply"), "{reply}");
    reply
}

fn missing(reply: &Value, reason: &str) {
    assert!(reply.get("image").is_none(), "unexpected image");
    assert_eq!(reply["image_unavailable"]["reason"], reason, "{reply}");
}

fn no_front(reply: &Value, requested: bool) {
    if requested {
        assert_eq!(
            reply["image_fronting"],
            json!({
                "attempted": false, "restored": false, "longest_fronted_interval_ms": 0,
                "reason": "fronting_unavailable",
            }),
            "{reply}"
        );
    } else {
        assert!(reply.get("image_fronting").is_none(), "{reply}");
    }
}

fn decoded_pixel_frame(
    planes: &crate::Planes,
    fixture: &fixture::Desktop,
    reply: &Value,
    color: u32,
) {
    let image = &reply["image"];
    let id = image["image_id"]
        .as_str()
        .unwrap_or_else(|| panic!("{reply}"));
    assert_eq!(image["mime"], "image/jpeg");
    assert_eq!(image["width_px"], CLIENT.width);
    assert_eq!(image["height_px"], CLIENT.height);
    let conversation = planes.routes.get(7, 1).unwrap().identity.conversation_key;
    assert_eq!(
        planes
            .management
            .app_state_sessions()
            .image_window_geometry(&conversation, id),
        Some((
            fixture.window(),
            Some([
                CLIENT.x as f64,
                CLIENT.y as f64,
                CLIENT.width as f64,
                CLIENT.height as f64
            ]),
        ))
    );
    let jpeg = cerebellum_core::serde_base64::decode(image["data_b64"].as_str().unwrap()).unwrap();
    let mut decoder = Command::new("/usr/bin/timeout")
        .args(["5s", &std::env::var("CK_X11_DECODE_PICTURE").unwrap()])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    decoder.stdin.take().unwrap().write_all(&jpeg).unwrap();
    let output = decoder.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "JPEG could not be decoded: {}",
        output.status
    );
    let header = format!("{} {}\n", CLIENT.width, CLIENT.height);
    let pixels = output
        .stdout
        .strip_prefix(header.as_bytes())
        .expect("decoded size");
    assert_eq!(
        pixels.len(),
        usize::from(CLIENT.width) * usize::from(CLIENT.height) * 3
    );
    let component = |shift: u32| ((color >> shift) & 0xff) as u8;
    let assert_rgb = |x: usize, y: usize| {
        let at = (y * usize::from(CLIENT.width) + x) * 3;
        let expected = [component(16), component(8), component(0)];
        assert!(
            pixels[at..at + 3]
                .iter()
                .zip(expected)
                .all(|(a, b)| a.abs_diff(b) < 24),
            "decoded pixel ({x},{y}) was {:?}, not {expected:?}",
            &pixels[at..at + 3]
        );
    };
    // One point was behind the occluder, the other outside it; neither may
    // be a root, border, stale fill, or occluder pixel. The text drew ink too.
    assert_rgb(10, 10);
    assert_rgb(146, 90);
    assert!(
        (35..46).any(|y| (20..77).any(|x| {
            let at = (y * usize::from(CLIENT.width) + x) * 3;
            pixels[at..at + 3].iter().all(|&v| v < 55)
        })),
        "the crop must contain the label"
    );
}

async fn desktop(planes: &crate::Planes) -> Arc<picture::Desktop> {
    let session = planes
        .computer
        .as_ref()
        .unwrap()
        .linux_session
        .as_ref()
        .unwrap();
    let (epoch, _) = session.refresh().await.unwrap();
    epoch.x11.as_ref().unwrap().desktop.clone()
}

fn record_front(events: Arc<std::sync::Mutex<Vec<&'static str>>>) -> Arc<PictureFrontTest> {
    let lifecycle = events.clone();
    Arc::new(PictureFrontTest {
        observer: InputObserverLiveness {
            session_tap_live: true,
            raw_hid_live: true,
            self_echo_filter_live: true,
        },
        bracket: Box::new(move |target, bound, hooks, acquire| {
            let now = StdInstant::now();
            let previous = std::process::id() + 1;
            let active = Arc::new(AtomicU32::new(previous));
            let gate = Arc::new(CutoffGate::new());
            gate.set_bound(
                now + Duration::from_millis(bound - 20),
                now + Duration::from_millis(bound),
            );
            assert!(hooks.register(
                previous,
                target.pid,
                Box::new(RecordingRestore {
                    active: active.clone(),
                    start: now,
                    events: lifecycle.clone(),
                }),
                &gate
            ));
            assert!(hooks.begin_front_attempt(0));
            assert!(hooks.target_front_permitted());
            active.store(target.pid, Ordering::Relaxed);
            lifecycle.lock().unwrap().push("front");
            hooks.front_attempt_returned();
            hooks.front_confirmed();
            acquire();
            let restore = hooks.decide_restore().restore;
            assert_eq!(active.load(Ordering::Relaxed), previous);
            BracketReport {
                previous_frontmost: Some(previous),
                chunks: 1,
                units_posted: 0,
                posts_returned: 0,
                generation_verifications: 1,
                longest_fronted_interval_ms: now.elapsed().as_millis() as u64,
                slowest_unit_ms: 0,
                slowest_restore_ms: 0,
                restore,
                stop: None,
                waiting_out_slow_post: false,
                waiting_out_slow_restore: false,
                restore_calibrated: false,
                restore_started_by_cutoff: false,
            }
        }),
        before_encode: Box::new(move || {
            assert_ne!(
                events.lock().unwrap().last(),
                Some(&"front"),
                "encoding started before restore"
            );
            events.lock().unwrap().push("encode");
            std::thread::sleep(Duration::from_millis(35));
        }),
    })
}

struct RecordingRestore {
    active: Arc<AtomicU32>,
    start: StdInstant,
    events: Arc<std::sync::Mutex<Vec<&'static str>>>,
}

impl FrontingRestoreHost for RecordingRestore {
    fn now_ms(&mut self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }
    fn pause_ms(&mut self, milliseconds: u64) {
        std::thread::sleep(Duration::from_millis(milliseconds));
    }
    fn frontmost_pid(&mut self) -> Option<u32> {
        Some(self.active.load(Ordering::Relaxed))
    }
    fn request_front(&mut self, pid: u32) -> bool {
        self.active.store(pid, Ordering::Relaxed);
        self.events.lock().unwrap().push("restore");
        true
    }
    fn hardware_input_snapshot(&mut self) -> Option<HardwareInputSnapshot> {
        Some(HardwareInputSnapshot {
            coverage_start_ms: 0,
            last_input_ms: None,
        })
    }
}

#[tokio::test]
async fn linux_picture_refusing_backends_return_a_tree_without_fronting() {
    let bus = TestAtspiBus::start().await;
    let _app = bus.app("Picture App").await;
    for (kind, capture, fronting, reason) in [
        (SessionKind::Wayland, false, true, "picture_unattributable"),
        (SessionKind::Wayland, true, true, "picture_unattributable"),
        (SessionKind::X11, false, true, "route_not_reviewed"),
        (SessionKind::X11, true, true, "backend_unavailable"),
    ] {
        let events = Arc::default();
        let (planes, _) = rig_with(
            kind,
            bus.selected.clone(),
            false,
            Environment::new(),
            fronting,
            |s| {
                s.capture_reviewed = capture;
                s.picture_front_for_test = Some(record_front(Arc::clone(&events)));
            },
        );
        for with_front in [false, true] {
            let text = picture(&planes, false, with_front).await;
            assert!(text.get("image_unavailable").is_none());
            assert!(text.get("image").is_none());
            no_front(&text, with_front);
            let refused = picture(&planes, true, with_front).await;
            missing(&refused, reason);
            no_front(&refused, with_front);
        }
        assert!(events.lock().unwrap().is_empty());
    }
}

#[tokio::test]
#[ignore = "requires two private Xvfb displays and the fixture JPEG decoder"]
async fn native_x11_picture_matrix() {
    let display = std::env::var("CK_X11_FIXTURE_DISPLAY").expect("run through run-picture.sh");
    let authority = std::env::var("CK_X11_FIXTURE_AUTHORITY").unwrap();
    let secondary = std::env::var("CK_X11_NO_COMPOSITE_DISPLAY").unwrap();
    let secondary_authority = std::env::var("CK_X11_NO_COMPOSITE_AUTHORITY").unwrap();
    assert_ne!(display, secondary);
    let mut fixture = fixture::Desktop::open(&display);
    fixture.advertise_pid(std::process::id() + 1);
    let bus = TestAtspiBus::start().await;
    let _app = bus.app("Picture App").await;
    // The text tree has reviewed identity and accessibility routes in every
    // case. Vary the capture review, fronting review, and observer liveness.
    for (capture, fronting, observer, use_composite, include, front, expected) in [
        (true, true, true, true, false, true, "none"),
        (false, true, true, true, true, true, "route_not_reviewed"),
        (true, true, true, false, true, true, "backend_unavailable"),
        (true, false, true, true, true, true, "image"),
        (true, true, false, true, true, true, "image"),
        (true, true, true, true, true, false, "image"),
        (true, true, true, true, true, true, "fronted"),
    ] {
        let events = Arc::default();
        let env = if use_composite {
            environment(&display, &authority)
        } else {
            environment(&secondary, &secondary_authority)
        };
        let (planes, _) = rig_with(
            SessionKind::X11,
            bus.selected.clone(),
            false,
            env,
            fronting,
            |s| {
                s.connect_x11 = true;
                s.capture_reviewed = capture;
                // Without the recording observer, use the production readings.
                // A front requires a live session tap, raw input, and echo filter.
                s.picture_front_for_test = observer.then(|| record_front(Arc::clone(&events)));
            },
        );
        let desktop = desktop(&planes).await;
        if use_composite {
            assert_eq!(
                desktop.connection.owner_pid(fixture.window()).unwrap(),
                Some(std::process::id())
            );
            assert_eq!(desktop.active_pid(), Some(std::process::id()));
        }
        let reply = picture(&planes, include, front).await;
        match expected {
            "none" => {
                assert!(reply.get("image_unavailable").is_none(), "{reply}");
                assert!(reply.get("image").is_none());
                no_front(&reply, front);
            }
            "image" | "fronted" => {
                decoded_pixel_frame(&planes, &fixture, &reply, OLD);
                if expected == "fronted" {
                    assert_eq!(reply["image_fronting"]["attempted"], true, "{reply}");
                    assert_eq!(reply["image_fronting"]["restored"], true, "{reply}");
                    assert_eq!(*events.lock().unwrap(), ["front", "restore", "encode"]);
                } else {
                    no_front(&reply, front);
                    assert_eq!(
                        *events.lock().unwrap(),
                        if observer { vec!["encode"] } else { vec![] }
                    );
                }
            }
            reason => {
                missing(&reply, reason);
                no_front(&reply, front);
            }
        }
        let pixels = usize::from(matches!(expected, "image" | "fronted"));
        assert_eq!(fixture::pixels_requested(&desktop.connection), pixels);
        if pixels == 0 {
            assert!(events.lock().unwrap().is_empty());
        }
    }
    native_picture_freshness(&mut fixture, &bus, environment(&display, &authority)).await;
}

struct Repaint {
    done: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Repaint {
    fn start(paint: impl Fn() + Send + 'static) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let stop = done.clone();
        let thread = std::thread::spawn(move || {
            let deadline = StdInstant::now() + Duration::from_secs(2);
            while !stop.load(Ordering::Relaxed) && StdInstant::now() < deadline {
                paint();
                std::thread::sleep(Duration::from_millis(8));
            }
        });
        Self {
            done,
            thread: Some(thread),
        }
    }
}

impl Drop for Repaint {
    fn drop(&mut self) {
        self.done.store(true, Ordering::Relaxed);
        self.thread.take().unwrap().join().unwrap();
    }
}

async fn native_picture_freshness(
    fixture: &mut fixture::Desktop,
    bus: &TestAtspiBus,
    env: Environment,
) {
    let (planes, _) = rig_with(
        SessionKind::X11,
        bus.selected.clone(),
        false,
        env,
        false,
        |s| {
            s.connect_x11 = true;
            s.capture_reviewed = true;
        },
    );
    let desktop = desktop(&planes).await;
    let session = planes
        .computer
        .as_ref()
        .unwrap()
        .linux_session
        .as_ref()
        .unwrap();
    let (grant, _) = session.select("Picture App").await.unwrap();
    let fence = cerebellum_computer::capture::open_fence();
    let mut backend = picture::Backend::new(Ok(desktop.clone()), |_| Ok(()));
    let start = StdInstant::now();
    backend
        .select_and_acquire(&grant, 0, &fence)
        .expect("an uncovered idle window needs no damage");
    assert!(
        start.elapsed() < Duration::from_millis(200),
        "uncovered capture waited for damage"
    );

    fixture.set_covered(true);
    assert_eq!(fixture.covered_pixel(), OCCLUDER);
    let before = fixture::pixels_requested(&desktop.connection);
    let frame_only = Repaint::start(fixture.damage_frame());
    let start = StdInstant::now();
    let stale = picture(&planes, true, false).await;
    let elapsed = start.elapsed();
    drop(frame_only);
    missing(&stale, "window_covered_may_be_stale");
    assert!(
        elapsed >= Duration::from_millis(195) && elapsed < Duration::from_millis(550),
        "covered repaint wait elapsed {elapsed:?}"
    );
    assert_eq!(fixture::pixels_requested(&desktop.connection), before);

    // The update occurs after the occluder is mapped. Non-composited X11
    // must see a client repaint after redirect, not the frame's repaint.
    fixture.paint_new();
    let repaint = Repaint::start(fixture.repaint_new());
    let fresh = picture(&planes, true, false).await;
    drop(repaint);
    decoded_pixel_frame(&planes, fixture, &fresh, NEW);
    fixture.set_covered(false);
    fixture.paint_old();
    fixture.set_compositing(true);
    fixture.set_covered(true);
    fixture.paint_new();
    let fresh = picture(&planes, true, false).await;
    decoded_pixel_frame(&planes, fixture, &fresh, NEW);
    fixture.set_covered(false);
    fixture.set_compositing(false);

    let before = fixture::pixels_requested(&desktop.connection);
    fixture.map_client(false);
    missing(&picture(&planes, true, false).await, "window_not_mapped");
    fixture.map_client(true);
    fixture.map_frame(false);
    // Under a reparenting WM the client is still mapped but not viewable.
    missing(&picture(&planes, true, false).await, "window_not_mapped");
    fixture.map_frame(true);
    assert_eq!(fixture::pixels_requested(&desktop.connection), before);

    let cancelled = Arc::new(AtomicBool::new(false));
    let calls = Arc::new(AtomicUsize::new(0));
    let mut backend = picture::Backend::new(Ok(desktop.clone()), {
        let calls = calls.clone();
        let cancelled = cancelled.clone();
        move |_| {
            if calls.fetch_add(1, Ordering::Relaxed) == 1 {
                cancelled.store(true, Ordering::Relaxed);
            }
            Ok(())
        }
    });
    let fence: cerebellum_computer::capture::AcquisitionFence =
        Arc::new(move || !cancelled.load(Ordering::Relaxed));
    assert!(backend.select_and_acquire(&grant, 0, &fence).is_err());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        2,
        "the fence closed after selection and initial verification"
    );
    assert_eq!(
        fixture::pixels_requested(&desktop.connection),
        before,
        "a closed acquisition fence sent GetImage"
    );

    // The current clip matches its initial value again. The Shape events,
    // not a difference between snapshots, make the captured bytes unusable.
    fixture::before_next_image_read(&desktop.connection, fixture.transient_clip_change());
    missing(
        &picture(&planes, true, false).await,
        "picture_unattributable",
    );
    assert_eq!(fixture::pixels_requested(&desktop.connection), before + 1);
}
