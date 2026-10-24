//! Manual desk-only pixel experiment, kept separate from the overlay loop.
//! It checks each real panel's shareable-window membership and own single-window
//! capture, with a separate, normally shared window as a positive control.

use super::*;
use crate::macos::{capture_window, CaptureSourceRect, RawCapture};
use block2::RcBlock;
use objc2_foundation::NSError;
use objc2_screen_capture_kit::SCShareableContent;

fn shareable_window_ids(timeout: Duration) -> Result<Vec<u32>, String> {
    let (sink, delivery) = std::sync::mpsc::channel();
    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: callback objects remain valid until it returns. Copy only
            // IDs, without filtering out windows whose owner metadata is missing.
            let result = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    Ok(content.windows().iter().map(|w| w.windowID()).collect())
                } else {
                    Err("no shareable content or error".to_owned())
                }
            };
            let _ = sink.send(result);
        },
    );
    // SAFETY: ScreenCaptureKit retains the completion block until delivery.
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };
    delivery
        .recv_timeout(timeout)
        .map_err(|_| "shareable-window enumeration timed out".to_owned())?
}

const SIDE: f64 = 128.0;
const GAP: f64 = 64.0;
const COLOURS: [[u8; 3]; 4] = [
    [239, 17, 193],
    [23, 229, 211],
    [181, 241, 19],
    [251, 89, 31],
];

fn pattern_colours(pattern: usize) -> [[u8; 3]; 4] {
    std::array::from_fn(|i| COLOURS[(i + pattern) % COLOURS.len()])
}

define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    #[ivars = usize]
    struct CapturePattern;
    impl CapturePattern {
        #[unsafe(method(drawRect:))]
        fn draw(&self, _dirty: NSRect) {
            for (i, [r, g, b]) in pattern_colours(*self.ivars()).into_iter().enumerate() {
                srgb(f64::from(r) / 255.0, f64::from(g) / 255.0, f64::from(b) / 255.0, 1.0).setFill();
                NSBezierPath::bezierPathWithRect(rect(
                    (i % 2) as f64 * SIDE / 2.0, (i / 2) as f64 * SIDE / 2.0,
                    SIDE / 2.0, SIDE / 2.0)).fill();
            }
        }
    }
);

fn on_worker<T: Send + 'static>(
    mtm: MainThreadMarker,
    work: impl FnOnce() -> Result<T, String> + Send + 'static,
) -> Result<T, String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(work());
    });
    let end = Instant::now() + Duration::from_secs(22);
    loop {
        match receiver.try_recv() {
            Ok(result) => return result,
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("capture worker exited".into())
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if Instant::now() >= end {
            return Err("capture worker timed out".into());
        }
        commit_window_changes(mtm);
        // ScreenCaptureKit may deliver through the main run loop. Keep it
        // turning while the capture worker waits for the framework callback.
        objc2_foundation::NSRunLoop::currentRunLoop().runMode_beforeDate(
            unsafe { NSDefaultRunLoopMode },
            &NSDate::dateWithTimeIntervalSinceNow(0.01),
        );
    }
}

fn capture(mtm: MainThreadMarker, window_id: u32) -> Result<RawCapture, String> {
    on_worker(mtm, move || {
        capture_window(
            window_id,
            Duration::from_secs(10),
            Some(CaptureSourceRect {
                x: 0.0,
                y: 0.0,
                width: SIDE,
                height: SIDE,
            }),
        )
        .map_err(|error| error.to_string())
    })
}

fn patches(image: &RawCapture, pattern: usize) -> Result<usize, String> {
    if image.width != 128 || image.height != 128 || image.bgra.len() != 128 * 128 * 4 {
        return Err(format!(
            "unexpected single-window raster: {}x{} ({} bytes)",
            image.width,
            image.height,
            image.bgra.len()
        ));
    }
    Ok(pattern_colours(pattern)
        .iter()
        .enumerate()
        .filter(|(i, rgb)| {
            // AppKit paints bottom-up; the captured raster is top-down. Test an
            // interior 5x5 patch, not an antialiased edge or a single lucky pixel.
            let x = (i % 2) * 64 + 32;
            let y = (1 - i / 2) * 64 + 32;
            (y - 2..=y + 2).all(|y| {
                (x - 2..=x + 2).all(|x| {
                    let at = (y * image.width + x) * 4;
                    [image.bgra[at + 2], image.bgra[at + 1], image.bgra[at]]
                        .iter()
                        .zip(rgb.iter())
                        .all(|(a, b)| a.abs_diff(*b) <= 20)
                })
            })
        })
        .count())
}

#[derive(Debug)]
enum CaptureObservation {
    Refused(String),
    Pixels(usize),
}

#[derive(Debug)]
struct WindowObservation {
    listed: bool,
    capture: CaptureObservation,
}

fn observe(
    mtm: MainThreadMarker,
    window_id: u32,
    listed: bool,
    pattern: usize,
) -> Result<WindowObservation, String> {
    let capture = match capture(mtm, window_id) {
        Err(reason) => CaptureObservation::Refused(reason),
        // An invalid raster is a probe error, not evidence of capture refusal.
        Ok(image) => CaptureObservation::Pixels(patches(&image, pattern)?),
    };
    Ok(WindowObservation { listed, capture })
}

fn describe(observation: &WindowObservation) -> String {
    let capture = match &observation.capture {
        CaptureObservation::Refused(reason) => format!("refused ({reason})"),
        CaptureObservation::Pixels(count) => format!("captured {count}/4 pattern patches"),
    };
    format!("shareable={}, {capture}", observation.listed)
}

fn capture_verdict(
    protected: &[WindowObservation; 2],
    control: &WindowObservation,
) -> Result<String, String> {
    let report = format!(
        "control: {}; preview: {}; badge: {}",
        describe(control),
        describe(&protected[0]),
        describe(&protected[1]),
    );
    if !control.listed || !matches!(control.capture, CaptureObservation::Pixels(4)) {
        return Err(format!("capture positive control failed: {report}"));
    }
    for (name, observation) in ["preview", "badge"].into_iter().zip(protected) {
        if observation.listed {
            return Err(format!("{name} is listed in SCShareableContent: {report}"));
        }
        if matches!(observation.capture, CaptureObservation::Pixels(count) if count != 0) {
            return Err(format!("{name} private pattern pixels leaked: {report}"));
        }
    }
    Ok(report)
}

/// Check the actual preview and badge panels' shareable-window membership and
/// capture each panel's own ID through production's single-window path. A
/// separate shareable control must be listed and yield its pattern. Call only
/// from the manually started app_use_desk_probe example, on the main thread,
/// after its --approve-desk-probe opt-in and permission preflight.
/// No raster is stored or returned; the report records refusal versus no pattern.
#[doc(hidden)]
pub fn probe_overlay_capture_exclusion() -> Result<String, String> {
    if !crate::screen_capture_is_permitted() {
        return Err("Screen Recording permission is unavailable".into());
    }
    if crate::screen_is_locked() != Some(false) {
        return Err("the display is locked or unknown".into());
    }
    let mtm = MainThreadMarker::new().ok_or("pixel probe must run on the main thread")?;
    let app = NSApplication::sharedApplication(mtm);
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);
    app.finishLaunching();
    let screen = NSScreen::screens(mtm)
        .firstObject()
        .ok_or("no main screen")?;
    let frame = screen.frame();
    if frame.size.width < 640.0 || frame.size.height < 240.0 {
        return Err("display too small for the pixel probe".into());
    }
    let mut preview = PreviewWindow::new(mtm);
    let mut badge = Picture::new(mtm);
    let mut control = Picture::new(mtm);
    control.panel.setSharingType(NSWindowSharingType::ReadOnly);
    let panels = [
        preview.facts().panel,
        badge.panel.clone(),
        control.panel.clone(),
    ];
    let result = (|| {
        for (i, panel) in panels.iter().enumerate() {
            let local = rect(0.0, 0.0, SIDE, SIDE);
            // SAFETY: view and panel construction/manipulation stay on main.
            let view: Retained<CapturePattern> = unsafe {
                let this = CapturePattern::alloc(mtm).set_ivars(i);
                msg_send![super(this), initWithFrame: local]
            };
            panel.setContentView(Some(&view));
            panel.setFrame_display(
                rect(
                    frame.origin.x + 48.0 + i as f64 * (SIDE + GAP),
                    frame.origin.y + frame.size.height - 80.0 - SIDE,
                    SIDE,
                    SIDE,
                ),
                true,
            );
            panel.setAlphaValue(1.0);
            panel.orderFrontRegardless();
            view.setNeedsDisplay(true);
            panel.displayIfNeeded();
        }
        commit_window_changes(mtm);
        if panels
            .iter()
            .any(|p| !window_listed_on_screen(p.windowNumber()))
        {
            return Err("all three pattern windows must be on screen".into());
        }
        let ids = panels
            .iter()
            .map(|panel| u32::try_from(panel.windowNumber()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let listed = on_worker(mtm, || shareable_window_ids(Duration::from_secs(10)))?;
        let control = observe(mtm, ids[2], listed.contains(&ids[2]), 2)
            .map_err(|e| format!("capture positive control failed: {e}"))?;
        let protected = [
            observe(mtm, ids[0], listed.contains(&ids[0]), 0)?,
            observe(mtm, ids[1], listed.contains(&ids[1]), 1)?,
        ];
        capture_verdict(&protected, &control)
    })();
    // Cleanup runs on every error path as well as success.
    crate::preview_schedule::PreviewSurface::remove(&mut preview);
    badge.remove();
    control.remove();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_window_capture_rejects_listed_or_leaking_panels_and_requires_a_visible_control() {
        // The synthetic verdict cases below cannot observe constructor changes.
        // Keep both real panels' privacy policy tied to this capture contract
        // without creating windows or taking screenshots in a unit test.
        for (source, constructor) in [
            (include_str!("preview_window.rs"), "impl PreviewWindow {"),
            (include_str!("../cursor_overlay.rs"), "impl Picture {"),
        ] {
            let initialization = source
                .split_once(constructor)
                .unwrap()
                .1
                .split_once("panel.setHasShadow")
                .unwrap()
                .0;
            assert!(
                initialization
                    .lines()
                    .any(|line| line.trim() == "panel.setSharingType(NSWindowSharingType::None);"),
                "{constructor} must exclude its panel from capture"
            );
        }

        let observation = |listed, capture| WindowObservation { listed, capture };
        let hidden = || observation(false, CaptureObservation::Pixels(0));
        let refused = || observation(false, CaptureObservation::Refused("not shareable".into()));
        let control = observation(true, CaptureObservation::Pixels(4));
        for panels in [
            [hidden(), hidden()],
            [refused(), hidden()],
            [hidden(), refused()],
            [refused(), refused()],
        ] {
            let report = capture_verdict(&panels, &control).unwrap();
            for (name, panel) in ["preview", "badge"].into_iter().zip(&panels) {
                let expected = match panel.capture {
                    CaptureObservation::Refused(_) => "refused (not shareable)",
                    CaptureObservation::Pixels(_) => "captured 0/4 pattern patches",
                };
                assert!(report.contains(&format!("{name}: shareable=false, {expected}")));
            }
        }
        for index in 0..2 {
            for capture in [
                CaptureObservation::Refused("not shareable".into()),
                CaptureObservation::Pixels(0),
                CaptureObservation::Pixels(4),
            ] {
                let mut panels = [hidden(), hidden()];
                panels[index] = observation(true, capture);
                assert!(capture_verdict(&panels, &control)
                    .unwrap_err()
                    .contains("listed in SCShareableContent"));
            }
            for count in 1..=4 {
                let mut panels = [hidden(), hidden()];
                panels[index] = observation(false, CaptureObservation::Pixels(count));
                assert!(capture_verdict(&panels, &control)
                    .unwrap_err()
                    .contains("private pattern pixels leaked"));
            }
        }
        for listed in [false, true] {
            for count in 0..=4 {
                if listed && count == 4 {
                    continue;
                }
                let bad_control = observation(listed, CaptureObservation::Pixels(count));
                assert!(capture_verdict(&[hidden(), hidden()], &bad_control)
                    .unwrap_err()
                    .contains("control failed"));
            }
            let bad_control = observation(listed, CaptureObservation::Refused("denied".into()));
            assert!(capture_verdict(&[hidden(), hidden()], &bad_control)
                .unwrap_err()
                .contains("control failed"));
            // A broken control takes precedence even if a panel also leaks.
            assert!(capture_verdict(
                &[observation(true, CaptureObservation::Pixels(4)), hidden()],
                &bad_control,
            )
            .unwrap_err()
            .contains("control failed"));
        }
    }

    #[test]
    fn the_pixel_detector_reads_each_windows_own_pattern() {
        let mut image = RawCapture {
            width: 128,
            height: 128,
            bgra: vec![0; 128 * 128 * 4],
            owner_pid_at_capture: 0,
        };
        assert_eq!(patches(&image, 0).unwrap(), 0);
        // Explicit top-down quadrants, independent of the drawing/detection
        // coordinate conversion. Each window rotates this palette once more.
        for (pattern, quadrants) in [
            [
                [181, 241, 19],
                [251, 89, 31],
                [239, 17, 193],
                [23, 229, 211],
            ],
            [
                [251, 89, 31],
                [239, 17, 193],
                [23, 229, 211],
                [181, 241, 19],
            ],
            [
                [239, 17, 193],
                [23, 229, 211],
                [181, 241, 19],
                [251, 89, 31],
            ],
        ]
        .into_iter()
        .enumerate()
        {
            for (i, [r, g, b]) in quadrants.into_iter().enumerate() {
                for y in (i / 2) * 64..(i / 2 + 1) * 64 {
                    for x in (i % 2) * 64..(i % 2 + 1) * 64 {
                        image.bgra[(y * 128 + x) * 4..(y * 128 + x) * 4 + 4]
                            .copy_from_slice(&[b, g, r, 255]);
                    }
                }
            }
            for candidate in 0..3 {
                assert_eq!(
                    patches(&image, candidate).unwrap(),
                    if candidate == pattern { 4 } else { 0 }
                );
            }
            image.bgra[(32 * 128 + 32) * 4..(32 * 128 + 32) * 4 + 3].fill(0);
            assert_eq!(patches(&image, pattern).unwrap(), 3);
        }
        image.width = 320;
        assert!(patches(&image, 0).is_err());
        image.width = 128;
        image.bgra.pop();
        assert!(patches(&image, 0).is_err());
    }
}
