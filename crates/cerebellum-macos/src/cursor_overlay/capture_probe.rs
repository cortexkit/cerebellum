//! Manual desk-only pixel experiment, kept separate from the overlay loop.
//! It checks each real panel's shareable-window membership and own single-window
//! capture, with a separate, normally shared window as a positive control.

use super::*;
use crate::macos::{capture_window, CaptureSourceRect, RawCapture};
use block2::RcBlock;
use objc2_foundation::NSError;
use objc2_screen_capture_kit::SCShareableContent;

/// Every window ScreenCaptureKit offers for capture, as (window ID, on screen).
fn shareable_windows(timeout: Duration) -> Result<Vec<(u32, bool)>, String> {
    let (sink, delivery) = std::sync::mpsc::channel();
    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: callback objects remain valid until it returns. Copy only
            // IDs and on-screen flags, without filtering out windows whose
            // owner metadata is missing.
            let result = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    Ok(content
                        .windows()
                        .iter()
                        .map(|w| (w.windowID(), w.isOnScreen()))
                        .collect())
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

/// How long the three windows may take to reach the window server's on-screen
/// list, with the control also on screen in ScreenCaptureKit's list.
const ON_SCREEN_DEADLINE: Duration = Duration::from_secs(3);
/// Extra time after the windows are on screen, so the window server has
/// composited their first drawn frame before anything is captured.
const SETTLE: Duration = Duration::from_millis(250);
/// How long the control's capture is retried until it shows its pattern.
const CONTROL_DEADLINE: Duration = Duration::from_secs(3);
/// The pause between two readiness checks or two control captures.
const POLL: Duration = Duration::from_millis(100);

/// The largest per-channel difference at which a captured pixel still counts
/// as the colour drawn there.
///
/// The pattern is drawn in sRGB, but the capture may come back in another
/// colour space: this module's captures are known to pass through a
/// conversion that mixes channels (see the `source_rect_pattern` test). These
/// colours are saturated, so a conversion moves them a long way: rendered in
/// Display P3, the four palette colours land 22, 35, 60 and 84 levels from
/// their sRGB values, so a tolerance of 20 would miss all four patches on such
/// a display. The palette colours are at least 152 levels apart from each
/// other, so a pixel must also be nearer to the expected colour than to any
/// other palette colour; black, white and mid grey stay out of reach.
const TOLERANCE: u8 = 96;
/// A pixel less opaque than this is not the opaque fill that was drawn.
const MIN_ALPHA: u8 = 240;

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

/// Send pending window changes to the window server and turn the main run loop
/// once, briefly. ScreenCaptureKit may deliver through the main run loop, and
/// AppKit flushes drawn content to the window server from it.
fn turn_main_loop(mtm: MainThreadMarker) {
    commit_window_changes(mtm);
    objc2_foundation::NSRunLoop::currentRunLoop().runMode_beforeDate(
        unsafe { NSDefaultRunLoopMode },
        &NSDate::dateWithTimeIntervalSinceNow(0.01),
    );
}

/// Keep the main run loop turning for `duration`.
fn pump(mtm: MainThreadMarker, duration: Duration) {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        turn_main_loop(mtm);
    }
}

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
        // Keep the main run loop turning while the capture worker waits for
        // the framework callback.
        turn_main_loop(mtm);
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

/// One pattern patch as captured: the colour drawn there and the median of the
/// pixels sampled across its interior.
#[derive(Debug, Clone, Copy, PartialEq)]
struct PatchSample {
    expected: [u8; 3],
    /// Red, green, blue and alpha as the capture holds them (not
    /// un-premultiplied), each the median over the interior grid.
    sampled: [u8; 4],
    /// A strict majority of sampled pixels counted as the drawn palette colour.
    matched: bool,
}

/// Whether one captured BGRA pixel is the palette colour `expected`.
fn pixel_matches(bgra: &[u8], expected: [u8; 3]) -> bool {
    let alpha = bgra[3];
    if alpha < MIN_ALPHA {
        return false;
    }
    // The capture may hold premultiplied colour; undo that before comparing,
    // so a nearly opaque pixel is compared with the colour that was drawn.
    let unpremultiply =
        |c: u8| ((u32::from(c) * 255 + u32::from(alpha) / 2) / u32::from(alpha)).min(255) as u8;
    let rgb = [bgra[2], bgra[1], bgra[0]].map(unpremultiply);
    let distance = |colour: &[u8; 3]| {
        colour
            .iter()
            .zip(rgb)
            .map(|(a, b)| a.abs_diff(b))
            .max()
            .unwrap_or(0)
    };
    let own = distance(&expected);
    own <= TOLERANCE
        && COLOURS
            .iter()
            .all(|other| *other == expected || distance(other) > own)
}

/// Read the four patches of window pattern `pattern` from a capture.
///
/// Positions are computed in the raster's own pixels from its dimensions.
/// `capture_window` sizes its output to the source rect in points, so today the
/// raster has one pixel per point whatever the display's backing scale; a
/// raster at the backing scale is read at the same relative interior positions.
fn patches(image: &RawCapture, pattern: usize) -> Result<[PatchSample; 4], String> {
    let (width, height) = (image.width, image.height);
    // The source rect is square, so a raster of any other shape, or too small
    // to hold an interior square per quadrant, is not this window's capture.
    if width != height || width < 32 || image.bgra.len() != width * height * 4 {
        return Err(format!(
            "unexpected single-window raster: {width}x{height} ({} bytes)",
            image.bgra.len()
        ));
    }
    Ok(std::array::from_fn(|i| {
        let expected = pattern_colours(pattern)[i];
        // AppKit paints bottom-up; the captured raster is top-down.
        let column = i % 2;
        let row = 1 - i / 2;
        let left = column * width / 2;
        let top = row * height / 2;
        let patch_width = (column + 1) * width / 2 - left;
        let patch_height = (row + 1) * height / 2 - top;
        // Split the central 50% of the mapped patch into five cells per axis
        // and sample their centres (30%, 40%, ..., 70%). Spreading the votes
        // keeps a small resampled blend from vetoing an otherwise solid fill;
        // the outer quarter on every side never votes, at any raster scale.
        let pixels: Vec<&[u8]> = (0..5)
            .flat_map(|y| {
                let y = top + (y + 3) * patch_height / 10;
                (0..5).map(move |x| {
                    let x = left + (x + 3) * patch_width / 10;
                    (y * width + x) * 4
                })
            })
            .map(|at| &image.bgra[at..at + 4])
            .collect();
        let median = |channel: usize| {
            let mut values: Vec<u8> = pixels.iter().map(|p| p[channel]).collect();
            values.sort_unstable();
            values[values.len() / 2]
        };
        PatchSample {
            expected,
            sampled: [median(2), median(1), median(0), median(3)],
            matched: pixels.iter().filter(|p| pixel_matches(p, expected)).count()
                > pixels.len() / 2,
        }
    }))
}

fn matched_count(samples: &[PatchSample]) -> usize {
    samples.iter().filter(|sample| sample.matched).count()
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
    /// The patches read from the capture; empty when it was refused.
    samples: Vec<PatchSample>,
}

fn observe(
    mtm: MainThreadMarker,
    window_id: u32,
    listed: bool,
    pattern: usize,
) -> Result<WindowObservation, String> {
    let (capture, samples) = match capture(mtm, window_id) {
        Err(reason) => (CaptureObservation::Refused(reason), Vec::new()),
        // An invalid raster is a probe error, not evidence of capture refusal.
        Ok(image) => {
            let samples = patches(&image, pattern)?;
            (
                CaptureObservation::Pixels(matched_count(&samples)),
                samples.to_vec(),
            )
        }
    };
    Ok(WindowObservation {
        listed,
        capture,
        samples,
    })
}

fn describe(observation: &WindowObservation) -> String {
    let mut capture = match &observation.capture {
        CaptureObservation::Refused(reason) => format!("refused ({reason})"),
        CaptureObservation::Pixels(count) => format!("captured {count}/4 pattern patches"),
    };
    if !observation.samples.is_empty() {
        let samples: Vec<String> = observation
            .samples
            .iter()
            .map(
                |PatchSample {
                     expected: [r, g, b],
                     sampled: [sr, sg, sb, sa],
                     ..
                 }| { format!("rgb {sr},{sg},{sb} alpha {sa} vs {r},{g},{b}") },
            )
            .collect();
        capture.push_str(&format!(" (sampled vs expected: {})", samples.join("; ")));
    }
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
/// No raster is stored or returned; the report records refusal versus no pattern,
/// and for each captured window the median colour of each sampled patch next
/// to the colour drawn there.
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
        let ids = panels
            .iter()
            .map(|panel| u32::try_from(panel.windowNumber()).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        // A window captured right after it is ordered in can come back before
        // its first drawn frame was composited. Wait until the window server
        // lists all three windows on screen and ScreenCaptureKit lists the
        // control on screen, then settle once more before capturing.
        // A panel listed by ScreenCaptureKit in any read fails the verdict, so
        // every read counts towards the panels' membership, not only the last.
        let mut listed_ever = [false; 3];
        let record = |listed_ever: &mut [bool; 3], shareable: &[(u32, bool)]| {
            for (listed, id) in listed_ever.iter_mut().zip(&ids) {
                *listed |= shareable.iter().any(|(window, _)| window == id);
            }
        };
        let on_screen_deadline = Instant::now() + ON_SCREEN_DEADLINE;
        loop {
            let shareable = on_worker(mtm, || shareable_windows(Duration::from_secs(10)))?;
            record(&mut listed_ever, &shareable);
            let all_on_screen = panels
                .iter()
                .all(|p| window_listed_on_screen(p.windowNumber()));
            let control_on_screen = shareable
                .iter()
                .any(|&(window, on_screen)| window == ids[2] && on_screen);
            if all_on_screen && control_on_screen {
                break;
            }
            if Instant::now() >= on_screen_deadline {
                return Err(format!(
                    "the pattern windows were not on screen within {ON_SCREEN_DEADLINE:?}: \
                     all three in the window server's on-screen list={all_on_screen}, \
                     control on screen in SCShareableContent={control_on_screen}"
                ));
            }
            pump(mtm, POLL);
        }
        pump(mtm, SETTLE);

        // The control must show its whole pattern before anything else is
        // captured: until it does, an empty panel capture proves nothing.
        let control_deadline = Instant::now() + CONTROL_DEADLINE;
        let mut attempts = 0;
        let mut control = loop {
            attempts += 1;
            let attempt = observe(mtm, ids[2], true, 2)
                .map_err(|e| format!("capture positive control failed: {e}"))?;
            if matches!(attempt.capture, CaptureObservation::Pixels(4)) {
                break attempt;
            }
            if Instant::now() >= control_deadline {
                return Err(format!(
                    "capture positive control failed: no full pattern within \
                     {CONTROL_DEADLINE:?} ({attempts} captures); last control: {}",
                    describe(&attempt)
                ));
            }
            pump(mtm, POLL);
        };

        // The panels were ordered in and drawn before the control, so they
        // have had at least the control's time on screen and the same settle.
        let mut protected = [
            observe(mtm, ids[0], false, 0)?,
            observe(mtm, ids[1], false, 1)?,
        ];
        // Read membership once more after the captures, so a panel that joins
        // the shareable list late is still caught.
        let shareable = on_worker(mtm, || shareable_windows(Duration::from_secs(10)))?;
        record(&mut listed_ever, &shareable);
        for (observation, listed) in protected.iter_mut().zip(listed_ever) {
            observation.listed = listed;
        }
        control.listed = shareable.iter().any(|(window, _)| *window == ids[2]);
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

        let observation = |listed, capture| WindowObservation {
            listed,
            capture,
            samples: Vec::new(),
        };
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

    fn count(image: &RawCapture, pattern: usize) -> usize {
        matched_count(&patches(image, pattern).unwrap())
    }

    /// A square raster of `side` pixels whose top-down quadrants are filled
    /// with `quadrants` (top-left, top-right, bottom-left, bottom-right),
    /// premultiplied by `alpha` the way a capture may store them.
    fn quadrant_image(side: usize, quadrants: [[u8; 3]; 4], alpha: u8) -> RawCapture {
        let mut bgra = vec![0; side * side * 4];
        let half = side / 2;
        for (i, rgb) in quadrants.into_iter().enumerate() {
            let [r, g, b] = rgb.map(|c| (u32::from(c) * u32::from(alpha) / 255) as u8);
            for y in (i / 2) * half..(i / 2 + 1) * half {
                for x in (i % 2) * half..(i % 2 + 1) * half {
                    bgra[(y * side + x) * 4..(y * side + x) * 4 + 4]
                        .copy_from_slice(&[b, g, r, alpha]);
                }
            }
        }
        RawCapture {
            width: side,
            height: side,
            bgra,
            owner_pid_at_capture: 0,
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
        assert_eq!(count(&image, 0), 0);
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
                    count(&image, candidate),
                    if candidate == pattern { 4 } else { 0 }
                );
            }
            for y in 16..48 {
                for x in 16..48 {
                    image.bgra[(y * 128 + x) * 4..(y * 128 + x) * 4 + 3].fill(0);
                }
            }
            assert_eq!(count(&image, pattern), 3);
        }
        image.width = 320;
        assert!(patches(&image, 0).is_err());
        image.width = 128;
        image.bgra.pop();
        assert!(patches(&image, 0).is_err());
    }

    #[test]
    fn the_pixel_detector_accepts_a_wide_gamut_rendering_at_any_raster_scale() {
        // The control's pattern as a capture in Display P3 holds it: each sRGB
        // palette colour converted to P3, 22 to 84 levels from what was drawn.
        let p3 = [
            [219, 52, 188],
            [107, 226, 211],
            [193, 239, 79],
            [233, 100, 53],
        ];
        // One pixel per point, as `capture_window` returns today, and two, as
        // a capture at a Retina display's backing scale would.
        for side in [128, 256] {
            for alpha in [255, 245] {
                let image = quadrant_image(side, p3, alpha);
                assert_eq!(count(&image, 2), 4, "{side} px, alpha {alpha}");
                for other in [0, 1] {
                    assert_eq!(count(&image, other), 0, "{side} px, pattern {other}");
                }
            }
        }
        // Half-transparent pixels are not the opaque fill that was drawn.
        assert_eq!(count(&quadrant_image(128, p3, 128), 2), 0);
        // Greys from black to white, and a fully transparent capture, are
        // never read as a palette colour.
        for grey in [0, 64, 128, 192, 255] {
            assert_eq!(
                count(&quadrant_image(128, [[grey; 3]; 4], 255), 2),
                0,
                "grey {grey}"
            );
        }
        assert_eq!(count(&quadrant_image(128, p3, 0), 2), 0);
    }

    fn control_with_boundary_blend(side: usize) -> RawCapture {
        let mut image = quadrant_image(
            side,
            [
                [219, 52, 188],
                [107, 226, 211],
                [193, 239, 79],
                [233, 100, 53],
            ],
            255,
        );
        // Preserve a resampled boundary blend in the old centre-only sampling
        // square of the cyan patch. The surrounding interior retains its palette
        // colour converted to the Display P3 colour space.
        let radius = (side / 64).max(2);
        for y in side / 4 - radius..=side / 4 + radius {
            for x in 3 * side / 4 - radius..=3 * side / 4 + radius {
                let at = (y * side + x) * 4;
                image.bgra[at..at + 4].copy_from_slice(&[212, 224, 128, 255]);
            }
        }
        image
    }

    #[test]
    fn boundary_blends_do_not_hide_the_control_patch_interiors() {
        assert!(!pixel_matches(&[212, 224, 128, 255], [23, 229, 211]));
        for side in [128, 256] {
            let image = control_with_boundary_blend(side);
            let samples = patches(&image, 2).unwrap();
            assert_eq!(matched_count(&samples), 4, "{side}px: {samples:?}");
        }
    }

    #[test]
    fn only_the_central_half_of_each_patch_votes_at_both_capture_scales() {
        for side in [128, 256] {
            let mut image = quadrant_image(side, [[128, 224, 212]; 4], 255);
            let half = side / 2;
            for (i, [r, g, b]) in [
                [239, 17, 193],
                [23, 229, 211],
                [181, 241, 19],
                [251, 89, 31],
            ]
            .into_iter()
            .enumerate()
            {
                let left = (i % 2) * half;
                let top = (i / 2) * half;
                for y in top + half / 4..top + 3 * half / 4 {
                    for x in left + half / 4..left + 3 * half / 4 {
                        let at = (y * side + x) * 4;
                        image.bgra[at..at + 4].copy_from_slice(&[b, g, r, 255]);
                    }
                }
            }
            assert_eq!(count(&image, 2), 4, "{side}px");
        }
    }

    #[test]
    fn a_patch_needs_a_strict_majority_of_individually_matching_pixels() {
        let mut image = quadrant_image(128, [[239, 17, 193]; 4], 255);
        // Explicit raster positions for the top-left patch's interior grid.
        let positions: Vec<_> = [19, 25, 32, 38, 44]
            .into_iter()
            .flat_map(|y| [19, 25, 32, 38, 44].map(|x| (x, y)))
            .collect();
        for &(x, y) in &positions[..12] {
            let at = (y * 128 + x) * 4;
            image.bgra[at..at + 3].fill(0);
        }
        assert!(patches(&image, 2).unwrap()[2].matched, "13 of 25 votes");
        let (x, y) = positions[12];
        let at = (y * 128 + x) * 4;
        image.bgra[at..at + 3].fill(0);
        assert!(!patches(&image, 2).unwrap()[2].matched, "12 of 25 votes");
    }

    #[test]
    fn a_present_private_pattern_cannot_be_reported_absent() {
        let observation = |image: &RawCapture, pattern, listed| {
            let samples = patches(image, pattern).unwrap();
            WindowObservation {
                listed,
                capture: CaptureObservation::Pixels(matched_count(&samples)),
                samples: samples.to_vec(),
            }
        };
        for side in [128, 256] {
            let control = observation(&control_with_boundary_blend(side), 2, true);
            let absent = quadrant_image(side, [[0; 3]; 4], 255);
            for (pattern, name, quadrants) in [
                (
                    0,
                    "preview",
                    [
                        [193, 239, 79],
                        [233, 100, 53],
                        [219, 52, 188],
                        [107, 226, 211],
                    ],
                ),
                (
                    1,
                    "badge",
                    [
                        [233, 100, 53],
                        [219, 52, 188],
                        [107, 226, 211],
                        [193, 239, 79],
                    ],
                ),
            ] {
                let mut protected = [
                    observation(&absent, 0, false),
                    observation(&absent, 1, false),
                ];
                assert!(capture_verdict(&protected, &control).is_ok());
                let present = quadrant_image(side, quadrants, 255);
                protected[pattern] = observation(&present, pattern, false);
                assert!(matches!(
                    protected[pattern].capture,
                    CaptureObservation::Pixels(4)
                ));
                let reason = capture_verdict(&protected, &control).unwrap_err();
                assert!(
                    reason.contains(&format!("{name} private pattern pixels leaked")),
                    "{reason}"
                );
            }
        }
    }

    #[test]
    fn the_report_shows_each_sampled_colour_next_to_the_drawn_one() {
        let image = quadrant_image(128, [[0, 0, 0]; 4], 255);
        let samples = patches(&image, 2).unwrap();
        let observation = WindowObservation {
            listed: true,
            capture: CaptureObservation::Pixels(matched_count(&samples)),
            samples: samples.to_vec(),
        };
        let text = describe(&observation);
        assert!(
            text.starts_with("shareable=true, captured 0/4 pattern patches (sampled vs expected: ")
        );
        for [r, g, b] in pattern_colours(2) {
            assert!(
                text.contains(&format!("rgb 0,0,0 alpha 255 vs {r},{g},{b}")),
                "{text}"
            );
        }
    }
}
