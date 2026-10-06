// Separate binary: uses harness = false to open AppKit on the main thread.
//! A source rect returns THE REGION, not the whole window scaled into it, and
//! not some other region of it.
//!
//! WHY A WINDOW THIS TEST DRAWS ITSELF. The capture path resamples, and the
//! obvious assertions cannot see the defects that matter: `setWidth` and
//! `setHeight` apply whether or not a rect is honoured, so an ignored rect still
//! yields exactly the requested size -- a squashed thumbnail of the whole
//! window -- and a rect applied in the wrong coordinate space is clamped by the
//! framework rather than refused. An earlier version captured whatever real
//! window it found on the desktop and compared row distances between
//! hypotheses. Real windows are too self-similar for that: with the rect
//! deleted from production, and again with the window's screen position added
//! to it, that version reported "cannot separate the hypotheses" and skipped,
//! so neither defect it existed for was ever caught.
//!
//! Here a helper process opens a window whose every row names itself: row y, in
//! points, is painted the grey level y. The output of a top-half capture then
//! SAYS which source rows it holds, with no statistics:
//!   - honoured: row i holds source row i;
//!   - wrong space: row i holds source row i + k for some other band (or the
//!     capture fails, or holds no pattern at all);
//!   - ignored: row i holds source row 2i, the whole height squeezed.

//!
//! WHY A HELPER PROCESS, AND WHY THIS TARGET HAS NO TEST HARNESS. AppKit windows
//! must be created on a process's main thread, and the standard test harness
//! runs every test on a thread of its own. So this target is built with
//! `harness = false`: its `main` runs on the main thread, and it re-executes
//! itself in a helper mode to own the window. A separate process also means the
//! window is captured the way production captures -- another process's window,
//! resolved by that process's id through the window list.
//!
//! WHY THE HELPER DOES NOT TAKE FOCUS. This runs on a desk someone is using. The
//! helper is an accessory application (no Dock icon, never activated), its
//! window ignores the mouse, and it is ordered to the BACK of the window list:
//! a single-window capture reads the window's own contents whether or not
//! anything covers it, so it never needs to be in front. The test reads the
//! frontmost process before and after, and fails if the helper became it.

#[cfg(target_os = "macos")]
#[path = "../src/test_support.rs"]
mod permission_test_support;

#[cfg(not(target_os = "macos"))]
fn main() {
    // ScreenCaptureKit and AppKit exist only on macOS, so there is nothing to
    // measure here. The target still has to build so the workspace does.
}

#[cfg(target_os = "macos")]
fn main() {
    if std::env::var_os(pattern::HELPER_MODE).is_some() {
        pattern::run_window();
    } else {
        pattern::run_test();
    }
}

#[cfg(target_os = "macos")]
mod pattern {
    use std::io::{BufRead, BufReader, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    use super::permission_test_support::{run_after_permission_preflight, Permission};
    use cerebellum_macos::{
        capture_window, enumerate_windows, frontmost_process_id, screen_capture_is_permitted,
        screen_is_locked, CaptureSourceRect, RawCapture,
    };

    const TEST_NAME: &str = "a_source_rect_returns_the_region_rather_than_the_whole_window";

    /// Set in the environment of the re-executed copy that owns the window.
    pub const HELPER_MODE: &str = "CEREBELLUM_SOURCE_RECT_PATTERN_WINDOW";

    /// The window's side, in points. 256 so that an 8-bit grey level can name
    /// every row exactly, one level per point.
    const SIDE: usize = 256;

    /// Where the window's top-left corner sits, in screen points from the top
    /// left of the primary display.
    ///
    /// Chosen so that the window's screen position is well clear of zero, yet
    /// smaller than the window: a rect wrongly offset by that position then
    /// still overlaps the window, and the framework returns some OTHER band of
    /// rows rather than refusing -- the quiet form of the defect, which is the
    /// one a caller would not notice. Below the menu bar, so the system leaves
    /// the window where it was put. The test reads the position the window list
    /// reports and skips if it is too small to tell the defect apart.
    const TOP_LEFT: (f64, f64) = (48.0, 64.0);

    /// How many rows a decoded row may differ from the one requested before
    /// the capture is judged to hold the wrong region.
    ///
    /// Measured on macOS 26 at 2x: the honoured capture decodes to exactly the
    /// requested rows (maximum error 0), because each point of the pattern is
    /// a uniform block and the framework's downscale averages identical
    /// pixels. One is allowed because the bottom edge row of a capture can
    /// repeat the row above it (see `pattern_reference`), and for resampling
    /// that straddles a point boundary on a display at another scale. The
    /// defects are nowhere near it: an ignored rect is off by up to 127 rows,
    /// and the wrong space by the window's vertical screen position.
    const TOLERANCE: usize = 1;

    const TIMEOUT: Duration = Duration::from_secs(10);

    enum Outcome {
        Passed,
        Skipped(String),
        Failed(String),
    }

    pub fn run_test() {
        // Honour name filters the way the standard harness would, so running
        // a different test by name does not also open a window here. Options
        // are ignored, except that the harness options taking a value must not
        // have that value mistaken for a filter.
        let mut filters = Vec::new();
        let mut skips = Vec::new();
        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            match argument.as_str() {
                "--skip" => skips.extend(arguments.next()),
                "--test-threads" | "--format" | "--color" | "--logfile" | "-Z" => {
                    arguments.next();
                }
                option if option.starts_with('-') => {}
                _ => filters.push(argument),
            }
        }
        let excluded = skips.iter().any(|skip| TEST_NAME.contains(skip.as_str()));
        let unselected = !filters.is_empty()
            && !filters
                .iter()
                .any(|filter| TEST_NAME.contains(filter.as_str()));
        if excluded || unselected {
            return;
        }

        let outcome = measure();
        match outcome {
            Outcome::Passed => println!("test {TEST_NAME} ... ok"),
            // A skip is printed as one, never as "ok": a precondition that is
            // missing means nothing was measured.
            Outcome::Skipped(reason) => println!("test {TEST_NAME} ... SKIPPED: {reason}"),
            Outcome::Failed(reason) => {
                println!("test {TEST_NAME} ... FAILED\n\n{reason}\n");
                std::process::exit(101);
            }
        }
    }

    /// Ends the helper however the measurement ends, including by panic, so no
    /// stray window outlives the test.
    struct Helper(Child);

    impl Drop for Helper {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn measure() -> Outcome {
        match run_after_permission_preflight(
            Permission::ScreenRecording,
            screen_capture_is_permitted,
            measure_with_screen_recording,
        ) {
            Ok(outcome) => outcome,
            Err(reason) => Outcome::Skipped(reason.to_string()),
        }
    }

    fn measure_with_screen_recording() -> Outcome {
        if screen_is_locked() == Some(true) {
            return Outcome::Skipped(
                "the screen is locked, so no window is realised and no pixels are readable"
                    .to_string(),
            );
        }

        let frontmost_before = frontmost_process_id();

        let executable = std::env::current_exe().expect("the test binary's own path");
        let child = match Command::new(executable)
            .env(HELPER_MODE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                return Outcome::Failed(format!("the window helper could not start: {error}"))
            }
        };
        let mut helper = Helper(child);
        let helper_pid = helper.0.id();

        // The helper prints its window number once the window is ordered in.
        // Read on a thread so a helper that never answers cannot hold the test.
        let stdout = helper.0.stdout.take().expect("stdout is piped");
        let (lines, announced) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if lines.send(line).is_err() {
                    break;
                }
            }
        });
        let window_id = match announced.recv_timeout(TIMEOUT) {
            Ok(line) => match line.strip_prefix("window ").map(str::parse::<u32>) {
                Some(Ok(id)) => id,
                _ => {
                    return Outcome::Failed(format!(
                        "the window helper announced something other than a window: {line:?}"
                    ))
                }
            },
            Err(_) => {
                return Outcome::Skipped(format!(
                    "the window was not realised: the helper announced no window within \
                     {TIMEOUT:?}, which is what a session without a window server looks like"
                ))
            }
        };

        // RESOLVE BY PID through the same window list production reads, and
        // wait until the system reports the window at its full size: a window
        // the list does not yet describe cannot be captured at all.
        let deadline = Instant::now() + TIMEOUT;
        let window = loop {
            let found = enumerate_windows(TIMEOUT).ok().and_then(|windows| {
                windows.into_iter().find(|window| {
                    window.owner_pid == helper_pid
                        && window.window_id == window_id
                        && window.width == SIDE as f64
                        && window.height == SIDE as f64
                })
            });
            if let Some(window) = found {
                break window;
            }
            if Instant::now() > deadline {
                return Outcome::Skipped(format!(
                    "the window was not realised: window {window_id} of process {helper_pid} \
                     never appeared in the window list at {SIDE}x{SIDE}"
                ));
            }
            std::thread::sleep(Duration::from_millis(100));
        };
        // A window near the top of the screen would make an offset applied in
        // the wrong space too small to see, and a pass then would prove nothing
        // about that defect.
        println!(
            "window {window_id} of process {helper_pid} at ({}, {}), {}x{}",
            window.x, window.y, window.width, window.height
        );
        if window.y <= (TOLERANCE + 1) as f64 {
            return Outcome::Skipped(format!(
                "the window sits {} points from the top of the screen, too close to tell a rect \
                 in screen space from one in window space",
                window.y
            ));
        }

        // The full capture is the reference the half is decoded against, and
        // the proof that the pattern is on screen. It is taken without a rect,
        // so the defects under test cannot affect it; a failure here is about
        // the machine, not the rect.
        let deadline = Instant::now() + TIMEOUT;
        let full = loop {
            match capture_window(window.window_id, TIMEOUT, None) {
                Ok(full) if pattern_reference(&full).is_ok() => break full,
                attempt if Instant::now() > deadline => {
                    return Outcome::Skipped(match attempt {
                        Err(error) => format!(
                            "the window could not be captured without a rect, so Screen \
                             Recording is not usable here: {error}"
                        ),
                        Ok(full) => format!(
                            "the window was not realised: its capture does not hold the drawn \
                             pattern ({})",
                            pattern_reference(&full).err().unwrap_or_default()
                        ),
                    });
                }
                _ => std::thread::sleep(Duration::from_millis(100)),
            }
        };
        let reference = pattern_reference(&full).expect("checked in the loop above");

        let requested = CaptureSourceRect {
            x: 0.0,
            y: 0.0,
            width: SIDE as f64,
            height: (SIDE / 2) as f64,
        };
        // From here on every failure is a finding, not a skip: the machine has
        // just shown it can capture this window.
        let half = match capture_window(window.window_id, TIMEOUT, Some(requested)) {
            Ok(half) => half,
            Err(error) => {
                return Outcome::Failed(format!(
                    "capturing the top half of a window that captures whole failed: {error}. A \
                     rect outside the window's own coordinate space can be refused like this"
                ))
            }
        };

        let judged = region_of(&half, &reference, SIDE, SIDE / 2);

        let frontmost_after = frontmost_process_id();
        let _ = helper
            .0
            .stdin
            .as_mut()
            .map(|stdin| stdin.write_all(b"quit\n"));

        if let Err(reason) = judged {
            return Outcome::Failed(reason);
        }
        // Only the helper itself becoming frontmost is a failure. Another
        // change is the person at the desk switching applications during the
        // run, which the helper cannot cause and this test must not blame on
        // it; it is printed so a reader can see the reading was taken.
        println!(
            "frontmost process: {frontmost_before:?} before, {frontmost_after:?} after \
             (helper is {helper_pid})"
        );
        if frontmost_after == Some(helper_pid as i32) {
            return Outcome::Failed(format!(
                "the helper window became frontmost ({frontmost_before:?} before, helper \
                 {helper_pid} after). It must stay behind the person's work"
            ));
        }
        Outcome::Passed
    }

    /// How the full capture renders each row's grey level, top to bottom.
    ///
    /// Decoding against the window's own full capture rather than against the
    /// levels drawn, because the display's colour conversion maps a drawn
    /// level to a slightly different rendered one, and not by a fixed amount.
    /// It maps greys monotonically, and both captures pass through the same
    /// conversion, so the full capture is the dictionary for the half.
    ///
    /// Grey rather than a colour per axis: a pattern with the column in red and
    /// the row in green was measured too, and the conversion mixes channels,
    /// collapsing 65536 drawn colours into 34113 rendered ones, so positions
    /// stopped being unique. Greys stay distinct, one per row.
    struct Reference {
        rows: Vec<u8>,
    }

    const GREEN: usize = 1;

    /// The row's green level, as the median across the row, so a single stray
    /// pixel (a compositor edge) cannot move the reading.
    fn row_value(capture: &RawCapture, y: usize) -> u8 {
        let mut values: Vec<u8> = (0..capture.width)
            .map(|x| capture.bgra[(y * capture.width + x) * 4 + GREEN])
            .collect();
        values.sort_unstable();
        values[values.len() / 2]
    }

    /// Read the reference out of a full capture, or say why it is not one.
    ///
    /// Every row but the last must render to a distinct level, strictly
    /// increasing, or the pattern cannot name a row and nothing decoded from it
    /// would mean anything.
    ///
    /// The last row is exempt because the capture's bottom edge is not
    /// reliable. Measured on macOS 26, in four runs of about fifteen: the
    /// final output row repeated the one above it, or came out a level darker
    /// than it, with levels 0..=255 and again with levels 32..=223, while every
    /// other row decoded exactly. It is an edge effect of the resampling, not of the pattern.
    /// Left in the dictionary, it only ever duplicates a level held by an
    /// earlier row, and decoding takes the first row with the nearest level,
    /// so it cannot capture a reading that belongs elsewhere.
    fn pattern_reference(full: &RawCapture) -> Result<Reference, String> {
        if full.width != SIDE || full.height != SIDE {
            return Err(format!(
                "captured {}x{}, drawn {SIDE}x{SIDE}",
                full.width, full.height
            ));
        }
        let rows: Vec<u8> = (0..SIDE).map(|y| row_value(full, y)).collect();
        if let Some(at) = rows[..SIDE - 1]
            .windows(2)
            .position(|pair| pair[0] >= pair[1])
        {
            return Err(format!(
                "row {at} renders as {} and row {} as {}, so they cannot be told apart",
                rows[at],
                at + 1,
                rows[at + 1]
            ));
        }
        Ok(Reference { rows })
    }

    /// The source row whose rendered level is nearest `value`.
    fn decode(reference: &Reference, value: u8) -> usize {
        (0..reference.rows.len())
            .min_by_key(|&row| reference.rows[row].abs_diff(value))
            .expect("the reference has rows")
    }

    /// Whether `half` holds the top `height` rows of the window, in order and
    /// unscaled, and if not, what it holds instead.
    fn region_of(
        half: &RawCapture,
        reference: &Reference,
        width: usize,
        height: usize,
    ) -> Result<(), String> {
        if half.width != width || half.height != height {
            return Err(format!(
                "a {width}x{height} rect produced a {}x{} image",
                half.width, half.height
            ));
        }
        let rows: Vec<usize> = (0..height)
            .map(|y| decode(reference, row_value(half, y)))
            .collect();
        let (expected, found, error) = rows
            .iter()
            .enumerate()
            .map(|(expected, &found)| (expected, found, expected.abs_diff(found)))
            .max_by_key(|(_, _, error)| *error)
            .expect("the capture has rows");
        println!(
            "decoded source rows {}..={} (worst error {error}, tolerance {TOLERANCE})",
            rows[0],
            rows[height - 1],
        );
        if error <= TOLERANCE {
            return Ok(());
        }

        // Name the defect the decoded rows describe, so the failure says which
        // of the two known ways a rect goes wrong this is. A squeezed window's
        // output row y averages source rows 2y and 2y + 1, hence one more row
        // of slack than the tolerance.
        let squeezed = rows
            .iter()
            .enumerate()
            .all(|(y, &found)| found.abs_diff(y * SIDE / height) <= TOLERANCE + 1);
        let shape = if squeezed {
            format!(
                "The rect was IGNORED: the output holds source rows 0..={} squeezed into \
                 {height} rows, the whole window scaled to the requested size.",
                rows[height - 1]
            )
        } else {
            format!(
                "The rect selected the WRONG REGION: the output holds source rows {}..={}. A \
                 rect outside the window's own coordinate space is clamped into some other \
                 region rather than refused, so an offset applied in the wrong space looks like \
                 this.",
                rows[0],
                rows[height - 1]
            )
        };
        Err(format!(
            "a capture of the window's top {height} rows does not hold them: output row \
             {expected} holds source row {found}. {shape}"
        ))
    }

    /// The helper: open the pattern window, announce it, and keep it on screen
    /// until told to quit or until the test's end of the pipe closes.
    pub fn run_window() {
        use objc2::rc::{Allocated, Retained};
        use objc2::runtime::{AnyClass, AnyObject};
        use objc2::{class, msg_send};
        use objc2_core_foundation::CFData;
        use objc2_core_graphics::{
            CGBitmapInfo, CGColorRenderingIntent, CGColorSpace, CGDataProvider, CGImage,
        };
        use objc2_foundation::{NSPoint, NSRect, NSSize, NSString};

        // Loads AppKit so its classes exist at run time. Nothing else in this
        // crate links it, and `class!` looks classes up by name.
        #[link(name = "AppKit", kind = "framework")]
        extern "C" {}

        // Standard input is watched on a thread; the main thread belongs to
        // AppKit's event loop.
        let (commands, received) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if commands.send(line).is_err() {
                    return;
                }
            }
            // End of input means the test is gone, however it ended.
            let _ = commands.send("quit".to_string());
        });

        // The pattern: row y is grey level y, one level per point.
        let mut pixels = Vec::with_capacity(SIDE * SIDE * 4);
        for y in 0..SIDE {
            for _ in 0..SIDE {
                pixels.extend_from_slice(&[y as u8, y as u8, y as u8, 0xff]);
            }
        }
        let data = CFData::from_bytes(&pixels);
        let provider = CGDataProvider::with_cf_data(Some(&data)).expect("a data provider");
        let space = CGColorSpace::new_device_rgb().expect("the device RGB colour space");
        // SAFETY: the provider holds exactly SIDE * SIDE * 4 bytes, matching the
        // stated geometry; `decode` is null, which CGImageCreate accepts.
        let image = unsafe {
            CGImage::new(
                SIDE,
                SIDE,
                8,
                32,
                SIDE * 4,
                Some(&space),
                // Alpha skipped in the last byte: RGBX, opaque.
                CGBitmapInfo(5),
                Some(&provider),
                std::ptr::null(),
                false,
                CGColorRenderingIntent::RenderingIntentDefault,
            )
        }
        .expect("the pattern image");

        // SAFETY: every message below is sent to an AppKit or Core Animation
        // object on the main thread, with argument and return types matching
        // the documented signatures; objc2 checks the encodings in debug builds.
        unsafe {
            let application: Retained<AnyObject> =
                msg_send![class!(NSApplication), sharedApplication];
            // Accessory: may own windows, has no Dock icon, and is never made
            // the active application unless it asks, which it does not.
            let _: bool = msg_send![&application, setActivationPolicy: 1isize];
            let _: () = msg_send![&application, finishLaunching];

            // AppKit places windows by their BOTTOM-left corner, measured up
            // from the bottom of the primary display, so the top-left position
            // is converted through that display's height.
            let screens: Retained<AnyObject> = msg_send![class!(NSScreen), screens];
            let primary: Retained<AnyObject> = msg_send![&screens, firstObject];
            let primary_frame: NSRect = msg_send![&primary, frame];
            let frame = NSRect::new(
                NSPoint::new(
                    TOP_LEFT.0,
                    primary_frame.size.height - TOP_LEFT.1 - SIDE as f64,
                ),
                NSSize::new(SIDE as f64, SIDE as f64),
            );
            let window_class: &AnyClass = class!(NSWindow);
            let allocated: Allocated<AnyObject> = msg_send![window_class, alloc];
            // Borderless, so the window's whole frame is the pattern: a title
            // bar would occupy the top rows the test asks for.
            let window: Retained<AnyObject> = msg_send![
                allocated,
                initWithContentRect: frame,
                styleMask: 0usize,
                backing: 2usize,
                defer: false
            ];
            let _: () = msg_send![&window, setReleasedWhenClosed: false];
            let _: () = msg_send![&window, setHasShadow: false];
            let _: () = msg_send![&window, setOpaque: true];
            // A click meant for whatever is beneath goes there instead.
            let _: () = msg_send![&window, setIgnoresMouseEvents: true];

            let view: Retained<AnyObject> = msg_send![&window, contentView];
            let _: () = msg_send![&view, setWantsLayer: true];
            let layer: Retained<AnyObject> = msg_send![&view, layer];
            let contents: *const AnyObject = (&*image as *const CGImage).cast();
            let _: () = msg_send![&layer, setContents: contents];
            // Nearest, so a 2x display shows each point as a uniform block
            // rather than blending neighbouring rows into values between them.
            let nearest = NSString::from_str("nearest");
            let _: () = msg_send![&layer, setMagnificationFilter: &*nearest];
            let _: () = msg_send![&layer, setMinificationFilter: &*nearest];

            // Behind everything: ordered in, so the window server keeps its
            // contents and the window list reports it, without covering
            // anything the person is looking at.
            let _: () = msg_send![&window, orderBack: None::<&AnyObject>];

            let number: isize = msg_send![&window, windowNumber];
            println!("window {number}");
            let _ = std::io::stdout().flush();

            // Deliver AppKit's events so the window is drawn and stays
            // responsive, checking for a command between them. The overall cap
            // guards against a test that dies without closing the pipe.
            let mode = NSString::from_str("kCFRunLoopDefaultMode");
            let started = Instant::now();
            while started.elapsed() < Duration::from_secs(120) {
                if let Ok(command) = received.try_recv() {
                    if command == "quit" {
                        break;
                    }
                }
                let until: Retained<AnyObject> =
                    msg_send![class!(NSDate), dateWithTimeIntervalSinceNow: 0.05f64];
                let event: Option<Retained<AnyObject>> = msg_send![
                    &application,
                    nextEventMatchingMask: u64::MAX,
                    untilDate: &*until,
                    inMode: &*mode,
                    dequeue: true
                ];
                if let Some(event) = event {
                    let _: () = msg_send![&application, sendEvent: &*event];
                }
            }
            let _: () = msg_send![&window, orderOut: None::<&AnyObject>];
        }
    }
}
