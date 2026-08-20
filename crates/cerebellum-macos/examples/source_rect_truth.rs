//! Does ScreenCaptureKit honour `sourceRect` for a single-window filter, and in
//! which coordinate space?
//!
//! WHY THIS EXISTS. Apple documents `sourceRect` as NOT REFERENCED when the
//! filter was built with `SCContentFilter(desktopIndependentWindow:)`. Measured
//! on macOS 26, that is WRONG: the rect is honoured, and it crops. Getting
//! there took four failed instruments, each worth naming because each looked
//! conclusive:
//!
//!  1. ASSERTING THE OUTPUT SIZE. `setWidth`/`setHeight` are applied whether or
//!     not a rect is set, so an ignored rect still yields the requested
//!     dimensions -- a squashed thumbnail of the whole window.
//!  2. COMPARING TWO CAPTURES OF A LIVE WINDOW. An animating window differs
//!     whether or not the rect applies; a still one matches whether or not it
//!     does. Unsound in both directions.
//!  3. A WHOLE-WINDOW RECT. Honoured and ignored produce the same image, so it
//!     cannot discriminate -- the size trap wearing different clothes.
//!  4. BYTE EQUALITY AGAINST A CROP WE COMPUTE. The capture path resamples, so
//!     the correct answer still differs by about one unit per channel. Exact
//!     comparison reported "matches nothing" three times while the rect was
//!     being honoured all along.
//!
//! What works is a comparison the wrong answer cannot produce and resampling
//! cannot blur: capture HALF the window, then ask which row of the full capture
//! the last output row resembles. A crop ends at the halfway row; a scaled whole
//! window ends at the last row. Those are far apart, so the verdict survives
//! filtering, rounding and a cursor blinking somewhere.
//!
//! ```sh
//! cargo run -p cerebellum-macos --example source_rect_truth
//! ```

#[cfg(not(target_os = "macos"))]
fn main() {
    println!(
        "this probe measures macOS ScreenCaptureKit behaviour and has nothing to measure here"
    );
}

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::{
        capture_window, enumerate_windows, screen_is_locked, CaptureSourceRect,
    };
    use std::time::Duration;

    if screen_is_locked() == Some(true) {
        println!(
            "SKIPPED: the screen is locked, so window pixels are not readable and any result \
             here would describe the lock rather than the framework."
        );
        return;
    }

    const TIMEOUT: Duration = Duration::from_secs(10);

    let windows = match enumerate_windows(TIMEOUT) {
        Ok(windows) => windows,
        Err(error) => {
            println!("SKIPPED: the window list could not be read ({error:?})");
            return;
        }
    };
    let Some(window) = windows
        .iter()
        .find(|w| w.on_screen && w.width >= 256.0 && w.height >= 256.0)
    else {
        println!("SKIPPED: no on-screen window is at least 256x256");
        return;
    };
    println!(
        "window {} ({}x{}) at ({}, {}) owner={:?}",
        window.window_id,
        window.width as u32,
        window.height as u32,
        window.x,
        window.y,
        window.owner_bundle_identifier
    );

    let full = match capture_window(window.window_id, TIMEOUT, None) {
        Ok(full) => full,
        Err(error) => {
            println!("SKIPPED: the full capture failed ({error:?})");
            return;
        }
    };
    let (fw, fh) = (full.width as usize, full.height as usize);

    let half = match capture_window(
        window.window_id,
        TIMEOUT,
        Some(CaptureSourceRect {
            x: 0.0,
            y: 0.0,
            width: window.width,
            height: window.height / 2.0,
        }),
    ) {
        Ok(half) => half,
        Err(error) => {
            println!("SKIPPED: the half-window capture failed ({error:?})");
            return;
        }
    };
    let (gw, gh) = (half.width as usize, half.height as usize);
    println!("full {fw}x{fh}, half-rect output {gw}x{gh}");

    fn row(src: &[u8], width: usize, y: usize) -> &[u8] {
        &src[y * width * 4..(y + 1) * width * 4]
    }
    let distance = |a: &[u8], b: &[u8]| -> u64 {
        a.iter()
            .zip(b)
            .map(|(x, y)| u64::from(x.abs_diff(*y)))
            .sum()
    };

    let last_output_row = row(&half.bgra, gw, gh - 1);
    let to_crop_end = distance(last_output_row, row(&full.bgra, fw, gh - 1));
    let to_window_end = distance(last_output_row, row(&full.bgra, fw, fh - 1));

    println!(
        "  last output row vs full row {} (a crop would end here):   {to_crop_end}",
        gh - 1
    );
    println!(
        "  last output row vs full row {} (a scale would end here): {to_window_end}",
        fh - 1
    );

    if to_crop_end == to_window_end {
        println!(
            "VERDICT: none -- both candidates are equidistant, which means this window's \
             content cannot discriminate them. Try another window."
        );
    } else if to_crop_end < to_window_end {
        println!(
            "VERDICT: HONOURED. sourceRect crops, in window-local coordinates, top-left origin."
        );
    } else {
        println!(
            "VERDICT: NOT HONOURED. The output is the whole window scaled to the requested size."
        );
    }
}
