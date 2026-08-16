//! What a real window costs once encoded: compression ratio and encode time.
//!
//! An example rather than a test because the numbers are the point, and a test
//! that asserted them would be asserting a property of whatever happens to be on
//! screen. Run it on an unlocked machine with capture permission.
use std::time::{Duration, Instant};

fn main() {
    if cerebellum_macos::screen_is_locked() == Some(true) {
        // Said plainly: a locked screen lists windows and refuses their
        // contents, so every capture below would fail for a reason that has
        // nothing to do with encoding.
        println!("the screen is locked, so window contents are not readable");
        return;
    }
    if !cerebellum_macos::screen_capture_is_permitted() {
        println!("screen recording is not permitted for this process");
        return;
    }
    let windows = match cerebellum_macos::enumerate_windows(Duration::from_secs(10)) {
        Ok(windows) => windows,
        Err(reason) => {
            println!("could not list windows: {reason}");
            return;
        }
    };
    let mut shown = 0;
    for window in windows.iter().filter(|w| w.on_screen && w.width >= 200.0) {
        let capture =
            match cerebellum_macos::capture_window(window.window_id, Duration::from_secs(10), None)
            {
                Ok(capture) => capture,
                Err(reason) => {
                    println!("window {}: {reason}", window.window_id);
                    continue;
                }
            };
        let started = Instant::now();
        let png = match cerebellum_macos::encode_png(&capture.bgra, capture.width, capture.height) {
            Ok(png) => png,
            Err(reason) => {
                println!("window {}: could not encode: {reason}", window.window_id);
                continue;
            }
        };
        let took = started.elapsed();
        let tokens =
            ((capture.width as f64 / 28.0).ceil() * (capture.height as f64 / 28.0).ceil()) as u64;
        println!(
            "{}x{}  raw {:.1}MB -> png {:.2}MB ({:.0}x)  {:>4}ms  {} tokens (charged {})",
            capture.width,
            capture.height,
            capture.bgra.len() as f64 / 1e6,
            png.len() as f64 / 1e6,
            capture.bgra.len() as f64 / png.len() as f64,
            took.as_millis(),
            tokens,
            tokens.min(1568),
        );
        shown += 1;
        if shown == 6 {
            break;
        }
    }
    if shown == 0 {
        println!("no window on screen was large enough to measure");
    }
}
