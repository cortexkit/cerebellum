//! Manual desk-only pixel experiment, kept separate from the overlay loop.
//! It paints the real panels, captures their display region without explicit
//! exclusions, then makes them shareable as a positive capture control.

use super::*;
use crate::macos::{
    establish_window_server_connection, read_pixels, CaptureSourceRect, RawCapture,
};
use block2::RcBlock;
use objc2_core_foundation::{CGPoint, CGRect, CGSize};
use objc2_core_graphics::CGImage;
use objc2_foundation::{NSArray, NSError};
use objc2_screen_capture_kit::{
    SCContentFilter, SCScreenshotManager, SCShareableContent, SCStreamConfiguration,
};

// Display capture includes other apps, so it exists only in this opt-in probe.
fn capture_probe_display_region(
    region: CaptureSourceRect,
    timeout: Duration,
) -> Result<RawCapture, String> {
    establish_window_server_connection();
    let (sink, delivery) = std::sync::mpsc::channel();
    let handler = RcBlock::new(
        move |content: *mut SCShareableContent, error: *mut NSError| {
            // SAFETY: framework callback objects are valid for the callback; retain
            // the display before returning. The probe places its panels on main.
            let result = unsafe {
                if let Some(error) = error.as_ref() {
                    Err(error.localizedDescription().to_string())
                } else if let Some(content) = content.as_ref() {
                    content
                        .displays()
                        .iter()
                        .find(|d| d.displayID() == objc2_core_graphics::CGMainDisplayID())
                        .ok_or_else(|| "the main display is not shareable".to_owned())
                } else {
                    Err("no shareable content or error".to_owned())
                }
            };
            let _ = sink.send(result);
        },
    );
    unsafe { SCShareableContent::getShareableContentWithCompletionHandler(&handler) };
    let display = delivery
        .recv_timeout(timeout)
        .map_err(|_| "display enumeration timed out")??;
    // No explicit window exclusions: the experiment measures whether the
    // panels' sharing policy actually removes their pixels from a display.
    let (filter, configuration) = unsafe {
        let filter = SCContentFilter::initWithDisplay_excludingWindows(
            SCContentFilter::alloc(),
            &display,
            &NSArray::new(),
        );
        let configuration = SCStreamConfiguration::new();
        configuration.setSourceRect(CGRect::new(
            CGPoint::new(region.x, region.y),
            CGSize::new(region.width, region.height),
        ));
        configuration.setWidth(region.width as usize);
        configuration.setHeight(region.height as usize);
        configuration.setShowsCursor(false);
        (filter, configuration)
    };
    let (sink, delivery) = std::sync::mpsc::channel();
    let handler = RcBlock::new(move |image: *mut CGImage, error: *mut NSError| {
        // SAFETY: same screenshot completion contract as capture_window; copy
        // the raster while the image is alive, never retain private pixels.
        let result = unsafe {
            if let Some(error) = error.as_ref() {
                Err(error.localizedDescription().to_string())
            } else if let Some(image) = image.as_ref() {
                read_pixels(image, std::process::id())
            } else {
                Err("no captured image or error".to_owned())
            }
        };
        let _ = sink.send(result);
    });
    unsafe {
        SCScreenshotManager::captureImageWithFilter_configuration_completionHandler(
            &filter,
            &configuration,
            Some(&handler),
        );
    }
    delivery
        .recv_timeout(timeout)
        .map_err(|_| "display capture timed out".to_owned())?
}

const SIDE: f64 = 128.0;
const GAP: f64 = 64.0;
const COLOURS: [[u8; 3]; 4] = [
    [239, 17, 193],
    [23, 229, 211],
    [181, 241, 19],
    [251, 89, 31],
];

define_class!(
    #[unsafe(super(NSView))]
    #[thread_kind = MainThreadOnly]
    struct CapturePattern;
    impl CapturePattern {
        #[unsafe(method(drawRect:))]
        fn draw(&self, _dirty: NSRect) {
            for (i, [r, g, b]) in COLOURS.into_iter().enumerate() {
                srgb(f64::from(r) / 255.0, f64::from(g) / 255.0, f64::from(b) / 255.0, 1.0).setFill();
                NSBezierPath::bezierPathWithRect(rect(
                    (i % 2) as f64 * SIDE / 2.0, (i / 2) as f64 * SIDE / 2.0,
                    SIDE / 2.0, SIDE / 2.0)).fill();
            }
        }
    }
);

fn capture(mtm: MainThreadMarker, region: CaptureSourceRect) -> Result<RawCapture, String> {
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = sender.send(capture_probe_display_region(
            region,
            Duration::from_secs(10),
        ));
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

fn patches(image: &RawCapture, offset: usize) -> Result<usize, String> {
    if image.width != 320 || image.height != 128 || image.bgra.len() != 320 * 128 * 4 {
        return Err(format!(
            "unexpected display region: {}x{} ({} bytes)",
            image.width,
            image.height,
            image.bgra.len()
        ));
    }
    Ok(COLOURS
        .iter()
        .enumerate()
        .filter(|(i, rgb)| {
            // AppKit paints bottom-up; the captured raster is top-down. Test an
            // interior 5x5 patch, not an antialiased edge or a single lucky pixel.
            let x = offset + (i % 2) * 64 + 32;
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

fn capture_verdict(protected: [usize; 2], control: [usize; 2]) -> Result<(), String> {
    if control != [4, 4] {
        return Err(format!(
            "capture positive control did not see both patterns: {control:?}"
        ));
    }
    if protected != [0, 0] {
        return Err(format!("private pattern pixels leaked (preview, badge): {protected:?}; shareable control: {control:?}"));
    }
    Ok(())
}

/// Paint the actual preview and badge panels and measure their pixels through
/// ScreenCaptureKit's display filter, with no excluded-window list. Must only
/// be called by the hand-started, approved desk probe, on the main thread.
/// No raster is stored or returned. Missing permissions/capture are errors.
#[doc(hidden)]
pub fn probe_overlay_capture_exclusion() -> Result<(), String> {
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
    if frame.size.width < 400.0 || frame.size.height < 240.0 {
        return Err("display too small for the pixel probe".into());
    }
    let mut preview = PreviewWindow::new(mtm);
    let mut badge = Picture::new(mtm);
    let panels = [preview.facts().panel, badge.panel.clone()];
    let result = (|| {
        for (i, panel) in panels.iter().enumerate() {
            let local = rect(0.0, 0.0, SIDE, SIDE);
            // SAFETY: view and panel construction/manipulation stay on main.
            let view: Retained<CapturePattern> =
                unsafe { msg_send![CapturePattern::alloc(mtm), initWithFrame: local] };
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
            return Err("both pattern panels must be on screen".into());
        }
        let region = CaptureSourceRect {
            x: 48.0,
            y: 80.0,
            width: 320.0,
            height: 128.0,
        };
        let protected = capture(mtm, region)?;
        let protected_patches = [patches(&protected, 0)?, patches(&protected, 192)?];
        drop(protected);
        for panel in &panels {
            panel.setSharingType(NSWindowSharingType::ReadOnly);
        }
        commit_window_changes(mtm);
        let control = capture(mtm, region)?;
        let control_patches = [patches(&control, 0)?, patches(&control, 192)?];
        capture_verdict(protected_patches, control_patches)
    })();
    // Cleanup runs on every error path as well as success.
    crate::preview_schedule::PreviewSurface::remove(&mut preview);
    badge.remove();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_capture_rejects_either_private_pattern_and_requires_a_visible_control() {
        assert!(capture_verdict([0, 0], [4, 4]).is_ok());
        assert!(
            capture_verdict([1, 0], [4, 4]).is_err(),
            "preview pixels leaked"
        );
        assert!(
            capture_verdict([0, 1], [4, 4]).is_err(),
            "badge pixels leaked"
        );
        assert!(
            capture_verdict([0, 0], [0, 4]).is_err(),
            "preview control missing"
        );
        assert!(
            capture_verdict([0, 0], [4, 0]).is_err(),
            "badge control missing"
        );
    }

    #[test]
    fn the_pixel_detector_reads_both_panels_at_their_display_positions() {
        let mut image = RawCapture {
            width: 320,
            height: 128,
            bgra: vec![0; 320 * 128 * 4],
            owner_pid_at_capture: 0,
        };
        assert_eq!(patches(&image, 0).unwrap(), 0);
        for offset in [0, 192] {
            for (i, [r, g, b]) in COLOURS.into_iter().enumerate() {
                for y in (1 - i / 2) * 64..(2 - i / 2) * 64 {
                    for x in offset + (i % 2) * 64..offset + (i % 2 + 1) * 64 {
                        image.bgra[(y * 320 + x) * 4..(y * 320 + x) * 4 + 4]
                            .copy_from_slice(&[b, g, r, 255]);
                    }
                }
            }
        }
        assert_eq!(patches(&image, 0).unwrap(), 4);
        assert_eq!(patches(&image, 192).unwrap(), 4);
        image.bgra[(32 * 320 + 32) * 4..(32 * 320 + 32) * 4 + 3].fill(0);
        assert_eq!(patches(&image, 0).unwrap(), 3);
        assert_eq!(patches(&image, 192).unwrap(), 4);
    }
}
