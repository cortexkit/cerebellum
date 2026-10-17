//! Offscreen gallery of the agent cursor picture. It draws every badge state
//! into PNG files and never shows a window, takes focus, or reads the screen,
//! so it is safe to run on a desk that is in use.
//!
//! Usage: cargo run -p cerebellum-macos --example cursor_gallery -- [output-dir]
//! The default output directory is `cursor-gallery` under the system temp dir.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("SKIPPED: the cursor picture is drawn with AppKit, which is macOS-only");
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cerebellum_macos::{render_cursor_gallery_png, GalleryShot, OverlayGesture};

    let dir = std::env::args()
        .nth(1)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("cursor-gallery"));
    std::fs::create_dir_all(&dir)?;
    let avatar = sample_avatar();

    // A sidebar-like row the agent presses, a text field it types into, and a
    // read with no element. The red cross in each picture marks the exact
    // requested point; the arrow's tip should sit on its centre.
    let row = [24.0, 40.0, 200.0, 28.0];
    let field = [24.0, 40.0, 300.0, 30.0];
    let shot = |gesture, label, point, target, scale| GalleryShot {
        gesture,
        label,
        initial: 'M',
        avatar_rgba: None,
        dark: false,
        size: [360.0, 140.0],
        point,
        target,
        scale,
    };
    let pressing = Some("Pressing 07 Prompt surface");
    let scenes = [
        (
            "press",
            shot(
                OverlayGesture::Press,
                pressing,
                [124.0, 54.0],
                Some(row),
                1.0,
            ),
        ),
        // Mid-tap: the arrow dips to 0.9 about its tip.
        (
            "press-tap",
            shot(
                OverlayGesture::Press,
                pressing,
                [124.0, 54.0],
                Some(row),
                0.9,
            ),
        ),
        (
            "type",
            shot(
                OverlayGesture::Type,
                Some("Typing in Message"),
                [174.0, 55.0],
                Some(field),
                1.0,
            ),
        ),
        // Mid-settle: a 4% swell, and no label on a read.
        (
            "read",
            shot(OverlayGesture::Read, None, [180.0, 75.0], None, 1.04),
        ),
        // Long titles are ellipsised to a fixed width.
        (
            "press-long-title",
            shot(
                OverlayGesture::Press,
                Some("Pressing Smart notes and every other long title"),
                [124.0, 54.0],
                Some(row),
                1.0,
            ),
        ),
        // Near the right edge the label moves to the side with room.
        (
            "press-right-edge",
            shot(
                OverlayGesture::Press,
                Some("Pressing Send"),
                [330.0, 54.0],
                Some([300.0, 40.0, 50.0, 28.0]),
                1.0,
            ),
        ),
    ];
    let mut written = Vec::new();
    for (name, scene) in &scenes {
        for (avatar_name, avatar) in [("avatar", Some(avatar.as_slice())), ("initial", None)] {
            for (backdrop, dark) in [("light", false), ("dark", true)] {
                let path = dir.join(format!("{name}-{avatar_name}-{backdrop}.png"));
                let pixels = render_cursor_gallery_png(
                    &GalleryShot {
                        avatar_rgba: avatar,
                        dark,
                        ..*scene
                    },
                    &path,
                )?;
                println!("{} ({}x{})", path.display(), pixels[0], pixels[1]);
                written.push(path);
            }
        }
    }
    println!("wrote {} pictures to {}", written.len(), dir.display());
    Ok(())
}

/// A stand-in avatar: a 32x32 opaque RGBA square with a diagonal blend, in
/// the format the module's avatar renderer produces. The chip clips it round.
#[cfg(target_os = "macos")]
fn sample_avatar() -> Vec<u8> {
    let mut pixels = Vec::with_capacity(32 * 32 * 4);
    for y in 0..32 {
        for x in 0..32 {
            let t = (x + y) as f64 / 62.0;
            pixels.extend_from_slice(&[
                (240.0 - 140.0 * t) as u8,
                (120.0 + 60.0 * t) as u8,
                (60.0 + 180.0 * t) as u8,
                255,
            ]);
        }
    }
    pixels
}
