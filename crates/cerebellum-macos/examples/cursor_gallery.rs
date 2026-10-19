//! Offscreen gallery of the agent cursor picture. It draws every badge state
//! into PNG files and never shows a window, takes focus, or reads the screen,
//! so it is safe to run on a desk that is in use.
//!
//! Usage: cargo run -p cerebellum-macos --example cursor_gallery -- [output-dir] [avatar.rgba]
//! The default output directory is `cursor-gallery` under the system temp dir.
//! `avatar.rgba` is an optional raw 64x64 RGBA raster, such as a real agent
//! avatar as the module renders it; without one a stand-in pattern is drawn.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("SKIPPED: the cursor picture is drawn with AppKit, which is macOS-only");
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use cerebellum_macos::{render_cursor_gallery_png, GalleryShot, OverlayGesture, AVATAR_PIXELS};

    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::temp_dir().join("cursor-gallery"));
    std::fs::create_dir_all(&dir)?;
    let avatar = match args.next() {
        Some(path) => {
            let pixels = std::fs::read(&path)?;
            if pixels.len() != AVATAR_PIXELS * AVATAR_PIXELS * 4 {
                return Err(
                    format!("{path}: not a {AVATAR_PIXELS}x{AVATAR_PIXELS} RGBA raster").into(),
                );
            }
            pixels
        }
        None => sample_avatar(),
    };

    // A sidebar-like row the agent presses, a text field it types into, and a
    // read with no element. The red cross in each picture marks the exact
    // requested point; the pointer's tip should sit on its centre.
    let row = [24.0, 40.0, 200.0, 28.0];
    let field = [24.0, 40.0, 300.0, 30.0];
    // Violet and teal, two of the module's accent colours.
    let violet = [0.427, 0.290, 1.000];
    let teal = [0.000, 0.537, 0.482];
    let shot = |gesture, label, point, target, scale| GalleryShot {
        gesture,
        label,
        initial: 'M',
        accent: violet,
        avatar_rgba: None,
        dark: false,
        size: [380.0, 150.0],
        point,
        target,
        scale,
        entry_ms: None,
        reduce_motion: false,
    };
    // Stills along a first appearance (520 ms): the avatar alone and large on
    // the target, then shrinking onto its place as the pointer comes in, and
    // the Reduce Motion version, a plain fade of the resting badge.
    let pressing = Some("Pressing 07 Prompt surface");
    let mut scenes = Vec::new();
    for (name, ms, reduce_motion) in [
        ("entry-060ms", 60.0, false),
        ("entry-200ms", 200.0, false),
        ("entry-330ms", 330.0, false),
        ("entry-450ms", 450.0, false),
        ("entry-reduced-150ms", 150.0, true),
    ] {
        scenes.push((
            name,
            GalleryShot {
                entry_ms: Some(ms),
                reduce_motion,
                ..shot(OverlayGesture::Press, pressing, [180.0, 75.0], None, 1.0)
            },
        ));
    }
    scenes.extend([
        // The badge resting while its agent works: full opacity, no label.
        (
            "rest-working",
            shot(OverlayGesture::Read, None, [180.0, 60.0], None, 1.0),
        ),
        // Mid-settle after landing: a 4% swell about the tip.
        (
            "read-settle",
            shot(OverlayGesture::Read, None, [180.0, 60.0], None, 1.04),
        ),
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
        // Mid-tap: the pointer dips to 0.9 about its tip.
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
            GalleryShot {
                accent: teal,
                ..shot(
                    OverlayGesture::Type,
                    Some("Typing in Message"),
                    [174.0, 55.0],
                    Some(field),
                    1.0,
                )
            },
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
                [345.0, 54.0],
                Some([315.0, 40.0, 50.0, 28.0]),
                1.0,
            ),
        ),
    ]);
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

/// A stand-in avatar: an opaque RGBA square with a diagonal blend, at the size
/// the module renders avatars. The chip clips it round.
#[cfg(target_os = "macos")]
fn sample_avatar() -> Vec<u8> {
    let side = cerebellum_macos::AVATAR_PIXELS;
    let mut pixels = Vec::with_capacity(side * side * 4);
    for y in 0..side {
        for x in 0..side {
            let t = (x + y) as f64 / (2 * side - 2) as f64;
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
