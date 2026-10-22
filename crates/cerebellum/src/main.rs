//! ck-cerebellum binary entry point.
//!
//! The library (`lib.rs`) owns all module logic; this file is the thin OS entry
//! point that delegates to [`cerebellum::run_entry`] on the tokio runtime.

/// What this binary was built from, bound at compile time by `build.rs`.
///
/// Answered before anything else so it works on a binary that cannot start:
/// staging asks the bytes it is about to publish what they are, and a binary
/// that must first connect to a daemon could not answer during staging.
fn print_version() {
    println!(
        "ck-cerebellum ({}) tree={}",
        env!("CEREBELLUM_BUILD_REV"),
        env!("CEREBELLUM_BUILD_TREE")
    );
}

fn main() -> Result<(), cerebellum::ModuleError> {
    if std::env::args().skip(1).any(|arg| arg == "--version") {
        print_version();
        return Ok(());
    }
    if std::env::args().skip(1).any(|arg| arg == "--agent-cursor") {
        agent_cursor();
        return Ok(());
    }
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("the module runtime can be constructed")
        .block_on(cerebellum::run_entry())
}

#[cfg(not(target_os = "macos"))]
fn agent_cursor() {}

#[cfg(target_os = "macos")]
fn agent_cursor() {
    use cerebellum_computer::cursor::{
        accents, pill_colour, CursorKind, CursorLine, MAX_CURSOR_LINE,
    };
    use std::io::{BufRead, Read};
    // The module renders avatars at one size and the helper draws exactly that
    // size; a mismatch would silently drop every avatar.
    const _: () = assert!(
        cerebellum_computer::cursor::AVATAR_SIZE as usize == cerebellum_macos::AVATAR_PIXELS
    );
    let (sender, receiver) = std::sync::mpsc::sync_channel(32);
    std::thread::spawn(move || {
        let input = std::io::stdin();
        let mut input = input.lock();
        loop {
            let mut line = Vec::new();
            if !matches!(
                input
                    .by_ref()
                    .take((MAX_CURSOR_LINE + 1) as u64)
                    .read_until(b'\n', &mut line),
                Ok(1..)
            ) || line.len() > MAX_CURSOR_LINE
            {
                break;
            }
            let Ok(line) = serde_json::from_slice::<CursorLine>(&line) else {
                continue;
            };
            if !line.valid() {
                continue;
            }
            let message = match line {
                // A hide is waited for rather than dropped on a full queue: a
                // lost picture is cosmetic, but a lost hide leaves a finished
                // agent's badge on screen until it idles out. Only this reader
                // thread waits; the main thread keeps draining the queue.
                CursorLine::Hide(hide) => {
                    if sender
                        .send(cerebellum_macos::OverlayMessage::Hide { agent: hide.agent })
                        .is_err()
                    {
                        break;
                    }
                    continue;
                }
                // Dropped on a full queue, as a picture is. That loses nothing
                // lasting: each report carries the element's total offset since
                // the badge's latest event, not a step, so the next report
                // puts the badge in the right place anyway.
                CursorLine::Follow(follow) => cerebellum_macos::OverlayMessage::Follow {
                    agent: follow.agent,
                    serial: follow.serial,
                    offset: follow.offset,
                },
                CursorLine::Picture(event) => {
                    // The agent's colours come from its avatar; until that
                    // colour is known they are the neutral ones. The pill
                    // under the white label text is darkened as far as the
                    // text needs to stay readable.
                    let colours = accents(event.avatar_tint);
                    let pair = |accent: [f64; 3]| cerebellum_macos::OverlayColours {
                        accent,
                        pill: pill_colour(accent),
                    };
                    cerebellum_macos::OverlayMessage::Show(Box::new(
                        cerebellum_macos::OverlayEvent {
                            accent: cerebellum_macos::OverlayAccent {
                                light: pair(colours.light),
                                dark: pair(colours.dark),
                            },
                            accent_known: event.avatar_tint.is_some(),
                            agent: event.agent,
                            initial: event.initial,
                            to: event.to,
                            target: event.target,
                            resting: event.resting,
                            label: event.label,
                            gesture: match event.kind {
                                CursorKind::Press => cerebellum_macos::OverlayGesture::Press,
                                CursorKind::Write | CursorKind::Type | CursorKind::Keys => {
                                    cerebellum_macos::OverlayGesture::Type
                                }
                                CursorKind::Reading => cerebellum_macos::OverlayGesture::Read,
                            },
                            serial: event.serial,
                            avatar_rgba: event.avatar_rgba,
                            avatar_update: event.avatar_update,
                            // The module's chosen motion, passed through as it is.
                            motion: cerebellum_macos::PictureTiming {
                                entry: event.motion.style
                                    == cerebellum_computer::cursor::MotionStyle::Entry,
                                duration_ms: event.motion.duration_ms,
                                reduce_motion: event.motion.reduce_motion,
                            },
                        },
                    ))
                }
                // This helper does not draw the background-mode preview yet,
                // so its lines are read and dropped.
                CursorLine::Preview(_) | CursorLine::Frame(_) | CursorLine::PreviewMotion(_) => {
                    continue
                }
            };
            let _ = sender.try_send(message);
        }
    });
    cerebellum_macos::run_agent_cursor(
        receiver,
        cerebellum_macos::CursorMotion {
            duration_ms: cerebellum_computer::cursor::duration_ms,
            position: cerebellum_computer::cursor::position,
            settle_scale: cerebellum_computer::cursor::settle_scale,
            fade_alpha: cerebellum_computer::cursor::fade_alpha,
        },
    );
}
