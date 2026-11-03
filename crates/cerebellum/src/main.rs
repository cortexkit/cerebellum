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
    let version = format!(
        "ck-cerebellum ({}) tree={}",
        env!("CEREBELLUM_BUILD_REV"),
        env!("CEREBELLUM_BUILD_TREE")
    );
    println!("{version}");
}

fn print_manifest() {
    let manifest = cerebellum::manifest_for_inspection();
    println!("{manifest}");
}

fn main() -> Result<(), cerebellum::ModuleError> {
    if std::env::args().skip(1).any(|arg| arg == "--version") {
        print_version();
        return Ok(());
    }
    if std::env::args().skip(1).any(|arg| arg == "--manifest") {
        print_manifest();
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
        accents, pill_colour, CursorKind, CursorLine, PreviewFallback, PreviewGate, MAX_CURSOR_LINE,
    };
    use std::io::{BufRead, Read};
    // The module renders avatars at one size and the helper draws exactly that
    // size; a mismatch would silently drop every avatar.
    const _: () = assert!(
        cerebellum_computer::cursor::AVATAR_SIZE as usize == cerebellum_macos::AVATAR_PIXELS
    );
    let (sender, receiver) = std::sync::mpsc::sync_channel(32);
    std::thread::spawn(move || {
        use cerebellum_computer::pointer_query::{
            answer_prepare_request, answer_request, PrepareRequest, Request, QUERY_TIMEOUT,
        };
        // The barred cursor launch maps only its private reply pipe to fd 4.
        let Ok(mut replies) = std::fs::OpenOptions::new().write(true).open("/dev/fd/4") else {
            return;
        };
        let input = std::io::stdin();
        let mut input = input.lock();
        // Decides which preview lines are drawn: none from an older
        // generation, no frame or motion for a preview that is hidden or has
        // idled out, and no frame ever restarting a preview's idle clock.
        let mut gate = PreviewGate::default();
        // The module's chosen motion, passed through as it is.
        let timing =
            |motion: cerebellum_computer::cursor::PictureMotion| cerebellum_macos::PictureTiming {
                entry: motion.style == cerebellum_computer::cursor::MotionStyle::Entry,
                duration_ms: motion.duration_ms,
                reduce_motion: motion.reduce_motion,
            };
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
            if let Ok(prepare) = serde_json::from_slice::<PrepareRequest>(&line) {
                if !answer_prepare_request(
                    prepare,
                    || {
                        let (reply, ready) = std::sync::mpsc::sync_channel(1);
                        if sender
                            .try_send(cerebellum_macos::OverlayMessage::Ready { reply })
                            .is_err()
                        {
                            return false;
                        }
                        // The parent transport stops waiting at the call deadline.
                        // This private reader can await cold AppKit initialization
                        // without the hit test's 50 ms response cap.
                        ready.recv().is_ok()
                    },
                    &mut replies,
                ) {
                    break;
                }
                continue;
            }
            if let Ok(query) = serde_json::from_slice::<Request>(&line) {
                if !answer_request(
                    query,
                    |point| {
                        let (reply, answer) = std::sync::mpsc::sync_channel(1);
                        sender
                            .try_send(cerebellum_macos::OverlayMessage::PointerWindow {
                                point,
                                reply,
                            })
                            .ok()?;
                        answer.recv_timeout(QUERY_TIMEOUT).ok()
                    },
                    &mut replies,
                ) {
                    break;
                }
                continue;
            }
            let Ok(line) = serde_json::from_slice::<CursorLine>(&line) else {
                continue;
            };
            if !line.valid() || !gate.admit(&line, std::time::Instant::now()) {
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
                            motion: timing(event.motion),
                        },
                    ))
                }
                // Waited for rather than dropped, as a hide is: a lost preview
                // line leaves the agent with no preview, and so no badge, until
                // it moves to another window.
                CursorLine::Preview(preview) => {
                    let message = cerebellum_macos::OverlayMessage::Preview(Box::new(
                        cerebellum_macos::OverlayPreview {
                            agent: preview.preview_agent,
                            generation: preview.preview_generation,
                            slot: preview.preview_slot,
                            window: preview.preview_window,
                            app: preview.preview_app,
                            aspect: preview.preview_aspect,
                            label: preview.preview_label,
                            fallback: preview.preview_fallback.map(|fallback| match fallback {
                                PreviewFallback::Minimized => {
                                    cerebellum_macos::PreviewFallback::Minimized
                                }
                                PreviewFallback::CaptureRefused => {
                                    cerebellum_macos::PreviewFallback::CaptureRefused
                                }
                            }),
                            icon_path: preview.preview_icon_path,
                        },
                    ));
                    if sender.send(message).is_err() {
                        break;
                    }
                    continue;
                }
                // Dropped on a full queue, as a picture is: the next frame
                // shows the window anyway.
                CursorLine::Frame(frame) => {
                    let Some(jpeg) = frame.jpeg() else {
                        continue;
                    };
                    cerebellum_macos::OverlayMessage::Frame(Box::new(
                        cerebellum_macos::OverlayFrame {
                            agent: frame.frame_agent,
                            generation: frame.frame_generation,
                            window: frame.frame_window,
                            size: [frame.frame_w, frame.frame_h],
                            jpeg,
                        },
                    ))
                }
                CursorLine::PreviewMotion(motion) => {
                    cerebellum_macos::OverlayMessage::PreviewMotion(Box::new(
                        cerebellum_macos::OverlayPreviewMotion {
                            agent: motion.pmotion_agent,
                            generation: motion.pmotion_generation,
                            window: motion.pmotion_window,
                            press: motion.pmotion_kind == CursorKind::Press,
                            to: motion.pmotion_to,
                            motion: timing(motion.pmotion_motion),
                        },
                    ))
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
