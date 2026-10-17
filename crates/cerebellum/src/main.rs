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
    use cerebellum_computer::cursor::{CursorEvent, CursorKind, MAX_CURSOR_LINE};
    use std::io::{BufRead, Read};
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
            let Ok(event) = serde_json::from_slice::<CursorEvent>(&line) else {
                continue;
            };
            if !event.valid() {
                continue;
            }
            let _ = sender.try_send(cerebellum_macos::OverlayEvent {
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
            });
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
