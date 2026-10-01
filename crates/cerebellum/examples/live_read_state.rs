//! Read a running application's state the way `computer.read_state` does, and
//! report what the tree reaches: its size, the message composer, and any sheet
//! or dialog attached to a window (a file panel opened from a menu, for
//! example).
//!
//! The application is left exactly where it is. Nothing here fronts, focuses,
//! presses or writes: the read goes through the application's accessibility
//! tree, which answers for a backgrounded application too, so the person's
//! own windows stay in front throughout.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example live_read_state -- [bundle-identity]
//! ```
//!
//! Without an argument it reads Discord if it is running, and otherwise the
//! first running application of a short list. It prints `UNMEASURABLE` and
//! exits non-zero when the screen is locked, because a locked session hides
//! windows from the accessibility tree and a short tree would say nothing
//! about the reader.

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe reads macOS accessibility and has nothing to run here");
}

#[cfg(target_os = "macos")]
fn main() {
    std::process::exit(macos_probe::run());
}

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::time::{Duration, Instant};

    use cerebellum_computer::app_state::native::MacAppStateSource;
    use cerebellum_computer::app_state::render::{
        render_state, StateHeader, StateRequest, Truncation, Zoom,
    };
    use cerebellum_computer::app_state::session::AppStateSessions;
    use cerebellum_computer::app_state::source::{AppStateSource, ReadBounds};
    use cerebellum_computer::platform::native::resolve_target;
    use cerebellum_computer::platform::TargetResolution;

    /// Applications tried in order when none is named. Discord first: it is
    /// the Electron application whose tree this reader was built to reach.
    const CANDIDATES: [&str; 5] = [
        "com.hnc.Discord",
        "com.openai.codex",
        "com.apple.TextEdit",
        "com.apple.Notes",
        "com.apple.finder",
    ];

    pub fn run() -> i32 {
        if cerebellum_macos::screen_is_locked() == Some(true) {
            println!(
                "UNMEASURABLE: the screen is locked, so windows are hidden from the \
                 accessibility tree and a read would not show what the reader reaches"
            );
            return 2;
        }
        if !cerebellum_macos::accessibility_is_permitted() {
            println!("UNMEASURABLE: this process may not read accessibility trees");
            return 2;
        }
        let named = std::env::args().nth(1);
        let candidates: Vec<String> = match &named {
            Some(bundle) => vec![bundle.clone()],
            None => CANDIDATES.iter().map(ToString::to_string).collect(),
        };
        let resolved = candidates.iter().find_map(|bundle| {
            match resolve_target(bundle, Duration::from_secs(3)) {
                TargetResolution::Resolved(grant) => Some(grant),
                _ => None,
            }
        });
        let Some(grant) = resolved else {
            println!("FAILED: none of {candidates:?} is running as exactly one process");
            return 1;
        };
        let frontmost_before = cerebellum_macos::focused_application_pid().ok();

        let started = Instant::now();
        let raw = match MacAppStateSource.read_app_state(&grant, ReadBounds::default()) {
            Ok(raw) => raw,
            Err(error) => {
                println!(
                    "FAILED: {} could not be read: {}",
                    grant.bundle_identity,
                    error.as_str()
                );
                return 1;
            }
        };
        let elapsed = started.elapsed();
        let sessions = AppStateSessions::new();
        let observed = sessions.observe("live-probe", &grant, &raw);
        // Every top-level element in full, as zooming into each one prints
        // it, so the probe sees the whole tree rather than the outline.
        let mut tree = String::new();
        let mut truncation: Option<Truncation> = None;
        for root in observed.roots.iter().filter_map(|root| root.element_id.as_deref()) {
            let rendered = render_state(
                &StateHeader {
                    app_name: &grant.bundle_identity,
                    focused_element_id: None,
                },
                &observed.roots,
                &StateRequest {
                    zoom: Some(Zoom::Element(root)),
                    ..Default::default()
                },
            );
            if let Some((_, body)) = rendered.text.split_once('\n') {
                tree.push_str(body);
            }
            truncation = truncation.or(rendered.truncation);
        }
        struct Rendered {
            tree: String,
            truncation: Option<Truncation>,
        }
        let rendered = Rendered { tree, truncation };
        let lines: Vec<&str> = rendered.tree.lines().collect();

        println!("application: {} (pid {})", grant.bundle_identity, grant.pid);
        println!(
            "tree: {} lines, {} bytes, read in {} ms, unreadable subtrees {}, read bound reached {}",
            lines.len(),
            rendered.tree.len(),
            elapsed.as_millis(),
            raw.unreadable_subtrees,
            raw.read_bound_reached
        );
        println!("truncation: {:?}", rendered.truncation);
        println!(
            "focused element: {}",
            observed.focused_element_id.as_deref().unwrap_or("(none)")
        );
        let windows = lines
            .iter()
            .filter(|line| !line.starts_with(' ') && line.contains(" window "))
            .count();
        println!("top-level windows: {windows}");

        let composer = lines.iter().find(|line| {
            (line.contains(" text area ") || line.contains(" text field "))
                && line.contains("settable")
        });
        match composer {
            Some(line) => println!("composer: {}", line.trim()),
            None => println!("composer: (no settable text element in the tree)"),
        }

        let sheets: Vec<(usize, &str)> = lines
            .iter()
            .enumerate()
            .filter(|(_, line)| line.contains(" sheet ") || line.contains(" dialog "))
            .map(|(index, line)| (index, *line))
            .collect();
        if sheets.is_empty() {
            println!(
                "attached sheets: none open. Open a sheet or file panel from the \
                 application's own menu and run again to see it attached under its window."
            );
        }
        for (index, sheet) in &sheets {
            let depth = sheet.len() - sheet.trim_start().len();
            println!("attached sheet: {}", sheet.trim());
            for line in lines[index + 1..]
                .iter()
                .take_while(|line| line.len() - line.trim_start().len() > depth)
                .filter(|line| line.contains(" text field ") || line.contains(" button "))
                .take(8)
            {
                println!("  under it: {}", line.trim());
            }
        }

        let frontmost_after = cerebellum_macos::focused_application_pid().ok();
        if frontmost_before != frontmost_after {
            println!(
                "NOTE: the frontmost application changed during the read ({frontmost_before:?} \
                 -> {frontmost_after:?}); the read fronts nothing, so something else moved it"
            );
        }
        println!("PASS: the tree was read without fronting the application");
        0
    }
}
