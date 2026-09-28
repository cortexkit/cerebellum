//! THE MEASUREMENT: does a keystroke land in a background web-content app, and
//! which posting route delivers it?
//!
//! Web-content apps (browsers and browser-based desktop apps) drop keystrokes
//! posted through the public per-process call when they are not frontmost, and
//! writing their text field directly corrupts the editor. A private posting
//! route reaches them, and on recent systems that route wants an authentication
//! object attached to each event. This probe measures three routes against one
//! background target and reports which delivers:
//!
//!   1. the public per-process post (the control; expected NOT to deliver),
//!   2. the private post with no authentication object,
//!   3. the private post with the authentication object attached.
//!
//! The operator focuses the target's text box first. This probe never fronts
//! the target and never focuses it: a pass may only mean true background
//! delivery, so the frontmost app is sampled throughout and a route's result is
//! discarded if the target ever becomes frontmost while it runs.
//!
//! It reads back both the focused element's value and its descendant static
//! texts, because a web-content app puts typed text in child nodes rather than
//! on the field itself. It clears the field afterward with whichever route
//! delivered, and exits non-zero if the authentication route did not deliver.
//!
//! Not run in CI: it needs a desk with the target focused. The pure decision
//! rules below carry host-neutral tests so they are checked everywhere.

/// A short delivery marker built from a seed: letters only, no spaces, so the
/// editor cannot transform it into punctuation and nothing can split it on
/// whitespace during read-back.
///
/// The pure rules are compiled where the probe runs and wherever tests build,
/// so they are checked on every host without being dead code elsewhere.
#[cfg(any(target_os = "macos", test))]
fn marker(seed: u64) -> String {
    let mut value = seed;
    let mut text = String::from("ckprobe");
    for _ in 0..6 {
        text.push((b'a' + (value % 26) as u8) as char);
        value /= 26;
    }
    text
}

/// The distinct frontmost pids seen during a sample window, in the order they
/// first appeared. `None` samples (no readable frontmost app) are dropped.
#[cfg(any(target_os = "macos", test))]
fn summarize_frontmost(samples: &[Option<i32>]) -> Vec<i32> {
    let mut seen = Vec::new();
    for pid in samples.iter().flatten() {
        if !seen.contains(pid) {
            seen.push(*pid);
        }
    }
    seen
}

/// Whether the target became frontmost at any point during the samples.
///
/// A route's result is only meaningful while the target stays in the
/// background: if it was ever frontmost, the keystroke may have reached a
/// FOCUSED app, so the result must be discarded rather than counted.
#[cfg(any(target_os = "macos", test))]
fn target_became_frontmost(target: i32, samples: &[Option<i32>]) -> bool {
    samples.contains(&Some(target))
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this probe measures macOS background keystroke delivery");
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    /// The public per-process post.
    PublicPost,
    /// The private post without an authentication object.
    PrivatePlain,
    /// The private post with an authentication object attached.
    PrivateAuth,
}

#[cfg(target_os = "macos")]
impl Method {
    fn label(self) -> &'static str {
        match self {
            Method::PublicPost => "public CGEventPostToPid",
            Method::PrivatePlain => "private post, no auth message",
            Method::PrivateAuth => "private post, with auth message",
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use cerebellum_macos::{keyboard_auth_available, screen_is_locked, skylight_available};

    // The screen must be unlocked, or nothing can be measured.
    if screen_is_locked() == Some(true) {
        println!("UNMEASURABLE: the screen is locked");
        std::process::exit(2);
    }

    let bundle_id = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "com.hnc.Discord".to_string());

    let Some(pid) = pid_for_bundle(&bundle_id) else {
        println!("UNMEASURABLE: no running application with bundle id {bundle_id}");
        std::process::exit(2);
    };
    println!("target {bundle_id} pid: {pid}");

    // The operator must have focused the text box. If the app reports no
    // focused element, there is nowhere to measure delivery.
    match cerebellum_macos::focused_element(pid as u32) {
        Ok(Some(_)) => {}
        Ok(None) => {
            println!("UNMEASURABLE: {bundle_id} reports no focused element; focus its text box");
            std::process::exit(2);
        }
        Err(error) => {
            println!("UNMEASURABLE: could not read {bundle_id}'s focused element: {error:?}");
            std::process::exit(2);
        }
    }

    println!("private posting available:      {}", skylight_available());
    println!(
        "keyboard auth message available: {}",
        keyboard_auth_available()
    );
    println!();

    let methods = [
        Method::PublicPost,
        Method::PrivatePlain,
        Method::PrivateAuth,
    ];
    let mut delivering_method: Option<Method> = None;
    let mut auth_delivered = false;

    for (index, method) in methods.into_iter().enumerate() {
        let marker = marker(index as u64);

        // Sample the frontmost app for the whole window this route runs in, so
        // a focus change mid-post cannot slip between two endpoint readings.
        let stop = Arc::new(AtomicBool::new(false));
        let watcher_stop = Arc::clone(&stop);
        let watcher = thread::spawn(move || {
            let mut samples = Vec::new();
            while !watcher_stop.load(Ordering::Relaxed) {
                samples.push(cerebellum_macos::frontmost_process_id());
                thread::sleep(Duration::from_millis(100));
            }
            samples
        });

        post_marker(method, pid, &marker);
        // Let the target's editor settle before reading it back.
        thread::sleep(Duration::from_millis(600));

        stop.store(true, Ordering::Relaxed);
        let samples = watcher.join().unwrap_or_default();
        let timeline = summarize_frontmost(&samples);
        let discarded = target_became_frontmost(pid, &samples);

        let value = cerebellum_macos::focused_element(pid as u32)
            .ok()
            .flatten()
            .and_then(|element| {
                cerebellum_macos::element_text_value(&element)
                    .ok()
                    .flatten()
            });
        let child_texts = focused_subtree_texts(pid as u32);

        let in_value = value.as_deref().is_some_and(|text| text.contains(&marker));
        let in_children = child_texts.iter().any(|text| text.contains(&marker));
        let delivered = !discarded && (in_value || in_children);

        println!("route: {}", method.label());
        println!("  marker posted:            {marker}");
        println!("  frontmost timeline:       {timeline:?}");
        println!("  discarded (target fronted): {discarded}");
        println!("  focused value:            {value:?}");
        println!("  marker in value:          {in_value}");
        println!("  marker in child texts:    {in_children}");
        println!("  DELIVERED:                {delivered}");
        println!();

        if delivered && delivering_method.is_none() {
            delivering_method = Some(method);
        }
        if method == Method::PrivateAuth {
            auth_delivered = delivered;
        }
    }

    // Do not leave a draft behind: clear the field with whatever delivered.
    if let Some(method) = delivering_method {
        clear_field(method, pid);
        thread::sleep(Duration::from_millis(400));
        let final_value = cerebellum_macos::focused_element(pid as u32)
            .ok()
            .flatten()
            .and_then(|element| {
                cerebellum_macos::element_text_value(&element)
                    .ok()
                    .flatten()
            });
        println!(
            "cleared with {}; final value: {final_value:?}",
            method.label()
        );
    } else {
        println!("no route delivered; nothing to clear");
    }

    if !auth_delivered {
        eprintln!("VERDICT: the authentication route did NOT deliver in the background");
        std::process::exit(1);
    }
    println!("VERDICT: the authentication route delivered in the background");
}

/// Post the marker string through one route.
#[cfg(target_os = "macos")]
fn post_marker(method: Method, pid: i32, marker: &str) {
    use std::thread::sleep;
    use std::time::Duration;

    use cerebellum_macos::{post_event_to_pid, post_key_to_pid, text_input_events, OwnedKeyEvent};

    match method {
        Method::PublicPost => {
            for event in text_input_events(marker).unwrap_or_default() {
                let _ = post_event_to_pid(pid, &event);
                sleep(Duration::from_millis(20));
            }
        }
        Method::PrivatePlain | Method::PrivateAuth => {
            let attach_auth = method == Method::PrivateAuth;
            for character in marker.chars() {
                let event = OwnedKeyEvent::for_character(character);
                let _ = post_key_to_pid(pid, &event, attach_auth);
                sleep(Duration::from_millis(20));
            }
        }
    }
}

/// Select all and delete, through the route that delivered the marker.
#[cfg(target_os = "macos")]
fn clear_field(method: Method, pid: i32) {
    use cerebellum_macos::{
        key_combination_events, post_event_to_pid, post_key_to_pid, KeyModifiers, OwnedKeyEvent,
        VirtualKey,
    };

    let select_all = KeyModifiers {
        command: true,
        ..Default::default()
    };
    match method {
        Method::PublicPost => {
            if let Ok(events) = key_combination_events(VirtualKey::A, select_all) {
                for event in events {
                    let _ = post_event_to_pid(pid, &event);
                }
            }
            if let Ok(events) = key_combination_events(VirtualKey::Backspace, KeyModifiers::NONE) {
                for event in events {
                    let _ = post_event_to_pid(pid, &event);
                }
            }
        }
        Method::PrivatePlain | Method::PrivateAuth => {
            let attach_auth = method == Method::PrivateAuth;
            let select = OwnedKeyEvent::for_key_code(VirtualKey::A.key_code(), select_all);
            let _ = post_key_to_pid(pid, &select, attach_auth);
            let delete =
                OwnedKeyEvent::for_key_code(VirtualKey::Backspace.key_code(), KeyModifiers::NONE);
            let _ = post_key_to_pid(pid, &delete, attach_auth);
        }
    }
}

/// Every text value under the focused element's subtree.
///
/// A web-content app places typed text in child nodes rather than on the
/// focused field itself, so the read gathers the focused node's own text and
/// its descendants' text together.
#[cfg(target_os = "macos")]
fn focused_subtree_texts(pid: u32) -> Vec<String> {
    use std::time::Duration;

    use cerebellum_macos::{read_app_state, AxAppStateBounds, AxStateElement, AxStateValue};

    fn find_focused(node: &AxStateElement) -> Option<&AxStateElement> {
        if node.focused {
            return Some(node);
        }
        node.children.iter().find_map(find_focused)
    }

    fn collect(node: &AxStateElement, out: &mut Vec<String>) {
        if let AxStateValue::Text(text) = &node.value {
            out.push(text.clone());
        }
        for child in &node.children {
            collect(child, out);
        }
    }

    let bounds = AxAppStateBounds {
        max_elements: 4_000,
        max_depth: 40,
        timeout: Duration::from_secs(3),
    };
    let Ok(state) = read_app_state(pid, bounds) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for root in &state.roots {
        if let Some(focused) = find_focused(root) {
            collect(focused, &mut out);
            return out;
        }
    }
    out
}

/// The unix pid of the running application with `bundle_id`, or `None`.
///
/// Read through System Events, which the probe already relies on the desk
/// providing. A probe-only reading: production resolves targets differently.
#[cfg(target_os = "macos")]
fn pid_for_bundle(bundle_id: &str) -> Option<i32> {
    let script = format!(
        "tell application \"System Events\" to get unix id of (first process whose bundle identifier is \"{bundle_id}\")"
    );
    let output = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", &script])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8_lossy(&output.stdout).trim().parse().ok()
}

#[cfg(test)]
mod tests {
    use super::{marker, summarize_frontmost, target_became_frontmost};

    #[test]
    fn a_marker_is_letters_only_and_carries_no_spaces() {
        for seed in 0..200u64 {
            let marker = marker(seed);
            assert!(!marker.is_empty());
            assert!(
                marker.chars().all(|c| c.is_ascii_alphabetic()),
                "marker {marker:?} for seed {seed} has a non-letter"
            );
        }
    }

    #[test]
    fn distinct_seeds_give_distinct_markers() {
        // Each route posts a different marker so read-back cannot confuse them.
        let a = marker(0);
        let b = marker(1);
        let c = marker(2);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    #[test]
    fn the_frontmost_summary_dedups_in_first_seen_order_and_drops_gaps() {
        let samples = [Some(10), None, Some(10), Some(20), None, Some(10)];
        assert_eq!(summarize_frontmost(&samples), vec![10, 20]);
    }

    #[test]
    fn a_run_where_the_target_never_fronted_is_kept() {
        let samples = [Some(10), None, Some(20), Some(10)];
        // The target (99) is absent, so its result stands.
        assert!(!target_became_frontmost(99, &samples));
    }

    #[test]
    fn a_run_where_the_target_fronted_is_discarded() {
        let samples = [Some(10), None, Some(99), Some(10)];
        // The target (99) appeared, so the result cannot be trusted. Inverting
        // the rule to ignore the target would wrongly keep this run.
        assert!(target_became_frontmost(99, &samples));
    }
}
