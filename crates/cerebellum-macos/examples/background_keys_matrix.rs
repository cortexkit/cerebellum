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
//! It reads back both the message box's value and its descendant static texts,
//! because a web-content app puts typed text in child nodes rather than on the
//! field itself. After each route that delivered, it sends select-all plus one
//! Backspace through that same route, to measure whether a Command chord
//! survives per-process delivery, then empties the box with plain Backspaces.
//! A route this system does not provide is reported as not tested. It exits
//! non-zero only if the box is left non-empty, so a leftover draft is never
//! missed.
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

    // `<bundle> backspace <n>`: remove leftover probe text one key at a time
    // through the public route, which needs no modifier chord. A select-all
    // chord posted per process may lose its modifier on the way in, so this is
    // the cleanup that does not depend on it.
    if std::env::args().nth(2).as_deref() == Some("labels") {
        let Some(pid) = pid_for_bundle(&bundle_id) else {
            println!("UNMEASURABLE: no running application with bundle id {bundle_id}");
            std::process::exit(2);
        };
        for label in text_area_labels(pid as u32) {
            println!("text area: {label:?}");
        }
        return;
    }

    if std::env::args().nth(2).as_deref() == Some("explicit") {
        let Some(pid) = pid_for_bundle(&bundle_id) else {
            println!("UNMEASURABLE: no running application with bundle id {bundle_id}");
            std::process::exit(2);
        };
        if composer_texts(pid as u32).is_none() {
            println!(
                "UNMEASURABLE: no message box labelled {:?}",
                expected_box_label()
            );
            std::process::exit(2);
        }
        println!(
            "public, Command as its own key: Cmd+A {}",
            explicit_modifier_chord(pid)
        );
        let left = composer_text_len(pid as u32);
        println!("message box left with {left} character(s)");
        std::process::exit(if left == 0 { 0 } else { 1 });
    }

    if std::env::args().nth(2).as_deref() == Some("backspace") {
        let count: usize = std::env::args()
            .nth(3)
            .and_then(|n| n.parse().ok())
            .unwrap_or(0);
        let Some(pid) = pid_for_bundle(&bundle_id) else {
            println!("UNMEASURABLE: no running application with bundle id {bundle_id}");
            std::process::exit(2);
        };
        backspaces(pid, count);
        thread::sleep(Duration::from_millis(600));
        println!("after {count} backspaces: {:?}", composer_texts(pid as u32));
        return;
    }

    let Some(pid) = pid_for_bundle(&bundle_id) else {
        println!("UNMEASURABLE: no running application with bundle id {bundle_id}");
        std::process::exit(2);
    };
    println!("target {bundle_id} pid: {pid}");

    // Delivery is read back from the message box itself, found by role and
    // label. A web-content app reports NO focused element while it is in the
    // background (it keeps keyboard focus internally and exposes it only when
    // frontmost), so asking for the focused element here would refuse every
    // background run. The operator still clicks into the box beforehand, since
    // that internal focus is where the posted keys go.
    let Some((initial_value, initial_texts)) = composer_texts(pid as u32) else {
        println!("UNMEASURABLE: {bundle_id} shows no text area labelled as a message box");
        std::process::exit(2);
    };
    println!("message box before: value {initial_value:?}, texts {initial_texts:?}");

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
    let mut rows: Vec<(Method, &'static str, &'static str)> = Vec::new();

    for (index, method) in methods.into_iter().enumerate() {
        // A route this system does not provide is reported as not tested. It
        // posts nothing, so reading "not delivered" from it would be false.
        let available = match method {
            Method::PublicPost => true,
            Method::PrivatePlain => skylight_available(),
            Method::PrivateAuth => skylight_available() && keyboard_auth_available(),
        };
        if !available {
            println!(
                "route: {}\n  NOT TESTED: this system does not provide it\n",
                method.label()
            );
            rows.push((method, "not tested", "not tested"));
            continue;
        }
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
        let (value, child_texts) = composer_texts(pid as u32).unwrap_or_default();
        let in_value = value.as_deref().is_some_and(|text| text.contains(&marker));
        let in_children = child_texts.iter().any(|text| text.contains(&marker));

        // The chord test: select-all then one Backspace through this same route.
        // An honoured Command key empties the box; a dropped one removes only
        // the last letter. Run only when the marker landed, or there is
        // nothing to tell the two apart by.
        let mut chord = "not tested (marker did not land)";
        if in_value || in_children {
            clear_field(method, pid);
            thread::sleep(Duration::from_millis(600));
            let after = composer_text_len(pid as u32);
            chord = if after == 0 {
                "honoured (box emptied)"
            } else {
                "DROPPED (Command lost; only Backspace landed)"
            };
        }

        stop.store(true, Ordering::Relaxed);
        let samples = watcher.join().unwrap_or_default();
        let timeline = summarize_frontmost(&samples);
        let discarded = target_became_frontmost(pid, &samples);
        let delivered = !discarded && (in_value || in_children);

        println!("route: {}", method.label());
        println!("  marker posted:            {marker}");
        println!("  frontmost timeline:       {timeline:?}");
        println!("  discarded (target fronted): {discarded}");
        println!("  box value after typing:   {value:?}");
        println!("  DELIVERED:                {delivered}");
        println!("  Cmd+A chord:              {chord}");
        println!();
        rows.push((
            method,
            if discarded {
                "discarded"
            } else if delivered {
                "delivered"
            } else {
                "NOT delivered"
            },
            if discarded { "discarded" } else { chord },
        ));

        // Leave the box empty before the next route, with plain Backspaces
        // through the public route (no chord needed).
        let remaining = composer_text_len(pid as u32);
        if remaining > 0 {
            backspaces(pid, remaining + 3);
            thread::sleep(Duration::from_millis(600));
        }
    }

    println!("SUMMARY");
    for (method, typing, chord) in &rows {
        println!(
            "  {:34} typing: {:14} Cmd+A: {}",
            method.label(),
            typing,
            chord
        );
    }
    println!(
        "  {:34} Cmd+A: {}",
        "public, Command as its own key",
        explicit_modifier_chord(pid)
    );
    let final_len = composer_text_len(pid as u32);
    println!("message box left with {final_len} character(s)");
    if final_len > 0 {
        eprintln!("WARNING: the message box is not empty; clear it before sending anything");
        std::process::exit(1);
    }
}

/// The exact accessibility label of the message box to type into.
#[cfg(target_os = "macos")]
fn expected_box_label() -> String {
    std::env::var("CEREBELLUM_PROBE_BOX_LABEL").unwrap_or_else(|_| "Message @IceTea".to_string())
}

/// Type a marker, then send select-all the way a physical keyboard does:
/// Command down, A down, A up, Command up, each as its own event, then one
/// plain Backspace. The chord test above only marks the A events as
/// Command-held, and an app that tracks modifiers from separate modifier
/// events sees no Command at all. An emptied box means this form is honoured.
#[cfg(target_os = "macos")]
fn explicit_modifier_chord(pid: i32) -> &'static str {
    use objc2_core_graphics::{CGEvent, CGEventFlags, CGEventSource, CGEventSourceStateID};
    use std::thread::sleep;
    use std::time::Duration;

    const COMMAND_KEY: u16 = 55;
    const A_KEY: u16 = 0;

    post_marker(Method::PublicPost, pid, &marker(7));
    // Poll rather than read once: the editor updates its accessibility value
    // some time after the keys land, and a single early read reports nothing.
    if !wait_for_len(pid, |len| len > 0) {
        return "not tested (marker did not land)";
    }
    let Some(source) = CGEventSource::new(CGEventSourceStateID::HIDSystemState) else {
        return "not tested (no event source)";
    };
    let steps = [
        (COMMAND_KEY, true, CGEventFlags::MaskCommand),
        (A_KEY, true, CGEventFlags::MaskCommand),
        (A_KEY, false, CGEventFlags::MaskCommand),
        (COMMAND_KEY, false, CGEventFlags::empty()),
    ];
    for (key, down, flags) in steps {
        let Some(event) = CGEvent::new_keyboard_event(Some(&source), key, down) else {
            return "not tested (event build failed)";
        };
        CGEvent::set_flags(Some(&event), flags);
        CGEvent::post_to_pid(pid, Some(&event));
        sleep(Duration::from_millis(30));
    }
    backspaces(pid, 1);
    // An honoured chord empties the box; a dropped one leaves all but one
    // letter. Wait for the box to settle either way before judging.
    let before = marker(7).len();
    let _ = wait_for_len(pid, |len| len == 0 || len < before);
    sleep(Duration::from_millis(300));
    let verdict = if composer_text_len(pid as u32) == 0 {
        "honoured (box emptied)"
    } else {
        "DROPPED (Command lost; only Backspace landed)"
    };
    let remaining = composer_text_len(pid as u32);
    if remaining > 0 {
        backspaces(pid, remaining + 3);
        sleep(Duration::from_millis(600));
    }
    verdict
}

/// The title and description of every text area in the app, for diagnosing
/// why the exact-label match found nothing.
#[cfg(target_os = "macos")]
fn text_area_labels(pid: u32) -> Vec<(Option<String>, Option<String>)> {
    use cerebellum_macos::{read_app_state, AxAppStateBounds, AxStateElement};

    fn walk(node: &AxStateElement, out: &mut Vec<(Option<String>, Option<String>)>) {
        if node.role.as_deref() == Some("AXTextArea") {
            out.push((node.title.clone(), node.description.clone()));
        }
        for child in &node.children {
            walk(child, out);
        }
    }

    let bounds = AxAppStateBounds {
        max_elements: 4_000,
        max_depth: 40,
        timeout: std::time::Duration::from_secs(3),
    };
    let mut out = Vec::new();
    if let Ok(state) = read_app_state(pid, bounds) {
        for root in &state.roots {
            walk(root, &mut out);
        }
    }
    out
}

/// Poll the box's visible length until `done` holds, for up to three seconds.
#[cfg(target_os = "macos")]
fn wait_for_len(pid: i32, done: impl Fn(usize) -> bool) -> bool {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while std::time::Instant::now() < deadline {
        if done(composer_text_len(pid as u32)) {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(150));
    }
    false
}

/// How many visible characters the message box holds, ignoring the invisible
/// placeholder characters a web editor keeps in an empty field.
#[cfg(target_os = "macos")]
fn composer_text_len(pid: u32) -> usize {
    let (value, _) = composer_texts(pid).unwrap_or_default();
    value
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '\u{feff}')
        .count()
}

/// Post `count` plain Backspaces through the public per-process route.
#[cfg(target_os = "macos")]
fn backspaces(pid: i32, count: usize) {
    use cerebellum_macos::{key_combination_events, post_event_to_pid, KeyModifiers, VirtualKey};
    for _ in 0..count {
        if let Ok(events) = key_combination_events(VirtualKey::Backspace, KeyModifiers::NONE) {
            for event in events {
                let _ = post_event_to_pid(pid, &event);
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(15));
    }
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

/// The message box's own value and every text value in its subtree, or `None`
/// when no message box is found.
///
/// The box is the first text area whose title or description names it a
/// message box (Discord labels it "Message @<name>"). A web-content app places
/// typed text in child nodes rather than on the field itself, so the read
/// gathers the box's own value and its descendants' text separately.
#[cfg(target_os = "macos")]
fn composer_texts(pid: u32) -> Option<(Option<String>, Vec<String>)> {
    use std::time::Duration;

    use cerebellum_macos::{read_app_state, AxAppStateBounds, AxStateElement, AxStateValue};

    fn is_message_box(node: &AxStateElement) -> bool {
        // Match the box's label exactly, so the probe types only into the
        // conversation the operator named and never into whichever channel
        // happens to be open.
        let expected = expected_box_label();
        let labelled = |text: &Option<String>| text.as_deref() == Some(expected.as_str());
        node.role.as_deref() == Some("AXTextArea")
            && (labelled(&node.title) || labelled(&node.description))
    }

    fn find_box(node: &AxStateElement) -> Option<&AxStateElement> {
        if is_message_box(node) {
            return Some(node);
        }
        node.children.iter().find_map(find_box)
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
    let state = read_app_state(pid, bounds).ok()?;
    let found = state.roots.iter().find_map(find_box)?;
    let own = match &found.value {
        AxStateValue::Text(text) => Some(text.clone()),
        _ => None,
    };
    let mut texts = Vec::new();
    for child in &found.children {
        collect(child, &mut texts);
    }
    Some((own, texts))
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
