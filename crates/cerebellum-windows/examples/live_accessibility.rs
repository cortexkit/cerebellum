//! Read a live process's UI Automation tree through the seam's own COM code.
//!
//! The unit tests exercise traversal, bounds, cycle cuts and uniqueness over
//! constructed sources, so they prove the logic and nothing about the COM
//! layer beneath it. This probe is the other half: it drives the real
//! `IUIAutomation` interfaces against a running process and prints what the
//! reader reports, so the platform's answer can be compared with the assumptions
//! the FFI was written against.
//!
//! Usage: `live_accessibility <pid> [max_depth] [max_elements] [timeout_ms]`
//!
//! Run it from an interactive session. From a service session the read
//! SUCCEEDS with zero roots -- the tree carries its session provenance so that
//! outcome is attributable rather than mistaken for an application with no
//! windows.

#[cfg(target_os = "windows")]
fn main() {
    use std::time::{Duration, Instant};

    use cerebellum_windows::{
        current_session_provenance, enumerated_window_visibility, process_start_time,
        read_accessibility_tree, AccessibilityReadBounds, UiaElement,
    };

    let mut args = std::env::args().skip(1);
    let Some(pid) = args.next().and_then(|raw| raw.parse::<u32>().ok()) else {
        eprintln!("usage: live_accessibility <pid> [max_depth] [max_elements] [timeout_ms]");
        std::process::exit(2);
    };
    let max_depth = args.next().and_then(|raw| raw.parse().ok()).unwrap_or(12);
    let max_elements = args
        .next()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(2_000);
    let timeout_ms = args
        .next()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(5_000);

    println!("session: {:?}", current_session_provenance());
    println!("target pid: {pid}");
    println!("process start time: {:?}", process_start_time(pid));
    println!(
        "enumerated visibility: {:?}",
        enumerated_window_visibility(pid)
    );

    let bounds = AccessibilityReadBounds {
        timeout: Duration::from_millis(timeout_ms),
        max_depth,
        max_elements,
    };
    let started = Instant::now();
    let tree = match read_accessibility_tree(pid, bounds) {
        Ok(tree) => tree,
        Err(failure) => {
            println!("read failed: {failure:?}");
            std::process::exit(1);
        }
    };
    let elapsed = started.elapsed();

    fn count(element: &UiaElement, depth: usize, total: &mut usize, deepest: &mut usize) {
        *total += 1;
        *deepest = (*deepest).max(depth);
        for child in &element.children {
            count(child, depth + 1, total, deepest);
        }
    }
    let mut total = 0;
    let mut deepest = 0;
    for root in &tree.roots {
        count(root, 0, &mut total, &mut deepest);
    }

    println!("read took: {elapsed:?}");
    println!("session that produced it: {:?}", tree.session);
    println!("roots: {}", tree.roots.len());
    println!("unreadable roots: {}", tree.unreadable_roots.len());
    println!("elements: {total}");
    println!("deepest: {deepest}");
    println!("completeness: {:?}", tree.completeness);

    let mut with_automation_id = 0;
    let mut with_name = 0;
    let mut foreign_pid = 0;
    fn walk(
        element: &UiaElement,
        pid: u32,
        ids: &mut usize,
        names: &mut usize,
        foreign: &mut usize,
    ) {
        if element.process_id != pid {
            *foreign += 1;
        }
        if element.identity.automation_id.is_some() {
            *ids += 1;
        }
        if !element.identity.control_type_and_name.name.is_empty() {
            *names += 1;
        }
        for child in &element.children {
            walk(child, pid, ids, names, foreign);
        }
    }
    for root in &tree.roots {
        walk(
            root,
            pid,
            &mut with_automation_id,
            &mut with_name,
            &mut foreign_pid,
        );
    }
    println!("addressable by automation id: {with_automation_id}");
    println!("addressable by control type + name: {with_name}");
    println!("elements owned by a different pid: {foreign_pid}");

    for root in tree.roots.iter().take(4) {
        println!(
            "  root class={:?} identity={:?} children={} rect={:?}",
            root.class_name,
            root.identity,
            root.children.len(),
            root.bounding_rectangle
        );
    }

    // `--list` prints every element with an automation id or a name, so a
    // follow-up invoke probe can pick a real key rather than guessing one.
    if std::env::args().any(|arg| arg == "--list") {
        fn list(element: &UiaElement, depth: usize) {
            let id = element.identity.automation_id.as_deref().unwrap_or("");
            let name = &element.identity.control_type_and_name.name;
            if !id.is_empty() || !name.is_empty() {
                println!(
                    "{:indent$}[{}] type={} id={:?} name={:?} pid={} enabled={} rect={:?}",
                    "",
                    element.class_name.as_deref().unwrap_or("?"),
                    element.identity.control_type_and_name.control_type,
                    id,
                    name,
                    element.process_id,
                    element.enabled,
                    element.bounding_rectangle,
                    indent = depth * 2
                );
            }
            for child in &element.children {
                list(child, depth + 1);
            }
        }
        for root in &tree.roots {
            list(root, 0);
        }
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("this probe reads a Windows UI Automation tree and does nothing elsewhere");
}
