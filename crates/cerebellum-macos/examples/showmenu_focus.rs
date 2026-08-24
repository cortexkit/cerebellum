//! THE MEASUREMENT: does `AXShowMenu` seize a global interaction resource?
//!
//! Our levels are defined by EFFECT, and level 4 is reserved for actions that
//! seize a resource shared with the user: cursor, keyboard, focus, or z-order.
//! `AXShowMenu` is semantic in MECHANISM -- the application opens its own menu --
//! but a menu that captures global key events or pulls focus is level 4 by the
//! resource list, exactly as `AXRaise` is.
//!
//! It is currently frozen at 4 as a conservative default, which is free while
//! the action is unserved. This measures it so the freeze can be replaced by a
//! fact whenever the action is served.
//!
//! Launches its own TextEdit and quits it.

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("this probe measures macOS accessibility menu behaviour");
}

#[cfg(target_os = "macos")]
fn main() {
    use cerebellum_macos::{
        read_accessibility_tree, request_accessibility_action, AxAction, AxActionOptions,
        AxReadOptions,
    };
    use std::process::Command;
    use std::thread::sleep;
    use std::time::Duration;

    let _ = Command::new("/usr/bin/open")
        .args(["-a", "TextEdit", "-n"])
        .status();
    sleep(Duration::from_millis(2500));

    let Some(pid) = pid_of("TextEdit") else {
        eprintln!("PROBE FAILED: TextEdit did not start");
        return;
    };

    // Put something else in front. If the target is already frontmost, a focus
    // change cannot be observed and the measurement answers nothing.
    let _ = Command::new("/usr/bin/open")
        .args(["-a", "Finder"])
        .status();
    sleep(Duration::from_millis(1500));

    let before = frontmost_process_id();
    println!("target pid {pid}, frontmost before: {before:?}");
    if before == Some(pid as i32) {
        eprintln!("PROBE INCONCLUSIVE: the target is frontmost, so focus movement is unobservable");
        quit_textedit();
        return;
    }

    let Ok(tree) = read_accessibility_tree(pid, AxReadOptions::default()) else {
        eprintln!("PROBE FAILED: the accessibility tree could not be read");
        quit_textedit();
        return;
    };

    // Any element that ADVERTISES ShowMenu. Asking an element that does not
    // advertise it measures our refusal path, not the framework's behaviour.
    let Some(name) = find_show_menu(&tree.root) else {
        eprintln!(
            "PROBE INCONCLUSIVE: no element in TextEdit advertises AXShowMenu, so this app \
             cannot answer the question. Try one with context menus."
        );
        quit_textedit();
        return;
    };
    println!("element advertising ShowMenu: {name:?}");

    // WATCH FOCUS THROUGHOUT, not only at the ends. A human clicking during the
    // measurement changes focus for reasons that have nothing to do with the
    // action, and before/after sampling cannot see it happen -- it reports
    // whatever the two endpoints happened to be. A sample that disagrees with
    // the start means the measurement was disturbed and must be discarded
    // rather than interpreted.
    let watcher = std::thread::spawn(move || {
        let mut seen = Vec::new();
        for _ in 0..12 {
            if let Some(pid) = frontmost_process_id() {
                if !seen.contains(&pid) {
                    seen.push(pid);
                }
            }
            std::thread::sleep(Duration::from_millis(150));
        }
        seen
    });

    let outcome =
        request_accessibility_action(pid, &name, AxAction::ShowMenu, AxActionOptions::default());
    println!("action outcome: {outcome:?}");
    sleep(Duration::from_millis(1200));

    // DID A MENU ACTUALLY OPEN? `HandlerReturned` means the handler returned,
    // not that anything happened. Without this check, an action that did
    // nothing reports "focus unmoved, keyboard free" -- trivially true, and a
    // level assignment drawn from it would be measuring silence.
    let menu_opened = read_accessibility_tree(pid, AxReadOptions::default())
        .map(|t| has_menu(&t.root))
        .unwrap_or(false);
    println!("a menu is present in the tree: {menu_opened}");

    let after = frontmost_process_id();
    println!("frontmost after: {after:?}");

    // Does a key event still reach a DIFFERENT process while the menu is open?
    // A menu that captures the keyboard globally is level 4 whether or not it
    // moved focus, and focus alone would miss that.
    let keyboard_captured = !key_reaches_other_process();
    println!("keyboard captured by the menu: {keyboard_captured}");

    let observed = watcher.join().unwrap_or_default();
    println!("every frontmost process seen during the action: {observed:?}");

    // More than one process frontmost during a single action means something
    // else moved focus. Whether that was the menu or a human cannot be told
    // apart from here, so the honest result is no result.
    let disturbed =
        observed.len() > 1 && !(observed.len() == 2 && observed.contains(&(pid as i32)));
    let focus_moved = after != before || observed.contains(&(pid as i32));
    quit_textedit();

    if disturbed {
        println!();
        println!(
            "VERDICT: DISCARDED -- focus moved between processes that are neither the target nor \
             the starting one, so something outside this measurement moved it. Re-run without \
             touching the machine."
        );
        return;
    }

    if !menu_opened {
        println!();
        println!(
            "VERDICT: INCONCLUSIVE -- no menu appeared, so nothing was measured. The handler \
             returning is not evidence a menu opened, and an action that did nothing cannot \
             seize anything. AXShowMenu stays at its conservative 4."
        );
        return;
    }

    println!();
    println!(
        "VERDICT: {}",
        if focus_moved || keyboard_captured {
            "LEVEL 4 CONFIRMED -- ShowMenu seizes a resource shared with the user, so the \
             conservative freeze is a measured fact rather than caution."
        } else {
            "LEVEL 2 BY MEASUREMENT -- ShowMenu neither moved focus nor captured the keyboard, \
             so its effects stayed inside the target application. The conservative 4 is a debt \
             that should be paid down in the migration that first serves it."
        }
    );
}

#[cfg(target_os = "macos")]
fn has_menu(element: &cerebellum_macos::AxElement) -> bool {
    if element.role.as_deref().is_some_and(|role| role == "AXMenu") {
        return true;
    }
    element.children.iter().any(has_menu)
}

#[cfg(target_os = "macos")]
fn find_show_menu(
    element: &cerebellum_macos::AxElement,
) -> Option<cerebellum_macos::AxElementName> {
    if element
        .actions
        .iter()
        .any(|action| action.eq_ignore_ascii_case("AXShowMenu"))
    {
        // Prefer the identifier, fall back to role-and-title -- the same two
        // key forms the plane addresses elements with everywhere else.
        if let Some(identifier) = element.identifier.as_ref().filter(|id| !id.is_empty()) {
            return Some(cerebellum_macos::AxElementName::Identifier(
                identifier.clone(),
            ));
        }
        if let Some(role) = element.role.as_ref() {
            return Some(cerebellum_macos::AxElementName::RoleAndTitle {
                role: role.clone(),
                title: element.title.clone().unwrap_or_default(),
            });
        }
    }
    element.children.iter().find_map(find_show_menu)
}

/// Whether a key event still reaches a process other than the menu's owner.
#[cfg(target_os = "macos")]
fn key_reaches_other_process() -> bool {
    // Reading the frontmost process through System Events requires the event
    // system to answer at all; a globally captured keyboard makes this fail or
    // hang rather than return.
    std::process::Command::new("/usr/bin/osascript")
        .args(["-e", "tell application \"System Events\" to get name of first process whose frontmost is true"])
        .output()
        .map(|out| out.status.success())
        .unwrap_or(false)
}

#[cfg(target_os = "macos")]
fn frontmost_process_id() -> Option<i32> {
    let out = std::process::Command::new("/usr/bin/osascript")
        .args([
            "-e",
            "tell application \"System Events\" to get unix id of first process whose frontmost is true",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(target_os = "macos")]
fn pid_of(name: &str) -> Option<u32> {
    let out = std::process::Command::new("/usr/bin/pgrep")
        .args(["-x", name])
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .next()?
        .trim()
        .parse()
        .ok()
}

#[cfg(target_os = "macos")]
fn quit_textedit() {
    let _ = std::process::Command::new("/usr/bin/osascript")
        .args(["-e", "tell application \"TextEdit\" to quit saving no"])
        .status();
}
