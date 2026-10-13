//! Ask native macOS TextEdit to open one of its menus and prove the contents
//! appeared.
//!
//! TextEdit is deliberately different from the Calculator driven by
//! `live_native_click`: the target here is a menu bar item, whose effect is a
//! structural change rather than a value change. Opening a menu changes no
//! document, sends nothing, and persists nothing, and the menu's contents
//! appearing beneath the item is directly observable with the accessibility
//! reader this repository already has. The menu bar item advertises `AXCancel`
//! alongside `AXPress`, so the probe closes what it opened through the same
//! closed action vocabulary rather than synthetic input.
//!
//! Every instance is the probe's own: TextEdit is refused when already running
//! (quitting a pre-existing instance could close documents the probe does not
//! own), each attempt launches a fresh instance with a temporary file the
//! probe creates, quits it at the end, and removes the file.
//!
//! Candidate menus are tried in order, each in its own instance, until one
//! completes the full open -> observe -> cancel -> return sequence. A menu
//! whose OPEN state reads as an incomplete accessibility tree cannot be
//! observed through this reader and cannot be cancelled through the action
//! path either (both refuse incomplete trees by design), so that attempt ends
//! by quitting the instance — which the probe owns and always tears down —
//! and the sweep moves on. Measured on this machine, TextEdit's File menu is
//! exactly such a case: one AXMenuItem under the opened menu fails an
//! attribute read, which marks the whole tree incomplete.
//!
//! Run with:
//!
//! ```text
//! cargo run -p cerebellum --example live_native_menu
//! ```

/// The child counts observable on one menu bar item.
///
/// `bar_children` is the menu bar item's own child count; `menu_children` is
/// the child count of the AXMenu beneath it, when one is present. TextEdit
/// pre-creates the AXMenu while the menu is closed, so the bar item's own
/// count does not move when the menu opens — the contents appear INSIDE the
/// AXMenu. Observing both levels is what makes the assertion independent of
/// which of the two shapes an application uses.
#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MenuCounts {
    bar_children: usize,
    menu_children: Option<usize>,
}

#[cfg(target_os = "macos")]
fn menu_opened(before: &MenuCounts, after: &MenuCounts) -> Result<(), String> {
    let bar_changed = before.bar_children != after.bar_children;
    let menu_changed = match (before.menu_children, after.menu_children) {
        (Some(before), Some(after)) => before != after,
        (None, Some(_)) | (Some(_), None) => true,
        (None, None) => false,
    };
    if bar_changed || menu_changed {
        Ok(())
    } else {
        Err(format!(
            "menu contents did not appear after AXPress: before={before:?} after={after:?}"
        ))
    }
}

#[cfg(target_os = "macos")]
fn menu_closed(before: &MenuCounts, after: &MenuCounts) -> Result<(), String> {
    if before == after {
        Ok(())
    } else {
        Err(format!(
            "menu counts did not return after AXCancel: before={before:?} after={after:?}"
        ))
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe drives macOS TextEdit accessibility and has nothing to run here");
}

#[cfg(target_os = "macos")]
#[tokio::main]
async fn main() {
    if let Err(reason) = macos_probe::run().await {
        eprintln!("PROBE FAILED: {reason}");
        // A locked screen is the first thing to rule out, because its
        // signature is easy to misread as a defect in whatever the probe was
        // driving. An application LAUNCHED under a locked session appears to
        // start, answers about itself, and exposes only a menu bar: its
        // accessibility tree reports a root with one child and no AXWindow,
        // because the window was never realised. Applications launched BEFORE
        // the lock keep their full trees, which is why some targets read
        // normally in the same run and makes the cause look like a property of
        // the target rather than of the session.
        if cerebellum_macos::screen_is_locked() == Some(true) {
            eprintln!(
                "  the screen is locked. An application launched now does not \
                 realise its windows, so a menu-bar-only tree is expected and \
                 says nothing about actuation. Re-run unlocked before treating \
                 this as a defect."
            );
        }
        std::process::exit(1);
    }
}

// The consent relay, shared by every probe that answers its own elicitation.
//
// Declared at the file's top level rather than inside the probe module: a
// `#[path]` on a mod nested in an inline module resolves against
// `examples/<inline-mod-name>/`, a directory that does not exist, and POSIX
// will not resolve `..` out of a missing component.
#[cfg(target_os = "macos")]
#[path = "support/cingulate_answer.rs"]
mod cingulate_answer;

#[cfg(target_os = "macos")]
mod macos_probe {
    use std::path::PathBuf;
    use std::process::Command;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use cerebellum::management;
    use cerebellum::Planes;
    use cerebellum_computer::dispatch::post_condition::PostCondition;
    use cerebellum_computer::dispatch::{
        AttendanceContext, AttendanceLease, DispatchRequest, Dispatcher, ExpectedPostCondition,
        FrozenDispatchRow,
    };
    use cerebellum_computer::platform::macos::MacOs26PlatformDriver;
    use cerebellum_computer::platform::{
        AccessibilityElementName, AccessibilityTreeRequest, DispatchMode, ElementResolutionRequest,
        PlatformDriver, ProcessGrant, SEMANTIC_CANCEL_ACTION, SEMANTIC_PRESS_ACTION,
    };
    use cerebellum_core::clock::MonotonicClock;
    use cerebellum_core::health::HealthState;
    use cerebellum_core::identity::SessionKind;
    use cerebellum_core::journal::JournalIdentity;
    use serde_json::{json, Value};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

    use super::cingulate_answer::answer_cards;

    use super::{menu_closed, menu_opened, MenuCounts};

    const TEXTEDIT_PROCESS_NAME: &str = "TextEdit";
    const TEXTEDIT_BUNDLE_ID: &str = "com.apple.TextEdit";
    const MENU_ROLE: &str = "AXMenuBarItem";
    /// Menus tried in order, static content first: a menu whose opened state
    /// reads incomplete ends its attempt, so the menus most likely to read
    /// complete go first. File carries the dynamically populated Open Recent
    /// submenu and Window carries the live window list, so they go last.
    const CANDIDATE_MENUS: &[&str] = &["View", "Format", "Edit", "Help", "File", "Window"];
    const TOOL_CHANNEL: u16 = 9;
    const TOOL_EPOCH: u32 = 3;
    const MANAGEMENT_CHANNEL: u16 = 4;
    const MANAGEMENT_EPOCH: u32 = 1;
    const GRANTEE: &str = "pj-live-native-menu-probe";
    const CONVERSATION: &str = "live-native-menu-probe";

    pub async fn run() -> Result<(), String> {
        let screen = match cerebellum_macos::screen_is_locked() {
            Some(true) => "locked",
            Some(false) => "unlocked",
            None => "no graphical session (lock state unknown)",
        };
        println!("screen state: {screen}");
        println!(
            "accessibility permission: {}",
            cerebellum_macos::accessibility_is_permitted()
        );
        if cerebellum_macos::screen_is_locked() == Some(true) {
            return Err(
                "REFUSED session_locked: the screen is locked, so an application launched now \
                 would never realise its windows and its tree would be menu-bar-only; nothing \
                 actuated in that state proves an effect. Re-run unlocked"
                    .to_string(),
            );
        }
        if !textedit_pids()?.is_empty() {
            return Err(format!(
                "REFUSED target_not_exclusive: TextEdit is already running (pids {:?}); the \
                 probe may only drive an instance it launched itself, because quitting a \
                 pre-existing instance could close documents the probe does not own",
                textedit_pids()?
            ));
        }

        let planes = Planes::with_browser_config(Arc::new(HealthState::new()), None);
        bind_routes(&planes).await?;

        let mut findings = Vec::new();
        for (index, menu_title) in CANDIDATE_MENUS.iter().enumerate() {
            if cerebellum_macos::screen_is_locked() == Some(true) {
                findings.push(format!(
                    "{menu_title}: not attempted, the screen locked during the sweep"
                ));
                break;
            }
            println!("=== candidate menu {menu_title:?} (own TextEdit instance) ===");
            match attempt_menu_probe(&planes, menu_title, index).await {
                Ok(()) => {
                    println!(
                        "NATIVE MENU VERDICT: {MENU_ROLE} {menu_title:?} proved an observable \
                         effect end to end: AXPress opened it, the child counts changed, \
                         AXCancel closed it, and the counts returned"
                    );
                    println!(
                        "non-vacuity condition: unchanged child counts return PROBE FAILED even \
                         when dispatch reports success"
                    );
                    return Ok(());
                }
                Err(reason) => {
                    println!("candidate menu {menu_title:?} did not prove the effect: {reason}");
                    findings.push(format!("{menu_title}: {reason}"));
                }
            }
        }
        Err(format!(
            "REFUSED no_candidate_proved_the_effect: every candidate menu was tried in its own \
             TextEdit instance; findings per menu: {}",
            findings.join(" | ")
        ))
    }

    async fn attempt_menu_probe(
        planes: &Planes,
        menu_title: &str,
        attempt_index: usize,
    ) -> Result<(), String> {
        if !textedit_pids()?.is_empty() {
            return Err(
                "REFUSED teardown_incomplete: a TextEdit instance from an earlier attempt is \
                 still running"
                    .to_string(),
            );
        }
        let temp_file = create_temp_file(menu_title)?;
        let session = match launch_textedit(&temp_file).await {
            Ok(session) => session,
            Err(error) => {
                let cleanup = std::fs::remove_file(&temp_file);
                return Err(format!(
                    "{error}; temporary file cleanup={cleanup:?} (path={temp_file:?})"
                ));
            }
        };
        println!(
            "TextEdit state: launched by probe; pid={} generation={}; temporary file={}",
            session.pid,
            session.start_time_micros,
            temp_file.display()
        );

        let proof = prove_menu_open_and_close(planes, &session, menu_title, attempt_index).await;
        let teardown = teardown_textedit(&session, &temp_file).await;
        match (proof, teardown) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(proof), Ok(())) => Err(proof),
            (Ok(()), Err(teardown)) => Err(teardown),
            (Err(proof), Err(teardown)) => Err(format!(
                "{proof}; TextEdit teardown also failed: {teardown}"
            )),
        }
    }

    fn create_temp_file(menu_title: &str) -> Result<PathBuf, String> {
        let path = std::env::temp_dir().join(format!(
            "ck-live-native-menu-probe-{}-{menu_title}.txt",
            std::process::id()
        ));
        std::fs::write(
            &path,
            "Temporary file created by the live_native_menu probe. Safe to delete.\n",
        )
        .map_err(|error| format!("could not create temporary file {path:?}: {error}"))?;
        Ok(path)
    }

    async fn launch_textedit(temp_file: &PathBuf) -> Result<TextEditSession, String> {
        let status = Command::new("/usr/bin/open")
            .args(["-a", TEXTEDIT_PROCESS_NAME])
            .arg(temp_file)
            .status()
            .map_err(|error| format!("TextEdit launch command failed: {error}"))?;
        if !status.success() {
            return Err(format!(
                "TextEdit launch command exited with status {status}"
            ));
        }

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let pids = textedit_pids()?;
            if pids.len() == 1 {
                return session_for_pid(pids[0]);
            }
            if pids.len() > 1 {
                let cleanup = quit_textedit_application().await;
                return Err(format!(
                    "REFUSED target_ambiguous: launch produced multiple TextEdit processes: \
                     {pids:?}; cleanup={cleanup:?}"
                ));
            }
            if Instant::now() >= deadline {
                let cleanup = quit_textedit_application().await;
                return Err(format!(
                    "TextEdit launch returned but no process appeared within 10s; \
                     cleanup={cleanup:?}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn session_for_pid(pid: u32) -> Result<TextEditSession, String> {
        let start_time_micros =
            cerebellum_macos::process_start_time_micros(pid).ok_or_else(|| {
                format!(
                    "REFUSED process_identity_unavailable: no generation for TextEdit pid {pid}"
                )
            })?;
        Ok(TextEditSession {
            pid,
            start_time_micros,
        })
    }

    fn textedit_pids() -> Result<Vec<u32>, String> {
        let output = Command::new("/usr/bin/pgrep")
            .args(["-x", TEXTEDIT_PROCESS_NAME])
            .output()
            .map_err(|error| format!("could not inspect TextEdit processes: {error}"))?;
        if !output.status.success() && output.status.code() != Some(1) {
            return Err(format!(
                "pgrep TextEdit exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            ));
        }
        let stdout = String::from_utf8(output.stdout)
            .map_err(|error| format!("pgrep TextEdit returned non-UTF-8 output: {error}"))?;
        let mut pids = stdout
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.trim()
                    .parse::<u32>()
                    .map_err(|error| format!("invalid TextEdit pid {line:?}: {error}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        pids.sort_unstable();
        pids.dedup();
        Ok(pids)
    }

    async fn teardown_textedit(
        session: &TextEditSession,
        temp_file: &PathBuf,
    ) -> Result<(), String> {
        if !exact_process_is_running(session) {
            println!(
                "TextEdit quit request: skipped because the exact launched generation already \
                 exited or was replaced"
            );
        } else {
            let quit = quit_textedit_application().await;
            println!("TextEdit quit request: {quit:?}");
            let mut still_running =
                wait_for_exact_process_exit(session, Duration::from_secs(5)).await;
            if still_running {
                let forced = cerebellum_macos::terminate_exact_generation(
                    cerebellum_macos::ProcessGeneration {
                        pid: session.pid,
                        start_time_micros: session.start_time_micros,
                    },
                );
                println!("TextEdit exact-generation termination fallback: {forced:?}");
                still_running = wait_for_exact_process_exit(session, Duration::from_secs(2)).await;
            }
            println!("exact launched process running after quit: {still_running}");
            if still_running {
                return Err(
                    "TextEdit did not exit after graceful and exact-generation termination"
                        .to_string(),
                );
            }
        }

        match std::fs::remove_file(temp_file) {
            Ok(()) => println!("temporary file removed: {}", temp_file.display()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                println!("temporary file already absent: {}", temp_file.display())
            }
            Err(error) => {
                return Err(format!(
                    "temporary file {} was not removed: {error}",
                    temp_file.display()
                ))
            }
        }
        println!("nothing left behind by probe: true");
        Ok(())
    }

    async fn quit_textedit_application() -> Result<(), String> {
        // Bounded because a TextEdit that stops answering AppleEvents would
        // otherwise hold this quit open for AppleEvent's default timeout. If
        // the graceful quit times out, the probe records that failure and
        // terminates only the specific TextEdit process instance it launched
        // (verified by kernel start time before signalling), rather than
        // hanging.
        let status = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "with timeout of 5 seconds",
                "-e",
                "tell application id \"com.apple.TextEdit\" to quit",
                "-e",
                "end timeout",
            ])
            .status()
            .map_err(|error| format!("TextEdit quit command failed: {error}"))?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("TextEdit quit command exited with status {status}"))
        }
    }

    async fn wait_for_exact_process_exit(session: &TextEditSession, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while exact_process_is_running(session) && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        exact_process_is_running(session)
    }

    fn exact_process_is_running(session: &TextEditSession) -> bool {
        cerebellum_macos::process_start_time_micros(session.pid) == Some(session.start_time_micros)
    }

    #[derive(Debug)]
    struct TextEditSession {
        pid: u32,
        start_time_micros: u64,
    }

    async fn prove_menu_open_and_close(
        planes: &Planes,
        session: &TextEditSession,
        menu_title: &str,
        attempt_index: usize,
    ) -> Result<(), String> {
        let before_tree =
            wait_for_textedit_ready(session.pid, menu_title, Duration::from_secs(15)).await?;
        print_tree_observation("BEFORE", &before_tree);

        let menu = find_menu_bar_item(&before_tree.root, menu_title)?;
        println!(
            "resolved element: role={:?} title={:?} identifier={:?} enabled={:?} actions={:?} frame={:?}",
            menu.role, menu.title, menu.identifier, menu.enabled, menu.actions, menu.frame
        );
        let before = MenuCounts {
            bar_children: menu.child_count,
            menu_children: menu.menu_child_count,
        };
        println!(
            "BEFORE counts: menu bar item children={}, AXMenu children={:?}",
            before.bar_children, before.menu_children
        );
        for required in ["AXPress", "AXCancel"] {
            if !menu.actions.iter().any(|action| action == required) {
                return Err(format!(
                    "REFUSED unsupported_action: menu bar item does not advertise {required}: {:?}",
                    menu.actions
                ));
            }
        }

        let identifier_count = menu
            .identifier
            .as_deref()
            .filter(|identifier| !identifier.is_empty())
            .map(|identifier| count_identifier(&before_tree.root, identifier))
            .unwrap_or(0);
        let role_title_count = count_role_and_title(&before_tree.root, &menu.role, &menu.title);
        println!(
            "address measurement: identifier={:?} matches={identifier_count}; role_and_title={{role:{:?}, title:{:?}}} matches={role_title_count}",
            menu.identifier, menu.role, menu.title
        );

        let target = mint_target_lease(planes).await?;
        println!(
            "target lease: pid={} bundle_identity={} generation={}",
            target.pid, target.bundle_identity, target.process_generation_evidence
        );
        let expected_generation = session.start_time_micros.to_string();
        if target.pid != session.pid
            || target.bundle_identity != TEXTEDIT_BUNDLE_ID
            || target.process_generation_evidence != expected_generation
        {
            return Err(format!(
                "REFUSED target_changed: TextEdit resolved to a different process: launched={session:?} resolved={target:?}"
            ));
        }

        let press_outcome = press_menu_bar_item(
            planes,
            &target,
            &menu,
            identifier_count,
            role_title_count,
            attempt_index,
        )
        .await?;
        println!("AXPress dispatcher outcome: {press_outcome}");

        // Between a successful press and a successful cancel the menu is open.
        // Every failure path in between attempts AXCancel before returning.
        // The attempt is best-effort by construction: when the opened menu
        // makes the tree incomplete, the action path refuses to resolve the
        // element at all, and nothing semantic can close the menu. In that
        // case the teardown quitting this probe-owned instance is what
        // removes the open menu, which is why the instance is always quit
        // even on a failed attempt.
        match observe_open_then_close(session, planes, &target, &menu, before).await {
            Ok(()) => Ok(()),
            Err(error) => {
                let cancel =
                    dispatch_semantic_action(planes, &target, &menu, SEMANTIC_CANCEL_ACTION).await;
                Err(format!(
                    "{error}; best-effort AXCancel on the failure path: {cancel:?}"
                ))
            }
        }
    }

    /// Press the menu bar item, preferring the wire route and falling through
    /// to the semantic dispatcher below it when the wire refuses.
    ///
    /// The fall-through records the wire refusal verbatim and names what it
    /// leaves unproven, because a press that succeeds below the wire is not
    /// evidence about the wire: the two layers are reported separately.
    async fn press_menu_bar_item(
        planes: &Planes,
        target: &ProcessGrant,
        menu: &MenuBarItemObservation,
        identifier_count: usize,
        role_title_count: usize,
        attempt_index: usize,
    ) -> Result<Value, String> {
        if identifier_count == 1 {
            let identifier = menu.identifier.as_deref().expect("counted identifier");
            println!("address key: identifier {identifier:?} (matches=1)");
            println!(
                "attempting actuation layer: wire tool route -> computer.click handler -> \
                 semantic dispatcher -> macOS AXPress"
            );
            let outcome = invoke_tool(
                planes,
                30 + attempt_index as u64,
                "computer.click",
                json!({
                    "target": identifier,
                    "button": "left",
                    "click_count": 1,
                    "modifiers": []
                }),
            )
            .await?;
            if outcome["outcome"] == "handler_returned_no_effect_claim" {
                println!("wire computer.click served the press");
                return Ok(outcome);
            }
            println!("wire computer.click refused: {outcome}");
            println!(
                "falling through to the semantic dispatcher below the frozen wire schema; \
                 left unproven: the wire route itself for an identifier-addressed element. \
                 The refusal above is the release gate closing computer.click in this probe \
                 build, not a schema limitation: the frozen request schema carries the \
                 identifier form, and the handler's action-name translation stays unexercised"
            );
        } else if role_title_count == 1 {
            println!(
                "address key: role_and_title {{ role: {:?}, title: {:?} }} (matches=1)",
                menu.role, menu.title
            );
            println!(
                "actuation layer: cerebellum-computer semantic dispatcher below the frozen \
                 wire schema"
            );
            println!(
                "left unproven: wire computer.click cannot carry role_and_title; its handler \
                 resolves target only by AXIdentifier"
            );
        } else {
            return Err(format!(
                "REFUSED ambiguous_element_name: identifier matched {identifier_count} and \
                 role+title matched {role_title_count}; neither key uniquely addresses the \
                 menu bar item"
            ));
        }
        dispatch_semantic_action(planes, target, menu, SEMANTIC_PRESS_ACTION).await
    }

    async fn observe_open_then_close(
        session: &TextEditSession,
        planes: &Planes,
        target: &ProcessGrant,
        menu: &MenuBarItemObservation,
        before: MenuCounts,
    ) -> Result<(), String> {
        let (open_tree, open_counts, open_elapsed, open_attempts) = wait_for_menu_counts(
            session.pid,
            &menu.key,
            Duration::from_secs(5),
            |counts| menu_opened(&before, counts).is_ok(),
            "menu opening (child-count change)",
        )
        .await?;
        print_tree_observation("AFTER AXPress", &open_tree);
        println!(
            "AFTER counts: menu bar item children={}, AXMenu children={:?} (observed {}ms \
             after AXPress, attempts={open_attempts})",
            open_counts.bar_children,
            open_counts.menu_children,
            open_elapsed.as_millis()
        );
        menu_opened(&before, &open_counts)?;

        println!(
            "left unproven: wire computer.click cannot carry AXCancel; the menu is closed \
             below the frozen wire schema"
        );
        let cancel_outcome =
            dispatch_semantic_action(planes, target, menu, SEMANTIC_CANCEL_ACTION).await?;
        println!("AXCancel dispatcher outcome: {cancel_outcome}");

        let (closed_tree, closed_counts, closed_elapsed, closed_attempts) = wait_for_menu_counts(
            session.pid,
            &menu.key,
            Duration::from_secs(5),
            |counts| menu_closed(&before, counts).is_ok(),
            "menu closing (child-count return)",
        )
        .await?;
        print_tree_observation("AFTER AXCancel", &closed_tree);
        println!(
            "counts returned: menu bar item children={}, AXMenu children={:?} (observed {}ms \
             after AXCancel, attempts={closed_attempts})",
            closed_counts.bar_children,
            closed_counts.menu_children,
            closed_elapsed.as_millis()
        );
        menu_closed(&before, &closed_counts)?;

        println!(
            "menu {:?} opened by AXPress (counts {before:?} -> {open_counts:?}) and closed by \
             AXCancel ({open_counts:?} -> {closed_counts:?})",
            menu.title
        );
        Ok(())
    }

    async fn wait_for_textedit_ready(
        pid: u32,
        menu_title: &str,
        timeout: Duration,
    ) -> Result<cerebellum_macos::AxAccessibilityTree, String> {
        let started = Instant::now();
        let deadline = started + timeout;
        let mut attempts = 0usize;
        let mut last_tree = None;
        let mut last_error = None;
        loop {
            attempts += 1;
            match read_tree_once(pid) {
                Ok(tree) => {
                    let complete =
                        tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete;
                    // The menu bar realises before the document window does, so
                    // a complete tree holding the menu bar item is not yet a
                    // realised application: readiness requires an AXWindow the
                    // same way the Calculator probe's readiness required the
                    // window's controls.
                    if complete
                        && count_role(&tree.root, "AXWindow") > 0
                        && find_menu_bar_item(&tree.root, menu_title).is_ok()
                    {
                        println!(
                            "TextEdit tree became readable {}ms after process discovery \
                             (attempts={attempts})",
                            started.elapsed().as_millis()
                        );
                        return Ok(tree);
                    }
                    last_tree = Some(tree);
                }
                Err(error) => last_error = Some(error),
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        if let Some(tree) = last_tree {
            print_tree_observation("READ REFUSAL", &tree);
            let windows = count_role(&tree.root, "AXWindow");
            return Err(format!(
                "REFUSED element_not_found: within {}ms (attempts={attempts}) no readable \
                 complete tree with an AXWindow and a {MENU_ROLE} titled {menu_title:?} \
                 appeared; last completeness={:?}, AXWindow count={windows}; a tree that stays \
                 menu-bar-only under an unlocked screen is the locked-session signature and \
                 says nothing about actuation",
                started.elapsed().as_millis(),
                tree.completeness
            ));
        }
        Err(format!(
            "REFUSED accessibility_read: no TextEdit tree was readable within {}ms \
             (attempts={attempts}); last refusal={}",
            started.elapsed().as_millis(),
            last_error.unwrap_or_else(|| "no read completed".to_string())
        ))
    }

    fn read_tree_once(pid: u32) -> Result<cerebellum_macos::AxAccessibilityTree, String> {
        cerebellum_macos::read_accessibility_tree(pid, cerebellum_macos::AxReadOptions::default())
            .map_err(|error| format!("{error:?}"))
    }

    fn print_tree_observation(phase: &str, tree: &cerebellum_macos::AxAccessibilityTree) {
        println!(
            "{phase} accessibility tree: completeness={:?} elements={} root_role={:?} root_children={}",
            tree.completeness,
            element_count(&tree.root),
            tree.root.role,
            tree.root.children.len()
        );
    }

    fn element_count(element: &cerebellum_macos::AxElement) -> usize {
        1 + element.children.iter().map(element_count).sum::<usize>()
    }

    #[derive(Debug, Clone)]
    struct MenuBarItemObservation {
        role: String,
        title: String,
        identifier: Option<String>,
        enabled: Option<bool>,
        actions: Vec<String>,
        frame: Option<cerebellum_macos::AxFrame>,
        child_count: usize,
        menu_child_count: Option<usize>,
        key: MenuBarItemKey,
    }

    #[derive(Debug, Clone)]
    enum MenuBarItemKey {
        Identifier(String),
        RoleAndTitle { role: String, title: String },
    }

    impl MenuBarItemKey {
        fn describe(&self) -> String {
            match self {
                Self::Identifier(identifier) => format!("identifier {identifier:?}"),
                Self::RoleAndTitle { role, title } => {
                    format!("role_and_title {{ role: {role:?}, title: {title:?} }}")
                }
            }
        }
    }

    fn find_menu_bar_item(
        root: &cerebellum_macos::AxElement,
        menu_title: &str,
    ) -> Result<MenuBarItemObservation, String> {
        let mut matches = Vec::new();
        collect_menu_bar_items(root, menu_title, &mut matches);
        match matches.as_slice() {
            [menu] => {
                let role = menu.role.clone().unwrap_or_default();
                let title = menu.title.clone().unwrap_or_default();
                let identifier = menu.identifier.clone().filter(|value| !value.is_empty());
                let key = identifier
                    .as_deref()
                    .filter(|identifier| count_identifier(root, identifier) == 1)
                    .map(|identifier| MenuBarItemKey::Identifier(identifier.to_string()))
                    .unwrap_or_else(|| MenuBarItemKey::RoleAndTitle {
                        role: role.clone(),
                        title: title.clone(),
                    });
                let menu_child_count = menu
                    .children
                    .iter()
                    .find(|child| child.role.as_deref() == Some("AXMenu"))
                    .map(|menu| menu.children.len());
                Ok(MenuBarItemObservation {
                    role,
                    title,
                    identifier,
                    enabled: menu.enabled,
                    actions: menu.actions.clone(),
                    frame: menu.frame,
                    child_count: menu.children.len(),
                    menu_child_count,
                    key,
                })
            }
            [] => {
                let mut titles = Vec::new();
                collect_menu_bar_titles(root, &mut titles);
                Err(format!(
                    "REFUSED element_not_found: no {MENU_ROLE} titled {menu_title:?}; menu bar \
                     items present: {titles:?}"
                ))
            }
            many => Err(format!(
                "REFUSED ambiguous_element_name: {} {MENU_ROLE} elements titled {menu_title:?}",
                many.len()
            )),
        }
    }

    fn collect_menu_bar_items<'a>(
        element: &'a cerebellum_macos::AxElement,
        menu_title: &str,
        matches: &mut Vec<&'a cerebellum_macos::AxElement>,
    ) {
        if element.role.as_deref() == Some(MENU_ROLE)
            && element.title.as_deref() == Some(menu_title)
        {
            matches.push(element);
        }
        for child in &element.children {
            collect_menu_bar_items(child, menu_title, matches);
        }
    }

    fn collect_menu_bar_titles(element: &cerebellum_macos::AxElement, titles: &mut Vec<String>) {
        if element.role.as_deref() == Some(MENU_ROLE) {
            titles.push(element.title.clone().unwrap_or_default());
        }
        for child in &element.children {
            collect_menu_bar_titles(child, titles);
        }
    }

    fn resolve_menu_counts(
        root: &cerebellum_macos::AxElement,
        key: &MenuBarItemKey,
    ) -> Result<MenuCounts, String> {
        let mut matches = Vec::new();
        collect_menu_bar_key(root, key, &mut matches);
        match matches.as_slice() {
            [element] => Ok(MenuCounts {
                bar_children: element.children.len(),
                menu_children: element
                    .children
                    .iter()
                    .find(|child| child.role.as_deref() == Some("AXMenu"))
                    .map(|menu| menu.children.len()),
            }),
            [] => Err(format!(
                "REFUSED element_not_found: {} no longer resolves in the current tree",
                key.describe()
            )),
            many => Err(format!(
                "REFUSED element_resolution_changed: {} matched {} elements after dispatch",
                key.describe(),
                many.len()
            )),
        }
    }

    fn collect_menu_bar_key<'a>(
        element: &'a cerebellum_macos::AxElement,
        key: &MenuBarItemKey,
        matches: &mut Vec<&'a cerebellum_macos::AxElement>,
    ) {
        let matched = match key {
            MenuBarItemKey::Identifier(identifier) => {
                element.identifier.as_deref() == Some(identifier.as_str())
            }
            MenuBarItemKey::RoleAndTitle { role, title } => {
                element.role.as_deref() == Some(role.as_str())
                    && element.title.as_deref() == Some(title.as_str())
            }
        };
        if matched {
            matches.push(element);
        }
        for child in &element.children {
            collect_menu_bar_key(child, key, matches);
        }
    }

    async fn wait_for_menu_counts(
        pid: u32,
        key: &MenuBarItemKey,
        timeout: Duration,
        satisfied: impl Fn(&MenuCounts) -> bool,
        description: &str,
    ) -> Result<
        (
            cerebellum_macos::AxAccessibilityTree,
            MenuCounts,
            Duration,
            usize,
        ),
        String,
    > {
        let started = Instant::now();
        let deadline = started + timeout;
        let mut attempts = 0usize;
        let mut last_tree = None;
        let mut last_counts = None;
        let mut last_error = None;
        loop {
            attempts += 1;
            match read_tree_once(pid) {
                Ok(tree) if tree.completeness == cerebellum_macos::AxTreeCompleteness::Complete => {
                    match resolve_menu_counts(&tree.root, key) {
                        Ok(counts) if satisfied(&counts) => {
                            return Ok((tree, counts, started.elapsed(), attempts));
                        }
                        Ok(counts) => last_counts = Some(counts),
                        Err(error) => last_error = Some(error),
                    }
                    last_tree = Some(tree);
                }
                Ok(tree) => {
                    last_error = Some(format!(
                        "incomplete accessibility tree: {:?}",
                        tree.completeness
                    ));
                    last_tree = Some(tree);
                }
                Err(error) => last_error = Some(error),
            }
            if Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        if let (Some(tree), Some(counts)) = (last_tree, last_counts) {
            print_tree_observation("UNCHANGED", &tree);
            return Err(format!(
                "{description} was not observable within {}ms (attempts={attempts}); the counts \
                 stayed at {counts:?}: the assertion is the child-count change, never the \
                 dispatch returning without error",
                started.elapsed().as_millis()
            ));
        }
        Err(format!(
            "{description} was not observable within {}ms (attempts={attempts}); last \
             refusal={}",
            started.elapsed().as_millis(),
            last_error.unwrap_or_else(|| "no readable tree".to_string())
        ))
    }

    fn count_role(element: &cerebellum_macos::AxElement, role: &str) -> usize {
        usize::from(element.role.as_deref() == Some(role))
            + element
                .children
                .iter()
                .map(|child| count_role(child, role))
                .sum::<usize>()
    }

    fn count_identifier(element: &cerebellum_macos::AxElement, identifier: &str) -> usize {
        usize::from(element.identifier.as_deref() == Some(identifier))
            + element
                .children
                .iter()
                .map(|child| count_identifier(child, identifier))
                .sum::<usize>()
    }

    fn count_role_and_title(
        element: &cerebellum_macos::AxElement,
        role: &str,
        title: &str,
    ) -> usize {
        usize::from(
            element.role.as_deref() == Some(role) && element.title.as_deref() == Some(title),
        ) + element
            .children
            .iter()
            .map(|child| count_role_and_title(child, role, title))
            .sum::<usize>()
    }

    async fn dispatch_semantic_action(
        planes: &Planes,
        target: &ProcessGrant,
        menu: &MenuBarItemObservation,
        action_name: &str,
    ) -> Result<Value, String> {
        let current = match planes.management.resolve_process(&target.bundle_identity) {
            Ok(grant) => grant,
            Err(refusal) => {
                return Err(format!(
                    "REFUSED target_authority: authority refused before dispatch: {refusal}"
                ))
            }
        };
        if &current != target {
            return Err(format!(
                "REFUSED target_changed: target changed between tree read and dispatch: \
                 before={target:?} now={current:?}"
            ));
        }

        let mut driver = MacOs26PlatformDriver::default().without_expected_post_condition();
        let tree = driver
            .read_accessibility_tree(AccessibilityTreeRequest {
                target: current.clone(),
                settle_interval_ms: 500,
            })
            .map_err(|error| format!("REFUSED dispatcher_accessibility_read: {error:?}"))?;
        let root_identifier = tree.root_identifier.ok_or_else(|| {
            "REFUSED dispatcher_accessibility_read: no root identifier".to_string()
        })?;
        let element_name = match &menu.key {
            MenuBarItemKey::Identifier(identifier) => {
                AccessibilityElementName::Identifier(identifier.clone())
            }
            MenuBarItemKey::RoleAndTitle { role, title } => {
                AccessibilityElementName::role_and_title(role.clone(), title.clone())
            }
        };
        let element = driver
            .resolve_element(ElementResolutionRequest {
                root_identifier,
                element_name,
            })
            .map_err(|error| format!("REFUSED element_resolution: {error:?}"))?;
        println!(
            "dispatcher resolved ({action_name}): {}",
            serde_json::to_string(&element).map_err(|error| error.to_string())?
        );

        let row = FrozenDispatchRow::for_capability("computer.click")
            .ok_or_else(|| "frozen vocabulary has no computer.click row".to_string())?;
        let dispatch_at_ms = planes.lease_clock.now().as_nanos() / 1_000_000;
        let expires_at_ms = dispatch_at_ms.saturating_add(row.maximum_attendance_lease_age_ms);
        let lease = AttendanceLease::new(
            CONVERSATION,
            current.clone(),
            GRANTEE,
            dispatch_at_ms,
            expires_at_ms,
            current.process_generation_evidence.clone(),
            "cerebellum-serve-context-v1",
        )
        .map_err(|error| format!("REFUSED attendance_lease: {error:?}"))?;
        let attendance = AttendanceContext::background(
            CONVERSATION,
            current.clone(),
            GRANTEE,
            lease,
            dispatch_at_ms,
            dispatch_at_ms,
            row.maximum_attendance_lease_age_ms,
            row.maximum_attendance_check_to_dispatch_interval_ms,
            true,
        );
        let request = DispatchRequest::new(
            row,
            DispatchMode::Background,
            current,
            ExpectedPostCondition::new(
                "live-native-menu-no-effect-claim-v1",
                PostCondition::ElementPresent {
                    element: element.element_name.clone(),
                },
            ),
            attendance,
            dispatch_at_ms,
        )
        .with_semantic(element, action_name);
        let identity = JournalIdentity {
            witness: cerebellum_core::dispatch_witness::DispatchWitness::detached(),
            principal: format!("{:?}", Principal::Direct),
            conversation_key: CONVERSATION.to_string(),
            agent_project_id: GRANTEE.to_string(),
            session_kind: SessionKind::Primary,
            origin: Default::default(),
            computer_order: None,
        };
        let mut audit = cerebellum::computer_capability::production_audit()
            .map_err(|error| format!("production audit unavailable: {error}"))?;
        let action_obligation_id = audit.journal().next_sequence();
        let probe_single_action_has_no_interrupt =
            cerebellum_computer::platform::process_event::never_cancelled;
        let report = Dispatcher::new(driver, &probe_single_action_has_no_interrupt)
            .dispatch(&mut audit, identity, request)
            .map_err(|error| {
                let typed = serde_json::to_string(&error).unwrap_or_else(|_| format!("{error:?}"));
                format!("REFUSED semantic_dispatch: {typed}")
            })?;
        let containment_rung = report
            .containment
            .rung()
            .ok_or_else(|| "semantic dispatch returned no containment rung".to_string())?;
        let journal_rung = audit
            .read_computer_audit_record(action_obligation_id)
            .map_err(|error| format!("semantic audit record unavailable: {error:?}"))?
            .descriptor
            .containment_rung;
        let reported_rung =
            serde_json::to_value(containment_rung).map_err(|error| error.to_string())?;
        let recorded_rung =
            serde_json::to_value(journal_rung).map_err(|error| error.to_string())?;
        if reported_rung != recorded_rung {
            return Err(format!(
                "semantic containment diverged between reply and journal: reply={reported_rung} \
                 journal={recorded_rung}"
            ));
        }
        Ok(json!({
            "outcome": "dispatcher_accepted_no_effect_claim",
            "delivery_primitive": report.delivery_primitive,
            "containment_rung": reported_rung,
            "journal_containment_rung": recorded_rung,
            "accepted_by_platform": report.platform_result.accepted_by_platform,
            "effect_status": report.effect.status,
        }))
    }

    async fn mint_target_lease(planes: &Planes) -> Result<ProcessGrant, String> {
        let reply = answer_cards(
            planes,
            route_request(
                MANAGEMENT_CHANNEL,
                MANAGEMENT_EPOCH,
                20,
                json!({
                    "method": management::OPEN_TARGET,
                    "params": {
                        "bundle_identity": TEXTEDIT_BUNDLE_ID
                    }
                }),
            ),
            json!({"decision": "allow_conversation"}),
            "target lease",
        )
        .await?;
        // After the first attempt the app grant is already held for this
        // conversation, so every later attempt answers `granted` at once and
        // one consent covers the whole candidate sweep.
        if reply["outcome"] != "granted" {
            return Err(format!("target grant refused: {reply}"));
        }

        planes
            .management
            .resolve_process(TEXTEDIT_BUNDLE_ID)
            .map_err(|refusal| format!("the granted target did not resolve: {refusal}"))
    }

    async fn bind_routes(planes: &Planes) -> Result<(), String> {
        bind_route(
            planes,
            TOOL_CHANNEL,
            TOOL_EPOCH,
            RouteTarget::ToolProvider {
                module_id: "cerebellum".to_string(),
            },
            false,
        )
        .await?;
        bind_route(
            planes,
            MANAGEMENT_CHANNEL,
            MANAGEMENT_EPOCH,
            RouteTarget::ManagementSurface {
                module_id: "cerebellum".to_string(),
            },
            true,
        )
        .await
    }

    async fn bind_route(
        planes: &Planes,
        route_channel: u16,
        epoch: u32,
        target: RouteTarget,
        raises_cards: bool,
    ) -> Result<(), String> {
        let request = ModuleControlRequest::RouteBind {
            role_versions: None,
            call_mode: None,
            route_channel,
            epoch,
            target,
            identity: probe_identity(),
            principal: cerebellum::session_caller_principal_for_test(),
            consumer_capabilities: None,
            admission_facts: Some(json!({
                "agentProjectId": GRANTEE,
                "sessionKind": "primary",
                "effectiveCapabilityScope": ["*"]
            })),
            // A permission card is raised with Cingulate only from a call
            // under an agent session's scope.
            scope: raises_cards.then(|| super::cingulate_answer::cingulate::stamp(GRANTEE)),
        };
        let frame = Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Passive, false),
            0,
            0,
            route_channel as u64,
            serde_json::to_vec(&request).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        let (writer, mut replies) = mpsc::channel(2);
        cerebellum::handle_control_request_for_test_with_bindings(
            frame,
            &writer,
            &planes.health,
            &planes.routes,
        )
        .await
        .map_err(|error| error.to_string())?;
        let reply = replies
            .recv()
            .await
            .ok_or_else(|| "route.bind returned no reply".to_string())?;
        if reply.header.ty != FrameType::Response {
            return Err("route.bind returned a non-response frame".to_string());
        }
        Ok(())
    }

    async fn invoke_tool(
        planes: &Planes,
        corr: u64,
        name: &str,
        arguments: Value,
    ) -> Result<Value, String> {
        let (writer, mut replies) = mpsc::channel(2);
        cerebellum::handle_tool_request_for_test_with_existing_planes(
            route_request(
                TOOL_CHANNEL,
                TOOL_EPOCH,
                corr,
                json!({"name": name, "arguments": arguments}),
            ),
            &writer,
            planes,
        )
        .await
        .map_err(|error| format!("{name} handler failed: {error}"))?;
        let response = replies
            .recv()
            .await
            .ok_or_else(|| format!("{name} returned no reply"))?;
        serde_json::from_slice(&response.body)
            .map_err(|error| format!("{name} returned invalid JSON: {error}"))
    }

    fn route_request(channel: u16, epoch: u32, corr: u64, body: Value) -> Frame {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            corr,
            serde_json::to_vec(&body).expect("probe requests are JSON"),
        )
        .expect("probe request fits the protocol frame")
    }

    fn probe_identity() -> BindIdentity {
        BindIdentity::new(
            std::env::temp_dir().join("ck-live-native-menu"),
            "probe",
            CONVERSATION.to_string(),
        )
    }
}

// The probe body these tests exercise is macOS-only, so the module is gated to
// match it. Without this the tests reference symbols that do not exist on other
// hosts, and the cross-platform lint fails for a reason unrelated to the code
// under test.
#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::{menu_closed, menu_opened, MenuCounts};

    fn counts(bar_children: usize, menu_children: Option<usize>) -> MenuCounts {
        MenuCounts {
            bar_children,
            menu_children,
        }
    }

    #[test]
    fn unchanged_counts_are_a_failure() {
        let refusal = menu_opened(&counts(1, Some(0)), &counts(1, Some(0)))
            .expect_err("unchanged must refuse");
        assert!(refusal.contains("did not appear"));
    }

    #[test]
    fn menu_contents_appearing_inside_the_existing_menu_is_accepted() {
        menu_opened(&counts(1, Some(0)), &counts(1, Some(13)))
            .expect("contents appearing inside the AXMenu proves the effect");
    }

    #[test]
    fn a_menu_child_appearing_is_accepted() {
        menu_opened(&counts(0, None), &counts(1, Some(13)))
            .expect("the AXMenu appearing as a child proves the effect");
    }

    #[test]
    fn counts_that_did_not_return_are_a_failure() {
        let refusal = menu_closed(&counts(1, Some(0)), &counts(1, Some(13)))
            .expect_err("a still-open menu must refuse");
        assert!(refusal.contains("did not return"));
    }

    #[test]
    fn returned_counts_are_accepted() {
        menu_closed(&counts(1, Some(0)), &counts(1, Some(0)))
            .expect("returned counts prove the menu closed");
    }
}
