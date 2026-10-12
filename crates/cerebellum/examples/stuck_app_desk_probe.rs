//! Stuck-application desk probe for the computer plane's bounded calls.
//!
//! Run it only with the operator's approval, on an unlocked Mac:
//!
//! ```text
//! cargo run -p cerebellum --example stuck_app_desk_probe -- --approve-desk-probe
//! ```
//!
//! It launches its own scratch TextEdit process (a new instance, never the
//! person's), waits for its window, then stops that one process with SIGSTOP
//! so its accessibility server cannot answer. It measures:
//!
//! - that a state read and an element press against the stopped process
//!   return within the call budget the worker sets;
//! - that the system-wide focus read is bounded;
//! - whether a messaging timeout set only on the application element bounds a
//!   read through a child element reference, which decides whether each
//!   element reference needs its own timeout.
//!
//! The scratch process is resumed with SIGCONT and killed on every exit path:
//! normal return, a failed check, a panic, and Ctrl-C. Nothing is saved, and
//! no other process is signalled. Plane-level quarantine behaviour is covered
//! by the `computer_capability` unit tests and is not measured here.

// Other platforms only print a refusal; the shared constants serve the macOS
// desk module alone.
#![cfg_attr(not(target_os = "macos"), allow(dead_code))]

use std::time::Duration;

const APPROVAL_FLAG: &str = "--approve-desk-probe";
/// The call budget each measured operation runs under.
const CALL_BUDGET: Duration = Duration::from_secs(2);
/// Scheduling allowance on top of a bound before a check fails.
const SLACK: Duration = Duration::from_secs(1);
const LAUNCH_WAIT: Duration = Duration::from_secs(15);

/// Whether the operator approved this run on the command line.
fn approved(arguments: impl IntoIterator<Item = String>) -> bool {
    arguments
        .into_iter()
        .any(|argument| argument == APPROVAL_FLAG)
}

fn main() {
    if !approved(std::env::args().skip(1)) {
        eprintln!(
            "REFUSED: this probe stops a scratch application with SIGSTOP. Run it only with \
             the operator's approval, passing {APPROVAL_FLAG}."
        );
        std::process::exit(2);
    }
    #[cfg(target_os = "macos")]
    std::process::exit(desk::run());
    #[cfg(not(target_os = "macos"))]
    {
        eprintln!("UNMEASURABLE: macOS desk required");
        std::process::exit(2);
    }
}

#[cfg(target_os = "macos")]
mod desk {
    use super::*;
    use cerebellum_computer::app_state::native::MacAppStateSource;
    use cerebellum_computer::app_state::source::{
        AppStateSource, ElementHandle, RawElement, ReadBounds,
    };
    use cerebellum_computer::platform::ProcessGrant;
    use std::process::{Child, Command};
    use std::sync::{Arc, Mutex};
    use std::time::Instant;

    const TEXTEDIT: &str = "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit";

    /// The scratch process, resumed and killed when dropped.
    struct Scratch {
        child: Child,
    }

    impl Scratch {
        fn pid(&self) -> u32 {
            self.child.id()
        }
    }

    fn signal(pid: u32, name: &str) -> bool {
        Command::new("/bin/kill")
            .args([format!("-{name}"), pid.to_string()])
            .status()
            .is_ok_and(|status| status.success())
    }

    fn release(pid: u32) {
        signal(pid, "CONT");
        signal(pid, "KILL");
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            release(self.child.id());
            let _ = self.child.wait();
            println!("SCRATCH {} resumed and killed", self.child.id());
        }
    }

    /// The scratch pid, for the Ctrl-C handler. Zero when none is running.
    static SCRATCH_PID: Mutex<u32> = Mutex::new(0);

    fn install_interrupt_handler() {
        std::thread::spawn(|| {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                return;
            };
            runtime.block_on(async {
                if tokio::signal::ctrl_c().await.is_ok() {
                    let pid = *SCRATCH_PID.lock().unwrap();
                    if pid != 0 {
                        release(pid);
                        println!("SCRATCH {pid} resumed and killed after interrupt");
                    }
                    std::process::exit(130);
                }
            });
        });
    }

    fn grant(pid: u32) -> ProcessGrant {
        ProcessGrant {
            pid,
            bundle_identity: "com.apple.TextEdit".into(),
            process_generation_evidence: String::new(),
        }
    }

    fn find(nodes: &[RawElement], want: &dyn Fn(&RawElement) -> bool) -> Option<ElementHandle> {
        nodes.iter().find_map(|node| {
            if want(node) {
                Some(node.handle.clone())
            } else {
                find(&node.children, want)
            }
        })
    }

    struct Report {
        failed: bool,
    }

    impl Report {
        fn check(&mut self, name: &str, elapsed: Duration, bound: Duration, detail: &str) {
            let pass = elapsed <= bound + SLACK;
            self.failed |= !pass;
            println!(
                "{} {name}: {} ms (bound {} ms) {detail}",
                if pass { "PASS" } else { "FAIL" },
                elapsed.as_millis(),
                bound.as_millis()
            );
        }
    }

    pub fn run() -> i32 {
        println!(
            "TIME BUDGET: at most {} s (launch wait {} s, four bounded checks of {} s plus {} s \
             slack each, teardown)",
            (LAUNCH_WAIT + 4 * (CALL_BUDGET + SLACK) + Duration::from_secs(10)).as_secs(),
            LAUNCH_WAIT.as_secs(),
            CALL_BUDGET.as_secs(),
            SLACK.as_secs()
        );
        if cerebellum_macos::screen_is_locked().unwrap_or(true) {
            eprintln!("UNMEASURABLE: the screen is locked or its state is unknown");
            return 2;
        }
        install_interrupt_handler();
        // A second TextEdit instance runs under the person's HOME, so without
        // this it would reopen the person's documents from saved window state,
        // and stopping and killing it could disturb them. Ignoring persistent
        // state keeps the scratch instance to an empty window or open panel.
        let child = match Command::new(TEXTEDIT)
            .args(["-ApplePersistenceIgnoreState", "YES"])
            .spawn()
        {
            Ok(child) => child,
            Err(error) => {
                eprintln!("UNMEASURABLE: cannot launch scratch TextEdit: {error}");
                return 2;
            }
        };
        let scratch = Scratch { child };
        *SCRATCH_PID.lock().unwrap() = scratch.pid();
        println!("SCRATCH TextEdit pid {}", scratch.pid());
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| measure(&scratch)));
        *SCRATCH_PID.lock().unwrap() = 0;
        drop(scratch);
        match outcome {
            Ok(code) => code,
            Err(_) => {
                eprintln!("FAIL probe panicked");
                1
            }
        }
    }

    /// Read the scratch window while it answers, stop the process, then run
    /// each bounded check against it. Returns the process exit code.
    fn measure(scratch: &Scratch) -> i32 {
        let source = Arc::new(MacAppStateSource);
        let pid = scratch.pid();
        let started = Instant::now();
        let tree = loop {
            match source.read_app_state(&grant(pid), ReadBounds::default()) {
                Ok(tree) if !tree.roots.is_empty() => break tree,
                _ if started.elapsed() > LAUNCH_WAIT => {
                    eprintln!("UNMEASURABLE: the scratch window never appeared");
                    return 2;
                }
                _ => std::thread::sleep(Duration::from_millis(250)),
            }
        };
        let minimize = find(&tree.roots, &|node| {
            node.subrole.as_deref() == Some("AXMinimizeButton")
        });
        let child_ref = child_ref::first_window(pid);
        if !signal_stop(pid) {
            eprintln!("UNMEASURABLE: could not stop the scratch process");
            return 2;
        }
        println!("SCRATCH {pid} stopped");
        let mut report = Report { failed: false };

        let cap = cerebellum_macos::ax_budget::bound_messages_until(Instant::now() + CALL_BUDGET);
        let begun = Instant::now();
        let read = source.read_app_state(&grant(pid), ReadBounds::default());
        report.check(
            "read_state against a stopped app",
            begun.elapsed(),
            CALL_BUDGET,
            &format!("(result: {})", if read.is_ok() { "ok" } else { "error" }),
        );
        drop(cap);

        match &minimize {
            Some(handle) => {
                let _cap =
                    cerebellum_macos::ax_budget::bound_messages_until(Instant::now() + CALL_BUDGET);
                let begun = Instant::now();
                let pressed = source.press(handle);
                report.check(
                    "press against a stopped app",
                    begun.elapsed(),
                    CALL_BUDGET,
                    &format!("(result: {pressed:?})"),
                );
            }
            None => println!("SKIPPED press: no minimize button was found before the stop"),
        }

        let _cap = cerebellum_macos::ax_budget::bound_messages_until(Instant::now() + CALL_BUDGET);
        let begun = Instant::now();
        let focus = cerebellum_macos::focused_application_pid();
        report.check(
            "system-wide focus read",
            begun.elapsed(),
            Duration::from_secs(1),
            &format!("(result: {focus:?}; the scratch app may or may not be frontmost)"),
        );

        match child_ref {
            Some(window) => {
                let app_only = child_ref::title_with_app_timeout_only(pid, &window, 0.5);
                println!(
                    "RECORD application-element timeout bounds a read through a child ref: {} \
                     ({} ms with a 500 ms timeout on the application element only)",
                    app_only < Duration::from_millis(1_500),
                    app_only.as_millis()
                );
                let own = child_ref::title_with_own_timeout(&window, 0.5);
                report.check(
                    "child ref read with its own timeout",
                    own,
                    Duration::from_millis(500),
                    "",
                );
            }
            None => println!("SKIPPED child-ref record: no window ref was read before the stop"),
        }
        if report.failed {
            1
        } else {
            0
        }
    }

    /// Stop the scratch process so its accessibility server cannot answer.
    fn signal_stop(pid: u32) -> bool {
        signal(pid, "STOP")
    }

    /// Raw accessibility calls for the one measurement the production
    /// readers cannot isolate: they always set a timeout on each element.
    #[allow(unsafe_code)]
    mod child_ref {
        use std::ffi::{c_void, CString};
        use std::time::{Duration, Instant};

        type CfRef = *const c_void;

        #[link(name = "ApplicationServices", kind = "framework")]
        extern "C" {
            fn AXUIElementCreateApplication(pid: i32) -> CfRef;
            fn AXUIElementCopyAttributeValue(element: CfRef, name: CfRef, value: *mut CfRef)
                -> i32;
            fn AXUIElementSetMessagingTimeout(element: CfRef, seconds: f32) -> i32;
        }

        #[link(name = "CoreFoundation", kind = "framework")]
        extern "C" {
            fn CFStringCreateWithCString(allocator: CfRef, text: *const i8, encoding: u32)
                -> CfRef;
            fn CFArrayGetCount(array: CfRef) -> isize;
            fn CFArrayGetValueAtIndex(array: CfRef, index: isize) -> CfRef;
            fn CFRetain(value: CfRef) -> CfRef;
            fn CFRelease(value: CfRef);
        }

        const UTF8: u32 = 0x0800_0100;

        /// An owned CoreFoundation reference, released when dropped.
        pub struct Owned(CfRef);

        impl Drop for Owned {
            fn drop(&mut self) {
                // SAFETY: `Owned` holds exactly one retain count.
                unsafe { CFRelease(self.0) };
            }
        }

        fn string(text: &str) -> Owned {
            let text = CString::new(text).unwrap();
            // SAFETY: a valid NUL-terminated UTF-8 string; returns one retain.
            Owned(unsafe { CFStringCreateWithCString(std::ptr::null(), text.as_ptr(), UTF8) })
        }

        fn copy(element: CfRef, name: &str) -> Option<Owned> {
            let name = string(name);
            let mut value: CfRef = std::ptr::null();
            // SAFETY: element and name are live; `value` receives one retain.
            let code = unsafe { AXUIElementCopyAttributeValue(element, name.0, &mut value) };
            (code == 0 && !value.is_null()).then_some(Owned(value))
        }

        fn application(pid: u32) -> Owned {
            // SAFETY: returns one retained application element.
            Owned(unsafe { AXUIElementCreateApplication(pid as i32) })
        }

        /// The first window of `pid`, read while it still answers.
        pub fn first_window(pid: u32) -> Option<Owned> {
            let app = application(pid);
            let windows = copy(app.0, "AXWindows")?;
            // SAFETY: `windows` is a live CFArray.
            if unsafe { CFArrayGetCount(windows.0) } < 1 {
                return None;
            }
            // SAFETY: index 0 exists; the value is borrowed, so retain it.
            Some(Owned(unsafe {
                CFRetain(CFArrayGetValueAtIndex(windows.0, 0))
            }))
        }

        /// Read the window's title with a timeout set only on a fresh
        /// application element, never on the window ref itself.
        pub fn title_with_app_timeout_only(pid: u32, window: &Owned, seconds: f32) -> Duration {
            let app = application(pid);
            // SAFETY: a live application element.
            unsafe { AXUIElementSetMessagingTimeout(app.0, seconds) };
            let begun = Instant::now();
            let _ = copy(window.0, "AXTitle");
            begun.elapsed()
        }

        /// Read the window's title with a timeout set on the window ref.
        pub fn title_with_own_timeout(window: &Owned, seconds: f32) -> Duration {
            // SAFETY: a live element ref.
            unsafe { AXUIElementSetMessagingTimeout(window.0, seconds) };
            let begun = Instant::now();
            let _ = copy(window.0, "AXTitle");
            begun.elapsed()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_probe_runs_only_with_the_explicit_approval_flag() {
        assert!(!approved(Vec::<String>::new()));
        assert!(!approved(["--approve".to_string()]));
        assert!(approved(["--approve-desk-probe".to_string()]));
    }
}
