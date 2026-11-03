//! Manual, VM-only measurement of session-global mouse-up routing.
//! The helper apps are built with the VM's Swift compiler; no installed app or
//! operator document is used. A missing receipt means no receipt within the
//! stated observation interval, not a WindowServer delivery acknowledgement.

use std::io::Write;

fn main() {
    if let Err(error) = run() {
        let _ = writeln!(std::io::stderr(), "UNMEASURABLE: {error}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "macos"))]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    Err("this probe requires a disposable macOS VM".into())
}

#[cfg(target_os = "macos")]
fn run() -> Result<(), Box<dyn std::error::Error>> {
    use std::process::Command;
    if !std::env::args().any(|arg| arg == "--approve-scratch-desk") {
        return Err("pass --approve-scratch-desk inside a disposable VM only".into());
    }
    let vm = Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.hv_vmm_present"])
        .output()?;
    if !vm.status.success() || String::from_utf8_lossy(&vm.stdout).trim() != "1" {
        return Err("refusing input: kern.hv_vmm_present is not 1".into());
    }
    if !cerebellum_macos::pointer_probe_posting_permitted() {
        return Err("input posting not permitted for this process".into());
    }
    let ready = cerebellum_macos::prepare_pointer_hit_tests();
    let (before, setter, after) = cerebellum_macos::pointer_hit_test_startup_diagnosis();
    writeln!(std::io::stdout(), "AppKit init: policy_before={before:?} setter_return={setter:?} policy_after={after:?} ready={ready}")?;
    if !ready {
        return Err("AppKit mouse-down hit-test initialization failed to retain prohibited activation policy".into());
    }
    if std::env::args().any(|arg| arg == "--startup-init-only") {
        for second in 0..10 {
            let own = cerebellum_macos::pointer_probe_own_window_count()
                .ok_or("CGWindowList own-pid telemetry unavailable")?;
            writeln!(
                std::io::stdout(),
                "second={second} policy={} (Prohibited=2) own_on_screen_windows={own}",
                cerebellum_macos::current_app_activation_mode_raw()
            )?;
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
        return Ok(());
    }
    probe::run()
}

#[cfg(target_os = "macos")]
mod probe {
    use super::*;
    use cerebellum_macos::{
        mouse_click_events, pointer_window_at, post_event_globally, EventPoint,
    };
    use std::error::Error;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};
    use std::time::{Duration, Instant};

    type Result<T> = std::result::Result<T, Box<dyn Error>>;
    const POINT: EventPoint = EventPoint { x: 220.0, y: 220.0 };

    struct App {
        child: Child,
        log: PathBuf,
        window: u32,
    }

    impl Drop for App {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    impl App {
        fn start(bundle: &Path, log: PathBuf) -> Result<Self> {
            let child = Command::new(bundle.join("Contents/MacOS/Probe"))
                .arg(&log)
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()?;
            let mut app = Self {
                child,
                log,
                window: 0,
            };
            app.wait_for("ready ")?;
            app.window = app
                .text()?
                .lines()
                .find_map(|line| line.strip_prefix("ready "))
                .ok_or("missing window number")?
                .parse()?;
            Ok(app)
        }

        fn text(&self) -> Result<String> {
            Ok(fs::read_to_string(&self.log)?)
        }

        fn wait_for(&mut self, needle: &str) -> Result<()> {
            let deadline = Instant::now() + Duration::from_secs(5);
            while Instant::now() < deadline {
                if self.text().is_ok_and(|text| text.contains(needle)) {
                    return Ok(());
                }
                if self.child.try_wait()?.is_some() {
                    return Err(format!("helper exited before {needle}").into());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(format!("no helper acknowledgement for {needle}").into())
        }

        fn command(&mut self, command: &str) -> Result<()> {
            writeln!(
                self.child.stdin.as_mut().ok_or("helper pipe closed")?,
                "{command}"
            )?;
            self.wait_for(&format!("ack {command}"))
        }
    }

    fn wait_top(window: u32) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if receiver_window_at() == Some(window) {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        Err(format!("AppKit mouse-down hit-test/CG identity bridge at probe point: returned {:?}, expected {window}", receiver_window_at()).into())
    }

    fn receiver_window_at() -> Option<u32> {
        // Match production's blocking worker instead of assuming a successful
        // main-thread query proves that off-main-thread reads work.
        std::thread::spawn(|| pointer_window_at(POINT.x, POINT.y))
            .join()
            .ok()
            .flatten()
    }

    pub(super) fn run() -> Result<()> {
        let root = std::env::temp_dir().join(format!("ck-mouse-up-routing-{}", std::process::id()));
        fs::create_dir(&root)?;
        let source = root.join("Probe.swift");
        fs::write(&source, HELPER)?;
        let executable = root.join("Probe");
        let status = Command::new("/usr/bin/xcrun")
            .args(["swiftc", "-framework", "AppKit"])
            .arg(&source)
            .arg("-o")
            .arg(&executable)
            .status()?;
        if !status.success() {
            return Err(
                "scratch app compilation failed (VM needs Xcode command-line tools)".into(),
            );
        }
        for name in ["A", "B"] {
            let bundle = root.join(format!("{name}.app/Contents"));
            fs::create_dir_all(bundle.join("MacOS"))?;
            fs::copy(&executable, bundle.join("MacOS/Probe"))?;
            fs::write(
                bundle.join("Info.plist"),
                format!(
                    "<?xml version=\"1.0\"?><plist version=\"1.0\"><dict>\
                 <key>CFBundleExecutable</key><string>Probe</string>\
                 <key>CFBundleIdentifier</key><string>dev.cortexkit.mouse-up.{name}</string>\
                 <key>CFBundleName</key><string>Routing {name}</string>\
                 <key>CFBundlePackageType</key><string>APPL</string></dict></plist>"
                ),
            )?;
        }
        let mut out = std::io::stdout().lock();
        writeln!(out, "Logs: {}", root.display())?;
        writeln!(
            out,
            "case | down window | A up | B up | receipt (1 second observation)"
        )?;
        for case in ["baseline", "move", "close", "terminate"] {
            let mut b = App::start(&root.join("B.app"), root.join(format!("{case}-B.log")))?;
            b.command("raise")?;
            let mut a = App::start(&root.join("A.app"), root.join(format!("{case}-A.log")))?;
            a.command("raise")?;
            wait_top(a.window)?;
            let [down, up] = mouse_click_events(POINT)?;
            let _ = post_event_globally(down);
            // A verified down receipt is essential: otherwise an up in B says
            // nothing about the owner of an established click/drag sequence.
            if let Err(error) = a.wait_for(&format!("down {}", a.window)) {
                let _ = post_event_globally(up);
                return Err(error);
            }
            let transition = (|| -> Result<()> {
                match case {
                    "move" => a.command("move")?,
                    "close" => a.command("close")?,
                    "terminate" => {
                        a.child.kill()?;
                        a.child.wait()?;
                    }
                    _ => {}
                }
                if case != "baseline" {
                    b.command("raise")?;
                    wait_top(b.window)?;
                }
                Ok(())
            })();
            // Even an unmeasurable transition must not strand a held button. This
            // probe runs only inside a VM (checked at startup), where posting an
            // up to whatever is under the point is acceptable; production never
            // posts an up without its containment check.
            let _ = post_event_globally(up);
            transition?;
            std::thread::sleep(Duration::from_secs(1));
            if case != "terminate" {
                a.command("barrier")?;
            }
            b.command("barrier")?;
            let a_text = a.text()?;
            let b_text = b.text()?;
            let a_ups = a_text.lines().filter(|s| s.starts_with("up ")).count();
            let b_ups = b_text.lines().filter(|s| s.starts_with("up ")).count();
            let receipt = match (a_ups, b_ups) {
                (1, 0) => "down owner",
                (0, 1) => "OTHER APP",
                (0, 0) if case != "baseline" => "none observed",
                _ => return Err(format!("{case}: ambiguous receipts A={a_ups} B={b_ups}").into()),
            };
            writeln!(out, "{case} | {} | {a_ups} | {b_ups} | {receipt}", a.window)?;
        }
        Ok(())
    }

    const HELPER: &str = r#"
import AppKit
import Foundation

let path = CommandLine.arguments[1]
FileManager.default.createFile(atPath: path, contents: nil)
let log = FileHandle(forWritingAtPath: path)!
func record(_ text: String) {
    log.write((text + "\n").data(using: .utf8)!)
    log.synchronizeFile()
}
class Canvas: NSView {
    override func acceptsFirstMouse(for event: NSEvent?) -> Bool { true }
}
class Window: NSWindow {
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func sendEvent(_ event: NSEvent) {
        if event.type == .leftMouseDown { record("down \(windowNumber)") }
        if event.type == .leftMouseUp { record("up \(windowNumber)") }
        super.sendEvent(event)
    }
}
let app = NSApplication.shared
app.setActivationPolicy(.regular)
let screen = NSScreen.screens[0].frame
let window = Window(contentRect: NSRect(x: 120, y: screen.height - 320, width: 240, height: 200),
                    styleMask: [.borderless], backing: .buffered, defer: false)
window.isReleasedWhenClosed = false
window.level = .normal
window.contentView = Canvas(frame: NSRect(x: 0, y: 0, width: 240, height: 200))
window.backgroundColor = .white
app.finishLaunching()
window.makeKeyAndOrderFront(nil)
record("ready \(window.windowNumber)")
DispatchQueue.global().async {
    while let command = readLine() {
        DispatchQueue.main.async {
            switch command {
            case "raise":
                window.orderFrontRegardless()
            case "move": window.setFrameOrigin(NSPoint(x: 600, y: screen.height - 320))
            case "close": window.close()
            case "barrier": break
            default: exit(2)
            }
            record("ack \(command)")
        }
    }
    exit(0)
}
app.run()
"#;
}
