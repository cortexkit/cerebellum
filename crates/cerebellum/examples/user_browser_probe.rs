//! Operator-approved, headed Chrome for Testing probe (macOS only).
//!
//! Run the prebuilt, fleet-signed example in one command, from the repository:
//! target/debug/examples/user_browser_probe --approve-local-probe \
//!   --chrome '/path/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing' \
//!   --native-host /absolute/path/ck-cerebellum-native-host --extension-dir "$PWD/extension"
//!
//! Budget: at most 180 seconds, plus up to 3 seconds for process cleanup. All
//! generated state is under /tmp. The in-process scratch cerebellum uses an
//! isolated journal and a local consent relay: only its loopback origin can be
//! answered, with allow_once, and no phone or standing grants are involved.
//! See docs/user-browser.md for the pinned CfT version, probe feature and signing.
//!
//! This launches a headed browser with --no-startup-window, never activates it
//! or restores focus, and samples foreground pid and Chrome activation events.
//! macOS/Chrome startup might nevertheless front a window: that is a FAIL, not
//! a guarantee this harness can prevent it. Keep your current focus unchanged.
//! The supervisor kills/reaps only its own process group and removes its scratch
//! directory on success, failure, timeout, Ctrl-C and SIGTERM. SIGKILL of the
//! supervisor or machine failure cannot run cleanup.

use cerebellum_bridge_protocol::{EXTENSION_ID, EXTENSION_ORIGIN, EXTENSION_PUBLIC_KEY_B64};
use cerebellum_core::private_fs;
use serde_json::{json, Value};
use std::io::Write;
use std::path::{Path, PathBuf};

const HOST: &str = "com.cortexkit.cerebellum";
const CHROME_MANIFEST_DIR: &str = "Library/Application Support/Google/Chrome/NativeMessagingHosts";
const BUDGET_SECS: u64 = 180;

#[derive(Debug)]
struct Options {
    chrome: PathBuf,
    host: PathBuf,
    extension: PathBuf,
    scratch: Option<PathBuf>,
}

fn options(args: &[String]) -> Result<Options, String> {
    if !args.iter().any(|arg| arg == "--approve-local-probe") {
        return Err("Live Chrome requires --approve-local-probe after operator approval; no browser was launched.".into());
    }
    let mut result = Options {
        chrome: PathBuf::new(),
        host: PathBuf::new(),
        extension: PathBuf::new(),
        scratch: None,
    };
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--approve-local-probe" {
            i += 1;
            continue;
        }
        let value = args.get(i + 1).ok_or("missing option value")?;
        let path = PathBuf::from(value);
        if !path.is_absolute() {
            return Err("all paths must be absolute".into());
        }
        match args[i].as_str() {
            "--chrome" => result.chrome = path,
            "--native-host" => result.host = path,
            "--extension-dir" => result.extension = path,
            "--scratch-child" => result.scratch = Some(path),
            _ => return Err(format!("unknown option {}", args[i])),
        }
        i += 2;
    }
    if result.chrome.as_os_str().is_empty()
        || result.host.as_os_str().is_empty()
        || result.extension.as_os_str().is_empty()
    {
        return Err("required: --chrome, --native-host, --extension-dir".into());
    }
    if result.chrome.file_name().and_then(|s| s.to_str()) != Some("Google Chrome for Testing") {
        return Err(
            "only the pinned Google Chrome for Testing executable is accepted, never normal Chrome"
                .into(),
        );
    }
    Ok(result)
}

fn extension_is_pinned(extension: &Path) -> Result<(), String> {
    let manifest: Value = serde_json::from_slice(
        &std::fs::read(extension.join("manifest.json")).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if manifest["key"] != EXTENSION_PUBLIC_KEY_B64 {
        return Err("extension key differs from the pinned host origin".into());
    }
    Ok(())
}

// Reject links before creating directories, so installation cannot follow a
// redirected Chrome directory into a different browser's profile or manifest.
fn no_links(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component);
        match std::fs::symlink_metadata(&current) {
            Ok(meta) if meta.file_type().is_symlink() => {
                return Err(format!("refusing symlink {}", current.display()))
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    Ok(())
}

fn write_manifest(home: &Path, host: &Path) -> Result<PathBuf, String> {
    if !home.is_absolute() || !host.is_absolute() || !host.is_file() {
        return Err("home and existing host executable must be absolute".into());
    }
    write_manifest_at(&home.join(CHROME_MANIFEST_DIR), host)
}

fn write_manifest_at(directory: &Path, host: &Path) -> Result<PathBuf, String> {
    let path = directory.join(format!("{HOST}.json"));
    no_links(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if std::fs::metadata(&path).is_ok_and(|m| !m.is_file() || m.nlink() != 1) {
            return Err("refusing non-regular or multiply linked manifest".into());
        }
    }
    let manifest = json!({
        "name": HOST, "description": "CortexKit Chrome bridge", "path": host,
        "type": "stdio", "allowed_origins": [EXTENSION_ORIGIN]
    });
    let bytes = serde_json::to_vec_pretty(&manifest).map_err(|e| e.to_string())?;
    private_fs::create_dir_all(directory).map_err(|e| e.to_string())?;
    let mut file = private_fs::create_file(&path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| e.to_string())?;
    }
    file.write_all(&bytes)
        .and_then(|_| file.write_all(b"\n"))
        .and_then(|_| file.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(path)
}

struct Scratch(PathBuf);
impl Scratch {
    fn new() -> Result<Self, String> {
        let mut bytes = [0u8; 16];
        getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        // Canonicalize /tmp on macOS (where it is /private/tmp), not a caller's
        // TMPDIR. No live profile, journal or runtime-directory fallback exists.
        let path = std::fs::canonicalize("/tmp")
            .map_err(|e| e.to_string())?
            .join(format!("ck-user-browser-{nonce}"));
        private_fs::create_dir(&path).map_err(|e| e.to_string())?;
        Ok(Self(path))
    }
}
impl Scratch {
    fn cleanup(&mut self) -> Result<(), String> {
        if !self.0.as_os_str().is_empty() {
            std::fs::remove_dir_all(&self.0).map_err(|e| e.to_string())?;
            self.0.clear();
        }
        Ok(())
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        if let Err(e) = self.cleanup() {
            eprintln!("FAIL cleanup scratch: {e}");
        }
    }
}

fn consent_for_fixture(card: &Value, origin: &str) -> Result<(), String> {
    let p = &card["params"];
    if card["method"] != "elicitation/create"
        || p["kind"] != "consent"
        || p["scope"]["browser"] != "user"
        || p["scope"]["origins"] != json!([origin])
        || p["target"]["label"] != origin
        || p["prompt"] != "Let the agent use your own Chrome, signed in as you, on this site?"
        || !p["options"]
            .as_array()
            .is_some_and(|options| options.iter().any(|o| o["id"] == "allow_once"))
    {
        return Err("scratch relay refused a non-fixture or malformed site card".into());
    }
    Ok(())
}

#[async_trait::async_trait(?Send)]
trait Driver {
    async fn call(&mut self, args: Value) -> Result<(Value, usize), String>;
    fn observe(&mut self) -> Result<Value, String>;
    async fn restart(&mut self) -> Result<(), String>;
    fn outside_tab(&self) -> String;
}

fn check(label: &str, passed: bool) -> Result<(), String> {
    println!("{} {label}", if passed { "PASS" } else { "FAIL" });
    if passed {
        Ok(())
    } else {
        Err(label.into())
    }
}
fn ok(reply: &Value) -> bool {
    reply["browser"] == "user" && reply["outcome"] == "ok"
}
fn detached_and_unfocused(driver: &mut impl Driver) -> Result<(), String> {
    let observation = driver.observe()?;
    check(
        "debugger detached between actions",
        observation["agent_attached"] == false,
    )?;
    check(
        "no Chrome tab/window activation",
        observation["focus_events"] == 0,
    )?;
    Ok(())
}
fn reference(snapshot: &Value, name: &str) -> Result<String, String> {
    snapshot["state_text"]
        .as_str()
        .and_then(|text| text.lines().find(|line| line.contains(name)))
        .and_then(|line| line.split_whitespace().next())
        .map(str::to_owned)
        .ok_or_else(|| format!("snapshot lacks {name}"))
}

async fn exercise(driver: &mut impl Driver, origin: &str) -> Result<(), String> {
    let (opened, _) = driver.call(json!({"action":"open_tab"})).await?;
    check(
        "open_tab in Agent group",
        ok(&opened) && opened["tab"].is_string(),
    )?;
    let tab = opened["tab"].as_str().unwrap().to_owned();
    detached_and_unfocused(driver)?;
    let (status, _) = driver.call(json!({"action":"status"})).await?;
    let observation = driver.observe()?;
    check(
        "outside-group tab is invisible and stays outside",
        ok(&status)
            && status["tabs"]
                .as_array()
                .is_some_and(|tabs| tabs.len() == 1 && tabs[0]["tab"] == tab)
            && observation["outside_group"] == -1
            && observation["agent_tabs"] == 1,
    )?;
    let (outside, _) = driver
        .call(json!({"action":"snapshot", "tab":driver.outside_tab()}))
        .await?;
    check(
        "outside tab read refuses without content",
        outside["outcome"] == "refused" && outside.get("state_text").is_none(),
    )?;
    let severity = json!({"tier":1,"credential":false,"financial":false});
    let (navigated, asks) = driver.call(json!({"action":"navigate","tab":tab,"url":format!("{origin}/"),"wait":"settle","intent":"load loopback probe","severity":severity})).await?;
    check(
        "navigation asks per site through scratch relay",
        ok(&navigated) && asks == 1,
    )?;
    detached_and_unfocused(driver)?;
    let (snapshot, asks) = driver
        .call(json!({"action":"snapshot","tab":tab,"mode":"ax"}))
        .await?;
    check(
        "snapshot reads fixture and asks again after allow_once",
        ok(&snapshot)
            && asks == 1
            && snapshot["state_text"].as_str().is_some_and(|s| {
                s.contains("Probe button")
                    && s.contains("Probe input")
                    && !s.contains("OUTSIDE_SECRET")
            }),
    )?;
    detached_and_unfocused(driver)?;
    let button = reference(&snapshot, "Probe button")?;
    let (clicked, _) = driver.call(json!({"action":"click","tab":tab,"ref":button,"snapshot_id":snapshot["snapshot_id"],"intent":"click fixture button","severity":severity})).await?;
    check(
        "click delivered to local fixture",
        ok(&clicked) && driver.observe()?["clicks"] == 1,
    )?;
    detached_and_unfocused(driver)?;
    let (fresh, _) = driver
        .call(json!({"action":"snapshot","tab":tab,"mode":"ax"}))
        .await?;
    check("fresh snapshot after click", ok(&fresh))?;
    let input = reference(&fresh, "Probe input")?;
    let (typed, _) = driver
        .call(
            json!({"action":"type","tab":tab,"ref":input,"text":"scratch-only","clear_first":true}),
        )
        .await?;
    check(
        "type delivered to local fixture",
        ok(&typed) && driver.observe()?["typed"] == "scratch-only",
    )?;
    detached_and_unfocused(driver)?;
    let old_epoch = opened["connection_epoch"].clone();
    driver.restart().await?;
    let (reconnected, _) = driver.call(json!({"action":"status"})).await?;
    check(
        "killed worker reconnects with a new epoch",
        ok(&reconnected)
            && reconnected["connected"] == true
            && reconnected["connection_epoch"].is_number()
            && reconnected["connection_epoch"] != old_epoch,
    )?;
    let (stale, _) = driver.call(json!({"action":"click","tab":tab,"ref":input,"snapshot_id":fresh["snapshot_id"],"intent":"stale input must refuse","severity":severity})).await?;
    check(
        "old worker handles refuse and commands are not replayed",
        stale["outcome"] == "refused"
            && driver.observe()?["clicks"] == 1
            && driver.observe()?["typed"] == "scratch-only",
    )?;
    detached_and_unfocused(driver)?;
    let (closed, _) = driver.call(json!({"action":"close"})).await?;
    check(
        "close releases without closing unrelated tab",
        closed["outcome"] == "closed" && driver.observe()?["outside_group"] == -1,
    )?;
    Ok(())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args == ["--self-test"] {
        if let Err(reason) = self_test().await {
            eprintln!("FAIL self-test: {reason}");
            std::process::exit(1);
        }
        return;
    }
    println!("user_browser_probe {}: maximum {BUDGET_SECS}s + 3s cleanup; scratch-only, local pages, no focus restoration", env!("CARGO_PKG_VERSION"));
    #[cfg(target_os = "macos")]
    let result = live::entry(args).await;
    #[cfg(not(target_os = "macos"))]
    let result: Result<(), String> = {
        let _ = args;
        Err("Installation and live probe are macOS-only; use cargo test -p cerebellum --example user_browser_probe for offline doubles.".into())
    };
    if let Err(reason) = result {
        eprintln!("FAIL user_browser_probe: {reason}");
        std::process::exit(1);
    }
}

#[cfg(target_os = "macos")]
mod live {
    use super::*;
    use cerebellum::user_browser_bridge::{BridgeListener, Route};
    use cerebellum::{JournalPersistence, Planes};
    use cerebellum_core::health::HealthState;
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

    fn verify(path: &Path, requirement: &str) -> Result<(), String> {
        let status = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "-R", requirement])
            .arg(path)
            .status()
            .map_err(|e| e.to_string())?;
        if status.success() {
            Ok(())
        } else {
            Err(format!("{} does not satisfy {requirement}", path.display()))
        }
    }

    pub async fn entry(args: Vec<String>) -> Result<(), String> {
        if args.first().is_some_and(|a| a == "--install-native-host") {
            if args.len() != 4 || args[2] != "--extension-dir" {
                return Err(
                    "usage: --install-native-host ABS_HOST --extension-dir ABS_EXTENSION".into(),
                );
            }
            let host = Path::new(&args[1]);
            extension_is_pinned(Path::new(&args[3]))?;
            verify(host, cerebellum_bridge_protocol::HOST_REQUIREMENT)?;
            let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is unset")?);
            let written = write_manifest(&home, host)?;
            println!(
                "Installed {} (extension {EXTENSION_ID}, no wildcards).",
                written.display()
            );
            println!("In normal Google Chrome: open chrome://extensions, turn Developer mode ON, click Load unpacked, select {}. Keep its manifest key unchanged. Start your configured cerebellum; open_tab/claim_tab use browser: user.", args[3]);
            return Ok(());
        }
        let options = options(&args)?;
        extension_is_pinned(&options.extension)?;
        if !cfg!(feature = "chrome-for-testing-parent-probe") {
            return Err("build both this example and native host with --features chrome-for-testing-parent-probe (development only)".into());
        }
        verify(&options.host, cerebellum_bridge_protocol::HOST_REQUIREMENT)?;
        verify(
            &std::env::current_exe().map_err(|e| e.to_string())?,
            cerebellum_bridge_protocol::CEREBELLUM_REQUIREMENT,
        )?;
        if let Some(root) = options.scratch.as_ref() {
            return child(&options, root).await;
        }
        supervisor(&options).await
    }

    // The signed scratch child is the socket server. Environment redirection is
    // done before it starts, rather than changing HOME in a multithreaded runtime.
    async fn supervisor(options: &Options) -> Result<(), String> {
        use std::os::unix::process::CommandExt;
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
                .map_err(|e| e.to_string())?;
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|e| e.to_string())?;
        let mut scratch = Scratch::new()?;
        for dir in [
            "home", "data", "config", "state", "cache", "runtime", "tmp", "profile",
        ] {
            private_fs::create_dir(&scratch.0.join(dir)).map_err(|e| e.to_string())?;
        }
        // Place manifests in the overridden user-data directory and CfT's
        // default HOME-relative directory. Both are private scratch locations;
        // failed discovery never falls back to installing into the real home.
        write_manifest_at(
            &scratch.0.join("profile/NativeMessagingHosts"),
            &options.host,
        )?;
        write_manifest_at(
            &scratch.0.join(
                "home/Library/Application Support/Google/ChromeForTesting/NativeMessagingHosts",
            ),
            &options.host,
        )?;

        let mut command = Command::new(std::env::current_exe().map_err(|e| e.to_string())?);
        command
            .args(["--approve-local-probe", "--chrome"])
            .arg(&options.chrome)
            .arg("--native-host")
            .arg(&options.host)
            .arg("--extension-dir")
            .arg(&options.extension)
            .arg("--scratch-child")
            .arg(&scratch.0)
            .process_group(0);
        for (name, dir) in [
            ("HOME", "home"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_RUNTIME_DIR", "runtime"),
            ("TMPDIR", "tmp"),
        ] {
            command.env(name, scratch.0.join(dir));
        }
        let child = command.spawn().map_err(|e| e.to_string())?;
        let mut group = Group {
            child,
            root: scratch.0.clone(),
            cleaned: false,
        };
        let deadline = Instant::now() + Duration::from_secs(BUDGET_SECS);
        let outcome = loop {
            if let Some(status) = group.child.try_wait().map_err(|e| e.to_string())? {
                break if status.success() {
                    Ok(())
                } else {
                    Err(format!("scratch child exited {status}"))
                };
            }
            if Instant::now() >= deadline {
                break Err("180 second probe deadline exceeded".into());
            }
            tokio::select! {
                _ = interrupt.recv() => break Err("operator interrupted probe".into()),
                _ = term.recv() => break Err("probe received SIGTERM".into()),
                _ = tokio::time::sleep(Duration::from_millis(50)) => {},
            }
        };
        group.cleanup()?;
        scratch.cleanup()?;
        println!(
            "{} process-group and scratch cleanup completed",
            if outcome.is_ok() { "PASS" } else { "FAIL" }
        );
        outcome
    }
    struct Group {
        child: Child,
        root: PathBuf,
        cleaned: bool,
    }
    impl Group {
        fn cleanup(&mut self) -> Result<(), String> {
            if self.cleaned {
                return Ok(());
            }
            // Crashpad can leave Chrome's process group. Capture only processes
            // carrying this run's random scratch path, plus our spawned group.
            // Recheck each process's kernel-recorded start time before signalling
            // it, so a reused pid cannot target an unrelated process.
            let output = Command::new("/bin/ps")
                .args(["-axo", "pid=,pgid=,command="])
                .output()
                .map_err(|e| e.to_string())?;
            if !output.status.success() {
                return Err("cannot enumerate scratch children for cleanup".into());
            }
            let mut children = Vec::new();
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let mut fields = line.split_whitespace();
                let Some(pid) = fields.next().and_then(|s| s.parse::<u32>().ok()) else {
                    continue;
                };
                let pgid = fields.next().and_then(|s| s.parse::<u32>().ok());
                if pid != std::process::id()
                    && (pgid == Some(self.child.id())
                        || line.contains(&*self.root.to_string_lossy()))
                {
                    if let Some(start) = cerebellum_macos::process_start_time_micros(pid) {
                        children.push((pid, start));
                    }
                }
            }
            let group = rustix::process::Pid::from_raw(self.child.id() as i32)
                .ok_or("invalid owned process group")?;
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::TERM);
            for (pid, start) in &children {
                if cerebellum_macos::process_start_time_micros(*pid) == Some(*start) {
                    let _ = rustix::process::kill_process(
                        rustix::process::Pid::from_raw(*pid as i32).unwrap(),
                        rustix::process::Signal::TERM,
                    );
                }
            }
            let end = Instant::now() + Duration::from_secs(2);
            while Instant::now() < end
                && children.iter().any(|(pid, start)| {
                    cerebellum_macos::process_start_time_micros(*pid) == Some(*start)
                })
            {
                let _ = self.child.try_wait();
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = rustix::process::kill_process_group(group, rustix::process::Signal::KILL);
            for (pid, start) in &children {
                if cerebellum_macos::process_start_time_micros(*pid) == Some(*start) {
                    let _ = rustix::process::kill_process(
                        rustix::process::Pid::from_raw(*pid as i32).unwrap(),
                        rustix::process::Signal::KILL,
                    );
                }
            }
            self.child.wait().map_err(|e| e.to_string())?;
            let end = Instant::now() + Duration::from_secs(1);
            while Instant::now() < end
                && children.iter().any(|(pid, start)| {
                    cerebellum_macos::process_start_time_micros(*pid) == Some(*start)
                })
            {
                std::thread::sleep(Duration::from_millis(20));
            }
            if children.iter().any(|(pid, start)| {
                cerebellum_macos::process_start_time_micros(*pid) == Some(*start)
            }) {
                return Err("scratch helper remained alive after cleanup".into());
            }
            self.cleaned = true;
            Ok(())
        }
    }
    impl Drop for Group {
        fn drop(&mut self) {
            if let Err(e) = self.cleanup() {
                eprintln!("FAIL process cleanup: {e}");
            }
        }
    }

    pub fn cleanup_control() -> Result<(), String> {
        use std::os::unix::process::CommandExt;
        let mut scratch = Scratch::new()?;
        let path = scratch.0.clone();
        let child = Command::new("/bin/sh")
            .args(["-c", "sleep 300 & wait", "scratch-cleanup-double"])
            .arg(&path)
            .process_group(0)
            .spawn()
            .map_err(|e| e.to_string())?;
        let mut group = Group {
            child,
            root: path.clone(),
            cleaned: false,
        };
        std::thread::sleep(Duration::from_millis(100));
        group.cleanup()?;
        scratch.cleanup()?;
        if path.exists() || group.child.try_wait().map_err(|e| e.to_string())?.is_none() {
            return Err("process or directory survived scratch cleanup".into());
        }
        Ok(())
    }

    struct Focus {
        stop: Arc<AtomicBool>,
        changed: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Focus {
        fn start() -> Result<Self, String> {
            let initial =
                cerebellum_macos::frontmost_process_id().ok_or("cannot observe foreground app")?;
            let stop = Arc::new(AtomicBool::new(false));
            let changed = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let result = changed.clone();
            let thread = std::thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    if cerebellum_macos::frontmost_process_id() != Some(initial) {
                        result.store(true, Ordering::SeqCst);
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            Ok(Self {
                stop,
                changed,
                thread: Some(thread),
            })
        }
    }
    impl Drop for Focus {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    // Independent fixture readback avoids trusting CDP success as proof of
    // delivery. The browser sends click/input beacons to the loopback server.
    struct Page {
        origin: String,
        reports: Arc<Mutex<(usize, String)>>,
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Page {
        fn start() -> Result<Self, String> {
            let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            listener.set_nonblocking(true).map_err(|e| e.to_string())?;
            let origin = format!(
                "http://{}",
                listener.local_addr().map_err(|e| e.to_string())?
            );
            let reports = Arc::new(Mutex::new((0, String::new())));
            let state = reports.clone();
            let stop = Arc::new(AtomicBool::new(false));
            let flag = stop.clone();
            let thread = std::thread::spawn(move || {
                while !flag.load(Ordering::SeqCst) {
                    let (mut stream, _) = match listener.accept() {
                        Ok(s) => s,
                        Err(_) => {
                            std::thread::sleep(Duration::from_millis(10));
                            continue;
                        }
                    };
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                    let mut bytes = [0u8; 8192];
                    let size = stream.read(&mut bytes).unwrap_or(0);
                    let request = String::from_utf8_lossy(&bytes[..size]);
                    let path = request.split_whitespace().nth(1).unwrap_or("");
                    let mut report = state.lock().unwrap();
                    if path == "/click" {
                        report.0 += 1;
                    }
                    if let Some(text) = path.strip_prefix("/type?") {
                        report.1 = text.to_owned();
                    }
                    drop(report);
                    let body = if path == "/outside-secret" {
                        "<!doctype html><title>OUTSIDE_SECRET</title><p>OUTSIDE_SECRET</p>"
                    } else if path == "/" {
                        r#"<!doctype html><meta charset="utf-8"><title>Local user browser probe</title><button aria-label="Probe button" onclick="navigator.sendBeacon('/click')">Probe button</button><input aria-label="Probe input" oninput="navigator.sendBeacon('/type?'+encodeURIComponent(this.value))">"#
                    } else {
                        "ok"
                    };
                    let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body);
                }
            });
            Ok(Self {
                origin,
                reports,
                stop,
                thread: Some(thread),
            })
        }
    }
    impl Drop for Page {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    // Minimal observer-only WebSocket transport. It never dispatches browser_use
    // inputs: those travel through the signed host, bridge and production plane.
    struct Cdp {
        stream: TcpStream,
        seq: u64,
        events: Vec<Value>,
    }
    impl Cdp {
        fn connect(port: u16, path: &str) -> Result<Self, String> {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            stream
                .set_write_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            write!(stream, "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n").map_err(|e| e.to_string())?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                let mut byte = [0];
                stream.read_exact(&mut byte).map_err(|e| e.to_string())?;
                header.push(byte[0]);
                if header.len() > 8192 {
                    return Err("oversized websocket handshake".into());
                }
            }
            if !header.starts_with(b"HTTP/1.1 101 ") {
                return Err("CDP websocket refused".into());
            }
            Ok(Self {
                stream,
                seq: 0,
                events: Vec::new(),
            })
        }
        fn send(&mut self, opcode: u8, bytes: &[u8]) -> Result<(), String> {
            let mut frame = vec![0x80 | opcode];
            if bytes.len() < 126 {
                frame.push(0x80 | bytes.len() as u8);
            } else if bytes.len() <= u16::MAX as usize {
                frame.push(0xfe);
                frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
            } else {
                frame.push(0xff);
                frame.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            }
            let mut mask = [0u8; 4];
            getrandom::getrandom(&mut mask).map_err(|e| e.to_string())?;
            frame.extend_from_slice(&mask);
            frame.extend(bytes.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
            self.stream.write_all(&frame).map_err(|e| e.to_string())
        }
        fn receive(&mut self) -> Result<Value, String> {
            let mut message = Vec::new();
            loop {
                let mut head = [0u8; 2];
                self.stream
                    .read_exact(&mut head)
                    .map_err(|e| e.to_string())?;
                let mut length = u64::from(head[1] & 127);
                if length == 126 {
                    let mut b = [0; 2];
                    self.stream.read_exact(&mut b).map_err(|e| e.to_string())?;
                    length = u64::from(u16::from_be_bytes(b));
                } else if length == 127 {
                    let mut b = [0; 8];
                    self.stream.read_exact(&mut b).map_err(|e| e.to_string())?;
                    length = u64::from_be_bytes(b);
                }
                if length > 16 * 1024 * 1024
                    || message.len() as u64 + length > 16 * 1024 * 1024
                    || head[1] & 128 != 0
                {
                    return Err("invalid CDP websocket frame".into());
                }
                let mut data = vec![0; length as usize];
                self.stream
                    .read_exact(&mut data)
                    .map_err(|e| e.to_string())?;
                match head[0] & 15 {
                    8 => return Err("CDP websocket closed".into()),
                    9 => {
                        self.send(10, &data)?;
                        continue;
                    }
                    10 => continue,
                    0 | 1 => message.extend(data),
                    _ => return Err("non-text CDP websocket frame".into()),
                }
                if head[0] & 128 != 0 {
                    return serde_json::from_slice(&message).map_err(|e| e.to_string());
                }
            }
        }
        fn call(
            &mut self,
            method: &str,
            params: Value,
            session: Option<&str>,
        ) -> Result<Value, String> {
            self.seq += 1;
            let mut request = json!({"id":self.seq,"method":method,"params":params});
            if let Some(s) = session {
                request["sessionId"] = json!(s);
            }
            self.send(1, &serde_json::to_vec(&request).map_err(|e| e.to_string())?)?;
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                if Instant::now() >= deadline {
                    return Err(format!("CDP {method} timed out"));
                }
                let reply = self.receive()?;
                if reply["id"] == self.seq {
                    if reply.get("error").is_some() {
                        return Err(format!("CDP {method}: {}", reply["error"]));
                    }
                    return Ok(reply["result"].clone());
                }
                if self.events.len() >= 4096 {
                    return Err("CDP observer event limit".into());
                }
                self.events.push(reply);
            }
        }
        fn eval(&mut self, session: &str, expression: &str) -> Result<Value, String> {
            let result = self.call(
                "Runtime.evaluate",
                json!({"expression":expression,"awaitPromise":true,"returnByValue":true}),
                Some(session),
            )?;
            if result.get("exceptionDetails").is_some() {
                return Err(format!("observer evaluation failed: {result}"));
            }
            result["result"]
                .get("value")
                .cloned()
                .ok_or("observer did not return a value".into())
        }
        fn worker(&mut self) -> Result<Option<String>, String> {
            let list = self.call("Target.getTargets", json!({}), None)?;
            Ok(list["targetInfos"]
                .as_array()
                .and_then(|rows| {
                    rows.iter().find(|r| {
                        r["type"] == "service_worker"
                            && r["url"] == format!("{EXTENSION_ORIGIN}service-worker.mjs")
                    })
                })
                .and_then(|r| r["targetId"].as_str())
                .map(str::to_owned))
        }
        fn attach(&mut self, target: &str) -> Result<String, String> {
            self.call(
                "Target.attachToTarget",
                json!({"targetId":target,"flatten":true}),
                None,
            )?["sessionId"]
                .as_str()
                .map(str::to_owned)
                .ok_or("observer attachment missing session".into())
        }
    }

    struct Live {
        planes: Planes,
        cdp: Cdp,
        worker_session: String,
        worker_target: String,
        service_session: String,
        outside_id: String,
        origin: String,
        page: Page,
        focus: Focus,
        corr: u64,
    }
    const CHANNEL: u16 = 9;
    const EPOCH: u32 = 1;
    fn frame(corr: u64, channel: u16, epoch: u32, body: Value) -> Result<Frame, String> {
        Frame::build_with_version(
            PROTOCOL_VERSION,
            FrameType::Request,
            Flags::new(false, Priority::Interactive, false),
            channel,
            epoch,
            corr,
            serde_json::to_vec(&body).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())
    }
    async fn bind(planes: &Planes, root: &Path) -> Result<(), String> {
        let request = ModuleControlRequest::RouteBind {
            role_versions: None,
            route_channel: CHANNEL,
            epoch: EPOCH,
            target: RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            identity: BindIdentity::new(root.to_owned(), "probe", "user-browser-probe"),
            principal: cerebellum::session_caller_principal_for_test(),
            consumer_capabilities: Some(vec!["elicitation".into()]),
            admission_facts: Some(
                json!({"agentProjectId":"pj-user-browser-probe","sessionKind":"primary",
                "effectiveCapabilityScope":["*"],"browserControlOperations":["browser.launch","browser.status","browser.close"]}),
            ),
            scope: None,
        };
        let (writer, mut frames) = mpsc::channel(2);
        cerebellum::handle_control_request_for_test_with_bindings(
            frame(
                1,
                0,
                0,
                serde_json::to_value(request).map_err(|e| e.to_string())?,
            )?,
            &writer,
            &planes.health,
            &planes.routes,
        )
        .await
        .map_err(|e| e.to_string())?;
        let reply = frames
            .recv()
            .await
            .ok_or("route binding returned no reply")?;
        if reply.header.ty != FrameType::Response {
            return Err("scratch route binding refused".into());
        }
        Ok(())
    }
    fn instrument(cdp: &mut Cdp, session: &str) -> Result<(), String> {
        cdp.eval(
            session,
            r#"(() => {
          globalThis.__probeFocus = 0;
          chrome.tabs.onActivated.addListener(() => { globalThis.__probeFocus++; });
          chrome.windows.onFocusChanged.addListener(() => { globalThis.__probeFocus++; });
          return true;
        })()"#,
        )?;
        Ok(())
    }

    async fn child(options: &Options, root: &Path) -> Result<(), String> {
        let tmp = std::fs::canonicalize("/tmp").map_err(|e| e.to_string())?;
        let canonical = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
        if canonical.parent() != Some(tmp.as_path())
            || !canonical
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("ck-user-browser-"))
        {
            return Err(
                "scratch child must be under /tmp, with the supervisor's private directory".into(),
            );
        }
        for (name, dir) in [
            ("HOME", "home"),
            ("XDG_DATA_HOME", "data"),
            ("XDG_CONFIG_HOME", "config"),
            ("XDG_STATE_HOME", "state"),
            ("XDG_CACHE_HOME", "cache"),
            ("XDG_RUNTIME_DIR", "runtime"),
            ("TMPDIR", "tmp"),
        ] {
            if std::env::var_os(name).map(PathBuf::from) != Some(root.join(dir)) {
                return Err(format!("scratch child {name} not isolated"));
            }
        }
        let run = cortexkit_paths::cortexkit_run_dir().map_err(|e| e.to_string())?;
        if run != root.join("data/cortexkit/run") {
            return Err("refusing non-scratch bridge socket".into());
        }
        let config = cerebellum::browser_config::BrowserConfig {
            executable_path: None,
            expected_identity: None,
            launch_handshake_deadline_ms: 10_000,
            termination_grace_period_ms: 2_000,
            browser_idle_timeout_ms: 60_000,
            browser_exit_observation_deadline_ms: 2_000,
            navigation_settle_deadline_ms: 10_000,
        };
        let planes = Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config),
            JournalPersistence::Isolated,
        );
        bind(&planes, root).await?;
        let listener =
            BridgeListener::bind(planes.user_browser.clone()).map_err(|e| e.to_string())?;
        let focus = Focus::start()?;
        let page = Page::start()?;
        let mut chrome = Command::new(&options.chrome)
            .args([
                "--no-startup-window",
                "--no-first-run",
                "--no-default-browser-check",
                "--disable-background-networking",
                "--disable-component-update",
                "--disable-sync",
                "--metrics-recording-only",
                "--noerrdialogs",
                "--remote-debugging-port=0",
                "--remote-debugging-address=127.0.0.1",
            ])
            .arg(format!(
                "--user-data-dir={}",
                root.join("profile").display()
            ))
            .arg(format!("--load-extension={}", options.extension.display()))
            .arg(format!(
                "--disable-extensions-except={}",
                options.extension.display()
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| e.to_string())?;
        let deadline = Instant::now() + Duration::from_secs(25);
        let port_file = root.join("profile/DevToolsActivePort");
        let contents = loop {
            if let Ok(text) = std::fs::read_to_string(&port_file) {
                break text;
            }
            if chrome.try_wait().map_err(|e| e.to_string())?.is_some() {
                return Err("Chrome exited before CDP startup".into());
            }
            if Instant::now() > deadline {
                return Err("Chrome CDP startup timed out".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        let mut lines = contents.lines();
        let port: u16 = lines
            .next()
            .ok_or("missing CDP port")?
            .parse()
            .map_err(|_| "invalid CDP port")?;
        let path = lines
            .next()
            .filter(|p| p.starts_with("/devtools/browser/"))
            .ok_or("invalid CDP path")?;
        let mut cdp = Cdp::connect(port, path)?;
        let version = cdp.call("Browser.getVersion", json!({}), None)?;
        println!("Chrome version: {}", version["product"]);
        check(
            "pinned Chrome for Testing 155.0.8059.39",
            version["product"]
                .as_str()
                .is_some_and(|s| s.ends_with("/155.0.8059.39")),
        )?;
        let outside_target = cdp.call(
            "Target.createTarget",
            json!({"url":format!("{}/outside-secret",page.origin),"background":true}),
            None,
        )?["targetId"]
            .as_str()
            .ok_or("outside fixture target missing")?
            .to_owned();
        let service_session = cdp.attach(&outside_target)?;
        cdp.call("ServiceWorker.enable", json!({}), Some(&service_session))?;
        let worker_target = loop {
            if let Some(id) = cdp.worker()? {
                break id;
            }
            if Instant::now() > deadline {
                return Err("extension worker did not appear".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        let worker_session = cdp.attach(&worker_target)?;
        let outside_id = cdp
            .eval(
                &worker_session,
                &format!(
                    "chrome.tabs.query({{}}).then(tabs => tabs.find(t => t.url === {})?.id)",
                    json!(format!("{}/outside-secret", page.origin))
                ),
            )?
            .as_i64()
            .ok_or("outside fixture Chrome tab missing")?
            .to_string();
        // Instrument only after creating the unrelated fixture. OS focus has
        // been sampled since BEFORE Chrome started, so startup is still covered.
        instrument(&mut cdp, &worker_session)?;
        while planes.user_browser.connected_epoch().is_none() {
            if Instant::now() > deadline {
                return Err("signed host did not connect to scratch bridge; check probe feature/signing/manifest discovery".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        check(
            "startup never fronted Chrome",
            !focus.changed.load(Ordering::SeqCst),
        )?;
        let origin = page.origin.clone();
        let mut driver = Live {
            planes,
            cdp,
            worker_session,
            worker_target,
            service_session,
            outside_id,
            origin: origin.clone(),
            page,
            focus,
            corr: 10,
        };
        let result = exercise(&mut driver, &origin).await;
        let focus_ok = !driver.focus.changed.load(Ordering::SeqCst);
        driver.planes.user_browser.goodbye(Route {
            channel: CHANNEL,
            epoch: EPOCH,
        });
        driver.planes.user_browser.shutdown();
        drop(listener);
        check("foreground pid never changed (10ms sampling)", focus_ok)?;
        result
    }

    #[async_trait::async_trait(?Send)]
    impl Driver for Live {
        async fn call(&mut self, mut args: Value) -> Result<(Value, usize), String> {
            args["browser"] = json!("user");
            self.corr += 1;
            let opening = frame(
                self.corr,
                CHANNEL,
                EPOCH,
                json!({"name":"browser_use","arguments":args}),
            )?;
            let (writer, mut frames) = mpsc::channel(16);
            cerebellum::handle_frame_for_test(opening, &writer, &self.planes)
                .await
                .map_err(|e| e.to_string())?;
            let mut asks = 0;
            loop {
                let response = tokio::time::timeout(Duration::from_secs(15), frames.recv())
                    .await
                    .map_err(|_| "scratch call timed out")?
                    .ok_or("scratch route closed")?;
                let body: Value =
                    serde_json::from_slice(&response.body).map_err(|e| e.to_string())?;
                if response.header.ty == FrameType::Request {
                    consent_for_fixture(&body, &self.origin)?;
                    asks += 1;
                    println!(
                        "PASS per-site card: your own Chrome, signed in as you; {} -> allow_once",
                        self.origin
                    );
                    let answer = Frame::build_with_version(
                        PROTOCOL_VERSION,
                        FrameType::Response,
                        Flags::new(false, Priority::Interactive, false),
                        response.header.channel,
                        response.header.epoch,
                        response.header.corr,
                        serde_json::to_vec(&json!({"decision":"allow_once"})).unwrap(),
                    )
                    .map_err(|e| e.to_string())?;
                    cerebellum::handle_frame_for_test(answer, &writer, &self.planes)
                        .await
                        .map_err(|e| e.to_string())?;
                } else if matches!(response.header.ty, FrameType::Response | FrameType::Error) {
                    // Beacons can arrive a turn after the tool reply. This is
                    // bounded observation, not an assumption that delivery worked.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if !ok(&body) && body["outcome"] != "closed" {
                        println!("reply: {body}");
                    }
                    return Ok((body, asks));
                }
            }
        }
        fn observe(&mut self) -> Result<Value, String> {
            let mut observation = self.cdp.eval(&self.worker_session, &format!(r#"Promise.all([chrome.tabs.query({{}}), chrome.debugger.getTargets()]).then(([tabs, targets]) => {{
              const agent = tabs.filter(t => t.groupId !== -1);
              return {{agent_tabs:agent.length, outside_group:tabs.find(t => t.id === {})?.groupId,
                agent_attached:targets.some(t => t.attached && agent.some(a => a.id === t.tabId)), focus_events:globalThis.__probeFocus}};
            }})"#, self.outside_id))?;
            let reports = self.page.reports.lock().unwrap();
            observation["clicks"] = json!(reports.0);
            observation["typed"] = json!(reports.1);
            if self.focus.changed.load(Ordering::SeqCst) {
                observation["focus_events"] = json!(1);
            }
            Ok(observation)
        }
        async fn restart(&mut self) -> Result<(), String> {
            let before = self
                .planes
                .user_browser
                .connected_epoch()
                .ok_or("no connection before worker stop")?;
            // ServiceWorker is used over the TEST browser's independent CDP
            // session, not through chrome.debugger's restricted domain set.
            self.cdp.call(
                "ServiceWorker.enable",
                json!({}),
                Some(&self.service_session),
            )?;
            let version = self
                .cdp
                .events
                .iter()
                .rev()
                .filter(|e| e["method"] == "ServiceWorker.workerVersionUpdated")
                .filter_map(|e| e["params"]["versions"].as_array())
                .flat_map(|v| v.iter())
                .find(|v| {
                    v["scriptURL"] == format!("{EXTENSION_ORIGIN}service-worker.mjs")
                        && v["runningStatus"] == "running"
                })
                .and_then(|v| v["versionId"].as_str())
                .ok_or("CDP did not report running extension worker version")?
                .to_owned();
            self.cdp.call(
                "Target.detachFromTarget",
                json!({"sessionId":self.worker_session}),
                None,
            )?;
            self.cdp.call(
                "ServiceWorker.stopWorker",
                json!({"versionId":version}),
                Some(&self.service_session),
            )?;
            let end = Instant::now() + Duration::from_secs(30);
            loop {
                let gone = self.cdp.worker()?.as_deref() != Some(self.worker_target.as_str());
                if gone && self.planes.user_browser.connected_epoch() != Some(before) {
                    break;
                }
                if Instant::now() >= end {
                    return Err("worker stop was not observed; reconnect check cannot run".into());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            check("old worker terminated and old bridge disconnected", true)?;
            // Wake the registration explicitly; this measures a worker killed
            // and restarted, not the wall-clock cadence of Chrome's alarm.
            self.cdp.call(
                "ServiceWorker.startWorker",
                json!({"scopeURL":EXTENSION_ORIGIN}),
                Some(&self.service_session),
            )?;
            loop {
                if let Some(target) = self.cdp.worker()? {
                    if self
                        .planes
                        .user_browser
                        .connected_epoch()
                        .is_some_and(|epoch| epoch != before)
                    {
                        self.worker_target = target;
                        self.worker_session = self.cdp.attach(&self.worker_target)?;
                        instrument(&mut self.cdp, &self.worker_session)?;
                        break;
                    }
                }
                if Instant::now() >= end {
                    return Err("new worker failed to reconnect".into());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Ok(())
        }
        fn outside_tab(&self) -> String {
            self.outside_id.clone()
        }
    }
}

// Offline driver doubles exercise the SAME acceptance routine as the live run.
// This is an explicit --self-test gate, so it does not require changing Cargo's
// example test-target declarations or silently relying on cargo test discovery.
struct Double {
    fault: &'static str,
    epoch: u64,
    clicked: usize,
    typed: String,
}
impl Double {
    fn new(fault: &'static str) -> Self {
        Self {
            fault,
            epoch: 1,
            clicked: 0,
            typed: String::new(),
        }
    }
}
#[async_trait::async_trait(?Send)]
impl Driver for Double {
    async fn call(&mut self, args: Value) -> Result<(Value, usize), String> {
        let mut reply = json!({"browser":"user","outcome":"ok"});
        let mut asks = 0;
        match args["action"].as_str().unwrap_or("") {
            "open_tab" => {
                reply["tab"] = json!("opaque-agent-tab");
                reply["connection_epoch"] = json!(self.epoch);
            }
            "status" => {
                reply["tabs"] = json!([{"tab":"opaque-agent-tab"}]);
                reply["connected"] = json!(true);
                reply["connection_epoch"] = json!(self.epoch);
            }
            "navigate" => {
                asks = if self.fault == "ask" { 0 } else { 1 };
            }
            "snapshot" if args["tab"] == "outside" => {
                reply["outcome"] = json!("refused");
            }
            "snapshot" => {
                asks = 1;
                reply["snapshot_id"] = json!("fresh-snapshot");
                reply["state_text"] =
                    json!("button-ref button Probe button\ninput-ref textbox Probe input");
            }
            "click" if self.epoch != 1 => {
                reply["outcome"] = json!("refused");
            }
            "click" => {
                self.clicked += 1;
            }
            "type" => {
                self.typed = args["text"].as_str().unwrap().to_owned();
            }
            "close" => {
                reply["outcome"] = json!("closed");
            }
            _ => return Err("unexpected double action".into()),
        }
        Ok((reply, asks))
    }
    fn observe(&mut self) -> Result<Value, String> {
        Ok(
            json!({"agent_attached":self.fault == "detach", "focus_events":if self.fault == "focus" {1} else {0},
            "outside_group":if self.fault == "group" {1} else {-1}, "agent_tabs":1,
            "clicks":self.clicked,"typed":self.typed}),
        )
    }
    async fn restart(&mut self) -> Result<(), String> {
        if self.fault != "epoch" {
            self.epoch += 1;
        }
        Ok(())
    }
    fn outside_tab(&self) -> String {
        "outside".into()
    }
}

fn installer_control() -> Result<(), String> {
    let scratch = Scratch::new()?;
    let host = scratch.0.join("host with spaces");
    private_fs::create_new_file(&host).map_err(|e| e.to_string())?;
    let home = scratch.0.join("home");
    let path = write_manifest(&home, &host)?;
    let actual: Value = serde_json::from_slice(&std::fs::read(&path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let expected_path = home.join("Library/Application Support/Google/Chrome/NativeMessagingHosts/com.cortexkit.cerebellum.json");
    if path != expected_path
        || actual
            != json!({"name":"com.cortexkit.cerebellum","description":"CortexKit Chrome bridge","path":host,"type":"stdio","allowed_origins":["chrome-extension://bfmlflnlaflnibiellpjjifdbcifciei/"]})
    {
        return Err(
            "manifest must pin exactly the reviewed extension, stdio host, and Chrome-only path"
                .into(),
        );
    }
    fn files(root: &Path, result: &mut Vec<PathBuf>) -> Result<(), String> {
        for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
            let path = entry.map_err(|e| e.to_string())?.path();
            if path.is_dir() {
                files(&path, result)?;
            } else {
                result.push(path);
            }
        }
        Ok(())
    }
    let mut written = Vec::new();
    files(&home, &mut written)?;
    if written != [expected_path] {
        return Err("installer wrote something other than Chrome's host manifest".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if std::fs::metadata(&path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o777
            != 0o600
        {
            return Err("manifest is not private".into());
        }
    }
    // Idempotent installation must not create a backup or a temporary file.
    write_manifest(&home, &host)?;
    Ok(())
}
fn symlink_control() -> Result<(), String> {
    #[cfg(unix)]
    {
        let scratch = Scratch::new()?;
        let host = scratch.0.join("host");
        private_fs::create_new_file(&host).map_err(|e| e.to_string())?;
        let home = scratch.0.join("home");
        private_fs::create_dir(&home).map_err(|e| e.to_string())?;
        let other = scratch.0.join("other");
        private_fs::create_dir(&other).map_err(|e| e.to_string())?;
        std::os::unix::fs::symlink(&other, home.join("Library")).map_err(|e| e.to_string())?;
        if write_manifest(&home, &host).is_ok()
            || std::fs::read_dir(&other)
                .map_err(|e| e.to_string())?
                .next()
                .is_some()
        {
            return Err("installer followed a redirected Library directory".into());
        }
    }
    Ok(())
}
fn relay_control() -> Result<(), String> {
    let origin = "http://127.0.0.1:12345";
    let card = json!({"method":"elicitation/create","params":{"kind":"consent","scope":{"browser":"user","origins":[origin]},
        "target":{"label":origin},"prompt":"Let the agent use your own Chrome, signed in as you, on this site?","options":[{"id":"allow_once"},{"id":"deny"}]}});
    consent_for_fixture(&card, origin)?;
    for mutation in ["origin", "target", "option"] {
        let mut other = card.clone();
        match mutation {
            "origin" => other["params"]["scope"]["origins"] = json!(["https://example.com"]),
            "target" => other["params"]["scope"]["browser"] = json!("own"),
            _ => other["params"]["options"] = json!([{"id":"allow_all"}]),
        }
        if consent_for_fixture(&other, origin).is_ok() {
            return Err(format!("scratch relay accepted bad {mutation}"));
        }
    }
    Ok(())
}

async fn self_test() -> Result<(), String> {
    let mut tests: Vec<(&str, Result<(), String>)> = Vec::new();
    let args = vec![
        "--chrome".into(),
        "/some/Google Chrome for Testing".into(),
        "--native-host".into(),
        "/host".into(),
        "--extension-dir".into(),
        "/extension".into(),
    ];
    let mut approved = args.clone();
    approved.push("--approve-local-probe".into());
    let parsed = options(&approved);
    let cli = if options(&args).is_err()
        && parsed.as_ref().is_ok_and(|p| {
            p.scratch.is_none()
                && p.chrome.is_absolute()
                && p.host.is_absolute()
                && p.extension.is_absolute()
        }) {
        Ok(())
    } else {
        Err("probe did not enforce explicit approval and absolute inputs".into())
    };
    tests.push(("operator_approval_is_required", cli));
    tests.push((
        "extension_key_and_id_are_pinned",
        extension_is_pinned(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../extension"))
            .and_then(|_| {
                if EXTENSION_ID == "bfmlflnlaflnibiellpjjifdbcifciei" {
                    Ok(())
                } else {
                    Err("wrong extension id".into())
                }
            }),
    ));
    tests.push((
        "installer_pins_origin_and_writes_only_chrome",
        installer_control(),
    ));
    tests.push(("installer_refuses_symlink_escape", symlink_control()));
    tests.push((
        "relay_answers_only_fixture_site_and_user_target",
        relay_control(),
    ));
    tests.push((
        "acceptance_routine_passes_with_independent_double",
        exercise(&mut Double::new(""), "http://127.0.0.1:12345").await,
    ));
    for (fault, name, expected) in [
        (
            "group",
            "acceptance_rejects_outside_group_visibility",
            "outside-group tab is invisible and stays outside",
        ),
        (
            "focus",
            "acceptance_rejects_focus_movement",
            "no Chrome tab/window activation",
        ),
        (
            "detach",
            "acceptance_rejects_attached_debugger",
            "debugger detached between actions",
        ),
        (
            "ask",
            "acceptance_rejects_skipped_per_site_ask",
            "navigation asks per site through scratch relay",
        ),
        (
            "epoch",
            "acceptance_rejects_unchanged_reconnect_epoch",
            "killed worker reconnects with a new epoch",
        ),
    ] {
        let result = exercise(&mut Double::new(fault), "http://127.0.0.1:12345").await;
        tests.push((
            name,
            if result.as_ref().err().is_some_and(|e| e == expected) {
                Ok(())
            } else {
                Err(format!(
                    "fault {fault} was not rejected at its named check: {result:?}"
                ))
            },
        ));
    }
    #[cfg(target_os = "macos")]
    tests.push((
        "scratch_process_and_directory_cleanup",
        live::cleanup_control(),
    ));
    let count = tests.len();
    let mut failed = 0;
    for (name, result) in tests {
        match result {
            Ok(()) => println!("PASS self-test {name}"),
            Err(e) => {
                failed += 1;
                println!("FAIL self-test {name}: {e}");
            }
        }
    }
    println!("user_browser_probe {}: {count} offline checks, {failed} failures; no Chrome, live profile, socket or durable journal", env!("CARGO_PKG_VERSION"));
    if failed == 0 {
        Ok(())
    } else {
        Err(format!("{failed} of {count} checks failed"))
    }
}
