//! Operator-approved, headed Chrome for Testing probe (macOS only).
//!
//! Run the prebuilt, fleet-signed example in one command, from the repository:
//! target/debug/examples/user_browser_probe --approve-local-probe \
//!   --chrome '/path/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing' \
//!   --native-host /absolute/path/ck-cerebellum-native-host --extension-dir "$PWD/extension"
//!
//! Budget: at most 180 seconds, plus up to 3 seconds for process cleanup. All
//! generated state is under /tmp. The in-process scratch cerebellum uses an
//! isolated journal and a scripted Cingulate (the consent module) in place of
//! the real one: only a card for its loopback origin is answered, with
//! allow_30m into the scratch-only grant store; no phone or personal grants are involved.
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

#[path = "user_browser_probe/fixture_http.rs"]
mod fixture_http;

const HOST: &str = "com.cortexkit.cerebellum";
const CHROME_MANIFEST_DIR: &str = "Library/Application Support/Google/Chrome/NativeMessagingHosts";
const BUDGET_SECS: u64 = 180;

// Chrome for Testing runs with a scratch HOME, so without a mock keychain
// macOS finds no login keychain there and shows "Keychain Not Found", whose
// "Reset To Defaults" button would reset the person's real keychain. The probe
// must never touch the keychain: --use-mock-keychain and a basic password
// store keep Chrome away from it entirely.
const CHROME_PROBE_ARGS: [&str; 12] = [
    "--use-mock-keychain",
    "--password-store=basic",
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
];

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
        // Eight random bytes and a short prefix keep the scratch cerebellum's
        // socket path (scratch/data/cortexkit/run/cerebellum/user-browser.sock)
        // under macOS's 104-byte sun_path limit.
        let mut bytes = [0u8; 8];
        getrandom::getrandom(&mut bytes).map_err(|e| e.to_string())?;
        let nonce: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        // Canonicalize /tmp on macOS (where it is /private/tmp), not a caller's
        // TMPDIR. No live profile, journal or runtime-directory fallback exists.
        let path = std::fs::canonicalize("/tmp")
            .map_err(|e| e.to_string())?
            .join(format!("ckub-{nonce}"));
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

/// Whether `card`, a `consent.request` the scripted Cingulate received (as
/// `{"id", "params"}`), is the per-site card for the probe's own fixture
/// origin or its explicit localhost iframe origin, so it may answer allow_30m.
fn consent_for_fixture(card: &Value, origin: &str) -> Result<(), String> {
    let p = &card["params"];
    let child_origin = origin.replace("127.0.0.1", "localhost");
    let site = p["target"]["label"].as_str().unwrap_or("");
    if p["kind"] != "consent"
        || p["scope"]["browser"] != "user"
        || ![origin, child_origin.as_str()].contains(&site)
        || p["scope"]["origins"] != json!([site])
        || p["prompt"] != "Let the agent use your own Chrome, signed in as you, on this site?"
        || !p["options"]
            .as_array()
            .is_some_and(|options| options.iter().any(|o| o["id"] == "allow_30m"))
    {
        return Err(format!(
            "scripted Cingulate refused a non-fixture or malformed site card: label {site:?}, expected origins {:?}, scope origins {}, option ids {}",
            [origin, child_origin.as_str()],
            p["scope"]["origins"],
            Value::Array(
                p["options"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .map(|option| option["id"].clone())
                    .collect()
            )
        ));
    }
    Ok(())
}

fn fixture_site_answer_line(card: &Value, origin: &str, decision: &str) -> Result<String, String> {
    consent_for_fixture(card, origin)?;
    // The iframe deliberately uses localhost rather than 127.0.0.1. Print the
    // validated card's site, not the top page's site, so its separate approval
    // cannot look like a duplicate decision for the parent origin.
    let site = card["params"]["target"]["label"]
        .as_str()
        .expect("validated fixture origin");
    Ok(format!(
        "PASS per-site card: your own Chrome, signed in as you; {site} -> {decision}"
    ))
}

fn unclaimed_handed_tab(status: &Value) -> Result<Option<String>, String> {
    if !ok(status) || status["connected"] != true {
        return Err("handover status is not connected and successful".into());
    }
    let tabs = status["tabs"]
        .as_array()
        .ok_or("handover status has no tab list")?;
    let mut candidate = None;
    for tab in tabs {
        // browser_use translates the extension's claimed/handed booleans into
        // a public claim label. The probe receives that public reply, not the
        // extension bridge inventory, so looking for the booleans would miss every tab.
        match tab["claim"].as_str() {
            Some("claimed_by_this_route") => continue,
            Some("unclaimed_handed") => {}
            _ => return Err("handover status tab has no recognized public claim label".into()),
        }
        let handle = tab["tab"]
            .as_str()
            .filter(|handle| !handle.is_empty())
            .ok_or("handed handle missing")?;
        if candidate.replace(handle.to_owned()).is_some() {
            return Err("handover status has more than one unclaimed handed tab".into());
        }
    }
    Ok(candidate)
}

#[async_trait::async_trait(?Send)]
trait Driver {
    async fn call(&mut self, args: Value) -> Result<(Value, usize), String>;
    async fn fixture_readiness(&mut self) -> Result<Value, String>;
    fn observe(&mut self) -> Result<Value, String>;
    async fn click_observation(&mut self) -> Result<Value, String>;
    fn failure_diagnostics(&mut self) -> Value;
    async fn restart(&mut self) -> Result<(), String>;
    fn outside_tab(&self) -> String;
    async fn hand_fixture(&mut self, active: bool) -> Result<String, String>;
    fn defer_site_answer(&mut self);
    fn answer_late(&mut self) -> Result<(), String>;
    fn decline_next_site_answer(&mut self);
    async fn link_observation(&mut self) -> Result<Value, String>;
}

#[derive(Default)]
struct LastReply {
    reply: Value,
    asks: usize,
}

impl LastReply {
    fn diagnostics(&self, fixture_text_allowed: bool) -> Value {
        let text = self.reply["state_text"].as_str();
        let prefix = text.filter(|_| fixture_text_allowed).map(|text| {
            let mut end = text.len().min(400);
            while !text.is_char_boundary(end) {
                end -= 1;
            }
            &text[..end]
        });
        json!({"outcome":self.reply["outcome"], "reason":self.reply["reason"],
            "ask_count":self.asks, "state_text_prefix":prefix,
            "state_text_withheld":text.is_some() && !fixture_text_allowed})
    }
}

fn fixture_pages_only(targets: &Value, origin: &str) -> bool {
    let Some(rows) = targets["targetInfos"].as_array() else {
        return false;
    };
    let mut pages = rows
        .iter()
        .filter(|target| target["type"] == "page")
        .peekable();
    pages.peek().is_some()
        && pages.all(|target| {
            target["url"] == format!("{origin}/")
                || target["url"] == format!("{origin}/outside-secret")
                || target["url"] == format!("{origin}/handed-active")
                || target["url"] == format!("{origin}/handed-background")
        })
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
        .ok_or_else(|| {
            format!(
                "snapshot lacks {name}; state_text:\n{}",
                snapshot["state_text"].as_str().unwrap_or("<missing>")
            )
        })
}

fn fixture_page_target(targets: &Value, origin: &str) -> Result<String, String> {
    let rows = targets["targetInfos"]
        .as_array()
        .ok_or("observer target list missing")?;
    let url = format!("{origin}/");
    let mut pages = rows
        .iter()
        .filter(|target| target["type"] == "page" && target["url"] == url);
    let target = pages.next().ok_or("fixture page target missing")?;
    if pages.next().is_some() {
        return Err("fixture page target is ambiguous".into());
    }
    target["targetId"]
        .as_str()
        .map(str::to_owned)
        .ok_or("fixture page target missing id".into())
}

// The supervisor reports cleanup on its own line. The probe's verdict is the
// checks above it; folding it into this line made a successful cleanup after
// a failed check read as a failed cleanup.
fn cleanup_line(cleaned: &Result<(), String>) -> String {
    match cleaned {
        Ok(()) => "PASS process-group and scratch cleanup completed".into(),
        Err(e) => format!("FAIL process-group and scratch cleanup: {e}"),
    }
}

// File the probe build of the native host appends its exit reasons to, in the
// `cerebellum` run directory beside the bridge socket. It must match
// PROBE_EXIT_LOG in crates/cerebellum-native-host/src/macos.rs.
const HOST_EXIT_LOG: &str = "native-host-exit.log";

// Lines describing why each native host process ended. The host is silent by
// design, so after a failed check this record is the only evidence of whether
// Chrome, the socket, framing or a write closed the native port.
fn host_exit_report(path: &Path) -> Vec<String> {
    match std::fs::read_to_string(path) {
        Ok(text) if !text.trim().is_empty() => text
            .lines()
            .map(|line| format!("native host exit: {line}"))
            .collect(),
        Ok(_) => vec!["native host exit: record is empty".into()],
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            vec!["native host exit: no record (no probe-build host has exited)".into()]
        }
        Err(e) => vec![format!("native host exit: record unreadable: {e}")],
    }
}

// One readable line for a console, exception or log event that CDP reported
// from the extension worker, or None for any other event. Only the extension's
// own worker is observed, so no page content is printed.
fn worker_event_line(event: &Value) -> Option<String> {
    let params = &event["params"];
    let line = match event["method"].as_str()? {
        "Runtime.consoleAPICalled" => {
            let args: Vec<String> = params["args"]
                .as_array()
                .map(|args| {
                    args.iter()
                        .map(|arg| match (&arg["value"], arg["description"].as_str()) {
                            (Value::String(text), _) => text.clone(),
                            (Value::Null, Some(description)) => description.to_owned(),
                            (value, _) => value.to_string(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            format!(
                "console.{}: {}",
                params["type"].as_str().unwrap_or("log"),
                args.join(" ")
            )
        }
        "Runtime.exceptionThrown" => {
            let details = &params["exceptionDetails"];
            format!(
                "exception: {} {}",
                details["text"].as_str().unwrap_or(""),
                details["exception"]["description"].as_str().unwrap_or("")
            )
        }
        "Log.entryAdded" => {
            let entry = &params["entry"];
            format!(
                "log.{} ({}): {}",
                entry["level"].as_str().unwrap_or("?"),
                entry["source"].as_str().unwrap_or("?"),
                entry["text"].as_str().unwrap_or("")
            )
        }
        _ => return None,
    };
    Some(line.chars().take(1000).collect())
}

async fn exercise(driver: &mut impl Driver, origin: &str) -> Result<(), String> {
    let result = exercise_checks(driver, origin).await;
    if result.is_err() {
        println!("failed-check reply: {}", driver.failure_diagnostics());
    }
    result
}

async fn exercise_checks(driver: &mut impl Driver, origin: &str) -> Result<(), String> {
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
    // Input actions need at least tier 2; tier 1 covers reads and navigation.
    let input_severity = json!({"tier":2,"credential":false,"financial":false});
    let (navigated, asks) = driver.call(json!({"action":"navigate","tab":tab,"url":format!("{origin}/"),"wait":"settle","intent":"load loopback probe","severity":severity})).await?;
    check(
        "navigation asks per site through scripted Cingulate",
        ok(&navigated) && asks == 1,
    )?;
    detached_and_unfocused(driver)?;
    wait_for_fixture(driver, std::time::Duration::from_secs(5)).await?;
    let (snapshot, asks) = driver
        .call(json!({"action":"snapshot","tab":tab,"mode":"ax"}))
        .await?;
    check(
        "snapshot reuses the fixture site's read grant",
        ok(&snapshot)
            && asks == 0
            && snapshot["state_text"].as_str().is_some_and(|s| {
                s.contains("Probe button")
                    && s.contains("Probe input")
                    && !s.contains("OUTSIDE_SECRET")
            }),
    )?;
    detached_and_unfocused(driver)?;
    let button = reference(&snapshot, "Probe button")?;
    let (clicked, _) = driver.call(json!({"action":"click","tab":tab,"ref":button,"snapshot_id":snapshot["snapshot_id"],"intent":"click fixture button","severity":input_severity})).await?;
    println!("click reply: {clicked}");
    println!("focus before click readback: {}", driver.observe()?);
    let observation = driver.click_observation().await.map_err(|error| {
        println!("click diagnostics unavailable: {error}");
        error
    })?;
    let delivered =
        ok(&clicked) && observation["beacon_clicks"] == 1 && observation["page_clicks"] == 1;
    if !delivered {
        println!("click diagnostics: {observation}");
    }
    check("click delivered to local fixture", delivered)?;
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
    let child_input = reference(&fresh, "Iframe input")?;
    let (child_typed, asks) = driver.call(json!({"action":"type","tab":tab,"ref":child_input,"text":"iframe-only","clear_first":true})).await?;
    check(
        "type delivered inside iframe fixture",
        ok(&child_typed) && asks == 1 && driver.observe()?["child_typed"] == "iframe-only",
    )?;
    detached_and_unfocused(driver)?;
    let (child_reused, asks) = driver.call(json!({"action":"type","tab":tab,"ref":child_input,"text":"iframe-reused","clear_first":true})).await?;
    check(
        "iframe typing reuses its own site grant",
        ok(&child_reused) && asks == 0 && driver.observe()?["child_typed"] == "iframe-reused",
    )?;
    detached_and_unfocused(driver)?;
    handed_checks(driver, origin).await?;
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

fn fixture_ready(observed: &Value) -> bool {
    observed["document_complete"] == true
        && observed["iframe_ready"] == true
        && observed["url_matches"] == true
}

async fn wait_for_fixture(
    driver: &mut impl Driver,
    timeout: std::time::Duration,
) -> Result<(), String> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let observed = driver.fixture_readiness().await?;
        if fixture_ready(&observed) {
            println!("fixture readiness: {observed}");
            return check("fixture document and iframe finished loading", true);
        }
        if tokio::time::Instant::now() >= deadline {
            println!("fixture readiness: {observed}");
            return check("fixture document and iframe finished loading", false);
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn handed_checks(driver: &mut impl Driver, origin: &str) -> Result<(), String> {
    for active in [true, false] {
        let tab = driver.hand_fixture(active).await?;
        let (claimed, _) = driver.call(json!({"action":"claim_tab","tab":tab})).await?;
        check("drag-in group member is handed and claimable", ok(&claimed))?;
        if active {
            let (revoked, _) = driver
                .call(json!({"action":"revoke_access","origin":origin}))
                .await?;
            check(
                "scratch site grant revoked before late-answer check",
                revoked["outcome"] == "revoked",
            )?;
            driver.defer_site_answer();
            let (pending, asks) = driver
                .call(json!({"action":"snapshot","tab":tab,"mode":"ax"}))
                .await?;
            check(
                "read site card detaches before late allow_30m",
                pending["outcome"] == "consent_pending" && asks == 1,
            )?;
            driver.answer_late()?;
        }
        let (first, asks) = driver
            .call(json!({"action":"snapshot","tab":tab,"mode":"ax"}))
            .await?;
        check(
            "late allow_30m covers a different action without a new card",
            ok(&first) && asks == 0,
        )?;
        let link = reference(&first, "Probe link")?;
        check(
            "user refs use short e-number names",
            link.starts_with('e')
                && link.len() < 10
                && link[1..].chars().all(|c| c.is_ascii_digit()),
        )?;
        let (second, asks) = driver
            .call(json!({"action":"snapshot","tab":tab,"mode":"ax"}))
            .await?;
        check(
            "short refs stay stable across snapshots",
            ok(&second) && asks == 0 && reference(&second, "Probe link")? == link,
        )?;
        let (clicked, asks) = driver.call(json!({"action":"click","tab":tab,"ref":link,"snapshot_id":second["snapshot_id"],"intent":"click visible handed fixture link","severity":{"tier":2,"credential":false,"financial":false}})).await?;
        check(
            "late read allow_30m covers clicking without a new card",
            ok(&clicked) && asks == 0,
        )?;
        let observation = driver.link_observation().await?;
        println!("handed link diagnostics: {observation}; reply: {clicked}");
        check(
            if active {
                "visible link delivered on handed active tab"
            } else {
                "visible link delivered on handed background tab"
            },
            ok(&clicked)
                && asks == 0
                && observation["page_links"] == 1
                && observation["active"] == active,
        )?;
        detached_and_unfocused(driver)?;
        if active {
            driver.decline_next_site_answer();
            let submit = reference(&second, "Probe submit")?;
            let (refused, asks) = driver.call(json!({"action":"click","tab":tab,"ref":submit,"snapshot_id":second["snapshot_id"],"intent":"submit fixture form","severity":{"tier":3,"credential":false,"financial":false}})).await?;
            check(
                "form submit still needs a separate approval",
                refused["reason"] == "consent_declined" && asks == 1,
            )?;
            detached_and_unfocused(driver)?;
        }
    }
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
    use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};
    use subc_protocol::session::ModuleControlRequest;
    use subc_protocol::{
        BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
    };
    use tokio::sync::mpsc;

    /// A scripted Cingulate, the consent module, shared with the integration
    /// tests. The scratch cerebellum raises its per-site card there, and the
    /// probe answers it; nothing is sent back on the probe's own route.
    #[allow(dead_code)]
    mod cingulate {
        include!("../tests/support/cingulate.rs");
    }
    const PROBE_AGENT: &str = "pj-user-browser-probe";

    fn verify(path: &Path, requirement: &str) -> Result<(), String> {
        // codesign reads -R as a requirement FILE unless the text starts with
        // "=", so an inline requirement must carry that prefix.
        let status = Command::new("/usr/bin/codesign")
            .args(["--verify", "--strict", "-R", &format!("={requirement}")])
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
        let cleaned = group.cleanup().and_then(|()| scratch.cleanup());
        println!("{}", cleanup_line(&cleaned));
        outcome.and(cleaned)
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
        /// Set once the probe's own Chrome has been the frontmost app.
        changed: Arc<AtomicBool>,
        /// The probe's Chrome pid, or 0 before it is spawned.
        watched: Arc<AtomicI32>,
        events: Arc<Mutex<Vec<Value>>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Focus {
        /// Samples the foreground app every 10 ms. Every transition is
        /// recorded for diagnosis, but only the probe's own Chrome coming to
        /// the front counts as a failure: the operator switching between their
        /// own apps while the probe runs is not something the probe caused.
        fn start() -> Result<Self, String> {
            let initial =
                cerebellum_macos::frontmost_process_id().ok_or("cannot observe foreground app")?;
            let stop = Arc::new(AtomicBool::new(false));
            let changed = Arc::new(AtomicBool::new(false));
            let watched = Arc::new(AtomicI32::new(0));
            let flag = stop.clone();
            let result = changed.clone();
            let chrome = watched.clone();
            let events = Arc::new(Mutex::new(Vec::new()));
            let recorded = events.clone();
            let thread = std::thread::spawn(move || {
                let mut previous = Some(initial);
                while !flag.load(Ordering::SeqCst) {
                    let current = cerebellum_macos::frontmost_process_id();
                    let chrome_pid = chrome.load(Ordering::SeqCst);
                    if chrome_pid != 0 && current == Some(chrome_pid) {
                        result.store(true, Ordering::SeqCst);
                    }
                    if current != previous {
                        let event =
                            json!({"at":wall_millis(),"previous_pid":previous,"pid":current});
                        eprintln!("foreground transition: {event}");
                        let mut rows = recorded.lock().unwrap();
                        if rows.len() < 64 {
                            rows.push(event);
                        }
                        previous = current;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            Ok(Self {
                stop,
                changed,
                watched,
                events,
                thread: Some(thread),
            })
        }

        /// Give the sampler the pid of the Chrome this probe launched. From now
        /// on, that Chrome becoming the frontmost app fails the probe: driving
        /// the person's browser must never pull it in front of their work.
        fn watch(&self, chrome_pid: u32) {
            self.watched.store(chrome_pid as i32, Ordering::SeqCst);
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
        reports: Arc<Mutex<(usize, String, String)>>,
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
            let reports = Arc::new(Mutex::new((0, String::new(), String::new())));
            let child_origin = origin.replace("127.0.0.1", "localhost");
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
                    let _ = fixture_http::serve(&mut stream, &child_origin, &state);
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
            if matches!(method, "Target.attachToTarget" | "Target.detachFromTarget") {
                println!(
                    "probe CDP timing: {}",
                    json!({"at":wall_millis(),"stage":"start","method":method,"params":params})
                );
            }
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
                    if matches!(method, "Target.attachToTarget" | "Target.detachFromTarget") {
                        println!(
                            "probe CDP timing: {}",
                            json!({"at":wall_millis(),"stage":"done","method":method})
                        );
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
        consent: cingulate::ScriptedCarrier,
        cdp: Cdp,
        worker_session: String,
        worker_target: String,
        service_session: String,
        outside_id: String,
        active_id: String,
        handed_id: Option<i64>,
        handed_url: String,
        defer_answer: bool,
        late_card: Option<String>,
        decline_answer: bool,
        origin: String,
        page: Page,
        focus: Focus,
        corr: u64,
        /// How many of the scripted Cingulate's cards have been answered.
        cards_seen: usize,
        last_reply: LastReply,
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
            call_mode: None,
            route_channel: CHANNEL,
            epoch: EPOCH,
            target: RouteTarget::ToolProvider {
                module_id: "cerebellum".into(),
            },
            identity: BindIdentity::new(root.to_owned(), "probe", "user-browser-probe"),
            principal: cerebellum::session_caller_principal_for_test(),
            consumer_capabilities: None,
            admission_facts: Some(json!({"agentProjectId":PROBE_AGENT,"sessionKind":"primary",
                "effectiveCapabilityScope":["*"],"browserControlOperations":["browser.launch","browser.status","browser.close"]})),
            // The card is raised with Cingulate only from a call under an
            // agent session's scope.
            scope: Some(cingulate::stamp(PROBE_AGENT)),
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
        // Collect the worker's console and exception events so a failed check
        // can show them. Enabling Runtime also replays console messages the
        // worker logged before this point. Log carries Chrome's own messages,
        // such as an unchecked native-port error; it is best effort because
        // not every Chrome build offers it on worker targets.
        cdp.call("Runtime.enable", json!({}), Some(session))?;
        #[cfg(feature = "chrome-for-testing-parent-probe")]
        cdp.eval(session, "globalThis.__ckProbeReadDiagnostics = true")?;
        let _ = cdp.call("Log.enable", json!({}), Some(session));
        cdp.eval(
            session,
            r#"(() => {
          globalThis.__probeFocus = 0;
          globalThis.__probeFocusEvents = [];
          globalThis.__probePhase = 'startup';
          globalThis.__probeMembership = [];
          const focus = (event, details) => {
            globalThis.__probeFocus++;
            const row = {at:Date.now(), event, phase:globalThis.__probePhase, ...details};
            if (globalThis.__probeFocusEvents.length < 64) globalThis.__probeFocusEvents.push(row);
            console.info('Agent probe focus: ' + JSON.stringify(row));
          };
          chrome.tabs.onActivated.addListener(info => focus('tab_activated', {tabId:info.tabId,windowId:info.windowId}));
          chrome.windows.onFocusChanged.addListener(windowId => focus('window_focus', {windowId}));
          const note = (event, details) => {
            const rows = globalThis.__probeMembership;
            if (rows.length >= 32) rows.shift();
            rows.push({event, ...details});
          };
          chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
            if (tabId !== globalThis.__probeHandTab) return;
            note('tabs.onUpdated', {tabId, keys:Object.keys(change), deltaGroupId:change.groupId ?? null,
              groupId:tab?.groupId ?? null, windowId:tab?.windowId ?? null, active:tab?.active ?? null});
          });
          chrome.tabs.onMoved.addListener((tabId, move) => {
            if (tabId === globalThis.__probeHandTab) note('tabs.onMoved', {tabId, ...move});
          });
          chrome.tabGroups.onUpdated.addListener(group => {
            if (group.id === globalThis.__probeHandGroup) note('tabGroups.onUpdated', {groupId:group.id, windowId:group.windowId});
          });
          return true;
        })()"#,
        )?;
        Ok(())
    }

    fn wall_millis() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
    }

    // Print the extension's own console before shutdown on success as well as
    // failure, so the group-adoption decision can be matched to Chrome's events.
    fn print_worker_events(cdp: &mut Cdp, session: &str) {
        // Events that arrived after the last reply are still unread on the
        // socket; a trivial call drains them into the event buffer.
        let _ = cdp.call("Runtime.evaluate", json!({"expression":"0"}), Some(session));
        let lines: Vec<String> = cdp.events.iter().filter_map(worker_event_line).collect();
        if lines.is_empty() {
            println!("worker: no console, exception or log events");
        }
        // Keep all timestamped probe metadata, including initial blank-page
        // failures; a tail alone can make an old error look post-click.
        for (index, line) in lines.iter().enumerate() {
            if index >= lines.len().saturating_sub(50)
                || line.contains("Agent probe read:")
                || line.contains("Agent probe focus:")
            {
                println!("worker {line}");
            }
        }
    }

    // Prints the native host's exit record once, either when asked after a
    // failed check or when a startup step fails and returns early. Printing
    // happens while the scratch tree still exists; the supervisor removes it.
    struct HostExits {
        path: PathBuf,
        armed: bool,
    }
    impl HostExits {
        fn print(&mut self) {
            if std::mem::take(&mut self.armed) {
                for line in host_exit_report(&self.path) {
                    println!("{line}");
                }
            }
        }
    }
    impl Drop for HostExits {
        fn drop(&mut self) {
            self.print();
        }
    }
    async fn child(options: &Options, root: &Path) -> Result<(), String> {
        let tmp = std::fs::canonicalize("/tmp").map_err(|e| e.to_string())?;
        let canonical = std::fs::canonicalize(root).map_err(|e| e.to_string())?;
        if canonical.parent() != Some(tmp.as_path())
            || !canonical
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("ckub-"))
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
        let consent = cingulate::ScriptedCarrier::default();
        let mut planes = consent.install(Planes::with_browser_config_journaling(
            Arc::new(HealthState::new()),
            Some(config),
            JournalPersistence::Isolated,
        ));
        // An isolated plane has no machine identity and cannot record site
        // consent. Supply a scratch-only store so the probe can exercise the
        // same temporary-grant path as a durable installation.
        planes.management = Arc::new(
            cerebellum::management::ManagementPlane::new(Arc::new(
                cerebellum::management::PlatformResolver::new(),
            ))
            .with_agent_grants(Arc::new(
                cerebellum::agent_grants::AgentGrants::in_memory(Some("user-browser-probe".into())),
            )),
        );
        bind(&planes, root).await?;
        let listener =
            BridgeListener::bind(planes.user_browser.clone()).map_err(|e| e.to_string())?;
        let focus = Focus::start()?;
        let page = Page::start()?;
        let mut chrome = Command::new(&options.chrome)
            .args(CHROME_PROBE_ARGS)
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
        focus.watch(chrome.id());
        println!(
            "Chrome process: {}",
            json!({"at":wall_millis(),"pid":chrome.id()})
        );
        // Declared after the listener so it is dropped first (Rust drops
        // locals in reverse order). On an early return the host's exit record
        // is printed before the listener drops and tears down the bridge;
        // that teardown would make the host exit too, for a reason unrelated
        // to the failure.
        let mut host_exits = HostExits {
            path: run.join("cerebellum").join(HOST_EXIT_LOG),
            armed: true,
        };
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
        // The first page in this scratch-only window is selected by Chrome.
        // Keep that selection; subsequent fixtures are created in the background.
        cdp.call(
            "Target.createTarget",
            json!({"url":format!("{}/handed-active",page.origin),"background":true}),
            None,
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
        // A freshly started extension worker can be attached before Chrome has
        // installed its extension bindings, and an evaluation then sees no
        // `chrome`. Wait for the bindings before the first real query.
        loop {
            let ready = cdp.eval(
                &worker_session,
                "typeof chrome !== 'undefined' && !!chrome.tabs",
            );
            if matches!(ready, Ok(Value::Bool(true))) {
                break;
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "extension bindings never appeared in the worker: {ready:?}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
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
        let active_id = cdp
            .eval(
                &worker_session,
                &format!(
                    "chrome.tabs.query({{}}).then(tabs => tabs.find(t => t.url === {})?.id)",
                    json!(format!("{}/handed-active", page.origin))
                ),
            )?
            .as_i64()
            .ok_or("active fixture Chrome tab missing")?
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
            consent,
            cdp,
            worker_session,
            worker_target,
            service_session,
            outside_id,
            active_id,
            handed_id: None,
            handed_url: String::new(),
            defer_answer: false,
            late_card: None,
            decline_answer: false,
            origin: origin.clone(),
            page,
            focus,
            corr: 10,
            cards_seen: 0,
            last_reply: LastReply::default(),
        };
        let result = exercise(&mut driver, &origin).await;
        let session = driver.worker_session.clone();
        print_worker_events(&mut driver.cdp, &session);
        if result.is_err() {
            host_exits.print();
        }
        host_exits.armed = false;
        let focus_ok = !driver.focus.changed.load(Ordering::SeqCst);
        driver.planes.user_browser.goodbye(Route {
            channel: CHANNEL,
            epoch: EPOCH,
        });
        driver.planes.user_browser.shutdown();
        drop(listener);
        check(
            "the probe's Chrome never came to the front (10ms sampling)",
            focus_ok,
        )?;
        result
    }

    #[async_trait::async_trait(?Send)]
    impl Driver for Live {
        async fn call(&mut self, mut args: Value) -> Result<(Value, usize), String> {
            let action = args["action"].as_str().unwrap_or("unknown").to_owned();
            self.cdp.eval(
                &self.worker_session,
                &format!(
                    "globalThis.__probePhase = {}",
                    json!(format!("tool:{action}"))
                ),
            )?;
            println!(
                "tool timing: {}",
                json!({"at":wall_millis(),"stage":"start","action":action})
            );
            let deferred = std::mem::take(&mut self.defer_answer);
            let decline = std::mem::take(&mut self.decline_answer);
            let calls_before = self.consent.calls().len();
            if deferred {
                self.consent.defer_awaits();
            }
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
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                // Answer each card the call raised with the scripted
                // Cingulate, after checking it is the fixture's own site card.
                for card in self.consent.questions().into_iter().skip(self.cards_seen) {
                    self.cards_seen += 1;
                    let decision = if decline { "deny" } else { "allow_30m" };
                    let line = fixture_site_answer_line(&card, &self.origin, decision)?;
                    asks += 1;
                    println!("{line}");
                    let id = card["id"].as_str().ok_or("the card has no id")?;
                    if deferred {
                        self.late_card = Some(id.to_owned());
                    } else if !self.consent.answer_id(
                        id,
                        cerebellum::cingulate_client::ScriptedAnswer::Answered(
                            json!({"decision":decision}),
                        ),
                    ) {
                        return Err(format!("the scripted Cingulate does not hold card {id}"));
                    }
                }
                if deferred
                    && self
                        .consent
                        .calls()
                        .iter()
                        .skip(calls_before)
                        .any(|(method, _)| method == "consent.await")
                {
                    // Return a pending await deterministically rather than spend
                    // the live probe's budget waiting two minutes for its timer.
                    self.consent.resume_awaits();
                }
                let response = match frames.try_recv() {
                    Ok(response) => response,
                    Err(mpsc::error::TryRecvError::Empty) => {
                        if Instant::now() > deadline {
                            return Err("scratch call timed out".into());
                        }
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        continue;
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        return Err("scratch route closed".into())
                    }
                };
                let body: Value =
                    serde_json::from_slice(&response.body).map_err(|e| e.to_string())?;
                if response.header.ty == FrameType::Request {
                    return Err(format!(
                        "the scratch cerebellum sent a request back on the probe's route: {body}"
                    ));
                }
                if matches!(response.header.ty, FrameType::Response | FrameType::Error) {
                    // Beacons can arrive a turn after the tool reply. This is
                    // bounded observation, not an assumption that delivery worked.
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    if !ok(&body) && body["outcome"] != "closed" {
                        println!("reply: {body}");
                    }
                    self.last_reply = LastReply {
                        reply: body.clone(),
                        asks,
                    };
                    println!(
                        "tool timing: {}",
                        json!({"at":wall_millis(),"stage":"done","action":action})
                    );
                    return Ok((body, asks));
                }
            }
        }
        fn observe(&mut self) -> Result<Value, String> {
            let mut observation = self.cdp.eval(&self.worker_session, &format!(r#"Promise.all([chrome.tabs.query({{}}), chrome.debugger.getTargets(), chrome.windows.getAll()]).then(([tabs, targets, windows]) => {{
              const agent = tabs.filter(t => t.groupId !== -1);
              return {{agent_tabs:agent.length, outside_group:tabs.find(t => t.id === {})?.groupId,
                agent_attached:targets.some(t => t.attached && agent.some(a => a.id === t.tabId)), focus_events:globalThis.__probeFocus, chrome_focus_events:globalThis.__probeFocusEvents,
                active_tabs:tabs.filter(t => t.active).map(t => ({{tabId:t.id,windowId:t.windowId,groupId:t.groupId}})), windows:windows.map(w => ({{windowId:w.id,focused:w.focused}}))}};
            }})"#, self.outside_id))?;
            let reports = self.page.reports.lock().unwrap();
            observation["clicks"] = json!(reports.0);
            observation["typed"] = json!(reports.1);
            observation["child_typed"] = json!(reports.2);
            if self.focus.changed.load(Ordering::SeqCst) {
                observation["focus_events"] = json!(1);
            }
            observation["foreground_events"] = json!(self.focus.events.lock().unwrap().clone());
            if observation["focus_events"] != 0 {
                println!("focus attribution: {observation}");
            }
            Ok(observation)
        }
        async fn fixture_readiness(&mut self) -> Result<Value, String> {
            self.cdp.eval(
                &self.worker_session,
                "globalThis.__probePhase = 'probe:fixture_readiness'",
            )?;
            let targets = self.cdp.call("Target.getTargets", json!({}), None)?;
            let target = fixture_page_target(&targets, &self.origin)?;
            let session = self.cdp.attach(&target)?;
            // This observer-only read is restricted to the scratch fixture. The
            // child signals readiness after its input and load handler exist.
            let result = self.cdp.eval(&session, &format!(r#"({{document_complete:document.readyState === 'complete', iframe_ready:window.__probeIframeReady === true, url_matches:location.href === {}}})"#, json!(format!("{}/", self.origin))));
            let detached = self.cdp.call(
                "Target.detachFromTarget",
                json!({"sessionId":session}),
                None,
            );
            detached?;
            result
        }
        async fn click_observation(&mut self) -> Result<Value, String> {
            self.cdp.eval(
                &self.worker_session,
                "globalThis.__probePhase = 'probe:click_readback'",
            )?;
            // The page counter records handler execution independently of the
            // beacon, which can arrive after the tool has acknowledged input.
            let deadline = Instant::now() + Duration::from_secs(2);
            while self.page.reports.lock().unwrap().0 == 0 && Instant::now() < deadline {
                tokio::time::sleep(
                    Duration::from_millis(20)
                        .min(deadline.saturating_duration_since(Instant::now())),
                )
                .await;
            }
            let targets = self.cdp.call("Target.getTargets", json!({}), None)?;
            let target = fixture_page_target(&targets, &self.origin)?;
            // Use the test browser's own page session, not extension evaluation
            // or chrome.debugger. Detach even when evaluation fails so this
            // observer cannot change the next action's attachment baseline.
            let session = self.cdp.attach(&target)?;
            let result = self.cdp.eval(
                &session,
                r#"(() => {
                    const button = document.querySelector('[aria-label="Probe button"]');
                    return {visibilityState: document.visibilityState,
                        innerWidth, innerHeight, devicePixelRatio, scrollX, scrollY, buttonRect: button?.getBoundingClientRect().toJSON(),
                        page_clicks: window.__clicks, hasFocus: document.hasFocus()};
                })()"#,
            );
            let metrics = self
                .cdp
                .call("Page.getLayoutMetrics", json!({}), Some(&session));
            let detached = self.cdp.call(
                "Target.detachFromTarget",
                json!({"sessionId":session}),
                None,
            );
            let mut observation = result?;
            detached?;
            observation["metrics"] = metrics?;
            observation["beacon_clicks"] = json!(self.page.reports.lock().unwrap().0);
            Ok(observation)
        }
        fn failure_diagnostics(&mut self) -> Value {
            // The scratch browser should contain only our loopback fixture pages.
            // Verify that through its own CDP observer before printing any text;
            // unknown targets or a failed provenance check withhold the prefix.
            let fixture_text_allowed = self
                .cdp
                .call("Target.getTargets", json!({}), None)
                .is_ok_and(|targets| fixture_pages_only(&targets, &self.origin));
            self.last_reply.diagnostics(fixture_text_allowed)
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
        async fn hand_fixture(&mut self, active: bool) -> Result<String, String> {
            let url = format!(
                "{}/handed-{}",
                self.origin,
                if active { "active" } else { "background" }
            );
            // Move the fixture through Chrome's group API, not the extension's
            // adoption helper. Record the actual event shapes instead of assuming
            // Chrome reports membership in an onUpdated groupId delta.
            let expression = format!(
                r#"(async () => {{
                const saved = (await chrome.storage.session.get('agentGroup')).agentGroup;
                if (!saved) throw new Error('probe Agent group missing');
                const tab = {tab};
                if (tab.active !== {active}) throw new Error('fixture active state differs; probe never switches tabs');
                globalThis.__probeHandTab = tab.id;
                globalThis.__probeHandGroup = saved.id;
                globalThis.__probeMembership = [];
                globalThis.__probeGroupMove = {{tabId:tab.id, beforeGroupId:tab.groupId, active:tab.active, windowId:tab.windowId}};
                await chrome.tabs.group({{groupId:saved.id, tabIds:[tab.id]}});
                const grouped = await chrome.tabs.get(tab.id);
                Object.assign(globalThis.__probeGroupMove, {{afterGroupId:grouped.groupId, afterWindowId:grouped.windowId, afterActive:grouped.active}});
                return tab.id;
            }})()"#,
                tab = if active {
                    format!("await chrome.tabs.get({})", self.active_id)
                } else {
                    format!(
                        "await chrome.tabs.create({{url:{}, active:false}})",
                        json!(url)
                    )
                }
            );
            self.handed_id = self.cdp.eval(&self.worker_session, &expression)?.as_i64();
            self.handed_url = url;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let (status, _) = self.call(json!({"action":"status"})).await?;
                let member = unclaimed_handed_tab(&status);
                // Handover can finish before the fixture's HTTP load. Wait for
                // this created tab, not for an agent snapshot to happen to pass.
                let readiness = self.cdp.eval(&self.worker_session, &format!("chrome.tabs.get({}).then(tab => ({{url_matches:tab.url === {}, complete:tab.status === 'complete'}}))", self.handed_id.ok_or("handed fixture Chrome id missing")?, json!(self.handed_url)))?;
                let ready = readiness["url_matches"] == true && readiness["complete"] == true;
                let timed_out = Instant::now() > deadline;
                if member.as_ref().is_ok_and(Option::is_some) && ready
                    || member.is_err()
                    || timed_out
                {
                    println!("handover fixture readiness: {readiness}");
                    println!("handover public status: {status}");
                    let observed = self.cdp.eval(&self.worker_session, r#"(async () => {
                        const saved = (await chrome.storage.session.get('agentGroup')).agentGroup;
                        const tabs = saved ? await chrome.tabs.query({groupId:saved.id, windowId:saved.windowId}) : [];
                        return {move:globalThis.__probeGroupMove, events:globalThis.__probeMembership,
                            recordedGroup:saved ? {id:saved.id, windowId:saved.windowId} : null,
                            members:tabs.map(tab => ({id:tab.id, groupId:tab.groupId, windowId:tab.windowId, active:tab.active}))};
                    })()"#);
                    match observed {
                        Ok(observed) => println!("handover membership diagnostics: {observed}"),
                        Err(error) => {
                            println!("handover membership diagnostics unavailable: {error}")
                        }
                    }
                }
                if let Some(handle) = member? {
                    if ready {
                        return Ok(handle);
                    }
                    if timed_out {
                        return Err(
                            "handed fixture did not finish loading at its expected URL".into()
                        );
                    }
                }
                if timed_out {
                    return Err("drag-in member never appeared as handed".into());
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        fn defer_site_answer(&mut self) {
            self.defer_answer = true;
        }
        fn decline_next_site_answer(&mut self) {
            self.decline_answer = true;
        }
        fn answer_late(&mut self) -> Result<(), String> {
            let id = self.late_card.take().ok_or("late site card missing")?;
            if !self.consent.answer_id(
                &id,
                cerebellum::cingulate_client::ScriptedAnswer::Answered(
                    json!({"decision":"allow_30m"}),
                ),
            ) {
                return Err("late site answer could not be recorded".into());
            }
            Ok(())
        }
        async fn link_observation(&mut self) -> Result<Value, String> {
            let targets = self.cdp.call("Target.getTargets", json!({}), None)?;
            let target = targets["targetInfos"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|target| target["type"] == "page" && target["url"] == self.handed_url)
                .and_then(|target| target["targetId"].as_str())
                .ok_or("handed page target missing")?;
            let session = self.cdp.attach(target)?;
            let result = self.cdp.eval(&session, "({page_links:window.__links, linkRect:document.querySelector('a')?.getBoundingClientRect().toJSON(), scrollX, scrollY, devicePixelRatio})");
            let metrics = self
                .cdp
                .call("Page.getLayoutMetrics", json!({}), Some(&session));
            let detached = self.cdp.call(
                "Target.detachFromTarget",
                json!({"sessionId":session}),
                None,
            );
            let mut observation = result?;
            observation["metrics"] = metrics?;
            detached?;
            observation["active"] = self.cdp.eval(
                &self.worker_session,
                &format!(
                    "chrome.tabs.get({}).then(tab => tab.active)",
                    self.handed_id.ok_or("handed tab id missing")?
                ),
            )?;
            Ok(observation)
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
    child_typed: String,
    click_observations: usize,
    last_reply: LastReply,
    failure: Option<Value>,
    handed_active: bool,
    link_clicks: usize,
    deferred: bool,
    late_answered: bool,
    decline_answer: bool,
    fixture_polls: usize,
}
impl Double {
    fn new(fault: &'static str) -> Self {
        Self {
            fault,
            epoch: 1,
            clicked: 0,
            typed: String::new(),
            child_typed: String::new(),
            click_observations: 0,
            last_reply: LastReply::default(),
            failure: None,
            handed_active: false,
            link_clicks: 0,
            deferred: false,
            late_answered: false,
            decline_answer: false,
            fixture_polls: 0,
        }
    }
}
#[async_trait::async_trait(?Send)]
impl Driver for Double {
    async fn call(&mut self, args: Value) -> Result<(Value, usize), String> {
        let mut reply = json!({"browser":"user","outcome":"ok"});
        let mut asks = 0;
        let decline = std::mem::take(&mut self.decline_answer);
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
            "claim_tab" => {
                if self.fault == "drag_in" {
                    reply["outcome"] = json!("refused");
                }
            }
            "revoke_access" => {
                reply["outcome"] = json!("revoked");
            }
            "open_grant" => {
                asks = 1;
                if self.deferred {
                    reply["outcome"] = json!("consent_pending");
                }
            }
            "snapshot" if args["tab"] == "outside" => {
                reply["outcome"] = json!("refused");
            }
            "snapshot" if self.deferred => {
                asks = 1;
                reply["outcome"] = json!("consent_pending");
            }
            "snapshot" => {
                if self.fixture_polls < 2 {
                    return Err("snapshot reached the fixture before its iframe was ready".into());
                }
                asks = 0;
                reply["snapshot_id"] = json!("fresh-snapshot");
                reply["state_text"] =
                    json!("e1 button Probe button\ne2 textbox Probe input\ne3 textbox Iframe input\ne4 link Probe link\ne5 button Probe submit");
                if self.fault == "long_refs" {
                    reply["state_text"] = json!("e1 button Probe button\ne2 textbox Probe input\ne3 textbox Iframe input\nur12345678901234567890123456789012 link Probe link");
                }
                if self.late_answered && self.fault == "late_card" {
                    asks = 1;
                }
                if self.fault == "snapshot_text" {
                    reply["state_text"] = json!("fixture-only".repeat(50));
                }
            }
            "click" if self.epoch != 1 => {
                reply["outcome"] = json!("refused");
            }
            "click" => {
                if args["severity"]["tier"] == 3 && self.fault != "submit_without_card" {
                    asks = 1;
                    if decline {
                        reply["outcome"] = json!("refused");
                        reply["reason"] = json!("consent_declined");
                    }
                } else if args["ref"] == "e4" {
                    if self.late_answered && self.fault == "read_tier_one" {
                        asks = 1;
                    }
                    if self.fault
                        != (if self.handed_active {
                            "active_link"
                        } else {
                            "background_link"
                        })
                    {
                        self.link_clicks += 1;
                    }
                } else if self.fault != "missed_click" {
                    self.clicked += 1;
                }
            }
            "type" => {
                if args["ref"] == "e3" {
                    asks = if self.child_typed.is_empty() || self.fault == "iframe_repeat_card" {
                        1
                    } else {
                        0
                    };
                    if self.fault != "iframe" {
                        self.child_typed = args["text"].as_str().unwrap().to_owned();
                    }
                } else {
                    self.typed = args["text"].as_str().unwrap().to_owned();
                }
            }
            "close" => {
                reply["outcome"] = json!("closed");
            }
            _ => return Err("unexpected double action".into()),
        }
        self.last_reply = LastReply {
            reply: reply.clone(),
            asks,
        };
        Ok((reply, asks))
    }
    async fn fixture_readiness(&mut self) -> Result<Value, String> {
        self.fixture_polls += 1;
        Ok(json!({"document_complete":true,"url_matches":true,
            "iframe_ready":self.fixture_polls >= 2 && self.fault != "iframe_unready"}))
    }
    fn observe(&mut self) -> Result<Value, String> {
        Ok(
            json!({"agent_attached":self.fault == "detach", "focus_events":if self.fault == "focus" {1} else {0},
            "outside_group":if self.fault == "group" {1} else {-1}, "agent_tabs":1,
            "clicks":self.clicked,"typed":self.typed,"child_typed":self.child_typed}),
        )
    }
    async fn click_observation(&mut self) -> Result<Value, String> {
        self.click_observations += 1;
        Ok(
            json!({"visibilityState":"hidden","innerWidth":800,"innerHeight":600,
            "buttonRect":{"x":8,"y":8,"width":100,"height":20},"hasFocus":false,
            "page_clicks":self.clicked,
            "beacon_clicks":if self.fault == "missed_beacon" {0} else {self.clicked}}),
        )
    }
    fn failure_diagnostics(&mut self) -> Value {
        let diagnostics = self.last_reply.diagnostics(true);
        self.failure = Some(diagnostics.clone());
        diagnostics
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
    async fn hand_fixture(&mut self, active: bool) -> Result<String, String> {
        self.handed_active = active;
        self.link_clicks = 0;
        Ok(if active {
            "handed-active"
        } else {
            "handed-background"
        }
        .into())
    }
    fn defer_site_answer(&mut self) {
        self.deferred = true;
    }
    fn decline_next_site_answer(&mut self) {
        self.decline_answer = true;
    }
    fn answer_late(&mut self) -> Result<(), String> {
        self.deferred = false;
        self.late_answered = true;
        Ok(())
    }
    async fn link_observation(&mut self) -> Result<Value, String> {
        Ok(json!({"page_links":self.link_clicks,"active":self.handed_active}))
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
fn cingulate_answer_control() -> Result<(), String> {
    let origin = "http://127.0.0.1:12345";
    let card = json!({"id":"el_1","params":{"kind":"consent","scope":{"browser":"user","origins":[origin]},
        "target":{"label":origin},"prompt":"Let the agent use your own Chrome, signed in as you, on this site?","options":[{"id":"allow_30m"},{"id":"deny"}]}});
    consent_for_fixture(&card, origin)?;
    for mutation in ["origin", "target", "option"] {
        let mut other = card.clone();
        match mutation {
            "origin" => other["params"]["scope"]["origins"] = json!(["https://example.com"]),
            "target" => other["params"]["scope"]["browser"] = json!("own"),
            _ => other["params"]["options"] = json!([{"id":"allow_all"}]),
        }
        if consent_for_fixture(&other, origin).is_ok() {
            return Err(format!("scripted Cingulate accepted bad {mutation}"));
        }
    }
    let mut deny_only = card.clone();
    deny_only["params"]["options"] = json!([{"id":"deny"}]);
    let error = consent_for_fixture(&deny_only, origin).unwrap_err();
    for detail in [
        origin,
        "http://localhost:12345",
        "label",
        "expected origins",
        "scope origins",
        "option ids [\"deny\"]",
    ] {
        if !error.contains(detail) {
            return Err(format!("site card diagnostic omitted {detail:?}: {error}"));
        }
    }
    Ok(())
}

fn site_card_answer_line_control() -> Result<(), String> {
    let origin = "http://127.0.0.1:12345";
    for (site, expected) in [
        (origin, "PASS per-site card: your own Chrome, signed in as you; http://127.0.0.1:12345 -> allow_30m"),
        ("http://localhost:12345", "PASS per-site card: your own Chrome, signed in as you; http://localhost:12345 -> allow_30m"),
    ] {
        let card = json!({"id":"el_site","params":{"kind":"consent","scope":{"browser":"user","origins":[site]},"target":{"label":site},"prompt":"Let the agent use your own Chrome, signed in as you, on this site?","options":[{"id":"allow_30m"},{"id":"deny"}]}});
        let line = fixture_site_answer_line(&card, origin, "allow_30m")?;
        if line != expected {
            return Err(format!("site-card answer named the wrong origin: {line}"));
        }
    }
    Ok(())
}

fn handover_status_control() -> Result<(), String> {
    let status = json!({"browser":"user","outcome":"ok","connected":true,"connection_epoch":9,"tabs":[
        {"tab":"owned-handle","claim":"claimed_by_this_route","interaction_epoch":2},
        {"tab":"handed-handle","claim":"unclaimed_handed","interaction_epoch":0}
    ]});
    if unclaimed_handed_tab(&status)? != Some("handed-handle".into()) {
        return Err("handover did not select the public unclaimed_handed handle".into());
    }
    let mut empty = status.clone();
    empty["tabs"] = json!([]);
    if unclaimed_handed_tab(&empty)?.is_some() {
        return Err("empty status invented a handed handle".into());
    }
    let mut raw = status.clone();
    raw["tabs"] =
        json!([{"tab":"bridge-handle","handed":true,"claimed":false,"interaction_epoch":0}]);
    let mut ambiguous = status.clone();
    ambiguous["tabs"]
        .as_array_mut()
        .unwrap()
        .push(json!({"tab":"another-handle","claim":"unclaimed_handed","interaction_epoch":0}));
    let mut disconnected = status;
    disconnected["connected"] = json!(false);
    for invalid in [raw, ambiguous, disconnected] {
        if unclaimed_handed_tab(&invalid).is_ok() {
            return Err("handover accepted raw bridge inventory, ambiguous handles, or a disconnected status".into());
        }
    }
    Ok(())
}

fn cleanup_line_control() -> Result<(), String> {
    let passed = cleanup_line(&Ok(()));
    let failed = cleanup_line(&Err("helper survived".into()));
    if passed != "PASS process-group and scratch cleanup completed"
        || !failed.starts_with("FAIL ")
        || !failed.contains("helper survived")
    {
        return Err(format!("cleanup lines misreport: {passed:?} / {failed:?}"));
    }
    Ok(())
}
fn worker_event_control() -> Result<(), String> {
    let events = [
        json!({"method":"Runtime.consoleAPICalled","params":{"type":"error","args":[
            {"type":"string","value":"Unchecked runtime.lastError:"},
            {"type":"object","description":"Error: Native host has exited."},
            {"type":"number","value":3}]}}),
        json!({"method":"Runtime.exceptionThrown","params":{"exceptionDetails":{"text":"Uncaught (in promise)",
            "exception":{"description":"TypeError: tabGroups is undefined"}}}}),
        json!({"method":"Log.entryAdded","params":{"entry":{"level":"error","source":"other","text":"port closed"}}}),
        json!({"method":"Runtime.executionContextCreated","params":{}}),
    ];
    let lines: Vec<String> = events.iter().filter_map(worker_event_line).collect();
    let expected = [
        "console.error: Unchecked runtime.lastError: Error: Native host has exited. 3",
        "exception: Uncaught (in promise) TypeError: tabGroups is undefined",
        "log.error (other): port closed",
    ];
    if lines != expected {
        return Err(format!("worker events rendered as {lines:?}"));
    }
    Ok(())
}
fn host_exit_control() -> Result<(), String> {
    let scratch = Scratch::new()?;
    let path = scratch.0.join(HOST_EXIT_LOG);
    let missing = host_exit_report(&path);
    private_fs::create_new_file(&path).map_err(|e| e.to_string())?;
    std::fs::write(
        &path,
        "native host pid 7: EOF from Chrome (native port closed)\n",
    )
    .map_err(|e| e.to_string())?;
    let recorded = host_exit_report(&path);
    if missing.len() != 1
        || !missing[0].contains("no record")
        || recorded != ["native host exit: native host pid 7: EOF from Chrome (native port closed)"]
    {
        return Err(format!("host exit report: {missing:?} / {recorded:?}"));
    }
    Ok(())
}

async fn self_test() -> Result<(), String> {
    let mut tests: Vec<(&str, Result<(), String>)> = Vec::new();
    tests.extend(fixture_http::controls());
    tests.push((
        "fixture_readiness_waits_for_the_child_not_just_the_top_page",
        async {
            for missing in ["document_complete", "url_matches", "iframe_ready"] {
                let mut observed =
                    json!({"document_complete":true,"url_matches":true,"iframe_ready":true});
                observed[missing] = json!(false);
                if fixture_ready(&observed) {
                    return Err(format!("fixture readiness ignored {missing}"));
                }
            }
            let mut fixture = Double::new("");
            wait_for_fixture(&mut fixture, std::time::Duration::from_secs(1)).await?;
            if fixture.fixture_polls < 2 {
                return Err("fixture read did not wait for the child".into());
            }
            if wait_for_fixture(
                &mut Double::new("iframe_unready"),
                std::time::Duration::ZERO,
            )
            .await
            .is_ok()
            {
                return Err("fixture read accepted a child that never became ready".into());
            }
            Ok(())
        }
        .await,
    ));
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
        "chrome_never_touches_the_keychain",
        if CHROME_PROBE_ARGS.contains(&"--use-mock-keychain")
            && CHROME_PROBE_ARGS.contains(&"--password-store=basic")
        {
            Ok(())
        } else {
            Err("Chrome must launch with a mock keychain and basic password store".into())
        },
    ));
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
        "cingulate_answers_only_fixture_site_and_user_target",
        cingulate_answer_control(),
    ));
    tests.push((
        "site_card_answer_lines_name_the_card_origin",
        site_card_answer_line_control(),
    ));
    tests.push((
        "handover_uses_public_status_claim_labels",
        handover_status_control(),
    ));
    tests.push(("cleanup_line_reports_cleanup_alone", cleanup_line_control()));
    tests.push((
        "worker_events_render_console_exceptions_and_logs",
        worker_event_control(),
    ));
    tests.push((
        "host_exit_record_is_printed_or_named_absent",
        host_exit_control(),
    ));
    let mut driver = Double::new("");
    let result = exercise(&mut driver, "http://127.0.0.1:12345").await;
    tests.push((
        "acceptance_routine_passes_with_independent_double",
        result.and_then(|_| {
            if driver.click_observations == 1 {
                Ok(())
            } else {
                Err("click must have one independent page observation".into())
            }
        }),
    ));
    let origin = "http://127.0.0.1:12345";
    let targets = json!({"targetInfos":[
        {"type":"service_worker","url":format!("{origin}/"),"targetId":"worker"},
        {"type":"page","url":format!("{origin}/outside-secret"),"targetId":"outside"},
        {"type":"page","url":format!("{origin}/"),"targetId":"fixture"}
    ]});
    let mut ambiguous = targets.clone();
    ambiguous["targetInfos"]
        .as_array_mut()
        .unwrap()
        .push(targets["targetInfos"][2].clone());
    tests.push((
        "page_diagnostics_select_only_the_unique_fixture_target",
        if fixture_page_target(&targets, origin) == Ok("fixture".into())
            && fixture_page_target(&targets, "http://127.0.0.1:54321").is_err()
            && fixture_page_target(&ambiguous, origin).is_err()
        {
            Ok(())
        } else {
            Err("page diagnostics did not isolate the fixture target".into())
        },
    ));
    let mut driver = Double::new("snapshot_text");
    let result = exercise(&mut driver, origin).await;
    tests.push((
        "failed_checks_report_last_reply_outcome_asks_and_fixture_prefix",
        if result
            .as_ref()
            .err()
            .is_some_and(|error| error == "snapshot reuses the fixture site's read grant")
            && driver.failure.as_ref().is_some_and(|diagnostics| {
                diagnostics["outcome"] == "ok"
                    && diagnostics["reason"].is_null()
                    && diagnostics["ask_count"] == 0
                    && diagnostics["state_text_prefix"]
                        .as_str()
                        .is_some_and(|text| text.len() == 400)
                    && diagnostics["state_text_withheld"] == false
            })
        {
            Ok(())
        } else {
            Err(format!(
                "failed snapshot lacks reply diagnostics: {result:?}"
            ))
        },
    ));
    let reply = LastReply {
        reply: json!({"outcome":"refused","reason":"read_again","state_text":format!("{}☃", "a".repeat(399))}),
        asks: 2,
    };
    let allowed = reply.diagnostics(fixture_pages_only(&targets, origin));
    let mut foreign = targets.clone();
    foreign["targetInfos"]
        .as_array_mut()
        .unwrap()
        .push(json!({"type":"page","url":"https://outside.invalid/private","targetId":"foreign"}));
    let withheld = reply.diagnostics(fixture_pages_only(&foreign, origin));
    tests.push((
        "failure_text_prefix_is_utf8_safe_and_withheld_for_nonfixture_targets",
        if allowed["state_text_prefix"] == "a".repeat(399)
            && allowed["outcome"] == "refused"
            && allowed["reason"] == "read_again"
            && allowed["ask_count"] == 2
            && withheld["state_text_prefix"].is_null()
            && withheld["state_text_withheld"] == true
            && !fixture_pages_only(&json!({"targetInfos":[]}), origin)
        {
            Ok(())
        } else {
            Err("failure text was unbounded or exposed a nonfixture page".into())
        },
    ));
    for (fault, name) in [
        (
            "missed_click",
            "acceptance_reads_page_counter_when_click_misses_button",
        ),
        (
            "missed_beacon",
            "acceptance_reads_page_counter_when_beacon_is_missing",
        ),
    ] {
        let mut driver = Double::new(fault);
        let result = exercise(&mut driver, origin).await;
        tests.push((
            name,
            if result
                .as_ref()
                .err()
                .is_some_and(|error| error == "click delivered to local fixture")
                && driver.click_observations == 1
            {
                Ok(())
            } else {
                Err(format!(
                    "fault {fault} lacks failed-click diagnostics: {result:?}"
                ))
            },
        ));
    }
    for (fault, name, expected) in [
        (
            "iframe_repeat_card",
            "acceptance_rejects_repeated_iframe_site_card",
            "iframe typing reuses its own site grant",
        ),
        (
            "read_tier_one",
            "acceptance_rejects_read_grant_that_cannot_click",
            "late read allow_30m covers clicking without a new card",
        ),
        (
            "submit_without_card",
            "acceptance_rejects_submit_without_separate_approval",
            "form submit still needs a separate approval",
        ),
        (
            "drag_in",
            "acceptance_rejects_unadopted_group_member",
            "drag-in group member is handed and claimable",
        ),
        (
            "late_card",
            "acceptance_rejects_second_card_after_late_durable_answer",
            "late allow_30m covers a different action without a new card",
        ),
        (
            "long_refs",
            "acceptance_rejects_long_user_refs",
            "user refs use short e-number names",
        ),
        (
            "active_link",
            "acceptance_rejects_undelivered_handed_active_link",
            "visible link delivered on handed active tab",
        ),
        (
            "background_link",
            "acceptance_rejects_undelivered_handed_background_link",
            "visible link delivered on handed background tab",
        ),
        (
            "iframe",
            "acceptance_rejects_undelivered_iframe_input",
            "type delivered inside iframe fixture",
        ),
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
            "navigation asks per site through scripted Cingulate",
        ),
        (
            "epoch",
            "acceptance_rejects_unchanged_reconnect_epoch",
            "killed worker reconnects with a new epoch",
        ),
    ] {
        let mut driver = Double::new(fault);
        let result = exercise(&mut driver, "http://127.0.0.1:12345").await;
        tests.push((
            name,
            if result.as_ref().err().is_some_and(|e| e == expected) && driver.failure.is_some() {
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
    println!("user_browser_probe {}: {count} offline checks, {failed} failures; loopback HTTP sockets only, no Chrome, live profile, bridge socket or durable journal", env!("CARGO_PKG_VERSION"));
    if failed == 0 {
        Ok(())
    } else {
        Err(format!("{failed} of {count} checks failed"))
    }
}
