//! Which part of the capture browser's driving does a human-verification
//! check (Cloudflare Turnstile, bot-detection pages) react to?
//!
//! Launches Chrome the way `browser.capture_login` does: the same
//! `browser_launch_arguments`, through the same suspended spawn and release,
//! with CDP over `--remote-debugging-pipe`. It then replays the capture's own
//! CDP sequence against one page: a background target, a flattened attach,
//! `Page.enable` and `Network.enable`, `Page.navigate`, `Page.bringToFront`
//! and `Target.activateTarget`, and the opening `Network.getCookies`. What
//! happens while the page is "handed to the person" is chosen per run, so one
//! detection vector can be switched on at a time:
//!
//! - `--mode nopoll`: nothing after the opening reads.
//! - `--mode page`: the handoff's page-level poll every two seconds, as the
//!   capture ran it: `Network.getCookies`, `Page.getNavigationHistory`,
//!   `Accessibility.enable` and an accessibility-tree walk, `DOM.enable` and
//!   `DOM.getFlattenedDocument`.
//! - `--mode browser`: a poll that touches only the browser target:
//!   `Storage.getCookies` and `Target.getTargetInfo`.
//! - `--runtime-enable`: send `Runtime.enable` on the page right after attach.
//! - `--arg <flag>`: add one Chrome argument (repeatable).
//!
//! After `--seconds` (default 25) it reports, reading as late as possible so
//! the read cannot influence the check: the target's title and URL from the
//! browser target, and on the page `navigator.webdriver` plus the length (never
//! the value) of any Turnstile response token. `--report <js>` adds one more
//! page expression whose result is printed; use it only for a page's own
//! verdict text, never for anything a person typed.
//!
//! It opens a visible Chrome window on a throwaway profile, so run it only
//! with the operator's permission:
//!
//! ```text
//! cargo run -p cerebellum --example turnstile_probe -- https://dash.cloudflare.com/ --mode page
//! ```

#[cfg(target_os = "macos")]
use std::ffi::OsString;
#[cfg(target_os = "macos")]
use std::io::{Read, Write};
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::net::UnixStream;
#[cfg(target_os = "macos")]
use std::path::PathBuf;
#[cfg(target_os = "macos")]
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use serde_json::{json, Value};

#[cfg(not(target_os = "macos"))]
fn main() {
    println!("this probe launches macOS Chrome and has nothing to run here");
}

/// A minimal CDP client over the browser's pipe: one command at a time, every
/// event read past and dropped.
#[cfg(target_os = "macos")]
struct Cdp {
    command: UnixStream,
    response: UnixStream,
    buffer: Vec<u8>,
    next_id: u64,
    log: Vec<String>,
}

#[cfg(target_os = "macos")]
impl Cdp {
    fn call(&mut self, method: &str, params: Value, session: Option<&str>) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        let mut message = json!({"id": id, "method": method, "params": params});
        if let Some(session) = session {
            message["sessionId"] = Value::String(session.to_string());
        }
        self.log.push(format!(
            "{}{method}",
            if session.is_some() { "page:" } else { "browser:" }
        ));
        let mut bytes = serde_json::to_vec(&message).expect("json");
        bytes.push(0);
        self.command.write_all(&bytes).expect("write");
        let deadline = Instant::now() + Duration::from_secs(15);
        loop {
            if let Some(at) = self.buffer.iter().position(|byte| *byte == 0) {
                let frame: Vec<u8> = self.buffer.drain(..=at).collect();
                let value: Value =
                    serde_json::from_slice(&frame[..frame.len() - 1]).expect("frame json");
                if value.get("id").and_then(Value::as_u64) == Some(id) {
                    return value;
                }
                continue;
            }
            assert!(Instant::now() < deadline, "no answer to {method}");
            let mut chunk = [0u8; 65536];
            match self.response.read(&mut chunk) {
                Ok(0) => panic!("pipe closed awaiting {method}"),
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => panic!("read: {error}"),
            }
        }
    }
}

#[cfg(target_os = "macos")]
struct Options {
    url: String,
    mode: String,
    runtime_enable: bool,
    extra_arguments: Vec<OsString>,
    seconds: u64,
    report: Option<String>,
}

#[cfg(target_os = "macos")]
fn options() -> Options {
    let mut arguments = std::env::args().skip(1);
    let mut options = Options {
        url: String::new(),
        mode: "nopoll".into(),
        runtime_enable: false,
        extra_arguments: Vec::new(),
        seconds: 25,
        report: None,
    };
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--mode" => options.mode = arguments.next().expect("--mode value"),
            "--runtime-enable" => options.runtime_enable = true,
            "--arg" => options
                .extra_arguments
                .push(OsString::from(arguments.next().expect("--arg value"))),
            "--seconds" => {
                options.seconds = arguments
                    .next()
                    .and_then(|value| value.parse().ok())
                    .expect("--seconds number")
            }
            "--report" => options.report = arguments.next(),
            url => options.url = url.to_string(),
        }
    }
    assert!(
        ["nopoll", "page", "browser"].contains(&options.mode.as_str()),
        "--mode is nopoll, page or browser"
    );
    assert!(options.url.starts_with("https://"), "pass an https URL");
    options
}

/// The capture's accessibility walk: the root, then every child list, until
/// the same node cap the driver uses.
#[cfg(target_os = "macos")]
fn walk_accessibility_tree(cdp: &mut Cdp, session: &str) {
    const MAX_AX_NODES: usize = 4_000;
    cdp.call("Accessibility.enable", json!({}), Some(session));
    let root = cdp.call("Accessibility.getRootAXNode", json!({}), Some(session));
    let mut pending: Vec<(String, Option<String>)> = root["result"]["node"]["nodeId"]
        .as_str()
        .map(|id| vec![(id.to_string(), root["result"]["node"]["frameId"].as_str().map(str::to_string))])
        .unwrap_or_default();
    let mut seen = 0;
    while let Some((node_id, frame_id)) = pending.pop() {
        seen += 1;
        if seen > MAX_AX_NODES {
            break;
        }
        let mut params = json!({"id": node_id});
        if let Some(frame_id) = &frame_id {
            params["frameId"] = Value::String(frame_id.clone());
        }
        let children = cdp.call("Accessibility.getChildAXNodes", params, Some(session));
        for node in children["result"]["nodes"].as_array().into_iter().flatten() {
            if let Some(id) = node["nodeId"].as_str() {
                if id != node_id {
                    pending.push((
                        id.to_string(),
                        node["frameId"].as_str().map(str::to_string).or(frame_id.clone()),
                    ));
                }
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn main() {
    let options = options();
    let chrome = PathBuf::from("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome");
    if !chrome.is_file() {
        println!("skipped: no Chrome at {}", chrome.display());
        return;
    }
    let profile = std::env::temp_dir().join(format!("ck-turnstile-probe-{}", std::process::id()));
    std::fs::create_dir_all(&profile).expect("profile dir");
    let mut arguments = cerebellum::browser_launch_service::browser_launch_arguments(
        &profile,
        &profile.join("crash-dumps"),
    );
    arguments.extend(options.extra_arguments.iter().cloned());

    let (command_child, command_parent) = UnixStream::pair().expect("command pair");
    let (response_parent, response_child) = UnixStream::pair().expect("response pair");
    response_parent
        .set_read_timeout(Some(Duration::from_millis(200)))
        .expect("read timeout");
    let barred = cerebellum_macos::spawn_barred(
        &chrome,
        &arguments,
        &[],
        command_child.as_raw_fd(),
        response_child.as_raw_fd(),
    )
    .expect("spawn barred");
    let released = barred.release().expect("release");
    drop(command_child);
    drop(response_child);
    let mut cdp = Cdp {
        command: command_parent,
        response: response_parent,
        buffer: Vec::new(),
        next_id: 0,
        log: Vec::new(),
    };

    cdp.call("Browser.getVersion", json!({}), None);
    let created = cdp.call(
        "Target.createTarget",
        json!({"url": "about:blank", "background": true}),
        None,
    );
    let target_id = created["result"]["targetId"]
        .as_str()
        .expect("targetId")
        .to_string();
    let attached = cdp.call(
        "Target.attachToTarget",
        json!({"targetId": target_id, "flatten": true}),
        None,
    );
    let session = attached["result"]["sessionId"]
        .as_str()
        .expect("sessionId")
        .to_string();
    if options.runtime_enable {
        cdp.call("Runtime.enable", json!({}), Some(&session));
    }
    cdp.call("Page.enable", json!({}), Some(&session));
    cdp.call("Network.enable", json!({}), Some(&session));
    cdp.call("Page.navigate", json!({"url": options.url}), Some(&session));
    cdp.call("Page.bringToFront", json!({}), Some(&session));
    cdp.call(
        "Target.activateTarget",
        json!({"targetId": target_id}),
        None,
    );
    let origin = {
        let rest = options.url.trim_start_matches("https://");
        format!("https://{}", rest.split('/').next().unwrap_or_default())
    };
    cdp.call("Network.getCookies", json!({"urls": [origin]}), Some(&session));
    let opening_commands = cdp.log.len();

    let started = Instant::now();
    let mut polls = 0;
    while started.elapsed() < Duration::from_secs(options.seconds) {
        std::thread::sleep(Duration::from_secs(2));
        match options.mode.as_str() {
            "page" => {
                cdp.call("Network.getCookies", json!({"urls": [origin]}), Some(&session));
                cdp.call("Page.getNavigationHistory", json!({}), Some(&session));
                walk_accessibility_tree(&mut cdp, &session);
                cdp.call("DOM.enable", json!({}), Some(&session));
                cdp.call(
                    "DOM.getFlattenedDocument",
                    json!({"depth": -1, "pierce": true}),
                    Some(&session),
                );
                polls += 1;
            }
            "browser" => {
                cdp.call("Storage.getCookies", json!({}), None);
                cdp.call("Target.getTargetInfo", json!({"targetId": target_id}), None);
                polls += 1;
            }
            _ => {}
        }
    }

    // Read from the browser target first: it does not touch the page.
    let info = cdp.call("Target.getTargetInfo", json!({"targetId": target_id}), None);
    let title = info["result"]["targetInfo"]["title"].as_str().unwrap_or("?").to_string();
    let url = info["result"]["targetInfo"]["url"].as_str().unwrap_or("?").to_string();
    let evaluate = |cdp: &mut Cdp, expression: &str| {
        cdp.call(
            "Runtime.evaluate",
            json!({"expression": expression, "returnByValue": true}),
            Some(&session),
        )["result"]["result"]["value"]
            .clone()
    };
    let webdriver = evaluate(&mut cdp, "navigator.webdriver");
    let token_lengths = evaluate(
        &mut cdp,
        "Array.from(document.querySelectorAll('[name=\"cf-turnstile-response\"]')).map(input => input.value.length)",
    );
    let report = options
        .report
        .as_deref()
        .map(|expression| evaluate(&mut cdp, expression));

    let mut commands: Vec<String> = cdp.log[..opening_commands].to_vec();
    commands.dedup();
    println!("url_requested: {}", options.url);
    println!(
        "mode: {} runtime_enable: {} extra_arguments: {:?} seconds: {} polls: {polls}",
        options.mode, options.runtime_enable, options.extra_arguments, options.seconds
    );
    println!("opening commands: {}", commands.join(", "));
    println!("final title: {title:?}");
    println!("final url: {url}");
    println!("navigator.webdriver: {webdriver}");
    println!("turnstile response token lengths: {token_lengths}");
    if let Some(report) = report {
        println!("report: {report}");
    }

    // The profile is throwaway, so a kill is as good as a clean close.
    let _ = released.terminate_and_reap();
    let _ = std::fs::remove_dir_all(&profile);
}
