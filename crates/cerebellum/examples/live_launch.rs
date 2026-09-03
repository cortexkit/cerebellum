//! Drive the browser surface exactly as a caller does: bind routes, launch a
//! real browser, mint authority through the consent relay, snapshot the page,
//! click a ref from that snapshot, and snapshot the visible result.
//!
//! This is a probe rather than a test because it needs Chrome, a window server,
//! and a signed executable whose identity can be verified.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p cerebellum --example live_launch
//! ```

#[cfg(target_os = "linux")]
use std::ffi::OsString;
#[cfg(target_os = "linux")]
use std::io::Read;
use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use cerebellum::browser_config::BrowserConfig;
#[cfg(target_os = "linux")]
use cerebellum::browser_launch::{LINUX_EXEC_CHAIN_HOP_LIMIT, LINUX_EXEC_CHAIN_PROBE_WINDOW};
use cerebellum::management;
use cerebellum::profile_custody::{
    classify_supervisor_start_time, read_record_if_present, SupervisorLiveness,
};
use cerebellum::Planes;
use cerebellum_core::health::HealthState;
#[cfg(target_os = "linux")]
use cerebellum_linux::{executed_image_identity, spawn_barred};
use serde_json::{json, Value};
#[cfg(target_os = "linux")]
use sha2::{Digest, Sha256};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

#[cfg(target_os = "macos")]
const MACOS_CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
#[cfg(target_os = "linux")]
const LINUX_CHROME_CANDIDATES: [&str; 3] = [
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
    "/usr/bin/google-chrome",
];
const CUSTODY_LOCK_DIRECTORY: &str = ".ck-browser-profile-custody";
const TOOL_CHANNEL: u16 = 9;
const TOOL_EPOCH: u32 = 3;
const MANAGEMENT_CHANNEL: u16 = 4;
const MANAGEMENT_EPOCH: u32 = 1;

#[tokio::main]
async fn main() {
    if let Err(refusal) = precheck_custody_residue() {
        eprintln!("{refusal}");
        std::process::exit(1);
    }

    let Some(executable) = browser_executable() else {
        eprintln!("skipped: no browser at {}", browser_search_description());
        return;
    };
    let identity = match browser_identity(&executable) {
        Ok(identity) => identity,
        Err(reason) => {
            eprintln!("skipped: {reason}");
            return;
        }
    };
    println!("browser identity: {identity}");

    let config = BrowserConfig {
        executable_path: Some(executable),
        expected_identity: Some(identity),
        launch_handshake_deadline_ms: 10_000,
        termination_grace_period_ms: 5_000,
        browser_idle_timeout_ms: 60_000,
        browser_exit_observation_deadline_ms: 5_000,
        navigation_settle_deadline_ms: 10_000,
    };

    let first = run_wire_probe(config.clone(), "first").await;
    let after_first = profile_directories();
    println!(
        "profile directories after first launch: {} {after_first:?}",
        after_first.len()
    );

    let second = run_wire_probe(config, "second").await;
    let after_second = profile_directories();
    println!(
        "profile directories after second launch: {} {after_second:?}",
        after_second.len()
    );

    if first && second {
        if after_first == after_second && !after_first.is_empty() {
            println!("VERDICT: the second launch REUSED the same profile directory");
        } else if after_first.is_empty() {
            println!("VERDICT: no profile directory was observed — reuse unproven");
        } else {
            println!(
                "VERDICT: the second launch MINTED A NEW DIRECTORY, so nothing an agent \
                 does in its browser survives its next launch"
            );
        }
    } else {
        eprintln!("VERDICT: a wire probe failed");
        std::process::exit(1);
    }
}

async fn run_wire_probe(config: BrowserConfig, label: &str) -> bool {
    let page = match ProbePage::start() {
        Ok(page) => page,
        Err(error) => {
            eprintln!("[{label}] probe page failed to start: {error}");
            return false;
        }
    };
    let planes = Planes::with_browser_config(Arc::new(HealthState::new()), Some(config));
    bind_route(
        &planes,
        TOOL_CHANNEL,
        TOOL_EPOCH,
        RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        },
        false,
    )
    .await;
    bind_route(
        &planes,
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        true,
    )
    .await;

    let launched = invoke_tool(&planes, 1, "browser.launch", json!({})).await;
    if launched["outcome"] != "launched" {
        eprintln!("[{label}] launch refused: {launched}");
        return false;
    }
    let browser_session_id = launched["browser_session_id"]
        .as_str()
        .expect("a launch names its browser session")
        .to_string();
    println!("[{label}] launch: {launched}");

    // One grant covering both origins the probe will visit. Two grants would be
    // the natural shape, and it is exactly what does not work today: grant
    // selection ignores the target origin, so only the first-minted grant is
    // ever consulted and every action on the second origin is refused. That
    // defect is recorded separately; this probe measures the DNS reply, not it.
    mint_browser_grant(&planes, &[page.origin(), "http://unreachable.invalid"]).await;

    let navigated = invoke_tool(
        &planes,
        2,
        "browser.navigate",
        json!({
            "url": page.url(),
            "intent": "open the visible click probe",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    if navigated["outcome"] != "ok" {
        eprintln!("[{label}] navigation failed: {navigated}");
        close_browser(&planes, label, &browser_session_id, 90).await;
        return false;
    }

    let before = invoke_tool(
        &planes,
        3,
        "browser.snapshot",
        json!({"mode": "ax", "max_bytes": 65_536}),
    )
    .await;
    print_wire_snapshot(label, "BEFORE", &before);
    if before["outcome"] != "ok" {
        eprintln!("[{label}] snapshot before click failed: {before}");
        close_browser(&planes, label, &browser_session_id, 91).await;
        return false;
    }
    let Some(reference) = before["refs"]
        .as_array()
        .and_then(|refs| refs.iter().find(|reference| reference["name"] == "Sign in"))
        .and_then(|reference| reference["ref"].as_str())
        .map(str::to_string)
    else {
        eprintln!("[{label}] snapshot before click exposed no named button ref");
        close_browser(&planes, label, &browser_session_id, 92).await;
        return false;
    };
    let Some(snapshot_id) = before["snapshot_id"].as_str().map(str::to_string) else {
        eprintln!("[{label}] snapshot before click exposed no snapshot_id");
        close_browser(&planes, label, &browser_session_id, 93).await;
        return false;
    };

    let clicked = invoke_tool(
        &planes,
        4,
        "browser.click",
        json!({
            "ref": reference,
            "snapshot_id": snapshot_id,
            "intent": "change the visible probe heading",
            "severity": {"tier": 4, "credential": true, "financial": false}
        }),
    )
    .await;
    if clicked["outcome"] != "ok" {
        eprintln!("[{label}] click failed: {clicked}");
        close_browser(&planes, label, &browser_session_id, 94).await;
        return false;
    }
    println!("[{label}] click: {clicked}");

    let after = invoke_tool(
        &planes,
        5,
        "browser.snapshot",
        json!({"mode": "ax", "max_bytes": 65_536}),
    )
    .await;
    print_wire_snapshot(label, "AFTER", &after);
    let before_content = before["content"].as_str().unwrap_or_default();
    let after_content = after["content"].as_str().unwrap_or_default();
    let page_changed = before_content.contains("Click probe before")
        && after_content.contains("Click probe after")
        && before_content != after_content;

    // Capture through the same wire path a caller uses, THROUGH the
    // authorization gate. Checking the reply against the machine rather than
    // against itself: a capture that reports its own numbers back is satisfied
    // by any constant.
    let shot = invoke_tool(
        &planes,
        6,
        "browser.screenshot",
        json!({"max_bytes": 4_194_304}),
    )
    .await;
    if shot["outcome"] == "ok" {
        let width = shot["image_width_px"].as_u64().unwrap_or_default();
        let height = shot["image_height_px"].as_u64().unwrap_or_default();
        let scale = shot["device_scale_factor"].as_f64().unwrap_or_default();
        let css_width = shot["input_rect"]["width_input_css"]
            .as_f64()
            .unwrap_or_default();
        let css_height = shot["input_rect"]["height_input_css"]
            .as_f64()
            .unwrap_or_default();
        let png_chars = shot["image_png_b64"].as_str().unwrap_or_default().len();
        println!(
            "[{label}] SCREENSHOT: {width}x{height}px, scale {scale}, css {css_width}x{css_height}, {png_chars} b64 chars"
        );
        // The device scale factor is retained as evidence and is NOT part of the
        // pixel-to-css mapping, which is a ratio: x_px * width_input_css /
        // image_width_px. So the property that matters is that the image and the
        // css rect describe the same region, which shows up as agreeing aspect
        // ratios. An earlier version asserted pixel width == css width * scale,
        // which is a model of Chrome rather than a property of ours, and it was
        // wrong: this capture comes back 1:1 with css while the display scale
        // is 2.
        let image_aspect = width as f64 / height as f64;
        let css_aspect = css_width / css_height;
        if (image_aspect - css_aspect).abs() < 0.01 && scale > 0.0 && png_chars > 0 && width > 0 {
            println!(
                "[{label}] SCREENSHOT VERDICT: authorized, and the image and css rect describe the \
                 same region (aspect {image_aspect:.4} vs {css_aspect:.4})"
            );
        } else {
            eprintln!(
                "[{label}] SCREENSHOT VERDICT: image aspect {image_aspect:.4} does not match css \
                 aspect {css_aspect:.4}"
            );
        }
    } else {
        eprintln!("[{label}] screenshot failed: {shot}");
    }

    // Drive a COORDINATE click against the capture just retained, then read
    // back where it landed. click_point is the escape hatch for pages whose
    // accessibility tree cannot name a control, and its whole risk is the
    // pixel-to-css mapping: a click that lands somewhere plausible is worse
    // than one that fails, because nothing reports it.
    if shot["outcome"] == "ok" {
        let image_width = shot["image_width_px"].as_u64().unwrap_or_default();
        let image_height = shot["image_height_px"].as_u64().unwrap_or_default();
        let rect = &shot["input_rect"];
        let x_px = image_width / 2;
        let y_px = image_height / 2;
        let point = invoke_tool(
            &planes,
            7,
            "browser.click_point",
            json!({
                "snapshot_id": shot["snapshot_id"],
                "x_px": x_px,
                "y_px": y_px,
                "image_width_px": image_width,
                "image_height_px": image_height,
                "intent": "verify the coordinate mapping against a real browser",
                "severity": {"tier": 2, "credential": false, "financial": false}
            }),
        )
        .await;
        if point["outcome"] == "ok" {
            // The same ratio the module maps with, computed here independently
            // so a matching answer is agreement rather than an echo.
            let expected_x = rect["x_input_css"].as_f64().unwrap_or_default()
                + (x_px as f64 + 0.5) * rect["width_input_css"].as_f64().unwrap_or_default()
                    / image_width as f64;
            let expected_y = rect["y_input_css"].as_f64().unwrap_or_default()
                + (y_px as f64 + 0.5) * rect["height_input_css"].as_f64().unwrap_or_default()
                    / image_height as f64;
            let after_point = invoke_tool(
                &planes,
                8,
                "browser.snapshot",
                json!({"mode": "ax", "max_bytes": 65_536}),
            )
            .await;
            let content = after_point["content"].as_str().unwrap_or_default();
            let landed = content
                .split("point ")
                .nth(1)
                .map(|rest| {
                    // Take only the coordinate itself. The page text is
                    // followed by snapshot JSON with no separating space, so
                    // splitting on whitespace swallows the next field and the
                    // parse below then fails -- which is honest, but it reports
                    // a broken reading as a failed mapping.
                    rest.chars()
                        .take_while(|c| c.is_ascii_digit() || *c == ',' || *c == '.')
                        .collect::<String>()
                })
                .unwrap_or_default();
            println!(
                "[{label}] CLICK_POINT: asked ({x_px},{y_px})px, expected css \
                 ({expected_x:.0},{expected_y:.0}), page recorded ({landed})"
            );
            let recorded: Vec<f64> = landed
                .split(',')
                .filter_map(|part| part.trim().parse::<f64>().ok())
                .collect();
            if recorded.len() == 2
                && (recorded[0] - expected_x).abs() <= 2.0
                && (recorded[1] - expected_y).abs() <= 2.0
            {
                println!(
                    "[{label}] CLICK_POINT VERDICT: the click landed where the mapping says it \
                     should, so pixel coordinates address css points correctly"
                );
            } else {
                eprintln!(
                    "[{label}] CLICK_POINT VERDICT: the page recorded ({landed}) where the \
                     mapping predicts ({expected_x:.0},{expected_y:.0})"
                );
            }
        } else {
            eprintln!("[{label}] click_point failed: {point}");
        }
    }

    // A navigation Chrome cannot complete must answer with Chrome's own error
    // rather than `ok` or a settlement timeout. `.invalid` is reserved by RFC
    // 2606 so this can never resolve. Same-session, so it also proves the
    // failure leaves the session usable enough to close cleanly below.
    let failed = invoke_tool(
        &planes,
        7,
        "browser.navigate",
        json!({
            "url": "http://unreachable.invalid/",
            "intent": "prove a DNS failure is reported as Chrome names it",
            "wait": "none",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    println!("[{label}] DNS FAILURE reply: {failed}");
    let dns_named = failed["outcome"] == "navigation_failed"
        && failed["detail"]["error_text"]
            .as_str()
            .is_some_and(|text| text.starts_with("net::ERR_"));
    if dns_named {
        println!("[{label}] DNS FAILURE VERDICT: reported as navigation_failed with Chrome's net:: error");
    } else {
        eprintln!("[{label}] DNS FAILURE VERDICT: the reply does not carry Chrome's error");
    }

    let closed = close_browser(&planes, label, &browser_session_id, 6).await;
    if page_changed {
        println!(
            "[{label}] CLICK VERDICT: the AFTER snapshot differs and exposes 'Click probe after'"
        );
    } else {
        eprintln!(
            "[{label}] CLICK VERDICT: the two printed snapshots do not prove the page changed"
        );
    }
    page_changed && dns_named && closed["outcome"] == "closed"
}

async fn bind_route(
    planes: &Planes,
    route_channel: u16,
    epoch: u32,
    target: RouteTarget,
    declares_elicitation: bool,
) {
    let request = ModuleControlRequest::RouteBind {
        route_channel,
        epoch,
        target,
        identity: probe_identity(),
        principal: Some(Principal::Direct),
        consumer_capabilities: declares_elicitation.then(|| vec!["elicitation".to_string()]),
        admission_facts: Some(json!({
            "agentProjectId": std::env::var("CK_PROBE_PROJECT_ID")
                .unwrap_or_else(|_| "pj-live-launch-probe".to_string()),
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": [
                "browser.launch",
                "browser.status",
                "browser.close"
            ]
        })),
    };
    let frame = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Passive, false),
        0,
        0,
        route_channel as u64,
        serde_json::to_vec(&request).unwrap(),
    )
    .unwrap();
    let (writer, mut replies) = mpsc::channel(2);
    cerebellum::handle_control_request_for_test_with_bindings(
        frame,
        &writer,
        &planes.health,
        &planes.routes,
    )
    .await
    .unwrap();
    let reply = replies.recv().await.expect("route.bind receives a reply");
    assert_eq!(reply.header.ty, FrameType::Response);
}

async fn mint_browser_grant(planes: &Planes, origins: &[&str]) {
    let (writer, mut frames) = mpsc::channel(8);
    let opening = route_request(
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        10,
        json!({
            "method": management::OPEN_GRANT,
            "params": {
                "origins": origins,
                "hazards": [
                    "credential_form_submit",
                    "unverified_form_contents"
                ]
            }
        }),
    );
    cerebellum::handle_frame_for_test(opening, &writer, planes)
        .await
        .unwrap();

    let mut pending = None;
    let mut question = None;
    for _ in 0..2 {
        let frame = tokio::time::timeout(Duration::from_secs(2), frames.recv())
            .await
            .expect("the grant reply and consent question are prompt")
            .expect("the consent relay remains open");
        let body: Value = serde_json::from_slice(&frame.body).unwrap();
        if frame.header.ty == FrameType::Request {
            question = Some((frame, body));
        } else {
            pending = Some(body);
        }
    }
    let pending = pending.expect("browser.open_grant returns consent_pending");
    assert_eq!(pending["outcome"], "consent_pending", "{pending}");
    let (question_frame, question) = question.expect("the relay receives a consent question");
    println!("consent question: {question}");

    let answer = Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Response,
        Flags::new(false, Priority::Interactive, false),
        question_frame.header.channel,
        question_frame.header.epoch,
        question_frame.header.corr,
        serde_json::to_vec(&json!({"decision": "allow"})).unwrap(),
    )
    .unwrap();
    cerebellum::handle_frame_for_test(answer, &writer, planes)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while planes.management.browser_grant_count().await == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the affirmative relay answer mints a browser grant");
}

async fn close_browser(planes: &Planes, label: &str, browser_session_id: &str, corr: u64) -> Value {
    let closed = invoke_tool(
        planes,
        corr,
        "browser.close",
        json!({"browser_session_id": browser_session_id}),
    )
    .await;
    println!("[{label}] close: {closed}");
    closed
}

async fn invoke_tool(planes: &Planes, corr: u64, name: &str, arguments: Value) -> Value {
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
    .unwrap();
    let response = replies.recv().await.expect("tool request receives a reply");
    serde_json::from_slice(&response.body).unwrap()
}

fn route_request(channel: u16, epoch: u32, corr: u64, body: Value) -> Frame {
    Frame::build_with_version(
        PROTOCOL_VERSION,
        FrameType::Request,
        Flags::new(false, Priority::Interactive, false),
        channel,
        epoch,
        corr,
        serde_json::to_vec(&body).unwrap(),
    )
    .unwrap()
}

fn print_wire_snapshot(label: &str, phase: &str, snapshot: &Value) {
    println!("[{label}] SNAPSHOT {phase} RESPONSE: {snapshot}");
    println!(
        "[{label}] SNAPSHOT {phase} CONTENT:\n{}",
        snapshot["content"].as_str().unwrap_or("<missing content>")
    );
}

fn probe_identity() -> BindIdentity {
    BindIdentity {
        project_root: std::env::temp_dir().join("ck-live-launch"),
        harness: "probe".to_string(),
        session: "live-launch-probe".to_string(),
    }
}

/// Read the profile directories themselves. Listing only their parent would
/// compare equal no matter how many per-agent profiles were minted below it.
///
/// An unreadable parent returns EMPTY, which the caller reports as reuse
/// unproven rather than as reuse. That distinction earned itself: when the data
/// root moved under the module's own directory, this path went stale and the
/// probe said "no profile directory observed" while the profile existed and was
/// being reused correctly. Had absence been read as a verdict instead of as a
/// missing observation, the probe would have reported a defect that was its own.
fn profile_directories() -> Vec<String> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    let profiles = PathBuf::from(home)
        .join(".local/share/cortexkit/cerebellum/browser")
        .join("profiles");
    let Ok(entries) = std::fs::read_dir(&profiles) else {
        return Vec::new();
    };
    let mut found: Vec<String> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_dir())
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    found
}

struct ProbePage {
    address: SocketAddr,
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ProbePage {
    fn start() -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let body = concat!(
                            "<!doctype html><html><head><title>Cerebellum Click Probe</title></head>",
                            "<body><main><h1 id='status'>Click probe before</h1>",
                            "<h1 id='point'>no point click</h1>",
                            "<form><input type='password' autocomplete='current-password'>",
                            "<button type='submit' onclick=\"event.preventDefault();document.getElementById('status').textContent='Click probe after'\">",
                            "Sign in</button></form></main>",
                            // Records where a click LANDED, in css pixels. A
                            // coordinate click that reports success proves only
                            // that a click was dispatched; reading back the
                            // landing point is what checks the pixel-to-css
                            // mapping against a real browser and a real display
                            // scale.
                            "<script>document.addEventListener('click',function(e){",
                            "document.getElementById('point').textContent=",
                            "'point '+Math.round(e.clientX)+','+Math.round(e.clientY);});</script>",
                            "</body></html>"
                        );
                        let response = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            url: format!("http://{address}/"),
            stop,
            worker: Some(worker),
        })
    }

    fn url(&self) -> &str {
        &self.url
    }

    fn origin(&self) -> &str {
        self.url.trim_end_matches('/')
    }
}

impl Drop for ProbePage {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn browser_executable() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let path = PathBuf::from(MACOS_CHROME);
        path.is_file().then_some(path)
    }

    #[cfg(target_os = "linux")]
    {
        LINUX_CHROME_CANDIDATES
            .iter()
            .map(PathBuf::from)
            .find(|path| path.is_file())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    None
}

fn browser_search_description() -> String {
    #[cfg(target_os = "macos")]
    {
        MACOS_CHROME.to_string()
    }

    #[cfg(target_os = "linux")]
    {
        LINUX_CHROME_CANDIDATES.join(", ")
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    "a supported browser path on this platform".to_string()
}

fn browser_identity(path: &Path) -> Result<String, String> {
    #[cfg(target_os = "macos")]
    {
        signing_identifier(path)
            .ok_or_else(|| "could not read a signing identifier from the browser".to_string())
    }

    #[cfg(target_os = "linux")]
    {
        let probe_profile = browser_probe_profile_path();
        let crash_dumps_directory = probe_profile.join("crash-dumps");
        let arguments = cerebellum::browser_launch_service::browser_launch_arguments(
            &probe_profile,
            &crash_dumps_directory,
        );
        // The production function itself, not a copy of it. Two mirrors of launch
        // inputs have drifted before, and the second made this very walk measure a
        // browser with no display -- a process the real launch never runs.
        let environment =
            cerebellum::browser_launch_service::browser_launch_environment(&probe_profile);
        let result = (|| {
            let final_image = configured_terminal_image(path, &arguments, &environment)?;
            let digest = sha256_file(&final_image).map_err(|error| {
                format!(
                    "could not hash browser image {}: {error}",
                    final_image.display()
                )
            })?;
            println!(
                "browser final image hashed: {} {digest}",
                final_image.display()
            );
            Ok(digest)
        })();
        let cleanup = cleanup_browser_probe(&probe_profile);
        match (result, cleanup) {
            (Err(error), _) => Err(error),
            (Ok(_), Err(error)) => Err(error),
            (Ok(digest), Ok(())) => Ok(digest),
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = path;
        Err("browser identity is unsupported on this platform".to_string())
    }
}

#[cfg(target_os = "linux")]
fn browser_probe_profile_path() -> PathBuf {
    std::env::temp_dir().join(format!(
        "cerebellum-live-launch-image-probe-{}",
        std::process::id()
    ))
}

#[cfg(target_os = "linux")]
fn configured_terminal_image(
    configured: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
) -> Result<PathBuf, String> {
    let (command_child, _command_parent) = UnixStream::pair()
        .map_err(|error| format!("could not create browser probe command pipe: {error}"))?;
    let (_response_parent, response_child) = UnixStream::pair()
        .map_err(|error| format!("could not create browser probe response pipe: {error}"))?;
    let mut child = spawn_barred(
        configured,
        arguments,
        environment,
        command_child.as_raw_fd(),
        response_child.as_raw_fd(),
    )
    .map_err(|error| format!("could not bar browser image discovery: {error:?}"))?;
    let result = (|| {
        let mut observed = executed_image_identity(child.generation().pid)
            .map_err(|error| format!("could not read configured browser image: {error:?}"))?;
        for _ in 0..LINUX_EXEC_CHAIN_HOP_LIMIT {
            let Some(next) = child
                .continue_to_next_exec_stop_with_deadline(
                    LINUX_EXEC_CHAIN_HOP_LIMIT,
                    std::time::Instant::now() + LINUX_EXEC_CHAIN_PROBE_WINDOW,
                )
                .map_err(|error| format!("could not walk browser exec chain: {error:?}"))?
            else {
                return Ok(observed.resolved_path);
            };
            observed = next;
        }
        Err(format!(
            "could not identify terminal browser image after {LINUX_EXEC_CHAIN_HOP_LIMIT} exec hops"
        ))
    })();
    let cleanup = child
        .terminate_and_reap()
        .map_err(|error| format!("could not reap browser image discovery: {error:?}"));
    match (result, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(path), Ok(())) => Ok(path),
    }
}

#[cfg(target_os = "linux")]
fn cleanup_browser_probe(probe_profile: &Path) -> Result<(), String> {
    match std::fs::remove_dir_all(probe_profile) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(format!(
            "could not remove browser image probe tree {}: {error}",
            probe_profile.display()
        )),
    }
}

#[cfg(target_os = "linux")]
fn sha256_file(path: &Path) -> std::io::Result<String> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            return Ok(format!("{:x}", digest.finalize()));
        }
        digest.update(&buffer[..read]);
    }
}

#[cfg(target_os = "macos")]
fn signing_identifier(path: &Path) -> Option<String> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stderr);
    text.lines()
        .find_map(|line| line.strip_prefix("Identifier="))
        .map(str::to_string)
}

fn precheck_custody_residue() -> Result<(), String> {
    let home = std::env::var_os("HOME")
        .ok_or_else(|| "refusing: could not determine HOME for custody inspection. Next step: set HOME and rerun the probe.".to_string())?;
    let root = PathBuf::from(home)
        .join(".local/share/cortexkit/cerebellum/browser")
        .join(CUSTODY_LOCK_DIRECTORY);
    check_custody_residue(&root, observed_supervisor_start_time)
}

fn check_custody_residue(
    root: &Path,
    mut observe: impl FnMut(u32) -> Result<Option<u64>, String>,
) -> Result<(), String> {
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(format!(
                "refusing: could not inspect custody lock directory {}: {error}. Next step: repair its permissions or inspect it manually before rerunning the probe.",
                root.display()
            ));
        }
    };

    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "refusing: could not inspect custody lock directory {}: {error}. Next step: repair its permissions or inspect it manually before rerunning the probe.",
                root.display()
            )
        })?;
        let lock_path = entry.path();
        if !is_holder_lock_path(&lock_path) {
            continue;
        }
        let Some(record) = read_record_if_present(&lock_path).map_err(|error| {
            format!(
                "refusing: could not read custody lock {}: {error:?}. Next step: repair access or inspect the lock manually before rerunning the probe.",
                lock_path.display()
            )
        })? else {
            continue;
        };
        let supervisor = record.supervisor();
        let observed = observe(supervisor.pid).map_err(|error| {
            format!(
                "refusing: could not read custody supervisor for {}: recorded pid {} start time {}; {error}. Next step: inspect the lock and supervisor before rerunning the probe.",
                lock_path.display(),
                supervisor.pid,
                supervisor.start_time,
            )
        })?;
        match (
            observed,
            classify_supervisor_start_time(supervisor, observed),
        ) {
            (None, SupervisorLiveness::NotLive) => {
                return Err(format!(
                    "refusing: stale custody residue at {}: recorded pid {} start time {}; live reading: pid is gone. Next step: inspect the stale lock, then remove or move it aside only after confirming no live holder before rerunning the probe.",
                    lock_path.display(),
                    supervisor.pid,
                    supervisor.start_time,
                ));
            }
            (Some(start_time), SupervisorLiveness::Live) => {
                return Err(format!(
                    "refusing: another cerebellum holds this profile at {}: recorded pid {} start time {}; live reading: pid {} start time {}. Next step: wait for that supervisor to exit, then rerun the probe.",
                    lock_path.display(),
                    supervisor.pid,
                    supervisor.start_time,
                    supervisor.pid,
                    start_time,
                ));
            }
            (Some(start_time), SupervisorLiveness::NotLive) => {
                return Err(format!(
                    "refusing: stale custody residue at {}: recorded pid {} start time {}; live reading: pid {} start time {} (PID reuse). Next step: inspect the stale lock, then remove or move it aside only after confirming no live holder before rerunning the probe.",
                    lock_path.display(),
                    supervisor.pid,
                    supervisor.start_time,
                    supervisor.pid,
                    start_time,
                ));
            }
            _ => unreachable!("supervisor liveness classification matches its observation"),
        }
    }
    Ok(())
}

fn is_holder_lock_path(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    let Some(stem) = name.strip_suffix(".lock") else {
        return false;
    };
    stem.len() == 64 && stem.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn observed_supervisor_start_time(pid: u32) -> Result<Option<u64>, String> {
    #[cfg(target_os = "linux")]
    {
        match cerebellum_linux::process_start_time(pid) {
            cerebellum_linux::ProcessStartTime::Started(start_time) => Ok(Some(start_time)),
            cerebellum_linux::ProcessStartTime::NoSuchProcess => Ok(None),
            outcome => Err(format!("live reading unavailable: {outcome:?}")),
        }
    }

    #[cfg(target_os = "macos")]
    {
        match cerebellum_macos::process_start_time(pid) {
            cerebellum_macos::ProcessStartTime::Started(start_time) => Ok(Some(start_time)),
            cerebellum_macos::ProcessStartTime::NoSuchProcess => Ok(None),
            outcome => Err(format!("live reading unavailable: {outcome:?}")),
        }
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = pid;
        Err("live reading unavailable on this platform".to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use super::*;

    #[test]
    fn custody_precheck_refuses_a_gone_supervisor() {
        let root = fixture_root("gone-supervisor");
        let lock = root.join(format!("{}.lock", "a".repeat(64)));
        write_lock(&lock, 42, 100);

        let refusal = check_custody_residue(&root, |_| Ok(None)).expect_err("stale lock refuses");

        assert!(refusal.contains("pid is gone"), "{refusal}");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn custody_precheck_distinguishes_a_live_holder_from_pid_reuse() {
        let root = fixture_root("live-and-reused");
        let lock = root.join(format!("{}.lock", "b".repeat(64)));
        write_lock(&lock, 42, 100);

        let live =
            check_custody_residue(&root, |_| Ok(Some(100))).expect_err("live holder refuses");
        assert!(
            live.contains("another cerebellum holds this profile"),
            "{live}"
        );

        let reused =
            check_custody_residue(&root, |_| Ok(Some(101))).expect_err("reused pid refuses");
        assert!(reused.contains("PID reuse"), "{reused}");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[test]
    fn custody_precheck_refuses_a_malformed_holder_lock() {
        let root = fixture_root("malformed-lock");
        let lock = root.join(format!("{}.lock", "c".repeat(64)));
        fs::write(&lock, "not json").expect("write malformed lock");

        let refusal =
            check_custody_residue(&root, |_| Ok(None)).expect_err("malformed lock refuses");

        assert!(refusal.contains("could not read custody lock"), "{refusal}");
        fs::remove_dir_all(root).expect("remove fixture");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_terminal_image_walks_the_configured_exec_chain() {
        let terminal_image = configured_terminal_image(
            Path::new("/bin/sh"),
            &[
                std::ffi::OsString::from("-c"),
                std::ffi::OsString::from("exec /bin/sleep 1"),
            ],
            &[],
        )
        .expect("walk configured shell to its terminal image");

        assert_eq!(
            terminal_image,
            fs::canonicalize("/bin/sleep").expect("canonical terminal image")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_file_digest_is_lowercase_sha256() {
        let root = fixture_root("digest");
        let image = root.join("image");
        fs::write(&image, "abc").expect("write image");

        assert_eq!(
            sha256_file(&image).expect("hash image"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        fs::remove_dir_all(root).expect("remove fixture");
    }

    fn fixture_root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "cerebellum-live-launch-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        fs::create_dir(&root).expect("create fixture root");
        root
    }

    fn write_lock(path: &Path, pid: u32, start_time: u64) {
        fs::write(
            path,
            format!(
                r#"{{"format_version":"ck-browser-profile-custody-lock/v1","holder_id":"holder-test","supervisor_pid":{pid},"supervisor_start_time":{start_time},"profile_directory":"/tmp/profile"}}"#
            ),
        )
        .expect("write lock");
    }
}
