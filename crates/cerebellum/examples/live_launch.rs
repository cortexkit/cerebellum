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

use std::io::Write;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use cerebellum::browser_config::BrowserConfig;
use cerebellum::management;
use cerebellum::Planes;
use cerebellum_core::health::HealthState;
use serde_json::{json, Value};
use subc_protocol::session::ModuleControlRequest;
use subc_protocol::{
    BindIdentity, Flags, Frame, FrameType, Principal, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";
const TOOL_CHANNEL: u16 = 9;
const TOOL_EPOCH: u32 = 3;
const MANAGEMENT_CHANNEL: u16 = 4;
const MANAGEMENT_EPOCH: u32 = 1;

#[tokio::main]
async fn main() {
    let executable = PathBuf::from(CHROME);
    if !executable.is_file() {
        eprintln!("skipped: no browser at {}", executable.display());
        return;
    }
    let Some(identity) = signing_identifier(&executable) else {
        eprintln!("skipped: could not read a signing identifier from the browser");
        return;
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

    mint_browser_grant(&planes, page.origin()).await;

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
    page_changed && closed["outcome"] == "closed"
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

async fn mint_browser_grant(planes: &Planes, origin: &str) {
    let (writer, mut frames) = mpsc::channel(8);
    let opening = route_request(
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        10,
        json!({
            "method": management::OPEN_GRANT,
            "params": {
                "origins": [origin],
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
                            "<form><input type='password' autocomplete='current-password'>",
                            "<button type='submit' onclick=\"event.preventDefault();document.getElementById('status').textContent='Click probe after'\">",
                            "Sign in</button></form></main></body></html>"
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

fn signing_identifier(path: &PathBuf) -> Option<String> {
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
