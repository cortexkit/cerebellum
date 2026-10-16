//! Drive `browser.present` / `browser.resume` and `browser.import_login` the
//! way a caller does: bind routes, launch the module's own Chrome, mint
//! authority through the consent relay, and answer elicitation on the same
//! process.
//!
//! This is a probe rather than a test because it needs Chrome, a window
//! server, and — for the import arms — the operator's real host-browser
//! stores. It never transfers those stores. A transfer against a real store
//! is a separate, operator-approved run.
//!
//! Run it with:
//!
//! ```text
//! cargo run -p cerebellum --example live_login -- --handoff
//! cargo run -p cerebellum --example live_login -- --import https://example.com
//! cargo run -p cerebellum --example live_login -- --handoff --import https://example.com
//! ```
//!
//! Exit 0 only when every arm that ran reports PASS. UNMEASURABLE and FAIL
//! exit 1 with the reason. Each arm prints one
//! `ARM <name>: PASS|FAIL|UNMEASURABLE <evidence>` line.

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
use cerebellum::classification::canonical_origin;
use cerebellum::journal::{
    Capability, HandoffJournalOutcome, JournalEntry, JournalPayload, LoginImportPayload,
};
use cerebellum::login_import::ImportSettings;
use cerebellum::management;
use cerebellum::profile_custody::{
    classify_supervisor_start_time, read_record_if_present, StartTimeStability, SupervisorLiveness,
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
    BindIdentity, Flags, Frame, FrameType, Priority, RouteTarget, PROTOCOL_VERSION,
};
use tokio::sync::mpsc;

// The consent relay, shared with the computer-plane probes. These two carried
// a byte-identical copy whose frame pump was a fixed two-iteration loop, which
// assumes every request opens an elicitation: a capability answering without
// one left the second recv waiting until its own timeout, reported as "the
// consent question was not prompt" about a question that was never owed.
#[path = "support/cingulate_answer.rs"]
mod cingulate_answer;

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
const AGENT_COOKIES_RELATIVE: &str = "Default/Cookies";
const FIXTURE_MARKER: &str = "ck-live-login-fixture-marker";
const SECOND_FIXTURE_MARKER: &str = "ck-live-login-second-origin-marker";

#[tokio::main]
async fn main() {
    let args = match parse_args_from(std::env::args().skip(1)) {
        Ok(args) => args,
        Err(reason) => {
            eprintln!("{reason}");
            std::process::exit(1);
        }
    };

    if let Err(refusal) = precheck_custody_residue() {
        eprintln!("{refusal}");
        std::process::exit(1);
    }

    let Some(executable) = browser_executable() else {
        eprintln!(
            "ARM setup: UNMEASURABLE no browser at {}",
            browser_search_description()
        );
        std::process::exit(1);
    };
    let identity = match browser_identity(&executable) {
        Ok(identity) => identity,
        Err(reason) => {
            eprintln!("ARM setup: UNMEASURABLE {reason}");
            std::process::exit(1);
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

    let mut all_passed = true;
    if args.handoff {
        all_passed &= run_handoff_arms(config.clone()).await;
    }
    if let Some(origin) = args.import_origin {
        all_passed &= run_import_arms(config.clone(), &origin).await;
    }
    if let Some(url) = args.capture_url {
        all_passed &= run_capture_arm(config, &url).await;
    }

    if !all_passed {
        std::process::exit(1);
    }
}

#[derive(Debug)]
struct Args {
    handoff: bool,
    import_origin: Option<String>,
    capture_url: Option<String>,
}

fn parse_args_from<I, S>(args: I) -> Result<Args, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut handoff = false;
    let mut import_origin = None;
    let mut capture_url = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_ref() {
            "--handoff" => handoff = true,
            "--capture" => {
                let url = args
                    .next()
                    .ok_or_else(|| "usage: --capture requires an https URL".to_string())?;
                capture_url = Some(url.as_ref().to_string());
            }
            "--import" => {
                let origin = args
                    .next()
                    .ok_or_else(|| "usage: --import requires a canonical origin".to_string())?;
                let origin = origin.as_ref().to_string();
                if canonical_origin(&origin).as_deref() != Some(origin.as_str()) {
                    return Err(format!(
                        "usage: --import takes one canonical http or https origin, got {origin}"
                    ));
                }
                import_origin = Some(origin);
            }
            other => {
                return Err(format!(
                    "unknown argument {other}; usage: --handoff, --import <origin>, or both"
                ));
            }
        }
    }
    if !handoff && import_origin.is_none() && capture_url.is_none() {
        return Err(
            "usage: cargo run -p cerebellum --example live_login -- --handoff, --import <origin>, or both"
                .to_string(),
        );
    }
    Ok(Args {
        handoff,
        import_origin,
        capture_url,
    })
}

#[derive(Debug)]
enum ArmVerdict {
    Pass(String),
    Fail(String),
    Unmeasurable(String),
}

fn report_arm(name: &str, verdict: ArmVerdict) -> bool {
    match verdict {
        ArmVerdict::Pass(evidence) => {
            println!("ARM {name}: PASS {evidence}");
            true
        }
        ArmVerdict::Fail(evidence) => {
            println!("ARM {name}: FAIL {evidence}");
            false
        }
        ArmVerdict::Unmeasurable(evidence) => {
            println!("ARM {name}: UNMEASURABLE {evidence}");
            false
        }
    }
}

async fn run_handoff_arms(config: BrowserConfig) -> bool {
    let page = match ProbePage::start(FIXTURE_MARKER) {
        Ok(page) => page,
        Err(error) => {
            return report_arm(
                "present_fronts_the_window",
                ArmVerdict::Fail(format!("probe page failed to start: {error}")),
            );
        }
    };
    let second = match ProbePage::start(SECOND_FIXTURE_MARKER) {
        Ok(page) => page,
        Err(error) => {
            return report_arm(
                "present_refuses_origin_mismatch",
                ArmVerdict::Fail(format!("second probe page failed to start: {error}")),
            );
        }
    };

    let planes = Arc::new(Planes::with_browser_config(
        Arc::new(HealthState::new()),
        Some(config),
    ));
    bind_route(
        planes.as_ref(),
        TOOL_CHANNEL,
        TOOL_EPOCH,
        RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        },
        false,
    )
    .await;
    bind_route(
        planes.as_ref(),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        true,
    )
    .await;

    let launched = invoke_tool(planes.as_ref(), 1, "browser.launch", json!({})).await;
    if launched["outcome"] != "launched" {
        eprintln!("handoff launch refused: {launched}");
        return report_arm(
            "present_fronts_the_window",
            ArmVerdict::Fail(format!("launch refused: {launched}")),
        );
    }
    let browser_session_id = launched["browser_session_id"]
        .as_str()
        .expect("a launch names its browser session")
        .to_string();
    println!("handoff launch: {launched}");

    mint_browser_grant(planes.as_ref(), &[page.origin()]).await;
    mint_browser_grant(planes.as_ref(), &[second.origin()]).await;

    let navigated = invoke_tool(
        planes.as_ref(),
        2,
        "browser.navigate",
        json!({
            "url": page.url(),
            "intent": "open the login handoff fixture",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    if navigated["outcome"] != "ok" {
        eprintln!("handoff navigation failed: {navigated}");
        close_browser(planes.as_ref(), "handoff", &browser_session_id, 90).await;
        return report_arm(
            "present_fronts_the_window",
            ArmVerdict::Fail(format!("navigation failed: {navigated}")),
        );
    }

    let journal_before_handoff = planes.browser.journal_export_for_test().await;
    let mut passed = true;

    passed &= report_arm(
        "present_fronts_the_window",
        present_fronts_the_window(planes.as_ref(), page.origin()).await,
    );
    passed &= report_arm(
        "tools_refuse_while_human_in_control",
        tools_refuse_while_human_in_control(planes.as_ref(), page.origin(), page.url()).await,
    );
    passed &= report_arm(
        "resume_returns_control",
        resume_returns_control(
            planes.as_ref(),
            page.origin(),
            FIXTURE_MARKER,
            &journal_before_handoff,
        )
        .await,
    );
    passed &= report_arm(
        "present_refuses_origin_mismatch",
        present_refuses_origin_mismatch(planes.as_ref(), page.origin(), &second).await,
    );

    close_browser(planes.as_ref(), "handoff", &browser_session_id, 91).await;
    passed
}

async fn present_fronts_the_window(planes: &Planes, origin: &str) -> ArmVerdict {
    let presented =
        invoke_management(planes, 20, management::PRESENT, json!({ "origin": origin })).await;
    println!("present reply: {presented}");
    if presented["outcome"] != "presented" {
        return ArmVerdict::Fail(format!("expected outcome presented, got {presented}"));
    }
    let Some(expires_in_ms) = presented["expires_in_ms"].as_u64() else {
        return ArmVerdict::Fail(format!(
            "presented reply omitted expires_in_ms: {presented}"
        ));
    };
    if expires_in_ms == 0 {
        return ArmVerdict::Fail(format!("expires_in_ms was 0: {presented}"));
    }

    let status = invoke_tool(planes, 21, "browser.status", json!({})).await;
    println!("browser.status after present: {status}");
    let Some(browser_pid) = launched_browser_pid() else {
        return ArmVerdict::Fail(format!(
            "no child of this probe carries --remote-debugging-pipe; the launched browser \
             was not found (status: {status})"
        ));
    };

    #[cfg(target_os = "macos")]
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let frontmost = cerebellum_macos::frontmost_process_id();
            println!("pid pair: browser={browser_pid} frontmost={frontmost:?}");
            if frontmost == Some(browser_pid) {
                return ArmVerdict::Pass(format!(
                    "outcome=presented expires_in_ms={expires_in_ms} browser_pid={browser_pid} frontmost={browser_pid}"
                ));
            }
            if std::time::Instant::now() >= deadline {
                return ArmVerdict::Fail(format!(
                    "frontmost pid {frontmost:?} != browser pid {browser_pid}"
                ));
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        ArmVerdict::Unmeasurable(format!(
            "presented with expires_in_ms={expires_in_ms} browser_pid={browser_pid}; frontmost_process_id is macOS-only"
        ))
    }
}

/// Seconds the capture arm leaves the window to the handoff before it closes
/// the browser itself, standing in for a person closing the window.
const CAPTURE_WINDOW_SECONDS: u64 = 20;

/// Run `browser.capture_login` on `url` with nobody logging in, and report
/// how the handoff ended and when.
///
/// Nobody logs in, so the only honest endings are the window closing or the
/// handoff expiring. The arm closes the browser after
/// [`CAPTURE_WINDOW_SECONDS`]; a reply of `no_login_observed` before that means
/// the handoff decided a running browser had exited. While it waits it prints
/// the kernel's start-time reading for the capture browser once a second: the
/// reading the handoff's liveness check is built on.
async fn run_capture_arm(config: BrowserConfig, url: &str) -> bool {
    let Some(host) = url
        .strip_prefix("https://")
        .and_then(|rest| rest.split(['/', '?', '#']).next())
        .filter(|host| !host.is_empty())
    else {
        return report_arm(
            "capture_handoff_stays_open",
            ArmVerdict::Unmeasurable(format!("--capture takes an https URL, got {url}")),
        );
    };
    let planes = Arc::new(Planes::with_browser_config(
        Arc::new(HealthState::new()),
        Some(config),
    ));
    bind_route(
        planes.as_ref(),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        true,
    )
    .await;

    let started = std::time::Instant::now();
    let watching = Arc::new(AtomicBool::new(true));
    let watcher = {
        let watching = Arc::clone(&watching);
        std::thread::spawn(move || {
            let mut closed_at = None;
            while watching.load(Ordering::Acquire) {
                std::thread::sleep(Duration::from_secs(1));
                let elapsed = started.elapsed().as_secs();
                let Some(pid) = launched_browser_pid() else {
                    println!("[capture] t={elapsed}s no capture browser child");
                    continue;
                };
                #[cfg(target_os = "macos")]
                println!(
                    "[capture] t={elapsed}s browser pid={pid} start-time reading={:?}",
                    cerebellum_macos::process_start_time(pid as u32)
                );
                #[cfg(not(target_os = "macos"))]
                println!("[capture] t={elapsed}s browser pid={pid}");
                if elapsed >= CAPTURE_WINDOW_SECONDS && closed_at.is_none() {
                    // SIGTERM, as a window close ends the browser; the handoff
                    // must then see it gone.
                    let _ = std::process::Command::new("/bin/kill")
                        .args(["-TERM", &pid.to_string()])
                        .status();
                    closed_at = Some(elapsed);
                    println!("[capture] t={elapsed}s closed the capture browser");
                }
            }
            closed_at
        })
    };

    let request = route_request(
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        40,
        json!({
            "method": management::CAPTURE_LOGIN,
            "params": {
                "account": "live-probe",
                "credential_domain": host,
                "login_url": url,
                "fetch_url": url,
            }
        }),
    );
    let reply = cingulate_answer::answer_cards_waiting(
        planes.as_ref(),
        request,
        json!({"decision": "allow"}),
        management::CAPTURE_LOGIN,
        |_| {},
        Duration::from_secs(CAPTURE_WINDOW_SECONDS + 15),
    )
    .await;
    let elapsed = started.elapsed();
    watching.store(false, Ordering::Release);
    let closed_at = watcher.join().unwrap_or(None);
    // Whatever the reply, no capture browser may outlive the arm.
    if let Some(pid) = launched_browser_pid() {
        let _ = std::process::Command::new("/bin/kill")
            .args(["-KILL", &pid.to_string()])
            .status();
    }
    let reply = match reply {
        Ok(reply) => reply,
        Err(error) => {
            return report_arm(
                "capture_handoff_stays_open",
                ArmVerdict::Fail(format!("the capture call did not complete: {error}")),
            )
        }
    };
    let outcome = reply["outcome"].as_str().unwrap_or("?").to_string();
    // Whether the session check ran and what it found, from the reply's
    // outcome and reason alone: a capture happens only after a passing check,
    // and a handoff that ended after failed checks names that reason. The
    // reply never carries a cookie value, so nothing here can print one.
    let verification = match (outcome.as_str(), reply["reason"].as_str()) {
        ("captured", _) => "passed",
        (_, Some(cerebellum::login_capture::LOGIN_NOT_VERIFIED)) => "failed",
        _ => "not_reached",
    };
    let evidence = format!(
        "outcome={outcome} session_verification={verification} after {} ms; browser closed by the arm at {closed_at:?} s",
        elapsed.as_millis()
    );
    let verdict = match (outcome.as_str(), closed_at) {
        ("no_login_observed", Some(_)) => ArmVerdict::Pass(evidence),
        ("no_login_observed", None) => ArmVerdict::Fail(format!(
            "{evidence}: the handoff ended on a browser nobody closed"
        )),
        _ => ArmVerdict::Fail(format!("{evidence}; reply {reply}")),
    };
    report_arm("capture_handoff_stays_open", verdict)
}

/// The pid of the browser this in-process harness launched.
///
/// `browser.status` deliberately reports no pid (its envelope is closed and a
/// pid is not something a caller can act on), and the launcher runs in this
/// process, so the browser is a direct child of the probe: the one child
/// carrying the pipe flag the custody rules require.
fn launched_browser_pid() -> Option<i32> {
    let output = std::process::Command::new("/usr/bin/pgrep")
        .args([
            "-P",
            &std::process::id().to_string(),
            "-f",
            "remote-debugging-pipe",
        ])
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| line.trim().parse::<i32>().ok())
        .next()
}

async fn tools_refuse_while_human_in_control(
    planes: &Planes,
    origin: &str,
    url: &str,
) -> ArmVerdict {
    let snapshot = invoke_tool(
        planes,
        22,
        "browser.snapshot",
        json!({"mode": "ax", "max_bytes": 65_536}),
    )
    .await;
    println!("snapshot while presented: {snapshot}");
    if let Err(reason) = human_in_control_refusal(&snapshot, origin) {
        return ArmVerdict::Fail(format!("browser.snapshot {reason}"));
    }

    let navigated = invoke_tool(
        planes,
        23,
        "browser.navigate",
        json!({
            "url": url,
            "intent": "prove tools refuse during handoff",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    println!("navigate while presented: {navigated}");
    if let Err(reason) = human_in_control_refusal(&navigated, origin) {
        return ArmVerdict::Fail(format!("browser.navigate {reason}"));
    }

    ArmVerdict::Pass(format!(
        "snapshot and navigate both human_in_control origin={origin} remedy=browser.resume expires_in_ms={}",
        snapshot["expires_in_ms"]
    ))
}

fn human_in_control_refusal(reply: &Value, origin: &str) -> Result<(), String> {
    if reply["outcome"] != "human_in_control" {
        return Err(format!("expected outcome human_in_control, got {reply}"));
    }
    if reply["remedy"] != "browser.resume" {
        return Err(format!("expected remedy browser.resume, got {reply}"));
    }
    if reply["origin"].as_str() != Some(origin) {
        return Err(format!("expected origin {origin}, got {reply}"));
    }
    match reply["expires_in_ms"].as_u64() {
        Some(ms) if ms > 0 => Ok(()),
        _ => Err(format!("expected expires_in_ms > 0, got {reply}")),
    }
}

async fn resume_returns_control(
    planes: &Planes,
    origin: &str,
    fixture_marker: &str,
    journal_before: &str,
) -> ArmVerdict {
    let resumed = invoke_management(planes, 24, management::RESUME, json!({})).await;
    println!("resume reply: {resumed}");
    if resumed["outcome"] != "resumed"
        || resumed["handoff"] != "closed_by_caller"
        || resumed["origin"].as_str() != Some(origin)
    {
        return ArmVerdict::Fail(format!(
            "expected outcome=resumed handoff=closed_by_caller origin={origin}, got {resumed}"
        ));
    }

    let snapshot = invoke_tool(
        planes,
        25,
        "browser.snapshot",
        json!({"mode": "ax", "max_bytes": 65_536}),
    )
    .await;
    println!("snapshot after resume: {snapshot}");
    if snapshot["outcome"] != "ok" {
        return ArmVerdict::Fail(format!("snapshot after resume was not ok: {snapshot}"));
    }

    let export = planes.browser.journal_export_for_test().await;
    let entries = journal_entries_since(&export, journal_before);
    println!("handoff journal entries since present: {}", entries.len());
    match verify_handoff_journal(&entries, origin, fixture_marker) {
        Ok(evidence) => {
            ArmVerdict::Pass(format!("resumed closed_by_caller; snapshot ok; {evidence}"))
        }
        Err(reason) => ArmVerdict::Fail(reason),
    }
}

fn verify_handoff_journal(
    entries: &[JournalEntry],
    origin: &str,
    fixture_marker: &str,
) -> Result<String, String> {
    let mut opened = 0usize;
    let mut closed_by_caller = 0usize;
    for entry in entries {
        let serialized = serde_json::to_string(entry)
            .map_err(|error| format!("could not serialize journal entry: {error}"))?;
        if serialized.contains(fixture_marker) {
            return Err(format!(
                "journal entry carried fixture page text {fixture_marker}: {serialized}"
            ));
        }
        // The close record legitimately carries `cookie_names_added`, a count.
        // A leak would carry the names themselves (a list under a plural key)
        // or an encrypted value; the count's own key must not trip the scan.
        if serialized.contains("\"cookie_names\"") || serialized.contains("encrypted_value") {
            return Err(format!(
                "journal entry carried a cookie name or value: {serialized}"
            ));
        }
        if entry.capability != Some(Capability::Present)
            || entry.identity.conversation_key != probe_conversation_key()
        {
            continue;
        }
        let Some(JournalPayload::Handoff(payload)) = entry.payload.as_ref() else {
            continue;
        };
        if payload.origin != origin {
            continue;
        }
        match payload.outcome {
            HandoffJournalOutcome::Opened => {
                if let Some(count) = payload.cookie_names_added {
                    return Err(format!("open record carried cookie_names_added: {count}"));
                }
                opened += 1;
            }
            HandoffJournalOutcome::ClosedByCaller => {
                if payload.cookie_names_added != Some(0) {
                    return Err(format!(
                        "close record cookie_names_added={:?}, expected 0",
                        payload.cookie_names_added
                    ));
                }
                closed_by_caller += 1;
            }
            other => {
                return Err(format!("unexpected handoff journal outcome {other:?}"));
            }
        }
    }
    if opened != 1 || closed_by_caller != 1 {
        return Err(format!(
            "expected one present open record and one closed_by_caller close, got opened={opened} closed_by_caller={closed_by_caller}"
        ));
    }
    Ok("journal opened=1 closed_by_caller cookie_names_added=0".to_string())
}

async fn present_refuses_origin_mismatch(
    planes: &Planes,
    first_origin: &str,
    second: &ProbePage,
) -> ArmVerdict {
    let navigated = invoke_tool(
        planes,
        26,
        "browser.navigate",
        json!({
            "url": second.url(),
            "intent": "move off the handoff origin",
            "wait": "settle",
            "severity": {"tier": 1, "credential": false, "financial": false}
        }),
    )
    .await;
    println!("navigation to second origin: {navigated}");
    if navigated["outcome"] != "ok" {
        return ArmVerdict::Fail(format!("navigation to second origin failed: {navigated}"));
    }

    let presented = invoke_management(
        planes,
        27,
        management::PRESENT,
        json!({ "origin": first_origin }),
    )
    .await;
    println!("present after origin change: {presented}");
    if presented["outcome"] != "origin_mismatch" {
        return ArmVerdict::Fail(format!(
            "expected origin_mismatch for {first_origin}, got {presented}"
        ));
    }
    let current = presented["current_origin"].as_str().unwrap_or_default();
    if current != second.origin() {
        return ArmVerdict::Fail(format!(
            "origin_mismatch current_origin={current}, expected {}",
            second.origin()
        ));
    }
    ArmVerdict::Pass(format!(
        "origin_mismatch current_origin={current} after navigating to {}",
        second.origin()
    ))
}

async fn run_import_arms(config: BrowserConfig, origin: &str) -> bool {
    let planes = Arc::new(Planes::with_browser_config(
        Arc::new(HealthState::new()),
        Some(config),
    ));
    bind_route(
        planes.as_ref(),
        TOOL_CHANNEL,
        TOOL_EPOCH,
        RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        },
        false,
    )
    .await;
    bind_route(
        planes.as_ref(),
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        RouteTarget::ManagementSurface {
            module_id: "cerebellum".to_string(),
        },
        true,
    )
    .await;

    if let Err(reason) = ensure_durable_profile_closed(planes.as_ref()).await {
        return report_arm(
            "presence_is_reported_without_values",
            ArmVerdict::Fail(reason),
        );
    }

    let cookies_path = agent_cookies_path(planes.as_ref());
    let journal_before_import = planes.browser.journal_export_for_test().await;
    let mut passed = true;

    passed &= report_arm(
        "presence_is_reported_without_values",
        presence_is_reported_without_values(&planes, origin).await,
    );
    passed &= report_arm(
        "hand_off_is_returned_to_the_caller",
        hand_off_is_returned_to_the_caller(&planes, origin, cookies_path.as_deref()).await,
    );

    passed &= report_arm(
        "session_open_is_refused",
        session_open_is_refused(&planes, origin).await,
    );
    // Exported after the refusal arm on purpose: a refused import is journaled
    // under its code, and the window must show that record beside the two
    // answered ones.
    let import_journal = planes.browser.journal_export_for_test().await;
    passed &= report_arm(
        "import_login_journal",
        verify_import_journal_arm(&import_journal, &journal_before_import, origin),
    );
    passed
}

async fn ensure_durable_profile_closed(planes: &Planes) -> Result<(), String> {
    let project_id = probe_project_id();
    match planes
        .management
        .durable_login_profile_location(&project_id)
    {
        Ok(Some(_)) => {
            let status = invoke_tool(planes, 30, "browser.status", json!({})).await;
            if status["outcome"] == "ready" {
                let id = status["browser_session_id"].as_str().unwrap_or_default();
                close_browser(planes, "import-setup", id, 31).await;
            }
            Ok(())
        }
        Ok(None) => {
            let launched = invoke_tool(planes, 32, "browser.launch", json!({})).await;
            if launched["outcome"] != "launched" {
                return Err(format!(
                    "could not mint a durable profile; launch refused: {launched}"
                ));
            }
            let id = launched["browser_session_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            close_browser(planes, "import-setup", &id, 33).await;
            match planes.management.durable_login_profile_location(&project_id) {
                Ok(Some(_)) => Ok(()),
                Ok(None) => Err(
                    "durable profile still absent after a launch-and-close; import_login cannot elicit"
                        .to_string(),
                ),
                Err(reason) => Err(format!("durable profile registry unavailable: {reason}")),
            }
        }
        Err(reason) => Err(format!("durable profile registry unavailable: {reason}")),
    }
}

fn agent_cookies_path(planes: &Planes) -> Option<PathBuf> {
    planes
        .management
        .durable_login_profile_location(&probe_project_id())
        .ok()
        .flatten()
        .map(|location| location.profile_directory.join(AGENT_COOKIES_RELATIVE))
}

async fn presence_is_reported_without_values(planes: &Arc<Planes>, origin: &str) -> ArmVerdict {
    let looked_for = known_host_store_paths();
    let mut leak = None;
    let mut listed = Vec::new();
    let exchange = invoke_import_login_with(planes, 40, origin, |question| {
        listed = print_presence_list(question);
        leak = question_secret_leak(question);
        "deny".to_string()
    })
    .await;

    match exchange {
        Err(reason) => ArmVerdict::Fail(reason),
        Ok(exchange) => {
            println!("import_login deny reply: {}", exchange.reply);
            if let Some(leak) = leak {
                return ArmVerdict::Fail(leak);
            }
            if listed.is_empty() {
                return ArmVerdict::Unmeasurable(format!(
                    "no known browser store exists on this machine; looked for {}",
                    looked_for
                        .iter()
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
            if exchange.reply["outcome"] != "denied" {
                return ArmVerdict::Fail(format!(
                    "expected outcome denied after answering deny, got {}",
                    exchange.reply
                ));
            }
            ArmVerdict::Pass(format!(
                "deny after presence {:?}; question carried no encrypted_value",
                listed
            ))
        }
    }
}

fn print_presence_list(question: &Value) -> Vec<String> {
    let browsers = question
        .pointer("/params/browsers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut listed = Vec::new();
    for browser in &browsers {
        let id = browser
            .get("browser")
            .and_then(Value::as_str)
            .unwrap_or("<missing browser>");
        let rows = browser
            .get("persistent_rows")
            .and_then(Value::as_u64)
            .unwrap_or(0);
        let availability = browser
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| browser.get("transfer").and_then(Value::as_str))
            .unwrap_or("<missing transfer>");
        println!("import presence: browser={id} persistent_rows={rows} {availability}");
        listed.push(format!("{id}:{rows}:{availability}"));
    }
    listed
}

fn known_host_store_paths() -> Vec<PathBuf> {
    let Some(home) = std::env::var_os("HOME") else {
        return Vec::new();
    };
    let settings = ImportSettings::production(Path::new(&home));
    let mut paths: Vec<PathBuf> = settings
        .browsers
        .iter()
        .map(|browser| {
            settings
                .application_support
                .join(&browser.data_directory)
                .join(AGENT_COOKIES_RELATIVE)
        })
        .collect();
    paths.push(settings.safari_store);
    paths
}

fn question_secret_leak(question: &Value) -> Option<String> {
    let serialized = question.to_string();
    if serialized.contains("encrypted_value") {
        return Some("elicitation question contained encrypted_value".to_string());
    }
    let browsers = question
        .pointer("/params/browsers")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let allowed_names: Vec<String> = browsers
        .iter()
        .filter_map(|browser| {
            browser
                .get("name")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .chain(browsers.iter().filter_map(|browser| {
            browser
                .get("browser")
                .and_then(Value::as_str)
                .map(str::to_string)
        }))
        .collect();
    let mut long = Vec::new();
    collect_long_non_path_strings(question, "", &allowed_names, &mut long);
    if long.is_empty() {
        None
    } else {
        Some(format!(
            "elicitation question carried a string longer than 64 characters that is not a path or browser name: {}",
            long.join("; ")
        ))
    }
}

fn collect_long_non_path_strings(
    value: &Value,
    path: &str,
    allowed_names: &[String],
    out: &mut Vec<String>,
) {
    match value {
        Value::String(text) => {
            if text.len() <= 64 {
                return;
            }
            if text.contains('/') || text.contains('\\') {
                return;
            }
            if allowed_names.iter().any(|name| name == text) {
                return;
            }
            out.push(format!("{path}={text}"));
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                collect_long_non_path_strings(
                    item,
                    &format!("{path}[{index}]"),
                    allowed_names,
                    out,
                );
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                if key == "message" {
                    // Elicitation prose is supposed to be longer than 64
                    // characters; the leak check is for values, not the ask.
                    continue;
                }
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                collect_long_non_path_strings(child, &child_path, allowed_names, out);
            }
        }
        _ => {}
    }
}

async fn hand_off_is_returned_to_the_caller(
    planes: &Arc<Planes>,
    origin: &str,
    cookies_path: Option<&Path>,
) -> ArmVerdict {
    let before = cookies_path.and_then(|path| std::fs::read(path).ok());
    let exchange = invoke_import_login_with(planes, 41, origin, |_| "hand_off".to_string()).await;
    match exchange {
        Err(reason) => ArmVerdict::Fail(reason),
        Ok(exchange) => {
            println!("import_login hand_off reply: {}", exchange.reply);
            if exchange.reply["outcome"] != "hand_off" {
                return ArmVerdict::Fail(format!(
                    "expected outcome hand_off, got {}",
                    exchange.reply
                ));
            }
            let after = cookies_path.and_then(|path| std::fs::read(path).ok());
            if before != after {
                return ArmVerdict::Fail(format!(
                    "agent Default/Cookies changed after hand_off (before {} bytes, after {} bytes)",
                    before.as_ref().map(Vec::len).unwrap_or(0),
                    after.as_ref().map(Vec::len).unwrap_or(0)
                ));
            }
            ArmVerdict::Pass(format!(
                "outcome=hand_off; Default/Cookies unchanged ({})",
                match cookies_path {
                    Some(path) if path.exists() => format!(
                        "{} bytes at {}",
                        before.as_ref().map(Vec::len).unwrap_or(0),
                        path.display()
                    ),
                    Some(path) => format!("still absent at {}", path.display()),
                    None => "profile cookies path unknown".to_string(),
                }
            ))
        }
    }
}

async fn session_open_is_refused(planes: &Arc<Planes>, origin: &str) -> ArmVerdict {
    let launched = invoke_tool(planes.as_ref(), 42, "browser.launch", json!({})).await;
    println!("import session launch: {launched}");
    if launched["outcome"] != "launched" {
        return ArmVerdict::Fail(format!("launch before import_login refused: {launched}"));
    }
    let browser_session_id = launched["browser_session_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let exchange = invoke_import_login_with(planes, 43, origin, |_| "deny".to_string()).await;
    let closed = close_browser(planes.as_ref(), "import-session", &browser_session_id, 44).await;
    match exchange {
        Err(reason) => ArmVerdict::Fail(reason),
        Ok(exchange) => {
            println!("import_login while session open: {}", exchange.reply);
            if exchange.question.is_some() {
                return ArmVerdict::Fail(
                    "session_open raised elicitation instead of refusing immediately".to_string(),
                );
            }
            if exchange.reply["outcome"] != "session_open"
                || exchange.reply["remedy"] != "browser.close"
            {
                return ArmVerdict::Fail(format!(
                    "expected session_open with remedy browser.close, got {}",
                    exchange.reply
                ));
            }
            if closed["outcome"] != "closed" {
                return ArmVerdict::Fail(format!("close after session_open failed: {closed}"));
            }
            ArmVerdict::Pass("session_open remedy=browser.close, then closed".to_string())
        }
    }
}

fn verify_import_journal_arm(export: &str, before: &str, origin: &str) -> ArmVerdict {
    let entries = journal_entries_since(export, before);
    println!(
        "import journal entries since presence arm: {}",
        entries.len()
    );
    match verify_import_journal(&entries, origin) {
        Ok(evidence) => ArmVerdict::Pass(evidence),
        Err(reason) => ArmVerdict::Fail(reason),
    }
}

fn verify_import_journal(entries: &[JournalEntry], origin: &str) -> Result<String, String> {
    let this_run = probe_conversation_key();
    let mut denied = 0usize;
    let mut hand_off = 0usize;
    // The session-open arm runs before this check and its refusal is
    // journaled under its own code: a refused import is still an import
    // someone asked for, and the record says why nothing moved.
    let mut session_open = 0usize;
    for entry in entries {
        let serialized = serde_json::to_string(entry)
            .map_err(|error| format!("could not serialize journal entry: {error}"))?;
        // The import record carries a row COUNT. The names GitHub actually
        // sets are the positive markers a leak would have to carry, and they
        // are real on any host whose Chrome holds a GitHub login, so their
        // absence here is an assertion about the record and not about the
        // scanner's vocabulary.
        for leak in [
            "\"cookie_names\"",
            "encrypted_value",
            "_octo",
            "logged_in",
            "user_session",
        ] {
            if serialized.contains(leak) {
                return Err(format!(
                    "import journal entry carried a cookie name or value ({leak}): {serialized}"
                ));
            }
        }
        if entry.capability != Some(Capability::ImportLogin) {
            continue;
        }
        let Some(JournalPayload::LoginImport(LoginImportPayload {
            origin: recorded_origin,
            outcome,
            rows,
            ..
        })) = entry.payload.as_ref()
        else {
            continue;
        };
        if recorded_origin != origin || entry.identity.conversation_key != this_run {
            continue;
        }
        if *rows != 0 {
            return Err(format!(
                "import journal row count {rows} for outcome {outcome}, expected 0"
            ));
        }
        match outcome.as_str() {
            "denied" => denied += 1,
            "hand_off" => hand_off += 1,
            "session_open" => session_open += 1,
            other => {
                return Err(format!("unexpected import journal outcome {other}"));
            }
        }
    }
    if denied != 1 || hand_off != 1 || session_open != 1 {
        return Err(format!(
            "expected one denied, one hand_off and one session_open import_login record, \
             got denied={denied} hand_off={hand_off} session_open={session_open}"
        ));
    }
    Ok(
        "journal import_login denied + hand_off + session_open refusal, rows=0, no cookie names"
            .to_string(),
    )
}

struct ImportExchange {
    question: Option<Value>,
    reply: Value,
}

async fn invoke_import_login_with<F>(
    planes: &Arc<Planes>,
    corr: u64,
    origin: &str,
    on_question: F,
) -> Result<ImportExchange, String>
where
    F: FnOnce(&Value) -> String,
{
    let (writer, mut frames) = mpsc::channel(8);
    let opening = route_request(
        MANAGEMENT_CHANNEL,
        MANAGEMENT_EPOCH,
        corr,
        json!({
            "method": management::IMPORT_LOGIN,
            "params": { "origin": origin }
        }),
    );
    let writer_for_request = writer.clone();
    let planes_for_request = Arc::clone(planes);
    let request_task = tokio::spawn(async move {
        cerebellum::handle_frame_for_test(opening, &writer_for_request, planes_for_request.as_ref())
            .await
            .map_err(|error| format!("import_login dispatch failed: {error:?}"))
    });

    let mut question = None;
    let mut reply = None;
    let mut on_question = Some(on_question);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    while reply.is_none() {
        let frame = tokio::time::timeout_at(deadline, frames.recv())
            .await
            .map_err(|_| "timed out waiting for import_login frames".to_string())?
            .ok_or_else(|| "import_login writer closed before a reply".to_string())?;
        let body: Value = serde_json::from_slice(&frame.body)
            .map_err(|error| format!("import_login frame was not JSON: {error}"))?;
        if frame.header.ty == FrameType::Request {
            let decision = on_question
                .take()
                .ok_or_else(|| "import_login asked more than once".to_string())?(
                &body
            );
            question = Some(body);
            let answer = Frame::build_with_version(
                PROTOCOL_VERSION,
                FrameType::Response,
                Flags::new(false, Priority::Interactive, false),
                frame.header.channel,
                frame.header.epoch,
                frame.header.corr,
                serde_json::to_vec(&json!({ "decision": decision })).unwrap(),
            )
            .unwrap();
            cerebellum::handle_frame_for_test(answer, &writer, planes.as_ref())
                .await
                .map_err(|error| format!("import_login answer failed: {error:?}"))?;
        } else {
            reply = Some(body);
        }
    }
    request_task
        .await
        .map_err(|error| format!("import_login task joined with {error}"))??;
    Ok(ImportExchange {
        question,
        reply: reply.expect("the loop exits only with a reply"),
    })
}

fn journal_entries_since(export: &str, before: &str) -> Vec<JournalEntry> {
    let before_lines = before.lines().filter(|line| !line.is_empty()).count();
    export
        .lines()
        .filter(|line| !line.is_empty())
        .skip(before_lines)
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

async fn bind_route(
    planes: &Planes,
    route_channel: u16,
    epoch: u32,
    target: RouteTarget,
    raises_cards: bool,
) {
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
            "agentProjectId": probe_project_id(),
            "sessionKind": "primary",
            "effectiveCapabilityScope": ["*"],
            "browserControlOperations": [
                "browser.launch",
                "browser.status",
                "browser.close"
            ]
        })),
        // A permission card is raised with Cingulate only from a call under
        // an agent session's scope.
        scope: raises_cards.then(|| cingulate_answer::cingulate::stamp(&probe_project_id())),
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
    let grant_count_before = planes.management.browser_grant_count().await;
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
    let pending = cingulate_answer::answer_cards(
        planes,
        opening,
        json!({"decision": "allow_30m"}),
        "browser.open_grant",
    )
    .await
    .expect("the grant request and its consent question complete");
    assert_eq!(pending["outcome"], "consent_pending", "{pending}");

    tokio::time::timeout(Duration::from_secs(2), async {
        while planes.management.browser_grant_count().await <= grant_count_before {
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

async fn invoke_management(planes: &Planes, corr: u64, method: &str, params: Value) -> Value {
    let (writer, mut replies) = mpsc::channel(8);
    cerebellum::handle_frame_for_test(
        route_request(
            MANAGEMENT_CHANNEL,
            MANAGEMENT_EPOCH,
            corr,
            json!({ "method": method, "params": params }),
        ),
        &writer,
        planes,
    )
    .await
    .unwrap();
    let response = replies
        .recv()
        .await
        .expect("management request receives a reply");
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

/// The conversation key carries a per-process nonce. The probe drives the
/// DURABLE journal, so records from every earlier run are in the same file,
/// and the store opens lazily on the first reservation: a baseline export
/// taken before the first op is empty and a line-count filter then counts
/// all of history. Filtering by this run's own key is the discriminator
/// that does not depend on when the store opened.
fn probe_conversation_key() -> String {
    format!("live-login-probe-{}", std::process::id())
}

fn probe_identity() -> BindIdentity {
    BindIdentity::new(
        std::env::temp_dir().join("ck-live-login"),
        "probe",
        probe_conversation_key(),
    )
}

fn probe_project_id() -> String {
    std::env::var("CK_PROBE_PROJECT_ID").unwrap_or_else(|_| "pj-live-login-probe".to_string())
}

struct ProbePage {
    address: SocketAddr,
    url: String,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<()>>,
}

impl ProbePage {
    fn start(marker: &'static str) -> std::io::Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = Arc::clone(&stop);
        let worker = std::thread::spawn(move || {
            while !worker_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let body = format!(
                            "<!doctype html><html><head><title>Cerebellum Login Probe</title></head>\
                             <body><main><p>{marker}</p></main></body></html>"
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
        "cerebellum-live-login-image-probe-{}",
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
            classify_supervisor_start_time(
                supervisor,
                observed,
                StartTimeStability::MovesWithWallClock,
            ),
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
            // A live pid whose start time moved is NOT evidence of reuse on
            // Linux: the reading is recomputed from the wall clock, so a clock
            // step since the lock was written produces the same difference.
            (Some(start_time), SupervisorLiveness::Unavailable) => {
                return Err(format!(
                    "refusing: custody lock at {} names recorded pid {} start time {}; live reading: pid {} start time {}. That is either PID reuse or a wall-clock step since the lock was written, and this reading cannot tell which. Next step: check whether pid {} is a cerebellum supervisor before touching the lock.",
                    lock_path.display(),
                    supervisor.pid,
                    supervisor.start_time,
                    supervisor.pid,
                    start_time,
                    supervisor.pid,
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
        // Current locks record the start in clock ticks since boot, which a
        // wall-clock step cannot move (see `SupervisorGeneration`). A lock
        // written before that holds epoch microseconds and reads here as a
        // moved start time, which this probe refuses the same way.
        match cerebellum_linux::process_generation(pid) {
            cerebellum_linux::ProcessGenerationReading::Started { start_ticks, .. } => {
                Ok(Some(start_ticks))
            }
            cerebellum_linux::ProcessGenerationReading::NoSuchProcess => Ok(None),
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
    fn parse_args_requires_an_arm() {
        let error = parse_args_from(Vec::<String>::new()).expect_err("empty args refuse");
        assert!(error.contains("usage:"), "{error}");
    }

    #[test]
    fn parse_args_accepts_handoff_and_import() {
        let args = parse_args_from(["--handoff", "--import", "https://example.com"])
            .expect("both arms parse");
        assert!(args.handoff);
        assert_eq!(args.import_origin.as_deref(), Some("https://example.com"));
    }

    #[test]
    fn parse_args_rejects_a_non_canonical_import_origin() {
        let error = parse_args_from(["--import", "https://example.com/path"])
            .expect_err("pathful origin refuses");
        assert!(error.contains("canonical"), "{error}");
    }

    #[test]
    fn question_leak_ignores_message_and_paths() {
        let question = json!({
            "params": {
                "message": "Allow agent pj-live-login-probe to import the persistent login for example.com from a browser on this Mac? Google Chrome: 1 persistent row(s), available. No cookie value will be decrypted by the agent.",
                "browsers": [{
                    "browser": "chrome",
                    "name": "Google Chrome",
                    "persistent_rows": 1,
                    "session_rows": 0,
                    "transfer": "available",
                }],
                "path": "/Users/someone/Library/Application Support/Google/Chrome/Default/Cookies",
            }
        });
        assert_eq!(question_secret_leak(&question), None);
    }

    #[test]
    fn question_leak_flags_encrypted_value_and_long_secrets() {
        let encrypted = json!({"params": {"message": "short", "encrypted_value": "abc"}});
        assert!(question_secret_leak(&encrypted)
            .expect("encrypted_value leaks")
            .contains("encrypted_value"));

        let long = json!({
            "params": {
                "message": "short",
                "browsers": [],
                "secret": "this-string-is-definitely-longer-than-sixty-four-characters-and-is-not-a-path",
            }
        });
        assert!(question_secret_leak(&long)
            .expect("long secret leaks")
            .contains("longer than 64"));
    }

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
            "cerebellum-live-login-{label}-{}-{}",
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
