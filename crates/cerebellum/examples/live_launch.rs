//! Launch a real browser through the production service, then close it.
//!
//! Every test of this path uses doubles: a fake launcher, a fake pipe, a fake
//! clock. That is correct for a suite — a test that opens a browser cannot run
//! on a machine without one, and would be skipped into meaninglessness on CI.
//! But it leaves the whole production path proven only against stand-ins, and
//! this module has now been bitten three times by the difference between what a
//! double reports and what the system does: a handshake that worked headless and
//! not headed, renderer subprocesses that appeared broken under our launcher,
//! and a contended child whose exit code inverts between modes.
//!
//! So this drives the real service against the real browser and prints what a
//! caller would see. A probe rather than a test, because it needs Chrome
//! installed, a signed executable whose identity matches configuration, and a
//! window server to talk to.
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
use std::time::{Duration, Instant};

use cerebellum::browser::navigation::BrowserSnapshotObservation;
use cerebellum::browser::Tracker;
use cerebellum::browser_config::BrowserConfig;
use cerebellum::browser_launch_service::ProductionLaunchService;
use cerebellum::browser_session::{NavigationWait, OwnedBrowserProcess};
use cerebellum::snapshot_store::SnapshotKind;
use cerebellum_core::identity::AcceptedBindFacts;
use serde_json::json;
use subc_protocol::{BindIdentity, Principal, RouteTarget};

const CHROME: &str = "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome";

fn main() {
    let executable = PathBuf::from(CHROME);
    if !executable.is_file() {
        eprintln!("skipped: no browser at {}", executable.display());
        return;
    }

    // Read the identity from the binary rather than hardcoding it, so the probe
    // keeps working across Chrome updates. A configuration would name this
    // explicitly; here the point is to exercise the verification, not to pin a
    // particular build.
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

    // Daemon-attested facts, because an unattested identity is refused before
    // any profile effect — which is the property this probe would otherwise
    // silently skip past.
    let facts = json!({
        "agentProjectId": std::env::var("CK_PROBE_PROJECT_ID")
            .unwrap_or_else(|_| "pj-live-launch-probe".to_string()),
        "sessionKind": "primary",
        "controlOperations": ["browser.launch", "browser.status", "browser.close"],
    });
    let accepted = AcceptedBindFacts::from_bind(
        &BindIdentity {
            project_root: std::env::temp_dir().join("ck-live-launch"),
            harness: "probe".to_string(),
            session: "live-launch-probe".to_string(),
        },
        // A principal, because an accepted bind always has one: the default-deny
        // backstop refuses an absent principal before any capability runs, so a
        // probe without one exercises a state production cannot reach.
        Some(Principal::Direct),
        Some(&facts),
        None,
        &RouteTarget::ToolProvider {
            module_id: "cerebellum".to_string(),
        },
    );

    println!(
        "attested: project_id={} session_kind={} disposition={}",
        accepted.agent_project_id_attested,
        accepted.session_kind_attested,
        accepted.identity.profile_disposition.as_str()
    );

    let service = ProductionLaunchService::open(config);

    // Two launches for the SAME identity. The per-agent profile is only worth
    // anything if the second one lands in the directory the first one used: a
    // fresh directory each time satisfies every "a profile directory exists"
    // assertion while defeating the entire purpose.
    let first = launch_once(&service, &accepted, "live-launch-probe-first");
    let after_first = profile_directories();
    println!(
        "profile directories after first launch: {} {after_first:?}",
        after_first.len()
    );

    let second = launch_once(&service, &accepted, "live-launch-probe-second");
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
        println!("VERDICT: a launch failed, so reuse was not tested");
    }
}

/// The per-agent profile directories on disk, read from the filesystem rather
/// than from anything the module reports about itself.
///
/// Reads the `profiles` subdirectory specifically. Listing the ROOT instead
/// names only its fixed children and would compare equal across two launches
/// however many profiles were minted underneath — an observation that cannot
/// fail, which is worse than no observation at all.
fn profile_directories() -> Vec<String> {
    let Ok(home) = std::env::var("HOME") else {
        return Vec::new();
    };
    let profiles = PathBuf::from(home)
        .join(".local/share/cortexkit/browser")
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

fn print_snapshot(label: &str, snapshot: &BrowserSnapshotObservation) {
    println!(
        "snapshot {label}: records={} refs={} truncated={} refs_truncated={}",
        snapshot.records.len(),
        snapshot.refs.len(),
        snapshot.ax_truncated,
        snapshot.refs_truncated
    );
    for record in &snapshot.records {
        println!(
            "snapshot {label} AX: role={:?} name={:?}",
            record.role, record.name
        );
    }
}

fn drive_click_probe(
    process: &mut dyn OwnedBrowserProcess,
    context_key: &str,
    current_origin: &str,
) -> Option<String> {
    let before =
        match process.snapshot_classified(context_key, SnapshotKind::Ax, 0, current_origin, 10_000)
        {
            Ok(snapshot) => snapshot,
            Err(error) => return Some(format!("snapshot before click failed: {error:?}")),
        };
    print_snapshot("BEFORE", &before);
    let Some(reference) = before.refs.iter().find(|reference| {
        reference.captured.role == "button" && reference.captured.name == "Sign in"
    }) else {
        return Some("snapshot before click did not expose the named button ref".into());
    };
    let Some(backend_identity) = reference.backend_identity.as_ref() else {
        return Some("named button ref had no backend DOM identity".into());
    };
    let Some(classification) = reference.classification.clone() else {
        return Some(
            "live login form classification was unavailable in the pinned snapshot".into(),
        );
    };
    println!(
        "classification: submit={} credential={} financial={} tier={}",
        classification.activation_invokes_form_submit,
        classification.credential,
        classification.financial,
        classification.required_tier,
    );
    if !classification.activation_invokes_form_submit || !classification.credential {
        return Some(format!(
            "live login form was not classified as credential_form_submit: {classification:?}"
        ));
    }

    let mut input_events = Vec::new();
    let position = match process.click_classified(
        context_key,
        backend_identity,
        0,
        current_origin,
        Some(&classification),
        10_000,
        &mut |event| input_events.push(event),
    ) {
        Ok(position) => position,
        Err(error) => {
            return Some(format!(
                "click {} failed: {error:?}",
                reference.captured.reference
            ))
        }
    };
    println!(
        "click ref={} resolved=({}, {}) input={input_events:?}",
        reference.captured.reference, position.x_css, position.y_css
    );

    let after = match process.snapshot(context_key, SnapshotKind::Ax, 10_000) {
        Ok(snapshot) => snapshot,
        Err(error) => return Some(format!("snapshot after click failed: {error:?}")),
    };
    print_snapshot("AFTER", &after);
    let changed = before.records != after.records
        && after
            .records
            .iter()
            .any(|record| record.role == "heading" && record.name == "Click probe after");
    if changed {
        println!("CLICK VERDICT: second snapshot DIFFERS and exposes 'Click probe after'");
        None
    } else {
        Some("second snapshot did not differ with the expected visible text change".into())
    }
}

fn launch_once(
    service: &ProductionLaunchService,
    accepted: &AcceptedBindFacts,
    session_id: &str,
) -> bool {
    let started = Instant::now();
    let page = match ProbePage::start() {
        Ok(page) => page,
        Err(error) => {
            println!("probe page failed to start: {error}");
            return false;
        }
    };
    match service.launch(accepted, session_id) {
        Ok(ready) => {
            println!("[{session_id}] LAUNCHED in {:?}", started.elapsed());
            let (mut process, mut cleanup) = ready.into_parts();
            println!("generation still matches: {}", process.generation_matches());

            // Serve a normal HTTP page so both navigation and the click effect are
            // observations of browser state, not values embedded in a data URL.
            let requested_url = page.url();
            let mut tracker = Tracker::default();
            tracker.token("navigation_started");
            let navigation_failure = match process.navigate(
                &accepted.identity.conversation_key,
                requested_url,
                NavigationWait::Settle,
                10_000,
                &mut tracker,
            ) {
                Ok(()) => {
                    println!(
                        "navigation: requested={requested_url} url_final={:?} settled={} lifecycle={:?}",
                        tracker.url_final, tracker.settled, tracker.lifecycle
                    );
                    None
                }
                Err(error) => {
                    let failure = format!(
                        "navigation failed: {error:?}; url_final={:?} lifecycle={:?}",
                        tracker.url_final, tracker.lifecycle
                    );
                    println!("{failure}");
                    Some(failure)
                }
            };

            let click_probe_failure = if navigation_failure.is_none() {
                let current_origin = format!("http://{}", page.address);
                drive_click_probe(
                    process.as_mut(),
                    &accepted.identity.conversation_key,
                    &current_origin,
                )
            } else {
                navigation_failure
            };

            // The real ladder: ask, wait the grace period, force only if the
            // same generation is still alive, then reap before any cleanup.
            println!("requesting graceful termination");
            if let Err(error) = process.request_graceful_termination() {
                println!("graceful request failed: {error:?}");
            }
            let exited = process
                .wait_for_exit(std::time::Duration::from_millis(5_000))
                .unwrap_or(false);
            println!("exited within the grace period: {exited}");
            if !exited && process.generation_matches() {
                println!("forcing termination");
                if let Err(error) = process.force_terminate() {
                    println!("force failed: {error:?}");
                }
            }
            match process.wait_until_reaped() {
                Ok(()) => println!("reaped"),
                Err(error) => println!("reap failed: {error:?}"),
            }
            // Say how the session ended before cleaning up, exactly as the
            // session layer does. A probe that skips this is not driving the
            // production sequence, and the journal cannot record an outcome
            // nobody supplied.
            cleanup.set_terminal_outcome(
                cerebellum::browser_session::BrowserSessionTerminalOutcome::Closed,
            );
            match cleanup.after_reap() {
                Ok(()) => println!("[{session_id}] reaped and cleaned up after reap"),
                Err(stage) => println!("[{session_id}] cleanup failed at {stage:?}"),
            }
            if let Some(failure) = click_probe_failure {
                panic!("{failure}");
            }
            true
        }
        Err(refusal) => {
            println!(
                "[{session_id}] REFUSED after {:?}: {refusal}",
                started.elapsed()
            );
            false
        }
    }
}

fn signing_identifier(path: &PathBuf) -> Option<String> {
    let output = std::process::Command::new("/usr/bin/codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .ok()?;
    String::from_utf8_lossy(&output.stderr)
        .lines()
        .find_map(|line| line.strip_prefix("Identifier=").map(ToOwned::to_owned))
}
